//! Synthetic hostname generation and conditional domain selection.
//!
//! This module implements automatic DNS hostname synthesis and conditional domain
//! selection based on client IP addresses. It is the Rust equivalent of the C
//! `src/domain.c` module (707 lines) and provides both IPv4 and IPv6 support.
//!
//! # Key Functions
//!
//! - [`is_name_synthetic`] — Match a domain name against synthetic domain patterns
//!   and generate the corresponding IP address (forward lookup synthesis).
//! - [`is_rev_synth`] — Generate a synthetic domain name from an IP address
//!   (reverse DNS / PTR record synthesis).
//! - [`get_domain`] / [`get_domain6`] — Select the appropriate domain suffix
//!   for a client based on its IPv4/IPv6 address (split-horizon DNS).
//!
//! # Synthetic Name Formats
//!
//! Synthetic domain names follow two formats depending on configuration:
//!
//! ## Indexed Mode
//! `<prefix><index>.<domain>` where index is the offset from the range start address.
//! - Example: `host10.synth.example.com` → 192.168.1.10 (if start = 192.168.1.0)
//!
//! ## Non-Indexed Mode
//! - IPv4: `<prefix><a-b-c-d>.<domain>` — dotted-decimal with dots replaced by dashes.
//!   Example: `host192-168-1-100.synth.example.com`
//! - IPv6: `<prefix><XXXX-XXXX-...-XXXX>.<domain>` — full expanded hex pairs with dashes.
//!   Example: `host2001-0db8-0000-0000-0000-0000-0000-0001.synth.example.com`
//!
//! # Design Decisions
//!
//! - **No in-place mutation:** The C version modifies the input name string during
//!   processing (dots→nulls) then restores it. The Rust version uses string slicing
//!   and owned copies, avoiding mutation entirely.
//! - **No global state:** All domain lists and default suffixes are passed as
//!   parameters rather than accessed through a global daemon struct.
//! - **Zero `unsafe`:** Pure safe Rust implementation.
//!
//! # Source
//! - Primary: `src/domain.c` (707 lines)
//! - Data structures: `struct cond_domain` from `src/dnsmasq.h` lines 1216–1224

use std::net::{Ipv4Addr, Ipv6Addr};

use log::{debug, warn};

use crate::core::util::hostname_isequal;
use crate::types::addr::AllAddr;
use crate::types::dns::CacheEntryFlags;
use crate::types::ipv6::Ipv6AddrExt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Address list flag indicating an IPv6 entry.
///
/// Corresponds to C `ADDRLIST_IPV6 = 2` from `dnsmasq.h` line 598.
/// Used in interface-based matching to select IPv4 or IPv6 entries from
/// the address list.
const ADDRLIST_IPV6_FLAG: u32 = 2;

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

/// Conditional domain configuration entry.
///
/// Represents a mapping between an IP address range (or interface) and a
/// domain suffix. Used for both synthetic hostname generation (`synth_domains`)
/// and conditional domain selection (`cond_domains`).
///
/// Replaces: C `struct cond_domain` from `dnsmasq.h` lines 1216–1224.
/// The linked list `next` pointer is removed — entries are stored in `Vec`.
///
/// # Examples
///
/// ```rust,ignore
/// let domain = ConditionalDomain {
///     domain: "lan.example.com".to_string(),
///     prefix: Some("host".to_string()),
///     start: Some(Ipv4Addr::new(192, 168, 1, 0)),
///     end: Some(Ipv4Addr::new(192, 168, 1, 255)),
///     indexed: true,
///     ..ConditionalDomain::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ConditionalDomain {
    /// Domain suffix (e.g., "example.com").
    pub domain: String,
    /// Optional prefix for synthetic names (e.g., "host-").
    /// When `None`, the address portion immediately begins the hostname.
    pub prefix: Option<String>,
    /// IPv4 start address for range matching.
    pub start: Option<Ipv4Addr>,
    /// IPv4 end address for range matching.
    pub end: Option<Ipv4Addr>,
    /// IPv6 start address for range matching.
    pub start6: Option<Ipv6Addr>,
    /// IPv6 end address for range matching.
    pub end6: Option<Ipv6Addr>,
    /// Whether this is an IPv6 conditional domain.
    pub is6: bool,
    /// Whether indexed mode is used (numeric component extraction).
    ///
    /// In indexed mode, the hostname contains a numeric index offset from the
    /// range start (e.g., `host10.example.com` for the 10th address in range).
    /// In non-indexed mode, the hostname embeds the full IP address with dashes.
    pub indexed: bool,
    /// Interface name for interface-based matching (alternative to address range).
    ///
    /// When set, addresses are matched against the interface's assigned prefixes
    /// from `address_list` instead of the explicit start/end range.
    pub interface: Option<String>,
    /// Address list for interface-based matching.
    ///
    /// Contains the IP addresses and prefix lengths assigned to the interface
    /// specified in `interface`. Each entry's `flags` field indicates whether
    /// it is IPv4 or IPv6 (via `ADDRLIST_IPV6_FLAG`).
    pub address_list: Vec<AddressListEntry>,
    /// IPv6 prefix length for subnet-based matching.
    ///
    /// Used in `match_domain_v6()` to determine the matching strategy:
    /// - `prefixlen >= 64`: Check /64 prefix match AND compare lower 64-bit host parts
    /// - `prefixlen < 64`: Check prefix match only
    ///
    /// Corresponds to C `cond_domain.prefixlen` field.
    pub prefixlen: u32,
}

impl Default for ConditionalDomain {
    fn default() -> Self {
        Self {
            domain: String::new(),
            prefix: None,
            start: None,
            end: None,
            start6: None,
            end6: None,
            is6: false,
            indexed: false,
            interface: None,
            address_list: Vec::new(),
            prefixlen: 0,
        }
    }
}

/// Address list entry for interface-based domain matching.
///
/// Each entry represents an IP address (IPv4 or IPv6) with a prefix length,
/// used to determine whether a client address falls within the interface's subnet.
///
/// Replaces: C `struct addrlist` from `dnsmasq.h` lines 604–609.
/// The linked list `next` pointer is removed — entries are stored in `Vec`.
#[derive(Debug, Clone)]
pub struct AddressListEntry {
    /// The address (IPv4 or IPv6) wrapped in the [`AllAddr`] enum.
    pub addr: AllAddr,
    /// Prefix length for subnet matching (0–32 for IPv4, 0–128 for IPv6).
    pub prefixlen: u32,
    /// Flags controlling this entry's behavior.
    ///
    /// Bit 1 (`ADDRLIST_IPV6_FLAG = 2`) indicates an IPv6 address entry.
    /// When this bit is clear, the entry is treated as IPv4.
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Public Functions
// ---------------------------------------------------------------------------

/// Check if a domain name matches a synthetic domain configuration and generate
/// the corresponding IP address.
///
/// Validates whether a given domain name matches any configured synthetic domain
/// patterns (from the `synth_domains` list) and generates the corresponding IP
/// address if a match is found. Synthetic domains enable automatic DNS responses
/// for ranges of hostnames without explicit per-host configuration.
///
/// The function performs:
/// 1. Case-insensitive prefix matching
/// 2. For indexed mode: numeric index extraction and range validation
/// 3. For non-indexed mode: address parsing from dash-separated components
///
/// # Arguments
/// * `flags` — Query flags as raw `u32`. Checked for [`CacheEntryFlags::IPV6`]
///   to determine protocol family.
/// * `name` — Domain name to check (not modified, unlike the C version which
///   temporarily mutates the input string).
/// * `synth_domains` — Slice of configured synthetic domain entries.
///
/// # Returns
/// `Some(AllAddr)` containing the generated IP address on successful match,
/// or `None` if no synthetic domain configuration matches.
///
/// # Source
/// Port of `src/domain.c` `is_name_synthetic()` lines 134–259.
pub fn is_name_synthetic(
    flags: u32,
    name: &str,
    synth_domains: &[ConditionalDomain],
) -> Option<AllAddr> {
    let cache_flags = CacheEntryFlags::from_bits_truncate(flags);
    let is_ipv6 = cache_flags.contains(CacheEntryFlags::IPV6);

    debug!(
        "is_name_synthetic: checking '{}' (ipv6={})",
        name, is_ipv6
    );

    for c in synth_domains {
        // Step 1: Case-insensitive prefix match.
        // C code iterates char-by-char with manual ASCII case folding.
        // Rust uses eq_ignore_ascii_case on the prefix-length substring.
        let tail = match c.prefix {
            Some(ref prefix) if !prefix.is_empty() => {
                if name.len() < prefix.len() {
                    continue;
                }
                if !name[..prefix.len()].eq_ignore_ascii_case(prefix) {
                    continue;
                }
                &name[prefix.len()..]
            }
            // No prefix or empty prefix — entire name is the "tail"
            _ => name,
        };

        if c.indexed {
            // ----- Indexed mode -----
            // Find the end of the digit sequence after the prefix
            let dot_pos = match find_first_non_digit(tail) {
                Some(pos) => pos,
                None => continue, // All digits, no dot separator found
            };

            // The character at dot_pos must be '.' (domain separator)
            if tail.as_bytes().get(dot_pos) != Some(&b'.') {
                continue;
            }

            let num_str = &tail[..dot_pos];
            let domain_str = &tail[dot_pos + 1..];

            // Empty numeric part is not valid
            if num_str.is_empty() {
                continue;
            }

            // Check domain suffix match (case-insensitive)
            if !hostname_isequal(&c.domain, domain_str) {
                continue;
            }

            if !is_ipv6 {
                // IPv4 indexed: index must be within start..=end range offset
                if c.is6 {
                    continue;
                }
                let index: u32 = match num_str.parse() {
                    Ok(i) => i,
                    Err(_) => {
                        warn!(
                            "is_name_synthetic: failed to parse IPv4 index '{}'",
                            num_str
                        );
                        continue;
                    }
                };

                let start = c.start.map(|a| a.to_bits()).unwrap_or(0);
                let end = c.end.map(|a| a.to_bits()).unwrap_or(0);

                if index <= end.wrapping_sub(start) {
                    let ip = Ipv4Addr::from(start.wrapping_add(index));
                    debug!("is_name_synthetic: indexed IPv4 match → {}", ip);
                    return Some(AllAddr::V4(ip));
                }
            } else {
                // IPv6 indexed: index must be within addr6part range
                if !c.is6 {
                    continue;
                }
                let index: u64 = match num_str.parse() {
                    Ok(i) => i,
                    Err(_) => {
                        warn!(
                            "is_name_synthetic: failed to parse IPv6 index '{}'",
                            num_str
                        );
                        continue;
                    }
                };

                let start6 = c.start6.unwrap_or(Ipv6Addr::UNSPECIFIED);
                let end6 = c.end6.unwrap_or(Ipv6Addr::UNSPECIFIED);
                let start_part = addr6part(&start6);
                let end_part = addr6part(&end6);

                if index <= end_part.wrapping_sub(start_part) {
                    let result = set_addr6part(&start6, start_part.wrapping_add(index));
                    debug!("is_name_synthetic: indexed IPv6 match → {}", result);
                    return Some(AllAddr::V6(result));
                }
            }
        } else {
            // ----- Non-indexed mode -----
            // Find the first character that isn't a valid address component:
            //   - Digits 0-9 and dashes '-' are always valid
            //   - Hex digits a-f/A-F are valid for IPv6 only
            let dot_pos = match find_first_non_addr_char(tail, is_ipv6) {
                Some(pos) => pos,
                None => continue, // No separator found
            };

            // The character at dot_pos must be '.' (domain separator)
            if tail.as_bytes().get(dot_pos) != Some(&b'.') {
                continue;
            }

            let addr_part = &tail[..dot_pos];
            let domain_str = &tail[dot_pos + 1..];

            // Check domain suffix match first (short-circuit evaluation like C)
            if !hostname_isequal(&c.domain, domain_str) {
                continue;
            }

            // Replace dashes with dots (IPv4) or colons (IPv6) to form a
            // parseable IP address string. C does this in-place; we create a
            // new String to avoid mutating the input.
            let parsed_addr_str = if !is_ipv6 {
                addr_part.replace('-', ".")
            } else {
                addr_part.replace('-', ":")
            };

            if !is_ipv6 {
                // IPv4: parse address and verify it falls within the domain range
                match parsed_addr_str.parse::<Ipv4Addr>() {
                    Ok(addr) => {
                        if match_domain_v4(addr, c) {
                            debug!(
                                "is_name_synthetic: non-indexed IPv4 match → {}",
                                addr
                            );
                            return Some(AllAddr::V4(addr));
                        }
                    }
                    Err(_) => continue,
                }
            } else {
                // IPv6: parse address and verify it falls within the domain range
                match parsed_addr_str.parse::<Ipv6Addr>() {
                    Ok(addr) => {
                        if match_domain_v6(&addr, c) {
                            debug!(
                                "is_name_synthetic: non-indexed IPv6 match → {}",
                                addr
                            );
                            return Some(AllAddr::V6(addr));
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    None
}

/// Generate a synthetic domain name from an IP address for reverse DNS queries.
///
/// Performs reverse synthetic name generation by searching the configured synthetic
/// domain list for a domain that includes the specified IP address, then constructing
/// the corresponding synthetic domain name. Used primarily for automatic PTR record
/// generation enabling reverse DNS resolution of synthetic forward records.
///
/// # Arguments
/// * `flag` — Protocol flags as raw `u32`. Checked for [`CacheEntryFlags::IPV4`]
///   and [`CacheEntryFlags::IPV6`] to determine address family.
/// * `addr` — Address for which to generate a synthetic name.
/// * `synth_domains` — Slice of configured synthetic domain entries.
///
/// # Returns
/// `Some(String)` with the generated synthetic hostname on successful match,
/// or `None` if no synthetic domain configuration matches the address.
///
/// # Synthetic Name Format
/// - **Indexed IPv4:** `<prefix><index>.<domain>` (e.g., `host10.example.com`)
/// - **Non-indexed IPv4:** `<prefix><a-b-c-d>.<domain>` (e.g., `host192-168-1-100.example.com`)
/// - **Indexed IPv6:** `<prefix><index>.<domain>` (e.g., `host42.example.com`)
/// - **Non-indexed IPv6:** `<prefix><xxxx-xxxx-...-xxxx>.<domain>` with 8 hex-pair groups
///
/// # Source
/// Port of `src/domain.c` `is_rev_synth()` lines 303–365.
pub fn is_rev_synth(
    flag: u32,
    addr: &AllAddr,
    synth_domains: &[ConditionalDomain],
) -> Option<String> {
    let cache_flags = CacheEntryFlags::from_bits_truncate(flag);

    // IPv4 reverse synthesis
    if cache_flags.contains(CacheEntryFlags::IPV4) {
        if let AllAddr::V4(ipv4) = addr {
            if let Some(c) = search_domain_v4(*ipv4, synth_domains) {
                let mut name = String::new();

                if c.indexed {
                    // Indexed: "prefix{index}.domain"
                    let start = c.start.map(|a| a.to_bits()).unwrap_or(0);
                    let index = ipv4.to_bits().wrapping_sub(start);
                    if let Some(ref prefix) = c.prefix {
                        name.push_str(prefix);
                    }
                    name.push_str(&index.to_string());
                } else {
                    // Non-indexed: "prefix{a-b-c-d}.domain"
                    // C code: copies prefix, appends inet_ntop result, then replaces
                    // ALL dots with dashes in the entire name (prefix + address).
                    if let Some(ref prefix) = c.prefix {
                        name.push_str(prefix);
                    }
                    let addr_str = ipv4.to_string();
                    name.push_str(&addr_str);
                    // Replace all dots with dashes (matching C behavior where the
                    // for loop iterates from `name` start, not just the address part)
                    name = name.replace('.', "-");
                }

                name.push('.');
                name.push_str(&c.domain);

                debug!("is_rev_synth: IPv4 {} → '{}'", ipv4, name);
                return Some(name);
            }
        }
    }

    // IPv6 reverse synthesis
    if cache_flags.contains(CacheEntryFlags::IPV6) {
        if let AllAddr::V6(ipv6) = addr {
            if let Some(c) = search_domain_v6(ipv6, synth_domains) {
                let mut name = String::new();

                if c.indexed {
                    // Indexed: "prefix{index}.domain"
                    let start6 = c.start6.unwrap_or(Ipv6Addr::UNSPECIFIED);
                    let index = addr6part(ipv6).wrapping_sub(addr6part(&start6));
                    if let Some(ref prefix) = c.prefix {
                        name.push_str(prefix);
                    }
                    name.push_str(&index.to_string());
                } else {
                    // Non-indexed: "prefix{xxxx-xxxx-...-xxxx}.domain"
                    // 8 groups of 4-hex-char (2 octets each), separated by dashes
                    if let Some(ref prefix) = c.prefix {
                        name.push_str(prefix);
                    }
                    let octets = ipv6.octets();
                    for i in (0..16).step_by(2) {
                        if i > 0 {
                            name.push('-');
                        }
                        // Format as zero-padded 4-hex-char groups matching C's
                        // sprintf(frag, "%s%02x%02x", ...) behavior
                        name.push_str(&format!(
                            "{:02x}{:02x}",
                            octets[i],
                            octets[i + 1]
                        ));
                    }
                }

                name.push('.');
                name.push_str(&c.domain);

                debug!("is_rev_synth: IPv6 {} → '{}'", ipv6, name);
                return Some(name);
            }
        }
    }

    None
}

/// Retrieve the conditional domain name for an IPv4 address.
///
/// Searches the list of conditional domain configurations to find a domain
/// matching the specified IPv4 address. Conditional domains enable split-horizon
/// DNS where different client networks receive different domain suffixes.
///
/// If no conditional domain matches the address, returns the global default
/// domain suffix.
///
/// # Arguments
/// * `addr` — IPv4 address to match against conditional domain configurations.
/// * `cond_domains` — Slice of conditional domain configurations.
/// * `default_suffix` — Global default domain suffix (fallback if no match).
///
/// # Returns
/// The matched domain string, the default suffix, or `None` if neither is available.
///
/// # Source
/// Port of `src/domain.c` `get_domain()` lines 515–523.
pub fn get_domain<'a>(
    addr: Ipv4Addr,
    cond_domains: &'a [ConditionalDomain],
    default_suffix: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(c) = search_domain_v4(addr, cond_domains) {
        debug!("get_domain: {} matched domain '{}'", addr, c.domain);
        Some(&c.domain)
    } else {
        default_suffix
    }
}

/// Retrieve the conditional domain name for an IPv6 address.
///
/// IPv6 equivalent of [`get_domain`]. Searches conditional domain configurations
/// to find a domain matching the specified IPv6 address.
///
/// # Arguments
/// * `addr` — IPv6 address to match against conditional domain configurations.
/// * `cond_domains` — Slice of conditional domain configurations.
/// * `default_suffix` — Global default domain suffix (fallback if no match).
///
/// # Returns
/// The matched domain string, the default suffix, or `None` if neither is available.
///
/// # Source
/// Port of `src/domain.c` `get_domain6()` lines 699–707.
pub fn get_domain6<'a>(
    addr: &Ipv6Addr,
    cond_domains: &'a [ConditionalDomain],
    default_suffix: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(c) = search_domain_v6(addr, cond_domains) {
        debug!("get_domain6: {} matched domain '{}'", addr, c.domain);
        Some(&c.domain)
    } else {
        default_suffix
    }
}

// ---------------------------------------------------------------------------
// Internal Helper Functions
// ---------------------------------------------------------------------------

/// Find the position of the first non-digit character in a string.
///
/// Used by indexed-mode synthetic name parsing to locate the boundary
/// between the numeric index and the domain separator dot.
///
/// Returns `None` if the string is empty or contains only digits.
fn find_first_non_digit(s: &str) -> Option<usize> {
    s.find(|ch: char| !ch.is_ascii_digit())
}

/// Find the first character in `s` that is not a valid address component.
///
/// Valid characters depend on the protocol family:
/// - **Both:** ASCII digits `0-9` and dashes `-`
/// - **IPv6 only:** Hex digits `a-f`, `A-F`
///
/// Used by non-indexed synthetic name parsing to locate the boundary
/// between the address portion and the domain separator dot.
///
/// Returns `None` if all characters are valid address components.
fn find_first_non_addr_char(s: &str, is_ipv6: bool) -> Option<usize> {
    s.find(|ch: char| {
        if ch == '-' || ch.is_ascii_digit() {
            return false;
        }
        if is_ipv6 && ch.is_ascii_hexdigit() {
            return false;
        }
        true
    })
}

/// Test if an IPv4 address matches a conditional domain's range or interface list.
///
/// Supports two matching modes:
/// - **Interface-based:** Iterates through the address list, selecting IPv4 entries
///   (those without `ADDRLIST_IPV6_FLAG`), and checks if the address falls within
///   each entry's prefix.
/// - **Range-based:** Compares the address in host byte order against the configured
///   start–end range. Skips IPv6-only domains (`c.is6 == true`).
///
/// # Source
/// Port of `src/domain.c` `match_domain()` lines 412–428.
fn match_domain_v4(addr: Ipv4Addr, c: &ConditionalDomain) -> bool {
    if c.interface.is_some() {
        // Interface-based matching: iterate all IPv4 address entries
        for al in &c.address_list {
            if (al.flags & ADDRLIST_IPV6_FLAG) == 0 {
                // This is an IPv4 entry
                if let AllAddr::V4(al_addr) = al.addr {
                    if is_same_net_prefix_v4(addr, al_addr, al.prefixlen) {
                        return true;
                    }
                }
            }
        }
    } else if !c.is6 {
        // Range-based matching using host byte order (u32) comparison.
        // Equivalent to C: ntohl(addr) >= ntohl(start) && ntohl(addr) <= ntohl(end)
        let addr_val = addr.to_bits();
        let start_val = c.start.map(|a| a.to_bits()).unwrap_or(0);
        let end_val = c.end.map(|a| a.to_bits()).unwrap_or(0);
        if addr_val >= start_val && addr_val <= end_val {
            return true;
        }
    }
    false
}

/// Search the conditional domain list for an IPv4 address match.
///
/// Performs a linear search through the domain list, returning the first
/// entry whose range or interface subnet includes the given address.
///
/// # Source
/// Port of `src/domain.c` `search_domain()` lines 468–475.
fn search_domain_v4<'a>(
    addr: Ipv4Addr,
    domains: &'a [ConditionalDomain],
) -> Option<&'a ConditionalDomain> {
    domains.iter().find(|c| match_domain_v4(addr, c))
}

/// Test if an IPv6 address matches a conditional domain's range or interface list.
///
/// Supports three matching strategies:
/// - **Interface-based:** Iterates through the address list, selecting IPv6 entries
///   (those with `ADDRLIST_IPV6_FLAG`), and checks prefix matching via
///   [`Ipv6AddrExt::matches_prefix`].
/// - **Range-based with `prefixlen >= 64`:** Optimized matching within a /64 subnet —
///   verifies /64 prefix match first, then compares the lower 64-bit host parts
///   against the start–end range.
/// - **Range-based with `prefixlen < 64`:** Simple prefix-only matching using the
///   configured prefix length.
///
/// # Source
/// Port of `src/domain.c` `match_domain6()` lines 578–605.
fn match_domain_v6(addr: &Ipv6Addr, c: &ConditionalDomain) -> bool {
    if c.interface.is_some() {
        // Interface-based matching: iterate all IPv6 address entries
        for al in &c.address_list {
            if (al.flags & ADDRLIST_IPV6_FLAG) != 0 {
                // This is an IPv6 entry
                if let AllAddr::V6(ref al_addr) = al.addr {
                    if addr.matches_prefix(al_addr, al.prefixlen as u8) {
                        return true;
                    }
                }
            }
        }
    } else if c.is6 {
        let start6 = c.start6.unwrap_or(Ipv6Addr::UNSPECIFIED);

        if c.prefixlen >= 64 {
            // Optimized /64 subnet matching:
            // 1. Check that the upper 64 bits (network prefix) match
            // 2. Check that the lower 64 bits (host part) fall within range
            let addr_part = addr6part(addr);
            let end6 = c.end6.unwrap_or(Ipv6Addr::UNSPECIFIED);
            if addr.matches_prefix(&start6, 64)
                && addr_part >= addr6part(&start6)
                && addr_part <= addr6part(&end6)
            {
                return true;
            }
        } else if addr.matches_prefix(&start6, c.prefixlen as u8) {
            // Simple prefix-only matching for shorter prefixes (< /64)
            return true;
        }
    }
    false
}

/// Search the conditional domain list for an IPv6 address match.
///
/// Performs a linear search through the domain list, returning the first
/// entry whose range or interface subnet includes the given address.
///
/// # Source
/// Port of `src/domain.c` `search_domain6()` lines 649–656.
fn search_domain_v6<'a>(
    addr: &Ipv6Addr,
    domains: &'a [ConditionalDomain],
) -> Option<&'a ConditionalDomain> {
    domains.iter().find(|c| match_domain_v6(addr, c))
}

// ---------------------------------------------------------------------------
// IPv6 Address Helpers
// ---------------------------------------------------------------------------

/// Extract the lower 64 bits (host/interface identifier) of an IPv6 address.
///
/// Returns the lower 64 bits as a `u64` in host byte order. Used for range
/// comparison within a /64 subnet, where the upper 64 bits form the network
/// prefix and the lower 64 bits form the interface identifier.
///
/// # Algorithm
/// Reads octets 8–15 (the lower 64 bits) and assembles them into a `u64`
/// in big-endian order (matching network byte order).
///
/// Replaces: C `addr6part()` from `util.c` lines 1617–1627.
fn addr6part(addr: &Ipv6Addr) -> u64 {
    let octets = addr.octets();
    let mut ret: u64 = 0;
    for i in 8..16 {
        ret = (ret << 8) | (octets[i] as u64);
    }
    ret
}

/// Create a new IPv6 address with the lower 64 bits set to the given host value.
///
/// Preserves the upper 64 bits (network prefix) of the source address and
/// replaces the lower 64 bits with the provided host identifier.
///
/// # Algorithm
/// Copies the source address octets, then writes `host` into octets 8–15
/// in big-endian byte order (most significant byte first).
///
/// Replaces: C `setaddr6part()` from `util.c` lines 1662–1672.
fn set_addr6part(addr: &Ipv6Addr, host: u64) -> Ipv6Addr {
    let mut octets = addr.octets();
    let mut h = host;
    for i in (8..=15).rev() {
        octets[i] = (h & 0xff) as u8;
        h >>= 8;
    }
    Ipv6Addr::from(octets)
}

/// Check if two IPv4 addresses share the same network prefix.
///
/// Compares the first `prefixlen` bits of both addresses using a bitmask.
/// This is the IPv4 equivalent of [`Ipv6AddrExt::matches_prefix`].
///
/// # Arguments
/// * `a` — First IPv4 address.
/// * `b` — Second IPv4 address.
/// * `prefixlen` — Number of significant prefix bits (0–32).
///
/// Replaces: C `is_same_net_prefix()` from `network.c` line 1684.
fn is_same_net_prefix_v4(a: Ipv4Addr, b: Ipv4Addr, prefixlen: u32) -> bool {
    if prefixlen == 0 {
        return true;
    }
    if prefixlen >= 32 {
        return a == b;
    }
    let mask = !0u32 << (32 - prefixlen);
    (a.to_bits() & mask) == (b.to_bits() & mask)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ===================================================================
    // Test helpers
    // ===================================================================

    /// Create a simple IPv4 range conditional domain for testing.
    fn make_v4_range_domain(
        domain: &str,
        prefix: Option<&str>,
        start: Ipv4Addr,
        end: Ipv4Addr,
        indexed: bool,
    ) -> ConditionalDomain {
        ConditionalDomain {
            domain: domain.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            start: Some(start),
            end: Some(end),
            is6: false,
            indexed,
            ..ConditionalDomain::default()
        }
    }

    /// Create a simple IPv6 range conditional domain for testing.
    fn make_v6_range_domain(
        domain: &str,
        prefix: Option<&str>,
        start6: Ipv6Addr,
        end6: Ipv6Addr,
        indexed: bool,
        prefixlen: u32,
    ) -> ConditionalDomain {
        ConditionalDomain {
            domain: domain.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            start6: Some(start6),
            end6: Some(end6),
            is6: true,
            indexed,
            prefixlen,
            ..ConditionalDomain::default()
        }
    }

    // ===================================================================
    // is_name_synthetic — indexed IPv4
    // ===================================================================

    #[test]
    fn test_is_name_synthetic_indexed_ipv4_basic() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host10.example.com",
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 10)),
            _ => panic!("Expected V4 address"),
        }
    }

    #[test]
    fn test_is_name_synthetic_indexed_ipv4_zero_index() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(10, 0, 0, 100),
            Ipv4Addr::new(10, 0, 0, 200),
            true,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host0.example.com",
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 100)),
            _ => panic!("Expected V4 address"),
        }
    }

    #[test]
    fn test_is_name_synthetic_indexed_ipv4_max_index() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 10),
            true,
        )];

        // Index 10 = exactly at the boundary (end - start = 10)
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host10.example.com",
            &domains,
        );
        assert!(result.is_some());

        // Index 11 exceeds the range
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host11.example.com",
            &domains,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_is_name_synthetic_indexed_ipv4_case_insensitive_prefix() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("Host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        // "host" should match "Host" prefix (case-insensitive)
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host5.example.com",
            &domains,
        );
        assert!(result.is_some());

        // "HOST" should also match
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "HOST5.example.com",
            &domains,
        );
        assert!(result.is_some());
    }

    // ===================================================================
    // is_name_synthetic — non-indexed IPv4
    // ===================================================================

    #[test]
    fn test_is_name_synthetic_non_indexed_ipv4() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            false,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host192-168-1-100.example.com",
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100)),
            _ => panic!("Expected V4 address"),
        }
    }

    #[test]
    fn test_is_name_synthetic_non_indexed_ipv4_out_of_range() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 50),
            false,
        )];

        // 192.168.1.100 is outside the range 0-50
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host192-168-1-100.example.com",
            &domains,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_is_name_synthetic_non_indexed_ipv4_no_prefix() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            None,
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
            false,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "10-0-0-42.example.com",
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 42)),
            _ => panic!("Expected V4 address"),
        }
    }

    // ===================================================================
    // is_name_synthetic — indexed IPv6
    // ===================================================================

    #[test]
    fn test_is_name_synthetic_indexed_ipv6() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff);
        let domains = vec![make_v6_range_domain(
            "example.com",
            Some("host"),
            start6,
            end6,
            true,
            64,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV6.bits(),
            "host10.example.com",
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V6(ip) => {
                assert_eq!(ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));
            }
            _ => panic!("Expected V6 address"),
        }
    }

    // ===================================================================
    // is_name_synthetic — non-indexed IPv6
    // ===================================================================

    #[test]
    fn test_is_name_synthetic_non_indexed_ipv6() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);
        let domains = vec![make_v6_range_domain(
            "example.com",
            None,
            start6,
            end6,
            false,
            64,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV6.bits(),
            "2001-0db8-0000-0000-0000-0000-0000-0001.example.com",
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V6(ip) => {
                assert_eq!(ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            }
            _ => panic!("Expected V6 address"),
        }
    }

    // ===================================================================
    // is_name_synthetic — edge cases
    // ===================================================================

    #[test]
    fn test_is_name_synthetic_wrong_domain_suffix() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host5.other.com",
            &domains,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_is_name_synthetic_empty_name() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            None,
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        let result =
            is_name_synthetic(CacheEntryFlags::IPV4.bits(), "", &domains);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_name_synthetic_no_domains_configured() {
        let domains: Vec<ConditionalDomain> = vec![];
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host5.example.com",
            &domains,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_is_name_synthetic_no_dot_separator() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        // No dot after the digits
        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "host10",
            &domains,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_is_name_synthetic_prefix_longer_than_name() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("very-long-prefix-"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        let result = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "short",
            &domains,
        );
        assert!(result.is_none());
    }

    // ===================================================================
    // is_rev_synth — IPv4
    // ===================================================================

    #[test]
    fn test_is_rev_synth_indexed_ipv4() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            true,
        )];

        let addr = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let result = is_rev_synth(CacheEntryFlags::IPV4.bits(), &addr, &domains);
        assert_eq!(result, Some("host10.example.com".to_string()));
    }

    #[test]
    fn test_is_rev_synth_non_indexed_ipv4() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("dhcp-"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            false,
        )];

        let addr = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let result = is_rev_synth(CacheEntryFlags::IPV4.bits(), &addr, &domains);
        assert_eq!(
            result,
            Some("dhcp-192-168-1-100.example.com".to_string())
        );
    }

    #[test]
    fn test_is_rev_synth_no_prefix_ipv4() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            None,
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
            false,
        )];

        let addr = AllAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
        let result = is_rev_synth(CacheEntryFlags::IPV4.bits(), &addr, &domains);
        assert_eq!(result, Some("10-0-0-42.example.com".to_string()));
    }

    #[test]
    fn test_is_rev_synth_no_match_ipv4() {
        let domains = vec![make_v4_range_domain(
            "example.com",
            Some("host"),
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 10),
            true,
        )];

        // Address outside configured range
        let addr = AllAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = is_rev_synth(CacheEntryFlags::IPV4.bits(), &addr, &domains);
        assert!(result.is_none());
    }

    // ===================================================================
    // is_rev_synth — IPv6
    // ===================================================================

    #[test]
    fn test_is_rev_synth_indexed_ipv6() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let end6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff);
        let domains = vec![make_v6_range_domain(
            "example.com",
            Some("host"),
            start6,
            end6,
            true,
            64,
        )];

        let addr = AllAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42));
        let result = is_rev_synth(CacheEntryFlags::IPV6.bits(), &addr, &domains);
        assert_eq!(result, Some("host42.example.com".to_string()));
    }

    #[test]
    fn test_is_rev_synth_non_indexed_ipv6() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let end6 =
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);
        let domains = vec![make_v6_range_domain(
            "example.com",
            None,
            start6,
            end6,
            false,
            64,
        )];

        let addr = AllAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = is_rev_synth(CacheEntryFlags::IPV6.bits(), &addr, &domains);
        assert_eq!(
            result,
            Some(
                "2001-0db8-0000-0000-0000-0000-0000-0001.example.com"
                    .to_string()
            )
        );
    }

    // ===================================================================
    // Roundtrip tests (forward ↔ reverse)
    // ===================================================================

    #[test]
    fn test_roundtrip_indexed_ipv4() {
        let domains = vec![make_v4_range_domain(
            "lan.local",
            Some("pc"),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 254),
            true,
        )];

        // Forward: name → address
        let addr = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "pc50.lan.local",
            &domains,
        );
        assert!(addr.is_some());
        let addr = addr.unwrap();

        // Reverse: address → name
        let name =
            is_rev_synth(CacheEntryFlags::IPV4.bits(), &addr, &domains);
        assert_eq!(name, Some("pc50.lan.local".to_string()));
    }

    #[test]
    fn test_roundtrip_non_indexed_ipv4() {
        let domains = vec![make_v4_range_domain(
            "lan.local",
            None,
            Ipv4Addr::new(172, 16, 0, 0),
            Ipv4Addr::new(172, 16, 255, 255),
            false,
        )];

        // Forward
        let addr = is_name_synthetic(
            CacheEntryFlags::IPV4.bits(),
            "172-16-1-99.lan.local",
            &domains,
        );
        assert!(addr.is_some());
        let addr = addr.unwrap();
        match addr {
            AllAddr::V4(ip) => assert_eq!(ip, Ipv4Addr::new(172, 16, 1, 99)),
            _ => panic!("Expected V4"),
        }

        // Reverse
        let name =
            is_rev_synth(CacheEntryFlags::IPV4.bits(), &addr, &domains);
        assert_eq!(name, Some("172-16-1-99.lan.local".to_string()));
    }

    #[test]
    fn test_roundtrip_indexed_ipv6() {
        let start6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let end6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1000);
        let domains = vec![make_v6_range_domain(
            "v6.local",
            Some("node"),
            start6,
            end6,
            true,
            64,
        )];

        // Forward
        let addr = is_name_synthetic(
            CacheEntryFlags::IPV6.bits(),
            "node7.v6.local",
            &domains,
        );
        assert!(addr.is_some());

        // Reverse
        let name =
            is_rev_synth(CacheEntryFlags::IPV6.bits(), &addr.unwrap(), &domains);
        assert_eq!(name, Some("node7.v6.local".to_string()));
    }

    #[test]
    fn test_roundtrip_non_indexed_ipv6() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let end6 =
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);
        let domains = vec![make_v6_range_domain(
            "v6.local",
            Some("host-"),
            start6,
            end6,
            false,
            64,
        )];

        // Reverse: known address → name
        let addr =
            AllAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xabcd));
        let name =
            is_rev_synth(CacheEntryFlags::IPV6.bits(), &addr, &domains);
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(
            name,
            "host-2001-0db8-0000-0000-0000-0000-0000-abcd.v6.local"
        );

        // Forward: name → address
        let result = is_name_synthetic(
            CacheEntryFlags::IPV6.bits(),
            &name,
            &domains,
        );
        assert!(result.is_some());
        match result.unwrap() {
            AllAddr::V6(ip) => {
                assert_eq!(
                    ip,
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xabcd)
                );
            }
            _ => panic!("Expected V6"),
        }
    }

    // ===================================================================
    // get_domain / get_domain6
    // ===================================================================

    #[test]
    fn test_get_domain_with_match() {
        let domains = vec![make_v4_range_domain(
            "lan.example.com",
            None,
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            false,
        )];

        let result = get_domain(
            Ipv4Addr::new(192, 168, 1, 50),
            &domains,
            Some("default.com"),
        );
        assert_eq!(result, Some("lan.example.com"));
    }

    #[test]
    fn test_get_domain_fallback_to_default() {
        let domains = vec![make_v4_range_domain(
            "lan.example.com",
            None,
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            false,
        )];

        // Address not in range → fallback
        let result = get_domain(
            Ipv4Addr::new(10, 0, 0, 1),
            &domains,
            Some("default.com"),
        );
        assert_eq!(result, Some("default.com"));
    }

    #[test]
    fn test_get_domain_no_match_no_default() {
        let domains: Vec<ConditionalDomain> = vec![];
        let result = get_domain(Ipv4Addr::new(10, 0, 0, 1), &domains, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_domain6_with_match() {
        let start6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let end6 =
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);
        let domains = vec![make_v6_range_domain(
            "v6.example.com",
            None,
            start6,
            end6,
            false,
            64,
        )];

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = get_domain6(&addr, &domains, Some("default.com"));
        assert_eq!(result, Some("v6.example.com"));
    }

    #[test]
    fn test_get_domain6_fallback_to_default() {
        let domains: Vec<ConditionalDomain> = vec![];
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = get_domain6(&addr, &domains, Some("default.com"));
        assert_eq!(result, Some("default.com"));
    }

    // ===================================================================
    // match_domain_v4
    // ===================================================================

    #[test]
    fn test_match_domain_v4_range_in_range() {
        let c = make_v4_range_domain(
            "example.com",
            None,
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            false,
        );

        assert!(match_domain_v4(Ipv4Addr::new(192, 168, 1, 0), &c));
        assert!(match_domain_v4(Ipv4Addr::new(192, 168, 1, 128), &c));
        assert!(match_domain_v4(Ipv4Addr::new(192, 168, 1, 255), &c));
    }

    #[test]
    fn test_match_domain_v4_range_out_of_range() {
        let c = make_v4_range_domain(
            "example.com",
            None,
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            false,
        );

        assert!(!match_domain_v4(Ipv4Addr::new(192, 168, 2, 0), &c));
        assert!(!match_domain_v4(Ipv4Addr::new(10, 0, 0, 1), &c));
    }

    #[test]
    fn test_match_domain_v4_interface_based() {
        let c = ConditionalDomain {
            domain: "lan.example.com".to_string(),
            interface: Some("eth0".to_string()),
            address_list: vec![AddressListEntry {
                addr: AllAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                prefixlen: 24,
                flags: 0, // Not IPv6
            }],
            ..ConditionalDomain::default()
        };

        assert!(match_domain_v4(Ipv4Addr::new(192, 168, 1, 100), &c));
        assert!(!match_domain_v4(Ipv4Addr::new(192, 168, 2, 1), &c));
    }

    #[test]
    fn test_match_domain_v4_skips_ipv6_domain() {
        let c = ConditionalDomain {
            domain: "example.com".to_string(),
            is6: true, // IPv6 domain — must not match IPv4 queries
            start: Some(Ipv4Addr::new(192, 168, 1, 0)),
            end: Some(Ipv4Addr::new(192, 168, 1, 255)),
            ..ConditionalDomain::default()
        };

        assert!(!match_domain_v4(Ipv4Addr::new(192, 168, 1, 1), &c));
    }

    // ===================================================================
    // match_domain_v6
    // ===================================================================

    #[test]
    fn test_match_domain_v6_range_with_prefix64() {
        let c = make_v6_range_domain(
            "example.com",
            None,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            false,
            64,
        );

        // Within range
        assert!(match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50),
            &c
        ));
        // At boundaries
        assert!(match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            &c
        ));
        assert!(match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff),
            &c
        ));
        // Beyond range
        assert!(!match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 1, 0),
            &c
        ));
        // Different /64 prefix
        assert!(!match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
            &c
        ));
    }

    #[test]
    fn test_match_domain_v6_short_prefix() {
        let c = make_v6_range_domain(
            "example.com",
            None,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(
                0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            false,
            32, // /32 prefix
        );

        // Same /32 prefix → match
        assert!(match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
            &c
        ));
        // Different /32 prefix → no match
        assert!(!match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1),
            &c
        ));
    }

    #[test]
    fn test_match_domain_v6_interface_based() {
        let c = ConditionalDomain {
            domain: "v6.example.com".to_string(),
            is6: true,
            interface: Some("eth0".to_string()),
            address_list: vec![AddressListEntry {
                addr: AllAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                prefixlen: 64,
                flags: ADDRLIST_IPV6_FLAG,
            }],
            ..ConditionalDomain::default()
        };

        assert!(match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            &c
        ));
        assert!(!match_domain_v6(
            &Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1),
            &c
        ));
    }

    // ===================================================================
    // IPv6 address helpers
    // ===================================================================

    #[test]
    fn test_addr6part_basic() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(addr6part(&addr), 1);
    }

    #[test]
    fn test_addr6part_full() {
        // Lower 64 bits = 0x0000_0000_0000_abcd
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xabcd);
        assert_eq!(addr6part(&addr), 0xabcd);
    }

    #[test]
    fn test_addr6part_uses_octets() {
        // The segments() method gives us 16-bit segments; octets gives us bytes
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let segs = addr.segments();
        // Verify segments are correct
        assert_eq!(segs[4], 0x1234);
        let expected: u64 =
            (0x1234u64 << 48) | (0x5678u64 << 32) | (0x9abcu64 << 16) | 0xdef0u64;
        assert_eq!(addr6part(&addr), expected);
    }

    #[test]
    fn test_set_addr6part_basic() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let result = set_addr6part(&addr, 0x42);
        assert_eq!(
            result,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)
        );
    }

    #[test]
    fn test_set_addr6part_preserves_prefix() {
        let addr = Ipv6Addr::new(0xfd00, 0x1234, 0x5678, 0x9abc, 0, 0, 0, 0);
        let result = set_addr6part(&addr, 0xdead_beef);
        assert_eq!(
            result,
            Ipv6Addr::new(0xfd00, 0x1234, 0x5678, 0x9abc, 0, 0, 0xdead, 0xbeef)
        );
    }

    #[test]
    fn test_addr6part_roundtrip() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let host_val: u64 = 0x0102_0304_0506_0708;
        let new_addr = set_addr6part(&addr, host_val);
        assert_eq!(addr6part(&new_addr), host_val);
    }

    // ===================================================================
    // is_same_net_prefix_v4
    // ===================================================================

    #[test]
    fn test_is_same_net_prefix_v4_exact() {
        assert!(is_same_net_prefix_v4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 100),
            32
        ));
    }

    #[test]
    fn test_is_same_net_prefix_v4_slash24() {
        assert!(is_same_net_prefix_v4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            24
        ));
        assert!(!is_same_net_prefix_v4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 2, 100),
            24
        ));
    }

    #[test]
    fn test_is_same_net_prefix_v4_zero() {
        // /0 matches everything
        assert!(is_same_net_prefix_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            0
        ));
    }
}

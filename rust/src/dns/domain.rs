// Copyright (C) 2024 Simon Kelley and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

//! Domain name utilities, synthetic name generation, and conditional domain
//! selection.
//!
//! This module provides:
//! - **Conditional domain matching**: Selects a domain suffix for DNS/DHCP
//!   clients based on their IP address, supporting split-horizon DNS
//!   configurations.
//! - **Synthetic name generation**: Creates forward and reverse DNS names
//!   from IP addresses, enabling automatic PTR record creation without
//!   manual zone editing.
//! - **Domain name validation**: Enforces RFC 1035 constraints (label length
//!   ≤ 63, total name length ≤ 1025 bytes).
//!
//! Migrated from C `src/domain.c` (707 lines).  All manual memory management
//! (`malloc`/`free`, `strncpy`, `strncat`) replaced with Rust owned
//! `String`/`&str`.  In-place string mutation with restore-on-failure
//! replaced by immutable slicing and `String::replace()`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::{debug, trace};

use crate::core::types::{DnsmasqError, DnsmasqResult};
use crate::core::util::{
    addr6_host_part, hostname_eq, is_same_net, is_same_net6, set_addr6_host_part,
};
use crate::dns::protocol::{MAXDNAME, MAXLABEL};

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Conditional domain configuration for split-horizon DNS and synthetic name
/// generation.
///
/// Replaces C `struct cond_domain` (`dnsmasq.h` line 1216).  Each instance
/// maps an IP address range to a domain suffix and optionally enables
/// automatic synthetic (forward / reverse) DNS name generation.
///
/// # IPv4 Example
///
/// ```text
/// ConditionalDomain {
///     domain: "internal.example.com",
///     prefix: Some("host-"),
///     addr4_range: Some((192.168.1.0, 192.168.1.255)),
///     is_synthetic: true,   // indexed mode
///     index: 0,
///     ..
/// }
/// // 192.168.1.5 → "host-5.internal.example.com"
/// ```
///
/// # IPv6 Example
///
/// ```text
/// ConditionalDomain {
///     domain: "ip6.example.com",
///     prefix: None,
///     addr6_range: Some((2001:db8::1, 2001:db8::ff)),
///     is_synthetic: false,  // dash-encoded mode
///     index: 0,
///     ..
/// }
/// // 2001:db8::5 → "2001-db8--5.ip6.example.com"
/// ```
#[derive(Debug, Clone)]
pub struct ConditionalDomain {
    /// Domain suffix (e.g., `"internal.example.com"`).
    pub domain: String,

    /// Optional text prefix prepended to synthetic names (e.g., `"host-"`).
    pub prefix: Option<String>,

    /// IPv4 address range `(start, end)` for matching.
    /// `None` if this domain applies only to IPv6.
    /// When both `start` and `end` are `0.0.0.0`, matches all IPv4 addresses.
    pub addr4_range: Option<(Ipv4Addr, Ipv4Addr)>,

    /// IPv6 address range `(start, end)` for matching.
    /// `None` if this domain applies only to IPv4.
    pub addr6_range: Option<(Ipv6Addr, Ipv6Addr)>,

    /// Whether this domain uses indexed synthetic name generation.
    ///
    /// - `true` (indexed): names are `{prefix}{index}.{domain}` where
    ///   `index = address − range_start`.
    /// - `false` (dash-encoded): names are `{prefix}{addr-with-dashes}.{domain}`.
    ///
    /// Maps to C's `cond_domain.indexed` field.
    pub is_synthetic: bool,

    /// Numeric index for synthetic name generation bookkeeping.
    /// In indexed mode, represents the current offset or identifier.
    pub index: u32,

    /// IPv6 prefix length for subnet-based matching.
    ///
    /// - `prefixlen >= 64`: match requires same /64 prefix AND host part
    ///   within `addr6_range`.
    /// - `0 < prefixlen < 64`: match requires same prefix of this length.
    /// - `0`: range-based matching only.
    ///
    /// Maps to C's `cond_domain.prefixlen` field.
    pub prefixlen: u8,
}

impl ConditionalDomain {
    /// Create a new `ConditionalDomain` with all fields specified.
    pub fn new(
        domain: String,
        prefix: Option<String>,
        addr4_range: Option<(Ipv4Addr, Ipv4Addr)>,
        addr6_range: Option<(Ipv6Addr, Ipv6Addr)>,
        is_synthetic: bool,
        index: u32,
        prefixlen: u8,
    ) -> Self {
        Self {
            domain,
            prefix,
            addr4_range,
            addr6_range,
            is_synthetic,
            index,
            prefixlen,
        }
    }
}

// ---------------------------------------------------------------------------
// Private Helpers
// ---------------------------------------------------------------------------

/// Convert an IPv4 prefix length (0–32) to a dotted-decimal netmask.
///
/// Used to bridge between prefix-length notation and [`is_same_net()`] which
/// requires a netmask parameter.
fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    if prefix_len >= 32 {
        return Ipv4Addr::new(255, 255, 255, 255);
    }
    let mask_bits: u32 = !((1u32 << (32 - prefix_len)) - 1);
    Ipv4Addr::from(mask_bits)
}

/// Test whether an IPv4 address matches a conditional domain's range.
///
/// Replaces C `match_domain()` (`domain.c` line 412).  The interface-based
/// matching path from C (walking `addrlist` via `c->al`) is replaced by
/// prefix-based subnet matching using [`is_same_net()`] when `start == end`
/// and a non-zero `prefixlen` is present.
///
/// # Match Rules
///
/// 1. If `start == 0.0.0.0` AND `end == 0.0.0.0` → match all addresses.
/// 2. If `start == end` AND `prefixlen > 0` → subnet match via
///    [`is_same_net()`].
/// 3. Otherwise → integer range comparison `start ≤ addr ≤ end`.
fn match_domain_v4(addr: &Ipv4Addr, c: &ConditionalDomain) -> bool {
    let (start, end) = match c.addr4_range {
        Some(range) => range,
        None => return false,
    };

    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    let addr_u32 = u32::from(*addr);

    // Match-all sentinel: both start and end are zero.
    if start_u32 == 0 && end_u32 == 0 {
        trace!(%addr, domain = %c.domain, "IPv4 match-all domain");
        return true;
    }

    // Subnet-based match: when start == end and prefixlen is set, use
    // is_same_net() — this replaces C's interface/addrlist matching path
    // which called is_same_net_prefix().
    if start == end && c.prefixlen > 0 && c.prefixlen < 32 {
        let mask = prefix_to_mask(c.prefixlen);
        let matched = is_same_net(*addr, start, mask);
        trace!(%addr, %start, prefixlen = c.prefixlen, matched, "IPv4 subnet match");
        return matched;
    }

    // Standard range comparison (host byte order).
    let matched = addr_u32 >= start_u32 && addr_u32 <= end_u32;
    trace!(%addr, %start, %end, matched, "IPv4 range match");
    matched
}

/// Test whether an IPv6 address matches a conditional domain's range.
///
/// Replaces C `match_domain6()` (`domain.c` line 578).  Uses
/// [`is_same_net6()`] for prefix matching and [`addr6_host_part()`] for
/// host-part range comparison.
///
/// # Match Rules
///
/// - `prefixlen >= 64`: First checks /64 prefix match, then compares the
///   lower 64-bit host portion against `(start_host..=end_host)`.
/// - `0 < prefixlen < 64`: Simple prefix match of the given length.
/// - `prefixlen == 0`: Full 128-bit octet-wise range comparison.
fn match_domain_v6(addr: &Ipv6Addr, c: &ConditionalDomain) -> bool {
    let (start, end) = match c.addr6_range {
        Some(range) => range,
        None => return false,
    };

    if c.prefixlen >= 64 {
        // Must share the same /64 prefix with the start address.
        if !is_same_net6(*addr, start, 64) {
            trace!(%addr, %start, "IPv6 /64 prefix mismatch");
            return false;
        }
        // Compare host parts (lower 64 bits).
        let host = addr6_host_part(addr);
        let s = addr6_host_part(&start);
        let e = addr6_host_part(&end);
        let matched = host >= s && host <= e;
        trace!(%addr, host, s, e, matched, "IPv6 host-part range match");
        matched
    } else if c.prefixlen > 0 {
        // Simple prefix match.
        let matched = is_same_net6(*addr, start, c.prefixlen);
        trace!(%addr, %start, prefixlen = c.prefixlen, matched, "IPv6 prefix match");
        matched
    } else {
        // No prefix length set — full 128-bit octet-wise comparison.
        let a = addr.octets();
        let s = start.octets();
        let e = end.octets();
        let matched = a >= s && a <= e;
        trace!(%addr, %start, %end, matched, "IPv6 full-range match");
        matched
    }
}

/// Validate that a synthesised name does not exceed RFC 1035 limits.
///
/// Returns `Err(DnsmasqError::DnsProtocol)` if the total name exceeds
/// [`MAXDNAME`] bytes or any single label exceeds [`MAXLABEL`] bytes.
fn validate_synthetic_name(name: &str) -> DnsmasqResult<()> {
    if name.len() >= MAXDNAME {
        return Err(DnsmasqError::DnsProtocol(format!(
            "synthetic name length {} exceeds MAXDNAME ({})",
            name.len(),
            MAXDNAME,
        )));
    }
    for label in name.split('.') {
        if label.len() > MAXLABEL {
            return Err(DnsmasqError::DnsProtocol(format!(
                "label length {} exceeds MAXLABEL ({})",
                label.len(),
                MAXLABEL,
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API: Synthetic Name Resolution
// ---------------------------------------------------------------------------

/// Validate a DNS name against configured synthetic domain patterns and
/// extract the embedded IP address.
///
/// Replaces C `is_name_synthetic()` (`domain.c` line 134).  For each entry
/// in `synth_domains`, checks whether `name` ends with `.{domain}`, has the
/// expected prefix, and contains a valid address encoding (indexed decimal
/// or dash-encoded IP literal).
///
/// # Arguments
///
/// * `name` — The DNS name to test (e.g., `"host-5.internal.example.com"`).
/// * `synth_domains` — Slice of configured synthetic domain entries.
///
/// # Returns
///
/// - `Ok(Some((addr, index)))` — match found; `addr` is the extracted IP
///   and `index` identifies the matching entry in `synth_domains`.
/// - `Ok(None)` — no matching synthetic domain.
/// - `Err(DnsmasqError::DnsProtocol)` — name violates RFC 1035 constraints.
pub fn is_name_synthetic(
    name: &str,
    synth_domains: &[ConditionalDomain],
) -> DnsmasqResult<Option<(IpAddr, usize)>> {
    // Quick validation: empty names never match.
    if name.is_empty() {
        return Ok(None);
    }

    // Validate the input name against RFC 1035 limits.
    validate_synthetic_name(name)?;

    for (idx, c) in synth_domains.iter().enumerate() {
        let domain = &c.domain;
        let name_len = name.len();
        let domain_len = domain.len();

        // Name must be longer than ".{domain}" (at least 1 char + dot + domain).
        if name_len <= domain_len + 1 {
            continue;
        }

        // Check that the character before the domain suffix is a dot.
        let dot_pos = name_len - domain_len - 1;
        if name.as_bytes()[dot_pos] != b'.' {
            continue;
        }

        // Case-insensitive domain suffix comparison (RFC 1035 §3.1).
        if !hostname_eq(&name[dot_pos + 1..], domain) {
            continue;
        }

        // Everything before the dot is the "local part" (prefix + address).
        let local_part = &name[..dot_pos];

        // Check the optional prefix (case-sensitive, matching C strncmp).
        let addr_part = match &c.prefix {
            Some(prefix) => {
                if local_part.starts_with(prefix.as_str()) {
                    &local_part[prefix.len()..]
                } else {
                    continue; // Prefix mismatch — try next domain.
                }
            }
            None => local_part,
        };

        // Address part must not be empty.
        if addr_part.is_empty() {
            continue;
        }

        // --- Try IPv4 matching ---
        if let Some((start, end)) = c.addr4_range {
            if c.is_synthetic {
                // Indexed mode: addr_part is a decimal index.
                // C equivalent: strtol(name, &end, 10)
                if let Ok(offset) = addr_part.parse::<u32>() {
                    let start_u32 = u32::from(start);
                    let end_u32 = u32::from(end);
                    if let Some(result_u32) = start_u32.checked_add(offset) {
                        if result_u32 <= end_u32 {
                            let result_addr = Ipv4Addr::from(result_u32);
                            debug!(
                                %name, %result_addr, offset,
                                "synthetic IPv4 indexed match"
                            );
                            return Ok(Some((IpAddr::V4(result_addr), idx)));
                        }
                    }
                }
            } else {
                // Non-indexed mode: addr_part is a dash-encoded IPv4 literal
                // (e.g., "192-168-1-100" → "192.168.1.100").
                let addr_str = addr_part.replace('-', ".");
                if let Ok(v4_addr) = addr_str.parse::<Ipv4Addr>() {
                    if match_domain_v4(&v4_addr, c) {
                        debug!(
                            %name, %v4_addr,
                            "synthetic IPv4 dash-encoded match"
                        );
                        return Ok(Some((IpAddr::V4(v4_addr), idx)));
                    }
                }
            }
        }

        // --- Try IPv6 matching ---
        if let Some((start, end)) = c.addr6_range {
            if c.is_synthetic {
                // Indexed mode: addr_part is a decimal index into host-part.
                // C equivalent: strtoull(name, &end, 10) + addr6part()
                if let Ok(offset) = addr_part.parse::<u64>() {
                    let s = addr6_host_part(&start);
                    let e = addr6_host_part(&end);
                    if let Some(result_host) = s.checked_add(offset) {
                        if result_host <= e {
                            let mut result_addr = start;
                            set_addr6_host_part(&mut result_addr, result_host);
                            debug!(
                                %name, %result_addr, offset,
                                "synthetic IPv6 indexed match"
                            );
                            return Ok(Some((IpAddr::V6(result_addr), idx)));
                        }
                    }
                }
            } else {
                // Non-indexed mode: addr_part is a dash-encoded IPv6 literal
                // (e.g., "2001-db8--1" → "2001:db8::1").
                let addr_str = addr_part.replace('-', ":");
                if let Ok(v6_addr) = addr_str.parse::<Ipv6Addr>() {
                    if match_domain_v6(&v6_addr, c) {
                        debug!(
                            %name, %v6_addr,
                            "synthetic IPv6 dash-encoded match"
                        );
                        return Ok(Some((IpAddr::V6(v6_addr), idx)));
                    }
                }
            }
        }
    }

    trace!(%name, "no synthetic domain match");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Public API: Reverse Synthetic Name Generation
// ---------------------------------------------------------------------------

/// Generate a synthetic domain name from an IP address for reverse DNS.
///
/// Replaces C `is_rev_synth()` (`domain.c` line 303).  Finds the first
/// matching synthetic domain and constructs a forward name encoding the
/// address.
///
/// # Formats
///
/// | Mode | IPv4 | IPv6 |
/// |------|------|------|
/// | **Indexed** | `{prefix}{index}.{domain}` | `{prefix}{host_index}.{domain}` |
/// | **Dash-encoded** | `{prefix}{a-b-c-d}.{domain}` | `{prefix}{addr-with-dashes}.{domain}` |
///
/// Where *index* = `addr − start` (IPv4) or `host_part(addr) − host_part(start)` (IPv6).
///
/// # Returns
///
/// - `Ok(Some(name))` — synthetic name generated.
/// - `Ok(None)` — no matching synthetic domain for this address.
/// - `Err(DnsmasqError::DnsProtocol)` — generated name exceeds RFC 1035 limits.
pub fn is_rev_synth(
    addr: &IpAddr,
    synth_domains: &[ConditionalDomain],
) -> DnsmasqResult<Option<String>> {
    match addr {
        IpAddr::V4(v4) => rev_synth_v4(v4, synth_domains),
        IpAddr::V6(v6) => rev_synth_v6(v6, synth_domains),
    }
}

/// Internal: reverse-synthesise an IPv4 name.
fn rev_synth_v4(
    v4: &Ipv4Addr,
    synth_domains: &[ConditionalDomain],
) -> DnsmasqResult<Option<String>> {
    for c in synth_domains {
        // Only consider domains with IPv4 configuration.
        if c.addr4_range.is_none() {
            continue;
        }
        if !match_domain_v4(v4, c) {
            continue;
        }

        let mut name = String::with_capacity(128);

        if c.is_synthetic {
            // Indexed mode: name = "{prefix}{index}"
            // C: index = ntohl(addr) − ntohl(start)
            if let Some((start, _end)) = c.addr4_range {
                let index = u32::from(*v4).wrapping_sub(u32::from(start));
                if let Some(ref prefix) = c.prefix {
                    name.push_str(prefix);
                }
                name.push_str(&index.to_string());
            }
        } else {
            // Non-indexed mode: name = "{prefix}{a-b-c-d}"
            // C: inet_ntop + replace '.' with '-'
            if let Some(ref prefix) = c.prefix {
                name.push_str(prefix);
            }
            name.push_str(&v4.to_string().replace('.', "-"));
        }

        // Append ".{domain}"
        name.push('.');
        name.push_str(&c.domain);

        validate_synthetic_name(&name)?;

        debug!(addr = %v4, %name, "reverse synthetic IPv4 name generated");
        return Ok(Some(name));
    }

    Ok(None)
}

/// Internal: reverse-synthesise an IPv6 name.
fn rev_synth_v6(
    v6: &Ipv6Addr,
    synth_domains: &[ConditionalDomain],
) -> DnsmasqResult<Option<String>> {
    for c in synth_domains {
        // Only consider domains with IPv6 configuration.
        if c.addr6_range.is_none() {
            continue;
        }
        if !match_domain_v6(v6, c) {
            continue;
        }

        let mut name = String::with_capacity(128);

        if c.is_synthetic {
            // Indexed mode: name = "{prefix}{host_part_index}"
            // C: index = addr6part(addr) − addr6part(start)
            if let Some((start, _end)) = c.addr6_range {
                let index = addr6_host_part(v6).wrapping_sub(addr6_host_part(&start));
                if let Some(ref prefix) = c.prefix {
                    name.push_str(prefix);
                }
                name.push_str(&index.to_string());
            }
        } else {
            // Non-indexed mode: name = "{prefix}{ipv6-with-dashes}"
            // C: inet_ntop + replace ':' with '-'
            if let Some(ref prefix) = c.prefix {
                name.push_str(prefix);
            }
            name.push_str(&v6.to_string().replace(':', "-"));
        }

        // Append ".{domain}"
        name.push('.');
        name.push_str(&c.domain);

        validate_synthetic_name(&name)?;

        debug!(addr = %v6, %name, "reverse synthetic IPv6 name generated");
        return Ok(Some(name));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Public API: Conditional Domain Selection
// ---------------------------------------------------------------------------

/// Select the appropriate domain suffix for an IPv4 client address.
///
/// Replaces C `get_domain()` (`domain.c` line 515).  Walks the
/// `cond_domains` list and returns the first domain whose IPv4 range
/// contains `addr`.  Falls back to `default_domain` if no conditional
/// domain matches.
///
/// # Returns
///
/// - `Ok(Some(domain))` — a matching domain (conditional or default).
/// - `Ok(None)` — no match and no default domain configured.
pub fn get_domain<'a>(
    addr: &Ipv4Addr,
    cond_domains: &'a [ConditionalDomain],
    default_domain: Option<&'a str>,
) -> DnsmasqResult<Option<&'a str>> {
    for c in cond_domains {
        if c.addr4_range.is_some() && match_domain_v4(addr, c) {
            debug!(%addr, domain = %c.domain, "IPv4 conditional domain matched");
            return Ok(Some(c.domain.as_str()));
        }
    }
    trace!(%addr, "no IPv4 conditional domain, using default");
    Ok(default_domain)
}

/// Select the appropriate domain suffix for an IPv6 client address.
///
/// Replaces C `get_domain6()` (`domain.c` line 699).  Walks the
/// `cond_domains` list and returns the first domain whose IPv6 range
/// contains `addr`.  Falls back to `default_domain` if no conditional
/// domain matches or `addr` is `None`.
///
/// # Returns
///
/// - `Ok(Some(domain))` — a matching domain (conditional or default).
/// - `Ok(None)` — no match and no default domain configured.
pub fn get_domain6<'a>(
    addr: Option<&Ipv6Addr>,
    cond_domains: &'a [ConditionalDomain],
    default_domain: Option<&'a str>,
) -> DnsmasqResult<Option<&'a str>> {
    // C version: if addr is NULL, return domain_suffix directly.
    if let Some(v6) = addr {
        for c in cond_domains {
            if c.addr6_range.is_some() && match_domain_v6(v6, c) {
                debug!(%v6, domain = %c.domain, "IPv6 conditional domain matched");
                return Ok(Some(c.domain.as_str()));
            }
        }
        trace!(%v6, "no IPv6 conditional domain, using default");
    }
    Ok(default_domain)
}

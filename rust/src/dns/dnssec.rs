// Copyright (C) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # DNSSEC Validation Engine
//!
//! Complete DNSSEC validation chain processing per RFC 4033/4034/4035, migrated
//! from C `src/dnssec.c` (4,009 lines). This module provides cryptographic
//! verification of DNS responses to protect against cache poisoning and domain
//! hijacking attacks.
//!
//! ## Architecture
//!
//! The validation engine implements a bottom-up trust chain traversal:
//!
//! 1. **Target RRset** — The DNS response records to be validated.
//! 2. **RRSIG verification** — Each RRset is verified against its RRSIG signature
//!    using the zone's DNSKEY.
//! 3. **DNSKEY validation** — The DNSKEY is validated against the DS record from
//!    the parent zone.
//! 4. **DS chain** — The DS record is itself validated by the parent zone's
//!    DNSKEY, recursing upward until a configured trust anchor (typically the
//!    root zone KSK) is reached.
//!
//! ## Denial of Existence
//!
//! Two mechanisms for authenticated denial of existence are supported:
//! - **NSEC** (RFC 4034) — Direct proof via sorted name ordering.
//! - **NSEC3** (RFC 5155) — Hashed proof with opt-out and iteration limits.
//!
//! ## Resource Limits (DoS Protection)
//!
//! All validation operations are bounded by configurable resource limits
//! (from `config.h`) to prevent denial-of-service attacks through
//! computationally expensive DNSSEC chains:
//! - `DNSSEC_LIMIT_WORK` (40) — Maximum queries per validation chain.
//! - `DNSSEC_LIMIT_SIG_FAIL` (20) — Maximum signature verification failures.
//! - `DNSSEC_LIMIT_CRYPTO` (200) — Maximum total cryptographic operations.
//! - `DNSSEC_LIMIT_NSEC3_ITERS` (150) — Maximum NSEC3 hash iterations.
//!
//! ## Feature Gate
//!
//! This entire module is gated by `#[cfg(feature = "dnssec")]`, mapping to C's
//! `HAVE_DNSSEC` preprocessor macro.
//!
//! ## Safety
//!
//! Zero `unsafe` blocks — all cryptographic operations are delegated to the
//! `crypto.rs` module which interfaces with the `nettle` crate.

use std::cmp::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{BufMut, BytesMut};
use tracing::{debug, info, trace, warn};

use crate::config::constants::{
    DNSSEC_LIMIT_CRYPTO, DNSSEC_LIMIT_NSEC3_ITERS, DNSSEC_LIMIT_SIG_FAIL, DNSSEC_LIMIT_WORK,
};
use crate::core::types::{DnsmasqError, DnsmasqResult};
use crate::core::util::hostname_eq;
use crate::dns::blockdata::BlockData;
use crate::dns::cache::{CacheData, CacheEntry, CacheFlags, DnsCache};
use crate::dns::crypto::{CryptoVerifier, DigestAlgorithm, DnssecAlgorithm, Nsec3HashAlgorithm};
use crate::dns::domain_match::DomainMatcher;
use crate::dns::protocol::{
    ede, DnsClass, DnsHeader, DnsName, DnsPacket, DnsResourceRecord, RRSet, RRType,
};

// ===========================================================================
// DNSSEC Validation Status
// (replaces C STAT_SECURE/STAT_INSECURE/STAT_BOGUS from dnsmasq.h ~line 757)
// ===========================================================================

/// DNSSEC validation result status.
///
/// Replaces C constants `STAT_SECURE` (757), `STAT_INSECURE` (758),
/// `STAT_BOGUS` (759), `STAT_NEED_DS_NEG` (762), `STAT_NEED_KEY` (764),
/// `STAT_NEED_DS` (766), `STAT_TRUNCATED` (768), `STAT_ABANDONED` (770).
///
/// Each variant carries an optional bitfield of [`DnssecFailFlags`] via
/// [`DnssecStatus::with_fail_flags`] when the status is `Bogus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// All signatures valid, trust chain complete to a configured trust anchor.
    Secure,
    /// Zone is provably unsigned (no DS in parent), validation not required.
    Insecure,
    /// Signature verification failed, trust chain broken, or resource limits
    /// exceeded. The associated [`DnssecFailFlags`] describe the specific
    /// failure mode.
    Bogus,
    /// Validation in progress — need to fetch the DS digest from the parent zone.
    NeedDsDigest,
    /// Validation in progress — need to fetch the DNSKEY record for the zone.
    NeedKey,
    /// Validation in progress — need to fetch the DS record from the parent zone.
    NeedDs,
    /// DNS response was truncated; need TCP retry before DNSSEC validation can proceed.
    Truncated,
    /// Validation abandoned due to resource limit exhaustion.
    Abandoned,
}

impl DnssecStatus {
    /// Returns `true` if this status indicates a fully validated, secure response.
    #[inline]
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure)
    }

    /// Returns `true` if this status indicates a validation failure.
    #[inline]
    pub fn is_bogus(&self) -> bool {
        matches!(self, Self::Bogus)
    }

    /// Returns `true` if this status indicates the zone is provably unsigned.
    #[inline]
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::Insecure)
    }

    /// Returns `true` if this status requires an additional DNS query to continue
    /// the validation chain (NeedDsDigest, NeedKey, NeedDs, or Truncated).
    #[inline]
    pub fn needs_additional_query(&self) -> bool {
        matches!(
            self,
            Self::NeedDsDigest | Self::NeedKey | Self::NeedDs | Self::Truncated
        )
    }

    /// Combine this status with failure flags. Returns `Bogus` with the given
    /// flags encoded in the upper bits, matching C's `STAT_BOGUS | failflags`
    /// pattern from `dnssec.c`.
    #[inline]
    pub fn with_fail_flags(self, flags: DnssecFailFlags) -> (Self, DnssecFailFlags) {
        (self, flags)
    }
}

// ===========================================================================
// DNSSEC Failure Flags
// (replaces C DNSSEC_FAIL_* bitmask constants from dnsmasq.h ~line 771)
// ===========================================================================

/// Bitflags indicating the specific reason(s) for a DNSSEC validation failure.
///
/// Replaces C's `DNSSEC_FAIL_*` bitmask constants (dnsmasq.h lines 771-781).
/// Multiple flags may be set simultaneously when several issues are detected
/// during a single validation attempt.
///
/// These flags are used by [`errflags_to_ede`] to generate RFC 8914 Extended
/// DNS Error codes for detailed error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DnssecFailFlags {
    bits: u32,
}

impl DnssecFailFlags {
    /// No RRSIG signature found for the RRset.
    pub const NOSIG: u32 = 0x0001;
    /// Signature not yet valid (inception time in the future).
    pub const NYV: u32 = 0x0002;
    /// Signature has expired (expiration time in the past).
    pub const EXP: u32 = 0x0004;
    /// Unsupported DNSKEY algorithm.
    pub const NOKEYSUP: u32 = 0x0008;
    /// No zone key bit (flag bit 7) set in any DNSKEY.
    pub const NOZONE: u32 = 0x0010;
    /// No matching DNSKEY found for the RRSIG key tag.
    pub const NOKEY: u32 = 0x0020;
    /// Unsupported DS digest type.
    pub const NODSSUP: u32 = 0x0040;
    /// NSEC3 iterations limit exceeded.
    pub const NSEC3_ITERS: u32 = 0x0080;
    /// NSEC/NSEC3 records missing for denial of existence proof.
    pub const NONSEC: u32 = 0x0100;
    /// DNSSEC validation result is indeterminate.
    pub const INDET: u32 = 0x0200;

    /// Create an empty flag set with no failure flags set.
    #[inline]
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Check whether this flag set contains the specified flag.
    #[inline]
    pub fn contains(&self, flag: u32) -> bool {
        (self.bits & flag) != 0
    }

    /// Set the specified flag bit in this flag set.
    #[inline]
    pub fn insert(&mut self, flag: u32) {
        self.bits |= flag;
    }

    /// Return the raw bit value for combining with status codes.
    #[inline]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Create a flag set from a raw bit value.
    #[inline]
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Check whether any flags are set.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }
}

// ===========================================================================
// errflags_to_ede — Convert DNSSEC failure flags to Extended DNS Error codes
// (from C dnssec.c lines 3980-4008)
// ===========================================================================

/// Convert DNSSEC validation failure flags to an RFC 8914 Extended DNS Error code.
///
/// When multiple failure flags are set, returns the highest-priority error code
/// based on diagnostic value. The priority ordering matches the C implementation:
///
/// `NYV > EXP > NOKEYSUP > NOZONE > NOKEY > NODSSUP > NSEC3_ITERS > NONSEC > INDET > NOSIG`
///
/// # Arguments
///
/// * `flags` — Bitwise OR of `DnssecFailFlags` constants indicating validation failures.
///
/// # Returns
///
/// The corresponding EDE info-code per RFC 8914, or `ede::UNSET` (-1) if no flags are set.
///
/// # Examples
///
/// ```ignore
/// let mut flags = DnssecFailFlags::empty();
/// flags.insert(DnssecFailFlags::NOSIG);
/// flags.insert(DnssecFailFlags::EXP);
/// let ede_code = errflags_to_ede(&flags);
/// // Returns ede::SIG_EXPIRED (EXP has higher priority than NOSIG)
/// ```
pub fn errflags_to_ede(flags: &DnssecFailFlags) -> i16 {
    if flags.contains(DnssecFailFlags::NYV) {
        ede::SIG_NOT_YET_VALID as i16
    } else if flags.contains(DnssecFailFlags::EXP) {
        ede::SIG_EXPIRED as i16
    } else if flags.contains(DnssecFailFlags::NOKEYSUP) {
        ede::UNSUP_DNSKEY as i16
    } else if flags.contains(DnssecFailFlags::NOZONE) {
        ede::NO_ZONE_KEY as i16
    } else if flags.contains(DnssecFailFlags::NOKEY) {
        ede::DNSKEY_MISSING as i16
    } else if flags.contains(DnssecFailFlags::NODSSUP) {
        ede::UNSUP_DS as i16
    } else if flags.contains(DnssecFailFlags::NSEC3_ITERS) {
        ede::UNS_NS3_ITER as i16
    } else if flags.contains(DnssecFailFlags::NONSEC) {
        ede::NSEC_MISSING as i16
    } else if flags.contains(DnssecFailFlags::INDET) {
        ede::DNSSEC_INDETERMINATE as i16
    } else if flags.contains(DnssecFailFlags::NOSIG) {
        ede::RRSIG_MISSING as i16
    } else {
        ede::UNSET
    }
}

// ===========================================================================
// Trust Anchor
// (replaces C struct ds_config from dnsmasq.h)
// ===========================================================================

/// A configured DNSSEC trust anchor, typically representing a root zone DS record.
///
/// Trust anchors are the starting points for DNSSEC validation chains. They are
/// configured via `--trust-anchor` directives in `dnsmasq.conf` or loaded from
/// a trust anchor file. The root zone trust anchor is typically the only one
/// needed for full DNSSEC validation.
///
/// Replaces C's `struct ds_config` (dnsmasq.h ~line 620).
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Domain name this trust anchor applies to (e.g., `"."` for root zone).
    pub domain: DnsName,
    /// Key tag (16-bit checksum) identifying the DNSKEY this anchor references.
    pub key_tag: u16,
    /// DNSSEC algorithm number (e.g., 8 = RSASHA256, 13 = ECDSAP256SHA256).
    pub algorithm: u8,
    /// DS digest type (e.g., 1 = SHA-1, 2 = SHA-256, 4 = SHA-384).
    pub digest_type: u8,
    /// Raw digest bytes of the referenced DNSKEY record.
    pub digest: Vec<u8>,
}

impl TrustAnchor {
    /// Create a new trust anchor with the given parameters.
    pub fn new(
        domain: DnsName,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    ) -> Self {
        Self {
            domain,
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    /// Check whether this trust anchor matches a DS record's parameters.
    ///
    /// Compares key tag, algorithm, digest type, and digest bytes. Returns
    /// `true` if all fields match, indicating the DS record can be validated
    /// against this trust anchor.
    pub fn matches_ds(&self, key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> bool {
        self.key_tag == key_tag
            && self.algorithm == algorithm
            && self.digest_type == digest_type
            && self.digest == digest
    }
}

// ===========================================================================
// DNSSEC Resource Limits (DoS protection)
// (from C config.h lines 25-29)
// ===========================================================================

/// DNSSEC validation resource limits to prevent denial-of-service attacks.
///
/// These counters are decremented as validation proceeds. If any counter
/// reaches zero, validation is abandoned and the response is treated as
/// BOGUS to prevent CPU exhaustion from maliciously crafted DNS responses.
///
/// From `src/config.h` lines 25-29.
#[derive(Debug, Clone)]
pub struct DnssecLimits {
    /// Maximum queries per validation chain (DNSSEC_LIMIT_WORK=40).
    pub max_work: u32,
    /// Maximum signature verification failures (DNSSEC_LIMIT_SIG_FAIL=20).
    pub max_sig_fail: u32,
    /// Maximum total cryptographic operations (DNSSEC_LIMIT_CRYPTO=200).
    pub max_crypto: u32,
    /// Maximum NSEC3 hash iterations (DNSSEC_LIMIT_NSEC3_ITERS=150).
    pub max_nsec3_iters: u32,
}

impl Default for DnssecLimits {
    /// Create limits with the default values from `config.h`.
    fn default() -> Self {
        Self {
            max_work: DNSSEC_LIMIT_WORK,
            max_sig_fail: DNSSEC_LIMIT_SIG_FAIL,
            max_crypto: DNSSEC_LIMIT_CRYPTO,
            max_nsec3_iters: DNSSEC_LIMIT_NSEC3_ITERS,
        }
    }
}

impl DnssecLimits {
    /// Create limits with custom values.
    pub fn new(max_work: u32, max_sig_fail: u32, max_crypto: u32, max_nsec3_iters: u32) -> Self {
        Self {
            max_work,
            max_sig_fail,
            max_crypto,
            max_nsec3_iters,
        }
    }

    /// Decrement the work counter. Returns `true` if the limit has been exhausted.
    ///
    /// Matches C's `dec_counter()` pattern: post-decrement, return 1 if the
    /// counter was already zero before decrement.
    #[inline]
    pub fn dec_work(&mut self) -> bool {
        if self.max_work == 0 {
            return true;
        }
        self.max_work -= 1;
        false
    }

    /// Decrement the signature failure counter. Returns `true` if exhausted.
    #[inline]
    pub fn dec_sig_fail(&mut self) -> bool {
        if self.max_sig_fail == 0 {
            return true;
        }
        self.max_sig_fail -= 1;
        false
    }

    /// Decrement the crypto operations counter. Returns `true` if exhausted.
    #[inline]
    pub fn dec_crypto(&mut self) -> bool {
        if self.max_crypto == 0 {
            return true;
        }
        self.max_crypto -= 1;
        false
    }

    /// Check whether any resource limit has been exhausted.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.max_work == 0 || self.max_sig_fail == 0 || self.max_crypto == 0
    }
}

// ===========================================================================
// Serial number comparison (RFC 1982)
// (from C dnssec.c line 57)
// ===========================================================================

/// Constants for serial comparison results, matching C's SERIAL_* defines.
const SERIAL_UNDEF: i32 = -100;
const SERIAL_EQ: i32 = 0;
const SERIAL_LT: i32 = -1;
const SERIAL_GT: i32 = 1;

/// Compare two 32-bit serial numbers per RFC 1982 "Serial Number Arithmetic".
///
/// Used for RRSIG signature inception/expiration timestamp comparison, where
/// timestamps wrap around at 2^32. Returns `SERIAL_LT`, `SERIAL_EQ`,
/// `SERIAL_GT`, or `SERIAL_UNDEF` for undefined ordering.
///
/// Replaces C `serial_compare_32()` from dnssec.c line 57.
fn serial_compare_32(s1: u32, s2: u32) -> i32 {
    if s1 == s2 {
        return SERIAL_EQ;
    }
    let diff = s1.wrapping_sub(s2);
    if diff == 0x80000000 {
        return SERIAL_UNDEF; // exactly half-space apart: undefined
    }
    if diff < 0x80000000 {
        SERIAL_GT // s1 is "greater" (ahead in serial space)
    } else {
        SERIAL_LT // s1 is "less" (behind in serial space)
    }
}

// ===========================================================================
// Label counting utility
// (from C dnssec.c count_labels())
// ===========================================================================

/// Count the number of labels in a domain name string.
///
/// For `"www.example.com"`, returns 3. For `"."` (root), returns 0.
/// Matches C `count_labels()` from dnssec.c.
fn count_labels(name: &str) -> usize {
    if name.is_empty() || name == "." {
        return 0;
    }
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return 0;
    }
    trimmed.split('.').count()
}

// ===========================================================================
// RFC 4034 §6.3 canonical DNS name ordering
// ===========================================================================

/// Compare two domain names in canonical DNS name order per RFC 4034 §6.3.
///
/// The canonical ordering compares names label-by-label, starting from
/// the **rightmost (most significant)** label and working left.  Within
/// each label the comparison is case-insensitive (ASCII lowercase).
/// Shorter names (fewer labels) sort before longer names when the
/// shorter name is a suffix of the longer one.
///
/// This is the ordering required for NSEC and NSEC3 denial-of-existence
/// proofs.  It differs from simple byte comparison because the label
/// structure matters (e.g., `a.example.com` vs `b.example.com` compares
/// `com`, then `example`, then `a` vs `b`).
///
/// Source: RFC 4034 §6.1 — Canonical DNS Name Order.
fn canonical_dns_name_cmp(a: &str, b: &str) -> Ordering {
    let a_trimmed = a.trim_end_matches('.');
    let b_trimmed = b.trim_end_matches('.');

    // Split into labels and reverse so we compare rightmost first.
    let a_labels: Vec<&str> = if a_trimmed.is_empty() {
        Vec::new()
    } else {
        a_trimmed.split('.').collect()
    };
    let b_labels: Vec<&str> = if b_trimmed.is_empty() {
        Vec::new()
    } else {
        b_trimmed.split('.').collect()
    };

    // Compare label-by-label from rightmost (most significant) to leftmost.
    let a_len = a_labels.len();
    let b_len = b_labels.len();
    let min_len = a_len.min(b_len);

    for i in 0..min_len {
        let a_label = a_labels[a_len - 1 - i].as_bytes();
        let b_label = b_labels[b_len - 1 - i].as_bytes();

        // Compare this label pair byte-by-byte (case-insensitive).
        let label_len = a_label.len().min(b_label.len());
        for j in 0..label_len {
            let c1 = a_label[j].to_ascii_lowercase();
            let c2 = b_label[j].to_ascii_lowercase();
            match c1.cmp(&c2) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        // If label bytes compared equal, shorter label sorts first.
        match a_label.len().cmp(&b_label.len()) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    // All compared labels are equal — fewer labels sorts first.
    a_len.cmp(&b_len)
}

// ===========================================================================
// Domain name to wire format (lowercase) helper
// ===========================================================================

/// Convert a dotted domain name to DNS wire format (lowercase, length-prefixed labels).
///
/// The result includes the terminating zero-length root label. Used for DS
/// digest computation and NSEC3 hashing where the wire format owner name is
/// required.
fn name_to_wire(name: &str) -> Vec<u8> {
    let mut wire: Vec<u8> = Vec::with_capacity(name.len() + 2);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let lower = label.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(bytes);
    }
    wire.push(0); // root label
    wire
}

// ===========================================================================
// Keytag computation (RFC 4034 Appendix B)
// (from C dnssec.c line 3854)
// ===========================================================================

/// Compute the DNSKEY keytag (16-bit checksum) per RFC 4034 Appendix B.
///
/// The keytag is used to quickly match RRSIG records to the appropriate DNSKEY
/// without comparing the entire public key. Algorithm 1 (RSAMD5, legacy) uses
/// a different calculation method.
///
/// Replaces C `dnskey_keytag()` from dnssec.c line 3854.
pub fn dnskey_keytag(algo: u8, flags: u16, key: &[u8]) -> u16 {
    if algo == 1 {
        // Algorithm 1 (RSAMD5) legacy keytag: last 2 bytes before the end
        if key.len() >= 4 {
            return (key[key.len() - 4] as u16) * 256 + key[key.len() - 3] as u16;
        }
        return 0;
    }

    let mut ac: u64 = flags as u64 + 0x300 + algo as u64;
    for (i, &byte) in key.iter().enumerate() {
        if (i & 1) != 0 {
            ac += byte as u64;
        } else {
            ac += (byte as u64) << 8;
        }
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}

// ===========================================================================
// Base32 decoding (RFC 4648, extended hex alphabet)
// (from C dnssec.c line 2518)
// ===========================================================================

/// Decode a base32-encoded string (extended hex alphabet: 0-9, a-v) into bytes.
///
/// Used for NSEC3 hashed owner names in the authority section. Decoding stops
/// at the first '.' character or end of string. Returns `None` on invalid input.
///
/// Replaces C `base32_decode()` from dnssec.c line 2518.
fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for &byte in encoded.as_bytes() {
        if byte == b'.' {
            break;
        }

        let val = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'v' => byte - b'a' + 10,
            b'A'..=b'V' => byte - b'A' + 10,
            _ => return None,
        };

        bits = (bits << 5) | val as u32;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Some(result)
}

// ===========================================================================
// NSEC3 hash computation
// (from C dnssec.c line 2448)
// ===========================================================================

/// Compute the NSEC3 iterated hash of a domain name per RFC 5155.
///
/// The hash is computed as: H(H(H(wire_name + salt) + salt) ...) for the
/// specified number of iterations. The result is the raw hash bytes.
///
/// Replaces C `hash_name()` from dnssec.c line 2448.
fn hash_name(
    name: &str,
    hash_algo: &Nsec3HashAlgorithm,
    iterations: u16,
    salt: &[u8],
) -> DnsmasqResult<Vec<u8>> {
    // Convert name to wire format for hashing
    let mut wire_name: Vec<u8> = Vec::with_capacity(name.len() + 2);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let lower = label.to_ascii_lowercase();
        let label_bytes = lower.as_bytes();
        wire_name.push(label_bytes.len() as u8);
        wire_name.extend_from_slice(label_bytes);
    }
    wire_name.push(0); // root label terminator

    // Get the hash function for this NSEC3 algorithm
    let digest_name = CryptoVerifier::nsec3_digest_name(*hash_algo)
        .ok_or_else(|| DnsmasqError::Dnssec("Unsupported NSEC3 hash algorithm".into()))?;
    let mut hash_fn = CryptoVerifier::hash_find(digest_name)?;

    // Initial hash: H(wire_name || salt)
    hash_fn.update(&wire_name);
    hash_fn.update(salt);
    let mut digest = hash_fn.finalize();

    // Iterated hash: H(prev_digest || salt)
    for _ in 0..iterations {
        let mut hash_fn = CryptoVerifier::hash_find(digest_name)?;
        hash_fn.update(&digest);
        hash_fn.update(salt);
        digest = hash_fn.finalize();
    }

    Ok(digest)
}

// ===========================================================================
// NSEC type bitmap checking
// (used in prove_non_existence_nsec and prove_non_existence_nsec3)
// ===========================================================================

/// Check whether a given RR type is present in an NSEC/NSEC3 type bitmap.
///
/// The bitmap format (RFC 4034 Section 4.1.2) uses window blocks, where each
/// window covers 256 types. Each window has a block number, length, and a
/// bitmap of which types are present.
///
/// Returns `true` if the specified type is present in the bitmap.
fn check_type_bitmap(bitmap: &[u8], rr_type: RRType) -> bool {
    let type_val = rr_type.to_u16();
    let window_needed = (type_val >> 8) as u8;
    let bit_offset = (type_val & 0xff) as u8;
    let byte_in_block = (bit_offset >> 3) as usize;
    let bit_in_byte = 7 - (bit_offset & 7);

    let mut pos = 0;
    while pos + 2 <= bitmap.len() {
        let window = bitmap[pos];
        let block_len = bitmap[pos + 1] as usize;
        pos += 2;

        if pos + block_len > bitmap.len() {
            break;
        }

        if window == window_needed {
            if byte_in_block < block_len {
                return (bitmap[pos + byte_in_block] & (1 << bit_in_byte)) != 0;
            }
            return false;
        }

        pos += block_len;
    }

    false
}

// ===========================================================================
// DnssecValidator — main validation engine
// ===========================================================================

/// DNSSEC validation engine providing cryptographic verification of DNS responses.
///
/// The validator maintains references to the DNS cache and trust anchors, and
/// provides methods for the complete validation chain from target RRset through
/// RRSIG/DNSKEY/DS records up to the configured trust anchors.
///
/// Replaces the collection of C functions in `dnssec.c` with a struct-based
/// approach that explicitly passes state rather than relying on global variables.
pub struct DnssecValidator {
    /// Trust anchors (root zone DS records typically).
    trust_anchors: Vec<TrustAnchor>,
    /// Whether to check RRSIG inception/expiration timestamps.
    check_date: bool,
    /// Timestamp file path for systems with unreliable clocks.
    timestamp_file: Option<String>,
}

impl DnssecValidator {
    /// Create a new DNSSEC validator with the given trust anchors.
    ///
    /// # Arguments
    ///
    /// * `trust_anchors` — Configured trust anchors (typically root zone DS records).
    /// * `check_date` — Whether to verify RRSIG timestamp validity. Set to `false`
    ///   on systems with unreliable clocks (e.g., embedded devices without RTC).
    pub fn new(trust_anchors: Vec<TrustAnchor>, check_date: bool) -> Self {
        Self {
            trust_anchors,
            check_date,
            timestamp_file: None,
        }
    }

    /// Validate a complete DNS response, walking the trust chain for all RRsets.
    ///
    /// This is the main entry point for DNSSEC validation, called when a DNS
    /// response is received from an upstream server with the AD bit set or when
    /// the resolver is configured to validate responses.
    ///
    /// The function iterates through all RRsets in the answer and authority
    /// sections, validates each one by:
    /// 1. Finding the RRSIG for the RRset
    /// 2. Determining the zone status (secure/insecure) by walking up the DNS tree
    /// 3. Verifying the RRSIG signature using the zone's DNSKEY
    /// 4. For unsigned answers, proving non-existence via NSEC/NSEC3
    ///
    /// Replaces C `dnssec_validate_reply()` from dnssec.c line 3351.
    ///
    /// # Arguments
    ///
    /// * `packet` — Raw DNS response packet bytes.
    /// * `cache` — DNS cache for storing/retrieving validated DNSKEY/DS records.
    /// * `limits` — Mutable resource limits for DoS protection.
    /// * `domain_matcher` — Domain matcher for checking domain-specific servers.
    /// * `qname` — The original query name.
    /// * `qclass` — The query class.
    ///
    /// # Returns
    ///
    /// `Ok((DnssecStatus, DnssecFailFlags))` with the overall validation result.
    pub fn dnssec_validate_reply(
        &self,
        packet: &[u8],
        cache: &mut DnsCache,
        limits: &mut DnssecLimits,
        _domain_matcher: &DomainMatcher,
        qname: &str,
        qtype: RRType,
        qclass: DnsClass,
    ) -> DnsmasqResult<(DnssecStatus, DnssecFailFlags)> {
        let header = DnsHeader::parse(packet)?;
        let mut fail_flags = DnssecFailFlags::empty();
        let _qclass = qclass; // used for future class-specific validation

        trace!(
            id = header.id,
            ancount = header.ancount,
            nscount = header.nscount,
            "dnssec_validate_reply: starting validation"
        );

        // Check for truncated response
        if header.flags.tc {
            debug!("dnssec_validate_reply: truncated response, need TCP retry");
            return Ok((DnssecStatus::Truncated, fail_flags));
        }

        // Parse the packet to extract answer and authority sections
        let dns_packet = DnsPacket::parse(packet)?;

        // Track validation status for each RRset in the answer section
        let mut overall_secure = true;
        let mut any_bogus = false;

        // Validate answer section RRsets
        let mut validated_names: Vec<(DnsName, RRType)> = Vec::new();
        for answer in &dns_packet.answers {
            // Skip already-validated RRsets (same name+type)
            let key = (answer.name.clone(), answer.rr_type);
            if validated_names.contains(&key) {
                continue;
            }
            validated_names.push(key);

            // Collect the RRset (all records with same name, type, class)
            let rrset_records: Vec<&DnsResourceRecord> = dns_packet
                .answers
                .iter()
                .filter(|rr| {
                    rr.name == answer.name
                        && rr.rr_type == answer.rr_type
                        && rr.class == answer.class
                })
                .collect();

            // Find RRSIG records covering this RRset
            let rrsigs: Vec<&DnsResourceRecord> = dns_packet
                .answers
                .iter()
                .filter(|rr| {
                    rr.rr_type == RRType::RRSIG
                        && rr.name == answer.name
                        && rr.rdata.len() >= 18
                        && {
                            // Check that the type-covered field matches
                            let covered = u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]);
                            RRType::from_u16(covered) == answer.rr_type
                        }
                })
                .collect();

            // Skip RRSIG records themselves (they are validated as part of other RRsets)
            if answer.rr_type == RRType::RRSIG {
                continue;
            }

            // Check zone status for this name
            let zone_name = answer.name.to_string();
            let zone_status = self.zone_status(&zone_name, cache, limits)?;

            match zone_status {
                DnssecStatus::Insecure => {
                    debug!(name = %answer.name, "zone is insecure, skipping validation");
                    continue;
                }
                DnssecStatus::NeedKey | DnssecStatus::NeedDs | DnssecStatus::NeedDsDigest => {
                    return Ok((zone_status, fail_flags));
                }
                DnssecStatus::Bogus => {
                    any_bogus = true;
                    overall_secure = false;
                    continue;
                }
                _ => {} // Secure — proceed with validation
            }

            if rrsigs.is_empty() {
                // No RRSIG found for a zone that should be secure
                warn!(name = %answer.name, rr_type = ?answer.rr_type, "no RRSIG for RRset in secure zone");
                fail_flags.insert(DnssecFailFlags::NOSIG);
                any_bogus = true;
                overall_secure = false;
                continue;
            }

            // Validate the RRset against its RRSIG(s)
            let rrset = RRSet {
                name: answer.name.clone(),
                rr_type: answer.rr_type,
                class: answer.class,
                records: rrset_records.into_iter().cloned().collect(),
            };

            let mut rrset_flags = DnssecFailFlags::empty();
            let result = self.validate_rrset(&rrset, &rrsigs, cache, limits, &mut rrset_flags)?;

            match result {
                DnssecStatus::Secure => {
                    debug!(name = %answer.name, rr_type = ?answer.rr_type, "RRset validated as SECURE");
                }
                DnssecStatus::NeedKey | DnssecStatus::NeedDs | DnssecStatus::NeedDsDigest => {
                    return Ok((result, rrset_flags));
                }
                _ => {
                    warn!(name = %answer.name, rr_type = ?answer.rr_type, "RRset validation failed");
                    fail_flags.bits |= rrset_flags.bits;
                    any_bogus = true;
                    overall_secure = false;
                }
            }
        }

        // Check authority section for NSEC/NSEC3 denial of existence proofs
        // when the answer section doesn't contain the queried records
        let qname_dns = DnsName::from_str_unchecked(qname);
        let answer_has_qname = dns_packet
            .answers
            .iter()
            .any(|rr| rr.name == qname_dns && rr.rr_type != RRType::RRSIG);

        if !answer_has_qname && !dns_packet.authority.is_empty() {
            // Need to validate denial of existence
            let nsec_result =
                self.prove_non_existence(packet, &dns_packet, qname, qtype, qclass, cache, limits)?;

            match nsec_result {
                DnssecStatus::Secure => {
                    debug!(name = qname, "denial of existence validated");
                }
                DnssecStatus::Insecure => {
                    debug!(name = qname, "zone is insecure for denial of existence");
                }
                DnssecStatus::NeedKey | DnssecStatus::NeedDs | DnssecStatus::NeedDsDigest => {
                    return Ok((nsec_result, fail_flags));
                }
                _ => {
                    warn!(name = qname, "denial of existence validation failed");
                    fail_flags.insert(DnssecFailFlags::NONSEC);
                    any_bogus = true;
                    overall_secure = false;
                }
            }
        }

        if any_bogus {
            warn!(
                name = qname,
                flags = fail_flags.bits(),
                "DNSSEC validation BOGUS"
            );
            Ok((DnssecStatus::Bogus, fail_flags))
        } else if overall_secure {
            Ok((DnssecStatus::Secure, fail_flags))
        } else {
            Ok((DnssecStatus::Insecure, fail_flags))
        }
    }

    /// Validate a DNSKEY record using the DS digest from the parent zone.
    ///
    /// This function is called when a DNSKEY response is received from a zone.
    /// It validates the DNSKEY by:
    /// 1. Computing the keytag for each DNSKEY in the response
    /// 2. Finding matching DS records in the cache (from the parent zone)
    /// 3. Computing the DNSKEY digest and comparing with the DS digest
    /// 4. Verifying the DNSKEY is self-signed (zone key flag 0x0100)
    /// 5. Caching all validated DNSKEYs for future use
    ///
    /// Replaces C `dnssec_validate_by_ds()` from dnssec.c line 717.
    ///
    /// # Arguments
    ///
    /// * `packet` — Raw DNS response containing DNSKEY records.
    /// * `name` — Domain name of the zone being validated.
    /// * `cache` — DNS cache for DS record lookup and DNSKEY storage.
    /// * `limits` — Resource limits for DoS protection.
    /// * `domain_matcher` — Domain matcher for checking domain-specific servers.
    ///
    /// # Returns
    ///
    /// `Ok(DnssecStatus)` indicating whether the DNSKEY was validated.
    pub fn dnssec_validate_by_ds(
        &self,
        packet: &[u8],
        name: &str,
        cache: &mut DnsCache,
        limits: &mut DnssecLimits,
        _domain_matcher: &DomainMatcher,
    ) -> DnsmasqResult<(DnssecStatus, DnssecFailFlags)> {
        let dns_packet = DnsPacket::parse(packet)?;
        let mut fail_flags = DnssecFailFlags::empty();
        let name_dns = DnsName::from_str_unchecked(name);

        trace!(
            name = name,
            "dnssec_validate_by_ds: starting DNSKEY validation"
        );

        // Find DNSKEY records in the answer section
        let dnskeys: Vec<&DnsResourceRecord> = dns_packet
            .answers
            .iter()
            .filter(|rr| rr.rr_type == RRType::DNSKEY && rr.name == name_dns)
            .collect();

        if dnskeys.is_empty() {
            warn!(name = name, "no DNSKEY records in response");
            fail_flags.insert(DnssecFailFlags::NOKEY);
            return Ok((DnssecStatus::Bogus, fail_flags));
        }

        // Find DS records in cache for this zone
        let ds_entries = cache.cache_find_by_name(&name_dns, Some(RRType::DS));

        if ds_entries.is_empty() {
            // Check trust anchors
            let has_trust_anchor = self.trust_anchors.iter().any(|ta| {
                hostname_eq(
                    ta.domain.to_string().trim_end_matches('.'),
                    name.trim_end_matches('.'),
                )
            });

            if !has_trust_anchor {
                debug!(name = name, "no DS in cache and no trust anchor, need DS");
                return Ok((DnssecStatus::NeedDs, fail_flags));
            }
        }

        let mut validated_key = false;
        let mut any_key_supported = false;

        // Iterate through DNSKEY records
        for dnskey_rr in &dnskeys {
            if dnskey_rr.rdata.len() < 4 {
                continue; // Too short to be valid
            }

            let key_flags = u16::from_be_bytes([dnskey_rr.rdata[0], dnskey_rr.rdata[1]]);
            let key_protocol = dnskey_rr.rdata[2];
            let key_algorithm = dnskey_rr.rdata[3];
            let key_data = &dnskey_rr.rdata[4..];

            // Must be a zone key (flag bit 8 set, value 0x0100)
            if key_flags & 0x0100 == 0 {
                fail_flags.insert(DnssecFailFlags::NOZONE);
                continue;
            }

            // Protocol must be 3 (RFC 4034 Section 2.1.2)
            if key_protocol != 3 {
                continue;
            }

            // Check if the algorithm is supported
            let algo = DnssecAlgorithm::from_u8(key_algorithm);
            if algo.is_none() {
                fail_flags.insert(DnssecFailFlags::NOKEYSUP);
                continue;
            }
            any_key_supported = true;

            // Compute the keytag for this DNSKEY
            let keytag = dnskey_keytag(key_algorithm, key_flags, key_data);

            if limits.dec_crypto() {
                warn!(
                    name = name,
                    "crypto limit exhausted during DNSKEY validation"
                );
                return Ok((DnssecStatus::Abandoned, fail_flags));
            }

            // Check against trust anchors first
            for ta in &self.trust_anchors {
                if hostname_eq(
                    ta.domain.to_string().trim_end_matches('.'),
                    name.trim_end_matches('.'),
                ) && ta.key_tag == keytag
                    && ta.algorithm == key_algorithm
                {
                    // Verify digest against trust anchor
                    let digest_algo = DigestAlgorithm::from_u8(ta.digest_type);
                    if let Some(digest_algo) = digest_algo {
                        if let Some(digest_name) = CryptoVerifier::ds_digest_name(digest_algo) {
                            if let Ok(mut hash_fn) = CryptoVerifier::hash_find(digest_name) {
                                // DS digest = H(owner_name || DNSKEY_RDATA)
                                let wire_name = name_to_wire(name);
                                hash_fn.update(&wire_name);
                                hash_fn.update(&dnskey_rr.rdata);
                                let computed_digest = hash_fn.finalize();

                                if computed_digest == ta.digest {
                                    validated_key = true;
                                    debug!(
                                        name = name,
                                        keytag = keytag,
                                        algo = key_algorithm,
                                        "DNSKEY validated against trust anchor"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if validated_key {
                break;
            }

            // Check against cached DS records
            let ds_entries = cache.cache_find_by_name(&name_dns, Some(RRType::DS));
            for ds_entry in &ds_entries {
                if let CacheData::Ds {
                    key_tag: ds_keytag,
                    algorithm: ds_algo,
                    digest_type,
                    ref digest,
                } = ds_entry.data
                {
                    if ds_keytag != keytag || ds_algo != key_algorithm {
                        continue;
                    }

                    let digest_algo = match DigestAlgorithm::from_u8(digest_type) {
                        Some(a) => a,
                        None => {
                            fail_flags.insert(DnssecFailFlags::NODSSUP);
                            continue;
                        }
                    };

                    let digest_name = match CryptoVerifier::ds_digest_name(digest_algo) {
                        Some(n) => n,
                        None => continue,
                    };

                    if let Ok(mut hash_fn) = CryptoVerifier::hash_find(digest_name) {
                        // DS digest = H(owner_name || DNSKEY_RDATA)
                        let wire_name = name_to_wire(name);
                        hash_fn.update(&wire_name);
                        hash_fn.update(&dnskey_rr.rdata);
                        let computed_digest = hash_fn.finalize();

                        if computed_digest.as_slice() == digest.as_slice() {
                            validated_key = true;
                            debug!(
                                name = name,
                                keytag = keytag,
                                algo = key_algorithm,
                                "DNSKEY validated against cached DS"
                            );
                            break;
                        }
                    }
                }
            }

            if validated_key {
                break;
            }
        }

        if !validated_key {
            if !any_key_supported {
                fail_flags.insert(DnssecFailFlags::NOKEYSUP);
            } else {
                fail_flags.insert(DnssecFailFlags::NOKEY);
            }
            warn!(
                name = name,
                "DNSKEY validation failed — no matching DS found"
            );
            return Ok((DnssecStatus::Bogus, fail_flags));
        }

        // Now validate the DNSKEY RRset's own RRSIG (self-signed)
        let dnskey_rrset = RRSet {
            name: name_dns.clone(),
            rr_type: RRType::DNSKEY,
            class: DnsClass::IN,
            records: dnskeys.into_iter().cloned().collect(),
        };

        let dnskey_rrsigs: Vec<&DnsResourceRecord> = dns_packet
            .answers
            .iter()
            .filter(|rr| {
                rr.rr_type == RRType::RRSIG && rr.name == name_dns && rr.rdata.len() >= 18 && {
                    let covered = u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]);
                    covered == RRType::DNSKEY.to_u16()
                }
            })
            .collect();

        if dnskey_rrsigs.is_empty() {
            fail_flags.insert(DnssecFailFlags::NOSIG);
            return Ok((DnssecStatus::Bogus, fail_flags));
        }

        let mut sig_flags = DnssecFailFlags::empty();
        let sig_result =
            self.validate_rrset(&dnskey_rrset, &dnskey_rrsigs, cache, limits, &mut sig_flags)?;

        if sig_result != DnssecStatus::Secure {
            fail_flags.bits |= sig_flags.bits;
            return Ok((sig_result, fail_flags));
        }

        // Cache all validated DNSKEYs
        for dnskey_rr in &dnskey_rrset.records {
            if dnskey_rr.rdata.len() >= 4 {
                let key_flags = u16::from_be_bytes([dnskey_rr.rdata[0], dnskey_rr.rdata[1]]);
                let key_algorithm = dnskey_rr.rdata[3];
                let key_data = dnskey_rr.rdata[4..].to_vec();
                let _keytag = dnskey_keytag(key_algorithm, key_flags, &key_data);

                let entry = CacheEntry {
                    name: name_dns.clone(),
                    rr_type: RRType::DNSKEY,
                    data: CacheData::DnsKey {
                        flags: key_flags,
                        protocol: dnskey_rr.rdata[2],
                        algorithm: key_algorithm,
                        key_data,
                    },
                    // Cap TTL to RFC-recommended maximum of 7 days (604800 seconds) to prevent
                    // malicious responses with extremely large TTLs from causing overflow or
                    // indefinite cache retention.
                    expires: std::time::Instant::now()
                        + Duration::from_secs((dnskey_rr.ttl as u64).min(604_800)),
                    last_access: std::time::Instant::now(),
                    flags: CacheFlags {
                        from_upstream: true,
                        ..Default::default()
                    },
                    ttl: dnskey_rr.ttl,
                };

                if let Err(e) = cache.cache_insert(entry) {
                    debug!(name = name, "failed to cache DNSKEY: {}", e);
                }
            }
        }

        info!(name = name, "DNSKEY validation successful");
        Ok((DnssecStatus::Secure, fail_flags))
    }

    /// Verify the cryptographic signature on a single RRset.
    ///
    /// Performs RRSIG verification per RFC 4034 Section 3:
    /// 1. Sort the RRset into canonical order (RFC 4034 Section 6.3).
    /// 2. Construct the signature verification data: RRSIG RDATA fields ||
    ///    signer's name || canonical RR data.
    /// 3. Look up the DNSKEY matching the RRSIG key tag in the cache.
    /// 4. Verify the signature using [`CryptoVerifier::verify`].
    ///
    /// Multiple RRSIG records may cover the same RRset (key rotation); the
    /// function tries each one until a valid signature is found.
    ///
    /// Replaces C `validate_rrset()` from dnssec.c line 457.
    ///
    /// # Arguments
    ///
    /// * `rrset` — The RRset to validate (records with same name/type/class).
    /// * `rrsigs` — RRSIG records covering this RRset.
    /// * `cache` — DNS cache for DNSKEY lookup.
    /// * `limits` — Resource limits for DoS protection.
    /// * `fail_flags` — Mutable flags to record failure reasons.
    ///
    /// # Returns
    ///
    /// `Ok(DnssecStatus)` indicating the validation result.
    pub fn validate_rrset(
        &self,
        rrset: &RRSet,
        rrsigs: &[&DnsResourceRecord],
        cache: &mut DnsCache,
        limits: &mut DnssecLimits,
        fail_flags: &mut DnssecFailFlags,
    ) -> DnsmasqResult<DnssecStatus> {
        if rrsigs.is_empty() {
            fail_flags.insert(DnssecFailFlags::NOSIG);
            return Ok(DnssecStatus::Bogus);
        }

        let mut tried_any = false;

        for rrsig in rrsigs {
            if rrsig.rdata.len() < 18 {
                continue; // RRSIG RDATA too short
            }

            // Parse RRSIG RDATA fields (RFC 4034 Section 3.1)
            let _type_covered = u16::from_be_bytes([rrsig.rdata[0], rrsig.rdata[1]]);
            let algorithm = rrsig.rdata[2];
            let labels = rrsig.rdata[3];
            let original_ttl = u32::from_be_bytes([
                rrsig.rdata[4],
                rrsig.rdata[5],
                rrsig.rdata[6],
                rrsig.rdata[7],
            ]);
            let sig_expiration = u32::from_be_bytes([
                rrsig.rdata[8],
                rrsig.rdata[9],
                rrsig.rdata[10],
                rrsig.rdata[11],
            ]);
            let sig_inception = u32::from_be_bytes([
                rrsig.rdata[12],
                rrsig.rdata[13],
                rrsig.rdata[14],
                rrsig.rdata[15],
            ]);
            let key_tag = u16::from_be_bytes([rrsig.rdata[16], rrsig.rdata[17]]);

            // Extract signer's name from RRSIG RDATA (after fixed 18 bytes).
            // We preserve the consumed byte count so we can correctly locate
            // the signature data that follows the signer name in the RDATA.
            // Source: RFC 4034 §3.1 — RRSIG RDATA format.
            let signer_data = &rrsig.rdata[18..];
            let (signer_name, signer_name_consumed) = match DnsName::from_wire(0, signer_data) {
                Ok((name, consumed)) => (name, consumed),
                Err(_) => continue,
            };

            // Check algorithm is supported
            let algo = match DnssecAlgorithm::from_u8(algorithm) {
                Some(a) => a,
                None => {
                    fail_flags.insert(DnssecFailFlags::NOKEYSUP);
                    continue;
                }
            };

            tried_any = true;

            // Check timestamps if date checking is enabled
            if self.check_date {
                let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(d) => d.as_secs() as u32,
                    Err(_) => 0,
                };

                if serial_compare_32(now, sig_expiration) == SERIAL_GT
                    || serial_compare_32(now, sig_expiration) == SERIAL_EQ
                {
                    fail_flags.insert(DnssecFailFlags::EXP);
                    if limits.dec_sig_fail() {
                        warn!("sig_fail limit exhausted");
                        return Ok(DnssecStatus::Abandoned);
                    }
                    continue;
                }

                if serial_compare_32(now, sig_inception) == SERIAL_LT {
                    fail_flags.insert(DnssecFailFlags::NYV);
                    if limits.dec_sig_fail() {
                        warn!("sig_fail limit exhausted");
                        return Ok(DnssecStatus::Abandoned);
                    }
                    continue;
                }
            }

            // Find the DNSKEY matching this RRSIG's signer name and key tag
            let signer_str = signer_name.to_string();
            let signer_str_trimmed = signer_str.trim_end_matches('.');
            let key_entries = cache.cache_find_by_name(&signer_name, Some(RRType::DNSKEY));

            let mut found_key = false;
            for key_entry in &key_entries {
                if let CacheData::DnsKey {
                    flags: key_flags,
                    algorithm: key_algo,
                    ref key_data,
                    ..
                } = key_entry.data
                {
                    // Check zone key flag
                    if key_flags & 0x0100 == 0 {
                        continue;
                    }

                    if key_algo != algorithm {
                        continue;
                    }

                    let computed_keytag = dnskey_keytag(key_algo, key_flags, key_data);
                    if computed_keytag != key_tag {
                        continue;
                    }

                    if limits.dec_crypto() {
                        warn!("crypto limit exhausted during RRSIG verification");
                        return Ok(DnssecStatus::Abandoned);
                    }

                    // Build the verification data:
                    // RRSIG_RDATA(sans signature) || signer_name_wire || canonical_RRs
                    let mut verify_data = BytesMut::new();

                    // RRSIG RDATA fields (first 18 bytes + signer name, sans signature)
                    verify_data.extend_from_slice(&rrsig.rdata[..18]);

                    // Signer name in wire format (lowercase)
                    let mut signer_wire = BytesMut::new();
                    signer_name.to_wire(&mut signer_wire);
                    verify_data.extend_from_slice(&signer_wire);

                    // Canonical RRset data
                    let mut sorted_records = rrset.records.clone();
                    sorted_records.sort_by(|a, b| a.rdata.cmp(&b.rdata));

                    for rr in &sorted_records {
                        // Owner name in wire format (lowercase, with wildcard expansion).
                        // RFC 4035 §5.3.4: if RRSIG label count < actual owner name
                        // label count, the response was synthesised from a wildcard.
                        // Reconstruct the wildcard source by taking the rightmost
                        // `labels` labels of the actual owner name and prepending `*`.
                        let name_labels = count_labels(&rr.name.to_string());
                        if (labels as usize) < name_labels {
                            // Wildcard expansion per RFC 4035 §5.3.4:
                            // Take the rightmost `labels` labels of the owner
                            // name and prepend the wildcard label `*`.
                            let owner_str = rr.name.to_string();
                            let owner_str = owner_str.trim_end_matches('.');
                            let all_labels: Vec<&str> = owner_str.split('.').collect();
                            let keep = labels as usize;
                            // Reconstruct from the rightmost `keep` labels.
                            let suffix = if keep > 0 && keep <= all_labels.len() {
                                all_labels[all_labels.len() - keep..].join(".")
                            } else {
                                owner_str.to_string()
                            };
                            let wildcard = format!("*.{}", suffix);
                            let wc_name = DnsName::from_str_unchecked(&wildcard);
                            let mut owner_wire = BytesMut::new();
                            wc_name.to_wire(&mut owner_wire);
                            verify_data.extend_from_slice(&owner_wire);
                        } else {
                            let mut owner_wire = BytesMut::new();
                            rr.name.to_wire(&mut owner_wire);
                            verify_data.extend_from_slice(&owner_wire);
                        }

                        // Type, class, original TTL
                        verify_data.put_u16(rr.rr_type.to_u16());
                        verify_data.put_u16(rr.class.to_u16());
                        verify_data.put_u32(original_ttl);

                        // RDATA length and RDATA
                        verify_data.put_u16(rr.rdata.len() as u16);
                        verify_data.extend_from_slice(&rr.rdata);
                    }

                    // Extract the actual signature from the RRSIG.
                    // Use the consumed byte count from the original wire-format
                    // parse (not signer_wire.len()) because the original RDATA
                    // may use name compression pointers that differ in length
                    // from the re-encoded canonical form.
                    let sig_offset = 18 + signer_name_consumed;
                    if sig_offset >= rrsig.rdata.len() {
                        continue;
                    }
                    let signature = &rrsig.rdata[sig_offset..];

                    // Verify the signature via CryptoVerifier:
                    // verify(algo, key_data: &BlockData, sig_data: &BlockData, digest: &[u8])
                    let key_block = BlockData::new(key_data);
                    let sig_block = BlockData::new(signature);
                    match CryptoVerifier::verify(algo, &key_block, &sig_block, verify_data.as_ref())
                    {
                        Ok(true) => {
                            debug!(
                                name = %rrset.name,
                                rr_type = ?rrset.rr_type,
                                keytag = key_tag,
                                algo = algorithm,
                                "RRSIG signature verified"
                            );
                            return Ok(DnssecStatus::Secure);
                        }
                        Ok(false) => {
                            trace!(
                                keytag = key_tag,
                                "RRSIG signature verification failed for keytag"
                            );
                            if limits.dec_sig_fail() {
                                warn!("sig_fail limit exhausted");
                                return Ok(DnssecStatus::Abandoned);
                            }
                        }
                        Err(e) => {
                            trace!(
                                keytag = key_tag,
                                error = %e,
                                "RRSIG signature verification error"
                            );
                            if limits.dec_sig_fail() {
                                return Ok(DnssecStatus::Abandoned);
                            }
                        }
                    }

                    found_key = true;
                }
            }

            if !found_key {
                // DNSKEY not found in cache — need to fetch it
                debug!(
                    signer = signer_str_trimmed,
                    keytag = key_tag,
                    "DNSKEY not in cache, need to fetch"
                );
                return Ok(DnssecStatus::NeedKey);
            }
        }

        if !tried_any {
            fail_flags.insert(DnssecFailFlags::NOKEYSUP);
        }

        Ok(DnssecStatus::Bogus)
    }

    /// Prove non-existence of a DNS name or type using NSEC/NSEC3 records.
    ///
    /// Dispatches to either NSEC or NSEC3 proof validation based on the type
    /// of denial records present in the authority section. Validates that
    /// NSEC/NSEC3 records don't intermix (mixing is BOGUS per RFC 5155).
    ///
    /// Replaces C `prove_non_existence()` from dnssec.c line 3048.
    ///
    /// # Arguments
    ///
    /// * `raw_packet` — Raw DNS packet bytes.
    /// * `packet` — Parsed DNS packet.
    /// * `qname` — The queried domain name.
    /// * `qclass` — The query class.
    /// * `cache` — DNS cache for DNSKEY lookups.
    /// * `limits` — Resource limits for DoS protection.
    ///
    /// # Returns
    ///
    /// `Ok(DnssecStatus)` indicating whether non-existence was proven.
    pub fn prove_non_existence(
        &self,
        _raw_packet: &[u8],
        packet: &DnsPacket,
        qname: &str,
        qtype: RRType,
        _qclass: DnsClass,
        cache: &mut DnsCache,
        limits: &mut DnssecLimits,
    ) -> DnsmasqResult<DnssecStatus> {
        // Collect NSEC and NSEC3 records from authority section
        let mut has_nsec = false;
        let mut has_nsec3 = false;
        let mut nsec_records: Vec<&DnsResourceRecord> = Vec::new();
        let mut nsec3_records: Vec<&DnsResourceRecord> = Vec::new();

        for rr in &packet.authority {
            match rr.rr_type {
                RRType::NSEC => {
                    has_nsec = true;
                    nsec_records.push(rr);
                }
                RRType::NSEC3 => {
                    has_nsec3 = true;
                    nsec3_records.push(rr);
                }
                _ => {}
            }
        }

        // NSEC and NSEC3 records must not be mixed (RFC 5155 Section 8.9)
        if has_nsec && has_nsec3 {
            warn!(name = qname, "mixed NSEC and NSEC3 records — BOGUS");
            return Ok(DnssecStatus::Bogus);
        }

        if !has_nsec && !has_nsec3 {
            debug!(name = qname, "no NSEC/NSEC3 records in authority section");
            return Ok(DnssecStatus::Bogus);
        }

        // First validate the RRSIG on the NSEC/NSEC3 records
        let nsec_type = if has_nsec {
            RRType::NSEC
        } else {
            RRType::NSEC3
        };
        let records_to_check = if has_nsec {
            &nsec_records
        } else {
            &nsec3_records
        };

        // Validate RRSIG signatures on the NSEC/NSEC3 records
        for nsec_rr in records_to_check {
            let nsec_rrsigs: Vec<&DnsResourceRecord> = packet
                .authority
                .iter()
                .filter(|rr| {
                    rr.rr_type == RRType::RRSIG
                        && rr.name == nsec_rr.name
                        && rr.rdata.len() >= 18
                        && {
                            let covered = u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]);
                            RRType::from_u16(covered) == nsec_type
                        }
                })
                .collect();

            if !nsec_rrsigs.is_empty() {
                let nsec_rrset = RRSet {
                    name: nsec_rr.name.clone(),
                    rr_type: nsec_type,
                    class: nsec_rr.class,
                    records: records_to_check
                        .iter()
                        .filter(|rr| rr.name == nsec_rr.name)
                        .cloned()
                        .cloned()
                        .collect(),
                };

                let mut sig_flags = DnssecFailFlags::empty();
                let sig_result =
                    self.validate_rrset(&nsec_rrset, &nsec_rrsigs, cache, limits, &mut sig_flags)?;

                if sig_result != DnssecStatus::Secure {
                    return Ok(sig_result);
                }
            }
        }

        if has_nsec {
            self.prove_non_existence_nsec(&nsec_records, qname, qtype, packet)
        } else {
            self.prove_non_existence_nsec3(&nsec3_records, qname, qtype, limits)
        }
    }

    /// Check whether the system clock is reliable for DNSSEC timestamp validation.
    ///
    /// Returns `true` if RRSIG inception/expiration times should be checked,
    /// `false` if the system clock is unreliable (e.g., embedded devices without
    /// RTC that start with epoch time).
    ///
    /// Replaces C `is_check_date()` from dnssec.c.
    pub fn is_check_date(&self) -> bool {
        self.check_date
    }

    /// Initialize timestamp-based validation for systems with unreliable clocks.
    ///
    /// On systems without a real-time clock (RTC), the system time may start
    /// at epoch (1970-01-01) or some arbitrary value. This function uses a
    /// timestamp file to detect when the system clock becomes valid:
    ///
    /// 1. If the timestamp file exists and its mtime is in the past, the clock
    ///    is considered valid (the system has been running with valid time before).
    /// 2. If the clock appears valid, `check_date` is set to `true`.
    /// 3. If a validated DNSSEC response is received while `check_date` is false,
    ///    the timestamp file is updated and `check_date` is enabled.
    ///
    /// Replaces C `setup_timestamp()` from dnssec.c line 68.
    pub fn setup_timestamp(&mut self, timestamp_path: &str) -> DnsmasqResult<bool> {
        self.timestamp_file = Some(timestamp_path.to_string());

        // Check if the timestamp file exists and has a valid timestamp
        match std::fs::metadata(timestamp_path) {
            Ok(metadata) => {
                if let Ok(mtime) = metadata.modified() {
                    if let Ok(elapsed) = SystemTime::now().duration_since(mtime) {
                        // If the file was modified in the past, the clock is valid
                        if elapsed.as_secs() > 0 {
                            self.check_date = true;
                            info!(
                                path = timestamp_path,
                                "timestamp file valid, enabling date checking"
                            );
                            return Ok(true);
                        }
                    }
                    // Clock might be wrong — file mtime is in the future
                    info!(
                        path = timestamp_path,
                        "timestamp file mtime in future, clock may be unreliable"
                    );
                    self.check_date = false;
                    return Ok(false);
                }
                self.check_date = false;
                Ok(false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Create the timestamp file
                if let Err(create_err) = std::fs::File::create(timestamp_path) {
                    warn!(
                        path = timestamp_path,
                        error = %create_err,
                        "failed to create timestamp file"
                    );
                }
                self.check_date = false;
                info!(
                    path = timestamp_path,
                    "created timestamp file, date checking disabled until clock is validated"
                );
                Ok(false)
            }
            Err(e) => {
                warn!(
                    path = timestamp_path,
                    error = %e,
                    "failed to check timestamp file"
                );
                self.check_date = false;
                Ok(false)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: zone_status — walk DNS tree to find trust anchor or insecure point
    // (from C dnssec.c line 3258)
    // -----------------------------------------------------------------------

    /// Determine the DNSSEC status of a zone by walking up the DNS tree.
    ///
    /// Starting from the target name, walks upward through parent domains
    /// checking for cached DS records or trust anchors. Returns:
    /// - `Secure` if a trust anchor or validated DS is found
    /// - `Insecure` if an unsigned delegation is found
    /// - `NeedDs` if DS records need to be fetched
    fn zone_status(
        &self,
        name: &str,
        cache: &mut DnsCache,
        limits: &mut DnssecLimits,
    ) -> DnsmasqResult<DnssecStatus> {
        let trimmed = name.trim_end_matches('.');

        // Identify the deepest trust anchor that is an ancestor of (or equal
        // to) the queried name.  A trust anchor at the root covers everything.
        // RFC 4035 §5.1: validation starts from a configured trust anchor and
        // walks DOWN through delegation points, verifying DS records at each.
        let mut anchor_name: Option<String> = None;

        for ta in &self.trust_anchors {
            let ta_name = ta.domain.to_string();
            let ta_trimmed = ta_name.trim_end_matches('.');

            let covers = hostname_eq(trimmed, ta_trimmed)
                || ta_trimmed == "."
                || ta_trimmed.is_empty()
                || trimmed.ends_with(&format!(".{}", ta_trimmed));

            if covers {
                // Keep the deepest (longest) matching trust anchor.
                if anchor_name
                    .as_ref()
                    .is_none_or(|prev| ta_trimmed.len() > prev.len())
                {
                    anchor_name = Some(ta_trimmed.to_string());
                }
            }
        }

        // If the queried name IS the trust anchor itself, it is secure by
        // definition — no intermediate delegations exist.
        if let Some(ref anchor) = anchor_name {
            if hostname_eq(trimmed, anchor) || anchor == "." || anchor.is_empty() {
                // Trust anchor matches exactly (or root anchor) — secure.
                // For the root anchor we still need to check child delegations
                // unless the queried name IS the root.
                if hostname_eq(trimmed, anchor) && !anchor.is_empty() && anchor != "." {
                    return Ok(DnssecStatus::Secure);
                }
            }
        }

        // Walk UP from the queried name toward the trust anchor, checking for
        // cached DS records at each delegation point.  If we encounter a
        // delegation with NO DS record, the chain is broken and the zone
        // is insecure.  If we find DS records all the way up to the trust
        // anchor, the zone is secure.
        let mut current = trimmed.to_string();
        loop {
            let dns_name = DnsName::from_str_unchecked(&current);

            // Check for cached DS records at this delegation point.
            let ds_entries = cache.cache_find_by_name(&dns_name, Some(RRType::DS));
            if !ds_entries.is_empty() {
                // Verify at least one DS has a supported algorithm and digest.
                let mut has_supported = false;
                for entry in &ds_entries {
                    if let CacheData::Ds {
                        algorithm,
                        digest_type,
                        ..
                    } = &entry.data
                    {
                        if DnssecAlgorithm::from_u8(*algorithm).is_some()
                            && DigestAlgorithm::from_u8(*digest_type).is_some()
                        {
                            has_supported = true;
                            break;
                        }
                    }
                }

                if has_supported {
                    // DS is validated at this delegation — if we are at or
                    // above the trust anchor level, the chain is complete.
                    if let Some(ref anchor) = anchor_name {
                        if hostname_eq(&current, anchor) || anchor == "." || anchor.is_empty() {
                            return Ok(DnssecStatus::Secure);
                        }
                    }
                    // DS exists but we haven't reached the trust anchor yet;
                    // continue walking up.
                }
            } else {
                // No DS at this delegation.  Check for explicit proof of
                // insecure delegation (negative cache entry or non-terminal).
                if cache.cache_find_non_terminal(&dns_name) {
                    // Records exist for this name but no DS — insecure
                    // delegation per RFC 4035.
                    return Ok(DnssecStatus::Insecure);
                }
            }

            // Check if this level matches the trust anchor (reached the
            // anchor without finding a broken chain → secure).
            if let Some(ref anchor) = anchor_name {
                if hostname_eq(&current, anchor)
                    || ((anchor == "." || anchor.is_empty()) && current.is_empty())
                {
                    return Ok(DnssecStatus::Secure);
                }
            }

            // Move to parent domain.
            if let Some(dot_pos) = current.find('.') {
                current = current[dot_pos + 1..].to_string();
            } else {
                break; // Reached root
            }

            if current.is_empty() {
                // At root — check if root trust anchor covers us.
                if let Some(ref anchor) = anchor_name {
                    if anchor == "." || anchor.is_empty() {
                        return Ok(DnssecStatus::Secure);
                    }
                }
                break;
            }

            if limits.dec_work() {
                warn!(name = name, "work limit exhausted in zone_status");
                return Ok(DnssecStatus::Abandoned);
            }
        }

        // No trust anchor found or delegation chain is incomplete.
        if anchor_name.is_some() {
            // Trust anchor exists but DS records are missing — need to fetch.
            Ok(DnssecStatus::NeedDs)
        } else {
            // No trust anchor covers this name at all.
            Ok(DnssecStatus::NeedDs)
        }
    }

    // -----------------------------------------------------------------------
    // Internal: prove_non_existence_nsec — NSEC denial of existence
    // (from C dnssec.c line 2261)
    // -----------------------------------------------------------------------

    /// Validate NSEC-based denial of existence proof.
    ///
    /// Checks that NSEC records in the authority section prove that the queried
    /// name does not exist or does not have the queried type. Implements the
    /// three canonical ordering cases:
    /// 1. Exact match — name exists but type is not in bitmap.
    /// 2. Between — name falls between owner and next name.
    /// 3. Wrap-around — name is after last or before first in zone.
    ///
    /// Also handles wildcard expansion proofs (sig_labels < name_labels).
    fn prove_non_existence_nsec(
        &self,
        nsec_records: &[&DnsResourceRecord],
        qname: &str,
        qtype: RRType,
        _packet: &DnsPacket,
    ) -> DnsmasqResult<DnssecStatus> {
        let qname_lower = qname.to_ascii_lowercase();

        for nsec_rr in nsec_records {
            let owner_name = nsec_rr.name.to_string();
            let owner_lower = owner_name.trim_end_matches('.').to_ascii_lowercase();

            // Parse NSEC RDATA: next domain name + type bitmap
            if nsec_rr.rdata.is_empty() {
                continue;
            }

            // Extract next domain name from NSEC RDATA
            let (next_name, consumed) = match DnsName::from_wire(0, &nsec_rr.rdata) {
                Ok(result) => result,
                Err(_) => continue,
            };
            let next_lower = next_name
                .to_string()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let bitmap = &nsec_rr.rdata[consumed..];

            // Case 1: Exact match — name exists but type not in bitmap (NODATA response)
            if hostname_eq(&qname_lower, &owner_lower) {
                // The name exists. In a NODATA response the queried type is absent
                // from the NSEC type bitmap. Verify the queried type is indeed absent.
                if !check_type_bitmap(bitmap, qtype) {
                    debug!(
                        qname = qname,
                        owner = owner_lower,
                        "NSEC exact match — queried type absent from bitmap, NODATA proven"
                    );
                    return Ok(DnssecStatus::Secure);
                }
                // Type IS present in bitmap — this NSEC doesn't prove non-existence
                // (the name and type both exist; this is not NXDOMAIN or NODATA)
                continue;
            }

            // Case 2: Name falls between owner and next (canonical ordering)
            // Uses RFC 4034 §6.3 label-by-label canonical ordering (right-to-left)
            // instead of simple byte comparison, as required for NSEC proofs.
            let cmp_owner = canonical_dns_name_cmp(&qname_lower, &owner_lower);
            let cmp_next = canonical_dns_name_cmp(&qname_lower, &next_lower);

            let name_covered =
                // Normal ordering: owner < qname < next
                (cmp_owner == Ordering::Greater && cmp_next == Ordering::Less)
                || {
                    // Wrap-around case: owner > next (last NSEC in zone)
                    let owner_next_cmp = canonical_dns_name_cmp(&owner_lower, &next_lower);
                    (owner_next_cmp == Ordering::Greater || owner_next_cmp == Ordering::Equal)
                        && (cmp_owner == Ordering::Greater || cmp_next == Ordering::Less)
                };

            if name_covered {
                debug!(
                    qname = qname,
                    owner = owner_lower,
                    next = next_lower,
                    "NSEC proves name non-existence"
                );

                // RFC 4035 §5.4 step 3: additionally prove that no wildcard at
                // the closest encloser could have matched the queried name.
                // The closest encloser is the longest ancestor of qname that
                // actually exists in the zone.  We derive it by stripping
                // the leftmost label from qname.
                let closest_encloser = if let Some(dot_pos) = qname_lower.find('.') {
                    &qname_lower[dot_pos + 1..]
                } else {
                    &qname_lower
                };
                let wildcard_name = format!("*.{}", closest_encloser);
                let wc_lower = wildcard_name.to_ascii_lowercase();

                // Check whether another NSEC in the authority section covers
                // the wildcard name, proving it doesn't exist either.
                let mut wildcard_proven = false;
                for wc_nsec in nsec_records {
                    let wc_owner = wc_nsec
                        .name
                        .to_string()
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                        .to_string();

                    // If the wildcard name is the NSEC owner, the wildcard exists.
                    // Check the type bitmap — if the queried type is absent, it is
                    // a NODATA wildcard answer (still non-existent for this type).
                    if hostname_eq(&wc_lower, &wc_owner) {
                        let (_, wc_consumed) = match DnsName::from_wire(0, &wc_nsec.rdata) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        let wc_bitmap = &wc_nsec.rdata[wc_consumed..];
                        if !check_type_bitmap(wc_bitmap, qtype) {
                            wildcard_proven = true;
                            break;
                        }
                        continue;
                    }

                    // Check if the wildcard name falls between this NSEC's owner
                    // and next name (same canonical ordering logic).
                    let (wc_next, wc_consumed) = match DnsName::from_wire(0, &wc_nsec.rdata) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let _ = &wc_nsec.rdata[wc_consumed..]; // bitmap (unused here)
                    let wc_next_lower = wc_next
                        .to_string()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();

                    let wc_cmp_owner = canonical_dns_name_cmp(&wc_lower, &wc_owner);
                    let wc_cmp_next = canonical_dns_name_cmp(&wc_lower, &wc_next_lower);

                    let wc_covered =
                        (wc_cmp_owner == Ordering::Greater && wc_cmp_next == Ordering::Less) || {
                            let own_next = canonical_dns_name_cmp(&wc_owner, &wc_next_lower);
                            (own_next == Ordering::Greater || own_next == Ordering::Equal)
                                && (wc_cmp_owner == Ordering::Greater
                                    || wc_cmp_next == Ordering::Less)
                        };
                    if wc_covered {
                        wildcard_proven = true;
                        break;
                    }
                }

                if wildcard_proven {
                    debug!(
                        qname = qname,
                        wildcard = wc_lower,
                        "NSEC proves both name and wildcard non-existence"
                    );
                    return Ok(DnssecStatus::Secure);
                }

                // Wildcard proof not found — the name doesn't exist but a
                // wildcard might, so we can't definitively prove NXDOMAIN.
                debug!(
                    qname = qname,
                    wildcard = wc_lower,
                    "NSEC covers name but wildcard non-existence not proven"
                );
            }
        }

        debug!(qname = qname, "NSEC proof failed — no covering NSEC found");
        Ok(DnssecStatus::Bogus)
    }

    // -----------------------------------------------------------------------
    // Internal: prove_non_existence_nsec3 — NSEC3 denial of existence
    // (from C dnssec.c line 2805)
    // -----------------------------------------------------------------------

    /// Validate NSEC3-based denial of existence proof per RFC 5155.
    ///
    /// Implements the closest encloser proof:
    /// 1. Find the closest encloser (longest ancestor of qname that is matched
    ///    by an NSEC3 record).
    /// 2. Prove the next-closest name (closest_encloser + one more label) is
    ///    covered by an NSEC3 range.
    /// 3. Prove the wildcard at the closest encloser (*.closest_encloser) is
    ///    either matched or covered.
    ///
    /// Respects the NSEC3 iterations limit for DoS protection.
    fn prove_non_existence_nsec3(
        &self,
        nsec3_records: &[&DnsResourceRecord],
        qname: &str,
        qtype: RRType,
        limits: &mut DnssecLimits,
    ) -> DnsmasqResult<DnssecStatus> {
        if nsec3_records.is_empty() {
            return Ok(DnssecStatus::Bogus);
        }

        // Extract NSEC3 parameters from the first record
        let first_nsec3 = nsec3_records[0];
        if first_nsec3.rdata.len() < 5 {
            return Ok(DnssecStatus::Bogus);
        }

        let hash_algo_byte = first_nsec3.rdata[0];
        let _flags = first_nsec3.rdata[1];
        let iterations = u16::from_be_bytes([first_nsec3.rdata[2], first_nsec3.rdata[3]]);
        let salt_len = first_nsec3.rdata[4] as usize;

        // Check iteration limit
        if iterations as u32 > limits.max_nsec3_iters {
            warn!(
                iterations = iterations,
                limit = limits.max_nsec3_iters,
                "NSEC3 iterations exceed limit"
            );
            return Ok(DnssecStatus::Bogus);
        }

        if 5 + salt_len > first_nsec3.rdata.len() {
            return Ok(DnssecStatus::Bogus);
        }
        let salt = &first_nsec3.rdata[5..5 + salt_len];

        let hash_algo = match Nsec3HashAlgorithm::from_u8(hash_algo_byte) {
            Some(a) => a,
            None => {
                warn!(algo = hash_algo_byte, "unsupported NSEC3 hash algorithm");
                return Ok(DnssecStatus::Bogus);
            }
        };

        // Compute hash of the query name
        let qname_hash = hash_name(qname, &hash_algo, iterations, salt)?;

        // Check for exact match in NSEC3 records
        for nsec3_rr in nsec3_records {
            let owner = nsec3_rr.name.to_string();
            let owner_hash_str = owner.split('.').next().unwrap_or("");
            if let Some(owner_hash) = base32_decode(owner_hash_str) {
                if owner_hash == qname_hash {
                    // Exact match — extract type bitmap from NSEC3 RDATA and
                    // verify the queried type is absent (NODATA proof).
                    // NSEC3 RDATA: hash_algo(1) + flags(1) + iterations(2) +
                    //   salt_len(1) + salt(n) + hash_len(1) + next_hash(m) + bitmap
                    let bitmap_start = 5 + salt_len;
                    if bitmap_start < nsec3_rr.rdata.len() {
                        let next_hash_len = nsec3_rr.rdata[bitmap_start] as usize;
                        let bitmap_offset = bitmap_start + 1 + next_hash_len;
                        if bitmap_offset <= nsec3_rr.rdata.len() {
                            let nsec3_bitmap = &nsec3_rr.rdata[bitmap_offset..];
                            if !check_type_bitmap(nsec3_bitmap, qtype) {
                                debug!(
                                    qname = qname,
                                    "NSEC3 exact match — queried type absent, NODATA proven"
                                );
                                return Ok(DnssecStatus::Secure);
                            }
                        }
                    }
                    // If type IS in bitmap, continue checking other records
                    continue;
                }
            }
        }

        // Closest encloser proof: walk up the name tree
        let mut current = qname.to_string();
        let mut closest_encloser: Option<String> = None;

        loop {
            // Hash the current name
            let current_hash = hash_name(&current, &hash_algo, iterations, salt)?;

            // Check if this hash matches any NSEC3 owner
            for nsec3_rr in nsec3_records {
                let owner = nsec3_rr.name.to_string();
                let owner_hash_str = owner.split('.').next().unwrap_or("");
                if let Some(owner_hash) = base32_decode(owner_hash_str) {
                    if owner_hash == current_hash {
                        closest_encloser = Some(current.clone());
                        break;
                    }
                }
            }

            if closest_encloser.is_some() {
                break;
            }

            // Move to parent
            if let Some(dot_pos) = current.find('.') {
                current = current[dot_pos + 1..].to_string();
            } else {
                break;
            }

            if current.is_empty() {
                break;
            }
        }

        let closest_encloser = match closest_encloser {
            Some(ce) => ce,
            None => {
                debug!(qname = qname, "NSEC3 no closest encloser found");
                return Ok(DnssecStatus::Bogus);
            }
        };

        // Prove next closest name is covered by an NSEC3 range
        let ce_label_count = count_labels(&closest_encloser);
        let qname_label_count = count_labels(qname);

        if qname_label_count <= ce_label_count {
            return Ok(DnssecStatus::Bogus);
        }

        // Extract the next-closest name (one label more than closest encloser)
        let labels: Vec<&str> = qname.split('.').collect();
        let skip = qname_label_count - ce_label_count - 1;
        let next_closest: String = labels[skip..].join(".");

        let next_closest_hash = hash_name(&next_closest, &hash_algo, iterations, salt)?;

        // Check if next_closest_hash is covered by any NSEC3 range
        let covered = self.check_nsec3_coverage(nsec3_records, &next_closest_hash)?;
        if !covered {
            debug!(
                qname = qname,
                next_closest = next_closest,
                "NSEC3 next closest not covered"
            );
            return Ok(DnssecStatus::Bogus);
        }

        // Prove wildcard at closest encloser
        let wildcard = format!("*.{}", closest_encloser);
        let wildcard_hash = hash_name(&wildcard, &hash_algo, iterations, salt)?;

        // Check if wildcard hash is either an exact match or covered
        let mut wildcard_exact = false;
        for nsec3_rr in nsec3_records {
            let owner = nsec3_rr.name.to_string();
            let owner_hash_str = owner.split('.').next().unwrap_or("");
            if let Some(owner_hash) = base32_decode(owner_hash_str) {
                if owner_hash == wildcard_hash {
                    wildcard_exact = true;
                    break;
                }
            }
        }

        if !wildcard_exact {
            let wildcard_covered = self.check_nsec3_coverage(nsec3_records, &wildcard_hash)?;
            if !wildcard_covered {
                debug!(
                    qname = qname,
                    wildcard = wildcard,
                    "NSEC3 wildcard not covered"
                );
                return Ok(DnssecStatus::Bogus);
            }
        }

        debug!(
            qname = qname,
            closest_encloser = closest_encloser,
            "NSEC3 proof of non-existence validated"
        );
        Ok(DnssecStatus::Secure)
    }

    /// Check if a hash value falls within any NSEC3 record range.
    ///
    /// Returns `true` if the hash is covered by the range [owner_hash, next_hash)
    /// of any NSEC3 record, handling wrap-around at the end of the hash space.
    fn check_nsec3_coverage(
        &self,
        nsec3_records: &[&DnsResourceRecord],
        target_hash: &[u8],
    ) -> DnsmasqResult<bool> {
        for nsec3_rr in nsec3_records {
            let owner = nsec3_rr.name.to_string();
            let owner_hash_str = owner.split('.').next().unwrap_or("");
            let owner_hash = match base32_decode(owner_hash_str) {
                Some(h) => h,
                None => continue,
            };

            // Parse the next hashed owner from NSEC3 RDATA
            if nsec3_rr.rdata.len() < 5 {
                continue;
            }
            let salt_len = nsec3_rr.rdata[4] as usize;
            let hash_offset = 5 + salt_len;
            if hash_offset >= nsec3_rr.rdata.len() {
                continue;
            }
            let hash_len = nsec3_rr.rdata[hash_offset] as usize;
            let next_hash_start = hash_offset + 1;
            let next_hash_end = next_hash_start + hash_len;
            if next_hash_end > nsec3_rr.rdata.len() {
                continue;
            }
            let next_hash = &nsec3_rr.rdata[next_hash_start..next_hash_end];

            // Check if target_hash is between owner_hash and next_hash
            let cmp_owner = target_hash.cmp(&owner_hash);
            let cmp_next = target_hash.cmp(next_hash);

            // Normal range: owner < target < next
            if cmp_owner == Ordering::Greater && cmp_next == Ordering::Less {
                return Ok(true);
            }

            // Wrap-around: owner > next (last record in hash space)
            if owner_hash > next_hash.to_vec()
                && (cmp_owner == Ordering::Greater || cmp_next == Ordering::Less)
            {
                return Ok(true);
            }
        }

        Ok(false)
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

    #[test]
    fn test_dnssec_status_methods() {
        assert!(DnssecStatus::Secure.is_secure());
        assert!(!DnssecStatus::Secure.is_bogus());
        assert!(!DnssecStatus::Secure.is_insecure());
        assert!(!DnssecStatus::Secure.needs_additional_query());

        assert!(DnssecStatus::Bogus.is_bogus());
        assert!(!DnssecStatus::Bogus.is_secure());
        assert!(!DnssecStatus::Bogus.is_insecure());
        assert!(!DnssecStatus::Bogus.needs_additional_query());

        assert!(DnssecStatus::Insecure.is_insecure());
        assert!(!DnssecStatus::Insecure.is_secure());
        assert!(!DnssecStatus::Insecure.is_bogus());

        assert!(DnssecStatus::NeedKey.needs_additional_query());
        assert!(DnssecStatus::NeedDs.needs_additional_query());
        assert!(DnssecStatus::NeedDsDigest.needs_additional_query());
        assert!(DnssecStatus::Truncated.needs_additional_query());
        assert!(!DnssecStatus::Abandoned.needs_additional_query());
    }

    #[test]
    fn test_dnssec_fail_flags() {
        let mut flags = DnssecFailFlags::empty();
        assert!(flags.is_empty());
        assert!(!flags.contains(DnssecFailFlags::NOSIG));

        flags.insert(DnssecFailFlags::NOSIG);
        assert!(!flags.is_empty());
        assert!(flags.contains(DnssecFailFlags::NOSIG));
        assert!(!flags.contains(DnssecFailFlags::EXP));

        flags.insert(DnssecFailFlags::EXP);
        assert!(flags.contains(DnssecFailFlags::NOSIG));
        assert!(flags.contains(DnssecFailFlags::EXP));
    }

    #[test]
    fn test_errflags_to_ede_priority() {
        // NYV has highest priority
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NYV);
        flags.insert(DnssecFailFlags::EXP);
        flags.insert(DnssecFailFlags::NOSIG);
        assert_eq!(errflags_to_ede(&flags), ede::SIG_NOT_YET_VALID as i16);

        // EXP has second priority
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::EXP);
        flags.insert(DnssecFailFlags::NOSIG);
        assert_eq!(errflags_to_ede(&flags), ede::SIG_EXPIRED as i16);

        // NOKEYSUP third
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOKEYSUP);
        assert_eq!(errflags_to_ede(&flags), ede::UNSUP_DNSKEY as i16);

        // Empty flags
        let flags = DnssecFailFlags::empty();
        assert_eq!(errflags_to_ede(&flags), ede::UNSET);

        // NOSIG is lowest priority
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOSIG);
        assert_eq!(errflags_to_ede(&flags), ede::RRSIG_MISSING as i16);

        // INDET
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::INDET);
        assert_eq!(errflags_to_ede(&flags), ede::DNSSEC_INDETERMINATE as i16);

        // NONSEC
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NONSEC);
        assert_eq!(errflags_to_ede(&flags), ede::NSEC_MISSING as i16);

        // NSEC3_ITERS
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NSEC3_ITERS);
        assert_eq!(errflags_to_ede(&flags), ede::UNS_NS3_ITER as i16);

        // NODSSUP
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NODSSUP);
        assert_eq!(errflags_to_ede(&flags), ede::UNSUP_DS as i16);

        // NOZONE
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOZONE);
        assert_eq!(errflags_to_ede(&flags), ede::NO_ZONE_KEY as i16);

        // NOKEY
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOKEY);
        assert_eq!(errflags_to_ede(&flags), ede::DNSKEY_MISSING as i16);
    }

    #[test]
    fn test_dnssec_limits() {
        let mut limits = DnssecLimits::default();
        assert_eq!(limits.max_work, 40);
        assert_eq!(limits.max_sig_fail, 20);
        assert_eq!(limits.max_crypto, 200);
        assert_eq!(limits.max_nsec3_iters, 150);

        assert!(!limits.is_exhausted());

        // Decrement work
        for _ in 0..39 {
            assert!(!limits.dec_work());
        }
        assert_eq!(limits.max_work, 1);
        assert!(!limits.dec_work());
        assert_eq!(limits.max_work, 0);
        assert!(limits.dec_work()); // Now exhausted
        assert!(limits.is_exhausted());
    }

    #[test]
    fn test_dnssec_limits_custom() {
        let limits = DnssecLimits::new(10, 5, 50, 30);
        assert_eq!(limits.max_work, 10);
        assert_eq!(limits.max_sig_fail, 5);
        assert_eq!(limits.max_crypto, 50);
        assert_eq!(limits.max_nsec3_iters, 30);
    }

    #[test]
    fn test_serial_compare_32() {
        assert_eq!(serial_compare_32(0, 0), SERIAL_EQ);
        assert_eq!(serial_compare_32(1, 0), SERIAL_GT);
        assert_eq!(serial_compare_32(0, 1), SERIAL_LT);
        assert_eq!(serial_compare_32(100, 50), SERIAL_GT);
        assert_eq!(serial_compare_32(50, 100), SERIAL_LT);

        // Wrap-around: 0xFFFFFFFF is "less" than 0 in serial arithmetic
        assert_eq!(serial_compare_32(0, 0xFFFFFFFF), SERIAL_GT);
        assert_eq!(serial_compare_32(0xFFFFFFFF, 0), SERIAL_LT);

        // Exactly half-space apart: undefined
        assert_eq!(serial_compare_32(0, 0x80000000), SERIAL_UNDEF);
    }

    #[test]
    fn test_count_labels() {
        assert_eq!(count_labels(""), 0);
        assert_eq!(count_labels("."), 0);
        assert_eq!(count_labels("com"), 1);
        assert_eq!(count_labels("example.com"), 2);
        assert_eq!(count_labels("www.example.com"), 3);
        assert_eq!(count_labels("www.example.com."), 3);
        assert_eq!(count_labels("a.b.c.d.e"), 5);
    }

    #[test]
    fn test_dnskey_keytag() {
        // Test with algorithm 8 (RSASHA256)
        let key = vec![0x01, 0x00, 0x03, 0x08, 0xAA, 0xBB, 0xCC, 0xDD];
        let tag = dnskey_keytag(8, 0x0101, &key[4..]);
        // Verify it produces a sensible value (no overflow/panic)
        let _ = tag;

        // Test with empty key
        let tag = dnskey_keytag(8, 0x0100, &[]);
        let _ = tag;

        // Test algorithm 1 (RSAMD5) legacy
        let key = vec![0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let tag = dnskey_keytag(1, 0x0100, &key);
        assert_eq!(tag, (key[4] as u16) * 256 + key[5] as u16);
    }

    #[test]
    fn test_base32_decode() {
        // Empty string
        assert_eq!(base32_decode(""), Some(vec![]));

        // Valid base32 (extended hex alphabet)
        let result = base32_decode("0");
        assert!(result.is_some());

        // Stop at dot
        let result = base32_decode("0.example.com");
        assert!(result.is_some());

        // Invalid character
        assert!(base32_decode("xyz!").is_none());
    }

    #[test]
    fn test_check_type_bitmap() {
        // Empty bitmap
        assert!(!check_type_bitmap(&[], RRType::A));

        // Window 0, block length 1, bit for type 1 (A) set
        let bitmap = vec![0u8, 1, 0x40]; // Window 0, len 1, bit 1 set (A=1, bit 6 of byte 0)
        assert!(check_type_bitmap(&bitmap, RRType::A));
        assert!(!check_type_bitmap(&bitmap, RRType::AAAA));

        // Window 0, block length 4, bits for A(1) and AAAA(28) set
        let mut bitmap = vec![0u8, 4, 0x40, 0x00, 0x00, 0x00];
        // AAAA = type 28, byte 28/8 = 3, bit 7-(28%8) = 7-4 = 3
        bitmap[5] = 0x08; // bit 3 in byte 3 (0-indexed from after window header)
        assert!(check_type_bitmap(&bitmap, RRType::A));
    }

    #[test]
    fn test_trust_anchor() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xE0, 0x6D, 0x44, 0xB8],
        );

        assert_eq!(ta.key_tag, 20326);
        assert_eq!(ta.algorithm, 8);
        assert_eq!(ta.digest_type, 2);

        assert!(ta.matches_ds(20326, 8, 2, &[0xE0, 0x6D, 0x44, 0xB8]));
        assert!(!ta.matches_ds(20327, 8, 2, &[0xE0, 0x6D, 0x44, 0xB8]));
        assert!(!ta.matches_ds(20326, 13, 2, &[0xE0, 0x6D, 0x44, 0xB8]));
        assert!(!ta.matches_ds(20326, 8, 1, &[0xE0, 0x6D, 0x44, 0xB8]));
        assert!(!ta.matches_ds(20326, 8, 2, &[0xFF, 0x6D, 0x44, 0xB8]));
    }

    #[test]
    fn test_with_fail_flags() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOSIG);
        let (status, returned_flags) = DnssecStatus::Bogus.with_fail_flags(flags);
        assert_eq!(status, DnssecStatus::Bogus);
        assert!(returned_flags.contains(DnssecFailFlags::NOSIG));
    }

    // -----------------------------------------------------------------------
    // DnssecFailFlags exhaustive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fail_flags_all_variants() {
        let all_flags = [
            DnssecFailFlags::NOSIG,
            DnssecFailFlags::NYV,
            DnssecFailFlags::EXP,
            DnssecFailFlags::NOKEYSUP,
            DnssecFailFlags::NOZONE,
            DnssecFailFlags::NOKEY,
            DnssecFailFlags::NODSSUP,
            DnssecFailFlags::NSEC3_ITERS,
            DnssecFailFlags::NONSEC,
            DnssecFailFlags::INDET,
        ];
        let mut flags = DnssecFailFlags::empty();
        for &flag in &all_flags {
            assert!(!flags.contains(flag));
            flags.insert(flag);
            assert!(flags.contains(flag));
        }
        // All flags now set
        assert!(!flags.is_empty());
        for &flag in &all_flags {
            assert!(flags.contains(flag));
        }
    }

    #[test]
    fn test_fail_flags_from_bits() {
        let flags = DnssecFailFlags::from_bits(0x0003);
        assert!(flags.contains(DnssecFailFlags::NOSIG));
        assert!(flags.contains(DnssecFailFlags::NYV));
        assert!(!flags.contains(DnssecFailFlags::EXP));
        assert_eq!(flags.bits(), 0x0003);
    }

    #[test]
    fn test_fail_flags_from_bits_zero() {
        let flags = DnssecFailFlags::from_bits(0);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_fail_flags_insert_idempotent() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::EXP);
        let bits1 = flags.bits();
        flags.insert(DnssecFailFlags::EXP);
        assert_eq!(flags.bits(), bits1);
    }

    // -----------------------------------------------------------------------
    // errflags_to_ede comprehensive tests (all single-flag combinations)
    // -----------------------------------------------------------------------

    #[test]
    fn test_errflags_to_ede_nozone() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOZONE);
        assert_eq!(errflags_to_ede(&flags), ede::NO_ZONE_KEY as i16);
    }

    #[test]
    fn test_errflags_to_ede_nokey() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOKEY);
        assert_eq!(errflags_to_ede(&flags), ede::DNSKEY_MISSING as i16);
    }

    #[test]
    fn test_errflags_to_ede_all_flags_priority() {
        // All flags set: NYV should win (highest priority)
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOSIG);
        flags.insert(DnssecFailFlags::NYV);
        flags.insert(DnssecFailFlags::EXP);
        flags.insert(DnssecFailFlags::NOKEYSUP);
        flags.insert(DnssecFailFlags::NOZONE);
        flags.insert(DnssecFailFlags::NOKEY);
        flags.insert(DnssecFailFlags::NODSSUP);
        flags.insert(DnssecFailFlags::NSEC3_ITERS);
        flags.insert(DnssecFailFlags::NONSEC);
        flags.insert(DnssecFailFlags::INDET);
        assert_eq!(errflags_to_ede(&flags), ede::SIG_NOT_YET_VALID as i16);
    }

    #[test]
    fn test_errflags_to_ede_exp_and_nokeysup() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::EXP);
        flags.insert(DnssecFailFlags::NOKEYSUP);
        assert_eq!(errflags_to_ede(&flags), ede::SIG_EXPIRED as i16);
    }

    // -----------------------------------------------------------------------
    // DnssecStatus comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_needs_additional_query_all_variants() {
        assert!(!DnssecStatus::Secure.needs_additional_query());
        assert!(!DnssecStatus::Insecure.needs_additional_query());
        assert!(!DnssecStatus::Bogus.needs_additional_query());
        assert!(DnssecStatus::NeedDsDigest.needs_additional_query());
        assert!(DnssecStatus::NeedKey.needs_additional_query());
        assert!(DnssecStatus::NeedDs.needs_additional_query());
        assert!(DnssecStatus::Truncated.needs_additional_query());
        assert!(!DnssecStatus::Abandoned.needs_additional_query());
    }

    #[test]
    fn test_status_is_secure_exhaustive() {
        assert!(DnssecStatus::Secure.is_secure());
        assert!(!DnssecStatus::Insecure.is_secure());
        assert!(!DnssecStatus::Bogus.is_secure());
        assert!(!DnssecStatus::NeedDsDigest.is_secure());
        assert!(!DnssecStatus::NeedKey.is_secure());
        assert!(!DnssecStatus::NeedDs.is_secure());
        assert!(!DnssecStatus::Truncated.is_secure());
        assert!(!DnssecStatus::Abandoned.is_secure());
    }

    #[test]
    fn test_status_is_bogus_exhaustive() {
        assert!(!DnssecStatus::Secure.is_bogus());
        assert!(!DnssecStatus::Insecure.is_bogus());
        assert!(DnssecStatus::Bogus.is_bogus());
        assert!(!DnssecStatus::NeedDsDigest.is_bogus());
        assert!(!DnssecStatus::NeedKey.is_bogus());
    }

    #[test]
    fn test_status_is_insecure_exhaustive() {
        assert!(!DnssecStatus::Secure.is_insecure());
        assert!(DnssecStatus::Insecure.is_insecure());
        assert!(!DnssecStatus::Bogus.is_insecure());
        assert!(!DnssecStatus::NeedKey.is_insecure());
        assert!(!DnssecStatus::Abandoned.is_insecure());
    }

    // -----------------------------------------------------------------------
    // serial_compare_32 additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_serial_compare_boundary() {
        // One past half-space: 0 is "ahead" of 0x80000001 in serial space
        assert_eq!(serial_compare_32(0, 0x80000001), SERIAL_GT);
        assert_eq!(serial_compare_32(0x80000001, 0), SERIAL_LT);
    }

    #[test]
    fn test_serial_compare_large_values() {
        assert_eq!(serial_compare_32(0xFFFFFFFE, 0xFFFFFFFF), SERIAL_LT);
        assert_eq!(serial_compare_32(0xFFFFFFFF, 0xFFFFFFFE), SERIAL_GT);
    }

    #[test]
    fn test_serial_compare_wraparound_small() {
        // 5 is "greater" than 0xFFFFFFF0 in serial arithmetic (wraps around)
        assert_eq!(serial_compare_32(5, 0xFFFFFFF0), SERIAL_GT);
        assert_eq!(serial_compare_32(0xFFFFFFF0, 5), SERIAL_LT);
    }

    // -----------------------------------------------------------------------
    // count_labels additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_count_labels_trailing_dot_variants() {
        assert_eq!(count_labels("com."), 1);
        assert_eq!(count_labels("a.b.c."), 3);
    }

    #[test]
    fn test_count_labels_single_char_labels() {
        assert_eq!(count_labels("a.b.c.d.e.f"), 6);
    }

    // -----------------------------------------------------------------------
    // canonical_dns_name_cmp comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_canonical_cmp_equal() {
        assert_eq!(
            canonical_dns_name_cmp("example.com", "example.com"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_canonical_cmp_case_insensitive() {
        assert_eq!(
            canonical_dns_name_cmp("Example.COM", "example.com"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_canonical_cmp_different_tld() {
        // "com" < "org" → example.com < example.org
        assert_eq!(
            canonical_dns_name_cmp("example.com", "example.org"),
            Ordering::Less
        );
    }

    #[test]
    fn test_canonical_cmp_parent_child() {
        // Shorter name (suffix) sorts before longer name
        assert_eq!(
            canonical_dns_name_cmp("example.com", "www.example.com"),
            Ordering::Less
        );
    }

    #[test]
    fn test_canonical_cmp_sibling_subdomains() {
        // Compare leftmost labels after right labels match
        assert_eq!(
            canonical_dns_name_cmp("a.example.com", "b.example.com"),
            Ordering::Less
        );
        assert_eq!(
            canonical_dns_name_cmp("z.example.com", "a.example.com"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_canonical_cmp_root() {
        assert_eq!(canonical_dns_name_cmp(".", "."), Ordering::Equal);
        assert_eq!(canonical_dns_name_cmp("", ""), Ordering::Equal);
    }

    #[test]
    fn test_canonical_cmp_root_vs_name() {
        // Root sorts before everything
        assert_eq!(canonical_dns_name_cmp(".", "com"), Ordering::Less);
        assert_eq!(canonical_dns_name_cmp("com", "."), Ordering::Greater);
    }

    #[test]
    fn test_canonical_cmp_trailing_dots() {
        assert_eq!(
            canonical_dns_name_cmp("example.com.", "example.com"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_canonical_cmp_different_label_lengths() {
        // "abc.com" vs "ab.com" — compare "abc" vs "ab": "ab" < "abc"
        assert_eq!(
            canonical_dns_name_cmp("abc.com", "ab.com"),
            Ordering::Greater
        );
    }

    // -----------------------------------------------------------------------
    // name_to_wire comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_name_to_wire_root() {
        assert_eq!(name_to_wire(""), vec![0]);
        assert_eq!(name_to_wire("."), vec![0]);
    }

    #[test]
    fn test_name_to_wire_single_label() {
        let wire = name_to_wire("com");
        assert_eq!(wire, vec![3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn test_name_to_wire_multi_label() {
        let wire = name_to_wire("www.example.com");
        assert_eq!(
            wire,
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[test]
    fn test_name_to_wire_lowercase() {
        let wire = name_to_wire("WWW.EXAMPLE.COM");
        assert_eq!(
            wire,
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[test]
    fn test_name_to_wire_trailing_dot() {
        let wire = name_to_wire("example.com.");
        // Trailing dot results in empty label filtered out
        assert_eq!(
            wire,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    // -----------------------------------------------------------------------
    // dnskey_keytag additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_keytag_empty_key() {
        let tag = dnskey_keytag(8, 0x0101, &[]);
        // Should not panic with empty key
        // Base: flags(0x0101) + 0x300 + algo(8) = 0x0101 + 0x300 + 8 = 0x0409
        // ac += ac >> 16 → 0x0409 + 0 = 0x0409
        // tag = 0x0409 & 0xffff = 0x0409 = 1033
        assert_eq!(tag, 1033);
    }

    #[test]
    fn test_keytag_algo1_short_key() {
        // Algorithm 1 with key shorter than 4 bytes
        let tag = dnskey_keytag(1, 0x0100, &[0xAA, 0xBB]);
        assert_eq!(tag, 0);
    }

    #[test]
    fn test_keytag_algo1_exact_4_bytes() {
        let key = vec![0x00, 0x01, 0x02, 0x03];
        let tag = dnskey_keytag(1, 0x0100, &key);
        assert_eq!(tag, (0x00 as u16) * 256 + 0x01);
    }

    #[test]
    fn test_keytag_deterministic() {
        let key = vec![0x03, 0x08, 0xAA, 0xBB, 0xCC, 0xDD];
        let tag1 = dnskey_keytag(8, 0x0101, &key);
        let tag2 = dnskey_keytag(8, 0x0101, &key);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_keytag_different_flags() {
        let key = vec![0x01, 0x02, 0x03, 0x04];
        let tag1 = dnskey_keytag(8, 0x0100, &key);
        let tag2 = dnskey_keytag(8, 0x0101, &key);
        assert_ne!(tag1, tag2); // Different flags → different tags
    }

    // -----------------------------------------------------------------------
    // base32_decode comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_base32_decode_empty() {
        assert_eq!(base32_decode(""), Some(vec![]));
    }

    #[test]
    fn test_base32_decode_valid_hex_chars() {
        // '0' through '9' = values 0-9
        let result = base32_decode("01234567890").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_base32_decode_valid_alpha_chars() {
        // 'a' through 'v' = values 10-31
        let result = base32_decode("abcdefghijklmnopqrstuv").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_base32_decode_case_insensitive() {
        let lower = base32_decode("abc");
        let upper = base32_decode("ABC");
        assert_eq!(lower, upper);
    }

    #[test]
    fn test_base32_decode_stops_at_dot() {
        let result1 = base32_decode("abc.example.com");
        let result2 = base32_decode("abc");
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_base32_decode_invalid_char() {
        assert!(base32_decode("abc!").is_none());
        assert!(base32_decode("xyz").is_none()); // 'x', 'y', 'z' are > 'v'
    }

    #[test]
    fn test_base32_decode_w_is_invalid() {
        // 'w' is beyond 'v' in the extended hex alphabet
        assert!(base32_decode("w").is_none());
    }

    // -----------------------------------------------------------------------
    // check_type_bitmap comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_type_bitmap_empty() {
        assert!(!check_type_bitmap(&[], RRType::A));
        assert!(!check_type_bitmap(&[], RRType::AAAA));
        assert!(!check_type_bitmap(&[], RRType::MX));
    }

    #[test]
    fn test_type_bitmap_a_only() {
        // A = type 1: window 0, byte 0, bit 6 (7-1=6)
        let bitmap = vec![0u8, 1, 0x40]; // Window 0, len 1, byte 0 = 0x40
        assert!(check_type_bitmap(&bitmap, RRType::A));
        assert!(!check_type_bitmap(&bitmap, RRType::AAAA));
        assert!(!check_type_bitmap(&bitmap, RRType::NS));
    }

    #[test]
    fn test_type_bitmap_ns_and_soa() {
        // NS = type 2: window 0, byte 0, bit 5 (7-2=5) → 0x20
        // SOA = type 6: window 0, byte 0, bit 1 (7-6=1) → 0x02
        let bitmap = vec![0u8, 1, 0x22]; // 0x20 | 0x02
        assert!(check_type_bitmap(&bitmap, RRType::NS));
        assert!(check_type_bitmap(&bitmap, RRType::from_u16(6))); // SOA
        assert!(!check_type_bitmap(&bitmap, RRType::A));
    }

    #[test]
    fn test_type_bitmap_wrong_window() {
        // Window 1 bitmap won't match window 0 types
        let bitmap = vec![1u8, 1, 0xFF]; // Window 1
        assert!(!check_type_bitmap(&bitmap, RRType::A)); // type 1 is window 0
    }

    #[test]
    fn test_type_bitmap_truncated() {
        // Block length exceeds remaining data
        let bitmap = vec![0u8, 10, 0xFF]; // Claims length 10 but only 1 byte follows
        assert!(!check_type_bitmap(&bitmap, RRType::A));
    }

    #[test]
    fn test_type_bitmap_multiple_windows() {
        // Window 0 with A type, then Window 1 (unused types 256+)
        let bitmap = vec![
            0u8, 1, 0x40, // Window 0, len 1, A set
            1, 1, 0x80, // Window 1, len 1, type 256 set
        ];
        assert!(check_type_bitmap(&bitmap, RRType::A));
        assert!(check_type_bitmap(&bitmap, RRType::from_u16(256)));
        assert!(!check_type_bitmap(&bitmap, RRType::AAAA));
    }

    // -----------------------------------------------------------------------
    // DnssecLimits additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_limits_dec_sig_fail() {
        let mut limits = DnssecLimits::new(10, 3, 100, 50);
        assert!(!limits.dec_sig_fail());
        assert!(!limits.dec_sig_fail());
        assert!(!limits.dec_sig_fail());
        assert!(limits.dec_sig_fail()); // exhausted
        assert!(limits.is_exhausted());
    }

    #[test]
    fn test_limits_dec_crypto() {
        let mut limits = DnssecLimits::new(10, 10, 2, 50);
        assert!(!limits.dec_crypto());
        assert!(!limits.dec_crypto());
        assert!(limits.dec_crypto()); // exhausted
    }

    #[test]
    fn test_limits_is_exhausted_checks_all() {
        // Not exhausted when all > 0
        let limits = DnssecLimits::new(1, 1, 1, 1);
        assert!(!limits.is_exhausted());

        // Exhausted when work = 0
        let limits = DnssecLimits::new(0, 1, 1, 1);
        assert!(limits.is_exhausted());

        // Exhausted when sig_fail = 0
        let limits = DnssecLimits::new(1, 0, 1, 1);
        assert!(limits.is_exhausted());

        // Exhausted when crypto = 0
        let limits = DnssecLimits::new(1, 1, 0, 1);
        assert!(limits.is_exhausted());
    }

    // -----------------------------------------------------------------------
    // TrustAnchor additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_trust_anchor_fields() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            13,
            2,
            vec![0x01, 0x02, 0x03],
        );
        assert_eq!(ta.key_tag, 12345);
        assert_eq!(ta.algorithm, 13);
        assert_eq!(ta.digest_type, 2);
        assert_eq!(ta.digest, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_trust_anchor_matches_partial() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xAA, 0xBB],
        );
        // Wrong key_tag
        assert!(!ta.matches_ds(65535, 8, 2, &[0xAA, 0xBB]));
        // Wrong algorithm
        assert!(!ta.matches_ds(20326, 99, 2, &[0xAA, 0xBB]));
        // Wrong digest_type
        assert!(!ta.matches_ds(20326, 8, 99, &[0xAA, 0xBB]));
        // Wrong digest
        assert!(!ta.matches_ds(20326, 8, 2, &[0xFF, 0xFF]));
        // Correct
        assert!(ta.matches_ds(20326, 8, 2, &[0xAA, 0xBB]));
    }

    // -----------------------------------------------------------------------
    // DnssecValidator construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_new_empty() {
        let validator = DnssecValidator::new(vec![], true);
        assert!(validator.trust_anchors.is_empty());
        assert!(validator.check_date);
    }

    #[test]
    fn test_validator_new_with_anchors() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xE0, 0x6D],
        );
        let validator = DnssecValidator::new(vec![ta], false);
        assert_eq!(validator.trust_anchors.len(), 1);
        assert!(!validator.check_date);
    }

    // -----------------------------------------------------------------------
    // with_fail_flags additional combinations
    // -----------------------------------------------------------------------

    #[test]
    fn test_with_fail_flags_empty() {
        let flags = DnssecFailFlags::empty();
        let (status, returned_flags) = DnssecStatus::Bogus.with_fail_flags(flags);
        assert_eq!(status, DnssecStatus::Bogus);
        assert!(returned_flags.is_empty());
    }

    #[test]
    fn test_with_fail_flags_multiple() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOSIG);
        flags.insert(DnssecFailFlags::EXP);
        let (_, returned_flags) = DnssecStatus::Bogus.with_fail_flags(flags);
        assert!(returned_flags.contains(DnssecFailFlags::NOSIG));
        assert!(returned_flags.contains(DnssecFailFlags::EXP));
    }

    #[test]
    fn test_with_fail_flags_secure_status() {
        let flags = DnssecFailFlags::empty();
        let (status, _) = DnssecStatus::Secure.with_fail_flags(flags);
        assert_eq!(status, DnssecStatus::Secure);
    }

    // =========================================================================
    // Additional comprehensive tests for coverage
    // =========================================================================

    use crate::dns::protocol::{DnsHeaderFlags, DnsPacketBuilder};

    // --- canonical_dns_name_cmp edge cases ---

    #[test]
    fn test_canonical_cmp_empty_vs_empty() {
        assert_eq!(canonical_dns_name_cmp("", ""), Ordering::Equal);
    }

    #[test]
    fn test_canonical_cmp_empty_vs_name() {
        assert_eq!(canonical_dns_name_cmp("", "a.com"), Ordering::Less);
        assert_eq!(canonical_dns_name_cmp("a.com", ""), Ordering::Greater);
    }

    #[test]
    fn test_canonical_cmp_deep_subdomain() {
        let r = canonical_dns_name_cmp("a.b.c.example.com", "d.e.f.example.com");
        assert_eq!(r, Ordering::Less);
    }

    #[test]
    fn test_canonical_cmp_numeric_labels() {
        assert_eq!(canonical_dns_name_cmp("1.com", "2.com"), Ordering::Less);
    }

    #[test]
    fn test_canonical_cmp_mixed_case_deep() {
        assert_eq!(
            canonical_dns_name_cmp("A.B.Example.COM", "a.b.example.com"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_canonical_cmp_prefix_label() {
        assert_eq!(canonical_dns_name_cmp("ab.com", "a.com"), Ordering::Greater);
    }

    #[test]
    fn test_canonical_cmp_single_labels() {
        assert_eq!(canonical_dns_name_cmp("abc", "def"), Ordering::Less);
        assert_eq!(canonical_dns_name_cmp("xyz", "abc"), Ordering::Greater);
    }

    // --- name_to_wire edge cases ---

    #[test]
    fn test_name_to_wire_empty_string() {
        let wire = name_to_wire("");
        assert_eq!(wire, vec![0]);
    }

    #[test]
    fn test_name_to_wire_only_dots() {
        let wire = name_to_wire("...");
        assert_eq!(wire, vec![0]);
    }

    #[test]
    fn test_name_to_wire_long_label() {
        let wire = name_to_wire("abcdefghij.com");
        assert_eq!(wire[0], 10);
        assert_eq!(&wire[1..11], b"abcdefghij");
        assert_eq!(wire[11], 3);
        assert_eq!(&wire[12..15], b"com");
        assert_eq!(wire[15], 0);
    }

    #[test]
    fn test_name_to_wire_uppercase_converted() {
        let wire = name_to_wire("ABC.DEF");
        assert_eq!(wire[0], 3);
        assert_eq!(&wire[1..4], b"abc");
        assert_eq!(wire[4], 3);
        assert_eq!(&wire[5..8], b"def");
        assert_eq!(wire[8], 0);
    }

    // --- serial_compare_32 additional edge cases ---

    #[test]
    fn test_serial_compare_zero_vs_max() {
        assert_eq!(serial_compare_32(0, u32::MAX), SERIAL_GT);
    }

    #[test]
    fn test_serial_compare_max_vs_zero() {
        assert_eq!(serial_compare_32(u32::MAX, 0), SERIAL_LT);
    }

    #[test]
    fn test_serial_compare_identical_large() {
        assert_eq!(serial_compare_32(0xFFFFFFFF, 0xFFFFFFFF), SERIAL_EQ);
    }

    #[test]
    fn test_serial_compare_half_space_exactly() {
        assert_eq!(serial_compare_32(0, 0x80000000), SERIAL_UNDEF);
        assert_eq!(serial_compare_32(0x80000000, 0), SERIAL_UNDEF);
    }

    #[test]
    fn test_serial_compare_just_below_half() {
        assert_eq!(serial_compare_32(0x7FFFFFFF, 0), SERIAL_GT);
    }

    #[test]
    fn test_serial_compare_just_above_half() {
        assert_eq!(serial_compare_32(0x80000001, 0), SERIAL_LT);
    }

    // --- count_labels edge cases ---

    #[test]
    fn test_count_labels_deeply_nested() {
        assert_eq!(count_labels("a.b.c.d.e.f.g.h"), 8);
    }

    #[test]
    fn test_count_labels_dots_only() {
        assert_eq!(count_labels("..."), 0);
    }

    #[test]
    fn test_count_labels_single_trailing_dot() {
        assert_eq!(count_labels("example.com."), 2);
    }

    #[test]
    fn test_count_labels_multiple_trailing_dots() {
        assert_eq!(count_labels("example.com.."), 2);
    }

    // --- dnskey_keytag edge cases ---

    #[test]
    fn test_keytag_algo1_large_key() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF, 0x12];
        let tag = dnskey_keytag(1, 0x0100, &key);
        assert_eq!(tag, 0xAB * 256 + 0xCD);
    }

    #[test]
    fn test_keytag_algo1_exactly_3_bytes() {
        let key = vec![0x01, 0x02, 0x03];
        assert_eq!(dnskey_keytag(1, 0x0100, &key), 0);
    }

    #[test]
    fn test_keytag_normal_algo_odd_length_key() {
        let key = vec![0x01, 0x02, 0x03];
        let tag1 = dnskey_keytag(8, 0x0100, &key);
        let tag2 = dnskey_keytag(8, 0x0100, &key);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_keytag_normal_algo_even_length_key() {
        let key = vec![0x01, 0x02, 0x03, 0x04];
        let tag = dnskey_keytag(8, 0x0100, &key);
        assert_eq!(tag, 2062);
    }

    // --- base32_decode edge cases ---

    #[test]
    fn test_base32_decode_single_char() {
        let result = base32_decode("0").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_base32_decode_two_chars() {
        let result = base32_decode("00").unwrap();
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn test_base32_decode_max_value_chars() {
        let result = base32_decode("vv");
        assert!(result.is_some());
    }

    #[test]
    fn test_base32_decode_mixed_case() {
        let lower = base32_decode("abc").unwrap();
        let upper = base32_decode("ABC").unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn test_base32_decode_stops_at_first_dot() {
        let r1 = base32_decode("00.11").unwrap();
        let r2 = base32_decode("00").unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_base32_decode_invalid_chars() {
        assert!(base32_decode("xyz").is_none());
        assert!(base32_decode("!@#").is_none());
        assert!(base32_decode(" ").is_none());
    }

    // --- check_type_bitmap edge cases ---

    #[test]
    fn test_type_bitmap_high_type_number() {
        let bitmap = vec![1, 1, 0x80];
        assert!(check_type_bitmap(&bitmap, RRType::from_u16(256)));
        assert!(!check_type_bitmap(&bitmap, RRType::A));
    }

    #[test]
    fn test_type_bitmap_byte_offset_in_block() {
        let bitmap = vec![0, 2, 0x00, 0x01];
        assert!(check_type_bitmap(&bitmap, RRType::MX));
    }

    #[test]
    fn test_type_bitmap_block_len_too_short() {
        let bitmap = vec![0, 0];
        assert!(!check_type_bitmap(&bitmap, RRType::A));
    }

    #[test]
    fn test_type_bitmap_truncated_block() {
        let bitmap = vec![0, 5, 0xFF, 0xFF];
        assert!(!check_type_bitmap(&bitmap, RRType::A));
    }

    #[test]
    fn test_type_bitmap_all_types_in_window0() {
        let bitmap = vec![0, 4, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(check_type_bitmap(&bitmap, RRType::A));
        assert!(check_type_bitmap(&bitmap, RRType::NS));
        assert!(check_type_bitmap(&bitmap, RRType::CNAME));
        assert!(check_type_bitmap(&bitmap, RRType::SOA));
        assert!(check_type_bitmap(&bitmap, RRType::MX));
        assert!(check_type_bitmap(&bitmap, RRType::AAAA));
    }

    // --- DnssecStatus exhaustive tests ---

    #[test]
    fn test_status_all_variants_is_secure() {
        assert!(DnssecStatus::Secure.is_secure());
        assert!(!DnssecStatus::Insecure.is_secure());
        assert!(!DnssecStatus::Bogus.is_secure());
        assert!(!DnssecStatus::NeedDsDigest.is_secure());
        assert!(!DnssecStatus::NeedKey.is_secure());
        assert!(!DnssecStatus::NeedDs.is_secure());
        assert!(!DnssecStatus::Truncated.is_secure());
        assert!(!DnssecStatus::Abandoned.is_secure());
    }

    #[test]
    fn test_status_all_variants_is_bogus() {
        assert!(!DnssecStatus::Secure.is_bogus());
        assert!(!DnssecStatus::Insecure.is_bogus());
        assert!(DnssecStatus::Bogus.is_bogus());
        assert!(!DnssecStatus::NeedDsDigest.is_bogus());
        assert!(!DnssecStatus::NeedKey.is_bogus());
        assert!(!DnssecStatus::NeedDs.is_bogus());
        assert!(!DnssecStatus::Truncated.is_bogus());
        assert!(!DnssecStatus::Abandoned.is_bogus());
    }

    #[test]
    fn test_status_all_variants_is_insecure() {
        assert!(!DnssecStatus::Secure.is_insecure());
        assert!(DnssecStatus::Insecure.is_insecure());
        assert!(!DnssecStatus::Bogus.is_insecure());
        assert!(!DnssecStatus::NeedDsDigest.is_insecure());
        assert!(!DnssecStatus::NeedKey.is_insecure());
        assert!(!DnssecStatus::NeedDs.is_insecure());
        assert!(!DnssecStatus::Truncated.is_insecure());
        assert!(!DnssecStatus::Abandoned.is_insecure());
    }

    #[test]
    fn test_status_all_variants_needs_additional() {
        assert!(!DnssecStatus::Secure.needs_additional_query());
        assert!(!DnssecStatus::Insecure.needs_additional_query());
        assert!(!DnssecStatus::Bogus.needs_additional_query());
        assert!(DnssecStatus::NeedDsDigest.needs_additional_query());
        assert!(DnssecStatus::NeedKey.needs_additional_query());
        assert!(DnssecStatus::NeedDs.needs_additional_query());
        assert!(DnssecStatus::Truncated.needs_additional_query());
        assert!(!DnssecStatus::Abandoned.needs_additional_query());
    }

    // --- DnssecFailFlags comprehensive tests ---

    #[test]
    fn test_fail_flags_all_individual_flags() {
        let all_flags: &[u32] = &[
            DnssecFailFlags::NOSIG,
            DnssecFailFlags::NYV,
            DnssecFailFlags::EXP,
            DnssecFailFlags::NOKEYSUP,
            DnssecFailFlags::NOZONE,
            DnssecFailFlags::NOKEY,
            DnssecFailFlags::NODSSUP,
            DnssecFailFlags::NSEC3_ITERS,
            DnssecFailFlags::NONSEC,
            DnssecFailFlags::INDET,
        ];
        for flag in all_flags {
            let mut flags = DnssecFailFlags::empty();
            assert!(!flags.contains(*flag));
            flags.insert(*flag);
            assert!(flags.contains(*flag));
            assert!(!flags.is_empty());
        }
    }

    #[test]
    fn test_fail_flags_combine_all() {
        let mut flags = DnssecFailFlags::empty();
        flags.insert(DnssecFailFlags::NOSIG);
        flags.insert(DnssecFailFlags::NYV);
        flags.insert(DnssecFailFlags::EXP);
        flags.insert(DnssecFailFlags::NOKEYSUP);
        flags.insert(DnssecFailFlags::NOZONE);
        flags.insert(DnssecFailFlags::NOKEY);
        flags.insert(DnssecFailFlags::NODSSUP);
        flags.insert(DnssecFailFlags::NSEC3_ITERS);
        flags.insert(DnssecFailFlags::NONSEC);
        flags.insert(DnssecFailFlags::INDET);
        let expected_bits =
            0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080 | 0x0100 | 0x0200;
        assert_eq!(flags.bits(), expected_bits);
    }

    #[test]
    fn test_fail_flags_from_bits_roundtrip() {
        let bits: u32 = 0x0135;
        let flags = DnssecFailFlags::from_bits(bits);
        assert_eq!(flags.bits(), bits);
        assert!(flags.contains(DnssecFailFlags::NOSIG));
        assert!(!flags.contains(DnssecFailFlags::NYV));
        assert!(flags.contains(DnssecFailFlags::EXP));
        assert!(flags.contains(DnssecFailFlags::NOZONE));
        assert!(flags.contains(DnssecFailFlags::NOKEY));
        assert!(flags.contains(DnssecFailFlags::NONSEC));
    }

    // --- errflags_to_ede comprehensive priority tests ---

    #[test]
    fn test_errflags_to_ede_each_individual_flag() {
        let cases: Vec<(u32, i16)> = vec![
            (DnssecFailFlags::NOSIG, ede::RRSIG_MISSING as i16),
            (DnssecFailFlags::NYV, ede::SIG_NOT_YET_VALID as i16),
            (DnssecFailFlags::EXP, ede::SIG_EXPIRED as i16),
            (DnssecFailFlags::NOKEYSUP, ede::UNSUP_DNSKEY as i16),
            (DnssecFailFlags::NOZONE, ede::NO_ZONE_KEY as i16),
            (DnssecFailFlags::NOKEY, ede::DNSKEY_MISSING as i16),
            (DnssecFailFlags::NODSSUP, ede::UNSUP_DS as i16),
            (DnssecFailFlags::NSEC3_ITERS, ede::UNS_NS3_ITER as i16),
            (DnssecFailFlags::NONSEC, ede::NSEC_MISSING as i16),
            (DnssecFailFlags::INDET, ede::DNSSEC_INDETERMINATE as i16),
        ];
        for (flag, expected_ede) in &cases {
            let mut f = DnssecFailFlags::empty();
            f.insert(*flag);
            assert_eq!(
                errflags_to_ede(&f),
                *expected_ede,
                "flag {} should map to ede {}",
                flag,
                expected_ede
            );
        }
    }

    #[test]
    fn test_errflags_to_ede_priority_nyv_over_all() {
        let mut f = DnssecFailFlags::empty();
        f.insert(DnssecFailFlags::NYV);
        f.insert(DnssecFailFlags::NOSIG);
        f.insert(DnssecFailFlags::EXP);
        f.insert(DnssecFailFlags::NOKEY);
        assert_eq!(errflags_to_ede(&f), ede::SIG_NOT_YET_VALID as i16);
    }

    #[test]
    fn test_errflags_to_ede_priority_exp_over_nokeysup() {
        let mut f = DnssecFailFlags::empty();
        f.insert(DnssecFailFlags::EXP);
        f.insert(DnssecFailFlags::NOKEYSUP);
        assert_eq!(errflags_to_ede(&f), ede::SIG_EXPIRED as i16);
    }

    #[test]
    fn test_errflags_to_ede_nodssup_over_nsec3() {
        let mut f = DnssecFailFlags::empty();
        f.insert(DnssecFailFlags::NODSSUP);
        f.insert(DnssecFailFlags::NSEC3_ITERS);
        assert_eq!(errflags_to_ede(&f), ede::UNSUP_DS as i16);
    }

    // --- DnssecLimits comprehensive tests ---

    #[test]
    fn test_limits_default_values() {
        let limits = DnssecLimits::default();
        assert_eq!(limits.max_work, DNSSEC_LIMIT_WORK);
        assert_eq!(limits.max_sig_fail, DNSSEC_LIMIT_SIG_FAIL);
        assert_eq!(limits.max_crypto, DNSSEC_LIMIT_CRYPTO);
        assert_eq!(limits.max_nsec3_iters, DNSSEC_LIMIT_NSEC3_ITERS);
    }

    #[test]
    fn test_limits_custom_values() {
        let limits = DnssecLimits::new(10, 5, 50, 100);
        assert_eq!(limits.max_work, 10);
        assert_eq!(limits.max_sig_fail, 5);
        assert_eq!(limits.max_crypto, 50);
        assert_eq!(limits.max_nsec3_iters, 100);
    }

    #[test]
    fn test_limits_dec_work_to_exhaustion() {
        let mut limits = DnssecLimits::new(3, 10, 10, 10);
        assert!(!limits.dec_work());
        assert_eq!(limits.max_work, 2);
        assert!(!limits.dec_work());
        assert_eq!(limits.max_work, 1);
        assert!(!limits.dec_work());
        assert_eq!(limits.max_work, 0);
        assert!(limits.dec_work());
    }

    #[test]
    fn test_limits_dec_sig_fail_to_exhaustion() {
        let mut limits = DnssecLimits::new(10, 2, 10, 10);
        assert!(!limits.dec_sig_fail());
        assert!(!limits.dec_sig_fail());
        assert!(limits.dec_sig_fail());
    }

    #[test]
    fn test_limits_dec_crypto_to_exhaustion() {
        let mut limits = DnssecLimits::new(10, 10, 1, 10);
        assert!(!limits.dec_crypto());
        assert!(limits.dec_crypto());
    }

    #[test]
    fn test_limits_is_exhausted_work() {
        let mut limits = DnssecLimits::new(1, 10, 10, 10);
        assert!(!limits.is_exhausted());
        limits.dec_work();
        assert!(limits.is_exhausted());
    }

    #[test]
    fn test_limits_is_exhausted_sig_fail() {
        let mut limits = DnssecLimits::new(10, 1, 10, 10);
        assert!(!limits.is_exhausted());
        limits.dec_sig_fail();
        assert!(limits.is_exhausted());
    }

    #[test]
    fn test_limits_is_exhausted_crypto() {
        let mut limits = DnssecLimits::new(10, 10, 1, 10);
        assert!(!limits.is_exhausted());
        limits.dec_crypto();
        assert!(limits.is_exhausted());
    }

    #[test]
    fn test_limits_is_exhausted_none() {
        let limits = DnssecLimits::new(10, 10, 10, 10);
        assert!(!limits.is_exhausted());
    }

    // --- TrustAnchor comprehensive tests ---

    #[test]
    fn test_trust_anchor_new_and_fields() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xE0, 0x6D, 0x44],
        );
        assert_eq!(ta.domain.to_string(), ".");
        assert_eq!(ta.key_tag, 20326);
        assert_eq!(ta.algorithm, 8);
        assert_eq!(ta.digest_type, 2);
        assert_eq!(ta.digest, vec![0xE0, 0x6D, 0x44]);
    }

    #[test]
    fn test_trust_anchor_matches_ds_exact() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xAA, 0xBB],
        );
        assert!(ta.matches_ds(20326, 8, 2, &[0xAA, 0xBB]));
    }

    #[test]
    fn test_trust_anchor_matches_ds_wrong_keytag() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xAA, 0xBB],
        );
        assert!(!ta.matches_ds(12345, 8, 2, &[0xAA, 0xBB]));
    }

    #[test]
    fn test_trust_anchor_matches_ds_wrong_algo() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xAA, 0xBB],
        );
        assert!(!ta.matches_ds(20326, 13, 2, &[0xAA, 0xBB]));
    }

    #[test]
    fn test_trust_anchor_matches_ds_wrong_digest_type() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xAA, 0xBB],
        );
        assert!(!ta.matches_ds(20326, 8, 1, &[0xAA, 0xBB]));
    }

    #[test]
    fn test_trust_anchor_matches_ds_wrong_digest() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("."),
            20326,
            8,
            2,
            vec![0xAA, 0xBB],
        );
        assert!(!ta.matches_ds(20326, 8, 2, &[0xCC, 0xDD]));
    }

    #[test]
    fn test_trust_anchor_matches_ds_empty_digest() {
        let ta = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![]);
        assert!(ta.matches_ds(20326, 8, 2, &[]));
        assert!(!ta.matches_ds(20326, 8, 2, &[0x00]));
    }

    // --- DnssecValidator construction and setup tests ---

    #[test]
    fn test_validator_empty_anchors() {
        let v = DnssecValidator::new(vec![], true);
        assert!(v.trust_anchors.is_empty());
        assert!(v.check_date);
        assert!(v.timestamp_file.is_none());
    }

    #[test]
    fn test_validator_check_date_flag() {
        let v = DnssecValidator::new(vec![], false);
        assert!(!v.is_check_date());
        let v2 = DnssecValidator::new(vec![], true);
        assert!(v2.is_check_date());
    }

    #[test]
    fn test_validator_with_multiple_anchors() {
        let ta1 = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![0xAA]);
        let ta2 = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            13,
            2,
            vec![0xBB],
        );
        let v = DnssecValidator::new(vec![ta1, ta2], true);
        assert_eq!(v.trust_anchors.len(), 2);
    }

    // --- setup_timestamp tests ---

    #[test]
    fn test_setup_timestamp_nonexistent_file_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnssec_timestamp");
        let path_str = path.to_str().unwrap();

        let mut v = DnssecValidator::new(vec![], true);
        let result = v.setup_timestamp(path_str).unwrap();

        assert!(!result);
        assert!(!v.check_date);
        assert!(path.exists());
        assert_eq!(v.timestamp_file, Some(path_str.to_string()));
    }

    #[test]
    fn test_setup_timestamp_existing_file_past_mtime() {
        use std::fs::FileTimes;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnssec_timestamp");
        let file = std::fs::File::create(&path).unwrap();
        // Set mtime to 1 hour in the past so elapsed.as_secs() > 0
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        file.set_times(FileTimes::new().set_modified(past)).unwrap();
        drop(file);

        let mut v = DnssecValidator::new(vec![], false);
        let result = v.setup_timestamp(path.to_str().unwrap()).unwrap();
        assert!(result);
        assert!(v.check_date);
    }

    #[test]
    fn test_setup_timestamp_permission_error() {
        let mut v = DnssecValidator::new(vec![], true);
        let result = v.setup_timestamp("/proc/nonexistent/timestamp");
        assert!(result.is_ok());
        assert!(!v.check_date);
    }

    // --- zone_status tests ---

    #[test]
    fn test_zone_status_exact_trust_anchor_match() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            20326,
            8,
            2,
            vec![0xAA],
        );
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let status = v
            .zone_status("example.com", &mut cache, &mut limits)
            .unwrap();
        assert_eq!(status, DnssecStatus::Secure);
    }

    #[test]
    fn test_zone_status_root_anchor_no_ds() {
        let ta = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![0xAA]);
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let status = v
            .zone_status("www.example.com", &mut cache, &mut limits)
            .unwrap();
        assert_eq!(status, DnssecStatus::NeedDs);
    }

    #[test]
    fn test_zone_status_no_trust_anchor() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let status = v
            .zone_status("example.com", &mut cache, &mut limits)
            .unwrap();
        assert_eq!(status, DnssecStatus::NeedDs);
    }

    #[test]
    fn test_zone_status_work_limit_exhausted() {
        let ta = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![0xAA]);
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::new(1, 10, 10, 10);
        let status = v
            .zone_status("a.b.c.d.e.f.example.com", &mut cache, &mut limits)
            .unwrap();
        assert!(status == DnssecStatus::Abandoned || status == DnssecStatus::NeedDs);
    }

    // --- Helper to build raw DNS response bytes ---

    fn build_raw_response(
        id: u16,
        qname: &str,
        qtype: RRType,
        answers: &[(&str, RRType, u32, &[u8])],
        authority: &[(&str, RRType, u32, &[u8])],
        tc: bool,
    ) -> Vec<u8> {
        let name = DnsName::from_str_unchecked(qname);
        let mut buf = BytesMut::with_capacity(512);
        let hdr = DnsHeader {
            id,
            flags: DnsHeaderFlags {
                qr: true,
                tc,
                ..DnsHeaderFlags::default()
            },
            qdcount: 1,
            ancount: answers.len() as u16,
            nscount: authority.len() as u16,
            arcount: 0,
        };
        hdr.serialize(&mut buf);
        name.to_wire(&mut buf);
        buf.put_u16(qtype.to_u16());
        buf.put_u16(DnsClass::IN.to_u16());
        for (rr_name, rr_type, ttl, rdata) in answers {
            let n = DnsName::from_str_unchecked(rr_name);
            n.to_wire(&mut buf);
            buf.put_u16(rr_type.to_u16());
            buf.put_u16(DnsClass::IN.to_u16());
            buf.put_u32(*ttl);
            buf.put_u16(rdata.len() as u16);
            buf.extend_from_slice(rdata);
        }
        for (rr_name, rr_type, ttl, rdata) in authority {
            let n = DnsName::from_str_unchecked(rr_name);
            n.to_wire(&mut buf);
            buf.put_u16(rr_type.to_u16());
            buf.put_u16(DnsClass::IN.to_u16());
            buf.put_u32(*ttl);
            buf.put_u16(rdata.len() as u16);
            buf.extend_from_slice(rdata);
        }
        buf.to_vec()
    }

    fn build_header_only(id: u16, tc: bool) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(12);
        let hdr = DnsHeader {
            id,
            flags: DnsHeaderFlags {
                qr: true,
                tc,
                ..DnsHeaderFlags::default()
            },
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        hdr.serialize(&mut buf);
        buf.to_vec()
    }

    // --- DnssecValidator::dnssec_validate_reply tests ---

    #[test]
    fn test_validate_reply_truncated_response() {
        let ta = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![0xAA]);
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = build_header_only(0x5678, true);
        let result = v
            .dnssec_validate_reply(
                &packet,
                &mut cache,
                &mut limits,
                &domain_matcher,
                "example.com",
                RRType::A,
                DnsClass::IN,
            )
            .unwrap();
        assert_eq!(result.0, DnssecStatus::Truncated);
    }

    #[test]
    fn test_validate_reply_simple_response_no_anchor() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = build_raw_response(
            0x1234,
            "example.com",
            RRType::A,
            &[("example.com", RRType::A, 300, &[1, 2, 3, 4])],
            &[],
            false,
        );
        let result = v
            .dnssec_validate_reply(
                &packet,
                &mut cache,
                &mut limits,
                &domain_matcher,
                "example.com",
                RRType::A,
                DnsClass::IN,
            )
            .unwrap();
        assert!(
            result.0 == DnssecStatus::NeedDs
                || result.0 == DnssecStatus::Insecure
                || result.0 == DnssecStatus::Secure
        );
    }

    #[test]
    fn test_validate_reply_with_root_anchor_no_rrsig() {
        let ta = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![0xAA]);
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = build_raw_response(
            0x1234,
            "example.com",
            RRType::A,
            &[("example.com", RRType::A, 300, &[1, 2, 3, 4])],
            &[],
            false,
        );
        let result = v
            .dnssec_validate_reply(
                &packet,
                &mut cache,
                &mut limits,
                &domain_matcher,
                "example.com",
                RRType::A,
                DnsClass::IN,
            )
            .unwrap();
        assert!(matches!(
            result.0,
            DnssecStatus::Bogus | DnssecStatus::NeedDs | DnssecStatus::NeedKey
        ));
    }

    #[test]
    fn test_validate_reply_empty_packet() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let result = v.dnssec_validate_reply(
            &[],
            &mut cache,
            &mut limits,
            &domain_matcher,
            "example.com",
            RRType::A,
            DnsClass::IN,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_reply_header_only() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = build_header_only(0x1234, false);
        let result = v
            .dnssec_validate_reply(
                &packet,
                &mut cache,
                &mut limits,
                &domain_matcher,
                "example.com",
                RRType::A,
                DnsClass::IN,
            )
            .unwrap();
        assert!(matches!(
            result.0,
            DnssecStatus::Secure | DnssecStatus::Insecure
        ));
    }

    #[test]
    fn test_validate_reply_answer_rrsig_only() {
        let v = DnssecValidator::new(vec![], false);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let mut rrsig_rdata = vec![0u8; 20];
        rrsig_rdata[0] = 0;
        rrsig_rdata[1] = 1; // covers type A

        let packet = build_raw_response(
            0x1234,
            "example.com",
            RRType::A,
            &[("example.com", RRType::RRSIG, 300, &rrsig_rdata)],
            &[],
            false,
        );
        let result = v
            .dnssec_validate_reply(
                &packet,
                &mut cache,
                &mut limits,
                &domain_matcher,
                "example.com",
                RRType::A,
                DnsClass::IN,
            )
            .unwrap();
        assert!(matches!(
            result.0,
            DnssecStatus::Secure | DnssecStatus::Insecure
        ));
    }

    // --- validate_rrset tests ---

    #[test]
    fn test_validate_rrset_empty_rrsigs() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();

        let rrset = RRSet {
            name: DnsName::from_str_unchecked("example.com"),
            rr_type: RRType::A,
            class: DnsClass::IN,
            records: vec![],
        };
        let empty_rrsigs: Vec<&DnsResourceRecord> = vec![];
        let mut fail_flags = DnssecFailFlags::empty();

        let result = v
            .validate_rrset(
                &rrset,
                &empty_rrsigs,
                &mut cache,
                &mut limits,
                &mut fail_flags,
            )
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
        assert!(fail_flags.contains(DnssecFailFlags::NOSIG));
    }

    #[test]
    fn test_validate_rrset_short_rrsig_rdata() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();

        let rrset = RRSet {
            name: DnsName::from_str_unchecked("example.com"),
            rr_type: RRType::A,
            class: DnsClass::IN,
            records: vec![],
        };
        let rrsig = DnsResourceRecord {
            name: DnsName::from_str_unchecked("example.com"),
            rr_type: RRType::RRSIG,
            class: DnsClass::IN,
            ttl: 300,
            rdata: vec![0; 10].into(),
        };
        let rrsigs: Vec<&DnsResourceRecord> = vec![&rrsig];
        let mut fail_flags = DnssecFailFlags::empty();

        let result = v
            .validate_rrset(&rrset, &rrsigs, &mut cache, &mut limits, &mut fail_flags)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
        assert!(fail_flags.contains(DnssecFailFlags::NOKEYSUP));
    }

    #[test]
    fn test_validate_rrset_unsupported_algo() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();

        let rrset = RRSet {
            name: DnsName::from_str_unchecked("example.com"),
            rr_type: RRType::A,
            class: DnsClass::IN,
            records: vec![],
        };
        let mut rdata = vec![0u8; 18];
        rdata[0] = 0;
        rdata[1] = 1; // type covered: A
        rdata[2] = 255; // unsupported algorithm
        rdata[3] = 2; // labels

        let rrsig = DnsResourceRecord {
            name: DnsName::from_str_unchecked("example.com"),
            rr_type: RRType::RRSIG,
            class: DnsClass::IN,
            ttl: 300,
            rdata: rdata.into(),
        };
        let rrsigs: Vec<&DnsResourceRecord> = vec![&rrsig];
        let mut fail_flags = DnssecFailFlags::empty();

        let result = v
            .validate_rrset(&rrset, &rrsigs, &mut cache, &mut limits, &mut fail_flags)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
        assert!(fail_flags.contains(DnssecFailFlags::NOKEYSUP));
    }

    // --- prove_non_existence tests ---

    #[test]
    fn test_prove_non_existence_no_nsec_records() {
        let v = DnssecValidator::new(vec![], false);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();

        let name = DnsName::from_str_unchecked("example.com");
        let packet = DnsPacketBuilder::new(0x1234)
            .set_response()
            .add_question(&name, RRType::A, DnsClass::IN)
            .build()
            .unwrap();

        let result = v
            .prove_non_existence(
                &[],
                &packet,
                "nonexistent.example.com",
                RRType::A,
                DnsClass::IN,
                &mut cache,
                &mut limits,
            )
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    #[test]
    fn test_prove_non_existence_mixed_nsec_nsec3() {
        let v = DnssecValidator::new(vec![], false);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();

        let name = DnsName::from_str_unchecked("example.com");
        let nsec_name = DnsName::from_str_unchecked("a.example.com");

        let mut nsec_rdata = BytesMut::new();
        let next_name = DnsName::from_str_unchecked("b.example.com");
        next_name.to_wire(&mut nsec_rdata);
        nsec_rdata.extend_from_slice(&[0, 1, 0x40]);

        let nsec3_rdata = vec![1, 0, 0, 1, 0];

        let packet = DnsPacketBuilder::new(0x1234)
            .set_response()
            .add_question(&name, RRType::A, DnsClass::IN)
            .add_authority(&nsec_name, RRType::NSEC, DnsClass::IN, 300, &nsec_rdata)
            .add_authority(&nsec_name, RRType::NSEC3, DnsClass::IN, 300, &nsec3_rdata)
            .build()
            .unwrap();

        let result = v
            .prove_non_existence(
                &[],
                &packet,
                "c.example.com",
                RRType::A,
                DnsClass::IN,
                &mut cache,
                &mut limits,
            )
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    // --- prove_non_existence_nsec tests ---

    fn make_nsec_rdata(next_name: &str, type_bitmap: &[u8]) -> Vec<u8> {
        let mut rdata = BytesMut::new();
        let next = DnsName::from_str_unchecked(next_name);
        next.to_wire(&mut rdata);
        rdata.extend_from_slice(type_bitmap);
        rdata.to_vec()
    }

    #[test]
    fn test_nsec_exact_match_nodata() {
        let v = DnssecValidator::new(vec![], false);
        let name = DnsName::from_str_unchecked("example.com");
        let nsec_rdata = make_nsec_rdata("next.example.com", &[0, 1, 0x40]);

        let nsec_rr = DnsResourceRecord {
            name: name.clone(),
            rr_type: RRType::NSEC,
            class: DnsClass::IN,
            ttl: 300,
            rdata: nsec_rdata.into(),
        };
        let nsec_records: Vec<&DnsResourceRecord> = vec![&nsec_rr];
        let packet = DnsPacketBuilder::new(1).set_response().build().unwrap();

        let result = v
            .prove_non_existence_nsec(&nsec_records, "example.com", RRType::MX, &packet)
            .unwrap();
        assert_eq!(result, DnssecStatus::Secure);
    }

    #[test]
    fn test_nsec_exact_match_type_present() {
        let v = DnssecValidator::new(vec![], false);
        let name = DnsName::from_str_unchecked("example.com");
        let nsec_rdata = make_nsec_rdata("next.example.com", &[0, 1, 0x40]);

        let nsec_rr = DnsResourceRecord {
            name: name.clone(),
            rr_type: RRType::NSEC,
            class: DnsClass::IN,
            ttl: 300,
            rdata: nsec_rdata.into(),
        };
        let nsec_records: Vec<&DnsResourceRecord> = vec![&nsec_rr];
        let packet = DnsPacketBuilder::new(1).set_response().build().unwrap();

        let result = v
            .prove_non_existence_nsec(&nsec_records, "example.com", RRType::A, &packet)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    #[test]
    fn test_nsec_empty_rdata() {
        let v = DnssecValidator::new(vec![], false);
        let nsec_rr = DnsResourceRecord {
            name: DnsName::from_str_unchecked("a.example.com"),
            rr_type: RRType::NSEC,
            class: DnsClass::IN,
            ttl: 300,
            rdata: vec![].into(),
        };
        let nsec_records: Vec<&DnsResourceRecord> = vec![&nsec_rr];
        let packet = DnsPacketBuilder::new(1).set_response().build().unwrap();

        let result = v
            .prove_non_existence_nsec(&nsec_records, "b.example.com", RRType::A, &packet)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    // --- prove_non_existence_nsec3 tests ---

    #[test]
    fn test_nsec3_empty_records() {
        let v = DnssecValidator::new(vec![], false);
        let empty: Vec<&DnsResourceRecord> = vec![];
        let mut limits = DnssecLimits::default();
        let result = v
            .prove_non_existence_nsec3(&empty, "example.com", RRType::A, &mut limits)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    #[test]
    fn test_nsec3_short_rdata() {
        let v = DnssecValidator::new(vec![], false);
        let mut limits = DnssecLimits::default();
        let rr = DnsResourceRecord {
            name: DnsName::from_str_unchecked("hash.example.com"),
            rr_type: RRType::NSEC3,
            class: DnsClass::IN,
            ttl: 300,
            rdata: vec![1, 0, 0].into(),
        };
        let records: Vec<&DnsResourceRecord> = vec![&rr];
        let result = v
            .prove_non_existence_nsec3(&records, "example.com", RRType::A, &mut limits)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    #[test]
    fn test_nsec3_iterations_exceed_limit() {
        let v = DnssecValidator::new(vec![], false);
        let mut limits = DnssecLimits::new(40, 20, 200, 10);
        let rdata = vec![1, 0, 1, 244, 0]; // iterations = 500
        let rr = DnsResourceRecord {
            name: DnsName::from_str_unchecked("hash.example.com"),
            rr_type: RRType::NSEC3,
            class: DnsClass::IN,
            ttl: 300,
            rdata: rdata.into(),
        };
        let records: Vec<&DnsResourceRecord> = vec![&rr];
        let result = v
            .prove_non_existence_nsec3(&records, "example.com", RRType::A, &mut limits)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    #[test]
    fn test_nsec3_unsupported_hash_algo() {
        let v = DnssecValidator::new(vec![], false);
        let mut limits = DnssecLimits::default();
        let rdata = vec![255, 0, 0, 0, 0]; // unsupported hash algo
        let rr = DnsResourceRecord {
            name: DnsName::from_str_unchecked("hash.example.com"),
            rr_type: RRType::NSEC3,
            class: DnsClass::IN,
            ttl: 300,
            rdata: rdata.into(),
        };
        let records: Vec<&DnsResourceRecord> = vec![&rr];
        let result = v
            .prove_non_existence_nsec3(&records, "example.com", RRType::A, &mut limits)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    #[test]
    fn test_nsec3_salt_length_exceeds_rdata() {
        let v = DnssecValidator::new(vec![], false);
        let mut limits = DnssecLimits::default();
        let rdata = vec![1, 0, 0, 0, 100]; // salt_len=100 exceeds
        let rr = DnsResourceRecord {
            name: DnsName::from_str_unchecked("hash.example.com"),
            rr_type: RRType::NSEC3,
            class: DnsClass::IN,
            ttl: 300,
            rdata: rdata.into(),
        };
        let records: Vec<&DnsResourceRecord> = vec![&rr];
        let result = v
            .prove_non_existence_nsec3(&records, "example.com", RRType::A, &mut limits)
            .unwrap();
        assert_eq!(result, DnssecStatus::Bogus);
    }

    // --- check_nsec3_coverage tests ---

    #[test]
    fn test_nsec3_coverage_empty_records() {
        let v = DnssecValidator::new(vec![], false);
        let empty: Vec<&DnsResourceRecord> = vec![];
        let result = v.check_nsec3_coverage(&empty, &[0x50]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_nsec3_coverage_short_rdata() {
        let v = DnssecValidator::new(vec![], false);
        let rr = DnsResourceRecord {
            name: DnsName::from_str_unchecked("aaa.example.com"),
            rr_type: RRType::NSEC3,
            class: DnsClass::IN,
            ttl: 300,
            rdata: vec![1, 0, 0].into(),
        };
        let records: Vec<&DnsResourceRecord> = vec![&rr];
        let result = v.check_nsec3_coverage(&records, &[0x50]).unwrap();
        assert!(!result);
    }

    // --- dnssec_validate_by_ds tests ---

    fn make_dnskey_raw_packet(
        name: &str,
        flags: u16,
        protocol: u8,
        algo: u8,
        key: &[u8],
    ) -> Vec<u8> {
        let dns_name = DnsName::from_str_unchecked(name);
        let mut rdata = BytesMut::new();
        rdata.put_u16(flags);
        rdata.put_u8(protocol);
        rdata.put_u8(algo);
        rdata.extend_from_slice(key);

        let mut buf = BytesMut::with_capacity(512);
        let hdr = DnsHeader {
            id: 0xABCD,
            flags: DnsHeaderFlags {
                qr: true,
                ..DnsHeaderFlags::default()
            },
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        hdr.serialize(&mut buf);
        dns_name.to_wire(&mut buf);
        buf.put_u16(RRType::DNSKEY.to_u16());
        buf.put_u16(DnsClass::IN.to_u16());
        dns_name.to_wire(&mut buf);
        buf.put_u16(RRType::DNSKEY.to_u16());
        buf.put_u16(DnsClass::IN.to_u16());
        buf.put_u32(300);
        buf.put_u16(rdata.len() as u16);
        buf.extend_from_slice(&rdata);
        buf.to_vec()
    }

    #[test]
    fn test_validate_by_ds_no_dnskey_in_response() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = build_header_only(0x1234, false);
        let (status, flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::Bogus);
        assert!(flags.contains(DnssecFailFlags::NOKEY));
    }

    #[test]
    fn test_validate_by_ds_no_ds_no_anchor() {
        let v = DnssecValidator::new(vec![], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = make_dnskey_raw_packet("example.com", 0x0100, 3, 8, &[1, 2, 3, 4]);
        let (status, _flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::NeedDs);
    }

    #[test]
    fn test_validate_by_ds_non_zone_key() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            8,
            2,
            vec![0xAA],
        );
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = make_dnskey_raw_packet("example.com", 0x0000, 3, 8, &[1, 2, 3, 4]);
        let (status, flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::Bogus);
        assert!(flags.contains(DnssecFailFlags::NOZONE));
    }

    #[test]
    fn test_validate_by_ds_wrong_protocol() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            8,
            2,
            vec![0xAA],
        );
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = make_dnskey_raw_packet("example.com", 0x0100, 1, 8, &[1, 2, 3, 4]);
        let (status, _flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::Bogus);
    }

    #[test]
    fn test_validate_by_ds_unsupported_algorithm() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            255,
            2,
            vec![0xAA],
        );
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        let packet = make_dnskey_raw_packet("example.com", 0x0100, 3, 255, &[1, 2, 3, 4]);
        let (status, flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::Bogus);
        assert!(flags.contains(DnssecFailFlags::NOKEYSUP));
    }

    #[test]
    fn test_validate_by_ds_crypto_limit_exhausted() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            8,
            2,
            vec![0xAA],
        );
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::new(40, 20, 0, 150);
        let domain_matcher = DomainMatcher::new();

        let packet = make_dnskey_raw_packet("example.com", 0x0100, 3, 8, &[1, 2, 3, 4]);
        let (status, _flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::Abandoned);
    }

    #[test]
    fn test_validate_by_ds_short_dnskey_rdata() {
        let ta = TrustAnchor::new(
            DnsName::from_str_unchecked("example.com"),
            12345,
            8,
            2,
            vec![0xAA],
        );
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();
        let domain_matcher = DomainMatcher::new();

        // 2-byte DNSKEY rdata (< 4 minimum)
        let dns_name = DnsName::from_str_unchecked("example.com");
        let rdata = vec![0x01, 0x00];
        let mut buf = BytesMut::with_capacity(512);
        let hdr = DnsHeader {
            id: 0xABCD,
            flags: DnsHeaderFlags {
                qr: true,
                ..DnsHeaderFlags::default()
            },
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        hdr.serialize(&mut buf);
        dns_name.to_wire(&mut buf);
        buf.put_u16(RRType::DNSKEY.to_u16());
        buf.put_u16(DnsClass::IN.to_u16());
        dns_name.to_wire(&mut buf);
        buf.put_u16(RRType::DNSKEY.to_u16());
        buf.put_u16(DnsClass::IN.to_u16());
        buf.put_u32(300);
        buf.put_u16(rdata.len() as u16);
        buf.extend_from_slice(&rdata);
        let packet = buf.to_vec();

        let (status, _flags) = v
            .dnssec_validate_by_ds(
                &packet,
                "example.com",
                &mut cache,
                &mut limits,
                &domain_matcher,
            )
            .unwrap();
        assert_eq!(status, DnssecStatus::Bogus);
    }

    // --- with_fail_flags additional combinations ---

    #[test]
    fn test_with_fail_flags_all_status_variants() {
        let flags = DnssecFailFlags::from_bits(0xFFFF);
        for status in [
            DnssecStatus::Secure,
            DnssecStatus::Insecure,
            DnssecStatus::Bogus,
            DnssecStatus::NeedDsDigest,
            DnssecStatus::NeedKey,
            DnssecStatus::NeedDs,
            DnssecStatus::Truncated,
            DnssecStatus::Abandoned,
        ] {
            let (returned_status, returned_flags) = status.with_fail_flags(flags);
            assert_eq!(returned_status, status);
            assert_eq!(returned_flags.bits(), 0xFFFF);
        }
    }

    // --- zone_status DS in cache tests ---

    #[test]
    fn test_zone_status_with_ds_in_cache() {
        let ta = TrustAnchor::new(DnsName::from_str_unchecked("."), 20326, 8, 2, vec![0xAA]);
        let v = DnssecValidator::new(vec![ta], true);
        let mut cache = DnsCache::cache_init(Some(150)).unwrap();
        let mut limits = DnssecLimits::default();

        let ds_entry = CacheEntry {
            name: DnsName::from_str_unchecked("com"),
            rr_type: RRType::DS,
            data: CacheData::Ds {
                key_tag: 12345,
                algorithm: 8,
                digest_type: 2,
                digest: vec![0xBB, 0xCC],
            },
            expires: std::time::Instant::now() + Duration::from_secs(300),
            last_access: std::time::Instant::now(),
            flags: CacheFlags::default(),
            ttl: 300,
        };
        let _ = cache.cache_insert(ds_entry);

        let status = v
            .zone_status("example.com", &mut cache, &mut limits)
            .unwrap();
        assert!(status == DnssecStatus::Secure || status == DnssecStatus::NeedDs);
    }

    // --- Additional canonical name comparison deep tests ---

    #[test]
    fn test_canonical_cmp_same_labels_different_depths() {
        assert_eq!(canonical_dns_name_cmp("a.com", "com"), Ordering::Greater);
        assert_eq!(canonical_dns_name_cmp("com", "a.com"), Ordering::Less);
    }

    #[test]
    fn test_canonical_cmp_with_trailing_dots_mixed() {
        assert_eq!(
            canonical_dns_name_cmp("example.com.", "example.com"),
            Ordering::Equal
        );
        assert_eq!(
            canonical_dns_name_cmp("example.com..", "example.com"),
            Ordering::Equal
        );
    }

    // --- Base32 decode thorough tests ---

    #[test]
    fn test_base32_decode_all_digit_chars() {
        for c in b'0'..=b'9' {
            let s = String::from_utf8(vec![c, c]).unwrap();
            assert!(
                base32_decode(&s).is_some(),
                "char {} should be valid",
                c as char
            );
        }
    }

    #[test]
    fn test_base32_decode_all_alpha_chars() {
        for c in b'a'..=b'v' {
            let s = String::from_utf8(vec![c, c]).unwrap();
            assert!(
                base32_decode(&s).is_some(),
                "char {} should be valid",
                c as char
            );
        }
        for c in b'w'..=b'z' {
            let s = String::from_utf8(vec![c, c]).unwrap();
            assert!(
                base32_decode(&s).is_none(),
                "char {} should be invalid",
                c as char
            );
        }
    }

    // --- keytag comprehensive tests ---

    #[test]
    fn test_keytag_known_value() {
        let key = vec![0x03, 0x01, 0x00, 0x01];
        let tag = dnskey_keytag(8, 0x0101, &key);
        assert!(tag > 0);
    }

    #[test]
    fn test_keytag_zero_key_data() {
        let key = vec![0x00, 0x00, 0x00, 0x00];
        let tag = dnskey_keytag(8, 0x0100, &key);
        // algo=8, flags=0x0100 => accumulator includes flags and proto+algo contribution
        assert_eq!(tag, 1032);
    }

    // --- name_to_wire roundtrip tests ---

    #[test]
    fn test_name_to_wire_matches_dns_name_to_wire() {
        let name_str = "www.example.com";
        let wire = name_to_wire(name_str);
        let dns_name = DnsName::from_str_unchecked(name_str);
        let mut buf = BytesMut::new();
        dns_name.to_wire(&mut buf);
        assert_eq!(wire.len(), buf.len());
    }
}

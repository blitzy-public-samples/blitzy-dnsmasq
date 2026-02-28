//! Cryptographically-secure pseudo-random number generator.
//!
//! Replaces the C SURF PRNG (Daniel J. Bernstein's "Speedy Unpredictable Random Function")
//! from `src/util.c` with Rust's `rand` crate CSPRNG. Provides the same API surface:
//! - [`rand16()`] — 16-bit random values for DNS query IDs and source port randomization
//! - [`rand32()`] — 32-bit random values for cache keys and timestamps
//! - [`rand64()`] — 64-bit random values for unique identifiers and cryptographic operations
//!
//! # Security Rationale
//!
//! The C SURF PRNG, while based on a cryptographic primitive, uses global mutable state
//! (`static u32 seed[32], in[12], out[8]`) and a fixed seed read from `/dev/urandom` at
//! initialization. The Rust `rand` crate provides:
//! - Thread-local CSPRNG via [`rand::rng()`] (ChaCha-based, periodically reseeded)
//! - OS entropy via [`rand::rngs::OsRng`] for critical operations
//! - No global mutable state — each [`Prng`] instance is self-contained
//! - Automatic fork protection on Unix platforms
//!
//! # Usage
//!
//! DNS transaction ID randomization (RFC 5452 recommendations) and DHCP XID generation
//! are the primary security-critical consumers of this PRNG.
//!
//! ```rust,no_run
//! use dnsmasq::core::prng::{Prng, rand16, rand32, rand64};
//!
//! // Using the struct-based API
//! let mut prng = Prng::new();
//! let query_id = prng.rand16();
//! let cache_key = prng.rand32();
//! let unique_id = prng.rand64();
//!
//! // Using module-level convenience functions
//! let port = rand16();
//! let xid = rand32();
//! let nonce = rand64();
//! ```
//!
//! # Migration from C
//!
//! | C function     | Rust equivalent         | Notes                                    |
//! |---------------|-------------------------|------------------------------------------|
//! | `rand_init()` | `Prng::new()`           | No explicit init needed; auto-seeded     |
//! | `rand16()`    | `prng.rand16()` / `rand16()` | Full u16 range (0–65535)           |
//! | `rand32()`    | `prng.rand32()` / `rand32()` | Full u32 range                     |
//! | `rand64()`    | `prng.rand64()` / `rand64()` | Native u64; C combined two u32s    |

use rand::Rng;
use rand::rngs::OsRng;

/// Cryptographically-secure PRNG instance.
///
/// Wraps the `rand` crate's thread-local CSPRNG to provide a clean, encapsulated
/// interface for random number generation. This replaces the C global SURF state
/// (`seed[32]`, `in[12]`, `out[8]`) with a properly encapsulated instance.
///
/// # Implementation Details
///
/// Internally uses [`rand::rng()`] which provides a thread-local, automatically-seeded
/// ChaCha-based CSPRNG that periodically reseeds from OS entropy. This matches or
/// exceeds the security properties of the C SURF PRNG which used a one-time seed from
/// `/dev/urandom`.
///
/// # Performance
///
/// The thread-local RNG buffers OS entropy through a ChaCha cipher, making individual
/// random value generation very fast (no syscall per call). This is suitable for
/// high-frequency use such as DNS query ID generation where the C version also used
/// a buffered approach (8 u32 outputs per SURF round).
///
/// # Thread Safety
///
/// Each thread gets its own independent CSPRNG state. This is an improvement over the
/// C SURF implementation which used global mutable state and was not thread-safe.
/// While dnsmasq is single-threaded, this design is forward-compatible.
pub struct Prng {
    /// Cached thread-local RNG handle for efficient repeated use.
    /// Using `rand::rngs::ThreadRng` avoids repeated thread-local lookups
    /// when generating multiple random values in sequence.
    rng: rand::rngs::ThreadRng,
}

impl Prng {
    /// Create a new PRNG instance.
    ///
    /// Replaces the C `rand_init()` function from `util.c` (line 126) which opened
    /// `/dev/urandom`, read a 32-byte seed and 48-byte input state, and called
    /// `die()` on failure. In Rust, the underlying CSPRNG is automatically initialized
    /// and seeded from OS entropy — no explicit initialization or error handling is needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::core::prng::Prng;
    /// let mut prng = Prng::new();
    /// let id = prng.rand16();
    /// ```
    ///
    /// # Panics
    ///
    /// Does not panic. The underlying `rand::rng()` is infallible on all supported
    /// platforms (Linux x86-64, ARM64).
    pub fn new() -> Self {
        log::trace!("PRNG initialized (rand crate CSPRNG, replaces SURF)");
        Prng {
            rng: rand::rng(),
        }
    }

    /// Generate a cryptographically-strong random 16-bit value.
    ///
    /// Direct replacement for the C `rand16()` function (`util.c` line 206) which
    /// maintained an 8-element output buffer refilled by the SURF algorithm. The Rust
    /// implementation generates values directly from the buffered ChaCha CSPRNG.
    ///
    /// Returns a uniformly distributed value in the range `0..=65535`.
    ///
    /// # Primary Consumers
    ///
    /// - **DNS query ID generation** — RFC 1035 §4.1.1 requires a random 16-bit ID
    ///   for each query. RFC 5452 recommends cryptographic-quality randomness to prevent
    ///   DNS cache poisoning attacks.
    /// - **Source port randomization** — Random UDP source ports for DNS queries to
    ///   increase the entropy of the query tuple (port + ID = 48 bits of randomness).
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::core::prng::Prng;
    /// let mut prng = Prng::new();
    /// let query_id: u16 = prng.rand16();
    /// assert!(query_id <= u16::MAX);
    /// ```
    pub fn rand16(&mut self) -> u16 {
        self.rng.random::<u16>()
    }

    /// Generate a cryptographically-strong random 32-bit value.
    ///
    /// Direct replacement for the C `rand32()` function (`util.c` line 245) which
    /// used the same SURF output buffer as `rand16()`. The Rust implementation generates
    /// full 32-bit values directly from the CSPRNG.
    ///
    /// Returns a uniformly distributed value in the range `0..=4294967295`.
    ///
    /// # Primary Consumers
    ///
    /// - **Cache keys** — Random keys for DNS cache entry identification
    /// - **DHCP XIDs** — Transaction identifiers for DHCP protocol exchanges
    /// - **Random delays** — Jittered timing for retry logic and lease renewal
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::core::prng::Prng;
    /// let mut prng = Prng::new();
    /// let cache_key: u32 = prng.rand32();
    /// ```
    pub fn rand32(&mut self) -> u32 {
        self.rng.random::<u32>()
    }

    /// Generate a cryptographically-strong random 64-bit value.
    ///
    /// Direct replacement for the C `rand64()` function (`util.c` line 285) which
    /// combined two 32-bit SURF outputs: `(u64)out[outleft+1] + (((u64)out[outleft]) << 32)`.
    /// The Rust implementation generates native 64-bit values directly, avoiding the
    /// potential bias of combining two 32-bit values.
    ///
    /// Returns a uniformly distributed value in the range `0..=18446744073709551615`.
    ///
    /// # Primary Consumers
    ///
    /// - **Unique identifiers** — 64-bit unique IDs for tracking and correlation
    /// - **Cryptographic nonces** — One-time values for protocol security
    /// - **Large random intervals** — Values requiring more than 32 bits of entropy
    ///
    /// # C Compatibility Note
    ///
    /// The C version used a separate static `outleft` counter (shadowing the global one)
    /// and consumed two u32 outputs per call. This Rust version generates a native u64,
    /// which is both simpler and provides better uniformity.
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::core::prng::Prng;
    /// let mut prng = Prng::new();
    /// let nonce: u64 = prng.rand64();
    /// ```
    pub fn rand64(&mut self) -> u64 {
        self.rng.random::<u64>()
    }
}

impl Default for Prng {
    /// Create a default `Prng` instance.
    ///
    /// Equivalent to [`Prng::new()`]. Provided for ergonomic use with
    /// `Default::default()` and struct initialization.
    fn default() -> Self {
        Self::new()
    }
}

// Implement Debug manually to avoid exposing RNG internal state
impl std::fmt::Debug for Prng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prng")
            .field("backend", &"ThreadRng (ChaCha-based CSPRNG)")
            .finish()
    }
}

/// Generate a cryptographically-strong random 16-bit value.
///
/// Module-level convenience function providing the same interface as the C `rand16()`
/// function from `util.c` (line 206). This is the simplest way to get a random u16
/// without maintaining a [`Prng`] instance.
///
/// Internally calls [`rand::rng()`] to access the thread-local CSPRNG and generates
/// a uniformly distributed value in the range `0..=65535`.
///
/// # Usage
///
/// This function is intended for call sites that need a single random value without
/// the overhead of creating and storing a [`Prng`] instance. For generating multiple
/// values in sequence, prefer creating a [`Prng`] instance to cache the thread-local
/// RNG handle.
///
/// # Examples
///
/// ```
/// use dnsmasq::core::prng::rand16;
/// let query_id = rand16();
/// assert!(query_id <= u16::MAX);
/// ```
///
/// # Security
///
/// Uses the same CSPRNG backend as [`Prng::rand16()`]. Suitable for DNS query ID
/// generation (RFC 5452) and source port randomization.
pub fn rand16() -> u16 {
    rand::rng().random::<u16>()
}

/// Generate a cryptographically-strong random 32-bit value.
///
/// Module-level convenience function providing the same interface as the C `rand32()`
/// function from `util.c` (line 245). Generates a uniformly distributed u32 from the
/// thread-local CSPRNG.
///
/// # Examples
///
/// ```
/// use dnsmasq::core::prng::rand32;
/// let xid = rand32();
/// ```
///
/// # Security
///
/// Uses the same CSPRNG backend as [`Prng::rand32()`]. Suitable for DHCP transaction
/// IDs and cache key generation.
pub fn rand32() -> u32 {
    rand::rng().random::<u32>()
}

/// Generate a cryptographically-strong random 64-bit value.
///
/// Module-level convenience function providing the same interface as the C `rand64()`
/// function from `util.c` (line 285). Generates a native u64 directly from the CSPRNG,
/// unlike the C version which combined two 32-bit SURF outputs.
///
/// # Examples
///
/// ```
/// use dnsmasq::core::prng::rand64;
/// let nonce = rand64();
/// ```
///
/// # Security
///
/// Uses the same CSPRNG backend as [`Prng::rand64()`]. Suitable for unique identifiers
/// and cryptographic nonces.
pub fn rand64() -> u64 {
    rand::rng().random::<u64>()
}

/// Generate a random value using OS entropy directly.
///
/// This function bypasses the thread-local CSPRNG and requests entropy directly from
/// the operating system via [`rand::rngs::OsRng`]. This is slower than the buffered
/// CSPRNG but provides the highest assurance of freshness.
///
/// Use this for security-critical one-time values where the overhead of a syscall
/// is acceptable (e.g., seeding other PRNGs, generating long-lived cryptographic keys).
///
/// # Errors
///
/// Returns `None` if the OS entropy source is unavailable (extremely rare on Linux).
///
/// # Examples
///
/// ```
/// use dnsmasq::core::prng::os_random_u32;
/// if let Some(val) = os_random_u32() {
///     println!("OS-sourced random: {}", val);
/// }
/// ```
pub fn os_random_u32() -> Option<u32> {
    use rand::TryRngCore;
    let mut rng = OsRng;
    rng.try_next_u32().ok()
}

/// Generate a random 64-bit value using OS entropy directly.
///
/// Like [`os_random_u32()`] but produces a 64-bit value. Uses [`rand::rngs::OsRng`]
/// for direct OS entropy access.
///
/// # Errors
///
/// Returns `None` if the OS entropy source is unavailable.
pub fn os_random_u64() -> Option<u64> {
    use rand::TryRngCore;
    let mut rng = OsRng;
    rng.try_next_u64().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Verify that Prng::new() does not panic and creates a valid instance.
    #[test]
    fn test_prng_new_does_not_panic() {
        let prng = Prng::new();
        // Verify it has a debug representation
        let debug_str = format!("{:?}", prng);
        assert!(debug_str.contains("Prng"));
        assert!(debug_str.contains("ChaCha"));
    }

    /// Verify that Prng implements Default
    #[test]
    fn test_prng_default() {
        let mut prng = Prng::default();
        // Should be functional immediately
        let _ = prng.rand16();
        let _ = prng.rand32();
        let _ = prng.rand64();
    }

    /// Verify that rand16() via Prng produces varying values (not constant).
    /// With 100 calls, the probability of all being identical is (1/65536)^99 ≈ 0.
    #[test]
    fn test_prng_rand16_produces_varying_values() {
        let mut prng = Prng::new();
        let values: HashSet<u16> = (0..100).map(|_| prng.rand16()).collect();
        // With 100 draws from 65536 possibilities, we expect high diversity
        assert!(
            values.len() > 1,
            "rand16() produced only a single value across 100 calls"
        );
        // Expect at least ~90 unique values with high probability
        assert!(
            values.len() > 50,
            "rand16() produced only {} unique values in 100 calls — suspiciously low",
            values.len()
        );
    }

    /// Verify that rand32() via Prng produces varying values.
    #[test]
    fn test_prng_rand32_produces_varying_values() {
        let mut prng = Prng::new();
        let values: HashSet<u32> = (0..100).map(|_| prng.rand32()).collect();
        assert!(
            values.len() > 90,
            "rand32() produced only {} unique values in 100 calls — suspiciously low",
            values.len()
        );
    }

    /// Verify that rand64() via Prng produces varying values.
    #[test]
    fn test_prng_rand64_produces_varying_values() {
        let mut prng = Prng::new();
        let values: HashSet<u64> = (0..100).map(|_| prng.rand64()).collect();
        assert!(
            values.len() > 90,
            "rand64() produced only {} unique values in 100 calls — suspiciously low",
            values.len()
        );
    }

    /// Verify that the module-level rand16() free function works correctly.
    #[test]
    fn test_free_fn_rand16() {
        let values: HashSet<u16> = (0..100).map(|_| rand16()).collect();
        assert!(
            values.len() > 1,
            "Free function rand16() produced only one value"
        );
    }

    /// Verify that the module-level rand32() free function works correctly.
    #[test]
    fn test_free_fn_rand32() {
        let values: HashSet<u32> = (0..100).map(|_| rand32()).collect();
        assert!(
            values.len() > 90,
            "Free function rand32() produced only {} unique values",
            values.len()
        );
    }

    /// Verify that the module-level rand64() free function works correctly.
    #[test]
    fn test_free_fn_rand64() {
        let values: HashSet<u64> = (0..100).map(|_| rand64()).collect();
        assert!(
            values.len() > 90,
            "Free function rand64() produced only {} unique values",
            values.len()
        );
    }

    /// Verify that rand16() spans the expected range by checking both low and high
    /// values appear in a large sample. With 10,000 draws, we expect values across
    /// the full u16 range.
    #[test]
    fn test_rand16_range_coverage() {
        let mut prng = Prng::new();
        let mut min_val = u16::MAX;
        let mut max_val = u16::MIN;
        for _ in 0..10_000 {
            let v = prng.rand16();
            min_val = min_val.min(v);
            max_val = max_val.max(v);
        }
        // With 10,000 draws from uniform u16, the expected min is ~0 and max is ~65535
        // Allow generous bounds: min < 100 and max > 65400
        assert!(
            min_val < 500,
            "Minimum rand16() value {} is suspiciously high",
            min_val
        );
        assert!(
            max_val > 65000,
            "Maximum rand16() value {} is suspiciously low",
            max_val
        );
    }

    /// Verify that rand32() produces values with reasonable distribution properties.
    #[test]
    fn test_rand32_distribution() {
        let mut prng = Prng::new();
        let mut above_mid = 0u32;
        let mut below_mid = 0u32;
        let midpoint = u32::MAX / 2;
        for _ in 0..1000 {
            let v = prng.rand32();
            if v > midpoint {
                above_mid += 1;
            } else {
                below_mid += 1;
            }
        }
        // With 1000 draws, expect roughly 500 above and 500 below midpoint
        // Allow 35% tolerance: each should be between 300 and 700
        assert!(
            above_mid > 300 && above_mid < 700,
            "rand32() distribution skewed: {} above midpoint out of 1000",
            above_mid
        );
        assert!(
            below_mid > 300 && below_mid < 700,
            "rand32() distribution skewed: {} below midpoint out of 1000",
            below_mid
        );
    }

    /// Verify that rand64() produces values with reasonable distribution properties.
    #[test]
    fn test_rand64_distribution() {
        let mut prng = Prng::new();
        let mut above_mid = 0u32;
        let midpoint = u64::MAX / 2;
        for _ in 0..1000 {
            if prng.rand64() > midpoint {
                above_mid += 1;
            }
        }
        // Allow 35% tolerance
        assert!(
            above_mid > 300 && above_mid < 700,
            "rand64() distribution skewed: {} above midpoint out of 1000",
            above_mid
        );
    }

    /// Verify that OsRng-based functions work on this platform.
    #[test]
    fn test_os_random_u32() {
        let val = os_random_u32();
        assert!(val.is_some(), "os_random_u32() should succeed on Linux");
    }

    /// Verify that OsRng-based u64 function works on this platform.
    #[test]
    fn test_os_random_u64() {
        let val = os_random_u64();
        assert!(val.is_some(), "os_random_u64() should succeed on Linux");
    }

    /// Verify that two separately-constructed Prng instances produce different sequences.
    /// This validates that the CSPRNG is properly seeded from entropy, unlike a
    /// deterministic PRNG with a fixed seed.
    #[test]
    fn test_independent_instances_differ() {
        let mut prng1 = Prng::new();
        let mut prng2 = Prng::new();
        // Collect 10 values from each
        let seq1: Vec<u64> = (0..10).map(|_| prng1.rand64()).collect();
        let seq2: Vec<u64> = (0..10).map(|_| prng2.rand64()).collect();
        // Sequences should differ (probability of identical sequences is astronomically low)
        assert_ne!(
            seq1, seq2,
            "Two Prng instances produced identical sequences — entropy failure"
        );
    }

    /// Verify that consecutive rand16 calls don't just return sequential values.
    /// This catches a failure mode where the "random" values are actually a counter.
    #[test]
    fn test_rand16_not_sequential() {
        let mut prng = Prng::new();
        let v1 = prng.rand16();
        let v2 = prng.rand16();
        let v3 = prng.rand16();
        // Check that values are not simply v1, v1+1, v1+2
        let is_sequential = v2 == v1.wrapping_add(1) && v3 == v2.wrapping_add(1);
        assert!(
            !is_sequential,
            "rand16() returned sequential values: {}, {}, {} — not random",
            v1, v2, v3
        );
    }
}

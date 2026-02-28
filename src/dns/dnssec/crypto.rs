//! # DNSSEC Cryptographic Verification Module
//!
//! Complete Rust rewrite of `src/crypto.c` (1295 lines of C) replacing the Nettle
//! cryptography library wrapper with `ring` crate-based signature verification for
//! DNSSEC. This module provides all cryptographic operations needed for DNSSEC
//! validation: signature verification, hash algorithm dispatch, and digest computation.
//!
//! ## Supported Algorithms
//!
//! | Algo | Name                | Signature | Digest  | Status    |
//! |------|---------------------|-----------|---------|-----------|
//! | 5    | RSA/SHA-1           | RSA       | SHA-1   | Supported |
//! | 7    | RSASHA1-NSEC3       | RSA       | SHA-1   | Supported |
//! | 8    | RSA/SHA-256         | RSA       | SHA-256 | Supported |
//! | 10   | RSA/SHA-512         | RSA       | SHA-512 | Supported |
//! | 13   | ECDSAP256SHA256     | ECDSA P-256 | SHA-256 | Supported |
//! | 14   | ECDSAP384SHA384     | ECDSA P-384 | SHA-384 | Supported |
//! | 15   | Ed25519             | EdDSA     | —       | Supported |
//! | 16   | Ed448               | EdDSA     | —       | Not supported (ring limitation) |
//! | 12   | ECC-GOST            | GOST      | GOST    | Not supported (ring limitation) |
//!
//! ## Unsupported Algorithm Notes
//!
//! - **GOST (algo 12):** The C implementation supports GOST via Nettle 3.6+
//!   (`gosthash94cp`, `gostdsa`). The `ring` crate does not support GOST
//!   algorithms. Returns `None`/`UnsupportedAlgorithm` for algo 12.
//!
//! - **Ed448 (algo 16):** The `ring` crate does not natively support Ed448.
//!   The C code supports Ed448 only with Nettle >= 3.6. Returns
//!   `UnsupportedAlgorithm` for algo 16. Ed448 is extremely rare in
//!   deployed DNSSEC zones.
//!
//! ## Key Transformations from C
//!
//! | C Pattern | Rust Replacement |
//! |-----------|-----------------|
//! | Nettle `rsa_sha256_verify_digest()` | `ring::signature::RsaPublicKeyComponents::verify()` |
//! | Nettle `ecdsa_verify()` | `ring::signature::UnparsedPublicKey::verify()` |
//! | Nettle `ed25519_sha512_verify()` | `ring::signature::UnparsedPublicKey::verify()` |
//! | `struct nettle_hash` | `HashFunction` struct |
//! | Static `null_hash` buffer | `NullHash` variant in `HashContextInner` |
//! | `whine_malloc` / `free` | Rust `Vec<u8>` automatic memory management |
//! | GMP `mpz_import` for keys | Direct `&[u8]` slicing for ring |
//!
//! ## RFC Compliance
//!
//! - RFC 3110: RSA/SHA-1 DNSKEY key wire format (exponent-length prefix)
//! - RFC 5702: RSA/SHA-256 and RSA/SHA-512 for DNSSEC
//! - RFC 6605: ECDSA P-256/P-384 for DNSSEC
//! - RFC 6944: DNSKEY algorithm deprecation (RSA/MD5 MUST NOT)
//! - RFC 8032: Ed25519 and Ed448 signature schemes
//! - RFC 8080: Ed25519 and Ed448 for DNSSEC
//! - RFC 8624: DNSSEC algorithm implementation recommendations
//!
//! ## Zero `unsafe` Blocks
//!
//! This module contains zero `unsafe` code. All cryptographic operations
//! are performed through the safe `ring` crate API.

use ring::digest::{self, Context as DigestContext, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during DNSSEC cryptographic operations.
///
/// Maps to the various failure modes from the C `crypto.c` implementation,
/// providing structured error information instead of the C-style return code
/// pattern (0 = failure, 1 = success).
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The DNSSEC algorithm number is not supported by this implementation.
    /// This includes deprecated algorithms (RSA/MD5, DSA/SHA-1),
    /// algorithms not available in ring (GOST, Ed448), and unknown numbers.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),

    /// Signature verification failed cryptographically. The signature does
    /// not match the provided key and message data.
    #[error("verification failed")]
    VerificationFailed,

    /// The public key data is malformed or cannot be parsed in the expected
    /// format (e.g., RFC 3110 RSA key format, ECDSA point format).
    #[error("invalid key format")]
    InvalidKeyFormat,

    /// Hash context initialization failed. This should not occur with ring
    /// but is preserved for API compatibility with the C implementation.
    #[error("hash initialization failed")]
    HashInitFailed,

    /// The DS record digest type or NSEC3 hash algorithm is not supported.
    /// Includes GOST R 34.11-94 (digest type 3) which is not available in ring.
    #[error("unsupported digest type: {0}")]
    UnsupportedDigest(u8),
}

// ---------------------------------------------------------------------------
// Hash Context Inner (private implementation detail)
// ---------------------------------------------------------------------------

/// Internal enum to handle both ring digest contexts and the EdDSA null-hash
/// message accumulator. Replaces the C dual-mode hash approach where normal
/// hash algorithms use Nettle's hash API and EdDSA uses a special `null_hash`
/// structure that simply buffers the entire message.
enum HashContextInner {
    /// Standard cryptographic hash using ring::digest::Context.
    /// Used for SHA-1, SHA-256, SHA-384, SHA-512.
    Digest(DigestContext),

    /// EdDSA "null hash" — accumulates the entire message in a Vec<u8>.
    /// EdDSA algorithms (Ed25519, Ed448) operate on the complete message
    /// rather than a pre-computed hash digest. This replaces the C
    /// `null_hash_init`/`null_hash_update`/`null_hash_digest` functions
    /// and the static `null_hash_buff` buffer (C lines 98-269 of crypto.c).
    NullHash(Vec<u8>),
}

// ---------------------------------------------------------------------------
// HashFunction — Replaces Nettle's `struct nettle_hash`
// ---------------------------------------------------------------------------

/// Represents a hash algorithm with its properties, replacing Nettle's
/// `struct nettle_hash` from the C implementation. Provides algorithm
/// metadata (name, digest size, context size) and operations for creating
/// and manipulating hash contexts.
///
/// The `null_hash` variant is used for EdDSA algorithms which operate on
/// the complete message rather than a digest. Its `digest_size` is 0 since
/// the output size equals the input message length.
pub struct HashFunction {
    /// Algorithm name as a static string (e.g., "sha1", "sha256", "null_hash").
    /// Used for lookup via `hash_find()` and diagnostic messages.
    pub name: &'static str,

    /// Output digest size in bytes. For standard hash algorithms, this is fixed
    /// (e.g., 20 for SHA-1, 32 for SHA-256). For `null_hash`, this is 0 since
    /// the output size is dynamic (equals the accumulated message length).
    pub digest_size: usize,

    /// Logical context size in bytes. For ring digest contexts, this is the
    /// size of the `ring::digest::Context` structure. For `null_hash`, this
    /// is the initial buffer capacity (0, grows dynamically).
    pub context_size: usize,

    /// The ring digest algorithm, if this is a standard hash function.
    /// `None` for the `null_hash` EdDSA message accumulator.
    algorithm: Option<&'static digest::Algorithm>,
}

impl HashFunction {
    /// Create a new HashFunction wrapping a ring digest algorithm.
    fn new(name: &'static str, algorithm: &'static digest::Algorithm) -> Self {
        HashFunction {
            name,
            digest_size: algorithm.output_len(),
            context_size: std::mem::size_of::<DigestContext>(),
            algorithm: Some(algorithm),
        }
    }

    /// Create the special `null_hash` function for EdDSA message accumulation.
    /// Replaces the static `null_hash` structure defined at C lines 261-269.
    fn null_hash() -> Self {
        HashFunction {
            name: "null_hash",
            digest_size: 0,
            context_size: 0,
            algorithm: None,
        }
    }

    /// Returns the digest output size in bytes.
    /// For `null_hash`, returns 0 (actual output size equals message length).
    pub fn digest_size(&self) -> usize {
        self.digest_size
    }

    /// Update a hash context with additional data.
    /// Delegates to the context's `update()` method.
    ///
    /// Equivalent to `hash->update(ctx, length, src)` in the C implementation.
    pub fn update(&self, ctx: &mut HashContext, data: &[u8]) {
        ctx.update(data);
    }

    /// Finalize the hash context and return the digest bytes.
    /// For standard hash algorithms, returns the fixed-size digest.
    /// For `null_hash`, returns the accumulated message data.
    ///
    /// Equivalent to `hash->digest(ctx, hash->digest_size, digest)` in C.
    pub fn digest(&self, ctx: &mut HashContext) -> Vec<u8> {
        ctx.finish().to_vec()
    }
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashFunction({})", self.name)
    }
}

impl fmt::Debug for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashFunction")
            .field("name", &self.name)
            .field("digest_size", &self.digest_size)
            .field("context_size", &self.context_size)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HashContext — Wrapper around ring::digest::Context and NullHash
// ---------------------------------------------------------------------------

/// A hash computation context that wraps either a ring digest context or the
/// EdDSA null-hash message accumulator. Replaces the C pattern of using
/// `void *ctx` with hash function pointer tables.
///
/// # Usage
///
/// ```ignore
/// let mut ctx = HashContext::new(&ring::digest::SHA256);
/// ctx.update(b"hello ");
/// ctx.update(b"world");
/// let digest = ctx.finish();
/// assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes
/// ```
pub struct HashContext {
    /// The inner context variant (digest or null-hash).
    inner: HashContextInner,

    /// Reference to the ring algorithm for reset operations.
    /// `None` for null-hash contexts.
    algorithm: Option<&'static digest::Algorithm>,

    /// Buffer to store the most recent digest result, allowing
    /// `finish()` to return a reference without consuming self.
    digest_buf: Vec<u8>,
}

impl HashContext {
    /// Create a new hash context for the given ring digest algorithm.
    ///
    /// For standard hash algorithms (SHA-1, SHA-256, SHA-384, SHA-512),
    /// initializes a ring `DigestContext`. This replaces the C
    /// `hash_init()` function (C lines 320-355).
    pub fn new(algorithm: &'static digest::Algorithm) -> Self {
        HashContext {
            inner: HashContextInner::Digest(DigestContext::new(algorithm)),
            algorithm: Some(algorithm),
            digest_buf: Vec::with_capacity(algorithm.output_len()),
        }
    }

    /// Create a new null-hash context for EdDSA message accumulation.
    ///
    /// Replaces the C `null_hash_init()` function (C lines 137-140).
    /// The context simply buffers all input data for EdDSA verification
    /// which operates on the complete message.
    fn new_null_hash() -> Self {
        HashContext {
            inner: HashContextInner::NullHash(Vec::new()),
            algorithm: None,
            digest_buf: Vec::new(),
        }
    }

    /// Append data to the hash computation.
    ///
    /// For standard hash algorithms, feeds data into the ring digest context.
    /// For null-hash, appends data to the message buffer.
    ///
    /// Replaces `hash->update(ctx, length, src)` in C and
    /// `null_hash_update()` (C lines 171-196).
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.inner {
            HashContextInner::Digest(ctx) => {
                ctx.update(data);
            }
            HashContextInner::NullHash(buff) => {
                buff.extend_from_slice(data);
            }
        }
    }

    /// Finalize the hash and return the digest bytes.
    ///
    /// For standard hash algorithms, computes and returns the fixed-size digest.
    /// For null-hash, returns the accumulated message data.
    ///
    /// The context is cloned before finalization so it can continue to be used
    /// (though typically `reset()` should be called after `finish()`).
    ///
    /// Replaces `hash->digest(ctx, hash->digest_size, digest)` in C and
    /// `null_hash_digest()` (C lines 230-236).
    pub fn finish(&mut self) -> &[u8] {
        let result_bytes = match &self.inner {
            HashContextInner::Digest(ctx) => {
                let digest = ctx.clone().finish();
                digest.as_ref().to_vec()
            }
            HashContextInner::NullHash(buff) => buff.clone(),
        };
        self.digest_buf = result_bytes;
        &self.digest_buf
    }

    /// Reset the hash context for reuse with a new computation.
    ///
    /// For standard hash algorithms, creates a fresh ring digest context.
    /// For null-hash, clears the accumulated message buffer.
    pub fn reset(&mut self) {
        match self.algorithm {
            Some(alg) => {
                self.inner = HashContextInner::Digest(DigestContext::new(alg));
            }
            None => {
                if let HashContextInner::NullHash(ref mut buff) = self.inner {
                    buff.clear();
                }
            }
        }
        self.digest_buf.clear();
    }
}

impl fmt::Debug for HashContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match &self.inner {
            HashContextInner::Digest(_) => "Digest",
            HashContextInner::NullHash(_) => "NullHash",
        };
        f.debug_struct("HashContext")
            .field("variant", &variant)
            .field("digest_buf_len", &self.digest_buf.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Algorithm Mapping Functions
// ---------------------------------------------------------------------------

/// Map DNSKEY algorithm numbers to digest algorithm names per IANA registry.
///
/// Translates DNSSEC algorithm identifiers from DNSKEY/RRSIG records into the
/// hash digest algorithm name strings used by `hash_find()` for algorithm
/// lookup. Returns `None` for deprecated, unsupported, or unknown algorithms.
///
/// Replaces the C `algo_digest_name()` function (C lines 1122-1147).
///
/// # Algorithm Mapping
///
/// | Algo | Name                  | Result              | Notes                              |
/// |------|-----------------------|---------------------|------------------------------------|
/// | 1    | RSA/MD5               | `None`              | MUST NOT implement (RFC 6944)      |
/// | 2    | Diffie-Hellman        | `None`              | Not a signing algorithm            |
/// | 3    | DSA/SHA-1             | `None`              | MUST NOT implement (RFC 8624)      |
/// | 5    | RSA/SHA-1             | `Some("sha1")`      | Legacy, deprecated                 |
/// | 6    | DSA-NSEC3-SHA1        | `None`              | MUST NOT implement (RFC 8624)      |
/// | 7    | RSASHA1-NSEC3-SHA1    | `Some("sha1")`      | Legacy, deprecated                 |
/// | 8    | RSA/SHA-256           | `Some("sha256")`    | Recommended                        |
/// | 10   | RSA/SHA-512           | `Some("sha512")`    | Recommended                        |
/// | 12   | ECC-GOST              | `None`              | Not supported (no ring support)    |
/// | 13   | ECDSAP256SHA256       | `Some("sha256")`    | Recommended                        |
/// | 14   | ECDSAP384SHA384       | `Some("sha384")`    | Recommended                        |
/// | 15   | Ed25519               | `Some("null_hash")` | EdDSA — operates on full message   |
/// | 16   | Ed448                 | `Some("null_hash")` | EdDSA — not verified (ring lacks)  |
///
/// # GOST Limitation
///
/// Algorithm 12 (ECC-GOST) is supported in the C implementation via Nettle 3.6+
/// using `gosthash94cp` and `gostdsa`. The `ring` crate does not support GOST
/// algorithms, so this function returns `None` for algorithm 12.
///
/// # References
///
/// - IANA: <http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
/// - RFC 8624: Algorithm Implementation Requirements and Usage Guidance for DNSSEC
pub fn algo_digest_name(algo: u8) -> Option<&'static str> {
    match algo {
        1 => None,              // RSA/MD5 — MUST NOT implement (RFC 6944 para 2.3)
        2 => None,              // Diffie-Hellman — not a signing algorithm
        3 => None,              // DSA/SHA1 — MUST NOT implement (RFC 8624 section 3.1)
        5 => Some("sha1"),      // RSA/SHA-1
        6 => None,              // DSA-NSEC3-SHA1 — MUST NOT implement (RFC 8624 section 3.1)
        7 => Some("sha1"),      // RSASHA1-NSEC3-SHA1
        8 => Some("sha256"),    // RSA/SHA-256
        10 => Some("sha512"),   // RSA/SHA-512
        // Algorithm 12 (ECC-GOST): Not supported by ring crate.
        // The C implementation supports this via Nettle 3.6+ (gosthash94cp, gostdsa).
        // GOST is primarily used in regional (Russian/CIS) DNSSEC deployments.
        12 => None,
        13 => Some("sha256"),   // ECDSAP256SHA256
        14 => Some("sha384"),   // ECDSAP384SHA384
        15 => Some("null_hash"), // Ed25519 — EdDSA operates on full message
        // Algorithm 16 (Ed448): ring does not support Ed448 natively.
        // We still return "null_hash" for the digest name to indicate
        // the EdDSA message accumulation pattern, but actual verification
        // will fail with UnsupportedAlgorithm in verify_func().
        16 => Some("null_hash"), // Ed448 — EdDSA operates on full message
        _ => None,
    }
}

/// Map DS record digest type numbers to hash algorithm names.
///
/// Translates DNSSEC DS record digest algorithm identifiers into hash function
/// name strings used by `hash_find()`. DS records contain a hash of the child
/// zone's DNSKEY, and this function selects the appropriate hash algorithm.
///
/// Replaces the C `ds_digest_name()` function (C lines 1052-1064).
///
/// # Digest Type Mapping
///
/// | Type | Algorithm           | Result            | Notes                          |
/// |------|---------------------|-------------------|--------------------------------|
/// | 1    | SHA-1               | `Some("sha1")`    | Deprecated but still in use    |
/// | 2    | SHA-256             | `Some("sha256")`  | MUST implement (RFC 8624)      |
/// | 3    | GOST R 34.11-94     | `None`            | Not supported (no ring support)|
/// | 4    | SHA-384             | `Some("sha384")`  | RECOMMENDED (RFC 8624)         |
///
/// # References
///
/// - IANA: <http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>
/// - RFC 4034 Section 5.1.3: DS Record Wire Format
/// - RFC 8624 Section 3.3: DS Digest Algorithm Recommendations
pub fn ds_digest_name(digest: u8) -> Option<&'static str> {
    match digest {
        1 => Some("sha1"),    // SHA-1 (deprecated but maintained for compatibility)
        2 => Some("sha256"),  // SHA-256 (MUST implement per RFC 8624)
        // Digest type 3 (GOST R 34.11-94): Not supported by ring.
        // The C implementation supports this via Nettle 3.6+ (gosthash94cp).
        3 => None,
        4 => Some("sha384"),  // SHA-384 (RECOMMENDED per RFC 8624)
        _ => None,
    }
}

/// Map NSEC3 hash algorithm numbers to digest names.
///
/// Translates NSEC3 hash algorithm identifiers into hash function name strings.
/// NSEC3 provides authenticated denial of existence by hashing owner names.
/// Currently only SHA-1 (algorithm 1) is defined in the IANA registry.
///
/// Replaces the C `nsec3_digest_name()` function (C lines 1198-1205).
///
/// # Algorithm Mapping
///
/// | Algo | Algorithm | Result          | Notes                            |
/// |------|-----------|-----------------|----------------------------------|
/// | 1    | SHA-1     | `Some("sha1")`  | Only defined NSEC3 hash          |
///
/// # References
///
/// - IANA: <http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml>
/// - RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
pub fn nsec3_digest_name(digest: u8) -> Option<&'static str> {
    match digest {
        1 => Some("sha1"), // SHA-1 — the only defined NSEC3 hash algorithm
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Hash Function Lookup and Initialization
// ---------------------------------------------------------------------------

/// Find a hash function by its algorithm name string.
///
/// Returns a `HashFunction` descriptor for the named algorithm, or `None` if
/// the name is unrecognized. This is the primary mechanism for obtaining hash
/// algorithm implementations for DNSSEC operations.
///
/// Replaces the C `hash_find()` function (C lines 1266-1293) which searched
/// through Nettle's `nettle_hashes[]` array or used `nettle_lookup_hash()`.
///
/// # Supported Names
///
/// | Name          | Algorithm      | Digest Size |
/// |---------------|----------------|-------------|
/// | `"sha1"`      | SHA-1          | 20 bytes    |
/// | `"sha256"`    | SHA-256        | 32 bytes    |
/// | `"sha384"`    | SHA-384        | 48 bytes    |
/// | `"sha512"`    | SHA-512        | 64 bytes    |
/// | `"null_hash"` | Message buffer | 0 (dynamic) |
pub fn hash_find(name: &str) -> Option<HashFunction> {
    match name {
        "sha1" => Some(HashFunction::new("sha1", &SHA1_FOR_LEGACY_USE_ONLY)),
        "sha256" => Some(HashFunction::new("sha256", &SHA256)),
        "sha384" => Some(HashFunction::new("sha384", &SHA384)),
        "sha512" => Some(HashFunction::new("sha512", &SHA512)),
        "null_hash" => Some(HashFunction::null_hash()),
        _ => None,
    }
}

/// Initialize a hash context and allocate a digest buffer for the given
/// hash function.
///
/// Returns `Some((context, digest_buffer))` on success, or `None` if
/// initialization fails. The returned context is ready for `update()` calls,
/// and the digest buffer is pre-allocated with the appropriate capacity.
///
/// Replaces the C `hash_init()` function (C lines 320-355) which managed
/// statically-allocated context and digest buffers with grow-only semantics.
/// In Rust, we use stack/heap allocation via `Vec` instead of static buffers.
///
/// # Examples
///
/// ```ignore
/// let hash = hash_find("sha256").unwrap();
/// let (mut ctx, digest_buf) = hash_init(&hash).unwrap();
/// ctx.update(b"data to hash");
/// let result = ctx.finish();
/// ```
pub fn hash_init(hash: &HashFunction) -> Option<(HashContext, Vec<u8>)> {
    match hash.algorithm {
        Some(alg) => {
            let ctx = HashContext::new(alg);
            let digest_buf = vec![0u8; alg.output_len()];
            Some((ctx, digest_buf))
        }
        None => {
            // null_hash for EdDSA message accumulation
            let ctx = HashContext::new_null_hash();
            let digest_buf = Vec::new();
            Some((ctx, digest_buf))
        }
    }
}

// ---------------------------------------------------------------------------
// Signature Verification — Type Definitions
// ---------------------------------------------------------------------------

/// Function signature for algorithm-specific verification implementations.
type VerifyFn = fn(u8, &[u8], &[u8], &[u8]) -> Result<bool, CryptoError>;

// ---------------------------------------------------------------------------
// Signature Verification — Main Entry Point
// ---------------------------------------------------------------------------

/// Verify a DNSSEC signature using the appropriate algorithm-specific
/// verification function.
///
/// This is the primary external entry point for DNSSEC signature verification,
/// dispatching to RSA, ECDSA, or EdDSA verification based on the algorithm
/// number. It acts as a convenience wrapper around the internal `verify_func()`
/// dispatcher.
///
/// Replaces the C `verify()` function (C lines 970-983).
///
/// # Parameters
///
/// - `algo` — DNSSEC algorithm number from the RRSIG record (5-16 supported)
/// - `key` — Public key bytes in DNSKEY wire format:
///   - RSA: RFC 3110 format (exponent-length prefix + exponent + modulus)
///   - ECDSA: Raw (x || y) coordinates (64 bytes for P-256, 96 for P-384)
///   - Ed25519: 32-byte public key
/// - `sig` — Signature bytes from the RRSIG record
/// - `data` — The message data to verify. For ring-based verification, this
///   is the full message (RRSIG header + canonical RRset data), not a
///   pre-computed hash. Ring handles hashing internally.
///
/// # Returns
///
/// - `Ok(true)` — Signature is cryptographically valid
/// - `Ok(false)` — Should not normally occur; verification either succeeds or
///   returns an error
/// - `Err(CryptoError::UnsupportedAlgorithm)` — Algorithm not supported
/// - `Err(CryptoError::VerificationFailed)` — Signature verification failed
/// - `Err(CryptoError::InvalidKeyFormat)` — Key data is malformed
///
/// # Algorithm Dispatch
///
/// | Algorithm | Verification Function |
/// |-----------|----------------------|
/// | 5, 7, 8, 10 | `rsa_verify()` |
/// | 13, 14 | `ecdsa_verify()` |
/// | 15 | `eddsa_verify()` |
/// | 16 | Returns `UnsupportedAlgorithm` (no ring Ed448 support) |
/// | Others | Returns `UnsupportedAlgorithm` |
pub fn verify(algo: u8, key: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, CryptoError> {
    match verify_func(algo) {
        Some(func) => func(algo, key, sig, data),
        None => Err(CryptoError::UnsupportedAlgorithm(algo)),
    }
}

// ---------------------------------------------------------------------------
// Signature Verification — Algorithm Dispatcher
// ---------------------------------------------------------------------------

/// Return the appropriate verification function for a DNSSEC algorithm number.
///
/// Checks that the required digest algorithm is available (via `hash_find()`
/// and `algo_digest_name()`) before returning the function pointer. This
/// prevents attempting cryptographic operations with unavailable algorithms.
///
/// Replaces the C `verify_func()` function (C lines 867-901).
///
/// # Returns
///
/// `Some(fn)` if the algorithm is supported and the required digest is available,
/// `None` otherwise.
fn verify_func(algo: u8) -> Option<VerifyFn> {
    // First check that we have a supported digest algorithm for this algo number
    let digest_name = algo_digest_name(algo)?;
    let _hash = hash_find(digest_name)?;

    match algo {
        // RSA variants: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512
        5 | 7 | 8 | 10 => Some(rsa_verify),

        // ECDSA variants: ECDSAP256SHA256, ECDSAP384SHA384
        13 | 14 => Some(ecdsa_verify),

        // Ed25519 — supported via ring::signature::ED25519
        15 => Some(eddsa_verify),

        // Ed448 — NOT supported by ring. The C implementation only supports
        // Ed448 with Nettle >= 3.6. Ed448 is extremely rare in deployed DNSSEC.
        // We return None here, causing verify() to return UnsupportedAlgorithm.
        16 => None,

        // All other algorithms are unsupported
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// RSA Signature Verification
// ---------------------------------------------------------------------------

/// Verify an RSA signature for DNSSEC algorithms 5, 7, 8, and 10.
///
/// Parses the RSA public key from DNSKEY wire format (RFC 3110), then uses
/// `ring::signature::RsaPublicKeyComponents` for PKCS#1 v1.5 verification.
///
/// Replaces the C `dnsmasq_rsa_verify()` function (C lines 411-461).
///
/// # Key Format (RFC 3110)
///
/// The DNSKEY RDATA public key field for RSA contains:
/// ```text
/// +--+--+--+--+--+--+--+--+
/// |  exponent length (1 or 3 bytes)  |
/// +--+--+--+--+--+--+--+--+
/// |  exponent (exp_len bytes)        |
/// +--+--+--+--+--+--+--+--+
/// |  modulus (remaining bytes)        |
/// +--+--+--+--+--+--+--+--+
/// ```
///
/// - If the first byte is non-zero (1-255), it is the exponent length
/// - If the first byte is zero, the next 2 bytes are the exponent length (big-endian)
///
/// # Algorithm Mapping
///
/// | Algo | ring Verification Algorithm |
/// |------|---------------------------|
/// | 5, 7 | `RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY` |
/// | 8    | `RSA_PKCS1_2048_8192_SHA256` |
/// | 10   | `RSA_PKCS1_2048_8192_SHA512` |
fn rsa_verify(algo: u8, key: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, CryptoError> {
    // Key must be at least 3 bytes (1 byte exp_len + 1 byte exp + 1 byte modulus minimum)
    if key.len() < 3 {
        return Err(CryptoError::InvalidKeyFormat);
    }

    // Parse RFC 3110 key format: extract exponent length, exponent, and modulus
    let mut offset: usize = 0;
    let exp_len: usize;

    let first_byte = key[0];
    offset += 1;

    if first_byte != 0 {
        // Short form: first byte is the exponent length (1-255)
        exp_len = first_byte as usize;
    } else {
        // Long form: first byte is 0, next 2 bytes are exponent length (big-endian)
        if key.len() < 3 {
            return Err(CryptoError::InvalidKeyFormat);
        }
        exp_len = u16::from_be_bytes([key[1], key[2]]) as usize;
        offset += 2;
    }

    // Validate there's enough data for the exponent and at least 1 byte of modulus
    if offset + exp_len >= key.len() {
        return Err(CryptoError::InvalidKeyFormat);
    }

    let exponent = &key[offset..offset + exp_len];
    let modulus = &key[offset + exp_len..];

    // Validate exponent and modulus are non-empty
    if exponent.is_empty() || modulus.is_empty() {
        return Err(CryptoError::InvalidKeyFormat);
    }

    // Construct ring RSA public key components from parsed key data
    let components = RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    };

    // Select the ring RSA verification algorithm and verify based on DNSSEC algo number.
    // ring's verify() takes &RsaParameters (a concrete struct), the raw message, and
    // the signature. Ring handles PKCS#1 v1.5 padding and hashing internally.
    let result = match algo {
        // Algorithms 5 and 7 use SHA-1 (legacy, deprecated but still in use)
        5 | 7 => components.verify(
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            data,
            sig,
        ),
        // Algorithm 8 uses SHA-256 (recommended)
        8 => components.verify(&signature::RSA_PKCS1_2048_8192_SHA256, data, sig),
        // Algorithm 10 uses SHA-512 (recommended for large keys)
        10 => components.verify(&signature::RSA_PKCS1_2048_8192_SHA512, data, sig),
        _ => return Err(CryptoError::UnsupportedAlgorithm(algo)),
    };

    result
        .map(|_| true)
        .map_err(|_| CryptoError::VerificationFailed)
}

// ---------------------------------------------------------------------------
// ECDSA Signature Verification
// ---------------------------------------------------------------------------

/// Verify an ECDSA signature for DNSSEC algorithms 13 and 14.
///
/// ECDSA public keys in DNSSEC are raw (x || y) coordinates without the
/// 0x04 uncompressed point prefix. This function prepends the 0x04 byte
/// before passing to ring. Signatures are in fixed (r || s) format, which
/// matches ring's `ECDSA_P*_SHA*_FIXED` verification algorithms.
///
/// Replaces the C `dnsmasq_ecdsa_verify()` function (C lines 514-586).
///
/// # Key Format
///
/// - P-256 (algo 13): 64 bytes (32-byte X + 32-byte Y coordinates)
/// - P-384 (algo 14): 96 bytes (48-byte X + 48-byte Y coordinates)
///
/// The function prepends `0x04` (uncompressed point indicator) for ring.
///
/// # Signature Format
///
/// DNSSEC ECDSA signatures use raw (r || s) format, NOT DER/ASN.1:
/// - P-256: 64 bytes (32-byte r + 32-byte s)
/// - P-384: 96 bytes (48-byte r + 48-byte s)
///
/// ring's `ECDSA_P256_SHA256_FIXED` / `ECDSA_P384_SHA384_FIXED` accept
/// this fixed-size format directly.
///
/// # Important Note
///
/// The `data` parameter is the full message (RRSIG header + canonical RRset),
/// NOT a pre-computed hash digest. Ring's ECDSA verification handles hashing
/// internally, which matches the C code behavior where the hash context
/// accumulates the message data before verification.
fn ecdsa_verify(algo: u8, key: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, CryptoError> {
    // Determine curve parameters based on algorithm
    let (t, verification_alg): (usize, &dyn signature::VerificationAlgorithm) = match algo {
        // Algorithm 13: ECDSA P-256 with SHA-256, 32-byte coordinates
        13 => (32, &signature::ECDSA_P256_SHA256_FIXED),
        // Algorithm 14: ECDSA P-384 with SHA-384, 48-byte coordinates
        14 => (48, &signature::ECDSA_P384_SHA384_FIXED),
        _ => return Err(CryptoError::UnsupportedAlgorithm(algo)),
    };

    // Validate key and signature lengths
    // Key must be exactly 2*t bytes (x coordinate + y coordinate)
    if key.len() != 2 * t {
        return Err(CryptoError::InvalidKeyFormat);
    }
    // Signature must be exactly 2*t bytes (r value + s value)
    if sig.len() != 2 * t {
        return Err(CryptoError::VerificationFailed);
    }

    // Prepend 0x04 uncompressed point indicator for ring
    // DNSSEC DNSKEY public keys contain raw (x || y) without the prefix
    let mut uncompressed_key = Vec::with_capacity(1 + key.len());
    uncompressed_key.push(0x04);
    uncompressed_key.extend_from_slice(key);

    // Verify the signature against the full message data
    // ring handles SHA-256/SHA-384 hashing internally
    let public_key = UnparsedPublicKey::new(verification_alg, &uncompressed_key);
    public_key
        .verify(data, sig)
        .map(|_| true)
        .map_err(|_| CryptoError::VerificationFailed)
}

// ---------------------------------------------------------------------------
// EdDSA Signature Verification
// ---------------------------------------------------------------------------

/// Verify an EdDSA signature for DNSSEC algorithm 15 (Ed25519).
///
/// EdDSA algorithms operate on the complete message rather than a pre-computed
/// hash digest. The `data` parameter contains the full accumulated message
/// from the null-hash context.
///
/// Replaces the C `dnsmasq_eddsa_verify()` function (C lines 755-796).
///
/// # Ed25519 (Algorithm 15)
///
/// - Key: 32 bytes
/// - Signature: 64 bytes
/// - Uses `ring::signature::ED25519`
///
/// # Ed448 (Algorithm 16) — NOT SUPPORTED
///
/// Ed448 is not supported by the `ring` crate. The C implementation only
/// supports Ed448 with Nettle >= 3.6. This function returns
/// `UnsupportedAlgorithm` for algorithm 16. Ed448 is extremely rare in
/// deployed DNSSEC zones.
///
/// # Security Note (RFC 8032 Section 8.4)
///
/// Modified verification (re-signing to detect malicious data modifications)
/// is not performed because any attacker capable of creating a collision
/// preserving both the hash and signature would require finding arbitrary
/// SHA-512 collisions, which implies a complete break of SHA-512.
fn eddsa_verify(algo: u8, key: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, CryptoError> {
    match algo {
        15 => {
            // Ed25519: 32-byte key, 64-byte signature
            if key.len() != 32 {
                return Err(CryptoError::InvalidKeyFormat);
            }
            if sig.len() != 64 {
                return Err(CryptoError::VerificationFailed);
            }

            let public_key = UnparsedPublicKey::new(&signature::ED25519, key);
            public_key
                .verify(data, sig)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }

        // Ed448: 57-byte key, 114-byte signature
        // NOT SUPPORTED by ring. The C code supports Ed448 only with Nettle >= 3.6.
        // Ed448 is extremely rare in deployed DNSSEC zones.
        16 => Err(CryptoError::UnsupportedAlgorithm(algo)),

        _ => Err(CryptoError::UnsupportedAlgorithm(algo)),
    }
}

// ---------------------------------------------------------------------------
// DS Record Digest Computation
// ---------------------------------------------------------------------------

/// Compute the digest for a DS (Delegation Signer) record.
///
/// DS records contain a hash of the child zone's DNSKEY record. This function
/// computes that hash using the specified digest algorithm over the concatenation
/// of the owner name (in wire format, lowercased) and the DNSKEY RDATA
/// (flags + protocol + algorithm + public key).
///
/// Used by `validation.rs` for DS record verification during trust chain
/// traversal.
///
/// # Parameters
///
/// - `digest_type` — DS digest algorithm number (1=SHA-1, 2=SHA-256, 4=SHA-384)
/// - `owner_wire` — DNS owner name in wire format (lowercased per RFC 4034)
/// - `dnskey_rdata` — Complete DNSKEY RDATA: flags(2) + protocol(1) + algo(1) + pubkey
///
/// # Returns
///
/// The computed digest as a byte vector, or an error if the digest type is unsupported.
///
/// # References
///
/// - RFC 4034 Section 5.1.4: Computing the DS Record Digest
pub fn compute_ds_digest(
    digest_type: u8,
    owner_wire: &[u8],
    dnskey_rdata: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let digest_name =
        ds_digest_name(digest_type).ok_or(CryptoError::UnsupportedDigest(digest_type))?;
    let hash =
        hash_find(digest_name).ok_or(CryptoError::UnsupportedDigest(digest_type))?;

    let algorithm = hash
        .algorithm
        .ok_or(CryptoError::UnsupportedDigest(digest_type))?;

    let mut ctx = HashContext::new(algorithm);
    ctx.update(owner_wire);
    ctx.update(dnskey_rdata);
    Ok(ctx.finish().to_vec())
}

// ---------------------------------------------------------------------------
// NSEC3 Hash Computation
// ---------------------------------------------------------------------------

/// Compute the iterated hash for NSEC3 authenticated denial of existence.
///
/// Implements the NSEC3 hash computation defined in RFC 5155 Section 5:
///
/// ```text
/// IH(salt, x, 0) = H(x || salt)
/// IH(salt, x, k) = H(IH(salt, x, k-1) || salt)  for k > 0
/// ```
///
/// Where H is the hash function (currently only SHA-1 is defined for NSEC3).
///
/// # Parameters
///
/// - `algo` — NSEC3 hash algorithm number (1 = SHA-1)
/// - `name_wire` — DNS name in wire format to hash
/// - `salt` — NSEC3 salt bytes (may be empty)
/// - `iterations` — Number of additional hash iterations (0 = single hash)
///
/// # Returns
///
/// The computed hash as a byte vector, or an error if the algorithm is unsupported.
///
/// # References
///
/// - RFC 5155 Section 5: Calculation of the Hash
pub fn compute_nsec3_hash(
    algo: u8,
    name_wire: &[u8],
    salt: &[u8],
    iterations: u16,
) -> Result<Vec<u8>, CryptoError> {
    let digest_name =
        nsec3_digest_name(algo).ok_or(CryptoError::UnsupportedAlgorithm(algo))?;
    let hash =
        hash_find(digest_name).ok_or(CryptoError::UnsupportedAlgorithm(algo))?;

    let algorithm = hash
        .algorithm
        .ok_or(CryptoError::UnsupportedAlgorithm(algo))?;

    // Initial hash: H(name || salt)
    let mut ctx = HashContext::new(algorithm);
    ctx.update(name_wire);
    ctx.update(salt);
    let mut digest_result = ctx.finish().to_vec();

    // Iterated hashing: H(prev_hash || salt) for `iterations` times
    for _ in 0..iterations {
        let mut iter_ctx = HashContext::new(algorithm);
        iter_ctx.update(&digest_result);
        iter_ctx.update(salt);
        digest_result = iter_ctx.finish().to_vec();
    }

    Ok(digest_result)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Algorithm Mapping Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_algo_digest_name_rsa_sha1() {
        assert_eq!(algo_digest_name(5), Some("sha1"));
        assert_eq!(algo_digest_name(7), Some("sha1"));
    }

    #[test]
    fn test_algo_digest_name_rsa_sha256() {
        assert_eq!(algo_digest_name(8), Some("sha256"));
    }

    #[test]
    fn test_algo_digest_name_rsa_sha512() {
        assert_eq!(algo_digest_name(10), Some("sha512"));
    }

    #[test]
    fn test_algo_digest_name_ecdsa() {
        assert_eq!(algo_digest_name(13), Some("sha256"));
        assert_eq!(algo_digest_name(14), Some("sha384"));
    }

    #[test]
    fn test_algo_digest_name_eddsa() {
        assert_eq!(algo_digest_name(15), Some("null_hash"));
        assert_eq!(algo_digest_name(16), Some("null_hash"));
    }

    #[test]
    fn test_algo_digest_name_deprecated() {
        // RSA/MD5 — MUST NOT implement
        assert_eq!(algo_digest_name(1), None);
        // Diffie-Hellman
        assert_eq!(algo_digest_name(2), None);
        // DSA/SHA1 — MUST NOT implement
        assert_eq!(algo_digest_name(3), None);
        // DSA-NSEC3-SHA1 — MUST NOT implement
        assert_eq!(algo_digest_name(6), None);
    }

    #[test]
    fn test_algo_digest_name_gost_unsupported() {
        // GOST not supported by ring
        assert_eq!(algo_digest_name(12), None);
    }

    #[test]
    fn test_algo_digest_name_unknown() {
        assert_eq!(algo_digest_name(0), None);
        assert_eq!(algo_digest_name(4), None);
        assert_eq!(algo_digest_name(9), None);
        assert_eq!(algo_digest_name(11), None);
        assert_eq!(algo_digest_name(17), None);
        assert_eq!(algo_digest_name(255), None);
    }

    #[test]
    fn test_ds_digest_name_sha1() {
        assert_eq!(ds_digest_name(1), Some("sha1"));
    }

    #[test]
    fn test_ds_digest_name_sha256() {
        assert_eq!(ds_digest_name(2), Some("sha256"));
    }

    #[test]
    fn test_ds_digest_name_gost_unsupported() {
        assert_eq!(ds_digest_name(3), None);
    }

    #[test]
    fn test_ds_digest_name_sha384() {
        assert_eq!(ds_digest_name(4), Some("sha384"));
    }

    #[test]
    fn test_ds_digest_name_unknown() {
        assert_eq!(ds_digest_name(0), None);
        assert_eq!(ds_digest_name(5), None);
        assert_eq!(ds_digest_name(255), None);
    }

    #[test]
    fn test_nsec3_digest_name_sha1() {
        assert_eq!(nsec3_digest_name(1), Some("sha1"));
    }

    #[test]
    fn test_nsec3_digest_name_unknown() {
        assert_eq!(nsec3_digest_name(0), None);
        assert_eq!(nsec3_digest_name(2), None);
        assert_eq!(nsec3_digest_name(255), None);
    }

    // -----------------------------------------------------------------------
    // Hash Function Lookup Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_find_sha1() {
        let hash = hash_find("sha1").expect("sha1 should be found");
        assert_eq!(hash.name, "sha1");
        assert_eq!(hash.digest_size, 20);
        assert!(hash.algorithm.is_some());
    }

    #[test]
    fn test_hash_find_sha256() {
        let hash = hash_find("sha256").expect("sha256 should be found");
        assert_eq!(hash.name, "sha256");
        assert_eq!(hash.digest_size, 32);
        assert!(hash.algorithm.is_some());
    }

    #[test]
    fn test_hash_find_sha384() {
        let hash = hash_find("sha384").expect("sha384 should be found");
        assert_eq!(hash.name, "sha384");
        assert_eq!(hash.digest_size, 48);
        assert!(hash.algorithm.is_some());
    }

    #[test]
    fn test_hash_find_sha512() {
        let hash = hash_find("sha512").expect("sha512 should be found");
        assert_eq!(hash.name, "sha512");
        assert_eq!(hash.digest_size, 64);
        assert!(hash.algorithm.is_some());
    }

    #[test]
    fn test_hash_find_null_hash() {
        let hash = hash_find("null_hash").expect("null_hash should be found");
        assert_eq!(hash.name, "null_hash");
        assert_eq!(hash.digest_size, 0);
        assert!(hash.algorithm.is_none());
    }

    #[test]
    fn test_hash_find_unknown() {
        assert!(hash_find("md5").is_none());
        assert!(hash_find("").is_none());
        assert!(hash_find("gosthash94cp").is_none());
    }

    // -----------------------------------------------------------------------
    // Hash Init Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_init_sha256() {
        let hash = hash_find("sha256").unwrap();
        let (ctx, digest_buf) = hash_init(&hash).expect("init should succeed");
        assert_eq!(digest_buf.len(), 32);
        assert!(matches!(ctx.inner, HashContextInner::Digest(_)));
    }

    #[test]
    fn test_hash_init_null_hash() {
        let hash = hash_find("null_hash").unwrap();
        let (ctx, digest_buf) = hash_init(&hash).expect("init should succeed");
        assert!(digest_buf.is_empty());
        assert!(matches!(ctx.inner, HashContextInner::NullHash(_)));
    }

    // -----------------------------------------------------------------------
    // HashContext Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_context_sha256_empty() {
        let mut ctx = HashContext::new(&SHA256);
        let digest = ctx.finish();
        // SHA-256 of empty string
        assert_eq!(digest.len(), 32);
        assert_eq!(
            digest,
            &[
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
                0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn test_hash_context_sha256_hello() {
        let mut ctx = HashContext::new(&SHA256);
        ctx.update(b"hello");
        let digest = ctx.finish();
        assert_eq!(digest.len(), 32);
        // SHA-256 of "hello"
        assert_eq!(
            digest,
            &[
                0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b,
                0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7,
                0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
            ]
        );
    }

    #[test]
    fn test_hash_context_sha256_incremental() {
        let mut ctx = HashContext::new(&SHA256);
        ctx.update(b"hel");
        ctx.update(b"lo");
        let digest1 = ctx.finish().to_vec();

        let mut ctx2 = HashContext::new(&SHA256);
        ctx2.update(b"hello");
        let digest2 = ctx2.finish().to_vec();

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_hash_context_null_hash() {
        let mut ctx = HashContext::new_null_hash();
        ctx.update(b"hello ");
        ctx.update(b"world");
        let result = ctx.finish();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_hash_context_reset() {
        let mut ctx = HashContext::new(&SHA256);
        ctx.update(b"first data");
        ctx.reset();
        ctx.update(b"hello");
        let digest = ctx.finish().to_vec();

        let mut ctx2 = HashContext::new(&SHA256);
        ctx2.update(b"hello");
        let digest2 = ctx2.finish().to_vec();

        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_hash_context_null_hash_reset() {
        let mut ctx = HashContext::new_null_hash();
        ctx.update(b"some data");
        ctx.reset();
        assert_eq!(ctx.finish(), b"" as &[u8]);
    }

    // -----------------------------------------------------------------------
    // HashFunction Method Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_function_update_and_digest() {
        let hash = hash_find("sha256").unwrap();
        let (mut ctx, _) = hash_init(&hash).unwrap();
        hash.update(&mut ctx, b"hello");
        let result = hash.digest(&mut ctx);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash_function_digest_size() {
        assert_eq!(hash_find("sha1").unwrap().digest_size(), 20);
        assert_eq!(hash_find("sha256").unwrap().digest_size(), 32);
        assert_eq!(hash_find("sha384").unwrap().digest_size(), 48);
        assert_eq!(hash_find("sha512").unwrap().digest_size(), 64);
        assert_eq!(hash_find("null_hash").unwrap().digest_size(), 0);
    }

    // -----------------------------------------------------------------------
    // Verify Function Dispatch Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_unsupported_algorithm() {
        let result = verify(1, &[], &[], &[]); // RSA/MD5 — MUST NOT implement
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::UnsupportedAlgorithm(1)
        ));
    }

    #[test]
    fn test_verify_gost_unsupported() {
        let result = verify(12, &[], &[], &[]); // GOST — not supported
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::UnsupportedAlgorithm(12)
        ));
    }

    #[test]
    fn test_verify_ed448_unsupported() {
        let result = verify(16, &[0u8; 57], &[0u8; 114], &[0u8; 10]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::UnsupportedAlgorithm(16)
        ));
    }

    #[test]
    fn test_rsa_verify_short_key() {
        let result = rsa_verify(8, &[0, 0], &[], &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeyFormat));
    }

    #[test]
    fn test_rsa_verify_invalid_exp_len() {
        // exp_len (255) > remaining key bytes (1)
        let result = rsa_verify(8, &[255, 0x01], &[], &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeyFormat));
    }

    #[test]
    fn test_rsa_verify_long_form_exp_len() {
        // Long form: first byte 0, then 2-byte exp_len = 1
        // Key: [0, 0, 1, <exp: 0x03>, <modulus: 0xFF...>]
        let mut key = vec![0u8, 0, 1, 0x03];
        key.extend_from_slice(&[0xFF; 256]); // modulus
        let result = rsa_verify(8, &key, &[0u8; 256], b"test data");
        // Should fail verification (invalid key/sig combo) but not format error
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdsa_verify_wrong_key_length() {
        // P-256 expects 64-byte key, we provide 32
        let result = ecdsa_verify(13, &[0u8; 32], &[0u8; 64], b"data");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeyFormat));
    }

    #[test]
    fn test_ecdsa_verify_wrong_sig_length() {
        // P-256 expects 64-byte sig, we provide 32
        let result = ecdsa_verify(13, &[0u8; 64], &[0u8; 32], b"data");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::VerificationFailed
        ));
    }

    #[test]
    fn test_eddsa_verify_wrong_key_length() {
        // Ed25519 expects 32-byte key
        let result = eddsa_verify(15, &[0u8; 16], &[0u8; 64], b"data");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeyFormat));
    }

    #[test]
    fn test_eddsa_verify_wrong_sig_length() {
        // Ed25519 expects 64-byte signature
        let result = eddsa_verify(15, &[0u8; 32], &[0u8; 32], b"data");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::VerificationFailed
        ));
    }

    // -----------------------------------------------------------------------
    // DS Digest Computation Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_ds_digest_sha256() {
        let owner_wire = b"\x07example\x03com\x00"; // example.com in wire format
        let dnskey_rdata = &[
            0x01, 0x01, // flags: 257 (KSK)
            0x03, // protocol: 3
            0x08, // algorithm: 8 (RSA/SHA-256)
            0xAA, 0xBB, 0xCC, 0xDD, // some public key bytes
        ];
        let result = compute_ds_digest(2, owner_wire, dnskey_rdata);
        assert!(result.is_ok());
        let digest = result.unwrap();
        assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_compute_ds_digest_sha1() {
        let owner_wire = b"\x07example\x03com\x00";
        let dnskey_rdata = &[0x01, 0x01, 0x03, 0x08, 0xAA, 0xBB];
        let result = compute_ds_digest(1, owner_wire, dnskey_rdata);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 20); // SHA-1 produces 20 bytes
    }

    #[test]
    fn test_compute_ds_digest_sha384() {
        let owner_wire = b"\x07example\x03com\x00";
        let dnskey_rdata = &[0x01, 0x01, 0x03, 0x08, 0xAA, 0xBB];
        let result = compute_ds_digest(4, owner_wire, dnskey_rdata);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 48); // SHA-384 produces 48 bytes
    }

    #[test]
    fn test_compute_ds_digest_unsupported() {
        let result = compute_ds_digest(3, b"", b""); // GOST — unsupported
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::UnsupportedDigest(3)
        ));
    }

    #[test]
    fn test_compute_ds_digest_deterministic() {
        let owner = b"\x07example\x03com\x00";
        let rdata = &[0x01, 0x01, 0x03, 0x08, 0xAA];
        let d1 = compute_ds_digest(2, owner, rdata).unwrap();
        let d2 = compute_ds_digest(2, owner, rdata).unwrap();
        assert_eq!(d1, d2);
    }

    // -----------------------------------------------------------------------
    // NSEC3 Hash Computation Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_nsec3_hash_sha1() {
        let name_wire = b"\x07example\x03com\x00";
        let salt = b"\xAA\xBB\xCC\xDD";
        let result = compute_nsec3_hash(1, name_wire, salt, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 20); // SHA-1 produces 20 bytes
    }

    #[test]
    fn test_compute_nsec3_hash_with_iterations() {
        let name_wire = b"\x07example\x03com\x00";
        let salt = b"\xAA\xBB";
        let no_iter = compute_nsec3_hash(1, name_wire, salt, 0).unwrap();
        let with_iter = compute_nsec3_hash(1, name_wire, salt, 5).unwrap();
        // Different iteration counts should produce different results
        assert_ne!(no_iter, with_iter);
        // Both should be 20 bytes (SHA-1)
        assert_eq!(no_iter.len(), 20);
        assert_eq!(with_iter.len(), 20);
    }

    #[test]
    fn test_compute_nsec3_hash_empty_salt() {
        let name_wire = b"\x07example\x03com\x00";
        let result = compute_nsec3_hash(1, name_wire, b"", 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 20);
    }

    #[test]
    fn test_compute_nsec3_hash_unsupported_algo() {
        let result = compute_nsec3_hash(2, b"", b"", 0); // Only algo 1 is defined
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::UnsupportedAlgorithm(2)
        ));
    }

    #[test]
    fn test_compute_nsec3_hash_deterministic() {
        let name = b"\x03foo\x03bar\x00";
        let salt = b"\x01\x02";
        let h1 = compute_nsec3_hash(1, name, salt, 3).unwrap();
        let h2 = compute_nsec3_hash(1, name, salt, 3).unwrap();
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // CryptoError Display Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::UnsupportedAlgorithm(12);
        assert_eq!(format!("{}", err), "unsupported algorithm: 12");

        let err = CryptoError::VerificationFailed;
        assert_eq!(format!("{}", err), "verification failed");

        let err = CryptoError::InvalidKeyFormat;
        assert_eq!(format!("{}", err), "invalid key format");

        let err = CryptoError::HashInitFailed;
        assert_eq!(format!("{}", err), "hash initialization failed");

        let err = CryptoError::UnsupportedDigest(3);
        assert_eq!(format!("{}", err), "unsupported digest type: 3");
    }

    // -----------------------------------------------------------------------
    // Verify Function — Algorithm Availability Check
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_func_rsa_algorithms() {
        assert!(verify_func(5).is_some());
        assert!(verify_func(7).is_some());
        assert!(verify_func(8).is_some());
        assert!(verify_func(10).is_some());
    }

    #[test]
    fn test_verify_func_ecdsa_algorithms() {
        assert!(verify_func(13).is_some());
        assert!(verify_func(14).is_some());
    }

    #[test]
    fn test_verify_func_eddsa_algorithms() {
        assert!(verify_func(15).is_some()); // Ed25519 supported
        assert!(verify_func(16).is_none()); // Ed448 not supported
    }

    #[test]
    fn test_verify_func_unsupported() {
        assert!(verify_func(0).is_none());
        assert!(verify_func(1).is_none()); // RSA/MD5 deprecated
        assert!(verify_func(2).is_none()); // DH
        assert!(verify_func(3).is_none()); // DSA
        assert!(verify_func(6).is_none()); // DSA-NSEC3
        assert!(verify_func(12).is_none()); // GOST
        assert!(verify_func(17).is_none());
    }
}

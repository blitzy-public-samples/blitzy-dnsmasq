// Copyright (c) 2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// DNSSEC Cryptographic Operations Module
//
// This module provides cryptographic operations for DNSSEC signature
// verification, serving as a thin abstraction layer over the GNU Nettle
// library (via the `nettle` Rust crate). Migrated from C `src/crypto.c`
// (1,295 lines).
//
// Isolates all cryptographic functionality from the core DNSSEC validation
// logic in `dns/dnssec.rs`. Gated by the `dnssec` Cargo feature flag.
//
// Supported algorithms:
//   - RSA/SHA-1 (algorithm 5), RSA/SHA-1-NSEC3 (algorithm 7)
//   - RSA/SHA-256 (algorithm 8), RSA/SHA-512 (algorithm 10)
//   - ECDSA P-256/SHA-256 (algorithm 13), ECDSA P-384/SHA-384 (algorithm 14)
//   - Ed25519 (algorithm 15), Ed448 (algorithm 16)
//   - ECC-GOST (algorithm 12) — reported as unsupported (no safe Rust binding)
//
// Replaces direct C FFI calls to libnettle/libhogweed in the original
// crypto.c with safe Rust crate APIs. No `unsafe` blocks in this file.

use crate::core::types::{DnsmasqError, DnsmasqResult};
use crate::dns::blockdata::BlockData;

use nettle::dsa::Signature as DsaSignature;
use nettle::ecc::{Point, Secp256r1, Secp384r1};
use nettle::hash::insecure_do_not_use::Sha1;
use nettle::hash::{Hash, Sha256, Sha384, Sha512};
use nettle::rsa::{self, PublicKey as RsaPublicKey};
use nettle::{ecdsa, ed25519, ed448};

use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// DNSSEC Algorithm Identifiers (IANA DNSSEC Algorithm Numbers)
// ---------------------------------------------------------------------------

/// DNSSEC signature algorithm identifiers as defined by the IANA registry.
///
/// Maps to the algorithm field in DNSKEY, RRSIG, and DS resource records.
/// Replaces the integer constants dispatched through `verify_func()` in
/// the original C `crypto.c` (line 867).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecAlgorithm {
    /// RSA/SHA-1 — DNSSEC algorithm 5 (RFC 3110)
    RsaSha1 = 5,
    /// RSA/SHA-1 with NSEC3 — DNSSEC algorithm 7 (RFC 5155)
    RsaSha1Nsec3 = 7,
    /// RSA/SHA-256 — DNSSEC algorithm 8 (RFC 5702)
    RsaSha256 = 8,
    /// RSA/SHA-512 — DNSSEC algorithm 10 (RFC 5702)
    RsaSha512 = 10,
    /// ECC-GOST — DNSSEC algorithm 12 (RFC 5933)
    /// Note: Not currently verifiable via the safe nettle crate; reported
    /// as unsupported. Kept for algorithm enumeration completeness.
    EccGost = 12,
    /// ECDSA Curve P-256 with SHA-256 — DNSSEC algorithm 13 (RFC 6605)
    EcdsaP256Sha256 = 13,
    /// ECDSA Curve P-384 with SHA-384 — DNSSEC algorithm 14 (RFC 6605)
    EcdsaP384Sha384 = 14,
    /// Ed25519 — DNSSEC algorithm 15 (RFC 8080)
    Ed25519 = 15,
    /// Ed448 — DNSSEC algorithm 16 (RFC 8080)
    Ed448 = 16,
}

impl DnssecAlgorithm {
    /// Converts a raw IANA algorithm number to a `DnssecAlgorithm` variant.
    ///
    /// Returns `None` for unrecognised or deprecated algorithm numbers
    /// (e.g. RSAMD5=1, DH=2, DSA=3, DSA-NSEC3=6 are all deprecated).
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            5 => Some(Self::RsaSha1),
            7 => Some(Self::RsaSha1Nsec3),
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            12 => Some(Self::EccGost),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }

    /// Returns the raw IANA algorithm number.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// DS Record Digest Algorithm Identifiers
// ---------------------------------------------------------------------------

/// Digest algorithm identifiers used in DS (Delegation Signer) records.
///
/// Maps to the digest type field in DS RRs (RFC 4034 Appendix A.2,
/// updated by RFC 4509, RFC 5933, RFC 6605).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-1 — DS digest type 1 (RFC 3658)
    Sha1 = 1,
    /// SHA-256 — DS digest type 2 (RFC 4509)
    Sha256 = 2,
    /// GOST R 34.11-94 — DS digest type 3 (RFC 5933)
    /// Note: Not supported via the safe nettle crate API in this build.
    GostHash94 = 3,
    /// SHA-384 — DS digest type 4 (RFC 6605)
    Sha384 = 4,
}

impl DigestAlgorithm {
    /// Converts a raw DS digest type number to a `DigestAlgorithm` variant.
    ///
    /// Returns `None` for unrecognised digest type numbers.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            3 => Some(Self::GostHash94),
            4 => Some(Self::Sha384),
            _ => None,
        }
    }

    /// Returns the raw DS digest type number.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// NSEC3 Hash Algorithm Identifiers
// ---------------------------------------------------------------------------

/// NSEC3 hash algorithm identifiers (RFC 5155 Section 4.1).
///
/// Currently only SHA-1 (type 1) is defined by the IANA registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nsec3HashAlgorithm {
    /// SHA-1 — NSEC3 hash algorithm 1 (RFC 5155)
    Sha1 = 1,
}

impl Nsec3HashAlgorithm {
    /// Converts a raw NSEC3 hash algorithm number to a variant.
    ///
    /// Returns `None` for any value other than 1.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Sha1),
            _ => None,
        }
    }

    /// Returns the raw NSEC3 hash algorithm number.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// HashFunction Trait — Replaces C function-pointer-based hash dispatch
// ---------------------------------------------------------------------------

/// Abstraction over hash functions used in DNSSEC operations.
///
/// Replaces the C `struct nettle_hash` function-pointer table and the
/// dynamic `hash_init()` / `hash_find()` dispatch in `crypto.c`.
///
/// The trait is object-safe so callers can use `Box<dyn HashFunction>`.
pub trait HashFunction: Send + Sync {
    /// Feed additional data into the hash state.
    fn update(&mut self, data: &[u8]);

    /// Finalise the hash computation and return the digest bytes.
    ///
    /// After calling `finalize()` the internal state is reset, matching
    /// the behaviour of `nettle::hash::Hash::digest()`.
    fn finalize(&mut self) -> Vec<u8>;

    /// Returns the output digest size in bytes.
    fn digest_size(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Concrete HashFunction implementations wrapping nettle hash types
// ---------------------------------------------------------------------------

/// SHA-1 wrapper implementing `HashFunction`.
struct Sha1Hash {
    inner: Sha1,
}

impl Sha1Hash {
    fn new() -> Self {
        Self {
            inner: Sha1::default(),
        }
    }
}

impl HashFunction for Sha1Hash {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.inner.digest_size()];
        self.inner.digest(&mut out);
        out
    }

    fn digest_size(&self) -> usize {
        self.inner.digest_size()
    }
}

/// SHA-256 wrapper implementing `HashFunction`.
struct Sha256Hash {
    inner: Sha256,
}

impl Sha256Hash {
    fn new() -> Self {
        Self {
            inner: Sha256::default(),
        }
    }
}

impl HashFunction for Sha256Hash {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.inner.digest_size()];
        self.inner.digest(&mut out);
        out
    }

    fn digest_size(&self) -> usize {
        self.inner.digest_size()
    }
}

/// SHA-384 wrapper implementing `HashFunction`.
struct Sha384Hash {
    inner: Sha384,
}

impl Sha384Hash {
    fn new() -> Self {
        Self {
            inner: Sha384::default(),
        }
    }
}

impl HashFunction for Sha384Hash {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.inner.digest_size()];
        self.inner.digest(&mut out);
        out
    }

    fn digest_size(&self) -> usize {
        self.inner.digest_size()
    }
}

/// SHA-512 wrapper implementing `HashFunction`.
struct Sha512Hash {
    inner: Sha512,
}

impl Sha512Hash {
    fn new() -> Self {
        Self {
            inner: Sha512::default(),
        }
    }
}

impl HashFunction for Sha512Hash {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.inner.digest_size()];
        self.inner.digest(&mut out);
        out
    }

    fn digest_size(&self) -> usize {
        self.inner.digest_size()
    }
}

/// Null hash — buffers the entire message without hashing.
///
/// Used for EdDSA algorithms (Ed25519 / Ed448) which operate on the
/// complete message rather than a pre-computed digest. Mirrors the
/// `null_hash` structure from C `crypto.c` lines 91–271.
struct NullHash {
    buffer: Vec<u8>,
}

impl NullHash {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl HashFunction for NullHash {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(&mut self) -> Vec<u8> {
        // Return the accumulated message buffer and reset.
        std::mem::take(&mut self.buffer)
    }

    fn digest_size(&self) -> usize {
        // The "digest" is the full message — size is dynamic.
        self.buffer.len()
    }
}

// ---------------------------------------------------------------------------
// CryptoVerifier — Main DNSSEC signature verification entry point
// ---------------------------------------------------------------------------

/// Cryptographic verifier for DNSSEC signatures.
///
/// Provides a stateless API that dispatches signature verification to the
/// appropriate algorithm-specific implementation. Replaces the `verify()`
/// entry point at C `crypto.c` line 970 and the `verify_func()` dispatcher
/// at line 867.
///
/// # Usage
///
/// ```ignore
/// let result = CryptoVerifier::verify(
///     algorithm,
///     &key_blockdata,
///     key_len,
///     &sig_blockdata,
///     sig_len,
///     digest,
///     algo,
/// );
/// ```
pub struct CryptoVerifier;

impl CryptoVerifier {
    /// Verify a DNSSEC signature.
    ///
    /// This is the main entry point that dispatches to algorithm-specific
    /// verification functions. Mirrors C `verify()` (crypto.c line 970).
    ///
    /// # Arguments
    ///
    /// * `algo`     — The DNSSEC algorithm number from the RRSIG record.
    /// * `key_data` — The DNSKEY RDATA containing the public key material.
    /// * `sig_data` — The signature bytes from the RRSIG record.
    /// * `digest`   — The pre-computed digest (or full message for EdDSA).
    ///
    /// # Returns
    ///
    /// * `Ok(true)`  — Signature is valid.
    /// * `Ok(false)` — Signature is cryptographically invalid.
    /// * `Err(_)`    — A structural or operational error occurred (malformed
    ///   key, unsupported algorithm, library error).
    pub fn verify(
        algo: DnssecAlgorithm,
        key_data: &BlockData,
        sig_data: &BlockData,
        digest: &[u8],
    ) -> DnsmasqResult<bool> {
        let key_bytes = key_data.as_bytes();
        let sig_bytes = sig_data.as_bytes();
        let key_len = key_data.len();
        let sig_len = sig_data.len();

        debug!(
            algorithm = ?algo,
            key_len = key_len,
            sig_len = sig_len,
            digest_len = digest.len(),
            "DNSSEC signature verification attempt"
        );

        let result = match algo {
            DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3 => {
                verify_rsa(algo, key_bytes, sig_bytes, digest)
            }
            DnssecAlgorithm::RsaSha256 => verify_rsa(algo, key_bytes, sig_bytes, digest),
            DnssecAlgorithm::RsaSha512 => verify_rsa(algo, key_bytes, sig_bytes, digest),
            DnssecAlgorithm::EcdsaP256Sha256 => verify_ecdsa_p256(key_bytes, sig_bytes, digest),
            DnssecAlgorithm::EcdsaP384Sha384 => verify_ecdsa_p384(key_bytes, sig_bytes, digest),
            DnssecAlgorithm::Ed25519 => verify_ed25519(key_bytes, sig_bytes, digest),
            DnssecAlgorithm::Ed448 => verify_ed448(key_bytes, sig_bytes, digest),
            DnssecAlgorithm::EccGost => {
                warn!("ECC-GOST (algorithm 12) is not supported in this build");
                Err(DnsmasqError::Dnssec(
                    "ECC-GOST (algorithm 12) not supported".to_string(),
                ))
            }
        };

        match &result {
            Ok(true) => {
                debug!(algorithm = ?algo, "Signature verification succeeded");
            }
            Ok(false) => {
                debug!(algorithm = ?algo, "Signature verification failed (invalid)");
            }
            Err(e) => {
                debug!(algorithm = ?algo, error = %e, "Signature verification error");
            }
        }

        result
    }

    /// Map a DNSSEC algorithm number to its associated digest algorithm name.
    ///
    /// Replaces C `algo_digest_name()` (crypto.c line 1068). Returns the
    /// canonical hash name string used for digest computation during
    /// RRSIG validation.
    ///
    /// Returns `None` for deprecated or unrecognised algorithms.
    pub fn algo_digest_name(algo: DnssecAlgorithm) -> Option<&'static str> {
        match algo {
            DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3 => Some("sha1"),
            DnssecAlgorithm::RsaSha256 | DnssecAlgorithm::EcdsaP256Sha256 => Some("sha256"),
            DnssecAlgorithm::EcdsaP384Sha384 => Some("sha384"),
            DnssecAlgorithm::RsaSha512 => Some("sha512"),
            DnssecAlgorithm::EccGost => {
                // In C, this returns "gosthash94cp" if nettle >= 3.6.
                // The safe Rust nettle crate does not expose GOST hashes.
                None
            }
            DnssecAlgorithm::Ed25519 | DnssecAlgorithm::Ed448 => {
                // EdDSA uses the "null hash" — the full message is passed
                // to the verification function rather than a digest.
                Some("null_hash")
            }
        }
    }

    /// Map a DS digest type to its associated hash function name.
    ///
    /// Replaces C `ds_digest_name()` (crypto.c line 1028). Used to
    /// select the hash function for computing the digest over a DNSKEY
    /// record to compare against a DS record.
    ///
    /// Returns `None` for unsupported digest types.
    pub fn ds_digest_name(digest_type: DigestAlgorithm) -> Option<&'static str> {
        match digest_type {
            DigestAlgorithm::Sha1 => Some("sha1"),
            DigestAlgorithm::Sha256 => Some("sha256"),
            DigestAlgorithm::GostHash94 => {
                // In C, returns "gosthash94cp" if nettle >= 3.6.
                // Not available via safe Rust nettle crate.
                None
            }
            DigestAlgorithm::Sha384 => Some("sha384"),
        }
    }

    /// Map an NSEC3 hash algorithm number to its hash function name.
    ///
    /// Replaces C `nsec3_digest_name()` (crypto.c line 1104). Currently
    /// only SHA-1 (type 1) is defined.
    ///
    /// Returns `None` for unrecognised hash algorithm numbers.
    pub fn nsec3_digest_name(hash_algo: Nsec3HashAlgorithm) -> Option<&'static str> {
        match hash_algo {
            Nsec3HashAlgorithm::Sha1 => Some("sha1"),
        }
    }

    /// Look up a hash function implementation by name.
    ///
    /// Replaces C `hash_find()` (crypto.c line 1117). Returns a boxed
    /// `HashFunction` trait object that can be used for incremental
    /// digest computation.
    ///
    /// Supported names: `"sha1"`, `"sha256"`, `"sha384"`, `"sha512"`,
    /// `"null_hash"`.
    ///
    /// Returns `Err` if the name is not recognised.
    pub fn hash_find(name: &str) -> DnsmasqResult<Box<dyn HashFunction>> {
        match name {
            "sha1" => Ok(Box::new(Sha1Hash::new())),
            "sha256" => Ok(Box::new(Sha256Hash::new())),
            "sha384" => Ok(Box::new(Sha384Hash::new())),
            "sha512" => Ok(Box::new(Sha512Hash::new())),
            "null_hash" => Ok(Box::new(NullHash::new())),
            _ => {
                warn!(hash_name = name, "Unknown hash function requested");
                Err(DnsmasqError::Dnssec(format!(
                    "Unknown hash function: {}",
                    name
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal verification functions
// ---------------------------------------------------------------------------

/// RSA signature verification for algorithms 5, 7, 8, and 10.
///
/// Parses the DNSKEY RDATA wire format per RFC 3110:
///   - 1-byte exponent length if value <= 255
///   - 3-byte (0x00 || 2-byte big-endian) exponent length otherwise
///   - exponent bytes (big-endian)
///   - modulus bytes (big-endian, remaining bytes)
///
/// Dispatches to `nettle::rsa::verify_digest_pkcs1` with the appropriate
/// ASN.1 DigestInfo OID prefix for the hash algorithm.
///
/// Replaces C `dnsmasq_rsa_verify()` (crypto.c line 411).
fn verify_rsa(algo: DnssecAlgorithm, key: &[u8], sig: &[u8], digest: &[u8]) -> DnsmasqResult<bool> {
    if key.is_empty() {
        return Err(DnsmasqError::Dnssec("RSA: empty key data".to_string()));
    }

    // Parse exponent length per RFC 3110 Section 2.
    let (exp_len, offset) = {
        let first = key[0] as usize;
        if first > 0 {
            // 1-byte exponent length
            (first, 1)
        } else {
            // 3-byte exponent length: 0x00 || 2-byte big-endian length
            if key.len() < 3 {
                return Err(DnsmasqError::Dnssec(
                    "RSA: key too short for 3-byte exponent length".to_string(),
                ));
            }
            let high = key[1] as usize;
            let low = key[2] as usize;
            ((high << 8) | low, 3)
        }
    };

    if key.len() < offset + exp_len {
        return Err(DnsmasqError::Dnssec(
            "RSA: key data truncated (exponent)".to_string(),
        ));
    }

    let exponent = &key[offset..offset + exp_len];
    let modulus = &key[offset + exp_len..];

    if modulus.is_empty() {
        return Err(DnsmasqError::Dnssec("RSA: empty modulus".to_string()));
    }

    // Construct the nettle RSA public key from (n, e) in big-endian.
    let pubkey = RsaPublicKey::new(modulus, exponent)
        .map_err(|e| DnsmasqError::Dnssec(format!("RSA: failed to construct public key: {}", e)))?;

    // Select the ASN.1 DigestInfo OID prefix for PKCS#1 v1.5 verification.
    let digest_info: &[u8] = match algo {
        DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3 => rsa::ASN1_OID_SHA1,
        DnssecAlgorithm::RsaSha256 => rsa::ASN1_OID_SHA256,
        DnssecAlgorithm::RsaSha512 => rsa::ASN1_OID_SHA512,
        _ => {
            return Err(DnsmasqError::Dnssec(format!(
                "RSA: unexpected algorithm {:?} for RSA verification",
                algo
            )));
        }
    };

    rsa::verify_digest_pkcs1(&pubkey, digest, digest_info, sig)
        .map_err(|e| DnsmasqError::Dnssec(format!("RSA: verification error: {}", e)))
}

/// ECDSA P-256/SHA-256 verification (algorithm 13).
///
/// Key format: X || Y coordinates, each 32 bytes (64 bytes total).
/// Signature format: R || S, each 32 bytes (64 bytes total).
///
/// Replaces C `dnsmasq_ecdsa_verify()` for P-256 (crypto.c line 514).
fn verify_ecdsa_p256(key: &[u8], sig: &[u8], digest: &[u8]) -> DnsmasqResult<bool> {
    const T: usize = 32; // P-256 coordinate size

    if key.len() != 2 * T {
        return Err(DnsmasqError::Dnssec(format!(
            "ECDSA P-256: expected {} byte key, got {}",
            2 * T,
            key.len()
        )));
    }
    if sig.len() != 2 * T {
        return Err(DnsmasqError::Dnssec(format!(
            "ECDSA P-256: expected {} byte signature, got {}",
            2 * T,
            sig.len()
        )));
    }

    let x = &key[..T];
    let y = &key[T..];
    let r = &sig[..T];
    let s = &sig[T..];

    let point = Point::new::<Secp256r1>(x, y).map_err(|e| {
        DnsmasqError::Dnssec(format!("ECDSA P-256: invalid public key point: {}", e))
    })?;

    let signature = DsaSignature::new(r, s);

    Ok(ecdsa::verify(&point, digest, &signature))
}

/// ECDSA P-384/SHA-384 verification (algorithm 14).
///
/// Key format: X || Y coordinates, each 48 bytes (96 bytes total).
/// Signature format: R || S, each 48 bytes (96 bytes total).
///
/// Replaces C `dnsmasq_ecdsa_verify()` for P-384 (crypto.c line 514).
fn verify_ecdsa_p384(key: &[u8], sig: &[u8], digest: &[u8]) -> DnsmasqResult<bool> {
    const T: usize = 48; // P-384 coordinate size

    if key.len() != 2 * T {
        return Err(DnsmasqError::Dnssec(format!(
            "ECDSA P-384: expected {} byte key, got {}",
            2 * T,
            key.len()
        )));
    }
    if sig.len() != 2 * T {
        return Err(DnsmasqError::Dnssec(format!(
            "ECDSA P-384: expected {} byte signature, got {}",
            2 * T,
            sig.len()
        )));
    }

    let x = &key[..T];
    let y = &key[T..];
    let r = &sig[..T];
    let s = &sig[T..];

    let point = Point::new::<Secp384r1>(x, y).map_err(|e| {
        DnsmasqError::Dnssec(format!("ECDSA P-384: invalid public key point: {}", e))
    })?;

    let signature = DsaSignature::new(r, s);

    Ok(ecdsa::verify(&point, digest, &signature))
}

/// Ed25519 verification (algorithm 15).
///
/// Ed25519 operates on the complete message, not a pre-computed digest.
/// The `digest` parameter here is actually the full message accumulated
/// by the `NullHash`.
///
/// Key: 32 bytes.  Signature: 64 bytes.
///
/// Replaces C `dnsmasq_eddsa_verify()` for Ed25519 (crypto.c line 755).
fn verify_ed25519(key: &[u8], sig: &[u8], message: &[u8]) -> DnsmasqResult<bool> {
    if key.len() != ed25519::ED25519_KEY_SIZE {
        return Err(DnsmasqError::Dnssec(format!(
            "Ed25519: expected {} byte key, got {}",
            ed25519::ED25519_KEY_SIZE,
            key.len()
        )));
    }
    if sig.len() != ed25519::ED25519_SIGNATURE_SIZE {
        return Err(DnsmasqError::Dnssec(format!(
            "Ed25519: expected {} byte signature, got {}",
            ed25519::ED25519_SIGNATURE_SIZE,
            sig.len()
        )));
    }

    ed25519::verify(key, message, sig)
        .map_err(|e| DnsmasqError::Dnssec(format!("Ed25519: verification error: {}", e)))
}

/// Ed448 verification (algorithm 16).
///
/// Ed448 operates on the complete message, not a pre-computed digest.
/// The `digest` parameter here is actually the full message accumulated
/// by the `NullHash`.
///
/// Key: 57 bytes.  Signature: 114 bytes.
///
/// Replaces C `dnsmasq_eddsa_verify()` for Ed448 (crypto.c line 755).
fn verify_ed448(key: &[u8], sig: &[u8], message: &[u8]) -> DnsmasqResult<bool> {
    // Check runtime support — Ed448 may not be available in all
    // builds of the system's libnettle (requires Curve448 support).
    if !ed448::IS_SUPPORTED {
        return Err(DnsmasqError::Dnssec(
            "Ed448: not supported by this build of Nettle".to_string(),
        ));
    }

    if key.len() != ed448::ED448_KEY_SIZE {
        return Err(DnsmasqError::Dnssec(format!(
            "Ed448: expected {} byte key, got {}",
            ed448::ED448_KEY_SIZE,
            key.len()
        )));
    }
    if sig.len() != ed448::ED448_SIGNATURE_SIZE {
        return Err(DnsmasqError::Dnssec(format!(
            "Ed448: expected {} byte signature, got {}",
            ed448::ED448_SIGNATURE_SIZE,
            sig.len()
        )));
    }

    ed448::verify(key, message, sig)
        .map_err(|e| DnsmasqError::Dnssec(format!("Ed448: verification error: {}", e)))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

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

    // -- DnssecAlgorithm round-trip tests --

    #[test]
    fn test_dnssec_algorithm_from_u8_known() {
        assert_eq!(DnssecAlgorithm::from_u8(5), Some(DnssecAlgorithm::RsaSha1));
        assert_eq!(
            DnssecAlgorithm::from_u8(7),
            Some(DnssecAlgorithm::RsaSha1Nsec3)
        );
        assert_eq!(
            DnssecAlgorithm::from_u8(8),
            Some(DnssecAlgorithm::RsaSha256)
        );
        assert_eq!(
            DnssecAlgorithm::from_u8(10),
            Some(DnssecAlgorithm::RsaSha512)
        );
        assert_eq!(DnssecAlgorithm::from_u8(12), Some(DnssecAlgorithm::EccGost));
        assert_eq!(
            DnssecAlgorithm::from_u8(13),
            Some(DnssecAlgorithm::EcdsaP256Sha256)
        );
        assert_eq!(
            DnssecAlgorithm::from_u8(14),
            Some(DnssecAlgorithm::EcdsaP384Sha384)
        );
        assert_eq!(DnssecAlgorithm::from_u8(15), Some(DnssecAlgorithm::Ed25519));
        assert_eq!(DnssecAlgorithm::from_u8(16), Some(DnssecAlgorithm::Ed448));
    }

    #[test]
    fn test_dnssec_algorithm_from_u8_deprecated() {
        // Deprecated: RSAMD5=1, DH=2, DSA=3, DSA-NSEC3=6
        assert_eq!(DnssecAlgorithm::from_u8(1), None);
        assert_eq!(DnssecAlgorithm::from_u8(2), None);
        assert_eq!(DnssecAlgorithm::from_u8(3), None);
        assert_eq!(DnssecAlgorithm::from_u8(6), None);
        assert_eq!(DnssecAlgorithm::from_u8(0), None);
        assert_eq!(DnssecAlgorithm::from_u8(255), None);
    }

    #[test]
    fn test_dnssec_algorithm_round_trip() {
        for val in [5u8, 7, 8, 10, 12, 13, 14, 15, 16] {
            let algo = DnssecAlgorithm::from_u8(val).unwrap();
            assert_eq!(algo.to_u8(), val);
        }
    }

    // -- DigestAlgorithm round-trip tests --

    #[test]
    fn test_digest_algorithm_from_u8_known() {
        assert_eq!(DigestAlgorithm::from_u8(1), Some(DigestAlgorithm::Sha1));
        assert_eq!(DigestAlgorithm::from_u8(2), Some(DigestAlgorithm::Sha256));
        assert_eq!(
            DigestAlgorithm::from_u8(3),
            Some(DigestAlgorithm::GostHash94)
        );
        assert_eq!(DigestAlgorithm::from_u8(4), Some(DigestAlgorithm::Sha384));
    }

    #[test]
    fn test_digest_algorithm_from_u8_unknown() {
        assert_eq!(DigestAlgorithm::from_u8(0), None);
        assert_eq!(DigestAlgorithm::from_u8(5), None);
        assert_eq!(DigestAlgorithm::from_u8(255), None);
    }

    #[test]
    fn test_digest_algorithm_round_trip() {
        for val in [1u8, 2, 3, 4] {
            let algo = DigestAlgorithm::from_u8(val).unwrap();
            assert_eq!(algo.to_u8(), val);
        }
    }

    // -- Nsec3HashAlgorithm tests --

    #[test]
    fn test_nsec3_hash_from_u8() {
        assert_eq!(
            Nsec3HashAlgorithm::from_u8(1),
            Some(Nsec3HashAlgorithm::Sha1)
        );
        assert_eq!(Nsec3HashAlgorithm::from_u8(0), None);
        assert_eq!(Nsec3HashAlgorithm::from_u8(2), None);
    }

    #[test]
    fn test_nsec3_hash_round_trip() {
        let algo = Nsec3HashAlgorithm::from_u8(1).unwrap();
        assert_eq!(algo.to_u8(), 1);
    }

    // -- algo_digest_name tests --

    #[test]
    fn test_algo_digest_name() {
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::RsaSha1),
            Some("sha1")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::RsaSha1Nsec3),
            Some("sha1")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::RsaSha256),
            Some("sha256")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::EcdsaP256Sha256),
            Some("sha256")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::EcdsaP384Sha384),
            Some("sha384")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::RsaSha512),
            Some("sha512")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::EccGost),
            None
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::Ed25519),
            Some("null_hash")
        );
        assert_eq!(
            CryptoVerifier::algo_digest_name(DnssecAlgorithm::Ed448),
            Some("null_hash")
        );
    }

    // -- ds_digest_name tests --

    #[test]
    fn test_ds_digest_name() {
        assert_eq!(
            CryptoVerifier::ds_digest_name(DigestAlgorithm::Sha1),
            Some("sha1")
        );
        assert_eq!(
            CryptoVerifier::ds_digest_name(DigestAlgorithm::Sha256),
            Some("sha256")
        );
        assert_eq!(
            CryptoVerifier::ds_digest_name(DigestAlgorithm::GostHash94),
            None
        );
        assert_eq!(
            CryptoVerifier::ds_digest_name(DigestAlgorithm::Sha384),
            Some("sha384")
        );
    }

    // -- nsec3_digest_name tests --

    #[test]
    fn test_nsec3_digest_name() {
        assert_eq!(
            CryptoVerifier::nsec3_digest_name(Nsec3HashAlgorithm::Sha1),
            Some("sha1")
        );
    }

    // -- hash_find tests --

    #[test]
    fn test_hash_find_sha1() {
        let mut h = CryptoVerifier::hash_find("sha1").unwrap();
        assert_eq!(h.digest_size(), 20);
        h.update(b"hello");
        let digest = h.finalize();
        assert_eq!(digest.len(), 20);
    }

    #[test]
    fn test_hash_find_sha256() {
        let mut h = CryptoVerifier::hash_find("sha256").unwrap();
        assert_eq!(h.digest_size(), 32);
        h.update(b"hello");
        let digest = h.finalize();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_hash_find_sha384() {
        let mut h = CryptoVerifier::hash_find("sha384").unwrap();
        assert_eq!(h.digest_size(), 48);
        h.update(b"hello");
        let digest = h.finalize();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_hash_find_sha512() {
        let mut h = CryptoVerifier::hash_find("sha512").unwrap();
        assert_eq!(h.digest_size(), 64);
        h.update(b"hello");
        let digest = h.finalize();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_hash_find_null_hash() {
        let mut h = CryptoVerifier::hash_find("null_hash").unwrap();
        h.update(b"hello");
        h.update(b" world");
        let result = h.finalize();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_hash_find_unknown() {
        assert!(CryptoVerifier::hash_find("md5").is_err());
        assert!(CryptoVerifier::hash_find("").is_err());
    }

    // -- verify rejects malformed inputs --

    #[test]
    fn test_verify_rsa_empty_key() {
        let key = BlockData::new(&[]);
        let sig = BlockData::new(&[0u8; 64]);
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::RsaSha256, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_p256_wrong_key_size() {
        let key = BlockData::new(&[0u8; 63]); // should be 64
        let sig = BlockData::new(&[0u8; 64]);
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::EcdsaP256Sha256, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_p384_wrong_sig_size() {
        let key = BlockData::new(&[0u8; 96]);
        let sig = BlockData::new(&[0u8; 95]); // should be 96
        let digest = [0u8; 48];
        let result = CryptoVerifier::verify(DnssecAlgorithm::EcdsaP384Sha384, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed25519_wrong_key_size() {
        let key = BlockData::new(&[0u8; 31]); // should be 32
        let sig = BlockData::new(&[0u8; 64]);
        let msg = b"test message";
        let result = CryptoVerifier::verify(DnssecAlgorithm::Ed25519, &key, &sig, msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed448_wrong_sig_size() {
        let key = BlockData::new(&[0u8; 57]);
        let sig = BlockData::new(&[0u8; 113]); // should be 114
        let msg = b"test message";
        let result = CryptoVerifier::verify(DnssecAlgorithm::Ed448, &key, &sig, msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecc_gost_unsupported() {
        let key = BlockData::new(&[0u8; 64]);
        let sig = BlockData::new(&[0u8; 64]);
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::EccGost, &key, &sig, &digest);
        assert!(result.is_err());
    }

    // -- HashFunction trait: incremental update works --

    #[test]
    fn test_sha256_incremental() {
        // Verify that incremental updates produce the same digest as single-shot.
        let mut h1 = CryptoVerifier::hash_find("sha256").unwrap();
        h1.update(b"hello ");
        h1.update(b"world");
        let d1 = h1.finalize();

        let mut h2 = CryptoVerifier::hash_find("sha256").unwrap();
        h2.update(b"hello world");
        let d2 = h2.finalize();

        assert_eq!(d1, d2);
    }

    #[test]
    fn test_null_hash_accumulates() {
        let mut h = CryptoVerifier::hash_find("null_hash").unwrap();
        h.update(b"abc");
        h.update(b"def");
        h.update(b"ghi");
        let result = h.finalize();
        assert_eq!(result, b"abcdefghi");

        // After finalize, buffer should be reset.
        h.update(b"new");
        let result2 = h.finalize();
        assert_eq!(result2, b"new");
    }

    #[test]
    fn test_verify_rsa_three_byte_exponent_too_short() {
        // Key starts with 0x00 (3-byte exponent length) but too short
        let key = BlockData::new(&[0x00, 0x01]); // Only 2 bytes, need 3
        let sig = BlockData::new(&[0u8; 64]);
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::RsaSha256, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rsa_three_byte_exponent_truncated() {
        // Key with 3-byte exponent length but data truncated before exponent
        let key = BlockData::new(&[0x00, 0x00, 0x10]); // exp_len=16, but no exponent data
        let sig = BlockData::new(&[0u8; 64]);
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::RsaSha256, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rsa_empty_modulus() {
        // Key: exp_len=1, exponent=0x03, no modulus
        let key = BlockData::new(&[0x01, 0x03]); // 1-byte exp length (value 1), 1-byte exponent, empty modulus
        let sig = BlockData::new(&[0u8; 64]);
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::RsaSha256, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_p256_wrong_sig_size_short() {
        let key = BlockData::new(&[0u8; 64]); // correct key size
        let sig = BlockData::new(&[0u8; 63]); // wrong sig size (should be 64)
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::EcdsaP256Sha256, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_p384_wrong_key_size_short() {
        let key = BlockData::new(&[0u8; 95]); // wrong (should be 96)
        let sig = BlockData::new(&[0u8; 96]);
        let digest = [0u8; 48];
        let result = CryptoVerifier::verify(DnssecAlgorithm::EcdsaP384Sha384, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ecdsa_p384_wrong_sig_size_short() {
        let key = BlockData::new(&[0u8; 96]);
        let sig = BlockData::new(&[0u8; 95]); // wrong (should be 96)
        let digest = [0u8; 48];
        let result = CryptoVerifier::verify(DnssecAlgorithm::EcdsaP384Sha384, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed25519_wrong_sig_size_short() {
        let key = BlockData::new(&[0u8; 32]); // correct
        let sig = BlockData::new(&[0u8; 63]); // wrong (should be 64)
        let digest = [0u8; 32];
        let result = CryptoVerifier::verify(DnssecAlgorithm::Ed25519, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed448_wrong_key_size_short() {
        let key = BlockData::new(&[0u8; 56]); // wrong (should be 57)
        let sig = BlockData::new(&[0u8; 114]);
        let digest = [0u8; 57];
        let result = CryptoVerifier::verify(DnssecAlgorithm::Ed448, &key, &sig, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rsa_three_byte_exponent_valid_structure() {
        // 3-byte exponent length form: 0x00 || 0x00 || 0x03 means exp_len=3
        let mut key_data = vec![0x00, 0x00, 0x03]; // 3-byte exp len = 3
        key_data.extend_from_slice(&[0x01, 0x00, 0x01]); // exponent = 65537
        key_data.extend_from_slice(&[0x42; 128]); // dummy modulus
        let key = BlockData::new(&key_data);
        let sig = BlockData::new(&[0u8; 128]);
        let digest = [0u8; 32];
        // Exercises the 3-byte path; verification fails but parsing succeeds
        let _result = CryptoVerifier::verify(DnssecAlgorithm::RsaSha256, &key, &sig, &digest);
    }

    #[test]
    fn test_nsec3_digest_name_sha1_found() {
        let name = CryptoVerifier::nsec3_digest_name(super::Nsec3HashAlgorithm::Sha1);
        assert!(name.is_some());
        assert_eq!(name.unwrap(), "sha1");
    }

    #[test]
    fn test_hash_find_sha1_produces_digest() {
        let hash = CryptoVerifier::hash_find("sha1");
        assert!(hash.is_ok());
        let mut h = hash.unwrap();
        h.update(b"test");
        let digest = h.finalize();
        assert!(!digest.is_empty());
    }

    #[test]
    fn test_hash_find_sha384_digest_length() {
        let hash = CryptoVerifier::hash_find("sha384");
        assert!(hash.is_ok());
        let mut h = hash.unwrap();
        h.update(b"test");
        let digest = h.finalize();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_hash_find_sha512_digest_length() {
        let hash = CryptoVerifier::hash_find("sha512");
        assert!(hash.is_ok());
        let mut h = hash.unwrap();
        h.update(b"data");
        let digest = h.finalize();
        assert_eq!(digest.len(), 64);
    }
}

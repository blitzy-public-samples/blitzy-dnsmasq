//! # DNSSEC Validation Module
//!
//! Feature-gated DNSSEC subsystem providing cryptographic trust chain
//! validation and denial-of-existence proofs for DNS responses per
//! RFC 4033/4034/4035 and RFC 5155.
//!
//! This module replaces `src/dnssec.c` (4009 lines) and `src/crypto.c`
//! (1295 lines) from the C dnsmasq codebase with safe Rust implementations.
//!
//! ## Submodules
//!
//! - **`crypto`** — Cryptographic signature verification using the `ring` crate:
//!   RSA (algos 5/7/8/10), ECDSA P-256/P-384 (algos 13/14), Ed25519 (algo 15).
//!
//! - **`validation`** — Trust chain validation: RRSIG verification, DS chain-of-trust
//!   traversal, NSEC/NSEC3 denial-of-existence proofs. (Declared when created.)

pub mod crypto;

// Re-export crypto public API for convenient access
pub use crypto::{
    algo_digest_name, compute_ds_digest, compute_nsec3_hash, ds_digest_name, hash_find, hash_init,
    nsec3_digest_name, verify, CryptoError, HashContext, HashFunction,
};

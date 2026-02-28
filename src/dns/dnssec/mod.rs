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
pub mod validation;

// Re-export crypto public API for convenient access
pub use crypto::{
    algo_digest_name, compute_ds_digest, compute_nsec3_hash, ds_digest_name, hash_find, hash_init,
    nsec3_digest_name, verify, CryptoError, HashContext, HashFunction,
};

// Re-export validation public API
pub use validation::{
    DnssecError, DnssecStatus, DnssecValidator,
    dnssec_validate_reply, dnssec_validate_by_ds, dnssec_validate_ds,
    dnssec_generate_query, dnskey_keytag, errflags_to_ede, setup_timestamp,
    prove_non_existence, hostname_cmp, validate_rrset,
    STAT_SECURE, STAT_INSECURE, STAT_BOGUS, STAT_NEED_KEY, STAT_NEED_DS,
    STAT_ABANDONED, STAT_SECURE_WILDCARD, STAT_OK,
    DNSSEC_FAIL_NOSIG, DNSSEC_FAIL_NYV, DNSSEC_FAIL_EXP, DNSSEC_FAIL_NOKEYSUP,
    DNSSEC_FAIL_WORK, DNSSEC_FAIL_NSEC3_ITERS,
    DNSSEC_LIMIT_WORK, DNSSEC_LIMIT_SIG_FAIL, DNSSEC_LIMIT_CRYPTO, DNSSEC_LIMIT_NSEC3_ITERS,
    DNSSEC_FAIL_NOZONE, DNSSEC_FAIL_NOKEY, DNSSEC_FAIL_NODSSUP, DNSSEC_FAIL_NONSEC,
    DNSSEC_FAIL_INDET, DNSSEC_FAIL_BADPACKET,
    EDE_UNSET, EDE_SIG_NYV, EDE_SIG_EXP, EDE_USUPDNSKEY, EDE_NO_ZONEKEY,
    EDE_NO_DNSKEY, EDE_USUPDS, EDE_UNS_NS3_ITER, EDE_NO_NSEC, EDE_DNSSEC_IND, EDE_NO_RRSIG,
};

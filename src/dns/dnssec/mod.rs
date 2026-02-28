//! # DNSSEC Validation Module
//!
//! Feature-gated DNSSEC subsystem (`#[cfg(feature = "dnssec")]`) providing
//! cryptographic trust chain validation and denial-of-existence proofs for DNS
//! responses per RFC 4033/4034/4035 and RFC 5155.
//!
//! ## Architecture
//!
//! This module replaces `src/dnssec.c` (4009 lines) and `src/crypto.c` (1295 lines)
//! from the C dnsmasq codebase with safe Rust implementations.
//!
//! - **`validation`** — Trust chain validation: RRSIG verification, DS chain-of-trust
//!   traversal, NSEC/NSEC3 denial-of-existence proofs, zone status determination,
//!   and the main `dnssec_validate_reply()` orchestrator.
//!
//! - **`crypto`** — Cryptographic signature verification using the `ring` crate:
//!   RSA (algos 5/7/8/10), ECDSA P-256/P-384 (algos 13/14), Ed25519 (algo 15).
//!   Replaces the Nettle library dependency from the C codebase.
//!
//! ## Key Transformations from C
//!
//! | C Pattern | Rust Replacement |
//! |-----------|-----------------|
//! | Nettle crypto library | `ring` crate |
//! | `blockdata` chain pool | `Vec<u8>` |
//! | C global state in `struct daemon` | `DnssecValidator` struct |
//! | `setjmp`/`longjmp` error recovery | `Result<DnssecStatus, DnssecError>` |
//! | Intrusive linked lists | `Vec`, `HashMap` |
//! | `HAVE_DNSSEC` preprocessor guard | `#[cfg(feature = "dnssec")]` |
//!
//! ## Resource Limits
//!
//! Preserved exactly from the C implementation to prevent DoS attacks:
//! - `DNSSEC_LIMIT_WORK` = 40 (max validation queries per response)
//! - `DNSSEC_LIMIT_SIG_FAIL` = 20 (max signature verification failures)
//! - `DNSSEC_LIMIT_CRYPTO` = 200 (max cryptographic operations)
//! - `DNSSEC_LIMIT_NSEC3_ITERS` = 150 (max NSEC3 hash iterations)
//!
//! ## Supported Algorithms
//!
//! | Algo | Name | Signature | Digest | Status |
//! |------|------|-----------|--------|--------|
//! | 5 | RSA/SHA-1 | RSA | SHA-1 | Supported |
//! | 7 | RSASHA1-NSEC3 | RSA | SHA-1 | Supported |
//! | 8 | RSA/SHA-256 | RSA | SHA-256 | Supported |
//! | 10 | RSA/SHA-512 | RSA | SHA-512 | Supported |
//! | 13 | ECDSAP256SHA256 | ECDSA P-256 | SHA-256 | Supported |
//! | 14 | ECDSAP384SHA384 | ECDSA P-384 | SHA-384 | Supported |
//! | 15 | Ed25519 | EdDSA | — | Supported |
//! | 16 | Ed448 | EdDSA | — | Not supported (ring limitation) |
//! | 12 | ECC-GOST | GOST | GOST hash | Not supported (ring limitation) |
//!
//! ## RFC Compliance
//!
//! - RFC 4033: DNS Security Introduction and Requirements
//! - RFC 4034: Resource Records for DNSSEC
//! - RFC 4035: Protocol Modifications for DNSSEC
//! - RFC 5155: NSEC3 Hashed Authenticated Denial of Existence
//! - RFC 1982: Serial Number Arithmetic
//! - RFC 8914: Extended DNS Errors
//! - RFC 3110: RSA Key Format
//! - RFC 6944: DNSKEY Algorithm Implementation Status (RSA/MD5 deprecated)
//! - RFC 8624: DNSSEC Algorithm Recommendations (DSA deprecated)
//!
//! ## Usage
//!
//! This module is conditionally compiled behind the `dnssec` Cargo feature flag.
//! The parent `dns/mod.rs` applies the feature gate:
//!
//! ```rust,ignore
//! #[cfg(feature = "dnssec")]
//! pub mod dnssec;
//! ```
//!
//! Consumers access DNSSEC functionality via convenient re-exports:
//!
//! ```rust,ignore
//! use crate::dns::dnssec::{
//!     dnssec_validate_reply, DnssecStatus, DnssecValidator,
//!     STAT_SECURE, STAT_BOGUS,
//! };
//! ```

// ---------------------------------------------------------------------------
// Submodule Declarations
// ---------------------------------------------------------------------------

/// DNSSEC trust chain validation submodule.
///
/// Provides the complete DNSSEC validation pipeline including RRSIG signature
/// verification against DNSKEY records, DS chain-of-trust traversal from target
/// domain to root trust anchors, NSEC/NSEC3 denial-of-existence proofs, and
/// resource limit enforcement to prevent validation-based DoS attacks.
///
/// Derived from `src/dnssec.c` (4009 lines of C).
pub mod validation;

/// DNSSEC cryptographic verification submodule.
///
/// Provides ring-based cryptographic operations for DNSSEC signature
/// verification: RSA (algos 5/7/8/10), ECDSA P-256/P-384 (algos 13/14),
/// Ed25519 (algo 15). Includes hash algorithm dispatch, DS digest computation,
/// and NSEC3 hash computation.
///
/// Derived from `src/crypto.c` (1295 lines of C), replacing the Nettle
/// library dependency with the `ring` crate.
pub mod crypto;

// ---------------------------------------------------------------------------
// Re-exports: Core Validation Types
// ---------------------------------------------------------------------------

/// Re-export core validation types for convenient access by consumers
/// (especially `dns::forward` and `dns::cache`).
pub use validation::{
    DnssecError,
    DnssecStatus,
    DnssecValidator,
};

// ---------------------------------------------------------------------------
// Re-exports: Validation Functions
// ---------------------------------------------------------------------------

/// Re-export validation functions used by the DNS forwarding engine
/// and cache management subsystems.
pub use validation::{
    dnssec_validate_reply,
    dnssec_validate_by_ds,
    dnssec_validate_ds,
    dnssec_generate_query,
    dnskey_keytag,
    errflags_to_ede,
    setup_timestamp,
    prove_non_existence,
};

// ---------------------------------------------------------------------------
// Re-exports: Cryptographic Types
// ---------------------------------------------------------------------------

/// Re-export cryptographic types for consumers needing direct hash or
/// signature verification operations.
pub use crypto::{
    CryptoError,
    HashFunction,
    HashContext,
};

// ---------------------------------------------------------------------------
// Re-exports: Cryptographic Functions
// ---------------------------------------------------------------------------

/// Re-export crypto functions for DNSSEC algorithm dispatch, hash operations,
/// and signature verification.
pub use crypto::{
    verify,
    hash_find,
    hash_init,
    algo_digest_name,
    ds_digest_name,
    nsec3_digest_name,
    compute_ds_digest,
    compute_nsec3_hash,
};

// ---------------------------------------------------------------------------
// Re-exports: DNSSEC Status Code Constants
// ---------------------------------------------------------------------------

/// Re-export DNSSEC validation status codes used throughout the forwarding
/// engine for determining validation outcomes and triggering key/DS fetches.
pub use validation::{
    STAT_SECURE,
    STAT_INSECURE,
    STAT_BOGUS,
    STAT_NEED_KEY,
    STAT_NEED_DS,
    STAT_ABANDONED,
};

// ---------------------------------------------------------------------------
// Re-exports: Resource Limit Constants
// ---------------------------------------------------------------------------

/// Re-export resource limit constants that bound computational effort during
/// DNSSEC validation to prevent denial-of-service attacks.
pub use validation::{
    DNSSEC_LIMIT_WORK,
    DNSSEC_LIMIT_SIG_FAIL,
    DNSSEC_LIMIT_CRYPTO,
    DNSSEC_LIMIT_NSEC3_ITERS,
};

// ---------------------------------------------------------------------------
// Re-exports: DNSSEC Failure Flag Constants
// ---------------------------------------------------------------------------

/// Re-export DNSSEC failure flag bitfield constants used to communicate
/// specific validation failure reasons in the status return value.
pub use validation::{
    DNSSEC_FAIL_NOSIG,
    DNSSEC_FAIL_NYV,
    DNSSEC_FAIL_EXP,
    DNSSEC_FAIL_NOKEYSUP,
    DNSSEC_FAIL_NOZONE,
    DNSSEC_FAIL_NOKEY,
    DNSSEC_FAIL_NODSSUP,
    DNSSEC_FAIL_NONSEC,
    DNSSEC_FAIL_INDET,
    DNSSEC_FAIL_BADPACKET,
    DNSSEC_FAIL_WORK,
    DNSSEC_FAIL_NSEC3_ITERS,
};

// ---------------------------------------------------------------------------
// Re-exports: Extended DNS Error (EDE) Code Constants
// ---------------------------------------------------------------------------

/// Re-export Extended DNS Error codes (RFC 8914) used in EDNS0 OPT records
/// to communicate detailed DNSSEC validation failure information to clients.
pub use validation::{
    EDE_UNSET,
    EDE_SIG_NYV,
    EDE_SIG_EXP,
    EDE_USUPDNSKEY,
    EDE_NO_ZONEKEY,
    EDE_NO_DNSKEY,
    EDE_USUPDS,
    EDE_UNS_NS3_ITER,
    EDE_NO_NSEC,
    EDE_DNSSEC_IND,
    EDE_NO_RRSIG,
};

//! Debug and diagnostic utilities for dnsmasq.
//!
//! This module provides packet capture and diagnostic tools used during
//! development and troubleshooting. All functionality in this module is
//! gated behind the `dump` Cargo feature flag (replacing C's `HAVE_DUMPFILE`
//! compile-time guard).
//!
//! # Modules
//!
//! - [`dump`] — Pcap packet capture for protocol analysis with Wireshark/tcpdump
//!
//! # Feature Gates
//!
//! This entire module is only compiled when the `dump` feature is enabled in
//! `Cargo.toml`. The parent `lib.rs` declares:
//! ```rust,ignore
//! #[cfg(feature = "dump")]
//! pub mod debug;
//! ```

pub mod dump;

// Re-export commonly used types for ergonomic access.
// Allows `use crate::debug::{PacketDumper, DumpMask};` instead of
// `use crate::debug::dump::{PacketDumper, DumpMask};`.
pub use dump::{DumpMask, PacketDumper};

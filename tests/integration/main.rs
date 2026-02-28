//! Integration test harness for the dnsmasq Rust rewrite.
//!
//! This file serves as the entry point for the `tests/integration/` multi-file
//! integration test crate. Each submodule corresponds to a test suite for a
//! specific subsystem. Rust discovers this file as a test binary because it is
//! located at `tests/integration/main.rs` (the `integration` directory name
//! becomes the test binary name).
//!
//! # Submodules
//! - `wire_format` — DNS wire-format encoding/decoding roundtrip tests
//! - `dns_forwarding` — end-to-end DNS query forwarding tests

mod config_parsing;
mod dns_cache;
mod dns_forwarding;
mod wire_format;

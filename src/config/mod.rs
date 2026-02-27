//! Configuration parsing, constants, and feature flag management for dnsmasq.
//!
//! This module replaces the C codebase's `src/option.c` (configuration parser)
//! and `src/config.h` (compile-time constants and feature flags).
//!
//! # Submodules
//! - [`constants`] — Numeric constants (cache sizes, timeouts, limits, file paths)

pub mod constants;

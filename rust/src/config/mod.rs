// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Configuration Module
//!
//! Implements dnsmasq's configuration system, migrated from `src/config.h` (3,020 lines)
//! and `src/option.c` (8,128 lines). Provides:
//!
//! - Compile-time numeric constants and resource limits ([`constants`])
//! - Cargo feature flag helpers and platform detection ([`features`])
//! - Configuration file parser for 350+ `dnsmasq.conf` directives ([`options`])
//! - CLI argument processing via clap derive API ([`cli`])
//!
//! ## Config Pipeline
//!
//! The configuration system processes input from multiple sources with a defined
//! precedence order, matching the C implementation's `read_opts()` behavior:
//!
//! 1. Parse CLI arguments via [`CliArgs`] (highest precedence)
//! 2. Load configuration file via [`DnsmasqConfig::from_file()`]
//! 3. Merge CLI overrides into config
//! 4. Validate the final merged configuration via [`DnsmasqConfig::validate()`]
//!
//! The [`load_config()`] convenience function orchestrates this full pipeline.
//!
//! ## Configuration Precedence
//!
//! | Priority | Source | Description |
//! |----------|--------|-------------|
//! | 1 (highest) | CLI arguments | `--port 5353`, `-c 1000`, etc. |
//! | 2 | Config file | Directives from `dnsmasq.conf` |
//! | 3 | Included files | `conf-file=` and `conf-dir=` directives |
//! | 4 (lowest) | Compile-time defaults | Constants from [`constants`] module |
//!
//! ## Feature Flags
//!
//! Optional functionality is gated behind Cargo feature flags. See [`features`]
//! for the complete mapping from C `HAVE_*` macros to Cargo features.
//!
//! ## Error Handling
//!
//! Configuration errors are reported via [`ConfigError`], which provides specific
//! error variants for each failure mode. Error messages are formatted to match
//! the C dnsmasq error output for drop-in replacement compatibility (e.g.,
//! "bad address", "unknown option", "conflicting options").
//!
//! ## Example
//!
//! ```no_run
//! use dnsmasq::config::{load_config, DnsmasqConfig, CliArgs, ConfigError};
//!
//! // Full pipeline: CLI args → config file → merge → validate
//! match load_config() {
//!     Ok(config) => {
//!         println!("DNS port: {}", config.dns_port);
//!         println!("Cache size: {}", config.cache_size);
//!     }
//!     Err(e) => eprintln!("Configuration error: {}", e),
//! }
//! ```

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Compile-time numeric constants and resource limits.
///
/// Migrated from `src/config.h` lines 93–828 and `src/dns-protocol.h`.
/// Contains all default values for DNS cache size, forward table size,
/// TCP connection limits, DNSSEC validation limits, DHCP lease defaults,
/// file paths, and platform-specific settings.
pub mod constants;

/// Cargo feature flag detection helpers and platform detection.
///
/// Migrated from `src/config.h` lines 2060–2520.
/// Provides compile-time feature detection functions (`has_dhcp()`,
/// `has_dnssec()`, etc.), platform detection (`is_linux()`, `is_bsd()`),
/// and feature dependency validation.
pub mod features;

/// Configuration file parser for 350+ `dnsmasq.conf` directives.
///
/// Migrated from `src/option.c` (8,128 lines). Implements the INI-style
/// parser supporting `key=value`, `key`, and `server=/domain/ip` syntax.
/// Produces the [`DnsmasqConfig`] struct representing the complete daemon
/// configuration.
pub mod options;

/// CLI argument processing via clap derive API.
///
/// Migrated from the CLI processing section of `src/option.c`.
/// Maps every dnsmasq command-line flag to a [`CliArgs`] struct field
/// for drop-in replacement compatibility.
pub mod cli;

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

/// Primary configuration struct — used throughout the crate.
///
/// Re-exported from [`options::DnsmasqConfig`] for convenient access as
/// `crate::config::DnsmasqConfig`.
pub use options::DnsmasqConfig;

/// CLI argument struct — used by `main.rs` for command-line parsing.
///
/// Re-exported from [`cli::CliArgs`] for convenient access as
/// `crate::config::CliArgs`.
pub use cli::CliArgs;

/// Re-export all compile-time constants for convenient access.
///
/// Allows importing constants directly: `use crate::config::CACHESIZ;`
/// instead of `use crate::config::constants::CACHESIZ;`.
pub use constants::*;

// ---------------------------------------------------------------------------
// Configuration Error Type
// ---------------------------------------------------------------------------

use thiserror::Error;

/// Errors arising from configuration parsing and validation.
///
/// Provides specific error variants for each configuration failure mode,
/// replacing the C `die()` function and `errno`-based error reporting
/// in `src/option.c`. Error messages are formatted to match the C dnsmasq
/// error output for drop-in replacement compatibility.
///
/// # Error Categories
///
/// | Variant | C Equivalent | Trigger |
/// |---------|-------------|---------|
/// | [`IoError`](ConfigError::IoError) | `die(EC_BADCONF, ...)` | Cannot read config file |
/// | [`SyntaxError`](ConfigError::SyntaxError) | `die(EC_BADCONF, ...)` | Malformed directive |
/// | [`UnknownOption`](ConfigError::UnknownOption) | `"unknown option"` | Unrecognized directive |
/// | [`InvalidValue`](ConfigError::InvalidValue) | `"bad value"` | Invalid parameter value |
/// | [`MissingArgument`](ConfigError::MissingArgument) | `"missing argument"` | Required param absent |
/// | [`Conflict`](ConfigError::Conflict) | `"conflicting options"` | Mutually exclusive opts |
/// | [`FeatureDisabled`](ConfigError::FeatureDisabled) | `"not available"` | Feature not compiled in |
/// | [`InvalidAddress`](ConfigError::InvalidAddress) | `"bad address"` | Malformed IP/hostname |
/// | [`InvalidDhcpRange`](ConfigError::InvalidDhcpRange) | `"bad dhcp-range"` | Invalid DHCP range |
/// | [`ValidationError`](ConfigError::ValidationError) | various | Post-parse validation |
///
/// # Example
///
/// ```
/// use dnsmasq::config::ConfigError;
///
/// let err = ConfigError::UnknownOption {
///     option: "bad-option".to_string(),
///     file: "/etc/dnsmasq.conf".to_string(),
///     line: 42,
/// };
/// assert!(err.to_string().contains("unknown option"));
/// ```
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O error reading configuration file.
    ///
    /// Raised when the configuration file cannot be opened, read, or accessed
    /// due to filesystem-level errors (permission denied, file not found, etc.).
    /// Wraps the underlying [`std::io::Error`] with the file path for diagnostics.
    #[error("failed to read configuration file '{path}': {source}")]
    IoError {
        /// Path to the configuration file that could not be read.
        path: String,
        /// Underlying I/O error from the standard library.
        source: std::io::Error,
    },

    /// Syntax error in configuration file.
    ///
    /// Raised when a configuration directive is syntactically malformed —
    /// for example, an unterminated quote, invalid escape sequence, or
    /// malformed `key=value` pair.
    #[error("syntax error at {file}:{line}: {message}")]
    SyntaxError {
        /// Configuration file containing the error.
        file: String,
        /// Line number where the error was detected (1-based).
        line: usize,
        /// Human-readable description of the syntax error.
        message: String,
    },

    /// Unknown configuration directive.
    ///
    /// Raised when a configuration key does not match any of the 350+
    /// recognized dnsmasq directives. Matches C's `"unknown option"` error.
    #[error("unknown option '{option}' at {file}:{line}")]
    UnknownOption {
        /// The unrecognized option name.
        option: String,
        /// Configuration file containing the unknown option.
        file: String,
        /// Line number where the unknown option was found (1-based).
        line: usize,
    },

    /// Invalid argument value for a known directive.
    ///
    /// Raised when a configuration directive is recognized but its value
    /// cannot be parsed (e.g., non-numeric cache size, out-of-range port).
    /// Matches C's `"bad value"` error messages.
    #[error("bad value '{value}' for option '{option}': {reason}")]
    InvalidValue {
        /// The option name with the invalid value.
        option: String,
        /// The value that was rejected.
        value: String,
        /// Explanation of why the value is invalid.
        reason: String,
    },

    /// Missing required argument for a directive.
    ///
    /// Raised when a directive that requires a value is specified without one.
    /// For example, `cache-size=` with no number following the `=`.
    #[error("option '{option}' requires an argument at {file}:{line}")]
    MissingArgument {
        /// The option missing its required argument.
        option: String,
        /// Configuration file where the error occurred.
        file: String,
        /// Line number of the incomplete directive (1-based).
        line: usize,
    },

    /// Conflicting configuration options.
    ///
    /// Raised when two or more configuration directives are mutually exclusive
    /// or create an inconsistent configuration state. For example, specifying
    /// both `--bind-interfaces` and `--bind-dynamic` simultaneously.
    #[error("conflicting options: {message}")]
    Conflict {
        /// Description of the conflicting options.
        message: String,
    },

    /// Feature not available due to compile-time feature flag.
    ///
    /// Raised when a configuration directive requires a Cargo feature that
    /// was not enabled at compile time. For example, using `dnssec` options
    /// without the `dnssec` feature flag. Matches C's `"not available"`
    /// errors from `#ifdef HAVE_*` guarded code paths.
    #[error("option '{option}' requires feature '{feature}' which is not enabled")]
    FeatureDisabled {
        /// The option that requires the missing feature.
        option: String,
        /// The Cargo feature flag required (e.g., "dnssec", "dbus").
        feature: String,
    },

    /// Address parsing error.
    ///
    /// Raised when an IP address, hostname, or socket address cannot be parsed
    /// from a configuration value. Matches C's `"bad address"` error messages.
    #[error("bad address '{address}': {reason}")]
    InvalidAddress {
        /// The address string that could not be parsed.
        address: String,
        /// Explanation of the parsing failure.
        reason: String,
    },

    /// DHCP range configuration error.
    ///
    /// Raised when a `dhcp-range` directive contains invalid parameters —
    /// for example, the start address is greater than the end address, or
    /// the netmask is invalid for the given range.
    #[error("invalid DHCP range: {message}")]
    InvalidDhcpRange {
        /// Description of the DHCP range error.
        message: String,
    },

    /// Generic validation failure.
    ///
    /// Raised during the post-parse validation phase when cross-field
    /// constraints are violated. This is the catch-all variant for
    /// validation errors that do not fit a more specific category.
    #[error("configuration validation failed: {message}")]
    ValidationError {
        /// Description of the validation failure.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Config Loading Convenience Function
// ---------------------------------------------------------------------------

/// Load and validate dnsmasq configuration from CLI arguments and config file.
///
/// This is the primary entry point for the configuration system, equivalent to
/// the `read_opts()` function in C `src/option.c`. It orchestrates the complete
/// configuration pipeline:
///
/// 1. Parse command-line arguments via [`CliArgs`]
/// 2. Determine configuration file path (CLI `--conf-file` or default [`CONFFILE`])
/// 3. Parse configuration file(s) recursively (handles `conf-file` and `conf-dir` directives)
/// 4. Merge CLI overrides into parsed configuration
/// 5. Validate the final merged configuration for consistency
///
/// # Returns
///
/// A fully validated [`DnsmasqConfig`] ready for daemon initialization.
///
/// # Errors
///
/// Returns [`ConfigError`] if any step in the pipeline fails:
/// - CLI argument parsing errors → [`ConfigError::InvalidValue`]
/// - Config file I/O errors → [`ConfigError::IoError`]
/// - Syntax or parse errors → [`ConfigError::SyntaxError`]
/// - Validation failures → [`ConfigError::ValidationError`]
///
/// # Example
///
/// ```no_run
/// use dnsmasq::config::load_config;
///
/// let config = load_config().expect("Failed to load configuration");
/// println!("Listening on port {}", config.dns_port);
/// ```
///
/// # Precedence
///
/// Command-line arguments have the highest precedence, followed by configuration
/// file directives (processed in order), followed by compile-time defaults from
/// [`constants`]. This matches the C implementation exactly.
pub fn load_config() -> Result<DnsmasqConfig, ConfigError> {
    // Step 1: Parse CLI arguments.
    // Uses clap's try_parse() for non-panicking error handling.
    // Replaces C's getopt_long() processing in option.c.
    let cli_args = {
        use clap::Parser as _;
        CliArgs::try_parse().map_err(|e| ConfigError::InvalidValue {
            option: String::new(),
            value: String::new(),
            reason: e.to_string(),
        })?
    };

    // Step 2: Determine config file path.
    // CLI --conf-file takes precedence; falls back to compiled-in CONFFILE default.
    // An empty path ("") disables config file loading entirely, matching C behavior
    // where `--conf-file=""` skips file parsing.
    let conf_path = cli_args
        .conf_file
        .first()
        .map(|s| s.as_str())
        .unwrap_or(constants::CONFFILE);

    // Step 3: Parse config file (unless --conf-file="" to disable).
    // DnsmasqConfig::from_file() handles recursive includes (conf-file, conf-dir)
    // with cycle detection and depth limiting, matching C's one_file() behavior.
    // DnsmasqConfig::default() provides compile-time defaults from constants.rs.
    let mut config = if conf_path.is_empty() {
        DnsmasqConfig::default()
    } else {
        DnsmasqConfig::from_file(conf_path).map_err(|e| ConfigError::ValidationError {
            message: e.to_string(),
        })?
    };

    // Step 4: Merge CLI overrides (highest precedence).
    // Boolean CLI flags override config file settings. List-based options
    // (servers, interfaces) accumulate. Single-value options take CLI value.
    config
        .merge_cli_args(&cli_args)
        .map_err(|e| ConfigError::ValidationError {
            message: e.to_string(),
        })?;

    // Step 5: Validate the final merged configuration.
    // Checks cross-field constraints that can only be verified after all
    // sources have been merged (e.g., port range validity, feature gating).
    config
        .validate()
        .map_err(|e| ConfigError::ValidationError {
            message: e.to_string(),
        })?;

    Ok(config)
}

// ---------------------------------------------------------------------------
// Tests
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

    /// Verify all four sub-modules are accessible through the config module.
    #[test]
    fn test_submodule_accessibility() {
        // constants module accessible via re-export
        let _cachesiz = CACHESIZ;
        let _ftabsiz = FTABSIZ;
        let _conffile = CONFFILE;
        let _leasefile = LEASEFILE;
        let _resolvfile = RESOLVFILE;
        let _runfile = RUNFILE;

        // features module accessible
        let _has_dhcp = features::has_dhcp();
        let _has_dnssec = features::has_dnssec();
        let _has_dbus = features::has_dbus();
        let _has_auth = features::has_auth();
        let _is_linux = features::is_linux();
        let _is_bsd = features::is_bsd();
    }

    /// Verify DnsmasqConfig re-export is accessible and default() works.
    #[test]
    fn test_dnsmasq_config_reexport() {
        let config = DnsmasqConfig::default();
        assert_eq!(config.dns_port, 53);
        assert_eq!(config.cache_size, CACHESIZ);
        assert_eq!(config.dns_forward_max, FTABSIZ);
        assert_eq!(config.edns_packet_max, EDNS_PKTSZ);
    }

    /// Verify ConfigError variants can be constructed and display correctly.
    #[test]
    fn test_config_error_io() {
        let err = ConfigError::IoError {
            path: "/etc/dnsmasq.conf".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };
        let msg = err.to_string();
        assert!(msg.contains("failed to read configuration file"));
        assert!(msg.contains("/etc/dnsmasq.conf"));
    }

    #[test]
    fn test_config_error_syntax() {
        let err = ConfigError::SyntaxError {
            file: "/etc/dnsmasq.conf".to_string(),
            line: 42,
            message: "unterminated quote".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("syntax error at /etc/dnsmasq.conf:42"));
        assert!(msg.contains("unterminated quote"));
    }

    #[test]
    fn test_config_error_unknown_option() {
        let err = ConfigError::UnknownOption {
            option: "bad-option".to_string(),
            file: "/etc/dnsmasq.conf".to_string(),
            line: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains("unknown option 'bad-option'"));
        assert!(msg.contains("/etc/dnsmasq.conf:10"));
    }

    #[test]
    fn test_config_error_invalid_value() {
        let err = ConfigError::InvalidValue {
            option: "cache-size".to_string(),
            value: "abc".to_string(),
            reason: "not a number".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad value 'abc'"));
        assert!(msg.contains("cache-size"));
        assert!(msg.contains("not a number"));
    }

    #[test]
    fn test_config_error_missing_argument() {
        let err = ConfigError::MissingArgument {
            option: "server".to_string(),
            file: "dnsmasq.conf".to_string(),
            line: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("requires an argument"));
        assert!(msg.contains("server"));
    }

    #[test]
    fn test_config_error_conflict() {
        let err = ConfigError::Conflict {
            message: "bind-interfaces and bind-dynamic are mutually exclusive".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("conflicting options"));
        assert!(msg.contains("bind-interfaces"));
    }

    #[test]
    fn test_config_error_feature_disabled() {
        let err = ConfigError::FeatureDisabled {
            option: "dnssec".to_string(),
            feature: "dnssec".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("requires feature 'dnssec'"));
        assert!(msg.contains("not enabled"));
    }

    #[test]
    fn test_config_error_invalid_address() {
        let err = ConfigError::InvalidAddress {
            address: "999.999.999.999".to_string(),
            reason: "invalid IPv4 address".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad address"));
        assert!(msg.contains("999.999.999.999"));
    }

    #[test]
    fn test_config_error_invalid_dhcp_range() {
        let err = ConfigError::InvalidDhcpRange {
            message: "start address must precede end address".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid DHCP range"));
        assert!(msg.contains("start address"));
    }

    #[test]
    fn test_config_error_validation() {
        let err = ConfigError::ValidationError {
            message: "min-port exceeds max-port".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("configuration validation failed"));
        assert!(msg.contains("min-port"));
    }

    /// Verify the features module's compile_options_string returns a non-empty string.
    #[test]
    fn test_features_compile_options() {
        let opts = features::compile_options_string();
        // With default features enabled, should contain at least "dhcp"
        assert!(!opts.is_empty());
    }

    /// Verify that feature dependency validation runs without error for default features.
    #[test]
    fn test_features_validate_dependencies() {
        let result = features::validate_feature_dependencies();
        assert!(
            result.is_ok(),
            "Feature dependency validation failed: {:?}",
            result
        );
    }

    /// Verify constants are accessible via the glob re-export.
    #[test]
    fn test_constants_reexport_values() {
        // Verify a representative sample of constants match C config.h values
        assert_eq!(FTABSIZ, 150);
        assert_eq!(CACHESIZ, 150);
        assert_eq!(MAX_PROCS, 20);
        assert_eq!(TIMEOUT, 10);
        assert_eq!(EDNS_PKTSZ, 1232);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(PACKETSZ, 512);
    }

    /// Verify ConfigError implements std::error::Error and Display traits.
    #[test]
    fn test_config_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ConfigError::ValidationError {
            message: "test".to_string(),
        });
        assert!(err.to_string().contains("test"));
    }
}

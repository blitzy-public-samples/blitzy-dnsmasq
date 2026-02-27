// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; version 2 dated June, 1991, or
//   (at your option) version 3 dated 29 June, 2007.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Configuration parsing, constants, and feature flag management for dnsmasq.
//!
//! This module is the Rust replacement for the C codebase's `src/config.h`
//! (compile-time constants and feature flags) and `src/option.c` (the
//! configuration file and command-line parser, the largest single module in
//! the original dnsmasq at ~2,500 lines).
//!
//! # Architecture
//!
//! In the C codebase, every source file includes the monolithic `dnsmasq.h`
//! header, which in turn includes `config.h`. Together these headers export
//! all type definitions, numeric constants, feature flags, and function
//! prototypes into a single flat namespace. The Rust rewrite replaces this
//! pattern with a structured module hierarchy under `crate::config`:
//!
//! ```text
//! crate::config
//! ├── constants       — Compile-time numeric constants, file paths, port numbers
//! ├── feature_flags   — Cargo feature flag integration, platform detection, version reporting
//! └── options         — CLI / config-file parser, DaemonConfig, ConfigBuilder, error types
//! ```
//!
//! # Submodules
//!
//! - [`constants`] — All compile-time numeric constants originally defined as
//!   `#define` macros in `src/config.h`. Includes cache sizes (`CACHESIZ`),
//!   forward table limits (`FTABSIZ`), timeout values (`TIMEOUT`), DNSSEC
//!   validation limits, DHCP lease defaults, TFTP parameters, default file
//!   paths, port numbers, and security defaults. All constants are `pub const`
//!   and glob-reexported at this module level for convenient crate-wide access.
//!
//! - [`feature_flags`] — Cargo feature flag integration that replaces C's
//!   `HAVE_*` / `NO_*` preprocessor macros. Provides the
//!   [`compile_opts_string`] function to reproduce the feature banner printed
//!   by `dnsmasq --version`, compile-time feature dependency validation via
//!   `compile_error!` guards, and helper predicates (`has_dhcp`,
//!   `has_firewall_sets`, `is_linux`, `is_bsd`) and platform detection
//!   constants in the [`feature_flags::platform`] sub-module.
//!
//! - [`options`] — The CLI and configuration file parser for all 160+
//!   dnsmasq directives. This module replaces the C `src/option.c` entirely,
//!   replacing `setjmp`/`longjmp` error recovery with Rust's `Result<T, E>`
//!   error handling. The [`ConfigBuilder`] provides a builder pattern for
//!   constructing a validated [`DaemonConfig`].
//!
//! # Key Types
//!
//! - [`DaemonConfig`] — Complete daemon configuration. This is the Rust
//!   equivalent of the configuration-related fields from the global C
//!   `struct daemon` (which had 100+ members). The struct is decomposed into
//!   domain-specific sub-structs: `dns`, `dhcp`, `tftp`, `dnssec`, `log`,
//!   `auth`, `network`, `security`, and a boolean `options` bitflag set.
//!
//! - [`ConfigError`] — An enum of all errors that can occur during
//!   configuration parsing. Replaces the C `setjmp`/`longjmp` error recovery
//!   mechanism with idiomatic `thiserror`-derived variants: `ParseError`,
//!   `InvalidOption`, `ConflictingOptions`, `IoError`, `UnknownOption`, and
//!   `MissingArgument`.
//!
//! - [`ConfigBuilder`] — Builder for constructing a validated `DaemonConfig`.
//!   Usage: `ConfigBuilder::new().parse_cli(&args).parse_file(path).build()`.
//!   The builder accumulates configuration from multiple sources (CLI
//!   arguments, config files, included files) and validates the result on
//!   `build()`.
//!
//! - [`OptionFlags`] — A bitflag set for boolean configuration options,
//!   canonically defined in [`crate::core::daemon`] and re-exported here for
//!   ergonomic access. Provides `get()`, `set()`, `clear()`, and `new()`
//!   methods for querying and manipulating individual option bits.
//!
//! # Configuration Precedence
//!
//! Configuration values are applied in the following order, with later sources
//! overriding earlier ones:
//!
//! 1. **Compile-time defaults** — Constants from the [`constants`] module
//!    (e.g., `CACHESIZ = 150`, `MAXLEASES = 1000`).
//! 2. **Configuration file** — Directives from `dnsmasq.conf` (default path:
//!    `/etc/dnsmasq.conf`), including any files referenced via `conf-file=`
//!    or `conf-dir=` directives.
//! 3. **Command-line arguments** — CLI flags take highest precedence and
//!    override both defaults and config-file values.
//!
//! # Feature Flag System
//!
//! The C `HAVE_*` preprocessor macros from `config.h` are mapped to Cargo
//! feature flags in `Cargo.toml`:
//!
//! | C Macro | Cargo Feature | Default |
//! |---------|---------------|---------|
//! | `HAVE_DHCP` | `dhcp` | enabled |
//! | `HAVE_DHCP6` | `dhcp6` | enabled |
//! | `HAVE_DNSSEC` | `dnssec` | disabled |
//! | `HAVE_TFTP` | `tftp` | enabled |
//! | `HAVE_SCRIPT` | `script` | enabled |
//! | `HAVE_AUTH` | `auth` | enabled |
//! | `HAVE_IPSET` | `ipset` | enabled |
//! | `HAVE_NFTSET` | `nftset` | disabled |
//! | `HAVE_DBUS` | `dbus` | disabled |
//! | `HAVE_UBUS` | `ubus` | disabled |
//! | `HAVE_CONNTRACK` | `conntrack` | disabled |
//! | `HAVE_LOOP` | `loop_detect` | enabled |
//! | `HAVE_DUMPFILE` | `dump` | enabled |
//! | `HAVE_IDN` | `idn` | disabled |
//!
//! Modules guarded by feature flags use `#[cfg(feature = "...")]` attributes,
//! directly replacing the C `#ifdef HAVE_*` / `#endif` pattern.
//!
//! # Examples
//!
//! ## Basic Configuration Parsing
//!
//! ```rust,no_run
//! use dnsmasq::config::{ConfigBuilder, ConfigError, DaemonConfig};
//!
//! fn load_config() -> Result<DaemonConfig, ConfigError> {
//!     let args: Vec<String> = std::env::args().skip(1).collect();
//!     let mut builder = ConfigBuilder::new();
//!     builder.parse_cli(&args);
//!     builder.parse_file("/etc/dnsmasq.conf", true);
//!     builder.build()
//! }
//! ```
//!
//! ## Accessing Constants
//!
//! ```rust
//! use dnsmasq::config::{CACHESIZ, MAXLEASES, DNS_PORT, TIMEOUT};
//!
//! assert_eq!(CACHESIZ, 150);
//! assert_eq!(MAXLEASES, 1000);
//! assert_eq!(DNS_PORT, 53);
//! assert_eq!(TIMEOUT, 10);
//! ```
//!
//! ## Feature Reporting
//!
//! ```rust
//! use dnsmasq::config::compile_opts_string;
//!
//! let opts = compile_opts_string();
//! assert!(opts.starts_with("IPv6 GNU-getopt"));
//! ```

// ============================================================================
// Submodule declarations
// ============================================================================

/// Compile-time numeric constants, default file paths, and port numbers.
///
/// All constants originally defined as `#define` macros in `src/config.h` and
/// `src/dns-protocol.h` are provided as `pub const` declarations in this
/// submodule. Constants are also glob re-exported at the `config` module level
/// via `pub use constants::*` for convenient crate-wide access.
pub mod constants;

/// Cargo feature flag integration, platform detection, and runtime feature
/// reporting.
///
/// This submodule replaces the C `HAVE_*` / `NO_*` preprocessor macro system
/// with idiomatic Cargo feature flags. It provides:
///
/// - [`feature_flags::compile_opts_string`] — version banner string matching
///   `dnsmasq --version` output format.
/// - [`feature_flags::has_dhcp`], [`feature_flags::has_firewall_sets`] — compound
///   feature detection predicates.
/// - [`feature_flags::is_linux`], [`feature_flags::is_bsd`] — platform detection.
/// - [`feature_flags::platform`] — compile-time boolean constants for platform
///   capabilities.
pub mod feature_flags;

/// CLI and configuration file parser for all 160+ dnsmasq directives.
///
/// This submodule is the Rust replacement for `src/option.c`, the largest
/// module in the C codebase (~2,500 lines). It provides the [`DaemonConfig`]
/// struct (decomposed from the global C `struct daemon`), [`ConfigBuilder`]
/// for validated construction, [`ConfigError`] for error handling, and
/// [`OptionFlags`] for boolean option bitflags.
pub mod options;

// ============================================================================
// Re-exports for ergonomic imports
// ============================================================================

// Re-export primary types from the `options` submodule so consumers can write:
//
//   use crate::config::{DaemonConfig, ConfigError, ConfigBuilder};
//
// instead of the longer:
//
//   use crate::config::options::{DaemonConfig, ConfigError, ConfigBuilder};
//
// OptionFlags is canonically defined in `crate::core::daemon` and imported
// privately by `options`. We re-export it here for convenient access via
// `crate::config::OptionFlags`.
pub use options::{ConfigBuilder, ConfigError, DaemonConfig};

// Re-export OptionFlags from its canonical definition site. The OptionFlags
// type is defined in `crate::core::daemon` using the `bitflags!` macro and
// represents the full set of boolean configuration options (OPT_*). It is
// re-exported here so that modules consuming configuration types can import
// it alongside DaemonConfig:
//
//   use crate::config::{DaemonConfig, OptionFlags};
//
pub use crate::core::daemon::OptionFlags;

// Glob re-export all compile-time constants so they are available directly
// from `crate::config::CONSTANT_NAME` without requiring the intermediate
// `constants::` path segment. This matches the C convention where including
// `config.h` makes all constants available at the top level.
pub use constants::*;

// Re-export the compile_opts_string function from feature_flags for version
// banner generation. This is the Rust equivalent of C's `compile_opts` array
// defined in config.h, used by `dnsmasq --version` to display enabled features.
pub use feature_flags::compile_opts_string;

// ============================================================================
// Module-level tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the three submodules are accessible and the key types are
    /// re-exported correctly.
    #[test]
    fn test_submodule_reexports_accessible() {
        // Verify DaemonConfig is accessible via the re-export.
        let config = DaemonConfig::default();
        // The default DNS cache size must match the constant.
        assert_eq!(config.dns.cache_size, CACHESIZ);
        // The default forward table size must match the constant.
        assert_eq!(config.dns.forward_max, FTABSIZ);
        // The default DNS port must match the constant.
        assert_eq!(config.dns.port, DNS_PORT);
    }

    /// Verify ConfigBuilder can be constructed via the re-export.
    #[test]
    fn test_config_builder_reexport() {
        let builder = ConfigBuilder::new();
        let config = builder.build();
        assert!(config.is_ok(), "ConfigBuilder::new().build() should succeed with defaults");
    }

    /// Verify ConfigError variants are accessible via the re-export.
    #[test]
    fn test_config_error_variants() {
        let err = ConfigError::UnknownOption("--bogus".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("--bogus"), "Error message should contain the option name");

        let err2 = ConfigError::MissingArgument("--port".to_string());
        let msg2 = format!("{}", err2);
        assert!(msg2.contains("--port"), "Error message should contain the option name");
    }

    /// Verify OptionFlags is accessible via the re-export.
    #[test]
    fn test_option_flags_reexport() {
        let mut flags = OptionFlags::new();
        // Verify basic set/get/clear cycle.
        assert!(!flags.get(0), "Fresh OptionFlags should have all bits clear");
        flags.set(0);
        assert!(flags.get(0), "Bit 0 should be set after set(0)");
        flags.clear(0);
        assert!(!flags.get(0), "Bit 0 should be clear after clear(0)");
    }

    /// Verify compile_opts_string is accessible via the re-export and produces
    /// the expected format.
    #[test]
    fn test_compile_opts_string_reexport() {
        let opts = compile_opts_string();
        assert!(
            opts.starts_with("IPv6 GNU-getopt"),
            "compile_opts_string must start with 'IPv6 GNU-getopt', got: {opts}"
        );
        // Must contain at least one feature indicator.
        assert!(
            opts.contains("DHCP") || opts.contains("no-DHCP"),
            "compile_opts_string must report DHCP status, got: {opts}"
        );
    }

    /// Verify that key constants are accessible via the glob re-export.
    #[test]
    fn test_constants_glob_reexport() {
        assert_eq!(CACHESIZ, 150);
        assert_eq!(MAXLEASES, 1000);
        assert_eq!(FTABSIZ, 150);
        assert_eq!(EDNS_PKTSZ, 1232);
        assert_eq!(DNS_PORT, 53);
        assert_eq!(TIMEOUT, 10);
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(PACKETSZ, 512);
        assert_eq!(MAXDNAME, 1025);
        assert_eq!(TCP_MAX_QUERIES, 100);
        assert_eq!(TCP_TIMEOUT, 5);
        assert_eq!(TFTP_MAX_CONNECTIONS, 50);
        assert_eq!(DNSSEC_LIMIT_WORK, 40);
        assert_eq!(DNSSEC_LIMIT_CRYPTO, 200);
    }

    /// Verify that feature_flags submodule functions are accessible.
    #[test]
    fn test_feature_flags_submodule_accessible() {
        // The feature_flags module should be accessible as a submodule.
        let _ = feature_flags::has_dhcp();
        let _ = feature_flags::has_firewall_sets();
        let _ = feature_flags::is_linux();
        let _ = feature_flags::is_bsd();

        // Platform constants should be accessible.
        let _ = feature_flags::platform::LINUX_NETWORK;
        let _ = feature_flags::platform::BSD_NETWORK;
        let _ = feature_flags::platform::SOCKADDR_SA_LEN;
    }

    /// Verify that the options submodule types are accessible both through
    /// the re-export and through the full path.
    #[test]
    fn test_options_submodule_accessible() {
        // LongOption should be accessible through the options submodule
        // (not re-exported at the config level, requires full path).
        let opt = options::LongOption::Reload;
        assert_eq!(opt as u16, 256);
    }

    /// Verify default file paths are accessible.
    #[test]
    fn test_default_paths_accessible() {
        assert!(!HOSTSFILE.is_empty(), "HOSTSFILE must be non-empty");
        assert!(!CONFFILE.is_empty(), "CONFFILE must be non-empty");
        assert!(!LEASEFILE.is_empty(), "LEASEFILE must be non-empty");
        assert!(!RUNFILE.is_empty(), "RUNFILE must be non-empty");
        assert!(!CHUSER.is_empty(), "CHUSER must be non-empty");
        assert!(!CHGRP.is_empty(), "CHGRP must be non-empty");
    }

    /// Verify default timeout and lease constants.
    #[test]
    fn test_default_limits() {
        assert!(DEFLEASE > 0, "Default lease time must be positive");
        assert!(PING_WAIT > 0, "Ping wait must be positive");
    }
}

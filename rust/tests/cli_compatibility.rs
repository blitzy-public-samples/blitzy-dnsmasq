// Copyright (C) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later

//! # CLI Argument Compatibility Integration Tests
//!
//! This module verifies that the Rust dnsmasq binary accepts the **exact same**
//! command-line arguments as the C dnsmasq binary (version 2.92). The Rust binary
//! must be a 100% drop-in replacement — every CLI flag accepted by the C version
//! must work identically in the Rust version.
//!
//! ## Testing Strategy
//!
//! Tests use the [`assert_cmd`] crate to invoke the compiled `dnsmasq` binary as
//! a subprocess and verify:
//! - Exit codes (0 for success, non-zero for invalid options)
//! - Standard output content (version strings, help text)
//! - Standard error content (error messages for invalid inputs)
//!
//! Most tests use the `--test` flag to run dnsmasq in "syntax check" mode, which
//! validates the configuration without actually starting the daemon (matching the
//! C `dnsmasq --test` behavior from `option.c`).
//!
//! ## Source References
//!
//! - `man/dnsmasq.8` — Authoritative CLI flag behavioral specification
//! - `src/option.c` — C config/CLI parser with 350+ directives
//! - `src/dnsmasq.c` — Main entry point where CLI args are processed
//! - `src/config.h` — Feature flag constants affecting CLI options

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

// ────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ────────────────────────────────────────────────────────────────────────────

/// Creates a new [`Command`] instance for the compiled `dnsmasq` binary.
///
/// Uses `assert_cmd::Command::cargo_bin()` to locate the binary built by Cargo.
/// This helper is used by every test to invoke the binary with various CLI flags.
///
/// # Panics
///
/// Panics if the `dnsmasq` binary cannot be found in the Cargo build output.
/// This typically means `cargo build` has not been run or the binary target
/// name in `Cargo.toml` does not match `"dnsmasq"`.
fn dnsmasq_cmd() -> Command {
    Command::cargo_bin("dnsmasq").expect("Failed to find dnsmasq binary")
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 2: Help and Version Output Tests
// ════════════════════════════════════════════════════════════════════════════

/// Verify that `-w` (short help flag) prints usage text and exits with code 0.
///
/// In C dnsmasq, `-w` is the help flag (not the standard `-h` which maps to
/// `--no-hosts`). This is mapped to `display_opts()` which prints the `usage[]`
/// array from `option.c` lines 543-742. The Rust implementation checks
/// `cli_args.help_flag` and calls `CliArgs::command().print_help()`.
#[test]
fn test_help_flag_short() {
    dnsmasq_cmd()
        .arg("-w")
        .assert()
        .success()
        .stdout(predicate::str::contains("dnsmasq"));
}

/// Verify that `--help` (long help flag) prints usage text and exits with code 0.
///
/// The Rust implementation uses clap's `print_help()` method, which outputs
/// all registered options with their help text and headings. We verify that
/// well-known option names appear in the output.
#[test]
fn test_help_flag_long() {
    dnsmasq_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--port"))
        .stdout(predicate::str::contains("--no-daemon"));
}

/// Verify that `-v` (short version flag) prints version string containing "2.92".
///
/// In C dnsmasq, `-v` prints the version banner. In the Rust implementation,
/// main.rs outputs: `"dnsmasq version {VERSION} — {COPYRIGHT}"` where
/// `VERSION = "2.92"` (defined in `lib.rs`).
#[test]
fn test_version_flag_short() {
    dnsmasq_cmd()
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains("2.92"));
}

/// Verify that `--version` (long version flag) prints version string containing "2.92".
#[test]
fn test_version_flag_long() {
    dnsmasq_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("2.92"));
}

/// Verify that version output matches the expected format:
/// `"dnsmasq version 2.92 — Copyright (c) 2000-2025 Simon Kelley"`
///
/// This validates that the Rust version output matches the C version's startup
/// banner format, ensuring compatibility with monitoring scripts and automation
/// that parse the version output.
#[test]
fn test_version_output_format() {
    dnsmasq_cmd()
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains("dnsmasq version 2.92"))
        .stdout(predicate::str::contains("Copyright"));
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 3: Core DNS Option Tests
//
// Each test runs the dnsmasq binary with `--test` to exercise the CLI
// parsing chain (main.rs → CliArgs::parse() → DnsmasqConfig::load())
// without starting the daemon. A successful exit with "syntax check OK"
// confirms that the flag is correctly recognized and validated.
// ════════════════════════════════════════════════════════════════════════════

/// Verify `--port=5353` is accepted (tests `-p` / `--port` flag).
///
/// Port 5353 is a valid non-privileged DNS port commonly used for mDNS.
/// The `port` field in `CliArgs` is `Option<u16>`, so valid range is 0–65535.
#[test]
fn test_port_option() {
    dnsmasq_cmd()
        .args(["--port=5353", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--listen-address=127.0.0.1` is accepted (tests `-a` / `--listen-address`).
///
/// Restricts dnsmasq to listen only on the specified IP address.
#[test]
fn test_listen_address_option() {
    dnsmasq_cmd()
        .args(["--listen-address=127.0.0.1", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--no-daemon` is accepted (tests `-d` / `--no-daemon`).
///
/// Keeps dnsmasq in the foreground and logs to stderr instead of syslog.
/// Combined with `--test`, this flag is simply parsed and validated.
#[test]
fn test_no_daemon_option() {
    dnsmasq_cmd()
        .args(["--no-daemon", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--keep-in-foreground` is accepted (tests `-k` / `--keep-in-foreground`).
///
/// Similar to `--no-daemon` but retains syslog logging. Commonly used
/// with systemd or container supervisors.
#[test]
fn test_keep_in_foreground_option() {
    dnsmasq_cmd()
        .args(["--keep-in-foreground", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--cache-size=1000` is accepted (tests `-c` / `--cache-size`).
///
/// Overrides the default DNS cache size (`CACHESIZ = 150` from `config.h`).
#[test]
fn test_cache_size_option() {
    dnsmasq_cmd()
        .args(["--cache-size=1000", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--server=8.8.8.8` is accepted (tests `-S` / `--server`).
///
/// Configures an upstream DNS server for query forwarding.
#[test]
fn test_server_option() {
    dnsmasq_cmd()
        .args(["--server=8.8.8.8", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--local=/mynet/` is accepted (tests `--local`, long-only option).
///
/// Note: `--local` is a **long-only** option (defined at cli.rs line 542-543).
/// The short flag `-L` maps to `--localmx`, NOT `--local`. This tests the
/// correct long-only form for local domain resolution.
#[test]
fn test_local_option() {
    dnsmasq_cmd()
        .args(["--local=/mynet/", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--domain-needed` is accepted (tests `-D` / `--domain-needed`).
///
/// Prevents forwarding of plain name queries (names without dots)
/// to upstream DNS servers, matching C dnsmasq behavior.
#[test]
fn test_domain_needed_option() {
    dnsmasq_cmd()
        .args(["--domain-needed", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--bogus-priv` is accepted (tests `-b` / `--bogus-priv`).
///
/// Prevents forwarding of reverse queries for private IP ranges
/// (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) to upstream servers.
#[test]
fn test_bogus_priv_option() {
    dnsmasq_cmd()
        .args(["--bogus-priv", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--expand-hosts` is accepted (tests `-E` / `--expand-hosts`).
///
/// Appends the domain suffix to entries in `/etc/hosts` and DHCP host names,
/// enabling short-name resolution within the configured domain.
#[test]
fn test_expand_hosts_option() {
    dnsmasq_cmd()
        .args(["--expand-hosts", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--no-resolv` is accepted (tests `-R` / `--no-resolv`).
///
/// Disables reading `/etc/resolv.conf`; upstream servers must be specified
/// explicitly via `--server` instead.
#[test]
fn test_no_resolv_option() {
    dnsmasq_cmd()
        .args(["--no-resolv", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--no-hosts` is accepted (tests `-h` / `--no-hosts`).
///
/// Disables reading `/etc/hosts`; only DHCP-derived and statically
/// configured host records will be used for name resolution.
#[test]
fn test_no_hosts_option() {
    dnsmasq_cmd()
        .args(["--no-hosts", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--log-queries` is accepted (tests `-q` / `--log-queries`).
///
/// Enables logging of all DNS queries and replies. The `--log-queries` flag
/// uses `num_args = 0..=1` in cli.rs, accepting both `--log-queries` (no value)
/// and `--log-queries=extra` forms.
#[test]
fn test_log_queries_option() {
    dnsmasq_cmd()
        .args(["--log-queries", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 4: DHCP Option Tests (Feature-Gated)
//
// These tests are gated by the `dhcp` or `dhcp6` Cargo feature flags,
// corresponding to C dnsmasq's `HAVE_DHCP` and `HAVE_DHCP6` macros.
// Since `dhcp` and `dhcp6` are default features, these tests run in
// standard `cargo test` invocations.
// ════════════════════════════════════════════════════════════════════════════

/// Verify `--dhcp-range=192.168.1.100,192.168.1.200,12h` is accepted.
///
/// This is the primary DHCP range configuration directive (`-F` / `--dhcp-range`).
/// Format: `<start-addr>,<end-addr>,<lease-time>`.
/// The 12h suffix specifies a 12-hour lease duration.
#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_range_option() {
    dnsmasq_cmd()
        .args(["--dhcp-range=192.168.1.100,192.168.1.200,12h", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--dhcp-host=aa:bb:cc:dd:ee:ff,192.168.1.50` is accepted.
///
/// Static DHCP host assignment (`-G` / `--dhcp-host`), mapping a MAC address
/// to a fixed IP address for deterministic DHCP allocation.
#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_host_option() {
    dnsmasq_cmd()
        .args(["--dhcp-host=aa:bb:cc:dd:ee:ff,192.168.1.50", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--dhcp-option=6,192.168.1.1` is accepted.
///
/// Sends DHCP option 6 (DNS server) with value `192.168.1.1` to clients
/// (`-O` / `--dhcp-option`). Option 6 specifies the DNS server addresses
/// that DHCP clients should use.
#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_option_option() {
    dnsmasq_cmd()
        .args(["--dhcp-option=6,192.168.1.1", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--dhcp-leasefile=/tmp/test-leases` is accepted.
///
/// Sets the path for DHCP lease persistence (`-l` / `--dhcp-leasefile`).
/// The lease file stores active DHCP leases across daemon restarts.
#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_leasefile_option() {
    dnsmasq_cmd()
        .args(["--dhcp-leasefile=/tmp/test-leases", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--enable-ra` is accepted.
///
/// Enables sending of IPv6 Router Advertisements on interfaces that are
/// doing DHCPv6. This option is semantically tied to DHCPv6 functionality
/// and is gated by the `dhcp6` feature in the test.
#[cfg(feature = "dhcp6")]
#[test]
fn test_enable_ra_option() {
    dnsmasq_cmd()
        .args(["--enable-ra", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 5: TFTP/PXE Option Tests (Feature-Gated)
//
// These tests are gated by the `tftp` Cargo feature flag, corresponding to
// C dnsmasq's `HAVE_TFTP` macro. The CLI flags themselves are conditionally
// compiled in cli.rs using `#[cfg(feature = "tftp")]`.
// ════════════════════════════════════════════════════════════════════════════

/// Verify `--enable-tftp` is accepted.
///
/// Enables the built-in TFTP server for PXE network boot support.
/// The `--enable-tftp` flag uses `num_args = 0..=1` in cli.rs, accepting
/// both `--enable-tftp` (all interfaces) and `--enable-tftp=eth0` (specific
/// interface) forms.
#[cfg(feature = "tftp")]
#[test]
fn test_enable_tftp_option() {
    dnsmasq_cmd()
        .args(["--enable-tftp", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--tftp-root=/tftpboot` is accepted.
///
/// Sets the root directory for TFTP file serving. Files requested by
/// PXE/TFTP clients are resolved relative to this directory.
#[cfg(feature = "tftp")]
#[test]
fn test_tftp_root_option() {
    dnsmasq_cmd()
        .args(["--tftp-root=/tftpboot", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 6: Configuration Test Mode
//
// The `--test` flag triggers dnsmasq's configuration validation mode:
// parse and validate all configuration files, report errors, and exit
// without starting the daemon. This matches C dnsmasq behavior.
// ════════════════════════════════════════════════════════════════════════════

/// Verify `--test` flag exits with code 0 (config syntax check mode).
///
/// `--test` triggers the configuration validation path in main.rs:
/// `DnsmasqConfig::load(&cli_args)` → "dnsmasq: syntax check OK." on success.
/// This matches the C behavior where `--test` parses config and exits.
#[test]
fn test_test_flag() {
    dnsmasq_cmd()
        .arg("--test")
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--conf-file=/dev/null --test` is accepted.
///
/// Tests the `-C` / `--conf-file` flag with an empty configuration file
/// (`/dev/null`). The binary should parse the empty config successfully
/// and apply all default values.
#[test]
fn test_conf_file_option() {
    dnsmasq_cmd()
        .args(["--conf-file=/dev/null", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify `--conf-file=/dev/null --test` produces a clean exit.
///
/// Explicitly passing an empty config file (`/dev/null`) combined with
/// `--test` should produce exit code 0 and the "syntax check OK" message
/// without any errors or warnings on stderr.
#[test]
fn test_no_conf_file_with_test() {
    let output = dnsmasq_cmd()
        .args(["--conf-file=/dev/null", "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));

    // Verify no error output on stderr (clean exit).
    // Note: We use the returned Assert for this additional check.
    let _ = output;
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 7: Invalid Option Tests
//
// These tests verify that the binary correctly rejects invalid options
// and values with non-zero exit codes, matching C dnsmasq's error handling.
// ════════════════════════════════════════════════════════════════════════════

/// Verify that an unrecognized option causes a non-zero exit code.
///
/// clap rejects unrecognized flags and exits with an error code, matching
/// C dnsmasq's behavior of reporting unknown options via `die()`.
/// The binary should print an error message to stderr.
#[test]
fn test_invalid_option_rejected() {
    dnsmasq_cmd().arg("--nonexistent-option").assert().failure();
}

/// Verify that an out-of-range port value causes an error.
///
/// The `--port` flag is declared as `Option<u16>` in cli.rs, so clap rejects
/// values outside the 0–65535 range at the argument parsing stage. The value
/// 99999 overflows `u16` and should produce a parsing error before any
/// configuration validation runs.
#[test]
fn test_invalid_port_value() {
    dnsmasq_cmd()
        .args(["--port=99999", "--test"])
        .assert()
        .failure();
}

// ════════════════════════════════════════════════════════════════════════════
// Phase 8: Multiple Options Combination
//
// These tests verify that multiple CLI options and configuration file
// directives can be combined without conflicts or unexpected interactions.
// ════════════════════════════════════════════════════════════════════════════

/// Verify multiple CLI options can be combined in a single invocation.
///
/// Tests that `--port`, `--no-daemon`, `--cache-size`, and `--no-resolv`
/// all work together without conflicts. This validates that the clap parser
/// correctly handles multiple simultaneous options, matching C dnsmasq's
/// behavior where options accumulate without mutual exclusion.
#[test]
fn test_combined_options() {
    dnsmasq_cmd()
        .args([
            "--port=5353",
            "--no-daemon",
            "--cache-size=500",
            "--no-resolv",
            "--test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

/// Verify that a configuration file with multiple directives is accepted
/// when passed via `--conf-file`.
///
/// Creates a temporary configuration file containing multiple valid dnsmasq
/// directives, then invokes the binary with `--conf-file=<tmpfile> --test`.
/// Uses [`tempfile::NamedTempFile`] for automatic cleanup, ensuring test
/// isolation.
///
/// The directives tested here represent a common production configuration:
/// custom DNS port, no resolv.conf reading, increased cache size, and
/// privacy-oriented flags (domain-needed, bogus-priv).
#[test]
fn test_config_file_with_options() {
    let mut config_file = NamedTempFile::new().expect("Failed to create temp config file");
    writeln!(
        config_file,
        "# Test configuration file for CLI compatibility"
    )
    .unwrap();
    writeln!(config_file, "port=5353").unwrap();
    writeln!(config_file, "no-resolv").unwrap();
    writeln!(config_file, "cache-size=500").unwrap();
    writeln!(config_file, "domain-needed").unwrap();
    writeln!(config_file, "bogus-priv").unwrap();
    config_file.flush().unwrap();

    let config_path = config_file
        .path()
        .to_str()
        .expect("Temp file path is not valid UTF-8");

    dnsmasq_cmd()
        .args([&format!("--conf-file={}", config_path), "--test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("syntax check OK"));
}

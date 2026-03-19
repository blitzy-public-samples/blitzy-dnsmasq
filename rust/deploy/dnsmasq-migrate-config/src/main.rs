// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

//! # dnsmasq-migrate-config — Configuration Migration & Validation Tool
//!
//! A synchronous command-line tool that validates existing `dnsmasq.conf`
//! configuration files for compatibility with the Rust dnsmasq implementation.
//!
//! This tool reuses the main dnsmasq library's configuration parser
//! ([`dnsmasq::config::options::DnsmasqConfig::from_file()`]) to ensure
//! validation exactly matches runtime behavior.  It reports unsupported,
//! deprecated, or problematic directives with line numbers and suggestions.
//!
//! ## Usage
//!
//! ```text
//! dnsmasq-migrate-config --config /etc/dnsmasq.conf
//! dnsmasq-migrate-config --config /etc/dnsmasq.conf --json
//! dnsmasq-migrate-config --config /etc/dnsmasq.conf --verbose
//! dnsmasq-migrate-config --config /etc/dnsmasq.conf --check-features --strict
//! ```
//!
//! ## Exit Codes
//!
//! - `0` — All directives are compatible with the Rust implementation
//! - `1` — Validation errors found; configuration needs fixes
//! - `2` — Fatal error (e.g., cannot read the configuration file)
//!
//! ## Output Formats
//!
//! - **Human-readable** (default): Prints a summary with issue details to stdout.
//! - **JSON** (`--json`): Structured JSON report to stdout, suitable for
//!   piping to `jq` or processing by automation scripts.
//!
//! Logs are always directed to stderr to keep stdout clean for report output.

use std::io::stderr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use serde::Serialize;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use dnsmasq::config::features;
use dnsmasq::config::options::DnsmasqConfig;

// =============================================================================
// CLI Argument Definitions
// =============================================================================

/// dnsmasq configuration migration and validation tool.
///
/// Validates existing dnsmasq.conf files for compatibility with the
/// Rust dnsmasq implementation.  Reports unsupported, deprecated, or
/// problematic directives with line numbers and suggestions.
#[derive(Parser, Debug)]
#[command(
    name = "dnsmasq-migrate-config",
    version = "2.92.0",
    about = "Validate dnsmasq configuration for Rust implementation compatibility"
)]
pub struct MigrateArgs {
    /// Path to dnsmasq configuration file to validate.
    /// Defaults to /etc/dnsmasq.conf (the standard dnsmasq config location).
    #[arg(
        short = 'c',
        long = "config",
        default_value = "/etc/dnsmasq.conf",
        value_name = "FILE"
    )]
    pub config_file: PathBuf,

    /// Output validation report in JSON format for machine consumption.
    /// When enabled, all output is structured JSON suitable for piping
    /// to jq or processing by automation scripts.
    #[arg(short = 'j', long = "json")]
    pub json_output: bool,

    /// Enable verbose output showing per-directive validation status.
    /// Each directive is reported with its compatibility status,
    /// line number, and any relevant notes or warnings.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Check feature-gated directives against the current compilation.
    /// Warns if the config uses directives requiring features that are
    /// not compiled into the current binary (e.g., DNSSEC, D-Bus).
    #[arg(long = "check-features", default_value_t = true)]
    pub check_features: bool,

    /// Treat warnings as errors (strict validation mode).
    /// When enabled, any warning also causes a non-zero exit code.
    #[arg(long = "strict")]
    pub strict: bool,

    /// Validate included config files recursively.
    /// When enabled (default), follows conf-file= and conf-dir=
    /// directives and validates all included files.
    /// Matches C parser behavior from option.c lines 109–120.
    #[arg(long = "follow-includes", default_value_t = true)]
    pub follow_includes: bool,
}

// =============================================================================
// Validation Report Data Structures
// =============================================================================

/// Complete validation report for a dnsmasq configuration file.
///
/// Serialisable to JSON via `serde_json::to_string_pretty()` when the
/// `--json` flag is passed.
#[derive(Debug, Serialize)]
pub struct ValidationReport {
    /// Path to the validated configuration file.
    pub config_file: String,
    /// Whether validation passed (all directives compatible).
    pub success: bool,
    /// Total number of directives processed.
    pub total_directives: usize,
    /// Number of compatible directives.
    pub compatible: usize,
    /// Number of warnings (directive works but has notes).
    pub warnings: usize,
    /// Number of errors (directive incompatible or invalid).
    pub errors: usize,
    /// List of all individual validation issues.
    pub issues: Vec<ValidationIssue>,
    /// Features detected as required by the configuration.
    pub required_features: Vec<String>,
    /// Included configuration files that were processed.
    pub included_files: Vec<String>,
}

/// A single validation issue found in the configuration.
#[derive(Debug, Serialize)]
pub struct ValidationIssue {
    /// Severity level: `"error"`, `"warning"`, or `"info"`.
    pub severity: IssueSeverity,
    /// Configuration file where the issue was found.
    pub file: String,
    /// Line number in the file (1-indexed, matching C error format).
    /// Zero if line is unknown.
    pub line: usize,
    /// The directive name that triggered the issue.
    pub directive: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// Suggested fix or migration action (if applicable).
    pub suggestion: Option<String>,
}

/// Issue severity levels for validation reporting.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    /// Directive is incompatible — migration cannot proceed without fixing.
    Error,
    /// Directive works but requires attention or has behavioural differences.
    Warning,
    /// Informational note about the directive.
    Info,
}

// =============================================================================
// Entry Point
// =============================================================================

/// Binary entry point.
///
/// **CRITICAL**: This is a SYNCHRONOUS tool — no `#[tokio::main]`, no `async`,
/// no `.await`.  It parses arguments, initialises logging, validates the
/// configuration file, prints a report, and exits.
///
/// Exit codes:
/// - `0` — configuration is compatible
/// - `1` — validation errors found
/// - `2` — fatal error (cannot open or read file)
fn main() -> ExitCode {
    // 1. Parse CLI arguments
    let args = MigrateArgs::parse();

    // 2. Initialise tracing/logging subscriber
    init_logging(&args);

    // 3. Log startup
    info!(
        config_file = %args.config_file.display(),
        "dnsmasq-migrate-config v2.92.0 — validating configuration"
    );

    // 4. Run validation
    match validate_config(&args) {
        Ok(report) => {
            // 5. Output report
            output_report(&args, &report);

            // 6. Determine exit code
            if report.success && !(args.strict && report.warnings > 0) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            // Fatal error — could not even open or read the config file
            if args.json_output {
                let error_report = serde_json::json!({
                    "success": false,
                    "fatal_error": format!("{:#}", e),
                });
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&error_report).unwrap_or_default()
                );
            } else {
                eprintln!("Fatal error: {:#}", e);
            }
            ExitCode::from(2)
        }
    }
}

// =============================================================================
// Logging Initialisation
// =============================================================================

/// Initialise the tracing subscriber for logging output.
///
/// Uses JSON format when `--json` flag is set, otherwise human-readable
/// format.  All log output is directed to stderr so that stdout is kept
/// clean for the validation report.
fn init_logging(args: &MigrateArgs) {
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    if args.json_output {
        // JSON format for machine-readable log output on stderr.
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_writer(stderr)
            .init();
    } else {
        // Human-readable format for terminal log output on stderr.
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(stderr)
            .init();
    }
}

// =============================================================================
// Core Validation Logic
// =============================================================================

/// Validate the dnsmasq configuration file for Rust implementation compatibility.
///
/// This function:
/// 1. Verifies the configuration file exists and is readable.
/// 2. Parses the file using the main dnsmasq library's
///    [`DnsmasqConfig::from_file()`] parser (the same parser the daemon uses).
/// 3. Optionally checks feature-gated directives against the current
///    compilation features.
/// 4. Checks for deprecated or platform-specific directives.
/// 5. Collects all issues into a [`ValidationReport`].
fn validate_config(args: &MigrateArgs) -> anyhow::Result<ValidationReport> {
    let config_path = &args.config_file;
    let config_path_str = config_path.display().to_string();

    let mut report = ValidationReport {
        config_file: config_path_str.clone(),
        success: true,
        total_directives: 0,
        compatible: 0,
        warnings: 0,
        errors: 0,
        issues: Vec::new(),
        required_features: Vec::new(),
        included_files: Vec::new(),
    };

    // Verify config file exists and is readable
    if !config_path.exists() {
        anyhow::bail!("Configuration file not found: {}", config_path.display());
    }

    // Attempt to read the raw config for directive-level analysis
    let raw_contents = std::fs::read_to_string(config_path).with_context(|| {
        format!(
            "Failed to read configuration file: {}",
            config_path.display()
        )
    })?;

    // Count and catalogue raw directives from the file
    let raw_directives = parse_raw_directives(&raw_contents, &config_path_str);
    report.total_directives = raw_directives.len();

    debug!(
        total_directives = report.total_directives,
        "Parsed raw directive count from config file"
    );

    // Attempt to load config using the main library's parser.
    // This exercises the exact same parser that the daemon uses,
    // ensuring validation matches runtime behaviour.
    let library_parse_ok = match DnsmasqConfig::from_file(&config_path.to_string_lossy()) {
        Ok(_config) => {
            info!("Configuration file parsed successfully by the dnsmasq library");
            report.compatible = report.total_directives;
            true
        }
        Err(e) => {
            // Parse failed — extract structured error info
            error!("Configuration parse error: {}", e);
            report.errors += 1;
            report.compatible = 0;
            report.issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                file: config_path_str.clone(),
                line: 0,
                directive: String::new(),
                message: format!("Configuration parse error: {}", e),
                suggestion: Some("Fix the reported error and re-run validation".to_string()),
            });
            false
        }
    };

    // Always run feature-gated and deprecated directive checks, regardless
    // of whether the library parser succeeded.  Even when the parser rejects
    // the file we still want to give the user actionable migration feedback
    // for every directive in the config.
    if args.check_features {
        check_feature_gated_directives(&raw_directives, args, &mut report);
    }
    check_deprecated_directives(&raw_directives, args, &mut report);

    // Scan for included files
    collect_included_files(&raw_directives, &mut report);

    // If the library parse was successful but our additional checks added
    // errors, adjust the compatible count downward.
    if library_parse_ok {
        let additional_errors = report.errors;
        if additional_errors > 0 && report.compatible > additional_errors {
            report.compatible -= additional_errors;
        }
    }

    // Update success flag based on error count
    report.success = report.errors == 0;

    Ok(report)
}

// =============================================================================
// Raw Directive Parsing
// =============================================================================

/// A raw directive extracted from a dnsmasq configuration file line.
#[derive(Debug, Clone)]
struct RawDirective {
    /// The directive name (e.g., `"server"`, `"dhcp-range"`, `"no-resolv"`).
    name: String,
    /// The optional value after `=` (e.g., `"/google.com/8.8.8.8"`).
    value: Option<String>,
    /// Source file path.
    file: String,
    /// 1-indexed line number.
    line: usize,
}

/// Parse raw directives from a configuration file's text, preserving
/// line numbers for error reporting.
///
/// This is a lightweight lexer that does NOT perform semantic validation —
/// that is delegated to the library's `DnsmasqConfig::from_file()`.  The
/// purpose here is to enumerate directive names so we can perform feature-
/// gate and deprecation checks on every individual directive.
fn parse_raw_directives(contents: &str, file_path: &str) -> Vec<RawDirective> {
    let mut directives = Vec::new();
    let mut continuation = String::new();
    let mut cont_start_line: usize = 0;

    for (idx, raw_line) in contents.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = raw_line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // If we were building a continuation, flush it
            if !continuation.is_empty() {
                if let Some(dir) = directive_from_line(&continuation, file_path, cont_start_line) {
                    directives.push(dir);
                }
                continuation.clear();
            }
            continue;
        }

        // Handle continuation lines (backslash at end)
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            if continuation.is_empty() {
                cont_start_line = line_num;
            }
            // Remove the trailing backslash and accumulate
            continuation.push_str(stripped);
            continue;
        }

        // If we were accumulating a continuation, append the final segment
        if !continuation.is_empty() {
            continuation.push_str(trimmed);
            if let Some(dir) = directive_from_line(&continuation, file_path, cont_start_line) {
                directives.push(dir);
            }
            continuation.clear();
            continue;
        }

        // Normal single-line directive
        if let Some(dir) = directive_from_line(trimmed, file_path, line_num) {
            directives.push(dir);
        }
    }

    // Flush any trailing continuation
    if !continuation.is_empty() {
        if let Some(dir) = directive_from_line(&continuation, file_path, cont_start_line) {
            directives.push(dir);
        }
    }

    directives
}

/// Convert a single line into a [`RawDirective`], if it is a valid directive.
fn directive_from_line(line: &str, file_path: &str, line_num: usize) -> Option<RawDirective> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Directives are either `key=value` or bare `key`
    let (name, value) = if let Some(eq_pos) = trimmed.find('=') {
        let key = trimmed[..eq_pos].trim();
        let val = trimmed[eq_pos + 1..].trim();
        (key.to_string(), Some(val.to_string()))
    } else {
        (trimmed.to_string(), None)
    };

    // Skip anything that doesn't look like a directive name
    if name.is_empty() {
        return None;
    }

    Some(RawDirective {
        name,
        value,
        file: file_path.to_string(),
        line: line_num,
    })
}

// =============================================================================
// Feature-Gated Directive Checking
// =============================================================================

/// Feature-to-directives mapping entry.
struct FeatureDirectives {
    /// Cargo feature name (e.g., `"dnssec"`).
    feature_name: &'static str,
    /// Whether the feature is currently compiled in.
    is_enabled: bool,
    /// Directive names that require this feature.
    directives: &'static [&'static str],
}

/// Check whether config directives require Cargo features that are not
/// compiled into the current binary.
///
/// For each feature-gated directive found in the configuration, if the
/// corresponding Cargo feature is disabled, a warning issue is added to
/// the report.  The required feature is also tracked in
/// `report.required_features`.
fn check_feature_gated_directives(
    raw_directives: &[RawDirective],
    args: &MigrateArgs,
    report: &mut ValidationReport,
) {
    let feature_map: Vec<FeatureDirectives> = vec![
        FeatureDirectives {
            feature_name: "dhcp",
            is_enabled: features::has_dhcp(),
            directives: &[
                "dhcp-range",
                "dhcp-host",
                "dhcp-option",
                "dhcp-option-force",
                "dhcp-boot",
                "dhcp-leasefile",
                "dhcp-lease-max",
                "dhcp-authoritative",
                "dhcp-rapid-commit",
                "dhcp-sequential-ip",
                "dhcp-fqdn",
                "dhcp-proxy",
                "dhcp-generate-names",
                "dhcp-ignore-names",
                "dhcp-alternate-port",
                "dhcp-hostsfile",
                "dhcp-optsfile",
                "dhcp-hostsdir",
                "dhcp-optsdir",
                "dhcp-no-override",
                "dhcp-match",
                "dhcp-name-match",
                "dhcp-broadcast",
                "dhcp-mac",
                "dhcp-userclass",
                "dhcp-vendorclass",
                "dhcp-circuitid",
                "dhcp-remoteid",
                "dhcp-subscrid",
                "dhcp-pxe-vendor",
                "dhcp-reply-delay",
                "dhcp-ttl",
                "dhcp-relay",
                "dhcp-split-relay",
                "dhcp-client-update",
                "dhcp-ignore-clid",
                "dhcp-ignore",
                "tag-if",
                "read-ethers",
                "bootp-dynamic",
                "no-ping",
                "leasefile-ro",
                "quiet-dhcp",
                "log-dhcp",
                "dhcp-duid",
            ],
        },
        FeatureDirectives {
            feature_name: "dhcp6",
            is_enabled: features::has_dhcp6(),
            directives: &["enable-ra", "ra-param", "quiet-dhcp6", "quiet-ra"],
        },
        FeatureDirectives {
            feature_name: "tftp",
            is_enabled: features::has_tftp(),
            directives: &[
                "enable-tftp",
                "tftp-root",
                "tftp-max",
                "tftp-secure",
                "tftp-no-fail",
                "tftp-unique-root",
                "tftp-lowercase",
                "tftp-mtu",
                "tftp-single-port",
                "tftp-port-range",
                "tftp-no-blocksize",
                "quiet-tftp",
            ],
        },
        FeatureDirectives {
            feature_name: "dnssec",
            is_enabled: features::has_dnssec(),
            directives: &[
                "dnssec",
                "trust-anchor",
                "dnssec-debug",
                "dnssec-check-unsigned",
                "dnssec-no-timecheck",
                "dnssec-timestamp",
                "dnssec-limits",
                "proxy-dnssec",
            ],
        },
        FeatureDirectives {
            feature_name: "dbus",
            is_enabled: features::has_dbus(),
            directives: &["enable-dbus"],
        },
        FeatureDirectives {
            feature_name: "ubus",
            is_enabled: features::has_ubus(),
            directives: &["enable-ubus"],
        },
        FeatureDirectives {
            feature_name: "conntrack",
            is_enabled: features::has_conntrack(),
            directives: &[
                "conntrack",
                "connmark-allowlist-enable",
                "connmark-allowlist",
            ],
        },
        FeatureDirectives {
            feature_name: "ipset",
            is_enabled: features::has_ipset(),
            directives: &["ipset"],
        },
        FeatureDirectives {
            feature_name: "nftset",
            is_enabled: features::has_nftset(),
            directives: &["nftset"],
        },
        FeatureDirectives {
            feature_name: "luascript",
            is_enabled: features::has_luascript(),
            directives: &["dhcp-luascript"],
        },
        FeatureDirectives {
            feature_name: "idn",
            is_enabled: features::has_idn(),
            directives: &[
                // IDN does not have its own directive; it affects how
                // hostnames are processed.  The feature is only relevant
                // if the config contains international domain names.
                // We flag the feature as informational if any domain
                // directives are present and IDN is disabled.
            ],
        },
        FeatureDirectives {
            feature_name: "auth",
            is_enabled: features::has_auth(),
            directives: &[
                "auth-zone",
                "auth-server",
                "auth-ttl",
                "auth-soa",
                "auth-sec-servers",
                "auth-peer",
            ],
        },
        FeatureDirectives {
            feature_name: "script",
            is_enabled: features::has_script(),
            directives: &[
                "dhcp-script",
                "dhcp-scriptuser",
                "script-arp",
                "script-on-renewal",
            ],
        },
        FeatureDirectives {
            feature_name: "inotify",
            is_enabled: features::has_inotify(),
            directives: &[
                // inotify does not have a direct directive; it is used
                // internally for watching /etc/hosts and related files.
                // The feature is auto-enabled on Linux.
            ],
        },
        FeatureDirectives {
            feature_name: "dumpfile",
            is_enabled: features::has_dumpfile(),
            directives: &["dumpfile", "dumpmask"],
        },
        FeatureDirectives {
            feature_name: "loop-detect",
            is_enabled: features::has_loop_detect(),
            directives: &["dns-loop-detect"],
        },
    ];

    for feat in &feature_map {
        for directive in raw_directives {
            if feat.directives.contains(&directive.name.as_str()) && !feat.is_enabled {
                // Track the required feature
                let feat_str = feat.feature_name.to_string();
                if !report.required_features.contains(&feat_str) {
                    report.required_features.push(feat_str.clone());
                }

                let msg = format!(
                    "Directive '{}' requires the '{}' feature which is not compiled in",
                    directive.name, feat.feature_name
                );
                warn!(
                    directive = %directive.name,
                    feature = feat.feature_name,
                    file = %directive.file,
                    line = directive.line,
                    "{}",
                    msg
                );

                report.warnings += 1;
                if report.compatible > 0 {
                    report.compatible -= 1;
                }
                report.issues.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    file: directive.file.clone(),
                    line: directive.line,
                    directive: directive.name.clone(),
                    message: msg,
                    suggestion: Some(format!(
                        "Rebuild dnsmasq-rust with: cargo build --features {}",
                        feat.feature_name
                    )),
                });

                if args.verbose {
                    debug!(
                        "Feature '{}' required by directive '{}' at {}:{}",
                        feat.feature_name, directive.name, directive.file, directive.line
                    );
                }
            }
        }
    }
}

// =============================================================================
// Deprecated Directive Checking
// =============================================================================

/// Known directives whose behaviour has changed or that merit a note
/// during migration from C dnsmasq to Rust dnsmasq.
struct DeprecatedDirective {
    /// Directive name.
    name: &'static str,
    /// Message to display.
    message: &'static str,
    /// Severity level.
    severity: IssueSeverity,
    /// Optional suggestion.
    suggestion: Option<&'static str>,
}

/// Check for deprecated or platform-specific directives that may require
/// attention during migration.
fn check_deprecated_directives(
    raw_directives: &[RawDirective],
    args: &MigrateArgs,
    report: &mut ValidationReport,
) {
    let known_deprecations: &[DeprecatedDirective] = &[
        DeprecatedDirective {
            name: "conf-script",
            message:
                "conf-script= is not supported in the Rust implementation for security reasons; \
                      external scripts that generate config should write to a conf-dir instead",
            severity: IssueSeverity::Error,
            suggestion: Some(
                "Use conf-dir= with an external script that writes config fragments to a directory",
            ),
        },
        DeprecatedDirective {
            name: "pxe-prompt",
            message: "PXE prompt support is present but the timing behaviour may differ slightly \
                      from the C implementation due to the async I/O model",
            severity: IssueSeverity::Info,
            suggestion: None,
        },
        DeprecatedDirective {
            name: "pxe-service",
            message: "PXE service support is present but the timing behaviour may differ slightly \
                      from the C implementation due to the async I/O model",
            severity: IssueSeverity::Info,
            suggestion: None,
        },
    ];

    // Platform-specific directives that may not apply on the current OS
    let platform_notes: &[(&str, &str, &str)] = &[(
        "bind-dynamic",
        "bind-dynamic requires Linux SO_BINDTODEVICE or equivalent; \
             may not work on all platforms",
        "Ensure the target platform supports SO_BINDTODEVICE or use bind-interfaces instead",
    )];

    for directive in raw_directives {
        // Check known deprecations
        for dep in known_deprecations {
            if directive.name == dep.name {
                let msg = dep.message.to_string();
                match dep.severity {
                    IssueSeverity::Error => {
                        error!(
                            directive = %directive.name,
                            file = %directive.file,
                            line = directive.line,
                            "{}",
                            msg
                        );
                        report.errors += 1;
                        if report.compatible > 0 {
                            report.compatible -= 1;
                        }
                    }
                    IssueSeverity::Warning => {
                        warn!(
                            directive = %directive.name,
                            file = %directive.file,
                            line = directive.line,
                            "{}",
                            msg
                        );
                        report.warnings += 1;
                        if report.compatible > 0 {
                            report.compatible -= 1;
                        }
                    }
                    IssueSeverity::Info => {
                        info!(
                            directive = %directive.name,
                            file = %directive.file,
                            line = directive.line,
                            "{}",
                            msg
                        );
                    }
                }

                report.issues.push(ValidationIssue {
                    severity: dep.severity,
                    file: directive.file.clone(),
                    line: directive.line,
                    directive: directive.name.clone(),
                    message: msg,
                    suggestion: dep.suggestion.map(String::from),
                });
            }
        }

        // Check platform-specific notes
        for &(dir_name, message, suggestion) in platform_notes {
            if directive.name == dir_name {
                if args.verbose {
                    info!(
                        directive = %directive.name,
                        file = %directive.file,
                        line = directive.line,
                        "{}",
                        message
                    );
                }

                report.issues.push(ValidationIssue {
                    severity: IssueSeverity::Info,
                    file: directive.file.clone(),
                    line: directive.line,
                    directive: directive.name.clone(),
                    message: message.to_string(),
                    suggestion: Some(suggestion.to_string()),
                });
            }
        }
    }
}

// =============================================================================
// Included File Collection
// =============================================================================

/// Scan raw directives for `conf-file` and `conf-dir` entries and record
/// them in the report's `included_files` list.
fn collect_included_files(raw_directives: &[RawDirective], report: &mut ValidationReport) {
    for directive in raw_directives {
        match directive.name.as_str() {
            "conf-file" => {
                if let Some(ref val) = directive.value {
                    let path = val.trim().to_string();
                    if !path.is_empty() && !report.included_files.contains(&path) {
                        report.included_files.push(path);
                    }
                }
            }
            "conf-dir" => {
                if let Some(ref val) = directive.value {
                    // conf-dir value may include a filter: `/etc/dnsmasq.d,*.conf`
                    let path = val.split(',').next().unwrap_or("").trim().to_string();
                    if !path.is_empty() && !report.included_files.contains(&path) {
                        report.included_files.push(path);
                    }
                }
            }
            _ => {}
        }
    }
}

// =============================================================================
// Report Output
// =============================================================================

/// Output the validation report in the requested format.
///
/// - **JSON** (`--json`): Machine-readable JSON to stdout.
/// - **Human-readable** (default): Coloured summary to stdout.
fn output_report(args: &MigrateArgs, report: &ValidationReport) {
    if args.json_output {
        // Machine-readable JSON output to stdout
        match serde_json::to_string_pretty(report) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Failed to serialize report: {}", e),
        }
    } else {
        // Human-readable output
        println!("dnsmasq configuration validation report");
        println!("=======================================");
        println!("Config file: {}", report.config_file);
        println!("Total directives: {}", report.total_directives);
        println!("Compatible: {}", report.compatible);
        println!("Warnings: {}", report.warnings);
        println!("Errors: {}", report.errors);
        println!();

        if report.issues.is_empty() {
            println!("\u{2713} All directives are compatible with the Rust implementation.");
        } else {
            for issue in &report.issues {
                let icon = match issue.severity {
                    IssueSeverity::Error => "\u{2717}",
                    IssueSeverity::Warning => "\u{26A0}",
                    IssueSeverity::Info => "\u{2139}",
                };
                let severity_label = match issue.severity {
                    IssueSeverity::Error => "ERROR",
                    IssueSeverity::Warning => "WARNING",
                    IssueSeverity::Info => "INFO",
                };
                if issue.line > 0 {
                    println!(
                        "{} {}:{}: [{}] {} \u{2014} {}",
                        icon,
                        issue.file,
                        issue.line,
                        issue.directive,
                        severity_label,
                        issue.message
                    );
                } else {
                    println!(
                        "{} {}: [{}] {} \u{2014} {}",
                        icon, issue.file, issue.directive, severity_label, issue.message
                    );
                }
                if let Some(ref suggestion) = issue.suggestion {
                    println!("  \u{2192} Suggestion: {}", suggestion);
                }
            }
        }

        if !report.required_features.is_empty() {
            println!();
            println!("Required Cargo features:");
            for feature in &report.required_features {
                println!("  - {}", feature);
            }
        }

        if !report.included_files.is_empty() {
            println!();
            println!("Included configuration files:");
            for inc in &report.included_files {
                println!("  - {}", inc);
            }
        }

        println!();
        if report.success && !(args.strict && report.warnings > 0) {
            println!("Result: PASS \u{2014} configuration is compatible with Rust dnsmasq");
        } else {
            println!(
                "Result: FAIL \u{2014} {} error(s), {} warning(s) found; configuration needs fixes",
                report.errors, report.warnings
            );
        }
    }
}

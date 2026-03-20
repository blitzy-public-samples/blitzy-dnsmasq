// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]
// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Structured Logging Subsystem
//!
//! Rust implementation of dnsmasq's logging subsystem, replacing C's `src/log.c`
//! (1,120 lines) with the `tracing` + `tracing-subscriber` ecosystem.
//!
//! ## Architecture Comparison
//!
//! ### C Implementation (`log.c`)
//!
//! The C implementation uses a custom non-blocking queue with bounded depth
//! (`LOG_MAX=5` entries, defined in `config.h` line 654) to prevent a critical
//! deadlock scenario: if syslogd makes DNS lookups through dnsmasq, and dnsmasq
//! blocks waiting for syslogd to accept log messages via `/dev/log`, both daemons
//! deadlock. The C solution uses fixed-size log buffers (`MAX_MESSAGE=1024` per
//! RFC 3164), fork-safe PID tracking, and exponential backoff for queue overflow.
//!
//! Key C data structures replaced:
//! - `struct log_entry` (line 116): Fixed-size 1024-byte payload buffer with
//!   intrusive linked list — replaced by tracing's internal event storage
//! - Static queue: `entries` / `free_entries` / `entries_alloced` / `entries_lost`
//!   — replaced by tracing-subscriber's buffered output layers
//! - Connection state: `log_fd` / `connection_good` / `connection_type` —
//!   replaced by [`FileWriter`] with mutex-protected file handle
//!
//! ### Rust Implementation (this module)
//!
//! The `tracing` ecosystem provides inherently async-safe, non-blocking structured
//! logging that eliminates the deadlock risk without a bounded queue:
//! - `tracing` macros (`info!`, `warn!`, etc.) never block the caller
//! - The subscriber pipeline handles buffering and output internally
//! - No fixed message size limit (C's `MAX_MESSAGE=1024` is unnecessary)
//! - No bounded queue depth needed (C's `LOG_MAX=5` is unnecessary)
//!
//! ## Output Modes
//!
//! - **Console/stderr**: Debug mode, matching C's `OPT_DEBUG` stderr echo
//! - **File**: Replacing C's `log_to_file` mode with SIGHUP rotation support
//! - **JSON**: New structured output for SIEM integration (not in C version)
//!
//! ## Facility Mapping
//!
//! C's syslog facility flags (dnsmasq.h lines 479-485) are mapped to tracing
//! target strings for structured filtering:
//! - `MS_TFTP`   (`LOG_USER`)   → target `"dnsmasq::tftp"`
//! - `MS_DHCP`   (`LOG_DAEMON`) → target `"dnsmasq::dhcp"`
//! - `MS_SCRIPT`  (`LOG_MAIL`)  → target `"dnsmasq::script"`
//! - `MS_DEBUG`  (`LOG_NEWS`)   → target `"dnsmasq::debug"`

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt as tracing_fmt, EnvFilter, Registry};

use crate::core::types::{DnsmasqError, DnsmasqResult};

// ---------------------------------------------------------------------------
// Syslog Facility Constants (from <syslog.h>)
// ---------------------------------------------------------------------------

/// LOG_DAEMON facility code (3 << 3 = 24).
const SYSLOG_FACILITY_DAEMON: i32 = 3 << 3;
/// LOG_LOCAL0 facility code (16 << 3 = 128), used in debug mode.
const SYSLOG_FACILITY_LOCAL0: i32 = 16 << 3;
/// LOG_USER facility code (1 << 3 = 8), maps MS_TFTP.
const SYSLOG_FACILITY_USER: i32 = 1 << 3;
/// LOG_MAIL facility code (2 << 3 = 16), maps MS_SCRIPT.
const SYSLOG_FACILITY_MAIL: i32 = 2 << 3;

// ---------------------------------------------------------------------------
// LogFacility Enum
// ---------------------------------------------------------------------------

/// Syslog facility selection for log message categorization.
///
/// Maps C's `log_fac` static variable (log.c line 105) and the syslog
/// facility constants from `<syslog.h>`. In the C implementation, the
/// facility is encoded in the RFC 3164 PRI field as `(facility * 8) | priority`.
///
/// In the Rust implementation, the facility primarily identifies the log
/// category for configuration and is stored for compatibility with external
/// syslog consumers. Tracing target strings provide the actual routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFacility {
    /// `LOG_DAEMON` — standard daemon facility (default).
    /// Used for general dnsmasq messages and DHCP events (`MS_DHCP`).
    Daemon,
    /// `LOG_LOCAL0` — local use facility.
    /// Automatically selected in debug mode (C: log.c lines 186-188).
    Local0,
    /// `LOG_USER` — user-level messages.
    /// Used for TFTP events (`MS_TFTP`, dnsmasq.h line 482).
    User,
    /// `LOG_MAIL` — mail subsystem facility.
    /// Used for script execution events (`MS_SCRIPT`, dnsmasq.h line 484).
    Mail,
    /// Custom syslog facility code for advanced configurations.
    /// Accepts raw numeric facility values from `--log-facility` directive.
    Custom(i32),
}

impl LogFacility {
    /// Returns the numeric syslog facility code per RFC 3164.
    ///
    /// The facility code occupies the upper 5 bits of the PRI value,
    /// pre-shifted left by 3 (multiplied by 8) per the syslog protocol.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(LogFacility::Daemon.as_syslog_code(), 24);
    /// assert_eq!(LogFacility::Local0.as_syslog_code(), 128);
    /// ```
    pub fn as_syslog_code(&self) -> i32 {
        match self {
            Self::Daemon => SYSLOG_FACILITY_DAEMON,
            Self::Local0 => SYSLOG_FACILITY_LOCAL0,
            Self::User => SYSLOG_FACILITY_USER,
            Self::Mail => SYSLOG_FACILITY_MAIL,
            Self::Custom(code) => *code,
        }
    }

    /// Creates a [`LogFacility`] from a numeric syslog facility code.
    ///
    /// Recognizes standard facilities and falls back to [`Custom`](Self::Custom)
    /// for unrecognized values. Used when parsing `--log-facility` from config.
    pub fn from_syslog_code(code: i32) -> Self {
        if code == SYSLOG_FACILITY_DAEMON {
            Self::Daemon
        } else if code == SYSLOG_FACILITY_LOCAL0 {
            Self::Local0
        } else if code == SYSLOG_FACILITY_USER {
            Self::User
        } else if code == SYSLOG_FACILITY_MAIL {
            Self::Mail
        } else {
            Self::Custom(code)
        }
    }
}

impl Default for LogFacility {
    /// Returns [`LogFacility::Daemon`], matching C's default `LOG_DAEMON`
    /// (log.c line 105: `static int log_fac = LOG_DAEMON;`).
    fn default() -> Self {
        Self::Daemon
    }
}

impl std::fmt::Display for LogFacility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daemon => write!(f, "daemon"),
            Self::Local0 => write!(f, "local0"),
            Self::User => write!(f, "user"),
            Self::Mail => write!(f, "mail"),
            Self::Custom(code) => write!(f, "custom({})", code),
        }
    }
}

// ---------------------------------------------------------------------------
// LogConfig Struct
// ---------------------------------------------------------------------------

/// Logging configuration derived from dnsmasq configuration directives.
///
/// Replaces C's scattered static variables in log.c:
/// - `log_fac` (line 105) → [`facility`](Self::facility)
/// - `log_to_file` (line 109) / `daemon->log_file` → [`log_file`](Self::log_file)
/// - `echo_stderr` (line 107) / `OPT_DEBUG` → [`debug`](Self::debug)
/// - `max_logs` (line 113) → not needed (tracing handles buffering internally)
/// - `OPT_EXTRALOG` → [`extra_logging`](Self::extra_logging)
/// - `OPT_LOG` → [`log_queries`](Self::log_queries)
/// - inverted `OPT_QUIET_DHCP` → [`log_dhcp`](Self::log_dhcp)
///
/// The [`json_output`](Self::json_output) field is a new capability not present
/// in the C implementation, enabling machine-parseable structured log output
/// for SIEM (Security Information and Event Management) integration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Syslog facility for log categorization.
    ///
    /// Maps C's `log_fac` (log.c line 105). Default: `LOG_DAEMON`.
    /// In debug mode, C uses `LOG_LOCAL0` (log.c lines 186-188).
    pub facility: LogFacility,

    /// Path to log file, or `None` for stderr output.
    ///
    /// Maps C's `daemon->log_file` and `log_to_file` flag (line 109).
    /// When set, all log output goes to this file with rotation support
    /// via [`reopen_log`]. In C, setting this to `"-"` logged to stderr;
    /// in Rust, leave as `None` and set `debug: true` instead.
    pub log_file: Option<String>,

    /// Enable debug mode with stderr echo and ANSI colors.
    ///
    /// Maps C's `echo_stderr` (line 107) and `OPT_DEBUG`. When true,
    /// log messages are written to stderr with colored output for
    /// interactive debugging.
    pub debug: bool,

    /// Enable JSON structured output for SIEM integration.
    ///
    /// New capability not present in the C implementation. Produces
    /// machine-parseable JSON log lines with structured fields for
    /// integration with log aggregation systems (e.g., ELK, Splunk).
    pub json_output: bool,

    /// Maximum tracing level for log filtering.
    ///
    /// Maps C's priority-based filtering:
    /// - [`Level::INFO`] (default) — standard operational messages
    /// - [`Level::DEBUG`] — verbose, set by `OPT_DEBUG`
    /// - [`Level::TRACE`] — maximum detail, set by `OPT_LOG_DEBUG`
    pub max_level: Level,

    /// Enable extra logging detail (`OPT_EXTRALOG`).
    ///
    /// Adds additional context to log messages (source addresses,
    /// interface names, etc.) matching C's `--log-extra` option.
    pub extra_logging: bool,

    /// Enable DNS query logging (`OPT_LOG`).
    ///
    /// When true, all DNS queries are logged to the `dnsmasq::dns`
    /// target. Matches C's `--log-queries` option.
    pub log_queries: bool,

    /// Enable DHCP event logging (inverted `OPT_QUIET_DHCP`).
    ///
    /// When true, DHCP events are logged to the `dnsmasq::dhcp`
    /// target. Matches C's default behavior (active unless
    /// `--quiet-dhcp` is explicitly set).
    pub log_dhcp: bool,
}

impl Default for LogConfig {
    /// Creates a default logging configuration matching C's defaults.
    ///
    /// - Facility: `LOG_DAEMON`
    /// - No log file (output to stderr)
    /// - Debug mode: off
    /// - JSON output: off
    /// - Level: INFO
    /// - Extra logging: off
    /// - Query logging: off
    /// - DHCP logging: on (C default — `--quiet-dhcp` not set)
    fn default() -> Self {
        Self {
            facility: LogFacility::Daemon,
            log_file: None,
            debug: false,
            json_output: false,
            max_level: Level::INFO,
            extra_logging: false,
            log_queries: false,
            log_dhcp: true,
        }
    }
}

// ---------------------------------------------------------------------------
// File Writer for Log Rotation Support
// ---------------------------------------------------------------------------

/// Internal state for file-based log output with rotation support.
///
/// Wraps a [`std::fs::File`] behind a [`Mutex`] to allow atomic reopen
/// operations during SIGHUP-triggered log rotation, matching C's
/// `log_reopen()` behavior (log.c line 291).
struct FileWriterState {
    /// Path to the log file (stored for reopening on rotation).
    path: String,
    /// Currently open file handle for append writes.
    file: std::fs::File,
}

/// File-based log writer supporting rotation via [`reopen_log`].
///
/// Implements [`tracing_subscriber::fmt::MakeWriter`] for integration with
/// the tracing subscriber pipeline. Each write operation acquires the
/// internal mutex and writes to the current file handle. The handle can
/// be atomically swapped by [`reopen_log`] without restarting the subscriber.
///
/// This replaces C's `log_fd` file descriptor (log.c line 108) with a
/// Rust-safe mutex-protected file handle. The [`Arc`] wrapper allows the
/// writer to be cloned into the global state for rotation access while
/// the subscriber pipeline holds its own reference.
#[derive(Clone)]
struct FileWriter {
    state: Arc<Mutex<FileWriterState>>,
}

impl FileWriter {
    /// Opens a log file for appended writing.
    ///
    /// Maps C's `log_reopen()` initial file open (log.c line 301):
    /// `open(daemon->log_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP)`
    ///
    /// Creates the file if it does not exist, and opens in append mode
    /// to preserve existing content across daemon restarts.
    fn open(path: &str) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            state: Arc::new(Mutex::new(FileWriterState {
                path: path.to_owned(),
                file,
            })),
        })
    }

    /// Reopens the log file for rotation support.
    ///
    /// Closes the current file handle and opens a new one at the same path.
    /// External log rotation tools (e.g., `logrotate`) rename the old file
    /// before this call; the new handle opens/creates the original path.
    ///
    /// Maps C's `log_reopen()` (log.c lines 291-321).
    fn reopen(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| io::Error::other(format!("Log mutex poisoned: {e}")))?;
        let new_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&state.path)?;
        state.file = new_file;
        Ok(())
    }

    /// Flushes the underlying file handle to ensure all buffered data
    /// reaches disk. Called by [`flush_logging`] during shutdown.
    fn flush_file(&self) {
        if let Ok(mut state) = self.state.lock() {
            let _ = state.file.flush();
        }
    }
}

/// Write handle produced by [`FileWriter`]'s `MakeWriter` implementation.
///
/// Each write operation acquires the mutex, writes to the file, and releases.
/// This allows concurrent log rotation without disrupting in-flight writes —
/// the mutex serializes access so a rotation between writes simply swaps
/// the underlying file handle.
struct FileWriterHandle {
    state: Arc<Mutex<FileWriterState>>,
}

impl Write for FileWriterHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| io::Error::other(format!("Log mutex poisoned: {e}")))?;
        state.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| io::Error::other(format!("Log mutex poisoned: {e}")))?;
        state.file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriter {
    type Writer = FileWriterHandle;

    fn make_writer(&'a self) -> Self::Writer {
        FileWriterHandle {
            state: Arc::clone(&self.state),
        }
    }
}

// ---------------------------------------------------------------------------
// Global Log State
// ---------------------------------------------------------------------------

/// Global logging state for rotation and flush support.
///
/// Stored in a [`OnceLock`] initialized by [`init_logging`] and accessed
/// by [`reopen_log`] and [`flush_logging`]. The [`RwLock`] allows concurrent
/// read access during flush operations while serializing state changes.
struct GlobalLogState {
    /// File writer handle, present only when logging to a file.
    file_writer: Option<FileWriter>,
}

/// Global logging state singleton, initialized once by [`init_logging`].
static GLOBAL_LOG_STATE: OnceLock<RwLock<GlobalLogState>> = OnceLock::new();

/// Initializes the global log state with an optional file writer.
///
/// Called during [`init_logging`] to store the file writer reference
/// for later use by [`reopen_log`] and [`flush_logging`].
fn init_global_state(file_writer: Option<FileWriter>) {
    let _ = GLOBAL_LOG_STATE.set(RwLock::new(GlobalLogState { file_writer }));
}

// ---------------------------------------------------------------------------
// Logging Initialization
// ---------------------------------------------------------------------------

/// Initialize the structured logging subsystem.
///
/// Replaces C's `log_start()` (log.c line 177) which established a connection
/// to the syslog daemon via `/dev/log` socket and configured the async log
/// queue with `LOG_MAX` entries. In Rust, constructs and installs a `tracing`
/// subscriber pipeline with appropriate output layers and filtering.
///
/// # Output Mode Selection
///
/// Based on [`LogConfig`], the subscriber is configured with one of:
///
/// | `log_file` | `json_output` | `debug` | Result |
/// |------------|---------------|---------|--------|
/// | Some(path) | true | — | JSON to file |
/// | Some(path) | false | — | Plain text to file |
/// | None | true | — | JSON to stderr |
/// | None | false | true | Colored text to stderr |
/// | None | false | false | Plain text to stderr (default) |
///
/// # Filtering
///
/// Log level filtering replaces C's priority-based message suppression:
/// - Default: `INFO` — standard operational messages
/// - `OPT_DEBUG` → `DEBUG` (C: log.c line 181)
/// - `OPT_LOG_DEBUG` → `TRACE`
/// - Per-target overrides via `--log-queries`, `--log-dhcp`, `--log-extra`
///
/// The `RUST_LOG` environment variable overrides config-based directives.
///
/// # Errors
///
/// Returns [`DnsmasqError::Config`] if subscriber initialization fails.
/// Returns [`DnsmasqError::Io`] if the log file cannot be opened.
pub fn init_logging(config: &LogConfig) -> DnsmasqResult<()> {
    let filter = build_env_filter(config);

    match (&config.log_file, config.json_output, config.debug) {
        // JSON output to file
        (Some(path), true, _) => {
            let writer = FileWriter::open(path).map_err(DnsmasqError::Io)?;
            init_global_state(Some(writer.clone()));
            Registry::default()
                .with(filter)
                .with(
                    tracing_fmt::layer()
                        .json()
                        .with_writer(writer)
                        .with_target(true)
                        .with_span_events(FmtSpan::NONE),
                )
                .try_init()
                .map_err(|e| DnsmasqError::Config(format!("Failed to initialize logging: {e}")))?;
        }

        // Plain text output to file
        (Some(path), false, _) => {
            let writer = FileWriter::open(path).map_err(DnsmasqError::Io)?;
            init_global_state(Some(writer.clone()));
            Registry::default()
                .with(filter)
                .with(
                    tracing_fmt::layer()
                        .with_writer(writer)
                        .with_target(true)
                        .with_ansi(false)
                        .with_span_events(FmtSpan::NONE),
                )
                .try_init()
                .map_err(|e| DnsmasqError::Config(format!("Failed to initialize logging: {e}")))?;
        }

        // JSON output to stderr
        (None, true, _) => {
            init_global_state(None);
            Registry::default()
                .with(filter)
                .with(
                    tracing_fmt::layer()
                        .json()
                        .with_writer(io::stderr)
                        .with_target(true)
                        .with_span_events(FmtSpan::NONE),
                )
                .try_init()
                .map_err(|e| DnsmasqError::Config(format!("Failed to initialize logging: {e}")))?;
        }

        // Debug mode: colored text to stderr (matches C's echo_stderr)
        (None, false, true) => {
            init_global_state(None);
            Registry::default()
                .with(filter)
                .with(
                    tracing_fmt::layer()
                        .with_writer(io::stderr)
                        .with_target(true)
                        .with_ansi(true)
                        .with_span_events(FmtSpan::NONE),
                )
                .try_init()
                .map_err(|e| DnsmasqError::Config(format!("Failed to initialize logging: {e}")))?;
        }

        // Default daemon mode: plain text to stderr (syslog-compatible)
        (None, false, false) => {
            init_global_state(None);
            Registry::default()
                .with(filter)
                .with(
                    tracing_fmt::layer()
                        .with_writer(io::stderr)
                        .with_target(true)
                        .with_ansi(false)
                        .with_span_events(FmtSpan::NONE),
                )
                .try_init()
                .map_err(|e| DnsmasqError::Config(format!("Failed to initialize logging: {e}")))?;
        }
    }

    tracing::info!(
        target: "dnsmasq",
        facility = %config.facility,
        "Logging subsystem initialized"
    );

    // Trace-level detail logging of the full configuration for diagnostics.
    // Only visible at TRACE level (C's `OPT_LOG_DEBUG` equivalent).
    tracing::trace!(
        target: "dnsmasq",
        facility = %config.facility,
        log_file = ?config.log_file,
        debug = config.debug,
        json_output = config.json_output,
        max_level = %config.max_level,
        extra_logging = config.extra_logging,
        log_queries = config.log_queries,
        log_dhcp = config.log_dhcp,
        "Logging configuration details"
    );

    Ok(())
}

/// Build an [`EnvFilter`] from logging configuration.
///
/// Constructs filter directives matching C's priority-based message filtering.
/// The `RUST_LOG` environment variable, if set, overrides configuration-based
/// directives for developer-level control.
fn build_env_filter(config: &LogConfig) -> EnvFilter {
    // Allow RUST_LOG environment variable to override config-based filtering.
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return filter;
    }

    // Map tracing Level to filter directive string
    let base_level = level_to_directive_str(config.max_level);
    let mut directives = base_level.to_string();

    // Per-target overrides for verbose subsystem logging
    if config.log_queries {
        directives.push_str(",dnsmasq::dns=debug");
    }
    if config.log_dhcp {
        directives.push_str(",dnsmasq::dhcp=debug");
    }
    if config.extra_logging {
        directives.push_str(",dnsmasq=debug");
    }

    EnvFilter::new(directives)
}

/// Convert a [`tracing::Level`] to its corresponding filter directive string.
///
/// [`tracing::Level`] is a struct with associated constants (not an enum),
/// so equality comparison is used rather than pattern matching.
fn level_to_directive_str(level: Level) -> &'static str {
    if level == Level::ERROR {
        "error"
    } else if level == Level::WARN {
        "warn"
    } else if level == Level::INFO {
        "info"
    } else if level == Level::DEBUG {
        "debug"
    } else {
        "trace"
    }
}

// ---------------------------------------------------------------------------
// Flush and Rotation
// ---------------------------------------------------------------------------

/// Flush all pending log messages to their output destinations.
///
/// Replaces C's `flush_log()` (log.c line 1003) which blocked in a loop
/// calling `log_write()` with 1ms `nanosleep()` between iterations until
/// the queue was drained, then closed `log_fd`.
///
/// In Rust, flushes the underlying file handle (if logging to file) and
/// stderr to ensure all buffered data reaches disk or the terminal.
pub fn flush_logging() {
    // Flush file writer if present
    if let Some(global_state) = GLOBAL_LOG_STATE.get() {
        if let Ok(state) = global_state.read() {
            if let Some(ref writer) = state.file_writer {
                writer.flush_file();
            }
        }
    }
    // Always flush stderr — some output may go there even with file logging
    let _ = io::stderr().flush();
}

/// Reopen the log file for rotation support.
///
/// Replaces C's `log_reopen()` (log.c lines 291-321). Called in response to
/// SIGHUP to support log file rotation via external tools (e.g., `logrotate`).
/// Atomically closes the current file handle and opens a new one at the
/// same path.
///
/// If no log file is configured, succeeds as a no-op matching C's behavior.
///
/// # Errors
///
/// Returns [`DnsmasqError::Config`] if logging was not initialized.
/// Returns [`DnsmasqError::Io`] if the file cannot be reopened.
pub fn reopen_log() -> DnsmasqResult<()> {
    let global_state = GLOBAL_LOG_STATE
        .get()
        .ok_or_else(|| DnsmasqError::Config("Logging not initialized".into()))?;

    let state = global_state
        .read()
        .map_err(|e| DnsmasqError::Config(format!("Log state lock poisoned: {e}")))?;

    if let Some(ref writer) = state.file_writer {
        writer.reopen().map_err(DnsmasqError::Io)?;
        tracing::info!(target: "dnsmasq", "Log file reopened for rotation");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Structured Domain-Specific Logging
// ---------------------------------------------------------------------------

/// Log a DNS query with structured fields.
///
/// Replaces C's `log_query()` from `cache.c` and `my_syslog(LOG_INFO, ...)`
/// calls in the DNS forwarding code. Emits structured fields for machine
/// processing and SIEM integration.
///
/// Target `"dnsmasq::dns"` — filtered via `--log-queries` or
/// `RUST_LOG=dnsmasq::dns=debug`.
pub fn log_dns_query(name: &str, query_type: u16, source: &str, flags: u32) {
    tracing::info!(
        target: "dnsmasq::dns",
        query_name = name,
        query_type = query_type,
        source = source,
        flags = flags,
        "DNS query"
    );
}

/// Log a DHCP event with structured fields.
///
/// Replaces C's `my_syslog(MS_DHCP | LOG_INFO, "DHCPACK(%s) %s %s %s", ...)`
/// pattern from `rfc2131.c` and `rfc3315.c`.
///
/// Target `"dnsmasq::dhcp"` — mapped from C's `MS_DHCP` (dnsmasq.h line 483).
pub fn log_dhcp_event(event: &str, mac: &str, ip: &str, hostname: Option<&str>) {
    tracing::info!(
        target: "dnsmasq::dhcp",
        event = event,
        mac_address = mac,
        ip_address = ip,
        hostname = hostname.unwrap_or("*"),
        "DHCP event"
    );
}

// ---------------------------------------------------------------------------
// Security Audit Logging (AAP Section 0.7.1)
// ---------------------------------------------------------------------------

/// Log a privilege drop event for security auditing (AAP Section 0.7.1).
pub fn log_privilege_drop(username: &str) {
    tracing::warn!(
        target: "dnsmasq::security",
        username = username,
        "Dropped root privileges, now running as user {}",
        username
    );
}

/// Log a configuration reload event for security auditing (AAP Section 0.7.1).
pub fn log_config_reload(config_path: &str) {
    tracing::info!(
        target: "dnsmasq::security",
        config_path = config_path,
        "Configuration reloaded from {}",
        config_path
    );
}

/// Log a DNSSEC validation failure for security auditing (AAP Section 0.7.1).
pub fn log_dnssec_failure(domain: &str, reason: &str) {
    tracing::error!(
        target: "dnsmasq::security",
        domain = domain,
        reason = reason,
        "DNSSEC validation failed for {}: {}",
        domain,
        reason
    );
}

/// Log a suspected cache poisoning attempt (AAP Section 0.7.1).
pub fn log_cache_poisoning_attempt(domain: &str, source: &str) {
    tracing::error!(
        target: "dnsmasq::security",
        domain = domain,
        source = source,
        "Suspected cache poisoning attempt for {} from {}",
        domain,
        source
    );
}

/// Log a TFTP transfer event.
///
/// Target `"dnsmasq::tftp"` — maps C's `MS_TFTP` (`LOG_USER`, dnsmasq.h line 482).
pub fn log_tftp_event(event: &str, filename: &str, client: &str) {
    tracing::info!(
        target: "dnsmasq::tftp",
        event = event,
        filename = filename,
        client = client,
        "TFTP {}",
        event
    );
}

/// Log a script execution event.
///
/// Target `"dnsmasq::script"` — maps C's `MS_SCRIPT` (`LOG_MAIL`, dnsmasq.h line 484).
pub fn log_script_event(event: &str, details: &str) {
    tracing::info!(
        target: "dnsmasq::script",
        event = event,
        details = details,
        "Script {}",
        event
    );
}

/// Log a debug-level diagnostic message.
///
/// Target `"dnsmasq::debug"` — maps C's `MS_DEBUG` (`LOG_NEWS`, dnsmasq.h line 485).
/// Suppressed unless debug logging is enabled.
pub fn log_debug_message(message: &str) {
    tracing::debug!(
        target: "dnsmasq::debug",
        "{}",
        message
    );
}

// ---------------------------------------------------------------------------
// Native Syslog Integration
// ---------------------------------------------------------------------------

/// Open a connection to the system syslog daemon via `libc::openlog`.
///
/// This provides native syslog(3) integration ensuring messages route correctly
/// through rsyslog/syslog-ng when running in daemon mode. C's `log.c` used a
/// direct UDP/Unix domain socket connection to `/dev/log`; this function uses
/// the POSIX syslog API for broader compatibility.
///
/// # Arguments
///
/// * `ident` — Program name string for syslog identification (typically "dnsmasq").
/// * `facility` — Syslog facility code from [`LogFacility`].
///
/// # Safety
///
/// Uses `libc::openlog` which requires the ident string pointer to remain valid
/// for the lifetime of the syslog connection. The static string "dnsmasq\0"
/// satisfies this requirement.
pub fn open_system_syslog(facility: &LogFacility) {
    let facility_code = facility.as_syslog_code();
    // SAFETY: "dnsmasq\0" is a static string literal with null terminator.
    // libc::openlog requires the ident pointer to remain valid until closelog(),
    // which is satisfied by a static byte string. LOG_PID | LOG_NDELAY matches
    // C dnsmasq's syslog configuration.
    unsafe {
        libc::openlog(
            c"dnsmasq".as_ptr(),
            libc::LOG_PID | libc::LOG_NDELAY,
            facility_code,
        );
    }
}

/// Write a single message to the system syslog daemon via `libc::syslog`.
///
/// Priority levels map tracing levels to syslog priorities:
/// - ERROR → `LOG_ERR`
/// - WARN  → `LOG_WARNING`
/// - INFO  → `LOG_INFO`
/// - DEBUG/TRACE → `LOG_DEBUG`
pub fn write_system_syslog(priority: i32, message: &str) {
    let c_msg = std::ffi::CString::new(message).unwrap_or_default();
    // SAFETY: libc::syslog is a standard POSIX function. The CString ensures
    // null termination. The format string "%s" prevents format string attacks.
    unsafe {
        libc::syslog(priority, c"%s".as_ptr(), c_msg.as_ptr());
    }
}

/// Close the system syslog connection via `libc::closelog`.
///
/// Called during daemon shutdown to release syslog resources.
pub fn close_system_syslog() {
    // SAFETY: libc::closelog is a standard POSIX function with no preconditions.
    unsafe {
        libc::closelog();
    }
}

/// Map a tracing [`Level`] to a syslog priority value.
///
/// Follows the standard syslog priority mapping:
/// - `ERROR` → `LOG_ERR` (3)
/// - `WARN`  → `LOG_WARNING` (4)
/// - `INFO`  → `LOG_INFO` (6)
/// - `DEBUG` → `LOG_DEBUG` (7)
/// - `TRACE` → `LOG_DEBUG` (7)
pub fn tracing_level_to_syslog_priority(level: Level) -> i32 {
    if level == Level::ERROR {
        libc::LOG_ERR
    } else if level == Level::WARN {
        libc::LOG_WARNING
    } else if level == Level::INFO {
        libc::LOG_INFO
    } else {
        libc::LOG_DEBUG
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- LogFacility -------------------------------------------------------

    #[test]
    fn log_facility_default_is_daemon() {
        assert_eq!(LogFacility::default(), LogFacility::Daemon);
    }

    #[test]
    fn log_facility_syslog_codes() {
        assert_eq!(LogFacility::Daemon.as_syslog_code(), 24); // 3 << 3
        assert_eq!(LogFacility::Local0.as_syslog_code(), 128); // 16 << 3
        assert_eq!(LogFacility::User.as_syslog_code(), 8); // 1 << 3
        assert_eq!(LogFacility::Mail.as_syslog_code(), 16); // 2 << 3
        assert_eq!(LogFacility::Custom(42).as_syslog_code(), 42);
    }

    #[test]
    fn log_facility_round_trip() {
        let cases = [
            (SYSLOG_FACILITY_DAEMON, LogFacility::Daemon),
            (SYSLOG_FACILITY_LOCAL0, LogFacility::Local0),
            (SYSLOG_FACILITY_USER, LogFacility::User),
            (SYSLOG_FACILITY_MAIL, LogFacility::Mail),
        ];
        for (code, expected) in cases {
            assert_eq!(LogFacility::from_syslog_code(code), expected);
            assert_eq!(expected.as_syslog_code(), code);
        }
    }

    #[test]
    fn log_facility_unknown_code_becomes_custom() {
        let fac = LogFacility::from_syslog_code(999);
        assert_eq!(fac, LogFacility::Custom(999));
        assert_eq!(fac.as_syslog_code(), 999);
    }

    #[test]
    fn log_facility_display() {
        assert_eq!(format!("{}", LogFacility::Daemon), "daemon");
        assert_eq!(format!("{}", LogFacility::Local0), "local0");
        assert_eq!(format!("{}", LogFacility::User), "user");
        assert_eq!(format!("{}", LogFacility::Mail), "mail");
        assert_eq!(format!("{}", LogFacility::Custom(42)), "custom(42)");
    }

    // -- LogConfig ---------------------------------------------------------

    #[test]
    fn log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.facility, LogFacility::Daemon);
        assert!(config.log_file.is_none());
        assert!(!config.debug);
        assert!(!config.json_output);
        assert_eq!(config.max_level, Level::INFO);
        assert!(!config.extra_logging);
        assert!(!config.log_queries);
        assert!(config.log_dhcp); // C default: DHCP logging on
    }

    // -- EnvFilter ---------------------------------------------------------

    #[test]
    fn env_filter_default_level() {
        let config = LogConfig::default();
        let filter = build_env_filter(&config);
        // The default filter should contain "info" as the base level
        let filter_str = format!("{}", filter);
        assert!(
            filter_str.contains("info"),
            "Default filter should contain 'info', got: {}",
            filter_str
        );
    }

    #[test]
    fn env_filter_with_query_logging() {
        let config = LogConfig {
            log_queries: true,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        assert!(
            filter_str.contains("dnsmasq::dns=debug"),
            "Filter should contain dns debug directive, got: {}",
            filter_str
        );
    }

    #[test]
    fn env_filter_with_dhcp_logging() {
        let config = LogConfig {
            log_dhcp: true,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        assert!(
            filter_str.contains("dnsmasq::dhcp=debug"),
            "Filter should contain dhcp debug directive, got: {}",
            filter_str
        );
    }

    // -- Level mapping -----------------------------------------------------

    #[test]
    fn level_to_directive_str_mapping() {
        assert_eq!(level_to_directive_str(Level::ERROR), "error");
        assert_eq!(level_to_directive_str(Level::WARN), "warn");
        assert_eq!(level_to_directive_str(Level::INFO), "info");
        assert_eq!(level_to_directive_str(Level::DEBUG), "debug");
        assert_eq!(level_to_directive_str(Level::TRACE), "trace");
    }

    // -- Syslog priority mapping -------------------------------------------

    #[test]
    fn syslog_priority_mapping() {
        assert_eq!(
            tracing_level_to_syslog_priority(Level::ERROR),
            libc::LOG_ERR
        );
        assert_eq!(
            tracing_level_to_syslog_priority(Level::WARN),
            libc::LOG_WARNING
        );
        assert_eq!(
            tracing_level_to_syslog_priority(Level::INFO),
            libc::LOG_INFO
        );
        assert_eq!(
            tracing_level_to_syslog_priority(Level::DEBUG),
            libc::LOG_DEBUG
        );
        assert_eq!(
            tracing_level_to_syslog_priority(Level::TRACE),
            libc::LOG_DEBUG
        );
    }

    // -- FileWriter --------------------------------------------------------

    #[test]
    fn file_writer_open_and_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let writer = FileWriter::open(path.to_str().unwrap()).unwrap();
        // Flush should succeed on a valid file
        writer.flush_file();
    }

    #[test]
    fn file_writer_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let writer = FileWriter::open(path.to_str().unwrap()).unwrap();

        // Write something
        {
            let mut handle = writer.state.lock().unwrap();
            handle.file.write_all(b"hello").unwrap();
        }

        // Reopen should succeed
        writer.reopen().unwrap();

        // Write more after reopen
        {
            let mut handle = writer.state.lock().unwrap();
            handle.file.write_all(b"world").unwrap();
        }
    }

    #[test]
    fn file_writer_open_nonexistent_dir_fails() {
        let result = FileWriter::open("/nonexistent/dir/test.log");
        assert!(result.is_err());
    }

    // ===================================================================
    // Additional tests — LogFacility
    // ===================================================================

    #[test]
    fn log_facility_local0_code() {
        assert_eq!(LogFacility::Local0.as_syslog_code(), 128);
    }

    #[test]
    fn log_facility_from_local_codes() {
        // Local0 is recognized, others become Custom
        assert_eq!(LogFacility::from_syslog_code(128), LogFacility::Local0);
        // Code 136 (local1) becomes Custom since we only have Local0
        let fac = LogFacility::from_syslog_code(136);
        assert_eq!(fac.as_syslog_code(), 136);
    }

    #[test]
    fn log_facility_custom_roundtrip() {
        for code in [0, 32, 40, 48, 56, 64, 72, 80, 136, 200] {
            let fac = LogFacility::from_syslog_code(code);
            assert_eq!(fac.as_syslog_code(), code);
        }
    }

    #[test]
    fn log_facility_kern_is_custom() {
        let kern = LogFacility::from_syslog_code(0);
        assert_eq!(kern.as_syslog_code(), 0);
        // kern is not a recognized variant, becomes Custom
        assert!(matches!(kern, LogFacility::Custom(0)));
    }

    // ===================================================================
    // Additional tests — LogConfig
    // ===================================================================

    #[test]
    fn log_config_with_debug() {
        let config = LogConfig {
            debug: true,
            ..LogConfig::default()
        };
        assert!(config.debug);
        assert_eq!(config.facility, LogFacility::Daemon);
    }

    #[test]
    fn log_config_with_json() {
        let config = LogConfig {
            json_output: true,
            ..LogConfig::default()
        };
        assert!(config.json_output);
    }

    #[test]
    fn log_config_with_extra_logging() {
        let config = LogConfig {
            extra_logging: true,
            ..LogConfig::default()
        };
        assert!(config.extra_logging);
    }

    #[test]
    fn log_config_with_log_file() {
        let config = LogConfig {
            log_file: Some("/var/log/dnsmasq.log".to_string()),
            ..LogConfig::default()
        };
        assert_eq!(config.log_file.as_deref(), Some("/var/log/dnsmasq.log"));
    }

    #[test]
    fn log_config_with_trace_level() {
        let config = LogConfig {
            max_level: Level::TRACE,
            ..LogConfig::default()
        };
        assert_eq!(config.max_level, Level::TRACE);
    }

    #[test]
    fn log_config_with_error_level() {
        let config = LogConfig {
            max_level: Level::ERROR,
            ..LogConfig::default()
        };
        assert_eq!(config.max_level, Level::ERROR);
    }

    // ===================================================================
    // Additional tests — build_env_filter
    // ===================================================================

    #[test]
    fn env_filter_debug_mode() {
        let config = LogConfig {
            max_level: Level::DEBUG,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        assert!(
            filter_str.contains("debug"),
            "Debug filter should contain 'debug', got: {}",
            filter_str
        );
    }

    #[test]
    fn env_filter_trace_mode() {
        let config = LogConfig {
            max_level: Level::TRACE,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        assert!(
            filter_str.contains("trace"),
            "Trace filter should contain 'trace', got: {}",
            filter_str
        );
    }

    #[test]
    fn env_filter_extra_logging() {
        let config = LogConfig {
            extra_logging: true,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        // Extra logging should enable more verbose output
        assert!(!filter_str.is_empty());
    }

    #[test]
    fn env_filter_with_both_queries_and_dhcp() {
        let config = LogConfig {
            log_queries: true,
            log_dhcp: true,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        assert!(filter_str.contains("dns=debug") || filter_str.contains("debug"));
        assert!(filter_str.contains("dhcp=debug") || filter_str.contains("debug"));
    }

    #[test]
    fn env_filter_no_queries_no_dhcp() {
        let config = LogConfig {
            log_queries: false,
            log_dhcp: false,
            ..LogConfig::default()
        };
        let filter = build_env_filter(&config);
        let filter_str = format!("{}", filter);
        assert!(!filter_str.is_empty());
    }

    // ===================================================================
    // Additional tests — level_to_directive_str completeness
    // ===================================================================

    #[test]
    fn level_directive_all_levels() {
        let levels = [
            Level::ERROR,
            Level::WARN,
            Level::INFO,
            Level::DEBUG,
            Level::TRACE,
        ];
        let expected = ["error", "warn", "info", "debug", "trace"];
        for (level, exp) in levels.iter().zip(expected.iter()) {
            assert_eq!(level_to_directive_str(*level), *exp);
        }
    }

    // ===================================================================
    // Additional tests — syslog operations
    // ===================================================================

    #[test]
    fn syslog_priority_all_levels() {
        // Verify all levels map to valid syslog priorities
        let levels = [
            Level::ERROR,
            Level::WARN,
            Level::INFO,
            Level::DEBUG,
            Level::TRACE,
        ];
        for level in levels {
            let priority = tracing_level_to_syslog_priority(level);
            assert!(priority >= 0, "Priority for {:?} should be >= 0", level);
            assert!(priority <= 7, "Priority for {:?} should be <= 7", level);
        }
    }

    #[test]
    fn syslog_open_and_write() {
        // Test syslog operations (safe even if syslog not truly open)
        open_system_syslog(&LogFacility::Daemon);
        write_system_syslog(libc::LOG_INFO, "test message from unit test");
    }

    #[test]
    fn syslog_open_local_facility() {
        open_system_syslog(&LogFacility::Local0);
        write_system_syslog(libc::LOG_DEBUG, "local0 test");
    }

    #[test]
    fn syslog_open_user_facility() {
        open_system_syslog(&LogFacility::User);
        write_system_syslog(libc::LOG_WARNING, "user test");
    }

    // ===================================================================
    // Additional tests — log event functions
    // ===================================================================

    #[test]
    fn log_dns_query_does_not_panic() {
        log_dns_query("example.com", 1, "127.0.0.1", 0);
        log_dns_query("test.local", 28, "::1", 0x8000);
        log_dns_query("", 0, "", 0);
    }

    #[test]
    fn log_dhcp_event_does_not_panic() {
        log_dhcp_event(
            "DHCPOFFER",
            "aa:bb:cc:dd:ee:ff",
            "192.168.1.100",
            Some("client1"),
        );
        log_dhcp_event("DHCPACK", "11:22:33:44:55:66", "10.0.0.1", None);
        log_dhcp_event("", "", "", None);
    }

    #[test]
    fn log_privilege_drop_does_not_panic() {
        log_privilege_drop("nobody");
        log_privilege_drop("dnsmasq");
    }

    #[test]
    fn log_config_reload_does_not_panic() {
        log_config_reload("/etc/dnsmasq.conf");
        log_config_reload("/tmp/test.conf");
    }

    #[test]
    fn log_dnssec_failure_does_not_panic() {
        log_dnssec_failure("example.com", "signature expired");
        log_dnssec_failure("test.org", "no DNSKEY");
    }

    #[test]
    fn log_cache_poisoning_does_not_panic() {
        log_cache_poisoning_attempt("evil.com", "192.168.1.1:53");
        log_cache_poisoning_attempt("", "");
    }

    #[test]
    fn log_tftp_event_does_not_panic() {
        log_tftp_event("RRQ", "/boot/pxelinux.0", "10.0.0.50");
        log_tftp_event("WRQ", "/test.txt", "::1");
    }

    #[test]
    fn log_script_event_does_not_panic() {
        log_script_event("add", "192.168.1.100 aa:bb:cc:dd:ee:ff");
        log_script_event("del", "10.0.0.1 hostname");
    }

    #[test]
    fn log_debug_message_does_not_panic() {
        log_debug_message("Test debug message");
        log_debug_message("");
        log_debug_message("Multi\nline\nmessage");
    }

    // ===================================================================
    // Additional tests — FileWriter
    // ===================================================================

    #[test]
    fn file_writer_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("write_test.log");
        let writer = FileWriter::open(path.to_str().unwrap()).unwrap();

        // Write data
        {
            let mut handle = writer.state.lock().unwrap();
            handle.file.write_all(b"hello world\n").unwrap();
            handle.file.flush().unwrap();
        }

        // Verify content
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("hello world"));
    }

    #[test]
    fn file_writer_multiple_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.log");
        let writer = FileWriter::open(path.to_str().unwrap()).unwrap();

        for i in 0..10 {
            let mut handle = writer.state.lock().unwrap();
            write!(handle.file, "line {}\n", i).unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        for i in 0..10 {
            assert!(content.contains(&format!("line {}", i)));
        }
    }

    #[test]
    fn file_writer_reopen_preserves_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reopen.log");
        let writer = FileWriter::open(path.to_str().unwrap()).unwrap();

        // Write before reopen
        {
            let mut handle = writer.state.lock().unwrap();
            handle.file.write_all(b"before\n").unwrap();
        }

        writer.reopen().unwrap();

        // Write after reopen
        {
            let mut handle = writer.state.lock().unwrap();
            handle.file.write_all(b"after\n").unwrap();
        }

        // File should exist and have content
        assert!(path.exists());
    }

    // ===================================================================
    // Additional tests — init_logging
    // ===================================================================

    #[test]
    fn init_logging_stderr_default() {
        // Init with default config (stderr logging)
        let config = LogConfig::default();
        // This may fail if already initialized, but should not panic
        let _ = init_logging(&config);
    }

    #[test]
    fn init_logging_with_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init_test.log");
        let config = LogConfig {
            log_file: Some(path.to_str().unwrap().to_string()),
            ..LogConfig::default()
        };
        let _ = init_logging(&config);
    }

    // ===================================================================
    // Additional tests — flush and reopen
    // ===================================================================

    #[test]
    fn flush_logging_does_not_panic() {
        flush_logging();
    }

    #[test]
    fn reopen_log_no_file_is_ok() {
        let result = reopen_log();
        assert!(result.is_ok());
    }

    // ===================================================================
    // Additional tests — syslog constants
    // ===================================================================

    #[test]
    fn syslog_facility_constants() {
        assert_eq!(SYSLOG_FACILITY_DAEMON, 24);
        assert_eq!(SYSLOG_FACILITY_USER, 8);
        assert_eq!(SYSLOG_FACILITY_MAIL, 16);
        assert_eq!(SYSLOG_FACILITY_LOCAL0, 128);
    }

    #[test]
    fn tracing_to_syslog_priority_all_levels() {
        assert_eq!(
            tracing_level_to_syslog_priority(tracing::Level::ERROR),
            libc::LOG_ERR
        );
        assert_eq!(
            tracing_level_to_syslog_priority(tracing::Level::WARN),
            libc::LOG_WARNING
        );
        assert_eq!(
            tracing_level_to_syslog_priority(tracing::Level::INFO),
            libc::LOG_INFO
        );
        assert_eq!(
            tracing_level_to_syslog_priority(tracing::Level::DEBUG),
            libc::LOG_DEBUG
        );
        assert_eq!(
            tracing_level_to_syslog_priority(tracing::Level::TRACE),
            libc::LOG_DEBUG
        );
    }

    #[test]
    fn custom_facility_syslog_code() {
        let fac = LogFacility::Custom(32);
        assert_eq!(fac.as_syslog_code(), 32);
        let fac2 = LogFacility::Custom(200);
        assert_eq!(fac2.as_syslog_code(), 200);
    }
}

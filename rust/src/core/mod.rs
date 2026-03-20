// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! # Core Runtime Module
//!
//! Core runtime infrastructure for the dnsmasq Rust implementation.
//! This module provides the foundational types, event loop, logging,
//! and utility functions that all other modules depend on.
//!
//! ## Sub-modules
//!
//! - [`types`] — Global type definitions: `DaemonState`, `DnsmasqError`, `AllAddr`, event/exit codes
//! - [`daemon`] — Main async event loop, signal handling, daemon bootstrap
//! - [`poll`] — Async I/O abstraction wrapping tokio (replaces C `poll.c`)
//! - [`log`] — Structured logging subsystem (replaces C `log.c`)
//! - [`util`] — String utilities, RNG, network helpers (replaces C `util.c`)
//! - [`pattern`] — Wildcard/glob pattern matching (replaces C `pattern.c`)
//!
//! ## Architecture
//!
//! In C, `dnsmasq.h` served as the universal header included by every source file,
//! and `struct daemon` was a global mutable singleton. In Rust:
//!
//! - Types are defined in `types.rs` and re-exported from this module
//! - [`DaemonState`] replaces the global `struct daemon`, wrapped in `Arc<RwLock<...>>`
//! - The event loop uses `tokio::select!` instead of C's `poll()` system call
//! - Error handling uses `Result<T, DnsmasqError>` instead of C errno + goto
//!
//! ## C Source Mapping
//!
//! | Rust Module   | C Source      | Lines | Description                       |
//! |---------------|---------------|-------|-----------------------------------|
//! | `types.rs`    | `dnsmasq.h`   | 2,233 | Type definitions, struct daemon   |
//! | `daemon.rs`   | `dnsmasq.c`   | 3,827 | Main loop, signal handling, init  |
//! | `poll.rs`     | `poll.c`      |   484 | I/O multiplexing abstraction      |
//! | `log.rs`      | `log.c`       | 1,120 | Logging subsystem                 |
//! | `util.rs`     | `util.c`      | 2,730 | Utility functions                 |
//! | `pattern.rs`  | `pattern.c`   |   648 | Pattern matching                  |
//!
//! ## Usage
//!
//! Other modules import core types via this module for ergonomic access:
//!
//! ```rust,ignore
//! // Preferred: import from the core module root
//! use crate::core::{DaemonState, DnsmasqError, DnsmasqResult};
//! use crate::core::{AllAddr, EventCode, ExitCode, OptionFlags};
//! use crate::core::DaemonRunner;
//! use crate::core::init_logging;
//!
//! // Also valid: import from the specific sub-module
//! use crate::core::types::DaemonState;
//! use crate::core::daemon::DaemonRunner;
//! use crate::core::log::init_logging;
//! ```

// =============================================================================
// Sub-module Declarations
// =============================================================================

/// Global type definitions: `DaemonState`, `DnsmasqError`, `AllAddr`, event/exit codes.
///
/// Replaces type definitions from `dnsmasq.h` (2,233 lines). Provides the central
/// type system including the main daemon state struct, error types, address enums,
/// event codes, exit codes, and runtime option flags.
pub mod types;

/// Main async event loop, signal handling, daemon bootstrap.
///
/// Replaces `dnsmasq.c` main loop and signal handling (3,827 lines). Provides
/// [`DaemonRunner`] which owns the entire daemon lifecycle — from socket binding
/// and privilege separation through the `tokio::select!` event loop to graceful
/// shutdown on `SIGTERM`.
pub mod daemon;

/// Async I/O abstraction wrapping tokio runtime.
///
/// Replaces `poll.c` fd set management (484 lines). Provides [`poll::EventLoop`]
/// for timer scheduling and [`poll::bind_udp`]/[`poll::bind_tcp`] helpers for
/// async socket creation. The entire C `poll_reset()`/`poll_listen()`/`do_poll()`/
/// `poll_check()` cycle is eliminated in favor of tokio's internal epoll/kqueue
/// management.
pub mod poll;

/// Structured logging subsystem using tracing.
///
/// Replaces `log.c` syslog integration (1,120 lines). Provides [`init_logging()`]
/// for tracing subscriber initialization with syslog, JSON, and console output
/// support. The C deadlock-avoidance bounded queue is eliminated because `tracing`
/// macros are inherently non-blocking.
pub mod log;

/// String utilities, RNG, network helpers.
///
/// Replaces `util.c` memory wrappers and utilities (2,730 lines). All C
/// `safe_malloc`/`whine_malloc`/`expand_buf` wrappers are eliminated — Rust's
/// ownership model handles allocation automatically. Provides the SURF RNG for
/// DNS query ID security, DNS name utilities, network helpers, and time functions.
pub mod util;

/// Wildcard/glob pattern matching for DNS names.
///
/// Replaces `pattern.c` hostname pattern validation (648 lines). Provides
/// case-insensitive glob matching, RFC 1123 hostname validation, and DNS-aware
/// pattern matching used by server selection, address filtering, and conntrack
/// integration.
pub mod pattern;

// =============================================================================
// Public Re-exports
// =============================================================================
//
// These re-exports allow other modules to use `use crate::core::DaemonState`
// instead of the longer `use crate::core::types::DaemonState`, providing
// ergonomic access to the most commonly used core types.

// --- Core types used throughout the entire codebase ---

/// Main daemon state struct replacing C's global `struct daemon`.
pub use types::DaemonState;

/// Comprehensive error enum for all dnsmasq subsystems.
pub use types::DnsmasqError;

/// Convenience type alias: `Result<T, DnsmasqError>`.
pub use types::DnsmasqResult;

/// Multi-protocol address enum replacing C's `union all_addr`.
pub use types::AllAddr;

/// Async event codes for signal/timer processing (EVENT_RELOAD..EVENT_TIME).
pub use types::EventCode;

/// Process exit codes (EC_GOOD..EC_MISC).
pub use types::ExitCode;

/// Bit-array storage for 79 runtime boolean option flags.
pub use types::OptionFlags;

// --- Daemon runner for binary entry point ---

/// Main daemon runtime — owns the async event loop, signal handlers,
/// network sockets, and shared daemon state.
pub use daemon::DaemonRunner;

// --- Logging initialization for main.rs ---

/// Initialize the structured logging subsystem (syslog, JSON, or console).
pub use log::init_logging;

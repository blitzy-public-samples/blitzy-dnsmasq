//! Core runtime infrastructure for the dnsmasq daemon.
//!
//! This module provides the foundational runtime services that every other module
//! in the dnsmasq crate depends on:
//!
//! - [`daemon`] — Central daemon state ([`DaemonState`]) replacing C's global `struct daemon`
//! - [`event_loop`] — mio-based poll event loop ([`EventLoop`]) replacing C's `poll.c` + main loop
//! - [`signal`] — Signal handling via self-pipe pattern ([`SignalHandler`], [`Event`])
//! - [`logging`] — Async non-blocking syslog subsystem ([`Logger`])
//! - [`util`] — DNS name validation, pattern matching, I/O helpers
//! - [`prng`] — CSPRNG wrapper ([`Prng`]) replacing SURF PRNG
//! - [`metrics`] — Metric definitions ([`Metric`]), naming, and tracking ([`MetricsStore`])
//!
//! ## Architecture
//!
//! The core module replaces 6 C source files that form the runtime backbone:
//!
//! | C Source File(s)                       | Rust Module      | Description                                   |
//! |----------------------------------------|------------------|-----------------------------------------------|
//! | `src/dnsmasq.c` (init, state)          | `daemon.rs`      | Daemon state decomposed from global singleton  |
//! | `src/dnsmasq.c` (event loop)           | `event_loop.rs`  | mio-based poll loop replacing poll() wrapper   |
//! | `src/dnsmasq.c` (signals)              | `signal.rs`      | Self-pipe signal handling with Event enum       |
//! | `src/poll.c`                           | `event_loop.rs`  | Binary-search poll() → mio::Poll               |
//! | `src/log.c`                            | `logging.rs`     | Async non-blocking syslog with bounded queue   |
//! | `src/util.c` (utilities)               | `util.rs`        | DNS name validation, pattern matching, I/O     |
//! | `src/util.c` (PRNG)                    | `prng.rs`        | SURF PRNG → rand crate CSPRNG                  |
//! | `src/pattern.c`                        | `util.rs`        | Wildcard pattern matching                      |
//! | `src/metrics.c` + `src/metrics.h`      | `metrics.rs`     | Metric enum, naming, and counter storage       |
//!
//! ## Module Declaration Order
//!
//! Modules are declared in dependency order to prevent circular references:
//! 1. `metrics` — standalone, depends only on types crate
//! 2. `prng` — standalone, depends only on `rand` crate
//! 3. `logging` — standalone, depends only on `log`/`tracing` crates
//! 4. `util` — may use logging for error reporting
//! 5. `signal` — uses `nix`, may use logging
//! 6. `event_loop` — uses `mio`, `signal`, `logging`
//! 7. `daemon` — uses `metrics`, `prng`, `types` — declared last as it composes everything
//!
//! ## Re-exports
//!
//! The most commonly used types are re-exported from this module root for ergonomic
//! access by other modules. Instead of C's monolithic `#include "dnsmasq.h"` which
//! pulled in every declaration, consumers import only the specific types they need:
//!
//! ```rust,ignore
//! // Ergonomic import via re-exports
//! use crate::core::{DaemonState, EventLoop, Logger, Metric, MetricsStore, Prng};
//!
//! // Alternatively, direct module access for less common types
//! use crate::core::daemon::OPT_DEBUG;
//! use crate::core::util::check_name;
//! use crate::core::signal::EventDesc;
//! ```

// ============================================================================
// Sub-module declarations (ordered by dependency — leaf modules first)
// ============================================================================

/// Metric definitions, naming, and counter storage.
///
/// Defines the [`Metric`] enum (29 operational metrics) and [`MetricsStore`]
/// for counter management. Replaces `src/metrics.c` (metric_names[] array,
/// clear_metrics()) and `src/metrics.h` (metric enum definition).
pub mod metrics;

/// Cryptographically-secure pseudo-random number generator.
///
/// Provides the [`Prng`] struct wrapping the `rand` crate's ChaCha-based CSPRNG,
/// replacing the C SURF PRNG (Daniel J. Bernstein's algorithm) from `src/util.c`.
/// Used for DNS transaction ID generation (RFC 5452), source port randomization,
/// and DHCP XID generation.
pub mod prng;

/// Async non-blocking syslog subsystem.
///
/// Provides the [`Logger`] struct implementing non-blocking log message delivery
/// to the syslog daemon with bounded queue and connection retry. Replaces
/// `src/log.c` and prevents the syslog/DNS deadlock scenario described therein.
pub mod logging;

/// DNS name validation, pattern matching, and I/O helper functions.
///
/// Contains utility functions used across the codebase including `check_name()`,
/// `legal_hostname()`, `canonicalise()`, `hostname_isequal()`, `wildcard_match()`,
/// `retry_send()`, and `dnsmasq_time()`. Replaces non-PRNG portions of
/// `src/util.c` and `src/pattern.c`.
///
/// Note: This module's contents are accessed directly via `crate::core::util::*`
/// rather than being re-exported, since its numerous functions are only needed
/// by specific consumers.
pub mod util;

/// Signal handling via self-pipe pattern.
///
/// Provides [`SignalHandler`] for async-signal-safe event delivery and the
/// [`Event`] enum mapping POSIX signals to internal event codes. Replaces the
/// signal handling portions of `src/dnsmasq.c` (sig_handler, queue_event,
/// send_event, async_event functions).
pub mod signal;

/// mio-based poll event loop.
///
/// Provides [`EventLoop`] replacing both the poll() wrapper from `src/poll.c`
/// and the main event loop from `src/dnsmasq.c`. Uses `mio::Poll` for O(1)
/// token-based event dispatch instead of the C binary-search pollfd array.
pub mod event_loop;

/// Central daemon state management.
///
/// Provides [`DaemonState`] — the decomposed replacement for C's monolithic
/// global `struct daemon` (100+ fields). Also defines [`OptionFlags`] for the
/// OPT_* bitfield and exit code constants (EC_GOOD, EC_BADCONF, etc.).
/// This is the last module declared because it composes types from `metrics`,
/// `prng`, and the `types` crate.
pub mod daemon;

// ============================================================================
// Re-exports — commonly used types for ergonomic `use crate::core::*` access
// ============================================================================
//
// Only types referenced by other modules (dns, dhcp, net, integration, main.rs)
// are re-exported here. Module-internal types like `OPT_*` constants, `EventDesc`,
// `LogConfig`, etc. are accessed via their specific module paths (e.g.,
// `crate::core::daemon::OPT_DEBUG`) by the consumers that need them.

/// Central daemon state struct — the decomposed replacement for C's global
/// `struct daemon`. Passed as `&mut DaemonState` or `&DaemonState` to all
/// subsystem functions.
pub use daemon::DaemonState;

/// Bitfield for runtime option flags (OPT_BOGUSPRIV, OPT_FILTER, OPT_LOG, etc.).
/// Replaces the C `unsigned int options[OPTION_SIZE]` array with type-safe
/// get/set/clear operations.
pub use daemon::OptionFlags;

/// Exit code constants matching the C `EC_*` defines from `dnsmasq.h`.
/// Used by `main.rs` and error handling throughout the codebase.
pub use daemon::{EC_BADCONF, EC_BADNET, EC_FILE, EC_GOOD, EC_INIT_OFFSET, EC_MISC, EC_NOMEM};

/// mio-based event loop struct replacing the C poll() wrapper and main loop.
pub use event_loop::EventLoop;

/// Non-blocking async logger for syslog and file-based logging.
pub use logging::Logger;

/// Metric type enum with 29 operational metric variants.
pub use metrics::Metric;

/// Counter storage for all daemon metrics, providing get/increment/add/set/clear
/// operations indexed by [`Metric`] variants.
pub use metrics::MetricsStore;

/// CSPRNG wrapper providing rand16/rand32/rand64 random value generation.
pub use prng::Prng;

/// Signal handler using the self-pipe pattern for async-signal-safe event delivery.
pub use signal::SignalHandler;

/// Event types queued through the signal pipe, mapping POSIX signals and
/// internal notifications to typed enum variants.
pub use signal::Event;

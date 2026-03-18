// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Diagnostics and Monitoring
//!
//! Rust implementation of dnsmasq's diagnostic and operational monitoring capabilities.
//!
//! This module provides:
//! - **Packet dumping** ([`dump`]) — pcap-format packet capture for protocol debugging
//! - **File monitoring** ([`inotify`]) — inotify-based configuration change detection
//! - **Runtime metrics** ([`metrics`]) — atomic performance counters for operational visibility
//!
//! ## Feature Gates
//! - `dump` sub-module requires `dumpfile` feature (matches C `HAVE_DUMPFILE`)
//! - `inotify` sub-module requires `inotify` feature AND Linux target OS (matches C `HAVE_INOTIFY`)
//! - `metrics` sub-module is always available (no feature gate, matches C behavior)
//!
//! ## C Source Origin
//! - `dump.rs` ← `src/dump.c` (815 lines)
//! - `inotify.rs` ← `src/inotify.c` (687 lines)
//! - `metrics.rs` ← `src/metrics.c` (315 lines) + `src/metrics.h` (365 lines)

/// Runtime performance counters using atomic operations.
///
/// Provides thread-safe metrics for DNS cache operations, query routing,
/// DHCP transactions, DNSSEC validation, and upstream server performance.
///
/// Always compiled — no feature gate (matches C behavior where metrics are
/// unconditionally available).
pub mod metrics;

/// Async inotify-based file monitoring for configuration change detection.
///
/// Monitors resolv.conf, dynamic DHCP host directories, and DHCP option
/// directories for changes.  Linux-only — on other platforms, dnsmasq falls
/// back to polling.
///
/// Gated by both the `inotify` Cargo feature and `target_os = "linux"`.
#[cfg(all(feature = "inotify", target_os = "linux"))]
pub mod inotify;

/// pcap-format packet dumping for protocol debugging and troubleshooting.
///
/// Captures DNS queries/responses, DHCP transactions, Router Advertisements,
/// and TFTP transfers to standard libpcap files readable by Wireshark/tcpdump.
///
/// Gated by the `dumpfile` Cargo feature (matches C `HAVE_DUMPFILE`).
#[cfg(feature = "dumpfile")]
pub mod dump;

// Re-export key metrics types (used throughout the codebase)
pub use metrics::{MetricType, MetricsStore, ServerStats, METRIC_MAX, METRIC_NAMES};

// Re-export inotify types when the feature is active.
#[cfg(all(feature = "inotify", target_os = "linux"))]
pub use inotify::{dir_flags, InotifyCallbacks, InotifyWatcher};

// Re-export dump types when the dumpfile feature is active.
#[cfg(feature = "dumpfile")]
pub use dump::{mask, PacketDumper};

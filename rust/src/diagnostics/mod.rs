// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// SPDX-License-Identifier: GPL-2.0-or-later
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
//!
//! | Sub-module   | Feature requirement                                  | C equivalent       |
//! |-------------|------------------------------------------------------|-------------------|
//! | [`metrics`] | *(none — always available)*                          | `metrics.c/h`    |
//! | [`dump`]    | `dumpfile`                                            | `HAVE_DUMPFILE`   |
//! | [`inotify`] | `inotify` **and** `target_os = "linux"`               | `HAVE_INOTIFY`    |
//!
//! The diagnostics module itself is **not** feature-gated — it is declared
//! unconditionally in `lib.rs`.  Only individual sub-modules carry their own
//! conditional compilation attributes.
//!
//! ## C Source Origin
//!
//! - `dump.rs` ← `src/dump.c` (815 lines)
//! - `inotify.rs` ← `src/inotify.c` (687 lines)
//! - `metrics.rs` ← `src/metrics.c` (315 lines) + `src/metrics.h` (365 lines)

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Runtime performance counters using atomic operations.
///
/// Provides thread-safe metrics for DNS cache operations, query routing,
/// DHCP transactions, DNSSEC validation, and upstream server performance.
///
/// Always compiled — no feature gate (matches C behavior where `metrics.c`
/// and `metrics.h` have no conditional compilation guards).
pub mod metrics;

/// Packet capture in pcap format for protocol debugging.
///
/// Writes DNS queries/responses, DHCP transactions, Router Advertisement
/// packets, and TFTP transfers to standard libpcap files compatible with
/// Wireshark, tcpdump, and tshark.
///
/// Gated by the `dumpfile` Cargo feature flag, matching C's
/// `#ifdef HAVE_DUMPFILE` guard in `src/dump.c`.
#[cfg(feature = "dumpfile")]
#[cfg_attr(docsrs, doc(cfg(feature = "dumpfile")))]
pub mod dump;

/// Async inotify-based file change monitoring (Linux only).
///
/// Watches `/etc/resolv.conf`, dynamic DHCP host directories, and DHCP
/// option directories for changes.  Uses tokio for async I/O integration
/// with the main event loop.
///
/// Gated by **both** the `inotify` Cargo feature flag **and**
/// `target_os = "linux"`, matching C's `#ifdef HAVE_INOTIFY` guard
/// in `src/inotify.c`.  On non-Linux platforms, dnsmasq falls back
/// to polling-based configuration checking.
#[cfg(all(feature = "inotify", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "inotify", target_os = "linux"))))]
pub mod inotify;

// ---------------------------------------------------------------------------
// Public re-exports — metrics (always available)
// ---------------------------------------------------------------------------

/// Performance metric type identifiers (re-exported from [`metrics`]).
///
/// Enum with 30 variants covering DNS, DHCP, DNSSEC, and network metrics.
/// Always available — no feature gate required.
pub use metrics::MetricType;

/// Thread-safe runtime metrics store (re-exported from [`metrics`]).
///
/// Atomic counter array indexed by [`MetricType`] for lock-free metric
/// collection across async tasks.  Always available — no feature gate required.
pub use metrics::MetricsStore;

/// Per-upstream-server performance statistics (re-exported from [`metrics`]).
///
/// Tracks queries, failures, retries, NXDOMAIN replies, and latency per
/// upstream DNS server.  Always available — no feature gate required.
pub use metrics::ServerStats;

/// Human-readable metric name strings (re-exported from [`metrics`]).
///
/// Array of 30 `&str` entries indexed by [`MetricType`] discriminant,
/// matching C's `metric_names[]` for D-Bus/UBus export compatibility.
/// Always available — no feature gate required.
pub use metrics::METRIC_NAMES;

/// Total number of defined metric types (re-exported from [`metrics`]).
///
/// Equal to `30`, matching C's `__METRIC_MAX` sentinel.
/// Always available — no feature gate required.
pub use metrics::METRIC_MAX;

// ---------------------------------------------------------------------------
// Public re-exports — dump (feature-gated: dumpfile)
// ---------------------------------------------------------------------------

/// Packet dumper for pcap-format capture (re-exported from [`dump`]).
///
/// Provides [`PacketDumper::new()`], [`PacketDumper::dump_packet_udp()`],
/// and [`PacketDumper::dump_packet_icmp()`] for capturing network packets
/// to libpcap files.
///
/// Only available when the `dumpfile` feature is enabled.
#[cfg(feature = "dumpfile")]
#[cfg_attr(docsrs, doc(cfg(feature = "dumpfile")))]
pub use dump::PacketDumper;

/// Dump mask bit-flag constants (re-exported from [`dump`]).
///
/// Contains `DUMP_QUERY`, `DUMP_REPLY`, `DUMP_UP_QUERY`, `DUMP_DHCP`,
/// `DUMP_RA`, `DUMP_TFTP`, and other flags controlling which packet types
/// are written to the pcap dump file.  Matches C `DUMP_*` defines in
/// `src/dnsmasq.h` lines 922–933.
///
/// Only available when the `dumpfile` feature is enabled.
#[cfg(feature = "dumpfile")]
#[cfg_attr(docsrs, doc(cfg(feature = "dumpfile")))]
pub use dump::mask;

// ---------------------------------------------------------------------------
// Public re-exports — inotify (feature-gated: inotify + linux)
// ---------------------------------------------------------------------------

/// Async inotify watcher (re-exported from [`inotify`]).
///
/// Monitors configuration files and dynamic directories for changes,
/// integrating with the tokio event loop via [`AsyncFd`](tokio::io::unix::AsyncFd).
///
/// Only available when `inotify` feature is enabled **and** `target_os = "linux"`.
#[cfg(all(feature = "inotify", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "inotify", target_os = "linux"))))]
pub use inotify::InotifyWatcher;

/// Callback trait for inotify event handling (re-exported from [`inotify`]).
///
/// Decouples the inotify watcher from DNS cache, DHCP, and configuration
/// modules.  Implementors provide reload actions triggered by file-change events.
///
/// Only available when `inotify` feature is enabled **and** `target_os = "linux"`.
#[cfg(all(feature = "inotify", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "inotify", target_os = "linux"))))]
pub use inotify::InotifyCallbacks;

/// Dynamic directory flag constants (re-exported from [`inotify`]).
///
/// Contains `AH_DIR`, `AH_INACTIVE`, `AH_WD_DONE`, `AH_HOSTS`,
/// `AH_DHCP_HST`, and `AH_DHCP_OPT` flags matching C `AH_*` defines
/// in `src/dnsmasq.h` lines 898–903.
///
/// Only available when `inotify` feature is enabled **and** `target_os = "linux"`.
#[cfg(all(feature = "inotify", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "inotify", target_os = "linux"))))]
pub use inotify::dir_flags;

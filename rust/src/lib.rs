// dnsmasq — Memory-safe DNS forwarder, DHCP server, and network boot daemon
//
// Copyright (c) 2000-2025 Simon Kelley
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

//! # dnsmasq — Memory-safe DNS forwarder, DHCP server, and network boot daemon
//!
//! This library implements the complete dnsmasq v2.92 functionality in Rust,
//! providing a memory-safe drop-in replacement for the C implementation.
//!
//! ## Architecture
//!
//! The library is organized into modules mirroring the C source structure:
//! - [`config`] — Configuration parsing and constants (from `config.h`, `option.c`)
//! - [`core`] — Core runtime, event loop, logging, utilities (from `dnsmasq.c`, `log.c`, `util.c`)
//! - [`dns`] — DNS subsystem: forwarding, caching, DNSSEC (from `forward.c`, `cache.c`, etc.)
//! - [`dhcp`] — DHCP v4/v6 server, leases, Router Advertisement (from `dhcp.c`, `rfc2131.c`, etc.)
//! - [`network`] — Network interface management, platform abstraction (from `network.c`)
//! - [`integration`] — External integrations: D-Bus, scripts, ipset (from `dbus.c`, `helper.c`)
//! - [`services`] — TFTP server and PXE boot (from `tftp.c`)
//! - [`diagnostics`] — Packet dump, inotify, metrics (from `dump.c`, `metrics.c`)
//!
//! ## Memory Safety
//!
//! All C manual memory management (`malloc`/`free`/`realloc`) has been replaced with
//! Rust's ownership system, `Vec`, `Box`, `String`, `Arc`, and `Rc`.
//! Zero `unsafe` blocks in core logic; FFI exceptions are documented in SAFETY.md.
//!
//! ## Feature Flags
//!
//! Optional functionality is gated by Cargo features matching C `HAVE_*` macros:
//!
//! | Feature | C Macro | Default | Description |
//! |---------|---------|---------|-------------|
//! | `dhcp` | `HAVE_DHCP` | enabled | DHCPv4 server |
//! | `dhcp6` | `HAVE_DHCP6` | enabled | DHCPv6 server (implies `dhcp`) |
//! | `tftp` | `HAVE_TFTP` | enabled | TFTP server and PXE boot |
//! | `script` | `HAVE_SCRIPT` | enabled | Lease-change script execution |
//! | `auth` | `HAVE_AUTH` | enabled | Authoritative DNS zones |
//! | `ipset` | `HAVE_IPSET` | enabled | Linux ipset integration |
//! | `loop-detect` | `HAVE_LOOP` | enabled | DNS forwarding loop detection |
//! | `dumpfile` | `HAVE_DUMPFILE` | enabled | Packet dump for debugging |
//! | `inotify` | `HAVE_INOTIFY` | enabled | File change monitoring (Linux) |
//! | `dnssec` | `HAVE_DNSSEC` | disabled | DNSSEC validation |
//! | `dbus` | `HAVE_DBUS` | disabled | D-Bus/NetworkManager integration |
//! | `ubus` | `HAVE_UBUS` | disabled | OpenWrt ubus integration |
//! | `idn` | `HAVE_IDN` | disabled | International domain names |
//! | `conntrack` | `HAVE_CONNTRACK` | disabled | Linux conntrack mark support |
//! | `nftset` | `HAVE_NFTSET` | disabled | nftables set integration |
//! | `luascript` | `HAVE_LUASCRIPT` | disabled | Lua scripting support |
//!
//! See `Cargo.toml` for the complete feature flag mapping and dependency details.

// =============================================================================
// Crate-Level Lint Configuration
// =============================================================================
//
// NOTE ON CLIPPY SUPPRESSIONS:
// This crate has ~50 crate-level `#[allow(clippy::...)]` directives below.
// Each suppression is documented with its rationale (casting for wire-format
// protocol code, FFI pointer operations, style choices mirroring C patterns,
// struct shapes dictated by the protocol, etc.).  These are crate-wide rather
// than per-module because the same patterns recur across most modules in this
// protocol-heavy networking daemon.  As the port stabilises, individual
// suppressions should be periodically reviewed: remove any that no longer
// trigger, and migrate remaining ones to per-module `#[allow(...)]` where
// they apply to only a subset of modules.
// =============================================================================

// No unsafe code in core logic per AAP Section 0.7.1.  FFI exceptions in
// platform-specific modules (e.g., network/netlink.rs, network/bpf.rs) use
// `#![allow(unsafe_code)]` at the module level with `// SAFETY:` documentation.
#![deny(unsafe_code)]
// Enable comprehensive Clippy lint checking including pedantic lints.
// Specific pedantic categories that are intentional style choices in this
// protocol-heavy codebase are suppressed below to keep the signal-to-noise
// ratio high while still catching genuine issues.
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
// ---------------------------------------------------------------------------
// Documentation lints: Suppressed during active development of the C-to-Rust
// migration. Documentation will be added incrementally as modules stabilize.
// ---------------------------------------------------------------------------
#![allow(missing_docs)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
// ---------------------------------------------------------------------------
// Casting lints: Protocol and FFI code (DNS/DHCP packet construction, raw
// socket operations) requires extensive integer casts between wire format
// widths (u8, u16, u32) and Rust's native types (usize). These are
// intentional and reviewed for correctness at each call site.
// ---------------------------------------------------------------------------
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_ptr_alignment)]
// ---------------------------------------------------------------------------
// Pointer and FFI lints: Platform-specific FFI code (netlink, BPF, syslog,
// raw sockets) operates on raw pointers. These casts are confined to modules
// with `#![allow(unsafe_code)]` and accompanied by SAFETY comments.
// ---------------------------------------------------------------------------
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::ptr_cast_constness)]
#![allow(clippy::borrow_as_ptr)]
// ---------------------------------------------------------------------------
// Style and readability lints: Suppressed as intentional style choices for
// this codebase. Protocol code benefits from explicit iteration, match arms,
// and format patterns for readability during code review.
// ---------------------------------------------------------------------------
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::implicit_clone)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::single_match_else)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::if_not_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::needless_continue)]
#![allow(clippy::redundant_else)]
#![allow(clippy::unnested_or_patterns)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::large_stack_arrays)]
#![allow(clippy::ignored_unit_patterns)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::option_as_ref_cloned)]
#![allow(clippy::ip_constant)]
// ---------------------------------------------------------------------------
// Naming and structure lints: Protocol structs mirror C `struct daemon` which
// has 100+ boolean fields and similar variable names by necessity. Function
// sizes reflect the complexity of protocol state machines (e.g., DHCPv4
// DISCOVER/OFFER/REQUEST/ACK flow).
// ---------------------------------------------------------------------------
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::unreadable_literal)]
// ---------------------------------------------------------------------------
// Cloning and ownership lints: Some patterns (e.g., .to_string() on &String,
// pass-by-value for API consistency) are deliberate design choices for the
// interface contracts between modules.
// ---------------------------------------------------------------------------
#![allow(clippy::inefficient_to_string)]
#![allow(clippy::cloned_instead_of_copied)]
#![allow(clippy::assigning_clones)]
// ---------------------------------------------------------------------------
// Function signature lints: Some wrapper functions return Result for API
// consistency even when they cannot currently fail; some async functions are
// placeholders for future async I/O integration; self parameters are kept
// for trait conformance.
// ---------------------------------------------------------------------------
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::unused_async)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::ref_option)]
// ---------------------------------------------------------------------------
// Miscellaneous lints
// ---------------------------------------------------------------------------
#![allow(clippy::items_after_statements)]
#![allow(clippy::no_effect_underscore_binding)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::used_underscore_items)]
#![allow(clippy::format_push_string)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::match_bool)]
#![allow(clippy::range_plus_one)]
#![allow(clippy::format_collect)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::missing_fields_in_debug)]

// =============================================================================
// Module Declarations
// =============================================================================
//
// Module hierarchy mirrors the C source structure per AAP Section 0.4.1.
// Feature-gated modules use `#[cfg(feature = "...")]` matching C `HAVE_*` macros.
//
// C header files (dnsmasq.h, config.h, dns-protocol.h, dhcp-protocol.h,
// dhcp6-protocol.h, radv-protocol.h, ip6addr.h, metrics.h) are dissolved
// into Rust module-level type/trait/struct/const definitions — they do not
// exist as separate Rust modules.

/// Configuration parsing, constants, feature flags, and CLI handling.
///
/// Provides the complete configuration pipeline: compile-time constants and
/// resource limits ([`config::constants`]), Cargo feature flag detection
/// ([`config::features`]), INI-style config file parser for 350+
/// `dnsmasq.conf` directives ([`config::options`]), and CLI argument
/// processing via clap ([`config::cli`]).
///
/// Key re-exports: [`DnsmasqConfig`], [`CliArgs`], `ConfigError`, `load_config()`.
///
/// Source: `src/config.h` (3,020 lines), `src/option.c` (8,128 lines).
pub mod config;

/// Core runtime: daemon event loop, types, logging, and utilities.
///
/// Provides the foundational type system ([`core::types`]) including
/// [`DaemonState`], [`DnsmasqError`], and [`DnsmasqResult`]; the main async
/// event loop ([`core::daemon`]); structured logging ([`core::log`]); and
/// utility functions ([`core::util`], [`core::pattern`]).
///
/// Source: `src/dnsmasq.c` (3,827 lines), `src/dnsmasq.h` (2,233 lines),
/// `src/log.c` (1,120 lines), `src/util.c` (2,730 lines),
/// `src/pattern.c` (648 lines), `src/poll.c` (484 lines).
pub mod core;

/// DNS subsystem: forwarding, caching, wire format, DNSSEC.
///
/// Always present (not feature-gated) since DNS forwarding is core dnsmasq
/// functionality. Contains the query forwarding engine, DNS cache with TTL
/// eviction, wire format parsing/construction (RFC 1035), EDNS0 extensions,
/// resource record filtering, domain matching, and optional DNSSEC validation.
///
/// Sub-modules include: [`dns::protocol`], [`dns::forward`], [`dns::cache`],
/// [`dns::edns`], [`dns::rrfilter`], [`dns::domain_match`], [`dns::domain`],
/// and feature-gated [`dns::dnssec`], [`dns::crypto`], [`dns::blockdata`],
/// [`dns::auth`], [`dns::loop_detect`].
///
/// Source: 13 C source files totaling 21,856 lines.
pub mod dns;

/// DHCP v4/v6 server, lease management, Router Advertisement.
///
/// Contains the DHCPv4 server (DISCOVER/OFFER/REQUEST/ACK state machine),
/// DHCPv6 server (SOLICIT/ADVERTISE/REQUEST/REPLY), shared DHCP utilities,
/// lease persistence, IPv6 Router Advertisement, and SLAAC tracking.
///
/// Sub-modules: [`dhcp::v4`], [`dhcp::v6`] (cfg `dhcp6`), [`dhcp::common`],
/// [`dhcp::lease`], [`dhcp::radv`] (cfg `dhcp6`), [`dhcp::slaac`] (cfg `dhcp6`),
/// [`dhcp::ip6addr`].
///
/// Feature-gated by `cfg(feature = "dhcp")`, mapping to C's `HAVE_DHCP`.
///
/// Source: 13 C source files totaling 20,569 lines.
#[cfg(feature = "dhcp")]
pub mod dhcp;

/// Network interface management and platform-specific abstractions.
///
/// Always present. Contains interface enumeration, socket binding,
/// listener management, platform-specific backends (netlink on Linux,
/// BPF on BSD), and ARP cache management.
///
/// Sub-modules: [`network::interface`], [`network::netlink`] (Linux),
/// [`network::bpf`] (BSD/macOS), [`network::arp`].
///
/// Source: `src/network.c` (6,331 lines), `src/netlink.c` (740 lines),
/// `src/bpf.c` (805 lines), `src/arp.c` (475 lines).
pub mod network;

/// External integrations: D-Bus, ubus, scripts, firewall sets.
///
/// Always present at the module level, but individual sub-modules are
/// independently feature-gated: D-Bus ([`integration::dbus`] — `dbus`),
/// OpenWrt UBus ([`integration::ubus`] — `ubus`), script execution
/// ([`integration::helper`] — `script`), conntrack marks
/// ([`integration::conntrack`] — `conntrack`), ipset
/// ([`integration::ipset`] — `ipset`), nftables sets
/// ([`integration::nftset`] — `nftset`), and BSD routing tables
/// ([`integration::tables`] — auto-detected via `target_os`).
///
/// Source: 7 C source files totaling 6,038 lines.
pub mod integration;

/// Network services: TFTP server, PXE boot.
///
/// Feature-gated by `cfg(feature = "tftp")`, mapping to C's `HAVE_TFTP`.
/// Implements RFC 1350 (TFTP), RFC 2349 (option negotiation), and
/// RFC 7440 (windowsize) for network boot scenarios.
///
/// Source: `src/tftp.c` (1,647 lines).
#[cfg(feature = "tftp")]
pub mod services;

/// Diagnostics: packet dump, file monitoring, runtime metrics.
///
/// Always present at the module level. Individual sub-modules are feature-gated:
/// packet dump ([`diagnostics::dump`] — `dumpfile`), inotify file monitoring
/// ([`diagnostics::inotify`] — `inotify` + Linux), while runtime metrics
/// ([`diagnostics::metrics`]) are always available.
///
/// Source: `src/dump.c` (815 lines), `src/inotify.c` (687 lines),
/// `src/metrics.c` (315 lines), `src/metrics.h` (365 lines).
pub mod diagnostics;

// =============================================================================
// Public Re-exports
// =============================================================================
//
// These re-exports replace C's dnsmasq.h pattern where all types and function
// prototypes were accessible via a single `#include "dnsmasq.h"`.  They provide
// ergonomic crate-root access to the most commonly used types, so consumers
// can write `use dnsmasq::{DaemonState, DnsmasqConfig, DnsmasqError};`
// instead of navigating the module hierarchy for everyday types.

// --- Core types (replaces C struct daemon, union all_addr, errno patterns) ---

/// Main daemon state struct replacing C's global `struct daemon`.
///
/// In C, `struct daemon` was a single global instance accessed by all modules.
/// In Rust, [`DaemonState`] is wrapped in `Arc<RwLock<DaemonState>>` and passed
/// explicitly through function parameters.
pub use crate::core::types::DaemonState;

/// Comprehensive error enum for all dnsmasq subsystems.
///
/// Replaces C's errno checking and `goto` cleanup patterns with idiomatic
/// Rust `Result`-based error handling via the `?` operator.  Variants include
/// [`DnsmasqError::Config`], [`DnsmasqError::Network`], [`DnsmasqError::Io`],
/// [`DnsmasqError::DnsProtocol`], [`DnsmasqError::Dhcp`],
/// [`DnsmasqError::Privilege`], [`DnsmasqError::Dnssec`],
/// [`DnsmasqError::Lease`], and [`DnsmasqError::Fatal`].
pub use crate::core::types::DnsmasqError;

/// Convenience type alias: `Result<T, DnsmasqError>`.
///
/// Used as the return type for all fallible operations throughout the crate.
pub use crate::core::types::DnsmasqResult;

// --- Configuration types (used by binary entry point) ---

/// Primary configuration struct containing all 350+ dnsmasq.conf directives.
///
/// Produced by parsing CLI arguments and configuration files via
/// [`DnsmasqConfig::load()`].  Contains fields for DNS settings
/// ([`DnsmasqConfig::dns_port`], [`DnsmasqConfig::cache_size`],
/// [`DnsmasqConfig::servers`]), network binding, host/domain records,
/// DHCP configuration, and logging.  Used by `main.rs` to initialize the daemon.
pub use crate::config::options::DnsmasqConfig;

/// CLI argument struct for command-line parsing via clap.
///
/// Defines all command-line flags matching C dnsmasq's exact CLI interface
/// for drop-in replacement compatibility.  Includes flags like
/// [`CliArgs::listen_address`], [`CliArgs::port`], [`CliArgs::server`],
/// [`CliArgs::conf_file`], [`CliArgs::no_daemon`], [`CliArgs::user`],
/// and [`CliArgs::group`].  Used by `main.rs` for argument parsing.
pub use crate::config::cli::CliArgs;

/// Compile-time constants module re-exported at crate root.
///
/// Contains all numeric constants from C `config.h` including:
/// - DNS limits: [`constants::FTABSIZ`], [`constants::CACHESIZ`],
///   [`constants::EDNS_PKTSZ`], [`constants::PACKETSZ`], [`constants::MAXDNAME`]
/// - DHCP limits: [`constants::MAXLEASES`], [`constants::DEFLEASE`],
///   [`constants::DEFLEASE6`]
/// - Process limits: [`constants::MAX_PROCS`], [`constants::TIMEOUT`]
/// - Default file paths: [`constants::CONFFILE`], [`constants::LEASEFILE`],
///   [`constants::RESOLVFILE`], [`constants::RUNFILE`]
/// - Privilege settings: [`constants::CHUSER`], [`constants::CHGRP`]
/// - Zone TTL: [`constants::AUTH_TTL`]
///
/// Enables `use dnsmasq::constants::CACHESIZ;` at the crate root level.
pub use crate::config::constants;

// =============================================================================
// Version and Copyright Constants
// =============================================================================

/// dnsmasq version string identifying the Rust port of v2.92.
///
/// The `"-rust"` suffix distinguishes this binary from the original C
/// implementation (`VERSION "2.92"` in the Makefile) so that operators,
/// monitoring systems, and log parsers can identify which implementation
/// is running. The base version matches the C release for compatibility,
/// while the suffix signals the Rust memory-safe rewrite.
pub const VERSION: &str = "2.92-rust";

/// Copyright notice matching C source header.
///
/// Defined in C `dnsmasq.h` line 95:
/// `#define COPYRIGHT "Copyright (c) 2000-2025 Simon Kelley"`.
/// Displayed in `--version` output and startup logging.
pub const COPYRIGHT: &str = "Copyright (c) 2000-2025 Simon Kelley";

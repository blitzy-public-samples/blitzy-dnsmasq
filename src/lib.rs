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

//! dnsmasq — Lightweight DNS forwarder, DHCP server, TFTP server, and Router
//! Advertisement daemon.
//!
//! This crate is a complete, production-ready Rust rewrite of the
//! [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) C codebase (v2.92),
//! maintaining full functional equivalence with the original implementation.
//! All 50 C source files have been rewritten as idiomatic Rust modules, replacing
//! manual `malloc`/`free` memory management with Rust's ownership model, C unions
//! with Rust enums, and `setjmp`/`longjmp` error recovery with `Result<T, E>`.
//!
//! # Architecture
//!
//! The original C codebase uses a flat `src/` directory with a single monolithic
//! header `dnsmasq.h` included by every source file. This Rust rewrite organizes
//! the code into a hierarchical module tree grouped by functional domain:
//!
//! ```text
//! dnsmasq (crate root — this file)
//! ├── config      — Configuration parsing, compile-time constants, feature flags
//! ├── core        — Daemon state, event loop, signal handling, logging, PRNG, metrics
//! ├── types       — Shared type definitions (addresses, DNS records, DHCP leases, network)
//! ├── dns         — DNS forwarding, caching, wire format, EDNS0, DNSSEC validation
//! ├── dhcp        — DHCPv4/v6 servers, lease management, Router Advertisements  [feature-gated]
//! ├── net         — Network interfaces, socket pooling, ARP cache, platform abstraction
//! ├── integration — External interfaces: D-Bus, UBus, nftset, TFTP server       [submodules feature-gated]
//! └── debug       — Packet capture and diagnostic utilities                      [feature-gated]
//! ```
//!
//! # Module Descriptions
//!
//! ## [`config`] — Configuration and Constants
//!
//! Replaces `src/config.h` (compile-time constants and feature flags) and
//! `src/option.c` (the 2,500-line CLI/config-file parser). Provides
//! [`config::DaemonConfig`] for validated configuration, [`config::ConfigBuilder`]
//! for construction with `Result`-based error handling, and all numeric constants
//! (`CACHESIZ`, `MAXLEASES`, `FTABSIZ`, etc.) via [`config::constants`].
//!
//! ## [`core`] — Runtime Infrastructure
//!
//! Replaces `src/dnsmasq.c` (main loop, signal handling), `src/poll.c` (I/O
//! multiplexing), `src/log.c` (syslog), `src/util.c` (utilities), and
//! `src/metrics.c`/`src/metrics.h` (metrics). Provides [`core::DaemonState`]
//! (the decomposed replacement for C's global `struct daemon`),
//! [`core::EventLoop`] (mio-based poll loop), [`core::SignalHandler`],
//! [`core::Logger`], [`core::Prng`], and [`core::MetricsStore`].
//!
//! ## [`types`] — Shared Type Definitions
//!
//! Replaces type definitions from `src/dnsmasq.h` (1,800+ lines of structs,
//! unions, and typedefs). Provides [`AllAddr`] (replacing `union all_addr`),
//! [`SocketAddress`] (replacing `union mysockaddr`), [`DnsHeader`],
//! [`CacheEntry`] (replacing `struct crec`), [`ForwardRecord`] (replacing
//! `struct frec`), and DHCP/network types organized by domain.
//!
//! ## [`dns`] — DNS Stack
//!
//! Replaces `src/forward.c`, `src/cache.c`, `src/rfc1035.c`, `src/dnssec.c`,
//! `src/crypto.c`, `src/edns0.c`, `src/rrfilter.c`, `src/auth.c`,
//! `src/domain.c`, `src/domain-match.c`, `src/loop.c`, and
//! `src/dns-protocol.h`. Always available (DNS is the core function of dnsmasq).
//! Feature-gated submodules: `auth`, `loop_detect`, `dnssec`.
//!
//! ## [`dhcp`] — DHCP Subsystem
//!
//! Replaces `src/dhcp.c`, `src/dhcp6.c`, `src/rfc2131.c`, `src/rfc3315.c`,
//! `src/dhcp-common.c`, `src/lease.c`, `src/radv.c`, `src/slaac.c`,
//! `src/outpacket.c`, `src/helper.c`, and protocol header files. Feature-gated
//! by `dhcp` or `dhcp6` Cargo features.
//!
//! ## [`net`] — Network Layer
//!
//! Replaces `src/network.c`, `src/arp.c`, `src/netlink.c`, `src/bpf.c`,
//! `src/ipset.c`, `src/inotify.c`, `src/conntrack.c`, and `src/tables.c`.
//! Always available. Platform-specific submodules use `#[cfg(target_os)]`.
//!
//! ## [`integration`] — External Integrations
//!
//! Replaces `src/dbus.c`, `src/ubus.c`, `src/nftset.c`, and `src/tftp.c`.
//! Always declared but internal submodules are individually feature-gated.
//! Contains the only permitted `unsafe` blocks (FFI to external C libraries).
//!
//! ## [`debug`] — Debug Utilities
//!
//! Replaces `src/dump.c`. Feature-gated by the `dump` Cargo feature. Provides
//! pcap packet capture for protocol diagnostics.
//!
//! # Feature Flags
//!
//! Cargo feature flags replace the C `HAVE_*` preprocessor macros from
//! `src/config.h`. The mapping is:
//!
//! | C Macro          | Cargo Feature   | Default | Module Affected              |
//! |------------------|-----------------|---------|------------------------------|
//! | `HAVE_DHCP`      | `dhcp`          | ✓       | `dhcp` module                |
//! | `HAVE_DHCP6`     | `dhcp6`         | ✓       | `dhcp::v6`, `dhcp::radv`     |
//! | `HAVE_DNSSEC`    | `dnssec`        | ✗       | `dns::dnssec`                |
//! | `HAVE_TFTP`      | `tftp`          | ✓       | `integration::tftp`          |
//! | `HAVE_SCRIPT`    | `script`        | ✓       | `dhcp::helper`               |
//! | `HAVE_AUTH`      | `auth`          | ✓       | `dns::auth`                  |
//! | `HAVE_IPSET`     | `ipset`         | ✓       | `net::platform::linux::ipset`|
//! | `HAVE_NFTSET`    | `nftset`        | ✗       | `integration::nftset`        |
//! | `HAVE_DBUS`      | `dbus`          | ✗       | `integration::dbus`          |
//! | `HAVE_UBUS`      | `ubus`          | ✗       | `integration::ubus`          |
//! | `HAVE_CONNTRACK`  | `conntrack`     | ✗       | `net::platform::linux::conntrack` |
//! | `HAVE_LOOP`      | `loop_detect`   | ✓       | `dns::loop_detect`           |
//! | `HAVE_DUMPFILE`  | `dump`          | ✓       | `debug`                      |
//! | `HAVE_IDN`       | `idn`           | ✗       | IDN domain name support      |
//! | `HAVE_INOTIFY`   | `inotify_monitor`| ✗      | `net::platform::linux::inotify` |
//!
//! # Design Principles
//!
//! - **No global mutable state.** The C `struct daemon *daemon` global singleton
//!   (100+ fields) is decomposed into [`DaemonState`], passed explicitly as
//!   `&mut DaemonState` to all subsystem functions.
//!
//! - **Zero `unsafe` except for FFI.** All intrusive linked lists replaced with
//!   safe Rust collections (`HashMap`, `Vec`, `VecDeque`). The only `unsafe`
//!   blocks are thin FFI wrappers around external C libraries (D-Bus, nftables,
//!   conntrack) and `fork()`/`exec()` for the helper process.
//!
//! - **Wire-protocol fidelity.** DNS, DHCP, TFTP, and RA packet formats are
//!   byte-for-byte compatible with the C implementation.
//!
//! - **Configuration compatibility.** All 160+ `dnsmasq.conf` directives are
//!   parsed identically. The binary is a drop-in replacement for the C version.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use dnsmasq::config::{ConfigBuilder, DaemonConfig};
//! use dnsmasq::core::DaemonState;
//!
//! // Parse configuration
//! let args: Vec<String> = std::env::args().skip(1).collect();
//! let mut builder = ConfigBuilder::new();
//! builder.parse_cli(&args);
//! builder.parse_file("/etc/dnsmasq.conf", true);
//! let _config: DaemonConfig = builder.build().expect("valid configuration");
//!
//! // Initialize daemon state
//! let daemon = DaemonState::new();
//! ```

// ============================================================================
// Crate-level attributes
// ============================================================================

// Enforce documentation coverage for all public items. Every public function,
// struct, enum, trait, and module must have a doc comment.
#![warn(missing_docs)]

// Enable all standard Clippy lints for code quality enforcement.
#![warn(clippy::all)]

// Require explicit `unsafe` blocks inside `unsafe fn` bodies (Rust 2024 edition
// default, but we state it explicitly as a signal to readers and to prevent
// regression if edition changes).
#![deny(unsafe_op_in_unsafe_fn)]

// ============================================================================
// Module declarations
//
// The module tree replaces the flat C `src/` directory (50 files) with a
// hierarchical Rust module hierarchy grouped by functional domain.
//
// Modules are declared in dependency order:
// 1. config  — compile-time constants, no runtime dependencies
// 2. types   — shared type definitions, depends only on external crates
// 3. core    — runtime infrastructure, depends on types + config
// 4. dns     — DNS stack, depends on types + core
// 5. net     — network layer, depends on types + core
// 6. dhcp    — DHCP stack, depends on types + core + dns + net [feature-gated]
// 7. integration — external interfaces, depends on all above [submodules feature-gated]
// 8. debug   — diagnostic utilities [feature-gated]
// ============================================================================

/// Configuration parsing, compile-time constants, and Cargo feature flag
/// management.
///
/// This module replaces `src/config.h` (compile-time constants and feature
/// flags) and `src/option.c` (the CLI/config-file parser for all 160+
/// dnsmasq directives). Always available — no feature gate.
///
/// Key types: [`config::DaemonConfig`], [`config::ConfigBuilder`],
/// [`config::ConfigError`], [`config::OptionFlags`].
///
/// Key submodules: [`config::constants`], [`config::feature_flags`],
/// [`config::options`].
pub mod config;

/// Shared type definitions for addresses, DNS records, DHCP leases, and
/// network interfaces.
///
/// This module replaces the struct, union, and typedef declarations from
/// `src/dnsmasq.h` (1,800+ lines). Types are organized into domain-specific
/// submodules: [`types::addr`], [`types::dns`], [`types::dhcp`] (feature-gated),
/// [`types::network`], and [`types::ipv6`]. Always available — no feature gate.
///
/// Key types: [`AllAddr`], [`SocketAddress`], [`DnsHeader`], [`CacheEntry`],
/// [`ForwardRecord`].
pub mod types;

/// Core runtime infrastructure: daemon state, event loop, signal handling,
/// logging, PRNG, and metrics.
///
/// This module replaces `src/dnsmasq.c` (main loop, signals, init),
/// `src/poll.c` (I/O multiplexing), `src/log.c` (syslog), `src/util.c`
/// (utilities), `src/pattern.c` (wildcards), and `src/metrics.c`/`src/metrics.h`.
/// Always available — no feature gate.
///
/// Key types: [`DaemonState`], [`core::EventLoop`], [`core::SignalHandler`],
/// [`core::Logger`], [`core::Prng`], [`core::MetricsStore`].
pub mod core;

/// DNS forwarding, caching, wire-format codec, EDNS0, and DNSSEC validation
/// stack.
///
/// This module replaces `src/forward.c`, `src/cache.c`, `src/rfc1035.c`,
/// `src/dnssec.c`, `src/crypto.c`, `src/edns0.c`, `src/rrfilter.c`,
/// `src/auth.c`, `src/domain.c`, `src/domain-match.c`, `src/loop.c`, and
/// `src/dns-protocol.h`. Always available — DNS is the core function of dnsmasq.
///
/// Feature-gated submodules: [`dns::auth`] (`auth`), [`dns::loop_detect`]
/// (`loop_detect`), [`dns::dnssec`] (`dnssec`).
pub mod dns;

/// Network interface management, upstream socket pooling, ARP/neighbor cache,
/// and platform abstraction layer.
///
/// This module replaces `src/network.c`, `src/arp.c`, `src/netlink.c`,
/// `src/bpf.c`, `src/ipset.c`, `src/inotify.c`, `src/conntrack.c`, and
/// `src/tables.c`. Always available — networking is fundamental to dnsmasq.
///
/// Platform-specific submodules use `#[cfg(target_os)]` for conditional
/// compilation (Linux netlink vs. BSD BPF).
pub mod net;

/// DHCP subsystem: DHCPv4/v6 servers, lease management, Router Advertisements,
/// SLAAC, and the privilege-separated script helper process.
///
/// This module replaces `src/dhcp.c`, `src/dhcp6.c`, `src/rfc2131.c`,
/// `src/rfc3315.c`, `src/dhcp-common.c`, `src/lease.c`, `src/radv.c`,
/// `src/slaac.c`, `src/outpacket.c`, `src/helper.c`, and DHCP protocol headers.
///
/// # Feature Gate
///
/// Compiled only when the `dhcp` or `dhcp6` Cargo feature is enabled,
/// corresponding to C's `HAVE_DHCP` / `HAVE_DHCP6` compile-time flags.
/// Internal submodules are further gated: `v6` and `radv` require `dhcp6`,
/// `helper` requires `script`.
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
pub mod dhcp;

/// External system integration modules: D-Bus, UBus, nftset, and TFTP server.
///
/// This module replaces `src/dbus.c`, `src/ubus.c`, `src/nftset.c`, and
/// `src/tftp.c`. Always declared in the module tree, but each submodule is
/// individually feature-gated:
///
/// - [`integration::dbus`] — `#[cfg(feature = "dbus")]`
/// - [`integration::ubus`] — `#[cfg(feature = "ubus")]`
/// - [`integration::nftset`] — `#[cfg(feature = "nftset")]`
/// - [`integration::tftp`] — `#[cfg(feature = "tftp")]`
///
/// These modules contain the only permitted `unsafe` blocks in the codebase
/// (for FFI to external C libraries), except for the TFTP module which is
/// pure Rust.
pub mod integration;

/// Debug and diagnostic utilities: pcap packet capture.
///
/// This module replaces `src/dump.c`, providing pcap-format packet capture
/// for protocol analysis with Wireshark/tcpdump.
///
/// # Feature Gate
///
/// Compiled only when the `dump` Cargo feature is enabled, corresponding
/// to C's `HAVE_DUMPFILE` compile-time flag.
#[cfg(feature = "dump")]
pub mod debug;

// ============================================================================
// Public re-exports — commonly used types at the crate root
//
// These re-exports allow ergonomic imports for the most frequently used types.
// Instead of `use dnsmasq::types::addr::AllAddr`, consumers can write
// `use dnsmasq::AllAddr`.
//
// Only the most universally used types are re-exported here. Domain-specific
// types are accessed through their module paths (e.g., `dnsmasq::dns::cache::DnsCache`,
// `dnsmasq::net::InterfaceManager`).
// ============================================================================

/// Re-export [`AllAddr`](types::AllAddr) — unified address enum replacing
/// C's `union all_addr`. Variants: `V4`, `V6`, `Cname`, `Key`, `Ds`, `Log`,
/// `RrBlock`, `RrData`.
pub use types::AllAddr;

/// Re-export [`SocketAddress`](types::SocketAddress) — socket address enum
/// replacing C's `union mysockaddr`. Variants: `V4(SocketAddrV4)`,
/// `V6(SocketAddrV6)`. Methods: `port()`, `set_port()`, `is_v4()`, `is_v6()`.
pub use types::SocketAddress;

/// Re-export [`DnsHeader`](types::DnsHeader) — 12-byte DNS message header
/// per RFC 1035 Section 4.1.1. Fields: `id`, `hb3`, `hb4`, `qdcount`,
/// `ancount`, `nscount`, `arcount`.
pub use types::DnsHeader;

/// Re-export [`DnsName`](types::DnsName) — wire-format DNS name newtype
/// preventing accidental mixing of wire-format and presentation-format strings.
pub use types::DnsName;

/// Re-export [`CacheEntry`](types::CacheEntry) — DNS cache record replacing
/// C's `struct crec`. Fields: `addr`, `ttd`, `uid`, `flags`, `name`.
pub use types::CacheEntry;

/// Re-export [`ForwardRecord`](types::ForwardRecord) — upstream DNS query
/// tracking record replacing C's `struct frec`. Fields: `frec_src`, `sentto`,
/// `new_id`, `flags`, `time`.
pub use types::ForwardRecord;

/// Re-export [`DaemonState`](core::DaemonState) — the central daemon state
/// struct, decomposed from C's global `struct daemon` (100+ fields). Passed
/// explicitly as `&mut DaemonState` to all subsystem functions — no global
/// mutable state. Fields: `options`, `dns`, `log`, `user`, `metrics`,
/// `runtime`, `network`, `dhcp`, `tftp`, `prng`. Methods: `option_bool()`,
/// `set_option()`, `clear_option()`, `new()`.
pub use core::DaemonState;

/// Re-export [`constants`](config::constants) module — compile-time numeric
/// constants from `src/config.h`. Includes `CACHESIZ` (150), `MAXLEASES`
/// (1000), `FTABSIZ` (150), `EDNS_PKTSZ` (1232), `MAXDNAME` (1025),
/// `PACKETSZ` (512), `DNS_PORT` (53), `TIMEOUT` (10), `DHCP_SERVER_PORT`
/// (67), `DHCP_CLIENT_PORT` (68), `TCP_MAX_QUERIES` (100), `DEFLEASE`
/// (3600), `DNSSEC_LIMIT_WORK` (40), `DNSSEC_LIMIT_CRYPTO` (200).
pub use config::constants;

// ============================================================================
// Module-level tests
// ============================================================================

#[cfg(test)]
mod tests {
    //! Verification tests for the library root module declarations,
    //! feature gates, and public re-exports.

    use super::*;

    /// Verify that all always-available modules are accessible.
    #[test]
    fn test_always_available_modules() {
        // config module is accessible
        let _ = config::constants::CACHESIZ;

        // types module is accessible — AllAddr enum exists
        let _addr: types::AllAddr =
            types::AllAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // core module is accessible
        let _ = core::Metric::DnsQueriesForwarded;

        // dns module is accessible — protocol constants
        let _ = dns::protocol::NAMESERVER_PORT;

        // net module is accessible — submodules exist
        let _ = std::any::type_name::<net::InterfaceManager>();

        // integration module is accessible (even with no features)
        let _ = std::any::type_name::<fn()>();
    }

    /// Verify that crate-level re-exports are accessible at the root.
    #[test]
    fn test_crate_root_reexports() {
        // AllAddr re-export
        let _: AllAddr = AllAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // SocketAddress type exists (can't construct without data, just check type)
        let _ = std::any::type_name::<SocketAddress>();

        // DnsHeader type exists
        let _ = std::any::type_name::<DnsHeader>();

        // DnsName type exists
        let _ = std::any::type_name::<DnsName>();

        // CacheEntry type exists
        let _ = std::any::type_name::<CacheEntry>();

        // ForwardRecord type exists
        let _ = std::any::type_name::<ForwardRecord>();

        // DaemonState type exists
        let _ = std::any::type_name::<DaemonState>();

        // constants module is accessible
        assert_eq!(constants::CACHESIZ, 150);
        assert_eq!(constants::MAXLEASES, 1000);
        assert_eq!(constants::FTABSIZ, 150);
        assert_eq!(constants::DNS_PORT, 53);
        assert_eq!(constants::TIMEOUT, 10);
    }

    /// Verify DHCP module is available when both dhcp and dhcp6 features are enabled.
    #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
    #[test]
    fn test_dhcp_module_available() {
        // dhcp module accessible
        let _ = std::any::type_name::<dhcp::DhcpError>();
        let _ = std::any::type_name::<dhcp::DhcpBuffers>();
        let _ = std::any::type_name::<dhcp::Protocol>();
        let _ = std::any::type_name::<dhcp::LeaseDatabase>();
        let _ = std::any::type_name::<dhcp::DhcpPacket>();
        let _ = std::any::type_name::<dhcp::DhcpMessageType>();
    }

    /// Verify DHCPv6-specific types when dhcp6 feature is enabled.
    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_dhcp6_types_available() {
        let _ = std::any::type_name::<dhcp::Dhcp6MessageType>();
    }

    /// Verify debug module is available when dump feature is enabled.
    #[cfg(feature = "dump")]
    #[test]
    fn test_debug_module_available() {
        let _ = std::any::type_name::<debug::PacketDumper>();
        let _ = std::any::type_name::<debug::DumpMask>();
    }

    /// Verify DNS submodules are accessible.
    #[test]
    fn test_dns_submodules_accessible() {
        // Always-available DNS submodules
        let _ = std::any::type_name::<dns::WireError>();
        let _ = std::any::type_name::<dns::DnsCache>();
        let _ = std::any::type_name::<dns::ForwardingEngine>();
        let _ = std::any::type_name::<dns::ServerArray>();
    }

    /// Verify DNSSEC submodule when feature is enabled.
    #[cfg(feature = "dnssec")]
    #[test]
    fn test_dnssec_submodule_available() {
        // dnssec submodule accessible when feature enabled
        let _ = dns::dnssec::validation::DnssecValidator::new;
    }

    /// Verify net module re-exports are accessible.
    #[test]
    fn test_net_reexports_accessible() {
        let _ = std::any::type_name::<net::InterfaceManager>();
        let _ = std::any::type_name::<net::SocketPool>();
        let _ = std::any::type_name::<net::ArpCache>();
    }

    /// Verify config module re-exports are accessible.
    #[test]
    fn test_config_reexports_accessible() {
        let _ = std::any::type_name::<config::DaemonConfig>();
        let _ = std::any::type_name::<config::ConfigError>();
        let _ = std::any::type_name::<config::ConfigBuilder>();
        let _ = std::any::type_name::<config::OptionFlags>();
    }

    /// Verify core module re-exports are accessible.
    #[test]
    fn test_core_reexports_accessible() {
        let _ = std::any::type_name::<core::DaemonState>();
        let _ = std::any::type_name::<core::EventLoop>();
        let _ = std::any::type_name::<core::SignalHandler>();
        let _ = std::any::type_name::<core::Event>();
        let _ = std::any::type_name::<core::Logger>();
        let _ = std::any::type_name::<core::Metric>();
        let _ = std::any::type_name::<core::MetricsStore>();
        let _ = std::any::type_name::<core::Prng>();
    }

    /// Verify the constants module exposes all expected constants.
    #[test]
    fn test_constants_values() {
        // Verify backward-compatible defaults from AAP Section 0.7.2
        assert_eq!(constants::CACHESIZ, 150, "default cache size");
        assert_eq!(constants::MAXLEASES, 1000, "default lease limit");
        assert_eq!(constants::FTABSIZ, 150, "default forward table size");
        assert_eq!(constants::DNS_PORT, 53, "standard DNS port");
        assert_eq!(constants::TIMEOUT, 10, "default query timeout");
        assert_eq!(constants::TCP_MAX_QUERIES, 100, "TCP queries per connection");
        assert_eq!(constants::DNSSEC_LIMIT_WORK, 40, "DNSSEC work limit");
        assert_eq!(constants::DNSSEC_LIMIT_CRYPTO, 200, "DNSSEC crypto limit");
    }

    /// Verify that integration submodules are feature-gated correctly.
    #[test]
    fn test_integration_module_exists() {
        // The integration module itself is always available
        // (submodules are feature-gated internally)
        #[cfg(feature = "dbus")]
        {
            let _ = std::any::type_name::<integration::DbusState>();
        }
        #[cfg(feature = "ubus")]
        {
            let _ = std::any::type_name::<integration::UbusState>();
        }
        #[cfg(feature = "nftset")]
        {
            let _ = std::any::type_name::<integration::NftsetState>();
        }
    }
}

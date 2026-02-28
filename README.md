# dnsmasq — Lightweight DNS, DHCP, TFTP Server

**Version:** 2.92.0 (Rust Rewrite)
**License:** GPL-2.0-or-later
**Copyright:** © 2000–2025 Simon Kelley

A complete, production-ready Rust rewrite of [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html), the widely-deployed lightweight network services daemon. This implementation maintains **full functional equivalence** with the original C codebase (v2.92), preserving identical configuration file format, command-line interface, and wire-protocol behavior while leveraging Rust's ownership model for memory safety and type-safe error handling.

dnsmasq provides DNS forwarding and caching, DHCP server (v4 and v6), TFTP server for PXE/network boot, IPv6 Router Advertisements, DNSSEC validation, and authoritative DNS zone serving — all within a single lightweight daemon designed for small networks, home routers, and embedded systems.

---

## Table of Contents

- [Features](#features)
- [Building](#building)
- [Cargo Feature Flags](#cargo-feature-flags)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [License](#license)

---

## Features

- **DNS Forwarding and Caching** — Forwards queries to upstream recursive DNS servers with an in-memory LRU cache (default 150 entries, configurable). Supports domain-specific upstream server routing and automatic `/etc/resolv.conf` monitoring.
- **DHCPv4 Server** — Full RFC 2131 implementation with static reservations, dynamic address allocation from configurable pools, lease persistence, PXE/UEFI boot support, and DHCP-to-DNS integration for immediate name resolution of dynamically assigned hosts.
- **DHCPv6 Server** — RFC 3315 compliant with stateful address assignment (IA_NA), prefix delegation (IA_PD), and stateless configuration mode. Coordinates with Router Advertisements for managed/autonomous addressing.
- **TFTP Server** — Read-only TFTP server (RFC 1350/2349) for PXE network boot with blksize, tsize, and timeout option negotiation.
- **DNSSEC Validation** — Full DNSSEC validation with trust chain traversal, NSEC/NSEC3 denial-of-existence proofs, and support for RSA, ECDSA (P-256/P-384), and Ed25519 signature algorithms via the `ring` cryptography crate.
- **Router Advertisements** — IPv6 SLAAC support with periodic and solicited Router Advertisements, including Prefix Information Options (PIO), RDNSS, and DNSSL options.
- **Authoritative DNS Zones** — Serve authoritative DNS zones with SOA record generation and AXFR zone transfer support.
- **D-Bus and UBus Control Interfaces** — Programmatic runtime control via D-Bus (Linux desktop/server) and UBus (OpenWrt) for cache management, server reconfiguration, and lease monitoring.
- **Linux ipset/nftset Integration** — Automatically populate Linux ipset and nftables sets with resolved IP addresses for DNS-driven firewall rules.
- **Pcap Packet Dumping** — Optional pcap-format packet capture for protocol debugging and diagnostics.

---

## Building

### Prerequisites

- **Rust 1.93+** stable toolchain (edition 2024), pinned via `rust-toolchain.toml`
- **Cargo** (bundled with the Rust toolchain)
- **C compiler** (gcc or clang) — required at build time by the `ring` cryptography crate for assembly compilation
- **pkg-config** — required only when building with features that link to native system libraries (`dbus`, `nftset`, `conntrack`)

#### Installing the Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The pinned toolchain version is automatically selected from `rust-toolchain.toml` when you run any `cargo` command in the project directory.

### Build Commands

```bash
# Debug build (with default features)
cargo build

# Release build (optimized, with default features)
cargo build --release

# Release build with all features enabled
cargo build --release --all-features

# Minimal DNS-only build (no DHCP, no TFTP, no optional subsystems)
cargo build --release --no-default-features

# Build with specific features
cargo build --release --features "dnssec,dbus"
```

The output binary is located at `target/release/dnsmasq` (or `target/debug/dnsmasq` for debug builds).

### Cross-Compilation

Cross-compile for ARM64 Linux:

```bash
# Install the target
rustup target add aarch64-unknown-linux-gnu

# Build (requires linker configured in .cargo/config.toml)
cargo build --release --target aarch64-unknown-linux-gnu
```

Cross-compilation profiles for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` are preconfigured in `.cargo/config.toml`.

### Running Tests

```bash
# Run all tests with default features
cargo test

# Run all tests with all features enabled
cargo test --all-features

# Run a specific integration test module
cargo test --test integration -- dns_forwarding

# Run tests with output visible
cargo test -- --nocapture
```

### Static Linking

For a fully static binary (using musl libc):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

> **Note:** Features requiring native system libraries (`dbus`, `nftset`, `conntrack`) may not be compatible with musl static linking.

---

## Cargo Feature Flags

Feature flags replace the C build system's `HAVE_*` / `NO_*` compile-time macros (previously set via `COPTS` in the Makefile). Features are selected at build time using `cargo build --features "..."` or `--all-features`.

### Default Features

The following features are enabled by default (matching the original C build defaults):

| Cargo Feature | C Equivalent | Description |
|---|---|---|
| `dhcp` | `HAVE_DHCP` | DHCPv4 server with address allocation, lease management, and PXE support |
| `dhcp6` | `HAVE_DHCP6` | DHCPv6 server and Router Advertisements (implies `dhcp`) |
| `tftp` | `HAVE_TFTP` | Read-only TFTP server for PXE/network boot |
| `script` | `HAVE_SCRIPT` | External script execution for lease-change event notifications |
| `auth` | `HAVE_AUTH` | Authoritative DNS zone serving with AXFR support |
| `ipset` | `HAVE_IPSET` | Linux ipset population via netlink for DNS-driven firewall rules |
| `loop_detect` | `HAVE_LOOP` | DNS forwarding loop detection via periodic probe queries |
| `dump` | `HAVE_DUMPFILE` | Pcap-format packet dumping for protocol debugging |

### Optional Features

The following features must be explicitly enabled:

| Cargo Feature | C Equivalent | Description | System Library Required |
|---|---|---|---|
| `dnssec` | `HAVE_DNSSEC` | DNSSEC validation (RSA, ECDSA, Ed25519) via `ring` crate | None (pure Rust) |
| `dbus` | `HAVE_DBUS` | D-Bus system bus control interface | `libdbus-1-dev` |
| `ubus` | `HAVE_UBUS` | OpenWrt UBus control interface | `libubus-dev`, `libubox-dev` |
| `nftset` | `HAVE_NFTSET` | nftables set population for DNS-driven firewall rules | `libnftables-dev` |
| `netlink` | — | Linux netlink route/address monitoring | None |
| `inotify_monitor` | `HAVE_INOTIFY` | Linux inotify file-change monitoring for resolv.conf and dynamic config directories | None (Linux only) |
| `conntrack` | `HAVE_CONNTRACK` | Netfilter connection tracking mark retrieval | `libnetfilter-conntrack-dev` |
| `idn` | `HAVE_LIBIDN2` | IDNA 2008 internationalized domain name support via `idna` crate | None (pure Rust) |

### Feature Selection Examples

```bash
# Default features only (DHCPv4/v6, TFTP, Auth DNS, ipset, loop detect, dump)
cargo build --release

# Everything enabled
cargo build --release --all-features

# DNS-only (no DHCP, no TFTP, nothing optional)
cargo build --release --no-default-features

# DNSSEC + D-Bus on top of defaults
cargo build --release --features "dnssec,dbus"

# Minimal embedded build for ARM64
cargo build --release --no-default-features --target aarch64-unknown-linux-gnu
```

---

## Configuration

This Rust rewrite uses the **same configuration file format** as the original dnsmasq. All 160+ configuration directives and command-line options are preserved identically. Existing `dnsmasq.conf` files work without modification.

- **Configuration reference:** See [`dnsmasq.conf.example`](dnsmasq.conf.example) for the full annotated configuration template with all available options.
- **Configuration file location:** `/etc/dnsmasq.conf` (default), or specified via `-C` / `--conf-file` command-line option.
- **Configuration validation:** Use `--test` to validate configuration files without starting the daemon:

  ```bash
  ./target/release/dnsmasq --test
  ```

- **Hot reload:** Send `SIGHUP` to reload configuration, `/etc/hosts`, and upstream DNS server list without restarting:

  ```bash
  kill -HUP $(cat /var/run/dnsmasq.pid)
  ```

### Quick Start

```bash
# Run with default settings (forwards DNS queries, reads /etc/resolv.conf)
./target/release/dnsmasq --no-daemon --log-queries

# Run with a custom configuration file
./target/release/dnsmasq -C /path/to/dnsmasq.conf

# Run as a DHCP + DNS server on a specific interface
./target/release/dnsmasq --interface=eth0 --dhcp-range=192.168.1.100,192.168.1.200,12h
```

---

## Project Structure

The Rust codebase is organized into a hierarchical module tree grouped by functional domain, replacing the flat C `src/` directory:

```
Cargo.toml                       # Workspace manifest with dependencies and feature flags
rust-toolchain.toml              # Pinned Rust 1.93 stable, edition 2024
build.rs                         # Platform detection, optional native library linking
.cargo/config.toml               # Cross-compilation profiles (x86-64, ARM64)

src/
├── main.rs                      # Binary entry point: init, daemonize, event loop
├── lib.rs                       # Library root: module declarations, public API
├── config/                      # Configuration parsing and compile-time constants
│   ├── mod.rs
│   ├── options.rs               # CLI/config parser for 160+ options
│   ├── constants.rs             # Numeric defaults (CACHESIZ, MAXLEASES, etc.)
│   └── feature_flags.rs         # Cargo feature flag integration
├── core/                        # Daemon runtime infrastructure
│   ├── mod.rs
│   ├── daemon.rs                # DaemonState: decomposed from C global struct
│   ├── event_loop.rs            # mio-based poll event loop
│   ├── signal.rs                # Signal handling (SIGHUP, SIGTERM, etc.)
│   ├── logging.rs               # Non-blocking async syslog/logging
│   ├── util.rs                  # DNS name validation, I/O helpers
│   ├── prng.rs                  # CSPRNG (replacing C SURF PRNG)
│   └── metrics.rs               # Runtime metric definitions and tracking
├── dns/                         # DNS forwarding, caching, and DNSSEC
│   ├── mod.rs
│   ├── protocol.rs              # DNS wire-format constants (types, classes, opcodes)
│   ├── wire.rs                  # DNS packet parsing/construction, name compression
│   ├── cache.rs                 # DNS cache (HashMap + LRU eviction)
│   ├── forward.rs               # Forwarding engine and query state machine
│   ├── server_match.rs          # Domain pattern matching, upstream server selection
│   ├── edns.rs                  # EDNS0 OPT record handling
│   ├── rrfilter.rs              # RR filtering and compression pointer rewriting
│   ├── auth.rs                  # Authoritative zone serving, AXFR
│   ├── domain.rs                # Synthetic hostnames, split-horizon domains
│   ├── loop_detect.rs           # Forwarding loop detection
│   └── dnssec/                  # DNSSEC validation subsystem
│       ├── mod.rs
│       ├── validation.rs        # Trust chain, NSEC/NSEC3 proofs
│       └── crypto.rs            # ring-based signature verification
├── dhcp/                        # DHCPv4/v6, leases, Router Advertisements
│   ├── mod.rs
│   ├── common.rs                # Shared DHCP utilities, tag matching, PXE
│   ├── protocol_v4.rs           # DHCPv4 message type constants
│   ├── protocol_v6.rs           # DHCPv6 message type constants
│   ├── v4/                      # DHCPv4 subsystem
│   │   ├── mod.rs
│   │   ├── server.rs            # DHCPv4 core: address allocation, ICMP ping
│   │   └── rfc2131.rs           # DHCPv4 protocol (DORA cycle)
│   ├── v6/                      # DHCPv6 subsystem
│   │   ├── mod.rs
│   │   ├── server.rs            # DHCPv6 core: DUID, address6 allocation
│   │   ├── rfc3315.rs           # DHCPv6 protocol (SOLICIT/REQUEST/REPLY)
│   │   └── outpacket.rs         # DHCPv6 option serialization buffer
│   ├── lease.rs                 # Lease persistence, DNS registration, expiration
│   ├── radv/                    # Router Advertisement subsystem
│   │   ├── mod.rs
│   │   ├── protocol.rs          # RA ICMPv6 constants
│   │   ├── server.rs            # RA construction, periodic/solicited sends
│   │   └── slaac.rs             # SLAAC address probing
│   └── helper.rs                # Privilege-separated script helper process
├── net/                         # Network interfaces and platform abstraction
│   ├── mod.rs
│   ├── interface.rs             # Interface enumeration, listener management
│   ├── socket.rs                # Upstream socket pool, port randomization
│   ├── arp.rs                   # ARP/neighbor cache, MAC lookup
│   └── platform/                # OS-specific backends
│       ├── mod.rs
│       ├── linux/               # Linux-specific (behind #[cfg(target_os = "linux")])
│       │   ├── mod.rs
│       │   ├── netlink.rs       # NETLINK_ROUTE interface/route monitoring
│       │   ├── ipset.rs         # ipset via netlink
│       │   ├── inotify.rs       # inotify file-change monitoring
│       │   └── conntrack.rs     # netfilter conntrack mark retrieval
│       └── bsd/                 # BSD-specific (behind #[cfg(target_os = "freebsd")])
│           ├── mod.rs
│           ├── bpf.rs           # BPF raw packets, PF_ROUTE monitoring
│           └── pf_tables.rs     # PF table population
├── integration/                 # External system interfaces
│   ├── mod.rs
│   ├── dbus.rs                  # D-Bus system bus control interface
│   ├── ubus.rs                  # OpenWrt UBus control interface
│   ├── nftset.rs                # nftables set population
│   └── tftp.rs                  # Read-only TFTP server
├── debug/                       # Diagnostic utilities
│   ├── mod.rs
│   └── dump.rs                  # Pcap packet capture
└── types/                       # Shared type definitions
    ├── mod.rs
    ├── addr.rs                  # AllAddr enum, SocketAddress enum
    ├── dns.rs                   # DnsHeader, CacheEntry, ForwardRecord
    ├── dhcp.rs                  # DhcpLease, DhcpConfig, DhcpOption
    ├── network.rs               # InterfaceRecord, Listener, ServerEntry
    └── ipv6.rs                  # IPv6 address helpers

tests/
├── integration/                 # End-to-end integration tests
│   ├── dns_forwarding.rs
│   ├── dns_cache.rs
│   ├── dhcp_v4_lifecycle.rs
│   ├── dhcp_v6_lifecycle.rs
│   ├── config_parsing.rs
│   ├── wire_format.rs
│   └── dnssec_validation.rs
└── fixtures/                    # Test data (configs, sample packets)
```

---

## Architecture

This Rust rewrite preserves the core architectural characteristics of the original dnsmasq while replacing manual C memory management with Rust's compile-time safety guarantees.

### Design Principles

- **Single-Threaded, Event-Driven** — All services (DNS, DHCP, TFTP, Router Advertisements) operate within a single process using a `mio`-based poll event loop, eliminating thread synchronization complexity. This directly mirrors the original C architecture's `poll()` loop.

- **Memory-Safe by Default** — Rust's ownership and borrowing system replaces all manual `malloc`/`free` memory management. Zero `unsafe` blocks except where FFI to system libraries (D-Bus, netfilter, nftables) is unavoidable. Each `unsafe` block includes a `// SAFETY:` comment documenting its invariants.

- **Type-Safe Error Handling** — All C-style error codes and `errno` checks are replaced with `Result<T, E>` return types. The `setjmp`/`longjmp` pattern from the C configuration parser is replaced with `Result<DaemonConfig, ConfigError>` propagation.

- **Feature-Gated Compilation** — Optional subsystems are controlled via Cargo feature flags (replacing C `#ifdef HAVE_*` preprocessor guards), enabling customized builds from minimal DNS-only to full-featured.

- **Bounded Resource Consumption** — Core data structures use configurable capacity limits matching the original defaults: DNS cache (150 entries), forward table (150 concurrent queries), DHCP lease table (1000 leases), maintaining predictable memory usage suitable for embedded systems.

### Key Transformations from C

| Aspect | Original C | Rust Rewrite |
|---|---|---|
| Global state | `struct daemon` singleton (100+ fields) | `DaemonState` struct with nested domain-specific structs |
| Address types | `union all_addr` / `union mysockaddr` | `enum AllAddr` / `enum SocketAddress` with exhaustive matching |
| Cache data structure | Hash table + intrusive linked list | `HashMap` + `VecDeque` LRU |
| Forward records | Singly-linked list pool | `HashMap<u16, ForwardRecord>` keyed by transaction ID |
| DHCP leases | Linked list | `HashMap<IpAddr, DhcpLease>` keyed by IP address |
| Event loop | POSIX `poll()` with sorted fd array | `mio::Poll` with token-based dispatch |
| Error recovery | `setjmp`/`longjmp` in config parser | `Result<T, E>` propagation |
| Memory allocation | `safe_malloc`/`whine_realloc` wrappers | Standard Rust allocation (`Vec`, `Box`, `String`) |
| PRNG | SURF PRNG in `util.c` | `rand` crate CSPRNG |
| Crypto (DNSSEC) | Nettle/GnuTLS FFI | `ring` crate (pure Rust) |
| Platform abstraction | `#ifdef HAVE_LINUX_NETWORK` | `#[cfg(target_os = "linux")]` |
| Block data pool | Fixed 40-byte block chain (`blockdata.c`) | `Vec<u8>` / `bytes::Bytes` |

---

## Documentation

Detailed documentation for each subsystem is available in the `docs/` directory:

| Document | Description |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, module hierarchy, and design principles |
| [docs/BUILDING.md](docs/BUILDING.md) | Build instructions, feature selection, cross-compilation, and troubleshooting |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Complete configuration reference for all 160+ directives |
| [docs/DNS_FORWARDING.md](docs/DNS_FORWARDING.md) | DNS forwarding engine design and query processing pipeline |
| [docs/DNS_CACHING.md](docs/DNS_CACHING.md) | DNS cache implementation, LRU eviction, and TTL management |
| [docs/DNSSEC.md](docs/DNSSEC.md) | DNSSEC validation, trust chain logic, and cryptographic algorithms |
| [docs/DHCP_V4.md](docs/DHCP_V4.md) | DHCPv4 server implementation and DORA cycle |
| [docs/DHCP_V6.md](docs/DHCP_V6.md) | DHCPv6 server, Router Advertisements, and SLAAC |
| [docs/TFTP.md](docs/TFTP.md) | TFTP server implementation and PXE boot support |

Additional reference files:

| File | Description |
|---|---|
| [dnsmasq.conf.example](dnsmasq.conf.example) | Annotated example configuration with all available options |
| [trust-anchors.conf](trust-anchors.conf) | DNSSEC root trust anchor data for validation |

---

## License

dnsmasq is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) version 3.

See the [GNU General Public License](https://www.gnu.org/licenses/gpl-2.0.html) for details.

**Copyright © 2000–2025 Simon Kelley**

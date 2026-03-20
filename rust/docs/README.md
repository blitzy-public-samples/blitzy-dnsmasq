# dnsmasq — Memory-Safe Rust Implementation

**A drop-in replacement for dnsmasq v2.92, rewritten in Rust for memory safety**

[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
[![Rust: 1.91.0](https://img.shields.io/badge/Rust-1.91.0-orange.svg)](https://www.rust-lang.org/)

dnsmasq is a lightweight DNS forwarder, DHCP server, Router Advertisement
daemon, and TFTP/PXE network boot server designed for small networks, embedded
devices, and resource-constrained environments.

This implementation is a **complete rewrite of dnsmasq v2.92 in Rust**, with
the primary goal of eliminating all memory-safety vulnerabilities — including
buffer overflows, use-after-free, double-free, and dangling pointer issues — by
leveraging Rust's ownership system, borrow checker, and lifetime annotations.

**Drop-in replacement guarantee:** This binary is 100% backward compatible with
existing `dnsmasq.conf` configuration files, command-line flags, and systemd
service units. No changes to existing configurations or workflows are required
to adopt the Rust version.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building](#building)
- [Running](#running)
- [Testing](#testing)
- [Configuration](#configuration)
- [Feature Flags](#feature-flags)
- [Deployment](#deployment)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [License](#license)

---

## Features

All capabilities of dnsmasq v2.92 are fully supported:

- **DNS forwarding and caching** — Default cache size of 150 entries with
  TTL-based eviction and LRU replacement
- **DHCPv4 server** — Full DISCOVER/OFFER/REQUEST/ACK state machine with
  static and dynamic address allocation
- **DHCPv6 server** — Including prefix delegation for downstream routers
- **Router Advertisement (IPv6)** — Periodic and solicited RA messages for
  SLAAC and stateful DHCPv6
- **TFTP server** — PXE network boot support for diskless workstations
- **DNSSEC validation** — Cryptographic verification of DNS responses
  (optional, requires `dnssec` feature)
- **Authoritative DNS zone serving** — Local zone authority for internal domains
- **D-Bus interface** — NetworkManager integration for dynamic DNS server
  reconfiguration (optional, requires `dbus` feature)
- **OpenWrt ubus integration** — Control interface for OpenWrt-based routers
  (optional, requires `ubus` feature)
- **ipset/nftables set integration** — Populate Linux firewall sets with
  resolved IP addresses
- **DNS forwarding loop detection** — Automatic detection and prevention of
  query forwarding loops
- **inotify-based file monitoring** — Automatic reload when `/etc/hosts` or
  `/etc/resolv.conf` changes
- **350+ configuration directives** — Full backward compatibility with all
  existing dnsmasq configuration options

---

## Prerequisites

### Rust Toolchain

- **Rust 1.91.0** stable — enforced by `rust-toolchain.toml`
- **Cargo** — bundled with the Rust installation

No external dependencies are required for default features — core functionality
is implemented in pure Rust.

### System Dependencies (Optional Features)

The following system libraries are only needed when building with optional
features:

| Feature | Library | Debian/Ubuntu | RHEL/CentOS/Fedora |
|---------|---------|---------------|---------------------|
| `dbus` | libdbus-1 | `libdbus-1-dev` | `dbus-devel` |
| `dnssec` | nettle + hogweed | `nettle-dev` | `nettle-devel` |
| `dnssec` | GMP (optional) | `libgmp-dev` | `gmp-devel` |
| `luascript` | Lua 5.4 | `liblua5.4-dev` | `lua-devel` |

### Platform Support

- **Linux** (glibc and musl) — primary development platform
- **FreeBSD**
- **OpenBSD**
- **NetBSD**
- **macOS / Darwin**

---

## Quick Start

### 1. Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Clone and Build

```bash
cd rust/
# rust-toolchain.toml will automatically select Rust 1.91.0
cargo build --release
```

### 3. Run

```bash
sudo ./target/release/dnsmasq --no-daemon
```

The release binary is located at `target/release/dnsmasq`.

---

## Building

### Default Features

```bash
cd rust/
cargo build --release
# Binary: target/release/dnsmasq
```

### All Features

```bash
cargo build --release --all-features
```

### Specific Feature Combinations

```bash
# Minimal DNS-only build (no DHCP, no TFTP)
cargo build --release --no-default-features

# DNS + DHCP only
cargo build --release --no-default-features --features "dhcp,dhcp6"

# Full-featured with DNSSEC validation
cargo build --release --features "dnssec"

# With D-Bus support for NetworkManager integration
cargo build --release --features "dbus"
```

### Cross-Compilation

The `rust-toolchain.toml` includes pre-configured targets for cross-compilation:

```bash
# ARM64 Linux (e.g., Raspberry Pi, AWS Graviton)
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu

# Alpine Linux / musl (static binary)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# FreeBSD
rustup target add x86_64-unknown-freebsd
cargo build --release --target x86_64-unknown-freebsd

# macOS (Apple Silicon)
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

### Release Profile

Release builds are optimized for production deployment:

- **LTO** (Link-Time Optimization) enabled for maximum performance
- **Single codegen unit** for optimal whole-program optimization
- **Binary stripping** enabled for minimal file size
- **Optimization level 3** for maximum runtime performance

---

## Running

```bash
# Run with default configuration (/etc/dnsmasq.conf)
sudo ./target/release/dnsmasq

# Run with a specific configuration file
sudo ./target/release/dnsmasq --conf-file=/etc/dnsmasq.conf

# Run in foreground (no daemon mode)
sudo ./target/release/dnsmasq --no-daemon

# Test configuration file syntax without starting the daemon
./target/release/dnsmasq --test

# Display version and compiled feature set
./target/release/dnsmasq --version
```

> **Note:** Root privileges (or equivalent capabilities) are required to bind
> to privileged ports (DNS port 53, DHCP port 67, TFTP port 69). After binding,
> the daemon drops privileges to an unprivileged user for security.

---

## Testing

### Run All Tests

```bash
cargo test
```

### Run Integration Tests

```bash
cargo test --test dns_integration
cargo test --test dhcp_integration
cargo test --test config_compatibility
cargo test --test cli_compatibility
cargo test --test lease_persistence
cargo test --test protocol_compliance
```

### Run Benchmarks

```bash
cargo bench
```

### Code Coverage

Target: >80% code coverage as measured by `cargo-tarpaulin`.

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
# Open tarpaulin-report.html in a browser
```

### Lint and Format

```bash
# Run Clippy linter (treats warnings as errors)
cargo clippy --all-features -- -D warnings

# Check code formatting
cargo fmt -- --check

# Apply code formatting
cargo fmt
```

### Security Audit

```bash
cargo install cargo-audit
cargo audit
```

---

## Configuration

The Rust binary uses **identical configuration** to the original C dnsmasq
version. No configuration changes are needed when migrating from the C binary.

- **Configuration file:** `/etc/dnsmasq.conf` (or specify with `--conf-file=`)
- **Directive count:** All 350+ configuration directives are supported with
  identical syntax and semantics
- **Include directives:** `conf-file=` and `conf-dir=` for modular configuration
- **Hot reload:** Send `SIGHUP` to reload configuration without restarting the
  daemon
- **Signal handling:**
  - `SIGHUP` — Reload configuration and clear DNS cache
  - `SIGUSR1` — Dump DNS cache contents to syslog
  - `SIGUSR2` — Log upstream server statistics
  - `SIGTERM` / `SIGINT` — Graceful shutdown

For the full configuration reference, see the `man/dnsmasq.8` man page in the
repository root, which provides comprehensive documentation of all CLI flags
and configuration directives.

---

## Feature Flags

Cargo feature flags replace the C `HAVE_*` preprocessor macros. Features are
enabled at build time via `--features` or `--all-features` flags.

### Default Features (enabled unless `--no-default-features`)

| Feature | C Equivalent | Description |
|---------|-------------|-------------|
| `dhcp` | `HAVE_DHCP` | DHCPv4 server |
| `dhcp6` | `HAVE_DHCP6` | DHCPv6 server (implies `dhcp`) |
| `tftp` | `HAVE_TFTP` | TFTP/PXE boot server |
| `script` | `HAVE_SCRIPT` | Lease-change script execution |
| `auth` | `HAVE_AUTH` | Authoritative DNS zones |
| `ipset` | `HAVE_IPSET` | Linux ipset integration |
| `loop-detect` | `HAVE_LOOP` | DNS forwarding loop detection |
| `dumpfile` | `HAVE_DUMPFILE` | Packet dump debugging |
| `inotify` | `HAVE_INOTIFY` | File change monitoring |

### Optional Features (disabled by default)

| Feature | C Equivalent | Description | System Dependency |
|---------|-------------|-------------|-------------------|
| `dnssec` | `HAVE_DNSSEC` | DNSSEC validation | `nettle-dev` |
| `dbus` | `HAVE_DBUS` | D-Bus / NetworkManager | `libdbus-1-dev` |
| `ubus` | `HAVE_UBUS` | OpenWrt ubus | — |
| `idn` | `HAVE_IDN` | Internationalized domains | — |
| `conntrack` | `HAVE_CONNTRACK` | Linux conntrack marks | — |
| `nftset` | `HAVE_NFTSET` | nftables sets | `libnftables-dev` |
| `luascript` | `HAVE_LUASCRIPT` | Lua scripting | `liblua5.4-dev` |
| `broken-rtc` | `HAVE_BROKEN_RTC` | Embedded systems without hardware real-time clock | — |

### Platform Auto-Detection

Platform-specific functionality is automatically detected at compile time via
`#[cfg(target_os = "...")]` attributes:

- **Linux:** netlink interface monitoring, inotify, ipset/nftset, conntrack
- **BSD (FreeBSD, OpenBSD, NetBSD):** BPF packet filter, routing socket monitoring
- **macOS:** BPF packet filter with Darwin-specific paths

---

## Deployment

### Systemd Service

A drop-in replacement systemd service unit is provided:

```bash
sudo cp deploy/dnsmasq.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dnsmasq
```

### Docker

An Alpine Linux-based Docker image is available for containerized deployment:

```bash
cd rust/deploy
docker build -t dnsmasq-rust .
docker run -d \
  --name dnsmasq \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=NET_BIND_SERVICE \
  dnsmasq-rust
```

Supported Alpine Linux base versions: 3.19.9, 3.20.8, 3.21.5, 3.22.2.

### Configuration Migration

A configuration migration tool is provided to validate that existing
configuration files are compatible with the Rust implementation:

```bash
# Validate existing configuration
./target/release/dnsmasq-migrate-config --check /etc/dnsmasq.conf
```

---

## Project Structure

```
rust/
├── Cargo.toml              # Dependencies and feature flags
├── Cargo.lock              # Dependency version lock file
├── rust-toolchain.toml     # Pin Rust 1.91.0 stable
├── build.rs                # Platform detection, conditional compilation
├── clippy.toml             # Clippy lint configuration
├── rustfmt.toml            # Code formatting rules
├── .cargo/
│   └── config.toml         # Cargo build settings
├── src/
│   ├── main.rs             # Binary entry point, tokio runtime init
│   ├── lib.rs              # Library root, module declarations
│   ├── config/             # Configuration parsing (from config.h, option.c)
│   ├── core/               # Core runtime (from dnsmasq.c/h, poll.c, log.c, util.c)
│   ├── dns/                # DNS subsystem (from forward.c, cache.c, rfc1035.c, etc.)
│   ├── dhcp/               # DHCP subsystem (from rfc2131.c, rfc3315.c, lease.c, etc.)
│   ├── network/            # Network platform abstraction (from network.c, netlink.c, bpf.c)
│   ├── integration/        # External integrations (D-Bus, ubus, ipset, nftset, etc.)
│   ├── services/           # TFTP server (from tftp.c)
│   └── diagnostics/        # Monitoring and debugging (dump, inotify, metrics)
├── tests/                  # Integration tests
├── benches/                # Performance benchmarks
├── deploy/                 # Deployment files (Dockerfile, systemd service)
└── docs/                   # Documentation
```

For a detailed module hierarchy and dependency graph, see
[Architecture](ARCHITECTURE.md).

---

## Documentation

- [Architecture](ARCHITECTURE.md) — Module hierarchy, dependency graph, design
  patterns, state management, and async runtime architecture
- [Migration Guide](MIGRATION.md) — C-to-Rust pattern mapping, file-by-file
  transformation table, and dependency mapping
- [Safety](SAFETY.md) — Unsafe block inventory with justifications, eliminated
  unsafe patterns, and third-party crate safety assessment
- [API Reference](API.md) — Internal module API documentation derived from C
  source code inline comments

Generate full Rustdoc API documentation from source code comments:

```bash
cargo doc --open
```

---

## License

This program is free software; you can redistribute it and/or modify it under
the terms of the **GNU General Public License** as published by the Free
Software Foundation; version 2 dated June, 1991, or (at your option) version 3
dated 29 June, 2007.

**License:** GPL-2.0-or-later (same as the original dnsmasq by Simon Kelley)

**Original C version:** Copyright © 2000-2025 Simon Kelley

See [COPYING](../../COPYING) and [COPYING-v3](../../COPYING-v3) for the full
license texts.

# Building dnsmasq

**Version:** 2.92 (Rust rewrite)  
**Copyright:** © 2000-2025 Simon Kelley  
**License:** GPL-2.0-or-later

## Table of Contents

- [Overview](#overview)
- [Platform Support](#platform-support)
- [Required Dependencies](#required-dependencies)
- [Optional Dependencies and Feature Flags](#optional-dependencies-and-feature-flags)
- [Basic Build Instructions](#basic-build-instructions)
- [Feature Selection with Cargo](#feature-selection-with-cargo)
- [Dependency Detection](#dependency-detection)
- [Cross-Compilation](#cross-compilation)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Static vs Dynamic Linking](#static-vs-dynamic-linking)
- [Binary Size Optimization](#binary-size-optimization)
- [Build Troubleshooting](#build-troubleshooting)
- [Build System Architecture](#build-system-architecture)
- [Advanced Build Topics](#advanced-build-topics)
- [Summary](#summary)

---

## Overview

Dnsmasq is a lightweight DNS forwarder, DHCP server, TFTP server, and Router Advertisement daemon. The Rust rewrite uses Cargo as its build system, providing a modern, reproducible build workflow with automatic dependency resolution, feature-gated compilation, and built-in cross-compilation support.

The build system supports:
- **Modular compilation**: Rust module hierarchy organized by functional domain (DNS, DHCP, TFTP, platform abstraction, integration)
- **Feature selection via Cargo feature flags**: Enable or disable subsystems at compile time
- **Automatic dependency resolution**: Cargo fetches and compiles Rust crate dependencies from crates.io
- **Platform adaptation**: Conditional compilation via `#[cfg(target_os)]` and `#[cfg(target_arch)]` for Linux, BSD, and macOS
- **Minimal external dependencies**: Core functionality requires only the Rust standard library and well-established crates
- **Built-in testing**: Unit and integration tests via `cargo test`

**Key Build Files:**

| File | Purpose |
|------|---------|
| `Cargo.toml` | Root workspace manifest with dependencies, feature flags, and build profiles |
| `rust-toolchain.toml` | Pinned Rust toolchain version (1.93.1 stable, edition 2024) |
| `build.rs` | Build script for platform detection and optional native library linking via pkg-config |
| `.cargo/config.toml` | Cross-compilation profiles for x86-64 and ARM64 Linux targets |

**Build Time:** Typical compilation completes in 1–3 minutes on modern hardware (first build). Subsequent incremental builds complete in seconds.

---

## Platform Support

Dnsmasq compiles and runs on the following operating systems and architectures using Rust target triples.

### Supported Targets

| Target Triple | OS / Architecture | Platform Backend | Status |
|--------------|-------------------|-----------------|--------|
| `x86_64-unknown-linux-gnu` | Linux x86-64 (glibc) | `src/net/platform/linux/netlink.rs` | **Primary target** |
| `aarch64-unknown-linux-gnu` | Linux ARM64 (glibc) | `src/net/platform/linux/netlink.rs` | **Primary target** |
| `armv7-unknown-linux-gnueabihf` | Linux ARM32 (glibc) | `src/net/platform/linux/netlink.rs` | Fully supported |
| `x86_64-unknown-linux-musl` | Linux x86-64 (musl) | `src/net/platform/linux/netlink.rs` | Static builds |
| `aarch64-unknown-linux-musl` | Linux ARM64 (musl) | `src/net/platform/linux/netlink.rs` | Static builds |
| `x86_64-unknown-freebsd` | FreeBSD x86-64 | `src/net/platform/bsd/bpf.rs` | Fully supported |
| `x86_64-apple-darwin` | macOS x86-64 | `src/net/platform/bsd/bpf.rs` | Fully supported |
| `aarch64-apple-darwin` | macOS Apple Silicon | `src/net/platform/bsd/bpf.rs` | Fully supported |
| `x86_64-unknown-openbsd` | OpenBSD x86-64 | `src/net/platform/bsd/bpf.rs` | Conditional support |

### Platform-Specific Code

Platform-specific code uses Rust conditional compilation attributes:

- **Linux platform backend**: `#[cfg(target_os = "linux")]` — netlink route/address monitoring, ipset, inotify, conntrack
- **BSD platform backend**: `#[cfg(target_os = "freebsd")]`, `#[cfg(target_os = "macos")]` — BPF raw packets, PF_ROUTE, PF tables
- **Architecture-specific**: `#[cfg(target_arch = "x86_64")]`, `#[cfg(target_arch = "aarch64")]` — used where hardware-specific behavior differs (ioctl constants, struct padding)

**Endianness:** Both big-endian and little-endian architectures are fully supported via Rust's `u16::to_be_bytes()` / `u16::from_be_bytes()` and related methods.

---

## Required Dependencies

The following components are required to build dnsmasq from source.

### Rust Toolchain

| Component | Version | Purpose | Installation |
|-----------|---------|---------|--------------|
| **Rust** (stable) | 1.93.1 | Compiler and standard library | Via `rustup` (see below) |
| **Cargo** | (bundled with Rust) | Build system and package manager | Included with Rust |
| **Rust Edition** | 2024 | Language edition for latest features | Pinned in `rust-toolchain.toml` |

The exact Rust version is pinned in `rust-toolchain.toml` at the repository root:

```toml
[toolchain]
channel = "1.93.1"
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
```

When you run any `cargo` or `rustc` command inside the repository, `rustup` automatically downloads and uses the pinned toolchain version.

### Installing Rust

Install Rust via `rustup` (the official Rust toolchain installer):

```bash
# Linux / macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow prompts to add Rust to your PATH
source "$HOME/.cargo/env"

# Verify installation
rustc --version   # Should show: rustc 1.93.1
cargo --version   # Should show: cargo 1.93.1
```

### Build-Time System Dependencies

A C compiler is required at build time because the `ring` cryptographic crate compiles assembly routines via the `cc` crate:

| Component | Purpose | Required For |
|-----------|---------|--------------|
| **GCC** or **Clang** | C compiler for `ring` crate assembly | All builds |
| **pkg-config** | Native library detection | Only when `dbus`, `nftset`, or `conntrack` features are enabled |

```bash
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config

# RHEL/CentOS/Fedora
sudo dnf install gcc pkg-config

# FreeBSD
pkg install pkgconf

# macOS (Xcode command-line tools provide cc)
xcode-select --install
```

### System Requirements

- **POSIX-compliant operating system**: Linux, FreeBSD, macOS, or OpenBSD
- **Network stack**: POSIX sockets API for network operations
- **Internet access**: Required for first build (Cargo downloads crate dependencies from crates.io)

---

## Optional Dependencies and Feature Flags

Dnsmasq uses Cargo feature flags for compile-time feature selection. Features replace the C `HAVE_*` / `NO_*` preprocessor macros that were previously set via the `COPTS` variable.

### Cargo Feature Flag Reference

The following table maps every Cargo feature flag to its legacy C equivalent:

| Cargo Feature | Replaces C Macro | Description | Default | Native Library Required |
|---|---|---|---|---|
| `dhcp` | `HAVE_DHCP` | DHCPv4 server | ✅ Yes | None |
| `dhcp6` | `HAVE_DHCP6` | DHCPv6 server and Router Advertisements | ✅ Yes | None |
| `dnssec` | `HAVE_DNSSEC` | DNSSEC validation (RFC 4033/4034/4035) | No | None — uses `ring` crate |
| `dbus` | `HAVE_DBUS` | D-Bus system bus control interface | No | `libdbus-1-dev` |
| `ubus` | `HAVE_UBUS` | OpenWrt UBus control interface | No | `libubus-dev`, `libubox-dev` |
| `tftp` | `HAVE_TFTP` | Read-only TFTP server (RFC 1350/2349) | ✅ Yes | None |
| `script` | `HAVE_SCRIPT` | Script execution for lease events | ✅ Yes | None |
| `auth` | `HAVE_AUTH` | Authoritative DNS zone serving | ✅ Yes | None |
| `ipset` | `HAVE_IPSET` | Linux ipset integration via netlink | ✅ Yes | None — uses netlink crate |
| `nftset` | `HAVE_NFTSET` | nftables set population | No | `libnftables-dev` |
| `conntrack` | `HAVE_CONNTRACK` | Netfilter conntrack mark retrieval | No | `libnetfilter-conntrack-dev` |
| `idn` | `HAVE_LIBIDN2` | IDNA 2008 internationalized domain names | No | None — uses `idna` crate |
| `inotify_monitor` | `HAVE_INOTIFY` | Linux inotify file-change monitoring | No | None (Linux only) |
| `netlink` | (Linux netlink) | Netlink route/address monitoring | No | None — uses netlink crates |
| `loop_detect` | `HAVE_LOOP` | DNS forwarding loop detection | ✅ Yes | None |
| `dump` | `HAVE_DUMPFILE` | Pcap packet capture for debugging | ✅ Yes | None — uses `pcap-file` crate |

**Default features** (enabled unless `--no-default-features` is specified):
`dhcp`, `dhcp6`, `tftp`, `script`, `auth`, `ipset`, `loop_detect`, `dump`

### Key Changes from C Build

- **DNSSEC no longer requires Nettle or GnuTLS.** The Rust rewrite uses the pure-Rust `ring` crate for all cryptographic operations (RSA, ECDSA P-256/P-384, Ed25519). No system crypto libraries are needed.
- **IDN support no longer requires libidn2.** The Rust rewrite uses the pure-Rust `idna` crate for IDNA 2008 support. No system IDN library is needed.
- **Feature flags are additive.** Use `--features` to enable additional features, or `--no-default-features` to start from a minimal base and add only what you need.

### Native Library Requirements

The following features require native system libraries. These are detected at build time by `build.rs` using the `pkg-config` crate:

#### D-Bus Control Interface (`dbus` feature)

```bash
# Debian/Ubuntu
sudo apt-get install libdbus-1-dev

# RHEL/CentOS/Fedora
sudo dnf install dbus-devel

# Arch Linux
sudo pacman -S dbus

# FreeBSD
pkg install dbus
```

**Error if missing:** `Warning: D-Bus feature enabled but libdbus-1 not found`

#### nftables Set Integration (`nftset` feature)

```bash
# Debian/Ubuntu
sudo apt-get install libnftables-dev

# RHEL/CentOS/Fedora (RHEL 8+)
sudo dnf install nftables-devel

# Arch Linux
sudo pacman -S nftables
```

**Platform:** Linux only (requires `CONFIG_NF_TABLES` kernel support)  
**Error if missing:** `Warning: nftset feature enabled but libnftables not found`

#### Conntrack Mark Retrieval (`conntrack` feature)

```bash
# Debian/Ubuntu
sudo apt-get install libnetfilter-conntrack-dev

# RHEL/CentOS/Fedora
sudo dnf install libnetfilter_conntrack-devel

# Arch Linux
sudo pacman -S libnetfilter_conntrack
```

**Platform:** Linux only (requires `CONFIG_NF_CONNTRACK` kernel support)  
**Error if missing:** `Warning: conntrack feature enabled but libnetfilter_conntrack not found`

#### UBus Control Interface (`ubus` feature)

```bash
# OpenWrt build system
opkg install libubus-dev libubox-dev
```

**Platform:** OpenWrt/LEDE only

### Crate Dependencies

The following Rust crates are automatically fetched from crates.io by Cargo. No manual installation is required.

#### Core Dependencies (always included)

| Crate | Version | Purpose |
|-------|---------|---------|
| `mio` | 1.1.0 | Poll-based I/O event loop (epoll/kqueue abstraction) |
| `nix` | 0.30.1 | Safe POSIX API bindings (signals, sockets, ioctl, fork) |
| `libc` | 0.2.171 | Low-level C FFI types and constants |
| `log` | 0.4.27 | Logging facade for syslog integration |
| `tracing` | 0.1.41 | Structured diagnostic logging |
| `tracing-subscriber` | 0.3.19 | Log subscriber for syslog output formatting |
| `bitflags` | 2.9.0 | Type-safe bitflag definitions for DNS/DHCP option flags |
| `thiserror` | 2.0.12 | Derive macro for custom error types |
| `anyhow` | 1.0.98 | Ergonomic error handling for binary entry point |
| `bytes` | 1.10.1 | Efficient byte buffer management for packet construction |
| `cfg-if` | 1.0.0 | Conditional compilation helpers |
| `socket2` | 0.5.9 | Extended socket options (SO_REUSEPORT, SO_BINDTODEVICE, multicast) |
| `rand` | 0.9.1 | CSPRNG for transaction IDs and port randomization |

#### Optional Dependencies (feature-gated)

| Crate | Version | Enabled By Feature |
|-------|---------|-------------------|
| `ring` | 0.17.14 | `dnssec` — DNSSEC cryptographic verification |
| `dbus` | 0.9.7 | `dbus` — D-Bus system bus FFI bindings |
| `inotify` | 0.11.0 | `inotify_monitor` — Linux inotify file monitoring |
| `pcap-file` | 2.0.0 | `dump` — Pcap file writing for packet capture |
| `idna` | 1.0.3 | `idn` — IDNA 2008 domain name processing |
| `netlink-packet-core` | 0.7.0 | `ipset` — Netlink message construction for ipset |
| `netlink-packet-route` | 0.21.0 | `netlink` — Route/address netlink messages |
| `netlink-sys` | 0.8.7 | `netlink` — Netlink socket management |

#### Build Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `cc` | 1.2.16 | C compiler detection for `ring` assembly compilation |
| `pkg-config` | 0.3.31 | Native library detection for optional features |

---

## Basic Build Instructions

### Quick Start (Default Configuration)

Build dnsmasq with the default feature set (DHCPv4, DHCPv6, TFTP, auth DNS, scripting, ipset, loop detection, packet dump):

```bash
# Clone or extract source
cd dnsmasq

# Build in debug mode (fast compile, includes debug info)
cargo build

# Build in release mode (optimized)
cargo build --release

# Output binary location
ls -lh target/release/dnsmasq
```

### Installation

```bash
# Install to ~/.cargo/bin/dnsmasq
cargo install --path .

# Or manually copy the release binary
sudo cp target/release/dnsmasq /usr/local/sbin/dnsmasq

# Verify installation
dnsmasq --version
```

**Default Installation Paths (manual copy):**
- Binary: `/usr/local/sbin/dnsmasq`
- Configuration: User must create `/etc/dnsmasq.conf` (see `dnsmasq.conf.example`)
- Trust anchors: `/usr/share/dnsmasq/trust-anchors.conf` (for DNSSEC)

### Build Profiles

| Profile | Command | Optimizations | Debug Info | Use Case |
|---------|---------|--------------|------------|----------|
| Debug | `cargo build` | None (`opt-level = 0`) | Full | Development and debugging |
| Release | `cargo build --release` | Full (`opt-level = 3`, LTO) | Stripped | Production deployment |
| Release + Debug | See below | Full | Included | Profiling |

To build a release binary with debug info for profiling, add to `Cargo.toml`:

```toml
[profile.release]
debug = true
```

Then build with:

```bash
cargo build --release
```

### Running Tests

```bash
# Run all unit tests (default features)
cargo test

# Run all tests including feature-gated ones
cargo test --all-features

# Run a specific integration test
cargo test --test dns_forwarding

# Run tests with output visible
cargo test -- --nocapture

# Run tests for a specific module
cargo test dns::cache
```

---

## Feature Selection with Cargo

Cargo feature flags control which subsystems are compiled into the binary. This replaces the C build system's `COPTS` variable with `-DHAVE_*` and `-DNO_*` flags.

### Feature Selection Syntax

```bash
# Enable additional features (on top of defaults)
cargo build --release --features "dnssec,dbus"

# Disable all default features, start from scratch
cargo build --release --no-default-features

# Disable defaults, then enable specific features
cargo build --release --no-default-features --features "dhcp,tftp"

# Enable ALL features
cargo build --release --all-features
```

### Feature Selection Examples

#### Default Build (Standard Deployment)

Build with default features (DHCPv4, DHCPv6, TFTP, auth, scripting, ipset, loop detection, dump):

```bash
cargo build --release
```

**Capabilities:** DNS forwarding, DNS caching, DHCPv4/v6, TFTP, authoritative DNS, script hooks, ipset, loop detection, packet dump

#### Minimal DNS-Only Build

Build the smallest possible binary containing only DNS forwarding and caching:

```bash
cargo build --release --no-default-features
```

**Capabilities:** DNS forwarding, DNS caching, `/etc/hosts` integration  
**Excluded:** All DHCP, TFTP, scripting, auth DNS, ipset, loop detection, dump

#### DNSSEC-Enabled Build

Build with DNSSEC validation support:

```bash
cargo build --release --features dnssec
```

**Requirements:** None — the `ring` crate provides all cryptographic functionality  
**Provides:** RRSIG signature verification, DNSKEY/DS validation, NSEC/NSEC3 proofs  
**Trust Anchors:** `trust-anchors.conf` must be present at runtime

#### Full-Featured Build with D-Bus and DNSSEC

Build with all features including optional D-Bus and DNSSEC:

```bash
cargo build --release --all-features
```

**Requirements:**
- `libdbus-1-dev` (for D-Bus feature)
- `libnftables-dev` (for nftset feature)
- `libnetfilter-conntrack-dev` (for conntrack feature)

#### D-Bus + DNSSEC Build

Build with specific optional features:

```bash
cargo build --release --features "dbus,dnssec"
```

**Requirements:** `libdbus-1-dev` installed

#### No DHCP (DNS + TFTP Only)

Build without any DHCP functionality:

```bash
cargo build --release --no-default-features --features "tftp,auth,script,loop_detect"
```

#### Embedded System Build

Minimal build for resource-constrained devices:

```bash
cargo build --release --no-default-features --target aarch64-unknown-linux-gnu
```

**Rationale:** Smallest binary footprint for embedded Linux devices with only DNS forwarding and caching.

---

## Dependency Detection

Cargo handles dependency resolution automatically for all Rust crate dependencies. Native system libraries (required only for certain optional features) are detected at build time by `build.rs`.

### How Cargo Dependency Resolution Works

1. **Cargo reads `Cargo.toml`** — parses the `[dependencies]` and `[features]` sections
2. **Resolves dependency graph** — downloads and caches crate sources from crates.io in `~/.cargo/registry/`
3. **Runs `build.rs`** — executes the build script for platform detection and native library linking
4. **Compiles dependency tree** — builds all crate dependencies before the main project
5. **Compiles `src/` modules** — compiles the dnsmasq source with `#[cfg(feature = "...")]` gates applied
6. **Links binary** — produces `target/release/dnsmasq` (or `target/debug/dnsmasq`)

### How `build.rs` Handles Native Libraries

The `build.rs` build script uses the `pkg-config` crate to detect native system libraries at build time. It runs automatically when you invoke `cargo build`.

**What `build.rs` does:**

1. **Platform detection**: Emits `cargo:rustc-cfg` directives based on `target_os` and `target_arch`
2. **Native library detection**: For features requiring system libraries (`dbus`, `nftset`, `conntrack`), probes via pkg-config
3. **Linker directives**: Emits `cargo:rustc-link-lib=` to link native libraries
4. **Error reporting**: Prints clear warnings if a required native library is missing

**Example — D-Bus detection in `build.rs`:**

```rust
#[cfg(feature = "dbus")]
{
    if let Err(e) = pkg_config::probe_library("dbus-1") {
        eprintln!("Warning: D-Bus feature enabled but libdbus-1 not found: {}", e);
    }
}
```

### Cargo.toml `[features]` Section

The `[features]` section in `Cargo.toml` defines all available feature flags and their dependencies:

```toml
[features]
default = ["dhcp", "dhcp6", "tftp", "script", "auth", "ipset", "loop_detect", "dump"]

dhcp = []
dhcp6 = ["dhcp"]          # DHCPv6 requires DHCPv4
dnssec = ["dep:ring"]      # Enables ring crate for crypto
dbus = ["dep:dbus"]        # Enables dbus crate FFI
tftp = []
auth = []
ipset = ["dep:netlink-packet-core"]
# ... (see Cargo.toml for complete list)
```

---

## Cross-Compilation

Rust provides first-class cross-compilation support through `rustup` target management and `.cargo/config.toml` linker configuration.

### Cross-Compilation Workflow

1. **Install the target toolchain:**

```bash
rustup target add aarch64-unknown-linux-gnu
```

2. **Install the cross-compilation linker:**

```bash
# Debian/Ubuntu
sudo apt-get install gcc-aarch64-linux-gnu

# RHEL/CentOS/Fedora
sudo dnf install gcc-aarch64-linux-gnu
```

3. **Configure the linker in `.cargo/config.toml`:**

```toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
```

4. **Build for the target:**

```bash
cargo build --release --target aarch64-unknown-linux-gnu
```

5. **Output binary:**

```bash
ls -lh target/aarch64-unknown-linux-gnu/release/dnsmasq
file target/aarch64-unknown-linux-gnu/release/dnsmasq
# dnsmasq: ELF 64-bit LSB pie executable, ARM aarch64, ...
```

### Cross-Compilation Targets

#### ARM64 Linux (aarch64)

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

**Linker:** `aarch64-linux-gnu-gcc` (install via `apt install gcc-aarch64-linux-gnu`)

#### ARM32 Linux (armv7)

```bash
rustup target add armv7-unknown-linux-gnueabihf
cargo build --release --target armv7-unknown-linux-gnueabihf
```

**Linker:** `arm-linux-gnueabihf-gcc` (install via `apt install gcc-arm-linux-gnueabihf`)

#### MIPS Linux (OpenWrt)

```bash
rustup target add mips-unknown-linux-musl
cargo build --release --target mips-unknown-linux-musl
```

Or for little-endian MIPS:

```bash
rustup target add mipsel-unknown-linux-musl
cargo build --release --target mipsel-unknown-linux-musl
```

### Cross-Compilation with Features

Features work identically when cross-compiling:

```bash
cargo build --release --target aarch64-unknown-linux-gnu --features "dnssec,dbus"
```

**Note:** When the `dbus` or other native-library features are enabled during cross-compilation, ensure the target architecture's development libraries are available and that `PKG_CONFIG_PATH` points to the cross-compiled library pkgconfig files.

### C Compiler Requirement for `ring`

The `ring` crate requires a C compiler (via the `cc` build crate) to compile assembly routines for cryptographic operations. When cross-compiling with the `dnssec` feature, ensure the cross-compilation C compiler is available.

For cross-compilation, the `cc` crate automatically uses the linker specified in `.cargo/config.toml` to find the appropriate C compiler.

### `.cargo/config.toml` Reference

The repository includes pre-configured cross-compilation profiles:

```toml
# ARM64 (aarch64) cross-compilation
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
```

You can add additional target profiles as needed:

```toml
# ARM32 cross-compilation
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"

# MIPS cross-compilation (OpenWrt)
[target.mips-unknown-linux-musl]
linker = "mips-linux-musl-gcc"
```

---

## Platform-Specific Instructions

### Linux

Linux is the primary development platform with full feature support.

#### Debian/Ubuntu

**Install Rust and build dependencies:**

```bash
# Install C compiler (required for ring crate assembly)
sudo apt-get install build-essential pkg-config

# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build dnsmasq
cargo build --release
```

**Optional native libraries (only for features that require them):**

```bash
# D-Bus control interface (--features dbus)
sudo apt-get install libdbus-1-dev

# nftables set integration (--features nftset)
sudo apt-get install libnftables-dev

# Conntrack mark retrieval (--features conntrack)
sudo apt-get install libnetfilter-conntrack-dev
```

**Full-featured build:**

```bash
sudo apt-get install libdbus-1-dev libnftables-dev libnetfilter-conntrack-dev
cargo build --release --all-features
```

#### RHEL/CentOS/Fedora

**Install Rust and build dependencies:**

```bash
# Install C compiler (required for ring crate)
sudo dnf install gcc pkg-config

# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build dnsmasq
cargo build --release
```

**Optional native libraries:**

```bash
# D-Bus (--features dbus)
sudo dnf install dbus-devel

# nftables (--features nftset, RHEL 8+)
sudo dnf install nftables-devel

# Conntrack (--features conntrack)
sudo dnf install libnetfilter_conntrack-devel
```

#### Arch Linux

```bash
# Install Rust (system package or rustup)
sudo pacman -S rust

# Or via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build dnsmasq
cargo build --release
```

**Optional native libraries:**

```bash
sudo pacman -S dbus libnftables libnetfilter_conntrack
```

---

### FreeBSD

FreeBSD uses BPF (Berkeley Packet Filter) for raw packet access. The platform backend is `src/net/platform/bsd/bpf.rs`.

**Install Rust and build:**

```bash
# Install Rust via pkg or rustup
pkg install rust

# Or via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build dnsmasq
cargo build --release
```

**Platform-Specific Behavior:**
- Uses BPF instead of Linux netlink (`src/net/platform/bsd/bpf.rs`)
- Requires `/dev/bpf` device access for DHCP
- Service management via `rc.d` scripts

**Optional native libraries:**

```bash
# D-Bus (--features dbus)
pkg install dbus
```

---

### OpenBSD

**Install Rust and build:**

```bash
# Install Rust
pkg_add rust

# Build dnsmasq
cargo build --release
```

**Security Notes:**
- Privilege separation via `_dnsmasq` user (create before running)
- BPF filter socket requires root or appropriate group membership
- Platform backend: `src/net/platform/bsd/bpf.rs`

---

### macOS

macOS uses BPF for packet capture. The platform backend is `src/net/platform/bsd/bpf.rs`.

**Install Rust and build:**

```bash
# Install Xcode command-line tools (provides C compiler for ring)
xcode-select --install

# Install Rust via rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Or via Homebrew
brew install rust

# Build dnsmasq
cargo build --release
```

**macOS-Specific Notes:**
- System Integrity Protection (SIP) may prevent binding to port 53
- Consider using a high port (e.g., 5353) or configuring SIP for development
- BPF device limit: macOS limits number of `/dev/bpf*` devices (check `sysctl debug.bpf_maxdevices`)

**Optional native libraries (via Homebrew):**

```bash
# D-Bus (--features dbus)
brew install dbus
```

---

### Android (NDK Cross-Compilation)

Rust supports Android targets for cross-compilation via the Android NDK:

```bash
# Install Android target
rustup target add aarch64-linux-android

# Configure linker in .cargo/config.toml
# [target.aarch64-linux-android]
# linker = "/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"

# Build minimal (DNS-only) for Android
cargo build --release --no-default-features --target aarch64-linux-android
```

**Note:** Android builds typically use `--no-default-features` for security (no TFTP, no script execution).

---

## Static vs Dynamic Linking

### Dynamic Linking (Default)

The standard `cargo build --release` produces a dynamically-linked binary:

```bash
cargo build --release

# Check dynamic dependencies
ldd target/release/dnsmasq
```

**Advantages:**
- Smaller binary size
- Benefits from shared library security updates
- Standard deployment for most Linux distributions

**Disadvantages:**
- Requires shared libraries at runtime
- Not suitable for rescue environments or containers without shared libraries

---

### Static Linking with musl

For fully static binaries with no runtime library dependencies, build against the musl C library:

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Verify static linking
ldd target/x86_64-unknown-linux-musl/release/dnsmasq
# Output: "not a dynamic executable" (fully static)
file target/x86_64-unknown-linux-musl/release/dnsmasq
# dnsmasq: ELF 64-bit LSB executable, x86-64, statically linked, ...
```

**ARM64 static build:**

```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

**Advantages:**
- Self-contained executable — no runtime dependencies
- Ideal for containers, embedded systems, and rescue environments
- Consistent behavior across different Linux distributions

**Disadvantages:**
- Larger binary size
- No benefit from shared library security updates
- D-Bus feature may not work with musl (libdbus requires glibc)

---

### Static Linking of Native Dependencies

When optional features require native libraries (D-Bus, nftset, conntrack), static linking of those specific libraries can be configured through the `pkg-config` crate in `build.rs`:

```bash
# Force static linking of pkg-config detected libraries
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release
```

**Note:** This approach may not work for all native libraries. Prefer the musl target for fully static builds.

### RUSTFLAGS for Linker Options

Additional linker options can be passed via the `RUSTFLAGS` environment variable:

```bash
# Pass additional linker flags
RUSTFLAGS="-C link-args=-Wl,--gc-sections" cargo build --release
```

---

## Binary Size Optimization

Optimize binary size for embedded systems and size-constrained deployments.

### Size Optimization Techniques

#### 1. Feature Selection

Disable unnecessary features to reduce code size:

```bash
# DNS-only (smallest possible)
cargo build --release --no-default-features

# DNS + DHCP only
cargo build --release --no-default-features --features "dhcp,dhcp6"
```

**Impact:** Feature selection is the most effective size reduction technique. Each disabled feature eliminates its entire module from the binary.

#### 2. Cargo Release Profile Optimization

Configure size optimization in `Cargo.toml`:

```toml
[profile.release]
opt-level = "s"       # Optimize for size (or "z" for minimal size)
lto = true            # Link-time optimization (cross-crate dead code elimination)
strip = "symbols"     # Strip debug symbols from binary
panic = "abort"       # Abort on panic instead of unwinding (saves ~10-20KB)
codegen-units = 1     # Single codegen unit (slower compile, better optimization)
```

**Optimization levels:**
- `opt-level = 3` — Speed-optimized (default release)
- `opt-level = "s"` — Size-optimized
- `opt-level = "z"` — Aggressively size-optimized (may be slower)

#### 3. Strip Debug Symbols

Stripping is configured in the release profile (`strip = "symbols"`) or can be done manually:

```bash
# Manual strip after build
strip target/release/dnsmasq

# Check resulting size
ls -lh target/release/dnsmasq
```

#### 4. Abort on Panic

Replacing the default panic unwind mechanism with abort saves binary size:

```toml
[profile.release]
panic = "abort"
```

**Impact:** Saves approximately 10–20KB by removing unwinding tables and cleanup code.

#### 5. Single Codegen Unit

```toml
[profile.release]
codegen-units = 1
```

**Impact:** Allows LLVM to perform more aggressive optimizations across the entire crate. Increases compile time but produces smaller and faster binaries.

---

### Size Comparison Table

Approximate binary sizes for different configurations (Linux x86-64):

| Configuration | Approx. Size | Features |
|--------------|-------------|----------|
| Minimal (DNS-only, `--no-default-features`, `opt-level="z"`, stripped) | ~1.5–2 MB | DNS forwarding and caching only |
| Default features (release, stripped) | ~3–4 MB | DHCP, TFTP, auth, scripting, ipset, loop detection, dump |
| All features (release, stripped) | ~5–7 MB | All subsystems including DNSSEC, D-Bus, conntrack, nftset |
| Minimal musl static | ~2–3 MB | DNS-only, fully static, no shared libraries |

**Note:** Rust binaries are typically larger than equivalent C binaries because the Rust standard library is statically linked. This is a tradeoff for guaranteed memory safety and the elimination of runtime library dependencies.

### Analyzing Binary Size

Use `cargo-bloat` to identify which crates and functions contribute most to binary size:

```bash
# Install cargo-bloat
cargo install cargo-bloat

# Analyze by crate
cargo bloat --release --crates

# Analyze by function (top 20)
cargo bloat --release -n 20
```

---

## Build Troubleshooting

### Common Build Errors and Solutions

#### Error: "linker `cc` not found"

**Symptom:**

```
error: linker `cc` not found
  |
  = note: No such file or directory (os error 2)
```

**Cause:** No C compiler installed. The `ring` crate requires a C compiler for assembly compilation.

**Solution:**

```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# RHEL/CentOS/Fedora
sudo dnf install gcc

# macOS
xcode-select --install
```

---

#### Error: "failed to run custom build command for `ring`"

**Symptom:**

```
error: failed to run custom build command for `ring v0.17.14`
```

**Cause:** The `ring` crate's build script failed, usually because a C compiler or assembler is not available.

**Solution:** Ensure a C compiler (GCC or Clang) is installed and in your `PATH`:

```bash
# Verify C compiler
cc --version

# If missing, install build tools
sudo apt-get install build-essential   # Debian/Ubuntu
sudo dnf install gcc                   # Fedora/RHEL
```

---

#### Error: "pkg-config not found" or "could not find native library `dbus-1`"

**Symptom:**

```
error: could not find native static library `dbus-1`, perhaps an -L flag is missing?
```

**Cause:** A feature requiring a native library is enabled, but the library or pkg-config is not installed.

**Solution 1:** Install the required native library (see [Native Library Requirements](#native-library-requirements)).

**Solution 2:** Build without the feature that requires the library:

```bash
# Build without D-Bus
cargo build --release
# (D-Bus is not a default feature, so omitting --features dbus is sufficient)
```

**Solution 3:** Specify library path manually:

```bash
PKG_CONFIG_PATH=/opt/dbus/lib/pkgconfig cargo build --release --features dbus
```

---

#### Error: "linking with `cc` failed" (Cross-Compilation)

**Symptom:**

```
error: linking with `cc` failed: exit status: 1
  |
  = note: /usr/bin/ld: target/aarch64-unknown-linux-gnu/release/deps/dnsmasq-xxx.o:
          file format not recognized
```

**Cause:** The default linker (`cc`) is being used instead of the cross-compilation linker.

**Solution:** Configure the cross-compilation linker in `.cargo/config.toml`:

```toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
```

And ensure the cross-compiler is installed:

```bash
sudo apt-get install gcc-aarch64-linux-gnu
```

---

#### Error: "unresolved import"

**Symptom:**

```
error[E0432]: unresolved import `crate::dhcp`
```

**Cause:** A module that is gated behind a Cargo feature flag is being referenced, but the feature is not enabled.

**Solution:** Enable the required feature:

```bash
# If the error references dhcp modules
cargo build --features dhcp

# Or build with all features
cargo build --all-features
```

Check that feature dependencies are correct in `Cargo.toml` (e.g., `dhcp6` requires `dhcp`).

---

#### Error: "target `xxx` not found"

**Symptom:**

```
error[E0463]: can't find crate for `std`
  |
  = note: the `aarch64-unknown-linux-gnu` target may not be installed
```

**Cause:** The Rust target triple is not installed via rustup.

**Solution:**

```bash
rustup target add aarch64-unknown-linux-gnu
```

List available targets:

```bash
rustup target list
```

---

### Debugging Build Issues

#### Enable Verbose Build Output

```bash
# Verbose Cargo output (shows all compiler invocations)
cargo build -vv

# Even more detail
cargo build -vv 2>&1 | tee build.log
```

#### Check Rust Toolchain

```bash
# Verify Rust version
rustc --version
cargo --version

# Check installed targets
rustup target list --installed

# Check active toolchain
rustup show
```

#### Runtime Debugging

```bash
# Run with debug logging enabled
RUST_LOG=debug cargo run -- --no-daemon --log-queries

# Enable full panic backtraces
RUST_BACKTRACE=1 cargo run -- --no-daemon

# Full backtrace with source locations
RUST_BACKTRACE=full cargo run -- --no-daemon
```

---

## Build System Architecture

### Cargo Build Flow

```mermaid
flowchart TD
    Start([cargo build --release --features ...]) --> ReadManifest[Read Cargo.toml:<br/>dependencies, features, profiles]
    ReadManifest --> ResolveGraph[Resolve Dependency Graph:<br/>fetch crates from crates.io]
    
    ResolveGraph --> RunBuildScript[Run build.rs:<br/>platform detection,<br/>native lib linking via pkg-config]
    
    RunBuildScript --> CompileDeps[Compile Crate Dependencies:<br/>mio, nix, ring, bytes, etc.]
    
    CompileDeps --> CompileSrc[Compile src/ Module Tree:<br/>apply #[cfg feature] gates]
    
    CompileSrc --> ApplyFeatures{Apply Feature Gates}
    
    ApplyFeatures -->|dhcp enabled| CompileDHCP[Compile src/dhcp/**/*.rs]
    ApplyFeatures -->|dnssec enabled| CompileDNSSEC[Compile src/dns/dnssec/**/*.rs]
    ApplyFeatures -->|tftp enabled| CompileTFTP[Compile src/integration/tftp.rs]
    ApplyFeatures -->|dbus enabled| CompileDBUS[Compile src/integration/dbus.rs]
    ApplyFeatures -->|Core modules| CompileCore[Compile src/core/**/*.rs,<br/>src/dns/**/*.rs,<br/>src/net/**/*.rs,<br/>src/types/**/*.rs]
    
    CompileDHCP --> Link
    CompileDNSSEC --> Link
    CompileTFTP --> Link
    CompileDBUS --> Link
    CompileCore --> Link
    
    Link[Link Binary] --> Output([target/release/dnsmasq])
    
    style Start fill:#e1f5ff
    style Output fill:#e1ffe1
    style RunBuildScript fill:#fff4e1
    style ApplyFeatures fill:#fff4e1
```

### Feature Gate Compilation Flow

```mermaid
flowchart TD
    Feature([Cargo feature enabled]) --> CfgGate[#[cfg feature = ...] applied]
    
    CfgGate --> ModuleCompile[Feature module compiled]
    CfgGate --> TypesInclude[Related types included]
    CfgGate --> TestsCompile[Feature tests compiled]
    
    ModuleCompile --> Example1[Example: dhcp feature →<br/>src/dhcp/ modules compiled]
    TypesInclude --> Example2[Example: dhcp feature →<br/>src/types/dhcp.rs included]
    TestsCompile --> Example3[Example: dhcp feature →<br/>tests/integration/dhcp_*.rs compiled]
    
    style Feature fill:#e1f5ff
    style Example1 fill:#e1ffe1
    style Example2 fill:#e1ffe1
    style Example3 fill:#e1ffe1
```

### Rust Module Hierarchy

The source code is organized into domain-specific modules:

```
src/
├── main.rs                      # Binary entry point (init, daemonize, event loop)
├── lib.rs                       # Library root (module declarations, re-exports)
├── config/                      # Configuration parsing
│   ├── mod.rs                   # Config module root
│   ├── options.rs               # CLI/config parser (160+ options, Result-based errors)
│   ├── constants.rs             # Numeric defaults (CACHESIZ=150, MAXLEASES=1000, etc.)
│   └── feature_flags.rs         # Feature flag documentation
├── core/                        # Core runtime
│   ├── daemon.rs                # DaemonState struct (decomposed from C global state)
│   ├── event_loop.rs            # mio::Poll event loop
│   ├── signal.rs                # Signal handling (self-pipe pattern)
│   ├── logging.rs               # Async syslog (log/tracing facade)
│   ├── util.rs                  # DNS name validation, I/O helpers
│   ├── prng.rs                  # CSPRNG (replacing SURF PRNG)
│   └── metrics.rs               # Metric definitions and reset
├── dns/                         # DNS stack
│   ├── protocol.rs              # Wire-format constants
│   ├── wire.rs                  # DNS packet parsing/construction
│   ├── cache.rs                 # DNS cache (HashMap + LRU)
│   ├── forward.rs               # Forwarding engine (query state machine)
│   ├── server_match.rs          # Domain pattern matching, server selection
│   ├── edns.rs                  # EDNS0 OPT handling
│   ├── rrfilter.rs              # RR filtering
│   ├── auth.rs                  # Authoritative zone serving
│   ├── domain.rs                # Synthetic hostnames, split-horizon
│   ├── loop_detect.rs           # Forwarding loop detection
│   └── dnssec/                  # DNSSEC validation (feature-gated)
│       ├── validation.rs        # Trust chain validation
│       └── crypto.rs            # ring-based crypto (RSA, ECDSA, EdDSA)
├── dhcp/                        # DHCP stack (feature-gated)
│   ├── common.rs                # Shared DHCP utilities
│   ├── v4/                      # DHCPv4
│   │   ├── server.rs            # DHCPv4 core
│   │   └── rfc2131.rs           # DHCPv4 protocol (DORA cycle)
│   ├── v6/                      # DHCPv6
│   │   ├── server.rs            # DHCPv6 core
│   │   ├── rfc3315.rs           # DHCPv6 protocol
│   │   └── outpacket.rs         # DHCPv6 option serialization
│   ├── lease.rs                 # Lease persistence
│   ├── radv/                    # Router Advertisements
│   │   ├── server.rs            # RA construction
│   │   └── slaac.rs             # SLAAC address probing
│   └── helper.rs                # Privilege-separated script helper
├── net/                         # Network layer
│   ├── interface.rs             # Interface enumeration
│   ├── socket.rs                # Upstream socket pool
│   ├── arp.rs                   # ARP/neighbor cache
│   └── platform/                # Platform abstraction
│       ├── linux/               # Linux-specific (#[cfg(target_os = "linux")])
│       │   ├── netlink.rs       # Netlink route/address monitoring
│       │   ├── ipset.rs         # Linux ipset via netlink
│       │   ├── inotify.rs       # File-change monitoring
│       │   └── conntrack.rs     # Conntrack mark retrieval
│       └── bsd/                 # BSD-specific (#[cfg(target_os = "freebsd")])
│           ├── bpf.rs           # BPF raw packets, PF_ROUTE
│           └── pf_tables.rs     # PF table population
├── integration/                 # External system interfaces
│   ├── dbus.rs                  # D-Bus system bus (feature-gated)
│   ├── ubus.rs                  # OpenWrt UBus (feature-gated)
│   ├── nftset.rs                # nftables sets (feature-gated)
│   └── tftp.rs                  # TFTP server (feature-gated)
├── debug/                       # Debug utilities
│   └── dump.rs                  # Pcap packet capture (feature-gated)
└── types/                       # Shared type definitions
    ├── addr.rs                  # AllAddr enum, SocketAddress enum
    ├── dns.rs                   # DnsHeader, CacheEntry, ForwardRecord
    ├── dhcp.rs                  # DhcpLease, DhcpConfig, DhcpOption
    ├── network.rs               # InterfaceRecord, Listener, ServerEntry
    └── ipv6.rs                  # IPv6 address helpers
```

### Incremental Compilation

Cargo uses incremental compilation and fingerprinting to avoid unnecessary rebuilds:

- **Dependency caching**: Compiled crate dependencies are cached in `target/` and reused across builds
- **Incremental compilation**: Only modified modules and their dependents are recompiled
- **Build fingerprinting**: Cargo tracks file modifications, compiler flags, and feature flags to determine what needs rebuilding
- **Parallel compilation**: Modules without dependencies on each other are compiled in parallel

To force a full rebuild:

```bash
cargo clean
cargo build --release
```

---

## Advanced Build Topics

### Static Analysis

Rust provides compile-time memory safety guarantees. Additional static analysis tools:

```bash
# Clippy — Rust linter with 500+ lint checks
cargo clippy --all-features
cargo clippy --all-features -- -W clippy::pedantic

# Miri — experimental interpreter for detecting undefined behavior
cargo +nightly miri test
```

### Running Tests

The test suite includes unit tests (embedded in source modules via `#[cfg(test)]`) and integration tests (in `tests/`):

```bash
# Run all unit tests with default features
cargo test

# Run all tests including feature-gated ones
cargo test --all-features

# Run a specific integration test file
cargo test --test dns_forwarding

# Run tests matching a name pattern
cargo test dns::cache

# Run tests with stdout/stderr visible
cargo test -- --nocapture

# Run tests with a specific number of threads
cargo test -- --test-threads=1
```

### Code Coverage

Generate code coverage reports using `cargo-tarpaulin` or `cargo-llvm-cov`:

```bash
# Using cargo-tarpaulin
cargo install cargo-tarpaulin
cargo tarpaulin --all-features

# Using cargo-llvm-cov (requires llvm-tools)
cargo install cargo-llvm-cov
cargo llvm-cov --all-features --html
# Coverage report: target/llvm-cov/html/index.html
```

### Developer Build (Debug Mode)

Debug builds include full debug information and no optimizations:

```bash
# Build in debug mode (default)
cargo build

# Run with debug logging and backtraces
RUST_LOG=debug RUST_BACKTRACE=1 cargo run -- --no-daemon --log-queries
```

Debug builds include:
- Full debug symbols for debugger integration (GDB, LLDB)
- Runtime bounds checking and overflow detection
- Debug assertions enabled

**Debugging with GDB/LLDB:**

```bash
# GDB
gdb target/debug/dnsmasq
(gdb) run --no-daemon --log-queries

# LLDB (macOS)
lldb target/debug/dnsmasq
(lldb) run -- --no-daemon --log-queries
```

### Benchmarking

```bash
# Run benchmarks (requires nightly for built-in benchmarks)
cargo +nightly bench

# Or use criterion for stable Rust benchmarks
cargo bench
```

---

## Summary

### Quick Reference: Common Build Commands

```bash
# Standard build (debug)
cargo build

# Release build with default features
cargo build --release

# Full-featured build (all subsystems)
cargo build --release --all-features

# Minimal DNS-only build
cargo build --release --no-default-features

# DNSSEC + D-Bus build
cargo build --release --features "dnssec,dbus"

# Size-optimized build (configure opt-level="s" in Cargo.toml release profile)
cargo build --release

# Static build (musl, no runtime dependencies)
cargo build --release --target x86_64-unknown-linux-musl

# Cross-compile for ARM64
cargo build --release --target aarch64-unknown-linux-gnu

# Run all tests
cargo test --all-features

# Lint check
cargo clippy --all-features

# Install to ~/.cargo/bin
cargo install --path .

# Clean build artifacts
cargo clean
```

---

### Build System Files Reference

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace manifest with dependencies and feature flags |
| `rust-toolchain.toml` | Pinned Rust 1.93.1 stable, edition 2024 |
| `build.rs` | Platform detection, optional native library linking via pkg-config |
| `.cargo/config.toml` | Cross-compilation profiles for x86-64 and ARM64 |
| `src/config/constants.rs` | Compile-time numeric defaults (CACHESIZ, MAXLEASES, FTABSIZ, etc.) |
| `src/config/feature_flags.rs` | Feature flag documentation and compile-time configuration |

---

### Getting Help

**Documentation:**
- Build system: This document (`docs/BUILDING.md`)
- Configuration: `dnsmasq.conf.example` (annotated configuration template)
- Architecture: `docs/ARCHITECTURE.md`
- Project website: http://www.thekelleys.org.uk/dnsmasq/

**Diagnosing Build Issues:**

```bash
# Check Rust toolchain version
rustc --version
cargo --version

# Verbose build output
cargo build -vv

# Check installed targets
rustup target list --installed
```

**Reporting Build Issues:**
- Mailing list: dnsmasq-discuss@lists.thekelleys.org.uk
- Include: Platform, `rustc --version`, `cargo --version`, build command, error output
- Provide: `uname -a`, `rustup show`, `cargo build -vv` output

---

**Document Version:** 2.0  
**Based on:** dnsmasq 2.92 Rust rewrite  
**Last Updated:** 2025  
**Maintainer:** Simon Kelley

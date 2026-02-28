# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Refactoring Objective

Based on the prompt, the Blitzy platform understands that the refactoring objective is to perform a **complete, production-ready rewrite** of the entire dnsmasq C codebase (version 2.92, ~15,000 SLOC across 50 source files) into idiomatic Rust, replacing all manual memory management with Rust's ownership and borrowing semantics while maintaining full functional equivalence with the existing C implementation.

- **Refactoring Type:** Full tech stack migration (C → Rust) with architectural modernization
- **Target Repository:** New Rust crate within the same repository, replacing the C `src/` directory with a Rust `src/` workspace
- **Refactoring Goals with Enhanced Clarity:**
  - Eliminate all manual `malloc`/`free`/`realloc` memory management by leveraging Rust's ownership model, `Box`, `Vec`, `Arc`, and lifetime annotations
  - Replace C-style pointer arithmetic and `union` types with Rust enums, `Option<T>`, and `Result<T, E>` for type-safe error handling
  - Rewrite the single-threaded, poll-based event loop using Rust's `mio` crate to maintain the non-blocking I/O architecture without introducing async runtime overhead
  - Convert all 50 C source files into a well-organized Rust module hierarchy preserving the existing functional decomposition (DNS, DHCP, TFTP, platform abstraction, integration)
  - Preserve the existing configuration file format (dnsmasq.conf) and all 160+ CLI options exactly as documented in `dnsmasq.conf.example` and parsed by `src/option.c`
  - Maintain wire-protocol compatibility for DNS (RFC 1035, RFC 6891), DHCPv4 (RFC 2131), DHCPv6 (RFC 3315), DNSSEC (RFC 4033/4034/4035), TFTP (RFC 1350/2349), and Router Advertisements (RFC 4861)
  - Deliver zero `unsafe` blocks except where FFI to system libraries (D-Bus, UBus, netfilter, nftables, libidn2) is unavoidable
  - Ensure the output binary compiles and runs correctly on both Linux x86-64 and ARM64 architectures

- **Implicit Requirements Surfaced:**
  - The global `struct daemon` state hub (100+ members) must be decomposed into well-scoped Rust structs with clear ownership boundaries
  - The `HAVE_*` compile-time feature flag system (HAVE_DHCP, HAVE_DNSSEC, HAVE_DBUS, etc.) maps naturally to Cargo feature flags
  - Signal handling via the self-pipe pattern in `dnsmasq.c` must be reimplemented using Rust-safe signal abstractions
  - The privilege separation model (fork-based helper process in `helper.c`) requires careful `unsafe` FFI for `fork()`/`exec()` or a redesign using Rust process spawning
  - Platform abstraction between Linux (`netlink.c`) and BSD (`bpf.c`) must use Rust conditional compilation (`#[cfg(target_os)]`) rather than C preprocessor guards
  - The SURF PRNG in `util.c` should be replaced with a Rust-native CSPRNG from the `rand` crate family
  - DNS name compression (0xC0 pointers in `rfc1035.c`) and wire-format parsing require careful zero-copy buffer handling with Rust slices

### 0.1.2 Technical Interpretation

This refactoring translates to the following technical transformation strategy:

- **Current Architecture:** A monolithic single-process, single-threaded C daemon built with GNU Make, using POSIX `poll()` for I/O multiplexing, manual memory management with bounded data structures (CACHESIZ=150, MAXLEASES=1000, FTABSIZ=150), and compile-time feature selection via `HAVE_*` preprocessor macros in `config.h`
- **Target Architecture:** A modular Rust binary crate organized as a Cargo workspace, using `mio` for poll-based I/O, Rust ownership for all memory management, Cargo feature flags for optional subsystems, and trait-based abstractions for platform-specific behavior

**Architecture Mapping:**

| Current (C) | Target (Rust) | Transformation |
|---|---|---|
| `struct daemon` (global singleton, 100+ fields) | `DaemonState` struct with nested domain-specific structs | Decompose into `DnsConfig`, `DhcpState`, `CacheState`, etc. |
| `union all_addr` (multiplexed address types) | `enum AllAddr { V4(Ipv4Addr), V6(Ipv6Addr), ... }` | Replace C unions with Rust enums |
| `union mysockaddr` (socket address union) | `enum SocketAddress { V4(SocketAddrV4), V6(SocketAddrV6) }` | Leverage `std::net` types |
| `struct crec` (cache entry with intrusive list) | `CacheEntry` with `HashMap` + `VecDeque` for LRU | Replace intrusive linked lists with standard collections |
| `struct frec` (forward record with singly-linked list) | `ForwardRecord` managed in `HashMap<u16, ForwardRecord>` | Key by transaction ID |
| `struct dhcp_lease` (lease with linked list) | `DhcpLease` in `HashMap<IpAddr, DhcpLease>` | Key by IP address |
| `poll()` loop in `dnsmasq.c` | `mio::Poll` event loop | Direct architectural equivalent |
| `setjmp`/`longjmp` error recovery in `option.c` | `Result<T, ConfigError>` return types | Idiomatic Rust error handling |
| `HAVE_*` preprocessor macros | Cargo `[features]` in `Cargo.toml` | `#[cfg(feature = "dhcp")]` guards |
| C function pointers for callbacks | Rust trait objects or closures | Type-safe callback system |
| `blockdata` fixed-size chain pool | `Vec<u8>` or `bytes::Bytes` | Standard dynamic allocation |
| Manual `safe_malloc` / `whine_realloc` | Standard Rust allocation via `Vec`, `Box`, `String` | Compiler-managed memory |


## 0.2 Source Analysis

### 0.2.1 Comprehensive Source File Discovery

The dnsmasq repository contains **50 source files** (44 `.c` implementation files and 6 `.h` header files) organized in a flat `src/` directory. All files require rewriting into Rust. The codebase is estimated at approximately **15,000 SLOC** of C99 code.

**Current Structure Mapping:**

```
Current:
src/
├── dnsmasq.h          (central global header, all types/prototypes)
├── config.h           (compile-time feature flags, numeric constants)
├── dns-protocol.h     (DNS wire-format constants and macros)
├── dhcp-protocol.h    (DHCPv4 wire-format constants)
├── dhcp6-protocol.h   (DHCPv6 wire-format constants)
├── radv-protocol.h    (Router Advertisement constants)
├── ip6addr.h          (IPv6 address manipulation helpers)
├── metrics.h          (metric name enum definitions)
├── dnsmasq.c          (main entry point, event loop, signal handling)
├── forward.c          (DNS forwarding engine, query state machine)
├── cache.c            (DNS cache: hash table + LRU eviction)
├── rfc1035.c          (DNS wire-format parsing/construction)
├── option.c           (CLI/config parser, 160+ options, largest module)
├── network.c          (interface enumeration, socket management)
├── util.c             (PRNG, memory helpers, DNS name utilities)
├── log.c              (async non-blocking syslog subsystem)
├── poll.c             (poll()-based I/O multiplexing layer)
├── dnssec.c           (DNSSEC validation, trust chain traversal)
├── crypto.c           (DNSSEC crypto wrapper: RSA, ECDSA, EdDSA)
├── blockdata.c        (fixed-size block chain memory pool)
├── edns0.c            (EDNS0 OPT record handling, ECS, Umbrella)
├── rrfilter.c         (RR filtering, compression pointer rewriting)
├── auth.c             (authoritative DNS zone serving, AXFR)
├── dhcp.c             (DHCPv4 server core, address allocation)
├── dhcp6.c            (DHCPv6 server core, DUID management)
├── rfc2131.c          (DHCPv4 protocol: DISCOVER/OFFER/REQUEST/ACK)
├── rfc3315.c          (DHCPv6 protocol: SOLICIT/ADVERTISE/REQUEST)
├── dhcp-common.c      (shared DHCP utilities, tag matching, PXE)
├── lease.c            (lease persistence, DNS registration)
├── radv.c             (IPv6 Router Advertisement subsystem)
├── slaac.c            (SLAAC address probing and confirmation)
├── outpacket.c        (DHCPv6 packet buffer builder)
├── tftp.c             (read-only TFTP server)
├── helper.c           (privilege-separated script helper process)
├── netlink.c          (Linux netlink route/address monitoring)
├── bpf.c              (BSD BPF/PF_ROUTE interface abstraction)
├── arp.c              (ARP/neighbor cache management)
├── dbus.c             (D-Bus control interface integration)
├── ubus.c             (OpenWrt UBus control interface)
├── ipset.c            (Linux ipset population via netlink)
├── nftset.c           (nftables set population via libnftables)
├── tables.c           (BSD PF table population)
├── conntrack.c        (netfilter conntrack mark retrieval)
├── domain.c           (synthetic names, conditional domains)
├── domain-match.c     (domain pattern matching, server selection)
├── pattern.c          (wildcard pattern utilities)
├── loop.c             (DNS forwarding loop detection)
├── inotify.c          (Linux inotify file-change monitoring)
├── dump.c             (pcap packet dumping for debugging)
└── metrics.c          (metric naming and reset)
```

### 0.2.2 Source File Categorization

**Core Runtime (8 files) — Highest priority, foundational:**

| File | Lines (est.) | Key Responsibilities | Rewrite Complexity |
|------|-------------|---------------------|-------------------|
| `dnsmasq.c` | ~800 | Main entry, event loop, daemonization, signal handling, privilege separation | High — must redesign global init and signal patterns |
| `dnsmasq.h` | ~1,800 | All type definitions, 100+ struct members, function prototypes | High — becomes Rust module tree with trait definitions |
| `config.h` | ~300 | Feature flags, numeric constants, platform detection | Medium — maps to Cargo.toml features and const definitions |
| `option.c` | ~2,500 | Config/CLI parser for 160+ options, `setjmp`/`longjmp` error recovery | Very High — largest module, needs full error-handling redesign |
| `poll.c` | ~150 | Binary-search poll() wrapper with dynamic fd array | Low — replaced by `mio::Poll` abstractions |
| `network.c` | ~800 | Interface enumeration, listener sockets, upstream socket pool | High — platform-specific socket management |
| `log.c` | ~400 | Non-blocking async syslog with bounded queue | Medium — Rust `tracing` or `log` crate replacement |
| `util.c` | ~600 | SURF PRNG, memory allocators, DNS name validation, I/O helpers | Medium — most utilities have Rust stdlib equivalents |

**DNS Stack (9 files) — Core DNS functionality:**

| File | Lines (est.) | Key Responsibilities | Rewrite Complexity |
|------|-------------|---------------------|-------------------|
| `forward.c` | ~1,200 | DNS forwarding state machine, randomized sockets, EDNS0, TCP fallback | Very High — central query routing logic |
| `cache.c` | ~1,100 | Hash table + LRU cache, hosts file parsing, DHCP hostname registration | High — intrusive data structures to replace |
| `rfc1035.c` | ~1,000 | DNS wire-format: name compression, packet construction, answer_request | High — zero-copy buffer parsing critical for performance |
| `dnssec.c` | ~1,200 | DNSSEC validation, trust chains, NSEC/NSEC3 proofs, resource limits | Very High — complex cryptographic validation logic |
| `crypto.c` | ~400 | Nettle crypto wrapper: RSA, ECDSA P-256/P-384, EdDSA | High — must port to Rust `ring` crate APIs |
| `edns0.c` | ~500 | EDNS0 OPT record handling, ECS, MAC options, Umbrella | Medium — in-place packet modification logic |
| `rrfilter.c` | ~350 | RR filtering, compression pointer rewriting, wire-format canonicalization | Medium — pointer arithmetic intensive |
| `auth.c` | ~600 | Authoritative DNS zones, SOA generation, AXFR zone transfers | Medium — self-contained zone serving module |
| `dns-protocol.h` | ~100 | DNS type/class/opcode constants | Low — direct constant mapping |

**DHCP Stack (12 files) — DHCPv4/v6 and Router Advertisements:**

| File | Lines (est.) | Key Responsibilities | Rewrite Complexity |
|------|-------------|---------------------|-------------------|
| `dhcp.c` | ~600 | DHCPv4 core: init, address allocation, ICMP conflict detection | High — SDBM hash allocation, raw socket I/O |
| `dhcp6.c` | ~500 | DHCPv6 core: init, DUID management, address6 allocation | High — complex IPv6 address management |
| `rfc2131.c` | ~1,200 | DHCPv4 protocol: full DORA cycle, PXE/UEFI, relay agent | Very High — largest DHCP module |
| `rfc3315.c` | ~1,000 | DHCPv6 protocol: SOLICIT/REQUEST/REPLY, IA management, relay | Very High — complex DHCPv6 state machine |
| `dhcp-common.c` | ~700 | Shared DHCP utilities: tag matching, option filtering, PXE, recv_dhcp_packet | High — shared infrastructure for both DHCP versions |
| `lease.c` | ~600 | Lease persistence, DNS registration, expiration management | Medium — file I/O and linked list management |
| `radv.c` | ~500 | IPv6 Router Advertisements, PIO/RDNSS/DNSSL construction | Medium — ICMPv6 packet construction |
| `slaac.c` | ~300 | SLAAC address probing via ICMPv6 echo | Low — self-contained probing module |
| `outpacket.c` | ~150 | DHCPv6 option serialization buffer builder | Low — buffer management utility |
| `dhcp-protocol.h` | ~100 | DHCPv4 message type constants | Low — direct constant mapping |
| `dhcp6-protocol.h` | ~100 | DHCPv6 message type constants | Low — direct constant mapping |
| `radv-protocol.h` | ~50 | RA-related ICMPv6 constants | Low — direct constant mapping |

**Platform Abstraction (3 files) — OS-specific backends:**

| File | Lines (est.) | Key Responsibilities | Rewrite Complexity |
|------|-------------|---------------------|-------------------|
| `netlink.c` | ~400 | Linux NETLINK_ROUTE: interface/route enumeration, async events | High — raw netlink protocol via `nix` or `netlink` crate |
| `bpf.c` | ~500 | BSD: BPF raw packets, getifaddrs, PF_ROUTE socket monitoring | High — BSD-only, conditional compilation |
| `arp.c` | ~250 | ARP/neighbor cache: MAC lookup, topology change notification | Medium — platform-dependent iface_enumerate |

**Integration (8 files) — External system interfaces:**

| File | Lines (est.) | Key Responsibilities | Rewrite Complexity |
|------|-------------|---------------------|-------------------|
| `helper.c` | ~400 | Forked helper process for scripts and Lua execution | High — fork/exec with privilege separation |
| `dbus.c` | ~700 | D-Bus system bus: server config, metrics, lease management | High — FFI to libdbus-1 |
| `ubus.c` | ~500 | OpenWrt UBus: metrics, events, connmark allowlists | Medium — FFI to libubus/libubox |
| `tftp.c` | ~500 | Read-only TFTP server with option negotiation | Medium — self-contained UDP protocol |
| `ipset.c` | ~300 | Linux ipset via netlink for DNS-driven firewall sets | Medium — raw netlink message construction |
| `nftset.c` | ~200 | nftables set population via libnftables | Medium — FFI to libnftables |
| `tables.c` | ~200 | BSD PF table population via ioctl | Low — BSD-only, small API surface |
| `conntrack.c` | ~150 | netfilter conntrack mark retrieval via libnetfilter_conntrack | Low — thin FFI wrapper |

**Supporting Utilities (10 files) — Cross-cutting helpers:**

| File | Lines (est.) | Key Responsibilities | Rewrite Complexity |
|------|-------------|---------------------|-------------------|
| `domain.c` | ~350 | Synthetic hostnames, split-horizon domain selection | Medium — domain matching logic |
| `domain-match.c` | ~700 | Server selection: sorted array, binary search, longest-suffix match | High — performance-critical routing |
| `pattern.c` | ~100 | Wildcard pattern matching utilities | Low — simple string matching |
| `blockdata.c` | ~200 | Fixed-size 40-byte block chain pool for DNSSEC data | Low — replaced by `Vec<u8>` |
| `loop.c` | ~200 | DNS forwarding loop detection via probe queries | Low — self-contained probe logic |
| `inotify.c` | ~350 | Linux inotify: watch resolv.conf and dynamic config directories | Medium — Linux-specific, `inotify` crate available |
| `dump.c` | ~350 | Pcap packet dump for debugging | Low — optional debug feature |
| `metrics.c` | ~100 | Metric name array and reset logic | Low — trivial utility |
| `metrics.h` | ~50 | Metric name enum definitions | Low — direct enum mapping |
| `ip6addr.h` | ~50 | IPv6 address helper macros | Low — replaced by `std::net::Ipv6Addr` methods |

### 0.2.3 Additional Source Files

**Root-level configuration and build files:**

| File | Purpose | Action Required |
|------|---------|----------------|
| `Makefile` | GNU Make build driver for C compilation | Replace with `Cargo.toml` workspace configuration |
| `dnsmasq.conf.example` | Annotated example configuration (documentation/template) | Preserve as-is — config format must remain identical |
| `trust-anchors.conf` | DNSSEC root trust anchor data | Preserve as-is — consumed at runtime |
| `doc.html` / `setup.html` | HTML documentation | Preserve as-is |

**Documentation files (`docs/`):**

| File | Content |
|------|---------|
| `docs/ARCHITECTURE.md` | System architecture documentation |
| `docs/BUILDING.md` | Build instructions |
| `docs/CONFIGURATION.md` | Configuration reference |
| `docs/DNSSEC.md` | DNSSEC implementation guide |
| `docs/DNS_CACHING.md` | DNS caching behavior |
| `docs/DNS_FORWARDING.md` | DNS forwarding logic |
| `docs/DHCP_V4.md` | DHCPv4 implementation |
| `docs/DHCP_V6.md` | DHCPv6 implementation |
| `docs/TFTP.md` | TFTP server documentation |

**Contribution scripts (`contrib/`):**

Utility scripts in Perl, Python, and shell that interface with dnsmasq — these are out-of-scope for the Rust rewrite but remain functional as external integrations.


## 0.3 Scope Boundaries

### 0.3.1 Exhaustively In Scope

**Source Transformations (all C → Rust rewrites):**
- `src/*.c` — All 44 C implementation files rewritten as Rust modules
- `src/*.h` — All 6 C header files converted to Rust type definitions, constants, and trait declarations
- `Makefile` — Replaced by `Cargo.toml` with workspace configuration and feature flags

**Rust Crate Structure (new files):**
- `Cargo.toml` — Root workspace manifest with dependencies and feature flags
- `src/main.rs` — Binary entry point replacing `dnsmasq.c` main()
- `src/lib.rs` — Library root with module declarations
- `src/**/*.rs` — All Rust module files organized by functional domain
- `build.rs` — Build script for platform detection and optional native library linking
- `.cargo/config.toml` — Cross-compilation profiles for x86-64 and ARM64
- `rust-toolchain.toml` — Pinned Rust toolchain version

**Test Suite (new files):**
- `tests/**/*.rs` — Integration tests for DNS forwarding, DHCP lease lifecycle, config parsing, wire-format compliance
- `src/**/tests.rs` — Unit tests embedded in each Rust module via `#[cfg(test)]`
- `tests/fixtures/*` — Test configuration files, sample DNS packets, DHCP captures

**Configuration Compatibility:**
- `dnsmasq.conf.example` — Preserved unmodified as the canonical configuration template
- `trust-anchors.conf` — Preserved unmodified for DNSSEC root trust anchors
- All 160+ configuration directives parsed by the current `option.c` must be supported identically

**Documentation Updates:**
- `README.md` — Updated with Rust build instructions, Cargo commands, and architecture overview
- `docs/BUILDING.md` — Rewritten for Rust/Cargo build workflow
- `docs/ARCHITECTURE.md` — Updated to reflect Rust module structure
- `docs/*.md` — Updated references from C source files to Rust modules

**Platform-Specific Conditional Compilation:**
- Linux-specific modules: netlink, ipset, nftset, conntrack, inotify (behind `#[cfg(target_os = "linux")]`)
- BSD-specific modules: bpf, tables (behind `#[cfg(target_os = "freebsd")]` and related)
- Cross-platform modules: DNS, DHCP, TFTP, config parsing, logging

**Import and Dependency Corrections:**
- Every file referencing C `#include "dnsmasq.h"` transforms to Rust `use crate::...` imports
- All inter-module function calls replaced with Rust method calls and trait implementations
- External C library FFI bindings created for optional integrations (D-Bus, UBus, netfilter, nftables, libidn2)

### 0.3.2 Explicitly Out of Scope

As specified by the user, the following items are **excluded** from this refactoring:

- **New features not present in the current dnsmasq version** — The Rust rewrite must achieve functional parity only; no new protocol support, no new configuration options, and no new DNS record types beyond what dnsmasq v2.92 supports
- **Changes to network protocol behavior** — All DNS, DHCP, DHCP6, TFTP, RA, and DNSSEC wire-protocol behavior must remain identical; packet formats, timing, and semantics are preserved exactly
- **GUI or management interface** — No web UI, REST API, or graphical management tools; the Rust binary exposes the same CLI, syslog, D-Bus, and UBus interfaces as the C version
- **Contribution scripts in `contrib/`** — Perl, Python, and shell scripts (dnslist, dynamic-dnsmasq, lease-tools, etc.) remain unchanged as external integrations
- **Android build system in `bld/`** — The Android.mk build configuration is out of scope
- **Debian packaging in `submodules/`** — Debian/Ubuntu packaging metadata is not modified
- **D-Bus policy files in `dbus/`** — XML policy configuration preserved as-is
- **HTML documentation** — `doc.html` and `setup.html` preserved unmodified
- **Internationalization** — The i18n/gettext targets from the Makefile are not ported
- **Embedded Lua scripting** — The optional Lua 5.2+ integration in `helper.c` is deferred; the Rust rewrite supports external script execution only, with Lua embedding addressed as a future enhancement gated behind a Cargo feature flag


## 0.4 Target Design

### 0.4.1 Refactored Structure Planning

The Rust rewrite organizes the flat C `src/` directory into a hierarchical Rust module tree grouped by functional domain. Each C source file maps to one or more Rust modules, and protocol headers become Rust constant/type definition modules.

**Target Architecture:**

```
Target:
Cargo.toml                       (workspace root manifest)
rust-toolchain.toml              (pinned Rust edition and version)
build.rs                         (platform detection, optional native lib linking)
.cargo/
└── config.toml                  (cross-compilation profiles: x86-64, aarch64)
src/
├── main.rs                      (binary entry point: init, daemonize, event loop)
├── lib.rs                       (library root: module declarations, re-exports)
├── config/
│   ├── mod.rs                   (config module root)
│   ├── options.rs               (CLI/config parser: 160+ options with Result-based error handling)
│   ├── constants.rs             (compile-time constants from config.h)
│   └── feature_flags.rs         (Cargo feature flag integration)
├── core/
│   ├── mod.rs                   (core module root)
│   ├── daemon.rs                (DaemonState struct, initialization, shutdown)
│   ├── event_loop.rs            (mio-based poll event loop replacing poll.c)
│   ├── signal.rs                (signal handling via self-pipe pattern)
│   ├── logging.rs               (async non-blocking syslog: log/tracing facade)
│   ├── util.rs                  (DNS name validation, pattern matching, I/O helpers)
│   ├── prng.rs                  (CSPRNG wrapper replacing SURF PRNG)
│   └── metrics.rs               (metric definitions, naming, reset)
├── dns/
│   ├── mod.rs                   (DNS module root)
│   ├── protocol.rs              (DNS wire-format constants from dns-protocol.h)
│   ├── wire.rs                  (DNS wire-format: name compression, parsing, construction from rfc1035.c)
│   ├── cache.rs                 (DNS cache: HashMap + LRU replacing hash table + intrusive list)
│   ├── forward.rs               (forwarding engine: query state machine, server selection)
│   ├── server_match.rs          (domain pattern matching, sorted array, binary search)
│   ├── edns.rs                  (EDNS0 OPT handling, ECS, MAC options, Umbrella)
│   ├── rrfilter.rs              (RR filtering, compression pointer rewriting)
│   ├── auth.rs                  (authoritative zone serving, SOA, AXFR)
│   ├── domain.rs                (synthetic hostnames, split-horizon domain selection)
│   ├── loop_detect.rs           (forwarding loop detection probe system)
│   └── dnssec/
│       ├── mod.rs               (DNSSEC module root)
│       ├── validation.rs        (DNSSEC trust chain validation from dnssec.c)
│       └── crypto.rs            (ring-based crypto: RSA, ECDSA, EdDSA verification)
├── dhcp/
│   ├── mod.rs                   (DHCP module root)
│   ├── common.rs                (shared DHCP utilities: tag matching, option filtering, PXE)
│   ├── protocol_v4.rs           (DHCPv4 constants from dhcp-protocol.h)
│   ├── protocol_v6.rs           (DHCPv6 constants from dhcp6-protocol.h)
│   ├── v4/
│   │   ├── mod.rs               (DHCPv4 module root)
│   │   ├── server.rs            (DHCPv4 core: init, address allocation, ICMP ping)
│   │   └── rfc2131.rs           (DHCPv4 protocol: DORA cycle, PXE, relay agent)
│   ├── v6/
│   │   ├── mod.rs               (DHCPv6 module root)
│   │   ├── server.rs            (DHCPv6 core: init, DUID, address6 allocation)
│   │   ├── rfc3315.rs           (DHCPv6 protocol: SOLICIT/REQUEST/REPLY, IA management)
│   │   └── outpacket.rs         (DHCPv6 option serialization buffer)
│   ├── lease.rs                 (lease persistence, DNS registration, expiration)
│   ├── radv/
│   │   ├── mod.rs               (Router Advertisement module root)
│   │   ├── protocol.rs          (RA ICMPv6 constants from radv-protocol.h)
│   │   ├── server.rs            (RA construction, periodic/solicited sends)
│   │   └── slaac.rs             (SLAAC address probing and confirmation)
│   └── helper.rs                (privilege-separated script helper process)
├── net/
│   ├── mod.rs                   (network module root)
│   ├── interface.rs             (interface enumeration, listener management)
│   ├── socket.rs                (upstream socket pool, randomized source ports)
│   ├── arp.rs                   (ARP/neighbor cache, MAC lookup)
│   └── platform/
│       ├── mod.rs               (platform abstraction root)
│       ├── linux/
│       │   ├── mod.rs           (Linux platform root)
│       │   ├── netlink.rs       (NETLINK_ROUTE: interface/route events)
│       │   ├── ipset.rs         (Linux ipset via netlink)
│       │   ├── inotify.rs       (inotify file-change monitoring)
│       │   └── conntrack.rs     (netfilter conntrack mark retrieval)
│       └── bsd/
│           ├── mod.rs           (BSD platform root)
│           ├── bpf.rs           (BPF raw packets, getifaddrs, PF_ROUTE)
│           └── pf_tables.rs     (BSD PF table population)
├── integration/
│   ├── mod.rs                   (integration module root)
│   ├── dbus.rs                  (D-Bus control interface via FFI)
│   ├── ubus.rs                  (OpenWrt UBus interface via FFI)
│   ├── nftset.rs                (nftables set population via FFI)
│   └── tftp.rs                  (read-only TFTP server)
├── debug/
│   ├── mod.rs                   (debug utilities root)
│   └── dump.rs                  (pcap packet capture for diagnostics)
└── types/
    ├── mod.rs                   (shared type definitions root)
    ├── addr.rs                  (AllAddr enum, SocketAddress enum replacing C unions)
    ├── dns.rs                   (DnsHeader, CacheEntry, ForwardRecord types)
    ├── dhcp.rs                  (DhcpLease, DhcpConfig, DhcpOption types)
    ├── network.rs               (InterfaceRecord, Listener, ServerEntry types)
    └── ipv6.rs                  (IPv6 address helpers replacing ip6addr.h)

tests/
├── integration/
│   ├── dns_forwarding.rs        (end-to-end DNS query forwarding tests)
│   ├── dns_cache.rs             (cache insertion, eviction, TTL tests)
│   ├── dhcp_v4_lifecycle.rs     (DHCPv4 DORA cycle tests)
│   ├── dhcp_v6_lifecycle.rs     (DHCPv6 SOLICIT/REPLY tests)
│   ├── config_parsing.rs        (configuration file parsing tests)
│   ├── wire_format.rs           (DNS/DHCP wire-format encoding/decoding tests)
│   └── dnssec_validation.rs     (DNSSEC trust chain tests)
└── fixtures/
    ├── dnsmasq.conf             (test configuration files)
    ├── sample_packets/          (captured DNS/DHCP packets for replay)
    └── trust-anchors.conf       (test DNSSEC anchors)

dnsmasq.conf.example             (preserved unmodified)
trust-anchors.conf               (preserved unmodified)
docs/                            (updated documentation)
```

### 0.4.2 Web Search Research Conducted

Research was conducted on the following topics to inform the Rust rewrite strategy:

- **Rust networking ecosystem (2025-2026):** The `mio` crate provides a stable, zero-allocation poll-based I/O abstraction over `epoll`/`kqueue`/IOCP, making it the ideal replacement for the C `poll()` loop. Tokio is built on mio but adds async runtime overhead unnecessary for this single-threaded daemon.
- **Rust DNS implementations:** Hickory DNS (formerly Trust-DNS) is the major Rust DNS library (v0.26.x) providing protocol types and DNSSEC support. However, the user constraint of minimal external dependencies favors a self-contained implementation referencing Hickory only for design patterns.
- **Rust cryptography for DNSSEC:** The `ring` crate provides safe RSA, ECDSA (P-256/P-384), and Ed25519 signature verification without requiring OpenSSL. For Ed448 and GOST algorithms currently handled by Nettle, conditional `ring` + `ed448-goldilocks` can be used.
- **Rust stable version:** As of February 2026, Rust stable is at **1.93.1** with edition **2024** available since Rust 1.85.
- **Cross-compilation:** Rust natively supports `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` targets via `rustup target add`.

### 0.4.3 Design Pattern Applications

The Rust rewrite applies the following design patterns to replace C idioms:

- **Builder Pattern** for configuration construction — replacing `setjmp`/`longjmp` error recovery in `option.c` with `ConfigBuilder` that returns `Result<DaemonConfig, ConfigError>`
- **Type-State Pattern** for DHCP lease lifecycle — encoding lease states (DISCOVER → OFFER → REQUEST → ACK) as distinct Rust types to prevent invalid state transitions at compile time
- **Strategy Pattern via Traits** for platform abstraction — defining `trait NetworkBackend` with `fn enumerate_interfaces()`, `fn monitor_changes()` etc., implemented by `LinuxNetlink` and `BsdBpf`
- **Newtype Pattern** for domain names — `struct DnsName(Vec<u8>)` preventing accidental mixing of wire-format and presentation-format strings
- **Enum Dispatch** for address types — replacing C `union all_addr` with `enum AllAddr { V4(Ipv4Addr), V6(Ipv6Addr), Cname(DnsName), ... }` with exhaustive pattern matching
- **Interior Mutability via RefCell** for shared daemon state accessed by multiple subsystems within the single-threaded event loop — controlled mutation without `unsafe`
- **RAII for Socket/File Handle Management** — Rust's `Drop` trait automatically closes file descriptors, replacing manual cleanup in the C code
- **Feature-Gated Compilation** for optional subsystems — `#[cfg(feature = "dhcp")]`, `#[cfg(feature = "dnssec")]`, etc., replacing C `#ifdef HAVE_*` blocks


## 0.5 Transformation Mapping

### 0.5.1 File-by-File Transformation Plan

Every target Rust file is mapped to its C source origin. Transformation modes: **CREATE** (new Rust file from C source), **UPDATE** (modify existing non-code file), **REFERENCE** (use as design reference only).

**Root Project Files:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| Cargo.toml | CREATE | Makefile | Cargo workspace manifest with dependencies, feature flags replacing COPTS/HAVE_* macros |
| rust-toolchain.toml | CREATE | — | Pin Rust 1.93 stable, edition 2024 |
| build.rs | CREATE | Makefile | Platform detection, optional native library linking for D-Bus, netfilter, nftables |
| .cargo/config.toml | CREATE | — | Cross-compilation profiles for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu |
| dnsmasq.conf.example | UPDATE | dnsmasq.conf.example | No changes — config format preserved exactly |
| trust-anchors.conf | UPDATE | trust-anchors.conf | No changes — preserved as runtime data |
| README.md | UPDATE | README.md | Update with Rust build instructions and Cargo commands |
| docs/BUILDING.md | UPDATE | docs/BUILDING.md | Rewrite for Rust/Cargo build workflow |
| docs/ARCHITECTURE.md | UPDATE | docs/ARCHITECTURE.md | Update to reflect Rust module structure |

**Core Runtime Modules:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/main.rs | CREATE | src/dnsmasq.c | Binary entry point: argument parsing, daemonization, mio event loop, signal setup |
| src/lib.rs | CREATE | src/dnsmasq.h | Library root: module tree declarations, public API re-exports |
| src/config/mod.rs | CREATE | src/config.h | Feature flag integration, module organization |
| src/config/options.rs | CREATE | src/option.c | Config/CLI parser: 160+ options with Result<T,E> error handling replacing setjmp/longjmp |
| src/config/constants.rs | CREATE | src/config.h | Numeric constants: CACHESIZ, MAXLEASES, FTABSIZ, TTL defaults, port numbers |
| src/config/feature_flags.rs | CREATE | src/config.h | Cargo feature flag documentation and compile-time configuration |
| src/core/mod.rs | CREATE | — | Core module declarations |
| src/core/daemon.rs | CREATE | src/dnsmasq.c, src/dnsmasq.h | DaemonState struct decomposed from global struct daemon (100+ fields) |
| src/core/event_loop.rs | CREATE | src/poll.c, src/dnsmasq.c | mio::Poll event loop replacing binary-search poll() wrapper and main loop |
| src/core/signal.rs | CREATE | src/dnsmasq.c | Signal handling via self-pipe pattern with Rust-safe abstractions |
| src/core/logging.rs | CREATE | src/log.c | Non-blocking syslog with bounded queue using log/tracing crate facade |
| src/core/util.rs | CREATE | src/util.c | DNS name validation, safe I/O helpers, pattern matching from util.c |
| src/core/prng.rs | CREATE | src/util.c | CSPRNG replacing SURF PRNG, rand16/rand32/rand64 API |
| src/core/metrics.rs | CREATE | src/metrics.c, src/metrics.h | Metric definitions, naming, reset, enum-based metric identifiers |

**Shared Type Definitions:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/types/mod.rs | CREATE | src/dnsmasq.h | Shared types module root |
| src/types/addr.rs | CREATE | src/dnsmasq.h | AllAddr enum and SocketAddress enum replacing union all_addr and union mysockaddr |
| src/types/dns.rs | CREATE | src/dnsmasq.h | DnsHeader, CacheEntry, ForwardRecord structs replacing struct crec, struct frec |
| src/types/dhcp.rs | CREATE | src/dnsmasq.h | DhcpLease, DhcpConfig, DhcpOption types replacing struct dhcp_lease, dhcp_opt |
| src/types/network.rs | CREATE | src/dnsmasq.h | InterfaceRecord, Listener, ServerEntry types replacing struct irec, listener, server |
| src/types/ipv6.rs | CREATE | src/ip6addr.h | IPv6 address helpers using std::net::Ipv6Addr methods |

**DNS Stack Modules:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/dns/mod.rs | CREATE | — | DNS module declarations |
| src/dns/protocol.rs | CREATE | src/dns-protocol.h | DNS type/class/opcode constants as Rust enums and const values |
| src/dns/wire.rs | CREATE | src/rfc1035.c | DNS wire-format: name compression parsing, packet construction, answer_request() |
| src/dns/cache.rs | CREATE | src/cache.c | DNS cache: HashMap<DnsName, Vec<CacheEntry>> + VecDeque LRU replacing hash+intrusive list |
| src/dns/forward.rs | CREATE | src/forward.c | Forwarding engine: receive_query, forward_query, reply_query state machine |
| src/dns/server_match.rs | CREATE | src/domain-match.c | Domain pattern matching, sorted server array, binary search lookup_domain |
| src/dns/edns.rs | CREATE | src/edns0.c | EDNS0 OPT record handling, ECS, MAC options, Umbrella identity |
| src/dns/rrfilter.rs | CREATE | src/rrfilter.c | RR filtering, compression pointer rewriting, wire-format canonicalization |
| src/dns/auth.rs | CREATE | src/auth.c | Authoritative zone serving, SOA generation, AXFR zone transfer |
| src/dns/domain.rs | CREATE | src/domain.c | Synthetic hostnames, conditional domain selection, split-horizon |
| src/dns/loop_detect.rs | CREATE | src/loop.c | Forwarding loop detection: probe generation and detection |
| src/dns/dnssec/mod.rs | CREATE | — | DNSSEC module declarations |
| src/dns/dnssec/validation.rs | CREATE | src/dnssec.c | DNSSEC validation: trust chain, NSEC/NSEC3, resource limits (WORK=40, CRYPTO=200) |
| src/dns/dnssec/crypto.rs | CREATE | src/crypto.c | ring-based crypto: RSA, ECDSA P-256/P-384, Ed25519/Ed448 verification |

**DHCP Stack Modules:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/dhcp/mod.rs | CREATE | — | DHCP module declarations |
| src/dhcp/common.rs | CREATE | src/dhcp-common.c | Shared utilities: tag matching, option filtering, PXE handling, recv_dhcp_packet |
| src/dhcp/protocol_v4.rs | CREATE | src/dhcp-protocol.h | DHCPv4 message type constants and option codes |
| src/dhcp/protocol_v6.rs | CREATE | src/dhcp6-protocol.h | DHCPv6 message type constants and option codes |
| src/dhcp/v4/mod.rs | CREATE | — | DHCPv4 module declarations |
| src/dhcp/v4/server.rs | CREATE | src/dhcp.c | DHCPv4 core: init, address_allocate (SDBM hash), ICMP conflict detect |
| src/dhcp/v4/rfc2131.rs | CREATE | src/rfc2131.c | Full DHCPv4 protocol: DISCOVER/OFFER/REQUEST/ACK, PXE/UEFI, relay |
| src/dhcp/v6/mod.rs | CREATE | — | DHCPv6 module declarations |
| src/dhcp/v6/server.rs | CREATE | src/dhcp6.c | DHCPv6 core: init, DUID management, address6_allocate |
| src/dhcp/v6/rfc3315.rs | CREATE | src/rfc3315.c | DHCPv6 protocol: SOLICIT/ADVERTISE/REQUEST/REPLY, IA_NA/IA_PD |
| src/dhcp/v6/outpacket.rs | CREATE | src/outpacket.c | DHCPv6 option serialization buffer builder |
| src/dhcp/lease.rs | CREATE | src/lease.c | Lease persistence: file read/write, DNS registration, expiration |
| src/dhcp/radv/mod.rs | CREATE | — | Router Advertisement module declarations |
| src/dhcp/radv/protocol.rs | CREATE | src/radv-protocol.h | RA ICMPv6 option type constants |
| src/dhcp/radv/server.rs | CREATE | src/radv.c | RA construction: PIOs, RDNSS/DNSSL, M/O flags, periodic sends |
| src/dhcp/radv/slaac.rs | CREATE | src/slaac.c | SLAAC address probing via ICMPv6 echo, backoff timers |
| src/dhcp/helper.rs | CREATE | src/helper.c | Privilege-separated script helper: fork/exec (unsafe FFI for fork) |

**Network and Platform Modules:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/net/mod.rs | CREATE | — | Network module declarations |
| src/net/interface.rs | CREATE | src/network.c | Interface enumeration, listener socket creation/management |
| src/net/socket.rs | CREATE | src/network.c | Upstream server socket pool, randomized source ports |
| src/net/arp.rs | CREATE | src/arp.c | ARP/neighbor cache: MAC lookup, topology notifications |
| src/net/platform/mod.rs | CREATE | — | Platform abstraction trait definitions |
| src/net/platform/linux/mod.rs | CREATE | — | Linux platform module declarations |
| src/net/platform/linux/netlink.rs | CREATE | src/netlink.c | NETLINK_ROUTE: interface/route enumeration and async events |
| src/net/platform/linux/ipset.rs | CREATE | src/ipset.c | Linux ipset via netlink message construction |
| src/net/platform/linux/inotify.rs | CREATE | src/inotify.c | inotify file-change monitoring for resolv.conf and dynamic dirs |
| src/net/platform/linux/conntrack.rs | CREATE | src/conntrack.c | netfilter conntrack mark retrieval via FFI |
| src/net/platform/bsd/mod.rs | CREATE | — | BSD platform module declarations |
| src/net/platform/bsd/bpf.rs | CREATE | src/bpf.c | BPF raw packets, getifaddrs, PF_ROUTE monitoring |
| src/net/platform/bsd/pf_tables.rs | CREATE | src/tables.c | BSD PF table population via ioctl FFI |

**Integration Modules:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/integration/mod.rs | CREATE | — | Integration module declarations |
| src/integration/dbus.rs | CREATE | src/dbus.c | D-Bus system bus interface via FFI bindings to libdbus-1 |
| src/integration/ubus.rs | CREATE | src/ubus.c | OpenWrt UBus interface via FFI bindings to libubus |
| src/integration/nftset.rs | CREATE | src/nftset.c | nftables set population via FFI to libnftables |
| src/integration/tftp.rs | CREATE | src/tftp.c | Read-only TFTP server: RRQ, option negotiation, DATA/ACK |

**Debug and Utility Modules:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| src/debug/mod.rs | CREATE | — | Debug module declarations |
| src/debug/dump.rs | CREATE | src/dump.c | Pcap packet capture: DLT_RAW headers, IP/UDP/ICMP framing |

**Test Files:**

| Target File | Transformation | Source File | Key Changes |
|---|---|---|---|
| tests/integration/dns_forwarding.rs | CREATE | src/forward.c | REFERENCE: End-to-end DNS forwarding with mock upstream servers |
| tests/integration/dns_cache.rs | CREATE | src/cache.c | REFERENCE: Cache insert/lookup/eviction/TTL tests |
| tests/integration/dhcp_v4_lifecycle.rs | CREATE | src/rfc2131.c | REFERENCE: Full DORA cycle integration tests |
| tests/integration/dhcp_v6_lifecycle.rs | CREATE | src/rfc3315.c | REFERENCE: DHCPv6 SOLICIT/REPLY lifecycle tests |
| tests/integration/config_parsing.rs | CREATE | src/option.c | REFERENCE: Config file and CLI option parsing tests |
| tests/integration/wire_format.rs | CREATE | src/rfc1035.c | REFERENCE: DNS wire encoding/decoding roundtrip tests |
| tests/integration/dnssec_validation.rs | CREATE | src/dnssec.c | REFERENCE: DNSSEC trust chain validation tests |

### 0.5.2 Cross-File Dependencies

**Import Statement Transformations:**

The C codebase uses a single monolithic header `dnsmasq.h` included by every file. In Rust, this becomes targeted module imports:

- FROM: `#include "dnsmasq.h"` (in every .c file)
- TO: `use crate::types::{AllAddr, SocketAddress, DnsHeader};` (specific type imports per module)
- TO: `use crate::core::daemon::DaemonState;` (global state access)
- TO: `use crate::dns::wire::{extract_name, skip_questions};` (DNS utility functions)

**Key Cross-Module Dependencies:**

- `src/dns/forward.rs` depends on: `dns::cache`, `dns::wire`, `dns::edns`, `dns::server_match`, `dns::dnssec`, `core::daemon`, `net::socket`, `types::*`
- `src/dhcp/v4/rfc2131.rs` depends on: `dhcp::common`, `dhcp::lease`, `dns::cache`, `core::daemon`, `net::interface`, `types::dhcp`
- `src/dhcp/v6/rfc3315.rs` depends on: `dhcp::common`, `dhcp::lease`, `dhcp::v6::outpacket`, `core::daemon`, `types::dhcp`
- `src/core/event_loop.rs` depends on: `dns::forward`, `dhcp::v4::server`, `dhcp::v6::server`, `integration::tftp`, `net::interface`, `core::signal`

**Configuration Update Propagation:**

- `Cargo.toml` feature flags replace all `HAVE_*`/`NO_*` macros from `config.h` and `Makefile`
- `build.rs` replaces pkg-config detection logic from `Makefile` for optional native libraries
- Every module using `#ifdef HAVE_DHCP` becomes `#[cfg(feature = "dhcp")]` in Rust

### 0.5.3 Wildcard Patterns

Wildcard patterns are used sparingly and only with trailing wildcards:

- `src/**/*.rs` — All Rust source modules (CREATE from C counterparts)
- `src/dns/**/*.rs` — All DNS stack modules (CREATE from forward.c, cache.c, rfc1035.c, dnssec.c, etc.)
- `src/dhcp/**/*.rs` — All DHCP stack modules (CREATE from dhcp.c, rfc2131.c, rfc3315.c, etc.)
- `src/net/platform/linux/**/*.rs` — Linux-specific modules (CREATE from netlink.c, ipset.c, inotify.c, etc.)
- `src/net/platform/bsd/**/*.rs` — BSD-specific modules (CREATE from bpf.c, tables.c)
- `src/integration/**/*.rs` — Integration modules (CREATE from dbus.c, ubus.c, nftset.c, tftp.c)
- `tests/**/*.rs` — All test files (CREATE, new test suite)
- `docs/**/*.md` — Documentation files (UPDATE with Rust-specific content)

### 0.5.4 One-Phase Execution

The entire Rust rewrite is executed by Blitzy in **one phase**. All 70+ target Rust files, the Cargo.toml workspace, build.rs, test suite, and documentation updates are generated in a single coordinated pass. There is no phased rollout or incremental migration — the complete C-to-Rust transformation is atomic.


## 0.6 Dependency Inventory

### 0.6.1 Key Public Packages

All Rust crate dependencies are well-established, widely-used packages from the crates.io registry. Version numbers are verified against the latest stable releases as of February 2026.

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `mio` | 1.1.0 | Poll-based I/O event loop (epoll/kqueue abstraction), replacing C `poll()` in `poll.c` |
| crates.io | `ring` | 0.17.14 | DNSSEC cryptographic verification: RSA, ECDSA P-256/P-384, Ed25519 — replacing Nettle in `crypto.c` |
| crates.io | `nix` | 0.30.1 | Safe POSIX API bindings: signals, sockets, ioctl, netlink, fork — replacing raw libc calls |
| crates.io | `libc` | 0.2.171 | Low-level C FFI types and constants for platform syscalls |
| crates.io | `log` | 0.4.27 | Logging facade trait for syslog integration — replacing `log.c` |
| crates.io | `tracing` | 0.1.41 | Structured diagnostic logging — optional enhanced logging backend |
| crates.io | `tracing-subscriber` | 0.3.19 | Log subscriber for syslog output formatting |
| crates.io | `bitflags` | 2.9.0 | Type-safe bitflag definitions for DNS/DHCP option flags |
| crates.io | `thiserror` | 2.0.12 | Derive macro for custom error types throughout the codebase |
| crates.io | `anyhow` | 1.0.98 | Ergonomic error handling for main() and integration points |
| crates.io | `bytes` | 1.10.1 | Efficient byte buffer management for DNS/DHCP packet construction |
| crates.io | `cfg-if` | 1.0.0 | Conditional compilation helpers for platform-specific code |
| crates.io | `socket2` | 0.5.9 | Extended socket options (SO_REUSEPORT, SO_BINDTODEVICE, multicast) |
| crates.io | `inotify` | 0.11.0 | Linux inotify file monitoring — replacing raw inotify syscalls in `inotify.c` |
| crates.io | `rand` | 0.9.1 | CSPRNG for transaction IDs and port randomization — replacing SURF PRNG |
| crates.io | `pcap-file` | 2.1.0 | Pcap file writing for packet dump — replacing manual pcap construction in `dump.c` |

**Optional Feature-Gated Dependencies:**

| Registry | Package | Version | Feature Gate | Purpose |
|---|---|---|---|---|
| crates.io | `dbus` | 0.9.7 | `dbus` | D-Bus system bus FFI bindings — replacing raw libdbus-1 calls in `dbus.c` |
| crates.io | `netlink-packet-core` | 0.7.0 | `ipset` | Netlink message construction for ipset — replacing raw netlink in `ipset.c` |
| crates.io | `netlink-packet-route` | 0.21.0 | `netlink` | Route/address netlink messages — replacing raw netlink in `netlink.c` |
| crates.io | `netlink-sys` | 0.8.7 | `netlink` | Netlink socket management |
| crates.io | `idna` | 1.0.3 | `idn` | IDNA 2008 internationalized domain names — replacing libidn2 FFI |

### 0.6.2 Toolchain and Build Dependencies

| Component | Version | Purpose |
|---|---|---|
| Rust (stable) | 1.93.1 | Compiler toolchain |
| Rust Edition | 2024 | Language edition for latest features (let chains, etc.) |
| Cargo | (bundled with Rust) | Build system and package manager |
| `x86_64-unknown-linux-gnu` target | (built-in) | Primary Linux x86-64 compilation target |
| `aarch64-unknown-linux-gnu` target | (via `rustup target add`) | ARM64 cross-compilation target |
| `cc` crate | 1.2.16 | Build-time C compiler detection for ring's assembly |
| `pkg-config` crate | 0.3.31 | Build-time native library detection (D-Bus, nftables, etc.) |

### 0.6.3 Import Refactoring

**Files Requiring Import Updates:**

All source files undergo import transformation from C `#include` to Rust `use` statements. Since this is a full rewrite, every target file is created fresh with proper Rust imports.

- `src/**/*.rs` — All Rust source modules use `use crate::...` for internal module references
- `tests/**/*.rs` — Integration tests use `use dnsmasq::...` for public API access

**Import Transformation Rules:**

- Old: `#include "dnsmasq.h"` (monolithic C header)
- New: `use crate::types::{AllAddr, DnsHeader};` (targeted Rust imports)
- Apply to: All files matching `src/**/*.rs`

- Old: `#include <netinet/in.h>` / `#include <sys/socket.h>` (system headers)
- New: `use nix::sys::socket::{...};` or `use std::net::{...};` (Rust safe wrappers)
- Apply to: All network-related modules

- Old: `#ifdef HAVE_DHCP` / `#endif` (preprocessor conditionals)
- New: `#[cfg(feature = "dhcp")]` (Cargo feature gates)
- Apply to: All feature-gated modules

### 0.6.4 External Reference Updates

**Configuration Files:**

| File | Update Type |
|---|---|
| `Cargo.toml` | CREATE — new workspace manifest with all dependencies and features |
| `rust-toolchain.toml` | CREATE — pin Rust 1.93 stable, edition 2024 |
| `build.rs` | CREATE — platform detection, pkg-config for optional native libs |
| `.cargo/config.toml` | CREATE — cross-compilation profiles |

**Documentation:**

| File | Update Type |
|---|---|
| `README.md` | UPDATE — Rust build instructions, Cargo commands |
| `docs/BUILDING.md` | UPDATE — cargo build/test/install workflow |
| `docs/ARCHITECTURE.md` | UPDATE — Rust module hierarchy description |
| `docs/*.md` | UPDATE — file references from .c to .rs |

**Build System:**

| File | Update Type |
|---|---|
| `Makefile` | REFERENCE — feature flag mapping extracted into Cargo.toml features |


## 0.7 Refactoring Rules

### 0.7.1 Refactoring-Specific Rules

The following rules are directly derived from the user's explicit constraints and are non-negotiable throughout the rewrite:

- **Zero `unsafe` Rust blocks except where FFI is unavoidable.** Every module must be written in safe Rust. The only permitted `unsafe` blocks are thin FFI wrappers around external C libraries (D-Bus, libnftables, conntrack), fork/exec for the helper process, and raw socket operations that cannot be expressed through `nix` or `socket2`. Each `unsafe` block must include a `// SAFETY:` comment explaining why it is required and what invariants are maintained.

- **Preserve the existing public API and config file format.** The dnsmasq.conf file syntax (all 160+ directives documented in `dnsmasq.conf.example`) must be parsed identically. Every CLI flag and option currently handled by `src/option.c` must be accepted with the same names, abbreviations, and value semantics. The binary must be a drop-in replacement: same command-line interface, same config file, same default behavior.

- **Output must compile on Linux x86-64 and ARM64.** The Cargo workspace must produce a working binary on both `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` targets. Platform-specific code in `src/net/platform/linux/` uses `#[cfg(target_arch = "...")]` where hardware-specific behavior differs (e.g., ioctl constants, struct padding).

- **No new external dependencies beyond the Rust standard library and well-established crates.** All crate dependencies listed in section 0.6 are well-established crates with tens of millions of downloads. No experimental, unmaintained, or niche crates are permitted. The total dependency tree must remain minimal and auditable.

- **Maintain full functional equivalence.** Every DNS, DHCP, DHCPv6, TFTP, DNSSEC, Router Advertisement, and authorization feature in the current C codebase must be replicated. The Rust binary must produce identical wire-protocol behavior for any given configuration and input.

### 0.7.2 Special Instructions and Constraints

- **Wire Protocol Fidelity:** DNS response packets must be byte-for-byte identical to the C implementation for the same query under the same configuration. DHCP offer/ack packets must follow the same option ordering and padding. Any deviation in protocol behavior is a defect.

- **Config Compatibility Contract:** The Rust parser must accept every valid dnsmasq.conf accepted by the C implementation and reject the same invalid configurations. Error messages should reference the same line numbers and option names. The `--test` flag must validate configuration files identically.

- **Feature Flag Parity:** The Cargo feature flags must provide the same compile-time subsystem selection as the C `HAVE_*` macros. Specifically:
  - `dhcp` → enables DHCPv4 (`rfc2131.c` equivalent)
  - `dhcp6` → enables DHCPv6 (`rfc3315.c`, `outpacket.c` equivalents)
  - `dnssec` → enables DNSSEC validation (`dnssec.c`, `crypto.c` equivalents)
  - `dbus` → enables D-Bus control interface (`dbus.c` equivalent)
  - `ubus` → enables UBus control interface (`ubus.c` equivalent)
  - `tftp` → enables TFTP server (`tftp.c` equivalent)
  - `ipset` → enables ipset/nftset integration (`ipset.c`, `nftset.c` equivalents)
  - `auth` → enables authoritative DNS (`auth.c` equivalent)
  - `inotify` → enables file change monitoring (`inotify.c` equivalent)
  - `conntrack` → enables conntrack mark retrieval (`conntrack.c` equivalent)
  - `dump` → enables pcap packet dumping (`dump.c` equivalent)

- **Memory Safety Guarantees:** All intrusive linked lists in the C codebase (cache entries in `cache.c`, forward records in `forward.c`, DHCP leases in `lease.c`, server entries in `domain-match.c`) must be replaced with safe Rust collections (`HashMap`, `Vec`, `VecDeque`, `BTreeMap`). No raw pointer manipulation outside of `unsafe` FFI blocks.

- **Error Handling Strategy:** All C-style error codes and `errno` checks must be replaced with Rust `Result<T, E>` return types. The `setjmp`/`longjmp` pattern in `option.c` for config parsing error recovery must be replaced with `Result<T, ConfigError>` propagation.

- **Signal Handling:** The self-pipe signal handling pattern in `dnsmasq.c` must be reimplemented using `nix::sys::signal` with a safe pipe-based wakeup mechanism. SIGHUP (config reload), SIGTERM (graceful shutdown), SIGUSR1 (cache dump), SIGUSR2 (server stats), and SIGCHLD (helper process) must all be handled.

- **Privilege Separation:** The `fork()`-based helper process model in `helper.c` (used for script execution and lease-change notifications) must be preserved. This is one of the areas where `unsafe` FFI via `nix::unistd::fork()` is acceptable.

- **Backward-Compatible Behavior Defaults:** All numeric defaults must match the C implementation:
  - `CACHESIZ = 150` (default cache size)
  - `MAXLEASES = 1000` (default lease limit)
  - `FTABSIZ = 150` (default forward table size)
  - `TFTP_MAX_CONNECTIONS = 50` (default TFTP connection limit)
  - `EDNS_PKTSZ = 4096` (default EDNS0 buffer size)
  - `TIMEOUT = 10` (default query timeout in seconds)
  - `RANDOM_SOCKS = 64` (default random source ports)

### 0.7.3 Additional User-Provided Rules

- **No new features not present in the current dnsmasq version.** The Rust rewrite is a strict port, not an enhancement. Feature additions are deferred to a future phase after functional equivalence is confirmed.

- **No changes to network protocol behavior.** The rewrite must not alter how DNS queries are resolved or forwarded, how DHCP leases are allocated or renewed, or how any network protocol messages are constructed, validated, or responded to.

- **No GUI or management interface.** The rewrite does not include any web UI, TUI, or graphical management layer. Control interfaces are limited to the existing D-Bus and UBus APIs (which are themselves optional features).

- **Test Suite Requirement:** A comprehensive unit and integration test suite must be created covering all major subsystems. Tests must validate:
  - Config file parsing for all 160+ directives
  - DNS query forwarding and caching behavior
  - DHCP lease allocation and renewal
  - DNSSEC validation with known-good and known-bad signatures
  - Platform abstraction layer (netlink on Linux, BPF on BSD)
  - Feature flag combinations compile and link correctly


## 0.8 References

### 0.8.1 Codebase Files and Folders Searched

The following files and folders were comprehensively retrieved and analyzed to derive all conclusions in this Agent Action Plan.

**Repository Root:**

| Path | Type | Purpose |
|---|---|---|
| `/` (root) | Folder | Repository root — discovered top-level structure |
| `src/` | Folder | All 50 C source files examined |
| `docs/` | Folder | 9 markdown documentation files discovered |
| `contrib/` | Folder | Community scripts (Perl, Python) — excluded from scope |
| `Makefile` | File | Build system — 179 lines, feature flag and compilation logic |
| `dnsmasq.conf.example` | File | Canonical config template — all 160+ directives documented |
| `trust-anchors.conf` | File | DNSSEC root trust anchor configuration |

**Core Runtime Files (8 files):**

| Path | Summary |
|---|---|
| `src/dnsmasq.c` | Main entry point: daemon startup, privilege drop, poll-based event loop, self-pipe signal handling, SIGHUP config reload |
| `src/dnsmasq.h` | Central header: all struct definitions (daemon, crec, frec, dhcp_lease, etc.), function prototypes, HAVE_* feature detection |
| `src/config.h` | Compile-time constants (CACHESIZ=150, MAXLEASES=1000, FTABSIZ=150), default file paths, HAVE_* feature flags |
| `src/poll.c` | Compact poll()-based I/O multiplexer — sorted pollfd array with binary search, O(log n) fd lookup |
| `src/option.c` | Comprehensive configuration parser for dnsmasq.conf and CLI — 160+ options, setjmp/longjmp error recovery |
| `src/log.c` | Syslog and file-based logging — echo mode during startup, async buffered writes, connection retry |
| `src/network.c` | Network interface management — interface enumeration, wildcard/specific binding, listener and server creation |
| `src/util.c` | General utilities — safe_malloc/whine_realloc, SURF PRNG, hostname canonicalization, string helpers |

**DNS Stack Files (9 files):**

| Path | Summary |
|---|---|
| `src/forward.c` | DNS forwarding engine — upstream query dispatch, response validation, retry logic, UDP/TCP support |
| `src/cache.c` | DNS cache — hash-based lookup with intrusive LRU, TTL expiry, CNAME chains, wildcard NXDOMAIN |
| `src/rfc1035.c` | DNS wire-format codec — name compression (0xC0 pointers), answer/authority/additional RR construction |
| `src/dnssec.c` | DNSSEC validation — RRSIG verification, DS chain-of-trust, NSEC/NSEC3 negative proofs |
| `src/crypto.c` | Cryptographic dispatch — hash (SHA-256/384/512) and signature verification (RSA/ECDSA/Ed25519) via Nettle or GnuTLS |
| `src/edns0.c` | EDNS0 OPT record handling — ECS (RFC 7871), MAC/Umbrella options, DO bit for DNSSEC |
| `src/rrfilter.c` | DNS RR filtering — four-pass algorithm (mark, validate, rewrite compression pointers, compact) |
| `src/auth.c` | Authoritative DNS zone serving — AA flag, SOA generation, AXFR zone transfer with peer ACL |
| `src/dns-protocol.h` | DNS wire-format constants and macros |

**DHCP Stack Files (12 files):**

| Path | Summary |
|---|---|
| `src/dhcp.c` | DHCPv4 request dispatcher — raw socket I/O, BOOTP relay, interface matching, lease-change scripts |
| `src/dhcp6.c` | DHCPv6 request dispatcher — solicit/request/renew routing, relay chain handling |
| `src/rfc2131.c` | DHCPv4 protocol engine — DISCOVER→OFFER→REQUEST→ACK state machine, option assembly |
| `src/rfc3315.c` | DHCPv6 protocol engine — SOLICIT→ADVERTISE→REQUEST→REPLY, IA_NA/IA_TA/IA_PD handling |
| `src/lease.c` | DHCP lease database — file persistence, expiry management, DNS name registration |
| `src/radv.c` | Router Advertisement daemon — RA construction, prefix/RDNSS/DNSSL options, timer management |
| `src/slaac.c` | SLAAC duplicate-address detection — EUI-64 derivation from MAC, ICMPv6 echo probing |
| `src/outpacket.c` | DHCPv6 option serialization — expand()/new_opt6()/put_opt6*/end_opt6() nested option construction |
| `src/dhcp-common.c` | Shared DHCP utilities — recv_dhcp_packet, tag matching, option filtering, client config lookup |
| `src/dhcp-protocol.h` | DHCPv4 wire-format constants |
| `src/dhcp6-protocol.h` | DHCPv6 wire-format constants |
| `src/radv-protocol.h` | Router Advertisement constants |

**Platform Abstraction Files (3 files):**

| Path | Summary |
|---|---|
| `src/netlink.c` | Linux netlink interface — address/route change monitoring, interface enumeration |
| `src/bpf.c` | BSD BPF + Solaris DLPI — raw packet I/O, DHCP packet capture on non-Linux platforms |
| `src/arp.c` | ARP/neighbor cache — find_mac() with 90s refresh, binary filter_mac callback |

**Integration Files (8 files):**

| Path | Summary |
|---|---|
| `src/helper.c` | Privileged helper process — fork-based script executor for lease-change and TFTP events |
| `src/dbus.c` | D-Bus system bus interface — SetServers, cache management, DHCP lease signals |
| `src/ubus.c` | OpenWrt UBus interface — metrics export, DHCP events, connmark allowlists |
| `src/tftp.c` | TFTP server — file transfer with blksize/tsize/timeout options, chroot path resolution |
| `src/ipset.c` | Linux ipset via NETLINK_NETFILTER — fire-and-forget add/delete with retry_send |
| `src/nftset.c` | nftables set population via libnftables — "add element"/"delete element" commands |
| `src/tables.c` | BSD PF table population — DIOCRADDTABLES/DIOCRADDADDRS/DIOCRDELADDRS |
| `src/conntrack.c` | Netfilter conntrack mark retrieval — 5-tuple query via nfct_query |

**Supporting Utility Files (10 files):**

| Path | Summary |
|---|---|
| `src/domain.c` | Synthetic hostname generation and split-horizon conditional domain selection |
| `src/domain-match.c` | Domain pattern matching and server selection — sorted array with binary search |
| `src/pattern.c` | Pattern matching utilities |
| `src/blockdata.c` | Fixed-size block chain pool for DNSSEC record storage |
| `src/loop.c` | DNS forwarding loop detection — periodic probes with hex uid labels |
| `src/inotify.c` | Linux inotify file monitoring — resolv.conf, dynamic host/DHCP directories |
| `src/dump.c` | Pcap packet dumping — DLT_RAW, full IP header construction with checksums |
| `src/metrics.c` | Lightweight metrics — metric_names[] array, per-server statistics |
| `src/metrics.h` | Metric name enum definitions |
| `src/ip6addr.h` | IPv6 address manipulation helpers |

### 0.8.2 Technical Specification Sections Retrieved

| Section | Key Information Extracted |
|---|---|
| 1.1 Executive Summary | Project overview: dnsmasq is a lightweight DNS/DHCP/TFTP server for small networks; v2.92 with 25+ years of development history |
| 3.2 Programming Languages | C99 codebase confirmation, GNU Make build system, no Rust toolchain currently present |
| 3.4 Open Source Dependencies | Baseline zero external dependencies; optional Nettle/GnuTLS (DNSSEC), libidn2 (IDN), libdbus-1, libnftables, libconntrack |
| 5.1 High-Level Architecture | Single-process event-driven architecture, poll-based I/O, privilege separation via helper fork, platform abstraction layer |

### 0.8.3 External Research Conducted

| Topic | Key Findings |
|---|---|
| Rust 1.93.1 stable (Dec 2025) | Latest stable toolchain; edition 2024 available; native cross-compilation support for x86-64 and ARM64 |
| `mio` crate v1.1.0 | Lightweight non-blocking I/O library; poll-based event notification; direct replacement for C poll() loop; 459M+ total downloads |
| `ring` crate v0.17.14 | Cryptographic operations library; RSA/ECDSA/Ed25519/SHA verification; replaces Nettle/GnuTLS; 334M+ total downloads |
| `nix` crate v0.30.1 | Safe POSIX API bindings; signals, sockets, ioctl, fork, netlink; replaces direct libc calls; 362M+ total downloads |
| `tracing` crate v0.1.41 | Application-level structured logging; replaces syslog C interface; 387M+ total downloads |
| Hickory DNS patterns | Studied for idiomatic Rust DNS implementation patterns, wire-format handling, and zone authority serving |
| Rust C-to-Rust migration best practices | Incremental rewrite patterns, FFI boundary strategies, ownership model for network buffer management |

### 0.8.4 User Attachments

No attachments were provided by the user for this project.

### 0.8.5 User-Provided Setup Instructions

No specific environment setup instructions were provided. The Rust toolchain version (1.93.1 stable) and build targets (x86-64 and ARM64 Linux) were determined from the user's constraints and the current Rust ecosystem state.



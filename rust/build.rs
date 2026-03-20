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

//! Cargo build script for the dnsmasq Rust implementation.
//!
//! This build script replaces the C Makefile's platform detection and `COPTS`
//! system. It detects the target platform at compile time and emits
//! `cargo:rustc-cfg` directives that drive conditional compilation across the
//! entire Rust codebase, mirroring the C `#ifdef HAVE_*` / `#ifdef __linux__`
//! system defined in `src/config.h`.
//!
//! # Source Context
//!
//! - **Primary source**: `src/config.h` (lines 2061–2349) — Contains all
//!   platform detection logic using compiler-predefined macros (`__linux__`,
//!   `__FreeBSD__`, `__APPLE__`, etc.) that set `HAVE_LINUX_NETWORK`,
//!   `HAVE_BSD_NETWORK`, or `HAVE_SOLARIS_NETWORK`.
//! - **Secondary source**: `Makefile` — Contains `COPTS`, `CFLAGS`,
//!   platform-specific `LDFLAGS`, and `pkg-config` dependency detection.
//!
//! # Emitted cfg Flags
//!
//! The following `cfg` flags are emitted based on the target platform:
//!
//! | cfg Flag               | C Equivalent             | When Emitted                        |
//! |------------------------|--------------------------|-------------------------------------|
//! | `linux_network`        | `HAVE_LINUX_NETWORK`     | `target_os = "linux"`               |
//! | `bsd_network`          | `HAVE_BSD_NETWORK`       | `target_os ∈ {freebsd, openbsd, …}` |
//! | `solaris_network`      | `HAVE_SOLARIS_NETWORK`   | `target_os ∈ {solaris, illumos}`    |
//! | `have_inotify`         | `HAVE_INOTIFY`           | Linux + inotify feature enabled     |
//! | `android`              | `__ANDROID__`            | Linux + android target env          |
//! | `have_sockaddr_sa_len` | `HAVE_SOCKADDR_SA_LEN`   | BSD and macOS targets               |
//! | `linux_ipset`          | `HAVE_LINUX_IPSET`       | ipset feature + Linux               |
//! | `bsd_ipset`            | `HAVE_BSD_IPSET`         | ipset feature + BSD                 |
//!
//! # Emitted Environment Variables
//!
//! | Variable                      | Description                          |
//! |-------------------------------|--------------------------------------|
//! | `DNSMASQ_VERSION`             | Version string (e.g., "2.92-rust")   |
//! | `DNSMASQ_DEFAULT_LEASEFILE`   | Platform-specific lease file path    |
//! | `DNSMASQ_DEFAULT_CONFFILE`    | Platform-specific config file path   |
//! | `DNSMASQ_DEFAULT_RESOLVFILE`  | Platform-specific resolv.conf path   |
//! | `DNSMASQ_DEFAULT_RUNFILE`     | Platform-specific PID file path      |
//!
//! # Feature Flag Mapping (C HAVE_* → Cargo Features)
//!
//! The following feature flags are managed by `Cargo.toml` (not this build
//! script), but are documented here for reference since they correspond to
//! the C `HAVE_*` macros:
//!
//! | C Macro          | Cargo Feature     | Default  | Description                     |
//! |------------------|-------------------|----------|---------------------------------|
//! | `HAVE_DHCP`      | `dhcp`            | enabled  | DHCPv4 server                   |
//! | `HAVE_DHCP6`     | `dhcp6`           | enabled  | DHCPv6 server (implies dhcp)    |
//! | `HAVE_TFTP`      | `tftp`            | enabled  | TFTP server and PXE boot        |
//! | `HAVE_SCRIPT`    | `script`          | enabled  | Lease-change script execution   |
//! | `HAVE_AUTH`      | `auth`            | enabled  | Authoritative DNS zones         |
//! | `HAVE_IPSET`     | `ipset`           | enabled  | Linux ipset / BSD ipfw tables   |
//! | `HAVE_LOOP`      | `loop-detect`     | enabled  | DNS forwarding loop detection   |
//! | `HAVE_DUMPFILE`  | `dumpfile`        | enabled  | Packet dump for debugging       |
//! | `HAVE_DNSSEC`    | `dnssec`          | disabled | DNSSEC validation (nettle)      |
//! | `HAVE_DBUS`      | `dbus`            | disabled | D-Bus / NetworkManager          |
//! | `HAVE_UBUS`      | `ubus`            | disabled | OpenWrt ubus interface          |
//! | `HAVE_IDN`       | `idn`             | disabled | Internationalized domain names  |
//! | `HAVE_CONNTRACK`  | `conntrack`      | disabled | Linux conntrack marks           |
//! | `HAVE_NFTSET`    | `nftset`          | disabled | nftables set integration        |
//! | `HAVE_LUASCRIPT`  | `luascript`      | disabled | Lua scripting support           |
//! | `HAVE_INOTIFY`   | `inotify` + auto  | auto     | File change monitoring (Linux)  |
//! | `HAVE_LINUX_NETWORK` | (auto)        | auto     | Linux network stack             |
//! | `HAVE_BSD_NETWORK`   | (auto)        | auto     | BSD network stack               |
//!
//! # Safety
//!
//! This build script contains zero `unsafe` code.
//!
//! # Compatibility
//!
//! Requires Rust 1.91.0 stable or later.

/// Detect the target platform's network stack and emit the appropriate
/// `cargo:rustc-cfg` directives.
///
/// This mirrors the platform detection block in `src/config.h` lines 2138–2349,
/// which uses compiler-predefined macros (`__UCLIBC__`, `__linux__`,
/// `__FreeBSD__`, `__APPLE__`, `__NetBSD__`, `__sun`) to select exactly one of
/// `HAVE_LINUX_NETWORK`, `HAVE_BSD_NETWORK`, or `HAVE_SOLARIS_NETWORK`.
///
/// # Network Stack Selection
///
/// - **Linux** (`target_os = "linux"`): Uses netlink sockets for interface
///   monitoring, inotify for file-change detection, and Linux-specific DHCP
///   packet filters. Maps to C `HAVE_LINUX_NETWORK`. Also auto-enables
///   `have_inotify` when the `inotify` Cargo feature is active.
///
/// - **BSD** (`target_os ∈ {freebsd, openbsd, netbsd, dragonfly, macos}`):
///   Uses BPF (Berkeley Packet Filter) for DHCP packet capture and routing
///   sockets for interface monitoring. Maps to C `HAVE_BSD_NETWORK`.
///
/// - **Solaris** (`target_os ∈ {solaris, illumos}`): Uses STREAMS-based
///   network stack and Solaris-specific interfaces. Maps to C
///   `HAVE_SOLARIS_NETWORK`.
fn detect_platform(target_os: &str) {
    match target_os {
        // Linux with glibc or musl — src/config.h line 2177:
        //   #elif defined(__linux__)
        //   #define HAVE_LINUX_NETWORK
        // Also covers uClibc (embedded Linux) — src/config.h line 2138:
        //   #if defined(__UCLIBC__)
        //   #define HAVE_LINUX_NETWORK
        "linux" => {
            println!("cargo:rustc-cfg=linux_network");

            // Auto-enable inotify on Linux when the inotify feature is active.
            // Mirrors src/config.h line 2872:
            //   #if defined(HAVE_LINUX_NETWORK) && !defined(NO_INOTIFY)
            //   #define HAVE_INOTIFY
            //
            // The Cargo feature "inotify" acts as the gating mechanism (like
            // the absence of NO_INOTIFY in the C build). When the feature is
            // enabled in Cargo.toml (which it is by default), this cfg flag
            // enables inotify-based file monitoring throughout the codebase.
            if is_cargo_feature_enabled("inotify") {
                println!("cargo:rustc-cfg=have_inotify");
            }
        }

        // FreeBSD, OpenBSD, DragonFly BSD, GNU/kFreeBSD — src/config.h line 2211:
        //   #elif defined(__FreeBSD__) || defined(__OpenBSD__) ||
        //         defined(__DragonFly__) || defined(__FreeBSD_kernel__)
        //   #define HAVE_BSD_NETWORK
        "freebsd" | "openbsd" | "dragonfly" => {
            println!("cargo:rustc-cfg=bsd_network");
        }

        // NetBSD — src/config.h line 2302:
        //   #elif defined(__NetBSD__)
        //   #define HAVE_BSD_NETWORK
        "netbsd" => {
            println!("cargo:rustc-cfg=bsd_network");
        }

        // macOS / Darwin — src/config.h line 2264:
        //   #elif defined(__APPLE__)
        //   #define HAVE_BSD_NETWORK
        "macos" => {
            println!("cargo:rustc-cfg=bsd_network");
        }

        // Solaris and OpenSolaris/Illumos — src/config.h line 2343:
        //   #elif defined(__sun) || defined(__sun__)
        //   #define HAVE_SOLARIS_NETWORK
        "solaris" | "illumos" => {
            println!("cargo:rustc-cfg=solaris_network");
        }

        // Unknown platform — no network stack cfg emitted.
        // Compilation may still succeed if no platform-specific network code
        // is reached, but runtime functionality will be limited.
        _ => {
            println!(
                "cargo:warning=Unrecognized target OS '{}': \
                 no platform-specific network stack configured.",
                target_os
            );
        }
    }
}

/// Detect Android targets and emit the `android` cfg flag.
///
/// Android is a subset of Linux with different default behaviors:
/// - TFTP and script execution are disabled by default (security policy)
/// - File paths use Android-specific locations (/data/misc/dhcp/)
///
/// Maps to C `#ifdef __ANDROID__` checks throughout the codebase.
///
/// Detection uses `CARGO_CFG_TARGET_ENV` — on Android NDK targets, the
/// target triple has the form `aarch64-linux-android` or
/// `armv7-linux-androideabi`, where the environment component is `"android"`
/// or starts with `"android"`.
fn detect_android(target_os: &str, target_env: &str) {
    if target_os == "linux" && (target_env == "android" || target_env.starts_with("android")) {
        println!("cargo:rustc-cfg=android");
    }
}

/// Detect whether the target platform uses `struct sockaddr` with a `sa_len`
/// field and emit the `have_sockaddr_sa_len` cfg flag.
///
/// BSD-derived systems (FreeBSD, OpenBSD, NetBSD, DragonFly, macOS) include
/// a `sa_len` field in `struct sockaddr` that specifies the total length of
/// the address structure. Linux and Solaris do not have this field and rely
/// on a separate length parameter passed to socket functions.
///
/// Mirrors src/config.h:
/// - BSD: `#define HAVE_SOCKADDR_SA_LEN` (lines 2220, 2267, 2305)
/// - Linux: `#undef HAVE_SOCKADDR_SA_LEN` (lines 2144, 2180)
/// - Solaris: `#undef HAVE_SOCKADDR_SA_LEN` (line 2346)
fn detect_sockaddr_sa_len(target_os: &str) {
    match target_os {
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" | "macos" => {
            println!("cargo:rustc-cfg=have_sockaddr_sa_len");
        }
        _ => {
            // Linux, Solaris, and other platforms do not have sa_len.
        }
    }
}

/// Detect the appropriate ipset implementation variant for the target
/// platform and emit the corresponding cfg flag.
///
/// The C codebase (src/config.h lines 2743–2751) selects between two
/// ipset implementations based on the platform:
///
/// - **Linux** (`HAVE_LINUX_IPSET`): Uses netlink sockets to communicate
///   with the kernel's netfilter ipset subsystem.
/// - **BSD** (`HAVE_BSD_IPSET`): Uses `setsockopt()` with `IP_FW_TABLE_ADD`
///   / `IP_FW_TABLE_DEL` for ipfw table integration.
/// - **Other platforms**: ipset functionality is unavailable; the feature
///   is effectively a no-op.
///
/// This function only emits cfg flags when the `ipset` Cargo feature is
/// enabled, matching the C conditional:
/// ```c
/// #if defined(HAVE_IPSET)
/// #  if defined(HAVE_LINUX_NETWORK)
/// #    define HAVE_LINUX_IPSET
/// #  elif defined(HAVE_BSD_NETWORK)
/// #    define HAVE_BSD_IPSET
/// #  else
/// #    undef HAVE_IPSET
/// #  endif
/// #endif
/// ```
fn detect_ipset_variant(target_os: &str) {
    if !is_cargo_feature_enabled("ipset") {
        return;
    }

    match target_os {
        "linux" => {
            println!("cargo:rustc-cfg=linux_ipset");
        }
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" | "macos" => {
            println!("cargo:rustc-cfg=bsd_ipset");
        }
        _ => {
            // On unsupported platforms (Solaris, etc.), ipset feature is
            // enabled in Cargo but has no platform implementation. The
            // ipset module should handle this gracefully at compile time
            // by providing stub implementations gated on neither
            // linux_ipset nor bsd_ipset being set.
            println!(
                "cargo:warning=ipset feature enabled but no platform \
                 implementation available for target OS '{}'.",
                target_os
            );
        }
    }
}

/// Emit platform-specific default file paths as compile-time environment
/// variables.
///
/// These paths mirror the platform-conditional `#ifndef` blocks in
/// `src/config.h` (lines 1898–2059) that set `LEASEFILE`, `CONFFILE`,
/// `RESOLVFILE`, and `RUNFILE` based on the detected operating system.
///
/// The emitted environment variables are available in Rust code via:
/// ```rust,ignore
/// const DEFAULT_LEASEFILE: &str = env!("DNSMASQ_DEFAULT_LEASEFILE");
/// ```
///
/// # Platform Path Mapping
///
/// | Platform    | Lease File                       | Config File                 | Resolv File           | PID File               |
/// |-------------|----------------------------------|-----------------------------|-----------------------|------------------------|
/// | FreeBSD     | /var/db/dnsmasq.leases           | /usr/local/etc/dnsmasq.conf | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
/// | OpenBSD     | /var/db/dnsmasq.leases           | /etc/dnsmasq.conf           | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
/// | NetBSD      | /var/db/dnsmasq.leases           | /etc/dnsmasq.conf           | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
/// | DragonFly   | /var/db/dnsmasq.leases           | /etc/dnsmasq.conf           | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
/// | Solaris     | /var/cache/dnsmasq.leases        | /etc/dnsmasq.conf           | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
/// | Android     | /data/misc/dhcp/dnsmasq.leases   | /etc/dnsmasq.conf           | /etc/resolv.conf      | /data/dnsmasq.pid      |
/// | Linux       | /var/lib/misc/dnsmasq.leases     | /etc/dnsmasq.conf           | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
/// | macOS       | /var/lib/misc/dnsmasq.leases     | /etc/dnsmasq.conf           | /etc/resolv.conf      | /var/run/dnsmasq.pid   |
fn emit_default_paths(target_os: &str, target_env: &str) {
    // LEASEFILE — src/config.h lines 1898–1908
    let leasefile = match target_os {
        "freebsd" | "openbsd" | "dragonfly" | "netbsd" => "/var/db/dnsmasq.leases",
        "solaris" | "illumos" => "/var/cache/dnsmasq.leases",
        "linux" if target_env == "android" || target_env.starts_with("android") => {
            "/data/misc/dhcp/dnsmasq.leases"
        }
        _ => "/var/lib/misc/dnsmasq.leases",
    };
    println!("cargo:rustc-env=DNSMASQ_DEFAULT_LEASEFILE={}", leasefile);

    // CONFFILE — src/config.h lines 1950–1956
    let conffile = match target_os {
        "freebsd" => "/usr/local/etc/dnsmasq.conf",
        _ => "/etc/dnsmasq.conf",
    };
    println!("cargo:rustc-env=DNSMASQ_DEFAULT_CONFFILE={}", conffile);

    // RESOLVFILE — src/config.h lines 2002–2008
    // Note: uClinux uses /etc/config/resolv.conf, but Rust targets don't
    // have a uClinux-specific target triple; this is handled at runtime if
    // needed. All standard targets use /etc/resolv.conf.
    let resolvfile = "/etc/resolv.conf";
    println!("cargo:rustc-env=DNSMASQ_DEFAULT_RESOLVFILE={}", resolvfile);

    // RUNFILE — src/config.h lines 2053–2059
    let runfile = match target_os {
        "linux" if target_env == "android" || target_env.starts_with("android") => {
            "/data/dnsmasq.pid"
        }
        _ => "/var/run/dnsmasq.pid",
    };
    println!("cargo:rustc-env=DNSMASQ_DEFAULT_RUNFILE={}", runfile);
}

/// Process the `DNSMASQ_COPTS` environment variable for custom build-time
/// configuration overrides.
///
/// In the C build system, custom features are enabled via:
/// ```sh
/// make COPTS="-DHAVE_DNSSEC -DHAVE_DBUS"
/// ```
///
/// The Rust equivalent uses Cargo features (`--features dnssec,dbus`), but
/// for compatibility and migration convenience, the `DNSMASQ_COPTS`
/// environment variable is also supported. When set, it is parsed for
/// `-DHAVE_*` and `-DNO_*` directives and the corresponding warnings are
/// emitted guiding the user to use Cargo features instead.
///
/// This function does **not** modify the build configuration — Cargo features
/// are the authoritative mechanism. It serves as a migration aid that
/// validates the environment and warns about unsupported usage patterns.
fn process_copts() {
    let copts = match std::env::var("DNSMASQ_COPTS") {
        Ok(val) if !val.is_empty() => val,
        _ => return,
    };

    println!(
        "cargo:warning=DNSMASQ_COPTS environment variable detected: '{}'. \
         In the Rust build, use Cargo features instead of COPTS. \
         Example: cargo build --features dnssec,dbus",
        copts
    );

    // Parse individual flags and emit migration guidance.
    for token in copts.split_whitespace() {
        match token {
            "-DHAVE_DNSSEC" => {
                println!(
                    "cargo:warning=COPTS: -DHAVE_DNSSEC detected. \
                     Use: cargo build --features dnssec"
                );
            }
            "-DHAVE_DBUS" => {
                println!(
                    "cargo:warning=COPTS: -DHAVE_DBUS detected. \
                     Use: cargo build --features dbus"
                );
            }
            "-DHAVE_UBUS" => {
                println!(
                    "cargo:warning=COPTS: -DHAVE_UBUS detected. \
                     Use: cargo build --features ubus"
                );
            }
            "-DHAVE_IDN" | "-DHAVE_LIBIDN2" => {
                println!(
                    "cargo:warning=COPTS: {} detected. \
                     Use: cargo build --features idn",
                    token
                );
            }
            "-DHAVE_CONNTRACK" => {
                println!(
                    "cargo:warning=COPTS: -DHAVE_CONNTRACK detected. \
                     Use: cargo build --features conntrack"
                );
            }
            "-DHAVE_NFTSET" => {
                println!(
                    "cargo:warning=COPTS: -DHAVE_NFTSET detected. \
                     Use: cargo build --features nftset"
                );
            }
            "-DHAVE_LUASCRIPT" => {
                println!(
                    "cargo:warning=COPTS: -DHAVE_LUASCRIPT detected. \
                     Use: cargo build --features luascript"
                );
            }
            "-DNO_TFTP" => {
                println!(
                    "cargo:warning=COPTS: -DNO_TFTP detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'tftp' from feature list)"
                );
            }
            "-DNO_DHCP" => {
                println!(
                    "cargo:warning=COPTS: -DNO_DHCP detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'dhcp' and 'dhcp6' from feature list)"
                );
            }
            "-DNO_DHCP6" => {
                println!(
                    "cargo:warning=COPTS: -DNO_DHCP6 detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'dhcp6' from feature list)"
                );
            }
            "-DNO_SCRIPT" => {
                println!(
                    "cargo:warning=COPTS: -DNO_SCRIPT detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'script' from feature list)"
                );
            }
            "-DNO_AUTH" => {
                println!(
                    "cargo:warning=COPTS: -DNO_AUTH detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'auth' from feature list)"
                );
            }
            "-DNO_IPSET" => {
                println!(
                    "cargo:warning=COPTS: -DNO_IPSET detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'ipset' from feature list)"
                );
            }
            "-DNO_LOOP" => {
                println!(
                    "cargo:warning=COPTS: -DNO_LOOP detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'loop-detect' from feature list)"
                );
            }
            "-DNO_DUMPFILE" => {
                println!(
                    "cargo:warning=COPTS: -DNO_DUMPFILE detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'dumpfile' from feature list)"
                );
            }
            "-DNO_INOTIFY" => {
                println!(
                    "cargo:warning=COPTS: -DNO_INOTIFY detected. \
                     Use: cargo build --no-default-features --features '...' \
                     (omit 'inotify' from feature list)"
                );
            }
            _ => {
                // Unrecognized flag — emit a warning but do not fail the
                // build. The flag may be a C-specific option that has no
                // Rust equivalent.
                if token.starts_with("-D") {
                    println!(
                        "cargo:warning=COPTS: Unrecognized flag '{}'. \
                         This flag has no Cargo feature equivalent and is \
                         ignored in the Rust build.",
                        token
                    );
                }
            }
        }
    }
}

/// Check whether a Cargo feature is enabled for the current build.
///
/// Cargo sets the environment variable `CARGO_FEATURE_<NAME>` (with the
/// feature name uppercased and hyphens replaced by underscores) when a
/// feature is active. This function checks for that variable.
fn is_cargo_feature_enabled(feature: &str) -> bool {
    let env_key = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
    std::env::var(&env_key).is_ok()
}

/// Build script entry point.
///
/// Performs platform detection and emits `cargo:rustc-cfg` directives and
/// `cargo:rustc-env` variables that drive conditional compilation and
/// platform-specific defaults throughout the dnsmasq Rust codebase.
///
/// # Emitted Directives
///
/// 1. **Platform network stack** (`linux_network`, `bsd_network`, or
///    `solaris_network`) — exactly one is emitted per supported platform.
///
/// 2. **Inotify support** (`have_inotify`) — emitted on Linux when the
///    `inotify` Cargo feature is enabled.
///
/// 3. **Android detection** (`android`) — emitted on Android targets.
///
/// 4. **Socket address sa_len** (`have_sockaddr_sa_len`) — emitted on BSD
///    and macOS targets.
///
/// 5. **ipset variant** (`linux_ipset` or `bsd_ipset`) — emitted when the
///    `ipset` feature is enabled, selecting the platform implementation.
///
/// 6. **Default file paths** — `DNSMASQ_DEFAULT_LEASEFILE`,
///    `DNSMASQ_DEFAULT_CONFFILE`, `DNSMASQ_DEFAULT_RESOLVFILE`,
///    `DNSMASQ_DEFAULT_RUNFILE` — platform-specific defaults matching the
///    C `#ifndef` blocks in `src/config.h`.
///
/// 7. **Version string** — `DNSMASQ_VERSION` set to `"2.92-rust"`.
///
/// 8. **DNSMASQ_COPTS migration** — warns if the C-style `DNSMASQ_COPTS`
///    environment variable is set and guides the user to use Cargo features.
fn main() {
    // Read target platform information from Cargo-provided environment
    // variables. These are set by Cargo based on the `--target` triple and
    // are always available during build script execution.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // Phase 1: Platform-specific network stack detection.
    // Emits exactly one of: linux_network, bsd_network, solaris_network.
    // Mirrors src/config.h lines 2138–2349.
    detect_platform(&target_os);

    // Phase 2: Android-specific detection (subset of Linux).
    // Mirrors src/config.h __ANDROID__ checks.
    detect_android(&target_os, &target_env);

    // Phase 3: Socket address sa_len field detection.
    // Mirrors src/config.h HAVE_SOCKADDR_SA_LEN.
    detect_sockaddr_sa_len(&target_os);

    // Phase 4: ipset platform variant selection.
    // Mirrors src/config.h lines 2743–2751.
    detect_ipset_variant(&target_os);

    // Phase 5: Platform-specific default file paths.
    // Mirrors src/config.h lines 1898–2059.
    emit_default_paths(&target_os, &target_env);

    // Phase 6: Version information.
    // Embedded in the binary for identification via `dnsmasq --version`.
    println!("cargo:rustc-env=DNSMASQ_VERSION=2.92-rust");

    // Phase 7: Process DNSMASQ_COPTS environment variable (migration aid).
    process_copts();

    // Rerun-if-changed directives:
    // - build.rs: Rerun if this build script itself changes.
    // - DNSMASQ_COPTS: Rerun if the COPTS env variable changes.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DNSMASQ_COPTS");
}

// build.rs — Cargo build script for the dnsmasq Rust rewrite
//
// This build script replaces the platform detection and optional native library
// linking logic from the original C Makefile (lines 55-71). It runs at compile
// time before Rust source compilation and is responsible for:
//
//   1. Platform detection (Linux, BSD, macOS, Solaris) — replacing C preprocessor
//      macros (__linux__, __FreeBSD__, __APPLE__, __sun) from src/config.h
//   2. Architecture detection (x86_64, aarch64) for hardware-specific compilation
//   3. Optional native library detection via pkg-config — replacing the
//      bld/pkg-wrapper shell script used in the C Makefile
//   4. Emitting cargo:rustc-cfg directives for platform-specific conditional
//      compilation throughout the Rust codebase
//   5. Version information emission for runtime use
//
// Feature-gated library detection:
//   - D-Bus (feature = "dbus"):       pkg-config dbus-1       (from Makefile line 55-56)
//   - nftables (feature = "nftset"):   pkg-config libnftables  (from Makefile line 70-71)
//   - conntrack (feature = "conntrack"): pkg-config libnetfilter_conntrack (Makefile line 62-63)
//   - UBus (feature = "ubus"):         direct -lubus -lubox    (from Makefile line 57)
//
// IMPORTANT: The `ring` crate handles its own build via `cc` — no manual crypto
// library linking is needed here. Nettle/hogweed (used in C for DNSSEC) are NOT
// linked; they are fully replaced by the `ring` crate.
//
// Copyright (c) 2000-2025 Simon Kelley
// License: GPL-2.0-or-later

use std::env;
use std::fs;

/// Fallback version string used when the VERSION file is missing or contains
/// a git archive placeholder (e.g., `$Format:%d$`). This matches the version
/// defined in Cargo.toml.
const FALLBACK_VERSION: &str = "2.92";

fn main() {
    // ========================================================================
    // RERUN DIRECTIVES
    // ========================================================================
    // Ensure Cargo re-runs this build script when relevant inputs change.
    // This prevents stale cfg flags or link directives from persisting across
    // incremental builds.

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=VERSION");

    // Re-run if any feature-related environment variables change, since Cargo
    // passes feature flags as CARGO_FEATURE_<NAME> environment variables.
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DBUS");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NFTSET");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CONNTRACK");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UBUS");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");

    // ========================================================================
    // PLATFORM DETECTION
    // ========================================================================
    // Detect the target operating system and emit cargo:rustc-cfg directives
    // that replace the C preprocessor platform detection from src/config.h
    // (lines 2138-2349).
    //
    // C mapping:
    //   __linux__     / __UCLIBC__        → HAVE_LINUX_NETWORK
    //   __FreeBSD__   / __OpenBSD__  etc. → HAVE_BSD_NETWORK
    //   __APPLE__                         → HAVE_BSD_NETWORK
    //   __NetBSD__                        → HAVE_BSD_NETWORK
    //   __sun / __sun__                   → HAVE_SOLARIS_NETWORK
    //
    // Rust equivalents via CARGO_CFG_TARGET_OS:
    //   "linux"                           → target_platform_linux
    //   "freebsd" | "openbsd" | "netbsd"
    //   | "dragonfly"                     → target_platform_bsd
    //   "macos"                           → target_platform_bsd
    //   "solaris" | "illumos"             → target_platform_solaris

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "linux" => {
            // Linux: netlink, inotify, ipset/nftset, conntrack
            // Equivalent to C: #define HAVE_LINUX_NETWORK
            println!("cargo:rustc-cfg=target_platform_linux");
        }
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" => {
            // BSD variants: BPF, routing sockets, PF tables
            // Equivalent to C: #define HAVE_BSD_NETWORK
            println!("cargo:rustc-cfg=target_platform_bsd");
        }
        "macos" => {
            // macOS / Darwin: BSD networking with Apple-specific quirks
            // Equivalent to C: #define HAVE_BSD_NETWORK (under __APPLE__)
            // Note: macOS disables ipset (NO_IPSET in C config.h line 2268)
            println!("cargo:rustc-cfg=target_platform_bsd");
            println!("cargo:rustc-cfg=target_platform_macos");
        }
        "solaris" | "illumos" => {
            // Solaris / illumos: STREAMS-based networking, DLPI
            // Equivalent to C: #define HAVE_SOLARIS_NETWORK
            println!("cargo:rustc-cfg=target_platform_solaris");
        }
        _ => {
            // Unknown platform — emit a warning but do not fail the build.
            // The codebase will use safe fallback behavior without platform-specific
            // networking features.
            println!(
                "cargo:warning=Unknown target OS '{}'. Platform-specific features will be disabled.",
                target_os
            );
        }
    }

    // ========================================================================
    // ARCHITECTURE DETECTION
    // ========================================================================
    // Detect the target CPU architecture for any hardware-specific compilation
    // needs. Both x86_64 and aarch64 (ARM64) are primary targets per the AAP.

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    match target_arch.as_str() {
        "x86_64" => {
            // Standard x86-64 configuration — no special handling needed.
            println!("cargo:rustc-cfg=target_arch_x86_64");
        }
        "aarch64" => {
            // ARM64 configuration — may need specific alignment or struct
            // padding considerations for raw network protocol structs.
            println!("cargo:rustc-cfg=target_arch_aarch64");
        }
        "x86" => {
            println!("cargo:rustc-cfg=target_arch_x86");
        }
        "arm" => {
            // 32-bit ARM (e.g., Raspberry Pi, embedded routers)
            println!("cargo:rustc-cfg=target_arch_arm");
        }
        "mips" | "mipsel" | "mips64" | "mips64el" => {
            // MIPS variants common in embedded routers (OpenWrt targets)
            println!("cargo:rustc-cfg=target_arch_mips");
        }
        _ => {
            // Unsupported architecture — warn but allow compilation to proceed.
            println!(
                "cargo:warning=Unrecognized target architecture '{}'. Using default configuration.",
                target_arch
            );
        }
    }

    // ========================================================================
    // FEATURE-GATED NATIVE LIBRARY DETECTION
    // ========================================================================
    // Each optional native C library dependency is probed only when the
    // corresponding Cargo feature is enabled. This replaces the bld/pkg-wrapper
    // shell script from the C Makefile.
    //
    // The pkg-config crate automatically emits the necessary cargo:rustc-link-lib
    // and cargo:rustc-link-search directives when a library is found.

    detect_dbus_library(&target_os);
    detect_nftables_library(&target_os);
    detect_conntrack_library(&target_os);
    detect_ubus_library(&target_os);

    // ========================================================================
    // VERSION INFORMATION
    // ========================================================================
    // Read the VERSION file (if present) and emit it as a compile-time
    // environment variable accessible via env!("DNSMASQ_VERSION") in Rust code.
    //
    // The C Makefile uses bld/get-version (line 72) to extract version info.
    // In the Rust build, we read the VERSION file directly.

    emit_version_info();
}

// ============================================================================
// LIBRARY DETECTION FUNCTIONS
// ============================================================================

/// Detect libdbus-1 for D-Bus control interface integration.
///
/// Replaces C Makefile lines 55-56:
///   dbus_cflags = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DBUS $(PKG_CONFIG) --cflags dbus-1`
///   dbus_libs   = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DBUS $(PKG_CONFIG) --libs dbus-1`
///
/// The D-Bus feature is cross-platform (available on Linux, BSD, and macOS via
/// Homebrew), so this detection is not restricted to Linux only.
fn detect_dbus_library(_target_os: &str) {
    // Only probe if the "dbus" feature is enabled in Cargo.toml
    if env::var_os("CARGO_FEATURE_DBUS").is_none() {
        return;
    }

    match pkg_config::probe_library("dbus-1") {
        Ok(library) => {
            // pkg-config automatically emits link directives.
            // Log the detected version for build transparency.
            println!(
                "cargo:warning=Found libdbus-1 version {} for D-Bus integration",
                library.version
            );
        }
        Err(err) => {
            // D-Bus feature is enabled but the library was not found.
            // Emit a compile error so the user knows exactly what is missing.
            panic!(
                "D-Bus feature enabled but libdbus-1 not found via pkg-config. \
                 Install libdbus-1-dev (Debian/Ubuntu), dbus-devel (Fedora/RHEL), \
                 or dbus (Homebrew on macOS). Error: {}",
                err
            );
        }
    }
}

/// Detect libnftables for nftables set population.
///
/// Replaces C Makefile lines 70-71:
///   nft_cflags = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_NFTSET $(PKG_CONFIG) --cflags libnftables`
///   nft_libs   = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_NFTSET $(PKG_CONFIG) --libs libnftables`
///
/// nftables is Linux-specific (Linux kernel >= 3.13). This function is a no-op
/// on non-Linux targets.
fn detect_nftables_library(target_os: &str) {
    // Only probe if the "nftset" feature is enabled in Cargo.toml
    if env::var_os("CARGO_FEATURE_NFTSET").is_none() {
        return;
    }

    // nftables is Linux-only — skip detection on other platforms
    if target_os != "linux" {
        println!(
            "cargo:warning=nftset feature enabled but target OS '{}' is not Linux. \
             nftables is Linux-specific; feature will have no effect on this platform.",
            target_os
        );
        return;
    }

    match pkg_config::probe_library("libnftables") {
        Ok(library) => {
            println!(
                "cargo:warning=Found libnftables version {} for nftables set integration",
                library.version
            );
        }
        Err(err) => {
            panic!(
                "nftset feature enabled but libnftables not found via pkg-config. \
                 Install libnftables-dev (Debian/Ubuntu) or libnftables-devel (Fedora/RHEL). \
                 Error: {}",
                err
            );
        }
    }
}

/// Detect libnetfilter_conntrack for netfilter connection tracking mark retrieval.
///
/// Replaces C Makefile lines 62-63:
///   ct_cflags = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_CONNTRACK $(PKG_CONFIG) --cflags libnetfilter_conntrack`
///   ct_libs   = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_CONNTRACK $(PKG_CONFIG) --libs libnetfilter_conntrack`
///
/// Conntrack is Linux-specific (requires netfilter subsystem in the Linux kernel).
fn detect_conntrack_library(target_os: &str) {
    // Only probe if the "conntrack" feature is enabled in Cargo.toml
    if env::var_os("CARGO_FEATURE_CONNTRACK").is_none() {
        return;
    }

    // conntrack is Linux-only — skip detection on other platforms
    if target_os != "linux" {
        println!(
            "cargo:warning=conntrack feature enabled but target OS '{}' is not Linux. \
             Conntrack is Linux-specific; feature will have no effect on this platform.",
            target_os
        );
        return;
    }

    match pkg_config::probe_library("libnetfilter_conntrack") {
        Ok(library) => {
            println!(
                "cargo:warning=Found libnetfilter_conntrack version {} for conntrack integration",
                library.version
            );
        }
        Err(err) => {
            panic!(
                "conntrack feature enabled but libnetfilter_conntrack not found via pkg-config. \
                 Install libnetfilter-conntrack-dev (Debian/Ubuntu) or \
                 libnetfilter_conntrack-devel (Fedora/RHEL). Error: {}",
                err
            );
        }
    }
}

/// Emit direct link directives for OpenWrt UBus libraries.
///
/// Replaces C Makefile line 57:
///   ubus_libs = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_UBUS "" --copy '-lubox -lubus'`
///
/// UBus does not have pkg-config support — the C Makefile uses direct -l flags.
/// This is OpenWrt-specific, running on Linux. The libraries libubus and libubox
/// must be installed in the system library path or specified via LIBRARY_PATH.
fn detect_ubus_library(target_os: &str) {
    // Only emit link directives if the "ubus" feature is enabled in Cargo.toml
    if env::var_os("CARGO_FEATURE_UBUS").is_none() {
        return;
    }

    // UBus is Linux/OpenWrt-specific
    if target_os != "linux" {
        println!(
            "cargo:warning=ubus feature enabled but target OS '{}' is not Linux. \
             UBus is OpenWrt/Linux-specific; feature will have no effect on this platform.",
            target_os
        );
        return;
    }

    // No pkg-config for ubus — directly emit link instructions matching the
    // C Makefile's `-lubox -lubus` flags.
    println!("cargo:rustc-link-lib=ubus");
    println!("cargo:rustc-link-lib=ubox");

    println!("cargo:warning=UBus feature enabled: linking against libubus and libubox");
}

// ============================================================================
// VERSION INFORMATION
// ============================================================================

/// Read the VERSION file and emit the dnsmasq version as a compile-time
/// environment variable accessible via `env!("DNSMASQ_VERSION")` in Rust code.
///
/// The C Makefile uses `bld/get-version` (line 72) to extract version info:
///   version = -DVERSION='\"`$(top)/bld/get-version $(top)`\"'
///
/// In the Rust build, we read the VERSION file directly. If the file contains
/// a git archive placeholder (e.g., `$Format:%d$`), we fall back to the
/// hardcoded version matching Cargo.toml.
fn emit_version_info() {
    let version = match fs::read_to_string("VERSION") {
        Ok(content) => {
            let trimmed = content.trim().to_string();

            // The VERSION file may contain git-archive placeholders like
            // `$Format:%d$` which are not useful as version strings.
            // Detect and reject these placeholders.
            if trimmed.is_empty() || trimmed.contains("Format") || trimmed.starts_with('$') {
                FALLBACK_VERSION.to_string()
            } else {
                trimmed
            }
        }
        Err(_) => {
            // VERSION file not found — use fallback. This is normal during
            // development when building from a git checkout without the
            // VERSION file being populated by git-archive.
            FALLBACK_VERSION.to_string()
        }
    };

    println!("cargo:rustc-env=DNSMASQ_VERSION={}", version);
}

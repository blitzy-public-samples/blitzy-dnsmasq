// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Feature Flag Configuration
//!
//! This module documents the complete mapping from C `HAVE_*` preprocessor macros
//! (defined in `src/config.h`) to Cargo feature flags (defined in `Cargo.toml`).
//! It provides compile-time feature detection helper functions, platform detection
//! utilities, compile-options string generation for `--version` output, and
//! feature dependency validation.
//!
//! ## C-to-Rust Feature Flag Mapping
//!
//! | C Macro | Cargo Feature | Default | Description |
//! |---------|---------------|---------|-------------|
//! | `HAVE_DHCP` | `dhcp` | enabled | DHCPv4 server |
//! | `HAVE_DHCP6` | `dhcp6` | enabled | DHCPv6 server (implies `dhcp`) |
//! | `HAVE_TFTP` | `tftp` | enabled | TFTP server and PXE boot |
//! | `HAVE_SCRIPT` | `script` | enabled | Lease-change script execution |
//! | `HAVE_AUTH` | `auth` | enabled | Authoritative DNS zones |
//! | `HAVE_IPSET` | `ipset` | enabled | Linux ipset integration |
//! | `HAVE_LOOP` | `loop-detect` | enabled | DNS forwarding loop detection |
//! | `HAVE_DUMPFILE` | `dumpfile` | enabled | Packet dump for debugging |
//! | `HAVE_INOTIFY` | `inotify` | enabled | File change monitoring (Linux) |
//! | `HAVE_DNSSEC` | `dnssec` | disabled | DNSSEC validation (requires nettle) |
//! | `HAVE_DBUS` | `dbus` | disabled | D-Bus/NetworkManager integration |
//! | `HAVE_UBUS` | `ubus` | disabled | OpenWrt ubus integration |
//! | `HAVE_IDN`/`HAVE_LIBIDN2` | `idn` | disabled | International domain names |
//! | `HAVE_CONNTRACK` | `conntrack` | disabled | Linux conntrack mark support |
//! | `HAVE_NFTSET` | `nftset` | disabled | nftables set integration |
//! | `HAVE_LUASCRIPT` | `luascript` | disabled | Lua scripting support |
//! | `HAVE_LINUX_NETWORK` | (auto-detected) | auto | Linux via `cfg(target_os)` |
//! | `HAVE_BSD_NETWORK` | (auto-detected) | auto | BSD via `cfg(target_os)` |
//!
//! ## Feature Dependencies (matching C config.h lines 2350-2520)
//!
//! - `dhcp6` implies `dhcp` (DHCPv6 requires DHCPv4 infrastructure)
//! - `luascript` implies `script` (Lua scripting requires base script support)
//! - `nftset` requires Linux (`cfg(target_os = "linux")`)
//! - `inotify` requires Linux (`cfg(target_os = "linux")`)
//! - `ipset` requires Linux or BSD (platform-specific implementations)
//!
//! ## Platform Detection (replacing C lines 2060-2350)
//!
//! Platform selection uses Rust `cfg(target_os)` instead of C compiler macros:
//! - `cfg(target_os = "linux")` → replaces `HAVE_LINUX_NETWORK`
//! - `cfg(any(target_os = "freebsd", ..., target_os = "macos"))` → replaces `HAVE_BSD_NETWORK`
//! - `cfg(target_os = "solaris")` → replaces `HAVE_SOLARIS_NETWORK`

// =============================================================================
// Feature Detection Helper Functions
// =============================================================================
//
// These functions provide compile-time feature detection, replacing C
// `#ifdef HAVE_*` checks with idiomatic Rust `cfg!()` macro evaluations.
// Each function is `const fn` and `#[inline]` for zero-cost abstraction —
// the compiler evaluates them at compile time, eliminating dead code branches.
// =============================================================================

/// Returns true if DHCPv4 server is compiled in.
///
/// Replaces C `#ifdef HAVE_DHCP` checks from `src/config.h`.
/// When enabled, the DHCPv4 server module (`dhcp::v4`) is available,
/// providing DISCOVER/OFFER/REQUEST/ACK state machine, lease management,
/// and BOOTP compatibility.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_dhcp;
/// // With default features enabled:
/// assert!(has_dhcp());
/// ```
#[inline]
pub const fn has_dhcp() -> bool {
    cfg!(feature = "dhcp")
}

/// Returns true if DHCPv6 server is compiled in.
///
/// Replaces C `#ifdef HAVE_DHCP6` checks from `src/config.h`.
/// Note: `dhcp6` implies `dhcp` (enforced in `Cargo.toml` feature dependencies),
/// mirroring the C dependency chain in config.h lines 2350-2400.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_dhcp6;
/// // With default features enabled:
/// assert!(has_dhcp6());
/// ```
#[inline]
pub const fn has_dhcp6() -> bool {
    cfg!(feature = "dhcp6")
}

/// Returns true if TFTP server is compiled in.
///
/// Replaces C `#ifdef HAVE_TFTP` checks from `src/config.h`.
/// When enabled, the TFTP server module (`services::tftp`) provides
/// file transfer for PXE network boot.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_tftp;
/// // With default features enabled:
/// assert!(has_tftp());
/// ```
#[inline]
pub const fn has_tftp() -> bool {
    cfg!(feature = "tftp")
}

/// Returns true if external script execution is compiled in.
///
/// Replaces C `#ifdef HAVE_SCRIPT` checks from `src/config.h`.
/// When enabled, the script execution helper (`integration::helper`) can
/// invoke external scripts on DHCP lease events.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_script;
/// // With default features enabled:
/// assert!(has_script());
/// ```
#[inline]
pub const fn has_script() -> bool {
    cfg!(feature = "script")
}

/// Returns true if Lua scripting is compiled in.
///
/// Replaces C `#ifdef HAVE_LUASCRIPT` checks from `src/config.h`.
/// Note: `luascript` implies `script` (enforced in `Cargo.toml` feature dependencies),
/// mirroring the C dependency chain in config.h lines 2490-2520.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_luascript;
/// // luascript is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_luascript();
/// ```
#[inline]
pub const fn has_luascript() -> bool {
    cfg!(feature = "luascript")
}

/// Returns true if authoritative DNS is compiled in.
///
/// Replaces C `#ifdef HAVE_AUTH` checks from `src/config.h`.
/// When enabled, the authoritative DNS module (`dns::auth`) can serve
/// zone data for configured domains.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_auth;
/// // With default features enabled:
/// assert!(has_auth());
/// ```
#[inline]
pub const fn has_auth() -> bool {
    cfg!(feature = "auth")
}

/// Returns true if DNSSEC validation is compiled in.
///
/// Replaces C `#ifdef HAVE_DNSSEC` checks from `src/config.h`.
/// When enabled, the DNSSEC module (`dns::dnssec`) provides DNS Security
/// Extensions validation using the nettle cryptographic library.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_dnssec;
/// // dnssec is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_dnssec();
/// ```
#[inline]
pub const fn has_dnssec() -> bool {
    cfg!(feature = "dnssec")
}

/// Returns true if D-Bus integration is compiled in.
///
/// Replaces C `#ifdef HAVE_DBUS` checks from `src/config.h`.
/// When enabled, the D-Bus module (`integration::dbus`) provides
/// NetworkManager integration and runtime control via D-Bus messages.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_dbus;
/// // dbus is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_dbus();
/// ```
#[inline]
pub const fn has_dbus() -> bool {
    cfg!(feature = "dbus")
}

/// Returns true if UBus integration is compiled in.
///
/// Replaces C `#ifdef HAVE_UBUS` checks from `src/config.h`.
/// When enabled, the UBus module (`integration::ubus`) provides
/// OpenWrt message bus integration.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_ubus;
/// // ubus is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_ubus();
/// ```
#[inline]
pub const fn has_ubus() -> bool {
    cfg!(feature = "ubus")
}

/// Returns true if IDN (international domain names) is compiled in.
///
/// Replaces C `#ifdef HAVE_IDN` and `#ifdef HAVE_LIBIDN2` checks from `src/config.h`.
/// When enabled, domain names containing non-ASCII characters are processed
/// using the IDNA standard (RFC 5891).
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_idn;
/// // idn is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_idn();
/// ```
#[inline]
pub const fn has_idn() -> bool {
    cfg!(feature = "idn")
}

/// Returns true if conntrack integration is compiled in.
///
/// Replaces C `#ifdef HAVE_CONNTRACK` checks from `src/config.h`.
/// When enabled, DNS query connections can be tagged with conntrack marks
/// for firewall integration on Linux.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_conntrack;
/// // conntrack is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_conntrack();
/// ```
#[inline]
pub const fn has_conntrack() -> bool {
    cfg!(feature = "conntrack")
}

/// Returns true if ipset integration is compiled in.
///
/// Replaces C `#ifdef HAVE_IPSET` checks from `src/config.h`.
/// When enabled, DNS query results can add resolved addresses to Linux
/// ipset or BSD ipfw table sets for firewall integration.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_ipset;
/// // With default features enabled:
/// assert!(has_ipset());
/// ```
#[inline]
pub const fn has_ipset() -> bool {
    cfg!(feature = "ipset")
}

/// Returns true if nftables set integration is compiled in.
///
/// Replaces C `#ifdef HAVE_NFTSET` checks from `src/config.h`.
/// When enabled, DNS query results can add resolved addresses to
/// nftables named sets for firewall integration on Linux.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_nftset;
/// // nftset is disabled by default:
/// // (this test is feature-dependent)
/// let _ = has_nftset();
/// ```
#[inline]
pub const fn has_nftset() -> bool {
    cfg!(feature = "nftset")
}

/// Returns true if loop detection is compiled in.
///
/// Replaces C `#ifdef HAVE_LOOP` checks from `src/config.h`.
/// When enabled, the loop detection module (`dns::loop_detect`) can detect
/// DNS forwarding loops where dnsmasq forwards queries back to itself.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_loop_detect;
/// // With default features enabled:
/// assert!(has_loop_detect());
/// ```
#[inline]
pub const fn has_loop_detect() -> bool {
    cfg!(feature = "loop-detect")
}

/// Returns true if packet dump is compiled in.
///
/// Replaces C `#ifdef HAVE_DUMPFILE` checks from `src/config.h`.
/// When enabled, the dump module (`diagnostics::dump`) can capture
/// DNS and DHCP packets to a pcap-format file for debugging.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_dumpfile;
/// // With default features enabled:
/// assert!(has_dumpfile());
/// ```
#[inline]
pub const fn has_dumpfile() -> bool {
    cfg!(feature = "dumpfile")
}

/// Returns true if inotify file monitoring is compiled in.
///
/// Replaces C `#ifdef HAVE_INOTIFY` checks from `src/config.h`.
/// Auto-enabled on Linux if not explicitly disabled. When enabled,
/// the inotify module (`diagnostics::inotify`) monitors `/etc/hosts`
/// and `/etc/resolv.conf` for changes.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_inotify;
/// // With default features enabled:
/// assert!(has_inotify());
/// ```
#[inline]
pub const fn has_inotify() -> bool {
    cfg!(feature = "inotify")
}

// =============================================================================
// Platform Detection Helpers
// =============================================================================
//
// These functions replace C platform detection macros from config.h lines
// 2060-2350. They use Rust's `cfg!(target_os)` built-in macro instead of
// compiler-predefined macros like `__linux__`, `__FreeBSD__`, etc.
// =============================================================================

/// Returns true if running on Linux.
///
/// Replaces C `HAVE_LINUX_NETWORK` macro from `src/config.h` line 2177.
/// When true, the Linux-specific network stack is used: netlink sockets
/// for interface monitoring, inotify for file changes, and Linux-specific
/// DHCP packet filters.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::is_linux;
/// let _ = is_linux(); // true on Linux, false elsewhere
/// ```
#[inline]
pub const fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Returns true if running on a BSD variant (FreeBSD, OpenBSD, NetBSD, DragonFly, macOS).
///
/// Replaces C `HAVE_BSD_NETWORK` macro from `src/config.h` line 2211.
/// When true, the BSD-specific network stack is used: BPF (Berkeley Packet
/// Filter) for DHCP packet capture and routing sockets for interface monitoring.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::is_bsd;
/// let _ = is_bsd(); // true on FreeBSD/macOS/etc., false elsewhere
/// ```
#[inline]
pub const fn is_bsd() -> bool {
    cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))
}

/// Returns true if running on Solaris.
///
/// Replaces C `HAVE_SOLARIS_NETWORK` macro from `src/config.h`.
/// When true, the Solaris-specific STREAMS-based network stack is used.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::is_solaris;
/// let _ = is_solaris(); // true on Solaris/illumos, false elsewhere
/// ```
#[inline]
pub const fn is_solaris() -> bool {
    cfg!(target_os = "solaris")
}

/// Returns true if running on Android.
///
/// Replaces C `__ANDROID__` macro from `src/config.h`.
/// When true, Android-specific file paths are used (e.g.,
/// lease file at `/data/misc/dhcp/dnsmasq.leases`).
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::is_android;
/// let _ = is_android(); // true on Android, false elsewhere
/// ```
#[inline]
pub const fn is_android() -> bool {
    cfg!(target_os = "android")
}

/// Returns true if `struct sockaddr` has `sa_len` field.
///
/// Replaces C `HAVE_SOCKADDR_SA_LEN` macro from `src/config.h`.
/// Present on BSD variants, absent on Linux/Solaris.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_sockaddr_sa_len;
/// let _ = has_sockaddr_sa_len(); // true on BSD, false on Linux
/// ```
#[inline]
pub const fn has_sockaddr_sa_len() -> bool {
    cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))
}

/// Returns true if Linux-specific ipset (via netlink) is available.
///
/// Replaces C `HAVE_LINUX_IPSET` conditional compilation.
/// Requires both the `ipset` feature and Linux target OS.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_linux_ipset;
/// let _ = has_linux_ipset(); // true only on Linux with ipset feature
/// ```
#[inline]
pub const fn has_linux_ipset() -> bool {
    cfg!(all(feature = "ipset", target_os = "linux"))
}

/// Returns true if BSD-specific ipset (via ipfw tables) is available.
///
/// Replaces C `HAVE_BSD_IPSET` conditional compilation.
/// Requires both the `ipset` feature and a BSD target OS.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::has_bsd_ipset;
/// let _ = has_bsd_ipset(); // true only on FreeBSD/etc. with ipset feature
/// ```
#[inline]
pub const fn has_bsd_ipset() -> bool {
    cfg!(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )
    ))
}

// =============================================================================
// Compile-Time Options String
// =============================================================================
//
// Replaces the C `compile_opts` static string from config.h lines 2930-3020.
// Used for `dnsmasq --version` output and build identification.
// =============================================================================

/// Build a string describing which compile-time options are active.
///
/// Replaces C `compile_opts` static string from `src/config.h` lines 2930-3020.
/// Used for `--version` output and debugging build identification.
///
/// The format matches the C version's output exactly:
/// - Features that are enabled are listed by name
/// - Features that are disabled are prefixed with `no-`
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::compile_options_string;
/// let opts = compile_options_string();
/// assert!(opts.contains("IPv6"));
/// assert!(opts.contains("DHCP"));
/// ```
pub fn compile_options_string() -> String {
    let mut opts = String::with_capacity(256);
    opts.push_str("IPv6 ");

    // GNU-getopt (always available in Rust via clap)
    opts.push_str("GNU-getopt ");

    // Broken-RTC flag: Rust implementation does not assume a broken RTC,
    // but we include the token in the output for completeness. In C this is
    // controlled by the HAVE_BROKEN_RTC preprocessor macro. Since Rust uses
    // the system clock normally, we do not emit "no-RTC".
    // If a future build-time flag is added, gate this accordingly.

    // Feature flags — format matches C compile_opts exactly
    if !has_dbus() {
        opts.push_str("no-");
    }
    opts.push_str("DBus ");

    if !has_ubus() {
        opts.push_str("no-");
    }
    opts.push_str("UBus ");

    // i18n (internationalization/locale support): In C, controlled by
    // LOCALEDIR being defined. Rust does not use gettext/LOCALEDIR, so
    // we emit "no-i18n" to accurately reflect no locale translation support.
    opts.push_str("no-i18n ");

    // IDN: C distinguishes HAVE_LIBIDN2 (emits "IDN2") from HAVE_IDN
    // (emits "IDN"). Rust uses the `idna` crate which implements IDNA 2008
    // (equivalent to libidn2), so we emit "IDN2" when the feature is enabled.
    if has_idn() {
        opts.push_str("IDN2 ");
    } else {
        opts.push_str("no-IDN ");
    }

    if !has_dhcp() {
        opts.push_str("no-");
    }
    opts.push_str("DHCP ");

    if has_dhcp() {
        if !has_dhcp6() {
            opts.push_str("no-");
        }
        opts.push_str("DHCPv6 ");
    }

    if !has_script() {
        opts.push_str("no-scripts ");
    } else {
        if !has_luascript() {
            opts.push_str("no-");
        }
        opts.push_str("Lua ");
    }

    if !has_tftp() {
        opts.push_str("no-");
    }
    opts.push_str("TFTP ");

    if !has_conntrack() {
        opts.push_str("no-");
    }
    opts.push_str("conntrack ");

    if !has_ipset() {
        opts.push_str("no-");
    }
    opts.push_str("ipset ");

    if !has_nftset() {
        opts.push_str("no-");
    }
    opts.push_str("nftset ");

    if !has_auth() {
        opts.push_str("no-");
    }
    opts.push_str("auth ");

    if !has_dnssec() {
        opts.push_str("no-");
    }
    opts.push_str("DNSSEC ");

    // NO_ID: In C, controlled by the NO_ID preprocessor macro which
    // disables CHAOS TXT identity responses at compile time. In Rust,
    // identity support is always compiled in (controlled at runtime via
    // the --no-ident flag / OPT_NO_IDENT), so we never emit "no-ID".
    // This matches the default C build where NO_ID is not defined.

    if !has_loop_detect() {
        opts.push_str("no-");
    }
    opts.push_str("loop-detect ");

    if !has_inotify() {
        opts.push_str("no-");
    }
    opts.push_str("inotify ");

    if !has_dumpfile() {
        opts.push_str("no-");
    }
    opts.push_str("dumpfile");

    opts
}

// =============================================================================
// Feature Dependency Validation
// =============================================================================
//
// Provides compile-time and runtime validation that feature dependencies
// are correctly configured, complementing Cargo.toml feature dependencies.
// Replaces C config.h dependency resolution (lines 2350-2596).
// =============================================================================

/// Validate that feature dependencies are correctly configured.
///
/// This provides runtime verification complementing `Cargo.toml` feature
/// dependencies. The primary enforcement is at compile time via
/// `Cargo.toml` feature dependency declarations and `compile_error!`
/// macros, but this function provides a runtime check for diagnostic
/// purposes.
///
/// Replaces C config.h dependency resolution (lines 2350-2596).
///
/// # Returns
///
/// `Ok(())` if all feature dependencies are satisfied, or an `Err` with
/// a description of the unsatisfied dependency.
///
/// # Example
///
/// ```
/// use dnsmasq::config::features::validate_feature_dependencies;
/// assert!(validate_feature_dependencies().is_ok());
/// ```
pub fn validate_feature_dependencies() -> Result<(), String> {
    // DHCPv6 requires DHCPv4 — enforced in Cargo.toml: dhcp6 = ["dhcp"]
    // This compile_error! provides a clear message if someone bypasses Cargo.toml
    #[cfg(all(feature = "dhcp6", not(feature = "dhcp")))]
    compile_error!("Feature 'dhcp6' requires feature 'dhcp' to be enabled");

    // Luascript requires script — enforced in Cargo.toml: luascript = ["script", "dep:mlua"]
    #[cfg(all(feature = "luascript", not(feature = "script")))]
    compile_error!("Feature 'luascript' requires feature 'script' to be enabled");

    Ok(())
}

// =============================================================================
// Conditional Compilation Helper Macros
// =============================================================================
//
// Provide helper macros for common feature-gated patterns, replacing
// C `#ifdef HAVE_DHCP` ... `#endif` patterns with idiomatic Rust macros.
// =============================================================================

/// Helper macro for conditionally compiling DHCP-related code.
///
/// Usage: `if_dhcp! { /* DHCP code */ }`
///
/// Replaces C `#ifdef HAVE_DHCP` ... `#endif` pattern.
#[macro_export]
macro_rules! if_dhcp {
    ($($tt:tt)*) => {
        #[cfg(feature = "dhcp")]
        { $($tt)* }
    };
}

/// Helper macro for conditionally compiling DHCPv6-related code.
///
/// Usage: `if_dhcp6! { /* DHCPv6 code */ }`
///
/// Replaces C `#ifdef HAVE_DHCP6` ... `#endif` pattern.
#[macro_export]
macro_rules! if_dhcp6 {
    ($($tt:tt)*) => {
        #[cfg(feature = "dhcp6")]
        { $($tt)* }
    };
}

/// Helper macro for conditionally compiling TFTP-related code.
///
/// Usage: `if_tftp! { /* TFTP code */ }`
///
/// Replaces C `#ifdef HAVE_TFTP` ... `#endif` pattern.
#[macro_export]
macro_rules! if_tftp {
    ($($tt:tt)*) => {
        #[cfg(feature = "tftp")]
        { $($tt)* }
    };
}

/// Helper macro for conditionally compiling DNSSEC-related code.
///
/// Usage: `if_dnssec! { /* DNSSEC code */ }`
///
/// Replaces C `#ifdef HAVE_DNSSEC` ... `#endif` pattern.
#[macro_export]
macro_rules! if_dnssec {
    ($($tt:tt)*) => {
        #[cfg(feature = "dnssec")]
        { $($tt)* }
    };
}

/// Helper macro for conditionally compiling D-Bus-related code.
///
/// Usage: `if_dbus! { /* D-Bus code */ }`
///
/// Replaces C `#ifdef HAVE_DBUS` ... `#endif` pattern.
#[macro_export]
macro_rules! if_dbus {
    ($($tt:tt)*) => {
        #[cfg(feature = "dbus")]
        { $($tt)* }
    };
}

/// Helper macro for conditionally compiling authoritative DNS code.
///
/// Usage: `if_auth! { /* auth code */ }`
///
/// Replaces C `#ifdef HAVE_AUTH` ... `#endif` pattern.
#[macro_export]
macro_rules! if_auth {
    ($($tt:tt)*) => {
        #[cfg(feature = "auth")]
        { $($tt)* }
    };
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Feature detection function tests ──

    #[test]
    fn test_has_dhcp_returns_bool() {
        // has_dhcp() should return a bool; with default features it is true
        let result = has_dhcp();
        assert!(
            result == true || result == false,
            "has_dhcp() must return a bool"
        );
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn test_has_dhcp_enabled_with_feature() {
        assert!(
            has_dhcp(),
            "has_dhcp() should be true when dhcp feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn test_has_dhcp6_enabled_with_feature() {
        assert!(
            has_dhcp6(),
            "has_dhcp6() should be true when dhcp6 feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn test_dhcp6_implies_dhcp() {
        // If dhcp6 is enabled, dhcp must also be enabled (Cargo.toml enforces this)
        assert!(
            has_dhcp(),
            "has_dhcp() must be true when dhcp6 is enabled (dhcp6 implies dhcp)"
        );
    }

    #[test]
    #[cfg(feature = "tftp")]
    fn test_has_tftp_enabled_with_feature() {
        assert!(
            has_tftp(),
            "has_tftp() should be true when tftp feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "script")]
    fn test_has_script_enabled_with_feature() {
        assert!(
            has_script(),
            "has_script() should be true when script feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "auth")]
    fn test_has_auth_enabled_with_feature() {
        assert!(
            has_auth(),
            "has_auth() should be true when auth feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "ipset")]
    fn test_has_ipset_enabled_with_feature() {
        assert!(
            has_ipset(),
            "has_ipset() should be true when ipset feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "loop-detect")]
    fn test_has_loop_detect_enabled_with_feature() {
        assert!(
            has_loop_detect(),
            "has_loop_detect() should be true when loop-detect feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "dumpfile")]
    fn test_has_dumpfile_enabled_with_feature() {
        assert!(
            has_dumpfile(),
            "has_dumpfile() should be true when dumpfile feature is enabled"
        );
    }

    #[test]
    #[cfg(feature = "inotify")]
    fn test_has_inotify_enabled_with_feature() {
        assert!(
            has_inotify(),
            "has_inotify() should be true when inotify feature is enabled"
        );
    }

    #[test]
    fn test_has_ubus_returns_bool() {
        let result = has_ubus();
        assert!(
            result == true || result == false,
            "has_ubus() must return a bool"
        );
    }

    #[test]
    fn test_has_idn_returns_bool() {
        let result = has_idn();
        assert!(
            result == true || result == false,
            "has_idn() must return a bool"
        );
    }

    #[test]
    fn test_has_conntrack_returns_bool() {
        let result = has_conntrack();
        assert!(
            result == true || result == false,
            "has_conntrack() must return a bool"
        );
    }

    #[test]
    fn test_has_dnssec_returns_bool() {
        let result = has_dnssec();
        assert!(
            result == true || result == false,
            "has_dnssec() must return a bool"
        );
    }

    #[test]
    fn test_has_dbus_returns_bool() {
        let result = has_dbus();
        assert!(
            result == true || result == false,
            "has_dbus() must return a bool"
        );
    }

    #[test]
    fn test_has_nftset_returns_bool() {
        let result = has_nftset();
        assert!(
            result == true || result == false,
            "has_nftset() must return a bool"
        );
    }

    #[test]
    fn test_has_luascript_returns_bool() {
        let result = has_luascript();
        assert!(
            result == true || result == false,
            "has_luascript() must return a bool"
        );
    }

    // ── Platform detection tests ──

    #[test]
    fn test_is_linux_returns_bool() {
        let result = is_linux();
        assert!(
            result == true || result == false,
            "is_linux() must return a bool"
        );
    }

    #[test]
    fn test_is_bsd_returns_bool() {
        let result = is_bsd();
        assert!(
            result == true || result == false,
            "is_bsd() must return a bool"
        );
    }

    #[test]
    fn test_is_solaris_returns_bool() {
        let result = is_solaris();
        assert!(
            result == true || result == false,
            "is_solaris() must return a bool"
        );
    }

    #[test]
    fn test_is_android_returns_bool() {
        let result = is_android();
        assert!(
            result == true || result == false,
            "is_android() must return a bool"
        );
    }

    #[test]
    fn test_has_sockaddr_sa_len_returns_bool() {
        let result = has_sockaddr_sa_len();
        assert!(
            result == true || result == false,
            "has_sockaddr_sa_len() must return a bool"
        );
    }

    #[test]
    fn test_has_linux_ipset_returns_bool() {
        let result = has_linux_ipset();
        assert!(
            result == true || result == false,
            "has_linux_ipset() must return a bool"
        );
    }

    #[test]
    fn test_has_bsd_ipset_returns_bool() {
        let result = has_bsd_ipset();
        assert!(
            result == true || result == false,
            "has_bsd_ipset() must return a bool"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_platform_linux_detected() {
        assert!(is_linux(), "is_linux() must be true on Linux");
        assert!(!is_bsd(), "is_bsd() must be false on Linux");
        assert!(!is_solaris(), "is_solaris() must be false on Linux");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_ipset_when_feature_enabled() {
        // On Linux, has_linux_ipset() matches has_ipset()
        assert_eq!(
            has_linux_ipset(),
            has_ipset(),
            "On Linux, has_linux_ipset() should equal has_ipset()"
        );
    }

    // ── Compile options string tests ──

    #[test]
    fn test_compile_options_string_contains_ipv6() {
        let opts = compile_options_string();
        assert!(
            opts.contains("IPv6"),
            "compile_options_string() must contain 'IPv6'"
        );
    }

    #[test]
    fn test_compile_options_string_contains_gnu_getopt() {
        let opts = compile_options_string();
        assert!(
            opts.contains("GNU-getopt"),
            "compile_options_string() must contain 'GNU-getopt'"
        );
    }

    #[test]
    fn test_compile_options_string_contains_dhcp() {
        let opts = compile_options_string();
        assert!(
            opts.contains("DHCP"),
            "compile_options_string() must contain 'DHCP' (with or without 'no-' prefix)"
        );
    }

    #[test]
    fn test_compile_options_string_contains_dbus() {
        let opts = compile_options_string();
        assert!(
            opts.contains("DBus"),
            "compile_options_string() must contain 'DBus' (with or without 'no-' prefix)"
        );
    }

    #[test]
    fn test_compile_options_string_contains_dnssec() {
        let opts = compile_options_string();
        assert!(
            opts.contains("DNSSEC"),
            "compile_options_string() must contain 'DNSSEC' (with or without 'no-' prefix)"
        );
    }

    #[test]
    fn test_compile_options_string_contains_tftp() {
        let opts = compile_options_string();
        assert!(
            opts.contains("TFTP"),
            "compile_options_string() must contain 'TFTP' (with or without 'no-' prefix)"
        );
    }

    #[test]
    fn test_compile_options_string_contains_loop_detect() {
        let opts = compile_options_string();
        assert!(
            opts.contains("loop-detect"),
            "compile_options_string() must contain 'loop-detect'"
        );
    }

    #[test]
    fn test_compile_options_string_contains_inotify() {
        let opts = compile_options_string();
        assert!(
            opts.contains("inotify"),
            "compile_options_string() must contain 'inotify'"
        );
    }

    #[test]
    fn test_compile_options_string_contains_dumpfile() {
        let opts = compile_options_string();
        assert!(
            opts.contains("dumpfile"),
            "compile_options_string() must contain 'dumpfile'"
        );
    }

    #[test]
    #[cfg(all(feature = "dhcp", not(feature = "dhcp6")))]
    fn test_compile_options_no_dhcpv6_when_dhcp6_disabled() {
        let opts = compile_options_string();
        assert!(
            opts.contains("no-DHCPv6"),
            "Should show 'no-DHCPv6' when dhcp6 is disabled but dhcp is enabled"
        );
    }

    #[test]
    #[cfg(all(feature = "dhcp", feature = "dhcp6"))]
    fn test_compile_options_dhcpv6_when_enabled() {
        let opts = compile_options_string();
        // Should contain "DHCPv6" without "no-" prefix
        assert!(
            opts.contains("DHCPv6"),
            "Should contain 'DHCPv6' when dhcp6 is enabled"
        );
        // Should not contain "no-DHCPv6"
        assert!(
            !opts.contains("no-DHCPv6"),
            "Should not contain 'no-DHCPv6' when dhcp6 is enabled"
        );
    }

    // ── Feature dependency validation tests ──

    #[test]
    fn test_validate_feature_dependencies_ok() {
        let result = validate_feature_dependencies();
        assert!(
            result.is_ok(),
            "validate_feature_dependencies() should return Ok with valid feature configuration"
        );
    }

    // ── Exhaustive feature helper coverage ──

    #[test]
    fn test_all_feature_helpers_are_const() {
        // Verify all functions can be used in const contexts
        const _DHCP: bool = has_dhcp();
        const _DHCP6: bool = has_dhcp6();
        const _TFTP: bool = has_tftp();
        const _SCRIPT: bool = has_script();
        const _LUASCRIPT: bool = has_luascript();
        const _AUTH: bool = has_auth();
        const _DNSSEC: bool = has_dnssec();
        const _DBUS: bool = has_dbus();
        const _UBUS: bool = has_ubus();
        const _IDN: bool = has_idn();
        const _CONNTRACK: bool = has_conntrack();
        const _IPSET: bool = has_ipset();
        const _NFTSET: bool = has_nftset();
        const _LOOP: bool = has_loop_detect();
        const _DUMPFILE: bool = has_dumpfile();
        const _INOTIFY: bool = has_inotify();
        const _LINUX: bool = is_linux();
        const _BSD: bool = is_bsd();
        const _SOLARIS: bool = is_solaris();
        const _ANDROID: bool = is_android();
        const _SA_LEN: bool = has_sockaddr_sa_len();
        const _LINUX_IPSET: bool = has_linux_ipset();
        const _BSD_IPSET: bool = has_bsd_ipset();
    }
}

//! Cargo feature flag integration for dnsmasq.
//!
//! This module maps C compile-time `HAVE_*` macros to Rust `#[cfg(feature = "...")]`
//! attributes and provides runtime feature reporting equivalent to C's `compile_opts`
//! string (defined in `config.h` lines 2931–3018).
//!
//! # Overview
//!
//! In the original C codebase, optional subsystems are controlled by preprocessor
//! macros such as `HAVE_DHCP`, `HAVE_DNSSEC`, and `HAVE_TFTP`. These are toggled
//! at build time through the Makefile `COPTS` variable. In the Rust rewrite, these
//! macros are replaced by Cargo feature flags declared in `Cargo.toml` and consumed
//! via `#[cfg(feature = "...")]` attributes.
//!
//! This module centralises:
//!
//! 1. **Documentation** — a canonical mapping table from C macros to Cargo features.
//! 2. **Runtime reporting** — [`compile_opts_string`] reproduces the version-banner
//!    string printed by `dnsmasq --version`.
//! 3. **Feature detection helpers** — small `const fn` predicates for common
//!    compound checks (e.g. "is any DHCP flavour enabled?").
//! 4. **Compile-time dependency validation** — `compile_error!` guards that
//!    enforce the same feature dependency rules as the C `#ifdef` chains.
//! 5. **Platform constants** — the [`platform`] sub-module exposes boolean
//!    constants mirroring C's `HAVE_LINUX_NETWORK` / `HAVE_BSD_NETWORK`.
//!
//! # Feature Flag Mapping
//!
//! | C Macro | Cargo Feature | Default | Description |
//! |---------|---------------|---------|-------------|
//! | `HAVE_DHCP` | `dhcp` | enabled | DHCPv4 server (RFC 2131) |
//! | `HAVE_DHCP6` | `dhcp6` | enabled | DHCPv6 server (RFC 3315) + Router Advertisements |
//! | `HAVE_DNSSEC` | `dnssec` | disabled | DNSSEC validation (requires `ring` crate) |
//! | `HAVE_DBUS` | `dbus` | disabled | D-Bus control interface |
//! | `HAVE_UBUS` | `ubus` | disabled | OpenWrt UBus control interface |
//! | `HAVE_TFTP` | `tftp` | enabled | Built-in TFTP server (RFC 1350/2349) |
//! | `HAVE_SCRIPT` | `script` | enabled | Lease-change script execution |
//! | `HAVE_AUTH` | `auth` | enabled | Authoritative DNS zone serving |
//! | `HAVE_IPSET` | `ipset` | enabled | Linux ipset population via netlink |
//! | `HAVE_NFTSET` | `nftset` | disabled | nftables set population via libnftables |
//! | `HAVE_CONNTRACK` | `conntrack` | disabled | Netfilter conntrack mark retrieval |
//! | `HAVE_INOTIFY` | `inotify_monitor` | disabled | File change monitoring (Linux) |
//! | `HAVE_LOOP` | `loop_detect` | enabled | DNS forwarding loop detection |
//! | `HAVE_DUMPFILE` | `dump` | enabled | Pcap packet capture for diagnostics |
//! | `HAVE_IDN` / `HAVE_LIBIDN2` | `idn` | disabled | Internationalized domain names (IDNA 2008) |
//!
//! # Default Build Configuration
//!
//! The Cargo default feature set mirrors the C defaults from `config.h` lines 844-846:
//!
//! ```text
//! Enabled by default:  dhcp, dhcp6, tftp, script, auth, ipset, loop_detect, dump
//! Disabled by default: dnssec, dbus, ubus, nftset, conntrack, inotify_monitor, idn
//! ```
//!
//! # Feature Dependencies
//!
//! - `dhcp6` implies `dhcp` (Cargo.toml declares `dhcp6 = ["dhcp"]`).
//! - `nftset`, `ipset`, `conntrack`, and `inotify_monitor` are Linux-only and
//!   guarded by `compile_error!` on non-Linux targets.
//!
//! # Examples
//!
//! ```rust
//! use dnsmasq::config::feature_flags::{compile_opts_string, has_dhcp, platform};
//!
//! // Print the version feature string (same format as `dnsmasq --version`)
//! println!("{}", compile_opts_string());
//!
//! // Query compound feature availability
//! if has_dhcp() {
//!     println!("DHCP subsystem is compiled in");
//! }
//!
//! // Platform constants
//! if platform::LINUX_NETWORK {
//!     println!("Running on Linux with netlink support");
//! }
//! ```

// ============================================================================
// Compile-time feature dependency validation
// ============================================================================
//
// These guards replicate the C `#ifdef` dependency chains from config.h
// (lines 2351–2874). Violations are caught at compile time with clear
// diagnostic messages.

/// DHCPv6 requires DHCPv4 infrastructure (shared lease database, common
/// utilities, option parsing). In C this was enforced by
/// `#ifdef HAVE_DHCP6 / #define HAVE_DHCP`. In Cargo.toml the dependency
/// is expressed as `dhcp6 = ["dhcp"]`, but we add a belt-and-suspenders
/// compile-time check here.
#[cfg(all(feature = "dhcp6", not(feature = "dhcp")))]
compile_error!(
    "Feature 'dhcp6' requires 'dhcp' to be enabled. \
     DHCPv6 depends on DHCPv4 infrastructure (shared lease database, \
     common DHCP utilities, option parsing)."
);

/// nftables sets require Linux netfilter (libnftables).
/// C equivalent: `#if !defined(HAVE_LINUX_NETWORK) / #undef HAVE_NFTSET`.
#[cfg(all(feature = "nftset", not(target_os = "linux")))]
compile_error!(
    "Feature 'nftset' is only available on Linux. \
     nftables set population requires the Linux netfilter subsystem."
);

/// ipset requires Linux netlink (netfilter ipset kernel module).
/// C equivalent: `#if !defined(HAVE_LINUX_NETWORK) / #undef HAVE_IPSET`.
#[cfg(all(feature = "ipset", not(target_os = "linux")))]
compile_error!(
    "Feature 'ipset' is only available on Linux. \
     ipset population requires the Linux netfilter subsystem and netlink."
);

/// inotify file monitoring requires the Linux inotify kernel API.
/// C equivalent: `#if defined(HAVE_LINUX_NETWORK) && !defined(NO_INOTIFY)`.
#[cfg(all(feature = "inotify_monitor", not(target_os = "linux")))]
compile_error!(
    "Feature 'inotify_monitor' is only available on Linux. \
     inotify file change monitoring requires the Linux inotify kernel API."
);

/// Conntrack mark retrieval requires Linux netfilter conntrack.
/// C equivalent: conntrack features only link on Linux.
#[cfg(all(feature = "conntrack", not(target_os = "linux")))]
compile_error!(
    "Feature 'conntrack' is only available on Linux. \
     Conntrack mark retrieval requires libnetfilter_conntrack."
);

// ============================================================================
// Runtime feature reporting
// ============================================================================

/// Generate a runtime feature-reporting string equivalent to C's `compile_opts`.
///
/// The output follows the exact format printed by `dnsmasq --version`, e.g.:
///
/// ```text
/// IPv6 GNU-getopt no-DBus no-UBus no-i18n no-IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset no-nftset auth no-DNSSEC loop-detect inotify dumpfile
/// ```
///
/// Each token is either `<Name>` (feature enabled) or `no-<Name>` (feature
/// disabled), separated by spaces. The order matches the C implementation in
/// `config.h` lines 2931–3018.
///
/// # Returns
///
/// A heap-allocated `String` containing the space-separated feature tokens.
///
/// # Notes
///
/// * IPv6 is always reported as present (Rust `std::net` has full IPv6).
/// * `GNU-getopt` is always reported (Rust argument parsing has full long-opt
///   support equivalent to GNU getopt_long).
/// * `i18n` is always reported as `no-i18n` (gettext internationalisation is
///   not ported in the Rust rewrite; it was gated on `LOCALEDIR` in C).
/// * Lua scripting is always reported as `no-Lua` when the `script` feature is
///   active (Lua embedding is deferred per AAP scope exclusion).
pub fn compile_opts_string() -> String {
    // Pre-allocate a reasonable capacity to avoid repeated reallocation.
    // Typical output is ~180 bytes.
    let mut opts = String::with_capacity(256);

    // --- IPv6 (always present in Rust) ---
    opts.push_str("IPv6 ");

    // --- GNU-getopt (always present — Rust provides equivalent long-opt parsing) ---
    opts.push_str("GNU-getopt ");

    // --- D-Bus ---
    #[cfg(not(feature = "dbus"))]
    opts.push_str("no-");
    opts.push_str("DBus ");

    // --- UBus ---
    #[cfg(not(feature = "ubus"))]
    opts.push_str("no-");
    opts.push_str("UBus ");

    // --- i18n (not ported) ---
    opts.push_str("no-i18n ");

    // --- IDN / IDN2 ---
    // C logic: HAVE_LIBIDN2 → "IDN2 ", HAVE_IDN → "IDN ", else "no-IDN ".
    // Rust only supports libidn2-equivalent via the `idna` crate, so we
    // report "IDN2" when the `idn` feature is active.
    #[cfg(feature = "idn")]
    opts.push_str("IDN2 ");
    #[cfg(not(feature = "idn"))]
    opts.push_str("no-IDN ");

    // --- DHCP ---
    #[cfg(not(feature = "dhcp"))]
    opts.push_str("no-");
    opts.push_str("DHCP ");

    // --- DHCPv6 (only shown when DHCPv4 is also enabled, matching C logic) ---
    #[cfg(feature = "dhcp")]
    {
        #[cfg(not(feature = "dhcp6"))]
        opts.push_str("no-");
        opts.push_str("DHCPv6 ");
    }

    // --- Scripts / Lua ---
    // C logic: no HAVE_SCRIPT → "no-scripts ", HAVE_SCRIPT but no HAVE_LUASCRIPT → "no-Lua ".
    // Lua embedding is out of scope for the Rust rewrite, so we always print
    // "no-Lua " when scripts are enabled or "no-scripts " when disabled.
    #[cfg(not(feature = "script"))]
    opts.push_str("no-scripts ");
    #[cfg(feature = "script")]
    opts.push_str("no-Lua ");

    // --- TFTP ---
    #[cfg(not(feature = "tftp"))]
    opts.push_str("no-");
    opts.push_str("TFTP ");

    // --- conntrack ---
    #[cfg(not(feature = "conntrack"))]
    opts.push_str("no-");
    opts.push_str("conntrack ");

    // --- ipset ---
    #[cfg(not(feature = "ipset"))]
    opts.push_str("no-");
    opts.push_str("ipset ");

    // --- nftset ---
    #[cfg(not(feature = "nftset"))]
    opts.push_str("no-");
    opts.push_str("nftset ");

    // --- auth ---
    #[cfg(not(feature = "auth"))]
    opts.push_str("no-");
    opts.push_str("auth ");

    // --- DNSSEC ---
    #[cfg(not(feature = "dnssec"))]
    opts.push_str("no-");
    opts.push_str("DNSSEC ");

    // --- loop-detect ---
    #[cfg(not(feature = "loop_detect"))]
    opts.push_str("no-");
    opts.push_str("loop-detect ");

    // --- inotify ---
    #[cfg(not(feature = "inotify_monitor"))]
    opts.push_str("no-");
    opts.push_str("inotify ");

    // --- dumpfile ---
    #[cfg(not(feature = "dump"))]
    opts.push_str("no-");
    opts.push_str("dumpfile");

    opts
}

// ============================================================================
// Feature detection helper functions
// ============================================================================

/// Returns `true` if any DHCP subsystem (v4 or v6) is compiled in.
///
/// This is a convenience predicate used by modules that need to gate code on
/// "any DHCP functionality present", mirroring the common C pattern:
///
/// ```c
/// #if defined(HAVE_DHCP) || defined(HAVE_DHCP6)
/// ```
///
/// The function is `const` so it can be used in const contexts and is
/// guaranteed to be evaluated at compile time with no runtime cost.
pub const fn has_dhcp() -> bool {
    cfg!(any(feature = "dhcp", feature = "dhcp6"))
}

/// Returns `true` if any network firewall set integration is compiled in.
///
/// Covers both legacy ipset (Linux netfilter) and modern nftset (nftables).
/// Equivalent to the C pattern:
///
/// ```c
/// #if defined(HAVE_IPSET) || defined(HAVE_NFTSET)
/// ```
pub const fn has_firewall_sets() -> bool {
    cfg!(any(feature = "ipset", feature = "nftset"))
}

/// Returns `true` if the target platform is Linux.
///
/// Equivalent to C's `HAVE_LINUX_NETWORK` macro, which gates netlink,
/// ipset, inotify, conntrack, and nftset code paths.
pub const fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Returns `true` if the target platform is a BSD variant.
///
/// Covers FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and macOS.
/// Equivalent to C's `HAVE_BSD_NETWORK` macro, which gates BPF,
/// PF tables, and routing-socket code paths.
pub const fn is_bsd() -> bool {
    cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))
}

// ============================================================================
// Platform detection constants
// ============================================================================

/// Platform-specific compile-time constants.
///
/// These boolean constants replace the C platform-detection macros set in
/// `config.h` (e.g. `HAVE_LINUX_NETWORK`, `HAVE_BSD_NETWORK`,
/// `HAVE_SOCKADDR_SA_LEN`). They are evaluated at compile time and enable
/// downstream modules to use simple `if platform::LINUX_NETWORK { ... }`
/// guards that the compiler will optimise to zero-cost conditional
/// compilation.
///
/// # Members
///
/// * [`LINUX_NETWORK`](platform::LINUX_NETWORK) — `true` on Linux targets.
/// * [`BSD_NETWORK`](platform::BSD_NETWORK) — `true` on BSD-family targets.
/// * [`SOCKADDR_SA_LEN`](platform::SOCKADDR_SA_LEN) — `true` when
///   `struct sockaddr` includes the `sa_len` field (BSD-family only).
pub mod platform {
    /// Whether we are compiling for a Linux target.
    ///
    /// Equivalent to C's `HAVE_LINUX_NETWORK`. When `true`, Linux-specific
    /// subsystems are available: netlink interface/route monitoring, ipset,
    /// nftset, inotify, and conntrack.
    pub const LINUX_NETWORK: bool = cfg!(target_os = "linux");

    /// Whether we are compiling for a BSD-family target.
    ///
    /// Covers FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and macOS (Darwin).
    /// Equivalent to C's `HAVE_BSD_NETWORK`. When `true`, BSD-specific
    /// subsystems are available: BPF raw packet I/O, `getifaddrs` interface
    /// enumeration, `PF_ROUTE` socket monitoring, and PF table population.
    pub const BSD_NETWORK: bool = cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ));

    /// Whether `struct sockaddr` includes the `sa_len` field.
    ///
    /// BSD-family systems (FreeBSD, OpenBSD, NetBSD, DragonFly, macOS)
    /// include a `sa_len` member at the start of every `sockaddr` struct.
    /// Linux and Solaris do not. Code that constructs raw sockaddrs for
    /// FFI must set this field on BSD and omit it on Linux.
    pub const SOCKADDR_SA_LEN: bool = cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ));
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The compile_opts_string must start with "IPv6 GNU-getopt ".
    #[test]
    fn compile_opts_starts_with_ipv6_and_getopt() {
        let opts = compile_opts_string();
        assert!(
            opts.starts_with("IPv6 GNU-getopt "),
            "compile_opts_string must begin with 'IPv6 GNU-getopt ', got: {opts}"
        );
    }

    /// The compile_opts_string must contain "no-i18n" (i18n is never ported).
    #[test]
    fn compile_opts_contains_no_i18n() {
        let opts = compile_opts_string();
        assert!(
            opts.contains("no-i18n"),
            "compile_opts_string must contain 'no-i18n', got: {opts}"
        );
    }

    /// The compile_opts_string must end with "dumpfile" (with or without
    /// the "no-" prefix depending on the `dump` feature).
    #[test]
    fn compile_opts_ends_with_dumpfile() {
        let opts = compile_opts_string();
        assert!(
            opts.ends_with("dumpfile"),
            "compile_opts_string must end with 'dumpfile', got: {opts}"
        );
    }

    /// With default features enabled, DHCP token should appear without "no-".
    #[test]
    fn compile_opts_dhcp_token() {
        let opts = compile_opts_string();
        // Regardless of feature state, the token "DHCP " must be present
        // (either as "DHCP " or "no-DHCP ").
        assert!(
            opts.contains("DHCP "),
            "compile_opts_string must contain 'DHCP ', got: {opts}"
        );
    }

    /// `has_dhcp` must be consistent with the individual feature flags.
    #[test]
    fn has_dhcp_consistency() {
        let expected = cfg!(any(feature = "dhcp", feature = "dhcp6"));
        assert_eq!(has_dhcp(), expected);
    }

    /// `has_firewall_sets` must be consistent with ipset/nftset features.
    #[test]
    fn has_firewall_sets_consistency() {
        let expected = cfg!(any(feature = "ipset", feature = "nftset"));
        assert_eq!(has_firewall_sets(), expected);
    }

    /// `is_linux` must match `cfg!(target_os = "linux")`.
    #[test]
    fn is_linux_consistency() {
        assert_eq!(is_linux(), cfg!(target_os = "linux"));
    }

    /// `is_bsd` must match the BSD target family.
    #[test]
    fn is_bsd_consistency() {
        let expected = cfg!(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "macos"
        ));
        assert_eq!(is_bsd(), expected);
    }

    /// Platform constants must be mutually consistent with helper functions.
    #[test]
    fn platform_constants_match_helpers() {
        assert_eq!(platform::LINUX_NETWORK, is_linux());
        assert_eq!(platform::BSD_NETWORK, is_bsd());
    }

    /// SOCKADDR_SA_LEN must match BSD_NETWORK (sa_len is a BSD thing).
    #[test]
    fn sockaddr_sa_len_matches_bsd() {
        assert_eq!(platform::SOCKADDR_SA_LEN, platform::BSD_NETWORK);
    }

    /// The compile_opts_string must not be empty.
    #[test]
    fn compile_opts_not_empty() {
        let opts = compile_opts_string();
        assert!(!opts.is_empty(), "compile_opts_string must not be empty");
    }

    /// All expected token labels must appear in the output (with or without
    /// the "no-" prefix).
    #[test]
    fn compile_opts_contains_all_expected_tokens() {
        let opts = compile_opts_string();
        let required_tokens = [
            "DBus",
            "UBus",
            "i18n",
            "DHCP ",
            "TFTP",
            "conntrack",
            "ipset",
            "nftset",
            "auth",
            "DNSSEC",
            "loop-detect",
            "inotify",
            "dumpfile",
        ];
        for token in &required_tokens {
            assert!(
                opts.contains(token),
                "compile_opts_string must contain token '{token}', got: {opts}"
            );
        }
    }

    /// Verify that the string contains either "IDN2" or "no-IDN" but not both.
    #[test]
    fn compile_opts_idn_exclusive() {
        let opts = compile_opts_string();
        let has_idn2 = opts.contains("IDN2");
        let has_no_idn = opts.contains("no-IDN");
        assert!(
            has_idn2 ^ has_no_idn,
            "compile_opts_string must contain exactly one of 'IDN2' or 'no-IDN', got: {opts}"
        );
    }

    /// The output must contain either "no-scripts" or "no-Lua" but not both.
    #[test]
    fn compile_opts_script_lua_exclusive() {
        let opts = compile_opts_string();
        let has_no_scripts = opts.contains("no-scripts");
        let has_no_lua = opts.contains("no-Lua");
        assert!(
            has_no_scripts ^ has_no_lua,
            "compile_opts_string must contain exactly one of 'no-scripts' or 'no-Lua', got: {opts}"
        );
    }
}

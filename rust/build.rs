//! Build script for dnsmasq Rust implementation.
//!
//! Performs platform detection and emits `cargo:rustc-cfg` directives
//! that drive conditional compilation across the codebase, mirroring
//! the C `#ifdef HAVE_*` / `#ifdef __linux__` system from config.h.
//!
//! Feature flag mapping from C HAVE_* macros to Cargo features:
//! - HAVE_DHCP        → cfg(feature = "dhcp")       — Default enabled
//! - HAVE_DHCP6       → cfg(feature = "dhcp6")      — Default enabled, implies dhcp
//! - HAVE_TFTP        → cfg(feature = "tftp")       — Default enabled
//! - HAVE_SCRIPT      → cfg(feature = "script")     — Default enabled
//! - HAVE_AUTH        → cfg(feature = "auth")        — Default enabled
//! - HAVE_IPSET       → cfg(feature = "ipset")      — Default enabled
//! - HAVE_LOOP        → cfg(feature = "loop-detect") — Default enabled
//! - HAVE_DUMPFILE    → cfg(feature = "dumpfile")   — Default enabled
//! - HAVE_DNSSEC      → cfg(feature = "dnssec")     — Disabled by default
//! - HAVE_DBUS        → cfg(feature = "dbus")       — Disabled by default
//! - HAVE_UBUS        → cfg(feature = "ubus")       — Disabled by default
//! - HAVE_IDN         → cfg(feature = "idn")        — Disabled by default
//! - HAVE_CONNTRACK   → cfg(feature = "conntrack")  — Disabled by default
//! - HAVE_NFTSET      → cfg(feature = "nftset")     — Disabled by default
//! - HAVE_LUASCRIPT   → cfg(feature = "luascript")  — Disabled by default
//! - HAVE_INOTIFY     → auto-detected on Linux via build.rs
//! - HAVE_LINUX_NETWORK → cfg(linux_network) via build.rs
//! - HAVE_BSD_NETWORK   → cfg(bsd_network) via build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Platform-specific network stack detection
    // Maps C's: #if defined(__linux__)... HAVE_LINUX_NETWORK
    //           #elif defined(__FreeBSD__)... HAVE_BSD_NETWORK
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-cfg=linux_network");
            println!("cargo:rustc-cfg=have_inotify");
        }
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" => {
            println!("cargo:rustc-cfg=bsd_network");
        }
        "macos" => {
            println!("cargo:rustc-cfg=bsd_network");
        }
        "solaris" | "illumos" => {
            println!("cargo:rustc-cfg=solaris_network");
        }
        _ => {}
    }

    // Detect Android (subset of Linux with different defaults)
    // Maps C's: #ifdef __ANDROID__
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "linux" && target_env == "android" {
        println!("cargo:rustc-cfg=android");
    }

    // Emit version info
    println!("cargo:rustc-env=DNSMASQ_VERSION=2.92-rust");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DNSMASQ_COPTS");
}

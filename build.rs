// build.rs — Platform detection and optional native library linking
// This build script replaces the platform detection logic from the C Makefile.

fn main() {
    // Rerun if build script changes
    println!("cargo:rerun-if-changed=build.rs");

    // Platform detection
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // Emit platform-specific cfg
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-cfg=target_platform_linux");
        }
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" => {
            println!("cargo:rustc-cfg=target_platform_bsd");
        }
        "macos" => {
            println!("cargo:rustc-cfg=target_platform_bsd");
        }
        _ => {}
    }

    // Emit architecture-specific cfg
    println!("cargo:rustc-cfg=target_architecture_{}", target_arch);

    // Version information
    if let Ok(version) = std::fs::read_to_string("VERSION") {
        let version = version.trim();
        if !version.contains("Format") {
            println!("cargo:rustc-env=DNSMASQ_VERSION={}", version);
        } else {
            println!("cargo:rustc-env=DNSMASQ_VERSION=2.92");
        }
    } else {
        println!("cargo:rustc-env=DNSMASQ_VERSION=2.92");
    }

    // Feature-gated native library detection

    // D-Bus library detection
    #[cfg(feature = "dbus")]
    {
        if let Err(e) = pkg_config::probe_library("dbus-1") {
            eprintln!("Warning: D-Bus feature enabled but libdbus-1 not found: {}", e);
        }
    }

    // nftables library detection (Linux only)
    #[cfg(all(feature = "nftset", target_os = "linux"))]
    {
        if let Err(e) = pkg_config::probe_library("libnftables") {
            eprintln!("Warning: nftset feature enabled but libnftables not found: {}", e);
        }
    }

    // conntrack library detection (Linux only)
    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    {
        if let Err(e) = pkg_config::probe_library("libnetfilter_conntrack") {
            eprintln!("Warning: conntrack feature enabled but libnetfilter_conntrack not found: {}", e);
        }
    }
}

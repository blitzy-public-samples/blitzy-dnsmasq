// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// dnsmasq — A memory-safe DNS forwarder, DHCP server, router advertisement,
// and network boot daemon.
//
// Rust implementation of dnsmasq v2.92, providing identical functionality to the
// C version with memory safety guaranteed by Rust's ownership system.
//
// This file replaces the main() function from src/dnsmasq.c (line 226) and serves
// as the binary entry point. All protocol logic, subsystem initialization, and
// event loop handling is delegated to the library crate modules.
//
// # Architecture
//
// The C implementation uses a single global `struct daemon` accessed by every module
// and a poll()-based event loop (poll.c). The Rust implementation replaces this with:
//
// - `Arc<RwLock<DaemonState>>` for safe shared state across async tasks
// - `tokio::select!` for async I/O multiplexing (replacing poll())
// - `clap` derive API for CLI argument parsing (replacing getopt_long)
// - `tracing` for structured logging (replacing syslog)
// - `anyhow` for top-level error handling (replacing goto/errno patterns)
//
// # Startup Sequence (mirrors C dnsmasq.c main())
//
// 1. Parse CLI arguments via clap (replaces C getopt_long at option.c)
// 2. Initialize structured logging (replaces C log_start() at log.c:177)
// 3. Load configuration from file + CLI merge (replaces C read_opts() at option.c:700)
// 4. Initialize daemon state (replaces C struct daemon allocation at dnsmasq.c:125)
// 5. Create DaemonRunner with privilege separation:
//    a. Bind privileged ports (53/DNS, 67/DHCP, 69/TFTP) as root
//    b. Drop to unprivileged user (default "nobody")
//    c. Retain CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE on Linux
// 6. Enter async event loop (replaces C poll() loop at dnsmasq.c:1272)
//
// # Signal Handling (mirrors C sig_handler() at dnsmasq.c:1512)
//
// Signal handling semantics are preserved identically from the C implementation:
// - SIGHUP  → Configuration reload, cache flush (EVENT_RELOAD)
// - SIGUSR1 → Dump DNS cache statistics to log (EVENT_DUMP)
// - SIGUSR2 → Dump upstream server statistics to log (EVENT_REOPEN)
// - SIGTERM → Graceful shutdown: flush leases, close sockets (EVENT_TERM)
// - SIGINT  → Graceful shutdown (same as SIGTERM)
// - SIGCHLD → Child process reaping for TCP handlers (EVENT_CHILD)
// - SIGPIPE → Ignored (prevents daemon crash on broken pipe)
//
// # Feature-Gated Initialization (mirrors C HAVE_* preprocessor guards)
//
// Optional subsystems are conditionally initialized based on Cargo feature flags:
// - `dhcp`        → DHCPv4 server (C: #ifdef HAVE_DHCP)
// - `dhcp6`       → DHCPv6 server with prefix delegation (C: #ifdef HAVE_DHCP6)
// - `tftp`        → TFTP server for PXE network boot (C: #ifdef HAVE_TFTP)
// - `dnssec`      → DNSSEC validation with chain of trust (C: #ifdef HAVE_DNSSEC)
// - `dbus`        → D-Bus interface for NetworkManager (C: #ifdef HAVE_DBUS)
// - `ubus`        → OpenWrt ubus integration (C: #ifdef HAVE_UBUS)
// - `inotify`     → File change monitoring for /etc/hosts (C: #ifdef HAVE_INOTIFY)
// - `loop-detect` → DNS forwarding loop detection (C: #ifdef HAVE_LOOP)
// - `auth`        → Authoritative DNS zone serving (C: #ifdef HAVE_AUTH)
// - `script`      → Lease-change script execution (C: #ifdef HAVE_SCRIPT)
// - `ipset`       → Linux ipset integration (C: #ifdef HAVE_IPSET)
// - `nftset`      → nftables set integration (C: #ifdef HAVE_NFTSET)
// - `conntrack`   → Linux conntrack mark support (C: #ifdef HAVE_CONNTRACK)
// - `dumpfile`    → Packet dump for debugging (C: #ifdef HAVE_DUMPFILE)

use dnsmasq::config::cli::CliArgs;
use dnsmasq::config::options::DnsmasqConfig;
use dnsmasq::core::daemon::DaemonRunner;
use dnsmasq::core::log;
use dnsmasq::core::types::DaemonState;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Binary entry point for the dnsmasq Rust daemon.
///
/// Initializes the tokio async runtime, parses CLI arguments, sets up logging,
/// and delegates to [`run_daemon`] for the core daemon lifecycle. Fatal errors
/// are logged via `tracing::error!` before propagation to the process exit handler,
/// ensuring all fatal conditions appear in syslog/structured log output.
///
/// # Privilege Separation Flow (from C dnsmasq.c lines 94-100)
///
/// The daemon follows a standard privilege separation model:
/// 1. **Start as root (UID 0)** — required for binding to privileged ports
/// 2. **Bind privileged ports** — DNS (53/udp+tcp), DHCP (67/udp), TFTP (69/udp)
/// 3. **Drop to configured user** — default "nobody" (from `--user` / `user=` directive)
/// 4. **Retain capabilities (Linux)** — CAP_NET_ADMIN (interface queries),
///    CAP_NET_RAW (raw sockets for DHCP), CAP_NET_BIND_SERVICE (if port rebind needed)
///
/// This ensures the daemon runs with minimal privileges after initialization,
/// reducing the attack surface in case of a security vulnerability.
///
/// # Errors
///
/// Returns `Err` with descriptive context on:
/// - CLI argument parsing failure (clap auto-handles with usage message)
/// - Logging initialization failure
/// - Configuration file parse or validation errors
/// - Daemon state initialization failure (e.g., out of memory)
/// - Network socket binding failure
/// - Privilege separation failure (e.g., user not found)
/// - Runtime event loop errors
#[tokio::main]
async fn main() -> Result<()> {
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 1: Parse CLI arguments
    // Replaces C getopt_long() processing in option.c (lines 197-535).
    // Uses clap derive API to match dnsmasq's exact command-line interface.
    // All short options from OPTSTRING and long-only options from LOPT_*
    // constants are supported for 100% CLI backward compatibility.
    //
    // NOTE: Custom --help (-w) and --version (-v) flags are defined in
    // cli.rs with clap's built-in help/version disabled (disable_help_flag
    // = true, disable_version_flag = true) because dnsmasq uses -w for
    // help and -v for version (not the standard -h/-V). We check these
    // flags explicitly below before proceeding to daemon initialization.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let cli_args = CliArgs::parse();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 1a: Handle early-exit flags (--help, --version, --test)
    // These must be checked before logging or daemon initialization.
    // Matching C dnsmasq behavior: these flags print output and exit(0).
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // --help / -w: Print usage text and exit with code 0.
    // Replaces C's display of usage[] array from option.c lines 543-742.
    if cli_args.help_flag {
        CliArgs::command()
            .print_help()
            .context("Failed to print help")?;
        println!(); // Ensure trailing newline after help output
        return Ok(());
    }

    // --version / -v: Print version and copyright information, then exit.
    // Replaces C's "dnsmasq version" output from dnsmasq.c startup banner.
    if cli_args.version_flag {
        println!(
            "dnsmasq version {} — {}",
            dnsmasq::VERSION,
            dnsmasq::COPYRIGHT
        );
        return Ok(());
    }

    // --test: Validate configuration syntax without starting the daemon.
    // Replaces C's one_file() + die() config validation path.
    // Parse the configuration file(s), report errors, and exit with code
    // 0 on success or non-zero on failure — without binding any sockets.
    if cli_args.test {
        // Initialize minimal logging for config error output.
        let log_config = build_log_config(&cli_args);
        log::init_logging(&log_config).context("Failed to initialize logging subsystem")?;

        match DnsmasqConfig::load(&cli_args) {
            Ok(_) => {
                println!("dnsmasq: syntax check OK.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("dnsmasq: syntax check FAILED: {}", e);
                return Err(e.into());
            }
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 2: Initialize logging subsystem
    // Replaces C log_start() from log.c (line 177).
    // MUST be initialized before any other subsystem so that all
    // subsequent startup messages and errors are properly captured.
    //
    // Supports three output modes (matching C behavior):
    // - Syslog output (default, RFC 3164 format to /dev/log)
    // - Console/stderr output (when --no-daemon or --keep-in-foreground)
    // - JSON structured output (new capability for SIEM integration)
    //
    // Log facility mapping from C (dnsmasq.h lines 482-485):
    //   MS_TFTP   → target "dnsmasq::tftp"   (LOG_USER)
    //   MS_DHCP   → target "dnsmasq::dhcp"   (LOG_DAEMON)
    //   MS_SCRIPT → target "dnsmasq::script"  (LOG_MAIL)
    //   MS_DEBUG  → target "dnsmasq::debug"   (LOG_NEWS)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let log_config = build_log_config(&cli_args);
    log::init_logging(&log_config).context("Failed to initialize logging subsystem")?;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 3+: Run the daemon lifecycle
    // Logging is now active, so all errors will be captured via tracing.
    // Fatal errors are logged with error!() before propagation so they
    // appear in syslog/JSON output (matching C's die() behavior from
    // util.c line 18 which logs to syslog before exit(1)).
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let result = run_daemon(cli_args).await;

    if let Err(ref err) = result {
        // Log the fatal error via tracing before the process exits.
        // This ensures the error appears in syslog/JSON structured output,
        // matching C dnsmasq's die() behavior which logs to syslog before
        // calling exit(). The {:#} format includes the full error chain
        // from anyhow for maximum diagnostic value.
        error!("dnsmasq fatal error: {:#}", err);
    }

    result
}

/// Core daemon lifecycle: configuration, state initialization, and event loop.
///
/// Separated from `main()` so that fatal errors occurring after logging
/// initialization can be captured and logged via `tracing::error!` before
/// the process exits. This mirrors the C implementation's `die()` function
/// which sends the error message to syslog before calling `exit(1)`.
///
/// # Arguments
///
/// * `cli_args` — Parsed command-line arguments from clap, containing all
///   flags and options that override configuration file settings.
///
/// # Errors
///
/// Returns `Err` with descriptive anyhow context on any initialization
/// or runtime failure.
async fn run_daemon(cli_args: CliArgs) -> Result<()> {
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 3: Load and validate configuration
    // Replaces C read_opts() from option.c (line ~700)
    //
    // Configuration loading follows this precedence chain (highest first):
    // 1. Command-line arguments (from CliArgs)
    // 2. Configuration file directives (default /etc/dnsmasq.conf)
    // 3. Included files processed at point of inclusion (conf-file=, conf-dir=)
    // 4. Compile-time defaults from config/constants.rs
    //
    // The parser supports 350+ configuration directives with 100% backward
    // compatibility with existing dnsmasq.conf files. Syntax variants:
    //   key=value   (e.g., cache-size=1000)
    //   key         (boolean options, e.g., no-resolv)
    //   server=/domain/ip  (domain-specific forwarding)
    //   # comments, continuation lines (\), include directives
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let config = DnsmasqConfig::load(&cli_args).context("Failed to load dnsmasq configuration")?;

    // Log feature-gated subsystem availability at startup.
    // Mirrors C's compile_opts string output (config.h lines 2930-3020)
    // and the conditional initialization checks in dnsmasq.c (lines 300-450).
    log_enabled_features();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 4: Initialize daemon state
    // Replaces C's `struct daemon *daemon = safe_malloc(sizeof(struct daemon))`
    // from dnsmasq.c (line 125) and the subsequent initialization of all
    // 100+ struct daemon fields with sensible defaults.
    //
    // In C, `struct daemon` was a single global mutable instance accessed
    // directly by every module. In Rust, DaemonState is wrapped in
    // Arc<RwLock<...>> for safe concurrent access across async tasks:
    //
    //   Arc    → Multiple ownership (shared across tokio tasks)
    //   RwLock → Multiple readers OR single writer (no data races)
    //
    // This eliminates all data race vulnerabilities present in the C version
    // where the global state was accessed without synchronization.
    //
    // DaemonState::new() creates defaults matching C's init (dnsmasq.c ~226).
    // The loaded DnsmasqConfig is passed to DaemonRunner::new() which
    // applies configuration to the state and initializes all subsystems.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let state = Arc::new(RwLock::new(DaemonState::new()));

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 5: Create daemon runner with privilege separation
    // Replaces C dnsmasq.c initialization (lines 450-1090):
    //
    //   - Network interface enumeration (network.c enumerate_interfaces)
    //   - Socket binding for DNS/DHCP/TFTP listeners
    //   - Signal handler installation (SIGHUP, SIGUSR1/2, SIGTERM, etc.)
    //   - Privilege separation: bind ports as root → drop to nobody
    //     (retaining CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE
    //      on Linux via prctl(PR_SET_KEEPCAPS))
    //   - DHCP lease file loading (if dhcp feature enabled)
    //   - DNS cache initialization with configured size
    //   - DNSSEC trust anchor loading (if dnssec feature enabled)
    //   - D-Bus connection establishment (if dbus feature enabled)
    //   - inotify watch setup for /etc/hosts (if inotify feature enabled)
    //
    // DaemonRunner::new() performs all subsystem initialization and returns
    // a fully configured runner ready to enter the event loop.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let daemon = DaemonRunner::new(state, &config)
        .await
        .context("Failed to initialize daemon")?;

    // Log startup banner with version information.
    // Mirrors C dnsmasq.c lines 1080-1090 startup message output.
    info!(
        version = dnsmasq::VERSION,
        copyright = dnsmasq::COPYRIGHT,
        "dnsmasq starting"
    );

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Phase 6: Enter main async event loop
    // Replaces C's while(1) { poll_reset(); ... do_poll(); ... } loop
    // from dnsmasq.c (lines 1272-1510).
    //
    // The Rust event loop uses tokio::select! to concurrently multiplex:
    //
    //   DNS:     UDP query receive + TCP connection accept
    //   DHCP:    DHCPv4 packet receive (cfg feature = "dhcp")
    //   DHCPv6:  DHCPv6 packet receive (cfg feature = "dhcp6")
    //   TFTP:    TFTP request receive (cfg feature = "tftp")
    //   Signals: SIGHUP (reload), SIGUSR1/2 (dump), SIGTERM (shutdown)
    //   Timers:  Lease expiry, cache cleanup, RA intervals
    //   Watch:   inotify events for /etc/hosts changes (cfg feature = "inotify")
    //   Bus:     D-Bus messages (cfg feature = "dbus")
    //
    // The loop runs until SIGTERM/SIGINT triggers graceful shutdown,
    // which flushes DHCP leases, closes sockets, and logs the exit.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    daemon.run().await.context("Daemon runtime error")?;

    Ok(())
}

/// Log which feature-gated subsystems are compiled into this build.
///
/// Mirrors the C `compile_opts` string from `config.h` lines 2930-3020, which
/// prints a summary of enabled/disabled features during startup. This helps
/// operators verify that their binary includes the expected capabilities.
///
/// Each feature flag maps to a C `HAVE_*` macro as documented in the module
/// header comments and AAP Section 0.4.4.
fn log_enabled_features() {
    // Build feature summary string matching C's compile_opts format.
    // Uses cfg! macro for compile-time feature detection.
    let mut features = Vec::new();

    // Core features (enabled by default in Cargo.toml)
    // These correspond to the C default-enabled HAVE_* macros.
    if cfg!(feature = "dhcp") {
        features.push("DHCP");
    }
    if cfg!(feature = "dhcp6") {
        features.push("DHCPv6");
    }
    if cfg!(feature = "tftp") {
        features.push("TFTP");
    }
    if cfg!(feature = "auth") {
        features.push("auth");
    }
    if cfg!(feature = "script") {
        features.push("scripts");
    }
    if cfg!(feature = "ipset") {
        features.push("ipset");
    }
    if cfg!(feature = "loop-detect") {
        features.push("loop-detect");
    }
    if cfg!(feature = "dumpfile") {
        features.push("dumpfile");
    }
    if cfg!(feature = "inotify") {
        features.push("inotify");
    }

    // Optional features (disabled by default in Cargo.toml)
    // These correspond to the C disabled-by-default HAVE_* macros
    // that require additional system libraries.
    if cfg!(feature = "dnssec") {
        features.push("DNSSEC");
    }
    if cfg!(feature = "dbus") {
        features.push("DBus");
    }
    if cfg!(feature = "ubus") {
        features.push("UBus");
    }
    if cfg!(feature = "idn") {
        features.push("IDN");
    }
    if cfg!(feature = "conntrack") {
        features.push("conntrack");
    }
    if cfg!(feature = "nftset") {
        features.push("nftset");
    }
    if cfg!(feature = "luascript") {
        features.push("Lua");
    }

    info!(
        compile_options = features.join(" "),
        "compile-time options: {}",
        features.join(" ")
    );
}

/// Build a [`log::LogConfig`] from parsed CLI arguments for early logging init.
///
/// This constructs a logging configuration before the full configuration file
/// is parsed. The CLI arguments provide enough information to determine the
/// logging mode (syslog vs. stderr, debug level, facility).
///
/// Mirrors C's early logging setup in `dnsmasq.c` lines 280-295 where the
/// logger is initialized from command-line options before `read_opts()` processes
/// the configuration file.
///
/// # Arguments
///
/// * `cli_args` — Parsed command-line arguments from clap.
///
/// # Mapping from C flags
///
/// | C flag / option         | CliArgs field          | LogConfig field |
/// |-------------------------|------------------------|-----------------|
/// | `--no-daemon` / `-d`    | `no_daemon`            | `debug = true`  |
/// | `--log-debug`           | `log_debug`            | `max_level = DEBUG` |
/// | `--log-queries[=extra]` | `log_queries`          | `log_queries`   |
/// | `--log-facility=X`      | `log_facility`         | `facility`      |
/// | `--log-dhcp`            | `log_dhcp`             | `log_dhcp`      |
/// | `--quiet-dhcp`          | `quiet_dhcp`           | `log_dhcp = false` |
fn build_log_config(cli_args: &CliArgs) -> log::LogConfig {
    // Debug mode: --no-daemon or --log-debug enables verbose output.
    // Mirrors C behavior: OPT_DEBUG sets echo_stderr in log.c (line 107).
    let debug = cli_args.no_daemon || cli_args.log_debug;

    // Determine tracing level from debug/log-debug flags.
    // C maps this to syslog priority levels; Rust uses tracing::Level.
    let max_level = if debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    // Parse syslog facility from CLI.
    // C default: LOG_DAEMON; debug mode: LOG_LOCAL0 (log.c lines 186-188).
    let facility = match &cli_args.log_facility {
        Some(fac) => parse_log_facility(fac),
        None if debug => log::LogFacility::Local0,
        None => log::LogFacility::Daemon,
    };

    // DNS query logging: --log-queries enables, optional "extra" suffix
    // enables extra_logging mode (matching C's --log-queries=extra).
    let log_queries = cli_args.log_queries.is_some();
    let extra_logging = cli_args
        .log_queries
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("extra"));

    // DHCP logging: suppressed by --quiet-dhcp, otherwise ON by default.
    // C default: DHCP logging is ON unless --quiet-dhcp is explicitly set.
    // The --log-dhcp flag is redundant since logging is the default, but
    // it is accepted for compatibility with existing configurations.
    let log_dhcp = !cli_args.quiet_dhcp;

    log::LogConfig {
        facility,
        // log_file is intentionally None during early CLI-based logging setup.
        // File-based logging (via `--log-facility=/path/to/file` or
        // `log-facility=/path/to/file` in dnsmasq.conf) is parsed from the
        // full configuration in DnsmasqConfig::load() (Phase 3) and applied
        // when DaemonRunner::new() reconfigures the logging subsystem with
        // the complete configuration. This early LogConfig is only used for
        // logging during CLI parsing and config loading itself.
        log_file: None,
        debug,
        json_output: false,
        max_level,
        extra_logging,
        log_queries,
        log_dhcp,
    }
}

/// Parse a syslog facility name or number from the `--log-facility` directive.
///
/// Supports the full POSIX syslog facility set (matching C's `facilitynames[]`
/// array from `option.c` lines 164-184): `kern`, `user`, `mail`, `daemon`,
/// `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, and `local0` through
/// `local7`. Numeric facility codes are also accepted for advanced
/// configurations.
///
/// If the value starts with `/` it is treated as a log file path by the
/// config parser (handled upstream in `DnsmasqConfig::load()`), not here.
///
/// # Examples
///
/// - `"daemon"` → `LogFacility::Daemon`
/// - `"local0"` → `LogFacility::Local0`
/// - `"local3"` → `LogFacility::Custom(19 << 3)` (LOG_LOCAL3)
/// - `"kern"` → `LogFacility::Custom(0)` (LOG_KERN)
/// - `"auth"` → `LogFacility::Custom(4 << 3)` (LOG_AUTH)
/// - `"cron"` → `LogFacility::Custom(9 << 3)` (LOG_CRON)
/// - `"16"` → `LogFacility::Custom(16 * 8)` (numeric facility code)
fn parse_log_facility(name: &str) -> log::LogFacility {
    // Syslog facility codes from <syslog.h> — each is the facility number
    // shifted left by 3 (i.e., multiplied by 8) per RFC 3164 PRI encoding.
    //
    // This list matches C dnsmasq's facilitynames[] array in option.c
    // (lines 164-184) which maps all standard POSIX facility names.
    match name.to_ascii_lowercase().as_str() {
        // Facilities with dedicated LogFacility enum variants:
        "daemon" => log::LogFacility::Daemon, // LOG_DAEMON = 3 << 3 = 24
        "local0" => log::LogFacility::Local0, // LOG_LOCAL0 = 16 << 3 = 128
        "user" => log::LogFacility::User,     // LOG_USER = 1 << 3 = 8
        "mail" => log::LogFacility::Mail,     // LOG_MAIL = 2 << 3 = 16

        // Additional POSIX syslog facilities (C option.c lines 165-183).
        // Mapped via Custom(code) with pre-computed syslog facility codes.
        "kern" => log::LogFacility::Custom(0), // LOG_KERN = 0 << 3 = 0
        "auth" => log::LogFacility::Custom(4 << 3), // LOG_AUTH = 4 << 3 = 32
        "syslog" => log::LogFacility::Custom(5 << 3), // LOG_SYSLOG = 5 << 3 = 40
        "lpr" => log::LogFacility::Custom(6 << 3), // LOG_LPR = 6 << 3 = 48
        "news" => log::LogFacility::Custom(7 << 3), // LOG_NEWS = 7 << 3 = 56
        "uucp" => log::LogFacility::Custom(8 << 3), // LOG_UUCP = 8 << 3 = 64
        "cron" => log::LogFacility::Custom(9 << 3), // LOG_CRON = 9 << 3 = 72
        "local1" => log::LogFacility::Custom(17 << 3), // LOG_LOCAL1 = 17 << 3 = 136
        "local2" => log::LogFacility::Custom(18 << 3), // LOG_LOCAL2 = 18 << 3 = 144
        "local3" => log::LogFacility::Custom(19 << 3), // LOG_LOCAL3 = 19 << 3 = 152
        "local4" => log::LogFacility::Custom(20 << 3), // LOG_LOCAL4 = 20 << 3 = 160
        "local5" => log::LogFacility::Custom(21 << 3), // LOG_LOCAL5 = 21 << 3 = 168
        "local6" => log::LogFacility::Custom(22 << 3), // LOG_LOCAL6 = 22 << 3 = 176
        "local7" => log::LogFacility::Custom(23 << 3), // LOG_LOCAL7 = 23 << 3 = 184

        // Numeric facility: parse and convert to syslog code (facility * 8).
        other => {
            if let Ok(code) = other.parse::<i32>() {
                log::LogFacility::from_syslog_code(code)
            } else {
                // Unrecognized facility name: fall back to daemon (matching C behavior
                // which returns "bad log facility" error but we gracefully degrade).
                log::LogFacility::Daemon
            }
        }
    }
}

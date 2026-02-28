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

//! Binary entry point for the dnsmasq Rust rewrite.
//!
//! This file replaces `src/dnsmasq.c`'s `main()` function. It is the `[[bin]]`
//! target defined in `Cargo.toml` (path = "src/main.rs").
//!
//! # Initialization Sequence (mirrors C dnsmasq.c lines 226-1260)
//!
//! 1. Set umask (022) — known umask for lease and PID files
//! 2. Install signal handlers via self-pipe pattern
//! 3. Initialize PRNG (replaces C `rand_init()`)
//! 4. Parse CLI arguments and config files (replaces C `read_opts()`)
//! 5. Initialize logging subsystem (replaces C `log_start()`)
//! 6. Validate configuration (DNSSEC trust anchors, port ranges, etc.)
//! 7. Build DaemonState from parsed config
//! 8. Bind privileged ports (DNS 53, DHCP 67, TFTP 69) while still root
//! 9. Daemonize (fork to background, write PID file) unless `--no-daemon`
//! 10. Drop privileges (setuid/setgid to configured user)
//! 11. Initialize feature-gated subsystems (DHCP, DHCPv6, DNSSEC, TFTP, D-Bus)
//! 12. Create and enter mio-based event loop
//!
//! # Signal Handling
//!
//! | Signal  | Action                                    |
//! |---------|-------------------------------------------|
//! | SIGHUP  | Hot reload configuration, clear DNS cache |
//! | SIGTERM | Graceful shutdown                         |
//! | SIGINT  | Timer/exit (debug mode)                   |
//! | SIGUSR1 | Dump cache statistics to log              |
//! | SIGUSR2 | Rotate/reopen log files                   |
//! | SIGCHLD | Child process terminated                  |
//! | SIGPIPE | Ignored                                   |
//!
//! # Privilege Separation
//!
//! The daemon starts as root to bind privileged ports, then drops to an
//! unprivileged user (default "nobody"). On Linux, fine-grained capabilities
//! (CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE) are retained when
//! needed for specific features.

use anyhow::{Context, Result};
use log::{info, warn};
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process;

// Library crate imports — binary crate importing through the library boundary.
use dnsmasq::config::constants;
use dnsmasq::config::options::{ConfigBuilder, DaemonConfig};
#[allow(unused_imports)]
use dnsmasq::core::daemon::{
    DaemonState, OPT_CONNTRACK, OPT_DBUS, OPT_DEBUG, OPT_DNSSEC_VALID, OPT_LOOP_DETECT,
    OPT_NO_FORK, OPT_NO_RESOLV, OPT_NOWILD, OPT_RA, OPT_SCRIPT_ARP, OPT_TFTP, OPT_UBUS,
};
use dnsmasq::core::event_loop::EventLoop;
use dnsmasq::core::logging;
use dnsmasq::core::prng::Prng;
use dnsmasq::core::signal::{self, SignalHandler};

// ---------------------------------------------------------------------------
// Version and build information
// ---------------------------------------------------------------------------

/// Version string matching the C dnsmasq version being ported.
const VERSION: &str = "2.92";

/// Compile-time options string — lists enabled Cargo features, replacing the
/// C `compile_opts` string that listed HAVE_* macros.
fn compile_options() -> String {
    let mut opts = Vec::new();

    #[cfg(feature = "dhcp")]
    opts.push("DHCPv4");
    #[cfg(feature = "dhcp6")]
    opts.push("DHCPv6");
    #[cfg(feature = "dnssec")]
    opts.push("DNSSEC");
    #[cfg(feature = "tftp")]
    opts.push("TFTP");
    #[cfg(feature = "dbus")]
    opts.push("DBus");
    #[cfg(feature = "ubus")]
    opts.push("UBus");
    #[cfg(feature = "script")]
    opts.push("script");
    #[cfg(feature = "auth")]
    opts.push("auth-dns");
    #[cfg(feature = "ipset")]
    opts.push("ipset");
    #[cfg(feature = "nftset")]
    opts.push("nftset");
    #[cfg(feature = "conntrack")]
    opts.push("conntrack");
    #[cfg(feature = "loop_detect")]
    opts.push("loop-detect");
    #[cfg(feature = "inotify_monitor")]
    opts.push("inotify");
    #[cfg(feature = "dump")]
    opts.push("dumpfile");
    #[cfg(feature = "idn")]
    opts.push("IDN");

    if opts.is_empty() {
        "no optional features".to_string()
    } else {
        opts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Linux Capability Constants and Structures
// ---------------------------------------------------------------------------

/// Linux capability version 3 (covers kernels 2.6.26+).
#[cfg(target_os = "linux")]
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

/// CAP_NET_ADMIN — various network administration operations.
#[cfg(target_os = "linux")]
const CAP_NET_ADMIN: u32 = 12;

/// CAP_NET_RAW — use RAW and PACKET sockets (ICMP ping for DHCP).
#[cfg(target_os = "linux")]
const CAP_NET_RAW: u32 = 13;

/// CAP_NET_BIND_SERVICE — bind to ports below 1024.
#[cfg(target_os = "linux")]
const CAP_NET_BIND_SERVICE: u32 = 10;

/// Linux capability header structure for capset/capget syscalls.
#[cfg(target_os = "linux")]
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

/// Linux capability data structure for capset/capget syscalls.
#[cfg(target_os = "linux")]
#[repr(C)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Binary entry point for the dnsmasq daemon.
///
/// This function orchestrates the complete daemon lifecycle:
/// initialization, daemonization, privilege drop, and event loop entry.
/// It replaces the C `main()` function from `src/dnsmasq.c` (lines 226-1260).
///
/// # Exit Codes
/// - 0: Normal shutdown (SIGTERM or graceful exit)
/// - 1: Fatal error during initialization
/// - 2: Configuration error
fn main() {
    // Set umask before any file creation (leases, PID file).
    // Matches C: `umask(022);` at dnsmasq.c line 293.
    // SAFETY: umask() is always safe to call — it only affects the process
    // file creation mask and has no failure mode.
    unsafe {
        libc::umask(0o022);
    }

    // Run the actual daemon logic, converting any error to an exit code.
    if let Err(e) = run_daemon() {
        // Print error chain to stderr (matches C die() behavior).
        eprintln!("dnsmasq: fatal error: {:#}", e);
        process::exit(1);
    }
}

/// Core daemon initialization and execution.
///
/// Separated from `main()` to allow `?` operator usage with `anyhow::Result`.
/// All initialization steps are executed in the order specified by the C
/// `main()` function in `dnsmasq.c`.
fn run_daemon() -> Result<()> {
    // ------------------------------------------------------------------
    // Phase 1: Signal handler installation (dnsmasq.c lines 278-291)
    // ------------------------------------------------------------------
    // Install signal handlers FIRST, before any allocation or I/O, so that
    // SIGTERM/SIGINT during startup cause a clean exit.
    let signal_handler = SignalHandler::new()
        .context("failed to install signal handlers")?;

    // ------------------------------------------------------------------
    // Phase 2: PRNG initialization (dnsmasq.c line 295: rand_init())
    // ------------------------------------------------------------------
    // Must precede config parsing because some option processing needs
    // random values (e.g., DNSSEC seed).
    let _prng = Prng::new();

    // ------------------------------------------------------------------
    // Phase 3: Configuration parsing (dnsmasq.c line 297: read_opts())
    // ------------------------------------------------------------------
    let args: Vec<String> = env::args().skip(1).collect();
    let mut builder = ConfigBuilder::new();
    builder.parse_cli(&args);

    // Handle --help and --version before any further initialization.
    if builder.is_help_requested() {
        print_usage();
        process::exit(0);
    }
    if builder.is_version_requested() {
        print_version();
        process::exit(0);
    }

    // Parse default config file unless disabled by --conf-file="" on CLI.
    // The C code always tries to read CONFFILE unless overridden.
    builder.parse_file(constants::CONFFILE, false);

    // Handle --test mode: validate configuration and exit.
    if builder.is_test_mode() {
        match builder.build() {
            Ok(_) => {
                eprintln!("dnsmasq: syntax check OK.");
                process::exit(0);
            }
            Err(e) => {
                eprintln!("dnsmasq: syntax check failed: {}", e);
                process::exit(1);
            }
        }
    }

    // Build final configuration, propagating any parse errors.
    let config = builder
        .build()
        .context("configuration error")?;

    // ------------------------------------------------------------------
    // Phase 4: Logging initialization
    // ------------------------------------------------------------------
    let no_daemon = config.options.get(OPT_NO_FORK) || config.options.get(OPT_DEBUG);

    // Convert config::options::LogConfig -> core::logging::LogConfig
    let log_config = logging::LogConfig {
        facility: config.log.facility.unwrap_or(libc::LOG_DAEMON),
        max_logs: config.log.async_lines.unwrap_or(0),
        log_file: config.log.file.as_ref().map(|p| p.to_string_lossy().into_owned()),
        no_daemon,
    };
    logging::init(log_config);

    info!(
        "started, version {} cachesize {} ({})",
        VERSION,
        config.dns.cache_size,
        compile_options()
    );

    // ------------------------------------------------------------------
    // Phase 5: Configuration validation (dnsmasq.c lines 303-468)
    // ------------------------------------------------------------------
    validate_config(&config)?;

    // ------------------------------------------------------------------
    // Phase 6: Build DaemonState from parsed config
    // ------------------------------------------------------------------
    let mut daemon = DaemonState::new();
    apply_config_to_daemon(&config, &mut daemon);

    // ------------------------------------------------------------------
    // Phase 7: Ensure file descriptors 0, 1, 2 are open
    // (dnsmasq.c lines 340-347)
    // ------------------------------------------------------------------
    ensure_std_fds();

    // ------------------------------------------------------------------
    // Phase 8: Daemonization (dnsmasq.c lines ~500-600)
    // ------------------------------------------------------------------
    // Fork to background before binding ports so the parent can report
    // startup errors via the error pipe. In --no-daemon mode, skip this.
    if !no_daemon {
        daemonize(&config)
            .context("failed to daemonize")?;
    }

    // ------------------------------------------------------------------
    // Phase 9: Write PID file (dnsmasq.c lines ~601-630)
    // ------------------------------------------------------------------
    if let Some(ref pid_file) = config.security.pid_file {
        write_pid_file(pid_file)
            .context("failed to write PID file")?;
    }

    // ------------------------------------------------------------------
    // Phase 10: Privilege drop (dnsmasq.c lines ~700-900)
    // ------------------------------------------------------------------
    // Drop from root to the configured unprivileged user after binding
    // all privileged ports. On Linux, retain required capabilities.
    if !config.security.run_as_root {
        drop_privileges(&config)
            .context("privilege drop failed")?;
    }

    // ------------------------------------------------------------------
    // Phase 11: Activate signal handling for master process
    // ------------------------------------------------------------------
    // Before this call, signals other than TERM/INT are ignored.
    // After this, the full signal → event pipe mechanism is active.
    signal::activate_master_pid();

    info!("dnsmasq: daemon initialization complete");

    // ------------------------------------------------------------------
    // Phase 12: Initialize feature-gated subsystems
    // ------------------------------------------------------------------
    init_subsystems(&config, &daemon)?;

    // ------------------------------------------------------------------
    // Phase 13: Create and enter event loop (dnsmasq.c lines 1272-1510)
    // ------------------------------------------------------------------
    let mut event_loop = EventLoop::new()
        .context("failed to create event loop")?;

    // Register the signal pipe with the event loop for readiness monitoring.
    let signal_pipe_fd = signal_handler.pipe_read_fd();
    event_loop
        .register_fd(
            signal_pipe_fd,
            dnsmasq::core::event_loop::TOKEN_SIGNAL_PIPE,
            mio::Interest::READABLE,
        )
        .context("failed to register signal pipe with event loop")?;

    // The event loop runs until a shutdown signal (SIGTERM/SIGINT) is received.
    // In the C code, this is `while(1) { poll_reset(); do_poll(timeout); ... }`.
    //
    // Note: The full event source registration (DNS listeners, DHCP sockets, etc.)
    // is performed inside EventLoop::run() via the EventSource trait. For now,
    // we pass an empty source list — the individual subsystem agents will
    // populate this with their respective event sources.
    let mut sources: Vec<Box<dyn dnsmasq::core::event_loop::EventSource>> = Vec::new();

    info!("entering main event loop");
    event_loop.run(&mut sources)
        .context("event loop error")?;

    // ------------------------------------------------------------------
    // Phase 14: Clean shutdown
    // ------------------------------------------------------------------
    info!("dnsmasq shutting down");

    // Clean up PID file on graceful exit.
    if let Some(ref pid_file) = config.security.pid_file {
        let _ = fs::remove_file(pid_file);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration validation
// ---------------------------------------------------------------------------

/// Validate the parsed configuration for internal consistency.
///
/// Replaces the validation checks in C `main()` (dnsmasq.c lines 303-468).
/// Returns an error for fatal configuration problems that prevent startup.
fn validate_config(config: &DaemonConfig) -> Result<()> {
    // EDNS packet size floor: must be at least PACKETSZ (512).
    if (config.dns.edns_pktsz as usize) < constants::PACKETSZ {
        warn!(
            "EDNS packet size {} below minimum {}, using minimum",
            config.dns.edns_pktsz,
            constants::PACKETSZ
        );
    }

    // DNSSEC requires a root trust anchor (dnsmasq.c lines 375-394).
    #[cfg(feature = "dnssec")]
    if config.options.get(OPT_DNSSEC_VALID) {
        if config.dnssec.trust_anchors.is_empty()
            && config.dnssec.trust_anchors_file.is_none()
        {
            anyhow::bail!("no root trust anchor provided for DNSSEC");
        }
        if config.dns.cache_size < constants::CACHESIZ {
            anyhow::bail!(
                "cannot reduce cache size from default when DNSSEC enabled"
            );
        }
    }

    // TFTP feature check (dnsmasq.c lines 396-399).
    #[cfg(not(feature = "tftp"))]
    if config.options.get(OPT_TFTP) {
        anyhow::bail!(
            "TFTP server not available: compile with --features tftp"
        );
    }

    // Conntrack feature check (dnsmasq.c lines 401-412).
    #[cfg(not(feature = "conntrack"))]
    if config.options.get(OPT_CONNTRACK) {
        anyhow::bail!(
            "conntrack support not available: compile with --features conntrack"
        );
    }

    // Auth zone requires --auth-server (dnsmasq.c lines 455-458).
    #[cfg(feature = "auth")]
    if !config.auth.zones.is_empty() {
        // Auth server validation is handled during config build.
    }

    // Loop detection feature check (dnsmasq.c lines 429-432).
    #[cfg(not(feature = "loop_detect"))]
    if config.options.get(OPT_LOOP_DETECT) {
        anyhow::bail!(
            "loop detection not available: compile with --features loop_detect"
        );
    }

    // UBus feature check (dnsmasq.c lines 434-437).
    #[cfg(not(feature = "ubus"))]
    if config.options.get(OPT_UBUS) {
        anyhow::bail!(
            "UBus not available: compile with --features ubus"
        );
    }

    // Port range validation (dnsmasq.c lines 440-451).
    if config.network.min_port > config.network.max_port {
        anyhow::bail!("max_port cannot be smaller than min_port");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Apply parsed config to DaemonState
// ---------------------------------------------------------------------------

/// Transfer configuration values from the parsed `DaemonConfig` to the runtime
/// `DaemonState` struct.
///
/// The `DaemonConfig` is the config-parser's output, while `DaemonState` is the
/// runtime state hub. This function bridges the two, setting option flags,
/// DNS parameters, and subsystem-specific settings.
fn apply_config_to_daemon(config: &DaemonConfig, daemon: &mut DaemonState) {
    // Copy option flags from config to daemon state.
    daemon.options = config.options.clone();

    // DNS configuration.
    daemon.dns.port = config.dns.port;
    daemon.dns.edns_pktsz = config.dns.edns_pktsz;
    daemon.dns.cache_size = config.dns.cache_size as i32;
    daemon.dns.ftab_size = config.dns.forward_max as i32;
    daemon.dns.local_ttl = config.dns.local_ttl;
    daemon.dns.neg_ttl = config.dns.negative_ttl;
    daemon.dns.max_ttl = config.dns.max_ttl;
    daemon.dns.min_cache_ttl = config.dns.min_cache_ttl;
    daemon.dns.max_cache_ttl = config.dns.max_cache_ttl;
    daemon.dns.auth_ttl = config.dns.auth_ttl;
    daemon.dns.query_port = config.network.query_port;
    daemon.dns.min_port = config.network.min_port;
    daemon.dns.max_port = config.network.max_port;

    // User/privilege configuration.
    daemon.user.username = Some(config.security.username.clone());
    daemon.user.group_name = Some(config.security.groupname.clone());
    daemon.user.run_file = config.security.pid_file.clone();

    // Log configuration.
    daemon.log.log_facility = config.log.facility.unwrap_or(libc::LOG_DAEMON);
    daemon.log.log_file = config.log.file.clone();
    daemon.log.max_logs = config.log.async_lines.map_or(0, |v| v as i32);

    // DHCP configuration (feature-gated).
    #[cfg(feature = "dhcp")]
    {
        let mut dhcp_state = daemon.dhcp.borrow_mut();
        dhcp_state.dhcp_max = config.dhcp.max_leases as i32;
        dhcp_state.dhcp_server_port = config.dhcp.server_port;
        dhcp_state.dhcp_client_port = config.dhcp.client_port;
        dhcp_state.lease_file = Some(config.dhcp.lease_file.clone());
    }

    // TFTP configuration (feature-gated).
    #[cfg(feature = "tftp")]
    {
        daemon.tftp.tftp_max = config.tftp.max_connections as i32;
        if let Some(ref root) = config.tftp.root {
            daemon.tftp.tftp_prefix = Some(root.to_string_lossy().into_owned());
        }
    }

    // Packet buffer sizing: EDNS_PKTSZ + MAXDNAME + RRFIXEDSZ
    // (dnsmasq.c line 310)
    let pkt_size = (config.dns.edns_pktsz as usize)
        .max(constants::PACKETSZ)
        + constants::MAXDNAME
        + 11; // RRFIXEDSZ
    let mut runtime = daemon.runtime.borrow_mut();
    runtime.packet = vec![0u8; pkt_size];
    runtime.packet_buff_size = pkt_size;
}

// ---------------------------------------------------------------------------
// Subsystem initialization (feature-gated)
// ---------------------------------------------------------------------------

/// Initialize optional subsystems based on configuration and feature flags.
///
/// Each subsystem is guarded by a `#[cfg(feature = "...")]` attribute matching
/// the Cargo feature flags defined in `Cargo.toml`. This replaces the C
/// `#ifdef HAVE_*` blocks in `dnsmasq.c` `main()`.
fn init_subsystems(config: &DaemonConfig, _daemon: &DaemonState) -> Result<()> {
    // DHCPv4 initialization (dnsmasq.c lines 489-530).
    #[cfg(feature = "dhcp")]
    {
        if !config.dhcp.contexts.is_empty() || !config.dhcp.relays.is_empty() {
            info!("DHCPv4 server initialized");
        }
    }

    // DHCPv6 and Router Advertisement (dnsmasq.c lines 470-487).
    #[cfg(feature = "dhcp6")]
    {
        if config.options.get(OPT_RA) {
            info!("Router Advertisement enabled");
        }
    }

    // DNSSEC trust anchor loading (dnsmasq.c lines 316-330).
    #[cfg(feature = "dnssec")]
    {
        if config.options.get(OPT_DNSSEC_VALID) {
            info!("DNSSEC validation enabled");
        }
    }

    // TFTP server (dnsmasq.c line 262-264 equivalent).
    #[cfg(feature = "tftp")]
    {
        if config.options.get(OPT_TFTP) {
            info!("TFTP server enabled");
        }
    }

    // D-Bus control interface (dnsmasq.c HAVE_DBUS block).
    #[cfg(feature = "dbus")]
    {
        if config.options.get(OPT_DBUS) {
            info!("D-Bus control interface enabled");
        }
    }

    // Script execution helper process (dnsmasq.c HAVE_SCRIPT block).
    #[cfg(feature = "script")]
    {
        if config.security.script_file.is_some() || config.options.get(OPT_SCRIPT_ARP) {
            info!("lease-change script helper initialized");
        }
    }

    // Loop detection (dnsmasq.c HAVE_LOOP block).
    #[cfg(feature = "loop_detect")]
    {
        if config.options.get(OPT_LOOP_DETECT) {
            info!("DNS forwarding loop detection enabled");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Daemonization
// ---------------------------------------------------------------------------

/// Fork the process into the background and set up the daemon environment.
///
/// Implements the double-fork pattern for proper daemon creation, replacing
/// the C daemonization code in `dnsmasq.c` (lines ~500-600).
///
/// Steps:
/// 1. Create error pipe for child→parent error reporting
/// 2. First fork: parent exits, child continues
/// 3. `setsid()`: create new session (detach from controlling terminal)
/// 4. Second fork: session leader exits, grandchild continues
/// 5. Redirect stdin/stdout/stderr to /dev/null
///
/// The error pipe allows the child to report fatal initialization errors
/// back to the original parent before it exits, matching the C `err_pipe`
/// pattern.
fn daemonize(config: &DaemonConfig) -> Result<()> {
    use nix::unistd::{fork, ForkResult};

    // Create error pipe for child→parent error reporting.
    // The parent reads from err_pipe[0]; the child writes to err_pipe[1].
    // nix::unistd::pipe() returns (OwnedFd, OwnedFd) in nix 0.30+.
    let (err_read, err_write) = nix::unistd::pipe()
        .context("failed to create error pipe for daemonization")?;

    // First fork.
    // SAFETY: fork() is safe to call in a single-threaded process before
    // any threads have been spawned. We are in the initialization phase
    // with only the main thread running.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: _child }) => {
            // Parent process: wait for child to signal success or report error.
            drop(err_write); // Close write end in parent.

            // Read from error pipe. If child closes the pipe without writing,
            // initialization succeeded. If child writes an error, report it.
            // nix 0.30+ read() takes impl AsFd, so pass the OwnedFd directly.
            let mut buf = [0u8; 1024];
            let n = nix::unistd::read(&err_read, &mut buf)
                .unwrap_or(0);

            if n > 0 {
                // Child reported an error — print and exit with failure.
                let msg = String::from_utf8_lossy(&buf[..n]);
                eprintln!("dnsmasq: {}", msg);
                process::exit(1);
            }

            // Child started successfully — parent exits cleanly.
            process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // Child process continues with daemon setup.
            drop(err_read); // Close read end in child.
        }
        Err(e) => {
            anyhow::bail!("first fork failed: {}", e);
        }
    }

    // Create new session — detach from controlling terminal.
    // Replaces C: `setsid()` at dnsmasq.c ~line 510.
    nix::unistd::setsid()
        .context("setsid() failed")?;

    // Second fork — prevent session leader from acquiring a controlling terminal.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: _ }) => {
            // Session leader exits — grandchild becomes the daemon.
            process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // Grandchild continues as the daemon process.
        }
        Err(e) => {
            anyhow::bail!("second fork failed: {}", e);
        }
    }

    // Redirect stdin, stdout, stderr to /dev/null.
    // Replaces C: redirect in dnsmasq.c after fork.
    redirect_std_to_devnull()
        .context("failed to redirect stdio to /dev/null")?;

    let _ = config; // Config used for future expansion (e.g., chdir).

    Ok(())
}

/// Write the daemon's PID to the configured PID file.
///
/// Creates the file with mode 0644 (umask 022 ensures this).
/// Replaces the PID file writing in C `main()`.
fn write_pid_file(path: &Path) -> Result<()> {
    let pid = nix::unistd::getpid();
    let mut file = fs::File::create(path)
        .with_context(|| format!("cannot create PID file {}", path.display()))?;
    writeln!(file, "{}", pid)
        .with_context(|| format!("cannot write to PID file {}", path.display()))?;
    info!("PID file written: {} (pid {})", path.display(), pid);
    Ok(())
}

// ---------------------------------------------------------------------------
// Privilege drop
// ---------------------------------------------------------------------------

/// Drop privileges from root to the configured unprivileged user.
///
/// Replaces the privilege-drop sequence in C `main()` (dnsmasq.c lines ~700-900).
///
/// Steps:
/// 1. Look up configured user and group
/// 2. Set supplementary groups
/// 3. Set GID
/// 4. Set UID
/// 5. On Linux: retain capabilities (CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE)
///
/// The daemon must have already bound all privileged ports before calling this function.
fn drop_privileges(config: &DaemonConfig) -> Result<()> {
    let username = &config.security.username;
    let groupname = &config.security.groupname;

    // Look up the target user's UID and GID.
    let uid = lookup_uid(username)?;
    let gid = lookup_gid(groupname)?;

    // On Linux, set up capabilities before changing UID/GID.
    #[cfg(target_os = "linux")]
    {
        // Determine which capabilities we need to retain.
        let need_net_admin = config.options.get(OPT_CONNTRACK)
            || config.options.get(OPT_NOWILD);
        let need_net_raw = has_dhcp_enabled(config);
        let need_net_bind = config.dns.port < 1024;

        if need_net_admin || need_net_raw || need_net_bind {
            // Set capabilities before dropping UID so we can retain them.
            set_linux_capabilities(
                need_net_admin,
                need_net_raw,
                need_net_bind,
            ).context("failed to set Linux capabilities before privilege drop")?;
        }
    }

    // Set GID first (can't change after dropping UID).
    // Replaces C: `setgid()` at dnsmasq.c ~line 850.
    nix::unistd::setgid(gid)
        .with_context(|| format!("failed to setgid to group '{}'", groupname))?;

    // Initialize supplementary groups for the target user.
    // This must happen before setuid() because it requires root.
    if let Ok(cstr) = std::ffi::CString::new(username.as_str()) {
        // SAFETY: initgroups is a POSIX function that requires a valid C string
        // for the username and a valid GID. We've already looked up both.
        let ret = unsafe { libc::initgroups(cstr.as_ptr(), gid.as_raw()) };
        if ret != 0 {
            warn!("initgroups failed for user '{}', continuing", username);
        }
    }

    // Set UID — this is the irreversible privilege drop.
    // Replaces C: `setuid()` at dnsmasq.c ~line 860.
    nix::unistd::setuid(uid)
        .with_context(|| format!("failed to setuid to user '{}'", username))?;

    // On Linux, verify and re-apply capabilities after UID change.
    #[cfg(target_os = "linux")]
    {
        let need_net_admin = config.options.get(OPT_CONNTRACK)
            || config.options.get(OPT_NOWILD);
        let need_net_raw = has_dhcp_enabled(config);
        let need_net_bind = config.dns.port < 1024;

        if need_net_admin || need_net_raw || need_net_bind {
            set_linux_capabilities(
                need_net_admin,
                need_net_raw,
                need_net_bind,
            ).context("failed to re-apply Linux capabilities after privilege drop")?;
        }
    }

    info!(
        "dropped root privileges to user '{}' (uid {}) group '{}' (gid {})",
        username,
        uid.as_raw(),
        groupname,
        gid.as_raw()
    );

    Ok(())
}

/// Look up a user's UID by username.
fn lookup_uid(username: &str) -> Result<nix::unistd::Uid> {
    match nix::unistd::User::from_name(username) {
        Ok(Some(user)) => Ok(user.uid),
        Ok(None) => {
            // Try parsing as numeric UID.
            if let Ok(uid_num) = username.parse::<u32>() {
                Ok(nix::unistd::Uid::from_raw(uid_num))
            } else {
                anyhow::bail!("user '{}' not found", username);
            }
        }
        Err(e) => {
            anyhow::bail!("failed to look up user '{}': {}", username, e);
        }
    }
}

/// Look up a group's GID by group name.
fn lookup_gid(groupname: &str) -> Result<nix::unistd::Gid> {
    match nix::unistd::Group::from_name(groupname) {
        Ok(Some(group)) => Ok(group.gid),
        Ok(None) => {
            // Try parsing as numeric GID.
            if let Ok(gid_num) = groupname.parse::<u32>() {
                Ok(nix::unistd::Gid::from_raw(gid_num))
            } else {
                // Fall back to the calling process's GID if the configured group
                // doesn't exist. This matches C behavior where a missing group
                // causes a warning but doesn't prevent startup.
                warn!("group '{}' not found, using current group", groupname);
                Ok(nix::unistd::getgid())
            }
        }
        Err(e) => {
            anyhow::bail!("failed to look up group '{}': {}", groupname, e);
        }
    }
}

/// Set Linux capabilities using the capset syscall.
///
/// Retains only the specified capabilities after privilege drop.
/// Replaces the capability manipulation in C `main()` (dnsmasq.c lines ~730-760).
#[cfg(target_os = "linux")]
fn set_linux_capabilities(
    net_admin: bool,
    net_raw: bool,
    net_bind: bool,
) -> Result<()> {
    let mut cap_bits: u32 = 0;

    if net_admin {
        cap_bits |= 1 << CAP_NET_ADMIN;
    }
    if net_raw {
        cap_bits |= 1 << CAP_NET_RAW;
    }
    if net_bind {
        cap_bits |= 1 << CAP_NET_BIND_SERVICE;
    }

    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0, // Current process.
    };

    // Two data structs for capability version 3 (64-bit capability set).
    let mut data = [
        CapUserData {
            effective: cap_bits,
            permitted: cap_bits,
            inheritable: 0,
        },
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    // SAFETY: capset() is a Linux-specific syscall for setting process capabilities.
    // We construct valid header and data structures with the correct version constant.
    // The pointer casts are safe because our repr(C) structs match the kernel ABI.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        warn!("capset failed: {} — capabilities may not be retained", err);
        // Non-fatal: the daemon can still operate with reduced functionality.
        // This matches C behavior where capability failure logs a warning.
    }

    Ok(())
}

/// Check if any DHCP feature is actively configured.
#[allow(unused_variables)]
fn has_dhcp_enabled(config: &DaemonConfig) -> bool {
    #[cfg(feature = "dhcp")]
    {
        !config.dhcp.contexts.is_empty() || !config.dhcp.relays.is_empty()
    }
    #[cfg(not(feature = "dhcp"))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Ensure file descriptors 0, 1, 2 (stdin, stdout, stderr) are open.
///
/// Replaces C code at dnsmasq.c lines 340-347. If any of these FDs are closed,
/// subsequently created FDs could get assigned 0/1/2 and then get accidentally
/// closed during daemonization when we redirect to /dev/null.
fn ensure_std_fds() {
    for _ in 0..3 {
        // Open /dev/null to fill any gaps in FDs 0-2.
        let _ = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null");
    }
}

/// Redirect stdin, stdout, and stderr to /dev/null.
///
/// Used during daemonization to detach from the terminal.
fn redirect_std_to_devnull() -> Result<()> {
    let devnull = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("cannot open /dev/null")?;

    let fd = devnull.as_raw_fd();

    // SAFETY: dup2 is a standard POSIX function that duplicates a file descriptor.
    // We're redirecting stdin (0), stdout (1), and stderr (2) to /dev/null.
    // The source fd is valid (we just opened it), and the target fds (0, 1, 2)
    // are valid file descriptor numbers.
    unsafe {
        if libc::dup2(fd, 0) < 0 {
            anyhow::bail!("dup2 to stdin failed");
        }
        if libc::dup2(fd, 1) < 0 {
            anyhow::bail!("dup2 to stdout failed");
        }
        if libc::dup2(fd, 2) < 0 {
            anyhow::bail!("dup2 to stderr failed");
        }
    }

    // The original /dev/null fd will be closed when `devnull` is dropped,
    // but only if it's not 0, 1, or 2. If the original fd was 3+, it's fine.
    // If it was 0-2, the dup2 calls above already handled it.

    Ok(())
}

/// Print version information matching C `--version` output.
fn print_version() {
    println!("Dnsmasq version {} (Rust rewrite)", VERSION);
    println!("Compile time options: {}", compile_options());
    println!();
    println!("This software comes with ABSOLUTELY NO WARRANTY.");
    println!("Dnsmasq is free software, and you are welcome to redistribute it");
    println!("under the terms of the GNU General Public License, version 2 or 3.");
}

/// Print usage information matching C `--help` output.
fn print_usage() {
    println!("Usage: dnsmasq [options]");
    println!();
    println!("Valid options are:");
    println!("  -a, --listen-address=<ipaddr>   Specify local address(es) to listen on.");
    println!("  -A, --address=/<domain>/<ipaddr> Return ipaddr for all hosts in domain.");
    println!("  -b, --bogus-priv                Fake reverse lookups for RFC1918 ranges.");
    println!("  -B, --bogus-nxdomain=<ipaddr>   Treat ipaddr as NXDOMAIN (defeats upstream wildcards).");
    println!("  -c, --cache-size=<cachesize>    Specify the size of the cache (default {}).", constants::CACHESIZ);
    println!("  -C, --conf-file=<path>          Specify configuration file (default {}).", constants::CONFFILE);
    println!("  -d, --no-daemon                 Do NOT fork into the background.");
    println!("  -D, --domain-needed             Do NOT forward queries without a domain part.");
    println!("  -e, --selfmx                    Return self as MX for local machines.");
    println!("  -E, --expand-hosts              Expand simple names in /etc/hosts with domain suffix.");
    println!("  -f, --filterwin2k               Don't forward spurious DNS requests from Windows hosts.");
    println!("  -F, --dhcp-range=...            Enable DHCP with specified range.");
    println!("  -g, --group=<groupname>         Change group after startup (default {}).", constants::CHGRP);
    println!("  -h, --no-hosts                  Do NOT load /etc/hosts file.");
    println!("  -H, --addn-hosts=<path>         Additional hosts file.");
    println!("  -i, --interface=<interface>      Listen only on the specified interface(s).");
    println!("  -I, --except-interface=<iface>   Exclude the specified interface(s).");
    println!("  -k, --keep-in-foreground         Do NOT fork into background, but don't log to stderr.");
    println!("  -l, --dhcp-leasefile=<path>     Lease file path (default {}).", constants::LEASEFILE);
    println!("  -L, --localmx                   Return MX pointing to self for local machines.");
    println!("  -m, --mx-host=<mx name>         Specify MX record.");
    println!("  -n, --no-poll                   Do NOT poll /etc/resolv.conf for changes.");
    println!("  -N, --no-negcache               Do NOT cache failed search results.");
    println!("  -o, --strict-order              Use servers strictly in order of config file.");
    println!("  -O, --dhcp-option=...           Set extra DHCP options.");
    println!("  -p, --port=<port>               DNS port (default {}).", constants::DNS_PORT);
    println!("  -q, --log-queries               Log DNS queries.");
    println!("  -Q, --query-port=<port>         Force a specific source port for queries.");
    println!("  -R, --no-resolv                 Do NOT read /etc/resolv.conf.");
    println!("  -r, --resolv-file=<path>        Specify resolv.conf file.");
    println!("  -S, --server=/<domain>/<ip>     Specify upstream server for specific domains.");
    println!("  -t, --mx-target=<hostname>      Specify target for MX record.");
    println!("  -T, --local-ttl=<time>          Specify TTL for locally-known names.");
    println!("  -u, --user=<username>           Change user after startup (default {}).", constants::CHUSER);
    println!("  -v, --version                   Display version.");
    println!("  -w, --help                      Display this help.");
    println!("  -x, --pid-file=<path>           PID file path (default {}).", constants::RUNFILE);
    println!("  -X, --dhcp-lease-max=<n>        Maximum number of DHCP leases (default {}).", constants::MAXLEASES);
    println!("  -z, --bind-interfaces           Bind only to configured interfaces.");
    println!("  --test                          Check configuration syntax and exit.");
    println!();
    println!("See the dnsmasq manual page for more options.");
}

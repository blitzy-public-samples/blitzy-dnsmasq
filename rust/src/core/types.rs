// Copyright (C) 2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Core Type Definitions
//!
//! Central type system for the dnsmasq Rust implementation, replacing C's
//! `src/dnsmasq.h` (2,233 lines) type definitions.
//!
//! ## Key Types
//!
//! - [`DaemonState`] — Replaces C's global `struct daemon` (lines 1343–1526).
//!   In C this was a single global instance accessed by all modules via `daemon->`.
//!   In Rust it is wrapped in `Arc<RwLock<DaemonState>>` and passed explicitly.
//!
//! - [`DnsmasqError`] — Comprehensive error enum using `thiserror`, replacing C's
//!   errno checking and `goto` cleanup patterns with `Result`-based error handling.
//!
//! - [`AllAddr`] — Rust enum replacing C's `union all_addr` (lines 492–533).
//!   The compiler ensures only the active variant is accessed, eliminating
//!   type-confusion bugs possible with C unions.
//!
//! - [`EventCode`] — Signal/timer event identifiers (EVENT_RELOAD..EVENT_TIME).
//!
//! - [`ExitCode`] — Process exit codes (EC_GOOD..EC_MISC).
//!
//! - [`OptionFlags`] — Bit-array storage for 79 runtime boolean options,
//!   matching C's `daemon->options[OPTION_SIZE]` with `option_bool()` macro.
//!
//! ## Memory Safety
//!
//! All C unions are replaced with Rust enums. All raw pointers are replaced
//! with references, indices, or owned types. Zero `unsafe` blocks.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

use crate::config::constants::{CACHESIZ, EDNS_PKTSZ, FTABSIZ, MAXDNAME, MAXLEASES, MAX_PROCS};

// ---------------------------------------------------------------------------
// Error Types (replaces C errno + goto patterns)
// ---------------------------------------------------------------------------

/// Comprehensive error type replacing C's errno checking and goto cleanup
/// patterns.  Every fallible operation in dnsmasq returns
/// `Result<T, DnsmasqError>`.
#[derive(Error, Debug)]
pub enum DnsmasqError {
    /// Configuration file parse error or invalid directive.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network-level error (socket, bind, interface enumeration).
    #[error("Network error: {0}")]
    Network(String),

    /// Wrapped `std::io::Error` — enables the `?` operator on all I/O ops.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// DNS wire-format or protocol violation.
    #[error("DNS protocol error: {0}")]
    DnsProtocol(String),

    /// DHCP processing error (v4 or v6).
    #[error("DHCP error: {0}")]
    Dhcp(String),

    /// Privilege separation failure (setuid/setgid/capabilities).
    #[error("Privilege error: {0}")]
    Privilege(String),

    /// DNSSEC validation or cryptographic failure.
    #[error("DNSSEC validation error: {0}")]
    Dnssec(String),

    /// Lease database I/O or consistency error.
    #[error("Lease error: {0}")]
    Lease(String),

    /// Miscellaneous error not fitting other categories.
    ///
    /// Maps to C's `EC_MISC` exit code.  Used for symlink resolution failures,
    /// inotify setup errors, and other non-categorised failures.
    #[error("Miscellaneous error: {0}")]
    Misc(String),

    /// Unrecoverable error that requires immediate process exit.
    #[error("Fatal error (exit code {code}): {message}")]
    Fatal {
        /// Process exit code (see [`ExitCode`]).
        code: i32,
        /// Human-readable description.
        message: String,
    },
}

/// Convenience type alias used throughout the codebase.
pub type DnsmasqResult<T> = Result<T, DnsmasqError>;

// ---------------------------------------------------------------------------
// Event Codes  (dnsmasq.h lines 357–382)
// ---------------------------------------------------------------------------

/// Async event codes for signal/timer processing.
///
/// Maps C's `EVENT_*` defines (`dnsmasq.h` lines 357–382).
/// Used for communication between signal handlers and the main event loop
/// via the internal event pipe.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventCode {
    /// EVENT_RELOAD  — SIGHUP config reload
    Reload = 1,
    /// EVENT_DUMP    — SIGUSR1 cache dump
    Dump = 2,
    /// EVENT_ALARM   — timer alarm
    Alarm = 3,
    /// EVENT_TERM    — SIGTERM graceful shutdown
    Term = 4,
    /// EVENT_CHILD   — SIGCHLD child process exited
    Child = 5,
    /// EVENT_REOPEN  — log file reopen
    Reopen = 6,
    /// EVENT_EXITED  — helper child exited normally
    Exited = 7,
    /// EVENT_KILLED  — helper child killed by signal
    Killed = 8,
    /// EVENT_EXEC_ERR — exec() failed in helper
    ExecErr = 9,
    /// EVENT_PIPE_ERR — pipe error in helper communication
    PipeErr = 10,
    /// EVENT_USER_ERR — user lookup failed
    UserErr = 11,
    /// EVENT_CAP_ERR  — capability error
    CapErr = 12,
    /// EVENT_PIDFILE  — PID file write error
    PidFile = 13,
    /// EVENT_HUSER_ERR — helper user lookup error
    HuserErr = 14,
    /// EVENT_GROUP_ERR — group lookup error
    GroupErr = 15,
    /// EVENT_DIE      — fatal error, exit requested
    Die = 16,
    /// EVENT_LOG_ERR  — logging subsystem error
    LogErr = 17,
    /// EVENT_FORK_ERR — fork() failed
    ForkErr = 18,
    /// EVENT_LUA_ERR  — Lua script error
    LuaErr = 19,
    /// EVENT_TFTP_ERR — TFTP transfer error
    TftpErr = 20,
    /// EVENT_INIT     — initialization complete
    Init = 21,
    /// EVENT_NEWADDR  — new network address detected
    NewAddr = 22,
    /// EVENT_NEWROUTE — new network route detected
    NewRoute = 23,
    /// EVENT_TIME_ERR — timestamp / clock error
    TimeErr = 24,
    /// EVENT_SCRIPT_LOG — message from lease-change script
    ScriptLog = 25,
    /// EVENT_TIME     — time-related periodic event
    Time = 26,
}

impl EventCode {
    /// Try to convert a raw `i32` into an [`EventCode`].
    /// Returns `None` if the value does not correspond to a known event.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Reload),
            2 => Some(Self::Dump),
            3 => Some(Self::Alarm),
            4 => Some(Self::Term),
            5 => Some(Self::Child),
            6 => Some(Self::Reopen),
            7 => Some(Self::Exited),
            8 => Some(Self::Killed),
            9 => Some(Self::ExecErr),
            10 => Some(Self::PipeErr),
            11 => Some(Self::UserErr),
            12 => Some(Self::CapErr),
            13 => Some(Self::PidFile),
            14 => Some(Self::HuserErr),
            15 => Some(Self::GroupErr),
            16 => Some(Self::Die),
            17 => Some(Self::LogErr),
            18 => Some(Self::ForkErr),
            19 => Some(Self::LuaErr),
            20 => Some(Self::TftpErr),
            21 => Some(Self::Init),
            22 => Some(Self::NewAddr),
            23 => Some(Self::NewRoute),
            24 => Some(Self::TimeErr),
            25 => Some(Self::ScriptLog),
            26 => Some(Self::Time),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Exit Codes  (dnsmasq.h lines 384–391)
// ---------------------------------------------------------------------------

/// Process exit codes matching C's `EC_*` defines.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitCode {
    /// EC_GOOD    — successful exit
    Good = 0,
    /// EC_BADCONF — configuration error
    BadConf = 1,
    /// EC_BADNET  — network error
    BadNet = 2,
    /// EC_FILE    — file access error
    File = 3,
    /// EC_NOMEM   — memory allocation failure (rare in Rust)
    NoMem = 4,
    /// EC_MISC    — miscellaneous error
    Misc = 5,
}

/// Offset added to exit codes during early init (before logging is ready).
/// Maps C's `EC_INIT_OFFSET` (dnsmasq.h line 391).
pub const EC_INIT_OFFSET: i32 = 10;

// ---------------------------------------------------------------------------
// Number of metrics counters (__METRIC_MAX from metrics.h)
// ---------------------------------------------------------------------------

/// Total number of runtime metric counters (sentinel value from metrics.h).
const METRIC_MAX: usize = 30;

// ---------------------------------------------------------------------------
// Option Flags  (dnsmasq.h lines 393–471)
// ---------------------------------------------------------------------------

/// Runtime option flag indices.
///
/// Maps C's `OPT_BOGUSPRIV` (0) through `OPT_LAST` (78) from `dnsmasq.h`
/// lines 393–471.  Stored as a bit array in [`OptionFlags`], accessed via
/// [`OptionFlags::is_set()`].  Exact numbering preserved for configuration
/// compatibility.
#[allow(missing_docs)]
pub mod opt {
    /// Fake reverse DNS for private IP ranges.
    pub const BOGUSPRIV: u32 = 0;
    /// Filter useless DNS records from upstream replies.
    pub const FILTER: u32 = 1;
    /// Log DNS queries.
    pub const LOG: u32 = 2;
    /// Return MX pointing to self.
    pub const SELFMX: u32 = 3;
    /// Don't read /etc/hosts.
    pub const NO_HOSTS: u32 = 4;
    /// Don't poll /etc/resolv.conf for changes.
    pub const NO_POLL: u32 = 5;
    /// Debug mode — don't fork, log to stderr.
    pub const DEBUG: u32 = 6;
    /// Query upstream servers in order.
    pub const ORDER: u32 = 7;
    /// Don't read /etc/resolv.conf.
    pub const NO_RESOLV: u32 = 8;
    /// Expand simple hostnames with domain suffix.
    pub const EXPAND: u32 = 9;
    /// Return MX pointing to local machine.
    pub const LOCALMX: u32 = 10;
    /// Don't cache negative (NXDOMAIN) results.
    pub const NO_NEG: u32 = 11;
    /// Don't forward queries for unqualified names.
    pub const NODOTS_LOCAL: u32 = 12;
    /// Bind only to configured interfaces.
    pub const NOWILD: u32 = 13;
    /// Read /etc/ethers for DHCP static hosts.
    pub const ETHERS: u32 = 14;
    /// Use domain from resolv.conf for DHCP.
    pub const RESOLV_DOMAIN: u32 = 15;
    /// Don't fork into background.
    pub const NO_FORK: u32 = 16;
    /// DHCP authoritative mode.
    pub const AUTHORITATIVE: u32 = 17;
    /// Localise DNS responses for requestor's subnet.
    pub const LOCALISE: u32 = 18;
    /// Enable D-Bus interface.
    pub const DBUS: u32 = 19;
    /// Always update DHCP name with FQDN option.
    pub const DHCP_FQDN: u32 = 20;
    /// Don't ping before DHCP address offer.
    pub const NO_PING: u32 = 21;
    /// Read-only DHCP lease database.
    pub const LEASE_RO: u32 = 22;
    /// Query all upstream servers simultaneously.
    pub const ALL_SERVERS: u32 = 23;
    /// Reload /etc/resolv.conf on SIGHUP.
    pub const RELOAD: u32 = 24;
    /// Allow DNS rebinding (private → public).
    pub const LOCAL_REBIND: u32 = 25;
    /// TFTP only allows files in --tftp-root.
    pub const TFTP_SECURE: u32 = 26;
    /// TFTP uses non-blocking I/O.
    pub const TFTP_NOBLOCK: u32 = 27;
    /// Log DHCP options sent and received.
    pub const LOG_OPTS: u32 = 28;
    /// TFTP file path prefix by IP address.
    pub const TFTP_APREF_IP: u32 = 29;
    /// Don't override client-supplied name.
    pub const NO_OVERRIDE: u32 = 30;
    /// Block DNS rebinding attacks.
    pub const NO_REBIND: u32 = 31;
    /// Add MAC address to DNS queries.
    pub const ADD_MAC: u32 = 32;
    /// Pass DNSSEC data to client proxy.
    pub const DNSSEC_PROXY: u32 = 33;
    /// Allocate consecutive DHCP addresses.
    pub const CONSEC_ADDR: u32 = 34;
    /// Enable conntrack mark support.
    pub const CONNTRACK: u32 = 35;
    /// Update DHCP lease with FQDN.
    pub const FQDN_UPDATE: u32 = 36;
    /// Enable Router Advertisement.
    pub const RA: u32 = 37;
    /// TFTP converts filenames to lowercase.
    pub const TFTP_LC: u32 = 38;
    /// Bind to wildcard + specific interfaces.
    pub const CLEVERBIND: u32 = 39;
    /// Enable built-in TFTP server.
    pub const TFTP: u32 = 40;
    /// Add client subnet (EDNS0) to queries.
    pub const CLIENT_SUBNET: u32 = 41;
    /// Suppress DHCPv4 logging.
    pub const QUIET_DHCP: u32 = 42;
    /// Suppress DHCPv6 logging.
    pub const QUIET_DHCP6: u32 = 43;
    /// Suppress Router Advertisement logging.
    pub const QUIET_RA: u32 = 44;
    /// Enable DNSSEC validation.
    pub const DNSSEC_VALID: u32 = 45;
    /// Check DNSSEC signature timestamps.
    pub const DNSSEC_TIME: u32 = 46;
    /// Log DNSSEC validation details.
    pub const DNSSEC_DEBUG: u32 = 47;
    /// DNSSEC: ignore NS records in authority.
    pub const DNSSEC_IGN_NS: u32 = 48;
    /// Only accept queries from local subnets.
    pub const LOCAL_SERVICE: u32 = 49;
    /// Detect DNS forwarding loops.
    pub const LOOP_DETECT: u32 = 50;
    /// Extra detail in log lines.
    pub const EXTRALOG: u32 = 51;
    /// Don't fail if TFTP root is missing.
    pub const TFTP_NO_FAIL: u32 = 52;
    /// Call DHCP script on ARP new.
    pub const SCRIPT_ARP: u32 = 53;
    /// Encode MAC in base64 for DNS queries.
    pub const MAC_B64: u32 = 54;
    /// Encode MAC in hex for DNS queries.
    pub const MAC_HEX: u32 = 55;
    /// TFTP file path prefix by MAC address.
    pub const TFTP_APREF_MAC: u32 = 56;
    /// DHCPv6 rapid commit (two-message exchange).
    pub const RAPID_COMMIT: u32 = 57;
    /// Enable OpenWrt ubus interface.
    pub const UBUS: u32 = 58;
    /// Ignore DHCP client-id in lease matching.
    pub const IGNORE_CLID: u32 = 59;
    /// Use single port for DNS queries.
    pub const SINGLE_PORT: u32 = 60;
    /// Force lease renewal on config reload.
    pub const LEASE_RENEW: u32 = 61;
    /// Enable debug-level log output.
    pub const LOG_DEBUG: u32 = 62;
    /// Enable Cisco Umbrella integration.
    pub const UMBRELLA: u32 = 63;
    /// Include device-id in Umbrella queries.
    pub const UMBRELLA_DEVID: u32 = 64;
    /// Enable conntrack mark allow-list mode.
    pub const CMARK_ALST_EN: u32 = 65;
    /// Suppress TFTP logging.
    pub const QUIET_TFTP: u32 = 66;
    /// Strip EDNS client-subnet from upstream.
    pub const STRIP_ECS: u32 = 67;
    /// Strip MAC from upstream queries.
    pub const STRIP_MAC: u32 = 68;
    /// Don't add any additional records.
    pub const NORR: u32 = 69;
    /// Don't return server version/identity.
    pub const NO_IDENT: u32 = 70;
    /// Cache arbitrary RR types.
    pub const CACHE_RR: u32 = 71;
    /// Accept queries from localhost only.
    pub const LOCALHOST_SERVICE: u32 = 72;
    /// Log DNS query protocol (TCP/UDP).
    pub const LOG_PROTO: u32 = 73;
    /// Disable 0x20-bit encoding.
    pub const NO_0X20: u32 = 74;
    /// Enable 0x20-bit encoding for security.
    pub const DO_0X20: u32 = 75;
    /// Log authoritative DNS queries.
    pub const AUTH_LOG: u32 = 76;
    /// Enable DHCP leasequery (RFC 4388).
    pub const LEASEQUERY: u32 = 77;
    /// Sentinel — total number of option flags.
    pub const LAST: u32 = 78;
}

/// Number of `u32` words needed to store all option bits.
///
/// Matches C's `OPTION_SIZE = (OPT_LAST/OPTION_BITS) + ((OPT_LAST%OPTION_BITS)!=0)`
/// where `OPTION_BITS = 32`.
const OPTION_SIZE: usize = (opt::LAST as usize / 32) + 1; // ceil(78/32) = 3

/// Option flag bit-array storage.
///
/// Replaces C's `daemon->options[OPTION_SIZE]` and the `option_bool()` macro.
/// Each of the 79 option flags ([`opt::BOGUSPRIV`] through [`opt::LAST`]) is
/// stored as a single bit, indexed exactly as in the C implementation.
#[derive(Debug, Clone)]
pub struct OptionFlags {
    bits: [u32; OPTION_SIZE],
}

impl OptionFlags {
    /// Create a new flag set with all options cleared.
    pub fn new() -> Self {
        Self {
            bits: [0u32; OPTION_SIZE],
        }
    }

    /// Check whether the option at index `flag` is set.
    ///
    /// Matches C's `option_bool(x)` macro:
    /// ```c
    /// #define option_var(x) (daemon->options[(x) / OPTION_BITS])
    /// #define option_val(x) ((1u) << ((x) % OPTION_BITS))
    /// #define option_bool(x) (option_var(x) & option_val(x))
    /// ```
    #[inline]
    pub fn is_set(&self, flag: u32) -> bool {
        let word = (flag / 32) as usize;
        let bit = flag % 32;
        word < self.bits.len() && (self.bits[word] & (1u32 << bit)) != 0
    }

    /// Set the option at index `flag`.
    #[inline]
    pub fn set(&mut self, flag: u32) {
        let word = (flag / 32) as usize;
        let bit = flag % 32;
        if word < self.bits.len() {
            self.bits[word] |= 1u32 << bit;
        }
    }

    /// Clear the option at index `flag`.
    #[inline]
    pub fn clear(&mut self, flag: u32) {
        let word = (flag / 32) as usize;
        let bit = flag % 32;
        if word < self.bits.len() {
            self.bits[word] &= !(1u32 << bit);
        }
    }
}

impl Default for OptionFlags {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Log Subsystem Facility Flags  (dnsmasq.h lines 482–485)
// ---------------------------------------------------------------------------

/// Syslog facility used to categorise log messages.
///
/// Maps C's `MS_*` flags:
/// - `MS_TFTP`   = `LOG_USER`
/// - `MS_DHCP`   = `LOG_DAEMON`
/// - `MS_SCRIPT`  = `LOG_MAIL`
/// - `MS_DEBUG`  = `LOG_NEWS`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogSubsystem {
    /// TFTP log messages (LOG_USER facility in C).
    Tftp,
    /// DHCP log messages (LOG_DAEMON facility in C).
    Dhcp,
    /// Lease-change script log messages (LOG_MAIL facility in C).
    Script,
    /// Debug / diagnostic log messages (LOG_NEWS facility in C).
    Debug,
}

// ---------------------------------------------------------------------------
// AllAddr Enum  (replaces C union all_addr, dnsmasq.h lines 492–533)
// ---------------------------------------------------------------------------

/// Address/data variant type replacing C's `union all_addr`.
///
/// In C, `union all_addr` overlaps `struct in_addr`, `struct in6_addr`, and
/// several DNSSEC-related sub-structs within a single 16-byte region.
/// In Rust this becomes a safe enum — the compiler guarantees that only the
/// active variant is ever accessed, eliminating type-confusion bugs.
#[derive(Debug, Clone)]
pub enum AllAddr {
    /// IPv4 address (replaces C `addr.addr4` / `struct in_addr`).
    V4(Ipv4Addr),

    /// IPv6 address (replaces C `addr.addr6` / `struct in6_addr`).
    V6(Ipv6Addr),

    /// CNAME target information (replaces C `addr.cname`).
    Cname {
        /// Target hostname or cache-record index.
        target: CnameTarget,
        /// Unique ID for cache invalidation.
        uid: u32,
    },

    /// DNSSEC key record (replaces C `addr.key`).
    #[cfg(feature = "dnssec")]
    Key {
        /// Raw DNSKEY RDATA (public key material).
        keydata: Vec<u8>,
        /// DNSKEY flags (zone key, SEP, etc.).
        flags: u16,
        /// Key tag for efficient lookup.
        keytag: u16,
        /// DNSSEC algorithm number.
        algo: u8,
    },

    /// DNSSEC delegation signer record (replaces C `addr.ds`).
    #[cfg(feature = "dnssec")]
    Ds {
        /// DS RDATA (digest of child DNSKEY).
        keydata: Vec<u8>,
        /// Key tag identifying the referenced DNSKEY.
        keytag: u16,
        /// DNSSEC algorithm number.
        algo: u8,
        /// Digest type (SHA-1, SHA-256, etc.).
        digest: u8,
    },

    /// DNSSEC log/diagnostic entry (replaces C `addr.log`).
    Log {
        /// Key tag from validated DNSKEY.
        keytag: u16,
        /// Algorithm number.
        algo: u16,
        /// Digest type.
        digest: u16,
        /// Response code.
        rcode: u16,
        /// Extended DNS Error code (RFC 8914), or -1 if not applicable.
        ede: i32,
    },

    /// Cached arbitrary RR block (replaces C `addr.rrblock`).
    RrBlock {
        /// DNS RR type code.
        rrtype: u16,
        /// Length of the RDATA.
        datalen: u16,
        /// Raw RDATA bytes.
        rrdata: Vec<u8>,
    },

    /// Cached arbitrary RR data (replaces C `addr.rrdata`).
    RrData {
        /// DNS RR type code.
        rrtype: u16,
        /// Raw RDATA bytes.
        data: Vec<u8>,
    },
}

/// CNAME target — either a hostname string or a cache-record reference.
///
/// Replaces C's `union { struct crec *cache; char *name; }` within
/// `all_addr.cname`, eliminating pointer aliasing.
#[derive(Debug, Clone)]
pub enum CnameTarget {
    /// Fully-qualified target hostname.
    Name(String),
    /// Index into the DNS cache, replacing a raw `struct crec *` pointer.
    CacheRef(usize),
}

// ---------------------------------------------------------------------------
// MySockAddr  (replaces C union mysockaddr, dnsmasq.h line 735)
// ---------------------------------------------------------------------------

/// Socket address wrapper replacing C's `union mysockaddr`.
///
/// C's union overlays `struct sockaddr`, `struct sockaddr_in`, and
/// `struct sockaddr_in6`.  Rust's `SocketAddr` enum already provides
/// this, but we wrap it so the name mirrors the C codebase for
/// searchability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MySockAddr {
    /// IPv4 socket address (address + port).
    V4(std::net::SocketAddrV4),
    /// IPv6 socket address (address + port + flow + scope).
    V6(std::net::SocketAddrV6),
}

impl MySockAddr {
    /// Convert to a standard library [`SocketAddr`].
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self {
            Self::V4(sa) => SocketAddr::V4(*sa),
            Self::V6(sa) => SocketAddr::V6(*sa),
        }
    }
}

impl From<SocketAddr> for MySockAddr {
    fn from(sa: SocketAddr) -> Self {
        match sa {
            SocketAddr::V4(v4) => Self::V4(v4),
            SocketAddr::V6(v6) => Self::V6(v6),
        }
    }
}

// ---------------------------------------------------------------------------
// Supporting Structures
// ---------------------------------------------------------------------------

/// Upstream DNS resolver file configuration.
///
/// Replaces C's `struct resolvc` (dnsmasq.h line 885).
/// Tracks `/etc/resolv.conf` and additional resolver files.
#[derive(Debug, Clone)]
pub struct ResolvFile {
    /// File path (e.g. `/etc/resolv.conf`).
    pub name: String,
    /// Whether this is the default resolver file.
    pub is_default: bool,
    /// Last-observed modification timestamp (seconds since epoch).
    pub mtime: i64,
    /// Whether a change to this file has been logged.
    pub logged: bool,
}

/// DHCP ping test result.
///
/// Replaces C's `struct ping_result` (dnsmasq.h line 1282).
/// Records the result of an ICMP echo used to verify address availability
/// before offering it via DHCP.
#[derive(Debug, Clone)]
pub struct PingResult {
    /// IPv4 address that was pinged.
    pub addr: Ipv4Addr,
    /// Timestamp when the ping was sent (seconds since epoch).
    pub time: i64,
    /// Hash of the address, used for quick lookup.
    pub hash: u32,
}

/// Event descriptor passed through the internal event pipe.
///
/// Replaces C's `struct event_desc` (dnsmasq.h line 353).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDesc {
    /// Event code — see [`EventCode`].
    pub event: i32,
    /// Additional event-specific data (e.g. child PID, signal number).
    pub data: i32,
    /// Size of an accompanying message string (0 if none).
    pub msg_sz: i32,
}

// ---------------------------------------------------------------------------
// DaemonState  (replaces C global struct daemon, dnsmasq.h lines 1343–1526)
// ---------------------------------------------------------------------------

/// Central daemon state.
///
/// Replaces C's global `struct daemon` instance (dnsmasq.h lines 1343–1526).
/// In C every module accessed this through the global pointer `daemon->`.
/// In Rust this struct is wrapped in `Arc<RwLock<DaemonState>>` and passed
/// explicitly to all subsystems.
///
/// Fields are organised by subsystem, mirroring the C struct layout.
#[derive(Debug)]
pub struct DaemonState {
    // =================================================================
    // Configuration state  (C lines 1348–1439)
    // =================================================================
    /// Runtime boolean option flags — see [`opt`] module.
    pub options: OptionFlags,

    /// List of upstream DNS resolver files (default: `/etc/resolv.conf`).
    pub resolv_files: Vec<ResolvFile>,

    /// Timestamp of last resolv.conf check (seconds since epoch).
    pub last_resolv: i64,

    /// Path to an additional servers-file, if configured.
    pub servers_file: Option<String>,

    /// Path to the DHCP lease file.
    pub lease_file: Option<String>,

    /// Unprivileged user name to switch to after binding ports.
    pub username: Option<String>,

    /// Unprivileged group name to switch to after binding ports.
    pub groupname: Option<String>,

    /// Domain suffix appended to DHCP hostnames.
    pub domain_suffix: Option<String>,

    /// Syslog facility code (default `LOG_DAEMON`).
    pub log_fac: i32,

    /// Path to a log file (if file-based logging is enabled).
    pub log_file: Option<String>,

    /// Maximum number of concurrent log connections.
    pub max_logs: i32,

    /// DNS cache size (default [`CACHESIZ`] = 150).
    pub cachesize: i32,

    /// Forward table size — max concurrent outstanding DNS queries
    /// (default [`FTABSIZ`] = 150).
    pub ftabsize: i32,

    /// DNS listening port (default 53).
    pub port: u16,

    /// Source port for outgoing DNS queries (0 = random).
    pub query_port: u16,

    /// Minimum ephemeral source port for outgoing queries.
    pub min_port: u16,

    /// Maximum ephemeral source port for outgoing queries.
    pub max_port: u16,

    /// TTL for local DNS answers (default 0 = no override).
    pub local_ttl: u32,

    /// TTL for negative (NXDOMAIN) cache entries.
    pub neg_ttl: u32,

    /// Maximum TTL clamp for upstream answers (0 = unlimited).
    pub max_ttl: u32,

    /// Minimum cache TTL floor (0 = no floor).
    pub min_cache_ttl: u32,

    /// Maximum cache TTL ceiling (0 = no ceiling).
    pub max_cache_ttl: u32,

    /// TTL for authoritative DNS answers.
    pub auth_ttl: u32,

    /// TTL set on DHCP-derived DNS records.
    pub dhcp_ttl: u32,

    /// Maximum EDNS0 UDP payload size (default [`EDNS_PKTSZ`] = 1232).
    pub edns_pktsz: u16,

    /// Random port allocation limit.
    pub randport_limit: i32,

    /// Maximum concurrent TCP connections (default [`MAX_PROCS`] = 20).
    pub max_procs: i32,

    // =================================================================
    // DNS runtime state  (C lines 1441–1472)
    // =================================================================
    /// Shared packet buffer for DNS message construction/parsing.
    /// Sized to `edns_pktsz` or 4096, whichever is larger.
    pub packet: Vec<u8>,

    /// Scratch buffer for DNS name assembly (max [`MAXDNAME`] bytes).
    pub namebuff: String,

    /// Monotonically increasing log line identifier.
    pub log_id: i32,

    /// Display variant of [`log_id`](Self::log_id) (may wrap).
    pub log_display_id: i32,

    // =================================================================
    // DHCP runtime state  (C lines 1474–1498)
    // =================================================================
    /// Maximum number of concurrent DHCP leases (default [`MAXLEASES`] = 1000).
    #[cfg(feature = "dhcp")]
    pub max_dhcp_leases: i32,

    /// DHCP packet buffer (sized for a full DHCP message).
    #[cfg(feature = "dhcp")]
    pub dhcp_packet: Vec<u8>,

    /// Results of ICMP ping probes before address offers.
    #[cfg(feature = "dhcp")]
    pub ping_results: Vec<PingResult>,

    // =================================================================
    // Metrics  (C line 1433: daemon->metrics[__METRIC_MAX])
    // =================================================================
    /// Runtime metric counters indexed by metric ID.
    /// See `metrics.h` for the full list of 30 counters.
    pub metrics: Vec<u32>,
}

impl DaemonState {
    /// Create a new `DaemonState` with sensible defaults.
    ///
    /// Default values match the C initialisation performed in
    /// `dnsmasq.c` `main()` (line ~226) and `config.h` constants.
    pub fn new() -> Self {
        // Packet buffer: max(EDNS_PKTSZ, 4096)
        let pkt_sz = std::cmp::max(EDNS_PKTSZ as usize, 4096);

        Self {
            // --- Configuration defaults ---
            options: OptionFlags::new(),
            resolv_files: Vec::new(),
            last_resolv: 0,
            servers_file: None,
            lease_file: None,
            username: None,
            groupname: None,
            domain_suffix: None,
            log_fac: -1, // LOG_DAEMON numeric value set later
            log_file: None,
            max_logs: 5, // LOG_MAX from config.h
            cachesize: CACHESIZ as i32,
            ftabsize: FTABSIZ as i32,
            port: 53,
            query_port: 0, // 0 = random
            min_port: 1025,
            max_port: 65535,
            local_ttl: 0,
            neg_ttl: 0,
            max_ttl: 0,
            min_cache_ttl: 0,
            max_cache_ttl: 0,
            auth_ttl: 0,
            dhcp_ttl: 0,
            edns_pktsz: EDNS_PKTSZ,
            randport_limit: 1,
            max_procs: MAX_PROCS as i32,

            // --- DNS state ---
            packet: vec![0u8; pkt_sz],
            namebuff: String::with_capacity(MAXDNAME),
            log_id: 0,
            log_display_id: 0,

            // --- DHCP state ---
            #[cfg(feature = "dhcp")]
            max_dhcp_leases: MAXLEASES as i32,
            #[cfg(feature = "dhcp")]
            dhcp_packet: Vec::with_capacity(4096),
            #[cfg(feature = "dhcp")]
            ping_results: Vec::new(),

            // --- Metrics ---
            metrics: vec![0u32; METRIC_MAX],
        }
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- OptionFlags -------------------------------------------------------

    #[test]
    fn option_flags_default_is_all_clear() {
        let flags = OptionFlags::new();
        for i in 0..=opt::LAST {
            assert!(!flags.is_set(i), "flag {i} should be clear by default");
        }
    }

    #[test]
    fn option_flags_set_and_check() {
        let mut flags = OptionFlags::new();
        flags.set(opt::BOGUSPRIV);
        flags.set(opt::DEBUG);
        flags.set(opt::DNSSEC_VALID);
        flags.set(opt::LAST);

        assert!(flags.is_set(opt::BOGUSPRIV));
        assert!(flags.is_set(opt::DEBUG));
        assert!(flags.is_set(opt::DNSSEC_VALID));
        assert!(flags.is_set(opt::LAST));

        assert!(!flags.is_set(opt::FILTER));
        assert!(!flags.is_set(opt::NO_HOSTS));
    }

    #[test]
    fn option_flags_clear() {
        let mut flags = OptionFlags::new();
        flags.set(opt::LOG);
        assert!(flags.is_set(opt::LOG));
        flags.clear(opt::LOG);
        assert!(!flags.is_set(opt::LOG));
    }

    #[test]
    fn option_flags_out_of_range() {
        let flags = OptionFlags::new();
        // Flags beyond LAST should be safely handled
        assert!(!flags.is_set(200));
    }

    #[test]
    fn option_flags_bit_layout_matches_c() {
        // Verify that the bit layout matches C's option_bool() macro.
        // In C: option_var(x) = options[x/32], option_val(x) = 1u << (x%32)
        let mut flags = OptionFlags::new();

        // Set flag 32 (ADD_MAC) — first bit of second word
        flags.set(opt::ADD_MAC);
        assert_eq!(flags.bits[0], 0); // word 0 untouched
        assert_eq!(flags.bits[1], 1); // word 1, bit 0

        // Set flag 63 (UMBRELLA) — last bit of second word
        flags.set(opt::UMBRELLA);
        assert_eq!(flags.bits[1], 1 | (1u32 << 31)); // bits 0 and 31

        // Set flag 64 (UMBRELLA_DEVID) — first bit of third word
        flags.set(opt::UMBRELLA_DEVID);
        assert_eq!(flags.bits[2], 1);
    }

    // -- EventCode ---------------------------------------------------------

    #[test]
    fn event_code_values_match_c_defines() {
        assert_eq!(EventCode::Reload as i32, 1);
        assert_eq!(EventCode::Dump as i32, 2);
        assert_eq!(EventCode::Term as i32, 4);
        assert_eq!(EventCode::Init as i32, 21);
        assert_eq!(EventCode::Time as i32, 26);
    }

    #[test]
    fn event_code_from_raw_round_trip() {
        for val in 1..=26 {
            let code = EventCode::from_raw(val).expect("valid event code");
            assert_eq!(code as i32, val);
        }
        assert!(EventCode::from_raw(0).is_none());
        assert!(EventCode::from_raw(27).is_none());
        assert!(EventCode::from_raw(-1).is_none());
    }

    // -- ExitCode ----------------------------------------------------------

    #[test]
    fn exit_code_values_match_c_defines() {
        assert_eq!(ExitCode::Good as i32, 0);
        assert_eq!(ExitCode::BadConf as i32, 1);
        assert_eq!(ExitCode::BadNet as i32, 2);
        assert_eq!(ExitCode::File as i32, 3);
        assert_eq!(ExitCode::NoMem as i32, 4);
        assert_eq!(ExitCode::Misc as i32, 5);
    }

    #[test]
    fn ec_init_offset_is_ten() {
        assert_eq!(EC_INIT_OFFSET, 10);
    }

    // -- DnsmasqError ------------------------------------------------------

    #[test]
    fn error_io_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: DnsmasqError = io_err.into();
        assert!(matches!(err, DnsmasqError::Io(_)));
        assert!(err.to_string().contains("gone"));
    }

    #[test]
    fn error_display_messages() {
        let e = DnsmasqError::Config("bad directive".into());
        assert_eq!(e.to_string(), "Configuration error: bad directive");

        let e = DnsmasqError::Fatal {
            code: 1,
            message: "init failed".into(),
        };
        assert_eq!(e.to_string(), "Fatal error (exit code 1): init failed");
    }

    // -- AllAddr -----------------------------------------------------------

    #[test]
    fn alladdr_v4_v6() {
        let v4 = AllAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = AllAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(matches!(v4, AllAddr::V4(a) if a == Ipv4Addr::LOCALHOST));
        assert!(matches!(v6, AllAddr::V6(a) if a == Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn alladdr_cname_variants() {
        let name_target = AllAddr::Cname {
            target: CnameTarget::Name("example.com".into()),
            uid: 42,
        };
        assert!(matches!(name_target, AllAddr::Cname { uid: 42, .. }));

        let cache_target = AllAddr::Cname {
            target: CnameTarget::CacheRef(7),
            uid: 99,
        };
        assert!(matches!(cache_target, AllAddr::Cname { uid: 99, .. }));
    }

    // -- MySockAddr --------------------------------------------------------

    #[test]
    fn mysockaddr_round_trip() {
        let sa: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let msa = MySockAddr::from(sa);
        assert_eq!(msa.to_socket_addr(), sa);
    }

    // -- DaemonState -------------------------------------------------------

    #[test]
    fn daemon_state_default_values() {
        let state = DaemonState::new();
        assert_eq!(state.cachesize, CACHESIZ as i32);
        assert_eq!(state.ftabsize, FTABSIZ as i32);
        assert_eq!(state.edns_pktsz, EDNS_PKTSZ);
        assert_eq!(state.max_procs, MAX_PROCS as i32);
        assert_eq!(state.port, 53);
        assert_eq!(state.query_port, 0);
        assert!(!state.options.is_set(opt::DEBUG));
        assert_eq!(state.metrics.len(), METRIC_MAX);
        assert!(state.packet.len() >= 4096);
    }
}

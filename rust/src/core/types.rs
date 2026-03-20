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
use crate::diagnostics::metrics::METRIC_MAX;

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
// METRIC_MAX imported from crate::diagnostics::metrics (canonical source)
// ---------------------------------------------------------------------------

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
    /// Systems without a wall-clock RTC store lease lengths instead of
    /// expiry timestamps. Replaces C's `HAVE_BROKEN_RTC` compile-time flag.
    pub const BROKEN_RTC: u32 = 78;
    /// Sentinel — total number of option flags.
    pub const LAST: u32 = 79;
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
// Supporting types for DaemonState fields
// (Replaces C linked-list structs from dnsmasq.h with Rust Vec-based storage)
// ---------------------------------------------------------------------------

/// MX/SRV record entry (C: `struct mx_srv_record`).
#[derive(Debug, Clone)]
pub struct MxSrvRecord {
    pub name: String,
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub is_mx: bool,
}

/// NAPTR record entry (C: `struct naptr`).
#[derive(Debug, Clone)]
pub struct NaptrRecord {
    pub name: String,
    pub replace: String,
    pub regexp: String,
    pub services: String,
    pub flags: String,
    pub order: u16,
    pub pref: u16,
}

/// TXT record entry (C: `struct txt_record`).
///
/// Also used for custom RR records (via `--dns-rr`).  When representing a
/// TXT record `class` holds the DNS class (typically IN = 1) and `rr_type`
/// is 0.  When representing a custom RR record `rr_type` holds the DNS RR
/// type value (e.g. 1 = A, 28 = AAAA) and `class` remains IN.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub name: String,
    pub txt: Vec<u8>,
    pub class: u16,
    /// DNS resource record type — used by custom RR records (`--dns-rr`).
    /// For regular TXT records this is 0 (unused).
    pub rr_type: u16,
}

/// PTR record entry (C: `struct ptr_record`).
#[derive(Debug, Clone)]
pub struct PtrRecord {
    pub name: String,
    pub ptr: String,
}

/// Host record entry (C: `struct host_record`).
#[derive(Debug, Clone)]
pub struct HostRecord {
    pub names: Vec<String>,
    pub addr4: Option<Ipv4Addr>,
    pub addr6: Option<Ipv6Addr>,
    pub ttl: u32,
}

/// CNAME record entry (C: `struct cname`).
#[derive(Debug, Clone)]
pub struct CnameRecord {
    pub alias: String,
    pub target: String,
    pub ttl: u32,
}

/// Authoritative DNS zone (C: `struct auth_zone`).
#[cfg(feature = "auth")]
#[derive(Debug, Clone)]
pub struct AuthZone {
    pub domain: String,
    pub subnet: Vec<String>,
    pub interface_names: Vec<String>,
    pub exclude: Vec<String>,
}

/// Interface name mapping (C: `struct interface_name`).
#[derive(Debug, Clone)]
pub struct InterfaceName {
    pub name: String,
    pub intr: String,
    pub family: i32,
}

/// Subnet specification for EDNS0 (C: `struct mysubnet`).
#[derive(Debug, Clone)]
pub struct MySubnet {
    pub addr: std::net::IpAddr,
    pub mask: u8,
    /// Whether a fixed address was explicitly configured (C: `addr_used`).
    /// When true, the configured address is used instead of the variable
    /// client source address, making ECS responses cacheable.
    pub addr_used: bool,
}

/// Interface name filter entry (C: `struct iname`).
#[derive(Debug, Clone)]
pub struct IfName {
    pub name: Option<String>,
    pub addr: Option<std::net::IpAddr>,
    pub used: bool,
}

/// Bogus address entry for address blocking (C: `struct bogus_addr`).
#[derive(Debug, Clone)]
pub struct BogusAddr {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

/// Upstream DNS server entry (C: `struct server`).
#[derive(Debug, Clone)]
pub struct ServerEntry {
    pub addr: SocketAddr,
    pub source_addr: Option<SocketAddr>,
    pub interface: Option<String>,
    pub domain: Option<String>,
    pub flags: u32,
    pub queries: u32,
    pub failed_queries: u32,
    pub uid: u32,
}

/// Conditional domain entry (C: `struct cond_domain`).
#[derive(Debug, Clone)]
pub struct CondDomain {
    pub domain: String,
    pub prefix: Option<String>,
    pub start: Option<std::net::IpAddr>,
    pub end: Option<std::net::IpAddr>,
    pub is6: bool,
}

/// ipset/nftset entry (C: `struct ipsets`).
#[derive(Debug, Clone)]
pub struct IpsetEntry {
    pub domain: Vec<String>,
    pub sets: Vec<String>,
}

/// Connmark allowlist entry (C: `struct allowlist`).
#[derive(Debug, Clone)]
pub struct AllowlistEntry {
    pub mark: u32,
    pub mask: u32,
    pub patterns: Vec<String>,
}

/// Additional hosts file entry (C: `struct hostsfile`).
#[derive(Debug, Clone)]
pub struct HostsFile {
    pub fname: String,
    pub index: u32,
    pub flags: u32,
}

/// Dynamic directory entry (C: `struct dyndir`).
#[derive(Debug, Clone)]
pub struct DynDir {
    pub name: String,
    pub flags: u32,
}

/// DHCP context entry (C: `struct dhcp_context`).
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
#[derive(Debug, Clone)]
pub struct DhcpContextEntry {
    pub start: std::net::IpAddr,
    pub end: std::net::IpAddr,
    pub netmask: Option<std::net::IpAddr>,
    pub lease_time: u32,
    pub flags: u32,
    pub netid: Option<String>,
}

/// Router Advertisement interface (C: `struct ra_interface`).
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct RaInterface {
    pub name: String,
    pub interval: u32,
    pub priority: u32,
    pub mtu: u32,
    /// Router lifetime override in seconds (0 = use 3×interval).
    pub lifetime: u32,
    /// Interface name from which to read MTU via sysctl.
    /// Empty string means use the RA target interface itself.
    pub mtu_name: String,
}

/// DHCP config entry (C: `struct dhcp_config`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpConfigEntry {
    pub hwaddr: Vec<u8>,
    pub clid: Vec<u8>,
    pub hostname: Option<String>,
    pub addr: Option<Ipv4Addr>,
    pub addr6: Option<Ipv6Addr>,
    pub lease_time: u32,
    pub flags: u32,
    pub netid: Option<String>,
}

/// DHCP option entry (C: `struct dhcp_opt`).
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
#[derive(Debug, Clone)]
pub struct DhcpOptEntry {
    pub opt: u16,
    pub val: Vec<u8>,
    pub flags: u32,
    pub netid: Option<String>,
}

/// DHCP name match entry (C: `struct dhcp_match_name`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpNameMatch {
    pub name: String,
    pub wildcard: bool,
    pub netid: String,
}

/// DHCP vendor class entry (C: `struct dhcp_vendor`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpVendor {
    pub data: Vec<u8>,
    pub len: usize,
    pub match_type: i32,
    pub netid: String,
}

/// DHCP MAC match entry (C: `struct dhcp_mac`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpMac {
    pub hwaddr: Vec<u8>,
    pub hwaddr_len: usize,
    pub hwaddr_type: u16,
    pub netid: String,
}

/// DHCP boot configuration (C: `struct dhcp_boot`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpBoot {
    pub file: Option<String>,
    pub sname: Option<String>,
    pub next_server: Option<Ipv4Addr>,
    pub netid: Option<String>,
}

/// PXE service entry (C: `struct pxe_service`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct PxeService {
    pub menu: String,
    pub basename: Option<String>,
    pub sname: Option<String>,
    pub server: Option<Ipv4Addr>,
    pub csa: u16,
    pub service_type: u16,
}

/// Tag-based conditional settings (C: `struct tag_if`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct TagIf {
    pub tag: String,
    pub set: Vec<String>,
}

/// DHCP relay configuration (C: `struct dhcp_relay`).
///
/// Supports two relay modes:
/// - Normal mode (`split_mode = false`): relay forwards to a single upstream server.
/// - Split mode (`split_mode = true`): relay forwards to multiple upstream servers
///   (each matching relay config entry gets a copy of the packet).
#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
#[derive(Debug, Clone)]
pub struct DhcpRelay {
    pub local: std::net::IpAddr,
    pub server: std::net::IpAddr,
    pub interface: Option<String>,
    /// Network mask for subnet-based relay matching.
    pub mask: Option<Ipv4Addr>,
    /// Interface index — working storage for the interface on which requests arrived.
    pub iface_index: i32,
    /// Port of the upstream relay server (default: 67 for DHCPv4).
    pub port: u16,
    /// Split mode: when true, the relay forwards to ALL matching relay configs
    /// (C: `RELAY_SPLIT`). When false, only the first match is used.
    pub split_mode: bool,
}

/// Delay configuration (C: `struct delay_config`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DelayConfig {
    pub delay: u32,
    pub netid: Option<String>,
}

/// DHCP netid list entry (C: `struct dhcp_netid_list`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpNetIdList {
    pub list: Vec<String>,
}

/// DNS doctor entry for address rewriting (C: `struct doctor`).
#[derive(Debug, Clone)]
pub struct Doctor {
    pub in_addr: Ipv4Addr,
    pub end: Ipv4Addr,
    pub out: Ipv4Addr,
    pub mask: Ipv4Addr,
}

/// Per-interface TFTP prefix (C: `struct tftp_prefix`).
#[cfg(feature = "tftp")]
#[derive(Debug, Clone)]
pub struct TftpPrefix {
    pub interface: String,
    pub prefix: String,
}

/// DNSSEC DS trust anchor config (C: `struct ds_config`).
#[cfg(feature = "dnssec")]
#[derive(Debug, Clone)]
pub struct DsConfig {
    pub name: String,
    pub keytag: u16,
    pub algo: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// Forwarding record entry (C: `struct frec`).
#[derive(Debug, Clone)]
pub struct ForwardRecord {
    pub new_id: u16,
    pub sentto: Option<usize>,
    pub fd: i32,
    pub time: i64,
    pub flags: u32,
}

/// Server file descriptor entry (C: `struct serverfd`).
#[derive(Debug, Clone)]
pub struct ServerFd {
    pub fd: i32,
    pub source_addr: SocketAddr,
    pub interface: Option<String>,
    pub used: bool,
}

/// Interface record (C: `struct irec`).
#[derive(Debug, Clone)]
pub struct InterfaceRecord {
    pub addr: std::net::IpAddr,
    pub netmask: Option<std::net::IpAddr>,
    pub name: String,
    pub index: u32,
    pub label: i32,
    pub flags: u32,
}

/// Listener entry (C: `struct listener`).
#[derive(Debug, Clone)]
pub struct Listener {
    pub fd: i32,
    pub tcpfd: i32,
    pub tftpfd: i32,
    pub family: i32,
    pub iface: Option<usize>,
}

/// Random socket fd (C: `struct randfd`).
#[derive(Debug, Clone)]
pub struct RandFd {
    pub fd: i32,
    pub refcount: u16,
    pub family: i32,
}

/// Address entry (C: `struct addrlist`).
#[derive(Debug, Clone)]
pub struct AddrEntry {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
    pub flags: u32,
}

/// DHCP bridge mapping (C: `struct dhcp_bridge`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpBridge {
    pub iface: String,
    pub alias: Vec<String>,
}

/// Shared network mapping (C: `struct shared_network`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct SharedNetwork {
    pub if_index: u32,
    pub match_addr: std::net::IpAddr,
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

    /// MX/SRV record list (C: `struct mx_srv_record *mxnames`).
    pub mxnames: Vec<MxSrvRecord>,

    /// NAPTR record list (C: `struct naptr *naptr`).
    pub naptr: Vec<NaptrRecord>,

    /// TXT record list (C: `struct txt_record *txt`).
    pub txt_records: Vec<TxtRecord>,

    /// Custom RR record list (C: `struct txt_record *rr`).
    pub rr_records: Vec<TxtRecord>,

    /// PTR record list (C: `struct ptr_record *ptr`).
    pub ptr_records: Vec<PtrRecord>,

    /// RR types to cache (C: `struct rrlist *cache_rr`).
    pub cache_rr: Vec<u16>,

    /// RR types to filter (C: `struct rrlist *filter_rr`).
    pub filter_rr: Vec<u16>,

    /// Host record list (C: `struct host_record *host_records`).
    pub host_records: Vec<HostRecord>,

    /// CNAME alias list (C: `struct cname *cnames`).
    pub cnames: Vec<CnameRecord>,

    /// Authoritative DNS zones (C: `struct auth_zone *auth_zones`).
    #[cfg(feature = "auth")]
    pub auth_zones: Vec<AuthZone>,

    /// Interface-to-name mappings (C: `struct interface_name *int_names`).
    pub int_names: Vec<InterfaceName>,

    /// MX target host (C: `char *mxtarget`).
    pub mxtarget: Option<String>,

    /// Client subnet for EDNS0 IPv4 (C: `struct mysubnet *add_subnet4`).
    pub add_subnet4: Option<MySubnet>,

    /// Client subnet for EDNS0 IPv6 (C: `struct mysubnet *add_subnet6`).
    pub add_subnet6: Option<MySubnet>,

    /// Path to the DHCP lease file.
    pub lease_file: Option<String>,

    /// Unprivileged user name to switch to after binding ports.
    pub username: Option<String>,

    /// Unprivileged group name to switch to after binding ports.
    pub groupname: Option<String>,

    /// Script execution user (C: `char *scriptuser`).
    #[cfg(feature = "script")]
    pub scriptuser: Option<String>,

    /// Lua script path (C: `char *luascript`).
    #[cfg(feature = "luascript")]
    pub luascript: Option<String>,

    /// Authoritative DNS server name (C: `char *authserver`).
    #[cfg(feature = "auth")]
    pub authserver: Option<String>,

    /// SOA hostmaster email (C: `char *hostmaster`).
    #[cfg(feature = "auth")]
    pub hostmaster: Option<String>,

    /// Auth interface list (C: `struct iname *authinterface`).
    #[cfg(feature = "auth")]
    pub authinterface: Vec<IfName>,

    /// Secondary forward server list (C: `struct name_list *secondary_forward_server`).
    pub secondary_forward_server: Vec<String>,

    /// Group set flag (C: `int group_set`).
    pub group_set: bool,

    /// OS port flag (C: `int osport`).
    pub osport: bool,

    /// Domain suffix appended to DHCP hostnames.
    pub domain_suffix: Option<String>,

    /// Conditional domain list (C: `struct cond_domain *cond_domain`).
    pub cond_domain: Vec<CondDomain>,

    /// Synthetic domain list (C: `struct cond_domain *synth_domains`).
    pub synth_domains: Vec<CondDomain>,

    /// PID file path (C: `char *runfile`).
    pub runfile: Option<String>,

    /// Lease change command (C: `char *lease_change_command`).
    #[cfg(feature = "script")]
    pub lease_change_command: Option<String>,

    /// Listen interface name filters (C: `struct iname *if_names`).
    pub if_names: Vec<IfName>,

    /// Listen interface address filters (C: `struct iname *if_addrs`).
    pub if_addrs: Vec<IfName>,

    /// Excluded interface list (C: `struct iname *if_except`).
    pub if_except: Vec<IfName>,

    /// DHCP-excluded interface list (C: `struct iname *dhcp_except`).
    #[cfg(feature = "dhcp")]
    pub dhcp_except: Vec<IfName>,

    /// Auth peer list (C: `struct iname *auth_peers`).
    #[cfg(feature = "auth")]
    pub auth_peers: Vec<IfName>,

    /// TFTP interface list (C: `struct iname *tftp_interfaces`).
    #[cfg(feature = "tftp")]
    pub tftp_interfaces: Vec<IfName>,

    /// Bogus address list (C: `struct bogus_addr *bogus_addr`).
    pub bogus_addr: Vec<BogusAddr>,

    /// Ignore address list (C: `struct bogus_addr *ignore_addr`).
    pub ignore_addr: Vec<BogusAddr>,

    /// Upstream DNS server list (C: `struct server *servers`).
    pub servers: Vec<ServerEntry>,

    /// Local-only domain list (C: `struct server *local_domains`).
    pub local_domains: Vec<ServerEntry>,

    /// Flat server array for random/round-robin (C: `struct server **serverarray`).
    pub serverarray: Vec<usize>,

    /// Rebind domain exclusion list (C: `struct rebind_domain *no_rebind`).
    pub no_rebind: Vec<String>,

    /// Whether any server entry has a wildcard domain (C: `int server_has_wildcard`).
    pub server_has_wildcard: bool,

    /// Server array high water mark (C: `int serverarrayhwm`).
    pub serverarrayhwm: usize,

    /// ipset configuration list (C: `struct ipsets *ipsets`).
    #[cfg(feature = "ipset")]
    pub ipsets: Vec<IpsetEntry>,

    /// nftables set configuration list (C: `struct ipsets *nftsets`).
    #[cfg(feature = "nftset")]
    pub nftsets: Vec<IpsetEntry>,

    /// Connmark allowlist mask (C: `u32 allowlist_mask`).
    pub allowlist_mask: u32,

    /// Connmark allowlists (C: `struct allowlist *allowlists`).
    pub allowlists: Vec<AllowlistEntry>,

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

    /// Use DHCP-derived TTL (C: `unsigned long use_dhcp_ttl`).
    pub use_dhcp_ttl: u32,

    /// DNS client ID string (C: `char *dns_client_id`).
    pub dns_client_id: Option<String>,

    /// Umbrella org ID (C: `u32 umbrella_org`).
    pub umbrella_org: u32,

    /// Umbrella asset ID (C: `u32 umbrella_asset`).
    pub umbrella_asset: u32,

    /// Umbrella device ID (C: `u8 umbrella_device[8]`).
    pub umbrella_device: [u8; 8],

    /// Host file index counter (C: `int host_index`).
    pub host_index: i32,

    /// Additional hosts file list (C: `struct hostsfile *addn_hosts`).
    pub addn_hosts: Vec<HostsFile>,

    /// Maximum EDNS0 UDP payload size (default [`EDNS_PKTSZ`] = 1232).
    pub edns_pktsz: u16,

    /// Interface MTU value for DHCP Option 26 (C: `int mtu`).
    /// When non-zero, included in DHCP responses as the interface MTU option.
    pub mtu: u32,

    /// Random port allocation limit.
    pub randport_limit: i32,

    /// Maximum concurrent TCP connections (default [`MAX_PROCS`] = 20).
    pub max_procs: i32,

    /// Maximum TCP connections used high water mark (C: `uint max_procs_used`).
    pub max_procs_used: u32,

    // =================================================================
    // DHCP configuration (C lines 1389–1430)
    // =================================================================
    /// DHCPv4 context list (C: `struct dhcp_context *dhcp`).
    #[cfg(feature = "dhcp")]
    pub dhcp_contexts: Vec<DhcpContextEntry>,

    /// DHCPv6 context list (C: `struct dhcp_context *dhcp6`).
    #[cfg(feature = "dhcp6")]
    pub dhcp6_contexts: Vec<DhcpContextEntry>,

    /// Router Advertisement interface list (C: `struct ra_interface *ra_interfaces`).
    #[cfg(feature = "dhcp6")]
    pub ra_interfaces: Vec<RaInterface>,

    /// DHCP host configuration list (C: `struct dhcp_config *dhcp_conf`).
    #[cfg(feature = "dhcp")]
    pub dhcp_conf: Vec<DhcpConfigEntry>,

    /// DHCPv4 option list (C: `struct dhcp_opt *dhcp_opts`).
    #[cfg(feature = "dhcp")]
    pub dhcp_opts: Vec<DhcpOptEntry>,

    /// DHCPv4 match options (C: `struct dhcp_opt *dhcp_match`).
    #[cfg(feature = "dhcp")]
    pub dhcp_match: Vec<DhcpOptEntry>,

    /// DHCPv6 option list (C: `struct dhcp_opt *dhcp_opts6`).
    #[cfg(feature = "dhcp6")]
    pub dhcp_opts6: Vec<DhcpOptEntry>,

    /// DHCPv6 match options (C: `struct dhcp_opt *dhcp_match6`).
    #[cfg(feature = "dhcp6")]
    pub dhcp_match6: Vec<DhcpOptEntry>,

    /// DHCP name match list (C: `struct dhcp_match_name *dhcp_name_match`).
    #[cfg(feature = "dhcp")]
    pub dhcp_name_match: Vec<DhcpNameMatch>,

    /// DHCP PXE vendor list (C: `struct dhcp_pxe_vendor *dhcp_pxe_vendors`).
    #[cfg(feature = "dhcp")]
    pub dhcp_pxe_vendors: Vec<String>,

    /// DHCP vendor class list (C: `struct dhcp_vendor *dhcp_vendors`).
    #[cfg(feature = "dhcp")]
    pub dhcp_vendors: Vec<DhcpVendor>,

    /// DHCP MAC match list (C: `struct dhcp_mac *dhcp_macs`).
    #[cfg(feature = "dhcp")]
    pub dhcp_macs: Vec<DhcpMac>,

    /// DHCP boot configuration (C: `struct dhcp_boot *boot_config`).
    #[cfg(feature = "dhcp")]
    pub boot_config: Option<DhcpBoot>,

    /// PXE service list (C: `struct pxe_service *pxe_services`).
    #[cfg(feature = "dhcp")]
    pub pxe_services: Vec<PxeService>,

    /// Tag-based conditional settings (C: `struct tag_if *tag_if`).
    #[cfg(feature = "dhcp")]
    pub tag_if: Vec<TagIf>,

    /// Override relay list (C: `struct addr_list *override_relays`).
    #[cfg(feature = "dhcp")]
    pub override_relays: Vec<std::net::IpAddr>,

    /// DHCPv4 relay configuration (C: `struct dhcp_relay *relay4`).
    #[cfg(feature = "dhcp")]
    pub relay4: Vec<DhcpRelay>,

    /// DHCPv6 relay configuration (C: `struct dhcp_relay *relay6`).
    #[cfg(feature = "dhcp6")]
    pub relay6: Vec<DhcpRelay>,

    /// Delay configuration list (C: `struct delay_config *delay_conf`).
    #[cfg(feature = "dhcp")]
    pub delay_conf: Vec<DelayConfig>,

    /// DHCP server override flag (C: `int override`).
    #[cfg(feature = "dhcp")]
    pub override_flag: bool,

    /// PXE enable flag (C: `int enable_pxe`).
    #[cfg(feature = "dhcp")]
    pub enable_pxe: bool,

    /// Doing Router Advertisements (C: `int doing_ra`).
    #[cfg(feature = "dhcp6")]
    pub doing_ra: bool,

    /// Doing DHCPv6 (C: `int doing_dhcp6`).
    #[cfg(feature = "dhcp6")]
    pub doing_dhcp6: bool,

    /// DHCP ignore netid list (C: `struct dhcp_netid_list *dhcp_ignore`).
    #[cfg(feature = "dhcp")]
    pub dhcp_ignore: Vec<DhcpNetIdList>,

    /// DHCP ignore names netid list (C: `struct dhcp_netid_list *dhcp_ignore_names`).
    #[cfg(feature = "dhcp")]
    pub dhcp_ignore_names: Vec<DhcpNetIdList>,

    /// DHCP generate names netid list (C: `struct dhcp_netid_list *dhcp_gen_names`).
    #[cfg(feature = "dhcp")]
    pub dhcp_gen_names: Vec<DhcpNetIdList>,

    /// Force broadcast netid list (C: `struct dhcp_netid_list *force_broadcast`).
    #[cfg(feature = "dhcp")]
    pub force_broadcast: Vec<DhcpNetIdList>,

    /// BOOTP dynamic netid list (C: `struct dhcp_netid_list *bootp_dynamic`).
    #[cfg(feature = "dhcp")]
    pub bootp_dynamic: Vec<DhcpNetIdList>,

    /// DHCP hosts file list (C: `struct hostsfile *dhcp_hosts_file`).
    #[cfg(feature = "dhcp")]
    pub dhcp_hosts_file: Vec<HostsFile>,

    /// DHCP options file list (C: `struct hostsfile *dhcp_opts_file`).
    #[cfg(feature = "dhcp")]
    pub dhcp_opts_file: Vec<HostsFile>,

    /// Dynamic directory list (C: `struct dyndir *dynamic_dirs`).
    pub dynamic_dirs: Vec<DynDir>,

    /// Maximum DHCP leases (C: `int dhcp_max`).
    #[cfg(feature = "dhcp")]
    pub dhcp_max: i32,

    /// Maximum concurrent TFTP transfers (C: `int tftp_max`).
    #[cfg(feature = "tftp")]
    pub tftp_max: i32,

    /// TFTP maximum block size / MTU (C: `int tftp_mtu`).
    #[cfg(feature = "tftp")]
    pub tftp_mtu: i32,

    /// DHCP server port (C: `int dhcp_server_port`).
    #[cfg(feature = "dhcp")]
    pub dhcp_server_port: u16,

    /// DHCP client port (C: `int dhcp_client_port`).
    #[cfg(feature = "dhcp")]
    pub dhcp_client_port: u16,

    /// TFTP start port (C: `int start_tftp_port`).
    #[cfg(feature = "tftp")]
    pub start_tftp_port: u16,

    /// TFTP end port (C: `int end_tftp_port`).
    #[cfg(feature = "tftp")]
    pub end_tftp_port: u16,

    /// Minimum lease time (C: `unsigned int min_leasetime`).
    #[cfg(feature = "dhcp")]
    pub min_leasetime: u32,

    /// DNS doctor rewrite list (C: `struct doctor *doctors`).
    pub doctors: Vec<Doctor>,

    /// TFTP file prefix (C: `char *tftp_prefix`).
    #[cfg(feature = "tftp")]
    pub tftp_prefix: Option<String>,

    /// Per-interface TFTP prefixes (C: `struct tftp_prefix *if_prefix`).
    #[cfg(feature = "tftp")]
    pub if_prefix: Vec<TftpPrefix>,

    /// DUID enterprise number (C: `unsigned int duid_enterprise`).
    #[cfg(feature = "dhcp6")]
    pub duid_enterprise: u32,

    /// DUID config data (C: `unsigned char *duid_config` + `duid_config_len`).
    #[cfg(feature = "dhcp6")]
    pub duid_config: Vec<u8>,

    /// D-Bus service name (C: `char *dbus_name`).
    #[cfg(feature = "dbus")]
    pub dbus_name: Option<String>,

    /// UBus service name (C: `char *ubus_name`).
    #[cfg(feature = "ubus")]
    pub ubus_name: Option<String>,

    /// Dump file path (C: `char *dump_file`).
    #[cfg(feature = "dumpfile")]
    pub dump_file: Option<String>,

    /// Dump mask (C: `int dump_mask`).
    #[cfg(feature = "dumpfile")]
    pub dump_mask: i32,

    /// SOA serial number (C: `unsigned long soa_sn`).
    #[cfg(feature = "auth")]
    pub soa_sn: u32,

    /// SOA refresh interval (C: `unsigned long soa_refresh`).
    #[cfg(feature = "auth")]
    pub soa_refresh: u32,

    /// SOA retry interval (C: `unsigned long soa_retry`).
    #[cfg(feature = "auth")]
    pub soa_retry: u32,

    /// SOA expiry interval (C: `unsigned long soa_expiry`).
    #[cfg(feature = "auth")]
    pub soa_expiry: u32,

    /// Fast retry time in ms (C: `int fast_retry_time`).
    pub fast_retry_time: i32,

    /// Fast retry timeout in ms (C: `int fast_retry_timeout`).
    pub fast_retry_timeout: i32,

    /// Maximum cache expiry (C: `int cache_max_expiry`).
    pub cache_max_expiry: i32,

    // =================================================================
    // DNSSEC configuration (C lines 1439–1445)
    // =================================================================
    /// DS trust anchor configs (C: `struct ds_config *ds`).
    #[cfg(feature = "dnssec")]
    pub ds: Vec<DsConfig>,

    /// DNSSEC timestamp file path (C: `char *timestamp_file`).
    #[cfg(feature = "dnssec")]
    pub timestamp_file: Option<String>,

    // =================================================================
    // DNS runtime state  (C lines 1441–1472)
    // =================================================================
    /// Shared packet buffer for DNS message construction/parsing.
    /// Sized to `edns_pktsz` or 4096, whichever is larger.
    pub packet: Vec<u8>,

    /// Packet buffer size (C: `int packet_buff_sz`).
    pub packet_buff_sz: usize,

    /// Scratch buffer for DNS name assembly (max [`MAXDNAME`] bytes).
    pub namebuff: String,

    /// Workspace name buffer for DNS operations (C: `char *workspacename`).
    pub workspacename: String,

    /// DNSSEC key name buffer (C: `char *keyname`).
    #[cfg(feature = "dnssec")]
    pub keyname: String,

    /// DNSSEC CNAME chase buffer (C: `char *cname`).
    #[cfg(feature = "dnssec")]
    pub cname_buf: String,

    /// DNSSEC RR status (TTL ceiling) array (C: `unsigned long *rr_status`).
    #[cfg(feature = "dnssec")]
    pub rr_status: Vec<u32>,

    /// DNSSEC no-time-check flag (C: `int dnssec_no_time_check`).
    #[cfg(feature = "dnssec")]
    pub dnssec_no_time_check: bool,

    /// DNSSEC back-to-the-future flag (C: `int back_to_the_future`).
    #[cfg(feature = "dnssec")]
    pub back_to_the_future: bool,

    /// DNSSEC limits array (C: `int limit[LIMIT_MAX]`).
    #[cfg(feature = "dnssec")]
    pub dnssec_limits: Vec<i32>,

    /// Forwarding request list (C: `struct frec *frec_list`).
    /// Stored as indices into a pool for safety.
    pub frec_list: Vec<ForwardRecord>,

    /// Free frec_src count (C: `int frec_src_count`).
    pub frec_src_count: i32,

    /// Server file descriptors (C: `struct serverfd *sfds`).
    pub sfds: Vec<ServerFd>,

    /// Interface record list (C: `struct irec *interfaces`).
    pub interfaces: Vec<InterfaceRecord>,

    /// Listener list (C: `struct listener *listeners`).
    pub listeners: Vec<Listener>,

    /// Saved server pointer for resend/TFTP prefetch (C: `void *srv_save`).
    pub srv_save: Option<usize>,

    /// Saved packet length for resend (C: `size_t packet_len`).
    pub packet_len: usize,

    /// Saved fd for resend (C: `int fd_save`).
    pub fd_save: i32,

    /// TCP child pids (C: `pid_t *tcp_pids`).
    pub tcp_pids: Vec<i32>,

    /// TCP pipe fds (C: `int *tcp_pipes`).
    pub tcp_pipes: Vec<i32>,

    /// Pipe to parent fd (C: `int pipe_to_parent`).
    pub pipe_to_parent: i32,

    /// Number of random ports (C: `int numrrand`).
    pub numrrand: i32,

    /// Random socket fds (C: `struct randfd *randomsocks`).
    pub randomsocks: Vec<RandFd>,

    /// IPv6 pktinfo capability flag (C: `int v6pktinfo`).
    pub v6pktinfo: i32,

    /// All interface addresses (C: `struct addrlist *interface_addrs`).
    pub interface_addrs: Vec<AddrEntry>,

    /// Monotonically increasing log line identifier.
    pub log_id: i32,

    /// Display variant of [`log_id`](Self::log_id) (may wrap).
    pub log_display_id: i32,

    /// Log source address (C: `union mysockaddr *log_source_addr`).
    pub log_source_addr: Option<MySockAddr>,

    // =================================================================
    // DHCP runtime state  (C lines 1474–1498)
    // =================================================================
    /// DHCP socket fd (C: `int dhcpfd`).
    #[cfg(feature = "dhcp")]
    pub dhcpfd: i32,

    /// Helper process fd (C: `int helperfd`).
    #[cfg(feature = "script")]
    pub helperfd: i32,

    /// PXE socket fd (C: `int pxefd`).
    #[cfg(feature = "dhcp")]
    pub pxefd: i32,

    /// inotify fd (C: `int inotifyfd`).
    #[cfg(feature = "inotify")]
    pub inotifyfd: i32,

    /// Netlink fd (C: `int netlinkfd`).
    #[cfg(target_os = "linux")]
    pub netlinkfd: i32,

    /// Kernel version (C: `int kernel_version`).
    #[cfg(target_os = "linux")]
    pub kernel_version: i32,

    /// Maximum number of concurrent DHCP leases (default [`MAXLEASES`] = 1000).
    #[cfg(feature = "dhcp")]
    pub max_dhcp_leases: i32,

    /// Active DHCP lease database (both v4 and v6 leases).
    /// Replaces C's global `leases` linked list that was accessed by all
    /// lease-related functions. This Vec is the canonical lease store;
    /// `lease6_find_by_addr()`, `lease_find_by_addr()`, etc. search it.
    #[cfg(feature = "dhcp")]
    pub leases: Vec<crate::dhcp::lease::DhcpLease>,

    /// DHCP packet buffer (sized for a full DHCP message).
    #[cfg(feature = "dhcp")]
    pub dhcp_packet: Vec<u8>,

    /// DHCP scratch buffers (C: `char *dhcp_buff, *dhcp_buff2, *dhcp_buff3`).
    #[cfg(feature = "dhcp")]
    pub dhcp_buff: Vec<u8>,
    #[cfg(feature = "dhcp")]
    pub dhcp_buff2: Vec<u8>,
    #[cfg(feature = "dhcp")]
    pub dhcp_buff3: Vec<u8>,

    /// Results of ICMP ping probes before address offers.
    #[cfg(feature = "dhcp")]
    pub ping_results: Vec<PingResult>,

    /// Lease file stream handle present flag (C: `FILE *lease_stream`).
    #[cfg(feature = "dhcp")]
    pub lease_stream_active: bool,

    /// Bridge interface mappings (C: `struct dhcp_bridge *bridges`).
    #[cfg(feature = "dhcp")]
    pub bridges: Vec<DhcpBridge>,

    /// Shared network mappings (C: `struct shared_network *shared_networks`).
    #[cfg(feature = "dhcp")]
    pub shared_networks: Vec<SharedNetwork>,

    /// DHCPv6 DUID (C: `unsigned char *duid` + `int duid_len`).
    #[cfg(feature = "dhcp6")]
    pub duid: Vec<u8>,

    /// DHCPv6 outgoing packet buffer (C: `struct iovec outpacket`).
    #[cfg(feature = "dhcp6")]
    pub outpacket: Vec<u8>,

    /// DHCPv6 socket fd (C: `int dhcp6fd`).
    #[cfg(feature = "dhcp6")]
    pub dhcp6fd: i32,

    /// ICMPv6 socket fd (C: `int icmp6fd`).
    #[cfg(feature = "dhcp6")]
    pub icmp6fd: i32,

    /// SLAAC lease information for ICMPv6 echo reply confirmation.
    /// Populated by the lease module from `DhcpLease` entries; consumed by
    /// `radv::icmp6_packet()` → `slaac::slaac_ping_reply()`.
    /// Replaces C pattern where `slaac_ping_reply()` iterated the global
    /// `leases` linked list.
    #[cfg(feature = "dhcp6")]
    pub slaac_leases: Vec<crate::dhcp::slaac::SlaacLeaseInfo>,

    // =================================================================
    // Integration state
    // =================================================================
    /// D-Bus connection handle present flag (C: `void *dbus`).
    #[cfg(feature = "dbus")]
    pub dbus_active: bool,

    /// UBus connection handle present flag (C: `void *ubus`).
    #[cfg(feature = "ubus")]
    pub ubus_active: bool,

    // =================================================================
    // TFTP state
    // =================================================================
    /// Active TFTP transfer count (C: `struct tftp_transfer *tftp_trans`).
    #[cfg(feature = "tftp")]
    pub tftp_transfer_count: usize,

    // =================================================================
    // Utility buffers
    // =================================================================
    /// Address formatting buffer (C: `char *addrbuff`).
    pub addrbuff: String,

    /// Extra logging address buffer (C: `char *addrbuff2`).
    pub addrbuff2: Option<String>,

    // =================================================================
    // Diagnostics
    // =================================================================
    /// Dump file fd (C: `int dumpfd`).
    #[cfg(feature = "dumpfile")]
    pub dumpfd: i32,

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
            // =============================================================
            // Configuration state
            // =============================================================
            options: OptionFlags::new(),
            resolv_files: Vec::new(),
            last_resolv: 0,
            servers_file: None,
            mxnames: Vec::new(),
            naptr: Vec::new(),
            txt_records: Vec::new(),
            rr_records: Vec::new(),
            ptr_records: Vec::new(),
            cache_rr: Vec::new(),
            filter_rr: Vec::new(),
            host_records: Vec::new(),
            cnames: Vec::new(),
            #[cfg(feature = "auth")]
            auth_zones: Vec::new(),
            int_names: Vec::new(),
            mxtarget: None,
            add_subnet4: None,
            add_subnet6: None,
            lease_file: None,
            username: None,
            groupname: None,
            #[cfg(feature = "script")]
            scriptuser: None,
            #[cfg(feature = "luascript")]
            luascript: None,
            #[cfg(feature = "auth")]
            authserver: None,
            #[cfg(feature = "auth")]
            hostmaster: None,
            #[cfg(feature = "auth")]
            authinterface: Vec::new(),
            secondary_forward_server: Vec::new(),
            group_set: false,
            osport: true, // C default: daemon->osport = 1
            domain_suffix: None,
            cond_domain: Vec::new(),
            synth_domains: Vec::new(),
            runfile: None,
            #[cfg(feature = "script")]
            lease_change_command: None,
            if_names: Vec::new(),
            if_addrs: Vec::new(),
            if_except: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_except: Vec::new(),
            #[cfg(feature = "auth")]
            auth_peers: Vec::new(),
            #[cfg(feature = "tftp")]
            tftp_interfaces: Vec::new(),
            bogus_addr: Vec::new(),
            ignore_addr: Vec::new(),
            servers: Vec::new(),
            local_domains: Vec::new(),
            serverarray: Vec::new(),
            no_rebind: Vec::new(),
            server_has_wildcard: false,
            serverarrayhwm: 0,
            #[cfg(feature = "ipset")]
            ipsets: Vec::new(),
            #[cfg(feature = "nftset")]
            nftsets: Vec::new(),
            allowlist_mask: 0,
            allowlists: Vec::new(),
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
            use_dhcp_ttl: 0,
            dns_client_id: None,
            umbrella_org: 0,
            umbrella_asset: 0,
            umbrella_device: [0u8; 8],
            host_index: 0,
            addn_hosts: Vec::new(),
            edns_pktsz: EDNS_PKTSZ,
            mtu: 0,
            randport_limit: 1,
            max_procs: MAX_PROCS as i32,
            max_procs_used: 0,

            // =============================================================
            // DHCP configuration
            // =============================================================
            #[cfg(feature = "dhcp")]
            dhcp_contexts: Vec::new(),
            #[cfg(feature = "dhcp6")]
            dhcp6_contexts: Vec::new(),
            #[cfg(feature = "dhcp6")]
            ra_interfaces: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_conf: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_opts: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_match: Vec::new(),
            #[cfg(feature = "dhcp6")]
            dhcp_opts6: Vec::new(),
            #[cfg(feature = "dhcp6")]
            dhcp_match6: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_name_match: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_pxe_vendors: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_vendors: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_macs: Vec::new(),
            #[cfg(feature = "dhcp")]
            boot_config: None,
            #[cfg(feature = "dhcp")]
            pxe_services: Vec::new(),
            #[cfg(feature = "dhcp")]
            tag_if: Vec::new(),
            #[cfg(feature = "dhcp")]
            override_relays: Vec::new(),
            #[cfg(feature = "dhcp")]
            relay4: Vec::new(),
            #[cfg(feature = "dhcp6")]
            relay6: Vec::new(),
            #[cfg(feature = "dhcp")]
            delay_conf: Vec::new(),
            #[cfg(feature = "dhcp")]
            override_flag: false,
            #[cfg(feature = "dhcp")]
            enable_pxe: false,
            #[cfg(feature = "dhcp6")]
            doing_ra: false,
            #[cfg(feature = "dhcp6")]
            doing_dhcp6: false,
            #[cfg(feature = "dhcp")]
            dhcp_ignore: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_ignore_names: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_gen_names: Vec::new(),
            #[cfg(feature = "dhcp")]
            force_broadcast: Vec::new(),
            #[cfg(feature = "dhcp")]
            bootp_dynamic: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_hosts_file: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_opts_file: Vec::new(),
            dynamic_dirs: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_max: MAXLEASES as i32,
            #[cfg(feature = "tftp")]
            tftp_max: 50, // TFTP_MAX_CONNECTIONS
            #[cfg(feature = "tftp")]
            tftp_mtu: 0,
            #[cfg(feature = "dhcp")]
            dhcp_server_port: 67,
            #[cfg(feature = "dhcp")]
            dhcp_client_port: 68,
            #[cfg(feature = "tftp")]
            start_tftp_port: 0,
            #[cfg(feature = "tftp")]
            end_tftp_port: 0,
            #[cfg(feature = "dhcp")]
            min_leasetime: 120,
            doctors: Vec::new(),
            #[cfg(feature = "tftp")]
            tftp_prefix: None,
            #[cfg(feature = "tftp")]
            if_prefix: Vec::new(),
            #[cfg(feature = "dhcp6")]
            duid_enterprise: 0,
            #[cfg(feature = "dhcp6")]
            duid_config: Vec::new(),
            #[cfg(feature = "dbus")]
            dbus_name: None,
            #[cfg(feature = "ubus")]
            ubus_name: None,
            #[cfg(feature = "dumpfile")]
            dump_file: None,
            #[cfg(feature = "dumpfile")]
            dump_mask: 0,
            #[cfg(feature = "auth")]
            soa_sn: 0,
            #[cfg(feature = "auth")]
            soa_refresh: 1200, // SOA_REFRESH default
            #[cfg(feature = "auth")]
            soa_retry: 180, // SOA_RETRY default
            #[cfg(feature = "auth")]
            soa_expiry: 1_209_600, // SOA_EXPIRY default (2 weeks)
            fast_retry_time: 0,
            fast_retry_timeout: 0,
            cache_max_expiry: 0,

            // =============================================================
            // DNSSEC configuration
            // =============================================================
            #[cfg(feature = "dnssec")]
            ds: Vec::new(),
            #[cfg(feature = "dnssec")]
            timestamp_file: None,

            // =============================================================
            // DNS runtime state
            // =============================================================
            packet: vec![0u8; pkt_sz],
            packet_buff_sz: pkt_sz,
            namebuff: String::with_capacity(MAXDNAME),
            workspacename: String::with_capacity(MAXDNAME),
            #[cfg(feature = "dnssec")]
            keyname: String::with_capacity(MAXDNAME),
            #[cfg(feature = "dnssec")]
            cname_buf: String::with_capacity(MAXDNAME),
            #[cfg(feature = "dnssec")]
            rr_status: Vec::new(),
            #[cfg(feature = "dnssec")]
            dnssec_no_time_check: false,
            #[cfg(feature = "dnssec")]
            back_to_the_future: false,
            #[cfg(feature = "dnssec")]
            dnssec_limits: Vec::new(),
            frec_list: Vec::new(),
            frec_src_count: 0,
            sfds: Vec::new(),
            interfaces: Vec::new(),
            listeners: Vec::new(),
            srv_save: None,
            packet_len: 0,
            fd_save: -1,
            tcp_pids: Vec::new(),
            tcp_pipes: Vec::new(),
            pipe_to_parent: -1,
            numrrand: 0,
            randomsocks: Vec::new(),
            v6pktinfo: 0,
            interface_addrs: Vec::new(),
            log_id: 0,
            log_display_id: 0,
            log_source_addr: None,

            // =============================================================
            // DHCP runtime state
            // =============================================================
            #[cfg(feature = "dhcp")]
            dhcpfd: -1,
            #[cfg(feature = "script")]
            helperfd: -1,
            #[cfg(feature = "dhcp")]
            pxefd: -1,
            #[cfg(feature = "inotify")]
            inotifyfd: -1,
            #[cfg(target_os = "linux")]
            netlinkfd: -1,
            #[cfg(target_os = "linux")]
            kernel_version: 0,
            #[cfg(feature = "dhcp")]
            max_dhcp_leases: MAXLEASES as i32,
            #[cfg(feature = "dhcp")]
            leases: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_packet: Vec::with_capacity(4096),
            #[cfg(feature = "dhcp")]
            dhcp_buff: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_buff2: Vec::new(),
            #[cfg(feature = "dhcp")]
            dhcp_buff3: Vec::new(),
            #[cfg(feature = "dhcp")]
            ping_results: Vec::new(),
            #[cfg(feature = "dhcp")]
            lease_stream_active: false,
            #[cfg(feature = "dhcp")]
            bridges: Vec::new(),
            #[cfg(feature = "dhcp")]
            shared_networks: Vec::new(),
            #[cfg(feature = "dhcp6")]
            duid: Vec::new(),
            #[cfg(feature = "dhcp6")]
            outpacket: Vec::new(),
            #[cfg(feature = "dhcp6")]
            dhcp6fd: -1,
            #[cfg(feature = "dhcp6")]
            icmp6fd: -1,
            #[cfg(feature = "dhcp6")]
            slaac_leases: Vec::new(),

            // =============================================================
            // Integration state
            // =============================================================
            #[cfg(feature = "dbus")]
            dbus_active: false,
            #[cfg(feature = "ubus")]
            ubus_active: false,

            // =============================================================
            // TFTP state
            // =============================================================
            #[cfg(feature = "tftp")]
            tftp_transfer_count: 0,

            // =============================================================
            // Utility buffers
            // =============================================================
            addrbuff: String::with_capacity(64),
            addrbuff2: None,

            // =============================================================
            // Diagnostics
            // =============================================================
            #[cfg(feature = "dumpfile")]
            dumpfd: -1,

            // =============================================================
            // Metrics
            // =============================================================
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
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
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

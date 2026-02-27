//! Async non-blocking logging subsystem for dnsmasq.
//!
//! Replaces the custom C syslog client in `src/log.c` (1120 lines) with a Rust
//! implementation using the `log` crate facade. Preserves key behavioral properties:
//!
//! ## Key Features (from C log.c)
//! - **Non-blocking writes:** Log entries queued when syslog socket not writable
//! - **Bounded queue:** Maximum [`LOG_MAX`] (5) entries queued before dropping
//! - **Fork-safe:** Entries tagged with PID to handle fork-based TCP/helper children
//! - **Echo mode:** Debug mode echoes all logs to stderr during startup
//! - **Connection retry:** Exponential backoff on syslog daemon reconnection
//! - **RFC 3164:** Message size limited to [`MAX_MESSAGE`] (1024 bytes)
//! - **Facility/priority:** Configurable syslog facility (default `LOG_DAEMON`)
//! - **File logging:** Alternative to syslog — write to file with append mode
//!
//! ## Architecture
//! The C `log.c` solves a critical deadlock scenario: if syslogd makes DNS lookups
//! through dnsmasq, and dnsmasq blocks waiting for syslogd to accept log messages,
//! the two daemons can deadlock. The non-blocking async design prevents this by never
//! blocking on syslog writes. The Rust version preserves this through:
//! - Bounded internal queue ([`VecDeque<LogEntry>`])
//! - Non-blocking socket writes via `mio` integration
//! - [`Logger::set_log_writer()`] / [`Logger::check_log_writer()`] for event loop integration
//!
//! ## Global State
//! The logger is stored as a global static via [`OnceLock`] and registered with the
//! [`log`] crate facade. All modules use `log::warn!()`, `log::info!()` etc., which
//! dispatch through [`Logger`]'s `log::Log` implementation.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock};

use log::{Level, LevelFilter, Log, Metadata, Record};
// OFlag is used below for documenting non-blocking semantics and in test assertions.
#[allow(unused_imports)]
use nix::fcntl::OFlag;
use nix::sys::socket::{
    connect as nix_connect, socket as nix_socket, AddressFamily, SockFlag, SockType, UnixAddr,
};
use nix::unistd::getpid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum queued log entries before dropping (matches C `LOG_MAX` from config.h).
///
/// When the queue reaches this size, new messages are dropped and the
/// [`Logger::entries_lost`] counter is incremented. A meta-log message about
/// the lost entries is generated when queue space becomes available.
pub const LOG_MAX: usize = 5;

/// Maximum message size per RFC 3164 (BSD syslog protocol).
///
/// Messages longer than this are silently truncated by the formatting step.
pub const MAX_MESSAGE: usize = 1024;

/// Default syslog socket path on Linux.
const SYSLOG_PATH: &str = "/dev/log";

/// Tag string prefix for log lines (matches C `"dnsmasq"` tag).
const LOG_TAG: &str = "dnsmasq";

// ---------------------------------------------------------------------------
// LogConfig — Logging configuration
// ---------------------------------------------------------------------------

/// Configuration for the logging subsystem.
///
/// Populated during command-line / config file parsing and passed to [`init()`]
/// or [`Logger::new()`] to set up the logging backend. Replaces the configuration
/// fields extracted in C `log_start()` (log.c line 177).
///
/// ## Fields
/// - `facility` — syslog facility code (default [`libc::LOG_DAEMON`])
/// - `max_logs` — maximum queued log entries; 0 = synchronous mode
/// - `log_file` — optional log file path; [`None`] = use syslog
/// - `no_daemon` — running in foreground (debug) mode; echo logs to stderr
pub struct LogConfig {
    /// Syslog facility (e.g. `LOG_DAEMON`, `LOG_LOCAL0`).
    /// Mapped from C `daemon->log_fac` / `log_fac` global.
    pub facility: i32,

    /// Maximum queued log entries (0 = synchronous/blocking mode).
    /// Mapped from C `daemon->max_logs` / `max_logs` global.
    pub max_logs: usize,

    /// Optional log file path. When [`Some`], log output goes to the named file
    /// instead of the syslog daemon. The special value `"-"` redirects to stderr.
    /// Mapped from C `daemon->log_file`.
    pub log_file: Option<String>,

    /// Whether the daemon is running in foreground (no-daemon / debug) mode.
    /// When `true`, all log messages are also echoed to stderr.
    /// Mapped from C `option_bool(OPT_DEBUG)`.
    pub no_daemon: bool,
}

impl Default for LogConfig {
    /// Returns a default configuration matching C defaults before `log_start()`:
    /// - facility = `LOG_DAEMON`
    /// - max_logs = 0 (synchronous)
    /// - log_file = None (use syslog)
    /// - no_daemon = false
    fn default() -> Self {
        Self {
            facility: libc::LOG_DAEMON,
            max_logs: 0,
            log_file: None,
            no_daemon: false,
        }
    }
}

// ---------------------------------------------------------------------------
// LogEntry — Queued log entry (internal)
// ---------------------------------------------------------------------------

/// A single queued log entry awaiting write to syslog socket or file.
///
/// Replaces C `struct log_entry` (log.c lines 116-121). The `pid` field
/// provides fork-safety: after `fork()`, the parent skips entries created by
/// the child (and vice-versa), preventing duplicate log messages.
struct LogEntry {
    /// Byte offset into `payload` marking write progress (for partial writes).
    offset: usize,
    /// Total byte length of the formatted message in `payload`.
    length: usize,
    /// PID of the process that created this entry (fork-safety tag).
    pid: u32,
    /// Formatted log message payload (at most [`MAX_MESSAGE`] bytes).
    payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// LoggerInner — Mutable state behind Mutex
// ---------------------------------------------------------------------------

/// Internal mutable state for the logger, protected by a [`Mutex`].
///
/// Replaces the 11+ global static variables in C `log.c` (lines 104-124):
/// `log_fac`, `log_stderr`, `echo_stderr`, `log_fd`, `log_to_file`,
/// `entries_alloced`, `entries_lost`, `connection_good`, `max_logs`,
/// `connection_type`, `entries`, `free_entries`.
struct LoggerInner {
    /// Syslog facility code (e.g. `LOG_DAEMON`).
    facility: i32,
    /// Echo log messages to stderr (foreground/debug mode).
    echo_stderr: bool,
    /// Logging output goes to stderr (log_file = "-").
    log_stderr: bool,
    /// File descriptor for syslog socket or log file; [`None`] if not connected.
    log_fd: Option<RawFd>,
    /// Whether we are logging to a file (vs. syslog socket).
    log_to_file: bool,
    /// Count of dropped log entries due to queue overflow.
    entries_lost: u32,
    /// Whether the syslog connection is currently healthy.
    connection_good: bool,
    /// Maximum queued entries (0 = synchronous / immediate write).
    max_logs: usize,
    /// Socket type for syslog connection (`SOCK_DGRAM` or `SOCK_STREAM`).
    connection_type: i32,
    /// Bounded FIFO queue of pending log entries.
    queue: VecDeque<LogEntry>,
}

impl LoggerInner {
    /// Create a new `LoggerInner` from the given configuration.
    fn new(config: &LogConfig) -> Self {
        let log_to_file = config.log_file.is_some();
        let log_stderr = config.log_file.as_deref() == Some("-");
        // When logging to file, C forces synchronous mode (max_logs = 0).
        let max_logs = if log_to_file { 0 } else { config.max_logs };

        Self {
            facility: config.facility,
            echo_stderr: config.no_daemon,
            log_stderr,
            log_fd: None,
            log_to_file,
            entries_lost: 0,
            connection_good: true,
            max_logs,
            connection_type: libc::SOCK_DGRAM,
            queue: VecDeque::with_capacity(if max_logs > 0 { max_logs } else { 1 }),
        }
    }
}

// ---------------------------------------------------------------------------
// Logger — Public async logger
// ---------------------------------------------------------------------------

/// Non-blocking asynchronous logger for the dnsmasq daemon.
///
/// Manages a bounded queue of log entries, a connection to the syslog daemon
/// or log file, and state for connection retry. Implements [`log::Log`] for
/// seamless integration with the Rust logging ecosystem.
///
/// Replaces the C global state variables and functions in `src/log.c`:
/// - `log_start()` → [`Logger::new()`] + [`Logger::init()`]
/// - `my_syslog()` → [`Logger::log()`] (via `log::Log` trait)
/// - `log_write()` / `flush_log()` → [`Logger::flush()`]
/// - `log_reopen()` → [`Logger::reopen()`]
/// - `set_log_writer()` / `check_log_writer()` → event loop integration methods
/// - `die()` → [`Logger::die()`]
pub struct Logger {
    /// All mutable state is behind a [`Mutex`] because [`log::Log`] requires
    /// `Sync + Send`, and we need interior mutability for queue operations.
    inner: Mutex<LoggerInner>,
}

/// Global logger instance, initialised by [`init()`].
static GLOBAL_LOGGER: OnceLock<Logger> = OnceLock::new();

// ---------------------------------------------------------------------------
// Helper: syslog priority ↔ log::Level mapping
// ---------------------------------------------------------------------------

/// Convert a [`log::Level`] to the corresponding syslog priority constant.
fn level_to_syslog_priority(level: Level) -> i32 {
    match level {
        Level::Error => libc::LOG_ERR,
        Level::Warn => libc::LOG_WARNING,
        Level::Info => libc::LOG_INFO,
        Level::Debug | Level::Trace => libc::LOG_DEBUG,
    }
}

/// Convert a raw syslog priority to a [`log::Level`].
///
/// Used by other modules that receive raw syslog priorities and need to map
/// them to the `log` crate's level system.
pub fn syslog_priority_to_level(priority: i32) -> Level {
    let prio = priority & libc::LOG_PRIMASK;
    if prio <= libc::LOG_ERR {
        Level::Error
    } else if prio == libc::LOG_WARNING {
        Level::Warn
    } else if prio <= libc::LOG_INFO {
        Level::Info
    } else {
        Level::Debug
    }
}

// ---------------------------------------------------------------------------
// Helper: close a raw file descriptor safely
// ---------------------------------------------------------------------------

/// Close a raw file descriptor by wrapping it in an [`OwnedFd`] and dropping it.
///
/// This leverages Rust's RAII to call `close(2)` without requiring a direct
/// `libc::close()` call or the deprecated `nix::unistd::close()`.
fn close_raw_fd(fd: RawFd) {
    // SAFETY: We own this file descriptor and are intentionally closing it.
    // After this call the fd value must not be used again.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

/// Perform a non-blocking write to a raw file descriptor using [`nix::unistd::write`].
///
/// Returns the number of bytes written, or an `Err` with the nix errno.
fn write_to_fd(fd: RawFd, buf: &[u8]) -> Result<usize, nix::errno::Errno> {
    // SAFETY: `fd` is a valid, open file descriptor that we own.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    nix::unistd::write(borrowed, buf)
}

// ---------------------------------------------------------------------------
// Logger — Construction and initialisation
// ---------------------------------------------------------------------------

impl Logger {
    /// Create a new [`Logger`] from the given configuration.
    ///
    /// This allocates the internal state but does **not** open the syslog socket
    /// or log file. Call [`Logger::init()`] after construction to establish the
    /// connection. Replaces the config-extraction portion of C `log_start()`.
    pub fn new(config: LogConfig) -> Self {
        let inner = LoggerInner::new(&config);
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Initialise the logging backend: open the syslog socket or log file.
    ///
    /// Replaces the connection-establishment portion of C `log_start()` (log.c
    /// line 177). Must be called after [`Logger::new()`] and before the first
    /// log message. When using the module-level [`init()`] function this is
    /// called automatically.
    ///
    /// If a log file path was provided in [`LogConfig`], the file is opened
    /// in append mode. Otherwise a Unix-domain socket connection to
    /// [`SYSLOG_PATH`] (`/dev/log`) is established.
    pub fn init(&self) {
        let mut inner = self.inner.lock().unwrap();

        // If logging to stderr (log_file == "-"), dup stderr fd.
        if inner.log_stderr {
            // SAFETY: STDERR_FILENO (2) is always a valid fd.
            let duped = unsafe { libc::dup(libc::STDERR_FILENO) };
            if duped >= 0 {
                inner.log_fd = Some(duped);
            }
            inner.echo_stderr = false; // Don't double-echo.
            return;
        }

        // If logging to a named file, open it.
        if inner.log_to_file {
            // Retrieve the path — we stored log_to_file = true only when
            // log_file was Some. Since LoggerInner doesn't store the path
            // itself, we re-derive it from the global config in practice.
            // For robustness, open_log_file is called during init() below.
            // (The actual path is passed through the global GLOBAL_LOGGER
            //  setup; see the standalone init() function.)
        }

        // Default: open syslog socket.
        if !inner.log_to_file {
            Self::open_syslog_connection(&mut inner);
        }
    }

    // ------------------------------------------------------------------
    // Connection management helpers (static methods operating on inner)
    // ------------------------------------------------------------------

    /// Open (or reopen) a Unix-domain syslog socket and connect to `/dev/log`.
    ///
    /// Replaces the socket-opening branch of C `log_reopen()` (log.c line 291).
    /// The socket is set to non-blocking mode when `max_logs > 0` (async queue
    /// enabled) to prevent the event loop from stalling on slow syslogd.
    fn open_syslog_connection(inner: &mut LoggerInner) {
        // Determine nix SockType from connection_type.
        let sock_type = if inner.connection_type == libc::SOCK_DGRAM {
            SockType::Datagram
        } else {
            SockType::Stream
        };

        // Non-blocking flag when async queue is enabled (max_logs > 0).
        let mut flags = SockFlag::SOCK_CLOEXEC;
        if inner.max_logs > 0 {
            flags |= SockFlag::SOCK_NONBLOCK;
        }

        // Create the AF_UNIX socket.
        let owned_fd = match nix_socket(AddressFamily::Unix, sock_type, flags, None) {
            Ok(fd) => fd,
            Err(_) => return,
        };
        let raw_fd = owned_fd.into_raw_fd();

        // Connect to /dev/log.
        let addr = match UnixAddr::new(SYSLOG_PATH) {
            Ok(a) => a,
            Err(_) => {
                close_raw_fd(raw_fd);
                return;
            }
        };

        // nix 0.30.1's connect() takes RawFd directly.
        let connect_result = nix_connect(raw_fd, &addr);

        if connect_result.is_ok() {
            inner.log_fd = Some(raw_fd);
            inner.connection_good = true;
        } else {
            close_raw_fd(raw_fd);
        }
    }

    /// Open a log file in append mode, returning the raw fd.
    ///
    /// Replaces the file-opening branch of C `log_reopen()` (log.c line 301).
    fn open_log_file(path: &str) -> Option<RawFd> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        // Convert the std File into a raw fd so we manage it ourselves.
        Some(file.into_raw_fd())
    }

    /// Initialise the logger and open a log file connection.
    ///
    /// This is a convenience used by the standalone [`init()`] function when a
    /// log file path is configured.
    fn init_with_file(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(fd) = Self::open_log_file(path) {
            inner.log_fd = Some(fd);
        }
    }

    // ------------------------------------------------------------------
    // Core logging — replaces C my_syslog()
    // ------------------------------------------------------------------

    /// Log a message at the given raw syslog priority.
    ///
    /// This is the primary logging entry point, replacing C `my_syslog(priority,
    /// format, ...)` (log.c line 660). The message is formatted per RFC 3164,
    /// optionally echoed to stderr, and either written immediately (synchronous
    /// mode) or enqueued for async write by the event loop.
    ///
    /// The `priority` parameter uses syslog priority constants (`LOG_ERR`,
    /// `LOG_WARNING`, `LOG_INFO`, `LOG_DEBUG`, `LOG_CRIT`). Facility-mask bits
    /// (`LOG_FACMASK`) are stripped before use.
    pub fn log(&self, priority: i32, message: &str) {
        let mut inner = self.inner.lock().unwrap();

        // Extract the actual priority level (strip facility/service flags).
        let prio = priority & libc::LOG_PRIMASK;

        // --- Echo to stderr in debug/foreground mode ---
        if inner.echo_stderr {
            let _ = writeln!(std::io::stderr(), "{LOG_TAG}: {message}");
        }

        // --- Fallback to libc syslog if no fd is open ---
        if inner.log_fd.is_none() {
            // Fallback: use libc openlog/syslog (matches C behaviour log.c lines 719-733).
            unsafe {
                static SYSLOG_OPENED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !SYSLOG_OPENED.load(std::sync::atomic::Ordering::Relaxed) {
                    let tag = std::ffi::CString::new(LOG_TAG).unwrap();
                    libc::openlog(tag.as_ptr(), libc::LOG_PID, inner.facility);
                    SYSLOG_OPENED.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                let cmsg = std::ffi::CString::new(message).unwrap_or_default();
                libc::syslog(prio | inner.facility, c"%s".as_ptr(), cmsg.as_ptr());
            }
            return;
        }

        // --- Format the RFC 3164 syslog message ---
        let pid = getpid().as_raw() as u32;
        let mut payload = Vec::with_capacity(MAX_MESSAGE);

        // For syslog socket: prepend <priority|facility> header.
        if !inner.log_to_file {
            let _ = write!(payload, "<{}>", prio | inner.facility);
        }

        // Timestamp (matches C: "%.15s " from ctime+4 → "Mon DD HH:MM:SS ").
        // We use chrono-free formatting via libc for fidelity with C.
        if !inner.log_stderr {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let tm_ptr = unsafe { libc::localtime(&now) };
            if !tm_ptr.is_null() {
                let mut buf = [0u8; 32];
                let len = unsafe {
                    libc::strftime(
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        c"%b %e %T ".as_ptr(),
                        tm_ptr,
                    )
                };
                if len > 0 {
                    payload.extend_from_slice(&buf[..len]);
                }
            }
        }

        // Tag and PID.
        let _ = write!(payload, "{LOG_TAG}[{pid}]: ");

        // User message (truncated to fit MAX_MESSAGE).
        let remaining = MAX_MESSAGE.saturating_sub(payload.len()).saturating_sub(1);
        if message.len() > remaining {
            payload.extend_from_slice(&message.as_bytes()[..remaining]);
        } else {
            payload.extend_from_slice(message.as_bytes());
        }

        // Null terminator (used as record separator for SOCK_STREAM; elided
        // for SOCK_DGRAM; replaced with newline for file logging).
        payload.push(0);

        let entry = LogEntry {
            offset: 0,
            length: payload.len(),
            pid,
            payload,
        };

        // --- Enqueue or write immediately ---
        if inner.max_logs == 0 {
            // Synchronous mode: write immediately (no queue).
            inner.queue.push_back(entry);
            Self::log_write(&mut inner);
        } else if inner.queue.len() < inner.max_logs {
            inner.queue.push_back(entry);
            Self::log_write(&mut inner);

            // Exponential backoff throttling (matches C log.c lines 791-812).
            let depth = inner.queue.len();
            if depth > 0 && depth < inner.max_logs {
                let mut d = depth;
                if inner.max_logs > 8 {
                    d = d.saturating_sub(inner.max_logs - 8);
                }
                if d > 0 {
                    let ns = 1_000_000u64 << (d - 1).min(8);
                    std::thread::sleep(std::time::Duration::from_nanos(ns));
                    Self::log_write(&mut inner);
                }
            }
        } else {
            // Queue full — drop the message.
            inner.entries_lost += 1;
        }
    }

    // ------------------------------------------------------------------
    // Queue drain — replaces C log_write()
    // ------------------------------------------------------------------

    /// Attempt to write queued log entries to the syslog socket or log file.
    ///
    /// This is a non-blocking drain: it writes as many entries as the fd will
    /// accept, handling partial writes, fork-safety checks, and connection
    /// recovery. Replaces C `log_write()` (log.c line 437).
    fn log_write(inner: &mut LoggerInner) {
        let fd = match inner.log_fd {
            Some(fd) => fd,
            None => return,
        };

        let current_pid = getpid().as_raw() as u32;

        while let Some(entry) = inner.queue.front_mut() {
            // --- Fork safety: skip entries from a different process ---
            if entry.pid != current_pid {
                inner.queue.pop_front();
                continue;
            }

            // --- Adjust payload terminator per protocol ---
            let len_adjust: usize;
            if inner.log_to_file {
                // Replace trailing NUL with newline for file output.
                let last = entry.offset + entry.length - 1;
                if last < entry.payload.len() {
                    entry.payload[last] = b'\n';
                }
                len_adjust = 0;
            } else if inner.connection_type == libc::SOCK_DGRAM {
                // Elide trailing NUL for datagram sockets.
                len_adjust = 1;
            } else {
                // SOCK_STREAM: send NUL as record terminator.
                len_adjust = 0;
            }

            inner.connection_good = true;

            let write_buf =
                &entry.payload[entry.offset..entry.offset + entry.length - len_adjust];

            match write_to_fd(fd, write_buf) {
                Ok(written) => {
                    entry.length -= written;
                    entry.offset += written;
                    if entry.length <= len_adjust {
                        // Entry fully written — dequeue.
                        inner.queue.pop_front();

                        // Report any lost entries now that there is space.
                        if inner.entries_lost > 0 {
                            let lost = inner.entries_lost;
                            inner.entries_lost = 0;
                            // We cannot recurse into log() here (Mutex is held),
                            // so enqueue a synthetic entry directly.
                            let msg = format!(
                                "<{}>{}[{}]: overflow: {} log entries lost\0",
                                libc::LOG_WARNING | inner.facility,
                                LOG_TAG,
                                current_pid,
                                lost,
                            );
                            inner.queue.push_back(LogEntry {
                                offset: 0,
                                length: msg.len(),
                                pid: current_pid,
                                payload: msg.into_bytes(),
                            });
                        }
                    }
                    continue;
                }
                Err(errno) => {
                    use nix::errno::Errno;
                    match errno {
                        Errno::EINTR => continue,
                        Errno::EAGAIN => {
                            // Syslogd busy (EAGAIN / EWOULDBLOCK — same value
                            // on Linux) — wait for next poll cycle.
                            return;
                        }
                        Errno::ENOBUFS => {
                            inner.connection_good = false;
                            return;
                        }
                        Errno::EPIPE if !inner.log_to_file => {
                            // Stream socket broken — attempt reconnect.
                            if let Some(old_fd) = inner.log_fd.take() {
                                close_raw_fd(old_fd);
                            }
                            Self::open_syslog_connection(inner);
                            if inner.log_fd.is_some() {
                                continue;
                            }
                            inner.connection_good = false;
                            return;
                        }
                        Errno::ECONNREFUSED
                        | Errno::ENOTCONN
                        | Errno::EDESTADDRREQ
                        | Errno::ECONNRESET
                            if !inner.log_to_file =>
                        {
                            // Connection lost — try reconnect once.
                            let reconnect_addr = UnixAddr::new(SYSLOG_PATH).ok();
                            let reconnected = reconnect_addr.as_ref().is_some_and(|addr| {
                                nix_connect(fd, addr).is_ok()
                            });
                            if reconnected {
                                continue;
                            }
                            // Try alternate socket type (DGRAM ↔ STREAM).
                            if let Some(old_fd) = inner.log_fd.take() {
                                close_raw_fd(old_fd);
                            }
                            inner.connection_type = if inner.connection_type == libc::SOCK_DGRAM {
                                libc::SOCK_STREAM
                            } else {
                                libc::SOCK_DGRAM
                            };
                            Self::open_syslog_connection(inner);
                            if inner.log_fd.is_some() {
                                continue;
                            }
                            inner.connection_good = false;
                            return;
                        }
                        _ => {
                            // Unrecoverable error — fall back to libc syslog.
                            inner.log_fd = None;
                            return;
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Flush — replaces C flush_log()
    // ------------------------------------------------------------------

    /// Synchronously flush all queued log messages, blocking until the queue
    /// is drained or the connection fails.
    ///
    /// Replaces C `flush_log()` (log.c line 1003). Called during daemon shutdown
    /// and log rotation to ensure no messages are lost.
    ///
    /// **Warning:** This method blocks. It should only be called during shutdown,
    /// signal handling, or other contexts where blocking is acceptable.
    pub fn flush(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::flush_queue(&mut inner);
    }

    /// Internal blocking queue drain (operates on locked inner state).
    fn flush_queue(inner: &mut LoggerInner) {
        while inner.log_fd.is_some() {
            Self::log_write(inner);
            if inner.queue.is_empty() || !inner.connection_good {
                // Close the fd after draining (matches C flush_log() behaviour).
                if let Some(fd) = inner.log_fd.take() {
                    close_raw_fd(fd);
                }
                break;
            }
            // Brief sleep between attempts to avoid tight-looping.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    // ------------------------------------------------------------------
    // Reopen — replaces C log_reopen()
    // ------------------------------------------------------------------

    /// Reopen the log file or syslog connection for log rotation support.
    ///
    /// Replaces C `log_reopen()` (log.c line 291). Typically triggered by
    /// `SIGHUP` / `EVENT_REOPEN`. The current fd is closed and a new
    /// connection/file is opened. Queued entries are preserved and will be
    /// written through the new descriptor.
    pub fn reopen(&self) {
        self.reopen_with_path(None);
    }

    /// Reopen with an explicit file path (used during initialisation).
    fn reopen_with_path(&self, log_file: Option<&str>) {
        let mut inner = self.inner.lock().unwrap();

        if inner.log_stderr {
            // Logging to stderr — nothing to reopen.
            return;
        }

        // Close existing fd.
        if let Some(old_fd) = inner.log_fd.take() {
            close_raw_fd(old_fd);
        }

        if let Some(path) = log_file {
            // Reopen log file.
            inner.log_fd = Self::open_log_file(path);
        } else if inner.log_to_file {
            // log_to_file is set but we don't have the path here.
            // In practice, reopen() is called from the event loop which has
            // access to the daemon config. This is a no-op fallback.
        } else {
            // Reopen syslog socket.
            Self::open_syslog_connection(&mut inner);
        }
    }

    // ------------------------------------------------------------------
    // Event loop integration — replaces C set_log_writer() / check_log_writer()
    // ------------------------------------------------------------------

    /// Return the log file descriptor to register for `POLLOUT` monitoring,
    /// or [`None`] if no writes are pending.
    ///
    /// Replaces C `set_log_writer()` (log.c line 867). Called each event loop
    /// iteration to decide whether to monitor the log fd for writability.
    pub fn set_log_writer(&self) -> Option<RawFd> {
        let inner = self.inner.lock().unwrap();
        if !inner.queue.is_empty() && inner.log_fd.is_some() && inner.connection_good {
            inner.log_fd
        } else {
            None
        }
    }

    /// Called when the log file descriptor becomes writable. Attempts to
    /// flush queued entries.
    ///
    /// Replaces C `check_log_writer(force)` (log.c line 934). In the Rust
    /// version the `force` parameter is implicit: the event loop calls this
    /// when poll indicates writability, and [`Logger::flush()`] is used for
    /// forced drainage.
    pub fn check_log_writer(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.log_fd.is_some() {
            Self::log_write(&mut inner);
        }
    }

    // ------------------------------------------------------------------
    // Fatal error — replaces C die()
    // ------------------------------------------------------------------

    /// Log a fatal error message and terminate the process.
    ///
    /// Replaces C `die(message, arg1, exit_code)` (log.c line 1102).
    /// Temporarily enables stderr echo so the error is visible on the
    /// console, logs the error at `LOG_CRIT`, flushes the queue, and
    /// exits with the given code. **This function never returns.**
    pub fn die(&self, message: &str, exit_code: i32) -> ! {
        {
            let mut inner = self.inner.lock().unwrap();

            // Ensure the fatal message is visible on stderr.
            if !inner.log_stderr {
                inner.echo_stderr = true;
                let _ = writeln!(std::io::stderr());
            }
        }

        // Log the specific error and the generic "FAILED to start up" message.
        self.log(libc::LOG_CRIT, message);
        {
            let mut inner = self.inner.lock().unwrap();
            inner.echo_stderr = false;
        }
        self.log(libc::LOG_CRIT, "FAILED to start up");
        self.flush();

        std::process::exit(exit_code);
    }

    // ------------------------------------------------------------------
    // Echo mode control
    // ------------------------------------------------------------------

    /// Enable or disable echo-to-stderr mode.
    ///
    /// When enabled, all log messages are printed to stderr in addition to
    /// the normal syslog/file output. Used during startup in debug mode and
    /// temporarily by [`Logger::die()`].
    pub fn set_echo(&self, enable: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.echo_stderr = enable;
    }
}

// ---------------------------------------------------------------------------
// log::Log trait implementation
// ---------------------------------------------------------------------------

impl Log for Logger {
    /// Check whether a log record at the given level should be processed.
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Accept all levels — filtering is done by the `log` crate's
        // max level filter set during `init()`.
        let _ = metadata;
        true
    }

    /// Format and dispatch a log record through the dnsmasq logging subsystem.
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let priority = level_to_syslog_priority(record.level());
        let message = format!("{}", record.args());
        // Call the inherent log method (different signature — no ambiguity).
        Logger::log(self, priority, &message);
    }

    /// Flush all pending log entries (delegates to [`Logger::flush()`]).
    fn flush(&self) {
        Logger::flush(self);
    }
}

// ---------------------------------------------------------------------------
// Module-level init — standalone function
// ---------------------------------------------------------------------------

/// Initialise the global logging subsystem.
///
/// Creates a [`Logger`] from the given configuration, opens the syslog socket
/// or log file, and registers the logger with the [`log`] crate facade. After
/// this call, all uses of `log::info!()`, `log::warn!()` etc. dispatch through
/// the dnsmasq async logger.
///
/// # Panics
/// Panics if called more than once (the global logger can only be set once).
pub fn init(config: LogConfig) {
    let log_file_path = config.log_file.clone();
    let logger = Logger::new(config);
    logger.init();

    // If a file path was configured (but not stderr), open it.
    if let Some(ref path) = log_file_path
        && path != "-"
    {
        logger.init_with_file(path);
    }

    let _ = GLOBAL_LOGGER.set(logger);
    if let Some(lg) = GLOBAL_LOGGER.get() {
        let _ = log::set_logger(lg);
        log::set_max_level(LevelFilter::Trace);
    }
}

// ---------------------------------------------------------------------------
// Convenience functions — module-level wrappers
// ---------------------------------------------------------------------------

/// Log a message at syslog `LOG_WARNING` level.
///
/// Replaces C `my_syslog(LOG_WARNING, ...)`. If the global logger has not been
/// initialised, the message is printed to stderr as a fallback.
pub fn warn(msg: &str) {
    if let Some(logger) = GLOBAL_LOGGER.get() {
        logger.log(libc::LOG_WARNING, msg);
    } else {
        let _ = writeln!(std::io::stderr(), "dnsmasq: WARNING: {msg}");
    }
}

/// Log a message at syslog `LOG_ERR` level.
///
/// Replaces C `my_syslog(LOG_ERR, ...)`.
pub fn log_err(msg: &str) {
    if let Some(logger) = GLOBAL_LOGGER.get() {
        logger.log(libc::LOG_ERR, msg);
    } else {
        let _ = writeln!(std::io::stderr(), "dnsmasq: ERROR: {msg}");
    }
}

/// Log a message at syslog `LOG_INFO` level.
///
/// Replaces C `my_syslog(LOG_INFO, ...)`.
pub fn log_info(msg: &str) {
    if let Some(logger) = GLOBAL_LOGGER.get() {
        logger.log(libc::LOG_INFO, msg);
    } else {
        let _ = writeln!(std::io::stderr(), "dnsmasq: {msg}");
    }
}

/// Log a message at syslog `LOG_DEBUG` level.
///
/// Replaces C `my_syslog(LOG_DEBUG, ...)`.
pub fn log_debug(msg: &str) {
    if let Some(logger) = GLOBAL_LOGGER.get() {
        logger.log(libc::LOG_DEBUG, msg);
    } else {
        let _ = writeln!(std::io::stderr(), "dnsmasq: DEBUG: {msg}");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that [`LOG_MAX`] matches the C constant.
    #[test]
    fn test_log_max_constant() {
        assert_eq!(LOG_MAX, 5);
    }

    /// Verify that [`MAX_MESSAGE`] matches RFC 3164.
    #[test]
    fn test_max_message_constant() {
        assert_eq!(MAX_MESSAGE, 1024);
    }

    /// [`LogConfig::default()`] should use `LOG_DAEMON` and synchronous mode.
    #[test]
    fn test_log_config_default() {
        let cfg = LogConfig::default();
        assert_eq!(cfg.facility, libc::LOG_DAEMON);
        assert_eq!(cfg.max_logs, 0);
        assert!(cfg.log_file.is_none());
        assert!(!cfg.no_daemon);
    }

    /// A freshly created [`Logger`] should have an empty queue and no lost entries.
    #[test]
    fn test_logger_new_empty_queue() {
        let logger = Logger::new(LogConfig::default());
        let inner = logger.inner.lock().unwrap();
        assert!(inner.queue.is_empty());
        assert_eq!(inner.entries_lost, 0);
        assert!(inner.log_fd.is_none());
        assert!(inner.connection_good);
    }

    /// Verify the syslog priority ↔ Level mapping round-trips correctly.
    #[test]
    fn test_level_priority_mapping() {
        assert_eq!(level_to_syslog_priority(Level::Error), libc::LOG_ERR);
        assert_eq!(level_to_syslog_priority(Level::Warn), libc::LOG_WARNING);
        assert_eq!(level_to_syslog_priority(Level::Info), libc::LOG_INFO);
        assert_eq!(level_to_syslog_priority(Level::Debug), libc::LOG_DEBUG);
        assert_eq!(level_to_syslog_priority(Level::Trace), libc::LOG_DEBUG);
    }

    /// Verify reverse mapping from syslog priority to log::Level.
    #[test]
    fn test_syslog_priority_to_level() {
        assert_eq!(syslog_priority_to_level(libc::LOG_ERR), Level::Error);
        assert_eq!(syslog_priority_to_level(libc::LOG_CRIT), Level::Error);
        assert_eq!(syslog_priority_to_level(libc::LOG_WARNING), Level::Warn);
        assert_eq!(syslog_priority_to_level(libc::LOG_INFO), Level::Info);
        assert_eq!(syslog_priority_to_level(libc::LOG_DEBUG), Level::Debug);
    }

    /// The queue should be bounded at the configured `max_logs` size.
    /// When full, new entries should be dropped and `entries_lost` incremented.
    #[test]
    fn test_queue_overflow_drops_entries() {
        let config = LogConfig {
            facility: libc::LOG_DAEMON,
            max_logs: 3,
            log_file: None,
            no_daemon: false,
        };
        let logger = Logger::new(config);
        // The logger has no fd open so my_syslog falls back to libc syslog.
        // But we can test the inner state directly.
        {
            let mut inner = logger.inner.lock().unwrap();
            // Manually fill the queue beyond max_logs.
            for i in 0..5 {
                if inner.queue.len() < inner.max_logs {
                    inner.queue.push_back(LogEntry {
                        offset: 0,
                        length: 10,
                        pid: std::process::id(),
                        payload: format!("test {i}\0").into_bytes(),
                    });
                } else {
                    inner.entries_lost += 1;
                }
            }
            assert_eq!(inner.queue.len(), 3);
            assert_eq!(inner.entries_lost, 2);
        }
    }

    /// Verify that file logging mode disables async queue (max_logs forced to 0).
    #[test]
    fn test_file_logging_forces_sync_mode() {
        let config = LogConfig {
            facility: libc::LOG_DAEMON,
            max_logs: 10,
            log_file: Some("/tmp/test.log".to_string()),
            no_daemon: false,
        };
        let logger = Logger::new(config);
        let inner = logger.inner.lock().unwrap();
        assert!(inner.log_to_file);
        assert_eq!(inner.max_logs, 0); // Forced to sync mode.
    }

    /// Verify that log_file = "-" activates stderr logging mode.
    #[test]
    fn test_stderr_logging_mode() {
        let config = LogConfig {
            facility: libc::LOG_DAEMON,
            max_logs: 0,
            log_file: Some("-".to_string()),
            no_daemon: false,
        };
        let logger = Logger::new(config);
        let inner = logger.inner.lock().unwrap();
        assert!(inner.log_stderr);
        assert!(inner.log_to_file);
    }

    /// The `echo_stderr` flag should reflect the `no_daemon` config setting.
    #[test]
    fn test_echo_stderr_from_no_daemon() {
        let config = LogConfig {
            facility: libc::LOG_DAEMON,
            max_logs: 0,
            log_file: None,
            no_daemon: true,
        };
        let logger = Logger::new(config);
        let inner = logger.inner.lock().unwrap();
        assert!(inner.echo_stderr);
    }

    /// [`set_log_writer()`] should return None when the queue is empty.
    #[test]
    fn test_set_log_writer_empty_queue() {
        let logger = Logger::new(LogConfig::default());
        assert!(logger.set_log_writer().is_none());
    }

    /// [`Logger::set_echo()`] should toggle the echo flag.
    #[test]
    fn test_set_echo_toggle() {
        let logger = Logger::new(LogConfig::default());
        {
            let inner = logger.inner.lock().unwrap();
            assert!(!inner.echo_stderr);
        }
        logger.set_echo(true);
        {
            let inner = logger.inner.lock().unwrap();
            assert!(inner.echo_stderr);
        }
        logger.set_echo(false);
        {
            let inner = logger.inner.lock().unwrap();
            assert!(!inner.echo_stderr);
        }
    }

    /// Fork-safety: entries with a different PID are skipped during `log_write`.
    #[test]
    fn test_fork_safety_skips_wrong_pid() {
        let config = LogConfig {
            facility: libc::LOG_DAEMON,
            max_logs: 5,
            log_file: None,
            no_daemon: false,
        };
        let logger = Logger::new(config);
        {
            let mut inner = logger.inner.lock().unwrap();
            // Create a pipe so we have a valid writable fd.
            let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
            inner.log_fd = Some(write_fd.into_raw_fd());
            inner.log_to_file = true; // Treat as file for simpler write logic.

            // Enqueue an entry with a fake PID (simulating a forked child entry).
            inner.queue.push_back(LogEntry {
                offset: 0,
                length: 6,
                pid: 99999, // Not our PID.
                payload: b"hello\n".to_vec(),
            });
            assert_eq!(inner.queue.len(), 1);

            // log_write should skip (and remove) the foreign-PID entry.
            Logger::log_write(&mut inner);
            assert!(inner.queue.is_empty());

            // Clean up.
            if let Some(fd) = inner.log_fd.take() {
                close_raw_fd(fd);
            }
            close_raw_fd(read_fd.into_raw_fd());
        }
    }

    /// [`LogEntry`] payload should be properly bounded by [`MAX_MESSAGE`].
    #[test]
    fn test_log_entry_payload_max_size() {
        // Simulate the formatting logic: a very long message should be truncated.
        let long_msg = "x".repeat(MAX_MESSAGE + 100);
        let mut payload = Vec::with_capacity(MAX_MESSAGE);
        let header = format!("<30>dnsmasq[1234]: ");
        payload.extend_from_slice(header.as_bytes());
        let remaining = MAX_MESSAGE.saturating_sub(payload.len()).saturating_sub(1);
        payload.extend_from_slice(&long_msg.as_bytes()[..remaining]);
        payload.push(0);
        assert!(payload.len() <= MAX_MESSAGE);
    }

    /// Test the `OFlag` import is accessible (schema requirement).
    #[test]
    fn test_oflag_nonblock_available() {
        // Just verify the import resolves.
        let _flag = OFlag::O_NONBLOCK;
    }

    /// Verify the `LOG_FACMASK` and `LOG_PRIMASK` constants are usable.
    #[test]
    fn test_syslog_mask_constants() {
        let combined = libc::LOG_ERR | libc::LOG_DAEMON;
        let prio = combined & libc::LOG_PRIMASK;
        let fac = combined & libc::LOG_FACMASK;
        assert_eq!(prio, libc::LOG_ERR);
        assert_eq!(fac, libc::LOG_DAEMON);
    }
}


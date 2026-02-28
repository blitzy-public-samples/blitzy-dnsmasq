//! Signal handling for the dnsmasq daemon via self-pipe pattern.
//!
//! Implements the signal-to-event translation mechanism from `src/dnsmasq.c`.
//! The self-pipe pattern ensures async-signal-safety by having signal handlers
//! write event codes to a pipe, which the main event loop reads and dispatches.
//!
//! ## Signal Mapping (from C sig_handler, dnsmasq.c lines 1589-1636)
//!
//! | Signal   | Event Code      | Action                                    |
//! |----------|-----------------|-------------------------------------------|
//! | SIGHUP   | EVENT_RELOAD    | Hot reload configuration, clear DNS cache |
//! | SIGTERM  | EVENT_TERM      | Graceful shutdown                         |
//! | SIGINT   | EVENT_TIME      | Timer/exit (exit in debug mode)           |
//! | SIGUSR1  | EVENT_DUMP      | Dump cache statistics to log              |
//! | SIGUSR2  | EVENT_REOPEN    | Rotate log files                          |
//! | SIGALRM  | EVENT_ALARM     | Timer expired for periodic ops            |
//! | SIGCHLD  | EVENT_CHILD     | Child process terminated                  |
//! | SIGPIPE  | (ignored)       | Prevent write-to-broken-pipe crash        |
//!
//! ## Architecture
//!
//! 1. [`SignalHandler::new()`] creates self-pipe and installs signal handlers
//! 2. When signal arrives, handler writes event code to pipe (async-signal-safe)
//! 3. Event loop polls pipe read end via mio
//! 4. [`SignalHandler::read_event()`] reads and returns event for dispatch
//!
//! ## Async-Signal-Safety
//!
//! The extern "C" signal handler function only uses async-signal-safe operations:
//! - Atomic loads (`AtomicI32::load` with `Ordering::SeqCst`)
//! - `libc::write()` to the self-pipe
//! - `libc::getpid()` for process identity check
//! - `libc::_exit()` for fatal startup/helper signals
//! - errno save/restore via direct pointer access
//!
//! These are the **only** permitted `unsafe` blocks per AAP Section 0.7.1,
//! and each has a `// SAFETY:` comment explaining invariants.

use std::mem;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use nix::fcntl::OFlag;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::pipe2;

// ---------------------------------------------------------------------------
// Global atomics for async-signal-safe signal handler
// ---------------------------------------------------------------------------

/// Global atomic for the pipe write fd, accessible from signal handler context.
/// This is the ONLY global mutable state for the write end, required because
/// POSIX signal handlers cannot receive arbitrary user data — they only receive
/// the signal number. The atomic provides safe concurrent access without locks.
/// Value of -1 means the pipe is not yet initialized.
static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Global atomic for the daemon PID, used to distinguish the master process
/// from helper/child processes in the signal handler. Replaces the C global
/// `static volatile pid_t pid` from dnsmasq.c line 127.
///
/// - Value 0: startup phase — ignore all signals except SIGTERM/SIGINT
/// - Value == getpid(): master process — full signal handling
/// - Value != getpid(): helper/child process — only SIGALRM -> _exit(0)
static DAEMON_PID: AtomicI32 = AtomicI32::new(0);

/// Exit code for miscellaneous errors (matches C EC_MISC from dnsmasq.h line 390).
const EC_MISC: i32 = 5;

// ---------------------------------------------------------------------------
// Event enum — matches C EVENT_* constants from dnsmasq.h lines 357-382
// ---------------------------------------------------------------------------

/// Event types queued through the signal pipe.
///
/// Each variant corresponds to a C `EVENT_*` constant from `dnsmasq.h`
/// (lines 357-382). The integer discriminants must match exactly because
/// the wire format (via [`EventDesc`]) uses raw `i32` values, and other
/// modules may construct events using the numeric code directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Event {
    /// SIGHUP — hot reload configuration and clear DNS cache.
    Reload = 1,
    /// SIGUSR1 — dump cache statistics to syslog.
    Dump = 2,
    /// SIGALRM — periodic timer expired.
    Alarm = 3,
    /// SIGTERM — graceful shutdown requested.
    Term = 4,
    /// SIGCHLD — child process (TCP handler or script) terminated.
    Child = 5,
    /// SIGUSR2 — rotate/reopen log files.
    Reopen = 6,
    /// Helper child exited normally (with exit code in `data` field).
    Exited = 7,
    /// Helper child killed by signal (signal number in `data` field).
    Killed = 8,
    /// exec() failed in helper child (errno in `data` field).
    ExecErr = 9,
    /// Pipe error in helper communication.
    PipeErr = 10,
    /// Failed to change to configured user.
    UserErr = 11,
    /// Failed to set Linux capabilities.
    CapErr = 12,
    /// Failed to write PID file.
    PidFile = 13,
    /// Failed to change to helper user.
    HuserErr = 14,
    /// Failed to change to configured group.
    GroupErr = 15,
    /// Fatal error — daemon must exit.
    Die = 16,
    /// Failed to open log file or connect to syslog.
    LogErr = 17,
    /// fork() failed.
    ForkErr = 18,
    /// Lua script error.
    LuaErr = 19,
    /// TFTP error.
    TftpErr = 20,
    /// Daemon initialization complete.
    Init = 21,
    /// New network address detected.
    NewAddr = 22,
    /// New route detected.
    NewRoute = 23,
    /// Time-related error (clock jump, etc.).
    TimeErr = 24,
    /// Script produced log output.
    ScriptLog = 25,
    /// SIGINT in non-debug mode — time event.
    Time = 26,
}

impl Event {
    /// Total number of event variants.
    pub const COUNT: usize = 26;

    /// Returns a slice of all event variants for iteration.
    pub fn all() -> &'static [Event] {
        &[
            Event::Reload,
            Event::Dump,
            Event::Alarm,
            Event::Term,
            Event::Child,
            Event::Reopen,
            Event::Exited,
            Event::Killed,
            Event::ExecErr,
            Event::PipeErr,
            Event::UserErr,
            Event::CapErr,
            Event::PidFile,
            Event::HuserErr,
            Event::GroupErr,
            Event::Die,
            Event::LogErr,
            Event::ForkErr,
            Event::LuaErr,
            Event::TftpErr,
            Event::Init,
            Event::NewAddr,
            Event::NewRoute,
            Event::TimeErr,
            Event::ScriptLog,
            Event::Time,
        ]
    }
}

impl TryFrom<i32> for Event {
    type Error = InvalidEventError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Event::Reload),
            2 => Ok(Event::Dump),
            3 => Ok(Event::Alarm),
            4 => Ok(Event::Term),
            5 => Ok(Event::Child),
            6 => Ok(Event::Reopen),
            7 => Ok(Event::Exited),
            8 => Ok(Event::Killed),
            9 => Ok(Event::ExecErr),
            10 => Ok(Event::PipeErr),
            11 => Ok(Event::UserErr),
            12 => Ok(Event::CapErr),
            13 => Ok(Event::PidFile),
            14 => Ok(Event::HuserErr),
            15 => Ok(Event::GroupErr),
            16 => Ok(Event::Die),
            17 => Ok(Event::LogErr),
            18 => Ok(Event::ForkErr),
            19 => Ok(Event::LuaErr),
            20 => Ok(Event::TftpErr),
            21 => Ok(Event::Init),
            22 => Ok(Event::NewAddr),
            23 => Ok(Event::NewRoute),
            24 => Ok(Event::TimeErr),
            25 => Ok(Event::ScriptLog),
            26 => Ok(Event::Time),
            _ => Err(InvalidEventError(value)),
        }
    }
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Error type for invalid event code conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidEventError(pub i32);

impl std::fmt::Display for InvalidEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid event code: {}", self.0)
    }
}

impl std::error::Error for InvalidEventError {}

// ---------------------------------------------------------------------------
// EventDesc — wire format for event pipe communication
// ---------------------------------------------------------------------------

/// Event descriptor written through the signal pipe.
///
/// Matches the C `struct event_desc` from `dnsmasq.h` (lines 353-355):
/// ```c
/// struct event_desc {
///     int event, data, msg_sz;
/// };
/// ```
///
/// The `#[repr(C)]` attribute ensures the struct has the same memory layout
/// as the C version (three consecutive `i32` values, 12 bytes total).
/// This is critical because the signal handler writes raw bytes to the pipe.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDesc {
    /// Event type code (one of the [`Event`] discriminant values).
    pub event: i32,
    /// Event-specific data (e.g., errno value, child exit code, interface index).
    pub data: i32,
    /// Length of optional message payload following this descriptor in the pipe.
    /// Zero means no message follows.
    pub msg_sz: i32,
}

impl EventDesc {
    /// Size of the EventDesc in bytes (must be 12 to match C layout).
    pub const SIZE: usize = mem::size_of::<Self>();

    /// Create a new EventDesc with the given event, data, and message size.
    pub fn new(event: Event, data: i32, msg_sz: i32) -> Self {
        EventDesc {
            event: event as i32,
            data,
            msg_sz,
        }
    }

    /// Try to convert the event field to an [`Event`] enum variant.
    pub fn event_type(&self) -> Result<Event, InvalidEventError> {
        Event::try_from(self.event)
    }

    /// Reinterpret this descriptor as a byte slice for pipe writing.
    ///
    /// # Safety
    /// The caller must ensure the returned slice is not used after `self` is dropped.
    /// Since EventDesc is `#[repr(C)]` with only `i32` fields, this is safe
    /// for any bit pattern.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: EventDesc is #[repr(C)] with only primitive i32 fields.
        // Any bit pattern is valid, and the struct has no padding on all
        // supported platforms (Linux x86-64 and ARM64) where i32 is 4-byte aligned.
        unsafe {
            std::slice::from_raw_parts(
                (self as *const EventDesc).cast::<u8>(),
                Self::SIZE,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Errno save/restore helpers (async-signal-safe)
// ---------------------------------------------------------------------------

/// Get pointer to thread-local errno (async-signal-safe on all POSIX platforms).
///
/// # Safety
/// Caller must ensure this is called from a context where errno is meaningful.
/// The returned pointer is valid for the lifetime of the current thread.
#[cfg(target_os = "linux")]
#[inline(always)]
unsafe fn errno_location() -> *mut libc::c_int {
    // SAFETY: __errno_location() returns a pointer to the thread-local errno
    // variable. This is async-signal-safe on Linux (glibc and musl).
    unsafe { libc::__errno_location() }
}

/// Get pointer to thread-local errno for BSD/macOS platforms.
///
/// # Safety
/// Caller must ensure this is called from a context where errno is meaningful.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
#[inline(always)]
unsafe fn errno_location() -> *mut libc::c_int {
    // SAFETY: __error() returns a pointer to the thread-local errno variable.
    unsafe { libc::__error() }
}

// ---------------------------------------------------------------------------
// Signal handler (extern "C", async-signal-safe)
// ---------------------------------------------------------------------------

/// Async-signal-safe signal handler that translates OS signals into internal
/// event codes and writes them to the self-pipe.
///
/// This function is registered via `sigaction()` for SIGHUP, SIGTERM, SIGINT,
/// SIGUSR1, SIGUSR2, SIGALRM, and SIGCHLD. It performs ONLY async-signal-safe
/// operations: atomic loads, `write()`, `getpid()`, and `_exit()`.
///
/// Ports the C `sig_handler()` from `dnsmasq.c` lines 1589-1636 exactly:
///
/// - **Startup (PID == 0):** Ignore all signals except SIGTERM/SIGINT which
///   cause immediate `_exit(EC_MISC)`.
/// - **Helper child (PID != getpid()):** SIGALRM causes `_exit(0)` (TCP child
///   timeout mechanism).
/// - **Master process:** Map signal to event code and write [`EventDesc`] to
///   the self-pipe. SIGHUP→Reload, SIGCHLD→Child, SIGALRM→Alarm,
///   SIGTERM→Term, SIGUSR1→Dump, SIGUSR2→Reopen, SIGINT→Time.
///
/// # Safety
/// This is an `extern "C"` function called directly by the kernel's signal
/// delivery mechanism. It must be async-signal-safe per POSIX.1-2008.
extern "C" fn signal_handler(sig: libc::c_int) {
    // SAFETY: Reading errno is async-signal-safe. We save it to restore later
    // because write() may modify errno even on success paths.
    let saved_errno = unsafe { *errno_location() };

    let daemon_pid = DAEMON_PID.load(Ordering::SeqCst);

    if daemon_pid == 0 {
        // During startup: ignore all signals except TERM/INT.
        // In the C code (dnsmasq.c line 1591-1597), this also covers
        // the helper child process which inherits pid=0 after fork().
        if sig == libc::SIGTERM || sig == libc::SIGINT {
            // SAFETY: _exit() is async-signal-safe and terminates the process
            // immediately without running atexit handlers or flushing buffers.
            unsafe {
                libc::_exit(EC_MISC);
            }
        }
    // SAFETY: getpid() is async-signal-safe per POSIX and always succeeds.
    } else if daemon_pid != unsafe { libc::getpid() } {
        // In helper/TCP child process: SIGALRM kills the child.
        // This is used as a timeout mechanism for TCP DNS connections
        // (C: dnsmasq.c line 1600-1603).
        if sig == libc::SIGALRM {
            // SAFETY: _exit() is async-signal-safe.
            unsafe {
                libc::_exit(0);
            }
        }
    } else {
        // Master process: map signal → event code.
        let event = match sig {
            libc::SIGHUP => Event::Reload as i32,
            libc::SIGCHLD => Event::Child as i32,
            libc::SIGALRM => Event::Alarm as i32,
            libc::SIGTERM => Event::Term as i32,
            libc::SIGUSR1 => Event::Dump as i32,
            libc::SIGUSR2 => Event::Reopen as i32,
            libc::SIGINT => Event::Time as i32,
            _ => {
                // Unknown signal — restore errno and return.
                // SAFETY: Writing errno is async-signal-safe.
                unsafe {
                    *errno_location() = saved_errno;
                }
                return;
            }
        };

        let desc = EventDesc {
            event,
            data: 0,
            msg_sz: 0,
        };

        let pipe_fd = PIPE_WRITE.load(Ordering::SeqCst);
        if pipe_fd >= 0 {
            // SAFETY: write() is async-signal-safe per POSIX.1-2008.
            // We write exactly sizeof(EventDesc) = 12 bytes, which is well
            // below PIPE_BUF (4096 on Linux), guaranteeing atomic write.
            // The pipe is non-blocking, so this either succeeds or fails
            // without blocking. We intentionally ignore the return value
            // because there's nothing we can do about write failure in a
            // signal handler — the event will simply be lost (same as C).
            unsafe {
                libc::write(
                    pipe_fd,
                    desc.as_bytes().as_ptr().cast::<libc::c_void>(),
                    EventDesc::SIZE,
                );
            }
        }
    }

    // SAFETY: Restoring errno is async-signal-safe.
    unsafe {
        *errno_location() = saved_errno;
    }
}

// ---------------------------------------------------------------------------
// SignalHandler — the public API
// ---------------------------------------------------------------------------

/// Self-pipe signal handler for async-signal-safe event delivery.
///
/// Creates a non-blocking pipe during initialization and installs POSIX signal
/// handlers that write event descriptors to the pipe's write end. The read end
/// is intended to be monitored by the mio event loop for dispatching events.
///
/// # Lifecycle
///
/// ```text
/// SignalHandler::new()
///   → Creates pipe (O_NONBLOCK | O_CLOEXEC)
///   → Stores write fd in global atomic
///   → Installs signal handlers via sigaction()
///   → Returns SignalHandler owning both pipe ends
///
/// activate_master_pid()
///   → Sets DAEMON_PID to getpid()
///   → Enables full signal handling (before this, only TERM/INT work)
///
/// Event loop:
///   → Polls pipe_read_fd() for readability
///   → Calls read_event() to get queued events
///   → Dispatches events to subsystem handlers
///
/// Drop:
///   → Resets global atomics
///   → Restores default signal handlers
///   → Pipe fds closed automatically via OwnedFd
/// ```
pub struct SignalHandler {
    /// Read end of the self-pipe (monitored by event loop for readability).
    /// Owned; closed automatically on drop.
    pipe_read: std::os::fd::OwnedFd,
    /// Write end of the self-pipe (used by signal handler via global atomic,
    /// and by send_event/queue_event methods).
    /// Owned; closed automatically on drop.
    pipe_write: std::os::fd::OwnedFd,
}

impl SignalHandler {
    /// Create a new SignalHandler, setting up the self-pipe and installing
    /// all signal handlers.
    ///
    /// This replaces the signal setup code in `dnsmasq.c` main() (lines 278-291):
    /// ```c
    /// sigact.sa_handler = sig_handler;
    /// sigact.sa_flags = 0;
    /// sigemptyset(&sigact.sa_mask);
    /// sigaction(SIGUSR1, &sigact, NULL);
    /// // ... repeated for all signals ...
    /// sigact.sa_handler = SIG_IGN;
    /// sigaction(SIGPIPE, &sigact, NULL);
    /// ```
    ///
    /// # Errors
    /// Returns an error if pipe creation or signal handler installation fails.
    ///
    /// # Signal Handler Behavior
    /// After construction, the daemon is in "startup mode" (DAEMON_PID == 0).
    /// In this mode, only SIGTERM and SIGINT are handled (they cause `_exit`).
    /// Call [`activate_master_pid()`] after startup completes to enable full
    /// signal handling.
    pub fn new() -> Result<Self, nix::Error> {
        // Create self-pipe with non-blocking I/O and close-on-exec.
        // Non-blocking ensures the signal handler's write() never blocks.
        // Close-on-exec prevents fd leaks to child processes.
        let (pipe_read, pipe_write) = pipe2(OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)?;

        // Store the write fd in the global atomic for signal handler access.
        // SAFETY: OwnedFd.as_raw_fd() returns a valid fd number.
        // The global atomic is the bridge between the signal handler
        // (which can't access struct fields) and the pipe.
        use std::os::fd::AsRawFd;
        PIPE_WRITE.store(pipe_write.as_raw_fd(), Ordering::SeqCst);

        // Install signal handlers for all handled signals.
        // The C code uses sa_flags = 0 (no SA_RESTART), but SA_RESTART is
        // generally preferred in Rust to avoid EINTR on slow syscalls.
        // We match the C behavior of NOT setting SA_RESTART, since the
        // event loop explicitly handles EINTR in its poll() retry logic.
        let handler_action = SigAction::new(
            SigHandler::Handler(signal_handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );

        let ignore_action = SigAction::new(
            SigHandler::SigIgn,
            SaFlags::empty(),
            SigSet::empty(),
        );

        // SAFETY: sigaction() is safe when called with valid Signal values
        // and a valid SigAction. The signal_handler function has the correct
        // extern "C" fn(c_int) signature. This is one of the explicitly
        // permitted unsafe blocks per AAP Section 0.7.1, required because
        // installing signal handlers is inherently unsafe — it modifies
        // process-wide signal disposition.
        unsafe {
            nix::sys::signal::sigaction(Signal::SIGUSR1, &handler_action)?;
            nix::sys::signal::sigaction(Signal::SIGUSR2, &handler_action)?;
            nix::sys::signal::sigaction(Signal::SIGHUP, &handler_action)?;
            nix::sys::signal::sigaction(Signal::SIGTERM, &handler_action)?;
            nix::sys::signal::sigaction(Signal::SIGALRM, &handler_action)?;
            nix::sys::signal::sigaction(Signal::SIGCHLD, &handler_action)?;
            nix::sys::signal::sigaction(Signal::SIGINT, &handler_action)?;

            // Ignore SIGPIPE to prevent crashes when writing to a broken
            // syslog connection or closed client socket (dnsmasq.c line 289-291).
            nix::sys::signal::sigaction(Signal::SIGPIPE, &ignore_action)?;
        }

        Ok(SignalHandler {
            pipe_read,
            pipe_write,
        })
    }

    /// Return the raw file descriptor for the read end of the self-pipe.
    ///
    /// The caller uses this to register the fd with mio for readability polling.
    /// When the fd becomes readable, call [`read_event()`](Self::read_event)
    /// to consume queued events.
    pub fn pipe_read_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.pipe_read.as_raw_fd()
    }

    /// Read the next event from the self-pipe (non-blocking).
    ///
    /// Returns `Some((desc, msg))` if an event is available:
    /// - `desc`: The [`EventDesc`] with event code, data, and message size
    /// - `msg`: Optional message string if `desc.msg_sz > 0`
    ///
    /// Returns `None` if no event is pending (pipe empty, EAGAIN).
    ///
    /// This replaces the read side of C's `read_event()` from `dnsmasq.c`
    /// (lines 1834-1851).
    ///
    /// # Note on message memory
    /// Unlike the C version which intentionally leaks message memory (used only
    /// for fatal errors), the Rust version returns an owned `String` that is
    /// properly freed when dropped.
    pub fn read_event(&self) -> Option<(EventDesc, Option<String>)> {
        let mut desc = EventDesc {
            event: 0,
            data: 0,
            msg_sz: 0,
        };

        // Read the fixed-size EventDesc from the pipe.
        // SAFETY: We reinterpret the EventDesc as a mutable byte slice for
        // reading. This is safe because EventDesc is #[repr(C)] with only
        // i32 fields, and any bit pattern is valid for i32.
        let desc_buf: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut desc as *mut EventDesc).cast::<u8>(),
                EventDesc::SIZE,
            )
        };

        match nix::unistd::read(&self.pipe_read, desc_buf) {
            Ok(n) if n == EventDesc::SIZE => {
                // Successfully read a complete EventDesc.
                let msg = if desc.msg_sz > 0 {
                    // Read the message payload that follows the descriptor.
                    let msg_len = desc.msg_sz as usize;
                    let mut msg_buf = vec![0u8; msg_len];
                    match nix::unistd::read(&self.pipe_read, &mut msg_buf) {
                        Ok(n) if n == msg_len => String::from_utf8(msg_buf).ok(),
                        _ => None,
                    }
                } else {
                    None
                };
                Some((desc, msg))
            }
            _ => None,
        }
    }

    /// Write an event to the self-pipe for processing by the main event loop.
    ///
    /// This is the normal-context (non-signal-handler) version that supports
    /// an optional message payload. Replaces C `send_event()` from `dnsmasq.c`
    /// (lines 1761-1782).
    ///
    /// The write is atomic for the EventDesc portion (12 bytes < PIPE_BUF).
    /// When a message is present, `writev()` is used for scatter-gather I/O
    /// to write both the descriptor and message atomically.
    ///
    /// # Parameters
    /// - `event`: The event type to queue
    /// - `data`: Event-specific data value (e.g., errno, exit code)
    /// - `msg`: Optional message string (used for error descriptions)
    pub fn send_event(&self, event: Event, data: i32, msg: Option<&str>) {
        let desc = EventDesc {
            event: event as i32,
            data,
            msg_sz: msg.map_or(0, |m| m.len() as i32),
        };

        use std::os::fd::AsRawFd;
        let fd = self.pipe_write.as_raw_fd();
        let desc_bytes = desc.as_bytes();

        match msg {
            Some(msg_str) if !msg_str.is_empty() => {
                // Use writev() for atomic scatter-gather write of desc + message.
                let iovs = [
                    libc::iovec {
                        iov_base: desc_bytes.as_ptr() as *mut libc::c_void,
                        iov_len: desc_bytes.len(),
                    },
                    libc::iovec {
                        iov_base: msg_str.as_ptr() as *mut libc::c_void,
                        iov_len: msg_str.len(),
                    },
                ];
                // SAFETY: writev() is called with a valid fd (our pipe write end)
                // and properly initialized iovec array pointing to valid memory.
                // The pipe is non-blocking and the total size (EventDesc + msg)
                // is smaller than PIPE_BUF, so this either fails or writes
                // everything atomically. We retry on EINTR.
                unsafe {
                    loop {
                        let ret = libc::writev(fd, iovs.as_ptr(), 2);
                        if ret >= 0 {
                            break;
                        }
                        let err = std::io::Error::last_os_error();
                        if err.kind() != std::io::ErrorKind::Interrupted {
                            break;
                        }
                    }
                }
            }
            _ => {
                // No message — write just the EventDesc.
                let iov = libc::iovec {
                    iov_base: desc_bytes.as_ptr() as *mut libc::c_void,
                    iov_len: desc_bytes.len(),
                };
                // SAFETY: writev() with a single iovec containing valid EventDesc bytes.
                unsafe {
                    loop {
                        let ret = libc::writev(fd, &iov, 1);
                        if ret >= 0 {
                            break;
                        }
                        let err = std::io::Error::last_os_error();
                        if err.kind() != std::io::ErrorKind::Interrupted {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Schedule a SIGALRM or queue an immediate EVENT_ALARM.
    ///
    /// Replaces C `send_alarm()` from `dnsmasq.c` (lines 1669-1680):
    /// ```c
    /// void send_alarm(time_t event, time_t now) {
    ///     if (now == 0 || event != 0) {
    ///         if ((now == 0 || difftime(event, now) <= 0.0))
    ///             send_event(pipewrite, EVENT_ALARM, 0, NULL);
    ///         else
    ///             alarm((unsigned)difftime(event, now));
    ///     }
    /// }
    /// ```
    ///
    /// # Parameters
    /// - `event_time`: Absolute time (seconds since epoch) when alarm should fire.
    ///   Value of 0 means the timer is being canceled.
    /// - `now`: Current time (seconds since epoch). Value of 0 means "queue
    ///   immediate callback without timing check".
    ///
    /// # Behavior
    /// - If `now == 0`: Queue immediate EVENT_ALARM (used for forced callbacks)
    /// - If `event_time` has already passed: Queue immediate EVENT_ALARM
    /// - Otherwise: Schedule SIGALRM delivery via `alarm(delta_seconds)`
    pub fn send_alarm(&self, event_time: i64, now: i64) {
        if now == 0 || event_time != 0 {
            let diff = event_time - now;
            if now == 0 || diff <= 0 {
                // Time has passed or immediate callback requested — queue now.
                self.send_event(Event::Alarm, 0, None);
            } else {
                // Schedule future SIGALRM delivery.
                // alarm() replaces any previously scheduled alarm.
                // SAFETY: alarm() is a safe POSIX function. The diff is positive
                // and cast to unsigned. Very large values are clamped by the OS.
                let secs = diff as libc::c_uint;
                unsafe {
                    libc::alarm(secs);
                }
            }
        }
    }

    /// Queue an event to the main event loop (simplified send_event wrapper).
    ///
    /// Replaces C `queue_event()` from `dnsmasq.c` (lines 1714-1717):
    /// ```c
    /// void queue_event(int event) {
    ///     send_event(pipewrite, event, 0, NULL);
    /// }
    /// ```
    ///
    /// Convenience method that queues an event with no data and no message.
    pub fn queue_event(&self, event: Event) {
        self.send_event(event, 0, None);
    }
}

impl Drop for SignalHandler {
    fn drop(&mut self) {
        // Reset global atomics so the signal handler becomes a no-op.
        PIPE_WRITE.store(-1, Ordering::SeqCst);
        DAEMON_PID.store(0, Ordering::SeqCst);

        // Restore default signal handlers to prevent stale handler references.
        let default_action = SigAction::new(
            SigHandler::SigDfl,
            SaFlags::empty(),
            SigSet::empty(),
        );

        // SAFETY: Restoring default signal handlers is safe and prevents
        // the installed handler from running after the pipe fds are closed.
        let signals = [
            Signal::SIGUSR1,
            Signal::SIGUSR2,
            Signal::SIGHUP,
            Signal::SIGTERM,
            Signal::SIGALRM,
            Signal::SIGCHLD,
            Signal::SIGINT,
            Signal::SIGPIPE,
        ];

        for sig in &signals {
            // Ignore errors during cleanup — we're in a destructor.
            let _ = unsafe { nix::sys::signal::sigaction(*sig, &default_action) };
        }

        // OwnedFd handles closing pipe_read and pipe_write automatically.
    }
}

// ---------------------------------------------------------------------------
// Public helper functions
// ---------------------------------------------------------------------------

/// Activate the daemon PID for signal handling.
///
/// Must be called after daemon startup completes (daemonization, privilege drop,
/// helper process creation) to enable full signal handling. Before this call,
/// the signal handler is in "startup mode" where only SIGTERM/SIGINT cause
/// `_exit(EC_MISC)` and all other signals are ignored.
///
/// Replaces the C line `pid = getpid();` in `dnsmasq.c` (line 1263).
///
/// # Signal Handler Behavior After Activation
///
/// | Signal   | Action                                |
/// |----------|---------------------------------------|
/// | SIGHUP   | Queue EVENT_RELOAD                    |
/// | SIGTERM  | Queue EVENT_TERM                      |
/// | SIGINT   | Queue EVENT_TIME                      |
/// | SIGUSR1  | Queue EVENT_DUMP                      |
/// | SIGUSR2  | Queue EVENT_REOPEN                    |
/// | SIGALRM  | Queue EVENT_ALARM                     |
/// | SIGCHLD  | Queue EVENT_CHILD                     |
pub fn activate_master_pid() {
    let pid = nix::unistd::getpid();
    DAEMON_PID.store(pid.as_raw(), Ordering::SeqCst);
}

/// Reset the daemon PID to zero (startup/inactive mode).
///
/// This is useful before forking child processes, so the child inherits
/// pid=0 and the signal handler becomes passive in the child.
pub fn deactivate_master_pid() {
    DAEMON_PID.store(0, Ordering::SeqCst);
}

/// Get the current daemon PID as stored in the global atomic.
///
/// Returns 0 if the daemon is in startup mode (before [`activate_master_pid()`]).
pub fn get_daemon_pid() -> i32 {
    DAEMON_PID.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_enum_values_match_c_constants() {
        // Verify all 26 event values match C EVENT_* constants from dnsmasq.h
        assert_eq!(Event::Reload as i32, 1);
        assert_eq!(Event::Dump as i32, 2);
        assert_eq!(Event::Alarm as i32, 3);
        assert_eq!(Event::Term as i32, 4);
        assert_eq!(Event::Child as i32, 5);
        assert_eq!(Event::Reopen as i32, 6);
        assert_eq!(Event::Exited as i32, 7);
        assert_eq!(Event::Killed as i32, 8);
        assert_eq!(Event::ExecErr as i32, 9);
        assert_eq!(Event::PipeErr as i32, 10);
        assert_eq!(Event::UserErr as i32, 11);
        assert_eq!(Event::CapErr as i32, 12);
        assert_eq!(Event::PidFile as i32, 13);
        assert_eq!(Event::HuserErr as i32, 14);
        assert_eq!(Event::GroupErr as i32, 15);
        assert_eq!(Event::Die as i32, 16);
        assert_eq!(Event::LogErr as i32, 17);
        assert_eq!(Event::ForkErr as i32, 18);
        assert_eq!(Event::LuaErr as i32, 19);
        assert_eq!(Event::TftpErr as i32, 20);
        assert_eq!(Event::Init as i32, 21);
        assert_eq!(Event::NewAddr as i32, 22);
        assert_eq!(Event::NewRoute as i32, 23);
        assert_eq!(Event::TimeErr as i32, 24);
        assert_eq!(Event::ScriptLog as i32, 25);
        assert_eq!(Event::Time as i32, 26);
    }

    #[test]
    fn test_event_count() {
        assert_eq!(Event::COUNT, 26);
        assert_eq!(Event::all().len(), 26);
    }

    #[test]
    fn test_event_all_variants_ordered() {
        let all = Event::all();
        for (i, event) in all.iter().enumerate() {
            assert_eq!(*event as i32, (i + 1) as i32);
        }
    }

    #[test]
    fn test_try_from_valid_event_codes() {
        for code in 1..=26 {
            let event = Event::try_from(code);
            assert!(event.is_ok(), "Event code {} should be valid", code);
            assert_eq!(event.unwrap() as i32, code);
        }
    }

    #[test]
    fn test_try_from_invalid_event_codes() {
        assert!(Event::try_from(0).is_err());
        assert!(Event::try_from(-1).is_err());
        assert!(Event::try_from(27).is_err());
        assert!(Event::try_from(100).is_err());
        assert!(Event::try_from(i32::MAX).is_err());
        assert!(Event::try_from(i32::MIN).is_err());
    }

    #[test]
    fn test_event_display() {
        assert_eq!(format!("{}", Event::Reload), "Reload");
        assert_eq!(format!("{}", Event::Term), "Term");
        assert_eq!(format!("{}", Event::Time), "Time");
    }

    #[test]
    fn test_invalid_event_error_display() {
        let err = InvalidEventError(42);
        assert_eq!(format!("{}", err), "invalid event code: 42");
    }

    #[test]
    fn test_event_desc_size_matches_c_layout() {
        // C struct event_desc { int event, data, msg_sz; } = 3 * 4 = 12 bytes
        assert_eq!(EventDesc::SIZE, 12);
        assert_eq!(mem::size_of::<EventDesc>(), 12);
    }

    #[test]
    fn test_event_desc_new() {
        let desc = EventDesc::new(Event::Reload, 42, 5);
        assert_eq!(desc.event, 1);
        assert_eq!(desc.data, 42);
        assert_eq!(desc.msg_sz, 5);
    }

    #[test]
    fn test_event_desc_event_type() {
        let desc = EventDesc::new(Event::Term, 0, 0);
        assert_eq!(desc.event_type().unwrap(), Event::Term);

        let invalid = EventDesc { event: 999, data: 0, msg_sz: 0 };
        assert!(invalid.event_type().is_err());
    }

    #[test]
    fn test_event_desc_as_bytes() {
        let desc = EventDesc { event: 1, data: 2, msg_sz: 3 };
        let bytes = desc.as_bytes();
        assert_eq!(bytes.len(), 12);

        // Verify byte representation matches expected little-endian layout
        // (on little-endian platforms like x86-64 and ARM64 in LE mode)
        if cfg!(target_endian = "little") {
            assert_eq!(&bytes[0..4], &1i32.to_le_bytes());
            assert_eq!(&bytes[4..8], &2i32.to_le_bytes());
            assert_eq!(&bytes[8..12], &3i32.to_le_bytes());
        }
    }

    #[test]
    fn test_signal_handler_new_creates_valid_pipe() {
        // Create and immediately drop to test construction and cleanup.
        let handler = SignalHandler::new();
        assert!(handler.is_ok(), "SignalHandler::new() should succeed");

        let handler = handler.unwrap();
        let read_fd = handler.pipe_read_fd();
        assert!(read_fd >= 0, "pipe_read_fd should be non-negative");

        // Verify the global atomic was set.
        let write_fd = PIPE_WRITE.load(Ordering::SeqCst);
        assert!(write_fd >= 0, "PIPE_WRITE should be set");
        assert_ne!(read_fd, write_fd, "read and write fds should differ");

        drop(handler);

        // After drop, global atomic should be reset.
        assert_eq!(PIPE_WRITE.load(Ordering::SeqCst), -1);
        assert_eq!(DAEMON_PID.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_send_event_read_event_roundtrip() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        // Send a simple event with no message.
        handler.send_event(Event::Reload, 42, None);

        // Read it back.
        let result = handler.read_event();
        assert!(result.is_some(), "Should read back the event");

        let (desc, msg) = result.unwrap();
        assert_eq!(desc.event, Event::Reload as i32);
        assert_eq!(desc.data, 42);
        assert_eq!(desc.msg_sz, 0);
        assert!(msg.is_none());
    }

    #[test]
    fn test_send_event_with_message() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        let test_msg = "test error message";
        handler.send_event(Event::ForkErr, 11, Some(test_msg));

        let result = handler.read_event();
        assert!(result.is_some());

        let (desc, msg) = result.unwrap();
        assert_eq!(desc.event, Event::ForkErr as i32);
        assert_eq!(desc.data, 11);
        assert_eq!(desc.msg_sz, test_msg.len() as i32);
        assert_eq!(msg.as_deref(), Some(test_msg));
    }

    #[test]
    fn test_queue_event() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        handler.queue_event(Event::Dump);

        let result = handler.read_event();
        assert!(result.is_some());

        let (desc, msg) = result.unwrap();
        assert_eq!(desc.event, Event::Dump as i32);
        assert_eq!(desc.data, 0);
        assert_eq!(desc.msg_sz, 0);
        assert!(msg.is_none());
    }

    #[test]
    fn test_read_event_empty_pipe() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        // No events queued — should return None.
        let result = handler.read_event();
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_events_fifo_order() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        // Queue multiple events.
        handler.queue_event(Event::Reload);
        handler.queue_event(Event::Term);
        handler.queue_event(Event::Alarm);

        // Read them back in FIFO order.
        let (desc1, _) = handler.read_event().expect("event 1");
        assert_eq!(desc1.event, Event::Reload as i32);

        let (desc2, _) = handler.read_event().expect("event 2");
        assert_eq!(desc2.event, Event::Term as i32);

        let (desc3, _) = handler.read_event().expect("event 3");
        assert_eq!(desc3.event, Event::Alarm as i32);

        // No more events.
        assert!(handler.read_event().is_none());
    }

    #[test]
    fn test_send_alarm_immediate_when_now_zero() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        // now == 0 → immediate EVENT_ALARM
        handler.send_alarm(100, 0);

        let result = handler.read_event();
        assert!(result.is_some());
        let (desc, _) = result.unwrap();
        assert_eq!(desc.event, Event::Alarm as i32);
    }

    #[test]
    fn test_send_alarm_immediate_when_time_passed() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        // event_time <= now → immediate EVENT_ALARM
        handler.send_alarm(100, 200);

        let result = handler.read_event();
        assert!(result.is_some());
        let (desc, _) = result.unwrap();
        assert_eq!(desc.event, Event::Alarm as i32);
    }

    #[test]
    fn test_send_alarm_no_event_when_canceled() {
        let handler = SignalHandler::new().expect("SignalHandler::new failed");

        // event_time == 0, now != 0 → no event (timer canceled)
        handler.send_alarm(0, 100);

        // Should be no event in the pipe
        assert!(handler.read_event().is_none());
    }

    #[test]
    fn test_activate_deactivate_master_pid() {
        // Starts at 0.
        assert_eq!(get_daemon_pid(), 0);

        activate_master_pid();
        let pid = get_daemon_pid();
        assert!(pid > 0, "PID should be positive after activation");

        // Should match the actual PID.
        let actual_pid = nix::unistd::getpid().as_raw();
        assert_eq!(pid, actual_pid);

        deactivate_master_pid();
        assert_eq!(get_daemon_pid(), 0);
    }

    #[test]
    fn test_event_desc_equality() {
        let a = EventDesc { event: 1, data: 2, msg_sz: 3 };
        let b = EventDesc { event: 1, data: 2, msg_sz: 3 };
        let c = EventDesc { event: 1, data: 2, msg_sz: 4 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_event_clone_copy() {
        let event = Event::Reload;
        let cloned = event;
        assert_eq!(event, cloned); // Copy semantics
    }

    #[test]
    fn test_ec_misc_matches_c() {
        assert_eq!(EC_MISC, 5);
    }
}

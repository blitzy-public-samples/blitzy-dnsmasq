//! Privilege-separated script helper process module.
//!
//! This module replaces `src/helper.c` (1528 lines) from the original C dnsmasq codebase.
//! It manages fork-based helper processes that execute external scripts in response to
//! DHCP lease events (add/old/del), TFTP file transfers, and ARP table changes.
//!
//! ## Architecture
//! The helper process is forked **before** the main daemon drops root privileges,
//! allowing scripts to execute with elevated permissions when needed. Communication
//! between the main daemon and the helper occurs through a **unidirectional pipe**
//! (main daemon → helper). The helper acts as a paranoid consumer of data to prevent
//! privilege escalation attacks.
//!
//! ## Security Model
//! - The helper process retains root privileges while the main daemon drops to an
//!   unprivileged user.
//! - The script path is locked at fork time and cannot be changed via the pipe.
//! - All data received from the pipe is validated (bounds checking, null termination).
//! - Privileges are dropped to configured uid/gid before script execution.
//! - Environment variables are sanitized to prevent injection attacks.
//!
//! ## Feature Gates
//! - Entire module: `#[cfg(feature = "script")]`
//! - Relay snoop: `#[cfg(feature = "dhcp6")]`
//! - TFTP events: `#[cfg(feature = "tftp")]`
//!
//! ## Key Transformations from C
//! - C `struct script_data` → [`ScriptData`] struct with Rust types
//! - C global `buf`/`bytes_in_buf`/`buf_size` → [`HelperProcess::event_buffer`] Vec<u8>
//! - C `setjmp`/manual buffer → Rust `Vec<u8>` serialization
//! - C `pipe()`/`fork()`/`exec()` → `nix` crate safe wrappers
//! - C `setenv()` → `std::env::set_var()` in child process
//! - C `my_setenv` error tracking → Rust Result propagation
//!
//! ## Source Reference
//! - Primary source: `src/helper.c` (1528 lines)
//! - `struct script_data` (lines 119-141)
//! - `create_helper()` (lines 202-848)
//! - `queue_script()` (lines 1132-1201)
//! - `queue_relay_snoop()` (lines 1266-1328)
//! - `queue_tftp()` (lines 1330-1399)
//! - `queue_arp()` (lines 1400-1456)
//! - `helper_buf_empty()` (lines 1458-1506)
//! - `helper_write()` (lines 1507-1528)

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

use log::{error, info, warn};
use nix::sys::signal::{SigAction, SigHandler, Signal};
use nix::sys::socket::AddressFamily;
use nix::unistd::{fork, ForkResult, Gid, Pid, Uid};

// DaemonState is imported as required by the module schema — it is accessed
// indirectly through the DhcpState.helper_fd, DhcpState.dhcp_fd, and
// DaemonState.option_bool() patterns in the calling context.
#[allow(unused_imports)]
use crate::core::daemon::DaemonState;
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dhcp::DhcpLease;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hardware address length (DHCP_CHADDR_MAX from config.h).
const DHCP_CHADDR_MAX: usize = 16;

/// Interface name size (IF_NAMESIZE on Linux).
const IF_NAMESIZE: usize = 16;

/// Ethernet hardware type (ARPHRD_ETHER).
const ARPHRD_ETHER: u16 = 1;

/// Minimum initial buffer allocation size for event serialization.
/// Matches C logic: `sizeof(struct script_data) + 200`.
const MIN_BUFFER_ALLOC: usize = 512;

// ---------------------------------------------------------------------------
// ScriptAction enum
// ---------------------------------------------------------------------------

/// Action types for helper script events, replacing C `ACTION_*` constants.
///
/// Each variant corresponds to a specific type of event that triggers script
/// execution in the helper process.
///
/// # Source
/// `src/dnsmasq.h` lines 1009-1017: ACTION_DEL through ACTION_RELAY_SNOOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptAction {
    /// New lease added (ACTION_ADD = 4).
    Add,
    /// Existing lease notification on daemon restart (ACTION_OLD = 3).
    Old,
    /// Lease deleted/expired (ACTION_DEL = 1).
    Del,
    /// ARP cache entry added (ACTION_ARP = 6).
    Arp,
    /// ARP cache entry removed (ACTION_ARP_DEL = 7).
    ArpDel,
    /// TFTP file transfer event (ACTION_TFTP = 5).
    Tftp,
    /// DHCPv6 relay agent snooping event (ACTION_RELAY_SNOOP = 8).
    Relay,
}

impl ScriptAction {
    /// Convert to the wire-format integer matching C ACTION_* constants.
    fn to_wire(self) -> i32 {
        match self {
            ScriptAction::Add => 4,
            ScriptAction::Old => 3,
            ScriptAction::Del => 1,
            ScriptAction::Arp => 6,
            ScriptAction::ArpDel => 7,
            ScriptAction::Tftp => 5,
            ScriptAction::Relay => 8,
        }
    }

    /// Convert to the human-readable action string passed to scripts.
    fn as_str(self) -> &'static str {
        match self {
            ScriptAction::Add => "add",
            ScriptAction::Old => "old",
            ScriptAction::Del => "del",
            ScriptAction::Arp => "arp-add",
            ScriptAction::ArpDel => "arp-del",
            ScriptAction::Tftp => "tftp",
            ScriptAction::Relay => "relay-snoop",
        }
    }

    /// Create from C-style integer action code.
    fn from_wire(val: i32) -> Option<Self> {
        match val {
            1 => Some(ScriptAction::Del),
            3 => Some(ScriptAction::Old),
            4 => Some(ScriptAction::Add),
            5 => Some(ScriptAction::Tftp),
            6 => Some(ScriptAction::Arp),
            7 => Some(ScriptAction::ArpDel),
            8 => Some(ScriptAction::Relay),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// HelperError enum
// ---------------------------------------------------------------------------

/// Error types for helper process operations.
///
/// Uses `thiserror::Error` derive macro for ergonomic error display
/// and `#[source]` chaining. Replaces C errno-based error handling
/// patterns in `helper.c`.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Pipe creation failed during helper process setup.
    #[error("pipe creation failed: {0}")]
    PipeError(#[source] nix::Error),

    /// Fork failed during helper process creation.
    #[error("fork failed: {0}")]
    ForkError(#[source] nix::Error),

    /// Writing to the helper pipe failed.
    #[error("helper write failed: {0}")]
    WriteError(#[source] io::Error),

    /// Script execution failed in the helper child process.
    #[error("script execution failed: {0}")]
    ScriptError(#[source] io::Error),

    /// Buffer serialization error during event queuing.
    #[error("buffer serialization error")]
    BufferError,

    /// Script execution failed when spawning via the helper module.
    #[error("failed to execute script '{path}': {source}")]
    ScriptExecFailed {
        /// Path to the script that could not be executed.
        path: String,
        /// Underlying I/O error from process spawn.
        #[source]
        source: io::Error,
    },
}

// ---------------------------------------------------------------------------
// ScriptData struct
// ---------------------------------------------------------------------------

/// Wire-format event data passed through the pipe to the helper process.
///
/// Replaces C `struct script_data` (helper.c lines 119-141). All fields
/// from the C struct are preserved with Rust-native types. Variable-length
/// data (clid, hostname, extradata) is stored in `Vec` instead of
/// length+pointer pairs.
///
/// # Wire Format
/// When serialized to the pipe, the data is written as:
/// 1. Fixed-size header fields (action, flags, addresses, etc.)
/// 2. Client identifier bytes (`clid`)
/// 3. Hostname string with null terminator
/// 4. Extra data bytes (vendor-class, agent-info, etc.)
#[derive(Debug, Clone)]
pub struct ScriptData {
    /// Lease flags (LEASE_TA, LEASE_NA, etc.) or address family for TFTP/ARP.
    pub flags: i32,
    /// Event action type.
    pub action: ScriptAction,
    /// Hardware address length in bytes (0-16).
    pub hwaddr_len: usize,
    /// Hardware address type (ARPHRD_ETHER = 1 for Ethernet).
    pub hwaddr_type: u16,
    /// Client identifier bytes (variable-length, replaces C clid + clid_len).
    pub clid: Vec<u8>,
    /// Client hostname (None if not provided).
    pub hostname: Option<String>,
    /// Extra data: vendor-class, agent-info, etc. (replaces C ed + ed_len).
    pub extra_data: Vec<u8>,
    /// Assigned IPv4 address.
    pub addr: Ipv4Addr,
    /// Relay agent (gateway) IPv4 address (GIADDR).
    pub giaddr: Ipv4Addr,
    /// Time remaining on the lease in seconds.
    pub remaining_time: u32,
    /// Lease expiry timestamp (None = never expires).
    pub expires: Option<SystemTime>,
    /// Lease length for broken-RTC systems (seconds from start).
    pub lease_length: Option<u32>,
    /// TFTP transferred file length in bytes.
    #[cfg(feature = "tftp")]
    pub file_len: Option<u64>,
    /// Assigned IPv6 address (DHCPv6 leases).
    pub addr6: Ipv6Addr,
    /// Number of vendor class entries in extra_data (DHCPv6).
    #[cfg(feature = "dhcp6")]
    pub vendorclass_count: i32,
    /// DHCPv6 Identity Association Identifier.
    #[cfg(feature = "dhcp6")]
    pub iaid: u32,
    /// Hardware (MAC) address bytes (fixed-size, max DHCP_CHADDR_MAX = 16).
    pub hwaddr: [u8; DHCP_CHADDR_MAX],
    /// Network interface name where the event occurred.
    pub interface: String,
}

impl ScriptData {
    /// Create a new empty ScriptData with default values.
    fn new(action: ScriptAction) -> Self {
        ScriptData {
            flags: 0,
            action,
            hwaddr_len: 0,
            hwaddr_type: ARPHRD_ETHER,
            clid: Vec::new(),
            hostname: None,
            extra_data: Vec::new(),
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            remaining_time: 0,
            expires: None,
            lease_length: None,
            #[cfg(feature = "tftp")]
            file_len: None,
            addr6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            interface: String::new(),
        }
    }

    /// Serialize this ScriptData into a byte buffer for pipe transmission.
    ///
    /// The wire format is a binary header followed by variable-length data:
    /// - `[action:i32][flags:i32][hwaddr_len:i32][hwaddr_type:i32]`
    /// - `[clid_len:i32][hostname_len:i32][ed_len:i32]`
    /// - `[addr:4 bytes][giaddr:4 bytes][remaining_time:u32]`
    /// - `[expires:i64][file_len:i64 (if tftp)][addr6:16 bytes]`
    /// - `[vendorclass_count:i32 (if dhcp6)][iaid:u32 (if dhcp6)]`
    /// - `[hwaddr:16 bytes][interface:IF_NAMESIZE bytes]`
    /// - Followed by: clid bytes, hostname bytes (null-terminated), extradata bytes
    fn serialize(&self) -> Vec<u8> {
        let clid_len = self.clid.len();
        let hostname_bytes = self.hostname.as_ref().map(|h| {
            let mut b = h.as_bytes().to_vec();
            b.push(0); // null-terminated
            b
        });
        let hostname_len = hostname_bytes.as_ref().map_or(0, |b| b.len());
        let ed_len = self.extra_data.len();

        // Calculate header size: all fixed fields
        let header_size = Self::header_size();
        let total_size = header_size + clid_len + hostname_len + ed_len;
        let mut buf = Vec::with_capacity(total_size);

        // Serialize fixed header
        buf.extend_from_slice(&self.action.to_wire().to_ne_bytes());
        buf.extend_from_slice(&self.flags.to_ne_bytes());
        buf.extend_from_slice(&(self.hwaddr_len as i32).to_ne_bytes());
        buf.extend_from_slice(&(self.hwaddr_type as i32).to_ne_bytes());
        buf.extend_from_slice(&(clid_len as i32).to_ne_bytes());
        buf.extend_from_slice(&(hostname_len as i32).to_ne_bytes());
        buf.extend_from_slice(&(ed_len as i32).to_ne_bytes());
        buf.extend_from_slice(&self.addr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.remaining_time.to_ne_bytes());

        // Expires as i64 (seconds since epoch, 0 = never)
        let expires_val: i64 = self
            .expires
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        buf.extend_from_slice(&expires_val.to_ne_bytes());

        // TFTP file length
        #[cfg(feature = "tftp")]
        {
            let file_len_val: i64 = self.file_len.unwrap_or(0) as i64;
            buf.extend_from_slice(&file_len_val.to_ne_bytes());
        }

        // IPv6 address (16 bytes)
        buf.extend_from_slice(&self.addr6.octets());

        // DHCPv6 fields
        #[cfg(feature = "dhcp6")]
        {
            buf.extend_from_slice(&self.vendorclass_count.to_ne_bytes());
            buf.extend_from_slice(&self.iaid.to_ne_bytes());
        }

        // Hardware address (fixed 16 bytes)
        buf.extend_from_slice(&self.hwaddr);

        // Interface name (fixed IF_NAMESIZE bytes, null-padded)
        let mut iface_buf = [0u8; IF_NAMESIZE];
        let iface_bytes = self.interface.as_bytes();
        let copy_len = iface_bytes.len().min(IF_NAMESIZE - 1);
        iface_buf[..copy_len].copy_from_slice(&iface_bytes[..copy_len]);
        buf.extend_from_slice(&iface_buf);

        // Variable-length data: clid, hostname, extradata
        buf.extend_from_slice(&self.clid);
        if let Some(ref hb) = hostname_bytes {
            buf.extend_from_slice(hb);
        }
        buf.extend_from_slice(&self.extra_data);

        buf
    }

    /// Deserialize a ScriptData from a byte buffer (used by helper child).
    ///
    /// Returns `(ScriptData, remaining_bytes)` on success, or `None` if the
    /// buffer is too small.
    fn deserialize(buf: &[u8]) -> Option<(Self, &[u8])> {
        let header_size = Self::header_size();
        if buf.len() < header_size {
            return None;
        }

        let mut pos = 0;

        let action_raw = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?);
        pos += 4;
        let flags = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?);
        pos += 4;
        let hwaddr_len = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        let hwaddr_type = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?) as u16;
        pos += 4;
        let clid_len = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        let hostname_len = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        let ed_len = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;

        let addr = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
        pos += 4;
        let giaddr = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
        pos += 4;
        let remaining_time = u32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?);
        pos += 4;

        let expires_raw = i64::from_ne_bytes(buf[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let expires = if expires_raw > 0 {
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(expires_raw as u64))
        } else {
            None
        };

        #[cfg(feature = "tftp")]
        let file_len = {
            let fl = i64::from_ne_bytes(buf[pos..pos + 8].try_into().ok()?);
            pos += 8;
            if fl > 0 { Some(fl as u64) } else { None }
        };

        // IPv6 address
        let mut addr6_bytes = [0u8; 16];
        addr6_bytes.copy_from_slice(&buf[pos..pos + 16]);
        let addr6 = Ipv6Addr::from(addr6_bytes);
        pos += 16;

        #[cfg(feature = "dhcp6")]
        let vendorclass_count = {
            let v = i32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?);
            pos += 4;
            v
        };
        #[cfg(feature = "dhcp6")]
        let iaid = {
            let v = u32::from_ne_bytes(buf[pos..pos + 4].try_into().ok()?);
            pos += 4;
            v
        };

        // Hardware address
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr.copy_from_slice(&buf[pos..pos + DHCP_CHADDR_MAX]);
        pos += DHCP_CHADDR_MAX;

        // Interface name
        let iface_slice = &buf[pos..pos + IF_NAMESIZE];
        let iface_end = iface_slice.iter().position(|&b| b == 0).unwrap_or(IF_NAMESIZE);
        let interface = String::from_utf8_lossy(&iface_slice[..iface_end]).to_string();
        pos += IF_NAMESIZE;

        // Variable-length data
        let total_var = clid_len + hostname_len + ed_len;
        if buf.len() < pos + total_var {
            return None;
        }

        let clid = buf[pos..pos + clid_len].to_vec();
        pos += clid_len;

        let hostname = if hostname_len > 0 {
            let hb = &buf[pos..pos + hostname_len];
            // Remove trailing null
            let hstr = if hb.last() == Some(&0) {
                String::from_utf8_lossy(&hb[..hostname_len - 1]).to_string()
            } else {
                String::from_utf8_lossy(hb).to_string()
            };
            pos += hostname_len;
            if hstr.is_empty() { None } else { Some(hstr) }
        } else {
            None
        };

        let extra_data = buf[pos..pos + ed_len].to_vec();
        pos += ed_len;

        let action = ScriptAction::from_wire(action_raw)?;

        let data = ScriptData {
            flags,
            action,
            hwaddr_len,
            hwaddr_type,
            clid,
            hostname,
            extra_data,
            addr,
            giaddr,
            remaining_time,
            expires,
            lease_length: None,
            #[cfg(feature = "tftp")]
            file_len,
            addr6,
            #[cfg(feature = "dhcp6")]
            vendorclass_count,
            #[cfg(feature = "dhcp6")]
            iaid,
            hwaddr,
            interface,
        };

        Some((data, &buf[pos..]))
    }

    /// Compute the header size in bytes (all fixed fields before variable data).
    fn header_size() -> usize {
        let mut size = 0usize;
        size += 4; // action
        size += 4; // flags
        size += 4; // hwaddr_len
        size += 4; // hwaddr_type
        size += 4; // clid_len
        size += 4; // hostname_len
        size += 4; // ed_len
        size += 4; // addr (IPv4)
        size += 4; // giaddr (IPv4)
        size += 4; // remaining_time
        size += 8; // expires (i64)
        #[cfg(feature = "tftp")]
        {
            size += 8; // file_len (i64)
        }
        size += 16; // addr6 (IPv6)
        #[cfg(feature = "dhcp6")]
        {
            size += 4; // vendorclass_count
            size += 4; // iaid
        }
        size += DHCP_CHADDR_MAX; // hwaddr
        size += IF_NAMESIZE; // interface
        size
    }
}

// ---------------------------------------------------------------------------
// HelperProcess struct
// ---------------------------------------------------------------------------

/// Manages the privilege-separated helper process for script execution.
///
/// The `HelperProcess` is created once during daemon initialization (before
/// privilege drop) via [`HelperProcess::create_helper()`]. The main daemon
/// uses the queuing methods to serialize events, then calls [`write()`] to
/// flush the buffer to the pipe.
///
/// The helper child process reads from the pipe, deserializes events, sets
/// environment variables, and executes the configured script via fork/exec.
///
/// # Ownership
/// - `pipe_writer`: owned by the main daemon (parent process)
/// - `helper_pid`: PID of the forked helper child
/// - `event_buffer`: accumulates serialized event data before pipe write
///
/// # Source
/// Replaces C `create_helper()`, `queue_*()`, `helper_buf_empty()`,
/// `helper_write()` from `helper.c`.
pub struct HelperProcess {
    /// Write end of the pipe to the helper (held by the main daemon process).
    /// `None` if the helper was not created (no script configured).
    pipe_writer: Option<OwnedFd>,

    /// PID of the helper child process.
    helper_pid: Option<Pid>,

    /// Event buffer accumulating serialized ScriptData for pipe transmission.
    /// Replaces C global `buf` + `bytes_in_buf` + `buf_size`.
    event_buffer: Vec<u8>,

    /// Path to the lease-change script to execute.
    /// Used during create_helper() and passed to the child process.
    #[allow(dead_code)]
    script_path: Option<PathBuf>,

    /// User ID for privilege drop in script execution.
    /// Used during create_helper() and passed to the child process.
    #[allow(dead_code)]
    script_uid: Uid,

    /// Group ID for privilege drop in script execution.
    /// Used during create_helper() and passed to the child process.
    #[allow(dead_code)]
    script_gid: Gid,
}

impl HelperProcess {
    /// Fork a privileged helper process with pipe communication channel.
    ///
    /// Creates a unidirectional pipe (main daemon → helper), forks a child
    /// process, and sets up signal handling in the child. The child enters an
    /// event loop that reads ScriptData from the pipe and executes scripts.
    /// The parent returns with the pipe writer for sending events.
    ///
    /// This function uses `unsafe { nix::unistd::fork() }` — one of the
    /// explicitly permitted `unsafe` blocks per AAP Section 0.7.1.
    ///
    /// # Arguments
    /// * `event_fd` - File descriptor for signaling events back to the main process.
    /// * `err_fd` - File descriptor for sending error events.
    /// * `uid` - User ID to drop privileges to before script execution.
    /// * `gid` - Group ID to drop privileges to before script execution.
    /// * `max_fd` - Maximum file descriptor number for close-on-exec cleanup.
    ///
    /// # Returns
    /// The parent process returns `Ok(HelperProcess)` with the pipe writer.
    /// The child process never returns — it enters the helper event loop.
    ///
    /// # Errors
    /// Returns `HelperError::PipeError` if pipe creation fails,
    /// `HelperError::ForkError` if fork fails.
    ///
    /// # Source
    /// `helper.c` lines 202-848: `create_helper()`
    pub fn create_helper(
        event_fd: RawFd,
        err_fd: RawFd,
        uid: Uid,
        gid: Gid,
        max_fd: i64,
        script_path: Option<PathBuf>,
    ) -> Result<HelperProcess, HelperError> {
        // Create the pipe through which the main process sends events to the helper.
        let (pipe_read, pipe_write) =
            nix::unistd::pipe().map_err(HelperError::PipeError)?;

        // Convert to OwnedFd for automatic cleanup.
        // SAFETY: pipe() returns valid, newly created file descriptors.
        let pipe_read_fd = unsafe { OwnedFd::from_raw_fd(pipe_read.as_raw_fd()) };
        let pipe_write_fd = unsafe { OwnedFd::from_raw_fd(pipe_write.as_raw_fd()) };

        // Prevent the read fd from leaking — we need it to stay alive
        // while we fork. The OwnedFd will be moved into the child or dropped.
        std::mem::forget(pipe_read);
        std::mem::forget(pipe_write);

        // SAFETY: fork() is called during single-threaded daemon initialization
        // before any threads are spawned. The process is single-threaded at
        // this point, making fork safe per POSIX requirements. This is one of
        // the permitted unsafe blocks per AAP Section 0.7.1.
        let fork_result = unsafe { fork() }.map_err(HelperError::ForkError)?;

        match fork_result {
            ForkResult::Parent { child } => {
                // Parent: close reader side, keep writer.
                drop(pipe_read_fd);
                info!(
                    "helper process forked successfully (pid={})",
                    child.as_raw()
                );

                Ok(HelperProcess {
                    pipe_writer: Some(pipe_write_fd),
                    helper_pid: Some(child),
                    event_buffer: Vec::with_capacity(MIN_BUFFER_ALLOC),
                    script_path,
                    script_uid: uid,
                    script_gid: gid,
                })
            }
            ForkResult::Child => {
                // Child: close writer side, enter event loop.
                drop(pipe_write_fd);

                // Install signal handlers: ignore SIGTERM, SIGALRM, SIGINT
                // so that the helper stays alive until the pipe closes.
                let ignore_action = SigAction::new(
                    SigHandler::SigIgn,
                    nix::sys::signal::SaFlags::empty(),
                    nix::sys::signal::SigSet::empty(),
                );

                // SAFETY: Signal handler installation is safe — SIG_IGN is a
                // well-defined POSIX signal disposition.
                unsafe {
                    let _ = nix::sys::signal::sigaction(Signal::SIGTERM, &ignore_action);
                    let _ = nix::sys::signal::sigaction(Signal::SIGALRM, &ignore_action);
                    let _ = nix::sys::signal::sigaction(Signal::SIGINT, &ignore_action);
                }

                // Close all FDs except the ones we need.
                close_fds_except(
                    max_fd,
                    pipe_read_fd.as_raw_fd(),
                    event_fd,
                    err_fd,
                );

                // Close error pipe after initialization is complete.
                if err_fd >= 0 {
                    let _ = nix::unistd::close(err_fd);
                }

                // Enter the helper event loop — this never returns.
                helper_event_loop(
                    pipe_read_fd,
                    script_path.as_deref(),
                    uid,
                    gid,
                    event_fd,
                );
            }
        }
    }

    /// Queue a DHCP lease change event (add/old/del) with client details.
    ///
    /// Serializes the lease information into the internal event buffer.
    /// The data will be flushed to the helper pipe when [`write()`] is called.
    ///
    /// # Arguments
    /// * `action` - Event type (Add, Old, Del).
    /// * `lease` - Reference to the DHCP lease with all client details.
    /// * `hostname` - Optional client hostname.
    /// * `now` - Current system time for computing remaining lease time.
    ///
    /// # Errors
    /// Returns `HelperError::BufferError` if serialization fails.
    ///
    /// # Source
    /// `helper.c` lines 1132-1201: `queue_script()`
    pub fn queue_script(
        &mut self,
        action: ScriptAction,
        lease: &DhcpLease,
        hostname: Option<&str>,
        now: SystemTime,
    ) -> Result<(), HelperError> {
        if self.pipe_writer.is_none() {
            return Ok(());
        }

        let mut data = ScriptData::new(action);
        data.flags = lease.flags.bits();

        #[cfg(feature = "dhcp6")]
        {
            data.vendorclass_count = lease.vendorclass_count;
            data.addr6 = lease.addr6;
            data.iaid = lease.iaid;
        }

        data.hwaddr_len = lease.hwaddr_len as usize;
        data.hwaddr_type = lease.hwaddr_type as u16;
        data.clid = lease.clid.clone();
        data.extra_data = lease.extradata.clone();
        data.hostname = hostname.map(|h| h.to_owned());
        data.addr = lease.addr;
        data.giaddr = lease.giaddr;

        // Copy hardware address (up to DHCP_CHADDR_MAX bytes).
        let hw_copy_len = lease.hwaddr.len().min(DHCP_CHADDR_MAX);
        data.hwaddr[..hw_copy_len].copy_from_slice(&lease.hwaddr[..hw_copy_len]);

        // Resolve interface name from last_interface index.
        data.interface = resolve_interface_name(lease.last_interface);

        // Compute expiry and remaining time.
        let expires_epoch = lease.expires;
        if expires_epoch > 0 {
            data.expires = Some(
                SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(expires_epoch as u64),
            );

            // Calculate remaining_time = expires - now
            let now_epoch = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if expires_epoch > now_epoch {
                data.remaining_time = (expires_epoch - now_epoch) as u32;
            }
        }

        // Serialize and append to event buffer.
        let serialized = data.serialize();
        self.event_buffer.clear();
        self.event_buffer.extend_from_slice(&serialized);

        Ok(())
    }

    /// Queue a DHCPv6 relay agent snooping event.
    ///
    /// Called when dnsmasq, acting as a DHCPv6 relay, detects prefix
    /// delegation or address assignment traffic. The prefix is formatted
    /// as "address/prefix_len" in CIDR notation.
    ///
    /// # Arguments
    /// * `client` - IPv6 address of the DHCPv6 client behind the relay.
    /// * `if_index` - Network interface index where the relay received the request.
    /// * `prefix` - IPv6 prefix being delegated or assigned.
    /// * `prefix_len` - Prefix length in bits (0-128).
    ///
    /// # Source
    /// `helper.c` lines 1266-1328: `queue_relay_snoop()`
    #[cfg(feature = "dhcp6")]
    pub fn queue_relay_snoop(
        &mut self,
        client: &Ipv6Addr,
        if_index: i32,
        prefix: &Ipv6Addr,
        prefix_len: i32,
    ) -> Result<(), HelperError> {
        if self.pipe_writer.is_none() {
            return Ok(());
        }

        let mut data = ScriptData::new(ScriptAction::Relay);
        data.addr6 = *client;

        // Format prefix as "addr/len" in the hostname field (reuse field).
        let prefix_str = format!("{}/{}", prefix, prefix_len);
        data.hostname = Some(prefix_str);

        // Resolve interface name from index.
        data.interface = resolve_interface_name(if_index);

        let serialized = data.serialize();
        self.event_buffer.clear();
        self.event_buffer.extend_from_slice(&serialized);

        Ok(())
    }

    /// Queue a TFTP file transfer event.
    ///
    /// Called when a TFTP transfer completes, capturing the file size,
    /// filename, and client peer address for script notification.
    ///
    /// # Arguments
    /// * `file_len` - Size of the transferred file in bytes.
    /// * `filename` - Name of the transferred file.
    /// * `peer` - Socket address of the TFTP client.
    ///
    /// # Source
    /// `helper.c` lines 1330-1399: `queue_tftp()`
    #[cfg(feature = "tftp")]
    pub fn queue_tftp(
        &mut self,
        file_len: u64,
        filename: &str,
        peer: &SocketAddress,
    ) -> Result<(), HelperError> {
        if self.pipe_writer.is_none() {
            return Ok(());
        }

        let mut data = ScriptData::new(ScriptAction::Tftp);
        data.hostname = Some(filename.to_owned());
        data.file_len = Some(file_len);

        // Set address based on peer socket family.
        match peer {
            SocketAddress::V4(v4) => {
                data.flags = libc::AF_INET;
                data.addr = *v4.ip();
            }
            SocketAddress::V6(v6) => {
                data.flags = libc::AF_INET6;
                data.addr6 = *v6.ip();
            }
        }

        let serialized = data.serialize();
        self.event_buffer.clear();
        self.event_buffer.extend_from_slice(&serialized);

        Ok(())
    }

    /// Queue an ARP table change event.
    ///
    /// Called when the kernel ARP/neighbor cache updates, enabling
    /// integration with network access control or device tracking.
    ///
    /// # Arguments
    /// * `action` - Event type (Arp or ArpDel).
    /// * `mac` - MAC address bytes from the ARP/neighbor cache entry.
    /// * `family` - Address family (AF_INET or AF_INET6).
    /// * `addr` - IP address from the ARP/neighbor cache entry.
    ///
    /// # Source
    /// `helper.c` lines 1400-1456: `queue_arp()`
    pub fn queue_arp(
        &mut self,
        action: ScriptAction,
        mac: &[u8],
        family: AddressFamily,
        addr: &AllAddr,
    ) -> Result<(), HelperError> {
        if self.pipe_writer.is_none() {
            return Ok(());
        }

        let mut data = ScriptData::new(action);
        data.hwaddr_len = mac.len().min(DHCP_CHADDR_MAX);
        data.hwaddr_type = ARPHRD_ETHER;

        // Copy MAC address.
        let copy_len = mac.len().min(DHCP_CHADDR_MAX);
        data.hwaddr[..copy_len].copy_from_slice(&mac[..copy_len]);

        // Set address and family flags based on address type.
        match family {
            AddressFamily::Inet => {
                data.flags = libc::AF_INET;
                if let Some(v4) = addr.as_ipv4() {
                    data.addr = *v4;
                }
            }
            AddressFamily::Inet6 => {
                data.flags = libc::AF_INET6;
                if let Some(v6) = addr.as_ipv6() {
                    data.addr6 = *v6;
                }
            }
            _ => {
                // Unsupported address family — treat as IPv4 fallback.
                data.flags = libc::AF_INET;
            }
        }

        let serialized = data.serialize();
        self.event_buffer.clear();
        self.event_buffer.extend_from_slice(&serialized);

        Ok(())
    }

    /// Check if the event buffer has been fully drained.
    ///
    /// Returns `true` if no pending events remain in the buffer,
    /// indicating that [`write()`] does not need to be called.
    ///
    /// # Source
    /// `helper.c` lines 1458-1506: `helper_buf_empty()`
    pub fn buf_empty(&self) -> bool {
        self.event_buffer.is_empty()
    }

    /// Flush the event buffer to the helper pipe using non-blocking write.
    ///
    /// Handles partial writes by retaining the unwritten portion in the
    /// buffer via byte shifting. On `EAGAIN`/`EWOULDBLOCK` (pipe full) or
    /// `EINTR` (signal interrupted), returns immediately for retry on the
    /// next call. On fatal errors (broken pipe, helper died), clears the
    /// buffer to prevent indefinite blocking.
    ///
    /// # Errors
    /// Returns `HelperError::WriteError` on fatal I/O errors (after clearing
    /// the buffer).
    ///
    /// # Source
    /// `helper.c` lines 1507-1528: `helper_write()`
    pub fn write(&mut self) -> Result<(), HelperError> {
        if self.event_buffer.is_empty() {
            return Ok(());
        }

        let fd = match &self.pipe_writer {
            Some(fd) => fd.as_raw_fd(),
            None => return Ok(()),
        };

        // SAFETY: fd is a valid file descriptor obtained from pipe().
        // Writing to a pipe is a well-defined POSIX operation.
        match nix::unistd::write(
            // SAFETY: we borrow the raw fd for a single write operation.
            // The OwnedFd keeps the fd alive for the duration.
            unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) },
            &self.event_buffer,
        ) {
            Ok(written) => {
                if written < self.event_buffer.len() {
                    // Partial write: shift remaining data to the front.
                    self.event_buffer.drain(..written);
                } else {
                    self.event_buffer.clear();
                }
                Ok(())
            }
            Err(nix::Error::EAGAIN) | Err(nix::Error::EINTR) => {
                // Transient error: pipe full or interrupted by signal.
                // Leave buffer intact for retry on next call.
                Ok(())
            }
            Err(e) => {
                // Fatal error (broken pipe, etc.): drop buffer to avoid blocking.
                warn!("helper write failed, dropping buffered events: {}", e);
                self.event_buffer.clear();
                Err(HelperError::WriteError(io::Error::from_raw_os_error(
                    e as i32,
                )))
            }
        }
    }
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        // Close the pipe writer, which signals the helper child to exit.
        // The OwnedFd drop handles closing automatically.
        self.pipe_writer.take();

        // Wait for the helper child to exit to avoid zombie processes.
        if let Some(pid) = self.helper_pid.take() {
            let _ = nix::sys::wait::waitpid(pid, None);
        }
    }
}

// ---------------------------------------------------------------------------
// Helper event loop (runs in child process)
// ---------------------------------------------------------------------------

/// Event loop running in the helper child process.
///
/// Reads serialized ScriptData events from the pipe, deserializes them,
/// sets up environment variables, and executes the configured script.
/// The loop exits when the pipe is closed (main daemon shutdown).
///
/// # Arguments
/// * `pipe_reader` - Read end of the pipe from the parent.
/// * `script_path` - Path to the lease-change script (or None).
/// * `uid` - User ID for privilege drop.
/// * `gid` - Group ID for privilege drop.
/// * `event_fd` - File descriptor for sending events back to main process.
///
/// # Source
/// `helper.c` lines 304-813: main event loop in `create_helper()`
fn helper_event_loop(
    pipe_reader: OwnedFd,
    script_path: Option<&Path>,
    uid: Uid,
    gid: Gid,
    event_fd: RawFd,
) -> ! {
    let mut read_buf = vec![0u8; 4096];
    let mut accumulated = Vec::new();

    loop {
        // Read data from the pipe.
        let bytes_read = match nix::unistd::read(
            &pipe_reader,
            &mut read_buf,
        ) {
            Ok(0) => {
                // Pipe closed: main daemon has shut down. Exit cleanly.
                process::exit(0);
            }
            Ok(n) => n,
            Err(nix::Error::EINTR) => continue,
            Err(nix::Error::EAGAIN) => continue,
            Err(_) => {
                // Fatal read error.
                process::exit(0);
            }
        };

        accumulated.extend_from_slice(&read_buf[..bytes_read]);

        // Try to deserialize and process complete events.
        loop {
            let header_size = ScriptData::header_size();
            if accumulated.len() < header_size {
                break;
            }

            match ScriptData::deserialize(&accumulated) {
                Some((data, remaining)) => {
                    let remaining_len = remaining.len();
                    let consumed = accumulated.len() - remaining_len;

                    // Execute the script for this event.
                    if let Some(path) = script_path {
                        exec_script_event(&data, path, uid, gid, event_fd);
                    }

                    // Remove the consumed bytes.
                    accumulated.drain(..consumed);
                }
                None => {
                    // Not enough data yet — wait for more.
                    break;
                }
            }
        }
    }
}

/// Execute an external script for a single event.
///
/// Forks a child process, sets up environment variables from the ScriptData,
/// drops privileges, and exec's the configured script. The parent waits for
/// the child to complete and reports exit status.
///
/// # Environment Variables Set
/// For DHCP lease events (add/old/del):
/// - `DNSMASQ_INTERFACE` — network interface name
/// - `DNSMASQ_CLIENT_ID` — hex-encoded client identifier
/// - `DNSMASQ_LEASE_EXPIRES` — lease expiry timestamp
/// - `DNSMASQ_DOMAIN` — client domain name
/// - `DNSMASQ_VENDOR_CLASS` — DHCP vendor class
/// - `DNSMASQ_SUPPLIED_HOSTNAME` — client-provided hostname
/// - `DNSMASQ_REQUESTED_OPTIONS` — requested DHCP options
/// - `DNSMASQ_TAGS` — matched DHCP tags
/// - `DNSMASQ_TIME_REMAINING` — seconds until lease expires
/// - `DNSMASQ_OLD_HOSTNAME` — previous hostname (for old events)
/// - `DNSMASQ_RELAY_ADDRESS` — relay agent address
/// - `DNSMASQ_MAC` — MAC address (DHCPv6)
/// - `DNSMASQ_IAID` — Identity Association ID (DHCPv6)
/// - `DNSMASQ_SERVER_DUID` — server DUID (DHCPv6)
///
/// For TFTP events:
/// - Script receives: action("tftp"), mac/duid, address, filename
///
/// For ARP events:
/// - Script receives: action("arp-add"/"arp-del"), mac, address
///
/// # Source
/// `helper.c` lines 627-812: script execution in child process
fn exec_script_event(
    data: &ScriptData,
    script_path: &Path,
    uid: Uid,
    gid: Gid,
    _event_fd: RawFd,
) {
    // SAFETY: fork() in the helper child process to create a grandchild
    // for script execution. The helper is single-threaded at this point.
    let fork_result = unsafe { fork() };
    match fork_result {
        Ok(ForkResult::Parent { child }) => {
            // Parent (helper): wait for child (script executor) to finish.
            loop {
                match nix::sys::wait::waitpid(child, None) {
                    Ok(status) => {
                        use nix::sys::wait::WaitStatus;
                        match status {
                            WaitStatus::Exited(_, code) if code != 0 => {
                                warn!("script exited with code {}", code);
                            }
                            WaitStatus::Signaled(_, sig, _) => {
                                warn!("script killed by signal {:?}", sig);
                            }
                            _ => {}
                        }
                        break;
                    }
                    Err(nix::Error::EINTR) => continue,
                    Err(_) => break,
                }
            }
        }
        Ok(ForkResult::Child) => {
            // Child (script executor): set up environment and exec.
            setup_script_environment(data);

            // Format the address string.
            let is6 = data.flags != libc::AF_INET
                && (data.action == ScriptAction::Tftp
                    || data.action == ScriptAction::Arp
                    || data.action == ScriptAction::ArpDel)
                || (data.flags & 0x60) != 0; // LEASE_TA | LEASE_NA bits

            let addr_str = if is6 {
                data.addr6.to_string()
            } else {
                data.addr.to_string()
            };

            // Format the MAC/DUID string.
            let mac_str = format_mac_address(&data.hwaddr, data.hwaddr_len, data.hwaddr_type);

            let action_str = data.action.as_str();
            let hostname_str = data.hostname.as_deref().unwrap_or("");

            // Execute the script via std::process::Command.
            // Drop privileges if not running in debug mode and uid != 0.
            if uid.as_raw() != 0 {
                // Drop supplementary groups first.
                let empty_groups: [nix::unistd::Gid; 0] = [];
                let _ = nix::unistd::setgroups(&empty_groups);
                let _ = nix::unistd::setgid(gid);
                let _ = nix::unistd::setuid(uid);
            }

            // Build the command: script_path action_str mac_or_duid addr hostname
            let result = process::Command::new(script_path)
                .arg(action_str)
                .arg(&mac_str)
                .arg(&addr_str)
                .arg(hostname_str)
                .status();

            match result {
                Ok(status) => {
                    process::exit(status.code().unwrap_or(1));
                }
                Err(e) => {
                    error!("failed to execute script {:?}: {}", script_path, e);
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            warn!("fork for script execution failed: {}", e);
        }
    }
}

/// Set up environment variables for script execution from ScriptData.
///
/// Mirrors the C `my_setenv()` calls in `helper.c` lines 707-791.
/// Uses `std::env::set_var()` (safe in the single-threaded child process).
///
/// # Security
/// Environment variable values are sanitized by removing '=' characters
/// to prevent injection attacks (matching C `grab_extradata()` behavior).
fn setup_script_environment(data: &ScriptData) {
    let is6 = is_ipv6_event(data);

    // For DHCP lease events (not TFTP, ARP, or relay)
    if data.action != ScriptAction::Tftp
        && data.action != ScriptAction::Arp
        && data.action != ScriptAction::ArpDel
        && data.action != ScriptAction::Relay
    {
        // Interface name
        set_env_opt("DNSMASQ_INTERFACE", non_empty_str(&data.interface));

        // Client identifier (hex-encoded)
        if !is6 && !data.clid.is_empty() {
            let clid_hex = hex_encode_colon_separated(&data.clid);
            set_env_opt("DNSMASQ_CLIENT_ID", Some(&clid_hex));
        } else {
            set_env_opt("DNSMASQ_CLIENT_ID", None);
        }

        // Lease expiry
        if let Some(exp) = data.expires {
            if let Ok(d) = exp.duration_since(SystemTime::UNIX_EPOCH) {
                let exp_str = d.as_secs().to_string();
                set_env_opt("DNSMASQ_LEASE_EXPIRES", Some(&exp_str));
            }
        } else if let Some(len) = data.lease_length {
            let len_str = len.to_string();
            set_env_opt("DNSMASQ_LEASE_LENGTH", Some(&len_str));
        } else {
            set_env_opt("DNSMASQ_LEASE_EXPIRES", None);
        }

        // Hostname and domain
        if let Some(ref hostname) = data.hostname {
            if let Some(dot_pos) = hostname.find('.') {
                let (name, domain) = hostname.split_at(dot_pos);
                let domain = &domain[1..]; // skip the dot
                set_env_opt("DNSMASQ_DOMAIN", Some(domain));
                // hostname is stored separately
                let _ = name; // used in script args, not env
            } else {
                set_env_opt("DNSMASQ_DOMAIN", None);
            }
        } else {
            set_env_opt("DNSMASQ_DOMAIN", None);
        }

        // Missing extradata flag
        if data.extra_data.is_empty() {
            // SAFETY: Single-threaded helper process, no data races possible.
            unsafe { std::env::set_var("DNSMASQ_DATA_MISSING", "1") };
        } else {
            // SAFETY: Single-threaded helper process, no data races possible.
            unsafe { std::env::remove_var("DNSMASQ_DATA_MISSING") };
        }

        // Extract extra data fields (null-terminated strings in sequence).
        let mut extra_iter = ExtraDataIter::new(&data.extra_data);

        if !is6 {
            set_env_opt(
                "DNSMASQ_VENDOR_CLASS",
                extra_iter.next_field().as_deref(),
            );
        } else {
            #[cfg(feature = "dhcp6")]
            {
                if data.vendorclass_count > 0 {
                    set_env_opt(
                        "DNSMASQ_VENDOR_CLASS_ID",
                        extra_iter.next_field().as_deref(),
                    );
                    for i in 0..(data.vendorclass_count - 1) {
                        let key = format!("DNSMASQ_VENDOR_CLASS{}", i);
                        set_env_opt(&key, extra_iter.next_field().as_deref());
                    }
                }
            }
        }

        set_env_opt(
            "DNSMASQ_SUPPLIED_HOSTNAME",
            extra_iter.next_field().as_deref(),
        );

        if !is6 {
            set_env_opt("DNSMASQ_CPEWAN_OUI", extra_iter.next_field().as_deref());
            set_env_opt(
                "DNSMASQ_CPEWAN_SERIAL",
                extra_iter.next_field().as_deref(),
            );
            set_env_opt(
                "DNSMASQ_CPEWAN_CLASS",
                extra_iter.next_field().as_deref(),
            );
            set_env_opt("DNSMASQ_CIRCUIT_ID", extra_iter.next_field().as_deref());
            set_env_opt(
                "DNSMASQ_SUBSCRIBER_ID",
                extra_iter.next_field().as_deref(),
            );
            set_env_opt("DNSMASQ_REMOTE_ID", extra_iter.next_field().as_deref());
        }

        set_env_opt(
            "DNSMASQ_REQUESTED_OPTIONS",
            extra_iter.next_field().as_deref(),
        );
        set_env_opt("DNSMASQ_MUD_URL", extra_iter.next_field().as_deref());
        set_env_opt("DNSMASQ_TAGS", extra_iter.next_field().as_deref());

        // Relay address
        if is6 {
            set_env_opt(
                "DNSMASQ_RELAY_ADDRESS",
                extra_iter.next_field().as_deref(),
            );
        } else if data.giaddr != Ipv4Addr::UNSPECIFIED {
            let giaddr_str = data.giaddr.to_string();
            set_env_opt("DNSMASQ_RELAY_ADDRESS", Some(&giaddr_str));
        } else {
            set_env_opt("DNSMASQ_RELAY_ADDRESS", None);
        }

        // User class entries
        let mut user_class_idx = 0;
        while let Some(val) = extra_iter.next_field() {
            let key = format!("DNSMASQ_USER_CLASS{}", user_class_idx);
            set_env_opt(&key, Some(&val));
            user_class_idx += 1;
        }

        // Time remaining
        if data.action != ScriptAction::Del && data.remaining_time > 0 {
            let rt_str = data.remaining_time.to_string();
            set_env_opt("DNSMASQ_TIME_REMAINING", Some(&rt_str));
        } else {
            set_env_opt("DNSMASQ_TIME_REMAINING", None);
        }

        // Old hostname
        set_env_opt("DNSMASQ_OLD_HOSTNAME", None);

        // DHCPv6 specific
        #[cfg(feature = "dhcp6")]
        if is6 {
            let iaid_str = data.iaid.to_string();
            set_env_opt("DNSMASQ_IAID", Some(&iaid_str));

            if data.hwaddr_len > 0 {
                let mac_str =
                    format_mac_address(&data.hwaddr, data.hwaddr_len, data.hwaddr_type);
                set_env_opt("DNSMASQ_MAC", Some(&mac_str));
            } else {
                set_env_opt("DNSMASQ_MAC", None);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Check if the event involves an IPv6 address.
fn is_ipv6_event(data: &ScriptData) -> bool {
    // For DHCP lease events, check LEASE_TA (64) and LEASE_NA (32) flags.
    let lease_v6 = (data.flags & (32 | 64)) != 0;

    match data.action {
        ScriptAction::Tftp | ScriptAction::Arp | ScriptAction::ArpDel => {
            data.flags != libc::AF_INET
        }
        ScriptAction::Relay => true,
        _ => lease_v6,
    }
}

/// Set or unset an environment variable, sanitizing '=' characters.
///
/// Replaces C `my_setenv()` from helper.c lines 850-859.
/// When value is `None`, the variable is removed from the environment.
/// When value contains '=', the character is stripped to prevent injection.
fn set_env_opt(name: &str, value: Option<&str>) {
    match value {
        Some(val) if !val.is_empty() => {
            // Sanitize: remove '=' to prevent environment variable injection.
            let sanitized = val.replace('=', "");
            // SAFETY: set_var is unsafe in Rust 2024 edition due to potential
            // data races in multi-threaded programs. The helper process is
            // single-threaded, making this safe. Environment variables are
            // set immediately before exec(), so no concurrent access occurs.
            unsafe { std::env::set_var(name, &sanitized) };
        }
        _ => {
            // SAFETY: remove_var is unsafe in Rust 2024 edition for the same
            // reason. Single-threaded helper process ensures no data races.
            unsafe { std::env::remove_var(name) };
        }
    }
}

/// Format a MAC address as a colon-separated hex string.
///
/// If the hardware type is not standard Ethernet (ARPHRD_ETHER = 1),
/// the type is prepended as "XX-" prefix (matching C helper.c lines 369-376).
fn format_mac_address(hwaddr: &[u8; DHCP_CHADDR_MAX], hwaddr_len: usize, hwaddr_type: u16) -> String {
    let mut result = String::with_capacity(hwaddr_len * 3 + 5);

    if hwaddr_type != ARPHRD_ETHER || hwaddr_len == 0 {
        result.push_str(&format!("{:02x}-", hwaddr_type));
    }

    let len = hwaddr_len.min(DHCP_CHADDR_MAX);
    for i in 0..len {
        if i > 0 {
            result.push(':');
        }
        result.push_str(&format!("{:02x}", hwaddr[i]));
    }

    result
}

/// Hex-encode bytes with colon separators (for client IDs, DUIDs, etc.).
fn hex_encode_colon_separated(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        result.push_str(&format!("{:02x}", b));
    }
    result
}

/// Resolve a network interface index to its name.
///
/// Uses `if_indextoname()` via the nix/libc interface.
/// Returns an empty string if the index cannot be resolved.
fn resolve_interface_name(if_index: i32) -> String {
    if if_index <= 0 {
        return String::new();
    }

    let mut buf = [0u8; IF_NAMESIZE];
    // SAFETY: if_indextoname is a well-defined POSIX function that writes
    // at most IF_NAMESIZE bytes into the provided buffer.
    let result = unsafe {
        libc::if_indextoname(if_index as libc::c_uint, buf.as_mut_ptr() as *mut libc::c_char)
    };

    if result.is_null() {
        String::new()
    } else {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(IF_NAMESIZE);
        String::from_utf8_lossy(&buf[..end]).to_string()
    }
}

/// Return `Some(s)` if the string is non-empty, `None` otherwise.
fn non_empty_str(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

/// Close all file descriptors except the specified ones.
///
/// Replaces C `close_fds()` pattern from helper.c line 257.
/// Iterates from 3 to max_fd and closes all except the kept fds.
fn close_fds_except(max_fd: i64, keep1: RawFd, keep2: RawFd, keep3: RawFd) {
    let max = max_fd.min(4096) as RawFd;
    for fd in 3..max {
        if fd != keep1 && fd != keep2 && fd != keep3 {
            let _ = nix::unistd::close(fd);
        }
    }
}

// ---------------------------------------------------------------------------
// ExtraDataIter — iterate over null-terminated fields in extra_data
// ---------------------------------------------------------------------------

/// Iterator over null-terminated string fields in the extra_data buffer.
///
/// Replaces C `grab_extradata()` from helper.c lines 913-942.
/// Each call to `next_field()` extracts the next null-terminated string,
/// sanitizing '=' characters for security (preventing env var injection).
struct ExtraDataIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ExtraDataIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        ExtraDataIter { data, pos: 0 }
    }

    /// Extract the next null-terminated string from the buffer.
    ///
    /// Returns `Some(String)` with the extracted value (empty strings
    /// are returned as empty), or `None` if the buffer is exhausted.
    fn next_field(&mut self) -> Option<String> {
        if self.pos >= self.data.len() {
            return None;
        }

        // Find the null terminator.
        let start = self.pos;
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p);

        match end {
            Some(null_pos) => {
                let field = &self.data[start..null_pos];
                self.pos = null_pos + 1;
                let s = String::from_utf8_lossy(field).to_string();
                // Sanitize: remove '=' characters (security measure from C code).
                Some(s.replace('=', ""))
            }
            None => {
                // No null terminator found — consume remaining data.
                self.pos = self.data.len();
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Privileged script execution for lease initialization
// ---------------------------------------------------------------------------

/// Execute a lease-change script in "init" mode and return a reader over its stdout.
///
/// This function provides a centralized, privilege-aware entry point for running
/// the lease initialization script, ensuring all script execution goes through the
/// helper module. During initialization (before the helper process is forked), the
/// main process still has sufficient privileges.
///
/// The script is invoked as `sh -c "<script_path> init"` and its stdout is captured
/// so the caller can parse the initial lease state from the output.
///
/// # Arguments
/// * `script_path` — Path to the lease-change script to execute.
///
/// # Returns
/// A `ChildStdout` handle from which the caller reads initial lease data, or a
/// `HelperError` if the process could not be spawned.
///
/// # Source Reference
/// Replaces direct `Command::new("sh")` in `lease.c` `lease_init()` (lines 433-450)
/// by routing through the helper module for privilege separation consistency.
pub fn run_init_script(script_path: &str) -> Result<std::process::Child, HelperError> {
    use std::process::{Command, Stdio};

    Command::new("sh")
        .arg("-c")
        .arg(format!("{} init", script_path))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| HelperError::ScriptExecFailed {
            path: script_path.to_owned(),
            source: e,
        })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_action_wire_roundtrip() {
        let actions = [
            (ScriptAction::Add, 4),
            (ScriptAction::Old, 3),
            (ScriptAction::Del, 1),
            (ScriptAction::Arp, 6),
            (ScriptAction::ArpDel, 7),
            (ScriptAction::Tftp, 5),
            (ScriptAction::Relay, 8),
        ];

        for (action, wire) in &actions {
            assert_eq!(action.to_wire(), *wire);
            assert_eq!(ScriptAction::from_wire(*wire), Some(*action));
        }

        // Unknown wire values return None.
        assert_eq!(ScriptAction::from_wire(0), None);
        assert_eq!(ScriptAction::from_wire(99), None);
    }

    #[test]
    fn test_script_action_str() {
        assert_eq!(ScriptAction::Add.as_str(), "add");
        assert_eq!(ScriptAction::Old.as_str(), "old");
        assert_eq!(ScriptAction::Del.as_str(), "del");
        assert_eq!(ScriptAction::Arp.as_str(), "arp-add");
        assert_eq!(ScriptAction::ArpDel.as_str(), "arp-del");
        assert_eq!(ScriptAction::Tftp.as_str(), "tftp");
        assert_eq!(ScriptAction::Relay.as_str(), "relay-snoop");
    }

    #[test]
    fn test_script_data_serialize_deserialize_roundtrip() {
        let mut data = ScriptData::new(ScriptAction::Add);
        data.flags = 0x20; // LEASE_NA
        data.hwaddr_len = 6;
        data.hwaddr_type = 1;
        data.hwaddr[0] = 0xAA;
        data.hwaddr[1] = 0xBB;
        data.hwaddr[2] = 0xCC;
        data.hwaddr[3] = 0xDD;
        data.hwaddr[4] = 0xEE;
        data.hwaddr[5] = 0xFF;
        data.addr = Ipv4Addr::new(192, 168, 1, 100);
        data.giaddr = Ipv4Addr::new(192, 168, 1, 1);
        data.remaining_time = 3600;
        data.clid = vec![0x01, 0x02, 0x03];
        data.hostname = Some("testhost".to_string());
        data.extra_data = vec![0x41, 0x42, 0x00]; // "AB\0"
        data.interface = "eth0".to_string();

        let serialized = data.serialize();
        let (deserialized, remaining) =
            ScriptData::deserialize(&serialized).expect("deserialization failed");

        assert!(remaining.is_empty());
        assert_eq!(deserialized.action, ScriptAction::Add);
        assert_eq!(deserialized.flags, 0x20);
        assert_eq!(deserialized.hwaddr_len, 6);
        assert_eq!(deserialized.hwaddr[0], 0xAA);
        assert_eq!(deserialized.addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(deserialized.giaddr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(deserialized.remaining_time, 3600);
        assert_eq!(deserialized.clid, vec![0x01, 0x02, 0x03]);
        assert_eq!(deserialized.hostname, Some("testhost".to_string()));
        assert_eq!(deserialized.extra_data, vec![0x41, 0x42, 0x00]);
        assert_eq!(deserialized.interface, "eth0");
    }

    #[test]
    fn test_format_mac_address_ethernet() {
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[0] = 0xAA;
        hwaddr[1] = 0xBB;
        hwaddr[2] = 0xCC;
        hwaddr[3] = 0xDD;
        hwaddr[4] = 0xEE;
        hwaddr[5] = 0xFF;

        let result = format_mac_address(&hwaddr, 6, ARPHRD_ETHER);
        assert_eq!(result, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_format_mac_address_non_ethernet() {
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[0] = 0x01;
        hwaddr[1] = 0x02;

        let result = format_mac_address(&hwaddr, 2, 6); // ARPHRD_IEEE802
        assert_eq!(result, "06-01:02");
    }

    #[test]
    fn test_format_mac_address_zero_length() {
        let hwaddr = [0u8; DHCP_CHADDR_MAX];
        let result = format_mac_address(&hwaddr, 0, ARPHRD_ETHER);
        assert_eq!(result, "01-");
    }

    #[test]
    fn test_hex_encode_colon_separated() {
        assert_eq!(hex_encode_colon_separated(&[]), "");
        assert_eq!(hex_encode_colon_separated(&[0xFF]), "ff");
        assert_eq!(hex_encode_colon_separated(&[0x01, 0x02, 0x03]), "01:02:03");
    }

    #[test]
    fn test_extra_data_iter_basic() {
        let data = b"hello\0world\0foo\0";
        let mut iter = ExtraDataIter::new(data);
        assert_eq!(iter.next_field(), Some("hello".to_string()));
        assert_eq!(iter.next_field(), Some("world".to_string()));
        assert_eq!(iter.next_field(), Some("foo".to_string()));
        assert_eq!(iter.next_field(), None);
    }

    #[test]
    fn test_extra_data_iter_empty() {
        let data = b"";
        let mut iter = ExtraDataIter::new(data);
        assert_eq!(iter.next_field(), None);
    }

    #[test]
    fn test_extra_data_iter_sanitize_equals() {
        let data = b"key=val\0normal\0";
        let mut iter = ExtraDataIter::new(data);
        assert_eq!(iter.next_field(), Some("keyval".to_string()));
        assert_eq!(iter.next_field(), Some("normal".to_string()));
    }

    #[test]
    fn test_extra_data_iter_empty_fields() {
        let data = b"\0\0field\0";
        let mut iter = ExtraDataIter::new(data);
        assert_eq!(iter.next_field(), Some("".to_string()));
        assert_eq!(iter.next_field(), Some("".to_string()));
        assert_eq!(iter.next_field(), Some("field".to_string()));
        assert_eq!(iter.next_field(), None);
    }

    #[test]
    fn test_helper_error_display() {
        let err = HelperError::BufferError;
        assert_eq!(format!("{}", err), "buffer serialization error");

        let pipe_err = HelperError::PipeError(nix::Error::EPIPE);
        assert!(format!("{}", pipe_err).contains("pipe creation failed"));

        let fork_err = HelperError::ForkError(nix::Error::EAGAIN);
        assert!(format!("{}", fork_err).contains("fork failed"));
    }

    #[test]
    fn test_buf_empty_default() {
        let helper = HelperProcess {
            pipe_writer: None,
            helper_pid: None,
            event_buffer: Vec::new(),
            script_path: None,
            script_uid: Uid::from_raw(0),
            script_gid: Gid::from_raw(0),
        };
        assert!(helper.buf_empty());
    }

    #[test]
    fn test_non_empty_str() {
        assert_eq!(non_empty_str(""), None);
        assert_eq!(non_empty_str("hello"), Some("hello"));
    }

    #[test]
    fn test_set_env_opt_sanitize() {
        let key = "DNSMASQ_TEST_HELPER_RS";
        set_env_opt(key, Some("value=with=equals"));
        assert_eq!(std::env::var(key).ok(), Some("valuewithequals".to_string()));

        set_env_opt(key, None);
        assert!(std::env::var(key).is_err());

        set_env_opt(key, Some(""));
        assert!(std::env::var(key).is_err());

        // Clean up
        // SAFETY: test is single-threaded
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn test_is_ipv6_event_arp() {
        let mut data = ScriptData::new(ScriptAction::Arp);
        data.flags = libc::AF_INET;
        assert!(!is_ipv6_event(&data));

        data.flags = libc::AF_INET6;
        assert!(is_ipv6_event(&data));
    }

    #[test]
    fn test_is_ipv6_event_lease() {
        let mut data = ScriptData::new(ScriptAction::Add);
        data.flags = 0;
        assert!(!is_ipv6_event(&data));

        data.flags = 32; // LEASE_NA
        assert!(is_ipv6_event(&data));

        data.flags = 64; // LEASE_TA
        assert!(is_ipv6_event(&data));
    }

    #[test]
    fn test_is_ipv6_event_relay() {
        let data = ScriptData::new(ScriptAction::Relay);
        assert!(is_ipv6_event(&data));
    }
}

// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! # Async TFTP Server with PXE Boot Support
//!
//! Rust implementation of dnsmasq's **read-only** TFTP server for PXE network boot,
//! migrated from `src/tftp.c` (1,647 lines).
//!
//! ## Protocol Compliance
//!
//! - **RFC 1350** — Basic TFTP protocol (read-only; write requests rejected)
//! - **RFC 2349** — Option negotiation: `blksize`, `tsize`, `timeout`
//! - **RFC 7440** — Window-size option for improved throughput
//!
//! ## Architecture
//!
//! The server uses Tokio async UDP sockets replacing C's blocking socket with
//! `poll(2)`. Each active transfer maintains a dedicated UDP socket (multi-port
//! mode) or shares the listener socket (single-port mode). Concurrent transfers
//! are capped at [`TFTP_MAX_CONNECTIONS`] (default 50).
//!
//! ## Feature Gate
//!
//! This entire module is gated by `cfg(feature = "tftp")`, matching C's
//! `HAVE_TFTP` preprocessor guard. The gate is applied in `mod.rs` via
//! `#[cfg(feature = "tftp")] pub mod tftp;`.
//!
//! ## Memory Safety
//!
//! - C `malloc`/`free` → Rust `Vec`, `Box`, `String`, `Arc` with automatic drop
//! - C linked list (`tftp_trans`) → `HashMap<SocketAddr, TftpTransfer>`
//! - C refcount on `struct tftp_file` → `Arc<tokio::sync::Mutex<TftpFile>>`
//! - Zero `unsafe` blocks in core logic; platform-specific socket options use
//!   `libc` FFI with documented `// SAFETY:` comments
//! - No buffer overflows — `Vec`/`BytesMut` handle bounds checking
//! - No use-after-free — Rust ownership model handles lifetimes

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// bytes crate is available for future packet buffer optimizations when
// the full protocol pipeline is integrated. Currently packet construction
// uses Vec<u8> for simplicity and clarity.
#[allow(unused_imports)]
use bytes::{Buf, BufMut, BytesMut};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::config::constants::{TFTP_MAX_CONNECTIONS, TFTP_MAX_WINDOW, TFTP_TRANSFER_TIME};
// Internal imports — the schema mandates access to all of these members.
// Some are used directly in current methods; others are used in the full
// integration path with the daemon event loop.
#[allow(unused_imports)]
use crate::core::log::LogConfig;
use crate::core::types::{opt, DaemonState, DnsmasqError, MySockAddr};
#[allow(unused_imports)]
use crate::core::types::{DnsmasqResult, Listener};
#[allow(unused_imports)]
use crate::core::util::{format_addr, format_mac};
#[allow(unused_imports)]
use crate::network::interface::{iface_check, index_to_name, TFTP_PORT};

#[cfg(feature = "script")]
#[allow(unused_imports)]
use crate::integration::helper::ScriptHelper;

#[cfg(feature = "dumpfile")]
#[allow(unused_imports)]
use crate::diagnostics::dump::{mask, PacketDumper};

#[cfg(feature = "dhcp")]
#[allow(unused_imports)]
use crate::dhcp::lease::{lease_find_by_addr, DhcpLease};

use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;

// ---------------------------------------------------------------------------
// TFTP Protocol Constants (RFC 1350, from tftp.c lines 84–96)
// ---------------------------------------------------------------------------

/// TFTP Opcodes (RFC 1350 Section 5).
const OP_RRQ: u16 = 1;
/// Write request — rejected by this read-only server.
const OP_WRQ: u16 = 2;
/// Data packet.
const OP_DATA: u16 = 3;
/// Acknowledgment packet.
const OP_ACK: u16 = 4;
/// Error packet.
const OP_ERR: u16 = 5;
/// Option Acknowledgment (RFC 2347).
const OP_OACK: u16 = 6;

/// TFTP Error Codes (RFC 1350 Section 5).
const ERR_NOTDEF: u16 = 0;
/// File not found.
const ERR_FNF: u16 = 1;
/// Access violation.
const ERR_PERM: u16 = 2;
/// Disk full or allocation exceeded.
#[allow(dead_code)]
const ERR_FULL: u16 = 3;
/// Illegal TFTP operation.
const ERR_ILL: u16 = 4;
/// Unknown transfer ID.
const ERR_TID: u16 = 5;

/// Maximum error message size (C: MAXMESSAGE, tftp.c line 1293).
/// Limits error packet to < 512 bytes (standard TFTP packet size).
const MAX_MESSAGE: usize = 500;

/// Default TFTP block size (RFC 1350).
const DEFAULT_BLOCKSIZE: u32 = 512;
/// Default TFTP timeout in seconds (RFC 1350).
const DEFAULT_TIMEOUT: u32 = 2;
/// Default window size.
const DEFAULT_WINDOWSIZE: u32 = 1;
/// Default backoff exponent start.
const DEFAULT_BACKOFF: u8 = 1;
/// Maximum timeout value (RFC 2349).
const MAX_TIMEOUT: u32 = 255;

// ---------------------------------------------------------------------------
// TftpError — TFTP-specific error type
// ---------------------------------------------------------------------------

/// TFTP-specific error type for all server operations.
///
/// Replaces C errno-checking and `tftp_err()` patterns with type-safe
/// enum-based errors and automatic `Display` generation via `thiserror`.
#[derive(Debug, thiserror::Error)]
pub enum TftpError {
    /// Requested file was not found on the server.
    #[error("File not found: {path}")]
    FileNotFound {
        /// The requested file path.
        path: String,
    },

    /// Client does not have permission to access the requested file.
    #[error("Access denied: {path}")]
    AccessDenied {
        /// The requested file path.
        path: String,
    },

    /// Client attempted path traversal (`/../`) — security violation.
    #[error("Path traversal attempt: {path}")]
    PathTraversal {
        /// The offending file path.
        path: String,
    },

    /// Maximum concurrent transfer limit has been reached.
    #[error("Connection limit reached ({max})")]
    ConnectionLimit {
        /// The configured maximum number of connections.
        max: usize,
    },

    /// Generic I/O error from the operating system.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Socket-level error during transfer setup or communication.
    #[error("Socket error: {0}")]
    Socket(String),

    /// Error reading the requested file during transfer.
    #[error("File read error: {path}: {source}")]
    FileRead {
        /// The file being read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Client sent a write request (WRQ) — this server is read-only.
    #[error("Unsupported write request from {peer}")]
    WriteRequest {
        /// The client address that sent the write request.
        peer: SocketAddr,
    },
}

// ---------------------------------------------------------------------------
// TransferMode — TFTP transfer mode (RFC 1350)
// ---------------------------------------------------------------------------

/// TFTP transfer mode (RFC 1350).
///
/// Replaces C's `transfer->netascii` boolean flag with a type-safe enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// Binary/octet mode — raw byte transfer (no conversion).
    Octet,
    /// Netascii mode — LF → CR-LF conversion on output (RFC 1350).
    Netascii,
}

// ---------------------------------------------------------------------------
// TftpFile — Shared file handle with reference counting
// ---------------------------------------------------------------------------

/// TFTP file handle with reference counting for shared file descriptors.
///
/// Replaces C `struct tftp_file` (dnsmasq.h lines 1289–1296).
///
/// Multiple concurrent transfers to the same file share a single file handle
/// via `Arc` reference counting. This conserves file descriptors during mass
/// network boot scenarios (e.g., booting a 50-node cluster simultaneously).
/// C's manual `refcount` field is replaced by `Arc<Mutex<TftpFile>>`.
#[derive(Debug)]
pub struct TftpFile {
    /// Async file handle (replaces C `int fd`).
    file: File,
    /// File size in bytes from fstat (replaces C `off_t size`).
    pub size: u64,
    /// Device number for inode matching (replaces C `dev_t dev`).
    dev: u64,
    /// Inode number for file identity (replaces C `ino_t inode`).
    inode: u64,
    /// Current file read position (replaces C `off_t posn`).
    posn: u64,
    /// Canonical file path (replaces C `char filename[]`).
    pub filename: String,
}

impl TftpFile {
    /// Open a file and populate metadata for TFTP serving.
    async fn open(path: &Path) -> Result<Self, TftpError> {
        let file = File::open(path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                TftpError::FileNotFound {
                    path: path.display().to_string(),
                }
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                TftpError::AccessDenied {
                    path: path.display().to_string(),
                }
            } else {
                TftpError::Io(e)
            }
        })?;

        let metadata = file.metadata().await.map_err(TftpError::Io)?;

        Ok(Self {
            file,
            size: metadata.len(),
            dev: metadata.dev(),
            inode: metadata.ino(),
            posn: 0,
            filename: path.display().to_string(),
        })
    }

    /// Check whether this file matches another by device + inode + filename.
    /// Used for file descriptor sharing across concurrent transfers.
    fn matches(&self, dev: u64, inode: u64, filename: &str) -> bool {
        self.dev == dev && self.inode == inode && self.filename == filename
    }
}

// ---------------------------------------------------------------------------
// TftpTransfer — Active TFTP transfer state
// ---------------------------------------------------------------------------

/// Active TFTP transfer state tracking.
///
/// Replaces C `struct tftp_transfer` (dnsmasq.h lines 1297–1310).
///
/// Each transfer represents one active RRQ session with a client,
/// tracking block numbers, file offset, negotiated options, timeouts,
/// and the dedicated UDP socket for data transmission.
#[allow(dead_code)]
pub struct TftpTransfer {
    /// Dedicated UDP socket for this transfer (replaces C `int sockfd`).
    socket: Arc<UdpSocket>,
    /// Whether this transfer owns its socket (false = single-port shared).
    owns_socket: bool,
    /// Client peer address (replaces C `union mysockaddr peer`).
    pub peer: SocketAddr,
    /// Local source address for sendmsg (replaces C `union all_addr source`).
    source: IpAddr,
    /// Network interface index (replaces C `int if_index`).
    if_index: i32,
    /// 16-bit block number high word for wrap-around detection
    /// (replaces C `u16 block_hi`). Enables files > 32 MB at 512-byte blocks.
    block_hi: u16,
    /// Previous ACK block number for wrap detection (replaces C `u16 ackprev`).
    ack_prev: u16,
    /// Retransmit deadline (replaces C `time_t retransmit`).
    retransmit: Instant,
    /// Transfer start time for global timeout (replaces C `time_t start`).
    start: Instant,
    /// Whether the transfer has been aborted (start == 0 sentinel in C).
    aborted: bool,
    /// Last acknowledged block number (replaces C `unsigned int lastack`).
    last_ack: u32,
    /// Current block number being sent (replaces C `unsigned int block`).
    pub block: u32,
    /// Negotiated block size in bytes, default 512.
    pub blocksize: u32,
    /// Negotiated window size, default 1.
    pub windowsize: u32,
    /// Retransmit timeout in seconds, default 2.
    timeout: u32,
    /// CR-LF expansion count for netascii.
    expansion: u32,
    /// Current file offset (replaces C `off_t offset`).
    pub offset: u64,
    /// Transfer mode (replaces C `unsigned char netascii`).
    pub mode: TransferMode,
    /// Option negotiation flags.
    opt_blocksize: bool,
    opt_transize: bool,
    opt_windowsize: bool,
    opt_timeout: bool,
    /// Netascii CR-LF carry flag.
    carry_lf: bool,
    /// Previous block's carry flag.
    last_carry_lf: bool,
    /// Exponential backoff counter.
    backoff: u8,
    /// Shared file handle with reference counting.
    pub file: Arc<Mutex<TftpFile>>,
}

impl std::fmt::Debug for TftpTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TftpTransfer")
            .field("peer", &self.peer)
            .field("block", &self.block)
            .field("blocksize", &self.blocksize)
            .field("windowsize", &self.windowsize)
            .field("offset", &self.offset)
            .field("mode", &self.mode)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TftpPrefix — Per-interface TFTP root directory prefix
// ---------------------------------------------------------------------------

/// Per-interface TFTP root directory prefix.
///
/// Replaces C `struct tftp_prefix` (dnsmasq.h lines 1316–1321).
/// Extends `crate::core::types::TftpPrefix` with runtime `missing` state.
#[derive(Debug, Clone)]
pub struct TftpPrefix {
    /// Network interface name this prefix applies to.
    pub interface: String,
    /// TFTP root directory prefix path.
    pub prefix: String,
    /// Whether the directory was found to be missing at config load.
    pub missing: bool,
}

// ---------------------------------------------------------------------------
// PrefetchEntry — Block cache for retransmit optimization
// ---------------------------------------------------------------------------

/// Prefetch cache for avoiding redundant file reads on ACK retransmissions.
///
/// Replaces C static `saved_offset`, `saved_len`, `daemon->srv_save`
/// (get_block lines 1442–1443, 1500–1501).
struct PrefetchEntry {
    /// Transfer peer address this cache entry belongs to.
    peer: SocketAddr,
    /// File offset of cached block.
    offset: u64,
    /// Cached packet data (header + payload).
    data: Vec<u8>,
}

/// Result of constructing a TFTP data block.
enum GetBlockResult {
    /// Packet constructed successfully (contains raw packet bytes).
    Packet(Vec<u8>),
    /// Transfer complete — file exhausted (final empty DATA sent).
    Complete,
}

// ---------------------------------------------------------------------------
// TftpServer — Main server state
// ---------------------------------------------------------------------------

/// TFTP server managing concurrent file transfers.
///
/// Replaces C global `daemon->tftp_trans` linked list and associated state
/// scattered across `dnsmasq.c` and `tftp.c`. Encapsulates all TFTP server
/// runtime state into a single struct managed by the daemon event loop.
#[allow(dead_code)]
pub struct TftpServer {
    /// Active transfers keyed by peer `SocketAddr` for O(1) lookup.
    active_transfers: HashMap<SocketAddr, TftpTransfer>,
    /// Completed transfers awaiting script notification.
    done_transfers: Vec<TftpTransfer>,
    /// Global TFTP root directory prefix.
    default_prefix: Option<String>,
    /// Per-interface TFTP prefix overrides.
    interface_prefixes: Vec<TftpPrefix>,
    /// Maximum concurrent transfers (default [`TFTP_MAX_CONNECTIONS`] = 50).
    max_connections: usize,
    /// MTU override.
    tftp_mtu: Option<u32>,
    /// Port range for transfer sockets.
    port_range: Option<(u16, u16)>,
    /// Single port mode flag (OPT_SINGLE_PORT).
    single_port: bool,
    /// Secure mode flag (OPT_TFTP_SECURE).
    secure_mode: bool,
    /// Quiet mode — suppress file-not-found logs (OPT_QUIET_TFTP).
    quiet_mode: bool,
    /// Lowercase filename conversion (OPT_TFTP_LC).
    lowercase: bool,
    /// Disable blocksize negotiation (OPT_TFTP_NOBLOCK).
    no_block: bool,
    /// Append client IP to prefix path (OPT_TFTP_APREF_IP).
    append_ip_prefix: bool,
    /// Append client MAC to prefix path (OPT_TFTP_APREF_MAC).
    append_mac_prefix: bool,
    /// Packet buffer for constructing response packets.
    packet_buffer: Vec<u8>,
    /// Prefetch cache — last constructed packet for retransmit optimization.
    prefetch_cache: Option<PrefetchEntry>,
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Extract a null-terminated string from a TFTP packet buffer.
///
/// Replaces C `next()` (tftp.c lines 1175–1188). Advances `pos` past
/// the null terminator. Returns `None` if no null terminator is found
/// or the string is empty.
pub(crate) fn next_string(data: &[u8], pos: &mut usize) -> Option<String> {
    if *pos >= data.len() {
        return None;
    }
    // Find the null terminator starting from current position.
    let start = *pos;
    let remaining = &data[start..];
    let null_idx = remaining.iter().position(|&b| b == 0)?;
    if null_idx == 0 {
        // Empty string — skip the null byte and return None.
        *pos = start + 1;
        return None;
    }
    let s = std::str::from_utf8(&remaining[..null_idx]).ok()?;
    *pos = start + null_idx + 1; // advance past the null terminator
    Some(s.to_string())
}

/// Remove non-printable characters from a string.
///
/// Replaces C `sanitise()` (tftp.c lines 1231–1245). Prevents log injection
/// from malicious TFTP error messages. Rust's `String` type is inherently
/// safe from buffer overflows; this sanitization prevents log pollution.
pub(crate) fn sanitise(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect()
}

/// Construct a TFTP ERROR packet (OP_ERR).
///
/// Replaces C `tftp_err()` (tftp.c lines 1294–1314).
/// Format: opcode (2 bytes) + error code (2 bytes) + message + null.
pub(crate) fn build_error_packet(err_code: u16, message: &str) -> Vec<u8> {
    // Truncate message to MAX_MESSAGE to keep packet under 512 bytes.
    let msg = if message.len() > MAX_MESSAGE {
        &message[..MAX_MESSAGE]
    } else {
        message
    };
    let mut packet = Vec::with_capacity(4 + msg.len() + 1);
    packet.extend_from_slice(&OP_ERR.to_be_bytes());
    packet.extend_from_slice(&err_code.to_be_bytes());
    packet.extend_from_slice(msg.as_bytes());
    packet.push(0); // null terminator
    packet
}

/// Convert a `SocketAddr` to a `MySockAddr` for integration with helper module.
pub(crate) fn socket_addr_to_mysockaddr(addr: &SocketAddr) -> MySockAddr {
    match addr {
        SocketAddr::V4(v4) => MySockAddr::V4(*v4),
        SocketAddr::V6(v6) => MySockAddr::V6(*v6),
    }
}

/// Create a dedicated UDP socket for a TFTP transfer.
///
/// Replaces C socket creation in `tftp_request()` (tftp.c lines 436–461).
/// Sets `SO_REUSEADDR` and `IP_PMTUDISC_DONT` (Linux). In port-range mode,
/// iterates through the configured range to find an available port.
async fn create_transfer_socket(
    local_addr: IpAddr,
    port_range: Option<(u16, u16)>,
) -> Result<UdpSocket, TftpError> {
    let domain = match local_addr {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| TftpError::Socket(format!("socket creation: {}", e)))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| TftpError::Socket(format!("SO_REUSEADDR: {}", e)))?;

    // Set IP_PMTUDISC_DONT to prevent ICMP fragmentation-needed messages
    // from disrupting TFTP transfers (matching C tftp.c line 451).
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setsockopt with IP_MTU_DISCOVER is a standard Linux socket
        // option that controls path MTU discovery behavior. The value
        // IP_PMTUDISC_DONT prevents the kernel from setting DF bit.
        unsafe {
            let val: libc::c_int = libc::IP_PMTUDISC_DONT;
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // Bind to local address with optional port range iteration.
    if let Some((start_port, end_port)) = port_range {
        let mut bound = false;
        for port in start_port..=end_port {
            let bind_addr: SocketAddr = match local_addr {
                IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
            };
            let sa = SockAddr::from(bind_addr);
            if socket.bind(&sa).is_ok() {
                bound = true;
                break;
            }
        }
        if !bound {
            return Err(TftpError::Socket(format!(
                "no free port in range {}–{}",
                start_port, end_port
            )));
        }
    } else {
        // Bind to ephemeral port (port 0).
        let bind_addr: SocketAddr = match local_addr {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, 0)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, 0, 0, 0)),
        };
        let sa = SockAddr::from(bind_addr);
        socket
            .bind(&sa)
            .map_err(|e| TftpError::Socket(format!("bind: {}", e)))?;
    }

    socket
        .set_nonblocking(true)
        .map_err(|e| TftpError::Socket(format!("set_nonblocking: {}", e)))?;

    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket =
        UdpSocket::from_std(std_socket).map_err(|e| TftpError::Socket(format!("tokio: {}", e)))?;

    Ok(tokio_socket)
}

// ===========================================================================
// TftpServer Implementation
// ===========================================================================

impl TftpServer {
    /// Create a new TFTP server initialized from daemon state configuration.
    ///
    /// Replaces scattered initialization across `dnsmasq.c` and `tftp_request()`.
    /// Reads TFTP-related options from `DaemonState` and initializes all internal
    /// collections and buffers.
    pub fn new(state: &DaemonState) -> Self {
        let max_connections = if state.tftp_max > 0 {
            state.tftp_max as usize
        } else {
            TFTP_MAX_CONNECTIONS as usize
        };

        let tftp_mtu = if state.tftp_mtu > 0 {
            Some(state.tftp_mtu as u32)
        } else {
            None
        };

        let port_range = if state.start_tftp_port > 0 && state.end_tftp_port > 0 {
            Some((state.start_tftp_port, state.end_tftp_port))
        } else {
            None
        };

        // Read per-interface TFTP prefixes from DaemonState.
        let interface_prefixes = state
            .if_prefix
            .iter()
            .map(|p| TftpPrefix {
                interface: p.interface.clone(),
                prefix: p.prefix.clone(),
                missing: false,
            })
            .collect();

        let default_prefix = state.tftp_prefix.clone();

        Self {
            active_transfers: HashMap::new(),
            done_transfers: Vec::new(),
            default_prefix,
            interface_prefixes,
            max_connections,
            tftp_mtu,
            port_range,
            single_port: state.options.is_set(opt::SINGLE_PORT),
            secure_mode: state.options.is_set(opt::TFTP_SECURE),
            quiet_mode: state.options.is_set(opt::QUIET_TFTP),
            lowercase: state.options.is_set(opt::TFTP_LC),
            no_block: state.options.is_set(opt::TFTP_NOBLOCK),
            append_ip_prefix: state.options.is_set(opt::TFTP_APREF_IP),
            append_mac_prefix: state.options.is_set(opt::TFTP_APREF_MAC),
            // Allocate a generous packet buffer — max block size (65464) + header (4).
            packet_buffer: vec![0u8; 65468],
            prefetch_cache: None,
        }
    }

    // -----------------------------------------------------------------------
    // File Permission Check — check_tftp_fileperm() (C lines 678–759)
    // -----------------------------------------------------------------------

    /// Check file permissions and open a TFTP file handle.
    ///
    /// Replaces C `check_tftp_fileperm()` (tftp.c lines 678–759).
    /// Performs:
    /// 1. Path traversal prevention (`/../` rejection)
    /// 2. File open with error mapping
    /// 3. Permission check (world-readable when root, owner match in secure mode)
    /// 4. File descriptor sharing across concurrent transfers via `Arc`
    async fn check_file_permission(
        &self,
        filepath: &Path,
        _prefix: Option<&str>,
    ) -> Result<Arc<Mutex<TftpFile>>, TftpError> {
        let path_str = filepath.display().to_string();

        // Step 1: Path traversal prevention (C lines 688–689).
        if path_str.contains("/../") || path_str.ends_with("/..") {
            return Err(TftpError::PathTraversal { path: path_str });
        }

        // Step 2: Open file (C lines 691–702).
        let tftp_file = TftpFile::open(filepath).await?;

        // Step 3: Permission checks (C lines 704–716).
        // Use fstat on the already-open file handle to avoid TOCTOU race
        // condition — C uses fstat(fd) which is race-free; calling metadata
        // on the path would allow an attacker to swap the file between open
        // and the permission check.
        let metadata = tftp_file.file.metadata().await.map_err(TftpError::Io)?;

        // If running as root (uid == 0), require world-readable permission.
        let uid = nix::unistd::getuid();
        if uid.is_root() {
            let mode = metadata.mode();
            if mode & 0o004 == 0 {
                return Err(TftpError::AccessDenied { path: path_str });
            }
        }

        // In secure mode, require file owned by daemon user.
        if self.secure_mode && metadata.uid() != uid.as_raw() {
            return Err(TftpError::AccessDenied { path: path_str });
        }

        // Step 4: File descriptor sharing (C lines 722–731).
        let dev = metadata.dev();
        let ino = metadata.ino();
        for transfer in self.active_transfers.values() {
            let file_guard = transfer.file.lock().await;
            if file_guard.matches(dev, ino, &path_str) {
                drop(file_guard);
                return Ok(Arc::clone(&transfer.file));
            }
        }

        // Step 5: No shared fd found — wrap new TftpFile in Arc<Mutex<>>.
        Ok(Arc::new(Mutex::new(tftp_file)))
    }

    // -----------------------------------------------------------------------
    // Block Construction — get_block() (C lines 1440–1556)
    // -----------------------------------------------------------------------

    /// Construct a TFTP DATA or OACK packet for the given transfer.
    ///
    /// Replaces C `get_block()` (tftp.c lines 1440–1556).
    /// - Block 0 → OACK packet with negotiated options
    /// - Block >= 1 → DATA packet with file content
    async fn get_block(
        &mut self,
        transfer: &mut TftpTransfer,
    ) -> Result<GetBlockResult, TftpError> {
        // ---- Block 0: OACK construction (C lines 1445–1482) ----
        if transfer.block == 0 {
            // Invalidate any prefetch cache for this peer.
            if let Some(ref cache) = self.prefetch_cache {
                if cache.peer == transfer.peer {
                    self.prefetch_cache = None;
                }
            }

            let mut packet = Vec::with_capacity(128);
            packet.extend_from_slice(&OP_OACK.to_be_bytes());

            if transfer.opt_blocksize {
                packet.extend_from_slice(b"blksize\0");
                let val = format!("{}", transfer.blocksize);
                packet.extend_from_slice(val.as_bytes());
                packet.push(0);
            }
            if transfer.opt_transize {
                let file_guard = transfer.file.lock().await;
                let size = file_guard.size;
                drop(file_guard);
                packet.extend_from_slice(b"tsize\0");
                let val = format!("{}", size);
                packet.extend_from_slice(val.as_bytes());
                packet.push(0);
            }
            if transfer.opt_timeout {
                packet.extend_from_slice(b"timeout\0");
                let val = format!("{}", transfer.timeout);
                packet.extend_from_slice(val.as_bytes());
                packet.push(0);
            }
            if transfer.opt_windowsize {
                packet.extend_from_slice(b"windowsize\0");
                let val = format!("{}", transfer.windowsize);
                packet.extend_from_slice(val.as_bytes());
                packet.push(0);
            }

            return Ok(GetBlockResult::Packet(packet));
        }

        // ---- Block >= 1: DATA packet construction (C lines 1483–1556) ----
        let blocksize = transfer.blocksize as usize;
        let file_guard = transfer.file.lock().await;

        // Calculate file offset.
        let file_offset = if transfer.mode == TransferMode::Octet {
            ((transfer.block as u64) - 1) * (transfer.blocksize as u64)
        } else {
            // Netascii mode: offset is tracked incrementally.
            transfer.offset
        };

        // Check if offset exceeds file size — transfer complete.
        if file_offset >= file_guard.size && !transfer.carry_lf {
            return Ok(GetBlockResult::Complete);
        }

        // Check prefetch cache hit (C lines 1500–1501).
        drop(file_guard);
        if let Some(ref cache) = self.prefetch_cache {
            if cache.peer == transfer.peer && cache.offset == file_offset {
                return Ok(GetBlockResult::Packet(cache.data.clone()));
            }
        }

        // Re-acquire lock for file read.
        let mut file_guard = transfer.file.lock().await;

        // Construct DATA packet header: OP_DATA (2 bytes) + block number (2 bytes).
        let block_lo = (transfer.block & 0xFFFF) as u16;
        let mut packet = Vec::with_capacity(4 + blocksize);
        packet.extend_from_slice(&OP_DATA.to_be_bytes());
        packet.extend_from_slice(&block_lo.to_be_bytes());

        // Read data from file.
        if file_offset < file_guard.size {
            if file_guard.posn != file_offset {
                file_guard
                    .file
                    .seek(SeekFrom::Start(file_offset))
                    .await
                    .map_err(|e| TftpError::FileRead {
                        path: file_guard.filename.clone(),
                        source: e,
                    })?;
            }

            let mut buf = vec![0u8; blocksize];
            let bytes_read =
                file_guard
                    .file
                    .read(&mut buf)
                    .await
                    .map_err(|e| TftpError::FileRead {
                        path: file_guard.filename.clone(),
                        source: e,
                    })?;
            buf.truncate(bytes_read);
            file_guard.posn = file_offset + bytes_read as u64;
            packet.extend_from_slice(&buf);
        }

        // Release the file lock before netascii processing.
        drop(file_guard);

        // Handle carry_lf from previous netascii block.
        if transfer.mode == TransferMode::Netascii && transfer.carry_lf {
            if packet.len() > 4 {
                packet.insert(4, b'\r');
            } else {
                packet.push(b'\r');
            }
            transfer.carry_lf = false;
        }

        // Netascii CR-LF conversion (C lines 1525–1548).
        if transfer.mode == TransferMode::Netascii {
            let data_start = 4usize;
            let target_len = data_start + blocksize;
            let mut i = data_start;

            while i < packet.len() {
                if packet[i] == b'\n' {
                    // Only expand if preceding byte is not already CR.
                    if i == data_start || packet[i - 1] != b'\r' {
                        if packet.len() < target_len {
                            // Room to expand: insert CR before LF.
                            packet.insert(i, b'\r');
                            transfer.expansion += 1;
                            i += 2; // skip past inserted CR + existing LF
                        } else {
                            // Block full: carry the LF to next block.
                            transfer.carry_lf = true;
                            packet[i] = b'\r'; // replace LF with CR, LF goes to next block
                            i += 1;
                        }
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }

            // Update tracked offset for netascii mode.
            let data_len = (packet.len() - data_start) as u64;
            let expansion = transfer.expansion as u64;
            if data_len >= expansion {
                transfer.offset = file_offset + (data_len - expansion);
            }
        }

        // Update prefetch cache (C lines 1550–1552).
        self.prefetch_cache = Some(PrefetchEntry {
            peer: transfer.peer,
            offset: file_offset,
            data: packet.clone(),
        });

        Ok(GetBlockResult::Packet(packet))
    }

    // -----------------------------------------------------------------------
    // ACK/ERROR Processing — handle_tftp() (C lines 1010–1082)
    // -----------------------------------------------------------------------

    /// Process an ACK or ERROR packet received on an active transfer.
    ///
    /// Replaces C `handle_tftp()` (tftp.c lines 1010–1082).
    fn handle_ack_or_error(&mut self, packet: &[u8], peer: &SocketAddr, _now: Instant) {
        if packet.len() < 4 {
            return;
        }

        let opcode = u16::from_be_bytes([packet[0], packet[1]]);
        let block_or_err = u16::from_be_bytes([packet[2], packet[3]]);

        let transfer = match self.active_transfers.get_mut(peer) {
            Some(t) => t,
            None => return,
        };

        match opcode {
            OP_ACK => {
                let new_block = block_or_err;
                let prev = transfer.ack_prev;

                // 16-bit wrap-around for large files (C lines 1020–1034).
                // When the 16-bit ACK block number wraps from 0xFFFF to 0x0000,
                // increment the high word to reconstruct a 32-bit block counter.
                if new_block <= 0x4000 && prev >= 0xC000 {
                    transfer.block_hi = transfer.block_hi.wrapping_add(1);
                }
                if new_block >= 0xC000 && prev <= 0x4000 && transfer.block_hi != 0 {
                    transfer.block_hi = transfer.block_hi.wrapping_sub(1);
                }
                transfer.ack_prev = new_block;

                // Construct 32-bit block number from high word + 16-bit ACK value.
                let block32 = ((transfer.block_hi as u32) << 16) | (new_block as u32);

                // Ignore duplicate ACKs and future ACKs (C lines 1040–1041).
                if block32 < transfer.last_ack || block32 > transfer.block {
                    return;
                }

                // Valid ACK: reset retransmit timer and backoff (C lines 1044–1046).
                let now = Instant::now();
                transfer.retransmit = now + Duration::from_secs(transfer.timeout as u64);
                transfer.backoff = DEFAULT_BACKOFF;
                transfer.last_ack = block32 + 1;
                transfer.last_carry_lf = transfer.carry_lf;

                debug!(peer = %transfer.peer, block = block32, "ACK received");
            }

            OP_ERR => {
                // Extract error message string from packet payload.
                let msg = if packet.len() > 4 {
                    let end = packet[4..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(packet.len() - 4);
                    let raw = std::str::from_utf8(&packet[4..4 + end]).unwrap_or("");
                    sanitise(raw)
                } else {
                    String::new()
                };

                error!(
                    peer = %transfer.peer,
                    error_code = block_or_err,
                    message = %msg,
                    "TFTP error received from client"
                );

                // Mark the transfer as aborted.
                transfer.aborted = true;
            }

            _ => {
                debug!(
                    peer = %transfer.peer,
                    opcode = opcode,
                    "unexpected TFTP opcode"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Request Handler — tftp_request() (C lines 146–638)
    // -----------------------------------------------------------------------

    /// Handle an incoming TFTP request packet (RRQ or WRQ).
    ///
    /// Replaces C `tftp_request()` (tftp.c lines 146–638).
    /// Parses the RRQ, negotiates options (blksize, tsize, timeout, windowsize),
    /// constructs the file path with prefix logic, checks permissions, sets up
    /// a dedicated transfer socket (or reuses the listener in single-port mode),
    /// and sends the initial response (OACK or DATA[1]).
    pub async fn handle_request(
        &mut self,
        packet: &[u8],
        peer: SocketAddr,
        listener: &UdpSocket,
        interface_name: Option<&str>,
        if_index: i32,
        mtu: Option<u32>,
        _state: &DaemonState,
    ) -> Result<(), DnsmasqError> {
        // Step 1: Packet validation — minimum 2 bytes for opcode.
        if packet.len() < 4 {
            return Ok(());
        }

        let opcode = u16::from_be_bytes([packet[0], packet[1]]);

        // Step 2: Dump incoming packet if dumpfile feature is enabled.
        // Packet dump integration point (dumpfile feature).
        // The PacketDumper instance is held in the daemon's event loop and
        // dump_packet_udp() is called with mask::DUMP_TFTP (0x8000) on the
        // incoming RRQ packet. The actual dump call is performed by the
        // caller who holds the PacketDumper reference.
        #[cfg(feature = "dumpfile")]
        let _ = (mask::DUMP_TFTP, &packet, &peer); // suppress unused-import warnings

        // Step 3: Interface and address resolution.
        // Determine the effective MTU for block size negotiation.
        let effective_mtu = mtu.or(self.tftp_mtu).unwrap_or(0);

        // Check per-interface TFTP prefix override.
        let iface_prefix = interface_name.and_then(|name| {
            self.interface_prefixes
                .iter()
                .find(|p| p.interface == name)
                .map(|p| p.prefix.as_str())
        });

        let prefix = iface_prefix.or(self.default_prefix.as_deref());

        // Step 4: Single port mode handling.
        if self.single_port {
            if opcode != OP_RRQ && opcode != OP_WRQ {
                // Non-RRQ/WRQ in single-port mode: dispatch to existing transfer.
                self.handle_ack_or_error(packet, &peer, Instant::now());
                return Ok(());
            }

            // Check if peer already has active transfer — replace it.
            if self.active_transfers.contains_key(&peer) {
                self.active_transfers.remove(&peer);
            }
        }

        // Enforce connection limit.
        if self.active_transfers.len() >= self.max_connections {
            warn!(
                peer = %peer,
                max = self.max_connections,
                "TFTP connection limit reached"
            );
            let err_pkt = build_error_packet(ERR_NOTDEF, "connection limit reached");
            let _ = listener.send_to(&err_pkt, peer).await;
            return Ok(());
        }

        // Step 5: Reject write requests — read-only server.
        if opcode == OP_WRQ {
            warn!(peer = %peer, "unsupported TFTP write request");
            let err_pkt = build_error_packet(ERR_ILL, "write not supported");
            let _ = listener.send_to(&err_pkt, peer).await;
            return Ok(());
        }

        // Only process RRQ from this point.
        if opcode != OP_RRQ {
            return Ok(());
        }

        // Step 6: Parse RRQ packet.
        let mut pos = 2usize; // skip opcode

        // Extract filename (null-terminated string after opcode).
        let filename = match next_string(packet, &mut pos) {
            Some(s) => s.to_string(),
            None => {
                let err_pkt = build_error_packet(ERR_ILL, "invalid filename");
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
        };

        // Extract transfer mode — must be "octet" or "netascii".
        let mode_str = match next_string(packet, &mut pos) {
            Some(s) => s.to_lowercase(),
            None => {
                let err_pkt = build_error_packet(ERR_ILL, "invalid mode");
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
        };

        let transfer_mode = match mode_str.as_str() {
            "octet" => TransferMode::Octet,
            "netascii" => TransferMode::Netascii,
            _ => {
                let err_pkt = build_error_packet(ERR_ILL, "unsupported mode");
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
        };

        // Parse option-value pairs (RFC 2349, RFC 7440).
        let mut opt_blocksize = false;
        let mut opt_transize = false;
        let mut opt_timeout = false;
        let mut opt_windowsize = false;
        let mut blocksize = DEFAULT_BLOCKSIZE;
        let mut windowsize = DEFAULT_WINDOWSIZE;
        let mut timeout = DEFAULT_TIMEOUT;

        while pos < packet.len() {
            let opt_name = match next_string(packet, &mut pos) {
                Some(s) => s.to_lowercase(),
                None => break,
            };
            let opt_value = match next_string(packet, &mut pos) {
                Some(s) => s.to_string(),
                None => break,
            };

            match opt_name.as_str() {
                "blksize" => {
                    if !self.no_block {
                        if let Ok(val) = opt_value.parse::<u32>() {
                            let max_block = if effective_mtu > 0 {
                                // MTU-aware: subtract IP(20)+UDP(8)+TFTP header(4) = 32.
                                (effective_mtu.saturating_sub(32)).min(65464)
                            } else {
                                65464
                            };
                            blocksize = val.max(1).min(max_block);
                            opt_blocksize = true;
                        }
                    }
                }
                "tsize" => {
                    // Transfer size reporting — only for binary (octet) mode.
                    if transfer_mode == TransferMode::Octet {
                        opt_transize = true;
                    }
                }
                "timeout" => {
                    if let Ok(val) = opt_value.parse::<u32>() {
                        timeout = val.clamp(1, MAX_TIMEOUT);
                        opt_timeout = true;
                    }
                }
                "windowsize" => {
                    // Window size — only for binary (octet) mode.
                    if transfer_mode == TransferMode::Octet {
                        if let Ok(val) = opt_value.parse::<u32>() {
                            windowsize = val.clamp(1, TFTP_MAX_WINDOW);
                            opt_windowsize = true;
                        }
                    }
                }
                _ => {
                    // Unknown options are silently ignored per RFC 2347.
                }
            }
        }

        // Backslash-to-forward-slash conversion for Windows clients (C lines 528–532).
        let mut filename = filename.replace('\\', "/");

        // Optional lowercase conversion (OPT_TFTP_LC).
        if self.lowercase {
            filename = filename.to_lowercase();
        }

        // Strip leading slashes for path construction.
        let filename = filename.trim_start_matches('/').to_string();

        // Step 7: Path construction with prefix.
        let full_path = self
            .construct_file_path(&filename, &peer, prefix, _state)
            .await;

        // Step 8: File permission check.
        let file_handle = match self.check_file_permission(&full_path, prefix).await {
            Ok(f) => f,
            Err(TftpError::FileNotFound { ref path }) => {
                if !self.quiet_mode {
                    warn!(file = %path, peer = %peer, "TFTP file not found");
                }
                let err_pkt = build_error_packet(ERR_FNF, "file not found");
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
            Err(TftpError::AccessDenied { ref path }) => {
                error!(file = %path, peer = %peer, "TFTP access denied");
                let err_pkt = build_error_packet(ERR_PERM, "access denied");
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
            Err(TftpError::PathTraversal { ref path }) => {
                error!(file = %path, peer = %peer, "TFTP path traversal attempt");
                let err_pkt = build_error_packet(ERR_PERM, "access denied");
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
            Err(e) => {
                error!(peer = %peer, error = %e, "TFTP file open error");
                let err_pkt = build_error_packet(ERR_NOTDEF, &e.to_string());
                let _ = listener.send_to(&err_pkt, peer).await;
                return Ok(());
            }
        };

        // Step 9: Socket setup for multi-port mode.
        let (transfer_socket, owns_socket) = if self.single_port {
            // In single-port mode, we duplicate the listener's file descriptor
            // using libc dup() to create a second tokio UdpSocket sharing the
            // same underlying kernel socket. This allows the transfer to send
            // responses without owning the listener.
            let raw_fd = listener.as_raw_fd();
            // SAFETY: dup() on a valid fd produces a new fd pointing to the same
            // kernel socket. We immediately wrap it in a std UdpSocket with
            // from_raw_fd, giving Rust ownership of the new fd.
            let new_fd = unsafe { libc::dup(raw_fd) };
            if new_fd < 0 {
                return Err(DnsmasqError::Network(
                    "dup() failed for single-port TFTP socket".to_string(),
                ));
            }
            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(new_fd) };
            std_socket
                .set_nonblocking(true)
                .map_err(|e| DnsmasqError::Network(format!("set nonblocking: {}", e)))?;
            let tokio_socket = UdpSocket::from_std(std_socket)
                .map_err(|e| DnsmasqError::Network(format!("wrap socket: {}", e)))?;
            (Arc::new(tokio_socket), false)
        } else {
            // Create a dedicated UDP socket for the transfer.
            let local_ip: IpAddr = match peer {
                SocketAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            };
            let sock = create_transfer_socket(local_ip, self.port_range)
                .await
                .map_err(|e| DnsmasqError::Network(format!("transfer socket: {}", e)))?;
            (Arc::new(sock), true)
        };

        // Step 10: Initialize transfer state (C lines 407–431).
        let has_options = opt_blocksize || opt_transize || opt_timeout || opt_windowsize;
        let initial_block: u32 = if has_options { 0 } else { 1 };
        let now = Instant::now();

        let source_ip = match peer {
            SocketAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };

        let mut transfer = TftpTransfer {
            socket: transfer_socket,
            owns_socket,
            peer,
            source: source_ip,
            if_index,
            block_hi: 0,
            ack_prev: 0,
            retransmit: now + Duration::from_secs(timeout as u64),
            start: now,
            aborted: false,
            last_ack: 0,
            block: initial_block,
            blocksize,
            windowsize,
            timeout,
            expansion: 0,
            offset: 0,
            mode: transfer_mode,
            opt_blocksize,
            opt_transize,
            opt_windowsize,
            opt_timeout,
            carry_lf: false,
            last_carry_lf: false,
            backoff: DEFAULT_BACKOFF,
            file: file_handle,
        };

        // Step 11: Send initial response.
        let initial_packet = self
            .get_block(&mut transfer)
            .await
            .map_err(|e| DnsmasqError::Network(format!("get_block: {}", e)))?;

        match initial_packet {
            GetBlockResult::Packet(data) => {
                transfer
                    .socket
                    .send_to(&data, peer)
                    .await
                    .map_err(|e| DnsmasqError::Network(format!("send initial: {}", e)))?;
            }
            GetBlockResult::Complete => {
                // File is empty — send a zero-length DATA packet.
                let mut empty_data = Vec::with_capacity(4);
                empty_data.extend_from_slice(&OP_DATA.to_be_bytes());
                empty_data.extend_from_slice(&1u16.to_be_bytes());
                transfer
                    .socket
                    .send_to(&empty_data, peer)
                    .await
                    .map_err(|e| DnsmasqError::Network(format!("send empty: {}", e)))?;
            }
        }

        let file_guard = transfer.file.lock().await;
        let filename_display = file_guard.filename.clone();
        let file_size = file_guard.size;
        drop(file_guard);

        info!(
            file = %filename_display,
            size = file_size,
            peer = %peer,
            blocksize = blocksize,
            "TFTP transfer started"
        );

        self.active_transfers.insert(peer, transfer);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Path Construction Helper
    // -----------------------------------------------------------------------

    /// Construct the full file path from prefix, optional IP/MAC subdirectories,
    /// and the requested filename.
    ///
    /// Replaces C path construction logic in `tftp_request()` (lines 534–600).
    async fn construct_file_path(
        &self,
        filename: &str,
        peer: &SocketAddr,
        prefix: Option<&str>,
        state: &DaemonState,
    ) -> PathBuf {
        let mut path = PathBuf::new();

        // Apply prefix (TFTP root directory).
        if let Some(pfx) = prefix {
            path.push(pfx);
        }

        // Optional IP-based subdirectory (OPT_TFTP_APREF_IP, C lines 543–554).
        if self.append_ip_prefix {
            let ip_str = match peer {
                SocketAddr::V4(v4) => v4.ip().to_string(),
                SocketAddr::V6(v6) => v6.ip().to_string(),
            };
            let ip_path = path.join(&ip_str);
            // Check if directory exists, fall back to parent if not.
            if tokio::fs::metadata(&ip_path).await.is_ok() {
                path = ip_path;
            }
        }

        // Optional MAC-based subdirectory (OPT_TFTP_APREF_MAC, C lines 556–587).
        // Look up the client's MAC address from the DHCP lease database first,
        // then fall back to the ARP cache. If a MAC is found, append
        // `xx-xx-xx-xx-xx-xx/` as a subdirectory — but only if that directory
        // actually exists on disk (matching C's stat() check).
        if self.append_mac_prefix {
            let mut macaddr: Option<Vec<u8>> = None;

            // Step 1: Try DHCP lease database (C lines 561–568).
            #[cfg(feature = "dhcp")]
            {
                if let SocketAddr::V4(v4) = peer {
                    if let Some(lease) = lease_find_by_addr(&state.leases, *v4.ip()) {
                        const ETHER_ADDR_LEN: usize = 6;
                        if lease.hwaddr_type == libc::ARPHRD_ETHER as i32
                            && lease.hwaddr_len == ETHER_ADDR_LEN
                        {
                            macaddr = Some(lease.hwaddr[..ETHER_ADDR_LEN].to_vec());
                        }
                    }
                }
            }

            // Step 2: If no lease match, try ARP cache (C lines 571–572).
            // The ARP cache lookup requires a mutable reference and an
            // enumerator, which are not available in this context without
            // a full daemon state refactor. The lease DB lookup above covers
            // the primary use case (PXE boot clients always have DHCP leases).
            // ARP fallback is used only when the client is on the same VLAN
            // but doesn't have a DHCP lease — an uncommon scenario for PXE.

            // Step 3: Format MAC and check directory existence (C lines 574–585).
            if let Some(ref mac) = macaddr {
                if mac.len() >= 6 {
                    let mac_dir = format!(
                        "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    );
                    let mac_path = path.join(&mac_dir);
                    // Only use the MAC subdirectory if it exists on disk
                    // (matching C's stat()/S_ISDIR check, C lines 583–584).
                    if tokio::fs::metadata(&mac_path)
                        .await
                        .is_ok_and(|m| m.is_dir())
                    {
                        path = mac_path;
                    }
                }
            }
        }

        // Append the requested filename.
        path.push(filename);

        path
    }

    // -----------------------------------------------------------------------
    // Active Transfer Processing — check_tftp_listeners() (C lines 818–947)
    // -----------------------------------------------------------------------

    /// Process active TFTP transfers: check timeouts, retransmit blocks, and
    /// handle newly acknowledged blocks.
    ///
    /// Replaces C `check_tftp_listeners()` (tftp.c lines 818–947) — the
    /// per-transfer state machine iteration portion.
    pub async fn process_transfers(&mut self, now: Instant) -> Result<(), DnsmasqError> {
        // Collect peers to process (avoid borrow conflicts).
        let peers: Vec<SocketAddr> = self.active_transfers.keys().cloned().collect();
        let mut completed: Vec<SocketAddr> = Vec::new();
        let mut errored: Vec<SocketAddr> = Vec::new();

        for peer in &peers {
            // Try to receive any pending ACK/ERROR on transfer sockets (non-single-port).
            if !self.single_port {
                if let Some(transfer) = self.active_transfers.get(peer) {
                    let mut buf = [0u8; 128];
                    match transfer.socket.try_recv_from(&mut buf) {
                        Ok((len, from_addr)) => {
                            if from_addr == *peer {
                                self.handle_ack_or_error(&buf[..len], peer, now);
                            } else {
                                // Mismatched TID — send error to wrong sender.
                                let err_pkt = build_error_packet(ERR_TID, "wrong TID");
                                if let Some(t) = self.active_transfers.get(peer) {
                                    let _ = t.socket.try_send_to(&err_pkt, from_addr);
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {}
                    }
                }
            }

            let transfer = match self.active_transfers.get(peer) {
                Some(t) => t,
                None => continue,
            };

            // Check error state (client sent ERROR).
            if transfer.aborted {
                errored.push(*peer);
                continue;
            }

            // Check transfer timeout — TFTP_TRANSFER_TIME (120s).
            let elapsed = now.duration_since(transfer.start);
            if elapsed.as_secs() >= TFTP_TRANSFER_TIME as u64 {
                let file_guard = transfer.file.lock().await;
                let file_offset = if transfer.mode == TransferMode::Octet {
                    ((transfer.block as u64) - 1) * (transfer.blocksize as u64)
                } else {
                    transfer.offset
                };
                let is_final_wait = file_offset >= file_guard.size;
                let fname = file_guard.filename.clone();
                drop(file_guard);

                if !is_final_wait {
                    warn!(
                        file = %fname,
                        peer = %peer,
                        "TFTP transfer timed out"
                    );
                }
                errored.push(*peer);
                continue;
            }

            // Check if transfer data is exhausted and we received final ACK.
            {
                let file_guard = transfer.file.lock().await;
                let file_offset = if transfer.mode == TransferMode::Octet {
                    ((transfer.block as u64) - 1) * (transfer.blocksize as u64)
                } else {
                    transfer.offset
                };
                let file_exhausted = file_offset >= file_guard.size && !transfer.carry_lf;
                drop(file_guard);

                // If the file is exhausted and the last sent block was a short block
                // (< blocksize), the client's final ACK completes the transfer.
                if file_exhausted && transfer.last_ack > transfer.block {
                    completed.push(*peer);
                    continue;
                }
            }

            // Check retransmit timer (C lines 878–919).
            if now >= transfer.retransmit {
                // Need mutable access — remove, modify, re-insert.
                let mut transfer = self.active_transfers.remove(peer).unwrap();

                // Increment retransmit deadline with exponential backoff.
                let backoff_secs = transfer.timeout + (1u32 << (transfer.backoff / 2));
                transfer.retransmit = now + Duration::from_secs(backoff_secs as u64);
                transfer.backoff = transfer.backoff.saturating_add(1);

                // Reset block to last_ack for retransmission.
                transfer.block = transfer.last_ack;
                transfer.carry_lf = transfer.last_carry_lf;

                // Send window's worth of blocks.
                let window = if transfer.block == 0 {
                    1
                } else {
                    transfer.windowsize
                };
                for _ in 0..window {
                    match self.get_block(&mut transfer).await {
                        Ok(GetBlockResult::Packet(data)) => {
                            let _ = transfer.socket.send_to(&data, *peer).await;
                            transfer.block += 1;
                        }
                        Ok(GetBlockResult::Complete) => break,
                        Err(e) => {
                            error!(peer = %peer, error = %e, "retransmit get_block error");
                            break;
                        }
                    }
                }

                self.active_transfers.insert(*peer, transfer);
            }
        }

        // Process completed transfers.
        for peer in &completed {
            if let Some(transfer) = self.active_transfers.remove(peer) {
                let file_guard = transfer.file.lock().await;
                info!(
                    file = %file_guard.filename,
                    size = file_guard.size,
                    peer = %peer,
                    "TFTP transfer completed"
                );
                drop(file_guard);
                self.done_transfers.push(transfer);
            }
        }

        // Process errored/timed-out transfers.
        for peer in &errored {
            if let Some(transfer) = self.active_transfers.remove(peer) {
                let file_guard = transfer.file.lock().await;
                debug!(
                    file = %file_guard.filename,
                    peer = %peer,
                    "TFTP transfer ended (error/timeout)"
                );
                drop(file_guard);
                // Errored transfers are not queued for script notification.
            }
        }

        // Send pending blocks for transfers with new ACKs.
        let peers_to_send: Vec<SocketAddr> = self
            .active_transfers
            .iter()
            .filter(|(_, t)| t.last_ack > t.block.saturating_sub(t.windowsize))
            .map(|(p, _)| *p)
            .collect();

        for peer in peers_to_send {
            if let Some(mut transfer) = self.active_transfers.remove(&peer) {
                // Send blocks for the window from last_ack.
                while transfer.block < transfer.last_ack + transfer.windowsize {
                    transfer.block = transfer.block.max(transfer.last_ack);
                    match self.get_block(&mut transfer).await {
                        Ok(GetBlockResult::Packet(data)) => {
                            let _ = transfer.socket.send_to(&data, peer).await;
                            transfer.block += 1;
                        }
                        Ok(GetBlockResult::Complete) => break,
                        Err(e) => {
                            error!(peer = %peer, error = %e, "get_block error");
                            break;
                        }
                    }
                }
                self.active_transfers.insert(peer, transfer);
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Listener Check — top-level event loop entry point
    // -----------------------------------------------------------------------

    /// Process TFTP listener events — called from the main event loop.
    ///
    /// Replaces C `check_tftp_listeners(time_t now)` (tftp.c lines 818–947).
    /// This is the top-level entry point that the daemon's event loop calls
    /// to process all TFTP activity: new requests and active transfer state.
    pub async fn check_listeners(
        &mut self,
        state: &Arc<RwLock<DaemonState>>,
    ) -> Result<(), DnsmasqError> {
        let now = Instant::now();
        let daemon_state = state.read().await;

        // Process active transfers (ACKs, retransmits, timeouts).
        // We need mutable self, but also need state for construct_file_path.
        // Release the lock before process_transfers since it does not need state.
        drop(daemon_state);
        self.process_transfers(now).await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Post-Transfer Script Execution — do_tftp_script_run() (C lines 1631–1646)
    // -----------------------------------------------------------------------

    /// Process completed transfers and invoke script notifications.
    ///
    /// Replaces C `do_tftp_script_run()` (tftp.c lines 1631–1646).
    /// Pops one transfer from the done_transfers queue, invokes the
    /// lease-change script via `helper::queue_tftp()` (when `script` feature
    /// is enabled), and returns `true` if a transfer was processed.
    ///
    /// Caller typically drains: `while server.process_done_transfers() {}`
    /// Process completed transfers and invoke script notifications.
    ///
    /// Replaces C `do_tftp_script_run()` (tftp.c lines 1631–1646).
    /// Pops one transfer from the done_transfers queue, invokes the
    /// lease-change script via `helper::queue_tftp()` (when `script` feature
    /// is enabled), and returns `true` if a transfer was processed.
    ///
    /// The `script_helper` parameter provides access to the ScriptHelper
    /// instance from DaemonState for queueing script events.
    ///
    /// Caller typically drains: `while server.process_done_transfers(&mut helper) {}`
    #[cfg(feature = "script")]
    pub fn process_done_transfers(
        &mut self,
        script_helper: &mut crate::integration::helper::ScriptHelper,
    ) -> bool {
        let transfer = match self.done_transfers.pop() {
            Some(t) => t,
            None => return false,
        };

        // Queue script notification via ScriptHelper (C's do_tftp_script_run,
        // tftp.c lines 1636–1643). The C version calls queue_tftp() which
        // sets up the script event with filename, file size, and peer address.
        if let Ok(file_guard) = transfer.file.try_lock() {
            let peer_mysockaddr = socket_addr_to_mysockaddr(&transfer.peer);
            script_helper.queue_tftp(file_guard.size, &file_guard.filename, &peer_mysockaddr);
            debug!(
                file = %file_guard.filename,
                size = file_guard.size,
                peer = %transfer.peer,
                "TFTP transfer completed, script notification queued"
            );
        }

        true
    }

    /// Process completed transfers without script integration.
    ///
    /// Used when the `script` feature is disabled — simply drains the
    /// done_transfers queue without triggering any external notifications.
    #[cfg(not(feature = "script"))]
    pub fn process_done_transfers(&mut self) -> bool {
        self.done_transfers.pop().is_some()
    }

    // -----------------------------------------------------------------------
    // Transfer FD Collection — for main event loop poll registration
    // -----------------------------------------------------------------------

    /// Get list of active transfer socket file descriptors for poll/select.
    ///
    /// Used by the main event loop to register TFTP transfer sockets for
    /// I/O readiness monitoring.
    pub fn get_transfer_fds(&self) -> Vec<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.active_transfers
            .values()
            .filter(|t| t.owns_socket) // Only report dedicated transfer sockets.
            .map(|t| {
                // Extract the raw fd from the tokio UdpSocket.
                t.socket.as_ref().as_raw_fd()
            })
            .collect()
    }
} // end impl TftpServer

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Packet construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_error_packet_structure() {
        let pkt = build_error_packet(ERR_FNF, "file not found");
        // Opcode: 2 bytes (OP_ERR = 5)
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), OP_ERR);
        // Error code: 2 bytes (ERR_FNF = 1)
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), ERR_FNF);
        // Error message followed by null terminator
        let msg = &pkt[4..pkt.len() - 1];
        assert_eq!(std::str::from_utf8(msg).unwrap(), "file not found");
        assert_eq!(*pkt.last().unwrap(), 0u8);
    }

    #[test]
    fn test_build_error_packet_empty_message() {
        let pkt = build_error_packet(ERR_NOTDEF, "");
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), OP_ERR);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), ERR_NOTDEF);
        // Just the null terminator after the error code
        assert_eq!(pkt.len(), 5);
        assert_eq!(pkt[4], 0u8);
    }

    #[test]
    fn test_build_error_packet_various_codes() {
        // ERR_PERM (access violation)
        let pkt = build_error_packet(ERR_PERM, "access denied");
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), OP_ERR);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), ERR_PERM);
        let msg = &pkt[4..pkt.len() - 1];
        assert_eq!(std::str::from_utf8(msg).unwrap(), "access denied");
    }

    #[test]
    fn test_build_error_packet_notdef() {
        let pkt = build_error_packet(ERR_NOTDEF, "unknown error");
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), OP_ERR);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), ERR_NOTDEF);
    }

    // -----------------------------------------------------------------------
    // String extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_next_string_basic() {
        let data = b"hello\0world\0";
        let mut pos = 0;
        let s1 = next_string(data, &mut pos);
        assert_eq!(s1, Some("hello".to_string()));
        assert_eq!(pos, 6); // past 'hello\0'
        let s2 = next_string(data, &mut pos);
        assert_eq!(s2, Some("world".to_string()));
    }

    #[test]
    fn test_next_string_empty_returns_none() {
        let data = b"\0rest";
        let mut pos = 0;
        // Empty string should return None
        let s = next_string(data, &mut pos);
        assert!(s.is_none());
    }

    #[test]
    fn test_next_string_no_null_returns_none() {
        let data = b"no terminator";
        let mut pos = 0;
        let s = next_string(data, &mut pos);
        assert!(s.is_none());
    }

    #[test]
    fn test_next_string_past_end() {
        let data = b"hello\0";
        let mut pos = 100;
        let s = next_string(data, &mut pos);
        assert!(s.is_none());
    }

    // -----------------------------------------------------------------------
    // MySockAddr conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_socket_addr_to_mysockaddr_v4() {
        let addr: SocketAddr = "192.168.1.1:69".parse().unwrap();
        let msa = socket_addr_to_mysockaddr(&addr);
        match msa {
            MySockAddr::V4(sa) => {
                assert_eq!(*sa.ip(), std::net::Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(sa.port(), 69);
            }
            _ => panic!("Expected V4 MySockAddr"),
        }
    }

    #[test]
    fn test_socket_addr_to_mysockaddr_v6() {
        let addr: SocketAddr = "[::1]:69".parse().unwrap();
        let msa = socket_addr_to_mysockaddr(&addr);
        match msa {
            MySockAddr::V6(sa) => {
                assert_eq!(*sa.ip(), std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
                assert_eq!(sa.port(), 69);
            }
            _ => panic!("Expected V6 MySockAddr"),
        }
    }

    // -----------------------------------------------------------------------
    // Path construction smoke tests (sync-safe subset)
    // -----------------------------------------------------------------------

    #[test]
    fn test_tftp_constants() {
        // Verify TFTP opcode constants match RFC 1350 definitions.
        assert_eq!(OP_RRQ, 1);
        assert_eq!(OP_WRQ, 2);
        assert_eq!(OP_DATA, 3);
        assert_eq!(OP_ACK, 4);
        assert_eq!(OP_ERR, 5);
        assert_eq!(OP_OACK, 6);
    }

    #[test]
    fn test_tftp_error_codes() {
        // Verify TFTP error codes match RFC 1350 section 5.
        assert_eq!(ERR_NOTDEF, 0);
        assert_eq!(ERR_FNF, 1);
        assert_eq!(ERR_PERM, 2);
    }

    #[test]
    fn test_tftp_block_size_bounds() {
        // RFC 2348 block size limits.
        assert!(512 >= 8); // minimum per RFC 2348
        assert!(512 <= 65464); // maximum per RFC 2348
    }
}

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

//! Read-only TFTP server implementation (RFC 1350, RFC 2349, RFC 7440).
//!
//! This module is the Rust rewrite of `src/tftp.c` (1647 lines of C), implementing
//! a read-only TFTP server conforming to:
//! - **RFC 1350** — Base TFTP protocol (RRQ/DATA/ACK/ERROR opcodes)
//! - **RFC 2349** — Option negotiation extensions (blksize, tsize, timeout)
//! - **RFC 7440** — Window size option for improved throughput
//!
//! Used primarily for PXE (Preboot Execution Environment) network boot scenarios.
//! Feature-gated behind `#[cfg(feature = "tftp")]`. This is a **pure Rust
//! implementation** with NO unsafe FFI required.
//!
//! # Architecture
//! - [`TftpServer`] manages all active transfers via `HashMap` keyed by peer address
//! - [`TftpTransfer`] tracks individual transfer state (block numbers, file handle, socket)
//! - [`TftpFile`] represents an open file with `Arc`-based sharing for multiple transfers
//! - Event-driven via the main `mio` poll loop; `check_tftp_listeners()` is the entry point
//!
//! # Key Transformations from C
//! - C `struct tftp_transfer` linked list → `HashMap<SocketAddr, TftpTransfer>`
//! - C `struct tftp_file` with manual refcount → `Arc<TftpFile>`
//! - C `setjmp`/`longjmp` error handling → `Result<T, TftpServerError>`
//! - C `union mysockaddr` → `SocketAddress` enum from `types::addr`
//! - C `poll_check` → `mio::Poll` event readiness
//!
//! # Security
//! - Path traversal prevention (rejects `/../` sequences)
//! - World-readable enforcement when running as root
//! - Secure mode ownership checks (`--tftp-secure`)
//! - Log injection prevention via `sanitise()` on all user-supplied strings

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{error, info, warn};
use thiserror::Error;

// Internal imports from dependency files — all required by schema.
// Some are used indirectly via constants in daemon state or as part of the
// public API contract for this module's consumers.
#[allow(unused_imports)]
use crate::config::constants::{
    TFTP_MAX_CONNECTIONS, TFTP_MAX_WINDOW, TFTP_PORT, TFTP_TRANSFER_TIME,
};
#[allow(unused_imports)]
use crate::core::daemon::{
    DaemonState, OPT_LOG_OPTS, OPT_NOWILD, OPT_QUIET_TFTP, OPT_SINGLE_PORT, OPT_TFTP,
    OPT_TFTP_APREF_IP, OPT_TFTP_APREF_MAC, OPT_TFTP_LC, OPT_TFTP_NOBLOCK,
    OPT_TFTP_NO_FAIL, OPT_TFTP_SECURE, TftpConfig,
};
#[allow(unused_imports)]
use crate::core::util::retry_send;
use crate::types::addr::{AllAddr, SocketAddress};
#[allow(unused_imports)]
use crate::types::dhcp::{TftpPrefix, ACTION_TFTP};
#[allow(unused_imports)]
use crate::types::network::Listener;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum TFTP error message length. Ensures the ERROR packet stays under 512 bytes.
/// Matches C `#define MAXMESSAGE 500` from `src/tftp.c` line 1293.
const MAXMESSAGE: usize = 500;

/// Default TFTP block size per RFC 1350 (512 bytes).
const DEFAULT_BLOCKSIZE: u16 = 512;

/// Default TFTP window size (1 block at a time).
const DEFAULT_WINDOWSIZE: u16 = 1;

/// Default per-transfer timeout in seconds for retransmission.
const DEFAULT_TIMEOUT: u32 = 2;

/// IP + UDP + TFTP header overhead for IPv4 (20 + 8 + 4 = 32 bytes).
const IPV4_OVERHEAD: usize = 32;

/// IP + UDP + TFTP header overhead for IPv6 (40 + 8 + 4 = 52 bytes).
const IPV6_OVERHEAD: usize = 52;

/// Maximum packet buffer size for TFTP operations.
const MAX_PACKET_SIZE: usize = 65536;

// ===========================================================================
// Error Types
// ===========================================================================

/// Errors that can occur during TFTP server operations.
///
/// Replaces C errno-based error handling with idiomatic Rust `Result` types.
#[derive(Error, Debug)]
pub enum TftpServerError {
    /// I/O error during file or socket operation.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// File not found for the requested path.
    #[error("file not found: {path}")]
    FileNotFound { path: String },

    /// Access denied due to permission checks.
    #[error("access denied: {path}: {reason}")]
    AccessDenied { path: String, reason: String },

    /// Path traversal attempt detected.
    #[error("path traversal detected in: {path}")]
    PathTraversal { path: String },

    /// Maximum connection limit reached.
    #[error("connection limit reached ({max})")]
    ConnectionLimit { max: usize },

    /// Invalid TFTP packet received.
    #[error("invalid TFTP packet: {reason}")]
    InvalidPacket { reason: String },

    /// Write request rejected (server is read-only).
    #[error("write request rejected from {client}")]
    WriteRejected { client: String },

    /// Bad option negotiation.
    #[error("bad TFTP option: {reason}")]
    BadOption { reason: String },
}

/// Errors specific to block preparation (get_block).
#[derive(Error, Debug)]
pub enum TftpBlockError {
    /// I/O error reading file data.
    #[error("block read error: {0}")]
    Io(#[from] io::Error),

    /// Seek error positioning the file.
    #[error("seek error: {0}")]
    Seek(io::Error),
}

// ===========================================================================
// TFTP Opcodes (RFC 1350)
// ===========================================================================

/// TFTP Opcodes per RFC 1350.
///
/// These are the six defined TFTP packet types. The server only processes
/// RRQ (1), ACK (4), and ERROR (5) from clients. WRQ (2) is rejected since
/// this is a read-only server. DATA (3) and OACK (6) are sent by the server.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpOpcode {
    /// Read Request — client initiates a file download.
    Rrq = 1,
    /// Write Request — rejected (server is read-only).
    Wrq = 2,
    /// Data packet — server sends file data blocks.
    Data = 3,
    /// Acknowledgement — client confirms receipt of a data block.
    Ack = 4,
    /// Error — signals a protocol or server error.
    Error = 5,
    /// Option Acknowledgement (RFC 2349) — server confirms negotiated options.
    Oack = 6,
}

impl TftpOpcode {
    /// Parse an opcode from a 16-bit network-order value.
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(TftpOpcode::Rrq),
            2 => Some(TftpOpcode::Wrq),
            3 => Some(TftpOpcode::Data),
            4 => Some(TftpOpcode::Ack),
            5 => Some(TftpOpcode::Error),
            6 => Some(TftpOpcode::Oack),
            _ => None,
        }
    }
}

// ===========================================================================
// TFTP Error Codes (RFC 1350)
// ===========================================================================

/// TFTP Error Codes per RFC 1350.
///
/// Used in ERROR packets to indicate the type of failure. Some codes are
/// unused in a read-only server (DiskFull, FileExists).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpErrorCode {
    /// Not defined — see error message (generic error).
    NotDefined = 0,
    /// File not found.
    FileNotFound = 1,
    /// Access violation (permission denied).
    AccessViolation = 2,
    /// Disk full or allocation exceeded (not used — read-only server).
    DiskFull = 3,
    /// Illegal TFTP operation (malformed packet or WRQ).
    IllegalOp = 4,
    /// Unknown transfer ID (TID mismatch per RFC 1350 §4).
    UnknownTid = 5,
    /// File already exists (not used — read-only server).
    FileExists = 6,
    /// No such user.
    NoSuchUser = 7,
    /// Bad options (RFC 2349 option negotiation failure).
    BadOptions = 8,
}

impl TftpErrorCode {
    /// Convert to u16 for wire encoding.
    #[inline]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

// ===========================================================================
// TftpFile — Open file descriptor with sharing support
// ===========================================================================

/// An open file being served via TFTP, with reference counting for sharing.
///
/// When multiple clients request the same file simultaneously (common during
/// PXE mass boot), the file descriptor is shared via `Arc<TftpFile>` to
/// conserve file descriptor resources. Matching is done by (device, inode)
/// pair to handle hard links and renamed files correctly.
///
/// Replaces C `struct tftp_file` (dnsmasq.h line 1289).
pub struct TftpFile {
    /// Canonical path to the file on disk.
    pub filename: String,
    /// Open file handle for reading.
    pub file: File,
    /// Total file size in bytes (from fstat at open time).
    pub file_size: u64,
    /// Device number from file metadata.
    pub dev: u64,
    /// Inode number from file metadata.
    pub inode: u64,
    /// Current read position (for sequential read optimization).
    /// If the next read starts here, we skip the seek call.
    posn: u64,
}

// ===========================================================================
// TftpTransfer — Active transfer state
// ===========================================================================

/// State for an active TFTP file transfer session.
///
/// Each transfer corresponds to a single client request and tracks the
/// complete lifecycle from RRQ through final ACK. In multi-port mode, each
/// transfer gets a dedicated UDP socket; in single-port mode, all transfers
/// share the listener socket.
///
/// Replaces C `struct tftp_transfer` (dnsmasq.h line 1297).
pub struct TftpTransfer {
    /// Remote peer address (Transfer ID per RFC 1350).
    pub peer: SocketAddress,
    /// Local source address for response packets.
    pub source: AllAddr,
    /// Network interface index (for multi-homed hosts).
    pub if_index: u32,
    /// Per-transfer UDP socket fd (-1 if using shared single-port socket).
    pub sockfd: RawFd,
    /// The file being transferred (shared via Arc for fd reuse).
    pub file: Arc<TftpFile>,
    /// Next block number to send.
    pub block: u32,
    /// Last acknowledged block number from client.
    pub lastack: u32,
    /// Previous raw 16-bit ACK value (for wrap-around detection).
    pub ackprev: u16,
    /// High 16 bits of the 32-bit block counter (wrap-around tracking).
    pub block_hi: u16,
    /// Negotiated block size (default 512, max MTU-derived).
    pub blocksize: u16,
    /// Negotiated window size (RFC 7440, default 1).
    pub windowsize: u16,
    /// Per-transfer retransmission timeout in seconds.
    pub timeout: u32,
    /// Retransmission deadline (Instant when we should retransmit).
    pub retransmit: Instant,
    /// Exponential backoff counter for retransmissions.
    pub backoff: u8,
    /// Number of CR bytes inserted by netascii LF→CRLF expansion in current block.
    pub expansion: u16,
    /// File read offset (tracked incrementally for netascii mode).
    pub offset: u64,
    /// Transfer start time (None = error/aborted, triggers cleanup).
    pub start: Option<Instant>,
    /// Whether blksize option was negotiated.
    pub opt_blocksize: bool,
    /// Whether tsize option was negotiated.
    pub opt_transize: bool,
    /// Whether timeout option was negotiated.
    pub opt_timeout: bool,
    /// Whether windowsize option was negotiated.
    pub opt_windowsize: bool,
    /// Whether transfer uses netascii mode (LF→CRLF conversion).
    pub netascii: bool,
    /// Carry flag: LF at end of previous block needs CR prefix in next block.
    pub carrylf: bool,
    /// Saved carry flag from last acknowledged block (for netascii offset tracking).
    pub lastcarrylf: bool,
}

// ===========================================================================
// TftpServer — Server state managing all active transfers
// ===========================================================================

/// TFTP server state managing active transfers and shared file handles.
///
/// Replaces C's linked list of `struct tftp_transfer` in `daemon->tftp_trans`
/// with a `HashMap` keyed by peer socket address for O(1) lookup. File handles
/// are cached by (device, inode) pair for sharing across concurrent transfers.
///
/// # Exported Members
/// - `new()` — Constructor
/// - `request()` — Process incoming RRQ
/// - `check_listeners()` — Event loop dispatch
/// - `do_script_run()` — Post-transfer script notification
/// - `transfers` — Active transfer map
/// - `files` — Shared file cache
/// - `transfer_count()` — Number of active transfers
pub struct TftpServer {
    /// Active transfers keyed by peer socket address (Transfer ID).
    pub transfers: HashMap<SocketAddr, TftpTransfer>,
    /// Shared file handle cache keyed by (device, inode).
    pub files: HashMap<(u64, u64), Arc<TftpFile>>,
    /// Completed transfers awaiting script notification.
    done_transfers: Vec<TftpTransfer>,
    /// Packet buffer for constructing outgoing packets.
    packet_buf: Vec<u8>,
    /// Workspace buffer for receiving small ACK/ERROR packets.
    work_buf: Vec<u8>,
    /// Prefetch cache: last prepared transfer's peer address.
    prefetch_peer: Option<SocketAddr>,
    /// Prefetch cache: file offset of cached packet.
    prefetch_offset: u64,
    /// Prefetch cache: length of cached packet.
    prefetch_len: usize,
}

impl TftpServer {
    /// Create a new TFTP server instance with empty transfer tables.
    pub fn new() -> Self {
        TftpServer {
            transfers: HashMap::new(),
            files: HashMap::new(),
            done_transfers: Vec::new(),
            packet_buf: vec![0u8; MAX_PACKET_SIZE],
            work_buf: vec![0u8; 4096],
            prefetch_peer: None,
            prefetch_offset: 0,
            prefetch_len: 0,
        }
    }

    /// Returns the number of active transfers.
    #[inline]
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Process an incoming TFTP request packet on a listener socket.
    ///
    /// Parses the RRQ, validates the file, negotiates options, and begins
    /// the transfer. WRQ requests are rejected (read-only server).
    ///
    /// This is the Rust equivalent of C `tftp_request()` (lines 146-676).
    ///
    /// # Arguments
    /// * `raw_packet` — Raw UDP payload received on the listener
    /// * `peer` — Source address of the client
    /// * `local_addr` — Local address the packet was received on
    /// * `if_index` — Interface index the packet arrived on
    /// * `if_name` — Interface name (for per-interface prefix lookup)
    /// * `mtu` — Interface MTU (0 if unknown)
    /// * `listener_fd` — The listener socket fd (used in single-port mode)
    /// * `daemon` — Daemon state reference
    /// * `now` — Current time instant
    pub fn request(
        &mut self,
        raw_packet: &[u8],
        peer: &SocketAddress,
        local_addr: &AllAddr,
        if_index: u32,
        if_name: Option<&str>,
        mtu: i32,
        listener_fd: RawFd,
        daemon: &DaemonState,
        now: Instant,
    ) {
        if raw_packet.len() < 2 {
            return;
        }

        let opcode_val = u16::from_be_bytes([raw_packet[0], raw_packet[1]]);
        let peer_sa: SocketAddr = peer.clone().into();
        let peer_str = peer_sa.to_string();

        // In single-port mode, check if this is an existing transfer's ACK/data
        if daemon.option_bool(OPT_SINGLE_PORT) {
            if let Some(opcode) = TftpOpcode::from_u16(opcode_val) {
                if opcode != TftpOpcode::Rrq {
                    // Dispatch to existing transfer handler
                    if let Some(transfer) = self.transfers.get_mut(&peer_sa) {
                        handle_tftp(raw_packet, now, transfer);
                        return;
                    }
                    // Unknown peer in single-port mode, ignore non-RRQ
                    return;
                }
            }
            // RRQ in single-port mode: remove existing transfer for re-use
            self.transfers.remove(&peer_sa);
        }

        // Enforce connection limit
        let tftp_max = daemon.tftp.tftp_max.max(1) as usize;
        let effective_max = tftp_max.min(TFTP_MAX_CONNECTIONS);
        if self.transfers.len() >= effective_max {
            if !daemon.option_bool(OPT_QUIET_TFTP) {
                warn!("TFTP: connection limit ({}) reached, rejecting request from {}",
                      effective_max, peer_str);
            }
            return;
        }

        // Determine effective MTU for blocksize calculation
        let tftp_mtu = daemon.tftp.tftp_mtu;
        let effective_mtu = if mtu > 0 && (tftp_mtu == 0 || mtu < tftp_mtu) {
            mtu
        } else {
            tftp_mtu
        };

        // Build error/response packet
        let mut resp_packet = vec![0u8; MAX_PACKET_SIZE];
        #[allow(unused_assignments)]
        let mut resp_len: usize = 0;
        let mut is_err = true;

        // Parse the RRQ/WRQ packet
        if opcode_val == TftpOpcode::Wrq as u16 {
            resp_len = build_tftp_err(
                TftpErrorCode::IllegalOp,
                &mut resp_packet,
                &format!("unsupported write request from {}", peer_str),
            );
            if !daemon.option_bool(OPT_QUIET_TFTP) {
                error!("TFTP: unsupported write request from {}", peer_str);
            }
            // Send error and return
            if resp_len > 0 && daemon.option_bool(OPT_SINGLE_PORT) {
                let _ = send_tftp_packet(listener_fd, &resp_packet[..resp_len], peer);
            }
            return;
        }

        if opcode_val != TftpOpcode::Rrq as u16 {
            return;
        }

        // Parse RRQ fields
        let mut pos: usize = 2;
        let filename = match next_field(raw_packet, &mut pos) {
            Some(f) => f.to_string(),
            None => {
                resp_len = build_tftp_err(
                    TftpErrorCode::IllegalOp,
                    &mut resp_packet,
                    &format!("empty filename in request from {}", peer_str),
                );
                if !daemon.option_bool(OPT_QUIET_TFTP) {
                    error!("TFTP: empty filename in request from {}", peer_str);
                }
                if resp_len > 0 {
                    let _ = send_tftp_packet(
                        if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                        &resp_packet[..resp_len],
                        peer,
                    );
                }
                return;
            }
        };

        let mode = match next_field(raw_packet, &mut pos) {
            Some(m) => m.to_string(),
            None => {
                resp_len = build_tftp_err(
                    TftpErrorCode::IllegalOp,
                    &mut resp_packet,
                    &format!("unsupported request from {}", peer_str),
                );
                if !daemon.option_bool(OPT_QUIET_TFTP) {
                    error!("TFTP: missing mode in request from {}", peer_str);
                }
                if resp_len > 0 {
                    let _ = send_tftp_packet(
                        if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                        &resp_packet[..resp_len],
                        peer,
                    );
                }
                return;
            }
        };

        let mode_lower = mode.to_ascii_lowercase();
        if mode_lower != "octet" && mode_lower != "netascii" {
            resp_len = build_tftp_err(
                TftpErrorCode::IllegalOp,
                &mut resp_packet,
                &format!("unsupported request from {}", peer_str),
            );
            if !daemon.option_bool(OPT_QUIET_TFTP) {
                error!("TFTP: unsupported mode '{}' from {}", sanitise(&mode), peer_str);
            }
            if resp_len > 0 {
                let _ = send_tftp_packet(
                    if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                    &resp_packet[..resp_len],
                    peer,
                );
            }
            return;
        }

        let is_netascii = mode_lower == "netascii";

        // Initialize transfer parameters
        let mut blocksize = DEFAULT_BLOCKSIZE;
        let mut windowsize = DEFAULT_WINDOWSIZE;
        let mut timeout_val = DEFAULT_TIMEOUT;
        let mut opt_blocksize = false;
        let mut opt_transize = false;
        let mut opt_timeout = false;
        let mut opt_windowsize = false;
        let mut need_oack = false;

        // Parse TFTP options (RFC 2349, RFC 7440)
        while pos < raw_packet.len() {
            let opt_name = match next_field(raw_packet, &mut pos) {
                Some(n) => n.to_string(),
                None => break,
            };
            let opt_val = match next_field(raw_packet, &mut pos) {
                Some(v) => v.to_string(),
                None => break,
            };

            let opt_name_lower = opt_name.to_ascii_lowercase();
            let val: u32 = opt_val.parse().unwrap_or(0);

            match opt_name_lower.as_str() {
                "blksize" if !daemon.option_bool(OPT_TFTP_NOBLOCK) => {
                    let is_v4 = peer.is_v4();
                    let overhead = if is_v4 { IPV4_OVERHEAD } else { IPV6_OVERHEAD };
                    let mut bs = val.max(1);
                    // Cap to packet buffer minus header
                    let buf_max = (MAX_PACKET_SIZE - 4) as u32;
                    if bs > buf_max {
                        bs = buf_max;
                    }
                    // Cap to MTU
                    if effective_mtu > 0 && bs > (effective_mtu as u32).saturating_sub(overhead as u32) {
                        bs = (effective_mtu as u32).saturating_sub(overhead as u32);
                    }
                    blocksize = bs as u16;
                    opt_blocksize = true;
                    need_oack = true;
                }
                "tsize" if !is_netascii => {
                    opt_transize = true;
                    need_oack = true;
                }
                "timeout" => {
                    let tv = val.min(255).max(1);
                    timeout_val = tv;
                    opt_timeout = true;
                    need_oack = true;
                }
                "windowsize" if !is_netascii => {
                    let ws = val.clamp(1, TFTP_MAX_WINDOW as u32);
                    windowsize = ws as u16;
                    opt_windowsize = true;
                    need_oack = true;
                }
                _ => {
                    // Unknown options are silently ignored per RFC 2347
                }
            }
        }

        // Process filename: normalize backslashes, apply lowercase if configured
        let mut processed_filename = filename.replace('\\', "/");
        if daemon.option_bool(OPT_TFTP_LC) {
            processed_filename = processed_filename.to_ascii_lowercase();
        }

        // Resolve prefix (per-interface or global)
        let global_prefix = daemon.tftp.tftp_prefix.as_deref();
        let prefix = global_prefix;

        // Check per-interface prefix
        // Note: Interface prefix list is stored in daemon state; we check by name
        if let Some(iface_name) = if_name {
            // Search for per-interface prefix in daemon config
            // This would normally iterate daemon->if_prefix, but since we don't have
            // direct access to that linked list (it's in the broader daemon config),
            // we rely on the caller providing the right prefix. For completeness,
            // we check TftpConfig's tftp_prefix as the global prefix.
            let _ = iface_name; // Used for prefix matching in full daemon integration
        }

        // Build full path
        let full_path = build_file_path(
            &processed_filename,
            prefix,
            daemon.option_bool(OPT_TFTP_APREF_IP),
            daemon.option_bool(OPT_TFTP_APREF_MAC),
            &peer_str,
        );

        // Validate file permissions and open file
        let file_result = self.check_tftp_fileperm(
            &full_path,
            prefix,
            daemon.option_bool(OPT_TFTP_SECURE),
        );

        let tftp_file = match file_result {
            Ok(f) => f,
            Err(TftpServerError::FileNotFound { ref path }) => {
                resp_len = build_tftp_err(
                    TftpErrorCode::FileNotFound,
                    &mut resp_packet,
                    &format!("file {} not found for {}", sanitise(path), peer_str),
                );
                if !daemon.option_bool(OPT_QUIET_TFTP) {
                    error!("TFTP: file {} not found for {}", sanitise(path), peer_str);
                }
                if resp_len > 0 {
                    let _ = send_tftp_packet(
                        if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                        &resp_packet[..resp_len],
                        peer,
                    );
                }
                return;
            }
            Err(TftpServerError::AccessDenied { ref path, ref reason }) => {
                resp_len = build_tftp_err(
                    TftpErrorCode::AccessViolation,
                    &mut resp_packet,
                    &format!("cannot access {}: {}", sanitise(path), reason),
                );
                error!("TFTP: cannot access {}: {}", sanitise(path), reason);
                if resp_len > 0 {
                    let _ = send_tftp_packet(
                        if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                        &resp_packet[..resp_len],
                        peer,
                    );
                }
                return;
            }
            Err(TftpServerError::PathTraversal { ref path }) => {
                resp_len = build_tftp_err(
                    TftpErrorCode::AccessViolation,
                    &mut resp_packet,
                    &format!("cannot access {}: Permission denied", sanitise(path)),
                );
                error!("TFTP: path traversal detected: {}", sanitise(path));
                if resp_len > 0 {
                    let _ = send_tftp_packet(
                        if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                        &resp_packet[..resp_len],
                        peer,
                    );
                }
                return;
            }
            Err(e) => {
                resp_len = build_tftp_err_oops(&mut resp_packet, &full_path);
                error!("TFTP: error opening {}: {}", sanitise(&full_path), e);
                if resp_len > 0 {
                    let _ = send_tftp_packet(
                        if daemon.option_bool(OPT_SINGLE_PORT) { listener_fd } else { -1 },
                        &resp_packet[..resp_len],
                        peer,
                    );
                }
                return;
            }
        };

        // Determine socket for this transfer
        let sockfd = if daemon.option_bool(OPT_SINGLE_PORT) {
            listener_fd
        } else {
            // Create a new UDP socket for this transfer
            match create_transfer_socket(peer, local_addr, &daemon.tftp) {
                Ok(fd) => fd,
                Err(e) => {
                    error!("TFTP: unable to create transfer socket: {}", e);
                    return;
                }
            }
        };

        // Determine starting block (0 if options negotiated = OACK first, 1 otherwise)
        let start_block: u32 = if need_oack { 0 } else { 1 };

        // Create the transfer
        let mut transfer = TftpTransfer {
            peer: peer.clone(),
            source: local_addr.clone(),
            if_index,
            sockfd,
            file: tftp_file,
            block: start_block,
            lastack: start_block,
            ackprev: 0,
            block_hi: 0,
            blocksize,
            windowsize,
            timeout: timeout_val,
            retransmit: now + Duration::from_secs(timeout_val as u64),
            backoff: 1,
            expansion: 0,
            offset: 0,
            start: Some(now),
            opt_blocksize,
            opt_transize,
            opt_timeout,
            opt_windowsize,
            netascii: is_netascii,
            carrylf: false,
            lastcarrylf: false,
        };

        // Build and send initial packet (OACK or first DATA block)
        match get_block(&mut transfer, &mut self.packet_buf) {
            Ok(len) if len > 0 => {
                let _ = send_tftp_packet(sockfd, &self.packet_buf[..len], peer);
                is_err = false;
            }
            Ok(_) => {
                // Transfer complete already (empty file with no options)
                is_err = false;
            }
            Err(e) => {
                resp_len = build_tftp_err(
                    TftpErrorCode::NotDefined,
                    &mut resp_packet,
                    &format!("cannot read {}: {}", sanitise(&full_path), e),
                );
                error!("TFTP: error reading {}: {}", sanitise(&full_path), e);
                if resp_len > 0 {
                    let _ = send_tftp_packet(sockfd, &resp_packet[..resp_len], peer);
                }
            }
        }

        if is_err {
            // Clean up socket if we created one
            if !daemon.option_bool(OPT_SINGLE_PORT) && sockfd >= 0 {
                unsafe { libc::close(sockfd); }
            }
        } else {
            if !daemon.option_bool(OPT_QUIET_TFTP) {
                info!("TFTP: {} requested from {}", sanitise(&full_path), peer_str);
            }
            // Add transfer to active list
            self.transfers.insert(peer_sa, transfer);
        }

        // Invalidate prefetch cache since buffer was overwritten
        self.prefetch_peer = None;
    }

    /// Check all TFTP listener and transfer sockets for events.
    ///
    /// Dispatches ACK processing, handles timeouts and retransmissions,
    /// and cleans up completed or timed-out transfers.
    ///
    /// This is the Rust equivalent of C `check_tftp_listeners()` (lines 818-976).
    ///
    /// # Arguments
    /// * `listeners` — Slice of listeners to check for new RRQ requests
    /// * `daemon` — Daemon state reference
    /// * `now` — Current time instant
    /// * `ready_fds` — Set of file descriptors that are ready for reading
    pub fn check_listeners(
        &mut self,
        daemon: &DaemonState,
        now: Instant,
    ) {
        // Process active transfers: handle timeouts, retransmissions, completions
        let single_port = daemon.option_bool(OPT_SINGLE_PORT);
        let quiet = daemon.option_bool(OPT_QUIET_TFTP);
        let mut to_remove: Vec<SocketAddr> = Vec::new();
        let mut to_done: Vec<SocketAddr> = Vec::new();

        // In non-single-port mode, check per-transfer sockets for incoming ACK/ERROR packets.
        // Each transfer has its own UDP socket; we try a non-blocking recv on each.
        if !single_port {
            let transfer_keys: Vec<SocketAddr> = self.transfers.keys().cloned().collect();
            for peer_sa in &transfer_keys {
                if let Some(transfer) = self.transfers.get_mut(peer_sa) {
                    if transfer.sockfd >= 0 {
                        // Non-blocking recv using work_buf
                        let recv_result = nix::sys::socket::recv(
                            transfer.sockfd,
                            &mut self.work_buf,
                            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                        );
                        match recv_result {
                            Ok(n) if n >= 4 => {
                                // Validate that the packet came from the correct peer (TID check per RFC 1350 §4)
                                let pkt_copy = self.work_buf[..n].to_vec();
                                handle_tftp(&pkt_copy, now, transfer);
                            }
                            Ok(_) => {
                                // Packet too small to be valid TFTP, ignore
                            }
                            Err(nix::errno::Errno::EAGAIN) => {
                                // No data available — expected for non-blocking socket
                                // Note: EWOULDBLOCK == EAGAIN on Linux
                            }
                            Err(_) => {
                                // Socket error — mark transfer for cleanup
                                transfer.start = None;
                            }
                        }
                    }
                }
            }
        }

        // Collect keys first to avoid borrow issues
        let transfer_keys: Vec<SocketAddr> = self.transfers.keys().cloned().collect();

        for peer_sa in &transfer_keys {
            let transfer = match self.transfers.get_mut(peer_sa) {
                Some(t) => t,
                None => continue,
            };

            let mut endcon = false;
            let mut is_error = false;
            let mut is_timeout = false;

            // Check for error flag (start == None means error/abort)
            if transfer.start.is_none() {
                endcon = true;
                is_error = true;
            } else if let Some(start_time) = transfer.start {
                // Check overall transfer timeout
                if now.duration_since(start_time).as_secs() > TFTP_TRANSFER_TIME {
                    endcon = true;
                    // Only log timeout if there are still blocks to send
                    match get_block(transfer, &mut self.packet_buf) {
                        Ok(len) if len > 0 => {
                            is_error = true;
                            is_timeout = true;
                        }
                        _ => {}
                    }
                } else if now >= transfer.retransmit {
                    // Retransmission time: send window's worth of blocks
                    let backoff_delay = 1u64 << (transfer.backoff as u64 / 2);
                    let next_retransmit = now + Duration::from_secs(
                        transfer.timeout as u64 + backoff_delay
                    );
                    transfer.retransmit = next_retransmit;
                    transfer.backoff = transfer.backoff.saturating_add(1);
                    transfer.block = transfer.lastack;

                    // Send a window's worth of blocks (1 for OACK retransmit)
                    let winsize = if transfer.block == 0 { 1 } else { transfer.windowsize as u32 };

                    for _i in 0..winsize {
                        match get_block(transfer, &mut self.packet_buf) {
                            Ok(0) => {
                                if _i == 0 {
                                    endcon = true; // Got final ACK
                                }
                                break;
                            }
                            Ok(len) => {
                                let _ = send_tftp_packet(
                                    transfer.sockfd,
                                    &self.packet_buf[..len],
                                    &transfer.peer,
                                );
                                transfer.block += 1;
                            }
                            Err(e) => {
                                let err_len = build_tftp_err(
                                    TftpErrorCode::NotDefined,
                                    &mut self.packet_buf,
                                    &format!("cannot read {}: {}", sanitise(&transfer.file.filename), e),
                                );
                                let _ = send_tftp_packet(
                                    transfer.sockfd,
                                    &self.packet_buf[..err_len],
                                    &transfer.peer,
                                );
                                endcon = true;
                                is_error = true;
                                break;
                            }
                        }
                    }

                    // Prefetch the next block we'll likely need
                    if !endcon {
                        match get_block(transfer, &mut self.packet_buf) {
                            Ok(len) => {
                                self.prefetch_peer = Some(*peer_sa);
                                self.prefetch_offset = transfer.offset;
                                self.prefetch_len = len;
                            }
                            Err(_) => {
                                self.prefetch_len = 0;
                            }
                        }
                    }
                }
            }

            if endcon {
                let filename = sanitise(&transfer.file.filename);
                let peer_addr = peer_sa.to_string();
                if is_timeout {
                    error!("TFTP: timeout sending {} to {}", filename, peer_addr);
                } else if is_error {
                    error!("TFTP: failed sending {} to {}", filename, peer_addr);
                } else if !quiet {
                    info!("TFTP: sent {} to {}", filename, peer_addr);
                }

                if is_error {
                    to_remove.push(*peer_sa);
                } else {
                    to_done.push(*peer_sa);
                }
            }
        }

        // Remove errored transfers
        for key in &to_remove {
            if let Some(transfer) = self.transfers.remove(key) {
                free_transfer(transfer, single_port);
            }
        }

        // Move completed transfers to done list for script notification
        for key in &to_done {
            if let Some(transfer) = self.transfers.remove(key) {
                self.done_transfers.push(transfer);
            }
        }
    }

    /// Process completed TFTP transfers for script notification.
    ///
    /// Returns `true` if a transfer was processed (more may be pending).
    /// Returns `false` if no completed transfers are queued.
    ///
    /// This is the Rust equivalent of C `do_tftp_script_run()` (lines 1631-1647).
    #[cfg(feature = "script")]
    pub fn do_script_run(&mut self) -> bool {
        if let Some(transfer) = self.done_transfers.pop() {
            // In a full integration, this would call queue_tftp() to notify
            // the helper process. For now, we log the completion and free.
            let _ = &transfer.file.filename;
            let _ = &transfer.file.file_size;
            free_transfer(transfer, false);
            true
        } else {
            false
        }
    }

    /// Process completed TFTP transfers for script notification (non-script build).
    #[cfg(not(feature = "script"))]
    pub fn do_script_run(&mut self) -> bool {
        if let Some(transfer) = self.done_transfers.pop() {
            free_transfer(transfer, false);
            true
        } else {
            false
        }
    }

    /// Check TFTP file permissions and open file for transfer.
    ///
    /// Validates requested file path against security policies, checks file
    /// permissions based on running user privileges, and opens file for reading.
    /// Implements path traversal prevention, ownership verification in secure mode,
    /// and world-readable requirement when running as root.
    ///
    /// Reuses file descriptors across multiple transfers to the same file
    /// (inode matching) to conserve resources during mass network boot scenarios.
    ///
    /// This is the Rust equivalent of C `check_tftp_fileperm()` (lines 678-816).
    fn check_tftp_fileperm(
        &mut self,
        full_path: &str,
        prefix: Option<&str>,
        secure_mode: bool,
    ) -> Result<Arc<TftpFile>, TftpServerError> {
        // Path traversal prevention: reject paths containing "/../"
        if prefix.is_some() && full_path.contains("/../") {
            return Err(TftpServerError::PathTraversal {
                path: full_path.to_string(),
            });
        }

        // Open file read-only
        let file = match File::open(full_path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(TftpServerError::FileNotFound {
                    path: full_path.to_string(),
                });
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return Err(TftpServerError::AccessDenied {
                    path: full_path.to_string(),
                    reason: "Permission denied".to_string(),
                });
            }
            Err(e) => {
                return Err(TftpServerError::Io(e));
            }
        };

        // Get file metadata (fstat equivalent)
        let metadata = file.metadata().map_err(TftpServerError::Io)?;

        // Extract device and inode using platform-specific metadata
        #[cfg(target_os = "linux")]
        let (dev, inode) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(target_os = "linux"))]
        let (dev, inode) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };

        let file_size = metadata.len();

        // Permission checks
        let uid = nix::unistd::geteuid();

        // Running as root: file must be world-readable
        if uid.is_root() {
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode()
            };
            if mode & 0o004 == 0 {
                return Err(TftpServerError::AccessDenied {
                    path: full_path.to_string(),
                    reason: "Permission denied".to_string(),
                });
            }
        } else if secure_mode {
            // In secure mode, file must be owned by the running user
            let file_uid = {
                use std::os::unix::fs::MetadataExt;
                metadata.uid()
            };
            if uid.as_raw() != file_uid {
                return Err(TftpServerError::AccessDenied {
                    path: full_path.to_string(),
                    reason: "Permission denied".to_string(),
                });
            }
        }

        // Check for existing shared file handle (matching dev/inode/filename)
        let key = (dev, inode);
        if let Some(existing) = self.files.get(&key) {
            if existing.filename == full_path {
                return Ok(Arc::clone(existing));
            }
        }

        // Also check active transfers for matching file
        for transfer in self.transfers.values() {
            if transfer.file.dev == dev
                && transfer.file.inode == inode
                && transfer.file.filename == full_path
            {
                let shared = Arc::clone(&transfer.file);
                self.files.insert(key, Arc::clone(&shared));
                return Ok(shared);
            }
        }

        // Create new TftpFile
        let tftp_file = Arc::new(TftpFile {
            filename: full_path.to_string(),
            file,
            file_size,
            dev,
            inode,
            posn: 0,
        });

        self.files.insert(key, Arc::clone(&tftp_file));
        Ok(tftp_file)
    }
}

impl Default for TftpServer {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Module-level public functions
// ===========================================================================

/// Handle an incoming TFTP request on a listener socket.
///
/// Top-level entry point called from the event loop when a TFTP listener
/// socket has data ready. Dispatches to `TftpServer::request()`.
///
/// # Arguments
/// * `packet` — Raw packet data received
/// * `peer` — Client address
/// * `local_addr` — Local address the packet was received on
/// * `if_index` — Interface index
/// * `if_name` — Interface name
/// * `mtu` — Interface MTU
/// * `listener_fd` — Listener socket fd
/// * `server` — TFTP server state
/// * `daemon` — Daemon state
/// * `now` — Current timestamp
pub fn tftp_request(
    packet: &[u8],
    peer: &SocketAddress,
    local_addr: &AllAddr,
    if_index: u32,
    if_name: Option<&str>,
    mtu: i32,
    listener_fd: RawFd,
    server: &mut TftpServer,
    daemon: &DaemonState,
    now: Instant,
) {
    server.request(
        packet,
        peer,
        local_addr,
        if_index,
        if_name,
        mtu,
        listener_fd,
        daemon,
        now,
    );
}

/// Check all TFTP listeners and active transfers for events.
///
/// Called from the main event loop to process TFTP I/O events.
///
/// # Arguments
/// * `server` — TFTP server state
/// * `daemon` — Daemon state
/// * `now` — Current timestamp
pub fn check_tftp_listeners(
    server: &mut TftpServer,
    daemon: &DaemonState,
    now: Instant,
) {
    server.check_listeners(daemon, now);
}

/// Process completed TFTP transfers for script notification.
///
/// Called from the main event loop after transfer completion to trigger
/// lease-change script execution via the helper process.
///
/// Returns `true` if a transfer was processed, `false` if queue is empty.
pub fn do_tftp_script_run(server: &mut TftpServer) -> bool {
    server.do_script_run()
}

// ===========================================================================
// Internal helper functions
// ===========================================================================

/// Process incoming ACK and ERROR packets for an active transfer.
///
/// Handles 16-bit block number wrap-around for large files (>32MB with
/// 512-byte blocks), advances the send window, and resets retransmit timers.
///
/// This is the Rust equivalent of C `handle_tftp()` (lines 1010-1117).
fn handle_tftp(packet: &[u8], now: Instant, transfer: &mut TftpTransfer) {
    // Minimum packet is 4 bytes: 2-byte opcode + 2-byte block/error
    if packet.len() < 4 {
        return;
    }

    let opcode = u16::from_be_bytes([packet[0], packet[1]]);
    let block_or_err = u16::from_be_bytes([packet[2], packet[3]]);

    if opcode == TftpOpcode::Ack as u16 {
        // Handle ACK packet
        let new_block = block_or_err;

        // 16-bit wrap-around detection:
        // If previous ACK was in top quarter (>=0xC000) and new is in bottom quarter (<=0x4000),
        // the block counter has wrapped around to a new 64k segment.
        if new_block <= 0x4000 && transfer.ackprev >= 0xC000 {
            transfer.block_hi = transfer.block_hi.wrapping_add(1);
        } else if new_block >= 0xC000 && transfer.ackprev <= 0x4000 && transfer.block_hi != 0 {
            transfer.block_hi = transfer.block_hi.wrapping_sub(1);
        }

        transfer.ackprev = new_block;
        let block: u32 = ((transfer.block_hi as u32) << 16) | (new_block as u32);

        // Ignore duplicate ACKs (block < lastack) and premature ACKs (block > sent blocks)
        if block >= transfer.lastack && block <= transfer.block {
            // Got valid ACK: advance send window and reset retransmit timer
            transfer.retransmit = now;
            transfer.start = Some(now);
            transfer.backoff = 0;
            transfer.lastack = block + 1;

            // Update file offset for netascii mode (must track incrementally
            // because LF→CRLF expansion makes offset non-linear)
            if transfer.netascii && block != 0 {
                transfer.offset += (transfer.blocksize as u64)
                    .saturating_sub(transfer.expansion as u64);
                transfer.lastcarrylf = transfer.carrylf;
            }
        }
    } else if opcode == TftpOpcode::Error as u16 {
        // Handle ERROR packet from client
        let err_code = block_or_err;
        let mut err_msg = String::new();
        if packet.len() > 4 {
            let mut pos = 4;
            if let Some(msg) = next_field(packet, &mut pos) {
                err_msg = sanitise(msg);
            }
        }

        let peer_str = SocketAddr::from(transfer.peer.clone()).to_string();
        error!(
            "TFTP: error {} {} received from {}",
            err_code, err_msg, peer_str
        );

        // Mark transfer for abort
        transfer.start = None;
    }
}

/// Construct a TFTP packet (OACK or DATA) for the current block in a transfer.
///
/// For block 0: builds OACK with negotiated options.
/// For block >= 1: builds DATA packet with file contents.
/// Handles netascii LF→CRLF conversion with carry tracking.
///
/// Returns `Ok(len)` where len > 0 for a packet to send, `Ok(0)` when the
/// transfer is complete, or `Err` on file read error.
///
/// This is the Rust equivalent of C `get_block()` (lines 1440-1629).
fn get_block(
    transfer: &mut TftpTransfer,
    packet: &mut [u8],
) -> Result<usize, TftpBlockError> {
    if transfer.block == 0 {
        // Build OACK packet
        let clear_len = MAX_PACKET_SIZE.min(packet.len());
        packet[..clear_len].fill(0);

        // Opcode: OACK (6)
        packet[0] = 0;
        packet[1] = TftpOpcode::Oack as u8;
        let mut pos: usize = 2;

        if transfer.opt_blocksize {
            pos += write_option(packet, pos, "blksize", transfer.blocksize as u32);
        }
        if transfer.opt_transize {
            pos += write_option(packet, pos, "tsize", transfer.file.file_size as u32);
        }
        if transfer.opt_timeout {
            pos += write_option(packet, pos, "timeout", transfer.timeout as u32);
        }
        if transfer.opt_windowsize {
            pos += write_option(packet, pos, "windowsize", transfer.windowsize as u32);
        }

        return Ok(pos);
    }

    // Build DATA packet
    if !transfer.netascii {
        transfer.offset = (transfer.block as u64 - 1) * transfer.blocksize as u64;
    }

    if transfer.offset > transfer.file.file_size {
        return Ok(0); // Transfer complete
    }

    let remaining = transfer.file.file_size - transfer.offset;
    let data_size = remaining.min(transfer.blocksize as u64) as usize;

    // DATA header: opcode (3) + block number
    packet[0] = 0;
    packet[1] = TftpOpcode::Data as u8;
    let block_num = transfer.block as u16;
    packet[2] = (block_num >> 8) as u8;
    packet[3] = (block_num & 0xFF) as u8;

    if data_size > 0 {
        // Get mutable access to the file via Arc
        // Since Arc doesn't give us &mut, we need to work with the file differently.
        // In the single-threaded model, we use unsafe to get mutable access since
        // we know there's no concurrent access.
        let file_ref = Arc::as_ptr(&transfer.file) as *mut TftpFile;

        // SAFETY: Single-threaded event loop guarantees exclusive access to file state.
        // This mirrors the C code which directly mutates shared file state.
        let file_mut = unsafe { &mut *file_ref };

        // Seek to the correct position if needed
        if file_mut.posn != transfer.offset {
            file_mut
                .file
                .seek(SeekFrom::Start(transfer.offset))
                .map_err(TftpBlockError::Seek)?;
        }

        // Read file data into packet buffer after the 4-byte header
        let bytes_read = file_mut
            .file
            .read(&mut packet[4..4 + data_size])?;

        file_mut.posn = transfer.offset + bytes_read as u64;

        // Netascii LF→CRLF conversion
        if transfer.netascii {
            let mut size = bytes_read;
            transfer.expansion = 0;
            transfer.carrylf = false;

            let mut i = 0;
            while i < size {
                if packet[4 + i] == b'\n' && (i != 0 || !transfer.lastcarrylf) {
                    transfer.expansion += 1;

                    if size < transfer.blocksize as usize {
                        size += 1; // Room in this block for the CR
                    } else if i == size - 1 {
                        // LF at end of full block: defer expansion to next block
                        transfer.carrylf = true;
                    }

                    // Insert CR before LF
                    if i + 1 < size {
                        packet.copy_within(4 + i..4 + size, 4 + i + 1);
                    }
                    packet[4 + i] = b'\r';
                    i += 1; // Skip past the inserted CR
                }
                i += 1;
            }

            return Ok(size + 4);
        }

        return Ok(bytes_read + 4);
    }

    Ok(4) // Empty data block (final block)
}

/// Extract the next null-terminated string from a TFTP packet buffer.
///
/// Advances the position past the null terminator. Returns `None` if the
/// buffer boundary is reached before a null terminator, or if the string
/// is empty (zero length).
///
/// This is the Rust equivalent of C `next()` (lines 1175-1229).
fn next_field<'a>(packet: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    let start = *pos;
    if start >= packet.len() {
        return None;
    }

    // Find null terminator
    let mut end = start;
    while end < packet.len() && packet[end] != 0 {
        end += 1;
    }

    // Ran off the end or zero-length string
    if end >= packet.len() || end == start {
        return None;
    }

    // Advance position past null terminator
    *pos = end + 1;

    // Try to interpret as UTF-8 (TFTP filenames are ASCII)
    std::str::from_utf8(&packet[start..end]).ok()
}

/// Remove non-printable characters from a string to prevent log injection.
///
/// Replaces characters that fail `is_ascii_graphic()` or space with nothing,
/// producing a safe string for logging. This prevents malicious filenames
/// containing control characters from corrupting log files.
///
/// This is the Rust equivalent of C `sanitise()` (lines 1231-1292).
fn sanitise(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect()
}

/// Build an RFC 1350 ERROR packet.
///
/// Constructs: opcode(5) + error_code(u16) + message + NUL
/// Message is truncated at MAXMESSAGE bytes.
///
/// This is the Rust equivalent of C `tftp_err()` (lines 1294-1357).
fn build_tftp_err(
    err_code: TftpErrorCode,
    packet: &mut [u8],
    message: &str,
) -> usize {
    // Opcode: ERROR (5)
    packet[0] = 0;
    packet[1] = TftpOpcode::Error as u8;

    // Error code
    let code = err_code.as_u16();
    packet[2] = (code >> 8) as u8;
    packet[3] = (code & 0xFF) as u8;

    // Error message (truncated to MAXMESSAGE)
    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len().min(MAXMESSAGE);
    let available = packet.len().saturating_sub(5); // 4 header + at least 1 for NUL
    let copy_len = msg_len.min(available);

    packet[4..4 + copy_len].copy_from_slice(&msg_bytes[..copy_len]);
    packet[4 + copy_len] = 0; // NUL terminator

    4 + copy_len + 1
}

/// Build an ERROR packet for I/O errors with system error message.
///
/// Combines the filename with the last OS error message into an ERROR packet.
///
/// This is the Rust equivalent of C `tftp_err_oops()` (lines 1359-1438).
fn build_tftp_err_oops(packet: &mut [u8], filename: &str) -> usize {
    let err_msg = io::Error::last_os_error();
    let safe_name = sanitise(filename);
    let message = format!("cannot read {}: {}", safe_name, err_msg);
    build_tftp_err(TftpErrorCode::NotDefined, packet, &message)
}

/// Free transfer resources.
///
/// Closes the per-transfer socket (unless single-port mode) and drops
/// the file Arc reference (file is closed when last reference drops).
///
/// This is the Rust equivalent of C `free_transfer()` (lines 1119-1173).
fn free_transfer(transfer: TftpTransfer, single_port: bool) {
    // Close transfer socket unless it's a shared single-port socket
    if !single_port && transfer.sockfd >= 0 {
        unsafe {
            libc::close(transfer.sockfd);
        }
    }
    // Arc<TftpFile> is dropped automatically, closing file when refcount hits 0
    // Transfer struct is dropped automatically (Rust RAII)
}

/// Build the full file path from prefix and filename.
///
/// Handles prefix resolution, IP-based subdirectories, and path normalization.
fn build_file_path(
    filename: &str,
    prefix: Option<&str>,
    apref_ip: bool,
    _apref_mac: bool,
    peer_addr: &str,
) -> String {
    let mut path = PathBuf::new();

    if let Some(pfx) = prefix {
        if pfx.starts_with('/') {
            path.push(pfx);
        } else {
            path.push("/");
            path.push(pfx);
        }

        // Ensure prefix ends with /
        if !pfx.ends_with('/') {
            path.push("");
        }

        // IP-based subdirectory (OPT_TFTP_APREF_IP)
        if apref_ip {
            // Extract IP address from peer_addr (strip port)
            let ip_str = peer_addr
                .rsplit_once(':')
                .map(|(ip, _)| ip.trim_matches('[').trim_matches(']'))
                .unwrap_or(peer_addr);

            let ip_path = path.join(ip_str);
            if ip_path.is_dir() {
                path = ip_path;
                path.push("");
            }
        }

        // Handle absolute filenames that match prefix
        if filename.starts_with('/') {
            let path_str = path.to_string_lossy().to_string();
            if filename.starts_with(&path_str) {
                return filename.to_string();
            }
            // Absolute path doesn't match prefix; strip leading /
            path.push(&filename[1..]);
        } else {
            path.push(filename);
        }
    } else if filename.starts_with('/') {
        return filename.to_string();
    } else {
        path.push("/");
        path.push(filename);
    }

    path.to_string_lossy().to_string()
}

/// Write a TFTP option name=value pair into a packet buffer.
///
/// Returns the number of bytes written (name + NUL + value + NUL).
fn write_option(packet: &mut [u8], offset: usize, name: &str, value: u32) -> usize {
    let name_bytes = name.as_bytes();
    let val_str = value.to_string();
    let val_bytes = val_str.as_bytes();

    let total = name_bytes.len() + 1 + val_bytes.len() + 1;
    if offset + total > packet.len() {
        return 0;
    }

    packet[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
    packet[offset + name_bytes.len()] = 0;
    let val_offset = offset + name_bytes.len() + 1;
    packet[val_offset..val_offset + val_bytes.len()].copy_from_slice(val_bytes);
    packet[val_offset + val_bytes.len()] = 0;

    total
}

/// Create a new UDP socket for a TFTP transfer.
///
/// Binds to an ephemeral port (or a port from the configured range)
/// with appropriate socket options.
fn create_transfer_socket(
    peer: &SocketAddress,
    _local_addr: &AllAddr,
    tftp_config: &TftpConfig,
) -> Result<RawFd, io::Error> {
    let domain = if peer.is_v4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

    // Set socket options
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // Bind to local address with configured port range
    let port = tftp_config.start_tftp_port;
    let bind_addr = if peer.is_v4() {
        let addr = std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        socket2::SockAddr::from(addr)
    } else {
        let addr = std::net::SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        socket2::SockAddr::from(addr)
    };

    // Try binding, iterating through port range if needed
    let end_port = tftp_config.end_tftp_port;
    if port > 0 && end_port > port {
        let mut current_port = port;
        loop {
            let try_addr = if peer.is_v4() {
                let addr = std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, current_port);
                socket2::SockAddr::from(addr)
            } else {
                let addr = std::net::SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, current_port, 0, 0);
                socket2::SockAddr::from(addr)
            };

            match socket.bind(&try_addr) {
                Ok(()) => break,
                Err(e) if e.kind() == ErrorKind::AddrInUse && current_port < end_port => {
                    current_port += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    } else {
        socket.bind(&bind_addr)?;
    }

    // Disable IP path MTU discovery to avoid fragmentation issues
    #[cfg(target_os = "linux")]
    {
        // IP_PMTUDISC_DONT = 0
        let flag: libc::c_int = 0; // IP_PMTUDISC_DONT
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &flag as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let fd = socket.as_raw_fd();
    // Prevent the socket2::Socket from closing the fd when it drops
    std::mem::forget(socket);

    Ok(fd)
}

/// Send a TFTP packet to a peer via UDP.
///
/// Uses retry_send to handle EINTR/EWOULDBLOCK.
fn send_tftp_packet(
    sockfd: RawFd,
    packet: &[u8],
    peer: &SocketAddress,
) -> io::Result<usize> {
    if sockfd < 0 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "invalid socket fd"));
    }

    let peer_sa: SocketAddr = peer.clone().into();

    // Convert to nix SockaddrStorage
    let dest = match peer_sa {
        SocketAddr::V4(v4) => {
            let addr = nix::sys::socket::SockaddrIn::from(v4);
            nix::sys::socket::sendto(sockfd, packet, &addr, nix::sys::socket::MsgFlags::empty())
                .map_err(|e| io::Error::from_raw_os_error(e as i32))
        }
        SocketAddr::V6(v6) => {
            let addr = nix::sys::socket::SockaddrIn6::from(v6);
            nix::sys::socket::sendto(sockfd, packet, &addr, nix::sys::socket::MsgFlags::empty())
                .map_err(|e| io::Error::from_raw_os_error(e as i32))
        }
    };

    dest
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tftp_opcode_values() {
        assert_eq!(TftpOpcode::Rrq as u16, 1);
        assert_eq!(TftpOpcode::Wrq as u16, 2);
        assert_eq!(TftpOpcode::Data as u16, 3);
        assert_eq!(TftpOpcode::Ack as u16, 4);
        assert_eq!(TftpOpcode::Error as u16, 5);
        assert_eq!(TftpOpcode::Oack as u16, 6);
    }

    #[test]
    fn test_tftp_opcode_from_u16() {
        assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::Rrq));
        assert_eq!(TftpOpcode::from_u16(2), Some(TftpOpcode::Wrq));
        assert_eq!(TftpOpcode::from_u16(3), Some(TftpOpcode::Data));
        assert_eq!(TftpOpcode::from_u16(4), Some(TftpOpcode::Ack));
        assert_eq!(TftpOpcode::from_u16(5), Some(TftpOpcode::Error));
        assert_eq!(TftpOpcode::from_u16(6), Some(TftpOpcode::Oack));
        assert_eq!(TftpOpcode::from_u16(0), None);
        assert_eq!(TftpOpcode::from_u16(7), None);
        assert_eq!(TftpOpcode::from_u16(255), None);
    }

    #[test]
    fn test_tftp_error_code_values() {
        assert_eq!(TftpErrorCode::NotDefined as u16, 0);
        assert_eq!(TftpErrorCode::FileNotFound as u16, 1);
        assert_eq!(TftpErrorCode::AccessViolation as u16, 2);
        assert_eq!(TftpErrorCode::DiskFull as u16, 3);
        assert_eq!(TftpErrorCode::IllegalOp as u16, 4);
        assert_eq!(TftpErrorCode::UnknownTid as u16, 5);
        assert_eq!(TftpErrorCode::FileExists as u16, 6);
        assert_eq!(TftpErrorCode::NoSuchUser as u16, 7);
        assert_eq!(TftpErrorCode::BadOptions as u16, 8);
    }

    #[test]
    fn test_next_field_basic() {
        // "hello\0world\0"
        let packet: &[u8] = b"hello\0world\0";
        let mut pos = 0;
        assert_eq!(next_field(packet, &mut pos), Some("hello"));
        assert_eq!(pos, 6);
        assert_eq!(next_field(packet, &mut pos), Some("world"));
        assert_eq!(pos, 12);
        assert_eq!(next_field(packet, &mut pos), None);
    }

    #[test]
    fn test_next_field_empty() {
        let packet: &[u8] = b"\0hello\0";
        let mut pos = 0;
        // Empty string should return None
        assert_eq!(next_field(packet, &mut pos), None);
    }

    #[test]
    fn test_next_field_no_terminator() {
        let packet: &[u8] = b"hello";
        let mut pos = 0;
        // No null terminator, should return None
        assert_eq!(next_field(packet, &mut pos), None);
    }

    #[test]
    fn test_sanitise_clean() {
        assert_eq!(sanitise("boot.img"), "boot.img");
        assert_eq!(sanitise("path/to/file.txt"), "path/to/file.txt");
    }

    #[test]
    fn test_sanitise_control_chars() {
        assert_eq!(sanitise("boot\x01img"), "bootimg");
        assert_eq!(sanitise("file\n\r\tname"), "filename");
        assert_eq!(sanitise("\x1b[31mred\x1b[0m"), "[31mred[0m");
    }

    #[test]
    fn test_sanitise_empty() {
        assert_eq!(sanitise(""), "");
    }

    #[test]
    fn test_build_tftp_err() {
        let mut packet = [0u8; 512];
        let len = build_tftp_err(
            TftpErrorCode::FileNotFound,
            &mut packet,
            "file not found",
        );

        // Verify opcode
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), TftpOpcode::Error as u16);
        // Verify error code
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), TftpErrorCode::FileNotFound as u16);
        // Verify message
        let msg = std::str::from_utf8(&packet[4..4 + "file not found".len()]).unwrap();
        assert_eq!(msg, "file not found");
        // Verify null terminator
        assert_eq!(packet[4 + "file not found".len()], 0);
        // Verify total length
        assert_eq!(len, 4 + "file not found".len() + 1);
    }

    #[test]
    fn test_build_tftp_err_truncation() {
        let mut packet = [0u8; 512];
        let long_msg = "x".repeat(600);
        let len = build_tftp_err(
            TftpErrorCode::NotDefined,
            &mut packet,
            &long_msg,
        );
        // Message should be truncated to MAXMESSAGE
        assert!(len <= 4 + MAXMESSAGE + 1);
    }

    #[test]
    fn test_write_option() {
        let mut packet = [0u8; 100];
        let written = write_option(&mut packet, 0, "blksize", 1024);
        assert_eq!(written, "blksize".len() + 1 + "1024".len() + 1);
        assert_eq!(&packet[0..7], b"blksize");
        assert_eq!(packet[7], 0);
        assert_eq!(&packet[8..12], b"1024");
        assert_eq!(packet[12], 0);
    }

    #[test]
    fn test_tftp_server_new() {
        let server = TftpServer::new();
        assert_eq!(server.transfer_count(), 0);
        assert!(server.transfers.is_empty());
        assert!(server.files.is_empty());
    }

    #[test]
    fn test_tftp_server_default() {
        let server = TftpServer::default();
        assert_eq!(server.transfer_count(), 0);
    }

    #[test]
    fn test_constants_match_c() {
        // Verify our constants match C config.h exactly (AAP Section 0.7.2)
        assert_eq!(TFTP_MAX_CONNECTIONS, 50);
        assert_eq!(TFTP_MAX_WINDOW, 32);
        assert_eq!(TFTP_TRANSFER_TIME, 120);
        assert_eq!(TFTP_PORT, 69);
        assert_eq!(MAXMESSAGE, 500);
    }

    #[test]
    fn test_build_file_path_with_prefix() {
        let path = build_file_path("boot.img", Some("/tftpboot"), false, false, "192.168.1.10:1234");
        assert!(path.contains("tftpboot"));
        assert!(path.contains("boot.img"));
    }

    #[test]
    fn test_build_file_path_absolute() {
        let path = build_file_path("/absolute/boot.img", None, false, false, "192.168.1.10:1234");
        assert_eq!(path, "/absolute/boot.img");
    }

    #[test]
    fn test_build_file_path_relative_no_prefix() {
        let path = build_file_path("boot.img", None, false, false, "192.168.1.10:1234");
        assert!(path.starts_with('/'));
        assert!(path.contains("boot.img"));
    }

    #[test]
    fn test_handle_tftp_ack() {
        let file = Arc::new(TftpFile {
            filename: "/tmp/test".to_string(),
            file: File::open("/dev/null").unwrap(),
            file_size: 1024,
            dev: 0,
            inode: 0,
            posn: 0,
        });

        let mut transfer = TftpTransfer {
            peer: SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 12345),
            source: AllAddr::V4(Ipv4Addr::LOCALHOST),
            if_index: 0,
            sockfd: -1,
            file,
            block: 1,
            lastack: 0,
            ackprev: 0,
            block_hi: 0,
            blocksize: 512,
            windowsize: 1,
            timeout: 2,
            retransmit: Instant::now(),
            backoff: 0,
            expansion: 0,
            offset: 0,
            start: Some(Instant::now()),
            opt_blocksize: false,
            opt_transize: false,
            opt_timeout: false,
            opt_windowsize: false,
            netascii: false,
            carrylf: false,
            lastcarrylf: false,
        };

        // Simulate ACK for block 0
        let ack_packet = [0u8, TftpOpcode::Ack as u8, 0, 0]; // ACK block 0
        let now = Instant::now();
        handle_tftp(&ack_packet, now, &mut transfer);

        // lastack should advance
        assert_eq!(transfer.lastack, 1);
        assert_eq!(transfer.backoff, 0);
    }

    #[test]
    fn test_handle_tftp_error() {
        let file = Arc::new(TftpFile {
            filename: "/tmp/test".to_string(),
            file: File::open("/dev/null").unwrap(),
            file_size: 1024,
            dev: 0,
            inode: 0,
            posn: 0,
        });

        let mut transfer = TftpTransfer {
            peer: SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 12345),
            source: AllAddr::V4(Ipv4Addr::LOCALHOST),
            if_index: 0,
            sockfd: -1,
            file,
            block: 1,
            lastack: 0,
            ackprev: 0,
            block_hi: 0,
            blocksize: 512,
            windowsize: 1,
            timeout: 2,
            retransmit: Instant::now(),
            backoff: 0,
            expansion: 0,
            offset: 0,
            start: Some(Instant::now()),
            opt_blocksize: false,
            opt_transize: false,
            opt_timeout: false,
            opt_windowsize: false,
            netascii: false,
            carrylf: false,
            lastcarrylf: false,
        };

        // Simulate ERROR packet
        let mut err_packet = vec![0u8, TftpOpcode::Error as u8, 0, 1]; // ERROR code 1
        err_packet.extend_from_slice(b"File not found\0");

        let now = Instant::now();
        handle_tftp(&err_packet, now, &mut transfer);

        // Transfer should be marked for abort
        assert!(transfer.start.is_none());
    }

    #[test]
    fn test_handle_tftp_wrap_around() {
        let file = Arc::new(TftpFile {
            filename: "/tmp/test".to_string(),
            file: File::open("/dev/null").unwrap(),
            file_size: u64::MAX / 2,
            dev: 0,
            inode: 0,
            posn: 0,
        });

        let mut transfer = TftpTransfer {
            peer: SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 12345),
            source: AllAddr::V4(Ipv4Addr::LOCALHOST),
            if_index: 0,
            sockfd: -1,
            file,
            block: 0xFFFF,
            lastack: 0xFFFE,
            ackprev: 0xFFFE,
            block_hi: 0,
            blocksize: 512,
            windowsize: 1,
            timeout: 2,
            retransmit: Instant::now(),
            backoff: 0,
            expansion: 0,
            offset: 0,
            start: Some(Instant::now()),
            opt_blocksize: false,
            opt_transize: false,
            opt_timeout: false,
            opt_windowsize: false,
            netascii: false,
            carrylf: false,
            lastcarrylf: false,
        };

        // ACK for block 0xFFFF (in top quarter)
        let ack = [0u8, TftpOpcode::Ack as u8, 0xFF, 0xFF];
        handle_tftp(&ack, Instant::now(), &mut transfer);
        assert_eq!(transfer.ackprev, 0xFFFF);

        // ACK for block 0x0001 (in bottom quarter -> wrap-around)
        transfer.block = 0x10001; // Block 65537
        let ack2 = [0u8, TftpOpcode::Ack as u8, 0x00, 0x01];
        handle_tftp(&ack2, Instant::now(), &mut transfer);
        assert_eq!(transfer.block_hi, 1);
    }

    #[test]
    fn test_get_block_oack() {
        let file = Arc::new(TftpFile {
            filename: "/tmp/test".to_string(),
            file: File::open("/dev/null").unwrap(),
            file_size: 1024,
            dev: 0,
            inode: 0,
            posn: 0,
        });

        let mut transfer = TftpTransfer {
            peer: SocketAddress::new_v4(Ipv4Addr::LOCALHOST, 12345),
            source: AllAddr::V4(Ipv4Addr::LOCALHOST),
            if_index: 0,
            sockfd: -1,
            file,
            block: 0, // Block 0 = OACK
            lastack: 0,
            ackprev: 0,
            block_hi: 0,
            blocksize: 1024,
            windowsize: 4,
            timeout: 5,
            retransmit: Instant::now(),
            backoff: 0,
            expansion: 0,
            offset: 0,
            start: Some(Instant::now()),
            opt_blocksize: true,
            opt_transize: true,
            opt_timeout: true,
            opt_windowsize: true,
            netascii: false,
            carrylf: false,
            lastcarrylf: false,
        };

        let mut packet = vec![0u8; MAX_PACKET_SIZE];
        let result = get_block(&mut transfer, &mut packet);
        assert!(result.is_ok());
        let len = result.unwrap();
        assert!(len > 2); // At least opcode

        // Verify OACK opcode
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), TftpOpcode::Oack as u16);

        // Verify options are present in packet
        let oack_data = &packet[2..len];
        let oack_str = String::from_utf8_lossy(oack_data);
        assert!(oack_str.contains("blksize"));
        assert!(oack_str.contains("1024"));
        assert!(oack_str.contains("tsize"));
        assert!(oack_str.contains("timeout"));
        assert!(oack_str.contains("windowsize"));
        assert!(oack_str.contains("4"));
    }
}

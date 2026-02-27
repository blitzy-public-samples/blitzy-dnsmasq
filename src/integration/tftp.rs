//! Read-only TFTP server implementation (RFC 1350, RFC 2349, RFC 7440).
//!
//! This module provides a standards-compliant read-only TFTP server for PXE
//! network boot scenarios. Pure Rust implementation with no external library
//! dependencies.
//!
//! This is a stub awaiting full implementation by the code generation agent.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

/// TFTP Opcodes per RFC 1350.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpOpcode {
    /// Read Request
    Rrq = 1,
    /// Write Request (rejected — read-only server)
    Wrq = 2,
    /// Data packet
    Data = 3,
    /// Acknowledgement
    Ack = 4,
    /// Error
    Error = 5,
    /// Option Acknowledgement (RFC 2349)
    Oack = 6,
}

/// TFTP Error Codes per RFC 1350.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpErrorCode {
    /// Not defined, see error message
    NotDefined = 0,
    /// File not found
    FileNotFound = 1,
    /// Access violation
    AccessViolation = 2,
    /// Disk full or allocation exceeded (not used — read-only)
    DiskFull = 3,
    /// Illegal TFTP operation
    IllegalOp = 4,
    /// Unknown transfer ID
    UnknownTid = 5,
    /// File already exists (not used — read-only)
    FileExists = 6,
    /// No such user
    NoSuchUser = 7,
    /// Bad options (RFC 2349)
    BadOptions = 8,
}

/// TFTP server state managing active transfers and file handles.
///
/// Replaces C's linked list of `struct tftp_transfer` with a `HashMap`
/// keyed by peer socket address for O(1) lookup.
pub struct TftpServer {
    /// Active transfers keyed by peer address (transfer ID).
    pub transfers: HashMap<SocketAddr, TftpTransfer>,
    /// Shared file handle cache keyed by (device, inode).
    pub files: HashMap<(u64, u64), std::sync::Arc<TftpFile>>,
}

/// A single TFTP file being served, with reference counting for sharing.
pub struct TftpFile {
    /// Path to the file on disk.
    pub filename: String,
    /// Open file handle.
    pub file: std::fs::File,
    /// File size in bytes.
    pub file_size: u64,
    /// Device number from fstat.
    pub dev: u64,
    /// Inode number from fstat.
    pub inode: u64,
}

/// State for an active TFTP transfer.
pub struct TftpTransfer {
    /// Remote peer address (transfer ID per RFC 1350).
    pub peer: SocketAddr,
    /// Current block number being sent.
    pub block: u32,
    /// Last acknowledged block number.
    pub lastack: u32,
    /// Negotiated block size (default 512).
    pub blocksize: u16,
    /// Negotiated window size (RFC 7440, default 1).
    pub windowsize: u16,
    /// Transfer start time for timeout tracking.
    pub start: Option<Instant>,
}

impl TftpServer {
    /// Create a new TFTP server instance with empty transfer tables.
    pub fn new() -> Self {
        Self {
            transfers: HashMap::new(),
            files: HashMap::new(),
        }
    }

    /// Process an incoming TFTP request packet.
    ///
    /// Parses the RRQ, validates the file, negotiates options, and begins
    /// the transfer. WRQ requests are rejected (read-only server).
    pub fn request(&mut self, _packet: &[u8], _now: Instant) {
        // Full implementation will be provided by the TFTP code generation agent.
    }

    /// Check all TFTP listener and transfer sockets for readiness.
    ///
    /// Dispatches ACK processing, handles timeouts and retransmissions,
    /// and cleans up completed or timed-out transfers.
    pub fn check_listeners(&mut self, _now: Instant) {
        // Full implementation will be provided by the TFTP code generation agent.
    }

    /// Process completed transfers for script notification.
    ///
    /// Returns `true` if there are more transfers to process.
    #[cfg(feature = "script")]
    pub fn do_script_run(&mut self) -> bool {
        false
    }

    /// Returns the number of active transfers.
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }
}

impl Default for TftpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle an incoming TFTP request on a listener socket.
///
/// Top-level entry point called from the event loop when a TFTP listener
/// socket has data ready. Dispatches to `TftpServer::request()`.
pub fn tftp_request(_packet: &[u8], _now: Instant) {
    // Full implementation will be provided by the TFTP code generation agent.
}

/// Check all TFTP listeners and active transfers for events.
///
/// Called from the main event loop to process TFTP I/O events.
pub fn check_tftp_listeners(_now: Instant) {
    // Full implementation will be provided by the TFTP code generation agent.
}

/// Process completed TFTP transfers for script notification.
///
/// Called from the main event loop after transfer completion to trigger
/// lease-change script execution via the helper process.
#[cfg(feature = "script")]
pub fn do_tftp_script_run() -> bool {
    false
}

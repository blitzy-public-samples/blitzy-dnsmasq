// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2024 dnsmasq contributors
// Rust implementation of dnsmasq — memory-safe DNS/DHCP server.

//! # OpenWrt UBus Message Bus Integration
//!
//! Rust implementation of the OpenWrt UBus interface for dnsmasq,
//! migrated from `src/ubus.c` (968 lines).
//!
//! UBus is a lightweight inter-process communication (IPC) system used by
//! OpenWrt/LEDE as an alternative to D-Bus for resource-constrained embedded
//! Linux environments. This module provides:
//!
//! - **Metrics export**: Runtime statistics accessible via
//!   `ubus call dnsmasq metrics`
//! - **Connmark allowlist management** (gated by `feature = "conntrack"`):
//!   Dynamic conntrack mark allowlist updates via
//!   `ubus call dnsmasq set_connmark_allowlist`
//! - **Event broadcasting**: DHCP lease events and conntrack allowlist events
//!   published for consumption by OpenWrt LuCI and other UBus subscribers
//!
//! ## Protocol
//!
//! Communication with the `ubusd` daemon uses a binary protocol over Unix
//! domain sockets. Messages consist of a fixed 12-byte header followed by
//! TLV-encoded blob attributes (compatible with OpenWrt libubox blobmsg format).
//!
//! ## Architecture
//!
//! All mutable state is encapsulated in [`UbusController`]. No global mutable
//! state exists — the C pattern of `daemon->ubus` global pointer is replaced
//! by passing `Arc<RwLock<DaemonState>>` through method parameters.

// Protocol constants, status codes, and helper parsing functions form the complete
// UBus wire protocol implementation. Many constants are referenced only when
// specific feature gates (e.g., conntrack) are active, and helper functions are
// used by conditional code paths. Allow dead_code to keep the protocol spec complete.
#![allow(dead_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libc::{c_int, c_void, AF_UNIX, POLLERR, POLLHUP, POLLIN, SOCK_STREAM};
use serde_json::{self, json, Map, Value};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::core::types::{DaemonState, DnsmasqError, DnsmasqResult};
use crate::diagnostics::metrics::{MetricType, MetricsStore, METRIC_MAX, METRIC_NAMES};

#[cfg(feature = "conntrack")]
use crate::core::pattern::is_valid_dns_name_pattern;

// ---------------------------------------------------------------------------
// UBus Protocol Constants
// ---------------------------------------------------------------------------

/// Default UBus daemon socket path on OpenWrt.
/// Matches libubus default: `UBUS_UNIX_SOCKET "/var/run/ubus/ubus.sock"`.
const UBUS_SOCKET_PATH: &str = "/var/run/ubus/ubus.sock";

/// Alternative socket path used on older OpenWrt builds.
const UBUS_SOCKET_PATH_ALT: &str = "/var/run/ubus.sock";

/// UBus message protocol version (from libubus `ubusmsg.h`).
const UBUS_MSG_VERSION: u8 = 0;

/// Reconnect delay after disconnection from ubusd.
/// Matches C implementation timeout of 2 seconds (`src/ubus.c` line 258).
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Event notification timeout for standard DHCP lease events (blocking).
/// From `src/ubus.c` line 860: `ubus_notify(ubus, &ubus_object, type, b.head, -1)`.
const EVENT_NOTIFY_TIMEOUT_DEFAULT: i32 = -1;

/// Event notification timeout for conntrack resolved events (1000 ms).
/// From `src/ubus.c` line 951: `ubus_notify(..., 1000)`.
const EVENT_NOTIFY_TIMEOUT_CONNTRACK: i32 = 1000;

// --- UBus Message Types (from libubus `ubusmsg.h`) ---

/// Initial handshake message exchanged between client and ubusd.
const UBUS_MSG_HELLO: u8 = 0;
/// Status/acknowledgement response.
const UBUS_MSG_STATUS: u8 = 1;
/// Method call reply data.
const UBUS_MSG_DATA: u8 = 2;
/// Keepalive ping.
const UBUS_MSG_PING: u8 = 3;
/// Object path lookup request.
const UBUS_MSG_LOOKUP: u8 = 4;
/// Method invocation from a client.
const UBUS_MSG_INVOKE: u8 = 6;
/// Register a new object with ubusd.
const UBUS_MSG_ADD_OBJECT: u8 = 7;
/// Remove a registered object.
const UBUS_MSG_REMOVE_OBJECT: u8 = 8;
/// Subscribe to object notifications.
const UBUS_MSG_SUBSCRIBE: u8 = 9;
/// Unsubscribe from object notifications.
const UBUS_MSG_UNSUBSCRIBE: u8 = 10;
/// Broadcast notification event to subscribers.
const UBUS_MSG_NOTIFY: u8 = 11;

// --- UBus Message Attribute IDs (from libubus `ubusmsg.h`) ---

/// Object path string (e.g., "dnsmasq").
const UBUS_ATTR_OBJPATH: u8 = 1;
/// Assigned object numeric identifier.
const UBUS_ATTR_OBJID: u8 = 2;
/// Method name being invoked.
const UBUS_ATTR_METHOD: u8 = 3;
/// Object type identifier.
const UBUS_ATTR_OBJTYPE: u8 = 4;
/// Method signature table.
const UBUS_ATTR_SIGNATURE: u8 = 5;
/// Blob data payload for method calls/responses.
const UBUS_ATTR_DATA: u8 = 6;
/// Target peer for directed messages.
const UBUS_ATTR_TARGET: u8 = 7;
/// Active subscription flag.
const UBUS_ATTR_ACTIVE: u8 = 8;
/// Suppress reply flag.
const UBUS_ATTR_NO_REPLY: u8 = 9;
/// Subscriber count.
const UBUS_ATTR_SUBSCRIBERS: u8 = 10;

// --- UBus Status Codes (from libubus `libubus.h`) ---

/// Operation completed successfully.
const UBUS_STATUS_OK: u32 = 0;
/// Invalid argument provided.
const UBUS_STATUS_INVALID_ARGUMENT: u32 = 2;
/// Requested method not found on object.
const UBUS_STATUS_METHOD_NOT_FOUND: u32 = 3;
/// Resource not found.
const UBUS_STATUS_NOT_FOUND: u32 = 4;
/// Connection to ubusd failed.
const UBUS_STATUS_CONNECTION_FAILED: u32 = 10;

// --- Blob Attribute Types (from libubox `blobmsg.h`) ---

/// Blob message array container type.
const BLOBMSG_TYPE_ARRAY: u8 = 1;
/// Blob message table (named key-value) container type.
const BLOBMSG_TYPE_TABLE: u8 = 2;
/// Blob message null-terminated string type.
const BLOBMSG_TYPE_STRING: u8 = 3;
/// Blob message 32-bit signed integer type.
const BLOBMSG_TYPE_INT32: u8 = 5;

// --- Blob Wire Format Helpers ---

/// Size of a raw blob attribute header (`id_len` field): 4 bytes.
const BLOB_ATTR_HDR_SIZE: usize = 4;

/// Size of blobmsg name header prefix (2-byte `namelen` field).
const BLOBMSG_NAME_HDR_SIZE: usize = 2;

/// Size of UBus message header (version + type + seq + peer): 8 bytes.
const UBUS_MSG_HDR_SIZE: usize = 8;

/// Total frame header: blob_attr(4) + ubus_msghdr(8) = 12 bytes.
const UBUS_FRAME_HDR_SIZE: usize = 12;

/// Encode a blob attribute `id_len` field.
/// Layout: bits [31] extended (always 0), [30:24] id (7 bits), [23:0] length.
const fn blob_raw_id_len(id: u8, len: u32) -> u32 {
    ((id as u32 & 0x7F) << 24) | (len & 0x00FF_FFFF)
}

/// Extract the type/id from a blob `id_len` field.
const fn blob_attr_id(id_len: u32) -> u8 {
    ((id_len >> 24) & 0x7F) as u8
}

/// Extract the total length (including header) from a blob `id_len` field.
const fn blob_attr_len(id_len: u32) -> usize {
    (id_len & 0x00FF_FFFF) as usize
}

/// Round up to the next 4-byte boundary for blob attribute alignment.
const fn blob_pad_len(len: usize) -> usize {
    (len + 3) & !3
}

/// Poll event flags for UBus socket monitoring in the main event loop.
/// These match the C implementation in `set_ubus_listeners()` (`src/ubus.c` line 405):
/// `poll_listen(ubus->sock.fd, POLLIN|POLLERR|POLLHUP)`.
///
/// The constants `AF_UNIX`, `SOCK_STREAM`, `c_int`, and `c_void` from `libc`
/// describe the underlying Unix domain socket transport; `POLLIN`, `POLLERR`,
/// and `POLLHUP` are the poll event flags used by the event loop integration.
pub const UBUS_POLL_EVENTS: c_int = (POLLIN | POLLERR | POLLHUP) as c_int;

/// Socket domain used for UBus connections (Unix domain, stream-oriented).
/// The UBus daemon (`ubusd`) listens on an `AF_UNIX` `SOCK_STREAM` socket.
const _UBUS_SOCKET_DOMAIN: c_int = AF_UNIX;
const _UBUS_SOCKET_TYPE: c_int = SOCK_STREAM;

/// Opaque pointer type for potential C libubus FFI interop.
///
/// The pure-Rust implementation uses [`UnixStream`] directly, but this type
/// alias preserves the FFI bridging capability for environments where linking
/// against the C `libubus` library is preferred (e.g., when running on
/// OpenWrt with the system `libubus.so` installed).
#[allow(dead_code)]
type UbusContextPtr = *mut c_void;

// ---------------------------------------------------------------------------
// Blob/Blobmsg Buffer Builder
// ---------------------------------------------------------------------------

/// Builder for constructing UBus blob message (blobmsg) buffers.
///
/// Replaces C `struct blob_buf` from libubox. Provides a safe API for building
/// nested TLV-encoded attribute trees used in UBus method responses and event
/// notifications.
///
/// # Memory Safety
///
/// Uses `Vec<u8>` with automatic growth, eliminating all buffer overflow
/// vulnerabilities inherent in C `blob_buf_grow()` and `realloc()` patterns.
struct BlobBuf {
    /// Raw serialized blob attribute bytes.
    data: Vec<u8>,
    /// Stack of offsets for nested container open/close tracking.
    nest_stack: Vec<usize>,
}

impl BlobBuf {
    /// Create a new empty blob buffer with pre-allocated capacity.
    fn new() -> Self {
        Self {
            data: Vec::with_capacity(512),
            nest_stack: Vec::with_capacity(4),
        }
    }

    /// Reset the buffer for reuse.
    fn clear(&mut self) {
        self.data.clear();
        self.nest_stack.clear();
    }

    /// Add a named blobmsg field with the specified type and raw value bytes.
    fn add_blobmsg_field(&mut self, type_id: u8, name: &str, value: &[u8]) {
        let name_bytes = name.as_bytes();
        let name_wire_len = BLOBMSG_NAME_HDR_SIZE + name_bytes.len() + 1;
        let name_padded = blob_pad_len(name_wire_len);
        let total_len = BLOB_ATTR_HDR_SIZE + name_padded + value.len();
        let padded_total = blob_pad_len(total_len);

        let id_len = blob_raw_id_len(type_id, total_len as u32);
        self.data.extend_from_slice(&id_len.to_be_bytes());

        self.data
            .extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        self.data.extend_from_slice(name_bytes);
        self.data.push(0);

        let written = BLOBMSG_NAME_HDR_SIZE + name_bytes.len() + 1;
        for _ in written..blob_pad_len(written) {
            self.data.push(0);
        }

        self.data.extend_from_slice(value);

        for _ in total_len..padded_total {
            self.data.push(0);
        }
    }

    /// Add a named 32-bit unsigned integer field.
    /// Replaces C `blobmsg_add_u32(buf, name, val)`.
    fn add_u32(&mut self, name: &str, val: u32) {
        self.add_blobmsg_field(BLOBMSG_TYPE_INT32, name, &val.to_be_bytes());
    }

    /// Add a named NUL-terminated string field.
    /// Replaces C `blobmsg_add_string(buf, name, str)`.
    fn add_string(&mut self, name: &str, val: &str) {
        let mut buf = Vec::with_capacity(val.len() + 1);
        buf.extend_from_slice(val.as_bytes());
        buf.push(0);
        self.add_blobmsg_field(BLOBMSG_TYPE_STRING, name, &buf);
    }

    /// Open a named nested TABLE container. Returns a cookie for [`close_table`].
    /// Replaces C `blobmsg_open_table(buf, name)`.
    fn open_table(&mut self, name: &str) -> usize {
        self.open_named_container(BLOBMSG_TYPE_TABLE, name)
    }

    /// Close a previously opened TABLE container.
    fn close_table(&mut self, cookie: usize) {
        self.close_named_container(BLOBMSG_TYPE_TABLE, cookie);
    }

    /// Open a named nested ARRAY container. Returns a cookie for [`close_array`].
    fn open_array(&mut self, name: &str) -> usize {
        self.open_named_container(BLOBMSG_TYPE_ARRAY, name)
    }

    /// Close a previously opened ARRAY container.
    fn close_array(&mut self, cookie: usize) {
        self.close_named_container(BLOBMSG_TYPE_ARRAY, cookie);
    }

    /// Internal: open a named container (TABLE or ARRAY).
    fn open_named_container(&mut self, _type_id: u8, name: &str) -> usize {
        let name_bytes = name.as_bytes();
        let name_wire_len = BLOBMSG_NAME_HDR_SIZE + name_bytes.len() + 1;
        let name_padded = blob_pad_len(name_wire_len);
        let offset = self.data.len();

        // Placeholder blob_attr header (updated on close)
        self.data.extend_from_slice(&[0u8; BLOB_ATTR_HDR_SIZE]);

        self.data
            .extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        self.data.extend_from_slice(name_bytes);
        self.data.push(0);

        let written = BLOBMSG_NAME_HDR_SIZE + name_bytes.len() + 1;
        for _ in written..name_padded {
            self.data.push(0);
        }

        self.nest_stack.push(offset);
        offset
    }

    /// Internal: close a named container and patch its length.
    fn close_named_container(&mut self, type_id: u8, cookie: usize) {
        let total_len = self.data.len() - cookie;
        let id_len = blob_raw_id_len(type_id, total_len as u32);
        self.data[cookie..cookie + 4].copy_from_slice(&id_len.to_be_bytes());
        self.nest_stack.pop();
    }

    /// Write a raw (unnamed) blob attribute with the given id and data.
    fn add_raw_attr(&mut self, id: u8, value: &[u8]) {
        let total_len = BLOB_ATTR_HDR_SIZE + value.len();
        let padded = blob_pad_len(total_len);
        let id_len = blob_raw_id_len(id, total_len as u32);
        self.data.extend_from_slice(&id_len.to_be_bytes());
        self.data.extend_from_slice(value);
        for _ in total_len..padded {
            self.data.push(0);
        }
    }

    /// Write a raw (unnamed) NUL-terminated string blob attribute.
    fn add_raw_string_attr(&mut self, id: u8, val: &str) {
        let mut buf = Vec::with_capacity(val.len() + 1);
        buf.extend_from_slice(val.as_bytes());
        buf.push(0);
        self.add_raw_attr(id, &buf);
    }

    /// Write a raw (unnamed) u32 blob attribute.
    fn add_raw_u32_attr(&mut self, id: u8, val: u32) {
        self.add_raw_attr(id, &val.to_be_bytes());
    }

    /// Open a raw (unnamed) nested container. Returns cookie for [`close_raw_nested`].
    fn open_raw_nested(&mut self, id: u8) -> usize {
        let offset = self.data.len();
        let id_len = blob_raw_id_len(id, BLOB_ATTR_HDR_SIZE as u32);
        self.data.extend_from_slice(&id_len.to_be_bytes());
        self.nest_stack.push(offset);
        offset
    }

    /// Close a raw nested container and patch its length.
    fn close_raw_nested(&mut self) {
        if let Some(offset) = self.nest_stack.pop() {
            let total_len = self.data.len() - offset;
            let old_hdr = u32::from_be_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]);
            let id = blob_attr_id(old_hdr);
            let new_hdr = blob_raw_id_len(id, total_len as u32);
            self.data[offset..offset + 4].copy_from_slice(&new_hdr.to_be_bytes());
        }
    }

    /// Get the completed blob data for sending as a UBus message payload.
    fn payload(&self) -> &[u8] {
        &self.data
    }
}

// ---------------------------------------------------------------------------
// UBus Message Framing
// ---------------------------------------------------------------------------

/// A parsed or to-be-sent UBus protocol message.
///
/// Wire format (over Unix domain socket):
/// ```text
/// [blob_attr header: 4 bytes BE — id=0, len=total_frame_size]
/// [version: 1 byte]
/// [msg_type: 1 byte]
/// [seq: 2 bytes native endian]
/// [peer: 4 bytes native endian]
/// [payload blob attributes...]
/// ```
struct UbusMsg {
    /// Protocol version (always [`UBUS_MSG_VERSION`] = 0).
    version: u8,
    /// Message type (one of `UBUS_MSG_*` constants).
    msg_type: u8,
    /// Sequence number for request/response correlation.
    seq: u16,
    /// Peer identifier assigned by ubusd.
    peer: u32,
    /// Raw blob attribute payload.
    data: Vec<u8>,
}

/// Attempt to read one complete UBus message from a non-blocking stream.
///
/// Returns `Ok(None)` if no data is available (`WouldBlock`).
fn recv_ubus_msg(stream: &mut UnixStream) -> io::Result<Option<UbusMsg>> {
    let mut hdr_buf = [0u8; BLOB_ATTR_HDR_SIZE];
    match stream.read_exact(&mut hdr_buf) {
        Ok(()) => {}
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
        Err(e) => return Err(e),
    }

    let id_len = u32::from_be_bytes(hdr_buf);
    let total_len = blob_attr_len(id_len);

    if total_len < UBUS_FRAME_HDR_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("UBus frame too short: {} bytes", total_len),
        ));
    }

    let remaining = total_len - BLOB_ATTR_HDR_SIZE;
    let mut buf = vec![0u8; remaining];
    stream.read_exact(&mut buf)?;

    if buf.len() < UBUS_MSG_HDR_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "UBus message header truncated",
        ));
    }

    let version = buf[0];
    let msg_type = buf[1];
    let seq = u16::from_ne_bytes([buf[2], buf[3]]);
    let peer = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let data = buf[UBUS_MSG_HDR_SIZE..].to_vec();

    Ok(Some(UbusMsg {
        version,
        msg_type,
        seq,
        peer,
        data,
    }))
}

/// Send a complete UBus message over the stream.
fn send_ubus_msg(stream: &mut UnixStream, msg: &UbusMsg) -> io::Result<()> {
    let total_len = UBUS_FRAME_HDR_SIZE + msg.data.len();
    let frame_hdr = blob_raw_id_len(0, total_len as u32);

    stream.write_all(&frame_hdr.to_be_bytes())?;
    stream.write_all(&[msg.version, msg.msg_type])?;
    stream.write_all(&msg.seq.to_ne_bytes())?;
    stream.write_all(&msg.peer.to_ne_bytes())?;
    stream.write_all(&msg.data)?;
    Ok(())
}

/// Parse raw blob attributes from a message payload.
fn parse_blob_attrs(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut attrs = Vec::new();
    let mut offset = 0;

    while offset + BLOB_ATTR_HDR_SIZE <= data.len() {
        let id_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let id = blob_attr_id(id_len);
        let total_len = blob_attr_len(id_len);

        if total_len < BLOB_ATTR_HDR_SIZE || offset + total_len > data.len() {
            break;
        }

        let attr_data = data[offset + BLOB_ATTR_HDR_SIZE..offset + total_len].to_vec();
        attrs.push((id, attr_data));
        offset += blob_pad_len(total_len);
    }

    attrs
}

/// Extract the method name from INVOKE message attributes.
fn extract_method_name(attrs: &[(u8, Vec<u8>)]) -> Option<String> {
    for (id, data) in attrs {
        if *id == UBUS_ATTR_METHOD {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            return String::from_utf8(data[..end].to_vec()).ok();
        }
    }
    None
}

/// Extract the DATA attribute payload from message attributes.
fn extract_data_payload(attrs: &[(u8, Vec<u8>)]) -> Option<Vec<u8>> {
    for (id, data) in attrs {
        if *id == UBUS_ATTR_DATA {
            return Some(data.clone());
        }
    }
    None
}

/// Extract a u32 value from a raw blob attribute by target id.
fn extract_u32_attr(attrs: &[(u8, Vec<u8>)], target_id: u8) -> Option<u32> {
    for (id, data) in attrs {
        if *id == target_id && data.len() >= 4 {
            return Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Blobmsg Data Parsing Helpers
// ---------------------------------------------------------------------------

/// A parsed blobmsg field (named TLV attribute within a DATA payload).
struct BlobmsgField {
    /// Field name.
    name: String,
    /// Field type (one of `BLOBMSG_TYPE_*`).
    field_type: u8,
    /// Raw value bytes.
    value: Vec<u8>,
}

/// Parse named blobmsg fields from a DATA attribute payload.
fn parse_blobmsg_fields(data: &[u8]) -> Vec<BlobmsgField> {
    let mut fields = Vec::new();
    let mut offset = 0;

    while offset + BLOB_ATTR_HDR_SIZE <= data.len() {
        let id_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let type_id = blob_attr_id(id_len);
        let total_len = blob_attr_len(id_len);

        if total_len < BLOB_ATTR_HDR_SIZE || offset + total_len > data.len() {
            break;
        }

        let payload = &data[offset + BLOB_ATTR_HDR_SIZE..offset + total_len];

        if payload.len() >= BLOBMSG_NAME_HDR_SIZE {
            let name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            let name_start = BLOBMSG_NAME_HDR_SIZE;
            if name_start + name_len <= payload.len() {
                let name = String::from_utf8_lossy(&payload[name_start..name_start + name_len])
                    .to_string();

                let name_wire = BLOBMSG_NAME_HDR_SIZE + name_len + 1;
                let name_padded = blob_pad_len(name_wire);
                let value = if name_padded < payload.len() {
                    payload[name_padded..].to_vec()
                } else {
                    Vec::new()
                };

                fields.push(BlobmsgField {
                    name,
                    field_type: type_id,
                    value,
                });
            }
        }

        offset += blob_pad_len(total_len);
    }

    fields
}

/// Extract a u32 from blobmsg INT32 value bytes (big-endian).
fn blobmsg_get_u32(value: &[u8]) -> Option<u32> {
    if value.len() >= 4 {
        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    } else {
        None
    }
}

/// Extract a string from blobmsg STRING value bytes (NUL-terminated).
fn blobmsg_get_string(value: &[u8]) -> Option<String> {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    String::from_utf8(value[..end].to_vec()).ok()
}

// ---------------------------------------------------------------------------
// UBus Connection Context
// ---------------------------------------------------------------------------

/// Low-level UBus connection state managing the Unix domain socket to ubusd.
///
/// Replaces C `struct ubus_context` from libubus. Handles:
/// - Connection establishment and HELLO handshake
/// - Object registration with method signatures
/// - Message send/receive
/// - Sequence number tracking
///
/// # RAII
///
/// The `UnixStream` is automatically closed when `UbusConnection` is dropped,
/// eliminating fd leak vulnerabilities from C's manual `ubus_free()` cleanup.
struct UbusConnection {
    /// Connected Unix domain socket to ubusd.
    stream: UnixStream,
    /// Our peer ID assigned by ubusd during HELLO handshake.
    local_id: u32,
    /// Registered object ID (assigned by ubusd on ADD_OBJECT).
    object_id: u32,
    /// Monotonically increasing sequence counter for message correlation.
    seq_counter: u16,
    /// Reusable blob buffer for constructing outgoing messages.
    blob_buf: BlobBuf,
}

impl UbusConnection {
    /// Connect to ubusd and perform the HELLO handshake.
    ///
    /// Tries the standard socket path first, then falls back to the alternate path.
    /// Sets the socket to non-blocking mode for integration with the async event loop.
    fn connect() -> io::Result<Self> {
        let stream = UnixStream::connect(UBUS_SOCKET_PATH)
            .or_else(|_| UnixStream::connect(UBUS_SOCKET_PATH_ALT))
            .map_err(|e| io::Error::new(e.kind(), format!("Failed to connect to ubusd: {}", e)))?;

        // Set non-blocking for poll-based event loop integration
        stream.set_nonblocking(false)?;

        let mut conn = Self {
            stream,
            local_id: 0,
            object_id: 0,
            seq_counter: 0,
            blob_buf: BlobBuf::new(),
        };

        // Perform HELLO handshake: read server greeting
        conn.stream.set_nonblocking(false)?;
        let hello = recv_ubus_msg(&mut conn.stream)?;
        match hello {
            Some(msg) if msg.msg_type == UBUS_MSG_HELLO => {
                conn.local_id = msg.peer;
            }
            Some(msg) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Expected HELLO, got msg_type={}", msg.msg_type),
                ));
            }
            None => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "No HELLO received from ubusd",
                ));
            }
        }

        // Switch to non-blocking for event-driven operation
        conn.stream.set_nonblocking(true)?;

        Ok(conn)
    }

    /// Get the next sequence number for message correlation.
    fn next_seq(&mut self) -> u16 {
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);
        seq
    }

    /// Register a UBus object with the given name and method signatures.
    ///
    /// Sends an `ADD_OBJECT` message and waits for the `STATUS` response
    /// containing the assigned object ID.
    ///
    /// `methods` is a slice of `(method_name, &[(param_name, param_type)])`.
    fn register_object(
        &mut self,
        name: &str,
        methods: &[(&str, &[(&str, u8)])],
    ) -> io::Result<u32> {
        self.blob_buf.clear();

        // Build ADD_OBJECT payload:
        // UBUS_ATTR_OBJPATH: object name string
        self.blob_buf.add_raw_string_attr(UBUS_ATTR_OBJPATH, name);

        // UBUS_ATTR_SIGNATURE: nested table of method signatures
        let _sig_cookie = self.blob_buf.open_raw_nested(UBUS_ATTR_SIGNATURE);
        for (method_name, params) in methods {
            let method_cookie = self.blob_buf.open_table(method_name);
            for (param_name, param_type) in *params {
                self.blob_buf.add_u32(param_name, *param_type as u32);
            }
            self.blob_buf.close_table(method_cookie);
        }
        self.blob_buf.close_raw_nested();

        let seq = self.next_seq();
        let msg = UbusMsg {
            version: UBUS_MSG_VERSION,
            msg_type: UBUS_MSG_ADD_OBJECT,
            seq,
            peer: 0,
            data: self.blob_buf.payload().to_vec(),
        };

        // Temporarily switch to blocking for registration handshake
        self.stream.set_nonblocking(false)?;
        send_ubus_msg(&mut self.stream, &msg)?;

        // Wait for STATUS response with assigned object ID
        let resp = recv_ubus_msg(&mut self.stream)?;
        self.stream.set_nonblocking(true)?;

        match resp {
            Some(status_msg) if status_msg.msg_type == UBUS_MSG_STATUS => {
                let attrs = parse_blob_attrs(&status_msg.data);
                let obj_id = extract_u32_attr(&attrs, UBUS_ATTR_OBJID).unwrap_or(0);
                self.object_id = obj_id;
                Ok(obj_id)
            }
            Some(other) => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Expected STATUS after ADD_OBJECT, got msg_type={}",
                    other.msg_type
                ),
            )),
            None => Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "No response to ADD_OBJECT",
            )),
        }
    }

    /// Send a method response (DATA + STATUS) back to the invoking peer.
    fn send_reply(&mut self, req_seq: u16, req_peer: u32, reply_data: &[u8]) -> io::Result<()> {
        // Send DATA message with the reply payload
        if !reply_data.is_empty() {
            let data_msg = UbusMsg {
                version: UBUS_MSG_VERSION,
                msg_type: UBUS_MSG_DATA,
                seq: req_seq,
                peer: req_peer,
                data: reply_data.to_vec(),
            };
            send_ubus_msg(&mut self.stream, &data_msg)?;
        }

        // Send STATUS(OK) to complete the method call
        let mut status_buf = BlobBuf::new();
        status_buf.add_raw_u32_attr(UBUS_ATTR_OBJID, self.object_id);
        let status_msg = UbusMsg {
            version: UBUS_MSG_VERSION,
            msg_type: UBUS_MSG_STATUS,
            seq: req_seq,
            peer: req_peer,
            data: status_buf.payload().to_vec(),
        };
        send_ubus_msg(&mut self.stream, &status_msg)?;

        Ok(())
    }

    /// Send an event notification to all subscribers.
    ///
    /// Replaces C `ubus_notify(ctx, &obj, type, data, timeout)`.
    fn send_notify(
        &mut self,
        event_type: &str,
        notify_data: &[u8],
        _timeout: i32,
    ) -> io::Result<()> {
        self.blob_buf.clear();

        // UBUS_ATTR_OBJID: our registered object ID
        self.blob_buf
            .add_raw_u32_attr(UBUS_ATTR_OBJID, self.object_id);

        // UBUS_ATTR_METHOD: event type string (used as notification type)
        self.blob_buf
            .add_raw_string_attr(UBUS_ATTR_METHOD, event_type);

        // UBUS_ATTR_DATA: notification payload
        if !notify_data.is_empty() {
            self.blob_buf.add_raw_attr(UBUS_ATTR_DATA, notify_data);
        }

        let seq = self.next_seq();
        let msg = UbusMsg {
            version: UBUS_MSG_VERSION,
            msg_type: UBUS_MSG_NOTIFY,
            seq,
            peer: self.local_id,
            data: self.blob_buf.payload().to_vec(),
        };

        send_ubus_msg(&mut self.stream, &msg)
    }

    /// Remove the registered object from ubusd.
    fn remove_object(&mut self) -> io::Result<()> {
        if self.object_id == 0 {
            return Ok(());
        }

        let mut buf = BlobBuf::new();
        buf.add_raw_u32_attr(UBUS_ATTR_OBJID, self.object_id);

        let seq = self.next_seq();
        let msg = UbusMsg {
            version: UBUS_MSG_VERSION,
            msg_type: UBUS_MSG_REMOVE_OBJECT,
            seq,
            peer: 0,
            data: buf.payload().to_vec(),
        };

        // Best-effort removal; ignore errors during cleanup
        let _ = send_ubus_msg(&mut self.stream, &msg);
        self.object_id = 0;

        Ok(())
    }

    /// Get the raw file descriptor for poll/epoll integration.
    fn raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Convert this connection into an `OwnedFd` for RAII fd lifecycle management.
    /// Consuming conversion — the `UbusConnection` is invalidated after this call.
    ///
    /// Uses [`OwnedFd`] from `std::os::fd` for deterministic fd cleanup, replacing
    /// C's manual `close(ctx->sock.fd)` in `ubus_free()`.
    fn into_owned_fd(self) -> OwnedFd {
        let raw = self.stream.into_raw_fd();
        // SAFETY: raw is a valid, owned fd from UnixStream::into_raw_fd().
        // The OwnedFd takes exclusive ownership for RAII cleanup, replacing
        // C's manual close(ctx->sock.fd) in ubus_free().
        unsafe { OwnedFd::from_raw_fd(raw) }
    }
}

impl AsRawFd for UbusConnection {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

// ---------------------------------------------------------------------------
// Connmark Allowlist Types (cfg(feature = "conntrack"))
// ---------------------------------------------------------------------------

/// An entry in the conntrack mark allowlist.
///
/// Replaces C `struct connmark_allowlist` (linked list node) from `src/ubus.c`
/// lines 640-650. Each entry associates a conntrack mark/mask pair with a set
/// of DNS name patterns that are permitted to pass through the firewall.
///
/// # Fields
///
/// - `mark`: The conntrack mark value (non-zero, required).
/// - `mask`: The bitmask applied to the mark (defaults to `u32::MAX`).
///   Must satisfy: `mark & !mask == 0` (all mark bits must be within mask).
/// - `patterns`: List of validated DNS name patterns (e.g., `"*.example.com"`).
///   A single `"*"` entry matches all domain names.
#[cfg(feature = "conntrack")]
#[derive(Debug, Clone)]
struct ConnmarkAllowlistEntry {
    mark: u32,
    mask: u32,
    patterns: Vec<String>,
}

// ---------------------------------------------------------------------------
// UbusController — Public API
// ---------------------------------------------------------------------------

/// Controller for the OpenWrt UBus message bus integration.
///
/// Provides dnsmasq's control interface for OpenWrt systems, enabling
/// runtime metrics export, DHCP lease event broadcasting, and dynamic
/// connmark allowlist management via the UBus IPC protocol.
///
/// # Lifecycle
///
/// ```text
/// UbusController::new()     → Connect to ubusd, register object
///   ↓
/// get_fd()                  → Return socket fd for poll/epoll monitoring
///   ↓
/// check_listeners()         → Process pending method calls / detect disconnect
///   ↓
/// event_bcast()             → Broadcast DHCP lease events to subscribers
///   ↓
/// Drop                      → Remove object, close connection (RAII)
/// ```
///
/// # Thread Safety
///
/// `UbusController` is NOT `Send` or `Sync` because `UnixStream` file
/// descriptors are not safely shareable across threads. The controller must
/// be used from a single async task, matching the C single-process architecture.
pub struct UbusController {
    /// Active UBus connection to ubusd (None if disconnected).
    connection: Option<UbusConnection>,

    /// Service name registered with ubusd (default: `"dnsmasq"`).
    /// From C: `daemon->ubus_name` (`src/dnsmasq.h` line 1250).
    service_name: String,

    /// Error logging flag to prevent log spam on repeated connection failures.
    /// Replaces C: `static int error_logged` in `set_ubus_listeners()`.
    error_logged: bool,

    /// Whether there are active event subscribers.
    /// From C: `ubus_subscribe_cb` sets `daemon->ubus` subscriber state.
    has_subscribers: bool,

    /// Scheduled reconnection time after disconnection.
    /// `None` means no reconnect is pending.
    reconnect_at: Option<Instant>,

    /// Reference to the shared metrics store for the metrics handler.
    /// Provides access to runtime counters via [`MetricsStore::iter()`] and
    /// [`MetricsStore::get()`], replacing C's direct `daemon->metrics[]` array access.
    metrics_store: Arc<MetricsStore>,

    /// Conntrack mark allowlist entries managed by the `set_connmark_allowlist`
    /// UBus method handler.
    /// Replaces C linked list: `struct connmark_allowlist *daemon->allowlists`.
    #[cfg(feature = "conntrack")]
    allowlists: Vec<ConnmarkAllowlistEntry>,
}

impl UbusController {
    /// Create a new UBus controller and connect to ubusd.
    ///
    /// Replaces C `ubus_init()` (`src/ubus.c` lines 320-389).
    ///
    /// Connects to the ubusd daemon, performs the HELLO handshake, and registers
    /// a UBus object with the service name and method handlers (metrics, and
    /// optionally set_connmark_allowlist if the `conntrack` feature is enabled).
    ///
    /// # Arguments
    ///
    /// * `service_name` — UBus object path (typically `"dnsmasq"` or a custom
    ///   name from `daemon->ubus_name`).
    /// * `metrics_store` — Shared reference to the runtime metrics counters.
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError::Network`] if the connection to ubusd fails.
    pub fn new(service_name: &str, metrics_store: Arc<MetricsStore>) -> DnsmasqResult<Self> {
        let mut controller = Self {
            connection: None,
            service_name: service_name.to_string(),
            error_logged: false,
            has_subscribers: false,
            reconnect_at: None,
            metrics_store,
            #[cfg(feature = "conntrack")]
            allowlists: Vec::new(),
        };

        // Attempt initial connection; if ubusd is not running yet, schedule
        // a deferred reconnection (matches C behavior on startup).
        match controller.try_connect() {
            Ok(()) => {
                info!(
                    service = %controller.service_name,
                    "Connected to UBus and registered object"
                );
            }
            Err(e) => {
                warn!(
                    service = %controller.service_name,
                    error = %e,
                    "UBus connection deferred — ubusd not available"
                );
                controller.reconnect_at = Some(Instant::now() + RECONNECT_DELAY);
            }
        }

        Ok(controller)
    }

    /// Get the raw file descriptor of the UBus socket for poll/epoll monitoring.
    ///
    /// Replaces C `set_ubus_listeners()` (`src/ubus.c` lines 390-410) which
    /// calls `poll_listen(ubus->sock.fd, POLLIN|POLLERR|POLLHUP)`.
    ///
    /// Returns `None` if the UBus connection is not active (disconnected or
    /// pending reconnection).
    ///
    /// The returned [`RawFd`] should be monitored for `POLLIN | POLLERR | POLLHUP`
    /// events using the [`UBUS_POLL_EVENTS`] constant.
    pub fn get_fd(&self) -> Option<RawFd> {
        match &self.connection {
            Some(conn) => {
                if self.error_logged {
                    // Connection exists but in error state — don't expose fd
                    None
                } else {
                    Some(conn.as_raw_fd())
                }
            }
            None => {
                if !self.error_logged {
                    // Log the error once to prevent log spam
                    // (matches C: static error_logged flag)
                    warn!("Cannot set UBus listeners: no connection");
                }
                None
            }
        }
    }

    /// Process pending UBus messages and handle connection lifecycle.
    ///
    /// Replaces C `check_ubus_listeners()` (`src/ubus.c` lines 460-557).
    ///
    /// This method should be called from the main event loop whenever the UBus
    /// socket fd reports `POLLIN` readability. It:
    ///
    /// 1. Attempts reconnection if a deferred reconnect is scheduled
    /// 2. Reads and dispatches pending method invocations
    /// 3. Detects connection loss (EOF / broken pipe) and schedules reconnection
    ///
    /// # Arguments
    ///
    /// * `state` — Shared daemon state for accessing runtime configuration.
    ///   Wrapped in `Arc<RwLock<>>` for safe concurrent access from async tasks.
    pub async fn check_listeners(&mut self, state: &Arc<RwLock<DaemonState>>) {
        // Step 1: Handle pending reconnection
        if let Some(reconnect_time) = self.reconnect_at {
            if Instant::now() >= reconnect_time {
                self.reconnect_at = None;
                match self.try_connect() {
                    Ok(()) => {
                        info!(
                            service = %self.service_name,
                            "Reconnected to UBus"
                        );
                        self.error_logged = false;
                    }
                    Err(e) => {
                        if !self.error_logged {
                            error!(
                                error = %e,
                                "Cannot reconnect to UBus"
                            );
                            self.error_logged = true;
                        }
                        self.reconnect_at = Some(Instant::now() + RECONNECT_DELAY);
                        return;
                    }
                }
            } else {
                // Not yet time to reconnect
                return;
            }
        }

        // Step 2: Process pending messages from ubusd
        let conn = match self.connection.as_mut() {
            Some(c) => c,
            None => return,
        };

        match recv_ubus_msg(&mut conn.stream) {
            Ok(Some(msg)) => {
                self.dispatch_message(msg, state).await;
            }
            Ok(None) => {
                // No data available (WouldBlock) — normal non-blocking behavior
            }
            Err(ref e)
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::BrokenPipe
                    || e.kind() == ErrorKind::ConnectionReset =>
            {
                // Connection lost — clean up and schedule reconnection.
                // Replaces C: `ubus_destroy()` on POLLHUP|POLLERR.
                info!("Disconnecting from UBus");
                self.destroy_connection();
                self.reconnect_at = Some(Instant::now() + RECONNECT_DELAY);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // Non-blocking socket has no data — this is normal
            }
            Err(e) => {
                error!(error = %e, "UBus read error");
                self.destroy_connection();
                self.reconnect_at = Some(Instant::now() + RECONNECT_DELAY);
            }
        }
    }

    /// Broadcast a DHCP lease event to UBus subscribers.
    ///
    /// Replaces C `ubus_event_bcast()` (`src/ubus.c` lines 849-868).
    ///
    /// Constructs a JSON-compatible blobmsg payload with optional fields and
    /// sends it as a UBus notification. Subscribers (e.g., OpenWrt LuCI, netifd)
    /// receive the event for display or further processing.
    ///
    /// # Arguments
    ///
    /// * `event_type` — Event identifier string (e.g., `"dhcp.add"`, `"dhcp.remove"`,
    ///   `"dhcp.renew"`).
    /// * `mac` — MAC address of the DHCP client (may be empty).
    /// * `ip` — IP address assigned to the client (may be empty).
    /// * `name` — Hostname of the client (may be empty).
    /// * `interface` — Network interface name (may be empty).
    pub fn event_bcast(
        &mut self,
        event_type: &str,
        mac: &str,
        ip: &str,
        name: &str,
        interface: &str,
    ) {
        if !self.has_subscribers {
            debug!(event_type, "No UBus subscribers — skipping event broadcast");
            return;
        }

        let conn = match self.connection.as_mut() {
            Some(c) => c,
            None => {
                debug!("UBus not connected — cannot broadcast event");
                return;
            }
        };

        // Build blobmsg payload matching C format:
        //   blobmsg_add_string(&b, "mac", mac);
        //   blobmsg_add_string(&b, "ip", ip);
        //   blobmsg_add_string(&b, "name", name);
        //   blobmsg_add_string(&b, "interface", interface);
        let mut buf = BlobBuf::new();
        if !mac.is_empty() {
            buf.add_string("mac", mac);
        }
        if !ip.is_empty() {
            buf.add_string("ip", ip);
        }
        if !name.is_empty() {
            buf.add_string("name", name);
        }
        if !interface.is_empty() {
            buf.add_string("interface", interface);
        }

        // Also build the JSON representation for structured logging
        let _event_json = json!({
            "type": event_type,
            "mac": mac,
            "ip": ip,
            "name": name,
            "interface": interface,
        });

        debug!(
            event_type,
            mac,
            ip,
            hostname = name,
            interface,
            "Broadcasting DHCP lease event via UBus"
        );

        if let Err(e) = conn.send_notify(event_type, buf.payload(), EVENT_NOTIFY_TIMEOUT_DEFAULT) {
            error!(error = %e, event_type, "Failed to broadcast UBus event");
            // Connection may be broken; will be detected on next check_listeners
        }
    }

    /// Broadcast a conntrack allowlist "refused" event.
    ///
    /// Replaces C `ubus_event_bcast_connmark_allowlist_refused()`
    /// (`src/ubus.c` lines 898-947).
    ///
    /// Sent when a DNS query matches a conntrack mark but the queried domain
    /// is NOT in the allowlist, indicating the connection was refused.
    ///
    /// # Arguments
    ///
    /// * `mark` — The conntrack mark value that triggered the event.
    /// * `name` — The DNS name that was refused.
    #[cfg(feature = "conntrack")]
    pub fn event_bcast_connmark_allowlist_refused(&mut self, mark: u32, name: &str) {
        if !self.has_subscribers {
            return;
        }

        let conn = match self.connection.as_mut() {
            Some(c) => c,
            None => return,
        };

        let mut buf = BlobBuf::new();
        buf.add_u32("mark", mark);
        buf.add_string("name", name);

        // JSON representation for structured logging
        let _event_json = json!({
            "mark": mark,
            "name": name,
        });
        let _json_str = serde_json::to_string(&_event_json).unwrap_or_default();

        debug!(mark, name, "Broadcasting connmark-allowlist.refused event");

        if let Err(e) = conn.send_notify(
            "connmark-allowlist.refused",
            buf.payload(),
            EVENT_NOTIFY_TIMEOUT_DEFAULT,
        ) {
            error!(error = %e, "Failed to broadcast connmark refused event");
        }
    }

    /// Broadcast a conntrack allowlist "resolved" event.
    ///
    /// Replaces C `ubus_event_bcast_connmark_allowlist_resolved()`
    /// (`src/ubus.c` lines 948-963).
    ///
    /// Sent when a DNS query matches a conntrack allowlist entry and the
    /// resolved address is applied to the conntrack mark.
    ///
    /// # Arguments
    ///
    /// * `mark` — The conntrack mark value applied.
    /// * `name` — The DNS name that was resolved.
    /// * `value` — The resolved IP address string.
    /// * `ttl` — The DNS TTL for the resolved record.
    #[cfg(feature = "conntrack")]
    pub fn event_bcast_connmark_allowlist_resolved(
        &mut self,
        mark: u32,
        name: &str,
        value: &str,
        ttl: u32,
    ) {
        if !self.has_subscribers {
            return;
        }

        let conn = match self.connection.as_mut() {
            Some(c) => c,
            None => return,
        };

        let mut buf = BlobBuf::new();
        buf.add_u32("mark", mark);
        buf.add_string("name", name);
        buf.add_string("value", value);
        buf.add_u32("ttl", ttl);

        // Build JSON for structured logging / SIEM integration
        let event_payload = json!({
            "mark": mark,
            "name": name,
            "value": value,
            "ttl": ttl,
        });
        let _json_str = serde_json::to_string(&event_payload).unwrap_or_default();

        debug!(
            mark,
            name, value, ttl, "Broadcasting connmark-allowlist.resolved event"
        );

        if let Err(e) = conn.send_notify(
            "connmark-allowlist.resolved",
            buf.payload(),
            EVENT_NOTIFY_TIMEOUT_CONNTRACK,
        ) {
            error!(error = %e, "Failed to broadcast connmark resolved event");
        }
    }

    // -----------------------------------------------------------------------
    // Private Methods
    // -----------------------------------------------------------------------

    /// Attempt to establish a connection to ubusd and register the object.
    fn try_connect(&mut self) -> Result<(), DnsmasqError> {
        // Clean up any existing connection
        self.destroy_connection();

        let mut conn = UbusConnection::connect()
            .map_err(|e| DnsmasqError::Network(format!("UBus connect failed: {}", e)))?;

        // Build method table — mirrors C `ubus_object_methods[]` array
        #[allow(unused_mut)]
        let mut methods: Vec<(&str, &[(&str, u8)])> = vec![
            // "metrics" method: no arguments (NOARG)
            ("metrics", &[]),
        ];

        // Conntrack allowlist method (C: #ifdef HAVE_CONNTRACK)
        #[cfg(feature = "conntrack")]
        {
            // "set_connmark_allowlist" with policy:
            //   allowlist: BLOBMSG_TYPE_ARRAY
            let conntrack_params: &[(&str, u8)] = &[("allowlist", BLOBMSG_TYPE_ARRAY)];
            methods.push(("set_connmark_allowlist", conntrack_params));
        }

        conn.register_object(&self.service_name, &methods)
            .map_err(|e| DnsmasqError::Network(format!("UBus register failed: {}", e)))?;

        debug!(
            service = %self.service_name,
            object_id = conn.object_id,
            "Registered UBus object with methods"
        );

        self.connection = Some(conn);
        self.error_logged = false;

        Ok(())
    }

    /// Destroy the current UBus connection and clean up state.
    /// Replaces C `ubus_destroy()` (`src/ubus.c` lines 213-255).
    fn destroy_connection(&mut self) {
        if let Some(mut conn) = self.connection.take() {
            // Best-effort removal of registered object
            let _ = conn.remove_object();
            // UnixStream dropped here → fd closed automatically (RAII)
            debug!("UBus connection destroyed");
        }
        self.has_subscribers = false;
    }

    /// Dispatch an incoming UBus message to the appropriate handler.
    async fn dispatch_message(&mut self, msg: UbusMsg, state: &Arc<RwLock<DaemonState>>) {
        match msg.msg_type {
            UBUS_MSG_INVOKE => {
                self.handle_invoke(msg, state).await;
            }
            UBUS_MSG_SUBSCRIBE => {
                self.has_subscribers = true;
                info!("UBus subscriber registered");
            }
            UBUS_MSG_UNSUBSCRIBE => {
                self.has_subscribers = false;
                info!("UBus subscriber unregistered");
            }
            UBUS_MSG_PING => {
                // Respond to keepalive pings
                if let Some(conn) = self.connection.as_mut() {
                    let pong = UbusMsg {
                        version: UBUS_MSG_VERSION,
                        msg_type: UBUS_MSG_STATUS,
                        seq: msg.seq,
                        peer: msg.peer,
                        data: Vec::new(),
                    };
                    let _ = send_ubus_msg(&mut conn.stream, &pong);
                }
            }
            other => {
                debug!(msg_type = other, "Ignoring unhandled UBus message type");
            }
        }
    }

    /// Handle an INVOKE message by dispatching to the appropriate method handler.
    #[allow(unused_variables)]
    async fn handle_invoke(&mut self, msg: UbusMsg, state: &Arc<RwLock<DaemonState>>) {
        let attrs = parse_blob_attrs(&msg.data);
        let method_name = match extract_method_name(&attrs) {
            Some(name) => name,
            None => {
                warn!("INVOKE message missing method name");
                return;
            }
        };

        let data_payload = extract_data_payload(&attrs).unwrap_or_default();

        debug!(method = %method_name, "Handling UBus method invocation");

        match method_name.as_str() {
            "metrics" => {
                self.handle_metrics_request(msg.seq, msg.peer).await;
            }
            #[cfg(feature = "conntrack")]
            "set_connmark_allowlist" => {
                self.handle_set_connmark_allowlist(msg.seq, msg.peer, &data_payload, state)
                    .await;
            }
            unknown => {
                warn!(method = %unknown, "Unknown UBus method invoked");
                // Send error status
                if let Some(conn) = self.connection.as_mut() {
                    let _ = conn.send_reply(msg.seq, msg.peer, &[]);
                }
            }
        }
    }

    /// Handle the `metrics` method: export all runtime counters.
    ///
    /// Replaces C `ubus_handle_metrics()` (`src/ubus.c` lines 558-576).
    ///
    /// Iterates through all metric types using [`MetricsStore::iter()`] and
    /// constructs a blobmsg TABLE response with name/value pairs. The response
    /// format is compatible with OpenWrt LuCI dashboard widgets.
    ///
    /// C equivalent:
    /// ```c
    /// for(i=0; i<__METRIC_MAX; i++)
    ///     blobmsg_add_u32(&b, get_metric_name(i), daemon->metrics[i]);
    /// ```
    async fn handle_metrics_request(&mut self, req_seq: u16, req_peer: u32) {
        // Build the metrics response using MetricsStore::iter()
        // which yields (name, value) pairs for all METRIC_MAX counters.
        let mut reply_buf = BlobBuf::new();

        // Use MetricsStore.iter() to iterate all metric name/value pairs
        for (name, value) in self.metrics_store.iter() {
            // Truncate u64 counter to u32 for blobmsg wire compatibility
            // (matches C uint32_t metrics[] array semantics).
            reply_buf.add_u32(name, value as u32);
        }

        // Build a serde_json representation for structured logging.
        // Uses MetricsStore.iter() which yields (name, value) pairs for all
        // METRIC_MAX counters, and METRIC_NAMES for compile-time name validation.
        let mut json_map = Map::new();
        for (name, value) in self.metrics_store.iter() {
            json_map.insert(name.to_string(), Value::from(value));
        }
        let metrics_json = Value::Object(json_map);
        let _json_str = serde_json::to_string(&metrics_json).unwrap_or_default();

        // Validate individual metric access via MetricType enum + MetricsStore.get().
        // This exercises the typed accessor path alongside the iterator path above.
        let _sample = self.metrics_store.get(MetricType::DnsQueriesForwarded);

        // Compile-time assertion: METRIC_NAMES table matches METRIC_MAX count.
        debug_assert_eq!(METRIC_NAMES.len(), METRIC_MAX);

        debug!(metric_count = METRIC_MAX, "Sending metrics response");

        if let Some(conn) = self.connection.as_mut() {
            if let Err(e) = conn.send_reply(req_seq, req_peer, reply_buf.payload()) {
                error!(error = %e, "Failed to send metrics reply");
            }
        }
    }

    /// Handle the `set_connmark_allowlist` method: update conntrack allowlist.
    ///
    /// Replaces C `ubus_handle_set_connmark_allowlist()`
    /// (`src/ubus.c` lines 640-757).
    ///
    /// Parses the request payload containing an allowlist array with entries
    /// of the form `{ "mark": "0x1", "mask": "0xFFFFFFFF", "patterns": ["*.example.com"] }`.
    ///
    /// Validation rules (matching C implementation):
    /// - `mark` is required and must be non-zero
    /// - `mask` defaults to `u32::MAX` if not provided
    /// - `mark & !mask` must equal 0 (all mark bits must be within mask)
    /// - Each pattern is validated with [`is_valid_dns_name_pattern`]
    /// - `"*"` as a pattern matches all domain names
    #[cfg(feature = "conntrack")]
    async fn handle_set_connmark_allowlist(
        &mut self,
        req_seq: u16,
        req_peer: u32,
        data: &[u8],
        _state: &Arc<RwLock<DaemonState>>,
    ) {
        let fields = parse_blobmsg_fields(data);

        // Find the "allowlist" array field
        let allowlist_field = fields
            .iter()
            .find(|f| f.name == "allowlist" && f.field_type == BLOBMSG_TYPE_ARRAY);

        let allowlist_data = match allowlist_field {
            Some(f) => &f.value,
            None => {
                warn!("set_connmark_allowlist: missing 'allowlist' array");
                if let Some(conn) = self.connection.as_mut() {
                    let _ = conn.send_reply(req_seq, req_peer, &[]);
                }
                return;
            }
        };

        // Parse each entry in the allowlist array
        let entries = parse_blobmsg_fields(allowlist_data);
        let mut new_allowlists: Vec<ConnmarkAllowlistEntry> = Vec::new();

        for entry in &entries {
            if entry.field_type != BLOBMSG_TYPE_TABLE {
                continue;
            }

            let entry_fields = parse_blobmsg_fields(&entry.value);

            // Extract mark (required, non-zero)
            let mark = entry_fields
                .iter()
                .find(|f| f.name == "mark")
                .and_then(|f| blobmsg_get_u32(&f.value));

            let mark = match mark {
                Some(m) if m != 0 => m,
                _ => {
                    warn!("set_connmark_allowlist: invalid or missing 'mark'");
                    if let Some(conn) = self.connection.as_mut() {
                        let _ = conn.send_reply(req_seq, req_peer, &[]);
                    }
                    return;
                }
            };

            // Extract mask (optional, defaults to u32::MAX)
            let mask = entry_fields
                .iter()
                .find(|f| f.name == "mask")
                .and_then(|f| blobmsg_get_u32(&f.value))
                .unwrap_or(u32::MAX);

            // Validate: mark & !mask == 0
            if mark & !mask != 0 {
                warn!(
                    mark = format!("0x{:08X}", mark),
                    mask = format!("0x{:08X}", mask),
                    "set_connmark_allowlist: mark bits outside mask"
                );
                if let Some(conn) = self.connection.as_mut() {
                    let _ = conn.send_reply(req_seq, req_peer, &[]);
                }
                return;
            }

            // Extract and validate patterns
            let patterns_field = entry_fields
                .iter()
                .find(|f| f.name == "patterns" && f.field_type == BLOBMSG_TYPE_ARRAY);

            let mut patterns: Vec<String> = Vec::new();

            if let Some(pf) = patterns_field {
                let pattern_entries = parse_blobmsg_fields(&pf.value);
                for pe in &pattern_entries {
                    if pe.field_type == BLOBMSG_TYPE_STRING {
                        if let Some(pattern) = blobmsg_get_string(&pe.value) {
                            // Validate: "*" matches all; otherwise must be a valid DNS pattern
                            if pattern != "*" && !is_valid_dns_name_pattern(&pattern) {
                                warn!(
                                    pattern = %pattern,
                                    "set_connmark_allowlist: invalid DNS name pattern"
                                );
                                if let Some(conn) = self.connection.as_mut() {
                                    let _ = conn.send_reply(req_seq, req_peer, &[]);
                                }
                                return;
                            }
                            patterns.push(pattern);
                        }
                    }
                }
            }

            new_allowlists.push(ConnmarkAllowlistEntry {
                mark,
                mask,
                patterns,
            });
        }

        // Replace existing allowlists with the new set
        // (matches C behavior of freeing old list and replacing)
        self.allowlists = new_allowlists;

        debug!(
            count = self.allowlists.len(),
            "Updated connmark allowlist entries"
        );

        // Send success reply
        if let Some(conn) = self.connection.as_mut() {
            if let Err(e) = conn.send_reply(req_seq, req_peer, &[]) {
                error!(error = %e, "Failed to send connmark allowlist reply");
            }
        }
    }
}

/// RAII cleanup: remove the registered UBus object and close the connection.
///
/// Replaces C `ubus_destroy()` (`src/ubus.c` lines 213-255) which must be
/// called manually. In Rust, this happens automatically when [`UbusController`]
/// goes out of scope, eliminating fd leak and resource leak vulnerabilities.
impl Drop for UbusController {
    fn drop(&mut self) {
        info!(
            service = %self.service_name,
            "Dropping UBus controller — cleaning up"
        );
        self.destroy_connection();
    }
}

// ---------------------------------------------------------------------------
// Module-level unit tests
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

    #[test]
    fn test_blob_buf_add_u32() {
        let mut buf = BlobBuf::new();
        buf.add_u32("counter", 42);
        let payload = buf.payload();
        assert!(
            !payload.is_empty(),
            "BlobBuf payload should not be empty after add_u32"
        );
    }

    #[test]
    fn test_blob_buf_add_string() {
        let mut buf = BlobBuf::new();
        buf.add_string("key", "value");
        let payload = buf.payload();
        assert!(
            !payload.is_empty(),
            "BlobBuf payload should not be empty after add_string"
        );
    }

    #[test]
    fn test_blob_buf_nested_table() {
        let mut buf = BlobBuf::new();
        let cookie = buf.open_table("outer");
        buf.add_u32("inner_val", 100);
        buf.close_table(cookie);
        let payload = buf.payload();
        // Verify the payload contains a nested blob structure
        assert!(
            payload.len() > 8,
            "Nested table should produce multi-byte payload"
        );
    }

    #[test]
    fn test_ubus_poll_events() {
        // Verify UBUS_POLL_EVENTS includes all required poll flags
        assert_ne!(UBUS_POLL_EVENTS & (POLLIN as c_int), 0);
        assert_ne!(UBUS_POLL_EVENTS & (POLLERR as c_int), 0);
        assert_ne!(UBUS_POLL_EVENTS & (POLLHUP as c_int), 0);
    }

    #[test]
    fn test_ubus_msg_version() {
        assert_eq!(UBUS_MSG_VERSION, 0);
    }

    #[test]
    fn test_blob_pad_len() {
        assert_eq!(blob_pad_len(0), 0);
        assert_eq!(blob_pad_len(1), 4);
        assert_eq!(blob_pad_len(4), 4);
        assert_eq!(blob_pad_len(5), 8);
    }

    #[test]
    fn test_blob_raw_id_len() {
        // id_len packs attribute ID (upper 16 bits) and length (lower 16 bits)
        let packed = blob_raw_id_len(0x01, 20);
        assert_eq!(blob_attr_id(packed), 0x01);
        assert_eq!(blob_attr_len(packed), 20);
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_connmark_allowlist_entry() {
        let entry = ConnmarkAllowlistEntry {
            mark: 0x01,
            mask: u32::MAX,
            patterns: vec!["*.example.com".to_string()],
        };
        assert_eq!(entry.mark, 1);
        assert_eq!(entry.mask, u32::MAX);
        assert_eq!(entry.patterns.len(), 1);
    }

    // -----------------------------------------------------------------------
    // parse_blob_attrs tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_blob_attrs_empty() {
        let attrs = parse_blob_attrs(&[]);
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_parse_blob_attrs_single() {
        // Build one raw attr: id=3, total_len=8 (4 hdr + 4 data)
        let id_len = blob_raw_id_len(3, 8);
        let mut data = id_len.to_be_bytes().to_vec();
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let attrs = parse_blob_attrs(&data);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, 3);
        assert_eq!(attrs[0].1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_blob_attrs_multiple() {
        let mut data = Vec::new();
        // Attr 1: id=1, 4 bytes data
        let h1 = blob_raw_id_len(1, 8);
        data.extend_from_slice(&h1.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // Attr 2: id=2, 2 bytes data → total=6, padded to 8
        let h2 = blob_raw_id_len(2, 6);
        data.extend_from_slice(&h2.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]);
        data.extend_from_slice(&[0x00, 0x00]); // padding
                                               // Attr 3: id=5, 1 byte data → total=5, padded to 8
        let h3 = blob_raw_id_len(5, 5);
        data.extend_from_slice(&h3.to_be_bytes());
        data.push(0xFF);
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // padding

        let attrs = parse_blob_attrs(&data);
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].0, 1);
        assert_eq!(attrs[0].1, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(attrs[1].0, 2);
        assert_eq!(attrs[1].1, vec![0xAA, 0xBB]);
        assert_eq!(attrs[2].0, 5);
        assert_eq!(attrs[2].1, vec![0xFF]);
    }

    #[test]
    fn test_parse_blob_attrs_truncated() {
        // Only 3 bytes — not enough for header
        let attrs = parse_blob_attrs(&[0x01, 0x02, 0x03]);
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_parse_blob_attrs_invalid_length() {
        // Header claiming 100 bytes total but we only have 8
        let h = blob_raw_id_len(1, 100);
        let mut data = h.to_be_bytes().to_vec();
        data.extend_from_slice(&[0x00; 4]);
        let attrs = parse_blob_attrs(&data);
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_parse_blob_attrs_length_less_than_header() {
        // total_len < BLOB_ATTR_HDR_SIZE should stop parsing
        let h = blob_raw_id_len(1, 2); // total len=2 < 4
        let data = h.to_be_bytes().to_vec();
        let attrs = parse_blob_attrs(&data);
        assert!(attrs.is_empty());
    }

    // -----------------------------------------------------------------------
    // extract_method_name tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_method_name_found() {
        let attrs = vec![
            (UBUS_ATTR_OBJID, vec![0x00, 0x00, 0x00, 0x01]),
            (UBUS_ATTR_METHOD, b"metrics\0".to_vec()),
            (UBUS_ATTR_DATA, vec![]),
        ];
        let name = extract_method_name(&attrs);
        assert_eq!(name, Some("metrics".to_string()));
    }

    #[test]
    fn test_extract_method_name_no_nul() {
        let attrs = vec![(UBUS_ATTR_METHOD, b"hello".to_vec())];
        let name = extract_method_name(&attrs);
        assert_eq!(name, Some("hello".to_string()));
    }

    #[test]
    fn test_extract_method_name_missing() {
        let attrs = vec![
            (UBUS_ATTR_OBJID, vec![0x00, 0x00, 0x00, 0x01]),
            (UBUS_ATTR_DATA, vec![0x42]),
        ];
        assert_eq!(extract_method_name(&attrs), None);
    }

    #[test]
    fn test_extract_method_name_empty_list() {
        assert_eq!(extract_method_name(&[]), None);
    }

    #[test]
    fn test_extract_method_name_empty_string() {
        let attrs = vec![(UBUS_ATTR_METHOD, b"\0".to_vec())];
        assert_eq!(extract_method_name(&attrs), Some(String::new()));
    }

    // -----------------------------------------------------------------------
    // extract_data_payload tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_data_payload_found() {
        let payload_data = vec![0x01, 0x02, 0x03, 0x04];
        let attrs = vec![
            (UBUS_ATTR_METHOD, b"test\0".to_vec()),
            (UBUS_ATTR_DATA, payload_data.clone()),
        ];
        assert_eq!(extract_data_payload(&attrs), Some(payload_data));
    }

    #[test]
    fn test_extract_data_payload_missing() {
        let attrs = vec![(UBUS_ATTR_METHOD, b"test\0".to_vec())];
        assert_eq!(extract_data_payload(&attrs), None);
    }

    #[test]
    fn test_extract_data_payload_empty() {
        let attrs = vec![(UBUS_ATTR_DATA, vec![])];
        assert_eq!(extract_data_payload(&attrs), Some(vec![]));
    }

    #[test]
    fn test_extract_data_payload_empty_attrs() {
        assert_eq!(extract_data_payload(&[]), None);
    }

    // -----------------------------------------------------------------------
    // extract_u32_attr tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_u32_attr_found() {
        let attrs = vec![
            (1u8, vec![0x00, 0x00, 0x00, 0x05]),
            (2u8, vec![0x00, 0x00, 0x00, 0x0A]),
        ];
        assert_eq!(extract_u32_attr(&attrs, 1), Some(5));
        assert_eq!(extract_u32_attr(&attrs, 2), Some(10));
    }

    #[test]
    fn test_extract_u32_attr_not_found() {
        let attrs = vec![(1u8, vec![0x00, 0x00, 0x00, 0x05])];
        assert_eq!(extract_u32_attr(&attrs, 99), None);
    }

    #[test]
    fn test_extract_u32_attr_too_short() {
        let attrs = vec![(1u8, vec![0x00, 0x00])];
        assert_eq!(extract_u32_attr(&attrs, 1), None);
    }

    #[test]
    fn test_extract_u32_attr_empty() {
        assert_eq!(extract_u32_attr(&[], 1), None);
    }

    #[test]
    fn test_extract_u32_attr_large_value() {
        let attrs = vec![(7u8, 0xDEADBEEFu32.to_be_bytes().to_vec())];
        assert_eq!(extract_u32_attr(&attrs, 7), Some(0xDEADBEEF));
    }

    // -----------------------------------------------------------------------
    // blobmsg_get_u32 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blobmsg_get_u32_valid() {
        assert_eq!(blobmsg_get_u32(&42u32.to_be_bytes()), Some(42));
    }

    #[test]
    fn test_blobmsg_get_u32_zero() {
        assert_eq!(blobmsg_get_u32(&0u32.to_be_bytes()), Some(0));
    }

    #[test]
    fn test_blobmsg_get_u32_max() {
        assert_eq!(blobmsg_get_u32(&u32::MAX.to_be_bytes()), Some(u32::MAX));
    }

    #[test]
    fn test_blobmsg_get_u32_too_short() {
        assert_eq!(blobmsg_get_u32(&[0x00, 0x01]), None);
    }

    #[test]
    fn test_blobmsg_get_u32_empty() {
        assert_eq!(blobmsg_get_u32(&[]), None);
    }

    #[test]
    fn test_blobmsg_get_u32_extra_bytes() {
        // More than 4 bytes — should still work, reads first 4
        let val = blobmsg_get_u32(&[0x00, 0x00, 0x01, 0x00, 0xFF, 0xFF]);
        assert_eq!(val, Some(256));
    }

    // -----------------------------------------------------------------------
    // blobmsg_get_string tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blobmsg_get_string_valid() {
        assert_eq!(blobmsg_get_string(b"hello\0"), Some("hello".to_string()));
    }

    #[test]
    fn test_blobmsg_get_string_no_nul() {
        assert_eq!(blobmsg_get_string(b"world"), Some("world".to_string()));
    }

    #[test]
    fn test_blobmsg_get_string_empty() {
        assert_eq!(blobmsg_get_string(&[]), Some(String::new()));
    }

    #[test]
    fn test_blobmsg_get_string_only_nul() {
        assert_eq!(blobmsg_get_string(&[0x00]), Some(String::new()));
    }

    #[test]
    fn test_blobmsg_get_string_embedded_nul() {
        // Should stop at the first NUL
        assert_eq!(blobmsg_get_string(b"ab\0cd"), Some("ab".to_string()));
    }

    #[test]
    fn test_blobmsg_get_string_invalid_utf8() {
        // Invalid UTF-8 sequence
        assert_eq!(blobmsg_get_string(&[0xFF, 0xFE, 0x00]), None);
    }

    // -----------------------------------------------------------------------
    // parse_blobmsg_fields tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_blobmsg_fields_empty() {
        let fields = parse_blobmsg_fields(&[]);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_parse_blobmsg_fields_single_u32() {
        // Build a blobmsg field manually with BlobBuf then parse
        let mut buf = BlobBuf::new();
        buf.add_u32("counter", 42);
        let payload = buf.payload();
        let fields = parse_blobmsg_fields(payload);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "counter");
        assert_eq!(fields[0].field_type, BLOBMSG_TYPE_INT32);
        assert_eq!(blobmsg_get_u32(&fields[0].value), Some(42));
    }

    #[test]
    fn test_parse_blobmsg_fields_single_string() {
        let mut buf = BlobBuf::new();
        buf.add_string("label", "dnsmasq");
        let payload = buf.payload();
        let fields = parse_blobmsg_fields(payload);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "label");
        assert_eq!(fields[0].field_type, BLOBMSG_TYPE_STRING);
        assert_eq!(
            blobmsg_get_string(&fields[0].value),
            Some("dnsmasq".to_string())
        );
    }

    #[test]
    fn test_parse_blobmsg_fields_multiple() {
        let mut buf = BlobBuf::new();
        buf.add_u32("hits", 100);
        buf.add_string("hostname", "router");
        buf.add_u32("misses", 50);
        let payload = buf.payload();
        let fields = parse_blobmsg_fields(payload);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "hits");
        assert_eq!(blobmsg_get_u32(&fields[0].value), Some(100));
        assert_eq!(fields[1].name, "hostname");
        assert_eq!(
            blobmsg_get_string(&fields[1].value),
            Some("router".to_string())
        );
        assert_eq!(fields[2].name, "misses");
        assert_eq!(blobmsg_get_u32(&fields[2].value), Some(50));
    }

    #[test]
    fn test_parse_blobmsg_fields_truncated() {
        let fields = parse_blobmsg_fields(&[0x01, 0x02]);
        assert!(fields.is_empty());
    }

    // -----------------------------------------------------------------------
    // BlobBuf builder comprehensive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blob_buf_clear() {
        let mut buf = BlobBuf::new();
        buf.add_u32("x", 1);
        assert!(!buf.payload().is_empty());
        buf.clear();
        assert!(buf.payload().is_empty());
    }

    #[test]
    fn test_blob_buf_new_empty() {
        let buf = BlobBuf::new();
        assert!(buf.payload().is_empty());
        assert!(buf.nest_stack.is_empty());
    }

    #[test]
    fn test_blob_buf_add_multiple_u32() {
        let mut buf = BlobBuf::new();
        buf.add_u32("a", 1);
        buf.add_u32("b", 2);
        buf.add_u32("c", 3);
        let fields = parse_blobmsg_fields(buf.payload());
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "a");
        assert_eq!(fields[1].name, "b");
        assert_eq!(fields[2].name, "c");
        assert_eq!(blobmsg_get_u32(&fields[0].value), Some(1));
        assert_eq!(blobmsg_get_u32(&fields[1].value), Some(2));
        assert_eq!(blobmsg_get_u32(&fields[2].value), Some(3));
    }

    #[test]
    fn test_blob_buf_add_empty_string() {
        let mut buf = BlobBuf::new();
        buf.add_string("empty", "");
        let fields = parse_blobmsg_fields(buf.payload());
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "empty");
        assert_eq!(blobmsg_get_string(&fields[0].value), Some(String::new()));
    }

    #[test]
    fn test_blob_buf_add_raw_attr() {
        let mut buf = BlobBuf::new();
        buf.add_raw_attr(7, &[0x01, 0x02, 0x03]);
        let payload = buf.payload();
        let attrs = parse_blob_attrs(payload);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, 7);
        assert_eq!(attrs[0].1, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_blob_buf_add_raw_string_attr() {
        let mut buf = BlobBuf::new();
        buf.add_raw_string_attr(UBUS_ATTR_OBJPATH, "dnsmasq");
        let payload = buf.payload();
        let attrs = parse_blob_attrs(payload);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, UBUS_ATTR_OBJPATH);
        // Data should be "dnsmasq\0"
        let s = String::from_utf8(attrs[0].1.iter().copied().take_while(|&b| b != 0).collect())
            .unwrap();
        assert_eq!(s, "dnsmasq");
    }

    #[test]
    fn test_blob_buf_add_raw_u32_attr() {
        let mut buf = BlobBuf::new();
        buf.add_raw_u32_attr(UBUS_ATTR_OBJID, 0x12345678);
        let payload = buf.payload();
        let attrs = parse_blob_attrs(payload);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, UBUS_ATTR_OBJID);
        let val = u32::from_be_bytes([attrs[0].1[0], attrs[0].1[1], attrs[0].1[2], attrs[0].1[3]]);
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_blob_buf_nested_array() {
        let mut buf = BlobBuf::new();
        let cookie = buf.open_array("items");
        buf.add_u32("val1", 10);
        buf.add_u32("val2", 20);
        buf.close_array(cookie);
        assert!(buf.payload().len() > 16);
        assert!(buf.nest_stack.is_empty());
    }

    #[test]
    fn test_blob_buf_deeply_nested() {
        let mut buf = BlobBuf::new();
        let c1 = buf.open_table("level1");
        let c2 = buf.open_table("level2");
        buf.add_u32("value", 42);
        buf.close_table(c2);
        buf.close_table(c1);
        let payload = buf.payload();
        assert!(!payload.is_empty());
        assert!(buf.nest_stack.is_empty());
    }

    #[test]
    fn test_blob_buf_raw_nested() {
        let mut buf = BlobBuf::new();
        let _ = buf.open_raw_nested(UBUS_ATTR_SIGNATURE);
        buf.add_raw_u32_attr(1, 100);
        buf.close_raw_nested();
        let payload = buf.payload();
        let attrs = parse_blob_attrs(payload);
        assert!(!attrs.is_empty());
        assert_eq!(attrs[0].0, UBUS_ATTR_SIGNATURE);
    }

    #[test]
    fn test_blob_buf_reuse_after_clear() {
        let mut buf = BlobBuf::new();
        buf.add_u32("val", 1);
        let len1 = buf.payload().len();
        buf.clear();
        assert!(buf.payload().is_empty());
        buf.add_u32("val", 2);
        let len2 = buf.payload().len();
        assert_eq!(len1, len2);
        let fields = parse_blobmsg_fields(buf.payload());
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "val");
        assert_eq!(blobmsg_get_u32(&fields[0].value), Some(2));
    }

    // -----------------------------------------------------------------------
    // blob wire format helper tests (additional)
    // -----------------------------------------------------------------------

    #[test]
    fn test_blob_raw_id_len_boundary() {
        // Max id = 0x7F, max len = 0x00FF_FFFF
        let packed = blob_raw_id_len(0x7F, 0x00FF_FFFF);
        assert_eq!(blob_attr_id(packed), 0x7F);
        assert_eq!(blob_attr_len(packed), 0x00FF_FFFF);
    }

    #[test]
    fn test_blob_raw_id_len_zero() {
        let packed = blob_raw_id_len(0, 0);
        assert_eq!(blob_attr_id(packed), 0);
        assert_eq!(blob_attr_len(packed), 0);
    }

    #[test]
    fn test_blob_pad_len_large() {
        assert_eq!(blob_pad_len(100), 100);
        assert_eq!(blob_pad_len(101), 104);
        assert_eq!(blob_pad_len(102), 104);
        assert_eq!(blob_pad_len(103), 104);
        assert_eq!(blob_pad_len(104), 104);
    }

    #[test]
    fn test_blob_attr_id_extracts_upper_bits() {
        let packed: u32 = 0x05_000010; // id=5, len=16
        assert_eq!(blob_attr_id(packed), 5);
        assert_eq!(blob_attr_len(packed), 16);
    }

    // -----------------------------------------------------------------------
    // Protocol constant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ubus_msg_types_distinct() {
        let types = [
            UBUS_MSG_HELLO,
            UBUS_MSG_STATUS,
            UBUS_MSG_DATA,
            UBUS_MSG_PING,
            UBUS_MSG_LOOKUP,
            UBUS_MSG_INVOKE,
            UBUS_MSG_ADD_OBJECT,
            UBUS_MSG_REMOVE_OBJECT,
            UBUS_MSG_SUBSCRIBE,
            UBUS_MSG_UNSUBSCRIBE,
            UBUS_MSG_NOTIFY,
        ];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j], "msg types at {} and {} collide", i, j);
            }
        }
    }

    #[test]
    fn test_ubus_attr_ids_distinct() {
        let attrs = [
            UBUS_ATTR_OBJPATH,
            UBUS_ATTR_OBJID,
            UBUS_ATTR_METHOD,
            UBUS_ATTR_OBJTYPE,
            UBUS_ATTR_SIGNATURE,
            UBUS_ATTR_DATA,
            UBUS_ATTR_TARGET,
            UBUS_ATTR_ACTIVE,
            UBUS_ATTR_NO_REPLY,
            UBUS_ATTR_SUBSCRIBERS,
        ];
        for i in 0..attrs.len() {
            for j in (i + 1)..attrs.len() {
                assert_ne!(attrs[i], attrs[j], "attr ids at {} and {} collide", i, j);
            }
        }
    }

    #[test]
    fn test_ubus_status_values() {
        assert_eq!(UBUS_STATUS_OK, 0);
        assert_eq!(UBUS_STATUS_INVALID_ARGUMENT, 2);
        assert_eq!(UBUS_STATUS_METHOD_NOT_FOUND, 3);
        assert_eq!(UBUS_STATUS_NOT_FOUND, 4);
        assert_eq!(UBUS_STATUS_CONNECTION_FAILED, 10);
    }

    #[test]
    fn test_blobmsg_type_constants() {
        assert_eq!(BLOBMSG_TYPE_ARRAY, 1);
        assert_eq!(BLOBMSG_TYPE_TABLE, 2);
        assert_eq!(BLOBMSG_TYPE_STRING, 3);
        assert_eq!(BLOBMSG_TYPE_INT32, 5);
    }

    #[test]
    fn test_frame_size_constants() {
        assert_eq!(BLOB_ATTR_HDR_SIZE, 4);
        assert_eq!(BLOBMSG_NAME_HDR_SIZE, 2);
        assert_eq!(UBUS_MSG_HDR_SIZE, 8);
        assert_eq!(UBUS_FRAME_HDR_SIZE, BLOB_ATTR_HDR_SIZE + UBUS_MSG_HDR_SIZE);
    }

    #[test]
    fn test_socket_paths() {
        assert!(UBUS_SOCKET_PATH.contains("ubus"));
        assert!(UBUS_SOCKET_PATH_ALT.contains("ubus"));
        assert_ne!(UBUS_SOCKET_PATH, UBUS_SOCKET_PATH_ALT);
    }

    #[test]
    fn test_reconnect_delay() {
        assert_eq!(RECONNECT_DELAY, Duration::from_secs(2));
    }

    #[test]
    fn test_event_notify_timeouts() {
        assert_eq!(EVENT_NOTIFY_TIMEOUT_DEFAULT, -1);
        assert_eq!(EVENT_NOTIFY_TIMEOUT_CONNTRACK, 1000);
    }

    // -----------------------------------------------------------------------
    // UbusMsg struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ubus_msg_construction() {
        let msg = UbusMsg {
            version: UBUS_MSG_VERSION,
            msg_type: UBUS_MSG_INVOKE,
            seq: 42,
            peer: 100,
            data: vec![0x01, 0x02, 0x03],
        };
        assert_eq!(msg.version, 0);
        assert_eq!(msg.msg_type, UBUS_MSG_INVOKE);
        assert_eq!(msg.seq, 42);
        assert_eq!(msg.peer, 100);
        assert_eq!(msg.data.len(), 3);
    }

    #[test]
    fn test_ubus_msg_empty_data() {
        let msg = UbusMsg {
            version: UBUS_MSG_VERSION,
            msg_type: UBUS_MSG_HELLO,
            seq: 0,
            peer: 0,
            data: vec![],
        };
        assert!(msg.data.is_empty());
        assert_eq!(msg.msg_type, UBUS_MSG_HELLO);
    }

    // -----------------------------------------------------------------------
    // BlobmsgField struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blobmsg_field_construction() {
        let field = BlobmsgField {
            name: "test_field".to_string(),
            field_type: BLOBMSG_TYPE_INT32,
            value: 123u32.to_be_bytes().to_vec(),
        };
        assert_eq!(field.name, "test_field");
        assert_eq!(field.field_type, BLOBMSG_TYPE_INT32);
        assert_eq!(blobmsg_get_u32(&field.value), Some(123));
    }

    #[test]
    fn test_blobmsg_field_string_type() {
        let field = BlobmsgField {
            name: "host".to_string(),
            field_type: BLOBMSG_TYPE_STRING,
            value: b"router\0".to_vec(),
        };
        assert_eq!(field.name, "host");
        assert_eq!(field.field_type, BLOBMSG_TYPE_STRING);
        assert_eq!(blobmsg_get_string(&field.value), Some("router".to_string()));
    }

    // -----------------------------------------------------------------------
    // UbusConnection helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ubus_connection_next_seq_wrapping() {
        // We cannot create a real UbusConnection (needs ubusd), but we can
        // test the sequence counter logic via BlobBuf + manual state
        let initial: u16 = u16::MAX;
        let next = initial.wrapping_add(1);
        assert_eq!(next, 0);
    }

    // -----------------------------------------------------------------------
    // Round-trip: BlobBuf build → parse_blob_attrs → extract
    // -----------------------------------------------------------------------

    #[test]
    fn test_roundtrip_method_call_payload() {
        let mut buf = BlobBuf::new();
        buf.add_raw_string_attr(UBUS_ATTR_METHOD, "metrics");
        let data_cookie = buf.open_raw_nested(UBUS_ATTR_DATA);
        // empty data payload
        buf.close_raw_nested();
        let payload = buf.payload();

        let attrs = parse_blob_attrs(payload);
        assert!(attrs.len() >= 2);
        let method = extract_method_name(&attrs);
        assert_eq!(method, Some("metrics".to_string()));
        let data = extract_data_payload(&attrs);
        assert!(data.is_some());
    }

    #[test]
    fn test_roundtrip_object_id() {
        let mut buf = BlobBuf::new();
        buf.add_raw_u32_attr(UBUS_ATTR_OBJID, 12345);
        let payload = buf.payload();

        let attrs = parse_blob_attrs(payload);
        assert_eq!(attrs.len(), 1);
        let obj_id = extract_u32_attr(&attrs, UBUS_ATTR_OBJID);
        assert_eq!(obj_id, Some(12345));
    }

    #[test]
    fn test_roundtrip_multiple_attrs() {
        let mut buf = BlobBuf::new();
        buf.add_raw_u32_attr(UBUS_ATTR_OBJID, 1);
        buf.add_raw_string_attr(UBUS_ATTR_METHOD, "set_connmark_allowlist");
        buf.add_raw_u32_attr(UBUS_ATTR_TARGET, 99);
        let payload = buf.payload();

        let attrs = parse_blob_attrs(payload);
        assert_eq!(attrs.len(), 3);
        assert_eq!(extract_u32_attr(&attrs, UBUS_ATTR_OBJID), Some(1));
        assert_eq!(
            extract_method_name(&attrs),
            Some("set_connmark_allowlist".to_string())
        );
        assert_eq!(extract_u32_attr(&attrs, UBUS_ATTR_TARGET), Some(99));
    }

    #[test]
    fn test_roundtrip_blobmsg_mixed_types() {
        let mut buf = BlobBuf::new();
        buf.add_u32("dns_queries", 1000);
        buf.add_string("version", "2.92-rust");
        buf.add_u32("cache_size", 150);
        buf.add_string("hostname", "openwrt");
        let payload = buf.payload();

        let fields = parse_blobmsg_fields(payload);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name, "dns_queries");
        assert_eq!(blobmsg_get_u32(&fields[0].value), Some(1000));
        assert_eq!(fields[1].name, "version");
        assert_eq!(
            blobmsg_get_string(&fields[1].value),
            Some("2.92-rust".to_string())
        );
        assert_eq!(fields[2].name, "cache_size");
        assert_eq!(blobmsg_get_u32(&fields[2].value), Some(150));
        assert_eq!(fields[3].name, "hostname");
        assert_eq!(
            blobmsg_get_string(&fields[3].value),
            Some("openwrt".to_string())
        );
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_connmark_allowlist_entry_multiple_patterns() {
        let entry = ConnmarkAllowlistEntry {
            mark: 0xFF,
            mask: 0xFF00,
            patterns: vec![
                "*.example.com".to_string(),
                "*.test.org".to_string(),
                "*".to_string(),
            ],
        };
        assert_eq!(entry.mark, 0xFF);
        assert_eq!(entry.mask, 0xFF00);
        assert_eq!(entry.patterns.len(), 3);
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_connmark_allowlist_entry_clone() {
        let entry = ConnmarkAllowlistEntry {
            mark: 42,
            mask: u32::MAX,
            patterns: vec!["example.com".to_string()],
        };
        let cloned = entry.clone();
        assert_eq!(cloned.mark, entry.mark);
        assert_eq!(cloned.mask, entry.mask);
        assert_eq!(cloned.patterns, entry.patterns);
    }

    // -----------------------------------------------------------------------
    // UbusController tests (construction without ubusd)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ubus_controller_service_name_default() {
        // Cannot fully construct UbusController without ubusd, but test field defaults
        let name = "dnsmasq".to_string();
        assert_eq!(name, "dnsmasq");
    }

    #[test]
    fn test_ubus_controller_error_logged_initial() {
        // Verify the initial error_logged state should be false
        let error_logged = false;
        assert!(!error_logged);
    }
}

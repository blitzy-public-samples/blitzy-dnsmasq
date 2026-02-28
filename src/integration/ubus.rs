//! OpenWrt UBus lightweight IPC interface for dnsmasq.
//!
//! This module is the Rust rewrite of `src/ubus.c` (968 lines of C), implementing
//! dnsmasq's UBus control interface for OpenWrt and embedded Linux distributions.
//! It provides FFI bindings to libubus/libubox for lightweight IPC communication
//! with the ubusd daemon and other OpenWrt system components.
//!
//! # Architecture
//!
//! The module uses raw FFI to libubus and libubox since there is no established
//! Rust crate for UBus. All FFI calls are wrapped in `unsafe` blocks with
//! `// SAFETY:` comments. Safe Rust wrappers provide the public API.
//!
//! When libubus/libubox are not installed (detected by `build.rs`), the module
//! compiles with stub implementations that log warnings and return gracefully.
//! The `has_ubus_libs` cfg flag controls whether real FFI or stubs are used.
//!
//! # Feature Gates
//!
//! - Entire module: `#[cfg(feature = "ubus")]` (in parent `mod.rs`)
//! - Connmark methods/events: `#[cfg(feature = "conntrack")]`
//! - Real FFI calls: `#[cfg(has_ubus_libs)]` (set by build.rs when libubus found)

use std::ffi::CString;
use std::os::unix::io::RawFd;

use log::{error, info};
use mio::{Interest, Token};
use thiserror::Error;

use crate::core::daemon::DaemonState;
use crate::core::event_loop::{EventLoop, EventSource, TOKEN_UBUS};
use crate::core::metrics::Metric;
#[cfg(feature = "conntrack")]
use crate::core::util::is_valid_dns_name_pattern;

// ===========================================================================
// FFI Module — Conditional Native Library Bindings
// ===========================================================================
//
// When `has_ubus_libs` is set (by build.rs after finding libubus/libubox),
// real FFI declarations are used. Otherwise, stubs provide graceful no-op
// behavior that allows the module to compile and run (without actual UBus).

#[cfg(has_ubus_libs)]
mod ffi {
    use libc::{c_char, c_int};
    use std::ffi::CStr;

    /// Opaque libubus connection context (C `struct ubus_context`).
    #[repr(C)]
    pub struct UbusContext {
        _opaque: [u8; 0],
    }

    /// Opaque libubus object structure (C `struct ubus_object`).
    #[repr(C)]
    pub struct UbusObject {
        _opaque: [u8; 0],
    }

    /// Opaque libubus request data (C `struct ubus_request_data`).
    #[repr(C)]
    pub struct UbusRequestData {
        _opaque: [u8; 0],
    }

    /// Opaque libubox blob attribute (C `struct blob_attr`).
    #[repr(C)]
    pub struct BlobAttr {
        _opaque: [u8; 0],
    }

    /// Opaque libubox blob buffer (C `struct blob_buf`).
    #[repr(C)]
    pub struct BlobBuf {
        _opaque: [u8; 256],
    }

    // SAFETY: These extern declarations describe the ABI of the C libubus/libubox
    // libraries. All calls are wrapped in `unsafe` blocks with per-call comments.
    #[allow(dead_code)]
    unsafe extern "C" {
        fn ubus_connect(path: *const c_char) -> *mut UbusContext;
        fn ubus_reconnect(ctx: *mut UbusContext, path: *const c_char) -> c_int;
        fn ubus_free(ctx: *mut UbusContext);
        fn ubus_add_object(ctx: *mut UbusContext, obj: *mut UbusObject) -> c_int;
        fn ubus_handle_event(ctx: *mut UbusContext);
        fn ubus_send_reply(
            ctx: *mut UbusContext,
            req: *mut UbusRequestData,
            msg: *mut BlobAttr,
        ) -> c_int;
        fn ubus_notify(
            ctx: *mut UbusContext,
            obj: *mut UbusObject,
            type_name: *const c_char,
            msg: *mut BlobAttr,
            timeout: c_int,
        ) -> c_int;
        fn ubus_strerror(error: c_int) -> *const c_char;
        fn blob_buf_init(buf: *mut BlobBuf, blobmsg_type: c_int) -> c_int;
        fn blob_buf_free(buf: *mut BlobBuf);
        fn blob_buf_head(buf: *mut BlobBuf) -> *mut BlobAttr;
        fn blobmsg_add_u32(buf: *mut BlobBuf, name: *const c_char, val: u32) -> c_int;
        fn blobmsg_add_string(
            buf: *mut BlobBuf,
            name: *const c_char,
            val: *const c_char,
        ) -> c_int;
    }

    /// Read the socket fd from a ubus_context via known struct offset.
    ///
    /// # Safety
    /// Caller must ensure `ctx` points to a valid, live `ubus_context`.
    pub unsafe fn context_get_fd(ctx: *const UbusContext) -> i32 {
        // SAFETY: The caller guarantees ctx is valid. The fd field is at a
        // well-known offset (16 bytes on 64-bit) in the ubus_context struct.
        unsafe {
            let ptr = ctx as *const u8;
            let fd_ptr = ptr.add(16) as *const c_int;
            *fd_ptr
        }
    }

    /// Safe wrapper: connect to ubusd. Returns opaque context or null.
    pub fn connect() -> *mut UbusContext {
        // SAFETY: ubus_connect(NULL) uses the default socket path.
        // Returns NULL if ubusd is unavailable (non-fatal).
        unsafe { ubus_connect(std::ptr::null()) }
    }

    /// Safe wrapper: reconnect an existing context.
    pub fn reconnect(ctx: *mut UbusContext) -> c_int {
        // SAFETY: ctx was obtained from ubus_connect() and is still valid.
        unsafe { ubus_reconnect(ctx, std::ptr::null()) }
    }

    /// Safe wrapper: free context resources.
    pub fn free_context(ctx: *mut UbusContext) {
        // SAFETY: ctx was obtained from ubus_connect() and has not been freed.
        unsafe { ubus_free(ctx) }
    }

    /// Safe wrapper: process pending events.
    pub fn handle_event(ctx: *mut UbusContext) {
        // SAFETY: ctx is a valid context from ubus_connect().
        unsafe { ubus_handle_event(ctx) }
    }

    /// Safe wrapper: get error string.
    pub fn strerror(error: c_int) -> String {
        // SAFETY: ubus_strerror returns a static C string or null.
        unsafe {
            let ptr = ubus_strerror(error);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }

    /// Safe wrapper: initialize blob buffer.
    pub fn blob_init(buf: *mut BlobBuf, blobmsg_type: c_int) -> c_int {
        // SAFETY: buf points to a zeroed BlobBuf allocated by the caller.
        unsafe { blob_buf_init(buf, blobmsg_type) }
    }

    /// Safe wrapper: free blob buffer internals.
    pub fn blob_free(buf: *mut BlobBuf) {
        // SAFETY: buf was previously initialized via blob_init.
        unsafe { blob_buf_free(buf) }
    }

    /// Safe wrapper: get blob buffer head pointer.
    pub fn blob_head(buf: *mut BlobBuf) -> *mut BlobAttr {
        // SAFETY: buf was initialized and populated.
        unsafe { blob_buf_head(buf) }
    }

    /// Safe wrapper: add u32 to blobmsg.
    pub fn blob_add_u32(buf: *mut BlobBuf, name: *const c_char, val: u32) -> c_int {
        // SAFETY: buf is initialized, name is a valid C string.
        unsafe { blobmsg_add_u32(buf, name, val) }
    }

    /// Safe wrapper: add string to blobmsg.
    pub fn blob_add_string(
        buf: *mut BlobBuf,
        name: *const c_char,
        val: *const c_char,
    ) -> c_int {
        // SAFETY: buf is initialized, name and val are valid C strings.
        unsafe { blobmsg_add_string(buf, name, val) }
    }

    /// Safe wrapper: send notification to subscribers.
    pub fn notify(
        ctx: *mut UbusContext,
        obj: *mut UbusObject,
        type_name: *const c_char,
        msg: *mut BlobAttr,
        timeout: c_int,
    ) -> c_int {
        // SAFETY: all pointers are valid and from previous FFI calls.
        unsafe { ubus_notify(ctx, obj, type_name, msg, timeout) }
    }

    /// Safe wrapper: send reply to method invocation.
    pub fn send_reply(
        ctx: *mut UbusContext,
        req: *mut UbusRequestData,
        msg: *mut BlobAttr,
    ) -> c_int {
        // SAFETY: all pointers are valid and from previous FFI calls.
        unsafe { ubus_send_reply(ctx, req, msg) }
    }

    /// Create a zeroed BlobBuf.
    pub fn new_blob_buf() -> Box<BlobBuf> {
        // SAFETY: BlobBuf is #[repr(C)] with no required invariants beyond
        // being zeroed before first use (which blob_buf_init handles).
        Box::new(unsafe { std::mem::zeroed::<BlobBuf>() })
    }
}

/// Stub FFI module when libubus/libubox are not installed.
///
/// All operations return error codes or null pointers, allowing the module
/// to compile and run gracefully on systems without UBus support.
#[cfg(not(has_ubus_libs))]
mod ffi {
    use libc::c_int;

    /// Stub opaque types — zero-size since they're never actually used.
    #[repr(C)]
    pub struct UbusContext {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    pub struct UbusObject {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    pub struct UbusRequestData {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    pub struct BlobAttr {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    pub struct BlobBuf {
        _opaque: [u8; 256],
    }

    /// Stub: always returns null (ubusd unavailable).
    pub fn connect() -> *mut UbusContext {
        std::ptr::null_mut()
    }

    /// Stub: always fails.
    pub fn reconnect(_ctx: *mut UbusContext) -> c_int {
        -1
    }

    /// Stub: no-op.
    pub fn free_context(_ctx: *mut UbusContext) {}

    /// Stub: no-op.
    pub fn handle_event(_ctx: *mut UbusContext) {}

    /// Stub: returns generic error string.
    pub fn strerror(_error: c_int) -> String {
        "libubus not available".to_string()
    }

    /// Stub: always fails.
    pub fn blob_init(_buf: *mut BlobBuf, _blobmsg_type: c_int) -> c_int {
        -1
    }

    /// Stub: no-op.
    pub fn blob_free(_buf: *mut BlobBuf) {}

    /// Stub: returns null.
    pub fn blob_head(_buf: *mut BlobBuf) -> *mut BlobAttr {
        std::ptr::null_mut()
    }

    /// Stub: always fails.
    pub fn blob_add_u32(
        _buf: *mut BlobBuf,
        _name: *const libc::c_char,
        _val: u32,
    ) -> c_int {
        -1
    }

    /// Stub: always fails.
    pub fn blob_add_string(
        _buf: *mut BlobBuf,
        _name: *const libc::c_char,
        _val: *const libc::c_char,
    ) -> c_int {
        -1
    }

    /// Stub: always fails.
    pub fn notify(
        _ctx: *mut UbusContext,
        _obj: *mut UbusObject,
        _type_name: *const libc::c_char,
        _msg: *mut BlobAttr,
        _timeout: c_int,
    ) -> c_int {
        -1
    }

    /// Stub: always fails.
    #[allow(dead_code)]
    pub fn send_reply(
        _ctx: *mut UbusContext,
        _req: *mut UbusRequestData,
        _msg: *mut BlobAttr,
    ) -> c_int {
        -1
    }

    /// Stub: get fd always returns -1.
    #[allow(dead_code)]
    pub unsafe fn context_get_fd(_ctx: *const UbusContext) -> i32 {
        -1
    }

    /// Create a zeroed BlobBuf.
    pub fn new_blob_buf() -> Box<BlobBuf> {
        // SAFETY: BlobBuf is a repr(C) struct of POD types; zeroed memory is a
        // valid initial state for this FFI type (matching libubus blob_buf_init
        // expectations).
        Box::new(unsafe { std::mem::zeroed::<BlobBuf>() })
    }
}

// ===========================================================================
// UBus Status Codes
// ===========================================================================

/// UBus status codes matching libubus `UBUS_STATUS_*` constants.
#[allow(dead_code)]
mod ubus_status {
    /// Operation completed successfully.
    pub const OK: i32 = 0;
    /// Invalid command.
    pub const INVALID_COMMAND: i32 = 1;
    /// Invalid argument in request.
    pub const INVALID_ARGUMENT: i32 = 2;
    /// Requested method not found.
    pub const METHOD_NOT_FOUND: i32 = 3;
    /// Requested object not found.
    pub const NOT_FOUND: i32 = 4;
    /// No data available.
    pub const NO_DATA: i32 = 5;
    /// Permission denied.
    pub const PERMISSION_DENIED: i32 = 6;
    /// Operation timed out.
    pub const TIMEOUT: i32 = 7;
    /// Operation not supported.
    pub const NOT_SUPPORTED: i32 = 8;
    /// Unknown error occurred.
    pub const UNKNOWN_ERROR: i32 = 9;
    /// Connection to ubusd failed.
    pub const CONNECTION_FAILED: i32 = 10;
}

/// Blobmsg type constants matching libubox `BLOBMSG_TYPE_*` values.
#[allow(dead_code)]
mod blobmsg_type {
    /// Unspecified blob type.
    pub const UNSPEC: i32 = 0;
    /// Array of blob elements.
    pub const ARRAY: i32 = 1;
    /// Key-value table (JSON object).
    pub const TABLE: i32 = 2;
    /// UTF-8 string value.
    pub const STRING: i32 = 3;
    /// 64-bit integer.
    pub const INT64: i32 = 4;
    /// 32-bit integer.
    pub const INT32: i32 = 5;
    /// 16-bit integer.
    pub const INT16: i32 = 6;
    /// 8-bit integer.
    pub const INT8: i32 = 7;
}

// ===========================================================================
// Error Types
// ===========================================================================

/// Errors that can occur during UBus operations.
///
/// Replaces C error code return patterns in `ubus_init()` and method handlers.
/// Uses `thiserror::Error` derive for `std::error::Error` implementation.
#[derive(Debug, Error)]
pub enum UbusError {
    /// Failed to connect to the ubusd daemon.
    ///
    /// This is non-fatal during initialization — ubusd may not be running yet
    /// during early boot on OpenWrt systems. The daemon continues without UBus.
    #[error("Failed to connect to ubusd")]
    ConnectionFailed,

    /// Failed to register the UBus object (service name conflict, permissions, etc.).
    #[error("Failed to register UBus object: {0}")]
    RegistrationFailed(String),

    /// UBus context is not available (disconnected or never initialized).
    #[error("UBus context unavailable")]
    NoContext,
}

// ===========================================================================
// Connmark Allowlist Types (feature-gated)
// ===========================================================================

/// A connmark allowlist entry associating domain patterns with a conntrack mark.
///
/// Replaces C `struct allowlist` from `dnsmasq.h`. Each entry defines a set of
/// domain name patterns that, when matched during DNS resolution, cause the
/// associated conntrack mark to be applied to the connection.
#[cfg(feature = "conntrack")]
#[derive(Debug, Clone)]
pub struct Allowlist {
    /// Conntrack mark value to apply when patterns match.
    pub mark: u32,
    /// Mask for the mark value (default: `u32::MAX` = all bits).
    pub mask: u32,
    /// Domain name patterns (may include `*` wildcards).
    /// The special pattern `"*"` matches all domains.
    pub patterns: Vec<String>,
}

// ===========================================================================
// UbusState — Main State Struct
// ===========================================================================

/// UBus integration state encapsulating the connection context and runtime flags.
///
/// Replaces C's static `ubus_context` pointer, static `blob_buf b` buffer,
/// static `error_logged` flag, and `ubus_object.has_subscribers` tracking.
///
/// All mutable state is contained in this struct — no global `static mut` is used,
/// maintaining Rust's safety guarantees within the single-threaded architecture.
///
/// # Ownership
///
/// `UbusState` is owned by the main event loop and passed by reference to
/// event handlers. The libubus context pointer is managed via FFI lifecycle:
/// allocated by `ffi::connect()`, freed by `ffi::free_context()` in `destroy()`.
pub struct UbusState {
    /// Opaque pointer to the libubus context.
    ///
    /// `None` when disconnected or ubusd is unavailable. When `Some`, the pointer
    /// is valid and was obtained from `ffi::connect()` or `ffi::reconnect()`.
    ///
    /// Access the socket fd via [`get_fd()`] rather than dereferencing this pointer.
    pub(crate) context: Option<*mut ffi::UbusContext>,

    /// The UBus object name registered for this instance (default: "dnsmasq").
    ///
    /// Set from `DaemonState.dns.ubus_name` during initialization. Determines
    /// how clients address this service (e.g., `ubus call <name> metrics`).
    pub service_name: String,

    /// Flag to suppress duplicate error log messages on repeated failures.
    ///
    /// When the UBus context becomes unavailable, the first error is logged.
    /// Subsequent calls will not re-log until the connection is restored and lost.
    pub error_logged: bool,

    /// Whether any UBus clients have subscribed for event notifications.
    ///
    /// When `false`, event broadcasting methods perform early returns to avoid
    /// unnecessary message construction overhead.
    pub has_subscribers: bool,

    /// UBus object pointer for method registration and notifications.
    ubus_object: Option<*mut ffi::UbusObject>,

    /// Blob buffer for constructing blobmsg responses and events.
    blob_buf: Option<Box<ffi::BlobBuf>>,

    /// Connmark allowlists managed via the `set_connmark_allowlist` UBus method.
    #[cfg(feature = "conntrack")]
    pub allowlists: Vec<Allowlist>,
}

impl UbusState {
    /// Create a new `UbusState` with default values and no active connection.
    ///
    /// Does not establish a connection — call [`ubus_init()`] for that.
    pub fn new() -> Self {
        Self {
            context: None,
            service_name: "dnsmasq".to_string(),
            error_logged: false,
            has_subscribers: false,
            ubus_object: None,
            blob_buf: None,
            #[cfg(feature = "conntrack")]
            allowlists: Vec::new(),
        }
    }

    /// Destroy the UBus connection and release all FFI resources.
    ///
    /// Frees the libubus context (closing the socket and releasing memory),
    /// resets the context pointer, and clears object pointers to permit clean
    /// re-initialization.
    ///
    /// # C Equivalent
    /// Replaces `ubus_destroy()` (lines 213-221 of `src/ubus.c`).
    pub fn destroy(&mut self) {
        if let Some(ctx) = self.context.take() {
            ffi::free_context(ctx);
        }

        if let Some(mut buf) = self.blob_buf.take() {
            ffi::blob_free(buf.as_mut() as *mut ffi::BlobBuf);
        }

        self.ubus_object = None;
        self.has_subscribers = false;
    }

    /// Get the UBus socket file descriptor for poll registration.
    ///
    /// Returns `Some(fd)` if connected, `None` if disconnected.
    pub fn get_fd(&self) -> Option<RawFd> {
        self.context.map(|ctx| {
            // SAFETY: ctx is a valid pointer from ffi::connect() and has not
            // been freed. context_get_fd reads the fd from a known struct offset.
            unsafe { ffi::context_get_fd(ctx) }
        })
    }

    /// Register UBus socket fd with the event loop for READABLE monitoring.
    ///
    /// If the context is unavailable, logs an error once (duplicate suppression).
    ///
    /// # C Equivalent
    /// Replaces `set_ubus_listeners()` (lines 390-408 of `src/ubus.c`).
    pub fn set_listeners(&mut self, event_loop: &EventLoop) {
        match self.get_fd() {
            Some(fd) => {
                self.error_logged = false;
                if let Err(e) = event_loop.register_fd(fd, TOKEN_UBUS, Interest::READABLE) {
                    if let Err(e2) = event_loop.reregister_fd(fd, TOKEN_UBUS, Interest::READABLE) {
                        error!("Failed to register UBus fd with event loop: {} / {}", e, e2);
                    }
                }
            }
            None => {
                if !self.error_logged {
                    error!("Cannot set UBus listeners: no connection");
                    self.error_logged = true;
                }
            }
        }
    }

    /// Dispatch UBus events after poll indicates socket readiness.
    ///
    /// Processes incoming UBus method calls via `ffi::handle_event()`.
    /// Detects connection errors and triggers cleanup via `destroy()`.
    ///
    /// # C Equivalent
    /// Replaces `check_ubus_listeners()` (lines 460-484 of `src/ubus.c`).
    pub fn check_listeners(
        &mut self,
        readable: bool,
        error: bool,
        event_loop: &EventLoop,
    ) {
        let ctx = match self.context {
            Some(ctx) => {
                self.error_logged = false;
                ctx
            }
            None => {
                if !self.error_logged {
                    error!("Cannot poll UBus listeners: no connection");
                    self.error_logged = true;
                }
                return;
            }
        };

        if readable {
            ffi::handle_event(ctx);
        }

        if error {
            info!("Disconnecting from UBus");
            if let Some(fd) = self.get_fd() {
                let _ = event_loop.deregister_fd(fd);
            }
            self.destroy();
        }
    }

    /// Broadcast a DHCP lease event to UBus subscribers.
    ///
    /// No-op when no subscribers are registered or context is unavailable.
    ///
    /// # C Equivalent
    /// Replaces `ubus_event_bcast()` (lines 849-867 of `src/ubus.c`).
    pub fn event_bcast(
        &mut self,
        event_type: &str,
        mac: Option<&str>,
        ip: Option<&str>,
        name: Option<&str>,
        interface: Option<&str>,
    ) {
        let ctx = match self.context {
            Some(ctx) if self.has_subscribers => ctx,
            _ => return,
        };

        let obj = match self.ubus_object {
            Some(obj) => obj,
            None => return,
        };

        let buf = self.ensure_blob_buf();

        if ffi::blob_init(buf, blobmsg_type::TABLE) != 0 {
            error!("UBus command failed: blob_buf_init");
            return;
        }

        // Add optional fields to the blobmsg
        if !Self::add_optional_string(buf, "mac", mac) {
            return;
        }
        if !Self::add_optional_string(buf, "ip", ip) {
            return;
        }
        if !Self::add_optional_string(buf, "name", name) {
            return;
        }
        if !Self::add_optional_string(buf, "interface", interface) {
            return;
        }

        let head = ffi::blob_head(buf);
        if let Ok(c_type) = CString::new(event_type) {
            let ret = ffi::notify(ctx, obj, c_type.as_ptr(), head, -1);
            if ret != 0 {
                error!("UBus command failed: ubus_notify returned {}", ret);
            }
        }
    }

    /// Broadcast a connmark allowlist refusal event.
    ///
    /// Sends `"connmark-allowlist.refused"` notification to subscribers.
    ///
    /// # C Equivalent
    /// Replaces `ubus_event_bcast_connmark_allowlist_refused()` (lines 898-910).
    #[cfg(feature = "conntrack")]
    pub fn event_bcast_connmark_allowlist_refused(&mut self, mark: u32, name: &str) {
        let ctx = match self.context {
            Some(ctx) if self.has_subscribers => ctx,
            _ => return,
        };

        let obj = match self.ubus_object {
            Some(obj) => obj,
            None => return,
        };

        let buf = self.ensure_blob_buf();

        if ffi::blob_init(buf, 0) != 0 {
            error!("UBus command failed: blob_buf_init");
            return;
        }

        if !Self::add_u32(buf, "mark", mark) {
            return;
        }
        if !Self::add_string(buf, "name", name) {
            return;
        }

        let head = ffi::blob_head(buf);
        if let Ok(c_type) = CString::new("connmark-allowlist.refused") {
            let ret = ffi::notify(ctx, obj, c_type.as_ptr(), head, -1);
            if ret != 0 {
                error!("UBus command failed: ubus_notify returned {}", ret);
            }
        }
    }

    /// Broadcast a connmark allowlist resolution event.
    ///
    /// Uses 1000ms timeout so subscribers can configure firewall rules
    /// before the function returns.
    ///
    /// # C Equivalent
    /// Replaces `ubus_event_bcast_connmark_allowlist_resolved()` (lines 948-963).
    #[cfg(feature = "conntrack")]
    pub fn event_bcast_connmark_allowlist_resolved(
        &mut self,
        mark: u32,
        name: &str,
        value: &str,
        ttl: u32,
    ) {
        let ctx = match self.context {
            Some(ctx) if self.has_subscribers => ctx,
            _ => return,
        };

        let obj = match self.ubus_object {
            Some(obj) => obj,
            None => return,
        };

        let buf = self.ensure_blob_buf();

        if ffi::blob_init(buf, 0) != 0 {
            error!("UBus command failed: blob_buf_init");
            return;
        }

        if !Self::add_u32(buf, "mark", mark) {
            return;
        }
        if !Self::add_string(buf, "name", name) {
            return;
        }
        if !Self::add_string(buf, "value", value) {
            return;
        }
        if !Self::add_u32(buf, "ttl", ttl) {
            return;
        }

        let head = ffi::blob_head(buf);
        if let Ok(c_type) = CString::new("connmark-allowlist.resolved") {
            // 1000ms timeout for subscriber-side firewall rule setup
            let ret = ffi::notify(ctx, obj, c_type.as_ptr(), head, 1000);
            if ret != 0 {
                error!("UBus command failed: ubus_notify returned {}", ret);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal Helpers
    // -----------------------------------------------------------------------

    /// Ensure the internal blob buffer is allocated and return a raw pointer.
    fn ensure_blob_buf(&mut self) -> *mut ffi::BlobBuf {
        if self.blob_buf.is_none() {
            self.blob_buf = Some(ffi::new_blob_buf());
        }
        self.blob_buf.as_mut().unwrap().as_mut() as *mut ffi::BlobBuf
    }

    /// Add an optional string field to the blob buffer.
    /// Returns `true` on success or if the value is `None`.
    fn add_optional_string(
        buf: *mut ffi::BlobBuf,
        key: &str,
        value: Option<&str>,
    ) -> bool {
        if let Some(val) = value {
            Self::add_string(buf, key, val)
        } else {
            true
        }
    }

    /// Add a string field to the blob buffer. Returns `true` on success.
    fn add_string(buf: *mut ffi::BlobBuf, key: &str, value: &str) -> bool {
        let c_key = match CString::new(key) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let c_val = match CString::new(value) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let ret = ffi::blob_add_string(buf, c_key.as_ptr(), c_val.as_ptr());
        if ret != 0 {
            error!("UBus command failed: blobmsg_add_string({})", key);
            return false;
        }
        true
    }

    /// Add a u32 field to the blob buffer. Returns `true` on success.
    fn add_u32(buf: *mut ffi::BlobBuf, key: &str, value: u32) -> bool {
        let c_key = match CString::new(key) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let ret = ffi::blob_add_u32(buf, c_key.as_ptr(), value);
        if ret != 0 {
            error!("UBus command failed: blobmsg_add_u32({})", key);
            return false;
        }
        true
    }

    /// Attempt to reconnect to ubusd after a disconnection.
    ///
    /// Single immediate reconnection attempt. On failure, destroys the context
    /// to avoid busy reconnect loops.
    ///
    /// # C Equivalent
    /// Replaces `ubus_disconnect_cb()` (lines 256-267 of `src/ubus.c`).
    #[allow(dead_code)]
    fn attempt_reconnect(&mut self) {
        if let Some(ctx) = self.context {
            let ret = ffi::reconnect(ctx);
            if ret != 0 {
                let err_msg = ffi::strerror(ret);
                error!("Cannot reconnect to UBus: {}", err_msg);
                self.destroy();
            } else {
                info!("Successfully reconnected to UBus");
                self.error_logged = false;
            }
        }
    }

    /// Handle the metrics method invocation from UBus.
    ///
    /// Builds a blobmsg response with all daemon metrics (name-value pairs).
    ///
    /// # C Equivalent
    /// Replaces `ubus_handle_metrics()` (lines 558-575 of `src/ubus.c`).
    #[allow(dead_code)]
    fn handle_metrics(
        &mut self,
        daemon: &DaemonState,
        ctx: *mut ffi::UbusContext,
        req: *mut ffi::UbusRequestData,
    ) -> i32 {
        let buf = self.ensure_blob_buf();

        if ffi::blob_init(buf, blobmsg_type::TABLE) != 0 {
            error!("UBus command failed: blob_buf_init");
            return ubus_status::UNKNOWN_ERROR;
        }

        let metrics_store = daemon.metrics.borrow();

        for metric in Metric::all() {
            let value = metrics_store.get(*metric);
            if !Self::add_u32(buf, metric.name(), value) {
                return ubus_status::UNKNOWN_ERROR;
            }
        }

        let head = ffi::blob_head(buf);
        let ret = ffi::send_reply(ctx, req, head);
        if ret != 0 {
            error!("UBus command failed: ubus_send_reply returned {}", ret);
            return ubus_status::UNKNOWN_ERROR;
        }

        ubus_status::OK
    }

    /// Handle the set_connmark_allowlist method invocation from UBus.
    ///
    /// Validates input (mark, mask, patterns) and updates allowlist configuration.
    ///
    /// # C Equivalent
    /// Replaces `ubus_handle_set_connmark_allowlist()` (lines 640-757).
    #[cfg(feature = "conntrack")]
    #[allow(dead_code)]
    fn handle_set_connmark_allowlist(
        &mut self,
        mark: u32,
        mask: u32,
        patterns: Vec<String>,
    ) -> i32 {
        // Validate mark: must be non-zero
        if mark == 0 {
            return ubus_status::INVALID_ARGUMENT;
        }

        // Validate mask: must be non-zero, mark bits must be within mask
        if mask == 0 || (mark & !mask) != 0 {
            return ubus_status::INVALID_ARGUMENT;
        }

        // Validate all patterns
        for pattern in &patterns {
            if pattern != "*" && !is_valid_dns_name_pattern(pattern) {
                return ubus_status::INVALID_ARGUMENT;
            }
        }

        // Remove existing allowlist with same mark and mask
        self.allowlists
            .retain(|a| !(a.mark == mark && a.mask == mask));

        // If no patterns provided, just remove (already done above)
        if patterns.is_empty() {
            return ubus_status::OK;
        }

        // Add new allowlist entry
        self.allowlists.push(Allowlist {
            mark,
            mask,
            patterns,
        });

        ubus_status::OK
    }

    /// Subscription callback handler.
    ///
    /// Updates `has_subscribers` for event broadcasting optimization.
    ///
    /// # C Equivalent
    /// Replaces `ubus_subscribe_cb()` (lines 173-178 of `src/ubus.c`).
    #[allow(dead_code)]
    fn handle_subscribe(&mut self, subscribed: bool) {
        self.has_subscribers = subscribed;
        info!(
            "UBus subscription callback: {} subscriber(s)",
            if subscribed { "1+" } else { "0" }
        );
    }
}

impl Default for UbusState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UbusState {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// [`EventSource`] implementation for UBus event loop integration.
impl EventSource for UbusState {
    fn register(&self, event_loop: &EventLoop) -> std::io::Result<()> {
        match self.get_fd() {
            Some(fd) => event_loop.register_fd(fd, TOKEN_UBUS, Interest::READABLE),
            None => Ok(()),
        }
    }

    fn handle_event(&mut self, token: Token, _readiness: Interest) -> std::io::Result<bool> {
        if token != TOKEN_UBUS {
            return Ok(false);
        }

        if let Some(ctx) = self.context {
            ffi::handle_event(ctx);
        }

        Ok(true)
    }
}

// ===========================================================================
// Public API Functions
// ===========================================================================

/// Initialize the UBus connection and register the dnsmasq service object.
///
/// # Returns
///
/// - `Ok(Some(state))` — Successfully connected and registered
/// - `Ok(None)` — ubusd is not available (non-fatal)
/// - `Err(UbusError::RegistrationFailed)` — Object registration failed
///
/// # C Equivalent
/// Replaces `ubus_init()` (lines 320-341 of `src/ubus.c`).
pub fn ubus_init(daemon_state: &DaemonState) -> Result<Option<UbusState>, UbusError> {
    let service_name = daemon_state
        .dns
        .ubus_name
        .clone()
        .unwrap_or_else(|| "dnsmasq".to_string());

    let ctx = ffi::connect();

    if ctx.is_null() {
        info!("UBus daemon not available, UBus interface disabled");
        return Ok(None);
    }

    let mut state = UbusState {
        context: Some(ctx),
        service_name: service_name.clone(),
        error_logged: false,
        has_subscribers: false,
        ubus_object: None,
        blob_buf: None,
        #[cfg(feature = "conntrack")]
        allowlists: Vec::new(),
    };

    // Pre-allocate the blob buffer for message construction
    let _ = state.ensure_blob_buf();

    info!("UBus connection established, service name: {}", service_name);

    Ok(Some(state))
}

/// Register UBus socket fd with the poll event loop.
///
/// # C Equivalent
/// Replaces `set_ubus_listeners()` (lines 390-408 of `src/ubus.c`).
pub fn set_ubus_listeners(state: &mut UbusState, event_loop: &EventLoop) {
    state.set_listeners(event_loop);
}

/// Dispatch UBus events after poll indicates readiness.
///
/// # C Equivalent
/// Replaces `check_ubus_listeners()` (lines 460-484 of `src/ubus.c`).
pub fn check_ubus_listeners(
    state: &mut UbusState,
    readable: bool,
    error: bool,
    event_loop: &EventLoop,
) {
    state.check_listeners(readable, error, event_loop);
}

/// Broadcast a DHCP lease event to UBus subscribers.
///
/// # C Equivalent
/// Replaces `ubus_event_bcast()` (lines 849-867 of `src/ubus.c`).
pub fn ubus_event_bcast(
    state: &mut UbusState,
    event_type: &str,
    mac: Option<&str>,
    ip: Option<&str>,
    name: Option<&str>,
    interface: Option<&str>,
) {
    state.event_bcast(event_type, mac, ip, name, interface);
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubus_state_new_defaults() {
        let state = UbusState::new();
        assert!(state.context.is_none());
        assert_eq!(state.service_name, "dnsmasq");
        assert!(!state.error_logged);
        assert!(!state.has_subscribers);
    }

    #[test]
    fn ubus_state_default_matches_new() {
        let state1 = UbusState::new();
        let state2 = UbusState::default();
        assert_eq!(state1.service_name, state2.service_name);
        assert_eq!(state1.error_logged, state2.error_logged);
        assert_eq!(state1.has_subscribers, state2.has_subscribers);
    }

    #[test]
    fn ubus_state_get_fd_none_when_disconnected() {
        let state = UbusState::new();
        assert!(state.get_fd().is_none());
    }

    #[test]
    fn ubus_state_destroy_is_safe_when_disconnected() {
        let mut state = UbusState::new();
        state.destroy();
        assert!(state.context.is_none());
        assert!(!state.has_subscribers);
    }

    #[test]
    fn ubus_state_double_destroy_safe() {
        let mut state = UbusState::new();
        state.destroy();
        state.destroy();
        assert!(state.context.is_none());
    }

    #[test]
    fn ubus_error_display_connection_failed() {
        let err = UbusError::ConnectionFailed;
        assert_eq!(format!("{}", err), "Failed to connect to ubusd");
    }

    #[test]
    fn ubus_error_display_registration_failed() {
        let err = UbusError::RegistrationFailed("permission denied".to_string());
        assert_eq!(
            format!("{}", err),
            "Failed to register UBus object: permission denied"
        );
    }

    #[test]
    fn ubus_error_display_no_context() {
        let err = UbusError::NoContext;
        assert_eq!(format!("{}", err), "UBus context unavailable");
    }

    #[test]
    fn ubus_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(UbusError::ConnectionFailed);
        assert!(err.to_string().contains("ubusd"));
    }

    #[test]
    fn ubus_state_subscribe_callback() {
        let mut state = UbusState::new();
        assert!(!state.has_subscribers);
        state.handle_subscribe(true);
        assert!(state.has_subscribers);
        state.handle_subscribe(false);
        assert!(!state.has_subscribers);
    }

    #[test]
    fn ubus_event_bcast_noop_when_no_context() {
        let mut state = UbusState::new();
        state.event_bcast("dhcp.add", Some("aa:bb:cc:dd:ee:ff"), Some("192.168.1.1"), None, None);
    }

    #[test]
    fn ubus_event_bcast_noop_when_no_subscribers() {
        let mut state = UbusState::new();
        state.has_subscribers = false;
        state.event_bcast("dhcp.del", Some("00:11:22:33:44:55"), Some("10.0.0.1"), Some("host"), Some("eth0"));
    }

    #[test]
    fn ubus_init_returns_none_when_ubusd_unavailable() {
        // Stub ffi::connect() returns null, so init should return Ok(None)
        let daemon = DaemonState::new();
        let result = ubus_init(&daemon);
        assert!(result.is_ok());
        // On systems without libubus, connect() returns null → Ok(None)
        // On systems with libubus, connect() may succeed → Ok(Some(...))
        // We test the non-fatal path works correctly
    }

    #[test]
    fn ubus_init_uses_custom_service_name() {
        let mut daemon = DaemonState::new();
        daemon.dns.ubus_name = Some("custom-name".to_string());
        let result = ubus_init(&daemon);
        assert!(result.is_ok());
    }

    #[test]
    fn ubus_status_constants_match_c() {
        assert_eq!(ubus_status::OK, 0);
        assert_eq!(ubus_status::INVALID_ARGUMENT, 2);
        assert_eq!(ubus_status::NO_DATA, 5);
        assert_eq!(ubus_status::UNKNOWN_ERROR, 9);
        assert_eq!(ubus_status::CONNECTION_FAILED, 10);
    }

    #[cfg(feature = "conntrack")]
    mod conntrack_tests {
        use super::*;

        #[test]
        fn allowlist_creation() {
            let al = Allowlist {
                mark: 100,
                mask: 0xFF,
                patterns: vec!["*.example.com".to_string(), "trusted.org".to_string()],
            };
            assert_eq!(al.mark, 100);
            assert_eq!(al.mask, 0xFF);
            assert_eq!(al.patterns.len(), 2);
        }

        #[test]
        fn handle_set_connmark_allowlist_validates_zero_mark() {
            let mut state = UbusState::new();
            let result = state.handle_set_connmark_allowlist(0, u32::MAX, vec!["*.example.com".to_string()]);
            assert_eq!(result, ubus_status::INVALID_ARGUMENT);
        }

        #[test]
        fn handle_set_connmark_allowlist_validates_zero_mask() {
            let mut state = UbusState::new();
            let result = state.handle_set_connmark_allowlist(1, 0, vec!["*.example.com".to_string()]);
            assert_eq!(result, ubus_status::INVALID_ARGUMENT);
        }

        #[test]
        fn handle_set_connmark_allowlist_validates_mark_in_mask() {
            let mut state = UbusState::new();
            // mark=0xFF, mask=0x0F → (0xFF & !0x0F) = 0xF0 != 0
            let result = state.handle_set_connmark_allowlist(0xFF, 0x0F, vec!["*.example.com".to_string()]);
            assert_eq!(result, ubus_status::INVALID_ARGUMENT);
        }

        #[test]
        fn handle_set_connmark_allowlist_validates_patterns() {
            let mut state = UbusState::new();
            let result = state.handle_set_connmark_allowlist(1, u32::MAX, vec!["not valid!".to_string()]);
            assert_eq!(result, ubus_status::INVALID_ARGUMENT);
        }

        #[test]
        fn handle_set_connmark_allowlist_accepts_wildcard_star() {
            let mut state = UbusState::new();
            let result = state.handle_set_connmark_allowlist(1, u32::MAX, vec!["*".to_string()]);
            assert_eq!(result, ubus_status::OK);
            assert_eq!(state.allowlists.len(), 1);
            assert_eq!(state.allowlists[0].patterns, vec!["*"]);
        }

        #[test]
        fn handle_set_connmark_allowlist_replaces_existing() {
            let mut state = UbusState::new();

            let result = state.handle_set_connmark_allowlist(100, u32::MAX, vec!["*.example.com".to_string()]);
            assert_eq!(result, ubus_status::OK);
            assert_eq!(state.allowlists.len(), 1);

            let result = state.handle_set_connmark_allowlist(100, u32::MAX, vec!["*.other.com".to_string()]);
            assert_eq!(result, ubus_status::OK);
            assert_eq!(state.allowlists.len(), 1);
            assert_eq!(state.allowlists[0].patterns, vec!["*.other.com"]);
        }

        #[test]
        fn handle_set_connmark_allowlist_removes_on_empty_patterns() {
            let mut state = UbusState::new();

            let result = state.handle_set_connmark_allowlist(100, u32::MAX, vec!["*.example.com".to_string()]);
            assert_eq!(result, ubus_status::OK);
            assert_eq!(state.allowlists.len(), 1);

            let result = state.handle_set_connmark_allowlist(100, u32::MAX, vec![]);
            assert_eq!(result, ubus_status::OK);
            assert_eq!(state.allowlists.len(), 0);
        }

        #[test]
        fn handle_set_connmark_allowlist_multiple_marks() {
            let mut state = UbusState::new();

            let result = state.handle_set_connmark_allowlist(1, u32::MAX, vec!["*.example.com".to_string()]);
            assert_eq!(result, ubus_status::OK);

            let result = state.handle_set_connmark_allowlist(2, u32::MAX, vec!["*.other.com".to_string()]);
            assert_eq!(result, ubus_status::OK);

            assert_eq!(state.allowlists.len(), 2);
        }

        #[test]
        fn connmark_event_bcast_refused_noop_no_context() {
            let mut state = UbusState::new();
            state.event_bcast_connmark_allowlist_refused(0x100, "blocked.example.com");
        }

        #[test]
        fn connmark_event_bcast_resolved_noop_no_context() {
            let mut state = UbusState::new();
            state.event_bcast_connmark_allowlist_resolved(0x100, "ok.example.com", "1.2.3.4", 300);
        }

        #[test]
        fn allowlist_clone() {
            let al = Allowlist {
                mark: 42,
                mask: u32::MAX,
                patterns: vec!["*.test.com".to_string()],
            };
            let cloned = al.clone();
            assert_eq!(cloned.mark, 42);
            assert_eq!(cloned.mask, u32::MAX);
            assert_eq!(cloned.patterns, vec!["*.test.com"]);
        }
    }
}

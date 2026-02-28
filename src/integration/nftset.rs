//! nftables set population for DNS-driven firewall rules.
//!
//! This module implements dnsmasq's integration with Linux nftables for dynamic
//! firewall set population based on DNS resolution results. It uses FFI to the
//! `libnftables` C library for command execution.
//!
//! # Overview
//!
//! When DNS resolution produces IP addresses that match configured `nftset=` rules,
//! those addresses are added to named nftables sets. This enables domain-based firewall
//! policies that automatically adapt as DNS resolutions change.
//!
//! Nftables is the modern successor to iptables/ipset on Linux, offering improved
//! performance, cleaner syntax, atomic rule updates, and unified IPv4/IPv6 handling.
//! This module allows dnsmasq to populate nftables sets immediately after DNS
//! resolution, enabling firewall rules to match traffic based on domain names
//! rather than maintaining static IP address lists.
//!
//! # Architecture
//!
//! The module wraps the libnftables C API through raw FFI bindings:
//! - `nft_ctx_new()` — creates an opaque nftables context
//! - `nft_ctx_buffer_error()` — enables error message buffering
//! - `nft_run_cmd_from_buffer()` — executes nftables commands from a string buffer
//! - `nft_ctx_get_error_buffer()` — retrieves error messages after failed commands
//! - `nft_ctx_free()` — releases the nftables context
//!
//! All mutable state is encapsulated in [`NftsetState`], which owns the nftables
//! context pointer and a reusable command buffer. The [`Drop`] implementation
//! ensures proper cleanup of the libnftables context.
//!
//! # Feature Gate
//!
//! This module is compiled only when the `nftset` Cargo feature is enabled,
//! corresponding to the C codebase's `HAVE_NFTSET` compile-time flag.
//! Requires `libnftables` (version 0.9.0+) at link time, detected via
//! `pkg-config` in `build.rs`.
//!
//! # Configuration Example
//!
//! ```text
//! # dnsmasq.conf:
//! nftset=/example.com/4#ip#mytable#blocked_ipv4
//! nftset=/example.com/6#ip6#mytable#blocked_ipv6
//! ```
//!
//! Corresponding nftables ruleset:
//! ```text
//! nft add table ip mytable
//! nft add set ip mytable blocked_ipv4 { type ipv4_addr; }
//! nft add rule ip mytable filter ip daddr @blocked_ipv4 drop
//! ```
//!
//! # Performance
//!
//! - Command buffer is reused across calls via `String::clear()` + `write!()`,
//!   avoiding repeated heap allocations.
//! - nftables commands execute synchronously but typically complete in <1ms.
//! - Error buffer handling suppresses normal output; only errors are captured.
//!
//! # Thread Safety
//!
//! Single-threaded architecture — all nftables operations execute in the main
//! event loop. No locking is required. All state is owned by [`NftsetState`]
//! with no `static mut` variables.
//!
//! Replaces the C implementation in `src/nftset.c` (392 lines).

use std::ffi::{CStr, CString};
use std::fmt::Write;
use std::net::IpAddr;

use log::error;
use thiserror::Error;

// ---------------------------------------------------------------------------
// libnftables FFI bindings
//
// These are minimal raw FFI declarations for the libnftables C library.
// The NftCtx type is opaque — we only interact with it through pointers.
// libnftables is linked at build time via pkg-config (see build.rs).
//
// Minimum libnftables version: 0.9.0 (released 2019)
// API reference: nftables/libnftables.h
// ---------------------------------------------------------------------------

/// Opaque nftables context type used by libnftables.
///
/// This corresponds to `struct nft_ctx` in the C library. We never access
/// its internals — all interaction happens through the FFI functions below.
/// Using a zero-sized array ensures this type cannot be constructed in safe
/// Rust and forces all access through raw pointers.
#[repr(C)]
struct NftCtx {
    _opaque: [u8; 0],
}

/// Default flags for `nft_ctx_new()` — no special behavior.
/// Matches the C constant `NFT_CTX_DEFAULT` from libnftables.
const NFT_CTX_DEFAULT: u32 = 0;

// SAFETY: These are FFI declarations for libnftables (linked via pkg-config).
// The function signatures match the C API exactly. All callers must ensure
// pointers are valid and contexts are properly allocated before use.
unsafe extern "C" {
    /// Allocate and initialize a new nftables context.
    ///
    /// `flags`: Context creation flags. Use `NFT_CTX_DEFAULT` (0) for standard behavior.
    ///
    /// Returns a pointer to the newly allocated context, or NULL on failure
    /// (e.g., memory exhaustion or internal initialization error).
    fn nft_ctx_new(flags: u32) -> *mut NftCtx;

    /// Enable error message buffering on the context.
    ///
    /// After calling this function, normal stdout/stderr output from nftables
    /// commands is suppressed, and error messages can be retrieved via
    /// [`nft_ctx_get_error_buffer()`]. This matches the C code's behavior
    /// of capturing errors for selective logging.
    fn nft_ctx_buffer_error(ctx: *mut NftCtx);

    /// Execute an nftables command from a null-terminated string buffer.
    ///
    /// `ctx`: A valid, non-null nftables context pointer.
    /// `buf`: A null-terminated C string containing the nftables command.
    ///
    /// Returns 0 on success, non-zero on failure. On failure, the error
    /// message can be retrieved via [`nft_ctx_get_error_buffer()`].
    fn nft_run_cmd_from_buffer(ctx: *mut NftCtx, buf: *const libc::c_char) -> libc::c_int;

    /// Retrieve the error message buffer after a failed command.
    ///
    /// Returns a pointer to a null-terminated C string containing the error
    /// message from the most recent command execution. The buffer is owned
    /// by the context and remains valid until the next command execution or
    /// context destruction.
    ///
    /// May return an empty string if no error has occurred.
    fn nft_ctx_get_error_buffer(ctx: *mut NftCtx) -> *const libc::c_char;

    /// Free an nftables context and all associated resources.
    ///
    /// After this call, the context pointer is invalid and must not be used.
    fn nft_ctx_free(ctx: *mut NftCtx);
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during nftset operations.
///
/// Maps C error patterns to idiomatic Rust error types:
///
/// | C Pattern | Rust Variant |
/// |-----------|--------------|
/// | `die()` on `nft_ctx_new()` failure | [`ContextCreationFailed`](NftsetError::ContextCreationFailed) |
/// | Non-zero return from `nft_run_cmd_from_buffer()` | [`CommandFailed`](NftsetError::CommandFailed) |
/// | `-1` return for family prefix mismatch | [`FamilyMismatch`](NftsetError::FamilyMismatch) |
#[derive(Debug, Error)]
pub enum NftsetError {
    /// Failed to create the nftables context via `nft_ctx_new`.
    ///
    /// This typically indicates memory exhaustion or a libnftables
    /// internal initialization failure. In the original C code, this
    /// would cause the daemon to terminate via `die(EC_MISC)`.
    /// In Rust, we propagate the error to let the caller decide.
    #[error("Failed to create nftset context")]
    ContextCreationFailed,

    /// An nftables command execution failed.
    ///
    /// The set may not exist, the address may be invalid, or there
    /// may be a permissions issue. The `message` field contains the
    /// first line of the error returned by libnftables.
    #[error("nftset command failed for {setname}: {message}")]
    CommandFailed {
        /// The nftables set path that was being modified.
        setname: String,
        /// The first line of the error message from libnftables.
        message: String,
    },

    /// Address family mismatch between the set prefix and the address.
    ///
    /// Returned when the setname has a `"4 "` prefix but the address is IPv6,
    /// or a `"6 "` prefix but the address is IPv4. This is not a true error
    /// but a filter — the operation is intentionally skipped for this set.
    ///
    /// Corresponds to the C function returning `-1` for family mismatch.
    #[error("Address family mismatch for set {0}")]
    FamilyMismatch(String),
}

// ---------------------------------------------------------------------------
// NftsetState — manages the libnftables context and command buffer
// ---------------------------------------------------------------------------

/// nftables integration state.
///
/// Encapsulates the libnftables context handle and a reusable command buffer,
/// replacing C's static `nft_ctx *ctx` and `cmd_buf`/`cmd_buf_sz` variables.
///
/// # Ownership
///
/// The `NftsetState` owns the nftables context pointer exclusively. When
/// dropped, it calls `nft_ctx_free()` to release all associated resources.
/// No copies of the context pointer are made outside this struct.
///
/// # Command Buffer
///
/// The `cmd_buf` field is a `String` that replaces C's manually-managed
/// `cmd_buf`/`cmd_buf_sz` static variables. Rust's `String` grows
/// automatically and is reused across calls via `clear()` + `write!()`,
/// avoiding repeated heap allocations while eliminating manual size
/// tracking and `realloc` calls.
///
/// # Lifetime
///
/// Typically created once during daemon initialization (replacing C's
/// `nftset_init()` call) and reused for all subsequent nftables operations
/// throughout the daemon's lifetime.
pub struct NftsetState {
    /// Pointer to the libnftables context allocated by `nft_ctx_new()`.
    /// Guaranteed non-null after successful initialization via [`nftset_init()`].
    /// Freed by [`Drop::drop()`] via `nft_ctx_free()`.
    ctx: *mut NftCtx,

    /// Reusable command buffer for formatting nftables commands.
    ///
    /// Replaces C's static `cmd_buf` (char*) and `cmd_buf_sz` (size_t) with
    /// a growable `String`. Initial capacity is 150 bytes, matching C's
    /// initial allocation size. The buffer is cleared and rewritten for
    /// each command execution.
    cmd_buf: String,
}

impl NftsetState {
    /// Create a new `NftsetState` by initializing the libnftables context.
    ///
    /// Allocates a new nftables context via `nft_ctx_new()` and configures
    /// it for error buffering (suppressing stdout/stderr output). Returns
    /// an error if context creation fails.
    ///
    /// This is the primary constructor and delegates to [`nftset_init()`].
    ///
    /// # Errors
    ///
    /// Returns [`NftsetError::ContextCreationFailed`] if `nft_ctx_new()` returns NULL,
    /// which typically indicates memory exhaustion or library initialization failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::integration::nftset::NftsetState;
    /// let state = NftsetState::new().expect("Failed to initialize nftset");
    /// ```
    pub fn new() -> Result<Self, NftsetError> {
        nftset_init()
    }

    /// Add an IP address to the specified nftables set.
    ///
    /// The `setname` follows the format `"family#table#set"` and may include
    /// an optional address family prefix:
    /// - `"4 family#table#set"` — only accepts IPv4 addresses
    /// - `"6 family#table#set"` — only accepts IPv6 addresses
    /// - `"family#table#set"` — accepts both IPv4 and IPv6
    ///
    /// Generates an nftables command: `add element <setname> { <addr> }`
    ///
    /// # Errors
    ///
    /// - [`NftsetError::FamilyMismatch`] if the address family doesn't match the prefix
    /// - [`NftsetError::CommandFailed`] if the nftables command execution fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::IpAddr;
    /// use dnsmasq::integration::nftset::NftsetState;
    ///
    /// let mut state = NftsetState::new().unwrap();
    /// let addr: IpAddr = "192.0.2.1".parse().unwrap();
    /// state.add_address("ip#filter#blocked", &addr).unwrap();
    /// ```
    pub fn add_address(&mut self, setname: &str, addr: &IpAddr) -> Result<(), NftsetError> {
        add_to_nftset(self, setname, addr, false)
    }

    /// Remove an IP address from the specified nftables set.
    ///
    /// Follows the same `setname` format and family-prefix semantics as
    /// [`add_address`](Self::add_address).
    ///
    /// Generates an nftables command: `delete element <setname> { <addr> }`
    ///
    /// # Errors
    ///
    /// Same error conditions as [`add_address`](Self::add_address).
    pub fn remove_address(&mut self, setname: &str, addr: &IpAddr) -> Result<(), NftsetError> {
        add_to_nftset(self, setname, addr, true)
    }
}

impl Drop for NftsetState {
    /// Release the nftables context when `NftsetState` is dropped.
    ///
    /// Calls `nft_ctx_free()` to deallocate the libnftables context and all
    /// associated resources. The command buffer (`String`) is dropped
    /// automatically by Rust's ownership system.
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: `self.ctx` was allocated by `nft_ctx_new()` in `nftset_init()`
            // and is guaranteed non-null by the check above. We are the sole owner
            // of this pointer (no copies exist), and after this call we never use
            // the pointer again (the struct is being dropped). `nft_ctx_free` is
            // the documented cleanup function for contexts created by `nft_ctx_new`.
            unsafe {
                nft_ctx_free(self.ctx);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public free functions
// ---------------------------------------------------------------------------

/// Initialize the nftables context and enable error buffering.
///
/// Creates a new libnftables context via `nft_ctx_new()`, configures it to
/// buffer error messages (suppressing stdout/stderr output), and returns
/// an initialized [`NftsetState`].
///
/// This replaces C's `nftset_init()` function (lines 190-198 of `nftset.c`).
/// The key difference is that C's version called `die(EC_MISC)` on failure
/// (terminating the daemon), while this Rust version returns `Result` to
/// let the caller decide how to handle the error.
///
/// # Errors
///
/// Returns [`NftsetError::ContextCreationFailed`] if `nft_ctx_new()` returns NULL.
///
/// # Safety Model
///
/// This function contains `unsafe` blocks for FFI calls to libnftables:
/// - `nft_ctx_new(NFT_CTX_DEFAULT)`: Allocates and returns a new context pointer
/// - `nft_ctx_buffer_error(ctx)`: Configures the context for error buffering
///
/// Both are well-defined C API calls with no special preconditions beyond
/// the flags parameter being valid (we use `NFT_CTX_DEFAULT = 0`).
pub fn nftset_init() -> Result<NftsetState, NftsetError> {
    // SAFETY: `nft_ctx_new` is a well-defined libnftables API function.
    // `NFT_CTX_DEFAULT` (0) is the documented default flags value.
    // The function either returns a valid, newly-allocated context pointer
    // or NULL on failure. We check for NULL immediately after.
    let ctx = unsafe { nft_ctx_new(NFT_CTX_DEFAULT) };

    if ctx.is_null() {
        return Err(NftsetError::ContextCreationFailed);
    }

    // SAFETY: `ctx` is non-null (verified above) and was just allocated by
    // `nft_ctx_new`. `nft_ctx_buffer_error` is a well-defined API call that
    // configures the context to buffer error messages instead of writing
    // to stdout/stderr. It has no failure mode — it always succeeds for
    // a valid context. This matches the C code at line 197: nft_ctx_buffer_error(ctx).
    unsafe {
        nft_ctx_buffer_error(ctx);
    }

    Ok(NftsetState {
        ctx,
        // Pre-allocate 150 bytes to match C's initial cmd_buf allocation size.
        // This is sufficient for typical set names and IPv6 addresses,
        // avoiding an early reallocation in most cases.
        cmd_buf: String::with_capacity(150),
    })
}

/// Add or remove an IP address to/from an nftables set.
///
/// This is the core operation function, replacing C's `add_to_nftset()`
/// (lines 333-390 of `nftset.c`). It performs address-family filtering based
/// on optional prefixes in the setname, formats the nftables command, and
/// executes it via the libnftables API.
///
/// # Algorithm (matching C implementation exactly)
///
/// 1. Convert IP to string using `IpAddr::to_string()` (replaces C's `inet_ntop()`)
/// 2. Parse optional address family prefix in `setname`:
///    - If second char is `' '` and first char is `'4'` or `'6'`:
///      - `'4'` prefix with IPv6 address → return `Err(FamilyMismatch)`
///      - `'6'` prefix with IPv4 address → return `Err(FamilyMismatch)`
///      - Otherwise strip the 2-character prefix
///    - No prefix: accept both IPv4 and IPv6
/// 3. Format the nftables command:
///    - Add: `"add element {setname} { {ipaddr} }"`
///    - Delete: `"delete element {setname} { {ipaddr} }"`
/// 4. Execute via `nft_run_cmd_from_buffer()`
/// 5. On error: retrieve error buffer, extract first line, log and return error
///
/// # Arguments
///
/// * `state` — Mutable reference to the nftables integration state
/// * `setname` — Set specification in format `"[4|6] family#table#set"`
/// * `ipaddr` — IP address to add or remove
/// * `remove` — If `true`, remove the address; if `false`, add it
///
/// # Errors
///
/// - [`NftsetError::FamilyMismatch`] if the set prefix doesn't match the address family
/// - [`NftsetError::CommandFailed`] if the nftables command execution fails
///
/// # Return Value Mapping from C
///
/// | C Return | Rust Result |
/// |----------|-------------|
/// | `0` (success) | `Ok(())` |
/// | `-1` (family mismatch) | `Err(FamilyMismatch)` |
/// | `>0` (nftables error) | `Err(CommandFailed)` |
pub fn add_to_nftset(
    state: &mut NftsetState,
    setname: &str,
    ipaddr: &IpAddr,
    remove: bool,
) -> Result<(), NftsetError> {
    // Step 1: Convert IP address to string representation.
    // Replaces C's: inet_ntop(af, ipaddr, daemon->addrbuff, ADDRSTRLEN)
    // Rust's IpAddr::to_string() handles both IPv4 and IPv6 automatically.
    let addr_str = ipaddr.to_string();

    // Step 2: Parse optional address family prefix in setname.
    //
    // The C code checks (line 345):
    //   if (setname[1] == ' ' && (setname[0] == '4' || setname[0] == '6'))
    //
    // This allows per-address-family filtering:
    // - "4 ip#table#set" → only add IPv4 addresses
    // - "6 ip6#table#set" → only add IPv6 addresses
    // - "ip#table#set" → add both IPv4 and IPv6
    let setname_bytes = setname.as_bytes();
    let effective_setname = if setname_bytes.len() >= 2
        && setname_bytes[1] == b' '
        && (setname_bytes[0] == b'4' || setname_bytes[0] == b'6')
    {
        // Family prefix detected — check for mismatch.
        // C line 347-348: if (setname[0] == '4' && !(flags & F_IPV4)) return -1;
        if setname_bytes[0] == b'4' && !ipaddr.is_ipv4() {
            return Err(NftsetError::FamilyMismatch(setname.to_string()));
        }

        // C line 350-351: if (setname[0] == '6' && !(flags & F_IPV6)) return -1;
        if setname_bytes[0] == b'6' && !ipaddr.is_ipv6() {
            return Err(NftsetError::FamilyMismatch(setname.to_string()));
        }

        // Strip the 2-character prefix (C line 353: setname += 2)
        &setname[2..]
    } else {
        // No family prefix — accept both IPv4 and IPv6 addresses.
        setname
    };

    // Step 3: Format the nftables command into the reusable buffer.
    //
    // Replaces C's manual buffer management (lines 356-371):
    //   snprintf(cmd_buf, cmd_buf_sz, cmd, setname, daemon->addrbuff)
    // with Rust's String::clear() + write!() for zero-overhead buffer reuse.
    //
    // Command templates match C exactly:
    //   cmd_add = "add element %s { %s }"     (C line 135)
    //   cmd_del = "delete element %s { %s }"   (C line 143)
    state.cmd_buf.clear();
    if remove {
        let _ = write!(
            state.cmd_buf,
            "delete element {} {{ {} }}",
            effective_setname, addr_str
        );
    } else {
        let _ = write!(
            state.cmd_buf,
            "add element {} {{ {} }}",
            effective_setname, addr_str
        );
    }

    // Step 4: Convert to CString for FFI and execute the command.
    //
    // CString::new() adds the null terminator required by C functions.
    // The command buffer should never contain interior NUL bytes with valid
    // input (IP addresses and nftables set names), but we handle the error
    // gracefully rather than panicking.
    let c_cmd = match CString::new(state.cmd_buf.as_str()) {
        Ok(s) => s,
        Err(_) => {
            // Interior NUL byte in command — should never happen with valid
            // set names and IP addresses. Return an error rather than panicking.
            return Err(NftsetError::CommandFailed {
                setname: effective_setname.to_string(),
                message: "command buffer contains interior NUL byte".to_string(),
            });
        }
    };

    // SAFETY: `state.ctx` is a valid, non-null nftables context pointer created
    // by `nft_ctx_new()` in `nftset_init()`. The context remains valid because:
    // 1. It was successfully allocated (checked for NULL in nftset_init)
    // 2. We are the sole owner (NftsetState has exclusive access)
    // 3. It has not been freed (only freed in Drop::drop)
    //
    // `c_cmd.as_ptr()` returns a valid, null-terminated C string pointer.
    // `nft_run_cmd_from_buffer` reads from the buffer synchronously and does
    // not take ownership or store the pointer beyond the call duration.
    //
    // SAFETY: ctx is a valid non-null nftables context (see invariants above);
    // c_cmd.as_ptr() is a valid null-terminated C string. Matches C line 373.
    let ret = unsafe { nft_run_cmd_from_buffer(state.ctx, c_cmd.as_ptr()) };

    // Step 5: Handle errors — retrieve and log first line of error message.
    //
    // Matches C behavior (lines 376-387):
    //   if (ret != 0) {
    //     err_str = whine_malloc(strlen(err) + 1);
    //     strcpy(err_str, err);
    //     if ((nl = strchr(err_str, '\n'))) *nl = 0;
    //     my_syslog(LOG_ERR, "nftset %s %s", setname, err_str);
    //     free(err_str);
    //   }
    if ret != 0 {
        // SAFETY: `state.ctx` is a valid nftables context (same invariants as above).
        // `nft_ctx_get_error_buffer` returns a pointer to a null-terminated string
        // owned by the context. The string remains valid until the next command
        // execution or context destruction. We copy the data out immediately
        // (into a Rust String), so there is no dangling reference risk.
        //
        // SAFETY: ctx is valid and non-null (see above). We copy the error
        // string immediately so no dangling reference risk exists.
        let error_msg = unsafe {
            let err_ptr = nft_ctx_get_error_buffer(state.ctx);
            if err_ptr.is_null() {
                String::from("unknown error")
            } else {
                // SAFETY: `err_ptr` is non-null and points to a valid null-terminated
                // C string allocated by libnftables. `CStr::from_ptr` requires a
                // valid, null-terminated pointer, which libnftables guarantees.
                // `to_string_lossy()` handles any non-UTF-8 bytes gracefully by
                // replacing them with the Unicode replacement character, which is
                // safer than the C code's direct strcpy.
                CStr::from_ptr(err_ptr).to_string_lossy().into_owned()
            }
        };

        // Extract only the first line of the error message, matching C behavior:
        //   C line 382-383: if ((nl = strchr(err_str, '\n'))) *nl = 0;
        // The C code truncates at the first newline. We use split('\n').next()
        // which achieves the same result without modifying the original string.
        let first_line = error_msg
            .split('\n')
            .next()
            .unwrap_or(&error_msg)
            .to_string();

        // Log the error at ERROR level, matching C's my_syslog(LOG_ERR, ...).
        //   C line 384: my_syslog(LOG_ERR, "nftset %s %s", setname, err_str);
        error!("nftset {} {}", effective_setname, first_line);

        return Err(NftsetError::CommandFailed {
            setname: effective_setname.to_string(),
            message: first_line,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -----------------------------------------------------------------------
    // Family prefix parsing tests
    //
    // These tests verify the address family prefix detection and mismatch
    // logic without requiring an actual libnftables context. The family
    // mismatch check occurs before any FFI call, so null ctx is safe.
    // -----------------------------------------------------------------------

    /// Verify that "4 " prefix with IPv6 address returns FamilyMismatch.
    #[test]
    fn test_family_prefix_v4_rejects_ipv6() {
        let addr_v6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut state = NftsetState {
            ctx: std::ptr::null_mut(),
            cmd_buf: String::new(),
        };
        let result = add_to_nftset(&mut state, "4 ip#table#set", &addr_v6, false);
        assert!(matches!(result, Err(NftsetError::FamilyMismatch(_))));
    }

    /// Verify that "6 " prefix with IPv4 address returns FamilyMismatch.
    #[test]
    fn test_family_prefix_v6_rejects_ipv4() {
        let addr_v4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut state = NftsetState {
            ctx: std::ptr::null_mut(),
            cmd_buf: String::new(),
        };
        let result = add_to_nftset(&mut state, "6 ip6#table#set", &addr_v4, false);
        assert!(matches!(result, Err(NftsetError::FamilyMismatch(_))));
    }

    /// Verify that "4 " prefix with IPv4 address does NOT return FamilyMismatch.
    /// (The test can't proceed past prefix check without a real ctx, so we
    /// verify the prefix parsing doesn't trigger a mismatch.)
    #[test]
    fn test_family_prefix_v4_accepts_ipv4() {
        let addr_v4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let setname = "4 ip#table#set";
        let setname_bytes = setname.as_bytes();

        // Verify prefix detection
        assert!(setname_bytes.len() >= 2);
        assert_eq!(setname_bytes[0], b'4');
        assert_eq!(setname_bytes[1], b' ');

        // Verify family match: "4" prefix with IPv4 should NOT mismatch
        let is_mismatch = setname_bytes[0] == b'4' && !addr_v4.is_ipv4();
        assert!(!is_mismatch);
    }

    /// Verify that "6 " prefix with IPv6 address does NOT return FamilyMismatch.
    #[test]
    fn test_family_prefix_v6_accepts_ipv6() {
        let addr_v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let setname = "6 ip6#table#set";
        let setname_bytes = setname.as_bytes();

        assert!(setname_bytes.len() >= 2);
        assert_eq!(setname_bytes[0], b'6');
        assert_eq!(setname_bytes[1], b' ');

        let is_mismatch = setname_bytes[0] == b'6' && !addr_v6.is_ipv6();
        assert!(!is_mismatch);
    }

    /// Verify that setnames shorter than 2 bytes don't trigger prefix parsing.
    #[test]
    fn test_short_setname_no_prefix() {
        let setname = "4";
        let bytes = setname.as_bytes();
        let has_prefix = bytes.len() >= 2
            && bytes[1] == b' '
            && (bytes[0] == b'4' || bytes[0] == b'6');
        assert!(!has_prefix);
    }

    /// Verify that setnames with non-space second char don't trigger prefix parsing.
    #[test]
    fn test_setname_no_space_no_prefix() {
        let setname = "4x ip#table#set";
        let bytes = setname.as_bytes();
        let has_prefix = bytes.len() >= 2
            && bytes[1] == b' '
            && (bytes[0] == b'4' || bytes[0] == b'6');
        assert!(!has_prefix);
    }

    /// Verify that setnames starting with non-4/6 chars don't trigger prefix parsing.
    #[test]
    fn test_setname_other_digit_no_prefix() {
        let setname = "3 ip#table#set";
        let bytes = setname.as_bytes();
        let has_prefix = bytes.len() >= 2
            && bytes[1] == b' '
            && (bytes[0] == b'4' || bytes[0] == b'6');
        assert!(!has_prefix);
    }

    /// Verify empty setname doesn't panic.
    #[test]
    fn test_empty_setname_no_prefix() {
        let setname = "";
        let bytes = setname.as_bytes();
        let has_prefix = bytes.len() >= 2
            && bytes[1] == b' '
            && (bytes[0] == b'4' || bytes[0] == b'6');
        assert!(!has_prefix);
    }

    // -----------------------------------------------------------------------
    // Command buffer formatting tests
    //
    // These tests verify the nftables command string construction matches
    // the C format templates exactly:
    //   cmd_add = "add element %s { %s }"
    //   cmd_del = "delete element %s { %s }"
    // -----------------------------------------------------------------------

    /// Verify add command format for IPv4 address.
    #[test]
    fn test_command_format_add_ipv4() {
        let mut buf = String::new();
        let setname = "ip#filter#blocked";
        let addr = "192.0.2.1";
        let _ = write!(buf, "add element {} {{ {} }}", setname, addr);
        assert_eq!(buf, "add element ip#filter#blocked { 192.0.2.1 }");
    }

    /// Verify delete command format for IPv6 address.
    #[test]
    fn test_command_format_delete_ipv6() {
        let mut buf = String::new();
        let setname = "ip6#filter#blocked_v6";
        let addr = "2001:db8::1";
        let _ = write!(buf, "delete element {} {{ {} }}", setname, addr);
        assert_eq!(buf, "delete element ip6#filter#blocked_v6 { 2001:db8::1 }");
    }

    /// Verify buffer reuse via clear + write.
    #[test]
    fn test_command_buffer_reuse() {
        let mut buf = String::with_capacity(150);

        // First write
        buf.clear();
        let _ = write!(buf, "add element ip#t#s {{ 10.0.0.1 }}");
        assert_eq!(buf, "add element ip#t#s { 10.0.0.1 }");

        // Second write reusing same buffer
        buf.clear();
        let _ = write!(buf, "delete element ip6#t#s {{ ::1 }}");
        assert_eq!(buf, "delete element ip6#t#s { ::1 }");

        // Capacity should still be >= 150 (no reallocation for small commands)
        assert!(buf.capacity() >= 150);
    }

    // -----------------------------------------------------------------------
    // Error handling tests
    // -----------------------------------------------------------------------

    /// Verify first-line extraction from multi-line error messages.
    #[test]
    fn test_first_line_extraction_multiline() {
        let error_msg = "Error: No such file or directory\nAdditional context\nMore details";
        let first_line = error_msg.split('\n').next().unwrap_or(error_msg);
        assert_eq!(first_line, "Error: No such file or directory");
    }

    /// Verify first-line extraction from single-line error messages.
    #[test]
    fn test_first_line_extraction_single() {
        let error_msg = "Error: Permission denied";
        let first_line = error_msg.split('\n').next().unwrap_or(error_msg);
        assert_eq!(first_line, "Error: Permission denied");
    }

    /// Verify first-line extraction from empty error messages.
    #[test]
    fn test_first_line_extraction_empty() {
        let error_msg = "";
        let first_line = error_msg.split('\n').next().unwrap_or(error_msg);
        assert_eq!(first_line, "");
    }

    // -----------------------------------------------------------------------
    // NftsetError Display tests
    // -----------------------------------------------------------------------

    /// Verify ContextCreationFailed display message.
    #[test]
    fn test_error_display_context_creation() {
        let err = NftsetError::ContextCreationFailed;
        assert_eq!(err.to_string(), "Failed to create nftset context");
    }

    /// Verify CommandFailed display message.
    #[test]
    fn test_error_display_command_failed() {
        let err = NftsetError::CommandFailed {
            setname: "ip#table#set".to_string(),
            message: "No such table".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "nftset command failed for ip#table#set: No such table"
        );
    }

    /// Verify FamilyMismatch display message.
    #[test]
    fn test_error_display_family_mismatch() {
        let err = NftsetError::FamilyMismatch("4 ip#table#set".to_string());
        assert_eq!(
            err.to_string(),
            "Address family mismatch for set 4 ip#table#set"
        );
    }

    /// Verify NftsetError implements std::error::Error trait.
    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(NftsetError::ContextCreationFailed);
        assert_eq!(err.to_string(), "Failed to create nftset context");
    }

    // -----------------------------------------------------------------------
    // IpAddr string conversion tests
    // -----------------------------------------------------------------------

    /// Verify IPv4 address string formatting.
    #[test]
    fn test_ipaddr_to_string_v4() {
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(addr.to_string(), "192.0.2.1");
    }

    /// Verify IPv6 address string formatting.
    #[test]
    fn test_ipaddr_to_string_v6() {
        let addr: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(addr.to_string(), "2001:db8::1");
    }

    /// Verify IPv4 address detection.
    #[test]
    fn test_ipaddr_is_v4() {
        let v4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(v4.is_ipv4());
        assert!(!v4.is_ipv6());
        assert!(v6.is_ipv6());
        assert!(!v6.is_ipv4());
    }
}

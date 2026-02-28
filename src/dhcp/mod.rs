// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2000-2025 Simon Kelley — Rust rewrite

//! DHCP subsystem: DHCPv4, DHCPv6, Router Advertisements, and lease management.
//!
//! This module implements the complete DHCP stack for dnsmasq, providing:
//!
//! - **DHCPv4** address allocation and protocol handling per [RFC 2131]
//! - **DHCPv6** stateful/stateless address management per [RFC 3315]
//! - **IPv6 Router Advertisement** construction per [RFC 4861]
//! - **SLAAC** address probing and confirmation via ICMPv6 echo
//! - **Persistent lease database** with DNS hostname registration
//! - **Privilege-separated helper process** for script execution on lease events
//!
//! # Module Architecture
//!
//! The DHCP subsystem is organized into a module tree that mirrors the C source
//! file decomposition while adding clear Rust module boundaries:
//!
//! ```text
//! dhcp/
//! ├── mod.rs              (this file — module root, re-exports, DhcpError)
//! ├── common.rs           (shared utilities: tag matching, option filtering, config lookup)
//! ├── protocol_v4.rs      (DHCPv4 wire-format constants and DhcpPacket struct)
//! ├── protocol_v6.rs      (DHCPv6 wire-format constants, feature-gated)
//! ├── lease.rs            (lease persistence, DNS registration, expiration)
//! ├── helper.rs           (privilege-separated script helper, feature-gated)
//! ├── v4/                 (DHCPv4 server: server.rs + rfc2131.rs)
//! ├── v6/                 (DHCPv6 server: server.rs + rfc3315.rs + outpacket.rs)
//! └── radv/               (Router Advertisements: protocol.rs + server.rs + slaac.rs)
//! ```
//!
//! # Feature Gates
//!
//! The entire `dhcp` module is conditionally compiled in `lib.rs` via:
//! ```rust,ignore
//! #[cfg(any(feature = "dhcp", feature = "dhcp6"))]
//! pub mod dhcp;
//! ```
//!
//! Within this module, submodules are further gated:
//!
//! | Feature    | Submodules Enabled                              |
//! |------------|------------------------------------------------|
//! | `dhcp`     | `common`, `protocol_v4`, `lease`, `v4`          |
//! | `dhcp6`    | `common`, `protocol_v4`, `protocol_v6`, `lease`, `v6`, `radv` |
//! | `script`   | `helper` (privilege-separated script execution)  |
//!
//! The `common`, `protocol_v4`, and `lease` modules are always available when
//! the DHCP subsystem is compiled (no additional feature gate).
//!
//! # C Source File Mapping
//!
//! | Rust Module        | C Source File(s)                              |
//! |--------------------|-----------------------------------------------|
//! | `common`           | `src/dhcp-common.c`                           |
//! | `protocol_v4`      | `src/dhcp-protocol.h`                         |
//! | `protocol_v6`      | `src/dhcp6-protocol.h`                        |
//! | `lease`            | `src/lease.c`                                 |
//! | `helper`           | `src/helper.c`                                |
//! | `v4::server`       | `src/dhcp.c`                                  |
//! | `v4::rfc2131`      | `src/rfc2131.c`                               |
//! | `v6::server`       | `src/dhcp6.c`                                 |
//! | `v6::rfc3315`      | `src/rfc3315.c`                               |
//! | `v6::outpacket`    | `src/outpacket.c`                             |
//! | `radv::protocol`   | `src/radv-protocol.h`                         |
//! | `radv::server`     | `src/radv.c`                                  |
//! | `radv::slaac`      | `src/slaac.c`                                 |
//!
//! [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
//! [RFC 3315]: https://www.rfc-editor.org/rfc/rfc3315
//! [RFC 4861]: https://www.rfc-editor.org/rfc/rfc4861

// ===========================================================================
// Submodule Declarations
// ===========================================================================

/// Shared DHCP utilities used by both DHCPv4 and DHCPv6 stacks.
///
/// Provides tag-based client classification (`match_netid`, `match_netid_wild`,
/// `run_tag_if`), option filtering (`option_filter`), configuration lookup
/// (`find_config`), hostname sanitization (`strip_hostname`), buffer management
/// (`DhcpBuffers`), DHCP option definition tables, and transaction logging helpers.
///
/// Always available when the DHCP module is compiled — no additional feature gate.
///
/// # Source
/// Rust rewrite of `src/dhcp-common.c` (2337 lines).
pub mod common;

/// DHCPv4 wire-format constants and packet structure (RFC 2131/2132).
///
/// Contains all DHCPv4 protocol definitions: port numbers, BOOTP operation codes,
/// the magic cookie constant, 40+ option codes, 13 message types, relay agent
/// suboption codes, PXE boot suboptions, hardware type constants, and the
/// `DhcpPacket` wire-format struct (`#[repr(C)]`, 548 bytes).
///
/// Always available when the DHCP module is compiled — no additional feature gate.
///
/// # Source
/// Rust rewrite of `src/dhcp-protocol.h` (936 lines).
pub mod protocol_v4;

/// DHCPv6 wire-format constants and message types (RFC 3315).
///
/// Contains all DHCPv6 protocol definitions: port numbers, multicast addresses,
/// 13 message types, 35+ option codes, 6 status codes, DUID type constants,
/// and NTP suboption codes.
///
/// # Feature Gate
/// Compiled only when the `dhcp6` Cargo feature is enabled.
///
/// # Source
/// Rust rewrite of `src/dhcp6-protocol.h` (685 lines).
#[cfg(feature = "dhcp6")]
pub mod protocol_v6;

/// DHCP lease persistence and management.
///
/// Manages the complete lifecycle of DHCP leases for both DHCPv4 and DHCPv6,
/// maintaining active leases in `HashMap`-based storage (replacing C intrusive
/// linked lists). Provides lease allocation, lookup, modification, file-based
/// persistence, DNS hostname registration, and expiration management.
///
/// Always available when the DHCP module is compiled — no additional feature gate.
///
/// # Source
/// Rust rewrite of `src/lease.c` (3364 lines).
pub mod lease;

/// Privilege-separated script helper process.
///
/// Manages fork-based helper processes that execute external scripts in response
/// to DHCP lease events (add/old/del), TFTP file transfers, and ARP table changes.
/// The helper retains root privileges while the main daemon drops to an
/// unprivileged user. Communication is via unidirectional pipe.
///
/// # Feature Gate
/// Compiled only when the `script` Cargo feature is enabled.
///
/// # Source
/// Rust rewrite of `src/helper.c` (1528 lines).
#[cfg(feature = "script")]
pub mod helper;

/// DHCPv4 server implementation (RFC 2131 DORA cycle).
///
/// Provides the complete DHCPv4 server including address allocation with
/// SDBM hash seeding, ICMP conflict detection, PXE/UEFI network boot support,
/// relay agent processing (RFC 3046), and full DHCP option encoding/decoding.
///
/// # Feature Gate
/// Compiled only when the `dhcp` Cargo feature is enabled.
///
/// # Source
/// Rust rewrite of `src/dhcp.c` and `src/rfc2131.c`.
#[cfg(feature = "dhcp")]
pub mod v4;

/// DHCPv6 server implementation (RFC 3315).
///
/// Provides the complete DHCPv6 server including SOLICIT/ADVERTISE/REQUEST/REPLY
/// message processing, IA_NA/IA_TA/IA_PD management, DUID handling, relay chain
/// traversal, and the `Dhcpv6OutPacket` option serialization buffer builder.
///
/// # Feature Gate
/// Compiled only when the `dhcp6` Cargo feature is enabled.
///
/// # Source
/// Rust rewrite of `src/dhcp6.c`, `src/rfc3315.c`, and `src/outpacket.c`.
#[cfg(feature = "dhcp6")]
pub mod v6;

/// IPv6 Router Advertisement subsystem (RFC 4861).
///
/// Implements RA construction and transmission, SLAAC address probing via
/// ICMPv6 echo, and the ICMPv6/Neighbor Discovery protocol constants. Supports
/// SLAAC-only, SLAAC+stateless DHCPv6, SLAAC with DNS registration, and
/// stateful DHCPv6 operational modes.
///
/// # Feature Gate
/// Compiled only when the `dhcp6` Cargo feature is enabled.
///
/// # Source
/// Rust rewrite of `src/radv.c`, `src/slaac.c`, and `src/radv-protocol.h`.
#[cfg(feature = "dhcp6")]
pub mod radv;

// ===========================================================================
// Public Re-exports — Ergonomic Access to Common Types
// ===========================================================================

// Re-export commonly used types from the `common` module so consumers can
// import directly from `crate::dhcp::` without navigating into submodules.

/// Re-export shared DHCP buffers for packet construction and option processing.
pub use common::DhcpBuffers;

/// Re-export the DHCP protocol version discriminator.
pub use common::Protocol;

// Re-export the lease database for centralized lease management.

/// Re-export the DHCP lease database.
pub use lease::LeaseDatabase;

// Re-export DHCPv4 protocol types for ergonomic access.

/// Re-export the DHCPv4 wire-format packet structure.
pub use protocol_v4::DhcpPacket;

/// Re-export the DHCPv4 message type enumeration.
pub use protocol_v4::DhcpMessageType;

// Re-export DHCPv6 message type when the dhcp6 feature is enabled.

/// Re-export the DHCPv6 message type enumeration.
#[cfg(feature = "dhcp6")]
pub use protocol_v6::Dhcp6MessageType;

// Re-export the helper process when the script feature is enabled.

/// Re-export the privilege-separated script helper process.
#[cfg(feature = "script")]
pub use helper::HelperProcess;

// ===========================================================================
// DhcpError — Top-Level DHCP Error Type
// ===========================================================================

/// Top-level error type encompassing all DHCP subsystem errors.
///
/// `DhcpError` provides a unified error type for the entire DHCP module,
/// aggregating errors from lease management, the script helper process,
/// packet processing, and general I/O operations. Each variant uses
/// `#[from]` where applicable for automatic conversion via the `?` operator.
///
/// # Variants
///
/// - `Common` — Errors from shared DHCP utilities (tag matching, config lookup,
///   option filtering failures).
/// - `Lease` — Errors from lease database operations (file I/O, limit exceeded,
///   parse errors). Automatically converted from [`lease::LeaseError`].
/// - `Helper` — Errors from the privilege-separated helper process (pipe/fork
///   failures, script execution errors). Only available with `script` feature.
///   Automatically converted from [`helper::HelperError`].
/// - `Packet` — Malformed or invalid DHCP packet errors (truncated packets,
///   missing required options, invalid message types).
/// - `Io` — General I/O errors (socket operations, file operations). Automatically
///   converted from [`std::io::Error`].
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::dhcp::DhcpError;
///
/// fn process_packet(data: &[u8]) -> Result<(), DhcpError> {
///     if data.len() < 240 {
///         return Err(DhcpError::Packet("packet too short for DHCP".into()));
///     }
///     // ... processing that may produce I/O errors via `?`
///     Ok(())
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum DhcpError {
    /// Error from shared DHCP common utilities.
    ///
    /// Wraps descriptive error messages from tag matching failures,
    /// configuration lookup errors, option filtering issues, and
    /// buffer management problems.
    #[error("DHCP common error: {0}")]
    Common(String),

    /// Error from the lease database subsystem.
    ///
    /// Automatically converted from [`lease::LeaseError`] via `#[from]`,
    /// covering lease file I/O failures, parse errors, and limit exceeded
    /// conditions.
    #[error("lease error: {0}")]
    Lease(#[from] lease::LeaseError),

    /// Error from the privilege-separated script helper process.
    ///
    /// Only available when the `script` Cargo feature is enabled. Automatically
    /// converted from [`helper::HelperError`] via `#[from]`, covering pipe
    /// creation failures, fork errors, write errors, and script execution
    /// failures.
    #[cfg(feature = "script")]
    #[error("helper error: {0}")]
    Helper(#[from] helper::HelperError),

    /// Malformed or invalid DHCP packet error.
    ///
    /// Wraps descriptive error messages for packet-level issues such as
    /// truncated packets, missing required options (e.g., no message type),
    /// invalid option lengths, and protocol violations.
    #[error("packet error: {0}")]
    Packet(String),

    /// General I/O error from socket or file operations.
    ///
    /// Automatically converted from [`std::io::Error`] via `#[from]`,
    /// covering socket read/write failures, file access errors, and
    /// other system-level I/O issues throughout the DHCP stack.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ===========================================================================
// DhcpError Convenience Constructors
// ===========================================================================

impl DhcpError {
    /// Create a `Common` error from any displayable value.
    ///
    /// Convenience constructor for creating `DhcpError::Common` variants
    /// from string-like types without requiring `.to_string()` at call sites.
    pub fn common(msg: impl Into<String>) -> Self {
        DhcpError::Common(msg.into())
    }

    /// Create a `Packet` error from any displayable value.
    ///
    /// Convenience constructor for creating `DhcpError::Packet` variants
    /// from string-like types without requiring `.to_string()` at call sites.
    pub fn packet(msg: impl Into<String>) -> Self {
        DhcpError::Packet(msg.into())
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that DhcpError::Common variant works correctly.
    #[test]
    fn test_dhcp_error_common() {
        let err = DhcpError::common("test common error");
        assert!(matches!(err, DhcpError::Common(_)));
        assert_eq!(format!("{err}"), "DHCP common error: test common error");
    }

    /// Verify that DhcpError::Packet variant works correctly.
    #[test]
    fn test_dhcp_error_packet() {
        let err = DhcpError::packet("truncated packet");
        assert!(matches!(err, DhcpError::Packet(_)));
        assert_eq!(format!("{err}"), "packet error: truncated packet");
    }

    /// Verify that DhcpError::Io converts from std::io::Error.
    #[test]
    fn test_dhcp_error_io_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let dhcp_err: DhcpError = io_err.into();
        assert!(matches!(dhcp_err, DhcpError::Io(_)));
        let msg = format!("{dhcp_err}");
        assert!(msg.contains("I/O error"));
    }

    /// Verify that Protocol enum is re-exported and accessible.
    #[test]
    fn test_protocol_reexport() {
        let v4 = Protocol::V4;
        let v6 = Protocol::V6;
        assert_ne!(v4, v6);
        assert_eq!(v4, Protocol::V4);
    }

    /// Verify that DhcpError Debug formatting works.
    #[test]
    fn test_dhcp_error_debug() {
        let err = DhcpError::common("debug test");
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("Common"));
    }
}

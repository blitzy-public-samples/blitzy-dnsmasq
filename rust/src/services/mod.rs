// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Network Services Module
//!
//! This module provides dnsmasq's network service daemons beyond DNS and DHCP,
//! migrated from the C source files in the services category.
//!
//! ## Sub-modules:
//! - [`tftp`] — Read-only TFTP server with PXE boot support (from `src/tftp.c`, 1,647 lines)
//!
//! ## Architecture
//! Each service is independently feature-gated via Cargo features, matching
//! the C `HAVE_*` preprocessor macro pattern from `config.h`.
//!
//! The TFTP server implements:
//! - RFC 1350 (TFTP protocol)
//! - RFC 2349 (option negotiation: blksize, tsize, timeout)
//! - RFC 7440 (windowsize option)
//!
//! ## Feature Flags
//! - `tftp` — Enable TFTP server (matches C `HAVE_TFTP`, enabled by default)
//!
//! ## Concurrency Model
//! All services use tokio async I/O, replacing the C poll-based event loop.
//! Concurrent transfers are managed through async tasks with bounded limits
//! (TFTP_MAX_CONNECTIONS: 50 concurrent transfers).

// Feature flag mapping from C HAVE_* macros to Cargo features:
// HAVE_TFTP → cfg(feature = "tftp")  (enabled by default)
//
// The entire services module is gated at lib.rs level:
//   #[cfg(feature = "tftp")]
//   pub mod services;
//
// This means when tftp feature is disabled, this entire module
// and all its sub-modules are excluded from compilation,
// matching the C behavior where HAVE_TFTP guards src/tftp.c.

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Read-only TFTP server with PXE boot support.
///
/// Implements RFC 1350 (TFTP), RFC 2349 (option negotiation),
/// and RFC 7440 (windowsize) for network boot scenarios.
///
/// Migrated from `src/tftp.c` (1,647 lines).
///
/// # Key Features
/// - Async UDP socket I/O via tokio
/// - Concurrent transfer management (up to TFTP_MAX_CONNECTIONS)
/// - PXE-specific extensions for network boot
/// - Option negotiation: blksize (512-65464), tsize, timeout, windowsize (1-32)
/// - Netascii and octet transfer modes
/// - File descriptor sharing for mass boot scenarios
/// - Path security: traversal prevention, permission checking
pub mod tftp;

// ---------------------------------------------------------------------------
// Public re-exports for ergonomic access
// ---------------------------------------------------------------------------

// Re-export primary TFTP types for ergonomic access by consumer modules.
// Allows `use crate::services::TftpServer;` instead of
// `use crate::services::tftp::TftpServer;`.

pub use tftp::TftpError;
pub use tftp::TftpFile;
pub use tftp::TftpPrefix;
pub use tftp::TftpServer;
pub use tftp::TftpTransfer;
pub use tftp::TransferMode;

// NOTE: This module currently contains only the TFTP server.
// Future network services (if any) would be added here as additional
// sub-modules with their own feature gates. The module structure
// mirrors the C source organization where tftp.c is the sole
// service file beyond the DNS and DHCP subsystems.

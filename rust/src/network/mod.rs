// Copyright (C) 2024 Simon Kelley and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! Network interface management and platform abstraction layer.
//!
//! Migrated from `src/network.c`, `src/netlink.c`, `src/bpf.c`, `src/arp.c`
//! (8,351 lines total of C source code).
//!
//! This module provides:
//! - Interface enumeration and address discovery
//! - Socket creation, binding, and listener management
//! - Platform-specific network monitoring (netlink on Linux, PF_ROUTE on BSD)
//! - ARP/neighbor cache management for DHCP conflict detection
//!
//! Platform-specific modules are conditionally compiled via `cfg(target_os)`:
//! - `netlink` — Linux NETLINK_ROUTE (replaces C `HAVE_LINUX_NETWORK`)
//! - `bpf` — BSD BPF and PF_ROUTE (replaces C `HAVE_BSD_NETWORK`)

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

/// Linux netlink socket interface for network interface monitoring.
/// Provides real-time kernel notifications for address and route changes.
#[cfg(target_os = "linux")]
pub mod netlink;

/// BSD BPF raw packet I/O and PF_ROUTE interface monitoring.
/// Compiled only on FreeBSD, OpenBSD, and macOS (replaces C `HAVE_BSD_NETWORK`).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub mod bpf;

/// Core network interface management: enumeration, socket binding, listeners.
/// Migrated from `network.c` — the platform-independent network management core.
pub mod interface;

// NOTE: The following sub-module is planned but created by a separate agent:
// - pub mod arp;        (from arp.c — ARP cache management)

// ---------------------------------------------------------------------------
// Conditional re-exports
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use netlink::{netlink_init, netlink_multicast, nl_async};

#[cfg(target_os = "linux")]
pub use netlink::{IfaceCallback, NetlinkNetwork};

#[cfg(target_os = "linux")]
pub use netlink::{IFACE_DEPRECATED, IFACE_PERMANENT, IFACE_TENTATIVE};

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
pub use bpf::{init_bpf, route_init, route_sock, send_via_bpf, BpfNetwork};

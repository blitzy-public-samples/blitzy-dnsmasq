// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2000-2025 Simon Kelley — Rust rewrite

//! DHCPv6 server implementation (RFC 3315).
//!
//! This module provides the complete DHCPv6 server stack including:
//! - Core server initialization and packet dispatch (`server`)
//! - Full RFC 3315 protocol message processing (`rfc3315`)
//! - DHCPv6 option serialization buffer builder (`outpacket`)
//!
//! # Feature Gate
//!
//! This module is compiled only when the `dhcp6` feature is enabled,
//! controlled by the parent `dhcp` module's conditional compilation.

pub mod outpacket;
pub mod server;

// Re-export primary public types for convenient access.
pub use outpacket::Dhcpv6OutPacket;
pub use server::{
    address6_allocate, address6_available, address6_valid, config_find_by_address6,
    dhcp6_init, dhcp6_packet, dhcp_construct_contexts, get_client_mac, make_duid,
    Dhcp6ServerError,
};

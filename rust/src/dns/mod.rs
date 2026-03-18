// Copyright (C) 2024 dnsmasq contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
//! DNS subsystem module root.
//!
//! This module provides DNS wire format handling, packet parsing/construction,
//! protocol constants, and supporting functionality for the dnsmasq daemon.

pub mod domain;
pub mod domain_match;
pub mod protocol;

#[cfg(feature = "dnssec")]
pub mod blockdata;

#[cfg(feature = "loop-detect")]
pub mod loop_detect;

// Re-export core protocol types for convenient access
pub use protocol::{
    // Byte helpers
    get_u16,
    get_u32,
    put_u16,
    put_u32,
    DnsClass,
    // Header types
    DnsHeader,
    DnsHeaderFlags,
    // Name handling
    DnsName,
    // Packet types
    DnsPacket,
    DnsPacketBuilder,
    DnsQuestion,
    DnsResourceRecord,
    // Enums
    RRType,
    ResponseCode,
    MAXDNAME,
    MAXLABEL,
    // Constants
    NAMESERVER_PORT,
    PACKETSZ,
    RRFIXEDSZ,
};

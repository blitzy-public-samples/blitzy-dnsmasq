//! Shared type definitions for the dnsmasq Rust implementation.
//!
//! This module contains all core data structures used across the dnsmasq codebase,
//! organized by functional domain. These types replace the struct, union, and typedef
//! declarations from the C `dnsmasq.h` header.
//!
//! # Organization
//! - [`addr`] — Address types (`AllAddr`, `SocketAddress`) replacing C unions
//! - `dns` — DNS record types (`DnsHeader`, `CacheEntry`, `ForwardRecord`, `DnsName`)
//! - `dhcp` — DHCP types (`DhcpLease`, `DhcpConfig`, `DhcpContext`) — feature-gated
//! - `network` — Network types (`InterfaceRecord`, `Listener`, `ServerEntry`)
//! - `ipv6` — IPv6 address classification helpers

pub mod addr;

// Re-export commonly used address types for ergonomic imports.
pub use addr::{AllAddr, CnameTarget, SocketAddress, RR_IMDATALEN};

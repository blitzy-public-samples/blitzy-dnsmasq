//! Network interface management, socket pooling, and platform abstraction.
//!
//! This module provides the networking infrastructure for dnsmasq, handling:
//! - Platform-specific networking backends (`platform`)
//!
//! # Architecture
//!
//! The module replaces the flat C source files `network.c`, `arp.c`, and
//! platform-specific files (`netlink.c`, `bpf.c`, `ipset.c`, etc.) with a
//! hierarchical structure using trait-based platform abstraction.
//!
//! Platform-specific behavior is abstracted behind the [`platform::NetworkBackend`]
//! trait, with implementations for Linux (netlink) and BSD (BPF/routing sockets).

pub mod platform;

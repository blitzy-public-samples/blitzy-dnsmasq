// lib.rs — Library root for dnsmasq Rust rewrite
// This is a stub that will be replaced by the code generation agent.

pub mod config;
pub mod core;
pub mod dns;
pub mod types;
pub mod net;
#[cfg(feature = "dump")]
pub mod debug;

#[cfg(any(feature = "dhcp", feature = "dhcp6"))]
pub mod dhcp;

pub mod integration;

// Library crate root - stub for build validation

pub mod config;
pub mod core;
pub mod diagnostics;
pub mod dns;
pub mod network;

#[cfg(feature = "dhcp")]
pub mod dhcp;

pub mod integration;

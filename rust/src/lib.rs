// Library crate root - stub for build validation

pub mod config;
pub mod core;
pub mod diagnostics;
pub mod dns;

#[cfg(feature = "dhcp")]
pub mod dhcp;

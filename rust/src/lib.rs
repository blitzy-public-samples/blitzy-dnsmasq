// Library crate root - stub for build validation

pub mod config;
pub mod core;
pub mod diagnostics;

#[cfg(feature = "dhcp")]
pub mod dhcp;

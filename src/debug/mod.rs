//! Debug utilities for dnsmasq diagnostics.
//!
//! This module contains optional diagnostic tools for protocol debugging
//! and troubleshooting. All sub-modules are feature-gated to prevent
//! unnecessary code inclusion in production builds.

/// Pcap packet capture for DNS/DHCP/TFTP protocol analysis.
///
/// Feature-gated behind `dump` (replacing C `HAVE_DUMPFILE`).
/// Writes standard libpcap format files compatible with Wireshark/tcpdump.
#[cfg(feature = "dump")]
pub mod dump;

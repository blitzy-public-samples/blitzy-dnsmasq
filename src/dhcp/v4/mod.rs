//! DHCPv4 module declarations.
//!
//! Contains the DHCPv4 server core (initialization, packet handling,
//! address allocation) and the DHCPv4 protocol engine (RFC 2131 DORA cycle).

/// DHCPv4 core server logic: init, packet reception, address allocation, ICMP ping.
pub mod server;

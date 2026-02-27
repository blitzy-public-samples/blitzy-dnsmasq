// mod.rs stub for dhcp module — will be replaced by code generation agent

// DHCPv4 wire-format constants (always available for protocol handling)
pub mod protocol_v4;

// DHCPv6 wire-format constants (only with dhcp6 feature)
#[cfg(feature = "dhcp6")]
pub mod protocol_v6;

// Shared DHCP utilities (tag matching, option tables, config lookup)
pub mod common;

// Submodule stubs — will be populated by other agents
pub mod v4;
#[cfg(feature = "dhcp6")]
pub mod v6;
#[cfg(feature = "dhcp6")]
pub mod radv;

// Privilege-separated script helper process
#[cfg(feature = "script")]
pub mod helper;

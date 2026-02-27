// mod.rs stub for dhcp module — will be replaced by code generation agent

// DHCPv4 wire-format constants (always available for protocol handling)
pub mod protocol_v4;

// Submodule stubs — will be populated by other agents
pub mod v4;
#[cfg(feature = "dhcp6")]
pub mod v6;
#[cfg(feature = "dhcp6")]
pub mod radv;

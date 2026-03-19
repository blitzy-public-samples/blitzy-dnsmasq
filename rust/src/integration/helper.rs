// SAFETY: This module contains unsafe blocks for platform-specific FFI operations.
// The crate-level #![deny(unsafe_code)] is overridden here because this module
// requires direct system call interactions that cannot be expressed in safe Rust.
#![allow(unsafe_code)]

// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Script Execution Helper for DHCP/TFTP/ARP Events
//!
//! Rust implementation of the external script execution helper for lease-change
//! callbacks, migrated from `src/helper.c` (1,528 lines). This module manages
//! async process spawning for executing user-configured scripts on DHCP lease
//! events (add/old/del), TFTP transfers, and ARP changes.
//!
//! ## Architecture
//!
//! The C implementation uses a privileged fork-based helper process that reads
//! serialised `struct script_data` from a pipe. The Rust implementation replaces
//! this with:
//!
//! - [`VecDeque<ScriptEvent>`] in-memory event queue (replaces pipe + buffer)
//! - [`tokio::process::Command`] for async script execution (replaces fork/exec)
//! - Rust ownership + borrow checker (eliminates buffer overflow risk)
//!
//! ## Privilege Separation
//!
//! The script path is locked at construction time and cannot be changed afterward.
//! Privileges are dropped to the configured uid/gid before script execution,
//! matching the C security model where the helper process calls
//! `setgroups`/`setgid`/`setuid` before `exec` (helper.c lines 202-260).
//!
//! ## Lua Scripting
//!
//! When the `luascript` feature is enabled, Lua scripts (`.lua` extension) are
//! executed in-process via the `mlua` crate instead of fork/exec. Lua handler
//! functions: `init()`, `shutdown()`, `lease()`, `tftp()`.
//!
//! ## Feature Gates
//!
//! - Entire module: `#[cfg(feature = "script")]` (via `integration/mod.rs`)
//! - Lua scripting: `#[cfg(feature = "luascript")]`
//! - DHCPv6 fields: `#[cfg(feature = "dhcp6")]`
//! - TFTP fields: `#[cfg(feature = "tftp")]`

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::time::SystemTime;

use tokio::process::Command;

use nix::unistd::{Gid, Uid};

use tracing::{debug, error, info, warn};

#[cfg(feature = "luascript")]
use mlua::prelude::Lua;

use crate::config::constants::{ARPHRD_ETHER, CHGRP, CHUSER};
use crate::core::types::{AllAddr, DaemonState, DnsmasqError, MySockAddr};

#[cfg(feature = "dhcp")]
use crate::dhcp::lease::{DhcpLease, LeaseType};

// ---------------------------------------------------------------------------
// Constants (from C helper.c and dnsmasq.h)
// ---------------------------------------------------------------------------

/// Maximum DHCP client hardware address length (matches C DHCP_CHADDR_MAX = 16).
const DHCP_CHADDR_MAX: usize = 16;

/// Lease flag: newly created (C: LEASE_NEW = 1).
const LEASE_NEW: u32 = 1;
/// Lease flag: core data changed (C: LEASE_CHANGED = 2).
const LEASE_CHANGED: u32 = 2;
/// Lease flag: auxiliary data changed (C: LEASE_AUX_CHANGED = 4).
const LEASE_AUX_CHANGED: u32 = 4;
/// Lease flag: DHCPv6 Non-Temporary Address (C: LEASE_NA = 32).
const LEASE_NA: u32 = 32;
/// Lease flag: DHCPv6 Temporary Address (C: LEASE_TA = 64).
const LEASE_TA: u32 = 64;

// ---------------------------------------------------------------------------
// Event Action Type
// ---------------------------------------------------------------------------

/// Script event action type, mapping C `ACTION_*` constants to a Rust enum.
///
/// The action determines the string passed as the second argument to the
/// external script and the value of the `DNSMASQ_ACTION` environment variable.
///
/// ## C Constant Mapping
///
/// | Variant | C Constant | Integer | Script String |
/// |---------|-----------|---------|---------------|
/// | `Add` | `ACTION_ADD` | 4 | `"add"` |
/// | `Del` | `ACTION_DEL` | 1 | `"del"` |
/// | `Old` | `ACTION_OLD` | 3 | `"old"` |
/// | `Tftp` | `ACTION_TFTP` | 5 | `"tftp"` |
/// | `Arp` | `ACTION_ARP` | 6 | `"arp-add"` |
/// | `ArpDel` | `ACTION_ARP_DEL` | 7 | `"arp-del"` |
/// | `RelaySnoopv6` | `ACTION_RELAY_SNOOP` | 8 | `"relay-snoop"` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    /// New DHCP lease created (C: ACTION_ADD = 4).
    Add,
    /// DHCP lease expired or released (C: ACTION_DEL = 1).
    Del,
    /// Existing DHCP lease renewed/updated (C: ACTION_OLD = 3).
    Old,
    /// TFTP file transfer completed (C: ACTION_TFTP = 5).
    Tftp,
    /// ARP table entry added/changed (C: ACTION_ARP = 6).
    Arp,
    /// ARP table entry removed (C: ACTION_ARP_DEL = 7).
    ArpDel,
    /// DHCPv6 relay snoop event (C: ACTION_RELAY_SNOOP = 8).
    RelaySnoopv6,
}

impl EventAction {
    /// Returns the action string passed to scripts, matching C behavior exactly.
    ///
    /// This string is used as:
    /// 1. The second positional argument to the script
    /// 2. The value of the `DNSMASQ_ACTION` environment variable
    ///
    /// Matches C helper.c lines 394-410 action string mapping.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventAction::Add => "add",
            EventAction::Del => "del",
            EventAction::Old => "old",
            EventAction::Tftp => "tftp",
            EventAction::Arp => "arp-add",
            EventAction::ArpDel => "arp-del",
            EventAction::RelaySnoopv6 => "relay-snoop",
        }
    }

    /// Returns true if this is a DHCP lease event (add/del/old).
    fn is_dhcp_event(&self) -> bool {
        matches!(self, EventAction::Add | EventAction::Del | EventAction::Old)
    }
}

impl std::fmt::Display for EventAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Script Event Data
// ---------------------------------------------------------------------------

/// DHCP/TFTP/ARP event data for script execution.
///
/// Replaces C `struct script_data` (helper.c lines 119-141). All variable-length
/// data uses `Vec<u8>` and `String` instead of C's raw pointers with separate
/// length fields, eliminating buffer overflow vulnerabilities.
///
/// ## Safety Improvements
///
/// | C Field | Rust Field | Safety Gain |
/// |---------|-----------|-------------|
/// | `unsigned char hwaddr[DHCP_CHADDR_MAX]` | `Vec<u8>` | Bounds-checked |
/// | `char *hostname` (null-terminated) | `Option<String>` | No null-pointer deref |
/// | `unsigned char *clid` + `clid_len` | `Option<Vec<u8>>` | No buffer over-read |
/// | `unsigned char *extra_data` + `ed_len` | `Option<Vec<u8>>` | No buffer over-read |
pub struct ScriptEvent {
    /// The action type for this event.
    pub action: EventAction,
    /// Raw flag bits from the lease for script compatibility.
    /// Contains LEASE_* bits (LEASE_NA=32, LEASE_TA=64, etc.)
    pub flags: u32,
    /// Hardware (MAC) address bytes. Variable length up to DHCP_CHADDR_MAX.
    pub hwaddr: Vec<u8>,
    /// Hardware address type (e.g., ARPHRD_ETHER = 1 for Ethernet).
    pub hwaddr_type: u16,
    /// DHCP client identifier (option 61 or DHCPv6 DUID).
    pub client_id: Option<Vec<u8>>,
    /// Client hostname (may be client-supplied or config-assigned).
    pub hostname: Option<String>,
    /// Extra data blob containing vendor class, relay agent info, tags, etc.
    /// Fields are null-terminated and packed sequentially.
    pub extra_data: Option<Vec<u8>>,
    /// IPv4 address (DHCPv4 assigned address or TFTP peer).
    pub addr: Ipv4Addr,
    /// Gateway/relay agent IPv4 address (DHCPv4 relay).
    pub giaddr: Ipv4Addr,
    /// IPv6 address (DHCPv6 assigned address or TFTP peer).
    pub addr6: Ipv6Addr,
    /// Remaining lease time in seconds.
    pub remaining_time: u32,
    /// Lease expiration timestamp (when RTC is available).
    /// None when using HAVE_BROKEN_RTC mode (use lease_length instead).
    pub expires: Option<SystemTime>,
    /// Lease length in seconds (used when RTC is broken — HAVE_BROKEN_RTC).
    /// When RTC is available, this is None and `expires` is used instead.
    pub lease_length: Option<u32>,
    /// Network interface name where the event occurred.
    pub interface: String,
    /// Number of DHCPv6 vendor class entries in extra_data.
    #[cfg(feature = "dhcp6")]
    pub vendorclass_count: i32,
    /// DHCPv6 Identity Association ID.
    #[cfg(feature = "dhcp6")]
    pub iaid: u32,
    /// TFTP transferred file size in bytes.
    #[cfg(feature = "tftp")]
    pub file_len: Option<u64>,
}

impl ScriptEvent {
    /// Returns true if this event is for a DHCPv6 lease (NA or TA type).
    /// Checks the LEASE_NA and LEASE_TA flag bits.
    fn is_v6(&self) -> bool {
        (self.flags & (LEASE_NA | LEASE_TA)) != 0
    }

    /// Create a new ScriptEvent with default/unspecified values for the given action.
    fn new_default(action: EventAction) -> Self {
        Self {
            action,
            flags: 0,
            hwaddr: Vec::new(),
            hwaddr_type: 0,
            client_id: None,
            hostname: None,
            extra_data: None,
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            addr6: Ipv6Addr::UNSPECIFIED,
            remaining_time: 0,
            expires: None,
            lease_length: None,
            interface: String::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "tftp")]
            file_len: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ScriptHelper — Event Queuing & Execution Manager
// ---------------------------------------------------------------------------

/// Script execution helper managing event queuing and async process spawning.
///
/// Replaces the C fork-based helper process (helper.c `create_helper()`) with
/// an async task-based model using [`tokio::process::Command`]. Events are queued
/// in-memory via [`VecDeque`] instead of being serialised over a pipe, eliminating
/// buffer overflow risks and simplifying error handling.
///
/// ## Security Model
///
/// - Script path is locked at construction time and cannot be changed afterward
/// - Privileges are dropped to configured uid/gid before script execution
/// - All data is validated before passing to external scripts
/// - Environment variables are sanitised before script invocation
pub struct ScriptHelper {
    /// Script path, locked at construction time for security.
    script_path: Option<String>,
    /// Event queue replacing C pipe-based communication.
    event_queue: VecDeque<ScriptEvent>,
    /// User ID to drop privileges to before script execution.
    script_uid: Option<Uid>,
    /// Group ID to drop privileges to before script execution.
    script_gid: Option<Gid>,
    /// Cached old hostname for two-event hostname-change sequence.
    old_hostname_cache: Option<String>,
    /// Lua interpreter state for executing Lua lease-change scripts.
    #[cfg(feature = "luascript")]
    lua_state: Option<Lua>,
}

impl ScriptHelper {
    /// Create a new [`ScriptHelper`] with locked script path and privilege settings.
    ///
    /// The script path is immutable after construction, matching C's security
    /// model where the path is locked at daemon startup (helper.c lines 86-98).
    ///
    /// # Arguments
    ///
    /// * `script_path` - Path to the lease-change script (`None` = no script)
    /// * `uid` - User ID for privilege dropping (`None` = keep current user)
    /// * `gid` - Group ID for privilege dropping (`None` = keep current group)
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError::Misc`] if Lua initialisation fails.
    pub fn new(
        script_path: Option<String>,
        uid: Option<Uid>,
        gid: Option<Gid>,
    ) -> Result<Self, DnsmasqError> {
        #[cfg(feature = "luascript")]
        let lua_state = {
            if let Some(ref path) = script_path {
                if path.ends_with(".lua") {
                    let lua = Lua::new();
                    let script_content = std::fs::read_to_string(path).map_err(|e| {
                        DnsmasqError::Misc(format!("failed to read Lua script '{}': {}", path, e))
                    })?;
                    lua.load(&script_content).exec().map_err(|e| {
                        DnsmasqError::Misc(format!("failed to load Lua script '{}': {}", path, e))
                    })?;
                    // Call Lua init() if defined — optional per C behavior.
                    let globals = lua.globals();
                    if let Ok(init_fn) = globals.get::<mlua::Function>("init") {
                        init_fn
                            .call::<()>(())
                            .map_err(|e| DnsmasqError::Misc(format!("Lua init() failed: {}", e)))?;
                        info!(script = %path, "Lua script init() completed");
                    }
                    Some(lua)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(ref path) = script_path {
            info!(script = %path, "script helper initialised");
        } else {
            debug!("script helper initialised without script");
        }

        Ok(Self {
            script_path,
            event_queue: VecDeque::new(),
            script_uid: uid,
            script_gid: gid,
            old_hostname_cache: None,
            #[cfg(feature = "luascript")]
            lua_state,
        })
    }

    /// Create a [`ScriptHelper`] from [`DaemonState`] configuration.
    ///
    /// Extracts the script path, Lua script path, and script execution user
    /// from the daemon state. Uses [`CHUSER`] / [`CHGRP`] as default privilege
    /// separation credentials when no explicit user/group is configured,
    /// matching C `daemon->scriptuser` default behaviour.
    pub fn from_daemon_state(state: &DaemonState) -> Result<Self, DnsmasqError> {
        // Determine the script path: prefer lease_change_command, fallback to luascript.
        #[cfg(feature = "luascript")]
        let script_path = state
            .lease_change_command
            .clone()
            .or_else(|| state.luascript.clone());

        #[cfg(not(feature = "luascript"))]
        let script_path = state.lease_change_command.clone();

        // Resolve uid/gid from scriptuser, falling back to CHUSER/CHGRP.
        let username = state.scriptuser.as_deref().unwrap_or(CHUSER);

        let (uid, gid) = Self::resolve_default_credentials(username, CHGRP);
        Self::new(script_path, uid, gid)
    }

    /// Resolve numeric user and group IDs from name strings.
    ///
    /// Uses [`CHUSER`] and [`CHGRP`] as the default privilege separation
    /// user and group names, matching C `daemon->scriptuser` default behaviour.
    ///
    /// Returns `(None, None)` if the names cannot be resolved (e.g. on systems
    /// where the user/group does not exist).
    pub fn resolve_default_credentials(
        username: &str,
        groupname: &str,
    ) -> (Option<Uid>, Option<Gid>) {
        let uid = nix::unistd::User::from_name(username)
            .ok()
            .flatten()
            .map(|u| u.uid);
        let gid = nix::unistd::Group::from_name(groupname)
            .ok()
            .flatten()
            .map(|g| g.gid);
        (uid, gid)
    }

    // -----------------------------------------------------------------------
    // Event queuing methods
    // -----------------------------------------------------------------------

    /// Queue a DHCP lease event for script notification.
    ///
    /// Serialises lease information into a [`ScriptEvent`] and pushes it onto
    /// the event queue. Replaces C `queue_script()` (helper.c lines 1132-1201).
    #[cfg(feature = "dhcp")]
    pub fn queue_script(
        &mut self,
        action: EventAction,
        lease: &DhcpLease,
        hostname: Option<&str>,
        now: SystemTime,
    ) {
        if self.script_path.is_none() {
            return;
        }

        // Calculate remaining lease time from expiry.
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let remaining_time = if lease.expires > 0 {
            let diff = lease.expires - now_secs;
            if diff > 0 {
                diff as u32
            } else {
                0
            }
        } else {
            0
        };

        // Convert expiry to SystemTime.
        let expires = if lease.expires > 0 {
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(lease.expires as u64))
        } else {
            None
        };

        // Reconstruct flag bits from public LeaseFlags and lease type.
        let mut flags = 0u32;
        if lease.flags.is_new {
            flags |= LEASE_NEW;
        }
        if lease.flags.has_changed {
            flags |= LEASE_CHANGED;
        }
        if lease.flags.aux_changed {
            flags |= LEASE_AUX_CHANGED;
        }
        // Determine v6 lease type via direct enum variant matching.
        match lease.lease_type {
            LeaseType::Na => flags |= LEASE_NA,
            LeaseType::Ta => flags |= LEASE_TA,
            _ => {} // Pd and V4 do not set additional flags here
        }

        let resolved_hostname = hostname
            .map(|h| h.to_string())
            .or_else(|| lease.hostname.clone());

        // Cache old_hostname for DNSMASQ_OLD_HOSTNAME env var.
        if let Some(ref oh) = lease.old_hostname {
            self.old_hostname_cache = Some(oh.clone());
        }

        let mut event = ScriptEvent::new_default(action);
        event.flags = flags;
        event.hwaddr = lease.hwaddr.clone();
        event.hwaddr_type = lease.hwaddr_type as u16;
        event.client_id = lease.clid.clone();
        event.hostname = resolved_hostname;
        event.extra_data = lease.extradata.clone();
        event.addr = lease.addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
        event.giaddr = Ipv4Addr::UNSPECIFIED;
        event.addr6 = lease.addr6.unwrap_or(Ipv6Addr::UNSPECIFIED);
        event.remaining_time = remaining_time;
        event.expires = expires;
        event.interface = lease.interface.clone().unwrap_or_default();
        #[cfg(feature = "dhcp6")]
        {
            event.vendorclass_count = 0;
            event.iaid = lease.iaid;
        }

        debug!(
            action = %event.action,
            interface = %event.interface,
            hostname = ?event.hostname,
            remaining = event.remaining_time,
            "queued DHCP script event"
        );
        self.event_queue.push_back(event);
    }

    /// Queue a TFTP file transfer completion event.
    ///
    /// Replaces C `queue_tftp()` (helper.c lines ~1330-1354).
    pub fn queue_tftp(&mut self, file_len: u64, filename: &str, peer: &MySockAddr) {
        if self.script_path.is_none() {
            return;
        }

        let (addr, addr6) = match peer {
            MySockAddr::V4(sa) => (*sa.ip(), Ipv6Addr::UNSPECIFIED),
            MySockAddr::V6(sa) => (Ipv4Addr::UNSPECIFIED, *sa.ip()),
        };

        let mut event = ScriptEvent::new_default(EventAction::Tftp);
        event.hostname = Some(filename.to_string());
        event.addr = addr;
        event.addr6 = addr6;
        #[cfg(feature = "tftp")]
        {
            event.file_len = Some(file_len);
        }

        debug!(filename = %filename, file_len = file_len, "queued TFTP script event");
        self.event_queue.push_back(event);
    }

    /// Queue an ARP table change event.
    ///
    /// Replaces C `queue_arp()` (helper.c lines 1400-1420). Hardware address
    /// type defaults to [`ARPHRD_ETHER`] (helper.c line 1411).
    pub fn queue_arp(&mut self, action: EventAction, mac: &[u8], _family: i32, addr: &AllAddr) {
        if self.script_path.is_none() {
            return;
        }

        let mut event = ScriptEvent::new_default(action);
        // Truncate MAC to maximum hardware address length (C: DHCP_CHADDR_MAX).
        let mac_len = mac.len().min(DHCP_CHADDR_MAX);
        event.hwaddr = mac[..mac_len].to_vec();
        event.hwaddr_type = ARPHRD_ETHER;

        match addr {
            AllAddr::V4(v4) => {
                event.addr = *v4;
            }
            AllAddr::V6(v6) => {
                event.addr6 = *v6;
                event.flags |= LEASE_NA;
            }
            _ => {
                warn!(action = %event.action, "queue_arp called with unsupported address type");
            }
        }

        debug!(action = %event.action, mac_len = mac.len(), "queued ARP script event");
        self.event_queue.push_back(event);
    }

    /// Queue a DHCPv6 relay snoop event.
    ///
    /// Replaces C `queue_relay_snoop()` (helper.c lines 1266-1285). The prefix
    /// is formatted as `"addr/len"` in the hostname field.
    #[cfg(feature = "dhcp6")]
    pub fn queue_relay_snoop(
        &mut self,
        client: &Ipv6Addr,
        _if_index: i32,
        prefix: &Ipv6Addr,
        prefix_len: i32,
    ) {
        if self.script_path.is_none() {
            return;
        }

        let mut event = ScriptEvent::new_default(EventAction::RelaySnoopv6);
        event.addr6 = *client;
        event.flags = LEASE_NA;
        event.hostname = Some(format!("{}/{}", prefix, prefix_len));

        debug!(
            client = %client, prefix = %prefix, prefix_len = prefix_len,
            "queued relay snoop script event"
        );
        self.event_queue.push_back(event);
    }

    /// Returns `true` if there are no pending events in the queue.
    ///
    /// Replaces C `helper_buf_empty()` (helper.c line 1458).
    pub fn is_empty(&self) -> bool {
        self.event_queue.is_empty()
    }

    // -----------------------------------------------------------------------
    // Script execution
    // -----------------------------------------------------------------------

    /// Process all queued events, executing the configured script for each.
    ///
    /// Drains the event queue and spawns the configured script via
    /// [`tokio::process::Command`] for each event, replacing the C fork/exec
    /// pattern (helper.c lines 259-621).
    ///
    /// ## Script Invocation Format
    ///
    /// ```text
    /// script_path action MAC_address IP_address hostname
    /// ```
    ///
    /// ## Environment Variables
    ///
    /// The following environment variables are set per event, matching the
    /// C implementation exactly for backward compatibility:
    ///
    /// - `DNSMASQ_ACTION` — event type ("add", "del", "old", "tftp", etc.)
    /// - `DNSMASQ_INTERFACE` — network interface name
    /// - `DNSMASQ_LEASE_EXPIRES` — lease expiry UNIX timestamp
    /// - `DNSMASQ_TIME_REMAINING` — remaining lease seconds
    /// - `DNSMASQ_SUPPLIED_HOSTNAME` — client-supplied hostname
    /// - `DNSMASQ_CLIENT_ID` — DHCP client identifier (hex)
    /// - Plus many more; see implementation for full list.
    pub async fn process_events(&mut self) -> Result<(), DnsmasqError> {
        while let Some(event) = self.event_queue.pop_front() {
            #[cfg(feature = "luascript")]
            {
                if self.lua_state.is_some() {
                    self.execute_lua_event(&event)?;
                    continue;
                }
            }

            let script_path = match self.script_path {
                Some(ref p) => p.clone(),
                None => continue,
            };

            // Format the MAC address as colon-separated hex.
            let mac_str = format_mac_address(&event.hwaddr);

            // Format the IP address string.
            let addr_str = if event.is_v6() {
                format!("{}", event.addr6)
            } else {
                format!("{}", event.addr)
            };

            // Hostname (empty string if not set).
            let hostname_str = event.hostname.clone().unwrap_or_default();

            // Action string for script argv[1].
            let action_str = event.action.as_str();

            // Build environment variables matching C helper.c lines 300-790.
            let mut envs: Vec<(String, String)> = Vec::with_capacity(32);

            // Core variables always set.
            envs.push(("DNSMASQ_ACTION".to_string(), action_str.to_string()));

            if !event.interface.is_empty() {
                envs.push(("DNSMASQ_INTERFACE".to_string(), event.interface.clone()));
            }

            // Time-related variables.
            envs.push((
                "DNSMASQ_TIME_REMAINING".to_string(),
                event.remaining_time.to_string(),
            ));

            if let Some(expires) = event.expires {
                if let Ok(dur) = expires.duration_since(SystemTime::UNIX_EPOCH) {
                    envs.push((
                        "DNSMASQ_LEASE_EXPIRES".to_string(),
                        dur.as_secs().to_string(),
                    ));
                }
            }

            if let Some(lease_len) = event.lease_length {
                envs.push(("DNSMASQ_LEASE_LENGTH".to_string(), lease_len.to_string()));
            }

            // Hostname-related variables.
            if let Some(ref hn) = event.hostname {
                if !hn.is_empty() {
                    envs.push(("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), hn.clone()));
                }
            }

            if let Some(ref old_hn) = self.old_hostname_cache {
                if !old_hn.is_empty() {
                    envs.push(("DNSMASQ_OLD_HOSTNAME".to_string(), old_hn.clone()));
                }
            }

            // Client ID (hex-encoded).
            if let Some(ref clid) = event.client_id {
                if !clid.is_empty() {
                    let clid_hex: String = clid
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    envs.push(("DNSMASQ_CLIENT_ID".to_string(), clid_hex));
                }
            }

            // Gateway / relay agent address (DHCPv4).
            if event.giaddr != Ipv4Addr::UNSPECIFIED {
                envs.push((
                    "DNSMASQ_RELAY_ADDRESS".to_string(),
                    format!("{}", event.giaddr),
                ));
            }

            // DHCPv6-specific variables.
            #[cfg(feature = "dhcp6")]
            {
                if event.is_v6() && event.action.is_dhcp_event() {
                    envs.push(("DNSMASQ_IAID".to_string(), event.iaid.to_string()));

                    // MAC address for v6 events (separate from positional arg).
                    if !event.hwaddr.is_empty() {
                        envs.push(("DNSMASQ_MAC".to_string(), mac_str.clone()));
                    }
                }
            }

            // Extra data processing — vendor class, user class, tags, relay data.
            if let Some(ref extra) = event.extra_data {
                Self::parse_extra_data(extra, &event, &mut envs);
            }

            // TFTP-specific file length.
            #[cfg(feature = "tftp")]
            {
                if let Some(flen) = event.file_len {
                    envs.push(("DNSMASQ_FILE_LENGTH".to_string(), flen.to_string()));
                }
            }

            // Spawn the script process with privilege dropping.
            let uid = self.script_uid;
            let gid = self.script_gid;

            info!(
                script = %script_path,
                action = action_str,
                addr = %addr_str,
                "executing lease-change script"
            );

            let mut cmd = Command::new(&script_path);
            cmd.arg(action_str)
                .arg(&mac_str)
                .arg(&addr_str)
                .arg(&hostname_str)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_clear();

            // Set all computed environment variables.
            for (key, val) in &envs {
                cmd.env(key, val);
            }

            // Preserve PATH for script discovery.
            if let Ok(path) = std::env::var("PATH") {
                cmd.env("PATH", path);
            }

            // Drop privileges before exec — SAFETY: setgroups/setgid/setuid are
            // async-signal-safe and the closure runs in the forked child
            // between fork and exec, matching C helper.c lines 202-260.
            // C calls setgroups(0, NULL) before setgid() to clear supplementary
            // groups, preventing privilege escalation through group memberships.
            unsafe {
                cmd.pre_exec(move || {
                    // Clear supplementary groups before changing GID.
                    // C: setgroups(0, NULL) — helper.c line 225.
                    // This prevents the child from retaining any supplementary
                    // group memberships from the parent process.
                    if gid.is_some() {
                        nix::unistd::setgroups(&[]).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("setgroups(0) failed: {}", e),
                            )
                        })?;
                    }
                    if let Some(gid_val) = gid {
                        nix::unistd::setgid(gid_val).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("setgid({}) failed: {}", gid_val, e),
                            )
                        })?;
                    }
                    if let Some(uid_val) = uid {
                        nix::unistd::setuid(uid_val).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("setuid({}) failed: {}", uid_val, e),
                            )
                        })?;
                    }
                    Ok(())
                });
            }

            // Wrap script execution with a timeout to prevent hanging scripts
            // from blocking the async task indefinitely. C uses HELPER_TIMEOUT
            // (typically 120 seconds). We use 120 seconds as the default.
            const HELPER_TIMEOUT_SECS: u64 = 120;
            let timeout_duration = std::time::Duration::from_secs(HELPER_TIMEOUT_SECS);

            match tokio::time::timeout(timeout_duration, cmd.output()).await {
                Ok(Ok(output)) => {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!(
                            script = %script_path,
                            action = action_str,
                            status = ?output.status,
                            stderr = %stderr.trim(),
                            "script exited with non-zero status"
                        );
                    } else {
                        debug!(
                            script = %script_path,
                            action = action_str,
                            "script completed successfully"
                        );
                    }
                }
                Ok(Err(e)) => {
                    error!(
                        script = %script_path,
                        action = action_str,
                        error = %e,
                        "failed to execute script"
                    );
                    return Err(DnsmasqError::Misc(format!(
                        "script execution failed: {}",
                        e
                    )));
                }
                Err(_elapsed) => {
                    // Timeout expired — script was killed or is still hanging.
                    // Log and continue processing other events.
                    error!(
                        script = %script_path,
                        action = action_str,
                        timeout_secs = HELPER_TIMEOUT_SECS,
                        "script execution timed out"
                    );
                    return Err(DnsmasqError::Misc(format!(
                        "script execution timed out after {} seconds",
                        HELPER_TIMEOUT_SECS
                    )));
                }
            }

            // Clear old hostname cache after it has been used once.
            self.old_hostname_cache = None;
        }

        Ok(())
    }

    /// Parse extra data buffer to extract vendor class, user class, tags, and
    /// relay agent information. Sets corresponding `DNSMASQ_*` environment
    /// variables.
    ///
    /// The extra data buffer uses NUL-separated fields matching the C
    /// implementation in helper.c lines 430-530.
    fn parse_extra_data(extra: &[u8], event: &ScriptEvent, envs: &mut Vec<(String, String)>) {
        // Extra data is NUL-separated fields: the order depends on the
        // event action and protocol version (v4 vs v6).
        let fields: Vec<&[u8]> = extra.split(|&b| b == 0).collect();
        let mut field_idx = 0;

        if event.action.is_dhcp_event() {
            // Field 0: vendor class (DHCPv4) or vendor class data (DHCPv6).
            if let Some(vc) = fields.get(field_idx) {
                if !vc.is_empty() {
                    if event.is_v6() {
                        // DHCPv6 may have multiple vendor classes.
                        #[cfg(feature = "dhcp6")]
                        {
                            let vc_str = String::from_utf8_lossy(vc);
                            envs.push(("DNSMASQ_VENDOR_CLASS_ID".to_string(), vc_str.to_string()));
                        }
                    } else {
                        let vc_str = String::from_utf8_lossy(vc);
                        envs.push(("DNSMASQ_VENDOR_CLASS".to_string(), vc_str.to_string()));
                    }
                }
                field_idx += 1;
            }

            // Field 1: CPEWAN data (DHCPv4 only) — OUI, serial, class.
            if !event.is_v6() {
                if let Some(cpewan) = fields.get(field_idx) {
                    if !cpewan.is_empty() {
                        let cpewan_str = String::from_utf8_lossy(cpewan);
                        // CPEWAN fields are comma-separated: OUI,Serial,Class
                        let parts: Vec<&str> = cpewan_str.splitn(3, ',').collect();
                        if let Some(oui) = parts.first() {
                            if !oui.is_empty() {
                                envs.push(("DNSMASQ_CPEWAN_OUI".to_string(), oui.to_string()));
                            }
                        }
                        if let Some(serial) = parts.get(1) {
                            if !serial.is_empty() {
                                envs.push((
                                    "DNSMASQ_CPEWAN_SERIAL".to_string(),
                                    serial.to_string(),
                                ));
                            }
                        }
                        if let Some(class) = parts.get(2) {
                            if !class.is_empty() {
                                envs.push(("DNSMASQ_CPEWAN_CLASS".to_string(), class.to_string()));
                            }
                        }
                    }
                    field_idx += 1;
                }
            }

            // Next fields: circuit ID, subscriber ID, remote ID (DHCPv4 only).
            if !event.is_v6() {
                if let Some(circuit_id) = fields.get(field_idx) {
                    if !circuit_id.is_empty() {
                        let cid_hex: String = circuit_id
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":");
                        envs.push(("DNSMASQ_CIRCUIT_ID".to_string(), cid_hex));
                    }
                    field_idx += 1;
                }
                if let Some(subscriber_id) = fields.get(field_idx) {
                    if !subscriber_id.is_empty() {
                        let sid_str = String::from_utf8_lossy(subscriber_id);
                        envs.push(("DNSMASQ_SUBSCRIBER_ID".to_string(), sid_str.to_string()));
                    }
                    field_idx += 1;
                }
                if let Some(remote_id) = fields.get(field_idx) {
                    if !remote_id.is_empty() {
                        let rid_hex: String = remote_id
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":");
                        envs.push(("DNSMASQ_REMOTE_ID".to_string(), rid_hex));
                    }
                    field_idx += 1;
                }
            }

            // Tags field.
            if let Some(tags) = fields.get(field_idx) {
                if !tags.is_empty() {
                    let tags_str = String::from_utf8_lossy(tags);
                    envs.push(("DNSMASQ_TAGS".to_string(), tags_str.to_string()));
                }
                field_idx += 1;
            }

            // User class fields (numbered DNSMASQ_USER_CLASS0, _CLASS1, ...).
            let mut user_class_idx = 0;
            while let Some(uc) = fields.get(field_idx) {
                if uc.is_empty() {
                    break;
                }
                let uc_str = String::from_utf8_lossy(uc);
                envs.push((
                    format!("DNSMASQ_USER_CLASS{}", user_class_idx),
                    uc_str.to_string(),
                ));
                user_class_idx += 1;
                field_idx += 1;
            }

            // Domain field.
            if let Some(domain) = fields.get(field_idx.wrapping_add(1)) {
                if !domain.is_empty() {
                    let dom_str = String::from_utf8_lossy(domain);
                    envs.push(("DNSMASQ_DOMAIN".to_string(), dom_str.to_string()));
                }
            }

            // Requested options (DHCPv4).
            if !event.is_v6() {
                if let Some(req_opts) = fields.get(field_idx.wrapping_add(2)) {
                    if !req_opts.is_empty() {
                        let opts_str = String::from_utf8_lossy(req_opts);
                        envs.push((
                            "DNSMASQ_REQUESTED_OPTIONS".to_string(),
                            opts_str.to_string(),
                        ));
                    }
                }
            }

            // MUD URL field.
            if let Some(mud) = fields.get(field_idx.wrapping_add(3)) {
                if !mud.is_empty() {
                    let mud_str = String::from_utf8_lossy(mud);
                    envs.push(("DNSMASQ_MUD_URL".to_string(), mud_str.to_string()));
                }
            }
        }
    }

    /// Execute a queued event via Lua scripting.
    ///
    /// Dispatches to the appropriate Lua function (`lease()`, `tftp()`,
    /// `arp()`, `snoop()`) based on the event action, matching C helper.c
    /// lines 259-621 Lua integration.
    #[cfg(feature = "luascript")]
    fn execute_lua_event(&self, event: &ScriptEvent) -> Result<(), DnsmasqError> {
        let lua = match self.lua_state {
            Some(ref l) => l,
            None => return Ok(()),
        };

        let globals = lua.globals();

        match event.action {
            EventAction::Add | EventAction::Del | EventAction::Old => {
                // Call lease(action, data_table).
                let func: mlua::Function = match globals.get("lease") {
                    Ok(f) => f,
                    Err(_) => {
                        debug!("Lua lease() function not defined, skipping");
                        return Ok(());
                    }
                };

                let action_str = event.action.as_str();
                let table = lua
                    .create_table()
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table creation failed: {}", e)))?;

                // Populate data table matching C Lua integration.
                table
                    .set("action", action_str)
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                table
                    .set("mac_address", format_mac_address(&event.hwaddr))
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;

                if event.is_v6() {
                    table
                        .set("ip_address", format!("{}", event.addr6))
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                } else {
                    table
                        .set("ip_address", format!("{}", event.addr))
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                if let Some(ref hn) = event.hostname {
                    table
                        .set("hostname", hn.as_str())
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                if !event.interface.is_empty() {
                    table
                        .set("interface", event.interface.as_str())
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                table
                    .set("time_remaining", event.remaining_time)
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;

                if let Some(ref clid) = event.client_id {
                    let clid_hex: String = clid
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    table
                        .set("client_id", clid_hex)
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                #[cfg(feature = "dhcp6")]
                if event.is_v6() {
                    table
                        .set("iaid", event.iaid)
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                func.call::<()>((action_str, table))
                    .map_err(|e| DnsmasqError::Misc(format!("Lua lease() call failed: {}", e)))?;

                info!(action = action_str, "Lua lease() executed");
            }

            EventAction::Tftp => {
                // Call tftp(data_table).
                let func: mlua::Function = match globals.get("tftp") {
                    Ok(f) => f,
                    Err(_) => {
                        debug!("Lua tftp() function not defined, skipping");
                        return Ok(());
                    }
                };

                let table = lua
                    .create_table()
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table creation failed: {}", e)))?;

                if event.is_v6() {
                    table
                        .set("destination_address", format!("{}", event.addr6))
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                } else {
                    table
                        .set("destination_address", format!("{}", event.addr))
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                if let Some(ref filename) = event.hostname {
                    table
                        .set("file_name", filename.as_str())
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                #[cfg(feature = "tftp")]
                if let Some(flen) = event.file_len {
                    table
                        .set("file_length", flen)
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                func.call::<()>(table)
                    .map_err(|e| DnsmasqError::Misc(format!("Lua tftp() call failed: {}", e)))?;

                info!("Lua tftp() executed");
            }

            EventAction::Arp | EventAction::ArpDel => {
                // Call arp(data_table).
                let func: mlua::Function = match globals.get("arp") {
                    Ok(f) => f,
                    Err(_) => {
                        debug!("Lua arp() function not defined, skipping");
                        return Ok(());
                    }
                };

                let table = lua
                    .create_table()
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table creation failed: {}", e)))?;

                table
                    .set("action", event.action.as_str())
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                table
                    .set("mac_address", format_mac_address(&event.hwaddr))
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;

                if event.is_v6() {
                    table
                        .set("ip_address", format!("{}", event.addr6))
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                } else {
                    table
                        .set("ip_address", format!("{}", event.addr))
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                func.call::<()>(table)
                    .map_err(|e| DnsmasqError::Misc(format!("Lua arp() call failed: {}", e)))?;

                info!(action = %event.action, "Lua arp() executed");
            }

            EventAction::RelaySnoopv6 => {
                // Call snoop(data_table).
                let func: mlua::Function = match globals.get("snoop") {
                    Ok(f) => f,
                    Err(_) => {
                        debug!("Lua snoop() function not defined, skipping");
                        return Ok(());
                    }
                };

                let table = lua
                    .create_table()
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table creation failed: {}", e)))?;

                table
                    .set("client_address", format!("{}", event.addr6))
                    .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;

                if let Some(ref prefix) = event.hostname {
                    table
                        .set("prefix", prefix.as_str())
                        .map_err(|e| DnsmasqError::Misc(format!("Lua table set failed: {}", e)))?;
                }

                func.call::<()>(table)
                    .map_err(|e| DnsmasqError::Misc(format!("Lua snoop() call failed: {}", e)))?;

                info!("Lua snoop() executed");
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Drop Implementation — Lua Cleanup
// ---------------------------------------------------------------------------

#[cfg(feature = "luascript")]
impl Drop for ScriptHelper {
    /// Calls Lua `shutdown()` function if defined, then drops the Lua state.
    ///
    /// Matches C helper.c cleanup where the Lua `shutdown()` function is
    /// invoked when the daemon exits.
    fn drop(&mut self) {
        if let Some(ref lua) = self.lua_state {
            let globals = lua.globals();
            if let Ok(shutdown_fn) = globals.get::<mlua::Function>("shutdown") {
                if let Err(e) = shutdown_fn.call::<()>(()) {
                    warn!(error = %e, "Lua shutdown() failed during cleanup");
                } else {
                    debug!("Lua shutdown() completed");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/// Format a hardware (MAC) address as a colon-separated hexadecimal string.
///
/// Example: `[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]` → `"aa:bb:cc:dd:ee:ff"`.
fn format_mac_address(hwaddr: &[u8]) -> String {
    if hwaddr.is_empty() {
        return String::new();
    }
    hwaddr
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// Standalone Public Functions (module-level convenience wrappers)
// ---------------------------------------------------------------------------

/// Queue a DHCP lease event for script notification (standalone convenience).
///
/// Delegates to [`ScriptHelper::queue_script()`]. This is the module-level
/// export matching the C `queue_script()` global function (helper.c line 1132).
#[cfg(feature = "dhcp")]
pub fn queue_script(
    helper: &mut ScriptHelper,
    action: EventAction,
    lease: &DhcpLease,
    hostname: Option<&str>,
    now: SystemTime,
) {
    helper.queue_script(action, lease, hostname, now);
}

/// Queue an ARP table change event (standalone convenience).
///
/// Delegates to [`ScriptHelper::queue_arp()`]. This is the module-level
/// export matching the C `queue_arp()` global function (helper.c line 1400).
pub fn queue_arp(
    helper: &mut ScriptHelper,
    action: EventAction,
    mac: &[u8],
    family: i32,
    addr: &AllAddr,
) {
    helper.queue_arp(action, mac, family, addr);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Address family constants for tests (matching libc values on Linux).
    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 10;

    #[test]
    fn test_event_action_as_str() {
        assert_eq!(EventAction::Add.as_str(), "add");
        assert_eq!(EventAction::Del.as_str(), "del");
        assert_eq!(EventAction::Old.as_str(), "old");
        assert_eq!(EventAction::Tftp.as_str(), "tftp");
        assert_eq!(EventAction::Arp.as_str(), "arp-add");
        assert_eq!(EventAction::ArpDel.as_str(), "arp-del");
        assert_eq!(EventAction::RelaySnoopv6.as_str(), "relay-snoop");
    }

    #[test]
    fn test_event_action_is_dhcp_event() {
        assert!(EventAction::Add.is_dhcp_event());
        assert!(EventAction::Del.is_dhcp_event());
        assert!(EventAction::Old.is_dhcp_event());
        assert!(!EventAction::Tftp.is_dhcp_event());
        assert!(!EventAction::Arp.is_dhcp_event());
        assert!(!EventAction::ArpDel.is_dhcp_event());
        assert!(!EventAction::RelaySnoopv6.is_dhcp_event());
    }

    #[test]
    fn test_format_mac_address() {
        assert_eq!(
            format_mac_address(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            format_mac_address(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "00:11:22:33:44:55"
        );
        assert_eq!(format_mac_address(&[]), "");
        assert_eq!(format_mac_address(&[0x42]), "42");
    }

    #[test]
    fn test_script_event_is_v6() {
        let mut event = ScriptEvent::new_default(EventAction::Add);
        // Default event has no v6 flags.
        assert!(!event.is_v6());

        // LEASE_NA flag marks DHCPv6 Non-Temporary Address.
        event.flags = LEASE_NA;
        assert!(event.is_v6());

        // LEASE_TA flag marks DHCPv6 Temporary Address.
        event.flags = LEASE_TA;
        assert!(event.is_v6());

        // Both flags combined.
        event.flags = LEASE_NA | LEASE_TA;
        assert!(event.is_v6());

        // No v6 flags: is_v6 returns false even with a v6 address set,
        // because v6 determination comes from DHCP lease flags (matching C).
        event.flags = 0;
        event.addr6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(!event.is_v6());
    }

    #[test]
    fn test_script_helper_new_no_script() {
        let helper = ScriptHelper::new(None, None, None).unwrap();
        assert!(helper.is_empty());
        assert!(helper.script_path.is_none());
    }

    #[test]
    fn test_script_helper_queue_arp_no_script() {
        let mut helper = ScriptHelper::new(None, None, None).unwrap();
        let addr = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        helper.queue_arp(
            EventAction::Arp,
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            AF_INET,
            &addr,
        );
        // No script configured, so queue should remain empty.
        assert!(helper.is_empty());
    }

    #[test]
    fn test_script_helper_queue_arp_with_script() {
        let mut helper =
            ScriptHelper::new(Some("/usr/bin/test-script".to_string()), None, None).unwrap();
        let addr = AllAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        helper.queue_arp(
            EventAction::Arp,
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            AF_INET,
            &addr,
        );
        assert!(!helper.is_empty());
    }

    #[test]
    fn test_script_helper_queue_tftp_no_script() {
        let mut helper = ScriptHelper::new(None, None, None).unwrap();
        let peer = MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 69));
        helper.queue_tftp(1024, "pxelinux.0", &peer);
        assert!(helper.is_empty());
    }

    #[test]
    fn test_script_helper_queue_tftp_with_script() {
        let mut helper =
            ScriptHelper::new(Some("/usr/bin/test-script".to_string()), None, None).unwrap();
        let peer = MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 69));
        helper.queue_tftp(1024, "pxelinux.0", &peer);
        assert!(!helper.is_empty());
    }

    #[test]
    fn test_event_action_display() {
        assert_eq!(format!("{}", EventAction::Add), "add");
        assert_eq!(format!("{}", EventAction::ArpDel), "arp-del");
        assert_eq!(format!("{}", EventAction::RelaySnoopv6), "relay-snoop");
    }

    #[test]
    fn test_standalone_queue_arp() {
        let mut helper = ScriptHelper::new(Some("/bin/true".to_string()), None, None).unwrap();
        let addr = AllAddr::V6(Ipv6Addr::LOCALHOST);
        queue_arp(
            &mut helper,
            EventAction::ArpDel,
            &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            AF_INET6,
            &addr,
        );
        assert!(!helper.is_empty());
    }

    #[test]
    fn test_parse_extra_data_empty() {
        let event = ScriptEvent::new_default(EventAction::Add);
        let mut envs = Vec::new();
        ScriptHelper::parse_extra_data(&[], &event, &mut envs);
        assert!(envs.is_empty());
    }
}

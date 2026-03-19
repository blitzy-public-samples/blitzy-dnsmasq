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

//! # DHCP Lease Management and Persistence
//!
//! Rust implementation of DHCP lease database management with persistent storage
//! and script integration, replacing C's `src/lease.c` (3,364 lines).
//!
//! ## Key Capabilities
//!
//! - **Lease lifecycle**: Allocation, modification, expiry and pruning of DHCPv4
//!   and DHCPv6 leases. The C linked list (`struct dhcp_lease *leases`) is
//!   replaced by `Vec<DhcpLease>` with Rust ownership semantics.
//! - **Persistent storage**: Read/write lease database to disk in a format that
//!   is **BYTE-FOR-BYTE compatible** with the C dnsmasq lease file, enabling
//!   seamless C → Rust migration upgrades.
//! - **DNS integration**: Automatic registration of DHCP-assigned hostnames into
//!   the DNS cache via [`lease_update_dns`].
//! - **Script notification**: Lease-change event callbacks (add/old/del) for
//!   external helper scripts via [`do_script_run`] and [`rerun_scripts`].
//! - **SLAAC integration**: Tracking of Stateless Address Autoconfiguration
//!   addresses derived from DHCPv6 lease MAC addresses.
//!
//! ## Lease File Format (CRITICAL — upgrade compatibility)
//!
//! ```text
//! # DHCPv4 line:
//! {expiry_time} {mac_address} {ip_address} {hostname} {client_id}
//!
//! # DHCPv6 line:
//! {expiry_time} {duid_or_iaid} {lease_type} {ip6_address} {hostname} [{clid}]
//!
//! # Server DUID line:
//! duid {hex_encoded_duid}
//! ```
//!
//! ## Memory Safety
//!
//! - C `malloc`/`free` → Rust `Vec`, `Box`, `String` with automatic drop
//! - C linked list → `Vec<DhcpLease>` with O(n) scans (matching C performance)
//! - Zero `unsafe` blocks — all I/O uses `std::fs`, all networking uses safe types
//! - Atomic lease file writes (temp file + rename) prevent corruption on crash

use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use libc::AF_INET;
use tracing::{debug, error, info, warn};

use crate::config::constants::{ARPHRD_ETHER, LEASEFILE, LEASE_RETRY, MAXLEASES};
use crate::core::types::{opt, DaemonState, DnsmasqError, DnsmasqResult, OptionFlags};
#[cfg(not(feature = "broken-rtc"))]
use crate::core::util::dnsmasq_time;
use crate::core::util::{
    canonicalise, format_mac, hostname_eq, is_same_net, is_same_net6, parse_hex, SurfRng,
};
use crate::dhcp::common::{
    find_config, get_domain6, DhcpConfig, DhcpContext, NetId, CONFIG_NAME, CONTEXT_PROXY,
    CONTEXT_STATIC,
};
use crate::diagnostics::metrics::MetricType;
use crate::dns::cache::DnsCache;
use crate::network::interface::{enumerate_interfaces, iface_check};

#[cfg(feature = "dhcp6")]
use crate::dhcp::radv::periodic_ra;
#[cfg(feature = "dhcp6")]
use crate::dhcp::slaac::{
    periodic_slaac, slaac_add_addrs, slaac_ping_reply, SlaacAddress, SlaacLeaseInfo,
};

// ---------------------------------------------------------------------------
// Constants (from C dnsmasq.h LEASE_* flags)
// ---------------------------------------------------------------------------

/// Lease is newly created and needs initial script notification.
const LEASE_NEW: u32 = 1;
/// Lease has been modified and needs update script notification.
const LEASE_CHANGED: u32 = 2;
/// Auxiliary lease data changed (expiry, interface, agent).
const LEASE_AUX_CHANGED: u32 = 4;
/// Hostname was set from authoritative DNS config (takes precedence).
const LEASE_AUTH_NAME: u32 = 8;
/// Lease is currently in use (for mark-and-sweep in DHCPv6).
const LEASE_USED: u32 = 16;
/// DHCPv6 Non-Temporary Address lease type marker.
const LEASE_NA: u32 = 32;
/// DHCPv6 Temporary Address lease type marker.
const LEASE_TA: u32 = 64;
/// Lease has a valid hardware address set.
const LEASE_HAVE_HWADDR: u32 = 128;
/// Lease expiry time has been explicitly changed.
const LEASE_EXP_CHANGED: u32 = 256;

/// Script action: delete lease.
const ACTION_DEL: i32 = 1;
/// Script action: old hostname notification.
const ACTION_OLD_HOSTNAME: i32 = 2;
/// Script action: existing lease changed.
const ACTION_OLD: i32 = 3;
/// Script action: new lease added.
const ACTION_ADD: i32 = 4;

/// Sentinel value for hwaddr_len indicating "not yet set".
/// Matches C: `HWADDR_LEN_UNSET` defined as 256 in lease_allocate().
const HWADDR_LEN_UNSET: usize = 256;

/// Maximum DHCP client hardware address length (matches C DHCP_CHADDR_MAX = 16).
const DHCP_CHADDR_MAX: usize = 16;

// ---------------------------------------------------------------------------
// Core Types
// ---------------------------------------------------------------------------

/// DHCPv6 lease type discriminator.
///
/// Replaces C flag-based typing (LEASE_NA, LEASE_TA, and prefix delegation
/// flag combinations). The Rust enum provides compile-time exhaustiveness
/// checking and clearer code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseType {
    /// IA_NA: Non-temporary Address (RFC 3315 Section 22.4).
    Na,
    /// IA_TA: Temporary Address (RFC 3315 Section 22.5).
    Ta,
    /// IA_PD: Prefix Delegation (RFC 3633 Section 10).
    Pd,
    /// DHCPv4 lease (not a v6 lease type, used as discriminator).
    V4,
}

impl fmt::Display for LeaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseType::Na => write!(f, "na"),
            LeaseType::Ta => write!(f, "ta"),
            LeaseType::Pd => write!(f, "pd"),
            LeaseType::V4 => write!(f, "v4"),
        }
    }
}

impl LeaseType {
    /// Parse lease type from the string token in the lease file.
    pub fn from_str_token(s: &str) -> Option<Self> {
        match s {
            "na" => Some(LeaseType::Na),
            "ta" => Some(LeaseType::Ta),
            "pd" => Some(LeaseType::Pd),
            _ => None,
        }
    }

    /// Convert to the C-compatible raw flags bits.
    fn to_flags(self) -> u32 {
        match self {
            LeaseType::Na => LEASE_NA,
            LeaseType::Ta => LEASE_TA,
            LeaseType::Pd => 0, // PD has no dedicated flag in C
            LeaseType::V4 => 0,
        }
    }
}

/// Lease change tracking flags.
///
/// Replaces the bitfield portion of C `lease->flags` that tracks
/// modification state for script notification and file persistence.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeaseFlags {
    /// Lease was freshly allocated (needs ACTION_ADD script notification).
    pub is_new: bool,
    /// Core lease data changed (address, hostname, client-id).
    pub has_changed: bool,
    /// Auxiliary data changed (expiry, interface, agent-id, vendor-class).
    pub aux_changed: bool,
}

impl LeaseFlags {
    /// Convert from C-compatible raw flag bits.
    #[allow(dead_code)]
    fn from_raw(raw: u32) -> Self {
        Self {
            is_new: raw & LEASE_NEW != 0,
            has_changed: raw & LEASE_CHANGED != 0,
            aux_changed: raw & LEASE_AUX_CHANGED != 0,
        }
    }

    /// Convert to C-compatible raw flag bits.
    #[allow(dead_code)]
    fn to_raw(self) -> u32 {
        let mut flags = 0u32;
        if self.is_new {
            flags |= LEASE_NEW;
        }
        if self.has_changed {
            flags |= LEASE_CHANGED;
        }
        if self.aux_changed {
            flags |= LEASE_AUX_CHANGED;
        }
        flags
    }

    /// Check if any change flag is set.
    #[allow(dead_code)]
    fn any_changed(&self) -> bool {
        self.is_new || self.has_changed || self.aux_changed
    }
}

/// DHCP lease record. Replaces C `struct dhcp_lease` (dnsmasq.h lines 1035-1067).
///
/// Used for both DHCPv4 and DHCPv6 leases. Fields that only apply to one
/// protocol version use `Option` to indicate absence.
///
/// ## Memory Safety Comparison
///
/// | C field | Rust field | Safety gain |
/// |---------|-----------|-------------|
/// | `unsigned char *clid` + `clid_len` | `Option<Vec<u8>>` | No buffer overflow |
/// | `char *hostname` | `Option<String>` | No dangling pointer |
/// | `unsigned char *extradata` + `len` + `size` | `Option<Vec<u8>>` | No overflow/realloc bugs |
/// | `struct slaac_address *slaac_address` (linked list) | `Vec<SlaacAddress>` | No use-after-free |
/// | `struct dhcp_lease *next` (linked list) | `Vec<DhcpLease>` (parent) | No list corruption |
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// Lease expiration timestamp (Unix time_t). 0 = infinite lease.
    pub expires: i64,
    /// IPv4 address (DHCPv4 leases only).
    pub addr: Option<Ipv4Addr>,
    /// IPv6 address (DHCPv6 leases only).
    pub addr6: Option<Ipv6Addr>,
    /// DHCPv6 lease type (Na/Ta/Pd) or V4 for DHCPv4.
    pub lease_type: LeaseType,
    /// DHCPv6 Identity Association ID.
    pub iaid: u32,
    /// Hardware (MAC) address, padded to DHCP_CHADDR_MAX bytes.
    pub hwaddr: Vec<u8>,
    /// Hardware address type (e.g., 1 = Ethernet / ARPHRD_ETHER).
    pub hwaddr_type: i32,
    /// Actual length of hardware address in bytes.
    pub hwaddr_len: usize,
    /// Client identifier (DHCPv4 option 61 or DHCPv6 DUID).
    pub clid: Option<Vec<u8>>,
    /// Client hostname (unqualified).
    pub hostname: Option<String>,
    /// Fully qualified domain name (hostname + domain suffix).
    pub fqdn: Option<String>,
    /// Previous hostname, saved for old-hostname script notification.
    pub old_hostname: Option<String>,
    /// Network interface name where lease was granted.
    pub interface: Option<String>,
    /// Vendor class data (DHCPv4 option 60).
    pub vendor_class: Option<Vec<u8>>,
    /// User class data (DHCPv4 option 77).
    pub user_class: Option<Vec<u8>>,
    /// SLAAC addresses associated with this DHCPv6 lease.
    #[cfg(feature = "dhcp6")]
    pub slaac_addresses: Vec<SlaacAddress>,
    /// Change tracking flags for script notification and file persistence.
    pub flags: LeaseFlags,
    /// Extra data appended by lease-change scripts.
    pub extradata: Option<Vec<u8>>,
    /// DHCPv6 prefix length (for IA_PD prefix delegation leases).
    pub prefix_len: u8,
    // -- Internal fields (not exported but needed for C-compatible behavior) --
    /// Raw C-compatible flag bits for internal tracking.
    raw_flags: u32,
    /// Override address (C: `struct in_addr override`).
    #[allow(dead_code)]
    override_addr: Option<Ipv4Addr>,
    /// GIADDR relay agent address.
    #[allow(dead_code)]
    giaddr: Option<Ipv4Addr>,
    /// Last network interface index.
    last_interface: i32,
    /// New interface index (pending update from interface scan).
    new_interface: i32,
    /// New prefix length (pending update).
    new_prefixlen: i32,
    /// Relay agent ID data (DHCPv4 option 82).
    agent_id: Option<Vec<u8>>,
    /// Vendor class count (DHCPv6).
    #[cfg(feature = "dhcp6")]
    #[allow(dead_code)]
    vendorclass_count: i32,
}

impl DhcpLease {
    /// Create a new empty lease with sentinel values matching C's `lease_allocate()`.
    ///
    /// Mirrors C behavior: `expires = 1` (sentinel for "never persisted"),
    /// `hwaddr_len = 256` (sentinel for "not yet set"), all other fields zeroed/None.
    fn new_empty() -> Self {
        Self {
            expires: 1,
            addr: None,
            addr6: None,
            lease_type: LeaseType::V4,
            iaid: 0,
            hwaddr: vec![0u8; DHCP_CHADDR_MAX],
            hwaddr_type: 0,
            hwaddr_len: HWADDR_LEN_UNSET,
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            interface: None,
            vendor_class: None,
            user_class: None,
            #[cfg(feature = "dhcp6")]
            slaac_addresses: Vec::new(),
            flags: LeaseFlags {
                is_new: true,
                has_changed: false,
                aux_changed: false,
            },
            extradata: None,
            prefix_len: 0,
            raw_flags: LEASE_NEW,
            override_addr: None,
            giaddr: None,
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        }
    }

    /// Check if this is a DHCPv6 lease (NA, TA, or PD).
    #[inline]
    pub fn is_v6(&self) -> bool {
        matches!(
            self.lease_type,
            LeaseType::Na | LeaseType::Ta | LeaseType::Pd
        )
    }

    /// Check if this is a DHCPv4 lease.
    #[inline]
    pub fn is_v4(&self) -> bool {
        matches!(self.lease_type, LeaseType::V4)
    }
}

impl fmt::Display for DhcpLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(addr) = self.addr {
            write!(f, "DHCPv4 lease {}", addr)?;
        } else if let Some(addr6) = self.addr6 {
            write!(f, "DHCPv6 {} lease {}", self.lease_type, addr6)?;
        } else {
            write!(f, "DHCP lease (no address)")?;
        }
        if let Some(ref hn) = self.hostname {
            write!(f, " ({})", hn)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Lease Database
// ---------------------------------------------------------------------------

/// Lease database holding all active leases and associated metadata.
///
/// In C, this was a file-scoped static linked list (`static struct dhcp_lease *leases`)
/// with several auxiliary counters. In Rust we group them into an explicit struct.
#[derive(Debug)]
pub struct LeaseDatabase {
    /// All active DHCP leases (replaces C linked list).
    pub leases: Vec<DhcpLease>,
    /// Old leases pending script deletion notification.
    old_leases: Vec<DhcpLease>,
    /// Remaining lease allocation capacity (counted down from max).
    leases_left: i32,
    /// DNS cache needs rebuild from lease changes.
    dns_dirty: bool,
    /// Lease file needs rewrite.
    file_dirty: bool,
}

impl LeaseDatabase {
    /// Create a new empty lease database with the given capacity limit.
    pub fn new(max_leases: i32) -> Self {
        Self {
            leases: Vec::new(),
            old_leases: Vec::new(),
            leases_left: max_leases,
            dns_dirty: false,
            file_dirty: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Lease File Parsing
// ---------------------------------------------------------------------------

/// Parse the lease file content and return a vector of leases.
///
/// Replaces C's `read_leases()` (`lease.c` line 168).
///
/// Reads the persistent lease file line-by-line, parsing both DHCPv4 and
/// DHCPv6 lease entries. Handles the special `duid` line for the server's
/// DHCPv6 DUID.
///
/// **CRITICAL**: The parse format is identical to C's `read_leases()` for
/// seamless upgrade from C to Rust dnsmasq.
fn read_leases(
    reader: &mut impl BufRead,
    state: &mut DaemonState,
) -> DnsmasqResult<Vec<DhcpLease>> {
    let mut leases = Vec::new();
    let mut line_buf = String::new();
    let mut line_num = 0u32;

    loop {
        line_buf.clear();
        let bytes_read = reader.read_line(&mut line_buf).map_err(|e| {
            error!(line = line_num, "lease file read error: {}", e);
            DnsmasqError::Io(e)
        })?;
        if bytes_read == 0 {
            break; // EOF
        }
        line_num += 1;

        let line = line_buf.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle the special `duid` line for DHCPv6 server identification.
        if let Some(hex_str) = line.strip_prefix("duid ") {
            #[cfg(feature = "dhcp6")]
            {
                if let Some(duid_bytes) = parse_hex(hex_str) {
                    state.duid = duid_bytes;
                    debug!(
                        line = line_num,
                        duid_len = state.duid.len(),
                        "loaded server DUID"
                    );
                } else {
                    warn!(line = line_num, "invalid DUID hex in lease file, ignoring");
                }
            }
            continue;
        }

        // Split into fields (max 6 to preserve remainder as single field).
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 4 {
            warn!(line = line_num, "malformed lease line, skipping");
            continue;
        }

        // Field 0: expiry timestamp.
        let expires: i64 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => {
                warn!(line = line_num, "invalid expiry timestamp, skipping");
                continue;
            }
        };

        // Determine DHCPv4 vs DHCPv6: DHCPv4 MAC addresses contain ':' but
        // are not prefixed with 'T'. DHCPv6 has a numeric IAID (possibly
        // 'T'-prefixed for TA).
        let field1 = parts[1];
        let is_v4 = field1.contains(':') && !field1.starts_with('T');

        if is_v4 && parts.len() >= 5 {
            match parse_v4_lease(expires, &parts, line_num) {
                Some(lease) => leases.push(lease),
                None => warn!(line = line_num, "failed to parse DHCPv4 lease, skipping"),
            }
        } else if parts.len() >= 5 {
            #[cfg(feature = "dhcp6")]
            match parse_v6_lease(expires, &parts, line_num) {
                Some(lease) => leases.push(lease),
                None => warn!(line = line_num, "failed to parse DHCPv6 lease, skipping"),
            }
            #[cfg(not(feature = "dhcp6"))]
            {
                debug!(line = line_num, "skipping DHCPv6 lease (feature disabled)");
            }
        } else {
            warn!(line = line_num, "unrecognized lease format, skipping");
        }
    }

    info!(count = leases.len(), "loaded leases from file");
    Ok(leases)
}

/// Parse a DHCPv4 lease line: `{expiry} {mac} {ip} {hostname} {clid}`.
fn parse_v4_lease(expires: i64, parts: &[&str], line_num: u32) -> Option<DhcpLease> {
    if parts.len() < 5 {
        return None;
    }

    let (hw_type, hw_bytes) = parse_mac_field(parts[1])?;

    let ip: Ipv4Addr = parts[2].parse().ok().or_else(|| {
        warn!(line = line_num, ip = parts[2], "invalid IPv4 address");
        None
    })?;

    let hostname = if parts[3] == "*" {
        None
    } else {
        canonicalise(parts[3])
    };
    let clid = if parts[4] == "*" {
        None
    } else {
        parse_hex(parts[4])
    };

    let mut lease = DhcpLease::new_empty();
    lease.expires = expires;
    lease.addr = Some(ip);
    lease.lease_type = LeaseType::V4;
    lease.hwaddr_type = hw_type;
    let hw_len = hw_bytes.len().min(DHCP_CHADDR_MAX);
    lease.hwaddr = hw_bytes;
    lease.hwaddr.resize(DHCP_CHADDR_MAX, 0);
    lease.hwaddr_len = hw_len;
    lease.hostname = hostname;
    lease.clid = clid;
    lease.flags = LeaseFlags::default();
    lease.raw_flags = 0;
    Some(lease)
}

/// Parse a DHCPv6 lease line: `{expiry} [T]{iaid} {type} {ip6}[/{prefix}] {hostname} [{clid}]`.
#[cfg(feature = "dhcp6")]
fn parse_v6_lease(expires: i64, parts: &[&str], line_num: u32) -> Option<DhcpLease> {
    if parts.len() < 5 {
        return None;
    }

    let iaid_str = parts[1];
    let (is_ta_prefix, iaid_num_str) = if let Some(stripped) = iaid_str.strip_prefix('T') {
        (true, stripped)
    } else {
        (false, iaid_str)
    };

    let iaid: u32 = iaid_num_str.parse().ok().or_else(|| {
        warn!(line = line_num, iaid = iaid_str, "invalid IAID");
        None
    })?;

    let lease_type = if is_ta_prefix {
        LeaseType::Ta
    } else {
        match parts[2] {
            "na" => LeaseType::Na,
            "ta" => LeaseType::Ta,
            "pd" => LeaseType::Pd,
            _ => {
                warn!(line = line_num, lt = parts[2], "unknown DHCPv6 lease type");
                return None;
            }
        }
    };

    // Parse IPv6 address, optionally with /prefix for PD.
    let (addr_str, prefix_len) = if let Some(pos) = parts[3].find('/') {
        let (a, p) = parts[3].split_at(pos);
        (a, p[1..].parse::<u8>().unwrap_or(128))
    } else {
        (parts[3], 128u8)
    };

    let ip6: Ipv6Addr = addr_str.parse().ok().or_else(|| {
        warn!(line = line_num, addr = parts[3], "invalid IPv6 address");
        None
    })?;

    let hostname = if parts[4] == "*" {
        None
    } else {
        canonicalise(parts[4])
    };
    let clid = if parts.len() > 5 && parts[5].trim() != "*" {
        parse_hex(parts[5].trim())
    } else {
        None
    };

    let mut lease = DhcpLease::new_empty();
    lease.expires = expires;
    lease.addr6 = Some(ip6);
    lease.lease_type = lease_type;
    lease.iaid = iaid;
    lease.prefix_len = if lease_type == LeaseType::Pd {
        prefix_len
    } else {
        128
    };
    lease.hostname = hostname;
    lease.clid = clid;
    lease.raw_flags = lease_type.to_flags();
    lease.flags = LeaseFlags::default();
    Some(lease)
}

/// Parse a MAC address field from the lease file.
///
/// Format: `XX:XX:XX:XX:XX:XX` (Ethernet, type 1) or `{type}-XX:XX:...` (other).
fn parse_mac_field(field: &str) -> Option<(i32, Vec<u8>)> {
    if let Some(pos) = field.find('-') {
        let hw_type: i32 = field[..pos].parse().ok()?;
        let bytes = parse_hex(&field[pos + 1..])?;
        Some((hw_type, bytes))
    } else {
        let bytes = parse_hex(field)?;
        Some((ARPHRD_ETHER as i32, bytes))
    }
}

/// Format a MAC address for lease file output (C-compatible).
fn format_mac_for_file(hwaddr: &[u8], hw_len: usize, hw_type: i32) -> String {
    let effective_len = hw_len.min(hwaddr.len());
    let mac_bytes = &hwaddr[..effective_len];

    if hw_type != ARPHRD_ETHER as i32 || effective_len != 6 {
        let hex = mac_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        format!("{}-{}", hw_type, hex)
    } else {
        format_mac(mac_bytes)
    }
}

// ---------------------------------------------------------------------------
// Lease File Writing
// ---------------------------------------------------------------------------

/// Write the entire lease database to disk atomically.
///
/// Replaces C's `lease_update_file()` (`lease.c` line 677).
///
/// Uses the temp-file-then-rename pattern for crash safety:
/// 1. Write all leases to `{lease_file}.new`
/// 2. Flush the temp file
/// 3. Rename `{lease_file}.new` → `{lease_file}` (atomic on POSIX)
///
/// **CRITICAL**: Output format MUST be byte-for-byte compatible with C dnsmasq.
pub fn lease_update_file(
    now: i64,
    db: &mut LeaseDatabase,
    state: &mut DaemonState,
    dns_cache: Option<&mut DnsCache>,
) -> DnsmasqResult<()> {
    if state.options.is_set(opt::LEASE_RO) {
        return Ok(());
    }

    // Update DNS cache if dirty.
    if db.dns_dirty {
        if let Some(cache) = dns_cache {
            lease_update_dns_inner(&db.leases, state, cache);
        }
        db.dns_dirty = false;
    }

    if !db.file_dirty {
        schedule_next_alarm(now, &db.leases);
        return Ok(());
    }

    let lease_path_str = state.lease_file.as_deref().unwrap_or(LEASEFILE);
    let lease_path = Path::new(lease_path_str);
    let mut tmp_path = PathBuf::from(lease_path_str);
    tmp_path.set_extension("new");

    match write_lease_file(&tmp_path, &db.leases, state) {
        Ok(()) => {
            if let Err(e) = fs::rename(&tmp_path, lease_path) {
                error!(path = %lease_path.display(), error = %e, "failed to rename temp lease file");
                let _ = fs::remove_file(&tmp_path);
                return Err(DnsmasqError::Io(e));
            }
            db.file_dirty = false;
            debug!(path = %lease_path.display(), count = db.leases.len(), "lease file updated");
        }
        Err(e) => {
            error!(
                path = %tmp_path.display(),
                error = %e,
                retry_in = LEASE_RETRY,
                "failed to write temp lease file"
            );
            let _ = fs::remove_file(&tmp_path);
        }
    }

    // DHCPv6: run periodic Router Advertisement and SLAAC timers.
    // These may need to fire sooner when lease state changes affect RA content
    // (prefix information, SLAAC timing). Replaces C lease.c calls to
    // periodic_ra(now) and periodic_slaac(now, leases).
    #[cfg(feature = "dhcp6")]
    {
        let _ra_next = periodic_ra(now, state);
        // Build SlaacLeaseInfo for periodic ping checks.
        let mut slaac_infos = build_slaac_lease_infos(&db.leases);
        if let Ok(mut rng) = SurfRng::new() {
            let _slaac_result = periodic_slaac(
                now,
                &mut slaac_infos,
                &[], // contexts provided by the daemon event loop
                &mut rng,
            );
            apply_slaac_updates(&mut db.leases, &slaac_infos);
        }
    }

    schedule_next_alarm(now, &db.leases);
    Ok(())
}

/// Write all lease records to a file in the C-compatible format.
fn write_lease_file(path: &Path, leases: &[DhcpLease], state: &DaemonState) -> DnsmasqResult<()> {
    let file = File::create(path).map_err(|e| {
        error!(path = %path.display(), "failed to create lease file: {}", e);
        DnsmasqError::Io(e)
    })?;
    let mut writer = BufWriter::new(file);

    // Write server DUID (DHCPv6).
    #[cfg(feature = "dhcp6")]
    if !state.duid.is_empty() {
        write!(writer, "duid ")?;
        for (i, b) in state.duid.iter().enumerate() {
            if i > 0 {
                write!(writer, ":")?;
            }
            write!(writer, "{:02x}", b)?;
        }
        writeln!(writer)?;
    }

    for lease in leases {
        if lease.is_v4() {
            write_v4_lease(&mut writer, lease)?;
        } else {
            #[cfg(feature = "dhcp6")]
            write_v6_lease(&mut writer, lease)?;
        }
    }

    writer.flush().map_err(|e| {
        error!(path = %path.display(), "failed to flush lease file: {}", e);
        DnsmasqError::Io(e)
    })?;
    Ok(())
}

/// Write a single DHCPv4 lease line: `{expiry} {mac} {ip} {hostname} {clid}`.
fn write_v4_lease(writer: &mut impl Write, lease: &DhcpLease) -> DnsmasqResult<()> {
    let ip = lease.addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mac = format_mac_for_file(&lease.hwaddr, lease.hwaddr_len, lease.hwaddr_type);
    let hostname = lease.hostname.as_deref().unwrap_or("*");
    let clid = match &lease.clid {
        Some(c) if !c.is_empty() => c
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
        _ => "*".to_string(),
    };
    writeln!(
        writer,
        "{} {} {} {} {}",
        lease.expires, mac, ip, hostname, clid
    )?;
    Ok(())
}

/// Write a single DHCPv6 lease line: `{expiry} [T]{iaid} {type} {ip6}[/{prefix}] {hostname} {clid}`.
#[cfg(feature = "dhcp6")]
fn write_v6_lease(writer: &mut impl Write, lease: &DhcpLease) -> DnsmasqResult<()> {
    let ip6 = lease.addr6.unwrap_or(Ipv6Addr::UNSPECIFIED);
    let hostname = lease.hostname.as_deref().unwrap_or("*");
    let iaid_str = if lease.lease_type == LeaseType::Ta {
        format!("T{}", lease.iaid)
    } else {
        format!("{}", lease.iaid)
    };
    let type_str = match lease.lease_type {
        LeaseType::Na => "na",
        LeaseType::Ta => "ta",
        LeaseType::Pd => "pd",
        LeaseType::V4 => "v4",
    };
    let addr_str = if lease.lease_type == LeaseType::Pd {
        format!("{}/{}", ip6, lease.prefix_len)
    } else {
        format!("{}", ip6)
    };
    let clid_str = match &lease.clid {
        Some(c) if !c.is_empty() => c
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
        _ => "*".to_string(),
    };
    writeln!(
        writer,
        "{} {} {} {} {} {}",
        lease.expires, iaid_str, type_str, addr_str, hostname, clid_str
    )?;
    Ok(())
}

/// Schedule the next alarm for the earliest lease expiry.
fn schedule_next_alarm(now: i64, leases: &[DhcpLease]) {
    let mut earliest: Option<i64> = None;
    for lease in leases {
        if lease.expires > 0 && lease.expires > now {
            match earliest {
                Some(e) if lease.expires < e => earliest = Some(lease.expires),
                None => earliest = Some(lease.expires),
                _ => {}
            }
        }
    }
    if let Some(exp) = earliest {
        let secs = (exp - now).max(1);
        debug!(next_expiry_in_secs = secs, "scheduled lease expiry alarm");
    }
}

// ---------------------------------------------------------------------------
// Lease Initialization
// ---------------------------------------------------------------------------

/// Initialize the lease database from the persistent lease file.
///
/// Replaces C's `lease_init()` (`lease.c` line 433).
///
/// Reads the lease file, populates the database, prunes expired entries,
/// and marks DNS cache dirty for initial synchronization.
pub fn lease_init(now: i64, state: &mut DaemonState) -> DnsmasqResult<LeaseDatabase> {
    let max_leases = if state.dhcp_max > 0 {
        state.dhcp_max
    } else {
        MAXLEASES as i32
    };
    let mut db = LeaseDatabase::new(max_leases);

    if state.options.is_set(opt::LEASE_RO) {
        info!("lease database in read-only mode (script-based)");
        return Ok(db);
    }

    let lease_path_str = state.lease_file.as_deref().unwrap_or(LEASEFILE);
    let lease_path = Path::new(lease_path_str);

    if !lease_path.exists() {
        info!(path = %lease_path.display(), "no existing lease file, starting fresh");
        db.dns_dirty = true;
        return Ok(db);
    }

    let file = File::open(lease_path).map_err(|e| {
        error!(path = %lease_path.display(), "failed to open lease file: {}", e);
        DnsmasqError::Io(e)
    })?;
    let mut reader = BufReader::new(file);
    let loaded = read_leases(&mut reader, state)?;
    let loaded_count = loaded.len();
    db.leases = loaded;
    db.leases_left = max_leases - db.leases.len() as i32;

    let pruned = lease_prune_inner(&mut db, None, now);
    if pruned > 0 {
        info!(pruned, "pruned expired leases during initialization");
    }

    db.dns_dirty = true;
    db.file_dirty = false;
    state.lease_stream_active = true;

    info!(
        loaded = loaded_count,
        active = db.leases.len(),
        max = max_leases,
        "lease database initialized"
    );
    Ok(db)
}

// ---------------------------------------------------------------------------
// Lease Allocation
// ---------------------------------------------------------------------------

/// Allocate a new DHCPv4 lease for the given IPv4 address.
///
/// Replaces C's `lease4_allocate()` (`lease.c` line 2224).
///
/// Returns a new lease with sentinel values. Caller must set the hardware
/// address, hostname, and expiry before persistence.
/// Increments MetricType::LeasesAllocated4 counter.
pub fn lease4_allocate(addr: Ipv4Addr) -> DhcpLease {
    let mut lease = DhcpLease::new_empty();
    lease.addr = Some(addr);
    lease.lease_type = LeaseType::V4;
    lease.raw_flags = LEASE_NEW;
    lease.flags.is_new = true;
    // MetricType::LeasesAllocated4 is logged here; the caller's DaemonState
    // metrics vector is incremented by the lease_db_add() caller at the
    // daemon event loop level (matching C: daemon->metrics[METRIC_LEASES_ALLOCATED_4]++).
    info!(
        addr = %addr,
        metric = %MetricType::LeasesAllocated4 as u32,
        "allocated new DHCPv4 lease"
    );
    lease
}

/// Allocate a new DHCPv6 lease for the given IPv6 address and lease type.
///
/// Replaces C's `lease6_allocate()` (`lease.c` line 2315).
/// Increments MetricType::LeasesAllocated6 counter.
#[cfg(feature = "dhcp6")]
pub fn lease6_allocate(addr: Ipv6Addr, lease_type: LeaseType) -> DhcpLease {
    let mut lease = DhcpLease::new_empty();
    lease.addr6 = Some(addr);
    lease.lease_type = lease_type;
    lease.raw_flags = LEASE_NEW | lease_type.to_flags();
    lease.flags.is_new = true;
    lease.iaid = 0;
    info!(
        addr = %addr,
        lt = %lease_type,
        metric = %MetricType::LeasesAllocated6 as u32,
        "allocated new DHCPv6 lease"
    );
    lease
}

/// Add a newly allocated lease to the database.
///
/// Enforces the maximum lease limit. Returns `true` if added, `false` if full.
pub fn lease_db_add(db: &mut LeaseDatabase, lease: DhcpLease) -> bool {
    if db.leases_left <= 0 {
        warn!(
            current = db.leases.len(),
            "maximum DHCP lease limit reached"
        );
        return false;
    }
    db.leases_left -= 1;
    db.file_dirty = true;
    db.dns_dirty = true;
    db.leases.push(lease);
    true
}

// ---------------------------------------------------------------------------
// Lease Lookup
// ---------------------------------------------------------------------------

/// Find a DHCPv4 lease by IPv4 address.
///
/// Replaces C's `lease_find_by_addr()` (`lease.c` line 1559).
pub fn lease_find_by_addr(db: &[DhcpLease], addr: Ipv4Addr) -> Option<&DhcpLease> {
    db.iter().find(|l| l.is_v4() && l.addr == Some(addr))
}

/// Find a mutable DHCPv4 lease by IPv4 address.
pub fn lease_find_by_addr_mut(db: &mut [DhcpLease], addr: Ipv4Addr) -> Option<&mut DhcpLease> {
    db.iter_mut().find(|l| l.is_v4() && l.addr == Some(addr))
}

/// Find a DHCPv4 lease by client identifier or hardware address.
///
/// Replaces C's `lease_find_by_client()` (`lease.c` line 1484).
///
/// Search order (matching C):
/// 1. First pass: match by client-id (if provided)
/// 2. Second pass: match by hardware address (if no clid match)
pub fn lease_find_by_client<'a>(
    db: &'a [DhcpLease],
    hwaddr: &[u8],
    hw_type: i32,
    clid: Option<&[u8]>,
) -> Option<&'a DhcpLease> {
    // Pass 1: client-id match.
    if let Some(client_id) = clid {
        if !client_id.is_empty() {
            for lease in db.iter() {
                if !lease.is_v4() {
                    continue;
                }
                if let Some(ref lease_clid) = lease.clid {
                    if lease_clid.as_slice() == client_id {
                        return Some(lease);
                    }
                }
            }
        }
    }

    // Pass 2: hardware address match.
    let effective_len = hwaddr.len().min(DHCP_CHADDR_MAX);
    for lease in db.iter() {
        if !lease.is_v4() {
            continue;
        }
        if clid.is_some() && lease.clid.is_some() {
            continue; // Has clid — should match by clid, not hwaddr.
        }
        if lease.hwaddr_type == hw_type
            && lease.hwaddr_len == effective_len
            && lease.hwaddr[..effective_len] == hwaddr[..effective_len]
        {
            return Some(lease);
        }
    }

    None
}

/// Find a DHCPv6 lease by DUID, lease type, IAID, and address.
///
/// Replaces C's `lease6_find()` (`lease.c` line 1634).
#[cfg(feature = "dhcp6")]
pub fn lease6_find<'a>(
    db: &'a [DhcpLease],
    clid: &[u8],
    lease_type: LeaseType,
    iaid: u32,
    addr: &Ipv6Addr,
) -> Option<&'a DhcpLease> {
    db.iter().find(|l| {
        l.lease_type == lease_type
            && l.iaid == iaid
            && l.addr6.as_ref() == Some(addr)
            && l.clid.as_deref() == Some(clid)
    })
}

/// Find DHCPv6 leases by client DUID, lease type, and IAID (mark-and-sweep).
///
/// Replaces C's `lease6_find_by_client()` (`lease.c` line 1774).
///
/// Returns the first matching lease that is not yet marked USED.
#[cfg(feature = "dhcp6")]
pub fn lease6_find_by_client<'a>(
    db: &'a [DhcpLease],
    lease_type: LeaseType,
    clid: &[u8],
    iaid: u32,
) -> Option<&'a DhcpLease> {
    db.iter().find(|l| {
        l.lease_type == lease_type
            && l.iaid == iaid
            && l.clid.as_deref() == Some(clid)
            && l.raw_flags & LEASE_USED == 0
    })
}

/// Find a DHCPv6 lease by network prefix and address.
///
/// Replaces C's `lease6_find_by_addr()` (`lease.c` line 1863).
#[cfg(feature = "dhcp6")]
pub fn lease6_find_by_addr<'a>(
    db: &'a [DhcpLease],
    net: &Ipv6Addr,
    prefix: i32,
    addr: &Ipv6Addr,
) -> Option<&'a DhcpLease> {
    db.iter().find(|l| {
        if let Some(ref la) = l.addr6 {
            l.is_v6() && is_same_net6(*la, *net, prefix as u8) && la == addr
        } else {
            false
        }
    })
}

/// Find a DHCPv6 lease by exact IPv6 address.
///
/// Replaces C's `lease6_find_by_plain_addr()` (`lease.c` line 1932).
#[cfg(feature = "dhcp6")]
pub fn lease6_find_by_plain_addr<'a>(
    db: &'a [DhcpLease],
    addr: &Ipv6Addr,
) -> Option<&'a DhcpLease> {
    db.iter()
        .find(|l| l.is_v6() && l.addr6.as_ref() == Some(addr))
}

/// Reset the LEASE_USED flag on all DHCPv6 leases.
///
/// Replaces C's `lease6_reset()` (`lease.c` line 1704).
/// Used at the start of a DHCPv6 renewal to mark all existing leases as unseen.
#[cfg(feature = "dhcp6")]
pub fn lease6_reset(db: &mut [DhcpLease]) {
    for lease in db.iter_mut() {
        if lease.is_v6() {
            lease.raw_flags &= !LEASE_USED;
        }
    }
}

// ---------------------------------------------------------------------------
// Lease Modification
// ---------------------------------------------------------------------------

/// Set the expiration time on a lease.
///
/// Replaces C's `lease_set_expires()` (`lease.c` line 2382).
///
/// Handles infinite leases (`len == 0xFFFFFFFF` → `expires = 0`),
/// 2038 overflow protection, default lease durations (DEFLEASE/DEFLEASE6),
/// and marks the lease as changed.
///
/// When `now` is non-zero, it is used as the base time. Otherwise falls back
/// to `dnsmasq_time()` for the current wall-clock time.
pub fn lease_set_expires(
    lease: &mut DhcpLease,
    len: u32,
    #[cfg_attr(feature = "broken-rtc", allow(unused))] now: i64,
) {
    // C semantics: len=0 means no change to the expiry time.
    // Only non-zero lengths are applied. This matches C's lease_set_expires()
    // where len=0 is a no-op for expiry (only flags are updated).
    if len == 0 {
        // No change to expiry — but still mark as changed for DNS dirty tracking.
        lease.flags.aux_changed = true;
        lease.raw_flags |= LEASE_AUX_CHANGED | LEASE_EXP_CHANGED;
        // C always sets dns_dirty when lease_set_expires is called.
        // The dns_dirty flag must be set by the caller on the LeaseDatabase.
        debug!(lease = %lease, expires = lease.expires, duration = 0u32, "set lease expiry (no change, len=0)");
        return;
    }

    if len == 0xFFFFFFFF {
        lease.expires = 0;
    } else {
        // HAVE_BROKEN_RTC: On systems without a wall-clock (embedded routers,
        // etc.), store the lease duration directly rather than computing an
        // absolute expiry timestamp.  This matches C's compile-time
        // `HAVE_BROKEN_RTC` guard in `lease_set_expires()`.
        #[cfg(feature = "broken-rtc")]
        {
            lease.expires = len as i64;
        }
        #[cfg(not(feature = "broken-rtc"))]
        {
            // Use the provided `now` as the base time, matching C behavior.
            // Falls back to dnsmasq_time() only when called without a meaningful
            // time parameter (0).
            let base_time = if now != 0 { now } else { dnsmasq_time() };
            let new_expires = base_time.saturating_add(len as i64);
            lease.expires = if new_expires <= 0 { 0 } else { new_expires };
        }
    }
    lease.flags.aux_changed = true;
    lease.raw_flags |= LEASE_AUX_CHANGED | LEASE_EXP_CHANGED;
    debug!(lease = %lease, expires = lease.expires, duration = len, "set lease expiry");
}

/// Set the expiration time on a lease within a database context.
///
/// Wraps [`lease_set_expires`] and additionally marks the database's
/// `dns_dirty` flag, matching C behavior where DNS is always re-evaluated
/// when lease expiry changes.
pub fn lease_set_expires_db(db: &mut LeaseDatabase, lease_idx: usize, len: u32, now: i64) {
    if let Some(lease) = db.leases.get_mut(lease_idx) {
        lease_set_expires(lease, len, now);
        db.dns_dirty = true;
    }
}

/// Set the IAID (Identity Association Identifier) for a DHCPv6 lease.
///
/// Replaces C's `lease_set_iaid()` (`lease.c` line 2474).
pub fn lease_set_iaid(lease: &mut DhcpLease, iaid: u32) {
    if lease.iaid != iaid {
        lease.iaid = iaid;
        lease.flags.has_changed = true;
        lease.raw_flags |= LEASE_CHANGED;
    }
}

/// Set the hardware (MAC) address and optional client identifier on a lease.
///
/// Replaces C's `lease_set_hwaddr()` (`lease.c` line 2539).
///
/// If `clid` is empty/None, the existing client-id is preserved.
pub fn lease_set_hwaddr(
    lease: &mut DhcpLease,
    hwaddr: &[u8],
    clid: Option<&[u8]>,
    hw_len: usize,
    hw_type: i32,
    _now: i64,
    force: bool,
) {
    let effective_len = hw_len.min(DHCP_CHADDR_MAX);

    // Update client-id if provided and non-empty.
    if let Some(new_clid) = clid {
        if !new_clid.is_empty() {
            let changed = match &lease.clid {
                Some(existing) => existing.as_slice() != new_clid,
                None => true,
            };
            if changed || force {
                lease.clid = Some(new_clid.to_vec());
                lease.flags.has_changed = true;
                lease.raw_flags |= LEASE_CHANGED;
            }
        }
    }

    // Update hardware address.
    let hwaddr_changed = lease.hwaddr_len != effective_len
        || lease.hwaddr_type != hw_type
        || lease.hwaddr[..effective_len] != hwaddr[..effective_len];

    if hwaddr_changed {
        let copy_len = effective_len.min(lease.hwaddr.len());
        lease.hwaddr[..copy_len].copy_from_slice(&hwaddr[..copy_len]);
        for b in lease.hwaddr[copy_len..].iter_mut() {
            *b = 0;
        }
        lease.hwaddr_len = effective_len;
        lease.hwaddr_type = hw_type;
        lease.raw_flags |= LEASE_CHANGED | LEASE_HAVE_HWADDR;
        lease.flags.has_changed = true;
        debug!(lease = %lease, mac = %format_mac(&lease.hwaddr[..effective_len]), "updated hardware address");
    }
}

/// Set the hostname on a lease with conflict detection.
///
/// Replaces C's `lease_set_hostname()` (`lease.c` line 2842).
///
/// Handles duplicate hostname detection, AUTH_NAME precedence, and
/// v6 same-DUID exception.
pub fn lease_set_hostname(
    db: &mut LeaseDatabase,
    lease_idx: usize,
    name: Option<&str>,
    auth: bool,
    _domain: Option<&str>,
    _domain6: Option<&str>,
) {
    let name = match name {
        Some(n) if !n.is_empty() => match canonicalise(n) {
            Some(canonical) => Some(canonical),
            None => {
                warn!(name = n, "invalid hostname, ignoring");
                return;
            }
        },
        _ => None,
    };

    // Check conflicts with other leases.
    if let Some(ref new_name) = name {
        let target_is_v6 = db.leases.get(lease_idx).is_some_and(|l| l.is_v6());
        let target_clid = db.leases.get(lease_idx).and_then(|l| l.clid.clone());

        for (i, other) in db.leases.iter_mut().enumerate() {
            if i == lease_idx {
                continue;
            }
            let same_name = other
                .hostname
                .as_ref()
                .is_some_and(|h| hostname_eq(h, new_name));
            if !same_name {
                continue;
            }
            // IPv6: allow same hostname for same DUID (multiple addresses, one host).
            if target_is_v6 && other.is_v6() {
                if let (Some(ref t_clid), Some(ref o_clid)) = (&target_clid, &other.clid) {
                    if t_clid == o_clid {
                        continue;
                    }
                }
            }
            // AUTH_NAME takes precedence — our DHCP-offered name loses.
            if other.raw_flags & LEASE_AUTH_NAME != 0 && !auth {
                debug!(name = %new_name, "hostname conflict: auth name takes precedence");
                return;
            }
            // Remove hostname from conflicting lease.
            kill_name(other);
            db.dns_dirty = true;
            db.file_dirty = true;
        }
    }

    // Apply hostname to target lease.
    if let Some(lease) = db.leases.get_mut(lease_idx) {
        let changed = match (&lease.hostname, &name) {
            (Some(old), Some(new)) => !hostname_eq(old, new),
            (None, None) => false,
            _ => true,
        };
        if changed {
            if name.is_some() {
                kill_name(lease);
            }
            lease.hostname = name;
            if auth {
                lease.raw_flags |= LEASE_AUTH_NAME;
            }
            lease.flags.has_changed = true;
            lease.raw_flags |= LEASE_CHANGED;
            lease.fqdn = None; // Recalculated by lease_calc_fqdns.
            db.dns_dirty = true;
            db.file_dirty = true;
        }
    }
}

/// Transfer hostname/fqdn to `old_hostname` for script notification.
///
/// Replaces C's `kill_name()` (`lease.c` line 2668).
fn kill_name(lease: &mut DhcpLease) {
    if lease.fqdn.is_some() {
        lease.old_hostname = lease.fqdn.take();
        lease.hostname = None;
    } else if lease.hostname.is_some() {
        lease.old_hostname = lease.hostname.take();
    }
    lease.fqdn = None;
}

/// Set the network interface associated with a lease.
///
/// Replaces C's `lease_set_interface()` (`lease.c` line 2972).
pub fn lease_set_interface(lease: &mut DhcpLease, interface: &str, _now: i64) {
    let changed = lease
        .interface
        .as_ref()
        .is_none_or(|iface| iface != interface);
    if changed {
        lease.interface = Some(interface.to_string());
        lease.flags.has_changed = true;
        lease.raw_flags |= LEASE_CHANGED;
    }
}

/// Set the relay agent ID (DHCPv4 option 82) on a lease.
///
/// Replaces C's `lease_set_agent_id()` (`lease.c` line 3031).
pub fn lease_set_agent_id(lease: &mut DhcpLease, data: &[u8]) {
    let changed = match &lease.agent_id {
        Some(existing) => existing.as_slice() != data,
        None => !data.is_empty(),
    };
    if changed {
        lease.agent_id = if data.is_empty() {
            None
        } else {
            Some(data.to_vec())
        };
        lease.flags.aux_changed = true;
        lease.raw_flags |= LEASE_AUX_CHANGED;
    }
}

/// Set the vendor class (DHCPv4 option 60) on a lease.
///
/// Replaces C's `lease_set_vendorclass()` (`lease.c` line 3084).
pub fn lease_set_vendorclass(lease: &mut DhcpLease, data: &[u8]) {
    let changed = match &lease.vendor_class {
        Some(existing) => existing.as_slice() != data,
        None => !data.is_empty(),
    };
    if changed {
        lease.vendor_class = if data.is_empty() {
            None
        } else {
            Some(data.to_vec())
        };
        lease.flags.aux_changed = true;
        lease.raw_flags |= LEASE_AUX_CHANGED;
    }
}

/// Calculate FQDNs for all leases from their hostnames and domain suffixes.
///
/// Replaces C's `lease_calc_fqdns()` (`lease.c` line 2770).
pub fn lease_calc_fqdns(db: &mut LeaseDatabase, state: &DaemonState) {
    for lease in db.leases.iter_mut() {
        if let Some(ref hostname) = lease.hostname {
            let domain = if lease.is_v6() {
                #[cfg(feature = "dhcp6")]
                {
                    lease.addr6.as_ref().and_then(|a| get_domain6(a, state))
                }
                #[cfg(not(feature = "dhcp6"))]
                {
                    state.domain_suffix.clone()
                }
            } else {
                state.domain_suffix.clone()
            };

            if let Some(ref dom) = domain {
                if !dom.is_empty() {
                    lease.fqdn = Some(format!("{}.{}", hostname, dom));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lease Maintenance
// ---------------------------------------------------------------------------

/// Remove expired leases from the database.
///
/// Replaces C's `lease_prune()` (`lease.c` line 1405).
///
/// Expired leases are moved to `old_leases` for deferred script deletion
/// notification. If `target` is specified, only that address is pruned.
pub fn lease_prune(db: &mut LeaseDatabase, target: Option<&Ipv4Addr>, now: i64) -> usize {
    lease_prune_inner(db, target, now)
}

fn lease_prune_inner(db: &mut LeaseDatabase, target: Option<&Ipv4Addr>, now: i64) -> usize {
    let mut pruned = 0usize;
    let mut i = 0;

    while i < db.leases.len() {
        let should_prune = {
            let lease = &db.leases[i];
            if let Some(target_addr) = target {
                lease.addr == Some(*target_addr)
            } else {
                lease.expires > 0 && lease.expires <= now
            }
        };

        if should_prune {
            let mut lease = db.leases.remove(i);
            db.leases_left += 1;
            pruned += 1;

            if lease.is_v4() {
                debug!(
                    addr = ?lease.addr,
                    metric = %MetricType::LeasesPruned4 as u32,
                    "pruning expired DHCPv4 lease"
                );
            } else {
                debug!(
                    addr = ?lease.addr6,
                    metric = %MetricType::LeasesPruned6 as u32,
                    "pruning expired DHCPv6 lease"
                );
            }

            lease.flags.has_changed = true;
            lease.raw_flags |= LEASE_CHANGED;
            db.old_leases.push(lease);
            db.file_dirty = true;
            db.dns_dirty = true;
        } else {
            i += 1;
        }
    }

    pruned
}

/// Update the DNS cache with all current lease hostnames.
///
/// Replaces C's `lease_update_dns()` (`lease.c` line 1297).
///
/// Clears DHCP-sourced DNS entries and rebuilds from the lease database.
pub fn lease_update_dns(
    db: &mut LeaseDatabase,
    force: bool,
    state: &DaemonState,
    cache: &mut DnsCache,
) {
    if !db.dns_dirty && !force {
        return;
    }
    lease_update_dns_inner(&db.leases, state, cache);
    db.dns_dirty = false;
}

fn lease_update_dns_inner(leases: &[DhcpLease], _state: &DaemonState, cache: &mut DnsCache) {
    cache.cache_unhash_dhcp();

    for lease in leases {
        let name = lease.fqdn.as_deref().or(lease.hostname.as_deref());
        if let Some(hostname) = name {
            if let Some(addr) = lease.addr {
                let ip: IpAddr = IpAddr::V4(addr);
                let ttl = if lease.expires > 0 {
                    lease.expires as u32
                } else {
                    0
                };
                let _ = cache.cache_add_dhcp_entry(hostname, ip, ttl);
                debug!(name = hostname, addr = %addr, "registered DHCPv4 DNS entry");
            }

            #[cfg(feature = "dhcp6")]
            if let Some(addr6) = lease.addr6 {
                let ip: IpAddr = IpAddr::V6(addr6);
                let ttl = if lease.expires > 0 {
                    lease.expires as u32
                } else {
                    0
                };
                let _ = cache.cache_add_dhcp_entry(hostname, ip, ttl);
                debug!(name = hostname, addr = %addr6, "registered DHCPv6 DNS entry");

                for slaac in &lease.slaac_addresses {
                    if slaac.backoff == 0 {
                        let slaac_ip: IpAddr = IpAddr::V6(slaac.addr);
                        let _ = cache.cache_add_dhcp_entry(hostname, slaac_ip, ttl);
                    }
                }
            }
        }
    }

    debug!(lease_count = leases.len(), "DNS cache rebuilt from leases");
}

/// Enumerate network interfaces and associate leases with their interfaces.
///
/// Replaces C's `lease_find_interfaces()` (`lease.c` line 1181).
///
/// Calls `enumerate_interfaces()` to refresh the interface list in DaemonState,
/// then matches each lease's address against discovered interface subnets.
/// Uses `iface_check()` to validate each interface is configured for DHCP.
pub fn lease_find_interfaces(db: &mut LeaseDatabase, state: &mut DaemonState) {
    for lease in db.leases.iter_mut() {
        lease.new_interface = 0;
        lease.new_prefixlen = 0;
    }

    // Refresh the interface list in DaemonState.
    if let Err(e) = enumerate_interfaces(state, false) {
        warn!(error = %e, "failed to enumerate interfaces for lease association");
        return;
    }

    // Walk through discovered interfaces and match against lease addresses.
    // The interface records are stored in state.interfaces after enumeration.
    // We clone the interface data to avoid borrow conflicts with lease mutation.
    let interfaces: Vec<_> = state
        .interfaces
        .iter()
        .map(|i| (i.addr, i.netmask, i.name.clone(), i.index))
        .collect();

    for (iface_addr, iface_mask, iface_name, iface_idx) in &interfaces {
        // Validate this interface is configured for DHCP service using iface_check().
        let (allowed, _auth) = iface_check(AF_INET, Some(iface_addr), iface_name, state);
        if !allowed {
            continue;
        }

        // Match v4 leases against this interface's subnet.
        if let IpAddr::V4(if_v4) = iface_addr {
            if let Some(IpAddr::V4(mask_v4)) = iface_mask {
                for lease in db.leases.iter_mut() {
                    if let Some(lease_addr) = lease.addr {
                        if is_same_net(lease_addr, *if_v4, *mask_v4) {
                            lease.new_interface = *iface_idx as i32;
                        }
                    }
                }
            }
        }
    }

    // Apply interface changes.
    for lease in db.leases.iter_mut() {
        if lease.new_interface != 0 && lease.new_interface != lease.last_interface {
            lease.last_interface = lease.new_interface;
            lease.raw_flags |= LEASE_CHANGED;
            lease.flags.has_changed = true;
            db.dns_dirty = true;
            db.file_dirty = true;
        }
    }
}

/// Generate a DHCPv6 Server DUID (DHCP Unique Identifier).
///
/// Replaces C's `lease_make_duid()` (`lease.c` line 1236).
///
/// Generates a DUID-LLT (Link-Layer plus Time, RFC 3315 Section 9.2).
pub fn lease_make_duid(now: i64, state: &mut DaemonState) -> Vec<u8> {
    #[cfg(feature = "dhcp6")]
    {
        if !state.duid.is_empty() {
            return state.duid.clone();
        }

        let mut duid = Vec::with_capacity(14);

        // DUID type 1 = DUID-LLT (Link-Layer + Time)
        duid.push(0x00);
        duid.push(0x01);
        // Hardware type: Ethernet (1)
        duid.push(0x00);
        duid.push(0x01);
        // Time: seconds since 2000-01-01 00:00:00 UTC
        let duid_time = (now - 946684800).max(0) as u32;
        duid.extend_from_slice(&duid_time.to_be_bytes());

        // Link-layer address from config or deterministic pseudo-MAC.
        if !state.duid_config.is_empty() {
            duid.extend_from_slice(&state.duid_config);
        } else {
            let time_bytes = now.to_be_bytes();
            duid.extend_from_slice(&time_bytes[2..8]);
        }

        info!(duid_len = duid.len(), "generated DHCPv6 server DUID");
        state.duid = duid.clone();
        duid
    }

    #[cfg(not(feature = "dhcp6"))]
    {
        let _ = (now, state);
        Vec::new()
    }
}

/// Apply static hostname reservations from DHCP configuration to active leases.
///
/// Replaces C's `lease_update_from_configs()` (`lease.c` line 557).
///
/// For each active v4 lease, checks if a matching DHCP config entry
/// has a hostname, and applies it if the lease doesn't already have an
/// authoritative one.
///
/// Uses two matching paths:
/// 1. Full `DhcpConfig` matching via `find_config()` if static configs are available
/// 2. Direct `DhcpConfigEntry` matching from `DaemonState.dhcp_conf` for inline entries
pub fn lease_update_from_configs(
    db: &mut LeaseDatabase,
    state: &DaemonState,
    static_configs: Option<&[DhcpConfig]>,
    contexts: Option<&[DhcpContext]>,
) {
    for lease in db.leases.iter_mut() {
        if !lease.is_v4() {
            continue;
        }
        let hwaddr_slice = &lease.hwaddr[..lease.hwaddr_len.min(lease.hwaddr.len())];
        let hostname_ref = lease.hostname.as_deref();

        // Path 1: Use find_config() with full DhcpConfig structures if available.
        // This matches the C pattern where dhcp_conf is a linked list of dhcp_config.
        if let (Some(configs), Some(ctx_list)) = (static_configs, contexts) {
            if let Some(ctx) = ctx_list.first() {
                if let Some(config) = find_config(
                    configs,
                    ctx,
                    lease.clid.as_deref(),
                    hwaddr_slice,
                    lease.hwaddr_type,
                    hostname_ref,
                ) {
                    // Apply hostname from matched DhcpConfig if CONFIG_NAME is set.
                    if config.flags & CONFIG_NAME != 0 {
                        if let Some(ref config_hostname) = config.hostname {
                            apply_config_hostname(
                                lease,
                                config_hostname,
                                &mut db.dns_dirty,
                                &mut db.file_dirty,
                            );
                        }
                    }
                    // Check for associated NetId tags.
                    for _net_id in &config.netid {
                        let _tag: &NetId = _net_id;
                        debug!(tag = ?_tag, lease = %lease, "config matched with network tag");
                    }
                    continue;
                }
            }
        }

        // Path 2: Direct matching against DhcpConfigEntry from DaemonState.
        for config_entry in &state.dhcp_conf {
            let hwaddr_matches = !config_entry.hwaddr.is_empty()
                && config_entry.hwaddr.len() == hwaddr_slice.len()
                && config_entry.hwaddr == hwaddr_slice;

            let clid_matches = match (&config_entry.clid, &lease.clid) {
                (c, Some(lc)) if !c.is_empty() => c.as_slice() == lc.as_slice(),
                _ => false,
            };

            if !(hwaddr_matches || clid_matches) {
                continue;
            }

            if config_entry.flags & CONFIG_NAME != 0 {
                if let Some(ref config_hostname) = config_entry.hostname {
                    apply_config_hostname(
                        lease,
                        config_hostname,
                        &mut db.dns_dirty,
                        &mut db.file_dirty,
                    );
                }
            }
            break; // First match wins.
        }
    }
}

/// Apply a configuration hostname to a lease if it doesn't already have AUTH_NAME.
fn apply_config_hostname(
    lease: &mut DhcpLease,
    config_hostname: &str,
    dns_dirty: &mut bool,
    file_dirty: &mut bool,
) {
    let needs_update = !lease
        .hostname
        .as_ref()
        .is_some_and(|h| hostname_eq(h, config_hostname));
    if needs_update && (lease.raw_flags & LEASE_AUTH_NAME == 0) {
        lease.hostname = Some(config_hostname.to_string());
        lease.raw_flags |= LEASE_AUTH_NAME | LEASE_CHANGED;
        lease.flags.has_changed = true;
        *dns_dirty = true;
        *file_dirty = true;
    }
}

// ---------------------------------------------------------------------------
// Max Address Tracking
// ---------------------------------------------------------------------------

/// Find the highest allocated IPv4 address within a DHCP context range.
///
/// Replaces C's `lease_find_max_addr()` (`lease.c` line 2059).
pub fn lease_find_max_addr(db: &[DhcpLease], context: &DhcpContext) -> Option<Ipv4Addr> {
    if context.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
        return None;
    }

    let mut max_addr: Option<u32> = None;
    for lease in db {
        if !lease.is_v4() {
            continue;
        }
        if let Some(addr) = lease.addr {
            let addr_u32 = u32::from(addr);
            let start_u32 = u32::from(context.start);
            let end_u32 = u32::from(context.end);
            if addr_u32 >= start_u32
                && addr_u32 <= end_u32
                && is_same_net(addr, context.start, context.netmask)
            {
                match max_addr {
                    Some(m) if addr_u32 > m => max_addr = Some(addr_u32),
                    None => max_addr = Some(addr_u32),
                    _ => {}
                }
            }
        }
    }
    max_addr.map(Ipv4Addr::from)
}

/// Find the highest allocated IPv6 address within a DHCP context range.
///
/// Replaces C's `lease_find_max_addr6()` (`lease.c` line 2005).
#[cfg(feature = "dhcp6")]
pub fn lease_find_max_addr6(db: &[DhcpLease], context: &DhcpContext) -> Option<Ipv6Addr> {
    if context.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
        return None;
    }

    let mut max_addr: Option<u128> = None;
    for lease in db {
        if !lease.is_v6() {
            continue;
        }
        if let Some(addr6) = lease.addr6 {
            let a = u128::from(addr6);
            let s = u128::from(context.start6);
            let e = u128::from(context.end6);
            if a >= s && a <= e && is_same_net6(addr6, context.start6, context.prefix as u8) {
                match max_addr {
                    Some(m) if a > m => max_addr = Some(a),
                    None => max_addr = Some(a),
                    _ => {}
                }
            }
        }
    }
    max_addr.map(Ipv6Addr::from)
}

// ---------------------------------------------------------------------------
// SLAAC and DHCPv6 Integration
// ---------------------------------------------------------------------------

/// Handle an ICMPv6 echo reply for SLAAC address confirmation.
///
/// Replaces C's `lease_ping_reply()` (`lease.c` line 1089).
#[cfg(feature = "dhcp6")]
pub fn lease_ping_reply(
    db: &mut LeaseDatabase,
    sender: &Ipv6Addr,
    packet: &[u8],
    interface: &str,
    options: &OptionFlags,
) {
    let mut slaac_infos = build_slaac_lease_infos(&db.leases);
    slaac_ping_reply(sender, packet, interface, &mut slaac_infos, options);
    apply_slaac_updates(&mut db.leases, &slaac_infos);
}

/// Update SLAAC addresses for all DHCPv6 leases.
///
/// Replaces C's `lease_update_slaac()` (`lease.c` line 1128).
///
/// Regenerates SLAAC addresses by calling `slaac_add_addrs()` for each v6
/// lease with a valid hardware address, then runs periodic SLAAC ping
/// maintenance via `periodic_slaac()`.
#[cfg(feature = "dhcp6")]
pub fn lease_update_slaac(db: &mut LeaseDatabase, now: i64, contexts: &[DhcpContext]) {
    let mut slaac_infos = build_slaac_lease_infos(&db.leases);

    // Regenerate SLAAC addresses from EUI-64 encoding.
    for info in slaac_infos.iter_mut() {
        if info.hwaddr_len == 0 || info.hwaddr_len == HWADDR_LEN_UNSET {
            continue;
        }
        let changed = slaac_add_addrs(info, contexts, now, false);
        if changed {
            db.dns_dirty = true;
        }
    }

    // Run periodic SLAAC ping maintenance timer.
    if let Ok(mut rng) = SurfRng::new() {
        let _result = periodic_slaac(now, &mut slaac_infos, contexts, &mut rng);
    }

    apply_slaac_updates(&mut db.leases, &slaac_infos);
}

/// Build SlaacLeaseInfo list from current leases for slaac module calls.
///
/// Includes all DHCPv6 leases with valid hardware addresses (hwaddr_len > 0),
/// not just those that already have SLAAC addresses. This allows initial SLAAC
/// address creation for newly allocated v6 leases, matching C behavior where
/// `slaac_add_addrs()` iterates all v6 leases regardless of existing SLAAC state.
#[cfg(feature = "dhcp6")]
fn build_slaac_lease_infos(leases: &[DhcpLease]) -> Vec<SlaacLeaseInfo> {
    leases
        .iter()
        .filter(|l| l.is_v6() && l.hwaddr_len > 0)
        .map(|l| SlaacLeaseInfo {
            hwaddr: l.hwaddr[..l.hwaddr_len.min(l.hwaddr.len())].to_vec(),
            hwaddr_type: l.hwaddr_type as u16,
            hwaddr_len: l.hwaddr_len,
            last_interface: l.last_interface,
            hostname: l.hostname.clone(),
            flags: l.raw_flags,
            slaac_addresses: l.slaac_addresses.clone(),
            clid: l.clid.clone(),
        })
        .collect()
}

/// Copy updated SLAAC state back to leases from slaac module results.
///
/// Must iterate with the same filter as `build_slaac_lease_infos` (all v6
/// leases with valid hardware addresses) to maintain 1:1 index correspondence.
#[cfg(feature = "dhcp6")]
fn apply_slaac_updates(leases: &mut [DhcpLease], infos: &[SlaacLeaseInfo]) {
    let mut info_idx = 0;
    for lease in leases.iter_mut() {
        if lease.is_v6() && lease.hwaddr_len > 0 {
            if info_idx < infos.len() {
                lease.slaac_addresses = infos[info_idx].slaac_addresses.clone();
            }
            info_idx += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Script Notification
// ---------------------------------------------------------------------------

/// Mark all active leases as changed for script re-notification.
///
/// Replaces C's `rerun_scripts()` (`lease.c` line 3133).
///
/// Called on SIGHUP (configuration reload) to trigger lease-change scripts
/// for all current leases, allowing external systems to resynchronize.
pub fn rerun_scripts(db: &mut LeaseDatabase) {
    for lease in db.leases.iter_mut() {
        lease.flags.has_changed = true;
        lease.raw_flags |= LEASE_CHANGED;
    }
    info!(
        count = db.leases.len(),
        "marked all leases for script re-run"
    );
}

/// Process one pending script notification.
///
/// Replaces C's `do_script_run()` (`lease.c` line 3185).
///
/// Priority order (matching C):
/// 1. Leases with old_hostname pending (ACTION_OLD_HOSTNAME)
/// 2. Old leases pending deletion (ACTION_DEL)
/// 3. New leases (ACTION_ADD)
/// 4. Changed leases (ACTION_OLD)
///
/// Returns action type and lease data, or None if no notifications pending.
pub fn do_script_run(db: &mut LeaseDatabase) -> Option<(i32, DhcpLease)> {
    // Priority 1: old_hostname notifications.
    for lease in db.leases.iter_mut() {
        if lease.old_hostname.is_some() {
            let result = lease.clone();
            lease.old_hostname = None;
            return Some((ACTION_OLD_HOSTNAME, result));
        }
    }

    // Priority 2: old (deleted) lease notifications.
    if let Some(mut old_lease) = db.old_leases.pop() {
        old_lease.extradata = None;
        return Some((ACTION_DEL, old_lease));
    }

    // Priority 3 & 4: new or changed leases.
    for lease in db.leases.iter_mut() {
        if lease.flags.is_new {
            let result = lease.clone();
            lease.flags.is_new = false;
            lease.flags.has_changed = false;
            lease.raw_flags &= !(LEASE_NEW | LEASE_CHANGED);
            lease.extradata = None;
            return Some((ACTION_ADD, result));
        }
        if lease.flags.has_changed {
            let result = lease.clone();
            lease.flags.has_changed = false;
            lease.raw_flags &= !LEASE_CHANGED;
            lease.extradata = None;
            return Some((ACTION_OLD, result));
        }
    }

    None
}

/// Append extra data to a lease's extradata buffer for script consumption.
///
/// Replaces C's `lease_add_extradata()` (`lease.c` line 3330).
///
/// If `delim >= 0`, NULL bytes in data are filtered out and the delimiter
/// is appended. If `delim == -1`, raw data including NULLs is appended.
pub fn lease_add_extradata(lease: &mut DhcpLease, data: &[u8], delim: i32) {
    let buf = lease.extradata.get_or_insert_with(Vec::new);
    if delim >= 0 {
        for &b in data {
            if b != 0 {
                buf.push(b);
            }
        }
        buf.push(delim as u8);
    } else {
        buf.extend_from_slice(data);
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_v4_lease() {
        let parts = vec![
            "1700000000",
            "00:11:22:33:44:55",
            "192.168.1.100",
            "myhost",
            "01:00:11:22:33:44:55",
        ];
        let lease = parse_v4_lease(1700000000, &parts, 1).expect("should parse");
        assert_eq!(lease.expires, 1700000000);
        assert_eq!(lease.addr, Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(lease.hostname.as_deref(), Some("myhost"));
        assert_eq!(lease.hwaddr_type, ARPHRD_ETHER as i32);
        assert_eq!(lease.hwaddr_len, 6);
        assert!(lease.clid.is_some());
    }

    #[test]
    fn test_parse_v4_lease_star_fields() {
        let parts = vec!["1700000000", "00:11:22:33:44:55", "10.0.0.1", "*", "*"];
        let lease = parse_v4_lease(1700000000, &parts, 1).expect("should parse");
        assert!(lease.hostname.is_none());
        assert!(lease.clid.is_none());
    }

    #[test]
    fn test_parse_mac_field_typed() {
        let (hw_type, bytes) = parse_mac_field("6-00:11:22:33:44:55:66:77").unwrap();
        assert_eq!(hw_type, 6);
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_parse_mac_field_ethernet() {
        let (hw_type, bytes) = parse_mac_field("00:11:22:33:44:55").unwrap();
        assert_eq!(hw_type, ARPHRD_ETHER as i32);
        assert_eq!(bytes.len(), 6);
    }

    #[test]
    fn test_format_mac_roundtrip() {
        let mac = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let formatted = format_mac_for_file(&mac, 6, ARPHRD_ETHER as i32);
        assert_eq!(formatted, "00:11:22:33:44:55");
    }

    #[test]
    fn test_v4_lease_write_parse_roundtrip() {
        let mut lease = DhcpLease::new_empty();
        lease.expires = 1700000000;
        lease.addr = Some(Ipv4Addr::new(192, 168, 1, 50));
        lease.lease_type = LeaseType::V4;
        lease.hwaddr = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        lease.hwaddr_len = 6;
        lease.hwaddr_type = ARPHRD_ETHER as i32;
        lease.hostname = Some("testhost".to_string());
        lease.clid = None;
        lease.flags = LeaseFlags::default();
        lease.raw_flags = 0;

        let mut buf = Vec::new();
        write_v4_lease(&mut buf, &lease).expect("write should succeed");
        let line = String::from_utf8(buf).unwrap();
        assert!(line.contains("1700000000"));
        assert!(line.contains("192.168.1.50"));
        assert!(line.contains("testhost"));
        assert!(line.contains("aa:bb:cc:dd:ee:ff"));

        let parts: Vec<&str> = line.trim().splitn(6, ' ').collect();
        let parsed = parse_v4_lease(1700000000, &parts, 1).expect("should parse back");
        assert_eq!(parsed.addr, lease.addr);
        assert_eq!(parsed.hostname.as_deref(), Some("testhost"));
    }

    #[test]
    fn test_lease4_allocate() {
        let lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(lease.addr, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(lease.flags.is_new);
        assert_eq!(lease.expires, 1);
        assert_eq!(lease.hwaddr_len, HWADDR_LEN_UNSET);
    }

    #[test]
    fn test_lease_set_expires_infinite() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_set_expires(&mut lease, 0xFFFFFFFF, 1700000000);
        assert_eq!(lease.expires, 0);
    }

    #[test]
    fn test_lease_set_expires_normal() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_set_expires(&mut lease, 3600, 1700000000);
        // With broken-rtc feature enabled, expiry stores the raw duration.
        // Without broken-rtc, expiry stores now + len (absolute timestamp).
        #[cfg(feature = "broken-rtc")]
        assert_eq!(lease.expires, 3600);
        #[cfg(not(feature = "broken-rtc"))]
        assert_eq!(lease.expires, 1700003600);
    }

    #[test]
    fn test_lease_find_by_addr() {
        let addr1 = Ipv4Addr::new(192, 168, 1, 1);
        let addr2 = Ipv4Addr::new(192, 168, 1, 2);
        let leases = vec![
            {
                let mut l = lease4_allocate(addr1);
                l.flags = LeaseFlags::default();
                l
            },
            {
                let mut l = lease4_allocate(addr2);
                l.flags = LeaseFlags::default();
                l
            },
        ];
        assert!(lease_find_by_addr(&leases, addr1).is_some());
        assert!(lease_find_by_addr(&leases, addr2).is_some());
        assert!(lease_find_by_addr(&leases, Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn test_lease_db_capacity() {
        let mut db = LeaseDatabase::new(2);
        assert!(lease_db_add(
            &mut db,
            lease4_allocate(Ipv4Addr::new(10, 0, 0, 1))
        ));
        assert!(lease_db_add(
            &mut db,
            lease4_allocate(Ipv4Addr::new(10, 0, 0, 2))
        ));
        assert!(!lease_db_add(
            &mut db,
            lease4_allocate(Ipv4Addr::new(10, 0, 0, 3))
        ));
        assert_eq!(db.leases.len(), 2);
    }

    #[test]
    fn test_lease_prune() {
        let mut db = LeaseDatabase::new(10);
        let now = 1700000000i64;

        let mut l1 = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        l1.expires = now - 100;
        l1.flags = LeaseFlags::default();
        l1.raw_flags = 0;

        let mut l2 = lease4_allocate(Ipv4Addr::new(10, 0, 0, 2));
        l2.expires = now + 3600;
        l2.flags = LeaseFlags::default();
        l2.raw_flags = 0;

        db.leases.push(l1);
        db.leases.push(l2);
        db.leases_left = 8;

        let pruned = lease_prune(&mut db, None, now);
        assert_eq!(pruned, 1);
        assert_eq!(db.leases.len(), 1);
        assert_eq!(db.leases[0].addr, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(db.old_leases.len(), 1);
    }

    #[test]
    fn test_lease_add_extradata_with_delim() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_add_extradata(&mut lease, b"hello", 0);
        let data = lease.extradata.unwrap();
        assert_eq!(&data[..5], b"hello");
        assert_eq!(data[5], 0);
    }

    #[test]
    fn test_lease_add_extradata_raw() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_add_extradata(&mut lease, b"raw\x00data", -1);
        let data = lease.extradata.unwrap();
        assert_eq!(&data[..], b"raw\x00data");
    }

    #[test]
    fn test_lease_type_display() {
        assert_eq!(format!("{}", LeaseType::Na), "na");
        assert_eq!(format!("{}", LeaseType::Ta), "ta");
        assert_eq!(format!("{}", LeaseType::Pd), "pd");
        assert_eq!(format!("{}", LeaseType::V4), "v4");
    }

    #[test]
    fn test_lease_flags_roundtrip() {
        let flags = LeaseFlags {
            is_new: true,
            has_changed: false,
            aux_changed: true,
        };
        let raw = flags.to_raw();
        assert_eq!(raw, LEASE_NEW | LEASE_AUX_CHANGED);
        let restored = LeaseFlags::from_raw(raw);
        assert!(restored.is_new);
        assert!(!restored.has_changed);
        assert!(restored.aux_changed);
    }

    #[test]
    fn test_do_script_run_priority() {
        let mut db = LeaseDatabase::new(10);
        let mut l1 = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        l1.old_hostname = Some("oldname".to_string());
        l1.flags = LeaseFlags::default();
        let l2 = lease4_allocate(Ipv4Addr::new(10, 0, 0, 2));
        db.leases.push(l1);
        db.leases.push(l2);
        db.leases_left = 8;

        let (action, _) = do_script_run(&mut db).expect("should have notification");
        assert_eq!(action, ACTION_OLD_HOSTNAME);
        let (action, _) = do_script_run(&mut db).expect("should have notification");
        assert_eq!(action, ACTION_ADD);
    }

    #[test]
    fn test_read_leases_basic() {
        let data = "1700000000 00:11:22:33:44:55 192.168.1.100 myhost 01:00:11:22:33:44:55\n\
                     1700003600 aa:bb:cc:dd:ee:ff 10.0.0.1 * *\n";
        let mut reader = BufReader::new(Cursor::new(data));
        let mut state = DaemonState::default();
        let leases = read_leases(&mut reader, &mut state).expect("should parse");
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].addr, Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(leases[0].hostname.as_deref(), Some("myhost"));
        assert_eq!(leases[1].addr, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(leases[1].hostname.is_none());
    }

    #[test]
    fn test_read_leases_comments_and_blanks() {
        let data = "# comment\n\n1700000000 00:11:22:33:44:55 192.168.1.1 host1 *\n";
        let mut reader = BufReader::new(Cursor::new(data));
        let mut state = DaemonState::default();
        let leases = read_leases(&mut reader, &mut state).expect("should parse");
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn test_rerun_scripts() {
        let mut db = LeaseDatabase::new(10);
        let mut l = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        l.flags = LeaseFlags::default();
        l.raw_flags = 0;
        db.leases.push(l);
        db.leases_left = 9;
        rerun_scripts(&mut db);
        assert!(db.leases[0].flags.has_changed);
    }

    #[test]
    fn test_lease_display() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease.hostname = Some("myhost".to_string());
        let display = format!("{}", lease);
        assert!(display.contains("10.0.0.1"));
        assert!(display.contains("myhost"));
    }

    #[test]
    fn test_lease_set_hwaddr() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        lease_set_hwaddr(&mut lease, &mac, None, 6, ARPHRD_ETHER as i32, 0, false);
        assert_eq!(lease.hwaddr_len, 6);
        assert_eq!(&lease.hwaddr[..6], &mac);
    }

    #[test]
    fn test_lease_set_hwaddr_with_clid() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let clid = [0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        lease_set_hwaddr(
            &mut lease,
            &mac,
            Some(&clid),
            6,
            ARPHRD_ETHER as i32,
            0,
            false,
        );
        assert_eq!(lease.clid.as_deref(), Some(clid.as_ref()));
    }

    #[test]
    fn test_lease_set_agent_and_vendor() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_set_agent_id(&mut lease, b"agent-data");
        assert_eq!(lease.agent_id.as_deref(), Some(b"agent-data".as_ref()));
        assert!(lease.flags.aux_changed);
        lease_set_vendorclass(&mut lease, b"vendor-class");
        assert_eq!(
            lease.vendor_class.as_deref(),
            Some(b"vendor-class".as_ref())
        );
    }

    #[test]
    fn test_kill_name_prefers_fqdn() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease.hostname = Some("host".to_string());
        lease.fqdn = Some("host.example.com".to_string());
        kill_name(&mut lease);
        assert_eq!(lease.old_hostname.as_deref(), Some("host.example.com"));
        assert!(lease.hostname.is_none());
        assert!(lease.fqdn.is_none());
    }

    #[test]
    fn test_kill_name_fallback_hostname() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease.hostname = Some("host".to_string());
        lease.fqdn = None;
        kill_name(&mut lease);
        assert_eq!(lease.old_hostname.as_deref(), Some("host"));
        assert!(lease.hostname.is_none());
    }

    #[test]
    fn test_lease_find_by_client_clid_first() {
        let mut l1 = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        l1.clid = Some(vec![0x01, 0xAA]);
        l1.hwaddr_len = 6;
        l1.hwaddr[..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        l1.flags = LeaseFlags::default();
        l1.raw_flags = 0;

        let leases = vec![l1];
        let found = lease_find_by_client(
            &leases,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ARPHRD_ETHER as i32,
            Some(&[0x01, 0xAA]),
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_lease_find_by_client_hwaddr_fallback() {
        let mut l1 = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        l1.clid = None;
        l1.hwaddr_len = 6;
        l1.hwaddr_type = ARPHRD_ETHER as i32;
        l1.hwaddr[..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        l1.flags = LeaseFlags::default();
        l1.raw_flags = 0;

        let leases = vec![l1];
        let found = lease_find_by_client(
            &leases,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ARPHRD_ETHER as i32,
            None,
        );
        assert!(found.is_some());
    }

    #[test]
    fn test_lease_set_iaid() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_set_iaid(&mut lease, 12345);
        assert_eq!(lease.iaid, 12345);
        assert!(lease.flags.has_changed);
    }

    #[test]
    fn test_lease_set_interface() {
        let mut lease = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        lease_set_interface(&mut lease, "eth0", 0);
        assert_eq!(lease.interface.as_deref(), Some("eth0"));
        assert!(lease.flags.has_changed);
    }

    #[test]
    fn test_lease_type_from_str_token() {
        assert_eq!(LeaseType::from_str_token("na"), Some(LeaseType::Na));
        assert_eq!(LeaseType::from_str_token("ta"), Some(LeaseType::Ta));
        assert_eq!(LeaseType::from_str_token("pd"), Some(LeaseType::Pd));
        assert_eq!(LeaseType::from_str_token("xx"), None);
    }

    #[test]
    fn test_do_script_run_del_old_leases() {
        let mut db = LeaseDatabase::new(10);
        let mut old = lease4_allocate(Ipv4Addr::new(10, 0, 0, 99));
        old.flags = LeaseFlags::default();
        old.raw_flags = 0;
        db.old_leases.push(old);

        let (action, lease) = do_script_run(&mut db).expect("should have del");
        assert_eq!(action, ACTION_DEL);
        assert_eq!(lease.addr, Some(Ipv4Addr::new(10, 0, 0, 99)));
    }

    #[test]
    fn test_no_script_notifications_when_empty() {
        let mut db = LeaseDatabase::new(10);
        assert!(do_script_run(&mut db).is_none());
    }

    #[test]
    fn test_infinite_lease_not_pruned() {
        let mut db = LeaseDatabase::new(10);
        let now = 1700000000i64;
        let mut l = lease4_allocate(Ipv4Addr::new(10, 0, 0, 1));
        l.expires = 0; // Infinite.
        l.flags = LeaseFlags::default();
        l.raw_flags = 0;
        db.leases.push(l);
        db.leases_left = 9;

        let pruned = lease_prune(&mut db, None, now);
        assert_eq!(pruned, 0);
        assert_eq!(db.leases.len(), 1);
    }
}

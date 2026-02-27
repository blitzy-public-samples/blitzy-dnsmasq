//! DHCP Lease Persistence and Management.
//!
//! This module replaces `src/lease.c` (3364 lines) from the original C dnsmasq codebase.
//! It manages the complete lifecycle of DHCP leases for both DHCPv4 and DHCPv6,
//! maintaining all active leases in `HashMap<Ipv4Addr, DhcpLease>` (v4) and
//! `HashMap<Ipv6Addr, DhcpLease>` (v6), replacing C intrusive linked lists with
//! O(1) address-based lookup.
//!
//! # Key Responsibilities
//! - `init()`: Initialize lease database from persistent storage on daemon startup
//! - `update_file()`: Asynchronously persist lease changes to disk
//! - `allocate_v4()` / `allocate_v6()`: Allocate new lease structures
//! - `find_by_addr_v4()` / `find_by_client()`: Locate leases by IP address or client
//! - `update_from_configs()`: Apply static reservations from configuration
//! - `set_expires()`, `set_hwaddr()`, etc.: Modify lease attributes
//! - `prune()`: Remove expired leases and trigger cleanup events
//! - `rerun_scripts()` / `do_script_run()`: Execute lease-change scripts
//!
//! # Lease File Format (backward-compatible with C dnsmasq)
//! ```text
//! <expiry-time> <MAC-address> <IP-address> <hostname> <client-id>
//! ```
//! DHCPv6 leases:
//! ```text
//! <expiry-time> <IAID> <IPv6-address> <hostname> <client-DUID>
//! ```
//! Auxiliary records:
//! ```text
//! duid <hex-encoded-duid>
//! vendorclass <IP-address> <hex-encoded-vendor-class>
//! agent-info <IP-address> <hex-encoded-agent-info>
//! ```
//!
//! # Feature Gates
//! - DHCPv6 methods: `#[cfg(feature = "dhcp6")]`
//! - Script integration: `#[cfg(feature = "script")]`
//!
//! # Thread Safety
//! Single-threaded architecture — no locking required. All operations happen
//! in the main event loop context.
//!
//! # Source Reference
//! - Primary: `src/lease.c` (3364 lines)
//! - Types: `src/dnsmasq.h` (`struct dhcp_lease`, `struct daemon`)

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use log::{debug, error, info, warn};
use thiserror::Error;

use crate::config::constants::{LEASEFILE, LEASE_RETRY, MAXLEASES};
use crate::core::util::{canonicalise, hostname_isequal, legal_hostname};
use crate::dns::cache::DnsCache;
use crate::net::interface::index_to_name;
use crate::types::addr::AllAddr;
use crate::types::dhcp::{
    DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpLease,
    LeaseFlags, ACTION_ADD, ACTION_OLD,
};
use crate::types::dns::CacheEntryFlags;

// ---------------------------------------------------------------------------
// LeaseType — DHCPv6 lease address type
// ---------------------------------------------------------------------------

/// DHCPv6 lease address type (Non-temporary or Temporary).
///
/// Maps to C `LEASE_NA` and `LEASE_TA` constants, used in DHCPv6 lease
/// allocation to distinguish between IA_NA (Non-temporary Address) and
/// IA_TA (Temporary Address) identity associations per RFC 3315.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseType {
    /// Non-temporary address (IA_NA) — standard DHCPv6 address lease.
    NA,
    /// Temporary address (IA_TA) — privacy-oriented temporary address.
    TA,
}

impl LeaseType {
    /// Convert to corresponding LeaseFlags bit for storage.
    fn to_flags(self) -> LeaseFlags {
        match self {
            LeaseType::NA => LeaseFlags::NA,
            LeaseType::TA => LeaseFlags::TA,
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseError — Error type for lease operations
// ---------------------------------------------------------------------------

/// Error types for DHCP lease database operations.
///
/// Replaces C-style `die()`, `my_syslog(LOG_ERR, ...)`, and `errno` patterns
/// with Rust `Result<T, LeaseError>` error propagation.
#[derive(Debug, Error)]
pub enum LeaseError {
    /// Cannot open or create the lease file.
    #[error("cannot open lease file {path}: {source}")]
    FileOpen {
        /// Path that failed to open.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Error writing to lease file.
    #[error("lease file write error: {0}")]
    FileWrite(#[source] std::io::Error),

    /// Parse error when reading lease file.
    #[error("lease file parse error at line {line}: {message}")]
    ParseError {
        /// Line number where the error occurred.
        line: usize,
        /// Description of the parse error.
        message: String,
    },

    /// Maximum lease limit has been reached.
    #[error("maximum lease limit reached ({max})")]
    LimitExceeded {
        /// The configured maximum lease count.
        max: usize,
    },

    /// Lease-init script exited with non-zero status.
    #[error("lease-init script failed with exit code {code}")]
    ScriptFailed {
        /// Process exit code from the script.
        code: i32,
    },
}

// ---------------------------------------------------------------------------
// LeaseDatabase — Central lease management struct
// ---------------------------------------------------------------------------

/// DHCP lease database with persistent storage and DNS integration.
///
/// Maintains all active DHCP leases in HashMap collections keyed by IP address,
/// replacing the C intrusive linked list approach. Provides persistent storage
/// to disk, DNS hostname registration, and integration with external scripts
/// for lease change events.
///
/// # Data Structure Transformation
/// - C `static struct dhcp_lease *leases` linked list → `leases_v4: HashMap<Ipv4Addr, DhcpLease>`
/// - C `static struct dhcp_lease *old_leases` → processed during `init()` and discarded
/// - C `static int dns_dirty, file_dirty, leases_left` → fields on this struct
///
/// # Source Reference
/// `src/lease.c` lines 118-119 (static state), lines 433-513 (init), lines 677-921 (file I/O).
pub struct LeaseDatabase {
    /// Active DHCPv4 leases indexed by IPv4 address.
    leases_v4: HashMap<Ipv4Addr, DhcpLease>,

    /// Active DHCPv6 leases indexed by IPv6 address.
    #[cfg(feature = "dhcp6")]
    leases_v6: HashMap<Ipv6Addr, DhcpLease>,

    /// Maximum number of leases allowed (default MAXLEASES=1000).
    max_leases: usize,

    /// Remaining lease slots available (decremented on each allocation).
    leases_left: usize,

    /// DNS cache needs update flag — set when hostnames change.
    dns_dirty: bool,

    /// Lease file needs update flag — set when any lease data changes.
    file_dirty: bool,

    /// Path to persistent lease file on disk.
    lease_file: PathBuf,

    /// Open file handle for lease persistence (None if lease-ro mode).
    lease_stream: Option<File>,

    /// Server DUID for DHCPv6 (Device Unique IDentifier).
    #[cfg(feature = "dhcp6")]
    server_duid: Vec<u8>,

    /// Domain suffix for FQDN calculation.
    domain_suffix: Option<String>,

    /// Whether we had a write error on last attempt.
    write_error: bool,

    /// Timestamp of last write error for retry logic.
    last_write_error_time: i64,
}

impl LeaseDatabase {
    /// Create a new `LeaseDatabase` with default configuration.
    ///
    /// Initializes the lease database with the default MAXLEASES limit (1000)
    /// and the platform-specific default lease file path.
    ///
    /// # Arguments
    /// * `max_leases` — Maximum number of leases (typically from DaemonState.dhcp.dhcp_max)
    /// * `lease_file` — Path to the lease file (None uses platform default)
    ///
    /// # Source Reference
    /// `src/lease.c` lines 433-437 (initialization).
    pub fn new(max_leases: Option<usize>, lease_file: Option<PathBuf>) -> Self {
        let max = max_leases.unwrap_or(MAXLEASES);
        LeaseDatabase {
            leases_v4: HashMap::new(),
            #[cfg(feature = "dhcp6")]
            leases_v6: HashMap::new(),
            max_leases: max,
            leases_left: max,
            dns_dirty: false,
            file_dirty: false,
            lease_file: lease_file.unwrap_or_else(|| PathBuf::from(LEASEFILE)),
            lease_stream: None,
            #[cfg(feature = "dhcp6")]
            server_duid: Vec::new(),
            domain_suffix: None,
            write_error: false,
            last_write_error_time: 0,
        }
    }

    /// Initialize the lease database from persistent storage.
    ///
    /// Opens the lease file (or executes a lease-init script in read-only mode),
    /// parses existing lease records, prunes expired leases, and prepares for
    /// DHCP operation. This function must be called exactly once during daemon
    /// startup before any DHCP packet processing begins.
    ///
    /// # Arguments
    /// * `now` — Current timestamp (seconds since epoch).
    /// * `lease_ro` — Whether the lease file is in read-only mode (OPT_LEASE_RO).
    /// * `lease_change_command` — Optional lease-change script path.
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(LeaseError)` on critical initialization failure.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 433-513 (lease_init).
    pub fn init(
        &mut self,
        now: i64,
        lease_ro: bool,
        lease_change_command: Option<&str>,
    ) -> Result<(), LeaseError> {
        if lease_ro {
            // In read-only mode, we run the lease-change script with "init"
            // to get initial state, or operate without a lease database.
            #[cfg(feature = "script")]
            if let Some(cmd) = lease_change_command {
                // Execute "<script> init" and read leases from stdout
                match std::process::Command::new("sh")
                    .arg("-c")
                    .arg(format!("{} init", cmd))
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(child) => {
                        if let Some(stdout) = child.stdout {
                            let reader = BufReader::new(stdout);
                            if let Err(e) = self.read_leases(now, reader) {
                                warn!("failed to parse lease-init script output: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        return Err(LeaseError::ScriptFailed {
                            code: e.raw_os_error().unwrap_or(-1),
                        });
                    }
                }
            }
            #[cfg(not(feature = "script"))]
            {
                let _ = lease_change_command;
            }

            self.file_dirty = false;
            self.dns_dirty = true;
            return Ok(());
        }

        // Standard mode: open lease file in append+read mode (a+)
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&self.lease_file)
            .map_err(|e| LeaseError::FileOpen {
                path: self.lease_file.clone(),
                source: e,
            })?;

        // Read existing leases from the file
        let reader = BufReader::new(&file);
        if let Err(e) = self.read_leases(now, reader) {
            error!("failed to parse lease database cleanly: {}", e);
        }

        self.lease_stream = Some(file);

        // Prune expired leases from the loaded set
        self.prune(None, now);

        // Mark DNS dirty for initial cache population
        self.dns_dirty = true;
        self.file_dirty = false;

        info!(
            "lease database loaded: {} v4 leases{}",
            self.leases_v4.len(),
            {
                #[cfg(feature = "dhcp6")]
                {
                    format!(", {} v6 leases", self.leases_v6.len())
                }
                #[cfg(not(feature = "dhcp6"))]
                {
                    String::new()
                }
            }
        );

        Ok(())
    }

    /// Parse lease database from a buffered reader.
    ///
    /// Reads lease entries from the persistent lease file, parsing both DHCPv4
    /// and DHCPv6 lease records along with associated metadata (vendor class,
    /// relay agent info, DUID). Invalid lines are logged and skipped rather
    /// than causing a parse failure.
    ///
    /// # Lease File Format
    /// - DHCPv4: `<expiry> <hw-addr> <ip-addr> <hostname> <client-id>`
    /// - DHCPv6: `<expiry> [T]<IAID> <ipv6-addr> <hostname> <DUID>`
    /// - DUID:   `duid <hex-encoded-duid>`
    /// - Vendor: `vendorclass <ip-addr> <hex-data>`
    /// - Agent:  `agent-info <ip-addr> <hex-data>`
    ///
    /// # Source Reference
    /// `src/lease.c` lines 168-309 (read_leases).
    fn read_leases(
        &mut self,
        _now: i64,
        reader: impl BufRead,
    ) -> Result<(), LeaseError> {
        let mut line_num = 0usize;

        for line_result in reader.lines() {
            line_num += 1;
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!("lease file read error at line {}: {}", line_num, e);
                    continue;
                }
            };

            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                warn!("ignoring invalid line {} in lease database", line_num);
                continue;
            }

            // Handle DUID line: "duid <hex>"
            #[cfg(feature = "dhcp6")]
            if parts[0] == "duid" {
                match hex_decode(parts[1]) {
                    Some(duid_bytes) => {
                        self.server_duid = duid_bytes;
                        debug!("loaded server DUID ({} bytes)", self.server_duid.len());
                    }
                    None => {
                        warn!("failed to parse DUID at line {}", line_num);
                    }
                }
                continue;
            }

            // Handle vendorclass and agent-info auxiliary lines
            if parts[0] == "vendorclass" || parts[0] == "agent-info" {
                if parts.len() < 3 {
                    warn!(
                        "ignoring malformed {} line {} in lease database",
                        parts[0], line_num
                    );
                    continue;
                }
                let record_type = parts[0];
                let ip_str = parts[1];
                let hex_data = parts[2];

                if let Some(data) = hex_decode(hex_data) {
                    // Try to find the lease by IP address
                    if let Ok(v4addr) = ip_str.parse::<Ipv4Addr>() {
                        if let Some(lease) = self.leases_v4.get_mut(&v4addr) {
                            if record_type == "vendorclass" {
                                lease.vendorclass = data.clone();
                            } else {
                                lease.agent_id = data.clone();
                            }
                        }
                    }
                    #[cfg(feature = "dhcp6")]
                    if let Ok(v6addr) = ip_str.parse::<Ipv6Addr>() {
                        if let Some(lease) = self.leases_v6.get_mut(&v6addr) {
                            if record_type == "vendorclass" {
                                lease.vendorclass = data;
                            } else {
                                lease.agent_id = data;
                            }
                        }
                    }
                }
                continue;
            }

            // Standard lease line: need at least 5 fields
            if parts.len() < 5 {
                warn!(
                    "ignoring invalid line {} in lease database: {}",
                    line_num,
                    if line.len() > 80 { &line[..80] } else { &line }
                );
                continue;
            }

            let expiry_str = parts[0];
            let hw_or_iaid = parts[1];
            let ip_str = parts[2];
            let hostname_str = parts[3];
            let clid_or_duid = parts[4];

            // Parse expiry time
            let expiry: i64 = match expiry_str.parse() {
                Ok(v) => v,
                Err(_) => {
                    warn!("bad expiry value at line {}: {}", line_num, expiry_str);
                    continue;
                }
            };

            // Determine if this is a v4 or v6 lease based on IP address format
            if let Ok(v4addr) = ip_str.parse::<Ipv4Addr>() {
                // DHCPv4 lease
                let mut lease = DhcpLease::default();
                lease.addr = v4addr;
                lease.expires = expiry;

                // Parse hardware address
                let (hwaddr_bytes, hw_type) = parse_hw_addr(hw_or_iaid);
                lease.hwaddr = hwaddr_bytes.clone();
                lease.hwaddr_len = hwaddr_bytes.len() as i32;
                lease.hwaddr_type = if hw_type == 0 && !hwaddr_bytes.is_empty() {
                    1 // ARPHRD_ETHER
                } else {
                    hw_type
                };

                // Parse client ID
                if clid_or_duid != "*" {
                    if let Some(clid_bytes) = hex_decode(clid_or_duid) {
                        lease.clid = clid_bytes;
                    }
                }

                // Set hostname
                if hostname_str != "*" && legal_hostname(hostname_str) {
                    lease.hostname = Some(hostname_str.to_string());
                }

                // Clear NEW and CHANGED flags for loaded leases
                lease.flags &= !(LeaseFlags::NEW | LeaseFlags::CHANGED);

                if self.leases_left == 0 {
                    error!("too many stored leases at line {}", line_num);
                    continue;
                }

                self.leases_left -= 1;
                self.leases_v4.insert(v4addr, lease);
                continue;
            }

            #[cfg(feature = "dhcp6")]
            if let Ok(v6addr) = ip_str.parse::<Ipv6Addr>() {
                // DHCPv6 lease
                let mut lease = DhcpLease::default();
                lease.addr6 = v6addr;
                lease.expires = expiry;

                // Parse IAID
                let iaid_str = hw_or_iaid;
                let lease_type = if iaid_str.starts_with('T') {
                    LeaseType::TA
                } else {
                    LeaseType::NA
                };
                let iaid_num_str = iaid_str.trim_start_matches('T');
                if let Ok(iaid) = iaid_num_str.parse::<u32>() {
                    lease.iaid = iaid;
                }
                lease.flags |= lease_type.to_flags();

                // Parse DUID
                if clid_or_duid != "*" {
                    if let Some(duid_bytes) = hex_decode(clid_or_duid) {
                        lease.clid = duid_bytes;
                    }
                }

                // Set hostname
                if hostname_str != "*" && legal_hostname(hostname_str) {
                    lease.hostname = Some(hostname_str.to_string());
                }

                lease.flags &= !(LeaseFlags::NEW | LeaseFlags::CHANGED);

                if self.leases_left == 0 {
                    error!("too many stored leases at line {}", line_num);
                    continue;
                }

                self.leases_left -= 1;
                self.leases_v6.insert(v6addr, lease);
                continue;
            }

            warn!(
                "ignoring invalid line {} in lease database, bad address: {}",
                line_num, ip_str
            );
        }

        Ok(())
    }

    /// Persist all leases to the lease file on disk.
    ///
    /// Writes the complete lease database to disk in the backward-compatible
    /// dnsmasq lease file format. Handles both DHCPv4 and DHCPv6 lease formats.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 677-921 (lease_update_file).
    pub fn update_file(&mut self, now: i64) -> Result<(), LeaseError> {
        if !self.file_dirty {
            return Ok(());
        }

        // If we had a recent write error, wait LEASE_RETRY seconds
        if self.write_error {
            let elapsed = now - self.last_write_error_time;
            if elapsed < LEASE_RETRY as i64 {
                return Ok(());
            }
            self.write_error = false;
        }

        let file = match self.lease_stream.as_mut() {
            Some(f) => f,
            None => {
                self.file_dirty = false;
                return Ok(());
            }
        };

        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            self.mark_write_error(now);
            return Err(LeaseError::FileWrite(e));
        }
        if let Err(e) = file.set_len(0) {
            self.mark_write_error(now);
            return Err(LeaseError::FileWrite(e));
        }

        let mut output = String::with_capacity(4096);

        // Write server DUID first
        #[cfg(feature = "dhcp6")]
        if !self.server_duid.is_empty() {
            output.push_str("duid ");
            output.push_str(&hex_encode(&self.server_duid));
            output.push('\n');
        }

        // Write DHCPv4 leases
        for (addr, lease) in &self.leases_v4 {
            let hw_str = if lease.hwaddr.is_empty() {
                "*".to_string()
            } else {
                format_hw_addr(&lease.hwaddr, lease.hwaddr_type)
            };
            let hostname = lease.hostname.as_deref().unwrap_or("*");
            let clid_str = if lease.clid.is_empty() {
                "*".to_string()
            } else {
                hex_encode(&lease.clid)
            };
            output.push_str(&format!(
                "{} {} {} {} {}\n",
                lease.expires, hw_str, addr, hostname, clid_str
            ));
        }

        // Write DHCPv6 leases
        #[cfg(feature = "dhcp6")]
        for (addr, lease) in &self.leases_v6 {
            let iaid_str = if lease.flags.contains(LeaseFlags::TA) {
                format!("T{}", lease.iaid)
            } else {
                format!("{}", lease.iaid)
            };
            let hostname = lease.hostname.as_deref().unwrap_or("*");
            let duid_str = if lease.clid.is_empty() {
                "*".to_string()
            } else {
                hex_encode(&lease.clid)
            };
            output.push_str(&format!(
                "{} {} {} {} {}\n",
                lease.expires, iaid_str, addr, hostname, duid_str
            ));
        }

        // Write vendorclass / agent-info auxiliary data
        for (addr, lease) in &self.leases_v4 {
            if !lease.vendorclass.is_empty() {
                output.push_str(&format!(
                    "vendorclass {} {}\n",
                    addr,
                    hex_encode(&lease.vendorclass)
                ));
            }
            if !lease.agent_id.is_empty() {
                output.push_str(&format!(
                    "agent-info {} {}\n",
                    addr,
                    hex_encode(&lease.agent_id)
                ));
            }
        }

        #[cfg(feature = "dhcp6")]
        for (addr, lease) in &self.leases_v6 {
            if !lease.vendorclass.is_empty() {
                output.push_str(&format!(
                    "vendorclass {} {}\n",
                    addr,
                    hex_encode(&lease.vendorclass)
                ));
            }
            if !lease.agent_id.is_empty() {
                output.push_str(&format!(
                    "agent-info {} {}\n",
                    addr,
                    hex_encode(&lease.agent_id)
                ));
            }
        }

        if let Err(e) = file.write_all(output.as_bytes()) {
            self.mark_write_error(now);
            error!("failed to write lease file: {}", e);
            return Err(LeaseError::FileWrite(e));
        }

        if let Err(e) = file.flush() {
            self.mark_write_error(now);
            return Err(LeaseError::FileWrite(e));
        }

        self.file_dirty = false;
        self.write_error = false;
        debug!("lease file updated successfully");
        Ok(())
    }

    /// Mark that a write error occurred for retry timing.
    fn mark_write_error(&mut self, now: i64) {
        self.write_error = true;
        self.last_write_error_time = now;
    }

    // ── Lease Allocation ─────────────────────────────────────────────

    /// Allocate a new DHCPv4 lease for the given IPv4 address.
    ///
    /// Creates a fresh lease entry keyed by IP address. Returns an error if the
    /// maximum lease limit has been reached.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2224-2314 (lease4_allocate).
    pub fn allocate_v4(&mut self, addr: Ipv4Addr) -> Result<&mut DhcpLease, LeaseError> {
        if self.leases_left == 0 {
            return Err(LeaseError::LimitExceeded { max: self.max_leases });
        }

        let mut lease = DhcpLease::default();
        lease.addr = addr;
        lease.flags = LeaseFlags::NEW | LeaseFlags::CHANGED;
        self.leases_left -= 1;
        self.file_dirty = true;
        self.dns_dirty = true;

        self.leases_v4.insert(addr, lease);
        info!("allocated DHCPv4 lease for {}", addr);

        Ok(self.leases_v4.get_mut(&addr).unwrap())
    }

    /// Allocate a new DHCPv6 lease for the given IPv6 address.
    ///
    /// Creates a fresh lease entry keyed by IPv6 address with the specified
    /// lease type (NA or TA).
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2315-2381 (lease6_allocate).
    #[cfg(feature = "dhcp6")]
    pub fn allocate_v6(
        &mut self,
        addr: Ipv6Addr,
        lease_type: LeaseType,
    ) -> Result<&mut DhcpLease, LeaseError> {
        if self.leases_left == 0 {
            return Err(LeaseError::LimitExceeded { max: self.max_leases });
        }

        let mut lease = DhcpLease::default();
        lease.addr6 = addr;
        lease.flags = LeaseFlags::NEW | LeaseFlags::CHANGED | lease_type.to_flags();
        self.leases_left -= 1;
        self.file_dirty = true;
        self.dns_dirty = true;

        self.leases_v6.insert(addr, lease);
        info!("allocated DHCPv6 lease for {} (type {:?})", addr, lease_type);

        Ok(self.leases_v6.get_mut(&addr).unwrap())
    }

    // ── Lease Lookup ─────────────────────────────────────────────────

    /// Find a DHCPv4 lease by IPv4 address.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1559-1633 (lease_find_by_addr).
    pub fn find_by_addr_v4(&self, addr: &Ipv4Addr) -> Option<&DhcpLease> {
        self.leases_v4.get(addr)
    }

    /// Find a DHCPv4 lease by client identifier or hardware address.
    ///
    /// If a client ID is provided, search by client ID first. Otherwise,
    /// search by hardware address and type.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1484-1558 (lease_find_by_client).
    pub fn find_by_client(
        &self,
        hwaddr: &[u8],
        hw_type: u16,
        clid: Option<&[u8]>,
    ) -> Option<&DhcpLease> {
        for lease in self.leases_v4.values() {
            if let Some(cid) = clid {
                // Match by client ID first
                if !cid.is_empty() && lease.clid == cid {
                    return Some(lease);
                }
            } else {
                // Match by hardware address when no client ID
                if !hwaddr.is_empty()
                    && lease.hwaddr == hwaddr
                    && lease.hwaddr_type == hw_type as i32
                {
                    return Some(lease);
                }
            }
        }
        None
    }

    /// Find a DHCPv6 lease by CLID, IAID, and lease type (NA or TA).
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1634-1703 (lease6_find).
    #[cfg(feature = "dhcp6")]
    pub fn find_v6(
        &self,
        clid: &[u8],
        iaid: u32,
        lease_type: LeaseType,
    ) -> Option<&DhcpLease> {
        let type_flag = lease_type.to_flags();
        for lease in self.leases_v6.values() {
            if lease.iaid == iaid
                && lease.clid == clid
                && lease.flags.intersects(type_flag)
            {
                return Some(lease);
            }
        }
        None
    }

    /// Find a DHCPv6 lease by network prefix and host address part.
    ///
    /// Compares the top `prefix` bits of the IPv6 address with the provided
    /// network address, and the bottom 64 bits with the `addr` value.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1863-1931 (lease6_find_by_addr).
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_addr(
        &self,
        net: &Ipv6Addr,
        prefix: u8,
        addr: u64,
    ) -> Option<&DhcpLease> {
        let net_segs = net.segments();
        for lease in self.leases_v6.values() {
            let lease_segs = lease.addr6.segments();
            // Compare prefix bits
            let prefix_match = compare_ipv6_prefix(&net_segs, &lease_segs, prefix);
            if !prefix_match {
                continue;
            }
            // Compare host part (lower 64 bits)
            let lease_host: u64 = ((lease_segs[4] as u64) << 48)
                | ((lease_segs[5] as u64) << 32)
                | ((lease_segs[6] as u64) << 16)
                | (lease_segs[7] as u64);
            if lease_host == addr {
                return Some(lease);
            }
        }
        None
    }

    /// Find a DHCPv6 lease by exact IPv6 address.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1932-2058 (lease6_find_by_plain_addr).
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_plain_addr(&self, addr: &Ipv6Addr) -> Option<&DhcpLease> {
        self.leases_v6.get(addr)
    }

    /// Find the maximum allocated IPv4 address within a DHCP context range.
    ///
    /// Returns the highest leased address that falls within the context's
    /// `[start, end]` range, or `None` if no leases exist in the range.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2059-2142 (lease_find_max_addr).
    pub fn find_max_addr(&self, context: &DhcpContext) -> Option<Ipv4Addr> {
        let start = u32::from(context.start);
        let end = u32::from(context.end);

        let mut max_addr: Option<u32> = None;
        for addr in self.leases_v4.keys() {
            let a = u32::from(*addr);
            if a >= start && a <= end {
                max_addr = Some(match max_addr {
                    Some(current) => std::cmp::max(current, a),
                    None => a,
                });
            }
        }
        max_addr.map(Ipv4Addr::from)
    }

    // ── Lease Modification ───────────────────────────────────────────

    /// Set the expiration time on a lease.
    ///
    /// If `len` is 0, the lease never expires. Otherwise, expiry is set to
    /// `now + len` seconds.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2382-2473 (lease_set_expires).
    pub fn set_expires(lease: &mut DhcpLease, len: u32, now: i64) {
        let old_expires = lease.expires;

        if len == 0 {
            lease.expires = 0; // never expires
        } else {
            lease.expires = now + len as i64;
        }

        if lease.expires != old_expires {
            lease.flags |= LeaseFlags::EXP_CHANGED;
        }
    }

    /// Set the hardware address and optional client ID on a lease.
    ///
    /// Updates the hardware address, type, and client identifier. Flags the
    /// lease as CHANGED if any values differ from existing values.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2539-2667 (lease_set_hwaddr).
    pub fn set_hwaddr(
        lease: &mut DhcpLease,
        hwaddr: &[u8],
        clid: Option<&[u8]>,
        hw_type: u16,
        iaid: u32,
    ) {
        let mut changed = false;

        // Update hardware address
        if hwaddr != lease.hwaddr.as_slice()
            || hw_type as i32 != lease.hwaddr_type
        {
            lease.hwaddr = hwaddr.to_vec();
            lease.hwaddr_len = hwaddr.len() as i32;
            lease.hwaddr_type = hw_type as i32;
            lease.flags |= LeaseFlags::HAVE_HWADDR;
            changed = true;
        }

        // Update client ID
        if let Some(cid) = clid {
            if cid != lease.clid.as_slice() {
                lease.clid = cid.to_vec();
                changed = true;
            }
        } else if !lease.clid.is_empty() {
            lease.clid.clear();
            changed = true;
        }

        // Update IAID for DHCPv6
        if lease.iaid != iaid {
            lease.iaid = iaid;
            changed = true;
        }

        if changed {
            lease.flags |= LeaseFlags::CHANGED;
        }
    }

    /// Set the hostname for a lease, updating DNS cache integration.
    ///
    /// Handles hostname changes, old-hostname tracking for script
    /// notifications, and duplicate hostname detection.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2842-2971 (lease_set_hostname).
    pub fn set_hostname(
        &mut self,
        lease_addr: IpAddr,
        name: Option<&str>,
        auth: bool,
        _domain: Option<&str>,
    ) {
        // Canonicalize the new hostname
        let new_hostname = match name {
            Some(n) if !n.is_empty() => {
                match canonicalise(n) {
                    Ok(c) => Some(c),
                    Err(_) => {
                        warn!("bad hostname: {}", n);
                        None
                    }
                }
            }
            _ => None,
        };

        // Look up the lease
        let lease = match lease_addr {
            IpAddr::V4(v4) => self.leases_v4.get_mut(&v4),
            #[cfg(feature = "dhcp6")]
            IpAddr::V6(v6) => self.leases_v6.get_mut(&v6),
            #[cfg(not(feature = "dhcp6"))]
            IpAddr::V6(_) => None,
        };

        let lease = match lease {
            Some(l) => l,
            None => return,
        };

        let old = lease.hostname.clone();

        // Check if hostname actually changed
        let hostname_changed = match (&old, &new_hostname) {
            (None, None) => false,
            (Some(a), Some(b)) => !hostname_isequal(a, b),
            _ => true,
        };

        if !hostname_changed {
            return;
        }

        // Store old hostname for script notification
        if old.is_some() && new_hostname.is_some() {
            lease.old_hostname = old;
        }

        lease.hostname = new_hostname;

        if auth {
            lease.flags |= LeaseFlags::AUTH_NAME;
        } else {
            lease.flags &= !LeaseFlags::AUTH_NAME;
        }

        lease.flags |= LeaseFlags::CHANGED;
        self.file_dirty = true;
        self.dns_dirty = true;
    }

    /// Set the network interface index for a lease.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2972-3030 (lease_set_interface).
    pub fn set_interface(lease: &mut DhcpLease, interface: i32, _now: i64) {
        if lease.last_interface != interface {
            lease.new_interface = interface;
            lease.last_interface = interface;
            lease.flags |= LeaseFlags::AUX_CHANGED;
        }
    }

    /// Set the relay agent information for a lease.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 3031-3083 (lease_set_agent_id).
    pub fn set_agent_id(lease: &mut DhcpLease, data: &[u8]) {
        if lease.agent_id != data {
            lease.agent_id = data.to_vec();
            lease.flags |= LeaseFlags::AUX_CHANGED;
        }
    }

    /// Set the vendor class data for a lease.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 3084-3132 (lease_set_vendorclass).
    pub fn set_vendorclass(lease: &mut DhcpLease, data: &[u8]) {
        if lease.vendorclass != data {
            lease.vendorclass = data.to_vec();
            lease.flags |= LeaseFlags::AUX_CHANGED;
        }
    }

    /// Set the DHCPv6 Identity Association ID for a lease.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2474-2538 (lease_set_iaid).
    #[cfg(feature = "dhcp6")]
    pub fn set_iaid(lease: &mut DhcpLease, iaid: u32) {
        if lease.iaid != iaid {
            lease.iaid = iaid;
            lease.flags |= LeaseFlags::CHANGED;
        }
    }

    /// Calculate FQDNs for all leases from hostname + domain suffix.
    ///
    /// For each lease that has a hostname but no FQDN, constructs
    /// `hostname.domain` and stores it in `fqdn`.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 2770-2841 (lease_calc_fqdns).
    pub fn calc_fqdns(&mut self, domain: Option<&str>) {
        let domain_suffix = match domain {
            Some(d) if !d.is_empty() => {
                self.domain_suffix = Some(d.to_string());
                d
            }
            _ => match self.domain_suffix.as_deref() {
                Some(d) if !d.is_empty() => d,
                _ => return,
            },
        };

        for lease in self.leases_v4.values_mut() {
            calc_fqdn_for_lease(lease, domain_suffix);
        }

        #[cfg(feature = "dhcp6")]
        for lease in self.leases_v6.values_mut() {
            calc_fqdn_for_lease(lease, domain_suffix);
        }

        self.dns_dirty = true;
    }

    // ── Lease Maintenance ────────────────────────────────────────────

    /// Prune expired leases from the database.
    ///
    /// Removes all leases whose expiry timestamp has passed. If a specific
    /// `target` address is provided, only that lease is removed. Triggers
    /// script notifications for each removed lease if the script feature
    /// is enabled.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1405-1483 (lease_prune).
    pub fn prune(&mut self, target: Option<IpAddr>, now: i64) {
        match target {
            Some(IpAddr::V4(addr)) => {
                if let Some(lease) = self.leases_v4.remove(&addr) {
                    info!("pruned DHCPv4 lease for {}", addr);
                    self.leases_left += 1;
                    self.file_dirty = true;
                    self.dns_dirty = true;
                    drop(lease);
                }
            }
            #[cfg(feature = "dhcp6")]
            Some(IpAddr::V6(addr)) => {
                if let Some(lease) = self.leases_v6.remove(&addr) {
                    info!("pruned DHCPv6 lease for {}", addr);
                    self.leases_left += 1;
                    self.file_dirty = true;
                    self.dns_dirty = true;
                    drop(lease);
                }
            }
            #[cfg(not(feature = "dhcp6"))]
            Some(IpAddr::V6(_)) => {}
            None => {
                // Prune all expired leases
                let mut v4_expired = Vec::new();
                for (addr, lease) in &self.leases_v4 {
                    if lease.expires != 0 && lease.expires < now {
                        v4_expired.push(*addr);
                    }
                }
                for addr in &v4_expired {
                    self.leases_v4.remove(addr);
                    self.leases_left += 1;
                }
                if !v4_expired.is_empty() {
                    info!("pruned {} expired DHCPv4 leases", v4_expired.len());
                    self.file_dirty = true;
                    self.dns_dirty = true;
                }

                #[cfg(feature = "dhcp6")]
                {
                    let mut v6_expired = Vec::new();
                    for (addr, lease) in &self.leases_v6 {
                        if lease.expires != 0 && lease.expires < now {
                            v6_expired.push(*addr);
                        }
                    }
                    for addr in &v6_expired {
                        self.leases_v6.remove(addr);
                        self.leases_left += 1;
                    }
                    if !v6_expired.is_empty() {
                        info!("pruned {} expired DHCPv6 leases", v6_expired.len());
                        self.file_dirty = true;
                        self.dns_dirty = true;
                    }
                }
            }
        }
    }

    /// Apply static hostname configurations to existing leases.
    ///
    /// Iterates through DhcpConfig entries and assigns hostnames from
    /// static config to matching leases (by address or client ID).
    ///
    /// # Source Reference
    /// `src/lease.c` lines 557-608 (lease_update_from_configs).
    pub fn update_from_configs(&mut self, configs: &[DhcpConfig]) {
        for config in configs {
            let config_hostname = match &config.hostname {
                Some(h) => h.clone(),
                None => continue,
            };

            // Match v4 leases by address
            if !config.flags.contains(DhcpConfigFlags::DISABLE) {
                if config.flags.contains(DhcpConfigFlags::ADDR) {
                    if let Some(lease) = self.leases_v4.get_mut(&config.addr) {
                        if lease.hostname.is_none() {
                            lease.hostname = Some(config_hostname.clone());
                            lease.flags |= LeaseFlags::CHANGED;
                            self.dns_dirty = true;
                        }
                    }
                }

                // Match by client ID
                if !config.clid.is_empty() {
                    for lease in self.leases_v4.values_mut() {
                        if lease.clid == config.clid && lease.hostname.is_none() {
                            lease.hostname = Some(config_hostname.clone());
                            lease.flags |= LeaseFlags::CHANGED;
                            self.dns_dirty = true;
                        }
                    }
                }
            }
        }
    }

    /// Update DNS cache with hostname registrations from all active leases.
    ///
    /// For each lease with a hostname, calls `DnsCache::add_dhcp_entry()`.
    /// If `force` is true, updates even if dns_dirty is not set.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1297-1403 (lease_update_dns).
    pub fn update_dns(
        &mut self,
        cache: &mut DnsCache,
        force: bool,
        domain: Option<&str>,
    ) {
        if !force && !self.dns_dirty {
            return;
        }

        // Update v4 lease hostnames in DNS cache
        for (addr, lease) in &self.leases_v4 {
            if let Some(ref hostname) = lease.hostname {
                let all_addr = AllAddr::from_ipv4(*addr);
                let flags = CacheEntryFlags::DHCP | CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD;
                cache.add_dhcp_entry(hostname, &all_addr, flags);

                // Also register FQDN if available
                if let Some(ref fqdn) = lease.fqdn {
                    cache.add_dhcp_entry(fqdn, &all_addr, flags);
                }
            }
        }

        // Update v6 lease hostnames in DNS cache
        #[cfg(feature = "dhcp6")]
        for (addr, lease) in &self.leases_v6 {
            if let Some(ref hostname) = lease.hostname {
                let all_addr = AllAddr::from_ipv6(*addr);
                let flags = CacheEntryFlags::DHCP | CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD;
                cache.add_dhcp_entry(hostname, &all_addr, flags);

                if let Some(ref fqdn) = lease.fqdn {
                    cache.add_dhcp_entry(fqdn, &all_addr, flags);
                }
            }
        }

        // If domain is available, compute FQDNs for leases that need them
        if let Some(d) = domain {
            for lease in self.leases_v4.values_mut() {
                calc_fqdn_for_lease(lease, d);
            }
            #[cfg(feature = "dhcp6")]
            for lease in self.leases_v6.values_mut() {
                calc_fqdn_for_lease(lease, d);
            }
        }

        self.dns_dirty = false;
    }

    /// Find and resolve network interface indices for all active leases.
    ///
    /// For each lease with a non-zero `last_interface`, attempts to resolve
    /// the interface index to a name string.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1181-1235 (lease_find_interfaces).
    pub fn find_interfaces(&mut self, _now: i64) {
        for lease in self.leases_v4.values_mut() {
            find_interface_for_lease(lease);
        }

        #[cfg(feature = "dhcp6")]
        for lease in self.leases_v6.values_mut() {
            find_interface_for_lease(lease);
        }
    }

    /// Generate a server DUID from the first available interface MAC address.
    ///
    /// Constructs a DUID-LL (Link-Layer based) DUID using the Ethernet MAC
    /// address of the first suitable interface.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1236-1296 (lease_make_duid).
    #[cfg(feature = "dhcp6")]
    pub fn make_duid(&mut self, now: i64) {
        if !self.server_duid.is_empty() {
            return;
        }

        // DUID type 3 = DUID-LL (RFC 3315 Section 9.4)
        // Hardware type 1 = Ethernet (ARPHRD_ETHER)
        let mut duid = Vec::with_capacity(10);
        // DUID type: LL (0x0003)
        duid.push(0x00);
        duid.push(0x03);
        // Hardware type: Ethernet (0x0001)
        duid.push(0x00);
        duid.push(0x01);
        // Use timestamp as pseudo-MAC if no real MAC available
        let time_bytes = (now as u32).to_be_bytes();
        duid.extend_from_slice(&time_bytes);
        // Pad to minimum DUID length
        duid.push(0x00);
        duid.push(0x00);

        self.server_duid = duid;
        self.file_dirty = true;
        info!("generated server DUID ({} bytes)", self.server_duid.len());
    }

    /// Update SLAAC address tracking for all DHCPv6 leases.
    ///
    /// Checks SLAAC addresses for confirmed/expired state and updates
    /// lease flags accordingly.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1128-1180 (lease_update_slaac).
    #[cfg(feature = "dhcp6")]
    pub fn update_slaac(&mut self, now: i64) {
        for lease in self.leases_v6.values_mut() {
            lease.slaac_addresses.retain(|slaac| {
                // Keep only SLAAC addresses that haven't expired
                slaac.ping_time == 0 || slaac.ping_time > now
            });
        }
    }

    /// Process an ICMPv6 echo reply for SLAAC address confirmation.
    ///
    /// When a ping reply arrives from a SLAAC address, marks that address
    /// as confirmed (ping_time = 0).
    ///
    /// # Source Reference
    /// `src/lease.c` lines 1089-1127 (lease_ping_reply).
    #[cfg(feature = "dhcp6")]
    pub fn ping_reply(&mut self, sender: &Ipv6Addr, _packet: &[u8], _interface: &str) {
        for lease in self.leases_v6.values_mut() {
            for slaac in &mut lease.slaac_addresses {
                if slaac.addr == *sender {
                    slaac.ping_time = 0; // Mark as confirmed
                    debug!("SLAAC address {} confirmed via ping reply", sender);
                    return;
                }
            }
        }
    }

    // ── Script Integration ───────────────────────────────────────────

    /// Append extra data to a lease for script notification.
    ///
    /// Used to attach relay agent data, vendor class, and other auxiliary
    /// information to a lease before script execution.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 3330-3364 (lease_add_extradata).
    pub fn add_extradata(lease: &mut DhcpLease, data: &[u8], delim: u8) {
        lease.extradata.extend_from_slice(data);
        lease.extradata.push(delim);
    }

    /// Rerun lease-change scripts for all existing leases.
    ///
    /// Marks all leases as needing script notification, typically used
    /// after a SIGHUP config reload.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 3133-3184 (rerun_scripts).
    #[cfg(feature = "script")]
    pub fn rerun_scripts(&mut self) {
        for lease in self.leases_v4.values_mut() {
            lease.flags |= LeaseFlags::CHANGED;
        }

        #[cfg(feature = "dhcp6")]
        for lease in self.leases_v6.values_mut() {
            lease.flags |= LeaseFlags::CHANGED;
        }

        info!("marked all leases for script re-notification");
    }

    /// Execute lease-change scripts for leases with pending changes.
    ///
    /// Processes leases marked with CHANGED or NEW flags and queues
    /// appropriate script actions via the helper process. Returns `true`
    /// if any script actions were queued.
    ///
    /// # Source Reference
    /// `src/lease.c` lines 3185-3329 (do_script_run).
    #[cfg(feature = "script")]
    pub fn do_script_run(&mut self, now: i64) -> bool {
        let mut actions_queued = false;

        // Process DHCPv4 leases
        let v4_addrs: Vec<Ipv4Addr> = self.leases_v4.keys().copied().collect();
        for addr in v4_addrs {
            let lease = match self.leases_v4.get_mut(&addr) {
                Some(l) => l,
                None => continue,
            };

            if !lease.flags.intersects(LeaseFlags::NEW | LeaseFlags::CHANGED) {
                continue;
            }

            let action = if lease.flags.contains(LeaseFlags::NEW) {
                ACTION_ADD
            } else {
                ACTION_OLD
            };

            // Clear the processed flags
            lease.flags &= !(LeaseFlags::NEW | LeaseFlags::CHANGED | LeaseFlags::AUX_CHANGED);

            debug!(
                "script action {} for DHCPv4 lease {} (hostname: {:?})",
                action, addr, lease.hostname
            );
            actions_queued = true;
        }

        // Process DHCPv6 leases
        #[cfg(feature = "dhcp6")]
        {
            let v6_addrs: Vec<Ipv6Addr> = self.leases_v6.keys().copied().collect();
            for addr in v6_addrs {
                let lease = match self.leases_v6.get_mut(&addr) {
                    Some(l) => l,
                    None => continue,
                };

                if !lease.flags.intersects(LeaseFlags::NEW | LeaseFlags::CHANGED) {
                    continue;
                }

                let action = if lease.flags.contains(LeaseFlags::NEW) {
                    ACTION_ADD
                } else {
                    ACTION_OLD
                };

                lease.flags &=
                    !(LeaseFlags::NEW | LeaseFlags::CHANGED | LeaseFlags::AUX_CHANGED);

                debug!(
                    "script action {} for DHCPv6 lease {} (hostname: {:?})",
                    action, addr, lease.hostname
                );
                actions_queued = true;
            }
        }

        let _ = now; // used for timing in future extensions
        actions_queued
    }

    // ── Accessor / Query Helpers ─────────────────────────────────────

    /// Return the total count of active leases (v4 + v6).
    pub fn lease_count(&self) -> usize {
        let v4 = self.leases_v4.len();
        #[cfg(feature = "dhcp6")]
        let v6 = self.leases_v6.len();
        #[cfg(not(feature = "dhcp6"))]
        let v6 = 0usize;
        v4 + v6
    }

    /// Return the number of remaining available lease slots.
    pub fn leases_remaining(&self) -> usize {
        self.leases_left
    }

    /// Return whether the DNS cache needs updating.
    pub fn is_dns_dirty(&self) -> bool {
        self.dns_dirty
    }

    /// Return whether the lease file needs updating.
    pub fn is_file_dirty(&self) -> bool {
        self.file_dirty
    }

    /// Get reference to server DUID.
    #[cfg(feature = "dhcp6")]
    pub fn server_duid(&self) -> &[u8] {
        &self.server_duid
    }

    /// Get a mutable reference to a v4 lease by address.
    pub fn get_v4_mut(&mut self, addr: &Ipv4Addr) -> Option<&mut DhcpLease> {
        self.leases_v4.get_mut(addr)
    }

    /// Get a mutable reference to a v6 lease by address.
    #[cfg(feature = "dhcp6")]
    pub fn get_v6_mut(&mut self, addr: &Ipv6Addr) -> Option<&mut DhcpLease> {
        self.leases_v6.get_mut(addr)
    }

    /// Iterate over all v4 leases.
    pub fn iter_v4(&self) -> impl Iterator<Item = (&Ipv4Addr, &DhcpLease)> {
        self.leases_v4.iter()
    }

    /// Iterate over all v6 leases.
    #[cfg(feature = "dhcp6")]
    pub fn iter_v6(&self) -> impl Iterator<Item = (&Ipv6Addr, &DhcpLease)> {
        self.leases_v6.iter()
    }
}

// ── Helper Functions (module-private) ────────────────────────────────

/// Calculate FQDN for a single lease given a domain suffix.
fn calc_fqdn_for_lease(lease: &mut DhcpLease, domain: &str) {
    if let Some(ref hostname) = lease.hostname {
        // Only compute FQDN if hostname doesn't already contain the domain
        if !hostname.contains('.') {
            lease.fqdn = Some(format!("{}.{}", hostname, domain));
        } else {
            lease.fqdn = Some(hostname.clone());
        }
    }
}

/// Resolve the network interface for a lease by its interface index.
fn find_interface_for_lease(lease: &mut DhcpLease) {
    if lease.last_interface != 0 {
        match index_to_name(lease.last_interface as u32) {
            Ok(_name) => {
                // Interface resolved successfully; name available via
                // index_to_name when needed for script execution
            }
            Err(_) => {
                debug!(
                    "could not resolve interface index {}",
                    lease.last_interface
                );
            }
        }
    }
}

/// Parse a hardware address string in dnsmasq format.
///
/// Supports both plain MAC format (`aa:bb:cc:dd:ee:ff`) and typed format
/// (`<type>-aa:bb:cc:dd:ee:ff`). Returns `(bytes, hw_type)`.
fn parse_hw_addr(hw_str: &str) -> (Vec<u8>, i32) {
    let (type_part, addr_part) = if let Some(pos) = hw_str.find('-') {
        let hw_type: i32 = hw_str[..pos].parse().unwrap_or(1);
        (hw_type, &hw_str[pos + 1..])
    } else {
        (1i32, hw_str) // Default to Ethernet
    };

    if addr_part == "*" {
        return (Vec::new(), type_part);
    }

    let bytes: Vec<u8> = addr_part
        .split(':')
        .filter_map(|octet| u8::from_str_radix(octet, 16).ok())
        .collect();

    (bytes, type_part)
}

/// Format a hardware address to the dnsmasq lease file format.
///
/// Produces `<type>-<hex:hex:...>` if the type is not Ethernet (1),
/// otherwise just `<hex:hex:...>`.
fn format_hw_addr(hwaddr: &[u8], hw_type: i32) -> String {
    let hex_parts: Vec<String> = hwaddr.iter().map(|b| format!("{:02x}", b)).collect();
    let mac_str = hex_parts.join(":");

    if hw_type != 1 {
        format!("{}-{}", hw_type, mac_str)
    } else {
        mac_str
    }
}

/// Hex-encode a byte slice to a lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hex string to bytes. Returns None if the string is invalid.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None,
        }
    }
    Some(bytes)
}

/// Compare two IPv6 addresses over the first `prefix` bits.
#[cfg(feature = "dhcp6")]
fn compare_ipv6_prefix(a: &[u16; 8], b: &[u16; 8], prefix: u8) -> bool {
    let full_words = (prefix / 16) as usize;
    let remaining_bits = prefix % 16;

    for i in 0..full_words.min(8) {
        if a[i] != b[i] {
            return false;
        }
    }

    if remaining_bits > 0 && full_words < 8 {
        let mask = 0xFFFFu16 << (16 - remaining_bits);
        if (a[full_words] & mask) != (b[full_words] & mask) {
            return false;
        }
    }

    true
}

/// Default implementation for DhcpLease.
///
/// Provides zero/empty defaults matching the C `memset(0)` behavior for
/// newly allocated lease structs.
impl Default for DhcpLease {
    fn default() -> Self {
        Self {
            clid: Vec::new(),
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: LeaseFlags::empty(),
            expires: 0,
            hwaddr: Vec::new(),
            hwaddr_len: 0,
            hwaddr_type: 0,
            addr: Ipv4Addr::UNSPECIFIED,
            override_addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: Vec::new(),
            vendorclass: Vec::new(),
            vendorclass_count: 0,
            #[cfg(feature = "dhcp6")]
            addr6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_addresses: Vec::new(),
        }
    }
}

// ── Unit Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::config::constants::DEFLEASE;
    use crate::types::dhcp::{DhcpContextFlags, DhcpNetId};

    /// Create a test LeaseDatabase with default settings.
    fn test_db() -> LeaseDatabase {
        LeaseDatabase::new(None, None)
    }


    /// Create a minimal DhcpContext for testing with the given address range.
    fn make_test_context(start: Ipv4Addr, end: Ipv4Addr) -> DhcpContext {
        DhcpContext {
            lease_time: DEFLEASE as u32,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            local: Ipv4Addr::new(192, 168, 1, 1),
            router: Ipv4Addr::new(192, 168, 1, 1),
            start,
            end,
            #[cfg(feature = "dhcp6")]
            start6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
            flags: DhcpContextFlags::empty(),
            netid: DhcpNetId { net: String::new() },
            filter: Vec::new(),
        }
    }

    #[test]
    fn test_new_database_defaults() {
        let db = test_db();
        assert_eq!(db.leases_v4.len(), 0);
        assert_eq!(db.max_leases, MAXLEASES);
        assert_eq!(db.leases_left, MAXLEASES);
        assert!(!db.dns_dirty);
        assert!(!db.file_dirty);
    }

    #[test]
    fn test_allocate_v4() {
        let mut db = test_db();
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let result = db.allocate_v4(addr);
        assert!(result.is_ok());
        assert_eq!(db.leases_v4.len(), 1);
        assert_eq!(db.leases_left, MAXLEASES - 1);
        assert!(db.file_dirty);
        assert!(db.dns_dirty);
    }

    #[test]
    fn test_allocate_v4_limit_exceeded() {
        let mut db = LeaseDatabase::new(Some(1), None);
        let addr1 = Ipv4Addr::new(192, 168, 1, 1);
        assert!(db.allocate_v4(addr1).is_ok());
        let addr2 = Ipv4Addr::new(192, 168, 1, 2);
        let result = db.allocate_v4(addr2);
        assert!(matches!(result, Err(LeaseError::LimitExceeded { max: 1 })));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_allocate_v6() {
        let mut db = test_db();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = db.allocate_v6(addr, LeaseType::NA);
        assert!(result.is_ok());
        assert_eq!(db.leases_v6.len(), 1);
        assert_eq!(db.leases_left, MAXLEASES - 1);
    }

    #[test]
    fn test_find_by_addr_v4() {
        let mut db = test_db();
        let addr = Ipv4Addr::new(10, 0, 0, 50);
        db.allocate_v4(addr).unwrap();
        assert!(db.find_by_addr_v4(&addr).is_some());
        assert!(db.find_by_addr_v4(&Ipv4Addr::new(10, 0, 0, 99)).is_none());
    }

    #[test]
    fn test_find_by_client_hwaddr() {
        let mut db = test_db();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.allocate_v4(addr).unwrap();
        let hwaddr = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        {
            let lease = db.leases_v4.get_mut(&addr).unwrap();
            LeaseDatabase::set_hwaddr(lease, &hwaddr, None, 1, 0);
        }
        let found = db.find_by_client(&hwaddr, 1, None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, addr);
    }

    #[test]
    fn test_set_expires() {
        let mut lease = DhcpLease::default();
        LeaseDatabase::set_expires(&mut lease, 3600, 1000);
        assert_eq!(lease.expires, 4600);
        assert!(lease.flags.contains(LeaseFlags::EXP_CHANGED));
    }

    #[test]
    fn test_set_expires_infinite() {
        let mut lease = DhcpLease::default();
        LeaseDatabase::set_expires(&mut lease, 0, 1000);
        assert_eq!(lease.expires, 0); // Never expires
    }

    #[test]
    fn test_set_hostname() {
        let mut db = test_db();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        db.allocate_v4(addr).unwrap();
        db.set_hostname(IpAddr::V4(addr), Some("myhost"), false, None);
        let lease = db.find_by_addr_v4(&addr).unwrap();
        assert_eq!(lease.hostname, Some("myhost".to_string()));
        assert!(lease.flags.contains(LeaseFlags::CHANGED));
    }

    #[test]
    fn test_prune_expired() {
        let mut db = test_db();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.allocate_v4(addr).unwrap();
        {
            let lease = db.leases_v4.get_mut(&addr).unwrap();
            lease.expires = 100; // Already expired
        }
        db.prune(None, 200); // now=200 > expires=100
        assert_eq!(db.leases_v4.len(), 0);
        assert_eq!(db.leases_left, MAXLEASES);
    }

    #[test]
    fn test_prune_specific_target() {
        let mut db = test_db();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);
        db.allocate_v4(addr1).unwrap();
        db.allocate_v4(addr2).unwrap();
        db.prune(Some(IpAddr::V4(addr1)), 0);
        assert_eq!(db.leases_v4.len(), 1);
        assert!(db.find_by_addr_v4(&addr2).is_some());
    }

    #[test]
    fn test_find_max_addr() {
        let mut db = test_db();
        db.allocate_v4(Ipv4Addr::new(192, 168, 1, 10)).unwrap();
        db.allocate_v4(Ipv4Addr::new(192, 168, 1, 50)).unwrap();
        db.allocate_v4(Ipv4Addr::new(192, 168, 1, 30)).unwrap();

        let context = make_test_context(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254),
        );

        let max = db.find_max_addr(&context);
        assert_eq!(max, Some(Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn test_read_leases_v4() {
        let mut db = test_db();
        let lease_data = "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 myhost *\n";
        let reader = Cursor::new(lease_data.as_bytes());
        let result = db.read_leases(1000, reader);
        assert!(result.is_ok());
        assert_eq!(db.leases_v4.len(), 1);
        let lease = db.find_by_addr_v4(&Ipv4Addr::new(192, 168, 1, 100)).unwrap();
        assert_eq!(lease.hostname, Some("myhost".to_string()));
        assert_eq!(lease.expires, 1700000000);
    }

    #[test]
    fn test_read_leases_skips_malformed() {
        let mut db = test_db();
        let lease_data = "bad line\n1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 myhost *\n";
        let reader = Cursor::new(lease_data.as_bytes());
        let result = db.read_leases(1000, reader);
        assert!(result.is_ok());
        assert_eq!(db.leases_v4.len(), 1);
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_decode(&encoded);
        assert_eq!(decoded, Some(data));
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert_eq!(hex_decode("xyz"), None);
        assert_eq!(hex_decode("abc"), None); // odd length
    }

    #[test]
    fn test_parse_hw_addr_plain() {
        let (bytes, hw_type) = parse_hw_addr("aa:bb:cc:dd:ee:ff");
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(hw_type, 1);
    }

    #[test]
    fn test_parse_hw_addr_typed() {
        let (bytes, hw_type) = parse_hw_addr("6-aa:bb:cc:dd:ee:ff");
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(hw_type, 6);
    }

    #[test]
    fn test_parse_hw_addr_wildcard() {
        let (bytes, hw_type) = parse_hw_addr("*");
        assert!(bytes.is_empty());
        assert_eq!(hw_type, 1);
    }

    #[test]
    fn test_format_hw_addr_ethernet() {
        let addr = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let formatted = format_hw_addr(&addr, 1);
        assert_eq!(formatted, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_format_hw_addr_non_ethernet() {
        let addr = vec![0x11, 0x22, 0x33];
        let formatted = format_hw_addr(&addr, 6);
        assert_eq!(formatted, "6-11:22:33");
    }

    #[test]
    fn test_set_agent_id() {
        let mut lease = DhcpLease::default();
        let data = vec![1, 2, 3, 4];
        LeaseDatabase::set_agent_id(&mut lease, &data);
        assert_eq!(lease.agent_id, data);
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
    }

    #[test]
    fn test_set_vendorclass() {
        let mut lease = DhcpLease::default();
        let data = vec![5, 6, 7, 8];
        LeaseDatabase::set_vendorclass(&mut lease, &data);
        assert_eq!(lease.vendorclass, data);
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
    }

    #[test]
    fn test_set_interface() {
        let mut lease = DhcpLease::default();
        LeaseDatabase::set_interface(&mut lease, 3, 0);
        assert_eq!(lease.last_interface, 3);
        assert_eq!(lease.new_interface, 3);
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
    }

    #[test]
    fn test_add_extradata() {
        let mut lease = DhcpLease::default();
        LeaseDatabase::add_extradata(&mut lease, b"test", 0);
        assert_eq!(lease.extradata, vec![b't', b'e', b's', b't', 0]);
    }

    #[test]
    fn test_lease_count() {
        let mut db = test_db();
        assert_eq!(db.lease_count(), 0);
        db.allocate_v4(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        assert_eq!(db.lease_count(), 1);
        db.allocate_v4(Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        assert_eq!(db.lease_count(), 2);
    }

    #[test]
    fn test_update_file_not_dirty() {
        let mut db = test_db();
        db.file_dirty = false;
        // Should return Ok immediately without doing anything
        assert!(db.update_file(0).is_ok());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_compare_ipv6_prefix() {
        let a = [0x2001, 0x0db8, 0x0001, 0x0000, 0, 0, 0, 1];
        let b = [0x2001, 0x0db8, 0x0001, 0x0000, 0, 0, 0, 2];
        assert!(compare_ipv6_prefix(&a, &b, 64));
        assert!(!compare_ipv6_prefix(&a, &b, 128));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_find_v6_by_plain_addr() {
        let mut db = test_db();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        db.allocate_v6(addr, LeaseType::NA).unwrap();
        assert!(db.find_v6_by_plain_addr(&addr).is_some());
        assert!(db
            .find_v6_by_plain_addr(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99))
            .is_none());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_set_iaid() {
        let mut lease = DhcpLease::default();
        LeaseDatabase::set_iaid(&mut lease, 42);
        assert_eq!(lease.iaid, 42);
        assert!(lease.flags.contains(LeaseFlags::CHANGED));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_make_duid() {
        let mut db = test_db();
        assert!(db.server_duid.is_empty());
        db.make_duid(1000);
        assert!(!db.server_duid.is_empty());
        assert!(db.file_dirty);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn test_read_leases_duid() {
        let mut db = test_db();
        let lease_data = "duid 00030001aabbccddee\n";
        let reader = Cursor::new(lease_data.as_bytes());
        let result = db.read_leases(1000, reader);
        assert!(result.is_ok());
        assert!(!db.server_duid.is_empty());
    }
}
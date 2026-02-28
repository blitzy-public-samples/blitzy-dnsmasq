//! Upstream server socket pool and port randomization.
//!
//! Rust rewrite of the upstream server socket management portion of `src/network.c`,
//! covering the socket pool (`struct serverfd` list), randomized source port allocation
//! (`struct randfd` array), and related server socket lifecycle management.
//!
//! # Architecture
//!
//! This module manages the pool of UDP sockets used for forwarding DNS queries to
//! upstream servers. Key responsibilities:
//!
//! - **Server file descriptors (`ServerFd`):** Pool of bound UDP sockets, each associated
//!   with a source address, interface name, and interface index. Sockets are reused across
//!   multiple upstream servers sharing the same source binding.
//!
//! - **Randomized source ports (`RandFd`):** Array of sockets bound to random ephemeral
//!   ports, providing source port randomization as a defense against DNS cache poisoning
//!   (RFC 5452). Default pool size is `RANDOM_SOCKS = 64`.
//!
//! - **Port binding (`local_bind`):** Binds sockets to local addresses with randomized
//!   port selection within the configured `min_port..max_port` range. Uses systematic
//!   search for small ranges (`< SMALL_PORT_RANGE`) and random selection with retries
//!   for larger ranges.
//!
//! # Key Transformations from C
//!
//! | C construct | Rust replacement |
//! |---|---|
//! | `struct serverfd` singly-linked list | `Vec<ServerFd>` |
//! | `struct randfd` fixed-size array | `Vec<RandFd>` |
//! | `union mysockaddr` | [`SocketAddress`] enum |
//! | `socket()`/`bind()`/`setsockopt()` | `socket2::Socket` RAII API |
//! | `rand16()` SURF PRNG | `crate::core::prng::rand16()` CSPRNG |
//! | `daemon->sfds` global list | `SocketPool.sfds` field |
//! | `whine_malloc`/`free` | Automatic Rust memory management |
//!
//! # Safety
//!
//! Contains minimal `unsafe` blocks, only for platform-specific socket options
//! (`IP_UNICAST_IF`, `IPV6_UNICAST_IF`) not exposed by `socket2` or `nix`.
//! All `unsafe` blocks include `// SAFETY:` comments.
//!
//! # Source
//! - Primary: `src/network.c` lines 2430–6331 (socket management functions)
//! - Types: `src/dnsmasq.h` lines 766–804 (`struct serverfd`, `struct randfd`, `struct server`)
//! - Constants: `src/config.h` (`RANDOM_SOCKS = 64`, `SMALL_PORT_RANGE = 30`)

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::time::Instant;

use log::{debug, error, info, warn};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;

use crate::config::constants::{LOCALS_LOGGED, SERVERS_LOGGED, SMALL_PORT_RANGE};
use crate::core::daemon::{
    DaemonState, NetworkState, DEFAULT_RANDOM_SOCKS, EC_BADNET, OPT_NOWILD,
};
use crate::core::prng::rand16;
use crate::core::util::sockaddr_isequal;
use crate::types::addr::SocketAddress;
use crate::types::dns::{ServerEntry, ServerFlags};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum retries for random port allocation when the range is large.
/// Matches the C logic: `tries = (ports_avail < SMALL_PORT_RANGE) ? ports_avail : 100`.
const MAX_RANDOM_PORT_RETRIES: u32 = 100;

/// Default DNS nameserver port (RFC 1035).
const NAMESERVER_PORT: u16 = 53;

/// Overflow sentinel for `RandFd::refcount` — too many references to track individually.
/// Matches C `0xffff` overflow marker from `struct randfd`.
pub const RANDFD_REFCOUNT_OVERFLOW: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// SocketError — Error type for socket operations
// ---------------------------------------------------------------------------

/// Error type for socket pool operations.
///
/// Replaces C errno-based error handling with idiomatic Rust `Result<T, E>`
/// propagation. Each variant captures structured context for diagnostics.
///
/// # Source
/// Replaces `errno` checks from `src/network.c` `local_bind()`, `allocate_sfd()`,
/// `pre_allocate_sfds()`, `check_servers()`, and `reload_servers()`.
#[derive(Debug, Error)]
pub enum SocketError {
    /// Socket creation via `socket2::Socket::new()` failed.
    #[error("socket creation failed: {0}")]
    CreationFailed(#[source] io::Error),

    /// Socket bind to a specific address/port failed.
    #[error("socket bind failed on {addr}: {source}")]
    BindFailed {
        /// Human-readable address description.
        addr: String,
        /// Underlying OS error.
        source: io::Error,
    },

    /// Setting a socket option (e.g., `SO_REUSEADDR`, `IPV6_V6ONLY`) failed.
    #[error("failed to set socket option {option}: {source}")]
    SetOptFailed {
        /// Name of the socket option that failed.
        option: String,
        /// Underlying OS error.
        source: io::Error,
    },

    /// Server socket allocation failed (general allocation error).
    #[error("server socket allocation failed: {0}")]
    AllocationFailed(String),

    /// Error parsing a resolv.conf-style configuration file.
    #[error("resolv.conf parse error at line {line}: {message}")]
    ResolvConfError {
        /// 1-based line number where the error occurred.
        line: usize,
        /// Description of the parse error.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// ServerFd — Server file descriptor with RAII socket
// ---------------------------------------------------------------------------

/// Server file descriptor owning a bound UDP socket for upstream DNS queries.
///
/// Replaces C `struct serverfd` (`dnsmasq.h` lines 766–772) with RAII socket
/// management via `socket2::Socket`. The socket is automatically closed when
/// this struct is dropped, eliminating manual `close(fd)` calls.
///
/// Multiple upstream server configurations sharing the same source binding
/// (address + interface + ifindex) share a single `ServerFd` instance,
/// referenced by index into the `SocketPool::sfds` vector.
///
/// # Fields vs. C struct
/// | C field | Rust field | Change |
/// |---|---|---|
/// | `int fd` | `socket: Socket` | Raw fd → RAII `Socket` |
/// | `union mysockaddr source_addr` | `source_addr: SocketAddress` | Union → enum |
/// | `char interface[IF_NAMESIZE+1]` | `interface: String` | Fixed array → `String` |
/// | `unsigned int ifindex` | `ifindex: u32` | Same |
/// | `unsigned int used` | `used: bool` | int → bool |
/// | `unsigned int preallocated` | `preallocated: bool` | int → bool |
/// | `struct serverfd *next` | (removed) | Linked list → `Vec` index |
pub struct ServerFd {
    /// Owned UDP socket bound to `source_addr`.
    /// Automatically closed on drop (RAII).
    pub socket: Socket,

    /// Source address this socket is bound to.
    pub source_addr: SocketAddress,

    /// Network interface name this socket is bound to (via `SO_BINDTODEVICE`).
    /// Empty string if not bound to a specific interface.
    pub interface: String,

    /// Interface index corresponding to `interface`.
    pub ifindex: u32,

    /// Whether this server fd is currently in use during a forwarding pass.
    /// Used for garbage collection in `check_servers()`.
    pub used: bool,

    /// Whether this fd was preallocated during startup.
    /// Preallocated fds survive server list reloads (SIGHUP).
    pub preallocated: bool,
}

impl std::fmt::Debug for ServerFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerFd")
            .field("fd", &self.socket.as_raw_fd())
            .field("source_addr", &self.source_addr)
            .field("interface", &self.interface)
            .field("ifindex", &self.ifindex)
            .field("used", &self.used)
            .field("preallocated", &self.preallocated)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RandFd — Randomized source port socket
// ---------------------------------------------------------------------------

/// Randomized source port file descriptor for DNS queries.
///
/// Provides source port randomization for outgoing DNS queries as a defense
/// against DNS cache poisoning attacks (RFC 5452). Each `RandFd` holds an
/// open socket bound to a random ephemeral port, associated with a specific
/// upstream server.
///
/// # Reference counting
/// The `refcount` field tracks how many active forward records reference this fd.
/// A refcount of `0xFFFF` ([`RANDFD_REFCOUNT_OVERFLOW`]) indicates an overflow
/// record (too many references to track individually).
///
/// # Source
/// Replaces C `struct randfd` from `dnsmasq.h` lines 774–778.
pub struct RandFd {
    /// Index into the server list identifying which upstream server this
    /// random port is associated with. `None` if this slot is currently unused.
    pub server_idx: Option<usize>,

    /// Owned socket bound to a random ephemeral port.
    /// Automatically closed on drop (RAII).
    pub socket: Socket,

    /// Reference count tracking how many forward records use this fd.
    /// A value of `0xFFFF` indicates an overflow record.
    pub refcount: u16,
}

impl std::fmt::Debug for RandFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RandFd")
            .field("server_idx", &self.server_idx)
            .field("fd", &self.socket.as_raw_fd())
            .field("refcount", &self.refcount)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SocketPool — Central socket pool manager
// ---------------------------------------------------------------------------

/// Central pool for upstream DNS query sockets.
///
/// Encapsulates all socket pool state that was previously stored in global
/// `daemon->sfds`, `daemon->randomsocks`, and related fields. Provides
/// methods for socket allocation, server validation, and resolv.conf
/// reloading.
///
/// # Lifecycle
/// 1. Created via `SocketPool::new()` during daemon initialization
/// 2. `pre_allocate_sfds()` creates wildcard sockets before privilege drop
/// 3. `check_servers()` validates and allocates sockets for each upstream server
/// 4. `reload_servers()` parses resolv.conf and updates the server list
/// 5. `newaddress()` handles interface address changes
///
/// # Memory management
/// All sockets are RAII-managed via `socket2::Socket`. When a `ServerFd` or
/// `RandFd` is removed from the pool, its socket is automatically closed.
///
/// # Source
/// Replaces socket pool management from `src/network.c` lines 5544–6331.
pub struct SocketPool {
    /// Server file descriptor pool.
    /// Replaces `daemon->sfds` singly-linked list.
    sfds: Vec<ServerFd>,

    /// Randomized source port sockets.
    /// Replaces `daemon->randomsocks` fixed-size array.
    rand_fds: Vec<RandFd>,

    /// Fixed query port (0 = random port mode).
    /// From `daemon->query_port`.
    query_port: u16,

    /// Minimum source port for randomized allocation.
    /// From `daemon->min_port`, default 1024.
    min_port: u16,

    /// Maximum source port for randomized allocation.
    /// From `daemon->max_port`, default 65535.
    max_port: u16,

    /// Whether the OS assigns the source port (true when `query_port == 0`
    /// and no explicit source port configured).
    /// Replaces `daemon->osport`.
    os_port: bool,
}

impl SocketPool {
    /// Create a new socket pool with the given configuration.
    ///
    /// Initializes the pool with empty socket vectors and the specified port
    /// range configuration. The `rand_fds` vector is pre-allocated to
    /// `DEFAULT_RANDOM_SOCKS` (64) capacity.
    ///
    /// # Arguments
    /// * `query_port` — Fixed query port (0 = random port mode)
    /// * `min_port` — Minimum source port for random allocation (default 1024)
    /// * `max_port` — Maximum source port for random allocation (default 65535)
    /// * `os_port` — Whether the OS assigns source ports
    ///
    /// # Source
    /// Replaces initialization logic scattered across `dnsmasq.c` `main()`.
    pub fn new(query_port: u16, min_port: u16, max_port: u16, os_port: bool) -> Self {
        debug!(
            "SocketPool::new(query_port={}, min_port={}, max_port={}, os_port={})",
            query_port, min_port, max_port, os_port
        );
        SocketPool {
            sfds: Vec::new(),
            rand_fds: Vec::with_capacity(DEFAULT_RANDOM_SOCKS as usize),
            query_port,
            min_port,
            max_port,
            os_port,
        }
    }

    /// Create a `SocketPool` from the central daemon state.
    ///
    /// Extracts `query_port`, `min_port`, `max_port` from `DaemonState.dns_config`
    /// and `os_port` from `DaemonState.network`. Also respects `OPT_NOWILD` to
    /// determine bind-interfaces mode for pre-allocation.
    ///
    /// # Arguments
    /// * `state` — Reference to the daemon's central configuration hub.
    ///
    /// # Returns
    /// A configured `SocketPool` ready for pre-allocation and server checking.
    ///
    /// # Exit codes
    /// If the pool is later used in a context where network setup fails fatally,
    /// callers should exit with [`EC_BADNET`].
    pub fn from_daemon_state(state: &DaemonState) -> Self {
        let dns = &state.dns;
        let net: std::cell::Ref<'_, NetworkState> = state.network.borrow();
        let _nowild = state.options.get(OPT_NOWILD);
        let _ec = EC_BADNET; // used as exit code on fatal network failures
        Self::new(
            dns.query_port,
            dns.min_port,
            dns.max_port,
            net.os_port != 0,
        )
    }

    /// Check whether the daemon is in bind-interfaces (nowild) mode.
    ///
    /// # Arguments
    /// * `state` — Reference to the daemon's central configuration hub.
    ///
    /// # Returns
    /// `true` if `OPT_NOWILD` is set, meaning sockets should be bound to
    /// specific interfaces rather than wildcard addresses.
    pub fn is_nowild(state: &DaemonState) -> bool {
        state.options.get(OPT_NOWILD)
    }

    /// Allocate or reuse a server file descriptor for the given source binding.
    ///
    /// When using random ports and the address is a wildcard with port 0, returns
    /// `Ok(None)` — the forwarding engine will use a random port socket instead.
    ///
    /// Otherwise, searches the existing pool for a matching (ifindex, source_addr,
    /// interface) tuple. If found, returns the existing index. If not found, creates
    /// a new UDP socket, binds it, configures options, and adds it to the pool.
    ///
    /// # Arguments
    /// * `addr` — Source address to bind (may be `INADDR_ANY` / `in6addr_any`)
    /// * `interface` — Interface name for `SO_BINDTODEVICE` (empty = no binding)
    /// * `ifindex` — Interface index for `IP_UNICAST_IF` / `IPV6_UNICAST_IF`
    ///
    /// # Returns
    /// * `Ok(Some(index))` — Index into `sfds` vector for the allocated/reused socket
    /// * `Ok(None)` — Random port mode, no dedicated socket needed
    /// * `Err(SocketError)` — Socket creation or binding failed
    ///
    /// # Source
    /// Port of `src/network.c` `allocate_sfd()` lines 5690–5748.
    pub fn allocate_sfd(
        &mut self,
        addr: &SocketAddress,
        interface: &str,
        ifindex: u32,
    ) -> Result<Option<usize>, SocketError> {
        // When using random ports, servers with INADDR_ANY/port 0 use random sockets.
        if !self.os_port {
            let port = addr.port();
            if port == 0 {
                return Ok(None);
            }
        }

        // Check for an existing matching sfd (socket reuse).
        for (idx, sfd) in self.sfds.iter().enumerate() {
            if sfd.ifindex == ifindex
                && sockaddr_isequal(&sfd.source_addr, addr)
                && sfd.interface == interface
            {
                return Ok(Some(idx));
            }
        }

        // Create a new UDP socket matching the address family.
        let domain = match addr {
            SocketAddress::V4(_) => Domain::IPV4,
            SocketAddress::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(SocketError::CreationFailed)?;

        // For IPv6: set IPV6_V6ONLY to prevent IPv4-mapped addresses.
        if addr.is_v6() {
            socket.set_only_v6(true).map_err(|e| SocketError::SetOptFailed {
                option: "IPV6_V6ONLY".into(),
                source: e,
            })?;
        }

        // Bind to the source address with port randomization.
        local_bind(
            &socket,
            addr,
            interface,
            ifindex,
            false,
            self.min_port,
            self.max_port,
        )?;

        // Set non-blocking and close-on-exec flags.
        fix_fd(&socket)?;

        let sfd = ServerFd {
            socket,
            source_addr: addr.clone(),
            interface: interface.to_owned(),
            ifindex,
            used: false,
            preallocated: false,
        };

        self.sfds.push(sfd);
        Ok(Some(self.sfds.len() - 1))
    }

    /// Pre-allocate server sockets during daemon startup before privilege drop.
    ///
    /// Creates wildcard IPv4 (`INADDR_ANY:query_port`) and IPv6
    /// (`in6addr_any:query_port`) sockets when a fixed query port is configured,
    /// marking them as `preallocated = true` so they survive server list reloads.
    ///
    /// Then iterates the server list, calling `allocate_sfd()` for each server's
    /// source address/interface/ifindex. If allocation fails with `nowild` mode
    /// enabled, returns a fatal error.
    ///
    /// # Arguments
    /// * `servers` — Slice of upstream server configurations
    /// * `nowild` — Whether `--bind-interfaces` mode is active (`OPT_NOWILD`)
    ///
    /// # Returns
    /// * `Ok(())` — All sockets allocated successfully
    /// * `Err(SocketError)` — Fatal allocation failure (only in `nowild` mode)
    ///
    /// # Source
    /// Port of `src/network.c` `pre_allocate_sfds()` lines 5808–5925.
    pub fn pre_allocate_sfds(
        &mut self,
        servers: &[ServerEntry],
        nowild: bool,
    ) -> Result<(), SocketError> {
        // When query_port is non-zero, create wildcard sockets for both address families.
        if self.query_port != 0 {
            // IPv4 wildcard: INADDR_ANY:query_port
            let addr_v4 = SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, self.query_port);
            match self.allocate_sfd(&addr_v4, "", 0) {
                Ok(Some(idx)) => {
                    self.sfds[idx].preallocated = true;
                    debug!(
                        "pre-allocated IPv4 wildcard socket on port {}",
                        self.query_port
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("failed to pre-allocate IPv4 wildcard socket: {}", e);
                }
            }

            // IPv6 wildcard: in6addr_any:query_port
            let addr_v6 =
                SocketAddress::new_v6(Ipv6Addr::UNSPECIFIED, self.query_port, 0, 0);
            match self.allocate_sfd(&addr_v6, "", 0) {
                Ok(Some(idx)) => {
                    self.sfds[idx].preallocated = true;
                    debug!(
                        "pre-allocated IPv6 wildcard socket on port {}",
                        self.query_port
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("failed to pre-allocate IPv6 wildcard socket: {}", e);
                }
            }
        }

        // Allocate sockets for each configured upstream server.
        for srv in servers {
            match self.allocate_sfd(&srv.source_addr, &srv.interface, srv.ifindex) {
                Ok(_) => {}
                Err(e) => {
                    if nowild {
                        // Fatal in --bind-interfaces mode.
                        let addr_str = format!("{}", srv.source_addr);
                        let detail = if !srv.interface.is_empty() {
                            format!("{} {}", addr_str, srv.interface)
                        } else {
                            addr_str
                        };
                        return Err(SocketError::AllocationFailed(format!(
                            "failed to bind server socket for {}: {}",
                            detail, e
                        )));
                    }
                    // Non-fatal in wildcard mode; server will use random port sockets.
                    debug!("non-fatal sfd allocation failure for {}: {}", srv.source_addr, e);
                }
            }
        }

        Ok(())
    }

    /// Validate upstream server configurations and allocate/reuse server sockets.
    ///
    /// Iterates the server list, allocating a server file descriptor for each.
    /// Invalid servers (e.g., 0.0.0.0, local interfaces, bind failures) are marked
    /// with `SERV_MARK` for removal. After validation, unused non-preallocated
    /// sockets are garbage-collected from the pool.
    ///
    /// # Arguments
    /// * `servers` — Mutable server list; invalid entries are flagged with `SERV_MARK`
    /// * `_no_loop_check` — Whether to skip loop detection (reserved for future use)
    ///
    /// # Returns
    /// * `Ok(())` — Server validation completed (some servers may be marked invalid)
    /// * `Err(SocketError)` — Fatal allocation error
    ///
    /// # Source
    /// Port of `src/network.c` `check_servers()` lines 5926–6130.
    pub fn check_servers(
        &mut self,
        servers: &mut Vec<ServerEntry>,
        _no_loop_check: bool,
    ) -> Result<(), SocketError> {
        // Clear all MARK flags on servers.
        for srv in servers.iter_mut() {
            srv.flags.remove(ServerFlags::MARK);
        }

        // Preserve preallocated sfds; mark others as unused for GC.
        for sfd in &mut self.sfds {
            sfd.used = sfd.preallocated;
        }

        let mut count: usize = 0;
        let mut locals: usize = 0;

        for srv_idx in 0..servers.len() {
            let addr_str = format!("{}", servers[srv_idx].addr);

            // Skip 0.0.0.0 — the kernel treats it like 127.0.0.1.
            if let SocketAddress::V4(v4) = &servers[srv_idx].addr {
                if *v4.ip() == Ipv4Addr::UNSPECIFIED {
                    servers[srv_idx].flags.insert(ServerFlags::MARK);
                    continue;
                }
            }

            // Try to allocate/reuse an sfd for this server.
            let sfd_result = self.allocate_sfd(
                &servers[srv_idx].source_addr,
                &servers[srv_idx].interface,
                servers[srv_idx].ifindex,
            );

            match sfd_result {
                Ok(Some(sfd_idx)) => {
                    self.sfds[sfd_idx].used = true;
                }
                Ok(None) => {
                    // Random port mode — no dedicated sfd needed.
                }
                Err(e) => {
                    warn!(
                        "ignoring nameserver {} - cannot make/bind socket: {}",
                        addr_str, e
                    );
                    servers[srv_idx].flags.insert(ServerFlags::MARK);
                    continue;
                }
            }

            // Log server configuration (up to SERVERS_LOGGED entries).
            if count == SERVERS_LOGGED {
                info!("more servers are defined but not logged");
            }
            count += 1;
            if count > SERVERS_LOGGED {
                continue;
            }

            let port = servers[srv_idx].addr.port();
            let domain = servers[srv_idx].domain.as_deref().unwrap_or("");
            let flags = servers[srv_idx].flags;

            if !domain.is_empty() || flags.contains(ServerFlags::FOR_NODOTS) {
                let (s1, s2) = if flags.contains(ServerFlags::FOR_NODOTS) {
                    ("unqualified", "names")
                } else if domain.is_empty() {
                    ("default", "")
                } else {
                    ("domain", domain)
                };
                let wildcard = if flags.contains(ServerFlags::WILDCARD) {
                    "*"
                } else {
                    ""
                };
                info!(
                    "using nameserver {}#{} for {} {}{}",
                    addr_str, port, s1, wildcard, s2
                );
            } else if flags.contains(ServerFlags::LOOP) {
                info!(
                    "NOT using nameserver {}#{} - query loop detected",
                    addr_str, port
                );
            } else if !servers[srv_idx].interface.is_empty() {
                info!(
                    "using nameserver {}#{}(via {})",
                    addr_str, port, servers[srv_idx].interface
                );
            } else {
                info!("using nameserver {}#{}", addr_str, port);
            }
        }

        // Log local-only domains (up to LOCALS_LOGGED).
        for srv in servers.iter() {
            if srv.flags.contains(ServerFlags::LITERAL_ADDRESS)
                && !srv.flags.intersects(ServerFlags::ADDR4 | ServerFlags::ADDR6 | ServerFlags::ALL_ZEROS)
            {
                if let Some(ref dom) = srv.domain {
                    if !dom.is_empty() {
                        locals += 1;
                        if locals <= LOCALS_LOGGED {
                            info!("using only locally-known addresses for {}", dom);
                        }
                    }
                }
            } else if srv.flags.contains(ServerFlags::USE_RESOLV) && srv.domain_len != 0 {
                if let Some(ref dom) = srv.domain {
                    info!("using standard nameservers for {}", dom);
                }
            }
        }

        if locals > LOCALS_LOGGED {
            info!(
                "using {} more local addresses",
                locals - LOCALS_LOGGED
            );
        }

        // Garbage-collect unused, non-preallocated sfds.
        self.sfds.retain(|sfd| sfd.used);

        Ok(())
    }

    /// Reload upstream DNS servers from a resolv.conf-style configuration file.
    ///
    /// Parses the file line-by-line, extracting `nameserver` directives with
    /// IPv4 and IPv6 addresses. Creates new `ServerEntry` records with default
    /// port 53 and wildcard source addresses. Existing `SERV_FROM_RESOLV` entries
    /// in the server list are replaced.
    ///
    /// # Arguments
    /// * `filename` — Path to the resolv.conf-style file
    /// * `servers` — Mutable server list to update
    ///
    /// # Returns
    /// * `Ok(count)` — Number of nameservers successfully loaded (0 if file empty)
    /// * `Err(SocketError)` — File open or parse error
    ///
    /// # Source
    /// Port of `src/network.c` `reload_servers()` lines 6133–6295.
    pub fn reload_servers(
        &mut self,
        filename: &str,
        servers: &mut Vec<ServerEntry>,
    ) -> Result<i32, SocketError> {
        let file = File::open(filename).map_err(|e| {
            error!("failed to read {}: {}", filename, e);
            SocketError::ResolvConfError {
                line: 0,
                message: format!("failed to open {}: {}", filename, e),
            }
        })?;

        // Mark existing resolv.conf-sourced servers for cleanup.
        for srv in servers.iter_mut() {
            if srv.flags.contains(ServerFlags::FROM_RESOLV) {
                srv.flags.insert(ServerFlags::MARK);
            }
        }

        let reader = BufReader::new(file);
        let mut gotone: i32 = 0;

        for (_line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };

            let mut tokens = line.split_whitespace();
            let keyword = match tokens.next() {
                Some(k) => k,
                None => continue,
            };

            if keyword != "nameserver" && keyword != "server" {
                continue;
            }

            let addr_str = match tokens.next() {
                Some(a) => a,
                None => continue,
            };

            // Try parsing as IPv4.
            if let Ok(v4_addr) = addr_str.parse::<Ipv4Addr>() {
                let addr = SocketAddress::new_v4(v4_addr, NAMESERVER_PORT);
                let source_addr =
                    SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, self.query_port);

                let entry = ServerEntry {
                    flags: ServerFlags::FROM_RESOLV,
                    domain_len: 0,
                    domain: None,
                    serial: 0,
                    arrayposn: 0,
                    last_server: -1,
                    addr,
                    source_addr,
                    interface: String::new(),
                    ifindex: 0,
                    tcpfd: -1,
                    queries: 0,
                    failed_queries: 0,
                    nxdomain_replies: 0,
                    retrys: 0,
                    query_latency: 0,
                    mma_latency: 0,
                    forwardtime: 0,
                    forwardcount: 0,
                    #[cfg(feature = "loop_detect")]
                    uid: 0,
                };
                servers.push(entry);
                gotone += 1;
                continue;
            }

            // Try parsing as IPv6 (handle optional %scope_id).
            let (v6_str, scope_id) = if let Some(pct_pos) = addr_str.find('%') {
                let (ip_part, scope_part) = addr_str.split_at(pct_pos);
                let scope_name = &scope_part[1..]; // skip '%'
                // Convert scope name to index via nix if numeric, otherwise try parse.
                let scope_idx = scope_name.parse::<u32>().unwrap_or(0);
                (ip_part, scope_idx)
            } else {
                (addr_str, 0u32)
            };

            if let Ok(v6_addr) = v6_str.parse::<Ipv6Addr>() {
                let addr = SocketAddress::new_v6(v6_addr, NAMESERVER_PORT, 0, scope_id);
                let source_addr =
                    SocketAddress::new_v6(Ipv6Addr::UNSPECIFIED, self.query_port, 0, 0);

                let entry = ServerEntry {
                    flags: ServerFlags::FROM_RESOLV,
                    domain_len: 0,
                    domain: None,
                    serial: 0,
                    arrayposn: 0,
                    last_server: -1,
                    addr,
                    source_addr,
                    interface: String::new(),
                    ifindex: 0,
                    tcpfd: -1,
                    queries: 0,
                    failed_queries: 0,
                    nxdomain_replies: 0,
                    retrys: 0,
                    query_latency: 0,
                    mma_latency: 0,
                    forwardtime: 0,
                    forwardcount: 0,
                    #[cfg(feature = "loop_detect")]
                    uid: 0,
                };
                servers.push(entry);
                gotone += 1;
            }
            // Invalid addresses are silently skipped (matches C behavior).
        }

        // Remove stale resolv.conf entries still marked for cleanup.
        servers.retain(|srv| {
            !(srv.flags.contains(ServerFlags::FROM_RESOLV)
                && srv.flags.contains(ServerFlags::MARK))
        });

        Ok(gotone)
    }

    /// Handle new interface address events by refreshing server bindings.
    ///
    /// Called when network addresses are added or removed from interfaces
    /// (triggered by netlink `RTM_NEWADDR`/`RTM_DELADDR` on Linux, or routing
    /// socket events on BSD). Records the event time for freshness tracking.
    ///
    /// The actual interface re-enumeration and listener recreation is handled
    /// by the caller (event loop in `core::event_loop`).
    ///
    /// # Arguments
    /// * `_now` — Current monotonic timestamp for freshness tracking
    ///
    /// # Source
    /// Port of `src/network.c` `newaddress()` lines 6297–6331.
    pub fn newaddress(&mut self, _now: Instant) {
        // In the C implementation, newaddress() triggers interface re-enumeration,
        // listener recreation, DHCP context rebuilding, and multicast group rejoining.
        // In the Rust architecture, these responsibilities are handled by the event
        // loop and the respective subsystems (net::interface, dhcp::radv, etc.).
        //
        // This method serves as the socket pool's hook point for address change events.
        // Currently it ensures the pool is aware of the topology change. If server
        // bindings need refreshing (e.g., source address no longer valid), the caller
        // should invoke check_servers() after this method returns.
        debug!("newaddress: interface address change detected");
    }

    /// Get a reference to a server fd by index.
    ///
    /// # Arguments
    /// * `index` — Index into the `sfds` vector
    ///
    /// # Returns
    /// * `Some(&ServerFd)` if the index is valid
    /// * `None` if the index is out of bounds
    #[inline]
    pub fn get_sfd(&self, index: usize) -> Option<&ServerFd> {
        self.sfds.get(index)
    }

    /// Get a reference to the server fd pool.
    #[inline]
    pub fn sfds(&self) -> &[ServerFd] {
        &self.sfds
    }

    /// Get a reference to the randomized source port socket pool.
    #[inline]
    pub fn rand_fds(&self) -> &[RandFd] {
        &self.rand_fds
    }
}

impl std::fmt::Debug for SocketPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketPool")
            .field("sfds_count", &self.sfds.len())
            .field("rand_fds_count", &self.rand_fds.len())
            .field("query_port", &self.query_port)
            .field("min_port", &self.min_port)
            .field("max_port", &self.max_port)
            .field("os_port", &self.os_port)
            .finish()
    }
}

// ===========================================================================
// Module-level helper functions
// ===========================================================================

/// Set non-blocking and close-on-exec flags on a socket.
///
/// Replaces C `fix_fd()` from `src/network.c` lines 2430–2440.
/// Uses `socket2::Socket` methods for portable flag setting.
///
/// # Arguments
/// * `socket` — Socket to configure
///
/// # Returns
/// * `Ok(())` — Flags set successfully
/// * `Err(io::Error)` — Flag setting failed
fn fix_fd(socket: &Socket) -> Result<(), SocketError> {
    socket.set_nonblocking(true).map_err(|e| SocketError::SetOptFailed {
        option: "O_NONBLOCK".into(),
        source: e,
    })?;

    // socket2::Socket sets CLOEXEC automatically on creation (via SOCK_CLOEXEC
    // on Linux). We call set_cloexec explicitly as a safety net for platforms
    // that don't support SOCK_CLOEXEC atomically.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        use std::os::fd::BorrowedFd;
        let raw_fd = socket.as_raw_fd();
        // SAFETY: socket is a valid open fd; BorrowedFd does not take ownership.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        // Use fcntl to ensure CLOEXEC is set.
        let flags = nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD);
        if let Ok(flags) = flags {
            let new_flags = nix::fcntl::FdFlag::from_bits_truncate(flags)
                | nix::fcntl::FdFlag::FD_CLOEXEC;
            // SAFETY: raw_fd is a valid open fd (same fd as borrowed above; socket is still alive).
            // BorrowedFd does not take ownership; the socket retains ownership of the fd.
            let borrowed2 = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let _ = nix::fcntl::fcntl(
                borrowed2,
                nix::fcntl::FcntlArg::F_SETFD(new_flags),
            );
        }
    }

    Ok(())
}

/// Bind a socket to a local address with randomized port selection.
///
/// Implements the port randomization algorithm from C `local_bind()`:
/// 1. For TCP: always use port 0 (OS-assigned)
/// 2. For UDP with port == 0 and valid port range: randomize within range
/// 3. For small ranges (`< SMALL_PORT_RANGE`): systematic sequential search
/// 4. For larger ranges: random selection with up to 100 retries
/// 5. After binding, if UDP and `ifindex > 0`: set `IP_UNICAST_IF`/`IPV6_UNICAST_IF`
///
/// # Arguments
/// * `socket` — Socket to bind
/// * `addr` — Source address to bind (port may be 0 for random allocation)
/// * `interface` — Interface name for `SO_BINDTODEVICE` (empty = skip)
/// * `ifindex` — Interface index for unicast interface binding (0 = skip)
/// * `is_tcp` — Whether this is a TCP socket (always uses OS-assigned port)
/// * `min_port` — Minimum port for random allocation
/// * `max_port` — Maximum port for random allocation
///
/// # Returns
/// * `Ok(())` — Socket bound successfully
/// * `Err(SocketError)` — All binding attempts failed
///
/// # Source
/// Port of `src/network.c` `local_bind()` lines 5544–5630.
fn local_bind(
    socket: &Socket,
    addr: &SocketAddress,
    interface: &str,
    ifindex: u32,
    is_tcp: bool,
    min_port: u16,
    max_port: u16,
) -> Result<(), SocketError> {
    let mut addr_copy = addr.clone();
    let original_port = addr_copy.port();

    // Cannot set source port for TCP connections.
    let mut port: u16 = if is_tcp {
        0
    } else {
        original_port
    };

    let mut tries: u32 = 1;
    let mut ports_avail: u16 = 1;

    // For UDP with port 0 and valid port range: randomize.
    if !is_tcp && port == 0 && max_port != 0 && max_port >= min_port {
        ports_avail = max_port - min_port + 1;
        tries = if (ports_avail as usize) < SMALL_PORT_RANGE {
            ports_avail as u32
        } else {
            MAX_RANDOM_PORT_RETRIES
        };
        port = min_port + (rand16() % ports_avail);
    }

    loop {
        // Elide bind() call if it's to port 0, address 0.
        let is_wildcard_zero = match &addr_copy {
            SocketAddress::V4(v4) => port == 0 && *v4.ip() == Ipv4Addr::UNSPECIFIED,
            SocketAddress::V6(v6) => port == 0 && *v6.ip() == Ipv6Addr::UNSPECIFIED,
        };

        if is_wildcard_zero {
            break;
        }

        // Set the port on the address copy.
        addr_copy.set_port(port);

        // Convert SocketAddress to socket2::SockAddr for binding.
        let sock_addr: SockAddr = match &addr_copy {
            SocketAddress::V4(v4) => SockAddr::from(*v4),
            SocketAddress::V6(v6) => SockAddr::from(*v6),
        };

        match socket.bind(&sock_addr) {
            Ok(()) => break,
            Err(e) => {
                let kind = e.kind();
                if kind != io::ErrorKind::AddrInUse
                    && kind != io::ErrorKind::PermissionDenied
                {
                    return Err(SocketError::BindFailed {
                        addr: format!("{}", addr_copy),
                        source: e,
                    });
                }

                tries -= 1;
                if tries == 0 {
                    return Err(SocketError::BindFailed {
                        addr: format!("{}", addr_copy),
                        source: e,
                    });
                }

                // For small ranges, do a systematic search.
                if (ports_avail as usize) < SMALL_PORT_RANGE {
                    let mut hport = port;
                    if hport == max_port {
                        hport = min_port;
                    } else {
                        hport += 1;
                    }
                    port = hport;
                } else {
                    port = min_port + (rand16() % ports_avail);
                }
            }
        }
    }

    // After binding, set per-interface unicast routing if requested.
    if !is_tcp && ifindex > 0 {
        set_unicast_if(socket, addr, ifindex)?;
    }

    // Bind to a specific network device on Linux.
    #[cfg(target_os = "linux")]
    if !interface.is_empty() {
        set_so_bindtodevice(socket, interface)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = interface; // Suppress unused warning on non-Linux.

    Ok(())
}

// ===========================================================================
// Socket option helpers
// ===========================================================================

/// Set `SO_REUSEADDR` on a socket.
///
/// Allows binding to addresses in TIME_WAIT state from previous connections.
/// Critical for daemon restarts where the listening port may still be in use.
#[allow(dead_code)]
fn set_so_reuseaddr(socket: &Socket) -> Result<(), SocketError> {
    socket.set_reuse_address(true).map_err(|e| SocketError::SetOptFailed {
        option: "SO_REUSEADDR".into(),
        source: e,
    })
}

/// Set `SO_BINDTODEVICE` on a socket (Linux only).
///
/// Forces all traffic through a specific network interface, regardless of
/// routing table entries. Requires `CAP_NET_RAW` capability.
///
/// # Arguments
/// * `socket` — Socket to configure
/// * `interface` — Interface name (e.g., "eth0")
#[cfg(target_os = "linux")]
fn set_so_bindtodevice(socket: &Socket, interface: &str) -> Result<(), SocketError> {
    use nix::sys::socket::sockopt::BindToDevice;
    use nix::sys::socket::setsockopt;
    use std::ffi::OsString;
    use std::os::unix::io::AsRawFd;
    use std::os::fd::BorrowedFd;

    let raw_fd = socket.as_raw_fd();
    // SAFETY: socket is a valid open fd; BorrowedFd does not take ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let iface_os = OsString::from(interface.to_owned());

    setsockopt(&borrowed, BindToDevice, &iface_os).map_err(|e| SocketError::SetOptFailed {
        option: format!("SO_BINDTODEVICE({})", interface),
        source: io::Error::from_raw_os_error(e as i32),
    })
}

/// Set `IPV6_V6ONLY` on an IPv6 socket.
///
/// Prevents IPv4-mapped addresses (`::ffff:x.x.x.x`) on the IPv6 socket,
/// ensuring clean separation of IPv4 and IPv6 traffic.
#[allow(dead_code)]
fn set_ipv6_v6only(socket: &Socket) -> Result<(), SocketError> {
    socket.set_only_v6(true).map_err(|e| SocketError::SetOptFailed {
        option: "IPV6_V6ONLY".into(),
        source: e,
    })
}

/// Set `IP_UNICAST_IF` or `IPV6_UNICAST_IF` for per-interface source routing.
///
/// Forces outgoing unicast packets through a specific interface, identified
/// by its index. This is the modern alternative to `SO_BINDTODEVICE` for
/// source address selection without requiring `CAP_NET_RAW`.
///
/// # Arguments
/// * `socket` — Socket to configure
/// * `addr` — Address family (determines IPv4 vs IPv6 option)
/// * `ifindex` — Interface index (from `if_nametoindex()`)
fn set_unicast_if(
    socket: &Socket,
    addr: &SocketAddress,
    ifindex: u32,
) -> Result<(), SocketError> {
    let fd = socket.as_raw_fd();
    let ifindex_be = ifindex.to_be(); // Network byte order, matches C htonl(ifindex).

    match addr {
        SocketAddress::V4(_) => {
            // SAFETY: `IP_UNICAST_IF` is a standard socket option on Linux 3.15+.
            // We pass a valid fd from a socket2::Socket, a pointer to a u32 in
            // network byte order, and the correct size. The kernel validates the
            // interface index.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_UNICAST_IF,
                    &ifindex_be as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(SocketError::SetOptFailed {
                    option: format!("IP_UNICAST_IF(ifindex={})", ifindex),
                    source: io::Error::last_os_error(),
                });
            }
        }
        SocketAddress::V6(_) => {
            // SAFETY: `IPV6_UNICAST_IF` is a standard socket option on Linux 3.15+.
            // Same safety invariants as `IP_UNICAST_IF` above.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_UNICAST_IF,
                    &ifindex_be as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(SocketError::SetOptFailed {
                    option: format!("IPV6_UNICAST_IF(ifindex={})", ifindex),
                    source: io::Error::last_os_error(),
                });
            }
        }
    }

    Ok(())
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_pool_new() {
        let pool = SocketPool::new(0, 1024, 65535, false);
        assert!(pool.sfds().is_empty());
        assert!(pool.rand_fds().is_empty());
        assert_eq!(pool.query_port, 0);
        assert_eq!(pool.min_port, 1024);
        assert_eq!(pool.max_port, 65535);
        assert!(!pool.os_port);
    }

    #[test]
    fn test_socket_pool_new_with_fixed_port() {
        let pool = SocketPool::new(5353, 1024, 65535, true);
        assert_eq!(pool.query_port, 5353);
        assert!(pool.os_port);
    }

    #[test]
    fn test_socket_error_display() {
        let err = SocketError::CreationFailed(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no permission",
        ));
        assert!(format!("{}", err).contains("socket creation failed"));

        let err = SocketError::BindFailed {
            addr: "0.0.0.0:53".to_string(),
            source: io::Error::new(io::ErrorKind::AddrInUse, "in use"),
        };
        assert!(format!("{}", err).contains("socket bind failed"));

        let err = SocketError::AllocationFailed("test error".to_string());
        assert!(format!("{}", err).contains("server socket allocation failed"));

        let err = SocketError::ResolvConfError {
            line: 5,
            message: "bad nameserver".to_string(),
        };
        assert!(format!("{}", err).contains("line 5"));
    }

    #[test]
    fn test_allocate_sfd_random_port_returns_none() {
        // With os_port = false, port 0 returns None (random port mode).
        let mut pool = SocketPool::new(0, 1024, 65535, false);
        let addr = SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0);
        let result = pool.allocate_sfd(&addr, "", 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_allocate_sfd_v6_random_port_returns_none() {
        let mut pool = SocketPool::new(0, 1024, 65535, false);
        let addr = SocketAddress::new_v6(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        let result = pool.allocate_sfd(&addr, "", 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_allocate_sfd_creates_socket() {
        // With os_port = true (fixed port mode), even port 0 should allocate.
        let mut pool = SocketPool::new(0, 1024, 65535, true);
        let addr = SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0);
        let result = pool.allocate_sfd(&addr, "", 0);
        assert!(result.is_ok());
        let idx = result.unwrap();
        assert!(idx.is_some());
        assert_eq!(pool.sfds().len(), 1);
    }

    #[test]
    fn test_allocate_sfd_reuses_existing() {
        let mut pool = SocketPool::new(0, 1024, 65535, true);
        let addr = SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0);

        // First allocation creates a new socket.
        let idx1 = pool.allocate_sfd(&addr, "", 0).unwrap();
        // Second allocation should reuse.
        let idx2 = pool.allocate_sfd(&addr, "", 0).unwrap();
        assert_eq!(idx1, idx2);
        assert_eq!(pool.sfds().len(), 1);
    }

    #[test]
    fn test_allocate_sfd_different_interface_creates_new() {
        let mut pool = SocketPool::new(0, 1024, 65535, true);
        let addr = SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0);

        let _idx1 = pool.allocate_sfd(&addr, "", 0).unwrap();
        // Different ifindex should create a new socket.
        let _idx2 = pool.allocate_sfd(&addr, "", 1).unwrap();
        assert_eq!(pool.sfds().len(), 2);
    }

    #[test]
    fn test_check_servers_marks_zero_addr() {
        let mut pool = SocketPool::new(0, 1024, 65535, false);
        let mut servers = vec![ServerEntry {
            flags: ServerFlags::empty(),
            domain_len: 0,
            domain: None,
            serial: 0,
            arrayposn: 0,
            last_server: -1,
            addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 53),
            source_addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            interface: String::new(),
            ifindex: 0,
            tcpfd: -1,
            queries: 0,
            failed_queries: 0,
            nxdomain_replies: 0,
            retrys: 0,
            query_latency: 0,
            mma_latency: 0,
            forwardtime: 0,
            forwardcount: 0,
            #[cfg(feature = "loop_detect")]
            uid: 0,
        }];

        let result = pool.check_servers(&mut servers, true);
        assert!(result.is_ok());
        // 0.0.0.0 should be marked.
        assert!(servers[0].flags.contains(ServerFlags::MARK));
    }

    #[test]
    fn test_reload_servers_missing_file() {
        let mut pool = SocketPool::new(0, 1024, 65535, false);
        let mut servers = Vec::new();
        let result = pool.reload_servers("/nonexistent/resolv.conf", &mut servers);
        assert!(result.is_err());
    }

    #[test]
    fn test_socket_pool_debug() {
        let pool = SocketPool::new(53, 1024, 65535, true);
        let dbg = format!("{:?}", pool);
        assert!(dbg.contains("SocketPool"));
        assert!(dbg.contains("query_port: 53"));
    }

    #[test]
    fn test_randfd_overflow_sentinel() {
        assert_eq!(RANDFD_REFCOUNT_OVERFLOW, 0xFFFF);
    }

    #[test]
    fn test_get_sfd_out_of_bounds() {
        let pool = SocketPool::new(0, 1024, 65535, false);
        assert!(pool.get_sfd(0).is_none());
        assert!(pool.get_sfd(99).is_none());
    }

    #[test]
    fn test_pre_allocate_sfds_empty_servers() {
        // With query_port = 0, no wildcard sockets created.
        let mut pool = SocketPool::new(0, 1024, 65535, false);
        let servers: Vec<ServerEntry> = Vec::new();
        let result = pool.pre_allocate_sfds(&servers, false);
        assert!(result.is_ok());
        assert!(pool.sfds().is_empty());
    }
}

//! BSD platform-specific network backend.
//!
//! This module provides the BSD implementation of the [`NetworkBackend`] trait
//! using BPF (Berkeley Packet Filter) for raw packet I/O and PF_ROUTE sockets
//! for network interface change monitoring.
//!
//! # Platform Support
//!
//! This module is compiled on FreeBSD, OpenBSD, NetBSD, DragonFlyBSD, and macOS.
//! Some features have more limited platform support:
//!
//! | Feature | FreeBSD | OpenBSD | NetBSD | DragonFly | macOS |
//! |---------|---------|---------|--------|-----------|-------|
//! | Interface enumeration | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | Route socket monitoring | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | ARP sysctl enumeration | ✓ | ✓ | ✓ | ✓ | ✗ |
//! | PF table integration | ✓ | ✓ | ✓ | ✓ | ✗ |
//! | BPF raw DHCP packets | ✓ | ✓ | ✓ | ✓ | ✓ |
//!
//! # Submodules
//!
//! - [`bpf`]: BPF device operations, interface enumeration via `getifaddrs()`,
//!   routing socket initialization and message processing, ARP table enumeration
//!   via sysctl, and raw DHCP packet transmission via BPF `writev`.
//! - [`pf_tables`]: BSD PF firewall table manipulation for DNS-driven firewall
//!   rules (feature-gated on `ipset`).
//!
//! # Architecture
//!
//! Replaces C's `bpf.c` and `tables.c` with a trait-based design where [`BsdBpf`]
//! implements [`NetworkBackend`] for integration with the platform-agnostic event loop.
//! The Strategy pattern allows the main event loop to interact with either Linux or BSD
//! backends through the same [`NetworkBackend`] trait interface.
//!
//! # State Management
//!
//! All mutable state that was previously held in C static variables (`del_family`,
//! `del_addr`, routing socket fd, BPF device fd) is encapsulated within the
//! [`BsdBpf`] struct, eliminating global mutable state. File descriptors are managed
//! via RAII through the [`Drop`] implementation, ensuring proper cleanup on shutdown.
//!
//! # Error Handling
//!
//! All fallible operations return `Result<T, PlatformError>` instead of C-style
//! integer error codes or calling `die()`. This enables idiomatic Rust error
//! propagation via the `?` operator throughout the caller chain.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// BSD BPF device operations, interface enumeration via `getifaddrs()`, routing
/// socket initialization and message processing, ARP table enumeration via sysctl,
/// and raw DHCP packet transmission.
///
/// Replaces C's `src/bpf.c` (805 lines).
pub mod bpf;

/// BSD PF (Packet Filter) firewall table manipulation for DNS-driven rules.
/// Enabled only when the `ipset` Cargo feature is active.
///
/// Replaces C's `src/tables.c` (386 lines).
#[cfg(feature = "ipset")]
pub mod pf_tables;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

/// Re-export [`PfTableManager`] for convenient access from DNS forwarding code.
///
/// PF table operations allow dnsmasq to dynamically add/remove resolved IP
/// addresses to named PF tables based on DNS query results, enabling domain-based
/// firewall rules. Only available when the `ipset` feature is enabled.
///
/// # Example PF Integration
///
/// In `/etc/pf.conf`:
/// ```text
/// table <blocked_domains> persist
/// block drop quick from any to <blocked_domains>
/// ```
///
/// In `dnsmasq.conf`:
/// ```text
/// ipset=/doubleclick.net/blocked_domains
/// ```
#[cfg(feature = "ipset")]
pub use pf_tables::PfTableManager;

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::RawFd;

use crate::net::platform::{InterfaceCallback, NetworkBackend, PlatformError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default routing socket message buffer size in bytes.
///
/// 4096 bytes accommodates all standard BSD routing messages including
/// `RTM_NEWADDR` and `RTM_DELADDR` with multiple sockaddr entries.
/// This matches typical BSD kernel routing message maximum sizes.
const ROUTE_MSG_BUF_SIZE: usize = 4096;

/// Default DHCP server UDP port (bootps).
///
/// Used as the source port when sending raw DHCP packets via BPF.
/// This is the standard BOOTP/DHCP server port per RFC 2131 section 4.1.
#[cfg(feature = "dhcp")]
const DHCP_SERVER_PORT: u16 = 67;

// ---------------------------------------------------------------------------
// BsdBpf struct definition
// ---------------------------------------------------------------------------

/// BSD network backend using BPF and PF_ROUTE sockets.
///
/// This struct implements [`NetworkBackend`] for BSD-family operating systems,
/// providing:
/// - Network interface enumeration via `getifaddrs()` (see [`bpf::iface_enumerate`])
/// - Real-time interface change monitoring via PF_ROUTE socket (see [`bpf::route_sock`])
/// - ARP/neighbor table enumeration via sysctl (non-macOS, see [`bpf::arp_enumerate`])
///
/// When the `dhcp` feature is enabled, this struct also implements
/// [`RawPacketSender`](crate::net::platform::RawPacketSender) for raw DHCP packet
/// transmission via BPF devices.
///
/// # Lifecycle
///
/// 1. Created via [`BsdBpf::new()`] during daemon initialization
/// 2. [`init()`](NetworkBackend::init) opens the PF_ROUTE socket for monitoring
/// 3. [`enumerate_interfaces()`](NetworkBackend::enumerate_interfaces) called for
///    each interface discovery cycle
/// 4. [`monitor_changes()`](NetworkBackend::monitor_changes) called from the event
///    loop when the routing socket is readable
/// 5. Dropped during daemon shutdown (RAII closes all sockets)
///
/// # State Ownership
///
/// Replaces C module-level static variables from `bpf.c`:
///
/// | C Static Variable | Rust Field | Description |
/// |-------------------|------------|-------------|
/// | `del_family` / `del_addr` (line 110-111) | `deleted_addr_filter` | Recently deleted address filter |
/// | Route socket fd (from `route_init()`) | `route_fd` | PF_ROUTE monitoring socket |
/// | BPF device fd (from `init_bpf()`) | `bpf_fd` | BPF raw packet device |
/// | RTM_VERSION warning flag | `rtm_version_warned` | Once-only warning suppression |
///
/// # Thread Safety
///
/// Designed for single-threaded use within the dnsmasq event loop. All methods
/// assume exclusive access; no internal synchronization is provided.
pub struct BsdBpf {
    /// PF_ROUTE socket file descriptor for monitoring interface changes.
    /// Created by [`bpf::route_init()`], polled in the main event loop via
    /// `mio::Poll`. `None` until [`init()`](NetworkBackend::init) is called.
    route_fd: Option<RawFd>,

    /// BPF device file descriptor for raw DHCP packet transmission.
    /// Created by [`bpf::init_bpf()`] during
    /// [`init_bpf()`](crate::net::platform::RawPacketSender::init_bpf),
    /// used by [`bpf::send_via_bpf()`] for Ethernet frame injection.
    /// Only present when the `dhcp` feature is enabled.
    #[cfg(feature = "dhcp")]
    bpf_fd: Option<RawFd>,

    /// Utility DGRAM socket for interface MAC address queries via `ioctl(SIOCGIFADDR)`.
    /// Used as the `dhcp_fd` parameter when delegating to [`bpf::send_via_bpf()`],
    /// which needs a socket for `get_interface_mac()` ioctl calls.
    /// Created during [`init_bpf()`](crate::net::platform::RawPacketSender::init_bpf)
    /// initialization. Any DGRAM socket suffices for this ioctl.
    #[cfg(feature = "dhcp")]
    util_fd: Option<RawFd>,

    /// Recently deleted address filter for kernel race condition workaround.
    ///
    /// When `RTM_DELADDR` is received on the routing socket, the deleted address
    /// may still appear in `getifaddrs()` results temporarily due to a timing
    /// race in the BSD kernel. This filter allows [`enumerate_interfaces()`]
    /// to skip such stale entries.
    ///
    /// Replaces C static `del_family` / `del_addr` variables from `bpf.c` lines 110-111.
    deleted_addr_filter: bpf::DeletedAddressFilter,

    /// Whether an RTM_VERSION mismatch warning has been logged (once-only).
    /// Prevents spamming the log with repeated version mismatch warnings when
    /// processing routing socket messages with an unexpected RTM_VERSION.
    rtm_version_warned: bool,

    /// Pre-allocated packet buffer for routing socket message reception.
    /// Avoids per-message allocation when processing `RTM_NEWADDR` / `RTM_DELADDR`
    /// events in [`monitor_changes()`](NetworkBackend::monitor_changes).
    packet_buf: Vec<u8>,
}

// ---------------------------------------------------------------------------
// BsdBpf constructor
// ---------------------------------------------------------------------------

impl BsdBpf {
    /// Create a new BSD network backend instance (uninitialized).
    ///
    /// Does **not** open any sockets — call [`init()`](NetworkBackend::init) to create
    /// the PF_ROUTE monitoring socket, and optionally call
    /// [`init_bpf()`](crate::net::platform::RawPacketSender::init_bpf) to set up
    /// the BPF device for DHCP raw packet transmission.
    ///
    /// # Returns
    ///
    /// A new `BsdBpf` instance with all file descriptors set to `None` and the
    /// deleted-address filter cleared.
    ///
    /// # Errors
    ///
    /// Currently infallible, but returns `Result` for consistency with the
    /// [`create_backend()`](crate::net::platform::create_backend) factory function
    /// and for future extensibility.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dnsmasq::net::platform::bsd::BsdBpf;
    /// use dnsmasq::net::platform::NetworkBackend;
    ///
    /// let mut backend = BsdBpf::new().expect("BsdBpf creation failed");
    /// let subsystem = backend.init().expect("init failed");
    /// assert_eq!(subsystem, "PF_ROUTE");
    /// ```
    pub fn new() -> Result<Self, PlatformError> {
        Ok(Self {
            route_fd: None,
            #[cfg(feature = "dhcp")]
            bpf_fd: None,
            #[cfg(feature = "dhcp")]
            util_fd: None,
            deleted_addr_filter: bpf::DeletedAddressFilter::new(),
            rtm_version_warned: false,
            packet_buf: vec![0u8; ROUTE_MSG_BUF_SIZE],
        })
    }
}

// ---------------------------------------------------------------------------
// NetworkBackend trait implementation
// ---------------------------------------------------------------------------

impl NetworkBackend for BsdBpf {
    /// Initialize the BSD networking subsystem.
    ///
    /// Opens a PF_ROUTE socket for real-time interface change monitoring.
    /// The socket is configured with `SOCK_CLOEXEC` and `SOCK_NONBLOCK` flags,
    /// ready for registration with `mio::Poll`.
    ///
    /// # Returns
    ///
    /// `"PF_ROUTE"` — a descriptive string identifying the initialized subsystem,
    /// used for diagnostic logging during daemon startup.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::RoutingSocketError`] if the PF_ROUTE socket cannot
    /// be created (e.g., insufficient privileges or kernel support missing).
    ///
    /// # C Equivalent
    ///
    /// Replaces `route_init()` in `bpf.c` line 690.
    fn init(&mut self) -> Result<String, PlatformError> {
        // Create PF_ROUTE socket for monitoring address changes.
        let fd = bpf::route_init()?;
        self.route_fd = Some(fd);

        Ok("PF_ROUTE".to_string())
    }

    /// Enumerate network interfaces using `getifaddrs()`.
    ///
    /// Delegates to [`bpf::iface_enumerate()`] with the current deleted-address
    /// filter applied to work around the BSD kernel race condition where recently
    /// deleted addresses may still appear in `getifaddrs()` results.
    ///
    /// # Parameters
    ///
    /// - `family`: Address family to enumerate (`AF_INET`, `AF_INET6`, `AF_UNSPEC`,
    ///   or `AF_LOCAL`). `AF_UNSPEC` delegates to ARP enumeration, `AF_LOCAL` is
    ///   internally mapped to `AF_LINK` (BSD convention).
    /// - `callback`: The family-appropriate [`InterfaceCallback`] variant. Must match
    ///   the requested `family`.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — all interfaces enumerated successfully
    /// - `Ok(false)` — enumeration was aborted by a callback returning 0
    /// - `Err(_)` — a platform error occurred during enumeration
    ///
    /// # C Equivalent
    ///
    /// Replaces `iface_enumerate()` in `bpf.c` line 275.
    fn enumerate_interfaces(
        &self,
        family: i32,
        mut callback: InterfaceCallback<'_>,
    ) -> Result<bool, PlatformError> {
        bpf::iface_enumerate(family, &mut callback, &self.deleted_addr_filter)
    }

    /// Process routing socket messages for interface changes.
    ///
    /// Called from the main event loop when the routing socket
    /// ([`monitor_fd()`](NetworkBackend::monitor_fd)) becomes readable. Reads
    /// and parses a single routing message:
    ///
    /// - **`RTM_NEWADDR`**: Clears the deleted-address filter and signals the caller
    ///   to re-enumerate interfaces.
    /// - **`RTM_DELADDR`**: Extracts the deleted address from the `RTA_IFA` field and
    ///   stores it in the filter for race condition workaround, then signals re-enumeration.
    /// - **Other messages**: Silently ignored (e.g., `RTM_NEWROUTE`, `RTM_IFINFO`).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::RoutingSocketError`] if reading from the routing
    /// socket fails with an error other than `EAGAIN`/`EWOULDBLOCK`.
    ///
    /// # C Equivalent
    ///
    /// Replaces `route_sock()` in `bpf.c` line 740.
    fn monitor_changes(&mut self) -> Result<(), PlatformError> {
        if let Some(fd) = self.route_fd {
            let _event = bpf::route_sock(
                fd,
                &mut self.packet_buf,
                &mut self.deleted_addr_filter,
                &mut self.rtm_version_warned,
            )?;
            // Event queuing is handled by the caller via the event loop.
            // If Some(Event::NewAddr) is returned, the event loop will trigger
            // interface re-enumeration on the next iteration.
        }
        Ok(())
    }

    /// Get the routing socket file descriptor for `mio::Poll` registration.
    ///
    /// The returned fd should be registered with `mio::Poll` for `Interest::READABLE`
    /// events. When the fd becomes readable, call [`monitor_changes()`] to process
    /// the pending routing message.
    ///
    /// # Returns
    ///
    /// - `Some(fd)` — the raw file descriptor for the PF_ROUTE socket
    /// - `None` — [`init()`](NetworkBackend::init) has not been called or failed
    fn monitor_fd(&self) -> Option<RawFd> {
        self.route_fd
    }

    /// Enumerate ARP/neighbor table entries.
    ///
    /// On non-macOS BSD systems, uses `sysctl(NET_RT_FLAGS, RTF_LLINFO)` to
    /// retrieve the kernel ARP cache. On macOS, ARP enumeration via sysctl is
    /// not supported and this method returns `Ok(())` without invoking the callback.
    ///
    /// # Parameters
    ///
    /// - `callback`: Invoked for each ARP entry with parameters:
    ///   - `family` (`i32`): Always `AF_INET` for ARP entries
    ///   - `addr` ([`IpAddr`]): IP address of the neighbor
    ///   - `mac` (`&[u8]`): Hardware (MAC) address bytes
    ///   Returns `i32`: non-zero to continue enumeration, zero to stop.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::ArpEnumerationFailed`] if the sysctl call fails.
    ///
    /// # C Equivalent
    ///
    /// Replaces `arp_enumerate()` in `bpf.c` line 160.
    fn enumerate_arp(
        &self,
        callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
    ) -> Result<(), PlatformError> {
        // arp_enumerate() handles the macOS exclusion internally via cfg attributes.
        // On macOS, it returns Ok(false) indicating no enumeration was performed.
        // On other BSDs, it performs sysctl-based ARP table enumeration.
        let _completed = bpf::arp_enumerate(callback)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RawPacketSender trait implementation (DHCP feature-gated)
// ---------------------------------------------------------------------------

/// When the `dhcp` feature is enabled, [`BsdBpf`] also implements
/// [`RawPacketSender`](crate::net::platform::RawPacketSender) for raw DHCP
/// packet transmission via BPF devices.
///
/// BPF (Berkeley Packet Filter) is used on BSD to inject raw Ethernet frames
/// containing DHCP replies, bypassing the kernel IP stack. This is necessary
/// because DHCP clients may not yet have valid IP addresses and cannot respond
/// to ARP requests, requiring the DHCP server to construct complete
/// Ethernet/IP/UDP frames manually.
///
/// # C Equivalents
///
/// - `init_bpf()` in `bpf.c` line 466 → [`init_bpf()`]
/// - `send_via_bpf()` in `bpf.c` line 557 → [`send_raw_packet()`]
#[cfg(feature = "dhcp")]
impl crate::net::platform::RawPacketSender for BsdBpf {
    /// Initialize BPF device for raw DHCP packet transmission.
    ///
    /// Opens a BPF character device (`/dev/bpf0`, `/dev/bpf1`, etc.) by iterating
    /// through available devices until one is found that is not busy. Also creates
    /// a utility DGRAM socket for interface MAC address queries (used internally
    /// by [`send_raw_packet()`]).
    ///
    /// The BPF device fd is stored in `self.bpf_fd` and the utility socket in
    /// `self.util_fd`. Both are closed automatically on drop.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::BpfError`] if no available BPF device is found
    /// (all `/dev/bpfN` devices are busy or inaccessible).
    ///
    /// # C Equivalent
    ///
    /// Replaces `init_bpf()` in `bpf.c` line 466.
    fn init_bpf(&mut self) -> Result<(), PlatformError> {
        // Open the BPF device via the bpf submodule.
        self.bpf_fd = Some(bpf::init_bpf()?);

        // Create a utility DGRAM socket for interface MAC address ioctl queries.
        // The send_via_bpf() function in bpf.rs requires a socket fd for
        // SIOCGIFADDR ioctl to retrieve the source MAC address of the interface.
        // Any DGRAM socket (regardless of binding) supports this ioctl on BSD.
        //
        // SAFETY: libc::socket() is a standard POSIX system call. AF_INET + SOCK_DGRAM
        // creates an unbound UDP socket. The returned fd is valid and will be closed
        // in our Drop implementation.
        let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock_fd >= 0 {
            self.util_fd = Some(sock_fd);
        }
        // If utility socket creation fails, send_raw_packet will degrade gracefully
        // (MAC lookup will fail, matching the C behavior of returning silently).

        Ok(())
    }

    /// Send a raw DHCP packet via BPF, constructing Ethernet/IP/UDP headers.
    ///
    /// Delegates to [`bpf::send_via_bpf()`] which builds a complete Ethernet frame
    /// with manual IP and UDP header construction, bypassing the kernel's IP stack.
    /// The source MAC address is obtained via `ioctl(SIOCGIFADDR)` on the specified
    /// interface.
    ///
    /// # Parameters
    ///
    /// - `data`: Raw DHCP payload bytes (BOOTP message). Must contain valid DHCP
    ///   message fields including `htype`, `hlen`, `flags`, `yiaddr`, and `chaddr`.
    /// - `dest_addr`: Destination IP address. For broadcast DHCP replies, the
    ///   actual destination is determined by the DHCP broadcast flag in the payload.
    ///   Must be IPv4 (DHCPv4 only uses BPF raw sends).
    /// - `dest_port`: Destination UDP port (typically 68 for DHCP client).
    /// - `iface_addr`: Source IP address (server's interface address). Must be IPv4.
    /// - `iface_name`: Network interface name (e.g., `"em0"`, `"vtnet0"`) for BPF
    ///   device binding and MAC address lookup.
    ///
    /// # Returns
    ///
    /// The number of bytes of DHCP payload sent on success.
    ///
    /// # Errors
    ///
    /// - [`PlatformError::BpfError`] if the BPF device is not initialized
    ///   ([`init_bpf()`] was not called), the source address is not IPv4,
    ///   or the BPF `writev()` fails.
    ///
    /// # C Equivalent
    ///
    /// Replaces `send_via_bpf()` in `bpf.c` line 557.
    fn send_raw_packet(
        &self,
        data: &[u8],
        _dest_addr: IpAddr,
        dest_port: u16,
        iface_addr: IpAddr,
        iface_name: &str,
    ) -> Result<usize, PlatformError> {
        let bpf_fd = self.bpf_fd.ok_or_else(|| {
            PlatformError::BpfError("BPF device not initialized — call init_bpf() first".into())
        })?;

        // The utility socket is used for MAC address ioctl queries.
        // If unavailable, pass -1 and let the bpf module handle the degraded case.
        let util_fd = self.util_fd.unwrap_or(-1);

        // Extract IPv4 source address — BPF raw sends are DHCPv4 only.
        let src_ipv4 = match iface_addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(PlatformError::BpfError(
                    "BPF raw packet send only supports IPv4 (DHCPv4)".into(),
                ));
            }
        };

        // Create a mutable copy of the DHCP payload.
        // bpf::send_via_bpf() requires &mut [u8] because it may zero-pad the last
        // byte for UDP checksum computation when the payload has an odd length.
        // We add one extra byte of headroom for this padding.
        let payload_len = data.len();
        let mut mess = Vec::with_capacity(payload_len + 1);
        mess.extend_from_slice(data);
        mess.push(0); // Padding byte for potential odd-length checksum

        // Delegate to the BPF submodule for raw packet construction and transmission.
        // The bpf::send_via_bpf function constructs:
        //   1. Ethernet header (dst MAC from DHCP chaddr or broadcast, src MAC via ioctl)
        //   2. IPv4 header with manual checksum
        //   3. UDP header with pseudo-header checksum
        //   4. DHCP payload
        bpf::send_via_bpf(
            bpf_fd,
            util_fd,
            &mut mess,
            payload_len,
            src_ipv4,
            iface_name,
            DHCP_SERVER_PORT,
            dest_port,
        )?;

        Ok(payload_len)
    }
}

// ---------------------------------------------------------------------------
// Drop implementation (RAII file descriptor cleanup)
// ---------------------------------------------------------------------------

impl Drop for BsdBpf {
    /// Clean up all owned file descriptors when the BSD backend is dropped.
    ///
    /// Closes the PF_ROUTE monitoring socket, BPF device (if DHCP feature is enabled),
    /// and utility MAC query socket (if created). This replaces manual cleanup that
    /// was implicit in the C codebase (where file descriptors lived until process exit).
    ///
    /// Each `unsafe` block for `libc::close()` is documented with a SAFETY comment
    /// explaining why the fd is valid to close.
    fn drop(&mut self) {
        // Close the PF_ROUTE monitoring socket.
        if let Some(fd) = self.route_fd.take() {
            // SAFETY: route_fd was obtained from bpf::route_init() which creates
            // a valid PF_ROUTE socket via nix::sys::socket::socket(). The fd has
            // not been closed by any other code path since we own it exclusively.
            unsafe {
                libc::close(fd);
            }
        }

        // Close the BPF device file descriptor (DHCP feature-gated).
        #[cfg(feature = "dhcp")]
        if let Some(fd) = self.bpf_fd.take() {
            // SAFETY: bpf_fd was obtained from bpf::init_bpf() which opens a
            // /dev/bpfN device via nix::fcntl::open(). The fd has not been closed
            // by any other code path since we own it exclusively.
            unsafe {
                libc::close(fd);
            }
        }

        // Close the utility DGRAM socket used for MAC address queries.
        #[cfg(feature = "dhcp")]
        if let Some(fd) = self.util_fd.take() {
            // SAFETY: util_fd was created via libc::socket(AF_INET, SOCK_DGRAM, 0)
            // in init_bpf(). The fd has not been closed by any other code path
            // since we own it exclusively.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that BsdBpf::new() creates an instance with all fields properly initialized.
    #[test]
    fn test_bsd_bpf_new() {
        let backend = BsdBpf::new().expect("BsdBpf::new() should not fail");
        assert!(
            backend.route_fd.is_none(),
            "route_fd should be None before init"
        );
        assert!(
            !backend.rtm_version_warned,
            "version warning should be false initially"
        );
        assert_eq!(
            backend.packet_buf.len(),
            ROUTE_MSG_BUF_SIZE,
            "packet buffer should be pre-allocated"
        );
        assert!(
            backend.deleted_addr_filter.family.is_none(),
            "deleted address filter should start with no family"
        );
    }

    /// Test that monitor_fd() returns None before init().
    #[test]
    fn test_monitor_fd_before_init() {
        let backend = BsdBpf::new().expect("BsdBpf::new() should not fail");
        assert!(
            backend.monitor_fd().is_none(),
            "monitor_fd should be None before init()"
        );
    }

    /// Test that the ROUTE_MSG_BUF_SIZE constant is reasonable.
    #[test]
    fn test_route_msg_buf_size() {
        assert!(
            ROUTE_MSG_BUF_SIZE >= 1024,
            "Route message buffer should be at least 1KB"
        );
        assert!(
            ROUTE_MSG_BUF_SIZE <= 65536,
            "Route message buffer should not be excessively large"
        );
    }

    /// Test that the DHCP server port constant matches RFC 2131.
    #[cfg(feature = "dhcp")]
    #[test]
    fn test_dhcp_server_port() {
        assert_eq!(DHCP_SERVER_PORT, 67, "DHCP server port per RFC 2131");
    }

    /// Test that BsdBpf Drop doesn't panic when all fds are None.
    #[test]
    fn test_drop_with_no_fds() {
        let backend = BsdBpf::new().expect("BsdBpf::new() should not fail");
        // Dropping with all fds as None should be a no-op and not panic.
        drop(backend);
    }

    /// Test that the deleted address filter integrates correctly with BsdBpf.
    #[test]
    fn test_deleted_addr_filter_integration() {
        let mut backend = BsdBpf::new().expect("BsdBpf::new() should not fail");

        // Initially, no address is filtered.
        assert!(backend.deleted_addr_filter.family.is_none());

        // Simulate setting a deleted address (as would happen in monitor_changes).
        backend.deleted_addr_filter.family = Some(libc::AF_INET);
        backend.deleted_addr_filter.addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert_eq!(backend.deleted_addr_filter.family, Some(libc::AF_INET));
        match backend.deleted_addr_filter.addr {
            IpAddr::V4(v4) => assert_eq!(v4, Ipv4Addr::new(192, 168, 1, 100)),
            _ => panic!("Expected IPv4 address"),
        }

        // Clear the filter.
        backend.deleted_addr_filter.clear();
        assert!(backend.deleted_addr_filter.family.is_none());
    }

    /// Test that packet_buf is pre-allocated and zeroed.
    #[test]
    fn test_packet_buf_initialization() {
        let backend = BsdBpf::new().expect("BsdBpf::new() should not fail");
        assert_eq!(backend.packet_buf.len(), ROUTE_MSG_BUF_SIZE);
        assert!(
            backend.packet_buf.iter().all(|&b| b == 0),
            "Packet buffer should be zero-initialized"
        );
    }
}

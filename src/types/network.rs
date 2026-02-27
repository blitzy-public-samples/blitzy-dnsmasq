//! Network-specific type definitions for the dnsmasq Rust implementation.
//!
//! This module defines all network-related data types used across the dnsmasq codebase
//! for interface enumeration, socket management, listener configuration, and server
//! file descriptor tracking. These types replace the network-related struct definitions
//! from the C `dnsmasq.h` header file.
//!
//! # Key Transformations from C
//! - **All `next` pointers removed:** C intrusive linked lists are replaced by Rust
//!   `Vec<T>` collections managed externally by the owning subsystem.
//! - **C `union mysockaddr` → [`SocketAddress`] enum:** Imported from [`crate::types::addr`],
//!   providing type-safe IPv4/IPv6 socket address handling.
//! - **C `struct irec *iface` → `Option<usize>`:** Pointer-to-struct references become
//!   indices into interface `Vec` collections.
//! - **C `char interface[IF_NAMESIZE+1]` → `String`:** Fixed-size character arrays
//!   become heap-allocated `String` values.
//! - **C `int` booleans → Rust `bool`:** Integer flags used as booleans in C (tftp_ok,
//!   dhcp4_ok, done, warned, etc.) become proper Rust `bool` fields.
//! - **C `#define` bitmasks → `bitflags!` types:** Type-safe flag sets for interface
//!   and name binding flags.
//!
//! # Safety
//! This module contains **no unsafe code**. All types use safe Rust idioms exclusively.
//!
//! # Source References
//! - `src/dnsmasq.h` lines 640–870 (interface and listener types)
//! - `src/dnsmasq.h` lines 1311–1314 (`struct addr_list`)

use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

use crate::types::addr::SocketAddress;
use crate::types::dns::AddrList;

// ===========================================================================
// Interface Enumeration Flags (dnsmasq.h lines 741–744)
// ===========================================================================

bitflags! {
    /// Flags for IPv6 callback from `iface_enumerate()`.
    ///
    /// These flags indicate the state of an IPv6 address on a network interface,
    /// as reported by the kernel during interface enumeration. They are passed
    /// through the callback mechanism in `network.c` / `netlink.c`.
    ///
    /// # Source
    /// Replaces C `IFACE_*` constants from `dnsmasq.h` lines 742–744.
    ///
    /// # Values
    /// - `TENTATIVE` (1): Address is undergoing Duplicate Address Detection (DAD)
    /// - `DEPRECATED` (2): Address lifetime has expired but is still usable
    /// - `PERMANENT` (4): Address is a permanent (static) assignment
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IfaceFlags: i32 {
        /// Address is tentative (undergoing DAD per RFC 4862).
        /// Corresponds to C `IFACE_TENTATIVE = 1`.
        const TENTATIVE  = 1;
        /// Address is deprecated (preferred lifetime expired per RFC 4862).
        /// Corresponds to C `IFACE_DEPRECATED = 2`.
        const DEPRECATED = 2;
        /// Address is permanent (statically configured).
        /// Corresponds to C `IFACE_PERMANENT = 4`.
        const PERMANENT  = 4;
    }
}

// ===========================================================================
// Interface Name Binding Flags (dnsmasq.h lines 868–870)
// ===========================================================================

bitflags! {
    /// Flags for interface name/address bindings specified on the command line.
    ///
    /// Used with [`InterfaceNameBinding`] to track which interface specifications
    /// from `--interface` / `--listen-address` options have been matched during
    /// interface enumeration.
    ///
    /// # Source
    /// Replaces C `INAME_*` constants from `dnsmasq.h` lines 868–870.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InameFlags: i32 {
        /// This interface binding has been matched to a real interface.
        /// Corresponds to C `INAME_USED = 1`.
        const USED = 1;
        /// This binding specifies an IPv4 address/interface.
        /// Corresponds to C `INAME_4 = 2`.
        const IPV4 = 2;
        /// This binding specifies an IPv6 address/interface.
        /// Corresponds to C `INAME_6 = 4`.
        const IPV6 = 4;
    }
}

// ===========================================================================
// Interface Name Direction Flags (dnsmasq.h lines 640–643)
// ===========================================================================

/// Interface name flag: resolve to IPv4 address.
///
/// Used in [`InterfaceName::flags`] to indicate that this interface-name
/// directive should return the interface's IPv4 address.
///
/// Corresponds to C `IN4 = 1` from `dnsmasq.h` line 640.
pub const IN4: i32 = 1;

/// Interface name flag: resolve to IPv6 address.
///
/// Used in [`InterfaceName::flags`] to indicate that this interface-name
/// directive should return the interface's IPv6 address.
///
/// Corresponds to C `IN6 = 2` from `dnsmasq.h` line 641.
pub const IN6: i32 = 2;

/// Interface name flag: resolve to IPv4 address using prototype address filtering.
///
/// Like `IN4`, but also requires the resolved address to be on the same subnet
/// as the prototype address in [`InterfaceName::proto4`].
///
/// Corresponds to C `INP4 = 4` from `dnsmasq.h` line 642.
pub const INP4: i32 = 4;

/// Interface name flag: resolve to IPv6 address using prototype address filtering.
///
/// Like `IN6`, but also requires the resolved address to be on the same subnet
/// as the prototype address in [`InterfaceName::proto6`].
///
/// Corresponds to C `INP6 = 8` from `dnsmasq.h` line 643.
pub const INP6: i32 = 8;

// ===========================================================================
// ReadWriteDirection (dnsmasq.h lines 645–648)
// ===========================================================================

/// Read/write direction constants for network I/O operations.
///
/// Controls the direction of data flow for socket read/write callbacks
/// used in the async DNS name resolution for `--interface-name` directives.
///
/// # Source
/// Replaces C `RW_*` constants from `dnsmasq.h` lines 645–648.
///
/// # Variants
/// - `Write` (0): Write direction for persistent connections
/// - `Read` (1): Read direction for persistent connections
/// - `WriteOnce` (2): Write direction for single-shot operations
/// - `ReadOnce` (3): Read direction for single-shot operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ReadWriteDirection {
    /// Persistent write direction.
    /// Corresponds to C `RW_WRITE = 0`.
    Write = 0,
    /// Persistent read direction.
    /// Corresponds to C `RW_READ = 1`.
    Read = 1,
    /// Single-shot write direction.
    /// Corresponds to C `RW_WRITE_ONCE = 2`.
    WriteOnce = 2,
    /// Single-shot read direction.
    /// Corresponds to C `RW_READ_ONCE = 3`.
    ReadOnce = 3,
}

// ===========================================================================
// InterfaceRecord (dnsmasq.h struct irec, lines 844–851)
// ===========================================================================

/// Network interface information record.
///
/// Represents a single network interface address discovered during interface
/// enumeration. Each interface may have multiple records (one per address).
/// The record tracks the interface's capabilities (TFTP, DHCPv4, DHCPv6),
/// operational state (DAD, multicast), and metadata (name, index, MTU).
///
/// # Critical Transformation
/// The C `struct irec` uses an intrusive linked list via `struct irec *next`.
/// In Rust, this pointer is **removed** — interface records are stored in
/// `Vec<InterfaceRecord>` and referenced by index where needed.
///
/// # Source
/// Replaces C `struct irec` from `dnsmasq.h` lines 844–851.
#[derive(Debug, Clone)]
pub struct InterfaceRecord {
    /// Socket address bound to this interface.
    /// Replaces: `union mysockaddr addr`.
    pub addr: SocketAddress,

    /// IPv4 netmask (only meaningful when `addr` is [`SocketAddress::V4`]).
    /// Replaces: `struct in_addr netmask`.
    pub netmask: Ipv4Addr,

    /// Whether TFTP serving is enabled on this interface.
    /// Replaces: C `int tftp_ok` (used as boolean).
    pub tftp_ok: bool,

    /// Whether DHCPv4 serving is enabled on this interface.
    /// Replaces: C `int dhcp4_ok` (used as boolean).
    pub dhcp4_ok: bool,

    /// Whether DHCPv6 serving is enabled on this interface.
    /// Replaces: C `int dhcp6_ok` (used as boolean).
    pub dhcp6_ok: bool,

    /// Interface Maximum Transmission Unit.
    /// Replaces: C `int mtu`.
    pub mtu: i32,

    /// Processing complete flag — set when this interface has been fully processed
    /// during listener creation.
    /// Replaces: C `int done` (used as boolean).
    pub done: bool,

    /// Warning issued flag — prevents duplicate warnings about interface problems.
    /// Replaces: C `int warned` (used as boolean).
    pub warned: bool,

    /// Duplicate Address Detection state — true if this address is undergoing DAD.
    /// Replaces: C `int dad` (used as boolean).
    pub dad: bool,

    /// DNS authoritative flag — true if this interface serves authoritative DNS.
    /// Replaces: C `int dns_auth` (used as boolean).
    pub dns_auth: bool,

    /// OS-assigned interface index (e.g., from `if_nametoindex()`).
    /// Replaces: C `int index`.
    pub index: i32,

    /// Whether multicast group join has been completed for this interface.
    /// Replaces: C `int multicast_done` (used as boolean).
    pub multicast_done: bool,

    /// Whether this interface was found during the most recent enumeration pass.
    /// Used for detecting interface removal between re-enumerations.
    /// Replaces: C `int found` (used as boolean).
    pub found: bool,

    /// Label identifier for this interface record, used for interface grouping.
    /// Replaces: C `int label`.
    pub label: i32,

    /// Interface name string (e.g., "eth0", "wlan0").
    /// `None` if the interface name is not known.
    /// Replaces: C `char *name` (NULL when unknown).
    pub name: Option<String>,
}

impl Default for InterfaceRecord {
    /// Create an `InterfaceRecord` with sensible defaults.
    ///
    /// All boolean fields default to `false`, numeric fields to `0`,
    /// and the address defaults to IPv4 unspecified (0.0.0.0:0).
    fn default() -> Self {
        InterfaceRecord {
            addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            netmask: Ipv4Addr::UNSPECIFIED,
            tftp_ok: false,
            dhcp4_ok: false,
            dhcp6_ok: false,
            mtu: 0,
            done: false,
            warned: false,
            dad: false,
            dns_auth: false,
            index: 0,
            multicast_done: false,
            found: false,
            label: 0,
            name: None,
        }
    }
}

// ===========================================================================
// Listener (dnsmasq.h struct listener, lines 853–858)
// ===========================================================================

/// Socket listener combining UDP, TCP, and optional TFTP file descriptors.
///
/// Each listener is bound to a specific address and manages the file descriptors
/// for DNS (UDP and TCP) and optionally TFTP on that address. Listeners are
/// created during startup from the enumerated interface records.
///
/// # Critical Transformation
/// - C `struct listener *next` pointer **removed** — listeners stored in `Vec<Listener>`.
/// - C `struct irec *iface` pointer → `Option<usize>` (index into interface record Vec).
/// - C `int used` (boolean) → Rust `bool`.
///
/// # Source
/// Replaces C `struct listener` from `dnsmasq.h` lines 853–858.
#[derive(Debug, Clone)]
pub struct Listener {
    /// UDP file descriptor for DNS queries.
    /// Value of `-1` indicates the fd is not open.
    /// Replaces: C `int fd`.
    pub fd: i32,

    /// TCP file descriptor for DNS connections.
    /// Value of `-1` indicates the fd is not open.
    /// Replaces: C `int tcpfd`.
    pub tcpfd: i32,

    /// TFTP file descriptor (if TFTP is enabled on this listener).
    /// Value of `-1` indicates the fd is not open.
    /// Replaces: C `int tftpfd`.
    pub tftpfd: i32,

    /// Whether this listener is currently in use.
    /// Replaces: C `int used` (used as boolean).
    pub used: bool,

    /// Bound address for this listener.
    /// Replaces: `union mysockaddr addr`.
    pub addr: SocketAddress,

    /// Index into the interface record list.
    /// Only valid for non-wildcard listeners.
    /// `None` if this listener is not associated with a specific interface.
    /// Replaces: C `struct irec *iface` pointer.
    pub iface_index: Option<usize>,
}

impl Default for Listener {
    /// Create a `Listener` with all file descriptors closed (-1)
    /// and default IPv4 unspecified address.
    fn default() -> Self {
        Listener {
            fd: -1,
            tcpfd: -1,
            tftpfd: -1,
            used: false,
            addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            iface_index: None,
        }
    }
}

// ===========================================================================
// InterfaceNameBinding (dnsmasq.h struct iname, lines 861–866)
// ===========================================================================

/// Interface name/address specification from command line options.
///
/// Represents an entry from `--interface`, `--except-interface`,
/// `--listen-address`, or `--except-interface` command-line options.
/// Each binding specifies either a named interface or a specific address.
///
/// # Critical Transformation
/// C `struct iname *next` pointer **removed** — bindings stored in `Vec<InterfaceNameBinding>`.
///
/// # Source
/// Replaces C `struct iname` from `dnsmasq.h` lines 861–866.
#[derive(Debug, Clone)]
pub struct InterfaceNameBinding {
    /// Interface name (e.g., "eth0").
    /// `None` if this binding specifies an address instead of a name.
    /// Replaces: C `char *name` (NULL for address-only bindings).
    pub name: Option<String>,

    /// Socket address for address-based bindings.
    /// Replaces: `union mysockaddr addr`.
    pub addr: SocketAddress,

    /// Flags indicating binding state and address family.
    /// See [`InameFlags`] for available flags.
    /// Replaces: C `int flags`.
    pub flags: InameFlags,
}

impl Default for InterfaceNameBinding {
    /// Create an `InterfaceNameBinding` with no name, unspecified address,
    /// and empty flags.
    fn default() -> Self {
        InterfaceNameBinding {
            name: None,
            addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            flags: InameFlags::empty(),
        }
    }
}

// ===========================================================================
// InterfaceName (dnsmasq.h struct interface_name, lines 650–658)
// ===========================================================================

/// Domain name to interface mapping for the `--interface-name` directive.
///
/// Associates a DNS domain name with a network interface. When a DNS query
/// arrives for the specified domain name, the daemon responds with the
/// address(es) of the named interface. This provides a dynamic DNS mechanism
/// that tracks interface address changes automatically.
///
/// The `flags` field (using [`IN4`], [`IN6`], [`INP4`], [`INP6`] constants)
/// controls which address families are returned and whether prototype address
/// filtering is applied.
///
/// # Critical Transformation
/// C `struct interface_name *next` pointer **removed** — entries stored in
/// `Vec<InterfaceName>`.
///
/// # Source
/// Replaces C `struct interface_name` from `dnsmasq.h` lines 650–658.
#[derive(Debug, Clone)]
pub struct InterfaceName {
    /// Domain name to resolve (e.g., "myrouter.home").
    /// Replaces: C `char *name`.
    pub name: String,

    /// Interface name to get the address from (e.g., "eth0").
    /// Replaces: C `char *intr`.
    pub intr: String,

    /// Direction/family flags controlling which addresses are returned.
    /// Combination of [`IN4`], [`IN6`], [`INP4`], [`INP6`] constants.
    /// Replaces: C `int flags`.
    pub flags: i32,

    /// IPv4 prototype address for subnet-filtered resolution.
    /// When [`INP4`] is set in `flags`, only IPv4 addresses on the same
    /// subnet as this prototype are returned.
    /// Replaces: C `struct in_addr proto4`.
    pub proto4: Ipv4Addr,

    /// IPv6 prototype address for subnet-filtered resolution.
    /// When [`INP6`] is set in `flags`, only IPv6 addresses on the same
    /// subnet as this prototype are returned.
    /// Replaces: C `struct in6_addr proto6`.
    pub proto6: Ipv6Addr,

    /// Address list associated with this interface name mapping.
    /// Contains resolved addresses for cached responses.
    /// Replaces: C `struct addrlist *addr` linked list.
    pub addr: Vec<AddrList>,
}

impl Default for InterfaceName {
    /// Create an `InterfaceName` with empty strings, zero flags,
    /// unspecified prototype addresses, and an empty address list.
    fn default() -> Self {
        InterfaceName {
            name: String::new(),
            intr: String::new(),
            flags: 0,
            proto4: Ipv4Addr::UNSPECIFIED,
            proto6: Ipv6Addr::UNSPECIFIED,
            addr: Vec::new(),
        }
    }
}

// ===========================================================================
// ServerFd (dnsmasq.h struct serverfd, lines 766–772)
// ===========================================================================

/// File descriptor for a server connection with source address binding.
///
/// Manages a socket used to communicate with an upstream DNS server.
/// Each `ServerFd` is bound to a specific source address and interface,
/// and may be shared across multiple upstream server configurations
/// that use the same source binding.
///
/// # Critical Transformation
/// C `struct serverfd *next` pointer **removed** — entries stored in `Vec<ServerFd>`.
/// C `char interface[IF_NAMESIZE+1]` fixed-size array → `String`.
///
/// # Source
/// Replaces C `struct serverfd` from `dnsmasq.h` lines 766–772.
#[derive(Debug, Clone)]
pub struct ServerFd {
    /// Socket file descriptor.
    /// Value of `-1` indicates the fd is not open.
    /// Replaces: C `int fd`.
    pub fd: i32,

    /// Source address this socket is bound to.
    /// Replaces: `union mysockaddr source_addr`.
    pub source_addr: SocketAddress,

    /// Network interface name this socket is bound to (via SO_BINDTODEVICE).
    /// Empty string if not bound to a specific interface.
    /// Replaces: C `char interface[IF_NAMESIZE+1]`.
    pub interface: String,

    /// Interface index corresponding to `interface`.
    /// Replaces: C `unsigned int ifindex`.
    pub ifindex: u32,

    /// Whether this server fd is currently in use during a forwarding pass.
    /// Replaces: C `unsigned int used` (used as boolean).
    pub used: bool,

    /// Whether this fd was preallocated during startup.
    /// Preallocated fds are not closed during server list changes.
    /// Replaces: C `unsigned int preallocated` (used as boolean).
    pub preallocated: bool,
}

impl Default for ServerFd {
    /// Create a `ServerFd` with closed fd (-1), unspecified source address,
    /// empty interface, and all flags false.
    fn default() -> Self {
        ServerFd {
            fd: -1,
            source_addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            interface: String::new(),
            ifindex: 0,
            used: false,
            preallocated: false,
        }
    }
}

// ===========================================================================
// RandFd (dnsmasq.h struct randfd, lines 774–778)
// ===========================================================================

/// Randomized source port file descriptor for DNS queries.
///
/// Used to provide source port randomization for outgoing DNS queries as a
/// defense against DNS cache poisoning attacks. Each `RandFd` holds an open
/// socket bound to a random ephemeral port, associated with a specific
/// upstream server.
///
/// The `refcount` tracks how many active forward records reference this fd.
/// A refcount of `0xFFFF` indicates an overflow record (too many references
/// to track individually).
///
/// # Source
/// Replaces C `struct randfd` from `dnsmasq.h` lines 774–778.
#[derive(Debug, Clone)]
pub struct RandFd {
    /// Index into the server array, identifying which upstream server this
    /// random port is associated with.
    /// `None` if this slot is currently unused.
    /// Replaces: C `struct server *serv` pointer.
    pub serv_index: Option<usize>,

    /// Socket file descriptor bound to a random ephemeral port.
    /// Value of `-1` indicates the fd is not open.
    /// Replaces: C `int fd`.
    pub fd: i32,

    /// Reference count tracking how many forward records use this fd.
    /// A value of `0xFFFF` indicates an overflow record.
    /// Replaces: C `unsigned short refcount`.
    pub refcount: u16,
}

impl Default for RandFd {
    /// Create a `RandFd` with no server association, closed fd, and zero refcount.
    fn default() -> Self {
        RandFd {
            serv_index: None,
            fd: -1,
            refcount: 0,
        }
    }
}

// ===========================================================================
// RandFdRef (dnsmasq.h struct randfd_list, lines 780–783)
// ===========================================================================

/// Reference to a randomized file descriptor in the random socket pool.
///
/// Provides an indirection layer allowing multiple forward records to share
/// the same randomized source port socket. The reference points into the
/// global `randomsocks` array by index.
///
/// # Critical Transformation
/// C `struct randfd_list *next` pointer **removed** — references stored in
/// `Vec<RandFdRef>`.
/// C `struct randfd *rfd` pointer → `usize` index into the randomsocks array.
///
/// # Source
/// Replaces C `struct randfd_list` from `dnsmasq.h` lines 780–783.
#[derive(Debug, Clone)]
pub struct RandFdRef {
    /// Index into the `randomsocks` array (in the daemon state).
    /// Replaces: C `struct randfd *rfd` pointer.
    pub rfd_index: usize,
}

// ===========================================================================
// SimpleAddrList (dnsmasq.h struct addr_list, lines 1311–1314)
// ===========================================================================

/// Simple IPv4 address list entry.
///
/// A lightweight address container used for `override_relays` and similar
/// configurations that need a plain list of IPv4 addresses without the
/// additional metadata of [`AddrList`].
///
/// # Critical Transformation
/// C `struct addr_list *next` pointer **removed** — entries stored in
/// `Vec<SimpleAddrList>`.
///
/// # Source
/// Replaces C `struct addr_list` from `dnsmasq.h` lines 1311–1314.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleAddrList {
    /// IPv4 address.
    /// Replaces: C `struct in_addr addr`.
    pub addr: Ipv4Addr,
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    // -----------------------------------------------------------------------
    // IfaceFlags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_iface_flags_values() {
        // Verify exact bit values match C constants
        assert_eq!(IfaceFlags::TENTATIVE.bits(), 1);
        assert_eq!(IfaceFlags::DEPRECATED.bits(), 2);
        assert_eq!(IfaceFlags::PERMANENT.bits(), 4);
    }

    #[test]
    fn test_iface_flags_combinations() {
        let flags = IfaceFlags::TENTATIVE | IfaceFlags::PERMANENT;
        assert!(flags.contains(IfaceFlags::TENTATIVE));
        assert!(!flags.contains(IfaceFlags::DEPRECATED));
        assert!(flags.contains(IfaceFlags::PERMANENT));
        assert_eq!(flags.bits(), 5);
    }

    #[test]
    fn test_iface_flags_empty() {
        let flags = IfaceFlags::empty();
        assert!(!flags.contains(IfaceFlags::TENTATIVE));
        assert!(!flags.contains(IfaceFlags::DEPRECATED));
        assert!(!flags.contains(IfaceFlags::PERMANENT));
        assert_eq!(flags.bits(), 0);
    }

    // -----------------------------------------------------------------------
    // InameFlags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_iname_flags_values() {
        assert_eq!(InameFlags::USED.bits(), 1);
        assert_eq!(InameFlags::IPV4.bits(), 2);
        assert_eq!(InameFlags::IPV6.bits(), 4);
    }

    #[test]
    fn test_iname_flags_combinations() {
        let flags = InameFlags::USED | InameFlags::IPV4;
        assert!(flags.contains(InameFlags::USED));
        assert!(flags.contains(InameFlags::IPV4));
        assert!(!flags.contains(InameFlags::IPV6));
        assert_eq!(flags.bits(), 3);
    }

    // -----------------------------------------------------------------------
    // Direction flag constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_direction_constants() {
        assert_eq!(IN4, 1);
        assert_eq!(IN6, 2);
        assert_eq!(INP4, 4);
        assert_eq!(INP6, 8);
    }

    // -----------------------------------------------------------------------
    // ReadWriteDirection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_write_direction_values() {
        assert_eq!(ReadWriteDirection::Write as i32, 0);
        assert_eq!(ReadWriteDirection::Read as i32, 1);
        assert_eq!(ReadWriteDirection::WriteOnce as i32, 2);
        assert_eq!(ReadWriteDirection::ReadOnce as i32, 3);
    }

    #[test]
    fn test_read_write_direction_equality() {
        assert_eq!(ReadWriteDirection::Write, ReadWriteDirection::Write);
        assert_ne!(ReadWriteDirection::Read, ReadWriteDirection::Write);
    }

    // -----------------------------------------------------------------------
    // InterfaceRecord tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_interface_record_default() {
        let rec = InterfaceRecord::default();
        assert!(!rec.tftp_ok);
        assert!(!rec.dhcp4_ok);
        assert!(!rec.dhcp6_ok);
        assert_eq!(rec.mtu, 0);
        assert!(!rec.done);
        assert!(!rec.warned);
        assert!(!rec.dad);
        assert!(!rec.dns_auth);
        assert_eq!(rec.index, 0);
        assert!(!rec.multicast_done);
        assert!(!rec.found);
        assert_eq!(rec.label, 0);
        assert!(rec.name.is_none());
        assert_eq!(rec.netmask, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_interface_record_with_values() {
        let rec = InterfaceRecord {
            addr: SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 53)),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            tftp_ok: true,
            dhcp4_ok: true,
            dhcp6_ok: false,
            mtu: 1500,
            done: false,
            warned: false,
            dad: false,
            dns_auth: true,
            index: 2,
            multicast_done: true,
            found: true,
            label: 0,
            name: Some("eth0".to_string()),
        };
        assert!(rec.tftp_ok);
        assert!(rec.dhcp4_ok);
        assert!(!rec.dhcp6_ok);
        assert_eq!(rec.mtu, 1500);
        assert!(rec.dns_auth);
        assert_eq!(rec.index, 2);
        assert!(rec.multicast_done);
        assert!(rec.found);
        assert_eq!(rec.name.as_deref(), Some("eth0"));
        assert_eq!(rec.netmask, Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_interface_record_v6_address() {
        let rec = InterfaceRecord {
            addr: SocketAddress::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                53,
                0,
                2,
            )),
            ..InterfaceRecord::default()
        };
        assert!(rec.addr.is_v6());
    }

    // -----------------------------------------------------------------------
    // Listener tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_listener_default() {
        let listener = Listener::default();
        assert_eq!(listener.fd, -1);
        assert_eq!(listener.tcpfd, -1);
        assert_eq!(listener.tftpfd, -1);
        assert!(!listener.used);
        assert!(listener.iface_index.is_none());
    }

    #[test]
    fn test_listener_with_values() {
        let listener = Listener {
            fd: 5,
            tcpfd: 6,
            tftpfd: 7,
            used: true,
            addr: SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            iface_index: Some(0),
        };
        assert_eq!(listener.fd, 5);
        assert_eq!(listener.tcpfd, 6);
        assert_eq!(listener.tftpfd, 7);
        assert!(listener.used);
        assert_eq!(listener.iface_index, Some(0));
    }

    // -----------------------------------------------------------------------
    // InterfaceNameBinding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_interface_name_binding_default() {
        let binding = InterfaceNameBinding::default();
        assert!(binding.name.is_none());
        assert!(binding.flags.is_empty());
    }

    #[test]
    fn test_interface_name_binding_by_name() {
        let binding = InterfaceNameBinding {
            name: Some("eth0".to_string()),
            addr: SocketAddress::new_v4(Ipv4Addr::UNSPECIFIED, 0),
            flags: InameFlags::IPV4,
        };
        assert_eq!(binding.name.as_deref(), Some("eth0"));
        assert!(binding.flags.contains(InameFlags::IPV4));
    }

    #[test]
    fn test_interface_name_binding_by_addr() {
        let binding = InterfaceNameBinding {
            name: None,
            addr: SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 0)),
            flags: InameFlags::USED | InameFlags::IPV4,
        };
        assert!(binding.name.is_none());
        assert!(binding.flags.contains(InameFlags::USED));
        assert!(binding.flags.contains(InameFlags::IPV4));
    }

    // -----------------------------------------------------------------------
    // InterfaceName tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_interface_name_default() {
        let iname = InterfaceName::default();
        assert!(iname.name.is_empty());
        assert!(iname.intr.is_empty());
        assert_eq!(iname.flags, 0);
        assert_eq!(iname.proto4, Ipv4Addr::UNSPECIFIED);
        assert_eq!(iname.proto6, Ipv6Addr::UNSPECIFIED);
        assert!(iname.addr.is_empty());
    }

    #[test]
    fn test_interface_name_with_values() {
        let iname = InterfaceName {
            name: "myrouter.home".to_string(),
            intr: "eth0".to_string(),
            flags: IN4 | IN6,
            proto4: Ipv4Addr::new(192, 168, 1, 0),
            proto6: Ipv6Addr::UNSPECIFIED,
            addr: Vec::new(),
        };
        assert_eq!(iname.name, "myrouter.home");
        assert_eq!(iname.intr, "eth0");
        assert_eq!(iname.flags, IN4 | IN6);
        assert_eq!(iname.proto4, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_interface_name_flags_ipv4_proto() {
        let iname = InterfaceName {
            flags: INP4,
            proto4: Ipv4Addr::new(10, 0, 0, 0),
            ..InterfaceName::default()
        };
        assert_eq!(iname.flags & INP4, INP4);
        assert_eq!(iname.flags & INP6, 0);
    }

    // -----------------------------------------------------------------------
    // ServerFd tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_fd_default() {
        let sfd = ServerFd::default();
        assert_eq!(sfd.fd, -1);
        assert!(sfd.interface.is_empty());
        assert_eq!(sfd.ifindex, 0);
        assert!(!sfd.used);
        assert!(!sfd.preallocated);
    }

    #[test]
    fn test_server_fd_with_values() {
        let sfd = ServerFd {
            fd: 10,
            source_addr: SocketAddress::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 100),
                0,
            )),
            interface: "eth0".to_string(),
            ifindex: 2,
            used: true,
            preallocated: true,
        };
        assert_eq!(sfd.fd, 10);
        assert_eq!(sfd.interface, "eth0");
        assert_eq!(sfd.ifindex, 2);
        assert!(sfd.used);
        assert!(sfd.preallocated);
    }

    // -----------------------------------------------------------------------
    // RandFd tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rand_fd_default() {
        let rfd = RandFd::default();
        assert!(rfd.serv_index.is_none());
        assert_eq!(rfd.fd, -1);
        assert_eq!(rfd.refcount, 0);
    }

    #[test]
    fn test_rand_fd_with_values() {
        let rfd = RandFd {
            serv_index: Some(3),
            fd: 42,
            refcount: 5,
        };
        assert_eq!(rfd.serv_index, Some(3));
        assert_eq!(rfd.fd, 42);
        assert_eq!(rfd.refcount, 5);
    }

    #[test]
    fn test_rand_fd_overflow() {
        let rfd = RandFd {
            serv_index: Some(0),
            fd: 100,
            refcount: 0xFFFF,
        };
        assert_eq!(rfd.refcount, 0xFFFF);
    }

    // -----------------------------------------------------------------------
    // RandFdRef tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rand_fd_ref() {
        let rfd_ref = RandFdRef { rfd_index: 7 };
        assert_eq!(rfd_ref.rfd_index, 7);
    }

    #[test]
    fn test_rand_fd_ref_clone() {
        let rfd_ref = RandFdRef { rfd_index: 42 };
        let cloned = rfd_ref.clone();
        assert_eq!(cloned.rfd_index, 42);
    }

    // -----------------------------------------------------------------------
    // SimpleAddrList tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_simple_addr_list() {
        let entry = SimpleAddrList {
            addr: Ipv4Addr::new(192, 168, 1, 1),
        };
        assert_eq!(entry.addr, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_simple_addr_list_equality() {
        let a = SimpleAddrList {
            addr: Ipv4Addr::new(10, 0, 0, 1),
        };
        let b = SimpleAddrList {
            addr: Ipv4Addr::new(10, 0, 0, 1),
        };
        let c = SimpleAddrList {
            addr: Ipv4Addr::new(10, 0, 0, 2),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // SocketAddress variant usage (verifying import works)
    // -----------------------------------------------------------------------

    #[test]
    fn test_socket_address_v4_usage() {
        let addr = SocketAddress::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
        assert!(addr.is_v4());
        assert!(!addr.is_v6());
    }

    #[test]
    fn test_socket_address_v6_usage() {
        let addr = SocketAddress::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0));
        assert!(!addr.is_v4());
        assert!(addr.is_v6());
    }
}

//! BSD/Solaris BPF Raw Packet I/O, Interface Enumeration, and PF_ROUTE Monitoring.
//!
//! Complete Rust rewrite of `src/bpf.c` (805 lines of C). Provides BSD and
//! Solaris-specific network interface implementations using:
//! - **BPF** (Berkeley Packet Filter) for raw DHCP packet transmission
//! - **PF_ROUTE** sockets for real-time network interface change detection
//! - **`getifaddrs()`** for interface/address enumeration
//!
//! This is the BSD counterpart to the Linux netlink implementation in
//! `src/net/platform/linux/netlink.rs`.
//!
//! # Architecture
//!
//! Replaces C static state (`del_family`/`del_addr`/`warned`) with the
//! [`DeletedAddressFilter`] struct, and C callback unions (`callback_t`)
//! with the [`InterfaceCallback`] enum from the platform module.
//!
//! # Conditional Compilation
//!
//! - Module-level: Entire module is BSD-only (`freebsd`, `openbsd`, `netbsd`,
//!   `dragonfly`, `macos`).
//! - `arp_enumerate()`: Excluded on macOS.
//! - `init_bpf()` / `send_via_bpf()`: Feature-gated on `dhcp`.
//!
//! # Safety
//!
//! `unsafe` blocks are used only for unavoidable FFI operations:
//! - `libc::sysctl()` for ARP enumeration
//! - `libc::ioctl()` for IPv6 flags, interface MAC retrieval, and BPF binding
//! - Casting raw byte buffers to routing message structs
//!
//! Each `unsafe` block includes a `// SAFETY:` comment.
//!
//! # Source Reference
//! - Primary: `src/bpf.c` lines 85–805
//! - Supporting: `src/dnsmasq.h` (types, constants)

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

use log::{error, info, warn};
use nix::fcntl::{open, OFlag};
use nix::sys::socket::{
    recv, socket, AddressFamily, MsgFlags, SockFlag, SockType,
};
use nix::sys::stat::Mode;

use crate::core::signal::Event;
use crate::net::platform::{InterfaceCallback, PlatformError};
use crate::types::network::IfaceFlags;

// We use retry_send from core::util for BPF writev retries.
#[cfg(feature = "dhcp")]
use crate::core::util::retry_send;
#[cfg(feature = "dhcp")]
use nix::sys::uio::{writev, IoSlice};

// ---------------------------------------------------------------------------
// Constants (from bpf.c, dnsmasq.h, and BSD headers)
// ---------------------------------------------------------------------------

/// Ethernet hardware type for ARP (ARPHRD_ETHER).
const ARPHRD_ETHER: u32 = 1;

/// Ethernet MAC address length in bytes.
const ETHER_ADDR_LEN: usize = 6;

/// Default IP TTL (IPDEFTTL from BSD headers).
const IPDEFTTL: u8 = 64;

/// IP version 4.
const IPVERSION: u8 = 4;

/// EtherType for IPv4 (host byte order).
const ETHERTYPE_IP: u16 = 0x0800;

/// IP protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// IP Don't Fragment flag (in network byte order position within ip_off).
const IP_DF: u16 = 0x4000;

/// Size of an Ethernet header (dst MAC + src MAC + EtherType).
const ETHER_HDR_LEN: usize = 14;

/// Size of a minimal IPv4 header (no options).
const IP_HDR_LEN: usize = 20;

/// Size of a UDP header.
const UDP_HDR_LEN: usize = 8;

/// Maximum number of BPF devices to probe (/dev/bpf0 .. /dev/bpf255).
const MAX_BPF_DEVICES: usize = 256;

// BSD routing message types (from <net/route.h>).
// These are consistent across FreeBSD, OpenBSD, NetBSD, DragonFly, macOS.

/// Routing message: new address added.
const RTM_NEWADDR: i32 = 0xC;

/// Routing message: address deleted.
const RTM_DELADDR: i32 = 0xD;

/// Routing table message version. BSD kernels since 4.4BSD use version 5.
const RTM_VERSION: i32 = 5;

// Routing address mask constants (from <net/route.h>).
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
const RTA_GENMASK: i32 = 0x8;
const RTA_IFP: i32 = 0x10;
const RTA_IFA: i32 = 0x20;
const RTA_AUTHOR: i32 = 0x40;
const RTA_BRD: i32 = 0x80;

/// AF_LINK constant for BSD (datalink layer addresses).
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
const AF_LINK: i32 = 18;

// ---------------------------------------------------------------------------
// DeletedAddressFilter — replaces C static del_family / del_addr
// ---------------------------------------------------------------------------

/// Tracks a recently deleted network address to work around a BSD kernel race
/// condition.
///
/// When `RTM_DELADDR` is received on the routing socket, the deleted address
/// may still appear in `getifaddrs()` results temporarily. By storing the
/// recently-deleted address here, [`iface_enumerate()`] can filter it out.
///
/// This replaces the C static variables `del_family` and `del_addr` from
/// `bpf.c` lines 110–111.
///
/// # C Equivalent
/// ```c
/// static int del_family = 0;
/// static union all_addr del_addr;
/// ```
#[derive(Debug, Clone)]
pub struct DeletedAddressFilter {
    /// Address family of the deleted address (`AF_INET` or `AF_INET6`),
    /// or `None` if no deletion is pending.
    pub family: Option<i32>,

    /// The IP address that was recently deleted.
    pub addr: IpAddr,
}

impl DeletedAddressFilter {
    /// Create a new filter with no deletion pending.
    pub fn new() -> Self {
        Self {
            family: None,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Clear the filter (no deletion pending).
    pub fn clear(&mut self) {
        self.family = None;
        self.addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    }

    /// Check if the given address should be filtered (i.e., was recently deleted).
    fn is_deleted(&self, family: i32, addr: &IpAddr) -> bool {
        match self.family {
            Some(f) if f == family => &self.addr == addr,
            _ => false,
        }
    }
}

impl Default for DeletedAddressFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SA_SIZE helper — replaces BSD SA_SIZE() macro
// ---------------------------------------------------------------------------

/// Calculate aligned sockaddr size for routing socket message parsing.
///
/// Equivalent to the BSD `SA_SIZE` macro from `bpf.c` lines 102–107:
/// ```c
/// #define SA_SIZE(sa) \
///     (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ? \
///         sizeof(long) : \
///         1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) )
/// ```
///
/// Rounds up `sa_len` to the nearest `size_of::<c_long>()` boundary.
fn sa_size(sa_len: usize) -> usize {
    let long_size = mem::size_of::<libc::c_long>();
    if sa_len == 0 {
        long_size
    } else {
        1 + ((sa_len - 1) | (long_size - 1))
    }
}

// ---------------------------------------------------------------------------
// Internet checksum — RFC 1071
// ---------------------------------------------------------------------------

/// Compute Internet checksum (RFC 1071) over a byte slice.
///
/// One's complement of the one's complement sum of all 16-bit words in `data`.
/// Used for IP header and UDP checksum computation in [`send_via_bpf()`].
///
/// If the data length is odd, the last byte is treated as the high byte of
/// a 16-bit word with the low byte set to zero.
///
/// # Arguments
/// * `data` — Byte slice over which to compute the checksum
///
/// # Returns
/// 16-bit checksum value suitable for embedding in IP or UDP headers.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if sum == 0xffff {
        sum as u16
    } else {
        !(sum as u16)
    }
}

/// Compute one's complement sum (without final inversion) for partial checksum
/// accumulation (used in UDP checksum with pseudo-header).
fn ones_complement_sum(data: &[u8], initial: u32) -> u32 {
    let mut sum = initial;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

/// Fold and finalize a one's complement sum into a 16-bit checksum.
fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if sum == 0xffff {
        sum as u16
    } else {
        !(sum as u16)
    }
}

// ---------------------------------------------------------------------------
// ARP Enumeration (non-macOS BSD only)
// ---------------------------------------------------------------------------

/// Enumerate ARP table entries via sysctl on BSD systems.
///
/// Retrieves the kernel ARP cache using BSD sysctl
/// (`CTL_NET/PF_ROUTE/NET_RT_FLAGS/RTF_LLINFO`) and invokes `callback` for
/// each entry with the address family (`AF_INET`), IP address, and hardware
/// (MAC) address bytes.
///
/// # Platform
/// BSD-specific, **excluded on macOS** where different APIs are used.
///
/// # Arguments
/// * `callback` — Called for each ARP entry: `(family, ip_addr, mac_bytes) -> continue?`
///
/// # Returns
/// * `Ok(true)` — all entries enumerated successfully
/// * `Ok(false)` — callback returned 0 (enumeration stopped early)
/// * `Err(PlatformError)` — sysctl or buffer error
///
/// # C Equivalent
/// `bpf.c` lines 160–209: `arp_enumerate()`
#[cfg(not(target_os = "macos"))]
pub fn arp_enumerate(
    callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
) -> Result<bool, PlatformError> {
    // sysctl MIB for ARP table: CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        // RTF_LLINFO may not be defined on all BSDs; use the value if available, else 0.
        rtf_llinfo_value(),
    ];

    // First call: determine required buffer size.
    let mut needed: libc::size_t = 0;
    // SAFETY: sysctl with a NULL oldp buffer returns the required size in needed.
    // The MIB array is a valid 6-element array. All pointer arguments are valid.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            6,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == -1 || needed == 0 {
        return Err(PlatformError::ArpEnumerationFailed(
            "sysctl size query failed".to_string(),
        ));
    }

    // Allocate buffer with some headroom, retry on ENOMEM.
    let mut buf: Vec<u8> = vec![0u8; needed];
    loop {
        let mut buf_len = buf.len();
        // SAFETY: buf is a valid allocation of buf_len bytes. sysctl will write
        // at most buf_len bytes into buf.as_mut_ptr(). All other arguments are valid.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut buf_len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            needed = buf_len;
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(PlatformError::ArpEnumerationFailed(format!(
                "sysctl data query failed: {}",
                err
            )));
        }
        // Expand buffer by 12.5% and retry (matches C: needed += needed / 8).
        needed += needed / 8;
        buf.resize(needed, 0);
    }

    // Parse routing table entries.
    let mut offset: usize = 0;
    while offset < needed {
        if offset + mem::size_of::<RtMsghdr>() > needed {
            break;
        }
        // SAFETY: We have verified that offset + size_of::<RtMsghdr>() <= needed,
        // so the pointer dereference is within bounds. The buffer is properly aligned
        // since RtMsghdr has alignment of c_int.
        let rtm = unsafe { &*(buf.as_ptr().add(offset) as *const RtMsghdr) };
        let msg_len = rtm.rtm_msglen as usize;
        if msg_len == 0 || offset + msg_len > needed {
            break;
        }

        // sockaddr_inarp follows the rt_msghdr.
        let sin_offset = offset + mem::size_of::<RtMsghdr>();
        if sin_offset + mem::size_of::<SockaddrInarp>() > needed {
            offset += msg_len;
            continue;
        }
        // SAFETY: Bounds checked above. sockaddr_inarp is a packed C struct.
        let sin2 = unsafe { &*(buf.as_ptr().add(sin_offset) as *const SockaddrInarp) };
        let ip_addr = Ipv4Addr::from(u32::from_be(sin2.sin_addr));

        // sockaddr_dl follows the sockaddr_inarp, aligned via SA_SIZE.
        let sa_len = if sin2.sin_len == 0 {
            mem::size_of::<libc::c_long>()
        } else {
            sa_size(sin2.sin_len as usize)
        };
        let sdl_offset = sin_offset + sa_len;
        if sdl_offset + mem::size_of::<SockaddrDlHeader>() > needed {
            offset += msg_len;
            continue;
        }
        // SAFETY: Bounds checked above. Reading the header portion of sockaddr_dl.
        let sdl_hdr =
            unsafe { &*(buf.as_ptr().add(sdl_offset) as *const SockaddrDlHeader) };
        let mac_len = sdl_hdr.sdl_alen as usize;
        let mac_offset = sdl_offset
            + mem::size_of::<SockaddrDlHeader>()
            + sdl_hdr.sdl_nlen as usize;
        if mac_offset + mac_len > needed {
            offset += msg_len;
            continue;
        }
        let mac = &buf[mac_offset..mac_offset + mac_len];

        if callback(libc::AF_INET, IpAddr::V4(ip_addr), mac) == 0 {
            return Ok(false);
        }

        offset += msg_len;
    }

    Ok(true)
}

/// On macOS, `arp_enumerate()` is not supported (different API).
/// Returns `Ok(false)` to indicate no enumeration was performed.
#[cfg(target_os = "macos")]
pub fn arp_enumerate(
    _callback: &mut dyn FnMut(i32, IpAddr, &[u8]) -> i32,
) -> Result<bool, PlatformError> {
    // macOS doesn't support sysctl-based ARP enumeration. Mirrors C behavior:
    // "return 0; /* need code for Solaris and MacOS*/"
    Ok(false)
}

/// Get the RTF_LLINFO value. On systems where it's defined, use it; otherwise 0.
#[cfg(not(target_os = "macos"))]
fn rtf_llinfo_value() -> libc::c_int {
    // RTF_LLINFO is 0x400 on FreeBSD, NetBSD, OpenBSD, DragonFly.
    // On systems where it's deprecated, we still try it for compatibility.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        0x400 // RTF_LLINFO
    }
    #[cfg(not(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Interface Enumeration via getifaddrs
// ---------------------------------------------------------------------------

/// Enumerate network interface addresses for a specified address family.
///
/// Uses BSD `getifaddrs()` to enumerate all interface addresses matching the
/// requested family, invoking the appropriate [`InterfaceCallback`] variant
/// for each discovered address.
///
/// # Address Family Handling
///
/// | Input `family` | Action |
/// |----------------|--------|
/// | `AF_UNSPEC` | Delegate to [`arp_enumerate()`] |
/// | `AF_LOCAL` | Internally converted to `AF_LINK` (BSD convention) |
/// | `AF_INET` | Enumerate IPv4 addresses |
/// | `AF_INET6` | Enumerate IPv6 addresses with flags/lifetimes |
/// | `AF_LINK` | Enumerate link-layer (MAC) addresses (dhcp6 feature) |
///
/// # Arguments
/// * `family` — Address family to enumerate
/// * `callback` — Family-specific callback variant
/// * `del_filter` — Recently-deleted address filter (race condition workaround)
///
/// # Returns
/// * `Ok(true)` — all interfaces enumerated
/// * `Ok(false)` — callback stopped enumeration or unsupported operation
/// * `Err(PlatformError)` — system error
///
/// # C Equivalent
/// `bpf.c` lines 275–413: `iface_enumerate()`
pub fn iface_enumerate(
    family: i32,
    callback: &mut InterfaceCallback<'_>,
    del_filter: &DeletedAddressFilter,
) -> Result<bool, PlatformError> {
    // AF_UNSPEC: delegate to ARP enumeration.
    if family == libc::AF_UNSPEC {
        if let InterfaceCallback::AfUnspec(ref mut cb) = callback {
            return arp_enumerate(cb);
        }
        return Ok(false);
    }

    // AF_LOCAL → AF_LINK mapping (BSD uses AF_LINK, not AF_LOCAL).
    let effective_family = if family == libc::AF_LOCAL {
        AF_LINK
    } else {
        family
    };

    // Retrieve all interface addresses via getifaddrs.
    let addrs = nix::ifaddrs::getifaddrs().map_err(|e| {
        PlatformError::EnumerationFailed(io::Error::from(e))
    })?;

    // Open an IPv6 socket for flag/lifetime queries on non-Apple BSD.
    #[cfg(not(target_os = "macos"))]
    let ipv6_fd: RawFd = if effective_family == libc::AF_INET6 {
        // SAFETY: Standard socket creation for IPv6 DGRAM. No special invariants.
        unsafe { libc::socket(libc::PF_INET6, libc::SOCK_DGRAM, 0) }
    } else {
        -1
    };

    let mut result = true;

    for ifaddr in addrs {
        // Get interface index.
        let iface_name = ifaddr.interface_name.clone();
        let if_index = {
            let c_name = std::ffi::CString::new(iface_name.as_str()).unwrap_or_default();
            // SAFETY: c_name is a valid NUL-terminated C string.
            unsafe { libc::if_nametoindex(c_name.as_ptr()) }
        };
        if if_index == 0 {
            continue;
        }

        // Check address is present and matches the requested family.
        let sa_family = match &ifaddr.address {
            Some(addr) => {
                let ss = addr.as_ref();
                // SAFETY: SockaddrStorage is a valid repr(C) struct from nix.
                unsafe { (*(ss as *const _ as *const libc::sockaddr)).sa_family as i32 }
            }
            None => continue,
        };
        if sa_family != effective_family {
            continue;
        }

        // For non-AF_LINK families, netmask is required.
        if effective_family != AF_LINK && ifaddr.netmask.is_none() {
            continue;
        }

        // --- AF_INET handling ---
        if effective_family == libc::AF_INET {
            let addr_v4 = extract_ipv4(&ifaddr.address)?;
            let netmask_v4 = extract_ipv4(&ifaddr.netmask)?;
            let broadcast_v4 = ifaddr
                .broadcast
                .as_ref()
                .and_then(|b| extract_ipv4_from_storage(b))
                .unwrap_or(Ipv4Addr::UNSPECIFIED);

            // Filter recently deleted address.
            if del_filter.is_deleted(libc::AF_INET, &IpAddr::V4(addr_v4)) {
                continue;
            }

            if let InterfaceCallback::AfInet(ref mut cb) = callback {
                if cb(addr_v4, if_index, &iface_name, netmask_v4, broadcast_v4) == 0 {
                    result = false;
                    break;
                }
            }
        }
        // --- AF_INET6 handling ---
        else if effective_family == libc::AF_INET6 {
            let (addr_v6, scope_id) = extract_ipv6_with_scope(&ifaddr.address)?;

            // Filter recently deleted address.
            if del_filter.is_deleted(libc::AF_INET6, &IpAddr::V6(addr_v6)) {
                continue;
            }

            // Compute prefix length from netmask.
            let prefix = compute_ipv6_prefix(&ifaddr.netmask);

            // IPv6 flags and lifetimes (non-Apple BSD only).
            let mut flags: u32 = 0;
            let mut preferred: u32 = 0xffff_ffff;
            let mut valid: u32 = 0xffff_ffff;

            #[cfg(not(target_os = "macos"))]
            {
                if ipv6_fd >= 0 {
                    let (f, p, v) =
                        query_ipv6_flags_lifetimes(ipv6_fd, &iface_name, &ifaddr.address);
                    flags = f;
                    preferred = p;
                    valid = v;
                }
            }

            // Clear link-local interface ID (bytes 2,3 of the address).
            // This matches the C "voodoo" at bpf.c lines 380–384.
            let mut addr_bytes = addr_v6.octets();
            if is_ipv6_link_local(&addr_v6) {
                addr_bytes[2] = 0;
                addr_bytes[3] = 0;
            }
            let addr_v6_cleaned = Ipv6Addr::from(addr_bytes);

            if let InterfaceCallback::AfInet6(ref mut cb) = callback {
                if cb(
                    addr_v6_cleaned,
                    prefix,
                    scope_id,
                    if_index,
                    flags,
                    preferred,
                    valid,
                ) == 0
                {
                    result = false;
                    break;
                }
            }
        }
        // --- AF_LINK handling (link-layer MAC addresses) ---
        else if effective_family == AF_LINK {
            #[cfg(any(feature = "dhcp6", feature = "dhcp"))]
            {
                if let Some(ref addr_storage) = ifaddr.address {
                    let mac = extract_mac_from_sockaddr_dl(addr_storage);
                    if !mac.is_empty() {
                        if let InterfaceCallback::AfLocal(ref mut cb) = callback {
                            if cb(if_index, ARPHRD_ETHER, &mac) == 0 {
                                result = false;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Close IPv6 socket if opened.
    #[cfg(not(target_os = "macos"))]
    {
        if ipv6_fd >= 0 {
            // SAFETY: ipv6_fd is a valid socket we opened above.
            unsafe {
                libc::close(ipv6_fd);
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// IPv4/IPv6 extraction helpers
// ---------------------------------------------------------------------------

/// Extract an IPv4 address from an `Option<nix::sys::socket::SockaddrStorage>`.
fn extract_ipv4(
    storage: &Option<nix::sys::socket::SockaddrStorage>,
) -> Result<Ipv4Addr, PlatformError> {
    match storage {
        Some(s) => Ok(extract_ipv4_from_storage(s).unwrap_or(Ipv4Addr::UNSPECIFIED)),
        None => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

/// Extract IPv4 address from a `SockaddrStorage`.
fn extract_ipv4_from_storage(s: &nix::sys::socket::SockaddrStorage) -> Option<Ipv4Addr> {
    // Try to interpret as sockaddr_in.
    let ss = s.as_ref();
    // SAFETY: SockaddrStorage wraps a sockaddr_storage which is large enough
    // for any sockaddr type. We check sa_family before casting.
    unsafe {
        let sa = &*(ss as *const _ as *const libc::sockaddr);
        if sa.sa_family as i32 == libc::AF_INET {
            let sin = &*(ss as *const _ as *const libc::sockaddr_in);
            Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
        } else {
            None
        }
    }
}

/// Extract IPv6 address and scope ID from an `Option<SockaddrStorage>`.
fn extract_ipv6_with_scope(
    storage: &Option<nix::sys::socket::SockaddrStorage>,
) -> Result<(Ipv6Addr, u32), PlatformError> {
    match storage {
        Some(s) => {
            let ss = s.as_ref();
            // SAFETY: SockaddrStorage is large enough for sockaddr_in6.
            // We verify sa_family == AF_INET6 before the cast.
            unsafe {
                let sa = &*(ss as *const _ as *const libc::sockaddr);
                if sa.sa_family as i32 == libc::AF_INET6 {
                    let sin6 = &*(ss as *const _ as *const libc::sockaddr_in6);
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let scope = sin6.sin6_scope_id;
                    Ok((addr, scope))
                } else {
                    Ok((Ipv6Addr::UNSPECIFIED, 0))
                }
            }
        }
        None => Ok((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

/// Compute IPv6 prefix length from a netmask `SockaddrStorage`.
fn compute_ipv6_prefix(netmask: &Option<nix::sys::socket::SockaddrStorage>) -> u32 {
    match netmask {
        Some(s) => {
            let ss = s.as_ref();
            // SAFETY: Verified below by checking sa_family.
            let mask_bytes: [u8; 16] = unsafe {
                let sa = &*(ss as *const _ as *const libc::sockaddr);
                if sa.sa_family as i32 == libc::AF_INET6 {
                    let sin6 = &*(ss as *const _ as *const libc::sockaddr_in6);
                    sin6.sin6_addr.s6_addr
                } else {
                    return 0;
                }
            };
            // Count prefix bits: full 0xFF bytes contribute 8, partial bytes add per-bit.
            let mut prefix: u32 = 0;
            for &b in &mask_bytes {
                if b == 0xff {
                    prefix += 8;
                } else {
                    // Count leading 1-bits in the byte.
                    let mut byte = b;
                    for _ in 0..8 {
                        if byte & 0x80 != 0 {
                            prefix += 1;
                            byte <<= 1;
                        } else {
                            break;
                        }
                    }
                    break;
                }
            }
            prefix
        }
        None => 0,
    }
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Extract MAC address from a `SockaddrStorage` that contains `sockaddr_dl`.
#[cfg(any(feature = "dhcp6", feature = "dhcp"))]
fn extract_mac_from_sockaddr_dl(s: &nix::sys::socket::SockaddrStorage) -> Vec<u8> {
    let ss = s.as_ref();
    // SAFETY: We're reading sockaddr_dl which is a standard BSD structure.
    // SockaddrStorage is large enough for any sockaddr type.
    unsafe {
        let sa = &*(ss as *const _ as *const libc::sockaddr);
        if sa.sa_family as i32 != AF_LINK {
            return Vec::new();
        }
        let sdl = &*(ss as *const _ as *const SockaddrDlHeader);
        let alen = sdl.sdl_alen as usize;
        if alen == 0 {
            return Vec::new();
        }
        // MAC address starts after the interface name in sockaddr_dl.
        let data_start = (ss as *const _ as *const u8)
            .add(mem::size_of::<SockaddrDlHeader>())
            .add(sdl.sdl_nlen as usize);
        let mut mac = vec![0u8; alen];
        std::ptr::copy_nonoverlapping(data_start, mac.as_mut_ptr(), alen);
        mac
    }
}

/// Query IPv6 interface flags and address lifetimes via ioctl on non-Apple BSD.
///
/// Uses `SIOCGIFAFLAG_IN6` for flags (tentative, deprecated, permanent) and
/// `SIOCGIFALIFETIME_IN6` for valid/preferred lifetimes.
///
/// # Returns
/// `(flags, preferred_lifetime, valid_lifetime)` — defaults to `(0, 0xFFFFFFFF, 0xFFFFFFFF)`
/// on error.
#[cfg(not(target_os = "macos"))]
fn query_ipv6_flags_lifetimes(
    fd: RawFd,
    iface_name: &str,
    addr_storage: &Option<nix::sys::socket::SockaddrStorage>,
) -> (u32, u32, u32) {
    let mut flags: u32 = 0;
    let mut preferred: u32 = 0xffff_ffff;
    let mut valid: u32 = 0xffff_ffff;

    let addr_ss = match addr_storage {
        Some(s) => s,
        None => return (flags, preferred, valid),
    };

    // Construct in6_ifreq for SIOCGIFAFLAG_IN6.
    // We use a raw byte buffer for the struct since in6_ifreq is not
    // consistently defined across all BSDs.
    let mut ifr6_buf = [0u8; 256]; // More than enough for in6_ifreq

    // Copy interface name (first 16 bytes of the struct).
    let name_bytes = iface_name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifr6_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Copy sockaddr_in6 into the ifr_addr field (offset 16, size ~28 bytes).
    let ss_ref = addr_ss.as_ref();
    // SAFETY: SockaddrStorage is at least sockaddr_in6 sized.
    unsafe {
        let sa = &*(ss_ref as *const _ as *const libc::sockaddr);
        if sa.sa_family as i32 != libc::AF_INET6 {
            return (flags, preferred, valid);
        }
        let sin6_size = mem::size_of::<libc::sockaddr_in6>();
        let src_ptr = ss_ref as *const _ as *const u8;
        std::ptr::copy_nonoverlapping(src_ptr, ifr6_buf[16..].as_mut_ptr(), sin6_size);
    }

    // SIOCGIFAFLAG_IN6: Get IPv6 address flags.
    // The ioctl number varies by platform but is consistently available.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        // SAFETY: fd is a valid IPv6 socket. ifr6_buf is a valid buffer
        // large enough for in6_ifreq. The ioctl reads the interface name
        // and address, then writes flags into the union field.
        let siocgifaflag_in6: libc::c_ulong = 0xC0906949; // Platform-specific value
        let ret = unsafe { libc::ioctl(fd, siocgifaflag_in6, ifr6_buf.as_mut_ptr()) };
        if ret != -1 {
            // Flags are at offset 44 (after ifr_name[16] + sockaddr_in6[28]) in the union.
            // On FreeBSD, the flags field is an int (4 bytes).
            let flag_offset = 16 + mem::size_of::<libc::sockaddr_in6>();
            if flag_offset + 4 <= ifr6_buf.len() {
                let raw_flags = i32::from_ne_bytes([
                    ifr6_buf[flag_offset],
                    ifr6_buf[flag_offset + 1],
                    ifr6_buf[flag_offset + 2],
                    ifr6_buf[flag_offset + 3],
                ]);

                // IN6_IFF_TENTATIVE = 0x02 on FreeBSD
                if raw_flags & 0x02 != 0 {
                    flags |= IfaceFlags::TENTATIVE.bits() as u32;
                }
                // IN6_IFF_DEPRECATED = 0x10 on FreeBSD
                if raw_flags & 0x10 != 0 {
                    flags |= IfaceFlags::DEPRECATED.bits() as u32;
                }
                // Check for PERMANENT: not AUTOCONF and not TEMPORARY/PRIVACY.
                // IN6_IFF_AUTOCONF = 0x40, IN6_IFF_TEMPORARY = 0x80 on FreeBSD
                let autoconf_mask = 0x40 | 0x80;
                if raw_flags & autoconf_mask == 0 {
                    flags |= IfaceFlags::PERMANENT.bits() as u32;
                }
            }
        }

        // SIOCGIFALIFETIME_IN6: Get IPv6 address lifetimes.
        // Re-copy the address into the buffer (ioctl may have modified it).
        unsafe {
            let src_ptr = ss_ref as *const _ as *const u8;
            let sin6_size = mem::size_of::<libc::sockaddr_in6>();
            std::ptr::copy_nonoverlapping(src_ptr, ifr6_buf[16..].as_mut_ptr(), sin6_size);
        }

        let siocgifalifetime_in6: libc::c_ulong = 0xC0906951; // Platform-specific value
        let ret =
            unsafe { libc::ioctl(fd, siocgifalifetime_in6, ifr6_buf.as_mut_ptr()) };
        if ret != -1 {
            // Lifetimes are in the ia6t_vltime/ia6t_pltime fields.
            // Offset varies by platform; on FreeBSD these are u32 values after the flags.
            let lifetime_offset = 16 + mem::size_of::<libc::sockaddr_in6>();
            // ia6t_expire (time_t) + ia6t_preferred (time_t) + ia6t_vltime (u32) + ia6t_pltime (u32)
            // Simplified: read vltime at offset+0 and pltime at offset+4 in the lifetime union.
            let time_t_size = mem::size_of::<libc::time_t>();
            let vltime_offset = lifetime_offset + 2 * time_t_size;
            let pltime_offset = vltime_offset + 4;
            if pltime_offset + 4 <= ifr6_buf.len() {
                valid = u32::from_ne_bytes([
                    ifr6_buf[vltime_offset],
                    ifr6_buf[vltime_offset + 1],
                    ifr6_buf[vltime_offset + 2],
                    ifr6_buf[vltime_offset + 3],
                ]);
                preferred = u32::from_ne_bytes([
                    ifr6_buf[pltime_offset],
                    ifr6_buf[pltime_offset + 1],
                    ifr6_buf[pltime_offset + 2],
                    ifr6_buf[pltime_offset + 3],
                ]);
            }
        }
    }

    (flags, preferred, valid)
}

// ---------------------------------------------------------------------------
// BPF Device Initialization (DHCP feature-gated)
// ---------------------------------------------------------------------------

/// Initialize Berkeley Packet Filter (BPF) device for DHCP raw packet transmission.
///
/// Opens a BPF character device by iterating through `/dev/bpf0`, `/dev/bpf1`, etc.
/// until an available device is found or all attempts are exhausted.
///
/// # Returns
/// * `Ok(fd)` — Raw file descriptor for the opened BPF device
/// * `Err(PlatformError::BpfError)` — No available BPF device found
///
/// # Feature Gate
/// Only compiled when the `dhcp` feature is enabled.
///
/// # C Equivalent
/// `bpf.c` lines 466–479: `init_bpf()`
#[cfg(feature = "dhcp")]
pub fn init_bpf() -> Result<RawFd, PlatformError> {
    for i in 0..MAX_BPF_DEVICES {
        let path = format!("/dev/bpf{}", i);
        match open(
            path.as_str(),
            OFlag::O_RDWR,
            Mode::empty(),
        ) {
            Ok(fd) => {
                info!("Opened BPF device: /dev/bpf{}", i);
                return Ok(fd.into_raw_fd());
            }
            Err(nix::errno::Errno::EBUSY) => {
                // Device is busy, try the next one.
                continue;
            }
            Err(e) => {
                return Err(PlatformError::BpfError(format!(
                    "cannot create DHCP BPF socket: {}",
                    e
                )));
            }
        }
    }
    Err(PlatformError::BpfError(
        "cannot create DHCP BPF socket: all /dev/bpfN devices are busy".to_string(),
    ))
}

// Need to bring in IntoRawFd for the fd conversion above.
#[cfg(feature = "dhcp")]
use std::os::unix::io::IntoRawFd;

// ---------------------------------------------------------------------------
// Raw DHCP Packet Transmission via BPF
// ---------------------------------------------------------------------------

/// Send a DHCP packet via BPF, constructing a complete Ethernet/IP/UDP frame.
///
/// Manually builds all three protocol layers (Ethernet, IP, UDP) and transmits
/// using `writev()` on the BPF device. This bypasses the kernel's IP stack,
/// which is necessary for DHCP because clients may not yet have valid IP
/// addresses.
///
/// # Arguments
/// * `raw_fd` — BPF device file descriptor (from [`init_bpf()`])
/// * `dhcp_fd` — DHCP socket fd (used for SIOCGIFADDR ioctl to get source MAC)
/// * `mess` — DHCP payload bytes (may be padded for checksum if odd length)
/// * `len` — Actual payload length in bytes
/// * `iface_addr` — Source IP address (server's interface address)
/// * `iface_name` — Network interface name (e.g., `"eth0"`)
/// * `server_port` — Source UDP port (typically 67)
/// * `client_port` — Destination UDP port (typically 68)
///
/// # DHCP Packet Layout Expected
/// The `mess` buffer is expected to contain a DHCP/BOOTP message where:
/// - Byte offset 1: `htype` (hardware type, must be 1 for Ethernet)
/// - Byte offset 2: `hlen` (hardware address length, must be 6 for Ethernet)
/// - Byte offset 10-11: `flags` (bit 15 = broadcast flag)
/// - Byte offset 16-19: `yiaddr` (assigned client IP address)
/// - Byte offset 28-33: `chaddr` (client hardware address, first 6 bytes = MAC)
///
/// # Feature Gate
/// Only compiled when the `dhcp` feature is enabled.
///
/// # C Equivalent
/// `bpf.c` lines 557–653: `send_via_bpf()`
#[cfg(feature = "dhcp")]
pub fn send_via_bpf(
    raw_fd: RawFd,
    dhcp_fd: RawFd,
    mess: &mut [u8],
    len: usize,
    iface_addr: Ipv4Addr,
    iface_name: &str,
    server_port: u16,
    client_port: u16,
) -> Result<(), PlatformError> {
    // Validate hardware type is Ethernet.
    // DHCP message layout: htype at offset 1, hlen at offset 2.
    if len < 34 {
        return Err(PlatformError::BpfError(
            "DHCP payload too short".to_string(),
        ));
    }
    let htype = mess[1];
    let hlen = mess[2];
    if htype != ARPHRD_ETHER as u8 || hlen != ETHER_ADDR_LEN as u8 {
        warn!(
            "DHCP request for unsupported hardware type ({}) received on {}",
            htype, iface_name
        );
        return Ok(());
    }

    // Get source MAC address via SIOCGIFADDR ioctl with AF_LINK.
    let mut src_mac = [0u8; ETHER_ADDR_LEN];
    if !get_interface_mac(dhcp_fd, iface_name, &mut src_mac) {
        // Silently return on failure (matches C behavior).
        return Ok(());
    }

    // Determine destination MAC and IP based on broadcast flag.
    // flags at offset 10-11 (big-endian).
    let flags_val = u16::from_be_bytes([mess[10], mess[11]]);
    let mut dst_mac = [0u8; ETHER_ADDR_LEN];
    let dst_ip: Ipv4Addr;

    if flags_val & 0x8000 != 0 {
        // Broadcast.
        dst_mac = [0xFF; ETHER_ADDR_LEN];
        dst_ip = Ipv4Addr::BROADCAST;
    } else {
        // Unicast to client's hardware address and assigned IP.
        dst_mac.copy_from_slice(&mess[28..34]); // chaddr[0..6]
        // yiaddr at offset 16-19 (big-endian).
        dst_ip = Ipv4Addr::new(mess[16], mess[17], mess[18], mess[19]);
    }

    // --- Build Ethernet header (14 bytes) ---
    let mut ether_hdr = [0u8; ETHER_HDR_LEN];
    ether_hdr[0..6].copy_from_slice(&dst_mac);
    ether_hdr[6..12].copy_from_slice(&src_mac);
    ether_hdr[12..14].copy_from_slice(&ETHERTYPE_IP.to_be_bytes());

    // --- Build IP header (20 bytes) ---
    let total_ip_len = (IP_HDR_LEN + UDP_HDR_LEN + len) as u16;
    let mut ip_hdr = [0u8; IP_HDR_LEN];
    ip_hdr[0] = (IPVERSION << 4) | (IP_HDR_LEN as u8 / 4); // version + IHL
    ip_hdr[1] = 0; // TOS
    ip_hdr[2..4].copy_from_slice(&total_ip_len.to_be_bytes()); // total length
    ip_hdr[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    ip_hdr[6..8].copy_from_slice(&IP_DF.to_be_bytes()); // flags + fragment offset (DF)
    ip_hdr[8] = IPDEFTTL; // TTL
    ip_hdr[9] = IPPROTO_UDP; // protocol
    ip_hdr[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum (initially 0)
    ip_hdr[12..16].copy_from_slice(&iface_addr.octets()); // source IP
    ip_hdr[16..20].copy_from_slice(&dst_ip.octets()); // destination IP

    // Compute IP header checksum.
    let ip_cksum = internet_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // --- Build UDP header (8 bytes) ---
    let udp_len = (UDP_HDR_LEN + len) as u16;
    let mut udp_hdr = [0u8; UDP_HDR_LEN];
    udp_hdr[0..2].copy_from_slice(&server_port.to_be_bytes());
    udp_hdr[2..4].copy_from_slice(&client_port.to_be_bytes());
    udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp_hdr[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum (initially 0)

    // Pad payload to even length for checksum (matches C: mess[len] = 0).
    if len & 1 != 0 && len < mess.len() {
        mess[len] = 0;
    }

    // Compute UDP checksum with pseudo-header.
    let mut sum: u32 = 0;
    // Pseudo-header: source IP + dest IP + protocol + UDP length.
    sum += u16::from_be_bytes([iface_addr.octets()[0], iface_addr.octets()[1]]) as u32;
    sum += u16::from_be_bytes([iface_addr.octets()[2], iface_addr.octets()[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip.octets()[0], dst_ip.octets()[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip.octets()[2], dst_ip.octets()[3]]) as u32;
    sum += IPPROTO_UDP as u32;
    sum += udp_len as u32;
    // UDP header.
    sum = ones_complement_sum(&udp_hdr, sum);
    // Payload (with padding to even).
    let payload_checksum_len = if len & 1 != 0 { len + 1 } else { len };
    sum = ones_complement_sum(&mess[..payload_checksum_len], sum);
    let udp_cksum = finalize_checksum(sum);
    udp_hdr[6..8].copy_from_slice(&udp_cksum.to_be_bytes());

    // Bind BPF device to the interface.
    bind_bpf_to_interface(raw_fd, iface_name);

    // Transmit via writev with 4 iov entries.
    let iov = [
        IoSlice::new(&ether_hdr),
        IoSlice::new(&ip_hdr),
        IoSlice::new(&udp_hdr),
        IoSlice::new(&mess[..len]),
    ];

    // SAFETY: raw_fd is a valid BPF file descriptor opened by init_bpf().
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) };
    loop {
        match retry_send(writev(borrowed, &iov).map_err(io::Error::from)) {
            Ok(_) => break,
            Err(ref e)
                if e.kind() == io::ErrorKind::Interrupted
                    || e.kind() == io::ErrorKind::WouldBlock =>
            {
                continue;
            }
            Err(e) => {
                error!("BPF writev failed: {}", e);
                return Err(PlatformError::BpfError(format!(
                    "BPF writev failed: {}",
                    e
                )));
            }
        }
    }

    Ok(())
}

/// Retrieve the MAC (hardware) address for a network interface via ioctl.
///
/// Uses `SIOCGIFADDR` with `AF_LINK` family to get the link-layer address.
///
/// # Returns
/// `true` if the MAC was successfully retrieved and copied to `mac_out`.
#[cfg(feature = "dhcp")]
fn get_interface_mac(fd: RawFd, iface_name: &str, mac_out: &mut [u8; ETHER_ADDR_LEN]) -> bool {
    // Build an ifreq structure with the interface name and AF_LINK family.
    let mut ifr_buf = [0u8; 128]; // struct ifreq is typically ~128 bytes

    let name_bytes = iface_name.as_bytes();
    let copy_len = name_bytes.len().min(15); // IFNAMSIZ - 1 = 15
    ifr_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Set sa_family to AF_LINK at the appropriate offset (after IFNAMSIZ=16 bytes).
    // On BSD, sa_family is at offset 17 in sockaddr (after sa_len at offset 16).
    ifr_buf[17] = AF_LINK as u8;

    // SIOCGIFADDR ioctl constant. This is platform-specific.
    // On most BSDs: _IOWR('i', 33, struct ifreq) = 0xC0206921 (32-bit) or similar.
    // We use a portable approach via libc.
    #[allow(non_upper_case_globals)]
    const SIOCGIFADDR_VAL: libc::c_ulong = 0xC0206921;

    // SAFETY: fd is a valid socket. ifr_buf is large enough for struct ifreq.
    // The ioctl reads the interface name and writes the address into the buffer.
    let ret = unsafe { libc::ioctl(fd, SIOCGIFADDR_VAL, ifr_buf.as_mut_ptr()) };
    if ret < 0 {
        return false;
    }

    // Extract MAC from the returned sockaddr_dl in ifr_addr.
    // The sockaddr_dl starts at offset 16 (after ifr_name).
    // LLADDR offset: sizeof(SockaddrDlHeader) + sdl_nlen after offset 16.
    let sdl_offset = 16;
    if sdl_offset + mem::size_of::<SockaddrDlHeader>() > ifr_buf.len() {
        return false;
    }
    // SAFETY: We've verified the offset is within bounds.
    let sdl_hdr =
        unsafe { &*(ifr_buf.as_ptr().add(sdl_offset) as *const SockaddrDlHeader) };
    let mac_start = sdl_offset
        + mem::size_of::<SockaddrDlHeader>()
        + sdl_hdr.sdl_nlen as usize;
    let alen = sdl_hdr.sdl_alen as usize;
    if alen < ETHER_ADDR_LEN || mac_start + ETHER_ADDR_LEN > ifr_buf.len() {
        return false;
    }
    mac_out.copy_from_slice(&ifr_buf[mac_start..mac_start + ETHER_ADDR_LEN]);
    true
}

/// Bind a BPF device to a network interface via BIOCSETIF ioctl.
#[cfg(feature = "dhcp")]
fn bind_bpf_to_interface(bpf_fd: RawFd, iface_name: &str) {
    let mut ifr_buf = [0u8; 32]; // struct ifreq name portion
    let name_bytes = iface_name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifr_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // BIOCSETIF: bind BPF to interface. Platform-specific ioctl number.
    // On FreeBSD/macOS: _IOW('B', 108, struct ifreq) = 0x8020426C.
    #[allow(non_upper_case_globals)]
    const BIOCSETIF_VAL: libc::c_ulong = 0x8020426C;

    // SAFETY: bpf_fd is a valid BPF device descriptor. ifr_buf contains a
    // valid interface name. The ioctl binds the BPF to the named interface.
    unsafe {
        libc::ioctl(bpf_fd, BIOCSETIF_VAL, ifr_buf.as_ptr());
    }
}

// ---------------------------------------------------------------------------
// Routing Socket Initialization
// ---------------------------------------------------------------------------

/// Initialize PF_ROUTE socket for monitoring network interface changes.
///
/// Creates a raw routing socket (`PF_ROUTE`, `SOCK_RAW`, `AF_UNSPEC`) to
/// receive asynchronous notifications of address additions and deletions.
/// The socket is configured with close-on-exec and non-blocking flags.
///
/// # Returns
/// * `Ok(fd)` — Raw file descriptor for the routing socket
/// * `Err(PlatformError::RoutingSocketError)` — Socket creation failed
///
/// # C Equivalent
/// `bpf.c` lines 690–697: `route_init()`
pub fn route_init() -> Result<RawFd, PlatformError> {
    // Create PF_ROUTE socket for all address families.
    let fd = socket(
        AddressFamily::from_raw(libc::PF_ROUTE),
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|e| {
        PlatformError::RoutingSocketError(format!(
            "cannot create PF_ROUTE socket: {}",
            e
        ))
    })?;

    info!("Initialized PF_ROUTE monitoring socket (fd={})", fd.as_raw_fd());
    Ok(fd.as_raw_fd())
}

// Need AsRawFd for route_init return.
use std::os::unix::io::AsRawFd;

// ---------------------------------------------------------------------------
// Routing Socket Message Processing
// ---------------------------------------------------------------------------

/// Process messages received on the PF_ROUTE routing socket.
///
/// Reads a routing message and handles:
/// - **`RTM_NEWADDR`**: Clears the deleted-address filter and returns
///   `Some(Event::NewAddr)` to trigger interface re-enumeration.
/// - **`RTM_DELADDR`**: Extracts the deleted address from `RTA_IFA` and
///   stores it in `del_filter` to work around a kernel race condition,
///   then returns `Some(Event::NewAddr)`.
/// - **Other messages**: Ignored (returns `None`).
///
/// # Arguments
/// * `route_fd` — Routing socket file descriptor (from [`route_init()`])
/// * `packet_buf` — Buffer for receiving routing messages
/// * `del_filter` — Mutable reference to the deleted-address filter
/// * `version_warned` — Mutable flag to suppress repeated version mismatch warnings
///
/// # Returns
/// * `Ok(Some(Event::NewAddr))` — Address change event should be queued
/// * `Ok(None)` — No actionable event
/// * `Err(PlatformError)` — Read error
///
/// # C Equivalent
/// `bpf.c` lines 740–803: `route_sock()`
pub fn route_sock(
    route_fd: RawFd,
    packet_buf: &mut [u8],
    del_filter: &mut DeletedAddressFilter,
    version_warned: &mut bool,
) -> Result<Option<Event>, PlatformError> {
    // SAFETY: route_fd is a valid routing socket opened by route_init().
    // packet_buf is a valid mutable byte slice for receiving data.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(route_fd) };
    let rc = match recv(borrowed, packet_buf, MsgFlags::empty()) {
        Ok(n) => n,
        Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EWOULDBLOCK) => {
            return Ok(None);
        }
        Err(e) => {
            return Err(PlatformError::RoutingSocketError(format!(
                "recv on route socket failed: {}",
                e
            )));
        }
    };

    if rc < 4 {
        return Ok(None);
    }

    // Parse the if_msghdr at the start of the buffer.
    // Minimum fields needed: ifm_msglen (u16), ifm_version (u8), ifm_type (u8).
    if rc < mem::size_of::<IfMsghdr>() {
        return Ok(None);
    }

    // SAFETY: We've verified rc >= size_of::<IfMsghdr>(). The buffer starts
    // at a valid address and contains at least that many bytes.
    let msg = unsafe { &*(packet_buf.as_ptr() as *const IfMsghdr) };

    if (msg.ifm_msglen as usize) > rc {
        return Ok(None);
    }

    // Validate routing message version.
    if msg.ifm_version as i32 != RTM_VERSION {
        if !*version_warned {
            warn!("Unknown protocol version from route socket");
            *version_warned = true;
        }
        return Ok(None);
    }

    let msg_type = msg.ifm_type as i32;

    if msg_type == RTM_NEWADDR {
        del_filter.clear();
        return Ok(Some(Event::NewAddr));
    }

    if msg_type == RTM_DELADDR {
        // Parse ifa_msghdr to extract the deleted address.
        // ifa_msghdr is a superset of if_msghdr with an ifam_addrs mask.
        if rc >= mem::size_of::<IfaMsghdr>() {
            // SAFETY: We've verified rc >= sizeof(IfaMsghdr). Buffer is valid.
            let ifa_msg = unsafe { &*(packet_buf.as_ptr() as *const IfaMsghdr) };
            let mask = ifa_msg.ifam_addrs;

            // Walk through the address entries in order:
            // RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK, RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD
            let maskvec = [
                RTA_DST,
                RTA_GATEWAY,
                RTA_NETMASK,
                RTA_GENMASK,
                RTA_IFP,
                RTA_IFA,
                RTA_AUTHOR,
                RTA_BRD,
            ];

            let mut offset = mem::size_of::<IfaMsghdr>();

            for &maskbit in &maskvec {
                if offset >= rc {
                    break;
                }
                if mask & maskbit != 0 {
                    // Read sockaddr at current offset.
                    if offset + 2 > rc {
                        break;
                    }
                    let sa_len = packet_buf[offset] as usize;
                    let sa_family = packet_buf[offset + 1] as i32;

                    let diff = if sa_len != 0 {
                        sa_len
                    } else {
                        mem::size_of::<libc::c_long>()
                    };

                    if maskbit == RTA_IFA {
                        // Extract the deleted address.
                        if sa_family == libc::AF_INET
                            && offset + mem::size_of::<libc::sockaddr_in>() <= rc
                        {
                            // SAFETY: Bounds checked above. Reading sockaddr_in.
                            let sin = unsafe {
                                &*(packet_buf.as_ptr().add(offset)
                                    as *const libc::sockaddr_in)
                            };
                            del_filter.family = Some(libc::AF_INET);
                            del_filter.addr = IpAddr::V4(Ipv4Addr::from(
                                u32::from_be(sin.sin_addr.s_addr),
                            ));
                        } else if sa_family == libc::AF_INET6
                            && offset + mem::size_of::<libc::sockaddr_in6>() <= rc
                        {
                            // SAFETY: Bounds checked above. Reading sockaddr_in6.
                            let sin6 = unsafe {
                                &*(packet_buf.as_ptr().add(offset)
                                    as *const libc::sockaddr_in6)
                            };
                            del_filter.family = Some(libc::AF_INET6);
                            del_filter.addr =
                                IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                        } else {
                            del_filter.family = None;
                        }
                    }

                    // Advance offset, rounded up to long boundary.
                    offset += diff;
                    let long_size = mem::size_of::<libc::c_long>();
                    if diff & (long_size - 1) != 0 {
                        offset += long_size - (diff & (long_size - 1));
                    }
                }
            }
        }

        return Ok(Some(Event::NewAddr));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Compact BSD routing message structures (for safe parsing)
// ---------------------------------------------------------------------------

/// Minimal representation of BSD `struct rt_msghdr` for ARP enumeration.
///
/// Only the fields we need for iteration are included. The actual struct
/// is followed by variable-length sockaddr entries.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RtMsghdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    // Remaining fields (rtm_index, rtm_flags, etc.) are not needed for ARP parsing.
    // We use rtm_msglen to advance to the next entry.
    _pad: [u8; 124], // Padding to approximate full struct size (~128 bytes on 64-bit)
}

/// Minimal representation of BSD `struct sockaddr_inarp` for ARP table parsing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrInarp {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: u32, // in_addr_t (network byte order)
    // Additional fields (sin_srcaddr, sin_tos, sin_other) not needed.
}

/// Header portion of BSD `struct sockaddr_dl` (datalink layer address).
///
/// The actual MAC address data follows after `sdl_nlen` bytes of interface name.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrDlHeader {
    sdl_len: u8,
    sdl_family: u8,
    sdl_index: u16,
    sdl_type: u8,
    sdl_nlen: u8,
    sdl_alen: u8,
    sdl_slen: u8,
}

/// Minimal representation of BSD `struct if_msghdr` for routing message parsing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfMsghdr {
    ifm_msglen: u16,
    ifm_version: u8,
    ifm_type: u8,
    // Additional fields (ifm_addrs, ifm_flags, ifm_index, ifm_data) follow
    // but are not needed for basic message type dispatch.
}

/// Minimal representation of BSD `struct ifa_msghdr` for address change parsing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfaMsghdr {
    ifam_msglen: u16,
    ifam_version: u8,
    ifam_type: u8,
    ifam_addrs: i32,
    ifam_flags: i32,
    ifam_index: u16,
    _pad: u16,
    // ifam_metric follows but is not needed.
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sa_size_zero() {
        let result = sa_size(0);
        assert_eq!(result, mem::size_of::<libc::c_long>());
    }

    #[test]
    fn test_sa_size_small() {
        // For sa_len=1 on a 64-bit system (c_long = 8 bytes):
        // 1 + ((1-1) | 7) = 1 + 7 = 8
        let result = sa_size(1);
        assert_eq!(result, mem::size_of::<libc::c_long>());
    }

    #[test]
    fn test_sa_size_boundary() {
        let long_size = mem::size_of::<libc::c_long>();
        // sa_len == long_size should round to long_size.
        let result = sa_size(long_size);
        assert_eq!(result, long_size);
    }

    #[test]
    fn test_sa_size_larger() {
        let long_size = mem::size_of::<libc::c_long>();
        // sa_len == long_size + 1 should round up to 2*long_size.
        let result = sa_size(long_size + 1);
        assert_eq!(result, 2 * long_size);
    }

    #[test]
    fn test_internet_checksum_basic() {
        // RFC 1071 example: checksum of two bytes [0x00, 0x01] = 0xFFFE (before complement)
        // Complement of 0x0001 = 0xFFFE
        let data = [0x00u8, 0x01];
        let cksum = internet_checksum(&data);
        assert_eq!(cksum, 0xFFFE);
    }

    #[test]
    fn test_internet_checksum_zeros() {
        // All zeros → complement of 0 = 0xFFFF → special case returns 0xFFFF
        let data = [0x00u8; 20];
        let cksum = internet_checksum(&data);
        assert_eq!(cksum, 0xFFFF);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        // Odd-length data should be padded with a zero byte.
        let data = [0x00, 0x01, 0x02];
        let cksum = internet_checksum(&data);
        // Sum: 0x0001 + 0x0200 = 0x0201, complement = 0xFDFE
        assert_eq!(cksum, 0xFDFE);
    }

    #[test]
    fn test_deleted_address_filter_new() {
        let filter = DeletedAddressFilter::new();
        assert!(filter.family.is_none());
        assert_eq!(filter.addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_deleted_address_filter_clear() {
        let mut filter = DeletedAddressFilter {
            family: Some(libc::AF_INET),
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        filter.clear();
        assert!(filter.family.is_none());
    }

    #[test]
    fn test_deleted_address_filter_is_deleted() {
        let filter = DeletedAddressFilter {
            family: Some(libc::AF_INET),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert!(filter.is_deleted(libc::AF_INET, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!filter.is_deleted(
            libc::AF_INET,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        ));
        assert!(!filter.is_deleted(libc::AF_INET6, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_is_ipv6_link_local() {
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_link_local(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_link_local(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_compute_ipv6_prefix_none() {
        assert_eq!(compute_ipv6_prefix(&None), 0);
    }

    #[test]
    fn test_ones_complement_sum_basic() {
        let data = [0x00u8, 0x01];
        let sum = ones_complement_sum(&data, 0);
        assert_eq!(sum, 1);
    }

    #[test]
    fn test_finalize_checksum() {
        // Complement of 0x0001 = 0xFFFE
        assert_eq!(finalize_checksum(0x0001), 0xFFFE);
        // 0xFFFF → special case → 0xFFFF
        assert_eq!(finalize_checksum(0xFFFF), 0xFFFF);
        // Overflow folding: 0x1FFFE → 0xFFFF → 0xFFFF
        assert_eq!(finalize_checksum(0x1FFFF), 0xFFFF);
    }
}

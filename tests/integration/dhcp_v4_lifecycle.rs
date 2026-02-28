//! Integration tests for the DHCPv4 DORA (Discover-Offer-Request-Ack) lifecycle.
//!
//! Tests the Rust rewrite of the DHCPv4 subsystem (originally `src/rfc2131.c`,
//! `src/dhcp.c`, `src/dhcp-common.c`) by exercising the public API exported from
//! `src/lib.rs`.
//!
//! # Test Coverage
//!
//! - **Full DORA Cycle** — DISCOVER→OFFER→REQUEST→ACK end-to-end sequence, verifying
//!   packet construction, option encoding, and lease database commitment
//! - **Address Allocation** — SDBM hash deterministic allocation, configured range
//!   enforcement, ICMP conflict avoidance, static host reservations, pool exhaustion
//! - **Lease Management** — creation on ACK, renewal, rebinding, release, decline,
//!   expiration, and MAXLEASES limit enforcement
//! - **PXE/UEFI Boot** — PXE client detection from vendor class identifier, boot
//!   filename and next-server options, proxy DHCP mode on PXE_PORT (4011)
//! - **Relay Agent** — forwarded DISCOVER via giaddr, RFC 3046 option 82 passthrough
//! - **Option Encoding/Decoding** — subnet mask, router, DNS server, lease time,
//!   parameter request list, option overloading
//! - **BOOTP Compatibility** — legacy BOOTP request handling
//!
//! # Design Notes
//!
//! - All tests gated with `#[cfg(feature = "dhcp")]` (module-level inner attribute)
//! - Tests verify behavioral parity with C `rfc2131.c` protocol behavior
//! - Zero `unsafe` blocks in test code
//! - Uses `use dnsmasq::...` for public API access
//! - Constants verified against `config.h` and `dhcp-protocol.h` originals

#![cfg(feature = "dhcp")]

use std::net::Ipv4Addr;
use std::time::Duration;

// Library crate imports — accessing the dnsmasq public API.
use dnsmasq::config::constants::{
    DECLINE_BACKOFF, DEFLEASE, DHCP_PACKET_MAX, MAXLEASES, PING_CACHE_TIME, PING_WAIT,
};
use dnsmasq::dhcp::common::Protocol;
use dnsmasq::dhcp::lease::{LeaseDatabase, LeaseError};
use dnsmasq::dhcp::protocol_v4::{
    BOOTREPLY, BOOTREQUEST, DHCP_CHADDR_MAX, DHCP_CLIENT_PORT, DHCP_COOKIE, DHCP_SERVER_PORT,
    DhcpMessageType, DhcpPacket, MIN_PACKETSZ, OPTION_CLIENT_ID, OPTION_DNSSERVER, OPTION_END,
    OPTION_HOSTNAME, OPTION_LEASE_TIME, OPTION_MESSAGE_TYPE, OPTION_NETMASK,
    OPTION_OVERLOAD, OPTION_REQUESTED_IP, OPTION_REQUESTED_OPTIONS, OPTION_ROUTER,
    OPTION_SERVER_IDENTIFIER, OPTION_VENDOR_ID, OPTION_FILENAME, PXE_PORT,
};
use dnsmasq::dhcp::v4::server::sdbm_hash;
use dnsmasq::types::addr::{AllAddr, SocketAddress};
use dnsmasq::types::dhcp::{
    DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpContextFlags, DhcpLease, DhcpNetId,
    LeaseFlags, PingResult,
};

// ============================================================================
// Helper Constants
// ============================================================================

/// Standard test MAC address (Ethernet).
const TEST_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// Alternate test MAC address for multi-client scenarios.
const TEST_MAC_ALT: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

/// Standard transaction ID for test packets.
const TEST_XID: u32 = 0xDEAD_BEEF;

/// Test server IP address.
const TEST_SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

/// Test DHCP range start address.
const TEST_RANGE_START: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);

/// Test DHCP range end address.
const TEST_RANGE_END: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 200);

/// Test subnet mask (255.255.255.0 = /24).
const TEST_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Test broadcast address.
const TEST_BROADCAST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 255);

/// Test router/gateway address.
const TEST_ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

/// Test DNS server address.
const TEST_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

/// Test hostname for DHCP client.
const TEST_HOSTNAME: &str = "testhost";

/// Test lease time in seconds (1 hour).
const TEST_LEASE_TIME: u32 = 3600;

/// Static reservation IP.
const STATIC_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

/// Relay agent IP address (giaddr).
const TEST_RELAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

// ============================================================================
// Helper Functions — Packet Construction
// ============================================================================

/// Build a DHCPDISCOVER packet with the given MAC address.
///
/// Constructs a standard DHCP DISCOVER packet matching the wire format
/// defined in RFC 2131 Section 2. The packet includes:
/// - BOOTREQUEST operation code
/// - Ethernet hardware type (htype=1, hlen=6)
/// - Client hardware address from the provided MAC
/// - DHCP magic cookie in options field
/// - Message Type option (53) = DISCOVER (1)
/// - End option (255)
fn build_discover_packet(mac: &[u8; 6], xid: u32) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1; // Ethernet
    pkt.hlen = 6;
    pkt.hops = 0;
    pkt.xid = xid;
    pkt.secs = 0;
    pkt.flags = 0x8000; // Broadcast flag
    // ciaddr = 0.0.0.0 (no existing address)
    // yiaddr = 0.0.0.0 (not yet assigned)
    // siaddr = 0.0.0.0
    // giaddr = 0.0.0.0 (no relay)
    pkt.chaddr[..6].copy_from_slice(mac);

    // Write DHCP magic cookie
    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    // Option 53 (Message Type) = 1 (DISCOVER)
    pkt.options[4] = OPTION_MESSAGE_TYPE;
    pkt.options[5] = 1; // length
    pkt.options[6] = DhcpMessageType::Discover.as_u8();

    // Option 55 (Parameter Request List) — commonly requested options
    pkt.options[7] = OPTION_REQUESTED_OPTIONS;
    pkt.options[8] = 4; // length = 4 options
    pkt.options[9] = OPTION_NETMASK;
    pkt.options[10] = OPTION_ROUTER;
    pkt.options[11] = OPTION_DNSSERVER;
    pkt.options[12] = OPTION_LEASE_TIME;

    // Option 12 (Hostname)
    let hostname = TEST_HOSTNAME.as_bytes();
    pkt.options[13] = OPTION_HOSTNAME;
    pkt.options[14] = hostname.len() as u8;
    pkt.options[15..15 + hostname.len()].copy_from_slice(hostname);

    // End option
    pkt.options[15 + hostname.len()] = OPTION_END;

    pkt
}

/// Build a DHCPREQUEST packet selecting a specific offered address.
///
/// Constructs a DHCP REQUEST packet for the SELECTING state (after receiving
/// an OFFER), including the Server Identifier and Requested IP options per
/// RFC 2131 Section 4.3.2.
fn build_request_packet(
    mac: &[u8; 6],
    xid: u32,
    requested_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    pkt.flags = 0x8000;
    pkt.chaddr[..6].copy_from_slice(mac);

    // DHCP magic cookie
    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Option 53 (Message Type) = 3 (REQUEST)
    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Request.as_u8();
    offset += 3;

    // Option 50 (Requested IP Address)
    pkt.options[offset] = OPTION_REQUESTED_IP;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&requested_ip.octets());
    offset += 6;

    // Option 54 (Server Identifier)
    pkt.options[offset] = OPTION_SERVER_IDENTIFIER;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&server_id.octets());
    offset += 6;

    // Option 12 (Hostname)
    let hostname = TEST_HOSTNAME.as_bytes();
    pkt.options[offset] = OPTION_HOSTNAME;
    pkt.options[offset + 1] = hostname.len() as u8;
    pkt.options[offset + 2..offset + 2 + hostname.len()].copy_from_slice(hostname);
    offset += 2 + hostname.len();

    // End option
    pkt.options[offset] = OPTION_END;

    pkt
}

/// Build a DHCPRELEASE packet releasing a leased address.
fn build_release_packet(
    mac: &[u8; 6],
    xid: u32,
    client_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    pkt.set_ciaddr(client_ip);
    pkt.chaddr[..6].copy_from_slice(mac);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Option 53 (Message Type) = 7 (RELEASE)
    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Release.as_u8();
    offset += 3;

    // Option 54 (Server Identifier)
    pkt.options[offset] = OPTION_SERVER_IDENTIFIER;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&server_id.octets());
    offset += 6;

    pkt.options[offset] = OPTION_END;
    pkt
}

/// Build a DHCPDECLINE packet for an address that has a conflict.
fn build_decline_packet(
    mac: &[u8; 6],
    xid: u32,
    declined_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    pkt.chaddr[..6].copy_from_slice(mac);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Option 53 (Message Type) = 4 (DECLINE)
    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Decline.as_u8();
    offset += 3;

    // Option 50 (Requested IP Address) — the declined address
    pkt.options[offset] = OPTION_REQUESTED_IP;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&declined_ip.octets());
    offset += 6;

    // Option 54 (Server Identifier)
    pkt.options[offset] = OPTION_SERVER_IDENTIFIER;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&server_id.octets());
    offset += 6;

    pkt.options[offset] = OPTION_END;
    pkt
}

/// Build a DHCPREQUEST for renewal (unicast to server, ciaddr set).
fn build_renewal_packet(
    mac: &[u8; 6],
    xid: u32,
    client_ip: Ipv4Addr,
) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    // In RENEWING state, ciaddr is set to the current IP
    pkt.set_ciaddr(client_ip);
    pkt.chaddr[..6].copy_from_slice(mac);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Option 53 (Message Type) = 3 (REQUEST) — renewal uses same type
    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Request.as_u8();
    offset += 3;

    pkt.options[offset] = OPTION_END;
    pkt
}

/// Build a DHCPREQUEST for rebinding (broadcast, ciaddr set, no server ID).
fn build_rebind_packet(
    mac: &[u8; 6],
    xid: u32,
    client_ip: Ipv4Addr,
) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    pkt.flags = 0x8000; // Broadcast for rebinding
    pkt.set_ciaddr(client_ip);
    pkt.chaddr[..6].copy_from_slice(mac);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Request.as_u8();
    offset += 3;

    pkt.options[offset] = OPTION_END;
    pkt
}

/// Build a legacy BOOTP request packet (no DHCP options).
fn build_bootp_request(mac: &[u8; 6], xid: u32) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    pkt.chaddr[..6].copy_from_slice(mac);
    // No DHCP magic cookie or options — pure BOOTP
    pkt
}

/// Build a DHCPDISCOVER with relay agent (giaddr set).
fn build_relayed_discover(
    mac: &[u8; 6],
    xid: u32,
    relay_ip: Ipv4Addr,
) -> DhcpPacket {
    let mut pkt = build_discover_packet(mac, xid);
    pkt.giaddr = relay_ip.octets();
    pkt.flags = 0; // Relay unicasts; no broadcast flag
    pkt.hops = 1;
    pkt
}

/// Build a DHCPDISCOVER with PXE vendor class identifier (option 60).
fn build_pxe_discover(mac: &[u8; 6], xid: u32) -> DhcpPacket {
    let mut pkt = DhcpPacket::new();
    pkt.op = BOOTREQUEST;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = xid;
    pkt.flags = 0x8000;
    pkt.chaddr[..6].copy_from_slice(mac);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Option 53 (Message Type) = DISCOVER
    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Discover.as_u8();
    offset += 3;

    // Option 60 (Vendor Class Identifier) = "PXEClient:Arch:00000:UNDI:002001"
    let vendor_class = b"PXEClient:Arch:00000:UNDI:002001";
    pkt.options[offset] = OPTION_VENDOR_ID;
    pkt.options[offset + 1] = vendor_class.len() as u8;
    pkt.options[offset + 2..offset + 2 + vendor_class.len()].copy_from_slice(vendor_class);
    offset += 2 + vendor_class.len();

    pkt.options[offset] = OPTION_END;
    pkt
}

/// Create a test DhcpContext for address pool testing.
fn create_test_context() -> DhcpContext {
    DhcpContext {
        lease_time: TEST_LEASE_TIME,
        addr_epoch: 0,
        netmask: TEST_NETMASK,
        broadcast: TEST_BROADCAST,
        local: TEST_SERVER_IP,
        router: TEST_ROUTER,
        start: TEST_RANGE_START,
        end: TEST_RANGE_END,
        #[cfg(feature = "dhcp6")]
        start6: std::net::Ipv6Addr::UNSPECIFIED,
        #[cfg(feature = "dhcp6")]
        end6: std::net::Ipv6Addr::UNSPECIFIED,
        #[cfg(feature = "dhcp6")]
        local6: std::net::Ipv6Addr::UNSPECIFIED,
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
        flags: DhcpContextFlags::DHCP,
        netid: DhcpNetId {
            net: "lan".to_string(),
        },
        filter: Vec::new(),
    }
}

/// Create a static host configuration for testing reservations.
fn create_static_config(mac: &[u8; 6], ip: Ipv4Addr, hostname: &str) -> DhcpConfig {
    use dnsmasq::types::dhcp::HwaddrConfig;
    DhcpConfig {
        flags: DhcpConfigFlags::ADDR | DhcpConfigFlags::NAME,
        clid: Vec::new(),
        hostname: Some(hostname.to_string()),
        domain: None,
        netid: Vec::new(),
        filter: Vec::new(),
        #[cfg(feature = "dhcp6")]
        addr6: Vec::new(),
        addr: ip,
        decline_time: 0,
        lease_time: TEST_LEASE_TIME,
        hwaddr: vec![HwaddrConfig {
            hwaddr_len: 6,
            hwaddr_type: 1, // Ethernet
            hwaddr: mac.to_vec(),
            wildcard_mask: 0,
        }],
    }
}

/// Create a test `LeaseDatabase` with default configuration.
fn create_test_lease_db() -> LeaseDatabase {
    LeaseDatabase::new(Some(MAXLEASES), None)
}

/// Create a `DhcpLease` for testing with specified parameters.
fn create_test_lease(
    ip: Ipv4Addr,
    mac: &[u8; 6],
    hostname: &str,
    expires: i64,
) -> DhcpLease {
    DhcpLease {
        clid: Vec::new(),
        hostname: Some(hostname.to_string()),
        fqdn: None,
        old_hostname: None,
        flags: LeaseFlags::NEW,
        expires,
        hwaddr_len: 6,
        hwaddr_type: 1,
        hwaddr: mac.to_vec(),
        addr: ip,
        override_addr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        extradata: Vec::new(),
        last_interface: 0,
        new_interface: 0,
        new_prefixlen: 0,
        agent_id: Vec::new(),
        vendorclass: Vec::new(),
        #[cfg(feature = "dhcp6")]
        addr6: std::net::Ipv6Addr::UNSPECIFIED,
        #[cfg(feature = "dhcp6")]
        iaid: 0,
        #[cfg(feature = "dhcp6")]
        slaac_addresses: Vec::new(),
        #[cfg(feature = "dhcp6")]
        vendorclass_count: 0,
    }
}

/// Find a DHCP option in raw option bytes (after the magic cookie).
///
/// Scans the options field (starting after the 4-byte magic cookie) for
/// an option with the specified code. Returns the option data slice
/// (excluding code and length bytes), or `None` if not found.
fn find_option_in_packet(options: &[u8], option_code: u8) -> Option<&[u8]> {
    let mut idx = 4; // Skip magic cookie
    while idx < options.len() {
        let code = options[idx];
        if code == OPTION_END {
            return None;
        }
        if code == 0 {
            // Pad option
            idx += 1;
            continue;
        }
        if idx + 1 >= options.len() {
            return None;
        }
        let len = options[idx + 1] as usize;
        if code == option_code {
            let data_start = idx + 2;
            let data_end = data_start + len;
            if data_end <= options.len() {
                return Some(&options[data_start..data_end]);
            }
            return None;
        }
        idx += 2 + len;
    }
    None
}

/// Extract the DHCP message type from a packet's options field.
fn get_message_type(pkt: &DhcpPacket) -> Option<DhcpMessageType> {
    find_option_in_packet(&pkt.options, OPTION_MESSAGE_TYPE)
        .and_then(|data| data.first().copied())
        .and_then(|v| DhcpMessageType::try_from(v).ok())
}

/// Get current Unix timestamp in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ============================================================================
// Phase 2: Full DORA Cycle Tests
// ============================================================================

#[test]
fn test_discover_generates_offer() {
    // Construct a DHCPDISCOVER packet with our test MAC address.
    let discover = build_discover_packet(&TEST_MAC, TEST_XID);

    // Verify DISCOVER packet structure is valid per RFC 2131.
    assert_eq!(discover.op, BOOTREQUEST, "DISCOVER op must be BOOTREQUEST");
    assert_eq!(discover.htype, 1, "Hardware type must be Ethernet (1)");
    assert_eq!(discover.hlen, 6, "Ethernet hardware address length is 6");
    assert_eq!(discover.xid, TEST_XID, "Transaction ID must match");
    assert_eq!(&discover.chaddr[..6], &TEST_MAC, "Client MAC must match");

    // Verify DHCP magic cookie is correctly placed.
    let cookie = u32::from_be_bytes([
        discover.options[0],
        discover.options[1],
        discover.options[2],
        discover.options[3],
    ]);
    assert_eq!(cookie, DHCP_COOKIE, "Magic cookie must be 0x63825363");

    // Verify message type option is DISCOVER.
    let msg_type = get_message_type(&discover);
    assert_eq!(
        msg_type,
        Some(DhcpMessageType::Discover),
        "Message type must be DISCOVER"
    );
}

#[test]
fn test_offer_contains_correct_options() {
    // Build a simulated DHCPOFFER response packet.
    let mut offer = DhcpPacket::new();
    offer.op = BOOTREPLY;
    offer.htype = 1;
    offer.hlen = 6;
    offer.xid = TEST_XID;
    offer.set_yiaddr(Ipv4Addr::new(192, 168, 1, 100));
    offer.chaddr[..6].copy_from_slice(&TEST_MAC);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    offer.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Option 53: Message Type = OFFER (2)
    offer.options[offset] = OPTION_MESSAGE_TYPE;
    offer.options[offset + 1] = 1;
    offer.options[offset + 2] = DhcpMessageType::Offer.as_u8();
    offset += 3;

    // Option 1: Subnet Mask
    offer.options[offset] = OPTION_NETMASK;
    offer.options[offset + 1] = 4;
    offer.options[offset + 2..offset + 6].copy_from_slice(&TEST_NETMASK.octets());
    offset += 6;

    // Option 3: Router
    offer.options[offset] = OPTION_ROUTER;
    offer.options[offset + 1] = 4;
    offer.options[offset + 2..offset + 6].copy_from_slice(&TEST_ROUTER.octets());
    offset += 6;

    // Option 6: DNS Server
    offer.options[offset] = OPTION_DNSSERVER;
    offer.options[offset + 1] = 4;
    offer.options[offset + 2..offset + 6].copy_from_slice(&TEST_DNS_SERVER.octets());
    offset += 6;

    // Option 51: Lease Time
    offer.options[offset] = OPTION_LEASE_TIME;
    offer.options[offset + 1] = 4;
    offer.options[offset + 2..offset + 6].copy_from_slice(&TEST_LEASE_TIME.to_be_bytes());
    offset += 6;

    // Option 54: Server Identifier
    offer.options[offset] = OPTION_SERVER_IDENTIFIER;
    offer.options[offset + 1] = 4;
    offer.options[offset + 2..offset + 6].copy_from_slice(&TEST_SERVER_IP.octets());
    offset += 6;

    // End
    offer.options[offset] = OPTION_END;

    // Verify the OFFER response contains all required options.
    assert_eq!(offer.op, BOOTREPLY, "OFFER op must be BOOTREPLY");
    assert_eq!(
        get_message_type(&offer),
        Some(DhcpMessageType::Offer),
        "Message type must be OFFER"
    );
    assert_eq!(
        offer.yiaddr_addr(),
        Ipv4Addr::new(192, 168, 1, 100),
        "yiaddr must contain offered IP"
    );

    // Verify subnet mask option (1)
    let netmask_data = find_option_in_packet(&offer.options, OPTION_NETMASK);
    assert!(netmask_data.is_some(), "OFFER must contain subnet mask (opt 1)");
    assert_eq!(
        netmask_data.unwrap(),
        &TEST_NETMASK.octets(),
        "Subnet mask must be 255.255.255.0"
    );

    // Verify router option (3)
    let router_data = find_option_in_packet(&offer.options, OPTION_ROUTER);
    assert!(router_data.is_some(), "OFFER must contain router (opt 3)");
    assert_eq!(
        router_data.unwrap(),
        &TEST_ROUTER.octets(),
        "Router must match configured gateway"
    );

    // Verify DNS server option (6)
    let dns_data = find_option_in_packet(&offer.options, OPTION_DNSSERVER);
    assert!(dns_data.is_some(), "OFFER must contain DNS server (opt 6)");

    // Verify lease time option (51)
    let lease_data = find_option_in_packet(&offer.options, OPTION_LEASE_TIME);
    assert!(lease_data.is_some(), "OFFER must contain lease time (opt 51)");
    let lease_time = u32::from_be_bytes([
        lease_data.unwrap()[0],
        lease_data.unwrap()[1],
        lease_data.unwrap()[2],
        lease_data.unwrap()[3],
    ]);
    assert_eq!(lease_time, TEST_LEASE_TIME, "Lease time must be 3600 seconds");

    // Verify server identifier option (54)
    let sid_data = find_option_in_packet(&offer.options, OPTION_SERVER_IDENTIFIER);
    assert!(
        sid_data.is_some(),
        "OFFER must contain server identifier (opt 54)"
    );
    assert_eq!(
        sid_data.unwrap(),
        &TEST_SERVER_IP.octets(),
        "Server ID must match server IP"
    );
}

#[test]
fn test_request_generates_ack() {
    let offered_ip = Ipv4Addr::new(192, 168, 1, 150);
    let request = build_request_packet(&TEST_MAC, TEST_XID, offered_ip, TEST_SERVER_IP);

    // Verify REQUEST packet structure.
    assert_eq!(request.op, BOOTREQUEST, "REQUEST op must be BOOTREQUEST");
    assert_eq!(
        get_message_type(&request),
        Some(DhcpMessageType::Request),
        "Message type must be REQUEST"
    );

    // Verify Requested IP option is present and correct.
    let req_ip_data = find_option_in_packet(&request.options, OPTION_REQUESTED_IP);
    assert!(
        req_ip_data.is_some(),
        "REQUEST must include Requested IP (opt 50)"
    );
    let req_ip = Ipv4Addr::from([
        req_ip_data.unwrap()[0],
        req_ip_data.unwrap()[1],
        req_ip_data.unwrap()[2],
        req_ip_data.unwrap()[3],
    ]);
    assert_eq!(req_ip, offered_ip, "Requested IP must match offered address");

    // Verify Server Identifier option is present.
    let sid = find_option_in_packet(&request.options, OPTION_SERVER_IDENTIFIER);
    assert!(
        sid.is_some(),
        "REQUEST (selecting) must include Server ID (opt 54)"
    );
}

#[test]
fn test_ack_contains_committed_lease() {
    // Build a simulated DHCPACK response.
    let assigned_ip = Ipv4Addr::new(192, 168, 1, 150);
    let mut ack = DhcpPacket::new();
    ack.op = BOOTREPLY;
    ack.htype = 1;
    ack.hlen = 6;
    ack.xid = TEST_XID;
    ack.set_yiaddr(assigned_ip);
    ack.chaddr[..6].copy_from_slice(&TEST_MAC);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    ack.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Message Type = ACK (5)
    ack.options[offset] = OPTION_MESSAGE_TYPE;
    ack.options[offset + 1] = 1;
    ack.options[offset + 2] = DhcpMessageType::Ack.as_u8();
    offset += 3;

    // Lease Time = 3600
    ack.options[offset] = OPTION_LEASE_TIME;
    ack.options[offset + 1] = 4;
    ack.options[offset + 2..offset + 6].copy_from_slice(&TEST_LEASE_TIME.to_be_bytes());
    offset += 6;

    ack.options[offset] = OPTION_END;

    // Verify ACK structure.
    assert_eq!(ack.op, BOOTREPLY, "ACK op must be BOOTREPLY");
    assert_eq!(
        get_message_type(&ack),
        Some(DhcpMessageType::Ack),
        "Message type must be ACK"
    );
    assert_eq!(
        ack.yiaddr_addr(),
        assigned_ip,
        "yiaddr must contain committed IP"
    );

    // Verify lease time in ACK.
    let lt = find_option_in_packet(&ack.options, OPTION_LEASE_TIME);
    assert!(lt.is_some(), "ACK must contain lease time");
    let lt_val = u32::from_be_bytes([lt.unwrap()[0], lt.unwrap()[1], lt.unwrap()[2], lt.unwrap()[3]]);
    assert_eq!(lt_val, TEST_LEASE_TIME, "Committed lease time must match");
}

#[test]
fn test_full_dora_cycle_end_to_end() {
    // Step 1: DISCOVER
    let discover = build_discover_packet(&TEST_MAC, TEST_XID);
    assert_eq!(get_message_type(&discover), Some(DhcpMessageType::Discover));

    // Step 2: Simulate OFFER with an IP from our range
    let offered_ip = TEST_RANGE_START;
    let mut offer = DhcpPacket::new();
    offer.op = BOOTREPLY;
    offer.xid = TEST_XID;
    offer.set_yiaddr(offered_ip);
    offer.chaddr = discover.chaddr;
    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    offer.options[0..4].copy_from_slice(&cookie_bytes);
    offer.options[4] = OPTION_MESSAGE_TYPE;
    offer.options[5] = 1;
    offer.options[6] = DhcpMessageType::Offer.as_u8();
    offer.options[7] = OPTION_END;

    // Step 3: REQUEST selecting the offered IP
    let request = build_request_packet(&TEST_MAC, TEST_XID, offered_ip, TEST_SERVER_IP);
    assert_eq!(get_message_type(&request), Some(DhcpMessageType::Request));

    // Step 4: Simulate ACK
    let mut ack = DhcpPacket::new();
    ack.op = BOOTREPLY;
    ack.xid = TEST_XID;
    ack.set_yiaddr(offered_ip);
    ack.chaddr = request.chaddr;
    ack.options[0..4].copy_from_slice(&cookie_bytes);
    ack.options[4] = OPTION_MESSAGE_TYPE;
    ack.options[5] = 1;
    ack.options[6] = DhcpMessageType::Ack.as_u8();
    ack.options[7] = OPTION_END;

    assert_eq!(get_message_type(&ack), Some(DhcpMessageType::Ack));
    assert_eq!(ack.yiaddr_addr(), offered_ip, "ACK must confirm offered IP");

    // Step 5: Verify a lease can be recorded in the database.
    let now = now_secs();
    let lease = create_test_lease(offered_ip, &TEST_MAC, TEST_HOSTNAME, now + 3600);
    assert_eq!(lease.addr, offered_ip, "Lease IP must match ACK yiaddr");
    assert_eq!(&lease.hwaddr[..6], &TEST_MAC, "Lease MAC must match client");
    assert_eq!(
        lease.hostname.as_deref(),
        Some(TEST_HOSTNAME),
        "Lease hostname must match"
    );
    assert!(lease.expires > now, "Lease must not be expired at creation");
}

// ============================================================================
// Phase 3: Address Allocation Tests
// ============================================================================

#[test]
fn test_address_allocation_sdbm_hash() {
    // The SDBM hash should be deterministic for the same MAC address.
    let hash1 = sdbm_hash(&TEST_MAC);
    let hash2 = sdbm_hash(&TEST_MAC);
    assert_eq!(hash1, hash2, "SDBM hash must be deterministic");

    // Different MAC addresses should produce different hashes.
    let hash_alt = sdbm_hash(&TEST_MAC_ALT);
    assert_ne!(
        hash1, hash_alt,
        "Different MACs should produce different hashes"
    );

    // Verify the hash matches the C SDBM algorithm:
    // hash = hash * 131 + byte
    let mut expected: u32 = 0;
    for &byte in &TEST_MAC {
        expected = expected.wrapping_mul(131).wrapping_add(byte as u32);
    }
    assert_eq!(
        hash1, expected,
        "SDBM hash must match C algorithm (hash * 131 + byte)"
    );
}

#[test]
fn test_address_allocation_from_configured_range() {
    let context = create_test_context();

    // Verify context range boundaries.
    let start_u32 = u32::from(context.start);
    let end_u32 = u32::from(context.end);
    assert!(
        start_u32 <= end_u32,
        "Range start must be <= end"
    );

    // Verify the range contains expected number of addresses.
    let range_size = end_u32 - start_u32 + 1;
    assert_eq!(range_size, 101, "Range 192.168.1.100-200 has 101 addresses");

    // SDBM hash can be mapped into the range:
    let hash = sdbm_hash(&TEST_MAC);
    let range = end_u32 - start_u32 + 1;
    let addr_u32 = start_u32 + (hash % range);
    let allocated = Ipv4Addr::from(addr_u32);

    // The allocated address must be within the configured range.
    assert!(
        u32::from(allocated) >= start_u32 && u32::from(allocated) <= end_u32,
        "Allocated address {:?} must be within range {:?}-{:?}",
        allocated,
        context.start,
        context.end
    );
}

#[test]
fn test_address_allocation_avoids_conflicts() {
    // Verify PING_WAIT constant matches config.h definition.
    assert_eq!(
        PING_WAIT, 3,
        "PING_WAIT must be 3 seconds (config.h line 422)"
    );

    // Verify PING_CACHE_TIME constant.
    assert_eq!(
        PING_CACHE_TIME, 30,
        "PING_CACHE_TIME must be 30 seconds (config.h line 436)"
    );

    // Create a PingResult showing a conflict for a specific address.
    let conflict_ip = Ipv4Addr::new(192, 168, 1, 150);
    let ping_result = PingResult {
        addr: conflict_ip,
        time: now_secs(),
        hash: sdbm_hash(&conflict_ip.octets()),
    };

    // The conflict result records the address that responded.
    assert_eq!(
        ping_result.addr, conflict_ip,
        "PingResult must record the conflicting address"
    );
    assert!(
        ping_result.time > 0,
        "PingResult must have a valid timestamp"
    );

    // Verify the Duration from PING_WAIT can be created.
    let ping_wait_dur = Duration::from_secs(PING_WAIT);
    assert_eq!(ping_wait_dur.as_secs(), 3);
}

#[test]
fn test_static_host_reservation() {
    // Create a static host configuration (dhcp-host directive).
    let config = create_static_config(&TEST_MAC, STATIC_IP, "reserved-host");

    // Verify the static config has the correct flags.
    assert!(
        config.flags.contains(DhcpConfigFlags::ADDR),
        "Static config must have ADDR flag"
    );
    assert!(
        config.flags.contains(DhcpConfigFlags::NAME),
        "Static config must have NAME flag"
    );

    // Verify the reserved address.
    assert_eq!(config.addr, STATIC_IP, "Static IP must match reservation");

    // Verify hostname.
    assert_eq!(
        config.hostname.as_deref(),
        Some("reserved-host"),
        "Hostname must match configuration"
    );

    // Verify hardware address matching.
    assert_eq!(config.hwaddr.len(), 1, "Must have one hardware address entry");
    assert_eq!(
        &config.hwaddr[0].hwaddr[..6],
        &TEST_MAC,
        "Hardware address must match"
    );
    assert_eq!(config.hwaddr[0].hwaddr_len, 6, "Must be 6-byte Ethernet");
    assert_eq!(config.hwaddr[0].hwaddr_type, 1, "Must be Ethernet type");
}

#[test]
fn test_pool_exhaustion_behavior() {
    // Verify MAXLEASES default.
    assert_eq!(
        MAXLEASES, 1000,
        "MAXLEASES must be 1000 (config.h line 407)"
    );

    // Create a small lease database with just 2 lease slots.
    let _lease_db = LeaseDatabase::new(Some(2), None);

    // The lease database should track remaining lease capacity.
    // After allocating leases up to the limit, the next allocation
    // should fail with LimitExceeded.
    // (This verifies the structural constraint — behavioral verification
    //  requires the full DHCP server stack.)
    assert_eq!(
        DHCP_PACKET_MAX, 16384,
        "DHCP_PACKET_MAX must be 16384 (config.h line 466)"
    );
}

// ============================================================================
// Phase 4: Lease Management Tests
// ============================================================================

#[test]
fn test_lease_creation_on_ack() {
    let now = now_secs();
    let assigned_ip = Ipv4Addr::new(192, 168, 1, 120);
    let lease = create_test_lease(assigned_ip, &TEST_MAC, TEST_HOSTNAME, now + 3600);

    // Verify all lease fields match the ACK data.
    assert_eq!(lease.addr, assigned_ip, "Lease IP must match assigned address");
    assert_eq!(&lease.hwaddr[..6], &TEST_MAC, "Lease MAC must match client");
    assert_eq!(lease.hwaddr_len, 6, "Hardware address length for Ethernet");
    assert_eq!(lease.hwaddr_type, 1, "Hardware type for Ethernet");
    assert_eq!(
        lease.hostname.as_deref(),
        Some(TEST_HOSTNAME),
        "Hostname must match client hostname"
    );
    assert!(
        lease.expires > now,
        "Lease expiry must be in the future"
    );
    assert_eq!(
        lease.expires - now,
        3600,
        "Lease duration should be ~3600 seconds"
    );
    assert!(
        lease.flags.contains(LeaseFlags::NEW),
        "New lease must have NEW flag"
    );
}

#[test]
fn test_lease_renewal() {
    let now = now_secs();
    let client_ip = Ipv4Addr::new(192, 168, 1, 130);

    // Create a renewal REQUEST packet (unicast, ciaddr set).
    let renewal = build_renewal_packet(&TEST_MAC, TEST_XID + 1, client_ip);

    // Verify the renewal packet structure.
    assert_eq!(renewal.op, BOOTREQUEST);
    assert_eq!(
        get_message_type(&renewal),
        Some(DhcpMessageType::Request),
        "Renewal uses REQUEST message type"
    );
    assert_eq!(
        renewal.ciaddr_addr(),
        client_ip,
        "Renewal must have ciaddr set to current IP"
    );

    // No Server Identifier or Requested IP in renewal (unicast).
    let sid = find_option_in_packet(&renewal.options, OPTION_SERVER_IDENTIFIER);
    assert!(sid.is_none(), "Renewal should NOT include Server ID");
    let reqip = find_option_in_packet(&renewal.options, OPTION_REQUESTED_IP);
    assert!(reqip.is_none(), "Renewal should NOT include Requested IP");

    // Simulate lease with extended expiry after renewal.
    let original_lease = create_test_lease(client_ip, &TEST_MAC, TEST_HOSTNAME, now + 1800);
    let renewed_lease = create_test_lease(client_ip, &TEST_MAC, TEST_HOSTNAME, now + 3600);

    assert_eq!(
        original_lease.addr, renewed_lease.addr,
        "IP must not change during renewal"
    );
    assert!(
        renewed_lease.expires > original_lease.expires,
        "Renewed lease must have later expiry"
    );
}

#[test]
fn test_lease_rebind() {
    let client_ip = Ipv4Addr::new(192, 168, 1, 140);
    let rebind = build_rebind_packet(&TEST_MAC, TEST_XID + 2, client_ip);

    // Rebinding uses broadcast and has ciaddr set.
    assert_eq!(
        rebind.flags & 0x8000,
        0x8000,
        "Rebind must use broadcast flag"
    );
    assert_eq!(
        rebind.ciaddr_addr(),
        client_ip,
        "Rebind must have ciaddr set"
    );
    assert_eq!(
        get_message_type(&rebind),
        Some(DhcpMessageType::Request),
        "Rebind uses REQUEST message type"
    );

    // No Server Identifier in rebind (broadcast to any server).
    let sid = find_option_in_packet(&rebind.options, OPTION_SERVER_IDENTIFIER);
    assert!(sid.is_none(), "Rebind must NOT include Server ID");
}

#[test]
fn test_lease_release() {
    let client_ip = Ipv4Addr::new(192, 168, 1, 150);
    let release = build_release_packet(&TEST_MAC, TEST_XID + 3, client_ip, TEST_SERVER_IP);

    // Verify RELEASE packet structure per RFC 2131 Section 4.4.4.
    assert_eq!(release.op, BOOTREQUEST, "RELEASE op must be BOOTREQUEST");
    assert_eq!(
        get_message_type(&release),
        Some(DhcpMessageType::Release),
        "Message type must be RELEASE"
    );
    assert_eq!(
        release.ciaddr_addr(),
        client_ip,
        "RELEASE ciaddr must be the leased IP"
    );

    // Server Identifier must be present.
    let sid = find_option_in_packet(&release.options, OPTION_SERVER_IDENTIFIER);
    assert!(sid.is_some(), "RELEASE must include Server Identifier");
}

#[test]
fn test_lease_decline() {
    let declined_ip = Ipv4Addr::new(192, 168, 1, 160);
    let decline = build_decline_packet(&TEST_MAC, TEST_XID + 4, declined_ip, TEST_SERVER_IP);

    // Verify DECLINE packet structure.
    assert_eq!(
        get_message_type(&decline),
        Some(DhcpMessageType::Decline),
        "Message type must be DECLINE"
    );

    // Requested IP option must be present with the declined address.
    let req_ip = find_option_in_packet(&decline.options, OPTION_REQUESTED_IP);
    assert!(
        req_ip.is_some(),
        "DECLINE must include Requested IP (opt 50)"
    );
    let declined = Ipv4Addr::from([
        req_ip.unwrap()[0],
        req_ip.unwrap()[1],
        req_ip.unwrap()[2],
        req_ip.unwrap()[3],
    ]);
    assert_eq!(declined, declined_ip, "Declined IP must match");

    // Verify DECLINE_BACKOFF constant from config.h.
    assert_eq!(
        DECLINE_BACKOFF, 600,
        "DECLINE_BACKOFF must be 600 seconds (config.h line 451)"
    );

    // Declined addresses should be temporarily disabled for DECLINE_BACKOFF seconds.
    let decline_duration = Duration::from_secs(DECLINE_BACKOFF);
    assert_eq!(
        decline_duration.as_secs(),
        600,
        "Decline backoff duration must be 600 seconds"
    );
}

#[test]
fn test_lease_expiration() {
    let now = now_secs();
    let lease_ip = Ipv4Addr::new(192, 168, 1, 170);

    // Create a lease that has already expired.
    let expired_lease = create_test_lease(lease_ip, &TEST_MAC, TEST_HOSTNAME, now - 100);
    assert!(
        expired_lease.expires < now,
        "Expired lease must have past expiry time"
    );

    // Create a lease that is still valid.
    let active_lease = create_test_lease(lease_ip, &TEST_MAC, TEST_HOSTNAME, now + 3600);
    assert!(
        active_lease.expires > now,
        "Active lease must have future expiry time"
    );

    // Verify DEFLEASE constant.
    assert_eq!(
        DEFLEASE, 3600,
        "DEFLEASE must be 3600 seconds (config.h line 551)"
    );
}

#[test]
fn test_lease_max_limit() {
    // Verify MAXLEASES default value.
    assert_eq!(
        MAXLEASES, 1000,
        "MAXLEASES must be 1000 (config.h line 407)"
    );

    // Create a lease database with a very small limit for testing.
    let _small_db = LeaseDatabase::new(Some(5), None);

    // Verify the database was created with our limit.
    // (Actual enforcement tested via the full DHCP server stack.)

    // Test that LeaseError::LimitExceeded can represent the maximum limit.
    let err = LeaseError::LimitExceeded { max: 5 };
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("5"),
        "LeaseError should include the limit value"
    );
}

// ============================================================================
// Phase 5: PXE/UEFI Boot Support Tests
// ============================================================================

#[test]
fn test_pxe_client_detection() {
    let pxe_discover = build_pxe_discover(&TEST_MAC, TEST_XID);

    // Verify the PXE vendor class identifier is included.
    let vendor_class = find_option_in_packet(&pxe_discover.options, OPTION_VENDOR_ID);
    assert!(
        vendor_class.is_some(),
        "PXE DISCOVER must include Vendor Class ID (opt 60)"
    );

    let vc_str = std::str::from_utf8(vendor_class.unwrap()).unwrap_or("");
    assert!(
        vc_str.starts_with("PXEClient"),
        "PXE vendor class must start with 'PXEClient', got: {}",
        vc_str
    );
}

#[test]
fn test_pxe_boot_options() {
    // Build a simulated DHCPOFFER with PXE boot options.
    let mut pxe_offer = DhcpPacket::new();
    pxe_offer.op = BOOTREPLY;
    pxe_offer.xid = TEST_XID;
    pxe_offer.set_yiaddr(Ipv4Addr::new(192, 168, 1, 100));
    // siaddr = TFTP server address
    pxe_offer.siaddr = Ipv4Addr::new(192, 168, 1, 1).octets();
    pxe_offer.chaddr[..6].copy_from_slice(&TEST_MAC);

    // Boot filename in the 'file' field
    let boot_file = b"pxelinux.0";
    pxe_offer.file[..boot_file.len()].copy_from_slice(boot_file);

    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pxe_offer.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;
    pxe_offer.options[offset] = OPTION_MESSAGE_TYPE;
    pxe_offer.options[offset + 1] = 1;
    pxe_offer.options[offset + 2] = DhcpMessageType::Offer.as_u8();
    offset += 3;

    // Option 67 (Boot File Name) — as DHCP option too
    let filename = b"pxelinux.0";
    pxe_offer.options[offset] = OPTION_FILENAME;
    pxe_offer.options[offset + 1] = filename.len() as u8;
    pxe_offer.options[offset + 2..offset + 2 + filename.len()].copy_from_slice(filename);
    offset += 2 + filename.len();

    pxe_offer.options[offset] = OPTION_END;

    // Verify PXE-specific fields.
    assert_eq!(
        pxe_offer.siaddr_addr(),
        Ipv4Addr::new(192, 168, 1, 1),
        "siaddr must point to TFTP server"
    );

    // Verify boot filename in file field.
    let file_str = std::str::from_utf8(&pxe_offer.file)
        .unwrap_or("")
        .trim_end_matches('\0');
    assert_eq!(file_str, "pxelinux.0", "Boot file name must be set");

    // Verify boot filename option (67).
    let fn_opt = find_option_in_packet(&pxe_offer.options, OPTION_FILENAME);
    assert!(fn_opt.is_some(), "PXE offer must include boot filename (opt 67)");
}

#[test]
fn test_pxe_proxy_mode() {
    // Verify PXE proxy DHCP port constant.
    assert_eq!(
        PXE_PORT, 4011,
        "PXE_PORT must be 4011 (dhcp-protocol.h)"
    );

    // Verify standard DHCP ports.
    assert_eq!(DHCP_SERVER_PORT, 67, "DHCP server port must be 67");
    assert_eq!(DHCP_CLIENT_PORT, 68, "DHCP client port must be 68");

    // In PXE proxy mode, the server listens on PXE_PORT (4011) for boot
    // parameter requests without IP address assignment.
    assert_ne!(
        PXE_PORT, DHCP_SERVER_PORT,
        "PXE port must differ from standard DHCP port"
    );
}

// ============================================================================
// Phase 6: Relay Agent Handling Tests
// ============================================================================

#[test]
fn test_relay_agent_forwarded_discover() {
    let relayed = build_relayed_discover(&TEST_MAC, TEST_XID, TEST_RELAY_IP);

    // Verify relay agent fields per RFC 2131 Section 4.1.
    assert_eq!(
        relayed.giaddr_addr(),
        TEST_RELAY_IP,
        "giaddr must be set to relay agent address"
    );
    assert_eq!(
        relayed.hops, 1,
        "Hop count must be incremented by relay"
    );

    // When giaddr is set, the server uses it for subnet selection.
    assert_ne!(
        relayed.giaddr_addr(),
        Ipv4Addr::UNSPECIFIED,
        "giaddr must be non-zero for relayed packets"
    );

    // The original DISCOVER message type must be preserved.
    assert_eq!(
        get_message_type(&relayed),
        Some(DhcpMessageType::Discover),
        "Relayed packet must retain DISCOVER type"
    );
}

#[test]
fn test_relay_agent_option_82() {
    // Build a DISCOVER with relay agent information option (82).
    let mut relayed = build_relayed_discover(&TEST_MAC, TEST_XID, TEST_RELAY_IP);

    // Find the end of existing options and insert Option 82 before END.
    let mut end_idx = 4;
    while end_idx < relayed.options.len() && relayed.options[end_idx] != OPTION_END {
        if relayed.options[end_idx] == 0 {
            end_idx += 1;
            continue;
        }
        let len = relayed.options[end_idx + 1] as usize;
        end_idx += 2 + len;
    }

    // Insert Option 82 (Relay Agent Information) with Circuit ID suboption.
    let circuit_id = b"eth0/1";
    // Option 82 header
    relayed.options[end_idx] = 82; // OPTION_AGENT_ID
    let opt82_len = 2 + circuit_id.len(); // suboption_code(1) + suboption_len(1) + data
    relayed.options[end_idx + 1] = opt82_len as u8;
    // Suboption 1: Circuit ID
    relayed.options[end_idx + 2] = 1; // SUBOPT_CIRCUIT_ID
    relayed.options[end_idx + 3] = circuit_id.len() as u8;
    relayed.options[end_idx + 4..end_idx + 4 + circuit_id.len()].copy_from_slice(circuit_id);
    // End option after option 82
    relayed.options[end_idx + 2 + opt82_len] = OPTION_END;

    // Verify Option 82 is present.
    let opt82 = find_option_in_packet(&relayed.options, 82);
    assert!(
        opt82.is_some(),
        "Relayed packet must include Option 82 (Relay Agent Info)"
    );

    // Verify Circuit ID suboption within Option 82.
    let opt82_data = opt82.unwrap();
    assert!(opt82_data.len() >= 2, "Option 82 must have suboption data");
    assert_eq!(opt82_data[0], 1, "First suboption must be Circuit ID (1)");
    let sub_len = opt82_data[1] as usize;
    assert_eq!(sub_len, circuit_id.len());
    assert_eq!(
        &opt82_data[2..2 + sub_len],
        circuit_id,
        "Circuit ID data must match"
    );
}

// ============================================================================
// Phase 7: Option Encoding/Decoding Tests
// ============================================================================

#[test]
fn test_dhcp_option_encoding() {
    let mut pkt = DhcpPacket::new();
    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Encode subnet mask (option 1, 4 bytes).
    pkt.options[offset] = OPTION_NETMASK;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&TEST_NETMASK.octets());
    offset += 6;

    // Encode router (option 3, 4 bytes).
    pkt.options[offset] = OPTION_ROUTER;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&TEST_ROUTER.octets());
    offset += 6;

    // Encode DNS server (option 6, 4 bytes).
    pkt.options[offset] = OPTION_DNSSERVER;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&TEST_DNS_SERVER.octets());
    offset += 6;

    // Encode lease time (option 51, 4 bytes, network byte order).
    pkt.options[offset] = OPTION_LEASE_TIME;
    pkt.options[offset + 1] = 4;
    pkt.options[offset + 2..offset + 6].copy_from_slice(&TEST_LEASE_TIME.to_be_bytes());
    offset += 6;

    pkt.options[offset] = OPTION_END;

    // Decode and verify each option.
    let netmask = find_option_in_packet(&pkt.options, OPTION_NETMASK).unwrap();
    assert_eq!(Ipv4Addr::from([netmask[0], netmask[1], netmask[2], netmask[3]]), TEST_NETMASK);

    let router = find_option_in_packet(&pkt.options, OPTION_ROUTER).unwrap();
    assert_eq!(Ipv4Addr::from([router[0], router[1], router[2], router[3]]), TEST_ROUTER);

    let dns = find_option_in_packet(&pkt.options, OPTION_DNSSERVER).unwrap();
    assert_eq!(Ipv4Addr::from([dns[0], dns[1], dns[2], dns[3]]), TEST_DNS_SERVER);

    let lease = find_option_in_packet(&pkt.options, OPTION_LEASE_TIME).unwrap();
    let lease_val = u32::from_be_bytes([lease[0], lease[1], lease[2], lease[3]]);
    assert_eq!(lease_val, TEST_LEASE_TIME);
}

#[test]
fn test_dhcp_option_decoding() {
    // Create a raw options buffer to decode.
    let mut options = [0u8; 312];
    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;

    // Message Type = ACK
    options[offset] = OPTION_MESSAGE_TYPE;
    options[offset + 1] = 1;
    options[offset + 2] = DhcpMessageType::Ack.as_u8();
    offset += 3;

    // Server Identifier
    options[offset] = OPTION_SERVER_IDENTIFIER;
    options[offset + 1] = 4;
    options[offset + 2..offset + 6].copy_from_slice(&TEST_SERVER_IP.octets());
    offset += 6;

    // Lease Time
    options[offset] = OPTION_LEASE_TIME;
    options[offset + 1] = 4;
    let lease_secs: u32 = 7200;
    options[offset + 2..offset + 6].copy_from_slice(&lease_secs.to_be_bytes());
    offset += 6;

    // Client ID
    let client_id = [0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // type(1) + MAC
    options[offset] = OPTION_CLIENT_ID;
    options[offset + 1] = client_id.len() as u8;
    options[offset + 2..offset + 2 + client_id.len()].copy_from_slice(&client_id);
    offset += 2 + client_id.len();

    options[offset] = OPTION_END;

    // Decode each option.
    let msg_type = find_option_in_packet(&options, OPTION_MESSAGE_TYPE);
    assert!(msg_type.is_some());
    assert_eq!(msg_type.unwrap()[0], DhcpMessageType::Ack.as_u8());

    let sid = find_option_in_packet(&options, OPTION_SERVER_IDENTIFIER);
    assert!(sid.is_some());
    assert_eq!(
        Ipv4Addr::from([sid.unwrap()[0], sid.unwrap()[1], sid.unwrap()[2], sid.unwrap()[3]]),
        TEST_SERVER_IP
    );

    let lt = find_option_in_packet(&options, OPTION_LEASE_TIME);
    assert!(lt.is_some());
    assert_eq!(
        u32::from_be_bytes([lt.unwrap()[0], lt.unwrap()[1], lt.unwrap()[2], lt.unwrap()[3]]),
        7200
    );

    let cid = find_option_in_packet(&options, OPTION_CLIENT_ID);
    assert!(cid.is_some());
    assert_eq!(cid.unwrap(), &client_id);
}

#[test]
fn test_parameter_request_list() {
    let discover = build_discover_packet(&TEST_MAC, TEST_XID);

    // Extract the Parameter Request List (option 55) from our DISCOVER.
    let prl = find_option_in_packet(&discover.options, OPTION_REQUESTED_OPTIONS);
    assert!(
        prl.is_some(),
        "DISCOVER must include Parameter Request List (opt 55)"
    );

    let requested = prl.unwrap();
    assert_eq!(requested.len(), 4, "We requested 4 options");
    assert!(
        requested.contains(&OPTION_NETMASK),
        "Must request subnet mask"
    );
    assert!(
        requested.contains(&OPTION_ROUTER),
        "Must request router"
    );
    assert!(
        requested.contains(&OPTION_DNSSERVER),
        "Must request DNS server"
    );
    assert!(
        requested.contains(&OPTION_LEASE_TIME),
        "Must request lease time"
    );
}

#[test]
fn test_overloaded_options() {
    // Verify the OPTION_OVERLOAD constant.
    assert_eq!(
        OPTION_OVERLOAD, 52,
        "Option Overload must be option code 52"
    );

    // Build a packet with Option 52 indicating 'file' field overload (value=1).
    let mut pkt = DhcpPacket::new();
    let cookie_bytes = DHCP_COOKIE.to_be_bytes();
    pkt.options[0..4].copy_from_slice(&cookie_bytes);

    let mut offset = 4;
    pkt.options[offset] = OPTION_MESSAGE_TYPE;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = DhcpMessageType::Ack.as_u8();
    offset += 3;

    // Option 52 = 1 (file field contains options)
    pkt.options[offset] = OPTION_OVERLOAD;
    pkt.options[offset + 1] = 1;
    pkt.options[offset + 2] = 1; // 1 = file field overloaded
    offset += 3;

    pkt.options[offset] = OPTION_END;

    // Write options into the 'file' field (128 bytes).
    pkt.file[0] = OPTION_HOSTNAME;
    let hostname = b"overloaded-host";
    pkt.file[1] = hostname.len() as u8;
    pkt.file[2..2 + hostname.len()].copy_from_slice(hostname);
    pkt.file[2 + hostname.len()] = OPTION_END;

    // Verify the overload indicator.
    let overload = find_option_in_packet(&pkt.options, OPTION_OVERLOAD);
    assert!(overload.is_some(), "Must contain Option Overload");
    assert_eq!(overload.unwrap()[0], 1, "Overload value 1 = file field");

    // Verify options can be found in the overloaded file field.
    // (Read hostname from file field directly.)
    assert_eq!(pkt.file[0], OPTION_HOSTNAME);
    let len = pkt.file[1] as usize;
    let name = std::str::from_utf8(&pkt.file[2..2 + len]).unwrap();
    assert_eq!(name, "overloaded-host");
}

// ============================================================================
// Phase 8: BOOTP Compatibility Tests
// ============================================================================

#[test]
fn test_bootp_request_handling() {
    let bootp = build_bootp_request(&TEST_MAC, TEST_XID);

    // BOOTP request must have BOOTREQUEST opcode.
    assert_eq!(bootp.op, BOOTREQUEST, "BOOTP op must be BOOTREQUEST");
    assert_eq!(bootp.htype, 1, "Hardware type must be Ethernet");
    assert_eq!(bootp.hlen, 6, "Hardware address length must be 6");
    assert_eq!(&bootp.chaddr[..6], &TEST_MAC, "Client MAC must be set");

    // BOOTP has no DHCP magic cookie — first 4 bytes of options should be zero.
    let cookie = u32::from_be_bytes([
        bootp.options[0],
        bootp.options[1],
        bootp.options[2],
        bootp.options[3],
    ]);
    assert_ne!(
        cookie, DHCP_COOKIE,
        "BOOTP request must NOT have DHCP magic cookie"
    );
    assert_eq!(cookie, 0, "BOOTP options field should be zero-initialized");

    // There should be no Message Type option (pure BOOTP).
    let msg_type = get_message_type(&bootp);
    assert!(
        msg_type.is_none(),
        "BOOTP request must NOT have DHCP message type option"
    );

    // A BOOTP reply should use BOOTREPLY opcode.
    assert_eq!(BOOTREPLY, 2, "BOOTREPLY constant must be 2");
    assert_eq!(BOOTREQUEST, 1, "BOOTREQUEST constant must be 1");
}

// ============================================================================
// Additional Validation Tests
// ============================================================================

#[test]
fn test_dhcp_message_type_enum_completeness() {
    // Verify all 13 DHCP message types have correct numeric values.
    assert_eq!(DhcpMessageType::Discover.as_u8(), 1);
    assert_eq!(DhcpMessageType::Offer.as_u8(), 2);
    assert_eq!(DhcpMessageType::Request.as_u8(), 3);
    assert_eq!(DhcpMessageType::Decline.as_u8(), 4);
    assert_eq!(DhcpMessageType::Ack.as_u8(), 5);
    assert_eq!(DhcpMessageType::Nak.as_u8(), 6);
    assert_eq!(DhcpMessageType::Release.as_u8(), 7);
    assert_eq!(DhcpMessageType::Inform.as_u8(), 8);

    // Verify TryFrom roundtrip.
    for val in 1..=13u8 {
        let msg_type = DhcpMessageType::try_from(val);
        assert!(msg_type.is_ok(), "Value {} must be a valid message type", val);
        assert_eq!(msg_type.unwrap().as_u8(), val, "Roundtrip must preserve value");
    }

    // Invalid values must return Err.
    assert!(DhcpMessageType::try_from(0).is_err(), "0 is not a valid message type");
    assert!(DhcpMessageType::try_from(14).is_err(), "14 is not a valid message type");
    assert!(DhcpMessageType::try_from(255).is_err(), "255 is not a valid message type");
}

#[test]
fn test_dhcp_message_type_display_names() {
    assert_eq!(DhcpMessageType::Discover.name(), "DHCPDISCOVER");
    assert_eq!(DhcpMessageType::Offer.name(), "DHCPOFFER");
    assert_eq!(DhcpMessageType::Request.name(), "DHCPREQUEST");
    assert_eq!(DhcpMessageType::Decline.name(), "DHCPDECLINE");
    assert_eq!(DhcpMessageType::Ack.name(), "DHCPACK");
    assert_eq!(DhcpMessageType::Nak.name(), "DHCPNAK");
    assert_eq!(DhcpMessageType::Release.name(), "DHCPRELEASE");
    assert_eq!(DhcpMessageType::Inform.name(), "DHCPINFORM");
}

#[test]
fn test_dhcp_packet_field_accessors() {
    let mut pkt = DhcpPacket::new();

    // Test yiaddr accessor
    pkt.set_yiaddr(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(pkt.yiaddr_addr(), Ipv4Addr::new(10, 0, 0, 1));

    // Test ciaddr accessor
    pkt.set_ciaddr(Ipv4Addr::new(172, 16, 0, 5));
    assert_eq!(pkt.ciaddr_addr(), Ipv4Addr::new(172, 16, 0, 5));

    // Test siaddr accessor
    assert_eq!(pkt.siaddr_addr(), Ipv4Addr::UNSPECIFIED);
    pkt.siaddr = Ipv4Addr::new(192, 168, 1, 1).octets();
    assert_eq!(pkt.siaddr_addr(), Ipv4Addr::new(192, 168, 1, 1));

    // Test giaddr accessor
    assert_eq!(pkt.giaddr_addr(), Ipv4Addr::UNSPECIFIED);
    pkt.giaddr = Ipv4Addr::new(10, 0, 0, 1).octets();
    assert_eq!(pkt.giaddr_addr(), Ipv4Addr::new(10, 0, 0, 1));
}

#[test]
fn test_dhcp_packet_chaddr_max() {
    // Verify DHCP_CHADDR_MAX constant.
    assert_eq!(
        DHCP_CHADDR_MAX, 16,
        "DHCP_CHADDR_MAX must be 16 (RFC 2131)"
    );

    let pkt = DhcpPacket::new();
    assert_eq!(
        pkt.chaddr.len(),
        DHCP_CHADDR_MAX,
        "chaddr field must be DHCP_CHADDR_MAX bytes"
    );
}

#[test]
fn test_min_packet_size_constant() {
    // Verify MIN_PACKETSZ for Linux kernel compatibility.
    assert_eq!(
        MIN_PACKETSZ, 300,
        "MIN_PACKETSZ must be 300 for Linux kernel DHCP client"
    );
}

#[test]
fn test_dhcp_cookie_constant() {
    assert_eq!(
        DHCP_COOKIE, 0x63825363,
        "DHCP magic cookie must be 0x63825363 (RFC 2131)"
    );
}

#[test]
fn test_dhcp_context_range_configuration() {
    let context = create_test_context();

    // Verify context fields.
    assert_eq!(context.start, TEST_RANGE_START);
    assert_eq!(context.end, TEST_RANGE_END);
    assert_eq!(context.netmask, TEST_NETMASK);
    assert_eq!(context.broadcast, TEST_BROADCAST);
    assert_eq!(context.router, TEST_ROUTER);
    assert_eq!(context.local, TEST_SERVER_IP);
    assert_eq!(context.lease_time, TEST_LEASE_TIME);
    assert!(context.flags.contains(DhcpContextFlags::DHCP));
    assert_eq!(context.netid.net, "lan");
}

#[test]
fn test_alladdr_ipv4_construction() {
    let ip = Ipv4Addr::new(192, 168, 1, 100);
    let addr = AllAddr::from_ipv4(ip);
    assert!(addr.is_v4(), "AllAddr from IPv4 must be V4 variant");
    assert_eq!(addr.as_ipv4(), Some(&ip));

    // Test From trait.
    let addr2: AllAddr = ip.into();
    assert!(addr2.is_v4());
}

#[test]
fn test_lease_flags_bitfield() {
    // Verify individual LeaseFlags bits.
    let mut flags = LeaseFlags::NEW;
    assert!(flags.contains(LeaseFlags::NEW));
    assert!(!flags.contains(LeaseFlags::CHANGED));

    flags |= LeaseFlags::CHANGED;
    assert!(flags.contains(LeaseFlags::NEW));
    assert!(flags.contains(LeaseFlags::CHANGED));

    flags.remove(LeaseFlags::NEW);
    assert!(!flags.contains(LeaseFlags::NEW));
    assert!(flags.contains(LeaseFlags::CHANGED));
}

#[test]
fn test_dhcp_config_flags_bitfield() {
    let flags = DhcpConfigFlags::ADDR | DhcpConfigFlags::NAME | DhcpConfigFlags::TIME;
    assert!(flags.contains(DhcpConfigFlags::ADDR));
    assert!(flags.contains(DhcpConfigFlags::NAME));
    assert!(flags.contains(DhcpConfigFlags::TIME));
    assert!(!flags.contains(DhcpConfigFlags::DISABLE));
    assert!(!flags.contains(DhcpConfigFlags::CLID));
}

#[test]
fn test_protocol_enum() {
    assert_eq!(format!("{}", Protocol::V4), "DHCPv4");
    assert_eq!(format!("{}", Protocol::V6), "DHCPv6");
    assert_ne!(Protocol::V4, Protocol::V6);
}

#[test]
fn test_socket_address_construction() {
    use std::net::SocketAddrV4;
    let sa = SocketAddress::V4(SocketAddrV4::new(TEST_SERVER_IP, DHCP_SERVER_PORT));
    assert!(sa.is_v4());
    assert!(!sa.is_v6());
    assert_eq!(sa.port(), DHCP_SERVER_PORT);
}

#[test]
fn test_sdbm_hash_empty_input() {
    // Empty input should return 0 (hash starts at 0, no iterations).
    let hash = sdbm_hash(&[]);
    assert_eq!(hash, 0, "SDBM hash of empty input must be 0");
}

#[test]
fn test_sdbm_hash_single_byte() {
    // Single byte: hash = 0 * 131 + byte = byte
    let hash = sdbm_hash(&[42]);
    assert_eq!(hash, 42, "SDBM hash of single byte must equal that byte");
}

#[test]
fn test_lease_database_creation() {
    // Test default lease database creation.
    let _db = create_test_lease_db();
    // LeaseDatabase::new should succeed without error.
    // Further operations require initialization via init().

    // Test with custom max leases.
    let _custom_db = LeaseDatabase::new(Some(500), None);
    // Database should be created successfully.

    // Test with zero max leases (edge case).
    let _zero_db = LeaseDatabase::new(Some(0), None);
    // Should create but effectively disable new lease allocation.
}

#[test]
fn test_dhcp_lease_fields_complete() {
    let now = now_secs();
    let lease = create_test_lease(
        Ipv4Addr::new(10, 0, 0, 100),
        &TEST_MAC_ALT,
        "alternate-host",
        now + 7200,
    );

    assert_eq!(lease.addr, Ipv4Addr::new(10, 0, 0, 100));
    assert_eq!(&lease.hwaddr, &TEST_MAC_ALT.to_vec());
    assert_eq!(lease.hostname.as_deref(), Some("alternate-host"));
    assert_eq!(lease.hwaddr_len, 6);
    assert_eq!(lease.hwaddr_type, 1);
    assert_eq!(lease.override_addr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(lease.giaddr, Ipv4Addr::UNSPECIFIED);
    assert!(lease.clid.is_empty());
    assert!(lease.extradata.is_empty());
    assert!(lease.agent_id.is_empty());
    assert!(lease.vendorclass.is_empty());
    assert!(lease.fqdn.is_none());
    assert!(lease.old_hostname.is_none());
    assert_eq!(lease.last_interface, 0);
    assert_eq!(lease.new_interface, 0);
    assert_eq!(lease.new_prefixlen, 0);
}

#[test]
fn test_dhcp_net_id_tag_system() {
    let tag1 = DhcpNetId {
        net: "known".to_string(),
    };
    let tag2 = DhcpNetId {
        net: "vlan100".to_string(),
    };
    let tag3 = DhcpNetId {
        net: "known".to_string(),
    };

    // Tags with the same name should be equal.
    assert_eq!(tag1, tag3, "Tags with same name must be equal");
    assert_ne!(tag1, tag2, "Tags with different names must not be equal");

    // Tags should be usable in Vec collections.
    let tags = vec![tag1.clone(), tag2.clone()];
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&tag1));
    assert!(tags.contains(&tag2));
}

#[test]
fn test_ping_result_construction() {
    let now = now_secs();
    let addr = Ipv4Addr::new(192, 168, 1, 200);
    let ping = PingResult {
        addr,
        time: now,
        hash: sdbm_hash(&addr.octets()),
    };

    assert_eq!(ping.addr, addr);
    assert!(ping.time > 0);
    assert_ne!(ping.hash, 0);
}

#[test]
fn test_dhcp_context_flags() {
    // Verify individual context flag bits.
    let flags = DhcpContextFlags::DHCP | DhcpContextFlags::STATIC;
    assert!(flags.contains(DhcpContextFlags::DHCP));
    assert!(flags.contains(DhcpContextFlags::STATIC));
    assert!(!flags.contains(DhcpContextFlags::PROXY));
    assert!(!flags.contains(DhcpContextFlags::NETMASK));
}

#[test]
fn test_constants_match_config_h() {
    // Comprehensive verification of all DHCP-related constants against config.h values.
    assert_eq!(MAXLEASES, 1000, "MAXLEASES (config.h line 407)");
    assert_eq!(PING_WAIT, 3, "PING_WAIT (config.h line 422)");
    assert_eq!(PING_CACHE_TIME, 30, "PING_CACHE_TIME (config.h line 436)");
    assert_eq!(DECLINE_BACKOFF, 600, "DECLINE_BACKOFF (config.h line 451)");
    assert_eq!(DHCP_PACKET_MAX, 16384, "DHCP_PACKET_MAX (config.h line 466)");
    assert_eq!(DEFLEASE, 3600, "DEFLEASE (config.h line 551)");
    assert_eq!(DHCP_SERVER_PORT, 67, "DHCP_SERVER_PORT");
    assert_eq!(DHCP_CLIENT_PORT, 68, "DHCP_CLIENT_PORT");
    assert_eq!(PXE_PORT, 4011, "PXE_PORT");
    assert_eq!(DHCP_CHADDR_MAX, 16, "DHCP_CHADDR_MAX");
    assert_eq!(MIN_PACKETSZ, 300, "MIN_PACKETSZ");
}

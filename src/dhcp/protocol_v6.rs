//! DHCPv6 wire-format protocol constants, message types, option codes, status codes,
//! and DUID type definitions per RFC 3315 and extension RFCs.
//!
//! This module is the Rust equivalent of `src/dhcp6-protocol.h` from the C implementation.
//! It provides all protocol-level definitions required for DHCPv6 packet construction,
//! parsing, and validation across the dnsmasq DHCPv6 implementation.
//!
//! # Wire Protocol Layout
//!
//! DHCPv6 messages consist of:
//! - 1-byte message type (values defined as [`Dhcp6MessageType`] / `DHCP6*` constants)
//! - 3-byte transaction ID
//! - Variable-length options using TLV encoding:
//!   - 2-byte option code (`OPTION6_*` constants)
//!   - 2-byte option length (big-endian, excludes the 4-byte option header)
//!   - Variable-length option data
//!
//! # RFC Compliance
//!
//! - RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! - RFC 3633: IPv6 Prefix Options for DHCPv6 (IA_PD, IAPREFIX)
//! - RFC 3646: DNS Configuration options for DHCPv6 (DNS_SERVER, DOMAIN_SEARCH)
//! - RFC 4242: Information Refresh Time Option (REFRESH_TIME)
//! - RFC 4580: DHCP Subscriber-ID Suboption (SUBSCRIBER_ID)
//! - RFC 4649: DHCPv6 Relay Agent Remote-ID Option (REMOTE_ID)
//! - RFC 4704: The DHCPv6 Client FQDN Option (FQDN)
//! - RFC 5908: NTP Server Option for DHCPv6 (NTP_SERVER)
//! - RFC 6355: Definition of the UUID-Based DHCPv6 Unique Identifier (DUID_UUID)
//! - RFC 6939: Client Link-Layer Address Option (CLIENT_MAC)
//! - RFC 8520: Manufacturer Usage Description (MUD_URL)

use std::net::Ipv6Addr;

// ============================================================================
// Port Constants (RFC 3315 Section 5.2)
// ============================================================================

/// DHCPv6 server UDP port number.
///
/// Well-known port 547 used by DHCPv6 servers to receive client messages.
/// Clients send DHCPv6 messages (SOLICIT, REQUEST, RENEW, etc.) to this port.
/// Per RFC 3315 Section 5.2.
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// DHCPv6 client UDP port number.
///
/// Well-known port 546 used by DHCPv6 clients to receive server messages.
/// Servers send DHCPv6 responses (ADVERTISE, REPLY, RECONFIGURE) to this port.
/// Per RFC 3315 Section 5.2.
pub const DHCPV6_CLIENT_PORT: u16 = 546;

// ============================================================================
// Multicast Address Constants (RFC 3315 Section 5.1)
// ============================================================================

/// All_DHCP_Servers multicast address string representation (site-local scope).
///
/// IPv6 multicast address FF05::1:3 used by DHCPv6 clients to communicate with
/// DHCPv6 servers when the client knows the site-local scope is appropriate.
/// Per RFC 3315 Section 5.1.
pub const ALL_SERVERS_STR: &str = "FF05::1:3";

/// All_DHCP_Relay_Agents_and_Servers multicast address string representation (link-local scope).
///
/// IPv6 multicast address FF02::1:2 used by DHCPv6 clients to communicate with
/// DHCPv6 relay agents and servers on the local link. This is the most commonly used
/// multicast address for initial DHCPv6 client requests (SOLICIT).
/// Per RFC 3315 Section 5.1.
pub const ALL_RELAY_AGENTS_AND_SERVERS_STR: &str = "FF02::1:2";

/// All_DHCP_Servers multicast address as a typed [`Ipv6Addr`] (site-local scope).
///
/// Equivalent to `FF05::1:3`. Per RFC 3315 Section 5.1.
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

/// All_DHCP_Relay_Agents_and_Servers multicast address as a typed [`Ipv6Addr`] (link-local scope).
///
/// Equivalent to `FF02::1:2`. Per RFC 3315 Section 5.1.
pub const ALL_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

// ============================================================================
// Message Type Enum (RFC 3315 Section 5.3)
// ============================================================================

/// DHCPv6 message types per RFC 3315 Section 5.3.
///
/// Each variant's discriminant value matches the on-wire message type byte exactly,
/// ensuring byte-for-byte compatibility with the C implementation's `#define` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Dhcp6MessageType {
    /// Client-to-server: locate available DHCPv6 servers (RFC 3315 Section 17.1.1)
    Solicit = 1,
    /// Server-to-client: response to SOLICIT with proposed addresses (RFC 3315 Section 17.1.2)
    Advertise = 2,
    /// Client-to-server: request assignment from specific server (RFC 3315 Section 18.1.1)
    Request = 3,
    /// Client-to-server: verify addresses are still appropriate for link (RFC 3315 Section 18.1.2)
    Confirm = 4,
    /// Client-to-server: extend address lifetimes from original server (RFC 3315 Section 18.1.3)
    Renew = 5,
    /// Client-to-server (multicast): extend lifetimes when original server unreachable (RFC 3315 Section 18.1.4)
    Rebind = 6,
    /// Server-to-client: assigned addresses, configuration, or status (RFC 3315 Sections 18.2.1-18.2.8)
    Reply = 7,
    /// Client-to-server: relinquish assigned addresses (RFC 3315 Section 18.1.6)
    Release = 8,
    /// Client-to-server: report duplicate address detected (RFC 3315 Section 18.1.7)
    Decline = 9,
    /// Server-to-client: trigger RENEW or INFORMATION-REQUEST (RFC 3315 Section 19.1.1)
    Reconfigure = 10,
    /// Client-to-server: request configuration only, no addresses (RFC 3315 Section 18.1.5)
    InformationRequest = 11,
    /// Relay-to-server: encapsulate client message for forwarding (RFC 3315 Section 20.1.1)
    RelayForward = 12,
    /// Server-to-relay: encapsulate reply for forwarding to client (RFC 3315 Section 20.1.2)
    RelayReply = 13,
}

impl Dhcp6MessageType {
    /// Returns the human-readable name of this message type.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Solicit => "SOLICIT",
            Self::Advertise => "ADVERTISE",
            Self::Request => "REQUEST",
            Self::Confirm => "CONFIRM",
            Self::Renew => "RENEW",
            Self::Rebind => "REBIND",
            Self::Reply => "REPLY",
            Self::Release => "RELEASE",
            Self::Decline => "DECLINE",
            Self::Reconfigure => "RECONFIGURE",
            Self::InformationRequest => "INFORMATION-REQUEST",
            Self::RelayForward => "RELAY-FORW",
            Self::RelayReply => "RELAY-REPL",
        }
    }
}

impl TryFrom<u8> for Dhcp6MessageType {
    type Error = u8;

    /// Attempts to convert a raw `u8` wire-format value into a [`Dhcp6MessageType`].
    ///
    /// Returns `Err(value)` if the value does not correspond to a known DHCPv6 message type.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Solicit),
            2 => Ok(Self::Advertise),
            3 => Ok(Self::Request),
            4 => Ok(Self::Confirm),
            5 => Ok(Self::Renew),
            6 => Ok(Self::Rebind),
            7 => Ok(Self::Reply),
            8 => Ok(Self::Release),
            9 => Ok(Self::Decline),
            10 => Ok(Self::Reconfigure),
            11 => Ok(Self::InformationRequest),
            12 => Ok(Self::RelayForward),
            13 => Ok(Self::RelayReply),
            _ => Err(value),
        }
    }
}

impl core::fmt::Display for Dhcp6MessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ============================================================================
// Bare Message Type Constants (backward compatibility)
// ============================================================================

/// SOLICIT message type (1) — per RFC 3315 Section 17.1.1
pub const DHCP6SOLICIT: u8 = 1;
/// ADVERTISE message type (2) — per RFC 3315 Section 17.1.2
pub const DHCP6ADVERTISE: u8 = 2;
/// REQUEST message type (3) — per RFC 3315 Section 18.1.1
pub const DHCP6REQUEST: u8 = 3;
/// CONFIRM message type (4) — per RFC 3315 Section 18.1.2
pub const DHCP6CONFIRM: u8 = 4;
/// RENEW message type (5) — per RFC 3315 Section 18.1.3
pub const DHCP6RENEW: u8 = 5;
/// REBIND message type (6) — per RFC 3315 Section 18.1.4
pub const DHCP6REBIND: u8 = 6;
/// REPLY message type (7) — per RFC 3315 Sections 18.2.1-18.2.8
pub const DHCP6REPLY: u8 = 7;
/// RELEASE message type (8) — per RFC 3315 Section 18.1.6
pub const DHCP6RELEASE: u8 = 8;
/// DECLINE message type (9) — per RFC 3315 Section 18.1.7
pub const DHCP6DECLINE: u8 = 9;
/// RECONFIGURE message type (10) — per RFC 3315 Section 19.1.1
pub const DHCP6RECONFIGURE: u8 = 10;
/// INFORMATION-REQUEST message type (11) — per RFC 3315 Section 18.1.5
pub const DHCP6IREQ: u8 = 11;
/// RELAY-FORW message type (12) — per RFC 3315 Section 20.1.1
pub const DHCP6RELAYFORW: u8 = 12;
/// RELAY-REPL message type (13) — per RFC 3315 Section 20.1.2
pub const DHCP6RELAYREPL: u8 = 13;

// ============================================================================
// DHCPv6 Option Codes (RFC 3315 Section 22 + extension RFCs)
// ============================================================================

/// Client Identifier option — contains client DUID (RFC 3315 Section 22.2)
pub const OPTION6_CLIENT_ID: u16 = 1;
/// Server Identifier option — contains server DUID (RFC 3315 Section 22.3)
pub const OPTION6_SERVER_ID: u16 = 2;
/// Identity Association for Non-temporary Addresses (RFC 3315 Section 22.4)
pub const OPTION6_IA_NA: u16 = 3;
/// Identity Association for Temporary Addresses (RFC 3315 Section 22.5)
pub const OPTION6_IA_TA: u16 = 4;
/// IA Address option — encapsulated within IA_NA or IA_TA (RFC 3315 Section 22.6)
pub const OPTION6_IAADDR: u16 = 5;
/// Option Request Option — list of requested option codes (RFC 3315 Section 22.7)
pub const OPTION6_ORO: u16 = 6;
/// Preference option — 8-bit server preference value (RFC 3315 Section 22.8)
pub const OPTION6_PREFERENCE: u16 = 7;
/// Elapsed Time option — hundredths of seconds since exchange began (RFC 3315 Section 22.9)
pub const OPTION6_ELAPSED_TIME: u16 = 8;
/// Relay Message option — encapsulates client/server message in relay (RFC 3315 Section 22.10)
pub const OPTION6_RELAY_MSG: u16 = 9;
/// Authentication option — message authentication (RFC 3315 Section 22.11)
pub const OPTION6_AUTH: u16 = 11;
/// Server Unicast option — enables direct unicast to server (RFC 3315 Section 22.12)
pub const OPTION6_UNICAST: u16 = 12;
/// Status Code option — indicates success or failure reason (RFC 3315 Section 22.13)
pub const OPTION6_STATUS_CODE: u16 = 13;
/// Rapid Commit option — enables two-message exchange (RFC 3315 Section 22.14)
pub const OPTION6_RAPID_COMMIT: u16 = 14;
/// User Class option — client user class identification (RFC 3315 Section 22.15)
pub const OPTION6_USER_CLASS: u16 = 15;
/// Vendor Class option — vendor-specific client classification (RFC 3315 Section 22.16)
pub const OPTION6_VENDOR_CLASS: u16 = 16;
/// Vendor-specific Information option — vendor-defined options (RFC 3315 Section 22.17)
pub const OPTION6_VENDOR_OPTS: u16 = 17;
/// Interface-Id option — relay agent interface identification (RFC 3315 Section 22.18)
pub const OPTION6_INTERFACE_ID: u16 = 18;
/// Reconfigure Message option — specifies desired reconfigure response type (RFC 3315 Section 22.19)
pub const OPTION6_RECONFIGURE_MSG: u16 = 19;
/// Reconfigure Accept option — client accepts RECONFIGURE messages (RFC 3315 Section 22.20)
pub const OPTION6_RECONF_ACCEPT: u16 = 20;
/// DNS Recursive Name Server option — IPv6 DNS server addresses (RFC 3646 Section 3)
pub const OPTION6_DNS_SERVER: u16 = 23;
/// Domain Search List option — DNS search domain list (RFC 3646 Section 4)
pub const OPTION6_DOMAIN_SEARCH: u16 = 24;
/// Identity Association for Prefix Delegation (RFC 3633 Section 9)
pub const OPTION6_IA_PD: u16 = 25;
/// IA Prefix option — delegated IPv6 prefix within IA_PD (RFC 3633 Section 10)
pub const OPTION6_IAPREFIX: u16 = 26;
/// Information Refresh Time option — stateless DHCPv6 refresh interval (RFC 4242 Section 3.1)
pub const OPTION6_REFRESH_TIME: u16 = 32;
/// Remote Identifier option — relay agent remote host identification (RFC 4649 Section 3)
pub const OPTION6_REMOTE_ID: u16 = 37;
/// Subscriber Identifier option — provider subscriber identification (RFC 4580 Section 3)
pub const OPTION6_SUBSCRIBER_ID: u16 = 38;
/// Fully Qualified Domain Name option — client FQDN negotiation (RFC 4704 Section 4)
pub const OPTION6_FQDN: u16 = 39;
/// Network Time Protocol Servers option — NTP server information (RFC 5908 Section 4)
pub const OPTION6_NTP_SERVER: u16 = 56;
/// Client Link-Layer Address option — client MAC address (RFC 6939 Section 3)
pub const OPTION6_CLIENT_MAC: u16 = 79;
/// Manufacturer Usage Description URL option — IoT device MUD file URL (RFC 8520 Section 10)
pub const OPTION6_MUD_URL: u16 = 112;

// ============================================================================
// NTP Server Option Suboptions (RFC 5908 Section 4)
// ============================================================================

/// NTP Server Address suboption — unicast NTP server IPv6 addresses (RFC 5908 Section 4.1)
pub const NTP_SUBOPTION_SRV_ADDR: u16 = 1;
/// NTP Multicast Address suboption — NTP multicast group addresses (RFC 5908 Section 4.2)
pub const NTP_SUBOPTION_MC_ADDR: u16 = 2;
/// NTP Server FQDN suboption — NTP server fully qualified domain names (RFC 5908 Section 4.3)
pub const NTP_SUBOPTION_SRV_FQDN: u16 = 3;

// ============================================================================
// Status Code Enum (RFC 3315 Section 24.4)
// ============================================================================

/// DHCPv6 status codes per RFC 3315 Section 24.4.
///
/// Each variant's discriminant value matches the on-wire status code exactly,
/// ensuring byte-for-byte compatibility with the C implementation's `#define` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dhcp6StatusCode {
    /// Successful operation (RFC 3315 Section 24.4)
    Success = 0,
    /// Failure for unspecified reason (RFC 3315 Section 24.4)
    UnspecFail = 1,
    /// Server has no addresses available to assign (RFC 3315 Section 24.4)
    NoAddrsAvail = 2,
    /// Server has no record of client binding/lease (RFC 3315 Section 24.4)
    NoBinding = 3,
    /// Client addresses are not appropriate for attached link (RFC 3315 Section 24.4)
    NotOnLink = 4,
    /// Client should use multicast instead of unicast (RFC 3315 Section 24.4)
    UseMulticast = 5,
}

impl Dhcp6StatusCode {
    /// Returns the human-readable name of this status code.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::UnspecFail => "UnspecFail",
            Self::NoAddrsAvail => "NoAddrsAvail",
            Self::NoBinding => "NoBinding",
            Self::NotOnLink => "NotOnLink",
            Self::UseMulticast => "UseMulticast",
        }
    }
}

impl TryFrom<u16> for Dhcp6StatusCode {
    type Error = u16;

    /// Attempts to convert a raw `u16` wire-format value into a [`Dhcp6StatusCode`].
    ///
    /// Returns `Err(value)` if the value does not correspond to a known DHCPv6 status code.
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::UnspecFail),
            2 => Ok(Self::NoAddrsAvail),
            3 => Ok(Self::NoBinding),
            4 => Ok(Self::NotOnLink),
            5 => Ok(Self::UseMulticast),
            _ => Err(value),
        }
    }
}

impl core::fmt::Display for Dhcp6StatusCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ============================================================================
// Bare Status Code Constants (backward compatibility)
// ============================================================================

/// Success status code (0) — per RFC 3315 Section 24.4
pub const DHCP6SUCCESS: u16 = 0;
/// Unspecified failure status code (1) — per RFC 3315 Section 24.4
pub const DHCP6UNSPEC: u16 = 1;
/// No Addresses Available status code (2) — per RFC 3315 Section 24.4
pub const DHCP6NOADDRS: u16 = 2;
/// No Binding status code (3) — per RFC 3315 Section 24.4
pub const DHCP6NOBINDING: u16 = 3;
/// Not On Link status code (4) — per RFC 3315 Section 24.4
pub const DHCP6NOTONLINK: u16 = 4;
/// Use Multicast status code (5) — per RFC 3315 Section 24.4
pub const DHCP6USEMULTI: u16 = 5;

// ============================================================================
// DUID Types (RFC 3315 Section 9, RFC 6355)
// ============================================================================

/// DUID based on Link-Layer address plus Time (DUID-LLT).
///
/// Contains hardware type, time value, and link-layer address. The time value is the
/// number of seconds since midnight January 1, 2000 UTC. Most common DUID type.
/// Per RFC 3315 Section 9.2.
pub const DUID_LLT: u16 = 1;

/// DUID based on Enterprise Number (DUID-EN).
///
/// Contains IANA-assigned enterprise number and vendor-chosen identifier.
/// Per RFC 3315 Section 9.3.
pub const DUID_EN: u16 = 2;

/// DUID based on Link-Layer address (DUID-LL).
///
/// Contains hardware type and link-layer address without time component.
/// Simpler than DUID-LLT but stable only as long as hardware doesn't change.
/// Per RFC 3315 Section 9.4.
pub const DUID_LL: u16 = 3;

/// DUID based on UUID (DUID-UUID).
///
/// Contains a UUID (Universally Unique Identifier) conforming to RFC 4122.
/// Useful for virtual machines and devices without stable link-layer addresses.
/// Per RFC 6355 Section 4.
pub const DUID_UUID: u16 = 4;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_constants() {
        assert_eq!(DHCPV6_SERVER_PORT, 547);
        assert_eq!(DHCPV6_CLIENT_PORT, 546);
    }

    #[test]
    fn test_multicast_address_strings() {
        assert_eq!(ALL_SERVERS_STR, "FF05::1:3");
        assert_eq!(ALL_RELAY_AGENTS_AND_SERVERS_STR, "FF02::1:2");
    }

    #[test]
    fn test_multicast_address_typed() {
        assert_eq!(ALL_SERVERS, Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3));
        assert_eq!(
            ALL_RELAY_AGENTS_AND_SERVERS,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2)
        );
        // Verify string representation matches the string constants
        let servers_str: Ipv6Addr = ALL_SERVERS_STR.parse().unwrap();
        assert_eq!(ALL_SERVERS, servers_str);
        let relay_str: Ipv6Addr = ALL_RELAY_AGENTS_AND_SERVERS_STR.parse().unwrap();
        assert_eq!(ALL_RELAY_AGENTS_AND_SERVERS, relay_str);
    }

    #[test]
    fn test_message_type_enum_values() {
        assert_eq!(Dhcp6MessageType::Solicit as u8, 1);
        assert_eq!(Dhcp6MessageType::Advertise as u8, 2);
        assert_eq!(Dhcp6MessageType::Request as u8, 3);
        assert_eq!(Dhcp6MessageType::Confirm as u8, 4);
        assert_eq!(Dhcp6MessageType::Renew as u8, 5);
        assert_eq!(Dhcp6MessageType::Rebind as u8, 6);
        assert_eq!(Dhcp6MessageType::Reply as u8, 7);
        assert_eq!(Dhcp6MessageType::Release as u8, 8);
        assert_eq!(Dhcp6MessageType::Decline as u8, 9);
        assert_eq!(Dhcp6MessageType::Reconfigure as u8, 10);
        assert_eq!(Dhcp6MessageType::InformationRequest as u8, 11);
        assert_eq!(Dhcp6MessageType::RelayForward as u8, 12);
        assert_eq!(Dhcp6MessageType::RelayReply as u8, 13);
    }

    #[test]
    fn test_message_type_try_from_valid() {
        assert_eq!(Dhcp6MessageType::try_from(1), Ok(Dhcp6MessageType::Solicit));
        assert_eq!(Dhcp6MessageType::try_from(7), Ok(Dhcp6MessageType::Reply));
        assert_eq!(
            Dhcp6MessageType::try_from(11),
            Ok(Dhcp6MessageType::InformationRequest)
        );
        assert_eq!(
            Dhcp6MessageType::try_from(13),
            Ok(Dhcp6MessageType::RelayReply)
        );
    }

    #[test]
    fn test_message_type_try_from_invalid() {
        assert_eq!(Dhcp6MessageType::try_from(0), Err(0));
        assert_eq!(Dhcp6MessageType::try_from(14), Err(14));
        assert_eq!(Dhcp6MessageType::try_from(255), Err(255));
    }

    #[test]
    fn test_bare_message_type_constants_match_enum() {
        assert_eq!(DHCP6SOLICIT, Dhcp6MessageType::Solicit as u8);
        assert_eq!(DHCP6ADVERTISE, Dhcp6MessageType::Advertise as u8);
        assert_eq!(DHCP6REQUEST, Dhcp6MessageType::Request as u8);
        assert_eq!(DHCP6CONFIRM, Dhcp6MessageType::Confirm as u8);
        assert_eq!(DHCP6RENEW, Dhcp6MessageType::Renew as u8);
        assert_eq!(DHCP6REBIND, Dhcp6MessageType::Rebind as u8);
        assert_eq!(DHCP6REPLY, Dhcp6MessageType::Reply as u8);
        assert_eq!(DHCP6RELEASE, Dhcp6MessageType::Release as u8);
        assert_eq!(DHCP6DECLINE, Dhcp6MessageType::Decline as u8);
        assert_eq!(DHCP6RECONFIGURE, Dhcp6MessageType::Reconfigure as u8);
        assert_eq!(DHCP6IREQ, Dhcp6MessageType::InformationRequest as u8);
        assert_eq!(DHCP6RELAYFORW, Dhcp6MessageType::RelayForward as u8);
        assert_eq!(DHCP6RELAYREPL, Dhcp6MessageType::RelayReply as u8);
    }

    #[test]
    fn test_option_code_constants() {
        assert_eq!(OPTION6_CLIENT_ID, 1);
        assert_eq!(OPTION6_SERVER_ID, 2);
        assert_eq!(OPTION6_IA_NA, 3);
        assert_eq!(OPTION6_IA_TA, 4);
        assert_eq!(OPTION6_IAADDR, 5);
        assert_eq!(OPTION6_ORO, 6);
        assert_eq!(OPTION6_PREFERENCE, 7);
        assert_eq!(OPTION6_ELAPSED_TIME, 8);
        assert_eq!(OPTION6_RELAY_MSG, 9);
        // Note: option 10 is not assigned
        assert_eq!(OPTION6_AUTH, 11);
        assert_eq!(OPTION6_UNICAST, 12);
        assert_eq!(OPTION6_STATUS_CODE, 13);
        assert_eq!(OPTION6_RAPID_COMMIT, 14);
        assert_eq!(OPTION6_USER_CLASS, 15);
        assert_eq!(OPTION6_VENDOR_CLASS, 16);
        assert_eq!(OPTION6_VENDOR_OPTS, 17);
        assert_eq!(OPTION6_INTERFACE_ID, 18);
        assert_eq!(OPTION6_RECONFIGURE_MSG, 19);
        assert_eq!(OPTION6_RECONF_ACCEPT, 20);
        assert_eq!(OPTION6_DNS_SERVER, 23);
        assert_eq!(OPTION6_DOMAIN_SEARCH, 24);
        assert_eq!(OPTION6_IA_PD, 25);
        assert_eq!(OPTION6_IAPREFIX, 26);
        assert_eq!(OPTION6_REFRESH_TIME, 32);
        assert_eq!(OPTION6_REMOTE_ID, 37);
        assert_eq!(OPTION6_SUBSCRIBER_ID, 38);
        assert_eq!(OPTION6_FQDN, 39);
        assert_eq!(OPTION6_NTP_SERVER, 56);
        assert_eq!(OPTION6_CLIENT_MAC, 79);
        assert_eq!(OPTION6_MUD_URL, 112);
    }

    #[test]
    fn test_ntp_suboption_constants() {
        assert_eq!(NTP_SUBOPTION_SRV_ADDR, 1);
        assert_eq!(NTP_SUBOPTION_MC_ADDR, 2);
        assert_eq!(NTP_SUBOPTION_SRV_FQDN, 3);
    }

    #[test]
    fn test_status_code_enum_values() {
        assert_eq!(Dhcp6StatusCode::Success as u16, 0);
        assert_eq!(Dhcp6StatusCode::UnspecFail as u16, 1);
        assert_eq!(Dhcp6StatusCode::NoAddrsAvail as u16, 2);
        assert_eq!(Dhcp6StatusCode::NoBinding as u16, 3);
        assert_eq!(Dhcp6StatusCode::NotOnLink as u16, 4);
        assert_eq!(Dhcp6StatusCode::UseMulticast as u16, 5);
    }

    #[test]
    fn test_status_code_try_from_valid() {
        assert_eq!(Dhcp6StatusCode::try_from(0), Ok(Dhcp6StatusCode::Success));
        assert_eq!(
            Dhcp6StatusCode::try_from(5),
            Ok(Dhcp6StatusCode::UseMulticast)
        );
    }

    #[test]
    fn test_status_code_try_from_invalid() {
        assert_eq!(Dhcp6StatusCode::try_from(6), Err(6));
        assert_eq!(Dhcp6StatusCode::try_from(65535), Err(65535));
    }

    #[test]
    fn test_bare_status_code_constants_match_enum() {
        assert_eq!(DHCP6SUCCESS, Dhcp6StatusCode::Success as u16);
        assert_eq!(DHCP6UNSPEC, Dhcp6StatusCode::UnspecFail as u16);
        assert_eq!(DHCP6NOADDRS, Dhcp6StatusCode::NoAddrsAvail as u16);
        assert_eq!(DHCP6NOBINDING, Dhcp6StatusCode::NoBinding as u16);
        assert_eq!(DHCP6NOTONLINK, Dhcp6StatusCode::NotOnLink as u16);
        assert_eq!(DHCP6USEMULTI, Dhcp6StatusCode::UseMulticast as u16);
    }

    #[test]
    fn test_duid_type_constants() {
        assert_eq!(DUID_LLT, 1);
        assert_eq!(DUID_EN, 2);
        assert_eq!(DUID_LL, 3);
        assert_eq!(DUID_UUID, 4);
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", Dhcp6MessageType::Solicit), "SOLICIT");
        assert_eq!(
            format!("{}", Dhcp6MessageType::InformationRequest),
            "INFORMATION-REQUEST"
        );
        assert_eq!(format!("{}", Dhcp6MessageType::RelayForward), "RELAY-FORW");
    }

    #[test]
    fn test_status_code_display() {
        assert_eq!(format!("{}", Dhcp6StatusCode::Success), "Success");
        assert_eq!(format!("{}", Dhcp6StatusCode::UseMulticast), "UseMulticast");
    }

    #[test]
    fn test_message_type_roundtrip() {
        for val in 1u8..=13 {
            let msg = Dhcp6MessageType::try_from(val).unwrap();
            assert_eq!(msg as u8, val);
        }
    }

    #[test]
    fn test_status_code_roundtrip() {
        for val in 0u16..=5 {
            let code = Dhcp6StatusCode::try_from(val).unwrap();
            assert_eq!(code as u16, val);
        }
    }
}

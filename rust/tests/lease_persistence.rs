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

//! # Lease File Format Round-Trip Tests
//!
//! Integration tests validating that DHCP lease persistence is backward-compatible
//! with the C dnsmasq implementation. These tests verify that the Rust DHCP lease
//! management module can correctly write lease files, restart the daemon, and read
//! them back — ensuring seamless upgrades from C to Rust dnsmasq without losing
//! DHCP lease state.
//!
//! ## Test Categories
//!
//! 1. **DHCPv4 round-trip** — Write/read of v4 leases in C-compatible format
//! 2. **DHCPv6 round-trip** — Write/read of v6 leases with DUID, IAID, prefix delegation
//! 3. **Auxiliary records** — Vendor class, agent ID (in-memory only; not persisted to file)
//! 4. **Edge cases** — Empty files, malformed lines, trailing newlines, permissions
//! 5. **Daemon restart simulation** — Full lifecycle with state teardown and recovery
//!
//! ## Lease File Format (C-compatible)
//!
//! ```text
//! duid <hex:colon:separated>              # DHCPv6 Server DUID (first line)
//! <expiry> <mac> <ip> <hostname> <clid>   # DHCPv4 lease
//! <expiry> [T]<iaid> <type> <ip6>[/pfx] <hostname> [<clid>]  # DHCPv6 lease
//! ```

#![cfg(feature = "dhcp")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use tempfile::{NamedTempFile, TempDir};

use dnsmasq::core::types::{DaemonState, DnsmasqError, DnsmasqResult};
use dnsmasq::dhcp::lease::{
    lease4_allocate, lease_db_add, lease_find_by_addr, lease_find_by_client, lease_init,
    lease_prune, lease_set_agent_id, lease_set_expires, lease_set_hostname, lease_set_hwaddr,
    lease_set_vendorclass, lease_update_file, DhcpLease, LeaseFlags, LeaseType,
};

#[cfg(feature = "dhcp6")]
use dnsmasq::dhcp::lease::{lease6_allocate, lease6_find_by_plain_addr};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create a `DaemonState` configured for lease persistence tests.
///
/// Sets the lease file path and ensures DHCP is enabled with a sensible
/// maximum lease count. All other fields use the default values from
/// `DaemonState::new()`.
fn create_test_state(lease_path: &str) -> DaemonState {
    let mut state = DaemonState::new();
    state.lease_file = Some(lease_path.to_string());
    state
}

/// Create a standard DHCPv4 test lease with known field values.
///
/// Returns a lease for `192.168.1.100` with MAC `aa:bb:cc:dd:ee:ff`,
/// hostname `testhost`, client-id `01:aa:bb:cc:dd:ee:ff`, and expiry
/// at Unix timestamp `1700000000`.
fn make_v4_test_lease() -> DhcpLease {
    let mut lease = lease4_allocate("192.168.1.100".parse::<Ipv4Addr>().unwrap());
    // Set hardware address: Ethernet type (1), 6-byte MAC
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let clid = vec![0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    lease_set_hwaddr(&mut lease, &mac, Some(&clid), 6, 1, 0, true);
    // Set expiry directly (field is pub) for exact control in tests.
    lease.expires = 1_700_000_000;
    // Set hostname directly for simplicity.
    lease.hostname = Some("testhost".to_string());
    lease
}

/// Create a DHCPv4 lease with specific parameters.
fn make_v4_lease(
    ip: Ipv4Addr,
    mac: &[u8; 6],
    hostname: Option<&str>,
    clid: Option<&[u8]>,
    expires: i64,
) -> DhcpLease {
    let mut lease = lease4_allocate(ip);
    lease_set_hwaddr(&mut lease, mac, clid, 6, 1, 0, true);
    lease.expires = expires;
    lease.hostname = hostname.map(|s| s.to_string());
    lease
}

/// Create a DHCPv6 NA lease with known field values.
#[cfg(feature = "dhcp6")]
fn make_v6_test_lease() -> DhcpLease {
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut lease = lease6_allocate(addr, LeaseType::Na);
    lease.iaid = 12345;
    lease.expires = 1_700_000_000;
    lease.hostname = Some("v6host".to_string());
    let duid = vec![0x00, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
    lease.clid = Some(duid);
    lease
}

// ===========================================================================
// Phase 2: DHCPv4 Lease Persistence Tests
// ===========================================================================

#[test]
fn test_dhcpv4_lease_write_read_roundtrip() {
    // Create a temporary directory for lease file operations.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    // Phase A: Write a lease to disk.
    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Verify the lease file was created.
    assert!(lease_path.exists(), "lease file should exist after write");

    // Phase B: Read the lease back from disk (simulating a restart).
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");

    // Phase C: Verify all fields match.
    assert_eq!(db2.leases.len(), 1, "should have exactly 1 lease");
    let recovered = &db2.leases[0];
    assert_eq!(
        recovered.addr,
        Some("192.168.1.100".parse::<Ipv4Addr>().unwrap())
    );
    assert_eq!(recovered.expires, 1_700_000_000);
    assert_eq!(recovered.hostname.as_deref(), Some("testhost"));
    assert_eq!(recovered.lease_type, LeaseType::V4);
    assert_eq!(recovered.hwaddr_type, 1); // Ethernet
    assert_eq!(recovered.hwaddr_len, 6);
    assert_eq!(
        &recovered.hwaddr[..6],
        &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert_eq!(
        recovered.clid.as_deref(),
        Some(&[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff][..])
    );
}

#[test]
fn test_dhcpv4_lease_no_hostname() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Create a lease with no hostname (uses '*' placeholder in file).
    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_lease(
        "10.0.0.50".parse().unwrap(),
        &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        None, // no hostname
        Some(&[0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        1_700_000_000,
    );
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Verify the raw file contains '*' for hostname.
    let content = fs::read_to_string(&lease_path).expect("failed to read lease file");
    assert!(
        content.contains(" * "),
        "lease file should contain '*' for missing hostname, got: {}",
        content
    );

    // Read back and verify hostname is None.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);
    assert!(
        db2.leases[0].hostname.is_none(),
        "hostname should be None after round-trip with '*'"
    );
}

#[test]
fn test_dhcpv4_lease_no_client_id() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Create a lease without explicit client-id (uses '*' placeholder).
    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_lease(
        "10.0.0.51".parse().unwrap(),
        &[0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33],
        Some("noclid"),
        None, // no client-id
        1_700_000_000,
    );
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Verify raw file format has '*' for client-id (last field).
    let content = fs::read_to_string(&lease_path).expect("failed to read lease file");
    let line = content
        .lines()
        .next()
        .expect("should have at least one line");
    assert!(
        line.ends_with(" *"),
        "lease line should end with '* ' for missing client-id, got: {}",
        line
    );

    // Read back and verify client_id is None.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);
    assert!(
        db2.leases[0].clid.is_none(),
        "client-id should be None after round-trip with '*'"
    );
    assert_eq!(db2.leases[0].hostname.as_deref(), Some("noclid"));
}

#[test]
fn test_dhcpv4_lease_infinite_expiry() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Create a lease with infinite expiry (expires=0).
    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let mut lease = make_v4_lease(
        "10.0.0.52".parse().unwrap(),
        &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        Some("infinite"),
        Some(&[0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        0, // initial
    );
    // Use lease_set_expires with 0xFFFFFFFF to set infinite lease (expires=0).
    lease_set_expires(&mut lease, 0xFFFFFFFF, now);
    assert_eq!(lease.expires, 0, "infinite lease should have expires=0");
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Verify file starts with "0 " for infinite expiry.
    let content = fs::read_to_string(&lease_path).expect("failed to read lease file");
    let first_line = content.lines().next().expect("should have a lease line");
    assert!(
        first_line.starts_with("0 "),
        "infinite lease should start with '0 ', got: {}",
        first_line
    );

    // Read back — infinite leases are never pruned (expires=0 means infinite).
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);
    assert_eq!(
        db2.leases[0].expires, 0,
        "infinite lease should preserve expires=0 across round-trip"
    );
}

#[test]
fn test_dhcpv4_multiple_leases_roundtrip() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Create 10 diverse leases with different field values.
    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let test_leases: Vec<(Ipv4Addr, [u8; 6], Option<&str>, i64)> = vec![
        (
            "192.168.1.1".parse().unwrap(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            Some("host-a"),
            1_700_000_001,
        ),
        (
            "192.168.1.2".parse().unwrap(),
            [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            Some("host-b"),
            1_700_000_002,
        ),
        (
            "192.168.1.3".parse().unwrap(),
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16],
            None,
            1_700_000_003,
        ),
        (
            "10.0.0.1".parse().unwrap(),
            [0x21, 0x22, 0x23, 0x24, 0x25, 0x26],
            Some("server"),
            1_700_000_004,
        ),
        (
            "10.0.0.2".parse().unwrap(),
            [0x31, 0x32, 0x33, 0x34, 0x35, 0x36],
            Some("printer"),
            0,
        ), // infinite
        (
            "172.16.0.1".parse().unwrap(),
            [0x41, 0x42, 0x43, 0x44, 0x45, 0x46],
            Some("laptop"),
            1_700_000_006,
        ),
        (
            "172.16.0.2".parse().unwrap(),
            [0x51, 0x52, 0x53, 0x54, 0x55, 0x56],
            Some("phone"),
            1_700_000_007,
        ),
        (
            "192.168.2.1".parse().unwrap(),
            [0x61, 0x62, 0x63, 0x64, 0x65, 0x66],
            Some("desktop"),
            1_700_000_008,
        ),
        (
            "192.168.2.2".parse().unwrap(),
            [0x71, 0x72, 0x73, 0x74, 0x75, 0x76],
            None,
            1_700_000_009,
        ),
        (
            "192.168.2.3".parse().unwrap(),
            [0x81, 0x82, 0x83, 0x84, 0x85, 0x86],
            Some("tablet"),
            1_700_000_010,
        ),
    ];

    for (ip, mac, hostname, expires) in &test_leases {
        let lease = make_v4_lease(*ip, mac, *hostname, None, *expires);
        lease_db_add(&mut db, lease);
    }

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back and verify all 10 leases are recovered.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 10, "should recover all 10 leases");

    // Verify each lease can be found by IP address.
    for (ip, mac, hostname, expires) in &test_leases {
        let found = lease_find_by_addr(&db2.leases, *ip);
        assert!(
            found.is_some(),
            "lease for {} should be found after round-trip",
            ip
        );
        let found = found.unwrap();
        assert_eq!(found.expires, *expires);
        assert_eq!(found.hostname.as_deref(), *hostname);
        assert_eq!(&found.hwaddr[..6], mac);
    }
}

#[test]
fn test_dhcpv4_lease_file_format_exact() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Create a lease with exact known values.
    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read the raw file content and verify exact C-compatible format.
    let content = fs::read_to_string(&lease_path).expect("failed to read lease file");
    let expected_line =
        "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 testhost 01:aa:bb:cc:dd:ee:ff\n";
    assert_eq!(
        content, expected_line,
        "lease file content should match exact C format.\nExpected: {:?}\nGot: {:?}",
        expected_line, content
    );
}

// ===========================================================================
// Phase 3: DHCPv6 Lease Persistence Tests
// ===========================================================================

#[cfg(feature = "dhcp6")]
#[test]
fn test_dhcpv6_lease_write_read_roundtrip() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v6_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    assert!(lease_path.exists(), "lease file should exist after write");

    // Read back.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");

    assert_eq!(db2.leases.len(), 1, "should have exactly 1 DHCPv6 lease");
    let recovered = &db2.leases[0];
    assert_eq!(
        recovered.addr6,
        Some("2001:db8::1".parse::<Ipv6Addr>().unwrap())
    );
    assert_eq!(recovered.expires, 1_700_000_000);
    assert_eq!(recovered.hostname.as_deref(), Some("v6host"));
    assert_eq!(recovered.lease_type, LeaseType::Na);
    assert_eq!(recovered.iaid, 12345);
    assert_eq!(
        recovered.clid.as_deref(),
        Some(&[0x00, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef][..])
    );
}

#[cfg(feature = "dhcp6")]
#[test]
fn test_dhcpv6_lease_with_duid_line() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Set a server DUID on the state so it gets written to the file.
    state.duid = vec![0x00, 0x01, 0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f];

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v6_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Verify the raw file starts with the DUID line.
    let content = fs::read_to_string(&lease_path).expect("failed to read lease file");
    let first_line = content
        .lines()
        .next()
        .expect("should have at least one line");
    assert!(
        first_line.starts_with("duid "),
        "first line should be the DUID line, got: {}",
        first_line
    );
    assert_eq!(
        first_line, "duid 00:01:00:01:1a:2b:3c:4d:5e:6f",
        "DUID hex should match exactly"
    );

    // Read back and verify the DUID is parsed into state.
    let mut state2 = create_test_state(lease_path_str);
    let _db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(
        state2.duid,
        vec![0x00, 0x01, 0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f],
        "server DUID should be recovered from lease file"
    );
}

#[cfg(feature = "dhcp6")]
#[test]
fn test_dhcpv6_prefix_delegation_lease() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Create an IA_PD (prefix delegation) lease.
    let pd_addr: Ipv6Addr = "2001:db8:abcd::".parse().unwrap();
    let mut lease = lease6_allocate(pd_addr, LeaseType::Pd);
    lease.iaid = 99999;
    lease.expires = 1_700_000_000;
    lease.hostname = Some("pd-router".to_string());
    lease.prefix_len = 48;
    lease.clid = Some(vec![0x00, 0x03, 0xAA, 0xBB]);

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Verify raw file format includes prefix length.
    let content = fs::read_to_string(&lease_path).expect("failed to read lease file");
    assert!(
        content.contains("/48"),
        "PD lease should include /48 prefix length in file, got: {}",
        content
    );
    assert!(
        content.contains("pd"),
        "PD lease should include 'pd' type marker, got: {}",
        content
    );

    // Read back and verify.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);
    let recovered = &db2.leases[0];
    assert_eq!(recovered.lease_type, LeaseType::Pd);
    assert_eq!(recovered.prefix_len, 48);
    assert_eq!(
        recovered.addr6,
        Some("2001:db8:abcd::".parse::<Ipv6Addr>().unwrap())
    );
    assert_eq!(recovered.iaid, 99999);
}

#[cfg(feature = "dhcp6")]
#[test]
fn test_mixed_v4_v6_lease_file() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    // Set a server DUID for DHCPv6.
    state.duid = vec![0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);

    // Add a DHCPv4 lease.
    let v4_lease = make_v4_test_lease();
    lease_db_add(&mut db, v4_lease);

    // Add a DHCPv6 NA lease.
    let v6_lease = make_v6_test_lease();
    lease_db_add(&mut db, v6_lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back and verify both types are present.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");

    // Should have both v4 and v6 leases.
    let v4_count = db2
        .leases
        .iter()
        .filter(|l| l.lease_type == LeaseType::V4)
        .count();
    let v6_count = db2
        .leases
        .iter()
        .filter(|l| l.lease_type != LeaseType::V4)
        .count();

    assert_eq!(v4_count, 1, "should have 1 DHCPv4 lease");
    assert_eq!(v6_count, 1, "should have 1 DHCPv6 lease");

    // Verify the v4 lease.
    let v4 = lease_find_by_addr(&db2.leases, "192.168.1.100".parse().unwrap());
    assert!(v4.is_some(), "should find the DHCPv4 lease");
    assert_eq!(v4.unwrap().hostname.as_deref(), Some("testhost"));

    // Verify the v6 lease.
    let v6 = lease6_find_by_plain_addr(&db2.leases, &"2001:db8::1".parse::<Ipv6Addr>().unwrap());
    assert!(v6.is_some(), "should find the DHCPv6 lease");
    assert_eq!(v6.unwrap().hostname.as_deref(), Some("v6host"));
}

// ===========================================================================
// Phase 4: Auxiliary Record Persistence Tests
// ===========================================================================

#[test]
fn test_vendor_class_persistence() {
    // Vendor class data is stored in-memory via `lease_set_vendorclass()`.
    // The Rust implementation does NOT persist vendor class to the lease file
    // (matching C's write behavior where vendorclass lines are read but not
    // re-written by `lease_update_file()`). This test verifies:
    // 1. Setting vendor class works in memory
    // 2. The field is NOT preserved across a write/read cycle
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let mut lease = make_v4_test_lease();

    // Set vendor class data.
    let vendor_data = b"MSFT 5.0";
    lease_set_vendorclass(&mut lease, vendor_data);
    assert_eq!(
        lease.vendor_class.as_deref(),
        Some(vendor_data.as_slice()),
        "vendor class should be set in memory"
    );

    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back — vendor class is NOT persisted in the lease file format.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);

    // The lease should be recovered (IP, MAC, etc.) but vendor_class will be
    // None since it's not written to the lease file.
    assert!(
        db2.leases[0].vendor_class.is_none(),
        "vendor class is not persisted to lease file; should be None after round-trip"
    );
    // The core lease data should still be intact.
    assert_eq!(
        db2.leases[0].addr,
        Some("192.168.1.100".parse::<Ipv4Addr>().unwrap()),
        "IP address should survive round-trip"
    );
}

#[test]
fn test_agent_info_persistence() {
    // Agent ID (DHCPv4 option 82 — relay agent information) is stored in-memory
    // via `lease_set_agent_id()`. Like vendor class, it is NOT persisted to the
    // lease file. This test verifies:
    // 1. Setting agent ID works in memory (via the setter function)
    // 2. Core lease data is preserved across the write/read cycle
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let mut lease = make_v4_test_lease();

    // Set agent ID (relay agent information).
    let agent_data = vec![0x01, 0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x06];
    lease_set_agent_id(&mut lease, &agent_data);

    // Agent ID is private, so we can't read it directly. Just verify no panic
    // and that the lease still functions normally.
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back — agent ID is NOT persisted to the lease file.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);

    // Core lease fields should be intact.
    assert_eq!(
        db2.leases[0].addr,
        Some("192.168.1.100".parse::<Ipv4Addr>().unwrap()),
        "IP address should survive round-trip"
    );
    assert_eq!(
        db2.leases[0].hostname.as_deref(),
        Some("testhost"),
        "hostname should survive round-trip"
    );
}

// ===========================================================================
// Phase 5: Edge Cases and Error Handling
// ===========================================================================

#[test]
fn test_empty_lease_file() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    // Create an empty lease file.
    fs::write(&lease_path, "").expect("failed to create empty lease file");

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;
    let db = lease_init(now, &mut state).expect("should parse empty lease file without error");

    assert!(
        db.leases.is_empty(),
        "empty lease file should produce empty lease list"
    );
}

#[test]
fn test_malformed_lease_line_skipped() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    // Write a lease file with one valid and one malformed line.
    // Malformed: missing fields (only 3 tokens), should be skipped.
    // Valid: proper DHCPv4 format.
    let content = "GARBAGE_LINE short\n\
                   1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 testhost 01:aa:bb:cc:dd:ee:ff\n\
                   not_a_timestamp xx:yy 10.0.0.1 bad\n";
    fs::write(&lease_path, content).expect("failed to write test lease file");

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;
    let db = lease_init(now, &mut state)
        .expect("should parse lease file with malformed lines without fatal error");

    // Only the valid lease should be loaded; malformed lines are skipped.
    assert_eq!(
        db.leases.len(),
        1,
        "only valid leases should be loaded, got {}",
        db.leases.len()
    );
    assert_eq!(
        db.leases[0].addr,
        Some("192.168.1.100".parse::<Ipv4Addr>().unwrap())
    );
}

#[test]
fn test_lease_file_with_trailing_newline() {
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    // Write a lease file with trailing newlines to ensure no phantom entries.
    let content = "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 testhost 01:aa:bb:cc:dd:ee:ff\n\n\n";
    fs::write(&lease_path, content).expect("failed to write test lease file");

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;
    let db = lease_init(now, &mut state).expect("should handle trailing newlines");

    assert_eq!(
        db.leases.len(),
        1,
        "trailing newlines should not create phantom lease entries"
    );
}

#[test]
fn test_lease_file_permissions() {
    // Verify that `lease_update_file()` creates the lease file with
    // appropriate Unix permissions. The file should be world-readable (0644)
    // or at least user-writable.
    use std::os::unix::fs::PermissionsExt;

    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    let metadata = fs::metadata(&lease_path).expect("failed to get file metadata");
    let mode = metadata.permissions().mode();
    // The file should be readable by the owner at minimum. On most systems,
    // File::create produces 0o644 (modified by umask). Verify the owner
    // read/write bits are set.
    assert!(
        mode & 0o600 == 0o600,
        "lease file should be owner-readable and owner-writable, got mode: {:o}",
        mode
    );
}

// ===========================================================================
// Phase 6: Daemon Restart Simulation
// ===========================================================================

#[test]
fn test_simulated_daemon_restart() {
    // Full lifecycle test: create leases → write to file → drop all in-memory
    // state → re-initialize from file → verify all leases recovered identically.
    // This simulates a dnsmasq daemon restart/upgrade scenario.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap().to_string();

    let now: i64 = 1_699_000_000;

    // === Phase A: Original daemon session ===
    {
        let mut state = create_test_state(&lease_path_str);
        let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);

        // Create diverse leases.
        let lease1 = make_v4_lease(
            "192.168.1.10".parse().unwrap(),
            &[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03],
            Some("webserver"),
            Some(&[0x01, 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]),
            1_700_100_000,
        );
        let lease2 = make_v4_lease(
            "192.168.1.20".parse().unwrap(),
            &[0xdd, 0xee, 0xff, 0x04, 0x05, 0x06],
            Some("database"),
            Some(&[0x01, 0xdd, 0xee, 0xff, 0x04, 0x05, 0x06]),
            1_700_200_000,
        );
        let lease3 = make_v4_lease(
            "192.168.1.30".parse().unwrap(),
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            None, // no hostname
            None, // no client-id
            0,    // infinite
        );

        lease_db_add(&mut db, lease1);
        lease_db_add(&mut db, lease2);
        lease_db_add(&mut db, lease3);

        lease_update_file(now, &mut db, &mut state, None)
            .expect("failed to write lease file in original session");
    }
    // At this point, all in-memory state (db, state) has been dropped.
    // Only the lease file on disk remains.

    // === Phase B: New daemon session (restart) ===
    {
        let mut state = create_test_state(&lease_path_str);
        let db =
            lease_init(now, &mut state).expect("failed to re-initialize lease database from file");

        // Verify all three leases are recovered.
        assert_eq!(
            db.leases.len(),
            3,
            "all 3 leases should be recovered after restart"
        );

        // Verify lease 1.
        let l1 = lease_find_by_addr(&db.leases, "192.168.1.10".parse().unwrap());
        assert!(l1.is_some(), "webserver lease should be recovered");
        let l1 = l1.unwrap();
        assert_eq!(l1.hostname.as_deref(), Some("webserver"));
        assert_eq!(l1.expires, 1_700_100_000);
        assert_eq!(&l1.hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]);
        assert_eq!(
            l1.clid.as_deref(),
            Some(&[0x01, 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03][..])
        );

        // Verify lease 2.
        let l2 = lease_find_by_addr(&db.leases, "192.168.1.20".parse().unwrap());
        assert!(l2.is_some(), "database lease should be recovered");
        let l2 = l2.unwrap();
        assert_eq!(l2.hostname.as_deref(), Some("database"));
        assert_eq!(l2.expires, 1_700_200_000);

        // Verify lease 3 (no hostname, no clid, infinite).
        let l3 = lease_find_by_addr(&db.leases, "192.168.1.30".parse().unwrap());
        assert!(l3.is_some(), "infinite lease should be recovered");
        let l3 = l3.unwrap();
        assert!(l3.hostname.is_none(), "no hostname should remain None");
        assert!(l3.clid.is_none(), "no client-id should remain None");
        assert_eq!(l3.expires, 0, "infinite lease should have expires=0");
    }
}

#[test]
fn test_c_format_lease_file_compatibility() {
    // Manually create a lease file in the EXACT C dnsmasq format (as produced
    // by the C implementation) and verify the Rust parser reads it correctly.
    // This validates backward compatibility with existing C-generated lease files
    // for seamless C → Rust dnsmasq upgrades.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    // C dnsmasq lease file format:
    // DHCPv4: {expiry} {mac} {ip} {hostname} {clid}
    // DHCPv6: duid {hex}, then {expiry} {iaid} {type} {addr} {hostname} {clid}
    let c_format_content = "\
1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 testhost 01:aa:bb:cc:dd:ee:ff
1700000001 11:22:33:44:55:66 10.0.0.1 * *
0 de:ad:be:ef:00:01 172.16.0.1 always-on 01:de:ad:be:ef:00:01
";

    fs::write(&lease_path, c_format_content).expect("failed to write C-format lease file");

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;
    let db = lease_init(now, &mut state).expect("Rust parser should handle C-format lease files");

    assert_eq!(db.leases.len(), 3, "should parse all 3 C-format leases");

    // Verify lease 1: full fields.
    let l1 = lease_find_by_addr(&db.leases, "192.168.1.100".parse().unwrap());
    assert!(l1.is_some(), "should find 192.168.1.100");
    let l1 = l1.unwrap();
    assert_eq!(l1.expires, 1_700_000_000);
    assert_eq!(&l1.hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(l1.hostname.as_deref(), Some("testhost"));
    assert_eq!(
        l1.clid.as_deref(),
        Some(&[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff][..])
    );
    assert_eq!(l1.lease_type, LeaseType::V4);
    assert_eq!(l1.hwaddr_type, 1); // ARPHRD_ETHER

    // Verify lease 2: no hostname, no client-id.
    let l2 = lease_find_by_addr(&db.leases, "10.0.0.1".parse().unwrap());
    assert!(l2.is_some(), "should find 10.0.0.1");
    let l2 = l2.unwrap();
    assert_eq!(l2.expires, 1_700_000_001);
    assert!(l2.hostname.is_none(), "'*' hostname should parse as None");
    assert!(l2.clid.is_none(), "'*' client-id should parse as None");

    // Verify lease 3: infinite expiry.
    let l3 = lease_find_by_addr(&db.leases, "172.16.0.1".parse().unwrap());
    assert!(l3.is_some(), "should find 172.16.0.1");
    let l3 = l3.unwrap();
    assert_eq!(l3.expires, 0, "infinite lease should have expires=0");
    assert_eq!(l3.hostname.as_deref(), Some("always-on"));
}

// ===========================================================================
// Additional lease_find_by_client test (uses members_accessed)
// ===========================================================================

#[test]
fn test_lease_find_by_client_roundtrip() {
    // Verify that `lease_find_by_client()` can locate leases after a round-trip.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let clid = vec![0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");

    // Find by client-id.
    let found_by_clid = lease_find_by_client(&db2.leases, &mac, 1, Some(&clid));
    assert!(
        found_by_clid.is_some(),
        "should find lease by client-id after round-trip"
    );
    assert_eq!(
        found_by_clid.unwrap().addr,
        Some("192.168.1.100".parse::<Ipv4Addr>().unwrap())
    );

    // Find by hardware address (without clid).
    let found_by_hw = lease_find_by_client(&db2.leases, &mac, 1, None);
    assert!(
        found_by_hw.is_some(),
        "should find lease by hardware address after round-trip"
    );
}

// ===========================================================================
// Additional lease_prune test (uses members_accessed)
// ===========================================================================

#[test]
fn test_lease_prune_expired_leases() {
    // Verify that `lease_prune()` correctly removes expired leases and
    // that the pruning integrates with persistence.
    // Set "now" to after the expiry of the first lease but before the second.
    let now: i64 = 1_700_050_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);

    // Lease 1: expires at 1_700_000_000 (already expired at now=1_700_050_000).
    let lease1 = make_v4_lease(
        "10.0.0.1".parse().unwrap(),
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        Some("expired-host"),
        None,
        1_700_000_000,
    );
    // Lease 2: expires at 1_700_100_000 (still active at now=1_700_050_000).
    let lease2 = make_v4_lease(
        "10.0.0.2".parse().unwrap(),
        &[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        Some("active-host"),
        None,
        1_700_100_000,
    );
    // Lease 3: infinite (never expires).
    let lease3 = make_v4_lease(
        "10.0.0.3".parse().unwrap(),
        &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16],
        Some("infinite-host"),
        None,
        0,
    );

    lease_db_add(&mut db, lease1);
    lease_db_add(&mut db, lease2);
    lease_db_add(&mut db, lease3);

    // Prune expired leases.
    let pruned = lease_prune(&mut db, None, now);
    assert_eq!(pruned, 1, "should prune exactly 1 expired lease");
    assert_eq!(db.leases.len(), 2, "2 leases should remain after pruning");

    // Verify the expired lease is gone and active + infinite remain.
    assert!(
        lease_find_by_addr(&db.leases, "10.0.0.1".parse().unwrap()).is_none(),
        "expired lease should be removed"
    );
    assert!(
        lease_find_by_addr(&db.leases, "10.0.0.2".parse().unwrap()).is_some(),
        "active lease should remain"
    );
    assert!(
        lease_find_by_addr(&db.leases, "10.0.0.3".parse().unwrap()).is_some(),
        "infinite lease should remain"
    );
}

// ===========================================================================
// Additional lease_set_expires test
// ===========================================================================

#[test]
fn test_lease_set_expires_roundtrip() {
    // Verify that `lease_set_expires()` correctly sets the expiry and that
    // the value survives a write/read cycle.
    //
    // We use small values for `now` and `len` so that the test works
    // regardless of the `broken-rtc` feature:
    //   - broken-rtc: expires = len (raw duration stored directly)
    //   - normal:     expires = now + len (absolute timestamp)
    // Either way, the stored expires must be > now at read time to avoid
    // being pruned by the initialization logic.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    // Use a small `now` value so both broken-rtc (stores 3600) and normal
    // (stores 500 + 3600 = 4100) produce an expires > now (500).
    let now: i64 = 500;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let mut lease = lease4_allocate("10.10.10.10".parse::<Ipv4Addr>().unwrap());
    let mac = [0xab, 0xcd, 0xef, 0x01, 0x02, 0x03];
    lease_set_hwaddr(&mut lease, &mac, None, 6, 1, 0, true);
    lease.hostname = Some("expire-test".to_string());

    // Set a 3600-second lease duration from `now`.
    lease_set_expires(&mut lease, 3600, now);

    // On systems with HAVE_BROKEN_RTC (Cargo feature "broken-rtc"), the
    // implementation stores the raw duration instead of computing
    // now + len.  Handle both configurations.
    #[cfg(not(feature = "broken-rtc"))]
    let expected_expires: i64 = now + 3600;
    #[cfg(feature = "broken-rtc")]
    let expected_expires: i64 = 3600;

    assert_eq!(
        lease.expires, expected_expires,
        "lease_set_expires should set expiry correctly"
    );

    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back and verify.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);
    assert_eq!(
        db2.leases[0].expires, expected_expires,
        "expiry should survive round-trip"
    );
}

// ===========================================================================
// Lease hostname persistence test (uses lease_set_hostname)
// ===========================================================================

#[test]
fn test_lease_set_hostname_roundtrip() {
    // Verify that `lease_set_hostname()` sets the hostname correctly and the
    // value survives a write/read cycle. This exercises the `lease_set_hostname`
    // API which takes a `&mut LeaseDatabase` and a lease index.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);

    // Create a lease without a hostname.
    let mut lease = lease4_allocate("10.20.30.40".parse::<Ipv4Addr>().unwrap());
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    lease_set_hwaddr(&mut lease, &mac, None, 6, 1, 0, true);
    lease.expires = 1_700_000_000;
    lease_db_add(&mut db, lease);

    // Use lease_set_hostname to set the hostname via the database API.
    lease_set_hostname(&mut db, 0, Some("hostname-test"), false, None, None);
    assert_eq!(
        db.leases[0].hostname.as_deref(),
        Some("hostname-test"),
        "hostname should be set by lease_set_hostname"
    );

    lease_update_file(now, &mut db, &mut state, None).expect("failed to write lease file");

    // Read back and verify.
    let mut state2 = create_test_state(lease_path_str);
    let db2 = lease_init(now, &mut state2).expect("failed to read lease file");
    assert_eq!(db2.leases.len(), 1);
    assert_eq!(
        db2.leases[0].hostname.as_deref(),
        Some("hostname-test"),
        "hostname should survive round-trip"
    );
}

// ===========================================================================
// LeaseFlags verification test
// ===========================================================================

#[test]
fn test_lease_flags_after_allocation() {
    // Verify that `LeaseFlags` fields are correctly set after lease allocation
    // and after various operations. This exercises the `LeaseFlags` type.
    let lease = lease4_allocate("10.0.0.1".parse::<Ipv4Addr>().unwrap());
    let flags: &LeaseFlags = &lease.flags;

    // Newly allocated leases should have is_new=true.
    assert!(
        flags.is_new,
        "newly allocated lease should have is_new=true"
    );
    assert!(
        !flags.has_changed,
        "new lease should not have has_changed initially"
    );
}

// ===========================================================================
// DnsmasqError/DnsmasqResult verification test
// ===========================================================================

#[test]
fn test_lease_init_nonexistent_path_creates_fresh_db() {
    // Verify that `lease_init()` with a non-existent lease file returns an
    // empty database (Ok result). Also exercises `DnsmasqResult` return type.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("does_not_exist.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let result: DnsmasqResult<dnsmasq::dhcp::lease::LeaseDatabase> = lease_init(now, &mut state);
    assert!(
        result.is_ok(),
        "non-existent lease file should produce Ok result"
    );
    let db = result.unwrap();
    assert!(db.leases.is_empty(), "should start with empty database");
}

// ===========================================================================
// NamedTempFile usage test
// ===========================================================================

#[test]
fn test_lease_file_via_named_temp_file() {
    // Use `NamedTempFile` for lease file creation — tests that the tempfile
    // RAII cleanup integrates with lease persistence. Also exercises `Write`
    // trait and `std::io::BufRead`/`BufReader` for reading lease files.
    let mut tmp_file = NamedTempFile::new().expect("failed to create NamedTempFile");

    // Write a C-format lease directly to the temp file using std::io::Write.
    writeln!(
        tmp_file,
        "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.99 namedtemp 01:aa:bb:cc:dd:ee:ff"
    )
    .expect("failed to write lease line");
    tmp_file.flush().expect("failed to flush");

    let path = tmp_file.path().to_str().unwrap().to_string();

    // Verify the file content using BufReader/BufRead.
    let file = fs::File::open(tmp_file.path()).expect("failed to open temp file");
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();
    assert_eq!(lines.len(), 1, "should have exactly one lease line");
    assert!(
        lines[0].contains("192.168.1.99"),
        "lease line should contain the IP address"
    );

    // Parse the lease file with the Rust implementation.
    let mut state = create_test_state(&path);
    let now: i64 = 1_699_000_000;
    let db = lease_init(now, &mut state).expect("should parse temp file lease");
    assert_eq!(db.leases.len(), 1);
    assert_eq!(db.leases[0].hostname.as_deref(), Some("namedtemp"));

    // NamedTempFile is dropped here and the file is automatically cleaned up.
}

// ===========================================================================
// Path/PathBuf usage test
// ===========================================================================

#[test]
fn test_lease_path_manipulation() {
    // Exercises `std::path::Path` and `std::path::PathBuf` for lease file
    // path construction and verification.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let base: &Path = tmp_dir.path();
    let mut lease_path: PathBuf = base.to_path_buf();
    lease_path.push("subdir");
    fs::create_dir_all(&lease_path).expect("failed to create subdir");
    lease_path.push("leases.db");

    let lease_path_str = lease_path.to_str().unwrap();
    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;

    let mut db = dnsmasq::dhcp::lease::LeaseDatabase::new(100);
    let lease = make_v4_test_lease();
    lease_db_add(&mut db, lease);

    lease_update_file(now, &mut db, &mut state, None)
        .expect("failed to write lease file in subdirectory");

    assert!(
        lease_path.exists(),
        "lease file should exist in subdirectory"
    );
    assert!(lease_path.is_file(), "lease path should be a file");
}

// ===========================================================================
// DhcpLease field access test
// ===========================================================================

#[test]
fn test_dhcp_lease_struct_fields() {
    // Verify that `DhcpLease` struct fields are accessible and have the
    // correct types after allocation. This exercises the `DhcpLease` type
    // directly.
    let lease: DhcpLease = lease4_allocate("172.16.0.1".parse::<Ipv4Addr>().unwrap());

    // Verify public field access.
    assert_eq!(lease.addr, Some("172.16.0.1".parse::<Ipv4Addr>().unwrap()));
    assert_eq!(lease.lease_type, LeaseType::V4);
    assert!(lease.hostname.is_none());
    assert!(lease.clid.is_none());
    assert!(lease.vendor_class.is_none());
    assert_eq!(lease.prefix_len, 0);
    assert_eq!(lease.iaid, 0);
}

// ===========================================================================
// DnsmasqError variant test
// ===========================================================================

#[test]
fn test_dnsmasq_error_lease_variant() {
    // Verify that `DnsmasqError::Lease` can be constructed and matched.
    // This exercises the `DnsmasqError` type.
    let err = DnsmasqError::Lease("test error".to_string());
    let msg = format!("{}", err);
    assert!(
        msg.contains("test error"),
        "DnsmasqError::Lease should format with the message"
    );

    // Verify pattern matching works.
    match err {
        DnsmasqError::Lease(ref s) => assert_eq!(s, "test error"),
        _ => panic!("expected DnsmasqError::Lease variant"),
    }
}

// ===========================================================================
// DHCPv6 C-format compatibility test
// ===========================================================================

#[cfg(feature = "dhcp6")]
#[test]
fn test_c_format_dhcpv6_lease_file_compatibility() {
    // Manually create a lease file with DHCPv6 entries in C dnsmasq format
    // and verify the Rust parser reads them correctly.
    let tmp_dir = TempDir::new().expect("failed to create temp dir");
    let lease_path = tmp_dir.path().join("test.leases");
    let lease_path_str = lease_path.to_str().unwrap();

    // C dnsmasq DHCPv6 lease file format:
    // duid {hex:colon:separated}
    // {expiry} {iaid} {type} {addr} {hostname} {clid}
    // {expiry} T{iaid} {type} {addr} {hostname} {clid}  (T prefix for TA)
    // {expiry} {iaid} pd {addr}/{prefix} {hostname} {clid}
    let c_format_content = "\
duid 00:01:00:01:1a:2b:3c:4d:5e:6f
1700000000 12345 na 2001:db8::1 v6host 00:01:00:01:de:ad:be:ef
1700000001 T54321 ta 2001:db8::2 v6temp *
1700000002 99999 pd 2001:db8:abcd::/48 pd-router 00:03:aa:bb
";

    fs::write(&lease_path, c_format_content).expect("failed to write C-format DHCPv6 lease file");

    let mut state = create_test_state(lease_path_str);
    let now: i64 = 1_699_000_000;
    let db =
        lease_init(now, &mut state).expect("Rust parser should handle C-format DHCPv6 lease files");

    // Verify DUID was parsed.
    assert_eq!(
        state.duid,
        vec![0x00, 0x01, 0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f],
        "server DUID should be parsed from C-format file"
    );

    assert_eq!(
        db.leases.len(),
        3,
        "should parse all 3 C-format DHCPv6 leases"
    );

    // Verify NA lease.
    let na_lease =
        lease6_find_by_plain_addr(&db.leases, &"2001:db8::1".parse::<Ipv6Addr>().unwrap());
    assert!(na_lease.is_some(), "should find NA lease");
    let na_lease = na_lease.unwrap();
    assert_eq!(na_lease.lease_type, LeaseType::Na);
    assert_eq!(na_lease.iaid, 12345);
    assert_eq!(na_lease.hostname.as_deref(), Some("v6host"));
    assert_eq!(na_lease.expires, 1_700_000_000);
    assert_eq!(
        na_lease.clid.as_deref(),
        Some(&[0x00, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef][..])
    );

    // Verify TA lease (T-prefixed IAID).
    let ta_lease =
        lease6_find_by_plain_addr(&db.leases, &"2001:db8::2".parse::<Ipv6Addr>().unwrap());
    assert!(ta_lease.is_some(), "should find TA lease");
    let ta_lease = ta_lease.unwrap();
    assert_eq!(ta_lease.lease_type, LeaseType::Ta);
    assert_eq!(ta_lease.iaid, 54321);
    assert!(ta_lease.clid.is_none(), "'*' DUID should parse as None");

    // Verify PD lease.
    let pd_lease =
        lease6_find_by_plain_addr(&db.leases, &"2001:db8:abcd::".parse::<Ipv6Addr>().unwrap());
    assert!(pd_lease.is_some(), "should find PD lease");
    let pd_lease = pd_lease.unwrap();
    assert_eq!(pd_lease.lease_type, LeaseType::Pd);
    assert_eq!(pd_lease.iaid, 99999);
    assert_eq!(pd_lease.prefix_len, 48);
    assert_eq!(pd_lease.hostname.as_deref(), Some("pd-router"));
    assert_eq!(
        pd_lease.clid.as_deref(),
        Some(&[0x00, 0x03, 0xaa, 0xbb][..])
    );
}

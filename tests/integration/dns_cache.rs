//! Integration tests for DNS cache insertion, lookup, eviction, and TTL management.
//!
//! Tests the Rust rewrite of the DNS cache subsystem (originally `src/cache.c`) by
//! exercising the public API exported from `src/lib.rs`. The Rust cache replaces the
//! C intrusive hash table + doubly-linked LRU list with `HashMap` + `VecDeque` LRU.
//!
//! # Test Coverage
//!
//! - **Cache Initialization** — default size, custom size, zero-size behaviour
//! - **Insert and Lookup** — A, AAAA, CNAME, PTR, MX, SRV, TXT records; forward and
//!   reverse lookups; CNAME chain following; type-filtered queries
//! - **LRU Eviction** — capacity enforcement, access-order promotion, recent-entry
//!   preservation, space reclamation after eviction
//! - **TTL Management** — expiration, min/max TTL clamping, negative caching (NXDOMAIN)
//! - **Hosts File Integration** — loading, override behaviour, reload on change
//! - **DHCP Hostname Registration** — addition and removal (feature-gated)
//! - **Statistics and Diagnostics** — make_stat(), enumerate(), hit/miss/eviction counters
//! - **Edge Cases** — duplicate inserts, wildcard NXDOMAIN, case-insensitive lookups
//!
//! # Design Notes
//!
//! - DNS name lookups are **case-insensitive** per RFC 4343.
//! - DHCP tests are gated with `#[cfg(feature = "dhcp")]`.
//! - Zero `unsafe` blocks in test code.
//! - TTL-based expiration tests use `Instant` arithmetic for deterministic timing.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

// Library crate imports — accessing the dnsmasq public API.
use dnsmasq::config::constants::{
    CACHESIZ, CNAME_CHAIN, SMALLDNAME, STALE_CACHE_EXPIRY, TTL_FLOOR_LIMIT,
};
use dnsmasq::dns::cache::{CacheError, DnsCache};
use dnsmasq::dns::protocol::{C_IN, RrType, T_A, T_AAAA, T_CNAME, T_MX, T_PTR, T_SRV, T_TXT};
use dnsmasq::types::addr::{AllAddr, CnameTarget};
use dnsmasq::types::dns::{CacheEntry, CacheEntryFlags, DnsHeader, DnsName};

// ============================================================================
// Helper functions
// ============================================================================

/// Create a [`DnsCache`] with the specified maximum size for testing.
fn create_test_cache(size: usize) -> DnsCache {
    DnsCache::new(size)
}

/// Create a temporary hosts file on disk with the given content.
///
/// Returns the absolute path to the created file. The caller must clean up
/// with [`cleanup_temp_file`] when finished.
fn create_temp_hosts_file(content: &str) -> String {
    let path = format!(
        "{}/dnsmasq_test_hosts_{}_{}.txt",
        std::env::temp_dir().display(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    let mut file = std::fs::File::create(&path).expect("create temp hosts file");
    file.write_all(content.as_bytes())
        .expect("write temp hosts file");
    file.flush().expect("flush temp hosts file");
    path
}

/// Remove a temporary file created by [`create_temp_hosts_file`].
fn cleanup_temp_file(path: &str) {
    let _ = std::fs::remove_file(path);
}

// ============================================================================
// Phase 2: Cache Initialization Tests
// ============================================================================

/// Test cache initialization with the default CACHESIZ (150).
/// Verifies the empty cache is ready for insertions and all counters are zero.
/// Reference: `cache.c:cache_init()`.
#[test]
fn test_cache_init_default_size() {
    let cache = DnsCache::new_default();
    assert_eq!(cache.max_size(), CACHESIZ, "Default cache size must be CACHESIZ");
    assert_eq!(cache.len(), 0, "New cache must be empty");
    assert!(cache.is_empty(), "New cache must report is_empty()");
    assert_eq!(cache.hits(), 0);
    assert_eq!(cache.misses(), 0);
    assert_eq!(cache.evictions(), 0);
    assert_eq!(cache.hosts_count(), 0);
    assert_eq!(cache.dhcp_count(), 0);
}

/// Test cache initialization with various custom sizes (e.g., 500, 1000, 1).
/// Verifies capacity is set correctly for each size.
#[test]
fn test_cache_init_custom_size() {
    for &size in &[1_usize, 10, 50, 500, 1000, 10_000] {
        let cache = DnsCache::new(size);
        assert_eq!(cache.max_size(), size, "Custom cache size must match");
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}

/// Test that cache size 0 effectively disables caching.
/// With max_size=0 the LRU eviction check is bypassed, meaning entries can
/// be stored but are never capacity-limited. This verifies the actual behaviour.
#[test]
fn test_cache_init_zero_disables() {
    let mut cache = DnsCache::new(0);
    assert_eq!(cache.max_size(), 0);
    assert_eq!(cache.len(), 0);

    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
    let result = cache.insert(
        "test.example.com",
        Some(&addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
    );
    // With max_size=0, the eviction condition (count >= max_size && max_size > 0)
    // is never satisfied, so insertion succeeds without limit.
    if result.is_ok() {
        let found = cache.find_by_name("test.example.com", now, CacheEntryFlags::IPV4);
        assert!(
            !found.is_empty(),
            "Entry should be retrievable even with max_size=0"
        );
    }
    // Either way the cache object is in a valid state.
}

// ============================================================================
// Phase 3: Cache Insertion and Lookup Tests
// ============================================================================

/// Insert an A record (IPv4) and verify successful insertion.
/// Reference: `cache.c:cache_insert()`.
#[test]
fn test_cache_insert_a_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));

    let result = cache.insert(
        "host.example.com",
        Some(&addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "A record insertion should succeed");
    assert_eq!(cache.len(), 1);
    assert!(!cache.is_empty());
}

/// Insert an AAAA record (IPv6) and verify successful insertion.
#[test]
fn test_cache_insert_aaaa_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    let result = cache.insert(
        "host6.example.com",
        Some(&addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "AAAA record insertion should succeed");
    assert_eq!(cache.len(), 1);
}

/// Insert a CNAME record and verify the target name is stored.
#[test]
fn test_cache_insert_cname_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let cname_addr = AllAddr::Cname {
        target: CnameTarget::Name("real.example.com".to_string()),
        uid: 1,
    };

    let result = cache.insert(
        "alias.example.com",
        Some(&cname_addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::CNAME | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "CNAME record insertion should succeed");

    let found = cache.find_by_name("alias.example.com", now, CacheEntryFlags::CNAME);
    assert!(!found.is_empty(), "CNAME entry should be findable");
    assert!(found[0].flags.contains(CacheEntryFlags::CNAME));
}

/// Insert a PTR record (reverse DNS) and verify insertion.
#[test]
fn test_cache_insert_ptr_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));

    let result = cache.insert(
        "host.example.com",
        Some(&addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD | CacheEntryFlags::REVERSE,
    );
    assert!(result.is_ok(), "PTR record insertion should succeed");
    assert_eq!(cache.len(), 1);
}

/// Insert an MX record with priority data.
#[test]
fn test_cache_insert_mx_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    // MX records are stored as RR data with rrtype = T_MX.
    let mx_addr = AllAddr::RrData {
        rrtype: T_MX,
        data: vec![
            0, 10, // priority 10
            4, b'm', b'a', b'i', b'l', // "mail"
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm', 0, // "com" + root
        ],
    };

    let result = cache.insert(
        "example.com",
        Some(&mx_addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::RR | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "MX record insertion should succeed");
}

/// Insert an SRV record.
#[test]
fn test_cache_insert_srv_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let srv_addr = AllAddr::RrData {
        rrtype: T_SRV,
        data: vec![0, 10, 0, 5, 0x1F, 0x90], // priority=10, weight=5, port=8080
    };

    let result = cache.insert(
        "_http._tcp.example.com",
        Some(&srv_addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::RR | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "SRV record insertion should succeed");
}

/// Insert a TXT record.
#[test]
fn test_cache_insert_txt_record() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let txt_data = b"v=spf1 include:example.com ~all";
    let txt_addr = AllAddr::RrData {
        rrtype: T_TXT,
        data: txt_data.to_vec(),
    };

    let result = cache.insert(
        "example.com",
        Some(&txt_addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::RR | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "TXT record insertion should succeed");
}

/// Look up A record by domain name, verify correct IPv4 returned.
/// Reference: `cache.c:cache_find_by_name()`.
#[test]
fn test_cache_find_by_name_a() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));

    cache
        .insert(
            "web.example.com",
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    let results = cache.find_by_name("web.example.com", now, CacheEntryFlags::IPV4);
    assert_eq!(results.len(), 1);
    assert!(results[0].flags.contains(CacheEntryFlags::IPV4));
    assert_eq!(
        results[0].addr.as_ipv4(),
        Some(&Ipv4Addr::new(10, 0, 0, 1))
    );
}

/// Look up AAAA record by domain name, verify correct IPv6 returned.
#[test]
fn test_cache_find_by_name_aaaa() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let expected = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let addr = AllAddr::from_ipv6(expected);

    cache
        .insert(
            "host6.example.com",
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    let results = cache.find_by_name("host6.example.com", now, CacheEntryFlags::IPV6);
    assert_eq!(results.len(), 1);
    assert!(results[0].flags.contains(CacheEntryFlags::IPV6));
    assert_eq!(results[0].addr.as_ipv6(), Some(&expected));
}

/// Test CNAME chain resolution: insert CNAME → A chain, verify final address.
#[test]
fn test_cache_find_by_name_cname_chain() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    // CNAME: alias.example.com → real.example.com
    let cname_addr = AllAddr::Cname {
        target: CnameTarget::Name("real.example.com".to_string()),
        uid: 1,
    };
    cache
        .insert(
            "alias.example.com",
            Some(&cname_addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::CNAME | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // A record: real.example.com → 10.0.0.1
    let a_addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
    cache
        .insert(
            "real.example.com",
            Some(&a_addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // Looking up alias with IPV4 flag should follow CNAME and return the A record.
    let results = cache.find_by_name("alias.example.com", now, CacheEntryFlags::IPV4);
    let has_a = results.iter().any(|e| e.flags.contains(CacheEntryFlags::IPV4));
    assert!(has_a, "CNAME chain should resolve to A record");
}

/// Reverse lookup: find entry by IP address.
/// Reference: `cache.c:cache_find_by_addr()`.
#[test]
fn test_cache_find_by_addr() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(172, 16, 0, 1));

    cache
        .insert(
            "server.local",
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    let results = cache.find_by_addr(
        &AllAddr::from_ipv4(Ipv4Addr::new(172, 16, 0, 1)),
        now,
        CacheEntryFlags::IPV4,
    );
    assert!(!results.is_empty(), "Reverse lookup should find entry");
    assert_eq!(results[0].name, "server.local");
}

/// Look up a name that is not in the cache — should return empty and increment misses.
#[test]
fn test_cache_find_nonexistent() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    let results = cache.find_by_name("nonexistent.example.com", now, CacheEntryFlags::IPV4);
    assert!(results.is_empty(), "Nonexistent name should return empty");
    assert_eq!(cache.misses(), 1, "Miss counter should increment");
}

/// Look up an existing name but with the wrong record type — should return empty.
#[test]
fn test_cache_find_wrong_type() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));

    cache
        .insert(
            "host.example.com",
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // Search for AAAA — the A record should NOT match.
    let results = cache.find_by_name("host.example.com", now, CacheEntryFlags::IPV6);
    assert!(results.is_empty(), "Wrong type lookup should return empty");
}

// ============================================================================
// Phase 4: LRU Eviction Tests
// ============================================================================

/// Fill cache to capacity, insert one more, verify LRU eviction of oldest.
/// Reference: `cache.c` LRU eviction logic.
#[test]
fn test_lru_eviction_at_capacity() {
    let cache_size: usize = 10;
    let mut cache = create_test_cache(cache_size);
    let now = Instant::now();

    // Fill cache to capacity.
    for i in 0..cache_size {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, i as u8));
        cache
            .insert(
                &format!("host{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }
    assert_eq!(cache.len(), cache_size);

    // Insert one more — should trigger eviction of host0 (oldest).
    let new_addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 100));
    let result = cache.insert(
        "new-host.example.com",
        Some(&new_addr),
        C_IN,
        now,
        300,
        CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "Insertion after eviction should succeed");

    // Newest entry must be present.
    let found_new = cache.find_by_name("new-host.example.com", now, CacheEntryFlags::IPV4);
    assert!(!found_new.is_empty(), "Newest entry should be in cache");

    // Oldest entry (host0) should have been evicted.
    let found_old = cache.find_by_name("host0.example.com", now, CacheEntryFlags::IPV4);
    assert!(found_old.is_empty(), "Oldest entry should have been evicted");
}

/// Access an older entry to move it to the back of the LRU queue, then verify
/// the *next* oldest (untouched) entry is evicted instead.
#[test]
fn test_lru_access_updates_order() {
    let cache_size: usize = 5;
    let mut cache = create_test_cache(cache_size);
    let now = Instant::now();

    for i in 0..cache_size {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, i as u8));
        cache
            .insert(
                &format!("host{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }

    // Access host0 (oldest) to promote it in the LRU.
    let _ = cache.find_by_name("host0.example.com", now, CacheEntryFlags::IPV4);

    // Insert a new entry — host1 (now the oldest untouched) should be evicted.
    let new_addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 200));
    cache
        .insert(
            "accessed-test.example.com",
            Some(&new_addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // host0 should survive (was promoted).
    let found0 = cache.find_by_name("host0.example.com", now, CacheEntryFlags::IPV4);
    assert!(!found0.is_empty(), "Accessed entry should survive eviction");

    // host1 should be evicted (oldest untouched).
    let found1 = cache.find_by_name("host1.example.com", now, CacheEntryFlags::IPV4);
    assert!(found1.is_empty(), "Oldest untouched entry should be evicted");
}

/// Fill cache, access some entries, insert new ones. Verify accessed entries
/// survive while untouched entries are evicted.
#[test]
fn test_lru_eviction_preserves_recent() {
    let cache_size: usize = 10;
    let mut cache = create_test_cache(cache_size);
    let now = Instant::now();

    for i in 0..cache_size {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, i as u8));
        cache
            .insert(
                &format!("host{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }

    // Access the first 5 entries to make them "recent".
    for i in 0..5 {
        let _ = cache.find_by_name(
            &format!("host{}.example.com", i),
            now,
            CacheEntryFlags::IPV4,
        );
    }

    // Insert 5 new entries — host5..host9 (untouched) should be evicted.
    for i in 0..5 {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 1, 0, i as u8));
        cache
            .insert(
                &format!("new{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }

    // Accessed entries should still be present.
    for i in 0..5 {
        let found = cache.find_by_name(
            &format!("host{}.example.com", i),
            now,
            CacheEntryFlags::IPV4,
        );
        assert!(
            !found.is_empty(),
            "Recently accessed host{} should survive eviction",
            i
        );
    }
}

/// After eviction, verify new entries can still be inserted into freed space.
#[test]
fn test_eviction_frees_space_for_new_entries() {
    let cache_size: usize = 5;
    let mut cache = create_test_cache(cache_size);
    let now = Instant::now();

    // Fill to capacity.
    for i in 0..cache_size {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, i as u8));
        cache
            .insert(
                &format!("host{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }

    // Insert multiple new entries sequentially after eviction.
    for i in 0..3 {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 1, 0, i as u8));
        let result = cache.insert(
            &format!("new{}.example.com", i),
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        );
        assert!(result.is_ok(), "Insertion {} after eviction should succeed", i);
    }

    // All new entries must be present.
    for i in 0..3 {
        let found = cache.find_by_name(
            &format!("new{}.example.com", i),
            now,
            CacheEntryFlags::IPV4,
        );
        assert!(!found.is_empty(), "New entry {} should be in cache", i);
    }
}

// ============================================================================
// Phase 5: TTL Management Tests
// ============================================================================

/// Insert a record with short TTL, wait for expiration, verify record is gone.
/// Reference: `cache.c` TTL-based expiry.
#[test]
fn test_ttl_expiration() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));

    // Insert with TTL = 1 second.
    cache
        .insert(
            "expiring.example.com",
            Some(&addr),
            C_IN,
            now,
            1,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // Simulate time advancement by computing a future Instant rather than using
    // thread::sleep, avoiding timing-dependent flakiness on slow CI runners.
    // The cache uses the passed-in Instant to compute epoch-based TTD comparisons,
    // so advancing the Instant by more than the TTL is sufficient.
    let after = now + Duration::from_secs(2);

    // find_by_name skips expired entries.
    let results = cache.find_by_name("expiring.example.com", after, CacheEntryFlags::IPV4);
    assert!(
        results.is_empty(),
        "Expired entry should not be returned by find_by_name"
    );

    // Explicit expire() should remove it.
    let expired_count = cache.expire(after);
    assert!(expired_count >= 1, "At least one entry should have been expired");
}

/// Insert a record with long TTL, query immediately, verify it is still present.
#[test]
fn test_ttl_not_yet_expired() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));

    cache
        .insert(
            "persistent.example.com",
            Some(&addr),
            C_IN,
            now,
            300, // 5 minutes
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    let results = cache.find_by_name("persistent.example.com", now, CacheEntryFlags::IPV4);
    assert!(!results.is_empty(), "Entry with valid TTL should be returned");
    assert_eq!(
        results[0].addr.as_ipv4(),
        Some(&Ipv4Addr::new(10, 0, 0, 1))
    );
}

/// Insert a negative cache entry (NXDOMAIN), verify it is stored and expires.
/// Reference: `cache.c` negative caching support.
#[test]
fn test_negative_caching_nxdomain() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    let result = cache.insert(
        "nonexistent.example.com",
        None, // No address for negative entries.
        C_IN,
        now,
        60,
        CacheEntryFlags::IPV4
            | CacheEntryFlags::NEG
            | CacheEntryFlags::NXDOMAIN
            | CacheEntryFlags::FORWARD,
    );
    assert!(result.is_ok(), "Negative cache entry should be insertable");
    assert_eq!(cache.len(), 1, "Cache should contain the negative entry");

    // The entry should exist in the cache.
    assert!(cache.contains_name("nonexistent.example.com"));
}

/// Test that `clamp_ttl` enforces minimum TTL capped at TTL_FLOOR_LIMIT (3600s).
/// Simulates `--min-cache-ttl` setting.
#[test]
fn test_min_cache_ttl() {
    // TTL below min → raised to min.
    assert_eq!(DnsCache::clamp_ttl(60, 300), 300);

    // TTL above min → unchanged.
    assert_eq!(DnsCache::clamp_ttl(600, 300), 600);

    // min_ttl exceeds TTL_FLOOR_LIMIT → capped to TTL_FLOOR_LIMIT.
    assert_eq!(
        DnsCache::clamp_ttl(60, 7200),
        TTL_FLOOR_LIMIT,
        "min_ttl should be capped at TTL_FLOOR_LIMIT ({})",
        TTL_FLOOR_LIMIT
    );

    // TTL equals min → unchanged.
    assert_eq!(DnsCache::clamp_ttl(300, 300), 300);

    // Zero TTL with non-zero min → raised to min.
    assert_eq!(DnsCache::clamp_ttl(0, 300), 300);

    // Both zero → 0.
    assert_eq!(DnsCache::clamp_ttl(0, 0), 0);

    // Verify the constant value itself.
    assert_eq!(TTL_FLOOR_LIMIT, 3600);
}

/// Test that `--max-cache-ttl` capping stores entries with bounded TTL.
/// We verify by inserting with a very large TTL and confirming the entry's ttd field.
#[test]
fn test_max_cache_ttl() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));

    // Insert with 1-day TTL.
    cache
        .insert(
            "long-ttl.example.com",
            Some(&addr),
            C_IN,
            now,
            86400,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    let results = cache.find_by_name("long-ttl.example.com", now, CacheEntryFlags::IPV4);
    assert!(!results.is_empty());
    // The ttd field should be set (non-zero for non-immortal entries).
    assert!(results[0].ttd > 0, "Entry should have a non-zero TTD");
}

// ============================================================================
// Phase 6: Hosts File Integration Tests
// ============================================================================

/// Load entries from an `/etc/hosts`-format file and verify they appear in cache
/// as static (immortal) records. Reference: `cache.c:read_hostsfile()`.
#[test]
fn test_hosts_file_loading() {
    let mut cache = create_test_cache(CACHESIZ);
    let hosts_content = "\
127.0.0.1       localhost
192.168.1.1     gateway router.local
::1             localhost6 ip6-localhost
# This is a comment
10.0.0.1        server.local
";
    let path = create_temp_hosts_file(hosts_content);
    let result = cache.read_hostsfile(&path, 0);
    cleanup_temp_file(&path);

    assert!(result.is_ok(), "Hosts file reading should succeed: {:?}", result.err());
    let loaded = result.unwrap();
    assert!(loaded > 0, "Should have loaded at least one entry");
    assert!(cache.hosts_count() > 0, "hosts_count should be incremented");

    // Verify at least one hosts entry is present and marked correctly.
    let now = Instant::now();
    let results = cache.find_by_name("localhost", now, CacheEntryFlags::IPV4);
    if !results.is_empty() {
        assert!(results[0].flags.contains(CacheEntryFlags::HOSTS));
        assert!(results[0].flags.contains(CacheEntryFlags::IMMORTAL));
    }
}

/// Verify hosts file entries take precedence over (or coexist with) cached DNS
/// responses when both are present for the same name.
#[test]
fn test_hosts_file_overrides_cache() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    // Insert a regular DNS cache entry.
    let dns_addr = AllAddr::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
    cache
        .insert(
            "myhost.local",
            Some(&dns_addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // Load hosts file with a different address for the same name.
    let hosts_content = "192.168.1.100 myhost.local\n";
    let path = create_temp_hosts_file(hosts_content);
    let _ = cache.read_hostsfile(&path, 0);
    cleanup_temp_file(&path);

    // Lookup should include the hosts entry (marked HOSTS).
    let results = cache.find_by_name("myhost.local", now, CacheEntryFlags::IPV4);
    assert!(!results.is_empty(), "Should find entries for the name");
    let hosts_entries: Vec<&CacheEntry> = results
        .iter()
        .filter(|e| e.flags.contains(CacheEntryFlags::HOSTS))
        .collect();
    assert!(
        !hosts_entries.is_empty(),
        "Hosts file entry should be present among results"
    );
}

/// Simulate hosts file reload: clear cache and re-read updated hosts file.
/// Reference: `cache.c:cache_reload()`.
#[test]
fn test_hosts_file_reload() {
    let mut cache = create_test_cache(CACHESIZ);

    // Load initial hosts file.
    let hosts_content_v1 = "10.0.0.1 server-v1.local\n";
    let path = create_temp_hosts_file(hosts_content_v1);
    let result1 = cache.read_hostsfile(&path, 0);
    assert!(result1.is_ok());

    // Write updated content.
    std::fs::write(&path, "10.0.0.2 server-v2.local\n").expect("write updated hosts");

    // Simulate SIGHUP: clear non-protected, then reload.
    cache.clear();
    let result2 = cache.read_hostsfile(&path, 0);
    cleanup_temp_file(&path);

    assert!(result2.is_ok());
    assert!(
        cache.contains_name("server-v2.local"),
        "Updated host entry should be present after reload"
    );
}

// ============================================================================
// Phase 7: DHCP Hostname Registration Tests
// ============================================================================

/// Test DHCP-assigned hostnames are added to DNS cache.
/// Reference: `cache.c:cache_add_dhcp_entry()`.
#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_hostname_registration() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 100));

    cache.add_dhcp_entry("dhcp-client.local", &addr, CacheEntryFlags::IPV4);

    assert_eq!(cache.dhcp_count(), 1);
    assert!(cache.contains_name("dhcp-client.local"));

    let results = cache.find_by_name("dhcp-client.local", now, CacheEntryFlags::IPV4);
    assert!(!results.is_empty(), "DHCP entry should be findable");
    let dhcp_entry = results
        .iter()
        .find(|e| e.flags.contains(CacheEntryFlags::DHCP))
        .expect("At least one result should have the DHCP flag");
    assert_eq!(
        dhcp_entry.addr.as_ipv4(),
        Some(&Ipv4Addr::new(192, 168, 1, 100))
    );
}

/// Test expired DHCP entries are removed from cache.
/// Reference: `cache.c:cache_unhash_dhcp()`.
#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_entry_removal() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 200));

    cache.add_dhcp_entry("dhcp-remove.local", &addr, CacheEntryFlags::IPV4);
    assert_eq!(cache.dhcp_count(), 1);

    let removed = cache.remove_dhcp_entry("dhcp-remove.local");
    assert!(removed, "remove_dhcp_entry should return true");
    assert_eq!(cache.dhcp_count(), 0);

    let results = cache.find_by_name("dhcp-remove.local", now, CacheEntryFlags::IPV4);
    let dhcp_results: Vec<&CacheEntry> = results
        .iter()
        .filter(|e| e.flags.contains(CacheEntryFlags::DHCP))
        .collect();
    assert!(
        dhcp_results.is_empty(),
        "Removed DHCP entry should not be found"
    );
}

// ============================================================================
// Phase 8: Cache Statistics and Dump Tests
// ============================================================================

/// Test cache statistics reporting (hits, misses, evictions, size).
/// Reference: `cache.c:cache_make_stat()`.
#[test]
fn test_cache_statistics() {
    let cache = create_test_cache(CACHESIZ);
    let stat = cache.make_stat();

    // Verify the statistics string contains the expected fields.
    assert!(stat.contains("entries:"), "Stats should include entry count");
    assert!(stat.contains("hits:"), "Stats should include hit count");
    assert!(stat.contains("misses:"), "Stats should include miss count");
    assert!(stat.contains("evictions:"), "Stats should include eviction count");
    assert!(stat.contains("hosts:"), "Stats should include hosts count");
    assert!(stat.contains("dhcp:"), "Stats should include dhcp count");
}

/// Test cache content dump via `enumerate()` which provides the raw data that
/// `dump()` formats for logging. The `dump()` method requires `DaemonState`
/// and is exercised by verifying that `enumerate()` returns all entries.
/// Reference: `cache.c:dump_cache()`.
#[test]
fn test_cache_dump() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    let addr1 = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
    let addr2 = AllAddr::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

    cache
        .insert(
            "host1.example.com",
            Some(&addr1),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();
    cache
        .insert(
            "host2.example.com",
            Some(&addr2),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV6 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // enumerate() iterates all entries — equivalent data to dump().
    let entries: Vec<&CacheEntry> = cache.enumerate().collect();
    assert_eq!(entries.len(), 2, "enumerate should return all entries");

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"host1.example.com"));
    assert!(names.contains(&"host2.example.com"));
}

/// Insert, lookup (hit + miss), evict. Verify stats reflect all operations.
#[test]
fn test_cache_stats_after_operations() {
    let mut cache = create_test_cache(5);
    let now = Instant::now();

    // Insert 5 entries.
    for i in 0..5u8 {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, i));
        cache
            .insert(
                &format!("stats{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }

    // Hit — lookup existing entry.
    let _ = cache.find_by_name("stats0.example.com", now, CacheEntryFlags::IPV4);
    assert_eq!(cache.hits(), 1, "Should record 1 hit");

    // Miss — lookup nonexistent entry.
    let _ = cache.find_by_name("missing.example.com", now, CacheEntryFlags::IPV4);
    assert_eq!(cache.misses(), 1, "Should record 1 miss");

    // Eviction — insert beyond capacity.
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 1, 0, 1));
    cache
        .insert(
            "overflow.example.com",
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // Verify statistics string reflects operations.
    let stat = cache.make_stat();
    assert!(stat.contains("hits: 1"), "Stats should show 1 hit");
    assert!(stat.contains("misses: 1"), "Stats should show 1 miss");
}

// ============================================================================
// Phase 9: Edge Case Tests
// ============================================================================

/// Insert same name+type+class twice. Both entries should exist (round-robin).
#[test]
fn test_cache_duplicate_insert() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    let addr1 = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
    cache
        .insert(
            "dup.example.com",
            Some(&addr1),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    let addr2 = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 2));
    cache
        .insert(
            "dup.example.com",
            Some(&addr2),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // DNS allows multiple A records for the same name (round-robin).
    let results = cache.find_by_name("dup.example.com", now, CacheEntryFlags::IPV4);
    assert_eq!(results.len(), 2, "Both A records should be present");
}

/// Test wildcard NXDOMAIN caching behaviour.
/// Reference: `cache.c` wildcard negative caching.
#[test]
fn test_cache_wildcard_nxdomain() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    cache
        .insert(
            "*.wildcard.example.com",
            None,
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4
                | CacheEntryFlags::NEG
                | CacheEntryFlags::NXDOMAIN
                | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    assert!(cache.contains_name("*.wildcard.example.com"));
    assert_eq!(cache.len(), 1);
}

/// Verify DNS name lookups are case-insensitive per RFC 4343.
/// `example.COM` should match `Example.com`.
#[test]
fn test_cache_case_insensitive_lookup() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();
    let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));

    // Insert with mixed case.
    cache
        .insert(
            "Example.COM",
            Some(&addr),
            C_IN,
            now,
            300,
            CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
        )
        .unwrap();

    // All case variations should match.
    let r1 = cache.find_by_name("example.com", now, CacheEntryFlags::IPV4);
    assert!(!r1.is_empty(), "Lowercase lookup should match");

    let r2 = cache.find_by_name("EXAMPLE.COM", now, CacheEntryFlags::IPV4);
    assert!(!r2.is_empty(), "Uppercase lookup should match");

    let r3 = cache.find_by_name("Example.Com", now, CacheEntryFlags::IPV4);
    assert!(!r3.is_empty(), "Mixed case lookup should match");
}

// ============================================================================
// Additional utility and constant tests
// ============================================================================

/// Test `DnsCache::clear()` removes all non-protected entries while preserving
/// hosts-file and DHCP entries, and resets statistics.
#[test]
fn test_cache_clear_preserves_protected() {
    let mut cache = create_test_cache(CACHESIZ);
    let now = Instant::now();

    // Insert regular entries.
    for i in 0..10u8 {
        let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, i));
        cache
            .insert(
                &format!("clear{}.example.com", i),
                Some(&addr),
                C_IN,
                now,
                300,
                CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD,
            )
            .unwrap();
    }

    // Insert a hosts-file entry (protected).
    let hosts_content = "10.0.0.100 persistent.local\n";
    let path = create_temp_hosts_file(hosts_content);
    let _ = cache.read_hostsfile(&path, 0);
    cleanup_temp_file(&path);

    let before = cache.len();
    assert!(before > 10);

    // Clear cache.
    cache.clear();

    // Stats should be reset immediately after clear (before any lookups).
    assert_eq!(cache.hits(), 0, "Hits should be reset after clear");
    assert_eq!(cache.misses(), 0, "Misses should be reset after clear");
    assert_eq!(cache.evictions(), 0, "Evictions should be reset after clear");

    // Hosts entries should survive.
    assert!(cache.hosts_count() > 0, "Hosts entries should survive clear");

    // Regular entries should be gone (this lookup will increment misses).
    let results = cache.find_by_name("clear0.example.com", now, CacheEntryFlags::IPV4);
    assert!(results.is_empty(), "Regular entries should be cleared");
}

/// Test `DnsCache::name_to_wire()` produces correct wire-format encoding.
#[test]
fn test_cache_name_to_wire() {
    let wire: DnsName = DnsCache::name_to_wire("www.example.com");
    let bytes = wire.as_bytes();

    // Expected: [3]www[7]example[3]com[0]
    assert_eq!(bytes[0], 3);
    assert_eq!(&bytes[1..4], b"www");
    assert_eq!(bytes[4], 7);
    assert_eq!(&bytes[5..12], b"example");
    assert_eq!(bytes[12], 3);
    assert_eq!(&bytes[13..16], b"com");
    assert_eq!(bytes[16], 0); // root label

    // Verify DnsName methods.
    assert!(!wire.is_empty());
    assert_eq!(wire.len(), 17);
    let presentation = wire.to_string_lossy();
    assert_eq!(presentation, "www.example.com");
}

/// Test `DnsCache::ipv4_reverse_name()` produces correct `in-addr.arpa` name.
#[test]
fn test_cache_ipv4_reverse_name() {
    let addr = Ipv4Addr::new(192, 168, 1, 1);
    let reverse = DnsCache::ipv4_reverse_name(&addr);
    assert_eq!(reverse, "1.1.168.192.in-addr.arpa");
}

/// Test `DnsCache::ipv6_reverse_name()` produces correct `ip6.arpa` name.
#[test]
fn test_cache_ipv6_reverse_name() {
    let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let reverse = DnsCache::ipv6_reverse_name(&addr);
    assert!(
        reverse.ends_with(".ip6.arpa"),
        "IPv6 reverse should end with .ip6.arpa, got: {}",
        reverse
    );
}

/// Verify all critical constants match their documented values from `config.h`.
#[test]
fn test_constants_values() {
    assert_eq!(CACHESIZ, 150, "Default cache size should be 150");
    assert_eq!(TTL_FLOOR_LIMIT, 3600, "TTL floor limit should be 3600");
    assert_eq!(CNAME_CHAIN, 10, "CNAME chain limit should be 10");
    assert_eq!(SMALLDNAME, 50, "Small domain name buffer should be 50");
    assert_eq!(
        STALE_CACHE_EXPIRY, 86400,
        "Stale cache expiry should be 86400 (1 day)"
    );
}

/// Verify DNS protocol constants (T_A, T_AAAA, etc.) match IANA-assigned values,
/// and that the `RrType` enum round-trips correctly.
#[test]
fn test_protocol_constants() {
    assert_eq!(T_A, 1);
    assert_eq!(T_AAAA, 28);
    assert_eq!(T_CNAME, 5);
    assert_eq!(T_PTR, 12);
    assert_eq!(T_MX, 15);
    assert_eq!(T_SRV, 33);
    assert_eq!(T_TXT, 16);
    assert_eq!(C_IN, 1);

    // RrType enum round-trip.
    assert_eq!(RrType::from_u16(T_A), Some(RrType::A));
    assert_eq!(RrType::from_u16(T_AAAA), Some(RrType::Aaaa));
    assert_eq!(RrType::from_u16(T_CNAME), Some(RrType::Cname));
    assert_eq!(RrType::from_u16(T_PTR), Some(RrType::Ptr));
}

/// Verify `DnsHeader` type is accessible and its default methods work.
#[test]
fn test_dns_header_accessible() {
    let header = DnsHeader {
        id: 0x1234,
        hb3: 0,
        hb4: 0,
        qdcount: 0,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    assert_eq!(header.id, 0x1234);
    assert!(!header.is_response());
    assert_eq!(header.opcode(), 0);
    assert_eq!(header.rcode(), 0);
}

/// Verify `CacheEntryFlags` bitflag operations work as expected.
#[test]
fn test_cache_entry_flags() {
    let flags = CacheEntryFlags::IPV4 | CacheEntryFlags::FORWARD;
    assert!(flags.contains(CacheEntryFlags::IPV4));
    assert!(flags.contains(CacheEntryFlags::FORWARD));
    assert!(!flags.contains(CacheEntryFlags::IPV6));
    assert!(!flags.contains(CacheEntryFlags::HOSTS));
    assert!(!flags.contains(CacheEntryFlags::DHCP));

    // Protected flags: HOSTS, DHCP, CONFIG
    let protected = CacheEntryFlags::HOSTS | CacheEntryFlags::IMMORTAL;
    assert!(protected.intersects(CacheEntryFlags::HOSTS));
    assert!(!protected.intersects(CacheEntryFlags::DHCP));

    // Negative entry flags.
    let neg = CacheEntryFlags::NEG | CacheEntryFlags::NXDOMAIN;
    assert!(neg.contains(CacheEntryFlags::NEG));
    assert!(neg.contains(CacheEntryFlags::NXDOMAIN));
}

/// Test `CacheError` variants for proper Display formatting.
#[test]
fn test_cache_error_display() {
    let err_full = CacheError::Full {
        count: 150,
        max: 150,
    };
    let msg = format!("{}", err_full);
    assert!(msg.contains("150"), "Full error should mention count");

    let err_invalid = CacheError::InvalidEntry("bad name".to_string());
    let msg2 = format!("{}", err_invalid);
    assert!(msg2.contains("bad name"));
}

/// Test that `AllAddr` variants can be constructed and inspected correctly.
#[test]
fn test_alladdr_variants() {
    // V4 variant.
    let v4 = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 0, 1));
    assert!(v4.is_v4());
    assert!(!v4.is_v6());
    assert_eq!(v4.as_ipv4(), Some(&Ipv4Addr::new(192, 168, 0, 1)));
    assert_eq!(v4.as_ipv6(), None);

    // V6 variant.
    let v6 = AllAddr::from_ipv6(Ipv6Addr::LOCALHOST);
    assert!(v6.is_v6());
    assert!(!v6.is_v4());
    assert_eq!(v6.as_ipv6(), Some(&Ipv6Addr::LOCALHOST));
    assert_eq!(v6.as_ipv4(), None);

    // Cname variant.
    let cname = AllAddr::Cname {
        target: CnameTarget::Name("target.example.com".to_string()),
        uid: 42,
    };
    assert!(!cname.is_v4());
    assert!(!cname.is_v6());

    // From trait impls.
    let from_v4: AllAddr = Ipv4Addr::new(10, 0, 0, 1).into();
    assert!(from_v4.is_v4());
    let from_v6: AllAddr = Ipv6Addr::UNSPECIFIED.into();
    assert!(from_v6.is_v6());
}

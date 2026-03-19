// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2024 The dnsmasq-rust contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! DNS cache performance benchmarks
//!
//! Validates that the Rust DNS cache implementation meets or exceeds
//! the C implementation's performance for the hottest code path in dnsmasq.
//!
//! Key metrics:
//! - Cache lookup by name: target < 1μs for 150-entry cache (CACHESIZ default)
//! - Cache insertion: target < 1μs including LRU eviction
//! - Cache lookup by address (reverse DNS): target < 10μs (full scan)
//! - TTL eviction: amortized cost during lookups
//!
//! Reference: `src/cache.c` (4,119 lines) — C DNS cache with custom hash table
//!
//! The C implementation uses:
//! - `cache_init()` (line 353): Initializes hash table + cache records
//! - `hash_bucket()` (line 489): Barker-code hash with rotate-left-7 mixing
//! - `cache_find_by_name()` (line 2213): Forward DNS lookup with round-robin
//! - `cache_find_by_addr()` (line 2353): Reverse DNS lookup (scans all buckets)
//! - `really_insert()` (line 1499): LRU eviction when cache is full

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use dnsmasq::config::constants::CACHESIZ;
use dnsmasq::dns::cache::{CacheData, CacheEntry, CacheFlags, DnsCache};
use dnsmasq::dns::protocol::{DnsName, RRType};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Generate a realistic domain name for benchmarking.
///
/// Produces names such as `"host-42.example.com"` that resemble typical
/// internal or CDN host names observed in real-world DNS caches.
fn make_domain(index: usize) -> String {
    format!("host-{}.example.com", index)
}

/// Construct [`CacheFlags`] representing a typical upstream DNS response.
///
/// Sets `from_upstream: true` and `forward: true` — the most common flag
/// combination in production dnsmasq caches (entries learned from upstream
/// forwarders).
fn make_cache_flags_upstream() -> CacheFlags {
    CacheFlags {
        from_upstream: true,
        forward: true,
        ..CacheFlags::new()
    }
}

/// Build a single [`CacheEntry`] for an A record with the given parameters.
///
/// Computes `expires` from `Instant::now() + Duration::from_secs(ttl)` to
/// match the insertion pattern used by `cache_insert` in the real daemon.
fn make_a_record_entry(name: &str, addr: Ipv4Addr, ttl: u32) -> CacheEntry {
    let now = Instant::now();
    CacheEntry {
        name: DnsName::from_str_unchecked(name),
        rr_type: RRType::A,
        data: CacheData::Addr4(addr),
        expires: now + Duration::from_secs(u64::from(ttl)),
        last_access: now,
        flags: make_cache_flags_upstream(),
        ttl,
    }
}

/// Create a pre-populated DNS cache with `count` A record entries.
///
/// Uses default `CACHESIZ` (150) when `count` matches the default
/// configuration.  Each entry gets a unique domain name and a unique
/// IPv4 address from the `10.0.0.0/8` range.
///
/// # Panics
///
/// Panics if cache initialisation fails (unexpected in benchmarks).
fn make_populated_cache(count: usize) -> DnsCache {
    let mut cache = DnsCache::cache_init(Some(count))
        .expect("DnsCache::cache_init should succeed in benchmarks");
    for i in 0..count {
        let name = make_domain(i);
        let addr = Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8);
        let entry = make_a_record_entry(&name, addr, 300);
        cache
            .cache_insert(entry)
            .expect("cache_insert should succeed during population");
    }
    cache
}

/// Create a cache pre-populated with entries whose TTLs have already
/// expired.
///
/// Uses `from_upstream: false` so that zero-TTL entries are not rejected
/// by the upstream zero-TTL guard in `cache_insert`.  Sets `expires` to
/// `Instant::now()` so that entries are stale by the time the benchmark
/// closure runs.
fn make_expired_cache(count: usize) -> DnsCache {
    let mut cache = DnsCache::cache_init(Some(count))
        .expect("DnsCache::cache_init should succeed in benchmarks");
    let past = Instant::now();
    for i in 0..count {
        let name = make_domain(i);
        let addr = Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8);
        let entry = CacheEntry {
            name: DnsName::from_str_unchecked(&name),
            rr_type: RRType::A,
            data: CacheData::Addr4(addr),
            // Set expiry to 'past' so entries are expired by measurement time.
            expires: past,
            last_access: past,
            flags: CacheFlags {
                forward: true,
                // Keep from_upstream false so zero-TTL entries are accepted.
                ..CacheFlags::new()
            },
            ttl: 1,
        };
        cache
            .cache_insert(entry)
            .expect("cache_insert should succeed for expired entries");
    }
    cache
}

// ---------------------------------------------------------------------------
// Benchmark 1: Cache lookup by name (forward DNS)
// ---------------------------------------------------------------------------

/// Benchmark forward DNS cache lookups at varying cache sizes.
///
/// This is the **hottest code path** in dnsmasq — every incoming DNS query
/// starts with a `cache_find_by_name` call.  The C implementation walks a
/// hash-chain and checks TTL expiry inline.  The Rust implementation uses
/// `HashMap` keyed by normalised domain name.
///
/// **C reference:** `cache_find_by_name()` — `cache.c` line 2213.
///
/// Tests cache sizes: 50, 150 (default CACHESIZ), 500, 1000, 5000.
fn bench_cache_find_by_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_find_by_name");

    for &cache_size in &[50_usize, 150, 500, 1000, 5000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(cache_size),
            &cache_size,
            |b, &size| {
                let mut cache = make_populated_cache(size);
                // Look up an entry in the middle of the population range.
                let target_name = DnsName::from_str_unchecked(&make_domain(size / 2));
                b.iter(|| {
                    let results = cache
                        .cache_find_by_name(black_box(&target_name), black_box(Some(RRType::A)));
                    // Consume the Vec inside the closure so references
                    // to the captured `cache` do not escape the FnMut body.
                    black_box(results.len())
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 2: Cache lookup miss
// ---------------------------------------------------------------------------

/// Benchmark the latency of a cache miss (domain not in cache).
///
/// In the C implementation, this traverses the entire hash-chain bucket
/// finding no match.  With a well-distributed hash, the bucket is small.
///
/// **C reference:** `cache_find_by_name()` returning NULL — `cache.c` line 2213.
fn bench_cache_lookup_miss(c: &mut Criterion) {
    let mut cache = make_populated_cache(CACHESIZ as usize);
    let miss_name = DnsName::from_str_unchecked("nonexistent.example.org");

    c.bench_function("cache_lookup_miss", |b| {
        b.iter(|| {
            let results =
                cache.cache_find_by_name(black_box(&miss_name), black_box(Some(RRType::A)));
            black_box(results.len())
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 3: Cache insertion
// ---------------------------------------------------------------------------

/// Benchmark cache insertion throughput at varying cache sizes.
///
/// Each iteration receives a freshly-populated cache (via `iter_batched`)
/// and inserts one new entry.  Measures hash computation, bucket allocation,
/// and any capacity-checking overhead.
///
/// **C reference:** `really_insert()` — `cache.c` line 1499.
fn bench_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert");

    for &cache_size in &[150_usize, 1000] {
        group.bench_with_input(
            BenchmarkId::new("size", cache_size),
            &cache_size,
            |b, &size| {
                b.iter_batched(
                    || make_populated_cache(size),
                    |mut cache| {
                        let entry = make_a_record_entry(
                            &format!("new-entry-{}.test.com", size),
                            Ipv4Addr::new(172, 16, 0, 1),
                            300,
                        );
                        let _ = black_box(cache.cache_insert(black_box(entry)));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 4: Cache insertion with LRU eviction
// ---------------------------------------------------------------------------

/// Benchmark insertion performance when the cache is full and LRU eviction
/// is triggered.
///
/// In the C implementation, `really_insert()` scans for expired entries
/// first, then evicts the LRU tail when no expired entries remain.  This
/// measures the worst-case insert path.
///
/// **C reference:** `really_insert()` lines 1544-1588 — `cache.c`.
fn bench_cache_insert_eviction(c: &mut Criterion) {
    c.bench_function("cache_insert_with_eviction", |b| {
        b.iter_batched(
            || make_populated_cache(CACHESIZ as usize),
            |mut cache| {
                // Insert 10 entries beyond capacity to trigger repeated eviction.
                for i in 0u8..10 {
                    let entry = make_a_record_entry(
                        &format!("evict-{}.test.com", i),
                        Ipv4Addr::new(192, 168, 1, i),
                        300,
                    );
                    let _ = black_box(cache.cache_insert(black_box(entry)));
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// Benchmark 5: Cache lookup by address (reverse DNS / PTR)
// ---------------------------------------------------------------------------

/// Benchmark reverse DNS (PTR) lookup by IP address.
///
/// The C implementation scans **all** hash buckets on the first call, which
/// is expensive.  It stops scanning each bucket after the first
/// non-`F_REVERSE` entry.  The Rust implementation uses a secondary index
/// or full-scan approach.
///
/// **C reference:** `cache_find_by_addr()` — `cache.c` line 2353.
fn bench_cache_find_by_addr(c: &mut Criterion) {
    let mut cache = DnsCache::cache_init(Some(CACHESIZ as usize))
        .expect("DnsCache::cache_init should succeed in benchmarks");

    // Populate with A record entries (forward records).
    for i in 0..(CACHESIZ as usize) {
        let name = make_domain(i);
        let addr = Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8);
        let entry = make_a_record_entry(&name, addr, 300);
        cache
            .cache_insert(entry)
            .expect("cache_insert should succeed during population");
    }

    // Search for an address in the middle of the populated range.
    let search_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 75));

    c.bench_function("cache_find_by_addr", |b| {
        b.iter(|| {
            let results = cache.cache_find_by_addr(black_box(&search_addr));
            black_box(results.len())
        })
    });
}

// ---------------------------------------------------------------------------
// Benchmark 6: TTL eviction performance
// ---------------------------------------------------------------------------

/// Benchmark the cost of evicting expired entries from the cache.
///
/// Creates a full cache where every entry has already expired, then
/// measures how long `cache_evict_expired()` takes to purge them.
///
/// **C reference:** `cache_find_by_name()` lines 2276-2284 — frees
/// expired entries during hash-chain traversal in `cache.c`.
fn bench_ttl_eviction(c: &mut Criterion) {
    c.bench_function("ttl_eviction", |b| {
        b.iter_batched(
            || {
                // Tiny sleep to guarantee entries created below have truly
                // expired by the time the measurement closure executes.
                std::thread::sleep(Duration::from_millis(1));
                make_expired_cache(CACHESIZ as usize)
            },
            |mut cache| {
                black_box(cache.cache_evict_expired());
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// Benchmark 7: Hash distribution / collision behaviour
// ---------------------------------------------------------------------------

/// Benchmark lookup performance under different domain-name distributions.
///
/// Compares "normal" distribution (varied host names) against "subdomain
/// clustering" (many labels under a single parent), which is more likely
/// to produce hash-bucket clustering.
///
/// **C reference:** `hash_bucket()` — `cache.c` line 489.  The Barker-code
/// hash with XOR folding degrades to O(n) per bucket on collision.
fn bench_hash_collision_behavior(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_collision");

    // --- Normal distribution (varied domain names) ---
    group.bench_function("normal_distribution", |b| {
        let mut cache = make_populated_cache(CACHESIZ as usize);
        let target = DnsName::from_str_unchecked(&make_domain(CACHESIZ as usize / 2));
        b.iter(|| {
            let results = cache.cache_find_by_name(black_box(&target), black_box(Some(RRType::A)));
            black_box(results.len())
        });
    });

    // --- Subdomain clustering (many subdomains of the same parent) ---
    group.bench_function("subdomain_clustering", |b| {
        let mut cache = DnsCache::cache_init(Some(CACHESIZ as usize))
            .expect("DnsCache::cache_init should succeed in benchmarks");
        for i in 0..(CACHESIZ as usize) {
            let name = format!("{}.internal.corp.example.com", i);
            let addr = Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8);
            let entry = make_a_record_entry(&name, addr, 300);
            cache
                .cache_insert(entry)
                .expect("cache_insert should succeed for subdomain entries");
        }
        let target = DnsName::from_str_unchecked(&format!(
            "{}.internal.corp.example.com",
            CACHESIZ as usize / 2
        ));
        b.iter(|| {
            let results = cache.cache_find_by_name(black_box(&target), black_box(Some(RRType::A)));
            black_box(results.len())
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 8: Mixed record types (realistic workload)
// ---------------------------------------------------------------------------

/// Benchmark lookup in a cache populated with mixed DNS record types.
///
/// Populates the cache with a realistic mix of A, AAAA, CNAME, and
/// NXDOMAIN records, then measures lookup latency for an A record.
/// This models a real-world home or enterprise DNS cache.
fn bench_mixed_record_types(c: &mut Criterion) {
    let mut cache = DnsCache::cache_init(Some(CACHESIZ as usize))
        .expect("DnsCache::cache_init should succeed in benchmarks");

    let now = Instant::now();

    for i in 0..(CACHESIZ as usize) {
        let name = make_domain(i);
        let entry = match i % 4 {
            // 25 % A records
            0 => {
                let addr = Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8);
                CacheEntry {
                    name: DnsName::from_str_unchecked(&name),
                    rr_type: RRType::A,
                    data: CacheData::Addr4(addr),
                    expires: now + Duration::from_secs(300),
                    last_access: now,
                    flags: make_cache_flags_upstream(),
                    ttl: 300,
                }
            }
            // 25 % AAAA records
            1 => {
                let addr = Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    0,
                    0,
                    0,
                    0,
                    (i / 256) as u16,
                    (i % 256) as u16,
                );
                CacheEntry {
                    name: DnsName::from_str_unchecked(&name),
                    rr_type: RRType::AAAA,
                    data: CacheData::Addr6(addr),
                    expires: now + Duration::from_secs(300),
                    last_access: now,
                    flags: make_cache_flags_upstream(),
                    ttl: 300,
                }
            }
            // 25 % CNAME records
            2 => {
                let target = format!("cname-target-{}.example.com", i);
                CacheEntry {
                    name: DnsName::from_str_unchecked(&name),
                    rr_type: RRType::CNAME,
                    data: CacheData::Cname(DnsName::from_str_unchecked(&target)),
                    expires: now + Duration::from_secs(300),
                    last_access: now,
                    flags: make_cache_flags_upstream(),
                    ttl: 300,
                }
            }
            // 25 % NXDOMAIN (negative cache)
            _ => CacheEntry {
                name: DnsName::from_str_unchecked(&name),
                rr_type: RRType::A,
                data: CacheData::NxDomain,
                expires: now + Duration::from_secs(60),
                last_access: now,
                flags: CacheFlags {
                    from_upstream: true,
                    forward: true,
                    nxdomain: true,
                    ..CacheFlags::new()
                },
                ttl: 60,
            },
        };
        cache
            .cache_insert(entry)
            .expect("cache_insert should succeed for mixed record types");
    }

    // Look up an A record (index 0 mod 4 == 0).
    let target = DnsName::from_str_unchecked(&make_domain(0));

    c.bench_function("mixed_record_lookup", |b| {
        b.iter(|| {
            let results = cache.cache_find_by_name(black_box(&target), black_box(Some(RRType::A)));
            black_box(results.len())
        });
    });
}

// ---------------------------------------------------------------------------
// Criterion group registration and entry point
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_cache_find_by_name,
    bench_cache_lookup_miss,
    bench_cache_insert,
    bench_cache_insert_eviction,
    bench_cache_find_by_addr,
    bench_ttl_eviction,
    bench_hash_collision_behavior,
    bench_mixed_record_types,
);
criterion_main!(benches);

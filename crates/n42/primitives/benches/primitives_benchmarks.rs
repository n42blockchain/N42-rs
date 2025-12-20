// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Performance benchmarks for n42-primitives operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use alloy_primitives::{Address, B256, U256};
use n42_primitives::{APosConfig, Snapshot};

/// Benchmark APosConfig operations
fn bench_apos_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("apos_config");

    // Benchmark config creation
    group.bench_function("default_creation", |b| {
        b.iter(|| black_box(APosConfig::default()));
    });

    // Benchmark config clone
    let config = APosConfig {
        period: 15,
        epoch: 30000,
        reward_epoch: 10000,
        reward_limit: U256::from(1_000_000u64),
        deposit_contract: Address::from_slice(&[0x42; 20]),
    };

    group.bench_function("clone", |b| {
        b.iter(|| black_box(config.clone()));
    });

    // Benchmark config comparison
    let config2 = config.clone();
    group.bench_function("equality_check", |b| {
        b.iter(|| black_box(config == config2));
    });

    group.finish();
}

/// Benchmark Snapshot hash operations
fn bench_snapshot_hash(c: &mut Criterion) {
    let config = APosConfig::default();
    let signers: Vec<Address> = (0..21)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    let snap = Snapshot::new_snapshot(config, 1000, B256::repeat_byte(0x42), signers);

    let mut group = c.benchmark_group("snapshot_hash");

    // Benchmark hash comparison
    let hash1 = snap.hash;
    let hash2 = B256::repeat_byte(0x42);

    group.bench_function("b256_equality", |b| {
        b.iter(|| black_box(hash1 == hash2));
    });

    // Benchmark hash as map key (hashing the hash)
    group.bench_function("b256_hash", |b| {
        b.iter(|| {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            hash1.hash(&mut hasher);
            black_box(hasher.finish())
        });
    });

    group.finish();
}

/// Benchmark signer list operations
fn bench_signer_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("signer_operations");

    for num_signers in [5, 21, 50, 100, 500].iter() {
        let signers: Vec<Address> = (0..*num_signers)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[0] = (i >> 8) as u8;
                bytes[1] = i as u8;
                Address::from_slice(&bytes)
            })
            .collect();

        // Benchmark signer list creation
        group.throughput(Throughput::Elements(*num_signers as u64));
        group.bench_with_input(
            BenchmarkId::new("vec_clone", num_signers),
            &signers,
            |b, signers| {
                b.iter(|| black_box(signers.clone()));
            },
        );

        // Benchmark contains check (linear search)
        let search_addr = signers[signers.len() / 2];
        group.bench_with_input(
            BenchmarkId::new("contains", num_signers),
            &(&signers, search_addr),
            |b, (signers, addr)| {
                b.iter(|| black_box(signers.contains(addr)));
            },
        );

        // Benchmark binary search (sorted list)
        let mut sorted_signers = signers.clone();
        sorted_signers.sort();
        group.bench_with_input(
            BenchmarkId::new("binary_search", num_signers),
            &(&sorted_signers, search_addr),
            |b, (signers, addr)| {
                b.iter(|| black_box(signers.binary_search(addr)));
            },
        );
    }

    group.finish();
}

/// Benchmark tally operations
fn bench_tally_operations(c: &mut Criterion) {
    use std::collections::BTreeMap;

    let mut group = c.benchmark_group("tally_operations");

    // Setup - create addresses
    let addresses: Vec<Address> = (0..100)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    // Benchmark BTreeMap insert (used in tally)
    group.bench_function("btreemap_insert", |b| {
        b.iter_batched(
            || BTreeMap::<Address, u32>::new(),
            |mut map| {
                for (i, addr) in addresses.iter().enumerate() {
                    map.insert(*addr, i as u32);
                }
                black_box(map)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark BTreeMap lookup
    let mut map = BTreeMap::new();
    for (i, addr) in addresses.iter().enumerate() {
        map.insert(*addr, i as u32);
    }

    let lookup_addr = addresses[50];
    group.bench_function("btreemap_get", |b| {
        b.iter(|| black_box(map.get(&lookup_addr)));
    });

    // Benchmark BTreeMap remove
    group.bench_function("btreemap_remove", |b| {
        b.iter_batched(
            || map.clone(),
            |mut map| {
                map.remove(&lookup_addr);
                black_box(map)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark RLP encoding/decoding for snapshot-like structures
fn bench_rlp_operations(c: &mut Criterion) {
    use alloy_rlp::{Decodable, Encodable};

    let config = APosConfig::default();
    let signers: Vec<Address> = (0..21)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    let snap = Snapshot::new_snapshot(config, 1000, B256::repeat_byte(0x42), signers);

    let mut group = c.benchmark_group("rlp_operations");

    // Benchmark RLP encoding
    group.bench_function("encode", |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            snap.encode(&mut buf);
            black_box(buf)
        });
    });

    // Benchmark RLP decoding
    let mut encoded = Vec::new();
    snap.encode(&mut encoded);

    group.bench_function("decode", |b| {
        b.iter(|| black_box(Snapshot::decode(&mut encoded.as_slice()).unwrap()));
    });

    group.finish();
}

/// Benchmark U256 operations (common in difficulty/TD calculations)
fn bench_u256_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("u256_operations");

    let a = U256::from(1_000_000_000_000u64);
    let b = U256::from(500_000_000_000u64);

    // Addition
    group.bench_function("addition", |b| {
        b.iter(|| black_box(a + b));
    });

    // Subtraction
    group.bench_function("subtraction", |b| {
        b.iter(|| black_box(a - b));
    });

    // Comparison
    group.bench_function("comparison", |b| {
        b.iter(|| black_box(a > b));
    });

    // Saturating subtraction (safe arithmetic)
    group.bench_function("saturating_sub", |b| {
        b.iter(|| black_box(a.saturating_sub(b)));
    });

    // From u64
    group.bench_function("from_u64", |b| {
        b.iter(|| black_box(U256::from(12345678901234u64)));
    });

    group.finish();
}

/// Benchmark Address operations
fn bench_address_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_operations");

    let addr1 = Address::from_slice(&[0x42; 20]);
    let addr2 = Address::from_slice(&[0x43; 20]);

    // Creation from slice
    group.bench_function("from_slice", |b| {
        let bytes = [0x42u8; 20];
        b.iter(|| black_box(Address::from_slice(&bytes)));
    });

    // Equality check
    group.bench_function("equality", |b| {
        b.iter(|| black_box(addr1 == addr2));
    });

    // Ordering comparison
    group.bench_function("ordering", |b| {
        b.iter(|| black_box(addr1.cmp(&addr2)));
    });

    // Hash calculation
    group.bench_function("hash", |b| {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            addr1.hash(&mut hasher);
            black_box(hasher.finish())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_apos_config,
    bench_snapshot_hash,
    bench_signer_operations,
    bench_tally_operations,
    bench_rlp_operations,
    bench_u256_operations,
    bench_address_operations,
);

criterion_main!(benches);


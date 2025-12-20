// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Performance benchmarks for consensus operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use alloy_primitives::{Address, B256, U256};
use n42_primitives::{APosConfig, Snapshot};

/// Benchmark snapshot creation
fn bench_snapshot_creation(c: &mut Criterion) {
    let config = APosConfig::default();

    let mut group = c.benchmark_group("snapshot_creation");

    for num_signers in [1, 5, 10, 21, 50, 100].iter() {
        let signers: Vec<Address> = (0..*num_signers)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[0] = (i >> 8) as u8;
                bytes[1] = i as u8;
                Address::from_slice(&bytes)
            })
            .collect();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("signers", num_signers),
            &signers,
            |b, signers| {
                b.iter(|| {
                    Snapshot::new_snapshot(
                        black_box(config.clone()),
                        black_box(1000),
                        black_box(B256::ZERO),
                        black_box(signers.clone()),
                    )
                });
            },
        );
    }

    group.finish();
}

/// Benchmark snapshot copy operation
fn bench_snapshot_copy(c: &mut Criterion) {
    let config = APosConfig::default();
    let signers: Vec<Address> = (0..21)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    let snap = Snapshot::new_snapshot(config, 1000, B256::ZERO, signers);

    c.bench_function("snapshot_copy", |b| {
        b.iter(|| black_box(snap.copy()));
    });
}

/// Benchmark inturn calculation
fn bench_inturn_calculation(c: &mut Criterion) {
    let config = APosConfig::default();

    let mut group = c.benchmark_group("inturn_calculation");

    for num_signers in [5, 10, 21, 50, 100].iter() {
        let signers: Vec<Address> = (0..*num_signers)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[0] = (i >> 8) as u8;
                bytes[1] = i as u8;
                Address::from_slice(&bytes)
            })
            .collect();

        let snap = Snapshot::new_snapshot(config.clone(), 1000, B256::ZERO, signers.clone());
        let test_signer = signers[0];

        group.throughput(Throughput::Elements(1000));
        group.bench_with_input(
            BenchmarkId::new("signers", num_signers),
            &(&snap, &test_signer),
            |b, (snap, signer)| {
                b.iter(|| {
                    for block_num in 1..=1000 {
                        black_box(snap.inturn(block_num, signer));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark vote casting
fn bench_vote_casting(c: &mut Criterion) {
    let config = APosConfig::default();
    let signers: Vec<Address> = (0..21)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    let mut group = c.benchmark_group("vote_operations");

    // Benchmark casting votes
    group.bench_function("cast_vote", |b| {
        b.iter_batched(
            || Snapshot::new_snapshot(config.clone(), 1000, B256::ZERO, signers.clone()),
            |mut snap| {
                let new_addr = Address::from_slice(&[0xFF; 20]);
                black_box(snap.cast(new_addr, true));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Benchmark uncasting votes
    group.bench_function("uncast_vote", |b| {
        b.iter_batched(
            || {
                let mut snap =
                    Snapshot::new_snapshot(config.clone(), 1000, B256::ZERO, signers.clone());
                let new_addr = Address::from_slice(&[0xFF; 20]);
                snap.cast(new_addr, true);
                (snap, new_addr)
            },
            |(mut snap, addr)| {
                black_box(snap.uncast(addr, true));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark valid_vote check
fn bench_valid_vote(c: &mut Criterion) {
    let config = APosConfig::default();
    let signers: Vec<Address> = (0..21)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    let snap = Snapshot::new_snapshot(config, 1000, B256::ZERO, signers.clone());

    let mut group = c.benchmark_group("valid_vote");

    // Check authorize vote for existing signer (should be invalid)
    group.bench_function("existing_signer_auth", |b| {
        b.iter(|| black_box(snap.valid_vote(signers[0], true)));
    });

    // Check authorize vote for new address (should be valid)
    let new_addr = Address::from_slice(&[0xFF; 20]);
    group.bench_function("new_signer_auth", |b| {
        b.iter(|| black_box(snap.valid_vote(new_addr, true)));
    });

    // Check deauthorize vote for existing signer (should be valid)
    group.bench_function("existing_signer_deauth", |b| {
        b.iter(|| black_box(snap.valid_vote(signers[0], false)));
    });

    group.finish();
}

/// Benchmark snapshot serialization
fn bench_snapshot_serialization(c: &mut Criterion) {
    let config = APosConfig {
        period: 15,
        epoch: 30000,
        reward_epoch: 10000,
        reward_limit: U256::from(1000000u64),
        deposit_contract: Address::from_slice(&[0xAB; 20]),
    };

    let signers: Vec<Address> = (0..21)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from_slice(&bytes)
        })
        .collect();

    let mut snap = Snapshot::new_snapshot(config, 50000, B256::repeat_byte(0x42), signers);

    // Add some votes to make it more realistic
    for i in 100..110 {
        let mut bytes = [0u8; 20];
        bytes[19] = i;
        let addr = Address::from_slice(&bytes);
        snap.cast(addr, true);
    }

    let mut group = c.benchmark_group("serialization");

    // Benchmark JSON serialization
    group.bench_function("json_serialize", |b| {
        b.iter(|| black_box(serde_json::to_string(&snap).unwrap()));
    });

    // Benchmark JSON deserialization
    let json = serde_json::to_string(&snap).unwrap();
    group.bench_function("json_deserialize", |b| {
        b.iter(|| black_box(serde_json::from_str::<Snapshot>(&json).unwrap()));
    });

    group.finish();
}

/// Benchmark signer lookup (binary search in sorted list)
fn bench_signer_lookup(c: &mut Criterion) {
    let config = APosConfig::default();

    let mut group = c.benchmark_group("signer_lookup");

    for num_signers in [10, 50, 100, 500, 1000].iter() {
        let signers: Vec<Address> = (0..*num_signers)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[0] = (i >> 8) as u8;
                bytes[1] = i as u8;
                Address::from_slice(&bytes)
            })
            .collect();

        let snap = Snapshot::new_snapshot(config.clone(), 1000, B256::ZERO, signers.clone());

        // Search for middle element
        let search_addr = signers[*num_signers as usize / 2];

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("signers", num_signers),
            &(&snap, search_addr),
            |b, (snap, addr)| {
                b.iter(|| black_box(snap.signers.binary_search(addr)));
            },
        );
    }

    group.finish();
}

/// Benchmark difficulty calculation pattern
fn bench_difficulty_pattern(c: &mut Criterion) {
    use n42_clique::{DIFF_IN_TURN, DIFF_NO_TURN};

    let mut group = c.benchmark_group("difficulty");

    // Benchmark U256 comparison (common operation in difficulty calculation)
    let td1 = U256::from(1_000_000u64);
    let td2 = U256::from(1_000_001u64);

    group.bench_function("u256_comparison", |b| {
        b.iter(|| black_box(td1 < td2));
    });

    // Benchmark U256 addition
    group.bench_function("u256_addition", |b| {
        b.iter(|| black_box(td1 + DIFF_IN_TURN));
    });

    // Benchmark difficulty selection
    group.bench_function("difficulty_select", |b| {
        b.iter(|| {
            let is_inturn = black_box(true);
            if is_inturn {
                black_box(DIFF_IN_TURN)
            } else {
                black_box(DIFF_NO_TURN)
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_snapshot_creation,
    bench_snapshot_copy,
    bench_inturn_calculation,
    bench_vote_casting,
    bench_valid_vote,
    bench_snapshot_serialization,
    bench_signer_lookup,
    bench_difficulty_pattern,
);

criterion_main!(benches);


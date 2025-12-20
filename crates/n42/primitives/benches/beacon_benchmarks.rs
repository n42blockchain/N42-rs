// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Beacon chain performance benchmarks
//!
//! Measures critical operations:
//! - BLS signature verification (single and batch)
//! - Public key parsing with caching
//! - Committee shuffle computation
//! - State transition operations
//! - Attestation processing

use alloy_primitives::{FixedBytes, B256};
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use n42_primitives::{beacon::AttestationData, shuffle_list::shuffle_list, Validator};
use std::collections::BTreeSet;

/// Generate a random seed for shuffling
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i * 7 + 13) as u8;
    }
    seed
}

/// Generate test validators
fn generate_validators(count: usize) -> Vec<Validator> {
    (0..count)
        .map(|i| {
            let mut pubkey = [0u8; 48];
            pubkey[0] = (i % 256) as u8;
            pubkey[1] = ((i / 256) % 256) as u8;
            Validator {
                pubkey: FixedBytes::from_slice(&pubkey),
                effective_balance: 32_000_000_000,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                ..Default::default()
            }
        })
        .collect()
}

/// Benchmark shuffle algorithm performance
fn benchmark_shuffle(c: &mut Criterion) {
    let mut group = c.benchmark_group("shuffle");
    let seed = random_seed();

    for validator_count in [100, 1000, 10000].iter() {
        let indices: Vec<usize> = (0..*validator_count).collect();

        group.throughput(Throughput::Elements(*validator_count as u64));
        group.bench_with_input(
            BenchmarkId::new("shuffle_list", validator_count),
            validator_count,
            |b, _| {
                b.iter(|| {
                    let result = shuffle_list(
                        black_box(indices.clone()),
                        black_box(10),
                        black_box(&seed),
                        black_box(false),
                    );
                    black_box(result)
                });
            },
        );
    }
    group.finish();
}

/// Benchmark public key parsing
fn benchmark_pubkey_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("pubkey_parsing");

    // Generate a valid BLS keypair
    let ikm = [0u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen failed");
    let pk = sk.sk_to_pk();
    let pk_bytes = pk.to_bytes();

    group.bench_function("parse_pubkey", |b| {
        b.iter(|| {
            let parsed = PublicKey::from_bytes(black_box(&pk_bytes));
            black_box(parsed)
        });
    });

    // Benchmark parsing multiple keys
    let keys: Vec<[u8; 48]> = (0..100)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen failed");
            sk.sk_to_pk().to_bytes()
        })
        .collect();

    group.throughput(Throughput::Elements(100));
    group.bench_function("parse_100_pubkeys", |b| {
        b.iter(|| {
            for key in &keys {
                let _ = PublicKey::from_bytes(black_box(key));
            }
        });
    });

    group.finish();
}

/// Benchmark BLS signature verification
fn benchmark_signature_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_verification");

    // Generate a valid BLS keypair and signature
    let ikm = [0u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen failed");
    let pk = sk.sk_to_pk();
    let message = b"test message for signature verification";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sig = sk.sign(message, dst, &[]);

    group.bench_function("verify_single_signature", |b| {
        b.iter(|| {
            let result = sig.verify(
                black_box(true),
                black_box(message),
                black_box(dst),
                black_box(&[]),
                black_box(&pk),
                black_box(true),
            );
            black_box(result)
        });
    });

    // Benchmark aggregate signature verification
    let num_signers = 100;
    let keypairs: Vec<(SecretKey, PublicKey)> = (0..num_signers)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen failed");
            let pk = sk.sk_to_pk();
            (sk, pk)
        })
        .collect();

    let signatures: Vec<Signature> = keypairs
        .iter()
        .map(|(sk, _)| sk.sign(message, dst, &[]))
        .collect();

    // Create aggregate signature
    let agg_sig = {
        let sig_refs: Vec<&Signature> = signatures.iter().collect();
        AggregateSignature::aggregate(&sig_refs, true).expect("aggregation failed")
    };

    let pubkeys: Vec<&PublicKey> = keypairs.iter().map(|(_, pk)| pk).collect();

    group.throughput(Throughput::Elements(num_signers as u64));
    group.bench_function("verify_aggregate_signature_100", |b| {
        b.iter(|| {
            let result = agg_sig.to_signature().fast_aggregate_verify(
                black_box(true),
                black_box(message),
                black_box(dst),
                black_box(&pubkeys),
            );
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark epoch processing simulation
fn benchmark_epoch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch_processing");

    // Simulate inactivity score updates
    for validator_count in [100, 1000].iter() {
        let scores: Vec<u64> = (0..*validator_count).map(|i| i as u64 % 100).collect();
        let active_set: BTreeSet<u64> = (0..(*validator_count as u64 / 2)).collect();

        group.throughput(Throughput::Elements(*validator_count as u64));
        group.bench_with_input(
            BenchmarkId::new("inactivity_score_update", validator_count),
            validator_count,
            |b, _| {
                b.iter(|| {
                    let mut new_scores = scores.clone();
                    for (idx, score) in new_scores.iter_mut().enumerate() {
                        if active_set.contains(&(idx as u64)) {
                            *score = score.saturating_sub(48);
                        } else if *score < 8100 {
                            *score = score.saturating_add(1);
                        }
                    }
                    black_box(new_scores)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark active validator lookup
fn benchmark_active_validator_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("validator_lookup");

    for validator_count in [100, 1000, 10000].iter() {
        let validators = generate_validators(*validator_count);
        let current_epoch = 100u64;

        group.throughput(Throughput::Elements(*validator_count as u64));
        group.bench_with_input(
            BenchmarkId::new("get_active_validators", validator_count),
            &validators,
            |b, validators| {
                b.iter(|| {
                    let active: Vec<usize> = validators
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| v.is_active_at(black_box(current_epoch)))
                        .map(|(i, _)| i)
                        .collect();
                    black_box(active)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark SSZ encoding vs JSON encoding for attestation data
fn benchmark_attestation_encoding(c: &mut Criterion) {
    use ssz::Encode;

    let mut group = c.benchmark_group("attestation_encoding");

    let attestation_data = AttestationData {
        slot: 12345,
        committee_index: 0,
        receipts_root: B256::ZERO,
    };

    group.bench_function("ssz_encode", |b| {
        b.iter(|| {
            let bytes = black_box(&attestation_data).as_ssz_bytes();
            black_box(bytes)
        });
    });

    group.bench_function("json_encode", |b| {
        b.iter(|| {
            let bytes = serde_json::to_vec(black_box(&attestation_data)).unwrap();
            black_box(bytes)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_shuffle,
    benchmark_pubkey_parsing,
    benchmark_signature_verification,
    benchmark_epoch_processing,
    benchmark_active_validator_lookup,
    benchmark_attestation_encoding,
);

criterion_main!(benches);

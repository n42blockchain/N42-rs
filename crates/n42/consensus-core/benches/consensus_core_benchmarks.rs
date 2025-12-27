// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for consensus core operations

use alloy_primitives::B256;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use n42_consensus_core::*;
use n42_primitives::{Attestation, AttestationData, BeaconBlock, BeaconState, SLOTS_PER_EPOCH};

/// Benchmark slot/epoch conversion functions
fn bench_slot_epoch_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("Slot/Epoch Conversions");

    // Slot to epoch
    for slot in [0u64, 32, 100, 1000, 100000] {
        group.bench_with_input(
            BenchmarkId::new("slot_to_epoch", slot),
            &slot,
            |b, &slot| b.iter(|| slot_to_epoch(black_box(slot))),
        );
    }

    // Epoch start slot
    for epoch in [0u64, 1, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("epoch_start_slot", epoch),
            &epoch,
            |b, &epoch| b.iter(|| epoch_start_slot(black_box(epoch))),
        );
    }

    // Is epoch boundary
    group.bench_function("is_epoch_boundary_true", |b| {
        b.iter(|| is_epoch_boundary(black_box(SLOTS_PER_EPOCH)))
    });

    group.bench_function("is_epoch_boundary_false", |b| {
        b.iter(|| is_epoch_boundary(black_box(SLOTS_PER_EPOCH + 1)))
    });

    // Slots until next epoch
    for slot in [0u64, 15, 31, 32, 100] {
        group.bench_with_input(
            BenchmarkId::new("slots_until_next_epoch", slot),
            &slot,
            |b, &slot| b.iter(|| slots_until_next_epoch(black_box(slot))),
        );
    }

    group.finish();
}

/// Benchmark validation functions
fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Validation");

    // Block validation (valid slot)
    let state = BeaconState {
        slot: 100,
        ..Default::default()
    };
    let valid_block = BeaconBlock {
        slot: 101,
        ..Default::default()
    };

    group.bench_function("validate_beacon_block_valid", |b| {
        b.iter(|| validate_beacon_block(black_box(&state), black_box(&valid_block)))
    });

    // Block validation (invalid slot)
    let invalid_block = BeaconBlock {
        slot: 100, // Same as state
        ..Default::default()
    };

    group.bench_function("validate_beacon_block_invalid", |b| {
        b.iter(|| validate_beacon_block(black_box(&state), black_box(&invalid_block)))
    });

    // Attestation validation (current epoch)
    let attestation_current = Attestation {
        data: AttestationData {
            slot: 100,
            ..Default::default()
        },
        ..Default::default()
    };

    group.bench_function("validate_attestation_current_epoch", |b| {
        b.iter(|| validate_attestation(black_box(&state), black_box(&attestation_current)))
    });

    // Parent hash validation
    let hash1 = B256::from([1u8; 32]);
    let hash2 = B256::from([2u8; 32]);

    group.bench_function("validate_parent_hash_match", |b| {
        b.iter(|| validate_parent_hash(black_box(hash1), black_box(hash1)))
    });

    group.bench_function("validate_parent_hash_mismatch", |b| {
        b.iter(|| validate_parent_hash(black_box(hash1), black_box(hash2)))
    });

    group.finish();
}

/// Benchmark error handling
fn bench_error_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Error Handling");

    // Error creation
    group.bench_function("create_invalid_slot_error", |b| {
        b.iter(|| ConsensusError::InvalidSlot {
            expected: black_box(100),
            actual: black_box(50),
        })
    });

    // Error classification
    let recoverable_err = ConsensusError::ParentStateNotFound(B256::ZERO);
    let validation_err = ConsensusError::InvalidBlock("test".to_string());

    group.bench_function("is_recoverable_true", |b| {
        b.iter(|| black_box(&recoverable_err).is_recoverable())
    });

    group.bench_function("is_validation_error_true", |b| {
        b.iter(|| black_box(&validation_err).is_validation_error())
    });

    group.finish();
}

/// Benchmark state root calculation
fn bench_state_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("State Root");

    let state = BeaconState::default();

    group.bench_function("calculate_state_root", |b| {
        b.iter(|| calculate_state_root(black_box(&state)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_slot_epoch_conversions,
    bench_validation,
    bench_error_handling,
    bench_state_root,
);

criterion_main!(benches);

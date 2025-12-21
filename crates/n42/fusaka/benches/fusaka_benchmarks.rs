// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for Fusaka hardfork operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use n42_fusaka::*;
use alloy_primitives::{Address, B256};

/// Benchmark BLS precompile address lookups
fn bench_bls_precompile_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLS Precompile Lookup");
    
    // Known BLS precompile
    let bls_addr = BLS12_G1ADD;
    group.bench_function("is_bls_precompile_true", |b| {
        b.iter(|| is_bls_precompile(black_box(&bls_addr)))
    });
    
    // Non-BLS address
    let non_bls = Address::ZERO;
    group.bench_function("is_bls_precompile_false", |b| {
        b.iter(|| is_bls_precompile(black_box(&non_bls)))
    });
    
    // Get precompile name
    group.bench_function("bls_precompile_name", |b| {
        b.iter(|| bls_precompile_name(black_box(&bls_addr)))
    });
    
    group.finish();
}

/// Benchmark input validation functions
fn bench_input_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLS Input Validation");
    
    // G1ADD validation
    let g1add_input = vec![0u8; G1_POINT_SIZE * 2];
    group.bench_function("validate_g1add_input", |b| {
        b.iter(|| validate_g1add_input(black_box(&g1add_input)))
    });
    
    // G2ADD validation
    let g2add_input = vec![0u8; G2_POINT_SIZE * 2];
    group.bench_function("validate_g2add_input", |b| {
        b.iter(|| validate_g2add_input(black_box(&g2add_input)))
    });
    
    // Pairing validation (different sizes)
    for num_pairs in [1, 2, 4, 8] {
        let pair_size = G1_POINT_SIZE + G2_POINT_SIZE;
        let input = vec![0u8; pair_size * num_pairs];
        group.bench_with_input(
            BenchmarkId::new("validate_pairing_input", num_pairs),
            &input,
            |b, input| b.iter(|| validate_pairing_input(black_box(input)))
        );
    }
    
    group.finish();
}

/// Benchmark gas calculation functions
fn bench_gas_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Gas Calculations");
    
    // G1 multiexp gas
    for num_pairs in [1, 4, 16, 64, 128] {
        group.bench_with_input(
            BenchmarkId::new("g1_multiexp_gas", num_pairs),
            &num_pairs,
            |b, &n| b.iter(|| g1_multiexp_gas(black_box(n)))
        );
    }
    
    // G2 multiexp gas
    for num_pairs in [1, 4, 16, 64, 128] {
        group.bench_with_input(
            BenchmarkId::new("g2_multiexp_gas", num_pairs),
            &num_pairs,
            |b, &n| b.iter(|| g2_multiexp_gas(black_box(n)))
        );
    }
    
    // Pairing gas
    for num_pairs in [1, 2, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::new("pairing_gas", num_pairs),
            &num_pairs,
            |b, &n| b.iter(|| pairing_gas(black_box(n)))
        );
    }
    
    group.finish();
}

/// Benchmark PeerDAS operations
fn bench_peerdas(c: &mut Criterion) {
    let mut group = c.benchmark_group("PeerDAS");
    
    // Column verification
    group.bench_function("verify_column_index_valid", |b| {
        b.iter(|| verify_column_index(black_box(64)))
    });
    
    group.bench_function("verify_column_index_invalid", |b| {
        b.iter(|| verify_column_index(black_box(200)))
    });
    
    // Cell verification
    group.bench_function("verify_cell_index_valid", |b| {
        b.iter(|| verify_cell_index(black_box(64)))
    });
    
    // Cell to columns mapping
    group.bench_function("cell_to_columns", |b| {
        b.iter(|| cell_to_columns(black_box(64)))
    });
    
    // Custody columns calculation
    let node_id = B256::from([42u8; 32]);
    for custody_count in [2, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::new("custody_columns", custody_count),
            &custody_count,
            |b, &count| b.iter(|| custody_columns(black_box(&node_id), black_box(count)))
        );
    }
    
    // Samples needed calculation
    for blob_count in [1, 3, 6, 9] {
        group.bench_with_input(
            BenchmarkId::new("samples_needed_for_availability", blob_count),
            &blob_count,
            |b, &count| b.iter(|| samples_needed_for_availability(black_box(count)))
        );
    }
    
    group.finish();
}

/// Benchmark DataColumn operations
fn bench_data_column(c: &mut Criterion) {
    let mut group = c.benchmark_group("DataColumn");
    
    // DataColumn creation
    group.bench_function("new_valid", |b| {
        b.iter(|| DataColumn::new(black_box(64)))
    });
    
    group.bench_function("new_invalid", |b| {
        b.iter(|| DataColumn::new(black_box(200)))
    });
    
    // DataColumn validation
    let column = DataColumn::new(0).unwrap();
    group.bench_function("is_valid", |b| {
        b.iter(|| black_box(&column).is_valid())
    });
    
    group.finish();
}

/// Benchmark OsakaBlobParams operations
fn bench_osaka_blob_params(c: &mut Criterion) {
    let mut group = c.benchmark_group("OsakaBlobParams");
    
    let params = OsakaBlobParams::new();
    
    group.bench_function("is_valid_blob_count", |b| {
        b.iter(|| params.is_valid_blob_count(black_box(6)))
    });
    
    group.bench_function("is_valid_tx_blob_count", |b| {
        b.iter(|| params.is_valid_tx_blob_count(black_box(4)))
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_bls_precompile_lookup,
    bench_input_validation,
    bench_gas_calculations,
    bench_peerdas,
    bench_data_column,
    bench_osaka_blob_params,
);

criterion_main!(benches);


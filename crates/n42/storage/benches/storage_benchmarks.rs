// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for storage operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use n42_storage::*;
use n42_primitives::{BeaconBlock, BeaconState};
use alloy_primitives::B256;

/// Benchmark codec operations
fn bench_codecs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Codecs");
    
    // BeaconState encoding
    let state = BeaconState::default();
    group.bench_function("encode_beacon_state", |b| {
        b.iter(|| encode_beacon_state(black_box(&state)))
    });
    
    // BeaconState decoding
    let encoded_state = encode_beacon_state(&state).unwrap();
    group.bench_function("decode_beacon_state", |b| {
        b.iter(|| decode_beacon_state(black_box(&encoded_state)))
    });
    
    // BeaconBlock encoding
    let block = BeaconBlock::default();
    group.bench_function("encode_beacon_block", |b| {
        b.iter(|| encode_beacon_block(black_box(&block)))
    });
    
    // BeaconBlock decoding
    let encoded_block = encode_beacon_block(&block).unwrap();
    group.bench_function("decode_beacon_block", |b| {
        b.iter(|| decode_beacon_block(black_box(&encoded_block)))
    });
    
    group.finish();
}

/// Benchmark error operations
fn bench_errors(c: &mut Criterion) {
    let mut group = c.benchmark_group("Errors");
    
    // Error creation
    group.bench_function("create_beacon_state_not_found", |b| {
        b.iter(|| StorageError::BeaconStateNotFound(black_box(B256::ZERO)))
    });
    
    group.bench_function("create_other_error", |b| {
        b.iter(|| StorageError::other(black_box("test error")))
    });
    
    // Error classification
    let not_found = StorageError::BeaconStateNotFound(B256::ZERO);
    let other = StorageError::other("test");
    
    group.bench_function("is_not_found_true", |b| {
        b.iter(|| black_box(&not_found).is_not_found())
    });
    
    group.bench_function("is_not_found_false", |b| {
        b.iter(|| black_box(&other).is_not_found())
    });
    
    group.finish();
}

/// Benchmark table ID operations
fn bench_table_ids(c: &mut Criterion) {
    let mut group = c.benchmark_group("Table IDs");
    
    // Get table name
    let table_id = N42TableId::BeaconState;
    group.bench_function("table_id_name", |b| {
        b.iter(|| black_box(table_id).name())
    });
    
    // Get all table IDs
    group.bench_function("table_id_all", |b| {
        b.iter(|| N42TableId::all())
    });
    
    // Display table ID
    group.bench_function("table_id_display", |b| {
        b.iter(|| format!("{}", black_box(table_id)))
    });
    
    group.finish();
}

/// Benchmark generic JSON encoding
fn bench_json_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("JSON Encoding");
    
    // Small struct
    let block = BeaconBlock::default();
    group.bench_function("encode_json_small", |b| {
        b.iter(|| encode_json(black_box(&block)))
    });
    
    // Larger struct (state has more fields)
    let state = BeaconState::default();
    group.bench_function("encode_json_large", |b| {
        b.iter(|| encode_json(black_box(&state)))
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_codecs,
    bench_errors,
    bench_table_ids,
    bench_json_encoding,
);

criterion_main!(benches);


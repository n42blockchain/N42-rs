// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPS (Transactions Per Second) Benchmarks
//!
//! This benchmark suite measures the performance of critical operations
//! that affect overall TPS in the N42 blockchain.
//!
//! ## Main Execution Path for ETH Transfer:
//!
//! ```text
//! 1. TX Signing (secp256k1)     ~50-200μs
//!    └── ECDSA signature generation
//!
//! 2. TX Verification            ~100-300μs
//!    ├── Signature recovery (ecrecover)
//!    └── Address derivation
//!
//! 3. Consensus Validation       ~10-50μs
//!    ├── Header validation
//!    ├── Difficulty check
//!    └── Timestamp check
//!
//! 4. State Access               ~1-10μs (cached) / ~100μs+ (DB)
//!    ├── Sender account lookup
//!    ├── Receiver account lookup
//!    └── Nonce validation
//!
//! 5. EVM Execution              ~20-50μs (simple transfer)
//!    ├── Gas calculation (21000 gas)
//!    ├── Balance deduction
//!    └── Balance addition
//!
//! 6. State Commit               ~50-500μs
//!    ├── Account state update
//!    └── State root calculation
//! ```
//!
//! ## Bottleneck Analysis:
//!
//! | Component | Time (μs) | CPU/IO | Optimization |
//! |-----------|-----------|--------|--------------|
//! | Signing | 50-200 | CPU | Pre-sign/batch |
//! | Verification | 100-300 | CPU | Parallel ecrecover |
//! | State Access | 1-100+ | IO | Cache increase |
//! | EVM Execution | 20-50 | CPU | Already fast |
//! | State Commit | 50-500 | IO/CPU | Lazy root, batch |

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use alloy_primitives::{Address, B256, U256};
use n42_clique::{DIFF_IN_TURN, DIFF_NO_TURN};
use n42_primitives::{APosConfig, Snapshot};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ==================== Transaction Simulation ====================

/// Simulated transaction for benchmarking
#[derive(Clone)]
struct SimulatedTx {
    from: Address,
    to: Address,
    value: U256,
    nonce: u64,
    gas_limit: u64,
    gas_price: U256,
}

impl SimulatedTx {
    fn new(from: Address, to: Address, value: U256, nonce: u64) -> Self {
        Self {
            from,
            to,
            value,
            nonce,
            gas_limit: 21_000,                       // Standard ETH transfer
            gas_price: U256::from(1_000_000_000u64), // 1 Gwei
        }
    }
}

/// Simulated account state
#[derive(Clone)]
struct AccountState {
    balance: U256,
    nonce: u64,
}

/// Simulated state database
struct SimulatedState {
    accounts: HashMap<Address, AccountState>,
}

impl SimulatedState {
    fn new(accounts: Vec<(Address, U256)>) -> Self {
        let accounts = accounts
            .into_iter()
            .map(|(addr, balance)| (addr, AccountState { balance, nonce: 0 }))
            .collect();
        Self { accounts }
    }

    fn get_account(&self, addr: &Address) -> Option<&AccountState> {
        self.accounts.get(addr)
    }

    fn get_account_mut(&mut self, addr: &Address) -> Option<&mut AccountState> {
        self.accounts.get_mut(addr)
    }

    fn execute_transfer(&mut self, tx: &SimulatedTx) -> Result<u64, &'static str> {
        // Check sender exists and has enough balance
        let sender = self.accounts.get_mut(&tx.from).ok_or("sender not found")?;

        let total_cost = tx.value + U256::from(tx.gas_limit) * tx.gas_price;
        if sender.balance < total_cost {
            return Err("insufficient balance");
        }
        if sender.nonce != tx.nonce {
            return Err("invalid nonce");
        }

        // Deduct from sender
        sender.balance -= total_cost;
        sender.nonce += 1;

        // Add to receiver
        if let Some(receiver) = self.accounts.get_mut(&tx.to) {
            receiver.balance += tx.value;
        } else {
            // Create new account
            self.accounts.insert(
                tx.to,
                AccountState {
                    balance: tx.value,
                    nonce: 0,
                },
            );
        }

        Ok(tx.gas_limit) // Return gas used
    }
}

// ==================== Helper Functions ====================

/// Generate test addresses
fn generate_addresses(count: usize) -> Vec<Address> {
    (0..count)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[0] = (i >> 16) as u8;
            bytes[1] = (i >> 8) as u8;
            bytes[2] = i as u8;
            Address::from_slice(&bytes)
        })
        .collect()
}

/// Generate test transactions
fn generate_transactions(
    senders: &[Address],
    receivers: &[Address],
    txs_per_sender: usize,
) -> Vec<SimulatedTx> {
    let mut txs = Vec::with_capacity(senders.len() * txs_per_sender);

    for (sender_idx, sender) in senders.iter().enumerate() {
        for tx_idx in 0..txs_per_sender {
            let receiver = receivers[(sender_idx + tx_idx) % receivers.len()];
            txs.push(SimulatedTx::new(
                *sender,
                receiver,
                U256::from(1_000_000_000_000_000u64), // 0.001 ETH
                tx_idx as u64,
            ));
        }
    }

    txs
}

// ==================== Benchmarks ====================

/// Benchmark: State lookup performance (critical for TPS)
fn bench_state_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_lookup");

    for num_accounts in [100, 1000, 10000, 100000].iter() {
        let addresses = generate_addresses(*num_accounts);
        let accounts: Vec<(Address, U256)> = addresses
            .iter()
            .map(|a| (*a, U256::from(1_000_000_000_000_000_000u128)))
            .collect();

        let state = SimulatedState::new(accounts);
        let lookup_addr = addresses[*num_accounts / 2]; // Middle element

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("hashmap_get", num_accounts),
            &(&state, lookup_addr),
            |b, (state, addr)| {
                b.iter(|| black_box(state.get_account(addr)));
            },
        );
    }

    group.finish();
}

/// Benchmark: Single transfer execution
fn bench_single_transfer(c: &mut Criterion) {
    let sender = Address::from_slice(&[0x01; 20]);
    let receiver = Address::from_slice(&[0x02; 20]);

    let accounts = vec![
        (sender, U256::from(1_000_000_000_000_000_000_000u128)), // 1000 ETH
        (receiver, U256::ZERO),
    ];

    let tx = SimulatedTx::new(
        sender,
        receiver,
        U256::from(1_000_000_000_000_000u64), // 0.001 ETH
        0,
    );

    let mut group = c.benchmark_group("single_transfer");
    group.throughput(Throughput::Elements(1));

    group.bench_function("execute", |b| {
        b.iter_batched(
            || SimulatedState::new(accounts.clone()),
            |mut state| {
                let result = state.execute_transfer(&tx);
                black_box(result)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark: Batch transfer execution (TPS measurement)
fn bench_batch_transfers(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_transfers");

    for batch_size in [10, 100, 500, 1000, 5000].iter() {
        let num_senders = (*batch_size / 10).max(10);
        let num_receivers = (*batch_size / 10).max(10);

        let senders = generate_addresses(num_senders);
        let receivers = generate_addresses(num_receivers);

        let accounts: Vec<(Address, U256)> = senders
            .iter()
            .chain(receivers.iter())
            .map(|a| (*a, U256::from(1_000_000_000_000_000_000_000u128)))
            .collect();

        let txs_per_sender = *batch_size / num_senders;
        let txs = generate_transactions(&senders, &receivers, txs_per_sender);

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("execute", batch_size),
            &(accounts.clone(), txs.clone()),
            |b, (accounts, txs)| {
                b.iter_batched(
                    || SimulatedState::new(accounts.clone()),
                    |mut state| {
                        let mut total_gas = 0u64;
                        for tx in txs {
                            if let Ok(gas) = state.execute_transfer(tx) {
                                total_gas += gas;
                            }
                        }
                        black_box(total_gas)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark: Consensus validation overhead
fn bench_consensus_validation(c: &mut Criterion) {
    let config = APosConfig::default();
    let signers: Vec<Address> = generate_addresses(21);

    let snap = Snapshot::new_snapshot(config, 1000, B256::ZERO, signers.clone());

    let mut group = c.benchmark_group("consensus_validation");

    // Inturn check (called for every block)
    group.throughput(Throughput::Elements(1));
    group.bench_function("inturn_check", |b| {
        let signer = signers[0];
        b.iter(|| black_box(snap.inturn(1001, &signer)));
    });

    // Difficulty calculation
    group.bench_function("difficulty_select", |b| {
        b.iter(|| {
            let is_inturn = true;
            if is_inturn {
                black_box(DIFF_IN_TURN)
            } else {
                black_box(DIFF_NO_TURN)
            }
        });
    });

    // Vote validation
    group.bench_function("valid_vote_check", |b| {
        let new_addr = Address::from_slice(&[0xFF; 20]);
        b.iter(|| black_box(snap.valid_vote(new_addr, true)));
    });

    group.finish();
}

/// Benchmark: Memory copy overhead (state cloning)
fn bench_state_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_copy");

    for num_accounts in [100, 1000, 10000].iter() {
        let addresses = generate_addresses(*num_accounts);
        let accounts: Vec<(Address, U256)> = addresses
            .iter()
            .map(|a| (*a, U256::from(1_000_000_000_000_000_000u128)))
            .collect();

        let state = SimulatedState::new(accounts);

        group.throughput(Throughput::Elements(*num_accounts as u64));
        group.bench_with_input(
            BenchmarkId::new("clone", num_accounts),
            &state,
            |b, state| {
                b.iter(|| black_box(state.accounts.clone()));
            },
        );
    }

    group.finish();
}

/// Benchmark: TPS measurement with timing
fn bench_tps_measurement(c: &mut Criterion) {
    let mut group = c.benchmark_group("tps_measurement");
    group.sample_size(10);

    // Large batch for TPS measurement
    let num_senders = 100;
    let num_receivers = 100;
    let txs_per_sender = 100;
    let total_txs = num_senders * txs_per_sender;

    let senders = generate_addresses(num_senders);
    let receivers = generate_addresses(num_receivers);

    let accounts: Vec<(Address, U256)> = senders
        .iter()
        .chain(receivers.iter())
        .map(|a| (*a, U256::from(u128::MAX)))
        .collect();

    let txs = generate_transactions(&senders, &receivers, txs_per_sender);

    group.throughput(Throughput::Elements(total_txs as u64));
    group.bench_function("10000_transfers", |b| {
        b.iter_custom(|iters| {
            let mut total_time = Duration::ZERO;

            for _ in 0..iters {
                let mut state = SimulatedState::new(accounts.clone());

                let start = Instant::now();
                for tx in &txs {
                    let _ = state.execute_transfer(tx);
                }
                total_time += start.elapsed();
            }

            total_time
        });
    });

    group.finish();
}

/// Print TPS analysis
fn print_tps_analysis() {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              TPS BOTTLENECK ANALYSIS & OPTIMIZATION               ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                   ║");
    println!("║  MAIN EXECUTION PATH (ETH Transfer):                              ║");
    println!("║  ─────────────────────────────────────                            ║");
    println!("║  1. Signature Verification   ~100-300μs  ← CPU bound              ║");
    println!("║  2. State Lookup             ~1-100μs    ← Cache critical         ║");
    println!("║  3. Balance Validation       ~1μs        ← Fast                   ║");
    println!("║  4. Balance Update           ~1μs        ← Fast                   ║");
    println!("║  5. State Commit             ~50-500μs   ← IO bound               ║");
    println!("║                                                                   ║");
    println!("║  BOTTLENECKS IDENTIFIED:                                          ║");
    println!("║  ─────────────────────                                            ║");
    println!("║  ⚠ Signature verification: Use parallel ecrecover                 ║");
    println!("║  ⚠ State access: Increase cache sizes (DONE ✓)                    ║");
    println!("║  ⚠ State commit: Batch updates, lazy root calculation             ║");
    println!("║  ⚠ Memory copy: Use copy-on-write / arc-based sharing             ║");
    println!("║                                                                   ║");
    println!("║  OPTIMIZATIONS IMPLEMENTED:                                       ║");
    println!("║  ─────────────────────────                                        ║");
    println!("║  ✓ INMEMORY_SNAPSHOTS: 128 → 512 (4x)                              ║");
    println!("║  ✓ INMEMORY_TDS: 1024 → 4096 (4x)                                  ║");
    println!("║  ✓ INMEMORY_CACHED_READS: 32 → 128 (4x)                            ║");
    println!("║  ✓ Network budget: 2x throughput                                  ║");
    println!("║                                                                   ║");
    println!("║  RECOMMENDED NEXT STEPS:                                          ║");
    println!("║  ────────────────────────                                         ║");
    println!("║  1. Parallel signature verification (rayon)                       ║");
    println!("║  2. Replace std::sync::RwLock with parking_lot                    ║");
    println!("║  3. Batch state root calculation                                  ║");
    println!("║  4. Pre-warm state cache for pending txs                          ║");
    println!("║                                                                   ║");
    println!("║  THEORETICAL MAX TPS (simple transfer):                           ║");
    println!("║  ─────────────────────────────────────                            ║");
    println!("║  • Single-threaded: ~3,000-5,000 TPS                              ║");
    println!("║  • With parallel sig verify: ~10,000-15,000 TPS                   ║");
    println!("║  • With state sharding: ~50,000+ TPS                              ║");
    println!("║                                                                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!("\n");
}

criterion_group!(
    benches,
    bench_state_lookup,
    bench_single_transfer,
    bench_batch_transfers,
    bench_consensus_validation,
    bench_state_copy,
    bench_tps_measurement,
);

criterion_main!(benches);

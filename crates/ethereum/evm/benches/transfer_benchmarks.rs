// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPS Benchmarks for Native Token Transfers
//!
//! This benchmark suite measures the performance of ETH transfers to identify
//! bottlenecks and optimization opportunities.
//!
//! ## Main Execution Path Analysis:
//!
//! 1. **Transaction Signing** (secp256k1 ECDSA)
//!    - Private key operation
//!    - Signature generation
//!
//! 2. **Transaction Verification**
//!    - Signature recovery (ecrecover)
//!    - Address derivation
//!    - Nonce validation
//!
//! 3. **State Access**
//!    - Account lookup (sender/receiver)
//!    - Balance read
//!    - Nonce read
//!
//! 4. **EVM Execution**
//!    - Gas calculation (21000 for simple transfer)
//!    - Balance update (subtract from sender)
//!    - Balance update (add to receiver)
//!
//! 5. **State Commit**
//!    - Account state update
//!    - State root calculation (Merkle Patricia Trie)
//!
//! ## Key Bottlenecks:
//!
//! - **Cryptography**: Signature verification is CPU-bound
//! - **State Access**: Database I/O for account lookups
//! - **Memory Copy**: State transitions involve data copying
//! - **State Root**: Trie updates are expensive

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use alloy_consensus::{constants::ETH_TO_WEI, TxLegacy};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use rand::Rng;
use reth_chainspec::{ChainSpec, ChainSpecBuilder, MAINNET};
use reth_ethereum_primitives::{Block, BlockBody, Transaction, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{crypto::secp256k1::public_key_to_address, RecoveredBlock};
use reth_testing_utils::generators::sign_tx_with_key_pair;
use revm::{
    database::CacheDB,
    primitives::address,
    state::{AccountInfo, EvmState},
    Database, EmptyDB,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::sync::Arc;
use std::time::Instant;

/// Gas cost for a simple ETH transfer
const TRANSFER_GAS: u64 = 21_000;

/// Initial balance for test accounts (1000 ETH)
const INITIAL_BALANCE: u128 = 1000 * ETH_TO_WEI;

/// Transfer amount (0.001 ETH)
const TRANSFER_AMOUNT: u128 = ETH_TO_WEI / 1000;

/// Generate a key pair for testing
fn generate_key_pair() -> (SecretKey, PublicKey, Address) {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let secret_key = SecretKey::new(&mut rng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = public_key_to_address(public_key);
    (secret_key, public_key, address)
}

/// Create a database with pre-funded accounts
fn create_database_with_accounts(accounts: &[(Address, U256)]) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());

    for (address, balance) in accounts {
        let account_info = AccountInfo {
            balance: *balance,
            nonce: 0,
            code_hash: B256::ZERO,
            code: None,
        };
        db.insert_account_info(*address, account_info);
    }

    db
}

/// Create a simple ETH transfer transaction
fn create_transfer_tx(
    secret_key: &SecretKey,
    chain_id: u64,
    nonce: u64,
    to: Address,
    value: U256,
    gas_price: u128,
) -> TransactionSigned {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price,
        gas_limit: TRANSFER_GAS,
        to: TxKind::Call(to),
        value,
        input: Bytes::default(),
    };

    let tx = Transaction::Legacy(tx);
    sign_tx_with_key_pair(*secret_key, tx)
}

/// Benchmark: Transaction signature generation
fn bench_tx_signing(c: &mut Criterion) {
    let (secret_key, _, _) = generate_key_pair();
    let (_, _, receiver) = generate_key_pair();

    let mut group = c.benchmark_group("tx_signing");
    group.throughput(Throughput::Elements(1));

    group.bench_function("legacy_transfer", |b| {
        let mut nonce = 0u64;
        b.iter(|| {
            let tx = create_transfer_tx(
                &secret_key,
                1,
                nonce,
                receiver,
                U256::from(TRANSFER_AMOUNT),
                1_000_000_000, // 1 gwei
            );
            nonce += 1;
            black_box(tx)
        });
    });

    group.finish();
}

/// Benchmark: Transaction signature verification (ecrecover)
fn bench_tx_verification(c: &mut Criterion) {
    let (secret_key, _, sender) = generate_key_pair();
    let (_, _, receiver) = generate_key_pair();

    // Pre-generate transactions
    let txs: Vec<TransactionSigned> = (0..1000)
        .map(|nonce| {
            create_transfer_tx(
                &secret_key,
                1,
                nonce,
                receiver,
                U256::from(TRANSFER_AMOUNT),
                1_000_000_000,
            )
        })
        .collect();

    let mut group = c.benchmark_group("tx_verification");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ecrecover", |b| {
        let mut idx = 0;
        b.iter(|| {
            let tx = &txs[idx % txs.len()];
            let recovered = tx.recover_signer();
            idx += 1;
            black_box(recovered)
        });
    });

    // Batch verification
    group.throughput(Throughput::Elements(100));
    group.bench_function("ecrecover_batch_100", |b| {
        b.iter(|| {
            let results: Vec<_> = txs[..100].iter().map(|tx| tx.recover_signer()).collect();
            black_box(results)
        });
    });

    group.finish();
}

/// Benchmark: Simple state access (account lookup)
fn bench_state_access(c: &mut Criterion) {
    let (_, _, sender) = generate_key_pair();
    let (_, _, receiver) = generate_key_pair();

    let accounts = vec![
        (sender, U256::from(INITIAL_BALANCE)),
        (receiver, U256::from(INITIAL_BALANCE)),
    ];

    let db = create_database_with_accounts(&accounts);

    let mut group = c.benchmark_group("state_access");
    group.throughput(Throughput::Elements(1));

    // Single account lookup
    group.bench_function("account_lookup", |b| {
        b.iter(|| {
            let account = db.basic_ref(sender).unwrap();
            black_box(account)
        });
    });

    // Balance check
    group.bench_function("balance_check", |b| {
        b.iter(|| {
            let account = db.basic_ref(sender).unwrap().unwrap();
            black_box(account.balance)
        });
    });

    group.finish();
}

/// Benchmark: Full EVM execution for ETH transfers
fn bench_evm_execution(c: &mut Criterion) {
    let (secret_key, _, sender) = generate_key_pair();
    let (_, _, receiver) = generate_key_pair();

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .build(),
    );

    let mut group = c.benchmark_group("evm_execution");

    // Single transfer execution
    for num_txs in [1, 10, 50, 100, 500].iter() {
        // Create fresh database for each benchmark
        let accounts = vec![
            (sender, U256::from(INITIAL_BALANCE)),
            (receiver, U256::ZERO),
        ];

        // Pre-generate transactions
        let transactions: Vec<TransactionSigned> = (0..*num_txs as u64)
            .map(|nonce| {
                create_transfer_tx(
                    &secret_key,
                    chain_spec.chain().id(),
                    nonce,
                    receiver,
                    U256::from(TRANSFER_AMOUNT),
                    1_000_000_000,
                )
            })
            .collect();

        let recovered_txs: Vec<_> = transactions
            .iter()
            .filter_map(|tx| tx.clone().try_into_recovered().ok())
            .collect();

        group.throughput(Throughput::Elements(*num_txs as u64));
        group.bench_with_input(
            BenchmarkId::new("transfers", num_txs),
            &(chain_spec.clone(), accounts.clone(), recovered_txs),
            |b, (chain_spec, accounts, txs)| {
                b.iter_batched(
                    || {
                        // Setup fresh state for each iteration
                        let db = create_database_with_accounts(accounts);
                        let provider = EthEvmConfig::new(chain_spec.clone());
                        let executor = provider.batch_executor(db);
                        (executor, txs.clone())
                    },
                    |(mut executor, txs)| {
                        // Create a block with all transactions
                        let header = alloy_consensus::Header {
                            number: 1,
                            gas_limit: TRANSFER_GAS * txs.len() as u64,
                            timestamp: 1,
                            ..Default::default()
                        };

                        let block = Block {
                            header,
                            body: BlockBody {
                                transactions: txs.iter().map(|tx| tx.tx().clone()).collect(),
                                ommers: vec![],
                                withdrawals: Some(vec![].into()),
                            },
                        };

                        let recovered_block = RecoveredBlock::new_unhashed(
                            block,
                            txs.iter().map(|tx| tx.signer()).collect(),
                        );

                        let result = executor.execute_one(&recovered_block);
                        black_box(result)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark: State updates (balance changes)
fn bench_state_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_updates");

    // Generate multiple accounts
    let num_accounts = 1000;
    let accounts: Vec<(Address, U256)> = (0..num_accounts)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[0] = (i >> 8) as u8;
            bytes[1] = i as u8;
            (Address::from_slice(&bytes), U256::from(INITIAL_BALANCE))
        })
        .collect();

    for batch_size in [10, 50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("balance_updates", batch_size),
            &(accounts.clone(), *batch_size),
            |b, (accounts, batch_size)| {
                b.iter_batched(
                    || create_database_with_accounts(accounts),
                    |mut db| {
                        // Simulate balance updates for batch_size accounts
                        for i in 0..*batch_size {
                            let (addr, _) = &accounts[i];

                            // Read current state
                            let mut account = db.basic_ref(*addr).unwrap().unwrap().clone();

                            // Update balance
                            account.balance = account.balance.saturating_sub(U256::from(TRANSFER_AMOUNT));
                            account.nonce += 1;

                            // Write back
                            db.insert_account_info(*addr, account);
                        }
                        black_box(db)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark: Memory copy operations (state cloning)
fn bench_memory_operations(c: &mut Criterion) {
    let num_accounts = 1000;
    let accounts: Vec<(Address, U256)> = (0..num_accounts)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[0] = (i >> 8) as u8;
            bytes[1] = i as u8;
            (Address::from_slice(&bytes), U256::from(INITIAL_BALANCE))
        })
        .collect();

    let db = create_database_with_accounts(&accounts);

    let mut group = c.benchmark_group("memory_operations");

    // Clone small state
    group.bench_function("state_clone_1000_accounts", |b| {
        b.iter(|| black_box(db.clone()));
    });

    // U256 operations (common in balance calculations)
    let balance = U256::from(INITIAL_BALANCE);
    let amount = U256::from(TRANSFER_AMOUNT);

    group.bench_function("u256_subtraction", |b| {
        b.iter(|| black_box(balance.saturating_sub(amount)));
    });

    group.bench_function("u256_addition", |b| {
        b.iter(|| black_box(balance + amount));
    });

    // Address operations
    let addr = Address::from_slice(&[0x42; 20]);
    group.bench_function("address_hash", |b| {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            addr.hash(&mut hasher);
            black_box(hasher.finish())
        });
    });

    group.finish();
}

/// Benchmark: End-to-end TPS measurement
fn bench_tps_measurement(c: &mut Criterion) {
    let (secret_key, _, sender) = generate_key_pair();
    let (_, _, receiver) = generate_key_pair();

    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*MAINNET)
            .shanghai_activated()
            .build(),
    );

    // Pre-generate many transactions
    let num_txs = 1000;
    let transactions: Vec<TransactionSigned> = (0..num_txs as u64)
        .map(|nonce| {
            create_transfer_tx(
                &secret_key,
                chain_spec.chain().id(),
                nonce,
                receiver,
                U256::from(TRANSFER_AMOUNT),
                1_000_000_000,
            )
        })
        .collect();

    let recovered_txs: Vec<_> = transactions
        .iter()
        .filter_map(|tx| tx.clone().try_into_recovered().ok())
        .collect();

    let mut group = c.benchmark_group("tps_measurement");
    group.sample_size(10); // Reduce sample size for large batches

    // Measure actual TPS
    group.throughput(Throughput::Elements(num_txs as u64));
    group.bench_function("end_to_end_1000_transfers", |b| {
        let accounts = vec![
            (sender, U256::from(u128::MAX)), // Very large balance
            (receiver, U256::ZERO),
        ];

        b.iter_custom(|iters| {
            let mut total_time = std::time::Duration::ZERO;

            for _ in 0..iters {
                // Fresh state
                let db = create_database_with_accounts(&accounts);
                let provider = EthEvmConfig::new(chain_spec.clone());
                let mut executor = provider.batch_executor(db);

                let header = alloy_consensus::Header {
                    number: 1,
                    gas_limit: TRANSFER_GAS * num_txs as u64,
                    timestamp: 1,
                    ..Default::default()
                };

                let block = Block {
                    header,
                    body: BlockBody {
                        transactions: recovered_txs.iter().map(|tx| tx.tx().clone()).collect(),
                        ommers: vec![],
                        withdrawals: Some(vec![].into()),
                    },
                };

                let recovered_block = RecoveredBlock::new_unhashed(
                    block,
                    recovered_txs.iter().map(|tx| tx.signer()).collect(),
                );

                let start = Instant::now();
                let _ = executor.execute_one(&recovered_block);
                total_time += start.elapsed();
            }

            total_time
        });
    });

    group.finish();
}

/// Print analysis of bottlenecks
fn analyze_bottlenecks() {
    println!("\n=== TPS Bottleneck Analysis ===\n");
    println!("1. SIGNATURE VERIFICATION (ecrecover)");
    println!("   - CPU-bound operation");
    println!("   - ~100-300μs per signature");
    println!("   - Can be parallelized with rayon\n");

    println!("2. STATE ACCESS");
    println!("   - Database I/O for account lookups");
    println!("   - Cache hit rate is critical");
    println!("   - Consider: Increase in-memory cache size\n");

    println!("3. MEMORY OPERATIONS");
    println!("   - State cloning for each block");
    println!("   - U256 arithmetic (relatively fast)");
    println!("   - Consider: Copy-on-write patterns\n");

    println!("4. STATE ROOT CALCULATION");
    println!("   - Merkle Patricia Trie updates");
    println!("   - Most expensive operation post-execution");
    println!("   - Consider: Lazy state root calculation\n");

    println!("5. OPTIMIZATION RECOMMENDATIONS:");
    println!("   - Parallel signature verification");
    println!("   - Batch state updates");
    println!("   - Increase cache sizes (already done in apos.rs)");
    println!("   - Use parking_lot::RwLock instead of std::sync::RwLock");
    println!("   - Consider state sharding for parallel execution\n");
}

criterion_group!(
    benches,
    bench_tx_signing,
    bench_tx_verification,
    bench_state_access,
    bench_evm_execution,
    bench_state_updates,
    bench_memory_operations,
    bench_tps_measurement,
);

criterion_main!(benches);


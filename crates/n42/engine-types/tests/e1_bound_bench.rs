// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! What bounds the E=1 leader's execution (`docs/SHARED_EXECUTION_SCOPE.md`
//! section 13): one block of the replay set's shape -- 200,000 pooled 0x50
//! transfers, 400 sender runs of 500, recipients drawn from 2,000,000 --
//! executed by the builder's own `execute_for_build` with the leader's batch
//! partition, its `convert`, and every batch handed to the output shards in
//! index mode (16 shards, the live index), as `N42_OUTPUT_SHARDS=16
//! N42_OUTPUT_INDEX=1 N42_OUTPUT_INDEX_LIVE=1` runs it. The parent's state is
//! the leader's read stack: the last three blocks' frozen output shards
//! (`N42_LEADER_LAYERS=3`, newest first), then a QMDB read view over an entry
//! file of every account. The engine's in-memory blocks between the two are
//! not modelled (the overlay filter skips most of them).
//!
//! Ignored; the thread count is the pool's (`N42_PARALLEL_BUILD_THREADS`), so
//! a sweep is one run per count:
//!
//! ```text
//! N42_PARALLEL_BUILD_THREADS=32 cargo test --release -p n42-engine-types \
//!   --test e1_bound_bench -- --ignored --nocapture
//! ```
//!
//! `E1_ROUNDS` (default 8) measured rounds over `E1_BLOCKS` (default 4)
//! distinct blocks, alternating the default two-wave dispatch and
//! `N42_BUILD_ONE_WAVE`'s one wave; `E1_WAVE=two|one` keeps one of them.
//! `E1_PERF_CTL` / `E1_PERF_ACK` name the control and ack FIFOs of a
//! `perf stat --control fifo:<ctl>,<ack> -D -1`: the counters are enabled
//! around the measured rounds only (not the set-up).
#![allow(missing_docs, unreachable_pub, unused_crate_dependencies)]

use std::io::{BufRead as _, Write as _};
use std::sync::Arc;
use std::time::Instant;

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, B256, U256};
use n42_engine_types::fast_transfer::N42EvmFactory;
use n42_engine_types::n42_evm::N42EvmConfig;
use n42_engine_types::output_shards::{FrozenShards, OutputShards};
use n42_engine_types::parallel_transfer::{build_pool, execute_for_build_dispatch, BatchSpans};
use n42_engine_types::N42PooledTransaction;
use n42_tx_types::{AltSigTx, N42TxEnvelope, TxAltSig, ALG_ED25519};
use reth_chainspec::MAINNET;
use reth_evm::ConfigureEvm as _;
use reth_primitives_traits::Recovered;
use reth_transaction_pool::{
    identifier::{SenderId, TransactionId},
    PoolTransaction as _, TransactionOrigin, ValidPoolTransaction,
};
use revm::database::BundleState;
use revm::state::AccountInfo;
use revm::Database;

/// The node's allocator: run with the fleet's `MALLOC_CONF` to see its pages.
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const TOTAL_SENDERS: u64 = 12_500;
const RECIPIENTS: u64 = 2_000_000;
const BLOCK_SENDERS: u64 = 400;
const RUN: u64 = 500;
const LAYERS: usize = 3;

fn env_or(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// Addresses spread over the key space as the fleet's are (the output shards
/// split by the top bits).
fn spread(i: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    a[12..].copy_from_slice(&i.to_be_bytes());
    Address::from(a)
}

fn beneficiary() -> Address {
    spread(1)
}

fn sender_of(s: u64) -> Address {
    spread(100 + s)
}

fn recipient_of(r: u64) -> Address {
    spread(1_000_000 + r)
}

/// The leader's read stack: the newest kept layer first, then the engine's
/// in-memory blocks behind their address filters (newest first, as
/// `MemoryOverlayStateProviderRef::basic_account` walks them), then the view.
#[derive(Debug)]
struct Stack {
    layers: Vec<Arc<FrozenShards>>,
    memory: Vec<(reth_provider::providers::overlay_filter::BlockFilter, BundleState)>,
    view: Arc<n42_qmdb_reth::QmdbReadView>,
    head: u64,
}

/// `E1_MEM_BLOCKS` (default 10) in-memory blocks of ~190,000 accounts each,
/// with their filters.
fn memory_blocks() -> Vec<(reth_provider::providers::overlay_filter::BlockFilter, BundleState)> {
    (0..env_or("E1_MEM_BLOCKS", 10) as u64)
        .map(|k| {
            // Senders 4,000 and up: none of the executed blocks' (their nonces would
            // refuse the transfers).
            let bundle = BundleState { state: block_accounts(10 + k).into_iter().collect(), ..Default::default() };
            let output = reth_execution_types::BlockExecutionOutput::<reth_ethereum_primitives::Receipt> {
                state: bundle,
                result: reth_execution_types::BlockExecutionResult {
                    receipts: Vec::new(),
                    requests: Default::default(),
                    gas_used: 0,
                    blob_gas_used: 0,
                },
            };
            (reth_provider::providers::overlay_filter::BlockFilter::build(&output), output.state)
        })
        .collect()
}

/// One batch's view of the stack, as the builder opens one a batch.
#[derive(Debug, Clone)]
struct StackDb(Arc<Stack>);

impl Database for StackDb {
    type Error = std::convert::Infallible;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        for layer in &self.0.layers {
            if let Some(account) = layer.get(&address) {
                // `ShardLayer::basic_account` as `StateProviderDatabase`
                // hands it on: no code loaded.
                return Ok(account.info.as_ref().map(|info| AccountInfo { code: None, ..info.clone() }));
            }
        }
        let key = reth_provider::providers::overlay_filter::FilterKey::address(&address);
        for (filter, bundle) in &self.0.memory {
            if !filter.may_hold_account(key) {
                continue;
            }
            if let Some(account) = bundle.account(&address) {
                return Ok(account.info.as_ref().map(|info| AccountInfo { code: None, ..info.clone() }));
            }
        }
        Ok(self.0.view.account(&address, self.0.head).flatten().map(AccountInfo::from))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<revm::state::Bytecode, Self::Error> {
        Ok(revm::state::Bytecode::default())
    }

    fn storage(&mut self, _address: Address, _index: revm::primitives::StorageKey) -> Result<revm::primitives::StorageValue, Self::Error> {
        Ok(U256::ZERO)
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

/// The entry file and its read view: the beneficiary, every sender, every
/// recipient.
fn view(dir: &std::path::Path) -> Arc<n42_qmdb_reth::QmdbReadView> {
    use n42_twig_core::qmdb_compat::{encode_gov5_account_value, gov5_account_key, GOV5_EMPTY_CODE_HASH};
    let path = dir.join("entries.log");
    let mut live = Vec::with_capacity((TOTAL_SENDERS + RECIPIENTS + 1) as usize);
    let mut out = std::io::BufWriter::new(std::fs::File::create(&path).expect("the entry file"));
    let mut offset = 0u64;
    let mut put = |address: Address, nonce: u64, balance: U256| {
        let key = gov5_account_key(&address.0 .0);
        let value = encode_gov5_account_value(nonce, &balance.to_be_bytes::<32>(), &GOV5_EMPTY_CODE_HASH);
        out.write_all(&key).expect("write");
        out.write_all(&(value.len() as u32).to_le_bytes()).expect("write");
        out.write_all(&value).expect("write");
        live.push((key, offset));
        offset += 36 + value.len() as u64;
    };
    put(beneficiary(), 0, U256::from(7));
    for s in 0..TOTAL_SENDERS {
        put(sender_of(s), 0, U256::from(10u128.pow(24)));
    }
    for r in 0..RECIPIENTS {
        put(recipient_of(r), r % 3, U256::from(1 + r));
    }
    out.flush().expect("flush");
    drop(out);
    let mut sorted = live.clone();
    sorted.sort_unstable_by_key(|(key, _)| *key);
    let view = n42_qmdb_reth::QmdbReadView::build(&path, (1, B256::ZERO), live).expect("the read view");
    // `E1_JOURNALS` (default 0): the view advanced that many blocks past the
    // version the batches read at (1), each block a journal of ~190,000
    // keys, as when the database's readers stand behind the view during a
    // persistence batch. The changes re-point each key at its own record, so
    // every answer is unchanged; only the walk differs.
    for k in 0..env_or("E1_JOURNALS", 0) as u64 {
        let mut changes: Vec<([u8; 32], Option<u64>)> = block_accounts(100 + k)
            .into_iter()
            .filter_map(|(address, _)| {
                let key = gov5_account_key(&address.0 .0);
                sorted.binary_search_by_key(&key, |(k, _)| *k).ok().map(|at| (key, Some(sorted[at].1)))
            })
            .collect();
        changes.sort_unstable_by_key(|(key, _)| *key);
        let raised = view.raise_floor(&changes);
        view.advance(2 + k, B256::from(U256::from(2 + k)), &changes, raised);
    }
    view
}

type Cand = Arc<ValidPoolTransaction<N42PooledTransaction>>;

/// Block `b`: senders `b * 400 ..` (fresh nonces: no two blocks share one),
/// each a contiguous run of 500 0x50 transfers to random recipients.
fn block(b: u64) -> Vec<Cand> {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ b.wrapping_mul(0x2545_f491_4f6c_dd1d);
    let mut cands = Vec::with_capacity((BLOCK_SENDERS * RUN) as usize);
    for s in b * BLOCK_SENDERS..(b + 1) * BLOCK_SENDERS {
        let mut pubkey = [0u8; 32];
        pubkey[..8].copy_from_slice(&s.to_be_bytes());
        for k in 0..RUN {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let tx = TxAltSig {
                chain_id: 1,
                nonce: k,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 10_000_000_000,
                gas_limit: 21_000,
                to: recipient_of(seed % RECIPIENTS),
                value: U256::from(1_000 + k),
                input: Bytes::new(),
                access_list: Default::default(),
                alg_type: ALG_ED25519,
                pubkey: Bytes::copy_from_slice(&pubkey),
            };
            let mut signature = [0u8; 64];
            signature[..8].copy_from_slice(&seed.to_be_bytes());
            let envelope = N42TxEnvelope::AltSig(AltSigTx::new(tx, Bytes::copy_from_slice(&signature)));
            let encoded = alloy_eips::eip2718::Encodable2718::encode_2718_len(&envelope);
            let pooled = N42PooledTransaction::new(Recovered::new_unchecked(envelope, sender_of(s)), encoded);
            cands.push(Arc::new(ValidPoolTransaction {
                transaction: pooled,
                transaction_id: TransactionId::new(SenderId::from(s), k),
                propagate: false,
                timestamp: Instant::now(),
                origin: TransactionOrigin::External,
                authority_ids: None,
            }));
        }
    }
    cands
}

/// What one run of the builder took.
struct Run {
    exec_us: u64,
    /// The process's CPU time over the run, every thread.
    cpu_us: u64,
    spans: BatchSpans,
    frozen: FrozenShards,
}

fn execute(evm_config: &N42EvmConfig, evm_env: &reth_evm::EvmEnv, cands: &[Cand], db: &StackDb, one_wave: bool) -> Run {
    let keys: Vec<(Address, Address)> =
        cands.iter().map(|tx| (tx.sender(), alloy_consensus::Transaction::to(&tx.transaction).unwrap_or_default())).collect();
    let convert = |i: usize| ((), evm_config.tx_env(cands[i].transaction.consensus_ref()));
    let shards = OutputShards::with_index_live(beneficiary(), keys.len(), 16, true, true);
    let sink = |bundle: BundleState| shards.add(bundle);
    let cpu_at = process_cpu_us();
    let at = Instant::now();
    let run = execute_for_build_dispatch(evm_env, &keys, &convert, &|| Some(db.clone()), Some(&sink), true, one_wave)
        .expect("a block of transfers");
    let exec_us = at.elapsed().as_micros() as u64;
    let cpu_us = process_cpu_us().saturating_sub(cpu_at);
    let executed = run.slots.iter().filter(|slot| slot.get().is_some()).count();
    assert_eq!(executed, cands.len(), "every transfer executed");
    let spans = run.phases.batch_spans;
    build_pool().spawn(move || drop(run));
    Run { exec_us, cpu_us, spans, frozen: shards.freeze() }
}

/// `perf stat --control`: a command and its ack, when the FIFOs are named.
struct PerfCtl(Option<(std::fs::File, std::io::BufReader<std::fs::File>)>);

impl PerfCtl {
    fn open() -> Self {
        let (Ok(ctl), Ok(ack)) = (std::env::var("E1_PERF_CTL"), std::env::var("E1_PERF_ACK")) else { return Self(None) };
        let ctl = std::fs::OpenOptions::new().write(true).open(ctl).expect("the perf control FIFO");
        let ack = std::fs::File::open(ack).expect("the perf ack FIFO");
        Self(Some((ctl, std::io::BufReader::new(ack))))
    }

    fn send(&mut self, command: &str) {
        if let Some((ctl, ack)) = self.0.as_mut() {
            ctl.write_all(format!("{command}\n").as_bytes()).expect("perf control");
            ctl.flush().expect("perf control");
            let mut line = String::new();
            ack.read_line(&mut line).expect("perf ack");
        }
    }
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or(0)
}

#[test]
#[ignore = "timing"]
fn e1_exec_bound() {
    let rounds = env_or("E1_ROUNDS", 8);
    let blocks = env_or("E1_BLOCKS", 4).max(1);
    let wave = std::env::var("E1_WAVE").unwrap_or_default();
    let threads = build_pool().current_num_threads();
    let dir = std::env::temp_dir().join(format!("n42-e1-bound-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let at = Instant::now();
    let view = view(&dir);
    println!("view: {} keys in {} ms", view.len(), at.elapsed().as_millis());
    let header = Header {
        number: 20_000_000,
        beneficiary: beneficiary(),
        gas_limit: 5_000_000_000,
        base_fee_per_gas: Some(1_000_000_000),
        timestamp: 1_800_000_000,
        ..Default::default()
    };
    let evm_config = N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
    let evm_env = evm_config.evm_env(&header).expect("env");

    // The three kept layers: each block executed on the stack below it.
    let mut layers: Vec<Arc<FrozenShards>> = Vec::new();
    for b in 0..LAYERS as u64 {
        let db = StackDb(Arc::new(Stack { layers: layers.clone(), memory: Vec::new(), view: Arc::clone(&view), head: 1 }));
        let run = execute(&evm_config, &evm_env, &block(b), &db, false);
        layers.insert(0, Arc::new(run.frozen));
    }
    let db = StackDb(Arc::new(Stack { layers, memory: memory_blocks(), view: Arc::clone(&view), head: 1 }));
    let measured: Vec<Vec<Cand>> = (0..blocks as u64).map(|b| block(LAYERS as u64 + b)).collect();
    println!(
        "block: {} transfers ({} senders x {}), {} pool threads, {} kept layers, {} measured blocks, set-up {} ms",
        measured[0].len(),
        BLOCK_SENDERS,
        RUN,
        threads,
        LAYERS,
        blocks,
        at.elapsed().as_millis()
    );

    // Where a block's recipients are answered (one pass, one thread).
    {
        let mut db = db.clone();
        let mut from_layer = [0usize; LAYERS + 1];
        let mut in_memory = 0usize;
        for tx in &measured[0] {
            let to = alloy_consensus::Transaction::to(&tx.transaction).unwrap_or_default();
            let depth = db.0.layers.iter().position(|layer| layer.get(&to).is_some()).unwrap_or(LAYERS);
            from_layer[depth] += 1;
            if depth == LAYERS && db.0.memory.iter().any(|(_, bundle)| bundle.account(&to).is_some()) {
                in_memory += 1;
            }
            let _ = db.basic(to);
        }
        println!(
            "reads by door (layer 0..{}, below them): {from_layer:?}; of those below, {in_memory} in the {} in-memory blocks",
            LAYERS - 1,
            db.0.memory.len()
        );
    }

    // The reads alone: every recipient of a block through the stack and
    // through the view alone, on this pool, one chunk of 3,500 a job (a
    // batch's worth), and on one thread.
    let read_pass = |use_view_only: bool, pool_threads: bool, cands: &[Cand]| -> (u64, u64, u64) {
        let addresses: Vec<Address> =
            cands.iter().map(|tx| alloy_consensus::Transaction::to(&tx.transaction).unwrap_or_default()).collect();
        let cpu = std::sync::atomic::AtomicU64::new(0);
        let read = |chunk: &[Address]| {
            let at = Instant::now();
            let mut db = db.clone();
            let mut found = 0u64;
            for address in chunk {
                let hit = if use_view_only {
                    db.0.view.account(address, 1).flatten().is_some()
                } else {
                    db.basic(*address).ok().flatten().is_some()
                };
                found += u64::from(hit);
            }
            cpu.fetch_add(at.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
            std::hint::black_box(found);
        };
        let at = Instant::now();
        if pool_threads {
            build_pool().scope(|scope| {
                for chunk in addresses.chunks(3_500) {
                    let read = &read;
                    scope.spawn(move |_| read(chunk));
                }
            });
        } else {
            for chunk in addresses.chunks(3_500) {
                read(chunk);
            }
        }
        let wall_us = at.elapsed().as_micros() as u64;
        let busy_ns = cpu.into_inner();
        (wall_us, busy_ns / addresses.len().max(1) as u64, addresses.len() as u64)
    };
    for pass in 0..2 {
        for (name, view_only) in [("stack", false), ("view only", true)] {
            let (wall1, per1, n) = read_pass(view_only, false, &measured[pass % blocks]);
            let (wall, per, _) = read_pass(view_only, true, &measured[(pass + 1) % blocks]);
            println!(
                "reads {name}: {n} reads; one thread {wall1} us ({per1} ns a read); pool {wall} us ({per} ns a read of busy time, {:.2}x)",
                per as f64 / per1.max(1) as f64
            );
        }
    }

    // The batch state's map alone: 58 fresh maps of a batch's capacity filled
    // with a batch's accounts as `BatchState` loads them (no reads), on the
    // pool, each map then freed on another thread as the output shards free
    // theirs.
    println!(
        "sizes: BundleAccount {} B, AccountInfo {} B, map slot {} B",
        std::mem::size_of::<revm::database::BundleAccount>(),
        std::mem::size_of::<AccountInfo>(),
        std::mem::size_of::<(Address, revm::database::BundleAccount)>()
    );
    for pass in 0..4 {
        // Passes 2 and 3 with `AccountInfo::default()`'s code: the shared
        // `Arc` of `Bytecode::default()` cloned for every entry.
        let shared_code = pass >= 2;
        let addresses: Vec<Address> = measured[pass % blocks]
            .iter()
            .map(|tx| alloy_consensus::Transaction::to(&tx.transaction).unwrap_or_default())
            .collect();
        let busy = std::sync::atomic::AtomicU64::new(0);
        let (sender, receiver) = std::sync::mpsc::channel::<alloy_primitives::map::AddressMap<revm::database::BundleAccount>>();
        let dropper = std::thread::spawn(move || receiver.into_iter().count());
        let at = Instant::now();
        build_pool().scope(|scope| {
            for chunk in addresses.chunks(3_500) {
                let (busy, sender) = (&busy, sender.clone());
                scope.spawn(move |_| {
                    let at = Instant::now();
                    let mut map: alloy_primitives::map::AddressMap<revm::database::BundleAccount> =
                        alloy_primitives::map::AddressMap::with_capacity_and_hasher(chunk.len() + chunk.len() / 4 + 1, Default::default());
                    for (i, address) in chunk.iter().enumerate() {
                        let info = AccountInfo {
                            nonce: i as u64,
                            balance: U256::from(i),
                            code_hash: alloy_primitives::KECCAK256_EMPTY,
                            account_id: None,
                            code: if shared_code { Some(revm::state::Bytecode::default()) } else { None },
                        };
                        map.entry(*address).or_insert_with(|| revm::database::BundleAccount {
                            original_info: Some(info.clone()),
                            info: Some(info),
                            storage: Default::default(),
                            status: revm::database::AccountStatus::Loaded,
                        });
                    }
                    busy.fetch_add(at.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
                    let _ = sender.send(map);
                });
            }
        });
        let wall = at.elapsed().as_micros();
        drop(sender);
        let _ = dropper.join();
        println!(
            "map fill alone (shared code Arc {shared_code}): {} entries in {wall} us wall, {} ns an entry of busy time",
            addresses.len(),
            busy.into_inner() / addresses.len() as u64
        );
    }

    // Warm-up: every measured block once, both dispatches.
    for cands in &measured {
        let _ = execute(&evm_config, &evm_env, cands, &db, false);
        let _ = execute(&evm_config, &evm_env, cands, &db, true);
    }

    let mut perf = PerfCtl::open();
    let mut rows: Vec<(bool, Run)> = Vec::with_capacity(rounds);
    let wall_at = Instant::now();
    perf.send("enable");
    for round in 0..rounds {
        let one_wave = match wave.as_str() {
            "one" => true,
            "two" => false,
            _ => round % 2 == 1,
        };
        let run = execute(&evm_config, &evm_env, &measured[round % blocks], &db, one_wave);
        rows.push((one_wave, run));
    }
    perf.send("disable");
    let measured_ms = wall_at.elapsed().as_millis();
    for (round, (one_wave, run)) in rows.iter().enumerate() {
        let s = run.spans;
        println!(
            "round {round} ({}): exec {} us ({:.1} cores of the process); batches {} on {} threads, skew {} ms, max {} / median {} / min {} ms, cpu of the longest {} ms; wall sum {} us, cpu sum {} us ({:.0}% on cpu); minflt {} vcsw {} ivcsw {}; {:.0} ns of cpu a transfer",
            if *one_wave { "one wave" } else { "two waves" },
            run.exec_us,
            run.cpu_us as f64 / run.exec_us.max(1) as f64,
            s.batches,
            s.threads,
            s.start_skew_ms,
            s.max_ms,
            s.median_ms,
            s.min_ms,
            s.cpu_max_ms,
            s.wall_sum_us,
            s.cpu_sum_us,
            100.0 * s.cpu_sum_us as f64 / s.wall_sum_us.max(1) as f64,
            s.minflt,
            s.vcsw,
            s.ivcsw,
            s.cpu_sum_us as f64 * 1000.0 / measured[0].len() as f64,
        );
    }
    for one_wave in [false, true] {
        let pick: Vec<&Run> = rows.iter().filter(|(w, _)| *w == one_wave).map(|(_, r)| r).collect();
        if pick.is_empty() {
            continue;
        }
        println!(
            "summary {} threads {}: exec median {} us, batch max median {} ms, cpu sum median {} us, wall sum median {} us, minflt median {}, vcsw median {}, ivcsw median {}",
            threads,
            if one_wave { "one wave" } else { "two waves" },
            median(pick.iter().map(|r| r.exec_us).collect()),
            median(pick.iter().map(|r| r.spans.max_ms).collect()),
            median(pick.iter().map(|r| r.spans.cpu_sum_us).collect()),
            median(pick.iter().map(|r| r.spans.wall_sum_us).collect()),
            median(pick.iter().map(|r| r.spans.minflt).collect()),
            median(pick.iter().map(|r| r.spans.vcsw).collect()),
            median(pick.iter().map(|r| r.spans.ivcsw).collect()),
        );
    }
    println!("measured section: {rounds} rounds in {measured_ms} ms");
    drop(rows);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The process's CPU time so far (every thread), microseconds.
fn process_cpu_us() -> u64 {
    // SAFETY: the call only writes into the zeroed struct passed to it.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    us(usage.ru_utime) + us(usage.ru_stime)
}

/// A QMDB chain whose genesis holds one account; the replay set's accounts
/// are block 1.
fn qmdb_chain() -> Arc<reth_chainspec::ChainSpec> {
    let genesis: alloy_genesis::Genesis = serde_json::from_str(
        r#"{
            "config": { "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0, "stateScheme": "qmdb" },
            "alloc": { "0x0000000000000000000000000000000000000001": { "balance": "0x64" } },
            "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
            "extraData": "0x", "nonce": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "number": "0x0", "gasUsed": "0x0",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
        }"#,
    )
    .expect("genesis");
    Arc::new(n42_qmdb_reth::chainspec::with_declared_state_scheme(genesis.into()).expect("a qmdb chain"))
}

fn changed(nonce: u64, balance: u64) -> revm::database::BundleAccount {
    // No code: `AccountInfo::default()`'s `Some(Bytecode::default())` is one
    // process-wide `Arc`, and cloning it from many threads is a contended
    // atomic (the provider's accounts carry none either).
    let info = AccountInfo {
        nonce,
        balance: U256::from(balance),
        code_hash: alloy_primitives::KECCAK256_EMPTY,
        account_id: None,
        code: None,
    };
    revm::database::BundleAccount {
        original_info: Some(info.clone()),
        info: Some(info),
        storage: Default::default(),
        status: revm::database::AccountStatus::Changed,
    }
}

/// Block `n`'s accounts as the leader's output shards hand them to the root:
/// its 400 senders, the beneficiary, and ~190,000 distinct recipients of
/// 200,000 transfers drawn from 2,000,000.
fn block_accounts(n: u64) -> Vec<(Address, revm::database::BundleAccount)> {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ n.wrapping_mul(0x2545_f491_4f6c_dd1d);
    let mut touched = std::collections::HashMap::with_capacity(200_000);
    for s in (n * BLOCK_SENDERS..(n + 1) * BLOCK_SENDERS).map(|s| s % TOTAL_SENDERS) {
        touched.insert(sender_of(s), changed(n * RUN, 10u64.pow(18) - n));
        for _ in 0..RUN {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            touched.insert(recipient_of(seed % RECIPIENTS), changed(0, n + seed % 1_000));
        }
    }
    touched.insert(beneficiary(), changed(0, 7 + n));
    touched.into_iter().collect()
}

/// Where the leader's QMDB root goes on the replay set's shape: the
/// operations from the block's accounts (`sorted_operations_from_accounts`)
/// and `QmdbNodeState::compute_operations` in entry-file mode over a tree of
/// the 2,012,501 accounts, after `E1_ROOT_WARM` (default 30) blocks of churn.
/// The global pool is the root's (`RAYON_NUM_THREADS`).
#[test]
#[ignore = "timing"]
fn e1_root_bound() {
    let warm = env_or("E1_ROOT_WARM", 30) as u64;
    let rounds = env_or("E1_ROUNDS", 8) as u64;
    let threads = rayon::current_num_threads();
    let chain = qmdb_chain();
    let dir = std::env::temp_dir().join(format!("n42-e1-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = n42_qmdb_reth::QmdbNodeState::new_with_entry_file(chain.clone(), &dir, true);
    state.initialize((0, chain.genesis_hash())).expect("initialize");
    let hash_of = |n: u64| B256::from(U256::from(n + 1) << 64);

    // Block 1: every account of the set.
    let at = Instant::now();
    let mut all: Vec<(Address, revm::database::BundleAccount)> = Vec::with_capacity((TOTAL_SENDERS + RECIPIENTS + 1) as usize);
    all.push((beneficiary(), changed(0, 7)));
    all.extend((0..TOTAL_SENDERS).map(|s| (sender_of(s), changed(0, 10u64.pow(18)))));
    all.extend((0..RECIPIENTS).map(|r| (recipient_of(r), changed(r % 3, 1 + r))));
    let refs: Vec<(&Address, &revm::database::BundleAccount)> = all.iter().map(|(a, b)| (a, b)).collect();
    let ops = n42_qmdb_reth::changes::sorted_operations_from_accounts(&refs, true);
    let prepared = state.compute_operations(chain.genesis_hash(), ops).expect("block 1");
    state.insert(hash_of(1), 1, prepared).expect("insert 1");
    state.on_canonical(hash_of(1)).expect("canonical 1");
    drop(refs);
    drop(all);
    println!("tree: {} accounts in {} ms, {} pool threads", TOTAL_SENDERS + RECIPIENTS + 1, at.elapsed().as_millis(), threads);

    let mut perf = PerfCtl::open();
    let mut parent = hash_of(1);
    let mut rows = Vec::new();
    for n in 2..2 + warm + rounds {
        let accounts = block_accounts(n);
        let refs: Vec<(&Address, &revm::database::BundleAccount)> = accounts.iter().map(|(a, b)| (a, b)).collect();
        let measured = n >= 2 + warm;
        if measured && n == 2 + warm {
            perf.send("enable");
        }
        let cpu_at = process_cpu_us();
        let at = Instant::now();
        let ops = n42_qmdb_reth::changes::sorted_operations_from_accounts(&refs, true);
        let ops_us = at.elapsed().as_micros() as u64;
        let cpu_ops = process_cpu_us() - cpu_at;
        let at = Instant::now();
        let cpu_at = process_cpu_us();
        let prepared = state.compute_operations(parent, ops).expect("a block's root");
        let compute_us = at.elapsed().as_micros() as u64;
        let cpu_compute = process_cpu_us() - cpu_at;
        if measured && n == 1 + warm + rounds {
            perf.send("disable");
        }
        let split = state.take_root_split(&parent).unwrap_or_default();
        state.insert(hash_of(n), n, prepared).expect("insert");
        state.on_canonical(hash_of(n)).expect("canonical");
        parent = hash_of(n);
        if measured {
            println!(
                "block {n}: {} accounts; ops {ops_us} us ({cpu_ops} us cpu, {:.1} cores); compute {compute_us} us ({cpu_compute} us cpu, {:.1} cores): move {} apply {} hash {} ms (sort {} leaves {} retire {} writes {} index {} rehash {} root {} note {} delta {} us; the apply's call {} us), faults {} (append {}, undo {}), pool misses {}",
                accounts.len(),
                cpu_ops as f64 / ops_us.max(1) as f64,
                cpu_compute as f64 / compute_us.max(1) as f64,
                split.move_ms,
                split.apply_ms,
                split.hash_ms,
                split.sort_us,
                split.leaves_us,
                split.retire_us,
                split.writes_us,
                split.index_us,
                split.rehash_us,
                split.root_us,
                split.note_us,
                split.delta_us,
                split.apply_total_us,
                split.faults,
                split.append_faults,
                split.faults_undo,
                split.twig_pool_misses,
            );
            rows.push((ops_us, compute_us, cpu_ops, cpu_compute));
        }
    }
    println!(
        "summary {threads} threads: ops median {} us ({} us cpu), compute median {} us ({} us cpu)",
        median(rows.iter().map(|r| r.0).collect()),
        median(rows.iter().map(|r| r.2).collect()),
        median(rows.iter().map(|r| r.1).collect()),
        median(rows.iter().map(|r| r.3).collect()),
    );
    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spinning load beside a measurement: `threads` threads verifying Ed25519
/// signatures on `scope` until `stop` (the ingest's recovery runs at ~9-11
/// cores on the E=1 layer at 3M transactions a second).
fn ed25519_load<'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    threads: usize,
    stop: &'scope std::sync::atomic::AtomicBool,
) {
    for t in 0..threads {
        scope.spawn(move || {
            use ed25519_dalek::{Signer as _, Verifier as _};
            let key = ed25519_dalek::SigningKey::from_bytes(&[t as u8 + 1; 32]);
            let message = [t as u8; 120];
            let signature = key.sign(&message);
            let public = key.verifying_key();
            let mut done = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                done += u64::from(public.verify(&message, &signature).is_ok());
            }
            std::hint::black_box(done);
        });
    }
}

/// The execution of block N with the QMDB root of block N-1 running beside
/// it, as on the E=1 leader (the parent's root starts ~14 ms after its seal
/// and lasts ~37; the child's execution runs from ~5 to ~35 ms after it),
/// and optionally `E1_LOAD_THREADS` threads of Ed25519 verification (the
/// ingest). Each round runs the execution alone, then beside the root, then
/// beside the root and the load, so the three read against each other.
/// `E1_ROOT_DELAY_US` (default 0) delays the root's start.
#[test]
#[ignore = "timing"]
fn e1_overlap() {
    let rounds = env_or("E1_ROUNDS", 8);
    let load_threads = env_or("E1_LOAD_THREADS", 10);
    let root_delay = std::time::Duration::from_micros(env_or("E1_ROOT_DELAY_US", 0) as u64);
    let blocks = 4usize;
    let dir = std::env::temp_dir().join(format!("n42-e1-overlap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let view = view(&dir);
    let header = Header {
        number: 20_000_000,
        beneficiary: beneficiary(),
        gas_limit: 5_000_000_000,
        base_fee_per_gas: Some(1_000_000_000),
        timestamp: 1_800_000_000,
        ..Default::default()
    };
    let evm_config = N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
    let evm_env = evm_config.evm_env(&header).expect("env");
    let mut layers: Vec<Arc<FrozenShards>> = Vec::new();
    for b in 0..LAYERS as u64 {
        let db = StackDb(Arc::new(Stack { layers: layers.clone(), memory: Vec::new(), view: Arc::clone(&view), head: 1 }));
        let run = execute(&evm_config, &evm_env, &block(b), &db, false);
        layers.insert(0, Arc::new(run.frozen));
    }
    let db = StackDb(Arc::new(Stack { layers, memory: memory_blocks(), view: Arc::clone(&view), head: 1 }));
    let measured: Vec<Vec<Cand>> = (0..blocks as u64).map(|b| block(LAYERS as u64 + b)).collect();

    // The root's tree, churned as in `e1_root_bound`.
    let chain = qmdb_chain();
    let root_dir = dir.join("qmdb");
    let state = n42_qmdb_reth::QmdbNodeState::new_with_entry_file(chain.clone(), &root_dir, true);
    state.initialize((0, chain.genesis_hash())).expect("initialize");
    let hash_of = |n: u64| B256::from(U256::from(n + 1) << 64);
    {
        let mut all: Vec<(Address, revm::database::BundleAccount)> = Vec::with_capacity((TOTAL_SENDERS + RECIPIENTS + 1) as usize);
        all.push((beneficiary(), changed(0, 7)));
        all.extend((0..TOTAL_SENDERS).map(|s| (sender_of(s), changed(0, 10u64.pow(18)))));
        all.extend((0..RECIPIENTS).map(|r| (recipient_of(r), changed(r % 3, 1 + r))));
        let refs: Vec<(&Address, &revm::database::BundleAccount)> = all.iter().map(|(a, b)| (a, b)).collect();
        let ops = n42_qmdb_reth::changes::sorted_operations_from_accounts(&refs, true);
        let prepared = state.compute_operations(chain.genesis_hash(), ops).expect("block 1");
        state.insert(hash_of(1), 1, prepared).expect("insert 1");
        state.on_canonical(hash_of(1)).expect("canonical 1");
    }
    let mut parent = hash_of(1);
    let mut next = 2u64;
    let mut root_once = |state: &n42_qmdb_reth::QmdbNodeState, accounts: &[(Address, revm::database::BundleAccount)]| {
        let at = Instant::now();
        let refs: Vec<(&Address, &revm::database::BundleAccount)> = accounts.iter().map(|(a, b)| (a, b)).collect();
        let ops = n42_qmdb_reth::changes::sorted_operations_from_accounts(&refs, true);
        let prepared = state.compute_operations(parent, ops).expect("a block's root");
        let took = at.elapsed().as_micros() as u64;
        state.insert(hash_of(next), next, prepared).expect("insert");
        state.on_canonical(hash_of(next)).expect("canonical");
        parent = hash_of(next);
        next += 1;
        took
    };
    for n in 0..20u64 {
        let _ = root_once(&state, &block_accounts(1_000 + n));
    }
    // Warm-up of the execution.
    for cands in &measured {
        let _ = execute(&evm_config, &evm_env, cands, &db, false);
    }
    println!(
        "overlap: {} build threads, {} root threads, {load_threads} load threads, root delay {} us",
        build_pool().current_num_threads(),
        rayon::current_num_threads(),
        root_delay.as_micros()
    );
    let mut alone = Vec::new();
    let mut beside = Vec::new();
    let mut loaded = Vec::new();
    for round in 0..rounds {
        let cands = &measured[round % blocks];
        let accounts = block_accounts(2_000 + round as u64);
        let run = execute(&evm_config, &evm_env, cands, &db, false);
        let root_alone = root_once(&state, &accounts);
        alone.push((run.exec_us, run.spans.cpu_sum_us, run.spans.wall_sum_us, root_alone));
        for with_load in [false, true] {
            let accounts = block_accounts(3_000 + 2 * round as u64 + u64::from(with_load));
            let stop = std::sync::atomic::AtomicBool::new(false);
            let (run, root_us) = std::thread::scope(|scope| {
                if with_load {
                    ed25519_load(scope, load_threads, &stop);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let state = &state;
                let accounts = &accounts;
                let root_once = &mut root_once;
                let root = scope.spawn(move || {
                    std::thread::sleep(root_delay);
                    root_once(state, accounts)
                });
                let run = execute(&evm_config, &evm_env, cands, &db, false);
                let root_us = root.join().unwrap_or(0);
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                (run, root_us)
            });
            let row = (run.exec_us, run.spans.cpu_sum_us, run.spans.wall_sum_us, root_us);
            println!(
                "round {round}: alone exec {} us (cpu {} / wall {} us) root {} us; beside the root{}: exec {} us (cpu {} / wall {} us, minflt {} vcsw {} ivcsw {}) root {} us",
                alone[round].0,
                alone[round].1,
                alone[round].2,
                alone[round].3,
                if with_load { " and the load" } else { "" },
                row.0,
                row.1,
                row.2,
                run.spans.minflt,
                run.spans.vcsw,
                run.spans.ivcsw,
                row.3,
            );
            if with_load {
                loaded.push(row);
            } else {
                beside.push(row);
            }
        }
    }
    for (name, rows) in [("alone", &alone), ("beside the root", &beside), ("beside the root and the load", &loaded)] {
        println!(
            "summary {name}: exec median {} us, cpu sum {} us, wall sum {} us, root {} us",
            median(rows.iter().map(|r| r.0).collect()),
            median(rows.iter().map(|r| r.1).collect()),
            median(rows.iter().map(|r| r.2).collect()),
            median(rows.iter().map(|r| r.3).collect()),
        );
    }
    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}

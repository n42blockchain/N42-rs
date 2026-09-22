// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the QMDB checkpoint costs as a chain gets longer, off the fleet.
//!
//! The checkpoint is the active-bit set: one bit per slot the tree has ever
//! appended (`ForestCheckpoint::active`). QMDB only appends, so it grows by
//! the accounts a block touches, forever -- 150,000 bits = 18,750 bytes a
//! block on the four-node bench shape, which is exactly the slope the fleet
//! measures (`bench-loop206S275/node0`: 61,940 B at block 101, 9,218,084 at
//! block 584). The compaction rewrites the whole set once the delta log has
//! grown to its size, so one compaction costs the state and the interval
//! between them grows with it.
//!
//! This bench drives the node's own three calls (`compute` / `insert` /
//! `on_canonical` on a `QmdbNodeState` in entry-file mode) with full-block
//! shaped updates, and prints the checkpoint's bytes, its wall time and
//! where that time went, beside the root job's milliseconds. It reproduces
//! the fleet's growth to the megabyte and the millisecond: 22 ms at 5.7 MB
//! here against 22 ms at 5.67 MB on loop207.
//!
//! What it also shows is where that time is: at a 13 MB checkpoint the
//! phases read replay 36, encode 2, write 0, sync 3. The checkpoint's write
//! is not the cost; replaying the sealed segment onto it is, and inside the
//! replay it was the keccak over every record. It is `#[ignore]`d: at the
//! default shape it writes gigabytes of entry file and runs for minutes.
//!
//! ```text
//! cargo test --release -p n42-qmdb-reth --test checkpoint_growth -- --ignored --nocapture
//! N42_CKPT_BENCH_BLOCKS=700 N42_CKPT_BENCH_DIR=/data/n42-build/ckpt-bench \
//!   cargo test --release -p n42-qmdb-reth --test checkpoint_growth -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use n42_qmdb_reth::QmdbNodeState;
use n42_qmdb_state::{AccountState, BlockChanges};
use reth_chainspec::ChainSpec;

/// How many measured blocks; each one rewrites [`touched`] existing accounts.
fn blocks() -> u64 {
    env_u64("N42_CKPT_BENCH_BLOCKS", 300)
}

/// Accounts a block touches — the fleet's full block is ~147,000-163,000.
fn touched() -> u64 {
    env_u64("N42_CKPT_BENCH_TOUCHED", 150_000)
}

/// Live accounts the state holds before the measured blocks start.
fn state_accounts() -> u64 {
    env_u64("N42_CKPT_BENCH_ACCOUNTS", 2_000_000)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn bench_dir() -> PathBuf {
    let dir = std::env::var("N42_CKPT_BENCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("n42-qmdb-ckpt-bench"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn qmdb_chain() -> Arc<ChainSpec> {
    let genesis: Genesis = serde_json::from_str(
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
    .expect("the bench's genesis");
    Arc::new(n42_qmdb_reth::with_declared_state_scheme(ChainSpec::from(genesis)).expect("a QMDB genesis"))
}

/// Account `i` of the synthetic state. Spread over the whole address space so
/// the keys — and so the slots a block retires — land the way a flood's do.
fn account(i: u64) -> Address {
    Address::from_word(alloy_primitives::keccak256(i.to_le_bytes()))
}

fn block_hash(number: u64) -> B256 {
    alloy_primitives::keccak256([&b"n42-ckpt-bench"[..], &number.to_le_bytes()[..]].concat())
}

/// Stride between the accounts one measured block touches: coprime with the
/// live set, so a block's 150,000 accounts are spread over the whole state
/// and the slots it retires are spread over the whole append history — the
/// shape the fixed flood produces (round 43), and the one that makes the
/// checkpoint's scattered bit writes what they are on the fleet.
const STRIDE: u64 = 1_000_003;

/// One block: `addresses` rewritten with a new nonce and balance, applied
/// through the node's own three calls, timed the way the follower's import
/// times its root job.
fn apply_block(
    state: &QmdbNodeState,
    number: u64,
    parent: B256,
    accounts: impl Iterator<Item = u64>,
) -> (B256, u128) {
    let mut changes = BlockChanges::new();
    for i in accounts {
        changes.set_account(
            account(i),
            AccountState { nonce: number, balance: U256::from(number) * U256::from(1_000u64), code_hash: B256::ZERO },
        );
    }
    let hash = block_hash(number);
    let root_at = std::time::Instant::now();
    let prepared = state.compute(parent, &changes).expect("the block's root");
    state.insert(hash, number, prepared).expect("filing the block");
    let root_us = root_at.elapsed().as_micros();
    state.on_canonical(hash).expect("persisting the head");
    (hash, root_us)
}

/// Prints, per block, the root job's milliseconds and the checkpoint the
/// compaction last wrote. The growth to look for is the checkpoint's `bytes`
/// and `ms` climbing with the block number while the block's shape is
/// constant.
#[test]
#[ignore = "writes gigabytes and runs for minutes; run it deliberately"]
fn the_checkpoint_grows_with_the_chain() {
    let chain = qmdb_chain();
    let dir = bench_dir();
    let state = QmdbNodeState::new_with_entry_file(chain.clone(), &dir, true);
    state.initialize((0, chain.genesis_hash())).expect("the genesis forest");

    let touched = touched();
    let seed_blocks = state_accounts().div_ceil(touched);
    let mut parent = chain.genesis_hash();
    let mut number = 0u64;

    // The state is built by the same block shape, so the bench's chain is one
    // history and not a state dropped in from the side.
    let seed_at = std::time::Instant::now();
    for i in 0..seed_blocks {
        number += 1;
        let (hash, _) = apply_block(&state, number, parent, i * touched..(i + 1) * touched);
        parent = hash;
    }
    let live = seed_blocks * touched;
    println!(
        "seeded {live} accounts in {seed_blocks} blocks, {:.1}s; blocks={} touched={touched}",
        seed_at.elapsed().as_secs_f64(),
        blocks(),
    );
    println!("block  root_ms  ckpt_bytes  ckpt_ms  compactions  ckpt_ms_total   phases (ms)");

    let mut roots: Vec<u128> = Vec::with_capacity(blocks() as usize);
    let started = std::time::Instant::now();
    for step in 1..=blocks() {
        number += 1;
        // Existing accounts, a different window each block, so every block
        // appends `touched` slots and retires `touched` older ones.
        let base = step.wrapping_mul(touched) % live;
        let (hash, root_us) =
            apply_block(&state, number, parent, (0..touched).map(|j| (base + j * STRIDE) % live));
        parent = hash;
        roots.push(root_us);
        let (n, bytes, ms, total) = state.compaction_stats();
        if step % 10 == 0 || step == 1 {
            let [read, replay, encode, write, sync] = state.compaction_phases();
            println!(
                "{step:5}  {:7.1}  {bytes:10}  {ms:7}  {n:11}  {total:13}                    read {read:3} replay {replay:3} encode {encode:3} write {write:3} sync {sync:3}",
                root_us as f64 / 1000.0
            );
        }
    }
    state.wait_for_compaction();

    let at = |b: usize| -> f64 {
        let lo = b.saturating_sub(10).min(roots.len().saturating_sub(1));
        let hi = (b + 10).min(roots.len());
        let mut window: Vec<u128> = roots[lo..hi].to_vec();
        window.sort_unstable();
        window.get(window.len() / 2).copied().unwrap_or(0) as f64 / 1000.0
    };
    let (n, bytes, ms, total) = state.compaction_stats();
    println!(
        "\n{} blocks in {:.1}s; root p50 at 50/150/300 = {:.1}/{:.1}/{:.1} ms; \
         {n} compactions, last {bytes} bytes / {ms} ms, {total} ms of compaction in all",
        blocks(),
        started.elapsed().as_secs_f64(),
        at(50),
        at(150),
        at(300.min(roots.len().saturating_sub(1))),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

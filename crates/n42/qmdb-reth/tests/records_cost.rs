// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a QMDB forest's block records cost to build and to drop, at fleet
//! size and on the fleet's allocator:
//!
//! ```text
//! MALLOC_CONF=thp:always,oversize_threshold:0,dirty_decay_ms:2000,background_thread:true \
//!   taskset -c 0-15 cargo test --release -p n42-qmdb-reth --test records_cost -- --ignored --nocapture
//! ```
//!
//! `N42_RECORDS_BENCH=<blocks>x<accounts>` (default 28x163000) sizes it;
//! `N42_RECORDS_BENCH_DIR` is where the entry file goes (default the temp
//! directory). Every block writes `accounts` fresh accounts; the reader's keep
//! holds every record until the last block, which releases `blocks` of them
//! (and genesis) in one head move -- the release a persistence batch causes on the fleet.

#![allow(missing_docs)]

use alloy_primitives::{Address, B256, U256};
use n42_qmdb_reth::{changes_from_bundle, sorted_operations_from_execution};
use n42_qmdb_state::QmdbForest;
use revm_database::{AccountStatus, BundleAccount, BundleState};
use revm_state::AccountInfo;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A genesis hash that is not any block's parent sentinel.
const GENESIS: B256 = B256::repeat_byte(0xee);

fn addr(i: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&(i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_be_bytes());
    a[12..].copy_from_slice(&i.to_be_bytes());
    Address::from(a)
}

fn bundle(ids: std::ops::Range<u64>) -> BundleState {
    let mut b = BundleState::default();
    for i in ids {
        let info = AccountInfo { balance: U256::from(1_000_000_000_000u64 + i), nonce: i % 7, ..Default::default() };
        b.state.insert(addr(i), BundleAccount::new(None, Some(info), Default::default(), AccountStatus::Changed));
    }
    b
}

#[test]
#[ignore = "a measurement, several GB of memory"]
fn records_cost() {
    let (blocks, accounts) = std::env::var("N42_RECORDS_BENCH")
        .ok()
        .and_then(|spec| {
            let (b, o) = spec.split_once('x')?;
            Some((b.parse::<u64>().ok()?, o.parse::<u64>().ok()?))
        })
        .unwrap_or((28, 163_000));
    let dir = std::env::var("N42_RECORDS_BENCH_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let path = dir.join(format!("records-cost-{}.entries", std::process::id()));
    let genesis = changes_from_bundle(&bundle(0..1_000));
    let mut forest =
        QmdbForest::genesis(GENESIS, &genesis).expect("genesis").with_entry_file(&path).expect("entry file");
    forest.set_keep_from(Some(1));
    let mut parent = GENESIS;
    let mut next = 1_000u64;
    let (mut build_ms, mut compute_ms) = (Vec::new(), Vec::new());
    // The forest keeps DEFAULT_RETAIN_DEPTH blocks below the head whatever
    // the keep says, so the batch is released that far below the last head.
    let last = blocks + 1 + n42_qmdb_state::DEFAULT_RETAIN_DEPTH;
    for n in 1..=last {
        let b = bundle(next..next + accounts);
        next += accounts;
        let at = std::time::Instant::now();
        let ops = sorted_operations_from_execution(&b, false);
        build_ms.push(at.elapsed().as_secs_f64() * 1e3);
        let at = std::time::Instant::now();
        let prepared = forest.compute_operations(parent, ops).expect("compute");
        compute_ms.push(at.elapsed().as_secs_f64() * 1e3);
        let hash = B256::from(U256::from(n));
        forest.insert(hash, n, prepared).expect("insert");
        if n == last {
            forest.set_keep_from(Some(blocks + 1));
        }
        let at = std::time::Instant::now();
        let released = forest.set_canonical_releasing(hash).expect("canonical");
        let move_ms = at.elapsed().as_secs_f64() * 1e3;
        let (records, twigs, operations) = (released.records(), released.twigs(), released.operations());
        let at = std::time::Instant::now();
        drop(released);
        let free_ms = at.elapsed().as_secs_f64() * 1e3;
        drop(b);
        if n == last || free_ms > 1.0 {
            println!(
                "block {n}: head move {move_ms:.1} ms; released {records} records, {twigs} twigs, {operations} operations; free {free_ms:.2} ms"
            );
        }
        parent = hash;
    }
    let median = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    println!(
        "per block ({accounts} accounts): build the operations median {:.1} ms, compute median {:.1} ms",
        median(&mut build_ms),
        median(&mut compute_ms)
    );
    drop(forest);
    let _ = std::fs::remove_file(&path);
}

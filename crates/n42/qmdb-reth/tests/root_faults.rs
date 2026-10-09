// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The page faults a QMDB root takes on its own thread, block after block,
//! on the fleet's allocator and the fleet's entry-file tree
//! (BREAKTHROUGH_DESIGN 10.48: a root is 32 ms median, one in seven 66, with
//! the root thread's minor faults 276 -> 1,923):
//!
//! ```text
//! MALLOC_CONF=thp:always,oversize_threshold:0,dirty_decay_ms:2000,background_thread:true \
//!   taskset -c 0-15 cargo test --release -p n42-qmdb-reth --test root_faults -- --ignored --nocapture
//! ```
//!
//! `N42_ROOT_FAULTS_BENCH=<blocks>x<ops>x<population>[x<new>]` (default
//! 400x163000x2000000x147000) sizes it; `N42_ROOT_FAULTS_BENCH_DIR` is where
//! the entry file goes (default the temp directory -- a tmpfs counts the file
//! as memory). Every block writes `ops` accounts: `new` of them never seen
//! before (the fleet's flood: ~147k new recipients a block, so the state
//! grows by that every block), the rest rewrites of accounts that exist,
//! cycling over all of them (every rewrite retires a slot and appends one).
//! `new` 0 is the earlier shape: rewrites of the fixed population only.
//! The reader's keep moves once per 44
//! blocks, as a persistence batch moves it, and the released records are
//! dropped on a thread of their own, as the node's release thread does; the
//! moved slots are forgotten and the entry file flushed after every block,
//! as the node's persistence of a block's own delta does.
//! `N42_ROOT_FAULTS_CHURN=<threads>` adds threads that allocate, write and
//! free 1-32 MiB buffers without pause, as the node's builder, executor and
//! importer do around the root (the fleet's heap is never this quiet).
//! `N42_TWIG_POOL_FLOOR=0 N42_QMDB_APPEND_AHEAD_MB=0 N42_QMDB_OFFSET_SEGMENTS_AHEAD=0`
//! turns the prefaulting off for the comparison.

#![cfg(target_os = "linux")]
#![allow(missing_docs)]

use alloy_primitives::{Address, B256, U256};
use n42_qmdb_reth::{changes_from_bundle, sorted_operations_from_execution};
use n42_qmdb_state::QmdbForest;
use revm_database::{AccountStatus, BundleAccount, BundleState};
use revm_state::AccountInfo;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const GENESIS: B256 = B256::repeat_byte(0xee);
/// Blocks between two moves of the reader's keep (a persistence batch).
const BATCH: u64 = 44;
/// Blocks at the start left out of the statistics.
const WARMUP: usize = 20;

fn addr(i: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&(i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_be_bytes());
    a[12..].copy_from_slice(&i.to_be_bytes());
    Address::from(a)
}

fn bundle(ids: impl Iterator<Item = u64>, round: u64) -> BundleState {
    let mut b = BundleState::default();
    for i in ids {
        let info = AccountInfo { balance: U256::from(1_000_000_000_000u64 + i + round), nonce: round, ..Default::default() };
        b.state.insert(addr(i), BundleAccount::new(None, Some(info), Default::default(), AccountStatus::Changed));
    }
    b
}

/// This thread's minor + major faults.
fn thread_faults() -> u64 {
    // SAFETY: `getrusage` writes one `rusage` into the zeroed struct it is given.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::getrusage(libc::RUSAGE_THREAD, &raw mut usage) } != 0 {
        return 0;
    }
    (usage.ru_minflt.max(0) + usage.ru_majflt.max(0)) as u64
}

fn quantiles(mut v: Vec<f64>) -> (f64, f64, f64) {
    v.sort_by(f64::total_cmp);
    let at = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    (at(0.5), at(0.9), v[v.len() - 1])
}

#[test]
#[ignore = "a measurement, several GB of memory"]
fn root_faults() {
    let spec = std::env::var("N42_ROOT_FAULTS_BENCH").unwrap_or_default();
    let parts: Vec<u64> = spec.split('x').filter_map(|p| p.parse().ok()).collect();
    let (blocks, ops, population, new) = match parts.as_slice() {
        [b, o, p] => (*b, *o, *p, 0),
        [b, o, p, n] => (*b, *o, *p, (*n).min(*o)),
        _ => (400, 163_000, 2_000_000, 147_000),
    };
    let dir = std::env::var("N42_ROOT_FAULTS_BENCH_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let path = dir.join(format!("root-faults-{}.entries", std::process::id()));
    let genesis = changes_from_bundle(&bundle(0..population, 0));
    let mut forest =
        QmdbForest::genesis(GENESIS, &genesis).expect("genesis").with_entry_file(&path).expect("entry file");
    drop(genesis);
    forest.set_keep_from(Some(0));
    let (release, released_rx) = std::sync::mpsc::channel::<n42_qmdb_state::Released>();
    let churn_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let churn_threads = std::env::var("N42_ROOT_FAULTS_CHURN").ok().and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
    let churners: Vec<_> = (0..churn_threads)
        .map(|t| {
            let stop = churn_stop.clone();
            std::thread::spawn(move || {
                let mut ring: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
                let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ t;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let len = (1 << 20) + (x % (31 << 20)) as usize;
                    let mut buf = Vec::<u8>::with_capacity(len);
                    // SAFETY: bytes, written before the length covers them.
                    unsafe {
                        std::ptr::write_bytes(buf.as_mut_ptr(), 1, len);
                        buf.set_len(len);
                    }
                    ring.push_back(buf);
                    if ring.len() > 8 {
                        ring.pop_front();
                    }
                }
            })
        })
        .collect();
    let releaser = std::thread::Builder::new()
        .name("bench-release".into())
        .spawn(move || released_rx.into_iter().for_each(drop))
        .expect("release thread");
    let (mut root_ms, mut apply_ms, mut faults, mut misses) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut prep_faults, mut writes_faults, mut hash_faults) = (Vec::new(), Vec::new(), Vec::new());
    // Per block: the root thread's faults by structure, and the total.
    let mut split: Vec<[u64; 8]> = Vec::new();
    let mut parent = GENESIS;
    let mut cursor = 0u64;
    let mut accounts = population;
    let refills_before = n42_twig_core::qmdb_compat::twig_pool_refills();
    for n in 1..=blocks {
        let old = ops - new;
        let total = accounts;
        let ids = (cursor..cursor + old).map(move |i| i % total).chain(total..total + new);
        cursor += old;
        accounts += new;
        let b = bundle(ids, n);
        let operations = sorted_operations_from_execution(&b, false);
        drop(b);
        let misses_before = n42_twig_core::qmdb_compat::twig_pool_misses();
        let faults_before = thread_faults();
        let at = std::time::Instant::now();
        let prepared = forest.compute_operations(parent, operations).expect("compute");
        let hash = B256::from(U256::from(n));
        forest.insert(hash, n, prepared).expect("insert");
        let elapsed = at.elapsed().as_secs_f64() * 1e3;
        let fault_count = thread_faults().saturating_sub(faults_before);
        let (_, phases) = forest.last_compute();
        let apply = (phases.sort_us + phases.leaves_us + phases.undo_us + phases.retire_us + phases.writes_us + phases.index_us)
            as f64
            / 1e3;
        if n % BATCH == 0 {
            forest.set_keep_from(Some(n.saturating_sub(4)));
        }
        let released = forest.set_canonical_releasing(hash).expect("canonical");
        let _ = release.send(released);
        // What the node's persistence does after every canonical block, off
        // the root: the block's own delta is written, so the moved slots are
        // forgotten, and the entry file's tail is flushed (the fsync is left
        // out).
        forest.forget_changes();
        let _ = forest.flush_entries_for_sync().expect("flush");
        if fault_count > 50 || elapsed > 30.0 {
            println!(
                "block {n}: root {elapsed:.1} ms, apply {apply:.1}, rehash {:.1}, root read {:.1}; faults {fault_count} \
                 (prep {}, writes {}, index+hash {}; entries {} offsets {} index {} bits {} twigs {} undo {} tmp {}); misses {}",
                phases.rehash_us as f64 / 1e3,
                phases.root_us as f64 / 1e3,
                phases.prep_faults,
                phases.writes_faults,
                phases.hash_faults,
                phases.entries_faults,
                phases.offsets_faults,
                phases.index_faults,
                phases.bits_faults,
                phases.twigs_faults,
                phases.undo_faults,
                phases.tmp_faults,
                n42_twig_core::qmdb_compat::twig_pool_misses() - misses_before,
            );
        }
        if n as usize > WARMUP {
            root_ms.push(elapsed);
            apply_ms.push(apply);
            faults.push(fault_count as f64);
            misses.push((n42_twig_core::qmdb_compat::twig_pool_misses() - misses_before) as f64);
            prep_faults.push(phases.prep_faults as f64);
            writes_faults.push(phases.writes_faults as f64);
            hash_faults.push(phases.hash_faults as f64);
            split.push([
                phases.entries_faults,
                phases.offsets_faults,
                phases.index_faults,
                phases.bits_faults,
                phases.twigs_faults,
                phases.undo_faults,
                phases.tmp_faults,
                fault_count,
            ]);
        }
        parent = hash;
    }
    drop(release);
    let _ = releaser.join();
    churn_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for churner in churners {
        let _ = churner.join();
    }
    let (root_med, root_p90, root_max) = quantiles(root_ms);
    let (apply_med, apply_p90, apply_max) = quantiles(apply_ms);
    let over_50 = faults.iter().filter(|f| **f > 50.0).count();
    let (fault_med, fault_p90, fault_max) = quantiles(faults);
    let (miss_med, _, miss_max) = quantiles(misses);
    let (prep, writes, hash) = (quantiles(prep_faults), quantiles(writes_faults), quantiles(hash_faults));
    println!(
        "root_faults bench: {blocks} blocks x {ops} ops ({new} new keys) on {population} accounts growing to {accounts} \
         (first {WARMUP} left out)\n\
         root   ms median {root_med:.1} p90 {root_p90:.1} max {root_max:.1} (p90/median {:.2})\n\
         apply  ms median {apply_med:.1} p90 {apply_p90:.1} max {apply_max:.1} (p90/median {:.2})\n\
         faults    median {fault_med:.0} p90 {fault_p90:.0} max {fault_max:.0}; blocks over 50: {over_50}\n\
         faults by phase (median/p90/max): prep {:.0}/{:.0}/{:.0}, writes {:.0}/{:.0}/{:.0}, index+hash {:.0}/{:.0}/{:.0}\n\
         twig pool misses median {miss_med:.0} max {miss_max:.0}; refills {}",
        root_p90 / root_med,
        apply_p90 / apply_med,
        prep.0, prep.1, prep.2, writes.0, writes.1, writes.2, hash.0, hash.1, hash.2,
        n42_twig_core::qmdb_compat::twig_pool_refills() - refills_before,
    );
    print_split(&split, blocks as usize - WARMUP);
    let (behind, lag) = n42_twig_core::prefault::append_populate_stats();
    println!("appends past the populate's edge {behind}; populate lag at the end {} MiB", lag >> 20);
    drop(forest);
    let _ = std::fs::remove_file(&path);
}

/// The faults by structure (median / p90 / max of each), and the share of
/// blocks over 500 faults by block-number quartile.
fn print_split(split: &[[u64; 8]], blocks: usize) {
    const NAMES: [&str; 8] = ["entries", "offsets", "index", "bits", "twigs", "undo", "tmp", "total"];
    let mut line = String::from("faults by structure (median/p90/max):");
    for (k, name) in NAMES.iter().enumerate() {
        let (med, p90, max) = quantiles(split.iter().map(|row| row[k] as f64).collect());
        line.push_str(&format!(" {name} {med:.0}/{p90:.0}/{max:.0}"));
    }
    println!("{line}");
    let quarter = blocks.div_ceil(4).max(1);
    let mut line = String::from("blocks over 500 faults by quartile:");
    for (q, rows) in split.chunks(quarter).enumerate() {
        let over = rows.iter().filter(|row| row[7] > 500).count();
        let (_, p90, _) = quantiles(rows.iter().map(|row| row[7] as f64).collect());
        line.push_str(&format!(" Q{} {over}/{} ({:.0}%, p90 {p90:.0})", q + 1, rows.len(), 100.0 * over as f64 / rows.len() as f64));
    }
    println!("{line}");
}

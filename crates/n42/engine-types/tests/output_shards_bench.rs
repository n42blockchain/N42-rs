// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The output shards' fold against the graft on the fleet's block shape
//! (`docs/BREAKTHROUGH_DESIGN.md` 10.10): sixteen batches of 10,000
//! transfers, 6,000 senders grouped by batch, a fresh recipient for almost
//! every transfer. Ignored; run it pinned and on a quiet box:
//!
//! `taskset -c 0-15 cargo test --release -p n42-engine-types --test output_shards_bench -- --ignored --nocapture`
#![allow(missing_docs, unreachable_pub, unused_crate_dependencies)]

use std::time::{Duration, Instant};

use alloy_primitives::{Address, U256};
use n42_engine_types::output_shards::{hashed_post_state_of, OutputShards};
use n42_engine_types::parallel_transfer::{build_pool, graft_bundles_folded, install_staged, GraftFold, StagedGraft};
use reth_revm::db::State;
use revm::database::{states::bundle_state::BundleRetention, BundleAccount, BundleState, CacheDB, EmptyDB};
use revm::state::{AccountInfo, AccountStatus, EvmState};
use revm::Database as _;

/// The node's allocator: run with the fleet's `MALLOC_CONF` to see its pages.
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Minor page faults of the process so far.
fn minflt() -> i64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    usage.ru_minflt
}

const BATCHES: u64 = 16;
const PER_BATCH: u64 = 10_000;
const SENDERS: u64 = 6_000;
/// One transfer in this many pays one of 64 shared recipients (an account
/// several batches write).
const SHARED_EVERY: u64 = 64;
static FOLD_SPLIT: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
static FOLD_FAULTS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const WARMUPS: usize = 3;
const ROUNDS: usize = 20;

fn addr(i: u64) -> Address {
    let hash = alloy_primitives::keccak256(i.to_be_bytes());
    Address::from_slice(&hash[12..])
}

fn beneficiary() -> Address {
    addr(1)
}

fn sender(i: u64) -> Address {
    addr(1_000_000 + i)
}

fn parent() -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(beneficiary(), AccountInfo { balance: U256::from(7), ..Default::default() });
    for i in 0..SENDERS {
        db.insert_account_info(sender(i), AccountInfo { balance: U256::from(10u128.pow(24)), nonce: 3, ..Default::default() });
    }
    db
}

/// The batches as the executor hands them to the sink: each a `State` over
/// the parent, one commit a transfer (sender, recipient, beneficiary), the
/// transitions merged with reverts and the bundle taken. Senders are grouped
/// by batch (the partition is by sender): batch `b` owns 375 of them.
fn batch_bundles(db: &CacheDB<EmptyDB>) -> Vec<BundleState> {
    let per = SENDERS / BATCHES;
    (0..BATCHES)
        .map(|b| {
            let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
            for k in 0..PER_BATCH {
                let from = sender(b * per + k % per);
                let to = if k % SHARED_EVERY == 0 { addr(5_000_000 + k % 64) } else { addr(9_000_000 + b * PER_BATCH + k) };
                let value = U256::from(1_000 + k);
                let mut changes: EvmState = Default::default();
                for (address, delta, nonce) in [(from, None, 1u64), (to, Some(value), 0), (beneficiary(), Some(U256::from(21)), 0)] {
                    let loaded = state.basic(address).expect("an in-memory database");
                    let existed = loaded.is_some();
                    let mut info = loaded.unwrap_or_default();
                    match delta {
                        Some(add) => info.balance += add,
                        None => info.balance -= value,
                    }
                    info.nonce += nonce;
                    let mut account = revm::state::Account::from(info);
                    account.status = AccountStatus::Touched;
                    if !existed {
                        account.status |= AccountStatus::Created;
                    }
                    changes.insert(address, account);
                }
                revm::DatabaseCommit::commit(&mut state, changes);
            }
            state.merge_transitions(BundleRetention::Reverts);
            state.take_bundle()
        })
        .collect()
}

fn median(mut v: Vec<Duration>) -> f64 {
    v.sort();
    v[v.len() / 2].as_secs_f64() * 1e3
}

/// `f` over a fresh copy of the batches, `WARMUPS + ROUNDS` times; the
/// median of each of the times it returns.
fn run<const N: usize>(bundles: &[BundleState], mut f: impl FnMut(Vec<BundleState>) -> [Duration; N]) -> [f64; N] {
    let mut times: Vec<Vec<Duration>> = (0..N).map(|_| Vec::new()).collect();
    for round in 0..WARMUPS + ROUNDS {
        let copy = bundles.to_vec();
        let got = f(copy);
        if round >= WARMUPS {
            for (i, t) in got.into_iter().enumerate() {
                times[i].push(t);
            }
        }
    }
    let mut out = [0.0; N];
    for (i, t) in times.into_iter().enumerate() {
        out[i] = median(t);
    }
    out
}

#[test]
#[ignore = "a timing benchmark: run it pinned, release, on a quiet box"]
fn bench_output_shards_fold() {
    use rayon::prelude::*;
    let db = parent();
    let bundles = batch_bundles(&db);
    let accounts: usize = bundles.iter().map(|b| b.state.len()).sum();
    let shards_n = std::env::var("BENCH_SHARDS").ok().and_then(|v| v.parse().ok()).unwrap_or(16usize);
    eprintln!(
        "batches {BATCHES}, transfers {}, batch accounts {accounts}, entry {} B, shards {shards_n}, pool {}",
        BATCHES * PER_BATCH,
        std::mem::size_of::<(Address, BundleAccount)>(),
        build_pool().current_num_threads()
    );

    // (a) The graft after the execution (`GraftFold::Direct`, no target), and
    // the streamed graft (`StagedGraft::add` a batch, then `install_staged`).
    let [graft] = run(&bundles, |copy| {
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let at = Instant::now();
        let graft = graft_bundles_folded(&mut state, copy, beneficiary(), false, GraftFold::Direct, None).expect("in memory");
        let t = at.elapsed();
        drop((graft, state));
        [t]
    });
    let [staged_add, staged_install] = run(&bundles, |copy| {
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let at = Instant::now();
        let mut staged = StagedGraft::new(beneficiary(), accounts);
        for bundle in copy {
            staged.add(bundle);
        }
        let added = at.elapsed();
        let at = Instant::now();
        let graft = install_staged(&mut state, staged, false).expect("in memory");
        let t = at.elapsed();
        drop((graft, state));
        [added, t]
    });

    // (b) The shards: the append a batch on the pool (wall, and summed as
    // the fleet's `shard_append_ms` reports it), the freeze's fold; (c) the
    // merge; (d) the roots' inputs from the merged bundle and from the view.
    let residual = BundleState::default();
    let [append_wall, append_sum, fold, merge, ops_merged, hashed_merged, view_build, ops_view, hashed_view] =
        run(&bundles, |copy| {
            let shards = OutputShards::new(beneficiary(), accounts, shards_n);
            let at = Instant::now();
            build_pool().install(|| copy.into_par_iter().for_each(|bundle| shards.add(bundle)));
            let append_wall = at.elapsed();
            let faults = minflt();
            let at = Instant::now();
            let frozen = shards.freeze();
            let fold = at.elapsed();
            FOLD_FAULTS.store(minflt() - faults, std::sync::atomic::Ordering::Relaxed);
            if let Ok(mut split) = FOLD_SPLIT.lock() {
                *split = format!("{:?}", frozen.fold_split());
            }
            let append_sum = Duration::from_millis(frozen.append_ms());
            let at = Instant::now();
            let merged = frozen.merged(&residual);
            let merge = at.elapsed();
            let at = Instant::now();
            let ops = n42_qmdb_reth::sorted_operations_from_execution(&merged, true);
            let ops_merged = at.elapsed();
            let at = Instant::now();
            let list: Vec<(&Address, &BundleAccount)> = merged.state.iter().collect();
            let hashed = hashed_post_state_of(&list);
            let hashed_merged = at.elapsed();
            drop((ops, hashed, list));
            let at = Instant::now();
            let overlaps = frozen.overlaps(&residual);
            let view = frozen.view(&residual, &overlaps);
            let view_build = at.elapsed();
            let at = Instant::now();
            let ops = n42_qmdb_reth::sorted_operations_from_accounts(&view, true);
            let ops_view = at.elapsed();
            let at = Instant::now();
            let hashed = hashed_post_state_of(&view);
            let hashed_view = at.elapsed();
            drop((ops, hashed, view));
            drop((merged, frozen));
            [append_wall, append_sum, fold, merge, ops_merged, hashed_merged, view_build, ops_view, hashed_view]
        });

    eprintln!("| path | median ms |");
    eprintln!("| --- | --- |");
    eprintln!("| graft (Direct) | {graft:.2} |");
    eprintln!("| staged add x16 / install | {staged_add:.2} / {staged_install:.2} |");
    eprintln!("| shards append wall / summed (1 ms granularity) | {append_wall:.2} / {append_sum:.0} |");
    eprintln!("| shards fold (freeze) | {fold:.2} (last round {} minor faults) |", FOLD_FAULTS.load(std::sync::atomic::Ordering::Relaxed));
    eprintln!("| fold split (last round) | {} |", FOLD_SPLIT.lock().map(|s| s.clone()).unwrap_or_default());
    eprintln!("| merge | {merge:.2} |");
    eprintln!("| roots from merged: qmdb ops / hashed | {ops_merged:.2} / {hashed_merged:.2} |");
    eprintln!("| roots from view: build / qmdb ops / hashed | {view_build:.2} / {ops_view:.2} / {hashed_view:.2} |");
}

/// The fleet's pipeline: block `k`'s merge and roots (the merge on the build
/// pool, the roots on the global pool) run behind its seal while block
/// `k + 1`'s batches append and freeze. The fold's wall under that load.
#[test]
#[ignore = "a timing benchmark: run it pinned, release, on a quiet box"]
fn bench_output_shards_fold_pipelined() {
    use rayon::prelude::*;
    let db = parent();
    let bundles = batch_bundles(&db);
    let accounts: usize = bundles.iter().map(|b| b.state.len()).sum();
    let residual = BundleState::default();
    let delay_ms: u64 = std::env::var("BENCH_BEHIND_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    // `BENCH_LOAD=<n>`: n threads walking a 64 MB buffer the whole time, the
    // node's other work (the ingest's recovery, the network, the roots of
    // other blocks) on the same cores.
    let load: usize = std::env::var("BENCH_LOAD").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loaders: Vec<_> = (0..load)
        .map(|i| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u64; 8 << 20];
                let mut x = i as u64 | 1;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for _ in 0..4096 {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        let at = (x as usize) & (buf.len() - 1);
                        buf[at] = buf[at].wrapping_add(x);
                    }
                }
                std::hint::black_box(buf);
            })
        })
        .collect();
    let mut grafts = Vec::new();
    let mut folds = Vec::new();
    let mut behind_times = Vec::new();
    let mut previous: Option<n42_engine_types::output_shards::FrozenShards> = None;
    for round in 0..WARMUPS + ROUNDS {
        let copy = bundles.to_vec();
        let shards = OutputShards::new(beneficiary(), accounts, 16);
        let (fold, behind) = std::thread::scope(|scope| {
            let behind = previous.take().map(|frozen| {
                let residual = &residual;
                scope.spawn(move || {
                    let at = Instant::now();
                    let merged = std::thread::scope(|inner| {
                        let merge = inner.spawn(|| frozen.merged(residual));
                        let overlaps = frozen.overlaps(residual);
                        let view = frozen.view(residual, &overlaps);
                        let ops = n42_qmdb_reth::sorted_operations_from_accounts(&view, true);
                        let hashed = hashed_post_state_of(&view);
                        drop((ops, hashed, view));
                        merge.join().expect("the merge")
                    });
                    let t = at.elapsed();
                    drop((merged, frozen));
                    t
                })
            });
            std::thread::sleep(Duration::from_millis(delay_ms));
            build_pool().install(|| copy.into_par_iter().for_each(|bundle| shards.add(bundle)));
            let at = Instant::now();
            let frozen = shards.freeze();
            let fold = at.elapsed();
            let behind = behind.map(|job| job.join().expect("the job behind the seal"));
            previous = Some(frozen);
            (fold, behind)
        });
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let copy = bundles.to_vec();
        let at = Instant::now();
        let graft = graft_bundles_folded(&mut state, copy, beneficiary(), false, GraftFold::Direct, None).expect("in memory");
        let graft_t = at.elapsed();
        drop((graft, state));
        if round >= WARMUPS {
            folds.push(fold);
            grafts.push(graft_t);
            behind_times.extend(behind);
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for loader in loaders {
        loader.join().expect("a load thread");
    }
    eprintln!(
        "pipelined (behind {delay_ms} ms, load {load}): fold median {:.2} ms (max {:.2}), graft median {:.2} ms, merge+roots behind median {:.2} ms",
        median(folds.clone()),
        folds.iter().max().map_or(0.0, |d| d.as_secs_f64() * 1e3),
        median(grafts),
        median(behind_times)
    );
}

/// The fleet's liveness (`docs/BREAKTHROUGH_DESIGN.md` 10.12): block `k`'s
/// frozen shards stay alive while block `k + 1` executes and folds (the
/// child's overlay holds them, the merge reads them), and the merged bundle
/// stays alive a few blocks (the executed-block cache); the batch maps are
/// cloned on the build pool as the execution would allocate them; block
/// `k`'s merge (its own thread) and roots (the global pool) run beside
/// block `k + 1`'s append and fold. `BENCH_HOLD=<n>` blocks' shards and
/// bundles are held (default 3); `BENCH_BEHIND_MS` delays the child behind
/// the parent's merge; `BENCH_NO_BEHIND=1` runs no merge or roots beside.
/// `BENCH_LOAD=<n>` runs n busy threads on the same cores. Run once as is
/// (a fresh map a shard, every block) and once with `N42_SHARD_RECYCLE=1`
/// (the maps recycled). Measured (16 cores, medians of 20; task wall / CPU
/// ms, minor faults a block): load 0 5.3-5.9 / 4.3, 9; load 16 20.4 / 8.3,
/// 2,055; load 24 26.6-27.2 / 9.0-9.3, ~2,000-2,400; load 32 31.3 / 8.5,
/// 2,117 -- the task's 40 ms on the fleet is reproduced by the cores being
/// shared (wall 2.5-3.7x its CPU, the CPU itself 2x), not by the maps'
/// allocation.
#[test]
#[ignore = "a timing benchmark: run it pinned, release, on a quiet box"]
fn bench_output_shards_fold_live() {
    use rayon::prelude::*;
    use std::sync::Arc;
    let db = parent();
    let bundles = batch_bundles(&db);
    let accounts: usize = bundles.iter().map(|b| b.state.len()).sum();
    let residual = Arc::new(BundleState::default());
    let hold: usize = std::env::var("BENCH_HOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let delay_ms: u64 = std::env::var("BENCH_BEHIND_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let behind_on = std::env::var("BENCH_NO_BEHIND").map_or(true, |v| v != "1");
    // `BENCH_LOAD=<n>`: n threads walking a 64 MB buffer the whole time (the
    // node's ingest, network and other blocks' work on the same cores).
    let load: usize = std::env::var("BENCH_LOAD").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loaders: Vec<_> = (0..load)
        .map(|i| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut buf = vec![0u64; 8 << 20];
                let mut x = i as u64 | 1;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for _ in 0..4096 {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        let at = (x as usize) & (buf.len() - 1);
                        buf[at] = buf[at].wrapping_add(x);
                    }
                }
                std::hint::black_box(buf);
            })
        })
        .collect();
    let mut held_shards: std::collections::VecDeque<Arc<n42_engine_types::output_shards::FrozenShards>> =
        Default::default();
    let held_merged: Arc<std::sync::Mutex<std::collections::VecDeque<BundleState>>> = Default::default();
    let (mut walls, mut tasks, mut cpus, mut fsum, mut fmax, mut migrated, mut behind_t, mut preempted) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for round in 0..WARMUPS + ROUNDS {
        let shards = OutputShards::new(beneficiary(), accounts, 16);
        let parent_shards = held_shards.back().cloned();
        let (fold, split, behind) = std::thread::scope(|scope| {
            let behind = parent_shards.filter(|_| behind_on).map(|frozen| {
                let residual = Arc::clone(&residual);
                let held_merged = Arc::clone(&held_merged);
                scope.spawn(move || {
                    let at = Instant::now();
                    let merged = std::thread::scope(|inner| {
                        let merge = inner.spawn(|| frozen.merged(&residual));
                        let overlaps = frozen.overlaps(&residual);
                        let view = frozen.view(&residual, &overlaps);
                        let ops = n42_qmdb_reth::sorted_operations_from_accounts(&view, true);
                        let hashed = hashed_post_state_of(&view);
                        drop((ops, hashed, view));
                        merge.join().expect("the merge")
                    });
                    let t = at.elapsed();
                    let mut kept = held_merged.lock().expect("the held bundles");
                    kept.push_back(merged);
                    while kept.len() > hold {
                        kept.pop_front();
                    }
                    t
                })
            });
            std::thread::sleep(Duration::from_millis(delay_ms));
            // The execution: the batch maps allocated on the pool's threads,
            // each handed to the shards as it ends.
            build_pool().install(|| bundles.par_iter().for_each(|bundle| shards.add(bundle.clone())));
            let at = Instant::now();
            let frozen = shards.freeze();
            let fold = at.elapsed();
            let split = frozen.fold_split();
            let behind = behind.map(|job| job.join().expect("the job behind the seal"));
            held_shards.push_back(Arc::new(frozen));
            while held_shards.len() > hold {
                held_shards.pop_front();
            }
            (fold, split, behind)
        });
        if round >= WARMUPS {
            walls.push(fold);
            tasks.push(Duration::from_micros(split.task_max_us));
            cpus.push(Duration::from_micros(split.task_cpu_max_us));
            fsum.push(split.task_minflt_sum);
            fmax.push(split.task_minflt_max);
            migrated.push(split.task_migrated);
            preempted.push(split.task_nivcsw_max);
            behind_t.extend(behind);
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for loader in loaders {
        loader.join().expect("a load thread");
    }
    let med = |mut v: Vec<u64>| {
        v.sort_unstable();
        v[v.len() / 2]
    };
    eprintln!(
        "live (hold {hold}, behind {delay_ms} ms, load {load}{}, recycle {}): fold wall median {:.2} ms, task_max {:.2}, task_cpu_max {:.2}, minflt sum {} / max {}, migrated {}, nivcsw max {}, merge+roots behind {:.2}",
        if behind_on { "" } else { ", no merge beside" },
        n42_engine_types::output_shards::shard_recycle(),
        median(walls),
        median(tasks),
        median(cpus),
        med(fsum),
        med(fmax),
        med(migrated),
        med(preempted),
        if behind_t.is_empty() { 0.0 } else { median(behind_t) }
    );
}

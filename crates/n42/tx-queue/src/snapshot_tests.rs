// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_QUEUE_PLAN_SNAPSHOT`: frame plans made off the lanes' lock from a
//! snapshot, checked per lane at commit. Every result is held against the
//! locked path's.

use super::offlock_tests::{assert_chain_valid, assert_counts, build, flood, seal, state};
use super::snapshot::{plan_from_snapshot, SnapMiss, GIVE_BACK_BATCH};
use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

fn queue(snapshot: bool) -> TxQueue<EthPooledTransaction> {
    TxQueue::new().with_offlock(snapshot).with_plan_snapshot(snapshot)
}

fn taken_pairs(segments: &[(FrameTxs<EthPooledTransaction>, usize)]) -> Vec<(Address, u64)> {
    segments.iter().flat_map(|(txs, n)| txs.iter().take(*n).map(|t| (t.sender(), t.nonce()))).collect()
}

/// Steps 1-3 on the queue as it stands: the frames, the lanes, the plan.
fn snapshot_plan(
    queue: &TxQueue<EthPooledTransaction>,
    gas: u64,
) -> (snapshot::PlanSnapshot<EthPooledTransaction>, Option<snapshot::SnapPlan<EthPooledTransaction>>) {
    let mut snap = queue.lock_inner_quiet().snapshot_frames(gas);
    assert!(queue.snapshot_lanes(&mut snap));
    let planned = plan_from_snapshot(&snap, gas).plan();
    (snap, planned)
}

fn chain(snapshot: bool, blocks: u64, gas: u64) -> (Vec<Vec<Tx>>, Vec<FrameSelectTimes>) {
    let queue = queue(snapshot);
    fill(&queue, 40, 12, 5, 0);
    flood(&queue, 200, 0, 6, 50);
    let mut parent = block_hash(0);
    let (mut out, mut times) = (Vec::new(), Vec::new());
    for n in 1..=blocks {
        let (txs, took) = build(&queue, parent, gas);
        let hash = block_hash(n);
        seal(&queue, parent, n, hash, &txs);
        assert_counts(&queue);
        parent = hash;
        out.push(txs);
        times.push(took);
    }
    (out, times)
}

/// A chain of builds, each with the child's plan prepared, makes the same
/// blocks from snapshots as under the lock, and every build after the first
/// uses its prepared plan.
#[test]
fn a_snapshot_chain_is_the_locked_chain() {
    for gas_txs in [7u64, 60, 333, 700] {
        let gas = gas_txs * 21_000;
        let (locked, _) = chain(false, 6, gas);
        let (snap, times) = chain(true, 6, gas);
        assert_eq!(
            locked.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            snap.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            "gas {gas_txs} txs"
        );
        assert_chain_valid(&snap);
        for (k, t) in times.iter().enumerate().skip(1) {
            if !snap[k].is_empty() {
                assert!(t.ahead >= 1, "gas {gas_txs}: block {} planned afresh: {t:?}", k + 1);
            }
        }
    }
}

/// On one state, the plan made from a snapshot is the plan the locked
/// parallel part makes: the same frames, prefixes, gas and transactions,
/// with mixed frames (a sender drawn on by several frames) among them.
#[test]
fn the_snapshot_plan_is_the_locked_plan_on_the_same_state() {
    let mut compared = 0;
    for gas_txs in [7u64, 60, 333, 700, 5_000] {
        let gas = gas_txs * 21_000;
        let queue = queue(true);
        fill(&queue, 40, 12, 5, 0);
        flood(&queue, 200, 0, 6, 50);
        queue.drain_now();
        let (_, planned) = snapshot_plan(&queue, gas);
        let mut inner = queue.lock_inner();
        let mut times = FrameSelectTimes::default();
        let (segments, plan, gas_left) = inner.plan_frames(gas, &mut times, SelectMode::Parallel);
        let Some(planned) = planned else {
            // Only when the locked plan needed its serial part.
            assert!(times.slow > 0 || gas_left > 0, "gas {gas_txs}: no snapshot plan for a parallel-only plan");
            continue;
        };
        assert_eq!(planned.plan.frames, plan.frames, "gas {gas_txs}: frames");
        assert_eq!(planned.plan.skipped, plan.skipped, "gas {gas_txs}: skipped");
        assert_eq!(planned.gas_left, gas_left, "gas {gas_txs}: gas left");
        assert_eq!(taken_pairs(&planned.segments), taken_pairs(&segments), "gas {gas_txs}: transactions");
        assert_eq!(pairs(&planned.taken), taken_pairs(&segments));
        compared += 1;
    }
    assert!(compared >= 4, "only {compared} plans compared");
}

/// A lane the plan took from moves between the snapshot and the commit (a
/// nonce below the plan's arrives): the commit names that lane alone, the
/// lane is read again, and the plan made again is the locked plan on the
/// queue as it now stands.
#[test]
fn a_lane_the_plan_took_from_that_moved_is_a_miss_and_is_planned_again() {
    let gas = 300 * 21_000;
    let hole = sender(0);
    let queue = queue(true);
    flood(&queue, 200, 1, 6, 50);
    queue.drain_now();
    let (mut snap, planned) = snapshot_plan(&queue, gas);
    let planned = planned.expect("a plan");
    assert!(pairs(&planned.taken).contains(&(hole, 1)), "the plan takes the lane that will move");
    // The hole below the plan's first nonce of that sender is filled.
    queue.push([tx_hashed(hole, 0)]);
    queue.drain_now();
    let replanned = {
        let inner = queue.lock_inner_quiet();
        assert_eq!(inner.snapshot_verdict(&planned, snap.builds), Err(SnapMiss::Lanes(vec![hole])));
        snap.refresh(&inner.lanes, &[hole]);
        drop(inner);
        plan_from_snapshot(&snap, gas).plan().expect("a plan again")
    };
    let inner = queue.lock_inner_quiet();
    assert_eq!(inner.snapshot_verdict(&replanned, snap.builds), Ok(()));
    drop(inner);
    assert_eq!(queue.commit_prepare_batched(&replanned, snap.builds, gas, std::time::Instant::now(), None), Ok(()));
    let inner = queue.lock_inner_quiet();
    let got = pairs(&inner.prepared.as_ref().expect("stored").taken);
    drop(inner);
    assert!(!got.iter().any(|(who, _)| *who == hole), "a frame of the moved lane is no longer whole at its head");
    assert_counts(&queue);

    // The locked preparation on the same state.
    let twin = TxQueue::<EthPooledTransaction>::new().with_offlock(false);
    flood(&twin, 200, 1, 6, 50);
    twin.push([tx_hashed(hole, 0)]);
    twin.drain_now();
    assert!(twin.prepare_next_locked(gas, SelectMode::Parallel));
    let expected = pairs(&twin.lock_inner_quiet().prepared.as_ref().expect("stored").taken);
    assert_eq!(got, expected);
    assert_eq!(state(&queue), state(&twin));
}

/// Arrivals into lanes the plan did not take from, or above the nonces it
/// took, are not a miss: the plan commits as made and the arrivals stay
/// queued.
#[test]
fn an_arrival_into_another_lane_is_not_a_miss() {
    let gas = 300 * 21_000;
    let queue = queue(true);
    flood(&queue, 200, 0, 6, 50);
    queue.drain_now();
    let (snap, planned) = snapshot_plan(&queue, gas);
    let planned = planned.expect("a plan");
    let before = queue.len();
    queue.push([tx_hashed(sender(10_000), 0), tx_hashed(sender(0), 40)]);
    queue.drain_now();
    assert_eq!(queue.len(), before + 2);
    let inner = queue.lock_inner_quiet();
    assert_eq!(inner.snapshot_verdict(&planned, snap.builds), Ok(()));
    drop(inner);
    assert_eq!(queue.commit_prepare_batched(&planned, snap.builds, gas, std::time::Instant::now(), None), Ok(()));
    let inner = queue.lock_inner_quiet();
    assert_eq!(pairs(&inner.prepared.as_ref().expect("stored").taken), pairs(&planned.taken));
    drop(inner);
    assert_eq!(queue.len(), before + 2 - planned.taken.len());
    assert_counts(&queue);
}

/// What a queue's arrival order holds.
fn arrivals(queue: &TxQueue<EthPooledTransaction>) -> Vec<Address> {
    queue.lock_inner_quiet().arrivals.iter().copied().collect()
}

/// A build whose prepared plan is unusable (not on its parent) gives the
/// plan back in batches -- more than one here -- and plans afresh: the
/// lanes, the depth, the arrival order and the build's transactions are the
/// one-hold path's.
#[test]
fn the_discarded_plan_path_leaves_the_lanes_as_the_one_hold_path() {
    // Whole frames of 50: no frame cut, so the child plan is as large.
    let gas_txs = (GIVE_BACK_BATCH as u64 / 200 + 3) * 200;
    let gas = gas_txs * 21_000;
    let run = |snapshot: bool| {
        let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(true).with_plan_snapshot(snapshot);
        flood(&queue, 200, 0, 2 * gas_txs / 200 + 10, 50);
        let p0 = block_hash(0);
        let (txs, _) = build(&queue, p0, gas);
        assert_eq!(txs.len() as u64, gas_txs);
        seal(&queue, p0, 1, block_hash(1), &txs);
        let prepared = queue.lock_inner_quiet().prepared.as_ref().map(|prepared| prepared.taken.len());
        assert!(prepared.is_some_and(|n| n > GIVE_BACK_BATCH), "a plan large enough for several batches: {prepared:?} queued {}", queue.len());
        let (mut best, _, times) = queue.frames_for_build_ahead(B256::repeat_byte(0xee), gas, SelectMode::Parallel, false);
        assert_eq!(times.ahead_discard, Some(AheadDiscard::NotOnItsParent));
        let next: Vec<Tx> = best.by_ref().collect();
        let after = (state(&queue), arrivals(&queue));
        drop(best);
        assert_counts(&queue);
        (pairs(&next), after)
    };
    let (locked, locked_state) = run(false);
    let (snap, snap_state) = run(true);
    assert_eq!(snap, locked, "the fresh plan");
    assert_eq!(snap_state, locked_state, "the lanes, depth, index, take and arrival order");
}

/// A usable prepared plan with room left is topped up from a snapshot with
/// what arrived since, as the locked top-up does.
#[test]
fn a_topped_up_prepared_plan_is_the_locked_top_up() {
    let gas = 300 * 21_000;
    let run = |snapshot: bool| {
        let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(true).with_plan_snapshot(snapshot);
        flood(&queue, 200, 0, 2, 50);
        let p0 = block_hash(0);
        let (txs, _) = build(&queue, p0, gas);
        assert_eq!(txs.len(), 300);
        flood(&queue, 200, 2, 2, 50);
        seal(&queue, p0, 1, block_hash(1), &txs);
        let (mut best, _, times) = queue.frames_for_build_ahead(block_hash(1), gas, SelectMode::Parallel, false);
        assert_eq!(times.ahead, 2, "topped up: {times:?}");
        let next: Vec<Tx> = best.by_ref().collect();
        drop(best);
        assert_counts(&queue);
        (pairs(&next), state(&queue), arrivals(&queue))
    };
    assert_eq!(run(true), run(false));
}

/// The longest hold of the lanes' lock in each step of a bench-tier chain
/// (`N42_BENCH_SENDERS` senders, default 100,000, four rounds in frames of
/// 500; blocks of 200,000 transfers), one hold path against the snapshot
/// path: the build, the child's preparation, a build whose prepared plan is
/// discarded, and a build that uses its plan.
/// `cargo test -p n42-tx-queue --release --lib -- --ignored bench_plan_snapshot_holds --nocapture`.
#[test]
#[ignore]
fn bench_plan_snapshot_holds() {
    let senders: u64 = std::env::var("N42_BENCH_SENDERS").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let gas = 2 * senders * 21_000;
    for snapshot in [false, true] {
        let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(true).with_plan_snapshot(snapshot);
        flood(&queue, senders, 0, 8, 500);
        queue.drain_now();
        let step = |name: &str| {
            let stats = take_lock_stats();
            eprintln!(
                "snapshot={snapshot} {name:>10}: holds {:>5} longest {:>8.2} ms at {:?}, total {:>8.2} ms",
                stats.holds,
                stats.hold_max_ns as f64 / 1e6,
                stats.hold_max_at.map(|at| at.line()),
                stats.hold_ns as f64 / 1e6
            );
        };
        let p0 = block_hash(0);
        take_lock_stats();
        let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
        let txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        drop(queue.lock_inner_quiet());
        step("build");
        queue.prepare_next_in(gas, SelectMode::Parallel);
        step("prepare");
        seal(&queue, p0, 1, block_hash(1), &txs);
        take_lock_stats();
        let (mut best, _, times) = queue.frames_for_build_ahead(B256::repeat_byte(0xee), gas, SelectMode::Parallel, false);
        let txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        drop(queue.lock_inner_quiet());
        assert!(times.ahead_discard.is_some());
        step("discarded");
        queue.prepare_next_in(gas, SelectMode::Parallel);
        seal(&queue, B256::repeat_byte(0xee), 2, block_hash(2), &txs);
        take_lock_stats();
        let (mut best, _, times) = queue.frames_for_build_ahead(block_hash(2), gas, SelectMode::Parallel, false);
        let _: Vec<Tx> = best.by_ref().collect();
        drop(best);
        drop(queue.lock_inner_quiet());
        step(if times.ahead >= 1 { "used" } else { "unused" });
    }
}

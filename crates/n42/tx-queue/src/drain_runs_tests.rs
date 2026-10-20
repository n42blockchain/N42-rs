// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_TX_QUEUE_DRAIN_RUNS`: the grouped drain held against the
//! per-transaction drain on the same sequence.

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

type Lanes = Vec<(Address, Vec<(u64, B256)>, bool, Option<u64>, Option<u64>)>;

/// Everything a drain can change: the lanes (nonces, hashes, queued,
/// watermarks), the arrival order, the depth and the parked depth, the drop
/// report, the frame index, the remainder counters, the by-hash index and
/// the depth mirror.
#[derive(Debug, PartialEq, Eq)]
struct State {
    lanes: Lanes,
    arrivals: Vec<Address>,
    len: usize,
    parked_len: usize,
    drops: DropReport,
    frames: Vec<B256>,
    frames_len: usize,
    pending: (usize, u64, u64, usize),
    hash_index: usize,
    gate: usize,
}

fn state(queue: &TxQueue<EthPooledTransaction>) -> State {
    let inner = queue.lock_inner_quiet();
    let mut lanes: Lanes = inner
        .lanes
        .iter()
        .map(|(sender, lane)| {
            let txs = lane.by_nonce.iter().map(|(nonce, t)| (*nonce, *t.hash())).collect();
            (*sender, txs, lane.queued, lane.mined, lane.chain_mined)
        })
        .collect();
    lanes.sort();
    let state = State {
        lanes,
        arrivals: inner.arrivals.iter().copied().collect(),
        len: inner.len,
        parked_len: inner.parked_len,
        drops: inner.drops.clone(),
        frames: inner.frames.ids_in_arrival_order(),
        frames_len: inner.frames.len(),
        pending: (inner.pending_drain.len(), inner.pending_in, inner.pending_out, inner.pending_frames.len()),
        hash_index: 0,
        gate: 0,
    };
    drop(inner);
    State { hash_index: queue.hash_index_len(), gate: queue.gate_len(), ..state }
}

/// Frames of interleaved senders, mixed frames, loose transactions out of
/// nonce order, duplicates (one a sender's first arrival in its slice, so
/// its arrival-order entry is not its first transaction), a chain-mined and
/// a build-refused watermark with arrivals at and below them.
fn scenario(queue: &TxQueue<EthPooledTransaction>) {
    fill(queue, 25, 6, 4, 0);
    queue.push((0..25u64).rev().map(|s| tx_hashed(sender(s), 25)).collect::<Vec<_>>());
    queue.push((0..25u64).map(|s| tx_hashed(sender(s), 24)).collect::<Vec<_>>());
    queue.push([tx_hashed(sender(3), 0), tx_hashed(sender(7), 30), tx_hashed(sender(7), 28), tx_hashed(sender(7), 30)]);
    queue.remove_mined(sender(4), 1);
    {
        let mut inner = queue.lock_inner_quiet();
        queue.drain_inbox(&mut inner);
        inner.remove_mined_from(sender(6), 2, false);
        // A lane out of the arrival order with a watermark: its first
        // arrival below is refused, so it enters the order behind a sender
        // that arrived after it.
        let lane = Lane { by_nonce: BTreeMap::new(), queued: false, mined: Some(5), chain_mined: Some(5), parked: None, road: 0 };
        inner.lanes.insert(sender(910), lane);
    }
    queue.push([tx_hashed(sender(910), 3), tx_hashed(sender(911), 0), tx_hashed(sender(910), 7)]);
    queue.push([
        tx_hashed(sender(4), 1),
        tx_hashed(sender(4), 0),
        tx_hashed(sender(6), 2),
        tx_hashed(sender(6), 1),
        tx_hashed(sender(900), 3),
        tx_hashed(sender(901), 0),
        tx_hashed(sender(900), 2),
    ]);
    // A sender whose first arrival is a duplicate and whose next one is new,
    // behind a sender with no lane yet.
    queue.push([tx_hashed(sender(902), 0), tx_hashed(sender(5), 0), tx_hashed(sender(902), 1), tx_hashed(sender(5), 99)]);
    fill(queue, 25, 2, 4, 6);
}

fn run(runs: bool, offlock: bool, chunk: usize) -> State {
    let queue: TxQueue<EthPooledTransaction> =
        TxQueue::new().with_offlock(offlock).with_drain_chunk(chunk).with_drain_runs(runs);
    scenario(&queue);
    queue.drain_now();
    state(&queue)
}

#[test]
fn a_grouped_drain_is_the_per_transaction_drain() {
    for offlock in [false, true] {
        for chunk in [1usize, 3, 7, 64, 100_000] {
            let plain = run(false, offlock, chunk);
            let grouped = run(true, offlock, chunk);
            assert!(plain.drops.counts[Dropped::Duplicate.index()] > 0);
            assert!(plain.drops.counts[Dropped::Mined.index()] > 0);
            assert!(plain.drops.counts[Dropped::StaleArrival.index()] > 0);
            assert_eq!(plain.pending.0, 0);
            assert_eq!(grouped, plain, "offlock={offlock} chunk={chunk}");
        }
    }
}

/// Grouping keeps a sender's arrivals in nonce order and the first of two
/// duplicates first, and the senders in the order of their first arrival.
#[test]
fn group_runs_is_stable_and_nonce_ordered() {
    let (a, b) = (sender(1), sender(2));
    let keyed = |s: Address, n: u64| {
        let valid = valid_for(tx_hashed(s, n), std::time::Instant::now(), TransactionOrigin::External);
        Keyed { sender: s, nonce: n, valid }
    };
    let batch = vec![keyed(b, 5), keyed(a, 2), keyed(b, 3), keyed(a, 2), keyed(a, 1), keyed(b, 4)];
    let first_dup = Arc::as_ptr(&batch[1].valid);
    let grouped = group_runs(batch);
    let order: Vec<(Address, u64)> = grouped.items.iter().map(|k| (k.sender, k.nonce)).collect();
    assert_eq!(order, vec![(b, 3), (b, 4), (b, 5), (a, 1), (a, 2), (a, 2)]);
    assert_eq!(grouped.meta.ends, vec![3, 6]);
    assert_eq!(grouped.meta.pos, vec![2, 5, 0, 4, 1, 3]);
    assert_eq!(Arc::as_ptr(&grouped.items[4].valid), first_dup);
}

/// A remainder of grouped slices with a plain stretch behind it (a block
/// path's drain taking newer arrivals while the drainer is part-way), and a
/// parked lane whose hole a grouped slice fills: the same queue as the
/// per-transaction drain in the same holds.
#[test]
fn a_grouped_remainder_and_a_parked_lane_match_the_plain_path() {
    let sequence = |runs: bool| {
        let queue: TxQueue<EthPooledTransaction> =
            TxQueue::new().with_drain_chunk(5).with_drain_runs(runs).with_park_lanes(4);
        fill(&queue, 6, 2, 3, 0);
        queue.drain_now();
        {
            let mut inner = queue.lock_inner_quiet();
            // Sender 2's lane holds 0..=5; parked waiting for 6, which the
            // next push brings after an 8.
            inner.park(sender(2), 6);
            assert!(!inner.parked_order.is_empty());
        }
        queue.push([tx_hashed(sender(2), 8), tx_hashed(sender(1), 6), tx_hashed(sender(2), 6), tx_hashed(sender(3), 6)]);
        fill(&queue, 6, 2, 3, 2);
        let holds = queue.drain_chunked(5, 2);
        assert_eq!(holds.len(), 2);
        // Newer arrivals, drained by a holder that does not group.
        queue.push((0..6u64).map(|s| tx_hashed(sender(s), 40)).collect::<Vec<_>>());
        {
            let mut inner = queue.lock_inner_quiet();
            queue.drain_inbox_upto(&mut inner, 3);
        }
        queue.drain_chunked(5, usize::MAX);
        let mut inner = queue.lock_inner_quiet();
        queue.drain_inbox(&mut inner);
        assert!(inner.pending_segs.is_empty() || inner.pending_drain.is_empty());
        drop(inner);
        state(&queue)
    };
    let (plain, grouped) = (sequence(false), sequence(true));
    assert_eq!(plain.pending.0, 0);
    assert_eq!(grouped, plain);
}

/// While a grouped drain holds the gate (its batch off the lock), another
/// hold leaves the inbox and the frame inbox alone.
#[test]
fn a_held_gate_keeps_other_drains_off_the_inbox() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_runs(true);
    frame(&queue, sender(1), 0, 4);
    let gate = queue.drain_gate.lock();
    {
        let mut inner = queue.lock_inner_quiet();
        assert_eq!(queue.drain_inbox_upto(&mut inner, usize::MAX), 0);
        assert_eq!(inner.len, 0);
    }
    drop(gate);
    let mut inner = queue.lock_inner_quiet();
    assert_eq!(queue.drain_inbox_upto(&mut inner, usize::MAX), 4);
    assert_eq!(inner.frames.len(), 1);
}

/// The grouped drain counts its runs and grouping time.
#[test]
fn a_grouped_drain_counts_its_runs() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_chunk(1_000).with_drain_runs(true);
    fill(&queue, 50, 4, 10, 0);
    let before = LOCK_COUNTERS.drain_run_txs.load(std::sync::atomic::Ordering::Relaxed);
    let holds = queue.drain_chunked(1_000, usize::MAX);
    assert!(holds.iter().all(|moved| *moved <= 1_000), "{holds:?}");
    let after = LOCK_COUNTERS.drain_run_txs.load(std::sync::atomic::Ordering::Relaxed);
    assert!(after - before >= holds.iter().sum::<u64>());
    assert!(queue.lock_inner_quiet().pending_segs.is_empty());
}

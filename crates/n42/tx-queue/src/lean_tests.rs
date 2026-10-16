// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_HANDOFF_DONE_FIRST`'s folded hold and `N42_PRUNE_LEAN`'s folded
//! prune, each held against the default path on the same sequence.

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

/// What a hold sequence leaves: the drop report, the held blocks and the
/// lanes' depth.
fn hold_state(queue: &TxQueue<EthPooledTransaction>) -> (DropReport, Vec<(u64, B256, usize)>, usize) {
    let len = queue.lock_inner_quiet().len;
    (queue.drops_view(), queue.held_view(), len)
}

fn hold_sequence(lean: bool) -> ((DropReport, Vec<(u64, B256, usize)>, usize), usize) {
    let queue = TxQueue::<EthPooledTransaction>::new();
    let blocks = own_hold_blocks() as u64 + 3;
    fill(&queue, 40, blocks, 1, 0);
    let mut evicted = 0;
    for n in 1..=blocks {
        let mined: Vec<(Address, u64)> = (0..40).map(|s| (sender(s), n - 1)).collect();
        // Sorted: the collecting removal's order follows a hash map's.
        let mut removed = queue.remove_mined_batch_collecting(mined);
        removed.sort_by_key(|t| (t.sender(), t.nonce()));
        assert_eq!(removed.len(), 40);
        evicted += queue.hold_own_block_with(n, block_hash(n), removed, lean).evicted;
    }
    (hold_state(&queue), evicted)
}

#[test]
fn lean_hold_matches_the_default_hold() {
    let (lean, lean_evicted) = hold_sequence(true);
    let (plain, plain_evicted) = hold_sequence(false);
    assert_eq!(lean_evicted, 3 * 40, "three blocks evicted past the bound");
    assert_eq!(lean_evicted, plain_evicted);
    assert_eq!(lean.0.counts[Dropped::HeldEvicted.index()], 120);
    assert_eq!(lean.0.samples.len(), DROP_SAMPLES);
    assert_eq!(lean, plain);
}

/// Each lane's nonces and watermarks, the lanes' depth, the by-hash index's
/// size and what is held, after the inbox is drained.
type PruneState = (Vec<(Address, Vec<u64>, Option<u64>, Option<u64>)>, usize, usize, Vec<(u64, B256, usize)>);

fn prune_state(queue: &TxQueue<EthPooledTransaction>) -> PruneState {
    let mut inner = queue.lock_inner_quiet();
    queue.drain_inbox(&mut inner);
    let mut lanes: Vec<_> = inner
        .lanes
        .iter()
        .map(|(sender, lane)| (*sender, lane.by_nonce.keys().copied().collect(), lane.mined, lane.chain_mined))
        .collect();
    lanes.sort();
    let len = inner.len;
    drop(inner);
    let held = queue.held_view();
    (lanes, len, queue.hash_index_len(), held)
}

/// Four canonical blocks over a queue whose inbox still holds what the
/// blocks mine, an own block held at height 2 that is not the committed one
/// (its settle gives back), and a sender whose only transactions are in the
/// inbox: pruned block by block, or folded (`lean`).
fn prune_sequence(lean: bool, offlock: bool) -> (PruneState, usize) {
    let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(offlock);
    fill(&queue, 40, 6, 3, 0);
    let own: Vec<(Address, u64)> = (0..10).map(|s| (sender(s), 5)).collect();
    let mut held = queue.remove_mined_batch_collecting(own);
    held.sort_by_key(|t| (t.sender(), t.nonce()));
    queue.hold_own_block(2, B256::repeat_byte(0xEE), held);
    // Left in the inbox: later rounds, and a sender with no lane yet.
    fill(&queue, 40, 2, 3, 6);
    frame(&queue, sender(5_000), 0, 4);
    let blocks: Vec<(u64, Vec<(Address, u64)>, Vec<B256>)> = (1..=4u64)
        .map(|n| {
            let mut mined: Vec<(Address, u64)> = (0..40u64)
                .filter(|s| s % 5 != n)
                .flat_map(|s| (3 * (n - 1)..3 * n).map(move |nonce| (sender(s), nonce)))
                .collect();
            mined.push((sender(5_000), n - 1));
            let hashes = mined.iter().map(|(s, nonce)| *tx_hashed(*s, *nonce).hash()).collect();
            (n, mined, hashes)
        })
        .collect();
    let back = if lean {
        let inputs: Vec<PruneInput<'_>> = blocks
            .iter()
            .map(|(n, mined, hashes)| PruneInput { number: *n, hash: block_hash(*n), mined, hashes })
            .collect();
        let (back, times) = queue.prune_blocks(&inputs);
        assert_eq!(times.folded, 4);
        assert_eq!(times.removals, 2, "the run is cut before the settle that gives back");
        back
    } else {
        blocks.iter().map(|(n, mined, hashes)| queue.prune_block(*n, block_hash(*n), mined, hashes).0).sum()
    };
    (prune_state(&queue), back)
}

#[test]
fn lean_prune_matches_the_per_block_prune() {
    for offlock in [false, true] {
        let (lean, lean_back) = prune_sequence(true, offlock);
        let (plain, plain_back) = prune_sequence(false, offlock);
        assert!(plain_back > 0, "the own block at height 2 gives back");
        assert_eq!(lean_back, plain_back, "offlock={offlock}");
        assert_eq!(lean, plain, "offlock={offlock}");
    }
}

/// The census follows a frame from the inbox to the live index and aside at
/// a whole take, and counts a re-sent frame refused while it is aside.
#[test]
fn the_frame_census_follows_a_frame_from_arrival_to_aside() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_frame_sweep_at_take(true);
    frame(&queue, sender(1), 0, 4);
    frame(&queue, sender(2), 0, 4);
    queue.drain_now();
    let census = queue.frame_census();
    assert_eq!((census.live, census.aside, census.pending, census.inserted), (2, 0, 0, 2));
    let (mut best, plan, _) = queue.frames_for_build_ahead(block_hash(0), 4 * 21_000, SelectMode::Parallel, false);
    assert_eq!(plan.tx_count(), 4);
    assert_eq!(best.by_ref().count(), 4);
    drop(best);
    let census = queue.frame_census();
    assert_eq!((census.live, census.aside), (1, 1));
    // The taken frame again, while it is aside: refused, its id known.
    let taken = plan.frames[0].id;
    let who = if taken == frame_id(sender(1), 0) { sender(1) } else { sender(2) };
    frame(&queue, who, 0, 4);
    queue.drain_now();
    let census = queue.frame_census();
    assert_eq!((census.live, census.aside, census.refused), (1, 1, 1));
}

/// The starvation of loop351 bw's lean leg: frames for senders whose
/// earlier nonces a folded wake prunes, still in a chunked drain's
/// remainder when the wake comes. The per-block prune's first hold drained
/// them all; the lean prune must leave every one of them indexed too, not
/// pending until the drainer's bounded holds reach them.
#[test]
fn lean_prune_indexes_the_frames_a_remainder_holds() {
    for offlock in [false, true] {
        let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(offlock).with_drain_chunk(3);
        // Nonces 0..4 of 30 senders, in their lanes.
        for s in 0..30 {
            frame(&queue, sender(s), 0, 4);
        }
        queue.drain_now();
        // Nonces 4..8 arrive; one chunked hold leaves the rest pending.
        for s in 0..30 {
            frame(&queue, sender(s), 4, 4);
        }
        let _ = queue.drain_chunked(3, 1);
        let before = queue.frame_census();
        assert!(before.pending > 20, "offlock={offlock}: a remainder is pending ({before:?})");
        // Two blocks folded into one wake mine nonces 0..4 of every sender.
        let blocks: Vec<(u64, Vec<(Address, u64)>, Vec<B256>)> = (1..=2u64)
            .map(|n| {
                let mined: Vec<(Address, u64)> =
                    (0..30).flat_map(|s| (2 * (n - 1)..2 * n).map(move |nonce| (sender(s), nonce))).collect();
                let hashes = mined.iter().map(|(s, nonce)| *tx_hashed(*s, *nonce).hash()).collect();
                (n, mined, hashes)
            })
            .collect();
        let inputs: Vec<PruneInput<'_>> = blocks
            .iter()
            .map(|(n, mined, hashes)| PruneInput { number: *n, hash: block_hash(*n), mined, hashes })
            .collect();
        let (_, times) = queue.prune_blocks(&inputs);
        assert_eq!(times.removals, 1);
        let census = queue.frame_census();
        assert_eq!(census.pending, 0, "offlock={offlock}: nothing left pending ({census:?})");
        assert_eq!(census.live, 30, "offlock={offlock}: every later frame indexed ({census:?})");
        assert_eq!(queue.len(), 30 * 4, "offlock={offlock}");
        assert!(times.drained > 0 && times.drain_holds > 1, "offlock={offlock}: {times:?}");
    }
}

/// loop351 by's lean legs: a pruner behind the engine folded more blocks a
/// wake and drained everything that had piled up since the last one, until
/// a wake drained 1.1M transactions in 135 holds. A wake's drain is bounded
/// by its blocks ([`lean_drain_budget`] each, [`LEAN_DRAIN_WAKE_MAX`] in
/// all), whatever the remainder holds; the rest stays pending, in order, for
/// the drainer, which indexes every frame once it is through.
#[test]
fn lean_prune_drains_a_bounded_share_a_wake() {
    for offlock in [false, true] {
        let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(offlock).with_drain_chunk(DRAINER_SLICE);
        let senders = 64u64;
        for s in 0..senders {
            frame(&queue, sender(s), 0, 4);
        }
        queue.drain_now();
        // 64 x 800 transactions arrive and stay in the remainder.
        for s in 0..senders {
            frame(&queue, sender(s), 4, 800);
        }
        let _ = queue.drain_chunked(DRAINER_SLICE, 1);
        let pending = |queue: &TxQueue<EthPooledTransaction>| queue.lock_inner_quiet().pending_drain.len();
        let deep = pending(&queue);
        assert!(deep > 2 * LEAN_DRAIN_PER_BLOCK, "offlock={offlock}: a deep remainder ({deep})");
        let wake = |numbers: std::ops::RangeInclusive<u64>| {
            let blocks: Vec<(u64, Vec<(Address, u64)>, Vec<B256>)> = numbers
                .map(|n| {
                    let mined: Vec<(Address, u64)> = (0..senders).map(|s| (sender(s), n - 1)).collect();
                    let hashes = mined.iter().map(|(s, nonce)| *tx_hashed(*s, *nonce).hash()).collect();
                    (n, mined, hashes)
                })
                .collect();
            let inputs: Vec<PruneInput<'_>> = blocks
                .iter()
                .map(|(n, mined, hashes)| PruneInput { number: *n, hash: block_hash(*n), mined, hashes })
                .collect();
            queue.prune_blocks(&inputs).1
        };
        // One block: one block's budget, the rest left pending.
        let times = wake(1..=1);
        assert!(times.drained <= LEAN_DRAIN_PER_BLOCK, "offlock={offlock}: {times:?}");
        assert!(times.drain_holds <= LEAN_DRAIN_PER_BLOCK.div_ceil(DRAINER_SLICE), "offlock={offlock}: {times:?}");
        assert_eq!(pending(&queue), deep - times.drained, "offlock={offlock}");
        // Three blocks folded: three blocks' budget, never past the cap.
        let before = pending(&queue);
        let times = wake(2..=4);
        assert!(times.drained <= (3 * LEAN_DRAIN_PER_BLOCK).min(LEAN_DRAIN_WAKE_MAX), "offlock={offlock}: {times:?}");
        assert_eq!(pending(&queue), before - times.drained, "offlock={offlock}");
        // The drainer's share: every frame indexed once the remainder is in.
        {
            let mut inner = queue.lock_inner_quiet();
            queue.drain_inbox(&mut inner);
        }
        let census = queue.frame_census();
        assert_eq!(census.pending, 0, "offlock={offlock}: {census:?}");
        assert_eq!(census.live, senders as usize, "offlock={offlock}: {census:?}");
        assert_eq!(queue.len(), (senders * 800) as usize, "offlock={offlock}");
    }
}

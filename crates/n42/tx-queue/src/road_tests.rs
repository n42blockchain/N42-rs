// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The frame road (`N42_FRAME_ROAD`, `docs/FRAME_ROAD_DESIGN.md`):
//! admission and seeding, and that counting it changes nothing a build
//! sees.

use super::offlock_tests::{assert_chain_valid, flood};
use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

fn queue(mode: RoadMode) -> TxQueue<EthPooledTransaction> {
    TxQueue::with_run_length(64).with_frame_road(mode)
}

/// A frame of `members` in their order, through the ingest's door.
fn push_members(queue: &TxQueue<EthPooledTransaction>, members: &[(Address, u64)], salt: u64) -> B256 {
    let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
    let id = frame_id(members[0].0, members[0].1.wrapping_mul(7_919) ^ salt);
    queue.push_frame(
        txs,
        Some(NewFrame { id, hashes, members: members.to_vec(), gas: 21_000 * members.len() as u64 }),
    );
    id
}

/// Builds `blocks` blocks of `gas`, each sealed and handed off as an own
/// block, and returns their transactions.
fn chain_of(queue: &TxQueue<EthPooledTransaction>, blocks: u64, gas: u64) -> Vec<Vec<Tx>> {
    let mut parent = block_hash(0);
    let mut out = Vec::new();
    for n in 1..=blocks {
        let (best, _plan) = queue.frames_for_build(parent, gas);
        let txs: Vec<Tx> = best.collect();
        let body = pairs(&txs);
        let (dropped, _) = queue.forget_mined_parallel(parent, body.len(), |i| body[i]);
        let hash = block_hash(n);
        queue.hold_own_block(n, hash, dropped);
        parent = hash;
        out.push(txs);
    }
    out
}

/// Stage 0: aligned frames are admitted once their senders are seeded,
/// and every build is the build the queue without a road makes.
#[test]
fn counting_the_road_admits_the_flood_and_changes_no_build() {
    let off = queue(RoadMode::Off);
    let counted = queue(RoadMode::Count);
    for q in [&off, &counted] {
        flood(q, 120, 0, 8, 40);
    }
    let a = chain_of(&off, 5, 150 * 21_000);
    let b = chain_of(&counted, 5, 150 * 21_000);
    assert_eq!(a.iter().map(|b| pairs(b)).collect::<Vec<_>>(), b.iter().map(|b| pairs(b)).collect::<Vec<_>>());
    assert_chain_valid(&b);
    let stats = counted.road_stats();
    // 8 rounds of 120 senders in frames of 40: 24 frames, every one aligned.
    assert_eq!((stats.frames, stats.txs), (24, 960), "{stats:?}");
    assert_eq!(stats.seeded, 120, "{stats:?}");
    assert_eq!(
        (stats.refused_unknown, stats.refused_gap, stats.refused_no_frame, stats.refused_dup_sender, stats.flushes),
        (0, 0, 0, 0, 0),
        "{stats:?}"
    );
    assert_eq!(off.road_stats(), RoadStats::default());
    assert_eq!(counted.road.senders(), 120);
    assert_eq!(counted.road.sender(&sender(7)).map(|s| s.next), Some(8));
}

/// A sender the lanes already hold joins at its lane's highest nonce + 1,
/// in one hold for all of the frame's new senders.
#[test]
fn a_sender_joins_at_its_lane_tail() {
    let q = queue(RoadMode::Off);
    // Lanes' arrivals before the road is on.
    push_members(&q, &[(sender(1), 0), (sender(2), 0)], 1);
    push_members(&q, &[(sender(1), 1), (sender(2), 1), (sender(3), 0)], 2);
    let q = q.with_frame_road(RoadMode::Count);
    push_members(&q, &[(sender(1), 2), (sender(2), 2), (sender(3), 1), (sender(4), 0)], 3);
    let stats = q.road_stats();
    assert_eq!((stats.frames, stats.seeded, stats.seed_holds), (1, 4, 1), "{stats:?}");
    assert_eq!(q.road.sender(&sender(1)).map(|s| s.next), Some(3));
    assert_eq!(q.road.sender(&sender(3)).map(|s| s.next), Some(2));
    assert_eq!(q.road.sender(&sender(4)).map(|s| s.next), Some(1));
}

/// A frame whose member skips its sender's next nonce, or names a sender
/// twice out of order, is refused with that reason; a member already on
/// the road invalidates the road, and its senders seed again from the
/// lanes, so the next aligned frame is admitted.
#[test]
fn a_gap_or_a_twice_named_sender_is_refused_and_flushes_the_road() {
    let q = queue(RoadMode::Count);
    push_members(&q, &[(sender(1), 0), (sender(2), 0)], 1);
    assert_eq!(q.road_stats().frames, 1);
    // sender(1) skips nonce 1.
    push_members(&q, &[(sender(1), 2), (sender(2), 1)], 2);
    let stats = q.road_stats();
    assert_eq!((stats.refused_gap, stats.flushes), (1, 1), "{stats:?}");
    assert_eq!(q.road.senders(), 0, "the flush clears the road's map");
    // Seeded again from the lanes (sender(1) holds 0 and 2: next 3).
    push_members(&q, &[(sender(1), 3), (sender(2), 2)], 3);
    let stats = q.road_stats();
    assert_eq!((stats.frames, stats.refused_gap), (2, 1), "{stats:?}");
    // A sender twice, not at consecutive nonces.
    push_members(&q, &[(sender(2), 3), (sender(1), 4), (sender(2), 5)], 4);
    let stats = q.road_stats();
    assert_eq!((stats.refused_dup_sender, stats.flushes), (1, 2), "{stats:?}");
    // Twice at consecutive nonces is admitted.
    push_members(&q, &[(sender(5), 0), (sender(5), 1), (sender(6), 0)], 5);
    assert_eq!(q.road_stats().frames, 3);
    assert_eq!(q.road.sender(&sender(5)).map(|s| s.next), Some(2));
}

/// A frame whose transactions do not match its record is refused as
/// `no_frame`; a refused frame whose senders were not yet on the road does
/// not flush, and moves their `next` past it.
#[test]
fn a_frame_without_a_matching_record_is_refused_without_a_flush() {
    let q = queue(RoadMode::Count);
    push_members(&q, &[(sender(1), 0)], 1);
    push_members(&q, &[(sender(2), 0)], 2);
    // A frame whose hashes are not its transactions'.
    let txs = vec![tx_hashed(sender(3), 0)];
    q.push_frame(
        txs,
        Some(NewFrame { id: frame_id(sender(3), 99), hashes: vec![B256::repeat_byte(0xee)], members: vec![(sender(3), 0)], gas: 21_000 }),
    );
    let stats = q.road_stats();
    assert_eq!((stats.refused_no_frame, stats.flushes), (1, 0), "{stats:?}");
    assert_eq!(q.road.sender(&sender(3)).map(|s| (s.next, s.on_road)), Some((1, false)));
    // Its sender's next frame is aligned.
    push_members(&q, &[(sender(3), 1)], 3);
    assert_eq!(q.road_stats().frames, 3);
}

/// A sender whose lane is empty but known (everything it had is in a
/// build's take) is not seeded: the frame is refused as `unknown`, and the
/// sender joins at its next frame, once the lanes hold the refused one.
#[test]
fn a_sender_with_an_empty_known_lane_is_refused_as_unknown() {
    let q = queue(RoadMode::Count);
    push_members(&q, &[(sender(1), 0), (sender(1), 1)], 1);
    let (best, _) = q.frames_for_build(block_hash(0), 10 * 21_000);
    assert_eq!(best.count(), 2);
    // Clear the road's map: a frame skipping a nonce of an on-road sender.
    push_members(&q, &[(sender(9), 0)], 2);
    push_members(&q, &[(sender(9), 5)], 3);
    assert_eq!(q.road_stats().flushes, 1);
    push_members(&q, &[(sender(1), 2)], 4);
    let stats = q.road_stats();
    assert_eq!(stats.refused_unknown, 1, "{stats:?}");
    push_members(&q, &[(sender(1), 3)], 5);
    assert_eq!(q.road.sender(&sender(1)).map(|s| s.next), Some(4));
}

/// Transactions of an on-road sender that arrive without a frame flush
/// the road; those of a sender not on it only move its `next`.
#[test]
fn a_frameless_arrival_of_an_on_road_sender_flushes_the_road() {
    let q = queue(RoadMode::Count);
    push_members(&q, &[(sender(1), 0)], 1);
    q.push([tx_hashed(sender(2), 0)]);
    assert_eq!(q.road_stats().flushes, 0);
    q.push([tx_hashed(sender(1), 1)]);
    assert_eq!(q.road_stats().flushes, 1);
}

// ---- Stage 1: the road as the build's source (`N42_FRAME_ROAD=1`). ----

const TX_GAS: u64 = 21_000;

fn build(queue: &TxQueue<EthPooledTransaction>, parent: B256, txs: u64) -> (Vec<Tx>, FramePlan) {
    let (best, plan, _) = queue.frames_for_build_ahead(parent, txs * TX_GAS, SelectMode::Parallel, false);
    let taken: Vec<Tx> = best.collect();
    assert_eq!(plan.tx_count(), taken.len());
    (taken, plan)
}

/// The own block's hand-off (forget + hold), then its canonical prune.
fn commit(queue: &TxQueue<EthPooledTransaction>, parent: B256, number: u64, txs: &[Tx]) -> B256 {
    let hash = block_hash(number);
    super::offlock_tests::seal(queue, parent, number, hash, txs);
    let mined = pairs(txs);
    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
    queue.prune_block(number, hash, &mined, &hashes);
    hash
}

/// `len`, the gate's mirror against the locked depth, and `usable`, all at
/// `expect` (nothing parked in these tests).
fn assert_depth(queue: &TxQueue<EthPooledTransaction>, expect: usize) {
    assert_eq!(queue.len(), expect, "len");
    assert_eq!(queue.gate_len_locked(), expect, "the locked depth");
    assert_eq!(queue.gate_len(), expect, "the mirror");
    assert_eq!(queue.usable(), expect, "usable");
}

fn road_queue() -> TxQueue<EthPooledTransaction> {
    queue(RoadMode::On)
}

/// An aligned frame waits on the road, not in the lanes; a frame build
/// takes the road's frames whole and first, the chain is the chain the
/// lanes would have built, and a committed block retires its frames.
#[test]
fn road_frames_bypass_the_lanes_and_build_the_lanes_chain() {
    let off = queue(RoadMode::Off);
    let on = road_queue();
    for q in [&off, &on] {
        flood(q, 100, 0, 6, 50);
    }
    {
        let inner = on.lock_inner_quiet();
        assert_eq!(inner.len, 0, "nothing of the road is in the lanes");
    }
    assert_eq!(on.road.queued_ids().len(), 12);
    assert_depth(&on, 600);
    let mut blocks = [Vec::new(), Vec::new()];
    for (k, q) in [&off, &on].into_iter().enumerate() {
        let mut parent = block_hash(0);
        for n in 1..=4 {
            let (txs, plan) = build(q, parent, 150);
            assert_eq!(plan.frames.len(), 3, "three whole frames a block");
            parent = commit(q, parent, n, &txs);
            blocks[k].push(txs);
        }
    }
    assert_eq!(
        blocks[0].iter().map(|b| pairs(b)).collect::<Vec<_>>(),
        blocks[1].iter().map(|b| pairs(b)).collect::<Vec<_>>()
    );
    assert_chain_valid(&blocks[1]);
    assert_depth(&on, 0);
    let stats = on.road_stats();
    assert_eq!((stats.frames, stats.taken, stats.retired, stats.flushes), (12, 12, 12, 0), "{stats:?}");
    assert_eq!(on.road.taken_len(), 0);
}

/// The gate (R1): while a road sender still has entries in its lane, no
/// road frame is taken -- not even into a block with room left -- and once
/// a build has taken those entries, the child takes the road's frames.
#[test]
fn road_frames_wait_for_the_lane_debt() {
    let q = queue(RoadMode::Off);
    // Nonces 0-1 of 100 senders arrive through the lanes.
    flood(&q, 100, 0, 2, 50);
    let q = q.with_frame_road(RoadMode::On);
    // Nonces 2-3 seed at the lane tail and wait on the road.
    flood(&q, 100, 2, 2, 50);
    assert_eq!(q.road.queued_ids().len(), 4);
    assert_depth(&q, 400);
    let (first, plan) = build(&q, block_hash(0), 1_000);
    assert_eq!(first.len(), 200, "only the lanes' frames: {plan:?}");
    assert!(first.iter().all(|t| t.nonce() < 2));
    assert_eq!(q.road_stats().lane_debt, 200, "counted when the gate was asked");
    assert_eq!(q.road.queued_ids().len(), 4);
    assert_depth(&q, 200);
    let parent = commit(&q, block_hash(0), 1, &first);
    let (second, _) = build(&q, parent, 1_000);
    assert_eq!(second.len(), 200);
    assert!(second.iter().all(|t| t.nonce() >= 2));
    assert_eq!(q.road_stats().lane_debt, 0);
    assert_chain_valid(&[first, second]);
    assert_depth(&q, 0);
}

/// A build on the same parent again gives the previous build's road frames
/// back to the road's front, in their order; a block replaced at its height
/// gives its own back there too, ahead of its child's -- whichever comes
/// back first -- and the commit of the replacement retires them.
#[test]
fn road_frames_given_back_return_to_the_front_in_order() {
    let q = road_queue();
    flood(&q, 100, 0, 4, 50);
    let all = q.road.queued_ids();
    assert_eq!(all.len(), 8);
    // Block 1 takes frames 0-1 and is handed off; its child takes 2-3.
    let (b1, plan1) = build(&q, block_hash(0), 100);
    assert_eq!(plan1.frames.iter().map(|f| f.id).collect::<Vec<_>>(), all[..2]);
    let h1 = block_hash(1);
    super::offlock_tests::seal(&q, block_hash(0), 1, h1, &b1);
    let (b2, plan2) = build(&q, h1, 100);
    assert_eq!(plan2.frames.iter().map(|f| f.id).collect::<Vec<_>>(), all[2..4]);
    assert_eq!(b2.len(), 100);
    assert_depth(&q, 200);
    // The child again on the same parent: its frames come back first.
    let (again, plan) = build(&q, h1, 100);
    assert_eq!(plan.frames.iter().map(|f| f.id).collect::<Vec<_>>(), all[2..4]);
    assert_eq!(pairs(&again), pairs(&b2));
    assert_eq!(q.road_stats().handed_back, 2);
    assert_depth(&q, 200);
    // Another block takes height 1: block 1's frames go back to the front.
    q.prune_block(1, B256::repeat_byte(0x77), &[], &[]);
    assert_eq!(q.road.queued_ids(), [&all[..2], &all[4..]].concat());
    assert_depth(&q, 300);
    // A build on the genesis parent again: the child's take comes back
    // behind them, so the road is in admission order once more.
    let (c1, plan) = build(&q, block_hash(0), 100);
    assert_eq!(plan.frames.iter().map(|f| f.id).collect::<Vec<_>>(), all[..2]);
    assert_eq!(q.road.queued_ids(), all[2..]);
    assert_depth(&q, 300);
    assert_eq!(q.road_stats().flushes, 0);
    // Committed: retired, and nothing of them is offered again.
    let parent = commit(&q, block_hash(0), 1, &c1);
    assert_eq!(q.road.taken_len(), 0, "block 1's frames retired; the child's are queued again");
    let (c2, _) = build(&q, parent, 1_000);
    assert_eq!(c2.len(), 300);
    assert_chain_valid(&[c1, c2]);
    assert_depth(&q, 0);
}

/// A block's body is nonce-consecutive per sender across the road's part
/// and the lanes': road frames first, then the frames of a sender that
/// could not join the road (its lane empty but known), from the index.
#[test]
fn a_block_mixes_road_and_lane_frames_in_nonce_order() {
    let q = queue(RoadMode::Off);
    let x = sender(5_000);
    push_members(&q, &[(x, 0)], 1);
    let (b1, _) = build(&q, block_hash(0), 10);
    assert_eq!(b1.len(), 1);
    let parent = commit(&q, block_hash(0), 1, &b1);
    let q = q.with_frame_road(RoadMode::On);
    flood(&q, 60, 0, 2, 30);
    push_members(&q, &[(x, 1), (x, 2)], 2);
    assert_eq!(q.road_stats().refused_unknown, 1);
    assert_eq!(q.road.queued_ids().len(), 4);
    assert_depth(&q, 122);
    let (b2, plan) = build(&q, parent, 1_000);
    assert_eq!(plan.frames.len(), 5);
    assert_eq!(&pairs(&b2)[120..], &[(x, 1), (x, 2)]);
    assert_chain_valid(&[b1, b2]);
    assert_depth(&q, 0);
}

/// Lane debt no frame plan can take (a road sender's transaction that
/// reached its lane without a frame) shuts the gate; after a few builds
/// without progress the road is invalidated, its frames go to the lanes,
/// and the builds take them from there.
#[test]
fn a_gate_stuck_on_untakeable_debt_flushes_the_road() {
    let q = road_queue();
    for s in 0..10 {
        q.push([tx_hashed(sender(s), 0)]);
    }
    flood(&q, 10, 1, 2, 10);
    assert_eq!(q.road.queued_ids().len(), 2);
    assert_depth(&q, 30);
    let mut parent = block_hash(0);
    let mut flushed_at = None;
    for n in 1..=12 {
        let (txs, _) = build(&q, parent, 1_000);
        if q.road_stats().flushes > 0 && flushed_at.is_none() {
            flushed_at = Some(n);
        }
        if !txs.is_empty() {
            parent = commit(&q, parent, n, &txs);
        }
    }
    let at = flushed_at.expect("the road was invalidated");
    assert!(at as u64 > ROAD_STUCK_BUILDS, "flushed at build {at}");
    assert_eq!(q.road_stats().len_txs, 0);
}

/// A road frame given back in part (a build's refusal, an untake) is not
/// a frame any more: it goes to the lanes, and so does the rest of the
/// road (an invalidation), every queued frame indexed there; the chain
/// stays valid and nothing is lost.
#[test]
fn a_partial_give_back_flushes_the_road_into_the_lanes() {
    let q = road_queue();
    flood(&q, 100, 0, 4, 50);
    let (b1, _) = build(&q, block_hash(0), 100);
    assert_eq!(b1.len(), 100);
    // The builder hands back the last transaction of the second frame.
    let tail = b1[99].clone();
    q.untake(vec![tail]);
    let stats = q.road_stats();
    assert_eq!((stats.flushes, stats.len_txs), (1, 0), "{stats:?}");
    assert_depth(&q, 301);
    let body: Vec<Tx> = b1[..99].to_vec();
    let parent = commit(&q, block_hash(0), 1, &body);
    // The frameless tail heads its lane: the frame plan cannot take it, and
    // the frames behind it of the same senders wait (as for any lanes frame
    // handed back in part). The others are taken from the index.
    let (b2, _) = build(&q, parent, 1_000);
    assert_eq!(b2.len(), 150);
    assert!(b2.iter().all(|t| t.sender() != b1[99].sender()));
    assert_chain_valid(&[body, b2]);
}

/// The plan prepared ahead takes the road's frames as the build's own plan
/// does, and the chain is the lanes' chain; a prepared plan holding road
/// frames is refused once a road sender has lane debt again, and its
/// frames go back to the road's front.
#[test]
fn a_prepared_plan_takes_road_frames_and_is_refused_on_new_debt() {
    let off = queue(RoadMode::Off);
    let on = road_queue();
    for q in [&off, &on] {
        flood(q, 100, 0, 8, 50);
    }
    let mut blocks = [Vec::new(), Vec::new()];
    for (k, q) in [&off, &on].into_iter().enumerate() {
        let mut parent = block_hash(0);
        for n in 1..=4 {
            let (txs, times) = super::offlock_tests::build(q, parent, 100 * TX_GAS);
            if n > 1 {
                assert!(times.ahead >= 1, "block {n} planned afresh: {times:?}");
            }
            parent = commit(q, parent, n, &txs);
            blocks[k].push(txs);
        }
    }
    assert_eq!(
        blocks[0].iter().map(|b| pairs(b)).collect::<Vec<_>>(),
        blocks[1].iter().map(|b| pairs(b)).collect::<Vec<_>>()
    );
    assert_chain_valid(&blocks[1]);
    // The last build's child plan is prepared and holds road frames 8-9.
    let queued = on.road.queued_ids();
    assert_eq!(queued.len(), 6);
    assert!(on.lock_inner_quiet().prepared.as_ref().is_some_and(|p| p.road_epoch != 0));
    // 800 flooded, 400 mined, 100 in the prepared plan (taken).
    assert_depth(&on, 300);
    // A road sender's transaction comes back to its lane (a lanes entry
    // given back): the gate is shut, so the prepared plan is refused.
    {
        let mut inner = on.lock_inner();
        let epoch = inner.road_epoch;
        assert_ne!(epoch, 0);
        inner.road_debt.insert(sender(0));
        let lane = inner.lanes.get_mut(&sender(0)).expect("a road sender has a lane");
        assert_eq!(lane.road, epoch);
        lane.by_nonce.insert(1_000, valid_for(tx_hashed(sender(0), 1_000), std::time::Instant::now(), TransactionOrigin::External));
        inner.len += 1;
    }
    let parent = block_hash(4);
    let (best, plan, times) = on.frames_for_build_ahead(parent, 100 * TX_GAS, SelectMode::Parallel, false);
    assert_eq!(times.ahead_discard, Some(AheadDiscard::Below), "{times:?}");
    assert!(plan.frames.is_empty(), "the gate is shut and the lanes hold no frame");
    drop(best);
    assert_eq!(on.road.queued_ids().len(), 8, "the prepared frames are on the road again");
    assert_eq!(&on.road.queued_ids()[2..], &queued[..]);
}

/// A full block's road take: the taken list (made on the planner's pool
/// past `ROAD_PARALLEL_CLONE`) is the body in order, what the hand-off
/// compares against.
#[test]
fn a_large_road_take_lists_the_body_in_order() {
    let q = road_queue();
    flood(&q, 1_000, 0, 20, 500);
    let (txs, plan) = build(&q, block_hash(0), 20_000);
    assert_eq!((txs.len(), plan.frames.len()), (20_000, 40));
    {
        let inner = q.lock_inner_quiet();
        let (_, taken) = inner.last_build.as_ref().expect("the build's taken list");
        assert!(taken.len() >= ROAD_PARALLEL_CLONE);
        assert!(taken.iter().zip(&txs).all(|(a, b)| Arc::ptr_eq(a, b)) && taken.len() == txs.len());
    }
    commit(&q, block_hash(0), 1, &txs);
    assert_depth(&q, 0);
    assert_eq!(q.road.taken_len(), 0);
}

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

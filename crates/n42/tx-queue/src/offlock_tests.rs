// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_QUEUE_OFFLOCK`: the plan-ahead preparation planned under one hold
//! and applied under a second one that checks the lanes did not move, the
//! canonical prune in bounded holds, and the hand-off's partition with the
//! lock released. Every result is held against the one-hold path's.

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;
use std::collections::{HashMap, HashSet};

fn queue(offlock: bool) -> TxQueue<EthPooledTransaction> {
    TxQueue::new().with_offlock(offlock)
}

/// The flood's shape: rounds `from..from + rounds` of one nonce for each of
/// `senders` senders, cut into frames of `width` distinct senders.
fn flood(queue: &TxQueue<EthPooledTransaction>, senders: u64, from: u64, rounds: u64, width: usize) {
    let all: Vec<(Address, u64)> = (from..from + rounds).flat_map(|n| (0..senders).map(move |s| (sender(s), n))).collect();
    for chunk in all.chunks(width) {
        let txs: Vec<EthPooledTransaction> = chunk.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
        let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
        let (who, first) = chunk[0];
        queue.push_frame(
            txs,
            Some(NewFrame {
                id: frame_id(who, first.wrapping_mul(1_000_003) ^ chunk.len() as u64),
                hashes,
                members: chunk.to_vec(),
                gas: 21_000 * chunk.len() as u64,
            }),
        );
    }
}

/// The lanes' own count against what they hold, and the gate's mirror
/// against the locked depth.
fn assert_counts(queue: &TxQueue<EthPooledTransaction>) {
    let inner = queue.lock_inner_quiet();
    let held: usize = inner.lanes.values().map(|lane| lane.by_nonce.len()).sum();
    assert_eq!(inner.len, held, "len against the lanes");
    drop(inner);
    assert_eq!(queue.gate_len(), queue.gate_len_locked(), "the mirror against the locked depth");
}

/// One build with the child's plan prepared, then every transaction taken.
fn build(queue: &TxQueue<EthPooledTransaction>, parent: B256, gas: u64) -> (Vec<Tx>, FrameSelectTimes) {
    let (mut best, plan, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
    queue.prepare_next_in(gas, SelectMode::Parallel);
    let txs: Vec<Tx> = best.by_ref().collect();
    drop(best);
    assert_eq!(plan.tx_count(), txs.len());
    (txs, times)
}

fn seal(queue: &TxQueue<EthPooledTransaction>, built_on: B256, number: u64, hash: B256, txs: &[Tx]) {
    let body = pairs(txs);
    let (dropped, _) = queue.forget_mined_parallel(built_on, body.len(), |i| body[i]);
    queue.hold_own_block(number, hash, dropped);
}

fn chain(offlock: bool, blocks: u64, gas: u64) -> (Vec<Vec<Tx>>, Vec<FrameSelectTimes>) {
    let queue = queue(offlock);
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

fn assert_chain_valid(blocks: &[Vec<Tx>]) {
    let mut next: HashMap<Address, u64> = HashMap::new();
    let mut seen: HashSet<B256> = HashSet::new();
    for (k, block) in blocks.iter().enumerate() {
        for t in block {
            assert!(seen.insert(*t.hash()), "block {k}: a transaction selected twice");
            let at = next.entry(t.sender()).or_insert_with(|| t.nonce());
            assert_eq!(t.nonce(), *at, "block {k}: sender {} out of nonce order", t.sender());
            *at += 1;
        }
    }
}

/// With nothing in between, the off-lock preparation makes the plan the
/// one-hold preparation makes, and every build after the first uses it.
#[test]
fn an_offlock_prepared_plan_is_the_one_hold_plan() {
    for gas_txs in [7u64, 60, 333, 700] {
        let gas = gas_txs * 21_000;
        let (locked, _) = chain(false, 6, gas);
        let (offlock, times) = chain(true, 6, gas);
        assert_eq!(
            locked.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            offlock.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            "gas {gas_txs} txs"
        );
        assert_chain_valid(&offlock);
        for (k, t) in times.iter().enumerate().skip(1) {
            if !offlock[k].is_empty() {
                assert!(t.ahead >= 1, "gas {gas_txs}: block {} planned afresh: {t:?}", k + 1);
            }
        }
    }
}

/// Arrivals between the two holds (the drainer's holds do not move the
/// lanes' generation) are not lost, the commit applies the plan, and the
/// plan is still valid: the next build uses it whole, and the arrivals come
/// after it in later blocks.
#[test]
fn an_insert_between_the_holds_is_kept_and_the_plan_commits() {
    let gas = 300 * 21_000;
    let queue = queue(true);
    flood(&queue, 200, 0, 6, 50);
    let p0 = block_hash(0);
    let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
    let OffPlanned::Planned(planned) = queue.offlock_plan(gas) else { panic!("a plan with noted takes") };
    let planned_pairs: Vec<(Address, u64)> =
        planned.segments.iter().flat_map(|(txs, n)| txs.iter().take(*n).map(|t| (t.sender(), t.nonce()))).collect();
    let before = queue.len();
    // The next round of every sender arrives and is drained into the lanes.
    flood(&queue, 200, 6, 1, 50);
    queue.drain_now();
    assert_eq!(queue.len(), before + 200);
    assert_eq!(queue.offlock_commit(planned), Some(true), "nothing moved the lanes");
    assert_counts(&queue);
    let txs: Vec<Tx> = best.by_ref().collect();
    drop(best);
    seal(&queue, p0, 1, block_hash(1), &txs);
    let (mut best, _, times) = queue.frames_for_build_ahead(block_hash(1), gas, SelectMode::Parallel, false);
    assert_eq!(times.ahead, 1, "{times:?}");
    let next: Vec<Tx> = best.by_ref().collect();
    drop(best);
    assert_eq!(pairs(&next), planned_pairs, "the build took the committed plan");
    // Everything else, the arrivals included, follows in order.
    let mut blocks = vec![txs, next];
    let mut parent = block_hash(1);
    for n in 2..20 {
        let body = pairs(blocks.last().expect("a block"));
        let (dropped, _) = queue.forget_mined_parallel(parent, body.len(), |i| body[i]);
        queue.hold_own_block(n, block_hash(n), dropped);
        parent = block_hash(n);
        let (mut best, _, _) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
        let txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        if txs.is_empty() {
            break;
        }
        blocks.push(txs);
    }
    assert_chain_valid(&blocks);
    assert_eq!(blocks.iter().map(Vec::len).sum::<usize>(), 200 * 7, "everything was mined once");
}

/// A hold that moves the lanes between the two (an untake, a canonical
/// prune that removes planned entries) refuses the commit: nothing is
/// applied, the counts stay exact, the retry plans on the lanes as they
/// now are, and nothing mined is offered or lost.
#[test]
fn a_hold_that_moves_the_lanes_between_the_holds_refuses_the_commit() {
    let gas = 300 * 21_000;
    for prune in [false, true] {
        let queue = queue(true);
        flood(&queue, 200, 0, 6, 50);
        let total = queue.len();
        let p0 = block_hash(0);
        let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
        let mut txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        let OffPlanned::Planned(planned) = queue.offlock_plan(gas) else { panic!("a plan with noted takes") };
        let first = planned.segments[0].0[0].clone();
        let mut mined: Vec<(Address, u64)> = Vec::new();
        if prune {
            // Another node's committed block mines the plan's first sender
            // through its first planned nonce.
            mined = (0..=first.nonce()).map(|n| (first.sender(), n)).collect();
            let hashes: Vec<B256> = mined.iter().map(|(s, n)| *tx_hashed(*s, *n).hash()).collect();
            queue.prune_block(1, B256::repeat_byte(0xcc), &mined, &hashes);
        } else {
            let back: Vec<Tx> = txs.drain(txs.len() - 5..).collect();
            queue.untake(back);
        }
        assert_counts(&queue);
        assert_eq!(queue.offlock_commit(planned), None, "the lanes moved");
        assert!(queue.lock_inner_quiet().prepared.is_none());
        assert_counts(&queue);
        // The retry (and its fallback) still prepares a plan.
        assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
        assert_counts(&queue);
        seal(&queue, p0, 1, block_hash(1), &txs);
        let parent = if prune { B256::repeat_byte(0xcc) } else { block_hash(1) };
        let (mut best, _, _) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
        let next: Vec<Tx> = best.by_ref().collect();
        drop(best);
        let mined: HashSet<(Address, u64)> = mined.into_iter().collect();
        assert!(next.iter().all(|t| !mined.contains(&(t.sender(), t.nonce()))), "a mined one offered");
        let unique: HashSet<B256> = txs.iter().chain(&next).map(|t| *t.hash()).collect();
        assert_eq!(unique.len(), txs.len() + next.len(), "a transaction twice");
        let mined_unseen = mined.iter().filter(|p| !txs.iter().chain(&next).any(|t| (t.sender(), t.nonce()) == **p)).count();
        assert_eq!(txs.len() + next.len() + queue.len() + mined_unseen, total, "prune {prune}: something lost");
    }
}

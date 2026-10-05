// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The seal chain's queue side (`docs/SHARED_EXECUTION_SCOPE.md` 12): the
//! child's frame plan prepared while the parent executes
//! ([`TxQueue::prepare_next_plan`], `N42_PLAN_AHEAD`), a build that takes its
//! frames whole ([`QueueBest::take_frame_segments`]), and the drain in
//! bounded holds (`N42_TX_QUEUE_DRAIN_CHUNK`).

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;
use std::collections::{HashMap, HashSet};

/// One frame build, as the build-on-own path runs it: the selection, then
/// (with `prepare`) the child's plan prepared at once -- before this build
/// has executed anything -- then the build takes every transaction offered.
fn build(
    queue: &TxQueue<EthPooledTransaction>,
    parent: B256,
    gas: u64,
    prepare: bool,
) -> (Vec<Tx>, FramePlan, FrameSelectTimes) {
    let (mut best, plan, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
    if prepare {
        queue.prepare_next_in(gas, SelectMode::Parallel);
    }
    let txs: Vec<Tx> = best.by_ref().collect();
    drop(best);
    (txs, plan, times)
}

/// The block sealed from `txs` on `built_on` became `hash`: the hand-off
/// forgets the take and holds it until the chain settles the height.
fn seal(queue: &TxQueue<EthPooledTransaction>, built_on: B256, number: u64, hash: B256, txs: &[Tx]) {
    let body = pairs(txs);
    let (dropped, _) = queue.forget_mined_parallel(built_on, body.len(), |i| body[i]);
    queue.hold_own_block(number, hash, dropped);
}

/// Every sender's nonces across `blocks`, in order, continue each other with
/// no gap and no repeat; and no transaction (by hash) is in two blocks.
fn assert_chain_valid(blocks: &[Vec<Tx>]) {
    let mut next: HashMap<Address, u64> = HashMap::new();
    let mut seen: HashSet<B256> = HashSet::new();
    for (k, block) in blocks.iter().enumerate() {
        for t in block {
            assert!(seen.insert(*t.hash()), "block {k}: a transaction selected twice");
            let at = next.entry(t.sender()).or_insert(t.nonce());
            assert_eq!(t.nonce(), *at, "block {k}: sender {} out of nonce order", t.sender());
            *at += 1;
        }
    }
}

/// A chain of `blocks` own blocks, each built on the previous one's sealed
/// hash, with or without the child's plan prepared ahead; `between` runs
/// after each block's plan (and its preparation) and before its seal.
fn chain(
    prepare: bool,
    blocks: u64,
    gas: u64,
    mut between: impl FnMut(u64, &TxQueue<EthPooledTransaction>),
) -> (Vec<Vec<Tx>>, Vec<FrameSelectTimes>) {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
    fill(&queue, 40, 12, 5, 0);
    let mut parent = block_hash(0);
    let mut out = Vec::new();
    let mut times = Vec::new();
    for n in 1..=blocks {
        let (txs, plan, took) = build(&queue, parent, gas, prepare);
        assert_eq!(plan.tx_count(), txs.len());
        between(n, &queue);
        let hash = block_hash(n);
        seal(&queue, parent, n, hash, &txs);
        parent = hash;
        out.push(txs);
        times.push(took);
    }
    (out, times)
}

/// With nothing in between, a chain built on plans prepared ahead is the
/// chain built on fresh plans, block for block, and every plan after the
/// first is the prepared one.
#[test]
fn a_prepared_plan_is_the_fresh_plan() {
    for gas_txs in [7u64, 60, 333, 700] {
        let gas = gas_txs * 21_000;
        let (fresh, _) = chain(false, 6, gas, |_, _| {});
        let (ahead, times) = chain(true, 6, gas, |_, _| {});
        assert_eq!(
            fresh.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            ahead.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            "gas {gas_txs} txs"
        );
        assert_chain_valid(&ahead);
        assert_eq!(times[0].ahead, 0);
        for (k, t) in times.iter().enumerate().skip(1) {
            if !ahead[k].is_empty() {
                assert!(t.ahead >= 1, "gas {gas_txs}: block {} planned afresh: {t:?}", k + 1);
                assert_eq!(t.ahead_discard, None);
            }
        }
    }
}

/// Frames that arrive between the preparation and the use are behind the
/// plan in arrival order: a full prepared plan is still the fresh plan, and
/// a short one is topped up with them (`ahead` 2) into what a fresh plan
/// takes.
#[test]
fn frames_arriving_after_the_preparation_top_up_a_short_plan() {
    for gas_txs in [100u64, 2_000] {
        let gas = gas_txs * 21_000;
        // The next round of every sender, continuing its nonces.
        let late = |n: u64, queue: &TxQueue<EthPooledTransaction>| fill(queue, 40, 1, 5, 11 + n);
        let (fresh, _) = chain(false, 5, gas, late);
        let (ahead, times) = chain(true, 5, gas, late);
        assert_eq!(
            fresh.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            ahead.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            "gas {gas_txs} txs"
        );
        assert_chain_valid(&ahead);
        if gas_txs == 2_000 {
            // The queue is thinner than the block: every plan ran out of
            // frames, and the late ones top it up.
            assert!(times.iter().skip(1).any(|t| t.ahead == 2 && t.ahead_topup_txs > 0), "{times:?}");
        } else {
            assert!(times.iter().skip(1).all(|t| t.ahead == 1), "{times:?}");
        }
    }
}

/// Every event that can make a prepared plan differ from a fresh one makes
/// the next build discard it (by the named reason) and plan afresh; the
/// chain stays valid -- nonce order, nothing twice, nothing the chain mined
/// -- and nothing is lost: every transaction is in a block or still queued.
#[test]
fn every_invalidation_discards_the_prepared_plan_and_loses_nothing() {
    let gas = 120 * 21_000;
    let cases: [(&str, AheadDiscard); 5] = [
        ("refused", AheadDiscard::NotOnItsParent),
        ("handover", AheadDiscard::NotOnItsParent),
        ("untake", AheadDiscard::Below),
        ("arrival_below", AheadDiscard::Below),
        ("gas", AheadDiscard::Gas),
    ];
    for (case, want) in cases {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        fill(&queue, 40, 12, 5, 0);
        let total = queue.len();
        let p0 = block_hash(0);
        let mut blocks: Vec<Vec<Tx>> = Vec::new();
        // Block 1, its child's plan prepared.
        let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
        assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
        let parent_of_2 = match case {
            "refused" => {
                // The build gives half of its take back unused and its block
                // is never sealed: the next build stands on the same parent.
                let half: Vec<Tx> = best.by_ref().take(300).collect();
                drop(best);
                drop(half);
                p0
            }
            "handover" => {
                // Block 1 sealed, but the chain goes on from another block at
                // its height: its take comes back when that block settles.
                let txs: Vec<Tx> = best.by_ref().collect();
                drop(best);
                seal(&queue, p0, 1, block_hash(1), &txs);
                let back = queue.settle_own_block(1, B256::repeat_byte(0xee), |_, _| false);
                assert_eq!(back, txs.len());
                B256::repeat_byte(0xee)
            }
            "untake" => {
                // The builder's check gives block 1's first frame back before
                // the hand-off (its sender's claim failed): block 1 does not
                // carry it, and the prepared plan holds that sender's next.
                let mut txs: Vec<Tx> = best.by_ref().collect();
                drop(best);
                let back: Vec<Tx> = txs.drain(..5).collect();
                queue.untake(back);
                seal(&queue, p0, 1, block_hash(1), &txs);
                blocks.push(txs);
                block_hash(1)
            }
            "arrival_below" => {
                // A transaction block 1 took arrives again before block 1 is
                // committed (a re-sent frame): its lane holds a nonce below
                // the prepared plan's runs.
                let txs: Vec<Tx> = best.by_ref().collect();
                drop(best);
                seal(&queue, p0, 1, block_hash(1), &txs);
                let first = txs.first().expect("a block");
                queue.push([tx_hashed(first.sender(), first.nonce())]);
                blocks.push(txs);
                block_hash(1)
            }
            _ => {
                let txs: Vec<Tx> = best.by_ref().collect();
                drop(best);
                seal(&queue, p0, 1, block_hash(1), &txs);
                blocks.push(txs);
                block_hash(1)
            }
        };
        let gas_2 = if case == "gas" { 50 * 21_000 } else { gas };
        let (mut best, plan, times) = queue.frames_for_build_ahead(parent_of_2, gas_2, SelectMode::Parallel, false);
        assert_eq!(times.ahead, 0, "{case}");
        assert_eq!(times.ahead_discard, Some(want), "{case}");
        let txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        assert_eq!(txs.len(), plan.tx_count(), "{case}");
        // The duplicate arrival is not a second transaction: the lane keeps
        // one of the two, and the chain mines it once.
        blocks.push(txs);
        assert_chain_valid(&blocks);
        // Nothing lost: what the blocks hold and what is still queued is
        // everything pushed (the re-sent one is a duplicate of a mined one
        // only once block 1 commits; until then it is queued again).
        let in_blocks: usize = blocks.iter().map(Vec::len).sum();
        let extra = usize::from(case == "arrival_below");
        assert_eq!(in_blocks + queue.len(), total + extra, "{case}");
    }
}

/// A canonical prune that mines a nonce a prepared plan holds discards it at
/// once (the mined ones freed with the prune's garbage, the rest back in the
/// lanes); the next build plans afresh and is never offered a mined one.
#[test]
fn a_prune_of_a_frame_in_the_prepared_plan_discards_it() {
    let gas = 120 * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
    fill(&queue, 40, 12, 5, 0);
    let p0 = block_hash(0);
    let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
    assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
    let txs: Vec<Tx> = best.by_ref().collect();
    drop(best);
    seal(&queue, p0, 1, block_hash(1), &txs);
    // Another node's block, committed, mines the first prepared frame's
    // sender up to a nonce the prepared plan holds.
    let (who, nonce) = {
        let inner = queue.lock_inner();
        let prepared = inner.prepared.as_ref().expect("a prepared plan");
        let first = prepared.taken.first().expect("the plan holds something");
        (first.sender(), first.nonce())
    };
    let foreign: Vec<(Address, u64)> = (0..=nonce).map(|n| (who, n)).collect();
    let hashes: Vec<B256> = foreign.iter().map(|(s, n)| *tx_hashed(*s, *n).hash()).collect();
    queue.prune_block(1, B256::repeat_byte(0xcc), &foreign, &hashes);
    assert!(queue.lock_inner().prepared.is_none(), "the prune discarded it");
    let (mut best, _, times) = queue.frames_for_build_ahead(B256::repeat_byte(0xcc), gas, SelectMode::Parallel, false);
    assert_eq!(times.ahead, 0);
    let next: Vec<Tx> = best.by_ref().collect();
    drop(best);
    assert!(next.iter().all(|t| t.sender() != who || t.nonce() > nonce), "a mined nonce was offered");
    let mut lanes_who: Vec<u64> = next.iter().filter(|t| t.sender() == who).map(|t| t.nonce()).collect();
    lanes_who.dedup();
    assert!(lanes_who.windows(2).all(|w| w[1] == w[0] + 1));
}

/// A build that walks the lanes (no frames) gives a prepared plan back
/// before it walks: it is offered everything in order.
#[test]
fn a_walking_build_gets_the_prepared_plan_back_first() {
    let gas = 120 * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
    fill(&queue, 10, 4, 5, 0);
    let total = queue.len();
    let (best, _, _) = queue.frames_for_build_ahead(block_hash(0), gas, SelectMode::Parallel, false);
    drop(best);
    assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
    let all: Vec<Tx> = queue.best_for_build(block_hash(9)).collect();
    assert_eq!(all.len(), total);
    assert_chain_valid(&[all]);
}

/// A prepare, an untake and a prune racing each other, then the next build:
/// whatever the interleaving, nothing is offered twice or out of nonce
/// order, nothing mined is offered, and nothing is lost.
#[test]
fn an_untake_and_a_prune_racing_a_preparation_lose_nothing() {
    let gas = 150 * 21_000;
    for round in 0..20u64 {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        fill(&queue, 40, 12, 5, 0);
        let total = queue.len();
        let p0 = block_hash(0);
        let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
        let mut txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        let back: Vec<Tx> = txs.drain(txs.len() - 5..).collect();
        // Another node's committed block mines sender 39's first frame.
        let foreign: Vec<(Address, u64)> = (0..5).map(|n| (sender(39), n)).collect();
        let hashes: Vec<B256> = foreign.iter().map(|(s, n)| *tx_hashed(*s, *n).hash()).collect();
        let preparer = {
            let queue = queue.clone();
            std::thread::spawn(move || queue.prepare_next_in(gas, SelectMode::Parallel))
        };
        let untaker = {
            let queue = queue.clone();
            std::thread::spawn(move || queue.untake(back))
        };
        let pruner = {
            let queue = queue.clone();
            let (foreign, hashes) = (foreign.clone(), hashes.clone());
            std::thread::spawn(move || {
                if round % 2 == 0 {
                    std::thread::yield_now();
                }
                queue.prune_block(7, B256::repeat_byte(0xdd), &foreign, &hashes);
            })
        };
        preparer.join().expect("preparer");
        untaker.join().expect("untaker");
        pruner.join().expect("pruner");
        seal(&queue, p0, 1, block_hash(1), &txs);
        let (mut best, _, _) = queue.frames_for_build_ahead(block_hash(1), gas, SelectMode::Parallel, false);
        let next: Vec<Tx> = best.by_ref().collect();
        drop(best);
        let mined: HashSet<(Address, u64)> = foreign.iter().copied().collect();
        assert!(next.iter().all(|t| !mined.contains(&(t.sender(), t.nonce()))), "round {round}: a mined one offered");
        // Block 1 is ours and not settled: its nonces of sender 39 below the
        // foreign block's are what the chain mined elsewhere; the check is
        // on the build's own offer.
        let mut by_sender: HashMap<Address, Vec<u64>> = HashMap::new();
        for t in &next {
            by_sender.entry(t.sender()).or_default().push(t.nonce());
        }
        for (who, nonces) in by_sender {
            assert!(nonces.windows(2).all(|w| w[1] == w[0] + 1), "round {round}: {who} out of order");
        }
        let unique: HashSet<B256> = txs.iter().chain(&next).map(|t| *t.hash()).collect();
        assert_eq!(unique.len(), txs.len() + next.len(), "round {round}: a transaction twice");
        // Nothing lost: block 1, the next block, the queue and the foreign
        // block's (dropped as mined) account for everything.
        let foreign_unseen = foreign.iter().filter(|p| !txs.iter().any(|t| (t.sender(), t.nonce()) == **p)).count();
        assert_eq!(txs.len() + next.len() + queue.len() + foreign_unseen, total, "round {round}");
    }
}

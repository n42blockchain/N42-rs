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
            let at = next.entry(t.sender()).or_insert_with(|| t.nonce());
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
        // With a body made with every plan: a discarded plan's body goes with it.
        queue.set_plan_ahead_hook(pairs_hook());
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
        assert!(matches!(best.take_prepared_body(), PreparedBodyTake::None), "{case}: the body went with its plan");
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
    queue.set_plan_ahead_hook(pairs_hook());
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
    assert!(matches!(best.take_prepared_body(), PreparedBodyTake::None), "the body went with its plan");
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

/// A build takes its frames whole: the segments are exactly what `next`
/// would have handed out, in order, and dropping the iterator afterwards
/// gives nothing back.
#[test]
fn a_build_takes_its_frames_whole() {
    let gas = 90 * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
    fill(&queue, 30, 6, 5, 0);
    let reference: TxQueue<EthPooledTransaction> = TxQueue::new();
    fill(&reference, 30, 6, 5, 0);
    let (mut best, plan, _) = queue.frames_for_build_ahead(block_hash(0), gas, SelectMode::Parallel, false);
    let segments = best.take_frame_segments();
    assert!(best.next().is_none());
    drop(best);
    let whole: Vec<Tx> =
        segments.iter().flat_map(|(txs, from, to)| txs[*from..*to].to_vec()).collect();
    let (mut best, _, _) = reference.frames_for_build_ahead(block_hash(0), gas, SelectMode::Parallel, false);
    let walked: Vec<Tx> = best.by_ref().collect();
    drop(best);
    assert_eq!(pairs(&whole), pairs(&walked));
    assert_eq!(whole.len(), plan.tx_count());
    assert_eq!(queue.len(), reference.len());
}

/// A plan-ahead hook for the tests: the plan's (sender, nonce) pairs in plan
/// order, as the builder's body would list them.
fn pairs_hook() -> PlanAheadHook<EthPooledTransaction> {
    Arc::new(|segments: &[(FrameTxs<EthPooledTransaction>, usize)], _plan: &FramePlan| {
        let all: Vec<Tx> = segments.iter().flat_map(|(txs, taken)| txs[..*taken].to_vec()).collect();
        Some(Box::new(pairs(&all)) as PreparedBody)
    })
}

/// `N42_PLAN_AHEAD_BODY=1`: the body made with each prepared plan is handed
/// to the build that stands on that plan, and it is that build's take, in
/// order, block for block, at four gas limits; a topped-up plan hands none
/// (its take is not the plan the body was made from), and the chain is the
/// one built without hook or preparation.
#[test]
fn a_prepared_body_is_the_take_of_the_build_on_its_plan() {
    for gas_txs in [7u64, 60, 333, 700] {
        let gas = gas_txs * 21_000;
        let (fresh, _) = chain(false, 6, gas, |_, _| {});
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.set_plan_ahead_hook(pairs_hook());
        assert!(queue.has_plan_ahead_hook());
        fill(&queue, 40, 12, 5, 0);
        let mut parent = block_hash(0);
        let mut blocks = Vec::new();
        for n in 1..=6u64 {
            let (mut best, plan, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
            let body = best.take_prepared_body();
            queue.prepare_next_in(gas, SelectMode::Parallel);
            let txs: Vec<Tx> = best.by_ref().collect();
            drop(best);
            assert_eq!(plan.tx_count(), txs.len());
            match body {
                PreparedBodyTake::Ready(body, _) => {
                    assert_eq!(times.ahead, 1, "gas {gas_txs}, block {n}");
                    let made = body.downcast::<Vec<(Address, u64)>>().expect("the hook's type");
                    assert_eq!(*made, pairs(&txs), "gas {gas_txs}, block {n}: the body is the take");
                }
                PreparedBodyTake::None => assert!(n == 1 || times.ahead != 1 || txs.is_empty(), "gas {gas_txs}, block {n}: {times:?}"),
                PreparedBodyTake::Late => panic!("the hook runs inside the preparation here"),
            }
            let hash = block_hash(n);
            seal(&queue, parent, n, hash, &txs);
            parent = hash;
            blocks.push(txs);
        }
        assert_eq!(
            fresh.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            blocks.iter().map(|b| pairs(b)).collect::<Vec<_>>(),
            "gas {gas_txs} txs"
        );
    }
}

/// The O(1) hand-off of a whole take (`N42_PLAN_AHEAD_BODY=1`): on a build
/// whose block is its take it forgets exactly what the position-by-position
/// hand-off forgets, and marks the take handed so the next prepared plan is
/// accepted; on a parent, a length or a point that does not match it changes
/// nothing and says so.
#[test]
fn the_whole_take_hand_off_is_the_compared_one() {
    let gas = 120 * 21_000;
    let run = |whole: bool| {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        fill(&queue, 40, 12, 5, 0);
        let mut parent = block_hash(0);
        let mut out = Vec::new();
        for n in 1..=5u64 {
            let (mut best, _, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
            queue.prepare_next_in(gas, SelectMode::Parallel);
            let txs: Vec<Tx> = best.by_ref().collect();
            drop(best);
            if n > 1 {
                assert_eq!(times.ahead, 1, "block {n}");
            }
            let hash = block_hash(n);
            let body = pairs(&txs);
            let (dropped, forget) = if whole {
                let last = body.len() - 1;
                let checks: Vec<(usize, Address, u64)> =
                    [0, last / 2, last].into_iter().map(|i| (i, body[i].0, body[i].1)).collect();
                // What does not match changes nothing.
                assert!(queue.forget_whole_take(block_hash(99), body.len(), &checks).is_none());
                assert!(queue.forget_whole_take(parent, body.len() + 1, &checks).is_none());
                let wrong = [(last, body[last].0, body[last].1 + 1)];
                assert!(queue.forget_whole_take(parent, body.len(), &wrong).is_none());
                queue.forget_whole_take(parent, body.len(), &checks).expect("the whole take")
            } else {
                queue.forget_mined_parallel(parent, body.len(), |i| body[i])
            };
            assert!(forget.whole, "block {n}");
            assert_eq!(pairs(&dropped), body, "block {n}");
            queue.hold_own_block(n, hash, dropped);
            parent = hash;
            out.push(body);
        }
        (out, queue.len())
    };
    assert_eq!(run(true), run(false));
}

/// One frame build under `N42_PLAN_AHEAD_WAIT_MS` (`ahead` on: the
/// continuous preparation starts on the settling thread right after the
/// take), the build taking every transaction offered.
fn build_waiting(queue: &TxQueue<EthPooledTransaction>, parent: B256, gas: u64) -> (Vec<Tx>, FramePlan, FrameSelectTimes) {
    let (mut best, plan, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, true);
    let txs: Vec<Tx> = best.by_ref().collect();
    drop(best);
    (txs, plan, times)
}

/// Polls until `done` holds of the queue's prepared plan, at most 2 s.
fn until_prepared(queue: &TxQueue<EthPooledTransaction>, done: impl Fn(Option<&Prepared<EthPooledTransaction>>) -> bool) {
    let at = std::time::Instant::now();
    while at.elapsed() < std::time::Duration::from_secs(2) {
        if done(queue.lock_inner_quiet().prepared.as_ref()) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("the continuous preparation did not reach the expected plan");
}

/// The queue held nothing usable after a take: the continuous preparation
/// keeps looking, prepares a plan from the frames that arrive later, tops
/// it up with the ones after them until it fills the block's gas, and the
/// next build uses it without a timed-out wait; the chain stays valid.
#[test]
fn the_continuous_preparation_plans_frames_that_arrive_after_the_take() {
    // The later waves overrun it: the continuous plan fills (cut).
    let gas = (2 * 40 * 5 + 5) * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_plan_ahead_wait(200);
    fill(&queue, 40, 1, 5, 0);
    let (first, _, times) = build_waiting(&queue, block_hash(0), gas);
    assert!(!first.is_empty());
    assert_eq!(times.ahead, 0);
    seal(&queue, block_hash(0), 1, block_hash(1), &first);
    // Nothing usable is left; arrivals come in two waves.
    fill(&queue, 40, 1, 5, 1);
    until_prepared(&queue, |p| p.is_some());
    fill(&queue, 40, 1, 5, 2);
    until_prepared(&queue, |p| p.is_some_and(|p| p.tx_count_for_test() > 40 * 5 + 5));
    let (second, plan, times) = build_waiting(&queue, block_hash(1), gas);
    assert!(times.ahead >= 1, "{times:?}");
    assert_eq!(times.ahead_discard, None);
    assert!(!times.ahead_wait_timeout, "{times:?}");
    assert_eq!(plan.tx_count(), second.len());
    // The block full of both waves, every sender's nonces continuing the
    // first block's.
    assert_eq!(second.len() as u64 * 21_000, gas);
    assert_chain_valid(&[first, second]);
}

/// A build that starts while the continuous preparation is in flight and
/// nothing arrives waits the switch's milliseconds, says the wait ran out,
/// and plans afresh as before.
#[test]
fn a_wait_for_a_plan_that_never_fills_runs_out() {
    let gas = 1_000 * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_plan_ahead_wait(20);
    fill(&queue, 10, 1, 5, 0);
    let (first, _, _) = build_waiting(&queue, block_hash(0), gas);
    seal(&queue, block_hash(0), 1, block_hash(1), &first);
    let (second, _, times) = build_waiting(&queue, block_hash(1), gas);
    assert!(second.is_empty());
    assert!(times.ahead_wait_timeout, "{times:?}");
    assert!(times.ahead_wait_us >= 20_000, "{times:?}");
    assert_eq!(times.ahead, 0);
}

/// Off (the default): no wait, and no continuous preparation in flight.
#[test]
fn without_the_switch_a_build_never_waits() {
    let gas = 1_000 * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_plan_ahead_wait(0);
    fill(&queue, 10, 1, 5, 0);
    let (first, _, _) = build_waiting(&queue, block_hash(0), gas);
    seal(&queue, block_hash(0), 1, block_hash(1), &first);
    let (_, _, times) = build_waiting(&queue, block_hash(1), gas);
    assert_eq!((times.ahead_wait_us, times.ahead_wait_timeout), (0, false));
    assert_eq!(queue.ahead_wait.inflight.load(std::sync::atomic::Ordering::Acquire), 0);
}

/// `N42_FRAME_SWEEP_AT_TAKE`: the frames a build takes whole leave the
/// live index at the take, so the next build walks no dead frame; a build
/// on the same parent after one given up gets the given-back frames whole
/// again (they come back to the index with their transactions).
#[test]
fn a_taken_frame_leaves_the_index_at_the_take_and_comes_back_with_a_given_up_build() {
    let gas = 50 * 21_000;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_frame_sweep_at_take(true);
    // Rounds 0 and 1 of 10 senders (5 nonces each) and one mixed frame.
    fill(&queue, 10, 2, 5, 0);
    queue.drain_now();
    assert_eq!(queue.frames_indexed(), 21);
    // A build given up: its take comes back whole, frames and all.
    let (given_up, _, times) = build(&queue, block_hash(0), gas, false);
    assert_eq!(given_up.len(), 50);
    assert_eq!(times.frames_index, 21);
    assert_eq!(queue.frames_indexed(), 11);
    let (first, plan, times) = build(&queue, block_hash(0), gas, false);
    assert_eq!(pairs(&first), pairs(&given_up));
    assert_eq!((times.by_ref, times.slow, plan.skipped), (10, 0, 0), "{times:?}");
    assert_eq!(times.frames_swept_at_take, 10);
    assert_eq!(queue.frames_indexed(), 11);
    seal(&queue, block_hash(0), 1, block_hash(1), &first);
    // The next build skips nothing: round 0's frames are not in its walk.
    let (second, plan, times) = build(&queue, block_hash(1), gas, false);
    assert_eq!(second.len(), 50);
    assert_eq!(plan.skipped, 0, "{plan:?}");
    assert_eq!(times.frames_index, 11);
    assert_chain_valid(&[first, second]);
}

/// At [`MAX_FRAMES`] live frames a new frame is refused, not the oldest
/// evicted: every indexed frame's transactions stay reachable by frame, and
/// the refused frame's transaction is still queued. With the switch off the
/// oldest leaves, as before.
#[test]
fn a_full_index_refuses_a_new_frame_instead_of_evicting_a_live_one() {
    for on in [true, false] {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_frame_sweep_at_take(on);
        for s in 0..=MAX_FRAMES as u64 {
            frame(&queue, sender(s), 0, 1);
        }
        queue.drain_now();
        assert_eq!(queue.frames_indexed(), MAX_FRAMES);
        assert_eq!(queue.len(), MAX_FRAMES + 1);
        let inner = queue.lock_inner_quiet();
        let oldest = frame_id(sender(0), 0);
        let newest = frame_id(sender(MAX_FRAMES as u64), 0);
        assert_eq!(inner.frames.txs_gas_of(&oldest).is_some(), on, "switch {on}");
        assert_eq!(inner.frames.txs_gas_of(&newest).is_some(), !on, "switch {on}");
        assert_eq!(inner.frames.refused_at_cap, u64::from(on));
    }
}

/// The plan prepared right after a take, before the take's noted
/// transactions have left their lanes (the settle), is full whether the
/// taken frames are swept at the take or not, on the one-hold and the
/// off-lock paths.
#[test]
fn the_plan_prepared_before_the_settle_of_a_take_is_full() {
    for offlock in [false, true] {
        for on in [false, true] {
            let gas = 200 * 21_000;
            let queue: TxQueue<EthPooledTransaction> =
                TxQueue::new().with_offlock(offlock).with_frame_sweep_at_take(on);
            fill(&queue, 40, 4, 5, 0);
            queue.drain_now();
            let (mut best, plan, _) = queue.frames_for_build_ahead(block_hash(0), gas, SelectMode::Parallel, false);
            assert_eq!(plan.tx_count(), 200);
            assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
            let prepared = queue.lock_inner_quiet().prepared.as_ref().map(|p| (p.plan.tx_count(), p.plan.skipped));
            // Without the sweep the taken frames are still indexed and the
            // plan passes over them (one each).
            assert_eq!(prepared, Some((200, if on { 0 } else { 40 })), "offlock {offlock} sweep {on}");
            assert_eq!(best.by_ref().count(), 200);
        }
    }
}

/// A chain of own blocks on plans prepared after each take: with the sweep
/// every build after the first uses its prepared plan and the plan passes
/// over no frame, and the live index shrinks by what each block took.
#[test]
fn with_the_sweep_every_prepared_plan_is_used_and_skips_nothing() {
    for offlock in [false, true] {
        let gas = 100 * 21_000;
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(offlock).with_frame_sweep_at_take(true);
        fill(&queue, 40, 12, 5, 0);
        queue.drain_now();
        let mut parent = block_hash(0);
        let mut blocks = Vec::new();
        for n in 1..=10u64 {
            let (mut best, plan, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
            assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
            let txs: Vec<Tx> = best.by_ref().collect();
            drop(best);
            assert_eq!(txs.len(), 100);
            assert_eq!(plan.skipped, 0, "offlock {offlock} block {n}");
            if n > 1 {
                assert_eq!(times.ahead, 1, "offlock {offlock} block {n}: {times:?}");
            }
            seal(&queue, parent, n, block_hash(n), &txs);
            parent = block_hash(n);
            blocks.push(txs);
        }
        assert_chain_valid(&blocks);
    }
}

/// The production shape (the flood's, `offlock_tests::flood`): `rounds`
/// rounds of one nonce for each of `senders` senders, in frames of `width`
/// distinct senders (1.0 scale: 200,000 senders, 12 rounds, 500 a frame =
/// 2.4M queued; a 200k block is one round), the queue off-lock with the
/// frame sweep on.
fn production_queue(senders: u64, rounds: u64, width: usize, sweep: bool) -> TxQueue<EthPooledTransaction> {
    let queue: TxQueue<EthPooledTransaction> =
        TxQueue::new().with_offlock(false).with_frame_sweep_at_take(sweep).with_hash_index(4_000_000);
    crate::offlock_tests::flood(&queue, senders, 0, rounds, width);
    // Drained in one hold (the off-lock drain leaves a remainder for a
    // drainer thread), then off-lock as in production.
    queue.drain_now();
    queue.with_offlock(true)
}

/// Keeps every worker of the global rayon pool busy for `ms`, as an
/// executing block does.
fn busy_global_pool(ms: u64) {
    for _ in 0..rayon::current_num_threads() {
        rayon::spawn(move || std::thread::sleep(std::time::Duration::from_millis(ms)));
    }
    // Let the jobs start.
    std::thread::sleep(std::time::Duration::from_millis(20));
}

/// A take, then the one preparation that follows it, while the global pool
/// is busy: the plan is full, and neither the build's walk nor the
/// preparation waits for the pool. Returns (walk us, preparation us).
fn take_then_prepare(senders: u64, rounds: u64, width: usize, sweep: bool) -> (u64, u64) {
    let queue = production_queue(senders, rounds, width, sweep);
    let block = senders;
    let gas = block * 21_000;
    busy_global_pool(1_000);
    let at = std::time::Instant::now();
    let (mut best, plan, times) = queue.frames_for_build_ahead(block_hash(0), gas, SelectMode::Parallel, false);
    let walk_us = at.elapsed().as_micros() as u64;
    assert_eq!(plan.tx_count() as u64, block);
    assert_eq!(times.frames_index as u64, senders * rounds / width as u64);
    // The take leaves the lanes first, as the settling thread does before
    // it prepares.
    let at = std::time::Instant::now();
    drop(queue.lock_inner_quiet());
    let settle_us = at.elapsed().as_micros() as u64;
    let at = std::time::Instant::now();
    assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
    let prepare_us = at.elapsed().as_micros() as u64;
    eprintln!("sweep {sweep}: walk {walk_us} us, settle {settle_us} us, prepare {prepare_us} us");
    let prepared = queue.lock_inner_quiet().prepared.as_ref().map(|p| (p.plan.tx_count() as u64, p.plan.skipped));
    assert_eq!(prepared.map(|(count, _)| count), Some(block));
    if sweep {
        assert_eq!(prepared.map(|(_, skipped)| skipped), Some(0));
    }
    assert_eq!(best.by_ref().count() as u64, block);
    (walk_us, prepare_us)
}

/// The production shape at a small scale (24k queued, 2k blocks, frames of
/// 50): with the
/// global pool busy for a second, the walk and the preparation take well
/// under it.
#[test]
fn the_plan_prepared_after_a_take_is_full_and_does_not_wait_for_the_global_pool() {
    let (walk_us, prepare_us) = take_then_prepare(2_000, 12, 50, true);
    eprintln!("walk {walk_us} us, prepare {prepare_us} us");
    assert!(walk_us < 300_000 && prepare_us < 300_000, "walk {walk_us} us, prepare {prepare_us} us");
}

/// The same at the production scale (2.4M queued in 500-transaction frames,
/// a 200k take), against the queue without the sweep: the walk stays a few
/// ms with the global pool busy, and the preparation (its own settle of the
/// 200k take included) costs what it did without the sweep.
/// `cargo test --release -p n42-tx-queue --lib -- --ignored
/// the_plan_prepared_after_a_200k_take --nocapture`. Measured 2026-10-11 on
/// eight throttled cores: walk 6.0 / 6.1 ms (on / off), the take's settle
/// 30 / 28 ms, the preparation 54 / 59 ms.
#[test]
#[ignore = "2.4M transactions; run with --release"]
fn the_plan_prepared_after_a_200k_take_of_a_2_4m_queue_is_full_and_fast() {
    let (off_walk, off_prepare) = take_then_prepare(200_000, 12, 500, false);
    let (walk_us, prepare_us) = take_then_prepare(200_000, 12, 500, true);
    assert!(walk_us < 50_000, "walk {walk_us} us");
    assert!(walk_us <= off_walk * 3 / 2 + 5_000, "walk {walk_us} us against {off_walk} us without the sweep");
    assert!(prepare_us <= off_prepare * 3 / 2 + 5_000, "prepare {prepare_us} us against {off_prepare} us without the sweep");
}

/// `N42_PLAN_BODY_WAIT_MS`: a body that arrives 1 ms after the take is taken
/// by a take that may wait, and is `Late` to one that may not; a take whose
/// bound expires before the body is `Late`, and one whose hook made no body
/// returns at once.
#[test]
fn a_late_body_is_taken_by_a_take_that_waits() {
    use std::time::Duration;
    let late = |wait: Duration, after: Duration| {
        let slot = Arc::new(Mutex::new(BodySlot::default()));
        let filler = {
            let slot = Arc::clone(&slot);
            std::thread::spawn(move || {
                std::thread::sleep(after);
                fill_body_slot(&slot, Some(Box::new(7u32) as PreparedBody), 42);
            })
        };
        let take = take_body_slot(&slot, wait);
        filler.join().expect("the filler");
        take
    };
    match late(Duration::from_millis(500), Duration::from_millis(1)) {
        (PreparedBodyTake::Ready(body, made_us), waited_us) => {
            assert_eq!(made_us, 42);
            assert_eq!(*body.downcast::<u32>().expect("the body's type"), 7);
            assert!(waited_us > 0 && waited_us < 500_000, "waited {waited_us} us");
        }
        other => panic!("the body arrived within the bound: {other:?}"),
    }
    assert!(matches!(late(Duration::ZERO, Duration::from_millis(1)), (PreparedBodyTake::Late, 0)));
    let (take, waited_us) = late(Duration::from_millis(2), Duration::from_millis(100));
    assert!(matches!(take, PreparedBodyTake::Late), "{take:?}");
    assert!(waited_us >= 2_000, "waited {waited_us} us");
    let empty = Mutex::new(BodySlot::default());
    fill_body_slot(&empty, None, 3);
    assert!(matches!(take_body_slot(&empty, Duration::from_secs(5)), (PreparedBodyTake::Late, 0)));
}

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
pub(crate) fn flood(queue: &TxQueue<EthPooledTransaction>, senders: u64, from: u64, rounds: u64, width: usize) {
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
pub(crate) fn assert_counts(queue: &TxQueue<EthPooledTransaction>) {
    let inner = queue.lock_inner_quiet();
    let held: usize = inner.lanes.values().map(|lane| lane.by_nonce.len()).sum();
    assert_eq!(inner.len, held, "len against the lanes");
    drop(inner);
    assert_eq!(queue.gate_len(), queue.gate_len_locked(), "the mirror against the locked depth");
}

/// One build with the child's plan prepared, then every transaction taken.
pub(crate) fn build(queue: &TxQueue<EthPooledTransaction>, parent: B256, gas: u64) -> (Vec<Tx>, FrameSelectTimes) {
    let (mut best, plan, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
    queue.prepare_next_in(gas, SelectMode::Parallel);
    let txs: Vec<Tx> = best.by_ref().collect();
    drop(best);
    assert_eq!(plan.tx_count(), txs.len());
    (txs, times)
}

pub(crate) fn seal(queue: &TxQueue<EthPooledTransaction>, built_on: B256, number: u64, hash: B256, txs: &[Tx]) {
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

pub(crate) fn assert_chain_valid(blocks: &[Vec<Tx>]) {
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

/// What a queue holds, for comparing two: each lane's nonces and mined
/// watermarks (sorted by sender), the depth, the frames indexed, the build's
/// taken list and whether a plan is prepared.
pub(crate) type Lanes = Vec<(Address, Vec<u64>, Option<u64>, Option<u64>)>;

pub(crate) fn state(queue: &TxQueue<EthPooledTransaction>) -> (Lanes, usize, usize, Vec<(Address, u64)>, Option<usize>) {
    let inner = queue.lock_inner_quiet();
    let mut lanes: Lanes = inner
        .lanes
        .iter()
        .map(|(who, lane)| (*who, lane.by_nonce.keys().copied().collect(), lane.mined, lane.chain_mined))
        .collect();
    lanes.sort_by_key(|(who, ..)| *who);
    let taken = inner.last_build.as_ref().map(|(_, taken)| pairs(taken)).unwrap_or_default();
    (lanes, inner.len, inner.frames.len(), taken, inner.prepared.as_ref().map(|prepared| prepared.taken.len()))
}

/// A canonical block of another node's mining the first `rounds` nonces of
/// every sender, on a queue deep enough that the off-lock prune splits the
/// lanes in several holds (600 senders) and sweeps the index in several
/// (60 frames), with a build's take out and the child's plan prepared:
/// every mined transaction leaves the lanes, the index and the taken list,
/// nothing else does, the watermarks are the block's, and the queue is the
/// one-hold prune's in every respect.
#[test]
fn a_batched_prune_is_the_one_hold_prune() {
    let gas = 1_500 * 21_000;
    for rounds in [1u64, 3] {
        let mut states = Vec::new();
        for offlock in [false, true] {
            let queue = queue(offlock);
            flood(&queue, 600, 0, 5, 50);
            let (mut best, _, _) = queue.frames_for_build_ahead(block_hash(0), gas, SelectMode::Parallel, false);
            assert!(queue.prepare_next_in(gas, SelectMode::Parallel));
            let took: Vec<Tx> = best.by_ref().collect();
            drop(best);
            assert_eq!(took.len(), 1_500);
            let mined: Vec<(Address, u64)> = (0..rounds).flat_map(|n| (0..600).map(move |s| (sender(s), n))).collect();
            let hashes: Vec<B256> = mined.iter().map(|(s, n)| *tx_hashed(*s, *n).hash()).collect();
            let (_, times) = queue.prune_block(1, B256::repeat_byte(0xee), &mined, &hashes);
            queue.note_pruned(1);
            assert_eq!(times.senders, 600);
            assert_counts(&queue);
            let st = state(&queue);
            // Every mined transaction is gone, from the lanes and the
            // taken list, and every watermark is the block's.
            for (who, nonces, _, chain) in &st.0 {
                assert_eq!(*chain, Some(rounds - 1), "{who}: the watermark");
                assert!(nonces.iter().all(|n| *n >= rounds), "{who}: a mined nonce still queued");
            }
            assert!(st.3.iter().all(|(_, n)| *n >= rounds), "a mined nonce still taken");
            // The plan holds rounds 2 and up: a block mining round 2 takes
            // it with it (back to the lanes, minus what was mined).
            assert_eq!(st.4.is_none(), rounds >= 3, "rounds {rounds}: the prepared plan");
            assert_eq!(queue.pruned_through(), 1);
            // Nothing else: the lanes, the taken list and the prepared plan
            // account for every unmined transaction.
            let queued: usize = st.0.iter().map(|(_, nonces, ..)| nonces.len()).sum();
            assert_eq!(
                queued + st.3.len() + st.4.unwrap_or(0),
                600 * (5 - rounds) as usize,
                "rounds {rounds} offlock {offlock}"
            );
            states.push(st);
        }
        assert_eq!(states[0], states[1], "rounds {rounds}: the batched prune against the one-hold prune");
    }
}

/// The off-lock prune racing a build's selection, a preparation, the
/// drainer and an untake, over many rounds: whatever the interleaving,
/// nothing mined is offered afterwards, nothing is offered twice or out of
/// nonce order, and nothing is lost.
#[test]
fn a_batched_prune_racing_builds_and_drains_loses_nothing() {
    let gas = 600 * 21_000;
    for round in 0..12u64 {
        let queue = queue(true);
        flood(&queue, 600, 0, 4, 50);
        let p0 = block_hash(0);
        let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
        let mut txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        let back: Vec<Tx> = txs.drain(txs.len() - 50..).collect();
        // Another node's committed block mines round 0 of senders 300..600
        // (the build took round 0 of senders 0..600 bar the untaken tail).
        let mined: Vec<(Address, u64)> = (300..600).map(|s| (sender(s), 0)).chain((0..100).map(|s| (sender(s), 1))).collect();
        let hashes: Vec<B256> = mined.iter().map(|(s, n)| *tx_hashed(*s, *n).hash()).collect();
        let workers = vec![
            {
                let queue = queue.clone();
                std::thread::spawn(move || {
                    queue.prepare_next_in(gas, SelectMode::Parallel);
                })
            },
            {
                let queue = queue.clone();
                std::thread::spawn(move || queue.untake(back))
            },
            {
                let queue = queue.clone();
                std::thread::spawn(move || {
                    flood(&queue, 600, 4, 1, 50);
                    queue.drain_now();
                })
            },
            {
                let queue = queue.clone();
                let (mined, hashes) = (mined.clone(), hashes.clone());
                std::thread::spawn(move || {
                    if round % 2 == 0 {
                        std::thread::yield_now();
                    }
                    queue.prune_block(1, B256::repeat_byte(0xdd), &mined, &hashes);
                })
            },
        ];
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_counts(&queue);
        assert!(queue.lock_inner_quiet().pruning.is_none());
        // The first build's block is sealed (not committed: another block
        // took height 1), so its take is not offered again.
        seal(&queue, p0, 1, block_hash(1), &txs);
        let mut offered: Vec<Tx> = Vec::new();
        let mut parent = B256::repeat_byte(0xdd);
        for n in 2..40u64 {
            let (mut best, _, _) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
            let next: Vec<Tx> = best.by_ref().collect();
            drop(best);
            if next.is_empty() {
                break;
            }
            let body = pairs(&next);
            let (dropped, _) = queue.forget_mined_parallel(parent, body.len(), |i| body[i]);
            queue.hold_own_block(n, block_hash(n), dropped);
            parent = block_hash(n);
            offered.extend(next);
        }
        let mined_set: HashSet<(Address, u64)> = mined.iter().copied().collect();
        assert!(offered.iter().all(|t| !mined_set.contains(&(t.sender(), t.nonce()))), "round {round}: a mined one offered");
        let unique: HashSet<B256> = offered.iter().chain(&txs).map(|t| *t.hash()).collect();
        assert_eq!(unique.len(), offered.len() + txs.len(), "round {round}: a transaction twice");
        let mut by_sender: HashMap<Address, Vec<u64>> = HashMap::new();
        for t in &offered {
            by_sender.entry(t.sender()).or_default().push(t.nonce());
        }
        for (who, nonces) in by_sender {
            assert!(nonces.windows(2).all(|w| w[1] == w[0] + 1), "round {round}: {who} out of order");
        }
        // Everything is in the first build's block, offered since, or is
        // one of the foreign block's that the build did not take; the
        // queue ends empty.
        let first: HashSet<(Address, u64)> = pairs(&txs).into_iter().collect();
        let foreign_unseen = mined.iter().filter(|p| !first.contains(p)).count();
        assert_eq!(txs.len() + offered.len() + queue.len() + foreign_unseen, 600 * 5, "round {round}");
    }
}

/// The hand-off's forget with the taken list out of the lock is the
/// one-hold forget: the same mined transactions in the same order, the same
/// kept list, the same hand-off mark, for a whole take and a part of one,
/// through the parallel and the serial door.
#[test]
fn the_offlock_hand_off_is_the_one_hold_hand_off() {
    let gas = 1_000 * 21_000;
    for (parallel, part) in [(true, false), (true, true), (false, false), (false, true)] {
        let mut outcomes = Vec::new();
        for offlock in [false, true] {
            let queue = queue(offlock);
            flood(&queue, 400, 0, 4, 50);
            let p0 = block_hash(0);
            let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
            let took: Vec<Tx> = best.by_ref().collect();
            drop(best);
            let body = if part { pairs(&took[..took.len() / 2]) } else { pairs(&took) };
            let (mined, times) = if parallel {
                queue.forget_mined_parallel(p0, body.len(), |i| body[i])
            } else {
                queue.forget_mined_timed(p0, body.iter().copied())
            };
            assert_eq!(times.whole, parallel && !part);
            assert_counts(&queue);
            let handed = queue.lock_inner_quiet().handed;
            outcomes.push((pairs(&mined), state(&queue), handed));
        }
        assert_eq!(outcomes[0], outcomes[1], "parallel {parallel} part {part}");
    }
}

/// A build that begins between the hand-off's two holds finds the taken
/// list empty; the second hold gives the kept part back to the lanes, as
/// that build's opening would have, and the next build is offered it first.
#[test]
fn a_build_between_the_hand_off_holds_gets_the_kept_part_back() {
    let gas = 1_000 * 21_000;
    let queue = queue(true);
    flood(&queue, 400, 0, 4, 50);
    let p0 = block_hash(0);
    let (mut best, _, _) = queue.frames_for_build_ahead(p0, gas, SelectMode::Parallel, false);
    let took: Vec<Tx> = best.by_ref().collect();
    drop(best);
    let mut times = ForgetTimes::default();
    let (all, build) = queue.take_out_taken(p0, &mut times).expect("the build's take");
    assert_eq!(all.len(), took.len());
    // Another build begins (on another parent) while the list is out.
    let (best, _, _) = queue.frames_for_build_ahead(block_hash(7), gas, SelectMode::Parallel, false);
    let walked: Vec<Tx> = best.collect();
    let (mined, kept) = all.split_at(all.len() / 2);
    queue.put_back_kept(p0, build, kept.to_vec(), true, &mut times);
    assert_counts(&queue);
    // The mined half is forgotten; the kept half is queued again and the
    // next build on a new parent is offered it before anything newer.
    let (mut best, _, _) = queue.frames_for_build_ahead(block_hash(8), 50 * 21_000, SelectMode::Parallel, false);
    let next: Vec<Tx> = best.by_ref().collect();
    drop(best);
    let kept_set: HashSet<(Address, u64)> = pairs(kept).into_iter().collect();
    let mined_set: HashSet<(Address, u64)> = pairs(mined).into_iter().collect();
    assert!(!walked.is_empty());
    assert!(next.iter().all(|t| !mined_set.contains(&(t.sender(), t.nonce()))));
    assert!(next.iter().any(|t| kept_set.contains(&(t.sender(), t.nonce()))), "the kept part is offered again");
    // Build 8's opening gave build 7's take back too: the queue, build 8's
    // take and the mined half are everything.
    assert_eq!(queue.len() + next.len() + mined.len(), 1_600, "nothing lost");
}

/// A frame build's noted takes applied by the off-lock settle leave the
/// queue exactly as the ordinary settle does -- lanes, depth, taken list in
/// plan order -- with arrivals drained in between (the drainer's holds do
/// not settle under the switch); and a settle that finds the takes already
/// applied by another hold does nothing.
#[test]
fn the_offlock_settle_is_the_ordinary_settle() {
    let gas = 900 * 21_000;
    for already in [false, true] {
        let mut states = Vec::new();
        for offlock in [false, true] {
            let queue = queue(offlock);
            flood(&queue, 400, 0, 4, 50);
            let (segments, mark) = {
                let mut inner = queue.lock_inner();
                queue.begin_build(&mut inner, block_hash(0));
                let mut times = FrameSelectTimes::default();
                let (segments, plan, _) = inner.plan_frames(gas, &mut times, SelectMode::Parallel);
                assert_eq!(plan.tx_count(), 900);
                assert_eq!(inner.pending.len(), segments.len(), "the whole plan is noted");
                let mark = SettleMark {
                    build: inner.builds,
                    count: inner.pending.len(),
                    first: inner.pending[0].0,
                    last: inner.pending[inner.pending.len() - 1].0,
                };
                (segments, mark)
            };
            // The next round arrives and is drained before the settle.
            flood(&queue, 400, 4, 1, 50);
            queue.drain_now();
            if already {
                drop(queue.lock_inner());
            }
            if offlock {
                queue.settle_offlock(mark, segments);
            } else {
                drop(queue.lock_inner());
            }
            assert!(queue.lock_inner_unsettled().pending.is_empty());
            assert_counts(&queue);
            states.push(state(&queue));
        }
        assert_eq!(states[0], states[1], "already settled {already}");
        assert_eq!(states[1].3.len(), 900);
    }
}

/// A settle in batches of 64 senders leaves the queue as the one-hold
/// settle does, with arrivals drained between its holds into a lane it has
/// settled and one it has not touched yet; whether its own batches finish
/// the rest or another hold of the lanes does.
#[test]
fn a_batched_settle_is_the_one_hold_settle() {
    let gas = 900 * 21_000;
    for finish_by_lock in [false, true] {
        let mut states = Vec::new();
        let mut arrivals: Vec<Address> = Vec::new();
        for batched in [true, false] {
            let queue = queue(true);
            flood(&queue, 400, 0, 4, 50);
            let (segments, mark) = {
                let mut inner = queue.lock_inner();
                queue.begin_build(&mut inner, block_hash(0));
                let mut times = FrameSelectTimes::default();
                let (segments, plan, _) = inner.plan_frames(gas, &mut times, SelectMode::Parallel);
                assert_eq!(plan.tx_count(), 900);
                let mark = SettleMark {
                    build: inner.builds,
                    count: inner.pending.len(),
                    first: inner.pending[0].0,
                    last: inner.pending[inner.pending.len() - 1].0,
                };
                (segments, mark)
            };
            let gen_before = queue.lock_inner_unsettled().lanes_gen;
            if batched {
                queue.settle_offlock_in(mark, segments, 64, 2);
                let inner = queue.lock_inner_unsettled();
                assert!(inner.pending.is_empty());
                assert_eq!(inner.lanes_gen, gen_before + 2, "one raise a hold");
                assert_eq!(inner.last_build.as_ref().map(|(_, taken)| taken.len()), Some(900), "the taken list at the first hold");
                // 400 senders, 128 settled: one lane of each kind.
                let unsettled: HashSet<Address> = inner.settling.iter().map(|(who, ..)| *who).collect();
                assert_eq!(unsettled.len(), 400 - 128);
                let open = *unsettled.iter().next().unwrap();
                let done = (0..400).map(sender).find(|who| !unsettled.contains(who)).unwrap();
                assert!(inner.lanes[&open].by_nonce.contains_key(&0));
                assert!(!inner.lanes[&done].by_nonce.contains_key(&0));
                drop(inner);
                arrivals = vec![done, open];
            } else {
                queue.settle_offlock(mark, segments);
            }
            // Arrivals into both lanes, drained between the holds (the
            // drainer does not settle under the switch).
            for who in &arrivals {
                let txs = vec![tx_hashed(*who, 4), tx_hashed(*who, 5)];
                let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
                queue.push_frame(
                    txs,
                    Some(NewFrame { id: frame_id(*who, 0xa11), hashes, members: vec![(*who, 4), (*who, 5)], gas: 42_000 }),
                );
            }
            queue.drain_now();
            if batched {
                assert!(!queue.lock_inner_unsettled().settling.is_empty());
                if finish_by_lock {
                    drop(queue.lock_inner());
                } else {
                    queue.settle_rest(64, usize::MAX);
                }
                assert!(queue.lock_inner_unsettled().settling.is_empty());
            }
            assert_counts(&queue);
            states.push(state(&queue));
        }
        assert_eq!(states[0], states[1], "finish by lock {finish_by_lock}");
        assert_eq!(states[0].3.len(), 900);
        for who in &arrivals {
            let lane = states[0].0.iter().find(|(w, ..)| w == who).unwrap();
            assert!(lane.1.ends_with(&[4, 5]), "the arrivals queued");
        }
    }
}

/// The off-lock settle's holds for a bench-tier build (`N42_BENCH_SENDERS`
/// senders, default 100,000, two nonces each taken: 200,000 transfers), in
/// one hold against batches of [`OFFLOCK_SETTLE_SENDERS`].
/// `cargo test -p n42-tx-queue --lib -- --ignored bench_settle_holds --nocapture`.
#[test]
#[ignore]
fn bench_settle_holds() {
    let senders: u64 = std::env::var("N42_BENCH_SENDERS").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let gas = 2 * senders * 21_000;
    for batch in [usize::MAX, OFFLOCK_SETTLE_SENDERS] {
        let queue = queue(true);
        flood(&queue, senders, 0, 4, 500);
        queue.drain_now();
        let (segments, mark) = {
            let mut inner = queue.lock_inner();
            queue.begin_build(&mut inner, block_hash(0));
            let mut times = FrameSelectTimes::default();
            let (segments, _, _) = inner.plan_frames(gas, &mut times, SelectMode::Parallel);
            let mark = SettleMark {
                build: inner.builds,
                count: inner.pending.len(),
                first: inner.pending[0].0,
                last: inner.pending[inner.pending.len() - 1].0,
            };
            (segments, mark)
        };
        take_lock_stats();
        queue.settle_offlock_in(mark, segments, batch, usize::MAX);
        let stats = take_lock_stats();
        eprintln!(
            "batch {batch:>20}: holds {:>3} longest {:>7.2} ms total {:>7.2} ms",
            stats.holds,
            stats.hold_max_ns as f64 / 1e6,
            stats.hold_ns as f64 / 1e6
        );
        assert!(queue.lock_inner_unsettled().settling.is_empty());
        assert_eq!(state(&queue).3.len() as u64, 2 * senders);
    }
}

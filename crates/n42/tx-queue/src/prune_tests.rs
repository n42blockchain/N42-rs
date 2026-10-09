// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The feed path's queue side (`docs/SHARED_EXECUTION_SCOPE.md` 11): the
//! gate's depth read without the lanes' lock, and a canonical block's prune
//! in one pass ([`TxQueue::prune_block`]).

use super::*;
use alloy_primitives::{Signature, TxKind, U256};
use reth_transaction_pool::EthPooledTransaction;
use std::collections::HashMap;

fn tx_hashed(sender: Address, nonce: u64) -> EthPooledTransaction {
    use alloy_consensus::{Signed, TxEip1559};
    let inner = TxEip1559 {
        chain_id: 1,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(Address::repeat_byte(9)),
        value: U256::from(1),
        ..Default::default()
    };
    let mut seed = [0u8; 28];
    seed[..20].copy_from_slice(sender.as_slice());
    seed[20..].copy_from_slice(&nonce.to_be_bytes());
    let signed = Signed::new_unchecked(inner, Signature::test_signature(), alloy_primitives::keccak256(seed));
    let recovered = reth_primitives_traits::Recovered::new_unchecked(
        reth_ethereum_primitives::TransactionSigned::from(signed),
        sender,
    );
    EthPooledTransaction::new(recovered, 120)
}

fn sender(index: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&(index.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1).to_be_bytes());
    Address::from(a)
}

/// One frame: `len` consecutive nonces of one sender from `first`, the
/// flood's shape (a frame is one sender's run).
fn frame(queue: &TxQueue<EthPooledTransaction>, who: Address, first: u64, len: u64) -> (Vec<(Address, u64)>, Vec<B256>) {
    let members: Vec<(Address, u64)> = (first..first + len).map(|n| (who, n)).collect();
    let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
    let id = n42_frame_id(who, first);
    queue.push_frame(txs, Some(NewFrame { id, hashes: hashes.clone(), members: members.clone(), gas: 21_000 * len }));
    (members, hashes)
}

fn n42_frame_id(who: Address, first: u64) -> B256 {
    let mut seed = [0u8; 29];
    seed[..20].copy_from_slice(who.as_slice());
    seed[20..28].copy_from_slice(&first.to_be_bytes());
    seed[28] = 0xf7;
    alloy_primitives::keccak256(seed)
}

/// Each frame round's block: its (sender, nonce) pairs and its hashes.
type Rounds = Vec<(Vec<(Address, u64)>, Vec<B256>)>;

/// A queue of `senders` x `frames` frames of `per` nonces each, pushed one
/// frame of each sender in turn (the arrival order the flood makes), with
/// the by-hash index. Returns the queue and, per frame round, the block it
/// would be: the pairs and the hashes.
fn deep_queue(
    senders: u64,
    frames: u64,
    per: u64,
) -> (TxQueue<EthPooledTransaction>, Rounds) {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_hash_index(4_000_000);
    let mut rounds = Vec::new();
    for f in 0..frames {
        let mut pairs = Vec::with_capacity((senders * per) as usize);
        let mut hashes = Vec::with_capacity((senders * per) as usize);
        for s in 0..senders {
            let (m, h) = frame(&queue, sender(s), f * per, per);
            pairs.extend(m);
            hashes.extend(h);
        }
        rounds.push((pairs, hashes));
    }
    queue.drain_now();
    (queue, rounds)
}

/// Everything a build on a fresh parent is offered, in order.
fn offered(queue: &TxQueue<EthPooledTransaction>, parent: u8) -> Vec<(Address, u64)> {
    queue.best_for_build(B256::repeat_byte(parent)).map(|t| (t.sender(), t.nonce())).collect()
}

/// Each sender's nonces offered in order from `from[sender]` with no gap
/// and no repeat, and the contents exactly `expected`.
fn assert_offered(got: &[(Address, u64)], from: &HashMap<Address, u64>, expected: &[(Address, u64)]) {
    let mut next = from.clone();
    for (who, nonce) in got {
        let at = next.entry(*who).or_insert(0);
        assert_eq!(*nonce, *at, "sender {who} offered out of order");
        *at += 1;
    }
    let (mut a, mut b) = (got.to_vec(), expected.to_vec());
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a.len(), b.len(), "lost or duplicated");
    assert!(a == b, "different contents");
}

// ---------------------------------------------------------------- the gate

/// The mirror is the locked reading after every kind of operation that
/// moves the depth: pushes (staged), drains, builds that take by walk and
/// by frame, give-backs, refusals that park a lane (parking on), stale
/// refusals, untakes, prunes, own blocks held and settled, reverts. With
/// nobody holding the lock the two must be equal, so the gate's decision
/// against any limit is the same.
#[test]
fn the_gate_mirror_is_the_locked_depth_after_every_operation() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_hash_index(100_000).with_park_lanes(8);
    let check = |what: &str| {
        let (fast, locked) = (queue.gate_len(), queue.gate_len_locked());
        assert_eq!(fast, locked, "after {what}: mirror {fast} against locked {locked}");
        for limit in [0usize, 1, fast, fast + 1, 10_000] {
            assert_eq!(fast < limit, locked < limit, "gate decision at {limit} after {what}");
        }
    };
    check("nothing");
    let mut blocks = Vec::new();
    for s in 0..40u64 {
        blocks.push(frame(&queue, sender(s), 0, 20));
        check("a frame pushed, not drained");
    }
    queue.drain_now();
    check("a drain");
    // A walk build takes some and gives the rest back on drop.
    {
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        for _ in 0..137 {
            let _ = best.next();
        }
        check("a walk build's take");
    }
    check("a walk build's give-back");
    // A refusal for a hole parks the lane (parking on in this queue).
    {
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        if let Some(first) = best.next() {
            let gap = InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent {
                tx: first.nonce() + 5,
                state: first.nonce(),
            });
            best.mark_invalid(&first, gap);
        }
        check("a park");
        if let Some(next) = best.next() {
            let stale = InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent {
                tx: next.nonce(),
                state: next.nonce() + 1,
            });
            best.mark_invalid(&next, stale);
        }
        check("a stale refusal");
    }
    check("a build with refusals dropped");
    assert!(queue.parked().0 > 0, "the refusal parked a lane");
    // A frame build, its take settled at the next lock, then untaken.
    let (best, plan) = queue.frames_for_build(B256::repeat_byte(3), 21_000 * 200);
    check("a frame build's plan");
    drop(queue.lock_inner());
    check("a frame build's settle");
    drop(best);
    check("a frame build's give-back");
    // An own block taken, held, and settled to another hash.
    let own: Vec<(Address, u64)> = blocks[0].0.iter().take(5).copied().collect();
    let held = queue.remove_mined_batch_collecting(own.clone());
    check("an own block's collection");
    queue.hold_own_block(7, B256::repeat_byte(0x70), held);
    check("an own block held");
    let (back, _) = queue.prune_block(7, B256::repeat_byte(0x71), &own[..2], &[]);
    assert_eq!(back, 3);
    check("an own block settled elsewhere and pruned");
    // A canonical prune of a whole frame of another sender, with hashes.
    let (pairs, hashes) = &blocks[1];
    queue.prune_block(8, B256::repeat_byte(0x80), pairs, hashes);
    check("a canonical prune");
    // A revert of what was pruned.
    queue.push_reverted(pairs.iter().map(|(s, n)| tx_hashed(*s, *n)).collect());
    check("a revert, staged");
    queue.drain_now();
    check("a revert, drained");
    // An explicit untake of a build's take.
    let mut best = queue.best_for_build(B256::repeat_byte(4));
    let taken: Vec<_> = (0..10).filter_map(|_| best.next()).collect();
    drop(best);
    queue.untake(taken);
    check("an untake");
    assert!(!plan.frames.is_empty(), "the frame build planned something");
}

/// The mirror under a drain racing the reader: a reader that knows how many
/// transactions had been pushed (and not removed) before it read must never
/// see fewer. Counting the batch into the mirror after `staged` let go of it
/// would show the drain's batch as missing for the drain's length.
#[test]
fn the_gate_mirror_never_undercounts_a_drain() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
    let pushed = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let pusher = {
        let (queue, pushed, stop) = (queue.clone(), Arc::clone(&pushed), Arc::clone(&stop));
        std::thread::spawn(move || {
            for round in 0..400u64 {
                let batch: Vec<EthPooledTransaction> = (0..250u64).map(|s| tx_hashed(sender(s), round)).collect();
                queue.push(batch);
                pushed.fetch_add(250, Ordering::SeqCst);
            }
            stop.store(true, Ordering::SeqCst);
        })
    };
    let drainer = {
        let (queue, stop) = (queue.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                queue.drain_now();
            }
            queue.drain_now();
        })
    };
    let mut reads = 0u64;
    while !stop.load(Ordering::SeqCst) {
        let floor = pushed.load(Ordering::SeqCst);
        let seen = queue.gate_len();
        assert!(seen >= floor, "the gate read {seen} with {floor} pushed");
        reads += 1;
    }
    pusher.join().expect("pusher");
    drainer.join().expect("drainer");
    assert_eq!(queue.gate_len(), 100_000);
    assert_eq!(queue.gate_len(), queue.gate_len_locked());
    assert!(reads > 0);
}

/// The drain's time and the lock's holds reach the 5 s report.
#[test]
fn a_drain_is_counted_in_the_lock_stats() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
    queue.push((0..300u64).map(|s| tx_hashed(sender(s), 0)).collect::<Vec<_>>());
    queue.drain_now();
    // Process-wide counters other tests also move: at least this drain.
    let stats = take_lock_stats();
    assert!(stats.drains >= 1, "{stats:?}");
    assert!(stats.drain_txs >= 300, "{stats:?}");
    assert!(stats.holds >= 1, "{stats:?}");
    assert!(stats.hold_max_ns >= stats.drain_max_ns.min(stats.hold_max_ns), "{stats:?}");
}

// ---------------------------------------------------------------- the prune

/// The old prune, as the node ran it: the three calls in turn.
fn prune_three_calls(
    queue: &TxQueue<EthPooledTransaction>,
    number: u64,
    hash: B256,
    pairs: &[(Address, u64)],
    hashes: &[B256],
) -> usize {
    let carried: std::collections::HashSet<(Address, u64)> = pairs.iter().copied().collect();
    let back = queue.settle_own_block(number, hash, |s, n| carried.contains(&(*s, n)));
    queue.remove_mined_batch(pairs.iter().copied());
    queue.forget_hashes(hashes.iter().copied());
    back
}

/// What a queue looks like from outside: what a fresh build is offered, in
/// order, its depth, its frames and its by-hash index over `probe`.
fn observe(
    queue: &TxQueue<EthPooledTransaction>,
    probe: &[B256],
    parent: u8,
) -> (Vec<(Address, u64)>, usize, usize, usize, Vec<bool>) {
    let depth = queue.len();
    let gate = queue.gate_len();
    let frames = queue.frames_indexed();
    let held: Vec<bool> = probe.iter().map(|h| queue.get_by_hash(h).is_some()).collect();
    (offered(queue, parent), depth, gate, frames, held)
}

/// 400,000 queued in frames of 500, a 200,000-transaction block of the
/// oldest frames pruned, on a follower (the block's transactions in the
/// lanes) and on a leader (a frame build took them): the queue keeps the
/// other 200,000 in nonce order, the block's frames and hashes are gone,
/// and nothing of the block can be offered again by any door -- a give-back,
/// a re-arrival or an untake. The one-pass prune and the three calls leave
/// identical queues.
#[test]
fn a_block_prune_on_a_deep_queue_keeps_order_and_never_offers_the_block_again() {
    for leader in [false, true] {
        let (one_pass, rounds) = deep_queue(400, 2, 500);
        let (three_calls, _) = deep_queue(400, 2, 500);
        let (block, block_hashes) = &rounds[0];
        let (rest, rest_hashes) = &rounds[1];
        assert_eq!(one_pass.len(), 400_000);
        if leader {
            for queue in [&one_pass, &three_calls] {
                let (best, plan) = queue.frames_for_build(B256::repeat_byte(0x11), 200_000 * 21_000);
                assert_eq!(plan.frames.len(), 400);
                // The build used everything: nothing to give back on drop.
                let used: Vec<_> = best.collect();
                assert_eq!(used.len(), 200_000);
            }
        }
        let at = std::time::Instant::now();
        let (back, times) = one_pass.prune_block(100, B256::repeat_byte(0x64), block, block_hashes);
        let took = at.elapsed();
        assert_eq!(back, 0);
        assert_eq!(times.senders, 400);
        assert_eq!(times.frames_swept, 400);
        eprintln!("leader {leader}: prune of 200,000 from 400,000 in {took:?} {times:?}");
        prune_three_calls(&three_calls, 100, B256::repeat_byte(0x64), block, block_hashes);
        let mut probe: Vec<B256> = block_hashes.iter().step_by(97).copied().collect();
        probe.extend(rest_hashes.iter().step_by(97));
        let a = observe(&one_pass, &probe, 0x21);
        let b = observe(&three_calls, &probe, 0x21);
        assert!(a == b, "the one-pass prune and the three calls disagree");
        let (got, depth, gate, frames, held) = a;
        assert_eq!(depth, 200_000);
        assert_eq!(gate, 200_000);
        assert_eq!(frames, 400);
        let from: HashMap<Address, u64> = (0..400).map(|s| (sender(s), 500)).collect();
        assert_offered(&got, &from, rest);
        let split = block_hashes.iter().step_by(97).count();
        assert!(held[..split].iter().all(|h| !h), "a block hash is still in the index");
        assert!(held[split..].iter().all(|h| *h), "a queued hash left the index");
        // Never again: re-arrivals of the block are stale, and a give-back
        // of them (an untake) is filtered as mined.
        one_pass.push(block.iter().take(1_000).map(|(s, n)| tx_hashed(*s, *n)).collect::<Vec<_>>());
        let replay: Vec<_> = block.iter().skip(1_000).take(1_000).map(|(s, n)| {
            Arc::new(ValidPoolTransaction {
                transaction: tx_hashed(*s, *n),
                transaction_id: TransactionId::new(SenderId::from(0), *n),
                propagate: false,
                timestamp: std::time::Instant::now(),
                origin: TransactionOrigin::External,
                authority_ids: None,
            })
        }).collect();
        one_pass.untake(replay);
        let again = offered(&one_pass, 0x22);
        assert_offered(&again, &from, rest);
        #[cfg(not(debug_assertions))]
        assert!(
            took < std::time::Duration::from_millis(25),
            "a 200,000-transaction prune took {took:?} (the node's took 49-65 ms on a busy runtime)"
        );
    }
}

/// An own block held at a height: settled by the prune of another block at
/// that height, its transactions the committed block does not carry come
/// back (in nonce order, offered again); settled by the prune of the same
/// block, nothing comes back and nothing is lost.
#[test]
fn an_uncommitted_own_block_is_held_until_the_prune_settles_its_height() {
    let (queue, rounds) = deep_queue(20, 2, 50);
    let (block, _) = &rounds[0];
    // Our block at 9: the first round, taken out of the lanes and held.
    let held = queue.remove_mined_batch_collecting(block.iter().copied());
    assert_eq!(held.len(), 1_000);
    queue.hold_own_block(9, B256::repeat_byte(0x90), held);
    assert_eq!(queue.len(), 1_000);
    // While held: no build is offered them.
    let during = offered(&queue, 0x30);
    assert!(during.iter().all(|(_, n)| *n >= 50));
    // Another block at 9 carries the first ten nonces of every sender.
    let carried: Vec<(Address, u64)> = block.iter().filter(|(_, n)| *n < 10).copied().collect();
    let (back, _) = queue.prune_block(9, B256::repeat_byte(0x91), &carried, &[]);
    assert_eq!(back, 800, "every nonce 10..50 of twenty senders comes back");
    let from: HashMap<Address, u64> = (0..20).map(|s| (sender(s), 10)).collect();
    let mut expected: Vec<(Address, u64)> = block.iter().filter(|(_, n)| *n >= 10).copied().collect();
    expected.extend(rounds[1].0.iter().copied());
    assert_offered(&offered(&queue, 0x31), &from, &expected);
    // The same hash at the next height: settled, nothing back.
    let next: Vec<(Address, u64)> = expected.iter().filter(|(_, n)| *n < 20).copied().collect();
    let held = queue.remove_mined_batch_collecting(next.iter().copied());
    assert_eq!(held.len(), 200);
    queue.hold_own_block(10, B256::repeat_byte(0xa0), held);
    let (back, _) = queue.prune_block(10, B256::repeat_byte(0xa0), &next, &[]);
    assert_eq!(back, 0);
    let from: HashMap<Address, u64> = (0..20).map(|s| (sender(s), 20)).collect();
    let rest: Vec<(Address, u64)> = expected.iter().filter(|(_, n)| *n >= 20).copied().collect();
    assert_offered(&offered(&queue, 0x32), &from, &rest);
    assert_eq!(queue.take_drops().counts[Dropped::HeldBehind.index()], 0);
}

/// Prunes racing pushes, walk and frame builds, untakes and each other:
/// at the end every transaction is either in one of the pruned blocks or
/// offered exactly once, in each sender's nonce order, and no pruned one is
/// offered.
#[test]
fn a_prune_racing_push_selection_untake_and_another_prune_loses_nothing() {
    use std::sync::Barrier;
    let senders = 200u64;
    let (queue, rounds) = deep_queue(senders, 4, 100);
    let start = Arc::new(Barrier::new(4));
    let mut threads = Vec::new();
    // Two prunes, blocks 1 and 2 (rounds 0 and 1), at once.
    for (k, (pairs, hashes)) in rounds.iter().take(2).cloned().enumerate() {
        let (queue, start) = (queue.clone(), Arc::clone(&start));
        threads.push(std::thread::spawn(move || {
            start.wait();
            let (back, _) = queue.prune_block(1 + k as u64, B256::repeat_byte(0xb0 + k as u8), &pairs, &hashes);
            assert_eq!(back, 0);
        }));
    }
    // A pusher: round 4 (nonces 400..500) of every sender.
    let fresh: Vec<(Address, u64)> = {
        let (queue, start) = (queue.clone(), Arc::clone(&start));
        let fresh: Vec<(Address, u64)> = (0..senders).flat_map(|s| (400..500).map(move |n| (sender(s), n))).collect();
        threads.push(std::thread::spawn(move || {
            start.wait();
            for s in 0..senders {
                frame(&queue, sender(s), 400, 100);
            }
        }));
        fresh
    };
    // One selection thread (the node has one builder): walk builds that
    // take and untake part of their take, and frame builds superseded by
    // the next build, alternately.
    {
        let (queue, start) = (queue.clone(), Arc::clone(&start));
        threads.push(std::thread::spawn(move || {
            start.wait();
            for b in 0..20u8 {
                let mut best = queue.best_for_build(B256::repeat_byte(0x40 + b));
                let taken: Vec<_> = (0..3_000).filter_map(|_| best.next()).collect();
                drop(best);
                queue.untake(taken.into_iter().step_by(2).collect());
                let (best, _) = queue.frames_for_build(B256::repeat_byte(0x80 + b), 5_000 * 21_000);
                let half: Vec<_> = best.take(2_500).collect();
                drop(half);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("a racer panicked");
    }
    let mut expected: Vec<(Address, u64)> = rounds[2].0.clone();
    expected.extend(rounds[3].0.iter().copied());
    expected.extend(fresh);
    let from: HashMap<Address, u64> = (0..senders).map(|s| (sender(s), 200)).collect();
    // The last build's take comes back with the next build's start.
    let got = offered(&queue, 0xee);
    assert_offered(&got, &from, &expected);
    for (_, hashes) in rounds.iter().take(2) {
        assert!(hashes.iter().all(|h| queue.get_by_hash(h).is_none()));
    }
}

/// The prune's cost at the bench tier, against the three calls it replaces:
/// `cargo test -p n42-tx-queue --release --lib -- --ignored bench_prune_block --nocapture`.
#[test]
#[ignore = "timing"]
fn bench_prune_block() {
    for (leader, one) in [(false, false), (false, true), (true, false), (true, true)] {
        let (queue, rounds) = deep_queue(400, 2, 500);
        if leader {
            let (best, _) = queue.frames_for_build(B256::repeat_byte(0x11), 200_000 * 21_000);
            drop(best.collect::<Vec<_>>());
        }
        let (block, hashes) = &rounds[0];
        let at = std::time::Instant::now();
        if one {
            let (_, times) = queue.prune_block(100, B256::repeat_byte(1), block, hashes);
            eprintln!("leader {leader} one-pass: {:?} {times:?}", at.elapsed());
        } else {
            prune_three_calls(&queue, 100, B256::repeat_byte(1), block, hashes);
            eprintln!("leader {leader} three calls: {:?}", at.elapsed());
        }
    }
}

/// The inbox drain at the feed's target: 3.5M transactions a second is
/// 17,500 per 5 ms drainer tick (35 frames of 500), into a queue already
/// 2,000,000 deep, timed under the lanes' lock as the 5 s line reports it:
/// `cargo test -p n42-tx-queue --release --lib -- --ignored bench_drain --nocapture`.
#[test]
#[ignore = "timing"]
fn bench_drain() {
    let (queue, _) = deep_queue(2_000, 2, 500);
    let _ = take_lock_stats();
    for tick in 0..8u64 {
        for s in 0..35u64 {
            // The next frame of a sender already queued: its lane grows.
            frame(&queue, sender(tick * 35 + s), 1_000, 500);
        }
        let at = std::time::Instant::now();
        queue.drain_now();
        let took = at.elapsed();
        let stats = take_lock_stats();
        eprintln!(
            "tick {tick}: drain of 17,500 into {} in {took:?} (under the lock {} us, longest hold {} us)",
            queue.gate_len(),
            stats.drain_ns / 1_000,
            stats.hold_max_ns / 1_000
        );
    }
}

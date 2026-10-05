// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The feed path's queue side (`docs/SHARED_EXECUTION_SCOPE.md` 11): the
//! gate's depth read without the lanes' lock, and a canonical block's prune
//! in one pass ([`TxQueue::prune_block`]).

use super::*;
use alloy_primitives::{Signature, TxKind, U256};
use reth_transaction_pool::EthPooledTransaction;

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

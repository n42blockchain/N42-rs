// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The drain in bounded holds (`N42_TX_QUEUE_DRAIN_CHUNK`,
//! `docs/SHARED_EXECUTION_SCOPE.md` 12): the same queue as the one-hold
//! drain, each hold bounded, the gate never short.

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;


fn scenario(queue: &TxQueue<EthPooledTransaction>) {
    fill(queue, 25, 6, 4, 0);
    // Loose transactions, a duplicate and a stale one.
    queue.push((0..25u64).map(|s| tx_hashed(sender(s), 24)).collect::<Vec<_>>());
    queue.push([tx_hashed(sender(3), 0)]);
    queue.remove_mined(sender(4), 1);
    queue.push([tx_hashed(sender(4), 1)]);
    fill(queue, 25, 2, 4, 6);
}

fn snapshot(queue: &TxQueue<EthPooledTransaction>) -> (usize, usize, Vec<B256>, Vec<(Address, u64)>) {
    let frames: Vec<B256> = queue.frames_in_arrival_order().map(|f| f.id).collect();
    let (len, gate) = (queue.len(), queue.gate_len());
    let offered: Vec<(Address, u64)> = queue.best_for_build(B256::repeat_byte(0x99)).map(|t| (t.sender(), t.nonce())).collect();
    (len, gate, frames, offered)
}

/// The chunked drain leaves the queue the one-hold drain leaves: the same
/// depth, the same frames in the same order, the same offer order.
#[test]
fn a_chunked_drain_is_the_one_hold_drain() {
    for chunk in [1usize, 7, 64, 100_000] {
        let one: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_chunk(0);
        let chunked: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_chunk(chunk);
        // Pushed and drained in the same steps.
        scenario(&one);
        one.drain_now();
        scenario(&chunked);
        chunked.drain_now();
        assert_eq!(chunked.gate_len(), chunked.gate_len_locked());
        assert_eq!(snapshot(&one), snapshot(&chunked), "chunk {chunk}");
    }
}

/// Each hold of a chunked drain moves at most its chunk, and the batch is
/// all moved by the drain's end.
#[test]
fn a_chunked_drain_holds_the_lock_for_at_most_its_chunk() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_chunk(1_000);
    fill(&queue, 50, 20, 10, 0);
    let holds = queue.drain_chunked(1_000, usize::MAX);
    assert!(holds.iter().all(|moved| *moved <= 1_000), "{holds:?}");
    assert_eq!(holds.iter().sum::<u64>(), 10_000 + 7 * 2 * 10);
    assert!(holds.len() >= 10, "{holds:?}");
    assert!(queue.lock_inner().pending_drain.is_empty());
}

/// A build that starts while a chunked drain's remainder is pending finishes
/// it first: its plan sees every frame the remainder carries, in arrival
/// order, as if the drain had been one hold.
#[test]
fn a_build_during_a_chunked_drain_finishes_it_first() {
    let gas = 200 * 21_000;
    let chunked: TxQueue<EthPooledTransaction> = TxQueue::new();
    let one: TxQueue<EthPooledTransaction> = TxQueue::new();
    fill(&chunked, 20, 6, 5, 0);
    fill(&one, 20, 6, 5, 0);
    // One hold of 50 moved; the rest (and every frame) still pending.
    let holds = chunked.drain_chunked(50, 1);
    assert_eq!(holds, vec![50]);
    assert!(!chunked.lock_inner().pending_drain.is_empty());
    assert_eq!(chunked.gate_len(), chunked.gate_len_locked());
    assert_eq!(chunked.gate_len(), one.gate_len());
    // Later arrivals into the inbox.
    fill(&chunked, 20, 1, 5, 6);
    fill(&one, 20, 1, 5, 6);
    let (mut a, plan_a, _) = chunked.frames_for_build_in(block_hash(0), gas, SelectMode::Parallel);
    let (mut b, plan_b, _) = one.frames_for_build_in(block_hash(0), gas, SelectMode::Parallel);
    assert_eq!(plan_a, plan_b);
    let (ta, tb): (Vec<Tx>, Vec<Tx>) = (a.by_ref().collect(), b.by_ref().collect());
    assert_eq!(pairs(&ta), pairs(&tb));
    drop((a, b));
    assert!(chunked.lock_inner().pending_drain.is_empty());
}

/// The gate never reads fewer than were pushed while chunked drains move the
/// inbox: the batch is in `staged`, `in_hand` or the mirror at every moment.
#[test]
fn the_gate_never_undercounts_a_chunked_drain() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_chunk(97);
    let pushed = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let pusher = {
        let (queue, pushed, stop) = (queue.clone(), Arc::clone(&pushed), Arc::clone(&stop));
        std::thread::spawn(move || {
            for round in 0..300u64 {
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
    assert_eq!(queue.gate_len(), 75_000);
    assert_eq!(queue.gate_len(), queue.gate_len_locked());
    assert!(reads > 0);
}

/// The drain at the feed's target shape, chunked: 17,500 transactions a 5 ms
/// tick (3.5M/s, frames of 500) appended to a 2,000,000-deep queue; the
/// longest hold and the whole drain. `cargo test -p n42-tx-queue --release
/// --lib -- --ignored bench_drain_chunked --nocapture`.
#[test]
#[ignore]
fn bench_drain_chunked() {
    for chunk in [0usize, 16_384, 8_192, 4_096] {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_drain_chunk(chunk);
        // 4,000 senders x 500: the deep part, drained in one go first.
        for round in 0..1u64 {
            for s in 0..4_000u64 {
                frame(&queue, sender(s), round * 500, 500);
            }
        }
        queue.drain_now();
        let mut longest = std::time::Duration::ZERO;
        let mut whole = std::time::Duration::ZERO;
        for tick in 0..20u64 {
            // 35 frames of 500 from senders whose lanes are queued.
            for k in 0..35u64 {
                frame(&queue, sender((tick * 35 + k) % 4_000), 500 + tick * 500, 500);
            }
            let at = std::time::Instant::now();
            if chunk == 0 {
                let mut inner = queue.lock_inner();
                queue.drain_inbox(&mut inner);
                drop(inner);
                longest = longest.max(at.elapsed());
            } else {
                let started = std::time::Instant::now();
                let holds = queue.drain_chunked(chunk, usize::MAX);
                let per = started.elapsed() / u32::try_from(holds.len().max(1)).unwrap_or(1);
                longest = longest.max(per);
            }
            whole += at.elapsed();
        }
        eprintln!("chunk {chunk}: longest hold ~{longest:?}, mean drain {:?}", whole / 20);
    }
}

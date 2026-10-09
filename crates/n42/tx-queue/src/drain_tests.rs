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

/// A bounded drain (`N42_QUEUE_OFFLOCK` with a dedicated drainer, the block
/// path's holds) moves at most its slice, oldest first; what it leaves stays
/// queued and in order, a frame is indexed only once its last transaction is
/// in, and later drains complete it to the queue the one-hold drain makes.
#[test]
fn a_bounded_drain_leaves_the_rest_in_order() {
    let one: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(true).with_drain_chunk(0);
    let bounded: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(true).with_drain_chunk(0);
    scenario(&one);
    one.drain_now();
    scenario(&bounded);
    let mut len = bounded.len();
    let mut moves = Vec::new();
    loop {
        let mut inner = bounded.lock_inner_quiet();
        let moved = bounded.drain_inbox_upto(&mut inner, 37);
        assert!(moved <= 37);
        // A frame is indexed only with all of its transactions in a lane.
        for frame in inner.frames.in_arrival_order(&inner.lanes) {
            for (sender, nonce, _) in inner.frames.members_of(&frame.id).expect("indexed") {
                let lane = inner.lanes.get(&sender).expect("lane");
                let taken = lane.by_nonce.contains_key(&nonce) || lane.is_stale(nonce);
                assert!(taken, "frame indexed before its transaction ({sender}, {nonce}) was in");
            }
        }
        let done = inner.pending_drain.is_empty() && inner.pending_frames.is_empty();
        drop(inner);
        // The remainder stays counted: only a duplicate or a stale arrival,
        // dropped as it reaches its lane, leaves the depth.
        let now = bounded.len();
        assert!(now <= len && now == bounded.gate_len(), "depth {now} after {len}");
        len = now;
        moves.push(moved);
        if done {
            break;
        }
        if moves.len() == 3 {
            // Arrivals behind the remainder: drained after it, in order.
            fill(&bounded, 25, 1, 4, 8);
            fill(&one, 25, 1, 4, 8);
            return finish(&one, &bounded);
        }
    }
    panic!("the scenario drained in fewer than three slices: {moves:?}");

    fn finish(one: &TxQueue<EthPooledTransaction>, bounded: &TxQueue<EthPooledTransaction>) {
        one.drain_now();
        {
            let mut inner = bounded.lock_inner_quiet();
            while bounded.drain_inbox_upto(&mut inner, 37) > 0 {}
            assert!(inner.pending_drain.is_empty() && inner.pending_frames.is_empty());
        }
        assert_eq!(snapshot(bounded), snapshot(one));
    }
}

/// The block path's drain is bounded only while a dedicated drainer runs;
/// without one it drains everything, as before.
#[test]
fn the_block_path_drains_a_slice_only_beside_a_drainer() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(true);
    for s in 0..10u64 {
        frame(&queue, sender(s), 0, 500);
    }
    {
        let mut inner = queue.lock_inner_quiet();
        queue.drain_inbox_block(&mut inner);
        assert_eq!(inner.len, 5_000);
    }
    for s in 0..10u64 {
        frame(&queue, sender(s), 500, 500);
    }
    queue.drainer.running.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut inner = queue.lock_inner_quiet();
    queue.drain_inbox_block(&mut inner);
    assert_eq!(inner.len, 5_000 + BLOCK_DRAIN_SLICE);
    assert_eq!(inner.pending_drain.len(), 5_000 - BLOCK_DRAIN_SLICE);
}

/// `usable()` under `N42_QUEUE_OFFLOCK` counts the inbox without draining
/// it and reads what the draining `usable()` of the one-lock queue reads,
/// on the first call, a repeat (the cached walk) and after more arrivals.
#[test]
fn usable_counts_the_inbox_without_draining_it() {
    let old: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(false);
    let new: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(true);
    for queue in [&old, &new] {
        fill(queue, 40, 3, 5, 0);
        queue.drain_now();
        // A build takes some, leaving lanes in and out of the order.
        let taken = queue.best_for_build(B256::repeat_byte(0x42)).take(77).count();
        assert_eq!(taken, 77);
        // An inbox of fresh lanes and later nonces of queued ones.
        fill(queue, 60, 1, 5, 3);
    }
    assert!(new.staged.load(std::sync::atomic::Ordering::Acquire) > 0);
    let first = new.usable();
    assert!(new.staged.load(std::sync::atomic::Ordering::Acquire) > 0, "usable() drained the inbox");
    assert_eq!(first, old.usable());
    assert_eq!(new.usable(), first);
    // A drain moves the inbox into the lanes; the reading does not move.
    new.drain_now();
    assert_eq!(new.usable(), first);
    for queue in [&old, &new] {
        fill(queue, 70, 1, 5, 4);
    }
    assert_eq!(new.usable(), old.usable());
    new.drain_now();
    assert_eq!(new.usable(), old.usable());
}

/// The dedicated drainer keeps up with a flood of frames while the block
/// path's holds are taken back to back: no such hold moves more than
/// [`BLOCK_DRAIN_SLICE`] transactions or holds the lock long (debug-build
/// bound), the drainer empties the inbox once the flood stops, and the
/// queue ends whole: every transaction queued, every frame indexed.
#[test]
fn the_drainer_keeps_up_under_a_flood() {
    use std::sync::atomic::{AtomicBool, Ordering};
    const SENDERS: u64 = 400;
    const ROUNDS: u64 = 4;
    const PER: u64 = 250;
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(true).with_drain_chunk(0);
    let stop = Arc::new(AtomicBool::new(false));
    let drainer = {
        let (queue, stop) = (queue.clone(), Arc::clone(&stop));
        std::thread::spawn(move || queue.run_drainer_until(std::time::Duration::from_millis(5), &stop))
    };
    while !queue.drainer.running.load(Ordering::Relaxed) {
        std::thread::yield_now();
    }
    let flooded = Arc::new(AtomicBool::new(false));
    let pusher = {
        let (queue, flooded) = (queue.clone(), Arc::clone(&flooded));
        std::thread::spawn(move || {
            for round in 0..ROUNDS {
                for s in 0..SENDERS {
                    frame(&queue, sender(s), round * PER, PER);
                }
            }
            flooded.store(true, Ordering::SeqCst);
        })
    };
    let (mut holds, mut most_moved, mut longest) = (0u64, 0usize, std::time::Duration::ZERO);
    let mut usable_longest = std::time::Duration::ZERO;
    while !flooded.load(Ordering::SeqCst) {
        {
            let mut inner = queue.lock_inner();
            let at = std::time::Instant::now();
            let before = inner.len;
            queue.drain_inbox_block(&mut inner);
            longest = longest.max(at.elapsed());
            most_moved = most_moved.max(inner.len - before);
        }
        let at = std::time::Instant::now();
        let _ = queue.usable();
        usable_longest = usable_longest.max(at.elapsed());
        holds += 1;
    }
    pusher.join().expect("pusher");
    let total = (SENDERS * ROUNDS * PER) as usize;
    // Caught up by the drainer alone: no block-path hold from here on.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let inner = queue.lock_inner_quiet();
        if inner.len == total && inner.pending_drain.is_empty() && inner.pending_frames.is_empty() {
            assert_eq!(inner.frames.len(), (SENDERS * ROUNDS) as usize);
            break;
        }
        let state = (inner.len, inner.pending_drain.len());
        drop(inner);
        assert!(std::time::Instant::now() < deadline, "the drainer did not catch up: (len, remainder) {state:?}");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    stop.store(true, Ordering::SeqCst);
    drainer.join().expect("drainer");
    eprintln!(
        "block-path holds {holds}: most moved {most_moved}, longest drain {longest:?}, longest usable() {usable_longest:?}"
    );
    assert!(holds > 0);
    assert!(most_moved <= BLOCK_DRAIN_SLICE, "a block-path hold moved {most_moved}");
    assert!(longest < std::time::Duration::from_millis(250), "a block-path drain held {longest:?}");
    assert_eq!(queue.len(), total);
    assert_eq!(queue.usable(), total);
}

/// What `usable()`'s old hold cost, drain against walk, at the flood's
/// lane count: 200,000 lanes queued, 23,000 arrivals in the inbox (loop351
/// X8's mean drain). `cargo test -p n42-tx-queue --lib -- --ignored
/// bench_usable_parts --nocapture`.
#[test]
#[ignore]
fn bench_usable_parts() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_offlock(false);
    for chunk in 0..20u64 {
        let batch: Vec<EthPooledTransaction> = (chunk * 10_000..(chunk + 1) * 10_000).map(|s| tx_hashed(sender(s), 0)).collect();
        queue.push(batch);
        queue.drain_now();
    }
    queue.push((0..23_000u64).map(|s| tx_hashed(sender(s), 1)).collect::<Vec<_>>());
    let mut inner = queue.lock_inner_quiet();
    let at = std::time::Instant::now();
    queue.drain_inbox(&mut inner);
    let drain = at.elapsed();
    let at = std::time::Instant::now();
    let usable = inner.usable();
    let walk = at.elapsed();
    eprintln!("lanes {}: drain of 23,000 {drain:?}, walk {walk:?} (usable {usable})", inner.lanes.len());
}

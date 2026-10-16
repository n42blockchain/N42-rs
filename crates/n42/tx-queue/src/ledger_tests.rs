// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_QUEUE_LEDGER_LOCK`: the own-block ledger under a lock of its own
//! ([`Ledger`]) leaves the queue where the single lock leaves it, on a
//! sequence that interleaves builds on prepared plans, the whole-take
//! hand-off, own-block holds, drains, canonical prunes, a build that is
//! never handed off, evictions past the hold bound and a settle that gives
//! transactions back.

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

/// Each lane's nonces and watermarks, the depth, the held blocks, the
/// drops, `handed` and the logical taken list.
type LedgerState = (
    Vec<(Address, Vec<u64>, Option<u64>, Option<u64>)>,
    usize,
    Vec<(u64, B256, usize)>,
    DropReport,
    Option<Handed>,
    Vec<(Address, u64)>,
);

fn ledger_state(queue: &TxQueue<EthPooledTransaction>) -> LedgerState {
    let mut inner = queue.lock_inner_quiet();
    queue.drain_inbox(&mut inner);
    let mut lanes: Vec<_> = inner
        .lanes
        .iter()
        .map(|(sender, lane)| (*sender, lane.by_nonce.keys().copied().collect(), lane.mined, lane.chain_mined))
        .collect();
    lanes.sort();
    let len = inner.len;
    let taken = inner.taken_view().map(|taken| pairs(&taken)).unwrap_or_default();
    drop(inner);
    (lanes, len, queue.held_view(), queue.drops_view(), queue.handed_view(), taken)
}

/// The whole-take checks the builder sends for `body`.
fn checks(body: &[(Address, u64)]) -> Vec<(usize, Address, u64)> {
    let last = body.len() - 1;
    [0, last / 2, last].into_iter().map(|i| (i, body[i].0, body[i].1)).collect()
}

fn ledger_sequence(ledger: bool) -> (Vec<Vec<(Address, u64)>>, LedgerState, usize) {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_ledger_lock(ledger);
    let gas = 120 * 21_000;
    fill(&queue, 40, 30, 5, 0);
    let bound = own_hold_blocks() as u64;
    let blocks = bound + 4;
    let mut parent = block_hash(0);
    let mut bodies = Vec::new();
    let mut sealed: Vec<(u64, B256, Vec<Tx>)> = Vec::new();
    let mut published = 0usize;
    for n in 1..=blocks {
        let (mut best, _, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
        queue.prepare_next_in(gas, SelectMode::Parallel);
        let txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        // Arrivals and a drain between the seal and the hand-off.
        fill(&queue, 40, 1, 5, 30 + n);
        queue.drain_now();
        if n == 3 {
            // This block is never handed off (its view timed out): the next
            // build stands on the same parent and gives its take back.
            continue;
        }
        if ledger && times.ahead > 0 {
            published += usize::from(queue.lock_ledger().whole.is_some());
        }
        let body = pairs(&txs);
        let hash = block_hash(n);
        let (dropped, forget) = queue.forget_whole_take(parent, body.len(), &checks(&body)).expect("the whole take");
        assert!(forget.whole);
        assert_eq!(pairs(&dropped), body, "block {n}");
        // The hand-off's order under `N42_HANDOFF_DONE_FIRST`.
        queue.mark_handed_block(hash);
        queue.drain_now();
        queue.hold_own_block_timed(n, hash, dropped);
        // The chain commits the first two heights only, so the later held
        // blocks pass the bound and are evicted.
        if n <= 2 {
            let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
            queue.prune_block(n, hash, &body, &hashes);
        }
        sealed.push((n, hash, txs));
        bodies.push(body);
        parent = hash;
    }
    // The last held height goes to another block carrying half of ours: the
    // settle gives the other half back, then the prune removes the half.
    let (n, _, txs) = sealed.last().expect("a sealed block");
    let half = &txs[..txs.len() / 2];
    let hashes: Vec<B256> = half.iter().map(|t| *t.hash()).collect();
    let (back, _) = queue.prune_block(*n, B256::repeat_byte(0xEE), &pairs(half), &hashes);
    assert_eq!(back, txs.len() - half.len());
    queue.drain_now();
    (bodies, ledger_state(&queue), published)
}

#[test]
fn the_ledger_lock_leaves_the_single_lock_state() {
    let (plain_bodies, plain, _) = ledger_sequence(false);
    let (ledger_bodies, ledger, published) = ledger_sequence(true);
    assert_eq!(plain_bodies, ledger_bodies);
    assert_eq!(plain, ledger);
    assert!(plain.3.counts[Dropped::HeldEvicted.index()] > 0, "the bound was reached");
    // Every hand-off after a build on a prepared plan found its take in the
    // ledger (blocks 1 and 4 plan afresh: the first, and the one after the
    // block never handed off).
    assert!(published >= plain_bodies.len() - 2, "published {published} of {}", plain_bodies.len());
}

/// With the switch on, the whole-take hand-off, the hold and a settle that
/// gives nothing back never take the lanes' lock: they complete while
/// another thread holds it.
#[test]
fn the_ledger_steps_do_not_wait_for_the_lanes() {
    let queue: TxQueue<EthPooledTransaction> = TxQueue::new().with_ledger_lock(true);
    let gas = 120 * 21_000;
    fill(&queue, 40, 12, 5, 0);
    let mut parent = block_hash(0);
    let mut off_lanes = 0;
    for n in 1..=3u64 {
        let (mut best, _, times) = queue.frames_for_build_ahead(parent, gas, SelectMode::Parallel, false);
        queue.prepare_next_in(gas, SelectMode::Parallel);
        let txs: Vec<Tx> = best.by_ref().collect();
        drop(best);
        let body = pairs(&txs);
        let hash = block_hash(n);
        let lanes = queue.lock_inner_quiet();
        let (dropped, forget) = if times.ahead > 0 {
            // The lanes' lock is held here: the ledger's steps must not need it.
            let out = std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let out = queue.forget_whole_take(parent, body.len(), &checks(&body));
                        if let Some((dropped, _)) = out.as_ref() {
                            queue.mark_handed_block(hash);
                            queue.hold_own_block_timed(n, hash, dropped.clone());
                            queue.settle_own_block(n.saturating_sub(1), block_hash(n - 1), |_, _| false);
                        }
                        out
                    })
                    .join()
                    .expect("the ledger steps")
            });
            drop(lanes);
            off_lanes += 1;
            out.expect("the whole take from the ledger")
        } else {
            drop(lanes);
            let out = queue.forget_whole_take(parent, body.len(), &checks(&body)).expect("the whole take");
            queue.mark_handed_block(hash);
            queue.hold_own_block_timed(n, hash, out.0.clone());
            out
        };
        assert!(forget.whole);
        assert_eq!(pairs(&dropped), body);
        parent = hash;
    }
    assert_eq!(off_lanes, 2, "blocks 2 and 3 stand on prepared plans");
    // Each settle dropped the block before as committed.
    assert_eq!(queue.held_view().len(), 1);
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_HANDOFF_DONE_FIRST`'s folded hold and `N42_PRUNE_LEAN`'s folded
//! prune, each held against the default path on the same sequence.

use super::test_support::*;
use super::*;
use reth_transaction_pool::EthPooledTransaction;

/// What a hold sequence leaves: the drop report, the held blocks and the
/// lanes' depth.
fn hold_state(queue: &TxQueue<EthPooledTransaction>) -> (DropReport, Vec<(u64, B256, usize)>, usize) {
    let inner = queue.lock_inner_quiet();
    let held = inner.held.iter().map(|(n, h, txs)| (*n, *h, txs.len())).collect();
    (inner.drops.clone(), held, inner.len)
}

fn hold_sequence(lean: bool) -> ((DropReport, Vec<(u64, B256, usize)>, usize), usize) {
    let queue = TxQueue::<EthPooledTransaction>::new();
    let blocks = own_hold_blocks() as u64 + 3;
    fill(&queue, 40, blocks, 1, 0);
    let mut evicted = 0;
    for n in 1..=blocks {
        let mined: Vec<(Address, u64)> = (0..40).map(|s| (sender(s), n - 1)).collect();
        // Sorted: the collecting removal's order follows a hash map's.
        let mut removed = queue.remove_mined_batch_collecting(mined);
        removed.sort_by_key(|t| (t.sender(), t.nonce()));
        assert_eq!(removed.len(), 40);
        evicted += queue.hold_own_block_with(n, block_hash(n), removed, lean).evicted;
    }
    (hold_state(&queue), evicted)
}

#[test]
fn lean_hold_matches_the_default_hold() {
    let (lean, lean_evicted) = hold_sequence(true);
    let (plain, plain_evicted) = hold_sequence(false);
    assert_eq!(lean_evicted, 3 * 40, "three blocks evicted past the bound");
    assert_eq!(lean_evicted, plain_evicted);
    assert_eq!(lean.0.counts[Dropped::HeldEvicted.index()], 120);
    assert_eq!(lean.0.samples.len(), DROP_SAMPLES);
    assert_eq!(lean, plain);
}

/// Each lane's nonces and watermarks, the lanes' depth, the by-hash index's
/// size and what is held, after the inbox is drained.
type PruneState = (Vec<(Address, Vec<u64>, Option<u64>, Option<u64>)>, usize, usize, Vec<(u64, B256, usize)>);

fn prune_state(queue: &TxQueue<EthPooledTransaction>) -> PruneState {
    let mut inner = queue.lock_inner_quiet();
    queue.drain_inbox(&mut inner);
    let mut lanes: Vec<_> = inner
        .lanes
        .iter()
        .map(|(sender, lane)| (*sender, lane.by_nonce.keys().copied().collect(), lane.mined, lane.chain_mined))
        .collect();
    lanes.sort();
    let held = inner.held.iter().map(|(n, h, txs)| (*n, *h, txs.len())).collect();
    let len = inner.len;
    drop(inner);
    (lanes, len, queue.hash_index_len(), held)
}

/// Four canonical blocks over a queue whose inbox still holds what the
/// blocks mine, an own block held at height 2 that is not the committed one
/// (its settle gives back), and a sender whose only transactions are in the
/// inbox: pruned block by block, or folded (`lean`).
fn prune_sequence(lean: bool, offlock: bool) -> (PruneState, usize) {
    let queue = TxQueue::<EthPooledTransaction>::new().with_offlock(offlock);
    fill(&queue, 40, 6, 3, 0);
    let own: Vec<(Address, u64)> = (0..10).map(|s| (sender(s), 5)).collect();
    let mut held = queue.remove_mined_batch_collecting(own);
    held.sort_by_key(|t| (t.sender(), t.nonce()));
    queue.hold_own_block(2, B256::repeat_byte(0xEE), held);
    // Left in the inbox: later rounds, and a sender with no lane yet.
    fill(&queue, 40, 2, 3, 6);
    frame(&queue, sender(5_000), 0, 4);
    let blocks: Vec<(u64, Vec<(Address, u64)>, Vec<B256>)> = (1..=4u64)
        .map(|n| {
            let mut mined: Vec<(Address, u64)> = (0..40u64)
                .filter(|s| s % 5 != n)
                .flat_map(|s| (3 * (n - 1)..3 * n).map(move |nonce| (sender(s), nonce)))
                .collect();
            mined.push((sender(5_000), n - 1));
            let hashes = mined.iter().map(|(s, nonce)| *tx_hashed(*s, *nonce).hash()).collect();
            (n, mined, hashes)
        })
        .collect();
    let back = if lean {
        let inputs: Vec<PruneInput<'_>> = blocks
            .iter()
            .map(|(n, mined, hashes)| PruneInput { number: *n, hash: block_hash(*n), mined, hashes })
            .collect();
        let (back, times) = queue.prune_blocks(&inputs);
        assert_eq!(times.folded, 4);
        assert_eq!(times.removals, 2, "the run is cut before the settle that gives back");
        back
    } else {
        blocks.iter().map(|(n, mined, hashes)| queue.prune_block(*n, block_hash(*n), mined, hashes).0).sum()
    };
    (prune_state(&queue), back)
}

#[test]
fn lean_prune_matches_the_per_block_prune() {
    for offlock in [false, true] {
        let (lean, lean_back) = prune_sequence(true, offlock);
        let (plain, plain_back) = prune_sequence(false, offlock);
        assert!(plain_back > 0, "the own block at height 2 gives back");
        assert_eq!(lean_back, plain_back, "offlock={offlock}");
        assert_eq!(lean, plain, "offlock={offlock}");
    }
}

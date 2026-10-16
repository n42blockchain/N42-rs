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

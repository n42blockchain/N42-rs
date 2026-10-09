// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The builder queue's canonical pruner: every committed block's
//! transactions out of the queue, on every node.
//!
//! It used to be a tokio task on the execution layer's main runtime doing
//! 49-65 ms of synchronous work per 200,000-transaction block
//! (`docs/SHARED_EXECUTION_SCOPE.md` 10.1) on a runtime worker the ingest's
//! connections and the vote road also need. The work itself is now one pass
//! ([`n42_tx_queue::TxQueue::prune_block`], 5-10 ms in the unit test against
//! 69-76 for the three calls it replaced); with `N42_QUEUE_PRUNE_THREAD=1`
//! it also leaves the runtime: the task only forwards each notification to a
//! dedicated thread (`n42-queue-prune`), which takes every notification that
//! is waiting when it wakes (coalescing a burst into one wake, one block
//! after another in order) and prunes them.

use n42_engine_types::N42PooledTransaction;
use n42_tx_queue::TxQueue;
use n42_tx_types::N42Primitives;
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_provider::CanonStateNotification;
use tracing::{info, warn};

/// Whether the pruner runs on its own thread (`N42_QUEUE_PRUNE_THREAD=1`,
/// off by default).
pub fn on_own_thread() -> bool {
    std::env::var("N42_QUEUE_PRUNE_THREAD").is_ok_and(|v| v == "1")
}

/// One canonical notification's prune: a reorg's reverted transactions
/// offered again, then every committed block settled and pruned in order.
/// `coalesced` is how many notifications the thread took in this wake (1
/// on the runtime), `waited` how long this one waited for it.
pub fn prune_notification(
    queue: &TxQueue<N42PooledTransaction>,
    notification: &CanonStateNotification<N42Primitives>,
    coalesced: usize,
    waited: std::time::Duration,
) {
    let started = std::time::Instant::now();
    // A reorg: the reverted blocks' transactions are nowhere else -- with
    // the direct ingest the queue is their only holder -- so those the new
    // chain does not carry are offered again, before the new chain's prune
    // (which then removes any the new chain mined at a higher nonce).
    // Without this the affected senders' lanes started at a nonce ahead of
    // the chain and every leader refused them: half-empty blocks for the
    // rest of the leg (round 43).
    if let CanonStateNotification::Reorg { old, new } = notification {
        let reverted_blocks = old.blocks_iter().count();
        let back = crate::queue_reorg::reverted_transactions(old, new);
        let offered = back.len();
        // Through the reverted door: it lowers the senders' mined
        // watermarks, which the reverted blocks no longer justify.
        queue.push_reverted(back);
        warn!(target: "n42.tx_queue", reverted_blocks, offered, new_blocks = new.blocks_iter().count(), "reorg: the reverted blocks' transactions are offered again");
    }
    let mut mined = 0usize;
    // Where the prune's time goes (loop322 CTRL: 5 s on the new leader at
    // the handover): the own-block settle, the lanes' removal under the
    // lock, the by-hash index, microseconds; and the fold of the block's
    // pairs, the wait for the lock and the hand-off of what was removed to
    // the queue's freeing thread.
    let mut sum = n42_tx_queue::PruneTimes::default();
    for block in notification.committed().blocks_iter() {
        // What the builder reads to tell a build for a height the chain has
        // already decided from a build that is starving.
        n42_engine_types::canonical_head::saw(block.number());
        // What the builder compares its parent against: a build below this
        // is behind its own queue.
        queue.note_pruned(block.number());
        // One walk for both: the (sender, nonce) pairs the lanes are pruned
        // by, and the hashes the by-hash index is pruned by.
        let mut hashes: Vec<alloy_primitives::B256> = Vec::new();
        let pairs: Vec<(alloy_primitives::Address, u64)> = block
            .transactions_with_sender()
            .map(|(sender, tx)| {
                hashes.push(*alloy_consensus::transaction::TxHashRef::tx_hash(tx));
                (*sender, alloy_consensus::Transaction::nonce(tx))
            })
            .collect();
        mined += pairs.len();
        // An own block held at this height: the same hash is settled,
        // another hash gives back what this block does not carry (then
        // pruned where this block mined a higher nonce).
        let (back, times) = queue.prune_block(block.number(), block.hash(), &pairs, &hashes);
        if back > 0 {
            warn!(target: "n42.tx_queue", number = block.number(), back, "an own block at this height was not the one committed; its transactions are offered again");
        }
        sum.settle_us += times.settle_us;
        sum.fold_us += times.fold_us;
        sum.lock_us += times.lock_us;
        sum.remove_us += times.remove_us;
        sum.forget_us += times.forget_us;
        sum.free_us += times.free_us;
        sum.frames_swept += times.frames_swept;
    }
    if mined > 10_000 {
        // `usable` beside `queued`: what a build could take of the depth.
        // The two part company when lanes are parked behind a hole, which
        // is what loop207-208's defect 13 was -- 334-360k queued, empty
        // blocks, and no line saying which of the two it was.
        let (parked_lanes, parked, park_capped) = queue.parked();
        info!(
            target: "n42.tx_queue",
            mined,
            queued = queue.len(),
            usable = queue.usable(),
            parked,
            parked_lanes,
            park_capped,
            frames_indexed = queue.frames_indexed(),
            prune_ms = started.elapsed().as_millis() as u64,
            settle_us = sum.settle_us,
            remove_us = sum.remove_us,
            forget_us = sum.forget_us,
            fold_us = sum.fold_us,
            lock_us = sum.lock_us,
            free_us = sum.free_us,
            frames_swept = sum.frames_swept,
            coalesced,
            prune_wait_ms = waited.as_millis() as u64,
            "canonical blocks pruned from the queue"
        );
        // What the queue let go of since the last block, by reason, with
        // the first few named. A lane's hole -- a nonce the generator was
        // told this node had taken and that is in neither the queue nor a
        // block -- can only be made at one of these.
        let drops = queue.take_drops();
        if drops.interesting() {
            warn!(
                target: "n42.tx_queue",
                by_reason = ?drops.named(),
                first = ?drops.samples,
                "the queue let go of transactions"
            );
        }
    }
}

/// A notification on its way to the pruning thread, with when it arrived.
type Queued = (CanonStateNotification<N42Primitives>, std::time::Instant);

/// Starts the pruning thread; `None` (and a warning) if it could not be
/// started, and the caller prunes on the runtime as before.
pub fn spawn_thread(queue: TxQueue<N42PooledTransaction>) -> Option<std::sync::mpsc::Sender<Queued>> {
    let (tx, rx) = std::sync::mpsc::channel::<Queued>();
    let spawned = std::thread::Builder::new().name("n42-queue-prune".to_owned()).spawn(move || {
        while let Ok(first) = rx.recv() {
            // Everything already waiting is taken in this wake, in order.
            let mut batch = vec![first];
            while let Ok(next) = rx.try_recv() {
                batch.push(next);
            }
            let coalesced = batch.len();
            for (notification, arrived) in batch {
                prune_notification(&queue, &notification, coalesced, arrived.elapsed());
            }
        }
    });
    match spawned {
        Ok(_) => {
            info!(target: "n42.tx_queue", "canonical queue pruner on its own thread");
            Some(tx)
        }
        Err(err) => {
            warn!(target: "n42.tx_queue", %err, "N42_QUEUE_PRUNE_THREAD=1 but its thread could not be started; pruning on the runtime");
            None
        }
    }
}

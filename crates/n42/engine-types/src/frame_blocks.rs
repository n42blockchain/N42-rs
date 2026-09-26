// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frame-aligned blocks (`docs/BREAKTHROUGH_DESIGN.md` step 1, phase B).
//!
//! With `N42_FRAME_BLOCKS=1` on a chain whose genesis sets `frameBlocks`,
//! the builder pulls whole ingest frames in arrival order
//! ([`n42_tx_queue::TxQueue::frames_for_build`]), the last one possibly cut
//! to a prefix, and the block's transactions root is the frame tree
//! ([`crate::assembler::transactions_root_by_rule`] with the layout). The
//! follower assembles such a block from its frame description by reference
//! (`engine_validator::by_description`) and any body that arrives whole is
//! matched back to the frames this node indexed; a body that is not a run of
//! frames is not valid under the flag.
//!
//! Off (the default), nothing here is consulted and every root is the MPT
//! root, byte for byte as before.

use std::collections::VecDeque;
use std::sync::OnceLock;

use alloy_primitives::B256;
use n42_tx_queue::FramePlan;
use std::sync::Mutex;

static ACTIVE: OnceLock<bool> = OnceLock::new();

/// Decides the mode once, at start-up, from `N42_FRAME_BLOCKS` and the
/// chain's `frameBlocks` genesis flag. Refuses -- the caller must not start
/// -- when the variable asks for frame blocks on a chain that does not
/// enable them: a node that built frame-tree roots there would be proposing
/// blocks every other node refuses.
pub fn init(chain_enables: bool) -> Result<bool, String> {
    let requested = n42_tx_types::frame_blocks_requested();
    if requested && !chain_enables {
        return Err("N42_FRAME_BLOCKS=1 on a chain whose genesis does not set `frameBlocks: true`; \
                    refusing to start rather than build blocks no other node accepts"
            .to_owned());
    }
    let on = requested && chain_enables;
    let _ = ACTIVE.set(on);
    Ok(on)
}

/// Whether this node builds and checks frame-aligned blocks.
pub fn active() -> bool {
    if let Some(on) = OVERRIDE.with(std::cell::Cell::get) {
        return on;
    }
    ACTIVE.get().copied().unwrap_or(false)
}

std::thread_local! {
    static OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with the mode forced on or off for this thread only: what the
/// tests use, since the process-wide mode is decided once.
#[doc(hidden)]
pub fn with_active<R>(on: bool, f: impl FnOnce() -> R) -> R {
    let before = OVERRIDE.with(|slot| slot.replace(Some(on)));
    let out = f();
    OVERRIDE.with(|slot| slot.set(before));
    out
}

std::thread_local! {
    /// The plan of the frame build the selector just started on this
    /// thread: the selector and the build that consumes it run on one
    /// thread (`default_n42_payload` calls its selector synchronously).
    static PLAN: std::cell::RefCell<Option<FramePlan>> = const { std::cell::RefCell::new(None) };
}

/// The queue's selection for a build on `parent`: frames when the mode is
/// on (the plan left for [`take_plan`] on this thread), the ordinary walk
/// otherwise.
pub fn select<T: reth_transaction_pool::PoolTransaction>(
    queue: &n42_tx_queue::TxQueue<T>,
    parent: B256,
    gas_limit: u64,
) -> n42_tx_queue::QueueBest<T> {
    if !active() {
        return queue.best_for_build(parent);
    }
    let (best, plan) = queue.frames_for_build(parent, gas_limit);
    PLAN.with(|slot| *slot.borrow_mut() = Some(plan));
    best
}

/// The plan [`select`] left on this thread, taken.
pub fn take_plan() -> Option<FramePlan> {
    PLAN.with(|slot| slot.borrow_mut().take())
}

/// The frame layouts of the blocks this node built last, by transactions
/// root: what the execution layer hands its validator with the block, for
/// the frame description.
static LAYOUTS: Mutex<VecDeque<(B256, Vec<(B256, u32)>)>> = Mutex::new(VecDeque::new());
const LAYOUTS_KEPT: usize = 64;

fn remember_layout(root: B256, layout: Vec<(B256, u32)>) {
    let mut kept = LAYOUTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if kept.iter().any(|(known, _)| *known == root) {
        return;
    }
    kept.push_back((root, layout));
    while kept.len() > LAYOUTS_KEPT {
        kept.pop_front();
    }
}

/// The frame layout of a block this node built, by its transactions root.
pub fn layout_by_root(root: &B256) -> Option<Vec<(B256, u32)>> {
    LAYOUTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().find(|(known, _)| known == root).map(|(_, layout)| layout.clone())
}

/// The transactions root of a frame build's body, sealed by the rule: the
/// body must be a prefix of the plan (whole frames, the last one possibly
/// cut); its layout is remembered under the root for the description.
pub fn sealed_root<T: alloy_eips::eip2718::Encodable2718 + Sync>(
    plan: &FramePlan,
    body_hashes: &[B256],
    transactions: &[T],
) -> Result<B256, String> {
    let layout = plan.layout_for(body_hashes).ok_or_else(|| {
        format!(
            "the body of {} transactions is not a prefix of the frame plan ({} frames, {} transactions): \
             not frame-aligned, and a frame chain refuses it",
            body_hashes.len(),
            plan.frames.len(),
            plan.hashes.len()
        )
    })?;
    let counts: Vec<usize> = layout.iter().map(|(_, count)| *count).collect();
    // An empty body keeps the empty MPT root (see `root_of_hashes`).
    let root = if transactions.is_empty() {
        alloy_consensus::EMPTY_ROOT_HASH
    } else {
        crate::assembler::transactions_root_by_rule(true, Some(&counts), transactions)
    };
    let described: Vec<(B256, u32)> =
        layout.iter().map(|(id, count)| (*id, u32::try_from(*count).unwrap_or(u32::MAX))).collect();
    if body_hashes.len() >= 1000 {
        tracing::info!(
            target: "payload_builder",
            frames = described.len(),
            skipped = plan.skipped,
            txs = body_hashes.len(),
            last = described.last().map_or(0, |(_, count)| *count),
            "frame build sealed"
        );
    }
    remember_layout(root, described);
    Ok(root)
}

/// The transactions root a frame chain gives a body that arrived whole:
/// the frame tree over the layout this node's frame index finds for it.
/// `Err` when the body is not a run of frames this node indexed -- under
/// the flag such a body is not valid (or not checkable here).
pub fn body_root(hashes: &[B256]) -> Result<B256, String> {
    if hashes.is_empty() {
        return Ok(alloy_consensus::EMPTY_ROOT_HASH);
    }
    let queue = n42_tx_queue::global::<crate::N42PooledTransaction>()
        .ok_or_else(|| "frame blocks need the transaction queue (N42_TX_QUEUE=1)".to_owned())?;
    let layout = queue
        .frame_layout_of(hashes)
        .ok_or_else(|| format!("a body of {} transactions that is not a run of indexed frames", hashes.len()))?;
    let counts: Vec<usize> = layout.iter().map(|(_, count)| *count).collect();
    root_of_hashes(hashes, &counts).ok_or_else(|| "the frame layout does not cover the body".to_owned())
}

/// The frame-tree root over a body's hashes laid out as `counts`; an empty
/// body keeps the empty MPT root every empty block has, whichever path
/// built it. `None` when the layout does not cover the body.
pub fn root_of_hashes(hashes: &[B256], counts: &[usize]) -> Option<B256> {
    if hashes.is_empty() {
        return counts.is_empty().then_some(alloy_consensus::EMPTY_ROOT_HASH);
    }
    n42_tx_types::frame_tree_root_of(hashes, counts)
}

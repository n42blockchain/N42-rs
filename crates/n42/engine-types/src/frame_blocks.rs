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
//! matched back to the frames this node indexed.
//!
//! Aligned or not is a property of each block, not of the chain (loop266:
//! the funding transactions arrive by RPC and belong to no frame, and a
//! chain that refused every other body never got past them). A body that is
//! a run of whole indexed frames, the last possibly cut to a prefix, carries
//! the frame-tree root and travels as a frame description (version 2); any
//! other body carries the ordinary MPT root and travels by hashes (version
//! 1). The seal derives the layout from the body it actually sealed
//! ([`seal_root`]); validation accepts a header whose root is the frame tree
//! of a layout it can check against the body's hashes -- the one a version-2
//! description names, one this node remembered for that root, or the one its
//! own frame index finds -- or else the MPT root ([`root_for_body`]).
//!
//! Off (the default), nothing here is consulted and every root is the MPT
//! root, byte for byte as before.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
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
    if plan.frames.is_empty() {
        // No frame a build could take whole (the funding block, a thin pool,
        // transactions that came by RPC): the ordinary walk, and the seal
        // gives the body the MPT root unless it turns out aligned anyway.
        drop(best);
        FRAME_BUILDS_WALKED.fetch_add(1, Ordering::Relaxed);
        return queue.best_for_build(parent);
    }
    PLAN.with(|slot| *slot.borrow_mut() = Some(plan));
    best
}

/// Builds under the flag that found no usable frame and walked the queue.
pub static FRAME_BUILDS_WALKED: AtomicU64 = AtomicU64::new(0);
/// Non-empty blocks this node sealed with the frame-tree root.
pub static SEALED_ALIGNED: AtomicU64 = AtomicU64::new(0);
/// Non-empty blocks this node sealed under the flag with the MPT root (a
/// body that is not a run of indexed frames).
pub static SEALED_MPT: AtomicU64 = AtomicU64::new(0);
/// Whole bodies whose frame-tree root was checked from a layout.
pub static CHECKED_FRAME_ROOT: AtomicU64 = AtomicU64::new(0);
/// Whole bodies under the flag checked against the MPT root.
pub static CHECKED_MPT_ROOT: AtomicU64 = AtomicU64::new(0);

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

/// The transactions roots of blocks whose frame layout this node verified,
/// by block hash: what the engine's conversion, which has the payload but
/// not the header's root, looks up.
static BLOCK_ROOTS: Mutex<VecDeque<(B256, B256)>> = Mutex::new(VecDeque::new());

/// Remembers that block `block`'s root `root` was checked as the frame tree
/// of `layout` (a version-2 description this node verified), so a later
/// whole-body check of the same block -- the engine's conversion, the body
/// check -- can verify it again from the body's hashes without this node's
/// frame index.
pub fn remember_verified(block: B256, root: B256, layout: &[(B256, u32)]) {
    remember_layout(root, layout.to_vec());
    let mut kept = BLOCK_ROOTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if kept.iter().any(|(known, _)| *known == block) {
        return;
    }
    kept.push_back((block, root));
    while kept.len() > LAYOUTS_KEPT {
        kept.pop_front();
    }
}

/// The transactions root [`remember_verified`] recorded for `block`.
pub fn root_of_block(block: &B256) -> Option<B256> {
    BLOCK_ROOTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(known, _)| known == block)
        .map(|(_, root)| *root)
}

/// What [`seal_root_timed`] did, for the build's phase line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealRoot {
    /// The root the seal gives the body.
    pub root: B256,
    /// Microseconds spent finding the layout (the plan's prefix check, or
    /// the frame index's per-frame lookups).
    pub layout_us: u64,
    /// Microseconds spent on the root over the layout (or the MPT root).
    pub root_us: u64,
    /// Frames whose leaf was the id the ingest computed.
    pub indexed: usize,
    /// Frames whose leaf was hashed from the body (the cut last frame).
    pub hashed: usize,
}

/// A frame tree root and how its leaves were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTreeRoot {
    /// The root.
    pub root: B256,
    /// Leaves that were the frame's id as this node's index holds it -- the
    /// root the ingest computed once over the frame's hashes.
    pub indexed: usize,
    /// Leaves computed here over the body's hashes (a frame this node does
    /// not hold whole, a supplied one, the cut last frame).
    pub hashed: usize,
}

/// The frame tree over a body of `total` transactions laid out as `counts`
/// (each frame's length, in body order), where `known[k]` is frame `k`'s
/// root when this node already has it -- the frame's id from its index,
/// computed at ingest over exactly those hashes -- and `hash_at(i)` is the
/// body's `i`-th transaction hash. Only the frames without a known root are
/// hashed, on the worker pool. An empty body is the empty MPT root. `None`
/// when the layout does not cover the body.
///
/// A known root is only sound when the caller has established that the
/// frame's positions in the body hold exactly the indexed frame's
/// transactions (the queue's `take_frames` fetches them by hash; the index's
/// `layout_of` / `frames_held` compare the hashes).
pub fn frame_tree_root_known(
    counts: &[usize],
    known: &[Option<B256>],
    total: usize,
    hash_at: impl Fn(usize) -> B256 + Sync,
) -> Option<FrameTreeRoot> {
    use rayon::prelude::*;
    if total == 0 {
        return counts
            .is_empty()
            .then_some(FrameTreeRoot { root: alloy_consensus::EMPTY_ROOT_HASH, indexed: 0, hashed: 0 });
    }
    if counts.len() != known.len() || counts.contains(&0) || counts.iter().sum::<usize>() != total {
        return None;
    }
    let mut starts = Vec::with_capacity(counts.len());
    let mut at = 0usize;
    for count in counts {
        starts.push(at);
        at += count;
    }
    let indexed = known.iter().filter(|leaf| leaf.is_some()).count();
    let hashed = counts.len() - indexed;
    let leaf = |k: usize| {
        known[k].unwrap_or_else(|| {
            let hashes: Vec<B256> = (starts[k]..starts[k] + counts[k]).map(&hash_at).collect();
            n42_tx_types::frame_root(&hashes)
        })
    };
    let leaves: Vec<B256> = if hashed <= 1 {
        (0..counts.len()).map(leaf).collect()
    } else {
        (0..counts.len()).into_par_iter().map(leaf).collect()
    };
    Some(FrameTreeRoot { root: n42_tx_types::frame_tree_root(&leaves), indexed, hashed })
}

/// The known leaves of a layout the frame index found for a body
/// (`frame_layout_of`, which compared every frame's hashes with the body's):
/// every frame but the last is whole, so its id is its root; the last may be
/// a prefix and is hashed (at most one frame's worth).
fn known_from_index_layout(layout: &[(B256, usize)]) -> Vec<Option<B256>> {
    let last = layout.len().saturating_sub(1);
    layout.iter().enumerate().map(|(k, (id, _))| (k != last).then_some(*id)).collect()
}

/// The transactions root the seal gives a body under the flag, derived from
/// the body it actually sealed: the frame tree when the body is a run of
/// whole frames (the last possibly cut) -- by the build's plan, or else by
/// this node's frame index -- with the layout remembered under the root for
/// the description; `mpt` (the ordinary root) for any other body. A frame
/// build whose execution skipped or reordered a planned transaction is not
/// refused: its body is sealed with the MPT root and described by hashes.
pub fn seal_root(plan: Option<&FramePlan>, body_hashes: &[B256], mpt: impl FnOnce() -> B256) -> B256 {
    seal_root_timed(plan, body_hashes, mpt).root
}

/// [`seal_root`], with where its time went. The frame tree's leaves are the
/// plan's frame ids (computed at ingest); only the frame the body ends in
/// part-way through is hashed. The index's layout is consulted only when
/// the body is not a prefix of the plan, and it costs one lookup per frame.
pub fn seal_root_timed(plan: Option<&FramePlan>, body_hashes: &[B256], mpt: impl FnOnce() -> B256) -> SealRoot {
    // An empty body keeps the empty MPT root (see `root_of_hashes`).
    if body_hashes.is_empty() {
        let at = std::time::Instant::now();
        let root = mpt();
        return SealRoot { root, root_us: at.elapsed().as_micros() as u64, ..SealRoot::default() };
    }
    let layout_at = std::time::Instant::now();
    let by_plan = plan.and_then(|plan| {
        plan.layout_for(body_hashes).map(|layout| {
            // `layout_for` walks the plan's frames in order, so entry k is
            // frame k of the plan: whole when it holds all of that frame.
            let known: Vec<Option<B256>> = layout
                .iter()
                .zip(&plan.frames)
                .map(|((id, take), frame)| (*take == frame.len).then_some(*id))
                .collect();
            (layout, known)
        })
    });
    let layout = by_plan.or_else(|| {
        n42_tx_queue::global::<crate::N42PooledTransaction>()
            .and_then(|queue| queue.frame_layout_of(body_hashes))
            .map(|layout| {
                let known = known_from_index_layout(&layout);
                (layout, known)
            })
    });
    let layout_us = layout_at.elapsed().as_micros() as u64;
    let root_at = std::time::Instant::now();
    let tree = layout.as_ref().and_then(|(layout, known)| {
        let counts: Vec<usize> = layout.iter().map(|(_, count)| *count).collect();
        frame_tree_root_known(&counts, known, body_hashes.len(), |i| body_hashes[i])
    });
    let (Some((layout, _)), Some(tree)) = (layout, tree) else {
        SEALED_MPT.fetch_add(1, Ordering::Relaxed);
        if let Some(plan) = plan {
            tracing::info!(
                target: "payload_builder",
                txs = body_hashes.len(),
                planned = plan.hashes.len(),
                frames = plan.frames.len(),
                "frame build's body is not a run of frames; sealed with the MPT root"
            );
        }
        let root = mpt();
        return SealRoot { root, layout_us, root_us: root_at.elapsed().as_micros() as u64, ..SealRoot::default() };
    };
    let root_us = root_at.elapsed().as_micros() as u64;
    SEALED_ALIGNED.fetch_add(1, Ordering::Relaxed);
    let described: Vec<(B256, u32)> =
        layout.iter().map(|(id, count)| (*id, u32::try_from(*count).unwrap_or(u32::MAX))).collect();
    if body_hashes.len() >= 1000 {
        tracing::info!(
            target: "payload_builder",
            frames = described.len(),
            skipped = plan.map_or(0, |plan| plan.skipped),
            txs = body_hashes.len(),
            last = described.last().map_or(0, |(_, count)| *count),
            indexed = tree.indexed,
            hashed = tree.hashed,
            layout_us,
            root_us,
            "frame build sealed"
        );
    }
    remember_layout(tree.root, described);
    SealRoot { root: tree.root, layout_us, root_us, indexed: tree.indexed, hashed: tree.hashed }
}

/// What [`root_for_body_counted`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyRoot {
    /// The root accepted (or the MPT root, for the caller's mismatch).
    pub root: B256,
    /// Whether it is a frame-tree root.
    pub frame: bool,
    /// Leaves read from the frame index.
    pub indexed: usize,
    /// Leaves hashed from the body.
    pub hashed: usize,
}

/// The transactions root a frame chain accepts for a body that arrived
/// whole, and whether it is a frame-tree root.
///
/// With `claimed` (the header's root): a layout this node remembered for
/// that root (it verified the block's version-2 description, or built it)
/// is checked against the body's hashes first; then the layout this node's
/// frame index finds for the body; then the MPT root (`mpt`). The first
/// that equals `claimed` is returned, else the MPT root, for the caller's
/// mismatch. Without `claimed`: the frame tree when the index finds a
/// layout, the MPT root otherwise (the caller checks the result against
/// the block hash and falls back to the MPT root on a mismatch).
///
/// Every frame-tree root accepted here is computed from the body's own
/// hashes under a layout that covers them exactly -- a frame's leaf is its
/// indexed id only where the index holds that frame with exactly the body's
/// hashes at its positions, so the id is the root over them -- and so binds
/// the body as the MPT root does; which of the two a block carries is the
/// sealer's choice by its own index, and a follower whose index differs
/// still agrees on the block.
pub fn root_for_body(claimed: Option<B256>, hashes: &[B256], mpt: impl FnOnce() -> B256) -> (B256, bool) {
    let found = root_for_body_counted(claimed, hashes, mpt);
    (found.root, found.frame)
}

/// [`root_for_body`], with how many leaves were read and how many hashed.
pub fn root_for_body_counted(claimed: Option<B256>, hashes: &[B256], mpt: impl FnOnce() -> B256) -> BodyRoot {
    if hashes.is_empty() {
        return BodyRoot { root: alloy_consensus::EMPTY_ROOT_HASH, frame: false, indexed: 0, hashed: 0 };
    }
    let queue = n42_tx_queue::global::<crate::N42PooledTransaction>();
    if let Some(claimed) = claimed
        && let Some(layout) = layout_by_root(&claimed)
    {
        let layout: Vec<(B256, usize)> = layout.iter().map(|(id, count)| (*id, *count as usize)).collect();
        let known = queue.as_ref().map_or_else(|| vec![None; layout.len()], |queue| queue.frames_held(&layout, hashes));
        let counts: Vec<usize> = layout.iter().map(|(_, count)| *count).collect();
        if let Some(tree) = frame_tree_root_known(&counts, &known, hashes.len(), |i| hashes[i])
            && tree.root == claimed
        {
            CHECKED_FRAME_ROOT.fetch_add(1, Ordering::Relaxed);
            return BodyRoot { root: claimed, frame: true, indexed: tree.indexed, hashed: tree.hashed };
        }
    }
    let indexed = queue.and_then(|queue| queue.frame_layout_of(hashes)).and_then(|layout| {
        let counts: Vec<usize> = layout.iter().map(|(_, count)| *count).collect();
        frame_tree_root_known(&counts, &known_from_index_layout(&layout), hashes.len(), |i| hashes[i])
    });
    if let Some(tree) = indexed
        && claimed.is_none_or(|claimed| claimed == tree.root)
    {
        CHECKED_FRAME_ROOT.fetch_add(1, Ordering::Relaxed);
        return BodyRoot { root: tree.root, frame: true, indexed: tree.indexed, hashed: tree.hashed };
    }
    CHECKED_MPT_ROOT.fetch_add(1, Ordering::Relaxed);
    BodyRoot { root: mpt(), frame: false, indexed: 0, hashed: 0 }
}

/// The frame-tree root over a body's hashes laid out as `counts`, every
/// frame hashed (on the worker pool); an empty body keeps the empty MPT
/// root every empty block has, whichever path built it. `None` when the
/// layout does not cover the body.
pub fn root_of_hashes(hashes: &[B256], counts: &[usize]) -> Option<B256> {
    frame_tree_root_known(counts, &vec![None; counts.len()], hashes.len(), |i| hashes[i]).map(|tree| tree.root)
}

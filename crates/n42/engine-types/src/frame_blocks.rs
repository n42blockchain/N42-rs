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
    let mut times = SelectTimes::default();
    let best = if active() {
        let (best, plan, took) = queue.frames_for_build_timed(parent, gas_limit);
        times.select_us = took.lock_us + took.begin_us;
        times.walk_us = took.plan_us;
        times.check_us = took.check_us;
        times.by_ref = took.by_ref;
        times.slow = took.slow;
        if plan.frames.is_empty() {
            // No frame a build could take whole (the funding block, a thin
            // pool, transactions that came by RPC): the ordinary walk, and
            // the seal gives the body the MPT root unless it turns out
            // aligned anyway.
            drop(best);
            FRAME_BUILDS_WALKED.fetch_add(1, Ordering::Relaxed);
            let at = std::time::Instant::now();
            let best = queue.best_for_build(parent);
            times.pull_us = at.elapsed().as_micros() as u64;
            best
        } else {
            PLAN.with(|slot| *slot.borrow_mut() = Some(plan));
            best
        }
    } else {
        let at = std::time::Instant::now();
        let best = queue.best_for_build(parent);
        times.pull_us = at.elapsed().as_micros() as u64;
        best
    };
    SELECT_TIMES.with(|slot| slot.set(times));
    best
}

/// Where the last [`select`] on this thread spent its time, in
/// microseconds: the build's phase line splits `start_best_ms` with it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectTimes {
    /// The queue's frame take opening: the lanes' lock and the build's
    /// start under it (inbox drain, give-back, parked lanes readmitted).
    pub select_us: u64,
    /// The frame plan: the frames checked and taken
    /// ([`n42_tx_queue::FrameSelectTimes::plan_us`]).
    pub walk_us: u64,
    /// Of `walk_us`, the parallel check of the frames the gas reaches.
    pub check_us: u64,
    /// The ordinary walk's opening when no frame was usable, or the mode
    /// is off (`best_for_build`).
    pub pull_us: u64,
    /// Frames decided and taken by reference.
    pub by_ref: usize,
    /// Frames that needed the per-transaction check.
    pub slow: usize,
}

std::thread_local! {
    static SELECT_TIMES: std::cell::Cell<SelectTimes> = const {
        std::cell::Cell::new(SelectTimes { select_us: 0, walk_us: 0, check_us: 0, pull_us: 0, by_ref: 0, slow: 0 })
    };
}

/// The times [`select`] left on this thread, taken (reset to zero).
pub fn take_select_times() -> SelectTimes {
    SELECT_TIMES.with(|slot| slot.replace(SelectTimes::default()))
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

/// Remembers the transactions root and frame layout a block's description
/// *claims*, before anything has checked them: the description of a block
/// whose transactions this node does not hold is refused (the vote road asks
/// for the whole body instead), and the whole body -- a payload, which does
/// not carry the header's root -- then had no layout to be rooted by. It fell
/// back to the MPT root and to "no gov5 header variant hashes to the
/// payload's block hash" (loop278 IDX, blocks 1033 and 1038: 13,000 of
/// 14,000 transactions not held after a view change, every node refusing the
/// block). Safe unchecked: [`root_for_body`] uses a claim only when the frame
/// tree over the body's own hashes reproduces it, and the block hash is
/// confirmed after that; a verified record made first is kept.
pub fn remember_claimed(block: B256, root: B256, layout: &[(B256, u32)]) {
    if layout.is_empty() {
        return;
    }
    remember_verified(block, root, layout);
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
                planned = plan.tx_count(),
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

#[cfg(test)]
mod claimed_root_tests {
    use super::*;

    /// A block whose description was refused here (its frames not held) is
    /// fetched whole; the payload's conversion roots it by the description's
    /// claim, checked against the body's own hashes (loop278: without it the
    /// MPT root, and "no gov5 header variant hashes to the payload's block
    /// hash" on every follower).
    #[test]
    fn a_refused_description_roots_the_whole_body_by_its_claim() {
        let hashes: Vec<B256> = (0..7u8).map(|i| B256::repeat_byte(0x40 + i)).collect();
        let counts = [3usize, 2, 2];
        let root = root_of_hashes(&hashes, &counts).expect("the layout covers the body");
        let layout: Vec<(B256, u32)> =
            counts.iter().zip(0u8..).map(|(count, k)| (B256::repeat_byte(0xa0 + k), *count as u32)).collect();
        let mpt = B256::repeat_byte(0x11);
        let block = B256::repeat_byte(0x77);
        assert_eq!(root_for_body(root_of_block(&block), &hashes, || mpt), (mpt, false));
        remember_claimed(block, root, &layout);
        assert_eq!(root_for_body(root_of_block(&block), &hashes, || mpt), (root, true));
        // A claim the body does not reproduce is not used.
        let lying = B256::repeat_byte(0x78);
        remember_claimed(lying, B256::repeat_byte(0x99), &layout);
        assert_eq!(root_for_body(root_of_block(&lying), &hashes, || mpt), (mpt, false));
        // No layout, no claim.
        let bare = B256::repeat_byte(0x79);
        remember_claimed(bare, root, &[]);
        assert_eq!(root_of_block(&bare), None);
    }
}

#[cfg(test)]
mod frame_root_tests {
    use super::*;
    use alloy_consensus::EMPTY_ROOT_HASH;
    use n42_tx_queue::PlannedFrame;

    fn hashes(tag: u8, n: usize) -> Vec<B256> {
        (0..n).map(|i| B256::repeat_byte(tag.wrapping_add(i as u8))).collect()
    }

    #[test]
    fn the_mode_is_off_unless_forced_and_the_override_nests() {
        assert!(!active());
        with_active(true, || {
            assert!(active());
            with_active(false, || assert!(!active()));
            assert!(active(), "the outer override is restored");
        });
        assert!(!active());
    }

    #[test]
    fn a_layout_must_cover_the_body_exactly() {
        let h = hashes(0x10, 6);
        let by = |counts: &[usize], known: &[Option<B256>], total: usize| frame_tree_root_known(counts, known, total, |i| h[i]);
        // An empty body is the empty trie, and only with an empty layout.
        let empty = by(&[], &[], 0).expect("empty");
        assert_eq!((empty.root, empty.indexed, empty.hashed), (EMPTY_ROOT_HASH, 0, 0));
        assert!(by(&[3], &[None], 0).is_none());
        // Known leaves must be one per frame, frames non-empty, the counts must sum to the total.
        assert!(by(&[3, 3], &[None], 6).is_none(), "known and counts differ in length");
        assert!(by(&[3, 0, 3], &[None, None, None], 6).is_none(), "an empty frame");
        assert!(by(&[3, 2], &[None, None], 6).is_none(), "counts short of the body");
        assert!(by(&[3, 4], &[None, None], 6).is_none(), "counts past the body");
        assert!(by(&[6], &[None], 6).is_some());
    }

    #[test]
    fn a_known_leaf_is_used_as_is_and_hashing_counts_the_rest() {
        let h = hashes(0x20, 7);
        let counts = [3usize, 2, 2];
        let id0 = n42_tx_types::frame_root(&h[0..3]);
        let all_hashed = frame_tree_root_known(&counts, &[None, None, None], 7, |i| h[i]).expect("covers");
        assert_eq!((all_hashed.indexed, all_hashed.hashed), (0, 3));
        // A leaf that is the frame's true id changes nothing but the counters.
        let one_known = frame_tree_root_known(&counts, &[Some(id0), None, None], 7, |i| h[i]).expect("covers");
        assert_eq!((one_known.indexed, one_known.hashed), (1, 2));
        assert_eq!(one_known.root, all_hashed.root);
        // A known leaf is trusted without looking at the body: a different id gives a different root.
        let lie = frame_tree_root_known(&counts, &[Some(B256::repeat_byte(1)), None, None], 7, |i| h[i]).expect("covers");
        assert_ne!(lie.root, all_hashed.root);
        // The one-hashed (sequential) and many-hashed (parallel) paths agree on the same root.
        let sequential = frame_tree_root_known(&counts, &[Some(id0), Some(n42_tx_types::frame_root(&h[3..5])), None], 7, |i| h[i]).expect("covers");
        assert_eq!((sequential.indexed, sequential.hashed), (2, 1));
        assert_eq!(sequential.root, all_hashed.root);
        assert_eq!(root_of_hashes(&h, &counts), Some(all_hashed.root));
        assert_eq!(root_of_hashes(&h, &[3, 3]), None);
        assert_eq!(root_of_hashes(&[], &[]), Some(EMPTY_ROOT_HASH));
    }

    fn plan_of(tag: u8) -> (FramePlan, Vec<B256>) {
        let h = hashes(tag, 6);
        let (f0, f1) = (&h[0..3], &h[3..6]);
        let mut plan = FramePlan::default();
        plan.frames.push(PlannedFrame { id: n42_tx_types::frame_root(f0), len: 3, taken: 3 });
        plan.frames.push(PlannedFrame { id: n42_tx_types::frame_root(f1), len: 3, taken: 2 });
        plan.push_hashes(Arc::from(f0), 3);
        plan.push_hashes(Arc::from(f1), 2);
        (plan, h)
    }

    use std::sync::Arc;

    #[test]
    fn an_empty_body_keeps_the_mpt_root_without_a_layout() {
        let mpt = B256::repeat_byte(0xAB);
        let sealed = seal_root_timed(None, &[], || mpt);
        assert_eq!((sealed.root, sealed.indexed, sealed.hashed), (mpt, 0, 0));
        assert_eq!(seal_root(None, &[], || mpt), mpt);
    }

    #[test]
    fn a_body_that_is_a_prefix_of_the_plan_is_sealed_with_the_frame_tree() {
        let (plan, h) = plan_of(0x30);
        let mpt = B256::repeat_byte(0xAC);
        let aligned_before = SEALED_ALIGNED.load(Ordering::Relaxed);
        // The whole plan: frame 0 whole (its id is the leaf), frame 1 cut to 2 and hashed.
        let body = &h[0..5];
        let sealed = seal_root_timed(Some(&plan), body, || mpt);
        let expected = n42_tx_types::frame_tree_root(&[n42_tx_types::frame_root(&h[0..3]), n42_tx_types::frame_root(&h[3..5])]);
        assert_eq!(sealed.root, expected);
        assert_eq!((sealed.indexed, sealed.hashed), (1, 1));
        assert!(SEALED_ALIGNED.load(Ordering::Relaxed) > aligned_before);
        // The layout is remembered under the root for the block's description.
        assert_eq!(
            layout_by_root(&expected),
            Some(vec![(plan.frames[0].id, 3), (plan.frames[1].id, 2)])
        );
        // A body that stopped after frame 0 is that frame alone, all known.
        let short = seal_root_timed(Some(&plan), &h[0..3], || mpt);
        assert_eq!((short.indexed, short.hashed), (1, 0));
        assert_eq!(short.root, n42_tx_types::frame_tree_root(&[plan.frames[0].id]));
        // A body that ends inside frame 0 cuts it, so its leaf is hashed.
        let cut = seal_root_timed(Some(&plan), &h[0..2], || mpt);
        assert_eq!((cut.indexed, cut.hashed), (0, 1));
        assert_eq!(cut.root, n42_tx_types::frame_tree_root(&[n42_tx_types::frame_root(&h[0..2])]));
    }

    #[test]
    fn a_body_that_is_not_a_run_of_the_plans_frames_is_sealed_with_the_mpt_root() {
        let (plan, h) = plan_of(0x40);
        let mpt = B256::repeat_byte(0xAD);
        let before = SEALED_MPT.load(Ordering::Relaxed);
        // Reordered: not a prefix of the plan.
        let mut body = h[0..5].to_vec();
        body.swap(0, 1);
        let sealed = seal_root_timed(Some(&plan), &body, || mpt);
        assert_eq!((sealed.root, sealed.indexed, sealed.hashed), (mpt, 0, 0));
        // Longer than the plan.
        assert_eq!(seal_root(Some(&plan), &h, || mpt), mpt);
        // No plan and no index that knows these hashes.
        assert_eq!(seal_root(None, &hashes(0x44, 4), || mpt), mpt);
        assert!(SEALED_MPT.load(Ordering::Relaxed) >= before + 3);
    }

    #[test]
    fn a_remembered_layout_roots_a_whole_body_and_a_wrong_claim_falls_back_to_mpt() {
        let h = hashes(0x50, 5);
        let counts = [3usize, 2];
        let root = root_of_hashes(&h, &counts).expect("covers");
        let layout = [(B256::repeat_byte(0xA1), 3u32), (B256::repeat_byte(0xA2), 2u32)];
        let mpt = B256::repeat_byte(0xAE);
        remember_verified(B256::repeat_byte(0x51), root, &layout);
        assert_eq!(root_of_block(&B256::repeat_byte(0x51)), Some(root));
        assert_eq!(layout_by_root(&root), Some(layout.to_vec()));
        // The claimed root's layout reproduces it from the body's own hashes.
        let found = root_for_body_counted(Some(root), &h, || mpt);
        assert!(found.frame);
        assert_eq!(found.root, root);
        assert_eq!(found.indexed + found.hashed, 2);
        // Another body under the same claim does not reproduce it.
        let other = hashes(0x60, 5);
        let refused = root_for_body_counted(Some(root), &other, || mpt);
        assert_eq!((refused.root, refused.frame), (mpt, false));
        // An empty body is the empty trie whatever is claimed.
        assert_eq!(root_for_body(Some(root), &[], || mpt), (EMPTY_ROOT_HASH, false));
        // A claim nothing remembers, with an index that knows nothing of the body.
        assert_eq!(root_for_body(Some(B256::repeat_byte(0xFE)), &h, || mpt), (mpt, false));
        assert_eq!(root_for_body(None, &h, || mpt), (mpt, false));
    }

    #[test]
    fn a_layout_is_remembered_once_per_root_and_a_claim_with_no_layout_is_ignored() {
        let root = B256::repeat_byte(0x71);
        remember_verified(B256::repeat_byte(0x72), root, &[(B256::repeat_byte(1), 2)]);
        // A second filing under the same root keeps the first layout.
        remember_verified(B256::repeat_byte(0x73), root, &[(B256::repeat_byte(2), 9)]);
        assert_eq!(layout_by_root(&root), Some(vec![(B256::repeat_byte(1), 2)]));
        assert_eq!(root_of_block(&B256::repeat_byte(0x73)), Some(root), "the block's root is still recorded");
        // The same block filed twice keeps its first root.
        remember_verified(B256::repeat_byte(0x72), B256::repeat_byte(0x74), &[(B256::repeat_byte(3), 1)]);
        assert_eq!(root_of_block(&B256::repeat_byte(0x72)), Some(root));
        assert_eq!(layout_by_root(&B256::repeat_byte(0x75)), None);
    }
}

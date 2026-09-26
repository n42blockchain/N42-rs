// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The queue's frame index (`docs/BREAKTHROUGH_DESIGN.md` step 1, phase A).
//!
//! A frame is the ingest's unit -- 500 transactions at the bench tier, the
//! same bytes at every node -- named by its root (`n42_tx_types::frame_root`
//! over its transactions' hashes, computed once at admission). The index
//! sits beside the lanes and never changes what they hold: it records, per
//! frame the ingest admitted whole, the transactions' hashes in frame order
//! and where each one lives in the lanes (sender, nonce), so a caller can
//! ask which frames a build could take whole right now and fetch a frame's
//! transactions by reference.
//!
//! Memory: 32 bytes a transaction for the hashes (16 KB for a 500-frame)
//! plus 40 bytes per sender run (a run is a stretch of the frame with one
//! sender at consecutive nonces; the flood's frames hold a few), plus ~80
//! bytes of map and order entry: ~16-17 KB a frame, ~33 MB for the ~2,000
//! frames of a 1M-deep queue. Bounded by [`MAX_FRAMES`].
//!
//! A frame leaves the index when the chain mines any of its transactions
//! (the canonical prune, [`FrameIndex::sweep`]): it can never be referenced
//! whole again. What a build took, or an own block not yet committed, only
//! makes the frame not whole-usable for the moment.

use std::collections::VecDeque;

use alloy_primitives::{map::{AddressHashMap, B256HashMap}, Address, B256};
use reth_transaction_pool::PoolTransaction;

use crate::Lane;

/// The most frames the index holds; the oldest leave first past it. 16,384
/// frames of 500 is 8.2M transactions, far past any queue's gate, so the
/// bound only bites when nothing prunes (a node whose chain has stopped).
pub const MAX_FRAMES: usize = 16_384;

/// A frame the ingest admitted whole, for [`crate::TxQueue::note_frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFrame {
    /// The frame's root over `hashes`, which is its id.
    pub id: B256,
    /// The transactions' hashes, in frame order.
    pub hashes: Vec<B256>,
    /// Each transaction's (sender, nonce), in the same order.
    pub members: Vec<(Address, u64)>,
    /// The sum of the transactions' gas limits.
    pub gas: u64,
}

/// What [`crate::TxQueue::frames_in_arrival_order`] reports of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRef {
    /// The frame's id (its root).
    pub id: B256,
    /// How many transactions it holds.
    pub count: usize,
    /// The sum of their gas limits.
    pub gas: u64,
    /// Whether every one of them is in the lanes right now, unparked, with
    /// every lower nonce its sender has in the lanes present and contiguous
    /// from the lane's head -- i.e. a build could take the frame whole.
    ///
    /// The queue does not know an account's nonce, so "the lane's head" is
    /// the lowest nonce the lane holds; a head the chain is still waiting
    /// below is the builder's to find, as for any transaction.
    pub whole_usable: bool,
}

/// One frame of a build's frame plan ([`crate::TxQueue::frames_for_build`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedFrame {
    /// The frame's id (its root over all of its transactions).
    pub id: B256,
    /// How many transactions the frame holds.
    pub len: usize,
    /// How many of them the build took, from the frame's start: `len`, or
    /// fewer for the plan's last frame when the block's gas ran out in it.
    pub taken: usize,
}

/// What a frame build took, in the order its transactions are handed to
/// the builder: whole frames in arrival order, the last one possibly cut
/// to a prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FramePlan {
    /// The frames, in body order.
    pub frames: Vec<PlannedFrame>,
    /// The transactions' hashes, in body order: the frames' taken parts
    /// end to end.
    pub hashes: Vec<B256>,
    /// Indexed frames the plan passed over: not whole-usable, or not at
    /// their senders' lane heads once the frames before them were taken.
    pub skipped: usize,
}

impl FramePlan {
    /// The layout of a body built from this plan, as (frame id, length) in
    /// body order: `Some` when the body's hashes are a prefix of the plan's
    /// (a build that stopped early, or took everything), with the frame the
    /// body ends in cut to what it holds of it; `None` when the body is not
    /// a prefix of the plan -- it is not frame-aligned.
    pub fn layout_for(&self, body: &[B256]) -> Option<Vec<(B256, usize)>> {
        if body.len() > self.hashes.len() || self.hashes[..body.len()] != *body {
            return None;
        }
        let mut layout = Vec::new();
        let mut left = body.len();
        for frame in &self.frames {
            if left == 0 {
                break;
            }
            let take = frame.taken.min(left);
            layout.push((frame.id, take));
            left -= take;
        }
        (left == 0).then_some(layout)
    }
}

/// A stretch of a frame with one sender at consecutive nonces.
#[derive(Debug, Clone, Copy)]
struct SenderRun {
    sender: Address,
    first_nonce: u64,
    /// The run's first position in the frame.
    start: u32,
    len: u32,
}

#[derive(Debug)]
struct FrameEntry {
    hashes: Vec<B256>,
    runs: Vec<SenderRun>,
    gas: u64,
}

impl FrameEntry {
    fn from_new(frame: NewFrame) -> Option<(B256, Self)> {
        if frame.hashes.len() != frame.members.len() || frame.hashes.is_empty() {
            return None;
        }
        let len = u32::try_from(frame.hashes.len()).ok()?;
        let mut runs: Vec<SenderRun> = Vec::new();
        for (at, (sender, nonce)) in frame.members.iter().copied().enumerate() {
            let at = u32::try_from(at).ok()?;
            match runs.last_mut() {
                Some(run)
                    if run.sender == sender
                        && run.first_nonce.checked_add(u64::from(run.len)) == Some(nonce) =>
                {
                    run.len += 1;
                }
                _ => runs.push(SenderRun { sender, first_nonce: nonce, start: at, len: 1 }),
            }
        }
        debug_assert_eq!(runs.iter().map(|run| run.len).sum::<u32>(), len);
        Some((frame.id, Self { hashes: frame.hashes, runs, gas: frame.gas }))
    }

    /// Every position's (sender, nonce), in frame order.
    fn members(&self) -> impl Iterator<Item = (usize, Address, u64)> + '_ {
        self.runs.iter().flat_map(|run| {
            (0..run.len).map(move |i| {
                (run.start as usize + i as usize, run.sender, run.first_nonce + u64::from(i))
            })
        })
    }
}

/// The index itself: a plain map plus the arrival order.
#[derive(Debug, Default)]
pub(crate) struct FrameIndex {
    frames: B256HashMap<FrameEntry>,
    /// Each indexed frame's id by its first transaction's hash: how a body
    /// that arrived whole is matched back to the frames it was built from
    /// ([`FrameIndex::layout_of`]).
    by_first: B256HashMap<B256>,
    /// Ids in arrival order; an id no longer in `frames` is skipped, and the
    /// order is compacted when the skipped ones outnumber the live ones.
    order: VecDeque<B256>,
    /// Frames `note_frame` refused because their id was already indexed or
    /// their record was malformed; since the process started.
    pub(crate) refused: u64,
}

impl FrameIndex {
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(crate) fn insert(&mut self, frame: NewFrame) {
        if self.frames.contains_key(&frame.id) {
            self.refused += 1;
            return;
        }
        let Some((id, entry)) = FrameEntry::from_new(frame) else {
            self.refused += 1;
            return;
        };
        if let Some(first) = entry.hashes.first() {
            self.by_first.insert(*first, id);
        }
        self.frames.insert(id, entry);
        self.order.push_back(id);
        while self.frames.len() > MAX_FRAMES {
            let Some(oldest) = self.order.pop_front() else { break };
            if let Some(gone) = self.frames.remove(&oldest)
                && let Some(first) = gone.hashes.first()
                && self.by_first.get(first) == Some(&oldest)
            {
                self.by_first.remove(first);
            }
        }
        self.compact();
    }

    fn compact(&mut self) {
        if self.order.len() > 2 * self.frames.len() + 64 {
            let frames = &self.frames;
            self.order.retain(|id| frames.contains_key(id));
        }
    }

    /// Drops every frame the chain has mined any transaction of: a lane
    /// whose canonical watermark is at or past a run's first nonce. Called
    /// after a canonical prune has raised the watermarks.
    pub(crate) fn sweep<T: PoolTransaction>(&mut self, lanes: &AddressHashMap<Lane<T>>) -> usize {
        let before = self.frames.len();
        self.frames.retain(|_, entry| {
            !entry.runs.iter().any(|run| {
                lanes.get(&run.sender).is_some_and(|lane| lane.chain_mined(run.first_nonce))
            })
        });
        let gone = before - self.frames.len();
        if gone > 0 {
            let frames = &self.frames;
            self.by_first.retain(|_, id| frames.contains_key(id));
            self.compact();
        }
        gone
    }

    /// The frames in arrival order, each with whether a build could take it
    /// whole from `lanes` right now.
    pub(crate) fn in_arrival_order<T: PoolTransaction>(
        &self,
        lanes: &AddressHashMap<Lane<T>>,
    ) -> Vec<FrameRef> {
        self.order
            .iter()
            .filter_map(|id| {
                self.frames.get(id).map(|entry| FrameRef {
                    id: *id,
                    count: entry.hashes.len(),
                    gas: entry.gas,
                    whole_usable: whole_usable(entry, lanes),
                })
            })
            .collect()
    }

    /// A frame's positions as (index in frame, sender, nonce, hash), or
    /// `None` for a frame the index does not hold.
    pub(crate) fn members_of(&self, id: &B256) -> Option<Vec<(Address, u64, B256)>> {
        let entry = self.frames.get(id)?;
        let mut out = Vec::with_capacity(entry.hashes.len());
        for (at, sender, nonce) in entry.members() {
            out.push((sender, nonce, *entry.hashes.get(at)?));
        }
        Some(out)
    }

    /// The live frame ids in arrival order, without the whole-usable check
    /// [`FrameIndex::in_arrival_order`] makes of every one of them: a build
    /// checks only the frames it gets to.
    pub(crate) fn ids_in_arrival_order(&self) -> Vec<B256> {
        self.order.iter().filter(|id| self.frames.contains_key(*id)).copied().collect()
    }

    /// For each (id, length) of a layout over `body`, in order: `Some(id)`
    /// when the index holds that frame with exactly the body's hashes at
    /// those positions, whole -- so the id is the root over them -- `None`
    /// otherwise (not indexed, a prefix, different hashes, or a layout that
    /// runs past the body).
    pub(crate) fn held_whole(&self, layout: &[(B256, usize)], body: &[B256]) -> Vec<Option<B256>> {
        let mut at = 0usize;
        layout
            .iter()
            .map(|(id, len)| {
                let start = at;
                at = at.saturating_add(*len);
                let slice = body.get(start..at)?;
                let frame = self.frames.get(id)?;
                (frame.hashes.as_slice() == slice).then_some(*id)
            })
            .collect()
    }

    /// A frame's transactions' hashes, in frame order.
    pub(crate) fn hashes_of(&self, id: &B256) -> Option<&[B256]> {
        self.frames.get(id).map(|entry| entry.hashes.as_slice())
    }

    /// The frame layout of a body given by its transactions' hashes: the
    /// ids and lengths of the indexed frames it is made of, in order, the
    /// last one possibly a prefix of its frame. `None` when the body is not
    /// a run of indexed frames (a position that starts no indexed frame, a
    /// frame the body leaves before its end anywhere but last).
    pub(crate) fn layout_of(&self, hashes: &[B256]) -> Option<Vec<(B256, usize)>> {
        let mut layout = Vec::new();
        let mut at = 0usize;
        while at < hashes.len() {
            let id = *self.by_first.get(&hashes[at])?;
            let frame = &self.frames.get(&id)?.hashes;
            let take = frame.len().min(hashes.len() - at);
            if frame[..take] != hashes[at..at + take] {
                return None;
            }
            layout.push((id, take));
            at += take;
        }
        Some(layout)
    }
}

/// Whether every transaction of `entry` is in its lane, the lane is not
/// parked, and the lane's nonces run without a gap from its head through
/// the frame's.
fn whole_usable<T: PoolTransaction>(entry: &FrameEntry, lanes: &AddressHashMap<Lane<T>>) -> bool {
    entry.runs.iter().all(|run| {
        let Some(lane) = lanes.get(&run.sender) else { return false };
        if lane.parked.is_some() {
            return false;
        }
        let Some((&head, _)) = lane.by_nonce.first_key_value() else { return false };
        let Some(last) = run.first_nonce.checked_add(u64::from(run.len) - 1) else { return false };
        if run.first_nonce < head {
            return false;
        }
        let mut expect = head;
        for (&nonce, held) in lane.by_nonce.range(head..=last) {
            if nonce != expect {
                return false;
            }
            if nonce >= run.first_nonce {
                let at = run.start as usize + (nonce - run.first_nonce) as usize;
                if entry.hashes.get(at) != Some(held.hash()) {
                    return false;
                }
            }
            expect += 1;
        }
        expect == last + 1
    })
}

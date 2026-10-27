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
//! A frame noted through [`crate::TxQueue::push_frame`] also keeps the
//! queue's own `Arc`s of its transactions, in frame order (8 bytes a
//! transaction, 4 KB a 500-frame, ~8 MB at 2,000 frames), so the vote
//! road's [`crate::TxQueue::take_frames`] is one map look-up and one `Arc`
//! clone a frame instead of a lane look-up a transaction. The transactions
//! then live as long as their frame is indexed: the canonical prune that
//! drops the frame drops them with it. `N42_FRAME_ARCS=0` keeps no `Arc`s
//! (every frame is then fetched from the lanes, as before).
//!
//! A frame leaves the index when the chain mines any of its transactions
//! (the canonical prune, [`FrameIndex::sweep`]): it can never be referenced
//! whole again. What a build took, or an own block not yet committed, only
//! makes the frame not whole-usable for the moment.
//!
//! With `N42_FRAME_SWEEP_AT_TAKE` (on unless `=0`) a frame taken whole into
//! a build or a prepared plan leaves the live index at the take
//! ([`FrameIndex::retire`]): builds walk live frames only. It is kept aside,
//! out of the arrival walk but still found by id and by its first hash (the
//! seal's layout, the settle and the plan's lowest nonces read it after the
//! take), until the chain mines it (the sweep) or [`MAX_FRAMES`] newer ones
//! push it out. A take that comes back to the lanes whole (a build given
//! up, a prepared plan discarded) brings its frame back to the live index
//! at its arrival position ([`FrameIndex::revive_by_first`]); a frame only
//! partly returned (a build's tail handed back mid-frame) stays aside, and
//! its transactions are frameless at their lanes: the slow puller and the
//! per-transaction check take them, as before.

use std::collections::VecDeque;

use std::sync::Arc;

use alloy_primitives::{map::{AddressHashMap, B256HashMap}, Address, B256};
use reth_transaction_pool::{PoolTransaction, ValidPoolTransaction};

use crate::Lane;

/// The most frames the live index holds (and, apart, the most taken frames
/// it keeps aside). 16,384 frames of 500 is 8.2M transactions, past any
/// queue's gate -- but the bound is reached under load when taken frames
/// stay indexed until the canonical prune sweeps them: loop351 stage ak
/// held 16,384 from block ~1150 on with the queue pruner 140-157 blocks
/// behind, 13-16k of them dead. With `N42_FRAME_SWEEP_AT_TAKE` (the
/// default) taken frames leave at the take, and past the bound a new frame
/// is refused (its transactions stay in the lanes for the slow puller)
/// instead of evicting the oldest live one, whose transactions are still
/// queued: an evicted live frame left them frameless at their lane heads,
/// blocking every later frame of the same senders. With
/// `N42_FRAME_SWEEP_AT_TAKE=0` the oldest frame leaves, as before.
pub const MAX_FRAMES: usize = 16_384;

/// `N42_FRAME_SWEEP_AT_TAKE`, read once: on unless `0`.
pub(crate) fn frame_sweep_at_take() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FRAME_SWEEP_AT_TAKE", true))
}

/// A frame's transactions as the queue holds them, in frame order, shared.
pub type FrameTxs<T> = Arc<[Arc<ValidPoolTransaction<T>>]>;

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
#[derive(Debug, Clone, Default)]
pub struct FramePlan {
    /// The frames, in body order.
    pub frames: Vec<PlannedFrame>,
    /// The transactions' hashes, in body order, as the frames' taken parts
    /// end to end: each a frame's own shared hashes (the index's, by
    /// reference) and how many of them from its start. Copying them into
    /// one vector was ~5 MB under the queue's lock at every full build's
    /// start (step 7a, `start_walk_ms`); [`Self::hashes`] makes that vector
    /// for whoever needs it.
    pub parts: Vec<(Arc<[B256]>, usize)>,
    /// Indexed frames the plan passed over: not whole-usable, or not at
    /// their senders' lane heads once the frames before them were taken.
    pub skipped: usize,
}

/// Two plans are equal when their frames, their hashes in body order and
/// their passed-over count are: how the hashes are held (a frame's whole
/// shared list cut by a count, or a list of its taken part) does not count.
impl PartialEq for FramePlan {
    fn eq(&self, other: &Self) -> bool {
        self.frames == other.frames
            && self.skipped == other.skipped
            && self.tx_count() == other.tx_count()
            && self.parts.iter().flat_map(|(h, n)| &h[..*n]).eq(other.parts.iter().flat_map(|(h, n)| &h[..*n]))
    }
}

impl Eq for FramePlan {}

impl FramePlan {
    /// Appends a frame's taken part: the first `taken` of `hashes`.
    pub fn push_hashes(&mut self, hashes: Arc<[B256]>, taken: usize) {
        let taken = taken.min(hashes.len());
        if taken > 0 {
            self.parts.push((hashes, taken));
        }
    }

    /// How many transactions the plan holds.
    pub fn tx_count(&self) -> usize {
        self.parts.iter().map(|(_, taken)| *taken).sum()
    }

    /// The transactions' hashes, in body order, in one vector.
    pub fn hashes(&self) -> Vec<B256> {
        let mut out = Vec::with_capacity(self.tx_count());
        for (hashes, taken) in &self.parts {
            out.extend_from_slice(&hashes[..*taken]);
        }
        out
    }

    /// Whether `body` is a prefix of the plan's hashes, compared part by
    /// part.
    fn has_prefix(&self, body: &[B256]) -> bool {
        let mut rest = body;
        for (hashes, taken) in &self.parts {
            if rest.is_empty() {
                return true;
            }
            let n = (*taken).min(rest.len());
            if hashes[..n] != rest[..n] {
                return false;
            }
            rest = &rest[n..];
        }
        rest.is_empty()
    }

    /// The layout of a body built from this plan, as (frame id, length) in
    /// body order: `Some` when the body's hashes are a prefix of the plan's
    /// (a build that stopped early, or took everything), with the frame the
    /// body ends in cut to what it holds of it; `None` when the body is not
    /// a prefix of the plan -- it is not frame-aligned.
    pub fn layout_for(&self, body: &[B256]) -> Option<Vec<(B256, usize)>> {
        if !self.has_prefix(body) {
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
pub(crate) struct SenderRun {
    pub(crate) sender: Address,
    pub(crate) first_nonce: u64,
    /// The run's first position in the frame.
    pub(crate) start: u32,
    pub(crate) len: u32,
    /// How many positions of the same sender the frame holds before this
    /// run: a build can take the frame whole only when this run starts
    /// `before` nonces past the sender's lane head. Fixed at admission, so
    /// the build's check is one comparison a run.
    pub(crate) before: u32,
}

/// What [`FrameIndex::check_runs`] found of a frame against the lanes as
/// they stand before a build takes anything.
#[derive(Debug)]
pub(crate) enum RunCheck<T: PoolTransaction> {
    /// Only the per-transaction check can say (see [`ByRef::Slow`]).
    Slow,
    /// No build can take it whole, whatever the frames before it take: a
    /// lane missing or parked, a transaction missing, a run below its
    /// lane's head. `gas` is the frame's gas (for the cut decision).
    Unusable {
        /// The frame's transactions' gas.
        gas: u64,
    },
    /// Takeable whole once, for each run in `below`, exactly that many of
    /// its sender's lane entries have been taken by the frames before it
    /// (and none of any other sender of it).
    Ok {
        /// The frame's transactions, the lanes' very `Arc`s.
        txs: FrameTxs<T>,
        /// Their gas limits' sum.
        gas: u64,
        /// (run index, sender, lane entries below the run's target) for
        /// every run whose target is above its lane's head.
        below: Vec<(u32, Address, u64)>,
    },
}

/// What [`FrameIndex::check_by_ref`] found of a frame for a build.
#[derive(Debug)]
pub(crate) enum ByRef<T: PoolTransaction> {
    /// Not decidable by reference (a frame noted without its transactions,
    /// one that does not fit the gas left whole, or a lane holding another
    /// allocation of one of its transactions): the per-transaction check.
    Slow,
    /// A build cannot take it whole: the same verdict the per-transaction
    /// check reaches.
    Unusable,
    /// Every transaction is in its lane, at the lane's head in frame order,
    /// unparked, and is the frame's own allocation; the whole frame fits.
    Whole {
        /// The frame's transactions, the lanes' very `Arc`s.
        txs: FrameTxs<T>,
        /// Their gas limits' sum.
        gas: u64,
    },
}

#[derive(Debug)]
struct FrameEntry<T: PoolTransaction> {
    hashes: Arc<[B256]>,
    /// Shared so a plan snapshot (`crate::snapshot`) copies a frame's runs
    /// as one `Arc` clone.
    runs: Arc<[SenderRun]>,
    gas: u64,
    /// The transactions themselves, in frame order, when the frame was
    /// noted with them ([`crate::TxQueue::push_frame`]); `None` and
    /// [`crate::TxQueue::take_frames`] finds them in the lanes.
    txs: Option<FrameTxs<T>>,
    /// The sum of `txs`' gas limits, summed once at admission (0 without
    /// them): a build tests a whole frame against the gas left with it.
    txs_gas: u64,
}

impl<T: PoolTransaction> FrameEntry<T> {
    fn from_new(frame: NewFrame, txs: Option<FrameTxs<T>>) -> Option<(B256, Self)> {
        if frame.hashes.len() != frame.members.len() || frame.hashes.is_empty() {
            return None;
        }
        // A list of another length is not the frame's and is not kept: the
        // frame then reads from the lanes. Hash for hash it was matched by
        // `push_frame`, off the lanes' lock this runs under.
        let txs = txs.filter(|txs| txs.len() == frame.hashes.len());
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
                _ => runs.push(SenderRun { sender, first_nonce: nonce, start: at, len: 1, before: 0 }),
            }
        }
        debug_assert_eq!(runs.iter().map(|run| run.len).sum::<u32>(), len);
        // A sender with more than one run in the frame: each later run
        // counts the positions its earlier ones hold.
        if runs.len() > 1 {
            let mut seen: AddressHashMap<u32> = AddressHashMap::default();
            for run in &mut runs {
                let count = seen.entry(run.sender).or_insert(0);
                run.before = *count;
                *count += run.len;
            }
        }
        let txs_gas =
            txs.as_ref().map_or(0, |txs| txs.iter().map(|tx| tx.gas_limit()).fold(0u64, u64::saturating_add));
        Some((frame.id, Self { hashes: frame.hashes.into(), runs: runs.into(), gas: frame.gas, txs, txs_gas }))
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

/// What [`check_runs_of`] reads of a lane: the lane itself under the
/// lanes' lock, or a plan snapshot's copy of it (`crate::snapshot`).
/// Entries are compared by allocation address only, never dereferenced.
pub(crate) trait RunLane {
    /// Whether the lane is parked behind a hole.
    fn is_parked(&self) -> bool;
    /// The lane's lowest queued nonce.
    fn head(&self) -> Option<u64>;
    /// (nonce, allocation address) of the entries in `lo..hi`, ascending;
    /// `lo < hi`.
    fn range_addrs(&self, lo: u64, hi: u64) -> impl Iterator<Item = (u64, usize)> + '_;
    /// Whether the lane holds `nonce`.
    fn holds(&self, nonce: u64) -> bool;
    /// How many entries the lane holds in `lo..hi`; `lo < hi`.
    fn count_in(&self, lo: u64, hi: u64) -> u64;
}

impl<T: PoolTransaction> RunLane for Lane<T> {
    fn is_parked(&self) -> bool {
        self.parked.is_some()
    }
    fn head(&self) -> Option<u64> {
        self.by_nonce.first_key_value().map(|(nonce, _)| *nonce)
    }
    fn range_addrs(&self, lo: u64, hi: u64) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.by_nonce.range(lo..hi).map(|(nonce, held)| (*nonce, Arc::as_ptr(held) as usize))
    }
    fn holds(&self, nonce: u64) -> bool {
        self.by_nonce.contains_key(&nonce)
    }
    fn count_in(&self, lo: u64, hi: u64) -> u64 {
        self.by_nonce.range(lo..hi).count() as u64
    }
}

/// [`FrameIndex::check_runs`] of one frame's runs and transactions against
/// whatever `lane_of` reads the lanes from. A lane entry is the frame's own
/// transaction when its allocation address is the frame's `Arc`'s (the
/// frame keeps that allocation alive, so an equal address is the same
/// allocation).
pub(crate) fn check_runs_of<'l, T, L>(
    runs: &[SenderRun],
    txs: Option<&FrameTxs<T>>,
    txs_gas: u64,
    lane_of: impl Fn(&Address) -> Option<&'l L>,
) -> RunCheck<T>
where
    T: PoolTransaction,
    L: RunLane + 'l,
{
    let Some(txs) = txs else { return RunCheck::Slow };
    let unusable = RunCheck::Unusable { gas: txs_gas };
    let mut below = Vec::new();
    for (idx, run) in runs.iter().enumerate() {
        let Some(lane) = lane_of(&run.sender) else { return unusable };
        if lane.is_parked() {
            return unusable;
        }
        let Some(head) = lane.head() else { return unusable };
        let Some(target) = run.first_nonce.checked_sub(u64::from(run.before)) else { return unusable };
        if target < head {
            return unusable;
        }
        let Some(last) = run.first_nonce.checked_add(u64::from(run.len)) else { return RunCheck::Slow };
        let mut expect = run.first_nonce;
        for (at, (nonce, held)) in (run.start as usize..).zip(lane.range_addrs(run.first_nonce, last)) {
            if nonce != expect {
                return unusable;
            }
            let Some(own) = txs.get(at) else { return RunCheck::Slow };
            if held != Arc::as_ptr(own) as usize {
                return RunCheck::Slow;
            }
            expect += 1;
        }
        if expect != last {
            return unusable;
        }
        if run.before > 0 && !lane.holds(target) {
            return unusable;
        }
        if target > head {
            let Ok(idx) = u32::try_from(idx) else { return RunCheck::Slow };
            below.push((idx, run.sender, lane.count_in(head, target)));
        }
    }
    RunCheck::Ok { txs: Arc::clone(txs), gas: txs_gas, below }
}

/// The index itself: a plain map plus the arrival order.
#[derive(Debug)]
pub(crate) struct FrameIndex<T: PoolTransaction> {
    frames: B256HashMap<FrameEntry<T>>,
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
    /// Frames indexed since the process started: what the continuous
    /// plan-ahead preparer (`N42_PLAN_AHEAD_WAIT_MS`) reads to plan again
    /// only when a frame has arrived.
    pub(crate) inserted: u64,
    /// `N42_FRAME_SWEEP_AT_TAKE`: taken frames leave the live index at the
    /// take, and a full index refuses rather than evicts.
    pub(crate) sweep_at_take: bool,
    /// Frames taken whole, out of the live index ([`Self::retire`]).
    retired: B256HashMap<FrameEntry<T>>,
    /// Their ids in retirement order (an id no longer aside is skipped).
    retired_order: VecDeque<B256>,
    /// Transactions of frames pushed out of `retired` by the bound, for the
    /// next sweep to hand to its caller to free off the lock.
    retired_gone: Vec<FrameTxs<T>>,
    /// Frames retired at a take, and frames refused at the bound; since the
    /// process started.
    pub(crate) swept_at_take: u64,
    pub(crate) refused_at_cap: u64,
}

impl<T: PoolTransaction> Default for FrameIndex<T> {
    fn default() -> Self {
        Self {
            frames: B256HashMap::default(),
            by_first: B256HashMap::default(),
            order: VecDeque::new(),
            refused: 0,
            inserted: 0,
            sweep_at_take: frame_sweep_at_take(),
            retired: B256HashMap::default(),
            retired_order: VecDeque::new(),
            retired_gone: Vec::new(),
            swept_at_take: 0,
            refused_at_cap: 0,
        }
    }
}

impl<T: PoolTransaction> FrameIndex<T> {
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(crate) fn insert(&mut self, frame: NewFrame, txs: Option<FrameTxs<T>>) {
        if self.frames.contains_key(&frame.id) || self.retired.contains_key(&frame.id) {
            self.refused += 1;
            return;
        }
        if self.sweep_at_take && self.frames.len() >= MAX_FRAMES {
            // Refused, not evicting a live frame: its transactions are in
            // the lanes already and the slow puller takes them.
            self.refused += 1;
            self.refused_at_cap += 1;
            return;
        }
        let Some((id, entry)) = FrameEntry::from_new(frame, txs) else {
            self.refused += 1;
            return;
        };
        if let Some(first) = entry.hashes.first() {
            self.by_first.insert(*first, id);
        }
        self.frames.insert(id, entry);
        self.order.push_back(id);
        self.inserted = self.inserted.wrapping_add(1);
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
        // A frame aside keeps its arrival position: it comes back there.
        if self.order.len() > 2 * (self.frames.len() + self.retired.len()) + 64 {
            let (frames, retired) = (&self.frames, &self.retired);
            self.order.retain(|id| frames.contains_key(id) || retired.contains_key(id));
        }
    }

    /// A frame taken into a build or a prepared plan, `taken` of its
    /// transactions from its start (`N42_FRAME_SWEEP_AT_TAKE`): taken whole,
    /// it leaves the live index for the frames aside; a cut frame's rest is
    /// still in the lanes and the frame stays live. Returns whether it left.
    pub(crate) fn retire(&mut self, id: &B256, taken: usize) -> bool {
        if !self.sweep_at_take {
            return false;
        }
        if !self.frames.get(id).is_some_and(|entry| taken >= entry.hashes.len()) {
            return false;
        }
        let Some(entry) = self.frames.remove(id) else { return false };
        self.retired.insert(*id, entry);
        self.retired_order.push_back(*id);
        self.swept_at_take += 1;
        while self.retired.len() > MAX_FRAMES {
            let Some(oldest) = self.retired_order.pop_front() else { break };
            if let Some(gone) = self.retired.remove(&oldest) {
                self.forget_first(&oldest, &gone);
                if let Some(txs) = gone.txs {
                    self.retired_gone.push(txs);
                }
            }
        }
        if self.retired_order.len() > 2 * self.retired.len() + 64 {
            let retired = &self.retired;
            self.retired_order.retain(|id| retired.contains_key(id));
        }
        true
    }

    /// A transaction back in its lane whose hash starts a frame aside: the
    /// frame is live again, at its arrival position (a take given back
    /// whole -- a build given up, a prepared plan discarded). Returns
    /// whether a frame came back.
    pub(crate) fn revive_by_first(&mut self, hash: &B256) -> bool {
        if self.retired.is_empty() {
            return false;
        }
        let Some(id) = self.by_first.get(hash).copied() else { return false };
        let Some(entry) = self.retired.remove(&id) else { return false };
        self.frames.insert(id, entry);
        true
    }

    /// Frames aside now.
    pub(crate) fn retired_len(&self) -> usize {
        self.retired.len()
    }

    fn forget_first(&mut self, id: &B256, entry: &FrameEntry<T>) {
        if let Some(first) = entry.hashes.first()
            && self.by_first.get(first) == Some(id)
        {
            self.by_first.remove(first);
        }
    }

    /// The frames aside whose first run the chain has mined leave for good,
    /// their transactions (and those the bound pushed out) handed to `gone`
    /// to be freed off the lock. One lane look-up a frame aside, not one a
    /// run: the frames aside are up to [`MAX_FRAMES`] of hundreds of runs
    /// each, and checking every run held the prune's lock 45 ms longer at
    /// p90 in loop351 stage al (`X9FS`), long enough to make the plan
    /// prepared after a take late for half the builds. A block takes a frame
    /// whole, so its first run is mined with the rest; one mined some other
    /// way leaves with the bound.
    pub(crate) fn sweep_retired_into(&mut self, lanes: &AddressHashMap<Lane<T>>, gone: &mut Vec<FrameTxs<T>>) -> usize {
        gone.append(&mut self.retired_gone);
        let dead: Vec<B256> = self
            .retired
            .iter()
            .filter(|(_, entry)| {
                entry.runs.first().is_some_and(|run| lanes.get(&run.sender).is_some_and(|lane| lane.chain_mined(run.first_nonce)))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &dead {
            if let Some(entry) = self.retired.remove(id) {
                self.forget_first(id, &entry);
                if let Some(txs) = entry.txs {
                    gone.push(txs);
                }
            }
        }
        dead.len()
    }

    /// A frame live or aside, by id: for the reads that follow a take.
    fn any(&self, id: &B256) -> Option<&FrameEntry<T>> {
        self.frames.get(id).or_else(|| self.retired.get(id))
    }

    /// [`Self::runs_and_hashes`] of a frame live or aside.
    pub(crate) fn runs_and_hashes_any(&self, id: &B256) -> Option<(&[SenderRun], &Arc<[B256]>)> {
        self.any(id).map(|entry| (&entry.runs[..], &entry.hashes))
    }

    /// Drops every frame the chain has mined any transaction of: a lane
    /// whose canonical watermark is at or past a run's first nonce. Called
    /// after a canonical prune has raised the watermarks.
    pub(crate) fn sweep(&mut self, lanes: &AddressHashMap<Lane<T>>) -> usize {
        let mut gone = Vec::new();
        self.sweep_into(lanes, &mut gone);
        gone.len()
    }

    /// [`Self::sweep`], handing the dropped frames' transactions to `gone`
    /// instead of freeing them here: the caller holds the lanes' lock, and a
    /// frame's last reference to its transactions is often this one, so the
    /// free of a block's worth (200,000 allocations) would otherwise happen
    /// under it. Each dropped frame's own `by_first` entry is removed by its
    /// first hash rather than by a pass over every indexed frame.
    pub(crate) fn sweep_into(&mut self, lanes: &AddressHashMap<Lane<T>>, gone: &mut Vec<FrameTxs<T>>) -> usize {
        let aside = self.sweep_retired_into(lanes, gone);
        let dead: Vec<B256> = self
            .frames
            .iter()
            .filter(|(_, entry)| {
                entry.runs.iter().any(|run| {
                    lanes.get(&run.sender).is_some_and(|lane| lane.chain_mined(run.first_nonce))
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &dead {
            if let Some(entry) = self.frames.remove(id) {
                if let Some(first) = entry.hashes.first()
                    && self.by_first.get(first) == Some(id)
                {
                    self.by_first.remove(first);
                }
                if let Some(txs) = entry.txs {
                    gone.push(txs);
                }
            }
        }
        if !dead.is_empty() {
            self.compact();
        }
        dead.len() + aside
    }

    /// [`Self::sweep_into`] over `ids` only, without compacting the arrival
    /// order: one bounded hold of an off-lock prune's sweep
    /// (`N42_QUEUE_OFFLOCK`), which compacts once at its end
    /// ([`Self::compact_order`]). An id no longer indexed is passed over.
    pub(crate) fn sweep_ids_into(
        &mut self,
        ids: &[B256],
        lanes: &AddressHashMap<Lane<T>>,
        gone: &mut Vec<FrameTxs<T>>,
    ) -> usize {
        let mut dead = 0usize;
        for id in ids {
            let Some(entry) = self.frames.get(id) else { continue };
            if !entry.runs.iter().any(|run| lanes.get(&run.sender).is_some_and(|lane| lane.chain_mined(run.first_nonce))) {
                continue;
            }
            if let Some(entry) = self.frames.remove(id) {
                if let Some(first) = entry.hashes.first()
                    && self.by_first.get(first) == Some(id)
                {
                    self.by_first.remove(first);
                }
                if let Some(txs) = entry.txs {
                    gone.push(txs);
                }
                dead += 1;
            }
        }
        dead
    }

    /// Compacts the arrival order when the ids no longer indexed outnumber
    /// the live ones (what every sweep does at its end).
    pub(crate) fn compact_order(&mut self) {
        self.compact();
    }

    /// The frames in arrival order, each with whether a build could take it
    /// whole from `lanes` right now.
    pub(crate) fn in_arrival_order(
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

    /// A frame build's check of frame `id` by reference: per sender run,
    /// one lane look-up, the head's nonce against the run's, and the lane's
    /// entries compared with the frame's own `Arc`s by pointer -- no
    /// transaction is dereferenced, no gas summed, nothing allocated.
    /// [`ByRef::Whole`] exactly when the per-transaction check of
    /// `Inner::plan_frames` would take the frame whole; [`ByRef::Unusable`]
    /// exactly when it would skip it; [`ByRef::Slow`] when only it can say
    /// (see there).
    pub(crate) fn check_by_ref(&self, id: &B256, lanes: &AddressHashMap<Lane<T>>, gas_left: u64) -> ByRef<T> {
        let Some(entry) = self.frames.get(id) else { return ByRef::Slow };
        let Some(txs) = entry.txs.as_ref() else { return ByRef::Slow };
        if entry.txs_gas > gas_left {
            return ByRef::Slow;
        }
        for run in entry.runs.iter() {
            let Some(lane) = lanes.get(&run.sender) else { return ByRef::Unusable };
            if lane.parked.is_some() {
                return ByRef::Unusable;
            }
            let head = lane.by_nonce.first_key_value().map(|(nonce, _)| *nonce);
            if head.and_then(|head| head.checked_add(u64::from(run.before))) != Some(run.first_nonce) {
                return ByRef::Unusable;
            }
            let Some(last) = run.first_nonce.checked_add(u64::from(run.len)) else { return ByRef::Slow };
            let mut expect = run.first_nonce;
            for (at, (&nonce, held)) in (run.start as usize..).zip(lane.by_nonce.range(run.first_nonce..last)) {
                if nonce != expect {
                    // A missing nonce: the per-position check finds no
                    // transaction there.
                    return ByRef::Unusable;
                }
                let Some(own) = txs.get(at) else { return ByRef::Slow };
                if !Arc::ptr_eq(held, own) {
                    // Another allocation: equal or not, the hashes decide.
                    return ByRef::Slow;
                }
                expect += 1;
            }
            if expect != last {
                return ByRef::Unusable;
            }
        }
        ByRef::Whole { txs: Arc::clone(txs), gas: entry.txs_gas }
    }

    /// [`Self::check_by_ref`] against the lanes before a build takes
    /// anything, so it can run for many frames at once (read-only, on the
    /// worker pool). A run with `before` positions of its sender earlier in
    /// the frame is takeable once its lane's head is its target, its first
    /// nonce less `before`; the head only rises as the build takes, by exactly the
    /// entries the earlier frames take, so the run needs the lane to hold
    /// `target` and the build to have taken exactly the entries below it
    /// (`below`). Every other failure is final: takes neither park a lane
    /// nor put a transaction back, and a lane entry is some one frame's own
    /// allocation, so no other frame's take removes one this frame holds.
    pub(crate) fn check_runs(&self, id: &B256, lanes: &AddressHashMap<Lane<T>>) -> RunCheck<T> {
        let Some(entry) = self.frames.get(id) else { return RunCheck::Slow };
        check_runs_of(&entry.runs, entry.txs.as_ref(), entry.txs_gas, |sender| lanes.get(sender))
    }

    /// What a plan snapshot copies of an indexed frame (`crate::snapshot`):
    /// its runs, hashes, own transactions (`None` when noted without them)
    /// and their gas, each one `Arc` clone. `None` for a frame not indexed.
    #[allow(clippy::type_complexity)]
    pub(crate) fn snapshot_of(
        &self,
        id: &B256,
    ) -> Option<(Arc<[SenderRun]>, Arc<[B256]>, Option<FrameTxs<T>>, u64)> {
        self.frames
            .get(id)
            .map(|entry| (Arc::clone(&entry.runs), Arc::clone(&entry.hashes), entry.txs.clone(), entry.txs_gas))
    }

    /// The gas of a frame's own transactions, summed at admission: `None`
    /// for a frame not indexed or noted without its transactions.
    pub(crate) fn txs_gas_of(&self, id: &B256) -> Option<u64> {
        self.frames.get(id).filter(|entry| entry.txs.is_some()).map(|entry| entry.txs_gas)
    }

    /// A frame's sender runs and hashes, for the take after
    /// [`Self::check_by_ref`].
    pub(crate) fn runs_and_hashes(&self, id: &B256) -> Option<(&[SenderRun], &Arc<[B256]>)> {
        self.frames.get(id).map(|entry| (&entry.runs[..], &entry.hashes))
    }

    /// The transactions a frame was noted with, shared: `None` for a frame
    /// the index does not hold or one noted without them.
    pub(crate) fn txs_of(&self, id: &B256) -> Option<FrameTxs<T>> {
        self.any(id)?.txs.clone()
    }

    /// How many indexed frames hold their transactions.
    pub(crate) fn with_txs(&self) -> usize {
        self.frames.values().filter(|entry| entry.txs.is_some()).count()
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
                let frame = self.any(id)?;
                (&frame.hashes[..] == slice).then_some(*id)
            })
            .collect()
    }

    /// A frame's transactions' hashes, in frame order.
    pub(crate) fn hashes_of(&self, id: &B256) -> Option<&[B256]> {
        self.any(id).map(|entry| &entry.hashes[..])
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
            let frame = &self.any(&id)?.hashes;
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
fn whole_usable<T: PoolTransaction>(entry: &FrameEntry<T>, lanes: &AddressHashMap<Lane<T>>) -> bool {
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

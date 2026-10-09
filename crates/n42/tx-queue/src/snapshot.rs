// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_QUEUE_PLAN_SNAPSHOT=1` (with `N42_QUEUE_OFFLOCK=1`): frame plans
//! made off the lanes' lock from a snapshot.
//!
//! With `N42_QUEUE_OFFLOCK` alone the plan-ahead preparation still planned
//! under its first hold -- the parallel run check of every frame the block's
//! gas reaches, ~200,000 lane look-ups -- and a build whose prepared plan
//! was unusable gave the plan's ~200,000 transactions back and planned
//! afresh in one hold (loop351 stage p: holds of 32-35 ms median at
//! `frames_for_build_ahead`, 50 ms at `offlock_plan`, at a 40 ms cycle).
//! Here a plan is made in four steps:
//!
//! 1. **Frames** (inside a hold the caller already has): the ids the gas
//!    reaches plus [`PLAN_MARGIN`], each frame's runs, hashes and own
//!    transactions as one `Arc` clone apiece ([`Inner::snapshot_frames`]).
//! 2. **Lanes** (holds of at most [`SNAPSHOT_SENDERS`] senders, checked in
//!    parallel): per sender those frames name, whether its lane is parked,
//!    its head nonce and its entries' (nonce, allocation address) from the
//!    head up to the highest nonce a frame needs ([`SnapLane`]). A hold
//!    finding the build counter moved or a build's takes still noted ends
//!    the snapshot (a fallback).
//! 3. **Plan**, no lock held: [`plan_parallel_over`] on the snapshot -- the
//!    very code the locked plan runs, over a copy of what it reads. A plan
//!    the parallel part does not finish (a frame only the serial check can
//!    decide, or more frames passed over than the margin) falls back.
//! 4. **Commit** (one hold): every sender the plan takes from is checked
//!    in parallel -- lane present, unparked, its head the plan's first nonce
//!    for it, and every taken nonce holding the plan's own allocation -- and
//!    the noted frames still indexed. Then the takes apply (the prepared
//!    plan: popped from the lanes' heads into [`Prepared`]; a build: noted
//!    as [`Inner::pending`] for [`TxQueue::settle_offlock`], exactly as the
//!    locked plan notes them). A sender that fails is a miss: its lane is
//!    re-read in the same hold, the plan is made again off the lock, up to
//!    [`SNAPSHOT_REPLANS`] times, then the locked path plans.
//!
//! The check in step 4 is per lane, so an arrival into a lane the plan did
//! not take from -- or above the nonces it took -- is not a miss: it is an
//! arrival a moment later, which the locked plan could have missed as well.
//! What a miss catches is everything that would make the plan's takes wrong:
//! a lane's head moved (an arrival below the plan's nonces, a give-back, a
//! prune), an entry removed or replaced, a park. Per-sender nonce order, the
//! gas cut and the frame layout are the planner's own (unchanged); parked
//! lanes are read as parked; a reorg's give-back moves heads and is caught.
//!
//! A build whose prepared plan is unusable gives it back in batches of at
//! most [`GIVE_BACK_BATCH`] transactions ([`TxQueue::give_back_batched`]),
//! each a hold of its own, sender by sender in the order the one-hold
//! give-back would offer them, then plans as above.

use super::*;
use alloy_primitives::map::B256HashMap;
use frames::{check_runs_of, RunCheck, RunLane, SenderRun};
use rayon::prelude::*;

/// `N42_QUEUE_PLAN_SNAPSHOT`, read once (default off); only with
/// `N42_QUEUE_OFFLOCK` and the parallel frame selection. A test sets it per
/// queue ([`TxQueue::with_plan_snapshot`]).
pub(crate) fn queue_plan_snapshot() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_QUEUE_PLAN_SNAPSHOT").is_ok_and(|v| v == "1"))
}

/// Senders whose lanes one snapshot hold reads.
pub(crate) const SNAPSHOT_SENDERS: usize = 8_192;

/// How many times a plan whose commit missed is made again before the
/// locked path plans.
pub(crate) const SNAPSHOT_REPLANS: usize = 2;

/// How many times a snapshot is widened (its margin of frames past the gas
/// times eight each time) before the locked path plans.
pub(crate) const SNAPSHOT_FURTHER: usize = 3;

/// Transactions one hold of a batched give-back returns to the lanes.
pub(crate) const GIVE_BACK_BATCH: usize = 8_192;

/// Snapshot plans whose commit found a lane it took from moved (and
/// re-planned), and snapshot plans that went to the locked path instead,
/// since the last [`take_plan_snapshot_stats`].
static PLAN_SNAPSHOT_MISSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PLAN_SNAPSHOT_FALLBACKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `(misses, fallbacks)` of the snapshot planner since the last call, which
/// resets them.
pub fn take_plan_snapshot_stats() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (PLAN_SNAPSHOT_MISSES.swap(0, Relaxed), PLAN_SNAPSHOT_FALLBACKS.swap(0, Relaxed))
}

fn note_miss() {
    PLAN_SNAPSHOT_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn note_fallback() {
    PLAN_SNAPSHOT_FALLBACKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// One lane as a snapshot read it: from its head up to (not including) the
/// highest nonce a snapshot frame needs of it. Addresses are compared, never
/// dereferenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapLane {
    parked: bool,
    head: Option<u64>,
    entries: Vec<(u64, usize)>,
}

impl SnapLane {
    fn of<T: PoolTransaction>(lane: &Lane<T>, upto: u64) -> Self {
        let head = lane.head();
        let entries = match head {
            Some(head) if head < upto => lane.range_addrs(head, upto).collect(),
            _ => Vec::new(),
        };
        Self { parked: lane.parked.is_some(), head, entries }
    }

    fn at(&self, nonce: u64) -> usize {
        self.entries.partition_point(|(n, _)| *n < nonce)
    }
}

impl RunLane for SnapLane {
    fn is_parked(&self) -> bool {
        self.parked
    }
    fn head(&self) -> Option<u64> {
        self.head
    }
    fn range_addrs(&self, lo: u64, hi: u64) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.entries[self.at(lo)..self.at(hi)].iter().copied()
    }
    fn holds(&self, nonce: u64) -> bool {
        self.entries.binary_search_by_key(&nonce, |(n, _)| *n).is_ok()
    }
    fn count_in(&self, lo: u64, hi: u64) -> u64 {
        (self.at(hi) - self.at(lo)) as u64
    }
}

/// One frame as a snapshot holds it.
struct SnapFrame<T: PoolTransaction> {
    runs: Arc<[SenderRun]>,
    hashes: Arc<[B256]>,
    txs: Option<FrameTxs<T>>,
    txs_gas: u64,
}

/// What the parallel planner reads, copied out of the lanes' lock.
pub(crate) struct PlanSnapshot<T: PoolTransaction> {
    /// The frame ids the gas reaches plus the margin, in arrival order.
    ids: Vec<B256>,
    /// How many frames the index held: a plan that gets past `ids` without
    /// ending needs the serial part, which only the locked path runs.
    total: usize,
    frames: B256HashMap<SnapFrame<T>>,
    /// Frames whose first transaction is not in its lane, or whose lane is
    /// parked or gone, when the frames were read: no build can take any
    /// prefix of them (takes never add a lane entry), so they are passed
    /// over without reading their lanes. Mostly the frames the build in
    /// flight has just taken, still indexed until their block is pruned --
    /// without this, they exhausted the planner's margin and every
    /// preparation went to its serial part.
    dead: alloy_primitives::map::B256HashSet,
    /// Per sender the frames name, the nonce up to which its lane is read.
    want: AddressHashMap<u64>,
    lanes: AddressHashMap<SnapLane>,
    /// [`Inner::builds`] when it was taken.
    pub(crate) builds: u64,
    /// The planner's margin of frames past the gas this snapshot reaches.
    margin: usize,
}

impl<T: PoolTransaction> PlanSource<T> for PlanSnapshot<T> {
    fn txs_gas_of(&self, id: &B256) -> Option<u64> {
        if self.dead.contains(id) {
            return Some(0);
        }
        self.frames.get(id).filter(|frame| frame.txs.is_some()).map(|frame| frame.txs_gas)
    }
    fn check_runs(&self, id: &B256) -> RunCheck<T> {
        if self.dead.contains(id) {
            // Passed over whatever the gas left: no prefix of it is
            // takeable, which every mode of the locked plan agrees on.
            return RunCheck::Unusable { gas: 0 };
        }
        let Some(frame) = self.frames.get(id) else { return RunCheck::Slow };
        check_runs_of(&frame.runs, frame.txs.as_ref(), frame.txs_gas, |sender| self.lanes.get(sender))
    }
    fn runs_and_hashes(&self, id: &B256) -> Option<(&[SenderRun], &Arc<[B256]>)> {
        self.frames.get(id).map(|frame| (&frame.runs[..], &frame.hashes))
    }
}

impl<T: PoolTransaction> PlanSnapshot<T> {
    /// The senders whose lanes the snapshot reads, with the nonce up to
    /// which; computed off the lock.
    /// Only the senders not read yet, or read short of what the frames now
    /// need, are returned.
    fn wanted(&mut self) -> Vec<(Address, u64)> {
        let mut want: AddressHashMap<u64> = AddressHashMap::default();
        let mut order: Vec<Address> = Vec::new();
        for id in &self.ids {
            let Some(frame) = self.frames.get(id) else { continue };
            if frame.txs.is_none() {
                continue;
            }
            for run in frame.runs.iter() {
                let last = run.first_nonce.saturating_add(u64::from(run.len));
                if let Some(upto) = want.get_mut(&run.sender) {
                    *upto = (*upto).max(last);
                } else {
                    want.insert(run.sender, last);
                    order.push(run.sender);
                }
            }
        }
        let out = order
            .iter()
            .map(|sender| (*sender, want[sender]))
            .filter(|(sender, upto)| self.want.get(sender).is_none_or(|read| read < upto))
            .collect();
        self.want = want;
        out
    }

    /// Re-reads `senders`' lanes under a hold the caller has.
    pub(crate) fn refresh(&mut self, lanes: &AddressHashMap<Lane<T>>, senders: &[Address]) {
        for sender in senders {
            let Some(upto) = self.want.get(sender).copied() else { continue };
            match lanes.get(sender) {
                Some(lane) => {
                    self.lanes.insert(*sender, SnapLane::of(lane, upto));
                }
                None => {
                    self.lanes.remove(sender);
                }
            }
        }
    }
}

/// A plan made from a snapshot, before its commit.
pub(crate) struct SnapPlan<T: PoolTransaction> {
    pub(crate) segments: Vec<(FrameTxs<T>, usize)>,
    pub(crate) plan: FramePlan,
    pub(crate) gas_left: u64,
    /// (frame id, taken prefix) in plan order, as the locked plan notes them.
    pub(crate) noted: Vec<(B256, usize)>,
    /// The transactions taken, in plan order (the frames' own `Arc`s).
    pub(crate) taken: Vec<Arc<ValidPoolTransaction<T>>>,
    /// Per sender taken from, in first-taken order: the run of nonces
    /// `lo..hi` it takes from its lane's head.
    pub(crate) runs: Vec<(Address, u64, u64)>,
    pub(crate) times: FrameSelectTimes,
}

/// What [`plan_from_snapshot`] made of a snapshot.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SnapPlanned<T: PoolTransaction> {
    Plan(SnapPlan<T>),
    /// The plan ran past the frames the snapshot holds without ending:
    /// a snapshot reaching further plans it.
    Further,
    /// Only the locked path can finish the plan (a frame only the
    /// per-transaction check decides), or a sender's takes are not one run.
    Locked,
}

#[cfg(test)]
impl<T: PoolTransaction> SnapPlanned<T> {
    /// The plan, if one was made.
    pub(crate) fn plan(self) -> Option<SnapPlan<T>> {
        match self {
            Self::Plan(plan) => Some(plan),
            _ => None,
        }
    }
}

/// Plans from `snapshot` with no lock held.
pub(crate) fn plan_from_snapshot<T: PoolTransaction>(snapshot: &PlanSnapshot<T>, gas_limit: u64) -> SnapPlanned<T> {
    match plan_snapshot_once(snapshot, gas_limit) {
        Ok(plan) => SnapPlanned::Plan(plan),
        Err(true) => SnapPlanned::Further,
        Err(false) => SnapPlanned::Locked,
    }
}

fn plan_snapshot_once<T: PoolTransaction>(snapshot: &PlanSnapshot<T>, gas_limit: u64) -> Result<SnapPlan<T>, bool> {
    let mut times = FrameSelectTimes::default();
    let mut segments = Vec::new();
    let mut plan = FramePlan::default();
    let mut gas_left = gas_limit;
    let mut noted = Vec::new();
    let (next, ended) = plan_parallel_over(
        snapshot,
        &snapshot.ids,
        &mut gas_left,
        &mut segments,
        &mut plan,
        &mut times,
        &mut noted,
        snapshot.margin,
    );
    // The locked plan's serial part runs when the parallel part stops short
    // of the index's end with gas left: past the snapshot's frames, a
    // snapshot reaching further continues it; before, only the lock can.
    if !ended && gas_left > 0 && next < snapshot.total {
        return Err(next >= snapshot.ids.len());
    }
    let count: usize = noted.iter().map(|(_, prefix)| *prefix).sum();
    let mut taken: Vec<Arc<ValidPoolTransaction<T>>> = Vec::with_capacity(count);
    for (txs, prefix) in &segments {
        taken.extend(txs.iter().take(*prefix).cloned());
    }
    let mut index: AddressHashMap<usize> = AddressHashMap::default();
    let mut runs: Vec<(Address, u64, u64)> = Vec::new();
    for t in &taken {
        let nonce = t.nonce();
        if let Some(at) = index.get(&t.sender()) {
            let run = &mut runs[*at];
            if run.2 != nonce {
                return Err(false);
            }
            run.2 = nonce.saturating_add(1);
        } else {
            index.insert(t.sender(), runs.len());
            runs.push((t.sender(), nonce, nonce.saturating_add(1)));
        }
    }
    Ok(SnapPlan { segments, plan, gas_left, noted, taken, runs, times })
}

/// Why a snapshot plan's commit refused it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SnapMiss {
    /// These senders' lanes are not as the plan found them: re-read them
    /// and plan again.
    Lanes(Vec<Address>),
    /// The build counter moved, a plan is already prepared, or a frame the
    /// plan took left the index: the locked path decides.
    Stale,
}

impl<T: PoolTransaction> Inner<T> {
    /// Step 1 of a snapshot plan, under a hold the caller has: the frames
    /// a plan against `gas_limit` can reach, exactly the ones the locked
    /// parallel part would check.
    pub(crate) fn snapshot_frames(&self, gas_limit: u64) -> PlanSnapshot<T> {
        self.snapshot_frames_to(gas_limit, PLAN_MARGIN)
    }

    /// [`Self::snapshot_frames`] with `margin` frames past the gas.
    pub(crate) fn snapshot_frames_to(&self, gas_limit: u64, margin: usize) -> PlanSnapshot<T> {
        let all = self.frames.ids_in_arrival_order();
        let mut end = 0usize;
        let mut reach = 0u64;
        let mut past = 0usize;
        let mut frames = B256HashMap::default();
        let mut dead = alloy_primitives::map::B256HashSet::default();
        // The planner's own reach (`plan_parallel_over`), over the frames
        // that are not dead.
        while end < all.len() && past <= margin {
            let id = all[end];
            end += 1;
            let Some((runs, hashes, txs, txs_gas)) = self.frames.snapshot_of(&id) else {
                // Not indexed: the planner reads it as a frame of no
                // transactions (only the serial part decides).
                reach = u64::MAX;
                continue;
            };
            let gone = runs.first().is_none_or(|run| {
                self.lanes
                    .get(&run.sender)
                    .is_none_or(|lane| lane.parked.is_some() || !lane.by_nonce.contains_key(&run.first_nonce))
            });
            if gone {
                dead.insert(id);
                continue;
            }
            let gas = if txs.is_some() { txs_gas } else { u64::MAX };
            if reach > gas_limit {
                past += 1;
            }
            reach = reach.saturating_add(gas);
            frames.insert(id, SnapFrame { runs, hashes, txs, txs_gas });
        }
        PlanSnapshot {
            ids: all[..end].to_vec(),
            total: all.len(),
            frames,
            dead,
            want: AddressHashMap::default(),
            lanes: AddressHashMap::default(),
            builds: self.builds,
            margin,
        }
    }

    /// Step 4's check, read-only and in parallel: `Ok` when every sender
    /// `plan` takes from still holds, at its lane's unparked head, exactly
    /// the allocations the plan takes, and every frame it took is indexed.
    pub(crate) fn snapshot_verdict(&self, plan: &SnapPlan<T>, builds: u64) -> Result<(), SnapMiss> {
        if self.builds != builds || self.prepared.is_some() || self.takes_unsettled() {
            return Err(SnapMiss::Stale);
        }
        if plan.noted.iter().any(|(id, _)| self.frames.runs_and_hashes(id).is_none()) {
            return Err(SnapMiss::Stale);
        }
        self.runs_verdict(&plan.runs, &plan.taken)
    }

    /// The per-lane part of [`Self::snapshot_verdict`] for `runs` and the
    /// transactions they take (any order).
    fn runs_verdict(
        &self,
        runs: &[(Address, u64, u64)],
        taken: &[Arc<ValidPoolTransaction<T>>],
    ) -> Result<(), SnapMiss> {
        let lanes = &self.lanes;
        let mut moved: Vec<Address> = runs
            .par_iter()
            .with_min_len(1024)
            .filter(|(sender, lo, _)| {
                !lanes.get(sender).is_some_and(|lane| lane.parked.is_none() && lane.head() == Some(*lo))
            })
            .map(|(sender, _, _)| *sender)
            .collect();
        moved.extend(
            taken
                .par_iter()
                .with_min_len(1024)
                .filter(|t| {
                    !lanes
                        .get(&t.sender())
                        .and_then(|lane| lane.by_nonce.get(&t.nonce()))
                        .is_some_and(|held| Arc::ptr_eq(held, t))
                })
                .map(|t| t.sender())
                .collect::<Vec<_>>(),
        );
        if moved.is_empty() {
            return Ok(());
        }
        moved.sort_unstable();
        moved.dedup();
        Err(SnapMiss::Lanes(moved))
    }

    /// Takes a verified plan's runs off their lanes' heads (the lanes'
    /// own `Arc`s are dropped: the plan holds the same allocations), and
    /// returns how many left.
    fn pop_snapshot_runs(&mut self, runs: &[(Address, u64, u64)]) -> usize {
        let mut removed = 0usize;
        for (sender, lo, hi) in runs {
            let Some(lane) = self.lanes.get_mut(sender) else { continue };
            for _ in *lo..*hi {
                if lane.by_nonce.pop_first().is_some() {
                    removed += 1;
                }
            }
            if lane.by_nonce.is_empty() {
                lane.queued = false;
            }
        }
        self.len -= removed;
        self.lanes_gen = self.lanes_gen.wrapping_add(1);
        removed
    }

    /// The part of [`Self::discard_prepared`] for one batch: the mined ones
    /// counted and returned, the rest given back.
    fn discard_batch(&mut self, batch: Vec<Arc<ValidPoolTransaction<T>>>) -> Vec<Arc<ValidPoolTransaction<T>>> {
        let lanes = &self.lanes;
        let (mined, back): (Vec<_>, Vec<_>) =
            batch.into_iter().partition(|t| lanes.get(&t.sender()).is_some_and(|lane| lane.is_stale(t.nonce())));
        for t in &mined {
            self.dropped(Dropped::Mined, t.sender(), t.nonce());
        }
        if !back.is_empty() {
            self.give_back(back);
        }
        mined
    }
}

/// How a committed snapshot plan leaves the lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapCommit {
    /// Popped off the lanes into a [`Prepared`] plan.
    Prepare,
    /// Noted for the build that holds the lanes' current build counter, as
    /// the locked plan notes them ([`Inner::pending`]).
    Note,
}

impl<T: PoolTransaction> TxQueue<T> {
    /// Whether this queue plans from snapshots ([`queue_plan_snapshot`]):
    /// only with the off-lock steps on.
    pub(crate) fn plan_snapshot_on(&self) -> bool {
        self.offlock() && self.plan_snapshot.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The same queue with `N42_QUEUE_PLAN_SNAPSHOT` set to `on` whatever
    /// the environment says.
    #[must_use]
    pub fn with_plan_snapshot(self, on: bool) -> Self {
        self.plan_snapshot.store(on, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Step 2: the lanes `snapshot`'s frames name, read in holds of at most
    /// [`SNAPSHOT_SENDERS`] senders. `false` when a hold found the build
    /// counter moved or a build's takes noted (the snapshot is void).
    pub(crate) fn snapshot_lanes(&self, snapshot: &mut PlanSnapshot<T>) -> bool {
        let wanted = snapshot.wanted();
        snapshot.lanes.reserve(wanted.len());
        for chunk in wanted.chunks(SNAPSHOT_SENDERS) {
            let inner = self.lock_inner_unsettled();
            if inner.builds != snapshot.builds || inner.takes_unsettled() {
                return false;
            }
            let lanes = &inner.lanes;
            let read: Vec<(Address, Option<SnapLane>)> = chunk
                .par_iter()
                .with_min_len(512)
                .map(|(sender, upto)| (*sender, lanes.get(sender).map(|lane| SnapLane::of(lane, *upto))))
                .collect();
            drop(inner);
            for (sender, lane) in read {
                match lane {
                    Some(lane) => {
                        snapshot.lanes.insert(sender, lane);
                    }
                    None => {
                        snapshot.lanes.remove(&sender);
                    }
                }
            }
        }
        true
    }

    /// Steps 2-4 after `snapshot`'s frames were taken: the lanes read, the
    /// plan made off the lock and committed as `how`, re-planned on a miss.
    /// `Ok` with the committed plan (an empty plan commits nothing), `Err`
    /// when the locked path must plan (counted as a fallback).
    pub(crate) fn plan_and_commit(
        &self,
        mut snapshot: PlanSnapshot<T>,
        gas_limit: u64,
        how: SnapCommit,
        at: std::time::Instant,
        body: Option<Arc<Mutex<BodySlot>>>,
    ) -> Result<(SnapPlan<T>, Option<SettleMark>), ()> {
        if !self.snapshot_lanes(&mut snapshot) {
            note_fallback();
            return Err(());
        }
        let mut further = 0usize;
        let mut attempt = 0usize;
        while attempt <= SNAPSHOT_REPLANS {
            let planned = match plan_from_snapshot(&snapshot, gas_limit) {
                SnapPlanned::Plan(planned) => planned,
                SnapPlanned::Further if further < SNAPSHOT_FURTHER => {
                    // Frames the plan passes over used up the margin: the
                    // frames again, reaching further, and the lanes they
                    // add.
                    further += 1;
                    let margin = snapshot.margin.saturating_mul(8);
                    let wider = {
                        let inner = self.lock_inner_quiet();
                        (inner.builds == snapshot.builds).then(|| inner.snapshot_frames_to(gas_limit, margin))
                    };
                    let Some(mut wider) = wider else {
                        note_fallback();
                        return Err(());
                    };
                    wider.want = std::mem::take(&mut snapshot.want);
                    wider.lanes = std::mem::take(&mut snapshot.lanes);
                    snapshot = wider;
                    if !self.snapshot_lanes(&mut snapshot) {
                        note_fallback();
                        return Err(());
                    }
                    continue;
                }
                SnapPlanned::Further | SnapPlanned::Locked => {
                    note_fallback();
                    return Err(());
                }
            };
            attempt += 1;
            if planned.noted.is_empty() {
                return Ok((planned, None));
            }
            let verdict = match how {
                SnapCommit::Note => {
                    let mut inner = self.lock_inner_quiet();
                    let verdict = inner.snapshot_verdict(&planned, snapshot.builds);
                    if verdict.is_ok() {
                        let mark = self.commit_snapshot_plan(&mut inner, &planned, gas_limit, how, at, body);
                        drop(inner);
                        return Ok((planned, mark));
                    }
                    verdict
                }
                SnapCommit::Prepare => {
                    let verdict = self.commit_prepare_batched(&planned, snapshot.builds, gas_limit, at, body.clone());
                    if verdict.is_ok() {
                        return Ok((planned, None));
                    }
                    verdict
                }
            };
            match verdict {
                Ok(()) => unreachable!("committed above"),
                Err(SnapMiss::Lanes(moved)) if attempt <= SNAPSHOT_REPLANS && moved.len() <= SNAPSHOT_SENDERS => {
                    note_miss();
                    let inner = self.lock_inner_quiet();
                    snapshot.refresh(&inner.lanes, &moved);
                }
                Err(miss) => {
                    if matches!(miss, SnapMiss::Lanes(_)) {
                        note_miss();
                    }
                    note_fallback();
                    return Err(());
                }
            }
        }
        note_fallback();
        Err(())
    }

    /// Step 4 for a prepared plan, in holds of at most [`SNAPSHOT_SENDERS`]
    /// senders: each hold checks its senders' lanes (as
    /// [`Inner::snapshot_verdict`] does) and pops their runs, and the last
    /// one stores the plan. A hold that finds the build counter moved, a
    /// plan already stored or one of its lanes moved gives back what the
    /// earlier holds popped and refuses the plan. Between the holds the
    /// popped runs are out of the lanes and not yet in a plan: a build or a
    /// prune meanwhile sees them as taken, as it would a stored plan's, and
    /// the plan is judged at its use ([`Inner::prepared_verdict`]) as ever.
    pub(crate) fn commit_prepare_batched(
        &self,
        planned: &SnapPlan<T>,
        builds: u64,
        gas_limit: u64,
        at: std::time::Instant,
        body: Option<Arc<Mutex<BodySlot>>>,
    ) -> Result<(), SnapMiss> {
        // Off the lock: the takes grouped by run, each run's in nonce order.
        let mut offsets: Vec<usize> = Vec::with_capacity(planned.runs.len() + 1);
        let mut index: AddressHashMap<usize> = AddressHashMap::default();
        offsets.push(0);
        for (k, (sender, lo, hi)) in planned.runs.iter().enumerate() {
            index.insert(*sender, k);
            offsets.push(offsets[k] + (hi - lo) as usize);
        }
        let mut slots: Vec<Option<Arc<ValidPoolTransaction<T>>>> = vec![None; offsets[planned.runs.len()]];
        for t in &planned.taken {
            let Some(&k) = index.get(&t.sender()) else { return Err(SnapMiss::Stale) };
            let at = offsets[k] + (t.nonce() - planned.runs[k].1) as usize;
            slots[at] = Some(Arc::clone(t));
        }
        let Some(grouped) = slots.into_iter().collect::<Option<Vec<_>>>() else { return Err(SnapMiss::Stale) };
        let count = planned.runs.len().div_ceil(SNAPSHOT_SENDERS).max(1);
        for c in 0..count {
            let from = c * SNAPSHOT_SENDERS;
            let to = ((c + 1) * SNAPSHOT_SENDERS).min(planned.runs.len());
            let mut inner = self.lock_inner_quiet();
            let verdict = if inner.builds != builds
                || inner.prepared.is_some()
                || (c == 0 && planned.noted.iter().any(|(id, _)| inner.frames.runs_and_hashes(id).is_none()))
            {
                Err(SnapMiss::Stale)
            } else {
                inner.runs_verdict(&planned.runs[from..to], &grouped[offsets[from]..offsets[to]])
            };
            if let Err(miss) = verdict {
                if from > 0 {
                    inner.give_back(grouped[..offsets[from]].to_vec());
                    inner.lanes_gen = inner.lanes_gen.wrapping_add(1);
                }
                return Err(miss);
            }
            inner.pop_snapshot_runs(&planned.runs[from..to]);
            if c + 1 == count {
                self.commit_snapshot_plan(&mut inner, planned, gas_limit, SnapCommit::Prepare, at, body.clone());
            }
        }
        Ok(())
    }

    /// Step 4's apply, under the commit hold, after the verdict passed.
    pub(crate) fn commit_snapshot_plan(
        &self,
        inner: &mut Inner<T>,
        planned: &SnapPlan<T>,
        gas_limit: u64,
        how: SnapCommit,
        at: std::time::Instant,
        body: Option<Arc<Mutex<BodySlot>>>,
    ) -> Option<SettleMark> {
        match how {
            SnapCommit::Note => {
                for (id, prefix) in &planned.noted {
                    inner.len -= prefix;
                    inner.pending.push((*id, *prefix));
                }
                Some(SettleMark {
                    build: inner.builds,
                    count: inner.pending.len(),
                    first: inner.pending[0].0,
                    last: inner.pending[inner.pending.len() - 1].0,
                })
            }
            SnapCommit::Prepare => {
                // The runs were popped by the holds of
                // `commit_prepare_batched`, the last of them this one.
                let lowest: AddressHashMap<u64> = planned.runs.iter().map(|(sender, lo, _)| (*sender, *lo)).collect();
                let cut = planned.plan.frames.last().is_some_and(|frame| frame.taken < frame.len);
                inner.prepared = Some(Prepared {
                    after: inner.builds,
                    gas_used: gas_limit.saturating_sub(planned.gas_left),
                    cut,
                    segments: planned.segments.clone(),
                    plan: planned.plan.clone(),
                    taken: planned.taken.clone(),
                    lowest,
                    made_at: std::time::Instant::now(),
                    prep_us: at.elapsed().as_micros() as u64,
                    body,
                });
                None
            }
        }
    }

    /// The plan-ahead preparation from a snapshot: the inbox drained, a
    /// plan nobody used given back and the frames snapshotted in one short
    /// hold, then [`Self::plan_and_commit`]. `None` when the locked path
    /// must prepare.
    pub(crate) fn prepare_next_snapshot(&self, gas_limit: u64) -> Option<bool> {
        let at = std::time::Instant::now();
        let hook = self.ahead_hook.lock().clone();
        let mut snapshot = {
            let mut inner = self.lock_inner_quiet();
            self.drain_inbox(&mut inner);
            let unused = inner.prepared.take();
            match unused {
                None => Ok(inner.snapshot_frames(gas_limit)),
                Some(unused) => {
                    inner.lanes_gen = inner.lanes_gen.wrapping_add(1);
                    note_ahead_discard(AheadDiscard::OtherBuild);
                    Err(unused)
                }
            }
        };
        if let Err(unused) = snapshot {
            // Given back before the frames are read: a frame whose
            // transactions are out of the lanes is passed over unread.
            PruneGarbage { taken: self.give_back_batched(unused.taken), ..Default::default() }.free();
            snapshot = Ok(self.lock_inner_quiet().snapshot_frames(gas_limit));
        }
        let Ok(snapshot) = snapshot else { return None };
        let slot = hook.as_ref().map(|_| Arc::new(Mutex::new(BodySlot::default())));
        let (planned, _) =
            self.plan_and_commit(snapshot, gas_limit, SnapCommit::Prepare, at, slot.clone()).ok()?;
        if planned.noted.is_empty() {
            return Some(false);
        }
        // The body, made off the lock into the stored plan's slot.
        Self::run_body_hook(hook, slot.map(|slot| (planned.segments, slot)));
        Some(true)
    }

    /// Gives `taken` (a discarded prepared plan's transactions) back to the
    /// lanes in holds of at most [`GIVE_BACK_BATCH`], as one give-back
    /// would: grouped by sender in the order the one-hold give-back first
    /// meets them, never splitting a sender, and the groups returned last to
    /// first so the senders come out at the front of the arrival order in
    /// that same order. Returns the ones the chain has mined, for the caller
    /// to free after the lock.
    pub(crate) fn give_back_batched(&self, taken: Vec<Arc<ValidPoolTransaction<T>>>) -> Vec<Arc<ValidPoolTransaction<T>>> {
        let mut first_seen: AddressHashMap<u32> = AddressHashMap::default();
        for t in &taken {
            let next = first_seen.len() as u32;
            first_seen.entry(t.sender()).or_insert(next);
        }
        let mut keyed: Vec<(u32, Arc<ValidPoolTransaction<T>>)> =
            taken.into_iter().map(|t| (first_seen[&t.sender()], t)).collect();
        // Stable: a sender's own transactions keep their order.
        keyed.sort_by_key(|(key, _)| *key);
        let mut batches: Vec<Vec<Arc<ValidPoolTransaction<T>>>> = Vec::new();
        let mut current: Vec<Arc<ValidPoolTransaction<T>>> = Vec::new();
        let mut last_key = None;
        for (key, t) in keyed {
            if current.len() >= GIVE_BACK_BATCH && last_key != Some(key) {
                batches.push(std::mem::take(&mut current));
            }
            last_key = Some(key);
            current.push(t);
        }
        if !current.is_empty() {
            batches.push(current);
        }
        let mut mined = Vec::new();
        for batch in batches.into_iter().rev() {
            let mut inner = self.lock_inner();
            mined.extend(inner.discard_batch(batch));
        }
        mined
    }

    /// [`Self::frames_for_build_ahead`] with the plan made from a snapshot
    /// (`N42_QUEUE_PLAN_SNAPSHOT`): the first hold drains the inbox, judges
    /// the prepared plan, opens the build and snapshots the frames; an
    /// unusable prepared plan goes back in batches; the fresh plan, or the
    /// top-up of a usable prepared plan, is made off the lock and noted in
    /// a short commit hold, falling back to planning under one hold.
    pub(crate) fn frames_for_build_snapshot(
        &self,
        parent: B256,
        gas_limit: u64,
        ahead: bool,
    ) -> (QueueBest<T>, FramePlan, FrameSelectTimes) {
        let mode = SelectMode::Parallel;
        let mut times = FrameSelectTimes::default();
        let at = std::time::Instant::now();
        let mut prepared_body: Option<Arc<Mutex<BodySlot>>> = None;
        // (segments, plan so far, the snapshot for the rest and its gas,
        // a discarded plan's transactions)
        let (mut segments, mut plan, rest, discarded) = {
            let mut inner = self.lock_inner();
            times.lock_us = at.elapsed().as_micros() as u64;
            let begin_at = std::time::Instant::now();
            self.drain_inbox(&mut inner);
            let verdict =
                inner.prepared.as_ref().map(|prepared| inner.prepared_verdict_in(prepared, parent, gas_limit, true));
            match (verdict, inner.prepared.take()) {
                (Some(Ok(())), Some(prepared)) => {
                    let Prepared { gas_used, cut, segments, plan, taken, made_at, prep_us, body, .. } = prepared;
                    prepared_body = body;
                    times.ahead = 1;
                    times.ahead_age_us = made_at.elapsed().as_micros() as u64;
                    times.ahead_prep_us = prep_us;
                    inner.open_build(parent, taken);
                    let room = gas_limit.saturating_sub(gas_used);
                    let rest = (!cut && room >= MIN_FRAME_TX_GAS).then(|| (Some(inner.snapshot_frames(room)), room));
                    times.begin_us = begin_at.elapsed().as_micros() as u64;
                    (segments, plan, rest, None)
                }
                (verdict, prepared) => {
                    let discarded = prepared.map(|prepared| {
                        let reason = match verdict {
                            Some(Err(reason)) => reason,
                            _ => AheadDiscard::OtherBuild,
                        };
                        times.ahead_discard = Some(reason);
                        note_ahead_discard(reason);
                        prepared.taken
                    });
                    self.begin_build(&mut inner, parent);
                    times.begin_us = begin_at.elapsed().as_micros() as u64;
                    // With a plan to give back first, the frames are read
                    // after it (a frame whose transactions are out of the
                    // lanes is passed over unread).
                    let rest = discarded.is_none().then(|| inner.snapshot_frames(gas_limit));
                    (Vec::new(), FramePlan::default(), Some((rest, gas_limit)), discarded)
                }
            }
        };
        let topup = times.ahead == 1;
        let mut garbage = PruneGarbage::default();
        let mut mark = None;
        if let Some((snapshot, room)) = rest {
            let plan_at = std::time::Instant::now();
            if let Some(discarded) = discarded {
                garbage.taken = self.give_back_batched(discarded);
            }
            let snapshot = match snapshot {
                Some(snapshot) => snapshot,
                None => self.lock_inner_quiet().snapshot_frames(room),
            };
            let builds = snapshot.builds;
            let (more, more_plan, more_mark) = match self.plan_and_commit(snapshot, room, SnapCommit::Note, at, None) {
                Ok((planned, more_mark)) => {
                    times.check_us = planned.times.check_us;
                    times.by_ref = planned.times.by_ref;
                    times.counted = planned.times.counted;
                    (planned.segments, planned.plan, more_mark)
                }
                Err(()) => {
                    // The locked path, for the build that is still this one.
                    let mut inner = self.lock_inner();
                    if inner.builds == builds {
                        let mut more_times = FrameSelectTimes::default();
                        let (more, more_plan, _) = inner.plan_frames(room, &mut more_times, mode);
                        times.check_us = more_times.check_us;
                        times.settle_us = more_times.settle_us;
                        times.by_ref = more_times.by_ref;
                        times.slow = more_times.slow;
                        times.counted = more_times.counted;
                        let more_mark = (!inner.pending.is_empty()).then(|| SettleMark {
                            build: inner.builds,
                            count: inner.pending.len(),
                            first: inner.pending[0].0,
                            last: inner.pending[inner.pending.len() - 1].0,
                        });
                        (more, more_plan, more_mark)
                    } else {
                        (Vec::new(), FramePlan::default(), None)
                    }
                }
            };
            times.plan_us = plan_at.elapsed().as_micros() as u64;
            mark = more_mark;
            if topup {
                if !more_plan.frames.is_empty() {
                    prepared_body = None;
                    times.ahead = 2;
                    times.ahead_topup_txs = more_plan.tx_count();
                    segments.extend(more);
                    plan.frames.extend(more_plan.frames);
                    plan.parts.extend(more_plan.parts);
                }
                plan.skipped += more_plan.skipped;
            } else {
                segments = more;
                plan = more_plan;
            }
        }
        garbage.free();
        self.finish_frame_build(segments, plan, times, mark, prepared_body, gas_limit, mode, ahead)
    }
}

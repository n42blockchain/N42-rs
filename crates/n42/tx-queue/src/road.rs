// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The frame road (`docs/FRAME_ROAD_DESIGN.md`): attested, nonce-aligned
//! frames admitted whole beside the lanes, off the lanes' lock.
//!
//! At 4.5M transactions a second the lanes' lock is 85-98% busy, and about
//! 0.2 us of its work is per transaction: the drain's insert into a lane
//! (`drain_grouped`, ~95 ns) and the plan's check of every frame against its
//! lanes (`offlock_plan`, ~50 ns). On E=1 every block is built by this
//! queue's own builder and the flood's frames are aligned, so a frame can
//! be checked once per sender here instead: a sharded per-sender map of the
//! next nonce the road expects ([`RoadSender`]), advanced for every member
//! of a frame that is admitted.
//!
//! `N42_FRAME_ROAD=count` is stage 0 of the design: admission and seeding
//! run and are counted ([`RoadStats`]), and every frame still goes the
//! lanes' path, so nothing a build sees changes.
//!
//! `N42_FRAME_ROAD=1` is stage 1: an admitted frame does not enter the
//! lanes. It waits in the road's FIFO ([`RoadFrame`]) until a frame plan
//! takes it whole, first, while no transaction of a road sender is in the
//! lanes (the gate, invariant R1); it is then remembered as taken until the
//! chain mines it ([`Road::retire`]) or a give-back hands it back whole to
//! the FIFO, in its order ([`Road::hand_back`]). Anything else that would
//! put a road sender's transaction in the lanes invalidates the road
//! ([`Road::invalidate`]): its queued frames go to the lanes, its map is
//! cleared, and its senders seed again.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use alloy_primitives::{map::{AddressHashMap, B256HashMap}, Address, B256};
use parking_lot::{Mutex, MutexGuard};
use reth_transaction_pool::{PoolTransaction, ValidPoolTransaction};

use crate::{FrameTxs, NewFrame};

/// Shards of the road's per-sender map. A 500-member frame of distinct
/// senders touches nearly all of them, so this bounds the contention of
/// the seeding hold against admissions, not of admissions among
/// themselves.
pub(crate) const ROAD_SHARDS: usize = 64;

/// What `N42_FRAME_ROAD` asks of the queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RoadMode {
    /// No road: the queue as it always was.
    Off = 0,
    /// Stage 0: admission and seeding counted, every frame still goes the
    /// lanes' path.
    Count = 1,
    /// Stage 1: admitted frames bypass the lanes and are taken by the frame
    /// plan first.
    On = 2,
}

impl RoadMode {
    const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Count,
            2 => Self::On,
            _ => Self::Off,
        }
    }
}

/// `N42_FRAME_ROAD`, read once: `1` is the road (stage 1), `count` counts
/// only (stage 0), anything else is off.
pub(crate) fn road_mode_env() -> RoadMode {
    static MODE: OnceLock<RoadMode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("N42_FRAME_ROAD").as_deref() {
        Ok("1") => RoadMode::On,
        Ok("count") => RoadMode::Count,
        _ => RoadMode::Off,
    })
}

/// A frame on the road: admitted whole, its transactions in frame order.
pub(crate) struct RoadFrame<T: PoolTransaction> {
    /// Admission order: the FIFO is sorted by it, and a hand-back goes back
    /// to its place.
    pub(crate) seq: u64,
    /// [`Road::epoch`] at admission: a frame taken before an invalidation
    /// and handed back after it goes the lanes' path.
    pub(crate) epoch: u64,
    /// The road's own-block hold count when a frame plan took the frame
    /// ([`Road::note_hold`]); 0 while it is queued.
    pub(crate) taken_at: u64,
    pub(crate) id: B256,
    pub(crate) hashes: Arc<[B256]>,
    pub(crate) members: Arc<[(Address, u64)]>,
    pub(crate) gas: u64,
    pub(crate) txs: FrameTxs<T>,
}

impl<T: PoolTransaction> Clone for RoadFrame<T> {
    fn clone(&self) -> Self {
        Self {
            seq: self.seq,
            epoch: self.epoch,
            taken_at: self.taken_at,
            id: self.id,
            hashes: Arc::clone(&self.hashes),
            members: Arc::clone(&self.members),
            gas: self.gas,
            txs: Arc::clone(&self.txs),
        }
    }
}

impl<T: PoolTransaction> RoadFrame<T> {
    /// A frame for the queue of the road, from the ingest's record.
    pub(crate) fn of(frame: &NewFrame, txs: FrameTxs<T>) -> Self {
        Self {
            seq: 0,
            epoch: 0,
            taken_at: 0,
            id: frame.id,
            hashes: Arc::from(frame.hashes.as_slice()),
            members: Arc::from(frame.members.as_slice()),
            gas: frame.gas,
            txs,
        }
    }

    /// The ingest's record again, for the frame index (a frame leaving the
    /// road for the lanes).
    pub(crate) fn new_frame(&self) -> NewFrame {
        NewFrame { id: self.id, hashes: self.hashes.to_vec(), members: self.members.to_vec(), gas: self.gas }
    }

    pub(crate) fn len(&self) -> usize {
        self.txs.len()
    }

    fn first_ptr(&self) -> Option<usize> {
        self.txs.first().map(|first| Arc::as_ptr(first) as usize)
    }
}

/// The frames builds took off the road and the chain has not yet mined:
/// what a give-back is recognised against, by the pointer of a frame's
/// first transaction, and what [`crate::TxQueue::take_frames`] finds by id.
struct RoadTaken<T: PoolTransaction> {
    by_id: B256HashMap<RoadFrame<T>>,
    by_ptr: HashMap<usize, B256>,
    /// Ids in take order with the hold count they were taken at, for the
    /// bounds; an id already retired (or taken again since) is skipped.
    order: VecDeque<(B256, u64)>,
    /// `N42_ROAD_RETIRE_INDEX=1`: the ids by their first member's sender,
    /// what [`Road::retire`] looks up instead of scanning `by_id`. Empty
    /// while `indexed` is off.
    by_sender: AddressHashMap<Vec<B256>>,
    indexed: bool,
}

impl<T: PoolTransaction> Default for RoadTaken<T> {
    fn default() -> Self {
        Self {
            by_id: B256HashMap::default(),
            by_ptr: HashMap::new(),
            order: VecDeque::new(),
            by_sender: AddressHashMap::default(),
            indexed: false,
        }
    }
}

impl<T: PoolTransaction> RoadTaken<T> {
    fn insert(&mut self, frame: RoadFrame<T>) {
        let id = frame.id;
        if let Some(ptr) = frame.first_ptr() {
            self.by_ptr.insert(ptr, id);
        }
        self.order.push_back((id, frame.taken_at));
        let first = frame.members.first().map(|(sender, _)| *sender);
        let replaced = self.by_id.insert(id, frame);
        if self.indexed {
            if let Some((sender, _)) = replaced.as_ref().and_then(|old| old.members.first()) {
                let sender = *sender;
                self.unindex(&sender, &id);
            }
            if let Some(sender) = first {
                self.by_sender.entry(sender).or_default().push(id);
            }
        }
    }

    fn remove(&mut self, id: &B256) -> Option<RoadFrame<T>> {
        let frame = self.by_id.remove(id)?;
        if let Some(ptr) = frame.first_ptr() {
            self.by_ptr.remove(&ptr);
        }
        if self.indexed
            && let Some((sender, _)) = frame.members.first()
        {
            self.unindex(sender, id);
        }
        Some(frame)
    }

    fn unindex(&mut self, sender: &Address, id: &B256) {
        if let Some(ids) = self.by_sender.get_mut(sender) {
            if let Some(at) = ids.iter().position(|known| known == id) {
                ids.swap_remove(at);
            }
            if ids.is_empty() {
                self.by_sender.remove(sender);
            }
        }
    }

    /// Turns the sender index on or off, rebuilding it from `by_id`.
    fn set_indexed(&mut self, on: bool) {
        self.indexed = on;
        self.by_sender.clear();
        if on {
            let RoadTaken { by_id, by_sender, .. } = self;
            for (id, frame) in by_id.iter() {
                if let Some((sender, _)) = frame.members.first() {
                    by_sender.entry(*sender).or_default().push(*id);
                }
            }
        }
    }

    /// The ids whose first member `highest` mined, by a scan of every
    /// taken frame (the default) or through the sender index.
    fn mined(&self, highest: &AddressHashMap<u64>) -> Vec<B256> {
        let first_mined = |frame: &RoadFrame<T>| {
            frame.members.first().is_some_and(|(sender, nonce)| highest.get(sender).is_some_and(|m| m >= nonce))
        };
        if !self.indexed {
            return self.by_id.iter().filter(|(_, frame)| first_mined(frame)).map(|(id, _)| *id).collect();
        }
        let mut ids = Vec::new();
        let mut take = |list: &Vec<B256>| {
            ids.extend(list.iter().filter(|id| self.by_id.get(*id).is_some_and(first_mined)).copied());
        };
        // Whichever side is smaller is walked; the other is looked up.
        if self.by_sender.len() <= highest.len() {
            for (sender, list) in &self.by_sender {
                if highest.contains_key(sender) {
                    take(list);
                }
            }
        } else {
            for sender in highest.keys() {
                if let Some(list) = self.by_sender.get(sender) {
                    take(list);
                }
            }
        }
        ids
    }
}

/// `N42_ROAD_TAKEN_BOUND=1` (off by default): a taken frame is forgotten
/// once the own-block hold window has passed it ([`Road::note_hold`]).
fn road_taken_bound_env() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_ROAD_TAKEN_BOUND", false))
}

/// `N42_ROAD_RETIRE_INDEX=1` (off by default): [`Road::retire`] finds the
/// mined frames through an index of the taken frames by first-member
/// sender instead of scanning every taken frame.
fn road_retire_index_env() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_ROAD_RETIRE_INDEX", false))
}

/// Own blocks the bound waits past the hold window: a frame is taken before
/// its block is held, and up to the blocks in flight (`N42_FAR_AHEAD_BLOCKS`,
/// at most 8) may be held in between, so a frame is older than `hold + 8`
/// holds only when its block (if it was ever held) has left the window.
pub(crate) const ROAD_TAKEN_BOUND_SLACK: u64 = 8;

/// Senders whose oversize frame was logged; past this many the warning
/// stops (the counter keeps counting).
const OVERSIZE_WARNED_MAX: usize = 65_536;

/// The most taken frames the road remembers (~65M transactions of 500-frames,
/// far past what a held window of own blocks takes). Past it the oldest is
/// forgotten: a give-back of it is then not recognised, and goes the lanes'
/// path with an invalidation, which is correct, only slower.
const ROAD_TAKEN_MAX: usize = 131_072;

/// `N42_ROAD_TAKEN_MAX=<frames>`: the bound above, for the stage that
/// measures what the remembered frames cost in memory (at the default, a
/// map at its bound holds ~65M transactions).
fn road_taken_max() -> usize {
    static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("N42_ROAD_TAKEN_MAX").ok().and_then(|v| v.trim().parse().ok()).filter(|&n| n > 0).unwrap_or(ROAD_TAKEN_MAX)
    })
}

/// One sender as the road knows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RoadSender {
    /// The nonce the sender's next admitted member must carry.
    pub(crate) next: u64,
    /// Whether a frame naming this sender was admitted since it joined:
    /// from then on a transaction of it that goes the lanes' path could be
    /// taken ahead of its road frames, so the road is flushed instead
    /// ([`Road::invalidate`]).
    pub(crate) on_road: bool,
    /// The admission attempt that last touched it: a frame naming a sender
    /// twice needs consecutive nonces, and this tells the duplicate from a
    /// gap.
    pub(crate) stamp: u64,
}

/// `N42_ROAD_RESEED_AT_FLUSH=1` (off by default): a flush seeds again, at
/// once, every sender the road knew: from its lane's tail where the lane
/// holds anything (the flushed frames among it), else at the `next` it had
/// (everything below it is in a build's take or mined). Seeding is otherwise lazy, at the sender's next frame. By then a
/// build has usually taken the lane empty, and a sender with an empty
/// lane cannot be seeded. At 5M/s every sender is then refused for the
/// rest of the leg, and the road stays shut (10.206: `seeded` 0 and
/// `refused_unknown` ~40,000 per 5 s after the one flush).
fn reseed_at_flush() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ROAD_RESEED_AT_FLUSH").is_ok_and(|v| v.trim() == "1"))
}

/// `N42_ROAD_STUCK_LEGACY=1` (off by default): the stuck flush fires on the
/// first rule -- the gate shut with the debt not lower over
/// `ROAD_STUCK_BUILDS` builds -- with no progress test and no cool-down.
/// That rule flushed every ~8 builds at full load while the debt of the
/// previous flush was being taken (loop351 stage eu, leg LP2MEMF: six
/// flushes per 5 s, every one putting the frames admitted meanwhile back
/// in the lanes, so the gate never reopened).
pub(crate) fn road_stuck_legacy() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ROAD_STUCK_LEGACY").is_ok_and(|v| v.trim() == "1"))
}

/// `N42_ROAD_DEBT_SWEEP=0` turns it off (on by default; off under
/// `N42_ROAD_STUCK_LEGACY=1`): a frame build whose plan came back empty,
/// with frames on the road, nothing in the frame index and the gate shut by
/// lane debt no frame plan can take (a road sender's frameless lane entry, a
/// frame's tail), takes that debt as plain transactions -- only the debt
/// senders' lanes, in nonce order, up to the block's gas -- instead of
/// taking nothing until a stuck flush invalidates the road. Each such flush
/// brought the same untakeable debt back with the whole road behind it, a
/// flush loop at the cool-down's period (loop351 leg LR1b: 97 stuck
/// flushes, ~147k-transaction blocks).
fn road_debt_sweep_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_ROAD_DEBT_SWEEP", true))
}

/// Why the road was invalidated (the flush's log line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlushReason {
    /// A frame was refused with a member already on the road.
    Refused,
    /// An on-road sender's transactions arrived without a frame.
    Frameless,
    /// A give-back brought an on-road sender's transactions to the lanes.
    GiveBack,
    /// A build walks the lanes, which never takes the road's frames.
    Walk,
    /// The gate stayed shut on debt no build was taking.
    Stuck,
}

/// Why a frame was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A member's sender could not be seeded (its lane is empty but known:
    /// what it has in flight is not visible to the queue).
    Unknown = 0,
    /// A member's nonce is not the one its sender's next frame must carry.
    Gap = 1,
    /// No frame record, or transactions that do not match it.
    NoFrame = 2,
    /// A sender named twice without consecutive nonces.
    DupSender = 3,
    /// The frame's gas exceeds the block gas limit: no block can carry it,
    /// and at the FIFO's front it would stop every frame behind it.
    Oversize = 4,
}

/// What [`Road::admit`] decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Every member aligned: the senders advanced.
    Admitted,
    /// These (sender, first nonce in the frame) are unknown to the road:
    /// seed them and ask again. Nothing was changed.
    Seed(Vec<(Address, u64)>),
    /// Refused; with `flush` a member's sender was on the road, so the
    /// road has to be invalidated before the frame goes the lanes' path.
    Refused { reason: Refusal, flush: bool },
}

/// The road's counters: per queue (what the tests read) and registered
/// process-wide for the ingest's 5 s line ([`road_stats`]).
#[derive(Debug, Default)]
pub(crate) struct RoadCounters {
    pub(crate) frames: AtomicU64,
    pub(crate) txs: AtomicU64,
    pub(crate) refused: [AtomicU64; 5],
    pub(crate) flushes: AtomicU64,
    pub(crate) flushes_stuck: AtomicU64,
    pub(crate) debt_sweeps: AtomicU64,
    pub(crate) seeded: AtomicU64,
    pub(crate) seed_holds: AtomicU64,
    pub(crate) len_txs: AtomicU64,
    pub(crate) lane_debt: AtomicU64,
    pub(crate) taken: AtomicU64,
    pub(crate) handed_back: AtomicU64,
    pub(crate) retired: AtomicU64,
    pub(crate) evicted: AtomicU64,
    pub(crate) bounded: AtomicU64,
    pub(crate) taken_frames: AtomicU64,
}

/// The road's counters as read ([`road_stats`], [`crate::TxQueue::road_stats`]):
/// running totals since the queue was made, and the gauges as they stand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoadStats {
    /// Frames admitted whole.
    pub frames: u64,
    /// Their transactions.
    pub txs: u64,
    /// Frames refused because a sender could not be seeded.
    pub refused_unknown: u64,
    /// Frames refused because a member's nonce was not its sender's next.
    pub refused_gap: u64,
    /// Frames without a record or with transactions that do not match it.
    pub refused_no_frame: u64,
    /// Frames naming a sender twice without consecutive nonces.
    pub refused_dup_sender: u64,
    /// Frames whose gas exceeds the block gas limit
    /// (`n42_road_oversize_frames_total`).
    pub refused_oversize: u64,
    /// Times the road was invalidated: its map cleared (and its queued
    /// frames moved to the lanes' path).
    pub flushes: u64,
    /// Of those, the flushes of a gate stuck on debt no build was taking.
    pub flushes_stuck: u64,
    /// Builds that swept the road senders' lane debt as plain transactions
    /// (`N42_ROAD_DEBT_SWEEP`), instead of a stuck flush.
    pub debt_sweeps: u64,
    /// Senders that joined the road.
    pub seeded: u64,
    /// Holds of the lanes' lock the seeding took.
    pub seed_holds: u64,
    /// Transactions queued on the road (a gauge).
    pub len_txs: u64,
    /// Transactions of road senders still in the lanes, as last counted (a
    /// gauge).
    pub lane_debt: u64,
    /// Frames frame plans took off the road.
    pub taken: u64,
    /// Taken frames a give-back put back on the road.
    pub handed_back: u64,
    /// Taken frames the chain mined.
    pub retired: u64,
    /// Taken frames forgotten at the bound (`ROAD_TAKEN_MAX`) before the
    /// chain mined them.
    pub evicted: u64,
    /// Taken frames forgotten by the hold-window bound
    /// (`N42_ROAD_TAKEN_BOUND`).
    pub bounded: u64,
    /// Taken frames the road remembers now (a gauge,
    /// `n42_road_taken_frames`).
    pub taken_frames: u64,
}

impl RoadCounters {
    pub(crate) fn read(&self) -> RoadStats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        RoadStats {
            frames: get(&self.frames),
            txs: get(&self.txs),
            refused_unknown: get(&self.refused[Refusal::Unknown as usize]),
            refused_gap: get(&self.refused[Refusal::Gap as usize]),
            refused_no_frame: get(&self.refused[Refusal::NoFrame as usize]),
            refused_dup_sender: get(&self.refused[Refusal::DupSender as usize]),
            refused_oversize: get(&self.refused[Refusal::Oversize as usize]),
            flushes: get(&self.flushes),
            flushes_stuck: get(&self.flushes_stuck),
            debt_sweeps: get(&self.debt_sweeps),
            seeded: get(&self.seeded),
            seed_holds: get(&self.seed_holds),
            len_txs: get(&self.len_txs),
            lane_debt: get(&self.lane_debt),
            taken: get(&self.taken),
            handed_back: get(&self.handed_back),
            retired: get(&self.retired),
            evicted: get(&self.evicted),
            bounded: get(&self.bounded),
            taken_frames: get(&self.taken_frames),
        }
    }
}

/// The counters of the last road a production queue made ([`crate::TxQueue::new`]).
static REGISTERED: Mutex<Option<Arc<RoadCounters>>> = Mutex::new(None);

/// The road's counters of this process's queue, `None` when its road is
/// off: what the ingest's 5 s line reports.
pub fn road_stats() -> Option<RoadStats> {
    REGISTERED.lock().as_ref().map(|counters| counters.read())
}

pub(crate) fn register(counters: &Arc<RoadCounters>) {
    *REGISTERED.lock() = Some(Arc::clone(counters));
}

fn shard_of(sender: &Address) -> usize {
    let bytes = sender.as_slice();
    let mut head = [0u8; 8];
    head.copy_from_slice(&bytes[..8]);
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&bytes[12..20]);
    let mixed = (u64::from_be_bytes(head) ^ u64::from_be_bytes(tail)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (mixed >> 58) as usize % ROAD_SHARDS
}

/// The shards a set of senders lives in, as a bit mask.
fn mask_of<'a>(senders: impl IntoIterator<Item = &'a Address>) -> u64 {
    senders.into_iter().fold(0u64, |mask, sender| mask | (1u64 << shard_of(sender)))
}

/// The road's shared state. Lock order: the lanes' lock, then shards
/// (ascending), then the FIFO or the taken frames; the FIFO and the taken
/// frames are leaves.
pub(crate) struct Road<T: PoolTransaction> {
    mode: AtomicU8,
    shards: Box<[Mutex<AddressHashMap<RoadSender>>]>,
    /// Admission attempts, for [`RoadSender::stamp`].
    stamps: AtomicU64,
    /// Raised by every invalidation, which holds every shard.
    epoch: AtomicU64,
    /// Admitted frames not yet taken, in admission order.
    fifo: Mutex<VecDeque<RoadFrame<T>>>,
    next_seq: AtomicU64,
    taken: Mutex<RoadTaken<T>>,
    pub(crate) counters: Arc<RoadCounters>,
    /// [`reseed_at_flush`], read at construction (tests set it).
    reseed: std::sync::atomic::AtomicBool,
    /// [`road_debt_sweep_env`], read at construction (tests set it).
    debt_sweep: std::sync::atomic::AtomicBool,
    /// Own blocks held so far ([`Self::note_hold`]): the clock of the
    /// taken frames' bound.
    holds: AtomicU64,
    /// [`road_taken_bound_env`], read at construction (tests set it).
    taken_bound: std::sync::atomic::AtomicBool,
    /// The block gas limit of the latest frame build (0 before the first):
    /// a frame above it is refused ([`Refusal::Oversize`]).
    gas_limit: AtomicU64,
    /// First-member senders whose oversize frame was logged.
    oversize_warned: Mutex<alloy_primitives::map::AddressHashSet>,
}

/// Guards of the shards a frame touches, locked in ascending order (so two
/// frames never wait for each other's shards in a cycle).
pub(crate) struct ShardGuards<'a> {
    guards: Vec<Option<MutexGuard<'a, AddressHashMap<RoadSender>>>>,
}

impl ShardGuards<'_> {
    pub(crate) fn get(&self, sender: &Address) -> Option<&RoadSender> {
        self.guards[shard_of(sender)].as_ref().and_then(|shard| shard.get(sender))
    }

    pub(crate) fn get_mut(&mut self, sender: &Address) -> Option<&mut RoadSender> {
        self.guards[shard_of(sender)].as_mut().and_then(|shard| shard.get_mut(sender))
    }

    pub(crate) fn insert(&mut self, sender: Address, entry: RoadSender) {
        if let Some(shard) = self.guards[shard_of(&sender)].as_mut() {
            shard.insert(sender, entry);
        }
    }
}

impl<T: PoolTransaction> Road<T> {
    pub(crate) fn new(mode: RoadMode) -> Self {
        Self {
            mode: AtomicU8::new(mode as u8),
            shards: (0..ROAD_SHARDS).map(|_| Mutex::new(AddressHashMap::default())).collect(),
            stamps: AtomicU64::new(0),
            epoch: AtomicU64::new(1),
            fifo: Mutex::new(VecDeque::new()),
            next_seq: AtomicU64::new(0),
            taken: Mutex::new({
                let mut taken = RoadTaken::default();
                taken.set_indexed(road_retire_index_env());
                taken
            }),
            counters: Arc::new(RoadCounters::default()),
            reseed: std::sync::atomic::AtomicBool::new(reseed_at_flush()),
            debt_sweep: std::sync::atomic::AtomicBool::new(road_debt_sweep_env() && !road_stuck_legacy()),
            holds: AtomicU64::new(0),
            taken_bound: std::sync::atomic::AtomicBool::new(road_taken_bound_env()),
            gas_limit: AtomicU64::new(0),
            oversize_warned: Mutex::new(Default::default()),
        }
    }

    /// Sets the hold-window bound of the taken frames (tests).
    #[cfg(test)]
    pub(crate) fn set_taken_bound(&self, on: bool) {
        self.taken_bound.store(on, Ordering::Relaxed);
    }

    /// Sets the sender index of [`Self::retire`] (tests); rebuilt from the
    /// frames taken so far.
    #[cfg(test)]
    pub(crate) fn set_retire_index(&self, on: bool) {
        self.taken.lock().set_indexed(on);
    }

    /// The block gas limit a frame build was asked for: what admission
    /// refuses an oversize frame against.
    pub(crate) fn note_gas_limit(&self, gas_limit: u64) {
        if self.gas_limit.load(Ordering::Relaxed) != gas_limit {
            self.gas_limit.store(gas_limit, Ordering::Relaxed);
        }
    }

    /// Logs an oversize frame once per first-member sender.
    pub(crate) fn warn_oversize(&self, frame: &NewFrame) {
        let Some((sender, nonce)) = frame.members.first() else { return };
        let first = {
            let mut warned = self.oversize_warned.lock();
            warned.len() < OVERSIZE_WARNED_MAX && warned.insert(*sender)
        };
        if first {
            tracing::warn!(
                target: "n42.tx_queue",
                %sender,
                nonce,
                gas = frame.gas,
                gas_limit = self.gas_limit.load(Ordering::Relaxed),
                txs = frame.members.len(),
                "a frame above the block gas limit was refused by the road; it goes the lanes' path"
            );
        }
    }

    /// An own block was held ([`crate::TxQueue::hold_own_block`]): the
    /// clock of the taken frames' bound advances, and with
    /// `N42_ROAD_TAKEN_BOUND=1` every frame taken more than `hold +`
    /// [`ROAD_TAKEN_BOUND_SLACK`] holds ago that is still remembered (not
    /// retired, not handed back) is forgotten. Its block, if it was ever
    /// held, has left the window by then -- settled or evicted with its
    /// transactions lost to the queue -- so the frame can no longer be
    /// handed back whole; a later give-back of it goes the lanes' path with
    /// an invalidation, as after [`ROAD_TAKEN_MAX`]. Returns the forgotten
    /// frames, to be dropped after the caller's locks.
    pub(crate) fn note_hold(&self, hold: usize) -> Vec<RoadFrame<T>> {
        let now = self.holds.fetch_add(1, Ordering::AcqRel) + 1;
        if !self.taken_bound.load(Ordering::Relaxed) {
            return Vec::new();
        }
        self.bound_taken(now, hold as u64)
    }

    fn bound_taken(&self, now: u64, hold: u64) -> Vec<RoadFrame<T>> {
        let window = hold.saturating_add(ROAD_TAKEN_BOUND_SLACK);
        let mut out = Vec::new();
        let mut taken = self.taken.lock();
        while let Some(&(id, at)) = taken.order.front() {
            if now.saturating_sub(at) <= window {
                break;
            }
            taken.order.pop_front();
            // Only the take this entry records: a frame handed back and
            // taken again since has a younger entry behind it.
            if taken.by_id.get(&id).is_some_and(|frame| frame.taken_at == at)
                && let Some(frame) = taken.remove(&id)
            {
                out.push(frame);
            }
        }
        self.counters.taken_frames.store(taken.by_id.len() as u64, Ordering::Relaxed);
        drop(taken);
        self.counters.bounded.fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }

    /// Whether a frame build may sweep the lane debt ([`road_debt_sweep_env`]).
    pub(crate) fn debt_sweep(&self) -> bool {
        self.debt_sweep.load(Ordering::Relaxed)
    }

    /// Sets [`Self::debt_sweep`] (tests).
    #[cfg(test)]
    pub(crate) fn set_debt_sweep(&self, on: bool) {
        self.debt_sweep.store(on, Ordering::Relaxed);
    }

    /// Whether a flush seeds its senders again at once ([`reseed_at_flush`]).
    pub(crate) fn reseed(&self) -> bool {
        self.reseed.load(Ordering::Relaxed)
    }

    /// Sets [`Self::reseed`] (tests).
    #[cfg(test)]
    pub(crate) fn set_reseed(&self, on: bool) {
        self.reseed.store(on, Ordering::Relaxed);
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Transactions queued on the road.
    pub(crate) fn len_txs(&self) -> usize {
        self.counters.len_txs.load(Ordering::Acquire) as usize
    }

    /// Lowers the queued count by transactions that left the road for the
    /// lanes, once the lanes' depth mirror counts them.
    pub(crate) fn sub_len(&self, n: usize) {
        self.counters.len_txs.fetch_sub(n as u64, Ordering::AcqRel);
    }

    /// Queues an admitted frame; called under its senders' shard locks
    /// ([`Self::admit`]'s `on_admit`), so frames of one sender queue in the
    /// order they were admitted.
    pub(crate) fn queue_frame(&self, mut frame: RoadFrame<T>) {
        frame.epoch = self.epoch();
        let n = frame.len() as u64;
        let mut fifo = self.fifo.lock();
        frame.seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        fifo.push_back(frame);
        // Counted before the lock is released: a depth reading never misses
        // a frame that is queued.
        self.counters.len_txs.fetch_add(n, Ordering::AcqRel);
    }

    /// Takes frames off the front of the FIFO, whole, while each fits
    /// `gas_left`; they are remembered as taken.
    pub(crate) fn take_upto(&self, gas_left: &mut u64) -> Vec<RoadFrame<T>> {
        let mut out = Vec::new();
        {
            let mut fifo = self.fifo.lock();
            while fifo.front().is_some_and(|frame| frame.gas <= *gas_left) {
                let Some(frame) = fifo.pop_front() else { break };
                *gas_left -= frame.gas;
                out.push(frame);
            }
        }
        if out.is_empty() {
            return out;
        }
        let n: usize = out.iter().map(RoadFrame::len).sum();
        self.counters.len_txs.fetch_sub(n as u64, Ordering::AcqRel);
        self.counters.taken.fetch_add(out.len() as u64, Ordering::Relaxed);
        let mut evicted = Vec::new();
        {
            let mut taken = self.taken.lock();
            // Read under the lock, so `order` stays sorted by it.
            let at = self.holds.load(Ordering::Acquire);
            for frame in &out {
                let mut kept = frame.clone();
                kept.taken_at = at;
                taken.insert(kept);
            }
            while taken.by_id.len() > road_taken_max() {
                let Some((id, _)) = taken.order.pop_front() else { break };
                if let Some(frame) = taken.remove(&id) {
                    evicted.push(frame);
                }
            }
            if taken.order.len() > 2 * taken.by_id.len() + 1024 {
                let RoadTaken { by_id, order, .. } = &mut *taken;
                order.retain(|(id, _)| by_id.contains_key(id));
            }
            self.counters.taken_frames.store(taken.by_id.len() as u64, Ordering::Relaxed);
        }
        self.counters.evicted.fetch_add(evicted.len() as u64, Ordering::Relaxed);
        drop(evicted);
        out
    }

    /// Splits a give-back into the taken frames it holds whole (each found
    /// by its first transaction and followed by the rest of it, in order),
    /// forgotten as taken, and the rest of the transactions in their order.
    pub(crate) fn recognize(
        &self,
        given: Vec<Arc<ValidPoolTransaction<T>>>,
    ) -> (Vec<RoadFrame<T>>, Vec<Arc<ValidPoolTransaction<T>>>) {
        let mut taken = self.taken.lock();
        if taken.by_id.is_empty() {
            return (Vec::new(), given);
        }
        let mut whole = Vec::new();
        let mut keep = vec![true; given.len()];
        let mut i = 0;
        while i < given.len() {
            let ptr = Arc::as_ptr(&given[i]) as usize;
            let found = taken.by_ptr.get(&ptr).copied().and_then(|id| {
                let frame = taken.by_id.get(&id)?;
                let n = frame.len();
                let all = given
                    .get(i..i + n)
                    .is_some_and(|run| run.iter().zip(frame.txs.iter()).all(|(a, b)| Arc::ptr_eq(a, b)));
                all.then_some((id, n))
            });
            match found {
                Some((id, n)) => {
                    if let Some(frame) = taken.remove(&id) {
                        whole.push(frame);
                    }
                    keep[i..i + n].iter_mut().for_each(|k| *k = false);
                    i += n;
                }
                None => i += 1,
            }
        }
        self.counters.taken_frames.store(taken.by_id.len() as u64, Ordering::Relaxed);
        drop(taken);
        if whole.is_empty() {
            return (whole, given);
        }
        let rest = given.into_iter().zip(keep).filter_map(|(t, k)| k.then_some(t)).collect();
        (whole, rest)
    }

    /// Puts taken frames back on the FIFO, each at its admission place.
    pub(crate) fn hand_back(&self, frames: Vec<RoadFrame<T>>) {
        if frames.is_empty() {
            return;
        }
        let n: usize = frames.iter().map(RoadFrame::len).sum();
        let count = frames.len() as u64;
        let mut fifo = self.fifo.lock();
        for frame in frames {
            let at = fifo.partition_point(|queued| queued.seq < frame.seq);
            fifo.insert(at, frame);
        }
        self.counters.len_txs.fetch_add(n as u64, Ordering::AcqRel);
        self.counters.handed_back.fetch_add(count, Ordering::Relaxed);
    }

    /// Forgets the taken frames whose first member a canonical block mined
    /// (`highest`: the block's highest nonce per sender): they are in the
    /// chain and can never be handed back whole. Returns them, to be
    /// dropped after the caller's locks.
    ///
    /// With `N42_ROAD_RETIRE_INDEX=1` the frames are found through the
    /// index by first-member sender, touching only the senders `highest`
    /// and the taken frames share, instead of every taken frame; the set
    /// retired is the same.
    pub(crate) fn retire(&self, highest: &AddressHashMap<u64>) -> Vec<RoadFrame<T>> {
        let mut taken = self.taken.lock();
        if taken.by_id.is_empty() {
            return Vec::new();
        }
        let mined = taken.mined(highest);
        let out: Vec<RoadFrame<T>> = mined.iter().filter_map(|id| taken.remove(id)).collect();
        self.counters.taken_frames.store(taken.by_id.len() as u64, Ordering::Relaxed);
        self.counters.retired.fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }

    /// The taken frames' ids in take order, and the sender index as sorted
    /// (sender, ids) pairs (tests: the state two retire paths must agree on).
    #[cfg(test)]
    pub(crate) fn taken_state(&self) -> (Vec<B256>, Vec<(Address, Vec<B256>)>) {
        let taken = self.taken.lock();
        let mut ids: Vec<(u64, B256)> = taken.by_id.values().map(|frame| (frame.seq, frame.id)).collect();
        ids.sort_unstable();
        let mut index: Vec<(Address, Vec<B256>)> = taken
            .by_sender
            .iter()
            .map(|(sender, ids)| {
                let mut ids = ids.clone();
                ids.sort_unstable();
                (*sender, ids)
            })
            .collect();
        index.sort_unstable();
        (ids.into_iter().map(|(_, id)| id).collect(), index)
    }

    /// A taken frame's transactions, by id.
    pub(crate) fn taken_txs(&self, id: &B256) -> Option<FrameTxs<T>> {
        self.taken.lock().by_id.get(id).map(|frame| Arc::clone(&frame.txs))
    }

    /// Whether any of `senders` is on the road.
    pub(crate) fn any_on_road(&self, senders: &[Address]) -> bool {
        if senders.is_empty() {
            return false;
        }
        let shards = self.lock_senders(senders.iter());
        senders.iter().any(|sender| shards.get(sender).is_some_and(|entry| entry.on_road))
    }

    pub(crate) fn mode(&self) -> RoadMode {
        RoadMode::from_u8(self.mode.load(Ordering::Relaxed))
    }

    pub(crate) fn set_mode(&self, mode: RoadMode) {
        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    pub(crate) fn lock_shards(&self, mask: u64) -> ShardGuards<'_> {
        let mut guards: Vec<Option<MutexGuard<'_, AddressHashMap<RoadSender>>>> =
            (0..ROAD_SHARDS).map(|_| None).collect();
        for (k, slot) in guards.iter_mut().enumerate() {
            if mask & (1u64 << k) != 0 {
                *slot = Some(self.shards[k].lock());
            }
        }
        ShardGuards { guards }
    }

    pub(crate) fn lock_senders<'a>(&self, senders: impl IntoIterator<Item = &'a Address>) -> ShardGuards<'_> {
        self.lock_shards(mask_of(senders))
    }

    /// Admission of `frame` (`docs/FRAME_ROAD_DESIGN.md` 2, "Admission"):
    /// every member's sender known, the member's nonce its sender's next,
    /// a sender named twice at consecutive nonces. All touched shards are
    /// locked for the whole check, so two frames of one sender admitted at
    /// once are decided in one order. `matched` says whether the frame's
    /// transactions matched its record (`false` is [`Refusal::NoFrame`]).
    /// With `seed`, unknown senders are returned for seeding (nothing
    /// changed); without it they refuse the frame.
    ///
    /// A refused frame goes the lanes' path, so its members' senders that
    /// are known move their `next` past it: their next frame is aligned
    /// again. A member's sender already on the road asks for a flush --
    /// its transaction in the lanes could otherwise be planned ahead of its
    /// road frames, whose nonces are below it.
    ///
    /// `on_admit` runs under the shard locks when the frame is admitted
    /// (stage 1 queues it there, so two frames of one sender queue in the
    /// order they were admitted).
    pub(crate) fn admit(&self, frame: &NewFrame, matched: bool, seed: bool, on_admit: impl FnOnce()) -> Admit {
        // A frame above the block gas limit is refused whole, as any other
        // refusal (its senders move past it; a sender on the road flushes),
        // without seeding its senders first.
        let gas_limit = self.gas_limit.load(Ordering::Relaxed);
        let oversize = gas_limit != 0 && frame.gas > gas_limit;
        let mut shards = self.lock_senders(frame.members.iter().map(|(sender, _)| sender));
        if seed && !oversize {
            let mut unknown: Vec<(Address, u64)> = Vec::new();
            for (sender, nonce) in &frame.members {
                if shards.get(sender).is_none() && !unknown.iter().any(|(s, _)| s == sender) {
                    unknown.push((*sender, *nonce));
                }
            }
            if !unknown.is_empty() {
                return Admit::Seed(unknown);
            }
        }
        let stamp = self.stamps.fetch_add(1, Ordering::Relaxed) + 1;
        let mut reason: Option<Refusal> =
            (!matched).then_some(Refusal::NoFrame).or_else(|| oversize.then_some(Refusal::Oversize));
        let mut was_on_road = false;
        for (sender, nonce) in &frame.members {
            let Some(entry) = shards.get_mut(sender) else {
                reason.get_or_insert(Refusal::Unknown);
                continue;
            };
            was_on_road |= entry.on_road;
            if entry.next != *nonce {
                reason.get_or_insert(if entry.stamp == stamp { Refusal::DupSender } else { Refusal::Gap });
            }
            entry.next = entry.next.max(nonce.saturating_add(1));
            entry.stamp = stamp;
            entry.on_road = true;
        }
        match reason {
            None => {
                on_admit();
                self.counters.frames.fetch_add(1, Ordering::Relaxed);
                self.counters.txs.fetch_add(frame.members.len() as u64, Ordering::Relaxed);
                Admit::Admitted
            }
            Some(reason) => {
                if !was_on_road {
                    // Nothing of these senders is on the road: they stay
                    // off it until a frame of theirs is admitted.
                    for (sender, _) in &frame.members {
                        if let Some(entry) = shards.get_mut(sender) {
                            entry.on_road = false;
                        }
                    }
                }
                self.counters.refused[reason as usize].fetch_add(1, Ordering::Relaxed);
                Admit::Refused { reason, flush: was_on_road }
            }
        }
    }

    /// Transactions that reach the lanes by a door other than a frame (the
    /// pool's listener, a reorg, a frameless push): a sender the road knows
    /// moves its `next` past them; whether one of them is on the road (then
    /// the caller flushes, as for a refused frame).
    pub(crate) fn note_lanes_arrivals(&self, arrivals: &[(Address, u64)]) -> bool {
        if arrivals.is_empty() {
            return false;
        }
        let mut shards = self.lock_senders(arrivals.iter().map(|(sender, _)| sender));
        let mut flush = false;
        for (sender, nonce) in arrivals {
            if let Some(entry) = shards.get_mut(sender) {
                flush |= entry.on_road;
                entry.next = entry.next.max(nonce.saturating_add(1));
            }
        }
        flush
    }

    /// Invalidates the road: every shard locked (ascending), the map
    /// cleared and the epoch raised, so every sender seeds again from the
    /// lanes; the queued frames are returned in order, for the caller to
    /// put in the lanes (still counted as queued on the road: the caller
    /// lowers the count with [`Self::sub_len`] once the lanes count them).
    /// Counted as a flush.
    pub(crate) fn invalidate(&self) -> Vec<RoadFrame<T>> {
        self.invalidate_keeping(false).0
    }

    /// [`Self::invalidate`], and with `keep` the senders the map knew, each
    /// with the `next` it had (for [`reseed_at_flush`] to seed them again).
    pub(crate) fn invalidate_keeping(&self, keep: bool) -> (Vec<RoadFrame<T>>, Vec<(Address, u64)>) {
        let mut shards = self.lock_shards(u64::MAX);
        let mut known = Vec::new();
        for slot in shards.guards.iter_mut().flatten() {
            if keep {
                known.extend(slot.iter().map(|(sender, entry)| (*sender, entry.next)));
            }
            slot.clear();
        }
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.counters.flushes.fetch_add(1, Ordering::Relaxed);
        let frames: Vec<RoadFrame<T>> = std::mem::take(&mut *self.fifo.lock()).into();
        drop(shards);
        (frames, known)
    }

    /// The FIFO's frames' ids in order (tests).
    #[cfg(test)]
    pub(crate) fn queued_ids(&self) -> Vec<B256> {
        self.fifo.lock().iter().map(|frame| frame.id).collect()
    }

    /// Whether the sender index lists exactly the taken frames with a first
    /// member, each under that member's sender (tests).
    #[cfg(test)]
    pub(crate) fn index_consistent(&self) -> bool {
        let taken = self.taken.lock();
        let listed: usize = taken.by_sender.values().map(Vec::len).sum();
        let expect = taken.by_id.values().filter(|frame| !frame.members.is_empty()).count();
        listed == expect
            && taken.by_sender.iter().all(|(sender, ids)| {
                ids.iter().all(|id| taken.by_id.get(id).is_some_and(|f| f.members.first().is_some_and(|(s, _)| s == sender)))
            })
    }

    /// How many taken frames the road remembers (tests).
    #[cfg(test)]
    pub(crate) fn taken_len(&self) -> usize {
        self.taken.lock().by_id.len()
    }

    /// How many senders the road knows (tests).
    #[cfg(test)]
    pub(crate) fn senders(&self) -> usize {
        self.shards.iter().map(|shard| shard.lock().len()).sum()
    }

    /// The road's entry for `sender` (tests).
    #[cfg(test)]
    pub(crate) fn sender(&self, sender: &Address) -> Option<RoadSender> {
        self.shards[shard_of(sender)].lock().get(sender).copied()
    }
}

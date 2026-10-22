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
    /// Ids in take order, for the bound; an id already retired is skipped.
    order: VecDeque<B256>,
}

impl<T: PoolTransaction> Default for RoadTaken<T> {
    fn default() -> Self {
        Self { by_id: B256HashMap::default(), by_ptr: HashMap::new(), order: VecDeque::new() }
    }
}

impl<T: PoolTransaction> RoadTaken<T> {
    fn remove(&mut self, id: &B256) -> Option<RoadFrame<T>> {
        let frame = self.by_id.remove(id)?;
        if let Some(ptr) = frame.first_ptr() {
            self.by_ptr.remove(&ptr);
        }
        Some(frame)
    }
}

/// The most taken frames the road remembers (~65M transactions of 500-frames,
/// far past what a held window of own blocks takes). Past it the oldest is
/// forgotten: a give-back of it is then not recognised, and goes the lanes'
/// path with an invalidation, which is correct, only slower.
const ROAD_TAKEN_MAX: usize = 131_072;

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
    pub(crate) refused: [AtomicU64; 4],
    pub(crate) flushes: AtomicU64,
    pub(crate) seeded: AtomicU64,
    pub(crate) seed_holds: AtomicU64,
    pub(crate) len_txs: AtomicU64,
    pub(crate) lane_debt: AtomicU64,
    pub(crate) taken: AtomicU64,
    pub(crate) handed_back: AtomicU64,
    pub(crate) retired: AtomicU64,
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
    /// Times the road was invalidated: its map cleared (and its queued
    /// frames moved to the lanes' path).
    pub flushes: u64,
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
            flushes: get(&self.flushes),
            seeded: get(&self.seeded),
            seed_holds: get(&self.seed_holds),
            len_txs: get(&self.len_txs),
            lane_debt: get(&self.lane_debt),
            taken: get(&self.taken),
            handed_back: get(&self.handed_back),
            retired: get(&self.retired),
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
            taken: Mutex::new(RoadTaken::default()),
            counters: Arc::new(RoadCounters::default()),
            reseed: std::sync::atomic::AtomicBool::new(reseed_at_flush()),
        }
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
            for frame in &out {
                if let Some(ptr) = frame.first_ptr() {
                    taken.by_ptr.insert(ptr, frame.id);
                }
                taken.order.push_back(frame.id);
                taken.by_id.insert(frame.id, frame.clone());
            }
            while taken.by_id.len() > ROAD_TAKEN_MAX {
                let Some(id) = taken.order.pop_front() else { break };
                if let Some(frame) = taken.remove(&id) {
                    evicted.push(frame);
                }
            }
            if taken.order.len() > 2 * taken.by_id.len() + 1024 {
                let RoadTaken { by_id, order, .. } = &mut *taken;
                order.retain(|id| by_id.contains_key(id));
            }
        }
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
    pub(crate) fn retire(&self, highest: &AddressHashMap<u64>) -> Vec<RoadFrame<T>> {
        let mut taken = self.taken.lock();
        if taken.by_id.is_empty() {
            return Vec::new();
        }
        let mined: Vec<B256> = taken
            .by_id
            .iter()
            .filter(|(_, frame)| {
                frame.members.first().is_some_and(|(sender, nonce)| highest.get(sender).is_some_and(|m| m >= nonce))
            })
            .map(|(id, _)| *id)
            .collect();
        let out: Vec<RoadFrame<T>> = mined.iter().filter_map(|id| taken.remove(id)).collect();
        self.counters.retired.fetch_add(out.len() as u64, Ordering::Relaxed);
        out
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
        let mut shards = self.lock_senders(frame.members.iter().map(|(sender, _)| sender));
        if seed {
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
        let mut reason: Option<Refusal> = (!matched).then_some(Refusal::NoFrame);
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

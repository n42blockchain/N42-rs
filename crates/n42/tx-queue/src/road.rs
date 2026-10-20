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

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use alloy_primitives::{map::AddressHashMap, Address};
use parking_lot::{Mutex, MutexGuard};

use crate::NewFrame;

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
}

impl RoadMode {
    const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Count,
            _ => Self::Off,
        }
    }
}

/// `N42_FRAME_ROAD`, read once: `1` or `count` counts (stage 0), anything
/// else is off.
pub(crate) fn road_mode_env() -> RoadMode {
    static MODE: OnceLock<RoadMode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("N42_FRAME_ROAD").as_deref() {
        Ok("1" | "count") => RoadMode::Count,
        _ => RoadMode::Off,
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

/// The road's shared state.
#[derive(Debug)]
pub(crate) struct Road {
    mode: AtomicU8,
    shards: Box<[Mutex<AddressHashMap<RoadSender>>]>,
    /// Admission attempts, for [`RoadSender::stamp`].
    stamps: AtomicU64,
    /// Raised by every invalidation.
    epoch: AtomicU64,
    pub(crate) counters: Arc<RoadCounters>,
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

impl Road {
    pub(crate) fn new(mode: RoadMode) -> Self {
        Self {
            mode: AtomicU8::new(mode as u8),
            shards: (0..ROAD_SHARDS).map(|_| Mutex::new(AddressHashMap::default())).collect(),
            stamps: AtomicU64::new(0),
            epoch: AtomicU64::new(1),
            counters: Arc::new(RoadCounters::default()),
        }
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
    /// lanes. Counted as a flush.
    pub(crate) fn invalidate(&self) {
        let mut shards = self.lock_shards(u64::MAX);
        for slot in shards.guards.iter_mut().flatten() {
            slot.clear();
        }
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.counters.flushes.fetch_add(1, Ordering::Relaxed);
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

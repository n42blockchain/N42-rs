// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A transaction source for the block builder that lives beside reth's pool
//! rather than inside it.
//!
//! reth's pool was measured, on a leader that builds every view at 163,000
//! transactions a block, to cost about half a second per block: 116-220 ms
//! to select from its ordered sets and ~300 ms to remove the block's
//! transactions one at a time under its write lock -- the lock the ingest
//! needs to admit anything. The pool is right for a mainnet node and wrong
//! for that.
//!
//! This queue takes the same transactions the binary ingest has already
//! validated and recovered, keeps them per sender in nonce order, and hands
//! them to the builder in the order the senders' first transactions arrived,
//! one per sender per pass, so no sender starves another. Selection is a
//! walk; taking is a pop. reth's pool still receives everything for RPC and
//! gossip, off the builder's path.
//!
//! What goes out for a build is remembered until the next build. A build on
//! the same parent again usually means the previous block was not committed,
//! and its transactions go back to the front; a build on a new parent means
//! it was, and they are dropped. Canonical blocks prune the queue on every
//! node by (sender, nonce), so a follower that becomes leader does not offer
//! what the chain already holds.
//!
//! Neither rule is proof on its own -- two builds can be in flight on one
//! parent, and the block from the first can be committed and pruned before
//! the second asks -- so every lane carries the highest nonce the chain has
//! mined for its sender, and nothing at or below it is ever queued again,
//! whichever door it comes in by. Without that, a give-back after the prune
//! left the mined transactions queued for good: every later build of that
//! leader took them, refused each for a stale nonce and gave them back
//! (round 44: 814,431 refusals on one node, builds of 3.4-4.1 s against
//! 250 ms, and the chain's cycle 1.7-2.7 s against 0.42).
//!
//! Enabled by `N42_TX_QUEUE=1`. The queue is fed from the pool's
//! new-transaction listener, so a transaction that came in by the ingest,
//! by RPC or by gossip is offered alike; the builder finds the queue through
//! [`global`].

mod frames;

pub use frames::{FramePlan, FrameRef, FrameTxs, NewFrame, PlannedFrame, MAX_FRAMES};

use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, OnceLock};

use alloy_primitives::{map::{AddressHashMap, AddressHashSet}, Address, B256};
use parking_lot::Mutex;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    identifier::{SenderId, TransactionId},
    BestTransactions, PoolTransaction, TransactionOrigin, ValidPoolTransaction,
};

/// One sender's queued transactions, nonce-ordered.
struct Lane<T: PoolTransaction> {
    by_nonce: BTreeMap<u64, Arc<ValidPoolTransaction<T>>>,
    /// Whether the sender is in the arrival order right now.
    queued: bool,
    /// The highest nonce the chain is known to have mined for this sender,
    /// from a canonical block or a build's stale refusal. Nothing at or
    /// below it may re-enter the lane through a give-back: the chain has
    /// made it unusable for good, and a build that is offered it pays a
    /// full refusal for it -- every build, for as long as it is queued
    /// (round 44: 814,431 refusals on one node against 17,300 on a healthy
    /// one, and a leader's build at 3.4-4.1 s instead of 250 ms).
    mined: Option<u64>,
    /// Of that watermark, the part a canonical block put there.
    ///
    /// The rest of it comes from a build's refusal, which is a verdict
    /// about a state that may include blocks consensus has not committed.
    /// Both filter the same way -- they have to -- but only one of them is
    /// a fact, and a transaction filtered on the other is the shape a hole
    /// takes. Kept apart so the drop counters can say which
    /// ([`Dropped::Mined`] against [`Dropped::StaleGiveBack`]) instead of
    /// reporting every mined transaction as a suspect.
    chain_mined: Option<u64>,
    /// A build found a hole below this lane's head: the account is at
    /// `Parked::wanted` and the lowest nonce here is above it, so nothing
    /// in this lane can execute until the missing nonce arrives. See
    /// [`Parked`].
    parked: Option<Parked>,
}

/// A lane held out of the arrival order because a build found a hole below
/// its head.
///
/// With the ingest going straight to the queue (`N42_TX_INGEST_DIRECT`) a
/// missing nonce is not in the pool either, so a gapped lane's head is
/// unusable for as long as the hole lasts -- and it is the lane's *lowest*
/// nonce, which is what every build is offered first. On loop207 Ob node1
/// that cost the whole tenure: `par_skipped` climbed 2,880 -> 163,000 over
/// twenty blocks while the queue held 334-360k, and the leader proposed
/// `txs=0` blocks for the last twenty views of its tenure with the builder
/// refusing the same heads every build (`refused[6]` +3,971 a build).
/// Stepping the lane over until the hole is filled leaves the build's
/// candidate budget for lanes that can execute.
///
/// The park always expires ([`PARK_BUILDS`]), because a lane that is
/// offered to nothing again is the stranded-lane defect of loop144, and a
/// park is a guess about state the queue cannot see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parked {
    /// The nonce the account is at, as the build that parked the lane read
    /// it: the lane is usable again as soon as this nonce is queued or the
    /// chain passes it.
    wanted: u64,
    /// The build counter this lane is offered again at, whatever the hole.
    until_build: u64,
}

/// For how many builds a lane stays parked before it is offered again
/// regardless.
///
/// Small enough that a park which was wrong -- the hole filled by a door
/// this lane does not hear about -- costs one refusal every eight builds
/// rather than a stranded lane, and large enough that a real hole is not
/// re-offered to every build.
const PARK_BUILDS: u64 = 8;

/// How many lanes may be parked at once. **0, the default, is no parking at
/// all**; a positive value turns it on with that many lanes as the bound.
/// `N42_TX_QUEUE_PARK_LANES`.
///
/// Parking is off because a parked lane is a sink. Nothing drains it -- that
/// is the point -- but the generator keeps feeding its sender at full rate,
/// `insert_valid` keeps adding to it, and [`TxQueue::gate_len`] leaves it
/// out, so the ingest never pushes back on it either. loop211 Pd node1 held
/// its parked lanes at exactly the 64 the cap allows and watched them grow
/// from 1,434 transactions each to 5,505 over fourteen blocks -- 91,764 to
/// 355,700 in all, with `usable` falling 322,574 -> 10,132 in step. The node
/// then built 55 empty blocks over a queue of 370,000 and lost both windows
/// (407k, then 75k at 24% occupancy); Pe lost window 3 the same way
/// (parked 561,429). The two legs of that round that never parked at all,
/// Pa and Pb, were the cleanest of the campaign at 625-630k on both windows.
///
/// A cap in lanes cannot fix that: it bounds how many sinks there are, not
/// how large each one grows, and the lane's own depth is not knowable when
/// the park is made -- whatever the build in flight has not taken out of it
/// yet is not there to count.
///
/// Nor could a guard on the builder's side have bounded it. A park is asked
/// for by `QueueBest::mark_invalid`, which is the ordinary refusal path:
/// the serial loop reports every `NonceTooHigh` it meets
/// (`payload.rs`, one per transaction), so the three guards on the
/// builder's *diagnosis* never applied to it. On loop211 Pd node1 those
/// guards worked -- the "most of the senders a build was offered looked
/// gapped" warning fired and the diagnosis reported nothing -- while 43,229
/// parks were asked for in the same second by the serial loop alone.
///
/// So the machinery stays, off. What a hole actually needed is the
/// stale-head diagnosis beside it, which drops a head the chain has passed
/// so the lane is usable at the next build and the early seal recovers, and
/// which does not depend on parking; and within a build a refused sender is
/// already skipped for the rest of it (`QueueBest::skipped`). What
/// parking added was persistence across builds, and that is what turned a
/// per-build cost into a node-wide outage. Turning it on again wants a
/// different rule -- a lane parked only after the same head has been
/// reported gapped by several consecutive builds, and drained or bounded
/// while it is parked -- and a leg that shows the cost it saves.
fn park_lane_cap() -> usize {
    static LANES: OnceLock<usize> = OnceLock::new();
    *LANES.get_or_init(|| {
        std::env::var("N42_TX_QUEUE_PARK_LANES").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
    })
}

impl<T: PoolTransaction> Lane<T> {
    /// Whether the chain has passed this nonce, so the lane must not hold it.
    fn is_stale(&self, nonce: u64) -> bool {
        self.mined.is_some_and(|mined| nonce <= mined)
    }

    /// Records that the chain mined this nonce. The watermark only rises:
    /// blocks arrive in order, and a later build's refusal says no less
    /// than an earlier block did.
    fn mine(&mut self, nonce: u64, from_chain: bool) {
        self.mined = Some(self.mined.map_or(nonce, |mined| mined.max(nonce)));
        if from_chain {
            self.chain_mined = Some(self.chain_mined.map_or(nonce, |mined| mined.max(nonce)));
        }
    }

    /// Whether a canonical block is known to have mined this nonce, as
    /// against a build having said so.
    fn chain_mined(&self, nonce: u64) -> bool {
        self.chain_mined.is_some_and(|mined| nonce <= mined)
    }

    /// Why this lane will not take the nonce back: because the chain holds
    /// it, or only because a build said so.
    fn why_stale(&self, nonce: u64, give_back: bool) -> Dropped {
        match (self.chain_mined(nonce), give_back) {
            (true, _) => Dropped::Mined,
            (false, true) => Dropped::StaleGiveBack,
            (false, false) => Dropped::StaleArrival,
        }
    }

    /// A reorg took this nonce back off the chain: the watermark drops below
    /// it, or the transactions the reverted blocks give back would be
    /// filtered as mined the first time a build handed them back.
    fn unmine(&mut self, nonce: u64) {
        if self.mined.is_some_and(|mined| mined >= nonce) {
            self.mined = nonce.checked_sub(1);
        }
        if self.chain_mined.is_some_and(|mined| mined >= nonce) {
            self.chain_mined = nonce.checked_sub(1);
        }
    }

    /// Whether this lane's park is still holding at build `build`.
    ///
    /// A pure test: every park is ended through [`Inner::unpark`], which is
    /// what keeps `Inner::parked_len` honest.
    fn park_holds(&self, build: u64) -> bool {
        self.parked.is_some_and(|parked| parked.until_build > build)
    }

    /// A transaction reached the lane by some door: at or below the nonce
    /// the account was waiting for, it is the hole (or what is left of it),
    /// so the lane can be walked again.
    fn hole_filled_by(&self, nonce: u64) -> bool {
        self.parked.is_some_and(|parked| nonce <= parked.wanted)
    }

    /// The chain mined this nonce for the sender: at or above the hole,
    /// there is no hole left -- another leader mined what was missing, and
    /// what the lane still holds above it is next.
    fn chain_passed(&self, nonce: u64) -> bool {
        self.parked.is_some_and(|parked| nonce >= parked.wanted)
    }
}

/// Why the queue let go of a transaction.
///
/// A hole in a lane -- a nonce the generator delivered and got an
/// acknowledgement for, which is then in neither the queue nor a block --
/// can only be made at one of these, so none of them is silent any more.
/// Everything the queue holds is reachable through a lane, and the lane
/// only ever loses a transaction here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dropped {
    /// The lane already held that (sender, nonce). Harmless: the generator
    /// re-sends a frame whose answer it did not hear.
    Duplicate,
    /// A canonical block carries that (sender, nonce). Harmless, and the
    /// common one: a build hands its leftovers back after another build has
    /// mined them, which under the build chain is every block.
    Mined,
    /// An arrival at or below the lane's mined watermark.
    StaleArrival,
    /// A build's give-back at or below the watermark. **This is the one
    /// that makes a hole** when the watermark came from a build's verdict
    /// about a block consensus never committed.
    StaleGiveBack,
    /// A build refused it for a nonce a canonical block confirms is behind
    /// the chain, so the lane drops it and everything below.
    StaleRefusal,
    /// A build refused it as behind the chain, but no canonical block says
    /// so: the build was standing on a block of its own that consensus did
    /// not keep. Given back rather than dropped -- acting on that verdict
    /// is what made loop214's holes. Not a loss; a reading of how often a
    /// build's state runs ahead of the chain.
    StaleUnconfirmed,
    /// A give-back for a sender with no lane at all.
    NoLane,
    /// An own block pushed past the bound on held blocks before the chain
    /// settled its height.
    HeldEvicted,
    /// An own block still held at a height the chain had already passed.
    HeldBehind,
}

impl Dropped {
    /// Every reason, in report order.
    pub const ALL: [Self; 9] = [
        Self::Duplicate,
        Self::Mined,
        Self::StaleArrival,
        Self::StaleGiveBack,
        Self::StaleRefusal,
        Self::StaleUnconfirmed,
        Self::NoLane,
        Self::HeldEvicted,
        Self::HeldBehind,
    ];

    /// The name this reason is reported under.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Mined => "mined",
            Self::StaleArrival => "stale_arrival",
            Self::StaleGiveBack => "stale_give_back",
            Self::StaleRefusal => "stale_refusal",
            Self::StaleUnconfirmed => "stale_unconfirmed",
            Self::NoLane => "no_lane",
            Self::HeldEvicted => "held_evicted",
            Self::HeldBehind => "held_behind",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Duplicate => 0,
            Self::Mined => 1,
            Self::StaleArrival => 2,
            Self::StaleGiveBack => 3,
            Self::StaleRefusal => 4,
            Self::StaleUnconfirmed => 5,
            Self::NoLane => 6,
            Self::HeldEvicted => 7,
            Self::HeldBehind => 8,
        }
    }
}

/// The pool [`TxQueue::forget_mined_parallel`] runs on: eight threads of
/// the queue's own, so no job on it ever waits for the queue's lock (the
/// partition runs under it). `None` if the threads could not be started.
fn forget_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .thread_name(|i| format!("n42-queue-forget-{i}"))
            .build()
            .ok()
    })
    .as_ref()
}

/// Where [`TxQueue::forget_mined_timed`] spent its time, in microseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForgetTimes {
    /// Folding the block's (sender, nonce) pairs into a map, outside the lock.
    pub fold_us: u64,
    /// Waiting for the queue's lock, both times it is taken.
    pub lock_us: u64,
    /// Splitting the taken list into mined and kept, under the lock.
    pub partition_us: u64,
    /// Whether the taken list was the block's body, position by position
    /// (the same sender and nonce at every index): then every transaction
    /// in it is mined and the list is handed over whole, without the fold
    /// or the partition. `partition_us` is the comparison's time then.
    pub whole: bool,
    /// The taken list's length at the hand-off, against the body's: why
    /// the whole hand-over did not match (`docs/BREAKTHROUGH_DESIGN.md` 10.34:
    /// it never did on the fleet), with [`Self::first_miss`].
    pub taken_len: usize,
    /// With equal lengths, the first position whose (sender, nonce) differs
    /// from the body's; `usize::MAX` when not compared or none differs.
    pub first_miss: usize,
}

/// Where [`TxQueue::prune_block`] spent its time, in microseconds, and how
/// much it did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PruneTimes {
    /// The own block held at the height settled (its own lock).
    pub settle_us: u64,
    /// The block's pairs folded to one nonce a sender, outside the lock.
    pub fold_us: u64,
    /// Waiting for the lanes' lock.
    pub lock_us: u64,
    /// Under it: the inbox drained, the lanes split, the frames swept, the
    /// taken list split.
    pub remove_us: u64,
    /// The by-hash index, one write lock a shard.
    pub forget_us: u64,
    /// Handing what left the queue to the freeing thread (or freeing it
    /// here when that thread is four blocks behind), with no lock held.
    pub free_us: u64,
    /// Senders in the block.
    pub senders: usize,
    /// Frames the sweep dropped.
    pub frames_swept: usize,
    /// References released by the free (a transaction is freed when its
    /// last one goes).
    pub freed: usize,
}

/// What a prune took out of the queue, held until every lock is released.
struct PruneGarbage<T: PoolTransaction> {
    lanes: Vec<BTreeMap<u64, Arc<ValidPoolTransaction<T>>>>,
    taken: Vec<Arc<ValidPoolTransaction<T>>>,
    frames: Vec<FrameTxs<T>>,
    index: Vec<Arc<ValidPoolTransaction<T>>>,
}

impl<T: PoolTransaction> Default for PruneGarbage<T> {
    fn default() -> Self {
        Self { lanes: Vec::new(), taken: Vec::new(), frames: Vec::new(), index: Vec::new() }
    }
}

/// Garbage on its way to the freeing thread, type-erased: one thread serves
/// whatever transaction type the queue holds.
type Freeable = Box<dyn Send>;

/// The queue's freeing thread (`n42-queue-free`): what a prune took out of
/// the queue is released there, off the prune and off every lock. A
/// 200,000-transaction block is 600,000 references and 200,000
/// transactions freed, 27-31 ms on one thread with the system allocator
/// (`prune_tests::bench_prune_block`) -- most of the prune once nothing was
/// freed under a lock. Freeing in parallel was worse (110-150 ms: frees of
/// one allocator's objects from several threads contend). The channel holds
/// four blocks; a prune that finds it full frees its own garbage, so a
/// freeing thread that falls behind slows the prune down rather than letting
/// memory grow. `None` if the thread could not be started.
fn freeing_thread() -> Option<&'static std::sync::mpsc::SyncSender<Freeable>> {
    static SENDER: OnceLock<Option<std::sync::mpsc::SyncSender<Freeable>>> = OnceLock::new();
    SENDER
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Freeable>(4);
            std::thread::Builder::new()
                .name("n42-queue-free".to_owned())
                .spawn(move || {
                    while let Ok(garbage) = rx.recv() {
                        drop(garbage);
                    }
                })
                .ok()
                .map(|_| tx)
        })
        .as_ref()
}

impl<T: PoolTransaction + 'static> PruneGarbage<T> {
    /// Releases everything on the freeing thread ([`freeing_thread`]), or
    /// here when it is full or absent. The by-hash index's references go
    /// last: they are usually the last ones, so that is where the
    /// transactions themselves are freed.
    fn free(self) {
        if self.lanes.is_empty() && self.taken.is_empty() && self.frames.is_empty() && self.index.is_empty() {
            return;
        }
        let Some(sender) = freeing_thread() else {
            drop(self);
            return;
        };
        match sender.try_send(Box::new(self)) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(garbage) | std::sync::mpsc::TrySendError::Disconnected(garbage)) => {
                drop(garbage);
            }
        }
    }

    fn len(&self) -> usize {
        self.lanes.iter().map(BTreeMap::len).sum::<usize>()
            + self.taken.len()
            + self.frames.iter().map(|frame| frame.len()).sum::<usize>()
            + self.index.len()
    }
}

/// Each sender's highest nonce in `mined`. A block is runs of one sender's
/// consecutive nonces (a frame is one sender's run on the bench), so the
/// map is touched once a run, not once a transaction.
fn fold_highest(mined: impl IntoIterator<Item = (Address, u64)>) -> AddressHashMap<u64> {
    let mut highest: AddressHashMap<u64> = AddressHashMap::default();
    let mut run: Option<(Address, u64)> = None;
    let flush = |highest: &mut AddressHashMap<u64>, (sender, nonce): (Address, u64)| {
        let entry = highest.entry(sender).or_insert(nonce);
        *entry = (*entry).max(nonce);
    };
    for (sender, nonce) in mined {
        match run.as_mut() {
            Some((current, top)) if *current == sender => *top = (*top).max(nonce),
            _ => {
                if let Some(done) = run.replace((sender, nonce)) {
                    flush(&mut highest, done);
                }
            }
        }
    }
    if let Some(done) = run {
        flush(&mut highest, done);
    }
    highest
}

/// How many transactions the queue let go of since the last report, by
/// reason, with the first few named.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DropReport {
    /// Counts in [`Dropped::ALL`] order.
    pub counts: [u64; 9],
    /// The first few, as (reason, sender, nonce): enough to take one sender
    /// to the generator's own log and see which nonce went missing.
    pub samples: Vec<(Dropped, Address, u64)>,
}

impl DropReport {
    /// Whether anything was let go of that a hole could be hiding behind.
    ///
    /// A duplicate is the generator re-sending, and a transaction the chain
    /// holds is the build chain handing back what the next build mined:
    /// both are the queue working. Everything else is worth a line.
    pub fn interesting(&self) -> bool {
        self.counts
            .iter()
            .enumerate()
            .any(|(i, n)| i != Dropped::Duplicate.index() && i != Dropped::Mined.index() && *n > 0)
    }

    /// The reasons that fired, as `name=count` pairs.
    pub fn named(&self) -> Vec<(&'static str, u64)> {
        Dropped::ALL
            .into_iter()
            .filter(|reason| self.counts[reason.index()] > 0)
            .map(|reason| (reason.name(), self.counts[reason.index()]))
            .collect()
    }
}

/// How many (reason, sender, nonce) triples a report carries.
const DROP_SAMPLES: usize = 8;

/// What a give-back did: how many went back to the lanes, and how many were
/// dropped because the chain had already mined them (or their sender has no
/// lane left to go back to).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct GaveBack {
    offered: usize,
    filtered: usize,
}

/// The lanes' lock as [`TxQueue::lock_inner`] hands it out: the guard, when
/// it was taken, how long the caller waited for it, and who the caller is.
struct TimedInner<'a, T: PoolTransaction> {
    guard: parking_lot::MutexGuard<'a, Inner<T>>,
    at: std::time::Instant,
    waited: std::time::Duration,
    caller: &'static std::panic::Location<'static>,
    /// The queue's depth mirror ([`TxQueue::gate_len`]), stored from the
    /// lanes as the guard is released.
    mirror: &'a std::sync::atomic::AtomicU64,
}

/// `len` and `parked_len` packed into one word for the depth mirror: the
/// parked total in the high half, the queued total in the low half, each
/// saturated at `u32::MAX` (a queue of four billion is not a state this
/// node reaches; saturating keeps a wrong value from wrapping into the
/// other half).
const fn pack_depth(len: usize, parked: usize) -> u64 {
    let len = if len > u32::MAX as usize { u32::MAX as u64 } else { len as u64 };
    let parked = if parked > u32::MAX as usize { u32::MAX as u64 } else { parked as u64 };
    (parked << 32) | len
}

/// The (len, parked) a packed mirror holds.
const fn unpack_depth(packed: u64) -> (u64, u64) {
    (packed & 0xffff_ffff, packed >> 32)
}

/// The lanes' lock and the inbox drain, measured for the 5 s report
/// ([`take_lock_stats`]): how often the lock was held and for how long in
/// all, its longest hold (and who held it) and its longest wait, and the
/// drains' count, transactions and hold time. Process-wide: a node has one
/// queue.
struct LockCounters {
    holds: std::sync::atomic::AtomicU64,
    hold_ns: std::sync::atomic::AtomicU64,
    hold_max_ns: std::sync::atomic::AtomicU64,
    wait_max_ns: std::sync::atomic::AtomicU64,
    wait_ns: std::sync::atomic::AtomicU64,
    drains: std::sync::atomic::AtomicU64,
    drain_txs: std::sync::atomic::AtomicU64,
    drain_ns: std::sync::atomic::AtomicU64,
    drain_max_ns: std::sync::atomic::AtomicU64,
    drain_chunks: std::sync::atomic::AtomicU64,
    drain_chunk_max_txs: std::sync::atomic::AtomicU64,
    drain_finished: std::sync::atomic::AtomicU64,
}

static LOCK_COUNTERS: LockCounters = LockCounters {
    holds: std::sync::atomic::AtomicU64::new(0),
    hold_ns: std::sync::atomic::AtomicU64::new(0),
    hold_max_ns: std::sync::atomic::AtomicU64::new(0),
    wait_max_ns: std::sync::atomic::AtomicU64::new(0),
    wait_ns: std::sync::atomic::AtomicU64::new(0),
    drains: std::sync::atomic::AtomicU64::new(0),
    drain_txs: std::sync::atomic::AtomicU64::new(0),
    drain_ns: std::sync::atomic::AtomicU64::new(0),
    drain_max_ns: std::sync::atomic::AtomicU64::new(0),
    drain_chunks: std::sync::atomic::AtomicU64::new(0),
    drain_chunk_max_txs: std::sync::atomic::AtomicU64::new(0),
    drain_finished: std::sync::atomic::AtomicU64::new(0),
};

/// The caller that set the current longest hold, beside it.
static HOLD_MAX_AT: Mutex<Option<&'static std::panic::Location<'static>>> = Mutex::new(None);

/// What [`take_lock_stats`] reports: the lanes' lock and the inbox drain
/// since the previous call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockStats {
    /// Times the lanes' lock was taken and released.
    pub holds: u64,
    /// Their holds' sum, nanoseconds: over the interval, the lock's duty.
    pub hold_ns: u64,
    /// The longest single hold, nanoseconds, and where it was taken.
    pub hold_max_ns: u64,
    /// `file:line` of the longest hold's caller, when one was recorded.
    pub hold_max_at: Option<&'static std::panic::Location<'static>>,
    /// The longest wait for the lock, nanoseconds, and the waits' sum.
    pub wait_max_ns: u64,
    /// Sum of every wait for the lock, nanoseconds.
    pub wait_ns: u64,
    /// Inbox drains that moved anything into the lanes, the transactions
    /// they moved, their time under the lock in all and the longest one.
    pub drains: u64,
    /// Transactions those drains moved.
    pub drain_txs: u64,
    /// The drains' time under the lock, nanoseconds.
    pub drain_ns: u64,
    /// The longest drain, nanoseconds.
    pub drain_max_ns: u64,
    /// Holds of the lanes' lock a chunked drainer made
    /// (`N42_TX_QUEUE_DRAIN_CHUNK`); each is also one of `drains`.
    pub drain_chunks: u64,
    /// The most transactions one of those holds moved.
    pub drain_chunk_max_txs: u64,
    /// Chunked remainders another lock holder finished before draining the
    /// inbox (a build's start, a prune): those holds are not bounded.
    pub drain_finished: u64,
}

/// The lanes' lock and drain counters since the last call, which resets
/// them: the 5 s `ingest` line reports one interval each.
pub fn take_lock_stats() -> LockStats {
    use std::sync::atomic::Ordering::Relaxed;
    let c = &LOCK_COUNTERS;
    let hold_max_at = HOLD_MAX_AT.lock().take();
    LockStats {
        holds: c.holds.swap(0, Relaxed),
        hold_ns: c.hold_ns.swap(0, Relaxed),
        hold_max_ns: c.hold_max_ns.swap(0, Relaxed),
        hold_max_at,
        wait_max_ns: c.wait_max_ns.swap(0, Relaxed),
        wait_ns: c.wait_ns.swap(0, Relaxed),
        drains: c.drains.swap(0, Relaxed),
        drain_txs: c.drain_txs.swap(0, Relaxed),
        drain_ns: c.drain_ns.swap(0, Relaxed),
        drain_max_ns: c.drain_max_ns.swap(0, Relaxed),
        drain_chunks: c.drain_chunks.swap(0, Relaxed),
        drain_chunk_max_txs: c.drain_chunk_max_txs.swap(0, Relaxed),
        drain_finished: c.drain_finished.swap(0, Relaxed),
    }
}

/// Raises `max` to `value` if it is larger; returns whether it did. A load
/// first, so the common case (not a new maximum) writes nothing to a line
/// every lock of the queue would otherwise share.
fn raise_max(max: &std::sync::atomic::AtomicU64, value: u64) -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    value > max.load(Relaxed) && max.fetch_max(value, Relaxed) < value
}

/// A hold or a wait of the queue's lock this long is said.
const SLOW_LOCK: std::time::Duration = std::time::Duration::from_secs(1);

impl<T: PoolTransaction> std::ops::Deref for TimedInner<'_, T> {
    type Target = Inner<T>;
    fn deref(&self) -> &Inner<T> {
        &self.guard
    }
}

impl<T: PoolTransaction> std::ops::DerefMut for TimedInner<'_, T> {
    fn deref_mut(&mut self) -> &mut Inner<T> {
        &mut self.guard
    }
}

impl<T: PoolTransaction> Drop for TimedInner<'_, T> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        // Still under the lock: mirror stores are ordered by it, so the
        // mirror only ever holds a depth the lanes really had at a release.
        // A chunked drain's remainder is queued as far as the gate is
        // concerned: it left `staged` and is on its way into the lanes.
        let queued = self.guard.len + self.guard.pending_drain.len();
        self.mirror.store(pack_depth(queued, self.guard.parked_len), Release);
        let held = self.at.elapsed();
        let held_ns = held.as_nanos() as u64;
        let waited_ns = self.waited.as_nanos() as u64;
        let c = &LOCK_COUNTERS;
        c.holds.fetch_add(1, Relaxed);
        c.hold_ns.fetch_add(held_ns, Relaxed);
        if waited_ns > 0 {
            c.wait_ns.fetch_add(waited_ns, Relaxed);
            raise_max(&c.wait_max_ns, waited_ns);
        }
        if raise_max(&c.hold_max_ns, held_ns) {
            *HOLD_MAX_AT.lock() = Some(self.caller);
        }
        if held >= SLOW_LOCK || self.waited >= SLOW_LOCK {
            tracing::warn!(
                target: "n42.tx_queue",
                held_ms = held.as_millis() as u64,
                waited_ms = self.waited.as_millis() as u64,
                caller = %self.caller,
                "the queue's lock was held or waited for a second or more"
            );
        }
    }
}

struct Inner<T: PoolTransaction> {
    // Keyed by address with alloy's fixed-bytes hasher: the builder looks a
    // lane up per transaction, and std's SipHash was 3% of its thread.
    //
    // A lane never holds a transaction at or below its sender's mined
    // watermark, whichever door it came in by -- an arrival, a build's
    // give-back, an own block the chain settled elsewhere. The give-back is
    // the door that mattered: what a build took is outside the lanes, so a
    // canonical prune cannot see it, and a take handed back after its block
    // was pruned used to stay queued for the rest of the leg.
    lanes: AddressHashMap<Lane<T>>,
    /// Senders with queued transactions, in the order their queued run began;
    /// a sender taken from the front goes to the back if it has more.
    arrivals: VecDeque<Address>,
    len: usize,
    /// What the last build took, and the parent it built on.
    last_build: Option<(B256, Vec<Arc<ValidPoolTransaction<T>>>)>,
    /// A frame build's takes not yet applied to the lanes: (frame id, how
    /// many of its transactions from its start). Applied by
    /// [`Inner::settle`] at the next lock ([`TxQueue::lock_inner`]).
    pending: Vec<(B256, usize)>,
    /// Holes a build ran into: (sender, the account's next nonce, the lowest
    /// queued nonce above it). The feed fills them from the pool.
    gaps: Vec<(Address, u64, u64)>,
    /// Transactions this node's own built blocks took out of the queue before
    /// the chain committed them: (block number, block hash, the
    /// transactions). A block that consensus never commits -- its view timed
    /// out, another leader's block took its height -- would otherwise have
    /// carried them away for good, and every affected sender's lane would
    /// start above the chain's nonce (round 43: whole legs of 40,000
    /// nonce refusals a block after a stall). Settled by the canonical
    /// pruner: the same hash drops them, another hash at the height gives
    /// back the ones it does not carry. Bounded to the last few blocks.
    held: VecDeque<(u64, B256, Vec<Arc<ValidPoolTransaction<T>>>)>,
    /// Lanes stepped over behind a hole ([`Parked`]), roughly in the order
    /// their parks expire -- a park always ends `PARK_BUILDS` builds after
    /// the build that set it, and this is walked from the front, so an
    /// entry behind a younger one waits at most a few builds longer. A
    /// parked lane is out of `arrivals` entirely, so the walk does not step
    /// over it once per transaction: at the bench tier a build takes
    /// 163,000 transactions, and re-walking even a few hundred parked lanes
    /// for each of them would cost more than the defect. Drained at the
    /// start of every build ([`Inner::readmit_parked`]), which is also what
    /// makes a park impossible to lose.
    parked_order: VecDeque<Address>,
    /// How many transactions the parked lanes hold, as a running total.
    ///
    /// The ingest's gate reads the queue's depth once per frame -- thousands
    /// of times a second -- and what it must not count is supply no build
    /// can take. On loop209 Pa it did: node3's lanes parked, its depth stayed
    /// at 569,520 above the gate's 543,333, the gate shut, nothing arrived,
    /// its own blocks were empty so nothing was pruned, and the node
    /// proposed empty blocks for fifteen seconds until the tenure changed
    /// (`usable=0 queued=569520` on every build, `ingest ... rate=30591
    /// gate_us_per_frame=86660`). Walking the lanes per frame is not an
    /// option, so this is kept up to date at the few places a parked lane's
    /// contents or its park can change, and a test pins it against the walk.
    parked_len: usize,
    /// What the queue has let go of since the last report ([`Dropped`]).
    drops: DropReport,
    /// Parks refused by the cap since the process started; on the prune
    /// line, because a cap that keeps firing means something is asking for
    /// far more parking than a hole would explain. With parking off it
    /// counts every park that was asked for, which is the same reading.
    park_capped: u64,
    /// How many lanes this queue may park at once; 0 is no parking.
    /// [`park_lane_cap`] unless a test said otherwise.
    park_lanes: usize,
    /// The highest block number a canonical prune has taken out of the
    /// lanes.
    ///
    /// A build standing on a parent below this is standing behind its own
    /// queue: the lanes no longer hold what that parent's state is waiting
    /// for, so every lane's head is above its account nonce and the build
    /// can use none of them. See [`TxQueue::pruned_through`].
    pruned_through: u64,
    /// The sender a build is taking a run from, and how much of the run is
    /// left. See [`run_length`].
    current: Option<(Address, usize)>,
    /// Consecutive nonces a build takes from one sender before moving on.
    run: usize,
    /// Builds this queue has served, so a give-back line names the build
    /// that asked: two builds in flight on one parent are the shape this
    /// node's stale give-back came from, and the numbers tell them apart.
    builds: u64,
    /// The frames the ingest admitted whole ([`frames`]). Kept whether or
    /// not the chain builds frame blocks; nothing reads it unless asked.
    frames: frames::FrameIndex<T>,
    /// A chunked drain's remainder (`N42_TX_QUEUE_DRAIN_CHUNK`, see
    /// [`TxQueue::drain_now`]): transactions taken out of the inbox and not
    /// yet in their lanes, in inbox order. Counted in the depth mirror. Any
    /// other drain finishes it first, so the inbox's order is the lanes'
    /// order whoever drains.
    pending_drain: VecDeque<Arc<ValidPoolTransaction<T>>>,
    /// The frames noted with that remainder, indexed once its last
    /// transaction is in its lane (a frame is never indexed before its
    /// transactions are queued, as in the one-hold drain).
    pending_frames: Vec<(NewFrame, Option<FrameTxs<T>>)>,
    /// The child's frame plan, prepared while the build it follows is still
    /// executing (`N42_PLAN_AHEAD`, [`Prepared`]).
    prepared: Option<Prepared<T>>,
    /// The last hand-off that forgot a build's whole take as mined by an own
    /// block, and that block's hash ([`TxQueue::hold_own_block`]): what a
    /// prepared plan is accepted against.
    handed: Option<Handed>,
}

/// A whole take handed off to an own block: the build counter of the build
/// that took it, and the block's sealed hash once
/// [`TxQueue::hold_own_block`] names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handed {
    build: u64,
    block: Option<B256>,
}

/// The next build's frame plan, made right after the plan of the build it
/// follows (`N42_PLAN_AHEAD=1`, `docs/SHARED_EXECUTION_SCOPE.md` 12).
///
/// Made exactly as [`TxQueue::frames_for_build`] makes a plan, on the lanes
/// as they stand once the current build's take has left them: its frames
/// leave the lanes into `taken` (not the current build's taken list), so no
/// other build can take them, and the depth counts them as taken. Used by
/// the next frame build only when nothing that could make it differ from a
/// plan the fresh path could have made on that state has happened since
/// ([`Inner::prepared_verdict`]); otherwise given back, minus what the chain
/// has mined, before that build plans afresh.
struct Prepared<T: PoolTransaction> {
    /// `Inner::builds` when it was made: the build it follows.
    after: u64,
    /// The gas its frames take.
    gas_used: u64,
    /// Whether its last frame was cut to the gas (no top-up may follow a cut
    /// frame: the body would not be a run of frames).
    cut: bool,
    segments: Vec<(FrameTxs<T>, usize)>,
    plan: FramePlan,
    /// The lanes' `Arc`s it took, in plan order.
    taken: Vec<Arc<ValidPoolTransaction<T>>>,
    /// Per sender, the lowest nonce it took: nothing at or below the lane's
    /// mined watermark, and nothing below it in the lane, may exist when it
    /// is used.
    lowest: AddressHashMap<u64>,
    made_at: std::time::Instant,
    /// Its preparation, lock wait included.
    prep_us: u64,
}

/// Why a prepared plan was not used ([`FrameSelectTimes::ahead_discard`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AheadDiscard {
    /// Another build began after it was made.
    OtherBuild,
    /// The build it follows was not handed off whole to the block the new
    /// build stands on (refused, abandoned, another block at the height).
    NotOnItsParent,
    /// The previous build's take is still (partly) out: its block did not
    /// carry all of it.
    TakeLeft,
    /// The new build's gas limit is below what the plan takes.
    Gas,
    /// The chain mined a nonce the plan holds (a prune).
    Mined,
    /// A lane holds a nonce below the plan's (a give-back, an untake, a late
    /// arrival filling a hole).
    Below,
    /// A build that does not take frames (`best_for_build`).
    NotFrames,
}

impl AheadDiscard {
    /// The name it is logged under.
    pub const fn name(self) -> &'static str {
        match self {
            Self::OtherBuild => "other_build",
            Self::NotOnItsParent => "not_on_its_parent",
            Self::TakeLeft => "take_left",
            Self::Gas => "gas",
            Self::Mined => "mined",
            Self::Below => "below",
            Self::NotFrames => "not_frames",
        }
    }
}

/// The gas of the cheapest transaction: a prepared plan with less room
/// than this left is full, and no top-up is tried.
const MIN_FRAME_TX_GAS: u64 = 21_000;

/// Prepared plans discarded, by [`AheadDiscard`] reason, since the last
/// [`take_ahead_discards`].
static AHEAD_DISCARDS: [std::sync::atomic::AtomicU64; 7] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

const AHEAD_REASONS: [AheadDiscard; 7] = [
    AheadDiscard::OtherBuild,
    AheadDiscard::NotOnItsParent,
    AheadDiscard::TakeLeft,
    AheadDiscard::Gas,
    AheadDiscard::Mined,
    AheadDiscard::Below,
    AheadDiscard::NotFrames,
];

fn note_ahead_discard(reason: AheadDiscard) {
    if let Some(at) = AHEAD_REASONS.iter().position(|r| *r == reason) {
        AHEAD_DISCARDS[at].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Prepared plans discarded since the last call, by reason (name, count),
/// the zero ones left out; the call resets them.
pub fn take_ahead_discards() -> Vec<(&'static str, u64)> {
    AHEAD_REASONS
        .iter()
        .zip(&AHEAD_DISCARDS)
        .filter_map(|(reason, count)| {
            let n = count.swap(0, std::sync::atomic::Ordering::Relaxed);
            (n > 0).then_some((reason.name(), n))
        })
        .collect()
}

/// `N42_PLAN_AHEAD`, read once: a frame build prepares its child's plan
/// right after its own ([`Prepared`]). Off by default.
pub fn plan_ahead() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PLAN_AHEAD").is_ok_and(|v| v == "1"))
}

/// `N42_TX_QUEUE_DRAIN_CHUNK=<n>`, read once: the drainer
/// ([`TxQueue::drain_now`]) holds the lanes' lock for at most `n`
/// transactions at a time. 0 (the default) drains the whole inbox in one
/// hold, as before.
fn drain_chunk() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| std::env::var("N42_TX_QUEUE_DRAIN_CHUNK").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// How many consecutive nonces a build takes from one sender before moving
/// to the next: `N42_TX_QUEUE_RUN`, 1 by default (strict rotation).
///
/// A block drawn from a deep queue by strict rotation alternates among
/// every queued sender -- 6,000 of them at the bench tier -- so each
/// transaction touches two cold accounts; a block drawn from a shallow queue
/// alternates among the few dozen senders that have arrived, and the same
/// follower imports it at half the cost per transaction (round gcA1/gcB:
/// 2.1-2.3 us/tx for partial blocks, 4.0 for full ones of any size). Runs
/// keep a sender's account hot across its consecutive transactions.
fn run_length() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("N42_TX_QUEUE_RUN").ok().and_then(|v| v.parse().ok()).filter(|n: &usize| *n > 0).unwrap_or(1)
    })
}

/// `N42_COMPACT_BODY`, read once: the compact block body assembles a block
/// out of the by-hash index. `N42_BLOCK_BY_DESCRIPTION=1` implies it: that
/// road reads the same index, by reference instead of by copy.
fn compact_body() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_COMPACT_BODY").is_ok_and(|v| v == "1") || block_by_description())
}

/// `N42_BLOCK_BY_DESCRIPTION`, read once: a follower checks a compact body
/// against the block's transactions held by reference in this queue, and
/// copies them out for the execution beside the rest of its vote road.
///
/// Read here, as [`senders_from_queue`] is, so the execution layer's road and
/// the index it needs cannot disagree about whether the index is kept.
pub fn block_by_description() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BLOCK_BY_DESCRIPTION").is_ok_and(|v| v == "1"))
}

/// `N42_SENDERS_FROM_QUEUE`, read once: a follower takes the senders of a
/// foreign block out of the by-hash index instead of looking each one up in
/// the recovery caches. The whole block arrives as it always did; only the
/// senders come from here.
///
/// Read in this crate because the index it needs is this crate's, and the
/// follower's import asks the same function: one flag, one reading of the
/// environment, no way for the two to disagree about whether the index is
/// being kept.
pub fn senders_from_queue() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_SENDERS_FROM_QUEUE").is_ok_and(|v| v == "1"))
}

/// The by-hash index's bound, when one is kept: `N42_COMPACT_BODY=1`,
/// `N42_BLOCK_BY_DESCRIPTION=1` or `N42_SENDERS_FROM_QUEUE=1` turns it on
/// and `N42_COMPACT_BODY_INDEX` sets the bound. Either reader wants the same index over the same window, so
/// they share the bound as well as the switch.
///
/// The default holds about six full blocks at the bench tier, against a pool
/// the bench sizes at four (loop194 X2): the index must comfortably outlast
/// the deepest the queue runs, because the transactions a block names are
/// the *oldest* the queue holds and an index evicting in arrival order would
/// drop exactly those first. Only the map entries are new memory -- the
/// transactions themselves are the lanes' -- about 56 bytes each.
fn hash_index_capacity() -> Option<usize> {
    static CAP: OnceLock<Option<usize>> = OnceLock::new();
    *CAP.get_or_init(|| {
        if !(compact_body() || senders_from_queue()) {
            return None;
        }
        Some(
            std::env::var("N42_COMPACT_BODY_INDEX")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|n: &usize| *n > 0)
                .unwrap_or(1_000_000),
        )
    })
}

/// Wraps a transaction the way a lane holds it.
///
/// `transaction_id`'s sender part is derived from the address rather than
/// handed out by the lane, because the lane is not known here and nothing in
/// this queue or its builder ever reads it -- reth's `ValidPoolTransaction`
/// requires one, and its pool, which does read it, is not this. Two senders
/// may share it; nothing compares them.
/// Whether the frame index keeps each frame's transactions
/// ([`TxQueue::push_frame`]): `N42_FRAME_ARCS`, on unless `0`.
fn frame_arcs() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FRAME_ARCS").map_or(true, |v| v != "0"))
}

/// `staged` put in the order of `hashes`, the frame's: as it is when the
/// recovery kept the frame's order, matched by hash when it did not.
/// `None` when the two are not the same transactions.
fn frame_txs_in_order<T: PoolTransaction>(
    hashes: &[B256],
    staged: &[Arc<ValidPoolTransaction<T>>],
) -> Option<FrameTxs<T>> {
    if hashes.len() != staged.len() || hashes.is_empty() {
        return None;
    }
    if staged.iter().zip(hashes).all(|(tx, hash)| tx.hash() == hash) {
        return Some(FrameTxs::from(staged));
    }
    let by_hash: alloy_primitives::map::B256HashMap<&Arc<ValidPoolTransaction<T>>> =
        staged.iter().map(|tx| (*tx.hash(), tx)).collect();
    let ordered: Option<Vec<_>> = hashes.iter().map(|hash| by_hash.get(hash).map(|tx| Arc::clone(tx))).collect();
    ordered.map(FrameTxs::from)
}

fn valid_for<T: PoolTransaction>(
    transaction: T,
    now: std::time::Instant,
    origin: TransactionOrigin,
) -> Arc<ValidPoolTransaction<T>> {
    let sender = transaction.sender();
    let nonce = transaction.nonce();
    let id = SenderId::from(u64::from_be_bytes(
        sender.as_slice()[12..20].try_into().unwrap_or([0u8; 8]),
    ));
    Arc::new(ValidPoolTransaction {
        transaction,
        transaction_id: TransactionId::new(id, nonce),
        propagate: false,
        timestamp: now,
        origin,
        authority_ids: None,
    })
}

/// How many shards the by-hash index is split into. A block's assembly looks
/// up 163,000 hashes at once on the worker pool while the drain is inserting
/// the next block's worth, and the hashes spread evenly over the shards by
/// their first byte. One lock for the whole index serialises the two.
const HASH_INDEX_SHARDS: usize = 64;

/// One shard of the by-hash index: the transactions under their hashes, and
/// the order they were indexed in, so the oldest are evicted first.
struct HashShard<T: PoolTransaction> {
    by_hash: alloy_primitives::map::B256HashMap<Arc<ValidPoolTransaction<T>>>,
    order: VecDeque<B256>,
    /// Hashes dropped by [`TxQueue::forget_hashes`] whose place in `order`
    /// is still there; the bound skips them.
    removed: usize,
}

/// A by-hash view of the transactions that have passed through this queue.
///
/// Only ever a cache: a miss costs the caller a fallback, never correctness,
/// which is why eviction is a plain bound rather than a removal wired into
/// every path that takes a transaction out of the lanes. What it is for is
/// the compact block body (`N42_COMPACT_BODY`): a follower that has already
/// ingested, verified and queued every transaction of the block a leader is
/// proposing assembles that block from here, by the hashes the proposal
/// names, instead of receiving and decoding 26 MB of transactions it holds.
///
/// It deliberately keeps what a *build* took and what an own block holds:
/// those leave the lanes (`best_for_build`, `remove_mined_batch_collecting`)
/// but are exactly the transactions the next block names, and a follower
/// that was leader a moment ago must be able to assemble its successor's
/// block. Only the bound drops them.
struct HashIndex<T: PoolTransaction> {
    shards: Vec<parking_lot::RwLock<HashShard<T>>>,
    /// The bound per shard: the whole index holds `HASH_INDEX_SHARDS` times
    /// this many.
    per_shard: usize,
}

impl<T: PoolTransaction> HashIndex<T> {
    fn new(cap: usize) -> Self {
        let per_shard = cap.div_ceil(HASH_INDEX_SHARDS).max(1);
        Self {
            shards: (0..HASH_INDEX_SHARDS)
                .map(|_| {
                    parking_lot::RwLock::new(HashShard {
                        by_hash: Default::default(),
                        order: VecDeque::new(),
                        removed: 0,
                    })
                })
                .collect(),
            per_shard,
        }
    }

    fn shard_of(&self, hash: &B256) -> &parking_lot::RwLock<HashShard<T>> {
        // A transaction hash is a keccak output, so any byte of it spreads
        // evenly; the first is as good as any.
        &self.shards[usize::from(hash.0[0]) % HASH_INDEX_SHARDS]
    }

    fn insert(&self, transaction: &Arc<ValidPoolTransaction<T>>) {
        let hash = *transaction.hash();
        let mut shard = self.shard_of(&hash).write();
        if shard.by_hash.insert(hash, Arc::clone(transaction)).is_none() {
            shard.order.push_back(hash);
            // The bound counts what is *held*, so the places a canonical
            // prune has already emptied are stepped over rather than
            // counted.
            while shard.order.len().saturating_sub(shard.removed) > self.per_shard {
                let Some(oldest) = shard.order.pop_front() else { break };
                if shard.by_hash.remove(&oldest).is_none() {
                    shard.removed = shard.removed.saturating_sub(1);
                }
            }
        }
    }

    /// Removes every one of `hashes` the index holds and hands their `Arc`s
    /// back, to be freed by the caller with no shard locked.
    ///
    /// Grouped by shard first, then one write lock a shard -- not one a
    /// hash, 200,000 lock takes a block -- with the shards visited on the
    /// queue's small pool when the batch is large. Removing a hash the
    /// index does not hold is a no-op. The order list is walked only when
    /// the bound bites, and a hash no longer in the map is skipped there,
    /// so a removal costs one map operation rather than a scan.
    fn remove_all(&self, hashes: &[B256]) -> Vec<Arc<ValidPoolTransaction<T>>> {
        /// Below this a batch is removed in place, hash by hash.
        const BY_SHARD_FROM: usize = 1_024;
        if hashes.len() < BY_SHARD_FROM {
            let mut out = Vec::with_capacity(hashes.len());
            for hash in hashes {
                let mut shard = self.shard_of(hash).write();
                if let Some(held) = shard.by_hash.remove(hash) {
                    shard.removed = shard.removed.saturating_add(1);
                    out.push(held);
                }
            }
            return out;
        }
        let mut buckets: Vec<Vec<B256>> =
            (0..HASH_INDEX_SHARDS).map(|_| Vec::with_capacity(hashes.len() / HASH_INDEX_SHARDS + 16)).collect();
        for hash in hashes {
            buckets[usize::from(hash.0[0]) % HASH_INDEX_SHARDS].push(*hash);
        }
        let one_shard = |(at, bucket): (usize, &Vec<B256>)| {
            let mut out = Vec::with_capacity(bucket.len());
            if bucket.is_empty() {
                return out;
            }
            let mut shard = self.shards[at].write();
            for hash in bucket {
                if let Some(held) = shard.by_hash.remove(hash) {
                    out.push(held);
                }
            }
            shard.removed = shard.removed.saturating_add(out.len());
            out
        };
        let parts: Vec<Vec<Arc<ValidPoolTransaction<T>>>> = match forget_pool() {
            Some(pool) => {
                use rayon::prelude::*;
                pool.install(|| buckets.par_iter().enumerate().map(one_shard).collect())
            }
            None => buckets.iter().enumerate().map(one_shard).collect(),
        };
        let mut out = Vec::with_capacity(parts.iter().map(Vec::len).sum());
        for part in parts {
            out.extend(part);
        }
        out
    }

    fn get(&self, hash: &B256) -> Option<Arc<ValidPoolTransaction<T>>> {
        // A read lock, so the worker pool's 163,000 look-ups do not
        // serialise against each other while the drain writes the next
        // block's worth into another shard: 41-47 ns each at the bench tier
        // (`bench_hash_index`).
        self.shard_of(hash).read().by_hash.get(hash).cloned()
    }

    /// The sender alone, copied out under the read lock.
    ///
    /// Deliberately not `get(..).map(..)`: that clones the `Arc` -- a write
    /// to a refcount 163,000 times, on a line sixteen workers share with
    /// the ingest -- to read twenty bytes and drop it again. Here nothing
    /// leaves the index but the address.
    fn sender_of(&self, hash: &B256) -> Option<Address> {
        self.shard_of(hash).read().by_hash.get(hash).map(|held| held.transaction.sender())
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.read().by_hash.len()).sum()
    }
}

/// The queue. Cheap to clone; every clone is the same queue.
///
/// Pushes go to an inbox under their own lock, held for a `Vec` push; the
/// lanes' lock is taken only by the builder, the pruner and the feed's
/// drain. Sixty-four ingest connections pushing straight into the lanes
/// while a build took the lock 163,000 times and a prune held it for tens
/// of milliseconds put every node's runtime threads into a spin (round
/// prof3: 72% of a follower's samples on one kernel address).
pub struct TxQueue<T: PoolTransaction> {
    inner: Arc<Mutex<Inner<T>>>,
    inbox: Arc<Mutex<Vec<Arc<ValidPoolTransaction<T>>>>>,
    staged: Arc<std::sync::atomic::AtomicUsize>,
    /// The by-hash index, when this queue keeps one. `None` is the default
    /// and costs the drain nothing at all -- not a lock, not a hash.
    by_hash: Option<Arc<HashIndex<T>>>,
    /// Frames noted since the last drain, under their own lock for the same
    /// reason as `inbox`: the ingest notes one per frame, thousands a
    /// second, and must not wait on the lanes.
    frame_inbox: FrameInbox<T>,
    frames_staged: Arc<std::sync::atomic::AtomicUsize>,
    /// `Inner::pruned_through`, readable without the lanes' lock: a build
    /// reads it right after its selection, while the selection's takes may
    /// still be leaving the lanes ([`Inner::settle`]).
    pruned_mirror: Arc<std::sync::atomic::AtomicU64>,
    /// The lanes' `len` and `parked_len` as of the last release of their
    /// lock ([`pack_depth`]), and raised by a drain before it subtracts what
    /// it takes from `staged`: what [`Self::gate_len`] reads instead of
    /// taking the lock.
    depth: Arc<std::sync::atomic::AtomicU64>,
    /// A chunked drain's batch between the inbox and `Inner::pending_drain`
    /// (taken out of `staged`, not yet under the lanes' lock): counted by
    /// [`Self::gate_len`], so the batch is never in none of the readings.
    in_hand: Arc<std::sync::atomic::AtomicUsize>,
    /// `N42_TX_QUEUE_DRAIN_CHUNK` unless a test said otherwise.
    drain_chunk: Arc<std::sync::atomic::AtomicUsize>,
}

/// Frames noted since the last drain, each with its transactions when the
/// ingest handed them over ([`TxQueue::push_frame`]).
type FrameInbox<T> = Arc<Mutex<Vec<(NewFrame, Option<FrameTxs<T>>)>>>;

impl<T: PoolTransaction> Clone for TxQueue<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            inbox: Arc::clone(&self.inbox),
            staged: Arc::clone(&self.staged),
            by_hash: self.by_hash.clone(),
            frame_inbox: Arc::clone(&self.frame_inbox),
            pruned_mirror: Arc::clone(&self.pruned_mirror),
            frames_staged: Arc::clone(&self.frames_staged),
            depth: Arc::clone(&self.depth),
            in_hand: Arc::clone(&self.in_hand),
            drain_chunk: Arc::clone(&self.drain_chunk),
        }
    }
}

impl<T: PoolTransaction> std::fmt::Debug for TxQueue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxQueue").field("len", &self.len()).finish()
    }
}

impl<T: PoolTransaction> Default for TxQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PoolTransaction> TxQueue<T> {
    /// An empty queue, taking runs of `N42_TX_QUEUE_RUN` per sender, with
    /// the by-hash index iff `N42_COMPACT_BODY=1` asked for one.
    pub fn new() -> Self {
        let queue = Self::with_run_length(run_length());
        match hash_index_capacity() {
            Some(cap) => queue.with_hash_index(cap),
            None => queue,
        }
    }

    /// The same queue keeping a by-hash index of up to `cap` transactions.
    /// What a test uses to choose the path without the process environment
    /// deciding for it.
    #[must_use]
    pub fn with_hash_index(mut self, cap: usize) -> Self {
        self.by_hash = Some(Arc::new(HashIndex::new(cap)));
        self
    }

    /// The same queue parking at most `lanes` lanes behind a hole; 0 is no
    /// parking, which is the default ([`park_lane_cap`]). What a test uses
    /// to choose the path without the process environment deciding for it.
    #[must_use]
    pub fn with_park_lanes(self, lanes: usize) -> Self {
        self.lock_inner().park_lanes = lanes;
        self
    }

    /// Whether this queue keeps a by-hash index.
    pub const fn has_hash_index(&self) -> bool {
        self.by_hash.is_some()
    }

    /// How many transactions the by-hash index holds; 0 without one.
    pub fn hash_index_len(&self) -> usize {
        self.by_hash.as_ref().map_or(0, |index| index.len())
    }

    /// The transactions for `hashes`, in the same order, `None` where the
    /// index does not hold one -- the transaction never reached this node,
    /// is still in the inbox, or has been evicted. Nothing is removed: the
    /// canonical prune is what takes a block's transactions out, as it
    /// always was.
    ///
    /// Looked up on the worker pool: 163,000 of them sequentially is 10-16
    /// ms of a vote road whose whole budget is ~140.
    pub fn get_by_hashes(&self, hashes: &[B256]) -> Vec<Option<Arc<ValidPoolTransaction<T>>>>
    where
        T: Send + Sync,
    {
        let Some(index) = self.by_hash.as_ref() else {
            return vec![None; hashes.len()];
        };
        use rayon::prelude::*;
        hashes.par_iter().map(|hash| index.get(hash)).collect()
    }

    /// [`Self::get_by_hashes`] for one hash, on the caller's thread: what a
    /// caller that walks a block in chunks on the worker pool uses, so the
    /// look-up and whatever it does with the transaction happen on the same
    /// worker while the transaction is in its cache.
    pub fn get_by_hash(&self, hash: &B256) -> Option<Arc<ValidPoolTransaction<T>>> {
        self.by_hash.as_ref().and_then(|index| index.get(hash))
    }

    /// The sender this node recorded for `hash` when the transaction came
    /// in, or `None` where the index does not hold it -- no index kept, the
    /// transaction never reached this node, it is still in the inbox, or it
    /// has been evicted.
    ///
    /// The sender is this node's own recovery from the signature (the
    /// ingest's, the pool's, or a reverted block's), never a peer's word for
    /// it: nothing puts a transaction in this queue without having recovered
    /// its sender first. Copies nothing but the address.
    pub fn sender_of(&self, hash: &B256) -> Option<Address> {
        self.by_hash.as_ref().and_then(|index| index.sender_of(hash))
    }

    /// [`Self::get_by_hashes`], handing back what a block's assembly
    /// actually wants -- the transaction and the sender this node recorded
    /// for it -- rather than the queue's `Arc`.
    ///
    /// One pass, not two. Taking the `Arc`s first and copying out of them
    /// afterwards touches each of 163,000 transactions twice, and the second
    /// touch is a serial walk over objects a dozen ingest threads allocated
    /// at arbitrary times: on the fleet that pass was most of a 112-116 ms
    /// assembly (loop196) against 22 ms on an idle box, where the same
    /// objects are contiguous and warm. Here the copy happens on the worker
    /// that did the look-up, while the transaction is in its cache.
    pub fn recovered_by_hashes(
        &self,
        hashes: &[B256],
    ) -> Vec<Option<(T::Consensus, Address)>>
    where
        T: Send + Sync,
        T::Consensus: Send,
    {
        let Some(index) = self.by_hash.as_ref() else {
            return (0..hashes.len()).map(|_| None).collect();
        };
        use rayon::prelude::*;
        hashes
            .par_iter()
            .map(|hash| index.get(hash).map(|held| held.transaction.clone_into_consensus().into_parts()))
            .collect()
    }

    /// An empty queue taking `run` consecutive nonces per sender per turn.
    pub fn with_run_length(run: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                lanes: AddressHashMap::default(),
                arrivals: VecDeque::new(),
                len: 0,
                last_build: None,
                pending: Vec::new(),
                gaps: Vec::new(),
                held: VecDeque::new(),
                parked_order: VecDeque::new(),
                parked_len: 0,
                drops: DropReport::default(),
                park_capped: 0,
                park_lanes: park_lane_cap(),
                pruned_through: 0,
                current: None,
                run: run.max(1),
                builds: 0,
                frames: frames::FrameIndex::default(),
                pending_drain: VecDeque::new(),
                pending_frames: Vec::new(),
                prepared: None,
                handed: None,
            })),
            inbox: Arc::new(Mutex::new(Vec::new())),
            staged: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            by_hash: None,
            frame_inbox: Arc::new(Mutex::new(Vec::new())),
            frames_staged: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            pruned_mirror: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            depth: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            in_hand: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            drain_chunk: Arc::new(std::sync::atomic::AtomicUsize::new(drain_chunk())),
        }
    }

    /// The same queue draining at most `chunk` transactions per hold of the
    /// lanes' lock in [`Self::drain_now`]; 0 is one hold. What a test uses to
    /// choose the path without the process environment deciding for it.
    #[must_use]
    pub fn with_drain_chunk(self, chunk: usize) -> Self {
        self.drain_chunk.store(chunk, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// The lanes' lock, with a frame build's noted takes applied first
    /// ([`Inner::settle`]): every lock of the queue goes through here, so
    /// no caller ever sees the lanes before them.
    ///
    /// Timed ([`TimedInner`]): a hold or a wait of a second or more is said
    /// once, naming the caller, so a multi-second stall of everything that
    /// touches the queue (loop320 FAS, loop322 CTRL: the new leader's queue
    /// prune 5 s, the own block's hand-off and every finish behind it) names
    /// its holder.
    #[track_caller]
    fn lock_inner(&self) -> TimedInner<'_, T> {
        let caller = std::panic::Location::caller();
        let asked = std::time::Instant::now();
        let mut inner = self.inner.lock();
        let at = std::time::Instant::now();
        inner.settle();
        TimedInner { guard: inner, at, waited: at.saturating_duration_since(asked), caller, mirror: &self.depth }
    }

    /// Moves what was pushed since the last drain into the lanes. Called
    /// with the lanes' lock held; a no-op when nothing was pushed.
    fn drain_inbox(&self, inner: &mut Inner<T>) {
        use std::sync::atomic::Ordering;
        // A chunked drain's remainder is older than anything in the inbox:
        // it goes into the lanes first, whoever drains.
        if !inner.pending_drain.is_empty() || !inner.pending_frames.is_empty() {
            let at = std::time::Instant::now();
            let moved = inner.drain_pending(usize::MAX) as u64;
            let took = at.elapsed().as_nanos() as u64;
            let c = &LOCK_COUNTERS;
            c.drain_finished.fetch_add(1, Ordering::Relaxed);
            c.drain_txs.fetch_add(moved, Ordering::Relaxed);
            c.drain_ns.fetch_add(took, Ordering::Relaxed);
            raise_max(&c.drain_max_ns, took);
        }
        if self.frames_staged.load(Ordering::Acquire) != 0 {
            let mut noted = self.frame_inbox.lock();
            let frames = std::mem::take(&mut *noted);
            self.frames_staged.fetch_sub(frames.len(), Ordering::AcqRel);
            drop(noted);
            for (frame, txs) in frames {
                inner.frames.insert(frame, txs);
            }
        }
        if self.staged.load(Ordering::Acquire) == 0 {
            return;
        }
        // Taken and counted down under the inbox's lock, as a push adds
        // under it: a drain that took a batch a push had already put in the
        // inbox but not yet counted subtracted more than the counter held,
        // and `staged` -- which the ingest gate reads through `len` --
        // wrapped to about 2^64 until the push's own increment landed. It
        // healed itself in a few nanoseconds, but a gate that reads it in
        // that window shuts, and a debug build's `inner.len + staged`
        // overflows.
        let mut inbox = self.inbox.lock();
        let staged = std::mem::take(&mut *inbox);
        // The depth mirror counts the batch before `staged` lets go of it,
        // so a gate reading the two without the lanes' lock never sees the
        // batch in neither (an undercount that would open the gate for the
        // drain's length). Between the two it is counted twice -- the safe
        // side, a gate shut a few nanoseconds early -- and the release of
        // this lock stores the exact value again.
        self.depth.fetch_add(staged.len() as u64, Ordering::AcqRel);
        self.staged.fetch_sub(staged.len(), Ordering::AcqRel);
        drop(inbox);
        // Lanes only. Nothing here touches the by-hash index: this runs
        // under the lanes' lock, with the builder's puller waiting on it.
        let at = std::time::Instant::now();
        let count = staged.len() as u64;
        for valid in staged {
            inner.insert_valid(valid);
        }
        let took = at.elapsed().as_nanos() as u64;
        let c = &LOCK_COUNTERS;
        c.drains.fetch_add(1, Ordering::Relaxed);
        c.drain_txs.fetch_add(count, Ordering::Relaxed);
        c.drain_ns.fetch_add(took, Ordering::Relaxed);
        raise_max(&c.drain_max_ns, took);
    }

    /// Notes a frame the ingest admitted whole: its id (root), its
    /// transactions' hashes and (sender, nonce) in frame order, and its gas.
    /// Call it after the frame's transactions were pushed. O(1) on the
    /// caller's side: the frame waits in an inbox for the next drain, as the
    /// transactions do. A frame already indexed, or one whose record is
    /// malformed, is ignored.
    pub fn note_frame(&self, frame: NewFrame) {
        self.stage_frame(frame, None);
    }

    fn stage_frame(&self, frame: NewFrame, txs: Option<FrameTxs<T>>) {
        let mut noted = self.frame_inbox.lock();
        noted.push((frame, txs));
        self.frames_staged.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// [`Self::push`] and then [`Self::note_frame`] for a frame the ingest
    /// admitted whole, with the index keeping the queue's own `Arc`s of the
    /// frame's transactions in frame order ([`FrameTxs`]): what
    /// [`Self::take_frames`] then hands out, one clone a frame, instead of
    /// finding each transaction in its lane.
    ///
    /// The transactions are matched to the frame's hashes here, on the
    /// caller's thread (in order, or by hash when the recovery reordered
    /// them); a list that does not match is not kept and the frame reads
    /// from the lanes. `N42_FRAME_ARCS=0` keeps no `Arc`s at all.
    pub fn push_frame(&self, transactions: Vec<T>, frame: Option<NewFrame>) {
        let now = std::time::Instant::now();
        let staged: Vec<Arc<ValidPoolTransaction<T>>> = transactions
            .into_iter()
            .map(|transaction| valid_for(transaction, now, TransactionOrigin::External))
            .collect();
        let txs = frame.as_ref().filter(|_| frame_arcs()).and_then(|frame| frame_txs_in_order(&frame.hashes, &staged));
        self.index_and_stage(staged);
        if let Some(frame) = frame {
            self.stage_frame(frame, txs);
        }
    }

    /// How many frames the index holds, counting those still in its inbox.
    pub fn frames_indexed(&self) -> usize {
        self.lock_inner().frames.len() + self.frames_staged.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The indexed frames in the order they arrived, each with its count,
    /// gas and whether a build could take it whole right now
    /// ([`FrameRef::whole_usable`]).
    ///
    /// One pass over the index under the lanes' lock; the whole-usable test
    /// walks each run's lane from its head to the run, so this costs about
    /// one lane step per queued transaction -- a per-build call, not a
    /// per-transaction one.
    pub fn frames_in_arrival_order(&self) -> impl Iterator<Item = FrameRef> + use<T> {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        inner.frames.in_arrival_order(&inner.lanes).into_iter()
    }

    /// The transactions of each frame in `ids`, in frame order, by
    /// reference: the queue's own `Arc`s, shared, nothing copied. Nothing
    /// is taken out of the lanes -- this is a read for the vote road.
    ///
    /// A frame noted with its transactions ([`Self::push_frame`]) is one
    /// map look-up and one clone of its [`FrameTxs`]: the transactions are
    /// the frame's whatever has happened to the lanes since (a build took
    /// them, an own block not yet committed holds them), and they leave
    /// with the frame when the chain mines any of them.
    ///
    /// A frame noted without them: each transaction is found in its lane by
    /// (sender, nonce) and checked against the frame's hash; one that is
    /// not there (a build took it) is looked up in the by-hash index when
    /// the queue keeps one. `None` for a frame the index does not hold or
    /// one with any transaction found in neither place.
    pub fn take_frames(&self, ids: &[B256]) -> Vec<Option<FrameTxs<T>>> {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        ids.iter()
            .map(|id| {
                if let Some(txs) = inner.frames.txs_of(id) {
                    return Some(txs);
                }
                let members = inner.frames.members_of(id)?;
                let mut out = Vec::with_capacity(members.len());
                for (sender, nonce, hash) in members {
                    let held = inner
                        .lanes
                        .get(&sender)
                        .and_then(|lane| lane.by_nonce.get(&nonce))
                        .filter(|held| *held.hash() == hash)
                        .cloned()
                        .or_else(|| self.by_hash.as_ref().and_then(|index| index.get(&hash)))?;
                    out.push(held);
                }
                Some(FrameTxs::from(out))
            })
            .collect()
    }

    /// How many indexed frames hold their transactions ([`Self::push_frame`]).
    /// For tests and the prune's report.
    pub fn frames_with_txs(&self) -> usize {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        inner.frames.with_txs()
    }

    /// Records that a canonical block at `number` has been pruned out of the
    /// lanes. Only the highest is kept.
    pub fn note_pruned(&self, number: u64) {
        let mut inner = self.lock_inner();
        inner.pruned_through = inner.pruned_through.max(number);
        self.pruned_mirror.fetch_max(number, std::sync::atomic::Ordering::AcqRel);
    }

    /// The highest block a canonical prune has taken out of the lanes.
    ///
    /// What a build compares its parent against: a parent below this is
    /// behind the queue, and every lane will look gapped to it whatever the
    /// lanes actually hold. Nothing here acts on that -- it is a reading for
    /// the builder to take.
    pub fn pruned_through(&self) -> u64 {
        self.pruned_mirror.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The holes builds ran into since the last call: (sender, first missing
    /// nonce, first queued nonce above the hole). A hole is a transaction the
    /// queue never saw -- the pool's listener drops on a full channel -- or
    /// one still on its way in; the feed looks the pool up for it.
    pub fn take_gaps(&self) -> Vec<(Address, u64, u64)> {
        std::mem::take(&mut self.lock_inner().gaps)
    }

    /// How many transactions are queued.
    pub fn len(&self) -> usize {
        use std::sync::atomic::Ordering;
        let inner = self.lock_inner();
        inner.len
            + inner.pending_drain.len()
            + self.staged.load(Ordering::Acquire)
            + self.in_hand.load(Ordering::Acquire)
    }

    /// How many of them a build could take now: what [`Self::len`] counts,
    /// less the lanes parked behind a hole ([`Parked`]) and less the inbox,
    /// which the next drain moves into the lanes.
    ///
    /// Beside `queued` this is what says whether a short block was the
    /// queue running dry or the queue being deep and unusable -- the two
    /// look identical from the builder's side, and loop207's defect 13 was
    /// the second (`queued=334-360k` with every build finding nothing).
    /// One walk of the lanes (~6,000 at the bench tier), so it belongs on a
    /// per-block line and not in a loop.
    pub fn usable(&self) -> usize {
        let mut inner = self.lock_inner();
        // What is in the inbox is a build away from the lanes -- the next
        // pull drains it -- so it counts, and counting it means draining
        // it. The drainer task normally leaves nothing to do here.
        self.drain_inbox(&mut inner);
        inner.usable()
    }

    /// The depth the ingest's gate is held against: everything queued, less
    /// what no build can take because its lane is parked behind a hole
    /// ([`Parked`]).
    ///
    /// O(1) -- the gate asks once per frame. Counting the parked lanes here
    /// is what stops a hole from starving a node: on loop209 Pa node3's
    /// parked lanes held its depth at 569,520 against a gate of 543,333,
    /// the flood was held off, nothing was mined so nothing was pruned, and
    /// the node built empty blocks until its tenure ended.
    ///
    /// Read without the lanes' lock: the lanes' part is the depth mirror,
    /// stored at every release of the lock, and the inbox's part is the
    /// live `staged` counter. So the reading is exact whenever nobody holds
    /// the lock, and while somebody does it is the depth as of the last
    /// release (the staleness is one hold: a build's take, a prune's
    /// removal, a give-back are seen when their hold ends). A drain is the
    /// exception that is never undercounted: it raises the mirror before it
    /// takes its batch out of `staged` ([`Self::drain_inbox`]). Taking the
    /// lock here put every ingest connection behind any 17-24 ms removal
    /// (`docs/SHARED_EXECUTION_SCOPE.md` 10.2).
    pub fn gate_len(&self) -> usize {
        use std::sync::atomic::Ordering;
        // `staged` first: a drain moves a batch from it into the mirror,
        // and with the mirror read second the batch is in at least one of
        // the two readings (the mirror is raised before `staged` drops).
        let staged = self.staged.load(Ordering::Acquire) as u64;
        // A chunked drain's batch moves `staged` -> `in_hand` -> the mirror,
        // each step adding to the next before taking from the last: read in
        // that order, the batch is in at least one of the readings.
        let in_hand = self.in_hand.load(Ordering::Acquire) as u64;
        let (len, parked) = unpack_depth(self.depth.load(Ordering::Acquire));
        usize::try_from((len + staged + in_hand).saturating_sub(parked)).unwrap_or(usize::MAX)
    }

    /// [`Self::gate_len`] read under the lanes' lock, as it was before the
    /// mirror: the reference the tests hold the mirror against.
    pub fn gate_len_locked(&self) -> usize {
        use std::sync::atomic::Ordering;
        let inner = self.lock_inner();
        (inner.len
            + inner.pending_drain.len()
            + self.staged.load(Ordering::Acquire)
            + self.in_hand.load(Ordering::Acquire))
        .saturating_sub(inner.parked_len)
    }

    /// What the queue has let go of since the last call, by reason, with
    /// the first few named ([`Dropped`]). Taking it clears it, so a caller
    /// logging this reports a window and not a running total.
    pub fn take_drops(&self) -> DropReport {
        std::mem::take(&mut self.lock_inner().drops)
    }

    /// The lanes parked behind a hole, how many transactions they hold, and
    /// how many parks the cap has refused since the process started.
    pub fn parked(&self) -> (usize, usize, u64) {
        let inner = self.lock_inner();
        (inner.parked_order.len(), inner.parked_len, inner.park_capped)
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queues validated, recovered transactions. A (sender, nonce) already
    /// queued keeps its first arrival.
    ///
    /// The `Arc` a lane will hold is made here, on the caller's thread --
    /// the ingest's -- rather than in the drain: the drain runs under the
    /// lanes' lock, and the builder's puller is what waits behind it
    /// (`QueueBest::next`). Making it here also lets the by-hash index be
    /// written here, off every lock this queue has. See [`HashIndex`].
    pub fn push(&self, transactions: impl IntoIterator<Item = T>) {
        let now = std::time::Instant::now();
        self.index_and_stage(
            transactions
                .into_iter()
                .map(|transaction| valid_for(transaction, now, TransactionOrigin::External))
                .collect(),
        );
    }

    /// Queues transactions the pool has already validated, as the pool holds
    /// them. What the pool's new-transaction listener yields; the queue is a
    /// view of the pool's arrivals, whichever door they came in by.
    pub fn push_valid(&self, transactions: impl IntoIterator<Item = Arc<ValidPoolTransaction<T>>>) {
        self.index_and_stage(transactions.into_iter().collect());
    }

    /// Indexes what was pushed and puts it in the inbox.
    ///
    /// The index first and outside the inbox's lock, because it is the one
    /// thing here that another thread can be reading at the same time: a
    /// block's assembly takes 163,000 read locks across the worker pool, and
    /// a writer that held the queue's lock while waiting for them put the
    /// builder's pull from 22 ms to 103 (loop195 P2).
    fn index_and_stage(&self, staged: Vec<Arc<ValidPoolTransaction<T>>>) {
        if let Some(index) = self.by_hash.as_ref() {
            for transaction in &staged {
                index.insert(transaction);
            }
        }
        let count = staged.len();
        // Counted under the inbox's lock, so the counter and the inbox
        // always agree for a drain that holds it (see `drain_inbox`).
        let mut inbox = self.inbox.lock();
        inbox.extend(staged);
        self.staged.fetch_add(count, std::sync::atomic::Ordering::AcqRel);
    }

    /// Forgets `hashes`, for a block the chain has committed: nothing will
    /// ever name those transactions in a new block again, so the index need
    /// not carry them until its bound reaches them.
    ///
    /// Only for canonical blocks. An own block whose height the chain has
    /// not settled must stay findable: its transactions go back to the lanes
    /// if another block takes the height, and the block after that names
    /// them.
    pub fn forget_hashes(&self, hashes: impl IntoIterator<Item = B256>) {
        let Some(index) = self.by_hash.as_ref() else { return };
        let hashes: Vec<B256> = hashes.into_iter().collect();
        // One write lock a shard; what leaves is freed after the locks.
        drop(index.remove_all(&hashes));
    }

    /// Puts transactions a build took but will not offer to the builder back
    /// where they were, and forgets that the build took them.
    ///
    /// What [`QueueBest`] does for its own buffer when a build ends early,
    /// for a caller that buffers between the two -- the builder's check of
    /// claimed senders, which pulls a batch ahead of what the build asks
    /// for. Without it those transactions would sit in the build's taken
    /// list for ever: not in a lane, not in a block.
    pub fn untake(&self, transactions: Vec<Arc<ValidPoolTransaction<T>>>) {
        if transactions.is_empty() {
            return;
        }
        let returned = Returned::new(transactions);
        let mut inner = self.lock_inner();
        inner.untake_all(returned);
    }

    /// Forgets a transaction a build took and will not use: it leaves the
    /// build's taken list without going back to the lanes, and its hash
    /// leaves the by-hash index.
    ///
    /// The one caller is the builder's check of a claimed sender
    /// (`N42_INGEST_VERIFY=leader`): a transaction whose signature names a
    /// different sender than the frame claimed can never be mined under the
    /// lane it sits in, so giving it back would offer it to every later
    /// build, and leaving it in the taken list would let the next give-back
    /// put it in the lanes again (the shape section 2ad of the plan took
    /// apart). Its sender's other nonces are untouched: the claim was wrong
    /// about this transaction and says nothing about them.
    pub fn forget_taken(&self, transaction: &Arc<ValidPoolTransaction<T>>) {
        {
            let mut inner = self.lock_inner();
            if let Some((_, taken)) = inner.last_build.as_mut()
                && let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction))
            {
                taken.remove(at);
            }
        }
        self.forget_hashes([*transaction.hash()]);
    }

    /// Queues the transactions of reverted blocks. The chain no longer holds
    /// them, so each sender's mined watermark drops below what comes back:
    /// otherwise the give-back filter would treat them as mined the first
    /// time a build handed one back, and the reorg's whole point (round 43:
    /// half-empty blocks for the rest of the leg) would be lost again.
    pub fn push_reverted(&self, transactions: Vec<T>) {
        {
            let mut inner = self.lock_inner();
            for transaction in &transactions {
                let sender = transaction.sender();
                let nonce = transaction.nonce();
                if let Some(lane) = inner.lanes.get_mut(&sender) {
                    lane.unmine(nonce);
                }
            }
        }
        self.push(transactions);
    }

    /// Drops everything at or below `nonce` for `sender`, and records it as
    /// the sender's mined watermark: a block carrying (sender, nonce) has
    /// made every lower nonce unusable as well, for good.
    pub fn remove_mined(&self, sender: Address, nonce: u64) {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        inner.remove_mined(sender, nonce);
        let Inner { frames, lanes, .. } = &mut *inner;
        frames.sweep(lanes);
    }

    /// Drops a batch of mined (sender, nonce) pairs and raises the senders'
    /// mined watermarks, so nothing at or below them can be queued again.
    /// For canonical blocks only -- see [`Self::remove_mined_batch_collecting`]
    /// for a block of this node's that consensus has not committed yet.
    pub fn remove_mined_batch(&self, mined: impl IntoIterator<Item = (Address, u64)>)
    where
        T: 'static,
    {
        // Folded to the highest nonce per sender first, outside the lock: a
        // lane is split once per sender, not once per transaction.
        // Splitting per transaction was 163,000 tree splits and as many
        // allocations a block, 54-128 ms under the lock the next build's
        // puller is waiting on.
        let highest = fold_highest(mined);
        let mut garbage = PruneGarbage::default();
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        inner.remove_mined_highest(&highest, &mut garbage);
        drop(inner);
        garbage.free();
    }

    /// A canonical block's whole prune, in the order the node's pruner ran
    /// its three steps: the own block held at `number` settled
    /// ([`Self::settle_own_block`]), the block's `(sender, nonce)` pairs out
    /// of the lanes, the frame index and the build's taken list
    /// ([`Self::remove_mined_batch`]), and its `hashes` out of the by-hash
    /// index ([`Self::forget_hashes`]). Returns how many transactions the
    /// settle gave back, and where the time went.
    ///
    /// The result is that of the three calls in sequence; what differs is
    /// the cost (`docs/SHARED_EXECUTION_SCOPE.md` 10.1 and 11: 49-65 ms per
    /// 200,000-transaction block, serial, on a runtime worker):
    /// - the fold of the block's pairs runs outside the lock and follows the
    ///   block's runs (a frame is one sender's consecutive nonces), so a
    ///   200,000-transaction block is a few hundred map operations;
    /// - a lane whose head is already above the mined nonce (the leader's
    ///   case: its build took them) is not split;
    /// - the build's taken list is split in one pass, again by runs;
    /// - the frame sweep drops each dead frame's own `by_first` entry
    ///   instead of re-walking every frame's;
    /// - the by-hash index is visited one shard at a time (one write lock a
    ///   shard, not one a hash), on the queue's small pool;
    /// - nothing is freed under a lock: every `Arc` that leaves the lanes,
    ///   the taken list, the frame index or the by-hash index is collected
    ///   and handed at the end (`free_us`) to the queue's freeing thread,
    ///   with no lock held ([`freeing_thread`]).
    pub fn prune_block(
        &self,
        number: u64,
        hash: B256,
        mined: &[(Address, u64)],
        hashes: &[B256],
    ) -> (usize, PruneTimes)
    where
        T: 'static,
    {
        let mut times = PruneTimes::default();
        let at = std::time::Instant::now();
        // Built only if an own block is held at this height (rarely): a
        // 200,000-entry set every block on every node was 10-20 ms.
        let carried = std::cell::OnceCell::new();
        let back = self.settle_own_block(number, hash, |sender, nonce| {
            carried
                .get_or_init(|| mined.iter().copied().collect::<std::collections::HashSet<(Address, u64)>>())
                .contains(&(*sender, nonce))
        });
        times.settle_us = at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        let highest = fold_highest(mined.iter().copied());
        times.senders = highest.len();
        times.fold_us = at.elapsed().as_micros() as u64;
        let mut garbage = PruneGarbage::default();
        let at = std::time::Instant::now();
        {
            let mut inner = self.lock_inner();
            times.lock_us = at.elapsed().as_micros() as u64;
            let held = std::time::Instant::now();
            self.drain_inbox(&mut inner);
            times.frames_swept = inner.remove_mined_highest(&highest, &mut garbage);
            times.remove_us = held.elapsed().as_micros() as u64;
        }
        let at = std::time::Instant::now();
        if let Some(index) = self.by_hash.as_ref() {
            garbage.index = index.remove_all(hashes);
        }
        times.forget_us = at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        times.freed = garbage.len();
        garbage.free();
        times.free_us = at.elapsed().as_micros() as u64;
        (back, times)
    }

    /// [`Self::remove_mined_batch`], returning what it removed from the
    /// lanes and from the build's taken list, for [`Self::hold_own_block`].
    ///
    /// The block is this node's own and not committed yet, so unlike the
    /// canonical prune this does *not* raise the senders' mined watermarks:
    /// [`Self::settle_own_block`] has to be able to give these back if
    /// consensus commits another block at the height.
    pub fn remove_mined_batch_collecting(
        &self,
        mined: impl IntoIterator<Item = (Address, u64)>,
    ) -> Vec<Arc<ValidPoolTransaction<T>>> {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        let mut highest: AddressHashMap<u64> = AddressHashMap::default();
        for (sender, nonce) in mined {
            let entry = highest.entry(sender).or_insert(nonce);
            *entry = (*entry).max(nonce);
        }
        let mut removed = Vec::new();
        for (sender, nonce) in &highest {
            if let Some(lane) = inner.lanes.get_mut(sender) {
                let keep = lane.by_nonce.split_off(&(nonce + 1));
                let gone = std::mem::replace(&mut lane.by_nonce, keep);
                // A parked lane keeps its park here -- this block is this
                // node's own and not committed, so it says nothing about
                // the hole -- but what it no longer holds must leave the
                // parked total.
                let parked = lane.parked.is_some();
                inner.len -= gone.len();
                if parked {
                    inner.parked_len = inner.parked_len.saturating_sub(gone.len());
                }
                removed.extend(gone.into_values());
            }
        }
        if let Some((_, taken)) = inner.last_build.as_mut() {
            if !taken.is_empty() {
                let (mined, kept): (Vec<_>, Vec<_>) = std::mem::take(taken)
                    .into_iter()
                    .partition(|t| highest.get(&t.sender()).is_some_and(|m| t.nonce() <= *m));
                *taken = kept;
                removed.extend(mined);
            }
        }
        removed
    }

    /// Keeps the transactions an own block took out of the queue until the
    /// chain settles that height; see `Inner::held`.
    pub fn hold_own_block(&self, number: u64, hash: B256, transactions: Vec<Arc<ValidPoolTransaction<T>>>) {
        const HELD_BLOCKS: usize = 16;
        if transactions.is_empty() {
            return;
        }
        let mut inner = self.lock_inner();
        // The block a whole hand-off just forgot the take of: what a plan
        // prepared ahead of the next build is accepted against.
        let build = inner.builds;
        if let Some(handed) = inner.handed.as_mut()
            && handed.build == build
            && handed.block.is_none()
        {
            handed.block = Some(hash);
        }
        while inner.held.len() >= HELD_BLOCKS {
            let Some((evicted, _, gone)) = inner.held.pop_front() else { break };
            // Nothing else holds these: the block they were taken for was
            // never settled, so this is a hole in every lane they came
            // from. Said out loud rather than counted alone.
            for valid in &gone {
                inner.dropped(Dropped::HeldEvicted, valid.sender(), valid.nonce());
            }
            tracing::warn!(
                target: "n42.tx_queue",
                number = evicted,
                txs = gone.len(),
                holding = number,
                "an own block was still held when the bound was reached; its transactions are lost to the queue"
            );
        }
        inner.held.push_back((number, hash, transactions));
    }

    /// The chain committed `hash` at `number`: an own block held at that
    /// height is settled -- dropped if it is that block, otherwise its
    /// transactions that the committed block does not carry (`carried`
    /// says which (sender, nonce) it does) go back to the lanes. Returns how
    /// many went back. Heights the chain has passed are dropped too.
    pub fn settle_own_block(&self, number: u64, hash: B256, carried: impl Fn(&Address, u64) -> bool) -> usize {
        let mut inner = self.lock_inner();
        if inner.held.is_empty() {
            return 0;
        }
        let mut back = Vec::new();
        let mut kept = VecDeque::with_capacity(inner.held.len());
        let mut behind: Vec<(u64, Vec<Arc<ValidPoolTransaction<T>>>)> = Vec::new();
        for (held_number, held_hash, transactions) in std::mem::take(&mut inner.held) {
            if held_number == number && held_hash != hash {
                back.extend(transactions.into_iter().filter(|t| !carried(&t.sender(), t.nonce())));
            } else if held_number > number {
                kept.push_back((held_number, held_hash, transactions));
            } else if held_number < number {
                // A height the chain has passed with this block still held:
                // the pruner should have settled it at its own height, so
                // this is a hole and not housekeeping.
                behind.push((held_number, transactions));
            }
            // The same hash at this height: settled, and mined.
        }
        inner.held = kept;
        for (held_number, gone) in behind {
            for valid in &gone {
                inner.dropped(Dropped::HeldBehind, valid.sender(), valid.nonce());
            }
            tracing::warn!(
                target: "n42.tx_queue",
                number = held_number,
                txs = gone.len(),
                settling = number,
                "an own block was still held at a height the chain had passed; its transactions are lost to the queue"
            );
        }
        if back.is_empty() {
            return 0;
        }
        // Through the reverted door, which lowers the senders' watermarks
        // first.
        //
        // This block of ours was never committed, so nothing it carried was
        // ever mined -- but a build of ours may already have said otherwise:
        // a build standing on it refuses a re-offered (sender, nonce) it
        // carries as "the chain is past this", and `mark_invalid` raises the
        // lane's watermark on that verdict (round 44, and it has to: without
        // it a mined transaction is re-offered to every build for the rest
        // of the leg). When the height then goes to another block, the
        // give-back meets that watermark and the nonce is filtered out for
        // good -- in neither the queue nor a block, and every later nonce of
        // that sender unusable behind the hole. The canonical prune for the
        // committed block runs immediately after this and re-raises each
        // watermark from what the chain actually mined, so lowering it here
        // cannot re-admit anything the chain holds.
        inner.give_back_unmined(back).offered
    }

    /// Forgets the transactions the build on `parent` took that a block has
    /// now mined -- those at or below each sender's mined nonce -- and hands
    /// them back to the caller to drop off the calling path (freeing 163,000
    /// of them is 20-40 ms; this is the leader's own-import path, right
    /// before its next build starts). What the build took but did not
    /// mine -- the puller's batches in flight when the block filled -- stays
    /// taken, for the next build's give-back. The lanes are not touched:
    /// the canonical pruner cleans them later, off this path.
    pub fn forget_mined(
        &self,
        parent: B256,
        mined: impl IntoIterator<Item = (Address, u64)>,
    ) -> Vec<Arc<ValidPoolTransaction<T>>> {
        self.forget_mined_timed(parent, mined).0
    }

    /// [`Self::forget_mined`], saying where its time went: the fold of the
    /// block's nonces (outside the lock), the waits for the lock, and the
    /// partition of the taken list under it -- whether a slow hand-off is
    /// the walk or the lock.
    pub fn forget_mined_timed(
        &self,
        parent: B256,
        mined: impl IntoIterator<Item = (Address, u64)>,
    ) -> (Vec<Arc<ValidPoolTransaction<T>>>, ForgetTimes) {
        let mut times = ForgetTimes::default();
        // The hand-off calls this after build-on-seal already has: the build
        // then stands on another parent and there is nothing to forget. Look
        // before folding a block's nonces (a 163,000-entry map), and fold
        // outside the lock the puller needs.
        {
            let at = std::time::Instant::now();
            let inner = self.lock_inner();
            times.lock_us += at.elapsed().as_micros() as u64;
            match inner.last_build.as_ref() {
                Some((built_on, taken)) if *built_on == parent && !taken.is_empty() => {}
                _ => return (Vec::new(), times),
            }
        }
        let at = std::time::Instant::now();
        let mut highest: AddressHashMap<u64> = AddressHashMap::default();
        for (sender, nonce) in mined {
            let entry = highest.entry(sender).or_insert(nonce);
            *entry = (*entry).max(nonce);
        }
        times.fold_us = at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        let mut inner = self.lock_inner();
        times.lock_us += at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        let Some((built_on, taken)) = inner.last_build.as_mut() else { return (Vec::new(), times) };
        if *built_on != parent || taken.is_empty() {
            return (Vec::new(), times);
        }
        let (mined, kept): (Vec<_>, Vec<_>) = std::mem::take(taken)
            .into_iter()
            .partition(|t| highest.get(&t.sender()).is_some_and(|nonce| t.nonce() <= *nonce));
        let whole = kept.is_empty() && !mined.is_empty();
        *taken = kept;
        if whole {
            let build = inner.builds;
            inner.handed = Some(Handed { build, block: None });
        }
        times.partition_us = at.elapsed().as_micros() as u64;
        (mined, times)
    }

    /// [`Self::forget_mined_timed`] with the fold of the block's nonces and
    /// the partition of the taken list run on a small pool of the queue's
    /// own (plan v6, the seal gap's first term; `N42_BUILD_START_ASYNC=1` in
    /// the node). A chained build's first pull waits for this hand-off: at a
    /// full block its fold (7 ms) and partition (12 ms, under the lock) were
    /// all of the 19-21 ms before the build's parallel step (loop239,
    /// `queue_ms` against `par_start_ms`), a serial walk over 163,000 cold
    /// transactions. The block's `(sender, nonce)` pairs are read by index
    /// (`mined_at(i)` for `i < len`), so those reads spread over the pool too.
    ///
    /// The pool is the queue's alone -- nothing on it ever takes the queue's
    /// lock -- so the partition can run under the lock without a worker
    /// waiting on it. The result is the serial one's: the same mined and
    /// kept transactions in the same order (rayon's partition keeps it). A
    /// pool that could not be built falls back to the serial walk.
    pub fn forget_mined_parallel<F>(
        &self,
        parent: B256,
        len: usize,
        mined_at: F,
    ) -> (Vec<Arc<ValidPoolTransaction<T>>>, ForgetTimes)
    where
        T: Send + Sync,
        F: Fn(usize) -> (Address, u64) + Sync + Send,
    {
        use rayon::prelude::*;
        let Some(pool) = forget_pool() else {
            return self.forget_mined_timed(parent, (0..len).map(&mined_at));
        };
        let mut times = ForgetTimes::default();
        {
            let at = std::time::Instant::now();
            let mut inner = self.lock_inner();
            times.lock_us += at.elapsed().as_micros() as u64;
            let Some((built_on, taken)) = inner.last_build.as_mut() else { return (Vec::new(), times) };
            if *built_on != parent || taken.is_empty() {
                return (Vec::new(), times);
            }
            // The common case on a leader: the build took exactly the block
            // it sealed, in body order (a frame build of a full block). Then
            // every taken transaction's own (sender, nonce) is in the block,
            // so the partition below would call every one of them mined, in
            // order, and keep nothing: one parallel pass comparing the two
            // lists position by position decides that, instead of folding
            // 163,000 pairs into a map and then partitioning the list
            // (docs/BREAKTHROUGH_DESIGN.md 10.32, `start_handoff_ms`).
            times.taken_len = taken.len();
            times.first_miss = usize::MAX;
            if taken.len() == len {
                let at = std::time::Instant::now();
                let list: &[Arc<ValidPoolTransaction<T>>] = taken;
                let miss = pool.install(|| {
                    list.par_iter()
                        .with_min_len(1024)
                        .enumerate()
                        .position_first(|(i, t)| mined_at(i) != (t.sender(), t.nonce()))
                });
                times.partition_us = at.elapsed().as_micros() as u64;
                times.first_miss = miss.unwrap_or(usize::MAX);
                if miss.is_none() {
                    times.whole = true;
                    let whole = std::mem::take(taken);
                    let build = inner.builds;
                    inner.handed = Some(Handed { build, block: None });
                    return (whole, times);
                }
            }
        }
        let at = std::time::Instant::now();
        let fold_one = |mut highest: AddressHashMap<u64>, (sender, nonce): (Address, u64)| {
            let entry = highest.entry(sender).or_insert(nonce);
            *entry = (*entry).max(nonce);
            highest
        };
        let highest: AddressHashMap<u64> = pool.install(|| {
            (0..len)
                .into_par_iter()
                .map(&mined_at)
                .fold(AddressHashMap::default, fold_one)
                .reduce(AddressHashMap::default, |a, b| {
                    let (big, small) = if a.len() >= b.len() { (a, b) } else { (b, a) };
                    small.into_iter().fold(big, fold_one)
                })
        });
        times.fold_us = at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        let mut inner = self.lock_inner();
        times.lock_us += at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        let Some((built_on, taken)) = inner.last_build.as_mut() else { return (Vec::new(), times) };
        if *built_on != parent || taken.is_empty() {
            return (Vec::new(), times);
        }
        let all = std::mem::take(taken);
        let (mined, kept): (Vec<_>, Vec<_>) = pool.install(|| {
            all.into_par_iter().partition(|t| highest.get(&t.sender()).is_some_and(|nonce| t.nonce() <= *nonce))
        });
        let whole = kept.is_empty() && !mined.is_empty();
        *taken = kept;
        if whole {
            let build = inner.builds;
            inner.handed = Some(Handed { build, block: None });
        }
        times.partition_us = at.elapsed().as_micros() as u64;
        (mined, times)
    }

    /// Moves what the inbox holds into the lanes now. The builder does this
    /// on its own pulls otherwise, and at the bench tier that is ~0.7 us a
    /// transaction of a full block's build (118 ms of 440, round 38) spent
    /// inserting arrivals rather than building; a task calling this every
    /// few milliseconds (`N42_TX_QUEUE_DRAINER=1`) takes it off the builder.
    ///
    /// With `N42_TX_QUEUE_DRAIN_CHUNK=<n>` the lanes' lock is held for at
    /// most `n` transactions at a time ([`Self::drain_chunked`]); the result
    /// is the one-hold drain's.
    pub fn drain_now(&self) {
        use std::sync::atomic::Ordering;
        if self.staged.load(Ordering::Acquire) == 0 {
            return;
        }
        let chunk = self.drain_chunk.load(Ordering::Relaxed);
        if chunk > 0 {
            self.drain_chunked(chunk, usize::MAX);
            return;
        }
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
    }

    /// [`Self::drain_now`] in bounded holds (`docs/SHARED_EXECUTION_SCOPE.md`
    /// 12): at 3M transactions a second the one-hold drain moved ~70,000 a
    /// call, 4-5 ms mean and 25-35 ms at worst, and was the lanes' longest
    /// holder on every leg of loop338.
    ///
    /// The inbox and the frame inbox are taken without the lanes' lock (the
    /// batch is counted in `in_hand` meanwhile, so the gate never misses
    /// it), handed to `Inner::pending_drain` under the lock, and inserted
    /// `chunk` at a time, the lock released between chunks. The insert is
    /// the one-hold drain's, transaction by transaction in inbox order
    /// (`Inner::insert_valid`), and the frames are indexed in the hold that
    /// inserts the last transaction. Whoever else drains while a remainder
    /// is pending finishes it first ([`Self::drain_inbox`]), so the lanes
    /// see the inbox's order whoever moves it; a lock holder that does not
    /// drain (an untake, a give-back) sees a prefix of the batch queued,
    /// which is what it would have seen had the batch arrived in two drains.
    ///
    /// Stops after `max_holds` holds (a test's way to leave a remainder
    /// pending); returns how many transactions each hold moved.
    fn drain_chunked(&self, chunk: usize, max_holds: usize) -> Vec<u64> {
        use std::sync::atomic::Ordering;
        let frames = if self.frames_staged.load(Ordering::Acquire) != 0 {
            let mut noted = self.frame_inbox.lock();
            let frames = std::mem::take(&mut *noted);
            self.frames_staged.fetch_sub(frames.len(), Ordering::AcqRel);
            frames
        } else {
            Vec::new()
        };
        let batch = {
            let mut inbox = self.inbox.lock();
            let batch = std::mem::take(&mut *inbox);
            // In hand before out of `staged`: a gate reading both in that
            // order never misses the batch (counted twice for a moment).
            self.in_hand.fetch_add(batch.len(), Ordering::AcqRel);
            self.staged.fetch_sub(batch.len(), Ordering::AcqRel);
            batch
        };
        let total = batch.len();
        let (mut batch, mut frames) = (Some(batch), Some(frames));
        let c = &LOCK_COUNTERS;
        let mut first = true;
        let mut holds = Vec::new();
        loop {
            let at;
            let moved;
            let done;
            {
                let mut inner = self.lock_inner();
                at = std::time::Instant::now();
                // Moved, not copied: a `Vec` becomes the deque in O(1).
                if let Some(batch) = batch.take() {
                    if inner.pending_drain.is_empty() {
                        inner.pending_drain = VecDeque::from(batch);
                    } else {
                        inner.pending_drain.extend(batch);
                    }
                }
                if let Some(frames) = frames.take() {
                    inner.pending_frames.extend(frames);
                }
                moved = inner.drain_pending(chunk) as u64;
                done = inner.pending_drain.is_empty() && inner.pending_frames.is_empty();
            }
            let took = at.elapsed().as_nanos() as u64;
            if first {
                // After the release that put the batch in the mirror.
                self.in_hand.fetch_sub(total, Ordering::AcqRel);
                first = false;
            }
            if moved > 0 {
                c.drains.fetch_add(1, Ordering::Relaxed);
                c.drain_chunks.fetch_add(1, Ordering::Relaxed);
                c.drain_txs.fetch_add(moved, Ordering::Relaxed);
                c.drain_ns.fetch_add(took, Ordering::Relaxed);
                raise_max(&c.drain_max_ns, took);
                raise_max(&c.drain_chunk_max_txs, moved);
            }
            holds.push(moved);
            if done || moved == 0 || holds.len() >= max_holds {
                break;
            }
        }
        holds
    }

    /// The transactions for a build on `parent`, as the pool's iterator would
    /// hand them. Taking returns what the previous build on the same parent
    /// took, first.
    pub fn best_for_build(&self, parent: B256) -> QueueBest<T> {
        let mut garbage = PruneGarbage::default();
        {
            let mut inner = self.lock_inner();
            // A build that walks the lanes cannot use a frame plan: it goes
            // back before the walk, so the walk sees its transactions.
            if inner.prepared.is_some() {
                self.drain_inbox(&mut inner);
                garbage.taken = inner.discard_prepared();
                note_ahead_discard(AheadDiscard::NotFrames);
            }
            self.begin_build(&mut inner, parent);
        }
        garbage.free();
        QueueBest {
            queue: self.clone(),
            skipped: AddressHashSet::default(),
            buffer: VecDeque::new(),
            batch: queue_batch(),
            frame_mode: false,
            frames_ended: false,
            segments: VecDeque::new(),
        }
    }

    /// The transactions for a frame build on `parent`
    /// (`docs/BREAKTHROUGH_DESIGN.md` step 1): whole frames in the order
    /// they arrived, each taken only if a build could take it whole right
    /// now and its every sender's run starts at that sender's lane head
    /// (after the frames before it in the plan were taken), until the
    /// transactions' gas limits reach `gas_limit`; the frame they run out
    /// in is cut to the prefix that fits, and the plan ends there.
    ///
    /// The frames are taken out of the lanes into the build's taken list at
    /// once, exactly as the walk takes a transaction, and handed out in
    /// plan order by the returned iterator, which offers nothing else: its
    /// first refusal ends it (a body with a hole in a frame is not
    /// frame-aligned), and what it has not handed out goes back when it is
    /// dropped, as the walk's buffer does. What it handed out and the build
    /// did not use goes back through the builder's refusals and the next
    /// build's give-back, as for the walk.
    pub fn frames_for_build(&self, parent: B256, gas_limit: u64) -> (QueueBest<T>, FramePlan) {
        let (best, plan, _) = self.frames_for_build_timed(parent, gas_limit);
        (best, plan)
    }

    /// [`Self::frames_for_build`], with where its time went
    /// ([`FrameSelectTimes`]).
    pub fn frames_for_build_timed(&self, parent: B256, gas_limit: u64) -> (QueueBest<T>, FramePlan, FrameSelectTimes) {
        let mode = if frame_select_parallel() { SelectMode::Parallel } else { SelectMode::Serial };
        self.frames_for_build_in(parent, gas_limit, mode)
    }

    fn frames_for_build_in(
        &self,
        parent: B256,
        gas_limit: u64,
        mode: SelectMode,
    ) -> (QueueBest<T>, FramePlan, FrameSelectTimes) {
        self.frames_for_build_ahead(parent, gas_limit, mode, plan_ahead())
    }

    /// [`Self::frames_for_build_in`], using the plan prepared for this build
    /// when [`Inner::prepared_verdict`] allows it (topped up when it holds
    /// less gas than this build has room for and its last frame is whole),
    /// and with `ahead` preparing the next build's plan right after this
    /// one, on the thread that applies this plan's takes
    /// (`N42_PLAN_AHEAD=1`, [`Prepared`]).
    fn frames_for_build_ahead(
        &self,
        parent: B256,
        gas_limit: u64,
        mode: SelectMode,
        ahead: bool,
    ) -> (QueueBest<T>, FramePlan, FrameSelectTimes) {
        let mut times = FrameSelectTimes::default();
        let mut garbage = PruneGarbage::default();
        let at = std::time::Instant::now();
        let (segments, plan) = {
            let mut inner = self.lock_inner();
            times.lock_us = at.elapsed().as_micros() as u64;
            let begin_at = std::time::Instant::now();
            // The inbox first: an arrival below a prepared plan's nonces must
            // be in its lane when the plan is judged.
            self.drain_inbox(&mut inner);
            let verdict = inner.prepared.as_ref().map(|prepared| inner.prepared_verdict(prepared, parent, gas_limit));
            match (verdict, inner.prepared.take()) {
                (Some(Ok(())), Some(prepared)) => {
                    let Prepared { gas_used, cut, segments, plan, taken, made_at, prep_us, .. } = prepared;
                    times.ahead = 1;
                    times.ahead_age_us = made_at.elapsed().as_micros() as u64;
                    times.ahead_prep_us = prep_us;
                    inner.open_build(parent, taken);
                    times.begin_us = begin_at.elapsed().as_micros() as u64;
                    let (mut segments, mut plan) = (segments, plan);
                    let room = gas_limit.saturating_sub(gas_used);
                    if !cut && room >= MIN_FRAME_TX_GAS {
                        // The plan ran out of frames, not of gas: what has
                        // arrived since tops it up, planned on the lanes as
                        // the plan left them.
                        let plan_at = std::time::Instant::now();
                        let mut more_times = FrameSelectTimes::default();
                        let (more, more_plan, _) = inner.plan_frames(room, &mut more_times, mode);
                        times.plan_us = plan_at.elapsed().as_micros() as u64;
                        times.ids_us = more_times.ids_us;
                        times.check_us = more_times.check_us;
                        times.settle_us = more_times.settle_us;
                        times.by_ref = more_times.by_ref;
                        times.slow = more_times.slow;
                        times.counted = more_times.counted;
                        if !more_plan.frames.is_empty() {
                            times.ahead = 2;
                            times.ahead_topup_txs = more_plan.tx_count();
                            segments.extend(more);
                            plan.frames.extend(more_plan.frames);
                            plan.parts.extend(more_plan.parts);
                        }
                        plan.skipped += more_plan.skipped;
                    }
                    (segments, plan)
                }
                (verdict, prepared) => {
                    if let Some(prepared) = prepared {
                        // Not usable: back to the lanes (minus what the
                        // chain mined) before this build plans afresh.
                        inner.prepared = Some(prepared);
                        garbage.taken = inner.discard_prepared();
                        let reason = match verdict {
                            Some(Err(reason)) => reason,
                            _ => AheadDiscard::OtherBuild,
                        };
                        times.ahead_discard = Some(reason);
                        note_ahead_discard(reason);
                    }
                    self.begin_build(&mut inner, parent);
                    times.begin_us = begin_at.elapsed().as_micros() as u64;
                    let plan_at = std::time::Instant::now();
                    let (segments, plan, _) = inner.plan_frames(gas_limit, &mut times, mode);
                    times.plan_us = plan_at.elapsed().as_micros() as u64;
                    (segments, plan)
                }
            }
        };
        garbage.free();
        // The takes the plan left noted leave the lanes on a thread of their
        // own, off the build's start; any lock before that applies them first.
        // With `ahead`, the same thread then prepares the next build's plan.
        if mode == SelectMode::Parallel || ahead {
            let queue = self.clone();
            let spawned = std::thread::Builder::new().name("n42-frame-settle".to_owned()).spawn(move || {
                if ahead {
                    queue.prepare_next_in(gas_limit, mode);
                } else {
                    drop(queue.lock_inner());
                }
            });
            if spawned.is_err() && mode == SelectMode::Parallel {
                drop(self.lock_inner());
            }
        }
        let best = QueueBest {
            queue: self.clone(),
            skipped: AddressHashSet::default(),
            buffer: VecDeque::new(),
            batch: 1,
            frame_mode: true,
            frames_ended: false,
            segments: segments.into_iter().map(|(txs, taken)| (txs, 0, taken)).collect(),
        };
        (best, plan, times)
    }

    /// Prepares the next frame build's plan now ([`Prepared`],
    /// `N42_PLAN_AHEAD=1`): on the lanes as they stand once the current
    /// build's take has left them, against `gas_limit`, exactly as
    /// [`Self::frames_for_build`] would plan it, its frames taken out of the
    /// lanes and held for that build. Returns whether a plan was prepared (a
    /// queue with no usable frame prepares none).
    pub fn prepare_next_plan(&self, gas_limit: u64) -> bool {
        let mode = if frame_select_parallel() { SelectMode::Parallel } else { SelectMode::Serial };
        self.prepare_next_in(gas_limit, mode)
    }

    fn prepare_next_in(&self, gas_limit: u64, mode: SelectMode) -> bool {
        let at = std::time::Instant::now();
        let mut garbage = PruneGarbage::default();
        let prepared = {
            let mut inner = self.lock_inner();
            self.drain_inbox(&mut inner);
            if inner.prepared.is_some() {
                // A plan nobody used (two builds' plans in a row without a
                // build between them): it goes back first.
                garbage.taken = inner.discard_prepared();
                note_ahead_discard(AheadDiscard::OtherBuild);
            }
            // The plan's takes go to a list of their own, not the current
            // build's: that build's taken list is what its hand-off forgets.
            let current = inner.last_build.take();
            inner.last_build = Some((B256::ZERO, Vec::new()));
            let mut times = FrameSelectTimes::default();
            let (segments, plan, gas_left) = inner.plan_frames(gas_limit, &mut times, mode);
            inner.settle();
            let taken = inner.last_build.take().map(|(_, taken)| taken).unwrap_or_default();
            inner.last_build = current;
            if plan.frames.is_empty() {
                if !taken.is_empty() {
                    inner.give_back(taken);
                }
                false
            } else {
                let mut lowest: AddressHashMap<u64> = AddressHashMap::default();
                for frame in &plan.frames {
                    let Some((runs, _)) = inner.frames.runs_and_hashes(&frame.id) else { continue };
                    for run in runs.iter().filter(|run| (run.start as usize) < frame.taken) {
                        let entry = lowest.entry(run.sender).or_insert(run.first_nonce);
                        *entry = (*entry).min(run.first_nonce);
                    }
                }
                let cut = plan.frames.last().is_some_and(|frame| frame.taken < frame.len);
                let after = inner.builds;
                inner.prepared = Some(Prepared {
                    after,
                    gas_used: gas_limit.saturating_sub(gas_left),
                    cut,
                    segments,
                    plan,
                    taken,
                    lowest,
                    made_at: std::time::Instant::now(),
                    prep_us: at.elapsed().as_micros() as u64,
                });
                true
            }
        };
        garbage.free();
        prepared
    }

    /// The frame layout of a body, from this node's frame index: each
    /// frame's id and how much of it the body holds, in body order. `None`
    /// when the body is not a run of frames this node indexed.
    pub fn frame_layout_of(&self, hashes: &[B256]) -> Option<Vec<(B256, usize)>> {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        inner.frames.layout_of(hashes)
    }

    /// For each (frame id, length) of `layout` over the body `hashes`:
    /// the id when this node's index holds that frame whole with exactly
    /// those hashes at those positions (its id is then the root over them,
    /// computed at ingest), `None` otherwise. One map lookup and one
    /// comparison per frame; what a whole-body check reads instead of
    /// rehashing the frames.
    pub fn frames_held(&self, layout: &[(B256, usize)], hashes: &[B256]) -> Vec<Option<B256>> {
        let mut inner = self.lock_inner();
        self.drain_inbox(&mut inner);
        inner.frames.held_whole(layout, hashes)
    }

    /// What every build does first, under the lanes' lock: the previous
    /// build's take given back, this build's taken list opened, the parked
    /// lanes whose park ended offered again.
    fn begin_build(&self, inner: &mut Inner<T>, parent: B256) {
        self.drain_inbox(inner);
        inner.open_build(parent, Vec::new());
    }
}

impl<T: PoolTransaction> Inner<T> {
    /// A build's opening once the inbox is drained: the previous build's
    /// take given back, this build's taken list opened with `taken` (empty,
    /// or a prepared plan's), the parked lanes whose park ended offered
    /// again.
    fn open_build(&mut self, parent: B256, taken: Vec<Arc<ValidPoolTransaction<T>>>) {
        let inner = self;
        {
            inner.builds += 1;
            let build = inner.builds;
            match inner.last_build.take() {
                // "The same parent again" does not mean the block built from
                // that take was not committed: with two builds in flight on
                // one parent the first one's block can be committed and
                // pruned before this call, and everything re-offered here
                // would then be stale for the rest of the leg -- the
                // canonical pruner never revisits that block (round 44:
                // 169,293 re-offered against a block of 163,000, then
                // 814,431 stale refusals and builds of 3.4-4.1 s). The
                // lanes' mined watermark decides, per sender, inside
                // `give_back`.
                Some((previous, taken)) if previous == parent => {
                    let count = taken.len();
                    let gave = inner.give_back(taken);
                    tracing::info!(target: "n42.tx_queue", build, ?parent, count, offered = gave.offered, mined = gave.filtered, "previous build on the same parent was not committed; its transactions are offered again");
                }
                // A build on another parent -- a build ahead superseded by the
                // next block -- took transactions the queue must not lose: they
                // go back too, minus the ones the chain has meanwhile mined.
                // Dropping them all here starved the builder while the pool
                // sat at its gate (round 38).
                Some((previous, taken)) if !taken.is_empty() => {
                    let count = taken.len();
                    let gave = inner.give_back(taken);
                    if gave.filtered > 0 {
                        tracing::info!(target: "n42.tx_queue", build, ?previous, ?parent, count, offered = gave.offered, mined = gave.filtered, "a build on another parent was superseded; its transactions are offered again");
                    } else {
                        tracing::debug!(target: "n42.tx_queue", build, ?previous, ?parent, count, offered = gave.offered, "a build on another parent was superseded; its transactions are offered again");
                    }
                }
                _ => {}
            }
            inner.last_build = Some((parent, taken));
            inner.end_run();
            // Every lane whose park has ended is offered again before this
            // build walks: a park that outlived its reason must never cost
            // a build the lane behind it.
            inner.readmit_parked();
        }
    }
}

impl<T: PoolTransaction> Inner<T> {
    /// The frame plan of [`TxQueue::frames_for_build`], taken out of the
    /// lanes: the transactions in plan order, as one segment per frame (the
    /// frame's shared transactions and how many of them from its start),
    /// and the plan.
    ///
    /// A frame noted with its transactions ([`TxQueue::push_frame`]) that
    /// fits the gas left whole is checked and taken by reference
    /// ([`frames::FrameIndex::check_by_ref`]): one lane look-up a sender
    /// run, the lanes' entries compared with the frame's `Arc`s by pointer,
    /// the frame's gas summed at admission, its segment one `Arc` clone and
    /// its hashes one copy. Everything else -- a frame noted without its
    /// transactions (the pool door, `N42_FRAME_ARCS=0`), the frame the gas
    /// runs out in, a lane holding another allocation of a transaction --
    /// goes through the per-transaction check ([`Self::plan_frame_slow`]),
    /// which decides exactly as before; the two agree on every frame, so
    /// the plan and the transactions are the same either way.
    fn plan_frames(
        &mut self,
        gas_limit: u64,
        times: &mut FrameSelectTimes,
        mode: SelectMode,
    ) -> (Vec<(FrameTxs<T>, usize)>, FramePlan, u64) {
        let mut segments: Vec<(FrameTxs<T>, usize)> = Vec::new();
        let mut plan = FramePlan::default();
        let mut gas_left = gas_limit;
        // The ids only: the per-position check below is at least as strict
        // as the index's whole-usable test (each position at its sender's
        // lane head, unparked, holding the frame's hash), so the frames past
        // the block's gas are never examined. Computing whole-usable for
        // every indexed frame first cost ~50 ms a build at a 500k queue
        // (loop267, `start_best_ms`).
        let ids_at = std::time::Instant::now();
        let ids = self.frames.ids_in_arrival_order();
        times.ids_us = ids_at.elapsed().as_micros() as u64;
        let from = if mode == SelectMode::Parallel {
            let (next, ended) = self.plan_parallel(&ids, &mut gas_left, &mut segments, &mut plan, times);
            if ended {
                return (segments, plan, gas_left);
            }
            next
        } else {
            0
        };
        if from < ids.len() && gas_left > 0 {
            // The serial check reads the lanes' heads: the parallel part's
            // takes are applied first.
            let settle_at = std::time::Instant::now();
            self.settle();
            times.settle_us += settle_at.elapsed().as_micros() as u64;
            self.plan_serial(&ids[from..], &mut gas_left, &mut segments, &mut plan, times, mode == SelectMode::PerTx);
        }
        (segments, plan, gas_left)
    }

    /// The first part of [`Self::plan_frames`]: the frames the block's gas
    /// reaches (and a few past it, for the ones passed over) checked at
    /// once on the worker pool against the lanes as they stand
    /// ([`frames::FrameIndex::check_runs`]), then decided in arrival order
    /// with one counter per sender that more than one of them draws on.
    /// A taken frame is noted in `pending` and leaves the lanes at the next
    /// [`Self::settle`] -- the next lock of the queue, or the helper
    /// [`TxQueue::frames_for_build_timed`] starts -- so the build is handed
    /// its frames without a transaction touched. Returns where the serial
    /// part continues and whether the plan has ended.
    fn plan_parallel(
        &mut self,
        ids: &[B256],
        gas_left: &mut u64,
        segments: &mut Vec<(FrameTxs<T>, usize)>,
        plan: &mut FramePlan,
        times: &mut FrameSelectTimes,
    ) -> (usize, bool) {
        use rayon::prelude::*;
        // Past the gas, a margin for the frames the plan passes over; the
        // serial part continues if they run out.
        const MARGIN: usize = 16;
        let check_at = std::time::Instant::now();
        let mut end = 0usize;
        let mut reach = 0u64;
        let mut past = 0usize;
        while end < ids.len() && past <= MARGIN {
            if reach > *gas_left {
                past += 1;
            }
            reach = reach.saturating_add(self.frames.txs_gas_of(&ids[end]).unwrap_or(u64::MAX));
            end += 1;
        }
        let (frames, lanes) = (&self.frames, &self.lanes);
        let checks: Vec<frames::RunCheck<T>> =
            ids[..end].par_iter().with_min_len(4).map(|id| frames.check_runs(id, lanes)).collect();
        // Senders some run needs entries below it taken of, and each frame's
        // runs of those senders: what the decisions below count.
        let shared: AddressHashSet = checks
            .iter()
            .filter_map(|check| match check {
                frames::RunCheck::Ok { below, .. } => Some(below.iter().map(|(_, sender, _)| *sender)),
                _ => None,
            })
            .flatten()
            .collect();
        let draws: Vec<Vec<(u32, Address, u32)>> = if shared.is_empty() {
            Vec::new()
        } else {
            ids[..end]
                .par_iter()
                .zip(checks.par_iter())
                .map(|(id, check)| match check {
                    frames::RunCheck::Ok { .. } => frames.runs_and_hashes(id).map_or_else(Vec::new, |(runs, _)| {
                        runs.iter()
                            .enumerate()
                            .filter(|(_, run)| shared.contains(&run.sender))
                            .map(|(idx, run)| (idx as u32, run.sender, run.len))
                            .collect()
                    }),
                    _ => Vec::new(),
                })
                .collect()
        };
        times.check_us = check_at.elapsed().as_micros() as u64;
        let mut taken_of: AddressHashMap<u64> = AddressHashMap::default();
        for (k, check) in checks.into_iter().enumerate() {
            if *gas_left == 0 {
                return (k, true);
            }
            let (txs, gas) = match check {
                frames::RunCheck::Slow => return (k, false),
                frames::RunCheck::Unusable { gas } => {
                    // A frame the gas cuts is checked only as far as the
                    // cut: the serial check decides it.
                    if gas > *gas_left {
                        return (k, false);
                    }
                    plan.skipped += 1;
                    continue;
                }
                frames::RunCheck::Ok { txs, gas, below } => {
                    let draws = draws.get(k).map_or(&[][..], Vec::as_slice);
                    if !below.is_empty() {
                        times.counted += 1;
                    }
                    let at_heads = draws.iter().all(|(idx, sender, _)| {
                        let needs = below.iter().find(|(at, _, _)| at == idx).map_or(0, |(_, _, n)| *n);
                        taken_of.get(sender).copied().unwrap_or(0) == needs
                    });
                    if !at_heads {
                        if gas > *gas_left {
                            return (k, false);
                        }
                        plan.skipped += 1;
                        continue;
                    }
                    (txs, gas)
                }
            };
            let id = ids[k];
            let Some((_, hashes)) = self.frames.runs_and_hashes(&id) else { return (k, false) };
            let (prefix, used) = if gas <= *gas_left {
                (txs.len(), gas)
            } else {
                // The frame the block's gas runs out in, cut: its own
                // transactions' gas, the one frame read here.
                let mut used = 0u64;
                let mut prefix = 0usize;
                for tx in txs.iter() {
                    let tx_gas = tx.gas_limit();
                    if used.saturating_add(tx_gas) > *gas_left {
                        break;
                    }
                    used += tx_gas;
                    prefix += 1;
                }
                (prefix, used)
            };
            if prefix == 0 {
                return (k, true);
            }
            for (_, sender, len) in draws.get(k).map_or(&[][..], Vec::as_slice) {
                // Runs are in position order; a cut frame's runs past the cut
                // take nothing, and the plan ends with it anyway.
                *taken_of.entry(*sender).or_insert(0) += u64::from(*len);
            }
            self.len -= prefix;
            plan.push_hashes(Arc::clone(hashes), prefix);
            plan.frames.push(PlannedFrame { id, len: txs.len(), taken: prefix });
            self.pending.push((id, prefix));
            times.by_ref += 1;
            segments.push((txs, prefix));
            *gas_left = gas_left.saturating_sub(used);
            if prefix < hashes.len() {
                return (k + 1, true);
            }
        }
        (end, false)
    }

    /// Applies the takes [`Self::plan_parallel`] noted: each planned
    /// frame's transactions (its taken prefix) leave their lanes, by
    /// (sender, nonce), into the build's taken list in plan order, exactly
    /// as the serial take pops them. Every lock of the queue calls this
    /// first ([`TxQueue::lock_inner`]), so nothing ever sees the lanes
    /// before it.
    fn settle(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        let mut list = self.last_build.as_mut().map(|(_, list)| list);
        for (id, prefix) in pending {
            let Some((runs, _)) = self.frames.runs_and_hashes(&id) else { continue };
            if let Some(list) = list.as_mut() {
                list.reserve(prefix);
            }
            for run in runs {
                let start = run.start as usize;
                if start >= prefix {
                    break;
                }
                let count = (run.len as usize).min(prefix - start) as u64;
                let Some(lane) = self.lanes.get_mut(&run.sender) else { continue };
                for nonce in run.first_nonce..run.first_nonce + count {
                    // The lane's own `Arc` moves to the taken list; the
                    // build was handed the frame's, the same allocation.
                    if let Some(valid) = lane.by_nonce.remove(&nonce)
                        && let Some(list) = list.as_mut()
                    {
                        list.push(valid);
                    }
                }
                if lane.by_nonce.is_empty() {
                    lane.queued = false;
                }
            }
        }
    }

    /// The serial part of [`Self::plan_frames`] over `ids`, with the lanes
    /// settled: each frame by reference where [`frames::FrameIndex::check_by_ref`]
    /// can decide it, else by the per-transaction check.
    fn plan_serial(
        &mut self,
        ids: &[B256],
        gas_left: &mut u64,
        segments: &mut Vec<(FrameTxs<T>, usize)>,
        plan: &mut FramePlan,
        times: &mut FrameSelectTimes,
        per_tx: bool,
    ) {
        for &id in ids {
            if *gas_left == 0 {
                break;
            }
            let check =
                if per_tx { frames::ByRef::Slow } else { self.frames.check_by_ref(&id, &self.lanes, *gas_left) };
            match check {
                frames::ByRef::Unusable => plan.skipped += 1,
                frames::ByRef::Whole { txs, gas } => {
                    let taken_list = self.last_build.as_mut().map(|(_, list)| list);
                    let Some((runs, hashes)) = self.frames.runs_and_hashes(&id) else {
                        plan.skipped += 1;
                        continue;
                    };
                    let mut taken_list = taken_list;
                    if let Some(list) = taken_list.as_mut() {
                        list.reserve(txs.len());
                    }
                    let mut taken = 0usize;
                    for run in runs {
                        let Some(lane) = self.lanes.get_mut(&run.sender) else { break };
                        for _ in 0..run.len {
                            // The check under this same lock put each of
                            // the run's nonces at the lane's head in turn.
                            let Some((_, valid)) = lane.by_nonce.pop_first() else { break };
                            self.len -= 1;
                            taken += 1;
                            if let Some(list) = taken_list.as_mut() {
                                list.push(valid);
                            }
                        }
                        if lane.by_nonce.is_empty() {
                            lane.queued = false;
                        }
                    }
                    debug_assert_eq!(taken, txs.len());
                    plan.push_hashes(Arc::clone(hashes), txs.len());
                    plan.frames.push(PlannedFrame { id, len: txs.len(), taken: txs.len() });
                    times.by_ref += 1;
                    segments.push((txs, taken));
                    *gas_left = gas_left.saturating_sub(gas);
                }
                frames::ByRef::Slow => {
                    times.slow += 1;
                    match self.plan_frame_slow(id, gas_left, plan) {
                        SlowFrame::Skipped => {}
                        SlowFrame::Taken(out, whole) => {
                            let taken = out.len();
                            segments.push((FrameTxs::from(out), taken));
                            if !whole {
                                break;
                            }
                        }
                        SlowFrame::End => break,
                    }
                }
            }
        }
    }

    /// One frame of [`Self::plan_frames`] by the per-transaction check: each
    /// position found in its lane by (sender, nonce) and its hash compared,
    /// the gas summed position by position and the frame cut where it runs
    /// out.
    fn plan_frame_slow(&mut self, id: B256, gas_left: &mut u64, plan: &mut FramePlan) -> SlowFrame<T> {
        let mut out = Vec::new();
        {
            let Some(members) = self.frames.members_of(&id) else {
                plan.skipped += 1;
                return SlowFrame::Skipped;
            };
            // Checked before anything is taken: each position at its
            // sender's lane head, counting this frame's earlier positions
            // of the same sender, and the prefix the gas left allows.
            let mut at_head: AddressHashMap<u64> = AddressHashMap::default();
            let mut usable = true;
            let mut prefix = members.len();
            let mut gas = 0u64;
            for (at, (sender, nonce, hash)) in members.iter().enumerate() {
                let before = at_head.entry(*sender).or_insert(0);
                let Some(lane) = self.lanes.get(sender) else {
                    usable = false;
                    break;
                };
                let head = lane.by_nonce.first_key_value().map(|(nonce, _)| *nonce);
                let held = lane.by_nonce.get(nonce);
                if lane.parked.is_some()
                    || head.and_then(|head| head.checked_add(*before)) != Some(*nonce)
                    || held.is_none_or(|held| held.hash() != hash)
                {
                    usable = false;
                    break;
                }
                let tx_gas = held.map_or(0, |held| held.gas_limit());
                if gas.saturating_add(tx_gas) > *gas_left {
                    prefix = at;
                    break;
                }
                gas += tx_gas;
                *before += 1;
            }
            if !usable {
                plan.skipped += 1;
                return SlowFrame::Skipped;
            }
            if prefix == 0 {
                return SlowFrame::End;
            }
            let mut taken = 0usize;
            let mut taken_hashes: Vec<B256> = Vec::with_capacity(prefix);
            for (sender, nonce, hash) in &members[..prefix] {
                let Some(lane) = self.lanes.get_mut(sender) else { break };
                if lane.by_nonce.first_key_value().map(|(n, _)| *n) != Some(*nonce) {
                    break;
                }
                let Some((_, valid)) = lane.by_nonce.pop_first() else { break };
                self.len -= 1;
                if lane.by_nonce.is_empty() {
                    lane.queued = false;
                }
                if let Some((_, list)) = self.last_build.as_mut() {
                    list.push(Arc::clone(&valid));
                }
                out.push(valid);
                taken_hashes.push(*hash);
                taken += 1;
            }
            if taken == 0 {
                return SlowFrame::End;
            }
            plan.push_hashes(taken_hashes.into(), taken);
            plan.frames.push(PlannedFrame { id, len: members.len(), taken });
            *gas_left = gas_left.saturating_sub(gas);
            SlowFrame::Taken(out, taken == members.len())
        }
    }

    /// Whether the plan prepared ahead may be the plan of a frame build on
    /// `parent` with `gas_limit`, the lanes drained (`docs/SHARED_EXECUTION_SCOPE.md`
    /// 12). It may when the queue is exactly where the plan left it, less
    /// the build it followed and plus later arrivals:
    /// - no build began since it was made (`after`);
    /// - that build's whole take was forgotten as mined by an own block (the
    ///   hand-off), and that block is `parent` -- so the parent carries every
    ///   nonce the plan's runs start after;
    /// - nothing of that take is still out (`last_build` empty, on another
    ///   parent);
    /// - its gas fits;
    /// - for every sender it draws on, the chain has mined none of its
    ///   nonces (a prune) and the lane holds nothing below them (a
    ///   give-back, an untake, a refusal, a late arrival into a hole): its
    ///   runs are still at their lanes' heads once the parent is applied.
    ///
    /// Frames that arrived since are behind it in arrival order, so the plan
    /// is the one a fresh plan would have made on the queue as it stood
    /// when it was prepared.
    fn prepared_verdict(&self, prepared: &Prepared<T>, parent: B256, gas_limit: u64) -> Result<(), AheadDiscard> {
        if prepared.after != self.builds {
            return Err(AheadDiscard::OtherBuild);
        }
        if self.handed != Some(Handed { build: self.builds, block: Some(parent) }) {
            return Err(AheadDiscard::NotOnItsParent);
        }
        match &self.last_build {
            Some((built_on, taken)) if *built_on != parent && taken.is_empty() => {}
            _ => return Err(AheadDiscard::TakeLeft),
        }
        if prepared.gas_used > gas_limit {
            return Err(AheadDiscard::Gas);
        }
        for (sender, lowest) in &prepared.lowest {
            let Some(lane) = self.lanes.get(sender) else { continue };
            if lane.is_stale(*lowest) {
                return Err(AheadDiscard::Mined);
            }
            if lane.by_nonce.first_key_value().is_some_and(|(nonce, _)| nonce < lowest) {
                return Err(AheadDiscard::Below);
            }
        }
        Ok(())
    }

    /// Gives a prepared plan's transactions back to the lanes, as a build's
    /// give-back does, and returns the ones the chain has mined (at or below
    /// their lane's watermark) for the caller to free after the lock.
    fn discard_prepared(&mut self) -> Vec<Arc<ValidPoolTransaction<T>>> {
        let Some(prepared) = self.prepared.take() else { return Vec::new() };
        let lanes = &self.lanes;
        let (mined, back): (Vec<_>, Vec<_>) = prepared
            .taken
            .into_iter()
            .partition(|t| lanes.get(&t.sender()).is_some_and(|lane| lane.is_stale(t.nonce())));
        for t in &mined {
            self.dropped(Dropped::Mined, t.sender(), t.nonce());
        }
        if !back.is_empty() {
            self.give_back(back);
        }
        mined
    }

    /// Moves up to `budget` transactions of a chunked drain's remainder into
    /// their lanes, in inbox order, and indexes the remainder's frames once
    /// the last of them is in. Returns how many it moved.
    fn drain_pending(&mut self, budget: usize) -> usize {
        let mut moved = 0usize;
        while moved < budget {
            let Some(valid) = self.pending_drain.pop_front() else { break };
            self.insert_valid(valid);
            moved += 1;
        }
        if self.pending_drain.is_empty() && !self.pending_frames.is_empty() {
            for (frame, txs) in std::mem::take(&mut self.pending_frames) {
                self.frames.insert(frame, txs);
            }
        }
        moved
    }

    /// Queues one transaction the pusher has already wrapped.
    fn insert_valid(&mut self, valid: Arc<ValidPoolTransaction<T>>) {
        let sender = valid.sender();
        let nonce = valid.nonce();
        let lane = self
            .lanes
            .entry(sender)
            .or_insert_with(|| Lane { by_nonce: BTreeMap::new(), queued: false, mined: None, chain_mined: None, parked: None });
        if lane.by_nonce.contains_key(&nonce) {
            self.dropped(Dropped::Duplicate, sender, nonce);
            return;
        }
        if lane.is_stale(nonce) {
            let reason = lane.why_stale(nonce, false);
            self.dropped(reason, sender, nonce);
            return;
        }
        // The hole a build parked this lane behind, filled: the ingest saw
        // the missing nonce after all, so the lane is offered again at once
        // rather than at the park's expiry.
        let fills = lane.hole_filled_by(nonce);
        let parked = lane.parked.is_some();
        lane.by_nonce.insert(nonce, valid);
        self.len += 1;
        // A lane still parked stays out of the order whatever arrives: the
        // flood keeps feeding a gapped sender its *later* nonces, and
        // putting the lane back for each of them would undo the park a few
        // thousand times a second. `readmit_parked` is its other door back.
        if !parked && !lane.queued {
            lane.queued = true;
            self.arrivals.push_back(sender);
        }
        // Counted into the parked total first, then out of it with the
        // rest of the lane: `unpark` subtracts what the lane holds, and by
        // here that includes this transaction.
        if parked {
            self.parked_len += 1;
        }
        if fills {
            self.unpark(sender);
            self.requeue(sender);
        }
    }

    /// Puts transactions a build took back at their nonces; their senders go
    /// to the front so they are offered before anything newer.
    ///
    /// Everything that comes back passes the lane's mined watermark, the
    /// same filter the canonical prune applies: a transaction the chain has
    /// mined must not re-enter the lanes by any door. It can reach here
    /// after its block was pruned -- a build that took it before the block
    /// committed hands its leftovers back when it ends, a second build on
    /// one parent gives the first build's take back, an own block held at a
    /// height the chain settled elsewhere comes back -- and nothing would
    /// remove it a second time.
    fn give_back(&mut self, taken: Vec<Arc<ValidPoolTransaction<T>>>) -> GaveBack {
        let mut senders: Vec<Address> = Vec::new();
        let mut unparked: Vec<Address> = Vec::new();
        let mut gave = GaveBack::default();
        for valid in taken {
            let sender = valid.sender();
            let nonce = valid.nonce();
            let Some(lane) = self.lanes.get_mut(&sender) else {
                gave.filtered += 1;
                self.dropped(Dropped::NoLane, sender, nonce);
                continue;
            };
            if lane.is_stale(nonce) {
                gave.filtered += 1;
                let reason = lane.why_stale(nonce, true);
                self.dropped(reason, sender, nonce);
                continue;
            }
            gave.offered += 1;
            // An own block the chain settled elsewhere comes back through
            // here, and it can carry the very nonce a lane is parked
            // behind.
            let fills = lane.hole_filled_by(nonce);
            let fresh = lane.by_nonce.insert(nonce, valid).is_none();
            if fresh {
                self.len += 1;
            }
            let parked = lane.parked.is_some();
            // As in `insert_valid`: a parked lane comes back through
            // `readmit_parked` and not through a give-back of the very
            // transactions the build could not use.
            if !lane.queued && !parked {
                lane.queued = true;
                senders.push(sender);
            }
            // As in `insert_valid`: into the parked total first, then out
            // of it with the rest of the lane.
            if parked && fresh {
                self.parked_len += 1;
            }
            if fills {
                self.unpark(sender);
                unparked.push(sender);
            }
        }
        for sender in unparked {
            self.requeue(sender);
        }
        for sender in senders.into_iter().rev() {
            self.arrivals.push_front(sender);
        }
        gave
    }

    /// Records that a transaction left the queue, or never entered it.
    fn dropped(&mut self, reason: Dropped, sender: Address, nonce: u64) {
        self.drops.counts[reason.index()] += 1;
        if self.drops.samples.len() < DROP_SAMPLES
            && reason != Dropped::Duplicate
            && reason != Dropped::Mined
        {
            self.drops.samples.push((reason, sender, nonce));
        }
    }

    /// [`Self::give_back`] for transactions no block of the chain ever
    /// carried: each sender's watermark drops below the nonce coming back
    /// first, so a watermark raised from a verdict about a block that was
    /// never committed cannot swallow it.
    fn give_back_unmined(&mut self, back: Vec<Arc<ValidPoolTransaction<T>>>) -> GaveBack {
        for valid in &back {
            if let Some(lane) = self.lanes.get_mut(&valid.sender()) {
                lane.unmine(valid.nonce());
            }
        }
        self.give_back(back)
    }

    /// A build found a hole below this sender's head: the account is at
    /// `wanted` and the lane's lowest nonce is above it. The lane is
    /// stepped over until the hole is filled, the chain passes it, or the
    /// park expires ([`Parked`]).
    fn park(&mut self, sender: Address, wanted: u64) {
        let until_build = self.builds.saturating_add(PARK_BUILDS);
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        // The entry is made here and nowhere else, so a lane cannot be
        // parked without one: a lane that is in neither `arrivals` nor
        // `parked_order` is offered to nothing again, which is loop144's
        // stranded lane. A lane parked again while its entry is still
        // there keeps that entry -- the walk reads the lane's own expiry,
        // not the entry's.
        let fresh = lane.parked.is_none();
        let held = lane.by_nonce.len();
        if fresh {
            // Off, or past the cap: the lane is not parked. It stays in the
            // order and a build pays one refusal for its head, which is what
            // it did before parks existed.
            if self.park_lanes == 0 || self.parked_order.len() >= self.park_lanes {
                self.park_capped = self.park_capped.saturating_add(1);
                return;
            }
        }
        lane.parked = Some(Parked { wanted, until_build });
        if fresh {
            self.parked_len += held;
            self.parked_order.push_back(sender);
        }
    }

    /// Ends a lane's park, whatever ended it, and takes what it holds back
    /// out of [`Inner::parked_len`]. The one door out of a park.
    fn unpark(&mut self, sender: Address) {
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        if lane.parked.take().is_some() {
            let held = lane.by_nonce.len();
            self.parked_len = self.parked_len.saturating_sub(held);
        }
    }

    /// Puts a lane back in the arrival order if it holds anything and is
    /// not there already. The one door back for a parked lane.
    fn requeue(&mut self, sender: Address) {
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        if lane.queued || lane.by_nonce.is_empty() {
            return;
        }
        lane.queued = true;
        self.arrivals.push_back(sender);
    }

    /// Offers again every lane whose park has ended -- filled, passed by
    /// the chain, or expired. Run once per build, from
    /// [`TxQueue::best_for_build`]; a prefix walk rather than a scan,
    /// because `parked_order` is all but sorted by expiry.
    fn readmit_parked(&mut self) {
        while let Some(sender) = self.parked_order.front().copied() {
            let build = self.builds;
            // Parks end in the order they were made, so once one is still
            // held the rest are too.
            if self.lanes.get(&sender).is_some_and(|lane| lane.park_holds(build)) {
                break;
            }
            // Expired, or unparked by a door of its own (the hole filled,
            // the chain past it); in the second case the lane may be back
            // in the order already, which `requeue` sees.
            self.unpark(sender);
            self.parked_order.pop_front();
            self.requeue(sender);
        }
    }

    /// What a build could take from the lanes right now: a parked lane's
    /// transactions are queued and unusable, and so are those of a lane the
    /// arrival order does not offer.
    fn usable(&self) -> usize {
        self.lanes.values().filter(|lane| lane.queued).map(|lane| lane.by_nonce.len()).sum()
    }

    /// The parked lanes and what they hold, walked. What
    /// [`Inner::parked_len`] tracks incrementally; the two must agree.
    #[cfg(test)]
    fn parked_walked(&self) -> (usize, usize) {
        self.lanes
            .values()
            .filter(|lane| lane.parked.is_some())
            .fold((0, 0), |(lanes, txs), lane| (lanes + 1, txs + lane.by_nonce.len()))
    }

    /// A canonical block's removal, given each sender's highest mined nonce:
    /// the lanes, then the frame index, then the build's taken list; what
    /// leaves goes to `garbage` for the caller to free after the lock.
    /// Returns how many frames the sweep dropped.
    fn remove_mined_highest(&mut self, highest: &AddressHashMap<u64>, garbage: &mut PruneGarbage<T>) -> usize {
        for (sender, nonce) in highest {
            if let Some(gone) = self.remove_mined_taking(*sender, *nonce, true) {
                garbage.lanes.push(gone);
            }
        }
        // A plan prepared ahead that holds a nonce the chain has now mined
        // can never be used: back to the lanes now (the mined ones freed with
        // the rest of the prune's garbage), not when the next build finds it.
        if let Some(prepared) = self.prepared.as_ref()
            && prepared.lowest.iter().any(|(sender, lowest)| highest.get(sender).is_some_and(|mined| mined >= lowest))
        {
            let mined = self.discard_prepared();
            garbage.taken.extend(mined);
            note_ahead_discard(AheadDiscard::Mined);
        }
        // A frame any of whose transactions the chain has mined can never
        // be referenced whole again.
        let swept = {
            let Self { frames, lanes, .. } = self;
            frames.sweep_into(lanes, &mut garbage.frames)
        };
        // What a build has taken is not in the lanes, so the removal above
        // misses it; when the build is superseded its transactions are
        // offered again, and a mined one offered again is a stale
        // transaction the builder pays to refuse (42,000 a build in round
        // 38). Forget the mined ones here: one pass, the map read once a
        // run of one sender, the kept ones in their order.
        if let Some((_, taken)) = self.last_build.as_mut()
            && !taken.is_empty()
        {
            let all = std::mem::take(taken);
            let mut kept = Vec::with_capacity(all.len());
            let mut run: Option<(Address, Option<u64>)> = None;
            for t in all {
                let sender = t.sender();
                let mined = match run {
                    Some((current, mined)) if current == sender => mined,
                    _ => {
                        let mined = highest.get(&sender).copied();
                        run = Some((sender, mined));
                        mined
                    }
                };
                if mined.is_some_and(|mined| t.nonce() <= mined) {
                    garbage.taken.push(t);
                } else {
                    kept.push(t);
                }
            }
            *taken = kept;
        }
        swept
    }

    /// [`Self::remove_mined_from`] for a canonical block.
    fn remove_mined(&mut self, sender: Address, nonce: u64) {
        self.remove_mined_from(sender, nonce, true);
    }

    /// Drops everything at or below `nonce` and raises the watermark;
    /// `from_chain` says whether a canonical block put it there or a build
    /// did ([`Lane::chain_mined`]).
    fn remove_mined_from(&mut self, sender: Address, nonce: u64, from_chain: bool) {
        drop(self.remove_mined_taking(sender, nonce, from_chain));
    }

    /// [`Self::remove_mined_from`], handing back what left the lane rather
    /// than freeing it here, so a caller under the lock can free it after
    /// the lock is released.
    fn remove_mined_taking(
        &mut self,
        sender: Address,
        nonce: u64,
        from_chain: bool,
    ) -> Option<BTreeMap<u64, Arc<ValidPoolTransaction<T>>>> {
        let lane = self.lanes.get_mut(&sender)?;
        lane.mine(nonce, from_chain);
        // The chain has reached or passed the hole: whatever is left in the
        // lane above it is the next thing this sender wants mined.
        let ends_park = lane.chain_passed(nonce);
        let parked = lane.parked.is_some();
        // Nothing at or below the nonce: no split (a split of a lane whose
        // head is above the mined nonce moves the whole tree for nothing,
        // which on a leader is every lane the block's frames came from:
        // the build took them out already).
        let gone = lane.by_nonce.first_key_value().is_some_and(|(first, _)| *first <= nonce).then(|| {
            let keep = lane.by_nonce.split_off(&nonce.saturating_add(1));
            std::mem::replace(&mut lane.by_nonce, keep)
        });
        let dropped = gone.as_ref().map_or(0, BTreeMap::len);
        self.len -= dropped;
        // What left the lane leaves the parked total first, whatever
        // happens to the park itself: `unpark` subtracts what the lane
        // *still* holds, so a park ended in the same breath as a prune
        // used to leave the pruned part counted for ever (loop212 NPb:
        // `parked=640 parked_lanes=0`).
        if parked {
            self.parked_len = self.parked_len.saturating_sub(dropped);
        }
        // A now-empty lane leaves the arrival order when its turn comes.
        if ends_park {
            self.unpark(sender);
            self.requeue(sender);
        }
        gone
    }

    /// Ends the run in progress: the sender it was taking from goes back to
    /// the front of the arrival order if its lane still holds anything, so
    /// the next build offers it first.
    ///
    /// A build stops mid-run whenever the block fills, which at the bench
    /// tier is every full block. Dropping the cursor instead (what the
    /// next build's start did through loop145) left that sender's lane
    /// queued but in neither the order nor the cursor: nothing offered it
    /// again, and its later arrivals joined the same stranded lane. A leader
    /// stranded one sender a block, and by the second half of a 64-view
    /// tenure the stranded lanes held most of what its queue counted -- the
    /// ingest gate closed on that count, the flood stalled, and the leader
    /// built partial and then empty blocks (loop144 A2: 163k, 126k, 32k, 0)
    /// until the next leader, whose lanes were whole, mined them.
    fn end_run(&mut self) {
        let Some((sender, _)) = self.current.take() else { return };
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        if lane.by_nonce.is_empty() {
            lane.queued = false;
        } else {
            self.arrivals.push_front(sender);
        }
    }

    /// The next transaction: the lowest nonce of the sender at the front of
    /// the arrival order, skipping senders the build marked.
    fn next_ready(&mut self, skipped: &AddressHashSet) -> Option<Arc<ValidPoolTransaction<T>>> {
        // Continue the current sender's run first.
        if let Some((sender, left)) = self.current.take() {
            if left > 0 && !skipped.contains(&sender) {
                if let Some(lane) = self.lanes.get_mut(&sender) {
                    if let Some((_, valid)) = lane.by_nonce.pop_first() {
                        self.len -= 1;
                        if lane.by_nonce.is_empty() {
                            lane.queued = false;
                        } else if left > 1 {
                            self.current = Some((sender, left - 1));
                        } else {
                            self.arrivals.push_back(sender);
                        }
                        if let Some((_, taken)) = self.last_build.as_mut() {
                            taken.push(Arc::clone(&valid));
                        }
                        return Some(valid);
                    }
                }
            }
            // The run ended, was refused, or the lane emptied: the sender
            // rejoins the rotation if it still has anything.
            if let Some(lane) = self.lanes.get_mut(&sender) {
                if lane.by_nonce.is_empty() {
                    lane.queued = false;
                } else {
                    self.arrivals.push_back(sender);
                }
            }
        }
        let run = self.run;
        let mut passes = self.arrivals.len();
        while passes > 0 {
            passes -= 1;
            let sender = self.arrivals.pop_front()?;
            let Some(lane) = self.lanes.get_mut(&sender) else { continue };
            if lane.by_nonce.is_empty() {
                lane.queued = false;
                continue;
            }
            if skipped.contains(&sender) {
                self.arrivals.push_back(sender);
                continue;
            }
            // Parked behind a hole a build found ([`Parked`]): out of the
            // arrival order, so the build's whole candidate budget goes to
            // lanes that can execute. `park` filed it in `parked_order`
            // already, and that is the door back.
            //
            // The expiry is not tested here: a park this walk meets was set
            // during this build (a park from an earlier build took the lane
            // out of the order the first time the walk reached it, which is
            // within one build), so it cannot have expired yet.
            if lane.parked.is_some() {
                lane.queued = false;
                continue;
            }
            let (_, valid) = lane.by_nonce.pop_first()?;
            self.len -= 1;
            if lane.by_nonce.is_empty() {
                lane.queued = false;
            } else if run > 1 {
                self.current = Some((sender, run - 1));
            } else {
                self.arrivals.push_back(sender);
            }
            if let Some((_, taken)) = self.last_build.as_mut() {
                taken.push(Arc::clone(&valid));
            }
            return Some(valid);
        }
        None
    }
}

/// The builder's iterator over the queue. Implements reth's
/// [`BestTransactions`], so the payload builder takes it in place of the
/// pool's.
pub struct QueueBest<T: PoolTransaction> {
    /// A frame build's frames not yet handed out, in plan order: each
    /// frame's shared transactions, the next position to hand out and how
    /// many were taken from its start. A transaction is cloned out of its
    /// frame only when handed to the builder (on the builder's puller), so
    /// the selection itself touches no transaction.
    segments: VecDeque<(FrameTxs<T>, usize, usize)>,
    queue: TxQueue<T>,
    skipped: AddressHashSet,
    /// Transactions taken under one lock and not yet handed to the builder.
    /// `N42_TX_QUEUE_BATCH=<n>` sets how many are taken at a time; 1 (the
    /// default) locks once per transaction, which at the bench tier was
    /// ~100 ms of a full block's build, 0.6 us a transaction, in the lock
    /// and the inbox drain alone.
    buffer: VecDeque<Arc<ValidPoolTransaction<T>>>,
    batch: usize,
    /// A frame build ([`TxQueue::frames_for_build`]): only the planned
    /// frames, already in `buffer`, are offered; the lanes are not walked.
    frame_mode: bool,
    /// A frame build's first refusal: nothing more is offered, since a body
    /// with a hole in a frame is not frame-aligned.
    frames_ended: bool,
}

/// Where a frame build's selection ([`TxQueue::frames_for_build_timed`])
/// spent its time, in microseconds, and how it decided its frames.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameSelectTimes {
    /// Waiting for the lanes' lock.
    pub lock_us: u64,
    /// The build's opening under it: the inbox drained, the previous
    /// build's take given back, parked lanes readmitted.
    pub begin_us: u64,
    /// The plan: the frames checked and taken.
    pub plan_us: u64,
    /// Of `plan_us`, listing the live frame ids in arrival order.
    pub ids_us: u64,
    /// Of `plan_us`, the parallel check of the frames the gas reaches.
    pub check_us: u64,
    /// Of `plan_us`, applying the parallel part's takes before a serial
    /// part (0 when the plan ended in the parallel part: the takes are
    /// applied off the selection).
    pub settle_us: u64,
    /// Frames decided and taken by reference.
    pub by_ref: usize,
    /// Frames that went through the per-transaction check.
    pub slow: usize,
    /// Of `by_ref`, frames whose decision read the per-sender counters (a
    /// sender with entries below the frame's run in its lane).
    pub counted: usize,
    /// `N42_PLAN_AHEAD`: 0 the plan was made here, 1 it was prepared ahead
    /// and used as it was, 2 prepared ahead and topped up here (`plan_us`
    /// and the counters above are then the top-up's).
    pub ahead: u8,
    /// A used prepared plan's age at use, and its preparation's time.
    pub ahead_age_us: u64,
    /// Of a used prepared plan, how long its preparation took (lock wait
    /// included).
    pub ahead_prep_us: u64,
    /// Transactions the top-up added.
    pub ahead_topup_txs: usize,
    /// Why a prepared plan was not used, when there was one.
    pub ahead_discard: Option<AheadDiscard>,
}

/// How a frame build selects ([`Inner::plan_frames`]); the plan is the
/// same in every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectMode {
    /// The frames the gas reaches checked at once, the lanes' update left
    /// to [`Inner::settle`] (`N42_FRAME_SELECT_PARALLEL`, the default).
    Parallel,
    /// Each frame checked and taken in turn, by reference where it can be.
    Serial,
    /// Each frame by the per-transaction check (the selection before
    /// frames were taken by reference); for the tests' comparison.
    #[cfg_attr(not(test), allow(dead_code))]
    PerTx,
}

/// What [`Inner::plan_frame_slow`] did with one frame.
enum SlowFrame<T: PoolTransaction> {
    /// Not whole-usable: passed over.
    Skipped,
    /// Taken, whole (`true`) or cut to the gas left (`false`, the plan's end).
    Taken(Vec<Arc<ValidPoolTransaction<T>>>, bool),
    /// Nothing of it fits or could be taken: the plan ends here.
    End,
}

/// `N42_FRAME_SELECT_PARALLEL`, on unless `0`: a frame build checks the
/// frames the gas reaches at once on the worker pool and leaves the lanes'
/// update to [`Inner::settle`] ([`Inner::plan_parallel`]). Off, every frame
/// is checked and taken in turn. The plan is the same either way.
fn frame_select_parallel() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FRAME_SELECT_PARALLEL").map_or(true, |v| v != "0"))
}

/// `N42_TX_QUEUE_BATCH`, read once.
fn queue_batch() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| std::env::var("N42_TX_QUEUE_BATCH").ok().and_then(|v| v.parse().ok()).filter(|n| *n >= 1).unwrap_or(1))
}

/// Transactions a build took and gives back, indexed by allocation so that
/// [`Inner::untake_all`] forgets them from the build's taken list in one
/// pass. Built outside the queue's lock.
struct Returned<T: PoolTransaction> {
    transactions: Vec<Arc<ValidPoolTransaction<T>>>,
    /// How many times each allocation is returned.
    by_ptr: std::collections::HashMap<usize, u32>,
}

impl<T: PoolTransaction> Returned<T> {
    fn new(transactions: Vec<Arc<ValidPoolTransaction<T>>>) -> Self {
        let mut by_ptr = std::collections::HashMap::with_capacity(transactions.len());
        for transaction in &transactions {
            *by_ptr.entry(Arc::as_ptr(transaction) as usize).or_insert(0u32) += 1;
        }
        Self { transactions, by_ptr }
    }
}

impl<T: PoolTransaction> Inner<T> {
    /// Gives a build's untaken transactions back and forgets that the build
    /// took them: one pass over the taken list, then [`Self::give_back`]
    /// (which keeps each sender's nonces in their lane's order).
    ///
    /// The per-transaction untake this replaces searched the taken list from
    /// the back and removed from the middle of it for every transaction:
    /// quadratic in the selection. A refused chained build gives back a
    /// whole block (163,000 transactions) and held the lock 4,866 ms doing
    /// it (loop323 Ab, the tenure handover).
    fn untake_all(&mut self, returned: Returned<T>) {
        let Returned { transactions, mut by_ptr } = returned;
        if let Some((_, taken)) = self.last_build.as_mut()
            && !taken.is_empty()
        {
            taken.retain(|t| match by_ptr.get_mut(&(Arc::as_ptr(t) as usize)) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    false
                }
                _ => true,
            });
        }
        self.give_back(transactions);
    }
}

impl<T: PoolTransaction> QueueBest<T> {
    /// Returns a transaction taken but not built to the queue, and forgets
    /// that the build took it. The taken list ends with the buffered ones,
    /// so the search from the back is short.
    fn untake(inner: &mut Inner<T>, transaction: Arc<ValidPoolTransaction<T>>) {
        if let Some((_, taken)) = inner.last_build.as_mut() {
            if let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, &transaction)) {
                taken.remove(at);
            }
        }
        inner.give_back(vec![transaction]);
    }
}

impl<T: PoolTransaction> Drop for QueueBest<T> {
    fn drop(&mut self) {
        // A frame build's frames not handed out go back as its buffer does.
        for (txs, next, end) in std::mem::take(&mut self.segments) {
            self.buffer.extend(txs.get(next..end).into_iter().flatten().cloned());
        }
        if self.buffer.is_empty() {
            return;
        }
        // Indexed before the lock is taken: under it the give-back is one
        // pass over the build's taken list and one insert a transaction.
        let returned = Returned::new(self.buffer.drain(..).collect());
        let mut inner = self.queue.lock_inner();
        inner.untake_all(returned);
    }
}

impl<T: PoolTransaction> std::fmt::Debug for QueueBest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueBest").field("skipped", &self.skipped.len()).finish()
    }
}

impl<T: PoolTransaction> Iterator for QueueBest<T> {
    type Item = Arc<ValidPoolTransaction<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.frame_mode {
            // What is left in the buffer after the end goes back on drop.
            if self.frames_ended {
                return None;
            }
            while let Some((txs, next, end)) = self.segments.front_mut() {
                if *next < *end
                    && let Some(transaction) = txs.get(*next)
                {
                    *next += 1;
                    return Some(Arc::clone(transaction));
                }
                self.segments.pop_front();
            }
            return self.buffer.pop_front();
        }
        loop {
            if let Some(transaction) = self.buffer.pop_front() {
                // A sender the build refused meanwhile: its buffered
                // transactions go back rather than to the builder.
                if self.skipped.contains(&transaction.sender()) {
                    let mut inner = self.queue.lock_inner();
                    Self::untake(&mut inner, transaction);
                    continue;
                }
                return Some(transaction);
            }
            let mut inner = self.queue.lock_inner();
            self.queue.drain_inbox(&mut inner);
            if self.batch <= 1 {
                return inner.next_ready(&self.skipped);
            }
            for _ in 0..self.batch {
                match inner.next_ready(&self.skipped) {
                    Some(transaction) => self.buffer.push_back(transaction),
                    None => break,
                }
            }
            if self.buffer.is_empty() {
                return None;
            }
        }
    }
}

impl<T: PoolTransaction> BestTransactions for QueueBest<T> {
    /// The build refused this transaction: it goes back where it was and the
    /// sender's later nonces are not offered again in this build. A stale
    /// one (nonce below the account's) is dropped instead.
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        if self.frame_mode {
            self.frames_ended = true;
        }
        let sender = transaction.sender();
        let stale = matches!(&kind, InvalidPoolTransactionError::Consensus(err) if err.is_nonce_too_low());
        if stale {
            let nonce = transaction.nonce();
            let mut inner = self.queue.lock_inner();
            // Only the chain can say a nonce is behind it.
            //
            // A build's state is its parent's, and a parent is not always a
            // block consensus keeps. loop214 Pd node2 ran three builds at
            // once for heights 637-639 that were already committed
            // (`a build on another parent was superseded` twice in half a
            // second, `forgotten=0` on the hand-off of 639); each stood on a
            // block of its own that the chain replaced, and each was offered
            // a sender's run of 64 that its own state had already executed.
            // It refused them one at a time as behind the chain, and each
            // refusal took one more nonce out of the queue for good. The
            // chain had mined none of them: the sender's account stayed at 0
            // while its lane started at 64, 192, 320 -- whole multiples of
            // the run a build takes -- and every later nonce of that sender
            // queued behind the hole for the rest of the leg. Twenty-nine
            // senders on that node, `(sender, 0, 64)` and `(sender, 0, 256)`
            // on the holes line, and none of them gapped on any other node.
            //
            // So the verdict is acted on only as far as a canonical block
            // has confirmed it. Past that the transaction goes back the
            // ordinary way, to be offered again and removed by the prune if
            // the chain really does mine it.
            let confirmed = inner.lanes.get(&sender).is_some_and(|lane| lane.chain_mined(nonce));
            if !confirmed {
                inner.dropped(Dropped::StaleUnconfirmed, sender, nonce);
                drop(inner);
                self.skipped.insert(sender);
                let mut inner = self.queue.lock_inner();
                if let Some((_, taken)) = inner.last_build.as_mut()
                    && let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction))
                {
                    taken.remove(at);
                }
                inner.give_back(vec![Arc::clone(transaction)]);
                return;
            }
            // The chain is past this nonce. It used to be left in the build's
            // taken list -- not given back, but not forgotten either -- so the
            // next give-back on that parent put it in the lanes again, and
            // every build of this leader took it, refused it and gave it back
            // (round 44). Drop it and everything below it for this sender,
            // and mark the lane so no give-back can bring it back.
            //
            // The sender is deliberately not skipped for the rest of this
            // build: its higher nonces are what the chain wants next, and
            // this one being stale says nothing against them.
            if let Some((_, taken)) = inner.last_build.as_mut()
                && let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction))
            {
                taken.remove(at);
            }
            inner.dropped(Dropped::StaleRefusal, sender, nonce);
            inner.remove_mined_from(sender, nonce, true);
            return;
        }
        self.skipped.insert(sender);
        let mut inner = self.queue.lock_inner();
        if let Some((_, taken)) = inner.last_build.as_mut() {
            // The refused transaction is the one just yielded or one of the
            // few buffered after it: found from the back. A scan of
            // everything the build took (165,000 at the bench tier, once
            // per refused sender) was most of a full block's loop tail.
            if let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction)) {
                taken.remove(at);
            }
        }
        if let InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent {
            tx,
            state,
        }) = &kind
        {
            if tx > state {
                inner.gaps.push((sender, *state, *tx));
                // Nothing in this lane can execute until the hole is
                // filled, and its head is what every build is offered
                // first: stepped over until then ([`Parked`]).
                inner.park(sender, *state);
            }
        }
        inner.give_back(vec![Arc::clone(transaction)]);
    }

    fn no_updates(&mut self) {}

    fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
}

static GLOBAL: OnceLock<Option<Box<dyn Any + Send + Sync>>> = OnceLock::new();

/// Installs the fleet-wide queue for `T`, once. Returns whether this call
/// installed it.
pub fn install<T: PoolTransaction + 'static>(queue: TxQueue<T>) -> bool {
    GLOBAL.set(Some(Box::new(queue))).is_ok()
}

/// The installed queue for `T`, if one was installed with that type.
pub fn global<T: PoolTransaction + 'static>() -> Option<TxQueue<T>> {
    GLOBAL.get()?.as_ref()?.downcast_ref::<TxQueue<T>>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Signature, TxKind, U256};
    use reth_transaction_pool::EthPooledTransaction;

    fn tx(sender_seed: u8, nonce: u64) -> EthPooledTransaction {
        use alloy_consensus::{Signed, TxEip1559};
        let inner = TxEip1559 { chain_id: 1, nonce, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(9)), value: U256::from(1), ..Default::default() };
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), Default::default());
        let recovered = reth_primitives_traits::Recovered::new_unchecked(reth_ethereum_primitives::TransactionSigned::from(signed), Address::repeat_byte(sender_seed));
        EthPooledTransaction::new(recovered, 120)
    }

    /// A block's worth of transactions for `round`: one lane per sender,
    /// `per` nonces each, with addresses that do not collide across rounds.
    /// A free function rather than a closure, because the bench's ingest
    /// thread builds them too.
    fn block_of(senders: u64, per: u64, round: u64) -> Vec<EthPooledTransaction> {
        let mut all = Vec::with_capacity((senders * per) as usize);
        for n in 0..per {
            for sn in 0..senders {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(sn + 1).to_be_bytes());
                a[8..12].copy_from_slice(&(round as u32).to_be_bytes());
                all.push(tx_hashed(Address::from(a), n));
            }
        }
        all
    }

    /// [`tx_of`] with a hash of its own. The fixtures here leave the cached
    /// hash at zero, which is fine for a queue keyed by sender and nonce and
    /// not for one looked up by hash.
    fn tx_hashed(sender: Address, nonce: u64) -> EthPooledTransaction {
        use alloy_consensus::{Signed, TxEip1559};
        let inner = TxEip1559 { chain_id: 1, nonce, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(9)), value: U256::from(1), ..Default::default() };
        // Keccak, because a real transaction hash is one: the index shards
        // on the hash's first byte, and a fixture whose hashes all begin
        // with the same byte would measure one shard rather than the index.
        let mut seed = [0u8; 28];
        seed[..20].copy_from_slice(sender.as_slice());
        seed[20..].copy_from_slice(&nonce.to_be_bytes());
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), alloy_primitives::keccak256(seed));
        let recovered = reth_primitives_traits::Recovered::new_unchecked(reth_ethereum_primitives::TransactionSigned::from(signed), sender);
        EthPooledTransaction::new(recovered, 120)
    }

    fn tx_of(sender: Address, nonce: u64) -> EthPooledTransaction {
        use alloy_consensus::{Signed, TxEip1559};
        let inner = TxEip1559 { chain_id: 1, nonce, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(9)), value: U256::from(1), ..Default::default() };
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), Default::default());
        let recovered = reth_primitives_traits::Recovered::new_unchecked(reth_ethereum_primitives::TransactionSigned::from(signed), sender);
        EthPooledTransaction::new(recovered, 120)
    }

    /// What the by-hash index costs the two sides that matter, at the bench
    /// tier and with an ingest running at the same time.
    ///
    /// The builder's pull is the number that decides whether the compact
    /// body may be turned on at all: loop195 P2 read `par_pull_ms` 98-106
    /// against P1's 17-26, and an idle single-threaded drain measurement
    /// (+30-44 ns a transaction) had not predicted it. What it measures, in
    /// order: the pusher's own cost, the drain into the lanes, the builder's
    /// walk over a block's worth, and a block's assembly look-ups -- the
    /// last two with an ingest thread pushing into the same queue
    /// throughout, because that is the only way the contention this is
    /// about appears at all.
    ///
    /// `RAYON_NUM_THREADS=16 taskset -c 0-31 cargo test --release -p
    /// n42-tx-queue --lib bench_hash_index -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing"]
    fn bench_hash_index() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let senders = 6_000u64;
        let per = 27u64;
        let block = (senders * per) as usize;
        // Four blocks in the lanes before the build, as the bench's pool is
        // sized (loop194 X2), so the walk is over a deep queue.
        let depth = 4u64;
        let build = |round: u64| block_of(senders, per, round);
        // Both orders, because the second leg in a process runs on a warmer
        // and more fragmented heap than the first and that alone is worth a
        // few milliseconds of the builder's walk.
        let legs: Vec<(&str, TxQueue<EthPooledTransaction>)> = vec![
            ("without", TxQueue::<EthPooledTransaction>::with_run_length(64)),
            (
                "with   ",
                TxQueue::<EthPooledTransaction>::with_run_length(64).with_hash_index(block * 8),
            ),
            (
                "with   ",
                TxQueue::<EthPooledTransaction>::with_run_length(64).with_hash_index(block * 8),
            ),
            ("without", TxQueue::<EthPooledTransaction>::with_run_length(64)),
        ];
        for (what, queue) in legs {
            // The lanes, filled to the bench's depth.
            for round in 0..depth {
                queue.push(build(round));
            }
            queue.drain_now();
            let wanted = build(depth);
            let hashes: Vec<B256> = wanted.iter().map(|t| *t.hash()).collect();
            let at = std::time::Instant::now();
            queue.push(wanted);
            let push = at.elapsed();
            let at = std::time::Instant::now();
            queue.drain_now();
            let drain = at.elapsed();

            // An ingest pushing throughout the two measurements below, as
            // one runs on the fleet: batches of 500, the shape a flood frame
            // arrives in, and transactions built *before* the thread starts
            // -- a thread that built them itself spent the whole measurement
            // building and pushed nothing.
            let feed: Vec<EthPooledTransaction> =
                (depth + 1..depth + 3).flat_map(|round| block_of(senders, per, round)).collect();
            let started = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let pusher = {
                let queue = queue.clone();
                let stop = Arc::clone(&stop);
                let started = Arc::clone(&started);
                std::thread::spawn(move || {
                    let mut pushed = 0usize;
                    for chunk in feed.chunks(500) {
                        started.store(true, Ordering::Relaxed);
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        queue.push(chunk.to_vec());
                        pushed += chunk.len();
                    }
                    pushed
                })
            };
            // Let it get going, so the measurements below overlap it rather
            // than race its first push.
            while !started.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }

            // The builder's walk: a block's worth out of the queue, the way
            // the puller thread takes it.
            let at = std::time::Instant::now();
            let mut best = queue.best_for_build(B256::repeat_byte(1));
            let mut taken = 0usize;
            for t in best.by_ref() {
                std::hint::black_box(&t);
                taken += 1;
                if taken == block {
                    break;
                }
            }
            let pull = at.elapsed();
            drop(best);

            // A block's assembly, on the worker pool, against the same
            // queue the ingest is still writing to.
            let at = std::time::Instant::now();
            let found = queue.get_by_hashes(&hashes).iter().filter(|t| t.is_some()).count();
            let lookup = at.elapsed();
            stop.store(true, Ordering::Relaxed);
            let pushed = pusher.join().unwrap_or(0);

            eprintln!(
                "{what} index: push {:>7.1} ms ({:>4.0} ns/tx) | drain {:>7.1} ms ({:>4.0} ns/tx) | \
                 builder pull {taken} in {:>7.1} ms ({:>4.0} ns/tx) | look {block} up in {:>6.1} ms \
                 ({:>4.0} ns/tx), found {found} | ingest pushed {pushed} meanwhile",
                push.as_secs_f64() * 1e3,
                push.as_nanos() as f64 / block as f64,
                drain.as_secs_f64() * 1e3,
                drain.as_nanos() as f64 / block as f64,
                pull.as_secs_f64() * 1e3,
                pull.as_nanos() as f64 / taken.max(1) as f64,
                lookup.as_secs_f64() * 1e3,
                lookup.as_nanos() as f64 / block as f64,
            );
        }
    }

    /// A transaction a build has taken, and one an own block is holding, are
    /// still found by hash: a follower that was leader a moment ago has to
    /// assemble the block after its own out of the same queue, and both of
    /// those have left the lanes.
    #[test]
    fn the_index_still_holds_what_a_build_took_and_what_a_block_holds() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(1).with_hash_index(64);
        let first = tx_hashed(Address::repeat_byte(1), 0);
        let second = tx_hashed(Address::repeat_byte(2), 0);
        let (taken, held) = (*first.hash(), *second.hash());
        queue.push(vec![first, second]);
        queue.drain_now();

        // One goes out with a build and stays out until the build is given
        // back; the other is carried away by an own block the chain has not
        // settled yet.
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        let taken_tx = best.next().expect("a build takes one");
        let held_tx = best.next().expect("and the other");
        drop(best);
        let removed = queue.remove_mined_batch_collecting([(held_tx.sender(), held_tx.nonce())]);
        queue.hold_own_block(1, B256::repeat_byte(9), removed);
        assert_eq!(taken_tx.hash(), &taken);

        let found = queue.get_by_hashes(&[taken, held]);
        assert!(found[0].is_some(), "the build's transaction is still findable");
        assert!(found[1].is_some(), "and so is the held block's");
        assert_eq!(queue.hash_index_len(), 2);
    }

    /// The sender look-up the follower's import uses: the address this node
    /// recorded when the transaction arrived, for what the index holds, and
    /// a plain miss for everything else -- a transaction that never came
    /// this way, and a queue that keeps no index at all.
    #[test]
    fn the_index_hands_back_the_sender_it_recorded() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(1).with_hash_index(64);
        let sender = Address::repeat_byte(3);
        let one = tx_hashed(sender, 0);
        let hash = *one.hash();
        let elsewhere = *tx_hashed(Address::repeat_byte(4), 0).hash();
        queue.push(vec![one]);
        queue.drain_now();

        assert_eq!(queue.sender_of(&hash), Some(sender), "the sender the ingest recovered");
        assert_eq!(queue.sender_of(&elsewhere), None, "and a miss for one that never came this way");

        let without: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(1);
        without.push(vec![tx_hashed(sender, 0)]);
        without.drain_now();
        assert_eq!(without.sender_of(&hash), None, "a queue without an index misses everything");
    }

    /// The index is a cache: what it does not hold is a miss, never a wrong
    /// transaction, and a queue that keeps none misses everything.
    #[test]
    fn a_queue_without_an_index_finds_nothing_and_says_so() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(1);
        let one = tx_hashed(Address::repeat_byte(1), 0);
        let hash = *one.hash();
        queue.push(vec![one]);
        queue.drain_now();
        assert!(!queue.has_hash_index());
        assert_eq!(queue.hash_index_len(), 0);
        assert!(queue.get_by_hashes(&[hash])[0].is_none());
        assert_eq!(queue.len(), 1, "and the queue itself is untouched");
    }

    /// The bound drops the oldest and keeps the newest, so an index sized
    /// above the queue's depth always holds what the next block names.
    #[test]
    fn the_index_is_bounded_by_what_it_was_sized_for() {
        // One entry per shard, so the bound bites wherever the hashes fall.
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(1).with_hash_index(HASH_INDEX_SHARDS);
        let mut hashes = Vec::new();
        for n in 0..400u64 {
            let t = tx_hashed(Address::repeat_byte(7), n);
            hashes.push(*t.hash());
            queue.push(vec![t]);
            queue.drain_now();
        }
        assert!(queue.hash_index_len() <= HASH_INDEX_SHARDS, "the bound holds");
        assert!(queue.hash_index_len() > 0);
        assert_eq!(queue.len(), 400, "and the queue itself is not bounded by it");
        let found = queue.get_by_hashes(&hashes);
        assert!(found.last().expect("the newest").is_some(), "the newest is kept");
    }

    /// The queue's own cost per transaction at the bench tier's shape
    /// (6,000 senders, 30 transactions each), apart from everything the
    /// builder does around it. `cargo test -p n42-tx-queue --release -- --ignored bench_ --nocapture`.
    #[test]
    #[ignore]
    fn bench_next_at_the_bench_tier() {
        let senders = 6_000u64;
        let per = 30u64;
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let mut all = Vec::with_capacity((senders * per) as usize);
        for n in 0..per {
            for s in 0..senders {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(s + 1).to_be_bytes());
                all.push(tx_of(Address::from(a), n));
            }
        }
        let pushed_at = std::time::Instant::now();
        queue.push(all);
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        assert!(best.next().is_some());
        let pushed = pushed_at.elapsed();
        drop(best);
        for round in 0..3 {
            let mut best = queue.best_for_build(B256::repeat_byte(2 + round));
            let at = std::time::Instant::now();
            let mut n = 0u64;
            while let Some(t) = best.next() {
                n += 1;
                std::hint::black_box(&t);
                if n == 163_000 { break; }
            }
            let took = at.elapsed();
            eprintln!("round {round}: {n} next() in {:?} = {:.0} ns/tx (push+drain {:?})", took, took.as_nanos() as f64 / n as f64, pushed);
            drop(best);
        }
        // The canonical prune of a full block whose transactions a build took.
        let mut best = queue.best_for_build(B256::repeat_byte(9));
        let mined: Vec<(Address, u64)> = std::iter::from_fn(|| best.next()).take(163_000).map(|t| (t.sender(), t.nonce())).collect();
        drop(best);
        let at = std::time::Instant::now();
        queue.remove_mined_batch(mined);
        eprintln!("remove_mined_batch of 163,000 taken: {:?}", at.elapsed());
    }

    /// What the ingest's gate measures (`n42-tx-ingest`: the gate reads
    /// `TxQueue::len()`) is what the *next build* can still use, and nothing
    /// else: a transaction a build has taken, and one held for an own block
    /// the chain has not settled, are both outside it.
    ///
    /// Asked of this file because the build chain leaves three own blocks
    /// outstanding instead of two, and the question was whether that starves
    /// the gate. It does not -- held transactions were already out of `len`
    /// when the build took them.
    #[test]
    fn the_gates_depth_counts_neither_what_a_build_took_nor_what_is_held() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(2, 0), tx(2, 1)]);
        assert_eq!(queue.len(), 4);
        let parent = B256::repeat_byte(3);
        let mut best = queue.best_for_build(parent);
        let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        drop(best);
        assert_eq!(taken.len(), 4);
        assert_eq!(queue.len(), 0, "a build's take leaves the gate's depth as it is taken");
        let dropped = queue.forget_mined(parent, [(Address::repeat_byte(1), 1), (Address::repeat_byte(2), 1)]);
        assert_eq!(dropped.len(), 4);
        queue.hold_own_block(11, B256::repeat_byte(9), dropped);
        assert_eq!(queue.len(), 0, "holding an own block's transactions does not put them back in the gate's depth");
        // And the gate sees new arrivals at once, which is what makes it a
        // gate on the refill rather than on the blocks in flight.
        queue.push([tx(3, 0)]);
        assert_eq!(queue.len(), 1);
    }

    /// A gapped nonce as a build's refusal reports it: the account is at
    /// `state`, the lane's head is `tx`, and nothing between them exists.
    fn gap(tx: u64, state: u64) -> InvalidPoolTransactionError {
        InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx, state })
    }

    /// Takes a whole build's worth and refuses every head the way the
    /// builder's parallel step now does: the account's nonce against the
    /// lane's head. Returns what the build was handed, as (sender byte,
    /// nonce).
    fn build_refusing_gaps(
        queue: &TxQueue<EthPooledTransaction>,
        parent: B256,
        account_nonce: &dyn Fn(u8) -> u64,
    ) -> Vec<(u8, u64)> {
        // `account_nonce` is keyed by the address's first byte, which is
        // all the fixtures here need.
        let mut best = queue.best_for_build(parent);
        let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        let handed: Vec<(u8, u64)> = taken.iter().map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        // The head per sender, as the builder's parallel step reports it:
        // the first candidate it was handed for that sender, and only that
        // one.
        let mut seen: AddressHashSet = Default::default();
        for t in &taken {
            if !seen.insert(t.sender()) {
                continue;
            }
            let state = account_nonce(t.sender().as_slice()[0]);
            if t.nonce() != state {
                best.mark_invalid(t, gap(t.nonce(), state));
            }
        }
        drop(best);
        handed
    }

    /// The deep-and-unusable queue of loop207 Ob node1: most lanes hold a
    /// run whose head is above the account's nonce, a few are whole, and
    /// the build's whole budget was going to the gapped heads -- the same
    /// ones, build after build, because a refusal handed them straight back
    /// to their lanes and a lane's head is what every build is offered
    /// first.
    ///
    /// With the gap reported, those lanes are parked and the next build
    /// finds the nonces it can actually mine.
    #[test]
    fn a_build_steps_over_lanes_parked_behind_a_hole_and_finds_the_next_nonces() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(64);
        // Senders 1..=4 are gapped: the chain has them at nonce 0 and the
        // queue's lowest nonce for each is 5. Senders 5..=40 are whole --
        // a minority gapped, which is the shape a hole takes and the shape
        // the park's cap allows.
        let gapped: Vec<u8> = (1..=4).collect();
        let whole: Vec<u8> = (5..=40).collect();
        let mut all = Vec::new();
        for s in &gapped {
            for n in 5..15 {
                all.push(tx(*s, n));
            }
        }
        for s in &whole {
            for n in 0..10 {
                all.push(tx(*s, n));
            }
        }
        let queued = all.len();
        queue.push(all);
        assert_eq!(queue.len(), queued);
        assert_eq!(queue.usable(), queued, "nothing is parked before a build says so");

        let account_nonce = |_s: u8| 0;
        // The first build is offered the gapped heads and refuses them; the
        // whole lanes start at nonce 0 and are never refused.
        let first = build_refusing_gaps(&queue, B256::repeat_byte(1), &account_nonce);
        assert!(first.iter().any(|(s, _)| *s <= 4), "the first build was offered the gapped lanes");

        // The next build: its start gives the first build's take back, so
        // everything is in the lanes again -- and the depth and what a
        // build could take of it part company, which is what `usable=`
        // says.
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        assert_eq!(queue.len(), queued);
        assert_eq!(queue.usable(), whole.len() * 10);
        let second: Vec<(u8, u64)> =
            std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        drop(best);
        assert!(second.iter().all(|(s, _)| *s > 4), "a parked lane was offered again: {second:?}");
        assert_eq!(second.len(), whole.len() * 10, "the build did not find the nonces it could mine");
    }

    /// The hole, reproduced: a nonce the queue held, that no block of the
    /// chain ever carried, and that the queue would have lost for good.
    ///
    /// A build of ours seals block B at height 10 and the queue holds B's
    /// transactions until the chain settles that height. A later build --
    /// standing on B, whose state has the sender past that nonce -- is
    /// offered it again and refuses it as behind the chain, which raises the
    /// lane's watermark (round 44: without that, a mined transaction is
    /// re-offered to every build for the rest of the leg). Consensus then
    /// commits somebody else's block at height 10. The give-back meets the
    /// watermark, the nonce is filtered out, and the sender's lane starts
    /// above the chain's nonce with every later nonce stranded behind the
    /// hole -- which is exactly the state the leader's builds ran into.
    #[test]
    fn an_own_block_the_chain_replaced_gives_back_a_nonce_a_build_called_stale() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(64);
        let sender = Address::repeat_byte(1);
        queue.push((0..4).map(|n| tx(1, n)).collect::<Vec<_>>());

        // The build that becomes our block at height 10 takes nonces 0-1.
        let parent = B256::repeat_byte(3);
        let mut best = queue.best_for_build(parent);
        let ours: Vec<_> = (0..2).map(|_| best.next().expect("the lane's head")).collect();
        drop(best);
        let mined = queue.forget_mined(parent, ours.iter().map(|t| (t.sender(), t.nonce())));
        assert_eq!(mined.len(), 2);
        let block = B256::repeat_byte(10);
        queue.hold_own_block(10, block, mined);

        // A later build on our block is offered nonce 0 again -- a second
        // build on the same parent gives the first build's take back -- and
        // refuses it, because the state it stands on is past it.
        queue.push(vec![tx(1, 0)]);
        let mut best = queue.best_for_build(B256::repeat_byte(4));
        let head = best.next().expect("offered again");
        assert_eq!(head.nonce(), 0);
        best.mark_invalid(
            &head,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx: 0, state: 2 }),
        );
        drop(best);

        // Consensus commits another block at height 10, carrying nothing of
        // ours.
        let back = queue.settle_own_block(10, B256::repeat_byte(11), |_, _| false);
        assert_eq!(back, 2, "the held block's nonces did not come back");

        // The chain is at nonce 0 for this sender, and so is the queue.
        let mut best = queue.best_for_build(B256::repeat_byte(5));
        let offered: Vec<u64> = std::iter::from_fn(|| best.next()).map(|t| t.nonce()).collect();
        drop(best);
        assert_eq!(offered.first().copied(), Some(0), "a hole was left at the head of the lane");
        assert_eq!(offered, vec![0, 1, 2, 3]);
        let _ = sender;
    }

    /// Whatever the queue lets go of is counted and the first few are
    /// named, so a hole is never silent.
    #[test]
    fn what_the_queue_lets_go_of_is_counted_by_reason() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(64);
        queue.push(vec![tx(1, 0), tx(1, 1)]);
        queue.drain_now();
        // A duplicate.
        queue.push(vec![tx(1, 0)]);
        queue.drain_now();
        // An arrival a canonical block is past: `mined`, not a suspect.
        queue.remove_mined_batch([(Address::repeat_byte(1), 1)]);
        queue.push(vec![tx(1, 1)]);
        queue.drain_now();
        // A build's verdict a canonical block confirms: `stale_refusal`.
        queue.push(vec![tx(2, 5), tx(2, 6)]);
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        let head = best.next().expect("the lane's head");
        queue.remove_mined_batch([(Address::repeat_byte(2), 5)]);
        best.mark_invalid(
            &head,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx: 5, state: 9 }),
        );
        drop(best);
        // A build's verdict no block confirms: `stale_unconfirmed`, and the
        // transaction goes back rather than out.
        queue.push(vec![tx(3, 0), tx(3, 1)]);
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let head = std::iter::from_fn(|| best.next())
            .find(|t| t.sender() == Address::repeat_byte(3))
            .expect("the third sender");
        best.mark_invalid(
            &head,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx: 0, state: 7 }),
        );
        drop(best);

        let report = queue.take_drops();
        assert!(report.interesting(), "{report:?}");
        let named: alloy_primitives::map::HashMap<&str, u64> = report.named().into_iter().collect();
        assert_eq!(named.get("duplicate"), Some(&1), "{named:?}");
        assert_eq!(named.get("mined"), Some(&1), "{named:?}");
        assert_eq!(named.get("stale_refusal"), Some(&1), "{named:?}");
        assert_eq!(named.get("stale_unconfirmed"), Some(&1), "{named:?}");
        assert!(
            !report.samples.iter().any(|(r, _, _)| *r == Dropped::Mined),
            "a transaction the chain holds is not a suspect"
        );
        // The unconfirmed one is still in the queue.
        let mut after = queue.best_for_build(B256::repeat_byte(3));
        let offered: Vec<(u8, u64)> =
            std::iter::from_fn(|| after.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        drop(after);
        assert!(offered.contains(&(3, 0)), "an unconfirmed verdict took it out of the queue: {offered:?}");
        // Taking it clears it.
        assert_eq!(queue.take_drops(), DropReport::default());
    }

    /// The two doors the builder's claim check uses: a transaction it pulled
    /// ahead and never offered goes back to its lane, and one whose claim
    /// the signature contradicted leaves for good -- without taking the rest
    /// of its sender's lane with it.
    #[test]
    fn untake_puts_it_back_and_forget_taken_does_not() {
        // Roomy, because the bound is per shard: a capacity of one shard's
        // worth would let one of these three evict another.
        let queue = TxQueue::<EthPooledTransaction>::with_run_length(64).with_hash_index(4_096);
        queue.push(vec![
            tx_hashed(Address::repeat_byte(1), 0),
            tx_hashed(Address::repeat_byte(1), 1),
            tx_hashed(Address::repeat_byte(1), 2),
        ]);
        queue.drain_now();

        let mut best = queue.best_for_build(B256::repeat_byte(1));
        let first = best.next().expect("the lane's head");
        let second = best.next().expect("the lane's second");
        drop(best);
        assert_eq!(queue.len(), 1, "the build took two of the three");

        queue.untake(vec![Arc::clone(&second)]);
        assert_eq!(queue.sender_of(second.hash()), Some(Address::repeat_byte(1)));
        queue.forget_taken(&first);
        assert_eq!(queue.sender_of(first.hash()), None, "a forgotten transaction leaves the index");

        let mut after = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<u64> = std::iter::from_fn(|| after.next()).map(|t| t.nonce()).collect();
        drop(after);
        assert_eq!(offered, vec![1, 2], "the untaken one is offered again, the forgotten one is not");
    }

    #[test]
    fn the_parked_total_matches_the_walk_through_every_door() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(64);
        let check = |queue: &TxQueue<EthPooledTransaction>, what: &str| {
            let inner = queue.inner.lock();
            let (_, walked) = inner.parked_walked();
            assert_eq!(inner.parked_len, walked, "{what}");
        };
        // Three gapped lanes and one whole one.
        let mut all = Vec::new();
        for s in 1..=3u8 {
            all.extend((5..15).map(|n| tx(s, n)));
        }
        all.extend((0..10).map(|n| tx(9, n)));
        queue.push(all);
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        check(&queue, "after the parks");
        assert!(queue.parked().1 > 0, "nothing was parked");
        assert_eq!(queue.gate_len() + queue.parked().1, queue.len());

        // A later nonce arriving at a parked lane.
        queue.push(vec![tx(1, 20)]);
        queue.drain_now();
        check(&queue, "after an arrival above the hole");
        // The hole filled.
        queue.push(vec![tx(2, 0)]);
        queue.drain_now();
        check(&queue, "after the hole was filled");
        // The chain passing another lane's hole, with part of that lane at
        // or below the nonce it passed: the prune and the unpark happen in
        // one call and both have to be accounted for.
        queue.push(vec![tx(3, 2), tx(3, 3)]);
        queue.drain_now();
        check(&queue, "after an arrival below a parked lane's hole");
        queue.remove_mined(Address::repeat_byte(3), 6);
        check(&queue, "after the chain passed a hole");
        assert_eq!(queue.parked().1, {
            let inner = queue.inner.lock();
            inner.parked_walked().1
        });
        // An own block taking part of a parked lane out.
        queue.push(vec![tx(1, 0), tx(1, 1)]);
        queue.drain_now();
        let removed = queue.remove_mined_batch_collecting([(Address::repeat_byte(1), 1)]);
        assert!(!removed.is_empty());
        check(&queue, "after an own block took part of a lane");
        // And the expiry.
        for i in 0..PARK_BUILDS + 1 {
            let _ = queue.best_for_build(B256::from([i as u8 + 40; 32]));
            check(&queue, "after a build");
        }
        assert_eq!((queue.parked().0, queue.parked().1), (0, 0), "a park outlived its expiry");
    }

    /// The gate's depth leaves out what a parked lane holds, so a hole
    /// cannot hold the ingest off a node that is starving for supply
    /// (loop209 Pa node3: depth 569,520 against a gate of 543,333, all of
    /// it parked, and fifteen seconds of empty blocks).
    #[test]
    fn the_gates_depth_leaves_out_the_parked_lanes() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(64);
        let mut all = Vec::new();
        for s in 1..=3u8 {
            all.extend((5..15).map(|n| tx(s, n)));
        }
        // Enough whole lanes that the gapped three are a minority the cap
        // allows to park.
        for s in 4..=40u8 {
            all.extend((0..10).map(|n| tx(s, n)));
        }
        let queued = all.len();
        queue.push(all);
        assert_eq!(queue.gate_len(), queued);
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.parked().0, 3);
        assert_eq!(
            queue.len() - queue.gate_len(),
            queue.parked().1,
            "the gate was held against transactions no build can take"
        );
        assert!(queue.parked().1 > 0);
        assert!(!queue.is_empty(), "the queue still holds them");
    }

    /// A build standing on a parent below what the prune has taken out of
    /// the lanes is standing behind its own queue.
    ///
    /// loop213 Pe was read against this and it did *not* hold: node3's 26
    /// empty builds were chained builds whose parent was its own previous
    /// block, canonical and committed 100-200 ms before the build ran. The
    /// reading is kept because it is O(1) and it is the one question the
    /// logs could not answer at the time.
    #[test]
    fn the_queue_says_what_it_has_been_pruned_through() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4);
        assert_eq!(queue.pruned_through(), 0);
        queue.push((0..4).map(|n| tx(1, n)).collect::<Vec<_>>());
        queue.drain_now();
        // Two blocks a parent at height 7 does not have.
        queue.remove_mined_batch([(Address::repeat_byte(1), 1)]);
        queue.note_pruned(8);
        queue.remove_mined_batch([(Address::repeat_byte(1), 2)]);
        queue.note_pruned(9);
        assert_eq!(queue.pruned_through(), 9);
        assert!(queue.pruned_through() > 7, "a build on block 7 is behind the queue");
        // And the lane now starts above what that parent's state would be
        // waiting for, which is what such a build sees.
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        let offered: Vec<u64> = std::iter::from_fn(|| best.next()).map(|t| t.nonce()).collect();
        drop(best);
        assert_eq!(offered, vec![3]);
    }

    /// Parking is off unless a caller asks for it: a build reporting a hole
    /// costs one refusal and the lane keeps its turn, which is what the
    /// queue did before parks existed.
    #[test]
    fn parking_is_off_by_default() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4);
        queue.push((5..15).map(|n| tx(1, n)).collect::<Vec<_>>());
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.parked(), (0, 0, 1), "a lane was parked with parking off");
        // And the lane is still walked, head and all.
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<u64> = std::iter::from_fn(|| best.next()).map(|t| t.nonce()).collect();
        drop(best);
        assert_eq!(offered.first().copied(), Some(5));
        assert_eq!(offered.len(), 10);
    }

    /// Why parking is off: a parked lane is a sink, and the cap bounds how
    /// many sinks there are rather than how large each one grows.
    ///
    /// This is loop211 Pd node1 in miniature. Its parked lanes sat at
    /// exactly the 64 the cap allows while what they held went from 1,434
    /// transactions each to 5,505 over fourteen blocks -- 91,764 to 355,700
    /// -- because the generator keeps feeding a gapped sender at full rate,
    /// nothing drains a parked lane, and `gate_len` leaves it out, so the
    /// ingest never pushes back either. `usable` fell 322,574 -> 10,132 in
    /// step and the node built 55 empty blocks over a queue of 370,000.
    #[test]
    fn a_parked_lane_grows_without_bound_while_the_cap_holds() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(2);
        // Two gapped senders and enough whole ones that a build has work.
        let mut all = Vec::new();
        for s in 1..=2u8 {
            all.extend((5..9).map(|n| tx(s, n)));
        }
        for s in 3..=20u8 {
            all.extend((0..4).map(|n| tx(s, n)));
        }
        queue.push(all);
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.parked().0, 2, "the two gapped lanes did not park");
        let after_park = queue.parked().1;

        // The generator goes on feeding those two senders; nothing drains
        // them, and the gate is not told about them.
        for round in 0..8u64 {
            queue.push((0..2u8).flat_map(|s| (20 + round * 10..30 + round * 10).map(move |n| tx(s + 1, n))).collect::<Vec<_>>());
            queue.drain_now();
        }
        let grown = queue.parked().1;
        assert!(grown > after_park + 100, "the sink did not grow: {after_park} -> {grown}");
        assert_eq!(queue.parked().0, 2, "the cap moved");
        assert_eq!(
            queue.len() - queue.gate_len(),
            grown,
            "the ingest gate was told nothing about what the sinks hold"
        );
    }

    /// No build can park more than the cap's worth of lanes, whatever it
    /// reports.
    ///
    /// On loop210 one build a leg parked the node's whole sender set -- 384
    /// lanes, 631,212 transactions in Pb node3 -- and the four blocks after
    /// it carried 8,500 to 65,828 instead of 163,000. The builder no longer
    /// asks for that; this is the bound that holds if anything ever does
    /// again.
    #[test]
    fn no_build_parks_more_lanes_than_the_cap() {
        const CAP: usize = 64;
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(CAP);
        let lanes = CAP + 40;
        let mut all = Vec::new();
        for s in 0..lanes {
            let mut a = [0u8; 20];
            a[..8].copy_from_slice(&(s as u64 + 1).to_be_bytes());
            all.extend((5..9).map(|n| tx_of(Address::from(a), n)));
        }
        queue.push(all);
        // Every lane gapped, which is what a build on a parent the chain has
        // moved past reports.
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.parked().0, CAP, "the cap did not hold");
        assert!(queue.parked().2 >= 40, "the refused parks were not counted");
        // The lanes the cap refused are still walked, so the node is not
        // left with nothing to build from.
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        drop(best);
        assert!(!offered.is_empty(), "every lane was taken out of the order");
    }

    /// A park is a guess about state the queue cannot see, so it expires:
    /// after [`PARK_BUILDS`] builds the lane is offered again whatever the
    /// hole. Nothing here may be unreachable for good -- that is loop144's
    /// stranded lane.
    #[test]
    fn a_park_expires_so_no_lane_is_stranded() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(64);
        queue.push((5..10).map(|n| tx(1, n)).collect::<Vec<_>>());
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.usable(), 0);
        for i in 0..PARK_BUILDS {
            let mut best = queue.best_for_build(B256::from([i as u8 + 2; 32]));
            let offered: Vec<_> = std::iter::from_fn(|| best.next()).collect();
            drop(best);
            if i + 1 < PARK_BUILDS {
                assert!(offered.is_empty(), "build {i} was offered a parked lane");
            } else {
                assert_eq!(offered.len(), 5, "the park did not expire");
            }
        }
    }

    /// The hole filled by the ingest: the lane is offered again at once,
    /// from the nonce that was missing.
    #[test]
    fn a_parked_lane_comes_back_when_the_hole_is_filled() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(64);
        queue.push((5..10).map(|n| tx(1, n)).collect::<Vec<_>>());
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.usable(), 0);
        queue.push((0..5).map(|n| tx(1, n)).collect::<Vec<_>>());
        // The lane is walked again at once: nonces 0-4 and the head the
        // first build handed back. The rest (6-9) is still that build's
        // take and comes back at the next build's start.
        assert_eq!(queue.usable(), 6);
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<u64> = std::iter::from_fn(|| best.next()).map(|t| t.nonce()).collect();
        drop(best);
        assert_eq!(offered.len(), 10);
        assert_eq!(offered.first().copied(), Some(0));
    }

    /// The chain passing the hole ends the park too: another leader mined
    /// the missing nonces, and what is left in the lane is next.
    #[test]
    fn a_parked_lane_comes_back_when_the_chain_passes_the_hole() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4).with_park_lanes(64);
        queue.push((5..10).map(|n| tx(1, n)).collect::<Vec<_>>());
        build_refusing_gaps(&queue, B256::repeat_byte(1), &|_| 0);
        assert_eq!(queue.usable(), 0);
        queue.remove_mined(Address::repeat_byte(1), 4);
        // The head the first build handed back, offered again; the rest is
        // that build's take until the next build's start.
        assert_eq!(queue.usable(), 1);
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<u64> = std::iter::from_fn(|| best.next()).map(|t| t.nonce()).collect();
        drop(best);
        assert_eq!(offered, vec![5, 6, 7, 8, 9]);
    }

    /// A stale head -- the chain is past it -- is dropped rather than
    /// parked, so the lane is usable at the *next* build. This is the
    /// refusal the builder's parallel step now reports for the head it
    /// skipped; before it the head went back with `ExceedsGasLimit`, which
    /// says nothing, and was offered first to every build of the tenure.
    #[test]
    fn a_stale_head_is_dropped_so_the_next_build_finds_the_sender_usable() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(64);
        queue.push((3..8).map(|n| tx(1, n)).collect::<Vec<_>>());
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        let head = best.next().expect("the lane's head");
        assert_eq!(head.nonce(), 3);
        // A canonical block carried this sender through nonce 3, so the
        // build's verdict about it is one the queue acts on.
        queue.remove_mined_batch([(Address::repeat_byte(1), 3)]);
        // The account is at nonce 5: the head and everything below it are
        // behind the chain.
        best.mark_invalid(&head, gap(3, 5));
        drop(best);
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let offered: Vec<u64> = std::iter::from_fn(|| best.next()).map(|t| t.nonce()).collect();
        drop(best);
        // Nonce 3 and everything below it are gone and the lane starts at
        // 4: the sender is usable again at this build, where before it was
        // offered the same refused head for the rest of the tenure.
        assert_eq!(offered, vec![4, 5, 6, 7], "the stale head was offered again");
    }

    #[test]
    fn forget_mined_keeps_what_the_build_took_but_did_not_mine() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(1, 2), tx(2, 0), tx(2, 1)]);
        let parent = B256::repeat_byte(3);
        let mut best = queue.best_for_build(parent);
        // The build takes all five; the block carries (1,0), (1,1) and (2,0).
        let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        assert_eq!(taken.len(), 5);
        drop(best);
        let dropped = queue.forget_mined(parent, [(Address::repeat_byte(1), 1), (Address::repeat_byte(2), 0)]);
        assert_eq!(dropped.len(), 3);
        // The next build, on the block, is offered (1,2) and (2,1) again -- the
        // taken-but-unmined ones -- and nothing else.
        let mut best = queue.best_for_build(B256::repeat_byte(4));
        let mut again: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        again.sort();
        assert_eq!(again, vec![(1, 2), (2, 1)]);
    }

    /// A taken list that is the block's body position by position goes
    /// whole (no fold, no partition) and leaves what the serial forget
    /// leaves; one that differs anywhere takes the fold and partition.
    #[test]
    fn forget_mined_parallel_whole_body_is_the_serial_forget() {
        let run = |parallel: bool, swap: bool| {
            let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
            let mut all = Vec::new();
            for sender in 1..=30u8 {
                for nonce in 0..5u64 {
                    all.push(tx(sender, nonce));
                }
            }
            queue.push(all);
            let parent = B256::repeat_byte(5);
            let mut best = queue.best_for_build(parent);
            let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
            drop(best);
            let mut mined: Vec<(Address, u64)> = taken.iter().map(|t| (t.sender(), t.nonce())).collect();
            if swap {
                // The same set, two positions exchanged: not whole.
                mined.swap(0, 7);
            }
            let (dropped, whole) = if parallel {
                let (dropped, times) = queue.forget_mined_parallel(parent, mined.len(), |i| mined[i]);
                (dropped, times.whole)
            } else {
                (queue.forget_mined(parent, mined.iter().copied()), false)
            };
            let dropped: Vec<(u8, u64)> = dropped.iter().map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
            let mut best = queue.best_for_build(B256::repeat_byte(6));
            let again: Vec<(u8, u64)> =
                std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
            (taken.len(), dropped, again, whole)
        };
        let serial = run(false, false);
        assert_eq!(serial.1.len(), 150);
        assert!(serial.2.is_empty());
        let whole = run(true, false);
        assert!(whole.3, "the body is the taken list: handed over whole");
        assert_eq!((whole.0, &whole.1, &whole.2), (serial.0, &serial.1, &serial.2));
        let swapped = run(true, true);
        assert!(!swapped.3, "a body out of the taken list's order is partitioned");
        assert_eq!((swapped.0, &swapped.1, &swapped.2), (serial.0, &serial.1, &serial.2));
    }

    /// The hand-off on the queue's pool (`N42_BUILD_START_ASYNC=1`) forgets
    /// what the serial one does, in the same order, and leaves the same
    /// taken-but-unmined transactions for the next build.
    #[test]
    fn forget_mined_parallel_is_the_serial_forget() {
        let run = |parallel: bool| {
            let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
            let mut all = Vec::new();
            for sender in 1..=40u8 {
                for nonce in 0..6u64 {
                    all.push(tx(sender, nonce));
                }
            }
            queue.push(all);
            let parent = B256::repeat_byte(3);
            let mut best = queue.best_for_build(parent);
            let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
            drop(best);
            // The block mines up to nonce 3 of the even senders and nonce 1
            // of the odd ones, listed out of order.
            let mut mined: Vec<(Address, u64)> = Vec::new();
            for sender in (1..=40u8).rev() {
                for nonce in 0..=(if sender % 2 == 0 { 3 } else { 1 }) {
                    mined.push((Address::repeat_byte(sender), nonce));
                }
            }
            let dropped = if parallel {
                queue.forget_mined_parallel(parent, mined.len(), |i| mined[i]).0
            } else {
                queue.forget_mined(parent, mined.iter().copied())
            };
            let dropped: Vec<(u8, u64)> = dropped.iter().map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
            let mut best = queue.best_for_build(B256::repeat_byte(4));
            let mut again: Vec<(u8, u64)> =
                std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
            again.sort();
            (taken.len(), dropped, again)
        };
        let serial = run(false);
        assert_eq!(serial.1.len(), 20 * 4 + 20 * 2);
        assert_eq!(run(true), serial);
    }

    #[test]
    fn an_own_block_that_never_commits_gives_its_transactions_back() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(1, 2), tx(1, 3), tx(2, 0)]);
        let parent = B256::repeat_byte(3);
        let mut best = queue.best_for_build(parent);
        let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        assert_eq!(taken.len(), 5);
        drop(best);
        // Our block at height 10 carries all five; imported here, they leave the queue.
        let dropped = queue.forget_mined(parent, [(Address::repeat_byte(1), 3), (Address::repeat_byte(2), 0)]);
        assert_eq!(dropped.len(), 5);
        queue.hold_own_block(10, B256::repeat_byte(0xA), dropped);
        assert!(queue.is_empty());
        // Consensus commits another block at 10 that carries only (1,0) and (1,1).
        let carried = |sender: &Address, nonce: u64| *sender == Address::repeat_byte(1) && nonce <= 1;
        let back = queue.settle_own_block(10, B256::repeat_byte(0xB), carried);
        assert_eq!(back, 3, "(1,2), (1,3) and (2,0) come back");
        let mut best = queue.best_for_build(B256::repeat_byte(0xB));
        let mut again: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        again.sort();
        assert_eq!(again, vec![(1, 2), (1, 3), (2, 0)]);
        drop(best);
        // The same block committed: nothing comes back and the hold is gone.
        queue.push([tx(3, 0)]);
        let mut best = queue.best_for_build(B256::repeat_byte(0xB));
        let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        drop(best);
        let dropped = queue.remove_mined_batch_collecting([(Address::repeat_byte(3), 0), (Address::repeat_byte(1), 3), (Address::repeat_byte(2), 0)]);
        assert_eq!(dropped.len(), taken.len());
        queue.hold_own_block(11, B256::repeat_byte(0xC), dropped);
        assert_eq!(queue.settle_own_block(11, B256::repeat_byte(0xC), |_, _| false), 0);
        assert_eq!(queue.settle_own_block(12, B256::repeat_byte(0xD), |_, _| false), 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn senders_take_turns_in_nonce_order_and_a_failed_build_is_offered_again() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(2, 0), tx(1, 2), tx(3, 5)]);
        assert_eq!(queue.len(), 5);
        let parent = B256::repeat_byte(7);
        let mut best = queue.best_for_build(parent);
        let order: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(order, vec![(1, 0), (2, 0), (3, 5), (1, 1), (1, 2)]);
        assert!(queue.is_empty());
        // Same parent again: everything comes back, same order.
        let mut best = queue.best_for_build(parent);
        let again: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(again.len(), 5);
        assert_eq!(again[0], (1, 0));
        // A new parent before the chain pruned anything: the previous build
        // may have been superseded, so what it took is offered again.
        let mut best = queue.best_for_build(B256::repeat_byte(8));
        assert_eq!(best.next().map(|t| t.nonce()), Some(0));
        drop(best);
        // The chain mined the lot: pruned from the lanes and from the build's
        // taken list alike, so a build on yet another parent gets nothing.
        queue.remove_mined_batch([
            (Address::repeat_byte(1), 2),
            (Address::repeat_byte(2), 0),
            (Address::repeat_byte(3), 5),
        ]);
        let mut best = queue.best_for_build(B256::repeat_byte(9));
        assert!(best.next().is_none());
    }

    /// The fleet's sequence (round 44): two builds in flight on one parent.
    /// The second build's start gives the first's take back to the lanes, the
    /// first seals its block from that take anyway, and the chain commits and
    /// prunes it -- after which the second build's leftovers come back. A
    /// mined transaction that lands in the lanes here is never removed again:
    /// the canonical pruner does not revisit that block.
    #[test]
    fn a_take_the_chain_mined_is_not_offered_again_on_the_same_parent() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(2, 0)]);
        let parent = B256::repeat_byte(3);
        let mut first = queue.best_for_build(parent);
        let took: Vec<_> = std::iter::from_fn(|| first.next()).collect();
        assert_eq!(took.len(), 3);
        // The second build on the same parent: the first's take goes back.
        let mut second = queue.best_for_build(parent);
        let retook: Vec<_> = std::iter::from_fn(|| second.next()).collect();
        assert_eq!(retook.len(), 3, "the take was offered again: nothing was mined yet");
        // The first build's block is committed and pruned as mined.
        queue.remove_mined_batch([(Address::repeat_byte(1), 1), (Address::repeat_byte(2), 0)]);
        // The second build ends and hands back what it did not build, as the
        // builder's leftovers do -- after the prune.
        for transaction in &retook {
            second.mark_invalid(transaction, InvalidPoolTransactionError::ExceedsGasLimit(21_000, 30_000_000));
        }
        drop(second);
        assert!(queue.is_empty(), "mined transactions were offered again");
        // And a build on the same parent again offers none of them.
        let mut third = queue.best_for_build(parent);
        assert!(third.next().is_none());
    }

    /// The give-back the same-parent arm is there for: nothing was committed,
    /// so the whole take is offered again.
    #[test]
    fn a_take_the_chain_did_not_mine_is_offered_again_on_the_same_parent() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(2, 0)]);
        let parent = B256::repeat_byte(3);
        let mut first = queue.best_for_build(parent);
        let took: Vec<(u8, u64)> = std::iter::from_fn(|| first.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(took.len(), 3);
        drop(first);
        let mut second = queue.best_for_build(parent);
        let again: Vec<(u8, u64)> = std::iter::from_fn(|| second.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(again, took);
    }

    /// The superseded-parent arm with a take the chain mined part of: only
    /// the unmined part comes back.
    #[test]
    fn a_superseded_build_offers_back_only_what_the_chain_did_not_mine() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(1, 2), tx(2, 0)]);
        let parent = B256::repeat_byte(1);
        let mut build = queue.best_for_build(parent);
        let took: Vec<_> = std::iter::from_fn(|| build.next()).collect();
        assert_eq!(took.len(), 4);
        // A canonical block carried (1,1); the account is at nonce 2, and
        // the build refuses (1,1) as stale, which makes (1,0) -- still in
        // the take -- stale as well.
        queue.remove_mined_batch([(Address::repeat_byte(1), 1)]);
        let stale = took
            .iter()
            .find(|t| t.sender() == Address::repeat_byte(1) && t.nonce() == 1)
            .expect("taken");
        build.mark_invalid(
            stale,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx: 1, state: 2 }),
        );
        drop(build);
        // Superseded by a block on another parent: the take goes back, minus
        // what the chain has passed.
        let mut next = queue.best_for_build(B256::repeat_byte(2));
        let mut again: Vec<(u8, u64)> = std::iter::from_fn(|| next.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        again.sort_unstable();
        assert_eq!(again, vec![(1, 2), (2, 0)]);
    }

    /// A stale refusal takes the transaction out of the queue for good: no
    /// give-back and no later arrival brings it back, and the sender's higher
    /// nonces are still offered in the same build.
    #[test]
    fn a_stale_refusal_is_not_offered_again() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(1, 2)]);
        let parent = B256::repeat_byte(5);
        let mut build = queue.best_for_build(parent);
        let first = build.next().expect("one queued");
        assert_eq!(first.nonce(), 0);
        // The chain mines it while the build holds it, which is how a build
        // comes to be holding something the chain is past at all.
        queue.remove_mined_batch([(Address::repeat_byte(1), 0)]);
        build.mark_invalid(
            &first,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx: 0, state: 1 }),
        );
        assert_eq!(build.next().map(|t| t.nonce()), Some(1), "the sender's higher nonces are still offered");
        drop(build);
        // The ingest offers it again: the lane refuses it.
        queue.push([tx(1, 0)]);
        let mut next = queue.best_for_build(parent);
        let again: Vec<u64> = std::iter::from_fn(|| next.next()).map(|t| t.nonce()).collect();
        assert_eq!(again, vec![1, 2]);
    }

    /// loop214 Pd node2: a build standing on a block of its own that
    /// consensus replaced refuses a sender's whole run as behind the chain,
    /// and every refusal used to take one more nonce out of the queue for
    /// good -- the sender's account left at 0 with its lane starting at 64,
    /// and every later nonce of that sender stuck behind the hole for the
    /// rest of the leg.
    ///
    /// No canonical block ever carried any of it, so nothing the build says
    /// about it is something the queue may act on.
    #[test]
    fn a_verdict_no_block_confirms_does_not_take_the_lane_with_it() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(64);
        queue.push((0..64).map(|n| tx(1, n)).collect::<Vec<_>>());

        // A build takes the run and its block is superseded; the next build
        // is offered it again.
        let mut first = queue.best_for_build(B256::repeat_byte(1));
        let took: Vec<_> = std::iter::from_fn(|| first.next()).collect();
        assert_eq!(took.len(), 64);
        drop(first);

        // That next build stands on the superseded block, whose state has
        // the sender at 64, and refuses the head as behind the chain. The
        // sender is then skipped for the rest of this build -- one refusal,
        // not one per nonce, which is the walk-up the old path paid.
        let mut build = queue.best_for_build(B256::repeat_byte(2));
        let head = build.next().expect("the lane's head");
        assert_eq!(head.nonce(), 0);
        build.mark_invalid(
            &head,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent { tx: 0, state: 64 }),
        );
        assert!(build.next().is_none(), "the sender was offered again inside the same build");
        drop(build);

        // The chain mined none of it, so the queue still holds all of it and
        // the next build is offered the sender from nonce 0.
        let mut after = queue.best_for_build(B256::repeat_byte(3));
        let offered: Vec<u64> = std::iter::from_fn(|| after.next()).map(|t| t.nonce()).collect();
        drop(after);
        assert_eq!(offered.first().copied(), Some(0), "the lane's head was taken by an unconfirmed verdict");
        assert_eq!(offered.len(), 64, "the run was lost: {} left", offered.len());

        let report = queue.take_drops();
        let named: alloy_primitives::map::HashMap<&str, u64> = report.named().into_iter().collect();
        assert_eq!(named.get("stale_unconfirmed"), Some(&1), "{named:?}");
        assert_eq!(named.get("stale_refusal"), None, "no block confirmed any of it");
    }

    #[test]
    fn a_reorg_gives_back_what_the_watermark_would_have_filtered() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1)]);
        let parent = B256::repeat_byte(6);
        let mut build = queue.best_for_build(parent);
        assert_eq!(std::iter::from_fn(|| build.next()).count(), 2);
        drop(build);
        queue.remove_mined_batch([(Address::repeat_byte(1), 1)]);
        queue.push_reverted(vec![tx(1, 0), tx(1, 1)]);
        let mut next = queue.best_for_build(B256::repeat_byte(7));
        let again: Vec<u64> = std::iter::from_fn(|| next.next()).map(|t| t.nonce()).collect();
        assert_eq!(again, vec![0, 1]);
    }

    #[test]
    fn mined_nonces_and_refused_transactions_are_handled() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(1, 2), tx(2, 4)]);
        queue.remove_mined(Address::repeat_byte(1), 1);
        assert_eq!(queue.len(), 2);
        let mut best = queue.best_for_build(B256::ZERO);
        let first = best.next().unwrap();
        assert_eq!((first.sender(), first.nonce()), (Address::repeat_byte(1), 2));
        let second = best.next().unwrap();
        assert_eq!(second.nonce(), 4);
        // Refused for a gap: back in the queue, sender skipped for this build.
        best.mark_invalid(&second, InvalidPoolTransactionError::Underpriced);
        assert!(best.next().is_none());
        assert_eq!(queue.len(), 1);
        drop(best);
        // The chain mined sender 1's nonce 2 (taken by the build above): a
        // build on the next block gets only the refused one back.
        queue.remove_mined_batch([(Address::repeat_byte(1), 2)]);
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        assert_eq!(best.next().unwrap().nonce(), 4);
        assert!(best.next().is_none());
    }

    /// A build that stops in the middle of a sender's run (the block filled)
    /// must not lose that sender: the next build offers its lane first, and
    /// what arrives for it meanwhile is offered too.
    #[test]
    fn a_sender_whose_run_a_full_block_cut_short_is_offered_by_the_next_build() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::with_run_length(4);
        queue.push((0..8).map(|n| tx(1, n)).chain((0..2).map(|n| tx(2, n))));
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        // Two of sender 1's run of four, then the block is full.
        assert_eq!(best.next().map(|t| (t.sender().as_slice()[0], t.nonce())), Some((1, 0)));
        assert_eq!(best.next().map(|t| (t.sender().as_slice()[0], t.nonce())), Some((1, 1)));
        drop(best);
        // The chain mined them; a later arrival for the same sender.
        queue.remove_mined_batch([(Address::repeat_byte(1), 1)]);
        queue.push([tx(1, 8)]);
        assert_eq!(queue.len(), 9);
        // The next build: sender 1 first, and everything queued is offered.
        let mut best = queue.best_for_build(B256::repeat_byte(2));
        let order: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(order[0], (1, 2));
        assert_eq!(order.len(), 9, "{order:?}");
        assert!(queue.is_empty());
    }

    /// A frame of `members`, pushed and noted the way the ingest does it.
    fn push_frame(queue: &TxQueue<EthPooledTransaction>, id: u8, members: &[(Address, u64)]) -> Vec<B256> {
        let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
        let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
        queue.push(txs);
        queue.note_frame(NewFrame {
            id: B256::repeat_byte(id),
            hashes: hashes.clone(),
            members: members.to_vec(),
            gas: 21_000 * members.len() as u64,
        });
        hashes
    }

    #[test]
    fn frames_are_indexed_in_arrival_order_and_leave_when_mined() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let (a, b, c) = (Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3));
        push_frame(&queue, 0xa1, &[(a, 0), (a, 1), (a, 2), (b, 0), (b, 1)]);
        push_frame(&queue, 0xa2, &[(c, 0), (c, 1), (a, 3)]);
        assert_eq!(queue.frames_indexed(), 2);
        let frames: Vec<FrameRef> = queue.frames_in_arrival_order().collect();
        assert_eq!(frames.iter().map(|f| f.id).collect::<Vec<_>>(), vec![B256::repeat_byte(0xa1), B256::repeat_byte(0xa2)]);
        assert_eq!((frames[0].count, frames[0].gas), (5, 5 * 21_000));
        assert!(frames.iter().all(|f| f.whole_usable));

        // An own block (not committed) carries sender a's first two nonces:
        // both frames are still indexed; the first is no longer whole-usable
        // (two of its transactions left the lanes), the second still is --
        // a's lane now runs 2, 3 from its head.
        let taken = queue.remove_mined_batch_collecting([(a, 1)]);
        assert_eq!(taken.len(), 2);
        let frames: Vec<FrameRef> = queue.frames_in_arrival_order().collect();
        assert_eq!(frames.len(), 2);
        assert!(!frames[0].whole_usable);
        assert!(frames[1].whole_usable);

        // The canonical prune mines them: the first frame leaves the index,
        // the second is whole again (a's lane runs 2, 3 from its head).
        queue.remove_mined_batch([(a, 1)]);
        let frames: Vec<FrameRef> = queue.frames_in_arrival_order().collect();
        assert_eq!(frames.iter().map(|f| f.id).collect::<Vec<_>>(), vec![B256::repeat_byte(0xa2)]);
        assert!(frames[0].whole_usable);
        assert_eq!(queue.frames_indexed(), 1);
    }

    /// A frame build takes whole frames in arrival order, skips one that is
    /// not whole-usable and one whose run is not at its lane head once the
    /// earlier frames are taken, cuts the last to the gas left, and gives
    /// back what it did not hand out when dropped.
    #[test]
    fn a_frame_build_takes_whole_frames_and_cuts_the_last_to_the_gas() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let (a, b, c, d) = (Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3), Address::repeat_byte(4));
        let first = push_frame(&queue, 0xd1, &[(a, 0), (a, 1), (b, 0)]);
        // Behind a hole: c's lane holds 0 and 2..=3.
        queue.push([tx_hashed(c, 0)]);
        push_frame(&queue, 0xd2, &[(c, 2), (c, 3)]);
        let third = push_frame(&queue, 0xd3, &[(b, 1), (d, 0)]);
        let fourth = push_frame(&queue, 0xd4, &[(d, 1), (d, 2), (d, 3), (a, 2)]);
        // Room for 3 + 2 + 2 transactions of 21,000.
        let (best, plan) = queue.frames_for_build(B256::repeat_byte(9), 7 * 21_000);
        assert_eq!(plan.skipped, 1);
        assert_eq!(
            plan.frames.iter().map(|f| (f.id, f.len, f.taken)).collect::<Vec<_>>(),
            vec![(B256::repeat_byte(0xd1), 3, 3), (B256::repeat_byte(0xd3), 2, 2), (B256::repeat_byte(0xd4), 4, 2)]
        );
        let want: Vec<B256> = first.iter().chain(&third).chain(&fourth[..2]).copied().collect();
        assert_eq!(plan.hashes(), want);
        assert_eq!(plan.layout_for(&want[..4]), Some(vec![(B256::repeat_byte(0xd1), 3), (B256::repeat_byte(0xd3), 1)]));
        assert_eq!(plan.layout_for(&[want[1]]), None, "not a prefix: not frame-aligned");
        let mut best = best;
        let handed: Vec<B256> = best.by_ref().take(5).map(|t| *t.hash()).collect();
        assert_eq!(handed, want[..5]);
        // c's 3, 2 of d's and a's last one remain; the two the iterator
        // still buffers go back on drop.
        assert_eq!(queue.len(), 5);
        drop(best);
        assert_eq!(queue.len(), 7);
        // The index finds the layout of a body made of its frames.
        assert_eq!(queue.frame_layout_of(&want), Some(vec![(B256::repeat_byte(0xd1), 3), (B256::repeat_byte(0xd3), 2), (B256::repeat_byte(0xd4), 2)]));
        assert_eq!(queue.frame_layout_of(&want[1..]), None);
        // What a whole-body check reads instead of rehashing: the ids of the
        // frames held whole at exactly those positions; the cut last frame,
        // a frame with other hashes and a layout past the body are not.
        let layout = [(B256::repeat_byte(0xd1), 3), (B256::repeat_byte(0xd3), 2), (B256::repeat_byte(0xd4), 2)];
        assert_eq!(
            queue.frames_held(&layout, &want),
            vec![Some(B256::repeat_byte(0xd1)), Some(B256::repeat_byte(0xd3)), None]
        );
        let mut swapped = want.clone();
        swapped.swap(3, 4);
        assert_eq!(queue.frames_held(&layout, &swapped)[1], None);
        assert_eq!(queue.frames_held(&layout, &want[..4]), vec![Some(B256::repeat_byte(0xd1)), None, None]);
    }

    #[test]
    fn a_frame_behind_a_gap_or_a_park_is_not_whole_usable() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let a = Address::repeat_byte(1);
        // The lane holds 0 and 2..=3: the frame's 2..=3 are behind a hole.
        queue.push([tx_hashed(a, 0)]);
        push_frame(&queue, 0xb1, &[(a, 2), (a, 3)]);
        let frames: Vec<FrameRef> = queue.frames_in_arrival_order().collect();
        assert!(!frames[0].whole_usable);
        // The hole filled: whole again.
        queue.push([tx_hashed(a, 1)]);
        assert!(queue.frames_in_arrival_order().all(|f| f.whole_usable));
    }

    /// A frame of `members` through [`TxQueue::push_frame`], the ingest's
    /// direct door: the index keeps the transactions. `order` is the order
    /// they are pushed in (a recovery that reordered them), by position in
    /// `members`.
    fn push_frame_with_txs(
        queue: &TxQueue<EthPooledTransaction>,
        id: u8,
        members: &[(Address, u64)],
        order: Option<&[usize]>,
    ) -> Vec<B256> {
        let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
        let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
        let pushed: Vec<EthPooledTransaction> = match order {
            Some(order) => order.iter().map(|&k| txs[k].clone()).collect(),
            None => txs,
        };
        queue.push_frame(
            pushed,
            Some(NewFrame {
                id: B256::repeat_byte(id),
                hashes: hashes.clone(),
                members: members.to_vec(),
                gas: 21_000 * members.len() as u64,
            }),
        );
        hashes
    }

    #[test]
    fn take_frames_hands_out_the_frames_own_arcs_without_the_lanes() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let first = push_frame_with_txs(&queue, 0xe1, &[(b, 0), (a, 0), (b, 1), (a, 1)], None);
        // Recovered out of order: matched back to the frame's by hash.
        let second = push_frame_with_txs(&queue, 0xe2, &[(a, 2), (b, 2)], Some(&[1, 0]));
        assert_eq!(queue.frames_with_txs(), 2);
        let got = queue.take_frames(&[B256::repeat_byte(0xe1), B256::repeat_byte(0xe2), B256::repeat_byte(0xee)]);
        let hashes = |txs: &FrameTxs<EthPooledTransaction>| txs.iter().map(|t| *t.hash()).collect::<Vec<_>>();
        assert_eq!(got[0].as_ref().map(hashes), Some(first));
        assert_eq!(got[1].as_ref().map(hashes), Some(second));
        assert!(got[2].is_none());
        // The lane's own allocation, and the index's list itself: a second
        // take clones the frame's `Arc`, not its transactions.
        let again = queue.take_frames(&[B256::repeat_byte(0xe1)]);
        let (got0, again0) = (got[0].as_ref().unwrap(), again[0].as_ref().unwrap());
        assert!(Arc::ptr_eq(got0, again0));
        // A build takes every transaction out of the lanes (no by-hash
        // index): the lane look-up would find none of them, the frame still
        // hands out the same `Arc`s.
        let mut best = queue.best_for_build(B256::repeat_byte(7));
        let taken: Vec<_> = std::iter::from_fn(|| best.next()).collect();
        drop(best);
        assert_eq!(taken.len(), 6);
        assert!(queue.is_empty());
        let after = queue.take_frames(&[B256::repeat_byte(0xe1)]);
        let after0 = after[0].as_ref().expect("the frame's own transactions");
        for tx in after0.iter() {
            assert!(taken.iter().any(|t| Arc::ptr_eq(t, tx)), "the queue's own allocation");
        }
        // Without them (the lane look-up), the same frame is not found.
        let plain: TxQueue<EthPooledTransaction> = TxQueue::new();
        push_frame(&plain, 0xe1, &[(b, 0), (a, 0)]);
        let mut best = plain.best_for_build(B256::repeat_byte(7));
        while best.next().is_some() {}
        drop(best);
        assert!(plain.take_frames(&[B256::repeat_byte(0xe1)])[0].is_none());
    }

    #[test]
    fn a_pruned_frame_lets_go_of_its_transactions() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        push_frame_with_txs(&queue, 0xf1, &[(a, 0), (a, 1)], None);
        push_frame_with_txs(&queue, 0xf2, &[(b, 0)], None);
        let got = queue.take_frames(&[B256::repeat_byte(0xf1)]);
        let weak: Vec<std::sync::Weak<ValidPoolTransaction<EthPooledTransaction>>> =
            got[0].as_ref().unwrap().iter().map(Arc::downgrade).collect();
        drop(got);
        // The chain mines a's nonce 0: the frame leaves the index, and with
        // the lanes' copies gone too nothing holds its transactions.
        queue.remove_mined_batch([(a, 1)]);
        assert!(queue.take_frames(&[B256::repeat_byte(0xf1)])[0].is_none());
        assert_eq!(queue.frames_indexed(), 1);
        assert_eq!(queue.frames_with_txs(), 1);
        // Freed on the queue's freeing thread, after the prune returns.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while weak.iter().any(|w| w.upgrade().is_some()) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(weak.iter().all(|w| w.upgrade().is_none()), "the index still held a pruned frame's transactions");
        assert!(queue.take_frames(&[B256::repeat_byte(0xf2)])[0].is_some());
    }

    #[test]
    fn take_frames_hands_back_the_queues_own_transactions_in_frame_order() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        // Frame order is not lane order: b's before a's, interleaved.
        let first = push_frame(&queue, 0xc1, &[(b, 0), (a, 0), (b, 1), (a, 1)]);
        let second = push_frame(&queue, 0xc2, &[(a, 2), (b, 2)]);
        let got = queue.take_frames(&[B256::repeat_byte(0xc2), B256::repeat_byte(0xee), B256::repeat_byte(0xc1)]);
        assert_eq!(got.len(), 3);
        let hashes = |txs: &FrameTxs<EthPooledTransaction>| txs.iter().map(|t| *t.hash()).collect::<Vec<_>>();
        assert_eq!(got[0].as_ref().map(hashes), Some(second));
        assert!(got[1].is_none(), "an unknown frame");
        assert_eq!(got[2].as_ref().map(hashes), Some(first));
        // A read: nothing left the lanes.
        assert_eq!(queue.len(), 6);
        // By reference: the same allocation the lane holds.
        let again = queue.take_frames(&[B256::repeat_byte(0xc1)]);
        assert!(Arc::ptr_eq(&got[2].as_ref().unwrap()[0], &again[0].as_ref().unwrap()[0]));
    }

    /// A scenario of frames and loose transactions from `seed`: frames
    /// with their transactions (senders interleaved, so a sender has more
    /// than one run in a frame), frames noted without them (the pool door),
    /// loose transactions at lane heads, gaps, and a transaction that came
    /// in loose before its frame (the lane holds another allocation).
    fn frame_scenario(seed: u64) -> TxQueue<EthPooledTransaction> {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let senders: Vec<Address> = (1..=10u8).map(Address::repeat_byte).collect();
        let mut nonces = [0u64; 10];
        let mut frame_id = 0u32;
        for _ in 0..40 {
            match next(10) {
                0 => {
                    let s = next(10) as usize;
                    queue.push([tx_hashed(senders[s], nonces[s])]);
                    nonces[s] += 1;
                }
                1 => {
                    // A gap: this nonce never arrives.
                    nonces[next(10) as usize] += 1;
                }
                kind => {
                    let len = 1 + next(6) as usize;
                    let mut members = Vec::with_capacity(len);
                    for _ in 0..len {
                        let s = next(4 + (kind as u64 % 6)) as usize;
                        members.push((senders[s], nonces[s]));
                        nonces[s] += 1;
                    }
                    let txs: Vec<EthPooledTransaction> = members.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
                    if next(12) == 0 {
                        // One of them came in loose first.
                        queue.push([txs[0].clone()]);
                    }
                    let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
                    frame_id += 1;
                    let mut id = [0u8; 32];
                    id[..4].copy_from_slice(&frame_id.to_be_bytes());
                    let frame = NewFrame { id: B256::from(id), hashes, members, gas: 21_000 * len as u64 };
                    if kind == 2 {
                        queue.push(txs);
                        queue.note_frame(frame);
                    } else {
                        queue.push_frame(txs, Some(frame));
                    }
                }
            }
        }
        queue
    }

    /// Everything a frame build decides, for comparing the modes: the plan,
    /// what it hands out (hashes, and whether each is the frame index's own
    /// allocation), the queue's depth, the build's taken list, and the same
    /// again for a second build on another parent after the first gives
    /// half of its frames back unused.
    fn frame_outcome(
        queue: &TxQueue<EthPooledTransaction>,
        gas: u64,
        mode: SelectMode,
        seen: &mut FrameSelectTimes,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for (round, parent) in [B256::repeat_byte(0x71), B256::repeat_byte(0x72)].into_iter().enumerate() {
            let (mut best, plan, times) = queue.frames_for_build_in(parent, gas, mode);
            seen.by_ref += times.by_ref;
            seen.slow += times.slow;
            seen.counted += times.counted;
            seen.lock_us += plan.skipped as u64;
            seen.begin_us += u64::from(plan.frames.last().is_some_and(|f| f.taken < f.len));
            let ids: Vec<B256> = plan.frames.iter().map(|f| f.id).collect();
            let own = queue.take_frames(&ids);
            let mut handed = Vec::new();
            let mut by_ref = Vec::new();
            let keep = if round == 0 { plan.tx_count() / 2 } else { plan.tx_count() };
            for tx in best.by_ref().take(keep) {
                handed.push(*tx.hash());
                by_ref.push(own.iter().flatten().any(|txs| txs.iter().any(|t| Arc::ptr_eq(t, &tx))));
            }
            drop(best);
            let taken: Vec<B256> = queue
                .lock_inner()
                .last_build
                .as_ref()
                .map(|(_, list)| list.iter().map(|t| *t.hash()).collect())
                .unwrap_or_default();
            out.push(format!("{round} plan {:?} {:?} {}", plan.frames, plan.hashes(), plan.skipped));
            out.push(format!("{round} handed {handed:?}"));
            out.push(format!("{round} len {} taken {taken:?}", queue.len()));
            // Pointer identity: a transaction handed out is the frame
            // index's own allocation in every mode, when its frame holds one.
            out.push(format!("{round} own {by_ref:?}"));
        }
        out
    }

    /// The parallel selection, the serial one by reference and the
    /// per-transaction one decide the same plan, hand out the same
    /// transactions, and leave the queue the same, over many scenarios and
    /// gas limits (whole frames, cut frames, skipped frames, the pool door).
    #[test]
    fn frame_selection_modes_agree() {
        let mut seen = FrameSelectTimes::default();
        let mut unused = FrameSelectTimes::default();
        for seed in 1..=120u64 {
            for gas_txs in [1u64, 3, 7, 12, 25, 60, 400] {
                let gas = gas_txs * 21_000;
                let reference = frame_outcome(&frame_scenario(seed), gas, SelectMode::PerTx, &mut unused);
                let serial = frame_outcome(&frame_scenario(seed), gas, SelectMode::Serial, &mut unused);
                assert_eq!(serial, reference, "seed {seed}, gas {gas_txs} txs, serial");
                let parallel = frame_outcome(&frame_scenario(seed), gas, SelectMode::Parallel, &mut seen);
                assert_eq!(parallel, reference, "seed {seed}, gas {gas_txs} txs, parallel");
            }
        }
        // The scenarios reach every branch: frames by reference, by the
        // counters, by the per-transaction check, passed over, and cut.
        eprintln!("parallel: {seen:?} (lock_us = skipped, begin_us = cut)");
        assert!(seen.by_ref > 0 && seen.counted > 0 && seen.slow > 0 && seen.lock_us > 0 && seen.begin_us > 0);
    }

    /// A frame noted with its transactions is selected by reference: the
    /// build is handed the frame index's own allocations (pointer-equal
    /// `Arc`s), the plan decides it without the per-transaction check, and
    /// the frame's totals on the entry are its transactions'.
    #[test]
    fn frame_selection_hands_out_the_frames_own_arcs() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let (a, b, c) = (Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3));
        push_frame_with_txs(&queue, 0xf1, &[(a, 0), (b, 0), (a, 1), (c, 0)], None);
        push_frame_with_txs(&queue, 0xf2, &[(b, 1), (a, 2)], Some(&[1, 0]));
        push_frame_with_txs(&queue, 0xf3, &[(c, 1), (c, 2), (a, 3)], None);
        {
            let mut inner = queue.lock_inner();
            queue.drain_inbox(&mut inner);
            assert_eq!(inner.frames.txs_gas_of(&B256::repeat_byte(0xf1)), Some(4 * 21_000));
            assert_eq!(inner.frames.txs_gas_of(&B256::repeat_byte(0xf3)), Some(3 * 21_000));
        }
        for mode in [SelectMode::Parallel, SelectMode::Serial] {
            let parent = if mode == SelectMode::Parallel { B256::repeat_byte(0x81) } else { B256::repeat_byte(0x82) };
            let (best, plan, times) = queue.frames_for_build_in(parent, 9 * 21_000, mode);
            assert_eq!(times.slow, 0, "{mode:?}: no frame needed the per-transaction check");
            assert_eq!(times.by_ref, 3);
            assert_eq!(plan.frames.iter().map(|f| f.taken).collect::<Vec<_>>(), vec![4, 2, 3]);
            let ids: Vec<B256> = plan.frames.iter().map(|f| f.id).collect();
            let own: Vec<Arc<ValidPoolTransaction<EthPooledTransaction>>> =
                queue.take_frames(&ids).into_iter().flatten().flat_map(|txs| txs.iter().cloned().collect::<Vec<_>>()).collect();
            let handed: Vec<_> = best.collect();
            assert_eq!(handed.len(), 9);
            assert!(handed.iter().zip(&own).all(|(h, o)| Arc::ptr_eq(h, o)), "{mode:?}: the frames' own allocations");
            // The lanes gave them up: the taken list holds the same ones.
            let inner = queue.lock_inner();
            let taken = &inner.last_build.as_ref().expect("a build").1;
            assert_eq!(taken.len(), 9);
            assert!(taken.iter().zip(&own).all(|(t, o)| Arc::ptr_eq(t, o)));
            assert_eq!(inner.len, 0);
        }
    }

    /// The chained build's hand-off (`forget_mined_parallel`) for a full
    /// block the build took exactly (163,000 transactions, 2,547 senders of
    /// 64), caches cold: the taken list compared whole against the body
    /// (`ForgetTimes::whole`) against the fold and partition (the same body
    /// offered in another order). `cargo test -p n42-tx-queue --release --lib
    /// -- --ignored bench_forget_whole --nocapture`.
    #[test]
    #[ignore]
    fn bench_forget_whole() {
        for round in 0..4u8 {
            let whole = round % 2 == 1;
            let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
            let mut all = Vec::with_capacity(163_000);
            for s in 0..2_547u64 {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(s.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1).to_be_bytes());
                for n in 0..64u64 {
                    all.push(tx_hashed(Address::from(a), n));
                }
            }
            queue.push(all);
            let parent = B256::repeat_byte(0x50 + round);
            let mut best = queue.best_for_build(parent);
            let mut body: Vec<(Address, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender(), t.nonce())).collect();
            drop(best);
            if !whole {
                body.reverse();
            }
            let mut junk = vec![0u8; 1 << 30];
            for i in (0..junk.len()).step_by(4096) {
                junk[i] = round;
            }
            std::hint::black_box(&junk);
            drop(junk);
            let at = std::time::Instant::now();
            let (mined, times) = queue.forget_mined_parallel(parent, body.len(), |i| body[i]);
            let took = at.elapsed();
            assert_eq!(mined.len(), body.len());
            assert_eq!(times.whole, whole);
            eprintln!("round {round}: whole {whole}: forget of {} in {took:?} {times:?}", mined.len());
        }
    }

    /// The leader's frame selection at the bench's shape: 480k queued in
    /// frames of 500 (one transaction per sender per frame, as the flood's
    /// ingest makes them), a 163k-transaction block of 326 frames, caches
    /// A queue of `rounds` nonces for each of `senders` senders, pushed as
    /// frames of 500 the way the ingest does.
    fn framed_queue(senders: u64, rounds: u64) -> (TxQueue<EthPooledTransaction>, Vec<(Address, u64)>) {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let mut all: Vec<(Address, u64)> = Vec::with_capacity((senders * rounds) as usize);
        for n in 0..rounds {
            for s in 0..senders {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(s.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1).to_be_bytes());
                all.push((Address::from(a), n));
            }
        }
        for (k, chunk) in all.chunks(500).enumerate() {
            let txs: Vec<EthPooledTransaction> = chunk.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
            let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(k as u64 + 1).to_be_bytes());
            queue.push_frame(
                txs,
                Some(NewFrame { id: B256::from(id), hashes, members: chunk.to_vec(), gas: 21_000 * chunk.len() as u64 }),
            );
        }
        (queue, all)
    }

    /// Everything the queue would offer a build on a fresh parent, in order.
    fn offered(queue: &TxQueue<EthPooledTransaction>, parent: u8) -> Vec<(Address, u64)> {
        queue.best_for_build(B256::repeat_byte(parent)).map(|t| (t.sender(), t.nonce())).collect()
    }

    /// Every sender's nonces offered from 0 upwards with no gap and no
    /// repeat, and exactly the queue's contents.
    fn assert_lanes_whole(got: &[(Address, u64)], expected: &[(Address, u64)]) {
        let mut next: std::collections::HashMap<Address, u64> = std::collections::HashMap::new();
        for (sender, nonce) in got {
            let at = next.entry(*sender).or_insert(0);
            assert_eq!(*nonce, *at, "sender {sender} offered out of order");
            *at += 1;
        }
        let mut a = got.to_vec();
        let mut b = expected.to_vec();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a.len(), b.len(), "lost or duplicated");
        assert!(a == b, "different contents");
    }

    /// loop323 Ab: the chained build refused at the tenure handover gives a
    /// whole block's selection back, and the per-transaction untake held the
    /// queue's lock 4,866 ms doing it.
    #[test]
    fn a_refused_block_selection_goes_back_whole_and_fast() {
        let (queue, all) = framed_queue(136_000, 3);
        let before = queue.len();
        assert_eq!(before, all.len());
        let (best, plan) = queue.frames_for_build(B256::repeat_byte(0x51), 163_000 * 21_000);
        assert_eq!(plan.frames.len(), 326);
        // The take applied to the lanes, as the next lock does.
        drop(queue.lock_inner());
        assert_eq!(queue.len(), before - 163_000);
        let at = std::time::Instant::now();
        drop(best);
        let untake = at.elapsed();
        eprintln!("untake of 163,000 from a queue of {before}: {untake:?}");
        assert!(untake < std::time::Duration::from_millis(1_500), "untake took {untake:?}");
        assert_eq!(queue.len(), before);
        assert_lanes_whole(&offered(&queue, 0x52), &all);
    }

    /// The give-back's index is built before the lock is taken: a prune of
    /// other senders and a push of new frames, racing it, leave the queue
    /// exactly as running them one after the other would.
    #[test]
    fn an_untake_racing_a_prune_and_a_push_loses_nothing() {
        let (queue, all) = framed_queue(20_000, 3);
        let (best, _) = queue.frames_for_build(B256::repeat_byte(0x61), 30_000 * 21_000);
        drop(queue.lock_inner());
        // Mined elsewhere: the first 1,000 senders' nonce 0.
        let mined: Vec<(Address, u64)> = all.iter().take(1_000).copied().collect();
        // New arrivals: nonce 3 of the last 1,000 senders.
        let fresh: Vec<(Address, u64)> = all.iter().take(20_000).skip(19_000).map(|(s, _)| (*s, 3)).collect();
        let racer = {
            let queue = queue.clone();
            let mined = mined.clone();
            let fresh = fresh.clone();
            std::thread::spawn(move || {
                queue.remove_mined_batch(mined);
                queue.push(fresh.iter().map(|(s, n)| tx_hashed(*s, *n)).collect::<Vec<_>>());
            })
        };
        drop(best);
        racer.join().expect("racer");
        let mut expected: Vec<(Address, u64)> = all.iter().skip(1_000).copied().collect();
        expected.extend(fresh);
        let got = offered(&queue, 0x62);
        // The mined senders start at nonce 1 now.
        let mut next: std::collections::HashMap<Address, u64> = mined.iter().map(|(s, _)| (*s, 1)).collect();
        for (sender, nonce) in &got {
            let at = next.entry(*sender).or_insert(0);
            assert_eq!(*nonce, *at, "sender {sender} offered out of order");
            *at += 1;
        }
        let (mut a, mut b) = (got, expected);
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a.len(), b.len(), "lost or duplicated");
        assert!(a == b, "different contents");
    }

    /// cold. `cargo test -p n42-tx-queue --release --lib -- --ignored bench_frame_selection --nocapture`.
    #[test]
    #[ignore]
    fn bench_frame_selection() {
        let senders = 160_000u64;
        let rounds = 3u64;
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let mut all: Vec<(Address, u64)> = Vec::with_capacity((senders * rounds) as usize);
        for n in 0..rounds {
            for s in 0..senders {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(s.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1).to_be_bytes());
                all.push((Address::from(a), n));
            }
        }
        for (k, chunk) in all.chunks(500).enumerate() {
            let txs: Vec<EthPooledTransaction> = chunk.iter().map(|(s, n)| tx_hashed(*s, *n)).collect();
            let hashes: Vec<B256> = txs.iter().map(|t| *t.hash()).collect();
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(k as u64 + 1).to_be_bytes());
            queue.push_frame(
                txs,
                Some(NewFrame { id: B256::from(id), hashes, members: chunk.to_vec(), gas: 21_000 * chunk.len() as u64 }),
            );
        }
        assert_eq!(queue.frames_indexed(), all.len() / 500);
        for round in 0..3u8 {
            // The previous round's take given back, outside the timing.
            drop(queue.best_for_build(B256::repeat_byte(0x30 + round)));
            // Evict the caches: 1 GB written.
            let mut junk = vec![0u8; 1 << 30];
            for i in (0..junk.len()).step_by(4096) {
                junk[i] = round;
            }
            std::hint::black_box(&junk);
            drop(junk);
            let at = std::time::Instant::now();
            let (mut best, plan, times) = queue.frames_for_build_timed(B256::repeat_byte(0x40 + round), 163_000 * 21_000);
            let selected = at.elapsed();
            let at = std::time::Instant::now();
            drop(queue.lock_inner());
            let settled = at.elapsed();
            let at = std::time::Instant::now();
            let mut n = 0usize;
            for t in best.by_ref() {
                std::hint::black_box(&t);
                n += 1;
            }
            let pulled = at.elapsed();
            assert_eq!(plan.frames.len(), 326);
            assert_eq!(n, 163_000);
            eprintln!("round {round}: select {selected:?} {times:?}, lock after (the settle) {settled:?}, pull {n} {pulled:?}");
            drop(best);
            // The next build on another parent gives this one back.
        }
    }
}

#[cfg(test)]
mod prune_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod drain_tests;

#[cfg(test)]
mod ahead_tests;

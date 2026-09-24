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

    fn remove(&self, hash: &B256) {
        let mut shard = self.shard_of(hash).write();
        if shard.by_hash.remove(hash).is_some() {
            // The order list is walked only when the bound bites, and a hash
            // that is no longer in the map is skipped there, so a removal
            // costs one map operation rather than a scan.
            shard.removed = shard.removed.saturating_add(1);
        }
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
}

impl<T: PoolTransaction> Clone for TxQueue<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            inbox: Arc::clone(&self.inbox),
            staged: Arc::clone(&self.staged),
            by_hash: self.by_hash.clone(),
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
        self.inner.lock().park_lanes = lanes;
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
            })),
            inbox: Arc::new(Mutex::new(Vec::new())),
            staged: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            by_hash: None,
        }
    }

    /// Moves what was pushed since the last drain into the lanes. Called
    /// with the lanes' lock held; a no-op when nothing was pushed.
    fn drain_inbox(&self, inner: &mut Inner<T>) {
        use std::sync::atomic::Ordering;
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
        self.staged.fetch_sub(staged.len(), Ordering::AcqRel);
        drop(inbox);
        // Lanes only. Nothing here touches the by-hash index: this runs
        // under the lanes' lock, with the builder's puller waiting on it.
        for valid in staged {
            inner.insert_valid(valid);
        }
    }

    /// Records that a canonical block at `number` has been pruned out of the
    /// lanes. Only the highest is kept.
    pub fn note_pruned(&self, number: u64) {
        let mut inner = self.inner.lock();
        inner.pruned_through = inner.pruned_through.max(number);
    }

    /// The highest block a canonical prune has taken out of the lanes.
    ///
    /// What a build compares its parent against: a parent below this is
    /// behind the queue, and every lane will look gapped to it whatever the
    /// lanes actually hold. Nothing here acts on that -- it is a reading for
    /// the builder to take.
    pub fn pruned_through(&self) -> u64 {
        self.inner.lock().pruned_through
    }

    /// The holes builds ran into since the last call: (sender, first missing
    /// nonce, first queued nonce above the hole). A hole is a transaction the
    /// queue never saw -- the pool's listener drops on a full channel -- or
    /// one still on its way in; the feed looks the pool up for it.
    pub fn take_gaps(&self) -> Vec<(Address, u64, u64)> {
        std::mem::take(&mut self.inner.lock().gaps)
    }

    /// How many transactions are queued.
    pub fn len(&self) -> usize {
        self.inner.lock().len + self.staged.load(std::sync::atomic::Ordering::Acquire)
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
        let mut inner = self.inner.lock();
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
    pub fn gate_len(&self) -> usize {
        let inner = self.inner.lock();
        (inner.len + self.staged.load(std::sync::atomic::Ordering::Acquire)).saturating_sub(inner.parked_len)
    }

    /// What the queue has let go of since the last call, by reason, with
    /// the first few named ([`Dropped`]). Taking it clears it, so a caller
    /// logging this reports a window and not a running total.
    pub fn take_drops(&self) -> DropReport {
        std::mem::take(&mut self.inner.lock().drops)
    }

    /// The lanes parked behind a hole, how many transactions they hold, and
    /// how many parks the cap has refused since the process started.
    pub fn parked(&self) -> (usize, usize, u64) {
        let inner = self.inner.lock();
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
        for hash in hashes {
            index.remove(&hash);
        }
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
        let mut inner = self.inner.lock();
        for transaction in &transactions {
            if let Some((_, taken)) = inner.last_build.as_mut()
                && let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction))
            {
                taken.remove(at);
            }
        }
        inner.give_back(transactions);
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
            let mut inner = self.inner.lock();
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
            let mut inner = self.inner.lock();
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
        let mut inner = self.inner.lock();
        self.drain_inbox(&mut inner);
        inner.remove_mined(sender, nonce);
    }

    /// Drops a batch of mined (sender, nonce) pairs and raises the senders'
    /// mined watermarks, so nothing at or below them can be queued again.
    /// For canonical blocks only -- see [`Self::remove_mined_batch_collecting`]
    /// for a block of this node's that consensus has not committed yet.
    pub fn remove_mined_batch(&self, mined: impl IntoIterator<Item = (Address, u64)>) {
        let mut inner = self.inner.lock();
        self.drain_inbox(&mut inner);
        // Folded to the highest nonce per sender first: a lane is split once
        // per sender, not once per transaction. Splitting per transaction
        // was 163,000 tree splits and as many allocations a block, 54-128 ms
        // under the lock the next build's puller is waiting on.
        let mut highest: AddressHashMap<u64> = AddressHashMap::default();
        for (sender, nonce) in mined {
            let entry = highest.entry(sender).or_insert(nonce);
            *entry = (*entry).max(nonce);
        }
        for (sender, nonce) in &highest {
            inner.remove_mined(*sender, *nonce);
        }
        // What a build has taken is not in the lanes, so the removal above
        // misses it; when the build is superseded its transactions are
        // offered again, and a mined one offered again is a stale
        // transaction the builder pays to refuse (42,000 a build in round
        // 38). Forget the mined ones here.
        if let Some((_, taken)) = inner.last_build.as_mut() {
            if !taken.is_empty() {
                taken.retain(|t| highest.get(&t.sender()).is_none_or(|mined| t.nonce() > *mined));
            }
        }
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
        let mut inner = self.inner.lock();
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
        let mut inner = self.inner.lock();
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
        let mut inner = self.inner.lock();
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
            let inner = self.inner.lock();
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
        let mut inner = self.inner.lock();
        times.lock_us += at.elapsed().as_micros() as u64;
        let at = std::time::Instant::now();
        let Some((built_on, taken)) = inner.last_build.as_mut() else { return (Vec::new(), times) };
        if *built_on != parent || taken.is_empty() {
            return (Vec::new(), times);
        }
        let (mined, kept): (Vec<_>, Vec<_>) = std::mem::take(taken)
            .into_iter()
            .partition(|t| highest.get(&t.sender()).is_some_and(|nonce| t.nonce() <= *nonce));
        *taken = kept;
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
            let inner = self.inner.lock();
            times.lock_us += at.elapsed().as_micros() as u64;
            match inner.last_build.as_ref() {
                Some((built_on, taken)) if *built_on == parent && !taken.is_empty() => {}
                _ => return (Vec::new(), times),
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
        let mut inner = self.inner.lock();
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
        *taken = kept;
        times.partition_us = at.elapsed().as_micros() as u64;
        (mined, times)
    }

    /// Moves what the inbox holds into the lanes now. The builder does this
    /// on its own pulls otherwise, and at the bench tier that is ~0.7 us a
    /// transaction of a full block's build (118 ms of 440, round 38) spent
    /// inserting arrivals rather than building; a task calling this every
    /// few milliseconds (`N42_TX_QUEUE_DRAINER=1`) takes it off the builder.
    pub fn drain_now(&self) {
        use std::sync::atomic::Ordering;
        if self.staged.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        self.drain_inbox(&mut inner);
    }

    /// The transactions for a build on `parent`, as the pool's iterator would
    /// hand them. Taking returns what the previous build on the same parent
    /// took, first.
    pub fn best_for_build(&self, parent: B256) -> QueueBest<T> {
        {
            let mut inner = self.inner.lock();
            self.drain_inbox(&mut inner);
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
            inner.last_build = Some((parent, Vec::new()));
            inner.end_run();
            // Every lane whose park has ended is offered again before this
            // build walks: a park that outlived its reason must never cost
            // a build the lane behind it.
            inner.readmit_parked();
        }
        QueueBest { queue: self.clone(), skipped: AddressHashSet::default(), buffer: VecDeque::new(), batch: queue_batch() }
    }
}

impl<T: PoolTransaction> Inner<T> {
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

    /// [`Self::remove_mined_from`] for a canonical block.
    fn remove_mined(&mut self, sender: Address, nonce: u64) {
        self.remove_mined_from(sender, nonce, true);
    }

    /// Drops everything at or below `nonce` and raises the watermark;
    /// `from_chain` says whether a canonical block put it there or a build
    /// did ([`Lane::chain_mined`]).
    fn remove_mined_from(&mut self, sender: Address, nonce: u64, from_chain: bool) {
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        lane.mine(nonce, from_chain);
        // The chain has reached or passed the hole: whatever is left in the
        // lane above it is the next thing this sender wants mined.
        let ends_park = lane.chain_passed(nonce);
        let parked = lane.parked.is_some();
        let keep = lane.by_nonce.split_off(&(nonce + 1));
        let dropped = lane.by_nonce.len();
        self.len -= dropped;
        lane.by_nonce = keep;
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
    queue: TxQueue<T>,
    skipped: AddressHashSet,
    /// Transactions taken under one lock and not yet handed to the builder.
    /// `N42_TX_QUEUE_BATCH=<n>` sets how many are taken at a time; 1 (the
    /// default) locks once per transaction, which at the bench tier was
    /// ~100 ms of a full block's build, 0.6 us a transaction, in the lock
    /// and the inbox drain alone.
    buffer: VecDeque<Arc<ValidPoolTransaction<T>>>,
    batch: usize,
}

/// `N42_TX_QUEUE_BATCH`, read once.
fn queue_batch() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| std::env::var("N42_TX_QUEUE_BATCH").ok().and_then(|v| v.parse().ok()).filter(|n| *n >= 1).unwrap_or(1))
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
        if self.buffer.is_empty() {
            return;
        }
        let mut inner = self.queue.inner.lock();
        for transaction in self.buffer.drain(..) {
            Self::untake(&mut inner, transaction);
        }
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
        loop {
            if let Some(transaction) = self.buffer.pop_front() {
                // A sender the build refused meanwhile: its buffered
                // transactions go back rather than to the builder.
                if self.skipped.contains(&transaction.sender()) {
                    let mut inner = self.queue.inner.lock();
                    Self::untake(&mut inner, transaction);
                    continue;
                }
                return Some(transaction);
            }
            let mut inner = self.queue.inner.lock();
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
        let sender = transaction.sender();
        let stale = matches!(&kind, InvalidPoolTransactionError::Consensus(err) if err.is_nonce_too_low());
        if stale {
            let nonce = transaction.nonce();
            let mut inner = self.queue.inner.lock();
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
                let mut inner = self.queue.inner.lock();
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
        let mut inner = self.queue.inner.lock();
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
}

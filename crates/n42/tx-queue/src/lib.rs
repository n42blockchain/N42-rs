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
    id: SenderId,
    /// The highest nonce the chain is known to have mined for this sender,
    /// from a canonical block or a build's stale refusal. Nothing at or
    /// below it may re-enter the lane through a give-back: the chain has
    /// made it unusable for good, and a build that is offered it pays a
    /// full refusal for it -- every build, for as long as it is queued
    /// (round 44: 814,431 refusals on one node against 17,300 on a healthy
    /// one, and a leader's build at 3.4-4.1 s instead of 250 ms).
    mined: Option<u64>,
}

impl<T: PoolTransaction> Lane<T> {
    /// Whether the chain has passed this nonce, so the lane must not hold it.
    fn is_stale(&self, nonce: u64) -> bool {
        self.mined.is_some_and(|mined| nonce <= mined)
    }

    /// Records that the chain mined this nonce. The watermark only rises:
    /// blocks arrive in order, and a later build's refusal says no less
    /// than an earlier block did.
    fn mine(&mut self, nonce: u64) {
        self.mined = Some(self.mined.map_or(nonce, |mined| mined.max(nonce)));
    }

    /// A reorg took this nonce back off the chain: the watermark drops below
    /// it, or the transactions the reverted blocks give back would be
    /// filtered as mined the first time a build handed them back.
    fn unmine(&mut self, nonce: u64) {
        if self.mined.is_some_and(|mined| mined >= nonce) {
            self.mined = nonce.checked_sub(1);
        }
    }
}

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
    next_sender_id: u64,
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

/// The by-hash index's bound, when one is kept: `N42_COMPACT_BODY=1` turns
/// it on and `N42_COMPACT_BODY_INDEX` sets the bound.
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
        if !std::env::var("N42_COMPACT_BODY").is_ok_and(|v| v == "1") {
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

/// A transaction handed in but not yet in its lane.
enum Staged<T: PoolTransaction> {
    Raw(T, std::time::Instant),
    Valid(Arc<ValidPoolTransaction<T>>),
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
                    parking_lot::RwLock::new(HashShard { by_hash: Default::default(), order: VecDeque::new() })
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
            while shard.order.len() > self.per_shard {
                if let Some(oldest) = shard.order.pop_front() {
                    shard.by_hash.remove(&oldest);
                }
            }
        }
    }

    fn get(&self, hash: &B256) -> Option<Arc<ValidPoolTransaction<T>>> {
        // A read lock, so the worker pool's 163,000 look-ups do not
        // serialise against each other while the drain writes the next
        // block's worth into another shard: 41-47 ns each at the bench tier
        // (`bench_hash_index`).
        self.shard_of(hash).read().by_hash.get(hash).cloned()
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
    inbox: Arc<Mutex<Vec<Staged<T>>>>,
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

    /// An empty queue taking `run` consecutive nonces per sender per turn.
    pub fn with_run_length(run: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                lanes: AddressHashMap::default(),
                arrivals: VecDeque::new(),
                next_sender_id: 1,
                len: 0,
                last_build: None,
                gaps: Vec::new(),
                held: VecDeque::new(),
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
        // Indexed as they go into the lanes, and only when an index is kept.
        // Measured on the ingest's own path (`bench_drain_with_and_without_the_hash_index`)
        // because the drain is the fleet's supply: a microsecond a
        // transaction here is 163 ms a block of one core.
        for item in staged {
            let queued = match item {
                Staged::Raw(transaction, at) => inner.insert(transaction, at, TransactionOrigin::External),
                Staged::Valid(valid) => inner.insert_valid(valid),
            };
            if let (Some(index), Some(queued)) = (self.by_hash.as_ref(), queued) {
                index.insert(queued);
            }
        }
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

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queues validated, recovered transactions. A (sender, nonce) already
    /// queued keeps its first arrival.
    pub fn push(&self, transactions: impl IntoIterator<Item = T>) {
        let now = std::time::Instant::now();
        let staged: Vec<Staged<T>> = transactions.into_iter().map(|t| Staged::Raw(t, now)).collect();
        let count = staged.len();
        // Counted under the inbox's lock, so the counter and the inbox
        // always agree for a drain that holds it (see `drain_inbox`).
        let mut inbox = self.inbox.lock();
        inbox.extend(staged);
        self.staged.fetch_add(count, std::sync::atomic::Ordering::AcqRel);
    }

    /// Queues transactions the pool has already validated, as the pool holds
    /// them. What the pool's new-transaction listener yields; the queue is a
    /// view of the pool's arrivals, whichever door they came in by.
    pub fn push_valid(&self, transactions: impl IntoIterator<Item = Arc<ValidPoolTransaction<T>>>) {
        let staged: Vec<Staged<T>> = transactions.into_iter().map(Staged::Valid).collect();
        let count = staged.len();
        // Under the inbox's lock, as [`Self::push`].
        let mut inbox = self.inbox.lock();
        inbox.extend(staged);
        self.staged.fetch_add(count, std::sync::atomic::Ordering::AcqRel);
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
                inner.len -= gone.len();
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
            inner.held.pop_front();
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
        for (held_number, held_hash, transactions) in std::mem::take(&mut inner.held) {
            if held_number == number && held_hash != hash {
                back.extend(transactions.into_iter().filter(|t| !carried(&t.sender(), t.nonce())));
            } else if held_number > number {
                kept.push_back((held_number, held_hash, transactions));
            }
            // The same hash, or a height already behind the chain: dropped.
        }
        inner.held = kept;
        if back.is_empty() {
            return 0;
        }
        // The committed block at this height may have mined a higher nonce
        // for a sender than the held one carries; `carried` is an exact
        // (sender, nonce) test, so the lane's watermark is what catches
        // those.
        inner.give_back(back).offered
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
        // The hand-off calls this after build-on-seal already has: the build
        // then stands on another parent and there is nothing to forget. Look
        // before folding a block's nonces (a 163,000-entry map), and fold
        // outside the lock the puller needs.
        {
            let inner = self.inner.lock();
            match inner.last_build.as_ref() {
                Some((built_on, taken)) if *built_on == parent && !taken.is_empty() => {}
                _ => return Vec::new(),
            }
        }
        let mut highest: AddressHashMap<u64> = AddressHashMap::default();
        for (sender, nonce) in mined {
            let entry = highest.entry(sender).or_insert(nonce);
            *entry = (*entry).max(nonce);
        }
        let mut inner = self.inner.lock();
        let Some((built_on, taken)) = inner.last_build.as_mut() else { return Vec::new() };
        if *built_on != parent || taken.is_empty() {
            return Vec::new();
        }
        let (mined, kept): (Vec<_>, Vec<_>) = std::mem::take(taken)
            .into_iter()
            .partition(|t| highest.get(&t.sender()).is_some_and(|nonce| t.nonce() <= *nonce));
        *taken = kept;
        mined
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
        }
        QueueBest { queue: self.clone(), skipped: AddressHashSet::default(), buffer: VecDeque::new(), batch: queue_batch() }
    }
}

impl<T: PoolTransaction> Inner<T> {
    /// Queues one transaction, handing back what was queued so the caller
    /// can index it; `None` when the lane refused it (already queued at that
    /// nonce, or the chain has passed it).
    fn insert(
        &mut self,
        transaction: T,
        now: std::time::Instant,
        origin: TransactionOrigin,
    ) -> Option<&Arc<ValidPoolTransaction<T>>> {
        let sender = transaction.sender();
        let nonce = transaction.nonce();
        let next_id = &mut self.next_sender_id;
        let lane = self.lanes.entry(sender).or_insert_with(|| {
            let id = SenderId::from(*next_id);
            *next_id += 1;
            Lane { by_nonce: BTreeMap::new(), queued: false, id, mined: None }
        });
        if lane.by_nonce.contains_key(&nonce) || lane.is_stale(nonce) {
            return None;
        }
        let valid = Arc::new(ValidPoolTransaction {
            transaction,
            transaction_id: TransactionId::new(lane.id, nonce),
            propagate: false,
            timestamp: now,
            origin,
            authority_ids: None,
        });
        lane.by_nonce.insert(nonce, valid);
        self.len += 1;
        if !lane.queued {
            lane.queued = true;
            self.arrivals.push_back(sender);
        }
        lane.by_nonce.get(&nonce)
    }

    /// [`Self::insert`] for a transaction the pool has already validated.
    fn insert_valid(
        &mut self,
        valid: Arc<ValidPoolTransaction<T>>,
    ) -> Option<&Arc<ValidPoolTransaction<T>>> {
        let sender = valid.sender();
        let nonce = valid.nonce();
        let next_id = &mut self.next_sender_id;
        let lane = self.lanes.entry(sender).or_insert_with(|| {
            let id = SenderId::from(*next_id);
            *next_id += 1;
            Lane { by_nonce: BTreeMap::new(), queued: false, id, mined: None }
        });
        if lane.by_nonce.contains_key(&nonce) || lane.is_stale(nonce) {
            return None;
        }
        lane.by_nonce.insert(nonce, valid);
        self.len += 1;
        if !lane.queued {
            lane.queued = true;
            self.arrivals.push_back(sender);
        }
        lane.by_nonce.get(&nonce)
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
        let mut gave = GaveBack::default();
        for valid in taken {
            let sender = valid.sender();
            let nonce = valid.nonce();
            let Some(lane) = self.lanes.get_mut(&sender) else {
                gave.filtered += 1;
                continue;
            };
            if lane.is_stale(nonce) {
                gave.filtered += 1;
                continue;
            }
            gave.offered += 1;
            if lane.by_nonce.insert(nonce, valid).is_none() {
                self.len += 1;
            }
            if !lane.queued {
                lane.queued = true;
                senders.push(sender);
            }
        }
        for sender in senders.into_iter().rev() {
            self.arrivals.push_front(sender);
        }
        gave
    }

    fn remove_mined(&mut self, sender: Address, nonce: u64) {
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        lane.mine(nonce);
        let keep = lane.by_nonce.split_off(&(nonce + 1));
        self.len -= lane.by_nonce.len();
        lane.by_nonce = keep;
        // A now-empty lane leaves the arrival order when its turn comes.
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
            let mut inner = self.queue.inner.lock();
            if let Some((_, taken)) = inner.last_build.as_mut()
                && let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction))
            {
                taken.remove(at);
            }
            inner.remove_mined(sender, transaction.nonce());
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

    /// What the by-hash index costs the side that fills it, and what it
    /// gives the side that reads it, at the bench tier.
    ///
    /// The drain is the fleet's supply path: a microsecond a transaction
    /// here is 163 ms a block of one core, so this is the number that says
    /// whether the compact body may be turned on at all. Pinned:
    /// `RAYON_NUM_THREADS=16 taskset -c 0-31 cargo test --release -p
    /// n42-tx-queue --lib bench_hash_index -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing"]
    fn bench_hash_index() {
        let senders = 6_000u64;
        let per = 27u64;
        let count = (senders * per) as usize;
        let build = || {
            let mut all = Vec::with_capacity(count);
            for n in 0..per {
                for s in 0..senders {
                    let mut a = [0u8; 20];
                    a[..8].copy_from_slice(&(s + 1).to_be_bytes());
                    all.push(tx_hashed(Address::from(a), n));
                }
            }
            all
        };
        for (what, queue) in [
            ("without", TxQueue::<EthPooledTransaction>::with_run_length(64)),
            ("with   ", TxQueue::<EthPooledTransaction>::with_run_length(64).with_hash_index(count * 2)),
        ] {
            let all = build();
            let hashes: Vec<B256> = all.iter().map(|t| *t.hash()).collect();
            queue.push(all);
            let at = std::time::Instant::now();
            queue.drain_now();
            let drain = at.elapsed();
            let at = std::time::Instant::now();
            let found = queue.get_by_hashes(&hashes).iter().filter(|t| t.is_some()).count();
            let lookup = at.elapsed();
            eprintln!(
                "{what} index: drain {count} in {drain:?} = {:.0} ns/tx | look {count} up in \
                 {lookup:?} = {:.0} ns/tx, found {found}",
                drain.as_nanos() as f64 / count as f64,
                lookup.as_nanos() as f64 / count as f64,
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

    #[test]
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
        // The account is at nonce 2: the build refuses (1,1) as stale, which
        // makes (1,0) -- still in the take -- stale as well.
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

    /// A reorg puts back what the reverted blocks carried, watermark and all:
    /// the chain no longer holds those nonces (round 43).
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

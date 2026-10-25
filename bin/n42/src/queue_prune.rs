// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The builder queue's canonical pruner: every committed block's
//! transactions out of the queue, on every node.
//!
//! It used to be a tokio task on the execution layer's main runtime doing
//! 49-65 ms of synchronous work per 200,000-transaction block
//! (`docs/SHARED_EXECUTION_SCOPE.md` 10.1) on a runtime worker the ingest's
//! connections and the vote road also need. The work itself is now one pass
//! ([`n42_tx_queue::TxQueue::prune_block`], 5-10 ms in the unit test against
//! 69-76 for the three calls it replaced); with `N42_QUEUE_PRUNE_THREAD=1`
//! it also leaves the runtime: the task only forwards each notification to a
//! dedicated thread (`n42-queue-prune`), which takes every notification that
//! is waiting when it wakes (coalescing a burst into one wake, one block
//! after another in order) and prunes them.

use n42_engine_types::N42PooledTransaction;
use n42_tx_queue::TxQueue;
use n42_tx_types::N42Primitives;
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_provider::CanonStateNotification;
use tracing::{info, warn};

use alloy_primitives::{Address, B256};
use std::sync::atomic::{AtomicUsize, Ordering};

/// What the pruner takes from one committed block: its height, hash, the
/// `(sender, nonce)` pairs the lanes are pruned by and the transaction
/// hashes the by-hash index is pruned by (~12 MB a 200,000-transaction
/// block, against ~120 MB for the block itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanBlock {
    /// The block's height.
    pub number: u64,
    /// The block's hash.
    pub hash: B256,
    /// The block's `(sender, nonce)` pairs, in block order.
    pub pairs: Vec<(Address, u64)>,
    /// The block's transaction hashes, in block order.
    pub hashes: Vec<B256>,
}

impl LeanBlock {
    /// One walk of the block for both the pairs and the hashes.
    pub fn from_block(block: &reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Self {
        let mut hashes: Vec<B256> = Vec::with_capacity(block.senders().len());
        let pairs: Vec<(Address, u64)> = block
            .transactions_with_sender()
            .map(|(sender, tx)| {
                hashes.push(*alloy_consensus::transaction::TxHashRef::tx_hash(tx));
                (*sender, alloy_consensus::Transaction::nonce(tx))
            })
            .collect();
        Self { number: block.number(), hash: block.hash(), pairs, hashes }
    }
}

/// The committed blocks of a notification as lean summaries, in order.
pub fn lean_blocks(notification: &CanonStateNotification<N42Primitives>) -> Vec<LeanBlock> {
    notification.committed().blocks_iter().map(|b| LeanBlock::from_block(b)).collect()
}

/// What is carried to the pruning thread. An ordinary commit goes as
/// [`PruneFeed::Lean`], so the notification (an `Arc<Chain>` with every
/// block's body) is dropped at the forwarder instead of being kept alive
/// for as long as the pruner is behind; a reorg goes whole, since its
/// reverted chain's transactions are offered again.
#[derive(Debug)]
pub enum PruneFeed {
    /// The committed blocks' summaries of an ordinary commit.
    Lean(Vec<LeanBlock>),
    /// A whole notification (a reorg, or `N42_PRUNE_FEED_LEAN` off).
    Whole(CanonStateNotification<N42Primitives>),
}

impl PruneFeed {
    /// The feed for one notification: lean for a commit without reverted
    /// blocks when `lean` (`N42_PRUNE_FEED_LEAN`), whole otherwise.
    pub fn of(notification: CanonStateNotification<N42Primitives>, lean: bool) -> Self {
        if lean && notification.reverted().is_none() {
            Self::Lean(lean_blocks(&notification))
        } else {
            Self::Whole(notification)
        }
    }
}

/// `N42_PRUNE_FEED_LEAN=1` carries lean block summaries to the pruning
/// thread instead of whole canonical notifications; default off, read and
/// logged once. Loop351: with the pruner a wake (~1 s, ~25 blocks) behind,
/// the notifications in its channel were the last holders of the
/// committed blocks' bodies, 60-90 GB of the execution layer's heap. Round
/// 10.226 measured the lean feed losing 2-3.6% (LA1/LA1b 4.915 against
/// 5.100/5.019 M tx/s): the pair collection moved onto the notification
/// receiver's thread.
pub fn feed_lean() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let on = std::env::var("N42_PRUNE_FEED_LEAN").is_ok_and(|v| v == "1");
        info!(target: "n42.tx_queue", prune_feed_lean = on, "N42_PRUNE_FEED_LEAN");
        on
    })
}

/// Whether the pruning thread drops a wake's feed items itself
/// (`N42_PRUNE_FREE_INLINE=1`, default off: they go to the queue's freeing
/// thread through [`n42_tx_queue::free_later`] once the wake is pruned and
/// logged), read and logged once. A whole notification is the last holder
/// of its blocks' bodies once the pruner is behind the engine.
pub fn free_inline() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let on = std::env::var("N42_PRUNE_FREE_INLINE").is_ok_and(|v| v == "1");
        info!(target: "n42.tx_queue", prune_free_inline_items = on, "N42_PRUNE_FREE_INLINE");
        on
    })
}

/// Items sent to the pruning thread and not yet received by it.
static FEED_DEPTH: AtomicUsize = AtomicUsize::new(0);

/// The pruning thread's inbox: counts what it sends, so a wake can say how
/// deep the channel was (`feed_depth`).
#[derive(Debug, Clone)]
pub struct PruneSender(std::sync::mpsc::Sender<Queued>);

/// The inbox depth past which a send warns (at most once every ten
/// seconds): the channel is unbounded on purpose (a bound would put the
/// forwarder on the pruner's pace), so a pruner falling behind is said.
const FEED_DEPTH_WARN: usize = 64;

impl PruneSender {
    /// Sends one feed item with its arrival time; `Err` if the thread is gone.
    pub fn send(&self, feed: PruneFeed) -> Result<(), PruneFeed> {
        let depth = FEED_DEPTH.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::gauge!("n42_queue_prune_feed_depth").set(depth as f64);
        if depth > FEED_DEPTH_WARN && feed_depth_warn_allowed() {
            warn!(target: "n42.tx_queue", feed_depth = depth, "the queue's pruning thread is behind: its inbox holds every waiting block");
        }
        self.0.send((feed, std::time::Instant::now())).map_err(|err| {
            FEED_DEPTH.fetch_sub(1, Ordering::Relaxed);
            err.0 .0
        })
    }
}

/// At most one feed-depth warning every ten seconds.
fn feed_depth_warn_allowed() -> bool {
    static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = std::time::Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < std::time::Duration::from_secs(10)) {
        return false;
    }
    *last = Some(now);
    true
}

/// Forwards one feed item to the pruning thread; if the thread is gone (it
/// panicked, see [`spawn_thread`]), says so once at error level, forgets
/// the sender -- so every later notification takes the runtime's inline
/// path -- and prunes this item inline, so no block goes unpruned from here
/// on. What the dead thread had not yet taken from its inbox is lost with
/// it; later blocks settle the same senders past those nonces.
pub fn forward(pruner: &mut Option<PruneSender>, feed: PruneFeed, inline: impl FnOnce(PruneFeed)) {
    let Some(sender) = pruner.as_ref() else {
        inline(feed);
        return;
    };
    if let Err(feed) = sender.send(feed) {
        tracing::error!(target: "n42.tx_queue", "the queue's pruning thread is gone; pruning on the runtime from here on");
        *pruner = None;
        // What the dead thread never took stays counted otherwise, and the
        // depth would read as a pruner behind for the rest of the process.
        FEED_DEPTH.store(0, Ordering::Relaxed);
        metrics::gauge!("n42_queue_prune_feed_depth").set(0.0);
        inline(feed);
    }
}

/// One feed item pruned on the calling thread, as the pruning thread would
/// (the fallback of [`forward`]).
pub fn prune_feed_inline(queue: &TxQueue<N42PooledTransaction>, feed: &PruneFeed) {
    if n42_tx_queue::prune_lean() {
        prune_feed_lean(queue, &[feed], std::time::Duration::ZERO, 0);
    } else {
        prune_one(queue, FeedRef::from(feed), 1, std::time::Duration::ZERO, 0);
    }
}

/// How many committed blocks the canonical head is ahead of `pruned`, the
/// highest block a wake pruned.
fn lag_blocks(pruned: u64) -> u64 {
    n42_engine_types::canonical_head::number().saturating_sub(pruned)
}

/// Whether the pruner runs on its own thread (`N42_QUEUE_PRUNE_THREAD=1`,
/// off by default).
pub fn on_own_thread() -> bool {
    std::env::var("N42_QUEUE_PRUNE_THREAD").is_ok_and(|v| v == "1")
}

/// One canonical notification's prune: a reorg's reverted transactions
/// offered again, then every committed block settled and pruned in order.
/// `coalesced` is how many notifications the thread took in this wake (1
/// on the runtime), `waited` how long this one waited for it.
pub fn prune_notification(
    queue: &TxQueue<N42PooledTransaction>,
    notification: &CanonStateNotification<N42Primitives>,
    coalesced: usize,
    waited: std::time::Duration,
) {
    prune_one(queue, FeedRef::Whole(notification), coalesced, waited, 0);
}

/// One feed item, borrowed: what the prune functions walk.
#[derive(Debug, Clone, Copy)]
enum FeedRef<'a> {
    Lean(&'a [LeanBlock]),
    Whole(&'a CanonStateNotification<N42Primitives>),
}

impl<'a> From<&'a PruneFeed> for FeedRef<'a> {
    fn from(feed: &'a PruneFeed) -> Self {
        match feed {
            PruneFeed::Lean(blocks) => Self::Lean(blocks),
            PruneFeed::Whole(notification) => Self::Whole(notification),
        }
    }
}

impl<'a> FeedRef<'a> {
    /// The reorg's chains, if this item is a reorg.
    fn reorg(self) -> Option<(&'a reth_execution_types::Chain<N42Primitives>, &'a reth_execution_types::Chain<N42Primitives>)> {
        match self {
            Self::Whole(CanonStateNotification::Reorg { old, new }) => Some((old, new)),
            _ => None,
        }
    }

    /// The committed blocks' summaries: borrowed when the feed is lean,
    /// built from the blocks when it is whole.
    fn blocks(self) -> Vec<std::borrow::Cow<'a, LeanBlock>> {
        match self {
            Self::Lean(blocks) => blocks.iter().map(std::borrow::Cow::Borrowed).collect(),
            Self::Whole(notification) => {
                notification.committed().blocks_iter().map(|b| std::borrow::Cow::Owned(LeanBlock::from_block(b))).collect()
            }
        }
    }
}

/// [`prune_notification`] for one feed item; `feed_depth` is the pruning
/// thread's channel depth at the wake's start (0 on the runtime).
fn prune_one(
    queue: &TxQueue<N42PooledTransaction>,
    item: FeedRef<'_>,
    coalesced: usize,
    waited: std::time::Duration,
    feed_depth: usize,
) {
    let started = std::time::Instant::now();
    // A reorg: the reverted blocks' transactions are nowhere else -- with
    // the direct ingest the queue is their only holder -- so those the new
    // chain does not carry are offered again, before the new chain's prune
    // (which then removes any the new chain mined at a higher nonce).
    // Without this the affected senders' lanes started at a nonce ahead of
    // the chain and every leader refused them: half-empty blocks for the
    // rest of the leg (round 43).
    if let Some((old, new)) = item.reorg() {
        let reverted_blocks = old.blocks_iter().count();
        let back = crate::queue_reorg::reverted_transactions(old, new);
        let offered = back.len();
        // Through the reverted door: it lowers the senders' mined
        // watermarks, which the reverted blocks no longer justify.
        queue.push_reverted(back);
        warn!(target: "n42.tx_queue", reverted_blocks, offered, new_blocks = new.blocks_iter().count(), "reorg: the reverted blocks' transactions are offered again");
    }
    let mut mined = 0usize;
    // Where the prune's time goes (loop322 CTRL: 5 s on the new leader at
    // the handover): the own-block settle, the lanes' removal under the
    // lock, the by-hash index, microseconds; and the fold of the block's
    // pairs, the wait for the lock and the hand-off of what was removed to
    // the queue's freeing thread.
    let mut sum = n42_tx_queue::PruneTimes::default();
    let mut highest = 0u64;
    // The pairs and hashes collected from a whole notification's blocks.
    let at = std::time::Instant::now();
    let blocks = item.blocks();
    let collect_us = at.elapsed().as_micros() as u64;
    for block in blocks {
        // What the builder reads to tell a build for a height the chain has
        // already decided from a build that is starving.
        n42_engine_types::canonical_head::saw(block.number);
        // What the builder compares its parent against: a build below this
        // is behind its own queue.
        queue.note_pruned(block.number);
        highest = highest.max(block.number);
        // The (sender, nonce) pairs the lanes are pruned by, and the hashes
        // the by-hash index is pruned by.
        mined += block.pairs.len();
        // An own block held at this height: the same hash is settled,
        // another hash gives back what this block does not carry (then
        // pruned where this block mined a higher nonce).
        let (back, times) = queue.prune_block(block.number, block.hash, &block.pairs, &block.hashes);
        if back > 0 {
            note_settled_back(Some(block.number), 1, back);
        }
        sum.settle_us += times.settle_us;
        sum.fold_us += times.fold_us;
        sum.lock_us += times.lock_us;
        sum.remove_us += times.remove_us;
        sum.forget_us += times.forget_us;
        sum.free_us += times.free_us;
        sum.free_inline += times.free_inline;
        sum.frames_swept += times.frames_swept;
        sum.retire_us += times.retire_us;
        sum.retired += times.retired;
    }
    if mined > 10_000 {
        // `usable` beside `queued`: what a build could take of the depth.
        // The two part company when lanes are parked behind a hole, which
        // is what loop207-208's defect 13 was -- 334-360k queued, empty
        // blocks, and no line saying which of the two it was.
        let (parked_lanes, parked, park_capped) = queue.parked();
        let census = queue.frame_census();
        info!(
            target: "n42.tx_queue",
            mined,
            queued = queue.len(),
            usable = queue.usable(),
            parked,
            parked_lanes,
            park_capped,
            frames_indexed = queue.frames_indexed(),
            frames_aside = census.aside,
            frames_pending = census.pending,
            frames_inserted = census.inserted,
            frames_refused = census.refused,
            prune_ms = started.elapsed().as_millis() as u64,
            settle_us = sum.settle_us,
            remove_us = sum.remove_us,
            forget_us = sum.forget_us,
            fold_us = sum.fold_us,
            lock_us = sum.lock_us,
            free_us = sum.free_us,
            prune_free_inline = sum.free_inline,
            frames_swept = sum.frames_swept,
            retire_us = sum.retire_us,
            retired = sum.retired,
            collect_us,
            coalesced,
            prune_wait_ms = waited.as_millis() as u64,
            feed_depth,
            lag_blocks = lag_blocks(highest),
            "canonical blocks pruned from the queue"
        );
        // What the queue let go of since the last block, by reason, with
        // the first few named. A lane's hole -- a nonce the generator was
        // told this node had taken and that is in neither the queue nor a
        // block -- can only be made at one of these.
        let drops = queue.take_drops();
        if drops.interesting() {
            warn!(
                target: "n42.tx_queue",
                by_reason = ?drops.named(),
                first = ?drops.samples,
                "the queue let go of transactions"
            );
        }
    }
}

/// The lean prune of one wake's notifications (`N42_PRUNE_LEAN`): the
/// committed blocks of consecutive notifications folded into one
/// [`TxQueue::prune_blocks`]; a reorg ends the run before it (its reverted
/// transactions are offered again after the earlier blocks' prune and before
/// its new chain's, as on the per-notification path). `waited` is the
/// oldest notification's wait.
pub fn prune_notifications_lean(
    queue: &TxQueue<N42PooledTransaction>,
    notifications: &[&CanonStateNotification<N42Primitives>],
    waited: std::time::Duration,
) {
    let items: Vec<FeedRef<'_>> = notifications.iter().map(|n| FeedRef::Whole(n)).collect();
    prune_lean_items(queue, &items, waited, 0);
}

/// [`prune_notifications_lean`] for the pruning thread's feed items.
pub fn prune_feed_lean(queue: &TxQueue<N42PooledTransaction>, feed: &[&PruneFeed], waited: std::time::Duration, feed_depth: usize) {
    let items: Vec<FeedRef<'_>> = feed.iter().map(|f| FeedRef::from(*f)).collect();
    prune_lean_items(queue, &items, waited, feed_depth);
}

fn prune_lean_items(queue: &TxQueue<N42PooledTransaction>, items: &[FeedRef<'_>], waited: std::time::Duration, feed_depth: usize) {
    let started = std::time::Instant::now();
    let coalesced = items.len();
    let mut sum = n42_tx_queue::PruneTimes::default();
    let mut mined = 0usize;
    let mut highest = 0u64;
    // Microseconds collecting the pairs and hashes of whole notifications.
    let mut collect_us = 0u64;
    // Every block's pairs and hashes of the run, in order.
    let mut run: Vec<std::borrow::Cow<'_, LeanBlock>> = Vec::new();
    let flush = |run: &mut Vec<std::borrow::Cow<'_, LeanBlock>>, sum: &mut n42_tx_queue::PruneTimes| {
        if run.is_empty() {
            return;
        }
        let inputs: Vec<n42_tx_queue::PruneInput<'_>> = run
            .iter()
            .map(|b| n42_tx_queue::PruneInput { number: b.number, hash: b.hash, mined: &b.pairs, hashes: &b.hashes })
            .collect();
        let (back, times) = queue.prune_blocks(&inputs);
        if back > 0 {
            note_settled_back(None, inputs.len(), back);
        }
        sum.settle_us += times.settle_us;
        sum.fold_us += times.fold_us;
        sum.lock_us += times.lock_us;
        sum.remove_us += times.remove_us;
        sum.forget_us += times.forget_us;
        sum.free_us += times.free_us;
        sum.free_inline += times.free_inline;
        sum.frames_swept += times.frames_swept;
        sum.retire_us += times.retire_us;
        sum.retired += times.retired;
        sum.removals += times.removals;
        sum.folded += times.folded;
        sum.drained += times.drained;
        sum.drain_holds += times.drain_holds;
        sum.drain_us += times.drain_us;
        run.clear();
    };
    for item in items {
        if let Some((old, new)) = item.reorg() {
            flush(&mut run, &mut sum);
            let reverted_blocks = old.blocks_iter().count();
            let back = crate::queue_reorg::reverted_transactions(old, new);
            let offered = back.len();
            queue.push_reverted(back);
            warn!(target: "n42.tx_queue", reverted_blocks, offered, new_blocks = new.blocks_iter().count(), "reorg: the reverted blocks' transactions are offered again");
        }
        let at = std::time::Instant::now();
        let blocks = item.blocks();
        collect_us += at.elapsed().as_micros() as u64;
        for block in blocks {
            n42_engine_types::canonical_head::saw(block.number);
            queue.note_pruned(block.number);
            highest = highest.max(block.number);
            mined += block.pairs.len();
            run.push(block);
        }
    }
    flush(&mut run, &mut sum);
    if mined > 10_000 {
        let (parked_lanes, parked, park_capped) = queue.parked();
        let census = queue.frame_census();
        info!(
            target: "n42.tx_queue",
            mined,
            queued = queue.len(),
            usable = queue.usable(),
            parked,
            parked_lanes,
            park_capped,
            frames_indexed = queue.frames_indexed(),
            frames_aside = census.aside,
            frames_pending = census.pending,
            frames_inserted = census.inserted,
            frames_refused = census.refused,
            prune_ms = started.elapsed().as_millis() as u64,
            settle_us = sum.settle_us,
            remove_us = sum.remove_us,
            forget_us = sum.forget_us,
            fold_us = sum.fold_us,
            lock_us = sum.lock_us,
            free_us = sum.free_us,
            prune_free_inline = sum.free_inline,
            frames_swept = sum.frames_swept,
            retire_us = sum.retire_us,
            retired = sum.retired,
            collect_us,
            coalesced,
            prune_wait_ms = waited.as_millis() as u64,
            feed_depth,
            lag_blocks = lag_blocks(highest),
            // `N42_PRUNE_LEAN`: the lock holds' sum is `remove_us`; these
            // say how many removals the wake made and how many blocks were
            // folded into them.
            lean = true,
            prune_removals = sum.removals,
            blocks_folded = sum.folded,
            // The remainder finished after the removal, in bounded holds.
            prune_drained = sum.drained,
            prune_drain_holds = sum.drain_holds,
            prune_drain_us = sum.drain_us,
            "canonical blocks pruned from the queue"
        );
        let drops = queue.take_drops();
        if drops.interesting() {
            warn!(
                target: "n42.tx_queue",
                by_reason = ?drops.named(),
                first = ?drops.samples,
                "the queue let go of transactions"
            );
        }
    }
}

/// `N42_PRUNE_MIN_FOLD=<n>` (default 1: off) and `N42_PRUNE_MIN_FOLD_MS=<ms>`
/// (default 200), read and logged once: the pruning thread holds a wake
/// until at least `n` canonical notifications are in, or `ms` have passed
/// since the first arrived, so the wake's fixed cost (settle, forget,
/// remove: `prune_ms` 40-60 on loop351) is paid once per `n` blocks and
/// the lanes' lock is left to the drainer between wakes. Round 10.169: a
/// pruner waking once a block starved the inbox drain, the live frame
/// index emptied, and the selector waited 4-10 ms a build for frames;
/// legs whose pruner happened to fold 4-6 blocks a wake did not. Read by
/// the pruning thread and by the runtime's lean prune task (`main.rs`).
pub fn min_fold() -> (usize, std::time::Duration) {
    static KNOB: std::sync::OnceLock<(usize, std::time::Duration)> = std::sync::OnceLock::new();
    *KNOB.get_or_init(|| {
        let n = std::env::var("N42_PRUNE_MIN_FOLD").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(1).max(1);
        let ms = std::env::var("N42_PRUNE_MIN_FOLD_MS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(200);
        info!(target: "n42.tx_queue", min_fold = n, max_wait_ms = ms, "N42_PRUNE_MIN_FOLD");
        (n, std::time::Duration::from_millis(ms))
    })
}

/// `N42_PRUNE_MAX_FOLD=<n>` (default 0, unbounded): the most blocks one
/// wake of the pruning thread folds; what is over is carried into the next
/// wake, which starts at once, so the lanes' lock is released between
/// them. Round 10.172: with the prune ~37 ms a block, linear in the blocks
/// folded, against a ~42 ms block cadence, a minimum fold of 4 ran away to
/// 35-68-block wakes of 0.3-0.4 s on the thread (the builder's state wait
/// p50 0.2 -> 5 ms, and the inbox backlog came back on the long wakes).
pub fn max_fold() -> usize {
    static KNOB: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *KNOB.get_or_init(|| {
        let n = std::env::var("N42_PRUNE_MAX_FOLD").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
        if n > 0 {
            info!(target: "n42.tx_queue", max_fold = n, "N42_PRUNE_MAX_FOLD");
        }
        n
    })
}

/// A feed item on its way to the pruning thread, with when it arrived.
type Queued = (PruneFeed, std::time::Instant);

/// Starts the pruning thread; `None` (and a warning) if it could not be
/// started, and the caller prunes on the runtime as before.
pub fn spawn_thread(queue: TxQueue<N42PooledTransaction>) -> Option<PruneSender> {
    spawn_with(move |rx| run_pruner(&queue, rx)).map(|(sender, _)| sender)
}

/// Starts the pruning thread on `body`, which owns the inbox. A panic in
/// the body is caught and logged at error level with its message; the
/// thread then ends, its inbox closes, and [`forward`] falls back to
/// pruning on the runtime.
fn spawn_with(
    body: impl FnOnce(std::sync::mpsc::Receiver<Queued>) + Send + 'static,
) -> Option<(PruneSender, std::thread::JoinHandle<()>)> {
    let (tx, rx) = std::sync::mpsc::channel::<Queued>();
    let spawned = std::thread::Builder::new().name("n42-queue-prune".to_owned()).spawn(move || {
        if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(rx))) {
            let message = panic
                .downcast_ref::<&str>()
                .map(|m| (*m).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "a non-string panic".to_owned());
            tracing::error!(
                target: "n42.tx_queue",
                panic = %message,
                canonical_head = n42_engine_types::canonical_head::number(),
                feed_depth = FEED_DEPTH.load(Ordering::Relaxed),
                "the queue's pruning thread panicked; the runtime prunes from the next notification"
            );
        }
    });
    match spawned {
        Ok(handle) => {
            info!(target: "n42.tx_queue", "canonical queue pruner on its own thread");
            Some((PruneSender(tx), handle))
        }
        Err(err) => {
            warn!(target: "n42.tx_queue", %err, "N42_QUEUE_PRUNE_THREAD=1 but its thread could not be started; pruning on the runtime");
            None
        }
    }
}

/// The pruning thread's loop: wakes on its inbox, folds what is waiting
/// and prunes it, until the inbox closes.
fn run_pruner(queue: &TxQueue<N42PooledTransaction>, rx: std::sync::mpsc::Receiver<Queued>) {
    let (min_fold, max_wait) = min_fold();
    let max_fold = max_fold();
    // What a capped wake left over (`N42_PRUNE_MAX_FOLD`); the next
    // wake starts from it without blocking.
    let mut carry: Vec<Queued> = Vec::new();
    loop {
        let Some((batch, received, feed_depth)) = next_wake(&rx, &mut carry, min_fold, max_wait, max_fold) else {
            break;
        };
        FEED_DEPTH.fetch_sub(received, Ordering::Relaxed);
        let coalesced = batch.len();
        if n42_tx_queue::prune_lean() {
            let waited = batch[0].1.elapsed();
            let feed: Vec<&PruneFeed> = batch.iter().map(|(f, _)| f).collect();
            prune_feed_lean(queue, &feed, waited, feed_depth);
            drop(feed);
            // Freed on the queue's freeing thread: a pruner behind the
            // engine holds the last reference to the wake's blocks, and
            // their free was ~13 ms a block on this thread after the
            // logged prune (loop351 by, lean legs, 25-block wakes).
            if free_inline() {
                drop(batch);
            } else {
                n42_tx_queue::free_later(batch);
            }
            continue;
        }
        for (feed, arrived) in &batch {
            prune_one(queue, FeedRef::from(feed), coalesced, arrived.elapsed(), feed_depth);
        }
        // As on the lean path: the wake's notifications go to the
        // freeing thread once every one is pruned and logged.
        if free_inline() {
            drop(batch);
        } else {
            n42_tx_queue::free_later(batch);
        }
    }
}

/// One wake of the pruning thread: the items it folds, how many of them came
/// off the channel (the rest are `carry`), and the channel's depth at its
/// start (`feed_depth` on the prune line). `None` once the inbox is closed
/// and nothing is carried.
///
/// Everything already waiting is taken, in order. With `min_fold > 1`
/// (`N42_PRUNE_MIN_FOLD`) the wake waits for more, up to `max_wait` after
/// its first item arrived; with `max_fold > 0` (`N42_PRUNE_MAX_FOLD`) what
/// is over is left in `carry`, and the next wake starts from it without
/// blocking.
fn next_wake<T>(
    rx: &std::sync::mpsc::Receiver<(T, std::time::Instant)>,
    carry: &mut Vec<(T, std::time::Instant)>,
    min_fold: usize,
    max_wait: std::time::Duration,
    max_fold: usize,
) -> Option<(Vec<(T, std::time::Instant)>, usize, usize)> {
    // Whether the wake's first item comes from the channel (not the carry).
    let first_from_rx = carry.is_empty();
    let mut batch = if first_from_rx {
        match rx.recv() {
            Ok(first) => vec![first],
            Err(_) => return None,
        }
    } else {
        std::mem::take(carry)
    };
    // The channel's depth at the wake's start, the item just received
    // included.
    let feed_depth = FEED_DEPTH.load(Ordering::Relaxed);
    let mut received = usize::from(first_from_rx);
    while let Ok(next) = rx.try_recv() {
        batch.push(next);
        received += 1;
    }
    if min_fold > 1 {
        let deadline = batch[0].1 + max_wait;
        while batch.len() < min_fold {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            match rx.recv_timeout(deadline - now) {
                Ok(next) => {
                    batch.push(next);
                    received += 1;
                    while let Ok(more) = rx.try_recv() {
                        batch.push(more);
                        received += 1;
                    }
                }
                Err(_) => break,
            }
        }
    }
    if max_fold > 0 && batch.len() > max_fold {
        *carry = batch.split_off(max_fold);
    }
    Some((batch, received, feed_depth))
}

/// The canonical prune gave back an own block held at a height the chain
/// committed another block at. Under two-ahead (`N42_BUILD_AHEAD_GATE=seal`)
/// that is the release of a block the handover replaced when no build of this
/// execution layer released it first (this node does not build the next
/// height, or its hold landed after every such build had started): said at
/// info with its own wording. Otherwise it is a view change the queue
/// recovers from, said as a warning as before.
fn note_settled_back(number: Option<u64>, blocks: usize, back: usize) {
    if n42_tx_queue::release_replaced_own_blocks() {
        info!(
            target: "n42.tx_queue",
            ?number,
            blocks,
            back,
            "an own block replaced at a handover was released when the chain committed its height; its transactions are offered again"
        );
    } else if let Some(number) = number {
        warn!(target: "n42.tx_queue", number, back, "an own block at this height was not the one committed; its transactions are offered again");
    } else {
        warn!(target: "n42.tx_queue", blocks, back, "an own block at a pruned height was not the one committed; its transactions are offered again");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue_reorg::tests::{addr, block, transfer};
    use alloy_consensus::transaction::TxHashRef as _;
    use reth_execution_types::Chain;
    use reth_transaction_pool::PoolTransaction as _;
    use std::sync::Arc;

    fn commit() -> CanonStateNotification<N42Primitives> {
        let (a, b) = (addr(1), addr(2));
        let chain = Chain::new(
            vec![block(10, vec![(a, transfer(0, 1)), (b, transfer(0, 2))]), block(11, vec![(a, transfer(1, 3))])],
            Default::default(),
            Default::default(),
        );
        CanonStateNotification::Commit { new: Arc::new(chain) }
    }

    #[test]
    fn a_lean_feed_carries_what_the_whole_notification_gives_the_prune() {
        let notification = commit();
        // What the prune reads from the whole notification, block by block.
        let whole: Vec<LeanBlock> = FeedRef::Whole(&notification).blocks().into_iter().map(|b| b.into_owned()).collect();
        let PruneFeed::Lean(lean) = PruneFeed::of(notification.clone(), true) else { panic!("a commit goes lean") };
        assert_eq!(lean, whole);
        assert_eq!(lean.iter().map(|b| b.number).collect::<Vec<_>>(), vec![10, 11]);
        assert_eq!(lean[0].pairs, vec![(addr(1), 0), (addr(2), 0)]);
        let first = notification.committed().blocks_iter().next().map(|b| (b.hash(), *b.body().transactions[1].tx_hash()));
        assert_eq!(first, Some((lean[0].hash, lean[0].hashes[1])));
        assert!(matches!(PruneFeed::of(notification, false), PruneFeed::Whole(_)), "the knob off goes whole");
    }

    fn filled(notification: &CanonStateNotification<N42Primitives>) -> TxQueue<N42PooledTransaction> {
        let queue: TxQueue<N42PooledTransaction> = TxQueue::new();
        let txs: Vec<N42PooledTransaction> = notification
            .committed()
            .blocks_iter()
            .flat_map(|b| b.transactions_with_sender().map(|(s, tx)| (*s, tx.clone())).collect::<Vec<_>>())
            .chain(std::iter::once((addr(1), transfer(2, 9))))
            .filter_map(|(s, tx)| {
                N42PooledTransaction::try_from_consensus(reth_primitives_traits::Recovered::new_unchecked(tx, s)).ok()
            })
            .collect();
        queue.push_reverted(txs);
        queue
    }

    /// A pruning thread whose body panics: the panic is caught, the inbox
    /// closes, and the next forward prunes inline and forgets the thread.
    #[test]
    fn a_dead_pruning_thread_is_followed_by_inline_pruning() {
        let notification = commit();
        let queue = filled(&notification);
        let expected = filled(&notification);
        prune_feed_inline(&expected, &PruneFeed::of(notification.clone(), false));
        assert!(expected.len() < queue.len(), "the commit prunes something");
        let (sender, handle) = spawn_with(|_rx| panic!("a pruner bug")).expect("a thread");
        handle.join().expect("the panic is caught inside the thread");
        let mut pruner = Some(sender);
        let mut inline_runs = 0;
        forward(&mut pruner, PruneFeed::of(notification.clone(), false), |feed| {
            inline_runs += 1;
            prune_feed_inline(&queue, &feed);
        });
        assert!(pruner.is_none(), "the dead thread is forgotten");
        assert_eq!(FEED_DEPTH.load(Ordering::Relaxed), 0, "the dead inbox is not counted");
        assert_eq!(inline_runs, 1);
        assert_eq!(queue.len(), expected.len());
        assert_eq!(queue.usable(), expected.usable());
        // Later items go inline without trying the thread.
        forward(&mut pruner, PruneFeed::of(notification, false), |_| inline_runs += 1);
        assert_eq!(inline_runs, 2);
    }

    /// `N42_PRUNE_MAX_FOLD`: a wake folds at most `max_fold` items and the
    /// rest are carried, in order, into the next wakes, which take nothing
    /// off the channel until the carry is gone.
    #[test]
    fn a_capped_wake_carries_the_rest_in_order() {
        let (tx, rx) = std::sync::mpsc::channel::<(u32, std::time::Instant)>();
        for i in 0..5 {
            tx.send((i, std::time::Instant::now())).expect("open");
        }
        let mut carry = Vec::new();
        let items = |batch: &[(u32, std::time::Instant)]| batch.iter().map(|(i, _)| *i).collect::<Vec<_>>();
        let (batch, received, _) = next_wake(&rx, &mut carry, 1, std::time::Duration::ZERO, 2).expect("a wake");
        assert_eq!((items(&batch), received), (vec![0, 1], 5));
        let (batch, received, _) = next_wake(&rx, &mut carry, 1, std::time::Duration::ZERO, 2).expect("a wake");
        assert_eq!((items(&batch), received), (vec![2, 3], 0), "from the carry");
        let (batch, received, _) = next_wake(&rx, &mut carry, 1, std::time::Duration::ZERO, 2).expect("a wake");
        assert_eq!((items(&batch), received), (vec![4], 0));
        assert!(carry.is_empty());
        drop(tx);
        assert!(next_wake(&rx, &mut carry, 1, std::time::Duration::ZERO, 2).is_none(), "closed, nothing carried");
    }

    /// `N42_PRUNE_MIN_FOLD`: a wake with enough waiting folds at once; one
    /// short of the minimum waits out `max_wait` from its first item and
    /// then folds what it has.
    #[test]
    fn a_minimum_fold_waits_at_most_its_deadline() {
        let (tx, rx) = std::sync::mpsc::channel::<(u32, std::time::Instant)>();
        let mut carry = Vec::new();
        for i in 0..3 {
            tx.send((i, std::time::Instant::now())).expect("open");
        }
        let (batch, received, _) = next_wake(&rx, &mut carry, 3, std::time::Duration::from_secs(10), 0).expect("a wake");
        assert_eq!((batch.len(), received), (3, 3), "enough waiting: no wait");
        let max_wait = std::time::Duration::from_millis(30);
        let started = std::time::Instant::now();
        tx.send((9, started)).expect("open");
        let (batch, received, _) = next_wake(&rx, &mut carry, 3, max_wait, 0).expect("a wake");
        assert_eq!((batch.len(), received), (1, 1));
        assert!(started.elapsed() >= max_wait, "waited for more until the deadline");
        assert!(carry.is_empty());
    }

    #[test]
    fn a_lean_feed_prunes_the_queue_as_the_whole_notification_does() {
        let notification = commit();
        let fill = || {
            let queue: TxQueue<N42PooledTransaction> = TxQueue::new();
            let txs: Vec<N42PooledTransaction> = notification
                .committed()
                .blocks_iter()
                .flat_map(|b| b.transactions_with_sender().map(|(s, tx)| (*s, tx.clone())).collect::<Vec<_>>())
                .chain(std::iter::once((addr(1), transfer(2, 9))))
                .filter_map(|(s, tx)| {
                    N42PooledTransaction::try_from_consensus(reth_primitives_traits::Recovered::new_unchecked(tx, s)).ok()
                })
                .collect();
            queue.push_reverted(txs);
            queue
        };
        let (by_whole, by_lean) = (fill(), fill());
        prune_notifications_lean(&by_whole, &[&notification], std::time::Duration::ZERO);
        let feed = PruneFeed::of(notification.clone(), true);
        prune_feed_lean(&by_lean, &[&feed], std::time::Duration::ZERO, 1);
        assert_eq!(by_lean.len(), by_whole.len());
        assert_eq!(by_lean.usable(), by_whole.usable());
    }
}

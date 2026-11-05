// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The parts of [`crate::parallel_transfer`] that do not touch the EVM: the
//! knobs, the worker pools, the sender partition, the phase timers and the
//! revert helpers over reth's bundle state. They build with and without the
//! `legacy-revm-paths` feature (`crate::legacy_paths`); the revm-era
//! execution that uses them builds only with it, and re-exports them, so
//! every `crate::parallel_transfer::*` path keeps working.
// The stock evm2 build leaves the revm-era paths out (`legacy-revm-paths`): what only they
// use or mutate reads as dead here until F5 ports or removes them (docs/RETH_2_9_0_UPGRADE.md).
#![cfg_attr(
    not(feature = "legacy-revm-paths"),
    allow(dead_code, unused_mut, unused_variables, unused_assignments, unused_imports)
)]

use alloy_primitives::{Address, U256};
use n42_tx_types::Block;
use reth_primitives_traits::RecoveredBlock;
use reth_trie::bundle_state::{AccountRevert, BundleState};

/// The block executor factory of a node with the transfer path: what
/// [`execute_transfers`] requires of its EVM configuration.
pub type FastExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<n42_header::N42ChainSpec>;

/// The executor's phase timings, in milliseconds: partitioning, the groups'
/// execution (wall), the merge into the block's state, the finish.
#[derive(Debug, Clone, Copy, Default)]
pub struct Phases {
    /// Partitioning the transactions into conflict-free groups.
    pub partition_ms: u64,
    /// [`execute_for_build_in_place`] and its kin: from the call's entry to
    /// the batches' start (the partition, the hook before the batches, the
    /// read set, the slots), microseconds -- the leader's gap before the
    /// execution, with what the caller did before the call.
    pub batches_start_us: u64,
    /// `N42_PLAN_AHEAD_BODY=1`: the partition and the slots came prepared
    /// with the plan ([`PreparedExec`]) rather than made in the call.
    pub prepared_groups: bool,
    /// See `prepared_groups`.
    pub prepared_slots: bool,
    /// The partition and `batch_groups` (or the prepared groups' check),
    /// microseconds; and the slots made (or taken), microseconds.
    pub partition_us: u64,
    /// See `partition_us`.
    pub slots_us: u64,
    /// The caller's hook before the batches (the build's deferred state
    /// opened and its pre-execution changes), microseconds; inside
    /// `batches_start_us`.
    pub hook_us: u64,
    /// From the call's entry to the batches' end, microseconds: the caller
    /// names the gap after the execution from here.
    pub batches_end_us: u64,
    /// Of `partition_ms`: the transactions' EVM environments, built on the
    /// worker pool.
    pub env_us: u64,
    /// Packing the groups into batches and staging the graft, between the
    /// partition and the execution.
    pub batch_us: u64,
    /// The groups' execution on the worker pool, wall time.
    pub groups_ms: u64,
    /// The batches' gas placed in block order after the execution.
    pub gas_us: u64,
    /// The block's receipts, built in block order from that gas.
    pub receipts_us: u64,
    /// Freeing the transactions' environments, the groups and the batches'
    /// bundles, done here rather than at the return so the line can name it.
    pub drop_us: u64,
    /// The whole call, so a caller's `exec_ms` minus this is what it spends
    /// outside the executor (loop202: 40 of the follower's 133 ms had no
    /// name because the line stopped at the four phases below).
    pub total_us: u64,
    /// Folding the groups' changes into the block's state.
    pub merge_ms: u64,
    /// Of `merge_ms`: the graft (or fold) of the batches' bundles.
    pub graft_ms: u64,
    /// Of `merge_ms`: the state's own transition merge and the bundle take.
    pub take_ms: u64,
    /// Of `merge_ms`: appending and sorting the grafted reverts.
    pub reverts_ms: u64,
    /// The batches' results placed in candidate order (the build).
    pub collect_ms: u64,
    /// The build's partition (one vector per sender) and batch lists
    /// released at the run's end. With `N42_SEAL_AT_EXEC=1` they are handed
    /// to the worker pool to free and this is only the hand-off.
    pub release_ms: u64,
    /// Pre- and post-execution changes and the bundle.
    pub finish_ms: u64,
    /// How many groups there were.
    pub groups: usize,
    /// Whether the environments and the partition came from a plan made
    /// ahead of the call ([`plan_transfers`]); `partition_ms` is then only
    /// the plan's hand-over.
    pub planned_ahead: bool,
    /// The plan's environments, made ahead of the call, microseconds.
    pub ahead_env_us: u64,
    /// The plan's environments and partition, made ahead of the call,
    /// microseconds.
    pub ahead_plan_us: u64,
    /// [`follower_merge_behind`]: the grafted reverts' sort on its own
    /// thread, microseconds, and how long the merge waited for it at the end.
    pub reverts_sort_us: u64,
    /// See `reverts_sort_us`.
    pub reverts_wait_us: u64,
    /// How many batches of groups ran (the build's [`execute_for_build`]
    /// runs a sender per group and several groups per batch).
    pub batches: usize,
    /// The threads of the pool the batches ran on.
    pub threads: usize,
    /// `N42_PHASE_TIMERS=1` (plan v6 6.5/6.6): the block's transfers summed
    /// over every batch that ran part of it -- see
    /// [`crate::fast_transfer::TransferTimers`]. Zero when the flag is off.
    pub transfer_timers: crate::fast_transfer::TransferTimers,
    /// `N42_READ_SET=1`: the read set's pass (inside `groups_ms`, before the
    /// batches), its accounts, and the batches' reads it answered and those
    /// that fell to the parent's state. Zero when the flag is off.
    pub read_set: ReadSetPass,
    /// See `read_set`.
    pub read_set_hits: u64,
    /// See `read_set`.
    pub read_set_misses: u64,
    /// The build's batches on the pool, each from its start to its end:
    /// whether `groups_ms` is imbalance, gaps, or per-batch overhead.
    pub batch_spans: BatchSpans,
    /// `N42_PHASE_TIMERS=1`: the build's batch loop by section, summed over
    /// every batch (pool time) -- see [`LoopTimers`]. Zero when the flag is
    /// off.
    pub loop_timers: LoopTimers,
    /// `N42_BUILD_MLP=<k>`: the lookahead distance the batches ran with, 0
    /// when off ([`build_mlp`]).
    pub mlp_k: usize,
    /// `N42_BUILD_MLP`: the account hints the batches sent beneath their own
    /// maps, into the parent's layers, summed over the batches.
    pub mlp_hints: u64,
}

/// The calling thread's CPU time, nanoseconds (0 where it cannot be read).
pub(crate) fn thread_cpu_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the call only writes into the zeroed struct passed to it.
        unsafe {
            let mut ts: libc::timespec = std::mem::zeroed();
            if libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) == 0 {
                return (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64);
            }
        }
    }
    0
}

/// The calling thread's CPU time and its resource counters at one instant
/// (`getrusage(RUSAGE_THREAD)`): a batch's span is the difference of two.
/// The minor faults say whether a batch's off-CPU time is first touches, the
/// voluntary switches whether it blocked (a futex, a major fault), the
/// involuntary ones whether it was preempted.
/// The major faults say whether it waited on a file read (an entry-file page
/// of the QMDB view, a database page, not in the page cache). Beside the
/// kernel's counters, the thread's own lock-wait counters: the QMDB read
/// view's slot and index locks ([`n42_qmdb_reth::ViewLockWaits`]) and the
/// output shards' live-index locks
/// ([`crate::output_shards::LiveLockCounts`]) -- per-thread cells, read
/// without a syscall.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadMark {
    cpu_ns: u64,
    minflt: u64,
    majflt: u64,
    nvcsw: u64,
    nivcsw: u64,
    view: n42_qmdb_reth::ViewLockWaits,
    live: crate::output_shards::LiveLockCounts,
}

impl ThreadMark {
    /// The calling thread's counters now (zeros where they cannot be read).
    pub fn now() -> Self {
        let cpu_ns = thread_cpu_ns();
        let view = n42_qmdb_reth::ViewLockWaits::now();
        let live = crate::output_shards::LiveLockCounts::now();
        #[cfg(target_os = "linux")]
        {
            // SAFETY: the call only writes into the zeroed struct passed to it.
            unsafe {
                let mut usage: libc::rusage = std::mem::zeroed();
                if libc::getrusage(libc::RUSAGE_THREAD, &mut usage) == 0 {
                    return Self {
                        cpu_ns,
                        minflt: usage.ru_minflt.max(0) as u64,
                        majflt: usage.ru_majflt.max(0) as u64,
                        nvcsw: usage.ru_nvcsw.max(0) as u64,
                        nivcsw: usage.ru_nivcsw.max(0) as u64,
                        view,
                        live,
                    };
                }
            }
        }
        Self { cpu_ns, view, live, ..Self::default() }
    }
}

/// One batch of the build on the pool: its start and end against the
/// batches' start (microseconds), the CPU time its thread spent in it, and
/// its transactions.
#[derive(Debug, Clone, Copy, Default)]
pub struct BatchSpan {
    /// Start, microseconds after the batches' start.
    pub start_us: u64,
    /// End, microseconds after the batches' start.
    pub end_us: u64,
    /// The thread's CPU time inside the batch, microseconds.
    pub cpu_us: u64,
    /// Transactions in the batch.
    pub txs: usize,
    /// The pool thread that ran it (`usize::MAX` off the pool).
    pub thread: usize,
    /// Minor page faults the thread took inside the batch.
    pub minflt: u64,
    /// Voluntary context switches inside the batch (the thread blocked).
    pub vcsw: u64,
    /// Involuntary context switches inside the batch (it was preempted).
    pub ivcsw: u64,
    /// Major page faults inside the batch (a file page read from disk).
    pub majflt: u64,
    /// The QMDB read view's lock waits inside the batch.
    pub view: n42_qmdb_reth::ViewLockWaits,
    /// The live-index hand-over's lock counts inside the batch.
    pub live: crate::output_shards::LiveLockCounts,
    /// The batch's open of its view of the parent, microseconds.
    pub open_us: u64,
}

impl BatchSpan {
    pub(crate) fn close(start_us: u64, mark: ThreadMark, txs: usize, batches_at: std::time::Instant) -> Self {
        let now = ThreadMark::now();
        Self {
            start_us,
            end_us: batches_at.elapsed().as_micros() as u64,
            cpu_us: now.cpu_ns.saturating_sub(mark.cpu_ns) / 1000,
            txs,
            thread: rayon::current_thread_index().unwrap_or(usize::MAX),
            minflt: now.minflt.saturating_sub(mark.minflt),
            vcsw: now.nvcsw.saturating_sub(mark.nvcsw),
            ivcsw: now.nivcsw.saturating_sub(mark.nivcsw),
            majflt: now.majflt.saturating_sub(mark.majflt),
            view: now.view.since(mark.view),
            live: now.live.since(mark.live),
            open_us: 0,
        }
    }

    /// The span with its open's time set.
    pub(crate) fn with_open_us(mut self, open_us: u64) -> Self {
        self.open_us = open_us;
        self
    }
}

/// The batches' spans summed up for the phases line (milliseconds unless
/// named otherwise).
#[derive(Debug, Clone, Copy, Default)]
pub struct BatchSpans {
    /// The longest batch, start to end.
    pub max_ms: u64,
    /// The shortest.
    pub min_ms: u64,
    /// The median.
    pub median_ms: u64,
    /// The CPU time of the longest batch.
    pub cpu_max_ms: u64,
    /// The most transactions in a batch.
    pub txs_max: usize,
    /// The fewest.
    pub txs_min: usize,
    /// The last batch's start less the first's.
    pub start_skew_ms: u64,
    /// The batches' start to the first batch's start, plus the last batch's
    /// end to the batches' end.
    pub wait_ms: u64,
    /// How many batches ran.
    pub batches: usize,
    /// How many distinct pool threads ran them.
    pub threads: usize,
    /// The first batch's start, microseconds after the batches' start (the
    /// hand-over to the pool).
    pub first_start_us: u64,
    /// The last batch's start, microseconds after the batches' start.
    pub last_start_us: u64,
    /// The last batch's end, microseconds after the batches' start.
    pub last_end_us: u64,
    /// The dispatch: microseconds after the batches' start by which every
    /// thread that ran a batch had started its first one. With at most one
    /// batch a thread (`N42_BUILD_ONE_WAVE=1`) this equals `last_start_us`;
    /// with two waves, `last_start_us` less this is the first wave's length.
    pub dispatch_us: u64,
    /// Every batch's wall time summed, microseconds.
    pub wall_sum_us: u64,
    /// Every batch's thread CPU time summed, microseconds: `wall_sum_us` less
    /// this is the batches' time off the CPU.
    pub cpu_sum_us: u64,
    /// Minor page faults inside the batches, summed.
    pub minflt: u64,
    /// Voluntary context switches inside the batches, summed.
    pub vcsw: u64,
    /// Involuntary context switches inside the batches, summed.
    pub ivcsw: u64,
    /// Major page faults inside the batches, summed.
    pub majflt: u64,
    /// Reads that waited for a QMDB read-view reader slot (a publish), summed.
    pub view_slot_waits: u64,
    /// Microseconds those reads waited.
    pub view_slot_wait_us: u64,
    /// Reads that waited for a QMDB offset-index shard (an advance's writes).
    pub view_index_waits: u64,
    /// Microseconds those reads waited.
    pub view_index_wait_us: u64,
    /// Live-index shard locks the hand-overs blocked on.
    pub live_lock_waits: u64,
    /// Microseconds blocked on them.
    pub live_lock_wait_us: u64,
    /// Microseconds the hand-overs held shard locks.
    pub live_lock_hold_us: u64,
    /// Shards the hand-overs left to the freeze (`N42_LIVE_INDEX_DEFER=1`).
    pub live_deferred: u64,
    /// The batches' opens of the parent's view, microseconds summed.
    pub open_sum_us: u64,
    /// The longest of them.
    pub open_max_us: u64,
}

impl BatchSpans {
    /// `spans` over batches that took `total_us` from start to end.
    pub fn of(spans: &mut [BatchSpan], total_us: u64) -> Self {
        if spans.is_empty() {
            return Self::default();
        }
        let wall = |s: &BatchSpan| s.end_us.saturating_sub(s.start_us);
        let slowest = spans.iter().copied().max_by_key(wall).unwrap_or_default();
        let first_start = spans.iter().map(|s| s.start_us).min().unwrap_or(0);
        let last_start = spans.iter().map(|s| s.start_us).max().unwrap_or(0);
        let last_end = spans.iter().map(|s| s.end_us).max().unwrap_or(0);
        // Each thread's first start; the latest of those is when the last
        // thread got going.
        let mut first_by_thread: Vec<(usize, u64)> = Vec::with_capacity(spans.len());
        for span in spans.iter() {
            match first_by_thread.iter_mut().find(|(thread, _)| *thread == span.thread) {
                Some((_, first)) => *first = (*first).min(span.start_us),
                None => first_by_thread.push((span.thread, span.start_us)),
            }
        }
        let dispatch_us = first_by_thread.iter().map(|(_, first)| *first).max().unwrap_or(0);
        let (batches, threads) = (spans.len(), first_by_thread.len());
        let wall_sum_us = spans.iter().map(wall).sum();
        let cpu_sum_us = spans.iter().map(|s| s.cpu_us).sum();
        let minflt = spans.iter().map(|s| s.minflt).sum();
        let vcsw = spans.iter().map(|s| s.vcsw).sum();
        let ivcsw = spans.iter().map(|s| s.ivcsw).sum();
        let sum = |f: &dyn Fn(&BatchSpan) -> u64| spans.iter().map(f).sum::<u64>();
        let majflt = sum(&|s| s.majflt);
        let view_slot_waits = sum(&|s| s.view.slot_waits);
        let view_slot_wait_us = sum(&|s| s.view.slot_wait_ns) / 1000;
        let view_index_waits = sum(&|s| s.view.index_waits);
        let view_index_wait_us = sum(&|s| s.view.index_wait_ns) / 1000;
        let live_lock_waits = sum(&|s| s.live.waits);
        let live_lock_wait_us = sum(&|s| s.live.wait_ns) / 1000;
        let live_lock_hold_us = sum(&|s| s.live.hold_ns) / 1000;
        let live_deferred = sum(&|s| s.live.deferred);
        let open_sum_us = sum(&|s| s.open_us);
        let open_max_us = spans.iter().map(|s| s.open_us).max().unwrap_or(0);
        spans.sort_unstable_by_key(wall);
        Self {
            wall_sum_us,
            cpu_sum_us,
            minflt,
            vcsw,
            ivcsw,
            majflt,
            view_slot_waits,
            view_slot_wait_us,
            view_index_waits,
            view_index_wait_us,
            live_lock_waits,
            live_lock_wait_us,
            live_lock_hold_us,
            live_deferred,
            open_sum_us,
            open_max_us,
            batches,
            threads,
            first_start_us: first_start,
            last_start_us: last_start,
            last_end_us: last_end,
            dispatch_us,
            max_ms: wall(&slowest) / 1000,
            min_ms: wall(&spans[0]) / 1000,
            median_ms: wall(&spans[spans.len() / 2]) / 1000,
            cpu_max_ms: slowest.cpu_us / 1000,
            txs_max: spans.iter().map(|s| s.txs).max().unwrap_or(0),
            txs_min: spans.iter().map(|s| s.txs).min().unwrap_or(0),
            start_skew_ms: last_start.saturating_sub(first_start) / 1000,
            wait_ms: (first_start + total_us.saturating_sub(last_end)) / 1000,
        }
    }
}

/// `N42_PHASE_TIMERS=1`: the build's batch loop ([`execute_for_build`]) by
/// section, nanoseconds of pool time summed over every batch. The per-
/// transaction sections are sampled (one transaction in
/// [`LOOP_SAMPLE_STRIDE`], scaled to the batch's count, as
/// [`crate::fast_transfer::TransferTimers`] does); the per-batch ones are
/// measured on every batch.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopTimers {
    /// Transactions the loop executed (the scale's denominator).
    pub txs: u64,
    /// Getting the transaction's EVM environment (`convert`: on the builder,
    /// the `TxEnv` read off the pooled transaction by reference).
    pub fetch_ns: u64,
    /// Pre-checks in the loop outside `transfer` (none today: `transfer`
    /// makes every check itself).
    pub check_ns: u64,
    /// The `transfer` call as a whole (its own timers split it).
    pub transfer_ns: u64,
    /// A receipt built in the loop (none today: the receipts are built after
    /// the execution, `direct_receipts`).
    pub receipt_ns: u64,
    /// The transfer's accounts committed into the batch's `State` (its cache
    /// and transition map).
    pub sink_ns: u64,
    /// The transfer's gas read off its result.
    pub gas_ns: u64,
    /// The rest: the result placed in its slot, the loop's own control.
    pub other_ns: u64,
    /// Per batch, before its loop: the parent's view opened, the `State`
    /// and the EVM built.
    pub batch_setup_ns: u64,
    /// Per batch, after its loop: the transitions merged, the bundle taken
    /// and handed to the sink.
    pub batch_close_ns: u64,
}

/// One transaction of the batch loop timed in this many, per batch (a prime,
/// so it does not ride [`crate::fast_transfer`]'s own stride of 64).
pub const LOOP_SAMPLE_STRIDE: u64 = 61;

impl LoopTimers {
    /// Adds `other` into `self`.
    pub fn add(&mut self, other: Self) {
        self.txs += other.txs;
        self.fetch_ns += other.fetch_ns;
        self.check_ns += other.check_ns;
        self.transfer_ns += other.transfer_ns;
        self.receipt_ns += other.receipt_ns;
        self.sink_ns += other.sink_ns;
        self.gas_ns += other.gas_ns;
        self.other_ns += other.other_ns;
        self.batch_setup_ns += other.batch_setup_ns;
        self.batch_close_ns += other.batch_close_ns;
    }

    /// `ns` of pool time as nanoseconds a transaction.
    pub fn per_tx(&self, ns: u64) -> u64 {
        ns.checked_div(self.txs).unwrap_or(0)
    }
}

/// One batch's [`LoopTimers`] while it runs: sampled sums and their counts.
#[derive(Debug, Default)]
pub(crate) struct LoopSampler {
    on: bool,
    calls: u64,
    samples: u64,
    sums: [u64; 7],
}

impl LoopSampler {
    fn new() -> Self {
        Self { on: crate::fast_transfer::phase_timers(), ..Default::default() }
    }

    /// Whether the transaction about to run is timed.
    #[inline]
    fn begin(&mut self) -> bool {
        if !self.on {
            return false;
        }
        self.calls += 1;
        // Mid-stride, not the first: a batch's first transaction is its
        // coldest, and sampling it weighs it once in a stride instead of
        // once in the batch.
        self.calls % LOOP_SAMPLE_STRIDE == LOOP_SAMPLE_STRIDE / 2
    }

    /// A timed transaction's checkpoints: fetch, check, transfer, receipt,
    /// gas, sink, other (in the order the loop passes them).
    #[inline]
    fn record(&mut self, marks: &[std::time::Instant; 8]) {
        for (k, sum) in self.sums.iter_mut().enumerate() {
            *sum += marks[k + 1].saturating_duration_since(marks[k]).as_nanos() as u64;
        }
        self.samples += 1;
    }

    fn finish(self, setup_ns: u64, close_ns: u64) -> LoopTimers {
        if !self.on {
            return LoopTimers::default();
        }
        let scale = |ns: u64| if self.samples == 0 { 0 } else { (ns as u128 * self.calls as u128 / self.samples as u128) as u64 };
        LoopTimers {
            txs: self.calls,
            fetch_ns: scale(self.sums[0]),
            check_ns: scale(self.sums[1]),
            transfer_ns: scale(self.sums[2]),
            receipt_ns: scale(self.sums[3]),
            gas_ns: scale(self.sums[4]),
            sink_ns: scale(self.sums[5]),
            other_ns: scale(self.sums[6]),
            batch_setup_ns: setup_ns,
            batch_close_ns: close_ns,
        }
    }
}

/// Why the parallel path did not run; the caller executes serially.
#[derive(Debug)]
pub enum NotParallel {
    /// A transaction the transfer path does not take (index).
    NotATransfer(usize),
    /// A transfer to or from the block's beneficiary (index).
    TouchesBeneficiary(usize),
    /// A transfer failed on the path (index, message): the serial executor
    /// produces the exact error.
    Failed(usize, String),
    /// The parent's state could not be opened for a group.
    NoState,
}

impl std::fmt::Display for NotParallel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATransfer(i) => write!(f, "transaction {i} is not a plain transfer"),
            Self::TouchesBeneficiary(i) => write!(f, "transaction {i} touches the beneficiary"),
            Self::Failed(i, m) => write!(f, "transaction {i} failed on the transfer path: {m}"),
            Self::NoState => write!(f, "the parent's state could not be opened"),
        }
    }
}

/// Disjoint-set forest over the accounts a block touches.
pub(crate) struct Groups {
    parent: Vec<usize>,
}

impl Groups {
    fn with_capacity(n: usize) -> Self {
        Self { parent: Vec::with_capacity(n) }
    }
    /// A party of its own, returned as its index. The forest grows with the
    /// map of addresses rather than after it, so the partition needs no
    /// second pass over the block to union what the first pass already saw.
    fn add(&mut self) -> usize {
        let next = self.parent.len();
        self.parent.push(next);
        next
    }
    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.parent[a] = b;
        }
    }
}

/// Whether `N42_FOLLOWER_PARTITION_HASH=1` is set: the follower's partition
/// finds the addresses a block repeats on the worker pool
/// ([`partition_shared`]) instead of probing one map per transaction.
///
/// Off by default until a leg reads it: the partition is 31-33 ms of a
/// four-node follower's 131-136 ms execution (loop202) and the bench says
/// this halves it, but loop91 is the warning -- a partition made 20 ms
/// cheaper by grouping differently gave every millisecond back in the
/// batches. This one returns the same groups, so there is nothing to give
/// back, which is exactly what a leg has to confirm.
pub fn partition_hash() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_PARTITION_HASH", false))
}

/// A 64-bit hash of an address, for [`partition_shared`]'s duplicate search.
/// The address's own bytes are already a hash; the multiply is there so that
/// two accounts differing only in their low bytes -- which the flood's
/// recipients do -- do not collide.
#[inline]
pub(crate) fn address_hash(address: &Address) -> u64 {
    let mut low = [0u8; 8];
    low.copy_from_slice(&address.0[12..]);
    let mut high = [0u8; 8];
    high.copy_from_slice(&address.0[4..12]);
    let a = u64::from_le_bytes(low).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let b = u64::from_le_bytes(high).wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    let mut h = a ^ b.rotate_left(31) ^ u64::from(u32::from_le_bytes([address.0[0], address.0[1], address.0[2], address.0[3]]));
    h ^= h >> 29;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^ (h >> 32)
}

/// Groups candidate transfers by sender: every sender's transfers, in
/// candidate order, form one group. `keys` is each candidate's (sender,
/// recipient). Recipients do not join groups -- a transfer only adds to its
/// recipient's balance, and additions commute, so [`graft_bundles`] can fold
/// batches that share a recipient in any order. (Grouping by connected
/// component, as the follower's [`partition`] does, merges a full block of
/// random transfers into a handful of giant groups: round 43.)
///
/// Returns `Err` when a candidate touches the beneficiary.
pub fn partition_by_sender(keys: &[(Address, Address)], beneficiary: Address) -> Result<Vec<Vec<usize>>, NotParallel> {
    let mut group_of: alloy_primitives::map::AddressHashMap<usize> = alloy_primitives::map::AddressHashMap::default();
    group_of.reserve(keys.len() / 8);
    let mut groups: Vec<Vec<usize>> = Vec::new();
    // A frame build's candidates come in sender runs (a frame's run of one
    // sender at consecutive nonces, `n42_tx_queue` `SenderRun`): a candidate
    // whose sender is the one before's joins that group without the map's
    // probe -- one comparison a transfer instead of one hash, the same
    // groups (step 7a: the partition was a hash a transaction).
    let mut last: Option<(Address, usize)> = None;
    for (i, (sender, to)) in keys.iter().enumerate() {
        if *sender == beneficiary || *to == beneficiary {
            return Err(NotParallel::TouchesBeneficiary(i));
        }
        let g = match last {
            Some((prev, g)) if prev == *sender => g,
            _ => {
                let next = groups.len();
                let g = *group_of.entry(*sender).or_insert(next);
                if g == next {
                    groups.push(Vec::new());
                }
                last = Some((*sender, g));
                g
            }
        };
        groups[g].push(i);
    }
    Ok(groups)
}

/// The worker pool the build's batches run on: its own, so that they do not
/// queue behind the global pool's other jobs (the QMDB root of the block
/// before, a follower import). `N42_PARALLEL_BUILD_THREADS` threads, 16 by
/// default. Under `N42_CORE_LAYOUT=isolate` each thread pins itself to the
/// layout's build set (`n42_core_layout`).
///
/// Built once, lazily, on the first build. A pool that cannot be built at
/// its size (EAGAIN under thread or memory pressure) is retried at half the
/// threads down to one, with an error logged, rather than panicking the
/// build; only a box that cannot spawn a single thread still panics here
/// (every caller takes a `&'static` pool, so there is no `Err` to return).
///
/// There is no inline fallback for that last case: rayon has no pool of
/// zero threads, and `ThreadPoolBuilder::use_current_thread` would make the
/// first caller's thread the pool's only worker, so an `install` from any
/// other thread (the follower's import, the behind pool's users) would wait
/// on a worker that is not in the pool -- a hang in place of the panic.
/// Running the callers' work inline instead means a non-`&'static` return
/// type at every call site, on the leader's build path.
pub fn build_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let wanted: usize = std::env::var("N42_PARALLEL_BUILD_THREADS").ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(16);
        let build = |threads: usize| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .thread_name(|i| format!("n42-build-{i}"))
                .start_handler(|_| n42_core_layout::enter(n42_core_layout::Set::Build))
                .build()
        };
        let mut threads = wanted;
        loop {
            match build(threads) {
                Ok(pool) => break pool,
                Err(err) if threads > 1 => {
                    tracing::error!(target: "payload_builder", %err, threads, wanted, "the build pool could not be built; retrying with half the threads");
                    threads /= 2;
                }
                Err(err) => panic!("no thread pool for the parallel build, not even one thread: {err}"),
            }
        }
    })
}

/// `N42_FREEZE_POOL=own` (`docs/SHARED_EXECUTION_SCOPE.md` 16.2): the work
/// behind the seal -- the output shards' freeze (its tasks and the frees it
/// spawns), the receipts from the slots and the slots' free -- runs on a
/// small pool of its own ([`behind_pool`]) instead of the build pool, so a
/// latency-critical pass of the build never finishes behind one of its long
/// tasks (a rayon worker waiting in a join takes any job it finds). Off by
/// default: everything stays on [`build_pool`].
pub fn freeze_pool_own() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FREEZE_POOL").is_ok_and(|v| v.trim() == "own"))
}

/// The pool the work behind the seal runs on: with `N42_FREEZE_POOL=own` a
/// pool of `N42_FREEZE_POOL_THREADS` threads (16 by default, `n42-behind-*`,
/// in the layout's build set as the build pool's are, or the set
/// `N42_CORE_LAYOUT_BEHIND` names), else [`build_pool`].
/// A pool that cannot be built falls back to [`build_pool`].
pub fn behind_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
    if !freeze_pool_own() {
        return build_pool();
    }
    let own = POOL.get_or_init(|| {
        let threads =
            std::env::var("N42_FREEZE_POOL_THREADS").ok().and_then(|v| v.trim().parse().ok()).filter(|n| *n > 0).unwrap_or(16);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("n42-behind-{i}"))
            // The build set unless `N42_CORE_LAYOUT_BEHIND` places it elsewhere.
            .start_handler(|_| n42_core_layout::enter(n42_core_layout::Set::Behind))
            .build()
            .inspect_err(|err| tracing::warn!(target: "payload_builder", %err, "no pool of its own for the freeze; the build pool takes it"))
            .ok()
    });
    own.as_ref().unwrap_or_else(|| build_pool())
}

/// The pool the plan-ahead body is made on (`N42_PLAN_AHEAD_BODY=1`): its own
/// `N42_PLAN_AHEAD_BODY_THREADS` threads (8 by default, `n42-plan-body-*`),
/// so the next block's preparation does not take the build pool's workers
/// from the block executing on them. Falls back to the build pool.
pub fn plan_body_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
    let own = POOL.get_or_init(|| {
        let threads =
            std::env::var("N42_PLAN_AHEAD_BODY_THREADS").ok().and_then(|v| v.trim().parse().ok()).filter(|n| *n > 0).unwrap_or(8);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("n42-plan-body-{i}"))
            .build()
            .inspect_err(|err| tracing::warn!(target: "payload_builder", %err, "no pool for the plan-ahead body; the build pool makes it"))
            .ok()
    });
    own.as_ref().unwrap_or_else(|| build_pool())
}

/// Whether the leader's parallel build reads the block's accounts ahead of
/// its execution (`N42_BUILD_PREFETCH=1`, [`WarmAccounts`]): each batch the
/// puller hands over is read on the worker pool while the pull and the prep
/// run, and the execution's batches read those accounts from memory rather
/// than through the parent's state provider. Off by default until a leg says
/// the execution falls by more than the pool time it costs.
pub fn build_prefetch() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_PREFETCH").is_ok_and(|v| v == "1"))
}

/// The lookahead distance cap of [`build_mlp`]: a batch's ring of converted
/// transactions is `k + 1` entries, kept small.
pub(crate) const BUILD_MLP_MAX: usize = 256;

/// `usize::MAX`: [`build_mlp`] reads the environment; anything else is a
/// distance set by [`set_build_mlp`].
pub(crate) static BUILD_MLP_SET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Memory-level parallelism inside the leader's build batches
/// (`N42_BUILD_MLP=<k>`, 0 or unset = off): before a batch runs transaction
/// `i` it converts the transaction `k` places ahead in the batch's order
/// (its pooled transaction's memory read then, the environment kept in a
/// ring of `k + 1`), and issues prefetch hints for that transaction's result
/// slot and for its sender's and recipient's entries in the batch's own
/// account map ([`crate::batch_state::BatchState::prefetch_account`]). The
/// hints change no result: the conversion is pure and the probes read only.
/// Capped at 256.
pub fn build_mlp() -> usize {
    static ENV: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    match BUILD_MLP_SET.load(std::sync::atomic::Ordering::Relaxed) {
        usize::MAX => *ENV.get_or_init(|| {
            n42_env::parse::<usize>("N42_BUILD_MLP", 0).min(BUILD_MLP_MAX)
        }),
        k => k,
    }
}

/// Tests and benches: [`build_mlp`] answers `k` (capped) from now on;
/// `None` returns it to the environment's value.
#[doc(hidden)]
pub fn set_build_mlp(k: Option<usize>) {
    BUILD_MLP_SET.store(k.map_or(usize::MAX, |k| k.min(BUILD_MLP_MAX)), std::sync::atomic::Ordering::Relaxed);
}

/// A prefetch hint for the cache line at `p` into every level (`T0`): no
/// load is made architecturally, so the pointer need not be valid. A no-op
/// off x86_64.
#[inline(always)]
pub fn prefetch_hint<T>(p: *const T) {
    #[cfg(target_arch = "x86_64")]
    #[allow(unused_unsafe)]
    // SAFETY: `prefetcht0` is a hint: it never faults and never reads
    // architecturally, whatever the address; SSE is baseline on x86_64.
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(p.cast::<i8>());
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = p;
}

/// Shards of [`WarmAccounts`]: enough that the pool's prefetch jobs seldom
/// meet on one lock, few enough that each job takes every lock once.
pub(crate) const WARM_SHARDS: usize = 64;

/// The shard an address lands in: a multiplicative hash of all twenty
/// bytes. Not the first byte alone: the flood's recipients
/// (`tx_flood::recipient`) carry a slot under 2^20 big-endian in their first
/// four bytes, so their first byte is 0 and every one of them landed in
/// shard 0 (loop351 stage ay: one thread read ~147,000 recipients while 63
/// shards held a few hundred senders).
#[inline]
pub(crate) fn warm_shard(address: &Address) -> usize {
    let b = &address.0;
    let lo = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let mid = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    let hi = u32::from_le_bytes([b[16], b[17], b[18], b[19]]) as u64;
    let x = (lo ^ mid.rotate_left(21) ^ hi.rotate_left(42)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (x >> 58) as usize % WARM_SHARDS
}

/// Whether the leader's parallel build resolves the block's accounts once,
/// before its batches run, into a read-only [`ReadSet`] they read instead of
/// the parent's state (`N42_READ_SET=1`, `docs/BREAKTHROUGH_DESIGN.md`
/// section 4, design A). Off by default.
pub fn read_set() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_READ_SET").is_ok_and(|v| v == "1"))
}

/// What building a [`ReadSet`] cost and held.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadSetPass {
    /// The pass's wall time: the addresses gathered, sorted and deduplicated,
    /// each resolved once, and the directory built. Microseconds.
    pub wall_us: u64,
    /// Of `wall_us`: gathering, sorting and deduplicating the addresses.
    pub dedup_us: u64,
    /// Of `wall_us`: resolving them through the parent's state.
    pub resolve_us: u64,
    /// Distinct accounts in the set.
    pub accounts: usize,
    /// Of those, accounts the parent's state failed to answer (or no state
    /// could be opened for): left to the batches' own reads.
    pub unresolved: usize,
    /// `N42_PHASE_TIMERS=1`: the pass's reads by door (see
    /// [`crate::fast_transfer::TransferTimers`]); zero otherwise.
    pub reads_provider: u64,
    /// See `reads_provider`.
    pub reads_view: u64,
}

/// A batch database's hint path (`N42_BUILD_MLP`): `address` will be read
/// soon, so each layer probes for it -- the probe is the prefetch -- and, if
/// it does not hold it, passes the hint beneath; the parent's state provider
/// walks its own layers the same way
/// (`AccountReader::n42_prefetch_account`). Nothing is materialised, no
/// answer or counter changes, no lock is waited on. Returns whether a layer
/// held the account. The default does nothing.
pub trait AccountHint {
    /// See the trait.
    fn hint_account(&self, _address: &Address) -> bool {
        false
    }
}

/// Whole groups packed into at most `2 x workers` batches of about equal
/// size (a couple of thousand transfers each), in group order: what one
/// worker executes on one view of the parent's state.
pub fn batch_groups(groups: &[Vec<usize>], total: usize, workers: usize) -> Vec<Vec<&Vec<usize>>> {
    let wanted = (total / 2048).clamp(1, workers.max(1) * 2);
    let per_batch = total.div_ceil(wanted).max(1);
    let mut batches: Vec<Vec<&Vec<usize>>> = Vec::with_capacity(wanted + 1);
    let mut current: Vec<&Vec<usize>> = Vec::new();
    let mut filled = 0usize;
    for group in groups {
        current.push(group);
        filled += group.len();
        if filled >= per_batch {
            batches.push(std::mem::take(&mut current));
            filled = 0;
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// `N42_BUILD_ONE_WAVE=1`: the build's batches are one per pool thread at
/// most ([`batch_groups_one_wave`]) and handed to the pool all at once
/// ([`execute_for_build`]'s spawn per batch), instead of up to two a thread
/// split recursively. With two a thread the second wave starts only when a
/// first-wave batch ends: on loop334 (200,000 transfers, 400 sender runs of
/// 500, 32 threads, 58 batches) `batch_start_skew_ms` tracked
/// `batch_median_ms` + 2-3 ms (correlation 0.96), and the execution was two
/// batches long. Batches are still whole sender groups in candidate order,
/// as with a pool of a different size; the block's state, receipts and gas
/// are the same either way. Off by default.
pub fn build_one_wave() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_ONE_WAVE").is_ok_and(|v| v == "1"))
}

/// `N42_BUILD_BATCHES=<n>` (`docs/SHARED_EXECUTION_SCOPE.md` 16.4 item 4):
/// the build's transfers in `n` batches of about equal size (whole sender
/// groups in candidate order, [`batch_groups_one_wave`] with `n`), handed to
/// the pool largest first (FIFO, so the workers take them in that order):
/// with 96-128 batches on 32 workers no worker starts a second batch behind a
/// long one, and the execution ends within one small batch of its CPU floor.
/// 0 (the default) keeps the dispatch `N42_BUILD_ONE_WAVE` chooses. Each batch
/// opens its own view of the parent, so more batches cost more opens.
pub fn build_batches() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| n42_env::parse("N42_BUILD_BATCHES", 0))
}

/// How a build's batches are made and handed to the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Up to two batches a worker ([`batch_groups`]), split in halves by
    /// rayon (the default).
    Halves,
    /// One batch a worker at most ([`batch_groups_one_wave`]), all spawned
    /// at once (`N42_BUILD_ONE_WAVE=1`).
    OneWave,
    /// `n` batches, spawned largest first (`N42_BUILD_BATCHES=<n>`).
    LargestFirst(usize),
}

impl Dispatch {
    /// The dispatch the environment asks for.
    pub fn from_env() -> Self {
        match build_batches() {
            0 if build_one_wave() => Self::OneWave,
            0 => Self::Halves,
            n => Self::LargestFirst(n),
        }
    }

    fn from_one_wave(one_wave: bool) -> Self {
        if one_wave { Self::OneWave } else { Self::Halves }
    }
}

/// The order [`Dispatch::LargestFirst`] hands batches to the pool in: by
/// transfers, largest first, ties in batch order (longest processing time
/// first).
pub fn largest_first(sizes: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by(|a, b| sizes[*b].cmp(&sizes[*a]).then(a.cmp(b)));
    order
}

/// Whole groups packed into at most `workers` batches, in group order, each
/// ending at the first group that takes the running count past its share
/// (`k x total / batches`): every batch holds about `total / workers`
/// transfers, at most one group more. Fewer batches than `workers` when
/// there are fewer groups.
pub fn batch_groups_one_wave(groups: &[Vec<usize>], total: usize, workers: usize) -> Vec<Vec<&Vec<usize>>> {
    let wanted = workers.max(1).min(groups.len().max(1));
    let mut batches: Vec<Vec<&Vec<usize>>> = Vec::with_capacity(wanted);
    let mut current: Vec<&Vec<usize>> = Vec::new();
    let mut filled = 0usize;
    let mut boundary = 1usize;
    for group in groups {
        current.push(group);
        filled += group.len();
        // The k-th batch closes once the running count reaches k / wanted of
        // the total (integer arithmetic, rounded up, so no empty batch).
        if boundary < wanted && filled.saturating_mul(wanted) >= boundary.saturating_mul(total) {
            batches.push(std::mem::take(&mut current));
            while boundary < wanted && filled.saturating_mul(wanted) >= boundary.saturating_mul(total) {
                boundary += 1;
            }
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// A running sum a parallel `unzip` fills beside a collect, in the same
/// pass: the block's gas (and, with [`FeeSum`], its fees) read from the
/// slot or the transaction already in hand for the other side.
#[derive(Debug, Default, Clone, Copy)]
pub struct GasSum(pub u64);

impl rayon::iter::ParallelExtend<u64> for GasSum {
    fn par_extend<I>(&mut self, iter: I)
    where
        I: rayon::iter::IntoParallelIterator<Item = u64>,
    {
        use rayon::prelude::*;
        self.0 += iter.into_par_iter().sum::<u64>();
    }
}

/// The fees' counterpart of [`GasSum`].
#[derive(Debug, Default, Clone, Copy)]
pub struct FeeSum(pub U256);

impl rayon::iter::ParallelExtend<U256> for FeeSum {
    fn par_extend<I>(&mut self, iter: I)
    where
        I: rayon::iter::IntoParallelIterator<Item = U256>,
    {
        use rayon::prelude::*;
        self.0 += iter.into_par_iter().reduce(|| U256::ZERO, |a, b| a + b);
    }
}

/// What every batch counts as it executes ([`BuildRun::counters`]): the
/// transfers it executed, their gas, and -- when the caller handed a
/// candidate's tip per gas ([`execute_for_build_counted`]) -- their fees,
/// `tip x gas_used` summed exactly as [`fees_from_tips`] sums it over the
/// slots. The tip is read on the batch's thread, beside the conversion that
/// just read the same candidate. The same numbers a pass over the filled slots gives
/// ([`slot_refs_and_gas`]), read off the batches instead.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunCounters {
    /// Transfers executed (filled slots).
    pub executed: usize,
    /// Their gas used, summed.
    pub gas: u64,
    /// Their fees at the tips handed in; `None` without tips.
    pub fees: Option<U256>,
}

impl RunCounters {
    fn add(&mut self, batch: Self) {
        self.executed += batch.executed;
        self.gas += batch.gas;
        self.fees = match (self.fees, batch.fees) {
            (Some(a), Some(b)) => Some(a + b),
            _ => None,
        };
    }
}

/// Whether the builder leaves the executed transfers in their slots
/// (`N42_BUILD_COLLECT_IN_PLACE=1`) instead of moving them into one vector
/// before the receipts and the body are built from them.
///
/// The collect is one serial move of every transfer -- the transaction, its
/// result, ~470 bytes each, 77 MB for a 163,000-transfer block -- and it was
/// 18 ms of the leader's build on the four-node fleet (loop214-218,
/// `par_collect_ms`). In place, the order is a vector of references built by
/// one pass over the slots, and the block's body and receipts are made from
/// those on the worker pool, where the move was going to happen anyway. Off
/// by default until a four-node leg measures it.
pub fn build_collect_in_place() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_BUILD_COLLECT_IN_PLACE", false))
}

/// Whether `N42_GRAFT_SHARDED=1` is set: the in-place fold's insert
/// ([`graft_bundles_direct`]) runs sharded by address on the build pool
/// ([`graft_insert_sharded`]) -- plan v6 attempt G proper. The block it
/// leaves is the serial insert's, map for map and revert for revert in the
/// same order (`the_sharded_graft_equals_the_direct_one`). Off by default.
pub fn graft_sharded() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_GRAFT_SHARDED").is_ok_and(|v| v == "1"))
}

/// Below this many accounts left to insert the sharded insert is not worth
/// its jobs: a block of a few thousand transfers inserts in well under a ms.
pub(crate) const GRAFT_SHARDED_MIN: usize = 8_192;

/// Shards of the sharded insert: a power of two, twice the build pool's
/// default sixteen threads so one slow shard does not hold the rest.
pub(crate) const GRAFT_SHARDS: usize = 32;

pub(crate) fn graft_shard_of(address: &Address) -> usize {
    address.0[0] as usize & (GRAFT_SHARDS - 1)
}

/// How the batches' bundles become the block's one bundle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GraftFold {
    /// [`graft_bundles_with`]: bundle after bundle, account after account,
    /// each one probed in the block's map and written where its hash puts it.
    /// A full block's map is ~50 MB, so every account is two probes and a
    /// write into a line nothing has touched: 56-64 ms of the leader's build
    /// (loop214, `par_fold_ms` less `par_commit_ms`), and no thread count
    /// moves it because it is memory latency, not work.
    #[default]
    Direct,
    /// [`graft_bundles_indexed`]: every batch's accounts are listed once with
    /// the bucket the block's map will put each of them in, the list is
    /// sorted on the worker pool, and the merge walks it in that order -- so
    /// the writes into the block's map go region by region instead of all
    /// over it, and an account two batches touched is its own neighbour in
    /// the list rather than a probe that finds it.
    Indexed,
    /// [`graft_bundles_indexed`] with the merge pass split over ranges of
    /// that same order and run on the worker pool. The sharded graft's lock
    /// traffic is not here: a range shares no structure with the others, it
    /// folds its own slice of every batch's bundle and the ranges' outputs
    /// are concatenated in order.
    IndexedRanges,
}

pub(crate) fn fold_from_env(index: &str, ranges: &str) -> GraftFold {
    if std::env::var(ranges).is_ok_and(|v| v == "1") {
        GraftFold::IndexedRanges
    } else if std::env::var(index).is_ok_and(|v| v == "1") {
        GraftFold::Indexed
    } else {
        GraftFold::Direct
    }
}

/// The fold the leader's build uses: `N42_GRAFT_INDEX=1` for
/// [`GraftFold::Indexed`], `N42_GRAFT_RANGES=1` for
/// [`GraftFold::IndexedRanges`] (which implies the index), neither for the
/// fold that is in place. Both off by default until a four-node leg says
/// `par_fold_ms` fell and the roots agree.
///
/// The bench does not say it will (`bench_build_run`, 162,000 transfers,
/// 16 threads pinned, three rounds each): into a freshly reserved map the
/// fold in place grafts in 42-45 ms, the index in 60-62 and the index over
/// ranges in 53-55; into memory mapped beside the execution
/// ([`GraftTarget`]) 26.5-27, 43 and 35.5-36. Writing the map in bucket
/// order saves less than listing, sorting and moving every account a second
/// time costs; what the graft was paying for was the page faults, and
/// those go for any order. Kept, switched off, for a leg on a loaded node,
/// where locality may be worth more than on an idle one.
pub fn build_graft_fold() -> GraftFold {
    static FOLD: std::sync::OnceLock<GraftFold> = std::sync::OnceLock::new();
    *FOLD.get_or_init(|| fold_from_env("N42_GRAFT_INDEX", "N42_GRAFT_RANGES"))
}

/// The same for a follower's import (`N42_FOLLOWER_GRAFT_INDEX`,
/// `N42_FOLLOWER_GRAFT_RANGES`), switched apart from the leader's: the two
/// sides of the graft have never wanted the same setting ([`graft_stream`]
/// against [`follower_graft_stream`]). It is read only where the follower
/// grafts the bundles after the execution -- with the streamed graft on,
/// which is the follower's default, the fold is [`StagedGraft`]'s.
pub fn follower_graft_fold() -> GraftFold {
    static FOLD: std::sync::OnceLock<GraftFold> = std::sync::OnceLock::new();
    *FOLD.get_or_init(|| fold_from_env("N42_FOLLOWER_GRAFT_INDEX", "N42_FOLLOWER_GRAFT_RANGES"))
}

/// Whether the leader's build maps the graft's memory beside the parallel
/// step (`N42_GRAFT_PREFAULT=1`, [`GraftTarget`]). Off by default until a
/// four-node leg says the execution beside it does not pay for it.
pub fn graft_prefault() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_GRAFT_PREFAULT").is_ok_and(|v| v == "1"))
}

/// The bucket count of a hash table that reports `capacity`: hashbrown puts
/// a key at `hash & (buckets - 1)` and a table of eight buckets or more
/// reports `buckets * 7 / 8`. It orders the fold's writes and nothing else,
/// so a wrong answer would cost locality, never correctness.
pub(crate) const fn destination_buckets(capacity: usize) -> u64 {
    if capacity == 0 {
        return 1;
    }
    (capacity.saturating_mul(8).saturating_add(6) / 7).next_power_of_two() as u64
}

/// Appends a graft's reverts to a taken bundle's revert set for the block
/// (the last one, which the state's merge created; a new one if the merge
/// found nothing to revert). An account the block touched again after the
/// graft (a later transaction's sender, a withdrawal's recipient) got a
/// second revert from the merge, back to the grafted value: that one is
/// dropped, since the block's revert is to the parent's value, which the
/// graft's carries -- and two entries for one account in a block's
/// changeset fail persistence's history index (round 43, `UnsortedInput`).
/// The set is sorted by address, as the merge leaves it.
pub fn append_reverts(bundle: &mut BundleState, reverts: Vec<(Address, AccountRevert)>) {
    if reverts.is_empty() {
        return;
    }
    // Sorted by address as revm's own merge leaves them; on the worker pool,
    // a block's 147,000 reverts being too many for one thread on the
    // follower's critical path.
    let mut reverts = reverts;
    sort_reverts(&mut reverts);
    append_sorted_reverts(bundle, reverts);
}

/// [`append_reverts`] for a set already sorted by address.
pub(crate) fn append_sorted_reverts(bundle: &mut BundleState, reverts: Vec<(Address, AccountRevert)>) {
    if reverts.is_empty() {
        return;
    }
    if bundle.reverts.is_empty() {
        bundle.reverts.push(Vec::new());
    }
    let last = bundle.reverts.len() - 1;
    let mut reverts = reverts;
    let merged = &mut bundle.reverts[last];
    if merged.is_empty() {
        // The block's merge had nothing of its own to revert: the graft's set
        // becomes the block's, moved rather than copied into it.
        *merged = reverts;
    } else {
        // The block's own reverts are a handful -- the beneficiary, the
        // withdrawals' recipients -- so each is looked up in the graft's
        // sorted set rather than the graft's 147,000 being put in a set of
        // their own (5-8 ms of a follower's import, loop174).
        let mut few: Vec<(Address, AccountRevert)> = std::mem::take(merged)
            .into_iter()
            .filter(|(address, _)| reverts.binary_search_by_key(address, |(address, _)| *address).is_err())
            .collect();
        few.sort_unstable_by_key(|(address, _)| *address);
        // Merged into the graft's set from the back: every entry of it moves
        // at most once, and no second buffer of 147,000 reverts is allocated.
        let (mut i, mut k) = (reverts.len(), reverts.len() + few.len());
        reverts.resize_with(k, Default::default);
        while let Some(entry) = few.pop() {
            while i > 0 && reverts[i - 1].0 > entry.0 {
                reverts.swap(k - 1, i - 1);
                i -= 1;
                k -= 1;
            }
            reverts[k - 1] = entry;
            k -= 1;
        }
        *merged = reverts;
    }
    bundle.reverts_size = bundle.reverts.iter().map(Vec::len).sum();
}

/// A graft's reverts being sorted by address on a thread of their own
/// ([`follower_merge_behind`]): a plain thread, not a rayon job, so that its
/// wait is never a worker's; its sort still runs on the worker pool. If no
/// thread can be had the set is sorted where it is collected.
#[derive(Debug)]
pub(crate) enum RevertsSort {
    /// On its thread; the answer is the sorted set and the sort's time.
    Thread(std::sync::mpsc::Receiver<(Vec<(Address, AccountRevert)>, u64)>),
    /// No thread: sorted in [`RevertsSort::finish`].
    Here(Vec<(Address, AccountRevert)>),
}

impl RevertsSort {
    fn start(reverts: Vec<(Address, AccountRevert)>) -> Self {
        let (to_sort, sorting) = std::sync::mpsc::channel::<Vec<(Address, AccountRevert)>>();
        let (sorted, answer) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new().name("graft-reverts".into()).spawn(move || {
            // Spawned from a build thread: off the build's cores.
            n42_core_layout::enter(n42_core_layout::Set::Background);
            if let Ok(mut reverts) = sorting.recv() {
                let at = std::time::Instant::now();
                sort_reverts_indexed(&mut reverts);
                let _ = sorted.send((reverts, at.elapsed().as_micros() as u64));
            }
        });
        match spawned {
            Ok(_) => match to_sort.send(reverts) {
                Ok(()) => Self::Thread(answer),
                Err(std::sync::mpsc::SendError(reverts)) => Self::Here(reverts),
            },
            Err(_) => Self::Here(reverts),
        }
    }

    fn finish(self) -> Result<(Vec<(Address, AccountRevert)>, u64), String> {
        match self {
            Self::Thread(answer) => answer.recv().map_err(|_| "the reverts' sort thread ended without an answer".to_string()),
            Self::Here(mut reverts) => {
                let at = std::time::Instant::now();
                sort_reverts_indexed(&mut reverts);
                Ok((reverts, at.elapsed().as_micros() as u64))
            }
        }
    }
}

/// [`sort_reverts`] by an index: the addresses and positions (24 bytes an
/// entry) are sorted on the worker pool and the reverts (~200 bytes an entry)
/// are then moved once each, along the permutation's cycles, instead of being
/// swapped at every level of the sort. The order is the same: a graft's set
/// holds each address once.
pub(crate) fn sort_reverts_indexed(reverts: &mut [(Address, AccountRevert)]) {
    if reverts.len() < 4096 || reverts.len() > u32::MAX as usize {
        sort_reverts(reverts);
        return;
    }
    use rayon::prelude::*;
    let mut order: Vec<(Address, u32)> =
        reverts.par_iter().enumerate().map(|(at, (address, _))| (*address, at as u32)).collect();
    order.par_sort_unstable_by_key(|(address, _)| *address);
    permute_reverts(reverts, order);
}

/// [`sort_reverts`] by an index ([`sort_reverts_indexed`]'s move along the
/// permutation), the index sorted by address and then position: the order
/// [`sort_reverts`] gives a set holding each address once, and a stable
/// sort's order for one that holds an address twice. For the output
/// shards' merged reverts (`output_shards.rs` `merged_reverts`), which the
/// whole-entry sort moved ~200 bytes at a time at every level.
pub(crate) fn sort_reverts_by_index(reverts: &mut [(Address, AccountRevert)]) {
    if reverts.len() < 4096 || reverts.len() > u32::MAX as usize {
        reverts.sort_by_key(|(address, _)| *address);
        return;
    }
    use rayon::prelude::*;
    let mut order: Vec<(Address, u32)> =
        reverts.par_iter().enumerate().map(|(at, (address, _))| (*address, at as u32)).collect();
    order.par_sort_unstable();
    permute_reverts(reverts, order);
}

/// `reverts` put in the order `order` names (`order[k].1`: the position
/// whose revert belongs at `k`), each moved along its cycle.
pub(crate) fn permute_reverts(reverts: &mut [(Address, AccountRevert)], order: Vec<(Address, u32)>) {
    // `source[k]`: the position whose revert belongs at `k`.
    let mut source: Vec<u32> = order.into_iter().map(|(_, at)| at).collect();
    for start in 0..source.len() {
        let mut at = start;
        loop {
            let from = source[at] as usize;
            source[at] = at as u32;
            if from == start {
                break;
            }
            reverts.swap(at, from);
            at = from;
        }
    }
}

/// By address, on the worker pool where there are enough of them to pay for it.
pub(crate) fn sort_reverts(reverts: &mut [(Address, AccountRevert)]) {
    if reverts.len() >= 4096 {
        use rayon::prelude::*;
        reverts.par_sort_unstable_by_key(|(address, _)| *address);
    } else {
        reverts.sort_unstable_by_key(|(address, _)| *address);
    }
}

/// Whether `N42_FOLLOWER_PARTITION_AHEAD=1` is set: the follower plans a
/// block's transfers ([`plan_transfers`]: the environments and the partition,
/// 19 ms of a 122 ms execution at 163,000 transfers, loop234) on the worker
/// pool as soon as the block's senders are known, beside the includability
/// check and the wait for the parent, instead of inside the execution gate.
pub fn follower_partition_ahead() -> bool {
    // A revm-era path: the evm2 follower import partitions inside its call.
    if !crate::legacy_paths::LEGACY_REVM_PATHS {
        return false;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_PARTITION_AHEAD", false))
}

/// Whether `N42_FOLLOWER_MERGE_BEHIND=1` is set: with the streamed graft, the
/// grafted reverts (one per account the block touched, ~147,000 at the bench
/// tier) are sorted on a thread of their own from the moment the batches end,
/// beside the block's own executor and the install of the staged accounts,
/// instead of after them. The next block reads only the merged account map
/// (its includability check and its overlay read `BundleState::state`), so
/// the map's install stays where it is; the reverts are read by no one before
/// the engine's insert, and their sort is what leaves the gated part.
pub fn follower_merge_behind() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_MERGE_BEHIND").is_ok_and(|v| v == "1"))
}

/// Whether `N42_FOLLOWER_SENDER_GROUPS=1` is set: the follower groups a
/// block's transfers by sender, as the builder does, instead of by connected
/// component. A block of random transfers is ~200 components with a few
/// giant ones (partition 35-43 ms, the largest group setting the wall time);
/// by sender it is ~400 groups packed into 2 x workers batches. A transfer
/// that only another sender's credit in the same block would fund is refused
/// by its batch's view and sends the block to the serial path, as any
/// refusal does -- correct, and rare outside adversarial blocks.
pub fn follower_sender_groups() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_SENDER_GROUPS").is_ok_and(|v| v == "1"))
}

/// Whether `N42_GRAFT_STREAM=1` is set: a builder folds each batch's bundle
/// into the block's graft as that batch finishes ([`StagedGraft`]) instead of
/// all of them after the execution.
///
/// Off, and measured so (loop176, three pairs): the leader's fold falls 73 ->
/// 43-49 ms but its parallel step rises 78-84 -> 143-159, because the fold is
/// memory bandwidth and page faults rather than work that can be scheduled --
/// on a node whose ingest and imports are already using that bandwidth there
/// is nothing for it to hide in, and overlapping it costs more than it saves.
/// The bench, on an idle box, reads the opposite (5 ms against 49), which is
/// what makes it worth keeping behind a flag.
pub fn graft_stream() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_GRAFT_STREAM").is_ok_and(|v| v == "1"))
}

/// Whether a follower's import folds its batches' bundles the same way
/// (`N42_FOLLOWER_GRAFT_STREAM=0` goes back to grafting them after the
/// execution). On: it is the side of the change that paid on the fleet, over
/// four pairs of legs and with no invalid block among them -- the import
/// 344-363 -> 330-355 ms (loop176) and 355-356 -> 331-337 (loop177), since
/// the merge it removes is larger than the execution it lengthens, and fewer
/// imports run past 600 ms. The import gates both the vote and the build
/// after a tenure change. The leader's side of it costs and stays off
/// ([`graft_stream`]).
pub fn follower_graft_stream() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_GRAFT_STREAM", true))
}

/// Whether the graft takes the largest bundle as the block's bundle (default;
/// `N42_GRAFT_BASE_SWAP=0` re-inserts every bundle, the behaviour before round
/// 43's loop98).
pub(crate) fn graft_base_swap() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_GRAFT_BASE_SWAP", true))
}

/// Whether `N42_FOLLOWER_FREE_ASYNC=1` is set: the executor's own working
/// memory -- the transactions' environments, the groups, the batches'
/// bundles -- is freed on the worker pool rather than on the thread that
/// executed the block.
///
/// Off by default: on an idle bench it is worth 5-6 ms of a 120 ms call
/// ([`Phases::drop_us`]), and whether it is worth more on a node, where the
/// same 32 MB of environments is freed under the fleet's allocator settings
/// while the import thread is the chain's critical path, is a leg's question.
/// Nothing reads any of it again, so the only cost is a job on the pool.
pub fn free_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_FREE_ASYNC", false))
}

/// Whether `N42_FOLLOWER_GRAFT=1` is set: the follower folds the groups'
/// bundles into the block's state with [`graft_bundles`] instead of one
/// commit of the folded changes (round 43: the commit and its transition
/// merge were 265 ms of a 736 ms import of a block touching 147,000
/// accounts).
pub fn follower_graft() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_GRAFT", false))
}

/// Whether the follower's batches run on the leader's batch state (default;
/// `N42_FOLLOWER_BATCH_STATE=0` goes back to revm's `State`): the three cuts
/// of step 4b (be80847cc, 921de3899) -- [`crate::batch_state::BatchState`] as
/// the sink, `transfer_plain` handing the computed accounts over without an
/// `EvmState`, and the loaded info moved rather than cloned on a read. The
/// bundle a batch yields is the one `State`'s
/// `merge_transitions(BundleRetention::Reverts)` and `take_bundle` return
/// (`batch_state`'s tests, and `parallel_matches_serial*` here on the
/// follower's own path), so the block's post-state is unchanged.
pub fn follower_batch_state() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_BATCH_STATE", true))
}

/// Whether `N42_FOLLOWER_BUILD_PATH=1` is set: a follower executes a block of
/// plain transfers through the leader's own machinery
/// ([`execute_transfers_build_path`]) -- the sender-group partition, the
/// build pool, the batches on [`crate::batch_state::BatchState`] with
/// `transfer_plain`, the index-mode [`crate::output_shards::OutputShards`]
/// sink and no graft -- instead of [`execute_transfers_with_plan`]. Off by
/// default.
pub fn follower_build_path() -> bool {
    // A revm-era path (`legacy-revm-paths`); not ported to evm2.
    if !crate::legacy_paths::LEGACY_REVM_PATHS {
        return false;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_BUILD_PATH", false))
}

/// Where a build-path execution ([`execute_transfers_build_path`]) spends
/// the time its batches and its index do not: microseconds, always measured.
/// The pieces the follower's `exec_ms` held unnamed (~14 ms of 72 on the
/// fleet, loop288).
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildPathSplit {
    /// Before the partition: the block's environment and the output shards'
    /// allocation.
    pub setup_us: u64,
    /// The (sender, recipient) keys read off the block; 0 when they were
    /// made ahead ([`build_path_keys`]).
    pub keys_us: u64,
    /// The block's executor set up and its pre-execution changes (the
    /// beacon-root and block-hash system calls).
    pub pre_us: u64,
    /// The executor's post-execution changes (withdrawals, requests).
    pub post_us: u64,
    /// How far the executor's pre- and post-execution outran the batches
    /// when it runs beside them: 0 when they hid it.
    pub executor_overrun_us: u64,
    /// The run's own time outside the partition and the batch wall: the
    /// slots' allocation, the results' hand-over, the partition's release.
    pub sink_us: u64,
    /// The executor's accounts taken out of the shards
    /// ([`crate::output_shards::FrozenShards::take_cached`]).
    pub cached_us: u64,
    /// The fee credit, the transitions' merge and the residual's take.
    pub residual_us: u64,
    /// The receipts in block order.
    pub receipts_us: u64,
    /// What the receipts added after the index when built beside it.
    pub receipts_wait_us: u64,
    /// Whether the keys were made ahead of the call.
    pub keys_ahead: bool,
}

/// The (sender, recipient) keys the build path's partition reads
/// ([`execute_transfers_build_path`]): every transaction a call with no
/// input, its sender the recovered one. One pass on the build pool, as the
/// leader's prep reads its candidates (`par_prep_ms`): read serially, the
/// 163,000 transactions' cold memory was most of the follower's
/// `exec_part_ms` (10 against the leader's 4, loop288). Made ahead of the
/// execution when the block's senders are first known
/// (`N42_FOLLOWER_PARTITION_AHEAD=1` on the build path) and handed to
/// [`execute_transfers_build_path_keyed`].
pub fn build_path_keys(block: &RecoveredBlock<Block>) -> Result<Vec<(Address, Address)>, NotParallel> {
    build_path_keys_of(&block.body().transactions, block.senders())
}

/// [`build_path_keys`] on a block's transactions and senders wherever they
/// are held: the owned block's, or a frame description's by reference
/// ([`BuildPathTx`]), the keys made the moment the frames are taken.
pub fn build_path_keys_of<T: BuildPathTx>(txs: &[T], senders: &[Address]) -> Result<Vec<(Address, Address)>, NotParallel> {
    use alloy_consensus::Transaction as _;
    use rayon::prelude::*;
    if txs.len() != senders.len() {
        return Err(NotParallel::Failed(txs.len().min(senders.len()), "a transaction without its sender".to_string()));
    }
    build_pool().install(|| {
        txs.par_iter()
            .zip(senders.par_iter())
            .enumerate()
            .with_min_len(1024)
            .map(|(i, (tx, sender))| {
                let tx = tx.build_path_tx();
                match tx.kind() {
                    alloy_primitives::TxKind::Call(to) if tx.input().is_empty() => Ok((*sender, to)),
                    _ => Err(NotParallel::NotATransfer(i)),
                }
            })
            .collect()
    })
}

/// A transaction the follower's build path reads: the owned block's own, or
/// one held by reference where the block was assembled (a frame
/// description's `Arc`s into this node's queue), as the leader's batches
/// read the pooled transactions (`consensus_ref`).
pub trait BuildPathTx: Sync {
    /// The transaction.
    fn build_path_tx(&self) -> &n42_tx_types::N42TxEnvelope;
}

impl BuildPathTx for n42_tx_types::N42TxEnvelope {
    fn build_path_tx(&self) -> &n42_tx_types::N42TxEnvelope {
        self
    }
}

/// What the follower's build path reads of a block: the header, the
/// withdrawals and ommers its executor's pre- and post-execution changes
/// read, and the transactions with their senders -- the owned block's, or
/// a described block's held by reference, so the execution need not wait
/// for the owned block's copy (`N42_FOLLOWER_COPY_ASIDE=1`).
#[derive(Debug, Clone, Copy)]
pub struct BuildPathBlock<'a, T> {
    /// The header.
    pub header: &'a n42_header::N42Header,
    /// The owned block, when there is one: its executor context is the
    /// configuration's own (`context_for_block`).
    pub sealed: Option<&'a reth_primitives_traits::SealedBlock<Block>>,
    /// The ommers (a described block has none; no N42 chain has any, and
    /// the executor's ommer rewards read Ethereum headers).
    pub ommers: &'a [alloy_consensus::Header],
    /// The withdrawals, as the block's body lists them.
    pub withdrawals: Option<&'a [alloy_eips::eip4895::Withdrawal]>,
    /// The transactions, in block order.
    pub txs: &'a [T],
    /// Their senders, in the same order.
    pub senders: &'a [Address],
}

impl<'a> BuildPathBlock<'a, n42_tx_types::N42TxEnvelope> {
    /// The owned, recovered block.
    pub fn of(block: &'a RecoveredBlock<Block>) -> Self {
        Self {
            header: block.header(),
            sealed: Some(block.sealed_block()),
            ommers: &[],
            withdrawals: block.body().withdrawals.as_ref().map(|w| w.as_slice()),
            txs: &block.body().transactions,
            senders: block.senders(),
        }
    }
}

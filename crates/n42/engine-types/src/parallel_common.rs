// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The parts of the parallel step that do not touch the EVM: the knobs, the
//! worker pools, the sender partition, the phase timers and the revert
//! helpers over reth's bundle state. The evm2 builder and import
//! ([`crate::parallel_build`]) run on them; `crate::parallel_transfer`
//! re-exports them under the module's older path.

use alloy_primitives::Address;
use reth_trie::bundle_state::{AccountRevert, BundleState};

/// The block executor factory of a node with the transfer path: what
/// the parallel step ([`crate::parallel_build`]) requires of its EVM configuration.
pub type FastExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<n42_header::N42ChainSpec>;


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
/// Whether `N42_PHASE_TIMERS=1` is set: the build line's overlay counters.
pub fn phase_timers() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PHASE_TIMERS").is_ok_and(|v| v == "1"))
}

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


















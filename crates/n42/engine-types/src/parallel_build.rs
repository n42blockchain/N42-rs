// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The leader's parallel step on evm2 (reth v2.9.0; `docs/RETH_2_9_0_UPGRADE.md`
//! "F5 design", F5c).
//!
//! A block's plain transfers are partitioned by sender
//! ([`crate::parallel_common::partition_by_sender`]), the sender groups packed
//! into batches ([`crate::parallel_common::Dispatch`]), and each batch runs on
//! the build pool on its own evm2 `Evm` over its own view of the parent's
//! state, its changes folded into a [`BatchState`]. A transfer the EVM
//! refuses (a nonce that is not the sender's, a balance short) is skipped
//! with every later transfer of its sender in that batch, and left to the
//! serial loop. The batches' bundles are merged
//! ([`crate::graft_fold::merge_batches`]); the caller writes the merged
//! accounts into the block executor's overlay (the cache half), commits the
//! transfers' receipts in candidate order, and hands the merge to
//! [`crate::n42_evm::N42BlockExecutor::set_pending_fold`] so that `finish`
//! folds it into the block's bundle (the bundle half).
//!
//! This is the correctness baseline the design calls for: every transfer
//! goes through the stock evm2 handler. The transfer fast path (F5f) and the
//! revm-era refinements (output shards, the streamed graft, the read layers)
//! are not part of it.

use crate::{
    batch_state::{BatchState, Unsupported},
    graft_fold::{merge_batches, FoldRefused, MergedBatches},
    parallel_common::{batch_groups, batch_groups_one_wave, build_pool, largest_first, partition_by_sender, Dispatch, NotParallel},
};
use crate::n42_evm::N42BlockExecutor;
use alloy_primitives::Address;
use evm2::evm::AccountInfo;
use reth_evm::{ConfigureEvm, Evm as _, EvmEnvFor};
use reth_primitives_traits::Recovered;

/// The EVM type family a configuration's executors run on.
pub type TypesOf<C> = <<C as ConfigureEvm>::BlockExecutorFactory as reth_evm::execute::BlockExecutorFactory>::EvmTypes;

/// The transaction type a configuration's EVM executes.
pub type EvmTxOf<C> = <TypesOf<C> as evm2::EvmTypesHost>::Tx;

/// One transfer the batches executed: its index among the candidates and the
/// EVM's result, for its receipt. Its state changes are in its batch's
/// bundle.
#[derive(Debug)]
pub struct Executed<C: ConfigureEvm> {
    /// Index into the candidates.
    pub index: usize,
    /// The EVM's result.
    pub result: evm2::TxResult<TypesOf<C>>,
}

/// What [`execute_batches`] produced.
#[derive(Debug)]
pub struct ParallelRun<C: ConfigureEvm> {
    /// The executed transfers in candidate order, the order they take in the
    /// block.
    pub executed: Vec<Executed<C>>,
    /// Candidates the EVM refused, with every later one of the same sender
    /// in its batch: left to the serial loop, in candidate order.
    pub skipped: Vec<usize>,
    /// The batches' changes, merged and checked.
    pub merged: MergedBatches,
    /// How many batches ran.
    pub batches: usize,
    /// The partition the batches ran, handed back so that a caller can free
    /// it off its own thread (`N42_FOLLOWER_FREE_ASYNC`).
    pub groups: Vec<Vec<usize>>,
    /// With a sink ([`execute_batches_into`]): each batch's own bundle of the
    /// beneficiary, which `merged` is made of. Empty otherwise.
    pub split: Vec<reth_trie::bundle_state::BundleState>,
    /// The batches' spans on the pool (start, end, CPU, open), as the
    /// revm-era step reports them on the phases line (F5g9).
    pub spans: crate::parallel_common::BatchSpans,
    /// Inside the batches, by part, summed over the batches (F5g9).
    pub inside: BatchInside,
}

/// The evm2 batches' time by part, microseconds summed over every batch
/// (F5g9). The per-transaction parts are sampled, one transaction in
/// [`INSIDE_STRIDE`], and scaled to the batch's count; the shard add is
/// measured on every batch.
#[derive(Debug, Clone, Copy, Default)]
pub struct BatchInside {
    /// In the parent state's reads (`Database` calls under the EVM).
    pub reads_us: u64,
    /// In `transact`, the reads included.
    pub transact_us: u64,
    /// In the batch state's and the EVM's commits.
    pub commit_us: u64,
    /// The beneficiary's split-off and the bundle's add to its shards.
    pub shard_add_us: u64,
    /// Parent-state reads, sampled transactions only (unscaled).
    pub reads_sampled: u64,
    /// Before the batches: the partition (when not made ahead) and the
    /// batching, wall.
    pub before_us: u64,
    /// After the batches: the executed sets gathered into candidate order,
    /// wall.
    pub gather_us: u64,
    /// After the batches: the split-off bundles copied and merged, wall.
    pub merge_us: u64,
}

/// One transaction in this many is timed by part inside a batch.
pub const INSIDE_STRIDE: usize = 16;

std::thread_local! {
    /// Whether the current transaction on this thread is a sampled one, and
    /// the parent reads it made with their time (ns).
    static READ_TIMING: std::cell::Cell<(bool, u64, u64)> = const { std::cell::Cell::new((false, 0, 0)) };
}

/// A parent state whose reads, on a sampled transaction, are timed into
/// [`READ_TIMING`] (F5g9).
#[derive(Debug)]
pub struct TimedDb<D>(pub D);

impl<D: evm2::evm::Database> evm2::evm::Database for TimedDb<D> {
    type Error = D::Error;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        timed_read(|| self.0.get_account(address))
    }

    fn get_code_by_hash(&mut self, code_hash: &alloy_primitives::B256) -> Result<evm2::bytecode::Bytecode, Self::Error> {
        timed_read(|| self.0.get_code_by_hash(code_hash))
    }

    fn get_storage(&mut self, address: &Address, index: &alloy_primitives::U256) -> Result<alloy_primitives::U256, Self::Error> {
        timed_read(|| self.0.get_storage(address, index))
    }

    fn get_block_hash(&mut self, number: &alloy_primitives::U256) -> Result<alloy_primitives::B256, Self::Error> {
        timed_read(|| self.0.get_block_hash(number))
    }
}

fn timed_read<T>(read: impl FnOnce() -> T) -> T {
    let (sampled, count, ns) = READ_TIMING.with(std::cell::Cell::get);
    if !sampled {
        return read();
    }
    let at = std::time::Instant::now();
    let out = read();
    READ_TIMING.with(|cell| cell.set((true, count + 1, ns + at.elapsed().as_nanos() as u64)));
    out
}

/// One slot a candidate, written once by the batch that executed it, on
/// that batch's thread (F5g9): the executed set comes out in candidate order
/// without a gather and a sort of 200,000 results on one thread after the
/// batches (5.5 ms on the bench, `evm2_exec_gather_us`).
struct ScatterSlots<T> {
    data: Box<[std::cell::UnsafeCell<std::mem::MaybeUninit<T>>]>,
    filled: Box<[std::sync::atomic::AtomicBool]>,
}

// SAFETY: a slot is written by one thread only (`put` claims it through its
// flag first), and read only after every writer is joined (`into_ordered`
// and `drop` take `self` by value or `&mut`).
unsafe impl<T: Send> Sync for ScatterSlots<T> {}

impl<T> ScatterSlots<T> {
    fn new(len: usize) -> Self {
        Self {
            data: (0..len).map(|_| std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit())).collect(),
            filled: (0..len).map(|_| std::sync::atomic::AtomicBool::new(false)).collect(),
        }
    }

    /// Writes `value` into slot `i`; a slot already written (never, with
    /// candidates in one batch each) keeps its value and `value` is dropped.
    fn put(&self, i: usize, value: T) {
        if self.filled[i].swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        // SAFETY: the flag's swap made this thread the slot's only writer,
        // and no reader runs before the writers are joined.
        unsafe { (*self.data[i].get()).write(value) };
    }

    /// The written slots' values in slot order. Every slot written (a run
    /// with nothing skipped): the slots become the vector in place, no copy.
    fn into_ordered(mut self) -> Vec<T> {
        if self.filled.iter_mut().all(|f| *f.get_mut()) {
            let data = std::mem::take(&mut self.data);
            for f in self.filled.iter_mut() {
                *f.get_mut() = false;
            }
            let len = data.len();
            let raw = Box::into_raw(data) as *mut T;
            // SAFETY: `UnsafeCell<MaybeUninit<T>>` has `T`'s layout (both are
            // `repr(transparent)`), every element is initialised (its flag
            // was set), and the flags are cleared so `drop` reads nothing;
            // the allocation came from a `Box<[_]>` of `len` elements.
            return unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(raw, len)) }.into_vec();
        }
        let mut out = Vec::with_capacity(self.data.len());
        for i in 0..self.data.len() {
            if std::mem::replace(self.filled[i].get_mut(), false) {
                // SAFETY: the slot was written (its flag was set) and its
                // flag is cleared here, so it is read once and not dropped
                // again.
                out.push(unsafe { self.data[i].get_mut().assume_init_read() });
            }
        }
        out
    }
}

impl<T> Drop for ScatterSlots<T> {
    fn drop(&mut self) {
        for i in 0..self.data.len().min(self.filled.len()) {
            if *self.filled[i].get_mut() {
                // SAFETY: the slot was written and not read out.
                unsafe { self.data[i].get_mut().assume_init_drop() };
            }
        }
    }
}

/// Logs once which pool the evm2 batches run on, its threads and the CPUs
/// its threads may run on (F5g9).
fn log_pool_once(pool: &rayon::ThreadPool) {
    static LOGGED: std::sync::Once = std::sync::Once::new();
    LOGGED.call_once(|| {
        let cpus = pool.install(n42_core_layout::current_thread_cpus).map(|c| n42_core_layout::format_cpu_list(&c)).unwrap_or_default();
        let name = pool.install(|| std::thread::current().name().map(str::to_owned)).unwrap_or_default();
        tracing::info!(
            target: "n42::parallel_build",
            threads = pool.current_num_threads(),
            thread = %name,
            cpus = %cpus,
            layout = n42_core_layout::label(),
            "evm2 batches' pool"
        );
    });
}

/// Why the parallel step gave the block to the serial loop.
#[derive(Debug)]
pub enum Refused {
    /// The candidates could not be partitioned or a batch could not run.
    NotParallel(NotParallel),
    /// A batch made a change the batch state does not model.
    Unsupported(Unsupported),
    /// The batches' bundles could not be merged.
    Fold(FoldRefused),
    /// The block executor's overlay already holds an account the batches
    /// changed at a value other than the one they started from (a
    /// pre-execution system call touched it).
    Cache(Address),
    /// A receipt's commit failed after the cache half was written: the
    /// executor is left part-way and the build cannot go on with it. (The
    /// stock commit of a result with an empty write set does not fail.)
    Commit(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotParallel(err) => err.fmt(f),
            Self::Unsupported(err) => err.fmt(f),
            Self::Fold(err) => err.fmt(f),
            Self::Cache(address) => write!(f, "the executor already holds {address} at another value"),
            Self::Commit(err) => write!(f, "a receipt's commit failed: {err}"),
        }
    }
}

impl std::error::Error for Refused {}

impl Refused {
    /// A short name for the per-block line.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NotParallel(_) => "not-parallel",
            Self::Unsupported(_) => "unsupported-change",
            Self::Fold(_) => "merge-refused",
            Self::Cache(_) => "cache-conflict",
            Self::Commit(_) => "commit-failed",
        }
    }
}

static SERIAL_REBUILDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMMITTED_RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Runs handed to a block executor by [`commit_run`], since start.
pub fn committed_runs() -> u64 {
    COMMITTED_RUNS.load(std::sync::atomic::Ordering::Relaxed)
}

static SHARDED_RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Counts a sealed run whose output stayed in the output shards (F5g3).
pub fn note_sharded_run() {
    SHARDED_RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Sealed runs whose output stayed in the output shards, since start.
pub fn sharded_runs() -> u64 {
    SHARDED_RUNS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Counts a block rebuilt serially after its fold refused at `finish`.
pub fn note_serial_rebuild() {
    SERIAL_REBUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Blocks rebuilt serially after a refused fold, since start.
pub fn serial_rebuilds() -> u64 {
    SERIAL_REBUILDS.load(std::sync::atomic::Ordering::Relaxed)
}

fn same_account(a: &AccountInfo, b: &AccountInfo) -> bool {
    a.balance == b.balance && a.nonce == b.nonce && a.code_hash == b.code_hash
}

/// The cache half: the merged accounts written into the block executor's
/// overlay at their post-batch values, so that whatever runs after them
/// (the serial loop, the withdrawals, the post-block system calls) reads
/// them there and starts from where the batches left them. Refused, with
/// nothing written, when the overlay already holds one of them at a value
/// other than the parent's the batches started from: the batches' changes
/// would then not be the block's.
pub fn install_cache<X>(overlay: &mut evm2::evm::CacheDB<X>, merged: &MergedBatches) -> Result<usize, Address> {
    let addresses: Vec<Address> = merged.accounts().map(|(address, _)| *address).collect();
    install_entries(overlay, merged, addresses.iter().copied())
}

fn install_entries<X>(
    overlay: &mut evm2::evm::CacheDB<X>,
    merged: &MergedBatches,
    addresses: impl Iterator<Item = Address> + Clone,
) -> Result<usize, Address> {
    for address in addresses.clone() {
        let Some(original) = merged.original(&address) else { continue };
        if let Some(held) = overlay.cache.accounts.get(&address) {
            let agrees = match (held.as_ref(), original) {
                (Some(held), Some(original)) => same_account(held, original),
                (None, None) => true,
                // Loaded as absent and absent in the parent read alike.
                (Some(held), None) => held.is_empty(),
                (None, Some(original)) => original.is_empty(),
            };
            if !agrees {
                return Err(address);
            }
        }
    }
    let mut written = 0;
    for address in addresses {
        if let Some(info) = merged.get(&address) {
            overlay.insert_account_info(&address, info.clone());
            written += 1;
        }
    }
    Ok(written)
}

/// The intrinsic gas of a plain transfer: what every transfer the batches
/// keep used.
pub const TRANSFER_GAS: u64 = 21_000;

/// Which merged accounts the cache half writes into the executor's overlay.
#[derive(Debug, Clone, Copy)]
pub enum CacheScope<'a> {
    /// Every one: whatever runs after the batches may read any of them (the
    /// leader's serial loop).
    All,
    /// Only these (the follower's `keep_cache = false`, ported from the
    /// revm-era import: after the batches only the block's end runs, which
    /// reads the withdrawal recipients and the system contracts -- never a
    /// batch account, the merge refuses code). An account the end reads
    /// that is not written here makes the fold refuse (`Stale`), and the
    /// block is imported serially.
    Only(&'a [Address]),
}

/// [`install_cache`] for the merged accounts among `addresses` only.
pub fn install_cache_only<X>(overlay: &mut evm2::evm::CacheDB<X>, merged: &MergedBatches, addresses: &[Address]) -> Result<usize, Address> {
    install_entries(overlay, merged, addresses.iter().copied())
}

/// Hands a run to the block executor: the cache half ([`install_cache`]),
/// then each executed transfer's receipt and gas in block order (a commit
/// with an empty write set: the state is in the merge), then the merge for
/// `finish` to fold ([`N42BlockExecutor::set_pending_fold`]). Refused with
/// nothing changed when the cache half is ([`Refused::Cache`]); a
/// [`Refused::Commit`] leaves the executor part-way.
pub fn commit_run<'a, T>(
    executor: &mut N42BlockExecutor<'a, T>,
    executed: impl IntoIterator<Item = (evm2::TxResult<T>, n42_tx_types::N42TxType)>,
    merged: MergedBatches,
    cache: CacheScope<'_>,
) -> Result<u64, Refused>
where
    T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync + Default>,
{
    use reth_evm::execute::BlockExecutor as _;
    match cache {
        CacheScope::All => {
            install_cache(executor.evm_mut().overlay_db_mut(), &merged).map_err(Refused::Cache)?;
        }
        CacheScope::Only(addresses) => {
            install_cache_only(executor.evm_mut().overlay_db_mut(), &merged, addresses).map_err(Refused::Cache)?;
        }
    }
    let mut gas = 0u64;
    for (result, tx_type) in executed {
        let detached = evm2::evm::TxResultWithState::<T> { result, ..Default::default() };
        let out = executor
            .commit_transaction(reth_evm_ethereum::EthTransactionResultWithState::new(detached, tx_type, 0))
            .map_err(|err| Refused::Commit(err.to_string()))?;
        gas += out.tx_gas_used();
    }
    executor.set_pending_fold(merged);
    COMMITTED_RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(gas)
}

/// The receipts of `executed` (each transfer's result with its type) in
/// block order, with their cumulative gas from zero, and the block's gas:
/// what [`commit_run`] has the executor build one by one when nothing was
/// committed before (`N42ReceiptBuilder`), built off the executor (F5g7,
/// `N42_EVM2_RECEIPTS_LATE`).
pub fn late_receipts<X>(
    executed: impl IntoIterator<Item = (evm2::TxResultExt<X>, n42_tx_types::N42TxType)>,
) -> (Vec<n42_tx_types::Receipt>, u64) {
    let executed = executed.into_iter();
    let mut receipts = Vec::with_capacity(executed.size_hint().0);
    let mut cumulative = 0u64;
    for (result, tx_type) in executed {
        cumulative += result.tx_gas_used();
        receipts.push(n42_tx_types::Receipt { tx_type, success: result.status, cumulative_gas_used: cumulative, logs: result.logs });
    }
    (receipts, cumulative)
}

/// Runs the candidates' transfers in batches on the build pool, each batch on
/// an EVM from `config` with `env` over a database `open` returns (a view of
/// the block's parent). `keys` are the candidates' (sender, recipient);
/// `convert` gives candidate `i` as the EVM executes it. `groups`, when
/// given, is the partition of `keys` at `beneficiary` made ahead (the
/// plan-ahead body, `N42_PLAN_AHEAD_BODY=1`); it is made here otherwise.
/// `worst_case`, under deferred execution, gives candidate `i`'s worst-case
/// cost (`frame_scan::tx_cost`): each sender's summed worst case is kept
/// within its parent balance, as the follower checks it (audit R3-E1), and a
/// transfer over it is skipped with its sender's later ones.
#[allow(clippy::too_many_arguments)]
pub fn execute_batches<C, D>(
    config: &C,
    env: &EvmEnvFor<C>,
    keys: &[(Address, Address)],
    groups: Option<Vec<Vec<usize>>>,
    convert: &(dyn Fn(usize) -> Recovered<EvmTxOf<C>> + Sync),
    open: &(dyn Fn() -> Option<D> + Sync),
    worst_case: Option<&(dyn Fn(usize) -> alloy_primitives::U256 + Sync)>,
    beneficiary: Address,
    dispatch: Dispatch,
) -> Result<ParallelRun<C>, Refused>
where
    C: ConfigureEvm + Sync,
    EvmEnvFor<C>: Sync,
    D: evm2::evm::Database + Send + 'static,
    evm2::TxResult<TypesOf<C>>: Send,
{
    execute_batches_into(config, env, keys, groups, convert, open, worst_case, beneficiary, dispatch, None, &[])
}

/// [`execute_batches`] with each batch's bundle handed to `sink` on the
/// batch's thread as the batch ends (the output shards, F5g3), the
/// beneficiary's and `kept`'s accounts and reverts split off it first. The
/// run's `merged` is then theirs alone (every batch credits the beneficiary,
/// the fold sums the credits; `kept` are the accounts the block's end reads,
/// the withdrawal recipients, which the executor's cache must hold at their
/// post-batch values); every other account is the sink's. The checks the merge
/// makes across batches are the batch state's own refusals here (no code,
/// no storage, nothing created, destroyed or left empty), and the
/// partition by sender keeps a sender in one batch, so no account is
/// debited by two.
#[allow(clippy::too_many_arguments)]
pub fn execute_batches_into<C, D>(
    config: &C,
    env: &EvmEnvFor<C>,
    keys: &[(Address, Address)],
    groups: Option<Vec<Vec<usize>>>,
    convert: &(dyn Fn(usize) -> Recovered<EvmTxOf<C>> + Sync),
    open: &(dyn Fn() -> Option<D> + Sync),
    worst_case: Option<&(dyn Fn(usize) -> alloy_primitives::U256 + Sync)>,
    beneficiary: Address,
    dispatch: Dispatch,
    sink: Option<&(dyn Fn(reth_trie::bundle_state::BundleState) + Sync)>,
    kept: &[Address],
) -> Result<ParallelRun<C>, Refused>
where
    C: ConfigureEvm + Sync,
    EvmEnvFor<C>: Sync,
    D: evm2::evm::Database + Send + 'static,
    evm2::TxResult<TypesOf<C>>: Send,
{
    let before_at = std::time::Instant::now();
    let groups = match groups {
        Some(groups) => groups,
        None => partition_by_sender(keys, beneficiary).map_err(Refused::NotParallel)?,
    };
    let pool = build_pool();
    log_pool_once(pool);
    let workers = pool.current_num_threads().max(1);
    let batches = match dispatch {
        Dispatch::OneWave => batch_groups_one_wave(&groups, keys.len(), workers),
        Dispatch::LargestFirst(n) => batch_groups_one_wave(&groups, keys.len(), n.max(1)),
        Dispatch::Halves => batch_groups(&groups, keys.len(), workers),
    };
    let order = largest_first(&batches.iter().map(|b| b.iter().map(|g| g.len()).sum()).collect::<Vec<usize>>());
    type BatchOut = Result<(Vec<usize>, reth_trie::bundle_state::BundleState, crate::parallel_common::BatchSpan, BatchInside), Refused>;
    let executed_slots: ScatterSlots<Executed<C>> = ScatterSlots::new(keys.len());
    let batches_at = std::time::Instant::now();
    let before_us = before_at.elapsed().as_micros() as u64;
    let split_off: Vec<Address> = std::iter::once(beneficiary).chain(kept.iter().copied().filter(|a| *a != beneficiary)).collect();
    let run_batch = |members: &Vec<&Vec<usize>>| -> BatchOut {
        let start_us = batches_at.elapsed().as_micros() as u64;
        let mark = crate::parallel_common::ThreadMark::now();
        let open_at = std::time::Instant::now();
        let db = TimedDb(open().ok_or(Refused::NotParallel(NotParallel::NoState))?);
        let open_us = open_at.elapsed().as_micros() as u64;
        let mut inside = BatchInside::default();
        let mut sampled_txs = 0u64;
        let mut seen = 0usize;
        // The batch's EVM carries the fast transfer handler (as the revm-era
        // batches always did) unless `N42_BATCH_FAST_TRANSFER=0`.
        let mut evm = crate::fast_handler::as_batch(|| config.evm_with_env(db, env.clone()));
        let txs = members.iter().map(|g| g.len()).sum::<usize>();
        let mut state = BatchState::with_capacity(txs * 2 + 1);
        let mut skipped = Vec::new();
        let mut ledger = crate::includability::RunLedger::new();
        for group in members {
            // A sender's transfers in nonce order; once one is refused the
            // rest of the group cannot execute here either.
            let mut broken = false;
            let mut first = true;
            for &i in group.iter() {
                if broken {
                    skipped.push(i);
                    continue;
                }
                let tx = convert(i);
                let sample = seen.is_multiple_of(INSIDE_STRIDE);
                seen += 1;
                let transact_at = sample.then(|| {
                    READ_TIMING.with(|cell| cell.set((true, 0, 0)));
                    std::time::Instant::now()
                });
                let transacted = evm.transact(&tx);
                if let Some(at) = transact_at {
                    inside.transact_us += at.elapsed().as_nanos() as u64;
                    let (_, count, ns) = READ_TIMING.with(|cell| cell.replace((false, 0, 0)));
                    inside.reads_us += ns;
                    inside.reads_sampled += count;
                    sampled_txs += 1;
                }
                match transacted {
                    Ok(out) => {
                        // Checked before the commit: a transfer refused here
                        // leaves the batch's state as it was. One that used
                        // more than the intrinsic gas ran code, and code may
                        // read what another batch changes: not the batches'.
                        if out.result.tx_gas_used() != TRANSFER_GAS {
                            broken = true;
                            skipped.push(i);
                            continue;
                        }
                        if let Some(cost) = worst_case {
                            let sender = keys[i].0;
                            let before = out
                                .pending_state
                                .account_changes()
                                .find(|changes| changes.address == sender)
                                .and_then(|changes| changes.original.map(|info| info.balance))
                                .unwrap_or_default();
                            if !ledger.admit(sender, first, before, cost(i)) {
                                broken = true;
                                skipped.push(i);
                                continue;
                            }
                        }
                        first = false;
                        let commit_at = sample.then(std::time::Instant::now);
                        state.commit(&out.pending_state).map_err(Refused::Unsupported)?;
                        evm.commit_state(&out.pending_state);
                        if let Some(at) = commit_at {
                            inside.commit_us += at.elapsed().as_nanos() as u64;
                        }
                        executed_slots.put(i, Executed { index: i, result: out.result });
                    }
                    Err(_) => {
                        broken = true;
                        skipped.push(i);
                    }
                }
            }
        }
        // The sampled parts scaled to the batch's count, in microseconds
        // (accumulated in nanoseconds).
        let scale = |ns: u64| ns.saturating_mul(seen as u64).checked_div(sampled_txs).unwrap_or(0) / 1000;
        inside.transact_us = scale(inside.transact_us);
        inside.reads_us = scale(inside.reads_us);
        inside.commit_us = scale(inside.commit_us);
        let bundle = state.take_bundle();
        let own = match sink {
            Some(sink) => {
                let add_at = std::time::Instant::now();
                let mut bundle = bundle;
                let own = split_accounts(&mut bundle, &split_off);
                sink(bundle);
                inside.shard_add_us = add_at.elapsed().as_micros() as u64;
                own
            }
            None => bundle,
        };
        let span = crate::parallel_common::BatchSpan::close(start_us, mark, seen, batches_at).with_open_us(open_us);
        Ok((skipped, own, span, inside))
    };
    let slots: Vec<std::sync::OnceLock<BatchOut>> = (0..batches.len()).map(|_| std::sync::OnceLock::new()).collect();
    pool.scope(|scope| {
        for &b in &order {
            let (members, slot, run_batch) = (&batches[b], &slots[b], &run_batch);
            scope.spawn(move |_| {
                let _ = slot.set(run_batch(members));
            });
        }
    });
    let total_us = batches_at.elapsed().as_micros() as u64;
    let gather_at = std::time::Instant::now();
    let (mut skipped, mut bundles) = (Vec::new(), Vec::with_capacity(batches.len()));
    let mut spans = Vec::with_capacity(batches.len());
    let mut inside = BatchInside::default();
    for slot in slots {
        let (s, bundle, span, part) = slot.into_inner().unwrap_or(Err(Refused::NotParallel(NotParallel::NoState)))?;
        skipped.extend(s);
        bundles.push(bundle);
        spans.push(span);
        inside.reads_us += part.reads_us;
        inside.transact_us += part.transact_us;
        inside.commit_us += part.commit_us;
        inside.shard_add_us += part.shard_add_us;
        inside.reads_sampled += part.reads_sampled;
    }
    let spans = crate::parallel_common::BatchSpans::of(&mut spans, total_us);
    inside.before_us = before_us;
    let executed = executed_slots.into_ordered();
    skipped.sort_unstable();
    inside.gather_us = gather_at.elapsed().as_micros() as u64;
    let merge_at = std::time::Instant::now();
    let split = if sink.is_some() { bundles.clone() } else { Vec::new() };
    let merged = merge_batches(bundles).map_err(Refused::Fold)?;
    inside.merge_us = merge_at.elapsed().as_micros() as u64;
    let count = batches.len();
    drop(batches);
    Ok(ParallelRun { executed, skipped, merged, batches: count, groups, split, spans, inside })
}

/// `addresses`' accounts and reverts taken out of `bundle` into a bundle of
/// their own (empty of those the bundle does not hold), the reverts in their
/// order.
fn split_accounts(bundle: &mut reth_trie::bundle_state::BundleState, addresses: &[Address]) -> reth_trie::bundle_state::BundleState {
    let mut own = reth_trie::bundle_state::BundleState::default();
    for address in addresses {
        if let Some(account) = bundle.state.remove(address) {
            bundle.state_size = bundle.state_size.saturating_sub(account.size_hint());
            own.state_size += account.size_hint();
            own.state.insert(*address, account);
        }
    }
    if own.state.is_empty() {
        return own;
    }
    let mut reverts = Vec::new();
    for block in bundle.reverts.iter_mut() {
        block.retain(|entry| {
            let moved = own.state.contains_key(&entry.0);
            if moved {
                reverts.push(entry.clone());
            }
            !moved
        });
    }
    bundle.reverts_size = bundle.reverts.iter().map(Vec::len).sum();
    own.reverts_size = reverts.len();
    own.reverts.push(reverts);
    own
}

static IMPORTS_PARALLEL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static IMPORTS_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Follower imports that went parallel, since start.
pub fn imports_parallel() -> u64 {
    IMPORTS_PARALLEL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Follower imports the parallel step refused (each then imported
/// serially by the caller), since start.
pub fn imports_refused() -> u64 {
    IMPORTS_REFUSED.load(std::sync::atomic::Ordering::Relaxed)
}

/// What a parallel import did, for its log line.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportStats {
    /// Transfers executed in batches (the block's leading plain transfers).
    pub txs: usize,
    /// Transactions executed after them by the block's executor.
    pub tail: usize,
    /// Whether the plan was made ahead (`N42_FOLLOWER_PARTITION_AHEAD`).
    pub planned: bool,
    /// Batches they ran in.
    pub batches: usize,
    /// Accounts the batches changed.
    pub accounts: usize,
    /// Of those, written into the executor's overlay (`keep_cache = false`:
    /// the withdrawal recipients among them; every one when a tail follows).
    pub cached: usize,
    /// The batches' wall time, microseconds.
    pub batches_us: u64,
    /// The executor's part (pre-execution, receipts, the block's end and
    /// the fold), microseconds.
    pub finish_us: u64,
}

/// `N42_FOLLOWER_PARTITION_AHEAD=1` on evm2 (F5e): the follower makes a
/// block's [`ImportPlan`] on the worker pool as soon as the block is known,
/// beside the wait for its parent, instead of inside the execution gate.
pub fn follower_partition_ahead() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_PARTITION_AHEAD", false))
}

/// `N42_FOLLOWER_FREE_ASYNC=1` on evm2 (F5e): the import's own working
/// memory (the keys, the partition, the plan) is freed on the worker pool
/// rather than on the import thread.
pub fn follower_free_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FOLLOWER_FREE_ASYNC", false))
}

/// What [`import_block`] decides before it executes anything: the leading
/// transfers' (sender, recipient) and their partition by sender. Made by
/// [`plan_import`], either inside the import or ahead of it.
#[derive(Debug, Default)]
pub struct ImportPlan {
    keys: Vec<(Address, Address)>,
    groups: Option<Vec<Vec<usize>>>,
    beneficiary: Address,
}

/// The block's [`ImportPlan`]: its leading plain transfers -- every
/// transaction up to the first that is not one or that names the
/// beneficiary -- and their partition by sender.
pub fn plan_import(block: &reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> ImportPlan {
    use alloy_consensus::BlockHeader as _;
    let beneficiary = block.header().beneficiary();
    let keys: Vec<(Address, Address)> = block
        .body()
        .transactions
        .iter()
        .zip(block.senders())
        .map_while(|(tx, sender)| import_key(tx, *sender).filter(|(from, to)| *from != beneficiary && *to != beneficiary))
        .collect();
    let groups = (!keys.is_empty()).then(|| partition_by_sender(&keys, beneficiary).ok()).flatten();
    ImportPlan { keys, groups, beneficiary }
}

/// Frees `what` on the worker pool when `N42_FOLLOWER_FREE_ASYNC=1`, here
/// otherwise.
fn free<T: Send + 'static>(what: T) {
    if follower_free_async() {
        rayon::spawn(move || drop(what));
    } else {
        drop(what);
    }
}

/// A transaction's (sender, recipient) when the batches take it: a call
/// with no input, no access list, no blobs and no authorizations.
fn import_key(tx: &n42_tx_types::N42TxEnvelope, sender: Address) -> Option<(Address, Address)> {
    use alloy_consensus::Transaction as _;
    (tx.input().is_empty()
        && tx.access_list().is_none_or(|list| list.is_empty())
        && tx.blob_versioned_hashes().is_none()
        && tx.authorization_list().is_none())
    .then(|| tx.to())
    .flatten()
    .map(|to| (sender, to))
}

/// The follower's parallel import on evm2 (F5d): `block`'s leading plain
/// transfers -- every transaction up to the first that is not one or that
/// names the beneficiary -- executed in sender batches over the parent
/// ([`execute_batches`], `open` yields one view of the parent per batch),
/// then the block's own executor over `main_db` (the same parent): its
/// pre-execution changes, the transfers' receipts with the cache half, the
/// rest of the block transaction by transaction, the block's end and the
/// fold. A block of transfers only installs just the withdrawal recipients
/// in the executor's cache (`keep_cache = false`, [`CacheScope::Only`]); a
/// block with a serial tail installs every batch account, which the tail
/// may read. `Err` names why the block is not imported this way, with
/// nothing of it kept: the caller imports it serially, and a block that is
/// genuinely invalid is refused there with the stock executor's error.
pub fn import_block<C, M, D>(
    config: &C,
    block: &reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>,
    main_db: M,
    open: &(dyn Fn() -> Option<D> + Sync),
    dispatch: Dispatch,
    plan: Option<ImportPlan>,
) -> Result<(reth_evm::BlockExecutionOutput<n42_tx_types::Receipt>, ImportStats), Refused>
where
    C: ConfigureEvm<Primitives = n42_tx_types::N42Primitives, BlockExecutorFactory = crate::parallel_common::FastExecutorFactory> + Sync,
    EvmEnvFor<C>: Sync,
    M: evm2::evm::Database,
    D: evm2::evm::Database + Send + 'static,
{
    let refused = |why: Refused| {
        IMPORTS_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        why
    };
    let commit_err = |err: &dyn std::fmt::Display| Refused::Commit(err.to_string());
    let transactions = &block.body().transactions;
    let senders = block.senders();
    let env = config.evm_env(block.header()).map_err(|err| refused(commit_err(&err)))?;
    let beneficiary = env.block.beneficiary;
    // A plan made ahead is the block's own; one made for another fee
    // recipient than the EVM's is made again here.
    let planned = plan.is_some();
    let ImportPlan { keys, groups, .. } = match plan {
        Some(plan) if plan.beneficiary == beneficiary => plan,
        _ => plan_import(block),
    };
    if keys.is_empty() {
        return Err(refused(Refused::NotParallel(NotParallel::NotATransfer(0))));
    }
    let Some(groups) = groups else {
        // `plan_import` names no partition only for a beneficiary touch,
        // which its keys already stop before; made here for the error.
        let err = partition_by_sender(&keys, beneficiary).err().unwrap_or(NotParallel::NoState);
        return Err(refused(Refused::NotParallel(err)));
    };
    let tail = keys.len()..transactions.len();
    let tail_len = tail.len();
    let convert = |i: usize| Recovered::new_unchecked(evm2::ethereum::TxEnvelope::from(transactions[i].clone()), senders[i]);
    let batches_at = std::time::Instant::now();
    let run = execute_batches(config, &env, &keys, Some(groups), &convert, open, None, beneficiary, dispatch).map_err(refused)?;
    let batches_us = batches_at.elapsed().as_micros() as u64;
    if let Some(&i) = run.skipped.first() {
        return Err(refused(Refused::NotParallel(NotParallel::Failed(i, "refused by the EVM on the batches' view".to_owned()))));
    }
    let finish_at = std::time::Instant::now();
    let ParallelRun { executed, merged, batches, groups, .. } = run;
    let accounts = merged.len();
    let withdrawals: Vec<Address> = block.body().withdrawals.as_ref().map_or_else(Vec::new, |w| w.iter().map(|w| w.address).collect());
    let (scope, cached) = if tail.is_empty() {
        (CacheScope::Only(&withdrawals), withdrawals.iter().filter(|a| merged.get(a).is_some()).count())
    } else {
        (CacheScope::All, accounts)
    };
    let ctx = config.context_for_block(block.sealed_block()).map_err(|err| refused(commit_err(&err)))?;
    let evm = config.evm_with_env(main_db, env);
    use reth_evm::{execute::BlockExecutor as _, BlockExecutorFactory as _};
    let mut executor = config.block_executor_factory().create_executor(evm, ctx);
    executor.apply_pre_execution_changes().map_err(|err| refused(commit_err(&err)))?;
    let txs = executed.len();
    let results = executed.into_iter().map(|e| {
        let tx_type = <n42_tx_types::N42TxEnvelope as alloy_consensus::TransactionEnvelope>::tx_type(&transactions[e.index]);
        (e.result, tx_type)
    });
    commit_run(&mut executor, results, merged, scope).map_err(refused)?;
    for i in tail {
        executor
            .execute_transaction(Recovered::new_unchecked(&transactions[i], senders[i]))
            .map_err(|err| refused(commit_err(&err)))?;
    }
    let output = executor.finish().map_err(|err| match &err {
        reth_evm::BlockExecutionError::Internal(internal) => match internal.downcast_other::<FoldRefused>() {
            Some(fold) => refused(Refused::Fold(*fold)),
            None => refused(commit_err(&err)),
        },
        _ => refused(commit_err(&err)),
    })?;
    free((keys, groups));
    IMPORTS_PARALLEL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok((output, ImportStats { txs, tail: tail_len, planned, batches, accounts, cached, batches_us, finish_us: finish_at.elapsed().as_micros() as u64 }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n42_evm::N42EvmConfig;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_primitives::{Bytes, Signature, TxKind, B256, U256};
    use evm2::{
        bytecode::Bytecode,
        evm::{CacheDB, EmptyDB},
    };
    use n42_tx_types::N42TxEnvelope;
    use reth_evm::{execute::BlockExecutor as _, BlockExecutorFactory as _};
    use reth_trie::bundle_state::BundleState;
    use std::{borrow::Cow, sync::Arc};

    type Config = N42EvmConfig<n42_header::N42ChainSpec>;

    /// Shanghai: withdrawals at the block's end, no system contracts to
    /// deploy in the test's parent.
    fn config() -> Config {
        let spec = reth_chainspec::ChainSpecBuilder::mainnet().shanghai_activated().build();
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(spec)))
    }

    /// The timing tests' chain: Prague, where the fast transfer handler is
    /// registered (`fast_handler::covers`), as on the fleet's Osaka chain.
    /// `F5G_SPEC=shanghai` runs them without it.
    fn timing_config() -> Config {
        if std::env::var("F5G_SPEC").as_deref() == Ok("shanghai") {
            return config();
        }
        let spec = reth_chainspec::ChainSpecBuilder::mainnet().prague_activated().build();
        N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from(spec)))
    }

    /// [`ctx`] with the parent beacon root a Cancun-and-later block needs.
    fn timing_ctx(withdrawals: &[Withdrawal]) -> reth_evm_ethereum::EthBlockExecutionCtx<'_> {
        reth_evm_ethereum::EthBlockExecutionCtx { parent_beacon_block_root: Some(B256::ZERO), ..ctx(withdrawals) }
    }

    /// `header` with the fields a Cancun-and-later header carries.
    fn timing_header(mut header: alloy_consensus::Header) -> alloy_consensus::Header {
        header.parent_beacon_block_root = Some(B256::ZERO);
        header.blob_gas_used = Some(0);
        header.excess_blob_gas = Some(0);
        header.withdrawals_root = Some(alloy_consensus::EMPTY_ROOT_HASH);
        header.requests_hash = Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH);
        header
    }

    /// Clear of the precompiles (0x01-0x11): a value transfer to one of
    /// those runs out of gas at 21,000 and moves nothing.
    fn addr(i: u64) -> Address {
        Address::left_padding_from(&(0x1_0000 + i).to_be_bytes())
    }

    const BENEFICIARY: u64 = 0xbe;
    /// A contract that stores its calldata's first word at slot 0.
    const STORE: u64 = 0x5701;
    const FRESH: u64 = 0xf00d;
    const FUND: u64 = 1_000_000_000_000_000_000;

    fn parent() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for i in 1..=40 {
            db.insert_account_info(&addr(i), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        }
        db.insert_account_info(&alt_sender(), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        db.insert_account_info(&addr(BENEFICIARY), AccountInfo { balance: U256::from(1u64), ..Default::default() });
        // PUSH1 0 CALLDATALOAD PUSH1 0 SSTORE STOP
        let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00]));
        db.insert_account_info(&addr(STORE), AccountInfo::default().with_code(code));
        db
    }

    fn tx(from: u64, nonce: u64, to: Address, value: u64, gas_limit: u64, input: Bytes) -> Recovered<N42TxEnvelope> {
        let tx = TxEip1559 {
            chain_id: 1,
            nonce,
            gas_limit,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Call(to),
            value: U256::from(value),
            input,
            ..Default::default()
        };
        let signed = Signed::new_unchecked(tx, Signature::test_signature(), B256::left_padding_from(&(from * 1000 + nonce).to_be_bytes()));
        Recovered::new_unchecked(N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::from(signed)), addr(from))
    }

    fn transfer(from: u64, nonce: u64, to: Address, value: u64) -> Recovered<N42TxEnvelope> {
        tx(from, nonce, to, value, 21_000, Bytes::new())
    }

    fn env() -> reth_evm::EvmEnvFor<Config> {
        let header = n42_header::N42Header::from(alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            ..Default::default()
        });
        config().evm_env(&header).expect("env")
    }

    fn withdrawals() -> Vec<Withdrawal> {
        vec![
            Withdrawal { index: 0, validator_index: 0, address: addr(7), amount: 1 },
            Withdrawal { index: 1, validator_index: 0, address: addr(FRESH), amount: 2 },
        ]
    }

    fn ctx(withdrawals: &[Withdrawal]) -> reth_evm_ethereum::EthBlockExecutionCtx<'_> {
        reth_evm_ethereum::EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: B256::ZERO,
            parent_beacon_block_root: None,
            ommers: &[],
            withdrawals: Some(Cow::Borrowed(withdrawals)),
            extra_data: Default::default(),
            slot_number: None,
        }
    }

    /// The batches' part of the block: plain transfers, two senders paying
    /// one recipient, one creating its recipient, one sender with two (every
    /// one pays the beneficiary its fee; a transfer to the beneficiary is
    /// not the batches', `partition_by_sender`).
    fn batch_part() -> Vec<Recovered<N42TxEnvelope>> {
        vec![
            transfer(1, 0, addr(2), 100),
            transfer(3, 0, addr(FRESH), 100_000_000_000_000_000),
            transfer(5, 0, addr(2), 300),
            transfer(6, 0, addr(7), 400),
            transfer(8, 0, addr(9), 1),
            transfer(11, 0, addr(12), 6),
            transfer(11, 1, addr(13), 7),
        ]
    }

    /// The serial part after them: spending what the batches credited, a
    /// batch sender again, the created account spending, a contract call
    /// that writes storage.
    fn serial_part() -> Vec<Recovered<N42TxEnvelope>> {
        vec![
            transfer(2, 0, addr(9), 50),
            transfer(1, 1, addr(10), 60),
            transfer(FRESH, 0, addr(11), 10),
            transfer(10, 0, addr(BENEFICIARY), 5),
            tx(4, 0, addr(STORE), 0, 100_000, Bytes::from(B256::with_last_byte(0x2a).to_vec())),
        ]
    }

    fn keys(txs: &[Recovered<N42TxEnvelope>]) -> Vec<(Address, Address)> {
        use alloy_consensus::Transaction as _;
        txs.iter().map(|t| (t.signer(), t.to().unwrap_or_default())).collect()
    }

    fn sorted_reverts(bundle: &BundleState) -> Vec<Vec<(Address, String)>> {
        bundle
            .reverts
            .iter()
            .map(|block| {
                let mut v: Vec<_> = block.iter().map(|(a, r)| (*a, format!("{r:?}"))).collect();
                v.sort_by_key(|(a, _)| *a);
                v
            })
            .collect()
    }

    type Output = reth_evm::BlockExecutionOutput<n42_tx_types::Receipt>;

    /// The block executed transaction by transaction by the stock executor.
    fn sequential(txs: &[Recovered<N42TxEnvelope>]) -> Output {
        let c = config();
        let w = withdrawals();
        let mut ex = c.block_executor_factory().create_executor(c.evm_with_env(parent(), env()), ctx(&w));
        for t in txs {
            ex.execute_transaction(t.clone()).expect("the transaction executes");
        }
        ex.finish().expect("the block finishes")
    }

    fn run_batches(txs: &[Recovered<N42TxEnvelope>], worst_case: Option<&(dyn Fn(usize) -> U256 + Sync)>) -> Result<ParallelRun<Config>, Refused> {
        let c = config();
        let convert = |i: usize| txs[i].clone().map(evm2::ethereum::TxEnvelope::from);
        execute_batches(&c, &env(), &keys(txs), None, &convert, &|| Some(parent()), worst_case, addr(BENEFICIARY), Dispatch::LargestFirst(4))
    }

    /// The batches' part through [`execute_batches`] and [`commit_run`],
    /// then `serial` through the stock executor, finished with the fold.
    fn parallel(batch: &[Recovered<N42TxEnvelope>], serial: &[Recovered<N42TxEnvelope>]) -> (Output, usize) {
        use alloy_consensus::Typed2718 as _;
        let run = run_batches(batch, None).expect("the batches run");
        assert!(run.skipped.is_empty(), "skipped {:?}", run.skipped);
        let batches = run.batches;
        let c = config();
        let w = withdrawals();
        let mut ex = c.block_executor_factory().create_executor(c.evm_with_env(parent(), env()), ctx(&w));
        let results = run.executed.into_iter().map(|e| {
            let tx_type = n42_tx_types::N42TxType::try_from(batch[e.index].ty()).expect("a type");
            (e.result, tx_type)
        });
        commit_run(&mut ex, results, run.merged, CacheScope::All).expect("the cache half");
        for t in serial {
            ex.execute_transaction(t.clone()).expect("the transaction executes");
        }
        (ex.finish().expect("the block finishes with the fold"), batches)
    }

    fn assert_same(ours: &Output, theirs: &Output) {
        assert_eq!(ours.result.receipts, theirs.result.receipts, "receipts");
        assert_eq!(ours.result.gas_used, theirs.result.gas_used, "gas used");
        assert_eq!(ours.state.state, theirs.state.state, "state");
        assert_eq!(sorted_reverts(&ours.state), sorted_reverts(&theirs.state), "reverts");
        assert_eq!(ours.state.contracts, theirs.state.contracts, "contracts");
    }

    /// A mixed block -- batched transfers (shared recipients, a created
    /// recipient, the beneficiary), then a serial tail that spends what the
    /// batches credited and calls a contract that writes storage, then the
    /// withdrawals -- gives the receipts, gas and bundle (reverts included)
    /// the sequential execution of the same transactions gives. The state
    /// root is a function of that bundle over the same parent.
    #[test]
    fn the_parallel_build_equals_the_sequential_execution() {
        let (batch, serial) = (batch_part(), serial_part());
        let all: Vec<_> = batch.iter().chain(&serial).cloned().collect();
        let reference = sequential(&all);
        let (ours, batches) = parallel(&batch, &serial);
        assert!(batches >= 2, "{batches} batches");
        assert_same(&ours, &reference);
        assert_eq!(ours.result.receipts.len(), 12);
        // The contract call's storage is in the bundle, the created
        // account's original is the parent's absence.
        assert!(!ours.state.state[&addr(STORE)].storage.is_empty());
        assert_eq!(ours.state.state[&addr(FRESH)].original_info, None);
    }

    /// The batches alone, nothing after them but the withdrawals.
    #[test]
    fn a_block_of_only_batched_transfers_equals_the_sequential_execution() {
        let batch = batch_part();
        let reference = sequential(&batch);
        let (ours, _) = parallel(&batch, &[]);
        assert_same(&ours, &reference);
    }

    /// The batches' slots (F5g9): every slot written comes back in slot
    /// order in place; with holes (skipped candidates) the written ones in
    /// order; values neither read out nor kept are dropped exactly once.
    #[test]
    fn the_scatter_slots_give_the_executed_set_in_candidate_order() {
        let live = std::sync::Arc::new(());
        let slots = ScatterSlots::new(5);
        for i in [3usize, 0, 4, 1, 2] {
            slots.put(i, (i, std::sync::Arc::clone(&live)));
        }
        let all = slots.into_ordered();
        assert_eq!(all.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1, 2, 3, 4]);
        drop(all);
        let slots = ScatterSlots::new(5);
        for i in [4usize, 1] {
            slots.put(i, (i, std::sync::Arc::clone(&live)));
        }
        slots.put(1, (9, std::sync::Arc::clone(&live)));
        let some = slots.into_ordered();
        assert_eq!(some.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![1, 4]);
        drop(some);
        let slots = ScatterSlots::new(3);
        slots.put(2, (2, std::sync::Arc::clone(&live)));
        drop(slots);
        assert_eq!(std::sync::Arc::strong_count(&live), 1, "every value dropped once");
    }

    /// The late receipts (F5g7, `N42_EVM2_RECEIPTS_LATE`): the batches'
    /// merge handed to an executor that commits no receipt, its finish the
    /// block's end alone, and the receipts built off it, give the receipts,
    /// gas, requests and bundle of the sequential execution.
    #[test]
    fn the_late_receipts_equal_the_committed_ones() {
        use alloy_consensus::Typed2718 as _;
        let batch = batch_part();
        let reference = sequential(&batch);
        let run = run_batches(&batch, None).expect("the batches run");
        assert!(run.skipped.is_empty(), "skipped {:?}", run.skipped);
        let c = config();
        let w = withdrawals();
        let mut ex = c.block_executor_factory().create_executor(c.evm_with_env(parent(), env()), ctx(&w));
        commit_run(&mut ex, std::iter::empty(), run.merged, CacheScope::All).expect("the cache half");
        let mut out = ex.finish().expect("the block finishes with the fold");
        assert!(out.result.receipts.is_empty());
        let (receipts, gas) = late_receipts(run.executed.into_iter().map(|e| {
            let tx_type = n42_tx_types::N42TxType::try_from(batch[e.index].ty()).expect("a type");
            (e.result, tx_type)
        }));
        out.result.receipts = receipts;
        out.result.gas_used = gas;
        assert_same(&out, &reference);
        assert_eq!(out.result.requests, reference.result.requests, "requests");
    }

    /// A transfer the EVM refuses (a nonce ahead of the sender's) is
    /// skipped with its sender's later ones; the rest execute.
    #[test]
    fn a_refused_transfer_is_skipped_with_its_senders_later_ones() {
        let txs = vec![transfer(1, 0, addr(2), 1), transfer(3, 5, addr(4), 1), transfer(3, 6, addr(4), 1), transfer(6, 0, addr(7), 1)];
        let run = run_batches(&txs, None).expect("the batches run");
        assert_eq!(run.skipped, vec![1, 2]);
        assert_eq!(run.executed.iter().map(|e| e.index).collect::<Vec<_>>(), vec![0, 3]);
    }

    /// Under deferred execution a sender's summed worst case stays within
    /// its parent balance: the second transfer of a sender who could pay
    /// each but not both at the fee cap is skipped.
    #[test]
    fn the_worst_case_ledger_skips_a_transfer_over_the_balance() {
        let worst = |_: usize| U256::from(FUND / 2 + 1);
        let txs = vec![transfer(1, 0, addr(2), 1), transfer(1, 1, addr(2), 1), transfer(6, 0, addr(7), 1)];
        let run = run_batches(&txs, Some(&worst)).expect("the batches run");
        assert_eq!(run.skipped, vec![1]);
        assert_eq!(run.executed.len(), 2);
        assert!(run_batches(&txs, None).expect("the batches run").skipped.is_empty(), "the EVM alone takes both");
    }

    fn alt_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x50; 32])
    }

    /// The 0x50 (Ed25519) transfer's sender, funded in [`parent`].
    fn alt_sender() -> Address {
        alt_transfer(0).signer()
    }

    /// A signed 0x50 transfer of [`alt_sender`] at `nonce`.
    fn alt_transfer(nonce: u64) -> Recovered<N42TxEnvelope> {
        let key = alt_key();
        let tx = n42_tx_types::TxAltSig {
            chain_id: 1,
            nonce,
            max_priority_fee_per_gas: 3,
            max_fee_per_gas: 100,
            gas_limit: 21_000,
            to: addr(21),
            value: U256::from(5u64),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: n42_tx_types::ALG_ED25519,
            pubkey: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
        }
        .sign_ed25519(&key);
        let sender = tx.sender();
        Recovered::new_unchecked(N42TxEnvelope::AltSig(tx), sender)
    }

    /// `txs` as a block at [`env`]'s header, with [`withdrawals`].
    fn block_of(txs: &[Recovered<N42TxEnvelope>]) -> reth_primitives_traits::RecoveredBlock<n42_tx_types::Block> {
        let header = n42_header::N42Header::from(alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            ..Default::default()
        });
        let body = n42_tx_types::BlockBody {
            transactions: txs.iter().map(|t| t.inner().clone()).collect(),
            ommers: Vec::new(),
            withdrawals: Some(withdrawals().into()),
        };
        reth_primitives_traits::RecoveredBlock::new_unhashed(n42_tx_types::Block::new(header, body), txs.iter().map(|t| t.signer()).collect())
    }

    /// The stock import: the block through the stock executor over the parent.
    fn stock_import(block: &reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Output {
        use reth_evm::execute::Executor as _;
        config().executor(parent()).execute(block).expect("the stock import")
    }

    fn import(block: &reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Result<(Output, ImportStats), Refused> {
        import_block(&config(), block, parent(), &|| Some(parent()), Dispatch::LargestFirst(4), None)
    }

    /// The QMDB root of an output's bundle over an empty tree: the state
    /// root's function of the bundle, the parent being the same.
    fn qmdb_root(out: &Output) -> B256 {
        n42_qmdb_state::QmdbState::new()
            .apply_block(5, &n42_qmdb_reth::changes_from_execution(&out.state, false))
            .expect("the QMDB root")
    }

    fn receipts_root(out: &Output) -> B256 {
        use alloy_consensus::TxReceipt as _;
        alloy_consensus::proofs::calculate_receipt_root(&out.result.receipts.iter().map(|r| r.with_bloom_ref()).collect::<Vec<_>>())
    }

    fn assert_same_import(ours: &Output, stock: &Output) {
        assert_same(ours, stock);
        assert_eq!(receipts_root(ours), receipts_root(stock), "receipts root");
        assert_eq!(qmdb_root(ours), qmdb_root(stock), "QMDB root");
    }

    /// A mixed block -- batched transfers (shared recipients, a created
    /// recipient, a 0x50 sender), then a serial tail that spends what the
    /// batches credited, sends from a batch sender again, pays the
    /// beneficiary and calls a contract that writes storage, then the
    /// withdrawals (one to a batch recipient) -- imported in parallel gives
    /// the stock import's receipts, receipts root, bundle and QMDB root.
    #[test]
    fn the_parallel_import_of_a_mixed_block_equals_the_stock_import() {
        // The tail opens with the contract call: the transfers after it are
        // the tail's, not the batches'.
        let mut tail = serial_part();
        tail.rotate_right(1);
        let txs: Vec<_> = batch_part().into_iter().chain([alt_transfer(0)]).chain(tail).collect();
        let block = block_of(&txs);
        let stock = stock_import(&block);
        let parallel = imports_parallel();
        let (ours, stats) = import(&block).expect("the parallel import");
        // Process-wide, and the tests run beside each other.
        assert!(imports_parallel() > parallel);
        assert_eq!((stats.txs, stats.tail), (8, 5), "{stats:?}");
        assert!(stats.batches >= 2, "{stats:?}");
        assert_eq!(stats.cached, stats.accounts, "a tail follows: every batch account cached");
        assert_same_import(&ours, &stock);
        assert!(!ours.state.state[&addr(STORE)].storage.is_empty());
        assert_eq!(ours.state.state[&addr(FRESH)].original_info, None);
        // The plan made ahead (`N42_FOLLOWER_PARTITION_AHEAD`) is the one
        // made inside, and the import on it the same.
        let plan = plan_import(&block);
        assert_eq!(plan.keys.len(), 8);
        let (ahead, stats) = import_block(&config(), &block, parent(), &|| Some(parent()), Dispatch::LargestFirst(4), Some(plan)).expect("the import on the plan");
        assert!(stats.planned);
        assert_same_import(&ahead, &stock);
    }

    /// Leading transfers that spend in-block credits: a recipient with a
    /// parent balance of its own spends on the batches' view and the merge
    /// adds the credit to the debit, as the stock import does; an account
    /// the block creates has nothing on that view, so the batches skip its
    /// spend and the block is left to the serial import.
    #[test]
    fn leading_transfers_that_spend_in_block_credits_import_or_refuse() {
        let block = block_of(&[transfer(1, 0, addr(2), 100), transfer(2, 0, addr(9), 50), transfer(9, 0, addr(1), 7)]);
        let (ours, stats) = import(&block).expect("the parallel import");
        assert_eq!((stats.txs, stats.tail), (3, 0), "{stats:?}");
        assert_same_import(&ours, &stock_import(&block));
        let created = block_of(&[transfer(3, 0, addr(FRESH), 100_000_000_000_000_000), transfer(FRESH, 0, addr(11), 10)]);
        assert!(matches!(import(&created), Err(Refused::NotParallel(NotParallel::Failed(1, _)))));
    }

    /// A block of transfers only caches just the withdrawal recipients
    /// among the batch accounts (`keep_cache = false`) and still equals the
    /// stock import.
    #[test]
    fn a_block_of_transfers_imports_with_only_the_withdrawal_recipients_cached() {
        let txs: Vec<_> = batch_part().into_iter().chain([alt_transfer(0), alt_transfer(1)]).collect();
        let block = block_of(&txs);
        let stock = stock_import(&block);
        let (ours, stats) = import(&block).expect("the parallel import");
        assert_eq!((stats.txs, stats.tail), (9, 0), "{stats:?}");
        assert_eq!(stats.cached, 2, "addr(7) and the created recipient, both withdrawal recipients");
        assert!(stats.accounts > stats.cached);
        assert_same_import(&ours, &stock);
    }

    /// The fallback: a fold refused at finish refuses the import, counted,
    /// and the caller's serial import of the same block is the stock one;
    /// a block that opens with a contract call is not the batches' at all.
    #[test]
    fn a_refused_import_leaves_the_block_to_the_serial_import() {
        let block = block_of(&batch_part());
        let stock = stock_import(&block);
        let refused = imports_refused();
        let folds = crate::graft_fold::refused_count();
        crate::graft_fold::REFUSE_NEXT_FOLD.with(|next| next.set(true));
        let err = import(&block).expect_err("the fold refused");
        crate::graft_fold::REFUSE_NEXT_FOLD.with(|next| next.set(false));
        assert!(matches!(err, Refused::Fold(_)), "{err:?}");
        assert!(imports_refused() > refused);
        assert!(crate::graft_fold::refused_count() > folds);
        assert_same_import(&stock_import(&block), &stock);
        let call_first: Vec<_> = serial_part().into_iter().rev().collect();
        assert!(matches!(import(&block_of(&call_first)), Err(Refused::NotParallel(NotParallel::NotATransfer(0)))));
        // A transfer to a contract runs code: skipped on the batches, so the
        // block goes serial.
        let to_contract = vec![transfer(1, 0, addr(2), 1), tx(4, 0, addr(STORE), 0, 100_000, Bytes::new())];
        assert!(matches!(import(&block_of(&to_contract)), Err(Refused::NotParallel(NotParallel::Failed(1, _)))));
    }

    /// The cache half refuses, writing nothing, when the executor already
    /// holds a batch account at another value than the batches' original.
    #[test]
    fn the_cache_half_refuses_an_account_the_executor_holds_otherwise() {
        let run = run_batches(&batch_part(), None).expect("the batches run");
        let mut overlay = parent();
        overlay.insert_account_info(&addr(2), AccountInfo { balance: U256::from(5u64), ..Default::default() });
        let before = overlay.cache.accounts.clone();
        assert_eq!(install_cache(&mut overlay, &run.merged), Err(addr(2)));
        assert_eq!(overlay.cache.accounts, before, "nothing written");
        // Held at the parent's value it is overwritten.
        let mut overlay = parent();
        assert_eq!(install_cache(&mut overlay, &run.merged), Ok(run.merged.len()));
        assert_eq!(overlay.account_info(&addr(2)).map(|i| i.balance), run.merged.get(&addr(2)).map(|i| i.balance));
    }

    /// Where an evm2 leader's 200,000-transfer block goes (F5g): the
    /// batches, the transactions root the seal needs, the cache half and
    /// receipts (`commit_run`, both scopes), and the executor's finish with
    /// the fold. Senders and recipients in the replay set's shape (400
    /// senders of 500, recipients drawn from 2,000,000, nearly all created);
    /// the parent is an in-memory map, so the reads are a lower bound on
    /// the node's (QMDB view and overlay). Ignored; the pool's thread count
    /// is `N42_PARALLEL_BUILD_THREADS`:
    ///
    /// ```text
    /// N42_PARALLEL_BUILD_THREADS=32 cargo test --release -p n42-engine-types --lib \
    ///   evm2_step_bound -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "timing"]
    fn evm2_step_bound() {
        use std::time::Instant;
        let rounds = std::env::var("F5G_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(4usize);
        let senders = 400u64;
        let per_sender = 500u64;
        let sender = |s: u64| addr(0x10_0000 + s);
        let mut base = CacheDB::new(EmptyDB::default());
        for s in 0..senders {
            base.insert_account_info(&sender(s), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        }
        base.insert_account_info(&addr(BENEFICIARY), AccountInfo { balance: U256::from(1u64), ..Default::default() });
        let c = timing_config();
        let mut header = alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 21_000 * senders * per_sender,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            ..Default::default()
        };
        header.gas_limit += 21_000;
        let env = c.evm_env(&n42_header::N42Header::from(timing_header(header))).expect("env");
        let w = withdrawals();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let median = |mut v: Vec<u128>| {
            v.sort_unstable();
            v[v.len() / 2]
        };
        let (mut exec, mut root, mut fold_all, mut fold_only, mut finish) = (vec![], vec![], vec![], vec![], vec![]);
        let (mut shard_exec, mut freeze, mut shard_commit, mut shard_finish) = (vec![], vec![], vec![], vec![]);
        let (mut body_serial, mut body_pool) = (vec![], vec![]);
        let (mut late_finish, mut late_build) = (vec![], vec![]);
        for round in 0..rounds {
            let mut reference: Option<BundleState> = None;
            let mut txs = Vec::with_capacity((senders * per_sender) as usize);
            for s in 0..senders {
                for n in 0..per_sender {
                    let to = addr(0x100_0000 + next() % 2_000_000);
                    let mut t = transfer(0, n, to, 1 + round as u64);
                    t = Recovered::new_unchecked(t.into_inner(), sender(s));
                    txs.push(t);
                }
            }
            let keys = keys(&txs);
            let convert = |i: usize| txs[i].clone().map(evm2::ethereum::TxEnvelope::from);
            let open = || Some(base.clone());
            let at = Instant::now();
            let run = execute_batches(&c, &env, &keys, None, &convert, &open, None, addr(BENEFICIARY), Dispatch::from_env())
                .expect("the batches run");
            exec.push(at.elapsed().as_micros());
            assert_eq!(run.executed.len(), txs.len(), "skipped {}", run.skipped.len());
            let at = Instant::now();
            let signed: Vec<N42TxEnvelope> = txs.iter().map(|t| t.inner().clone()).collect();
            let _ = crate::assembler::parallel_transaction_root(&signed);
            root.push(at.elapsed().as_micros());
            // The seal's body (F5g items 3-4). Before: each executed
            // transaction cloned into the builder one by one, split into
            // transactions and senders at the seal, and its hashes collected
            // there. The fallback: the same three made on the build pool.
            // The plan path takes a body made ahead (a move).
            {
                use alloy_consensus::transaction::TxHashRef as _;
                use rayon::prelude::*;
                let at = Instant::now();
                let mut pushed = Vec::with_capacity(txs.len());
                for t in &txs {
                    pushed.push(t.clone());
                }
                let (transactions, senders): (Vec<N42TxEnvelope>, Vec<Address>) = pushed.into_iter().map(|t| t.into_parts()).unzip();
                let hashes: Vec<B256> = transactions.iter().map(|t| *t.tx_hash()).collect();
                body_serial.push(at.elapsed().as_micros());
                drop((transactions, senders, hashes));
                let at = Instant::now();
                #[allow(clippy::type_complexity)]
                let (transactions, (senders, hashes)): (Vec<N42TxEnvelope>, (Vec<Address>, Vec<B256>)) = build_pool().install(|| {
                    txs.par_iter().with_min_len(1024).map(|t| (t.inner().clone(), (t.signer(), *t.inner().tx_hash()))).unzip()
                });
                body_pool.push(at.elapsed().as_micros());
                drop((transactions, senders, hashes));
            }
            let accounts = run.merged.len();
            let mut first = Some(run);
            for only in [false, true] {
                let run = match first.take() {
                    Some(run) => run,
                    None => execute_batches(&c, &env, &keys, None, &convert, &open, None, addr(BENEFICIARY), Dispatch::from_env())
                        .expect("again"),
                };
                let ParallelRun { executed, merged, .. } = run;
                let mut ex = c.block_executor_factory().create_executor(c.evm_with_env(base.clone(), env.clone()), timing_ctx(&w));
                ex.apply_pre_execution_changes().expect("pre");
                let recipients: Vec<Address> = w.iter().map(|w| w.address).collect();
                let scope = if only { CacheScope::Only(&recipients) } else { CacheScope::All };
                let at = Instant::now();
                let results = executed.into_iter().map(|e| (e.result, <N42TxEnvelope as alloy_consensus::TransactionEnvelope>::tx_type(&signed[e.index])));
                commit_run(&mut ex, results, merged, scope).expect("the commit");
                let took = at.elapsed().as_micros();
                if only { fold_only.push(took) } else { fold_all.push(took) }
                let at = Instant::now();
                let out = ex.finish().expect("the finish");
                if only {
                    finish.push(at.elapsed().as_micros());
                }
                assert_eq!(out.result.receipts.len(), txs.len());
                if only {
                    reference = Some(out.state);
                }
            }
            // The shard path (F5g3): the batches' bundles filed into the
            // output shards on their threads, frozen behind the seal, the
            // beneficiary alone merged and folded at the finish.
            let shard_count = std::env::var("F5G_SHARDS").ok().and_then(|v| v.parse().ok()).unwrap_or(16usize);
            let shards = crate::output_shards::OutputShards::new(addr(BENEFICIARY), keys.len(), shard_count);
            let sink = |bundle: BundleState| shards.add(bundle);
            let at = Instant::now();
            let recipients: Vec<Address> = w.iter().map(|w| w.address).collect();
            let run = execute_batches_into(&c, &env, &keys, None, &convert, &open, None, addr(BENEFICIARY), Dispatch::from_env(), Some(&sink), &recipients)
                .expect("the sharded batches run");
            shard_exec.push(at.elapsed().as_micros());
            eprintln!(
                "round {round} shard batches: batches={} threads={} median_ms={} max_ms={} min_ms={} skew_ms={} last_start_us={} last_end_us={} open_sum_us={} txs_max={} txs_min={} wall_sum_us={} cpu_sum_us={} minflt={} vcsw={} ivcsw={} executed_size={} | inside us: reads={} transact={} commit={} shard_add={} reads_sampled={}",
                run.spans.batches, run.spans.threads, run.spans.median_ms, run.spans.max_ms, run.spans.min_ms, run.spans.start_skew_ms,
                run.spans.last_start_us, run.spans.last_end_us, run.spans.open_sum_us, run.spans.txs_max, run.spans.txs_min,
                run.spans.wall_sum_us, run.spans.cpu_sum_us, run.spans.minflt, run.spans.vcsw, run.spans.ivcsw,
                std::mem::size_of::<Executed<Config>>(),
                run.inside.reads_us, run.inside.transact_us, run.inside.commit_us, run.inside.shard_add_us, run.inside.reads_sampled,
            );
            eprintln!("round {round} outside the batches us: before={} gather={} merge={}", run.inside.before_us, run.inside.gather_us, run.inside.merge_us);
            let at = Instant::now();
            let frozen = shards.freeze();
            freeze.push(at.elapsed().as_micros());
            let ParallelRun { executed, merged, .. } = run;
            let mut ex = c.block_executor_factory().create_executor(c.evm_with_env(base.clone(), env.clone()), timing_ctx(&w));
            ex.apply_pre_execution_changes().expect("pre");
            let mut only = recipients;
            only.push(addr(BENEFICIARY));
            let at = Instant::now();
            let results = executed.into_iter().map(|e| (e.result, <N42TxEnvelope as alloy_consensus::TransactionEnvelope>::tx_type(&signed[e.index])));
            commit_run(&mut ex, results, merged, CacheScope::Only(&only)).expect("the sharded commit");
            shard_commit.push(at.elapsed().as_micros());
            let at = Instant::now();
            let out = ex.finish().expect("the sharded finish");
            shard_finish.push(at.elapsed().as_micros());
            assert_eq!(out.result.receipts.len(), txs.len());
            // The late receipts (F5g7): the same run, its receipts built off
            // the executor, which commits none and finishes with the block's
            // end alone. Receipts, gas and bundle must be the committed ones.
            {
                let shards2 = crate::output_shards::OutputShards::new(addr(BENEFICIARY), keys.len(), shard_count);
                let sink2 = |bundle: BundleState| shards2.add(bundle);
                let recipients2: Vec<Address> = w.iter().map(|w| w.address).collect();
                let run = execute_batches_into(&c, &env, &keys, None, &convert, &open, None, addr(BENEFICIARY), Dispatch::from_env(), Some(&sink2), &recipients2)
                    .expect("the late-receipts run");
                let frozen2 = shards2.freeze();
                let ParallelRun { executed, merged, .. } = run;
                let mut ex = c.block_executor_factory().create_executor(c.evm_with_env(base.clone(), env.clone()), timing_ctx(&w));
                ex.apply_pre_execution_changes().expect("pre");
                let types: Vec<_> = executed.iter().map(|e| <N42TxEnvelope as alloy_consensus::TransactionEnvelope>::tx_type(&signed[e.index])).collect();
                let at = Instant::now();
                commit_run(&mut ex, std::iter::empty(), merged, CacheScope::Only(&only)).expect("the late commit");
                let late_out = ex.finish().expect("the late finish");
                late_finish.push(at.elapsed().as_micros());
                let at = Instant::now();
                let (receipts, gas) = late_receipts(executed.into_iter().zip(types).map(|(e, t)| (e.result, t)));
                late_build.push(at.elapsed().as_micros());
                assert_eq!(receipts, out.result.receipts, "the late receipts");
                assert_eq!(gas, out.result.gas_used, "the late gas");
                assert_eq!(late_out.result.requests, out.result.requests, "the requests");
                let late_whole = frozen2.merged(&late_out.state);
                let whole = frozen.merged(&out.state);
                assert_eq!(late_whole.state.len(), whole.state.len(), "the late accounts");
                for (address, account) in &whole.state {
                    let got = late_whole.state.get(address).expect("the account under the late residual");
                    assert_eq!((&got.info, &got.status), (&account.info, &account.status), "{address}");
                }
            }
            // The shards under the residual are the bundle the fold leaves.
            let whole = frozen.merged(&out.state);
            let reference = reference.take().expect("the fold path's bundle");
            assert_eq!(whole.state.len(), reference.state.len(), "the accounts");
            for (address, account) in &reference.state {
                let got = whole.state.get(address).expect("the account in the shards' bundle");
                assert_eq!((&got.info, &got.original_info, &got.status), (&account.info, &account.original_info, &account.status), "{address}");
            }
            let reverts = |b: &BundleState| {
                let mut all: Vec<_> = b.reverts.iter().flatten().map(|(a, r)| (*a, format!("{r:?}"))).collect();
                all.sort();
                all
            };
            assert_eq!(reverts(&whole), reverts(&reference), "the reverts");
            drop((out, frozen, whole, reference));
            eprintln!(
                "round {round}: txs={} accounts={accounts} exec_us={} root_us={} commit_all_us={} commit_only_us={} finish_us={} | shards={shard_count} exec_us={} freeze_us={} commit_us={} finish_us={}",
                txs.len(),
                exec[round],
                root[round],
                fold_all[round],
                fold_only[round],
                finish[round],
                shard_exec[round],
                freeze[round],
                shard_commit[round],
                shard_finish[round],
            );
        }
        eprintln!(
            "evm2_step_bound medians over {rounds}: threads={} exec_ms={:.1} root_ms={:.1} commit_all_ms={:.1} commit_only_ms={:.1} finish_ms={:.1}",
            build_pool().current_num_threads(),
            median(exec) as f64 / 1000.0,
            median(root) as f64 / 1000.0,
            median(fold_all) as f64 / 1000.0,
            median(fold_only) as f64 / 1000.0,
            median(finish) as f64 / 1000.0,
        );
        eprintln!(
            "evm2_step_bound shard path medians: exec_ms={:.1} freeze_ms={:.1} commit_ms={:.1} finish_ms={:.1}",
            median(shard_exec) as f64 / 1000.0,
            median(freeze) as f64 / 1000.0,
            median(shard_commit) as f64 / 1000.0,
            median(shard_finish) as f64 / 1000.0,
        );
        eprintln!(
            "evm2_step_bound late receipts medians: commit_and_finish_ms={:.1} receipts_ms={:.1}",
            median(late_finish) as f64 / 1000.0,
            median(late_build) as f64 / 1000.0,
        );
        eprintln!(
            "evm2_step_bound seal body medians: serial_ms={:.1} build_pool_ms={:.1}",
            median(body_serial) as f64 / 1000.0,
            median(body_pool) as f64 / 1000.0,
        );
    }

    /// One evm2 batch, timed section by section on one thread (F5g2): what a
    /// transfer costs inside `execute_batches`' batch loop. 40 senders of
    /// 500 transfers to recipients drawn from 2,000,000 (nearly all
    /// created), the parent an in-memory map. Ignored:
    ///
    /// ```text
    /// cargo test --release -p n42-engine-types --lib evm2_batch_split -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "timing"]
    fn evm2_batch_split() {
        use std::time::Instant;
        let senders = 40u64;
        let per_sender = 500u64;
        let sender = |s: u64| addr(0x10_0000 + s);
        let mut base = CacheDB::new(EmptyDB::default());
        for s in 0..senders {
            base.insert_account_info(&sender(s), AccountInfo { balance: U256::from(FUND), ..Default::default() });
        }
        base.insert_account_info(&addr(BENEFICIARY), AccountInfo { balance: U256::from(1u64), ..Default::default() });
        let c = timing_config();
        let header = alloy_consensus::Header {
            number: 5,
            timestamp: 1_000,
            gas_limit: 30_000_000_000,
            base_fee_per_gas: Some(7),
            beneficiary: addr(BENEFICIARY),
            ..Default::default()
        };
        let env = c.evm_env(&n42_header::N42Header::from(timing_header(header))).expect("env");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..9u64 {
            let fast = round % 3 != 1;
            // The third of each three: the inherent `transact` (no detach),
            // the batch state fed from the borrowed changes, then `commit`.
            let inherent = round % 3 == 2;
            let mut txs = Vec::with_capacity((senders * per_sender) as usize);
            for s in 0..senders {
                for n in 0..per_sender {
                    let to = addr(0x100_0000 + next() % 2_000_000);
                    txs.push(Recovered::new_unchecked(transfer(0, n, to, 1 + round).into_inner(), sender(s)));
                }
            }
            let n = txs.len() as u128;
            let (mut t_convert, mut t_transact, mut t_batch, mut t_commit, mut t_push) = (0u128, 0u128, 0u128, 0u128, 0u128);
            let at = Instant::now();
            let make = || c.evm_with_env(base.clone(), env.clone());
            let mut evm = if fast { crate::fast_handler::as_batch(make) } else { make() };
            let mut state = crate::batch_state::BatchState::with_capacity(txs.len() * 2 + 1);
            let mut executed = Vec::with_capacity(txs.len());
            let t_open = at.elapsed().as_nanos();
            let hits = crate::fast_handler::hits();
            let whole = Instant::now();
            for (i, t) in txs.iter().enumerate() {
                let a = Instant::now();
                let tx = t.clone().map(evm2::ethereum::TxEnvelope::from);
                let b = Instant::now();
                if inherent {
                    let out = evm.transact(&tx).expect("the transfer");
                    let c2 = Instant::now();
                    for changes in out.account_changes() {
                        state.commit_account(changes).expect("modelled");
                    }
                    let d = Instant::now();
                    let result = out.commit();
                    let e = Instant::now();
                    executed.push((i, result));
                    let f = Instant::now();
                    t_convert += (b - a).as_nanos();
                    t_transact += (c2 - b).as_nanos();
                    t_batch += (d - c2).as_nanos();
                    t_commit += (e - d).as_nanos();
                    t_push += (f - e).as_nanos();
                    continue;
                }
                let out = reth_evm::Evm::transact(&mut evm, &tx).expect("the transfer");
                let c2 = Instant::now();
                state.commit(&out.pending_state).expect("modelled");
                let d = Instant::now();
                reth_evm::Evm::commit_state(&mut evm, &out.pending_state);
                let e = Instant::now();
                executed.push((i, out.result));
                let f = Instant::now();
                t_convert += (b - a).as_nanos();
                t_transact += (c2 - b).as_nanos();
                t_batch += (d - c2).as_nanos();
                t_commit += (e - d).as_nanos();
                t_push += (f - e).as_nanos();
            }
            let t_loop = whole.elapsed().as_nanos();
            let at = Instant::now();
            let bundle = state.take_bundle();
            let t_take = at.elapsed().as_nanos();
            let at = Instant::now();
            let accounts = bundle.state.len();
            let merged = merge_batches(vec![bundle]).expect("merge");
            let t_merge = at.elapsed().as_nanos();
            let at = Instant::now();
            drop((evm, executed, merged));
            let t_drop = at.elapsed().as_nanos();
            eprintln!(
                "split fast={fast} inherent={inherent} txs={n} accounts={accounts} hits={} per tx ns: loop={} convert={} transact={} batch_state={} commit_state={} push={} | per batch us: open={} take_bundle={} merge={} drop={}",
                crate::fast_handler::hits() - hits,
                t_loop / n,
                t_convert / n,
                t_transact / n,
                t_batch / n,
                t_commit / n,
                t_push / n,
                t_open / 1000,
                t_take / 1000,
                t_merge / 1000,
                t_drop / 1000,
            );
        }
    }
}

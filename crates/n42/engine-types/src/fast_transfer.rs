// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A plain value transfer applied without the interpreter.
//!
//! At the bench tier a block is 163,000 transfers between externally owned
//! accounts, and revm spends about 1.4 us on each: a journal, a frame, a
//! call into an account with no code, the journal's finalisation. The state
//! transition of such a transfer is three balance changes and a nonce, and
//! this module applies exactly that -- with revm's own arithmetic, in revm's
//! own order, producing the accounts revm's journal would hand back and the
//! result its handler would build -- and only when it can prove revm would
//! succeed and charge exactly the base cost. Anything else, and every
//! transaction on a fork this module has not been checked against, goes to
//! the interpreter unchanged. Every node executes every transaction either
//! way; nothing is skipped, and the post-state is the same to the byte.
//!
//! What qualifies: a call (legacy, EIP-2930 or EIP-1559) with no calldata, no
//! access list, no blob and no authorisation, from an account without code,
//! to an account without code that is not a precompile, with the nonce, the
//! balance and the fees revm's pre-execution checks demand, on Prague or
//! Osaka. The sender, the recipient and the block's beneficiary must be three
//! distinct accounts, the recipient must not be left empty (EIP-161) and the
//! beneficiary must already exist and not be empty, so that no account's
//! existence changes in a way this module would have to model.
//!
//! `N42_FAST_TRANSFER=1` turns it on; it is off by default so that a fleet
//! can measure it against the interpreter on the same binary.
// The stock evm2 build leaves the revm-era paths out (`legacy-revm-paths`): what only they
// use or mutate reads as dead here until F5 ports or removes them (docs/RETH_2_9_0_UPGRADE.md).
#![cfg_attr(
    not(feature = "legacy-revm-paths"),
    allow(dead_code, unused_mut, unused_variables, unused_assignments, unused_imports)
)]

#[cfg(feature = "legacy-revm-paths")]
use alloy_primitives::{Address, Bytes, U256};
#[cfg(feature = "legacy-revm-paths")]
use reth_evm::{
    eth::{EthEvmBuilder, EthEvmContext},
    precompiles::PrecompilesMap,
    Database, EthEvm, Evm, EvmEnv, EvmFactory,
};
#[cfg(feature = "legacy-revm-paths")]
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::{
        result::{EVMError, ExecutionResult, HaltReason, Output, ResultAndState, ResultGas, SuccessReason},
        Block as _, Cfg as _, Transaction as _,
    },
    database_interface::DBErrorMarker,
    inspector::NoOpInspector,
    primitives::{hardfork::SpecId, TxKind},
    state::{Account, AccountInfo, EvmState, TransactionId},
    Inspector,
};

/// The gas of a call with no calldata: the whole cost of a qualifying transfer.
pub(crate) const TRANSFER_GAS: u64 = 21_000;

/// How many transfers have taken this path in this process.
static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many transfers have taken this path in this process, so far.
pub fn hits() -> u64 {
    HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Why transfers were sent to the interpreter instead, by reason, so a
/// fleet that shows no hits says which check refused them.
static REJECTED: [std::sync::atomic::AtomicU64; 12] = [const { std::sync::atomic::AtomicU64::new(0) }; 12];

/// The refusals so far, by reason: shape, fork, configuration, limits, fees,
/// parties, sender, balance, recipient, beneficiary, arithmetic, inspecting.
pub fn rejected() -> [u64; 12] {
    std::array::from_fn(|i| REJECTED[i].load(std::sync::atomic::Ordering::Relaxed))
}

#[cfg(feature = "legacy-revm-paths")]
fn refused<T, E>(reason: usize) -> Result<Option<T>, E> {
    REJECTED[reason].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(None)
}

/// Whether `N42_FAST_TRANSFER=1` is set.
pub fn enabled() -> bool {
    if !crate::legacy_paths::LEGACY_REVM_PATHS {
        return false;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FAST_TRANSFER").map(|v| v == "1").unwrap_or(false))
}

/// Whether `N42_PHASE_TIMERS=1` is set (plan v6 6.5/6.6): per-batch phase
/// timers for the fast-transfer path -- where a transfer's time goes between
/// its account reads, its arithmetic and the state it writes back, and which
/// door each read took (the batch's own `State` cache, the state provider, or
/// the QMDB view through [`reth_storage_api::n42_state`]).
///
/// Off by default, and off leaves the per-transaction path exactly as it was:
/// every check below is `if timers`, so with the flag unset [`transfer`]
/// makes no [`std::time::Instant`] call and touches no thread-local, and
/// [`self::doors::CountedDb`] in `parallel_transfer` skips straight to its
/// inner database.
pub fn phase_timers() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PHASE_TIMERS").is_ok_and(|v| v == "1"))
}

/// Per-batch phase timers for [`N42Evm::transfer`] (`N42_PHASE_TIMERS=1`).
///
/// The nanosecond fields are sampled, not measured on every call: reading
/// [`std::time::Instant::now`] on every one of a batch's transfers was itself
/// a meaningful fraction of a transfer's ~400 ns (loop228's question was
/// exactly how little there is to measure), so only every
/// [`SAMPLE_STRIDE`]-th transfer is timed in full and the sum is scaled by
/// `calls / samples` when drained -- the plan's own allowance ("per-batch
/// sampling... is acceptable"). The read-door counts are exact: they cost one
/// thread-local increment per `db.basic` call, no clock read, so every
/// transfer's reads are counted whether or not that transfer was sampled.
///
/// Error this introduces: the scaled nanosecond totals are a batch-level
/// estimate (coefficient of variation on the order of `1/sqrt(samples)`,
/// a few percent at a batch's few thousand transfers) and assume the sampled
/// transfers are representative of the batch's un-sampled ones, which holds
/// for a block of plain transfers between similar accounts but would not for
/// one where the fast path's cost varied a lot by address. The read-door
/// split (cache / provider / view) is exact for reads that reach
/// [`self::doors`] on this thread, but the view-vs-provider call there reads
/// a process-wide counter ([`reth_storage_api::n42_state::stats`]) before and
/// after its own call: on a fleet with several batches reading concurrently,
/// another thread's read landing in that same narrow window can misattribute
/// one read in either direction. Neither error affects the block's actual
/// execution or its root; both are diagnostic only.
mod timers {
    use std::cell::Cell;

    /// One fine timing in `SAMPLE_STRIDE`.
    pub(super) const SAMPLE_STRIDE: u64 = 64;

    thread_local! {
        /// `transfer` calls on this thread since the last drain.
        static CALLS: Cell<u64> = const { Cell::new(0) };
        /// Of those, how many were sampled in full.
        static SAMPLES: Cell<u64> = const { Cell::new(0) };
        /// Sampled nanoseconds in the accounts' reads.
        static READ_NS: Cell<u64> = const { Cell::new(0) };
        /// Sampled nanoseconds in the qualification checks and the arithmetic.
        static EVM_NS: Cell<u64> = const { Cell::new(0) };
        /// Sampled nanoseconds building the touched accounts.
        static WRITE_NS: Cell<u64> = const { Cell::new(0) };
        /// Sampled nanoseconds after the write, before the call returns.
        static OTHER_NS: Cell<u64> = const { Cell::new(0) };
        /// `db.basic` calls `transfer` made on this thread, exact (every call,
        /// not only sampled ones).
        static READS_ATTEMPTED: Cell<u64> = const { Cell::new(0) };
        /// Of those, how many reached [`super::doors`] and were answered by
        /// the state provider (not the QMDB view).
        static READS_PROVIDER: Cell<u64> = const { Cell::new(0) };
        /// Of those, how many reached [`super::doors`] and were answered by
        /// the QMDB view (`N42StateReader`).
        static READS_VIEW: Cell<u64> = const { Cell::new(0) };
    }

    #[inline]
    fn add(cell: &'static std::thread::LocalKey<Cell<u64>>, ns: u64) {
        cell.with(|c| c.set(c.get() + ns));
    }

    /// Whether the call about to start should be timed in full: every
    /// `SAMPLE_STRIDE`-th call on this thread.
    #[inline]
    pub(super) fn begin_call() -> bool {
        let n = CALLS.with(|c| {
            let n = c.get() + 1;
            c.set(n);
            n
        });
        // Mid-stride: sampling a batch's first (coldest) call weighed it
        // once in a stride instead of once in the batch (step 4b: `read_ns`
        // read 3.1 us a transfer on the bench, more than the whole call).
        n % SAMPLE_STRIDE == SAMPLE_STRIDE / 2
    }

    #[inline]
    pub(super) fn sample_done() {
        SAMPLES.with(|c| c.set(c.get() + 1));
    }

    #[inline]
    pub(super) fn add_read_ns(ns: u64) {
        add(&READ_NS, ns);
    }
    #[inline]
    pub(super) fn add_evm_ns(ns: u64) {
        add(&EVM_NS, ns);
    }
    #[inline]
    pub(super) fn add_write_ns(ns: u64) {
        add(&WRITE_NS, ns);
    }
    #[inline]
    pub(super) fn add_other_ns(ns: u64) {
        add(&OTHER_NS, ns);
    }

    #[inline]
    pub(super) fn note_read_attempted() {
        READS_ATTEMPTED.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub(super) fn note_read_provider() {
        READS_PROVIDER.with(|c| c.set(c.get() + 1));
    }
    #[inline]
    pub(super) fn note_read_view() {
        READS_VIEW.with(|c| c.set(c.get() + 1));
    }

    /// This thread's timers since the last drain, zeroing them.
    pub(super) fn drain() -> super::TransferTimers {
        let calls = CALLS.with(|c| c.replace(0));
        let samples = SAMPLES.with(|c| c.replace(0));
        let read = READ_NS.with(|c| c.replace(0));
        let evm = EVM_NS.with(|c| c.replace(0));
        let write = WRITE_NS.with(|c| c.replace(0));
        let other = OTHER_NS.with(|c| c.replace(0));
        let attempted = READS_ATTEMPTED.with(|c| c.replace(0));
        let provider = READS_PROVIDER.with(|c| c.replace(0));
        let view = READS_VIEW.with(|c| c.replace(0));
        // Scaled from the sample to the thread's whole call count; 0 samples
        // (a batch smaller than the stride, or the flag toggled mid-batch)
        // leaves the nanosecond fields at 0 rather than dividing by it.
        let scale = if samples == 0 { 0.0 } else { calls as f64 / samples as f64 };
        super::TransferTimers {
            read_ns: (read as f64 * scale) as u64,
            evm_ns: (evm as f64 * scale) as u64,
            write_ns: (write as f64 * scale) as u64,
            other_ns: (other as f64 * scale) as u64,
            reads_attempted: attempted,
            reads_provider: provider,
            reads_view: view,
        }
    }
}

/// A door a `db.basic` call inside [`N42Evm::transfer`] can take, counted by
/// [`doors::CountedDb`] when [`phase_timers`] is on: the batch's own `State`
/// cache (never reaches here), the state provider (the hashed tables, or the
/// QMDB view declining), or the QMDB view itself
/// (`reth_storage_api::n42_state`, `N42StateReader`).
#[cfg(feature = "legacy-revm-paths")]
pub mod doors {
    use alloy_primitives::Address;
    use revm::{state::AccountInfo, Database};

    /// Wraps a batch's database and counts, per [`super::timers`], whether
    /// each `basic` call it answers was the QMDB view or the state provider
    /// otherwise. A call this wrapper never sees (answered by the batch's own
    /// `State` cache, or by a warmed layer in front of it such as
    /// `parallel_transfer::WarmDb`) is what [`super::TransferTimers`]
    /// attributes to the cache: `reads_attempted` less `reads_provider` and
    /// `reads_view`.
    #[derive(Debug)]
    pub struct CountedDb<G> {
        inner: G,
    }

    impl<G> CountedDb<G> {
        /// `inner`, with its `basic` calls counted by door when
        /// [`super::phase_timers`] is on.
        pub const fn new(inner: G) -> Self {
            Self { inner }
        }
    }

    impl<G: crate::parallel_transfer::AccountHint> crate::parallel_transfer::AccountHint for CountedDb<G> {
        /// Passed through uncounted: a hint is not a read.
        #[inline]
        fn hint_account(&self, address: &Address) -> bool {
            self.inner.hint_account(address)
        }
    }

    impl<G: Database> Database for CountedDb<G> {
        type Error = G::Error;

        #[inline]
        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            if !super::phase_timers() {
                return self.inner.basic(address);
            }
            // The QMDB view's answered-reads counter of this thread's slot,
            // read before and after this call: if it moved, this call is what
            // moved it. Only a thread sharing the slot (64, round robin) can
            // misattribute a read -- see [`super::phase_timers`].
            let before = reth_storage_api::n42_state::thread_answers();
            let out = self.inner.basic(address);
            let after = reth_storage_api::n42_state::thread_answers();
            if after != before {
                super::timers::note_read_view();
            } else {
                super::timers::note_read_provider();
            }
            out
        }

        #[inline]
        fn code_by_hash(&mut self, code_hash: alloy_primitives::B256) -> Result<revm::state::Bytecode, Self::Error> {
            self.inner.code_by_hash(code_hash)
        }

        #[inline]
        fn storage(&mut self, address: Address, index: revm::primitives::StorageKey) -> Result<revm::primitives::StorageValue, Self::Error> {
            self.inner.storage(address, index)
        }

        #[inline]
        fn block_hash(&mut self, number: u64) -> Result<alloy_primitives::B256, Self::Error> {
            self.inner.block_hash(number)
        }
    }
}

/// [`timers`]'s totals for one thread since the last drain
/// ([`drain_timers`]): nanoseconds are sampled and scaled, read-door counts
/// are exact. Zero in every field when [`phase_timers`] is off.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferTimers {
    /// Nanoseconds in the accounts' reads (all doors), sampled.
    pub read_ns: u64,
    /// Nanoseconds in the qualification checks and the arithmetic, sampled.
    pub evm_ns: u64,
    /// Nanoseconds building the touched accounts, sampled.
    pub write_ns: u64,
    /// Nanoseconds this sampling method cannot place in the three above,
    /// sampled.
    pub other_ns: u64,
    /// `db.basic` calls made, exact.
    pub reads_attempted: u64,
    /// Of those, answered by the state provider (not the QMDB view), exact.
    pub reads_provider: u64,
    /// Of those, answered by the QMDB view, exact.
    pub reads_view: u64,
}

impl TransferTimers {
    /// Adds `other`'s counts into `self`: a batch's whole [`TransferTimers`]
    /// is the sum of what every thread that ran part of it drained.
    pub fn add(&mut self, other: Self) {
        self.read_ns += other.read_ns;
        self.evm_ns += other.evm_ns;
        self.write_ns += other.write_ns;
        self.other_ns += other.other_ns;
        self.reads_attempted += other.reads_attempted;
        self.reads_provider += other.reads_provider;
        self.reads_view += other.reads_view;
    }

    /// `reads_attempted` less `reads_provider` and `reads_view`: calls a
    /// `db.basic` in [`N42Evm::transfer`] made that never reached
    /// [`doors::CountedDb`], answered by the batch's own `State` cache (or a
    /// warm layer in front of it).
    pub fn reads_cache(&self) -> u64 {
        self.reads_attempted.saturating_sub(self.reads_provider).saturating_sub(self.reads_view)
    }
}

/// Drains this thread's [`TransferTimers`] since the last call, zeroing them.
/// Call once per batch, on the batch's own thread, right after its transfers
/// are done -- the caller sums what every batch's thread drained into the
/// block's phases.
pub fn drain_timers() -> TransferTimers {
    timers::drain()
}

// The factory, the EVM wrapper and the transfer itself, written against revm 43.
#[cfg(feature = "legacy-revm-paths")]
include!("fast_transfer_legacy.rs");

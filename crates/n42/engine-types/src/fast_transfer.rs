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

use alloy_primitives::{Address, Bytes, U256};
use reth_evm::{
    eth::{EthEvmBuilder, EthEvmContext},
    precompiles::PrecompilesMap,
    Database, EthEvm, Evm, EvmEnv, EvmFactory,
};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::{
        result::{EVMError, ExecutionResult, HaltReason, Output, ResultAndState, ResultGas, SuccessReason},
        Block as _, Cfg as _, Transaction as _,
    },
    database_interface::DBErrorMarker,
    inspector::NoOpInspector,
    primitives::{hardfork::SpecId, HashMap, TxKind},
    state::{Account, EvmState, TransactionId},
    Inspector,
};

/// The gas of a call with no calldata: the whole cost of a qualifying transfer.
const TRANSFER_GAS: u64 = 21_000;

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

fn refused<T, E>(reason: usize) -> Result<Option<T>, E> {
    REJECTED[reason].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(None)
}

/// Whether `N42_FAST_TRANSFER=1` is set.
pub fn enabled() -> bool {
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
        n % SAMPLE_STRIDE == 1
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

    impl<G: Database> Database for CountedDb<G> {
        type Error = G::Error;

        #[inline]
        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            if !super::phase_timers() {
                return self.inner.basic(address);
            }
            // The QMDB view's own answered-reads counter, read before and
            // after this call: if it moved, this call is what moved it. A
            // concurrent batch's read landing in the same window can
            // misattribute one read either way -- see [`super::phase_timers`].
            let before = reth_storage_api::n42_state::stats().3;
            let out = self.inner.basic(address);
            let after = reth_storage_api::n42_state::stats().3;
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

/// [`EthEvmFactory`](reth_evm::EthEvmFactory) with the transfer path in front
/// of the interpreter.
#[derive(Debug, Clone, Copy, Default)]
pub struct N42EvmFactory {
    fast: bool,
}

impl N42EvmFactory {
    /// A factory whose EVMs take the transfer path when `N42_FAST_TRANSFER=1`.
    pub fn from_env() -> Self {
        Self { fast: enabled() }
    }

    /// A factory whose EVMs take (or never take) the transfer path.
    pub const fn with_fast_transfers(fast: bool) -> Self {
        Self { fast }
    }
}

impl EvmFactory for N42EvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = N42Evm<DB, I>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        N42Evm { inner: EthEvmBuilder::new(db, input).build(), inspecting: false, fast: self.fast }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        N42Evm {
            inner: EthEvmBuilder::new(db, input).activate_inspector(inspector).build(),
            inspecting: true,
            fast: self.fast,
        }
    }
}

/// [`EthEvm`] with the transfer path in front of the interpreter.
pub struct N42Evm<DB: Database, I> {
    inner: EthEvm<DB, I, PrecompilesMap>,
    /// An inspector is watching: every transaction goes through the
    /// interpreter, which is what the inspector expects to see.
    inspecting: bool,
    fast: bool,
}

impl<DB: Database, I> std::fmt::Debug for N42Evm<DB, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("N42Evm").field("inspecting", &self.inspecting).field("fast", &self.fast).finish_non_exhaustive()
    }
}

impl<DB: Database, I: Inspector<EthEvmContext<DB>>> N42Evm<DB, I> {
    /// The transfer's result and post-state, if the transaction qualifies and
    /// revm would succeed on it; `None` sends it to the interpreter. A database
    /// error is the same error the interpreter would have hit loading the
    /// account.
    pub(crate) fn transfer(&mut self, tx: &TxEnv) -> Result<Option<ResultAndState>, DB::Error> {
        // The transaction's shape.
        let TxKind::Call(to) = tx.kind else { return refused(0) };
        if !tx.data.is_empty()
            || tx.tx_type > 2
            || !tx.access_list.0.is_empty()
            || !tx.authorization_list.is_empty()
            || !tx.blob_hashes.is_empty()
            || tx.gas_limit < TRANSFER_GAS
        {
            return refused(0);
        }
        let cfg = self.inner.cfg_env();
        let block = self.inner.block();
        // The forks this path is checked against: after EIP-7623 and EIP-7702
        // (Prague), before EIP-7708's transfer logs and EIP-8037's state gas
        // (Amsterdam).
        let spec = cfg.spec();
        if !spec.is_enabled_in(SpecId::PRAGUE) || spec.is_enabled_in(SpecId::AMSTERDAM) {
            return refused(1);
        }
        // Every check revm makes before executing, as revm makes it; a
        // configuration that relaxes any of them is not modelled here.
        if cfg.is_nonce_check_disabled()
            || cfg.is_balance_check_disabled()
            || cfg.is_eip3607_disabled()
            || cfg.is_fee_charge_disabled()
            || cfg.is_base_fee_check_disabled()
            || cfg.is_priority_fee_check_disabled()
            || cfg.is_block_gas_limit_disabled()
            || cfg.is_eip7623_disabled()
        {
            return refused(2);
        }
        if tx.chain_id.is_some_and(|id| id != cfg.chain_id())
            || tx.gas_limit > cfg.tx_gas_limit_cap()
            || tx.gas_limit > block.gas_limit()
        {
            return refused(3);
        }
        let basefee = block.basefee() as u128;
        if tx.gas_price < basefee || tx.gas_priority_fee.is_some_and(|tip| tip > tx.gas_price) {
            return refused(4);
        }
        let caller = tx.caller;
        let beneficiary = block.beneficiary();
        if to == caller || to == beneficiary || caller == beneficiary {
            return refused(5);
        }
        // Every precompile lives below address 0x10000 (the BLS set ends at
        // 0x11, RIP-7212 is 0x100): a recipient with any of its first
        // eighteen bytes set is not one. The map lookup this replaces was 2%
        // of a follower's engine thread; the rare low address still asks.
        if to[..18].iter().any(|b| *b != 0) {
            // not a precompile
        } else if self.inner.precompiles().get(&to).is_some() {
            return refused(5);
        }

        // The accounts, loaded the way the journal would load them: through
        // the same database, so its cache holds them as the pre-state.
        //
        // `N42_PHASE_TIMERS=1` (plan v6 6.5/6.6): checkpoints around each
        // read and around the arithmetic and the write that follow it, kept
        // only on a sampled call (see `timers`) so the clock is read at most
        // once in `SAMPLE_STRIDE` transfers; a refusal anywhere below simply
        // returns before its later checkpoints run, and that call's sample
        // (if it was one) contributes nothing to `read_ns`/`evm_ns`/etc,
        // which is the intended target for these timers: the qualifying,
        // fully-executed transfer this path exists for.
        let value = tx.value;
        let db = self.inner.db_mut();
        let timers = phase_timers();
        let sample = timers && timers::begin_call();
        let now = || sample.then(std::time::Instant::now);
        let t0 = now();
        if timers {
            timers::note_read_attempted();
        }
        let Some(sender) = db.basic(caller)? else { return refused(6) };
        let t1 = now();
        if !sender.is_code_hash_empty_or_zero() || sender.nonce != tx.nonce || sender.nonce == u64::MAX {
            return refused(6);
        }
        let Ok(max_spending) = tx.max_balance_spending() else { return refused(7) };
        if max_spending > sender.balance {
            return refused(7);
        }
        let t2 = now();
        if timers {
            timers::note_read_attempted();
        }
        let recipient = db.basic(to)?;
        let t3 = now();
        match &recipient {
            Some(info) if !info.is_code_hash_empty_or_zero() => return refused(8),
            // An account that stays empty after being touched is deleted
            // (EIP-161); the interpreter models that, this does not.
            Some(info) if value.is_zero() && info.is_empty() => return refused(8),
            None if value.is_zero() => return refused(8),
            _ => {}
        }
        let t4 = now();
        if timers {
            timers::note_read_attempted();
        }
        let Some(coinbase) = db.basic(beneficiary)? else { return refused(9) };
        let t5 = now();
        if coinbase.is_empty() {
            return refused(9);
        }

        // revm's arithmetic: the caller pays gas_limit at the effective price
        // and the value, then gets the unused gas back at the same price; the
        // beneficiary receives the used gas at the price above the base fee.
        let effective_price = tx.effective_gas_price(basefee);
        let Some(gas_cost) = effective_price.checked_mul(TRANSFER_GAS as u128) else { return refused(10) };
        let Some(sender_balance) = sender.balance.checked_sub(value).and_then(|b| b.checked_sub(U256::from(gas_cost)))
        else {
            return refused(10);
        };
        let Some(recipient_balance) = recipient.as_ref().map_or(U256::ZERO, |r| r.balance).checked_add(value)
        else {
            return refused(10);
        };
        let tip = effective_price.saturating_sub(basefee);
        let Some(reward) = tip.checked_mul(TRANSFER_GAS as u128) else { return refused(10) };
        let Some(coinbase_balance) = coinbase.balance.checked_add(U256::from(reward)) else { return refused(10) };
        let t6 = now();

        // The accounts as the journal would return them: touched, with the
        // pre-state kept as the original, and a recipient that did not exist
        // marked as loaded that way.
        // Three accounts, sized once: growing from empty reallocated twice per
        // transaction, 326,000 allocations a full block on both the builder and
        // the follower.
        let mut state: EvmState = EvmState::with_capacity_and_hasher(4, Default::default());
        let mut sender_account = Account::from(sender);
        sender_account.info.balance = sender_balance;
        sender_account.info.nonce += 1;
        sender_account.mark_touch();
        state.insert(caller, sender_account);
        let mut recipient_account = match recipient {
            Some(info) => Account::from(info),
            None => Account::new_not_existing(TransactionId::ZERO),
        };
        recipient_account.info.balance = recipient_balance;
        recipient_account.mark_touch();
        state.insert(to, recipient_account);
        let mut coinbase_account = Account::from(coinbase);
        coinbase_account.info.balance = coinbase_balance;
        coinbase_account.mark_touch();
        state.insert(beneficiary, coinbase_account);
        let t7 = now();

        // The result revm's handler builds for a call into an account without
        // code: it stops, spends the base cost, refunds nothing, and the
        // EIP-7623 floor for no calldata is the base cost too.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::new_with_state_gas(TRANSFER_GAS, 0, TRANSFER_GAS, 0),
            logs: Vec::new(),
            output: Output::Call(Bytes::new()),
        };
        let out = Ok(Some(ResultAndState::new(result, state)));
        if let (Some(t0), Some(t1), Some(t2), Some(t3), Some(t4), Some(t5), Some(t6), Some(t7)) =
            (t0, t1, t2, t3, t4, t5, t6, t7)
        {
            let ns = |a: std::time::Instant, b: std::time::Instant| b.saturating_duration_since(a).as_nanos() as u64;
            timers::add_read_ns(ns(t0, t1) + ns(t2, t3) + ns(t4, t5));
            timers::add_evm_ns(ns(t1, t2) + ns(t3, t4) + ns(t5, t6));
            timers::add_write_ns(ns(t6, t7));
            timers::add_other_ns(ns(t7, std::time::Instant::now()));
            timers::sample_done();
        }
        out
    }
}

impl<DB, I> Evm for N42Evm<DB, I>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        self.inner.block()
    }

    fn cfg_env(&self) -> &CfgEnv<SpecId> {
        self.inner.cfg_env()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(&mut self, tx: TxEnv) -> Result<ResultAndState, Self::Error> {
        if self.fast && self.inspecting {
            REJECTED[11].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if self.fast && !self.inspecting {
            if let Some(done) = self.transfer(&tx).map_err(EVMError::Database)? {
                HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(done);
            }
        }
        self.inner.transact_raw(tx)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (DB, EvmEnv<SpecId, BlockEnv>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspecting = enabled;
        self.inner.set_inspector_enabled(enabled);
    }

    fn components(&self) -> (&DB, &I, &PrecompilesMap) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut DB, &mut I, &mut PrecompilesMap) {
        self.inner.components_mut()
    }
}

#[cfg(test)]
mod tests {
    //! The transfer path against the interpreter: same result, same accounts.
    use super::*;
    use alloy_primitives::{address, TxKind};
    use revm::{
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
        Database as _, DatabaseCommit,
    };

    const SENDER: Address = address!("0x1000000000000000000000000000000000000001");
    const RECIPIENT: Address = address!("0x2000000000000000000000000000000000000002");
    const EXISTING: Address = address!("0x3000000000000000000000000000000000000003");
    const COINBASE: Address = address!("0x4000000000000000000000000000000000000004");
    const BASEFEE: u64 = 1_000;

    fn env() -> EvmEnv {
        let mut cfg = CfgEnv::new_with_spec(SpecId::OSAKA);
        cfg.chain_id = 1;
        let block = BlockEnv {
            beneficiary: COINBASE,
            basefee: BASEFEE,
            gas_limit: 30_000_000,
            ..Default::default()
        };
        EvmEnv::new(cfg, block)
    }

    fn db() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(SENDER, AccountInfo { balance: U256::from(10u128.pow(20)), nonce: 7, ..Default::default() });
        db.insert_account_info(EXISTING, AccountInfo { balance: U256::from(5), nonce: 3, ..Default::default() });
        db.insert_account_info(COINBASE, AccountInfo { balance: U256::from(1), ..Default::default() });
        db
    }

    fn tx(to: Address, value: u128, tx_type: u8, gas_price: u128, tip: Option<u128>) -> TxEnv {
        TxEnv {
            tx_type,
            caller: SENDER,
            gas_limit: 50_000,
            gas_price,
            gas_priority_fee: tip,
            kind: TxKind::Call(to),
            value: U256::from(value),
            data: Bytes::new(),
            nonce: 7,
            chain_id: Some(1),
            ..Default::default()
        }
    }

    /// Runs `tx` on both paths from the same pre-state; returns (fast, slow),
    /// each as the result and the committed accounts of the three parties.
    fn both(tx: TxEnv) -> Vec<(ResultAndState, Vec<Option<AccountInfo>>)> {
        [true, false]
            .into_iter()
            .map(|fast| {
                let mut evm = N42EvmFactory::with_fast_transfers(fast).create_evm(db(), env());
                let out = evm.transact_raw(tx.clone()).expect("the transaction executes");
                let (mut db, _) = evm.finish();
                db.commit(out.state.clone());
                let infos = [SENDER, RECIPIENT, EXISTING, COINBASE]
                    .into_iter()
                    .map(|a| db.basic(a).expect("cache").map(|i| AccountInfo { code: None, ..i }))
                    .collect();
                (out, infos)
            })
            .collect()
    }

    fn assert_same(tx: TxEnv, expect_fast: bool) {
        let runs = both(tx.clone());
        let (fast, slow) = (&runs[0], &runs[1]);
        assert_eq!(fast.0.result, slow.0.result, "result");
        assert_eq!(fast.1, slow.1, "committed accounts");
        // The accounts the path hands back: only the touched ones, and for
        // those the same info and the same existence flag as the journal's.
        for (address, account) in &fast.0.state {
            let theirs = slow.0.state.get(address).expect("the interpreter loaded it too");
            assert_eq!(account.info, theirs.info, "info of {address}");
            assert_eq!(account.is_touched(), theirs.is_touched(), "touched {address}");
            assert_eq!(
                account.is_loaded_as_not_existing(),
                theirs.is_loaded_as_not_existing(),
                "not-existing flag {address}"
            );
        }
        let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(db(), env());
        assert_eq!(evm.transfer(&tx).expect("no database error").is_some(), expect_fast, "the path taken");
    }

    /// The two paths through revm's `State`, the layer the node persists
    /// from: the bundle (accounts, their statuses, the reverts) must be the
    /// same, or the block written to the database is not.
    fn bundles(tx: TxEnv) -> Vec<revm::database::BundleState> {
        use revm::database::{states::bundle_state::BundleRetention, State};
        [true, false]
            .into_iter()
            .map(|fast| {
                let mut state = State::builder().with_database(db()).with_bundle_update().build();
                {
                    let mut evm = N42EvmFactory::with_fast_transfers(fast).create_evm(&mut state, env());
                    let out = evm.transact_raw(tx.clone()).expect("the transaction executes");
                    evm.db_mut().commit(out.state);
                }
                state.merge_transitions(BundleRetention::Reverts);
                state.take_bundle()
            })
            .collect()
    }

    fn assert_same_bundle(tx: TxEnv) {
        let b = bundles(tx);
        let (fast, slow) = (&b[0], &b[1]);
        assert_eq!(fast.state.len(), slow.state.len(), "accounts in the bundle");
        for (address, account) in &slow.state {
            let ours = fast.state.get(address).expect("account in our bundle");
            assert_eq!(ours.info, account.info, "info {address}");
            assert_eq!(ours.original_info, account.original_info, "original info {address}");
            assert_eq!(ours.status, account.status, "status {address}");
            assert_eq!(ours.storage, account.storage, "storage {address}");
        }
        assert_eq!(fast.reverts, slow.reverts, "reverts");
        assert_eq!(fast.contracts.len(), slow.contracts.len(), "contracts");
    }

    #[test]
    fn bundle_of_a_transfer_to_a_new_account() {
        assert_same_bundle(tx(RECIPIENT, 12_345, 2, 5_000, Some(300)));
    }

    #[test]
    fn bundle_of_a_transfer_to_an_existing_account() {
        assert_same_bundle(tx(EXISTING, 1, 2, 5_000, Some(300)));
    }

    #[test]
    fn bundle_of_two_transfers_in_one_block() {
        use revm::database::{states::bundle_state::BundleRetention, State};
        let b: Vec<revm::database::BundleState> = [true, false]
            .into_iter()
            .map(|fast| {
                let mut state = State::builder().with_database(db()).with_bundle_update().build();
                {
                    let mut evm = N42EvmFactory::with_fast_transfers(fast).create_evm(&mut state, env());
                    for (nonce, to) in [(7u64, RECIPIENT), (8u64, RECIPIENT)] {
                        let mut t = tx(to, 5, 2, 5_000, Some(300));
                        t.nonce = nonce;
                        let out = evm.transact_raw(t).expect("executes");
                        evm.db_mut().commit(out.state);
                    }
                }
                state.merge_transitions(BundleRetention::Reverts);
                state.take_bundle()
            })
            .collect();
        assert_eq!(b[0].state.len(), b[1].state.len());
        for (address, account) in &b[1].state {
            let ours = &b[0].state[address];
            assert_eq!((&ours.info, &ours.original_info, ours.status), (&account.info, &account.original_info, account.status), "{address}");
        }
        assert_eq!(b[0].reverts, b[1].reverts, "reverts");
    }

    #[test]
    fn eip1559_transfer_to_a_new_account() {
        assert_same(tx(RECIPIENT, 12_345, 2, 5_000, Some(300)), true);
    }

    #[test]
    fn eip1559_transfer_to_an_existing_account() {
        assert_same(tx(EXISTING, 1, 2, 5_000, Some(300)), true);
    }

    #[test]
    fn tip_capped_by_the_max_fee() {
        assert_same(tx(EXISTING, 1, 2, 1_100, Some(300)), true);
    }

    #[test]
    fn legacy_transfer() {
        assert_same(tx(EXISTING, 99, 0, 2_000, None), true);
    }

    #[test]
    fn zero_value_to_a_new_account_goes_to_the_interpreter() {
        assert_same(tx(RECIPIENT, 0, 2, 5_000, Some(300)), false);
    }

    #[test]
    fn a_transfer_to_self_goes_to_the_interpreter() {
        assert_same(tx(SENDER, 1, 2, 5_000, Some(300)), false);
    }

    #[test]
    fn a_wrong_nonce_goes_to_the_interpreter() {
        let mut t = tx(EXISTING, 1, 2, 5_000, Some(300));
        t.nonce = 8;
        let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(db(), env());
        assert!(evm.transact_raw(t).is_err(), "the interpreter rejects it");
    }
}

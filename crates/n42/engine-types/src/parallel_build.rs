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
    for (address, _) in merged.accounts() {
        if let Some(held) = overlay.cache.accounts.get(address) {
            let original = merged.original(address).flatten();
            let agrees = match (held.as_ref(), original) {
                (Some(held), Some(original)) => same_account(held, original),
                (None, None) => true,
                // Loaded as absent and absent in the parent read alike.
                (Some(held), None) => held.is_empty(),
                (None, Some(original)) => original.is_empty(),
            };
            if !agrees {
                return Err(*address);
            }
        }
    }
    for (address, info) in merged.accounts() {
        overlay.insert_account_info(address, info.clone());
    }
    Ok(merged.len())
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
) -> Result<u64, Refused>
where
    T: evm2::EvmTypes<Tx: alloy_eips::eip2718::Typed2718, TxResultExt: Send + Sync + Default>,
{
    use reth_evm::execute::BlockExecutor as _;
    install_cache(executor.evm_mut().overlay_db_mut(), &merged).map_err(Refused::Cache)?;
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
    let groups = match groups {
        Some(groups) => groups,
        None => partition_by_sender(keys, beneficiary).map_err(Refused::NotParallel)?,
    };
    let pool = build_pool();
    let workers = pool.current_num_threads().max(1);
    let batches = match dispatch {
        Dispatch::OneWave => batch_groups_one_wave(&groups, keys.len(), workers),
        Dispatch::LargestFirst(n) => batch_groups_one_wave(&groups, keys.len(), n.max(1)),
        Dispatch::Halves => batch_groups(&groups, keys.len(), workers),
    };
    let order = largest_first(&batches.iter().map(|b| b.iter().map(|g| g.len()).sum()).collect::<Vec<usize>>());
    type BatchOut<C> = Result<(Vec<Executed<C>>, Vec<usize>, reth_trie::bundle_state::BundleState), Refused>;
    let run_batch = |members: &Vec<&Vec<usize>>| -> BatchOut<C> {
        let db = open().ok_or(Refused::NotParallel(NotParallel::NoState))?;
        let mut evm = config.evm_with_env(db, env.clone());
        let txs = members.iter().map(|g| g.len()).sum::<usize>();
        let mut state = BatchState::with_capacity(txs * 2 + 1);
        let (mut executed, mut skipped) = (Vec::with_capacity(txs), Vec::new());
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
                match evm.transact(&tx) {
                    Ok(out) => {
                        // Checked before the commit: a transfer refused here
                        // leaves the batch's state as it was.
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
                        state.commit(&out.pending_state).map_err(Refused::Unsupported)?;
                        evm.commit_state(&out.pending_state);
                        executed.push(Executed { index: i, result: out.result });
                    }
                    Err(_) => {
                        broken = true;
                        skipped.push(i);
                    }
                }
            }
        }
        Ok((executed, skipped, state.take_bundle()))
    };
    let slots: Vec<std::sync::OnceLock<BatchOut<C>>> = (0..batches.len()).map(|_| std::sync::OnceLock::new()).collect();
    pool.scope(|scope| {
        for &b in &order {
            let (members, slot, run_batch) = (&batches[b], &slots[b], &run_batch);
            scope.spawn(move |_| {
                let _ = slot.set(run_batch(members));
            });
        }
    });
    let (mut executed, mut skipped, mut bundles) = (Vec::with_capacity(keys.len()), Vec::new(), Vec::with_capacity(batches.len()));
    for slot in slots {
        let (e, s, bundle) = slot.into_inner().unwrap_or(Err(Refused::NotParallel(NotParallel::NoState)))?;
        executed.extend(e);
        skipped.extend(s);
        bundles.push(bundle);
    }
    executed.sort_unstable_by_key(|e| e.index);
    skipped.sort_unstable();
    let merged = merge_batches(bundles).map_err(Refused::Fold)?;
    Ok(ParallelRun { executed, skipped, merged, batches: batches.len() })
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
        commit_run(&mut ex, results, run.merged).expect("the cache half");
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
}

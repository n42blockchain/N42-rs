// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Another node's block, executed and checked here rather than in the engine.
//!
//! The engine imports a block through its payload processor: transactions
//! streamed to the executor over a channel, receipts to a receipt-root task,
//! every transaction's state through a hook into the cross-block cache, and
//! metrics on each. Round 38 measured that path at ~340 ms a block against
//! 121 ms for reth's plain block executor on the same blocks. This module is
//! the plain path with everything the engine's path also guarantees: the
//! consensus rules on the header and body, gas, receipts root and logs bloom
//! against the header after execution, the QMDB root against the header's
//! state root (which also files the block's tree), and the hashed post-state
//! the engine needs to carry the block. What it produces is handed to the
//! engine as an executed block; the engine's own `newPayload` then finds it
//! in the tree, and executes it itself if anything here was refused.

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use reth_consensus::{Consensus, FullConsensus, HeaderValidator};
use n42_tx_types::{Block, N42Primitives as EthPrimitives, N42TxEnvelope as TransactionSigned};
use reth_primitives_traits::transaction::TxHashRef as _;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_payload_primitives::BuiltPayloadExecutedBlock;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SignerRecoverable};
use reth_provider::{HeaderProvider, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_provider::HashedPostStateProvider;
use reth_revm::cached::CachedReads;
use reth_trie::updates::TrieUpdates;
use std::sync::{Condvar, Mutex};

/// The read cache carried from one direct import to the next: the previous
/// block's post-state (its senders above all -- every sender of the next
/// block is one of the same 6,000 at the bench tier), keyed by the block it
/// is the state of. What reth's payload builder does with its `pre_cached`.
pub type CarriedReads = Mutex<Option<(B256, CachedReads)>>;

/// Where a direct import is, for the watchdog: `block_number << 8 | stage`,
/// 0 when none is running. Stages: 1 header, 2 senders, 3 execution,
/// 4 post-execution checks, 5 carry, 6 QMDB root, 7 hashed state.
pub static IMPORT_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Names the stages of [`IMPORT_STAGE`].
pub const IMPORT_STAGES: [&str; 8] = ["idle", "header", "senders", "execution", "checks", "carry", "qmdb-root", "hashed-state"];

/// The leader's own-block hand-off in progress, `(block number << 8) | stage`
/// into [`HANDOFF_STAGES`], 0 when none: the header-only import's lookup,
/// the hand-off to the engine and the engine's `newPayload`. The watchdog
/// reads it: an engine that took 10 s to answer the own block's `newPayload`
/// at a tenure change (loop146 A1, the driver's commit forkchoice timing out
/// behind it) left no line saying what it was doing.
pub static HANDOFF_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Names for [`HANDOFF_STAGE`]'s low byte.
pub const HANDOFF_STAGES: [&str; 8] = ["idle", "lookup", "handoff", "payload", "new-payload", "-", "-", "-"];

/// Sets [`HANDOFF_STAGE`] while alive, clears it on drop.
pub struct HandoffStage(pub u64);

impl HandoffStage {
    /// Records the stage for the block.
    pub fn at(&self, stage: u64) {
        HANDOFF_STAGE.store((self.0 << 8) | stage, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for HandoffStage {
    fn drop(&mut self) {
        HANDOFF_STAGE.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Bumped every time a block lands in the engine here (a direct import, the
/// leader's own block), for [`wait_for_parent`]: under deferred execution
/// the next block's check starts the moment its parent is in.
static IMPORT_LANDED: (Mutex<u64>, Condvar) = (Mutex::new(0), Condvar::new());

/// Says a block has landed in the engine (see [`IMPORT_LANDED`]).
pub fn note_import_landed() {
    let (count, landed) = &IMPORT_LANDED;
    *count.lock().unwrap_or_else(|p| p.into_inner()) += 1;
    landed.notify_all();
}

/// The execution output of a block imported here, as its child's check reads it.
type ParentOutput = Arc<reth_provider::BlockExecutionOutput<n42_tx_types::Receipt>>;

/// The last blocks imported here, published as soon as their execution ends
/// and before the engine takes them (`N42_CHECK_ON_PARENT_OUTPUT`,
/// `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT`).
static PARENT_OUTPUTS: Mutex<std::collections::VecDeque<(B256, reth_primitives_traits::SealedHeader, ParentOutput)>> =
    Mutex::new(std::collections::VecDeque::new());

/// How many published outputs are kept: the check reads only the parent's.
const PARENT_OUTPUTS_KEPT: usize = 4;

/// Under deferred execution a block's check reads its senders from the
/// parent's execution output, published by the parent's import as soon as its
/// execution ends, instead of waiting for the parent to land in the engine. On
/// by default; `N42_CHECK_ON_PARENT_OUTPUT=0` turns it off.
///
/// A follower's vote waited ~200 ms for the previous import to finish
/// (loop155 A2: its carry, hashed post-state and engine insert included)
/// although the check reads ~6,000 senders' nonces and balances, all in the
/// parent's bundle after execution.
///
/// The output is published before the parent's QMDB root, so the includability
/// half of the check runs while that root is still being computed; the header's
/// fields -- the parent's state root among them -- are still compared against
/// this node's result for the parent before the vote, which is what waits for
/// the root (plan v4 step 1). This block's execution still waits for the parent
/// in the engine unless [`exec_on_parent_output`] is on.
///
/// Measured on five fleet legs with no invalid block: loop169's three, and
/// loop183's two at a 275 ms pacing. The pacing is why it read neutral the
/// first time -- at loop169's 350 ms the pacing sat above the natural cycle,
/// so nothing that shortens the vote path could show. At 275 ms window 1 reads
/// 388,814 and 401,741 against 339,784 and 391,021 without it, the round
/// 26.36M and 27.51M transactions against 26.02M and 24.29M, and R1 vote
/// collection 153 -> 106 ms where the pair is comparable.
fn check_on_parent_output() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_CHECK_ON_PARENT_OUTPUT").map_or(true, |v| v != "0"))
}

/// `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT=1`: the block is *executed* on the
/// parent's published output as well -- the parent's bundle laid over the
/// chain's state at the grandparent -- instead of waiting for the parent to
/// land in the engine's tree. The follower-side twin of the leader's
/// `opener_on_built_parent` (plan v4 step 2: the parent's engine insert was
/// 38 ms of a 287 ms R1 vote collection, loop179, and N+1's execution waited
/// for it on top).
///
/// It reads the same published output as [`check_on_parent_output`], so it
/// implies that path; with it on and that flag set to 0 the check still runs
/// on the output, because the parent whose state it would otherwise read is by
/// construction not in the tree. Off by default, and it stays off: loop183
/// measured a 0-1 ms median overlap of its two roads at a 275 ms pacing (the
/// parent's fields are filed before the child's check passes), so it has
/// nothing to gain until the cycle is shorter.
fn exec_on_parent_output() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT").is_ok_and(|v| v == "1"))
}

/// Whether an import publishes its execution output for its child at all.
fn publish_parent_outputs() -> bool {
    check_on_parent_output() || exec_on_parent_output()
}

/// Publishes a block's execution output for its child's check.
fn publish_parent_output(block_hash: B256, header: reth_primitives_traits::SealedHeader, output: ParentOutput) {
    {
        let mut outputs = PARENT_OUTPUTS.lock().unwrap_or_else(|p| p.into_inner());
        outputs.retain(|(hash, _, _)| *hash != block_hash);
        while outputs.len() >= PARENT_OUTPUTS_KEPT {
            outputs.pop_front();
        }
        outputs.push_back((block_hash, header, output));
    }
    note_import_landed();
}

/// The parent's header and published execution output, as soon as its
/// execution ends; `None` as soon as `parent_in` says the parent is in
/// the engine without one, or if neither happens within [`PARENT_WAIT`].
/// Only this path publishes: a parent this node built, or one the engine
/// imported by its own path, never appears, and waiting the whole
/// [`PARENT_WAIT`] for it put three seconds before the child's vote. Behind
/// a 350 ms cycle the child then missed its own import, went by the engine's
/// path too, and so did every block after it (loop156 C1).
///
/// The parent's execution *fields* are not waited for here: they complete
/// with its QMDB root, and the whole point is that the child's includability
/// check runs while that root is computed. The comparison that needs them
/// ([`wait_for_parent_fields`]) waits for them before the vote.
fn wait_for_parent_output(
    parent_hash: B256,
    parent_in: impl Fn() -> bool,
) -> Option<(reth_primitives_traits::SealedHeader, ParentOutput)> {
    let deadline = std::time::Instant::now() + PARENT_WAIT;
    let (count, landed) = &IMPORT_LANDED;
    let mut seen = *count.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        let found = PARENT_OUTPUTS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(hash, _, _)| *hash == parent_hash)
            .map(|(_, header, output)| (header.clone(), Arc::clone(output)));
        if let Some(found) = found {
            return Some(found);
        }
        if parent_in() {
            return None;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let guard = count.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, _) = landed
            .wait_timeout_while(guard, (deadline - now).min(std::time::Duration::from_millis(20)), |c| *c == seen)
            .unwrap_or_else(|p| p.into_inner());
        seen = *guard;
    }
}

/// Waits for the parent's execution fields, the half of the check the
/// includability pass does not cover: the header carries the parent's state
/// root, receipts root, logs bloom and gas, and
/// `validate_header_against_parent` compares them against what this node
/// executed. The state root is filed by the parent's own QMDB root job, so
/// on the published-output path this is the one thing the vote still owes the
/// parent's root -- run after the includability check, which the root
/// computes beside.
fn wait_for_parent_fields(parent_hash: B256) -> Result<(), String> {
    n42_engine_types::executed_fields::wait_for(&parent_hash, PARENT_WAIT)
        .map(|_| ())
        .ok_or_else(|| format!("parent {parent_hash}'s execution fields not recorded within {PARENT_WAIT:?}"))
}

/// The header against the parent, by the consensus rules: under deferred
/// execution the parent's execution fields, which this node filed itself, are
/// what the header's copies are compared with. A free function rather than a
/// closure because the vote road calls it from a thread of its own.
fn validate_against_parent(
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    header: &reth_primitives_traits::SealedHeader,
    parent: &reth_primitives_traits::SealedHeader,
) -> Result<(), String> {
    consensus.validate_header_against_parent(header, parent).map_err(|err| format!("header against parent: {err}"))
}

/// Runs the vote road beside the block's execution, once the includability
/// check has passed and the block is to be executed on the parent's published
/// output (`N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT`, plan v4 step 2).
///
/// `vote` waits for the parent's execution fields, compares the header against
/// them and releases the vote; `execute` needs nothing but the parent's bundle,
/// which is already in hand, so it starts at the same instant instead of after
/// the parent's QMDB root (~27 ms) and its header check.
///
/// The vote road's error wins: a header this node's own result refuses is not
/// imported, whatever the execution beside it produced -- the executed block is
/// dropped here and the import reports the header error, exactly as when the
/// two ran one after the other. A vote already released is *not* taken back
/// when the execution then fails; that is the rule as it stands, not a new one,
/// because the vote has preceded the execution since deferred execution went in
/// (`import_foreign_block` below). The import's error sends the block down the
/// engine's own path (`bin/n42/src/payload_serve.rs`, "direct import failed"),
/// and it is the driver's verdict, not the check, that moves the head
/// (`crates/n42/h2-execution/src/driver.rs`, `finish_execute`).
///
/// The vote road is a plain scoped thread and never a rayon job: it blocks on a
/// condvar another thread satisfies, and a rayon worker that blocks steals
/// other jobs -- the deadlock the QMDB root job runs on a thread of its own for
/// (loop164 O17). The execution road keeps the worker pool to itself.
fn two_roads<T>(
    number: u64,
    roads_at: std::time::Instant,
    vote: impl FnOnce() -> Result<(), String> + Send,
    execute: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let (voted, executed, exec_ms) = std::thread::scope(|scope| {
        let voted = std::thread::Builder::new()
            .name("vote-road".into())
            .spawn_scoped(scope, || vote().map(|()| roads_at.elapsed().as_millis() as u64))
            .expect("a thread for the vote road");
        let executed = execute();
        let exec_ms = roads_at.elapsed().as_millis() as u64;
        (voted.join().unwrap_or_else(|_| Err("the vote road thread panicked".to_string())), executed, exec_ms)
    });
    let vote_ms = voted?;
    let executed = executed?;
    // Both roads started at `roads_at`, so the shorter one is the overlap.
    tracing::info!(
        target: "n42.follower_import",
        number,
        exec_ms,
        vote_ms,
        overlap_ms = exec_ms.min(vote_ms),
        "two roads: the execution ran beside the vote"
    );
    Ok(executed)
}

/// A sender's account after the parent, from the parent's execution output:
/// `None` when the parent did not touch it (its state is then the
/// grandparent's), a default account when the parent destroyed it.
fn account_after_parent(bundle: &reth_revm::db::BundleState, sender: &Address) -> Option<reth_primitives_traits::Account> {
    bundle.account(sender).map(|account| {
        account
            .info
            .as_ref()
            .map(|info| reth_primitives_traits::Account { nonce: info.nonce, balance: info.balance, bytecode_hash: None })
            .unwrap_or_default()
    })
}

/// How long a check waits for the block's parent to land before giving the
/// block up to the engine's ordinary path (which answers SYNCING).
const PARENT_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// The parent's sealed header if it is in: known to the provider and, past
/// the fork, executed here (its result recorded).
fn parent_in<Provider>(
    provider: &Provider,
    parent_hash: B256,
    genesis: &alloy_genesis::Genesis,
    deferred: bool,
) -> Result<Option<reth_primitives_traits::SealedHeader>, String>
where
    Provider: HeaderProvider<Header = alloy_consensus::Header>,
{
    let Some(parent) = provider.sealed_header_by_hash(parent_hash).map_err(|err| format!("parent header: {err}"))? else {
        return Ok(None);
    };
    // A parent before the fork carries its own result in its header; one past
    // it has its result recorded here once executed.
    let executed_here =
        deferred && parent.number > 0 && reth_chainspec::qmdb::deferred_execution_active_at(genesis, parent.timestamp);
    Ok((!executed_here || n42_engine_types::executed_fields::get(&parent_hash).is_some()).then_some(parent))
}

/// The parent's sealed header once the parent is in: known to the provider
/// and, under deferred execution, executed here (its result recorded), so
/// the header's fields can be checked and the transactions read against its
/// post-state. Blocks arrive in order but their imports overlap from the
/// fork on, so the parent of the block being checked may still be
/// executing; this waits for it, up to [`PARENT_WAIT`].
fn wait_for_parent<Provider>(
    provider: &Provider,
    parent_hash: B256,
    genesis: &alloy_genesis::Genesis,
    deferred: bool,
) -> Result<reth_primitives_traits::SealedHeader, String>
where
    Provider: HeaderProvider<Header = alloy_consensus::Header>,
{
    let deadline = std::time::Instant::now() + PARENT_WAIT;
    let (count, landed) = &IMPORT_LANDED;
    let mut seen = *count.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        if let Some(parent) = parent_in(provider, parent_hash, genesis, deferred)? {
            return Ok(parent);
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            // Which half was missing: a parent the provider cannot see is not
            // canonical yet (its commit's forkchoice has not run); one with no
            // complete execution fields was not executed here, or its receipts
            // were never recorded.
            let header_known = provider.sealed_header_by_hash(parent_hash).ok().flatten().is_some();
            let fields_known = n42_engine_types::executed_fields::get(&parent_hash).is_some();
            return Err(format!(
                "parent {parent_hash} not imported within {PARENT_WAIT:?} (header known: {header_known}, execution fields known: {fields_known})"
            ));
        }
        // A landing bumps the count; a block that arrives by the engine's
        // own path bumps nothing, so the wait is also a poll.
        let guard = count.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, _) = landed
            .wait_timeout_while(guard, (deadline - now).min(std::time::Duration::from_millis(20)), |c| *c == seen)
            .unwrap_or_else(|p| p.into_inner());
        seen = *guard;
    }
}

/// The includability of a block's transactions on its parent's post-state
/// (docs/PHASE_D_DEFERRED_EXECUTION.md, section 8.4): what a follower's
/// vote attests under deferred execution, since the block's execution is
/// checked only by the next header. Per sender, one account read: the
/// nonces contiguous from the account's, the balance covering every
/// transaction's value and gas at its fee cap; per transaction, the chain
/// id, the fee cap against the block's base fee, the priority fee under the
/// cap, a gas limit at least a transfer's; for the block, the gas limits
/// within the header's. Senders are read on the worker pool, each chunk on
/// a state provider of its own.
/// The revm spec the intrinsic gas of a block stamped `timestamp` is
/// computed under (the forks that change it: Shanghai's init-code word
/// cost, Prague's calldata floor).
fn spec_for_intrinsic_gas<ChainSpec: reth_chainspec::EthereumHardforks>(chain_spec: &ChainSpec, timestamp: u64) -> reth_revm::primitives::hardfork::SpecId {
    use reth_revm::primitives::hardfork::SpecId;
    if chain_spec.is_osaka_active_at_timestamp(timestamp) {
        SpecId::OSAKA
    } else if chain_spec.is_prague_active_at_timestamp(timestamp) {
        SpecId::PRAGUE
    } else if chain_spec.is_cancun_active_at_timestamp(timestamp) {
        SpecId::CANCUN
    } else if chain_spec.is_shanghai_active_at_timestamp(timestamp) {
        SpecId::SHANGHAI
    } else {
        SpecId::LONDON
    }
}

/// The first thing wrong with a block, at the transaction it is wrong at.
/// Sorting these by index picks the same transaction the serial loops this
/// replaced would have stopped at.
#[derive(Debug)]
struct Fault {
    index: usize,
    message: String,
}

/// A stretch of consecutive transactions of one sender, folded as the scan
/// walks the block: the queue lays a sender's transactions out in runs, so
/// 162,000 transactions fold into ~6,000 of these and the sender map is
/// built over the runs rather than over every transaction.
#[derive(Debug)]
struct SenderRun {
    sender: Address,
    first_index: usize,
    first_nonce: u64,
    len: u64,
    /// Value plus gas at the fee cap plus blob gas at its cap, saturating.
    cost: alloy_primitives::U256,
    /// The first transaction of this run that is wrong on its own terms:
    /// its nonce does not continue the run, or its gas limit does not cover
    /// its intrinsic gas. Boxed: a block in error is the rare case and a run
    /// is otherwise 80 bytes.
    fault: Option<Box<Fault>>,
}

/// What one chunk of the block's transactions came to.
#[derive(Debug, Default)]
struct ChunkScan {
    gas_total: u64,
    /// The first transaction of this chunk refused on its own terms, before
    /// any sender is looked at: chain id, fee cap, priority fee, empty
    /// authorization list. These outrank everything else, as they did when
    /// they were a serial pass that returned early.
    refused: Option<Fault>,
    runs: Vec<SenderRun>,
}

/// A sender's whole share of the block, its runs folded together.
#[derive(Debug)]
struct SenderTotal {
    first_index: usize,
    first_nonce: u64,
    next_nonce: u64,
    count: u64,
    cost: alloy_primitives::U256,
    fault: Option<Fault>,
}

fn check_includable<Provider>(
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<(&reth_revm::db::BundleState, B256)>,
    block: &RecoveredBlock<Block>,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
) -> Result<(), String>
where
    Provider: StateProviderFactory + Sync,
{
    let scans = scan_transactions(block, chain_id, spec);
    if let Some(refused) = scans.iter().filter_map(|scan| scan.refused.as_ref()).min_by_key(|fault| fault.index) {
        return Err(refused.message.clone());
    }
    let gas_total = scans.iter().fold(0u64, |total, scan| total.saturating_add(scan.gas_total));
    let gas_limit = block.header().gas_limit;
    if gas_total > gas_limit {
        return Err(format!("gas limits sum to {gas_total}, over the block's {gas_limit}"));
    }
    let senders = fold_runs(scans);
    check_senders(provider, parent_hash, parent_output, &senders)
}

/// One pass over the block's transactions, on the worker pool: everything
/// that can be decided from a transaction alone, and the per-sender fold the
/// account reads then need. This used to be a serial pass that grouped the
/// transactions by sender and a parallel pass that walked them a second time
/// through those groups; the block's transaction data is ~33 MB at the bench
/// tier and streaming it once rather than twice is the point of the fold.
fn scan_transactions(
    block: &RecoveredBlock<Block>,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
) -> Vec<ChunkScan> {
    use alloy_consensus::Transaction as _;
    use rayon::prelude::*;

    let base_fee = u128::from(block.header().base_fee_per_gas.unwrap_or(0));
    let txs = &block.body().transactions;
    let senders = block.senders();
    let chunk = txs.len().div_ceil(32).max(1);
    txs.par_chunks(chunk)
        .enumerate()
        .map(|(nth, txs)| {
            let base = nth * chunk;
            let senders = &senders[base..base + txs.len()];
            let mut scan = ChunkScan { runs: Vec::with_capacity(txs.len() / 8 + 1), ..Default::default() };
            for (offset, (tx, sender)) in txs.iter().zip(senders).enumerate() {
                let index = base + offset;
                if let Some(id) = tx.chain_id()
                    && id != chain_id
                {
                    scan.refused =
                        Some(Fault { index, message: format!("transaction {index}: chain id {id}, the chain's is {chain_id}") });
                    break;
                }
                let cap = tx.max_fee_per_gas();
                if cap < base_fee {
                    scan.refused = Some(Fault {
                        index,
                        message: format!("transaction {index}: fee cap {cap} under the base fee {base_fee}"),
                    });
                    break;
                }
                if tx.max_priority_fee_per_gas().is_some_and(|tip| tip > cap) {
                    scan.refused =
                        Some(Fault { index, message: format!("transaction {index}: priority fee over the fee cap") });
                    break;
                }
                if tx.authorization_list().is_some_and(|list| list.is_empty()) {
                    scan.refused =
                        Some(Fault { index, message: format!("transaction {index}: empty authorization list") });
                    break;
                }
                scan.gas_total = scan.gas_total.saturating_add(tx.gas_limit());

                if !matches!(scan.runs.last(), Some(run) if run.sender == *sender) {
                    scan.runs.push(SenderRun {
                        sender: *sender,
                        first_index: index,
                        first_nonce: tx.nonce(),
                        len: 0,
                        cost: alloy_primitives::U256::ZERO,
                        fault: None,
                    });
                }
                let run = scan.runs.last_mut().expect("a run for this sender");
                // The nonce before the intrinsic gas, the order the
                // per-sender loop checked them in: a transaction wrong in
                // both ways still reports its nonce.
                if run.fault.is_none() {
                    let expected = run.first_nonce.saturating_add(run.len);
                    if tx.nonce() != expected {
                        run.fault = Some(Box::new(Fault {
                            index,
                            message: format!("transaction {index}: nonce {}, {sender} is at {expected}", tx.nonce()),
                        }));
                    } else if let Some(needed) = intrinsic_gas_shortfall(tx, spec) {
                        run.fault = Some(Box::new(Fault {
                            index,
                            message: format!("transaction {index}: gas limit {} under the intrinsic {needed}", tx.gas_limit()),
                        }));
                    }
                }
                run.len += 1;
                let gas = alloy_primitives::U256::from(tx.gas_limit()) * alloy_primitives::U256::from(tx.max_fee_per_gas());
                let blobs = alloy_primitives::U256::from(tx.blob_gas_used().unwrap_or(0))
                    * alloy_primitives::U256::from(tx.max_fee_per_blob_gas().unwrap_or(0));
                run.cost = run.cost.saturating_add(tx.value()).saturating_add(gas).saturating_add(blobs);
            }
            scan
        })
        .collect()
}

/// The intrinsic gas -- the transaction's kind, calldata, access list and
/// authorizations under this fork -- that its gas limit does not cover, or
/// `None` if it does. A block that fails this fails at execution, and the
/// vote that let it through was wrong.
fn intrinsic_gas_shortfall(tx: &TransactionSigned, spec: reth_revm::primitives::hardfork::SpecId) -> Option<u64> {
    use alloy_consensus::Transaction as _;

    let (al_accounts, al_storages) = tx
        .access_list()
        .map(|list| (list.len() as u64, list.iter().map(|item| item.storage_keys.len() as u64).sum::<u64>()))
        .unwrap_or((0, 0));
    let intrinsic = reth_revm::context_interface::cfg::gas::calculate_initial_tx_gas(
        spec,
        tx.input(),
        tx.kind().is_create(),
        al_accounts,
        al_storages,
        tx.authorization_list().map_or(0, |list| list.len() as u64),
        None,
    );
    let needed = (intrinsic.initial_regular_gas + intrinsic.initial_state_gas).max(intrinsic.floor_gas);
    (tx.gas_limit() < needed).then_some(needed)
}

/// The chunks' runs folded per sender. The chunks are in block order and so
/// are the runs inside them, so a sender's runs arrive in the order its
/// transactions sit in the block and the nonces chain across the joins.
fn fold_runs(scans: Vec<ChunkScan>) -> Vec<(Address, SenderTotal)> {
    let mut by_sender: alloy_primitives::map::AddressHashMap<SenderTotal> = Default::default();
    for scan in scans {
        for run in scan.runs {
            match by_sender.entry(run.sender) {
                alloy_primitives::map::Entry::Vacant(slot) => {
                    slot.insert(SenderTotal {
                        first_index: run.first_index,
                        first_nonce: run.first_nonce,
                        next_nonce: run.first_nonce.saturating_add(run.len),
                        count: run.len,
                        cost: run.cost,
                        fault: run.fault.map(|fault| *fault),
                    });
                }
                alloy_primitives::map::Entry::Occupied(mut slot) => {
                    let total = slot.get_mut();
                    // The joint between two runs of one sender is a nonce
                    // check like any other, at the first transaction of the
                    // later run -- which is before anything that run itself
                    // has to say, and after anything the sender already had.
                    if total.fault.is_none() && run.first_nonce != total.next_nonce {
                        total.fault = Some(Fault {
                            index: run.first_index,
                            message: format!(
                                "transaction {}: nonce {}, {} is at {}",
                                run.first_index, run.first_nonce, run.sender, total.next_nonce
                            ),
                        });
                    }
                    if total.fault.is_none() {
                        total.fault = run.fault.map(|fault| *fault);
                    }
                    total.next_nonce = run.first_nonce.saturating_add(run.len);
                    total.count += run.len;
                    total.cost = total.cost.saturating_add(run.cost);
                }
            }
        }
    }
    by_sender.into_iter().collect()
}

/// Each sender's total against the parent's post-state: one account read, the
/// nonces contiguous from the account's, the balance covering the whole
/// share. On the worker pool, each chunk on a state provider of its own; the
/// block's transactions are not touched again here.
fn check_senders<Provider>(
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<(&reth_revm::db::BundleState, B256)>,
    senders: &[(Address, SenderTotal)],
) -> Result<(), String>
where
    Provider: StateProviderFactory + Sync,
{
    use rayon::prelude::*;
    use reth_provider::AccountReader as _;

    let chunk = senders.len().div_ceil(32).max(1);
    let faults: Vec<Result<Option<Fault>, String>> = senders
        .par_chunks(chunk)
        .map(|chunk| {
            // With the parent's output, an untouched sender is read at the
            // grandparent, which is in the engine: the parent's own execution
            // read its state there.
            let state_at = parent_output.map_or(parent_hash, |(_, grandparent)| grandparent);
            let state = provider.state_by_block_hash(state_at).map_err(|err| format!("parent state: {err}"))?;
            let mut first: Option<Fault> = None;
            for (sender, total) in chunk {
                let after_parent = parent_output.and_then(|(bundle, _)| account_after_parent(bundle, sender));
                let account = match after_parent {
                    Some(account) => account,
                    None => state
                        .basic_account(sender)
                        .map_err(|err| format!("account {sender}: {err}"))?
                        .unwrap_or_default(),
                };
                // The account's own nonce is the sender's first transaction,
                // so a mismatch here outranks anything found later in its
                // share.
                let fault = if account.nonce != total.first_nonce {
                    Some(Fault {
                        index: total.first_index,
                        message: format!(
                            "transaction {}: nonce {}, {sender} is at {}",
                            total.first_index, total.first_nonce, account.nonce
                        ),
                    })
                } else if let Some(fault) = &total.fault {
                    Some(Fault { index: fault.index, message: fault.message.clone() })
                } else if total.cost > account.balance {
                    // Checked after every transaction of the sender, so it
                    // loses to any of them: the block's last word about it.
                    Some(Fault {
                        index: usize::MAX,
                        message: format!(
                            "{sender}: {} transactions cost {} of a balance of {}",
                            total.count, total.cost, account.balance
                        ),
                    })
                } else {
                    None
                };
                if let Some(fault) = fault
                    && first.as_ref().is_none_or(|held| fault.index < held.index)
                {
                    first = Some(fault);
                }
            }
            Ok(first)
        })
        .collect();
    let mut first: Option<Fault> = None;
    for chunk in faults {
        // A provider that cannot answer is not a verdict on the block, so it
        // is reported whatever the block itself says.
        if let Some(fault) = chunk?
            && first.as_ref().is_none_or(|held| fault.index < held.index)
        {
            first = Some(fault);
        }
    }
    first.map_or(Ok(()), |fault| Err(fault.message))
}

/// The parent as an executed block this import reads its post-state from
/// (`N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT`), or `None` -- with the reason -- to
/// wait for the parent in the engine as before.
///
/// Depth one: everything the parent did not touch is read from the chain's
/// state at the grandparent, so the grandparent must be in -- known to the
/// provider and executed here. Two published outputs stacked would need the
/// grandparent's bundle in the overlay too, and a follower two blocks behind
/// the chain has a larger problem than the parent's engine insert.
///
/// Sound with `N42_HASHED_TABLES=off`, where an import hands the engine an
/// empty hashed post-state, because the overlay answers `basic_account` and
/// `storage` from the executed block's *bundle*, not from its hashed state
/// (reth v2.5.1 `crates/chain-state/src/memory_overlay.rs:114-124` and
/// `:237-251`; `bytecode_by_hash` at `:253-262` likewise). The only reader of
/// the hashed state through an overlay is reth's Merkle-Patricia pass
/// (`trie_input`, `:52-63`, reached from `hashed_post_state` for an account
/// this block destroyed) -- so while that pass is on, this path is not taken:
/// the parent's hashed state is not published and the overlay's would be
/// empty.
fn overlay_parent<Provider>(
    provider: &Provider,
    parent: &reth_primitives_traits::SealedHeader,
    output: &ParentOutput,
    genesis: &alloy_genesis::Genesis,
    deferred: bool,
    number: u64,
) -> Option<n42_engine_types::direct_build::ExecutedParent>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
{
    let decline = |why: &'static str| {
        // Counted like the parallel execution's refusals: a leg that reads
        // medians cannot see a path that quietly never runs.
        static DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let declined = DECLINED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        tracing::info!(target: "n42.follower_import", number, why, declined, "not executing on the parent's output; waiting for the parent in the engine");
        None
    };
    if hashed_state_enabled() {
        return decline("the hashed post-state pass is on and the parent's is not published");
    }
    let grandparent = parent.parent_hash;
    if !matches!(parent_in(provider, grandparent, genesis, deferred), Ok(Some(_))) {
        return decline("the grandparent is not imported here");
    }
    // The overlay's fallback, opened once here so a missing state is this
    // fallback rather than a failed import.
    if let Err(err) = provider.state_by_block_hash(grandparent) {
        tracing::debug!(target: "n42.follower_import", number, %err, "no state at the grandparent");
        return decline("no state at the grandparent");
    }
    Some(n42_engine_types::direct_build::executed_from_output(parent, Arc::clone(output)))
}

struct ImportStage(u64);

impl ImportStage {
    fn at(&self, stage: u64) {
        IMPORT_STAGE.store((self.0 << 8) | stage, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for ImportStage {
    fn drop(&mut self) {
        IMPORT_STAGE.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}


/// Above this many cached accounts the carry starts again from the block's
/// own post-state: a follower sees every block, and the reads would grow
/// without bound.
const CARRY_CAP: usize = 1_000_000;

/// What a block's execution produced, so the execution can be run as one
/// piece beside the vote road: the view of the parent's post-state it read
/// (the hashed post-state pass still needs it), the read cache the carry is
/// made from, the output, whether the worker pool took the block, and the two
/// phase timings.
struct Executed {
    state: reth_provider::StateProviderBox,
    cached: CachedReads,
    output: reth_provider::BlockExecutionOutput<n42_tx_types::Receipt>,
    parallel: bool,
    state_ms: u64,
    exec_ms: u64,
}

/// What the block's road to this node's vote cost before the import began,
/// and which request carried it.
///
/// The road crosses two processes -- the validator receives the body, the
/// execution layer imports it -- and reading it used to mean joining two
/// logs by block hash. The pieces the validator knows are carried in here
/// so the whole road is one line, written where the vote is released.
///
/// Every field is microseconds and the line prints milliseconds: `other_ms`
/// is what the named parts leave over, and computed from millisecond fields
/// it would be mostly the truncation of the twelve it subtracts.
#[derive(Debug, Clone, Copy)]
pub struct VoteRoad {
    /// Which request carried the block: `foreign_body`, `compact_body` or
    /// `new_payload`.
    pub request: &'static str,
    /// Reading the frame off the loopback socket.
    pub recv_us: u64,
    /// Turning it into the block this import takes: the payload decode, and
    /// on the body road the conversion to a block with it.
    pub decode_us: u64,
    /// The own-build check every block pays before the import is dispatched.
    pub reuse_us: u64,
    /// What is copied between that check and the hand-off.
    pub prepare_us: u64,
    /// The hand-off to the blocking pool: submitted -> the closure running.
    pub dispatch_us: u64,
    /// `convert_payload_to_block`; 0 on the body road, which arrives converted.
    pub convert_us: u64,
    /// The sealed block filed for the engine's own conversion; 0 when that
    /// clone is made off this path.
    pub remember_us: u64,
    /// Compact body road only: finding the block's transactions in this
    /// node's queue by the hashes the body named.
    pub assemble_us: u64,
    /// Compact body road only: encoding the assembled transactions and
    /// building the trie whose root is compared with the header's -- what
    /// binds the assembled list to the block consensus voted on.
    pub root_us: u64,
    /// Compact body road only: waiting for this node's ingest to land a
    /// transaction the first pass did not find.
    pub miss_wait_us: u64,
    /// Compact body road only: checking, decoding and recovering the
    /// transactions the peer supplied for the positions this node could not
    /// fill. 0 on a first attempt.
    pub fill_us: u64,
    /// How many positions the peer supplied.
    pub filled: u64,
    /// Compact body road only: how many of the block's hashes the first
    /// pass did not find. Nonzero with a vote released means the wait was
    /// enough; a road that gave up logs a line of its own and is not this
    /// one.
    pub misses: u64,
    /// When the request's first byte arrived, for the total.
    pub started: std::time::Instant,
}

/// What the import itself spent on the road, in microseconds. Carried whole
/// so a part added here reaches the line without another argument.
#[derive(Debug, Clone, Copy, Default)]
struct RoadPhases {
    /// The header and body consensus checks, and before the deferred fork the
    /// parent lookup ahead of them.
    header_us: u64,
    /// Sender recovery and the recovered block.
    senders_us: u64,
    /// Waiting for the parent header or for its published output.
    parent_wait_us: u64,
    /// `validate_against_parent` and `check_includable`: what the vote attests.
    check_us: u64,
    /// Waiting for the parent's execution fields, and the header against them.
    fields_us: u64,
}

/// The one line a bench leg greps: where a block's road to this node's vote
/// went. Written once per block, at the point the vote is released.
///
/// The named parts are meant to add up to `total_ms`, and `other_ms` is what
/// they do not cover -- so a road that grows a part nobody named shows it as
/// a gap instead of hiding it (loop190: 50 ms of a 167 ms road had no name).
fn log_vote_road(road: VoteRoad, number: u64, txs: usize, phases: RoadPhases) {
    let total = road.started.elapsed().as_micros() as u64;
    let named = road.recv_us
        + road.decode_us
        + road.reuse_us
        + road.prepare_us
        + road.dispatch_us
        + road.convert_us
        + road.remember_us
        + road.assemble_us
        + road.root_us
        + road.miss_wait_us
        + road.fill_us
        + phases.header_us
        + phases.senders_us
        + phases.parent_wait_us
        + phases.check_us
        + phases.fields_us;
    tracing::info!(
        target: "n42.follower_import",
        number,
        txs,
        request = road.request,
        recv_ms = road.recv_us / 1000,
        decode_ms = road.decode_us / 1000,
        reuse_ms = road.reuse_us / 1000,
        prepare_ms = road.prepare_us / 1000,
        dispatch_ms = road.dispatch_us / 1000,
        convert_ms = road.convert_us / 1000,
        remember_ms = road.remember_us / 1000,
        assemble_ms = road.assemble_us / 1000,
        root_ms = road.root_us / 1000,
        miss_wait_ms = road.miss_wait_us / 1000,
        misses = road.misses,
        fill_ms = road.fill_us / 1000,
        filled = road.filled,
        header_ms = phases.header_us / 1000,
        senders_ms = phases.senders_us / 1000,
        parent_wait_ms = phases.parent_wait_us / 1000,
        check_ms = phases.check_us / 1000,
        fields_ms = phases.fields_us / 1000,
        other_ms = total.saturating_sub(named) / 1000,
        total_ms = total / 1000,
        "vote road"
    );
}

/// Executes and checks `sealed` on its parent's state. See the module docs.
/// Returns the executed block and the phase timings in milliseconds:
/// header checks, senders, execution, the post-execution checks, state root,
/// hashed state; then the number of senders the recovery cache held.
///
/// Under deferred execution (a block stamped at or past the chain's
/// `deferredExecutionTime`) the block is *checked* first -- its header's
/// execution fields against this node's result for the parent, its
/// transactions' includability on the parent's post-state -- and `checked`
/// is told so before the execution starts: that is the follower's vote. A
/// block before the fork sends nothing on it.
#[allow(clippy::too_many_arguments)]
pub fn import_foreign_block<Provider, Evm, ChainSpec>(
    sealed: SealedBlock<Block>,
    provider: &Provider,
    evm_config: &Evm,
    senders_cache: Option<&reth_evm::SenderRecoveryCache>,
    given_senders: Option<Vec<Address>>,
    carry: &Arc<CarriedReads>,
    qmdb: Option<&n42_qmdb_reth::QmdbNodeState>,
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    chain_spec: &ChainSpec,
    mut checked: Option<tokio::sync::oneshot::Sender<()>>,
    road: VoteRoad,
) -> Result<(Box<BuiltPayloadExecutedBlock<EthPrimitives>>, [u64; 9]), String>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
    Evm: ConfigureEvm<
        Primitives = EthPrimitives,
        BlockExecutorFactory = n42_engine_types::parallel_transfer::FastExecutorFactory,
    >,
    ChainSpec: reth_chainspec::EthereumHardforks + reth_chainspec::EthChainSpec,
{
    let qmdb = qmdb.ok_or("no QMDB state: the direct import needs the chain's root")?;
    let started = std::time::Instant::now();
    let stage = ImportStage(sealed.number);
    stage.at(1);
    let parent_hash = sealed.parent_hash;
    let number = sealed.number;
    let block_hash = sealed.hash();
    let tx_count = sealed.body().transactions.len();

    let deferred = reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), sealed.timestamp);
    // Before the fork the parent must be in already, as it always was: an
    // unknown parent fails here at once and the engine's own path answers
    // SYNCING, with no wait and no sender recovery spent on it. From the
    // fork on the parent may still be importing, and the check below waits
    // for it after the work that needs no parent.
    let parent_known = if deferred {
        None
    } else {
        Some(
            provider
                .sealed_header_by_hash(parent_hash)
                .map_err(|err| format!("parent header: {err}"))?
                .ok_or_else(|| format!("parent {parent_hash} unknown"))?,
        )
    };
    // The header and body, by the consensus rules the engine would apply;
    // what needs no parent first, so it overlaps the parent's import.
    consensus.validate_header(sealed.sealed_header()).map_err(|err| format!("header: {err}"))?;
    // The transactions root was computed and matched against the sealed hash
    // by the payload's conversion; the body check takes it as known.
    consensus
        .validate_block_pre_execution_with_tx_root(&sealed, Some(sealed.transactions_root))
        .map_err(|err| format!("body: {err}"))?;
    let mut phases = RoadPhases { header_us: started.elapsed().as_micros() as u64, ..Default::default() };
    let header_ms = phases.header_us / 1000;
    let senders_at = std::time::Instant::now();
    stage.at(2);

    // Senders, when the caller has not already got them. The compact body
    // road has (`N42_COMPACT_BODY`): it assembled the block out of this
    // node's queue, where every transaction sits with the sender the ingest
    // recovered when it arrived, so the whole pass below is skipped -- 27-43
    // ms of a 240 ms binding term at the bench tier (loop194 X2b). The
    // senders are the queue's own, not the body's: nothing a peer sent is
    // taken on trust here, and the transactions they belong to are bound to
    // the header by the transactions root the assembly checked.
    // The recovery pass writes its cache-hit count out here, because the
    // arm that skips the pass entirely has none to report.
    let cache_hits_out = std::sync::atomic::AtomicU64::new(0);
    let recovered = match given_senders {
        Some(senders) if senders.len() != tx_count => {
            return Err(format!("given {} senders for {tx_count} transactions", senders.len()));
        }
        Some(senders) => RecoveredBlock::new_sealed(sealed, senders),
        None => {
            let cache_hits = std::sync::atomic::AtomicU64::new(0);
            let alt_cache = n42_tx_types::AltSigSenderCache::global();
            let txs: Vec<&TransactionSigned> = sealed.body().transactions().collect();
            let mut senders: Vec<Option<Address>> = {
                use rayon::prelude::*;
                // Collected into a `Vec<Result>` (written in place) and checked after:
                // a parallel collect straight into `Result<Vec>` takes rayon's
                // short-circuiting path, three times the cost at 163,000 items
                // (round 43, `bench_convert_payload`).
                let looked_up: Vec<Result<Option<Address>, String>> = txs
                    .par_iter()
                    .map(|tx| match tx {
                        TransactionSigned::AltSig(alt) => Ok(alt_cache.get(alt.hash()).inspect(|_| {
                            cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        })),
                        TransactionSigned::Eth(_) => {
                            if let Some(sender) = senders_cache.and_then(|cache| cache.get(tx.tx_hash())) {
                                cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return Ok(Some(sender));
                            }
                            tx.recover_signer().map(Some).map_err(|err| format!("sender of {}: {err}", tx.tx_hash()))
                        }
                    })
                    .collect();
                looked_up.into_iter().collect::<Result<Vec<_>, String>>()?
            };
            let misses: Vec<usize> = senders.iter().enumerate().filter(|(_, s)| s.is_none()).map(|(i, _)| i).collect();
            if !misses.is_empty() {
                use rayon::prelude::*;
                let batch = n42_tx_types::ed25519_batch_size();
                let verified: Vec<(usize, Result<Address, n42_tx_types::AltSigError>)> = misses
                    .par_chunks(batch)
                    .flat_map_iter(|chunk| {
                        let refs: Vec<&n42_tx_types::AltSigTx> = chunk
                            .iter()
                            .filter_map(|&i| txs[i].as_alt_sig())
                            .collect();
                        chunk.iter().copied().zip(n42_tx_types::verify_batch(&refs)).collect::<Vec<_>>()
                    })
                    .collect();
                for (i, verdict) in verified {
                    let sender = verdict.map_err(|err| format!("sender of {}: {err}", txs[i].tx_hash()))?;
                    alt_cache.insert(*txs[i].tx_hash(), sender);
                    senders[i] = Some(sender);
                }
            }
            let senders: Vec<Address> = senders.into_iter().map(|s| s.expect("every sender resolved")).collect();
            cache_hits_out.store(cache_hits.into_inner(), std::sync::atomic::Ordering::Relaxed);
            RecoveredBlock::new_sealed(sealed, senders)
        }
    };
    let cache_hits = cache_hits_out.load(std::sync::atomic::Ordering::Relaxed);
    phases.senders_us = senders_at.elapsed().as_micros() as u64;
    let senders_ms = phases.senders_us / 1000;

    // The parent: in, and under deferred execution executed here, since the
    // header's fields are checked against its result and the transactions
    // against its post-state.
    let parent_at = std::time::Instant::now();
    let (parent, parent_output) = match parent_known {
        Some(parent) => (parent, None),
        None => match (deferred && publish_parent_outputs())
            .then(|| {
                wait_for_parent_output(parent_hash, || {
                    parent_in(provider, parent_hash, chain_spec.genesis(), deferred).ok().flatten().is_some()
                })
            })
            .flatten()
        {
            Some((parent, output)) => (parent, Some(output)),
            None => (wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?, None),
        },
    };
    phases.parent_wait_us = parent_at.elapsed().as_micros() as u64;
    let against_parent = || validate_against_parent(consensus, recovered.sealed_header(), &parent);
    // Set on the exec-on-parent-output path: the parent as an executed block
    // this import lays over the chain's state at the grandparent, and the
    // instant the vote road and the execution started together.
    let mut executed_parent = None;
    let mut roads_at = None;
    if !deferred {
        against_parent()?;
    } else {
        // What the vote attests: the header's execution fields are this
        // node's result for the parent, and every transaction is includable
        // on the parent's post-state.
        //
        // On the parent's published output the two run in the other order and
        // overlap. The includability check reads ~6,000 senders' nonces and
        // balances, all of them in the parent's bundle the moment its
        // execution ends; the fields comparison needs the parent's state
        // root, which its QMDB root job files while this check runs (plan v4
        // step 1: the parent's root and engine insert were 65 ms of a 287 ms
        // R1 vote collection, loop179).
        let check_at = std::time::Instant::now();
        if parent_output.is_none() {
            against_parent()?;
        }
        check_includable(
            provider,
            parent_hash,
            parent_output.as_ref().map(|output| (&output.state, parent.parent_hash)),
            &recovered,
            chain_spec.chain().id(),
            spec_for_intrinsic_gas(chain_spec, recovered.timestamp),
        )?;
        // Set on the deferred path, where the vote is the check; zero before
        // the fork, where the vote is the import itself.
        phases.check_us = check_at.elapsed().as_micros() as u64;

        // Where this block's execution will read the parent's post-state,
        // decided here because it decides whether that execution can run
        // beside the rest of the vote road or has to follow it: the parent's
        // published output laid over the chain's state at the grandparent
        // (`N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT`), or the engine's tree at the
        // parent. The parent may have landed while this block was being
        // checked, and the engine's tree is the cheaper state when it has it.
        if let Some(output) = &parent_output
            && exec_on_parent_output()
            && parent_in(provider, parent_hash, chain_spec.genesis(), deferred)?.is_none()
        {
            executed_parent = overlay_parent(provider, &parent, output, chain_spec.genesis(), deferred, number);
        }

        if executed_parent.is_none() {
            // The rest of the vote road, then the execution: it has to wait
            // for the parent in the engine anyway, so there is nothing for it
            // to run beside.
            let fields_at = std::time::Instant::now();
            if parent_output.is_some() {
                wait_for_parent_fields(parent_hash)?;
                against_parent()?;
            }
            phases.fields_us = fields_at.elapsed().as_micros() as u64;
            tracing::debug!(
                target: "n42.follower_import",
                number,
                check_ms = phases.check_us / 1000,
                fields_ms = phases.fields_us / 1000,
                "checked: the header carries the parent's result and the transactions are includable"
            );
            if let Some(checked) = checked.take() {
                let _ = checked.send(());
            }
            log_vote_road(road, number, tx_count, phases);
        } else {
            // Two roads from here (plan v4 step 2, [`two_roads`]): the rest of
            // the vote road -- the parent's execution fields and the header
            // against them -- and this block's execution, which needs nothing
            // but the parent's bundle and so waits for neither.
            roads_at = Some(std::time::Instant::now());
            tracing::debug!(
                target: "n42.follower_import",
                number,
                check_ms = phases.check_us / 1000,
                "the transactions are includable on the parent's output; the vote road and the execution run side by side"
            );
        }
    }

    // The parent in the engine, for a block whose execution reads it there.
    if parent_output.is_some() && executed_parent.is_none() {
        wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?;
    }
    drop(parent_output);

    // Execution on the parent's state, then gas, receipts root and bloom
    // against the header. One piece, because on the exec-on-parent-output path
    // it runs on this thread while the vote road runs on another.
    let execute_block = || -> Result<Executed, String> {
        let state_at = std::time::Instant::now();
        // One view of the parent's post-state per caller: the block's own
        // executor takes the first, each group of a parallel execution one of
        // its own. Both must be the *same* state -- a group that opened the
        // engine's tree while the block's executor read the overlay would
        // execute half the block one block behind.
        let open_parent_state = || -> Result<reth_provider::StateProviderBox, String> {
            match &executed_parent {
                Some(executed) => {
                    let historical = provider
                        .state_by_block_hash(parent.parent_hash)
                        .map_err(|err| format!("grandparent state: {err}"))?;
                    Ok(n42_engine_types::direct_build::overlay_on_executed(historical, executed.clone()))
                }
                None => provider.state_by_block_hash(parent_hash).map_err(|err| format!("parent state: {err}")),
            }
        };
        let state = open_parent_state()?;
        let state_ms = state_at.elapsed().as_millis() as u64;
        let executed_at = std::time::Instant::now();
        stage.at(3);
        let mut cached = match carry.lock().unwrap_or_else(|p| p.into_inner()).take() {
            Some((of, cached)) if of == parent_hash => cached,
            _ => CachedReads::default(),
        };
        // `N42_FOLLOWER_PARALLEL=1`: a block of plain transfers executes on the
        // worker pool (`parallel_transfer`), partitioned by the accounts it
        // touches; anything it cannot take falls back to the serial executor.
        let mut output = None;
        if follower_parallel() {
            let open = || open_parent_state().ok().map(StateProviderDatabase::new);
            match n42_engine_types::parallel_transfer::execute_transfers(
                evm_config,
                &recovered,
                cached.as_db_mut(StateProviderDatabase::new(&state)),
                &open,
            )
            .map_err(|err| format!("parallel execution: {err}"))?
            {
                Ok((out, phases)) => {
                    tracing::info!(
                        target: "n42.follower_import",
                        number,
                        groups = phases.groups,
                        partition_ms = phases.partition_ms,
                        groups_ms = phases.groups_ms,
                        merge_ms = phases.merge_ms,
                        finish_ms = phases.finish_ms,
                        "parallel import phases"
                    );
                    output = Some(out);
                }
                Err(why) => {
                    // Counted like the builder's: a block that fell back to the
                    // serial path costs several times its import, and a leg that
                    // reads medians cannot see it otherwise.
                    static DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    let declined = DECLINED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    tracing::info!(target: "n42.follower_import", number, %why, declined, "not parallel; executing serially");
                }
            }
        }
        // A block executed on the worker pool read its transfers' accounts
        // through providers of its own, not through `cached`: the carry below
        // would copy ~147,000 accounts (26 ms on the import, loop155) that the
        // next import barely reads.
        let parallel = output.is_some();
        let output = match output {
            Some(out) => out,
            None => evm_config
                .executor(cached.as_db_mut(StateProviderDatabase::new(&state)))
                .execute(&recovered)
                .map_err(|err| format!("execution: {err}"))?,
        };
        Ok(Executed { state, cached, output, parallel, state_ms, exec_ms: executed_at.elapsed().as_millis() as u64 })
    };
    let Executed { state, mut cached, output, parallel: parallel_executed, state_ms, exec_ms } = match roads_at {
        None => execute_block()?,
        Some(roads_at) => {
            // References rather than the values: the vote road's closure is
            // `move`, and the execution road needs the same block and parent.
            let header = recovered.sealed_header();
            let parent_header = &parent;
            let vote_checked = checked.take();
            two_roads(
                number,
                roads_at,
                move || {
                    let fields_at = std::time::Instant::now();
                    wait_for_parent_fields(parent_hash)?;
                    validate_against_parent(consensus, header, parent_header)?;
                    let mut phases = phases;
                    phases.fields_us = fields_at.elapsed().as_micros() as u64;
                    // The vote, with this block's execution still running.
                    if let Some(checked) = vote_checked {
                        let _ = checked.send(());
                    }
                    log_vote_road(road, number, tx_count, phases);
                    Ok(())
                },
                execute_block,
            )?
        }
    };
    let checks_at = std::time::Instant::now();
    stage.at(4);
    consensus
        .validate_block_post_execution(&recovered, &output.result, None, None)
        .map_err(|err| format!("post-execution: {err}"))?;
    let checks_ms = checks_at.elapsed().as_millis() as u64;
    let execution_output = Arc::new(output);
    // The child's check can start now: its ~6,000 senders are in this
    // bundle, and it has no use for the QMDB root below -- only the fields
    // comparison has, and that one waits for it on its own
    // ([`wait_for_parent_fields`]). Published after the post-execution
    // checks, so nothing is published for a block whose receipts or gas were
    // refused, and before the root, which is the ~27 ms the child's check now
    // runs beside (plan v4 step 1).
    if deferred && publish_parent_outputs() {
        publish_parent_output(block_hash, recovered.clone_sealed_header(), Arc::clone(&execution_output));
    }
    // The carry for the next block: this block's post-state over the reads.
    // The carry: this block's post-state over the reads, for the next block.
    // Nothing reads it until the next import, ~650 ms away, so with
    // `N42_CARRY_ASYNC=1` the copy of 129,000 accounts happens on the worker
    // pool after this returns instead of while the validator waits for its
    // answer (round 43, loop100: it was most of the 44 ms the import could not
    // account for). A carry that is not ready in time is not a correctness
    // problem: the next import simply reads the state provider instead.
    let carry_at = std::time::Instant::now();
    let carry_async = carry_async();
    if !carry_async && !parallel_executed {
        fill_carry(&mut cached, &execution_output.state, block_hash, carry);
    }
    let carry_ms = carry_at.elapsed().as_millis() as u64;

    // Executed on the parent's output: the forest computes this block's tree
    // from the parent's record, which the parent's own root job files, and
    // nothing has waited for it on this path. It is there by now in the
    // ordinary case -- the check above already waited for the fields the
    // parent's root completes -- so this states the ordering rather than
    // paying for it.
    if executed_parent.is_some() {
        wait_for_parent_fields(parent_hash)?;
    }

    // The QMDB root against the header's, which also files the block's tree
    // under its hash for the engine and the next block.
    let root_at = std::time::Instant::now();
    stage.at(6);
    let prague = chain_spec.is_prague_active_at_timestamp(recovered.timestamp);
    // The QMDB root and the hashed post-state read the same bundle and neither
    // needs the other's result, but they run one after the other: 63 and 26 ms
    // of a 438 ms import (round 43, loop99). `N42_ROOT_HASHED_PARALLEL=1` puts
    // them on the worker pool together.
    let bundle = &execution_output.state;
    let root_job = || -> Result<B256, String> {
        if deferred {
            // The header carries the parent's root (checked against the
            // parent's result by the consensus rules above); this block's
            // own root is filed and remembered for its child's header.
            let ops = n42_qmdb_reth::sorted_operations_from_execution(bundle, prague);
            let root = qmdb
                .insert_block_operations(parent_hash, block_hash, number, ops)
                .map_err(|err| format!("state root: {err}"))?;
            n42_engine_types::executed_fields::remember_state_root(block_hash, root);
            return Ok(root);
        }
        if parallel_state_commit() {
            // The leaf operations keyed, encoded and sorted on the worker pool,
            // straight from the bundle (the change set and its serial
            // `operations()` were 75 ms of this phase at 147,000 accounts).
            let ops = n42_qmdb_reth::sorted_operations_from_execution(bundle, prague);
            qmdb.validate_block_operations(parent_hash, block_hash, number, ops, recovered.state_root)
                .map_err(|err| format!("state root: {err}"))
        } else {
            let changes = n42_qmdb_reth::changes_from_execution(bundle, prague);
            qmdb.validate_block(parent_hash, block_hash, number, &changes, recovered.state_root)
                .map_err(|err| format!("state root: {err}"))
        }
    };
    // The provider is `Send` but not `Sync`, so the hashed job takes it by
    // value; both jobs borrow the bundle, which is plain data.
    //
    // `N42_HASHED_STATE=0` skips the pass entirely -- and stops the chain; see
    // `hashed_state_enabled`. Besides reth's Merkle-Patricia trie methods
    // (`MemoryOverlayStateProvider::trie_input`), `save_blocks` writes it to
    // `HashedAccounts`/`HashedStorages`, which under storage v2 are the
    // persisted latest state every account and storage read falls back to
    // once a block leaves the in-memory overlay. It costs 26 ms of every
    // import and holds ~15 MB a block until the block is persisted.
    let hashed_job = move || {
        if hashed_state_enabled() {
            state.hashed_post_state(bundle).map_err(|err| format!("hashed state: {err}"))
        } else {
            Ok(reth_trie::HashedPostState::default())
        }
    };
    let (root_ms, hashed_ms, hashed_state) = if !root_hashed_parallel() {
        root_job()?;
        let root_ms = root_at.elapsed().as_millis() as u64;
        let hashed_at = std::time::Instant::now();
        stage.at(7);
        let hashed_state = hashed_job()?;
        (root_ms, hashed_at.elapsed().as_millis() as u64, hashed_state)
    } else {
        stage.at(7);
        // The root on a thread of its own, never as a rayon job, the way the
        // assembler's has run since loop113. The forest's mutex is held for the
        // whole computation, whose hashing waits on the worker pool, and a
        // worker that waits steals other jobs: with two imports in flight (or a
        // build's assembly beside one) the worker holding the lock, or one
        // running its hashing, took the other import's root job, which then
        // waited for the lock -- loop164 O17 and T17: a new leader's import
        // stuck at "hashed-state" and its build at "finishing" with every
        // thread asleep, and the chain stopped for the rest of the tenure. A
        // plain thread that waits on the pool blocks and steals nothing.
        let (root, hashed) = std::thread::scope(|scope| {
            let root = std::thread::Builder::new()
                .name("qmdb-root".into())
                .spawn_scoped(scope, root_job)
                .expect("a thread for the QMDB root");
            let hashed = hashed_job();
            (root.join().unwrap_or_else(|_| Err("the QMDB root thread panicked".to_string())), hashed)
        });
        root?;
        let both = root_at.elapsed().as_millis() as u64;
        (both, 0, hashed?)
    };

    if carry_async && !parallel_executed {
        let state = Arc::clone(&execution_output);
        let carry = Arc::clone(carry);
        rayon::spawn(move || {
            let mut cached = cached;
            fill_carry(&mut cached, &state.state, block_hash, &carry);
        });
    }

    // The engine takes an executed block on top of its parent, so the
    // hand-offs must stay in chain order: a block executed on the parent's
    // output, rather than on the engine's tree, waits here for the parent to
    // land. By this point the parent landed long ago -- this block's own
    // execution and root have run since -- and the wait is the invariant, not
    // a cost.
    if executed_parent.is_some() {
        wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?;
    }

    // Before the deferred-execution fork the vote is this import's answer,
    // so the road ends here rather than at a check.
    if !deferred {
        log_vote_road(road, number, tx_count, phases);
    }

    Ok((
        Box::new(BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered),
            execution_output,
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(TrieUpdates::default()),
        }),
        [header_ms, senders_ms, exec_ms, checks_ms, root_ms, hashed_ms, cache_hits, state_ms, carry_ms],
    ))
}

/// Copies a block's post-state into the read cache the next import starts
/// from, and files it under the block's hash.
fn fill_carry(
    cached: &mut CachedReads,
    bundle: &reth_revm::db::BundleState,
    block_hash: B256,
    carry: &CarriedReads,
) {
    if cached.accounts.len() > CARRY_CAP {
        *cached = CachedReads::default();
    }
    for (address, account) in &bundle.state {
        match &account.info {
            Some(info) => cached.insert_account(*address, info.clone(), Default::default()),
            None => {
                cached.accounts.insert(*address, reth_revm::cached::CachedAccount { info: None, storage: Default::default() });
            }
        }
    }
    *carry.lock().unwrap_or_else(|p| p.into_inner()) = Some((block_hash, std::mem::take(cached)));
}

/// Whether the follower computes the Merkle-Patricia hashed post-state
/// (default).
///
/// **`N42_HASHED_STATE=0` stops the chain.** It is kept as the one-line
/// reproduction, not as an option: loop106 ran it twice and the fleet produced
/// zero blocks both times, dying on the first full block with
/// `block gas used mismatch: got 0, expected 3423000000; gas spent by each
/// transaction: []` -- the engine validating an executed block that has no
/// receipts at all -- while the same binary with the pass left in read 199,751
/// and 249,924. The dependency: under storage v2 (the default) the
/// `HashedAccounts`/`HashedStorages` tables are the persisted latest state --
/// `LatestStateProviderRef` reads `basic_account` and `storage` from them, and
/// `save_blocks` fills them only from each block's hashed post-state. Skipped,
/// persisted blocks change no state table; once the in-memory overlay drops
/// them, the senders they funded read as absent and the first full block
/// executes to gas 0 (`docs/QMDB_UPGRADE_PLAN.md`, stage 6). Removing this
/// pass -- 26 ms of every import and ~15 MB a block -- needs QMDB to serve
/// those reads first, and the leader's own build handled too.
///
/// With `N42_HASHED_TABLES=off` (stage 6c) the QMDB reader serves them and
/// nothing writes the tables, so the pass is skipped on that setting.
fn hashed_state_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("N42_HASHED_STATE").map_or(true, |v| v != "0") && !n42_qmdb_reth::n42_state::hashed_tables_off()
    })
}

/// Whether the carry is filled on the worker pool after the import returns
/// (`N42_CARRY_ASYNC=1`) instead of on the path the validator's vote waits
/// for. Nothing reads the carry until the next block, ~650 ms later.
fn carry_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_CARRY_ASYNC").is_ok_and(|v| v == "1"))
}

/// Whether the QMDB root and the hashed post-state run together on the worker
/// pool (default; `N42_ROOT_HASHED_PARALLEL=0` runs them one after the other).
/// They read the same bundle and neither needs the other: the pair measured
/// 94 -> 81 ms and was adopted (docs/FLEET7_STATUS.md), but the default had
/// stayed off and no launcher set it. In parallel the pair is reported as
/// `root_ms` with `hashed_ms` zero.
fn root_hashed_parallel() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ROOT_HASHED_PARALLEL").map_or(true, |v| v != "0"))
}

/// `N42_FOLLOWER_PARALLEL`, read once.
fn follower_parallel() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_PARALLEL").is_ok_and(|v| v == "1"))
}

/// Whether the parallel state commit is on (default; `N42_PARALLEL_STATE_COMMIT=0` turns it off): the QMDB leaf operations are
/// keyed, encoded and sorted on the worker pool instead of through the change set
/// (round 43: 190 -> 104 ms of a follower's import at 147,000 accounts).
pub fn parallel_state_commit() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // On by default since round 43's loop82 (223-228k against 189-201k on
    // window 1 at 147,000 accounts a block, the follower's import 488-562 ms
    // against 605-690); `N42_PARALLEL_STATE_COMMIT=0` is the serial path.
    *ON.get_or_init(|| std::env::var("N42_PARALLEL_STATE_COMMIT").map_or(true, |v| v != "0"))
}


#[cfg(test)]
mod parent_output_tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_revm::db::BundleState;
    use reth_revm::revm::state::AccountInfo;

    /// A sender the parent changed reads its post-state; one it destroyed
    /// reads empty; one it never touched is left to the grandparent's state.
    #[test]
    fn a_senders_account_after_the_parent_comes_from_its_bundle_when_touched() {
        let changed = Address::with_last_byte(1);
        let destroyed = Address::with_last_byte(2);
        let untouched = Address::with_last_byte(3);
        let before = AccountInfo { nonce: 4, balance: U256::from(10), ..Default::default() };
        let after = AccountInfo { nonce: 5, balance: U256::from(7), ..Default::default() };
        let bundle = BundleState::new(
            [
                (changed, Some(before.clone()), Some(after), Default::default()),
                (destroyed, Some(before), None, Default::default()),
            ],
            Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
            Vec::new(),
        );
        let account = account_after_parent(&bundle, &changed).expect("changed by the parent");
        assert_eq!((account.nonce, account.balance), (5, U256::from(7)));
        let account = account_after_parent(&bundle, &destroyed).expect("destroyed by the parent");
        assert_eq!((account.nonce, account.balance), (0, U256::ZERO));
        assert!(account_after_parent(&bundle, &untouched).is_none());
    }

    /// The two halves of a follower's vote, overlapped (plan v4 step 1): the
    /// parent's output is published when its execution ends, so the
    /// includability check reads its senders' nonces and balances while the
    /// parent's QMDB root is still being computed -- and the comparison of the
    /// header's execution fields, which needs that root, waits for it.
    #[test]
    fn the_output_is_published_before_the_root_and_only_the_fields_wait_for_it() {
        let parent_hash = B256::with_last_byte(0x51);
        let sender = Address::with_last_byte(0x52);
        let bundle = BundleState::new(
            [(
                sender,
                Some(AccountInfo { nonce: 4, balance: U256::from(10), ..Default::default() }),
                Some(AccountInfo { nonce: 5, balance: U256::from(7), ..Default::default() }),
                Default::default(),
            )],
            Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
            Vec::new(),
        );
        let header = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header::default());
        let output = Arc::new(reth_provider::BlockExecutionOutput { result: Default::default(), state: bundle });
        publish_parent_output(parent_hash, header, output);

        // What the check needs is there with no root filed.
        let (_, output) = wait_for_parent_output(parent_hash, || false).expect("published when the execution ended");
        assert_eq!(account_after_parent(&output.state, &sender).map(|account| account.nonce), Some(5));
        assert!(n42_engine_types::executed_fields::get(&parent_hash).is_none(), "the parent's root is not filed yet");

        // What the fields comparison needs arrives with that root.
        let filed = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            n42_engine_types::executed_fields::remember_receipts(parent_hash, B256::with_last_byte(0x53), Default::default(), 21_000);
            n42_engine_types::executed_fields::remember_state_root(parent_hash, B256::with_last_byte(0x54));
        });
        let started = std::time::Instant::now();
        wait_for_parent_fields(parent_hash).expect("the fields complete with the parent's root");
        assert!(started.elapsed() >= std::time::Duration::from_millis(50), "the comparison did not wait: {:?}", started.elapsed());
        assert!(started.elapsed() < PARENT_WAIT, "and it woke on the root, not on the deadline");
        filed.join().expect("the root thread");
    }

    /// The two roads (plan v4 step 2): on the exec-on-parent-output path the
    /// block's execution starts when the parent's *output* is published, not
    /// when its QMDB root files the parent's execution fields -- so it runs,
    /// and finishes, while those fields do not yet exist, and the vote road
    /// waits for them beside it.
    #[test]
    fn the_execution_starts_before_the_parents_fields_exist() {
        let parent_hash = B256::with_last_byte(0x61);
        let header = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header::default());
        let output = Arc::new(reth_provider::BlockExecutionOutput {
            result: Default::default(),
            state: BundleState::default(),
        });
        publish_parent_output(parent_hash, header, output);
        // The parent's execution has ended -- its output is published -- but
        // its root has not run, so its fields are not filed.
        assert!(wait_for_parent_output(parent_hash, || false).is_some());
        assert!(n42_engine_types::executed_fields::get(&parent_hash).is_none());

        let filed = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            n42_engine_types::executed_fields::remember_receipts(parent_hash, B256::with_last_byte(0x62), Default::default(), 21_000);
            n42_engine_types::executed_fields::remember_state_root(parent_hash, B256::with_last_byte(0x63));
        });
        let roads_at = std::time::Instant::now();
        let fields_at_execution = std::sync::atomic::AtomicBool::new(true);
        let executed = two_roads(
            0x61,
            roads_at,
            || wait_for_parent_fields(parent_hash),
            || {
                // The execution road, as short as a test can make it: what it
                // records is whether the parent's fields were there while it
                // ran.
                fields_at_execution.store(
                    n42_engine_types::executed_fields::get(&parent_hash).is_some(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
                Ok::<_, String>(21_000u64)
            },
        )
        .expect("the header is this node's result for the parent");
        assert_eq!(executed, 21_000);
        assert!(!fields_at_execution.load(std::sync::atomic::Ordering::Relaxed), "the execution waited for the parent's root");
        assert!(roads_at.elapsed() >= std::time::Duration::from_millis(100), "the vote road did not wait for the fields");
        filed.join().expect("the root thread");
    }

    /// A header this node's own result for the parent refuses is not imported,
    /// however the execution beside it ended: the vote road's error is what
    /// the import reports and the executed block is dropped. (The vote itself
    /// is not released on that road, so nothing was attested.)
    #[test]
    fn a_header_validation_failure_discards_the_execution() {
        let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran = std::sync::Arc::clone(&executed);
        let outcome = two_roads(
            0x71,
            std::time::Instant::now(),
            || Err("header against parent: state root mismatch".to_string()),
            move || {
                ran.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok::<_, String>("the executed block")
            },
        );
        assert_eq!(outcome, Err("header against parent: state root mismatch".to_string()));
        assert!(executed.load(std::sync::atomic::Ordering::Relaxed), "the execution did run -- and its result was dropped");
    }

    /// The vote road's error wins over the execution's, so a block refused by
    /// both is reported by its header, as it was when the header check ran
    /// first.
    #[test]
    fn the_header_error_wins_over_the_executions() {
        let outcome: Result<(), String> = two_roads(
            0x72,
            std::time::Instant::now(),
            || Err("header against parent: gas used mismatch".to_string()),
            || Err("execution: out of gas".to_string()),
        );
        assert_eq!(outcome, Err("header against parent: gas used mismatch".to_string()));
    }

    /// A parent already in the engine that nothing published (one this node
    /// built, or one the engine imported by its own path) ends the wait at
    /// once instead of after [`PARENT_WAIT`] (loop156 C1).
    #[test]
    fn a_parent_in_the_engine_without_an_output_ends_the_wait_at_once() {
        let started = std::time::Instant::now();
        assert!(wait_for_parent_output(B256::with_last_byte(0xee), || true).is_none());
        assert!(started.elapsed() < PARENT_WAIT / 10, "waited {:?}", started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, Signed, TxEip1559};
    use alloy_primitives::{map::AddressHashMap, Bytes, Signature, TxKind, U256};
    use reth_primitives_traits::{Account, SealedBlock};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_revm::db::BundleState;
    use reth_revm::primitives::hardfork::SpecId;
    use reth_revm::state::AccountInfo;

    /// The implementation the fused scan replaced, kept as the oracle the
    /// property tests compare against: a serial pass that grouped the block's
    /// transactions by sender, then a parallel pass that walked them a second
    /// time through those groups.
    fn check_includable_oracle<Provider>(
        provider: &Provider,
        parent_hash: B256,
        parent_output: Option<(&reth_revm::db::BundleState, B256)>,
        block: &RecoveredBlock<Block>,
        chain_id: u64,
        spec: reth_revm::primitives::hardfork::SpecId,
    ) -> Result<(), String>
    where
        Provider: StateProviderFactory + Sync,
    {
        let groups = group_by_sender(block, chain_id)?;
        check_sender_groups(provider, parent_hash, parent_output, block, &groups, spec)
    }

    /// The block's transactions grouped by sender, in block order, with the
    /// checks that need nothing but the transaction itself done on the way: the
    /// chain id, the fee cap against the block's base fee, the priority fee under
    /// the cap, a non-empty authorization list, and the gas limits' sum against
    /// the header's. A serial pass over 163,000 transactions.
    fn group_by_sender(block: &RecoveredBlock<Block>, chain_id: u64) -> Result<Vec<(Address, Vec<usize>)>, String> {
        use alloy_consensus::Transaction as _;

        let header = block.header();
        let base_fee = u128::from(header.base_fee_per_gas.unwrap_or(0));
        let mut gas_total: u64 = 0;
        // The addresses' own bytes as the hash: SipHash over 163,000 transactions
        // was ~29 ms of the check, serially, before the vote.
        let mut by_sender: alloy_primitives::map::AddressHashMap<Vec<usize>> = Default::default();
        for (index, (sender, tx)) in block.transactions_with_sender().enumerate() {
            if let Some(id) = tx.chain_id() {
                if id != chain_id {
                    return Err(format!("transaction {index}: chain id {id}, the chain's is {chain_id}"));
                }
            }
            let cap = tx.max_fee_per_gas();
            if cap < base_fee {
                return Err(format!("transaction {index}: fee cap {cap} under the base fee {base_fee}"));
            }
            if tx.max_priority_fee_per_gas().is_some_and(|tip| tip > cap) {
                return Err(format!("transaction {index}: priority fee over the fee cap"));
            }
            if tx.authorization_list().is_some_and(|list| list.is_empty()) {
                return Err(format!("transaction {index}: empty authorization list"));
            }
            gas_total = gas_total.saturating_add(tx.gas_limit());
            by_sender.entry(*sender).or_default().push(index);
        }
        if gas_total > header.gas_limit {
            return Err(format!("gas limits sum to {gas_total}, over the block's {}", header.gas_limit));
        }
        Ok(by_sender.into_iter().collect())
    }

    /// Each sender's group against the parent's post-state: one account read, the
    /// nonces contiguous from the account's, the intrinsic gas within every
    /// transaction's gas limit, and the balance covering the whole group. On the
    /// worker pool, each chunk on a state provider of its own.
    fn check_sender_groups<Provider>(
        provider: &Provider,
        parent_hash: B256,
        parent_output: Option<(&reth_revm::db::BundleState, B256)>,
        block: &RecoveredBlock<Block>,
        groups: &[(Address, Vec<usize>)],
        spec: reth_revm::primitives::hardfork::SpecId,
    ) -> Result<(), String>
    where
        Provider: StateProviderFactory + Sync,
    {
        use alloy_consensus::Transaction as _;
        use rayon::prelude::*;
        use reth_provider::AccountReader as _;

        let txs: Vec<&TransactionSigned> = block.body().transactions().collect();
        let chunk = groups.len().div_ceil(32).max(1);
        let checked: Vec<Result<(), String>> = groups
            .par_chunks(chunk)
            .map(|chunk| {
                // With the parent's output, an untouched sender is read at the
                // grandparent, which is in the engine: the parent's own execution
                // read its state there.
                let state_at = parent_output.map_or(parent_hash, |(_, grandparent)| grandparent);
                let state = provider.state_by_block_hash(state_at).map_err(|err| format!("parent state: {err}"))?;
                for (sender, indexes) in chunk {
                    let after_parent = parent_output.and_then(|(bundle, _)| account_after_parent(bundle, sender));
                    let account = match after_parent {
                        Some(account) => account,
                        None => state
                            .basic_account(sender)
                            .map_err(|err| format!("account {sender}: {err}"))?
                            .unwrap_or_default(),
                    };
                    let mut nonce = account.nonce;
                    let mut cost = alloy_primitives::U256::ZERO;
                    for &index in indexes {
                        let tx = txs[index];
                        if tx.nonce() != nonce {
                            return Err(format!("transaction {index}: nonce {}, {sender} is at {nonce}", tx.nonce()));
                        }
                        nonce += 1;
                        // The intrinsic gas -- the transaction's kind, calldata,
                        // access list and authorizations under this fork -- must
                        // fit the gas limit, or the block fails at execution and
                        // the vote was wrong. Here on the worker pool: serially
                        // it was ~40 ms of the check (loop143).
                        let (al_accounts, al_storages) = tx
                            .access_list()
                            .map(|list| (list.len() as u64, list.iter().map(|item| item.storage_keys.len() as u64).sum::<u64>()))
                            .unwrap_or((0, 0));
                        let intrinsic = reth_revm::context_interface::cfg::gas::calculate_initial_tx_gas(
                            spec,
                            tx.input(),
                            tx.kind().is_create(),
                            al_accounts,
                            al_storages,
                            tx.authorization_list().map_or(0, |list| list.len() as u64),
                            None,
                        );
                        let needed = (intrinsic.initial_regular_gas + intrinsic.initial_state_gas).max(intrinsic.floor_gas);
                        if tx.gas_limit() < needed {
                            return Err(format!("transaction {index}: gas limit {} under the intrinsic {needed}", tx.gas_limit()));
                        }
                        let gas = alloy_primitives::U256::from(tx.gas_limit()) * alloy_primitives::U256::from(tx.max_fee_per_gas());
                        let blobs = alloy_primitives::U256::from(tx.blob_gas_used().unwrap_or(0))
                            * alloy_primitives::U256::from(tx.max_fee_per_blob_gas().unwrap_or(0));
                        cost = cost.saturating_add(tx.value()).saturating_add(gas).saturating_add(blobs);
                    }
                    if cost > account.balance {
                        return Err(format!("{sender}: {} transactions cost {cost} of a balance of {}", indexes.len(), account.balance));
                    }
                }
                Ok(())
            })
            .collect();
        checked.into_iter().collect()
    }

    const CHAIN_ID: u64 = 1;
    const BASE_FEE: u64 = 1_000_000_000;
    /// A transfer's fee cap; with a 21,000 gas limit a transaction costs
    /// 2.1e14 wei of the sender's balance.
    const FEE_CAP: u128 = 10_000_000_000;

    fn addr(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    /// One transfer, signed with a placeholder signature: the check never
    /// recovers a sender, it is handed one.
    fn transfer(nonce: u64, to: Address, value: u128, gas_limit: u64) -> TransactionSigned {
        let inner = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce,
            gas_limit,
            max_fee_per_gas: FEE_CAP,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(to),
            value: U256::from(value),
            input: Bytes::new(),
            ..Default::default()
        };
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
        TransactionSigned::from(reth_ethereum_primitives::TransactionSigned::from(signed))
    }

    /// A block from transactions already paired with their senders.
    fn seal(txs: Vec<TransactionSigned>, senders: Vec<Address>, beneficiary: Address) -> RecoveredBlock<Block> {
        let header = Header {
            number: 20_000_000,
            beneficiary,
            gas_limit: 10_000_000_000,
            base_fee_per_gas: Some(BASE_FEE),
            timestamp: 1_800_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        let body = n42_tx_types::BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: Some(Vec::new().into()) };
        // Unhashed: the check never asks the block for its hash, and
        // hashing a body of 162,000 transactions dominates the fixtures.
        RecoveredBlock::new_sealed(SealedBlock::new_unhashed(Block { header, body }), senders)
    }

    /// The bench tier's block shape: `senders x per` transfers to recipients
    /// drawn at random from `space` accounts, laid out as the queue lays them
    /// out -- `run` transactions of one sender, then the next sender's.
    /// Returns the block and every sender's account at the parent.
    fn bench_fixture(senders: u64, per: u64, space: u64, run: usize) -> (RecoveredBlock<Block>, Vec<(Address, Account)>) {
        let mut lanes: Vec<Vec<TransactionSigned>> = Vec::with_capacity(senders as usize);
        let mut accounts = Vec::with_capacity(senders as usize);
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for s in 0..senders {
            let sender = addr(100 + s);
            accounts.push((sender, Account { nonce: 0, balance: U256::from(10u128.pow(21)), bytecode_hash: None }));
            let mut lane = Vec::with_capacity(per as usize);
            for k in 0..per {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                lane.push(transfer(k, addr(1_000_000 + seed % space), 1_000 + u128::from(k), 21_000));
            }
            lanes.push(lane);
        }
        let mut txs = Vec::with_capacity((senders * per) as usize);
        let mut recovered = Vec::with_capacity((senders * per) as usize);
        let mut k = 0usize;
        while k < per as usize {
            for (s, lane) in lanes.iter().enumerate() {
                for tx in &lane[k..(k + run).min(per as usize)] {
                    txs.push(tx.clone());
                    recovered.push(addr(100 + s as u64));
                }
            }
            k += run;
        }
        (seal(txs, recovered, addr(1)), accounts)
    }

    /// A provider whose state holds `accounts`.
    fn provider(accounts: &[(Address, Account)]) -> MockEthProvider {
        let mock = MockEthProvider::default();
        mock.extend_accounts(
            accounts.iter().map(|(address, account)| (*address, ExtendedAccount::new(account.nonce, account.balance))),
        );
        mock
    }

    /// The same accounts as a parent block's output, so the check reads them
    /// from the bundle and never touches the provider -- the fleet's path
    /// when the parent's output is published.
    fn bundle(accounts: &[(Address, Account)]) -> BundleState {
        BundleState::new(
            accounts.iter().map(|(address, account)| {
                (
                    *address,
                    None,
                    Some(AccountInfo { balance: account.balance, nonce: account.nonce, ..Default::default() }),
                    Default::default(),
                )
            }),
            Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
            Vec::new(),
        )
    }

    /// Where the includability check goes on a bench-tier block: the serial
    /// grouping pass, the parallel per-sender pass, and the whole check, with
    /// the senders read from the parent's published output (the fleet's path)
    /// and from the provider. Pinned the way a fleet node runs:
    /// `RAYON_NUM_THREADS=16 taskset -c 0-31 cargo test --release -p n42 --lib
    /// bench_check_includable -- --ignored --nocapture`.
    ///
    /// Two things this bench cannot show. The provider leg's `senders` figure
    /// is the mock's one mutex under 32 chunks at once, not what a state
    /// provider costs -- at `RAYON_NUM_THREADS=1` it is 0.5 ms. And an idle
    /// box flatters a pass this memory-bound: sixteen threads return 1.6x
    /// here, so on a fleet node whose pool is already full the check costs
    /// what it costs in total, which is what the one-thread legs read.
    #[test]
    #[ignore = "timing"]
    fn bench_check_includable() {
        let (block, accounts) = bench_fixture(6_000, 27, 2_000_000, 64);
        let mock = provider(&accounts);
        let parent = bundle(&accounts);
        let grandparent = B256::random();
        let parent_hash = B256::random();
        let ms = |at: std::time::Instant| at.elapsed().as_micros() as f64 / 1000.0;
        println!(
            "block: {} transactions, {} senders, {} bytes a transaction",
            block.body().transactions.len(),
            accounts.len(),
            std::mem::size_of::<TransactionSigned>(),
        );
        for (name, output) in [("parent-output", Some((&parent, grandparent))), ("provider", None)] {
            for round in 0..5 {
                let group_at = std::time::Instant::now();
                let groups = group_by_sender(&block, CHAIN_ID).expect("groups");
                let group_ms = ms(group_at);
                let check_at = std::time::Instant::now();
                check_sender_groups(&mock, parent_hash, output, &block, &groups, SpecId::OSAKA).expect("includable");
                let check_ms = ms(check_at);
                let old_at = std::time::Instant::now();
                check_includable_oracle(&mock, parent_hash, output, &block, CHAIN_ID, SpecId::OSAKA).expect("includable");
                let old_ms = ms(old_at);

                let scan_at = std::time::Instant::now();
                let scans = scan_transactions(&block, CHAIN_ID, SpecId::OSAKA);
                let scan_ms = ms(scan_at);
                let fold_at = std::time::Instant::now();
                let folded = fold_runs(scans);
                let fold_ms = ms(fold_at);
                let senders_at = std::time::Instant::now();
                check_senders(&mock, parent_hash, output, &folded).expect("includable");
                let senders_ms = ms(senders_at);
                let new_at = std::time::Instant::now();
                check_includable(&mock, parent_hash, output, &block, CHAIN_ID, SpecId::OSAKA).expect("includable");
                let new_ms = ms(new_at);
                println!(
                    "{name} round {round}: old group {group_ms:.1} check {check_ms:.1} whole {old_ms:.1} | \
                     new scan {scan_ms:.1} fold {fold_ms:.1} senders {senders_ms:.1} whole {new_ms:.1}",
                );
            }
        }
    }

    /// The two vote roads on the bench's block shape, side by side: today's
    /// gossip body (decode the block out of 26 MB, then look every sender
    /// up) against the compact body (find the block's transactions in this
    /// node's queue by hash, then recompute the transactions root over what
    /// was found).
    ///
    /// Pinned the way a fleet node runs: `RAYON_NUM_THREADS=16 taskset -c
    /// 0-31 cargo test --release -p n42 --lib bench_compact_body_road --
    /// --ignored --nocapture`.
    ///
    /// The caveat every bench in this file carries, and this one most: an
    /// idle pinned box understates what these passes cost on seven nodes.
    /// Both roads walk tens of megabytes -- one of body bytes, one of queue
    /// entries scattered across the heap -- and on a node whose six
    /// neighbours are faulting pages of their own they cost more, never
    /// less. The transfer this replaces (26 MB to six peers, 43 ms at
    /// loop194) is not here at all, and neither is the hand-off to the
    /// blocking pool.
    #[test]
    #[ignore = "timing"]
    fn bench_compact_body_road() {
        use alloy_consensus::transaction::TxHashRef as _;
        use alloy_eips::Encodable2718;
        use n42_h2_consensus::header_profile::N42HeaderProfile;
        use rayon::prelude::*;
        use reth_transaction_pool::PoolTransaction as _;

        let (block, _) = bench_fixture(6_000, 27, 2_000_000, 64);
        let txs = block.body().transactions.clone();
        let senders: Vec<Address> = block.senders().to_vec();
        let count = txs.len();
        let mut header = block.header().clone();
        header.transactions_root = alloy_consensus::proofs::calculate_transaction_root(&txs);
        let announced = header.hash_slow();
        let raw: Vec<alloy_primitives::Bytes> =
            txs.par_iter().map(|tx| alloy_primitives::Bytes::from(tx.encoded_2718())).collect();
        let body = n42_h2_consensus::encode_block_rlp_raw(&header, &raw, &[], None);
        let hashes: Vec<B256> = txs.iter().map(|tx| *tx.tx_hash()).collect();
        let compact = n42_h2_consensus::encode_compact_body(&body, &hashes, N42HeaderProfile::Ethereum)
            .expect("the compact body encodes");

        // The queue as this node's ingest leaves it: every transaction of
        // the block, with the sender the ingest recovered.
        let queue = n42_tx_queue::TxQueue::<n42_engine_types::N42PooledTransaction>::with_run_length(64)
            .with_hash_index(count * 2);
        let fill_at = std::time::Instant::now();
        queue.push(txs.iter().zip(&senders).map(|(tx, sender)| {
            n42_engine_types::N42PooledTransaction::new(
                reth_primitives_traits::Recovered::new_unchecked(tx.clone(), *sender),
                tx.encoded_2718().len(),
            )
        }));
        queue.drain_now();
        let fill_ms = fill_at.elapsed().as_millis() as u64;

        let validator = n42_engine_types::engine_validator::N42EngineValidator::new(
            std::sync::Arc::new((*reth_chainspec::MAINNET).clone()),
            N42HeaderProfile::Ethereum,
        );
        let ms = |at: std::time::Instant| at.elapsed().as_micros() as f64 / 1000.0;
        println!(
            "fixture: {count} transactions, body {} MB, compact {} MB, queue filled in {fill_ms} ms",
            body.len() / 1_000_000,
            compact.len() / 1_000_000,
        );

        for round in 0..3 {
            // Today's road: the body decoded once into the block, then a
            // sender per transaction out of the recovery cache. The cache is
            // filled first, because on the fleet the ingest filled it before
            // the block existed -- a leg that measured recovery here would
            // be measuring something no follower does.
            let decode_at = std::time::Instant::now();
            let (decoded, _) = validator
                .convert_body_to_block(announced, N42HeaderProfile::Ethereum, &body)
                .expect("the body converts");
            let decode_ms = ms(decode_at);
            let cache = reth_evm::SenderRecoveryCache::new(count.next_power_of_two() * 2);
            let filled: usize = decoded
                .body()
                .transactions
                .par_iter()
                .filter(|tx| cache.recover(*tx).is_ok())
                .count();
            let senders_at = std::time::Instant::now();
            let found = decoded
                .body()
                .transactions
                .par_iter()
                .filter(|tx| cache.get(tx.tx_hash()).is_some())
                .count();
            let senders_ms = ms(senders_at);

            // The compact road: the hashes looked up in the queue, the
            // transactions root recomputed over what came back, and the
            // block put together from it.
            let compact_at = std::time::Instant::now();
            let assembled = validator
                .convert_compact_body_to_block(
                    announced,
                    N42HeaderProfile::Ethereum,
                    &compact,
                    &queue,
                    std::time::Duration::ZERO,
                )
                .expect("the compact body assembles");
            let compact_ms = ms(compact_at);
            assert_eq!(assembled.block.hash(), decoded.hash(), "the two roads are the same block");
            assert_eq!(assembled.senders, senders, "and the senders are the queue's");
            println!(
                "round {round}: body decode {decode_ms:.1} + senders {senders_ms:.1} (cached {filled},                  found {found}) = {:.1} | compact {compact_ms:.1} = assemble {:.1} + root {:.1} +                  rest {:.1}, misses {}",
                decode_ms + senders_ms,
                assembled.assemble_us as f64 / 1000.0,
                assembled.root_us as f64 / 1000.0,
                (assembled.total_us.saturating_sub(assembled.assemble_us + assembled.root_us)) as f64 / 1000.0,
                assembled.misses,
            );
        }
    }

    /// The copies the vote road makes of a bench-tier block, each on its own.
    /// loop190 read 50 ms of a 167 ms road that no named part accounted for;
    /// these are the candidates on it that are work rather than a wait, and
    /// this says which of them is worth moving off. Pinned the way a fleet
    /// node runs: `RAYON_NUM_THREADS=16 taskset -c 0-31 cargo test --release
    /// -p n42 --lib bench_vote_road_copies -- --ignored --nocapture`.
    ///
    /// Two things it cannot show. Every one of these walks tens of megabytes
    /// of freshly allocated memory, and an idle box with a warm allocator
    /// flatters them: on a node whose six neighbours are faulting pages of
    /// their own they cost more, never less. And the hand-off to the blocking
    /// pool is not here at all -- that is a runtime's queue, and only the
    /// fleet's `dispatch_ms` measures it.
    #[test]
    #[ignore = "timing"]
    fn bench_vote_road_copies() {
        let (block, _) = bench_fixture(6_000, 27, 2_000_000, 64);
        let count = block.body().transactions.len();
        let sealed = block.sealed_block().clone();
        // Memoized before the rounds, as it is on the road: the conversion
        // sealed the block with its hash, and `remember_sealed` only reads it.
        let _ = sealed.hash();
        let senders: Vec<Address> = block.senders().to_vec();
        let optional: Vec<Option<Address>> = senders.iter().copied().map(Some).collect();
        // The payload's transaction bytes, which the serve path copies twice
        // per block before the import is dispatched.
        let raw: Vec<Bytes> = {
            use alloy_eips::eip2718::Encodable2718 as _;
            block.body().transactions.iter().map(|tx| Bytes::from(tx.encoded_2718())).collect()
        };
        let ms = |at: std::time::Instant| at.elapsed().as_micros() as f64 / 1000.0;
        println!("block: {count} transactions, {} bytes of transactions", raw.iter().map(|b| b.len()).sum::<usize>());
        for round in 0..5 {
            let at = std::time::Instant::now();
            let cloned = sealed.clone();
            let sealed_ms = ms(at);
            // The other half of `remember_sealed`: it keeps three blocks, so
            // every call also frees the one it evicts, under its mutex.
            let at = std::time::Instant::now();
            drop(cloned);
            let drop_ms = ms(at);

            let at = std::time::Instant::now();
            let refs: Vec<&TransactionSigned> = sealed.body().transactions().collect();
            let refs_ms = ms(at);
            drop(refs);

            let at = std::time::Instant::now();
            let misses: Vec<usize> =
                optional.iter().enumerate().filter(|(_, s)| s.is_none()).map(|(i, _)| i).collect();
            let misses_ms = ms(at);
            drop(misses);

            let owned = optional.clone();
            let at = std::time::Instant::now();
            let flat: Vec<Address> = owned.into_iter().map(|s| s.expect("every sender resolved")).collect();
            let flat_ms = ms(at);
            drop(flat);

            let one = sealed.clone();
            let these = senders.clone();
            let at = std::time::Instant::now();
            let recovered = RecoveredBlock::new_sealed(one, these);
            let new_sealed_ms = ms(at);
            drop(recovered);

            let at = std::time::Instant::now();
            let copy = raw.clone();
            let raw_ms = ms(at);
            drop(copy);

            println!(
                "round {round}: sealed.clone {sealed_ms:.1} sealed.drop {drop_ms:.1} txs-collect {refs_ms:.1} \
                 misses {misses_ms:.1} senders-flatten {flat_ms:.1} new_sealed {new_sealed_ms:.1} \
                 raw-transactions.clone {raw_ms:.1}",
            );
        }
    }

    /// The groups are the block's transactions, per sender in block order.
    #[test]
    fn groups_are_block_order() {
        let (block, _) = bench_fixture(8, 5, 64, 3);
        let groups = group_by_sender(&block, CHAIN_ID).expect("groups");
        assert_eq!(groups.len(), 8);
        let mut seen = 0;
        for (sender, indexes) in &groups {
            assert!(indexes.windows(2).all(|w| w[0] < w[1]), "block order");
            for &index in indexes {
                assert_eq!(block.senders()[index], *sender);
            }
            seen += indexes.len();
        }
        assert_eq!(seen, block.body().transactions.len());
    }

    /// A block every sender can pay for is includable; one whose senders are
    /// unknown to the state is not.
    #[test]
    fn accepts_a_funded_block_and_refuses_an_unfunded_one() {
        let (block, accounts) = bench_fixture(8, 5, 64, 3);
        let funded = provider(&accounts);
        let hash = B256::random();
        check_includable(&funded, hash, None, &block, CHAIN_ID, SpecId::OSAKA).expect("includable");
        let empty = provider(&[]);
        let refused = check_includable(&empty, hash, None, &block, CHAIN_ID, SpecId::OSAKA).expect_err("unfunded");
        assert!(refused.contains("of a balance of 0"), "{refused}");
    }

    /// The parent's output answers for a sender the chain's state does not
    /// know yet.
    #[test]
    fn reads_the_parent_output_before_the_state() {
        let (block, accounts) = bench_fixture(8, 5, 64, 3);
        let empty = provider(&[]);
        let parent = bundle(&accounts);
        check_includable(&empty, B256::random(), Some((&parent, B256::random())), &block, CHAIN_ID, SpecId::OSAKA)
            .expect("includable on the parent's output");
    }

    /// A transaction of another chain is refused, and by its index.
    #[test]
    fn refuses_a_foreign_chain_id() {
        let (block, accounts) = bench_fixture(4, 3, 64, 2);
        let refused = check_includable(&provider(&accounts), B256::random(), None, &block, CHAIN_ID + 1, SpecId::OSAKA)
            .expect_err("foreign chain");
        assert!(refused.starts_with("transaction 0: chain id 1,"), "{refused}");
    }

    /// The senders of a block, to keep the fixtures readable.
    fn senders_of(block: &RecoveredBlock<Block>) -> AddressHashMap<usize> {
        let mut counts: AddressHashMap<usize> = Default::default();
        for sender in block.senders() {
            *counts.entry(*sender).or_default() += 1;
        }
        counts
    }

    /// Every sender is grouped once.
    #[test]
    fn every_sender_grouped_once() {
        let (block, _) = bench_fixture(16, 4, 64, 5);
        let groups = group_by_sender(&block, CHAIN_ID).expect("groups");
        let counts = senders_of(&block);
        assert_eq!(groups.len(), counts.len());
        for (sender, indexes) in &groups {
            assert_eq!(indexes.len(), counts[sender]);
        }
    }

    /// A xorshift, so a case is a seed and a failing case is reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A number in `0..n`.
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// One thing wrong with a generated block, so a case can be built with
    /// exactly one and its error message compared word for word.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Flaw {
        /// A sender skips a nonce part-way through its share.
        NonceGap,
        /// A sender repeats the nonce before it.
        DuplicateNonce,
        /// A sender's balance covers all but its last transaction.
        ShortBalance,
        /// A sender neither the state nor the parent's output knows.
        AbsentSender,
        /// A sender the parent's output funded and the state has never seen.
        OnlyInParentOutput,
        /// A transaction of another chain.
        ForeignChainId,
        /// A gas limit under a transfer's intrinsic gas.
        UnderIntrinsicGas,
        /// A fee cap under the block's base fee.
        FeeCapUnderBase,
        /// A priority fee over the fee cap.
        PriorityOverCap,
    }

    /// A transaction before it is signed, so a flaw can be applied to it.
    #[derive(Clone)]
    struct Planned {
        nonce: u64,
        value: u128,
        gas_limit: u64,
        fee_cap: u128,
        priority: u128,
        chain_id: u64,
    }

    /// A generated block with the two states the check can read it against.
    struct Case {
        block: RecoveredBlock<Block>,
        /// What the chain's state at the parent holds.
        state: Vec<(Address, Account)>,
        /// What the parent's published output holds.
        output: Vec<(Address, Account)>,
    }

    /// A block of a few senders' shares, interleaved in short runs so a
    /// sender's transactions straddle the scan's chunks, with `flaws`
    /// applied to senders drawn from the seed.
    fn random_case(seed: u64, flaws: &[Flaw]) -> Case {
        let mut rng = Rng(seed | 1);
        let count = 1 + rng.below(10) as usize;
        let beneficiary = addr(1);
        // The beneficiary sends in a third of the cases: it is a sender like
        // any other here, and the check has no special case for it.
        let sender_at = |i: usize| if i == 0 && seed % 3 == 0 { beneficiary } else { addr(100 + i as u64) };
        let mut lanes: Vec<Vec<Planned>> = Vec::with_capacity(count);
        let mut starts = Vec::with_capacity(count);
        for _ in 0..count {
            let start = rng.below(4);
            let per = 1 + rng.below(5);
            starts.push(start);
            lanes.push(
                (0..per)
                    .map(|k| Planned {
                        nonce: start + k,
                        value: u128::from(rng.below(1_000)),
                        gas_limit: 21_000,
                        fee_cap: FEE_CAP,
                        priority: 1_000_000_000,
                        chain_id: CHAIN_ID,
                    })
                    .collect(),
            );
        }
        let mut state: Vec<(Address, Account)> = (0..count)
            .map(|i| (sender_at(i), Account { nonce: starts[i], balance: U256::from(10u128.pow(21)), bytecode_hash: None }))
            .collect();
        let mut output = state.clone();

        for flaw in flaws {
            let s = rng.below(count as u64) as usize;
            let lane = &mut lanes[s];
            match flaw {
                Flaw::NonceGap => {
                    let k = 1 + rng.below(lane.len() as u64);
                    for planned in lane.iter_mut().skip(k as usize - 1) {
                        planned.nonce += 1;
                    }
                }
                Flaw::DuplicateNonce => {
                    if lane.len() > 1 {
                        let k = 1 + rng.below(lane.len() as u64 - 1) as usize;
                        lane[k].nonce = lane[k - 1].nonce;
                    } else {
                        lane[0].nonce += 1;
                    }
                }
                Flaw::ShortBalance => {
                    // Everything but the last transaction: value plus the
                    // gas at the fee cap.
                    let covered: u128 = lane[..lane.len() - 1].iter().map(|p| p.value + u128::from(p.gas_limit) * p.fee_cap).sum();
                    let short = U256::from(covered);
                    for (address, account) in state.iter_mut().chain(output.iter_mut()) {
                        if *address == sender_at(s) {
                            account.balance = short;
                        }
                    }
                }
                Flaw::AbsentSender => {
                    // An unknown account reads as nonce 0 and no balance, so
                    // the share has to start at 0 for the balance to be what
                    // it fails on.
                    for planned in lane.iter_mut().enumerate() {
                        planned.1.nonce = planned.0 as u64;
                    }
                    state.retain(|(address, _)| *address != sender_at(s));
                    output.retain(|(address, _)| *address != sender_at(s));
                }
                Flaw::OnlyInParentOutput => {
                    state.retain(|(address, _)| *address != sender_at(s));
                }
                Flaw::ForeignChainId => {
                    let k = rng.below(lane.len() as u64) as usize;
                    lane[k].chain_id = CHAIN_ID + 1;
                }
                Flaw::UnderIntrinsicGas => {
                    let k = rng.below(lane.len() as u64) as usize;
                    lane[k].gas_limit = 20_000;
                }
                Flaw::FeeCapUnderBase => {
                    let k = rng.below(lane.len() as u64) as usize;
                    lane[k].fee_cap = u128::from(BASE_FEE) - 1;
                    lane[k].priority = 0;
                }
                Flaw::PriorityOverCap => {
                    let k = rng.below(lane.len() as u64) as usize;
                    lane[k].priority = lane[k].fee_cap + 1;
                }
            }
        }

        let signed: Vec<Vec<TransactionSigned>> = lanes
            .iter()
            .map(|lane| {
                lane.iter()
                    .map(|p| {
                        let inner = TxEip1559 {
                            chain_id: p.chain_id,
                            nonce: p.nonce,
                            gas_limit: p.gas_limit,
                            max_fee_per_gas: p.fee_cap,
                            max_priority_fee_per_gas: p.priority,
                            to: TxKind::Call(addr(900_000)),
                            value: U256::from(p.value),
                            input: Bytes::new(),
                            ..Default::default()
                        };
                        let tx = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
                        TransactionSigned::from(reth_ethereum_primitives::TransactionSigned::from(tx))
                    })
                    .collect()
            })
            .collect();
        // Runs of one to three, so a sender's share is split across runs and
        // the runs have to chain back together.
        let run = 1 + rng.below(3) as usize;
        let longest = signed.iter().map(Vec::len).max().unwrap_or(0);
        let mut txs = Vec::new();
        let mut senders = Vec::new();
        let mut k = 0;
        while k < longest {
            for (s, lane) in signed.iter().enumerate() {
                for tx in lane.iter().skip(k).take(run) {
                    txs.push(tx.clone());
                    senders.push(sender_at(s));
                }
            }
            k += run;
        }
        Case { block: seal(txs, senders, beneficiary), state, output }
    }

    /// Both implementations' verdicts on a case, from both the provider and
    /// the parent's output. `state` is reused across cases: building one
    /// holds a clone of the mainnet chain spec, which dominates a run of
    /// hundreds of small cases.
    fn verdicts(state: &MockEthProvider, case: &Case) -> [(Result<(), String>, Result<(), String>); 2] {
        {
            let mut accounts = state.accounts.lock();
            accounts.clear();
            accounts.extend(
                case.state.iter().map(|(address, account)| (*address, ExtendedAccount::new(account.nonce, account.balance))),
            );
        }
        let parent = bundle(&case.output);
        let grandparent = B256::random();
        let hash = B256::random();
        let read = |output| {
            (
                check_includable_oracle(state, hash, output, &case.block, CHAIN_ID, SpecId::OSAKA),
                check_includable(state, hash, output, &case.block, CHAIN_ID, SpecId::OSAKA),
            )
        };
        [read(None), read(Some((&parent, grandparent)))]
    }

    /// Every flaw, one at a time: the new check refuses the block for the
    /// same transaction and in the same words as the implementation it
    /// replaced, on both the provider and the parent's output.
    #[test]
    fn one_flaw_reports_the_same_error_as_the_oracle() {
        let flaws = [
            Flaw::NonceGap,
            Flaw::DuplicateNonce,
            Flaw::ShortBalance,
            Flaw::AbsentSender,
            Flaw::OnlyInParentOutput,
            Flaw::ForeignChainId,
            Flaw::UnderIntrinsicGas,
            Flaw::FeeCapUnderBase,
            Flaw::PriorityOverCap,
        ];
        let state = provider(&[]);
        let mut refused = 0;
        for flaw in flaws {
            for seed in 1..60u64 {
                let case = random_case(seed * 7919, &[flaw]);
                let read = verdicts(&state, &case);
                for (old, new) in &read {
                    assert_eq!(old, new, "{flaw:?}, seed {seed}");
                }
                refused += usize::from(read[0].0.is_err());
            }
        }
        // `OnlyInParentOutput` is no flaw at all on the parent's output, so
        // not every case is refused -- but most are.
        assert!(refused > 400, "{refused} of 531 cases refused");
    }

    /// A clean block is accepted by both, whatever its shape.
    #[test]
    fn a_clean_block_is_accepted() {
        let state = provider(&[]);
        for seed in 1..200u64 {
            let case = random_case(seed * 104_729, &[]);
            for (old, new) in verdicts(&state, &case) {
                assert_eq!(old, Ok(()), "seed {seed}");
                assert_eq!(new, Ok(()), "seed {seed}");
            }
        }
    }

    /// Blocks wrong in several ways at once: both implementations refuse the
    /// same blocks. Which of the failures is named can differ -- the
    /// implementation this replaced picked the sender group its hash map
    /// happened to iterate first, and the new one names the earliest failing
    /// transaction in block order -- so only the verdict is compared.
    #[test]
    fn many_flaws_give_the_same_verdict_as_the_oracle() {
        let all = [
            Flaw::NonceGap,
            Flaw::DuplicateNonce,
            Flaw::ShortBalance,
            Flaw::AbsentSender,
            Flaw::OnlyInParentOutput,
            Flaw::ForeignChainId,
            Flaw::UnderIntrinsicGas,
            Flaw::FeeCapUnderBase,
            Flaw::PriorityOverCap,
        ];
        let state = provider(&[]);
        for seed in 1..400u64 {
            let mut rng = Rng(seed * 2_654_435_761);
            let flaws: Vec<Flaw> = (0..2 + rng.below(3)).map(|_| all[rng.below(all.len() as u64) as usize]).collect();
            let case = random_case(seed * 15_485_863, &flaws);
            for (old, new) in verdicts(&state, &case) {
                assert_eq!(old.is_ok(), new.is_ok(), "seed {seed}, {flaws:?}: {old:?} against {new:?}");
                if let Err(new) = new {
                    // Whatever it names, it names a transaction of this
                    // block or one of its senders.
                    assert!(new.starts_with("transaction ") || new.starts_with("0x"), "{new}");
                }
            }
        }
    }

    /// An empty block is includable, and neither implementation opens a
    /// state provider for it.
    #[test]
    fn an_empty_block_is_includable() {
        let block = seal(Vec::new(), Vec::new(), addr(1));
        let empty = provider(&[]);
        let hash = B256::random();
        assert_eq!(check_includable_oracle(&empty, hash, None, &block, CHAIN_ID, SpecId::OSAKA), Ok(()));
        assert_eq!(check_includable(&empty, hash, None, &block, CHAIN_ID, SpecId::OSAKA), Ok(()));
    }

    /// The gas limits' sum against the header's, which outranks every
    /// per-sender failure and is reported in the same words.
    #[test]
    fn the_gas_limits_sum_is_checked_before_the_senders() {
        let mut case = random_case(31, &[Flaw::NonceGap]);
        let mut block = case.block.clone_block();
        block.header.gas_limit = 1;
        case.block = RecoveredBlock::new_sealed(SealedBlock::new_unhashed(block), case.block.senders().to_vec());
        for (old, new) in verdicts(&provider(&[]), &case) {
            assert!(old.as_ref().is_err_and(|err| err.starts_with("gas limits sum to")), "{old:?}");
            assert_eq!(old, new);
        }
    }

    /// A sender whose share is split across the scan's chunks: the nonces
    /// have to chain across the joins, and a break at a join is reported at
    /// the transaction the join starts with.
    #[test]
    fn a_share_split_across_chunks_chains_its_nonces() {
        // One sender, enough transactions that the scan's 32 chunks each
        // hold several of them.
        let (block, accounts) = bench_fixture(1, 2_000, 64, 1);
        let state = provider(&accounts);
        let hash = B256::random();
        assert_eq!(check_includable(&state, hash, None, &block, CHAIN_ID, SpecId::OSAKA), Ok(()));
        // The account one nonce ahead: the very first transaction is stale.
        let ahead = provider(&[(accounts[0].0, Account { nonce: 1, ..accounts[0].1 })]);
        let refused = check_includable(&ahead, hash, None, &block, CHAIN_ID, SpecId::OSAKA).expect_err("stale");
        assert_eq!(refused, check_includable_oracle(&ahead, hash, None, &block, CHAIN_ID, SpecId::OSAKA).expect_err("stale"));
        assert!(refused.starts_with("transaction 0: nonce 0,"), "{refused}");
    }
}

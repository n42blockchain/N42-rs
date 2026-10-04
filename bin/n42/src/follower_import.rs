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

/// Blocks this node refused because a transaction's signature named a
/// different sender than the claim its own queue was given for it
/// (`N42_INGEST_VERIFY=leader`). On the `vote road` line, where a healthy
/// leg reads 0 for the whole round: anything else is a proposer that built
/// on a sender nothing had verified.
pub static CLAIM_MISMATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

/// Executions held for their validator's release
/// (`request::HOLD_EXECUTION`, `N42_VOTE_BEFORE_SLOT`), by block hash: the
/// block is assembled and checked, and its vote released, as always; its
/// execution waits here until the validator has an import slot for it.
static HELD_EXECUTIONS: Mutex<Option<std::collections::HashMap<B256, std::sync::mpsc::Receiver<bool>>>> =
    Mutex::new(None);

/// What a held import's error says when its validator dropped it.
pub const HELD_DROPPED: &str = n42_h2_execution::HELD_IMPORT_DROPPED;

/// Holds `block_hash`'s execution until the returned sender says `true`
/// (execute) or `false` (drop). Registered before the import starts; a
/// sender dropped unsent drops the block too, so an import never waits on a
/// release that cannot come.
pub fn hold_execution(block_hash: B256) -> std::sync::mpsc::Sender<bool> {
    let (release, held) = std::sync::mpsc::channel();
    HELD_EXECUTIONS.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(Default::default).insert(block_hash, held);
    release
}

/// Forgets a hold whose import ended without reaching its execution.
pub fn forget_hold(block_hash: B256) {
    if let Some(held) = HELD_EXECUTIONS.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
        held.remove(&block_hash);
    }
}

/// Waits for `block_hash`'s release when its execution is held; at once
/// otherwise. `Err` when it was dropped.
fn wait_for_release(block_hash: B256) -> Result<(), String> {
    let held = HELD_EXECUTIONS.lock().unwrap_or_else(|p| p.into_inner()).as_mut().and_then(|held| held.remove(&block_hash));
    let Some(held) = held else { return Ok(()) };
    match held.recv() {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(HELD_DROPPED.to_owned()),
    }
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

/// The block is *executed* on the parent's published output as well -- the
/// parent's bundle, and under a backlog its own parent's bundle too, laid over
/// the chain's state at the nearest ancestor the engine holds -- instead of
/// waiting for the parent to land in the engine's tree. On by default;
/// `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT=0` turns it off. The follower-side twin
/// of the leader's `opener_on_built_parent` (plan v4 step 2).
///
/// It reads the same published output as [`check_on_parent_output`], so it
/// implies that path; with it on and that flag set to 0 the check still runs
/// on the output, because the parent whose state it would otherwise read is by
/// construction not in the tree.
///
/// Why it is on now, having been dropped at seven nodes (section 2h): there
/// was nothing to gain then -- loop183 measured a 0-1 ms median overlap of its
/// two roads, because at a 275 ms pacing the parent's fields were filed before
/// the child's check passed. At four nodes and a 225 ms pacing the wait it
/// removes is the import's largest unnamed term: `total_ms` minus every named
/// field is 10-14 ms when the chain has slack and 125-190 ms once the import
/// exceeds the cycle, and it is that wait, not the execution, that makes the
/// imports stack up (with two or more in flight the execution itself inflates
/// from 79-83 to 116-149 ms, because their worker pools collide). The wait is
/// named now ([`import_foreign_block`]'s `parent_engine_wait_ms`), so a leg
/// says what this path is worth instead of leaving it in the gap.
fn exec_on_parent_output() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT").map_or(true, |v| v != "0"))
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

/// The last blocks executed here on the build path
/// (`N42_FOLLOWER_BUILD_PATH=1`): the batches' frozen shards and the block's
/// executor's residual laid over them, under the block's hash, kept the moment
/// the block's post-execution checks pass -- before the merge into one bundle
/// and before the root. The child's includability check and its execution read
/// their parent through these ([`ShardLayer`] under the residual, as the
/// leader's chained build reads its sealed parent in `opener_on_sealed_parent`),
/// so the merge the published output ([`PARENT_OUTPUTS`]) waits for is off the
/// vote's chain.
///
/// [`ShardLayer`]: n42_engine_types::output_shards::ShardLayer
type KeptShards =
    (B256, reth_primitives_traits::SealedHeader, Arc<n42_engine_types::output_shards::FrozenShards>, ParentOutput);
static FOLLOWER_SHARDS: Mutex<std::collections::VecDeque<KeptShards>> = Mutex::new(std::collections::VecDeque::new());

/// How many blocks' shards are kept: the child reads its parent's, and under
/// a backlog its grandparent's when that one's merge is not yet published.
const FOLLOWER_SHARDS_KEPT: usize = 2;

/// Whether the child's check and execution read a parent executed here on the
/// build path through its shards the moment they are kept, instead of waiting
/// for the published (merged) output. On by default;
/// `N42_FOLLOWER_CHECK_ON_SHARDS=0` restores the wait for the merge.
fn check_on_shards() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_CHECK_ON_SHARDS").map_or(true, |v| v != "0"))
}

/// Keeps a block's shards and residual for its child's check and execution,
/// and wakes a child waiting for them.
fn keep_follower_shards(
    block_hash: B256,
    header: reth_primitives_traits::SealedHeader,
    shards: Arc<n42_engine_types::output_shards::FrozenShards>,
    residual: ParentOutput,
) {
    {
        let mut kept = FOLLOWER_SHARDS.lock().unwrap_or_else(|p| p.into_inner());
        kept.retain(|(hash, _, _, _)| *hash != block_hash);
        while kept.len() >= FOLLOWER_SHARDS_KEPT {
            kept.pop_front();
        }
        kept.push_back((block_hash, header, shards, residual));
    }
    note_import_landed();
}

/// The header, shards and residual kept for `block_hash`, if it was executed
/// here on the build path and the shards are read ([`check_on_shards`]).
fn follower_shards_of(block_hash: B256) -> Option<(reth_primitives_traits::SealedHeader, ParentLayer)> {
    if !check_on_shards() {
        return None;
    }
    FOLLOWER_SHARDS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(hash, _, _, _)| *hash == block_hash)
        .map(|(_, header, shards, residual)| (header.clone(), ParentLayer::Shards(Arc::clone(shards), Arc::clone(residual))))
}

/// A block's post-state as its child reads it before the engine holds it.
#[derive(Debug, Clone)]
enum ParentLayer {
    /// The one bundle published after the execution (and, on the build path,
    /// after the merge of the shards).
    Merged(ParentOutput),
    /// The build path's frozen shards under the executor's residual, kept
    /// before the merge: the accounts `FrozenShards::merged` would hold.
    Shards(Arc<n42_engine_types::output_shards::FrozenShards>, ParentOutput),
}

impl ParentLayer {
    /// A sender's account after this block, `None` when the block did not
    /// touch it: the residual over the shards, as the merge overlays them
    /// (the newer info wins), and as [`ShardLayer`] under the residual's
    /// overlay answers it.
    ///
    /// [`ShardLayer`]: n42_engine_types::output_shards::ShardLayer
    fn account(&self, sender: &Address) -> Option<reth_primitives_traits::Account> {
        match self {
            Self::Merged(output) => account_after_parent(&output.state, sender),
            Self::Shards(shards, residual) => account_after_parent(&residual.state, sender).or_else(|| {
                shards.get(sender).map(|account| {
                    account
                        .info
                        .as_ref()
                        .map(|info| reth_primitives_traits::Account {
                            nonce: info.nonce,
                            balance: info.balance,
                            bytecode_hash: None,
                        })
                        .unwrap_or_default()
                })
            }),
        }
    }

    /// Its code on the import's timings: 1 merged, 2 shards (0: no layer, the
    /// engine's state at the parent).
    const fn code(&self) -> u64 {
        match self {
            Self::Merged(_) => 1,
            Self::Shards(..) => 2,
        }
    }
}

/// The name of a [`ParentLayer`] code on the log lines (`parent_read`).
pub const fn parent_read_name(code: u64) -> &'static str {
    match code {
        1 => "merged",
        2 => "shards",
        _ => "engine",
    }
}

/// `layers` (newest first, each under its sealed header) over `historical`:
/// consecutive merged outputs as one overlay, a block held as shards as a
/// [`ShardLayer`] with its residual overlaid on top -- the chained build's
/// layering (`opener_on_sealed_parent`).
///
/// [`ShardLayer`]: n42_engine_types::output_shards::ShardLayer
fn open_on_layers(
    historical: reth_provider::StateProviderBox,
    layers: &[(reth_primitives_traits::SealedHeader, ParentLayer)],
) -> reth_provider::StateProviderBox {
    use n42_engine_types::direct_build::{executed_from_output, overlay_on_executed};
    let mut state = historical;
    // Merged outputs still to be laid over `state`, newest first.
    let mut pending: Vec<n42_engine_types::direct_build::ExecutedParent> = Vec::new();
    for (header, layer) in layers.iter().rev() {
        match layer {
            ParentLayer::Merged(output) => pending.insert(0, executed_from_output(header, Arc::clone(output))),
            ParentLayer::Shards(shards, residual) => {
                if !pending.is_empty() {
                    state = overlay_on_executed(state, std::mem::take(&mut pending));
                }
                let shard_layer: reth_provider::StateProviderBox =
                    Box::new(n42_engine_types::output_shards::ShardLayer::new(state, Arc::clone(shards)));
                state = overlay_on_executed(shard_layer, vec![executed_from_output(header, Arc::clone(residual))]);
            }
        }
    }
    if pending.is_empty() { state } else { overlay_on_executed(state, pending) }
}

/// The parent's header and post-state the moment it is readable without the
/// engine: its shards when it was executed here on the build path (kept
/// before the merge, [`keep_follower_shards`]), else its published output;
/// `None` as soon as `parent_in` says the parent is in the engine without
/// either, or if neither happens within [`PARENT_WAIT`]. Only this path keeps
/// or publishes: a parent this node built, or one the engine imported by its
/// own path, never appears, and waiting the whole [`PARENT_WAIT`] for it put
/// three seconds before the child's vote. Behind a 350 ms cycle the child then
/// missed its own import, went by the engine's path too, and so did every
/// block after it (loop156 C1).
///
/// The parent's execution *fields* are not waited for here: they complete
/// with its QMDB root, and the whole point is that the child's includability
/// check runs while that root is computed. The comparison that needs them
/// ([`wait_for_parent_fields`]) waits for them before the vote.
fn wait_for_parent_layer(
    parent_hash: B256,
    parent_in: impl Fn() -> bool,
) -> Option<(reth_primitives_traits::SealedHeader, ParentLayer)> {
    wait_for_layer_within(parent_hash, parent_in, PARENT_WAIT, layer_of)
}

/// A block's layer for its descendant's check and execution: its shards when
/// held, else its published output.
fn layer_of(hash: B256) -> Option<(reth_primitives_traits::SealedHeader, ParentLayer)> {
    follower_shards_of(hash).or_else(|| published_output(hash).map(|(header, output)| (header, ParentLayer::Merged(output))))
}

/// The parent's published (merged) output, waited for up to `wait`: what a
/// build on a peer's block reads ([`published_ancestry`]).
fn wait_for_output_within(
    parent_hash: B256,
    parent_in: impl Fn() -> bool,
    wait: std::time::Duration,
) -> Option<(reth_primitives_traits::SealedHeader, ParentOutput)> {
    wait_for_layer_within(parent_hash, parent_in, wait, published_output)
}

/// Waits up to `wait` for `find` to answer for `parent_hash`, woken by every
/// landing ([`note_import_landed`]) and polling every 20 ms; `None` as soon
/// as `parent_in` says the parent is in the engine.
fn wait_for_layer_within<T>(
    parent_hash: B256,
    parent_in: impl Fn() -> bool,
    wait: std::time::Duration,
    find: impl Fn(B256) -> Option<T>,
) -> Option<T> {
    let deadline = std::time::Instant::now() + wait;
    let (count, landed) = &IMPORT_LANDED;
    let mut seen = *count.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        if let Some(found) = find(parent_hash) {
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

/// The parent's post-state as the includability check reads it while the
/// parent is not in the engine: the bundles this node published for the
/// parent and, under a backlog, for its ancestors, newest first, over the
/// nearest ancestor the engine does hold.
///
/// Newest first because the newest bundle that touched an account is that
/// account's state -- the same rule reth's `MemoryOverlayStateProvider`
/// applies to the same bundles on the execution side, and the reason the two
/// agree by construction.
#[derive(Debug, Clone, Copy)]
struct ParentBundles<'a> {
    /// The parent's layer first, then its parent's, ...
    stack: &'a [&'a ParentLayer],
    /// The nearest ancestor in the engine: where a read that none of the
    /// bundles answers goes.
    anchor: B256,
}

impl ParentBundles<'_> {
    /// A sender's account after the newest bundle that touched it, or `None`
    /// when none did -- in which case the ancestor's state has it unchanged.
    fn account(&self, sender: &Address) -> Option<reth_primitives_traits::Account> {
        self.stack.iter().find_map(|layer| layer.account(sender))
    }
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

#[cfg_attr(not(test), allow(dead_code))] // the tests' entry; the node calls the timed form
fn check_includable<Provider>(
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<ParentBundles<'_>>,
    block: &RecoveredBlock<Block>,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
) -> Result<(), String>
where
    Provider: StateProviderFactory + Sync,
{
    check_includable_timed(provider, parent_hash, parent_output, block, chain_id, spec, &mut CheckTimes::default())
}

/// The header and the body by the consensus rules the engine would apply,
/// the transactions root taken as known (the payload's conversion, or the
/// frame road, computed and matched it against the sealed hash).
fn pre_execution_checks(
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    sealed: &SealedBlock<Block>,
) -> Result<(), String> {
    consensus.validate_header(sealed.sealed_header()).map_err(|err| format!("header: {err}"))?;
    consensus
        .validate_block_pre_execution_with_tx_root(sealed, Some(sealed.transactions_root))
        .map_err(|err| format!("body: {err}"))
}

/// Where the includability check's time went (the vote road's `check_*`
/// keys), and how many of the block's frames it read as summaries.
#[derive(Debug, Clone, Copy, Default)]
struct CheckTimes {
    /// The per-transaction facts: a scan, or the frames' summaries.
    scan_us: u64,
    /// The runs folded per sender.
    fold_us: u64,
    /// Each sender's total against the parent's post-state.
    senders_us: u64,
    /// Frames read from their ingest summary (`N42_FOLLOWER_FRAME_SCAN=1`).
    frames_summarized: u64,
    /// Frames scanned transaction by transaction on the frame road.
    frames_scanned: u64,
}

/// [`check_includable`], timed by part. Under `N42_FOLLOWER_FRAME_SCAN=1` a
/// block the frame road checked is scanned per frame: a frame taken whole
/// from this node's index whose summary answers for this block
/// ([`n42_engine_types::frame_scan::FrameScan::usable`]) gives its runs and
/// totals without its transactions being read; any other frame is scanned as
/// before. The verdict and its message are the same either way (a summary
/// exists only for a frame with nothing to refuse).
#[allow(clippy::too_many_arguments)]
fn check_includable_timed<Provider>(
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<ParentBundles<'_>>,
    block: &RecoveredBlock<Block>,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
    times: &mut CheckTimes,
) -> Result<(), String>
where
    Provider: StateProviderFactory + Sync,
{
    let layout = n42_engine_types::frame_scan::layout_of(&block.hash());
    check_includable_laid_out(provider, parent_hash, parent_output, block, chain_id, spec, layout.as_deref().map(Vec::as_slice), times)
}

/// [`check_includable_timed`] on a given frame layout (`None`: the block's
/// transactions scanned in 32 chunks, as without frames).
#[allow(clippy::too_many_arguments)]
fn check_includable_laid_out<Provider>(
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<ParentBundles<'_>>,
    block: &RecoveredBlock<Block>,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
    layout: Option<&[(B256, usize, bool)]>,
    times: &mut CheckTimes,
) -> Result<(), String>
where
    Provider: StateProviderFactory + Sync,
{
    let scan_at = std::time::Instant::now();
    let tx_count = block.body().transactions.len();
    let layout = layout.filter(|layout| layout.iter().map(|(_, count, _)| *count).sum::<usize>() == tx_count);
    let scans = match layout {
        Some(layout) => scan_by_frames(block, layout, chain_id, spec, times),
        None => scan_transactions(block, chain_id, spec),
    };
    times.scan_us = scan_at.elapsed().as_micros() as u64;
    if let Some(refused) = scans.iter().filter_map(|scan| scan.refused.as_ref()).min_by_key(|fault| fault.index) {
        return Err(refused.message.clone());
    }
    let gas_total = scans.iter().fold(0u64, |total, scan| total.saturating_add(scan.gas_total));
    let gas_limit = block.header().gas_limit;
    if gas_total > gas_limit {
        return Err(format!("gas limits sum to {gas_total}, over the block's {gas_limit}"));
    }
    let fold_at = std::time::Instant::now();
    let senders = fold_runs(scans);
    times.fold_us = fold_at.elapsed().as_micros() as u64;
    let senders_at = std::time::Instant::now();
    let checked = check_senders(provider, parent_hash, parent_output, &senders);
    times.senders_us = senders_at.elapsed().as_micros() as u64;
    checked
}

/// The block's scan, a frame per task: a frame's summary where it answers
/// for this block, else its transactions scanned ([`scan_range`]). Chunked by
/// frame rather than by a 32nd of the block; the chunking is invisible to the
/// fold and to the verdict (the fold joins a sender's runs across chunks).
fn scan_by_frames(
    block: &RecoveredBlock<Block>,
    layout: &[(B256, usize, bool)],
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
    times: &mut CheckTimes,
) -> Vec<ChunkScan> {
    use rayon::prelude::*;
    let base_fee = u128::from(block.header().base_fee_per_gas.unwrap_or(0));
    let txs = &block.body().transactions;
    let senders = block.senders();
    let summaries = n42_engine_types::frame_scan::lookup(layout.iter().map(|(id, _, _)| *id));
    let mut starts = Vec::with_capacity(layout.len());
    let mut at = 0usize;
    for (_, count, _) in layout {
        starts.push(at);
        at += count;
    }
    let scans: Vec<(ChunkScan, bool)> = layout
        .par_iter()
        .zip(summaries.par_iter())
        .zip(starts.par_iter())
        .map(|(((_, count, whole), summary), &start)| {
            let summary = summary.as_deref().filter(|summary| {
                *whole
                    && summary.len == *count
                    && summary.usable(chain_id, spec, base_fee)
                    && summary.runs.iter().all(|run| senders.get(start + run.offset as usize) == Some(&run.sender))
            });
            match summary {
                Some(summary) => (
                    ChunkScan {
                        gas_total: summary.gas_total,
                        refused: None,
                        runs: summary
                            .runs
                            .iter()
                            .map(|run| SenderRun {
                                sender: run.sender,
                                first_index: start + run.offset as usize,
                                first_nonce: run.first_nonce,
                                len: run.len,
                                cost: run.cost,
                                fault: None,
                            })
                            .collect(),
                    },
                    true,
                ),
                None => {
                    let end = start + count;
                    (scan_range(&txs[start..end], &senders[start..end], start, base_fee, chain_id, spec), false)
                }
            }
        })
        .collect();
    let summarized = scans.iter().filter(|(_, summarized)| *summarized).count() as u64;
    times.frames_summarized = summarized;
    times.frames_scanned = scans.len() as u64 - summarized;
    scans.into_iter().map(|(scan, _)| scan).collect()
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
    use rayon::prelude::*;

    let base_fee = u128::from(block.header().base_fee_per_gas.unwrap_or(0));
    let txs = &block.body().transactions;
    let senders = block.senders();
    let chunk = txs.len().div_ceil(32).max(1);
    txs.par_chunks(chunk)
        .enumerate()
        .map(|(nth, txs)| {
            let base = nth * chunk;
            scan_range(txs, &senders[base..base + txs.len()], base, base_fee, chain_id, spec)
        })
        .collect()
}

/// One stretch of the block's transactions, `base` its first index: what
/// [`scan_transactions`] computes per chunk.
fn scan_range(
    txs: &[TransactionSigned],
    senders: &[Address],
    base: usize,
    base_fee: u128,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
) -> ChunkScan {
    use alloy_consensus::Transaction as _;
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
        run.cost = run.cost.saturating_add(n42_engine_types::frame_scan::tx_cost(tx));
    }
    scan
}

/// The intrinsic gas -- the transaction's kind, calldata, access list and
/// authorizations under this fork -- that its gas limit does not cover, or
/// `None` if it does. A block that fails this fails at execution, and the
/// vote that let it through was wrong.
fn intrinsic_gas_shortfall(tx: &TransactionSigned, spec: reth_revm::primitives::hardfork::SpecId) -> Option<u64> {
    n42_engine_types::frame_scan::intrinsic_gas_shortfall(tx, spec)
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

/// A fault's sort key: its index, then its message. Two different senders'
/// transactions never share an index, except at [`usize::MAX`] -- the
/// balance fault every sender in error only that way ties at -- so the
/// message (which leads with the sender's address) is what tells them apart.
/// Without a total order here, which of two tied senders `check_senders`
/// reports depended on the fold's hash map's iteration order: a per-process
/// random seed, so a block with two such senders named a different one on
/// different runs, and named a different one again when the includability
/// check chunked the block by frame instead of by a plain 32nd (a different
/// chunking folds the senders into the map in a different order). Both paths
/// call this, so both settle on the same sender.
fn fault_order(fault: &Fault) -> (usize, &str) {
    (fault.index, fault.message.as_str())
}

/// Each sender's total against the parent's post-state: one account read, the
/// nonces contiguous from the account's, the balance covering the whole
/// share. On the worker pool, each chunk on a state provider of its own; the
/// block's transactions are not touched again here.
fn check_senders<Provider>(
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<ParentBundles<'_>>,
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
            // With the parent's output, a sender none of the published
            // bundles touched is read at the nearest ancestor the engine
            // holds: the oldest of those executions read its state there.
            let state_at = parent_output.map_or(parent_hash, |bundles| bundles.anchor);
            let state = provider.state_by_block_hash(state_at).map_err(|err| format!("parent state: {err}"))?;
            let mut first: Option<Fault> = None;
            for (sender, total) in chunk {
                let after_parent = parent_output.and_then(|bundles| bundles.account(sender));
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
                    && first.as_ref().is_none_or(|held| fault_order(&fault) < fault_order(held))
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
            && first.as_ref().is_none_or(|held| fault_order(&fault) < fault_order(held))
        {
            first = Some(fault);
        }
    }
    first.map_or(Ok(()), |fault| Err(fault.message))
}

/// Says a path was not taken and why, once per import and counted: a leg that
/// reads medians cannot see a path that quietly never runs. The message is the
/// one the runners count (`exec_on_output_declined`).
fn decline_on_output(number: u64, why: &'static str) {
    static DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let declined = DECLINED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    tracing::info!(target: "n42.follower_import", number, why, declined, "not executing on the parent's output; waiting for the parent in the engine");
}

/// The published output of a block imported here, if it is still kept.
fn published_output(hash: B256) -> Option<(reth_primitives_traits::SealedHeader, ParentOutput)> {
    PARENT_OUTPUTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(kept, _, _)| *kept == hash)
        .map(|(_, header, output)| (header.clone(), Arc::clone(output)))
}

/// What a build on a peer's block needs of this node's follower execution of
/// it (`N42_TENURE_FIRST_ON_OUTPUT`, the first build of a tenure): the
/// parent's published output, the outputs to lay over the chain's state
/// (the parent's, then its unimported ancestors', newest first) and the
/// ancestor below them.
#[derive(Debug)]
pub struct PublishedAncestry {
    /// The parent's execution output (its bundle names the nonces it mined).
    pub output: ParentOutput,
    /// The outputs, newest first, each under its sealed header.
    pub executed: Vec<n42_engine_types::direct_build::ExecutedParent>,
    /// The parent of the oldest output: the state the overlay falls through to.
    pub anchor: B256,
    /// How long the parent's output was waited for.
    pub waited: std::time::Duration,
}

/// The published outputs a build on `parent_hash` can stand on, waiting up to
/// `wait` for the parent's own output (its execution may still be running
/// beside the vote when this node becomes leader). The walk back stops at the
/// first ancestor with no output kept here, which becomes the anchor; at most
/// [`PARENT_OUTPUTS_KEPT`] outputs are stacked, as the follower's own path.
///
/// Blocking: the caller runs it off the async runtime.
pub fn published_ancestry(parent_hash: B256, wait: std::time::Duration) -> Result<PublishedAncestry, &'static str> {
    if !publish_parent_outputs() {
        return Err("this node publishes no execution outputs (N42_CHECK_ON_PARENT_OUTPUT and N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT off)");
    }
    if hashed_state_enabled() {
        return Err("the hashed post-state pass is on and no published output carries one (N42_HASHED_TABLES=off is what this path needs)");
    }
    let started = std::time::Instant::now();
    let (header, output) =
        wait_for_output_within(parent_hash, || false, wait).ok_or("the parent's output was not published here in time")?;
    let waited = started.elapsed();
    let mut executed = vec![n42_engine_types::direct_build::executed_from_output(&header, Arc::clone(&output))];
    let mut anchor = header.parent_hash;
    while executed.len() < PARENT_OUTPUTS_KEPT {
        let Some((older, published)) = published_output(anchor) else { break };
        executed.push(n42_engine_types::direct_build::executed_from_output(&older, published));
        anchor = older.parent_hash;
    }
    Ok(PublishedAncestry { output, executed, anchor, waited })
}

/// The parent's post-state while the parent is not in the engine: the outputs
/// this node published for the parent and, under a backlog, for its ancestors,
/// newest first, over the nearest ancestor the engine does hold.
///
/// One block deep is the ordinary case -- the parent executed here a moment
/// ago and its engine insert has not run. Deeper is the congested case, and it
/// is exactly the case the wait was worst in: with the import over the cycle,
/// block N+1 waited for N's root, hashed state and engine insert before it
/// could open a state provider at all, and the waits stacked
/// ([`exec_on_parent_output`]). Stacking the outputs instead costs a hash
/// look-up per bundle on a read none of the newer ones answered.
#[derive(Debug)]
struct Ancestry {
    /// The parent first, then its parent, ... -- the order reth's overlay
    /// expects (`memory_overlay.rs`: "Expected order is newest to oldest") and
    /// the order a read has to take them in.
    ///
    /// Each is the block's shards under its residual when it was executed here
    /// on the build path and they are still kept, else its merged output.
    outputs: Vec<(reth_primitives_traits::SealedHeader, ParentLayer)>,
    /// The nearest ancestor in the engine, whose state a read none of the
    /// bundles answers falls through to.
    anchor: B256,
}

impl Ancestry {
    /// The layers, newest first, for the includability check.
    fn layers(&self) -> Vec<&ParentLayer> {
        self.outputs.iter().map(|(_, layer)| layer).collect()
    }
}

/// Walks back from the parent over the published outputs to the nearest
/// ancestor the engine holds; `None` -- with the reason -- to read the parent
/// in the engine instead, which means waiting for it.
///
/// At most [`PARENT_OUTPUTS_KEPT`] outputs, because that is how many are kept:
/// a follower further behind than that will not catch up by stacking bundles,
/// and the wait is the honest answer.
fn ancestry_of<Provider>(
    provider: &Provider,
    parent: &reth_primitives_traits::SealedHeader,
    layer: &ParentLayer,
    genesis: &alloy_genesis::Genesis,
    deferred: bool,
    number: u64,
) -> Option<Ancestry>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
{
    let mut outputs = vec![(parent.clone(), layer.clone())];
    let mut anchor = parent.parent_hash;
    loop {
        match parent_in(provider, anchor, genesis, deferred) {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(target: "n42.follower_import", number, %err, "looking for the ancestor the parent's output is laid over");
                decline_on_output(number, "the provider could not answer for an ancestor");
                return None;
            }
        }
        if outputs.len() >= PARENT_OUTPUTS_KEPT {
            decline_on_output(number, "more unimported ancestors than there are published outputs");
            return None;
        }
        let Some((header, published)) = layer_of(anchor) else {
            decline_on_output(number, "an ancestor is neither in the engine nor published here");
            return None;
        };
        anchor = header.parent_hash;
        outputs.push((header, published));
    }
    // The fall-through state, opened once here so a state this node does not
    // hold is this refusal rather than a failed import halfway through the
    // block's senders.
    if let Err(err) = provider.state_by_block_hash(anchor) {
        tracing::debug!(target: "n42.follower_import", number, %err, "no state at the ancestor the outputs are laid over");
        decline_on_output(number, "no state at the nearest ancestor in the engine");
        return None;
    }
    Some(Ancestry { outputs, anchor })
}

/// The ancestry as the overlay the block's execution reads -- the ancestor's
/// hash and the published outputs over it -- or `None`, with the reason, to
/// wait for the parent in the engine.
///
/// Sound with `N42_HASHED_TABLES=off`, where an import hands the engine an
/// empty hashed post-state, because the overlay answers `basic_account` and
/// `storage` from each executed block's *bundle*, not from its hashed state
/// (reth v2.5.1 `crates/chain-state/src/memory_overlay.rs:114-124` and
/// `:237-251`; `bytecode_by_hash` at `:253-262` likewise), and takes the first
/// answer -- which, with the outputs newest first, is the newest bundle that
/// touched the account: the state the engine would have had. The only reader
/// of the hashed state through an overlay is reth's Merkle-Patricia pass
/// (`trie_input`, `:52-63`, reached from `hashed_post_state` for an account
/// this block destroyed) -- so while that pass is on, this path is not taken:
/// no published output carries a hashed state and the overlay's would be empty.
fn overlay_parent(
    ancestry: &Ancestry,
    number: u64,
) -> Option<(B256, Vec<(reth_primitives_traits::SealedHeader, ParentLayer)>)> {
    if hashed_state_enabled() {
        // A setting, not a property of this block, so it is said once: with
        // the pass on every block would otherwise print a refusal, and the
        // count of refusals is meant to name the blocks that could not take
        // the path.
        static SAID: std::sync::Once = std::sync::Once::new();
        SAID.call_once(|| {
            tracing::info!(
                target: "n42.follower_import",
                number,
                "not executing on the parent's output: the hashed post-state pass is on and no output carries one (N42_HASHED_TABLES=off is what this path needs)"
            );
        });
        return None;
    }
    Some((ancestry.anchor, ancestry.outputs.clone()))
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
/// made from, the output, whether the worker pool took the block, and the
/// phase timings -- the wait for the execution gate among them.
struct Executed {
    state: reth_provider::StateProviderBox,
    cached: CachedReads,
    /// `None` on the build path, whose output is `sharded` until merged.
    output: Option<reth_provider::BlockExecutionOutput<n42_tx_types::Receipt>>,
    /// The build path's output (`N42_FOLLOWER_BUILD_PATH=1`), its root
    /// already started.
    sharded: Option<StartedShards>,
    parallel: bool,
    gate_ms: u64,
    state_ms: u64,
    exec_ms: u64,
    /// When the execution proper began (after the gate and the state's
    /// opening) and ended, for the import's timeline.
    exec_started: std::time::Instant,
    exec_ended: std::time::Instant,
    /// The parallel execution taken apart ([`ExecSplit`]); zeros on the
    /// serial path.
    split: ExecSplit,
}

/// A build-path execution ([`execute_transfers_build_path_keyed`]) whose
/// QMDB root was started the instant the call returned, on the execution's
/// own thread -- before the execution's line, the join with the vote road
/// and the output's hand-over (`root_gap_ms`, 5-6 ms between `exec_end_ms`
/// and the root's start on the fleet, loop288).
///
/// [`execute_transfers_build_path_keyed`]: n42_engine_types::parallel_transfer::execute_transfers_build_path_keyed
struct StartedShards {
    shards: Arc<n42_engine_types::output_shards::FrozenShards>,
    residual: ParentOutput,
    result: reth_execution_types::BlockExecutionResult<n42_tx_types::Receipt>,
    early_root: EarlyRoot,
    /// When the execution returned: the root's start is timed against it.
    returned: std::time::Instant,
}

/// The follower's parallel execution taken apart for the direct import's
/// line, the leader's `par_*` fields' twins: the partition, the batches'
/// wall, the graft or fold into the block's output (by component: the
/// streamed graft's install, the take and the reverts; on the build path:
/// the index over the batches' maps, the executor's take and the fee
/// credit), the batch count, the
/// pool's threads, and the longest and median batch, milliseconds.
#[derive(Debug, Clone, Copy, Default)]
struct ExecSplit {
    part_ms: u64,
    batches_ms: u64,
    graft_ms: u64,
    batches: u64,
    threads: u64,
    batch_max_ms: u64,
    batch_median_ms: u64,
}

impl ExecSplit {
    const fn of(phases: &n42_engine_types::parallel_transfer::Phases) -> Self {
        Self {
            part_ms: phases.partition_ms,
            batches_ms: phases.groups_ms,
            graft_ms: phases.merge_ms,
            batches: phases.batches as u64,
            threads: phases.threads as u64,
            batch_max_ms: phases.batch_spans.max_ms,
            batch_median_ms: phases.batch_spans.median_ms,
        }
    }
}

/// `N42_FOLLOWER_COPY_ASIDE=1` (default off): a described block's owned
/// `RecoveredBlock` -- the 163,000 transactions copied out of the queue, the
/// seal and reth's well-formedness checks, 6-8 ms on the road (loop291-301)
/// -- is made beside the import instead of before it, and the build path
/// executes the frames' transactions by reference the moment they are taken
/// ([`n42_engine_types::parallel_transfer::execute_transfers_build_path_on`]).
/// What reads the owned block -- the vote road's header and body checks and
/// its includability check, the post-execution checks, the engine's
/// hand-off -- waits for it where it reads it ([`LateBlock`]).
pub fn copy_aside() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_COPY_ASIDE").is_ok_and(|v| v == "1"))
}

/// The owned block a [`DescribedAside`] is made into beside the import, and
/// what its copy cost (microseconds), or why it could not be made.
pub type MadeAside = Result<(RecoveredBlock<Block>, u64), String>;

/// A described block whose owned block is still being made
/// (`N42_FOLLOWER_COPY_ASIDE=1`): what the build path executes by reference,
/// and where the owned block arrives.
#[derive(Debug)]
pub struct DescribedAside {
    /// The header, sealed by the hash the description checked it against.
    pub header: reth_primitives_traits::SealedHeader,
    /// The withdrawals the body lists (`None` before Shanghai).
    pub withdrawals: Option<Vec<alloy_eips::eip4895::Withdrawal>>,
    /// The transactions, held by reference, in block order.
    pub transactions: Arc<Vec<n42_engine_types::engine_validator::DescribedTx>>,
    /// Their senders, this node's queue's.
    pub senders: Arc<Vec<Address>>,
    /// The owned block, made beside the import.
    pub made: std::sync::mpsc::Receiver<MadeAside>,
}

/// The block a foreign import takes: owned, or described with its owned
/// block made aside ([`copy_aside`]).
#[derive(Debug)]
pub enum ForeignBlock {
    /// The owned, sealed block.
    Sealed(SealedBlock<Block>),
    /// A described block, its owned block on the way.
    Aside(DescribedAside),
}

impl ForeignBlock {
    /// How many transactions the block carries.
    pub fn tx_count(&self) -> usize {
        match self {
            Self::Sealed(sealed) => sealed.body().transactions.len(),
            Self::Aside(aside) => aside.transactions.len(),
        }
    }
}

impl From<SealedBlock<Block>> for ForeignBlock {
    fn from(sealed: SealedBlock<Block>) -> Self {
        Self::Sealed(sealed)
    }
}

/// The import's owned block: ready, or made aside and waited for by
/// whichever reader needs it first ([`copy_aside`]). The wait and the copy's
/// cost are kept for the vote road's line.
struct LateBlock {
    ready: std::sync::OnceLock<Result<Arc<RecoveredBlock<Block>>, String>>,
    made: Mutex<Option<std::sync::mpsc::Receiver<MadeAside>>>,
    /// The copy's own cost, beside the import.
    copy_us: std::sync::atomic::AtomicU64,
    /// How long the first reader waited for it.
    wait_us: std::sync::atomic::AtomicU64,
}

impl LateBlock {
    fn ready(block: Arc<RecoveredBlock<Block>>) -> Self {
        Self {
            ready: std::sync::OnceLock::from(Ok(block)),
            made: Mutex::new(None),
            copy_us: Default::default(),
            wait_us: Default::default(),
        }
    }

    fn waiting(made: std::sync::mpsc::Receiver<MadeAside>) -> Self {
        Self {
            ready: std::sync::OnceLock::new(),
            made: Mutex::new(Some(made)),
            copy_us: Default::default(),
            wait_us: Default::default(),
        }
    }

    /// The owned block, waiting for it when it is still being made.
    fn get(&self) -> Result<&Arc<RecoveredBlock<Block>>, String> {
        self.ready
            .get_or_init(|| {
                let at = std::time::Instant::now();
                let made = self.made.lock().unwrap_or_else(|p| p.into_inner()).take();
                let made = match made {
                    Some(made) => made.recv().map_err(|_| "the owned block's maker went away".to_string()),
                    None => Err("no owned block and no maker".to_string()),
                };
                self.wait_us.store(at.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
                let (block, copy_us) = made??;
                self.copy_us.store(copy_us, std::sync::atomic::Ordering::Relaxed);
                Ok(Arc::new(block))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// The copy's cost and the first reader's wait, microseconds.
    fn times(&self) -> (u64, u64) {
        (
            self.copy_us.load(std::sync::atomic::Ordering::Relaxed),
            self.wait_us.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
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
    /// A frame description's frames (`N42_FRAME_BLOCKS=1`); 0 on every
    /// other road. With frames, `root_us` is the frame tree's.
    pub frames: u64,
    /// Of those, how many the first look-up did not find whole.
    pub frames_missing: u64,
    /// Of the frame tree's leaves, how many were the frame's id read from
    /// this node's index (computed at ingest), and how many were hashed
    /// from the body (a filled frame, the cut last frame).
    pub frame_roots_indexed: u64,
    /// See `frame_roots_indexed`.
    pub frame_roots_hashed: u64,
    /// Of `assemble_us`, a frame description's: the queue's frame look-ups
    /// (`take_frames`), one per frame.
    pub road_take_us: u64,
    /// Of `assemble_us`, a frame description's: the list in block order and
    /// its senders, out of the frames taken.
    pub road_body_us: u64,
    /// Of `assemble_us`, a frame description's: the payload list's share of
    /// the road (its blob versioned hashes; the list itself is encoded beside
    /// the import).
    pub road_encode_us: u64,
    /// Block by description only (`N42_BLOCK_BY_DESCRIPTION`): copying the
    /// block's transactions out of the queue into the owned block reth's
    /// execution takes, after the description was checked by reference.
    pub copy_us: u64,
    /// Compact body road only: how many of the block's hashes the first
    /// pass did not find. Nonzero with a vote released means the wait was
    /// enough; a road that gave up logs a line of its own and is not this
    /// one.
    pub misses: u64,
    /// How long the request's first byte sat in the channel's socket before
    /// the road read it: from the kernel's receive timestamp to `started`.
    /// Not part of `total_ms`, which starts where this ends. 0 unless measured
    /// (`N42_ROAD_RUNTIME=1` or `N42_ROAD_DISPATCH_WAIT=1`).
    pub dispatch_wait_us: u64,
    /// When the request's first byte arrived, for the total.
    pub started: std::time::Instant,
}

/// What the import itself spent on the road, in microseconds -- with the one
/// exception named below. Carried whole so a part added here reaches the line
/// without another argument.
#[derive(Debug, Clone, Copy, Default)]
struct RoadPhases {
    /// Not a duration: how many of the block's senders came out of the
    /// transaction queue's by-hash index rather than a cache look-up or a
    /// recovery (`N42_SENDERS_FROM_QUEUE`). It rides here because it belongs
    /// beside `senders_us` on the line, and it is left out of the sum the
    /// line's `other_ms` is made from.
    senders_indexed: u64,
    /// Not durations either, and for the same reason. Under
    /// `N42_INGEST_VERIFY=leader` the ingest took its senders from the frame
    /// without checking a signature, so the road pays for them here:
    /// `verified_on_road` is how many of the block's senders this node
    /// computed from the signature (0x50 in batches, secp256k1 by recovery),
    /// and `claims_checked` how many of those it could compare against the
    /// claim its own queue holds. A block whose claim and signature disagree
    /// never gets this far -- the import fails before the vote.
    verified_on_road: u64,
    claims_checked: u64,
    /// The header and body consensus checks, and before the deferred fork the
    /// parent lookup ahead of them.
    header_us: u64,
    /// Sender recovery and the recovered block.
    senders_us: u64,
    /// Waiting for the parent header or for its published output.
    parent_wait_us: u64,
    /// `validate_against_parent` and `check_includable`: what the vote attests.
    check_us: u64,
    /// Of `check_us`: the header against the parent (0 when the parent's
    /// output is read, where the header waits for the fields instead).
    check_header_us: u64,
    /// Of `check_us`: `check_includable` whole; the rest of `check_us` is the
    /// check pool's hand-off (`check_other_ms`).
    check_include_us: u64,
    /// Of `check_include_us`: the per-transaction facts, the fold per
    /// sender, and the senders against the parent ([`CheckTimes`]). Not in
    /// the line's sum, and neither are the frame counts below.
    check_scan_us: u64,
    check_fold_us: u64,
    check_senders_us: u64,
    check_frames_summarized: u64,
    check_frames_scanned: u64,
    /// Waiting for the parent's execution fields, and the header against them.
    fields_us: u64,
    /// Of `fields_us` (or, under `N42_FOLLOWER_EXEC_EARLY=1`, of the check):
    /// the wait alone for the parent's execution fields -- what the vote on
    /// this block waited for the parent's QMDB root. Not in the line's sum.
    parent_fields_wait_us: u64,
    /// Of `parent_wait_us`: the wait for the parent's output (its shards on
    /// the build path, else its published bundle) that the includability
    /// check and the early execution read. Not in the line's sum.
    parent_output_wait_us: u64,
    /// What the check read the parent through: 0 the engine, 1 the merged
    /// output, 2 the shards ([`parent_read_name`]).
    parent_read: u64,
    /// `N42_FOLLOWER_COPY_ASIDE=1`: the owned block's copy, made beside the
    /// import (not on the road; not in the line's sum), and how long the
    /// vote road waited for it.
    copy_aside_us: u64,
    copy_wait_us: u64,
}

impl RoadPhases {
    /// The check's parts, from one run of [`check_includable_timed`].
    const fn note_check(&mut self, header_us: u64, include_us: u64, times: CheckTimes) {
        self.check_header_us = header_us;
        self.check_include_us = include_us;
        self.check_scan_us = times.scan_us;
        self.check_fold_us = times.fold_us;
        self.check_senders_us = times.senders_us;
        self.check_frames_summarized = times.frames_summarized;
        self.check_frames_scanned = times.frames_scanned;
    }
}

/// The header against the parent when `against` is set, then the
/// includability, timed by part: (header us, includability us).
#[allow(clippy::too_many_arguments)]
fn timed_check<Provider>(
    against: Option<(&(dyn FullConsensus<EthPrimitives> + Send + Sync), &reth_primitives_traits::SealedHeader, &reth_primitives_traits::SealedHeader)>,
    provider: &Provider,
    parent_hash: B256,
    parent_output: Option<ParentBundles<'_>>,
    block: &RecoveredBlock<Block>,
    chain_id: u64,
    spec: reth_revm::primitives::hardfork::SpecId,
    times: &mut CheckTimes,
) -> Result<(u64, u64), String>
where
    Provider: StateProviderFactory + Sync,
{
    let header_at = std::time::Instant::now();
    if let Some((consensus, header, parent)) = against {
        validate_against_parent(consensus, header, parent)?;
    }
    let header_us = header_at.elapsed().as_micros() as u64;
    let include_at = std::time::Instant::now();
    check_includable_timed(provider, parent_hash, parent_output, block, chain_id, spec, times)?;
    Ok((header_us, include_at.elapsed().as_micros() as u64))
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
        + road.copy_us
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
        dispatch_wait_ms = road.dispatch_wait_us / 1000,
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
        frames = road.frames,
        frames_missing = road.frames_missing,
        frame_root_ms = if road.frames > 0 { road.root_us / 1000 } else { 0 },
        frame_root_us = if road.frames > 0 { road.root_us } else { 0 },
        frame_root_indexed = road.frame_roots_indexed,
        frame_root_hashed = road.frame_roots_hashed,
        road_take_ms = road.road_take_us / 1000,
        road_body_ms = road.road_body_us / 1000,
        road_encode_ms = road.road_encode_us / 1000,
        copy_ms = road.copy_us / 1000,
        copy_aside_ms = phases.copy_aside_us / 1000,
        copy_wait_ms = phases.copy_wait_us / 1000,
        header_ms = phases.header_us / 1000,
        senders_ms = phases.senders_us / 1000,
        senders_indexed = phases.senders_indexed,
        verified_on_road = phases.verified_on_road,
        claims_checked = phases.claims_checked,
        claim_mismatch = CLAIM_MISMATCH.load(std::sync::atomic::Ordering::Relaxed),
        parent_wait_ms = phases.parent_wait_us / 1000,
        check_ms = phases.check_us / 1000,
        // The check taken apart: the frame tree's root (on the road, before
        // the check), the header against the parent, the includability
        // (scan, fold, senders) and the rest (the check pool's hand-off).
        check_root_us = if road.frames > 0 { road.root_us } else { 0 },
        check_header_us = phases.check_header_us,
        check_include_us = phases.check_include_us,
        check_scan_us = phases.check_scan_us,
        check_fold_us = phases.check_fold_us,
        check_senders_us = phases.check_senders_us,
        check_other_us = phases.check_us.saturating_sub(phases.check_header_us + phases.check_include_us),
        check_frames_summarized = phases.check_frames_summarized,
        check_frames_scanned = phases.check_frames_scanned,
        fields_ms = phases.fields_us / 1000,
        parent_fields_wait_ms = phases.parent_fields_wait_us / 1000,
        parent_output_wait_ms = phases.parent_output_wait_us / 1000,
        parent_read = parent_read_name(phases.parent_read),
        other_ms = total.saturating_sub(named) / 1000,
        total_ms = total / 1000,
        "vote road"
    );
}

/// The senders this node's transaction queue holds for `txs`, by hash, and
/// `None` wherever it holds none. One parallel pass; the block's hashes are
/// already computed, so it reads a hash off each transaction and a shard of
/// the index, and copies out an address.
///
/// Why the queue's sender may be taken as the transaction's: nothing enters
/// this queue without this node having recovered its sender from the
/// signature -- the ingest's batch verification, the pool's validation, or a
/// reverted block's own recovered senders. A wrong sender here would be a
/// wrong sender in the ingest, and the same wrong sender would already be in
/// the block the ingest's own node built.
///
/// That holds everywhere but one mode: under `N42_INGEST_VERIFY=leader` the
/// ingest queues a transaction under the sender its frame claimed, without
/// checking a signature, so what this returns there is a claim. The caller
/// knows which it asked for -- in that mode it verifies every sender and
/// uses these only to check the claim against the signature.
///
/// What catches one all the same: `check_includable`, which reads each
/// sender's account and refuses a block whose nonces do not continue the
/// chain's -- a sender invented here has the wrong nonce almost surely, and
/// the vote is not released until that check has passed. The block's hash
/// and transactions root bind the *transactions* to the header the members
/// voted on; they say nothing about senders, so the nonce check is the one
/// that does.
///
/// A miss costs a fall back to the caches and a recovery, never correctness:
/// the index is a cache, and the ingest running a few milliseconds behind
/// the block, or a transaction that never came through this node at all, is
/// an ordinary miss.
fn senders_in_queue(
    queue: &n42_tx_queue::TxQueue<n42_engine_types::N42PooledTransaction>,
    txs: &[&TransactionSigned],
) -> Vec<Option<Address>> {
    use rayon::prelude::*;
    txs.par_iter().map(|tx| queue.sender_of(tx.tx_hash())).collect()
}

/// The queue to take senders from on a foreign block's road, when
/// `N42_SENDERS_FROM_QUEUE=1` and this node keeps a by-hash index (the queue
/// itself is `N42_TX_QUEUE`). `None` and the senders are looked up as they
/// always were.
fn queue_for_senders() -> Option<n42_tx_queue::TxQueue<n42_engine_types::N42PooledTransaction>> {
    // In the claimed mode the index is read for the claim rather than for
    // the answer, and that is worth doing whenever the index exists at all
    // -- it is what lets a wrong claim be named instead of merely failing
    // the block somewhere downstream.
    // `N42_INGEST_VERIFY=shard` (an unsafe benchmark probe): the index holds
    // claims nothing re-verifies, and they are read as the answer -- the
    // claimed mode's check below stays off, which is the probe's point.
    if !n42_tx_queue::senders_from_queue()
        && !n42_tx_types::senders_claimed_at_ingest()
        && n42_tx_types::ingest_shard().is_none()
    {
        return None;
    }
    n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>().filter(|queue| queue.has_hash_index())
}

/// Executes and checks `sealed` on its parent's state. See the module docs.
/// Returns the executed block and the phase timings in milliseconds: header
/// checks, senders, execution, the post-execution checks, state root, hashed
/// state; then the number of senders the recovery cache held, the parent-state
/// lookup, the carry, the wait for the parent to be canonical in the engine,
/// the wait for the execution gate, and the wait for the parent's own root.
///
/// Under deferred execution (a block stamped at or past the chain's
/// `deferredExecutionTime`) the block is *checked* first -- its header's
/// execution fields against this node's result for the parent, its
/// transactions' includability on the parent's post-state -- and `checked`
/// is told so before the execution starts: that is the follower's vote. A
/// block before the fork sends nothing on it.
#[allow(clippy::too_many_arguments)]
pub fn import_foreign_block<Provider, Evm, ChainSpec>(
    block: ForeignBlock,
    provider: &Provider,
    evm_config: &Evm,
    senders_cache: Option<&reth_evm::SenderRecoveryCache>,
    mut given_senders: Option<Vec<Address>>,
    carry: &Arc<CarriedReads>,
    qmdb: Option<&n42_qmdb_reth::QmdbNodeState>,
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    chain_spec: &ChainSpec,
    mut checked: Option<tokio::sync::oneshot::Sender<()>>,
    road: VoteRoad,
) -> Result<(Box<BuiltPayloadExecutedBlock<EthPrimitives>>, [u64; IMPORT_TIMES]), String>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
    Evm: ConfigureEvm<
        Primitives = EthPrimitives,
        BlockExecutorFactory = n42_engine_types::parallel_transfer::FastExecutorFactory,
    > + 'static,
    ChainSpec: reth_chainspec::EthereumHardforks + reth_chainspec::EthChainSpec,
{
    let qmdb = qmdb.ok_or("no QMDB state: the direct import needs the chain's root")?;
    let started = std::time::Instant::now();
    // The block's chain on this node, against the instant its request's first
    // byte landed (the road's start): when the vote was released, when the
    // execution ran, when the root and the fields were done.
    let road_started = road.started;
    let vote_at: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    // The vote's wait for the parent's fields, out of whichever road waited.
    let parent_fields_wait_us = std::sync::atomic::AtomicU64::new(0);
    // `N42_FOLLOWER_COPY_ASIDE=1`: a described block is executed by
    // reference only where the execution runs beside the vote road on the
    // build path with this node's own senders; anywhere else its owned block
    // is waited for here and the import is the one it always was.
    let by_ref_road = |timestamp: u64| {
        reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), timestamp)
            && exec_early()
            && follower_parallel()
            && n42_engine_types::parallel_transfer::follower_build_path()
            && !n42_tx_types::senders_claimed_at_ingest()
    };
    // The described block's parts the execution reads by reference, and
    // where its owned block arrives.
    let (head, owned, by_ref, made) = match block {
        ForeignBlock::Sealed(sealed) => (sealed.clone_sealed_header(), Some(sealed), None, None),
        ForeignBlock::Aside(DescribedAside { header, withdrawals, transactions, senders, made })
            if by_ref_road(header.timestamp) =>
        {
            (header, None, Some((transactions, senders, withdrawals)), Some(made))
        }
        ForeignBlock::Aside(aside) => {
            let (block, _) = aside.made.recv().map_err(|_| "the owned block's maker went away".to_string())??;
            let (sealed, senders) = block.split_sealed();
            given_senders = Some(senders);
            (sealed.clone_sealed_header(), Some(sealed), None, None)
        }
    };
    let stage = ImportStage(head.number);
    stage.at(1);
    let parent_hash = head.parent_hash;
    let number = head.number;
    let block_hash = head.hash();
    let tx_count = match (&owned, &by_ref) {
        (Some(sealed), _) => sealed.body().transactions.len(),
        (None, Some((transactions, _, _))) => transactions.len(),
        (None, None) => 0,
    };

    let deferred = reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), head.timestamp);
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
    //
    // Under `N42_FOLLOWER_EXEC_EARLY=1` (deferred execution) they are the
    // vote road's first step instead, beside the execution: nothing the
    // execution reads depends on them, and the vote still waits for them. A
    // block they refuse is refused by the vote road, whose error wins over
    // the execution's ([`two_roads`]); only which error an already invalid
    // block reports first can differ.
    let header_on_vote_road = deferred && exec_early();
    if !header_on_vote_road && let Some(sealed) = &owned {
        pre_execution_checks(consensus, sealed)?;
    }
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
    // Under `N42_INGEST_VERIFY=leader` the queue's senders are the frames'
    // claims rather than this node's recoveries, so the compact body's
    // answer stops being an answer: it becomes the claim list the pass below
    // checks the signatures against. Everything else about that road is
    // unchanged.
    let (given_senders, given_claims) = match given_senders {
        Some(senders) if n42_tx_types::senders_claimed_at_ingest() => (None, Some(senders)),
        given => (given, None),
    };
    if let Some(claims) = &given_claims
        && claims.len() != tx_count
    {
        return Err(format!("given {} senders for {tx_count} transactions", claims.len()));
    }
    let cache_hits_out = std::sync::atomic::AtomicU64::new(0);
    let late = match owned {
        None => LateBlock::waiting(made.ok_or("no block to import")?),
        Some(sealed) => {
            let recovered = match given_senders {
                Some(senders) if senders.len() != tx_count => {
                    return Err(format!("given {} senders for {tx_count} transactions", senders.len()));
                }
                Some(senders) => RecoveredBlock::new_sealed(sealed, senders),
                None => {
                    let cache_hits = std::sync::atomic::AtomicU64::new(0);
                    // Senders this road computed from a signature rather than read
                    // out of a cache or an index: what the ingest no longer pays for
                    // under `N42_INGEST_VERIFY=leader`.
                    let verified_here = std::sync::atomic::AtomicU64::new(0);
                    let alt_cache = n42_tx_types::AltSigSenderCache::global();
                    let txs: Vec<&TransactionSigned> = sealed.body().transactions().collect();
                    // The transaction queue's by-hash index first, where it is kept:
                    // every transaction of a block this node's ingest has already
                    // seen sits there with the sender that ingest recovered, and
                    // reading one is a shard's read lock rather than a look-up in a
                    // cache sixteen other threads are writing to (34 ms a block on
                    // the fleet at 163,000 transactions, loop202). See
                    // [`senders_in_queue`] for why it may be trusted and what would
                    // catch it if it could not be.
                    let indexed: Vec<Option<Address>> = match given_claims {
                        // The compact body's assembly already read every one of them
                        // out of this node's queue; the index is not asked twice.
                        Some(claims) => claims.into_iter().map(Some).collect(),
                        None => queue_for_senders().map_or_else(Vec::new, |queue| senders_in_queue(&queue, &txs)),
                    };
                    let from_index = indexed.iter().flatten().count();
                    // Under `N42_INGEST_VERIFY=leader` the queue holds the frame's
                    // word for a sender, not this node's recovery of it, so what the
                    // index gives is a claim: something to check the signature
                    // against, never the answer to take. Everything below then falls
                    // through to the caches and, on a miss, to the verification --
                    // which is the whole point of the mode.
                    let (claims, indexed) = if n42_tx_types::senders_claimed_at_ingest() {
                        phases.claims_checked = from_index as u64;
                        (indexed, Vec::new())
                    } else {
                        phases.senders_indexed = from_index as u64;
                        (Vec::new(), indexed)
                    };
                    let mut senders: Vec<Option<Address>> = if !indexed.is_empty() && from_index == tx_count {
                        // Nothing left to look up: the pass below would walk 33 MB
                        // of transactions to read a discriminant per transaction and
                        // decide it already has the answer.
                        indexed
                    } else {
                        use rayon::prelude::*;
                        // Collected into a `Vec<Result>` (written in place) and checked after:
                        // a parallel collect straight into `Result<Vec>` takes rayon's
                        // short-circuiting path, three times the cost at 163,000 items
                        // (round 43, `bench_convert_payload`).
                        let looked_up: Vec<Result<Option<Address>, String>> = txs
                            .par_iter()
                            .enumerate()
                            .map(|(at, tx)| {
                                if let Some(sender) = indexed.get(at).copied().flatten() {
                                    return Ok(Some(sender));
                                }
                                match tx {
                                    TransactionSigned::AltSig(alt) => Ok(alt_cache.get(alt.hash()).inspect(|_| {
                                        cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    })),
                                    TransactionSigned::Eth(_) => {
                                        if let Some(sender) = senders_cache.and_then(|cache| cache.get(tx.tx_hash())) {
                                            cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            return Ok(Some(sender));
                                        }
                                        // ecrecover is the verification: a sender
                                        // that comes out of it is this node's own,
                                        // whatever the frame claimed.
                                        verified_here.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        tx.recover_signer()
                                            .map(Some)
                                            .map_err(|err| format!("sender of {}: {err}", tx.tx_hash()))
                                    }
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
                    phases.verified_on_road =
                        verified_here.load(std::sync::atomic::Ordering::Relaxed) + misses.len() as u64;
                    let senders: Vec<Address> = senders.into_iter().map(|s| s.expect("every sender resolved")).collect();
                    // The claim against the signature, where this node holds both.
                    // A disagreement is the proposer's error -- it built a block on
                    // a sender nothing verified -- and the vote is not released for
                    // it. Nothing here depends on the claim being right; this is
                    // what says so out loud instead of letting the block fail later
                    // on a nonce nobody can explain.
                    if !claims.is_empty() {
                        use rayon::prelude::*;
                        let mismatch = claims
                            .par_iter()
                            .zip(senders.par_iter())
                            .position_any(|(claim, sender)| matches!(claim, Some(claimed) if claimed != sender));
                        if let Some(at) = mismatch
                            && let Some(claimed) = claims[at]
                        {
                            CLAIM_MISMATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return Err(format!(
                                "transaction {at} ({}): its signature says {}, this node's queue was told {claimed}",
                                txs[at].tx_hash(),
                                senders[at],
                            ));
                        }
                    }
                    cache_hits_out.store(cache_hits.into_inner(), std::sync::atomic::Ordering::Relaxed);
                    RecoveredBlock::new_sealed(sealed, senders)
                }
            };
            // Shared from here on: the executed block hands the engine this same
            // `Arc`, and a plan made ahead of the execution holds it meanwhile.
            LateBlock::ready(Arc::new(recovered))
        }
    };
    let cache_hits = cache_hits_out.load(std::sync::atomic::Ordering::Relaxed);
    phases.senders_us = senders_at.elapsed().as_micros() as u64;
    let senders_ms = phases.senders_us / 1000;

    // `N42_FOLLOWER_PARTITION_AHEAD=1`: the block's senders are known from
    // this point (the compact body's assembly read them out of the queue),
    // so its transfers' environments and partition are made now, on the
    // worker pool, beside the wait for the parent and the includability
    // check, instead of inside the execution gate (19 ms of a 122 ms gated
    // execution at 163,000 transfers, loop234). The execution takes the plan
    // just before the gate; one it cannot use is planned again there.
    // Not on the build path (`N42_FOLLOWER_BUILD_PATH=1`), which partitions by
    // sender inside its call and converts each transaction on its batch's
    // thread, as the leader does.
    let plan_ahead = (follower_parallel()
        && n42_engine_types::parallel_transfer::follower_partition_ahead()
        && !(deferred && n42_engine_types::parallel_transfer::follower_build_path()))
    .then(|| late.get().map(Arc::clone))
    .transpose()?
    .map(|block| {
        let (planned, plan) = std::sync::mpsc::sync_channel(1);
        let evm_config = evm_config.clone();
        rayon::spawn(move || {
            let made = n42_engine_types::parallel_transfer::plan_transfers(&evm_config, &block);
            drop(block);
            let _ = planned.send(made);
        });
        plan
    });

    // `N42_FOLLOWER_PARTITION_AHEAD=1` on the build path: the block's
    // (sender, recipient) keys, which its partition reads, made on the build
    // pool from here, beside the wait for the parent and the check, instead
    // of inside the execution (`exec_part_ms`).
    let keys_ahead = (deferred
        && follower_parallel()
        && n42_engine_types::parallel_transfer::follower_partition_ahead()
        && n42_engine_types::parallel_transfer::follower_build_path())
    .then(|| -> Result<_, String> {
        let (made, keys) = std::sync::mpsc::sync_channel(1);
        // A described block's keys from its transactions by reference
        // (`N42_FOLLOWER_COPY_ASIDE=1`), the moment its frames are taken.
        match &by_ref {
            Some((transactions, senders, _)) => {
                let (transactions, senders) = (Arc::clone(transactions), Arc::clone(senders));
                n42_engine_types::parallel_transfer::build_pool().spawn(move || {
                    let keys = n42_engine_types::parallel_transfer::build_path_keys_of(&transactions, &senders);
                    drop((transactions, senders));
                    let _ = made.send(keys);
                });
            }
            None => {
                let block = Arc::clone(late.get()?);
                n42_engine_types::parallel_transfer::build_pool().spawn(move || {
                    let keys = n42_engine_types::parallel_transfer::build_path_keys(&block);
                    drop(block);
                    let _ = made.send(keys);
                });
            }
        }
        Ok(keys)
    })
    .transpose()?;

    // The parent: in, and under deferred execution executed here, since the
    // header's fields are checked against its result and the transactions
    // against its post-state.
    //
    // Under the build path the parent's layer is its shards the moment its
    // execution's post-execution checks pass, not its published output, which
    // waits for the merge of those shards (45 ms on one thread, section 10.31
    // of `docs/BREAKTHROUGH_DESIGN.md`): the merge is then only the engine's
    // hand-off, and nothing on the vote's chain waits for it.
    let parent_at = std::time::Instant::now();
    let (parent, parent_output) = match parent_known {
        Some(parent) => (parent, None),
        None => match (deferred && publish_parent_outputs())
            .then(|| {
                wait_for_parent_layer(parent_hash, || {
                    parent_in(provider, parent_hash, chain_spec.genesis(), deferred).ok().flatten().is_some()
                })
            })
            .flatten()
        {
            Some((parent, layer)) => (parent, Some(layer)),
            None => (wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?, None),
        },
    };
    phases.parent_wait_us = parent_at.elapsed().as_micros() as u64;
    let parent_done = std::time::Instant::now();
    // What the check and the early execution waited for the parent's output
    // (its shards or its merged bundle), and which one they read.
    let parent_read = parent_output.as_ref().map_or(0, ParentLayer::code);
    phases.parent_output_wait_us = if parent_output.is_some() { phases.parent_wait_us } else { 0 };
    phases.parent_read = parent_read;
    let parent_output_wait_ms = phases.parent_output_wait_us / 1000;
    let against_parent = || validate_against_parent(consensus, &head, &parent);

    // How long this import waited for its parent to be *canonical in the
    // engine*, with its execution recorded. This was the one region of the
    // import nothing timed: `total_ms` minus every named field read 10-14 ms
    // with slack in the chain and 125-190 ms once the import passed the cycle,
    // which is where the four-node collapse lived (plan v4, loop199-204). It
    // is a sum because a block can wait in two places -- before its check when
    // there is nothing published to read the parent's state through, and
    // before its execution when that execution reads the engine's tree.
    let mut parent_engine_wait_us = 0u64;

    // The parent's post-state without the parent in the engine: what this node
    // published for the parent and, under a backlog, for its ancestors, over
    // the nearest ancestor the engine holds. `None` and both the check and the
    // execution read the engine's state at the parent, which means waiting for
    // it.
    let ancestry = parent_output
        .as_ref()
        .and_then(|output| ancestry_of(provider, &parent, output, chain_spec.genesis(), deferred, number));
    if parent_output.is_some() && ancestry.is_none() {
        // Published, but with no ancestor to read through: the engine's state
        // at the parent is the only one left, and the check below opens it.
        let wait_at = std::time::Instant::now();
        wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?;
        parent_engine_wait_us += wait_at.elapsed().as_micros() as u64;
    }
    let stack = ancestry.as_ref().map(Ancestry::layers);
    let parent_state = match (&stack, &ancestry) {
        (Some(stack), Some(ancestry)) => Some(ParentBundles { stack, anchor: ancestry.anchor }),
        _ => None,
    };

    // Set on the exec-on-parent-output path: the ancestor whose state the
    // published outputs are laid over and those outputs as executed blocks,
    // and the instant the vote road and the execution started together.
    let mut executed_parent = None;
    let mut roads_at = None;
    // `N42_FOLLOWER_EXEC_EARLY=1` took this block: the check runs on the vote road.
    let mut early_check = false;
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
        // `N42_FOLLOWER_EXEC_EARLY=1`: where the execution reads the
        // parent's post-state is decided first, and when it needs no wait --
        // the published outputs over the nearest ancestor the engine holds,
        // or the engine's tree with the parent already in it -- the execution
        // starts now and the whole vote road, the includability check
        // included, runs beside it ([`two_roads`]). The check's verdict is the
        // same and still comes before the vote; only the execution no longer
        // waits for it.
        early_check = exec_early() && {
            if let Some(ancestry) = &ancestry
                && exec_on_parent_output()
                && parent_in(provider, parent_hash, chain_spec.genesis(), deferred)?.is_none()
            {
                executed_parent = overlay_parent(ancestry, number);
            }
            executed_parent.is_some() || parent_state.is_none()
        };
        if early_check {
            roads_at = Some(std::time::Instant::now());
            tracing::debug!(
                target: "n42.follower_import",
                number,
                "executing before the check; the check and the rest of the vote road run beside the execution"
            );
        } else {
            let recovered = late.get()?;
            (phases.copy_aside_us, phases.copy_wait_us) = late.times();
            if header_on_vote_road {
                let header_at = std::time::Instant::now();
                pre_execution_checks(consensus, recovered.sealed_block())?;
                phases.header_us += header_at.elapsed().as_micros() as u64;
            }
            let check_at = std::time::Instant::now();
            let mut times = CheckTimes::default();
            let (header_us, include_us) = timed_check(
                parent_state.is_none().then(|| (consensus, recovered.sealed_header(), &parent)),
                provider,
                parent_hash,
                parent_state,
                recovered,
                chain_spec.chain().id(),
                spec_for_intrinsic_gas(chain_spec, recovered.timestamp),
                &mut times,
            )?;
            // Set on the deferred path, where the vote is the check; zero before
            // the fork, where the vote is the import itself.
            phases.check_us = check_at.elapsed().as_micros() as u64;
            phases.note_check(header_us, include_us, times);

            // Where this block's execution will read the parent's post-state,
            // decided here because it decides whether that execution can run
            // beside the rest of the vote road or has to follow it: the published
            // outputs laid over the chain's state at the nearest ancestor the
            // engine holds (`N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT`), or the engine's
            // tree at the parent. The parent may have landed while this block was
            // being checked, and the engine's tree is the cheaper state when it
            // has it.
            if let Some(ancestry) = &ancestry
                && exec_on_parent_output()
                && parent_in(provider, parent_hash, chain_spec.genesis(), deferred)?.is_none()
            {
                executed_parent = overlay_parent(ancestry, number);
            }

            if executed_parent.is_none() {
                // The rest of the vote road, then the execution: it has to wait
                // for the parent in the engine anyway, so there is nothing for it
                // to run beside.
                let fields_at = std::time::Instant::now();
                if parent_state.is_some() {
                    wait_for_parent_fields(parent_hash)?;
                    phases.parent_fields_wait_us = fields_at.elapsed().as_micros() as u64;
                    parent_fields_wait_us.store(phases.parent_fields_wait_us, std::sync::atomic::Ordering::Relaxed);
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
                let _ = vote_at.set(std::time::Instant::now());
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
    }

    // The parent in the engine, for a block whose execution reads it there.
    if parent_state.is_some() && executed_parent.is_none() {
        let wait_at = std::time::Instant::now();
        wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?;
        parent_engine_wait_us += wait_at.elapsed().as_micros() as u64;
    }
    drop(parent_output);

    // `N42_FOLLOWER_BUILD_PATH=1`: the block executes through the leader's
    // build path (deferred execution only: the root is filed, not checked).
    // Its parent, when it was executed here the same way and is read through
    // its published output, is read through its shards.
    let build_path = deferred && follower_parallel() && n42_engine_types::parallel_transfer::follower_build_path();
    let parent_shards = executed_parent
        .as_ref()
        .and_then(|(_, layers)| layers.first())
        .is_some_and(|(_, layer)| matches!(layer, ParentLayer::Shards(..)));

    // Execution on the parent's state, then gas, receipts root and bloom
    // against the header. One piece, because on the exec-on-parent-output path
    // it runs on this thread while the vote road runs on another.
    let execute_block = || -> Result<Executed, String> {
        // One block executes here at a time (see [`exec_gate`]). The gate is
        // taken before the state is opened and released when this closure
        // returns -- before the block's QMDB root, its hashed post-state and
        // its engine insert, which are meant to run beside the next block's
        // execution.
        // A held execution (`N42_VOTE_BEFORE_SLOT`) waits here for its
        // validator's import slot: the vote road -- beside this on its own
        // thread, or before it -- is not held. Deferred blocks only, the only
        // ones whose vote comes before their execution.
        if deferred {
            wait_for_release(block_hash)?;
        }
        // The plan made ahead, collected before the gate so that a plan
        // still running never holds another block's execution.
        let ahead_at = std::time::Instant::now();
        let plan = plan_ahead.as_ref().and_then(|plan| match plan.recv() {
            Ok(Ok(plan)) => Some(plan),
            Ok(Err(err)) => {
                tracing::debug!(target: "n42.follower_import", number, %err, "the plan made ahead failed; planning in the execution");
                None
            }
            Err(_) => None,
        });
        let ahead_wait_us = ahead_at.elapsed().as_micros() as u64;
        // The build path's keys made ahead; one that failed is made again in
        // the execution, which then declines the block the same way.
        let keys_at = std::time::Instant::now();
        let keys = keys_ahead.as_ref().and_then(|keys| keys.recv().ok()).and_then(Result::ok);
        let keys_wait_us = keys_at.elapsed().as_micros() as u64;
        let gate_at = std::time::Instant::now();
        let _gate = exec_gate();
        let gate_ms = gate_at.elapsed().as_millis() as u64;
        let state_at = std::time::Instant::now();
        // One view of the parent's post-state per caller: the block's own
        // executor takes the first, each group of a parallel execution one of
        // its own. Both must be the *same* state -- a group that opened the
        // engine's tree while the block's executor read the overlay would
        // execute half the block one block behind.
        let open_parent_state = || -> Result<reth_provider::StateProviderBox, String> {
            match &executed_parent {
                Some((anchor, layers)) => {
                    let historical = provider
                        .state_by_block_hash(*anchor)
                        .map_err(|err| format!("the state the published outputs are laid over: {err}"))?;
                    // A block held as shards under its residual, merged
                    // outputs as one overlay: the chained build's layers.
                    Ok(open_on_layers(historical, layers))
                }
                None => {
                    // No published-output overlay on this path: every read
                    // reaches the engine's own state at the parent directly,
                    // depth 0 by definition.
                    n42_engine_types::direct_build::read_depth::note_overlay_depth(0);
                    provider.state_by_block_hash(parent_hash).map_err(|err| format!("parent state: {err}"))
                }
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
        let mut sharded = None;
        let mut split = ExecSplit::default();
        if build_path {
            // The root's thread, up before the execution: its spawn and its
            // wait for the parent's fields happen beside the batches, and
            // the root starts the instant the execution hands it the shards.
            let root_slot = prespawn_early_root(parent_hash, block_hash, executed_parent.is_some())?;
            let open = || {
                open_parent_state()
                    .ok()
                    .map(|s| n42_engine_types::fast_transfer::doors::CountedDb::new(StateProviderDatabase::new(
                        reth_provider::StateProvider::into_evm_state_provider(s),
                    )))
            };
            // A described block (`N42_FOLLOWER_COPY_ASIDE=1`) executes on its
            // transactions by reference while its owned block is made aside.
            let executed = match &by_ref {
                Some((transactions, senders, withdrawals)) => {
                    n42_engine_types::parallel_transfer::execute_transfers_build_path_on(
                        evm_config,
                        n42_engine_types::parallel_transfer::BuildPathBlock {
                            header: head.header(),
                            sealed: None,
                            ommers: &[],
                            withdrawals: withdrawals.as_deref(),
                            txs: transactions.as_slice(),
                            senders: senders.as_slice(),
                        },
                        cached.as_db_mut(StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state))),
                        &open,
                        keys,
                    )
                }
                None => n42_engine_types::parallel_transfer::execute_transfers_build_path_keyed(
                    evm_config,
                    late.get()?,
                    cached.as_db_mut(StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state))),
                    &open,
                    keys,
                ),
            };
            match executed
            .map_err(|err| format!("parallel execution: {err}"))?
            {
                Ok((out, phases)) => {
                    // The root first: it reads the shards' view under the
                    // residual, both final here.
                    let returned = std::time::Instant::now();
                    let n42_engine_types::parallel_transfer::ShardedExecution { shards, residual, result, split: bp_split } = out;
                    let shards = Arc::new(shards);
                    let residual: ParentOutput = Arc::new(reth_provider::BlockExecutionOutput {
                        state: residual,
                        result: reth_execution_types::BlockExecutionResult {
                            receipts: Vec::new(),
                            requests: Default::default(),
                            gas_used: 0,
                            blob_gas_used: 0,
                        },
                    });
                    let early_root = {
                        let (shards, residual, qmdb) = (Arc::clone(&shards), Arc::clone(&residual), qmdb.clone());
                        let prague = chain_spec.is_prague_active_at_timestamp(head.timestamp);
                        root_slot.start(move || {
                            let overlaps = shards.overlaps(&residual.state);
                            let view = shards.view(&residual.state, &overlaps);
                            let ops = n42_qmdb_reth::sorted_operations_from_accounts(&view, prague);
                            qmdb.insert_block_operations(parent_hash, block_hash, number, ops).map_err(|err| format!("state root: {err}"))
                        })?
                    };
                    split = ExecSplit::of(&phases);
                    tracing::info!(
                        target: "n42.follower_import",
                        number,
                        groups = phases.groups,
                        partition_ms = phases.partition_ms,
                        groups_ms = phases.groups_ms,
                        batches = phases.batches,
                        threads = phases.threads,
                        batch_max_ms = phases.batch_spans.max_ms,
                        batch_median_ms = phases.batch_spans.median_ms,
                        batch_wait_ms = phases.batch_spans.wait_ms,
                        index_ms = phases.graft_ms,
                        merge_ms = phases.merge_ms,
                        finish_ms = phases.finish_ms,
                        receipts_ms = phases.receipts_us / 1000,
                        total_ms = phases.total_us / 1000,
                        parent_shards,
                        reads_cache = phases.transfer_timers.reads_cache(),
                        reads_provider = phases.transfer_timers.reads_provider,
                        reads_view = phases.transfer_timers.reads_view,
                        // Around the batches ([`BuildPathSplit`]): what
                        // `exec_ms` holds beside the partition, the batch
                        // wall and the index.
                        exec_setup_ms = bp_split.setup_us / 1000,
                        exec_keys_ms = bp_split.keys_us / 1000,
                        keys_ahead = bp_split.keys_ahead,
                        keys_ahead_wait_ms = keys_wait_us / 1000,
                        exec_pre_ms = bp_split.pre_us / 1000,
                        exec_post_ms = bp_split.post_us / 1000,
                        exec_overrun_ms = bp_split.executor_overrun_us / 1000,
                        exec_sink_ms = bp_split.sink_us / 1000,
                        exec_cached_ms = bp_split.cached_us / 1000,
                        exec_residual_ms = bp_split.residual_us / 1000,
                        exec_receipts_ms = bp_split.receipts_us / 1000,
                        exec_receipts_wait_ms = bp_split.receipts_wait_us / 1000,
                        exec_drop_ms = phases.drop_us / 1000,
                        // The execution's start after the road's, taken
                        // apart: before the import (the description, the
                        // owned block, the dispatch), the header and body
                        // checks (0 when they ride the vote road), the
                        // senders, the parent's layer, the set-up to the
                        // execution (ancestry, the check's road), the plan,
                        // the keys made ahead, the gate and the state.
                        exec_start_gap_us = executed_at.saturating_duration_since(road_started).as_micros() as u64,
                        gap_road_us = started.saturating_duration_since(road_started).as_micros() as u64,
                        gap_header_us = senders_at.saturating_duration_since(started).as_micros() as u64,
                        gap_senders_us = parent_at.saturating_duration_since(senders_at).as_micros() as u64,
                        gap_parent_us = parent_done.saturating_duration_since(parent_at).as_micros() as u64,
                        gap_setup_us = ahead_at.saturating_duration_since(parent_done).as_micros() as u64,
                        gap_plan_wait_us = ahead_wait_us,
                        gap_keys_wait_us = keys_wait_us,
                        gap_gate_us = state_at.saturating_duration_since(gate_at).as_micros() as u64,
                        gap_state_us = executed_at.saturating_duration_since(state_at).as_micros() as u64,
                        core_layout = n42_core_layout::label(),
                        "build-path import phases"
                    );
                    sharded = Some(StartedShards { shards, residual, result, early_root, returned });
                }
                Err(why) => {
                    static DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    let declined = DECLINED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    tracing::info!(target: "n42.follower_import", number, %why, declined, "not on the build path; executing serially");
                }
            }
        } else if follower_parallel() {
            // `N42_PHASE_TIMERS=1`: counts each batch's reads by door (plan
            // v6 6.5/6.6). `CountedDb` is a passthrough when the flag is
            // off, so this costs nothing extra on that path.
            let open = || {
                open_parent_state()
                    .ok()
                    .map(|s| n42_engine_types::fast_transfer::doors::CountedDb::new(StateProviderDatabase::new(
                        reth_provider::StateProvider::into_evm_state_provider(s),
                    )))
            };
            match n42_engine_types::parallel_transfer::execute_transfers_planned(
                evm_config,
                late.get()?,
                cached.as_db_mut(StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state))),
                &open,
                plan,
            )
            .map_err(|err| format!("parallel execution: {err}"))?
            {
                Ok((out, phases)) => {
                    // The line adds up now: `total_ms` is the executor's whole
                    // call and `other_ms` is what the named parts leave of it,
                    // the way `vote road` reports its own gap. At loop202 the
                    // four phases named 95 of a 133 ms execution and the rest
                    // had no name at all.
                    let named = phases.partition_ms * 1_000
                        + phases.batch_us
                        + phases.groups_ms * 1_000
                        + phases.gas_us
                        + phases.finish_ms * 1_000
                        + phases.merge_ms * 1_000
                        + phases.receipts_us
                        + phases.drop_us;
                    // `N42_READ_DEPTH_COUNTS=1`: see
                    // `n42_engine_types::direct_build::read_depth` (plan v6 6.4).
                    let read_depth = n42_engine_types::direct_build::read_depth::snapshot();
                    let overlay_depth = n42_engine_types::direct_build::read_depth::overlay_depth();
                    tracing::info!(
                        target: "n42.follower_import",
                        number,
                        groups = phases.groups,
                        partition_ms = phases.partition_ms,
                        env_ms = phases.env_us / 1000,
                        batch_ms = phases.batch_us / 1000,
                        groups_ms = phases.groups_ms,
                        gas_ms = phases.gas_us / 1000,
                        merge_ms = phases.merge_ms,
                        finish_ms = phases.finish_ms,
                        receipts_ms = phases.receipts_us / 1000,
                        drop_ms = phases.drop_us / 1000,
                        other_ms = phases.total_us.saturating_sub(named) / 1000,
                        total_ms = phases.total_us / 1000,
                        reads_d0 = read_depth[0],
                        reads_d1 = read_depth[1],
                        reads_d2 = read_depth[2],
                        reads_d3 = read_depth[3],
                        reads_d4_7 = read_depth[4],
                        reads_d8_15 = read_depth[5],
                        reads_d16p = read_depth[6],
                        reads_hist = read_depth[7],
                        overlay_depth,
                        // `N42_PHASE_TIMERS=1` (plan v6 6.5/6.6): where the
                        // groups' wall time (`groups_ms` above) goes inside
                        // `N42Evm::transfer`, and which door each account
                        // read took. Zero when the flag is off.
                        exec_read_ms = phases.transfer_timers.read_ns / 1_000_000,
                        exec_evm_ms = phases.transfer_timers.evm_ns / 1_000_000,
                        exec_write_ms = phases.transfer_timers.write_ns / 1_000_000,
                        exec_other_ms = phases.transfer_timers.other_ns / 1_000_000,
                        reads_cache = phases.transfer_timers.reads_cache(),
                        reads_provider = phases.transfer_timers.reads_provider,
                        reads_view = phases.transfer_timers.reads_view,
                        // Of `merge_ms`: the install of the staged graft, the
                        // state's merge and take, and the reverts' append.
                        graft_ms = phases.graft_ms,
                        take_ms = phases.take_ms,
                        reverts_ms = phases.reverts_ms,
                        // `N42_FOLLOWER_PARTITION_AHEAD=1`: whether the plan
                        // made ahead was used, what it cost off the gate, and
                        // how long the execution waited for it.
                        planned_ahead = phases.planned_ahead,
                        ahead_plan_ms = phases.ahead_plan_us / 1000,
                        ahead_env_ms = phases.ahead_env_us / 1000,
                        ahead_wait_ms = ahead_wait_us / 1000,
                        // `N42_FOLLOWER_MERGE_BEHIND=1`: the reverts' sort on
                        // its own thread, and the merge's wait for it.
                        reverts_sort_ms = phases.reverts_sort_us / 1000,
                        reverts_wait_ms = phases.reverts_wait_us / 1000,
                        "parallel import phases"
                    );
                    split = ExecSplit::of(&phases);
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
        let parallel = output.is_some() || sharded.is_some();
        let output = match output {
            Some(out) => Some(out),
            None if sharded.is_some() => None,
            None => Some(
                evm_config
                    .executor(cached.as_db_mut(StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state))))
                    .execute(late.get()?)
                    .map_err(|err| format!("execution: {err}"))?,
            ),
        };
        let exec_ended = std::time::Instant::now();
        Ok(Executed {
            state,
            cached,
            output,
            sharded,
            parallel,
            gate_ms,
            state_ms,
            exec_ms: exec_ended.duration_since(executed_at).as_millis() as u64,
            exec_started: executed_at,
            exec_ended,
            split,
        })
    };
    let Executed {
        state,
        mut cached,
        output,
        sharded,
        parallel: parallel_executed,
        gate_ms,
        state_ms,
        exec_ms,
        exec_started,
        exec_ended,
        split,
    } = match roads_at {
        None => execute_block()?,
        Some(roads_at) => {
            // References rather than the values: the vote road's closure is
            // `move`, and the execution road needs the same block and parent.
            let header = &head;
            let parent_header = &parent;
            let vote_checked = checked.take();
            let vote_at = &vote_at;
            let parent_fields_wait_us = &parent_fields_wait_us;
            let late = &late;
            let chain_id = chain_spec.chain().id();
            let spec = spec_for_intrinsic_gas(chain_spec, head.timestamp);
            two_roads(
                number,
                roads_at,
                move || {
                    let mut phases = phases;
                    // The owned block, made aside (`N42_FOLLOWER_COPY_ASIDE=1`)
                    // while the execution runs on the frames' transactions:
                    // what the checks below read.
                    let block: &RecoveredBlock<Block> = late.get()?;
                    (phases.copy_aside_us, phases.copy_wait_us) = late.times();
                    if early_check && header_on_vote_road {
                        let header_at = std::time::Instant::now();
                        pre_execution_checks(consensus, block.sealed_block())?;
                        phases.header_us += header_at.elapsed().as_micros() as u64;
                    }
                    if early_check {
                        // What the vote attests, as on the path above, on a
                        // pool of its own so the batches queued on the worker
                        // pool do not hold it.
                        let check_at = std::time::Instant::now();
                        let mut times = CheckTimes::default();
                        let (header_us, include_us) = on_check_pool(|| {
                            timed_check(
                                parent_state.is_none().then_some((consensus, header, parent_header)),
                                provider,
                                parent_hash,
                                parent_state,
                                block,
                                chain_id,
                                spec,
                                &mut times,
                            )
                        })?;
                        phases.check_us = check_at.elapsed().as_micros() as u64;
                        phases.note_check(header_us, include_us, times);
                    }
                    let fields_at = std::time::Instant::now();
                    wait_for_parent_fields(parent_hash)?;
                    phases.parent_fields_wait_us = fields_at.elapsed().as_micros() as u64;
                    parent_fields_wait_us.store(phases.parent_fields_wait_us, std::sync::atomic::Ordering::Relaxed);
                    validate_against_parent(consensus, header, parent_header)?;
                    phases.fields_us = fields_at.elapsed().as_micros() as u64;
                    // The vote, with this block's execution still running.
                    if let Some(checked) = vote_checked {
                        let _ = checked.send(());
                    }
                    let _ = vote_at.set(std::time::Instant::now());
                    log_vote_road(road, number, tx_count, phases);
                    Ok(())
                },
                execute_block,
            )?
        }
    };
    // The owned block from here on: the post-execution checks and the
    // engine's hand-off read it (made aside by now, under the execution).
    let recovered = Arc::clone(late.get()?);
    drop(late);
    let prague = chain_spec.is_prague_active_at_timestamp(recovered.timestamp);
    let on_parent_output = executed_parent.is_some();
    // The build path runs the post-execution checks beside its merge, and
    // (with the pass on) builds the hashed post-state from the shards' view.
    let mut pre_checked: Option<(u64, std::time::Instant)> = None;
    // The build path: when its execution returned, which its root's start
    // is timed against (`root_gap_ms`).
    let mut root_returned: Option<std::time::Instant> = None;
    let mut view_hashed: Option<reth_trie::HashedPostState> = None;
    let (execution_output, early_root) = match (output, sharded) {
        (Some(output), _) => {
            let execution_output = Arc::new(output);
            // `N42_FOLLOWER_FIELDS_EARLY=1`: this block's QMDB root -- the
            // half of its fields its child's vote waits for -- starts here,
            // on a thread of its own with its hashing on a pool of its own
            // ([`on_root_pool`]), beside the post-execution checks, the
            // published output, the carry and the hashed post-state below
            // instead of after them. The same operations on the same bundle,
            // filed under the same hash as the root job below would file them.
            let early_root = if deferred && fields_early() {
                let output = Arc::clone(&execution_output);
                let qmdb = qmdb.clone();
                Some(spawn_early_root(parent_hash, block_hash, on_parent_output, move || {
                    let ops = n42_qmdb_reth::sorted_operations_from_execution(&output.state, prague);
                    qmdb.insert_block_operations(parent_hash, block_hash, number, ops).map_err(|err| format!("state root: {err}"))
                })?)
            } else {
                None
            };
            (execution_output, early_root)
        }
        (None, Some(sharded)) => {
            // `N42_FOLLOWER_BUILD_PATH=1`: the block's output is the batches'
            // shards under the executor's residual. The root reads their view
            // on the root pool the instant the batches are done (the leader's
            // finish after its seal); the one bundle the engine, the child's
            // check and the published output need is merged on a thread of
            // its own beside it, while this thread runs the post-execution
            // checks; the child's execution reads the shards themselves.
            let StartedShards { shards, residual, result, early_root, returned } = sharded;
            root_returned = Some(returned);
            let merger = {
                let (shards, residual) = (Arc::clone(&shards), Arc::clone(&residual));
                std::thread::Builder::new()
                    .name("n42-follower-merge".into())
                    .spawn(move || {
                        n42_core_layout::background_thread();
                        let at = std::time::Instant::now();
                        let merged = shards.merged(&residual.state);
                        (merged, at.elapsed().as_millis() as u64)
                    })
                    .map_err(|err| format!("a thread for the shards' merge: {err}"))?
            };
            let checks_at = std::time::Instant::now();
            stage.at(4);
            consensus
                .validate_block_post_execution(&recovered, &result, None, None)
                .map_err(|err| format!("post-execution: {err}"))?;
            pre_checked = Some((checks_at.elapsed().as_millis() as u64, std::time::Instant::now()));
            // The child's check and execution read this block from here on,
            // through its shards: kept once its receipts and gas passed, as
            // the published output is, but before the merge below, which
            // only the engine's hand-off and the published output wait for.
            keep_follower_shards(block_hash, recovered.clone_sealed_header(), Arc::clone(&shards), Arc::clone(&residual));
            if hashed_state_enabled() {
                let overlaps = shards.overlaps(&residual.state);
                let view = shards.view(&residual.state, &overlaps);
                // A destroyed account's storage is zeroed from the database:
                // the provider's own pass, on the merged bundle, below.
                if !n42_engine_types::output_shards::any_destroyed(&view) {
                    view_hashed = Some(n42_engine_types::output_shards::hashed_post_state_of(&view));
                }
            }
            let wait_at = std::time::Instant::now();
            let (merged, merge_ms) = merger.join().map_err(|_| "the shards' merge thread panicked".to_string())?;
            tracing::debug!(
                target: "n42.follower_import",
                number,
                merge_ms,
                merge_wait_ms = wait_at.elapsed().as_millis() as u64,
                "build path: the shards merged into the block's bundle"
            );
            (Arc::new(reth_provider::BlockExecutionOutput { state: merged, result }), Some(early_root))
        }
        (None, None) => return Err("the execution left no output".to_string()),
    };
    let (checks_ms, receipts_filed) = match pre_checked {
        Some(checked) => checked,
        None => {
            let checks_at = std::time::Instant::now();
            stage.at(4);
            consensus
                .validate_block_post_execution(&recovered, &execution_output.result, None, None)
                .map_err(|err| format!("post-execution: {err}"))?;
            // Under deferred execution the check above filed the receipt half
            // of this block's fields; the root files the other.
            (checks_at.elapsed().as_millis() as u64, std::time::Instant::now())
        }
    };
    // The child's check can start now: its ~6,000 senders are in this
    // bundle, and it has no use for the QMDB root below -- only the fields
    // comparison has, and that one waits for it on its own
    // ([`wait_for_parent_fields`]). Published after the post-execution
    // checks, so nothing is published for a block whose receipts or gas were
    // refused, and before the root, which is the ~27 ms the child's check now
    // runs beside (plan v4 step 1). On the build path the child reads the
    // shards kept above instead, before this merged bundle exists; this copy
    // is for the ordinary path and the leader's build on this block
    // ([`published_ancestry`]).
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

    // Executed on the published outputs: the forest computes this block's tree
    // from the parent's record, which the parent's own root job files, so this
    // block's *root* needs the parent's -- and nothing before this point did.
    // The execution above ran on the parent's bundle while that root was still
    // running, which is the whole point of the path: a parent whose root took
    // 150-319 ms instead of the 24-30 ms baseline (the QMDB log checkpoint,
    // plan v4) must not hold the next block's execution, only the next block's
    // root.
    //
    // Timed apart from [`parent_engine_wait_us`] because the two say different
    // things: this is the parent's root running long, that is the parent's
    // engine insert not having happened. A leg that cannot tell them apart
    // cannot say which one a slow import waited on.
    let root_wait_at = std::time::Instant::now();
    if executed_parent.is_some() && early_root.is_none() {
        wait_for_parent_fields(parent_hash)?;
    }
    let mut root_wait_ms = root_wait_at.elapsed().as_millis() as u64;

    // The QMDB root against the header's, which also files the block's tree
    // under its hash for the engine and the next block.
    let root_at = std::time::Instant::now();
    stage.at(6);
    // The QMDB root and the hashed post-state read the same bundle and neither
    // needs the other's result, but they run one after the other: 63 and 26 ms
    // of a 438 ms import (round 43, loop99). `N42_ROOT_HASHED_PARALLEL=1` puts
    // them on the worker pool together.
    let bundle = &execution_output.state;
    // When the root job filed this block's state root (deferred execution
    // only): with the receipts filed above, when its fields became complete.
    let root_filed: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let root_filed = &root_filed;
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
            let _ = root_filed.set(std::time::Instant::now());
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
    let (root_ms, hashed_ms, hashed_state) = if let Some(early_root) = early_root {
        // The root has been running since the execution returned; the hashed
        // post-state here, then the root's answer.
        stage.at(7);
        let hashed_at = std::time::Instant::now();
        let hashed_state = match view_hashed.take() {
            Some(hashed) => hashed,
            None => hashed_job()?,
        };
        let hashed_ms = hashed_at.elapsed().as_millis() as u64;
        let (wait_ms, began, ended) =
            early_root.join().unwrap_or_else(|_| Err("the early QMDB root thread panicked".to_string()))?;
        root_wait_ms = wait_ms;
        if let Some(returned) = root_returned {
            // Where the root spent its time (the forest's lock, the apply,
            // the hashing, the filing, faults, the entry file's seals).
            let split = qmdb.take_root_split(&block_hash).unwrap_or_default();
            tracing::info!(
                target: "n42.follower_import",
                number,
                root_gap_ms = ms_between(returned, began),
                root_gap_us = began.saturating_duration_since(returned).as_micros() as u64,
                root_wait_ms = wait_ms,
                root_ms = ms_between(began, ended),
                root_lock_wait_ms = split.lock_wait_ms,
                root_lock_held_by = split.held_by,
                root_move_ms = split.move_ms,
                root_apply_ms = split.apply_ms,
                root_hash_ms = split.hash_ms,
                root_publish_ms = split.publish_ms,
                root_faults = split.faults,
                root_majflt = split.majflt,
                root_twig_pool_misses = split.twig_pool_misses,
                root_twig_pool_refills = split.twig_pool_refills,
                root_append_faults = split.append_faults,
                root_faults_entries = split.faults_entries,
                root_faults_offsets = split.faults_offsets,
                root_faults_index = split.faults_index,
                root_faults_bits = split.faults_bits,
                root_faults_twigs = split.faults_twigs,
                root_faults_undo = split.faults_undo,
                root_faults_tmp = split.faults_tmp,
                root_append_behind = split.append_behind,
                populate_lag_mb = split.populate_lag_mb,
                root_seals = split.seals,
                root_seal_ms = split.seal_ms,
                "build path: the root's start after the execution"
            );
        }
        let _ = root_filed.set(ended);
        (ms_between(began, ended), hashed_ms, hashed_state)
    } else if !root_hashed_parallel() {
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
    let root_end = root_filed.get().copied().unwrap_or_else(std::time::Instant::now);

    if carry_async && !parallel_executed {
        let state = Arc::clone(&execution_output);
        let carry = Arc::clone(carry);
        rayon::spawn(move || {
            let mut cached = cached;
            fill_carry(&mut cached, &state.state, block_hash, &carry);
        });
    }

    // The engine takes an executed block on top of its parent, so the
    // hand-offs must stay in chain order: a block executed on the published
    // outputs, rather than on the engine's tree, waits here for the parent to
    // land. This block's execution and root have run since the parent's, so in
    // the ordinary case the parent landed long ago and this states the
    // ordering rather than paying for it -- but it is timed into
    // `parent_engine_wait_ms` all the same, because under a backlog it is
    // where what the execution no longer waits for reappears.
    if executed_parent.is_some() {
        let wait_at = std::time::Instant::now();
        wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?;
        parent_engine_wait_us += wait_at.elapsed().as_micros() as u64;
    }

    // Before the deferred-execution fork the vote is this import's answer,
    // so the road ends here rather than at a check.
    if !deferred {
        log_vote_road(road, number, tx_count, phases);
    }

    Ok((
        Box::new(BuiltPayloadExecutedBlock {
            recovered_block: recovered,
            execution_output,
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(TrieUpdates::default()),
        }),
        [
            header_ms,
            senders_ms,
            exec_ms,
            checks_ms,
            root_ms,
            hashed_ms,
            cache_hits,
            state_ms,
            carry_ms,
            parent_engine_wait_us / 1000,
            gate_ms,
            root_wait_ms,
            // The chain, ms after the road's start: the vote released (0
            // before the fork, where the import is the answer), the execution,
            // the root filed, the fields complete, and how long this block's
            // vote waited for its parent's fields.
            vote_at.get().map_or(0, |at| ms_between(road_started, *at)),
            ms_between(road_started, exec_started),
            ms_between(road_started, exec_ended),
            ms_between(road_started, root_end),
            if deferred { ms_between(road_started, root_end.max(receipts_filed)) } else { 0 },
            parent_fields_wait_us.load(std::sync::atomic::Ordering::Relaxed) / 1000,
            // The execution taken apart ([`ExecSplit`]).
            split.part_ms,
            split.batches_ms,
            split.graft_ms,
            split.batches,
            split.threads,
            split.batch_max_ms,
            split.batch_median_ms,
            // What the check and the execution waited for the parent's
            // output, and what they read it through ([`parent_read_name`]).
            parent_output_wait_ms,
            parent_read,
        ],
    ))
}

/// The early root's thread: the wait before it, its start and its end.
type EarlyRoot = std::thread::JoinHandle<Result<(u64, std::time::Instant, std::time::Instant), String>>;

/// This block's QMDB root on a thread of its own, its hashing on the root
/// pool ([`on_root_pool`]): after the parent's fields when the block was
/// executed on the parent's published output (the parent's tree is filed by
/// the parent's own root, which this one builds on). `root_of` computes the
/// operations and files them. The thread answers the wait it had to do
/// first, when the root began, and when it ended.
fn spawn_early_root<F>(
    parent_hash: B256,
    block_hash: B256,
    on_parent_output: bool,
    root_of: F,
) -> Result<EarlyRoot, String>
where
    F: FnOnce() -> Result<B256, String> + Send + 'static,
{
    std::thread::Builder::new()
        .name("qmdb-root-early".into())
        .spawn(move || -> Result<(u64, std::time::Instant, std::time::Instant), String> {
            let wait_at = std::time::Instant::now();
            if on_parent_output {
                wait_for_parent_fields(parent_hash)?;
            }
            let root_at = std::time::Instant::now();
            let root = on_root_pool(root_of)?;
            n42_engine_types::executed_fields::remember_state_root(block_hash, root);
            Ok((ms_between(wait_at, root_at), root_at, std::time::Instant::now()))
        })
        .map_err(|err| format!("a thread for the early QMDB root: {err}"))
}

/// An early root's thread started ahead of the execution
/// ([`prespawn_early_root`]), waiting for the root's work.
struct RootSlot {
    work: std::sync::mpsc::SyncSender<RootWork>,
    handle: EarlyRoot,
}

/// What a [`RootSlot`]'s thread runs: the operations made and filed.
type RootWork = Box<dyn FnOnce() -> Result<B256, String> + Send + 'static>;

impl RootSlot {
    /// Hands the thread its work; the handle answers as
    /// [`spawn_early_root`]'s does, `began` the instant the work arrived.
    fn start<F>(self, root_of: F) -> Result<EarlyRoot, String>
    where
        F: FnOnce() -> Result<B256, String> + Send + 'static,
    {
        match self.work.send(Box::new(root_of)) {
            Ok(()) => Ok(self.handle),
            // The thread ended before the work came: its own error (the
            // parent's fields never filed) is the answer.
            Err(_) => match self.handle.join() {
                Ok(Err(err)) => Err(err),
                Ok(Ok(_)) => Err("the early QMDB root thread ended without its work".to_string()),
                Err(_) => Err("the early QMDB root thread panicked".to_string()),
            },
        }
    }
}

/// [`spawn_early_root`] in two steps: the thread now, beside the execution,
/// doing the wait for the parent's fields there; the work when the execution
/// returns ([`RootSlot::start`]). Before, the root's start after the
/// execution's end (`root_gap_ms`) held the thread's spawn and that wait. A
/// slot dropped without work (the block left the build path, or failed)
/// ends its thread.
fn prespawn_early_root(parent_hash: B256, block_hash: B256, on_parent_output: bool) -> Result<RootSlot, String> {
    let (work, arrives) = std::sync::mpsc::sync_channel::<RootWork>(1);
    let handle = std::thread::Builder::new()
        .name("qmdb-root-early".into())
        .spawn(move || -> Result<(u64, std::time::Instant, std::time::Instant), String> {
            let wait_at = std::time::Instant::now();
            if on_parent_output {
                wait_for_parent_fields(parent_hash)?;
            }
            let waited = wait_at.elapsed().as_millis() as u64;
            let root_of = arrives.recv().map_err(|_| "no root work: the execution left the build path".to_string())?;
            let root_at = std::time::Instant::now();
            let root = on_root_pool(root_of)?;
            n42_engine_types::executed_fields::remember_state_root(block_hash, root);
            Ok((waited, root_at, std::time::Instant::now()))
        })
        .map_err(|err| format!("a thread for the early QMDB root: {err}"))?;
    Ok(RootSlot { work, handle })
}

/// How many timings [`import_foreign_block`] returns (see its last lines).
pub const IMPORT_TIMES: usize = 27;

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

/// The gate that keeps one block executing here at a time (see [`exec_gate`]).
static EXEC_GATE: Mutex<()> = Mutex::new(());

/// Takes the execution gate; `N42_FOLLOWER_EXEC_GATE=0` runs without one.
///
/// **One, not two.** The imports of several blocks are in flight at once by
/// design -- a block's road and check run while its parent executes, and its
/// parent's root, hashed post-state and engine insert run while it executes --
/// but their *executions* must not overlap, because they share one worker pool
/// and collide on it. Bucketed by how many imports overlapped, a four-node leg
/// read execution 79-83 ms, groups 52-55 and import total 140-156 with none
/// overlapping, against execution 116-149, groups 74-108 and total 340-403
/// with two or more (plan v4, loop199-204): the execution inflates 1.5-2.5x
/// and the import passes the cycle, which is the collapse. Allowing two would
/// be allowing exactly that.
///
/// The ordering is the publication's, not the gate's: a block cannot reach its
/// execution before its parent's output is published, and that happens when
/// the parent's execution ends. So on the ordinary path the gate is taken
/// uncontended and `gate_ms` is 0; it is the paths that do not read a
/// published output -- a block whose parent came in by the engine's own way,
/// an import retried after a refusal -- that it holds back. A leg reads
/// `gate_ms` on the `direct import` line and sees whether it ever waited.
fn exec_gate() -> Option<std::sync::MutexGuard<'static, ()>> {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let on = *ON.get_or_init(|| std::env::var("N42_FOLLOWER_EXEC_GATE").map_or(true, |v| v != "0"));
    // A thread that panicked under the gate poisoned nothing but `()`.
    on.then(|| EXEC_GATE.lock().unwrap_or_else(|p| p.into_inner()))
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

/// `N42_FOLLOWER_EXEC_EARLY=1` (section 5 of `docs/BREAKTHROUGH_DESIGN.md`,
/// step 5a): under deferred execution the block's execution starts the moment
/// the parent's post-state is known -- before the includability check, which
/// then runs beside it on the vote road ([`two_roads`]) instead of in front of
/// it. The check still decides the vote and the import exactly as before: its
/// error wins over the execution's result, which is then dropped. The check's
/// parallel scan runs on a pool of its own ([`on_check_pool`]), so the
/// execution's batches, queued on the worker pool, do not hold the vote.
fn exec_early() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_EXEC_EARLY").is_ok_and(|v| v == "1"))
}

/// A small pool of its own, sized by `var` (default `default`), or `None` if
/// it cannot be built -- the caller then runs on the worker pool as before.
fn side_pool(var: &str, name: &'static str, default: usize) -> Option<rayon::ThreadPool> {
    let threads = std::env::var(var).ok().and_then(|v| v.parse::<usize>().ok()).filter(|n| *n > 0).unwrap_or(default);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(move |i| format!("{name}-{i}"))
        // Both side pools (the vote check, the root) are on a block's
        // chain: the layout's critical set under `N42_CORE_LAYOUT=isolate`.
        .start_handler(|_| n42_core_layout::enter(n42_core_layout::Set::Critical))
        .build()
        .inspect_err(|err| tracing::warn!(target: "n42.follower_import", %err, name, "no side pool; on the worker pool"))
        .ok()
}


/// Runs the early includability check's scan on its own pool
/// (`N42_FOLLOWER_CHECK_THREADS`, default 4), away from the execution's
/// batches. The check takes no lock another check could hold.
fn on_check_pool<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
    match POOL.get_or_init(|| side_pool("N42_FOLLOWER_CHECK_THREADS", "vote-check", 4)) {
        Some(pool) => pool.install(f),
        None => f(),
    }
}

/// `N42_FOLLOWER_FIELDS_EARLY=1` (step 5a): under deferred execution this
/// block's QMDB root -- the last of its execution fields, the one its child's
/// vote waits for ([`wait_for_parent_fields`]) -- starts on a thread of its
/// own the instant the execution returns, beside the post-execution checks,
/// the published output and the carry instead of after them, and its hashing
/// runs on a pool of its own ([`on_root_pool`]). loop284 read the root at
/// 36-38 ms alone and 100-106 on every other block, where it shared the worker
/// pool with the next block's execution batches, and the next block's vote
/// waited those extra ~65 ms. The root is the same computation on the same
/// bundle, filed under the same hash; only where and when it runs moves.
fn fields_early() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_FIELDS_EARLY").is_ok_and(|v| v == "1"))
}

/// Runs the early QMDB root's hashing on its own pool
/// (`N42_FOLLOWER_ROOT_THREADS`, default 8). One root at a time: the forest's
/// mutex is taken inside, on one of this pool's workers, and a worker that
/// holds it and waits for its own hashing may steal whatever else is queued
/// here -- a second root would then wait for the lock its own thread holds
/// (loop164 O17). Serialised, nothing else is ever queued on this pool.
///
/// `N42_FOLLOWER_ROOT_ON_BUILD_POOL=1`: on the build pool instead, whose
/// threads the build path's batches (`N42_FOLLOWER_BUILD_PATH=1`) have just
/// left -- the root starts when they are done -- so the node keeps no
/// separate eight threads for it. The next block's batches may start while
/// the root runs; a worker then finishes the root's queued pieces (its own
/// and stolen ones) before it takes a new batch from the pool's queue.
fn on_root_pool<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
    static ONE: Mutex<()> = Mutex::new(());
    if root_on_build_pool() {
        let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
        return n42_engine_types::parallel_transfer::build_pool().install(f);
    }
    match POOL.get_or_init(|| side_pool("N42_FOLLOWER_ROOT_THREADS", "qmdb-root", 8)) {
        Some(pool) => {
            let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
            pool.install(f)
        }
        None => f(),
    }
}
/// `N42_FOLLOWER_ROOT_ON_BUILD_POOL=1` ([`on_root_pool`]), read once.
fn root_on_build_pool() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_ROOT_ON_BUILD_POOL").is_ok_and(|v| v == "1"))
}

/// Milliseconds from `from` to `to`, zero if `to` is earlier.
fn ms_between(from: std::time::Instant, to: std::time::Instant) -> u64 {
    to.saturating_duration_since(from).as_millis() as u64
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
mod side_pool_tests {
    use super::*;

    /// The early root's hashing runs on the root pool's threads, and two
    /// roots at once -- each taking a lock inside, as the forest's mutex is
    /// taken -- finish: the pool never hands one root's closure to a worker
    /// that holds the other's lock.
    #[test]
    fn roots_run_on_their_pool_one_at_a_time() {
        static FOREST: Mutex<u64> = Mutex::new(0);
        let root = || {
            on_root_pool(|| {
                use rayon::prelude::*;
                let mut forest = FOREST.lock().unwrap_or_else(|p| p.into_inner());
                let names: Vec<bool> = (0..64u64)
                    .into_par_iter()
                    .map(|_| std::thread::current().name().is_some_and(|name| name.starts_with("qmdb-root-")))
                    .collect();
                *forest += 1;
                names.into_iter().all(|on_pool| on_pool)
            })
        };
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(root);
            let b = scope.spawn(root);
            (a.join().unwrap_or(false), b.join().unwrap_or(false))
        });
        assert!(a && b, "every piece of the roots' hashing ran on the root pool");
        assert_eq!(*FOREST.lock().unwrap_or_else(|p| p.into_inner()), 2);
    }

    /// The early check's scan runs on the check pool's threads.
    #[test]
    fn checks_run_on_their_pool() {
        let on_pool = on_check_pool(|| {
            use rayon::prelude::*;
            (0..64u64)
                .into_par_iter()
                .all(|_| std::thread::current().name().is_some_and(|name| name.starts_with("vote-check-")))
        });
        assert!(on_pool);
    }
}

#[cfg(test)]
mod parent_output_tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_revm::db::BundleState;
    use reth_revm::revm::state::AccountInfo;

    /// [`PARENT_OUTPUTS`] is one process-wide queue of [`PARENT_OUTPUTS_KEPT`]
    /// entries, and `cargo test` runs these in threads of one process: two
    /// publishing tests at once would evict each other's parent. Every test
    /// that publishes takes this first.
    pub(super) static PUBLISHING: Mutex<()> = Mutex::new(());

    /// Holds [`PUBLISHING`] for the length of a test.
    pub(super) fn publishing() -> std::sync::MutexGuard<'static, ()> {
        PUBLISHING.lock().unwrap_or_else(|p| p.into_inner())
    }

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
        let _one_at_a_time = publishing();
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
        let (_, output) = wait_for_output_within(parent_hash, || false, PARENT_WAIT).expect("published when the execution ended");
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
        let _one_at_a_time = publishing();
        let parent_hash = B256::with_last_byte(0x61);
        let header = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header::default());
        let output = Arc::new(reth_provider::BlockExecutionOutput {
            result: Default::default(),
            state: BundleState::default(),
        });
        publish_parent_output(parent_hash, header, output);
        // The parent's execution has ended -- its output is published -- but
        // its root has not run, so its fields are not filed.
        assert!(wait_for_output_within(parent_hash, || false, PARENT_WAIT).is_some());
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

    /// The congested case the wait was worst in: neither the parent nor the
    /// grandparent is in the engine, both published their output here, and the
    /// block reads its senders through both, over the state at the
    /// great-grandparent -- which is the one the walk anchors on.
    #[test]
    fn the_ancestry_stacks_the_published_outputs_down_to_the_ancestor_in_the_engine() {
        let _one_at_a_time = publishing();
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};

        let moved_by_both = Address::with_last_byte(0x81);
        let moved_by_the_grandparent = Address::with_last_byte(0x82);
        let untouched = Address::with_last_byte(0x83);

        // The chain's state at the great-grandparent, the only block of the
        // three the engine holds.
        let provider = MockEthProvider::default();
        provider.add_account(moved_by_both, ExtendedAccount::new(1, U256::from(100)));
        provider.add_account(moved_by_the_grandparent, ExtendedAccount::new(5, U256::from(50)));
        provider.add_account(untouched, ExtendedAccount::new(9, U256::from(9)));
        let anchor = alloy_consensus::Header { number: 10, ..Default::default() };
        let anchor = reth_primitives_traits::SealedHeader::seal_slow(anchor);
        provider.add_header(anchor.hash(), anchor.header().clone());

        let account = |nonce: u64, balance: u64| AccountInfo { nonce, balance: U256::from(balance), ..Default::default() };
        let publish = |number: u64, parent: B256, changes: Vec<(Address, AccountInfo)>| {
            let header = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header {
                number,
                parent_hash: parent,
                extra_data: number.to_be_bytes().to_vec().into(),
                ..Default::default()
            });
            let bundle = BundleState::new(
                changes.into_iter().map(|(address, info)| (address, None, Some(info), Default::default())),
                Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
                Vec::new(),
            );
            let output = Arc::new(reth_provider::BlockExecutionOutput { result: Default::default(), state: bundle });
            publish_parent_output(header.hash(), header.clone(), Arc::clone(&output));
            (header, output)
        };
        let (grandparent, _) = publish(
            11,
            anchor.hash(),
            vec![(moved_by_both, account(2, 90)), (moved_by_the_grandparent, account(6, 40))],
        );
        let (parent, parent_output) = publish(12, grandparent.hash(), vec![(moved_by_both, account(3, 80))]);

        let genesis = alloy_genesis::Genesis::default();
        let ancestry = ancestry_of(&provider, &parent, &ParentLayer::Merged(parent_output), &genesis, true, 13)
            .expect("the parent and the grandparent are published and the great-grandparent is in");
        assert_eq!(ancestry.outputs.len(), 2, "both unimported blocks are in the stack");
        assert_eq!(ancestry.anchor, anchor.hash(), "the walk stops at the block the engine holds");

        let stack = ancestry.layers();
        let bundles = ParentBundles { stack: &stack, anchor: ancestry.anchor };
        assert_eq!(
            bundles.account(&moved_by_both).map(|a| (a.nonce, a.balance)),
            Some((3, U256::from(80))),
            "the newest bundle that touched the sender wins"
        );
        assert_eq!(
            bundles.account(&moved_by_the_grandparent).map(|a| (a.nonce, a.balance)),
            Some((6, U256::from(40))),
            "a sender only the older block touched is read from it"
        );
        assert!(bundles.account(&untouched).is_none(), "a sender neither touched is left to the ancestor's state");
        // And the same outputs, in the same order, are what the execution's
        // overlay is built from.
        let executed = &ancestry.outputs;
        assert_eq!(executed.len(), 2);
        assert_eq!(executed[0].0.hash(), parent.hash(), "newest first");
        assert_eq!(executed[1].0.hash(), grandparent.hash());
    }

    /// Deeper than the published outputs go, the walk refuses and the block
    /// waits for its parent in the engine: a follower that far behind does not
    /// catch up by stacking bundles it does not have.
    #[test]
    fn an_ancestry_deeper_than_the_outputs_kept_is_refused() {
        let _one_at_a_time = publishing();
        use reth_provider::test_utils::MockEthProvider;

        // A chain of headers none of which the provider knows, each published.
        let provider = MockEthProvider::default();
        let mut parent_hash = B256::with_last_byte(0x91);
        let mut last = None;
        for number in 1..=(PARENT_OUTPUTS_KEPT as u64 + 1) {
            let header = reth_primitives_traits::SealedHeader::seal_slow(alloy_consensus::Header {
                number,
                parent_hash,
                extra_data: b"deep".to_vec().into(),
                ..Default::default()
            });
            let output = Arc::new(reth_provider::BlockExecutionOutput {
                result: Default::default(),
                state: BundleState::default(),
            });
            publish_parent_output(header.hash(), header.clone(), Arc::clone(&output));
            parent_hash = header.hash();
            last = Some((header, output));
        }
        let (parent, output) = last.expect("a chain was built");
        let genesis = alloy_genesis::Genesis::default();
        assert!(
            ancestry_of(&provider, &parent, &ParentLayer::Merged(output), &genesis, true, 99).is_none(),
            "no ancestor in the engine within the outputs kept"
        );
    }

    /// A parent already in the engine that nothing published (one this node
    /// built, or one the engine imported by its own path) ends the wait at
    /// once instead of after [`PARENT_WAIT`] (loop156 C1).
    #[test]
    fn a_parent_in_the_engine_without_an_output_ends_the_wait_at_once() {
        let started = std::time::Instant::now();
        assert!(wait_for_parent_layer(B256::with_last_byte(0xee), || true).is_none());
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
        parent_output: Option<ParentBundles<'_>>,
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
        parent_output: Option<ParentBundles<'_>>,
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
                let state_at = parent_output.map_or(parent_hash, |bundles| bundles.anchor);
                let state = provider.state_by_block_hash(state_at).map_err(|err| format!("parent state: {err}"))?;
                for (sender, indexes) in chunk {
                    let after_parent = parent_output.and_then(|bundles| bundles.account(sender));
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

    /// `state` as a published (merged) output.
    fn merged(state: BundleState) -> ParentLayer {
        ParentLayer::Merged(Arc::new(reth_provider::BlockExecutionOutput { result: Default::default(), state }))
    }

    /// `after` as the build path leaves it: the first two thirds in two
    /// batches' shards, the last third in the executor's residual, and one
    /// account of the residual also in the first batch with a stale value the
    /// residual overrides -- the overlap the merge resolves. With the same
    /// post-state merged into one bundle, as the published output carries it.
    fn build_path_output(after: &[(Address, Account)], index: bool) -> (ParentLayer, ParentLayer) {
        let third = after.len() / 3;
        let (batched, residual) = after.split_at(2 * third);
        let (first, second) = batched.split_at(third);
        let mut first = first.to_vec();
        if let Some((address, account)) = residual.first() {
            first.push((*address, Account { nonce: account.nonce.saturating_sub(2), balance: U256::ZERO, bytecode_hash: None }));
        }
        let shards =
            n42_engine_types::output_shards::OutputShards::with_index(Address::with_last_byte(0xbe), after.len(), 4, index);
        shards.add(bundle(&first));
        shards.add(bundle(second));
        let shards = Arc::new(shards.freeze());
        let residual = bundle(residual);
        let published = merged(shards.merged(&residual));
        let residual = Arc::new(reth_provider::BlockExecutionOutput { result: Default::default(), state: residual });
        (ParentLayer::Shards(shards, residual), published)
    }

    /// The child's check through its parent's shards under the residual gives
    /// the verdict -- and the words -- it gives through the merged output, on a
    /// block whose senders' nonces the parent advanced (the state below the
    /// parent refuses it), clean and with a flaw on either side of the split;
    /// and the execution's view of the parent through the same layers
    /// ([`open_on_layers`]) reads every sender as the check does.
    #[test]
    fn a_check_through_the_shards_gives_the_merged_outputs_verdict() {
        use reth_provider::AccountReader as _;
        let senders: Vec<Address> = (0..24).map(|s| addr(500 + s)).collect();
        let mut txs = Vec::new();
        let mut recovered = Vec::new();
        for k in 0..3u64 {
            for sender in &senders {
                txs.push(transfer(5 + k, addr(9_000), 1_000, 21_000));
                recovered.push(*sender);
            }
        }
        let block = seal(txs, recovered, addr(1));
        let rich = U256::from(10u128.pow(21));
        let below: Vec<(Address, Account)> =
            senders.iter().map(|s| (*s, Account { nonce: 2, balance: rich, bytecode_hash: None })).collect();
        let state = provider(&below);
        let anchor = B256::random();
        let header = reth_primitives_traits::SealedHeader::seal_slow(Header { number: 7, ..Default::default() });
        let verdict = |layer: &ParentLayer| {
            check_includable(&state, anchor, Some(ParentBundles { stack: &[layer], anchor }), &block, CHAIN_ID, SpecId::OSAKA)
        };
        assert!(
            check_includable(&state, anchor, None, &block, CHAIN_ID, SpecId::OSAKA).is_err(),
            "below the parent the nonces are 2: the block needs the parent's"
        );
        // No flaw; a stale nonce in the shards; a short balance in the residual.
        let flaws: [Option<(usize, Account)>; 3] = [
            None,
            Some((3, Account { nonce: 4, balance: rich, bytecode_hash: None })),
            Some((20, Account { nonce: 5, balance: U256::from(1), bytecode_hash: None })),
        ];
        for index in [false, true] {
            for flaw in &flaws {
                let mut after: Vec<(Address, Account)> =
                    senders.iter().map(|s| (*s, Account { nonce: 5, balance: rich, bytecode_hash: None })).collect();
                if let Some((at, account)) = flaw {
                    after[*at].1 = *account;
                }
                let (through_shards, published) = build_path_output(&after, index);
                let (on_shards, on_merged) = (verdict(&through_shards), verdict(&published));
                assert_eq!(on_shards, on_merged, "index {index}, flaw {flaw:?}");
                assert_eq!(on_shards.is_ok(), flaw.is_none(), "index {index}, flaw {flaw:?}: {on_shards:?}");

                let historical: reth_provider::StateProviderBox = Box::new(state.clone());
                let view = open_on_layers(historical, &[(header.clone(), through_shards.clone())]);
                for sender in &senders {
                    let read = view.basic_account(sender).expect("the layers answer");
                    assert_eq!(read, published.account(sender), "index {index}: {sender}");
                    assert_eq!(read, through_shards.account(sender), "index {index}: {sender}");
                }
            }
        }
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
        let parent = merged(bundle(&accounts));
        let grandparent = B256::random();
        let parent_hash = B256::random();
        let ms = |at: std::time::Instant| at.elapsed().as_micros() as f64 / 1000.0;
        println!(
            "block: {} transactions, {} senders, {} bytes a transaction",
            block.body().transactions.len(),
            accounts.len(),
            std::mem::size_of::<TransactionSigned>(),
        );
        let stack = [&parent];
        for (name, output) in [("parent-output", Some(ParentBundles { stack: &stack, anchor: grandparent })), ("provider", None)] {
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

    /// The pass the follower's import runs first with
    /// `N42_SENDERS_FROM_QUEUE` on: every transaction this node's ingest
    /// queued answers with the sender it recovered, and one that never came
    /// this way answers `None` -- the miss that sends the import back to the
    /// caches for that position and nothing else. The environment is not
    /// read here: the queue is handed in, as the import hands in the one it
    /// found.
    #[test]
    fn the_index_answers_the_senders_it_holds() {
        use alloy_eips::Encodable2718;
        let (block, _) = bench_fixture(4, 3, 16, 1);
        let txs: Vec<TransactionSigned> = block.body().transactions.clone();
        let senders: Vec<Address> = block.senders().to_vec();
        // The index's bound is per shard (`cap / HASH_INDEX_SHARDS`, at least
        // one): at 64 the shards hold one entry each and the fixture's random
        // hashes evict one another as they collide, and the test passed or
        // failed by the draw. Bounded well above a shard a hash.
        let queue = n42_tx_queue::TxQueue::<n42_engine_types::N42PooledTransaction>::with_run_length(4)
            .with_hash_index(1 << 16);
        // All but the last, so the block holds one transaction this node
        // never saw -- the ingest a few milliseconds behind the leader.
        let last = txs.len() - 1;
        queue.push(txs.iter().zip(&senders).take(last).map(|(tx, sender)| {
            n42_engine_types::N42PooledTransaction::new(
                reth_primitives_traits::Recovered::new_unchecked(tx.clone(), *sender),
                tx.encoded_2718().len(),
            )
        }));
        queue.drain_now();

        let refs: Vec<&TransactionSigned> = txs.iter().collect();
        let found = senders_in_queue(&queue, &refs);
        assert_eq!(found.len(), txs.len(), "one answer per transaction, in the block's order");
        for (at, got) in found.iter().enumerate() {
            if at == last {
                assert_eq!(*got, None, "the one that never reached this node");
            } else {
                assert_eq!(*got, Some(senders[at]), "the sender this node recovered");
            }
        }
    }

    /// The vote roads on the bench's block shape, side by side: today's
    /// gossip body (decode the block out of 26 MB, then look every sender
    /// up) against the compact body (find the block's transactions in this
    /// node's queue by hash, then recompute the transactions root over what
    /// was found) -- and, between them, the body road with only its senders
    /// taken from the queue's index (`N42_SENDERS_FROM_QUEUE`), which copies
    /// no transaction at all.
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

        // The queue as this node's ingest leaves it -- and *left by the
        // ingest*, on twelve threads of its own, with three more blocks'
        // worth pushed around it. That is the whole point of this fixture:
        // an assembly reads 163,000 objects a dozen other threads allocated
        // at arbitrary times, and a bench that allocates them on its own
        // thread a moment earlier reads them contiguous and warm. loop196
        // measured 112-116 ms on the fleet where this bench had said 22.
        let queue = std::sync::Arc::new(
            n42_tx_queue::TxQueue::<n42_engine_types::N42PooledTransaction>::with_run_length(64)
                .with_hash_index(count * 8),
        );
        let pooled = |tx: &TransactionSigned, sender: Address| {
            n42_engine_types::N42PooledTransaction::new(
                reth_primitives_traits::Recovered::new_unchecked(tx.clone(), sender),
                tx.encoded_2718().len(),
            )
        };
        let fill_at = std::time::Instant::now();
        {
            // Twelve ingest threads, the fleet's `N42_TX_INGEST_RECOVER_PARALLEL`,
            // pushing this block interleaved with noise of their own so the
            // block's transactions end up scattered through the heap rather
            // than laid out in one run.
            let noise = bench_fixture(6_000, 27, 2_000_000, 64).0;
            let noise_txs = noise.body().transactions.clone();
            let noise_senders: Vec<Address> = noise.senders().to_vec();
            std::thread::scope(|scope| {
                for lane in 0..12usize {
                    let queue = std::sync::Arc::clone(&queue);
                    let txs = &txs;
                    let senders = &senders;
                    let noise_txs = &noise_txs;
                    let noise_senders = &noise_senders;
                    scope.spawn(move || {
                        let mut at = lane * 500;
                        while at < txs.len() {
                            let end = (at + 500).min(txs.len());
                            queue.push(
                                (at..end).map(|i| pooled(&txs[i], senders[i])),
                            );
                            // Noise between the block's own batches: other
                            // senders arriving, as the flood delivers them.
                            let nend = end.min(noise_txs.len());
                            if at < nend {
                                queue.push((at..nend).map(|i| pooled(&noise_txs[i], noise_senders[i])));
                            }
                            at += 12 * 500;
                        }
                    });
                }
            });
        }
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

        // The rayon pool busy, as it is on a node: the parent's import runs
        // on the same sixteen threads the assembly's look-ups want, and an
        // idle pool is the other half of why this bench said 22 ms.
        let busy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        // And the ingest still running, as it is on a node: twelve threads
        // pushing while the assembly reads, so the shards are written to
        // and the heap keeps moving under it. The fleet's rate is ~400k
        // transactions a second across those twelve.
        let mut ingest = Vec::new();
        for lane in 0..12usize {
            let queue = std::sync::Arc::clone(&queue);
            let busy = std::sync::Arc::clone(&busy);
            let more = bench_fixture(500, 27, 2_000_000, 64).0;
            ingest.push(std::thread::spawn(move || {
                let txs = more.body().transactions.clone();
                let senders: Vec<Address> = more.senders().to_vec();
                let mut at = 0usize;
                let mut pushed = 0usize;
                while busy.load(std::sync::atomic::Ordering::Relaxed) {
                    let end = (at + 500).min(txs.len());
                    if at >= end {
                        at = 0;
                        // Nonces already queued are refused by the lanes and
                        // indexed all the same, which is the write traffic
                        // this is here for.
                        continue;
                    }
                    queue.push((at..end).map(|i| {
                        n42_engine_types::N42PooledTransaction::new(
                            reth_primitives_traits::Recovered::new_unchecked(txs[i].clone(), senders[i]),
                            120,
                        )
                    }));
                    pushed += end - at;
                    at = end;
                    // ~400k a second across twelve lanes is ~33k each, so a
                    // 500-transaction batch every 15 ms.
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                let _ = lane;
                pushed
            }));
        }
        let load: Vec<u8> = (0..64 << 20).map(|i| (i % 251) as u8).collect();
        {
            let busy = std::sync::Arc::clone(&busy);
            let load = load.clone();
            std::thread::spawn(move || {
                while busy.load(std::sync::atomic::Ordering::Relaxed) {
                    let sum: u64 = load.par_chunks(4096).map(|c| c.iter().map(|b| u64::from(*b)).sum::<u64>()).sum();
                    std::hint::black_box(sum);
                }
            });
        }

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

            // The same road with the senders taken from the queue's by-hash
            // index instead (`N42_SENDERS_FROM_QUEUE`): the same block, the
            // same order, and only the sender pass changes. The reference
            // list is collected outside the measurement, as the import has
            // it before its pass begins.
            //
            // Over the fixture's own transactions rather than the decoded
            // ones: a fixture transaction is signed `new_unchecked` with a
            // random hash, so decoding it computes a hash the queue has
            // never seen and every look-up would miss for a reason no node
            // has. On a node the two are the same transaction and the same
            // hash, which is what the compact road's `hashes` assume too.
            let refs: Vec<&TransactionSigned> = txs.iter().collect();
            let index_at = std::time::Instant::now();
            let from_index = senders_in_queue(&queue, &refs);
            let index_ms = ms(index_at);
            let indexed = from_index.iter().flatten().count();
            assert!(
                from_index.iter().zip(&senders).all(|(got, want)| got.is_none_or(|got| got == *want)),
                "what the index holds is the sender the ingest recovered",
            );

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
                "round {round}: body decode {decode_ms:.1} + senders {senders_ms:.1} (cached {filled},                  found {found}) = {:.1} | from the index {index_ms:.1} (indexed {indexed}) | compact {compact_ms:.1} = assemble {:.1} + root {:.1} +                  rest {:.1}, misses {}",
                decode_ms + senders_ms,
                assembled.assemble_us as f64 / 1000.0,
                assembled.root_us as f64 / 1000.0,
                (assembled.total_us.saturating_sub(assembled.assemble_us + assembled.root_us)) as f64 / 1000.0,
                assembled.misses,
            );
        }
        busy.store(false, std::sync::atomic::Ordering::Relaxed);
        let pushed: usize = ingest.into_iter().filter_map(|h| h.join().ok()).sum();
        println!("the ingest pushed {pushed} transactions while the rounds ran");
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
        let parent = merged(bundle(&accounts));
        check_includable(
            &empty,
            B256::random(),
            Some(ParentBundles { stack: &[&parent], anchor: B256::random() }),
            &block,
            CHAIN_ID,
            SpecId::OSAKA,
        )
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
        let parent = merged(bundle(&case.output));
        let grandparent = B256::random();
        let hash = B256::random();
        let read = |output| {
            (
                check_includable_oracle(state, hash, output, &case.block, CHAIN_ID, SpecId::OSAKA),
                check_includable(state, hash, output, &case.block, CHAIN_ID, SpecId::OSAKA),
            )
        };
        [read(None), read(Some(ParentBundles { stack: &[&parent], anchor: grandparent }))]
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

    /// `N42_FOLLOWER_FRAME_SCAN=1`: the block cut into frames, every frame
    /// with nothing to refuse summed as the ingest sums it, and the check on
    /// those summaries gives the verdict and the words of the per-transaction
    /// scan -- whole frames, a cut last frame, and frames with flaws alike.
    #[test]
    fn frame_summaries_give_the_scans_verdict() {
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
        let mut summarized_somewhere = false;
        for seed in 1..200u64 {
            let mut rng = Rng(seed * 2_654_435_761);
            let flaws: Vec<Flaw> = (0..rng.below(3)).map(|_| all[rng.below(all.len() as u64) as usize]).collect();
            let case = random_case(seed * 15_485_863, &flaws);
            {
                let mut accounts = state.accounts.lock();
                accounts.clear();
                accounts.extend(
                    case.state.iter().map(|(address, account)| (*address, ExtendedAccount::new(account.nonce, account.balance))),
                );
            }
            let txs = &case.block.body().transactions;
            let senders = case.block.senders();
            let frame = 1 + rng.below(9) as usize;
            let mut layout = Vec::new();
            let mut start = 0;
            while start < txs.len() {
                let count = frame.min(txs.len() - start);
                let id = B256::random();
                // The last frame cut, as a block ending in a prefix is.
                let whole = count == frame;
                if let Some(scan) = n42_engine_types::frame_scan::summarize(
                    txs[start..start + count].iter().zip(senders[start..start + count].iter().copied()),
                ) {
                    n42_engine_types::frame_scan::remember(id, scan);
                }
                layout.push((id, count, whole));
                start += count;
            }
            let hash = B256::random();
            let scanned = check_includable(&state, hash, None, &case.block, CHAIN_ID, SpecId::OSAKA);
            let mut times = CheckTimes::default();
            let framed = check_includable_laid_out(
                &state,
                hash,
                None,
                &case.block,
                CHAIN_ID,
                SpecId::OSAKA,
                Some(layout.as_slice()),
                &mut times,
            );
            assert_eq!(scanned, framed, "seed {seed}, {flaws:?}");
            summarized_somewhere |= times.frames_summarized > 0;
        }
        assert!(summarized_somewhere, "no frame was ever read from its summary");
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

#[cfg(test)]
mod by_description_bench;

#[cfg(test)]
#[path = "follower_import_tests.rs"]
mod branch_tests;

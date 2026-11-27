// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Committed ranges imported in one call: `n42Engine_importRange`.
//!
//! A node far behind its chain pulls committed blocks by range and, block by
//! block, hands each to the engine with `newPayload`: a JSON round trip, the
//! engine's payload processor (a prewarm pass, a receipt-root task, a state
//! root job), the profile-1 header's two BLS checks (the embedded QC and the
//! proposer's seal), and a forkchoice per batch. On an empty block that is
//! ~2 ms of fixed cost against well under 0.1 ms of execution
//! (`docs/P1_CATCHUP_PERF.md`), and a chain of 13 million mostly empty blocks
//! is then a day of catch-up.
//!
//! Here a run of consecutive blocks is executed in one call, on one cache
//! carried from block to block (the reads of block `n` are the post-state of
//! block `n - 1`, never a provider lookup through the engine's tree), each
//! block checked and its QMDB root filed as the engine would, and each handed
//! to the engine as an executed block (`InsertExecutedBlock`); one forkchoice
//! after the run makes the last one the head. Persistence then takes the
//! blocks in the engine's own batches.
//!
//! What is checked, per block, is everything the engine's own import checks
//! except the two signatures in a profile-1 header (the embedded QC and the
//! seal): the header's rules and its link to its parent, the body against the
//! header, execution, gas, receipts root and logs bloom, requests, and the
//! QMDB root against the header's state root. The last block of every run is
//! checked with the signatures too. Why skipping them is safe -- the caller
//! hands only blocks a verified commit QC authenticates -- is argued in
//! `docs/P1_CATCHUP_PERF.md` (step 6).
//!
//! Under deferred execution (profile 1 from block 1) a header carries an
//! ancestor's execution: each block's header is checked against the results
//! this node filed for its parent (the previous block of the run, or the
//! engine's last import), and its own results are filed for its child, as
//! the engine's import does. The run's last block's own results are checked
//! by the header that follows it, in the next run or on the live path.
//!
//! The run is refused as a whole -- `unavailable`, and the caller imports it
//! block by block as before -- when its first block's parent cannot be made
//! the engine's canonical head.

use std::sync::Arc;

use alloy_primitives::B256;
use n42_tx_types::{Block, N42Primitives};
use reth_consensus::FullConsensus;
use reth_evm::{database::StateProviderDatabase, execute::Executor as _, ConfigureEvm};
use reth_execution_types::BundleSource;
use reth_payload_primitives::BuiltPayloadExecutedBlock;
use reth_primitives_traits::SealedBlock;
use reth_provider::{HashedPostStateProvider as _, HeaderProvider, StateProviderFactory};
use reth_trie::updates::TrieUpdates;
use serde::{Deserialize, Serialize};

/// A parent block's `(number, hash, receipts root)`: the key of its committee link.
pub type ParentKey = (u64, B256, B256);

/// Computes the committee links of a run's parents ahead of the import.
pub type PrefetchLinks = dyn Fn(&[ParentKey]) + Send + Sync;

/// `N42_CATCHUP_IMPORT=0` withdraws `n42Engine_importRange` (it answers
/// `null`, and the validator imports block by block). On by default: the
/// method is only ever called by a validator that pulls a committed range.
pub const CATCHUP_IMPORT_ENV: &str = "N42_CATCHUP_IMPORT";

/// What one `n42Engine_importRange` call did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeImport {
    /// How many of the given blocks were executed, checked and made the
    /// engine's chain: all of them, or none ([`serve`] is all or nothing).
    pub imported: u64,
    /// The head after the call: the run's last block, when it was imported.
    pub head: Option<B256>,
    /// A block of the run was refused, and why. Nothing is imported; the
    /// caller imports the run block by block for the per-block verdict.
    pub refused: Option<String>,
    /// The run was not taken, and why; the caller imports it block by block.
    pub unavailable: Option<String>,
    /// Microseconds spent: decoding, header and body checks, execution,
    /// post-execution checks, QMDB roots, hashed state, engine hand-off.
    pub times_us: [u64; 7],
}

/// A run's blocks executed and checked, ready for the engine.
pub type Executed = BuiltPayloadExecutedBlock<N42Primitives>;

/// Index into [`RangeImport::times_us`].
pub const T_DECODE: usize = 0;
/// Index into [`RangeImport::times_us`].
pub const T_CHECKS: usize = 1;
/// Index into [`RangeImport::times_us`].
pub const T_EXECUTE: usize = 2;
/// Index into [`RangeImport::times_us`].
pub const T_POST: usize = 3;
/// Index into [`RangeImport::times_us`].
pub const T_ROOT: usize = 4;
/// Index into [`RangeImport::times_us`].
pub const T_HASHED: usize = 5;
/// Index into [`RangeImport::times_us`].
pub const T_HANDOFF: usize = 6;

fn us(at: std::time::Instant) -> u64 {
    at.elapsed().as_micros() as u64
}

/// Executes `blocks` (consecutive, the first on `blocks[0].parent_hash`) on
/// the parent's state and, once every block has passed, hands the executed
/// blocks to `hand_off` in order; a refused run hands over nothing.
///
/// `lean` checks every block but the last without the profile-1 signatures;
/// `full` checks the last with them (both are the node's consensus rules
/// otherwise). Stops at the first block refused; `head` is the canonical
/// head the run must start on. See the module docs.
#[allow(clippy::too_many_arguments)]
pub fn import_range<Provider, Evm, ChainSpec>(
    blocks: Vec<SealedBlock<Block>>,
    head: B256,
    provider: &Provider,
    evm_config: &Evm,
    qmdb: &n42_qmdb_reth::QmdbNodeState,
    lean: &(dyn FullConsensus<N42Primitives> + Send + Sync),
    full: &(dyn FullConsensus<N42Primitives> + Send + Sync),
    chain_spec: &ChainSpec,
    times_us: &mut [u64; 7],
    prefetch: &(dyn Fn(&[ParentKey]) + Sync),
    hand_off: &mut dyn FnMut(Executed) -> Result<(), String>,
) -> RangeImport
where
    Provider: StateProviderFactory + HeaderProvider<Header = n42_header::N42Header>,
    Evm: ConfigureEvm<Primitives = N42Primitives>,
    ChainSpec: reth_chainspec::EthereumHardforks + reth_chainspec::EthChainSpec,
{
    let mut out = RangeImport::default();
    let Some(first) = blocks.first() else {
        return out;
    };
    let unavailable = |why: String| RangeImport { unavailable: Some(why), ..Default::default() };
    if first.parent_hash != head {
        return unavailable(format!("the run starts on {}, not on the head {head}", first.parent_hash));
    }
    let genesis = chain_spec.genesis();
    let mut parent = match provider.sealed_header_by_hash(first.parent_hash) {
        Ok(Some(parent)) => parent,
        Ok(None) => return unavailable(format!("parent {} unknown", first.parent_hash)),
        Err(err) => return unavailable(format!("parent header: {err}")),
    };
    let state = match provider.state_by_block_hash(first.parent_hash) {
        Ok(state) => state,
        Err(err) => return unavailable(format!("parent state: {err}")),
    };
    // One cache over the parent's state for the whole run: each block's
    // post-state is committed into it, so the next block reads it from here.
    let mut db = evm2::evm::CacheDB::new(evm2::evm::Db::new(StateProviderDatabase::new(
        reth_provider::StateProvider::into_evm_state_provider(&state),
    )));
    // Every block's header check links it to its parent's committee
    // evidence, a pure function of the parent header that takes ~0.5 ms to
    // compute: the run's are computed on the worker pool beside the run, in
    // order, a chunk at a time, so they stay ahead of the checks (a check
    // that gets there first computes its own, as without the prefetch).
    let parents: Vec<(u64, B256, B256)> = std::iter::once((parent.number, parent.hash(), parent.receipts_root))
        .chain(blocks[..blocks.len() - 1].iter().map(|b| (b.number, b.hash(), b.receipts_root)))
        .collect();
    let stop_prefetch = std::sync::atomic::AtomicBool::new(false);
    let last = blocks.len() - 1;
    let mut ready: Vec<Executed> = Vec::with_capacity(blocks.len());
    // The QMDB roots are computed on a worker, in block order, beside the
    // execution: block `n`'s root while block `n + 1` executes. The roots
    // are a chain (each filed on its parent's) and the header check of
    // block `n + 1` reads block `n`'s filed results under deferred
    // execution, so that check waits for the root before it; execution does
    // not need it (the state is the run's cache). A refusal anywhere ends
    // the run before the hand-off, as before.
    std::thread::scope(|scope| {
        let stop_prefetch = &stop_prefetch;
        let parents = &parents;
        scope.spawn(move || {
            for chunk in parents.chunks(PREFETCH_CHUNK) {
                if stop_prefetch.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                // On a pool of its own: on rayon's global one it took the
                // threads the QMDB root runs on and slowed the root chain,
                // which bounds the run, by a third (ep1ba7c).
                match prefetch_pool() {
                    Some(pool) => pool.install(|| prefetch(chunk)),
                    None => prefetch(chunk),
                }
            }
        });
        // Whatever way the run ends, the prefetch stops at its next chunk.
        struct StopOnDrop<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let _stop = StopOnDrop(stop_prefetch);
        let (root_tx, root_rx) = std::sync::mpsc::channel::<RootJob>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<(u64, B256, Result<(), String>)>();
        scope.spawn(move || {
            for job in root_rx {
                let (number, hash) = (job.number, job.hash);
                let at = std::time::Instant::now();
                let result = job.run(qmdb);
                ROOT_WORK_US.fetch_add(us(at), std::sync::atomic::Ordering::Relaxed);
                if done_tx.send((number, hash, result)).is_err() {
                    break;
                }
            }
        });
        // The root in flight: waited for before the next block's parent check,
        // and after the last block.
        let mut in_flight = false;
        let wait_root = |out: &mut RangeImport, times_us: &mut [u64; 7], in_flight: &mut bool| -> bool {
            if !std::mem::take(in_flight) {
                return true;
            }
            let at = std::time::Instant::now();
            let done = done_rx.recv();
            times_us[T_ROOT] += us(at);
            match done {
                Ok((_, _, Ok(()))) => true,
                Ok((number, hash, Err(why))) => {
                    out.refused = Some(format!("block {number} ({hash}): {why}"));
                    false
                }
                Err(_) => {
                    out.unavailable = Some("the root worker stopped".to_string());
                    false
                }
            }
        };
        for (index, sealed) in blocks.into_iter().enumerate() {
            let block_at = std::time::Instant::now();
            let number = sealed.number;
            let hash = sealed.hash();
            let refuse = |out: &mut RangeImport, why: String| {
                out.refused = Some(format!("block {number} ({hash}): {why}"));
            };
            // The header and body by the consensus rules; the transactions root
            // was computed by the payload's conversion, which built the header
            // whose hash the payload names. The rules against the parent come
            // after execution, once the parent's root is filed.
            let at = std::time::Instant::now();
            let rules = if index == last { full } else { lean };
            let checked = rules.validate_header(sealed.sealed_header()).map_err(|err| format!("header: {err}")).and_then(|()| {
                rules
                    .validate_block_pre_execution_with_tx_root(&sealed, Some(sealed.transactions_root))
                    .map_err(|err| format!("body: {err}"))
            });
            times_us[T_CHECKS] += us(at);
            if let Err(why) = checked {
                refuse(&mut out, why);
                return out;
            }
            let at = std::time::Instant::now();
            let recovered = match sealed.try_recover() {
                Ok(recovered) => recovered,
                Err(err) => {
                    refuse(&mut out, format!("senders: {err}"));
                    return out;
                }
            };
            let output = match evm_config.executor(&mut db).execute(&recovered) {
                Ok(output) => output,
                Err(err) => {
                    refuse(&mut out, format!("execution: {err}"));
                    return out;
                }
            };
            db.commit_source(&BundleSource(&output.state));
            times_us[T_EXECUTE] += us(at);
            let at = std::time::Instant::now();
            if let Err(err) = rules.validate_block_post_execution(&recovered, &output.result, None, None) {
                refuse(&mut out, format!("post-execution: {err}"));
                return out;
            }
            times_us[T_POST] += us(at);
            // The QMDB root, filed under the block as the engine's own root job
            // files it (persistence and the forest's history read it per block),
            // on the worker. The ops are built here: they borrow the output.
            let at = std::time::Instant::now();
            let prague = n42_qmdb_reth::system_caller_leaf_at(chain_spec, recovered.timestamp);
            let ops = n42_qmdb_reth::sorted_operations_from_execution(&output.state, prague);
            // Deferred execution: the header carries an ancestor's root, which
            // the parent check compares with this node's result; this block's own
            // root is filed for its child's header, as the engine's and the
            // follower's imports file it. Otherwise the header's own root.
            let check = (!reth_chainspec::qmdb::deferred_execution_active_at(genesis, recovered.timestamp))
                .then_some(recovered.state_root);
            times_us[T_ROOT] += us(at);
            // The parent's root first: the worker files roots in order and the
            // parent check below reads it.
            if !wait_root(&mut out, times_us, &mut in_flight) {
                return out;
            }
            if root_tx.send(RootJob { parent: parent.hash(), hash, number, ops, check }).is_err() {
                out.unavailable = Some("the root worker stopped".to_string());
                return out;
            }
            in_flight = true;
            let at = std::time::Instant::now();
            if let Err(err) = rules.validate_header_against_parent(recovered.sealed_header(), &parent) {
                refuse(&mut out, format!("header against parent: {err}"));
                return out;
            }
            times_us[T_CHECKS] += us(at);
            let at = std::time::Instant::now();
            let hashed_state = if crate::follower_import::hashed_state_enabled() {
                match state.hashed_post_state(&output.state) {
                    Ok(hashed) => hashed,
                    Err(err) => {
                        refuse(&mut out, format!("hashed state: {err}"));
                        return out;
                    }
                }
            } else {
                reth_trie::HashedPostState::default()
            };
            times_us[T_HASHED] += us(at);
            let next_parent = recovered.clone_sealed_header();
            let txs = recovered.body().transactions.len();
            let at = std::time::Instant::now();
            let executed = BuiltPayloadExecutedBlock {
                recovered_block: Arc::new(recovered),
                execution_output: Arc::new(output),
                hashed_state: Arc::new(hashed_state),
                trie_updates: Arc::new(TrieUpdates::default()),
            };
            ready.push(executed);
            times_us[T_HANDOFF] += us(at);
            tracing::debug!(target: "n42.catchup", number, txs, us = us(block_at), "range block imported");
            out.imported += 1;
            out.head = Some(hash);
            parent = next_parent;
        }
        if !wait_root(&mut out, times_us, &mut in_flight) {
            out.imported = 0;
            out.head = None;
            return out;
        }
        // Every block passed, the last with the profile-1 signatures: only now
        // does anything reach the engine. A run refused above leaves nothing in
        // the tree (its matching QMDB roots are non-canonical forest entries,
        // as a fork block's are, never persisted).
        let at = std::time::Instant::now();
        for executed in ready {
            if let Err(why) = hand_off(executed) {
                out.unavailable = Some(format!("hand-off: {why}"));
                out.imported = 0;
                out.head = None;
                break;
            }
        }
        times_us[T_HANDOFF] += us(at);
        out
    })
}

/// Committee links the run's prefetch computes per step: enough to keep the
/// worker pool busy, small enough to stay just ahead of the checks.
const PREFETCH_CHUNK: usize = 32;

/// Threads of the committee-link prefetch's pool: at ~0.5 ms a link, four
/// keep ahead of a run of empty blocks (~0.15 ms each).
const PREFETCH_THREADS: usize = 4;

/// The committee-link prefetch's own pool (`None` if it cannot be built:
/// the prefetch then runs on rayon's global pool).
fn prefetch_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(PREFETCH_THREADS)
            .thread_name(|i| format!("catchup-link-{i}"))
            .build()
            .ok()
    })
    .as_ref()
}

/// The root worker's own time, summed over a call (one call runs at a
/// time): against `root` (the import's wait for it), what the roots cost and
/// what the overlap with execution hid.
static ROOT_WORK_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One block's QMDB root, for the run's root worker.
struct RootJob {
    parent: B256,
    hash: B256,
    number: u64,
    ops: n42_twig_core::qmdb_compat::QmdbOps,
    /// The header's state root to compare with; `None` under deferred
    /// execution, where the root is filed for the child's header.
    check: Option<B256>,
}

impl RootJob {
    /// Computes and files the root: under deferred execution it is
    /// remembered for the child's header check; otherwise it must be the
    /// header's (and only then is it filed).
    fn run(self, qmdb: &n42_qmdb_reth::QmdbNodeState) -> Result<(), String> {
        let ops = self.ops;
        match self.check {
            None => {
                let root = qmdb
                    .insert_block_operations(self.parent, self.hash, self.number, ops)
                    .map_err(|err| format!("state root: {err}"))?;
                n42_engine_types::executed_fields::remember_state_root(self.hash, root);
                Ok(())
            }
            Some(header_root) => {
                match qmdb.validate_block_operations(self.parent, self.hash, self.number, ops, header_root) {
                    Ok(root) if root == header_root => Ok(()),
                    Ok(root) => Err(format!("state root {root} is not the header's {header_root}")),
                    Err(err) => Err(format!("state root: {err}")),
                }
            }
        }
    }
}

/// Moves the engine's head to a block it holds; set once the engine runs
/// ([`set_forkchoice`]).
pub type Forkchoice =
    Arc<dyn Fn(B256) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>;

static FORKCHOICE: std::sync::OnceLock<Forkchoice> = std::sync::OnceLock::new();

/// Installs the head move the import ends with. Until it is set (the engine
/// launches after the RPC modules are built) an import answers `unavailable`.
pub fn set_forkchoice(forkchoice: Forkchoice) {
    let _ = FORKCHOICE.set(forkchoice);
}

/// `n42Engine_importRange` on this node: converts the payloads as the engine
/// would, runs [`import_range`] on a blocking thread, hands each executed
/// block to the engine's executed-insert stream in order, and moves the head
/// to the last one. One call runs at a time.
#[allow(clippy::too_many_arguments)]
pub fn serve<Provider, Evm>(
    provider: Provider,
    evm_config: Evm,
    qmdb: n42_qmdb_reth::QmdbNodeState,
    lean: Arc<dyn FullConsensus<N42Primitives> + Send + Sync>,
    full: Arc<dyn FullConsensus<N42Primitives> + Send + Sync>,
    prefetch: Arc<PrefetchLinks>,
    chain_spec: Arc<n42_header::N42ChainSpec>,
    validator: Arc<n42_engine_types::engine_validator::N42EngineValidator<n42_header::N42ChainSpec>>,
) -> crate::engine_ext::ImportRange
where
    Provider: StateProviderFactory
        + HeaderProvider<Header = n42_header::N42Header>
        + reth_provider::BlockNumReader
        + Clone
        + Send
        + Sync
        + 'static,
    Evm: ConfigureEvm<Primitives = N42Primitives> + Clone + Send + Sync + 'static,
{
    let one_at_a_time = Arc::new(tokio::sync::Mutex::new(()));
    Arc::new(move |payloads: Vec<alloy_rpc_types_engine::ExecutionData>| {
        let (provider, evm_config, qmdb) = (provider.clone(), evm_config.clone(), qmdb.clone());
        let (lean, full, chain_spec, validator) = (lean.clone(), full.clone(), chain_spec.clone(), validator.clone());
        let prefetch = prefetch.clone();
        let one_at_a_time = one_at_a_time.clone();
        Box::pin(async move {
            let _one = one_at_a_time.lock().await;
            let Some(forkchoice) = FORKCHOICE.get().cloned() else {
                return RangeImport { unavailable: Some("the engine is not running yet".to_string()), ..Default::default() };
            };
            // The run's first parent is the caller's last imported block, which
            // its own forkchoice may not have made the head yet (it moves the
            // head once per report). Made the head here, as that forkchoice
            // would: the engine takes it only for a block it holds as valid.
            if let Some(first) = payloads.first() {
                let first_parent = first.payload.parent_hash();
                let head = provider.chain_info().map(|info| info.best_hash);
                if head.as_ref().is_ok_and(|head| *head != first_parent)
                    && let Err(err) = forkchoice(first_parent).await
                {
                    return RangeImport {
                        unavailable: Some(format!("the run's parent {first_parent} could not be made the head: {err}")),
                        ..Default::default()
                    };
                }
            }
            let txs: usize = payloads.iter().map(|data| data.payload.as_v1().transactions.len()).sum();
            let run = tokio::task::spawn_blocking(move || {
                let mut times = [0u64; 7];
                let at = std::time::Instant::now();
                let given = payloads.len() as u64;
                // Each payload on its own (its hash and transactions root), in
                // parallel; the first malformed one in block order ends the run.
                let converted: Vec<Result<SealedBlock<Block>, String>> = {
                    use rayon::prelude::*;
                    payloads
                        .into_par_iter()
                        .map(|data| {
                            let number = data.payload.block_number();
                            <n42_engine_types::engine_validator::N42EngineValidator<n42_header::N42ChainSpec> as reth_engine_primitives::PayloadValidator<n42_engine_types::N42EngineTypes>>::convert_payload_to_block(&validator, data)
                                .map_err(|err| format!("block {number}: payload: {err}"))
                        })
                        .collect()
                };
                let mut blocks = Vec::with_capacity(converted.len());
                let mut malformed = None;
                for block in converted {
                    match block {
                        Ok(block) => blocks.push(block),
                        Err(why) => {
                            malformed = Some(why);
                            break;
                        }
                    }
                }
                times[T_DECODE] = us(at);
                let head = match provider.chain_info() {
                    Ok(info) => info.best_hash,
                    Err(err) => {
                        return RangeImport { unavailable: Some(format!("canonical head: {err}")), ..Default::default() };
                    }
                };
                let inserts = reth_node_builder::executed_inserts::sender();
                let mut handed = Vec::with_capacity(blocks.len());
                let mut hand_off = |executed: Executed| {
                    let hash = executed.recovered_block.hash();
                    let (done, landed) = tokio::sync::oneshot::channel();
                    inserts
                        .send(reth_node_builder::executed_inserts::ExecutedInsert { block: Box::new(executed), done })
                        .map_err(|_| "the engine's insert stream is closed".to_string())?;
                    handed.push((hash, landed));
                    Ok(())
                };
                let mut out = import_range(blocks, head, &provider, &evm_config, &qmdb, &*lean, &*full, &*chain_spec, &mut times, &*prefetch, &mut hand_off);
                // The inserts are queued in order; wait until the engine has
                // taken every one.
                let at = std::time::Instant::now();
                let landed_all = handed.into_iter().all(|(_, landed)| matches!(landed.blocking_recv(), Ok(true)));
                times[T_HANDOFF] += us(at);
                out.times_us = times;
                if out.refused.is_none() && out.unavailable.is_none() {
                    if let Some(why) = malformed {
                        out.refused = Some(why);
                    } else if !landed_all {
                        out.unavailable = Some("the engine did not take an executed block".to_string());
                    } else if out.imported != given {
                        out.unavailable = Some(format!("{} of {given} blocks imported", out.imported));
                    }
                }
                // All or nothing: the head only moves to the run's last block,
                // the one checked with the profile-1 signatures, whose QC
                // covers the run below it (`docs/P1_CATCHUP_PERF.md` step 6).
                // A run cut short leaves its executed blocks in the tree,
                // not canonical, and the caller imports it block by block
                // (`newPayload` answers a block the tree holds at once).
                if out.refused.is_some() || out.unavailable.is_some() {
                    out.imported = 0;
                    out.head = None;
                }
                out
            });
            let call_at = std::time::Instant::now();
            let out = run.await.unwrap_or_else(|err| RangeImport { unavailable: Some(format!("import task: {err}")), ..Default::default() });
            let fcu_at = std::time::Instant::now();
            if let Some(head) = out.head
                && let Err(err) = forkchoice(head).await
            {
                // The blocks are in the engine's tree, not canonical: the
                // caller's own newPayload finds them held and answers VALID.
                return RangeImport { unavailable: Some(format!("forkchoice to {head}: {err}")), times_us: out.times_us, ..Default::default() };
            }
            let [decode, checks, execute, post, root, hashed, handoff] = out.times_us;
            tracing::info!(
                target: "n42.catchup",
                blocks = out.imported,
                txs,
                total_us = us(call_at),
                decode, checks, execute, post, root, hashed, handoff,
                forkchoice_us = us(fcu_at),
                root_work_us = ROOT_WORK_US.swap(0, std::sync::atomic::Ordering::Relaxed),
                refused = out.refused.as_deref(),
                unavailable = out.unavailable.as_deref(),
                "range import"
            );
            out
        })
    })
}


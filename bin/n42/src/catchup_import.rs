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
    let last = blocks.len() - 1;
    let mut ready: Vec<Executed> = Vec::with_capacity(blocks.len());
    for (index, sealed) in blocks.into_iter().enumerate() {
        let block_at = std::time::Instant::now();
        let number = sealed.number;
        let hash = sealed.hash();
        let refuse = |out: &mut RangeImport, why: String| {
            out.refused = Some(format!("block {number} ({hash}): {why}"));
        };
        // The header and body by the consensus rules; the transactions root
        // was computed by the payload's conversion, which built the header
        // whose hash the payload names.
        let at = std::time::Instant::now();
        let rules = if index == last { full } else { lean };
        let checked = rules
            .validate_header(sealed.sealed_header())
            .map_err(|err| format!("header: {err}"))
            .and_then(|()| {
                rules
                    .validate_header_against_parent(sealed.sealed_header(), &parent)
                    .map_err(|err| format!("header against parent: {err}"))
            })
            .and_then(|()| {
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
        // files it: persistence and the forest's history read it per block.
        let at = std::time::Instant::now();
        let prague = n42_qmdb_reth::system_caller_leaf_at(chain_spec, recovered.timestamp);
        let ops = n42_qmdb_reth::sorted_operations_from_execution(&output.state, prague);
        if reth_chainspec::qmdb::deferred_execution_active_at(genesis, recovered.timestamp) {
            // Deferred execution: the header carries an ancestor's root, which
            // the header check above compared with this node's result. This
            // block's own root is filed for its child's header to be checked
            // against, as the engine's and the follower's imports file it.
            match qmdb.insert_block_operations(parent.hash(), hash, number, ops) {
                Ok(root) => n42_engine_types::executed_fields::remember_state_root(hash, root),
                Err(err) => {
                    refuse(&mut out, format!("state root: {err}"));
                    return out;
                }
            }
        } else {
            match qmdb.validate_block_operations(parent.hash(), hash, number, ops, recovered.state_root) {
                Ok(root) if root == recovered.state_root => {}
                Ok(root) => {
                    refuse(&mut out, format!("state root {root} is not the header's {}", recovered.state_root));
                    return out;
                }
                Err(err) => {
                    refuse(&mut out, format!("state root: {err}"));
                    return out;
                }
            }
        }
        times_us[T_ROOT] += us(at);
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
pub fn serve<Provider, Evm>(
    provider: Provider,
    evm_config: Evm,
    qmdb: n42_qmdb_reth::QmdbNodeState,
    lean: Arc<dyn FullConsensus<N42Primitives> + Send + Sync>,
    full: Arc<dyn FullConsensus<N42Primitives> + Send + Sync>,
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
            let run = tokio::task::spawn_blocking(move || {
                let mut times = [0u64; 7];
                let at = std::time::Instant::now();
                let given = payloads.len() as u64;
                let mut blocks = Vec::with_capacity(payloads.len());
                let mut malformed = None;
                for data in payloads {
                    let number = data.payload.block_number();
                    match <n42_engine_types::engine_validator::N42EngineValidator<n42_header::N42ChainSpec> as reth_engine_primitives::PayloadValidator<n42_engine_types::N42EngineTypes>>::convert_payload_to_block(&validator, data) {
                        Ok(block) => blocks.push(block),
                        Err(err) => {
                            malformed = Some(format!("block {number}: payload: {err}"));
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
                let mut out = import_range(blocks, head, &provider, &evm_config, &qmdb, &*lean, &*full, &*chain_spec, &mut times, &mut hand_off);
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
                total_us = us(call_at),
                decode, checks, execute, post, root, hashed, handoff,
                forkchoice_us = us(fcu_at),
                refused = out.refused.as_deref(),
                unavailable = out.unavailable.as_deref(),
                "range import"
            );
            out
        })
    })
}


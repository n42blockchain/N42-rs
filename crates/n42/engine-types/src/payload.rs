//! A basic Ethereum payload builder implementation.

/*
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
*/
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(clippy::useless_let_if_seq)]

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{B256, U256};
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_errors::{BlockExecutionError, BlockValidationError};
use n42_tx_types::{N42Primitives as EthPrimitives, N42TxEnvelope as TransactionSigned};
use alloy_consensus::transaction::TxHashRef as _;
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, NextBlockEnvAttributes,
};
use reth_evm_ethereum::EthBlockAssembler;
use crate::engine_types::N42BuiltPayload as EthBuiltPayload;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_evm::database::StateProviderDatabase;
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};
use std::sync::Arc;
use tracing::{debug, trace, warn};

//mod config;
//pub use config::*;

//pub mod validator;
//pub use validator::EthereumExecutionPayloadValidator;

use reth_primitives_traits::SealedBlock;
//use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};
use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_chain_state::CanonStateSubscriptions;
use n42_consensus_traits::SignerManager;
use n42_qmdb_reth::{changes_from_execution, QmdbNodeState};
use reth_trie::updates::TrieUpdates;
use reth_consensus::FullConsensus;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_node_builder::{
    components::{ConsensusBuilder, PayloadServiceBuilder},
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};

// Historical catch-up never enters the payload builder. Until a qualified
// live PEVM builder exists, every invocation here is the live sequential path.
const LIVE_EVM_PATH: &str = "live_sequential";

// wrapper

// Payload component configuration for the Ethereum node.

//use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_node_api::TxTy;
use reth_node_builder::{PayloadBuilderConfig, PayloadTypes};

/// A basic ethereum payload service builder marker.
///
/// Note: In v1.5.0, consensus is built separately and shared via NodeComponents.
/// The actual consensus instance will be passed through the N42PayloadServiceBuilder.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // wrapper kept for the stock payload builder; not constructed today
pub struct EthereumPayloadBuilderWrapper;

impl EthereumPayloadBuilderWrapper {
    /// Create a new wrapper.
    #[allow(dead_code)] // constructor of the wrapper above; not used today
    pub fn new() -> Self {
        Self
    }
}
// wrapper

// reth/crates/ethereum/payload/src/config.rs
use reth_primitives_traits::constants::GAS_LIMIT_BOUND_DIVISOR;

/*
/// Settings for the Ethereum builder.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EthereumBuilderConfig {
    /// Desired gas limit.
    pub desired_gas_limit: u64,
    /// Waits for the first payload to be built if there is no payload built when the payload is
    /// being resolved.
    pub await_payload_on_missing: bool,
}

impl Default for EthereumBuilderConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EthereumBuilderConfig {
    /// Create new payload builder config.
    pub const fn new() -> Self {
        Self { desired_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M, await_payload_on_missing: true }
    }

    /// Set desired gas limit.
    pub const fn with_gas_limit(mut self, desired_gas_limit: u64) -> Self {
        self.desired_gas_limit = desired_gas_limit;
        self
    }

    /// Configures whether the initial payload should be awaited when the payload job is being
    /// resolved and no payload has been built yet.
    pub const fn with_await_payload_on_missing(mut self, await_payload_on_missing: bool) -> Self {
        self.await_payload_on_missing = await_payload_on_missing;
        self
    }
}

impl EthereumBuilderConfig {
    /// Returns the gas limit for the next block based
    /// on parent and desired gas limits.
    pub fn gas_limit(&self, parent_gas_limit: u64) -> u64 {
        calculate_block_gas_limit(parent_gas_limit, self.desired_gas_limit)
    }
}
*/

/// Calculate the gas limit for the next block based on parent and desired gas limits.
/// Ref: <https://github.com/ethereum/go-ethereum/blob/88cbfab332c96edfbe99d161d9df6a40721bd786/core/block_validator.go#L166>
#[allow(dead_code)] // gas-limit helper kept for the stock builder; not used today
pub fn calculate_block_gas_limit(parent_gas_limit: u64, desired_gas_limit: u64) -> u64 {
    let delta = (parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1);
    let min_gas_limit = parent_gas_limit - delta;
    let max_gas_limit = parent_gas_limit + delta;
    desired_gas_limit.clamp(min_gas_limit, max_gas_limit)
}
// reth/crates/ethereum/payload/src/config.rs

/// The gas limit a block may take when its header carries another block's
/// `gasUsed` (`deferredExecutionDepth` 2, docs/DEFERRED_DEPTH_2_DESIGN.md
/// item 19): never below the carried gas, or the header fails
/// `gas_used <= gas_limit`. `computed` is the ordinary step towards the
/// desired limit; when it falls below the carried gas the limit is raised
/// towards it, no further than the parent's limit allows. An unknown carried
/// gas keeps the limit from shrinking at all.
pub fn gas_limit_over_carried(computed: u64, parent_gas_limit: u64, carried_gas_used: Option<u64>) -> u64 {
    let floor = carried_gas_used.unwrap_or(parent_gas_limit);
    if computed >= floor {
        return computed;
    }
    let max = parent_gas_limit.saturating_add((parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1));
    floor.min(max).max(computed)
}

/// The fields a header carries, waited for when a build needs them:
/// depth 1 is the parent's (under its sealed hash, or under `parent_built` as
/// the builder filed it); depth 2 the grandparent's under the parent header's
/// `parent_hash`, which [`crate::executed_fields`] follows to the builder's
/// entry when this node built it (`note_built`).
fn carried_fields_for_seal(
    genesis: &alloy_genesis::Genesis,
    parent: &reth_primitives_traits::SealedHeader<n42_header::N42Header>,
    parent_built: Option<B256>,
    depth: u64,
) -> Option<crate::executed_fields::ExecutedFields> {
    carried_fields_for_seal_traced(genesis, parent, parent_built, depth).0
}

/// [`carried_fields_for_seal`], saying what the seal waited on
/// (`parent_fields_wait_on` on the phases line): "ready" when the carried
/// ancestor's fields were in the registry at the call; otherwise the half
/// of that ancestor's entry still missing when the wait began --
/// "state_root" (its QMDB root job behind its own seal), "receipts" (its
/// receipts root behind its seal), "both" (neither half filed yet), or
/// "no_built" when there was no builder hash to wait under.
fn carried_fields_for_seal_traced(
    genesis: &alloy_genesis::Genesis,
    parent: &reth_primitives_traits::SealedHeader<n42_header::N42Header>,
    parent_built: Option<B256>,
    depth: u64,
) -> (Option<crate::executed_fields::ExecutedFields>, &'static str) {
    let depth = depth.max(1);
    if let Some(fields) = crate::hotstuff_consensus::ancestor_executed_fields(genesis, parent, depth) {
        return (Some(fields), "ready");
    }
    // The hash the wait below is under: the builder's hash of the parent at
    // depth 1, the grandparent's sealed hash (an alias of its builder hash)
    // at depth 2 -- as `carried_fields_for_seal_untraced` passes them.
    let built = if depth <= 1 { parent_built } else { Some(parent.parent_hash) };
    let on = built.map_or("no_built", |built| crate::executed_fields::missing_half(&built));
    (carried_fields_for_seal_untraced(genesis, parent, parent_built, depth), on)
}

fn carried_fields_for_seal_untraced(
    genesis: &alloy_genesis::Genesis,
    parent: &reth_primitives_traits::SealedHeader<n42_header::N42Header>,
    parent_built: Option<B256>,
    depth: u64,
) -> Option<crate::executed_fields::ExecutedFields> {
    if depth <= 1 {
        return crate::hotstuff_consensus::parent_executed_fields_or_built(
            genesis,
            parent,
            parent_built,
            crate::hotstuff_consensus::PARENT_FIELDS_WAIT,
        );
    }
    crate::hotstuff_consensus::ancestor_executed_fields_or_built(
        genesis,
        parent,
        Some(parent.parent_hash),
        depth,
        crate::hotstuff_consensus::PARENT_FIELDS_WAIT,
    )
}

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

/// Ethereum payload builder
#[derive(Debug, Clone, PartialEq, Eq)]
//pub struct N42PayloadBuilder<Pool, Client, EvmConfig = EthEvmConfig, Cons>
pub struct N42PayloadBuilder<Pool, Client, EvmConfig, Cons> {
    /// Client providing access to node state.
    client: Client,
    /// Transaction pool.
    pool: Pool,
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
    /// Payload builder configuration.
    builder_config: EthereumBuilderConfig,
    /// consensus
    cons: Cons,
    /// The QMDB state this node commits to. `None` means the chain is a
    /// Merkle-Patricia chain and reth computes the root.
    qmdb: Option<QmdbNodeState>,
}

impl<Pool, Client, EvmConfig, Cons> N42PayloadBuilder<Pool, Client, EvmConfig, Cons> {
    /// `N42PayloadBuilder` constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: EthereumBuilderConfig,
        cons: Cons,
    ) -> Self {
        Self {
            client,
            pool,
            evm_config,
            builder_config,
            cons,
            qmdb: None,
        }
    }

    /// Commits built blocks to `qmdb` instead of the Merkle-Patricia trie.
    ///
    /// Must be the same state the engine validator checks against: the block
    /// this builds is validated by this node's own execution layer next, and a
    /// root computed from one forest and checked against another disagrees
    /// even when both are right.
    pub fn with_qmdb(mut self, qmdb: Option<QmdbNodeState>) -> Self {
        self.qmdb = qmdb;
        self
    }
}

// Default implementation of [PayloadBuilder] for unit type
impl<Pool, Client, EvmConfig, Cons> PayloadBuilder
    for N42PayloadBuilder<Pool, Client, EvmConfig, Cons>
where
    EvmConfig: ConfigureEvm<
        Primitives = EthPrimitives,
        NextBlockEnvCtx = NextBlockEnvAttributes,
        BlockAssembler = crate::assembler::N42HeaderAssembler<Client::ChainSpec>,
        BlockExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<Client::ChainSpec>,
    > + 'static,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec>
        + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    Cons: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + 'static,
{
    // upstream: PayloadBuilder::Attributes is now a PayloadAttributes
    type Attributes = EthPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        let started = std::time::Instant::now();
        let parent_hash = args.config.parent_header.hash();
        let parent_gas_limit = args.config.parent_header.gas_limit;
    let block_number = args.config.parent_header.number + 1;
        let result = default_n42_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| {
                // The queue beside the pool, when installed (N42_TX_QUEUE=1):
                // selection is a walk and taking is a pop, against 116-220 ms
                // a build from the pool's ordered sets on a tenure leader.
                match n42_tx_queue::global::<Pool::Transaction>() {
                    // With `N42_INGEST_VERIFY=leader` the queue's senders
                    // are the frames' claims; the wrapper verifies each one
                    // before the build can include it (`claimed_build`).
                    Some(queue) => {
                        release_replaced_own_blocks(&queue, block_number, parent_hash);
                        // `N42_FRAME_BLOCKS=1`: whole frames in arrival
                        // order instead of the walk (`frame_blocks`).
                        let best = crate::frame_blocks::select(&queue, parent_hash, parent_gas_limit);
                        crate::claimed_build::selection(&queue, best)
                    }
                    None => self.pool.best_transactions_with_attributes(attributes),
                }
            },
            self.cons.clone(),
            self.qmdb.clone(),
            None,
            None,
        );
        let outcome = if result.is_ok() { "ok" } else { "error" };
        metrics::histogram!(
            "n42_evm_path_duration_ms",
            "path" => LIVE_EVM_PATH,
            "phase" => "payload_build",
        )
        .record(started.elapsed().as_secs_f64() * 1_000.0);
        metrics::counter!(
            "n42_evm_path_calls_total",
            "path" => LIVE_EVM_PATH,
            "phase" => "payload_build",
            "outcome" => outcome,
        )
        .increment(1);
        result
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        if self.builder_config.await_payload_on_missing {
            MissingPayloadBehaviour::AwaitInProgress
        } else {
            MissingPayloadBehaviour::RaceEmptyPayload
        }
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes, n42_header::N42Header>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        // upstream added execution_cache and state_root_handle; this path shares
        // neither with the engine, so both are None.
        let args = BuildArguments::new(
            Default::default(),
            None,
            None,
            config,
            Default::default(),
            None,
        );

        default_n42_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
            self.cons.clone(),
            self.qmdb.clone(),
            None,
            None,
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// `N42_BUILD_AHEAD_GATE=seal` (two-ahead): a build at `number` replaces the
/// own blocks the queue holds at that height or above -- a block built two
/// ahead that was never proposed (a tenure end, a timeout), held when the
/// build on it started -- and their transactions go back to the lanes before
/// this build selects, instead of when the chain settles the height
/// (`n42_tx_queue::release_replaced_own_blocks`). Nothing under the default
/// gate.
///
/// Also an own block held at the height below under another hash than this
/// build's parent: a sibling of the parent, whose hold landed after the build
/// that replaced it had started (`TxQueue::release_own_blocks_for_build`).
fn release_replaced_own_blocks<T: PoolTransaction>(queue: &n42_tx_queue::TxQueue<T>, number: u64, parent: B256) {
    if !n42_tx_queue::release_replaced_own_blocks() {
        return;
    }
    let offered = queue.release_own_blocks_for_build(number, parent);
    if offered > 0 {
        tracing::info!(
            target: "n42.tx_queue",
            number,
            ?parent,
            offered,
            "own blocks held at or above this build's height were replaced; their transactions are offered again"
        );
    }
}

// The raw payload channel's way in: a build on a block this node built and
// consensus has just sealed, from that build's own post-state, with reth's
// payload service out of the way. See `direct_build`.
impl<Pool, Client, EvmConfig, Cons> crate::direct_build::DirectBuilder
    for N42PayloadBuilder<Pool, Client, EvmConfig, Cons>
where
    EvmConfig: ConfigureEvm<
            Primitives = EthPrimitives,
            NextBlockEnvCtx = NextBlockEnvAttributes,
            BlockAssembler = crate::assembler::N42HeaderAssembler<Client::ChainSpec>,
            BlockExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<Client::ChainSpec>,
        > + Send
        + Sync
        + 'static,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>> + Send + Sync + 'static,
    Cons: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + Send + Sync + 'static,
{
    fn build_on_own(&self, request: crate::direct_build::BuildOnOwnRequest) -> Result<EthBuiltPayload, String> {
        let crate::direct_build::BuildOnOwnRequest { parent, parent_execution, attributes, before_pull } = request;
        let pre_at = std::time::Instant::now();
        OWN_ENTERED.with(|cell| cell.set(Some(pre_at)));
        let parent_hash = parent.hash();
        let parent_gas_limit = parent.gas_limit;
        let block_number = parent.number + 1;
        let parent_built = parent_execution.built_hash();
        // `deferredExecutionDepth` 2 (docs/DEFERRED_DEPTH_2_DESIGN.md item 5):
        // the parent becomes the grandparent of the next build, whose header
        // needs its result by the sealed hash, before the own-block hand-off
        // has filed it there. The pair is in hand only here. Depth 1 notes
        // nothing, so its lookups are what they were.
        if reth_chainspec::qmdb::deferred_execution_depth_at(self.client.chain_spec().genesis(), attributes.timestamp) >= 2 {
            crate::executed_fields::note_built(parent_hash, parent_built);
        }
        let opener = match &parent_execution {
            crate::direct_build::ParentExecution::Ready(execution) => {
                let executed = crate::direct_build::executed_under_seal(&parent, execution);
                crate::direct_build::opener_on_built_parent(self.client.clone(), parent.parent_hash, executed)
            }
            // Started at the parent's seal: its output is waited for when the
            // build opens its state (`N42_BUILD_ON_OUTPUT`).
            crate::direct_build::ParentExecution::Sealed { built_hash } => {
                crate::direct_build::opener_on_sealed_parent(self.client.clone(), parent.clone(), *built_hash)
            }
            // A peer's block this node executed as a follower: its published
            // output (and any unimported ancestors') over the anchor's state
            // (`N42_TENURE_FIRST_ON_OUTPUT`).
            crate::direct_build::ParentExecution::Published { executed, anchor, .. } => {
                crate::direct_build::opener_on_published_parent(self.client.clone(), *anchor, executed.clone())
            }
        };
        // The reads the parent's build cached, filed under the builder's own
        // hash: warm exactly where this block's senders are.
        let cached_reads = self
            .cons
            .get_cached_reads(parent_built)
            .ok()
            .flatten()
            .unwrap_or_default();
        let payload_id = reth_payload_primitives::payload_id(&parent_hash, &attributes);
        let config = PayloadConfig::new(Arc::new(parent), attributes, payload_id);
        let args = BuildArguments::new(cached_reads, None, None, config, Default::default(), None);
        let (evm_config, client, pool, builder_config, cons, qmdb) = (
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            self.cons.clone(),
            self.qmdb.clone(),
        );
        let select_pool = pool.clone();
        let select = move |attributes| match n42_tx_queue::global::<Pool::Transaction>() {
            Some(queue) => {
                // The parent's transactions leave the taken list before this
                // build takes: the hand-off ran beside the setup, and a pull
                // ahead of it would give the parent's block back to the lanes.
                // A hand-off that died drops its sender, which ends the wait.
                if let Some(handed) = before_pull {
                    let at = std::time::Instant::now();
                    let _ = handed.recv();
                    note_handoff_wait(at.elapsed());
                    tracing::debug!(
                        target: "payload_builder",
                        wait_ms = at.elapsed().as_millis() as u64,
                        "the parent's queue hand-off is done; the build pulls"
                    );
                }
                release_replaced_own_blocks(&queue, block_number, parent_hash);
                let best = crate::frame_blocks::select(&queue, parent_hash, parent_gas_limit);
                crate::claimed_build::selection(&queue, best)
            }
            None => select_pool.best_transactions_with_attributes(attributes),
        };
        let unwrap = |outcome: Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>| -> Result<EthBuiltPayload, String> {
            match outcome.map_err(|err| err.to_string())? {
                BuildOutcome::Better { payload, .. } | BuildOutcome::Freeze(payload) => Ok(payload),
                BuildOutcome::Aborted { .. } => Err("the build was aborted".to_owned()),
                BuildOutcome::Cancelled => Err("the build was cancelled".to_owned()),
            }
        };
        if !seal_first() {
            return unwrap(default_n42_payload(
                evm_config, client, pool, builder_config, args, select, cons, qmdb, Some(opener), None,
            ));
        }
        // Sealed before it finishes (`EarlySeal`): the build runs on a thread
        // of its own, the sealed payload comes back on the channel, and the
        // thread finishes the block behind it. A build the builder could not
        // seal early (the block not full, no gate) ends the ordinary way and
        // the channel closes without a payload.
        let (sealed_tx, sealed_rx) = std::sync::mpsc::sync_channel::<EthBuiltPayload>(1);
        let early = EarlySeal {
            hook: Box::new(move |payload| {
                let _ = sealed_tx.send(payload);
            }),
            parent_built: Some(parent_built),
        };
        let pre_ms = pre_at.elapsed().as_millis() as u64;
        let started = std::time::Instant::now();
        let worker = std::thread::Builder::new()
            .name("build-on-own".into())
            .spawn(move || {
                default_n42_payload(
                    evm_config, client, pool, builder_config, args, select, cons, qmdb, Some(opener), Some(early),
                )
            })
            .map_err(|err| format!("build thread: {err}"))?;
        // Whichever comes first: the early payload, or the build's end.
        loop {
            match sealed_rx.recv_timeout(std::time::Duration::from_millis(2)) {
                Ok(payload) => {
                    let number = payload.block().header().number;
                    let sealed_ms = started.elapsed().as_millis() as u64;
                    if payload.block().body().transactions.len() >= 1000 {
                        tracing::info!(target: "payload_builder", number, pre_ms, sealed_ms, "build on the sealed block answered on the early seal");
                    }
                    // The thread finishes the block; its outcome is a log
                    // line, its failure the handoff's problem to report.
                    std::thread::Builder::new()
                        .name("build-on-own-finish".into())
                        .spawn(move || match worker.join() {
                            Ok(Ok(_)) => debug!(target: "payload_builder", number, sealed_ms, "sealed early; finished behind the seal"),
                            Ok(Err(err)) => warn!(target: "payload_builder", number, %err, "sealed early; the finish behind the seal FAILED"),
                            Err(_) => warn!(target: "payload_builder", number, "sealed early; the finish behind the seal panicked"),
                        })
                        .ok();
                    return Ok(payload);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if worker.is_finished() {
                        // Not sealed early (or the seal came with the end):
                        // one more look at the channel, then the outcome.
                        if let Ok(payload) = sealed_rx.try_recv() {
                            return Ok(payload);
                        }
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        unwrap(worker.join().map_err(|_| "the build thread panicked".to_owned())?)
    }
}

/// Hands the sealed block to the early seal's hook as the build's payload
/// and returns, for the build's own return value, a stand-in under the same
/// sealed header with an empty body and no senders.
///
/// The build's thread finishes the block behind the seal, files it
/// (`built_executions::complete`), and only returns -- after the phases line,
/// the cached reads' copy and the drop of every local of a 200k-transaction
/// build -- well after the own-block hand-off has woken on that `complete`.
/// A full payload held across that tail was the outside holder that made
/// the hand-off's move of the body fail (`moved_body=false`) on most loaded
/// blocks and cost it a copy of the body and senders (`clone_ms` 16-43 ms,
/// loop351 af): of the hand-offs that began before the build's phases line,
/// 326 of 334 could not move the body. The stand-in holds no reference to
/// the block. The build's return is read only when the hook never ran
/// (`N42PayloadBuilder::build_on_own` answers with the hook's payload
/// whenever there is one), so no reader sees the stand-in.
fn hand_out_early(
    recovered: &Arc<reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>>,
    fees: U256,
    hook: impl FnOnce(EthBuiltPayload),
) -> EthBuiltPayload {
    hook(EthBuiltPayload::new(Arc::clone(recovered), fees, None, None));
    let stand_in = reth_primitives_traits::RecoveredBlock::new_sealed(
        SealedBlock::from_sealed_parts(recovered.clone_sealed_header(), Default::default()),
        Vec::new(),
    );
    EthBuiltPayload::new(Arc::new(stand_in), fees, None, None)
}

/// Where the builder is, for the watchdog: `parent_number << 8 | stage`, 0
/// when no build is running. Stages: 1 setup, 2 selecting, 3 executing,
/// 4 finishing, 5 sealing, 6 remembering, 7 payload.
pub static BUILD_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Names the stages of [`BUILD_STAGE`].
pub const BUILD_STAGES: [&str; 8] = ["idle", "setup", "selecting", "executing", "finishing", "sealing", "remembering", "payload"];

struct BuildStage(u64);

impl BuildStage {
    fn at(&self, stage: u64) {
        BUILD_STAGE.store((self.0 << 8) | stage, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for BuildStage {
    fn drop(&mut self) {
        BUILD_STAGE.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}


/// The hook of a build that seals before it finishes
/// (docs/PHASE_D_DEFERRED_EXECUTION.md section 13): under deferred execution
/// the header carries the parent's execution, so once the parallel step has
/// filled the block the header needs only the transactions root and the
/// block can be sealed and handed out while its state is folded, finished and
/// rooted behind it. `hook` receives the sealed payload; `parent_built` is
/// the parent's hash under the builder (the parent may be finishing behind
/// its own seal: its fields and its tree arrive under that hash).
pub struct EarlySeal {
    /// Receives the sealed payload, once.
    pub hook: Box<dyn FnOnce(EthBuiltPayload) + Send>,
    /// The parent's hash under the builder, when the parent was built here.
    pub parent_built: Option<B256>,
}

impl std::fmt::Debug for EarlySeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EarlySeal").field("parent_built", &self.parent_built).finish()
    }
}

/// Whether the build on the sealed block seals before it finishes (see
/// [`EarlySeal`]): on unless `N42_SEAL_FIRST=0` (adopted after loop137-140,
/// `NATIVE_FLEET7.md`); a precondition is the chain's
/// `deferredExecutionTime`, checked per block, so a chain before the fork
/// builds as before.
pub fn seal_first() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_SEAL_FIRST", true))
}

/// `N42_SEAL_AT_EXEC=1` (plan v6 attempt G2, `FLEET7_PLAN_V4.md` 6.6): a
/// block that seals early is sealed and proposed right after the parallel
/// step's execution and the collection of its body, and the fold -- the
/// graft, the beneficiary's fee credit, the withdrawal put-back, the
/// receipts, the skipped senders' diagnosis and the give-backs to the
/// queue -- runs behind the proposal, ahead of the finish that was behind
/// it already. The header needs of the block's own execution only its
/// transaction set and transactions root; the rest it carries is the
/// parent's. Off by default.
pub fn seal_at_exec() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_SEAL_AT_EXEC", false))
}

/// `N42_SHARDS_READY_FIRST=1` (docs/SEALED_AT_FLOOR.md candidate 1): on a
/// block sealed at the parallel step's end (`N42_SEAL_AT_EXEC=1`), the
/// shards are filed (`shards_ready`, what the child's open waits for) before
/// the lookahead and deferred candidates are given back to the queue and the
/// puller is dropped, and the pulled set (with the step's warm layer and
/// transfer keys) is freed on the `n42-built-free` thread after them instead
/// of at the step's scope end. Nothing that reads the shards reads the queue:
/// the child's selection precedes its open, and the merge and the root read
/// only the shards. Off by default; read and logged once.
pub fn shards_ready_first() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let on = n42_env::flag("N42_SHARDS_READY_FIRST", false);
        tracing::info!(target: "payload_builder", shards_ready_first = on, "N42_SHARDS_READY_FIRST");
        on
    })
}

/// `N42_FREEZE_AFTER_SEAL=1` (`docs/SHARED_EXECUTION_SCOPE.md` 15): with
/// `N42_SEAL_AT_EXEC=1` and the output shards, the shards' freeze (the index's
/// conflict sums, and under `N42_LIVE_INDEX_DEFER=1` the shards the batches
/// left to it: `index_ms` 4-5 ms, 13 with the defer) runs on a thread of its
/// own from the batches' end, beside the commit and the seal, and is joined
/// behind the seal where the graft first reads the shards -- beside the
/// receipts job. The seal reads the body, the transactions root and the
/// parent's fields, none of which the freeze touches; the frozen shards are
/// the same call on the same input either way. Off by default.
pub fn freeze_after_seal() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_FREEZE_AFTER_SEAL", false))
}

/// `N42_ROOT_OPS_AHEAD=1` (`docs/SHARED_EXECUTION_SCOPE.md` 15): with the
/// output shards on a block that seals early, the shards' QMDB leaf
/// operations are encoded and sorted on a thread of their own as soon as the
/// shards are final (the graft's end), beside the receipts and the
/// executor's finish; the root job behind the seal then encodes only the
/// residual's few accounts and merges them in (`OpsAhead::finish`), instead
/// of encoding the block's ~190,000 accounts after the finish. The same
/// operations either way (`operations_ahead_finished_equal_the_whole_views`).
/// Off by default.
pub fn root_ops_ahead() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_ROOT_OPS_AHEAD", false))
}

/// `N42_ROOT_OPS_BEFORE_GATE=1` (`docs/ROOT_FIELDS_RACE.md` option B): on
/// the output-shard path the leader's QMDB root job starts before
/// `rename_parent` waits for the parent's fields, and does there what reads
/// nothing of the parent: the operations' finish (the residual's accounts
/// merged into the operations encoded ahead, or the whole encode) and their
/// sort and leaf hashes (`LeafHashes::of`, which the leased compute would
/// otherwise take before the lease). Only the tree's apply at the parent
/// waits for the gate. The same operations and root either way. Off by default.
pub fn root_ops_before_gate() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_ROOT_OPS_BEFORE_GATE", false))
}

/// The shards' operations encoded ahead ([`root_ops_ahead`]), and when they
/// were done.
type OpsAheadJob = std::thread::JoinHandle<(n42_qmdb_reth::OpsAhead, std::time::Instant)>;

/// How the root job used the operations encoded ahead: its wait for them,
/// the finish (the residual's encoded and merged in), and when they were
/// done. All zero when it encoded the whole view itself.
#[derive(Debug, Default, Clone, Copy)]
struct OpsAheadUse {
    waited: std::time::Duration,
    finish: std::time::Duration,
    done_at: Option<std::time::Instant>,
    /// [`root_ops_before_gate`]: the job's work before the parent-fields
    /// gate (the operations' finish, sort and leaf hashes), and how long it
    /// then waited for the gate. Zero with the flag off.
    pre_gate: std::time::Duration,
    gate_wait: std::time::Duration,
}

/// The output shards frozen on a thread of their own ([`freeze_after_seal`]).
type LateFreeze = crate::output_shards::FreezeHandle;


/// Starts the freeze of `shards` on a thread of its own
/// ([`crate::output_shards::OutputShards::freeze_on_thread`]).
fn spawn_freeze(shards: crate::output_shards::OutputShards) -> Result<LateFreeze, Option<Box<crate::output_shards::OutputShards>>> {
    shards.freeze_on_thread().inspect_err(|_| {
        tracing::debug!(target: "payload_builder", "no thread for the freeze; frozen before the seal");
    })
}

/// `N42_STATE_AFTER_PULL=1` (plan v6 attempt G3, `FLEET7_PLAN_V4.md` 6.7):
/// with the parallel build and the puller on, the builder opens the parent's
/// state -- and applies the pre-execution changes, the one thing before the
/// execution that reads it -- after the parallel step's pull, prep and
/// partition rather than at the build's start. A chained build started at
/// its parent's seal (`N42_BUILD_ON_OUTPUT=1`) waits in that open for the
/// parent's `StateReady`; the pull, the prep and the partition need only the
/// queue, the parent header and the block environment, and now run during
/// that wait. Off by default; with it off, or on any build that does not
/// take the parallel step, the state is opened where it always was.
pub fn state_after_pull() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_STATE_AFTER_PULL", false))
}

/// The transaction's and the account's nonce when evm2 refused `error` for a
/// nonce mismatch (`HandlerError::InvalidNonce`, which reth's Ethereum
/// executor exposes through `InvalidTxError::as_any`).
fn invalid_nonce(error: &dyn reth_evm::execute::InvalidTxError) -> Option<(u64, u64)> {
    match error.as_any().downcast_ref::<evm2::registry::HandlerError>()? {
        evm2::registry::HandlerError::InvalidNonce { expected, got } => Some((*got, *expected)),
        _ => None,
    }
}

/// The builder's database over the parent's state: the provider in `slot`,
/// opened through `open` on the first read if nothing opened it before
/// (`N42_STATE_AFTER_PULL=1` opens it explicitly, timed, before the
/// parallel step's batches; a read ahead of that point would open it here).
/// With the flag off the slot is filled at the build's start and every read
/// is the provider's, as it was with `StateProviderDatabase` directly.
struct LazyParentDb<'a> {
    slot: &'a std::cell::OnceCell<reth_storage_api::StateProviderBox>,
    open: &'a dyn Fn() -> Result<reth_storage_api::StateProviderBox, reth_storage_api::errors::ProviderError>,
}

impl std::fmt::Debug for LazyParentDb<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyParentDb").field("opened", &self.slot.get().is_some()).finish()
    }
}

impl LazyParentDb<'_> {
    fn provider(&self) -> Result<&reth_storage_api::StateProviderBox, reth_storage_api::errors::ProviderError> {
        if let Some(provider) = self.slot.get() {
            return Ok(provider);
        }
        let opened = (self.open)()?;
        Ok(self.slot.get_or_init(|| opened))
    }
}

impl evm2::evm::Database for LazyParentDb<'_> {
    type Error = reth_storage_api::errors::ProviderError;

    fn get_account(&mut self, address: &alloy_primitives::Address) -> Result<Option<evm2::evm::AccountInfo>, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<evm2::bytecode::Bytecode, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &alloy_primitives::Address, index: &U256) -> Result<U256, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).get_storage(address, index)
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).get_block_hash(number)
    }
}

/// Whether the body the parallel step left is the pulled candidate set in
/// pull order, so that a transactions root computed over the pulled set
/// ahead of the execution is the body's root.
///
/// By construction it is whenever nothing was skipped: slot `i` of the
/// parallel step holds candidate `i` and the body is the filled slots in
/// slot order (`execute_for_build_run`). This is the cheap check that the
/// construction still holds: the lengths, and the first, middle and last
/// hashes.
fn body_matches_pull<A, P>(body: &[A], pulled: &[P], body_hash: impl Fn(&A) -> B256, pulled_hash: impl Fn(&P) -> B256) -> bool {
    if body.len() != pulled.len() {
        return false;
    }
    let Some(last) = body.len().checked_sub(1) else {
        return true;
    };
    [0, last / 2, last].into_iter().all(|i| body_hash(&body[i]) == pulled_hash(&pulled[i]))
}


/// The consensus transaction inside a pooled one, by reference.
fn pooled_consensus<P: PoolTransaction<Consensus = TransactionSigned>>(
    tx: &reth_transaction_pool::ValidPoolTransaction<P>,
) -> &TransactionSigned {
    tx.transaction.consensus_ref().into_inner()
}

/// A candidate's (sender, recipient) when it is a plain transfer the parallel
/// step takes -- the prep's check -- and `None` otherwise.
fn transfer_key<P: PoolTransaction<Consensus = TransactionSigned>>(
    tx: &reth_transaction_pool::ValidPoolTransaction<P>,
) -> Option<(alloy_primitives::Address, alloy_primitives::Address)> {
    if tx.transaction.gas_limit() != MIN_TRANSACTION_GAS {
        return None;
    }
    plain_transfer_key(tx)
}

/// [`transfer_key`] whatever the gas limit: the take of a block under gov5's
/// Amsterdam execution, where a transfer creating its recipient needs its
/// EIP-8037 state gas on top of the 21,000 (`docs/AMSTERDAM_PARALLEL_STEP.md`).
fn plain_transfer_key<P: PoolTransaction<Consensus = TransactionSigned>>(
    tx: &reth_transaction_pool::ValidPoolTransaction<P>,
) -> Option<(alloy_primitives::Address, alloy_primitives::Address)> {
    let inner = &tx.transaction;
    (inner.input().is_empty()
        && !inner.is_create()
        && inner.access_list().is_none_or(|list| list.is_empty())
        && !inner.is_eip4844()
        && !inner.is_eip7702())
    .then(|| (tx.sender(), inner.to().unwrap_or_default()))
}


/// The plan-ahead hook's work on evm2 (`N42_PLAN_AHEAD_BODY=1`, F5c): the
/// candidates in plan order, their transfer keys and hashes and the
/// partition at the beneficiary this node builds for, made on the plan
/// body's own pool -- what the evm2 parallel step reads -- and the body the
/// evm2 seal lays its header over (F5g items 3-4): the transactions and
/// their senders, and with `N42_PLAN_AHEAD_PARTS=1` the frame layout and
/// transactions root of the hashes on this plan. `None` when not every
/// candidate is a plain transfer.
fn make_prepared_build<P: PoolTransaction<Consensus = TransactionSigned>>(
    segments: &[(n42_tx_queue::FrameTxs<P>, usize)],
    plan: &n42_tx_queue::FramePlan,
) -> Option<crate::frame_blocks::PreparedBuild<P>> {
    use rayon::prelude::*;
    let at = std::time::Instant::now();
    let pool = crate::parallel_transfer::plan_body_pool();
    let parts: Vec<Vec<Arc<reth_transaction_pool::ValidPoolTransaction<P>>>> = pool.install(|| {
        segments.par_iter().map(|(txs, taken)| txs.get(..*taken).map_or_else(Vec::new, <[_]>::to_vec)).collect()
    });
    let mut cands = Vec::with_capacity(parts.iter().map(Vec::len).sum());
    for part in parts {
        cands.extend(part);
    }
    if cands.is_empty() {
        return None;
    }
    let keys = pool.install(|| cands.par_iter().map(|tx| transfer_key(tx)).collect::<Option<Vec<_>>>())?;
    #[allow(clippy::type_complexity)]
    let (transactions, (senders, hashes)): (Vec<TransactionSigned>, (Vec<alloy_primitives::Address>, Vec<B256>)) = pool
        .install(|| cands.par_iter().with_min_len(1024).map(|tx| (pooled_consensus(tx).clone(), (tx.sender(), *tx.hash()))).unzip());
    let groups = crate::frame_blocks::noted_beneficiary().and_then(|beneficiary| {
        crate::parallel_transfer::partition_by_sender(&keys, beneficiary).ok().map(|groups| (beneficiary, groups))
    });
    // `N42_PLAN_AHEAD_PARTS=1`: the body's frame layout and transactions
    // root, found here with the plan rather than at the seal.
    let root_ahead = (crate::frame_blocks::plan_ahead_parts() && crate::frame_blocks::active())
        .then(|| pool.install(|| crate::frame_blocks::root_ahead(plan, &hashes)))
        .flatten();
    Some(crate::frame_blocks::PreparedBuild {
        segments: segments.to_vec(),
        cands,
        keys,
        transactions,
        senders,
        hashes,
        groups,
        made_us: at.elapsed().as_micros() as u64,
        root_ahead,
    })
}

/// Installs the plan-ahead hook on the queue once (`N42_PLAN_AHEAD_BODY=1`).
fn install_plan_ahead_body<P: PoolTransaction<Consensus = TransactionSigned>>(queue: &n42_tx_queue::TxQueue<P>) {
    if queue.has_plan_ahead_hook() {
        return;
    }
    queue.set_plan_ahead_hook(Arc::new(|segments: &[(n42_tx_queue::FrameTxs<P>, usize)], plan: &n42_tx_queue::FramePlan| {
        make_prepared_build(segments, plan).map(|made| Box::new(made) as n42_tx_queue::PreparedBody)
    }));
}





/// Whether a block's receipts are built straight from the slots in two
/// passes on the receipts pool (`N42_RECEIPTS_FUSED=1`, off by default):
/// the per-chunk gas, then the receipts with their cumulative gas, instead
/// of the serial walks for the references and the cumulative gas before the
/// parallel map. Moving the receipts to the 64-thread build pool cut them
/// only 8.7 -> 8.0 ms (10.200): the serial walks are the suspect.
fn receipts_fused() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_RECEIPTS_FUSED", false))
}




/// Where the thread merging a block's revert set (`N42_ANSWER_BEFORE_REVERTS`)
/// is sent the promise to fill, once the execution it belongs to exists.
type LateRevertsTx = std::sync::mpsc::SyncSender<n42_deferred_reverts::LateReverts>;

/// `N42_ANSWER_BEFORE_REVERTS`: starts the merge of the block's complete
/// revert set (`FrozenShards::late_reverts`: the residual's, the shards', then
/// the graft's `graft`) on a thread of its own, beside the account half; it
/// fills the promise it is sent ([`LateRevertsTx`]) and ends. `graft` comes
/// back with `None` when no thread could be had: the caller merges whole.
fn spawn_late_reverts(
    shards: &Arc<crate::output_shards::FrozenShards>,
    residual: &reth_trie::bundle_state::BundleState,
    graft: Vec<(alloy_primitives::Address, reth_trie::bundle_state::AccountRevert)>,
    pool: Option<&'static rayon::ThreadPool>,
) -> (Vec<(alloy_primitives::Address, reth_trie::bundle_state::AccountRevert)>, Option<LateRevertsTx>) {
    spawn_late_reverts_with(shards, residual, graft, pool, OsThread)
}

/// How a helper thread is started: a named OS thread in production
/// ([`OsThread`]); a test passes one that fails, to reach the fallback.
trait SpawnThread {
    /// Starts `work` on a thread named `name`, detached.
    fn spawn<F: FnOnce() + Send + 'static>(self, name: &str, work: F) -> std::io::Result<()>;
}

/// [`SpawnThread`] by `std::thread::Builder`.
#[derive(Debug, Clone, Copy)]
struct OsThread;

impl SpawnThread for OsThread {
    fn spawn<F: FnOnce() + Send + 'static>(self, name: &str, work: F) -> std::io::Result<()> {
        std::thread::Builder::new().name(name.into()).spawn(work).map(drop)
    }
}

/// [`spawn_late_reverts`] with the thread started by `spawner`.
fn spawn_late_reverts_with(
    shards: &Arc<crate::output_shards::FrozenShards>,
    residual: &reth_trie::bundle_state::BundleState,
    graft: Vec<(alloy_primitives::Address, reth_trie::bundle_state::AccountRevert)>,
    pool: Option<&'static rayon::ThreadPool>,
    spawner: impl SpawnThread,
) -> (Vec<(alloy_primitives::Address, reth_trie::bundle_state::AccountRevert)>, Option<LateRevertsTx>) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<n42_deferred_reverts::LateReverts>(1);
    let shards = Arc::clone(shards);
    let block_reverts = residual.reverts.clone();
    let cell = Arc::new(std::sync::Mutex::new(Some(graft)));
    let taken = Arc::clone(&cell);
    let spawned = spawner.spawn("n42-merge-late-reverts", move || {
        n42_core_layout::background_thread();
        let graft = taken.lock().ok().and_then(|mut cell| cell.take()).unwrap_or_default();
        let at = std::time::Instant::now();
        let (reverts, size) = shards.late_reverts(block_reverts, graft, pool);
        let merged_us = at.elapsed().as_micros() as u64;
        // The promise comes once the execution exists; a build that ended
        // before that sends none, and nothing is owed.
        if let Ok(promise) = rx.recv() {
            let waited_us = (at.elapsed().as_micros() as u64).saturating_sub(merged_us);
            promise.fill(reverts, size);
            tracing::debug!(target: "payload_builder", merged_us, waited_us, size, "late revert set filled");
        }
    });
    match spawned {
        Ok(_) => (Vec::new(), Some(tx)),
        Err(err) => {
            tracing::warn!(target: "payload_builder", %err, "no thread for the late revert set; the merge runs whole");
            let back = cell.lock().ok().and_then(|mut cell| cell.take()).unwrap_or_default();
            (back, None)
        }
    }
}

/// The error of a step that runs after the block was proposed
/// (`N42_SEAL_AT_EXEC=1`): the store's waiters are told at once and the
/// failure is loud, as for the finish behind the seal. `sealed` is the
/// proposed block's hash and number, `None` when nothing was proposed yet
/// (the error then goes back as it always did).
/// The leader's merge of its output shards into the block's one bundle, as
/// its thread ran it behind the fields' publication.
#[derive(Debug, Default, Clone, Copy)]
struct LeaderMerge {
    /// The merge's start on its thread.
    started: Option<std::time::Instant>,
    /// Its end, before `StateReady` is filed.
    ended: Option<std::time::Instant>,
    /// `StateReady` filed with the merged bundle.
    state_ready: Option<std::time::Instant>,
    /// The halves ([`crate::output_shards::FrozenShards::merged_timed`]).
    split: crate::output_shards::MergeSplit,
    /// The graft's own reverts appended after the merge, us.
    tail_us: u64,
    /// The threads the merge ran on.
    threads: u32,
    /// The merged bundle's accounts.
    accounts: usize,
    /// The merged bundle's reverts.
    reverts: usize,
    /// `N42_MERGE_AT_SHARDS_READY`: the merge ran from `shards_ready` on
    /// the merge pool.
    early: bool,
    /// How long the merger thread (spawned after the fields' publication)
    /// waited for the early merge to end, us: 0 when it had ended.
    join_wait_us: u64,
    /// `N42_ANSWER_BEFORE_REVERTS`: the output's registration between the
    /// merge's end and `StateReady` (the registry lock's wait, its hold,
    /// the eviction's free under it, the entries evicted).
    register: n42_deferred_reverts::RegisterTiming,
    /// The `built_executions::state_ready` call, us (the store's lock, and
    /// the drop of the entry's output shards under it).
    state_ready_call_us: u64,
}

fn failed_after_seal(sealed: Option<(B256, u64)>, err: PayloadBuilderError) -> PayloadBuilderError {
    if let Some((block_hash, number)) = sealed {
        crate::built_executions::fail(block_hash);
        tracing::error!(target: "payload_builder", number, %err, "the fold behind the seal FAILED; the block was proposed already");
    }
    err
}

/// How short of the gas limit the parallel step may leave a block and still
/// seal it early: `block_gas_limit / N42_SEAL_SHORTFALL_DIV`, 0 to require
/// the block to be full to the last transaction.
///
/// The parallel step leaves out a candidate its transfer path refused and
/// every later candidate of that sender with it, so a block it filled is
/// 21,000 gas short per skipped candidate and the old exact test
/// (`gas left < MIN_TRANSACTION_GAS`) called it not full. One stuck sender
/// then cost the early seal for a whole tenure: loop207 Pb node3 built 63
/// blocks with `par_skipped=256-512`, all through the ordinary finish, and
/// proposed at p50 185 / p90 315 ms against 80-87 for the same node and
/// tenure in the legs beside it. The remainder is not lost -- it goes back
/// to the queue and the next block takes it -- so the trade is under 1.6%
/// of one block's occupancy against ~100 ms of proposal on a 250 ms cycle.
fn seal_shortfall(block_gas_limit: u64) -> u64 {
    static DIV: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let div = *DIV.get_or_init(|| {
        n42_env::parse("N42_SEAL_SHORTFALL_DIV", 64)
    });
    block_gas_limit.checked_div(div).unwrap_or(0)
}

/// `N42_BUILD_REFUSE_STALE_PARENT=1`: a build whose parent is below what
/// the queue has been pruned through answers "parent stale" instead of
/// pulling a block's worth of candidates it cannot use.
///
/// Off, because the reading it acts on has not been seen to fire. loop213
/// Pe node3 built 26 empty blocks over a queue of 383,412 and every one of
/// them was a chained build on its own previous block, canonical and
/// committed 100-200 ms earlier -- the parent was the head, not behind it.
/// The detector below is on and counted so the next leg can say whether
/// the case exists at all; the refusal waits for a leg that shows it.
fn refuse_stale_parent() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_REFUSE_STALE_PARENT").is_ok_and(|v| v == "1"))
}

/// `N42_BUILD_DECLINE_EMPTY_STEP=0` turns off [`after_parallel_step`] (the
/// serial loop always runs); on by default.
fn decline_empty_step() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_BUILD_DECLINE_EMPTY_STEP", true))
}

/// The fewest skipped candidates that make an empty parallel step a verdict
/// on the build rather than a shallow queue.
const DECLINE_MIN_SKIPPED: usize = 1000;

/// What a build does after a parallel step that skipped much of what it was
/// offered (defect 15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterParallelStep {
    /// The serial loop runs as it always did.
    Serial,
    /// The serial loop is not entered: the block is finished with what the
    /// parallel step built, the skipped candidates go back to the queue.
    Finish(&'static str),
    /// The build answers `Aborted` at once, everything taken given back.
    Decline(&'static str),
}

/// [`after_parallel_step`] under `N42_BUILD_DECLINE_EMPTY_STEP`.
fn after_parallel_step_now(
    par_txs: u64,
    par_skipped: usize,
    par_budget: usize,
    direct: bool,
    height_decided: bool,
) -> AfterParallelStep {
    after_parallel_step(decline_empty_step(), par_txs, par_skipped, par_budget, direct, height_decided)
}

/// Whether the serial loop may take over what the parallel step skipped.
///
/// It re-executes every skipped candidate one at a time (~55 us each), and
/// on loop237 it did exactly that for the whole skipped set every time:
/// `fast == par_skipped` on all twelve builds with `loop_ms` over a second,
/// 9.0-10.6 s where the step built nothing or 6-8k of a block. A skip that
/// large says the step's view of the parent is wrong, not the queue.
///
/// `par_budget` is what the step asked the queue for (a block's worth at its
/// start), `direct` a build on an own block from its own post-state
/// (`direct_build`: the build ahead on the sealed block, the chain), and
/// `height_decided` whether the chain has committed a block at this height,
/// i.e. the parent is no longer the head. The ordinary build (`try_build`:
/// not direct, height open) always keeps its serial loop -- it is the path
/// the consensus client falls back to when a direct build declines.
fn after_parallel_step(
    enabled: bool,
    par_txs: u64,
    par_skipped: usize,
    par_budget: usize,
    direct: bool,
    height_decided: bool,
) -> AfterParallelStep {
    if !enabled || par_skipped < DECLINE_MIN_SKIPPED {
        return AfterParallelStep::Serial;
    }
    if height_decided {
        return AfterParallelStep::Decline("the height is decided; the parent is no longer the head");
    }
    // Half a block or more skipped on a build on an own block.
    if direct && par_budget > 0 && par_skipped.saturating_mul(2) >= par_budget {
        if par_txs == 0 {
            return AfterParallelStep::Decline("a build on an own block executed nothing of a block's worth");
        }
        return AfterParallelStep::Finish("a build on an own block skipped most of a block's worth");
    }
    AfterParallelStep::Serial
}

// Thread-local: how long this thread's build waited in its selector for the
// parent's queue hand-off (`BuildOnOwnRequest::before_pull`), microseconds;
// reset at the build's selection and reported as `start_handoff_ms`.
thread_local! {
    static HANDOFF_WAIT_US: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}


/// What a build's `state_wait_ms` was on: the largest of the named waits
/// ([`crate::direct_build::open_wait`]), or `open` when the rest of the wait
/// -- what no named wait covers, a millisecond or more -- is larger than
/// each; `none` for no wait. Since loop333 the open's own two costs are named
/// (`layer_release`, `provider_open`), so `open` is what is left after them.
fn state_wait_label(total_us: u64, on: &crate::direct_build::open_wait::OpenWait) -> &'static str {
    let named = on.named_us();
    let rest = total_us.saturating_sub(named.iter().map(|(us, _)| us).sum());
    if rest >= 1000 && named.iter().all(|(us, _)| rest > *us) {
        return "open";
    }
    on.label()
}

/// The leader's seal-first seal of `number`: when its hook answered. A
/// chained build on it reads the road from there to its own entry and start
/// (`post_seal`, `next_start_gap_ms`, `prev_seal_to_*_us`): what lies between
/// one block's seal and the next build's first step -- the chain header's and
/// the request's trips and the payload service's set-up -- is on the leader's
/// cycle but in no build's own timers (docs/BREAKTHROUGH_DESIGN.md 10.32).
fn note_sealed(number: u64) {
    crate::post_seal::note(number, crate::post_seal::Mark::Sealed);
}

thread_local! {
    /// When this thread's chained build entered `build_on_own`, for
    /// `next_entry_gap_ms`; taken at the build's start.
    static OWN_ENTERED: std::cell::Cell<Option<std::time::Instant>> = const { std::cell::Cell::new(None) };
}

/// Records the selector's wait for the parent's queue hand-off on this
/// thread (see [`HANDOFF_WAIT_US`]).
fn note_handoff_wait(waited: std::time::Duration) {
    HANDOFF_WAIT_US.with(|cell| cell.set(cell.get().saturating_add(waited.as_micros() as u64)));
}

/// Whether a build for a height the chain has already committed is
/// cancelled before it takes anything from the queue;
/// `N42_BUILD_SKIP_DECIDED=0` turns it off.
///
/// Such a build cannot produce a payload anyone will ask for -- the height
/// is decided -- and what it does instead is harmful. loop214 Pd node2 ran
/// three at once for heights 637-639 while 635-638 were already committed:
/// each took a block's worth out of the queue, each stood on a block of its
/// own that consensus replaced, and each then refused a sender's run as
/// behind the chain on the strength of that state. Twenty-nine senders were
/// left with their account at nonce 0 and their lane starting at 64, 192 or
/// 320, and the node built eighteen empty blocks over a queue of 400,000.
fn skip_decided_builds() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_BUILD_SKIP_DECIDED", true))
}

/// At most one line a second per call site, so a defect that repeats every
/// build does not become a line every 250 ms.
fn say_once_a_second(last: &std::sync::atomic::AtomicU64) -> bool {
    use std::sync::atomic::Ordering;
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let now = START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64;
    let seen = last.load(Ordering::Relaxed);
    // `seen == 0` is "never said": the first call must print, and it did
    // not while `now` was still under a second (the decided-height line
    // never appeared in six legs where it fired).
    (seen == 0 || now.saturating_sub(seen) >= 1_000)
        && last.compare_exchange(seen, now.max(1), Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

/// The trailing fields gov5's schedule puts on a header at its time
/// (`docs/HEADER_FIELD_PARITY.md`): from Glamsterdam the slot number, equal to
/// the block number; from MobileAnchor and Glamsterdam the registry root the
/// leader named in its attributes, which is returned for the sealed
/// [`n42_header::N42Header`]. The header is rebuilt here from the assembled
/// block's fields one by one, so whatever the assembler stamped beyond them is
/// set again rather than lost. A gated header without a named root is refused.
fn stamp_gov5_tail(
    genesis: &alloy_genesis::Genesis,
    header: &mut alloy_consensus::Header,
    named_root: Option<B256>,
) -> Result<Option<B256>, PayloadBuilderError> {
    let rules = crate::hotstuff_consensus::header_tail_rules(genesis, header.timestamp);
    if rules.slot_number {
        header.slot_number = Some(header.number);
    }
    crate::assembler::registry_root_for_header(rules.mobile_registry_root, named_root).ok_or_else(|| {
        PayloadBuilderError::other(std::io::Error::other(format!(
            "a header at {} carries mobileRegistryRoot, and the payload attributes named none",
            header.timestamp
        )))
    })
}

/// Constructs an Ethereum transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Ethereum client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
#[allow(clippy::too_many_arguments)] // hot-path builder entry; the argument list is kept
pub fn default_n42_payload<EvmConfig, Client, Pool, F, Cons>(
    evm_config: EvmConfig,
    client: Client,
    pool: Pool,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<EthPayloadAttributes, EthBuiltPayload>,
    best_txs: F,
    cons: Cons,
    qmdb: Option<QmdbNodeState>,
    // The parent's post-state, when it is not what the client finds by the
    // parent's hash: a build on an own block the engine has not imported yet
    // (`direct_build`). `None` reads the client's state at the parent.
    parent_state: Option<crate::direct_build::ParentStateOpener>,
    // Seals before the finish when it can (`EarlySeal`).
    mut early_seal: Option<EarlySeal>,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<
        Primitives = EthPrimitives,
        NextBlockEnvCtx = NextBlockEnvAttributes,
        BlockAssembler = crate::assembler::N42HeaderAssembler<Client::ChainSpec>,
        BlockExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<Client::ChainSpec>,
    > + 'static,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
    Cons: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + 'static,
{
    // From the very top: the state provider and the cached reads are fetched
    // before anything is executed, and were outside every earlier timing.
    let build_started = std::time::Instant::now();
    let own_entered = OWN_ENTERED.with(std::cell::Cell::take);
    let BuildArguments {
        mut cached_reads,
        config,
        cancel,
        best_payload,
        // upstream additions this builder does not use
        execution_cache: _,
        state_root_handle: _,
    } = args;
    let PayloadConfig {
        parent_header,
        // upstream additions: the payload id moved off the attributes onto the config
        parent_block_info: _,
        payload_id,
        attributes,
    } = config;

    let parent_hash_for_state = parent_header.hash();
    // The parent's road from its seal to this build (`post_seal`): read by
    // this build's phases line as `prev_seal_to_*_us`. Recorded here, at
    // the start, because the line is written long after the parent's seal
    // has been overwritten by this block's own (`next_start_gap_ms` read 0
    // on every build until this moved here).
    crate::post_seal::note_at(parent_header.number, crate::post_seal::Mark::ChildStarted, build_started);
    if let Some(entered) = own_entered {
        crate::post_seal::note_at(parent_header.number, crate::post_seal::Mark::ChildEntered, entered);
    }
    let open_parent_state = || -> Result<reth_storage_api::StateProviderBox, reth_storage_api::errors::ProviderError> {
        match &parent_state {
            Some(open) => open(),
            None => client.state_by_block_hash(parent_hash_for_state),
        }
    };
    // A block under gov5's Amsterdam execution (EIP-2780 intrinsic, EIP-8037
    // state gas and its two block gas dimensions, EIP-7708 transfer logs)
    // takes the parallel step with the batches' Amsterdam checks
    // (`docs/AMSTERDAM_PARALLEL_STEP.md`) unless `N42_AMSTERDAM_PARALLEL=0`,
    // which builds it serially as before. reth's own Amsterdam (a block
    // access list) stays serial below (`is_amsterdam`).
    let glamsterdam_execution =
        reth_chainspec::qmdb::glamsterdam_execution_active_at(client.chain_spec().genesis(), attributes.timestamp);
    let parallel_build = parallel_build() && (!glamsterdam_execution || crate::parallel_build::amsterdam_parallel());
    let defer_state = state_after_pull() && parallel_build && builder_puller() != 0;
    let parent_state_slot: std::cell::OnceCell<reth_storage_api::StateProviderBox> = std::cell::OnceCell::new();
    if !defer_state {
        let _ = parent_state_slot.set(open_parent_state()?);
    }
    let state = LazyParentDb { slot: &parent_state_slot, open: &open_parent_state };
    // The parent's state once it is open: after the deferred open under
    // `N42_STATE_AFTER_PULL=1`, from the start otherwise.
    let parent_state_ref = || {
        parent_state_slot
            .get()
            .ok_or(reth_storage_api::errors::ProviderError::StateForHashNotFound(parent_hash_for_state))
    };
    // The block access list, when the chain is past Amsterdam.
    //
    // EIP-7928, and the reason to build one here is not the EIP: reth executes
    // an incoming block in parallel when it carries an access list and serially
    // when it does not (`payload_validator.rs::bal_path_eligible`). A builder
    // that omits it produces blocks every node then validates one transaction
    // at a time.
    //
    // This is the line reth's own `default_ethereum_payload` has and this
    // builder did not, which is why `getPayloadV6` answered
    // `MissingBlockAccessList` on a chain where Amsterdam was demonstrably
    // active -- the forkchoice had already refused attributes without EIP-7843's
    // slot number.
    let is_amsterdam = client.chain_spec().is_amsterdam_active_at_timestamp(attributes.timestamp);
    // reth v2.9.0 (evm2): the executor keeps the block's state and bundle
    // itself; the database is the cached reads over the parent's state.
    let db = cached_reads.as_db_mut(state);

    // Get signer address from consensus to use as coinbase (beneficiary)
    // This ensures consistency between payload builder and engine tree execution
    let coinbase = match cons.get_signer_address() {
        Ok(Some(addr)) => {
            debug!(target: "payload_builder", signer_address=?addr, "using signer address as coinbase");
            addr
        }
        Ok(None) => {
            // The normal case on a HotStuff chain: the leader names the
            // beneficiary, and a local signer key must not override it.
            debug!(target: "payload_builder", "no signer address configured; using suggested_fee_recipient");
            attributes.suggested_fee_recipient
        }
        Err(e) => {
            warn!(target: "payload_builder", error=?e, "Failed to get signer address, using suggested_fee_recipient");
            attributes.suggested_fee_recipient
        }
    };
    debug!(target: "payload_builder", ?coinbase, suggested_fee_recipient=?attributes.suggested_fee_recipient, "using coinbase for payload building");

    let chain_spec = client.chain_spec();
    // A HotStuff chain's blocks follow gov5's header profile: the beneficiary
    // is the fee recipient the leader named (gov5 sets Coinbase to the
    // signer), the ommers hash and difficulty are zero, and the receipts
    // root is gov5's keccak-of-receipts rather than a trie. The view and
    // the seal are stamped by the validator process after the build.
    let hotstuff = n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(chain_spec.genesis()).is_ok();

    // What `builder_for_next_block` does, with this repo's assembler in place
    // of reth's: see `assembler` for what that saves and why.
    let next_attributes = NextBlockEnvAttributes {
        // EIP-7843; APoS does not drive slots
        slot_number: None,
        timestamp: attributes.timestamp,
        suggested_fee_recipient: coinbase,
        prev_randao: attributes.prev_randao,
        gas_limit: {
            let computed = builder_config.gas_limit(parent_header.gas_limit);
            // `deferredExecutionDepth` 2 (docs/DEFERRED_DEPTH_2_DESIGN.md item
            // 19): the header's `gasUsed` is the grandparent's, which a limit
            // that shrank twice could fall under. Depth 1 is left as it was.
            let depth = reth_chainspec::qmdb::deferred_execution_depth_at(chain_spec.genesis(), attributes.timestamp);
            if depth >= 2 {
                let carried = crate::hotstuff_consensus::ancestor_executed_fields(chain_spec.genesis(), &parent_header, depth)
                    .map(|fields| fields.gas_used);
                gas_limit_over_carried(computed, parent_header.gas_limit, carried)
            } else {
                computed
            }
        },
        parent_beacon_block_root: attributes.parent_beacon_block_root,
        withdrawals: attributes.withdrawals.clone().map(Into::into),
        extra_data: Default::default(),
    };
    // What a serial rebuild after a refused fold starts again from
    // (`finish_or_rebuild`).
    let rebuild_attributes = next_attributes.clone();
    let evm_env = evm_config
        .next_evm_env(&parent_header, &next_attributes)
        .map_err(PayloadBuilderError::other)?;
    let group_env = evm_env.clone();
    let evm = evm_config.evm_with_env(db, evm_env.clone());
    let block_ctx = evm_config
        .context_for_next_block(&parent_header, next_attributes)
        .map_err(PayloadBuilderError::other)?;
    // The QMDB root is computed inside assembly, beside the transactions
    // trie, and collected from here afterwards.
    let qmdb_root: Arc<std::sync::Mutex<Option<Result<n42_qmdb_reth::PreparedBlock, String>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let mut assembler = crate::assembler::N42BlockAssembler::new(EthBlockAssembler::new(chain_spec.clone()), hotstuff)
        .with_mobile_registry_root(attributes.mobile_registry_root);
    if let Some(state) = &qmdb {
        assembler = assembler.with_qmdb_root(crate::assembler::QmdbRootJob {
            state: state.clone(),
            parent: parent_header.hash(),
            prague: n42_qmdb_reth::system_caller_leaf_at(&*chain_spec, attributes.timestamp),
            out: qmdb_root.clone(),
        });
    }
    let build_stage = BuildStage(parent_header.number);
    build_stage.at(1);
    let mut builder: reth_evm::execute::BasicBlockBuilder<'_, EvmConfig::BlockExecutorFactory, _, _, EthPrimitives> =
        reth_evm::execute::BasicBlockBuilder::new(
            evm_config.block_executor_factory(),
            &assembler,
            evm,
            evm_env,
            &parent_header,
            block_ctx,
        );
    if is_amsterdam {
        reth_evm::execute::BlockExecutor::enable_block_access_list_builder(builder.executor_mut());
    }

    debug!(target: "payload_builder", id=%payload_id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    // Timed in phases, because at the 163,000-transaction tier this function
    // is the largest single item on the fleet's serial chain (~740 ms of a
    // 2.3 s cycle) and "execution" was assumed to be most of it. The sibling
    // Rust client's breakdown at the same tier says otherwise: EVM 229 ms,
    // pool 57, block assembly 162. Which of those this builder spends its time
    // on decides what to fix, and guessing has been wrong before.
    let mut pool_ns: u128 = 0;
    let mut exec_ns: u128 = 0;
    let mut tail_ns: u128 = 0;
    let setup_took = build_started.elapsed();
    build_stage.at(2);
    let mut stale_txs: u64 = 0;
    // Transactions taken from the pool ahead of execution so that the
    // accounts they touch can be read in parallel first (`N42_BUILDER_PREFETCH`).
    let prefetch = builder_prefetch();
    let mut lookahead: std::collections::VecDeque<_> = std::collections::VecDeque::new();
    let mut prefetch_ns: u128 = 0;
    // The claimed senders this build verifies and refuses, and what it
    // spends doing so (`N42_INGEST_VERIFY=leader`; all three are 0 with the
    // mode off). Read as a difference over the build, like the fast-transfer
    // hits above, and smeared the same way when two builds overlap.
    let (verified_before, dropped_before, verify_ms_before) = (
        crate::claimed_build::verified(),
        crate::claimed_build::dropped(),
        crate::claimed_build::verify_ms(),
    );
    let ticks_at_start = ticks();
    let mut pool_ticks: u64 = 0;
    let mut exec_ticks: u64 = 0;
    // After the execution, before the next pull: the loop's own bookkeeping.
    let mut tail_ticks: u64 = 0;
    let mut tail_at: u64 = 0;
    let mut cumulative_gas_used = 0;
    let block_gas_limit: u64 = reth_evm::EvmEnv::block_env(reth_evm::BlockBuilder::evm_env(&builder)).gas_limit.saturating_to();
    let base_fee: u64 = reth_evm::EvmEnv::block_base_fee(reth_evm::BlockBuilder::evm_env(&builder));

    debug!(target: "payload_builder", ?block_gas_limit, ?base_fee, "payload builder block config");

    // A height the chain has already committed: nothing will ask for this
    // payload, and building it costs a block's worth of the queue and a
    // build's worth of verdicts about a state consensus did not keep. Taken
    // before anything is selected, so the queue is not touched at all:
    // until loop322 this ran after `best_txs`, so a payload job on a parent
    // the chain had passed (the build ahead on the old parent at a tenure
    // handover) took and gave back a block's worth of frames under the
    // queue's lock on every attempt before cancelling itself.
    if skip_decided_builds() && crate::canonical_head::already_decided(parent_header.number + 1) {
        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if say_once_a_second(&LAST) {
            tracing::info!(
                target: "payload_builder",
                number = parent_header.number + 1,
                head = crate::canonical_head::number(),
                "a build for a height the chain has already decided was cancelled"
            );
        }
        // Not `Cancelled`: reth's payload job treats that outcome as
        // unreachable unless its own cancel signal fired, and panics the
        // payload service -- which took the execution layer down on six
        // legs of loop215-218 and left the dead node leader for the rest of
        // its tenure (a TC moves the chain on by one view only). `Aborted`
        // is a build that chose not to produce a block; the job logs it at
        // debug and moves on.
        // The builder's executor borrows `cached_reads` (reth v2.9.0).
        drop(builder);
        return Ok(BuildOutcome::Aborted { fees: U256::ZERO, cached_reads });
    }
    // The seal gap's first term named (plan v6 6.13, `par_start_ms`): the
    // selection, of which the wait for the parent's queue hand-off (set by
    // a chained build's selector, [`note_handoff_wait`]), the checks, the
    // puller's start and the header's preparation, each timed.
    HANDOFF_WAIT_US.with(|cell| cell.set(0));
    let _ = crate::frame_blocks::take_select_times();
    let start_best_at = std::time::Instant::now();
    // `N42_PULL_BY_FRAMES`: the selector may hand the block over as one
    // vector out of the plan's frames, which only the parallel step with the
    // puller consumes (`frame_blocks::take_bulk`).
    crate::frame_blocks::want_bulk(parallel_build && builder_puller() != 0);
    // `N42_PLAN_AHEAD_BODY=1`: the queue makes the next block's body with its
    // plan; the partition is made at this build's beneficiary.
    if crate::frame_blocks::plan_ahead_body_wanted()
        && let Some(queue) = n42_tx_queue::global::<Pool::Transaction>()
    {
        crate::frame_blocks::note_beneficiary(group_env.block.beneficiary);
        install_plan_ahead_body(&queue);
    }
    let blob_fee = chain_spec
        .blob_params_at_timestamp(attributes.timestamp)
        .map(|_| reth_evm::EvmEnv::block_blob_base_fee(reth_evm::BlockBuilder::evm_env(&builder)));
    let best_txs = best_txs(BestTransactionsAttributes::new(base_fee, blob_fee));
    let start_best_us = start_best_at.elapsed().as_micros() as u64;
    let start_best_ms = start_best_us / 1_000;
    let mut bulk = crate::frame_blocks::take_bulk::<Pool::Transaction>();
    // `N42_PLAN_AHEAD_BODY=1`: what was made with the plan, its candidates
    // already the bulk vector (always taken, so nothing is left behind).
    let mut prepared_build = crate::frame_blocks::take_prepared::<Pool::Transaction>();
    let from_bulk = bulk.is_some();
    // `N42_PLAN_AHEAD_WARM`: the take's own transactions, before any pull.
    let bulk_len = bulk.as_ref().map_or(0, Vec::len);
    crate::frame_blocks::want_bulk(false);
    // `N42_FRAME_BLOCKS=1`: the frames the selector just took, whose layout
    // the transactions root is sealed over (`frame_blocks::sealed_root`).
    // The roots computed ahead over the pulled set are the MPT root and are
    // not computed for a frame build.
    let frame_plan = crate::frame_blocks::take_plan();
    let start_handoff_us = HANDOFF_WAIT_US.with(std::cell::Cell::get);
    let start_handoff_ms = start_handoff_us / 1_000;
    // The parent's hand-off hold (`N42_HANDOFF_DONE_FIRST` runs it after
    // the signal this build waited on), with its eviction's free.
    let (handoff_hold_us, evict_free_us) = crate::frame_blocks::take_handoff_hold();
    // `start_best_ms` split: the queue's frame take opening (lock, build
    // start), the plan (the frames checked and taken), the ordinary walk's
    // opening, and the rest (the hand-off above is its own key).
    let select_times = crate::frame_blocks::take_select_times();
    let start_select_ms = select_times.select_us / 1_000;
    let start_walk_ms = select_times.walk_us / 1_000;
    let start_walk_check_ms = select_times.check_us / 1_000;
    let start_pull_ms = select_times.pull_us / 1_000;
    let start_best_other_ms = start_best_us
        .saturating_sub(start_handoff_us + select_times.select_us + select_times.walk_us + select_times.pull_us)
        / 1_000;
    let start_check_at = std::time::Instant::now();
    // Tried and measured inert: `best_txs.no_updates()`, dropping the
    // iterator's live feed of new transactions. The pool phase stayed at
    // 66-82 ms a block either way, so the cost is the ordered sets
    // themselves, not what arrives during the build.
    //
    // The pool phase of a full block -- `next()` 163,000 times -- measured
    // 66 ms on the leader, 405 ns a transaction, where the queue's own walk
    // is 55-65 ns hot (`bench_next_at_the_bench_tier`): the rest is the cold
    // memory the transactions live in and the lock shared with the inbox
    // drain. `N42_BUILDER_PULLER=<n>` moves the walk to its own thread,
    // which pulls batches of <n> ahead of the execution into a bounded
    // channel; the loop below pops a local buffer. A refusal goes back to
    // the puller as a message, so the refused sender's later transactions
    // are still dropped, only a batch late -- each such transaction fails
    // its nonce check in the executor and is refused again, as the queue
    // did for them before. Whatever was pulled and not built is returned
    // by the puller when the build ends, and by the queue's give-back at
    // the next build in any case.
    // Whether the transactions come from the queue: the selector took it if
    // one is installed. Only the queue needs to hear about a stale nonce.
    let from_queue = n42_tx_queue::global::<Pool::Transaction>().is_some();
    // Is this build standing behind its own queue? The lanes are pruned by
    // every canonical block; a parent below the highest of those is a parent
    // whose state is waiting for nonces the lanes no longer hold, and every
    // lane will look gapped to it whatever it holds. O(1), taken before a
    // block's worth of candidates is pulled and refused.
    //
    // The reading is kept even though loop213 said it does not fire: Pe
    // node3's 26 empty builds were chained builds on their own previous
    // block, canonical and committed before the build ran. Counted so a leg
    // can say whether the case exists; acted on only under
    // `N42_BUILD_REFUSE_STALE_PARENT`.
    let pruned_through = n42_tx_queue::global::<Pool::Transaction>().map_or(0, |queue| queue.pruned_through());
    let parent_behind = pruned_through > parent_header.number;
    if parent_behind {
        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if say_once_a_second(&LAST) {
            warn!(
                target: "payload_builder",
                number = parent_header.number + 1,
                parent = %parent_header.hash(),
                parent_number = parent_header.number,
                pruned_through,
                refusing = refuse_stale_parent(),
                "build on own block refused: parent stale, the queue is pruned past it"
            );
        }
        if refuse_stale_parent() {
            // See above: never `Cancelled` from here.
            drop(builder);
            return Ok(BuildOutcome::Aborted { fees: U256::ZERO, cached_reads });
        }
    }
    // What the queue holds and what a build could take of it. `queued`
    // alone cannot tell a queue that ran dry from one that is deep and
    // unusable -- lanes parked behind a hole, or emptied -- and loop207's
    // defect 13 was the second: `queued=334-360k` on every build while the
    // leader proposed empty blocks. One walk of the lanes, once a build.
    let queue_depth = || -> (usize, usize, usize) {
        match n42_tx_queue::global::<Pool::Transaction>() {
            Some(queue) => (queue.len(), queue.usable(), queue.parked().1),
            None => (0, 0, 0),
        }
    };
    let start_check_ms = start_check_at.elapsed().as_millis() as u64;
    let start_puller_at = std::time::Instant::now();
    let puller = builder_puller();
    let mut pulled: Option<Puller<Pool::Transaction>> = None;
    // With the block in hand (`bulk`) there is nothing to pull: the
    // iterator stays here for the refusals, on this thread.
    let mut best_txs = if puller == 0 || bulk.is_some() {
        Some(best_txs)
    } else {
        pulled = Some(Puller::start(best_txs, puller));
        None
    };
    let start_puller_ms = start_puller_at.elapsed().as_millis() as u64;
    // What a candidate the parallel step skipped goes back with: the
    // truthful nonce error when the diagnosis above found one, so the queue
    // can drop a stale head or park a gapped lane, and the old
    // `ExceedsGasLimit` for everything else (a sender's later candidates,
    // which say nothing on their own).
    macro_rules! deferred_refusal {
        ($heads:expr, $tx:expr) => {
            match $heads.get(&$tx.sender()) {
                Some((head, state)) if *head == $tx.nonce() && *head != *state => {
                    InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent {
                        tx: *head,
                        state: *state,
                    })
                }
                _ => InvalidPoolTransactionError::ExceedsGasLimit($tx.gas_limit(), block_gas_limit),
            }
        };
    }
    macro_rules! refuse {
        ($tx:expr, $err:expr) => {
            match (best_txs.as_mut(), pulled.as_ref()) {
                (Some(best), _) => best.mark_invalid($tx, $err),
                (None, Some(puller)) => puller.refuse(Refusal::Invalid(Arc::clone($tx), $err)),
                (None, None) => {}
            }
        };
    }
    let mut tx_count = 0u64;
    let mut total_fees = U256::ZERO;

    let start_prepare_at = std::time::Instant::now();
    let mut header = cons
        .prepare(&n42_header::seal_to_alloy(&parent_header))
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
    if hotstuff {
        header.beneficiary = coinbase;
    }
    let start_prepare_ms = start_prepare_at.elapsed().as_millis() as u64;

    // `N42_STATE_AFTER_PULL=1`: the parent's state opened and the
    // pre-execution changes applied once, just before the parallel step's
    // batches (or wherever the step leaves for the serial path first). The
    // time inside the open is `state_wait_ms`: a chained build's wait for its
    // parent's `StateReady`.
    let state_pending = std::cell::Cell::new(defer_state);
    let mut state_wait_ms = 0u64;
    let mut state_wait_us = 0u64;
    // What that wait was on (`direct_build::open_wait`): the parent's output,
    // the grandparent's import, the parent's QMDB root or `Complete`, or the
    // open itself ("open": the rest of `state_wait_ms`).
    let mut state_wait_on = crate::direct_build::open_wait::OpenWait::default();
    // The pre-execution changes applied after that open, us: inside the
    // parallel step's hook before the batches, outside `state_wait_us`.
    let mut state_pre_changes_us = 0u64;
    macro_rules! open_deferred_state {
        () => {{
            if state_pending.get() {
                let _ = crate::direct_build::open_wait::take();
                let at = std::time::Instant::now();
                let opened = open_parent_state();
                let waited = at.elapsed();
                state_wait_ms += waited.as_millis() as u64;
                state_wait_us += waited.as_micros() as u64;
                state_wait_on = crate::direct_build::open_wait::take();
                match opened {
                    Err(err) => Err(PayloadBuilderError::from(err)),
                    Ok(provider) => {
                        let _ = parent_state_slot.set(provider);
                        state_pending.set(false);
                        let changes_at = std::time::Instant::now();
                        let applied = builder.apply_pre_execution_changes().map_err(|err| {
                            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
                            PayloadBuilderError::Internal(err.into())
                        });
                        state_pre_changes_us += changes_at.elapsed().as_micros() as u64;
                        applied
                    }
                }
            } else {
                Ok::<(), PayloadBuilderError>(())
            }
        }};
    }
    if !defer_state {
        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;
    }

    let mut block_blob_count = 0;
    let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
    let max_blob_count = blob_params
        .as_ref()
        .map(|params| params.max_blob_count)
        .unwrap_or_default();

    // N42_PARALLEL_BUILD=1: the block's plain transfers are executed in
    // conflict-free groups on the worker pool -- the way a follower imports
    // the block -- and committed to the builder's state in group order, before
    // the serial loop below takes whatever is left (transfers the path refused,
    // anything that is not a transfer). Only with the puller, whose batches
    // are the natural unit to take a block's worth from; the serial loop's
    // lookahead receives the leftovers in candidate order.
    let mut par_ms = 0u64;
    let mut par_txs = 0u64;
    let mut par_groups = 0usize;
    let mut par_batches = 0usize;
    let mut par_skipped = 0usize;
    // The candidates the parallel step asked the queue for: a block's worth
    // at the step's start (`budget` there), 0 when the step did not run.
    let mut par_budget = 0usize;
    let mut par_pull_ms = 0u64;
    let mut par_exec_ms = 0u64;
    let mut par_fold_ms = 0u64;
    let mut deferred: Vec<Arc<reth_transaction_pool::ValidPoolTransaction<Pool::Transaction>>> = Vec::new();
    // The head the parallel step refused per skipped sender, with the nonce
    // the parent's state has for it: what the give-back below tells the
    // queue instead of a refusal that says nothing. See the diagnosis after
    // the parallel step.
    let skipped_heads: alloy_primitives::map::AddressHashMap<(u64, u64)> = Default::default();
    let mut par_reverts: Vec<(alloy_primitives::Address, reth_trie::bundle_state::AccountRevert)> = Vec::new();
    let mut par_drained = false;
    // `N42_OUTPUT_SHARDS` (docs/BREAKTHROUGH_DESIGN.md section 3): the
    // parallel step's output left in address-range shards and never grafted;
    // carried to the finish behind the seal, where the next build is let go
    // on it before the block's one bundle is built.
    let mut output_shards: Option<Arc<crate::output_shards::FrozenShards>> = None;
    // `N42_ROOT_OPS_AHEAD=1`: the shards' QMDB leaves encoded on a thread of
    // their own from the graft's end (with the Prague flag they were encoded
    // under), for the root job behind the seal to finish.
    let mut ops_ahead: Option<(OpsAheadJob, bool)> = None;
    let mut out_shards = 0usize;
    let mut shard_append_ms = 0u64;
    let mut shard_fold_ms = 0u64;
    // The build's batches on the pool: imbalance, gaps, per-batch overhead.
    let mut par_batch_spans = crate::parallel_transfer::BatchSpans::default();
    // `N42_SHARDS_BEFORE_RECEIPTS=1`: the same receipts, still being built on
    // a thread of their own when the shards are filed; joined where the
    // receipts are first read (the receipts root behind the seal).
    let mut receipts_pending: Option<std::thread::JoinHandle<(Vec<n42_tx_types::Receipt>, u64)>> = None;
    // The block's body as the same parallel pass leaves it, already split into
    // the transactions and their senders: the seal wants those two vectors and
    // used to make them by moving 163,000 recovered transactions through one
    // serial `unzip` (most of a 24 ms `tx_root_ms`).
    let mut direct_body: Option<(Vec<TransactionSigned>, Vec<alloy_primitives::Address>)> = None;
    // The body's transaction hashes, made with it in the prep (or with the
    // plan): the seal's frame layout reads them instead of collecting
    // 200,000 hashes on its path. Set only beside `direct_body` from the same
    // source, so they are its hashes in its order.
    let mut direct_hashes: Option<Vec<B256>> = None;
    // Whether the seal took them.
    let mut seal_hashes_ahead = false;
    // `N42_PLAN_AHEAD_PARTS=1`: the root found with the plan for the hashes
    // in `direct_hashes` (set only beside them, from the same prepared
    // build), and whether the seal took it.
    let mut direct_root_ahead: Option<crate::frame_blocks::RootAhead> = None;
    let mut seal_root_ahead = false;
    let deferred_now = reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), attributes.timestamp);
    // What the seal-first path needs of the chain and the block, short of
    // the block being full (known after the parallel step).
    let seal_early_possible = early_seal.is_some() && deferred_now && hotstuff && !is_amsterdam && qmdb.is_some();
    // Read before the early seal is taken: a build that does not seal early
    // drops the `EarlySeal` on the way past, and with it the only record of
    // which hash the builder gave this block's parent. The ordinary finish
    // needs it for exactly the same reason the early seal does.
    let parent_built = early_seal.as_ref().and_then(|early| early.parent_built);
    // `deferredExecutionDepth`: which ancestor's result the header carries.
    let carried_depth = reth_chainspec::qmdb::deferred_execution_depth_at(chain_spec.genesis(), attributes.timestamp);
    // The lookahead and the puller given back before the ahead seal, ms.
    let mut give_back_ms = 0u64;
    // Of it on the evm2 step (F5g item 5): the lookahead's return to the
    // puller and the puller's stop and join (its walk's own give-back), us;
    // and whether the puller was stopped at the pull's end
    // (`N42_PULLER_STOP_AT_PULL`), its wind-down then beside the batches.
    let mut seal_lookahead_us = 0u64;
    let mut seal_puller_join_us = 0u64;
    // "stopped" (at the pull), "kept" (stopped at the seal), "none" (no
    // puller: the frames' bulk take or the direct iterator).
    let mut puller_at_pull: &'static str = "none";
    // The evm2 step's span before `execute_batches` starts and after it
    // ends, by part (F5g8), us: the open of the deferred state, the prepared
    // build's take (and why it missed), the keys made inline, the output
    // shards' set-up; after it, the run's indices and fees, the body.
    let mut evm2_pre_exec_us = 0u64;
    let mut evm2_open_us = 0u64;
    let mut evm2_prepared_us = 0u64;
    let mut evm2_prepared_miss: String = String::from("none");
    let mut evm2_keys_us = 0u64;
    let mut evm2_shards_new_us = 0u64;
    let mut evm2_setup_us = 0u64;
    let mut evm2_fees_us = 0u64;
    // Inside the evm2 batches by part (F5g9).
    let mut evm2_inside = crate::parallel_build::BatchInside::default();
    let mut index_ms = 0u64;
    // `N42_FREEZE_AFTER_SEAL=1`: whether the freeze ran beside the seal, when
    // it ended, and how long its join waited for it (us).
    let mut freeze_late_used = false;
    let mut freeze_ended_at: Option<std::time::Instant> = None;
    let mut freeze_join_wait_us = 0u64;
    let mut early_out: Option<Arc<crate::output_shards::EarlyOutput>> = None;
    let mut pending_freeze: Option<LateFreeze> = None;
    let mut shards_final_at: Option<std::time::Instant> = None;
    // Where the leader's time from the build's start to the seal goes, beside
    // the fields that already name it (plan v6, the seal gap). With the
    // parallel step taken, `sealed_at_ms` is, within a ms or two of rounding:
    // par_start + par_pull + par_prep + par_prefetch_wait + pre_exec +
    // par_run + scope_join + par_commit + sealed; `par_run` is itself
    // par_part + state_wait + par_exec + par_collect + par_release.
    // Build start to the parallel step's start (the setup, the puller's
    // start, the header's preparation).
    let mut par_start_ms = 0u64;
    // The parallel step's wall time (`par_ms`) split at the seal under
    // `N42_SEAL_AT_EXEC=1`: its start to the seal's start (on the seal's
    // chain) and the seal's end to its end (the fold and the give-backs,
    // behind the proposal), us. Both 0 when the step did not seal.
    let mut par_to_seal_us = 0u64;
    let mut pulled_drop_us = 0u64;
    // `N42_SHARDS_READY_FIRST=1`: the step's pulled set, warm layer and
    // transfer keys, kept past the step's scope and freed off the path after
    // the shards are filed.
    let mut pulled_keep: Option<Box<dyn Send>> = None;
    // The seal's wait for the carried ancestor's execution fields, us, and
    // what it waited on (`carried_fields_for_seal_traced`).
    let mut parent_fields_us = 0u64;
    let mut parent_fields_wait_on: &'static str = "";
    let mut commit_body_ms = 0u64;
    // Whether the commit took the body made in the prep's pass.
    let mut commit_body_ahead_used = false;
    let mut exec_end_to_seal_us = 0u64;
    // `N42_PLAN_AHEAD_BODY=1`: the prep took the keys and body made with the
    // plan; the call took its partition and slots; the hand-off of this
    // block was noted as its whole take.
    let mut prep_from_plan = false;
    let mut exec_prepared_groups = false;
    let mut whole_take_noted = false;
    // Of `sealed_ms`: the header filled and `cons.seal`; the sealed and
    // recovered block made; `remember_pending`; the payload and the hook.
    let mut seal_header_ms = 0u64;
    let mut seal_block_ms = 0u64;
    let mut seal_remember_ms = 0u64;
    // Of `tx_root_ms` under `N42_FRAME_BLOCKS=1`: the body's frame layout
    // found (the plan's prefix check, or the index's per-frame lookups) and
    // the frame tree over it; its leaves read from the plan's ids or hashed.
    let mut seal_layout_ms = 0u64;
    let mut seal_root_ms = 0u64;
    let mut seal_frames_indexed = 0usize;
    let mut seal_frames_hashed = 0usize;
    let mut seal_hook_ms = 0u64;
    // The moment the sealed payload went to the hook: the origin of the
    // `seal_to_*_us` stamps on the phases line (the finish behind the seal,
    // up to this block's own fields published).
    let mut sealed_instant: Option<std::time::Instant> = None;
    // The same moment on the wall clock (`sealed_unix_us` on the line).
    let mut sealed_unix_us = 0u64;
    // `N42_SEAL_AT_EXEC=1`: the block sealed and proposed at the parallel
    // step's end -- the payload, the block, its hash and number, and the seal's
    // timers -- for the fold and the finish that follow it.
    let mut sealed_ahead = None;
    // The same block's hash and number, for the fold's errors after the
    // proposal ([`failed_after_seal`]).
    let mut sealed_ahead_id: Option<(B256, u64)> = None;
    // The seal itself, where the early seal is taken: at the parallel step's
    // end (`N42_SEAL_AT_EXEC=1`) or after the fold (the default). The body
    // leaves the builder here; the header carries the block's transactions
    // root and, under deferred execution, the parent's execution.
    macro_rules! seal_block {
        ($hook:expr, $seal_at:expr, $early_root:expr) => {{
            let seal_at: std::time::Instant = $seal_at;
            // The transactions out of the builder: the body is the sealed
            // block's; nothing here assembles a block from them again.
            let (transactions, senders): (Vec<TransactionSigned>, Vec<alloy_primitives::Address>) = match direct_body.take() {
                Some(body) => body,
                None => {
                    let txs = std::mem::take(&mut builder.transactions);
                    txs.into_iter().map(|tx| tx.into_parts()).unzip()
                }
            };
            let early_root: Option<B256> = $early_root;
            let transactions_root = if crate::frame_blocks::active() {
                // Under the flag: the frame tree when the sealed body is a
                // run of frames (by the build's plan or this node's frame
                // index), the MPT root for any other body.
                use alloy_consensus::transaction::TxHashRef as _;
                let mut root_ahead = direct_root_ahead.take();
                let hashes: Vec<B256> = match direct_hashes.take().filter(|hashes| hashes.len() == transactions.len()) {
                    Some(hashes) => {
                        seal_hashes_ahead = true;
                        hashes
                    }
                    None => {
                        // The root found ahead is for the prepared hashes only.
                        root_ahead = None;
                        transactions.iter().map(|tx| *tx.tx_hash()).collect()
                    }
                };
                let carried = root_ahead
                    .as_ref()
                    .and_then(|ahead| crate::frame_blocks::seal_root_carried(ahead, frame_plan.as_ref(), &hashes));
                seal_root_ahead = carried.is_some();
                let sealed = match carried {
                    Some(sealed) => sealed,
                    None => crate::frame_blocks::seal_root_timed(frame_plan.as_ref(), &hashes, || {
                        early_root.unwrap_or_else(|| crate::assembler::parallel_transaction_root(&transactions))
                    }),
                };
                seal_layout_ms = sealed.layout_us / 1000;
                seal_root_ms = sealed.root_us / 1000;
                seal_frames_indexed = sealed.indexed;
                seal_frames_hashed = sealed.hashed;
                sealed.root
            } else {
                match early_root {
                    Some(root) => root,
                    None => crate::assembler::parallel_transaction_root(&transactions),
                }
            };
            let root_ms = seal_at.elapsed().as_millis() as u64;
            let parent_sealed = parent_header.hash();
            // The parent's execution, as this header carries it: recorded
            // under its sealed hash, or -- a parent finishing behind its own
            // seal -- arriving under the builder's hash a moment from now.
            // At depth 2 the grandparent's (`parent_fields_ms` keeps its name).
            let fields_at = std::time::Instant::now();
            let (parent_fields, fields_on) =
                carried_fields_for_seal_traced(chain_spec.genesis(), &parent_header, parent_built, carried_depth);
            parent_fields_us = fields_at.elapsed().as_micros() as u64;
            parent_fields_wait_on = fields_on;
            let parent_fields = parent_fields
                .ok_or_else(|| {
                    PayloadBuilderError::other(crate::hotstuff_consensus::DeferredExecutionError::ParentUnknown(
                        crate::hotstuff_consensus::ancestor_hash(&parent_header, carried_depth),
                    ))
                })?;
            let fields_ms = (seal_at.elapsed().as_millis() as u64).saturating_sub(root_ms);
            header.transactions_root = transactions_root;
            header.state_root = parent_fields.state_root;
            header.receipts_root = parent_fields.receipts_root;
            header.logs_bloom = parent_fields.logs_bloom;
            header.gas_used = parent_fields.gas_used;
            header.ommers_hash = B256::ZERO;
            header.difficulty = U256::ZERO;
            header.gas_limit = block_gas_limit;
            header.base_fee_per_gas = Some(base_fee);
            let withdrawals = attributes.withdrawals.clone().map(alloy_eips::eip4895::Withdrawals::new);
            header.withdrawals_root = withdrawals
                .as_ref()
                .map(|list| alloy_consensus::proofs::calculate_withdrawals_root(list));
            if chain_spec.is_cancun_active_at_timestamp(attributes.timestamp) {
                // A block of transfers carries no blobs.
                header.blob_gas_used = Some(0);
                // evm2's block env keeps only the blob base fee; the excess
                // comes from the parent, as reth's `EthBlockAssembler` derives it.
                header.excess_blob_gas = if chain_spec.is_cancun_active_at_timestamp(parent_header.timestamp) {
                    alloy_consensus::BlockHeader::maybe_next_block_excess_blob_gas(
                        parent_header.header(),
                        chain_spec.blob_params_at_timestamp(attributes.timestamp),
                    )
                } else {
                    Some(alloy_eips::eip7840::BlobParams::cancun().next_block_excess_blob_gas_osaka(0, 0, 0))
                };
            }
            // A block of transfers produces no EIP-7685 requests; the finish
            // behind the seal says so loudly if that ever stops being true.
            header.requests_hash = chain_spec
                .is_prague_active_at_timestamp(attributes.timestamp)
                .then_some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH);
            header.timestamp = attributes.timestamp;
            header.mix_hash = attributes.prev_randao;
            header.parent_beacon_block_root = attributes.parent_beacon_block_root;
            let block_number = header.number;
            let registry_root = stamp_gov5_tail(chain_spec.genesis(), &mut header, attributes.mobile_registry_root)?;
            cons.seal(&mut header).map_err(|err| PayloadBuilderError::Internal(err.into()))?;
            seal_header_ms = (seal_at.elapsed().as_millis() as u64).saturating_sub(root_ms + fields_ms);
            let step_at = std::time::Instant::now();
            let body = alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals };
            let sealed_block = SealedBlock::seal_parts(n42_header::N42Header::new(header.clone(), registry_root), body);
            let block_hash = SealedBlock::hash(&sealed_block);
            let recovered: Arc<reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>> =
                Arc::new(reth_primitives_traits::RecoveredBlock::new_sealed(sealed_block, senders));
            seal_block_ms = step_at.elapsed().as_millis() as u64;
            let step_at = std::time::Instant::now();
            crate::built_executions::remember_pending(block_hash, recovered.clone());
            seal_remember_ms = step_at.elapsed().as_millis() as u64;
            let step_at = std::time::Instant::now();
            // The hook takes the one full payload; the build keeps a
            // header-only stand-in for its own return (`hand_out_early`).
            let payload = hand_out_early(&recovered, total_fees, $hook);
            sealed_instant = Some(std::time::Instant::now());
            sealed_unix_us = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_micros() as u64);
            note_sealed(block_number);
            seal_hook_ms = step_at.elapsed().as_millis() as u64;
            let sealed_ms = seal_at.elapsed().as_millis() as u64;
            let sealed_at_ms = build_started.elapsed().as_millis() as u64;
            build_stage.at(5);
            (payload, recovered, block_hash, block_number, root_ms, fields_ms, sealed_ms, sealed_at_ms, parent_sealed)
        }};
    }
    // The parallel step on evm2 (docs/RETH_2_9_0_UPGRADE.md, F5c): a block's
    // worth of candidates taken from the puller, the frames' bulk vector or
    // the pool's iterator; when every one is a plain transfer and nothing
    // executed before, they run in sender batches on the build pool, each
    // transfer through the stock evm2 handler (`parallel_build`). The merge
    // is written into the executor's overlay (the cache half), the receipts
    // committed in candidate order, and the merge folded into the bundle at
    // `finish` (the bundle half; a refusal there rebuilds the block serially,
    // see `finish_or_rebuild`). Any refusal before the cache half hands the
    // candidates to the serial loop below in candidate order; a transfer the
    // EVM refused, with its sender's later ones, is given back at the end,
    // as the revm-era step did.
    if parallel_build && !is_amsterdam {
        let par_at = std::time::Instant::now();
        par_start_ms = build_started.elapsed().as_millis() as u64;
        let budget = (block_gas_limit.saturating_sub(cumulative_gas_used) / MIN_TRANSACTION_GAS) as usize;
        par_budget = budget;
        let mut cands: Vec<Arc<reth_transaction_pool::ValidPoolTransaction<Pool::Transaction>>> =
            bulk.take().unwrap_or_else(|| Vec::with_capacity(budget.min(262_144)));
        if let Some(puller) = pulled.as_ref() {
            while cands.len() < budget {
                match puller.batches().recv() {
                    Ok(batch) if !batch.is_empty() => cands.extend(batch),
                    _ => break,
                }
            }
        } else if let Some(best) = best_txs.as_mut() {
            while cands.len() < budget {
                let Some(tx) = best.next() else { break };
                cands.push(tx);
            }
        }
        par_drained = cands.len() < budget;
        if cands.len() > budget {
            for tx in cands.split_off(budget).into_iter().rev() {
                lookahead.push_front(tx);
            }
        }
        // Amsterdam: the prefix whose gas limits pass the block's two gas
        // dimensions whatever each transfer turns out to be
        // (`AmsterdamRules::take`); the rest waits for the next block like a
        // block's worth over the budget.
        let amsterdam_rules = crate::parallel_build::AmsterdamRules::of(&group_env.version, block_gas_limit);
        // EIP-8037's two block gas counters, for the late receipts' gas.
        let separate_block_gas = group_env.version.feature(evm2::EvmFeatures::EIP8037);
        if let Some(rules) = amsterdam_rules.as_ref() {
            let take = rules.take(cands.iter().map(|tx| tx.gas_limit()));
            if take < cands.len() {
                for tx in cands.split_off(take).into_iter().rev() {
                    lookahead.push_front(tx);
                }
            }
        }
        par_pull_ms = par_at.elapsed().as_millis() as u64;
        // `N42_PULLER_STOP_AT_PULL` (default on, F5g item 5): a full pull
        // on a block that can seal at the execution's end gives the
        // lookahead back and stops the puller now, so its walk's own
        // give-back runs beside the batches. Both still complete before the
        // seal (its join stays in front of it, loop232/233); only the wait
        // leaves the seal's path. A block that then does not seal builds on
        // without them (a slightly emptier block, never a lost transaction).
        if puller_stop_at_pull()
            && !par_drained
            && seal_at_exec()
            && seal_early_possible
            && block_blob_count == 0
            && early_seal.is_some()
            && let Some(puller) = pulled.as_mut()
        {
            let at = std::time::Instant::now();
            for pool_tx in std::mem::take(&mut lookahead).into_iter().rev() {
                puller.refuse(Refusal::Invalid(
                    Arc::clone(&pool_tx),
                    InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit),
                ));
            }
            puller.stop();
            seal_lookahead_us = at.elapsed().as_micros() as u64;
            puller_at_pull = "stopped";
        } else if pulled.is_some() {
            puller_at_pull = "kept";
        }
        let open_at = std::time::Instant::now();
        open_deferred_state!()?;
        evm2_open_us = open_at.elapsed().as_micros() as u64;
        let prepared_at = std::time::Instant::now();
        let beneficiary = group_env.block.beneficiary;
        // `N42_PLAN_AHEAD_BODY=1`: the keys and the partition made with the
        // plan, when they are for exactly these candidates. The selection
        // moved the plan's candidates into the bulk vector (`made.cands` is
        // empty then): the take is the plan's when the bulk vector came with
        // it and was not cut (F5g8: E13 missed on every block on the
        // `made.cands` length).
        let prepared_miss = match prepared_build.as_ref() {
            None => Some(String::from("no_plan")),
            Some(made) if made.keys.len() != cands.len() => Some(format!("keys_len {}!={}", made.keys.len(), cands.len())),
            Some(made) if !made.cands.is_empty() && made.cands.len() != cands.len() => {
                Some(format!("cands_len {}!={}", made.cands.len(), cands.len()))
            }
            Some(_) if made_cands_cut(from_bulk, bulk_len, cands.len()) => Some(format!("bulk_cut {}!={}", bulk_len, cands.len())),
            Some(made) if made.transactions.len() != cands.len() => {
                Some(format!("transactions_len {}!={}", made.transactions.len(), cands.len()))
            }
            Some(_) => None,
        };
        let prepared = if prepared_miss.is_none() { prepared_build.take() } else { None };
        prep_from_plan = prepared.is_some();
        evm2_prepared_miss = prepared_miss.unwrap_or_else(|| String::from("none"));
        // The body made with the plan (transactions, senders, hashes, the
        // root ahead), for the seal when it seals exactly these candidates.
        #[allow(clippy::type_complexity)]
        let mut prepared_body: Option<(Vec<TransactionSigned>, Vec<alloy_primitives::Address>, Vec<B256>, Option<crate::frame_blocks::RootAhead>)> =
            None;
        let (keys, groups) = match prepared {
            Some(mut made) => {
                let groups = made.groups.take().filter(|(at, _)| *at == beneficiary).map(|(_, groups)| groups);
                if made.transactions.len() == cands.len() {
                    prepared_body = Some((
                        std::mem::take(&mut made.transactions),
                        std::mem::take(&mut made.senders),
                        std::mem::take(&mut made.hashes),
                        made.root_ahead.take(),
                    ));
                }
                (Some(std::mem::take(&mut made.keys)), groups)
            }
            None => {
                let keys_at = std::time::Instant::now();
                // Amsterdam: a creating transfer needs more than 21,000
                // (EIP-8037), so the batches take plain transfers of any gas
                // limit there and check what each used.
                let keys = if amsterdam_rules.is_some() {
                    cands.iter().map(|tx| plain_transfer_key(tx)).collect::<Option<Vec<_>>>()
                } else {
                    cands.iter().map(|tx| transfer_key(tx)).collect::<Option<Vec<_>>>()
                };
                evm2_keys_us = keys_at.elapsed().as_micros() as u64;
                (keys, None)
            }
        };
        exec_prepared_groups = groups.is_some();
        evm2_prepared_us = prepared_at.elapsed().as_micros().saturating_sub(u128::from(evm2_keys_us)) as u64;
        let refused: Option<&'static str> = if cands.is_empty() {
            Some("no-candidates")
        } else if !builder.transactions.is_empty() {
            Some("transactions-before")
        } else if keys.is_none() {
            Some("not-all-transfers")
        } else {
            None
        };
        let mut line = (0usize, 0usize, 0usize, refused);
        if refused.is_none() {
            let keys = keys.unwrap_or_default();
            let exec_at = std::time::Instant::now();
            let convert = |i: usize| {
                let (tx, sender) = cands[i].to_consensus().into_parts();
                reth_primitives_traits::Recovered::new_unchecked(evm2::ethereum::TxEnvelope::from(tx), sender)
            };
            let worst_case = |i: usize| crate::frame_scan::tx_cost(pooled_consensus(&cands[i]));
            let open = || {
                open_parent_state()
                    .ok()
                    .map(|s| StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(s)))
            };
            // `N42_OUTPUT_SHARDS=<S>` on a block that can seal at the
            // execution's end (F5g3): each batch's bundle goes into the shard
            // that owns each address, on the batch's thread, and the block's
            // output stays in the shards -- no merge of the batches into one
            // map before the seal, no fold of them into the executor's bundle
            // after it. The next build reads the shards under the executor's
            // residual (`ShardedParent`), the root and the hashed post-state
            // read both, and the block's one bundle is merged behind them or
            // elided (`N42_MERGE_ELIDE`), as on the revm-era step.
            let shards_at = std::time::Instant::now();
            let shard_count = crate::output_shards::output_shards();
            let mut sharded = (shard_count > 0
                && seal_at_exec()
                && seal_early_possible
                && block_blob_count == 0
                && early_seal.is_some())
            .then(|| crate::output_shards::OutputShards::new(beneficiary, keys.len(), shard_count));
            evm2_shards_new_us = shards_at.elapsed().as_micros() as u64;
            let shard_sink = sharded.as_ref().map(|shards| move |bundle: reth_trie::bundle_state::BundleState| shards.add(bundle));
            let sink = shard_sink.as_ref().map(|sink| sink as &(dyn Fn(reth_trie::bundle_state::BundleState) + Sync));
            // The accounts the block's end reads stay out of the shards: the
            // executor's cache takes them at their post-batch values from the
            // run's merge, before the shards are frozen.
            let kept: Vec<alloy_primitives::Address> = if sink.is_some() {
                attributes.withdrawals.as_ref().map_or_else(Vec::new, |w| w.iter().map(|w| w.address).collect())
            } else {
                Vec::new()
            };
            evm2_setup_us = exec_at.elapsed().as_micros().saturating_sub(u128::from(evm2_shards_new_us)) as u64;
            // The batches apply plain transfers straight to their accounts
            // (F5g10) unless `N42_BATCH_DIRECT_TRANSFER=0`.
            let direct = crate::direct_transfer::DirectTransfers::for_env(&group_env, crate::direct_transfer::shape_of);
            // The batches count the block's gas and fees as they execute (a
            // candidate's tip read beside its conversion, while it is hot),
            // as the revm-era step's `tip_of` did: no pass over the executed
            // set between the execution's end and the seal.
            let tip_of = |i: usize| pooled_consensus(&cands[i]).effective_tip_per_gas(base_fee).unwrap_or_default();
            evm2_pre_exec_us = par_at.elapsed().as_micros() as u64;
            let run = crate::parallel_build::execute_batches_into(
                &evm_config,
                &group_env,
                &keys,
                groups,
                &convert,
                &open,
                deferred_now.then_some(&worst_case as &(dyn Fn(usize) -> U256 + Sync)),
                beneficiary,
                crate::parallel_transfer::Dispatch::from_env(),
                sink,
                &kept,
                direct.as_ref(),
                Some(&tip_of),
            );
            par_exec_ms = exec_at.elapsed().as_millis() as u64;
            let exec_end = std::time::Instant::now();
            let mut fold_at = exec_end;
            match run {
                Err(err) => {
                    line.3 = Some(err.reason());
                    warn!(target: "n42::parallel_build", number = header.number, %err, "the parallel step refused; the block is built serially");
                }
                Ok(run) => {
                    let crate::parallel_build::ParallelRun {
                        mut executed, skipped, merged, batches, groups, split, spans, inside, gas, fees,
                    } = run;
                    par_batch_spans = spans;
                    evm2_inside = inside;
                    // The fees and gas were summed on the batches (`tip_of`);
                    // the timer stays for the phases line and reads ~0.
                    let fees_at = std::time::Instant::now();
                    let fees = fees.unwrap_or_default();
                    let executed_len = executed.len();
                    evm2_fees_us = fees_at.elapsed().as_micros() as u64;
                    // `N42_SEAL_AT_EXEC=1` on evm2 (F5g1): under deferred
                    // execution the header carries the parent's execution, so
                    // a block the step filled (or the queue had no more for)
                    // needs only its transactions and their root to be
                    // sealed. It is sealed and proposed here, before the
                    // receipts are committed and the merge handed to the
                    // fold; those, and the finish, run behind the proposal,
                    // and any refusal among them is loud
                    // (`failed_after_seal`), never a different block. The
                    // test is the early-seal gate's below (`no_seal_why`),
                    // on the same inputs.
                    let gas_left_after = block_gas_limit.saturating_sub(cumulative_gas_used + gas);
                    let full_after = gas_left_after < MIN_TRANSACTION_GAS
                        || par_drained
                        || (executed_len != 0 && gas_left_after <= seal_shortfall(block_gas_limit));
                    let seal_here = seal_at_exec()
                        && seal_early_possible
                        && block_blob_count == 0
                        && executed_len != 0
                        && full_after
                        && early_seal.is_some();
                    if seal_here && let Some(EarlySeal { hook, parent_built: _ }) = early_seal.take() {
                        let seal_at = std::time::Instant::now();
                        par_to_seal_us = seal_at.saturating_duration_since(par_at).as_micros() as u64;
                        exec_end_to_seal_us = seal_at.saturating_duration_since(exec_end).as_micros() as u64;
                        // The body the seal lays its header over (F5g items
                        // 3-4): the one made with the plan when the block is
                        // every candidate in pull order and the plan's hashes
                        // are the pulled set's (its root ahead with it), or
                        // else made here from the executed candidates on the
                        // build pool -- never pushed into the builder one by
                        // one and split again at the seal.
                        let body_at = std::time::Instant::now();
                        let made = prepared_body.take().filter(|(transactions, _, hashes, _)| {
                            skipped.is_empty()
                                && executed_len == cands.len()
                                && transactions.len() == cands.len()
                                && body_matches_pull(hashes, &cands, |hash| *hash, |tx| *tx.hash())
                        });
                        match made {
                            Some((transactions, senders, hashes, root)) => {
                                direct_body = Some((transactions, senders));
                                direct_hashes = Some(hashes);
                                direct_root_ahead = root;
                                commit_body_ahead_used = true;
                            }
                            None => {
                                use rayon::prelude::*;
                                #[allow(clippy::type_complexity)]
                                let (transactions, (senders, hashes)): (Vec<TransactionSigned>, (Vec<alloy_primitives::Address>, Vec<B256>)) =
                                    crate::parallel_transfer::build_pool().install(|| {
                                        executed
                                            .par_iter()
                                            .with_min_len(1024)
                                            .map(|e| e.index)
                                            .map(|i| (pooled_consensus(&cands[i]).clone(), (cands[i].sender(), *cands[i].hash())))
                                            .unzip()
                                    });
                                direct_body = Some((transactions, senders));
                                direct_hashes = Some(hashes);
                            }
                        }
                        commit_body_ms = body_at.elapsed().as_millis() as u64;
                        total_fees += fees;
                        // What the puller took ahead and this block did not
                        // build goes back to the queue before the proposal,
                        // as on the revm-era step: the chained build pulls at
                        // the seal. Timed apart: the lookahead's return, then
                        // the puller's join (its walk's give-back).
                        let lookahead_at = std::time::Instant::now();
                        for pool_tx in std::mem::take(&mut lookahead).into_iter().rev() {
                            refuse!(
                                &pool_tx,
                                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
                            );
                        }
                        seal_lookahead_us += lookahead_at.elapsed().as_micros() as u64;
                        let join_at = std::time::Instant::now();
                        drop(pulled.take());
                        seal_puller_join_us = join_at.elapsed().as_micros() as u64;
                        give_back_ms = seal_at.elapsed().as_millis() as u64;
                        let sealed = seal_block!(hook, seal_at, None);
                        sealed_ahead_id = Some((sealed.2, sealed.3));
                        // `N42_PLAN_AHEAD_BODY=1`: the frames' bulk vector,
                        // uncut and executed whole, is the build's whole take.
                        if from_bulk
                            && crate::frame_blocks::plan_ahead_body_wanted()
                            && skipped.is_empty()
                            && executed_len == cands.len()
                            && cands.len() == bulk_len
                        {
                            let last = cands.len() - 1;
                            let checks = [0, last / 2, last].into_iter().map(|i| (i, cands[i].sender(), cands[i].nonce())).collect();
                            crate::frame_blocks::note_whole_take(crate::frame_blocks::WholeTake {
                                block: sealed.2,
                                parent: parent_header.hash(),
                                len: cands.len(),
                                checks,
                            });
                            whole_take_noted = true;
                        }
                        sealed_ahead = Some(sealed);
                    }
                    let sealed_here = sealed_ahead.is_some();
                    // The executed candidates' indices, for the serial loop's
                    // builder when the block did not seal here (after the
                    // seal otherwise, and then not needed).
                    let indices: Vec<usize> = if sealed_here { Vec::new() } else { executed.iter().map(|e| e.index).collect() };
                    fold_at = std::time::Instant::now();
                    // The shards frozen (one task a shard on the pool). A block
                    // that did not seal here goes back to one merge: the
                    // shards merged into one bundle and the beneficiary's
                    // bundles beside it, for the serial loop's cache.
                    let mut merged = merged;
                    let mut frozen = None;
                    let mut refused = None;
                    if let Some(shards) = sharded.take() {
                        // `N42_FREEZE_AFTER_SEAL`: on its own thread, joined
                        // where the seal branch files the residual.
                        let shards = if sealed_here && freeze_after_seal() {
                            match spawn_freeze(shards) {
                                Ok(handle) => {
                                    pending_freeze = Some(handle);
                                    freeze_late_used = true;
                                    None
                                }
                                Err(shards) => shards.map(|shards| shards.freeze()),
                            }
                        } else {
                            Some(shards.freeze())
                        };
                        match shards {
                            None if pending_freeze.is_some() => {}
                            None => {
                                refused = Some(crate::parallel_build::Refused::NotParallel(
                                    crate::parallel_common::NotParallel::NoState,
                                ));
                            }
                            Some(shards) if sealed_here => frozen = Some(shards),
                            Some(shards) => {
                                let mut whole = vec![shards.merged(&reth_trie::bundle_state::BundleState::default())];
                                whole.extend(split);
                                match crate::graft_fold::merge_batches(whole) {
                                    Ok(again) => merged = again,
                                    Err(err) => refused = Some(crate::parallel_build::Refused::Fold(err)),
                                }
                            }
                        }
                    }
                    // A block sealed here runs nothing after the batches but
                    // its end (the withdrawals and the post-block system
                    // calls), which reads the withdrawal recipients and the
                    // system contracts and never a batch account: the cache
                    // half writes just the withdrawal recipients, as the
                    // follower's import of a block without a serial tail does
                    // (`CacheScope::Only`). Otherwise every merged account,
                    // for the serial loop.
                    let withdrawal_recipients: Vec<alloy_primitives::Address> = if sealed_here {
                        attributes.withdrawals.as_ref().map_or_else(Vec::new, |w| w.iter().map(|w| w.address).collect())
                    } else {
                        Vec::new()
                    };
                    // On the shard path `merged` holds only the beneficiary
                    // and the withdrawal recipients, folded at `finish`.
                    let mut cached_only = withdrawal_recipients.clone();
                    if sealed_here && (frozen.is_some() || pending_freeze.is_some()) {
                        cached_only.push(beneficiary);
                    }
                    let scope = if sealed_here {
                        crate::parallel_build::CacheScope::Only(&cached_only)
                    } else {
                        crate::parallel_build::CacheScope::All
                    };
                    // `N42_EVM2_RECEIPTS_LATE` (default on, F5g7): on a block
                    // sealed here whose output stays in its shards, the
                    // receipts are built on a thread of their own and joined
                    // where they are first read (the receipts root, beside the
                    // QMDB root), as `N42_SHARDS_BEFORE_RECEIPTS` does on the
                    // revm-era step. The executor commits none of them, so its
                    // finish is the block's end alone (the withdrawals and the
                    // post-block system calls) and the shards are filed at
                    // about seal + 2 ms, not behind 200,000 commits (E12:
                    // seal_to_shards_ready 15-22 ms, the child's state_wait
                    // 11-14 ms). The finish reads no receipt it would miss: a
                    // transfer has no logs, so the deposit requests parsed from
                    // them are empty either way. Only when nothing was
                    // committed before the step, so the step's receipts are
                    // the block's.
                    let receipts_late_here = sealed_here
                        && refused.is_none()
                        && (frozen.is_some() || pending_freeze.is_some())
                        && builder.executor.receipts.is_empty()
                        && evm2_receipts_late();
                    // The skipped candidates, taken before the late receipts'
                    // thread takes the candidates with it.
                    let mut skipped_txs: Option<Vec<_>> = Some(skipped.iter().map(|&i| Arc::clone(&cands[i])).collect());
                    let committed = match refused {
                        Some(err) => Err(err),
                        None if receipts_late_here => {
                            let executed = std::mem::take(&mut executed);
                            let late_cands = std::mem::take(&mut cands);
                            let spawned = std::thread::Builder::new().name("n42-receipts-late".into()).spawn(move || {
                                let receipts = crate::parallel_build::late_receipts(
                                    executed.into_iter().map(|e| {
                                        let tx_type = <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(
                                            pooled_consensus(&late_cands[e.index]),
                                        );
                                        (e.result, tx_type)
                                    }),
                                    separate_block_gas,
                                );
                                crate::parallel_transfer::behind_pool().spawn(move || drop(late_cands));
                                receipts
                            });
                            match spawned {
                                Ok(handle) => {
                                    receipts_pending = Some(handle);
                                    crate::parallel_build::commit_run(&mut builder.executor, std::iter::empty(), merged, scope)
                                        .map(|_| gas)
                                }
                                Err(error) => Err(crate::parallel_build::Refused::Commit(format!(
                                    "no thread for the late receipts: {error}"
                                ))),
                            }
                        }
                        None => {
                            let results = std::mem::take(&mut executed).into_iter().map(|e| {
                                let tx_type =
                                    <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(pooled_consensus(&cands[e.index]));
                                (e.result, tx_type)
                            });
                            crate::parallel_build::commit_run(&mut builder.executor, results, merged, scope)
                        }
                    };
                    match committed {
                        Ok(committed_gas) => {
                            debug_assert_eq!(committed_gas, gas);
                            if frozen.is_some() || pending_freeze.is_some() {
                                crate::parallel_build::note_sharded_run();
                            }
                            if let Some(shards) = frozen.take() {
                                out_shards = shards.shard_count();
                                shard_append_ms = shards.append_ms();
                                shard_fold_ms = shards.fold_ms();
                                output_shards = Some(Arc::new(shards));
                            }
                            if !sealed_here {
                                for &i in &indices {
                                    builder.transactions.push(cands[i].to_consensus());
                                }
                                total_fees += fees;
                            }
                            cumulative_gas_used += committed_gas;
                            tx_count += executed_len as u64;
                            par_txs = executed_len as u64;
                            par_groups = groups.len();
                            par_batches = batches;
                            par_skipped = skipped.len();
                            deferred.extend(skipped_txs.take().unwrap_or_default());
                            line = (executed_len, par_skipped, batches, None);
                            // Freed behind the build (`N42_FREEZE_POOL=own`: on
                            // its own pool) rather than on the builder's thread.
                            let spent = (std::mem::take(&mut cands), groups);
                            crate::parallel_transfer::behind_pool().spawn(move || drop(spent));
                        }
                        Err(err) if sealed_here || matches!(err, crate::parallel_build::Refused::Commit(_)) => {
                            return Err(failed_after_seal(
                                sealed_ahead_id,
                                PayloadBuilderError::other(std::io::Error::other(format!(
                                    "the parallel step's receipts could not be committed: {err}"
                                ))),
                            ));
                        }
                        Err(err) => {
                            line.3 = Some(err.reason());
                            warn!(target: "n42::parallel_build", number = header.number, %err, "the parallel step refused; the block is built serially");
                        }
                    }
                }
            }
            par_fold_ms = fold_at.elapsed().as_millis() as u64;
        }
        if line.3.is_some() {
            for tx in std::mem::take(&mut cands).into_iter().rev() {
                lookahead.push_front(tx);
            }
        }
        par_ms = par_at.elapsed().as_millis() as u64;
        let (txs, skipped, batches, why) = line;
        tracing::info!(
            target: "n42::parallel_build",
            number = header.number,
            parallel = why.is_none(),
            txs,
            skipped,
            batches,
            refused = why.unwrap_or(""),
            fold_refused_total = crate::graft_fold::refused_count(),
            serial_rebuilds_total = crate::parallel_build::serial_rebuilds(),
            sharded_total = crate::parallel_build::sharded_runs(),
            fast_hits_total = crate::fast_handler::hits(),
            fast_delegated_total = crate::fast_handler::delegated(),
            direct_hits_total = crate::direct_transfer::hits(),
            direct_delegated_total = crate::direct_transfer::delegated(),
            pull_ms = par_pull_ms,
            exec_ms = par_exec_ms,
            commit_ms = par_fold_ms,
            "parallel step"
        );
    }
    // The step's scope has dropped: the pulled set among it.
    // `N42_STATE_AFTER_PULL=1`: every way out of the parallel step opened the
    // state already; this is a no-op kept so the serial loop and the finish
    // below never run on a state without its pre-execution changes.
    open_deferred_state!()?;

    // Sealed before it finishes (`EarlySeal`, docs/PHASE_D_DEFERRED_EXECUTION.md
    // section 13): under deferred execution the header carries the parent's
    // execution, so a block the parallel step filled needs only its
    // transactions root to be sealed. The seal goes out now; the fold is
    // done (it ran in the parallel step), and the finish, the hashed
    // post-state, the QMDB root and the receipts follow behind the seal --
    // the next build on this block waits for the state, the engine's handoff
    // for the rest.
    // Full, or the queue had no more to give: either way the serial loop
    // would add nothing worth the seal now. "Full" allows the shortfall the
    // parallel step's skipped candidates leave behind
    // ([`seal_shortfall`]): requiring the last 21,000 gas cost loop207 Pb
    // node3 the early seal on all 63 builds of a tenure, over 256-512
    // candidates of one stuck sender.
    let gas_left = block_gas_limit.saturating_sub(cumulative_gas_used);
    let block_full = gas_left < MIN_TRANSACTION_GAS
        || par_drained
        || (par_txs > 0 && gas_left <= seal_shortfall(block_gas_limit));
    // Why this build will not seal early, decided from the same inputs as
    // the gate below and said once a second. Until loop207 nothing named
    // it: `build on own block refused` and `early seal that did not happen`
    // never fired in five legs while two of them lost the seal for a whole
    // tenure, because the gate simply falls through to the ordinary finish.
    let no_seal_why = if early_seal.is_none() && sealed_ahead.is_none() {
        // The reth payload service's own path (`try_build`) asks for no
        // early seal; that is the first build of a tenure, not a defect.
        // A block sealed at the parallel step's end took `early_seal` with
        // it (loop230: every such build was refused here as "not asked").
        "no early seal asked for this build"
    } else if !deferred_now {
        "deferred execution is not active at this timestamp"
    } else if !hotstuff {
        "not a hotstuff chain"
    } else if is_amsterdam {
        "amsterdam"
    } else if qmdb.is_none() {
        "no qmdb state"
    } else if block_blob_count != 0 {
        "the block carries blobs"
    } else if par_txs == 0 {
        "the parallel step built nothing"
    } else if !block_full {
        "the parallel step left the block short of the gas limit"
    } else {
        ""
    };
    // `par_skipped` as well as `tx_count`: a build that skipped everything
    // it was offered has `tx_count` 0, and that is the build this line
    // exists for.
    if !no_seal_why.is_empty() && early_seal.is_some() && (tx_count >= 1000 || par_skipped >= 1000) {
        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if say_once_a_second(&LAST) {
            tracing::info!(
                target: "payload_builder",
                number = header.number,
                why = no_seal_why,
                par_txs,
                par_skipped,
                gas_left,
                shortfall = seal_shortfall(block_gas_limit),
                "a build did not seal early"
            );
        }
    }
    // Sealed already at the parallel step's end (`N42_SEAL_AT_EXEC=1`), or
    // sealed here. The gate is `no_seal_why` above, so the line that says why
    // a build did not seal early cannot drift from the test that decided it;
    // a block sealed at the step's end passed the same test by construction
    // (`seals_early_here`), and is refused loudly if it ever does not.
    let early = early_seal.take();
    if sealed_ahead.is_some() && !no_seal_why.is_empty() {
        return Err(failed_after_seal(
            sealed_ahead_id,
            PayloadBuilderError::other(std::io::Error::other(format!(
                "sealed at the execution's end, but the early-seal gate says: {no_seal_why}"
            ))),
        ));
    }
    if sealed_ahead.is_some() || (early.is_some() && no_seal_why.is_empty()) {
        {
            use reth_evm::execute::BlockExecutor as _;
            use reth_storage_api::HashedPostStateProvider as _;
            let seal_at = std::time::Instant::now();
            // Whatever was taken ahead and not built goes back to the queue,
            // as the loop's end does; the puller stops at its next batch.
            // Then the puller is dropped (the walk's own give-back) and,
            // under `N42_SHARDS_READY_FIRST`, the kept pulled set freed off
            // the path. By default here, before the seal or the finish;
            // with `N42_SHARDS_READY_FIRST=1` on a block sealed at the
            // step's end, right after the shards are filed (or the
            // `StateReady` of a block without shards), and in any case
            // before this branch returns.
            let mut give_backs = Some((lookahead, deferred));
            let mut giveback_us = 0u64;
            let mut puller_drop_us = 0u64;
            macro_rules! give_back_now {
                () => {
                    if let Some((lookahead, deferred)) = give_backs.take() {
                        let giveback_at = std::time::Instant::now();
                        for pool_tx in lookahead.into_iter().rev() {
                            refuse!(
                                &pool_tx,
                                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
                            );
                        }
                        for pool_tx in deferred.into_iter().rev() {
                            let err = deferred_refusal!(skipped_heads, pool_tx);
                            refuse!(&pool_tx, err);
                        }
                        giveback_us = giveback_at.elapsed().as_micros() as u64;
                        let puller_drop_at = std::time::Instant::now();
                        drop(pulled.take());
                        puller_drop_us = puller_drop_at.elapsed().as_micros() as u64;
                        if let Some(keep) = pulled_keep.take() {
                            let free_at = std::time::Instant::now();
                            crate::built_executions::free_boxed_off_path(keep);
                            pulled_drop_us += free_at.elapsed().as_micros() as u64;
                        }
                    }
                };
            }
            let shards_first = sealed_ahead.is_some() && shards_ready_first();
            if !shards_first {
                give_back_now!();
            }
            let seal_at_exec_used = sealed_ahead.is_some();
            let (payload, recovered, block_hash, block_number, root_ms, fields_ms, sealed_ms, sealed_at_ms, parent_sealed) =
                match sealed_ahead.take() {
                    Some(sealed) => sealed,
                    None => {
                        let Some(EarlySeal { hook, parent_built: _ }) = early else {
                            return Err(PayloadBuilderError::other(std::io::Error::other("no early seal to seal with")));
                        };
                        seal_block!(hook, seal_at, None)
                    }
                };
            let qmdb_state = qmdb.clone().expect("checked above");

            // reth v2.9.0: the executor borrows `cached_reads` through its
            // database. The builder is consumed in a block of its own (a
            // partially moved local stays drop-live to the borrow checker
            // until the function ends), so the borrow ends when the finish
            // consumes the executor and the reads can be handed back.
            let seal_executor = {
                let seal_builder = builder;
                seal_builder.executor
            };

            // ---- behind the seal ----
            // A failure here is after the proposal: the store's waiters are
            // told at once (`fail`), the engine's own path imports the block
            // when consensus commits it, and the error is loud.
            let behind_the_seal = || -> Result<(), PayloadBuilderError> {
            let finish_at = std::time::Instant::now();
            // reth v2.9.0: the executor holds the block's state and hands
            // back the bundle, its reverts merged, with the result.
            let reth_execution_types::BlockExecutionOutput { result: mut execution_result, state: executed_state } =
                seal_executor.finish().map_err(|err| PayloadBuilderError::Internal(err.into()))?;
            // Receipts built beside the parallel step: the executor committed
            // none, so its finish reports none and no gas.
            let receipts_late_used = receipts_pending.is_some();
            let direct_receipts_used = receipts_late_used;
            // `N42_SHARDS_BEFORE_RECEIPTS`: the receipts still being built
            // are joined where they are first read -- beside the QMDB root,
            // after the shards are filed -- on the shard path, and here on any
            // other (which never takes this road: it is chosen only for a
            // block whose output stays in its shards).
            let mut receipts_late = receipts_pending.take();
            if output_shards.is_none()
                && pending_freeze.is_none()
                && let Some(handle) = receipts_late.take()
            {
                let (receipts, gas_used) = handle.join().map_err(|_| {
                    PayloadBuilderError::other(std::io::Error::other("the late receipts job panicked"))
                })?;
                execution_result.receipts = receipts;
                execution_result.gas_used = gas_used;
            }
            let merge_ms = finish_at.elapsed().as_millis() as u64;
            // The post-state is final: the next block can be built on it.
            // The bundle is taken and its reverts appended once, here, and the
            // one execution output is shared by `state_ready`, the roots below
            // and `complete`: the provisional used to clone the whole bundle
            // (~147,000 accounts) and every receipt only to drop the receipts,
            // inside the 26 ms before the next build could start (loop138).
            // The hashed state comes with `complete`.
            let mut bundle = executed_state;
            let bundle_taken_at = std::time::Instant::now();
            // `N42_OUTPUT_INCREMENTAL=1`: the shards are filed on the early
            // output with this residual now -- the child's open proceeds --
            // and only then is the freeze joined; its indexed set gives up the
            // cached accounts the early take committed and is filed in the
            // early output's place for every later reader.
            let mut early_residual: Option<Arc<reth_execution_types::BlockExecutionOutput<n42_tx_types::Receipt>>> = None;
            let mut early_ready: Option<(u64, std::time::Instant)> = None;
            if let Some(handle) = pending_freeze.take() {
                let residual = Arc::new(reth_execution_types::BlockExecutionOutput {
                    state: std::mem::take(&mut bundle),
                    result: reth_execution_types::BlockExecutionResult {
                        receipts: Vec::new(),
                        requests: Default::default(),
                        gas_used: 0,
                        blob_gas_used: 0,
                    },
                });
                if let Some(early) = early_out.take() {
                    crate::built_executions::shards_ready(
                        block_hash,
                        crate::built_executions::ShardedParent {
                            residual: Arc::clone(&residual),
                            shards: Arc::new(crate::output_shards::FrozenShards::early(early)),
                        },
                    );
                    early_ready = Some((finish_at.elapsed().as_millis() as u64, std::time::Instant::now()));
                    give_back_now!();
                }
                let join_at = std::time::Instant::now();
                let (frozen, took, ended) = handle.join().map_err(|_| {
                    PayloadBuilderError::other(std::io::Error::other("the shards' freeze behind the early output panicked"))
                })?;
                freeze_join_wait_us += join_at.elapsed().as_micros() as u64;
                index_ms = took.as_millis() as u64;
                out_shards = frozen.shard_count();
                shard_append_ms = frozen.append_ms();
                shard_fold_ms = frozen.fold_ms();
                freeze_ended_at = Some(ended);
                let frozen = Arc::new(frozen);
                if root_ops_ahead() {
                    let shards = Arc::clone(&frozen);
                    let prague = n42_qmdb_reth::system_caller_leaf_at(&*chain_spec, attributes.timestamp);
                    let spawned = std::thread::Builder::new().name("n42-ops-ahead".into()).spawn(move || {
                        n42_core_layout::enter(n42_core_layout::Set::Critical);
                        let empty = reth_trie::bundle_state::BundleState::default();
                        let accounts = shards.view(&empty, &[]);
                        (n42_qmdb_reth::operations_ahead(&accounts, prague), std::time::Instant::now())
                    });
                    match spawned {
                        Ok(handle) => ops_ahead = Some((handle, prague)),
                        Err(error) => {
                            tracing::debug!(target: "payload_builder", %error, "no thread for the operations ahead; the root job encodes them");
                        }
                    }
                }
                output_shards = Some(frozen);
                early_residual = Some(residual);
            }
            if !execution_result.requests.is_empty() {
                tracing::error!(
                    target: "payload_builder",
                    number = block_number,
                    requests = execution_result.requests.len(),
                    "sealed with the empty requests hash, but the execution produced requests: the block is invalid"
                );
            }
            // The parent's tree under its sealed hash: a parent that finished
            // behind its seal after this build began has it under the
            // builder's hash still.
            // A parent this node executed as a follower
            // (`ParentExecution::Published`) has no builder hash: its tree is
            // filed under the sealed hash by its own import, and there is
            // nothing to rename.
            // `N42_FIELDS_AT_SEAL` (INDUSTRY_SURVEY_2026_10 11.8): off, the
            // rename waits for the parent's `Complete` (its merge and hashed
            // post-state) as it always did; on, a parent record already filed
            // under the builder's hash -- it is, whenever this block sealed on
            // the parent's published fields, because the parent files its tree
            // before it publishes them -- is renamed at once, and this block's
            // root job no longer queues behind the parent's finish.
            let fields_mode = crate::fields_at_seal::mode();
            let verify_fields = fields_mode.verify();
            let rename_wait_us = std::cell::Cell::new(0u64);
            let rename_early = std::cell::Cell::new(false);
            let renamed_at = std::cell::Cell::new(None::<std::time::Instant>);
            let rename_parent = || -> Result<(), PayloadBuilderError> {
                // At depth 2 this block's seal no longer waited for the
                // parent's fields, which was what made sure the parent's tree
                // was filed before this root job looked for it: the root job
                // waits for them itself (docs/DEFERRED_DEPTH_2_DESIGN.md item 8).
                let record_wait = (carried_depth >= 2).then_some(crate::hotstuff_consensus::PARENT_FIELDS_WAIT);
                let filed = crate::fields_at_seal::file_parent_under_seal_with_barrier(
                    &qmdb_state,
                    parent_sealed,
                    parent_built,
                    fields_mode.early(),
                    record_wait,
                    || {
                        if let Some(built) = parent_built {
                            let _ = crate::built_executions::wait_for(built, crate::built_executions::Stage::Complete);
                        }
                    },
                )
                .map_err(PayloadBuilderError::other)?;
                rename_wait_us.set(filed.waited_us);
                rename_early.set(filed.early);
                renamed_at.set(Some(std::time::Instant::now()));
                Ok(())
            };
            // The root job's own start and end, and the moment the fields
            // were published (the `seal_to_*_us` stamps).
            let root_started_at: Option<std::time::Instant>;
            let root_ended_at: Option<std::time::Instant>;
            let mut view_ready_at: Option<std::time::Instant> = None;
            // When the shards were filed (`shards_ready`): the child's open
            // proceeds from here.
            let mut shards_ready_at: Option<std::time::Instant> = None;
            let fields_published_at = std::cell::Cell::new(None::<std::time::Instant>);
            // `N42_FIELDS_AT_SEAL=verify`: what the fields were published
            // from, compared behind `Complete` with the late derivation.
            let mut early_inputs;
            let prague = n42_qmdb_reth::system_caller_leaf_at(&*chain_spec, attributes.timestamp);
            // `N42_OUTPUT_SHARDS`: the executor's bundle holds only what it
            // changed after the batches. The next build is let go on it laid
            // over the shards; the QMDB root and the hashed post-state read
            // the shards and it directly, and the block's one bundle (for
            // the engine and every `StateReady` reader) is merged after them
            // on the build pool.
            let mut shard_ready_ms = 0u64;
            let mut shard_merge_ms = 0u64;
            let mut shards_used = 0usize;
            // The leader's merge on its own thread (`merge_*` on the line),
            // and the shard path's root job split into its operations (encode,
            // join, sort) and the forest's compute.
            let mut leader_merge = LeaderMerge::default();
            let mut root_ops: (n42_qmdb_reth::OpsSplit, std::time::Duration, std::time::Duration, OpsAheadUse) = Default::default();
            let roots_ms;
            // Where the QMDB root spent its time (`root_*` on the phases line),
            // and how long its publication took.
            let root_split: n42_qmdb_reth::RootSplit;
            let root_publish_us = std::cell::Cell::new(0u64);
            // `N42_SHARDS_BEFORE_RECEIPTS`: how long the receipts root waited
            // for the late receipts, us (0 when they were in).
            let receipts_late_wait_us = std::cell::Cell::new(0u64);
            let state_ready_ms;
            // The block's own execution fields, published the moment its QMDB
            // root is in: the child's header carries them (deferred
            // execution), so the child's seal waits for exactly this. The tree
            // is filed first so the child's roots and every QMDB reader find
            // it by the time the fields say the block is executed.
            let publish = |prepared: Result<n42_qmdb_reth::PreparedBlock, n42_qmdb_reth::NodeStateError>,
                           (receipts_root, logs_bloom): reth_consensus::ReceiptRootBloom,
                           gas_used: u64|
             -> Result<crate::executed_fields::ExecutedFields, PayloadBuilderError> {
                let prepared = prepared.map_err(PayloadBuilderError::other)?;
                let state_root = prepared.root;
                qmdb_state.insert(block_hash, block_number, prepared).map_err(PayloadBuilderError::other)?;
                let fields = crate::executed_fields::ExecutedFields { state_root, receipts_root, logs_bloom, gas_used };
                crate::executed_fields::remember(block_hash, fields);
                crate::built_executions::answerable(block_hash);
                fields_published_at.set(Some(std::time::Instant::now()));
                Ok(fields)
            };
            let (execution_output, hashed_state) = match output_shards.take() {
                None => {
            crate::parallel_transfer::append_reverts(&mut bundle, std::mem::take(&mut par_reverts));
            let execution_output = Arc::new(reth_execution_types::BlockExecutionOutput {
                state: bundle,
                result: execution_result,
            });
            let execution_result = &execution_output.result;
            let provisional = crate::built_executions::BuiltExecution {
                block: recovered.clone(),
                execution_output: Arc::clone(&execution_output),
                hashed_state: Arc::new(Default::default()),
                trie_updates: Arc::new(TrieUpdates::default()),
            };
            crate::built_executions::state_ready(block_hash, provisional);
            state_ready_ms = finish_at.elapsed().as_millis() as u64;
            give_back_now!();
            rename_parent()?;
            let roots_at = std::time::Instant::now();
            let bundle_ref = &execution_output.state;
            // The state provider is `Send` but not `Sync`: the hashed
            // post-state stays on this thread while the root and the
            // receipts run beside it.
            let parent_root_early = verify_fields.then(|| qmdb_state.root_of(&parent_sealed)).flatten();
            let (hashed_state, prepared, roots) = std::thread::scope(|scope| {
                let receipts = &execution_result.receipts;
                let qmdb_job = &qmdb_state;
                let root = scope.spawn(move || {
                    // The leader's QMDB root job: on the critical set.
                    let started = std::time::Instant::now();
                    n42_core_layout::enter(n42_core_layout::Set::Critical);
                    let ops = n42_qmdb_reth::sorted_operations_from_execution(bundle_ref, prague);
                    let kept = verify_fields.then(|| ops.clone());
                    let prepared = qmdb_job.compute_operations(parent_sealed, ops);
                    (prepared, started, std::time::Instant::now(), kept)
                });
                let receipts = scope.spawn(move || crate::hotstuff_consensus::gov5_receipt_root_bloom(receipts));
                // `N42_HASHED_TABLES=off` (stage 6c): the tables this post-state is written to are
                // not written, and QMDB answers the reads they served.
                let hashed = if n42_qmdb_reth::n42_state::hashed_tables_off() {
                    Ok(Default::default())
                } else {
                    parent_state_ref().and_then(|state_provider| state_provider.hashed_post_state(bundle_ref))
                };
                let prepared = root.join().map_err(|_| "the QMDB root job panicked");
                let roots = receipts.join().map_err(|_| "the receipts root job panicked");
                (hashed, prepared, roots)
            });
            // After `state_ready`: a panicked job fails the build in the
            // store too, so a child build waiting on it is told at once.
            let panicked = |err: &str| {
                crate::built_executions::fail(block_hash);
                PayloadBuilderError::other(std::io::Error::other(err.to_owned()))
            };
            let (prepared, root_started, root_ended, kept_ops) = prepared.map_err(panicked)?;
            let roots = roots.map_err(panicked)?;
            let hashed_state = hashed_state.map_err(PayloadBuilderError::other)?;
            root_started_at = Some(root_started);
            root_ended_at = Some(root_ended);
            let published_at = std::time::Instant::now();
            let fields = publish(prepared, roots, execution_result.gas_used)?;
            root_publish_us.set(published_at.elapsed().as_micros() as u64);
            early_inputs = kept_ops.map(|ops| crate::fields_at_seal::EarlyInputs {
                fields,
                ops,
                parent_root: parent_root_early,
            });
            roots_ms = roots_at.elapsed().as_millis() as u64;
            root_split = qmdb_state.take_root_split(&parent_sealed).unwrap_or_default();
            (execution_output, hashed_state)
                }
                Some(shards) => {
            shards_used = out_shards;
            // The residual is filed as it is, not copied: the root, the
            // hashed post-state and the merge below read it through the Arc.
            // (`N42_OUTPUT_INCREMENTAL=1`: the one the early output was filed
            // with.)
            let residual = match early_residual.take() {
                Some(residual) => residual,
                None => Arc::new(reth_execution_types::BlockExecutionOutput {
                    state: bundle,
                    result: reth_execution_types::BlockExecutionResult {
                        receipts: Vec::new(),
                        requests: Default::default(),
                        gas_used: 0,
                        blob_gas_used: 0,
                    },
                }),
            };
            crate::built_executions::shards_ready(
                block_hash,
                crate::built_executions::ShardedParent { residual: Arc::clone(&residual), shards: Arc::clone(&shards) },
            );
            // The child's open proceeded at the early filing when there was
            // one; this filing is the frozen set's.
            match early_ready {
                Some((ms, at)) => {
                    shard_ready_ms = ms;
                    shards_ready_at = Some(at);
                    shards_final_at = Some(std::time::Instant::now());
                }
                None => {
                    shard_ready_ms = finish_at.elapsed().as_millis() as u64;
                    shards_ready_at = Some(std::time::Instant::now());
                }
            }
            give_back_now!();
            let shard_reverts = std::mem::take(&mut par_reverts);
            // `N42_MERGE_AT_SHARDS_READY=1`: every input of the merge is in
            // hand now (the shards frozen, the residual taken, the graft's
            // reverts): it starts here on its own pool instead of after the
            // fields' publication on one thread. The receipts are not an
            // input (they join the merged bundle in the output below), and
            // `StateReady` and `Complete` stay where they are: after the
            // publication, which files this block's QMDB tree.
            type EarlyMerge = (reth_trie::bundle_state::BundleState, crate::output_shards::MergeSplit, u64, u32, std::time::Instant, std::time::Instant, Option<LateRevertsTx>);
            let (early_merge, shard_reverts): (Option<std::thread::JoinHandle<EarlyMerge>>, _) =
                match crate::output_shards::merge_at_shards_ready().then(crate::output_shards::merge_pool).flatten() {
                    Some(pool) => {
                        let (shards, residual) = (Arc::clone(&shards), Arc::clone(&residual));
                        let threads = u32::try_from(pool.current_num_threads()).unwrap_or(u32::MAX);
                        // The graft's reverts reach the thread through a
                        // cell, so a thread that cannot be had leaves them
                        // here for the merge after the publication.
                        let reverts_cell = Arc::new(std::sync::Mutex::new(Some(shard_reverts)));
                        let cell = Arc::clone(&reverts_cell);
                        let spawned = std::thread::Builder::new().name("n42-merge-early".into()).spawn(move || {
                            n42_core_layout::background_thread();
                            let reverts = cell.lock().ok().and_then(|mut cell| cell.take()).unwrap_or_default();
                            let merge_at = std::time::Instant::now();
                            // `N42_ANSWER_BEFORE_REVERTS`: the account half
                            // here, the revert set beside it on a thread of
                            // its own (on the same pool).
                            let (reverts, late) = match n42_deferred_reverts::answer_before_reverts() {
                                true => spawn_late_reverts(&shards, &residual.state, reverts, Some(pool)),
                                false => (reverts, None),
                            };
                            if late.is_some() {
                                let (merged, state_us) = shards.merged_state_first(&residual.state, Some(pool));
                                let merge_end = std::time::Instant::now();
                                let total_us = merge_end.duration_since(merge_at).as_micros() as u64;
                                let split = crate::output_shards::MergeSplit { state_us, total_us, ..Default::default() };
                                return (merged, split, 0, threads, merge_at, merge_end, late);
                            }
                            let (mut merged, split) = shards.merged_on(&residual.state, pool);
                            let tail_at = std::time::Instant::now();
                            crate::parallel_transfer::append_reverts(&mut merged, reverts);
                            let merge_end = std::time::Instant::now();
                            let tail_us = merge_end.duration_since(tail_at).as_micros() as u64;
                            (merged, split, tail_us, threads, merge_at, merge_end, None)
                        });
                        match spawned {
                            Ok(handle) => (Some(handle), Vec::new()),
                            Err(err) => {
                                tracing::warn!(target: "payload_builder", %err, "no thread for the early merge; it runs after the fields' publication");
                                let back = reverts_cell.lock().ok().and_then(|mut cell| cell.take()).unwrap_or_default();
                                (None, back)
                            }
                        }
                    }
                    None => (None, shard_reverts),
                };
            let residual_state = &residual.state;
            let overlaps = shards.overlaps(residual_state);
            let view = shards.view(residual_state, &overlaps);
            view_ready_at = Some(std::time::Instant::now());
            let destroyed = crate::output_shards::any_destroyed(&view);
            let hashed_off = n42_qmdb_reth::n42_state::hashed_tables_off();
            let view_ref = &view;
            let publish_ref = &publish;
            // The order behind the seal (BREAKTHROUGH_DESIGN 10.16): the QMDB
            // root and the receipts root, then their publication -- all the
            // child's header needs -- then the merge. The merge sat between
            // the root and its publication (ec04b9322) and the child's seal
            // waited ~35 ms longer for a root already computed (loop279
            // sealed_at 131-135 against 119); beside the root (loop278) it
            // took the root's cores. Now it starts after the publication on a
            // thread of its own -- not the build pool (the child's execution
            // and fold run there, 10.11), not this thread (the hashed
            // post-state and the hand-off), not the QMDB root job's -- and
            // only `StateReady` and `Complete` (the engine's hand-off) wait
            // for it.
            let scoped = std::thread::scope(|scope| -> Result<_, PayloadBuilderError> {
                let receipts = scope.spawn(move || {
                    let mut execution_result = execution_result;
                    // `N42_SHARDS_BEFORE_RECEIPTS`: the receipts join the
                    // block's result here, after the shards were filed.
                    let joined_at = std::time::Instant::now();
                    if let Some(handle) = receipts_late {
                        let (receipts, gas_used) = handle.join().map_err(|_| ())?;
                        execution_result.receipts = receipts;
                        execution_result.gas_used = gas_used;
                    }
                    let late_wait = joined_at.elapsed();
                    let roots = crate::hotstuff_consensus::gov5_receipt_root_bloom(&execution_result.receipts);
                    Ok::<_, ()>((execution_result, roots, late_wait))
                });
                let qmdb_job = &qmdb_state;
                let ahead = ops_ahead.take();
                let shards_ref = &shards;
                let overlaps_ref = &overlaps;
                // `N42_ROOT_OPS_BEFORE_GATE=1`: the job starts before the
                // rename below and waits on `gate` only for the apply.
                let before_gate = root_ops_before_gate();
                let (gate_open, gate) = std::sync::mpsc::sync_channel::<()>(1);
                let root_body = move || {
                    // The leader's QMDB root job: on the critical set.
                    let spawned = std::time::Instant::now();
                    n42_core_layout::enter(n42_core_layout::Set::Critical);
                    // `N42_ROOT_OPS_AHEAD=1`: the shards' operations encoded
                    // beside the finish; the residual's added here. A job
                    // that failed, or ran under another Prague flag, leaves
                    // the whole encode to this one.
                    let finished = ahead.and_then(|(job, ahead_prague)| {
                        let joined_at = std::time::Instant::now();
                        let (ahead, done_at) = job.join().ok().filter(|_| ahead_prague == prague)?;
                        let waited = joined_at.elapsed();
                        let finish_at = std::time::Instant::now();
                        let replaced: Vec<(&alloy_primitives::Address, &reth_trie::bundle_state::BundleAccount)> = residual_state
                            .state
                            .keys()
                            .filter_map(|address| shards_ref.get(address).map(|account| (address, account)))
                            .collect();
                        let newer: Vec<(&alloy_primitives::Address, &reth_trie::bundle_state::BundleAccount)> = residual_state
                            .state
                            .iter()
                            .filter(|(address, _)| !shards_ref.holds(address))
                            .chain(overlaps_ref.iter().map(|(address, account)| (address, account)))
                            .collect();
                        let split = n42_qmdb_reth::OpsSplit {
                            encode_us: ahead.encode_us,
                            concat_us: 0,
                            sort_us: ahead.sort_us,
                        };
                        let ops = ahead.finish(&replaced, &newer, prague);
                        Some((
                            ops,
                            split,
                            OpsAheadUse { waited, finish: finish_at.elapsed(), done_at: Some(done_at), ..Default::default() },
                        ))
                    });
                    let (ops, split, mut ahead_use) = match finished {
                        Some(finished) => finished,
                        None => {
                            let (ops, split) = n42_qmdb_reth::sorted_operations_from_accounts_timed(view_ref, prague);
                            (ops, split, OpsAheadUse::default())
                        }
                    };
                    let kept = verify_fields.then(|| ops.clone());
                    let ops_done = std::time::Instant::now();
                    // Before the gate, the operations are sorted and their
                    // leaf hashes taken here (what the leased compute does
                    // before its lease under `N42_QMDB_PARALLEL_APPLY`): none
                    // of it reads the parent's tree or fields.
                    let (ops, leaves) = if before_gate {
                        let mut ops = ops;
                        let leaves = n42_qmdb_reth::sort_and_hash_leaves(&mut ops);
                        (ops, leaves)
                    } else {
                        (ops, None)
                    };
                    let started = if before_gate {
                        let head_done = std::time::Instant::now();
                        // The rename failed (its sender dropped): no apply.
                        gate.recv().ok()?;
                        let opened = std::time::Instant::now();
                        ahead_use.pre_gate = head_done.duration_since(spawned);
                        ahead_use.gate_wait = opened.duration_since(head_done);
                        opened
                    } else {
                        spawned
                    };
                    let prepared = qmdb_job.compute_operations_with_leaves(parent_sealed, ops, leaves);
                    let ended = std::time::Instant::now();
                    // The operations' phase is its own length whichever side
                    // of the gate it ran; the compute is the apply after it.
                    let compute_from = if before_gate { started } else { ops_done };
                    let timed = (split, ops_done.duration_since(spawned), ended.duration_since(compute_from), ahead_use);
                    Some((prepared, started, ended, kept, timed))
                };
                let mut root_body = Some(root_body);
                let early_root = if before_gate { root_body.take().map(|body| scope.spawn(body)) } else { None };
                rename_parent()?;
                // Opens the gate; with the flag off nothing waits on it.
                let _ = gate_open.send(());
                let parent_root_early = verify_fields.then(|| qmdb_state.root_of(&parent_sealed)).flatten();
                let roots_from = std::time::Instant::now();
                let root = match early_root {
                    Some(root) => root,
                    None => scope.spawn(root_body.take().ok_or_else(|| {
                        PayloadBuilderError::other(std::io::Error::other("the QMDB root job was not spawned"))
                    })?),
                };
                // The hashed post-state beside the root on a thread of its
                // own, so the publication does not wait for it. A destroyed
                // account's storage is zeroed from the database: the
                // provider's own path, on the merged bundle, below.
                let hashed = (!hashed_off && !destroyed)
                    .then(|| scope.spawn(move || crate::output_shards::hashed_post_state_of(view_ref)));
                let (prepared, root_started, root_ended, kept_ops, ops_timed) =
                    root.join().ok().flatten().ok_or_else(|| {
                        PayloadBuilderError::other(std::io::Error::other("the QMDB root job panicked"))
                    })?;
                let (execution_result, roots, late_wait) = receipts.join().ok().and_then(Result::ok).ok_or_else(|| {
                    PayloadBuilderError::other(std::io::Error::other("the receipts root (or the late receipts) panicked"))
                })?;
                receipts_late_wait_us.set(late_wait.as_micros() as u64);
                let published_at = std::time::Instant::now();
                let fields = publish_ref(prepared, roots, execution_result.gas_used)?;
                root_publish_us.set(published_at.elapsed().as_micros() as u64);
                let early = kept_ops.map(|ops| crate::fields_at_seal::EarlyInputs {
                    fields,
                    ops,
                    parent_root: parent_root_early,
                });
                let roots_ms = roots_from.elapsed().as_millis() as u64;
                let shards = Arc::clone(&shards);
                let residual = Arc::clone(&residual);
                let recovered = recovered.clone();
                let merger = std::thread::Builder::new()
                    .name("n42-shard-merge".into())
                    .spawn(move || {
                        n42_core_layout::background_thread();
                        // Every input is in hand when this thread starts (the
                        // shards frozen, the residual taken, the publication
                        // done): the merge waits for nothing, and its phases
                        // say where its wall goes (`merge_*` on the line).
                        // With the early merge it only takes that merge's
                        // result, waiting for it if it is still running.
                        let joined_at = std::time::Instant::now();
                        let early = early_merge.map(|handle| {
                            handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                        });
                        let join_wait_us = early.as_ref().map_or(0, |_| joined_at.elapsed().as_micros() as u64);
                        // `N42_MERGE_ELIDE`: no account map at all -- the
                        // thin bundle, the shards registered under it below.
                        let mut elided = false;
                        let (merged, split, tail_us, threads, merge_at, merge_end, was_early, late) = match early {
                            Some((merged, split, tail_us, threads, merge_at, merge_end, late)) => {
                                (merged, split, tail_us, threads, merge_at, merge_end, true, late)
                            }
                            None if n42_deferred_reverts::answer_before_reverts() => {
                                // `N42_ANSWER_BEFORE_REVERTS`: the account
                                // half, the revert set beside it.
                                let merge_at = std::time::Instant::now();
                                let (graft, late) = spawn_late_reverts(&shards, &residual.state, shard_reverts, None);
                                let elide = crate::output_shards::merge_elide()
                                    && n42_sharded_output::refused().is_none()
                                    && !shards.is_early();
                                let (merged, split) = match late {
                                    Some(_) if elide => {
                                        elided = true;
                                        let merged = shards.thin_state_first(&residual.state);
                                        let total_us = merge_at.elapsed().as_micros() as u64;
                                        (merged, crate::output_shards::MergeSplit { total_us, ..Default::default() })
                                    }
                                    Some(_) => {
                                        let (merged, state_us) = shards.merged_state_first(&residual.state, None);
                                        let total_us = merge_at.elapsed().as_micros() as u64;
                                        (merged, crate::output_shards::MergeSplit { state_us, total_us, ..Default::default() })
                                    }
                                    None => {
                                        let (mut merged, split) = shards.merged_timed(&residual.state, false);
                                        crate::parallel_transfer::append_reverts(&mut merged, graft);
                                        (merged, split)
                                    }
                                };
                                let merge_end = std::time::Instant::now();
                                (merged, split, 0, 1, merge_at, merge_end, false, late)
                            }
                            None => {
                                // `N42_MERGE_SPLIT=1`: the account map and the
                                // revert set at once, on two threads; the same
                                // bundle (`merged_timed`).
                                let concurrent = crate::output_shards::merge_split();
                                let merge_at = std::time::Instant::now();
                                let (mut merged, split) = shards.merged_timed(&residual.state, concurrent);
                                let tail_at = std::time::Instant::now();
                                crate::parallel_transfer::append_reverts(&mut merged, shard_reverts);
                                let merge_end = std::time::Instant::now();
                                let tail_us = merge_end.duration_since(tail_at).as_micros() as u64;
                                let threads = if concurrent { 2 } else { 1 };
                                (merged, split, tail_us, threads, merge_at, merge_end, false, None)
                            }
                        };
                        let merge_ms = merge_end.duration_since(merge_at).as_millis() as u64;
                        let timing = LeaderMerge {
                            started: Some(merge_at),
                            ended: Some(merge_end),
                            split,
                            tail_us,
                            threads,
                            accounts: if elided {
                                n42_sharded_output::accounts(Some(&*shards), &merged)
                            } else {
                                merged.state.len()
                            },
                            reverts: merged.reverts.iter().map(Vec::len).sum(),
                            state_ready: None,
                            early: was_early,
                            join_wait_us,
                            register: Default::default(),
                            state_ready_call_us: 0,
                        };
                        let execution_output =
                            Arc::new(reth_execution_types::BlockExecutionOutput { state: merged, result: execution_result });
                        // Elided: its accounts are read through the shards
                        // (`n42_sharded_output`), registered before anyone
                        // can see the execution.
                        if elided {
                            n42_sharded_output::register(&execution_output, Arc::clone(&shards) as n42_sharded_output::Shards);
                        }
                        // Owed its revert set (`N42_ANSWER_BEFORE_REVERTS`):
                        // registered before anyone can see the execution,
                        // and the promise handed to the thread that merges it.
                        let mut register_timing = n42_deferred_reverts::RegisterTiming::default();
                        if let Some(late) = late {
                            let (promise, timed) = n42_deferred_reverts::register_timed(&execution_output);
                            register_timing = timed;
                            if let Err(std::sync::mpsc::SendError(promise)) = late.send(promise) {
                                drop(promise);
                            }
                        }
                        let state_ready_call = std::time::Instant::now();
                        crate::built_executions::state_ready(
                            block_hash,
                            crate::built_executions::BuiltExecution {
                                block: recovered,
                                execution_output: Arc::clone(&execution_output),
                                hashed_state: Arc::new(Default::default()),
                                trie_updates: Arc::new(TrieUpdates::default()),
                            },
                        );
                        // The entries of blocks that left memory go (their
                        // shards freed here, off the build's path), also
                        // after a refusal at run time stopped new ones.
                        if crate::output_shards::merge_elide() {
                            n42_sharded_output::sweep();
                        }
                        let timing = LeaderMerge {
                            state_ready: Some(std::time::Instant::now()),
                            register: register_timing,
                            state_ready_call_us: state_ready_call.elapsed().as_micros() as u64,
                            ..timing
                        };
                        (execution_output, merge_ms, finish_at.elapsed().as_millis() as u64, timing)
                    })
                    .map_err(PayloadBuilderError::other)?;
                let hashed = match hashed {
                    Some(hashed) => Some(hashed.join().map_err(|_| {
                        PayloadBuilderError::other(std::io::Error::other("the hashed post-state panicked"))
                    })?),
                    None if hashed_off => Some(Default::default()),
                    None => None,
                };
                Ok((merger, hashed, roots_ms, (root_started, root_ended), early, ops_timed))
            });
            let (merger, hashed, shard_roots_ms, (root_started, root_ended), early, ops_timed) = scoped?;
            root_started_at = Some(root_started);
            root_ended_at = Some(root_ended);
            early_inputs = early;
            root_ops = ops_timed;
            let (execution_output, merge_ms, filed_ms, merge_timing) = merger.join().map_err(|_| {
                PayloadBuilderError::other(std::io::Error::other("the shards' merge panicked"))
            })?;
            leader_merge = merge_timing;
            let hashed_state = match hashed {
                Some(hashed) => hashed,
                None => parent_state_ref()
                    .and_then(|state_provider| state_provider.hashed_post_state(&execution_output.state))
                    .map_err(PayloadBuilderError::other)?,
            };
            shard_merge_ms = merge_ms;
            roots_ms = shard_roots_ms;
            root_split = qmdb_state.take_root_split(&parent_sealed).unwrap_or_default();
            state_ready_ms = filed_ms;
            (execution_output, hashed_state)
                }
            };
            let late_output = early_inputs.as_ref().map(|_| Arc::clone(&execution_output));
            let complete_at = std::time::Instant::now();
            crate::built_executions::complete(
                block_hash,
                crate::built_executions::BuiltExecution {
                    block: recovered,
                    execution_output,
                    hashed_state: Arc::new(hashed_state),
                    trie_updates: Arc::new(TrieUpdates::default()),
                },
            );
            build_stage.at(7);
            // `N42_FIELDS_AT_SEAL=verify`: behind `Complete`, so neither the
            // child's seal nor the engine's hand-off waits for it. The late
            // derivation: the operations from the merged bundle, the parent's
            // root after the parent's own `Complete` (where the rename used
            // to wait), and the receipts root and gas from the merged output.
            if let (Some(early), Some(output)) = (early_inputs.take(), late_output) {
                if let Some(built) = parent_built.filter(|built| *built != parent_sealed) {
                    let _ = crate::built_executions::wait_for(built, crate::built_executions::Stage::Complete);
                }
                let late = crate::fields_at_seal::LateInputs {
                    ops: n42_qmdb_reth::sorted_operations_from_execution(&output.state, prague),
                    parent_root: qmdb_state.root_of(&parent_sealed),
                    receipts: crate::hotstuff_consensus::gov5_receipt_root_bloom(&output.result.receipts),
                    gas_used: output.result.gas_used,
                };
                let verdict = crate::fields_at_seal::compare(&early, &late);
                crate::fields_at_seal::note(&verdict);
                if let crate::fields_at_seal::Verdict::Differ(differ) = &verdict {
                    tracing::error!(
                        target: "payload_builder",
                        number = block_number,
                        %block_hash,
                        ?differ,
                        "the fields published at the seal differ from the late derivation"
                    );
                }
            }
            if tx_count >= 1000 {
                let (queued, usable, parked) = queue_depth();
                // `N42_READ_DEPTH_COUNTS=1`: how many of this block's account
                // reads the parent's overlay answered at each depth of its own
                // executed-block stack versus falling through to the
                // historical provider (plan v6 6.4, `crate::direct_build::read_depth`).
                let read_depth = crate::direct_build::read_depth::snapshot();
                let overlay_depth = crate::direct_build::read_depth::overlay_depth();
                // `N42_PHASE_TIMERS=1`: the layered overlay's blocks skipped on
                // their address filters and bundles probed since the last line
                // (the process's, so a follower import in between counts too).
                let (overlay_filter_skips, overlay_probes) = if crate::parallel_common::phase_timers() {
                    reth_provider::providers::overlay_filter::take_counters()
                } else {
                    (0, 0)
                };
                let (overlay_filter_builds, overlay_filter_cached) =
                    reth_provider::providers::overlay_filter::filter_stats();
                // The QMDB view's reads that stood behind its head (or met a
                // block being indexed) since the last line, the journals they
                // binary-searched and those their filters skipped
                // (`N42_VIEW_JOURNAL_FILTER`): whether the reads walk journals
                // at all, and how deep (the process's, folded per 4,096 reads).
                let (view_journal_reads, view_journal_searches, view_journal_skips) =
                    n42_qmdb_reth::read_view::take_journal_counters();
                let prev_road = crate::post_seal::road_us(parent_header.number);
                tracing::info!(
                    target: "payload_builder",
                    number = block_number,
                    txs = tx_count,
                    queued,
                    usable,
                    parked,
                    setup_ms = setup_took.as_millis() as u64,
                    par_ms,
                    par_pull_ms,
                    par_exec_ms,
                    direct_receipts = direct_receipts_used,
                    par_fold_ms,
                    tx_root_ms = root_ms,
                    parent_fields_ms = fields_ms,
                    // The same wait in us and what it waited on: "ready"
                    // (no wait), or the carried ancestor's missing half --
                    // "state_root" (its QMDB root behind its seal),
                    // "receipts", "both", "no_built".
                    parent_fields_us,
                    parent_fields_wait_on,
                    // `par_ms` split at the seal: on the seal's chain and
                    // behind it (the fold), us; and of the batches' start,
                    // the hook (state open + pre-execution changes).
                    par_to_seal_us,
                    // The parallel step's end to the finish's start and to
                    // the shards' filing, and the steps between them: the
                    // step's scope drop (the pulled set), the give-backs, the
                    // puller's drop.
                    pulled_drop_us,
                    giveback_us,
                    puller_drop_us,
                    seal_lookahead_us,
                    seal_puller_join_us,
                    puller_at_pull,
                    evm2_pre_exec_us,
                    evm2_open_us,
                    evm2_prepared_us,
                    evm2_prepared_miss = %evm2_prepared_miss,
                    evm2_keys_us,
                    evm2_shards_new_us,
                    evm2_setup_us,
                    evm2_fees_us,
                    evm2_batch_reads_us = evm2_inside.reads_us,
                    evm2_batch_reads_sampled = evm2_inside.reads_sampled,
                    evm2_batch_transact_us = evm2_inside.transact_us,
                    evm2_batch_commit_us = evm2_inside.commit_us,
                    evm2_batch_shard_add_us = evm2_inside.shard_add_us,
                    evm2_exec_before_us = evm2_inside.before_us,
                    evm2_exec_gather_us = evm2_inside.gather_us,
                    evm2_exec_merge_us = evm2_inside.merge_us,
                    evm2_direct_hits = evm2_inside.direct_hits,
                    evm2_direct_delegated = evm2_inside.direct_delegated,
                    state_pre_changes_us,
                    sealed_ms,
                    sealed_at_ms,
                    merge_ms,
                    state_ready_ms,
                    roots_ms,
                    // The finish behind the seal, us from the seal (11.8's
                    // uninstrumented ~80 ms): the finish's start, the bundle
                    // taken, the shard view built (0 without shards), the
                    // parent's tree renamed (and of it, the wait for the
                    // parent's `Complete`), this block's QMDB root job's
                    // start and end, and its fields published.
                    // `N42_FIELDS_AT_SEAL`: the mode, whether the rename took
                    // the early path, and under `verify` the process's
                    // blocks found equal / unchecked / different.
                    seal_to_finish_us = crate::fields_at_seal::us_between(sealed_instant, Some(finish_at)),
                    seal_to_bundle_us = crate::fields_at_seal::us_between(sealed_instant, Some(bundle_taken_at)),
                    seal_to_view_us = crate::fields_at_seal::us_between(sealed_instant, view_ready_at),
                    // The shards filed (`shards_ready`): what the child's
                    // open waits for (`docs/SHARED_EXECUTION_SCOPE.md` 18.2).
                    seal_to_shards_ready_us = crate::fields_at_seal::us_between(sealed_instant, shards_ready_at),
                    // `N42_OUTPUT_INCREMENTAL=1`: the shards were filed on the
                    // early output (the time above), and the frozen set later.
                    output_incremental = shards_final_at.is_some(),
                    seal_to_shards_final_us = crate::fields_at_seal::us_between(sealed_instant, shards_final_at),
                    // `N42_SHARDS_BEFORE_RECEIPTS`: the receipts were built
                    // past the shards' filing, and how long their root then
                    // waited for them.
                    receipts_late = receipts_late_used,
                    receipts_late_wait_us = receipts_late_wait_us.get(),
                    seal_to_rename_us = crate::fields_at_seal::us_between(sealed_instant, renamed_at.get()),
                    rename_wait_us = rename_wait_us.get(),
                    seal_to_root_start_us = crate::fields_at_seal::us_between(sealed_instant, root_started_at),
                    seal_to_root_end_us = crate::fields_at_seal::us_between(sealed_instant, root_ended_at),
                    seal_to_fields_us = crate::fields_at_seal::us_between(sealed_instant, fields_published_at.get()),
                    fields_at_seal = fields_mode.label(),
                    rename_early = rename_early.get(),
                    fields_verified = crate::fields_at_seal::counts().0,
                    fields_unchecked = crate::fields_at_seal::counts().1,
                    fields_mismatches = crate::fields_at_seal::counts().2,
                    rename_record_waits = crate::fields_at_seal::barrier_counts().0,
                    rename_fallbacks = crate::fields_at_seal::barrier_counts().1,
                    carried_depth,
                    finish_ms = finish_at.elapsed().as_millis() as u64,
                    total_ms = build_started.elapsed().as_millis() as u64,
                    reads_d0 = read_depth[0],
                    reads_d1 = read_depth[1],
                    reads_d2 = read_depth[2],
                    reads_d3 = read_depth[3],
                    reads_d4_7 = read_depth[4],
                    reads_d8_15 = read_depth[5],
                    reads_d16p = read_depth[6],
                    reads_hist = read_depth[7],
                    overlay_depth,
                    overlay_filter_skips,
                    overlay_probes,
                    overlay_filter_builds,
                    overlay_filter_cached,
                    view_journal_reads,
                    view_journal_searches,
                    view_journal_skips,
                    // `N42_PHASE_TIMERS=1` (plan v6 6.5/6.6): where the
                    // parallel step's wall time (`par_exec_ms` above) goes
                    // inside `N42Evm::transfer`, which door each account read
                    // took, and the graft's own sub-phases (the default
                    // in-place fold only). Zero when the flag is off.
                    // `N42_READ_SET=1`: the pass (inside `par_exec_ms`), its
                    // accounts, the batches' reads it answered and those that
                    // fell to the parent's state. Zero when the flag is off.
                    // Each batch's wall on the pool, start to end (always on).
                    batch_max_ms = par_batch_spans.max_ms,
                    batch_min_ms = par_batch_spans.min_ms,
                    batch_median_ms = par_batch_spans.median_ms,
                    batch_cpu_max_ms = par_batch_spans.cpu_max_ms,
                    batch_txs_max = par_batch_spans.txs_max,
                    batch_txs_min = par_batch_spans.txs_min,
                    batch_start_skew_ms = par_batch_spans.start_skew_ms,
                    batch_wait_ms = par_batch_spans.wait_ms,
                    // Every batch's wall and thread CPU summed (us), and the
                    // batches' own minor faults and voluntary / involuntary
                    // context switches (`ThreadMark`): what the off-CPU part
                    // of a batch is -- first touches, blocking, preemption.
                    batch_wall_sum_us = par_batch_spans.wall_sum_us,
                    batch_cpu_sum_us = par_batch_spans.cpu_sum_us,
                    batch_minflt = par_batch_spans.minflt,
                    batch_vcsw = par_batch_spans.vcsw,
                    batch_ivcsw = par_batch_spans.ivcsw,
                    live_index_defer = crate::output_shards::live_index_defer(),
                    // Where a batch can block (SHARED_EXECUTION_SCOPE 14):
                    // major faults (a file page read from disk); reads that
                    // waited for the QMDB read view's reader slot (a publish)
                    // or offset-index shard (an advance's writes), count and
                    // us; the live-index hand-over's blocked shard locks,
                    // the time blocked, the time held, the shards left to
                    // the freeze (`N42_LIVE_INDEX_DEFER=1`); the opens of the
                    // parent's view, us summed and the longest.
                    batch_majflt = par_batch_spans.majflt,
                    batch_view_slot_waits = par_batch_spans.view_slot_waits,
                    batch_view_slot_wait_us = par_batch_spans.view_slot_wait_us,
                    batch_view_index_waits = par_batch_spans.view_index_waits,
                    batch_view_index_wait_us = par_batch_spans.view_index_wait_us,
                    batch_live_lock_waits = par_batch_spans.live_lock_waits,
                    batch_live_lock_wait_us = par_batch_spans.live_lock_wait_us,
                    batch_live_lock_hold_us = par_batch_spans.live_lock_hold_us,
                    batch_live_deferred = par_batch_spans.live_deferred,
                    batch_open_sum_us = par_batch_spans.open_sum_us,
                    batch_open_max_us = par_batch_spans.open_max_us,
                    // The dispatch, us from the batches' hand-over to the pool:
                    // the first and the last batch's start, the moment every
                    // thread that ran one had started its first (two waves:
                    // `batch_last_start_us` less this is the first wave), the
                    // last batch's end; the batches and the threads that ran
                    // them; `N42_BUILD_ONE_WAVE`.
                    batch_first_start_us = par_batch_spans.first_start_us,
                    batch_last_start_us = par_batch_spans.last_start_us,
                    batch_dispatch_us = par_batch_spans.dispatch_us,
                    batch_last_end_us = par_batch_spans.last_end_us,
                    batches = par_batch_spans.batches,
                    batch_threads = par_batch_spans.threads,
                    one_wave = crate::parallel_transfer::build_one_wave(),
                    // `N42_BUILD_BATCHES`: batches asked for, largest first (0 off).
                    build_batches = crate::parallel_transfer::build_batches(),
                    // `N42_PHASE_TIMERS=1`: the batch loop by section, ns of
                    // pool time a transaction (`LoopTimers`); zero when off.
                    // `N42_OUTPUT_SHARDS` (docs/BREAKTHROUGH_DESIGN.md section
                    // 3): the shard count (0 off, or folded after all), the
                    // batches' pool time splitting their accounts by range
                    // (inside `par_exec_ms`), the fold's wall time building
                    // the shard maps a task a shard, when the next build was
                    // let go on them (from the finish's start), and the merge
                    // into the block's one bundle beside the roots (which
                    // read the shards). The insert/wait keys of the first,
                    // locked shape stay at 0.
                    shards = shards_used,
                    shard_insert_ms = 0u64,
                    shard_wait_ms = 0u64,
                    shard_append_ms,
                    shard_fold_ms,
                    shard_ready_ms,
                    shard_merge_ms,
                    // The leader's merge into the block's one bundle
                    // (SHARED_EXECUTION_SCOPE 15), us from the seal: its
                    // thread's start (every input is ready by then: it is
                    // spawned after the fields' publication), its end,
                    // `StateReady` filed, `Complete` filed (the engine's
                    // hand-off; it also waits for the hashed post-state);
                    // its halves (the account map, the revert set copied and
                    // sorted, the sorted reverts appended, the graft's
                    // reverts appended after), the threads it ran on, and
                    // the accounts and reverts it copied.
                    seal_to_merge_start_us = crate::fields_at_seal::us_between(sealed_instant, leader_merge.started),
                    seal_to_merge_end_us = crate::fields_at_seal::us_between(sealed_instant, leader_merge.ended),
                    seal_to_state_ready_us = crate::fields_at_seal::us_between(sealed_instant, leader_merge.state_ready),
                    seal_to_complete_us = crate::fields_at_seal::us_between(sealed_instant, Some(complete_at)),
                    merge_state_us = leader_merge.split.state_us,
                    merge_reverts_us = leader_merge.split.reverts_us,
                    merge_append_us = leader_merge.split.append_us,
                    merge_tail_us = leader_merge.tail_us,
                    // The output registry's `register` (N42_ANSWER_BEFORE_REVERTS):
                    // the lock's wait, its hold, and the eviction's free under it.
                    register_wait_us = leader_merge.register.wait_us,
                    register_lock_us = leader_merge.register.lock_us,
                    register_free_us = leader_merge.register.free_us,
                    register_evicted = leader_merge.register.evicted,
                    state_ready_call_us = leader_merge.state_ready_call_us,
                    merge_threads = leader_merge.threads,
                    merge_accounts = leader_merge.accounts,
                    merge_reverts = leader_merge.reverts,
                    // `N42_MERGE_AT_SHARDS_READY`: the merge ran from the
                    // shards' filing on its own pool, and how long the
                    // merger (after the fields' publication) waited for it.
                    merge_early = leader_merge.early,
                    merge_join_wait_us = leader_merge.join_wait_us,
                    // The shard path's QMDB root job, us: its operations
                    // (the leaves encoded on the global pool, the chunks
                    // joined, the sort) and the forest's compute (the lock,
                    // the move, the apply -- `root_apply_total_us` -- the
                    // note and the delta).
                    root_ops_us = root_ops.1.as_micros() as u64,
                    root_ops_encode_us = root_ops.0.encode_us,
                    root_ops_concat_us = root_ops.0.concat_us,
                    root_ops_sort_us = root_ops.0.sort_us,
                    root_compute_us = root_ops.2.as_micros() as u64,
                    // `N42_ROOT_OPS_AHEAD=1`: whether the root job finished
                    // operations encoded ahead (the encode and sort above are
                    // then the ahead job's), when that job was done (us from
                    // the seal), the root job's wait for it, and its finish.
                    root_ops_ahead = root_ops.3.done_at.is_some(),
                    seal_to_ops_ahead_us = crate::fields_at_seal::us_between(sealed_instant, root_ops.3.done_at),
                    root_ops_ahead_wait_us = root_ops.3.waited.as_micros() as u64,
                    root_ops_finish_us = root_ops.3.finish.as_micros() as u64,
                    // `N42_ROOT_OPS_BEFORE_GATE=1`: the root job's work before
                    // the parent-fields gate and its wait there (0 when off).
                    root_pre_gate_us = root_ops.3.pre_gate.as_micros() as u64,
                    root_gate_wait_us = root_ops.3.gate_wait.as_micros() as u64,
                    // `N42_SEAL_AT_EXEC=1` (plan v6 G2): sealed at the parallel
                    // step's end with the fold behind the proposal; the
                    // transactions root computed over the pulled set beside
                    // the execution was the one sealed, and how long the
                    // step's end waited for it.
                    seal_at_exec = seal_at_exec_used,
                    give_back_ms,
                    // The seal gap (plan v6): see the declarations of these
                    // timers for how they sum to `sealed_at_ms`.
                    par_start_ms,
                    // From the parent's seal (this process's, the block just
                    // before) to this build's start and to its entry into
                    // `build_on_own` (0 when not chained on an own seal):
                    // the leader's cycle outside every build's timers.
                    next_start_gap_ms = prev_road[4] / 1_000,
                    next_entry_gap_ms = prev_road[3] / 1_000,
                    // The same road in microseconds, with what lies between
                    // (`post_seal`): the parent's chain header and answer
                    // written to the validator, this build's request read,
                    // `build_on_own` entered, this build started, and the
                    // parent's first import request by header (at E=1 the
                    // leader key's, just after its proposal). 0 = not seen.
                    prev_seal_to_header_us = prev_road[0],
                    prev_seal_to_answer_us = prev_road[1],
                    prev_seal_to_request_us = prev_road[2],
                    prev_seal_to_entry_us = prev_road[3],
                    prev_seal_to_start_us = prev_road[4],
                    prev_seal_to_import_us = prev_road[5],
                    // This block's seal on the wall clock, to join the
                    // validator's `proposal sent` and `block committed` lines.
                    sealed_unix_us,
                    // Of `par_start_ms`: the selection (`best_txs`, which on a
                    // chained build waits for the parent's queue hand-off --
                    // `start_handoff_ms` of it -- and then takes the queue's
                    // lock for `best_for_build`), the decided/stale checks,
                    // the puller's thread, `cons.prepare`, and the rest.
                    start_best_ms,
                    start_handoff_ms,
                    handoff_hold_us,
                    evict_free_us,
                    // Of `start_best_ms` (`frame_blocks::SelectTimes`).
                    start_select_ms,
                    start_walk_ms,
                    start_walk_check_ms,
                    // Of `start_walk_ms`, us: the ids listed, the parallel
                    // check, the takes settled; the rest of the walk is the
                    // decisions in arrival order and the segments.
                    start_walk_ids_us = select_times.ids_us,
                    start_walk_check_us = select_times.check_us,
                    start_walk_settle_us = select_times.settle_us,
                    start_walk_us = select_times.walk_us,
                    start_pull_ms,
                    start_best_other_ms,
                    start_frames_by_ref = select_times.by_ref,
                    start_frames_slow = select_times.slow,
                    // The frames the plan passed over, the live frame
                    // index at this start, the frames that left it at a
                    // take since the previous start
                    // (`N42_FRAME_SWEEP_AT_TAKE`), and the frames it refused
                    // at its bound (since the process started).
                    start_frames_skipped = select_times.frames_skipped,
                    // Builds since the process started that found no frame
                    // to plan and walked the lanes, or refused to: after a
                    // flood's first full block the walked count must not move.
                    frame_builds_walked =
                        crate::frame_blocks::FRAME_BUILDS_WALKED.load(std::sync::atomic::Ordering::Relaxed),
                    frame_walk_refused = crate::frame_blocks::FRAME_BUILDS_WALK_REFUSED
                        .load(std::sync::atomic::Ordering::Relaxed),
                    start_frames_index = select_times.frames_index,
                    start_frames_swept_at_take = select_times.frames_swept_at_take,
                    start_frames_refused_at_cap = select_times.frames_refused_at_cap,
                    // `N42_PLAN_AHEAD`: 0 the plan was made at this start,
                    // 1 it was prepared while the parent executed, 2 and
                    // topped up here; its age at use, its preparation's
                    // time, the top-up's transactions, and why a prepared
                    // plan was discarded ("" when none was).
                    plan_ahead = select_times.ahead,
                    plan_age_us = select_times.ahead_age_us,
                    plan_prep_us = select_times.ahead_prep_us,
                    plan_topup_txs = select_times.ahead_topup_txs,
                    plan_discard = select_times.ahead_discard,
                    // `N42_PLAN_AHEAD_WAIT_MS`: how long this start waited
                    // for the continuously prepared plan, and whether the
                    // wait ran out before it was full.
                    plan_wait_us = select_times.ahead_wait_us,
                    plan_wait_timeout = select_times.ahead_wait_timeout,
                    // `N42_PULL_BY_FRAMES`: the block taken out of its
                    // frames at once (0 = through the puller) and how long.
                    pull_bulk_txs = select_times.bulk_txs,
                    pull_bulk_us = select_times.bulk_us,
                    start_check_ms,
                    start_puller_ms,
                    start_prepare_ms,
                    commit_body_ms,
                    commit_body_ahead_used,
                    // `N42_SEAL_ON_COUNTERS=1`: sealed on the batches'
                    // counters (no pass over the slots before the seal), and
                    // the batches' end to the seal's start, us.
                    exec_end_to_seal_us,
                    // `N42_PLAN_AHEAD_BODY=1`: the plan's body (0 none, 1
                    // used, 2 not ready, 3 not this build's) and its making
                    // time, us; whether the prep, the partition and the slots
                    // came with it; the partition's and the slots' time in
                    // the call, us; the hand-off noted as a whole take.
                    plan_body = select_times.body_ahead,
                    plan_body_us = select_times.body_ahead_us,
                    prep_from_plan,
                    exec_prepared_groups,
                    whole_take_noted,
                    seal_header_ms,
                    seal_block_ms,
                    seal_remember_ms,
                    seal_hook_ms,
                    seal_layout_ms,
                    seal_root_ms,
                    // The seal's hash vector came with the body (no collect).
                    seal_hashes_ahead,
                    // `N42_PLAN_AHEAD_PARTS=1`: the seal took the frame
                    // layout and root found with the plan.
                    seal_root_ahead,
                    seal_frames_indexed,
                    seal_frames_hashed,
                    index_ms,
                    // `N42_FREEZE_AFTER_SEAL=1`: the freeze ran on its own
                    // thread beside the commit and the seal (`index_ms` is then
                    // its own wall, off the seal's path), when it ended (us
                    // from the seal; 0 = before it), and how long its join
                    // behind the seal waited.
                    freeze_late = freeze_late_used,
                    // `N42_FREEZE_POOL=own`: the freeze, the receipts and the
                    // frees behind the seal ran on a pool of their own.
                    freeze_pool_own = crate::parallel_transfer::freeze_pool_own(),
                    seal_to_frozen_us = crate::fields_at_seal::us_between(sealed_instant, freeze_ended_at),
                    freeze_join_wait_us,
                    // Where the receipts job spent its time (us) and
                    // whether it ran fused (`N42_RECEIPTS_FUSED`).
                    receipts_fused = receipts_fused(),
                    // `N42_STATE_AFTER_PULL=1` (plan v6 G3): the parent's state
                    // opened after the pull, prep and partition, and the time
                    // inside that open (0 with the flag off: the open is then
                    // inside `setup_ms`).
                    state_after_pull = defer_state,
                    state_wait_ms,
                    state_wait_us,
                    state_wait_on = state_wait_label(state_wait_us, &state_wait_on),
                    state_wait_split = %state_wait_on.split(),
                    root_lock_wait_ms = root_split.lock_wait_ms,
                    root_lock_held_by = root_split.held_by,
                    root_move_ms = root_split.move_ms,
                    root_apply_ms = root_split.apply_ms,
                    root_hash_ms = root_split.hash_ms,
                    // The apply by phase and the tail after it, us
                    // (`RootSplit`): which of the root's pieces is serial.
                    root_sort_us = root_split.sort_us,
                    root_leaves_us = root_split.leaves_us,
                    root_retire_us = root_split.retire_us,
                    root_writes_us = root_split.writes_us,
                    root_index_us = root_split.index_us,
                    root_rehash_us = root_split.rehash_us + root_split.root_us,
                    // The two halves of `root_rehash_us`: the twigs' rehash
                    // (timed from the join with the index inserts) and the
                    // upper tree's refresh with the root read.
                    root_twig_rehash_us = root_split.rehash_us,
                    root_upper_us = root_split.root_us,
                    root_twigs = root_split.twigs,
                    root_dirty_twigs = root_split.dirty_twigs,
                    root_note_us = root_split.note_us,
                    root_delta_us = root_split.delta_us,
                    root_apply_total_us = root_split.apply_total_us,
                    // Of the apply (SHARED_EXECUTION_SCOPE 15): the undo
                    // record's lists inside `root_retire_us`, and what lies
                    // between the phases (`root_apply_total_us` less them: the
                    // sortedness check, the undo record's start, the scratch).
                    root_undo_us = root_split.undo_us,
                    root_apply_gap_us = root_split.apply_total_us.saturating_sub(
                        root_split.sort_us
                            + root_split.leaves_us
                            + root_split.retire_us
                            + root_split.writes_us
                            + root_split.index_us
                            + root_split.rehash_us
                            + root_split.root_us
                    ),
                    root_publish_ms = root_publish_us.get() / 1000,
                    root_faults = root_split.faults,
                    root_majflt = root_split.majflt,
                    root_twig_pool_misses = root_split.twig_pool_misses,
                    root_twig_pool_refills = root_split.twig_pool_refills,
                    root_append_faults = root_split.append_faults,
                    root_faults_entries = root_split.faults_entries,
                    root_faults_offsets = root_split.faults_offsets,
                    root_faults_index = root_split.faults_index,
                    root_faults_bits = root_split.faults_bits,
                    root_faults_twigs = root_split.faults_twigs,
                    root_faults_undo = root_split.faults_undo,
                    root_faults_tmp = root_split.faults_tmp,
                    root_append_behind = root_split.append_behind,
                    populate_lag_mb = root_split.populate_lag_mb,
                    root_seals = root_split.seals,
                    root_seal_ms = root_split.seal_ms,
                    core_layout = n42_core_layout::label(),
                    "seal-first build phases"
                );
            }
            Ok(())
            };
            let finished = behind_the_seal();
            // A finish that failed before the shards were filed still gives
            // back what it took.
            let late = give_backs.is_some();
            give_back_now!();
            if late {
                tracing::debug!(
                    target: "payload_builder",
                    number = block_number,
                    giveback_us,
                    puller_drop_us,
                    pulled_drop_us,
                    "the give-backs ran after a finish that ended before the shards were filed"
                );
            }
            return match finished {
                Ok(()) => {
                    let _ = cons.set_cached_reads(block_hash, cached_reads.clone());
                    Ok(BuildOutcome::Better { payload, cached_reads })
                }
                Err(err) => {
                    crate::built_executions::fail(block_hash);
                    tracing::error!(target: "payload_builder", number = block_number, %err, "the finish behind the seal FAILED; the block was proposed already");
                    Err(err)
                }
            };
        }
    }
    // Not sealable early: the hook goes unused and the caller waits for
    // the ordinary outcome. Dropped here, where the gate used to drop it.
    drop(early);
    // The shards are kept ungrafted only for a block the gate above seals
    // early (`sealing_early` with transactions implies it): one that reaches
    // here would finish on a state missing the block's accounts.
    if output_shards.is_some() {
        return Err(PayloadBuilderError::other(std::io::Error::other(
            "the block's output was left in its shards, but the block did not seal early",
        )));
    }
    // Receipts built for an early seal belong to its finish; this block's
    // executor committed none of those transactions, so it must not go on.
    if receipts_pending.is_some() {
        return Err(PayloadBuilderError::other(std::io::Error::other(
            "receipts were built for an early seal that did not happen",
        )));
    }
    // A parallel step that skipped a block's worth, on a build whose view is
    // suspect, never hands it to the serial loop (defect 15). loop237 (three
    // legs of four, the new leader's build ahead on its own first block of a
    // tenure): the step skipped all 163,000 candidates as gapped, and the
    // serial loop then executed 163,000 transfers one at a time -- 9.0 s
    // (`fast=163000 loop_ms=9025`) while the payload service, the next
    // view's forkchoice and the ingest gate waited on it and the followers
    // timed the view out. A build that built nothing declines, everything
    // taken given back: a build on an own block lets the consensus client
    // build the ordinary way on the imported parent, and a decided height
    // asks for nothing at all. `Aborted`, never `Cancelled` (defect 14). A
    // build that built some of it finishes with that and gives the rest back.
    let height_decided = crate::canonical_head::already_decided(header.number);
    let after_step = after_parallel_step_now(par_txs, par_skipped, par_budget, parent_state.is_some(), height_decided);
    let serial_closed = after_step != AfterParallelStep::Serial;
    if let AfterParallelStep::Finish(why) | AfterParallelStep::Decline(why) = after_step {
        tracing::info!(
            target: "payload_builder",
            number = header.number,
            parent = %parent_header.hash(),
            head = crate::canonical_head::number(),
            par_txs,
            par_skipped,
            par_budget,
            par_groups,
            direct = parent_state.is_some(),
            declined = matches!(after_step, AfterParallelStep::Decline(_)),
            why,
            "a parallel step skipped a block's worth; the serial loop is not entered"
        );
    }
    if matches!(after_step, AfterParallelStep::Decline(_)) {
        for pool_tx in lookahead.into_iter().rev() {
            refuse!(
                &pool_tx,
                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
            );
        }
        for pool_tx in deferred.into_iter().rev() {
            let err = deferred_refusal!(skipped_heads, pool_tx);
            refuse!(&pool_tx, err);
        }
        drop(pulled.take());
        drop(builder);
        return Ok(BuildOutcome::Aborted { fees: U256::ZERO, cached_reads });
    }

    // Audit R3-E1: under deferred execution a follower votes for the block
    // before executing it and checks that it is includable instead
    // (`bin/n42/src/follower_import.rs` `check_includable_laid_out`; gov5
    // the same, docs/PHASE_D_DEFERRED_EXECUTION.md 2.4): the transactions'
    // gas limits within the block's, and each sender's summed worst-case
    // cost (`frame_scan::tx_cost`) within its balance in the parent's
    // post-state. The loop admits by that rule there, by reth's (the gas
    // used, what executes) otherwise. Everything executed before the loop is
    // the parallel step's: plain transfers whose gas limit is
    // MIN_TRANSACTION_GAS, the gas each used (`transfer_key`), so their gas
    // limits are `cumulative_gas_used`.
    //
    // The rest of the follower's rule holds by execution: the executor takes
    // a transaction only at its sender's in-block nonce (so a sender's
    // transactions run on from the parent's nonce, the pool yielding each
    // sender's in nonce order), and only with its fee cap at or over the
    // base fee and its tip at or under the cap (revm's checks, none disabled
    // here).
    let mut gas_budget = crate::includability::GasBudget::new(block_gas_limit, deferred_now);
    gas_budget.admit(cumulative_gas_used);
    let mut sender_ledger = deferred_now.then(crate::includability::SenderLedger::new);
    // Whether the parallel step put transactions in the block: a sender of
    // theirs met again here has a worst case the ledger has not counted.
    let built_before_loop = tx_count > 0;
    loop {
        // Once the block cannot fit even the smallest transaction there is
        // nothing left to take: every further candidate would only be
        // refused, one refusal per queued sender -- thousands of them at the
        // end of every full block (round 37). Checked before taking, so that
        // nothing is taken from the queue and left neither built nor returned.
        // Closed as well after a parallel step that skipped a block's worth
        // (`AfterParallelStep::Finish`): what was taken goes back below.
        if serial_closed || gas_budget.left(cumulative_gas_used) < MIN_TRANSACTION_GAS {
            break;
        }
        // The pool/execution split is timed with the cycle counter, not the
        // clock: round 37's clock-count shim found 99.9% of the builder
        // thread's clock reads were this loop's own per-transaction timers
        // (309,000 a block), and sampling one transaction in 32 biased the
        // split. rdtsc is a register read; the ticks are converted once, at
        // the end, against the build's wall clock.
        let pool_at = ticks();
        if tail_at != 0 {
            tail_ticks += pool_at.wrapping_sub(tail_at);
        }
        let pool_tx = if let Some(puller) = pulled.as_ref() {
            if lookahead.is_empty() {
                match puller.batches().recv() {
                    Ok(batch) => lookahead.extend(batch),
                    Err(_) => break,
                }
                if lookahead.is_empty() {
                    break;
                }
            }
            lookahead.pop_front().expect("checked non-empty")
        } else if prefetch == 0 && lookahead.is_empty() {
            // What the parallel step handed back (`lookahead`) is taken
            // first, by the branch below.
            let Some(pool_tx) = best_txs.as_mut().expect("direct").next() else { break };
            pool_tx
        } else {
            if lookahead.is_empty() {
                while lookahead.len() < prefetch {
                    let Some(pool_tx) = best_txs.as_mut().expect("direct").next() else { break };
                    lookahead.push_back(pool_tx);
                }
                if lookahead.is_empty() {
                    break;
                }
                let prefetch_at = std::time::Instant::now();
                prefetch_ns += prefetch_at.elapsed().as_nanos();
            }
            lookahead.pop_front().expect("checked non-empty")
        };
        let pulled_at = ticks();
        pool_ticks += pulled_at.wrapping_sub(pool_at);
        tx_count += 1;
        if tx_count == 0 { build_stage.at(3); }
        debug!(target: "payload_builder", tx_count, tx_hash=?pool_tx.hash(), gas_limit=pool_tx.gas_limit(), "processing transaction from pool");
        // ensure we still have capacity for this transaction
        if !gas_budget.fits(pool_tx.gas_limit(), cumulative_gas_used) {
            // we can't fit this transaction into the block, so we need to mark it as invalid
            // which also removes all dependent transaction from the iterator before we can
            // continue
            refuse!(
                &pool_tx,
                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
            );
            continue;
        }

        // check if the job was cancelled, if so we can exit early
        if cancel.is_cancelled() {
            return Ok(BuildOutcome::Cancelled);
        }

        // A transaction the chain has already mined, still in the pool because
        // the pool hears of a canonical block a little after the execution
        // layer has it. A build started the moment its parent was imported --
        // the build a leader with a tenure runs ahead of its next view --
        // finds every one of the parent's transactions still pending, and
        // executing each only to fail on its nonce cost 1.5-3 s at 163,000 a
        // block. The account is read from the same state the execution would
        // read it from, cached after the first transaction of each sender.
        // Skipped rather than marked invalid: marking drops the sender's later
        // transactions with it, and those are exactly the ones this block wants.
        // With the builder-side queue pruned by canonical blocks that finds
        // ~0 stale transactions a block, the executor refuses a stale one
        // anyway, and the read cost ~1 us on every transaction (round 36).
        // Kept behind N42_BUILDER_STALE_CHECK=1 for the bookend.
        if stale_check()
            && let Ok(Some(account)) = reth_evm::Evm::account_info(builder.evm_mut(), &pool_tx.sender())
                && pool_tx.nonce() < account.nonce {
                    stale_txs += 1;
                    continue;
                }

        // convert tx to a signed transaction
        let tx = pool_tx.to_consensus();

        // There's only limited amount of blob space available per block, so we need to check if
        // the EIP-4844 can still fit in the block
        if let Some(blob_tx) = tx.as_eth().and_then(|tx| tx.as_eip4844()) {
            let tx_blob_count = blob_tx.tx().blob_versioned_hashes.len() as u64;

            if block_blob_count + tx_blob_count > max_blob_count {
                // we can't fit this _blob_ transaction into the block, so we mark it as
                // invalid, which removes its dependent transactions from
                // the iterator. This is similar to the gas limit condition
                // for regular transactions above.
                trace!(target: "payload_builder", tx=?tx.hash(), ?block_blob_count, "skipping blob transaction because it would exceed the max blob count per block");
                refuse!(
                    &pool_tx,
                    InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::TooManyEip4844Blobs {
                            have: block_blob_count + tx_blob_count,
                            permitted: max_blob_count,
                        },
                    )
                );
                continue;
            }
        }

        // Audit R3-E1: the sender's worst case within its parent balance
        // (deferred execution only). The account is read below the block's
        // state, from the parent's post-state the build executes on, once per
        // sender; the admission is committed only once the transaction is in.
        let admitted = match sender_ledger.as_mut() {
            None => None,
            Some(ledger) => {
                use crate::includability::{Admission, Opening};
                let sender = pool_tx.sender();
                let nonce = pool_tx.nonce();
                let verdict = ledger.admit(sender, crate::frame_scan::tx_cost(tx.inner()), || {
                    let read = |err: &dyn std::fmt::Display| std::io::Error::other(format!("account {sender}: {err}"));
                    let parent = parent_state_ref()
                        .map_err(|err| read(&err))
                        .and_then(|provider| {
                            reth_storage_api::AccountReader::basic_account(provider, &sender).map_err(|err| read(&err))
                        })?
                        .unwrap_or_default();
                    // A nonce past the parent's after the parallel step: the
                    // sender's transfers are in the block when its in-block
                    // nonce moved (a gap otherwise, which execution refuses).
                    let unseen_earlier = built_before_loop
                        && nonce > parent.nonce
                        && reth_evm::Evm::account_info(builder.evm_mut(), &sender)
                            .map_err(|err| read(&err))?
                            .map_or(0, |now| now.nonce)
                            != parent.nonce;
                    Ok::<_, std::io::Error>(Opening { balance: parent.balance, unseen_earlier })
                });
                match verdict {
                    Ok(Admission::Admit(admitted)) => Some(admitted),
                    Ok(Admission::OverBalance { balance, cost }) => {
                        trace!(target: "payload_builder", tx = ?tx.hash(), %balance, %cost, "skipping a transaction whose sender's worst case exceeds its balance");
                        refuse!(
                            &pool_tx,
                            InvalidPoolTransactionError::Consensus(InvalidTransactionError::InsufficientFunds(
                                reth_primitives_traits::GotExpected { got: balance, expected: cost }.into(),
                            ))
                        );
                        continue;
                    }
                    Ok(Admission::Unseen) => {
                        refuse!(
                            &pool_tx,
                            InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
                        );
                        continue;
                    }
                    Err(err) => return Err(PayloadBuilderError::other(err)),
                }
            }
        };

        // What the bookkeeping after execution needs, taken before the
        // transaction is moved into the executor (it used to be cloned).
        let tx_hash = *tx.hash();
        let blob_count = tx.as_eth().and_then(|tx| tx.as_eip4844()).map(|blob_tx| blob_tx.tx().blob_versioned_hashes.len() as u64);
        let miner_fee = tx.effective_tip_per_gas(base_fee);
        let executed = builder.execute_transaction(tx);
        tail_at = ticks();
        exec_ticks += tail_at.wrapping_sub(pulled_at);
        let gas_used = match executed {
            Ok(gas_used) => gas_used,
            Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                error, ..
            })) => {
                if error.is_nonce_too_low() {
                    // if the nonce is too low, we can skip this transaction
                    trace!(target: "payload_builder", %error, tx = ?tx_hash, "skipping nonce too low transaction");
                    // Skipping is enough for the pool, which prunes itself
                    // against the state. The queue prunes only by canonical
                    // blocks, so one it offered stale would come back at the
                    // next give-back and be taken, refused and given back by
                    // every build of this leader for the rest of the leg
                    // (round 44: 814,431 refusals on one node, builds of
                    // 3.4-4.1 s). Told once, it drops that nonce and every
                    // lower one for the sender for good; the sender's higher
                    // nonces are still offered.
                    if from_queue
                        && let Some((tx, state)) = invalid_nonce(&*error).filter(|(tx, state)| tx < state)
                    {
                        refuse!(
                            &pool_tx,
                            InvalidPoolTransactionError::Consensus(
                                InvalidTransactionError::NonceNotConsistent { tx, state }
                            )
                        );
                    }
                } else {
                    // if the transaction is invalid, we can skip it and all of its
                    // descendants
                    trace!(target: "payload_builder", %error, tx = ?tx_hash, "skipping invalid transaction and its descendants");
                    // reth reports every such refusal as an unsupported type.
                    // A nonce above the account's is reported as what it is,
                    // so a queue that orders by nonce can tell a hole from a
                    // bad transaction and fill it.
                    let kind = match invalid_nonce(&*error) {
                        Some((tx, state)) if tx > state => InvalidTransactionError::NonceNotConsistent { tx, state },
                        _ => InvalidTransactionError::TxTypeNotSupported,
                    };
                    refuse!(&pool_tx, InvalidPoolTransactionError::Consensus(kind));
                }
                continue;
            }
            // this is an error that we should treat as fatal for this attempt
            Err(err) => return Err(PayloadBuilderError::evm(err)),
        };

        // add to the total blob gas used if the transaction successfully executed
        if let Some(tx_blob_count) = blob_count {
            block_blob_count += tx_blob_count;

            // if we've reached the max blob count, we can skip blob txs entirely
            if block_blob_count == max_blob_count {
                match (best_txs.as_mut(), pulled.as_ref()) {
                    (Some(best), _) => best.skip_blobs(),
                    (None, Some(puller)) => puller.refuse(Refusal::Blobs),
                    (None, None) => {}
                }
            }
        }

        // update add to total fees
        let miner_fee = miner_fee.expect("fee is always valid; execution succeeded");
        // EIP-8037 split gas into execution and state components; fees and the
        // block's cumulative counter both track the execution gas.
        let tx_gas_used = gas_used.tx_gas_used();
        total_fees += U256::from(miner_fee) * U256::from(tx_gas_used);
        cumulative_gas_used += tx_gas_used;
        gas_budget.admit(pool_tx.gas_limit());
        if let Some(admitted) = admitted {
            admitted.commit();
        }
    }

    debug!(target: "payload_builder", tx_count, ?cumulative_gas_used, ?total_fees, "payload builder finished processing transactions");
    // Whatever was taken ahead and not built goes back to the queue, last
    // taken first so each is the queue's last and the return is O(1).
    for pool_tx in lookahead.into_iter().rev() {
        refuse!(
            &pool_tx,
            InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
        );
    }
    for pool_tx in deferred.into_iter().rev() {
        let err = deferred_refusal!(skipped_heads, pool_tx);
        refuse!(&pool_tx, err);
    }
    // The puller stops at its next batch; what it pulled meanwhile it
    // returns itself.
    drop(pulled.take());
    let loop_done = build_started.elapsed();
    build_stage.at(4);
    // Ticks to nanoseconds, against the wall clock of the loop just run.
    {
        let elapsed_ticks = ticks().wrapping_sub(ticks_at_start).max(1);
        let ns_per_tick = loop_done.as_nanos() as f64 / elapsed_ticks as f64;
        pool_ns += (pool_ticks as f64 * ns_per_tick) as u128;
        exec_ns += (exec_ticks as f64 * ns_per_tick) as u128;
        tail_ns += (tail_ticks as f64 * ns_per_tick) as u128;
    }

    // check if we have a better block
    if !is_better_payload(best_payload.as_ref(), total_fees) {
        // Release db
        drop(builder);
        // can skip building the block
        return Ok(BuildOutcome::Aborted {
            fees: total_fees,
            cached_reads,
        });
    }

    // F5c: with the parallel step's merge pending, `finish` folds it into
    // the block's bundle (`N42BlockExecutor`). Should the fold refuse, the
    // block is not lost and the payload does not fail: the same transactions,
    // in the same order, are executed again serially on a fresh executor over
    // the parent, and that block is the build's. The transactions are copied
    // for it only on a build with a merge pending.
    let mut rebuild_txs = builder.executor.has_pending_fold().then(|| builder.transactions.clone());
    macro_rules! finish_or_rebuild {
        ($root:expr) => {{
            match builder.finish(parent_state_ref()?, $root) {
                Err(err) if matches!(&err, BlockExecutionError::Internal(internal) if internal.is_other::<crate::graft_fold::FoldRefused>()) => {
                    let txs = rebuild_txs.take().unwrap_or_default();
                    warn!(
                        target: "n42::parallel_build",
                        number = parent_header.number + 1,
                        %err,
                        txs = txs.len(),
                        "the fold refused at finish; the block is rebuilt serially in this build"
                    );
                    crate::parallel_build::note_serial_rebuild();
                    let db = cached_reads.as_db_mut(LazyParentDb { slot: &parent_state_slot, open: &open_parent_state });
                    let evm = evm_config.evm_with_env(db, group_env.clone());
                    let ctx = evm_config
                        .context_for_next_block(&parent_header, rebuild_attributes.clone())
                        .map_err(PayloadBuilderError::other)?;
                    let mut again: reth_evm::execute::BasicBlockBuilder<'_, EvmConfig::BlockExecutorFactory, _, _, EthPrimitives> =
                        reth_evm::execute::BasicBlockBuilder::new(
                            evm_config.block_executor_factory(),
                            &assembler,
                            evm,
                            group_env.clone(),
                            &parent_header,
                            ctx,
                        );
                    again.apply_pre_execution_changes().map_err(|err| PayloadBuilderError::Internal(err.into()))?;
                    for tx in txs {
                        again.execute_transaction(tx)?;
                    }
                    again.finish(parent_state_ref()?, $root)?
                }
                other => other?,
            }
        }};
    }
    // On a QMDB chain the state root is not reth's to compute. The builder is
    // handed a zero root so it skips the Merkle-Patricia computation; the real
    // root comes from the forest, over the bundle execution left behind, and
    // replaces the zero in the header below. The block hash follows from the
    // sealed header, so the tree is filed under it only once that is known.
    let (
        BlockBuilderOutcome {
            execution_result,
            execution_state,
            block,
            block_access_list,
            hashed_state,
            trie_updates,
        },
        qmdb_prepared,
        finish_took,
        root_took,
    ) = match &qmdb {
        Some(state) => {
            let finish_at = std::time::Instant::now();
            let outcome = finish_or_rebuild!(Some((B256::ZERO, TrieUpdates::default())));
            let finish_took = finish_at.elapsed();
            let root_at = std::time::Instant::now();
            // Computed during assembly (see `assembler`); the fallback below
            // is for an assembler that did not run the job, which does not
            // happen, and it is cheaper to keep than to reason about.
            let prepared = match qmdb_root.lock().unwrap_or_else(|p| p.into_inner()).take() {
                Some(Ok(prepared)) => prepared,
                Some(Err(err)) => return Err(PayloadBuilderError::other(std::io::Error::other(err))),
                None => state
                    .compute(
                        parent_header.hash(),
                        &changes_from_execution(
                            &outcome.execution_state,
                            n42_qmdb_reth::system_caller_leaf_at(&*chain_spec, attributes.timestamp),
                        ),
                    )
                    .map_err(PayloadBuilderError::other)?,
            };
            (outcome, Some(prepared), finish_took, root_at.elapsed())
        }
        None => {
            let finish_at = std::time::Instant::now();
            let outcome = finish_or_rebuild!(None);
            (outcome, None, finish_at.elapsed(), std::time::Duration::ZERO)
        }
    };
    let finished_at = build_started.elapsed();

    let requests = chain_spec
        .is_prague_active_at_timestamp(attributes.timestamp)
        .then(|| execution_result.requests.clone());
    // The bundle and the receipts, kept for the sealed block's import. Taken
    // here, after the QMDB changes were read from it, and moved rather than
    // cloned: 163,000 receipts are not free to copy on the build's own path.
    let mut bundle = execution_state;
    // The parallel step's accounts went into the bundle directly; their
    // reverts join the block's set here.
    crate::parallel_transfer::append_reverts(&mut bundle, std::mem::take(&mut par_reverts));
    let execution_output = Arc::new(reth_execution_types::BlockExecutionOutput {
        state: bundle,
        result: execution_result,
    });
    // How scattered the block is: accounts the bundle created against
    // accounts it updated (a round's per-transaction cost was found to move
    // with the block's shape, not its size).
    let (created, updated) = execution_output.state.state.values().fold((0u64, 0u64), |(c, u), account| {
        if account.original_info.is_none() { (c + 1, u) } else { (c, u + 1) }
    });

    // Blob sidecars, in whichever variant the pool holds them. Kept as the
    // variant and not flattened to EIP-4844: the Osaka `getPayload` envelope
    // carries cell proofs and refuses an EIP-4844-shaped bundle outright — even
    // an empty one — and reth reports that refusal as "unknown payload", which
    // reads like the build never happened.
    let mut blob_sidecars = reth_ethereum_engine_primitives::BlobSidecars::Empty;
    if chain_spec.is_cancun_active_at_timestamp(attributes.timestamp) {
        let raw_sidecars = pool
            .get_all_blobs_exact(
                block
                    .body()
                    .transactions()
                    .filter(|tx| tx.is_eip4844())
                    .map(|tx| *tx.tx_hash())
                    .collect(),
            )
            .map_err(PayloadBuilderError::other)?;
        for sidecar in raw_sidecars {
            blob_sidecars.push_sidecar_variant(Arc::unwrap_or_clone(sidecar));
        }
    }

    // This block's own execution, as its child's header will carry it
    // under deferred execution, or as its own header carries it before the
    // fork.
    let own_state_root = match &qmdb_prepared {
        Some(prepared) => prepared.root,
        None => block.header().state_root,
    };
    let (own_receipts_root, own_logs_bloom) = if hotstuff {
        crate::hotstuff_consensus::gov5_receipt_root_bloom(&execution_output.result.receipts)
    } else {
        (block.header().receipts_root, block.header().logs_bloom)
    };
    let own_gas_used = block.header().gas_used;
    let deferred = reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), attributes.timestamp);
    if deferred {
        // The header carries the parent's execution (docs/PHASE_D_DEFERRED_EXECUTION.md):
        // what this node executed for the parent, or the parent's own header
        // before the fork -- the first header past the fork repeats its
        // parent's fields, the invariant at the switch.
        // The same fallback the early seal has. Without it every build whose
        // parallel step came up empty -- which is every build made while the
        // queue is dry -- refused outright on a parent this node had built
        // itself moments earlier, because its execution was still filed only
        // under the builder's hash (loop193 W1b: 289 of 347 refusals, each
        // 0.4-1.3 ms after the request).
        // At depth 2 the grandparent's (docs/DEFERRED_DEPTH_2_DESIGN.md).
        let carried_depth = reth_chainspec::qmdb::deferred_execution_depth_at(chain_spec.genesis(), attributes.timestamp);
        let parent_fields = carried_fields_for_seal(chain_spec.genesis(), &parent_header, parent_built, carried_depth)
            .ok_or_else(|| {
                PayloadBuilderError::other(crate::hotstuff_consensus::DeferredExecutionError::ParentUnknown(
                    crate::hotstuff_consensus::ancestor_hash(&parent_header, carried_depth),
                ))
            })?;
        header.state_root = parent_fields.state_root;
        header.receipts_root = parent_fields.receipts_root;
        header.logs_bloom = parent_fields.logs_bloom;
        header.gas_used = parent_fields.gas_used;
    } else {
        header.state_root = own_state_root;
        header.receipts_root = own_receipts_root;
        header.logs_bloom = own_logs_bloom;
        header.gas_used = own_gas_used;
    }
    // Under the flag the assembler's root is the MPT root; the header's is
    // the frame tree when the sealed body is a run of frames.
    header.transactions_root = if crate::frame_blocks::active() {
        use alloy_consensus::transaction::TxHashRef as _;
        let transactions = &block.body().transactions;
        let hashes: Vec<B256> = transactions.iter().map(|tx| *tx.tx_hash()).collect();
        crate::frame_blocks::seal_root(frame_plan.as_ref(), &hashes, || block.header().transactions_root)
    } else {
        block.header().transactions_root
    };
    if hotstuff {
        header.ommers_hash = B256::ZERO;
        header.difficulty = U256::ZERO;
    }
    header.gas_limit = block.header().gas_limit;
    header.base_fee_per_gas = block.header().base_fee_per_gas;
    header.withdrawals_root = block.header().withdrawals_root;
    header.blob_gas_used = block.header().blob_gas_used;
    header.excess_blob_gas = block.header().excess_blob_gas;
    header.requests_hash = block.header().requests_hash;

    header.timestamp = attributes.timestamp;
    header.mix_hash = attributes.prev_randao;
    header.parent_beacon_block_root = attributes.parent_beacon_block_root;

    let block_number = header.number;
    let registry_root = stamp_gov5_tail(chain_spec.genesis(), &mut header, attributes.mobile_registry_root)?;

    // seal
    build_stage.at(5);
    cons.seal(&mut header)
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;

    // Keep the recovered senders: EthBuiltPayload now takes a RecoveredBlock, and
    // re-recovering them from signatures here would be pure waste.
    let senders = block.senders().to_vec();
    let sealed_block = SealedBlock::seal_parts(n42_header::N42Header::new(header, registry_root), block.into_block().body);
    let block_hash = SealedBlock::hash(&sealed_block);
    // Under the sealed hash, for the next header: the child's header is
    // assembled from and checked against exactly this.
    crate::executed_fields::remember(
        block_hash,
        crate::executed_fields::ExecutedFields {
            state_root: own_state_root,
            receipts_root: own_receipts_root,
            logs_bloom: own_logs_bloom,
            gas_used: own_gas_used,
        },
    );
    if let (Some(state), Some(prepared)) = (&qmdb, qmdb_prepared) {
        // Now the hash is known, the tree can be filed. Validation of this same
        // block, moments from now, finds it there and agrees by construction.
        state
            .insert(block_hash, block_number, prepared)
            .map_err(PayloadBuilderError::other)?;
    }
    let _ = cons.set_cached_reads(block_hash, cached_reads.clone());

    let recovered: Arc<reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>> =
        Arc::new(reth_primitives_traits::RecoveredBlock::new_sealed(sealed_block, senders));
    build_stage.at(6);
    crate::built_executions::remember(
        block_hash,
        crate::built_executions::BuiltExecution {
            block: recovered.clone(),
            execution_output,
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(trie_updates),
        },
    );

    // The EIP-7928 access list, RLP-encoded, when the builder made one.
    //
    // This used to be `None` with a comment saying APoS does not produce one,
    // which was true until the state above was given a BAL builder. Leaving it
    // `None` after that is worse than not building it: the list exists, is
    // thrown away here, `getPayloadV6` answers `MissingBlockAccessList`, and on
    // an Amsterdam chain the leader cannot produce a block at all.
    //
    // It is also what decides how every node executes the block. reth takes the
    // parallel path for a block that carries one and the serial path for a
    // block that does not, and says nothing either way.
    let block_access_list: Option<alloy_primitives::Bytes> =
        block_access_list.map(|bal| alloy_rlp::encode(&bal).into());
    // At info only for blocks big enough to matter; an empty block every
    // 250 ms would otherwise be a line every 250 ms.
    let total = build_started.elapsed();
    let assemble_ms = total.saturating_sub(finished_at).as_millis() as u64;
    let (queued, usable, parked) = queue_depth();
    // Whether the chain decided this height while the build was being set
    // up. Such a build reads exactly like a starved one -- its candidates
    // are the queue's, and the queue was pruned by the blocks its parent
    // does not have, so every lane looks gapped -- and it is neither
    // proposed nor a symptom of anything.
    let superseded = crate::canonical_head::already_decided(block_number);
    // A build that came out under a tenth of a block while the queue held
    // more than a block. This is the only path such a build can take (an
    // empty block never passes the early seal's `par_txs > 0`), and on
    // loop207 Ob node1 it was every build for twenty views -- `txs=0`,
    // `par_skipped=163000`, `queued=334-360k` -- with nothing in the logs
    // saying the queue was deep and unusable rather than dry.
    {
        let block_txs = block_gas_limit / MIN_TRANSACTION_GAS;
        if !superseded && cumulative_gas_used.saturating_mul(10) < block_gas_limit && queued as u64 >= block_txs {
            static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            if say_once_a_second(&LAST) {
                warn!(
                    target: "payload_builder",
                    number = block_number,
                    gas = cumulative_gas_used,
                    block_gas_limit,
                    candidates = tx_count,
                    par_skipped,
                    queued,
                    usable,
                    parked,
                    "a build found almost nothing usable while the queue held more than a block"
                );
            }
        }
    }
    if tx_count >= 1000 {
        tracing::info!(
            target: "payload_builder",
            number = block_number,
            txs = tx_count,
            gas = cumulative_gas_used,
            stale = stale_txs,
            created,
            updated,
            setup_ms = setup_took.as_millis() as u64,
            pool_ms = (pool_ns / 1_000_000) as u64,
            prefetch_ms = (prefetch_ns / 1_000_000) as u64,
            verified_by_builder = crate::claimed_build::verified().saturating_sub(verified_before),
            builder_dropped_bad_claim = crate::claimed_build::dropped().saturating_sub(dropped_before),
            verify_ms = crate::claimed_build::verify_ms().saturating_sub(verify_ms_before),
            par_txs,
            par_groups,
            par_batches,
            par_skipped,
            par_pull_ms,
            par_exec_ms,
            par_fold_ms,
            par_ms,
            state_after_pull = defer_state,
            state_wait_ms,
            state_wait_us,
            state_wait_on = state_wait_label(state_wait_us, &state_wait_on),
            state_wait_split = %state_wait_on.split(),
            queued,
            usable,
            parked,
            superseded,
            exec_ms = (exec_ns / 1_000_000) as u64,
            tail_ms = (tail_ns / 1_000_000) as u64,
            loop_ms = loop_done.as_millis() as u64,
            finish_ms = finish_took.as_millis() as u64,
            root_ms = root_took.as_millis() as u64,
            assemble_ms,
            total_ms = total.as_millis() as u64,
            core_layout = n42_core_layout::label(),
            "payload build phases"
        );
    }
    build_stage.at(7);
    let payload = EthBuiltPayload::new(recovered, total_fees, requests, block_access_list)
        // add blob sidecars from the executed txs
        .with_sidecars(blob_sidecars);

    Ok(BuildOutcome::Better {
        payload,
        cached_reads,
    })
}

/// A custom payload service builder that supports the custom engine types
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct N42PayloadServiceBuilder<CB> {
    /// The consensus builder to create consensus instances.
    consensus_builder: CB,
    /// The QMDB state built blocks commit to, on a chain that declares it.
    qmdb: Option<QmdbNodeState>,
}

impl<CB: Default> Default for N42PayloadServiceBuilder<CB> {
    fn default() -> Self {
        Self {
            consensus_builder: CB::default(),
            qmdb: None,
        }
    }
}

impl<CB> N42PayloadServiceBuilder<CB> {
    /// Create a new [`N42PayloadServiceBuilder`] with a consensus builder.
    pub const fn new(consensus_builder: CB) -> Self {
        Self {
            consensus_builder,
            qmdb: None,
        }
    }

    /// Commits built blocks to `qmdb`. See [`N42PayloadBuilder::with_qmdb`].
    pub fn with_qmdb(mut self, qmdb: Option<QmdbNodeState>) -> Self {
        self.qmdb = qmdb;
        self
    }
}

impl<Node, Pool, EvmConfig, CB> PayloadServiceBuilder<Node, Pool, EvmConfig>
    for N42PayloadServiceBuilder<CB>
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = n42_header::N42ChainSpec, Primitives = EthPrimitives>>,
    <Node::Types as NodeTypes>::Payload: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = EthPayloadAttributes,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    CB: ConsensusBuilder<Node> + Clone + Send + Sync,
    CB::Consensus: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + 'static,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: EvmConfig,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>> {
        // Build consensus using the consensus builder
        let consensus = self.consensus_builder.clone().build_consensus(ctx).await?;

        // Build payload builder with consensus
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);

        // The same EVM factory the engine imports with (the fast transfer
        // path lives in it). Until round 37 the builder had a plain
        // `EthEvmConfig::new`, so nothing done to the node's EVM reached it.
        let _ = evm_config;
        let payload_builder = N42PayloadBuilder::new(
            ctx.provider().clone(),
            pool.clone(),
            crate::n42_evm::N42EvmConfig::new(ctx.chain_spec()),
            EthereumBuilderConfig::new().with_gas_limit(gas_limit),
            consensus,
        )
        .with_qmdb(self.qmdb.clone());
        // The raw payload channel builds on a sealed own block through this
        // (`direct_build`), with the payload service out of the way.
        crate::direct_build::register(Arc::new(payload_builder.clone()));

        let builder_conf = ctx.config().builder.clone();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(builder_conf.interval)
            .deadline(builder_conf.deadline)
            .max_payload_tasks(builder_conf.max_payload_tasks);

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_service_handle) =
            PayloadBuilderService::new(
                payload_generator,
                // N42: the same stream, with its receiver's lag reported.
                crate::canon_lag::watched_notifications(
                    "payload_service",
                    ctx.provider().subscribe_to_canonical_state(),
                ),
            );

        ctx.task_executor()
            .spawn_critical_task("payload builder service", Box::pin(payload_service));

        Ok(payload_service_handle)
    }
}

/*
/// The type responsible for building custom payloads
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42PayloadBuilder<EvmConfig = EthEvmConfig> {
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
}

impl<EvmConfig> N42PayloadBuilder<EvmConfig> {
    /// `N42PayloadBuilder` constructor.
    pub const fn new(evm_config: EvmConfig) -> Self {
        Self { evm_config }
    }
}
*/



#[cfg(test)]
thread_local! {
    /// A test's choice for `N42_PARALLEL_BUILD` on its own thread.
    static PARALLEL_BUILD_FOR_TEST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

fn parallel_build() -> bool {
    #[cfg(test)]
    if let Some(on) = PARALLEL_BUILD_FOR_TEST.with(std::cell::Cell::get) {
        return on;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_PARALLEL_BUILD", false))
}

fn stale_check() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILDER_STALE_CHECK").is_ok_and(|v| v == "1"))
}

/// The gas of the cheapest transaction (a plain transfer). A block with less
/// than this left cannot take anything more.
const MIN_TRANSACTION_GAS: u64 = 21_000;

/// `N42_BUILDER_PREFETCH=<n>`: how many transactions the builder takes ahead
/// of execution to read their accounts in parallel first; 0 (the default)
/// executes straight from the pool.
/// `N42_BUILDER_PULLER=<n>`: the batch a puller thread takes from the pool
/// ahead of the build's execution; 0 (default) walks the pool on the build's
/// own thread.
fn builder_puller() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| n42_env::parse("N42_BUILDER_PULLER", 0))
}

/// What the build tells the puller about a transaction it was handed.
enum Refusal<T: reth_transaction_pool::PoolTransaction> {
    /// Refused: the pool's `mark_invalid`, from the puller's thread.
    Invalid(Arc<reth_transaction_pool::ValidPoolTransaction<T>>, InvalidPoolTransactionError),
    /// The block's blob space is full.
    Blobs,
}

/// The pool walk on its own thread: batches ahead of the execution, refusals
/// back. Dropping it ends the walk; the thread returns what it still holds.
struct Puller<T: reth_transaction_pool::PoolTransaction> {
    /// `None` only while the puller is being dropped: the receiver goes
    /// first, so a thread blocked on a full channel sees the send fail.
    batches: Option<std::sync::mpsc::Receiver<Vec<Arc<reth_transaction_pool::ValidPoolTransaction<T>>>>>,
    refusals: std::sync::mpsc::Sender<Refusal<T>>,
    done: Arc<std::sync::atomic::AtomicBool>,
    /// Joined on drop: the walk's give-back happens when the thread ends,
    /// and a build that seals must have it done before the chained build
    /// pulls (loop233: holes of one batch, the thread still running).
    thread: Option<std::thread::JoinHandle<()>>,
}

/// The puller's batches: after [`Puller::stop`] every receive fails, as
/// when the walk has ended.
struct PulledBatches<'a, T: reth_transaction_pool::PoolTransaction>(
    Option<&'a std::sync::mpsc::Receiver<Vec<Arc<reth_transaction_pool::ValidPoolTransaction<T>>>>>,
);

impl<T: reth_transaction_pool::PoolTransaction> PulledBatches<'_, T> {
    fn recv(&self) -> Result<Vec<Arc<reth_transaction_pool::ValidPoolTransaction<T>>>, std::sync::mpsc::RecvError> {
        self.0.ok_or(std::sync::mpsc::RecvError)?.recv()
    }
}

impl<T: reth_transaction_pool::PoolTransaction> Puller<T> {
    fn start(
        mut best: Box<dyn BestTransactions<Item = Arc<reth_transaction_pool::ValidPoolTransaction<T>>>>,
        batch: usize,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let (batch_tx, batches) = std::sync::mpsc::sync_channel(2);
        let (refusals, refusal_rx) = std::sync::mpsc::channel::<Refusal<T>>();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = done.clone();
        let apply = move |best: &mut Box<dyn BestTransactions<Item = Arc<reth_transaction_pool::ValidPoolTransaction<T>>>>| {
            while let Ok(refusal) = refusal_rx.try_recv() {
                match refusal {
                    Refusal::Invalid(tx, err) => best.mark_invalid(&tx, err),
                    Refusal::Blobs => best.skip_blobs(),
                }
            }
        };
        let spawned = std::thread::Builder::new().name("n42-builder-puller".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                apply(&mut best);
                let mut pulled = Vec::with_capacity(batch);
                for _ in 0..batch {
                    match best.next() {
                        Some(tx) => pulled.push(tx),
                        None => break,
                    }
                }
                if pulled.is_empty() || batch_tx.send(pulled).is_err() {
                    break;
                }
            }
            // The build's last refusals, then the walk's own give-back on drop.
            apply(&mut best);
        });
        let thread = match spawned {
            Ok(handle) => Some(handle),
            Err(err) => {
                warn!(target: "payload_builder", %err, "could not start the pool puller; the build has no transactions");
                None
            }
        };
        Self { batches: Some(batches), refusals, done, thread }
    }

    fn batches(&self) -> PulledBatches<'_, T> {
        PulledBatches(self.batches.as_ref())
    }

    /// Ends the walk without waiting for it: the thread applies the
    /// refusals sent so far and gives back what it holds as it ends. The
    /// drop still joins it.
    fn stop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(self.batches.take());
    }

    fn refuse(&self, refusal: Refusal<T>) {
        // A puller that already ended has nothing to refuse.
        let _ = self.refusals.send(refusal);
    }
}

impl<T: reth_transaction_pool::PoolTransaction> Drop for Puller<T> {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        // The receiver first: a thread blocked sending a batch wakes with an
        // error and ends; then the join, so the walk's give-back is complete
        // when this returns.
        drop(self.batches.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `N42_PULLER_STOP_AT_PULL` (default on; `0` keeps the stop at the seal):
/// see the evm2 parallel step.
fn puller_stop_at_pull() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_PULLER_STOP_AT_PULL", true))
}

/// Whether the build's candidates are not the plan's whole take: they did
/// not come as the selection's bulk vector, or it was cut to the budget.
const fn made_cands_cut(from_bulk: bool, bulk_len: usize, cands: usize) -> bool {
    !from_bulk || bulk_len != cands
}

/// `N42_EVM2_RECEIPTS_LATE` (default on; `0` commits the receipts before the
/// finish, as before F5g7): the evm2 step's receipts on a block sealed at the
/// execution's end with its output in shards are built behind the seal on a
/// thread of their own. Read once.
fn evm2_receipts_late() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| n42_env::flag("N42_EVM2_RECEIPTS_LATE", true))
}

fn builder_prefetch() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| n42_env::parse("N42_BUILDER_PREFETCH", 0))
}

/// The CPU's cycle counter: a register read, where a clock read is a vDSO
/// call. Monotonic enough for sums over one build on the same thread.
#[inline(always)]
fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: rdtsc has no preconditions on x86_64.
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
    }
}

#[cfg(test)]
mod late_reverts_tests {
    use super::{spawn_late_reverts_with, SpawnThread};
    use alloy_primitives::Address;
    use std::sync::Arc;

    /// A spawner that never gets a thread (EAGAIN under pressure).
    struct NoThread;

    impl SpawnThread for NoThread {
        fn spawn<F: FnOnce() + Send + 'static>(self, _name: &str, _work: F) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "no thread"))
        }
    }

    /// A late revert set that gets no thread hands the graft back whole, so
    /// the caller's merge runs it in place, and promises nothing.
    #[test]
    fn a_late_revert_set_without_a_thread_hands_the_graft_back() {
        let shards = Arc::new(crate::output_shards::OutputShards::with_index_live(Address::ZERO, 8, 1, false, false).freeze());
        let residual = reth_trie::bundle_state::BundleState::default();
        let graft: Vec<_> = (1u8..=3)
            .map(|i| (Address::repeat_byte(i), reth_trie::bundle_state::AccountRevert::default()))
            .collect();
        let (back, late) = spawn_late_reverts_with(&shards, &residual, graft, None, NoThread);
        assert!(late.is_none(), "no thread, no promise");
        let addresses: Vec<Address> = back.iter().map(|(address, _)| *address).collect();
        assert_eq!(addresses, vec![Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3)]);
    }
}

#[cfg(test)]
mod empty_step_tests {
    use super::{after_parallel_step, AfterParallelStep};

    fn verdict(par_txs: u64, par_skipped: usize, direct: bool, decided: bool) -> AfterParallelStep {
        after_parallel_step(true, par_txs, par_skipped, 163_000, direct, decided)
    }

    #[test]
    fn a_direct_build_that_built_nothing_of_a_block_declines() {
        // loop237 warm/G175 node1: the build ahead on the sealed block, 163,000 of 163,000 skipped.
        assert!(matches!(verdict(0, 163_000, true, false), AfterParallelStep::Decline(_)));
    }

    #[test]
    fn a_direct_build_that_skipped_most_of_a_block_finishes_without_the_serial_loop() {
        // loop237 G175b node1 (6,144 built, 156,856 skipped) and G175 node3 (7,916 / 155,084).
        assert!(matches!(verdict(6_144, 156_856, true, false), AfterParallelStep::Finish(_)));
        assert!(matches!(verdict(7_916, 155_084, true, false), AfterParallelStep::Finish(_)));
    }

    #[test]
    fn a_decided_height_declines_on_any_path() {
        assert!(matches!(verdict(0, 163_000, false, true), AfterParallelStep::Decline(_)));
        assert!(matches!(verdict(120_000, 5_000, false, true), AfterParallelStep::Decline(_)));
    }

    #[test]
    fn the_ordinary_build_on_an_open_height_keeps_its_serial_loop() {
        // The first build of a tenure (`try_build`), and the fallback of a declined direct build.
        assert_eq!(verdict(0, 163_000, false, false), AfterParallelStep::Serial);
    }

    #[test]
    fn a_minority_skip_keeps_the_serial_loop() {
        // loop237 G150: 131,640 built, 31,360 skipped.
        assert_eq!(verdict(131_640, 31_360, true, false), AfterParallelStep::Serial);
        assert_eq!(verdict(0, 999, true, true), AfterParallelStep::Serial);
    }

    #[test]
    fn the_switch_turns_it_off() {
        assert_eq!(after_parallel_step(false, 0, 163_000, 163_000, true, true), AfterParallelStep::Serial);
    }
}

#[cfg(test)]
mod seal_at_exec_tests {
    use super::body_matches_pull;
    use alloy_primitives::B256;

    fn hashes(n: u8) -> Vec<B256> {
        (0..n).map(|i| B256::repeat_byte(i + 1)).collect()
    }

    #[test]
    fn body_matches_pull_accepts_the_pulled_set_in_order() {
        let pulled = hashes(9);
        assert!(body_matches_pull(&pulled.clone(), &pulled, |h| *h, |h| *h));
        assert!(body_matches_pull::<B256, B256>(&[], &[], |h| *h, |h| *h));
        let one = hashes(1);
        assert!(body_matches_pull(&one, &one, |h| *h, |h| *h));
    }

    #[test]
    fn body_matches_pull_refuses_a_different_set() {
        let pulled = hashes(9);
        // One skipped: shorter.
        assert!(!body_matches_pull(&pulled[..8], &pulled, |h| *h, |h| *h));
        // Reordered at an end or in the middle.
        let mut body = pulled.clone();
        body.swap(0, 1);
        assert!(!body_matches_pull(&body, &pulled, |h| *h, |h| *h));
        let mut body = pulled.clone();
        body[4] = B256::ZERO;
        assert!(!body_matches_pull(&body, &pulled, |h| *h, |h| *h));
        let mut body = pulled.clone();
        body.swap(7, 8);
        assert!(!body_matches_pull(&body, &pulled, |h| *h, |h| *h));
    }
}


#[cfg(test)]
mod depth_two_tests {
    use super::*;
    use reth_primitives_traits::SealedHeader;

    /// T9 of docs/DEFERRED_DEPTH_2_DESIGN.md: the limit step never goes below
    /// the carried `gasUsed`, and never further than the parent allows.
    #[test]
    fn the_gas_limit_never_falls_under_the_carried_gas() {
        let parent = 30_000_000u64;
        let step = parent / GAS_LIMIT_BOUND_DIVISOR - 1;
        // A shrinking step under the carried gas is raised to it.
        let shrink = calculate_block_gas_limit(parent, 10_000_000);
        assert_eq!(shrink, parent - step);
        assert_eq!(gas_limit_over_carried(shrink, parent, Some(parent - 10)), parent - 10);
        // Never above the parent's ramp.
        assert_eq!(gas_limit_over_carried(shrink, parent, Some(parent + 2 * step)), parent + step);
        // Over the carried gas already: unchanged; growth is unchanged too.
        assert_eq!(gas_limit_over_carried(shrink, parent, Some(1_000)), shrink);
        let grow = calculate_block_gas_limit(parent, 60_000_000);
        assert_eq!(gas_limit_over_carried(grow, parent, Some(parent)), grow);
        // An unknown carried gas holds the limit where it was.
        assert_eq!(gas_limit_over_carried(shrink, parent, None), parent);
        // A fixed limit (the bench) is never touched.
        assert_eq!(gas_limit_over_carried(parent, parent, Some(parent)), parent);
    }

    fn depth_two_genesis() -> alloy_genesis::Genesis {
        let mut genesis = alloy_genesis::Genesis::default();
        genesis.config.extra_fields.insert(reth_chainspec::qmdb::DEFERRED_EXECUTION_TIME_KEY.to_owned(), serde_json::json!(0));
        genesis.config.extra_fields.insert(reth_chainspec::qmdb::DEFERRED_EXECUTION_DEPTH_KEY.to_owned(), serde_json::json!(2));
        genesis
    }

    fn fields(byte: u8) -> crate::executed_fields::ExecutedFields {
        crate::executed_fields::ExecutedFields {
            state_root: B256::repeat_byte(byte),
            receipts_root: B256::repeat_byte(byte ^ 1),
            logs_bloom: Default::default(),
            gas_used: u64::from(byte),
        }
    }

    /// T4: a chained build whose grandparent's result is filed under the
    /// builder hash only (the own-block hand-off has not run) seals, through
    /// the alias noted when the parent's build was requested; after a view
    /// timeout re-seals the grandparent the new sealed hash is noted and
    /// followed; with nothing filed the build fails (the loud `ParentUnknown`).
    #[test]
    fn a_chained_build_finds_its_grandparent_through_the_alias() {
        let genesis = depth_two_genesis();
        let (gp_built, gp_sealed, gp_resealed) = (alloy_primitives::keccak256(b"depth-two-tests-0xd1"), alloy_primitives::keccak256(b"depth-two-tests-0xd2"), alloy_primitives::keccak256(b"depth-two-tests-0xd3"));
        crate::executed_fields::remember(gp_built, fields(0xd4));
        // The parent was built on the grandparent's sealed hash.
        let parent = SealedHeader::new(
            n42_header::N42Header::from(alloy_consensus::Header { number: 12, timestamp: 12, parent_hash: gp_sealed, ..Default::default() }),
            alloy_primitives::keccak256(b"depth-two-tests-0xd5"),
        );
        let no_alias = SealedHeader::new(
            n42_header::N42Header::from(alloy_consensus::Header { number: 12, timestamp: 12, parent_hash: alloy_primitives::keccak256(b"depth-two-tests-0xd6"), ..Default::default() }),
            alloy_primitives::keccak256(b"depth-two-tests-0xd7"),
        );
        // With nothing under the sealed hash the build waits, then fails.
        let short = std::time::Duration::from_millis(20);
        assert_eq!(
            crate::hotstuff_consensus::ancestor_executed_fields_or_built(&genesis, &no_alias, Some(no_alias.parent_hash), 2, short),
            None
        );
        // The parent's build request noted (sealed, built) for the grandparent.
        crate::executed_fields::note_built(gp_sealed, gp_built);
        crate::executed_fields::remember(gp_built, fields(0xd4));
        assert_eq!(carried_fields_for_seal(&genesis, &parent, Some(parent.hash()), 2), Some(fields(0xd4)));
        // A re-seal of the grandparent (a view timeout): the request on the
        // re-sealed block notes its new hash, and a parent on it finds it.
        crate::executed_fields::note_built(gp_resealed, gp_built);
        // Filed again: the registry is process-wide and bounded, and work
        // other tests left running may have pushed the entry out meanwhile.
        crate::executed_fields::remember(gp_built, fields(0xd4));
        let on_resealed = SealedHeader::new(
            n42_header::N42Header::from(alloy_consensus::Header { number: 12, timestamp: 13, parent_hash: gp_resealed, ..Default::default() }),
            alloy_primitives::keccak256(b"depth-two-tests-0xd8"),
        );
        assert_eq!(carried_fields_for_seal(&genesis, &on_resealed, Some(on_resealed.hash()), 2), Some(fields(0xd4)));
        // At the chain start (parent 1) the genesis result is the parent's own header.
        let block1 = SealedHeader::new(
            n42_header::N42Header::from(alloy_consensus::Header { number: 1, timestamp: 1, state_root: alloy_primitives::keccak256(b"depth-two-tests-0xd9"), ..Default::default() }),
            alloy_primitives::keccak256(b"depth-two-tests-0xda"),
        );
        assert_eq!(
            carried_fields_for_seal(&genesis, &block1, None, 2).map(|f| f.state_root),
            Some(alloy_primitives::keccak256(b"depth-two-tests-0xd9"))
        );
    }
}

#[cfg(test)]
mod hand_out_early_tests {
    use super::{hand_out_early, EthBuiltPayload};
    use alloy_primitives::{Address, U256};
    use reth_primitives_traits::{RecoveredBlock, SealedBlock};
    use std::sync::Arc;

    fn block() -> Arc<RecoveredBlock<n42_tx_types::Block>> {
        let tx = n42_tx_types::N42TxEnvelope::Eth(reth_ethereum_primitives::TransactionSigned::new_unhashed(
            reth_ethereum_primitives::Transaction::Legacy(alloy_consensus::TxLegacy { nonce: 1, ..Default::default() }),
            alloy_primitives::Signature::test_signature(),
        ));
        let block = n42_tx_types::Block {
            header: n42_header::N42Header::from(alloy_consensus::Header { number: 7, extra_data: b"sealed".as_slice().into(), ..Default::default() }),
            body: alloy_consensus::BlockBody { transactions: vec![tx], ommers: Vec::new(), withdrawals: None },
        };
        Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), vec![Address::with_last_byte(1)]))
    }

    /// The build keeps no reference to the block once the hook's payload is
    /// gone: the own-block hand-off, the store's slots aside, is then the
    /// block's last holder and can move its body.
    #[test]
    fn the_build_keeps_no_reference_to_the_block_it_handed_out() {
        let recovered = block();
        let (send, receive) = std::sync::mpsc::sync_channel::<EthBuiltPayload>(1);
        let kept = hand_out_early(&recovered, U256::from(3), move |payload| {
            let _ = send.send(payload);
        });
        let handed = receive.recv().expect("the hook's payload");
        assert!(Arc::ptr_eq(handed.block_arc(), &recovered), "the hook gets the block itself");
        assert_eq!(handed.recovered_block().senders().len(), 1);
        drop(handed);
        assert_eq!(Arc::strong_count(&recovered), 1, "the stand-in the build keeps holds no reference to the block");
        assert_eq!(kept.block().hash(), recovered.hash(), "the stand-in is under the sealed header");
        assert!(kept.block().body().transactions.is_empty());
        assert_eq!(kept.fees(), U256::from(3));
        // The hand-off's move then succeeds: the last holder unwraps it.
        assert!(Arc::try_unwrap(recovered).is_ok());
    }
}

/// Audit R3-E1: under deferred execution the builder admits only what the
/// follower's includability check (`bin/n42/src/follower_import.rs`,
/// `check_includable_laid_out`) accepts; before the fork, reth's rule.
#[cfg(test)]
mod includability_tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Address, Bytes, Signature, TxKind};
    use reth_basic_payload_builder::PayloadConfig;
    use reth_chainspec::{ChainSpec, ChainSpecBuilder};
    use reth_primitives_traits::{Recovered, RecoveredBlock, SealedHeader};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        error::InvalidPoolTransactionError,
        identifier::{SenderId, TransactionId},
        noop::NoopTransactionPool,
        TransactionOrigin,
    };
    use std::collections::{HashMap, VecDeque};

    type Pooled = crate::N42PooledTransaction;
    type Candidate = Arc<ValidPoolTransaction<Pooled>>;

    const GAS_LIMIT: u64 = 1_000_000;
    const BASE_FEE: u64 = 1_000_000_000;
    const TIMESTAMP: u64 = 1_800_000_000;

    /// The pool's best transactions, in the order given: a refusal drops the
    /// sender's later transactions, as reth's iterator does.
    struct Listed {
        txs: VecDeque<Candidate>,
        refused: Vec<Address>,
    }

    impl Iterator for Listed {
        type Item = Candidate;
        fn next(&mut self) -> Option<Candidate> {
            loop {
                let tx = self.txs.pop_front()?;
                if !self.refused.contains(&tx.sender()) {
                    return Some(tx);
                }
            }
        }
    }

    impl BestTransactions for Listed {
        fn mark_invalid(&mut self, transaction: &Candidate, _kind: InvalidPoolTransactionError) {
            self.refused.push(transaction.sender());
        }
        fn no_updates(&mut self) {}
        fn skip_blobs(&mut self) {}
        fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
    }

    fn address(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    /// A transfer of `sender` at `nonce`: `gas_limit`, fee cap 10 gwei, tip
    /// 1 gwei (2 gwei effective at the 1 gwei base fee), value 1.
    fn transfer(sender: u64, nonce: u64, gas_limit: u64) -> Candidate {
        let inner = TxEip1559 {
            chain_id: 1,
            nonce,
            gas_limit,
            max_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(address(1_000_000 + sender * 1_000 + nonce)),
            value: U256::from(1),
            input: Bytes::new(),
            ..Default::default()
        };
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
        let envelope = TransactionSigned::from(reth_ethereum_primitives::TransactionSigned::from(signed));
        let encoded = alloy_eips::eip2718::Encodable2718::encode_2718_len(&envelope);
        Arc::new(ValidPoolTransaction {
            transaction: Pooled::new(Recovered::new_unchecked(envelope, address(sender)), encoded),
            transaction_id: TransactionId::new(SenderId::from(sender), nonce),
            propagate: false,
            timestamp: std::time::Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    fn chain(deferred: bool) -> Arc<ChainSpec> {
        let mut genesis = alloy_genesis::Genesis::default();
        if deferred {
            genesis
                .config
                .extra_fields
                .insert(reth_chainspec::qmdb::DEFERRED_EXECUTION_TIME_KEY.to_owned(), serde_json::json!(TIMESTAMP));
        }
        Arc::new(ChainSpecBuilder::mainnet().genesis(genesis).prague_activated().build())
    }

    /// The block built over `accounts` from `txs`, the first past the fork
    /// (deferred execution from `TIMESTAMP`) when `deferred`.
    fn build(deferred: bool, accounts: &[(Address, u64, U256)], txs: Vec<Candidate>) -> RecoveredBlock<n42_tx_types::Block> {
        build_on(chain(deferred), None, None, accounts, txs)
    }

    /// [`build`] on `spec`, with the attributes naming `slot_number` and
    /// `mobile_registry_root`.
    fn build_on(
        spec: Arc<ChainSpec>,
        slot_number: Option<u64>,
        mobile_registry_root: Option<B256>,
        accounts: &[(Address, u64, U256)],
        txs: Vec<Candidate>,
    ) -> RecoveredBlock<n42_tx_types::Block> {
        let client = MockEthProvider::default().with_chain_spec((*spec).clone());
        for (address, nonce, balance) in accounts {
            client.add_account(*address, ExtendedAccount::new(*nonce, *balance));
        }
        // Far above any height another test marks decided (the process-wide
        // `canonical_head`, which would decline the build), and before the
        // fork, so the header carries the parent's own fields.
        let parent = n42_header::N42Header::from(alloy_consensus::Header {
            number: 1_000_000_000,
            gas_limit: GAS_LIMIT,
            gas_used: GAS_LIMIT / 2,
            base_fee_per_gas: Some(BASE_FEE),
            timestamp: TIMESTAMP - 4,
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            parent_beacon_block_root: Some(B256::ZERO),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        });
        let attributes = EthPayloadAttributes {
            timestamp: TIMESTAMP,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: address(7),
            withdrawals: Some(Vec::new()),
            parent_beacon_block_root: Some(B256::ZERO),
            slot_number,
            target_gas_limit: None,
            mobile_registry_root,
        };
        let config = PayloadConfig {
            parent_header: Arc::new(SealedHeader::seal_slow(parent)),
            parent_block_info: None,
            attributes,
            payload_id: Default::default(),
        };
        let args = BuildArguments::new(Default::default(), None, None, config, Default::default(), None);
        let evm_config = crate::n42_evm::N42EvmConfig::new(spec.clone());
        let listed = Listed { txs: txs.into(), refused: Vec::new() };
        let outcome = default_n42_payload(
            evm_config,
            client,
            NoopTransactionPool::<Pooled>::new(),
            EthereumBuilderConfig::new().with_gas_limit(GAS_LIMIT),
            args,
            move |_| Box::new(listed) as BestTransactionsIter<NoopTransactionPool<Pooled>>,
            Arc::new(crate::hotstuff_consensus::HotStuffConsensus::new(Arc::new(n42_header::N42ChainSpec::from(spec)))),
            None,
            None,
            None,
        )
        .expect("the build");
        let payload = outcome.into_payload().expect("a payload");
        payload.recovered_block().clone()
    }

    /// The follower's verdict, recomputed over a built block (the follower's
    /// own functions live in `bin/n42`): the gas limits' sum within the
    /// header's, and per sender in block order nonces on from the parent's,
    /// fee cap over the base fee, tip under the cap, and the summed
    /// worst-case cost within the parent's balance.
    fn follower_verdict(block: &RecoveredBlock<n42_tx_types::Block>, accounts: &[(Address, u64, U256)]) -> Result<(), String> {
        let header = block.header();
        let base_fee = u128::from(header.base_fee_per_gas.unwrap_or(0));
        let gas: u64 = block.body().transactions.iter().map(|tx| tx.gas_limit()).sum();
        if gas > header.gas_limit {
            return Err(format!("gas limits sum to {gas}, over the block's {}", header.gas_limit));
        }
        let mut ledger: HashMap<Address, (u64, U256)> = HashMap::new();
        for (tx, sender) in block.body().transactions.iter().zip(block.senders()) {
            let (nonce, balance) = accounts.iter().find(|(a, _, _)| a == sender).map_or((0, U256::ZERO), |(_, n, b)| (*n, *b));
            let entry = ledger.entry(*sender).or_insert((nonce, U256::ZERO));
            if tx.nonce() != entry.0 {
                return Err(format!("{sender}: nonce {}, expected {}", tx.nonce(), entry.0));
            }
            if tx.max_fee_per_gas() < base_fee || tx.max_priority_fee_per_gas().is_some_and(|tip| tip > tx.max_fee_per_gas()) {
                return Err(format!("{sender}: fees"));
            }
            entry.0 += 1;
            entry.1 += crate::frame_scan::tx_cost(tx);
            if entry.1 > balance {
                return Err(format!("{sender}: cost {} over a balance of {balance}", entry.1));
            }
        }
        Ok(())
    }

    const RICH: U256 = U256::from_limbs([0, 1, 0, 0]);

    /// gov5's MobileAnchor gate on a HotStuff chain (`glamsterdamTime` and
    /// `mobileAnchorTime`, no reth Amsterdam): the leader's build carries the
    /// slot number and the registry root its attributes named, so the header
    /// it seals is the one the chain's members expect.
    #[test]
    fn a_gated_build_carries_the_slot_and_the_registry_root() {
        let mut genesis = alloy_genesis::Genesis::default();
        for key in [reth_chainspec::qmdb::GLAMSTERDAM_TIME_KEY, reth_chainspec::qmdb::MOBILE_ANCHOR_TIME_KEY] {
            genesis.config.extra_fields.insert(key.to_owned(), serde_json::json!(0));
        }
        let spec = Arc::new(ChainSpecBuilder::mainnet().genesis(genesis).prague_activated().build());
        let root = B256::repeat_byte(0x24);
        let block = build_on(spec, Some(1_000_000_001), Some(root), &[], Vec::new());
        assert_eq!(block.header().mobile_registry_root, Some(root), "the registry root");
        assert_eq!(block.header().slot_number, Some(1_000_000_001), "the slot number");
    }

    /// Thirty transfers of 60,000 gas limit that use 21,000 each: the gas
    /// used fits a 1,000,000 block, the gas limits do not.
    fn headroom_case() -> (Vec<(Address, u64, U256)>, Vec<Candidate>) {
        let accounts: Vec<_> = (1..=30).map(|s| (address(s), 0, RICH)).collect();
        let txs = (1..=30).map(|s| transfer(s, 0, 60_000)).collect();
        (accounts, txs)
    }

    #[test]
    fn a_deferred_build_keeps_the_gas_limits_within_the_block() {
        let (accounts, txs) = headroom_case();
        let block = build(true, &accounts, txs);
        let gas: u64 = block.body().transactions.iter().map(|tx| tx.gas_limit()).sum();
        assert!(gas <= block.header().gas_limit, "gas limits {gas} over {}", block.header().gas_limit);
        assert_eq!(block.body().transactions.len(), (GAS_LIMIT / 60_000) as usize, "as many as the limits allow");
        follower_verdict(&block, &accounts).expect("the follower accepts the block");
    }

    #[test]
    fn a_build_before_the_fork_budgets_by_gas_used() {
        let (accounts, txs) = headroom_case();
        let block = build(false, &accounts, txs);
        assert_eq!(block.body().transactions.len(), 30, "reth's rule: every transaction executes within the gas");
    }

    /// The worst-case cost of one transfer: 21,000 x 10 gwei + 1.
    fn worst() -> U256 {
        U256::from(21_000u64 * 10_000_000_000 + 1)
    }

    /// Sender 1 can pay two transfers at the effective price, and each at
    /// its fee cap on its own, but not both at the fee cap; sender 2 is rich.
    fn balance_case() -> (Vec<(Address, u64, U256)>, Vec<Candidate>) {
        let accounts = vec![(address(1), 0, worst() * U256::from(2) - U256::from(1)), (address(2), 0, RICH)];
        let txs = vec![transfer(1, 0, 21_000), transfer(1, 1, 21_000), transfer(2, 0, 21_000), transfer(2, 1, 21_000)];
        (accounts, txs)
    }

    #[test]
    fn a_deferred_build_keeps_each_senders_worst_case_within_its_balance() {
        let (accounts, txs) = balance_case();
        let block = build(true, &accounts, txs);
        let of = |s: u64| block.senders().iter().filter(|a| **a == address(s)).count();
        assert_eq!(of(1), 1, "the second transfer could cost more than sender 1 has");
        assert_eq!(of(2), 2, "the other sender's transfers are still in");
        follower_verdict(&block, &accounts).expect("the follower accepts the block");
    }

    /// [`build`] with `N42_PARALLEL_BUILD` as `parallel` on this thread, the
    /// fold made to refuse once when `refuse_fold`.
    fn build_with(parallel: bool, refuse_fold: bool, deferred: bool, accounts: &[(Address, u64, U256)], txs: &[Candidate]) -> RecoveredBlock<n42_tx_types::Block> {
        PARALLEL_BUILD_FOR_TEST.with(|on| on.set(Some(parallel)));
        crate::graft_fold::REFUSE_NEXT_FOLD.with(|next| next.set(refuse_fold));
        let block = build(deferred, accounts, txs.to_vec());
        PARALLEL_BUILD_FOR_TEST.with(|on| on.set(None));
        crate::graft_fold::REFUSE_NEXT_FOLD.with(|next| next.set(false));
        block
    }

    /// Ten senders, two transfers each, every recipient created: the
    /// parallel step's block (F5c) is the serial build's, header and all;
    /// and when the fold refuses at `finish` the build rebuilds the block
    /// serially in the same build, which is again the same block.
    #[test]
    fn the_parallel_build_and_its_serial_rebuild_give_the_serial_block() {
        // Not sender 7: the attributes' fee recipient.
        let accounts: Vec<_> = (11..=20).map(|s| (address(s), 0, RICH)).collect();
        let txs: Vec<Candidate> = (11..=20).flat_map(|s| [transfer(s, 0, 21_000), transfer(s, 1, 21_000)]).collect();
        let serial = build_with(false, false, false, &accounts, &txs);
        assert_eq!(serial.body().transactions.len(), 20);
        let rebuilds = crate::parallel_build::serial_rebuilds();
        let runs = crate::parallel_build::committed_runs();
        let parallel = build_with(true, false, false, &accounts, &txs);
        assert!(crate::parallel_build::committed_runs() > runs, "the block went parallel");
        assert_eq!(crate::parallel_build::serial_rebuilds(), rebuilds, "the fold held");
        assert_eq!(parallel.header(), serial.header(), "the parallel step's block");
        let rebuilt = build_with(true, true, false, &accounts, &txs);
        assert_eq!(crate::parallel_build::serial_rebuilds(), rebuilds + 1, "the refused fold rebuilt the block");
        assert_eq!(rebuilt.header(), serial.header(), "the serial rebuild's block");
        assert_eq!(rebuilt.body().transactions.len(), 20);
    }

    /// Build path = follower path = serial (the legacy tree's test, on
    /// evm2): the block the parallel builder (F5c) seals, imported by the
    /// parallel follower (F5d), gives the stock serial import's receipts,
    /// gas, bundle and QMDB root, and the gas its header carries.
    #[test]
    fn a_parallel_built_block_imports_in_parallel_as_it_imports_serially() {
        use reth_evm::execute::Executor as _;
        let accounts: Vec<_> = (11..=20).map(|s| (address(s), 0, RICH)).collect();
        let txs: Vec<Candidate> = (11..=20).flat_map(|s| [transfer(s, 0, 21_000), transfer(s, 1, 21_000)]).collect();
        let runs = crate::parallel_build::committed_runs();
        let block = build_with(true, false, false, &accounts, &txs);
        assert!(crate::parallel_build::committed_runs() > runs, "the block was built in parallel");
        assert_eq!(block.body().transactions.len(), 20);
        let config = crate::n42_evm::N42EvmConfig::new(Arc::new(n42_header::N42ChainSpec::from((*chain(false)).clone())));
        let parent = || {
            let mut db = evm2::evm::CacheDB::new(evm2::evm::EmptyDB::default());
            for (address, nonce, balance) in &accounts {
                db.insert_account_info(address, evm2::evm::AccountInfo { nonce: *nonce, balance: *balance, ..Default::default() });
            }
            db
        };
        let (ours, stats) = crate::parallel_build::import_block(&config, &block, parent(), &|| Some(parent()), crate::parallel_transfer::Dispatch::LargestFirst(4), None)
            .expect("the parallel import");
        assert_eq!((stats.txs, stats.tail), (20, 0), "{stats:?}");
        assert!(stats.batches >= 2, "{stats:?}");
        let stock = config.executor(parent()).execute(&block).expect("the serial import");
        assert_eq!(ours.result.receipts, stock.result.receipts, "receipts");
        assert_eq!(ours.result.gas_used, stock.result.gas_used, "gas used");
        assert_eq!(ours.result.gas_used, block.header().gas_used, "the header's gas");
        assert_eq!(ours.state.state, stock.state.state, "state");
        assert_eq!(ours.state.contracts, stock.state.contracts, "contracts");
        let reverts = |out: &reth_evm::BlockExecutionOutput<n42_tx_types::Receipt>| {
            out.state
                .reverts
                .iter()
                .map(|block| {
                    let mut v: Vec<_> = block.iter().map(|(a, r)| (*a, format!("{r:?}"))).collect();
                    v.sort_by_key(|(a, _)| *a);
                    v
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(reverts(&ours), reverts(&stock), "reverts");
        let root = |out: &reth_evm::BlockExecutionOutput<n42_tx_types::Receipt>| {
            n42_qmdb_state::QmdbState::new()
                .apply_block(block.header().number, &n42_qmdb_reth::changes_from_execution(&out.state, true))
                .expect("the QMDB root")
        };
        assert_eq!(root(&ours), root(&stock), "QMDB root");
    }

    /// Under deferred execution the parallel step keeps each sender's
    /// summed worst case within its balance, as the serial loop does.
    #[test]
    fn a_deferred_parallel_build_keeps_each_senders_worst_case_within_its_balance() {
        let (accounts, txs) = balance_case();
        let block = build_with(true, false, true, &accounts, &txs);
        let of = |s: u64| block.senders().iter().filter(|a| **a == address(s)).count();
        assert_eq!(of(1), 1, "the second transfer could cost more than sender 1 has");
        assert_eq!(of(2), 2, "the other sender's transfers are still in");
        follower_verdict(&block, &accounts).expect("the follower accepts the block");
    }

    #[test]
    fn a_build_before_the_fork_admits_what_executes() {
        let (accounts, txs) = balance_case();
        let block = build(false, &accounts, txs);
        assert_eq!(block.body().transactions.len(), 4, "reth's rule: both of sender 1's transfers execute");
    }
}

/// The prepared build's take on evm2 (F5g8).
#[cfg(test)]
mod prepared_take_tests {
    use super::made_cands_cut;

    /// The selection moves the plan's candidates into the bulk vector: an
    /// uncut bulk take of the plan's length is the plan's, a cut one or a
    /// take without the bulk vector is not.
    #[test]
    fn the_prepared_build_is_the_plans_only_on_its_uncut_bulk_take() {
        assert!(!made_cands_cut(true, 200_000, 200_000));
        assert!(made_cands_cut(true, 200_500, 200_000), "cut to the budget");
        assert!(made_cands_cut(false, 0, 200_000), "pulled, not the bulk vector");
    }
}

/// The evm2 plan-ahead body's cost (F5g6): what `make_prepared_build` takes
/// off the build, and what the build does inline without it.
#[cfg(test)]
mod plan_body_evm2_tests {
    use super::*;
    use alloy_primitives::{Address, Bytes};
    use n42_tx_types::{AltSigTx, N42TxEnvelope, TxAltSig, ALG_ED25519};
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{
        identifier::{SenderId, TransactionId},
        TransactionOrigin, ValidPoolTransaction,
    };

    type Cand = Arc<ValidPoolTransaction<crate::N42PooledTransaction>>;

    fn address(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[..8].copy_from_slice(&i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    /// `senders` frames of `run` 0x50 transfers each, recipients drawn from
    /// `space`.
    fn frames(senders: u64, run: u64, space: u64) -> Vec<(n42_tx_queue::FrameTxs<crate::N42PooledTransaction>, usize)> {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut out = Vec::new();
        for s in 0..senders {
            let sender = address(100 + s);
            let mut pubkey = [0u8; 32];
            pubkey[..8].copy_from_slice(&s.to_be_bytes());
            let mut frame: Vec<Cand> = Vec::new();
            for k in 0..run {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let tx = TxAltSig {
                    chain_id: 1,
                    nonce: k,
                    max_priority_fee_per_gas: 1_000_000_000,
                    max_fee_per_gas: 10_000_000_000,
                    gas_limit: 21_000,
                    to: address(1_000_000 + seed % space),
                    value: U256::from(1_000 + k),
                    input: Bytes::new(),
                    access_list: Default::default(),
                    alg_type: ALG_ED25519,
                    pubkey: Bytes::copy_from_slice(&pubkey),
                };
                let mut signature = [0u8; 64];
                signature[..8].copy_from_slice(&seed.to_be_bytes());
                let envelope = N42TxEnvelope::AltSig(AltSigTx::new(tx, Bytes::copy_from_slice(&signature)));
                let encoded = alloy_eips::eip2718::Encodable2718::encode_2718_len(&envelope);
                let pooled = crate::N42PooledTransaction::new(Recovered::new_unchecked(envelope, sender), encoded);
                frame.push(Arc::new(ValidPoolTransaction {
                    transaction: pooled,
                    transaction_id: TransactionId::new(SenderId::from(s), k),
                    propagate: false,
                    timestamp: std::time::Instant::now(),
                    origin: TransactionOrigin::External,
                    authority_ids: None,
                }));
            }
            let len = frame.len();
            out.push((Arc::from(frame), len));
        }
        out
    }

    /// 200,000 transfers (400 senders of 500, recipients from 2,000,000):
    /// the hook's whole cost on the plan body's pool (off the build), against
    /// what the build does on its own thread without it -- the keys, the
    /// partition at the beneficiary, and the seal's body made on the build
    /// pool (F5g4's fallback). Ignored:
    ///
    /// ```text
    /// cargo test --release -p n42-engine-types --lib plan_body_prep_bound -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "timing"]
    fn plan_body_prep_bound() {
        use rayon::prelude::*;
        let rounds = std::env::var("F5G_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(5usize);
        let beneficiary = address(1);
        crate::frame_blocks::note_beneficiary(beneficiary);
        let segments = frames(400, 500, 2_000_000);
        let mut plan = n42_tx_queue::FramePlan::default();
        for (txs, taken) in &segments {
            let frame_hashes: Vec<B256> = txs.iter().map(|tx| *tx.hash()).collect();
            plan.frames.push(n42_tx_queue::PlannedFrame { id: n42_tx_types::frame_root(&frame_hashes), len: txs.len(), taken: *taken });
            plan.push_hashes(Arc::from(frame_hashes), *taken);
        }
        let cands: Vec<Cand> = segments.iter().flat_map(|(txs, taken)| txs[..*taken].to_vec()).collect();
        let median = |mut v: Vec<u128>| {
            v.sort_unstable();
            v[v.len() / 2] as f64 / 1000.0
        };
        let (mut hook, mut keys_ms, mut part_ms, mut body_ms) = (vec![], vec![], vec![], vec![]);
        let (mut shards_new, mut fees_serial, mut fees_pool) = (vec![], vec![], vec![]);
        let base_fee = 1_000_000_000u64;
        for _ in 0..rounds {
            let at = std::time::Instant::now();
            let made = make_prepared_build(&segments, &plan).expect("every candidate a transfer");
            hook.push(at.elapsed().as_micros());
            assert_eq!(made.cands.len(), cands.len());
            assert!(made.groups.is_some());
            drop(made);
            let at = std::time::Instant::now();
            let keys = cands.iter().map(|tx| transfer_key(tx)).collect::<Option<Vec<_>>>().expect("transfers");
            keys_ms.push(at.elapsed().as_micros());
            let at = std::time::Instant::now();
            let groups = crate::parallel_transfer::partition_by_sender(&keys, beneficiary).expect("a partition");
            part_ms.push(at.elapsed().as_micros());
            drop(groups);
            let at = std::time::Instant::now();
            #[allow(clippy::type_complexity)]
            let body: (Vec<TransactionSigned>, (Vec<Address>, Vec<B256>)) = crate::parallel_transfer::build_pool().install(|| {
                cands.par_iter().with_min_len(1024).map(|tx| (pooled_consensus(tx).clone(), (tx.sender(), *tx.hash()))).unzip()
            });
            body_ms.push(at.elapsed().as_micros());
            drop(body);
            // The step's other pre-execution part: the output shards' set-up.
            let at = std::time::Instant::now();
            let shards = crate::output_shards::OutputShards::new(beneficiary, cands.len(), 16);
            shards_new.push(at.elapsed().as_micros());
            drop(shards);
            // After the execution: the fees over the executed set, serial
            // (before F5g8) and on the build pool.
            let at = std::time::Instant::now();
            let mut fees = U256::ZERO;
            for tx in &cands {
                fees += U256::from(pooled_consensus(tx).effective_tip_per_gas(base_fee).unwrap_or_default()) * U256::from(21_000u64);
            }
            fees_serial.push(at.elapsed().as_micros());
            let at = std::time::Instant::now();
            let pooled: U256 = crate::parallel_transfer::build_pool().install(|| {
                cands
                    .par_iter()
                    .with_min_len(4096)
                    .map(|tx| U256::from(pooled_consensus(tx).effective_tip_per_gas(base_fee).unwrap_or_default()) * U256::from(21_000u64))
                    .reduce(|| U256::ZERO, |a, b| a + b)
            });
            fees_pool.push(at.elapsed().as_micros());
            assert_eq!(fees, pooled);
        }
        eprintln!(
            "plan_body_prep_bound medians over {rounds}: txs={} hook_ms={:.1} (plan body pool, off the build) | inline: keys_ms={:.1} partition_ms={:.1} body_ms={:.1}",
            cands.len(),
            median(hook),
            median(keys_ms),
            median(part_ms),
            median(body_ms),
        );
        eprintln!(
            "plan_body_prep_bound step split medians: shards_new_ms={:.1} fees_serial_ms={:.1} fees_pool_ms={:.1}",
            median(shards_new),
            median(fees_serial),
            median(fees_pool),
        );
    }
}

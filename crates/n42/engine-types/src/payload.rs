//! A basic Ethereum payload builder implementation.

/*
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
*/
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(clippy::useless_let_if_seq)]

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{B256, U256};
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_errors::{BlockExecutionError, BlockValidationError};
use n42_tx_types::{N42Primitives as EthPrimitives, N42TxEnvelope as TransactionSigned};
use alloy_consensus::transaction::TxHashRef as _;
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig};
use crate::engine_types::N42BuiltPayload as EthBuiltPayload;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};
use revm::context_interface::Block as _;
use revm::Database as _;
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
use reth_consensus::{ConsensusError, FullConsensus};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_node_api::PayloadBuilderFor;
use reth_node_api::PrimitivesTy;
use reth_node_builder::{
    components::{ConsensusBuilder, PayloadBuilderBuilder, PayloadServiceBuilder},
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use std::future::Future;

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
pub struct EthereumPayloadBuilderWrapper;

impl EthereumPayloadBuilderWrapper {
    /// Create a new wrapper.
    pub fn new() -> Self {
        Self
    }
}
// wrapper

// reth/crates/ethereum/payload/src/config.rs
use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
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
pub fn calculate_block_gas_limit(parent_gas_limit: u64, desired_gas_limit: u64) -> u64 {
    let delta = (parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1);
    let min_gas_limit = parent_gas_limit - delta;
    let max_gas_limit = parent_gas_limit + delta;
    desired_gas_limit.clamp(min_gas_limit, max_gas_limit)
}
// reth/crates/ethereum/payload/src/config.rs

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
        BlockAssembler = EthBlockAssembler<Client::ChainSpec>,
        BlockExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<Client::ChainSpec>,
    >,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec + reth_evm::eth::spec::EthExecutorSpec>
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
        config: PayloadConfig<Self::Attributes>,
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

// The raw payload channel's way in: a build on a block this node built and
// consensus has just sealed, from that build's own post-state, with reth's
// payload service out of the way. See `direct_build`.
impl<Pool, Client, EvmConfig, Cons> crate::direct_build::DirectBuilder
    for N42PayloadBuilder<Pool, Client, EvmConfig, Cons>
where
    EvmConfig: ConfigureEvm<
            Primitives = EthPrimitives,
            NextBlockEnvCtx = NextBlockEnvAttributes,
            BlockAssembler = EthBlockAssembler<Client::ChainSpec>,
            BlockExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<Client::ChainSpec>,
        > + Send
        + Sync
        + 'static,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec + reth_evm::eth::spec::EthExecutorSpec>
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
        let parent_built = parent_execution.built_hash();
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
    *ON.get_or_init(|| std::env::var("N42_SEAL_FIRST").map_or(true, |v| v != "0"))
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
    *ON.get_or_init(|| std::env::var("N42_SEAL_AT_EXEC").is_ok_and(|v| v == "1"))
}

/// `N42_SEAL_ON_COUNTERS=1` (`docs/SHARED_EXECUTION_SCOPE.md` 16.4 item 1;
/// `N42_SEAL_ON_COUNTS=1` is the same switch): with `N42_SEAL_AT_EXEC=1` and
/// the body made in the prep, every batch counts its transfers, their gas and
/// their fees as it executes, and a block that seals at the execution's end
/// with every candidate executed in pull order seals on those sums, with the
/// prep's body, and no pass over the slots on the seal's path (the pass on the
/// build pool that finished behind the freeze's slowest task, 16.2). The
/// references are then made behind the seal by the receipts job only. Any
/// other block makes them as before. Off by default.
pub fn seal_on_counters() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        ["N42_SEAL_ON_COUNTERS", "N42_SEAL_ON_COUNTS"]
            .iter()
            .any(|name| std::env::var(name).is_ok_and(|v| v.trim() == "1"))
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
    *ON.get_or_init(|| std::env::var("N42_FREEZE_AFTER_SEAL").is_ok_and(|v| v.trim() == "1"))
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
    *ON.get_or_init(|| std::env::var("N42_ROOT_OPS_AHEAD").is_ok_and(|v| v.trim() == "1"))
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
    *ON.get_or_init(|| std::env::var("N42_STATE_AFTER_PULL").is_ok_and(|v| v == "1"))
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

impl revm::DatabaseRef for LazyParentDb<'_> {
    type Error = reth_storage_api::errors::ProviderError;

    fn basic_ref(&self, address: alloy_primitives::Address) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<revm::state::Bytecode, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: alloy_primitives::Address, index: U256) -> Result<U256, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        StateProviderDatabase::new(reth_storage_api::StateProvider::into_evm_state_provider(self.provider()?)).block_hash_ref(number)
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

/// The pooled candidates of a parallel step, in pull order: a slot's
/// `index` names its transaction here (the slot keeps no copy of it).
type Pulled<P> = [Arc<reth_transaction_pool::ValidPoolTransaction<P>>];

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
    let inner = &tx.transaction;
    (inner.gas_limit() == MIN_TRANSACTION_GAS
        && inner.input().is_empty()
        && !inner.is_create()
        && inner.access_list().is_none_or(|list| list.is_empty())
        && !inner.is_eip4844()
        && !inner.is_eip7702())
    .then(|| (tx.sender(), inner.to().unwrap_or_default()))
}

/// The plan-ahead hook's work (`N42_PLAN_AHEAD_BODY=1`): from a prepared
/// plan's segments, on the plan body's own pool, the candidates in plan
/// order, their transfer keys, the body's transactions and senders and the
/// hashes, the partition at the beneficiary this node builds for, and the
/// empty slots -- what the next build's start, prep and gap made. `None`
/// when not every candidate is a plain transfer (the build preps as before).
fn make_prepared_build<P: PoolTransaction<Consensus = TransactionSigned>>(
    segments: &[(n42_tx_queue::FrameTxs<P>, usize)],
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
    // The prep's own pass, with no tip: the batches read the tips at the
    // block's base fee (`N42_SEAL_ON_COUNTERS`), which this cannot know.
    let (keys, made) = crate::parallel_transfer::BodyAhead::make_keyed_on(pool, &cands, |_, tx| {
        (transfer_key(tx), pooled_consensus(tx).clone(), tx.sender(), 0, *tx.hash())
    })?;
    if keys.is_empty() {
        return None;
    }
    let hashes = made.hashes;
    let groups = crate::frame_blocks::noted_beneficiary().and_then(|beneficiary| {
        crate::parallel_transfer::partition_by_sender(&keys, beneficiary).ok().map(|groups| (beneficiary, groups))
    });
    let slots = crate::parallel_transfer::empty_slots(pool, cands.len());
    Some(crate::frame_blocks::PreparedBuild {
        segments: segments.to_vec(),
        cands,
        keys,
        transactions: made.transactions,
        senders: made.senders,
        hashes,
        groups,
        slots,
        made_us: at.elapsed().as_micros() as u64,
    })
}

/// Installs the plan-ahead hook on the queue once (`N42_PLAN_AHEAD_BODY=1`).
fn install_plan_ahead_body<P: PoolTransaction<Consensus = TransactionSigned>>(queue: &n42_tx_queue::TxQueue<P>) {
    if queue.has_plan_ahead_hook() {
        return;
    }
    queue.set_plan_ahead_hook(Arc::new(|segments: &[(n42_tx_queue::FrameTxs<P>, usize)]| {
        make_prepared_build(segments).map(|made| Box::new(made) as n42_tx_queue::PreparedBody)
    }));
}

/// The cumulative gas through each transaction of a block the parallel step
/// left in its slots, in block order, and the block's gas.
fn cumulative_gas(
    refs: &[&crate::parallel_transfer::BuiltTransfer<()>],
) -> (Vec<u64>, u64) {
    let mut cumulative = Vec::with_capacity(refs.len());
    let mut tx_gas = 0u64;
    for built in refs {
        tx_gas += built.result.gas().tx_gas_used();
        cumulative.push(tx_gas);
    }
    (cumulative, tx_gas)
}

/// The receipts of a block the parallel step left in its slots, in block
/// order, with `cumulative[i]` the block's gas through transaction `i`.
fn receipts_from_slots<P: PoolTransaction<Consensus = TransactionSigned>>(
    refs: &[&crate::parallel_transfer::BuiltTransfer<()>],
    cumulative: &[u64],
    pulled: &Pulled<P>,
) -> Vec<n42_tx_types::Receipt> {
    use rayon::prelude::*;
    refs.par_iter()
        .zip(cumulative.par_iter())
        .map(|(built, cumulative_gas_used)| n42_tx_types::Receipt {
            tx_type: <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(pooled_consensus(&pulled[built.index])),
            success: built.result.is_success(),
            cumulative_gas_used: *cumulative_gas_used,
            logs: built.result.logs().to_vec(),
        })
        .collect()
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
        std::env::var("N42_SEAL_SHORTFALL_DIV").ok().and_then(|v| v.parse().ok()).unwrap_or(64)
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
    *ON.get_or_init(|| std::env::var("N42_BUILD_DECLINE_EMPTY_STEP").map_or(true, |v| v != "0"))
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

/// Thread-local: how long this thread's build waited in its selector for the
/// parent's queue hand-off (`BuildOnOwnRequest::before_pull`), microseconds;
/// reset at the build's selection and reported as `start_handoff_ms`.
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
    *ON.get_or_init(|| std::env::var("N42_BUILD_SKIP_DECIDED").map_or(true, |v| v != "0"))
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

/// Constructs an Ethereum transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Ethereum client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
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
        BlockAssembler = EthBlockAssembler<Client::ChainSpec>,
        BlockExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<Client::ChainSpec>,
    >,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec + reth_evm::eth::spec::EthExecutorSpec>,
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
    // `N42_STATE_AFTER_PULL=1`: opened after the parallel step's pull, prep
    // and partition instead of here (see `state_after_pull`). Only a build
    // that takes the parallel step defers; every other opens it here.
    let defer_state = state_after_pull() && parallel_build() && builder_puller() != 0;
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
    let mut db = State::builder()
        .with_database(cached_reads.as_db_mut(state))
        .with_bundle_update()
        .with_bal_builder_if(is_amsterdam)
        .build();

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
        gas_limit: builder_config.gas_limit(parent_header.gas_limit),
        parent_beacon_block_root: attributes.parent_beacon_block_root,
        withdrawals: attributes.withdrawals.clone().map(Into::into),
        extra_data: Default::default(),
    };
    let evm_env = evm_config
        .next_evm_env(&parent_header, &next_attributes)
        .map_err(PayloadBuilderError::other)?;
    let group_env = evm_env.clone();
    let evm = evm_config.evm_with_env(&mut db, evm_env);
    let block_ctx = evm_config
        .context_for_next_block(&parent_header, next_attributes)
        .map_err(PayloadBuilderError::other)?;
    // The QMDB root is computed inside assembly, beside the transactions
    // trie, and collected from here afterwards.
    let qmdb_root: Arc<std::sync::Mutex<Option<Result<n42_qmdb_reth::PreparedBlock, String>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let mut assembler = crate::assembler::N42BlockAssembler::new(EthBlockAssembler::new(chain_spec.clone()), hotstuff);
    if let Some(state) = &qmdb {
        assembler = assembler.with_qmdb_root(crate::assembler::QmdbRootJob {
            state: state.clone(),
            parent: parent_header.hash(),
            prague: chain_spec.is_prague_active_at_timestamp(attributes.timestamp),
            out: qmdb_root.clone(),
        });
    }
    let build_stage = BuildStage(parent_header.number);
    build_stage.at(1);
    let mut builder: reth_evm::execute::BasicBlockBuilder<'_, EvmConfig::BlockExecutorFactory, _, _, EthPrimitives> = reth_evm::execute::BasicBlockBuilder {
        executor: evm_config.create_executor(evm, block_ctx.clone()),
        ctx: block_ctx,
        assembler,
        parent: &parent_header,
        transactions: Vec::new(),
    };

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
    let fast_hits_before = crate::fast_transfer::hits();
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
    let block_gas_limit: u64 = builder.evm_mut().block().gas_limit();
    let base_fee = builder.evm_mut().block().basefee();

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
    crate::frame_blocks::want_bulk(parallel_build() && builder_puller() != 0);
    // `N42_PLAN_AHEAD_BODY=1`: the queue makes the next block's body with its
    // plan; the partition is made at this build's beneficiary.
    if crate::frame_blocks::plan_ahead_body_wanted()
        && let Some(queue) = n42_tx_queue::global::<Pool::Transaction>()
    {
        crate::frame_blocks::note_beneficiary(group_env.block_env.beneficiary);
        install_plan_ahead_body(&queue);
    }
    let mut best_txs = best_txs(BestTransactionsAttributes::new(
        base_fee,
        builder
            .evm_mut()
            .block()
            .blob_gasprice()
            .map(|gasprice| gasprice as u64),
    ));
    let start_best_us = start_best_at.elapsed().as_micros() as u64;
    let start_best_ms = start_best_us / 1_000;
    let mut bulk = crate::frame_blocks::take_bulk::<Pool::Transaction>();
    // `N42_PLAN_AHEAD_BODY=1`: what was made with the plan, its candidates
    // already the bulk vector (always taken, so nothing is left behind).
    let mut prepared_build = crate::frame_blocks::take_prepared::<Pool::Transaction>();
    let from_bulk = bulk.is_some();
    crate::frame_blocks::want_bulk(false);
    // `N42_FRAME_BLOCKS=1`: the frames the selector just took, whose layout
    // the transactions root is sealed over (`frame_blocks::sealed_root`).
    // The roots computed ahead over the pulled set are the MPT root and are
    // not computed for a frame build.
    let frame_plan = crate::frame_blocks::take_plan();
    let start_handoff_us = HANDOFF_WAIT_US.with(std::cell::Cell::get);
    let start_handoff_ms = start_handoff_us / 1_000;
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
        .prepare(&parent_header)
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
                        builder.apply_pre_execution_changes().map_err(|err| {
                            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
                            PayloadBuilderError::Internal(err.into())
                        })
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
    let mut par_part_ms = 0u64;
    let mut par_exec_ms = 0u64;
    let mut par_fold_ms = 0u64;
    let mut par_committed = 0usize;
    let mut deferred: Vec<Arc<reth_transaction_pool::ValidPoolTransaction<Pool::Transaction>>> = Vec::new();
    // The head the parallel step refused per skipped sender, with the nonce
    // the parent's state has for it: what the give-back below tells the
    // queue instead of a refusal that says nothing. See the diagnosis after
    // the parallel step.
    let mut skipped_heads: alloy_primitives::map::AddressHashMap<(u64, u64)> = Default::default();
    let mut par_reverts: Vec<(alloy_primitives::Address, revm::database::AccountRevert)> = Vec::new();
    let mut par_drained = false;
    let mut par_prep_ms = 0u64;
    let mut par_collect_ms = 0u64;
    // Of the fold: the receipts loop, before the graft.
    let mut par_commit_ms = 0u64;
    // Of the fold: the graft alone. `par_fold_ms` covers the receipts loop
    // and then the longer of the graft and the transactions root beside it.
    let mut par_graft_ms = 0u64;
    // `N42_PHASE_TIMERS=1` (plan v6 6.5): the graft's own sub-phases, the
    // default in-place fold only (`graft_bundles_direct`), and the parallel
    // step's transfers by phase and read door -- see `Phases::transfer_timers`.
    let mut par_graft_base_ms = 0u64;
    let mut par_graft_reserve_ms = 0u64;
    let mut par_graft_insert_ms = 0u64;
    let mut par_graft_reverts_ms = 0u64;
    let mut par_graft_other_ms = 0u64;
    // `N42_GRAFT_SHARDED=1` (plan v6 attempt G proper): whether the graft's
    // insert ran sharded on the build pool, and its three phases in us.
    let mut par_graft_sharded = false;
    let mut par_graft_split_us = 0u64;
    let mut par_graft_build_us = 0u64;
    let mut par_graft_merge_us = 0u64;
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
    let mut par_transfer_timers = crate::fast_transfer::TransferTimers::default();
    // `N42_READ_SET=1` (docs/BREAKTHROUGH_DESIGN.md section 4, design A): the
    // read set's pass and what the batches read from it.
    let mut par_read_set = crate::parallel_transfer::ReadSetPass::default();
    let mut par_read_set_hits = 0u64;
    let mut par_read_set_misses = 0u64;
    // The build's batches on the pool: imbalance, gaps, per-batch overhead.
    let mut par_batch_spans = crate::parallel_transfer::BatchSpans::default();
    let mut par_loop_timers = crate::parallel_transfer::LoopTimers::default();
    // `N42_GRAFT_PREFAULT=1`: how long the graft's memory took to map, on its
    // own thread beside the parallel step (not on the chain).
    let mut par_prefault_ms = 0u64;
    // `N42_BUILD_PREFETCH=1`: the prefetch's own time on the worker pool,
    // summed over its jobs, and how long the build waited for it after the
    // pull and the prep.
    let mut par_prefetch_ms = 0u64;
    let mut par_prefetch_wait_ms = 0u64;
    // The transactions root, computed beside the graft for a block that
    // will seal early.
    let mut early_transactions_root: Option<B256> = None;
    // `N42_DIRECT_RECEIPTS=1`: for a block that will seal early, the receipts and the gas the
    // executor's finish reports, built beside the parallel step instead of one executor commit
    // per transaction (see `direct_receipts_enabled`); taken by the finish behind the seal.
    let mut direct_receipts: Option<(Vec<n42_tx_types::Receipt>, u64)> = None;
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
    let deferred_now = reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), attributes.timestamp);
    // What the seal-first path needs of the chain and the block, short of
    // the block being full (known after the parallel step).
    let seal_early_possible = early_seal.is_some() && deferred_now && hotstuff && !is_amsterdam && qmdb.is_some();
    // Read before the early seal is taken: a build that does not seal early
    // drops the `EarlySeal` on the way past, and with it the only record of
    // which hash the builder gave this block's parent. The ordinary finish
    // needs it for exactly the same reason the early seal does.
    let parent_built = early_seal.as_ref().and_then(|early| early.parent_built);
    // `N42_SEAL_AT_EXEC=1`: the transactions root computed over the pulled
    // candidates beside the parallel step, whether the seal used it, and how
    // long the step's end waited for it.
    let mut tx_root_ahead = false;
    let mut tx_root_wait_ms = 0u64;
    // The lookahead and the puller given back before the ahead seal, ms.
    let mut give_back_ms = 0u64;
    // The leader's seal chain between its named terms (step 7a): the prep's
    // end to the batches' start (the prefetch's scope, the shards and the
    // threads set up, the partition, the deferred state's open, the slots),
    // the batches' end to the commit's start less the index (`index_ms`, the
    // shards' freeze: the collect, the release, the joins, the deferred
    // state's re-check), and the commit's end to the seal's own start (the
    // body's match, the lookahead and the puller given back).
    let mut gap_before_exec_ms = 0u64;
    let mut gap_after_exec_ms = 0u64;
    let mut gap_before_seal_ms = 0u64;
    let mut index_ms = 0u64;
    // `N42_FREEZE_AFTER_SEAL=1`: whether the freeze ran beside the seal, when
    // it ended, and how long its join waited for it (us).
    let mut freeze_late_used = false;
    let mut freeze_ended_at: Option<std::time::Instant> = None;
    let mut freeze_join_wait_us = 0u64;
    // Where the leader's time from the build's start to the seal goes, beside
    // the fields that already name it (plan v6, the seal gap). With the
    // parallel step taken, `sealed_at_ms` is, within a ms or two of rounding:
    // par_start + par_pull + par_prep + par_prefetch_wait + pre_exec +
    // par_run + scope_join + par_commit + sealed; `par_run` is itself
    // par_part + state_wait + par_exec + par_collect + par_release.
    // Build start to the parallel step's start (the setup, the puller's
    // start, the header's preparation).
    let mut par_start_ms = 0u64;
    // Of `par_start_ms`: what the named start timers do not cover (the
    // setup before the selection, the macros' set-up, rounding).
    let mut start_other_ms = 0u64;
    // The pull and prep's end to the execution's call (the prefetch layer
    // frozen, the graft sink, the threads beside the batches spawned).
    let mut pre_exec_ms = 0u64;
    // The execution's call, whole: partition, the deferred state's open,
    // the batches, the collect and the release.
    let mut par_run_ms = 0u64;
    // Of `par_run_ms`: the partition's per-sender vectors released.
    let mut par_release_ms = 0u64;
    // The execution's return to the fold's start: the transactions-root
    // and prefault threads joined, the scope's end, the deferred state's
    // re-check.
    let mut scope_join_ms = 0u64;
    // Of `par_commit_ms` on the slots path: the references to the filled
    // slots and the block's gas; the cumulative gas per transaction (behind
    // the seal on the ahead path, 0 there); the fees; the body and senders.
    let mut commit_refs_ms = 0u64;
    let mut commit_cumulative_ms = 0u64;
    let mut commit_fees_ms = 0u64;
    let mut commit_body_ms = 0u64;
    // Whether the commit took the body made in the prep's pass.
    let mut commit_body_ahead_used = false;
    // `N42_SEAL_ON_COUNTERS=1`: whether this block sealed on the batches'
    // counters with no pass over the slots, and the batches' end to the
    // seal's start, us (the commit, the give-back and the match between).
    let mut seal_on_counters_used = false;
    let mut exec_end_to_seal_us = 0u64;
    // `N42_PLAN_AHEAD_BODY=1`: the prep took the keys and body made with the
    // plan; the call took its partition and slots; the hand-off of this
    // block was noted as its whole take.
    let mut prep_from_plan = false;
    let mut exec_partition_us = 0u64;
    let mut exec_slots_us = 0u64;
    let mut exec_prepared_groups = false;
    let mut exec_prepared_slots = false;
    let mut whole_take_noted = false;
    // Of `give_back_ms`: the body checked against the pulled set.
    let mut match_ms = 0u64;
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
                let hashes: Vec<B256> = match direct_hashes.take().filter(|hashes| hashes.len() == transactions.len()) {
                    Some(hashes) => {
                        seal_hashes_ahead = true;
                        hashes
                    }
                    None => transactions.iter().map(|tx| *tx.tx_hash()).collect(),
                };
                let sealed = crate::frame_blocks::seal_root_timed(frame_plan.as_ref(), &hashes, || {
                    early_root.unwrap_or_else(|| crate::assembler::parallel_transaction_root(&transactions))
                });
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
            let parent_fields = crate::hotstuff_consensus::parent_executed_fields_or_built(
                chain_spec.genesis(),
                &parent_header,
                parent_built,
                crate::hotstuff_consensus::PARENT_FIELDS_WAIT,
            )
            .ok_or_else(|| {
                PayloadBuilderError::other(crate::hotstuff_consensus::DeferredExecutionError::ParentUnknown(parent_sealed))
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
                header.excess_blob_gas = group_env.block_env.blob_excess_gas_and_price.as_ref().map(|b| b.excess_blob_gas);
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
            cons.seal(&mut header).map_err(|err| PayloadBuilderError::Internal(err.into()))?;
            seal_header_ms = (seal_at.elapsed().as_millis() as u64).saturating_sub(root_ms + fields_ms);
            let step_at = std::time::Instant::now();
            let body = alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals };
            let sealed_block = SealedBlock::seal_parts(header.clone(), body);
            let block_hash = SealedBlock::hash(&sealed_block);
            let recovered: Arc<reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>> =
                Arc::new(reth_primitives_traits::RecoveredBlock::new_sealed(sealed_block, senders));
            seal_block_ms = step_at.elapsed().as_millis() as u64;
            let step_at = std::time::Instant::now();
            crate::built_executions::remember_pending(block_hash, recovered.clone());
            seal_remember_ms = step_at.elapsed().as_millis() as u64;
            let step_at = std::time::Instant::now();
            let payload = EthBuiltPayload::new(recovered.clone(), total_fees, None, None);
            ($hook)(payload.clone());
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
    if parallel_build() && (pulled.is_some() || bulk.is_some()) {
        let par_at = std::time::Instant::now();
        par_start_ms = build_started.elapsed().as_millis() as u64;
        start_other_ms =
            par_start_ms.saturating_sub(start_best_ms + start_check_ms + start_puller_ms + start_prepare_ms);
        let budget = (block_gas_limit.saturating_sub(cumulative_gas_used) / MIN_TRANSACTION_GAS) as usize;
        par_budget = budget;
        let mut cands: Vec<Arc<reth_transaction_pool::ValidPoolTransaction<Pool::Transaction>>> =
            bulk.take().unwrap_or_else(|| Vec::with_capacity(budget.min(262_144)));
        // `N42_BUILD_PREFETCH=1`: each batch the puller hands over has its
        // senders' and recipients' accounts read on the worker pool while the
        // rest of the block is pulled and prepared, into a layer the
        // execution's batches read before the parent's state provider
        // (`WarmAccounts`). The addresses are copied out here, on this
        // thread, from transactions the build already holds: the jobs touch
        // neither the queue nor its locks.
        // `N42_PHASE_TIMERS=1`: counts each batch's reads by door (plan v6
        // 6.5/6.6). `CountedDb` is a passthrough when the flag is off.
        let open_db = || {
            open_parent_state()
                .ok()
                .map(|s| crate::fast_transfer::doors::CountedDb::new(StateProviderDatabase::new(
                    reth_storage_api::StateProvider::into_evm_state_provider(s),
                )))
        };
        let warm_fill = crate::parallel_transfer::build_prefetch().then(crate::parallel_transfer::WarmAccounts::new);
        let (warm_ref, open_ref) = (warm_fill.as_ref(), &open_db);
        // The body's parts made in the prep's pass (`BodyAhead`), for a
        // block that may seal at the execution's end.
        let body_at_prep = seal_at_exec() && seal_early_possible && block_blob_count == 0 && direct_receipts_enabled();
        let (all_transfers, keys, mut body_ahead, prep_done) = crate::parallel_transfer::build_pool().in_place_scope(|scope| {
            if let Some(puller) = pulled.as_ref() {
                while cands.len() < budget {
                    match puller.batches().recv() {
                        Ok(batch) if !batch.is_empty() => {
                            if let Some(warm) = warm_ref {
                                // Senders first, then recipients: a sender's
                                // run is read once.
                                let addresses: Vec<alloy_primitives::Address> = batch
                                    .iter()
                                    .map(|tx| tx.sender())
                                    .chain(batch.iter().map(|tx| tx.transaction.to().unwrap_or_default()))
                                    .collect();
                                scope.spawn(move |_| {
                                    if let Some(mut db) = open_ref() {
                                        warm.fill(&addresses, &mut db);
                                    }
                                });
                            }
                            cands.extend(batch)
                        }
                        _ => break,
                    }
                }
            }
            // The queue had less than a block: nothing more will come this build.
            par_drained = cands.len() < budget;
            par_pull_ms = par_at.elapsed().as_millis() as u64;
            let prep_at = std::time::Instant::now();
            if cands.len() > budget {
                let extra = cands.split_off(budget);
                for tx in extra.into_iter().rev() {
                    lookahead.push_front(tx);
                }
            }
            // One pass over the candidates on the build pool: the check
            // and the (sender, recipient) keys, in order. Serial, the two
            // passes read 163,000 transactions' cold memory one after the
            // other (`par_prep_ms` 10, loop274). The sender is the one the
            // ingest recorded (the attested frame's, for 0x50); nothing is
            // hashed or recovered here.
            // `N42_PLAN_AHEAD_BODY=1`: the keys and the body were made with the
            // plan, from exactly these candidates (the bulk vector is the
            // prepared one, uncut); nothing to read here.
            let from_plan = body_at_prep
                && prepared_build
                    .as_ref()
                    .is_some_and(|made| made.keys.len() == cands.len() && made.transactions.len() == cands.len());
            prep_from_plan = from_plan;
            let (all_transfers, keys, body_made) = if from_plan {
                let keys = prepared_build.as_mut().map(|made| std::mem::take(&mut made.keys)).unwrap_or_default();
                (!keys.is_empty(), keys, None)
            } else { crate::parallel_transfer::build_pool().install(|| {
                use rayon::prelude::*;
                let transfer_key = |tx: &Arc<reth_transaction_pool::ValidPoolTransaction<Pool::Transaction>>| {
                    let inner = &tx.transaction;
                    (inner.gas_limit() == MIN_TRANSACTION_GAS
                        && inner.input().is_empty()
                        && !inner.is_create()
                        && inner.access_list().is_none_or(|list| list.is_empty())
                        && !inner.is_eip4844()
                        && !inner.is_eip7702())
                    .then(|| (tx.sender(), inner.to().unwrap_or_default()))
                };
                if body_at_prep {
                    // The body's parts read in the same pass, each candidate
                    // once while its lines are in hand; the commit takes them
                    // when the block seals at the execution's end.
                    let made = crate::parallel_transfer::BodyAhead::make_keyed(&cands, |_, tx| {
                        let consensus = pooled_consensus(tx);
                        (
                            transfer_key(tx),
                            consensus.clone(),
                            tx.sender(),
                            consensus.effective_tip_per_gas(base_fee).unwrap_or_default(),
                            *tx.hash(),
                        )
                    });
                    return match made {
                        Some((keys, made)) if !keys.is_empty() => (true, keys, Some(made)),
                        _ => (false, Vec::new(), None),
                    };
                }
                // Straight into the vector, a refusal noted beside it: a
                // collect into `Option<Vec>` is not an indexed collect.
                let refused = std::sync::atomic::AtomicBool::new(false);
                let keys: Vec<(alloy_primitives::Address, alloy_primitives::Address)> = cands
                    .par_iter()
                    .with_min_len(1024)
                    .map(|tx| {
                        transfer_key(tx).unwrap_or_else(|| {
                            refused.store(true, std::sync::atomic::Ordering::Relaxed);
                            Default::default()
                        })
                    })
                    .collect();
                if refused.into_inner() || keys.is_empty() {
                    (false, Vec::new(), None)
                } else {
                    (true, keys, None)
                }
            }) };
            par_prep_ms = prep_at.elapsed().as_millis() as u64;
            (all_transfers, keys, body_made, std::time::Instant::now())
        });
        // The scope waited here for the prefetch's last jobs: 0 when the
        // pull and the prep hid it.
        par_prefetch_wait_ms = prep_done.elapsed().as_millis() as u64;
        let pre_exec_at = std::time::Instant::now();
        par_prefetch_ms = warm_fill.as_ref().map_or(0, |warm| warm.busy_us() / 1000);
        let warm = warm_fill.map(crate::parallel_transfer::WarmAccounts::freeze).unwrap_or_default();
        if !all_transfers {
            open_deferred_state!()?;
            for tx in cands.into_iter().rev() {
                lookahead.push_front(tx);
            }
        } else {
            // The environment is read off the pooled transaction by
            // reference (the sender the ingest recorded), and the slot keeps
            // only the candidate's index: the envelope's clone here (its 0x50
            // pubkey and signature bytes) was part of the fetch's 450 ns a
            // transfer on the fleet (loop283), and a slot holding it was 470
            // bytes to write. The body copies each transaction once, from
            // `cands`, behind the execution.
            let convert = |i: usize| ((), evm_config.tx_env(cands[i].transaction.consensus_ref()));
            // Without the prefetch the layer is empty and every read goes
            // to the provider, as before.
            let open = || open_db().map(|db| crate::parallel_transfer::WarmDb::new(&warm, db));
            // `N42_GRAFT_STREAM=1`: each batch's bundle is folded into the
            // block's graft as that batch finishes, on the worker pool, rather
            // than all of them on this thread once the execution is over (the
            // graft was 60 ms of the leader's serial chain, loop173-174). The
            // block's state is untouched until the install below, so a batch
            // that fails still leaves the serial path a clean state.
            // `N42_OUTPUT_SHARDS=<S>`: each batch writes its accounts into the
            // shard that owns each address instead (the streamed graft is
            // not used beside it).
            let shard_count = crate::output_shards::output_shards();
            let sharded_out = (shard_count > 0).then(|| {
                crate::output_shards::OutputShards::new(group_env.block_env.beneficiary, keys.len(), shard_count)
            });
            let staged = (sharded_out.is_none() && crate::parallel_transfer::graft_stream()).then(|| {
                std::sync::Mutex::new(crate::parallel_transfer::StagedGraft::new(group_env.block_env.beneficiary, keys.len()))
            });
            let sink = staged.as_ref().map(|staged| {
                move |bundle: revm::database::BundleState| staged.lock().expect("the staged graft's lock").add(bundle)
            });
            let shard_sink = sharded_out.as_ref().map(|shards| move |bundle: revm::database::BundleState| shards.add(bundle));
            let sink: Option<&(dyn Fn(revm::database::BundleState) + Sync)> = match shard_sink.as_ref() {
                Some(sink) => Some(sink as &(dyn Fn(revm::database::BundleState) + Sync)),
                None => sink.as_ref().map(|sink| sink as &(dyn Fn(revm::database::BundleState) + Sync)),
            };
            // `N42_BUILD_COLLECT_IN_PLACE=1`: the transfers stay in the slots the
            // batches wrote them to; the body and the receipts below are made from
            // there on the worker pool rather than after a serial move of all of
            // them (`par_collect_ms` 18 on the four-node fleet, loop214-218).
            let in_place = crate::parallel_transfer::build_collect_in_place();
            // `N42_GRAFT_PREFAULT=1`: the graft's memory -- the block's bundle
            // map and its revert list -- mapped on a thread of its own while
            // the batches execute, so the graft below writes into resident
            // pages rather than faulting one in for every fifteen accounts
            // (`GraftTarget`). Room for a quarter more accounts than
            // transfers: a block of distinct senders and recipients touches
            // at most twice as many, the bench's shape 1.04x, and a map that
            // turns out short grows in the graft as it does today.
            let prefault = crate::parallel_transfer::graft_prefault() && staged.is_none() && sharded_out.is_none();
            // `N42_SEAL_AT_EXEC=1`: the transactions root over the pulled
            // candidates, in pull order, on a thread of its own (not the build
            // pool, whose threads the execution uses) while the batches run.
            // With nothing skipped the body is exactly that set in that order
            // (`body_matches_pull`), and the seal takes this root instead of
            // computing one after the execution.
            let root_ahead_wanted = seal_at_exec()
                && seal_early_possible
                && block_blob_count == 0
                && direct_receipts_enabled()
                && frame_plan.is_none();
            // `N42_STATE_AFTER_PULL=1`: an error from the deferred open, raised
            // once the step's threads are joined.
            let mut deferred_state_err: Option<PayloadBuilderError> = None;
            let mut exec_returned: Option<std::time::Instant> = None;
            let mut run_started: Option<std::time::Instant> = None;
            let (executed, mut graft_target, root_ahead) = std::thread::scope(|scope| {
                let target = prefault.then(|| {
                    let accounts = keys.len() + keys.len() / 4;
                    scope.spawn(move || crate::parallel_transfer::GraftTarget::prefaulted(accounts))
                });
                let root_job = root_ahead_wanted.then(|| {
                    let pulled_set = &cands;
                    scope.spawn(move || {
                        use alloy_eips::eip2718::Encodable2718 as _;
                        crate::assembler::parallel_transaction_root_by(pulled_set.len(), |i| {
                            pooled_consensus(&pulled_set[i]).encoded_2718()
                        })
                    })
                });
                pre_exec_ms = pre_exec_at.elapsed().as_millis() as u64;
                let run_at = std::time::Instant::now();
                run_started = Some(run_at);
                // `N42_SEAL_ON_COUNTERS=1`: the batches count the block's
                // transfers, gas and fees as they execute (a candidate's tip
                // read beside its conversion, as the prep's body reads it), so
                // the seal needs no pass over the slots.
                let tip_of = |i: usize| pooled_consensus(&cands[i]).effective_tip_per_gas(base_fee).unwrap_or_default();
                // `N42_PLAN_AHEAD_BODY=1`: the partition (at this block's
                // beneficiary only) and the slots made with the plan.
                let prepared_exec = prepared_build.as_mut().filter(|_| prep_from_plan).map(|made| {
                    crate::parallel_transfer::PreparedExec {
                        groups: made
                            .groups
                            .take()
                            .filter(|(beneficiary, _)| *beneficiary == group_env.block_env.beneficiary)
                            .map(|(_, groups)| groups),
                        slots: Some(std::mem::take(&mut made.slots)),
                    }
                });
                let counted_tips: Option<&(dyn Fn(usize) -> u128 + Sync)> =
                    if seal_on_counters() && body_at_prep { Some(&tip_of) } else { None };
                let executed = if defer_state {
                    // After the partition, before the batches: the builder's
                    // own state opened (the wait for a sealed parent's output
                    // happens here) and the pre-execution changes applied.
                    let mut before_batches = || match open_deferred_state!() {
                        Ok(()) => true,
                        Err(err) => {
                            deferred_state_err = Some(err);
                            false
                        }
                    };
                    crate::parallel_transfer::execute_for_build_counted(
                        &group_env,
                        &keys,
                        &convert,
                        &open,
                        sink,
                        in_place,
                        Some(&mut before_batches),
                        counted_tips,
                        prepared_exec,
                    )
                } else {
                    crate::parallel_transfer::execute_for_build_counted(
                        &group_env,
                        &keys,
                        &convert,
                        &open,
                        sink,
                        in_place,
                        None,
                        counted_tips,
                        prepared_exec,
                    )
                };
                let exec_done = std::time::Instant::now();
                par_run_ms = exec_done.duration_since(run_at).as_millis() as u64;
                exec_returned = Some(exec_done);
                let root_ahead = root_job.and_then(|job| job.join().ok());
                tx_root_wait_ms = exec_done.elapsed().as_millis() as u64;
                (executed, target.and_then(|job| job.join().ok()), root_ahead)
            });
            par_prefault_ms = graft_target.as_ref().map_or(0, |target| target.prefault_us / 1000);
            if let Some(err) = deferred_state_err.take() {
                return Err(err);
            }
            // A partition that failed returned before the hook: the serial
            // path below needs the state all the same.
            open_deferred_state!()?;
            scope_join_ms = exec_returned.map_or(0, |at| at.elapsed().as_millis() as u64);
            match executed {
                Ok(mut run) => {
                    use reth_evm::execute::BlockExecutor as _;
                    let beneficiary = group_env.block_env.beneficiary;
                    // The batches are done: the fold, a task a shard on the
                    // build pool.
                    let freeze_at = std::time::Instant::now();
                    // `N42_FREEZE_AFTER_SEAL=1`: on a block that can seal at
                    // the execution's end, the freeze starts on its own
                    // thread and is joined where the shards are first read.
                    let freeze_late = freeze_after_seal()
                        && seal_at_exec()
                        && direct_receipts_enabled()
                        && seal_early_possible
                        && block_blob_count == 0
                        && early_seal.is_some();
                    let mut freezing: Option<LateFreeze> = None;
                    let mut sharded_out = match sharded_out {
                        Some(shards) if freeze_late => match spawn_freeze(shards) {
                            Ok(handle) => {
                                freezing = Some(handle);
                                None
                            }
                            Err(shards) => shards.map(|shards| shards.freeze()),
                        },
                        other => other.map(crate::output_shards::OutputShards::freeze),
                    };
                    let index_us = freeze_at.elapsed().as_micros() as u64;
                    index_ms = index_us / 1_000;
                    freeze_late_used = freezing.is_some();
                    if let Some(shards) = sharded_out.as_ref() {
                        out_shards = shards.shard_count();
                        shard_append_ms = shards.append_ms();
                        shard_fold_ms = shards.fold_ms();
                    }
                    // The late freeze joined: its counters as the inline
                    // freeze sets them, `index_ms` its own wall (off the
                    // seal's path), and when it ended and how long the join
                    // waited for it.
                    macro_rules! freeze_joined {
                        ($joined:expr) => {{
                            let (frozen, took, ended): (crate::output_shards::FrozenShards, std::time::Duration, std::time::Instant) = $joined;
                            index_ms = took.as_millis() as u64;
                            out_shards = frozen.shard_count();
                            shard_append_ms = frozen.append_ms();
                            shard_fold_ms = frozen.fold_ms();
                            freeze_ended_at = Some(ended);
                            frozen
                        }};
                    }
                    par_collect_ms = run.phases.collect_ms;
                    par_release_ms = run.phases.release_ms;
                    let fold_at = std::time::Instant::now();
                    if let Some(run_at) = run_started {
                        gap_before_exec_ms = (run_at.saturating_duration_since(prep_done).as_micros() as u64)
                            .saturating_add(run.phases.batches_start_us)
                            / 1_000;
                        let exec_end = run_at + std::time::Duration::from_micros(run.phases.batches_end_us);
                        gap_after_exec_ms =
                            (fold_at.saturating_duration_since(exec_end).as_micros() as u64).saturating_sub(index_us) / 1_000;
                    }
                    // `N42_SEAL_AT_EXEC=1`: the passes over the slots between the
                    // execution's end and the seal run on the build pool (each
                    // serial pass strides 163k slots of ~470 bytes).
                    let on_pool = seal_at_exec();
                    // `N42_SEAL_ON_COUNTERS=1`: the count and the gas are the
                    // batches' own (`RunCounters`, the same sums), and the
                    // references are made below only for a block that does
                    // not seal on the counters.
                    let counters_first = seal_on_counters() && !run.slots.is_empty();
                    // Block order, by reference: a pointer a transfer, where the
                    // collect moved ~470 bytes of each.
                    // On the pool, the references and the block's gas are one
                    // pass (`slot_refs_and_gas`).
                    let (mut refs, pool_gas) = if run.slots.is_empty() || counters_first {
                        (None, None)
                    } else if on_pool {
                        let (refs, gas) = crate::parallel_transfer::slot_refs_and_gas(&run.slots);
                        (Some(refs), Some(gas))
                    } else {
                        (Some(run.slots.iter().filter_map(std::sync::OnceLock::get).collect::<Vec<_>>()), None)
                    };
                    let (executed_count, executed_gas) = match (refs.as_ref(), pool_gas) {
                        _ if counters_first => (run.counters.executed, run.counters.gas),
                        (Some(refs), Some(gas)) => (refs.len(), gas),
                        (Some(refs), None) => (refs.len(), refs.iter().map(|built| built.gas_used).sum::<u64>()),
                        (None, _) => (run.executed.len(), run.executed.iter().map(|built| built.gas_used).sum::<u64>()),
                    };
                    commit_refs_ms = fold_at.elapsed().as_millis() as u64;
                    // This block seals early -- full or drained after this step,
                    // with nothing committed before it -- so nothing executes on
                    // this builder again: the executor's commit per transfer
                    // (receipt, gas counters, a Cancun check and an empty state
                    // commit, 53 ms a full block on the leader's serial chain,
                    // loop165) only feeds the receipts and the gas its finish
                    // reports. Both are built here on the worker pool instead and
                    // handed to that finish; the executor commits none.
                    let seals_early_here = seal_early_possible
                        && block_blob_count == 0
                        && executed_count > 0
                        && cumulative_gas_used == 0
                        && builder.transactions.is_empty()
                        && (block_gas_limit.saturating_sub(executed_gas) < MIN_TRANSACTION_GAS || par_drained);
                    // `N42_SEAL_AT_EXEC=1`: this block is sealed below, before
                    // the fold. `seals_early_here` implies the gate after the
                    // parallel step passes (the chain's preconditions, no blobs,
                    // something executed, full or drained), so a block sealed
                    // here is never handed to the serial loop.
                    let ahead = seal_at_exec() && seals_early_here && direct_receipts_enabled();
                    // With the slots left in place, the receipts are built from
                    // them behind the seal, beside the graft, and with them the
                    // cumulative gas per transaction and the block's gas: the
                    // seal needs neither.
                    let mut receipts_behind = false;
                    // `N42_SEAL_ON_COUNTERS=1`: a block that seals here with
                    // every candidate executed in pull order is the body made
                    // in the prep (`BodyAhead`) and the batches' fees; nothing
                    // on the seal's path reads the slots. Any other block
                    // makes the references now, as without the switch.
                    let counted_body = if counters_first
                        && ahead
                        && run.skipped.is_empty()
                        && executed_count == cands.len()
                        && let Some(fees) = run.counters.fees
                    {
                        // The body made with the plan (`N42_PLAN_AHEAD_BODY`)
                        // or in the prep, every candidate in pull order.
                        if prep_from_plan
                            && let Some(made) = prepared_build.as_mut().filter(|made| made.transactions.len() == cands.len())
                        {
                            Some((
                                (
                                    std::mem::take(&mut made.transactions),
                                    std::mem::take(&mut made.senders),
                                    std::mem::take(&mut made.hashes),
                                ),
                                fees,
                            ))
                        } else if body_ahead.as_ref().is_some_and(|made| made.transactions.len() == cands.len()) {
                            body_ahead.take().map(|made| ((made.transactions, made.senders, made.hashes), fees))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    if counters_first && counted_body.is_none() {
                        let at = std::time::Instant::now();
                        refs = Some(if on_pool {
                            crate::parallel_transfer::slot_refs_and_gas(&run.slots).0
                        } else {
                            run.slots.iter().filter_map(std::sync::OnceLock::get).collect::<Vec<_>>()
                        });
                        commit_refs_ms += at.elapsed().as_millis() as u64;
                    }
                    seal_on_counters_used = counted_body.is_some();
                    if let Some(((transactions, senders, hashes), fees)) = counted_body {
                        total_fees += fees;
                        commit_body_ahead_used = true;
                        cumulative_gas_used += executed_gas;
                        tx_count += executed_count as u64;
                        direct_body = Some((transactions, senders));
                        direct_hashes = Some(hashes);
                        // The references, the cumulative gas and the receipts
                        // are made behind the seal by the receipts job, which
                        // reads the slots itself.
                        receipts_behind = true;
                    } else if let (true, true, Some(refs)) = (seals_early_here, direct_receipts_enabled(), refs.as_ref()) {
                        // The same body and receipts as the branch below, made
                        // from the slots: the transaction is copied out of its
                        // slot once, on the pool, straight into the body.
                        use rayon::prelude::*;
                        let step_at = std::time::Instant::now();
                        let cumulative = (!ahead).then(|| cumulative_gas(refs));
                        commit_cumulative_ms = step_at.elapsed().as_millis() as u64;
                        let step_at = std::time::Instant::now();
                        // Ahead: the fees, the body and the senders in one pass
                        // on the build pool, each candidate read once
                        // (`body_and_fees`; `commit_fees_ms` is then 0).
                        if !ahead {
                            total_fees += refs
                                .par_iter()
                                .map(|built| {
                                    let tip = pooled_consensus(&cands[built.index]).effective_tip_per_gas(base_fee).unwrap_or_default();
                                    U256::from(tip) * U256::from(built.gas_used)
                                })
                                .reduce(|| U256::ZERO, |a, b| a + b);
                        }
                        commit_fees_ms = step_at.elapsed().as_millis() as u64;
                        let step_at = std::time::Instant::now();
                        // The body made ahead, when the transfers are every
                        // candidate in pull order (the fees from its tips).
                        let made = body_ahead.take().filter(|_| ahead).and_then(|made| {
                            crate::parallel_transfer::fees_from_tips(refs, &made.tips).map(|fees| (made, fees))
                        });
                        let (transactions, senders): (Vec<TransactionSigned>, Vec<alloy_primitives::Address>) = if let Some((made, fees)) = made {
                            total_fees += fees;
                            commit_body_ahead_used = true;
                            direct_hashes = Some(made.hashes);
                            (made.transactions, made.senders)
                        } else if ahead {
                            let (transactions, senders, fees) = crate::parallel_transfer::body_and_fees(refs, |built| {
                                let candidate = &cands[built.index];
                                let tx = pooled_consensus(candidate);
                                (tx.clone(), candidate.sender(), tx.effective_tip_per_gas(base_fee).unwrap_or_default())
                            });
                            total_fees += fees;
                            (transactions, senders)
                        } else {
                            (
                                refs.par_iter().map(|built| pooled_consensus(&cands[built.index]).clone()).collect(),
                                refs.par_iter().map(|built| cands[built.index].sender()).collect(),
                            )
                        };
                        commit_body_ms = step_at.elapsed().as_millis() as u64;
                        cumulative_gas_used += executed_gas;
                        tx_count += executed_count as u64;
                        direct_body = Some((transactions, senders));
                        if let Some((cumulative, tx_gas)) = cumulative {
                            direct_receipts = Some((receipts_from_slots(refs, &cumulative, &cands), tx_gas));
                            // The slots' 77 MB are freed on the pool, off this thread.
                            let slots = std::mem::take(&mut run.slots);
                            crate::parallel_transfer::behind_pool().spawn(move || drop(slots));
                        } else {
                            receipts_behind = true;
                        }
                    } else if seals_early_here && direct_receipts_enabled() {
                        use rayon::prelude::*;
                        let executed = run.take_executed();
                        let mut cumulative = Vec::with_capacity(executed_count);
                        let mut tx_gas = 0u64;
                        for built in &executed {
                            tx_gas += built.result.gas().tx_gas_used();
                            cumulative.push(tx_gas);
                        }
                        total_fees += executed
                            .par_iter()
                            .map(|built| {
                                let tip = pooled_consensus(&cands[built.index]).effective_tip_per_gas(base_fee).unwrap_or_default();
                                U256::from(tip) * U256::from(built.gas_used)
                            })
                            .reduce(|| U256::ZERO, |a, b| a + b);
                        let (transactions, rest): (Vec<TransactionSigned>, Vec<(alloy_primitives::Address, n42_tx_types::Receipt)>) = executed
                            .into_par_iter()
                            .zip(cumulative.into_par_iter())
                            .map(|(built, cumulative_gas_used)| {
                                let tx_type = <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(pooled_consensus(&cands[built.index]));
                                let receipt = n42_tx_types::Receipt {
                                    tx_type,
                                    success: built.result.is_success(),
                                    cumulative_gas_used,
                                    logs: built.result.into_logs(),
                                };
                                // Split here, on the pool, where the transaction
                                // is already in hand: the seal takes the two
                                // vectors as they are.
                                // The body's copy, the only one.
                                (pooled_consensus(&cands[built.index]).clone(), (cands[built.index].sender(), receipt))
                            })
                            .unzip();
                        let (senders, receipts): (Vec<alloy_primitives::Address>, Vec<n42_tx_types::Receipt>) =
                            rest.into_par_iter().unzip();
                        cumulative_gas_used += executed_gas;
                        tx_count += executed_count as u64;
                        direct_body = Some((transactions, senders));
                        direct_receipts = Some((receipts, tx_gas));
                    } else {
                        // The receipts and the gas, one transfer at a time, with
                        // no state to commit: the state comes in one piece below.
                        for built in run.take_executed() {
                            let recovered = cands[built.index].to_consensus();
                            let tip = recovered.effective_tip_per_gas(base_fee).unwrap_or_default();
                            total_fees += U256::from(tip) * U256::from(built.gas_used);
                            cumulative_gas_used += built.gas_used;
                            tx_count += 1;
                            let tx_type = <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(recovered.inner());
                            builder.executor.commit_transaction(alloy_evm::eth::EthTxResult {
                                result: revm::context::result::ResultAndState {
                                    result: built.result,
                                    state: revm::state::EvmState::default(),
                                },
                                blob_gas_used: 0,
                                tx_type,
                            });
                            builder.transactions.push(recovered);
                        }
                    }
                    // The batches' changes, grafted onto the block's state;
                    // the beneficiary, whom every batch credited from the
                    // same starting balance, once, through a commit.
                    // The state's cache is written only if something after
                    // the graft may read a grafted account: the serial loop
                    // (which runs only if the block has gas left) or a
                    // withdrawal to one of them. `N42_BUILD_GRAFT_NO_CACHE=1`
                    // turns the skip on; the cache insert per account was
                    // ~a third of a 70 ms graft.
                    let block_full = block_gas_limit.saturating_sub(cumulative_gas_used) < MIN_TRANSACTION_GAS;
                    // Sealed early, nothing after the graft reads the cache
                    // either: the serial loop never runs.
                    let sealing_early = seal_early_possible && block_blob_count == 0 && (block_full || par_drained);
                    // A block that will not seal early reads the shards below
                    // (the withdrawals' check, the staged graft): the late
                    // freeze is joined first. One that will is joined behind
                    // the seal, beside the receipts.
                    if !sealing_early && let Some(handle) = freezing.take() {
                        let joined = handle.join().map_err(|_| {
                            PayloadBuilderError::other(std::io::Error::other("the shards' freeze panicked"))
                        })?;
                        sharded_out = Some(freeze_joined!(joined));
                    }
                    let withdrawals_clear = attributes.withdrawals.as_ref().is_none_or(|ws| match (staged.as_ref(), sharded_out.as_ref()) {
                        (Some(staged), _) => {
                            let staged = staged.lock().expect("the staged graft's lock");
                            ws.iter().all(|w| !staged.holds(&w.address))
                        }
                        (None, Some(shards)) => ws.iter().all(|w| !shards.holds(&w.address)),
                        (None, None) => ws.iter().all(|w| !run.bundles.iter().any(|b| b.state.contains_key(&w.address))),
                    });
                    // The executor's finish credits the block's withdrawals
                    // through the cache, and a miss there would load the
                    // parent's account over the graft's (the faucet, on a
                    // funding block: audit 2026-09-12) -- so with the cache
                    // skipped, the withdrawal recipients the graft touched
                    // are put back into it below, and nothing else is.
                    let keep_cache = !(sealing_early || (build_graft_no_cache() && block_full && withdrawals_clear));
                    par_commit_ms = fold_at.elapsed().as_millis() as u64;
                    let commit_end = std::time::Instant::now();
                    let _ = executed_count;
                    // `N42_SEAL_AT_EXEC=1`: sealed and proposed here, with the
                    // body just collected; everything below -- the graft, the
                    // put-back, the fee credit, the receipts, the diagnosis and
                    // the give-backs -- is behind the proposal, and a failure
                    // in it tells the store's waiters (`failed_after_seal`).
                    // The seal's own time is left out of `par_fold_ms`.
                    let mut seal_took = std::time::Duration::ZERO;
                    if ahead && let Some(EarlySeal { hook, parent_built: _ }) = early_seal.take() {
                        let seal_at = std::time::Instant::now();
                        if let Some(run_at) = run_started {
                            let exec_end = run_at + std::time::Duration::from_micros(run.phases.batches_end_us);
                            exec_end_to_seal_us = seal_at.saturating_duration_since(exec_end).as_micros() as u64;
                        }
                        let matches = root_ahead.is_some()
                            && run.skipped.is_empty()
                            && direct_body.as_ref().is_some_and(|(transactions, _)| {
                                body_matches_pull(transactions, &cands, |tx| *tx.tx_hash(), |tx| *tx.hash())
                            });
                        match_ms = seal_at.elapsed().as_millis() as u64;
                        tx_root_ahead = matches;
                        // What the puller took ahead and this block did not
                        // build goes back to the queue before the proposal,
                        // not behind the graft: the chained build pulls at
                        // the seal (`N42_STATE_AFTER_PULL`), and on loop232
                        // it found the lanes holed by this build's lookahead
                        // still checked out (117 of 180 builds short of the
                        // gas limit, every one from a hole the pool could
                        // not fill); on loop233, with the give-back after the
                        // hook, by the puller's walk still ending. The
                        // puller's drop joins its thread. The skipped
                        // senders' heads, rare on a full block, are given
                        // back below with their diagnosis.
                        for pool_tx in std::mem::take(&mut lookahead).into_iter().rev() {
                            refuse!(
                                &pool_tx,
                                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit)
                            );
                        }
                        drop(pulled.take());
                        give_back_ms = seal_at.elapsed().as_millis() as u64;
                        gap_before_seal_ms = commit_end.elapsed().as_millis() as u64;
                        let sealed = seal_block!(hook, seal_at, if matches { root_ahead } else { None });
                        sealed_ahead_id = Some((sealed.2, sealed.3));
                        // `N42_PLAN_AHEAD_BODY=1`: a block sealed on its
                        // counters from the frames' bulk vector, uncut, is
                        // its build's whole take in take order: the queue's
                        // hand-off forgets it in O(1) (`forget_whole_take`).
                        if seal_on_counters_used && from_bulk && crate::frame_blocks::plan_ahead_body_wanted() && !cands.is_empty() {
                            let last = cands.len() - 1;
                            let checks = [0, last / 2, last]
                                .into_iter()
                                .map(|i| (i, cands[i].sender(), cands[i].nonce()))
                                .collect();
                            crate::frame_blocks::note_whole_take(crate::frame_blocks::WholeTake {
                                block: sealed.2,
                                parent: parent_header.hash(),
                                len: cands.len(),
                                checks,
                            });
                            whole_take_noted = true;
                        }
                        sealed_ahead = Some(sealed);
                        seal_took = seal_at.elapsed();
                    }
                    // The transactions root beside the graft when the block
                    // will seal early: the seal needs it, and the graft's
                    // 60-100 ms hide it (loop139: 42 ms on the seal path).
                    let bundles = run.bundles;
                    // `N42_OUTPUT_SHARDS`: no graft when the block seals early
                    // (nothing after this reads the executor's cache) onto a
                    // state with no bundle of its own; otherwise the shards are
                    // folded into one staged map here and installed as the
                    // streamed graft is.
                    // Decided once, for the shards frozen here and for the
                    // late freeze joined in the scope below alike.
                    let shards_stay = !keep_cache
                        && sealing_early
                        && tx_count > 0
                        && builder.executor.evm_mut().db_mut().bundle_state.state.is_empty();
                    let (staged, mut sharded_out) = match sharded_out {
                        Some(shards) if shards_stay => (None, Some(shards)),
                        Some(shards) => (Some(std::sync::Mutex::new(shards.into_staged())), None),
                        None => (staged, None),
                    };
                    let mut staged = staged.map(|staged| staged.into_inner().expect("the staged graft's lock"));
                    // Of the fold: the graft alone, without the transactions
                    // root that runs beside it -- `par_fold_ms` is the longer
                    // of the two, so a graft that falls under the root would
                    // not show in it (plan v5 attempt D).
                    let mut graft_ms = 0u64;
                    // `N42_FREEZE_AFTER_SEAL=1`: set when the late freeze's
                    // thread panicked; the graft is not run and the build
                    // fails behind its seal.
                    let mut freeze_failed = false;
                    let (graft, early_root, receipts) = std::thread::scope(|scope| {
                        // Sealed at the execution's end: the receipts from the
                        // slots, beside the graft, instead of the root.
                        let receipts_job = receipts_behind.then(|| {
                            let slots: &[_] = &run.slots;
                            let pulled: &[_] = &cands;
                            scope.spawn(move || {
                                let refs: Vec<_> = slots.iter().filter_map(std::sync::OnceLock::get).collect();
                                let (cumulative, tx_gas) = cumulative_gas(&refs);
                                // `N42_FREEZE_POOL=own`: the receipts on the
                                // pool behind the seal; the global pool else.
                                let receipts = if crate::parallel_transfer::freeze_pool_own() {
                                    crate::parallel_transfer::behind_pool().install(|| receipts_from_slots(&refs, &cumulative, pulled))
                                } else {
                                    receipts_from_slots(&refs, &cumulative, pulled)
                                };
                                (receipts, tx_gas)
                            })
                        });
                        let root = (sealing_early && sealed_ahead.is_none() && frame_plan.is_none()).then(|| match direct_body.as_ref() {
                            Some((transactions, _)) => {
                                let txs: &[TransactionSigned] = transactions;
                                scope.spawn(move || crate::assembler::parallel_transaction_root(txs))
                            }
                            None => {
                                let txs: &[reth_primitives_traits::Recovered<TransactionSigned>] = &builder.transactions;
                                scope.spawn(move || crate::assembler::parallel_transaction_root_recovered(txs))
                            }
                        });
                        // `N42_FREEZE_AFTER_SEAL=1`: the shards are first read
                        // here; the freeze has run beside the commit and the
                        // seal, and the receipts job runs beside its end.
                        if let Some(handle) = freezing.take() {
                            let join_at = std::time::Instant::now();
                            match handle.join() {
                                Ok(joined) => {
                                    let frozen = freeze_joined!(joined);
                                    if shards_stay {
                                        sharded_out = Some(frozen);
                                    } else {
                                        staged = Some(frozen.into_staged());
                                    }
                                }
                                Err(_) => freeze_failed = true,
                            }
                            freeze_join_wait_us = join_at.elapsed().as_micros() as u64;
                        }
                        let db = builder.executor.evm_mut().db_mut();
                        let at = std::time::Instant::now();
                        let graft = if freeze_failed { None } else { Some(match (staged, sharded_out.as_mut()) {
                            // The block's output stays in its shards: only the
                            // accounts a pre-execution call left in the cache
                            // are committed, as deltas.
                            (_, Some(shards)) => {
                                let committed = shards.take_cached(db);
                                Ok(crate::parallel_transfer::Graft {
                                    beneficiary_delta: shards.beneficiary_delta(),
                                    committed,
                                    ..Default::default()
                                })
                            }
                            (Some(staged), None) => crate::parallel_transfer::install_staged(db, staged, keep_cache),
                            (None, None) => crate::parallel_transfer::graft_bundles_folded(
                                db,
                                bundles,
                                beneficiary,
                                keep_cache,
                                crate::parallel_transfer::build_graft_fold(),
                                graft_target.take(),
                            ),
                        }) };
                        // Kept at 0 when nothing was grafted.
                        graft_ms = if sharded_out.is_some() { 0 } else { at.elapsed().as_millis() as u64 };
                        (
                            graft,
                            root.map(|job| job.join().expect("the transactions root job does not panic")),
                            receipts_job.map(|job| job.join()),
                        )
                    });
                    par_graft_ms = graft_ms;
                    early_transactions_root = early_root;
                    if let Some(receipts) = receipts {
                        let (receipts, tx_gas) = receipts.map_err(|_| {
                            failed_after_seal(
                                sealed_ahead_id,
                                PayloadBuilderError::other(std::io::Error::other("the receipts job behind the seal panicked")),
                            )
                        })?;
                        direct_receipts = Some((receipts, tx_gas));
                        // The slots' 77 MB are freed on the pool, off this thread.
                        let slots = std::mem::take(&mut run.slots);
                        crate::parallel_transfer::behind_pool().spawn(move || drop(slots));
                    }
                    let graft = graft
                        .ok_or_else(|| {
                            failed_after_seal(
                                sealed_ahead_id,
                                PayloadBuilderError::other(std::io::Error::other("the shards' freeze behind the seal panicked")),
                            )
                        })?
                        .map_err(|err| failed_after_seal(sealed_ahead_id, PayloadBuilderError::other(err)))?;
                    // Zero on `install_staged`'s streamed graft
                    // (`N42_GRAFT_STREAM=1`) and on `GraftFold::Indexed`/
                    // `IndexedRanges`: only the default in-place fold
                    // (`graft_bundles_direct`) fills these.
                    par_graft_base_ms = graft.direct_base_ms;
                    par_graft_reserve_ms = graft.direct_reserve_ms;
                    par_graft_insert_ms = graft.direct_insert_ms;
                    par_graft_reverts_ms = graft.direct_reverts_ms;
                    par_graft_other_ms = graft.direct_other_ms;
                    par_graft_sharded = graft.sharded;
                    par_graft_split_us = graft.sharded_split_us;
                    par_graft_build_us = graft.sharded_build_us;
                    par_graft_merge_us = graft.sharded_merge_us;
                    let db = builder.executor.evm_mut().db_mut();
                    if !keep_cache {
                        if let Some(withdrawals) = attributes.withdrawals.as_ref() {
                            for withdrawal in withdrawals {
                                let grafted = db
                                    .bundle_state
                                    .state
                                    .get(&withdrawal.address)
                                    .and_then(|account| account.info.clone())
                                    .or_else(|| {
                                        sharded_out
                                            .as_ref()
                                            .and_then(|shards| shards.get(&withdrawal.address))
                                            .and_then(|account| account.info.clone())
                                    });
                                if let Some(info) = grafted {
                                    db.insert_account(withdrawal.address, info);
                                }
                            }
                        }
                    }
                    let fees = graft.beneficiary_delta;
                    par_committed = graft.committed;
                    par_reverts = graft.reverts;
                    let mut changes = revm::state::EvmState::default();
                    if !fees.is_zero() {
                        let current = db
                            .basic(beneficiary)
                            .map_err(|err| failed_after_seal(sealed_ahead_id, PayloadBuilderError::other(err)))?;
                        let existed = current.is_some();
                        let mut info = current.unwrap_or_default();
                        info.balance = info.balance.saturating_add(fees);
                        let mut account = revm::state::Account::from(info);
                        account.status = revm::state::AccountStatus::Touched;
                        if !existed {
                            account.status |= revm::state::AccountStatus::Created;
                        }
                        changes.insert(beneficiary, account);
                    }
                    revm::DatabaseCommit::commit(db, changes);
                    output_shards = sharded_out.map(Arc::new);
                    // `N42_ROOT_OPS_AHEAD=1`: the shards are final here (the
                    // cached accounts taken out of them); their QMDB leaves
                    // are encoded and sorted now, beside the finish, and the
                    // root job adds the residual's to them.
                    if root_ops_ahead() && sealing_early && let Some(shards) = output_shards.as_ref() {
                        let shards = Arc::clone(shards);
                        let prague = chain_spec.is_prague_active_at_timestamp(attributes.timestamp);
                        let spawned = std::thread::Builder::new().name("n42-ops-ahead".into()).spawn(move || {
                            n42_core_layout::enter(n42_core_layout::Set::Critical);
                            let empty = revm::database::BundleState::default();
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
                    par_fold_ms = fold_at.elapsed().saturating_sub(seal_took).as_millis() as u64;
                    par_txs = tx_count;
                    par_groups = run.phases.groups;
                    par_batches = run.phases.batches;
                    par_part_ms = run.phases.partition_ms;
                    par_exec_ms = run.phases.groups_ms;
                    exec_prepared_groups = run.phases.prepared_groups;
                    exec_prepared_slots = run.phases.prepared_slots;
                    exec_partition_us = run.phases.partition_us;
                    exec_slots_us = run.phases.slots_us;
                    par_transfer_timers = run.phases.transfer_timers;
                    par_read_set = run.phases.read_set;
                    par_read_set_hits = run.phases.read_set_hits;
                    par_read_set_misses = run.phases.read_set_misses;
                    par_batch_spans = run.phases.batch_spans;
                    par_loop_timers = run.phases.loop_timers;
                    par_skipped = run.skipped.len();
                    // Read by the diagnosis below, which must see what this
                    // step actually built.
                    debug_assert_eq!(par_txs, tx_count);
                    // Not offered to the serial loop: what the transfer path
                    // refused it would refuse too, one full validation per
                    // transaction -- 5.2 s for a block's worth when the
                    // base fee had run past every candidate's fee (round 43).
                    // Given back with the leftovers at the end instead.
                    for i in run.skipped {
                        deferred.push(Arc::clone(&cands[i]));
                    }
                    // Why each skipped sender's head was refused, so the
                    // give-back below can say it. Handing every skipped
                    // candidate back with `ExceedsGasLimit` tells the queue
                    // nothing, and its lowest nonce is what the next build
                    // is offered first: on loop207 Pb node3 the same 256-512
                    // candidates were skipped on all 63 builds of the tenure
                    // (`refused[6]` +1 a build, `par_skipped` flat), and on
                    // Ob node1 the skipped set grew 2,880 -> 163,000 over
                    // twenty blocks until every block was empty with
                    // 334-360k queued. A stale head lets the queue drop it
                    // and everything below, so the lane is usable at the
                    // *next* build; a head above the account's nonce parks
                    // the lane (`n42_tx_queue::Parked`) so the budget goes
                    // to lanes that can execute.
                    //
                    // Read from *this block's* state, not the parent's, and
                    // that distinction is the whole correctness of the
                    // thing. The parallel step drops a sender's whole run
                    // from wherever it first failed, and the common reason
                    // is not a hole at all: a batch's view of a sender lacks
                    // what other groups credit it in the same block, so the
                    // run stops part-way and the rest is left to the serial
                    // loop. Those heads sit exactly `k` above the *parent's*
                    // nonce, where `k` is what this block already executed
                    // for that sender -- against the parent they look
                    // gapped, against the block they are the next nonce.
                    // Reading the parent parked them all: loop209 Pa node3
                    // parked its whole lane set over two such builds
                    // (`par_skipped=144000`, then `145936`), its depth stuck
                    // at 569,520 with `usable=0`, the ingest gate shut on
                    // the parked depth, and the node proposed empty blocks
                    // for fifteen seconds until its tenure ended. The graft
                    // is installed by here, so the builder's own database is
                    // the block's state.
                    //
                    // Only for a build whose own view is sound, and that
                    // is what `par_txs > 0` says. A build standing on a
                    // parent the chain has moved past sees *every* lane as
                    // gapped -- the queue was pruned by blocks that parent
                    // does not have, so every head is above its state -- and
                    // it is not the queue that is wrong. loop210 had one or
                    // two such builds a leg, all of the same shape
                    // (`par_txs=0 par_groups=384 par_skipped=163000 gas=0`,
                    // a superseded build at a tenure handover whose payload
                    // was never proposed), and each parked the node's whole
                    // sender set: Pb node3 parked 384 lanes holding 631,212
                    // transactions and the next four blocks carried 8,500 to
                    // 65,828 instead of 163,000. A build that executed
                    // nothing has learned nothing about any sender.
                    //
                    // And even then only a minority: a hole is a few senders
                    // among the hundreds a block draws on, so a build
                    // reporting most of them is describing itself.
                    const DIAGNOSE_MAX: usize = 1024;
                    const DIAGNOSE_SHARE: usize = 4;
                    let db = builder.executor.evm_mut().db_mut();
                    // ... and never for a height the chain has already
                    // decided: that build's parent is behind the queue's
                    // pruning by construction, which is the same thing said
                    // a second way.
                    let diagnose = par_txs > 0 && !crate::canonical_head::already_decided(header.number);
                    for pool_tx in diagnose.then_some(&deferred).into_iter().flatten() {
                        if skipped_heads.len() >= DIAGNOSE_MAX {
                            break;
                        }
                        let sender = pool_tx.sender();
                        if skipped_heads.contains_key(&sender) {
                            continue;
                        }
                        // The graft writes the block's accounts into the
                        // bundle, and into the state's cache only when
                        // something after it may read them (`keep_cache`
                        // above) -- which for a block that seals early is
                        // nothing at all. So the bundle first, and the
                        // database only for a sender this block has not
                        // touched.
                        let grafted = db
                            .bundle_state
                            .state
                            .get(&sender)
                            .or_else(|| output_shards.as_ref().and_then(|shards| shards.get(&sender)))
                            .and_then(|account| account.info.as_ref())
                            .map(|info| info.nonce);
                        let nonce = match grafted {
                            Some(nonce) => Some(nonce),
                            None => db.basic(sender).ok().map(|account| account.map_or(0, |a| a.nonce)),
                        };
                        if let Some(nonce) = nonce {
                            skipped_heads.insert(sender, (pool_tx.nonce(), nonce));
                        }
                    }
                    // What the gap actually is, for the first few senders:
                    // the nonce the account is at, the lowest the lane
                    // holds, and how far apart they are. `par_skipped` says
                    // a build could use nothing; this says why, and it is
                    // the one thing loop207 through loop213 could not read
                    // off any line.
                    if !skipped_heads.is_empty() {
                        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        if say_once_a_second(&LAST) {
                            let named: Vec<(alloy_primitives::Address, u64, u64, i64)> = skipped_heads
                                .iter()
                                .take(4)
                                .map(|(sender, (head, state))| {
                                    (*sender, *head, *state, (*head as i64) - (*state as i64))
                                })
                                .collect();
                            tracing::info!(
                                target: "payload_builder",
                                number = header.number,
                                senders = skipped_heads.len(),
                                par_groups,
                                par_skipped,
                                first = ?named,
                                "the heads a build could not use: (sender, lane head, account nonce, head - nonce)"
                            );
                        }
                    }
                    if skipped_heads.len().saturating_mul(DIAGNOSE_SHARE) > par_groups {
                        // Most of the senders this build was offered: the
                        // build is the odd one out, not the queue. The
                        // leftovers go back the way they did before parks
                        // existed.
                        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        if say_once_a_second(&LAST) {
                            warn!(
                                target: "payload_builder",
                                number = header.number,
                                heads = skipped_heads.len(),
                                par_groups,
                                par_txs,
                                par_skipped,
                                "most of the senders a build was offered looked gapped; reporting none of them"
                            );
                        }
                        skipped_heads.clear();
                    }
                }
                Err(why) => {
                    // Counted, and said out loud: a leg that reads the phase
                    // medians of the parallel step has no way of knowing that
                    // some of its blocks never took it.
                    static DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    let declined = DECLINED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    tracing::info!(target: "payload_builder", %why, candidates = cands.len(), declined, "parallel build declined; building serially");
                    for tx in cands.into_iter().rev() {
                        lookahead.push_front(tx);
                    }
                }
            }
        }
        par_ms = par_at.elapsed().as_millis() as u64;
    }
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
            let seal_at_exec_used = sealed_ahead.is_some();
            let (payload, recovered, block_hash, block_number, root_ms, fields_ms, sealed_ms, sealed_at_ms, parent_sealed) =
                match sealed_ahead.take() {
                    Some(sealed) => sealed,
                    None => {
                        let Some(EarlySeal { hook, parent_built: _ }) = early else {
                            return Err(PayloadBuilderError::other(std::io::Error::other("no early seal to seal with")));
                        };
                        seal_block!(hook, seal_at, early_transactions_root)
                    }
                };
            let qmdb_state = qmdb.clone().expect("checked above");

            // ---- behind the seal ----
            // A failure here is after the proposal: the store's waiters are
            // told at once (`fail`), the engine's own path imports the block
            // when consensus commits it, and the error is loud.
            let behind_the_seal = || -> Result<(), PayloadBuilderError> {
            let finish_at = std::time::Instant::now();
            let (evm, mut execution_result) = builder
                .executor
                .finish()
                .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
            // Receipts built beside the parallel step: the executor committed
            // none, so its finish reports none and no gas.
            let direct_receipts_used = direct_receipts.is_some();
            if let Some((receipts, gas_used)) = direct_receipts {
                execution_result.receipts = receipts;
                execution_result.gas_used = gas_used;
            }
            let (db, _evm_env) = reth_evm::Evm::finish(evm);
            db.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);
            let merge_ms = finish_at.elapsed().as_millis() as u64;
            // The post-state is final: the next block can be built on it.
            // The bundle is taken and its reverts appended once, here, and the
            // one execution output is shared by `state_ready`, the roots below
            // and `complete`: the provisional used to clone the whole bundle
            // (~147,000 accounts) and every receipt only to drop the receipts,
            // inside the 26 ms before the next build could start (loop138).
            // The hashed state comes with `complete`.
            let mut bundle = db.take_bundle();
            let bundle_taken_at = std::time::Instant::now();
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
                let filed = crate::fields_at_seal::file_parent_under_seal(
                    &qmdb_state,
                    parent_sealed,
                    parent_built,
                    fields_mode.early(),
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
            let fields_published_at = std::cell::Cell::new(None::<std::time::Instant>);
            // `N42_FIELDS_AT_SEAL=verify`: what the fields were published
            // from, compared behind `Complete` with the late derivation.
            let mut early_inputs;
            let prague = chain_spec.is_prague_active_at_timestamp(attributes.timestamp);
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
            rename_parent()?;
            let roots_at = std::time::Instant::now();
            let bundle_ref = &execution_output.state;
            // The state provider is `Send` but not `Sync`: the hashed
            // post-state stays on this thread while the root and the
            // receipts run beside it.
            let parent_root_early = verify_fields.then(|| qmdb_state.root_of(&parent_sealed)).flatten();
            let (hashed_state, (prepared, root_started, root_ended, kept_ops), roots) = std::thread::scope(|scope| {
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
                let prepared = root.join().expect("the QMDB root job does not panic");
                let roots = receipts.join().expect("the receipts root job does not panic");
                (hashed, prepared, roots)
            });
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
            let residual = Arc::new(reth_execution_types::BlockExecutionOutput {
                state: bundle,
                result: reth_execution_types::BlockExecutionResult {
                    receipts: Vec::new(),
                    requests: Default::default(),
                    gas_used: 0,
                    blob_gas_used: 0,
                },
            });
            crate::built_executions::shards_ready(
                block_hash,
                crate::built_executions::ShardedParent { residual: Arc::clone(&residual), shards: Arc::clone(&shards) },
            );
            shard_ready_ms = finish_at.elapsed().as_millis() as u64;
            let residual_state = &residual.state;
            let overlaps = shards.overlaps(residual_state);
            let view = shards.view(residual_state, &overlaps);
            view_ready_at = Some(std::time::Instant::now());
            let destroyed = crate::output_shards::any_destroyed(&view);
            let hashed_off = n42_qmdb_reth::n42_state::hashed_tables_off();
            let shard_reverts = std::mem::take(&mut par_reverts);
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
                    let roots = crate::hotstuff_consensus::gov5_receipt_root_bloom(&execution_result.receipts);
                    (execution_result, roots)
                });
                rename_parent()?;
                let parent_root_early = verify_fields.then(|| qmdb_state.root_of(&parent_sealed)).flatten();
                let roots_from = std::time::Instant::now();
                let qmdb_job = &qmdb_state;
                let ahead = ops_ahead.take();
                let shards_ref = &shards;
                let overlaps_ref = &overlaps;
                let root = scope.spawn(move || {
                    // The leader's QMDB root job: on the critical set.
                    let started = std::time::Instant::now();
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
                        let replaced: Vec<(&alloy_primitives::Address, &revm::database::BundleAccount)> = residual_state
                            .state
                            .keys()
                            .filter_map(|address| shards_ref.get(address).map(|account| (address, account)))
                            .collect();
                        let newer: Vec<(&alloy_primitives::Address, &revm::database::BundleAccount)> = residual_state
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
                        Some((ops, split, OpsAheadUse { waited, finish: finish_at.elapsed(), done_at: Some(done_at) }))
                    });
                    let (ops, split, ahead_use) = match finished {
                        Some(finished) => finished,
                        None => {
                            let (ops, split) = n42_qmdb_reth::sorted_operations_from_accounts_timed(view_ref, prague);
                            (ops, split, OpsAheadUse::default())
                        }
                    };
                    let kept = verify_fields.then(|| ops.clone());
                    let ops_done = std::time::Instant::now();
                    let prepared = qmdb_job.compute_operations(parent_sealed, ops);
                    let ended = std::time::Instant::now();
                    let timed = (split, ops_done.duration_since(started), ended.duration_since(ops_done), ahead_use);
                    (prepared, started, ended, kept, timed)
                });
                // The hashed post-state beside the root on a thread of its
                // own, so the publication does not wait for it. A destroyed
                // account's storage is zeroed from the database: the
                // provider's own path, on the merged bundle, below.
                let hashed = (!hashed_off && !destroyed)
                    .then(|| scope.spawn(move || crate::output_shards::hashed_post_state_of(view_ref)));
                let (prepared, root_started, root_ended, kept_ops, ops_timed) = root.join().map_err(|_| {
                    PayloadBuilderError::other(std::io::Error::other("the QMDB root job panicked"))
                })?;
                let (execution_result, roots) = receipts.join().map_err(|_| {
                    PayloadBuilderError::other(std::io::Error::other("the receipts root panicked"))
                })?;
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
                        let merge_at = std::time::Instant::now();
                        let (mut merged, split) = shards.merged_timed(&residual.state, false);
                        let tail_at = std::time::Instant::now();
                        crate::parallel_transfer::append_reverts(&mut merged, shard_reverts);
                        let merge_end = std::time::Instant::now();
                        let merge_ms = merge_end.duration_since(merge_at).as_millis() as u64;
                        let timing = LeaderMerge {
                            started: Some(merge_at),
                            ended: Some(merge_end),
                            split,
                            tail_us: merge_end.duration_since(tail_at).as_micros() as u64,
                            threads: 1,
                            accounts: merged.state.len(),
                            reverts: merged.reverts.iter().map(Vec::len).sum(),
                            state_ready: None,
                        };
                        let execution_output =
                            Arc::new(reth_execution_types::BlockExecutionOutput { state: merged, result: execution_result });
                        crate::built_executions::state_ready(
                            block_hash,
                            crate::built_executions::BuiltExecution {
                                block: recovered,
                                execution_output: Arc::clone(&execution_output),
                                hashed_state: Arc::new(Default::default()),
                                trie_updates: Arc::new(TrieUpdates::default()),
                            },
                        );
                        let timing = LeaderMerge { state_ready: Some(std::time::Instant::now()), ..timing };
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
                let (overlay_filter_skips, overlay_probes) = if crate::fast_transfer::phase_timers() {
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
                    par_prep_ms,
                    par_part_ms,
                    par_exec_ms,
                    par_collect_ms,
                    par_commit_ms,
                    direct_receipts = direct_receipts_used,
                    par_graft_ms,
                    par_prefault_ms,
                    par_prefetch_ms,
                    par_prefetch_wait_ms,
                    par_fold_ms,
                    tx_root_ms = root_ms,
                    parent_fields_ms = fields_ms,
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
                    exec_read_ms = par_transfer_timers.read_ns / 1_000_000,
                    exec_evm_ms = par_transfer_timers.evm_ns / 1_000_000,
                    exec_write_ms = par_transfer_timers.write_ns / 1_000_000,
                    exec_other_ms = par_transfer_timers.other_ns / 1_000_000,
                    reads_cache = par_transfer_timers.reads_cache(),
                    reads_provider = par_transfer_timers.reads_provider,
                    reads_view = par_transfer_timers.reads_view,
                    // `N42_READ_SET=1`: the pass (inside `par_exec_ms`), its
                    // accounts, the batches' reads it answered and those that
                    // fell to the parent's state. Zero when the flag is off.
                    read_set_ms = par_read_set.wall_us / 1000,
                    read_set_dedup_us = par_read_set.dedup_us,
                    read_set_resolve_us = par_read_set.resolve_us,
                    read_set_accounts = par_read_set.accounts,
                    read_set_unresolved = par_read_set.unresolved,
                    read_set_hits = par_read_set_hits,
                    read_set_misses = par_read_set_misses,
                    read_set_reads_provider = par_read_set.reads_provider,
                    read_set_reads_view = par_read_set.reads_view,
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
                    loop_fetch_ns = par_loop_timers.per_tx(par_loop_timers.fetch_ns),
                    loop_check_ns = par_loop_timers.per_tx(par_loop_timers.check_ns),
                    loop_transfer_ns = par_loop_timers.per_tx(par_loop_timers.transfer_ns),
                    loop_receipt_ns = par_loop_timers.per_tx(par_loop_timers.receipt_ns),
                    loop_sink_ns = par_loop_timers.per_tx(par_loop_timers.sink_ns),
                    loop_gas_ns = par_loop_timers.per_tx(par_loop_timers.gas_ns),
                    loop_other_ns = par_loop_timers.per_tx(par_loop_timers.other_ns),
                    batch_setup_ns = par_loop_timers.per_tx(par_loop_timers.batch_setup_ns),
                    batch_close_ns = par_loop_timers.per_tx(par_loop_timers.batch_close_ns),
                    graft_base_ms = par_graft_base_ms,
                    graft_reserve_ms = par_graft_reserve_ms,
                    graft_insert_ms = par_graft_insert_ms,
                    graft_reverts_ms = par_graft_reverts_ms,
                    graft_other_ms = par_graft_other_ms,
                    graft_sharded = par_graft_sharded,
                    graft_split_us = par_graft_split_us,
                    graft_build_us = par_graft_build_us,
                    graft_merge_us = par_graft_merge_us,
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
                    merge_threads = leader_merge.threads,
                    merge_accounts = leader_merge.accounts,
                    merge_reverts = leader_merge.reverts,
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
                    // `N42_SEAL_AT_EXEC=1` (plan v6 G2): sealed at the parallel
                    // step's end with the fold behind the proposal; the
                    // transactions root computed over the pulled set beside
                    // the execution was the one sealed, and how long the
                    // step's end waited for it.
                    seal_at_exec = seal_at_exec_used,
                    tx_root_ahead,
                    tx_root_wait_ms,
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
                    // `N42_PULL_BY_FRAMES`: the block taken out of its
                    // frames at once (0 = through the puller) and how long.
                    pull_bulk_txs = select_times.bulk_txs,
                    pull_bulk_us = select_times.bulk_us,
                    start_check_ms,
                    start_puller_ms,
                    start_prepare_ms,
                    start_other_ms,
                    pre_exec_ms,
                    par_run_ms,
                    par_release_ms,
                    scope_join_ms,
                    commit_refs_ms,
                    commit_cumulative_ms,
                    commit_fees_ms,
                    commit_body_ms,
                    commit_body_ahead_used,
                    // `N42_SEAL_ON_COUNTERS=1`: sealed on the batches'
                    // counters (no pass over the slots before the seal), and
                    // the batches' end to the seal's start, us.
                    seal_on_counters = seal_on_counters_used,
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
                    exec_prepared_slots,
                    exec_partition_us,
                    exec_slots_us,
                    whole_take_noted,
                    match_ms,
                    seal_header_ms,
                    seal_block_ms,
                    seal_remember_ms,
                    seal_hook_ms,
                    seal_layout_ms,
                    seal_root_ms,
                    // The seal's hash vector came with the body (no collect).
                    seal_hashes_ahead,
                    seal_frames_indexed,
                    seal_frames_hashed,
                    gap_before_exec_ms,
                    gap_after_exec_ms,
                    gap_before_seal_ms,
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
            return match behind_the_seal() {
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
    if direct_receipts.is_some() {
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

    loop {
        // Once the block cannot fit even the smallest transaction there is
        // nothing left to take: every further candidate would only be
        // refused, one refusal per queued sender -- thousands of them at the
        // end of every full block (round 37). Checked before taking, so that
        // nothing is taken from the queue and left neither built nor returned.
        // Closed as well after a parallel step that skipped a block's worth
        // (`AfterParallelStep::Finish`): what was taken goes back below.
        if serial_closed || block_gas_limit.saturating_sub(cumulative_gas_used) < MIN_TRANSACTION_GAS {
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
        } else if prefetch == 0 {
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
                // The accounts these transactions read, fetched on the worker
                // pool into the build's read cache: the serial execution then
                // finds them there. At the bench tier almost every recipient is
                // a cold miss, and those misses were most of the execution time.
                {
                    use rayon::prelude::*;
                    let cached: &mut reth_revm::cached::CachedReads = builder.evm_mut().db_mut().database.cached;
                    let mut wanted: Vec<alloy_primitives::Address> = Vec::with_capacity(lookahead.len() * 2);
                    for pool_tx in &lookahead {
                        let sender = pool_tx.sender();
                        if !cached.accounts.contains_key(&sender) {
                            wanted.push(sender);
                        }
                        if let Some(to) = pool_tx.to() {
                            if !cached.accounts.contains_key(&to) {
                                wanted.push(to);
                            }
                        }
                    }
                    wanted.sort_unstable();
                    wanted.dedup();
                    // The build's state provider is not shared across threads;
                    // each chunk opens its own on the same parent.
                    let fetched: Vec<(alloy_primitives::Address, Option<Option<revm::state::AccountInfo>>)> = wanted
                        .par_chunks(256)
                        .flat_map_iter(|chunk| {
                            let provider = open_parent_state().ok();
                            chunk.iter().map(move |address| {
                                let info = provider.as_ref().and_then(|provider| {
                                    reth_storage_api::AccountReader::basic_account(provider, address).ok().map(|a| a.map(Into::into))
                                });
                                (*address, info)
                            })
                        })
                        .collect();
                    for (address, info) in fetched {
                        // A read that failed is left for the execution to
                        // repeat, and report.
                        if let Some(info) = info {
                            cached.accounts.entry(address).or_insert(reth_revm::cached::CachedAccount { info, storage: Default::default() });
                        }
                    }
                }
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
        if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
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
        if stale_check() {
            if let Ok(Some(account)) = builder.evm_mut().db_mut().basic(pool_tx.sender()) {
                if pool_tx.nonce() < account.nonce {
                    stale_txs += 1;
                    continue;
                }
            }
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
                        && let Some(revm::context_interface::result::InvalidTransaction::NonceTooLow { tx, state }) =
                            reth_evm::InvalidTxError::as_invalid_tx_err(&*error)
                    {
                        refuse!(
                            &pool_tx,
                            InvalidPoolTransactionError::Consensus(
                                InvalidTransactionError::NonceNotConsistent { tx: *tx, state: *state }
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
                    let kind = match reth_evm::InvalidTxError::as_invalid_tx_err(&*error) {
                        Some(revm::context_interface::result::InvalidTransaction::NonceTooHigh { tx, state }) => {
                            InvalidTransactionError::NonceNotConsistent { tx: *tx, state: *state }
                        }
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

    // On a QMDB chain the state root is not reth's to compute. The builder is
    // handed a zero root so it skips the Merkle-Patricia computation; the real
    // root comes from the forest, over the bundle execution left behind, and
    // replaces the zero in the header below. The block hash follows from the
    // sealed header, so the tree is filed under it only once that is known.
    let (
        BlockBuilderOutcome {
            execution_result,
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
            let outcome =
                builder.finish(parent_state_ref()?, Some((B256::ZERO, TrieUpdates::default())))?;
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
                            &db.bundle_state,
                            chain_spec.is_prague_active_at_timestamp(attributes.timestamp),
                        ),
                    )
                    .map_err(PayloadBuilderError::other)?,
            };
            (outcome, Some(prepared), finish_took, root_at.elapsed())
        }
        None => {
            let finish_at = std::time::Instant::now();
            let outcome = builder.finish(parent_state_ref()?, None)?;
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
    let mut bundle = db.take_bundle();
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
        let parent_fields = crate::hotstuff_consensus::parent_executed_fields_or_built(
            chain_spec.genesis(),
            &parent_header,
            parent_built,
            crate::hotstuff_consensus::PARENT_FIELDS_WAIT,
        )
        .ok_or_else(|| PayloadBuilderError::other(crate::hotstuff_consensus::DeferredExecutionError::ParentUnknown(parent_header.hash())))?;
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

    // seal
    build_stage.at(5);
    cons.seal(&mut header)
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;

    // Keep the recovered senders: EthBuiltPayload now takes a RecoveredBlock, and
    // re-recovering them from signatures here would be pure waste.
    let senders = block.senders().to_vec();
    let sealed_block = SealedBlock::seal_parts(header, block.into_block().body);
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
            fast = crate::fast_transfer::hits().saturating_sub(fast_hits_before),
            verified_by_builder = crate::claimed_build::verified().saturating_sub(verified_before),
            builder_dropped_bad_claim = crate::claimed_build::dropped().saturating_sub(dropped_before),
            verify_ms = crate::claimed_build::verify_ms().saturating_sub(verify_ms_before),
            par_txs,
            par_groups,
            par_batches,
            par_skipped,
            par_pull_ms,
            par_part_ms,
            par_exec_ms,
            par_graft_ms,
            par_fold_ms,
            par_committed,
            par_ms,
            state_after_pull = defer_state,
            state_wait_ms,
            state_wait_us,
            state_wait_on = state_wait_label(state_wait_us, &state_wait_on),
            state_wait_split = %state_wait_on.split(),
            refused = ?crate::fast_transfer::rejected(),
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
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
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
            crate::n42_evm::N42EvmConfig::new_with_evm_factory(ctx.chain_spec(), crate::fast_transfer::N42EvmFactory::from_env()),
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
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

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

/// Whether the builder reads each sender's account before executing, to
/// skip stale transactions early: `N42_BUILDER_STALE_CHECK=1`; off by
/// default (see the loop).
/// `N42_PARALLEL_BUILD`, read once: the block's transfers built in parallel groups.
/// Whether `N42_BUILD_GRAFT_NO_CACHE=1` is set (see the graft in the parallel step).
fn build_graft_no_cache() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_GRAFT_NO_CACHE").is_ok_and(|v| v == "1"))
}

/// Whether a block that will seal early builds its receipts beside the parallel step instead of
/// one executor commit per transfer (`N42_DIRECT_RECEIPTS=0` goes back to the commits). On since
/// loop170-171: 1,514 early-sealed blocks over eight legs took it with no guard error, no invalid
/// block and no gas-used mismatch, and the receipts left the leader's serial chain (27-61 ms a
/// full block before, 11-33 after).
fn direct_receipts_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_DIRECT_RECEIPTS").map_or(true, |v| v != "0"))
}

fn parallel_build() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PARALLEL_BUILD").is_ok())
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
    *N.get_or_init(|| std::env::var("N42_BUILDER_PULLER").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
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

    fn batches(&self) -> &std::sync::mpsc::Receiver<Vec<Arc<reth_transaction_pool::ValidPoolTransaction<T>>>> {
        self.batches.as_ref().expect("the puller's receiver is taken only on drop")
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

fn builder_prefetch() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| std::env::var("N42_BUILDER_PREFETCH").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
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
mod plan_body_tests {
    //! `N42_PLAN_AHEAD_BODY=1` (`docs/SHARED_EXECUTION_SCOPE.md` 16.4 item 2):
    //! what the plan-ahead hook makes equals what the build's start, prep and
    //! gap make from the same candidates.
    use super::*;
    use crate::parallel_transfer::{execute_for_build_counted_dispatch, partition_by_sender, BodyAhead, PreparedExec};
    use alloy_primitives::{Address, Bytes};
    use n42_tx_types::{AltSigTx, N42TxEnvelope, TxAltSig, ALG_ED25519};
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{
        identifier::{SenderId, TransactionId},
        TransactionOrigin, ValidPoolTransaction,
    };
    use revm::database::{CacheDB, EmptyDB};
    use revm::state::AccountInfo;

    type Cand = Arc<ValidPoolTransaction<crate::N42PooledTransaction>>;

    fn address(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[..8].copy_from_slice(&i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    /// `senders` frames of `run` 0x50 transfers each (one sender a frame,
    /// nonces from `first`), recipients drawn from `space`, the senders funded
    /// in `db`.
    fn frames(senders: u64, run: u64, first: u64, space: u64, db: &mut CacheDB<EmptyDB>) -> Vec<(n42_tx_queue::FrameTxs<crate::N42PooledTransaction>, usize)> {
        let mut seed = 0x2545_f491_4f6c_dd1du64 ^ first;
        let mut out = Vec::new();
        for s in 0..senders {
            let sender = address(100 + s);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: first, ..Default::default() });
            let mut pubkey = [0u8; 32];
            pubkey[..8].copy_from_slice(&s.to_be_bytes());
            let mut frame: Vec<Cand> = Vec::new();
            for k in first..first + run {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let tx = TxAltSig {
                    chain_id: 1,
                    nonce: k,
                    max_priority_fee_per_gas: 1_000_000_000 + u128::from(seed % 1_000),
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
            // A cut last frame, as a plan's last frame may be.
            let taken = if s + 1 == senders { len.div_ceil(2) } else { len };
            out.push((Arc::from(frame), taken));
        }
        out
    }

    /// The body made with the plan equals the body the build's prep makes
    /// from the same candidates (keys, transactions, senders, hashes), its
    /// partition is the call's, its slots are empty; and three blocks of
    /// different shapes executed on the prepared partition and slots equal
    /// the fresh call: transfers, gas, success, skips, counters and the
    /// batches' bundles.
    #[test]
    fn body_made_with_the_plan_equals_body_made_at_start() {
        let beneficiary = address(1);
        crate::frame_blocks::note_beneficiary(beneficiary);
        let base_fee = 1_000_000_000u64;
        for (senders, run, first, space) in [(60u64, 20u64, 0u64, 500u64), (200, 3, 4, 50_000), (17, 90, 1, 40)] {
            let mut db = CacheDB::new(EmptyDB::default());
            db.insert_account_info(beneficiary, AccountInfo { balance: U256::from(7), ..Default::default() });
            let segments = frames(senders, run, first, space, &mut db);
            let made = make_prepared_build(&segments).expect("every candidate a transfer");
            let cands: Vec<Cand> = segments.iter().flat_map(|(txs, taken)| txs[..*taken].to_vec()).collect();
            assert_eq!(made.cands.len(), cands.len());
            assert!(made.cands.iter().zip(&cands).all(|(a, b)| Arc::ptr_eq(a, b)), "the candidates, in plan order");
            let in_place: Vec<(n42_tx_queue::FrameTxs<_>, usize, usize)> =
                segments.iter().map(|(txs, taken)| (Arc::clone(txs), 0, *taken)).collect();
            assert!(made.made_from(&in_place));
            let mut cut = in_place.clone();
            cut[0].2 -= 1;
            assert!(!made.made_from(&cut), "another take is not the plan's");
            // The prep, as the build runs it.
            let (keys, fresh) = BodyAhead::make_keyed(&cands, |_, tx| {
                let consensus = pooled_consensus(tx);
                (transfer_key(tx), consensus.clone(), tx.sender(), consensus.effective_tip_per_gas(base_fee).unwrap_or_default(), *tx.hash())
            })
            .expect("transfers");
            assert_eq!(made.keys, keys, "keys");
            assert_eq!(made.transactions, fresh.transactions, "transactions");
            assert_eq!(made.senders, fresh.senders, "senders");
            let hashes: Vec<B256> = fresh.transactions.iter().map(|tx| *alloy_consensus::transaction::TxHashRef::tx_hash(tx)).collect();
            assert_eq!(made.hashes, hashes, "hashes");
            assert_eq!(fresh.hashes, hashes, "the prep's hashes are the seal's collect");
            let (noted, groups) = made.groups.clone().expect("a beneficiary was noted");
            assert_eq!(noted, beneficiary);
            assert_eq!(groups, partition_by_sender(&keys, beneficiary).expect("a partition"), "partition");
            assert_eq!(made.slots.len(), cands.len());
            assert!(made.slots.iter().all(|slot| slot.get().is_none()), "empty slots");

            // Executed on the prepared partition and slots, and fresh.
            let header = alloy_consensus::Header {
                number: 20_000_000,
                beneficiary,
                gas_limit: 5_000_000_000,
                base_fee_per_gas: Some(base_fee),
                timestamp: 1_800_000_000,
                ..Default::default()
            };
            let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(
                reth_chainspec::MAINNET.clone(),
                crate::fast_transfer::N42EvmFactory::with_fast_transfers(true),
            );
            let evm_env = evm_config.evm_env(&header).expect("env");
            let convert = |i: usize| ((), evm_config.tx_env(reth_transaction_pool::PoolTransaction::consensus_ref(&cands[i].transaction)));
            let tip_of = |i: usize| pooled_consensus(&cands[i]).effective_tip_per_gas(base_fee).unwrap_or_default();
            let run_with = |prepared: Option<PreparedExec<()>>| {
                let run = execute_for_build_counted_dispatch(&evm_env, &keys, &convert, &|| Some(db.clone()), true, false, Some(&tip_of), prepared)
                    .expect("a block of transfers");
                let executed: Vec<(usize, u64, bool)> =
                    run.slots.iter().filter_map(std::sync::OnceLock::get).map(|b| (b.index, b.gas_used, b.result.is_success())).collect();
                let mut accounts: Vec<(Address, Option<AccountInfo>)> =
                    run.bundles.iter().flat_map(|b| b.state.iter().map(|(a, acc)| (*a, acc.info.clone()))).collect();
                accounts.sort_by_key(|(a, _)| *a);
                (executed, run.skipped, run.counters, accounts, run.phases.prepared_groups, run.phases.prepared_slots)
            };
            let fresh_run = run_with(None);
            let mut made = made;
            let prepared = PreparedExec { groups: made.groups.take().map(|(_, groups)| groups), slots: Some(std::mem::take(&mut made.slots)) };
            let planned_run = run_with(Some(prepared));
            assert!(planned_run.4 && planned_run.5, "the prepared partition and slots were taken");
            assert!(!fresh_run.4 && !fresh_run.5);
            assert_eq!(fresh_run.0.len(), cands.len(), "every transfer ran");
            assert_eq!(fresh_run.0, planned_run.0, "executed transfers");
            assert_eq!(fresh_run.1, planned_run.1, "skipped");
            assert_eq!(fresh_run.2, planned_run.2, "counters");
            assert_eq!(fresh_run.3, planned_run.3, "the batches' accounts");
            // A partition or slots of another size are not taken.
            let wrong = PreparedExec { groups: Some(vec![vec![0]]), slots: Some(crate::parallel_transfer::empty_slots(crate::parallel_transfer::build_pool(), 3)) };
            let fallback = run_with(Some(wrong));
            assert!(!fallback.4 && !fallback.5);
            assert_eq!(fallback.0, fresh_run.0);
        }
    }
}

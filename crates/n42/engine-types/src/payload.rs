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
                        let best = queue.best_for_build(parent_hash);
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
        let parent_hash = parent.hash();
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
                    tracing::debug!(
                        target: "payload_builder",
                        wait_ms = at.elapsed().as_millis() as u64,
                        "the parent's queue hand-off is done; the build pulls"
                    );
                }
                let best = queue.best_for_build(parent_hash);
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

/// The receipts of a block the parallel step left in its slots, in block
/// order, with `cumulative[i]` the block's gas through transaction `i`.
fn receipts_from_slots(
    refs: &[&crate::parallel_transfer::BuiltTransfer<reth_primitives_traits::Recovered<TransactionSigned>>],
    cumulative: &[u64],
) -> Vec<n42_tx_types::Receipt> {
    use rayon::prelude::*;
    refs.par_iter()
        .zip(cumulative.par_iter())
        .map(|(built, cumulative_gas_used)| n42_tx_types::Receipt {
            tx_type: <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(built.tx.inner()),
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
    let open_parent_state = || -> Result<reth_storage_api::StateProviderBox, reth_storage_api::errors::ProviderError> {
        match &parent_state {
            Some(open) => open(),
            None => client.state_by_block_hash(parent_hash_for_state),
        }
    };
    let state_provider = open_parent_state()?;
    let state = StateProviderDatabase::new(&state_provider);
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

    let mut best_txs = best_txs(BestTransactionsAttributes::new(
        base_fee,
        builder
            .evm_mut()
            .block()
            .blob_gasprice()
            .map(|gasprice| gasprice as u64),
    ));
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
    // A height the chain has already committed: nothing will ask for this
    // payload, and building it costs a block's worth of the queue and a
    // build's worth of verdicts about a state consensus did not keep. Taken
    // before anything is selected, so the queue is not touched at all.
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
    let puller = builder_puller();
    let mut pulled: Option<Puller<Pool::Transaction>> = None;
    let mut best_txs = if puller == 0 {
        Some(best_txs)
    } else {
        pulled = Some(Puller::start(best_txs, puller));
        None
    };
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

    let mut header = cons
        .prepare(&parent_header)
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
    if hotstuff {
        header.beneficiary = coinbase;
    }

    builder.apply_pre_execution_changes().map_err(|err| {
        warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
        PayloadBuilderError::Internal(err.into())
    })?;

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
    let mut par_transfer_timers = crate::fast_transfer::TransferTimers::default();
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
            let transactions_root = match early_root {
                Some(root) => root,
                None => crate::assembler::parallel_transaction_root(&transactions),
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
            let body = alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals };
            let sealed_block = SealedBlock::seal_parts(header.clone(), body);
            let block_hash = SealedBlock::hash(&sealed_block);
            let recovered: Arc<reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>> =
                Arc::new(reth_primitives_traits::RecoveredBlock::new_sealed(sealed_block, senders));
            crate::built_executions::remember_pending(block_hash, recovered.clone());
            let payload = EthBuiltPayload::new(recovered.clone(), total_fees, None, None);
            ($hook)(payload.clone());
            let sealed_ms = seal_at.elapsed().as_millis() as u64;
            let sealed_at_ms = build_started.elapsed().as_millis() as u64;
            build_stage.at(5);
            (payload, recovered, block_hash, block_number, root_ms, fields_ms, sealed_ms, sealed_at_ms, parent_sealed)
        }};
    }
    if parallel_build() && pulled.is_some() {
        let par_at = std::time::Instant::now();
        let budget = (block_gas_limit.saturating_sub(cumulative_gas_used) / MIN_TRANSACTION_GAS) as usize;
        let mut cands: Vec<Arc<reth_transaction_pool::ValidPoolTransaction<Pool::Transaction>>> =
            Vec::with_capacity(budget.min(262_144));
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
                .map(|s| crate::fast_transfer::doors::CountedDb::new(StateProviderDatabase::new(s)))
        };
        let warm_fill = crate::parallel_transfer::build_prefetch().then(crate::parallel_transfer::WarmAccounts::new);
        let (warm_ref, open_ref) = (warm_fill.as_ref(), &open_db);
        let (all_transfers, keys, prep_done) = crate::parallel_transfer::build_pool().in_place_scope(|scope| {
            if let Some(puller) = pulled.as_ref() {
                while cands.len() < budget {
                    match puller.batches.recv() {
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
            let all_transfers = !cands.is_empty()
                && cands.iter().all(|tx| {
                    let tx = &tx.transaction;
                    tx.gas_limit() == MIN_TRANSACTION_GAS
                        && tx.input().is_empty()
                        && !tx.is_create()
                        && tx.access_list().is_none_or(|list| list.is_empty())
                        && !tx.is_eip4844()
                        && !tx.is_eip7702()
                });
            let keys: Vec<(alloy_primitives::Address, alloy_primitives::Address)> = if all_transfers {
                cands.iter().map(|tx| (tx.sender(), tx.transaction.to().unwrap_or_default())).collect()
            } else {
                Vec::new()
            };
            par_prep_ms = prep_at.elapsed().as_millis() as u64;
            (all_transfers, keys, std::time::Instant::now())
        });
        // The scope waited here for the prefetch's last jobs: 0 when the
        // pull and the prep hid it.
        par_prefetch_wait_ms = prep_done.elapsed().as_millis() as u64;
        par_prefetch_ms = warm_fill.as_ref().map_or(0, |warm| warm.busy_us() / 1000);
        let warm = warm_fill.map(crate::parallel_transfer::WarmAccounts::freeze).unwrap_or_default();
        if !all_transfers {
            for tx in cands.into_iter().rev() {
                lookahead.push_front(tx);
            }
        } else {
            let convert = |i: usize| {
                let recovered: reth_primitives_traits::Recovered<TransactionSigned> = cands[i].to_consensus();
                let env = evm_config.tx_env(recovered.as_recovered_ref());
                (recovered, env)
            };
            // Without the prefetch the layer is empty and every read goes
            // to the provider, as before.
            let open = || open_db().map(|db| crate::parallel_transfer::WarmDb::new(&warm, db));
            // `N42_GRAFT_STREAM=1`: each batch's bundle is folded into the
            // block's graft as that batch finishes, on the worker pool, rather
            // than all of them on this thread once the execution is over (the
            // graft was 60 ms of the leader's serial chain, loop173-174). The
            // block's state is untouched until the install below, so a batch
            // that fails still leaves the serial path a clean state.
            let staged = crate::parallel_transfer::graft_stream().then(|| {
                std::sync::Mutex::new(crate::parallel_transfer::StagedGraft::new(group_env.block_env.beneficiary, keys.len()))
            });
            let sink = staged.as_ref().map(|staged| {
                move |bundle: revm::database::BundleState| staged.lock().expect("the staged graft's lock").add(bundle)
            });
            let sink: Option<&(dyn Fn(revm::database::BundleState) + Sync)> =
                sink.as_ref().map(|sink| sink as &(dyn Fn(revm::database::BundleState) + Sync));
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
            let prefault = crate::parallel_transfer::graft_prefault() && staged.is_none();
            // `N42_SEAL_AT_EXEC=1`: the transactions root over the pulled
            // candidates, in pull order, on a thread of its own (not the build
            // pool, whose threads the execution uses) while the batches run.
            // With nothing skipped the body is exactly that set in that order
            // (`body_matches_pull`), and the seal takes this root instead of
            // computing one after the execution.
            let root_ahead_wanted =
                seal_at_exec() && seal_early_possible && block_blob_count == 0 && direct_receipts_enabled();
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
                            pulled_set[i].to_consensus().into_inner().encoded_2718()
                        })
                    })
                });
                let executed =
                    crate::parallel_transfer::execute_for_build_in_place(&group_env, &keys, &convert, &open, sink, in_place);
                let exec_done = std::time::Instant::now();
                let root_ahead = root_job.and_then(|job| job.join().ok());
                tx_root_wait_ms = exec_done.elapsed().as_millis() as u64;
                (executed, target.and_then(|job| job.join().ok()), root_ahead)
            });
            par_prefault_ms = graft_target.as_ref().map_or(0, |target| target.prefault_us / 1000);
            match executed {
                Ok(mut run) => {
                    use reth_evm::execute::BlockExecutor as _;
                    let beneficiary = group_env.block_env.beneficiary;
                    par_collect_ms = run.phases.collect_ms;
                    let fold_at = std::time::Instant::now();
                    // Block order, by reference: a pointer a transfer, where the
                    // collect moved ~470 bytes of each.
                    let refs = (!run.slots.is_empty())
                        .then(|| run.slots.iter().filter_map(std::sync::OnceLock::get).collect::<Vec<_>>());
                    let (executed_count, executed_gas) = match refs.as_ref() {
                        Some(refs) => (refs.len(), refs.iter().map(|built| built.gas_used).sum::<u64>()),
                        None => (run.executed.len(), run.executed.iter().map(|built| built.gas_used).sum::<u64>()),
                    };
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
                    // them behind the seal, beside the graft: the cumulative gas
                    // per transaction and the block's gas.
                    let mut receipts_behind: Option<(Vec<u64>, u64)> = None;
                    if let (true, true, Some(refs)) = (seals_early_here, direct_receipts_enabled(), refs.as_ref()) {
                        // The same body and receipts as the branch below, made
                        // from the slots: the transaction is copied out of its
                        // slot once, on the pool, straight into the body.
                        use rayon::prelude::*;
                        let mut cumulative = Vec::with_capacity(executed_count);
                        let mut tx_gas = 0u64;
                        for built in refs {
                            tx_gas += built.result.gas().tx_gas_used();
                            cumulative.push(tx_gas);
                        }
                        total_fees += refs
                            .par_iter()
                            .map(|built| {
                                let tip = built.tx.effective_tip_per_gas(base_fee).unwrap_or_default();
                                U256::from(tip) * U256::from(built.gas_used)
                            })
                            .reduce(|| U256::ZERO, |a, b| a + b);
                        let transactions: Vec<TransactionSigned> =
                            refs.par_iter().map(|built| built.tx.inner().clone()).collect();
                        let senders: Vec<alloy_primitives::Address> = refs.par_iter().map(|built| built.tx.signer()).collect();
                        cumulative_gas_used += executed_gas;
                        tx_count += executed_count as u64;
                        direct_body = Some((transactions, senders));
                        if ahead {
                            receipts_behind = Some((cumulative, tx_gas));
                        } else {
                            direct_receipts = Some((receipts_from_slots(refs, &cumulative), tx_gas));
                            // The slots' 77 MB are freed on the pool, off this thread.
                            let slots = std::mem::take(&mut run.slots);
                            crate::parallel_transfer::build_pool().spawn(move || drop(slots));
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
                                let tip = built.tx.effective_tip_per_gas(base_fee).unwrap_or_default();
                                U256::from(tip) * U256::from(built.gas_used)
                            })
                            .reduce(|| U256::ZERO, |a, b| a + b);
                        let (transactions, rest): (Vec<TransactionSigned>, Vec<(alloy_primitives::Address, n42_tx_types::Receipt)>) = executed
                            .into_par_iter()
                            .zip(cumulative.into_par_iter())
                            .map(|(built, cumulative_gas_used)| {
                                let tx_type = <TransactionSigned as alloy_consensus::TransactionEnvelope>::tx_type(built.tx.inner());
                                let receipt = n42_tx_types::Receipt {
                                    tx_type,
                                    success: built.result.is_success(),
                                    cumulative_gas_used,
                                    logs: built.result.into_logs(),
                                };
                                // Split here, on the pool, where the transaction
                                // is already in hand: the seal takes the two
                                // vectors as they are.
                                let (tx, sender) = built.tx.into_parts();
                                (tx, (sender, receipt))
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
                            let recovered = built.tx;
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
                    let withdrawals_clear = attributes.withdrawals.as_ref().is_none_or(|ws| match staged.as_ref() {
                        Some(staged) => {
                            let staged = staged.lock().expect("the staged graft's lock");
                            ws.iter().all(|w| !staged.holds(&w.address))
                        }
                        None => ws.iter().all(|w| !run.bundles.iter().any(|b| b.state.contains_key(&w.address))),
                    });
                    // Sealed early, nothing after the graft reads the cache
                    // either: the serial loop never runs.
                    let sealing_early = seal_early_possible && block_blob_count == 0 && (block_full || par_drained);
                    // The executor's finish credits the block's withdrawals
                    // through the cache, and a miss there would load the
                    // parent's account over the graft's (the faucet, on a
                    // funding block: audit 2026-09-12) -- so with the cache
                    // skipped, the withdrawal recipients the graft touched
                    // are put back into it below, and nothing else is.
                    let keep_cache = !(sealing_early || (build_graft_no_cache() && block_full && withdrawals_clear));
                    par_commit_ms = fold_at.elapsed().as_millis() as u64;
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
                        let matches = root_ahead.is_some()
                            && run.skipped.is_empty()
                            && direct_body.as_ref().is_some_and(|(transactions, _)| {
                                body_matches_pull(transactions, &cands, |tx| *tx.tx_hash(), |tx| *tx.hash())
                            });
                        tx_root_ahead = matches;
                        let sealed = seal_block!(hook, seal_at, if matches { root_ahead } else { None });
                        sealed_ahead_id = Some((sealed.2, sealed.3));
                        sealed_ahead = Some(sealed);
                        seal_took = seal_at.elapsed();
                    }
                    // The transactions root beside the graft when the block
                    // will seal early: the seal needs it, and the graft's
                    // 60-100 ms hide it (loop139: 42 ms on the seal path).
                    let bundles = run.bundles;
                    let staged = staged.map(|staged| staged.into_inner().expect("the staged graft's lock"));
                    // Of the fold: the graft alone, without the transactions
                    // root that runs beside it -- `par_fold_ms` is the longer
                    // of the two, so a graft that falls under the root would
                    // not show in it (plan v5 attempt D).
                    let mut graft_ms = 0u64;
                    let (graft, early_root, receipts) = std::thread::scope(|scope| {
                        // Sealed at the execution's end: the receipts from the
                        // slots, beside the graft, instead of the root.
                        let receipts_job = receipts_behind.as_ref().map(|(cumulative, _)| {
                            let (slots, cumulative): (&[_], &[u64]) = (&run.slots, cumulative);
                            scope.spawn(move || {
                                let refs: Vec<_> = slots.iter().filter_map(std::sync::OnceLock::get).collect();
                                receipts_from_slots(&refs, cumulative)
                            })
                        });
                        let root = (sealing_early && sealed_ahead.is_none()).then(|| match direct_body.as_ref() {
                            Some((transactions, _)) => {
                                let txs: &[TransactionSigned] = transactions;
                                scope.spawn(move || crate::assembler::parallel_transaction_root(txs))
                            }
                            None => {
                                let txs: &[reth_primitives_traits::Recovered<TransactionSigned>] = &builder.transactions;
                                scope.spawn(move || crate::assembler::parallel_transaction_root_recovered(txs))
                            }
                        });
                        let db = builder.executor.evm_mut().db_mut();
                        let at = std::time::Instant::now();
                        let graft = match staged {
                            Some(staged) => crate::parallel_transfer::install_staged(db, staged, keep_cache),
                            None => crate::parallel_transfer::graft_bundles_folded(
                                db,
                                bundles,
                                beneficiary,
                                keep_cache,
                                crate::parallel_transfer::build_graft_fold(),
                                graft_target.take(),
                            ),
                        };
                        graft_ms = at.elapsed().as_millis() as u64;
                        (
                            graft,
                            root.map(|job| job.join().expect("the transactions root job does not panic")),
                            receipts_job.map(|job| job.join()),
                        )
                    });
                    par_graft_ms = graft_ms;
                    early_transactions_root = early_root;
                    if let (Some(receipts), Some((_, tx_gas))) = (receipts, receipts_behind.take()) {
                        let receipts = receipts.map_err(|_| {
                            failed_after_seal(
                                sealed_ahead_id,
                                PayloadBuilderError::other(std::io::Error::other("the receipts job behind the seal panicked")),
                            )
                        })?;
                        direct_receipts = Some((receipts, tx_gas));
                        // The slots' 77 MB are freed on the pool, off this thread.
                        let slots = std::mem::take(&mut run.slots);
                        crate::parallel_transfer::build_pool().spawn(move || drop(slots));
                    }
                    let graft = graft.map_err(|err| failed_after_seal(sealed_ahead_id, PayloadBuilderError::other(err)))?;
                    // Zero on `install_staged`'s streamed graft
                    // (`N42_GRAFT_STREAM=1`) and on `GraftFold::Indexed`/
                    // `IndexedRanges`: only the default in-place fold
                    // (`graft_bundles_direct`) fills these.
                    par_graft_base_ms = graft.direct_base_ms;
                    par_graft_reserve_ms = graft.direct_reserve_ms;
                    par_graft_insert_ms = graft.direct_insert_ms;
                    par_graft_reverts_ms = graft.direct_reverts_ms;
                    par_graft_other_ms = graft.direct_other_ms;
                    let db = builder.executor.evm_mut().db_mut();
                    if !keep_cache {
                        if let Some(withdrawals) = attributes.withdrawals.as_ref() {
                            for withdrawal in withdrawals {
                                let grafted = db
                                    .bundle_state
                                    .state
                                    .get(&withdrawal.address)
                                    .and_then(|account| account.info.clone());
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
                    par_fold_ms = fold_at.elapsed().saturating_sub(seal_took).as_millis() as u64;
                    par_txs = tx_count;
                    par_groups = run.phases.groups;
                    par_batches = run.phases.batches;
                    par_part_ms = run.phases.partition_ms;
                    par_exec_ms = run.phases.groups_ms;
                    par_transfer_timers = run.phases.transfer_timers;
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
    let no_seal_why = if early_seal.is_none() {
        // The reth payload service's own path (`try_build`) asks for no
        // early seal; that is the first build of a tenure, not a defect.
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
            let state_ready_ms = finish_at.elapsed().as_millis() as u64;
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
            if qmdb_state.root_of(&parent_sealed).is_none() {
                if let Some(built) = parent_built {
                    let _ = crate::built_executions::wait_for(built, crate::built_executions::Stage::Complete);
                    if qmdb_state.root_of(&parent_sealed).is_none() {
                        crate::chain_alias::rename(&qmdb_state, built, parent_sealed)
                            .map_err(PayloadBuilderError::other)?;
                    }
                }
            }
            let prague = chain_spec.is_prague_active_at_timestamp(attributes.timestamp);
            let roots_at = std::time::Instant::now();
            let bundle_ref = &execution_output.state;
            // The state provider is `Send` but not `Sync`: the hashed
            // post-state stays on this thread while the root and the
            // receipts run beside it.
            let (hashed_state, prepared, (own_receipts_root, own_logs_bloom)) = std::thread::scope(|scope| {
                let receipts = &execution_result.receipts;
                let qmdb_job = &qmdb_state;
                let root = scope.spawn(move || {
                    let ops = n42_qmdb_reth::sorted_operations_from_execution(bundle_ref, prague);
                    qmdb_job.compute_operations(parent_sealed, ops)
                });
                let receipts = scope.spawn(move || crate::hotstuff_consensus::gov5_receipt_root_bloom(receipts));
                // `N42_HASHED_TABLES=off` (stage 6c): the tables this post-state is written to are
                // not written, and QMDB answers the reads they served.
                let hashed = if n42_qmdb_reth::n42_state::hashed_tables_off() {
                    Ok(Default::default())
                } else {
                    state_provider.hashed_post_state(bundle_ref)
                };
                let prepared = root.join().expect("the QMDB root job does not panic");
                let roots = receipts.join().expect("the receipts root job does not panic");
                (hashed, prepared, roots)
            });
            let hashed_state = hashed_state.map_err(PayloadBuilderError::other)?;
            let prepared = prepared.map_err(PayloadBuilderError::other)?;
            let own_state_root = prepared.root;
            qmdb_state.insert(block_hash, block_number, prepared).map_err(PayloadBuilderError::other)?;
            let roots_ms = roots_at.elapsed().as_millis() as u64;
            crate::executed_fields::remember(
                block_hash,
                crate::executed_fields::ExecutedFields {
                    state_root: own_state_root,
                    receipts_root: own_receipts_root,
                    logs_bloom: own_logs_bloom,
                    gas_used: execution_result.gas_used,
                },
            );
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
            if tx_count >= 1000 {
                let (queued, usable, parked) = queue_depth();
                // `N42_READ_DEPTH_COUNTS=1`: how many of this block's account
                // reads the parent's overlay answered at each depth of its own
                // executed-block stack versus falling through to the
                // historical provider (plan v6 6.4, `crate::direct_build::read_depth`).
                let read_depth = crate::direct_build::read_depth::snapshot();
                let overlay_depth = crate::direct_build::read_depth::overlay_depth();
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
                    graft_base_ms = par_graft_base_ms,
                    graft_reserve_ms = par_graft_reserve_ms,
                    graft_insert_ms = par_graft_insert_ms,
                    graft_reverts_ms = par_graft_reverts_ms,
                    graft_other_ms = par_graft_other_ms,
                    // `N42_SEAL_AT_EXEC=1` (plan v6 G2): sealed at the parallel
                    // step's end with the fold behind the proposal; the
                    // transactions root computed over the pulled set beside
                    // the execution was the one sealed, and how long the
                    // step's end waited for it.
                    seal_at_exec = seal_at_exec_used,
                    tx_root_ahead,
                    tx_root_wait_ms,
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
    // Receipts built for an early seal belong to its finish; this block's
    // executor committed none of those transactions, so it must not go on.
    if direct_receipts.is_some() {
        return Err(PayloadBuilderError::other(std::io::Error::other(
            "receipts were built for an early seal that did not happen",
        )));
    }

    loop {
        // Once the block cannot fit even the smallest transaction there is
        // nothing left to take: every further candidate would only be
        // refused, one refusal per queued sender -- thousands of them at the
        // end of every full block (round 37). Checked before taking, so that
        // nothing is taken from the queue and left neither built nor returned.
        if block_gas_limit.saturating_sub(cumulative_gas_used) < MIN_TRANSACTION_GAS {
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
                match puller.batches.recv() {
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
                builder.finish(&state_provider, Some((B256::ZERO, TrieUpdates::default())))?;
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
            let outcome = builder.finish(&state_provider, None)?;
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
    header.transactions_root = block.header().transactions_root;
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
    batches: std::sync::mpsc::Receiver<Vec<Arc<reth_transaction_pool::ValidPoolTransaction<T>>>>,
    refusals: std::sync::mpsc::Sender<Refusal<T>>,
    done: Arc<std::sync::atomic::AtomicBool>,
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
        if let Err(err) = spawned {
            warn!(target: "payload_builder", %err, "could not start the pool puller; the build has no transactions");
        }
        Self { batches, refusals, done }
    }

    fn refuse(&self, refusal: Refusal<T>) {
        // A puller that already ended has nothing to refuse.
        let _ = self.refusals.send(refusal);
    }
}

impl<T: reth_transaction_pool::PoolTransaction> Drop for Puller<T> {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
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

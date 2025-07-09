//! Ethereum Node types config.

//pub use crate::{payload::EthereumPayloadBuilder, EthereumEngineValidator};
//use crate::{EthEngineTypes, EthEvmConfig};
//use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};
use reth_node_ethereum::node::{EthereumAddOns, EthereumConsensusBuilder};
pub use reth_node_ethereum::{payload::EthereumPayloadBuilder, EthereumEngineValidator};
use reth_node_ethereum::EthEvmConfig;
use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_consensus::{ConsensusError, FullConsensus};
//use reth_ethereum_consensus::EthBeaconConsensus;
use crate::consensus::{N42ConsensusBuilder};
use crate::network::{N42NetworkBuilder, N42NetworkPrimitives};
//use crate::{N42EngineTypes, N42NodeAddOns, N42PayloadServiceBuilder};
use crate::{N42PayloadBuilderWrapper, N42PayloadServiceBuilder};
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_ethereum_primitives::{EthPrimitives, PooledTransaction, TransactionSigned};
use reth_evm::{ConfigureEvm, EvmFactory, EvmFactoryFor, NextBlockEnvAttributes};
use reth_network::{EthNetworkPrimitives, NetworkHandle, PeersInfo};
use reth_node_api::{AddOnsContext, EngineValidator, FullNodeComponents, NodeAddOns, NodePrimitives, PayloadValidator, TxTy};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NetworkBuilder, PoolBuilder,
    },
    node::{FullNodeTypes, NodeTypes},
    rpc::{
        EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder, EthApiCtx, RethRpcAddOns,
        RpcAddOns, RpcHandle,
    },
    BuilderContext, DebugNode, Node, NodeAdapter, NodeComponentsBuilder, PayloadBuilderConfig,
    PayloadTypes,
};
use reth_provider::{providers::ProviderFactoryBuilder, CanonStateSubscriptions, EthStorage};
use reth_rpc::{eth::core::EthApiFor, ValidationApi};
use reth_rpc_api::{eth::FullEthApiServer, servers::BlockSubmissionValidationApiServer};
use reth_rpc_builder::config::RethRpcServerConfig;
use reth_rpc_eth_types::{error::FromEvmError, EthApiError};
use reth_rpc_server_types::RethRpcModule;
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::{DiskFileBlobStore, DiskFileBlobStoreConfig},
    EthTransactionPool, PoolTransaction, TransactionPool, TransactionValidationTaskExecutor,
};
use reth_trie_db::MerklePatriciaTrie;
use revm::context::TxEnv;
use std::{default::Default, sync::Arc, time::SystemTime};
use alloy_rpc_types::engine::ExecutionData;
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_payload_primitives::{validate_version_specific_fields, EngineApiMessageVersion, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes};
use reth_primitives_traits::{Block, RecoveredBlock};
use crate::block::N42Block;
use crate::evm::N42EvmConfig;
use crate::payload::{N42BuiltPayload, N42PayloadTypes};

/// Type configuration for a regular Ethereum node.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42Node;

impl N42Node {
    /// Returns a [`ComponentsBuilder`] configured for a regular Ethereum node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder<N42PayloadBuilderWrapper>,
        N42NetworkBuilder,
        N42ExecutorBuilder,
        N42ConsensusBuilder,
    >
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = N42Primitives>>,
        <Node::Types as NodeTypes>::Payload: PayloadTypes<
            BuiltPayload = N42BuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .executor(N42ExecutorBuilder::default())
            .consensus(N42ConsensusBuilder::default())
            .payload(N42PayloadServiceBuilder::default())
            .network(N42NetworkBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
}

impl NodeTypes for N42Node {
    type Primitives = N42Primitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = EthStorage;
    type Payload = N42PayloadTypes;
}

/// Helper struct that specifies the n42
/// [`NodePrimitives`](reth_primitives_traits::NodePrimitives) types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct N42Primitives;

impl NodePrimitives for N42Primitives {
    type Block = reth_ethereum_primitives::Block;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = reth_ethereum_primitives::BlockBody;
    type SignedTx = reth_ethereum_primitives::TransactionSigned;
    type Receipt = reth_ethereum_primitives::Receipt;
}

/// Builds [`EthApi`](reth_rpc::EthApi) for Ethereum.
#[derive(Debug, Default)]
pub struct N42EthApiBuilder;

impl<N> EthApiBuilder<N> for N42EthApiBuilder
where
    N: FullNodeComponents,
    EthApiFor<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type EthApi = EthApiFor<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let api = reth_rpc::EthApiBuilder::new(
            ctx.components.provider().clone(),
            ctx.components.pool().clone(),
            ctx.components.network().clone(),
            ctx.components.evm_config().clone(),
        )
        .eth_cache(ctx.cache)
        .task_spawner(ctx.components.task_executor().clone())
        .gas_cap(ctx.config.rpc_gas_cap.into())
        .max_simulate_blocks(ctx.config.rpc_max_simulate_blocks)
        .eth_proof_window(ctx.config.eth_proof_window)
        .fee_history_cache_config(ctx.config.fee_history_cache)
        .proof_permits(ctx.config.proof_permits)
        .gas_oracle_config(ctx.config.gas_oracle)
        .build();
        Ok(api)
    }
}

/// Add-ons w.r.t. l1 ethereum.
#[derive(Debug)]
pub struct N42AddOns<N: FullNodeComponents>
where
    EthApiFor<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    inner: RpcAddOns<N, N42EthApiBuilder, N42EngineValidatorBuilder>,
}

impl<N: FullNodeComponents> Default for N42AddOns<N>
where
    EthApiFor<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    fn default() -> Self {
        Self { inner: Default::default() }
    }
}

impl<N> NodeAddOns<N> for N42AddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = N42Primitives,
            Payload = N42PayloadTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type Handle = RpcHandle<N, EthApiFor<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        let validation_api = ValidationApi::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            ctx.node.evm_config().clone(),
            ctx.config.rpc.flashbots_config(),
            Box::new(ctx.node.task_executor().clone()),
            Arc::new(N42EngineValidator::new(ctx.config.chain.clone())),
        );

        self.inner
            .launch_add_ons_with(ctx, move |modules, _, _| {
                modules.merge_if_module_configured(
                    RethRpcModule::Flashbots,
                    validation_api.into_rpc(),
                )?;

                Ok(())
            })
            .await
    }
}

impl<N> RethRpcAddOns<N> for N42AddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = N42Primitives,
            Payload = N42PayloadTypes,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type EthApi = EthApiFor<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N> EngineValidatorAddOn<N> for N42AddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec = ChainSpec,
            Primitives = N42Primitives,
            Payload = N42PayloadTypes,
        >,
    >,
    EthApiFor<N>: FullEthApiServer<Provider = N::Provider, Pool = N::Pool>,
{
    type Validator = N42EngineValidator;

    async fn engine_validator(&self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        N42EngineValidatorBuilder::default().build(ctx).await
    }
}

impl<N> Node<N> for N42Node
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder<N42PayloadBuilderWrapper>,
        N42NetworkBuilder,
        N42ExecutorBuilder,
        N42ConsensusBuilder,
    >;

    type AddOns = N42AddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        N42AddOns::default()
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for N42Node {
    type RpcBlock = alloy_rpc_types_eth::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_ethereum_primitives::Block {
        let alloy_rpc_types_eth::Block { header, transactions, withdrawals, .. } = rpc_block;
        reth_ethereum_primitives::Block {
            header: header.inner,
            body: reth_ethereum_primitives::BlockBody {
                transactions: transactions
                    .into_transactions()
                    .map(|tx| tx.inner.into_inner().into())
                    .collect(),
                ommers: Default::default(),
                withdrawals,
            },
        }
    }
}

/// A regular ethereum evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42ExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for N42ExecutorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Primitives = N42Primitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = N42EvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let evm_config = N42EvmConfig::new(ctx.chain_spec())
            .with_extra_data(ctx.payload_builder_config().extra_data_bytes());
        Ok(evm_config)
    }
}

/// A basic ethereum transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct EthereumPoolBuilder {
    // TODO add options for txpool args
}

impl<Types, Node> PoolBuilder<Node> for EthereumPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = TransactionSigned>,
    >,
    Node: FullNodeTypes<Types = Types>,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let data_dir = ctx.config().datadir();
        let pool_config = ctx.pool_config();

        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            blob_cache_size
        } else {
            // get the current blob params for the current timestamp, fallback to default Cancun
            // params
            let current_timestamp =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or_else(BlobParams::cancun);

            // Derive the blob cache size from the target blob count, to auto scale it by
            // multiplying it with the slot count for 2 epochs: 384 for pectra
            (blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32
        };

        let custom_config =
            DiskFileBlobStoreConfig::default().with_max_cached_entries(blob_cache_size);

        let blob_store = DiskFileBlobStore::open(data_dir.blobstore(), custom_config)?;
        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .with_head_timestamp(ctx.head().timestamp)
            .kzg_settings(ctx.kzg_settings()?)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let transaction_pool =
            reth_transaction_pool::Pool::eth_pool(validator, blob_store, pool_config);
        info!(target: "reth::cli", "Transaction pool initialized");

        // spawn txpool maintenance task
        {
            let pool = transaction_pool.clone();
            let chain_events = ctx.provider().canonical_state_stream();
            let client = ctx.provider().clone();
            // Only spawn backup task if not disabled
            if !ctx.config().txpool.disable_transactions_backup {
                // Use configured backup path or default to data dir
                let transactions_path = ctx
                    .config()
                    .txpool
                    .transactions_backup_path
                    .clone()
                    .unwrap_or_else(|| data_dir.txpool_transactions());

                let transactions_backup_config =
                    reth_transaction_pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(transactions_path);

                ctx.task_executor().spawn_critical_with_graceful_shutdown_signal(
                    "local transactions backup task",
                    |shutdown| {
                        reth_transaction_pool::maintain::backup_local_transactions_task(
                            shutdown,
                            pool.clone(),
                            transactions_backup_config,
                        )
                    },
                );
            }

            // spawn the maintenance task
            ctx.task_executor().spawn_critical(
                "txpool maintenance task",
                reth_transaction_pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_transaction_pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: transaction_pool.config().max_queued_lifetime,
                        no_local_exemptions: transaction_pool
                            .config()
                            .local_transactions_config
                            .no_exemptions,
                        ..Default::default()
                    },
                ),
            );
            debug!(target: "reth::cli", "Spawned txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}

/// Builder for [`EthereumEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42EngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for N42EngineValidatorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Payload = N42PayloadTypes, Primitives = N42Primitives>,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = N42EngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(N42EngineValidator::new(ctx.config.chain.clone()))
    }
}


/// Custom engine validator
#[derive(Debug, Clone)]
pub struct N42EngineValidator {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl N42EngineValidator {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthereumExecutionPayloadValidator::new(chain_spec) }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl PayloadValidator for N42EngineValidator {
    type Block = reth_ethereum_primitives::Block;
    type ExecutionData = ExecutionData;

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block = self.inner.ensure_well_formed_payload(payload)?;
        sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }
}

impl<T> EngineValidator<T> for N42EngineValidator
where
    T: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Self::ExecutionData, T::PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &T::PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Self::ExecutionData, T::PayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )?;
        Ok(())
    }
}
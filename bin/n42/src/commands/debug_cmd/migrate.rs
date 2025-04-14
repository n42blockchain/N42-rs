use sled::{Db, IVec};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::BlockTransactionsKind;
use eyre::Result;
use alloy_rpc_types::Block;
use reth_provider::DatabaseProviderRW;
use alloy_primitives::{Address, BlockHash, BlockNumber, TxHash, TxNumber, B256};
use serde_json;

use reth_node_core::args::NetworkArgs;
use clap::Parser;
use eyre::Context;
use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_beacon_consensus::{hooks::EngineHooks, BeaconConsensusEngine, EthBeaconConsensus};
use reth_blockchain_tree::{
    BlockchainTree, BlockchainTreeConfig, ShareableBlockchainTree, TreeExternals,
};
use reth_chainspec::ChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_runner::CliContext;
use reth_cli_util::get_secret_key;
use reth_config::Config;
use reth_consensus::Consensus;
use reth_db::DatabaseEnv;
use reth_engine_util::engine_store::{EngineMessageStore, StoredEngineApiMessage};
use reth_fs_util as fs;
use reth_network::{BlockDownloaderProvider, NetworkHandle};
use reth_network_api::NetworkInfo;
use reth_node_api::{
    EngineApiMessageVersion, NodeTypesWithDB, NodeTypesWithDBAdapter, NodeTypesWithEngine,
};
use reth_node_ethereum::{EthEngineTypes, EthEvmConfig, EthExecutorProvider};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_provider::{
    providers::BlockchainProvider, CanonStateSubscriptions, ChainSpecProvider, ProviderFactory,
};
use reth_prune::PruneModes;
use reth_stages::Pipeline;
use reth_static_file::StaticFileProducer;
use reth_tasks::TaskExecutor;
use reth_transaction_pool::noop::NoopTransactionPool;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tracing::*;

#[derive(Debug, Parser)]
pub struct Command<C: ChainSpecParser> {
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    #[command(flatten)]
    network: NetworkArgs,

    /// The rpc to read ethereum blocks from.
    #[arg(long = "from-rpc", value_name = "END_POINT")]
    from_rpc: String,

    /// The database to write ethereum blocks to.
    #[arg(long = "to-db-path", value_name = "DB_PATH")]
    to_db_path: String,

    /// The number of milliseconds between Engine API messages.
    #[arg(long = "interval", default_value_t = 1_000)]
    interval: u64,
}

impl<C: ChainSpecParser<ChainSpec = ChainSpec>> Command<C> {
    async fn build_network<N: NodeTypesWithDB<ChainSpec = C::ChainSpec>>(
        &self,
        config: &Config,
        task_executor: TaskExecutor,
        provider_factory: ProviderFactory<N>,
        network_secret_path: PathBuf,
        default_peers_path: PathBuf,
    ) -> eyre::Result<NetworkHandle> {
        let secret_key = get_secret_key(&network_secret_path)?;
        let network = self
            .network
            .network_config(config, provider_factory.chain_spec(), secret_key, default_peers_path)
            .with_task_executor(Box::new(task_executor))
            .build(provider_factory)
            .start_network()
            .await?;
        info!(target: "reth::cli", peer_id = %network.peer_id(), local_addr = %network.local_addr(), "Connected to P2P network");
        debug!(target: "reth::cli", peer_id = ?network.peer_id(), "Full peer ID");
        Ok(network)
    }

    /// Execute `debug migrate` command
    pub async fn execute<
        N: NodeTypesWithEngine<Engine = EthEngineTypes, ChainSpec = C::ChainSpec>,
    >(
        self,
        ctx: CliContext,
    ) -> eyre::Result<()> {
        let Environment { provider_factory, config, data_dir } =
            self.env.init::<N>(AccessRights::RW)?;

        let consensus: Arc<dyn Consensus> =
            Arc::new(EthBeaconConsensus::new(provider_factory.chain_spec()));

        let executor = EthExecutorProvider::ethereum(provider_factory.chain_spec());
        let block_provider = provider_factory.provider_rw()?;

        let rpc_url = self.from_rpc.parse()?;
        let rpc_provider = ProviderBuilder::new().on_http(rpc_url);

        // Get latest block number.
        let latest_block_number = rpc_provider.get_block_number().await?;
        //let latest_block_number = 20;
        let to_db_path: String = self.to_db_path.parse()?;
        let db: Db = sled::open(to_db_path)?;
        let latest_local_block_number: u64 = db.iter().count() as u64;

        info!(target: "reth::cli", latest_block_number, latest_local_block_number);
        drop(block_provider);
        let mut block_number = latest_local_block_number;
        while latest_block_number > block_number {
            let block_provider = provider_factory.provider_rw()?;
            if block_number > 0 && !db.contains_key(block_number.to_be_bytes())? {
                eyre::bail!("expecting consecutive blocks, block {:?} not found, stop", block_number);
            }
            block_number += 1;
            if let Some(block) = rpc_provider.get_block(block_number.into(), BlockTransactionsKind::Full).await? {
                db.insert(block_number.to_be_bytes(), serde_json::to_vec(&block)?)?;
                info!(target: "reth::cli", "Latest committed block number: {block_number}");
            } else {
                break;
            }
        }
        let new_latest_local_block_number = db.iter().count() as u64;
        block_number = latest_local_block_number;
        while new_latest_local_block_number > block_number {
            block_number += 1;
            let value = db.get(block_number.to_be_bytes())?.unwrap();
            let block: Block = serde_json::from_slice(&value)?;
            //info!(target: "reth::cli", ?block, "Read block");
            if block_number != block.header.number {
                info!(target: "reth::cli",  "block number mismatch, expected {:?}, got {:?}", block_number, block.header.number);
                eyre::bail!("block number mismatch, expected {:?}, got {:?}", block_number, block.header.number);
            }
        }

        // Configure blockchain tree
        let tree_externals =
            TreeExternals::new(provider_factory.clone(), Arc::clone(&consensus), executor);
        let tree = BlockchainTree::new(tree_externals, BlockchainTreeConfig::default())?;
        let blockchain_tree = Arc::new(ShareableBlockchainTree::new(tree));

        // Set up the blockchain provider
        let blockchain_db = BlockchainProvider::new(provider_factory.clone(), blockchain_tree)?;

        // Set up network
        let network_secret_path =
            self.network.p2p_secret_key.clone().unwrap_or_else(|| data_dir.p2p_secret());
        let network = self
            .build_network(
                &config,
                ctx.task_executor.clone(),
                provider_factory.clone(),
                network_secret_path,
                data_dir.known_peers(),
            )
            .await?;

        // Set up payload builder
        let payload_builder = reth_ethereum_payload_builder::EthereumPayloadBuilder::new(
            EthEvmConfig::new(provider_factory.chain_spec()),
        );

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            blockchain_db.clone(),
            NoopTransactionPool::default(),
            ctx.task_executor.clone(),
            BasicPayloadJobGeneratorConfig::default(),
            payload_builder,
        );

        let (payload_service, payload_builder): (_, PayloadBuilderHandle<EthEngineTypes>) =
            PayloadBuilderService::new(payload_generator, blockchain_db.canonical_state_stream());

        ctx.task_executor.spawn_critical("payload builder service", payload_service);

        // Configure the consensus engine
        let network_client = network.fetch_client().await?;
        let (beacon_consensus_engine, beacon_engine_handle) = BeaconConsensusEngine::new(
            network_client,
            Pipeline::<NodeTypesWithDBAdapter<N, Arc<DatabaseEnv>>>::builder().build(
                provider_factory.clone(),
                StaticFileProducer::new(provider_factory.clone(), PruneModes::none()),
            ),
            blockchain_db.clone(),
            Box::new(ctx.task_executor.clone()),
            Box::new(network),
            None,
            payload_builder,
            None,
            u64::MAX,
            EngineHooks::new(),
        )?;
        info!(target: "reth::cli", "Consensus engine initialized");

        // Run consensus engine to completion
        let (tx, rx) = oneshot::channel();
        info!(target: "reth::cli", "Starting consensus engine");
        ctx.task_executor.spawn_critical_blocking("consensus engine", async move {
            let res = beacon_consensus_engine.await;
            let _ = tx.send(res);
        });

        info!(target: "reth::cli", "Finished replaying engine API messages");

        match rx.await? {
            Ok(()) => info!("Beacon consensus engine exited successfully"),
            Err(error) => {
                error!(target: "reth::cli", %error, "Beacon consensus engine exited with an error")
            }
        };

        Ok(())
    }

}

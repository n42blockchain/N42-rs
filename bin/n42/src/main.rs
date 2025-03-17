#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use std::collections::HashMap;

use clap::{Args, Parser};
use n42::cli::Cli;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::{engine_tree_config::{
    TreeConfig, DEFAULT_MEMORY_BLOCK_BUFFER_TARGET, DEFAULT_PERSISTENCE_THRESHOLD,
}, DefaultNodeLauncher, EngineNodeLauncher};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_provider::providers::BlockchainProvider2;
use reth_tracing::tracing::warn;
use tracing::info;

use n42_engine_types::{N42Node, N42NodeAddOns};

use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::{error::INVALID_PARAMS_CODE, ErrorObject}};
use alloy_primitives::Address;
use reth_consensus::Consensus;
use n42_primitives::Snapshot;
use reth_provider::HeaderProvider;

use n42_engine_types::minedblock::{MinedblockExt,MinedblockExtApiServer};

/// Parameters for configuring the engine
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "Engine")]
pub struct EngineArgs {
    /// Enable the experimental engine features on reth binary
    ///
    /// DEPRECATED: experimental engine is default now, use --engine.legacy to enable the legacy
    /// functionality
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,

    /// Enable the legacy engine on reth binary
    #[arg(long = "engine.legacy", default_value = "false")]
    pub legacy: bool,

    /// Configure persistence threshold for engine experimental.
    #[arg(long = "engine.persistence-threshold", conflicts_with = "legacy", default_value_t = DEFAULT_PERSISTENCE_THRESHOLD)]
    pub persistence_threshold: u64,

    /// Configure the target number of blocks to keep in memory.
    #[arg(long = "engine.memory-block-buffer-target", conflicts_with = "legacy", default_value_t = DEFAULT_MEMORY_BLOCK_BUFFER_TARGET)]
    pub memory_block_buffer_target: u64,
}

impl Default for EngineArgs {
    fn default() -> Self {
        Self {
            experimental: false,
            legacy: false,
            persistence_threshold: DEFAULT_PERSISTENCE_THRESHOLD,
            memory_block_buffer_target: DEFAULT_MEMORY_BLOCK_BUFFER_TARGET,
        }
    }
}

/// trait interface for a custom rpc namespace: `consensus`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "consensusExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "consensusExt"))]
pub trait ConsensusExtApi {
    /// Propose in the clique consensus.
    #[method(name = "propose")]
    fn propose(&self,
        address: Address,
        auth: bool,
        ) -> RpcResult<()>;

    /// Discard in the clique consensus.
    #[method(name = "discard")]
    fn discard(
        &self,
        address: Address,
        ) -> RpcResult<()>;

    /// GetSnapshot in the clique consensus.
    #[method(name = "get_snapshot")]
    fn get_snapshot(
        &self,
        number: u64,
        ) -> RpcResult<Snapshot>;

    /// Proposals in the clique consensus.
    #[method(name = "proposals")]
    fn proposals(
        &self,
        ) -> RpcResult<HashMap<Address, bool>>;
}

/// The type that implements the `consensus` rpc namespace trait
pub struct ConsensusExt<Cons, Provider> {
    consensus: Cons,
    provider: Provider,
}

impl<Cons, Provider> ConsensusExtApiServer for ConsensusExt<Cons, Provider>
where
    Cons: Consensus + Clone + 'static,
    Provider: HeaderProvider + Clone + 'static,
{
    fn propose(&self,
        address: Address,
        auth: bool,
        ) -> RpcResult<()> {
        Ok(self.consensus.propose(address, auth).unwrap_or_default())
    }

    fn discard(&self,
        address: Address,
        ) -> RpcResult<()> {
        Ok(self.consensus.discard(address).unwrap_or_default())
    }

    fn get_snapshot(&self,
        number: u64,
        ) -> RpcResult<Snapshot> {
        let hash = self.provider.header_by_number(number).unwrap_or_default().unwrap_or_default().hash_slow();
        self.consensus.snapshot(number, hash, None).map_err(|err| ErrorObject::owned(INVALID_PARAMS_CODE, err.to_string(), Option::<()>::None))
    }

    fn proposals(
        &self,
        ) -> RpcResult<HashMap<Address, bool>> {
        Ok(self.consensus.proposals().unwrap_or_default())
    }
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) =
        Cli::<EthereumChainSpecParser, EngineArgs>::parse().run(|builder, engine_args| async move {
            if engine_args.experimental {
                warn!(target: "reth::cli", "Experimental engine is default now, and the --engine.experimental flag is deprecated. To enable the legacy functionality, use --engine.legacy.");
            }

            let use_legacy_engine = engine_args.legacy;
            match use_legacy_engine {
                false => {
                    let engine_tree_config = TreeConfig::default()
                        .with_persistence_threshold(engine_args.persistence_threshold)
                        .with_memory_block_buffer_target(engine_args.memory_block_buffer_target);
                    let handle = builder
                        .with_types_and_provider::<N42Node, BlockchainProvider2<_>>()
                        .with_components(N42Node::components())
                        .with_add_ons(N42NodeAddOns::default())
                        .extend_rpc_modules(|ctx| {

                            let consensus = ctx.consensus().clone();
                            let provider = ctx.provider().clone();

                            let ext = ConsensusExt { consensus, provider };

                            // now we merge our extension namespace into all configured transports
                            ctx.auth_module.merge_auth_methods(ext.into_rpc())?;

                            // init minedblock rpc extension
                            let minedblock_ext=MinedblockExt::instance();
                            ctx.modules.merge_ws(minedblock_ext.into_rpc())?;

                            println!("consensus rpc extension enabled");

                            Ok(())
                        })
                        .launch_with_fn(|builder| {
                            let launcher = EngineNodeLauncher::new(
                                builder.task_executor().clone(),
                                builder.config().datadir(),
                                engine_tree_config,
                            );
                            builder.launch_with(launcher)
                        })
                        .await?;
                    handle.node_exit_future.await
                }
                true => {
                    info!(target: "reth::cli", "Running with legacy engine");
                    let handle = builder.launch_node(N42Node::default()).await?;
                    handle.node_exit_future.await
                }
            }
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use jsonrpsee::{http_client::HttpClientBuilder, server::ServerBuilder};
    use reth_consensus::noop::NoopConsensus;
    use reth_provider::test_utils::NoopProvider;

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_parse_engine_args() {
        let default_args = EngineArgs::default();
        let args = CommandParser::<EngineArgs>::parse_from(["reth"]).args;
        assert_eq!(args, default_args);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_propose_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::propose(&client, Address::random(), true).await.unwrap();
        assert_eq!(result, ());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_discard_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::discard(&client, Address::random()).await.unwrap();
        assert_eq!(result, ());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_get_snapshot_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::get_snapshot(&client, 0).await.unwrap();
        assert_eq!(result, Snapshot::default());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_call_proposals_http() {
        let server_addr = start_server().await;
        let uri = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(&uri).unwrap();
        let result = ConsensusExtApiClient::proposals(&client).await.unwrap();
        assert_eq!(result, HashMap::default());
    }

    async fn start_server() -> std::net::SocketAddr {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let consensus = NoopConsensus::default();
        let provider = NoopProvider::default();
        let api = ConsensusExt { consensus, provider };
        let server_handle = server.start(api.into_rpc());

        tokio::spawn(server_handle.stopped());

        addr
    }
}

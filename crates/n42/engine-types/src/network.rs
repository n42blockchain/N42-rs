use reth_network::{NetworkHandle, NetworkManager, PeersInfo};
use reth_network::config::NetworkMode;
use reth_network::import::ProofOfStakeBlockImport;
use reth_node_api::FullNodeTypes;
use reth_transaction_pool::TransactionPool;
use tracing::info;
use reth_chainspec::ChainSpec;
use reth_node_builder::components::NetworkBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};

/// A basic ethereum payload service.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42NetworkBuilder {
    // TODO add closure to modify network
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for N42NetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
    Pool: TransactionPool + Unpin + 'static,
{
    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<NetworkHandle> {
        let network_config_builder = ctx.network_config_builder()?.network_mode(NetworkMode::Work);
        let network_config = ctx.build_network_config(network_config_builder.block_import(Box::<ProofOfStakeBlockImport>::default()));
        let network =NetworkManager::builder(network_config).await?;

        let handle = ctx.start_network(network, pool);

        info!(target: "n42::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}
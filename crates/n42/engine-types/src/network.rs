use reth_chainspec::{ChainSpec, EthChainSpec, Hardforks};
use reth_eth_wire_types::BasicNetworkPrimitives;
use reth_ethereum_primitives::EthPrimitives;
use reth_network::config::NetworkMode;
use reth_network::{NetworkHandle, NetworkManager, PeersInfo};
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeAddOns, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{NetworkBuilder, PoolBuilder},
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    EthTransactionPool, PoolPooledTx, PoolTransaction, TransactionPool,
    TransactionValidationTaskExecutor,
};

/// A basic N42 network builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42NetworkBuilder {
    // TODO add closure to modify network
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for N42NetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let network_config_builder = ctx
            .network_config_builder()?
            .network_mode(NetworkMode::Work);
        let network_config = ctx.build_network_config(network_config_builder);
        let network = NetworkManager::builder(network_config).await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "n42::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}

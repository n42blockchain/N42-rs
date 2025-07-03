use reth_network::config::NetworkMode;
use reth_network::{EthNetworkPrimitives, NetworkManager, NetworkHandle, PeersInfo, NetworkPrimitives};
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeAddOns, TxTy};
use reth_ethereum_primitives::{EthPrimitives, PooledTransaction};
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_node_builder::{
    components::{
        NetworkBuilder, PoolBuilder,
    },
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_transaction_pool::{
    EthTransactionPool, PoolTransaction, TransactionPool, TransactionValidationTaskExecutor,
};
use reth_tracing::tracing::{debug, info};
use crate::node::N42Primitives;

/// A basic ethereum payload service.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42NetworkBuilder {
    // TODO add closure to modify network
}


/// Network primitive types used by N42 networks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct N42NetworkPrimitives;

impl NetworkPrimitives for N42NetworkPrimitives {
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = reth_ethereum_primitives::BlockBody;
    type Block = reth_ethereum_primitives::Block;
    type BroadcastedTransaction = reth_ethereum_primitives::TransactionSigned;
    type PooledTransaction = reth_ethereum_primitives::PooledTransaction;
    type Receipt = reth_ethereum_primitives::Receipt;
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for N42NetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = N42Primitives>>,
    Pool: TransactionPool<
            Transaction: PoolTransaction<Consensus = TxTy<Node::Types>, Pooled = PooledTransaction>,
        > + Unpin
        + 'static,
{
    type Network = NetworkHandle<N42NetworkPrimitives>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let network_config_builder = ctx.network_config_builder()?.network_mode(NetworkMode::Work);
        let network_config = ctx.build_network_config(network_config_builder);
        let network = NetworkManager::builder(network_config).await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "n42::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}

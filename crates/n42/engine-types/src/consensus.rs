use reth_consensus::{ConsensusError, FullConsensus};
use reth_ethereum_primitives::{EthPrimitives, PooledTransaction};
use std::sync::Arc;
use reth_node_api::FullNodeTypes;
use n42_clique::APos;
use reth_chainspec::ChainSpec;
use reth_node_builder::components::ConsensusBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};

/// A basic ethereum consensus builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42ConsensusBuilder {
    // TODO add closure to modify consensus
}

impl<Node> ConsensusBuilder<Node> for N42ConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type Consensus = Arc<dyn FullConsensus<EthPrimitives, Error = ConsensusError>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        //Ok(Arc::new(EthBeaconConsensus::new(ctx.chain_spec())))
            Ok(Arc::new(APos::new(ctx.provider().clone(), ctx.chain_spec(), ctx.config().dev.consensus_signer_private_key.map(|v|v.to_string()))))
    }
}


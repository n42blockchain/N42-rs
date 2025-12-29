use n42_clique::APos;
use n42_consensus_traits::SignerManager;
use reth_chainspec::ChainSpec;
use reth_consensus::{ConsensusError, FullConsensus};
use reth_ethereum_primitives::EthPrimitives;
use reth_node_api::FullNodeTypes;
use reth_node_builder::components::ConsensusBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};
use reth_provider::{BlockIdReader, BlockReaderIdExt, HeaderProvider};
use std::sync::Arc;

/// Combined trait for N42 consensus that includes both FullConsensus and SignerManager.
pub trait N42FullConsensus:
    FullConsensus<EthPrimitives, Error = ConsensusError> + SignerManager
{
}

// Blanket implementation for any type that implements both traits
impl<T> N42FullConsensus for T where
    T: FullConsensus<EthPrimitives, Error = ConsensusError> + SignerManager
{
}

/// A basic ethereum consensus builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42ConsensusBuilder {
    // TODO add closure to modify consensus
}

impl<Node> ConsensusBuilder<Node> for N42ConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type Consensus = Arc<
        APos<
            <Node as FullNodeTypes>::Provider,
            ChainSpec,
        >,
    >;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(APos::new(
            ctx.provider().clone(),
            ctx.chain_spec(),
            ctx.config().dev.consensus_signer_private_key.clone(),
        )))
    }
}

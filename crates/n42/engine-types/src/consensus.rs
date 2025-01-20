use std::sync::Arc;
use reth_node_api::FullNodeTypes;
use n42_clique::APos;
use reth_auto_seal_consensus::AutoSealConsensus;
use reth_chainspec::ChainSpec;
use reth_node_builder::components::ConsensusBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};

/// A n42 ethereum consensus builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42ConsensusBuilder {
    // TODO add closure to modify consensus
}

impl<Node> ConsensusBuilder<Node> for N42ConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
{
    type Consensus = Arc<dyn reth_consensus::Consensus>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        if ctx.is_dev() {
            Ok(Arc::new(AutoSealConsensus::new(ctx.chain_spec())))
        } else {
            Ok(Arc::new(APos::new(ctx.provider().clone(), ctx.chain_spec(), ctx.config().dev.consensus_signer_private_key.map(|v|v.to_string()))))
        }
    }
}

use reth::{
    api::PayloadTypes,
    builder::{
        components::{ComponentsBuilder},
        node::{NodeTypes, NodeTypesWithEngine},
        FullNodeTypes, Node, NodeAdapter, NodeComponentsBuilder,
    },
};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_node_api::{
    EngineTypes,
    FullNodeComponents, PayloadAttributes, PayloadBuilderAttributes,
};
use reth_node_ethereum::{
    node::{
        EthereumConsensusBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder,
        EthereumPoolBuilder,
    },
};
use reth_trie_db::MerklePatriciaTrie;
use crate::{N42EngineTypes, N42NodeAddOns, N42PayloadServiceBuilder};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct N42Node;

/// Configure the node types
impl NodeTypes for N42Node {
    type Primitives = ();
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
}

/// Configure the node types with the custom engine types
impl NodeTypesWithEngine for N42Node {
    type Engine = N42EngineTypes;
}

/// Implement the Node trait for the custom node
///
/// This provides a preset configuration for the node
impl<N> Node<N> for N42Node
where
    N: FullNodeTypes<Types: NodeTypesWithEngine<Engine =N42EngineTypes, ChainSpec = ChainSpec>>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = N42NodeAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
            .payload(N42PayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        N42NodeAddOns::default()
    }
}


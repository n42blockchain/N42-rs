use reth_node_builder::{components::{ComponentsBuilder}, node::{NodeTypes, NodeTypesWithEngine}, EngineTypes, FullNodeTypes, Node, NodeAdapter, NodeComponentsBuilder, NodeTypesWithDB};
use reth_payload_primitives::PayloadTypes;
use reth_payload_builder::EthBuiltPayload;
use reth_chainspec::ChainSpec;
use reth_node_ethereum::{node::{
    EthereumConsensusBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder,
    EthereumPoolBuilder,
}};
use reth_trie_db::MerklePatriciaTrie;
use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};
use crate::{N42EngineTypes, N42NodeAddOns, N42PayloadServiceBuilder};
use crate::consensus::N42ConsensusBuilder;
use crate::network::N42NetworkBuilder;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct N42Node;


impl N42Node {
    /// Returns a [`ComponentsBuilder`] configured for a regular Ethereum node.
    pub fn components<Node>() -> ComponentsBuilder<Node, EthereumPoolBuilder, N42PayloadServiceBuilder, N42NetworkBuilder, EthereumExecutorBuilder, N42ConsensusBuilder>
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
        <Node::Types as NodeTypesWithEngine>::Engine: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = N42PayloadAttributes,
            PayloadBuilderAttributes = N42PayloadBuilderAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .consensus(N42ConsensusBuilder::default())
            .payload(N42PayloadServiceBuilder::default())
            .network(N42NetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
    }
}

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
impl<Types, N> Node<N> for N42Node
where
    Types: NodeTypesWithDB + NodeTypesWithEngine<Engine = N42EngineTypes, ChainSpec = ChainSpec>,
    N: FullNodeTypes<Types = Types>
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder,
        N42NetworkBuilder,
        EthereumExecutorBuilder,
        N42ConsensusBuilder,
    >;
    type AddOns = N42NodeAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .consensus(N42ConsensusBuilder::default())
            .payload(N42PayloadServiceBuilder::default())
            .network(N42NetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        N42NodeAddOns::default()
    }
}


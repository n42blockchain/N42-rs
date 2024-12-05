//!
//! The [EngineTypes] trait can be implemented to configure the engine to work with custom types,
//! as long as those types implement certain traits.
//!
//! Custom payload attributes can be supported by implementing two main traits:
//!
//! [PayloadAttributes] can be implemented for payload attributes types that are used as
//! arguments to the `engine_forkchoiceUpdated` method. This type should be used to define and
//! _spawn_ payload jobs.
//!
//! [PayloadBuilderAttributes] can be implemented for payload attributes types that _describe_
//! running payload jobs.
//!
//! Once traits are implemented and custom types are defined, the [EngineTypes] trait can be
//! implemented:
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
            .payload(N42PayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        N42NodeAddOns::default()
    }
}


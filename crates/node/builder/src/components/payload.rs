//! Payload service component for the node builder.

use std::future::Future;

use reth_node_api::NodeTypesWithEngine;
use reth_payload_builder::PayloadBuilderHandle;
use reth_transaction_pool::TransactionPool;
use reth_consensus::Consensus;
use crate::{BuilderContext, FullNodeTypes};

/// A type that knows how to spawn the payload service.
pub trait PayloadServiceBuilder<Node: FullNodeTypes, Pool: TransactionPool, Cons: Consensus>: Send {
    /// Spawns the payload service and returns the handle to it.
    ///
    /// The [`BuilderContext`] is provided to allow access to the node's configuration.
    fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        consensus: Cons,
    ) -> impl Future<
        Output = eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypesWithEngine>::Engine>>,
    > + Send;
}

impl<Node, F, Fut, Pool, Cons> PayloadServiceBuilder<Node, Pool, Cons> for F
where
    Node: FullNodeTypes,
    Pool: TransactionPool,
    Cons: Consensus,
    F: Fn(&BuilderContext<Node>, Pool, Cons) -> Fut + Send,
    Fut: Future<
            Output = eyre::Result<
                PayloadBuilderHandle<<Node::Types as NodeTypesWithEngine>::Engine>,
            >,
        > + Send,
{
    fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        cons: Cons,
    ) -> impl Future<
        Output = eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypesWithEngine>::Engine>>,
    > + Send {
        self(ctx, pool, cons)
    }
}

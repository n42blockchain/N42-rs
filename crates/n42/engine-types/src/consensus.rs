use n42_clique::APos;
use n42_consensus_traits::SignerManager;
use reth_chainspec::ChainSpec;
use reth_consensus::FullConsensus;
use reth_ethereum_primitives::EthPrimitives;
use reth_node_api::FullNodeTypes;
use reth_node_builder::components::ConsensusBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};
use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Combined trait for N42 consensus that includes both FullConsensus and SignerManager.
pub trait N42FullConsensus:
    FullConsensus<EthPrimitives> + SignerManager
{
}

// Blanket implementation for any type that implements both traits
impl<T> N42FullConsensus for T where
    T: FullConsensus<EthPrimitives> + SignerManager
{
}

/// A basic ethereum consensus builder.
///
/// Clones of this builder share the same underlying consensus instance via a shared
/// `Arc<Mutex<...>>`.  This guarantees that the engine and the payload-builder subsystems
/// operate on the **same** [`APos`] object, so that a signer-key rotation performed through
/// [`reth_consensus::Consensus::set_eth_signer_by_key`] (e.g. from a test hook) is
/// immediately visible to both subsystems.
#[derive(Clone)]
pub struct N42ConsensusBuilder {
    /// Shared slot for the first-built consensus instance.
    ///
    /// All clones point at the same `Arc<Mutex>`.  The first call to
    /// `build_consensus` creates and caches the `Arc<APos<...>>`; subsequent calls
    /// (from other clones of the same original builder) downcast and return a clone of
    /// the cached value, so both the engine and the payload-builder end up sharing one
    /// `Arc<APos<...>>`.
    shared: Arc<Mutex<Option<Box<dyn Any + Send + Sync>>>>,
}

impl Default for N42ConsensusBuilder {
    fn default() -> Self {
        Self { shared: Arc::new(Mutex::new(None)) }
    }
}

impl fmt::Debug for N42ConsensusBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("N42ConsensusBuilder").finish_non_exhaustive()
    }
}

impl<Node> ConsensusBuilder<Node> for N42ConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
    Node::Provider: 'static,
{
    type Consensus = Arc<APos<<Node as FullNodeTypes>::Provider, ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        let mut guard = self.shared.lock().unwrap();

        // If another clone already built the consensus, reuse it.
        if let Some(cached) = guard.as_ref() {
            if let Some(arc) = cached.downcast_ref::<Arc<APos<Node::Provider, ChainSpec>>>() {
                return Ok(arc.clone());
            }
        }

        // First call: create the consensus and cache it for all other clones.
        let consensus = Arc::new(APos::new(
            ctx.provider().clone(),
            ctx.chain_spec(),
            ctx.config().dev.consensus_signer_private_key.clone(),
        ));
        *guard = Some(Box::new(consensus.clone()) as Box<dyn Any + Send + Sync>);
        Ok(consensus)
    }
}

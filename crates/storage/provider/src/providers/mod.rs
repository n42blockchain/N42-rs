//! Contains the main provider types and traits for interacting with the blockchain's storage.

use reth_chainspec::EthereumHardforks;
use reth_db_api::table::Value;
use reth_node_types::{FullNodePrimitives, NodeTypes, NodeTypesWithDB};

mod database;
pub use database::*;

mod static_file;
pub use static_file::{
    StaticFileAccess, StaticFileJarProvider, StaticFileProvider, StaticFileProviderRW,
    StaticFileProviderRWRefMut, StaticFileWriter,
};

mod state;
pub use state::{
    historical::{HistoricalStateProvider, HistoricalStateProviderRef, LowestAvailableBlocks},
    latest::{LatestStateProvider, LatestStateProviderRef},
};

mod consistent_view;
pub use consistent_view::{ConsistentDbView, ConsistentViewError};

mod blockchain_provider;
pub use blockchain_provider::BlockchainProvider;

mod consistent;
pub use consistent::ConsistentProvider;
//use n42_primitives::Snapshot;
//use reth_storage_api::{SnapshotProvider, SnapshotProviderWriter};


/// Helper trait to bound [`NodeTypes`] so that combined with database they satisfy
/// [`ProviderNodeTypes`].
pub trait NodeTypesForProvider
where
    Self: NodeTypes<
        ChainSpec: EthereumHardforks,
        Storage: ChainStorage<Self::Primitives>,
        Primitives: FullNodePrimitives<SignedTx: Value, Receipt: Value, BlockHeader: Value>,
    >,
{
}

impl<T> NodeTypesForProvider for T where
    T: NodeTypes<
        ChainSpec: EthereumHardforks,
        Storage: ChainStorage<T::Primitives>,
        Primitives: FullNodePrimitives<SignedTx: Value, Receipt: Value, BlockHeader: Value>,
    >
{
}

/// Helper trait keeping common requirements of providers for [`NodeTypesWithDB`].
pub trait ProviderNodeTypes
where
    Self: NodeTypesForProvider + NodeTypesWithDB,
{
}
impl<T> ProviderNodeTypes for T where T: NodeTypesForProvider + NodeTypesWithDB {}

/*
impl<N: ProviderNodeTypes> SnapshotProvider for BlockchainProvider<N> {
    fn load_snapshot(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Snapshot>> {
        self.database.provider()?.load_snapshot(id)
    }

    fn load_snapshot_by_hash(&self, block_hash: &BlockHash) -> ProviderResult<Option<Snapshot>> {
        self.database.provider()?.load_snapshot_by_hash(block_hash)
    }
}

impl<N: ProviderNodeTypes> SnapshotProviderWriter for BlockchainProvider<N> {
    fn save_snapshot(&self, id: BlockNumber, snapshot: Snapshot) -> ProviderResult<bool> {
        let provider_rw = self.database.database_provider_rw()?;
        provider_rw.save_snapshot(id, snapshot)?;
        provider_rw.commit()
    }

    fn save_snapshot_by_hash(&self, block_hash: &BlockHash,  snapshot: Snapshot) -> ProviderResult<()> {
        let provider_rw = self.database.database_provider_rw()?;
        provider_rw.save_snapshot_by_hash(block_hash, snapshot)?;
        provider_rw.commit().map(|_|())
    }

    fn save_signer_by_hash(&self, block_hash: &BlockHash,  signer: Address) -> ProviderResult<()> {
        let provider_rw = self.database.database_provider_rw()?;
        provider_rw.save_signer_by_hash(block_hash, signer)?;
        provider_rw.commit().map(|_|())
    }
}
*/

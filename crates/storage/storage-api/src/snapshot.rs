use reth_primitives::BlockHashOrNumber;
use reth_storage_errors::provider::ProviderResult;
use rast_primitives::Snapshot;

/// ly
pub trait SnapshotProvider{
    /// get snapshot by block id
    fn load_snapshot(&self, id: BlockHashOrNumber, timestamp: u64) -> ProviderResult<Option<Snapshot>>;
    /// save snapshot
    fn save_snapshot(&self, id: BlockHashOrNumber, snapshot: Snapshot) -> ProviderResult<()>;
}
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::BlockNumber;
use reth_storage_errors::provider::ProviderResult;
use n42_primitives::Snapshot;

/// ly
pub trait SnapshotProvider{
    /// get snapshot by block id
    fn load_snapshot(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Snapshot>>;
}

pub trait SnapshotProviderWriter{
    /// save snapshot
    fn save_snapshot(&self, id: BlockNumber, snapshot: Snapshot) -> ProviderResult<()>;
}

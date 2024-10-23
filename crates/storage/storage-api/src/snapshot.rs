use reth_primitives::BlockHashOrNumber;
use reth_storage_errors::provider::ProviderResult;
use rast_primitives::Snapshot;
use std::error::Error;
use reth_primitives::Header;
use alloy_primitives::Address;

/// ly
pub trait SnapshotProvider<F>: Send + Sync
where
    F: Fn(Header) -> Result<Address, Box<dyn Error>> + Clone,
{
    /// get snapshot by block id
    fn load_snapshot(&self, id: BlockHashOrNumber, timestamp: u64) -> ProviderResult<Option<Snapshot<F>>>;
    /// save snapshot
    fn save_snapshot(&self, id: BlockHashOrNumber, snapshot: Snapshot<F>) -> ProviderResult<()>;
}
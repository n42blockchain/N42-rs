use reth_primitives::Rewards;
use alloy_eips::BlockHashOrNumber;
use reth_storage_errors::provider::ProviderResult;
/// lytest
pub trait RewardsProvider:Send+Sync{
    /// lytest
    fn rewards_by_block(&self,id:BlockHashOrNumber,timestamp:u64,)->ProviderResult<Option<Rewards>>;
}
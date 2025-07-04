use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, BlockNumber, BlockHash};
use reth_storage_errors::provider::ProviderResult;
use n42_primitives::{BeaconBlock, BeaconState};

pub trait BeaconProvider{
    /// get beacon block by block hash
    fn get_beacon_block_by_hash(&self, block_hash: &BlockHash) -> ProviderResult<Option<BeaconBlock>>;

    fn get_beacon_block_by_eth1_hash(&self, block_hash: &BlockHash) -> ProviderResult<Option<BeaconBlock>>;

    fn get_beacon_state_by_hash(&self, block_hash: &BlockHash) -> ProviderResult<Option<BeaconState>>;

    fn get_beacon_block_hash_by_eth1_hash(&self, block_hash: &BlockHash) -> ProviderResult<Option<BlockHash>>;
}

pub trait BeaconProviderWriter {
    /// save beacon block by hash
    fn save_beacon_block_by_hash(&self, block_hash: &BlockHash,  beacon_block: BeaconBlock) -> ProviderResult<()>;

    fn save_beacon_block_by_eth1_hash(&self, block_hash: &BlockHash,  beacon_block: BeaconBlock) -> ProviderResult<()>;

    fn save_beacon_state_by_hash(&self, block_hash: &BlockHash,  beacon_state: BeaconState) -> ProviderResult<()>;

    fn save_beacon_block_hash_by_eth1_hash(&self, eth1_block_hash: &BlockHash, beacon_block_hash: BlockHash) -> ProviderResult<()>;

}

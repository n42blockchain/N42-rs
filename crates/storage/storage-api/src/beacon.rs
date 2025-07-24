use std::ops::RangeInclusive;
use alloy_primitives::{Address, BlockNumber, BlockHash};
use auto_impl::auto_impl;
use n42_primitives::{BeaconBlock, BeaconState, BeaconStateChangeset,BeaconBlockChangeset};
use reth_storage_errors::ProviderResult;

#[auto_impl(&, Arc, Box)]
pub trait BeaconReader{
    fn get_beaconstate_by_blockhash(&self,blockhash:BlockHash)->ProviderResult<Option<BeaconState>>;
    fn get_beaconblock_by_blockhash(&self,blockhash:BlockHash)->ProviderResult<Option<BeaconBlock>>;
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconWriter{
    fn unwind_beacon(&self,range:RangeInclusive<BlockNumber>)->ProviderResult<()>;
    fn write_beaconstate(&self,changes:BeaconStateChangeset)->ProviderResult<()>;
    fn remove_beaconstate(&self,range:Vec<BlockHash>)->ProviderResult<()>;
    // fn unwind_beaconblock(&self,range:RangeInclusive<BlockNumber>)->ProviderResult<()>;
    fn write_beaconblock(&self,changes:BeaconBlockChangeset)->ProviderResult<()>;
    fn remove_beaconblock(&self,range:Vec<BlockHash>)->ProviderResult<()>;
}

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

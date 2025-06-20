use std::ops::RangeInclusive;
use alloy_primitives::{BlockHash, BlockNumber};
use auto_impl::auto_impl;
use n42_primitives::{BeaconBlock, BeaconBlockBeforeBlock, BeaconState, BeaconStateChangeset};
use reth_storage_errors::ProviderResult;

#[auto_impl(&, Arc, Box)]
pub trait BeaconStateReader{
    fn get_beaconstate_by_blockhash(&self,blockhash:BlockHash)->ProviderResult<Option<BeaconState>>;
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconStateWriter{
    fn unwind_beaconstate(&self,range:RangeInclusive<BlockNumber>)->ProviderResult<()>;
    fn write_beaconstate(&self,changes:BeaconStateChangeset)->ProviderResult<()>;
    fn remove_beaconstate(&self,range:Vec<BlockHash>)->ProviderResult<()>;
    // fn unwind_beaconstate_history_indices<'a>(&self,changesets:impl Iterator<Item = &'a(BlockHash,BeaconStateBeforeBlock)>,)->ProviderResult<usize>;
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconBlockReader{
    fn get_beaconblock_by_blockhash(&self,bh:BlockHash)->ProviderResult<Option<BeaconBlock>>;
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconBlockWriter{

}
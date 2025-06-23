use std::ops::RangeInclusive;
use alloy_primitives::{BlockHash, BlockNumber};
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
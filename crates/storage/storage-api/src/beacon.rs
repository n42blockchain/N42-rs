use alloy_primitives::BlockHash;
use auto_impl::auto_impl;
use n42_primitives::{BeaconState,BeaconStateBeforeBlock,BeaconBlock,BeaconBlockBeforeBlock};
use reth_storage_errors::ProviderResult;

#[auto_impl(&, Arc, Box)]
pub trait BeaconStateReader{
    fn get_beaconstate_by_blockhash(&self,bh:BlockHash)->ProviderResult<Option<BeaconState>>;
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconStateWriter{
    
}

#[auto_impl(&, Arc, Box)]
pub trait BeaconBlockReader{
    fn get_beaconblock_by_blockhash(&self,bh:BlockHash)->ProviderResult<Option<BeaconBlock>>;
}
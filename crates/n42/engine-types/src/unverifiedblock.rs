use alloy_primitives::BlockNumber;
use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};
#[derive(Serialize,Clone,Deserialize,Default,Debug)]
pub struct UnverifiedBlock{
    pub blocknumber:BlockNumber,
    pub block:CachedReads,
}
impl UnverifiedBlock{
    pub fn new(blocknumber:BlockNumber,block:CachedReads)->Self{
        Self{
            blocknumber,
            block,
        }
    }
}
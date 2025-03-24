use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};
use reth_primitives::BlockBody;
use alloy_primitives::U256;
#[derive(Serialize,Clone,Deserialize,Default,Debug)]
pub struct UnverifiedBlock{
    pub blockbody:BlockBody,
    pub db:CachedReads,
    pub td:U256,
}
impl UnverifiedBlock{
    pub fn new(blockbody:BlockBody,db:CachedReads,td:U256)->Self{
        Self{
            blockbody,
            db,
            td,
        }
    }
}
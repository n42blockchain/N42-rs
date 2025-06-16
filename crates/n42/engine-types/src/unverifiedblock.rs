use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};
use reth_primitives::BlockBody;
use alloy_primitives::U256;
#[derive(Clone,Default,Deserialize,Serialize,Debug)]
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
    pub fn is_empty(&self) -> bool {
        self.blockbody.transactions.is_empty() &&
        self.blockbody.ommers.is_empty() &&
        self.blockbody.withdrawals.is_none() &&
        // self.blockbody.verifiers.is_none() &&
        // self.blockbody.rewards.is_none() &&
        self.db.is_empty() &&
        self.td == U256::ZERO
    }

    pub fn is_complete(&self) -> bool {
        !self.blockbody.transactions.is_empty() &&
        !self.blockbody.ommers.is_empty() &&
        !self.blockbody.withdrawals.is_none() &&
        // !self.blockbody.verifiers.is_none() &&
        // !self.blockbody.rewards.is_none() &&
        !self.db.is_empty() &&
        !self.td == U256::ZERO
    }
}
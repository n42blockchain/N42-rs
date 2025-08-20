use n42_primitives::{AttestationData, CommitteeIndex};
use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};
use reth_primitives::{BlockBody, SealedBlock};
use alloy_primitives::{B256, U256};

#[derive(Clone,Default,Deserialize,Serialize,Debug)]
pub struct BlockVerifyResult {
    pub pubkey: String,
    pub signature: String,
    pub attestation_data: AttestationData,
    pub block_hash: B256,
}

#[derive(Clone,Default,Deserialize,Serialize,Debug)]
pub struct UnverifiedBlock{
    pub blockbody:SealedBlock,
    pub db:CachedReads,
    pub td:U256,
    pub committee_index: CommitteeIndex,
}
impl UnverifiedBlock{
    pub fn new(blockbody:SealedBlock,db:CachedReads,td:U256,
        committee_index: CommitteeIndex,
        )->Self{
        Self{
            blockbody,
            db,
            td,
            committee_index,
        }
    }
}

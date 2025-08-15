use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};
use reth_primitives::{BlockBody, SealedBlock};
use alloy_primitives::{B256, U256};

pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone,Default,Deserialize,Serialize,Debug)]
pub struct BlockVerifyResult {
    pub pubkey: String,
    pub signature: String,
    pub receipts_root: String,
    pub block_hash: B256,
}

#[derive(Clone,Default,Deserialize,Serialize,Debug)]
pub struct UnverifiedBlock{
    pub blockbody:SealedBlock,
    pub db:CachedReads,
    pub td:U256,
}
impl UnverifiedBlock{
    pub fn new(blockbody:SealedBlock,db:CachedReads,td:U256)->Self{
        Self{
            blockbody,
            db,
            td,
        }
    }
}

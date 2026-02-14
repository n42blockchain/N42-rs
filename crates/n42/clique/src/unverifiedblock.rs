use blst::min_pk::Signature as BlstSignature;
use n42_primitives::{AttestationData, BLSPubkey, CommitteeIndex};
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

/// Pre-verified attestation sent from RPC handler to miner.
/// All hex decoding and BLS signature verification has already been performed.
pub struct VerifiedAttestation {
    pub pubkey_bytes: BLSPubkey,
    pub signature: BlstSignature,
    pub attestation_data: AttestationData,
    pub block_hash: B256,
}

impl std::fmt::Debug for VerifiedAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedAttestation")
            .field("pubkey", &hex::encode(&self.pubkey_bytes))
            .field("attestation_data", &self.attestation_data)
            .field("block_hash", &self.block_hash)
            .finish()
    }
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

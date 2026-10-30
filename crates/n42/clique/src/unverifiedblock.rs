// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::{B256, U256};
use n42_primitives::{AttestationData, CommitteeIndex};
// reth-primitives (deleted in reth 2.4.1) supplied this default type argument.
type SealedBlock<B = n42_tx_types::Block> = reth_primitives_traits::SealedBlock<B>;
use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize, Serialize, Debug)]
/// A validator's BLS verification of a block, as submitted over RPC.
pub struct BlockVerifyResult {
    /// Hex-encoded BLS public key of the verifier.
    pub pubkey: String,
    /// Hex-encoded BLS signature over the attestation data.
    pub signature: String,
    /// What the validator attests to.
    pub attestation_data: AttestationData,
    /// Hash of the verified block.
    pub block_hash: B256,
}

#[derive(Clone, Default, Deserialize, Serialize, Debug)]
/// A sealed block together with the cached state needed to verify it.
pub struct UnverifiedBlock {
    /// The sealed block to verify.
    pub blockbody: SealedBlock,
    /// Cached reads of the block's execution, so a verifier can re-execute it cheaply.
    pub db: CachedReads,
    /// Total difficulty of the chain at this block.
    pub td: U256,
    /// Committee the block was assigned to.
    pub committee_index: CommitteeIndex,
}
impl UnverifiedBlock {
    /// Creates an unverified block from its parts.
    pub const fn new(
        blockbody: SealedBlock,
        db: CachedReads,
        td: U256,
        committee_index: CommitteeIndex,
    ) -> Self {
        Self {
            blockbody,
            db,
            td,
            committee_index,
        }
    }
}

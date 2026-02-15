// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::{B256, U256};
use n42_primitives::{AttestationData, CommitteeIndex};
use reth_primitives::{Header, SealedBlock, TransactionSigned};
use reth_revm::cached::CachedReads;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Default, Deserialize, Serialize, Debug)]
pub struct BlockVerifyResult {
    pub pubkey: String,
    pub signature: String,
    pub attestation_data: AttestationData,
    pub block_hash: B256,
}

#[derive(Clone, Default, Deserialize, Serialize, Debug)]
pub struct UnverifiedBlock {
    pub blockbody: SealedBlock,
    /// Wrapped in Arc to avoid deep-copying state cache on every clone.
    /// Each committee broadcast only bumps the reference count (O(1)),
    /// instead of cloning the entire CachedReads (O(state_size)).
    pub db: Arc<CachedReads>,
    pub td: U256,
    pub committee_index: CommitteeIndex,
}
impl UnverifiedBlock {
    pub fn new(
        blockbody: SealedBlock,
        db: CachedReads,
        td: U256,
        committee_index: CommitteeIndex,
    ) -> Self {
        Self {
            blockbody,
            db: Arc::new(db),
            td,
            committee_index,
        }
    }
}

/// Compact state witness containing only the Merkle proofs needed for execution.
/// This replaces the full CachedReads for network transmission, reducing
/// bandwidth from ~500KB to ~50-100KB per block.
#[derive(Clone, Default, Deserialize, Serialize, Debug)]
pub struct CompactStateWitness {
    /// Account proofs keyed by address (20 bytes hex)
    pub account_proofs: HashMap<String, Vec<B256>>,
    /// Storage proofs keyed by address + storage key
    pub storage_proofs: HashMap<String, HashMap<B256, Vec<B256>>>,
    /// Contract bytecodes keyed by code hash
    pub bytecodes: HashMap<B256, Vec<u8>>,
}

/// Lightweight verification request sent to mobile validators via Gateway.
/// Contains only the data needed to re-execute the block, without full state cache.
/// Network size: ~50-100KB vs ~500KB for full UnverifiedBlock.
#[derive(Clone, Default, Deserialize, Serialize, Debug)]
pub struct LightVerificationRequest {
    /// Block header (without receipts_root, to be computed by validator)
    pub header: Header,
    /// Transactions to execute
    pub transactions: Vec<TransactionSigned>,
    /// Merkle proofs for state access during execution
    pub state_witness: CompactStateWitness,
    /// Total difficulty
    pub td: U256,
    /// Committee index this request is for
    pub committee_index: CommitteeIndex,
}

impl LightVerificationRequest {
    /// Create a light verification request from a full UnverifiedBlock.
    /// The state_witness should be generated from the CachedReads by
    /// extracting only the Merkle proofs needed for execution.
    pub fn from_unverified_block(
        block: &UnverifiedBlock,
        witness: CompactStateWitness,
    ) -> Self {
        Self {
            header: block.blockbody.header().clone(),
            transactions: block.blockbody.body().transactions().cloned().collect(),
            state_witness: witness,
            td: block.td,
            committee_index: block.committee_index,
        }
    }
}

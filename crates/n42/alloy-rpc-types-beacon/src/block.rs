// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Beacon block types.
//!
//! See also <https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2>

use crate::{header::BeaconBlockHeader, BlsPublicKey, BlsSignature};
use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

/// Response from the `eth/v2/beacon/blocks/{block_id}` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponse<T = serde_json::Value> {
    /// The version of the response.
    pub version: String,
    /// True if the response references an unverified execution payload.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// True if the response references the finalized history of the chain.
    #[serde(default)]
    pub finalized: bool,
    /// The signed beacon block data.
    pub data: SignedBeaconBlock<T>,
}

/// A signed beacon block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBeaconBlock<T = serde_json::Value> {
    /// The beacon block message.
    pub message: BeaconBlock<T>,
    /// The signature.
    pub signature: BlsSignature,
}

/// A beacon block.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlock<T = serde_json::Value> {
    /// The slot number.
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    /// Index of the proposer validator.
    #[serde_as(as = "DisplayFromStr")]
    pub proposer_index: u64,
    /// Root of the parent block.
    pub parent_root: B256,
    /// State root.
    pub state_root: B256,
    /// Block body.
    pub body: T,
}

/// Eth1 data included in beacon blocks.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Eth1Data {
    /// Root of the deposit tree.
    pub deposit_root: B256,
    /// Number of deposits.
    #[serde_as(as = "DisplayFromStr")]
    pub deposit_count: u64,
    /// Block hash.
    pub block_hash: B256,
}

/// A checkpoint in the beacon chain.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    /// The epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub epoch: u64,
    /// The root.
    pub root: B256,
}

/// Attestation data.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttestationData {
    /// Slot number.
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    /// Committee index.
    #[serde_as(as = "DisplayFromStr")]
    pub index: u64,
    /// Beacon block root being attested to.
    pub beacon_block_root: B256,
    /// Source checkpoint.
    pub source: Checkpoint,
    /// Target checkpoint.
    pub target: Checkpoint,
}

/// An attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Aggregation bits.
    pub aggregation_bits: Bytes,
    /// Attestation data.
    pub data: AttestationData,
    /// BLS signature.
    pub signature: BlsSignature,
}

/// An indexed attestation.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedAttestation {
    /// Attesting validator indices.
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub attesting_indices: Vec<u64>,
    /// Attestation data.
    pub data: AttestationData,
    /// BLS signature.
    pub signature: BlsSignature,
}

/// A proposer slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerSlashing {
    /// First signed header.
    pub signed_header_1: SignedBeaconBlockHeader,
    /// Second signed header.
    pub signed_header_2: SignedBeaconBlockHeader,
}

/// A signed beacon block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBeaconBlockHeader {
    /// Header message.
    pub message: BeaconBlockHeader,
    /// BLS signature.
    pub signature: BlsSignature,
}

/// An attester slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttesterSlashing {
    /// First attestation.
    pub attestation_1: IndexedAttestation,
    /// Second attestation.
    pub attestation_2: IndexedAttestation,
}

/// Deposit data.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositData {
    /// Validator public key.
    pub pubkey: BlsPublicKey,
    /// Withdrawal credentials.
    pub withdrawal_credentials: B256,
    /// Amount in gwei.
    #[serde_as(as = "DisplayFromStr")]
    pub amount: u64,
    /// BLS signature.
    pub signature: BlsSignature,
}

/// A deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    /// Merkle proof.
    pub proof: Vec<B256>,
    /// Deposit data.
    pub data: DepositData,
}

/// A voluntary exit.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    #[serde_as(as = "DisplayFromStr")]
    pub epoch: u64,
    /// Index of the exiting validator.
    #[serde_as(as = "DisplayFromStr")]
    pub validator_index: u64,
}

/// A signed voluntary exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVoluntaryExit {
    /// Voluntary exit message.
    pub message: VoluntaryExit,
    /// BLS signature.
    pub signature: BlsSignature,
}

/// Sync aggregate data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAggregate {
    /// Sync committee participation bits.
    pub sync_committee_bits: Bytes,
    /// Sync committee signature.
    pub sync_committee_signature: BlsSignature,
}

/// A BLS to execution address change message.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsToExecutionChange {
    /// Validator index.
    #[serde_as(as = "DisplayFromStr")]
    pub validator_index: u64,
    /// From BLS public key.
    pub from_bls_pubkey: BlsPublicKey,
    /// To execution layer address.
    pub to_execution_address: Address,
}

/// A signed BLS to execution address change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlsToExecutionChange {
    /// The change message.
    pub message: BlsToExecutionChange,
    /// BLS signature.
    pub signature: BlsSignature,
}

/// Deneb beacon block body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockBodyDeneb<T = serde_json::Value> {
    /// RANDAO reveal.
    pub randao_reveal: BlsSignature,
    /// Eth1 data.
    pub eth1_data: Eth1Data,
    /// Graffiti.
    pub graffiti: B256,
    /// Proposer slashings.
    pub proposer_slashings: Vec<ProposerSlashing>,
    /// Attester slashings.
    pub attester_slashings: Vec<AttesterSlashing>,
    /// Attestations.
    pub attestations: Vec<Attestation>,
    /// Deposits.
    pub deposits: Vec<Deposit>,
    /// Voluntary exits.
    pub voluntary_exits: Vec<SignedVoluntaryExit>,
    /// Sync aggregate.
    pub sync_aggregate: SyncAggregate,
    /// Execution payload.
    pub execution_payload: T,
    /// BLS to execution changes.
    pub bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
    /// Blob KZG commitments.
    pub blob_kzg_commitments: Vec<Bytes>,
}

/// Electra beacon block body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockBodyElectra<T = serde_json::Value> {
    /// RANDAO reveal.
    pub randao_reveal: BlsSignature,
    /// Eth1 data.
    pub eth1_data: Eth1Data,
    /// Graffiti.
    pub graffiti: B256,
    /// Proposer slashings.
    pub proposer_slashings: Vec<ProposerSlashing>,
    /// Attester slashings.
    pub attester_slashings: Vec<AttesterSlashing>,
    /// Attestations.
    pub attestations: Vec<Attestation>,
    /// Deposits.
    pub deposits: Vec<Deposit>,
    /// Voluntary exits.
    pub voluntary_exits: Vec<SignedVoluntaryExit>,
    /// Sync aggregate.
    pub sync_aggregate: SyncAggregate,
    /// Execution payload.
    pub execution_payload: T,
    /// BLS to execution changes.
    pub bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
    /// Blob KZG commitments.
    pub blob_kzg_commitments: Vec<Bytes>,
    /// Execution requests (EIP-7685).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_requests: Option<serde_json::Value>,
}

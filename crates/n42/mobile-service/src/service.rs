// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a node exposes to the phones verifying it.
//!
//! Two directions meet here. Outbound, the node publishes a finality proof: the
//! committed `Decide` in gov5's v4 wire format, which a phone checks against a
//! validator set with [`n42_h2_consensus::h2_finality::verify_h2_v4_decide`].
//! That is the whole point of the format being byte-exact — the phone trusts the
//! signatures, not the server. Inbound, phones return verification receipts,
//! which this aggregates into a BLS attestation that anyone can check with two
//! pairings regardless of how many phones took part.
//!
//! State proofs are served from the same QMDB tree the block header's state root
//! comes from — on a QMDB chain those are the same value, so a phone checks the
//! proof against a root it already established from the `Decide` above. That is
//! the whole chain of trust: signatures it verified, a root those signatures
//! commit to, and a proof that root commits to. Nothing in it is this server's
//! word.
//!
//! **Every receipt's signature is verified here.** Neither
//! [`n42_mobile_verify::ReceiptAggregator`] nor
//! [`n42_mobile_verify::AttestationBuilder`] checks one — the aggregator counts
//! and the builder aggregates. A forged signature that reached the builder would
//! not merely be one bad vote: BLS aggregation is all-or-nothing, so it would
//! make the whole attestation fail verification, and any phone could disable a
//! block's attestation by sending one bad receipt.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use alloy_primitives::{Address, B256};
use n42_qmdb_state::StateProofProvider;
use n42_h2_consensus::wire_bridge::{self, BridgeError};
use n42_h2_primitives::consensus::{
    ConsensusMessage, Decide, H2V4ChainIdentity, QuorumCertificate,
};
use n42_h2_wire::h2_v4::encode_envelope;
use n42_mobile_verify::{
    AggregatedAttestation, AttestationBuilder, ReceiptAggregator, VerificationReceipt,
    VerifierRegistry,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// How many recent blocks keep their attestation state.
///
/// A phone verifies near the head; a block nobody attested within this window is
/// not going to be attested. Bounded because this is fed by untrusted input.
const DEFAULT_TRACKED_BLOCKS: usize = 256;

/// What a phone needs to establish the chain head for itself.
///
/// `decide_envelope` is the committed `Decide` in gov5's v4 wire format. A phone
/// decodes it, checks the commit QC against the validator set, and accepts the
/// block — without trusting the server that sent it. The other fields are
/// conveniences that the envelope itself proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReport {
    /// The view the block was committed in.
    pub view: u64,
    /// The committed block.
    pub block_hash: B256,
    /// Its height.
    pub block_number: u64,
    /// The `Decide` envelope, verifiable on its own.
    #[serde(with = "hex_bytes")]
    pub decide_envelope: Vec<u8>,
}

/// What happened to a submitted receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitOutcome {
    /// Whether this receipt was new (a duplicate from the same verifier is not
    /// an error — a phone that retries on a flaky link should not be punished).
    pub accepted: bool,
    /// Valid receipts counted for this block so far.
    pub valid_receipts: u32,
    /// Whether the block has reached its attestation threshold.
    pub attested: bool,
}

/// Why a receipt was refused.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// The signature does not verify against the claimed public key. See the
    /// module docs: this check is what keeps one phone from voiding a block's
    /// attestation for everyone.
    #[error("receipt signature does not verify")]
    InvalidSignature,
    /// The verifier is not registered, so its signature cannot be placed in an
    /// attestation bitfield.
    #[error("verifier is not registered")]
    UnknownVerifier,
    /// The block is not one this node is collecting receipts for — too old, or
    /// never committed here.
    #[error("block {0} is not being tracked")]
    UnknownBlock(B256),
}

/// Why a commit could not be recorded.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The commit could not be expressed in the v4 wire format.
    #[error("encoding the Decide for phones: {0}")]
    Encode(#[from] BridgeError),
    /// The envelope could not be serialised.
    #[error("encoding the Decide envelope: {0}")]
    Envelope(#[from] n42_h2_wire::h2_v4::H2V4Error),
}

/// The node side of mobile verification.
pub struct MobileService {
    identity: H2V4ChainIdentity,
    registry: VerifierRegistry,
    aggregator: ReceiptAggregator,
    /// Per-block signature collectors, kept alive past the threshold so late
    /// receipts still strengthen the aggregate.
    builders: HashMap<B256, AttestationBuilder>,
    /// Insertion order, for evicting the oldest block.
    order: VecDeque<B256>,
    finality: Option<FinalityReport>,
    max_blocks: usize,
    /// The QMDB tree this node's state root comes from, when it keeps one.
    /// Shared with whatever applies blocks to it.
    state: Option<Arc<dyn StateProofProvider>>,
}

/// A membership proof and the root it is checked against.
///
/// The root is included so a phone can compare it with the one in the header it
/// already verified, and reject a proof cut from some other tree. A proof
/// without its root is a proof of nothing in particular.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProofReport {
    /// The state root the proof is anchored to. On a QMDB chain this is the
    /// header's state root.
    pub root: B256,
    /// The leaf key proved: `Blake3(address)` or `Blake3(address || slot)`.
    pub key: B256,
    /// The leaf value, as the tree holds it.
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
    /// The proof in gov5's v2 layout.
    #[serde(with = "hex_bytes")]
    pub proof: Vec<u8>,
}

impl std::fmt::Debug for MobileService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobileService")
            .field("identity", &self.identity)
            .field("tracked_blocks", &self.builders.len())
            .field("serves_state_proofs", &self.state.is_some())
            .finish_non_exhaustive()
    }
}

impl MobileService {
    /// Creates a service for `identity`, attesting a block once `threshold`
    /// distinct phones agree on its receipts root.
    pub fn new(identity: H2V4ChainIdentity, threshold: u32) -> Self {
        Self {
            identity,
            registry: VerifierRegistry::new(),
            aggregator: ReceiptAggregator::new(threshold, DEFAULT_TRACKED_BLOCKS),
            builders: HashMap::new(),
            order: VecDeque::new(),
            finality: None,
            max_blocks: DEFAULT_TRACKED_BLOCKS,
            state: None,
        }
    }

    /// Serves state proofs from `state`.
    ///
    /// The same tree the node's block headers take their state root from —
    /// anything else and a phone would be verifying a proof against a root
    /// nothing else agrees with.
    pub fn with_state(mut self, state: Arc<dyn StateProofProvider>) -> Self {
        self.state = Some(state);
        self
    }

    /// Registers a phone's BLS public key and returns its index.
    ///
    /// The index is what an attestation's bitfield refers to, so it is stable
    /// for the lifetime of the service and shared by everyone verifying its
    /// attestations. Registering twice returns the same index.
    pub fn register_verifier(&mut self, pubkey: [u8; 48]) -> u32 {
        self.registry.register(pubkey)
    }

    /// The registry, for verifying an attestation this service produced.
    pub const fn registry(&self) -> &VerifierRegistry {
        &self.registry
    }

    /// The most recent finality proof, if this node has committed anything.
    pub const fn finality(&self) -> Option<&FinalityReport> {
        self.finality.as_ref()
    }

    /// Records a block this node's consensus committed.
    ///
    /// Rebuilds the `Decide` a phone would have seen on the wire, so the proof
    /// it serves is the same bytes a fleet member would verify, rather than a
    /// server-side summary a phone would have to trust.
    pub fn record_commit(
        &mut self,
        view: u64,
        block_hash: B256,
        block_number: u64,
        commit_qc: QuorumCertificate,
        expected_receipts_root: Option<B256>,
    ) -> Result<(), RecordError> {
        // The v4 profile is static-validator, so the changes hash is zero
        // throughout; `wire_bridge` refuses a Decide that disagrees.
        let changes_hash = B256::ZERO;
        let decide = ConsensusMessage::Decide(Decide {
            view,
            block_hash,
            commit_qc,
            validator_changes_hash: changes_hash,
        });
        let envelope = wire_bridge::to_wire(&decide, self.identity, changes_hash)?;

        self.finality = Some(FinalityReport {
            view,
            block_hash,
            block_number,
            decide_envelope: encode_envelope(&envelope)?,
        });

        self.aggregator
            .register_block(block_hash, block_number, expected_receipts_root);
        if let std::collections::hash_map::Entry::Vacant(slot) =
            self.builders.entry(block_hash)
        {
            slot.insert(AttestationBuilder::new(
                block_hash,
                block_number,
                // With no expected root known, the first receipt's root is what
                // the aggregate is built around; the aggregator still counts
                // disagreeing ones separately.
                expected_receipts_root.unwrap_or_default(),
            ));
            self.order.push_back(block_hash);
        }
        self.evict_old_blocks();
        debug!(target: "n42.mobile", view, %block_hash, block_number, "recorded a commit for phones");
        Ok(())
    }

    /// Accepts a verification receipt from a phone.
    pub fn submit_receipt(
        &mut self,
        receipt: &VerificationReceipt,
    ) -> Result<SubmitOutcome, SubmitError> {
        // Signature first, before the receipt touches any shared state. See the
        // module docs: an unverified signature in the aggregate voids the whole
        // attestation, so this is a denial-of-service check, not just a
        // correctness one.
        receipt
            .verify_signature()
            .map_err(|_| SubmitError::InvalidSignature)?;

        if self.registry.index_of(&receipt.verifier_pubkey).is_none() {
            return Err(SubmitError::UnknownVerifier);
        }
        let Some(builder) = self.builders.get_mut(&receipt.block_hash) else {
            return Err(SubmitError::UnknownBlock(receipt.block_hash));
        };

        let added = builder.add_receipt(receipt, &self.registry);
        let counted = self.aggregator.process_receipt(receipt);
        let status = self.aggregator.get_status(&receipt.block_hash);

        if added && counted.is_none() {
            // The two disagree only if their views of the block diverged, which
            // means the block was evicted from one and not the other.
            warn!(target: "n42.mobile", block_hash = %receipt.block_hash, "receipt accepted by the aggregate but not counted");
        }

        Ok(SubmitOutcome {
            accepted: added,
            valid_receipts: status.map_or(0, |s| s.valid_count),
            attested: status.is_some_and(n42_mobile_verify::BlockVerificationStatus::is_attested),
        })
    }

    /// The aggregate attestation for a block, from the receipts collected so far.
    ///
    /// Derived on demand rather than frozen when the threshold is crossed: a
    /// receipt that arrives late still strengthens the aggregate, and a phone
    /// asking later should get the stronger one.
    pub fn attestation(&self, block_hash: &B256) -> Option<AggregatedAttestation> {
        let builder = self.builders.get(block_hash)?;
        if builder.count() == 0 {
            return None;
        }
        builder.clone().build().ok()
    }

    /// Proves what the state tree holds for an account, or for one of its
    /// storage slots when `slot` is given.
    ///
    /// `None` means either that this node keeps no state tree, or that the key
    /// has no live leaf. Those are deliberately not distinguished: QMDB
    /// membership proofs do not prove absence, so a caller must not read either
    /// as "the account does not exist".
    pub fn prove(&self, address: Address, slot: Option<B256>) -> Option<StateProofReport> {
        let state = self.state.as_ref()?;
        let proof = match slot {
            Some(slot) => state.prove_storage(address, slot),
            None => state.prove_account(address),
        }?;
        Some(StateProofReport {
            root: state.state_root(),
            key: B256::from(proof.key),
            value: proof.value.clone(),
            proof: proof.encode().ok()?,
        })
    }

    /// Whether this node can serve state proofs at all.
    pub const fn serves_state_proofs(&self) -> bool {
        self.state.is_some()
    }

    /// How many blocks are collecting receipts.
    pub fn tracked_blocks(&self) -> usize {
        self.builders.len()
    }

    fn evict_old_blocks(&mut self) {
        while self.order.len() > self.max_blocks {
            if let Some(oldest) = self.order.pop_front() {
                self.builders.remove(&oldest);
            }
        }
    }
}

/// Serialises a byte vector as a `0x`-prefixed hex string.
///
/// The wire-format envelope is bytes; phones and operators read it out of JSON,
/// and a decimal array is the same value in a form nobody can check by eye.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        hex::decode(raw.strip_prefix("0x").unwrap_or(&raw)).map_err(serde::de::Error::custom)
    }
}

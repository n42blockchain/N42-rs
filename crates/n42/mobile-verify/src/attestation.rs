use alloy_primitives::B256;
use n42_h2_primitives::bls::AggregateSignature;
use n42_h2_primitives::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::receipt::{VerificationReceipt, build_signing_message};

/// Bidirectional mapping between verifier BLS pubkeys and bitfield indices.
///
/// Each connected verifier is assigned a unique index starting from 0. The
/// index determines the bit position in the participation bitfield of an
/// [`AggregatedAttestation`]. Similar to the beacon chain's validator registry,
/// this enables compact representation of which verifiers participated.
///
/// Serializes pubkeys as hex strings for human-readable JSON persistence.
#[derive(Debug, Clone, Default)]
pub struct VerifierRegistry {
    pubkeys: Vec<[u8; 48]>,
    index_map: HashMap<[u8; 48], u32>,
}

/// Serde: serialize/deserialize VerifierRegistry via hex-encoded pubkey list.
/// The index_map is rebuilt from the pubkey list on deserialization.
impl Serialize for VerifierRegistry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex_keys: Vec<String> = self.pubkeys.iter().map(hex::encode).collect();
        hex_keys.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VerifierRegistry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_keys: Vec<String> = Vec::deserialize(deserializer)?;
        let mut reg = VerifierRegistry::new();
        for hex_key in &hex_keys {
            let bytes = hex::decode(hex_key).map_err(serde::de::Error::custom)?;
            let arr: [u8; 48] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected 48-byte BLS pubkey"))?;
            reg.register(arr);
        }
        Ok(reg)
    }
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a verifier pubkey and returns its assigned index.
    /// If already registered, returns the existing index.
    pub fn register(&mut self, pubkey: [u8; 48]) -> u32 {
        if let Some(&idx) = self.index_map.get(&pubkey) {
            return idx;
        }
        let idx = self.pubkeys.len() as u32;
        self.pubkeys.push(pubkey);
        self.index_map.insert(pubkey, idx);
        idx
    }

    /// Returns the index for a pubkey, if registered.
    pub fn index_of(&self, pubkey: &[u8; 48]) -> Option<u32> {
        self.index_map.get(pubkey).copied()
    }

    /// Returns the pubkey at the given index.
    pub fn pubkey_at(&self, index: u32) -> Option<&[u8; 48]> {
        self.pubkeys.get(index as usize)
    }

    /// Returns the total number of registered verifiers.
    pub fn len(&self) -> u32 {
        self.pubkeys.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.pubkeys.is_empty()
    }

    /// Returns all registered pubkeys in index order.
    pub fn all_pubkeys(&self) -> &[[u8; 48]] {
        &self.pubkeys
    }
}

/// A completed BLS aggregate attestation proof for a single block.
///
/// Analogous to the beacon chain's `Attestation`: a single aggregate BLS
/// signature proves that `participant_count` verifiers all computed the same
/// `receipts_root` for the given block. The `participant_bitfield` indicates
/// which verifiers (by registry index) contributed to the aggregate.
///
/// Verification: `fast_aggregate_verify(attestation_message, aggregate_signature,
/// [pubkeys selected by bitfield])` — constant 2 pairings regardless of count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedAttestation {
    pub block_hash: B256,
    pub block_number: u64,
    pub receipts_root: B256,
    pub aggregate_signature: BlsSignature,
    /// Bitfield where bit `i` is set if the verifier at registry index `i`
    /// participated in this attestation.
    pub participant_bitfield: Vec<u8>,
    pub participant_count: u32,
    /// When the aggregate was finalized (milliseconds since UNIX epoch).
    pub created_at_ms: u64,
}

impl AggregatedAttestation {
    /// Returns the canonical 72-byte message that was signed by all participants.
    pub fn signing_message(&self) -> Vec<u8> {
        build_signing_message(&self.block_hash, self.block_number, &self.receipts_root)
    }

    /// Verifies the aggregate signature against the given registry.
    ///
    /// Extracts the participant pubkeys from the bitfield, then calls
    /// `fast_aggregate_verify`. Returns `Ok(())` if the aggregate is valid.
    pub fn verify(&self, registry: &VerifierRegistry) -> Result<(), AttestationError> {
        let pubkeys = self.extract_participant_pubkeys(registry)?;
        if pubkeys.is_empty() {
            return Err(AttestationError::NoParticipants);
        }

        let bls_pubkeys: Vec<BlsPublicKey> = pubkeys
            .iter()
            .map(|pk| BlsPublicKey::from_bytes(pk).map_err(|_| AttestationError::InvalidPublicKey))
            .collect::<Result<Vec<_>, _>>()?;

        let pk_refs: Vec<&BlsPublicKey> = bls_pubkeys.iter().collect();
        let msg = self.signing_message();

        AggregateSignature::verify_aggregate(&msg, &self.aggregate_signature, &pk_refs)
            .map_err(|_| AttestationError::InvalidAggregateSignature)
    }

    /// Extracts participant pubkeys from the bitfield using the registry.
    fn extract_participant_pubkeys(
        &self,
        registry: &VerifierRegistry,
    ) -> Result<Vec<[u8; 48]>, AttestationError> {
        let mut pubkeys = Vec::with_capacity(self.participant_count as usize);
        for (byte_idx, &byte) in self.participant_bitfield.iter().enumerate() {
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let index = byte_idx as u32 * 8 + bit;
                    let pk = registry
                        .pubkey_at(index)
                        .ok_or(AttestationError::RegistryIndexOutOfBounds(index))?;
                    pubkeys.push(*pk);
                }
            }
        }
        Ok(pubkeys)
    }
}

/// Collects individual receipt signatures and builds an [`AggregatedAttestation`].
///
/// The builder accepts receipts that match the target `(block_hash, block_number,
/// receipts_root)` and deduplicates by verifier pubkey. Once enough receipts
/// have been collected, call [`build`] to produce the aggregate.
///
/// `Clone` so a caller can take an aggregate of what it has so far without
/// giving up the ability to add more: [`Self::build`] consumes the builder, and
/// receipts keep arriving after a threshold is first crossed.
#[derive(Debug, Clone)]
pub struct AttestationBuilder {
    block_hash: B256,
    block_number: u64,
    receipts_root: B256,
    /// Collected (registry_index, signature) pairs.
    entries: Vec<(u32, BlsSignature)>,
    /// Tracks which registry indices have already been added (dedup).
    seen_indices: HashSet<u32>,
}

impl AttestationBuilder {
    pub fn new(block_hash: B256, block_number: u64, receipts_root: B256) -> Self {
        Self {
            block_hash,
            block_number,
            receipts_root,
            entries: Vec::new(),
            seen_indices: HashSet::new(),
        }
    }

    /// Adds a receipt's signature to the aggregate.
    ///
    /// The receipt must match `(block_hash, block_number, receipts_root)` and
    /// the verifier must be in the registry. Returns `true` if the receipt was
    /// accepted (not a duplicate, matching block/root).
    pub fn add_receipt(
        &mut self,
        receipt: &VerificationReceipt,
        registry: &VerifierRegistry,
    ) -> bool {
        if receipt.block_hash != self.block_hash
            || receipt.block_number != self.block_number
            || receipt.computed_receipts_root != self.receipts_root
        {
            return false;
        }

        let Some(index) = registry.index_of(&receipt.verifier_pubkey) else {
            return false;
        };

        if !self.seen_indices.insert(index) {
            return false;
        }

        self.entries.push((index, receipt.signature.clone()));
        true
    }

    /// Returns the number of unique signatures collected so far.
    pub fn count(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Builds the aggregated attestation from collected signatures.
    ///
    /// Fails if no signatures have been collected or if BLS aggregation fails.
    pub fn build(self) -> Result<AggregatedAttestation, AttestationError> {
        if self.entries.is_empty() {
            return Err(AttestationError::NoParticipants);
        }

        let sig_refs: Vec<&BlsSignature> = self.entries.iter().map(|(_, s)| s).collect();
        let agg_sig = AggregateSignature::aggregate(&sig_refs)
            .map_err(|_| AttestationError::AggregationFailed)?;

        // Build the participation bitfield.
        let max_index = self.entries.iter().map(|(i, _)| *i).max().unwrap_or(0);
        let bitfield_len = (max_index as usize / 8) + 1;
        let mut bitfield = vec![0u8; bitfield_len];
        for &(index, _) in &self.entries {
            let byte_idx = index as usize / 8;
            let bit_idx = index % 8;
            bitfield[byte_idx] |= 1 << bit_idx;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(AggregatedAttestation {
            block_hash: self.block_hash,
            block_number: self.block_number,
            receipts_root: self.receipts_root,
            aggregate_signature: agg_sig,
            participant_bitfield: bitfield,
            participant_count: self.entries.len() as u32,
            created_at_ms: now_ms,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("no participants in attestation")]
    NoParticipants,
    #[error("BLS signature aggregation failed")]
    AggregationFailed,
    #[error("invalid aggregate BLS signature")]
    InvalidAggregateSignature,
    #[error("invalid BLS public key in registry")]
    InvalidPublicKey,
    #[error("registry index {0} out of bounds")]
    RegistryIndexOutOfBounds(u32),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::sign_receipt;
    use n42_h2_primitives::BlsSecretKey;

    fn make_keys(n: usize) -> Vec<BlsSecretKey> {
        (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                BlsSecretKey::key_gen(&seed).unwrap()
            })
            .collect()
    }

    #[test]
    fn test_verifier_registry() {
        let mut reg = VerifierRegistry::new();
        let pk1 = [1u8; 48];
        let pk2 = [2u8; 48];

        assert_eq!(reg.register(pk1), 0);
        assert_eq!(reg.register(pk2), 1);
        assert_eq!(
            reg.register(pk1),
            0,
            "re-register should return existing index"
        );
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.index_of(&pk1), Some(0));
        assert_eq!(reg.index_of(&pk2), Some(1));
        assert_eq!(reg.pubkey_at(0), Some(&pk1));
        assert_eq!(reg.pubkey_at(2), None);
    }

    #[test]
    fn test_attestation_builder_basic() {
        let keys = make_keys(3);
        let block_hash = B256::from([0xAA; 32]);
        let block_number = 100u64;
        let receipts_root = B256::from([0xBB; 32]);

        let mut registry = VerifierRegistry::new();
        for key in &keys {
            registry.register(key.public_key().to_bytes());
        }

        let mut builder = AttestationBuilder::new(block_hash, block_number, receipts_root);

        for key in &keys {
            let receipt = sign_receipt(block_hash, block_number, receipts_root, 1000, key);
            assert!(builder.add_receipt(&receipt, &registry));
        }
        assert_eq!(builder.count(), 3);

        let attestation = builder.build().expect("build should succeed");
        assert_eq!(attestation.block_hash, block_hash);
        assert_eq!(attestation.block_number, block_number);
        assert_eq!(attestation.receipts_root, receipts_root);
        assert_eq!(attestation.participant_count, 3);

        // Verify the aggregate signature.
        attestation
            .verify(&registry)
            .expect("aggregate should verify");
    }

    #[test]
    fn test_attestation_builder_dedup() {
        let keys = make_keys(1);
        let block_hash = B256::from([0xCC; 32]);
        let receipts_root = B256::from([0xDD; 32]);

        let mut registry = VerifierRegistry::new();
        registry.register(keys[0].public_key().to_bytes());

        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);
        let receipt = sign_receipt(block_hash, 1, receipts_root, 1000, &keys[0]);

        assert!(builder.add_receipt(&receipt, &registry));
        assert!(
            !builder.add_receipt(&receipt, &registry),
            "duplicate should be rejected"
        );
        assert_eq!(builder.count(), 1);
    }

    #[test]
    fn test_attestation_builder_wrong_block() {
        let keys = make_keys(1);
        let block_hash = B256::from([0xEE; 32]);
        let wrong_hash = B256::from([0xFF; 32]);
        let receipts_root = B256::from([0x11; 32]);

        let mut registry = VerifierRegistry::new();
        registry.register(keys[0].public_key().to_bytes());

        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);
        let receipt = sign_receipt(wrong_hash, 1, receipts_root, 1000, &keys[0]);

        assert!(
            !builder.add_receipt(&receipt, &registry),
            "wrong block_hash should be rejected"
        );
    }

    #[test]
    fn test_attestation_builder_wrong_receipts_root() {
        let keys = make_keys(1);
        let block_hash = B256::from([0xAA; 32]);
        let receipts_root = B256::from([0xBB; 32]);
        let wrong_root = B256::from([0xCC; 32]);

        let mut registry = VerifierRegistry::new();
        registry.register(keys[0].public_key().to_bytes());

        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);
        let receipt = sign_receipt(block_hash, 1, wrong_root, 1000, &keys[0]);

        assert!(
            !builder.add_receipt(&receipt, &registry),
            "wrong receipts_root should be rejected"
        );
    }

    #[test]
    fn test_attestation_builder_unregistered_verifier() {
        let keys = make_keys(2);
        let block_hash = B256::from([0xAA; 32]);
        let receipts_root = B256::from([0xBB; 32]);

        let mut registry = VerifierRegistry::new();
        registry.register(keys[0].public_key().to_bytes());
        // keys[1] is NOT registered.

        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);
        let receipt = sign_receipt(block_hash, 1, receipts_root, 1000, &keys[1]);

        assert!(
            !builder.add_receipt(&receipt, &registry),
            "unregistered verifier should be rejected"
        );
    }

    #[test]
    fn test_attestation_builder_empty_fails() {
        let builder = AttestationBuilder::new(B256::ZERO, 0, B256::ZERO);
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_bitfield_encoding() {
        let keys = make_keys(10);
        let block_hash = B256::from([0xAA; 32]);
        let receipts_root = B256::from([0xBB; 32]);

        let mut registry = VerifierRegistry::new();
        for key in &keys {
            registry.register(key.public_key().to_bytes());
        }

        // Add only indices 0, 2, 9.
        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);
        for &i in &[0usize, 2, 9] {
            let receipt = sign_receipt(block_hash, 1, receipts_root, 1000, &keys[i]);
            builder.add_receipt(&receipt, &registry);
        }

        let attestation = builder.build().unwrap();
        assert_eq!(attestation.participant_count, 3);

        // Verify bitfield: bit 0, 2, 9 should be set.
        assert_eq!(attestation.participant_bitfield[0] & (1 << 0), 1 << 0);
        assert_eq!(attestation.participant_bitfield[0] & (1 << 1), 0);
        assert_eq!(attestation.participant_bitfield[0] & (1 << 2), 1 << 2);
        assert_eq!(attestation.participant_bitfield[1] & (1 << 1), 1 << 1); // bit 9 = byte 1, bit 1

        // Verify the aggregate signature.
        attestation
            .verify(&registry)
            .expect("aggregate should verify");
    }

    #[test]
    fn test_aggregated_attestation_serialization() {
        let keys = make_keys(2);
        let block_hash = B256::from([0xAA; 32]);
        let receipts_root = B256::from([0xBB; 32]);

        let mut registry = VerifierRegistry::new();
        for key in &keys {
            registry.register(key.public_key().to_bytes());
        }

        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);
        for key in &keys {
            let receipt = sign_receipt(block_hash, 1, receipts_root, 1000, key);
            builder.add_receipt(&receipt, &registry);
        }

        let attestation = builder.build().unwrap();

        let encoded = bincode::serialize(&attestation).expect("serialize");
        let decoded: AggregatedAttestation = bincode::deserialize(&encoded).expect("deserialize");

        assert_eq!(decoded.block_hash, attestation.block_hash);
        assert_eq!(decoded.block_number, attestation.block_number);
        assert_eq!(decoded.receipts_root, attestation.receipts_root);
        assert_eq!(decoded.participant_count, attestation.participant_count);
        assert_eq!(
            decoded.participant_bitfield,
            attestation.participant_bitfield
        );

        // Verify the deserialized attestation.
        decoded
            .verify(&registry)
            .expect("deserialized aggregate should verify");
    }

    #[test]
    fn test_different_timestamps_same_aggregate() {
        let keys = make_keys(3);
        let block_hash = B256::from([0xAA; 32]);
        let receipts_root = B256::from([0xBB; 32]);

        let mut registry = VerifierRegistry::new();
        for key in &keys {
            registry.register(key.public_key().to_bytes());
        }

        let mut builder = AttestationBuilder::new(block_hash, 1, receipts_root);

        // Each phone signs with a different timestamp — but the signing message
        // excludes timestamp, so all signatures are over the same 72-byte message.
        for (i, key) in keys.iter().enumerate() {
            let receipt = sign_receipt(block_hash, 1, receipts_root, 1000 + i as u64 * 500, key);
            builder.add_receipt(&receipt, &registry);
        }

        let attestation = builder.build().unwrap();
        attestation
            .verify(&registry)
            .expect("different timestamps should not affect aggregate verification");
    }
}

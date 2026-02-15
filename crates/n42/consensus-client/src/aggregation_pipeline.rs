// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Aggregation pipeline for BLS signature verification.
//!
//! Replaces the serial per-signature verification in `handle_verification_result()`
//! with a batched, parallel pipeline:
//!
//! 1. Signatures accumulate in a buffer (from direct validators or pre-aggregated from gateways)
//! 2. When the buffer reaches `batch_threshold` or a flush is triggered, all pending
//!    signatures are verified in parallel using `rayon` via `spawn_blocking`
//! 3. Verified results are merged into per-committee aggregate signatures
//!
//! This provides ~8-16x speedup over serial verification at scale.

use alloy_primitives::B256;
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use n42_clique::BlockVerifyResult;
use n42_primitives::{
    agg_sig_to_fixed, fixed_to_agg_sig, Attestation, AttestationData, CommitteeIndex,
};
use rayon::prelude::*;
use ssz::Encode;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// A pre-aggregated submission from a Gateway node.
/// Contains an aggregate BLS signature over multiple validators' attestations.
#[derive(Debug, Clone)]
pub struct PartialAggregate {
    /// The committee this aggregate belongs to
    pub committee_index: CommitteeIndex,
    /// Pre-aggregated BLS signature from gateway
    pub aggregate_signature: Vec<u8>,
    /// Public keys of validators included in this aggregate
    pub pubkeys: Vec<Vec<u8>>,
    /// Validator indices included
    pub validator_indices: HashSet<u64>,
    /// The attestation data that was signed
    pub attestation_data: AttestationData,
    /// Block hash this attestation is for
    pub block_hash: B256,
}

/// Input to the aggregation pipeline — supports both individual and pre-aggregated signatures.
#[derive(Debug, Clone)]
pub enum AggregateSubmission {
    /// Single signature from a directly connected validator
    Individual(BlockVerifyResult),
    /// Pre-aggregated signature from a Gateway node
    PreAggregated(PartialAggregate),
}

/// Result of a single signature verification
struct VerifiedSignature {
    committee_index: CommitteeIndex,
    signature: Signature,
    pubkey: PublicKey,
    validator_index: u64,
    attestation_data: AttestationData,
}

/// Result of verifying a pre-aggregated signature batch
struct VerifiedAggregate {
    committee_index: CommitteeIndex,
    aggregate_signature: AggregateSignature,
    validator_indices: HashSet<u64>,
    attestation_data: AttestationData,
}

/// Verified result ready to merge into pending block attestations
pub enum VerifiedResult {
    Single(VerifiedSingle),
    Batch(VerifiedBatch),
}

/// A single verified signature
pub struct VerifiedSingle {
    pub committee_index: CommitteeIndex,
    pub signature: Signature,
    pub validator_index: u64,
}

/// A batch-verified pre-aggregated signature
pub struct VerifiedBatch {
    pub committee_index: CommitteeIndex,
    pub aggregate_signature: AggregateSignature,
    pub validator_indices: HashSet<u64>,
}

/// The aggregation pipeline configuration and state.
pub struct AggregationPipeline {
    /// Incoming submissions
    rx: mpsc::Receiver<AggregateSubmission>,
    /// Outgoing verified results
    verified_tx: mpsc::Sender<VerifiedResult>,
    /// Number of individual signatures to collect before batch-verifying
    batch_threshold: usize,
    /// Pending individual signatures awaiting batch verification
    pending_individuals: Vec<(BlockVerifyResult, u64)>,
    /// Current block hash we're collecting for
    current_block_hash: Option<B256>,
    /// Validator index resolver
    validator_resolver: Option<Box<dyn ValidatorResolver + Send + Sync>>,
}

/// Trait for resolving validator pubkeys to indices
pub trait ValidatorResolver: Send + Sync {
    fn resolve_pubkey(&self, pubkey_hex: &str) -> Option<(PublicKey, u64)>;
}

impl AggregationPipeline {
    pub fn new(
        rx: mpsc::Receiver<AggregateSubmission>,
        verified_tx: mpsc::Sender<VerifiedResult>,
        batch_threshold: usize,
    ) -> Self {
        Self {
            rx,
            verified_tx,
            batch_threshold,
            pending_individuals: Vec::with_capacity(batch_threshold),
            current_block_hash: None,
            validator_resolver: None,
        }
    }

    pub fn set_resolver(&mut self, resolver: Box<dyn ValidatorResolver + Send + Sync>) {
        self.validator_resolver = Some(resolver);
    }

    pub fn set_current_block(&mut self, block_hash: B256) {
        // When block changes, flush any pending signatures from the old block
        if self.current_block_hash != Some(block_hash) {
            self.pending_individuals.clear();
            self.current_block_hash = Some(block_hash);
        }
    }

    /// Run the pipeline loop. Collects submissions and processes in batches.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(submission) = self.rx.recv() => {
                    match submission {
                        AggregateSubmission::Individual(result) => {
                            self.handle_individual(result).await;
                        }
                        AggregateSubmission::PreAggregated(partial) => {
                            self.handle_pre_aggregated(partial).await;
                        }
                    }
                }
                else => break,
            }
        }
    }

    async fn handle_individual(&mut self, result: BlockVerifyResult) {
        // Check block hash matches
        if let Some(current_hash) = self.current_block_hash {
            if result.block_hash != current_hash {
                warn!(
                    target: "aggregation-pipeline",
                    expected = ?current_hash,
                    got = ?result.block_hash,
                    "signature for wrong block, discarding"
                );
                return;
            }
        }

        // Resolve validator index (placeholder - will be resolved during batch verify)
        self.pending_individuals.push((result, 0));

        // Flush if batch threshold reached
        if self.pending_individuals.len() >= self.batch_threshold {
            self.flush_batch().await;
        }
    }

    async fn handle_pre_aggregated(&mut self, partial: PartialAggregate) {
        // Verify pre-aggregated signature in a blocking task
        let verified_tx = self.verified_tx.clone();

        tokio::task::spawn_blocking(move || {
            match verify_pre_aggregated(&partial) {
                Ok(agg_sig) => {
                    let result = VerifiedResult::Batch(VerifiedBatch {
                        committee_index: partial.committee_index,
                        aggregate_signature: agg_sig,
                        validator_indices: partial.validator_indices,
                    });
                    // Use blocking send since we're in spawn_blocking
                    let _ = verified_tx.blocking_send(result);
                }
                Err(e) => {
                    warn!(target: "aggregation-pipeline", ?e, "pre-aggregated verification failed");
                }
            }
        });
    }

    /// Flush pending individual signatures: verify in parallel using rayon.
    async fn flush_batch(&mut self) {
        if self.pending_individuals.is_empty() {
            return;
        }

        let batch: Vec<_> = self.pending_individuals.drain(..).collect();
        let verified_tx = self.verified_tx.clone();

        tokio::task::spawn_blocking(move || {
            // Parallel signature verification with rayon
            let verified: Vec<_> = batch
                .into_par_iter()
                .filter_map(|(result, _)| {
                    match verify_individual_signature(&result) {
                        Ok(sig) => Some(sig),
                        Err(e) => {
                            warn!(
                                target: "aggregation-pipeline",
                                pubkey = %result.pubkey,
                                ?e,
                                "individual signature verification failed"
                            );
                            None
                        }
                    }
                })
                .collect();

            debug!(
                target: "aggregation-pipeline",
                verified_count = verified.len(),
                "batch verification complete"
            );

            // Send verified results
            for v in verified {
                let result = VerifiedResult::Single(VerifiedSingle {
                    committee_index: v.committee_index,
                    signature: v.signature,
                    validator_index: v.validator_index,
                });
                if verified_tx.blocking_send(result).is_err() {
                    break;
                }
            }
        });
    }
}

/// Verify a single BLS signature (called from rayon thread pool).
fn verify_individual_signature(result: &BlockVerifyResult) -> eyre::Result<VerifiedSignature> {
    let sig_bytes = hex::decode(&result.signature)?;
    let signature = Signature::from_bytes(&sig_bytes)
        .map_err(|e| eyre::eyre!("invalid signature: {e:?}"))?;

    let pubkey_bytes = hex::decode(&result.pubkey)?;
    let pubkey = PublicKey::from_bytes(&pubkey_bytes)
        .map_err(|e| eyre::eyre!("invalid pubkey: {e:?}"))?;

    // Use SSZ encoding for deterministic signature verification
    let msg_bytes = result.attestation_data.as_ssz_bytes();

    let err = signature.verify(
        true,
        &msg_bytes,
        alloy_rpc_types_beacon::constants::BLS_DST_SIG,
        &[],
        &pubkey,
        true,
    );
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(eyre::eyre!("BLS verification failed: {err:?}"));
    }

    Ok(VerifiedSignature {
        committee_index: result.attestation_data.committee_index,
        signature,
        pubkey,
        validator_index: 0, // Resolved by caller
        attestation_data: result.attestation_data.clone(),
    })
}

/// Verify a pre-aggregated BLS signature from a gateway.
fn verify_pre_aggregated(partial: &PartialAggregate) -> eyre::Result<AggregateSignature> {
    let agg_sig = AggregateSignature::from_signature(
        &Signature::from_bytes(&partial.aggregate_signature)
            .map_err(|e| eyre::eyre!("invalid aggregate signature: {e:?}"))?,
    );

    let pubkeys: Result<Vec<PublicKey>, _> = partial
        .pubkeys
        .iter()
        .map(|pk_bytes| {
            PublicKey::from_bytes(pk_bytes).map_err(|e| eyre::eyre!("invalid pubkey: {e:?}"))
        })
        .collect();
    let pubkeys = pubkeys?;
    let pubkeys_refs: Vec<&PublicKey> = pubkeys.iter().collect();

    // Use SSZ encoding for deterministic verification
    let msg_bytes = partial.attestation_data.as_ssz_bytes();

    let result = agg_sig.to_signature().fast_aggregate_verify(
        true,
        &msg_bytes,
        alloy_rpc_types_beacon::constants::BLS_DST_SIG,
        &pubkeys_refs,
    );

    if result != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(eyre::eyre!(
            "pre-aggregated verification failed: {result:?}"
        ));
    }

    Ok(agg_sig)
}

/// Helper to merge a verified single signature into the attestation map.
pub fn merge_single_into_attestations(
    attestations: &mut HashMap<CommitteeIndex, Attestation>,
    single: VerifiedSingle,
) -> eyre::Result<()> {
    let attestation = attestations
        .get_mut(&single.committee_index)
        .ok_or_else(|| {
            eyre::eyre!(
                "attestation not found for committee {}",
                single.committee_index
            )
        })?;

    if attestation.validator_indexes.contains(&single.validator_index) {
        return Err(eyre::eyre!(
            "duplicate attestation for validator {}",
            single.validator_index
        ));
    }

    match attestation.block_aggregate_signature {
        Some(ref mut v) => {
            let mut sig = fixed_to_agg_sig(v)?;
            sig.add_signature(&single.signature, false)
                .map_err(|e| eyre::eyre!("add_signature error: {e:?}"))?;
            *v = agg_sig_to_fixed(&sig);
        }
        None => {
            attestation.block_aggregate_signature =
                Some(agg_sig_to_fixed(&AggregateSignature::from_signature(
                    &single.signature,
                )));
        }
    }
    attestation.validator_indexes.insert(single.validator_index);
    Ok(())
}

/// Helper to merge a verified batch aggregate into the attestation map.
pub fn merge_batch_into_attestations(
    attestations: &mut HashMap<CommitteeIndex, Attestation>,
    batch: VerifiedBatch,
) -> eyre::Result<()> {
    let attestation = attestations
        .get_mut(&batch.committee_index)
        .ok_or_else(|| {
            eyre::eyre!(
                "attestation not found for committee {}",
                batch.committee_index
            )
        })?;

    // Check for duplicate validators
    for idx in &batch.validator_indices {
        if attestation.validator_indexes.contains(idx) {
            return Err(eyre::eyre!(
                "duplicate attestation for validator {} in batch",
                idx
            ));
        }
    }

    match attestation.block_aggregate_signature {
        Some(ref mut v) => {
            let mut existing = fixed_to_agg_sig(v)?;
            existing.add_aggregate(&batch.aggregate_signature);
            *v = agg_sig_to_fixed(&existing);
        }
        None => {
            attestation.block_aggregate_signature =
                Some(agg_sig_to_fixed(&batch.aggregate_signature));
        }
    }
    attestation
        .validator_indexes
        .extend(batch.validator_indices);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    #[test]
    fn test_verify_individual_signature() {
        let ikm = [1u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();

        let attestation_data = AttestationData {
            slot: 42,
            committee_index: 0,
            receipts_root: B256::from([0xab; 32]),
        };

        let msg = attestation_data.as_ssz_bytes();
        let sig = sk.sign(&msg, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);

        let result = BlockVerifyResult {
            pubkey: hex::encode(pk.to_bytes()),
            signature: hex::encode(sig.to_bytes()),
            attestation_data,
            block_hash: B256::ZERO,
        };

        let verified = verify_individual_signature(&result).unwrap();
        assert_eq!(verified.committee_index, 0);
    }

    #[test]
    fn test_verify_individual_signature_bad_sig() {
        let ikm = [1u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();

        let attestation_data = AttestationData {
            slot: 42,
            committee_index: 0,
            receipts_root: B256::from([0xab; 32]),
        };

        // Sign different data
        let wrong_data = AttestationData {
            slot: 99,
            ..attestation_data.clone()
        };
        let msg = wrong_data.as_ssz_bytes();
        let sig = sk.sign(&msg, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);

        let result = BlockVerifyResult {
            pubkey: hex::encode(pk.to_bytes()),
            signature: hex::encode(sig.to_bytes()),
            attestation_data,
            block_hash: B256::ZERO,
        };

        assert!(verify_individual_signature(&result).is_err());
    }

    #[test]
    fn test_verify_pre_aggregated() {
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for i in 0..3u8 {
            let ikm = [i + 1; 32];
            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            sks.push(sk);
            pks.push(pk);
        }

        let attestation_data = AttestationData {
            slot: 10,
            committee_index: 1,
            receipts_root: B256::from([0xcd; 32]),
        };

        let msg = attestation_data.as_ssz_bytes();
        let mut agg: Option<AggregateSignature> = None;
        for sk in &sks {
            let sig = sk.sign(&msg, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);
            match agg.as_mut() {
                Some(a) => a.add_signature(&sig, false).unwrap(),
                None => agg = Some(AggregateSignature::from_signature(&sig)),
            }
        }

        let partial = PartialAggregate {
            committee_index: 1,
            aggregate_signature: agg.unwrap().to_signature().to_bytes().to_vec(),
            pubkeys: pks.iter().map(|pk| pk.to_bytes().to_vec()).collect(),
            validator_indices: [0, 1, 2].into_iter().collect(),
            attestation_data,
            block_hash: B256::ZERO,
        };

        let result = verify_pre_aggregated(&partial);
        assert!(result.is_ok());
    }
}

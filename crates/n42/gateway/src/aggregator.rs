// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Intermediate BLS signature aggregator.
//!
//! Collects individual BLS signatures from mobile validators and produces
//! PartialAggregates to submit to the APoS Miner.
//!
//! This reduces the miner's load from verifying N individual signatures
//! to verifying K aggregate signatures (where K = number of gateways).

use crate::miner_client::GatewayToMiner;
use alloy_primitives::B256;
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use n42_clique::BlockVerifyResult;
use n42_primitives::{AttestationData, CommitteeIndex};
use ssz::Encode;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Per-committee aggregation state
struct CommitteeAggregate {
    aggregate_signature: Option<AggregateSignature>,
    pubkeys: Vec<Vec<u8>>,
    validator_indices: HashSet<u64>,
    attestation_data: AttestationData,
    block_hash: B256,
}

/// Intermediate aggregator that collects signatures from validators
/// and periodically flushes partial aggregates to the miner.
pub struct Aggregator {
    /// Incoming individual signatures from mobile validators
    sig_rx: mpsc::Receiver<BlockVerifyResult>,
    /// Output channel for aggregated results to miner
    aggregate_tx: mpsc::Sender<GatewayToMiner>,
    /// Minimum signatures before flushing
    batch_size: usize,
    /// Per-committee aggregation state
    committees: HashMap<CommitteeIndex, CommitteeAggregate>,
    /// Current block hash
    current_block_hash: Option<B256>,
}

impl Aggregator {
    pub fn new(
        sig_rx: mpsc::Receiver<BlockVerifyResult>,
        aggregate_tx: mpsc::Sender<GatewayToMiner>,
        batch_size: usize,
    ) -> Self {
        Self {
            sig_rx,
            aggregate_tx,
            batch_size,
            committees: HashMap::new(),
            current_block_hash: None,
        }
    }

    /// Run the aggregation loop.
    pub async fn run(mut self) {
        while let Some(result) = self.sig_rx.recv().await {
            // Reset state on new block
            if self.current_block_hash != Some(result.block_hash) {
                self.flush_all().await;
                self.committees.clear();
                self.current_block_hash = Some(result.block_hash);
            }

            if let Err(e) = self.process_signature(result).await {
                warn!(target: "gateway-aggregator", ?e, "failed to process signature");
            }
        }
    }

    async fn process_signature(&mut self, result: BlockVerifyResult) -> eyre::Result<()> {
        // Verify the individual signature first
        let sig_bytes = hex::decode(&result.signature)?;
        let signature =
            Signature::from_bytes(&sig_bytes).map_err(|e| eyre::eyre!("invalid sig: {e:?}"))?;

        let pubkey_bytes = hex::decode(&result.pubkey)?;
        let pubkey = PublicKey::from_bytes(&pubkey_bytes)
            .map_err(|e| eyre::eyre!("invalid pubkey: {e:?}"))?;

        // Verify signature using SSZ encoding
        let msg_bytes = result.attestation_data.as_ssz_bytes();
        let verify_result = signature.verify(
            true,
            &msg_bytes,
            alloy_rpc_types_beacon::constants::BLS_DST_SIG,
            &[],
            &pubkey,
            true,
        );
        if verify_result != blst::BLST_ERROR::BLST_SUCCESS {
            return Err(eyre::eyre!("BLS verification failed: {verify_result:?}"));
        }

        // Add to committee aggregate
        let committee_index = result.attestation_data.committee_index;
        let committee = self
            .committees
            .entry(committee_index)
            .or_insert_with(|| CommitteeAggregate {
                aggregate_signature: None,
                pubkeys: Vec::new(),
                validator_indices: HashSet::new(),
                attestation_data: result.attestation_data.clone(),
                block_hash: result.block_hash,
            });

        match committee.aggregate_signature.as_mut() {
            Some(agg) => {
                agg.add_signature(&signature, false)
                    .map_err(|e| eyre::eyre!("add_signature error: {e:?}"))?;
            }
            None => {
                committee.aggregate_signature =
                    Some(AggregateSignature::from_signature(&signature));
            }
        }
        committee.pubkeys.push(pubkey_bytes);
        // validator_index would be resolved by the miner, we pass 0 placeholder
        committee.validator_indices.insert(0);

        debug!(
            target: "gateway-aggregator",
            committee_index,
            count = committee.pubkeys.len(),
            "signature aggregated"
        );

        // Flush if batch size reached
        if committee.pubkeys.len() >= self.batch_size {
            self.flush_committee(committee_index).await;
        }

        Ok(())
    }

    async fn flush_committee(&mut self, committee_index: CommitteeIndex) {
        if let Some(committee) = self.committees.remove(&committee_index) {
            if let Some(agg_sig) = committee.aggregate_signature {
                let msg = GatewayToMiner::PartialAggregate {
                    committee_index,
                    aggregate_signature: agg_sig.to_signature().to_bytes().to_vec(),
                    pubkeys: committee.pubkeys,
                    validator_indices: committee.validator_indices.into_iter().collect(),
                    attestation_data: committee.attestation_data,
                    block_hash: committee.block_hash,
                };

                if let Err(e) = self.aggregate_tx.send(msg).await {
                    warn!(target: "gateway-aggregator", ?e, "failed to send aggregate to miner");
                }

                debug!(
                    target: "gateway-aggregator",
                    committee_index,
                    "flushed partial aggregate to miner"
                );
            }
        }
    }

    async fn flush_all(&mut self) {
        let indices: Vec<_> = self.committees.keys().copied().collect();
        for idx in indices {
            self.flush_committee(idx).await;
        }
    }
}

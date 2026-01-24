// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block and header validation
//!
//! This module provides validation functions for beacon blocks and headers.

use crate::{ConsensusError, ConsensusResult};
use alloy_primitives::{BlockHash, B256};
use n42_primitives::{Attestation, BeaconBlock, BeaconState, SLOTS_PER_EPOCH};

/// Validate a beacon block against the current state
pub fn validate_beacon_block(state: &BeaconState, block: &BeaconBlock) -> ConsensusResult<()> {
    // Validate slot
    if block.slot <= state.slot {
        return Err(ConsensusError::InvalidSlot {
            expected: state.slot + 1,
            actual: block.slot,
        });
    }

    // Validate parent hash
    // Note: actual parent hash validation requires looking up the parent block

    // Validate attestations
    for attestation in &block.body.attestations {
        validate_attestation(state, attestation)?;
    }

    Ok(())
}

/// Validate an attestation against the current state
pub fn validate_attestation(state: &BeaconState, attestation: &Attestation) -> ConsensusResult<()> {
    // Attestations should be from the current or previous epoch
    let current_epoch = state.slot / SLOTS_PER_EPOCH;
    let attestation_epoch = attestation.data.slot / SLOTS_PER_EPOCH;

    if attestation_epoch > current_epoch {
        return Err(ConsensusError::InvalidAttestation(format!(
            "attestation from future epoch: {attestation_epoch} > {current_epoch}"
        )));
    }

    if current_epoch > attestation_epoch + 1 {
        return Err(ConsensusError::InvalidAttestation(format!(
            "attestation too old: epoch {attestation_epoch} vs current {current_epoch}"
        )));
    }

    Ok(())
}

/// Validate block state root
pub fn validate_state_root(
    computed_state: &BeaconState,
    block: &BeaconBlock,
) -> ConsensusResult<()> {
    use alloy_primitives::Sealable;
    let computed_root = computed_state.hash_slow();

    if computed_root != block.state_root {
        return Err(ConsensusError::InvalidStateRoot {
            expected: block.state_root,
            actual: computed_root,
        });
    }

    Ok(())
}

/// Validate parent hash against expected value
pub fn validate_parent_hash(expected: BlockHash, actual: BlockHash) -> ConsensusResult<()> {
    if expected != actual {
        return Err(ConsensusError::InvalidParentHash { expected, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_primitives::AttestationData;

    #[test]
    fn test_validate_beacon_block_invalid_slot() {
        let state = BeaconState {
            slot: 100,
            ..Default::default()
        };
        let block = BeaconBlock {
            slot: 100, // Same as state, should fail
            ..Default::default()
        };

        let result = validate_beacon_block(&state, &block);
        assert!(matches!(result, Err(ConsensusError::InvalidSlot { .. })));
    }

    #[test]
    fn test_validate_beacon_block_valid_slot() {
        let state = BeaconState {
            slot: 100,
            ..Default::default()
        };
        let block = BeaconBlock {
            slot: 101,
            ..Default::default()
        };

        let result = validate_beacon_block(&state, &block);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_attestation_future_epoch() {
        let state = BeaconState {
            slot: 32, // Epoch 1
            ..Default::default()
        };
        let attestation = Attestation {
            data: AttestationData {
                slot: 64, // Epoch 2 (future)
                ..Default::default()
            },
            ..Default::default()
        };

        let result = validate_attestation(&state, &attestation);
        assert!(matches!(result, Err(ConsensusError::InvalidAttestation(_))));
    }

    #[test]
    fn test_validate_attestation_old_epoch() {
        let state = BeaconState {
            slot: 96, // Epoch 3
            ..Default::default()
        };
        let attestation = Attestation {
            data: AttestationData {
                slot: 0, // Epoch 0 (too old)
                ..Default::default()
            },
            ..Default::default()
        };

        let result = validate_attestation(&state, &attestation);
        assert!(matches!(result, Err(ConsensusError::InvalidAttestation(_))));
    }

    #[test]
    fn test_validate_parent_hash() {
        let hash1 = B256::from([1u8; 32]);
        let hash2 = B256::from([2u8; 32]);

        assert!(validate_parent_hash(hash1, hash1).is_ok());
        assert!(validate_parent_hash(hash1, hash2).is_err());
    }
}

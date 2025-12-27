// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! State transition functions
//!
//! This module provides traits and utilities for beacon chain state transitions.

use crate::ConsensusResult;
use alloy_primitives::{BlockHash, B256};
use n42_primitives::{BeaconBlock, BeaconState, Epoch, SLOTS_PER_EPOCH};

/// Slot number type
pub type Slot = u64;

/// State transition trait
///
/// Defines the interface for performing state transitions on the beacon chain.
pub trait StateTransition {
    /// The provider type for accessing blockchain state
    type Provider;

    /// Perform a state transition given the current state and a new block
    fn state_transition(
        &self,
        old_state: Option<BeaconState>,
        block: &BeaconBlock,
    ) -> ConsensusResult<BeaconState>;

    /// Get the state for a given block hash
    fn get_state(&self, block_hash: BlockHash) -> ConsensusResult<Option<BeaconState>>;

    /// Save the state for a given block hash
    fn save_state(&self, block_hash: BlockHash, state: &BeaconState) -> ConsensusResult<()>;
}

/// Calculate epoch from slot
#[inline]
pub fn slot_to_epoch(slot: Slot) -> Epoch {
    slot / SLOTS_PER_EPOCH
}

/// Calculate the first slot of an epoch
#[inline]
pub fn epoch_start_slot(epoch: Epoch) -> Slot {
    epoch * SLOTS_PER_EPOCH
}

/// Check if a slot is at an epoch boundary
#[inline]
pub fn is_epoch_boundary(slot: Slot) -> bool {
    slot % SLOTS_PER_EPOCH == 0
}

/// Calculate the number of slots until the next epoch
#[inline]
pub fn slots_until_next_epoch(slot: Slot) -> Slot {
    SLOTS_PER_EPOCH - (slot % SLOTS_PER_EPOCH)
}

/// State root calculation
pub fn calculate_state_root(state: &BeaconState) -> B256 {
    use alloy_primitives::Sealable;
    state.hash_slow()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_to_epoch() {
        assert_eq!(slot_to_epoch(0), 0);
        assert_eq!(slot_to_epoch(31), 0);
        assert_eq!(slot_to_epoch(32), 1);
        assert_eq!(slot_to_epoch(64), 2);
    }

    #[test]
    fn test_epoch_start_slot() {
        assert_eq!(epoch_start_slot(0), 0);
        assert_eq!(epoch_start_slot(1), 32);
        assert_eq!(epoch_start_slot(2), 64);
    }

    #[test]
    fn test_is_epoch_boundary() {
        assert!(is_epoch_boundary(0));
        assert!(is_epoch_boundary(32));
        assert!(is_epoch_boundary(64));
        assert!(!is_epoch_boundary(1));
        assert!(!is_epoch_boundary(31));
    }

    #[test]
    fn test_slots_until_next_epoch() {
        assert_eq!(slots_until_next_epoch(0), 32);
        assert_eq!(slots_until_next_epoch(1), 31);
        assert_eq!(slots_until_next_epoch(31), 1);
        assert_eq!(slots_until_next_epoch(32), 32);
    }
}

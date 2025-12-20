// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for N42 consensus core module

use crate::*;
use alloy_primitives::B256;
use n42_consensus_traits::AposError;

mod error_tests {
    use super::*;

    #[test]
    fn test_consensus_error_display() {
        let err = ConsensusError::StateTransitionFailed("test".to_string());
        assert!(format!("{}", err).contains("state transition failed"));

        let err = ConsensusError::InvalidBlock("bad block".to_string());
        assert!(format!("{}", err).contains("invalid block"));

        let err = ConsensusError::InvalidSlot { expected: 10, actual: 5 };
        assert!(format!("{}", err).contains("expected >= 10"));
    }

    #[test]
    fn test_consensus_error_is_recoverable() {
        assert!(ConsensusError::ParentStateNotFound(B256::ZERO).is_recoverable());
        assert!(ConsensusError::BlockNotFound(B256::ZERO).is_recoverable());

        assert!(!ConsensusError::InvalidBlock("test".to_string()).is_recoverable());
        assert!(!ConsensusError::InvalidSlot { expected: 10, actual: 5 }.is_recoverable());
    }

    #[test]
    fn test_consensus_error_is_validation_error() {
        assert!(ConsensusError::InvalidBlock("test".to_string()).is_validation_error());
        assert!(ConsensusError::InvalidHeader("test".to_string()).is_validation_error());
        assert!(ConsensusError::InvalidAttestation("test".to_string()).is_validation_error());
        assert!(ConsensusError::InvalidSlot { expected: 10, actual: 5 }.is_validation_error());

        assert!(!ConsensusError::ParentStateNotFound(B256::ZERO).is_validation_error());
        assert!(!ConsensusError::Other("test".to_string()).is_validation_error());
    }

    #[test]
    fn test_consensus_error_from_apos_error() {
        let apos_err = AposError::NoSignerSet;
        let err: ConsensusError = apos_err.into();
        assert!(matches!(err, ConsensusError::AposError(_)));
    }
}

mod state_tests {
    use super::*;
    use n42_primitives::SLOTS_PER_EPOCH;

    #[test]
    fn test_slot_epoch_conversions() {
        // Test slot to epoch
        assert_eq!(slot_to_epoch(0), 0);
        assert_eq!(slot_to_epoch(SLOTS_PER_EPOCH - 1), 0);
        assert_eq!(slot_to_epoch(SLOTS_PER_EPOCH), 1);
        assert_eq!(slot_to_epoch(SLOTS_PER_EPOCH * 2), 2);

        // Test epoch start slot
        assert_eq!(epoch_start_slot(0), 0);
        assert_eq!(epoch_start_slot(1), SLOTS_PER_EPOCH);
        assert_eq!(epoch_start_slot(2), SLOTS_PER_EPOCH * 2);
    }

    #[test]
    fn test_is_epoch_boundary() {
        assert!(is_epoch_boundary(0));
        assert!(is_epoch_boundary(SLOTS_PER_EPOCH));
        assert!(is_epoch_boundary(SLOTS_PER_EPOCH * 2));

        assert!(!is_epoch_boundary(1));
        assert!(!is_epoch_boundary(SLOTS_PER_EPOCH - 1));
        assert!(!is_epoch_boundary(SLOTS_PER_EPOCH + 1));
    }

    #[test]
    fn test_slots_until_next_epoch() {
        assert_eq!(slots_until_next_epoch(0), SLOTS_PER_EPOCH);
        assert_eq!(slots_until_next_epoch(1), SLOTS_PER_EPOCH - 1);
        assert_eq!(slots_until_next_epoch(SLOTS_PER_EPOCH - 1), 1);
        assert_eq!(slots_until_next_epoch(SLOTS_PER_EPOCH), SLOTS_PER_EPOCH);
    }
}


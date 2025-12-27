// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for N42 storage module

use crate::*;
use alloy_primitives::{Address, B256};

mod error_tests {
    use super::*;

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::BeaconStateNotFound(B256::ZERO);
        assert!(format!("{}", err).contains("beacon state not found"));

        let err = StorageError::BeaconBlockNotFound(B256::ZERO);
        assert!(format!("{}", err).contains("beacon block not found"));

        let err = StorageError::ValidatorNotFound("test".to_string());
        assert!(format!("{}", err).contains("validator not found"));
    }

    #[test]
    fn test_storage_error_is_not_found() {
        assert!(StorageError::BeaconStateNotFound(B256::ZERO).is_not_found());
        assert!(StorageError::BeaconBlockNotFound(B256::ZERO).is_not_found());
        assert!(StorageError::ValidatorNotFound("test".to_string()).is_not_found());
        assert!(StorageError::BlockNum2HashNotFound(100).is_not_found());

        assert!(!StorageError::other("test").is_not_found());
        assert!(!StorageError::DatabaseError("test".to_string()).is_not_found());
    }

    #[test]
    fn test_storage_error_other() {
        let err = StorageError::other("custom error");
        assert_eq!(format!("{}", err), "storage error: custom error");
    }
}

mod table_tests {
    use super::*;
    use crate::tables::names;

    #[test]
    fn test_table_names() {
        assert_eq!(names::BEACON_STATE, "BeaconStateRecord");
        assert_eq!(names::BEACON_BLOCK, "BeaconBlockRecord");
        assert_eq!(names::BEACON_NUM_TO_HASH, "BeaconNum2Hash");
        assert_eq!(names::PLAIN_VALIDATOR_STATE, "PlainValidatorState");
        assert_eq!(names::VALIDATORS_HISTORY, "ValidatorsHistory");
        assert_eq!(names::VALIDATOR_CHANGE_SETS, "ValidatorChangeSets");
    }

    #[test]
    fn test_n42_tables_count() {
        assert_eq!(N42_TABLES.len(), 6);
    }

    #[test]
    fn test_n42_tables_contains_all() {
        assert!(N42_TABLES.contains(&names::BEACON_STATE));
        assert!(N42_TABLES.contains(&names::BEACON_BLOCK));
        assert!(N42_TABLES.contains(&names::BEACON_NUM_TO_HASH));
        assert!(N42_TABLES.contains(&names::PLAIN_VALIDATOR_STATE));
        assert!(N42_TABLES.contains(&names::VALIDATORS_HISTORY));
        assert!(N42_TABLES.contains(&names::VALIDATOR_CHANGE_SETS));
    }
}

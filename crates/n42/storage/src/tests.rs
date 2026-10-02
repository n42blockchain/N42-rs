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

mod table_id_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn table_ids_map_to_names_in_declaration_order() {
        let expected = N42_TABLES;
        let ids = N42TableId::all();
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(id.name(), expected[i]);
            assert_eq!(*id as u8 as usize, i, "discriminant matches position");
        }
    }

    #[test]
    fn table_names_are_unique_and_display_matches_name() {
        let names: HashSet<_> = N42_TABLES.iter().collect();
        assert_eq!(names.len(), N42_TABLES.len());
        for id in N42TableId::all() {
            assert_eq!(id.to_string(), id.name());
        }
        assert_eq!(N42TableId::BeaconNum2Hash.to_string(), "BeaconNum2Hash");
    }
}

mod error_variant_tests {
    use super::*;

    #[test]
    fn display_carries_the_payload_for_every_variant() {
        let h = B256::repeat_byte(0xab);
        assert_eq!(
            StorageError::BeaconStateNotFound(h).to_string(),
            format!("beacon state not found for block {h}")
        );
        assert_eq!(
            StorageError::BlockNum2HashNotFound(7).to_string(),
            "block number 7 to hash mapping not found"
        );
        assert_eq!(
            StorageError::SerializationError("a".into()).to_string(),
            "serialization error: a"
        );
        assert_eq!(
            StorageError::DeserializationError("b".into()).to_string(),
            "deserialization error: b"
        );
        assert_eq!(
            StorageError::DatabaseError("c".into()).to_string(),
            "database error: c"
        );
        assert_eq!(
            StorageError::ValidatorNotFound("v".into()).to_string(),
            "validator not found: v"
        );
    }

    #[test]
    fn serialization_and_deserialization_errors_are_not_not_found() {
        assert!(!StorageError::SerializationError("x".into()).is_not_found());
        assert!(!StorageError::DeserializationError("x".into()).is_not_found());
    }

    #[test]
    fn other_accepts_string_and_str() {
        assert_eq!(StorageError::other(String::from("s")), StorageError::Other("s".into()));
        assert_eq!(StorageError::other("s"), StorageError::Other("s".into()));
    }

    #[test]
    fn serde_json_error_converts_to_serialization_error() {
        let e = serde_json::from_str::<u32>("nope").unwrap_err();
        let msg = e.to_string();
        match StorageError::from(e) {
            StorageError::SerializationError(m) => assert_eq!(m, msg),
            other => panic!("unexpected variant {other:?}"),
        }
    }
}

mod codec_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn json_roundtrip_preserves_value() {
        let mut m = BTreeMap::new();
        m.insert("a".to_string(), vec![1u64, 2, 3]);
        m.insert("b".to_string(), vec![]);
        let bytes = encode_json(&m).unwrap();
        assert_eq!(bytes, br#"{"a":[1,2,3],"b":[]}"#);
        let back: BTreeMap<String, Vec<u64>> = decode_json(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn decode_json_rejects_wrong_shape_and_garbage() {
        let err = decode_json::<Vec<u8>>(b"{\"a\":1}").unwrap_err();
        assert!(matches!(err, StorageError::SerializationError(_)));
        assert!(decode_json::<u32>(b"").is_err());
        assert!(decode_json::<u32>(b"1 2").is_err(), "trailing data is refused");
    }

    #[test]
    fn beacon_block_and_state_decode_errors_are_typed() {
        assert!(matches!(
            decode_beacon_block(b"{}"),
            Err(StorageError::SerializationError(_))
        ));
        assert!(matches!(
            decode_beacon_state(b"[1]"),
            Err(StorageError::SerializationError(_))
        ));
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Comprehensive tests for Fusaka hardfork support

use crate::*;
use alloy_primitives::{Address, B256};

mod hardfork_tests {
    use super::*;

    #[test]
    fn test_osaka_after_prague() {
        // Osaka (CL) should activate after Prague (EL)
        assert!(N42_OSAKA_TIMESTAMP > N42_PRAGUE_TIMESTAMP);

        // Time difference should be reasonable (about 1 month)
        let diff = N42_OSAKA_TIMESTAMP - N42_PRAGUE_TIMESTAMP;
        assert!(diff > 0);
        assert!(diff < 60 * 60 * 24 * 60); // Less than 60 days
    }

    #[test]
    fn test_osaka_timestamp_valid() {
        // 2025-07-01 00:00:00 UTC
        assert_eq!(N42_OSAKA_TIMESTAMP, 1751328000);

        // Verify it's in the future (as of code writing)
        // and a reasonable date
        assert!(N42_OSAKA_TIMESTAMP > 1700000000); // After 2023
        assert!(N42_OSAKA_TIMESTAMP < 2000000000); // Before 2033
    }
}

mod bls_precompile_tests {
    use super::*;

    #[test]
    fn test_all_bls_addresses_unique() {
        let addresses = &BLS_PRECOMPILE_ADDRESSES;
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(
                    addresses[i], addresses[j],
                    "Addresses at {} and {} should be different",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_bls_addresses_sequential() {
        // BLS precompiles are 0x0b through 0x13
        for (i, addr) in BLS_PRECOMPILE_ADDRESSES.iter().enumerate() {
            let expected_byte = 0x0b + i as u8;
            assert_eq!(
                addr.as_slice()[19],
                expected_byte,
                "Address {} should end with 0x{:02x}",
                i,
                expected_byte
            );
        }
    }

    #[test]
    fn test_bls_error_display() {
        let err = BlsError::InvalidInputLength {
            expected: 128,
            actual: 64,
        };
        assert!(format!("{}", err).contains("128"));
        assert!(format!("{}", err).contains("64"));

        let err = BlsError::InvalidG1Point;
        assert!(format!("{}", err).contains("G1"));
    }

    #[test]
    fn test_all_precompile_names() {
        for addr in &BLS_PRECOMPILE_ADDRESSES {
            let name = bls_precompile_name(addr);
            assert!(name.is_some(), "Address {:?} should have a name", addr);
            assert!(
                name.unwrap().starts_with("BLS12_"),
                "Name should start with BLS12_"
            );
        }
    }
}

mod gas_calculation_tests {
    use super::*;

    #[test]
    fn test_g1_operations_gas() {
        assert_eq!(BLS12_G1ADD_GAS, 500);
        assert_eq!(BLS12_G1MUL_GAS, 12000);
    }

    #[test]
    fn test_g2_operations_gas() {
        assert_eq!(BLS12_G2ADD_GAS, 800);
        assert_eq!(BLS12_G2MUL_GAS, 45000);
    }

    #[test]
    fn test_multiexp_gas_discount() {
        // More pairs should have better per-pair gas efficiency
        let gas_1 = g1_multiexp_gas(1);
        let gas_2 = g1_multiexp_gas(2);
        let gas_4 = g1_multiexp_gas(4);

        // Per-pair cost should decrease with more pairs
        let per_pair_1 = gas_1 / 1;
        let per_pair_2 = gas_2 / 2;
        let per_pair_4 = gas_4 / 4;

        assert!(
            per_pair_2 < per_pair_1,
            "2 pairs should be cheaper per pair than 1"
        );
        assert!(
            per_pair_4 < per_pair_2,
            "4 pairs should be cheaper per pair than 2"
        );
    }

    #[test]
    fn test_pairing_gas_linear() {
        let gas_1 = pairing_gas(1);
        let gas_2 = pairing_gas(2);
        let gas_3 = pairing_gas(3);

        // Pairing gas should increase linearly
        assert_eq!(gas_2 - gas_1, BLS12_PAIRING_PAIR_GAS);
        assert_eq!(gas_3 - gas_2, BLS12_PAIRING_PAIR_GAS);
    }
}

mod input_validation_tests {
    use super::*;

    #[test]
    fn test_g1add_input_sizes() {
        let valid = vec![0u8; G1_POINT_SIZE * 2];
        assert!(validate_g1add_input(&valid).is_ok());

        // Too short
        let short = vec![0u8; G1_POINT_SIZE];
        assert!(validate_g1add_input(&short).is_err());

        // Too long
        let long = vec![0u8; G1_POINT_SIZE * 3];
        assert!(validate_g1add_input(&long).is_err());

        // Empty
        let empty: Vec<u8> = vec![];
        assert!(validate_g1add_input(&empty).is_err());
    }

    #[test]
    fn test_g2add_input_sizes() {
        let valid = vec![0u8; G2_POINT_SIZE * 2];
        assert!(validate_g2add_input(&valid).is_ok());

        let invalid = vec![0u8; G2_POINT_SIZE];
        assert!(validate_g2add_input(&invalid).is_err());
    }

    #[test]
    fn test_map_fp_input_sizes() {
        let valid = vec![0u8; FP_SIZE];
        assert!(validate_map_fp_to_g1_input(&valid).is_ok());

        let invalid = vec![0u8; FP_SIZE - 1];
        assert!(validate_map_fp_to_g1_input(&invalid).is_err());
    }

    #[test]
    fn test_map_fp2_input_sizes() {
        let valid = vec![0u8; FP2_SIZE];
        assert!(validate_map_fp2_to_g2_input(&valid).is_ok());

        let invalid = vec![0u8; FP2_SIZE + 1];
        assert!(validate_map_fp2_to_g2_input(&invalid).is_err());
    }
}

mod peerdas_tests {
    use super::*;

    #[test]
    fn test_column_constants() {
        assert_eq!(NUMBER_OF_COLUMNS, 128);
        assert_eq!(CELLS_PER_EXT_BLOB, 128);
    }

    #[test]
    fn test_osaka_blob_params_consistency() {
        let params = OsakaBlobParams::new();

        // Target should be less than max
        assert!(params.target_blob_count < params.max_blob_count);

        // Per-tx max should not exceed block max
        assert!(params.max_blobs_per_tx <= params.max_blob_count);
    }

    #[test]
    fn test_custody_columns_deterministic() {
        let node_id = B256::from([42u8; 32]);
        let columns1 = custody_columns(&node_id, 4);
        let columns2 = custody_columns(&node_id, 4);

        assert_eq!(columns1, columns2, "Same node ID should get same columns");
    }

    #[test]
    fn test_custody_columns_different_nodes() {
        let node1 = B256::from([1u8; 32]);
        let node2 = B256::from([2u8; 32]);

        let columns1 = custody_columns(&node1, 4);
        let columns2 = custody_columns(&node2, 4);

        // Different nodes should likely have different columns
        // (not guaranteed but highly probable)
        assert_ne!(columns1, columns2);
    }

    #[test]
    fn test_data_column_validation() {
        let mut column = DataColumn::new(0).unwrap();
        assert!(column.is_valid());

        // Add mismatched data
        column.cells.push(vec![0u8; 32]);
        assert!(!column.is_valid());

        // Fix by adding proof
        column.proofs.push(B256::ZERO);
        assert!(column.is_valid());
    }

    #[test]
    fn test_samples_needed_scaling() {
        // More blobs need more samples
        let samples_1 = samples_needed_for_availability(1);
        let samples_2 = samples_needed_for_availability(2);
        let samples_3 = samples_needed_for_availability(3);

        assert!(samples_2 > samples_1);
        assert!(samples_3 > samples_2);
    }
}

mod integration_tests {
    use super::*;

    #[test]
    fn test_fusaka_complete_feature_set() {
        // Verify all Fusaka features are available

        // 1. BLS precompiles
        assert_eq!(BLS_PRECOMPILE_ADDRESSES.len(), 9);

        // 2. PeerDAS constants
        assert!(NUMBER_OF_COLUMNS > 0);
        assert!(CELLS_PER_EXT_BLOB > 0);

        // 3. Osaka blob params
        let params = OsakaBlobParams::new();
        assert!(params.max_blob_count > 0);

        // 4. Timestamps configured
        assert!(N42_OSAKA_TIMESTAMP > 0);
        assert!(N42_PRAGUE_TIMESTAMP > 0);
    }

    #[test]
    fn test_blob_capacity_increase() {
        // Cancun: target=3, max=6
        // Osaka: target=6, max=9

        assert_eq!(OSAKA_TARGET_BLOB_COUNT, 6);
        assert_eq!(OSAKA_MAX_BLOB_COUNT, 9);

        // Verify increase from Cancun
        let cancun_max = 6u64;
        assert!(OSAKA_MAX_BLOB_COUNT > cancun_max);
    }
}

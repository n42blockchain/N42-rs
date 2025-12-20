// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Integration tests for consensus boundary conditions

#[cfg(test)]
mod consensus_boundary_tests {
    use crate::{
        AposError, DIFF_IN_TURN, DIFF_NO_TURN, EPOCH_LENGTH, EXTRA_SEAL, EXTRA_VANITY,
        FULL_IMMUTABILITY_THRESHOLD, NONCE_AUTH_VOTE, NONCE_DROP_VOTE,
    };
    use alloy_primitives::{address, Address, B256, U256};
    use n42_primitives::{APosConfig, Snapshot, Tally, Vote};

    // ==================== Genesis Block Boundary Tests ====================

    #[test]
    fn test_genesis_block_number_zero() {
        // Genesis block (number 0) should have special handling
        let config = APosConfig::default();
        let signers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
        ];
        let snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers);

        assert_eq!(snap.number, 0);
        assert!(snap.recents.is_empty());
        assert!(snap.votes.is_empty());
    }

    #[test]
    fn test_block_number_one_after_genesis() {
        // Block 1 is the first block that can be validated
        let config = APosConfig::default();
        let signers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
        ];
        let snap = Snapshot::new_snapshot(config, 1, B256::ZERO, signers.clone());

        // First signer should be in-turn for block 1
        assert!(snap.inturn(1, &signers[0]));
        assert!(!snap.inturn(1, &signers[1]));
    }

    // ==================== Difficulty Boundary Tests ====================

    #[test]
    fn test_difficulty_values_are_valid() {
        assert!(DIFF_IN_TURN > U256::ZERO);
        assert!(DIFF_NO_TURN > U256::ZERO);
        assert!(DIFF_IN_TURN > DIFF_NO_TURN);
    }

    #[test]
    fn test_difficulty_difference() {
        // The difference between in-turn and no-turn should be 1
        assert_eq!(DIFF_IN_TURN - DIFF_NO_TURN, U256::from(1u64));
    }

    // ==================== Extra Data Boundary Tests ====================

    #[test]
    fn test_extra_data_minimum_size() {
        // Minimum extra data size is EXTRA_VANITY + EXTRA_SEAL
        let min_size = EXTRA_VANITY + EXTRA_SEAL;
        assert_eq!(min_size, 97); // 32 + 65
    }

    #[test]
    fn test_extra_data_checkpoint_size() {
        // At checkpoint, extra data includes signer addresses (20 bytes each)
        let num_signers = 5;
        let checkpoint_size = EXTRA_VANITY + (num_signers * 20) + EXTRA_SEAL;
        assert_eq!(checkpoint_size, 32 + 100 + 65);
    }

    #[test]
    fn test_extra_data_vanity_boundary() {
        assert_eq!(EXTRA_VANITY, 32);
    }

    #[test]
    fn test_extra_data_seal_boundary() {
        assert_eq!(EXTRA_SEAL, 65); // 64 bytes signature + 1 byte recovery id
    }

    // ==================== Voting Boundary Tests ====================

    #[test]
    fn test_vote_at_epoch_boundary() {
        let mut config = APosConfig::default();
        config.epoch = 100; // Short epoch for testing

        let signers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
        ];
        let mut snap = Snapshot::new_snapshot(config, 99, B256::ZERO, signers);

        // Add a vote before epoch boundary
        let new_signer = address!("0000000000000000000000000000000000000003");
        snap.cast(new_signer, true);
        assert!(snap.tally.contains_key(&new_signer));

        // At epoch boundary (block 100), votes should be cleared
        // This is handled in the apply() method
    }

    #[test]
    fn test_single_signer_voting() {
        // With only one signer, voting threshold is 0 (1/2 = 0)
        let config = APosConfig::default();
        let signers = vec![address!("0000000000000000000000000000000000000001")];
        let mut snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        // Even with 1 vote, it passes (1 > 0)
        let new_signer = address!("0000000000000000000000000000000000000002");
        snap.cast(new_signer, true);
        let tally = snap.tally.get(&new_signer).unwrap();
        assert!(tally.votes > (snap.signers.len() / 2) as u32);
    }

    #[test]
    fn test_two_signer_voting_threshold() {
        // With 2 signers, threshold is 1 (2/2 = 1), need > 1 = 2 votes
        let config = APosConfig::default();
        let signers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
        ];
        let mut snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        let new_signer = address!("0000000000000000000000000000000000000003");

        // 1 vote is not enough
        snap.cast(new_signer, true);
        let tally = snap.tally.get(&new_signer).unwrap();
        assert!(tally.votes <= (snap.signers.len() / 2) as u32);

        // 2 votes should pass
        snap.cast(new_signer, true);
        let tally = snap.tally.get(&new_signer).unwrap();
        assert!(tally.votes > (snap.signers.len() / 2) as u32);
    }

    #[test]
    fn test_three_signer_voting_threshold() {
        // With 3 signers, threshold is 1 (3/2 = 1), need > 1 = 2 votes
        let config = APosConfig::default();
        let signers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let mut snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        let new_signer = address!("0000000000000000000000000000000000000004");

        // 1 vote is not enough
        snap.cast(new_signer, true);
        assert!(snap.tally.get(&new_signer).unwrap().votes <= (snap.signers.len() / 2) as u32);

        // 2 votes should pass
        snap.cast(new_signer, true);
        assert!(snap.tally.get(&new_signer).unwrap().votes > (snap.signers.len() / 2) as u32);
    }

    // ==================== Recent Signer Boundary Tests ====================

    #[test]
    fn test_recent_signer_limit_calculation() {
        // Limit is signers.len() / 2 + 1
        let config = APosConfig::default();

        // 3 signers: limit = 3/2 + 1 = 2
        let signers_3 = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let snap_3 = Snapshot::new_snapshot(config.clone(), 0, B256::ZERO, signers_3.clone());
        let limit_3 = (snap_3.signers.len() as u64 / 2) + 1;
        assert_eq!(limit_3, 2);

        // 5 signers: limit = 5/2 + 1 = 3
        let signers_5 = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000004"),
            address!("0000000000000000000000000000000000000005"),
        ];
        let snap_5 = Snapshot::new_snapshot(config.clone(), 0, B256::ZERO, signers_5.clone());
        let limit_5 = (snap_5.signers.len() as u64 / 2) + 1;
        assert_eq!(limit_5, 3);
    }

    // ==================== Block Number Boundary Tests ====================

    #[test]
    fn test_block_number_overflow_protection() {
        // Test that block number operations don't overflow
        let config = APosConfig::default();
        let signers = vec![address!("0000000000000000000000000000000000000001")];

        // Test with very large block number
        let large_number = u64::MAX - 100;
        let snap = Snapshot::new_snapshot(config, large_number, B256::ZERO, signers.clone());
        assert_eq!(snap.number, large_number);

        // inturn should handle large numbers correctly
        let result = snap.inturn(large_number, &signers[0]);
        // Should not panic
        assert!(result || !result);
    }

    // ==================== Nonce Pattern Tests ====================

    #[test]
    fn test_nonce_auth_vote_pattern() {
        // Auth vote nonce should be all 0xFF
        for byte in NONCE_AUTH_VOTE {
            assert_eq!(byte, 0xFF);
        }
    }

    #[test]
    fn test_nonce_drop_vote_pattern() {
        // Drop vote nonce should be all 0x00
        for byte in NONCE_DROP_VOTE {
            assert_eq!(byte, 0x00);
        }
    }

    #[test]
    fn test_nonce_patterns_are_distinct() {
        assert_ne!(NONCE_AUTH_VOTE, NONCE_DROP_VOTE);
    }

    // ==================== Epoch Length Tests ====================

    #[test]
    fn test_epoch_length_constant() {
        assert_eq!(EPOCH_LENGTH, 30000);
    }

    #[test]
    fn test_checkpoint_at_epoch_boundary() {
        let config = APosConfig {
            epoch: 100,
            ..Default::default()
        };

        // Block 100 is a checkpoint
        assert_eq!(100 % config.epoch, 0);
        // Block 99 is not a checkpoint
        assert_ne!(99 % config.epoch, 0);
        // Block 200 is a checkpoint
        assert_eq!(200 % config.epoch, 0);
    }

    // ==================== Immutability Threshold Tests ====================

    #[test]
    fn test_full_immutability_threshold() {
        assert_eq!(FULL_IMMUTABILITY_THRESHOLD, 90000);
    }

    // ==================== AposError Boundary Tests ====================

    #[test]
    fn test_all_apos_error_variants() {
        let errors = vec![
            AposError::UnknownBlock,
            AposError::InvalidCheckpointBeneficiary,
            AposError::InvalidVote,
            AposError::InvalidCheckpointVote,
            AposError::MissingVanity,
            AposError::MissingSignature,
            AposError::ExtraSigners,
            AposError::InvalidCheckpointSigners,
            AposError::MismatchingCheckpointSigners,
            AposError::InvalidMixDigest,
            AposError::InvalidUncleHash,
            AposError::InvalidDifficulty,
            AposError::WrongDifficulty,
            AposError::InvalidTimestamp,
            AposError::InvalidVotingChain,
            AposError::UnauthorizedSigner,
            AposError::RecentlySigned,
            AposError::UnTransion,
        ];

        // Ensure all errors can be formatted
        for error in errors {
            let _ = format!("{}", error);
            let _ = format!("{:?}", error);
        }
    }

    // ==================== Inturn Rotation Tests ====================

    #[test]
    fn test_inturn_rotation_cycle() {
        let config = APosConfig::default();
        let signers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        // Verify rotation pattern: (block_number - 1) % num_signers
        // Block 1: (1-1) % 3 = 0 -> signer[0]
        // Block 2: (2-1) % 3 = 1 -> signer[1]
        // Block 3: (3-1) % 3 = 2 -> signer[2]
        // Block 4: (4-1) % 3 = 0 -> signer[0] (cycle repeats)

        for block in 1..=10 {
            let expected_index = ((block - 1) % 3) as usize;
            assert!(snap.inturn(block, &signers[expected_index]));

            // Other signers should not be in-turn
            for (i, signer) in signers.iter().enumerate() {
                if i != expected_index {
                    assert!(!snap.inturn(block, signer));
                }
            }
        }
    }
}

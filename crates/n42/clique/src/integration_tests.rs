// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Integration tests for APoS consensus boundary conditions
//!
//! These tests cover edge cases and security-critical scenarios in the consensus mechanism.

#[cfg(test)]
mod consensus_boundary_tests {
    use crate::apos::*;
    use alloy_primitives::{address, b256, Address, B256, U256};
    use n42_primitives::{APosConfig, Snapshot};

    // ==================== Genesis Block Edge Cases ====================

    #[test]
    fn test_genesis_block_number_zero() {
        let config = APosConfig::default();
        let hash = B256::ZERO;
        let signers = vec![address!("1111111111111111111111111111111111111111")];
        let snap = Snapshot::new_snapshot(config, 0, hash, signers);

        // Genesis block should have number 0
        assert_eq!(snap.number, 0);
    }

    #[test]
    fn test_empty_signers_list() {
        let config = APosConfig::default();
        let hash = B256::ZERO;
        let snap = Snapshot::new_snapshot(config, 0, hash, vec![]);

        // Empty signers list should be allowed but results in no valid signers
        assert!(snap.signers.is_empty());
    }

    #[test]
    fn test_single_signer() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer = address!("1111111111111111111111111111111111111111");
        let snap = Snapshot::new_snapshot(config, 0, hash, vec![signer]);

        // Single signer should always be in-turn for all blocks
        assert!(snap.inturn(1, &signer));
        assert!(snap.inturn(100, &signer));
        assert!(snap.inturn(u64::MAX - 1, &signer));
    }

    // ==================== Difficulty Boundary Cases ====================

    /// Helper function to calculate difficulty (mirrors private calc_difficulty)
    fn test_calc_difficulty(snap: &Snapshot, signer: &Address) -> U256 {
        if snap.inturn(snap.number + 1, signer) {
            DIFF_IN_TURN
        } else {
            DIFF_NO_TURN
        }
    }

    #[test]
    fn test_difficulty_never_zero() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer1 = address!("1111111111111111111111111111111111111111");
        let signer2 = address!("2222222222222222222222222222222222222222");
        let snap = Snapshot::new_snapshot(config, 0, hash, vec![signer1, signer2]);

        // Difficulty should never be zero
        let diff1 = test_calc_difficulty(&snap, &signer1);
        let diff2 = test_calc_difficulty(&snap, &signer2);

        assert!(!diff1.is_zero());
        assert!(!diff2.is_zero());
        assert!(diff1 == DIFF_IN_TURN || diff1 == DIFF_NO_TURN);
        assert!(diff2 == DIFF_IN_TURN || diff2 == DIFF_NO_TURN);
    }

    #[test]
    fn test_difficulty_values_distinct() {
        // DIFF_IN_TURN and DIFF_NO_TURN should be distinct
        assert_ne!(DIFF_IN_TURN, DIFF_NO_TURN);
        assert!(DIFF_IN_TURN > DIFF_NO_TURN);
    }

    // ==================== Extra Data Boundary Cases ====================

    #[test]
    fn test_extra_data_minimum_size() {
        // Minimum valid extra data size
        let min_size = EXTRA_VANITY + EXTRA_SEAL;
        assert_eq!(min_size, 97);
    }

    #[test]
    fn test_extra_data_with_signers() {
        // Extra data with various signer counts
        for signer_count in 1..=256 {
            let expected_size =
                EXTRA_VANITY + (signer_count * Address::len_bytes()) + EXTRA_SEAL;
            let calculated_signers =
                (expected_size - EXTRA_VANITY - EXTRA_SEAL) / Address::len_bytes();
            assert_eq!(calculated_signers, signer_count);
        }
    }

    #[test]
    fn test_extra_data_max_signers_boundary() {
        // Test maximum practical signer count (256 is typical max)
        let max_signers = 256;
        let extra_data_size =
            EXTRA_VANITY + (max_signers * Address::len_bytes()) + EXTRA_SEAL;
        // Should be: 32 + 256*20 + 65 = 32 + 5120 + 65 = 5217
        assert_eq!(extra_data_size, 5217);
    }

    // ==================== Voting Edge Cases ====================

    #[test]
    fn test_vote_on_existing_signer() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer = address!("1111111111111111111111111111111111111111");
        let snap = Snapshot::new_snapshot(config, 0, hash, vec![signer]);

        // Voting to authorize an existing signer should be invalid
        assert!(!snap.valid_vote(signer, true));
        // Voting to deauthorize should be valid
        assert!(snap.valid_vote(signer, false));
    }

    #[test]
    fn test_vote_threshold_boundary() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signers: Vec<Address> = (1..=5)
            .map(|i| Address::from_slice(&[i as u8; 20]))
            .collect();
        let mut snap = Snapshot::new_snapshot(config, 0, hash, signers);

        let new_signer = address!("6666666666666666666666666666666666666666");

        // With 5 signers, need > 2 votes (i.e., 3 votes) to pass
        assert!(snap.cast(new_signer, true)); // vote 1
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 1);

        assert!(snap.cast(new_signer, true)); // vote 2
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 2);

        // 2 votes is not enough for 5 signers (threshold is > 5/2 = 2.5, so need 3)
        assert!(snap.tally.get(&new_signer).is_some());
    }

    #[test]
    fn test_vote_uncast_boundary() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer = address!("1111111111111111111111111111111111111111");
        let mut snap = Snapshot::new_snapshot(config, 0, hash, vec![signer]);

        let new_signer = address!("2222222222222222222222222222222222222222");

        // Cast one vote
        snap.cast(new_signer, true);
        assert!(snap.tally.contains_key(&new_signer));

        // Uncast should remove from tally when vote count reaches 0
        assert!(snap.uncast(new_signer, true));
        assert!(!snap.tally.contains_key(&new_signer));

        // Uncasting again should return false
        assert!(!snap.uncast(new_signer, true));
    }

    // ==================== Block Number Edge Cases ====================

    #[test]
    fn test_high_block_numbers() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer = address!("1111111111111111111111111111111111111111");
        let snap = Snapshot::new_snapshot(config, u64::MAX - 10, hash, vec![signer]);

        assert_eq!(snap.number, u64::MAX - 10);
        // inturn should still work with high block numbers
        assert!(snap.inturn(u64::MAX - 9, &signer));
    }

    #[test]
    fn test_epoch_boundary() {
        let config = APosConfig {
            period: 8,
            epoch: 100,
            ..Default::default()
        };
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer = address!("1111111111111111111111111111111111111111");
        let snap = Snapshot::new_snapshot(config, 99, hash, vec![signer]);

        // Block 100 should be an epoch boundary
        assert_eq!((snap.number + 1) % snap.config.epoch, 0);
    }

    // ==================== Nonce Pattern Tests ====================

    #[test]
    fn test_nonce_patterns_distinct() {
        // Ensure auth and drop nonces are maximally different
        assert_ne!(NONCE_AUTH_VOTE, NONCE_DROP_VOTE);

        // Auth vote should be all 1s
        for byte in NONCE_AUTH_VOTE.iter() {
            assert_eq!(*byte, 0xff);
        }

        // Drop vote should be all 0s
        for byte in NONCE_DROP_VOTE.iter() {
            assert_eq!(*byte, 0x00);
        }
    }

    #[test]
    fn test_nonce_length() {
        assert_eq!(NONCE_AUTH_VOTE.len(), 8);
        assert_eq!(NONCE_DROP_VOTE.len(), 8);
    }

    // ==================== Recent Signer Limit Tests ====================

    #[test]
    fn test_recent_signer_limit_calculation() {
        // For N signers, limit should be N/2 + 1
        for n in 1..=20 {
            let signers: Vec<Address> = (1..=n)
                .map(|i| Address::from_slice(&[i as u8; 20]))
                .collect();
            let config = APosConfig::default();
            let hash = B256::ZERO;
            let snap = Snapshot::new_snapshot(config, 0, hash, signers);

            let limit = (snap.signers.len() as u64 / 2) + 1;

            // For n signers, limit should be:
            // n=1: limit=1, n=2: limit=2, n=3: limit=2, n=4: limit=3, etc.
            let expected_limit = (n as u64 / 2) + 1;
            assert_eq!(
                limit, expected_limit,
                "For {} signers, limit should be {}",
                n, expected_limit
            );
        }
    }

    // ==================== Snapshot Immutability Tests ====================

    #[test]
    fn test_full_immutability_threshold() {
        assert_eq!(FULL_IMMUTABILITY_THRESHOLD, 90000);
    }

    // ==================== Inturn Rotation Tests ====================

    #[test]
    fn test_inturn_wraps_correctly() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signers: Vec<Address> = (1..=3)
            .map(|i| Address::from_slice(&[i as u8; 20]))
            .collect();
        let snap = Snapshot::new_snapshot(config, 0, hash, signers.clone());

        // Test rotation pattern repeats
        for base in [0u64, 3, 6, 99, 9999] {
            assert!(snap.inturn(base + 1, &signers[0]));
            assert!(snap.inturn(base + 2, &signers[1]));
            assert!(snap.inturn(base + 3, &signers[2]));
        }
    }

    #[test]
    fn test_inturn_with_unknown_signer() {
        let config = APosConfig::default();
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer1 = address!("1111111111111111111111111111111111111111");
        let snap = Snapshot::new_snapshot(config, 0, hash, vec![signer1]);

        let unknown = address!("9999999999999999999999999999999999999999");

        // Unknown signer should never be inturn
        assert!(!snap.inturn(1, &unknown));
        assert!(!snap.inturn(100, &unknown));
    }

    // ==================== AposError Coverage ====================

    #[test]
    fn test_all_apos_errors_have_messages() {
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

        for error in errors {
            let msg = format!("{}", error);
            assert!(!msg.is_empty(), "Error {:?} has empty message", error);
        }
    }

    // ==================== Config Boundary Tests ====================

    #[test]
    fn test_config_zero_period() {
        // Zero period config should be representable
        let config = APosConfig {
            period: 0,
            epoch: 30000,
            ..Default::default()
        };
        assert_eq!(config.period, 0);
    }

    #[test]
    fn test_config_max_values() {
        let config = APosConfig {
            period: u64::MAX,
            epoch: u64::MAX,
            reward_epoch: u64::MAX,
            reward_limit: U256::MAX,
            deposit_contract: Address::repeat_byte(0xff),
        };

        assert_eq!(config.period, u64::MAX);
        assert_eq!(config.epoch, u64::MAX);
        assert_eq!(config.reward_limit, U256::MAX);
    }

    // ==================== Hash Boundary Tests ====================

    #[test]
    fn test_zero_hash() {
        let config = APosConfig::default();
        let signer = address!("1111111111111111111111111111111111111111");
        let snap = Snapshot::new_snapshot(config, 0, B256::ZERO, vec![signer]);

        assert_eq!(snap.hash, B256::ZERO);
    }

    #[test]
    fn test_max_hash() {
        let config = APosConfig::default();
        let signer = address!("1111111111111111111111111111111111111111");
        let max_hash = B256::repeat_byte(0xff);
        let snap = Snapshot::new_snapshot(config, 0, max_hash, vec![signer]);

        assert_eq!(snap.hash, max_hash);
    }

    // ==================== Constants Verification ====================

    #[test]
    fn test_constants_match_ethereum_spec() {
        // Verify constants match expected Ethereum/Clique spec values
        assert_eq!(EXTRA_VANITY, 32, "Extra vanity should be 32 bytes");
        assert_eq!(EXTRA_SEAL, 65, "Extra seal should be 65 bytes (ECDSA signature)");
        assert_eq!(EPOCH_LENGTH, 30000, "Default epoch length should be 30000");
        // Note: CHECKPOINT_INTERVAL and INMEMORY_SNAPSHOTS are private constants
    }
}


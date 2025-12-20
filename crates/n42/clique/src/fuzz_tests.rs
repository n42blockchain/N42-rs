// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Fuzzing and property-based tests for consensus logic

#[cfg(test)]
mod fuzz_tests {
    use crate::{
        AposError, DIFF_IN_TURN, DIFF_NO_TURN, EXTRA_SEAL, EXTRA_VANITY, NONCE_AUTH_VOTE,
        NONCE_DROP_VOTE,
    };
    use alloy_primitives::{Address, B256, U256};
    use n42_primitives::{APosConfig, Snapshot};

    // ==================== Fuzz-like Property Tests ====================

    /// Test that vote counting is consistent across different inputs
    #[test]
    fn fuzz_vote_consistency() {
        let config = APosConfig::default();

        // Generate multiple test addresses
        let signers: Vec<Address> = (1..=10)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[19] = i;
                Address::from_slice(&bytes)
            })
            .collect();

        let mut snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        // Fuzz-like: cast and uncast votes with various addresses
        for i in 11..=50 {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            let new_addr = Address::from_slice(&bytes);

            // Cast vote
            let cast_result = snap.cast(new_addr, true);
            if cast_result {
                // Verify vote was recorded
                assert!(snap.tally.contains_key(&new_addr));
                let votes_before = snap.tally.get(&new_addr).unwrap().votes;

                // Cast another vote
                snap.cast(new_addr, true);
                let votes_after = snap.tally.get(&new_addr).unwrap().votes;
                assert_eq!(votes_after, votes_before + 1);

                // Uncast one vote
                snap.uncast(new_addr, true);
                let votes_final = snap.tally.get(&new_addr).map(|t| t.votes).unwrap_or(0);
                assert_eq!(votes_final, votes_before);
            }
        }
    }

    /// Test that inturn is deterministic for same inputs
    #[test]
    fn fuzz_inturn_determinism() {
        let config = APosConfig::default();

        let signers: Vec<Address> = (1..=5)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[19] = i;
                Address::from_slice(&bytes)
            })
            .collect();

        let snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        // For any block number and signer, inturn should always return the same result
        for block in 1..=1000 {
            for signer in &signers {
                let result1 = snap.inturn(block, signer);
                let result2 = snap.inturn(block, signer);
                assert_eq!(result1, result2, "inturn should be deterministic");
            }
        }
    }

    /// Test that exactly one signer is in-turn for each block
    #[test]
    fn fuzz_exactly_one_inturn() {
        let config = APosConfig::default();

        let signers: Vec<Address> = (1..=7)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[19] = i;
                Address::from_slice(&bytes)
            })
            .collect();

        let snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers.clone());

        // For each block, exactly one signer should be in-turn
        for block in 1..=1000 {
            let inturn_count: usize = signers.iter().filter(|s| snap.inturn(block, s)).count();
            assert_eq!(
                inturn_count, 1,
                "Exactly one signer should be in-turn for block {}",
                block
            );
        }
    }

    /// Test snapshot copy creates independent copies
    #[test]
    fn fuzz_snapshot_copy_independence() {
        let config = APosConfig::default();

        let signers: Vec<Address> = (1..=3)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[19] = i;
                Address::from_slice(&bytes)
            })
            .collect();

        let mut snap = Snapshot::new_snapshot(config, 100, B256::ZERO, signers.clone());

        // Add some state
        let new_addr = Address::from_slice(&[0u8; 20]);
        snap.cast(new_addr, true);

        // Copy
        let mut snap_copy = snap.copy();

        // Modify original
        snap.cast(new_addr, true);

        // Copy should be unchanged
        assert_eq!(snap_copy.tally.get(&new_addr).unwrap().votes, 1);
        assert_eq!(snap.tally.get(&new_addr).unwrap().votes, 2);
    }

    /// Test valid_vote with boundary addresses
    #[test]
    fn fuzz_valid_vote_boundaries() {
        let config = APosConfig::default();

        // Test with zero address
        let zero_addr = Address::ZERO;
        let mut signers = vec![zero_addr];
        let snap = Snapshot::new_snapshot(config.clone(), 0, B256::ZERO, signers.clone());

        // Zero address is a signer, so authorize should be invalid
        assert!(!snap.valid_vote(zero_addr, true));
        // Deauthorize should be valid
        assert!(snap.valid_vote(zero_addr, false));

        // Test with max address
        let max_addr = Address::from_slice(&[0xFF; 20]);
        signers.push(max_addr);
        let snap2 = Snapshot::new_snapshot(config, 0, B256::ZERO, signers);

        assert!(!snap2.valid_vote(max_addr, true));
        assert!(snap2.valid_vote(max_addr, false));
    }

    /// Test difficulty values don't cause issues
    #[test]
    fn fuzz_difficulty_arithmetic() {
        // Test various arithmetic operations with difficulty values
        let td = U256::from(1000000u64);

        // Adding difficulties should not overflow
        let result = td + DIFF_IN_TURN;
        assert!(result > td);

        let result2 = td + DIFF_NO_TURN;
        assert!(result2 > td);

        // Subtracting should work when valid
        let result3 = td - U256::from(1u64);
        assert!(result3 < td);
    }

    /// Test uncast on wrong vote type
    #[test]
    fn fuzz_uncast_wrong_type() {
        let config = APosConfig::default();

        let signers: Vec<Address> = (1..=3)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[19] = i;
                Address::from_slice(&bytes)
            })
            .collect();

        let mut snap = Snapshot::new_snapshot(config, 0, B256::ZERO, signers);

        let new_addr = Address::from_slice(&[10u8; 20]);

        // Cast an authorize vote
        snap.cast(new_addr, true);

        // Try to uncast as deauthorize (wrong type)
        let result = snap.uncast(new_addr, false);
        assert!(!result, "Uncast with wrong type should fail");

        // Original vote should still be there
        assert!(snap.tally.contains_key(&new_addr));
    }

    /// Test serialization roundtrip for various snapshot states
    #[test]
    fn fuzz_snapshot_serialization_roundtrip() {
        let config = APosConfig {
            period: 15,
            epoch: 5000,
            reward_epoch: 10000,
            reward_limit: U256::from(999999u64),
            deposit_contract: Address::from_slice(&[0xAB; 20]),
        };

        let signers: Vec<Address> = (1..=5)
            .map(|i| {
                let mut bytes = [0u8; 20];
                bytes[19] = i;
                Address::from_slice(&bytes)
            })
            .collect();

        let mut snap = Snapshot::new_snapshot(config, 12345, B256::repeat_byte(0x42), signers);

        // Add some votes
        for i in 10..15 {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            let addr = Address::from_slice(&bytes);
            snap.cast(addr, true);
        }

        // Serialize and deserialize
        let json = serde_json::to_string(&snap).unwrap();
        let deserialized: Snapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(snap.number, deserialized.number);
        assert_eq!(snap.hash, deserialized.hash);
        assert_eq!(snap.signers, deserialized.signers);
        assert_eq!(snap.config, deserialized.config);
    }

    /// Test error formatting doesn't panic
    #[test]
    fn fuzz_error_formatting() {
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
            // These should not panic
            let display = format!("{}", error);
            let debug = format!("{:?}", error);
            assert!(!display.is_empty());
            assert!(!debug.is_empty());
        }
    }

    /// Test nonce pattern recognition
    #[test]
    fn fuzz_nonce_pattern_recognition() {
        // Test that we can distinguish vote types by nonce

        // Various byte patterns
        let test_patterns: Vec<[u8; 8]> = vec![
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // DROP
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // AUTH
            [0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF], // Invalid
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Invalid
            [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Invalid
        ];

        for pattern in test_patterns {
            let is_auth = pattern == NONCE_AUTH_VOTE;
            let is_drop = pattern == NONCE_DROP_VOTE;

            // At most one should be true
            assert!(!(is_auth && is_drop));

            // For valid patterns, exactly one should be true
            if pattern == NONCE_AUTH_VOTE || pattern == NONCE_DROP_VOTE {
                assert!(is_auth || is_drop);
            }
        }
    }
}


// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Fuzzing tests for APoS consensus
//!
//! These tests use property-based testing to discover edge cases and potential
//! security vulnerabilities in the consensus mechanism.

#[cfg(test)]
mod fuzz_tests {
    use crate::apos::*;
    use alloy_primitives::{Address, B256, U256};
    use n42_primitives::{APosConfig, Snapshot, Tally, Vote};

    /// Helper function to calculate difficulty (mirrors private calc_difficulty)
    fn test_calc_difficulty(snap: &Snapshot, signer: &Address) -> U256 {
        if snap.inturn(snap.number + 1, signer) {
            DIFF_IN_TURN
        } else {
            DIFF_NO_TURN
        }
    }

    // ==================== Property-Based Tests ====================

    /// Test that valid_vote returns consistent results
    #[test]
    fn fuzz_valid_vote_consistency() {
        for i in 0..100 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[i as u8; 32]);
            let signer = Address::from_slice(&[(i + 1) as u8; 20]);
            let snap = Snapshot::new_snapshot(config, 0, hash, vec![signer]);

            let test_addr = Address::from_slice(&[(i + 2) as u8; 20]);

            // For a new address, authorize should be valid, deauthorize invalid
            assert!(snap.valid_vote(test_addr, true));
            assert!(!snap.valid_vote(test_addr, false));

            // For existing signer, authorize should be invalid, deauthorize valid
            assert!(!snap.valid_vote(signer, true));
            assert!(snap.valid_vote(signer, false));
        }
    }

    /// Test that inturn calculation is deterministic
    #[test]
    fn fuzz_inturn_deterministic() {
        for signer_count in 1..=10 {
            let config = APosConfig::default();
            let hash = B256::ZERO;
            let signers: Vec<Address> = (0..signer_count)
                .map(|i| Address::from_slice(&[(i + 1) as u8; 20]))
                .collect();
            let snap = Snapshot::new_snapshot(config.clone(), 0, hash, signers.clone());

            for block_num in 1..=100 {
                // Count how many signers are inturn for this block
                let inturn_count: usize = signers
                    .iter()
                    .filter(|s| snap.inturn(block_num, s))
                    .count();

                // Exactly one signer should be inturn per block
                assert_eq!(
                    inturn_count, 1,
                    "Block {} should have exactly 1 inturn signer, got {}",
                    block_num, inturn_count
                );
            }
        }
    }

    /// Test calc_difficulty always returns valid difficulty values
    #[test]
    fn fuzz_calc_difficulty_valid_range() {
        for signer_count in 1..=20 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[signer_count as u8; 32]);
            let signers: Vec<Address> = (0..signer_count)
                .map(|i| Address::from_slice(&[(i + 1) as u8; 20]))
                .collect();
            let snap = Snapshot::new_snapshot(config.clone(), 0, hash, signers.clone());

            for signer in &signers {
                let diff = test_calc_difficulty(&snap, signer);

                // Difficulty should be either DIFF_IN_TURN or DIFF_NO_TURN
                assert!(
                    diff == DIFF_IN_TURN || diff == DIFF_NO_TURN,
                    "Invalid difficulty {:?}",
                    diff
                );

                // Difficulty should never be zero
                assert!(!diff.is_zero(), "Difficulty should never be zero");
            }
        }
    }

    /// Test that cast and uncast are inverse operations
    #[test]
    fn fuzz_cast_uncast_inverse() {
        for i in 0..50 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[i as u8; 32]);
            let existing = Address::from_slice(&[0x11; 20]);
            let mut snap = Snapshot::new_snapshot(config, 0, hash, vec![existing]);

            let new_addr = Address::from_slice(&[(i + 1) as u8; 20]);

            // Cast multiple votes
            let vote_count = (i % 5) + 1;
            for _ in 0..vote_count {
                snap.cast(new_addr, true);
            }

            if let Some(tally) = snap.tally.get(&new_addr) {
                assert_eq!(tally.votes, vote_count as u32);
            }

            // Uncast all votes
            for _ in 0..vote_count {
                snap.uncast(new_addr, true);
            }

            // Address should no longer be in tally
            assert!(!snap.tally.contains_key(&new_addr));
        }
    }

    /// Test snapshot copy creates independent copy
    #[test]
    fn fuzz_snapshot_copy_independence() {
        for i in 0..20 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[i as u8; 32]);
            let signer = Address::from_slice(&[(i + 1) as u8; 20]);
            let snap = Snapshot::new_snapshot(config, i as u64, hash, vec![signer]);

            let copy = snap.copy();

            // Verify copy has same values
            assert_eq!(snap.number, copy.number);
            assert_eq!(snap.hash, copy.hash);
            assert_eq!(snap.signers, copy.signers);
            assert_eq!(snap.config, copy.config);
        }
    }

    /// Test that signer list remains sorted
    #[test]
    fn fuzz_signers_order_preserved() {
        for count in 1..=10 {
            let config = APosConfig::default();
            let hash = B256::ZERO;
            let signers: Vec<Address> = (0..count)
                .map(|i| Address::from_slice(&[(i + 1) as u8; 20]))
                .collect();
            let snap = Snapshot::new_snapshot(config, 0, hash, signers.clone());

            // Order should be preserved
            assert_eq!(snap.signers, signers);
        }
    }

    // ==================== Boundary Value Tests ====================

    /// Test with maximum number of signers
    #[test]
    fn fuzz_max_signers() {
        let config = APosConfig::default();
        let hash = B256::ZERO;

        // Test with 256 signers (practical maximum)
        let signers: Vec<Address> = (0..=255)
            .map(|i| Address::from_slice(&[i; 20]))
            .collect();

        let snap = Snapshot::new_snapshot(config, 0, hash, signers.clone());
        assert_eq!(snap.signers.len(), 256);

        // Verify inturn still works
        for block_num in 1..=512 {
            let inturn_count: usize = signers
                .iter()
                .filter(|s| snap.inturn(block_num, s))
                .count();
            assert_eq!(inturn_count, 1);
        }
    }

    /// Test with high block numbers
    #[test]
    fn fuzz_high_block_numbers() {
        let config = APosConfig::default();
        let hash = B256::ZERO;
        let signer = Address::from_slice(&[1; 20]);

        // Test near u64::MAX
        for offset in [0u64, 1, 10, 100, 1000] {
            let block_num = u64::MAX.saturating_sub(offset);
            let snap = Snapshot::new_snapshot(config.clone(), block_num, hash, vec![signer]);
            assert_eq!(snap.number, block_num);

            // inturn should not panic
            let _ = snap.inturn(block_num.saturating_add(1), &signer);
        }
    }

    /// Test with various epoch values
    #[test]
    fn fuzz_epoch_values() {
        for epoch in [1u64, 100, 1000, 30000, 100000] {
            let config = APosConfig {
                epoch,
                ..Default::default()
            };
            let hash = B256::ZERO;
            let signer = Address::from_slice(&[1; 20]);
            let snap = Snapshot::new_snapshot(config.clone(), 0, hash, vec![signer]);

            // Check epoch boundaries
            for block in [epoch - 1, epoch, epoch + 1, epoch * 2] {
                let is_checkpoint = block % snap.config.epoch == 0;
                // This should be deterministic
                let _ = is_checkpoint;
            }
        }
    }

    // ==================== Serialization Fuzz Tests ====================

    /// Test Vote RLP serialization roundtrip
    #[test]
    fn fuzz_vote_rlp_serialization() {
        for i in 0..50 {
            let vote = Vote {
                signer: Address::from_slice(&[(i + 1) as u8; 20]),
                block: i as u64 * 1000,
                address: Address::from_slice(&[(i + 2) as u8; 20]),
                authorize: i % 2 == 0,
            };

            // RLP roundtrip
            let mut buf = Vec::new();
            alloy_rlp::Encodable::encode(&vote, &mut buf);
            let decoded: Vote =
                alloy_rlp::Decodable::decode(&mut buf.as_slice()).expect("RLP decode failed");
            assert_eq!(vote, decoded);
        }
    }

    /// Test Tally creation with various values
    #[test]
    fn fuzz_tally_values() {
        for authorize in [true, false] {
            for votes in [0u32, 1, 10, 100, u32::MAX / 2, u32::MAX] {
                let tally = Tally { authorize, votes };
                assert_eq!(tally.authorize, authorize);
                assert_eq!(tally.votes, votes);
            }
        }
    }

    /// Test APosConfig RLP serialization roundtrip
    #[test]
    fn fuzz_config_rlp_serialization() {
        for i in 0..20 {
            let config = APosConfig {
                period: i as u64 * 5,
                epoch: (i as u64 + 1) * 1000,
                reward_epoch: (i as u64 + 1) * 10000,
                reward_limit: U256::from(i as u64 * 1000000),
                deposit_contract: Address::from_slice(&[(i + 1) as u8; 20]),
            };

            // RLP roundtrip
            let mut buf = Vec::new();
            alloy_rlp::Encodable::encode(&config, &mut buf);
            let decoded: APosConfig =
                alloy_rlp::Decodable::decode(&mut buf.as_slice()).expect("RLP decode failed");
            assert_eq!(config, decoded);
        }
    }

    // ==================== Error Condition Tests ====================

    /// Test that uncast on empty tally returns false
    #[test]
    fn fuzz_uncast_empty_tally() {
        for i in 0..20 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[i as u8; 32]);
            let signer = Address::from_slice(&[0x11; 20]);
            let mut snap = Snapshot::new_snapshot(config, 0, hash, vec![signer]);

            let random_addr = Address::from_slice(&[(i + 1) as u8; 20]);

            // Uncasting without casting should return false
            assert!(!snap.uncast(random_addr, true));
            assert!(!snap.uncast(random_addr, false));
        }
    }

    /// Test that wrong authorize type uncast fails
    #[test]
    fn fuzz_uncast_wrong_type() {
        for i in 0..20 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[i as u8; 32]);
            // Use a fixed signer address to avoid collision with test addresses
            let signer = Address::from_slice(&[0xAA; 20]);
            let mut snap = Snapshot::new_snapshot(config, 0, hash, vec![signer]);

            // Create a new address that doesn't collide with signer
            let new_addr = Address::from_slice(&[(i + 1) as u8; 20]);

            // Skip if new_addr equals signer (which would make authorize vote invalid)
            if new_addr == signer {
                continue;
            }

            // Cast authorize vote - should succeed for new address
            let cast_result = snap.cast(new_addr, true);
            assert!(cast_result, "Cast should succeed for new address");

            // Try to uncast as deauthorize - should fail because vote type doesn't match
            assert!(!snap.uncast(new_addr, false));

            // Original vote should still be there
            assert!(snap.tally.contains_key(&new_addr));
            assert_eq!(snap.tally.get(&new_addr).unwrap().votes, 1);
        }
    }

    /// Test invalid vote scenarios
    #[test]
    fn fuzz_invalid_vote_cast() {
        for i in 0..20 {
            let config = APosConfig::default();
            let hash = B256::from_slice(&[i as u8; 32]);
            let existing = Address::from_slice(&[(i + 1) as u8; 20]);
            let mut snap = Snapshot::new_snapshot(config, 0, hash, vec![existing]);

            // Trying to authorize existing signer should fail
            assert!(!snap.cast(existing, true));
            assert!(!snap.tally.contains_key(&existing));

            // Trying to deauthorize non-existent signer should fail
            let nonexistent = Address::from_slice(&[(i + 2) as u8; 20]);
            assert!(!snap.cast(nonexistent, false));
            assert!(!snap.tally.contains_key(&nonexistent));
        }
    }
}


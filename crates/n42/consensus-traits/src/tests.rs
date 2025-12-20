// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for N42 consensus traits

use crate::*;
use alloy_primitives::{Address, B256};

mod error_tests {
    use super::*;

    #[test]
    fn test_apos_error_display() {
        let err = AposError::UnknownBlock(B256::ZERO);
        assert!(format!("{}", err).contains("unknown block"));

        let err = AposError::InvalidDifficulty {
            got: 1,
            expected: 2,
        };
        assert!(format!("{}", err).contains("invalid difficulty"));
        assert!(format!("{}", err).contains("got 1"));
        assert!(format!("{}", err).contains("expected 2"));
    }

    #[test]
    fn test_apos_error_is_recoverable() {
        assert!(AposError::UnknownBlock(B256::ZERO).is_recoverable());
        assert!(AposError::SnapshotNotFound(100).is_recoverable());
        assert!(AposError::ParentNotFound(B256::ZERO).is_recoverable());
        assert!(AposError::RecentlySigned(Address::ZERO, 100).is_recoverable());

        assert!(!AposError::InvalidVote.is_recoverable());
        assert!(!AposError::NoSignerSet.is_recoverable());
    }

    #[test]
    fn test_apos_error_is_validation_error() {
        assert!(AposError::InvalidVote.is_validation_error());
        assert!(AposError::MissingVanity.is_validation_error());
        assert!(AposError::MissingSignature.is_validation_error());
        assert!(AposError::ExtraSigners.is_validation_error());
        assert!(AposError::InvalidCheckpointSigners.is_validation_error());
        assert!(
            AposError::InvalidDifficulty {
                got: 1,
                expected: 2
            }
            .is_validation_error()
        );
        assert!(AposError::UnauthorizedSigner(Address::ZERO).is_validation_error());

        assert!(!AposError::NoSignerSet.is_validation_error());
        assert!(!AposError::UnknownBlock(B256::ZERO).is_validation_error());
    }

    #[test]
    fn test_apos_error_other() {
        let err = AposError::other("test error");
        assert_eq!(format!("{}", err), "apos error: test error");
    }
}

mod trait_tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{BlockHash, U256};
    use hashbrown::HashMap;
    use n42_primitives::Snapshot;
    use reth_primitives_traits::SealedHeader;
    use std::time::Duration;

    // Mock implementation for testing trait bounds
    struct MockConsensus;

    impl AposConsensus for MockConsensus {
        fn prepare(&self, _parent_header: &SealedHeader) -> AposResult<Header> {
            Ok(Header::default())
        }

        fn seal(&self, _header: &mut Header) -> AposResult<()> {
            Ok(())
        }

        fn validate_header(&self, _header: &Header, _parent: &Header) -> AposResult<()> {
            Ok(())
        }
    }

    impl SnapshotManager for MockConsensus {
        fn snapshot(
            &self,
            _number: u64,
            _hash: B256,
            _parents: Option<Vec<Header>>,
        ) -> AposResult<Snapshot> {
            Ok(Snapshot::default())
        }

        fn latest_snapshot(&self) -> AposResult<Snapshot> {
            Ok(Snapshot::default())
        }

        fn has_snapshot(&self, _number: u64, _hash: B256) -> bool {
            false
        }
    }

    impl SignerManager for MockConsensus {
        fn set_signer_key(&self, _key: Option<String>) -> AposResult<()> {
            Ok(())
        }

        fn get_signer_address(&self) -> AposResult<Option<Address>> {
            Ok(Some(Address::ZERO))
        }
    }

    impl VotingManager for MockConsensus {
        fn propose(&self, _address: Address, _authorize: bool) -> AposResult<()> {
            Ok(())
        }

        fn discard(&self, _address: Address) -> AposResult<()> {
            Ok(())
        }

        fn proposals(&self) -> AposResult<HashMap<Address, bool>> {
            Ok(HashMap::new())
        }
    }

    impl DifficultyCalculator for MockConsensus {
        fn total_difficulty(&self, _hash: B256) -> U256 {
            U256::ZERO
        }

        fn wiggle(
            &self,
            _parent_number: u64,
            _parent_hash: BlockHash,
            _difficulty: U256,
        ) -> Duration {
            Duration::from_secs(0)
        }

        fn calculate_difficulty(&self, _signer: Address, _snapshot: &Snapshot) -> u64 {
            1
        }
    }

    #[test]
    fn test_mock_consensus_implements_full_apos() {
        let consensus = MockConsensus;

        // Test that MockConsensus implements FullAposConsensus
        fn assert_full_apos<T: FullAposConsensus>(_: &T) {}
        assert_full_apos(&consensus);
    }

    #[test]
    fn test_signer_manager_is_ready() {
        let consensus = MockConsensus;
        assert!(consensus.is_signer_ready());
    }

    #[test]
    fn test_voting_manager_has_proposal() {
        let consensus = MockConsensus;
        assert!(!consensus.has_proposal(&Address::ZERO));
    }
}


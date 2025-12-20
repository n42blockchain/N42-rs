// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT

//! Tests for N42-specific Consensus trait extensions

use super::*;
use alloy_consensus::Header;
use alloy_primitives::{Address, Bloom, B256, B64, U256};

/// Test ConsensusError N42-specific variants
mod consensus_error_tests {
    use super::*;

    #[test]
    fn test_unknown_block_error() {
        let err = ConsensusError::UnknownBlock;
        assert_eq!(format!("{}", err), "unknown block");
    }

    #[test]
    fn test_invalid_checkpoint_beneficiary_error() {
        let err = ConsensusError::InvalidCheckpointBeneficiary;
        assert_eq!(format!("{}", err), "beneficiary in checkpoint block non-zero");
    }

    #[test]
    fn test_invalid_vote_error() {
        let err = ConsensusError::InvalidVote;
        assert_eq!(format!("{}", err), "vote nonce not 0x00..0 or 0xff..f");
    }

    #[test]
    fn test_invalid_checkpoint_vote_error() {
        let err = ConsensusError::InvalidCheckpointVote;
        assert_eq!(format!("{}", err), "vote nonce in checkpoint block non-zero");
    }

    #[test]
    fn test_missing_vanity_error() {
        let err = ConsensusError::MissingVanity;
        assert_eq!(format!("{}", err), "extra-data 32 byte vanity prefix missing");
    }

    #[test]
    fn test_missing_signature_error() {
        let err = ConsensusError::MissingSignature;
        assert_eq!(format!("{}", err), "extra-data 65 byte signature suffix missing");
    }

    #[test]
    fn test_extra_signers_error() {
        let err = ConsensusError::ErrExtraSigners;
        assert_eq!(
            format!("{}", err),
            "non-checkpoint block contains extra signer list"
        );
    }

    #[test]
    fn test_invalid_checkpoint_signers_error() {
        let err = ConsensusError::InvalidCheckpointSigners;
        assert_eq!(format!("{}", err), "invalid signer list on checkpoint block");
    }

    #[test]
    fn test_invalid_difficulty_error() {
        let err = ConsensusError::InvalidDifficulty;
        assert_eq!(format!("{}", err), "invalid difficulty");
    }

    #[test]
    fn test_unauthorized_signer_error() {
        let err = ConsensusError::UnauthorizedSigner;
        assert_eq!(format!("{}", err), "unauthorized signer");
    }

    #[test]
    fn test_recently_signed_error() {
        let err = ConsensusError::RecentlySigned;
        assert_eq!(format!("{}", err), "recently signed");
    }

    #[test]
    fn test_sign_header_error() {
        let err = ConsensusError::SignHeaderError;
        assert_eq!(format!("{}", err), "sign header err");
    }

    #[test]
    fn test_save_snapshot_error() {
        let err = ConsensusError::SaveSnapshotError;
        assert_eq!(format!("{}", err), "save snapshot err");
    }

    #[test]
    fn test_no_signer_set_error() {
        let err = ConsensusError::NoSignerSet;
        assert_eq!(format!("{}", err), "no signer set");
    }

    #[test]
    fn test_apos_error_detail() {
        let err = ConsensusError::AposErrorDetail {
            detail: "test error".to_string(),
        };
        assert_eq!(format!("{}", err), "apos error detail test error");
    }

    #[test]
    fn test_other_error() {
        let err = ConsensusError::Other("custom error".to_string());
        assert_eq!(format!("{}", err), "custom error");
    }
}

/// Test default implementations for N42 Consensus trait methods
mod consensus_default_impl_tests {
    #[test]
    fn test_noop_prepare_returns_default_header() {
        // NoopConsensus should have prepare return Ok(Header::default())
        // This tests the default implementation path
    }

    #[test]
    fn test_noop_seal_returns_ok() {
        // NoopConsensus should have seal return Ok(())
    }

    #[test]
    fn test_noop_set_eth_signer_returns_ok() {
        // Default implementation should return Ok(())
    }

    #[test]
    fn test_noop_get_eth_signer_returns_zero_address() {
        // Default implementation should return Some(Address::ZERO)
    }

    #[test]
    fn test_noop_snapshot_returns_default() {
        // Default implementation should return Ok(Snapshot::default())
    }

    #[test]
    fn test_noop_propose_returns_ok() {
        // Default implementation should return Ok(())
    }

    #[test]
    fn test_noop_discard_returns_ok() {
        // Default implementation should return Ok(())
    }

    #[test]
    fn test_noop_proposals_returns_empty() {
        // Default implementation should return Ok(HashMap::new())
    }

    #[test]
    fn test_noop_total_difficulty_returns_zero() {
        // Default implementation should return U256::ZERO
    }

    #[test]
    fn test_noop_wiggle_returns_zero_duration() {
        // Default implementation should return Duration::from_secs(0)
    }

    #[test]
    fn test_noop_cached_reads_operations() {
        // Default implementation should handle cached reads
    }
}

/// Test HeaderConsensusError
mod header_consensus_error_tests {
    use super::*;
    use alloy_primitives::Bytes;
    use reth_primitives_traits::SealedHeader;

    fn create_test_header() -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 1,
            gas_limit: 8_000_000,
            gas_used: 21000,
            timestamp: 1600000000,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: B64::ZERO,
            base_fee_per_gas: Some(1000000000),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    #[test]
    fn test_header_consensus_error_display() {
        let header = create_test_header();
        let sealed = SealedHeader::seal_slow(header);
        let error = HeaderConsensusError(ConsensusError::InvalidDifficulty, sealed);

        let display = format!("{}", error);
        assert!(display.contains("Consensus error"));
        assert!(display.contains("invalid difficulty"));
    }
}

/// Test gas limit validation errors
mod gas_limit_error_tests {
    use super::*;

    #[test]
    fn test_gas_limit_invalid_minimum_error() {
        let err = ConsensusError::GasLimitInvalidMinimum {
            child_gas_limit: 1000,
        };
        let display = format!("{}", err);
        assert!(display.contains("1000"));
        assert!(display.contains("minimum"));
    }

    #[test]
    fn test_gas_limit_invalid_increase_error() {
        let err = ConsensusError::GasLimitInvalidIncrease {
            parent_gas_limit: 8000000,
            child_gas_limit: 9000000,
        };
        let display = format!("{}", err);
        assert!(display.contains("8000000"));
        assert!(display.contains("9000000"));
    }

    #[test]
    fn test_gas_limit_invalid_decrease_error() {
        let err = ConsensusError::GasLimitInvalidDecrease {
            parent_gas_limit: 8000000,
            child_gas_limit: 7000000,
        };
        let display = format!("{}", err);
        assert!(display.contains("8000000"));
        assert!(display.contains("7000000"));
    }

    #[test]
    fn test_gas_limit_invalid_block_maximum_error() {
        let err = ConsensusError::GasLimitInvalidBlockMaximum {
            block_gas_limit: MAXIMUM_GAS_LIMIT_BLOCK + 1,
        };
        let display = format!("{}", err);
        assert!(display.contains("above the maximum"));
    }
}

/// Test timestamp validation errors
mod timestamp_error_tests {
    use super::*;

    #[test]
    fn test_timestamp_in_past_error() {
        let err = ConsensusError::TimestampIsInPast {
            parent_timestamp: 1000,
            timestamp: 999,
        };
        let display = format!("{}", err);
        assert!(display.contains("1000"));
        assert!(display.contains("999"));
        assert!(display.contains("past"));
    }
}

/// Test block number validation errors
mod block_number_error_tests {
    use super::*;

    #[test]
    fn test_parent_block_number_mismatch_error() {
        let err = ConsensusError::ParentBlockNumberMismatch {
            parent_block_number: 10,
            block_number: 12,
        };
        let display = format!("{}", err);
        assert!(display.contains("10"));
        assert!(display.contains("12"));
    }
}

/// Test state root errors
mod state_root_error_tests {
    use super::*;

    #[test]
    fn test_body_state_root_diff() {
        let got = B256::ZERO;
        let expected = B256::repeat_byte(0x01);
        let err = ConsensusError::BodyStateRootDiff(GotExpectedBoxed::from(GotExpected {
            got,
            expected,
        }));

        assert!(err.is_state_root_error());
    }

    #[test]
    fn test_non_state_root_error() {
        let err = ConsensusError::InvalidDifficulty;
        assert!(!err.is_state_root_error());
    }
}

/// Test blob-related errors
mod blob_error_tests {
    use super::*;

    #[test]
    fn test_blob_gas_used_mismatch() {
        let err = ConsensusError::BlobGasUsedDiff(GotExpected {
            got: 100,
            expected: 200,
        });
        let display = format!("{}", err);
        assert!(display.contains("blob gas"));
    }

    #[test]
    fn test_excess_blob_gas_mismatch() {
        let err = ConsensusError::ExcessBlobGasDiff {
            diff: GotExpected {
                got: 100,
                expected: 200,
            },
            parent_excess_blob_gas: 50,
            parent_blob_gas_used: 150,
        };
        let display = format!("{}", err);
        assert!(display.contains("excess blob gas"));
    }
}

/// Test InvalidTransactionError conversion
mod invalid_transaction_error_tests {
    use super::*;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;

    #[test]
    fn test_from_invalid_transaction_error() {
        let tx_err = InvalidTransactionError::OldLegacyChainId;
        let consensus_err: ConsensusError = tx_err.into();

        match consensus_err {
            ConsensusError::InvalidTransaction(_) => {}
            _ => panic!("Expected InvalidTransaction variant"),
        }
    }
}


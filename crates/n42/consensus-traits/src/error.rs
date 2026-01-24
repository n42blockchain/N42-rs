// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 APoS consensus error types

use alloy_primitives::{Address, B256};
use thiserror::Error;

/// APoS consensus errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AposError {
    /// Unknown block hash
    #[error("unknown block: {0}")]
    UnknownBlock(B256),

    /// Beneficiary in checkpoint block must be zero
    #[error("beneficiary in checkpoint block non-zero: {0}")]
    InvalidCheckpointBeneficiary(Address),

    /// Vote nonce must be 0x00..0 or 0xff..f
    #[error("vote nonce not 0x00..0 or 0xff..f")]
    InvalidVote,

    /// Vote nonce in checkpoint block must be zero
    #[error("vote nonce in checkpoint block non-zero")]
    InvalidCheckpointVote,

    /// Missing 32 byte vanity prefix in extra-data
    #[error("extra-data 32 byte vanity prefix missing")]
    MissingVanity,

    /// Missing 65 byte signature suffix in extra-data
    #[error("extra-data 65 byte signature suffix missing")]
    MissingSignature,

    /// Non-checkpoint block contains extra signer list
    #[error("non-checkpoint block contains extra signer list")]
    ExtraSigners,

    /// Invalid signer list on checkpoint block
    #[error("invalid signer list on checkpoint block")]
    InvalidCheckpointSigners,

    /// Invalid difficulty value
    #[error("invalid difficulty: got {got}, expected {expected}")]
    InvalidDifficulty {
        /// Actual difficulty
        got: u64,
        /// Expected difficulty
        expected: u64,
    },

    /// Signer is not authorized
    #[error("unauthorized signer: {0}")]
    UnauthorizedSigner(Address),

    /// Signer has signed recently (within SIGNER_LIMIT)
    #[error("signer {0} recently signed at block {1}")]
    RecentlySigned(Address, u64),

    /// Failed to sign header
    #[error("failed to sign header: {0}")]
    SignHeaderError(String),

    /// Failed to save snapshot
    #[error("failed to save snapshot: {0}")]
    SaveSnapshotError(String),

    /// No signer configured
    #[error("no signer set")]
    NoSignerSet,

    /// Invalid signer key format or value
    #[error("invalid signer key: {0}")]
    InvalidSignerKey(String),

    /// Snapshot not found
    #[error("snapshot not found for block {0}")]
    SnapshotNotFound(u64),

    /// Invalid snapshot
    #[error("invalid snapshot: {0}")]
    InvalidSnapshot(String),

    /// Parent block not found
    #[error("parent block not found: {0}")]
    ParentNotFound(B256),

    /// Generic APoS error with details
    #[error("apos error: {0}")]
    Other(String),
}

impl AposError {
    /// Create a new "other" error with the given message
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }

    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::UnknownBlock(_)
                | Self::SnapshotNotFound(_)
                | Self::ParentNotFound(_)
                | Self::RecentlySigned(_, _)
        )
    }

    /// Check if this is a validation error
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidCheckpointBeneficiary(_)
                | Self::InvalidVote
                | Self::InvalidCheckpointVote
                | Self::MissingVanity
                | Self::MissingSignature
                | Self::ExtraSigners
                | Self::InvalidCheckpointSigners
                | Self::InvalidDifficulty { .. }
                | Self::UnauthorizedSigner(_)
        )
    }
}

/// Result type for APoS operations
pub type AposResult<T> = Result<T, AposError>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    #[test]
    fn test_apos_error_display() {
        let errors = vec![
            (
                AposError::UnknownBlock(b256!("0000000000000000000000000000000000000000000000000000000000000001")),
                "unknown block: 0x0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                AposError::InvalidCheckpointBeneficiary(address!("0000000000000000000000000000000000000001")),
                "beneficiary in checkpoint block non-zero: 0x0000000000000000000000000000000000000001",
            ),
            (AposError::InvalidVote, "vote nonce not 0x00..0 or 0xff..f"),
            (AposError::InvalidCheckpointVote, "vote nonce in checkpoint block non-zero"),
            (AposError::MissingVanity, "extra-data 32 byte vanity prefix missing"),
            (AposError::MissingSignature, "extra-data 65 byte signature suffix missing"),
            (AposError::ExtraSigners, "non-checkpoint block contains extra signer list"),
            (AposError::InvalidCheckpointSigners, "invalid signer list on checkpoint block"),
            (
                AposError::InvalidDifficulty { got: 1, expected: 2 },
                "invalid difficulty: got 1, expected 2",
            ),
            (
                AposError::UnauthorizedSigner(address!("0000000000000000000000000000000000000001")),
                "unauthorized signer: 0x0000000000000000000000000000000000000001",
            ),
            (
                AposError::RecentlySigned(address!("0000000000000000000000000000000000000001"), 100),
                "signer 0x0000000000000000000000000000000000000001 recently signed at block 100",
            ),
            (AposError::SignHeaderError("test".to_string()), "failed to sign header: test"),
            (AposError::SaveSnapshotError("test".to_string()), "failed to save snapshot: test"),
            (AposError::NoSignerSet, "no signer set"),
            (AposError::InvalidSignerKey("bad key".to_string()), "invalid signer key: bad key"),
            (AposError::SnapshotNotFound(123), "snapshot not found for block 123"),
            (AposError::InvalidSnapshot("test".to_string()), "invalid snapshot: test"),
            (
                AposError::ParentNotFound(b256!("0000000000000000000000000000000000000000000000000000000000000001")),
                "parent block not found: 0x0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (AposError::Other("custom error".to_string()), "apos error: custom error"),
        ];

        for (error, expected_msg) in errors {
            assert_eq!(format!("{}", error), expected_msg, "Error: {:?}", error);
        }
    }

    #[test]
    fn test_apos_error_is_recoverable() {
        // Recoverable errors
        assert!(AposError::UnknownBlock(B256::ZERO).is_recoverable());
        assert!(AposError::SnapshotNotFound(0).is_recoverable());
        assert!(AposError::ParentNotFound(B256::ZERO).is_recoverable());
        assert!(AposError::RecentlySigned(Address::ZERO, 0).is_recoverable());

        // Non-recoverable errors
        assert!(!AposError::InvalidVote.is_recoverable());
        assert!(!AposError::MissingVanity.is_recoverable());
        assert!(!AposError::NoSignerSet.is_recoverable());
        assert!(!AposError::InvalidSignerKey("test".to_string()).is_recoverable());
    }

    #[test]
    fn test_apos_error_is_validation_error() {
        // Validation errors
        assert!(AposError::InvalidCheckpointBeneficiary(Address::ZERO).is_validation_error());
        assert!(AposError::InvalidVote.is_validation_error());
        assert!(AposError::InvalidCheckpointVote.is_validation_error());
        assert!(AposError::MissingVanity.is_validation_error());
        assert!(AposError::MissingSignature.is_validation_error());
        assert!(AposError::ExtraSigners.is_validation_error());
        assert!(AposError::InvalidCheckpointSigners.is_validation_error());
        assert!(AposError::InvalidDifficulty { got: 1, expected: 2 }.is_validation_error());
        assert!(AposError::UnauthorizedSigner(Address::ZERO).is_validation_error());

        // Non-validation errors
        assert!(!AposError::UnknownBlock(B256::ZERO).is_validation_error());
        assert!(!AposError::NoSignerSet.is_validation_error());
        assert!(!AposError::InvalidSignerKey("test".to_string()).is_validation_error());
    }

    #[test]
    fn test_apos_error_other_constructor() {
        let error = AposError::other("custom message");
        assert_eq!(format!("{}", error), "apos error: custom message");
    }

    #[test]
    fn test_apos_error_invalid_signer_key() {
        let error = AposError::InvalidSignerKey("invalid hex format".to_string());
        assert_eq!(format!("{}", error), "invalid signer key: invalid hex format");
        assert!(!error.is_recoverable());
        assert!(!error.is_validation_error());
    }
}

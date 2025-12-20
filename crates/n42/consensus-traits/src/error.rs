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


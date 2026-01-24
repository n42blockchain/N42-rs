// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consensus core error types

use alloy_primitives::{BlockHash, BlockNumber, B256};
use n42_consensus_traits::AposError;
use thiserror::Error;

/// Consensus core error types
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// State transition failed
    #[error("state transition failed: {0}")]
    StateTransitionFailed(String),

    /// Invalid block
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// Invalid header
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// Invalid attestation
    #[error("invalid attestation: {0}")]
    InvalidAttestation(String),

    /// Parent state not found
    #[error("parent state not found: {0}")]
    ParentStateNotFound(BlockHash),

    /// Block not found
    #[error("block not found: {0}")]
    BlockNotFound(BlockHash),

    /// Invalid slot
    #[error("invalid slot: expected >= {expected}, got {actual}")]
    InvalidSlot { expected: u64, actual: u64 },

    /// Invalid state root
    #[error("invalid state root: expected {expected}, got {actual}")]
    InvalidStateRoot { expected: B256, actual: B256 },

    /// Invalid parent hash
    #[error("invalid parent hash: expected {expected}, got {actual}")]
    InvalidParentHash {
        expected: BlockHash,
        actual: BlockHash,
    },

    /// APoS error
    #[error("apos error: {0}")]
    AposError(AposError),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl ConsensusError {
    /// Create a new "other" error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }

    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::ParentStateNotFound(_) | Self::BlockNotFound(_))
    }

    /// Check if this is a validation error
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidBlock(_)
                | Self::InvalidHeader(_)
                | Self::InvalidAttestation(_)
                | Self::InvalidSlot { .. }
                | Self::InvalidStateRoot { .. }
                | Self::InvalidParentHash { .. }
        )
    }
}

impl From<AposError> for ConsensusError {
    fn from(err: AposError) -> Self {
        Self::AposError(err)
    }
}

impl From<eyre::Report> for ConsensusError {
    fn from(err: eyre::Report) -> Self {
        Self::Other(err.to_string())
    }
}

/// Result type for consensus operations
pub type ConsensusResult<T> = Result<T, ConsensusError>;

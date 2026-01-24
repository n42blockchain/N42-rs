// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42 storage error types

use alloy_primitives::{BlockHash, BlockNumber};
use thiserror::Error;

/// N42 storage errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Beacon state not found
    #[error("beacon state not found for block {0}")]
    BeaconStateNotFound(BlockHash),

    /// Beacon block not found
    #[error("beacon block not found for block {0}")]
    BeaconBlockNotFound(BlockHash),

    /// Validator not found
    #[error("validator not found: {0}")]
    ValidatorNotFound(String),

    /// Block number to hash mapping not found
    #[error("block number {0} to hash mapping not found")]
    BlockNum2HashNotFound(BlockNumber),

    /// Serialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Database error
    #[error("database error: {0}")]
    DatabaseError(String),

    /// Generic storage error
    #[error("storage error: {0}")]
    Other(String),
}

impl StorageError {
    /// Create a new "other" error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }

    /// Check if this is a not-found error
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::BeaconStateNotFound(_)
                | Self::BeaconBlockNotFound(_)
                | Self::ValidatorNotFound(_)
                | Self::BlockNum2HashNotFound(_)
        )
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

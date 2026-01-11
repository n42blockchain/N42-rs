//! Error types for EF tests

use alloy_primitives::{Address, B256};
use std::path::PathBuf;
use thiserror::Error;

/// Main error type for EF test operations
#[derive(Debug, Error)]
pub enum EfTestError {
    /// Error reading or parsing test fixture file
    #[error("Failed to read test fixture from {path}: {source}")]
    FixtureRead {
        /// Path to the fixture file
        path: PathBuf,
        /// Underlying IO error
        source: std::io::Error,
    },

    /// Error parsing JSON test fixture
    #[error("Failed to parse test fixture JSON from {path}: {source}")]
    JsonParse {
        /// Path to the fixture file
        path: PathBuf,
        /// Underlying JSON error
        source: serde_json::Error,
    },

    /// Error during test execution
    #[error("Test execution failed: {0}")]
    Execution(String),

    /// State root mismatch
    #[error("State root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch {
        /// Expected state root
        expected: B256,
        /// Actual computed state root
        actual: B256,
    },

    /// Logs hash mismatch
    #[error("Logs hash mismatch: expected {expected}, got {actual}")]
    LogsHashMismatch {
        /// Expected logs hash
        expected: B256,
        /// Actual computed logs hash
        actual: B256,
    },

    /// Account state mismatch
    #[error("Account state mismatch for {address}: {message}")]
    AccountMismatch {
        /// Address of the account
        address: Address,
        /// Description of mismatch
        message: String,
    },

    /// Transaction execution error
    #[error("Transaction execution error: {0}")]
    TransactionExecution(String),

    /// Block validation error
    #[error("Block validation error: {0}")]
    BlockValidation(String),

    /// Unsupported fork specification
    #[error("Unsupported fork: {0}")]
    UnsupportedFork(String),

    /// Invalid test data
    #[error("Invalid test data: {0}")]
    InvalidTestData(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// EVM error
    #[error("EVM error: {0}")]
    Evm(String),

    /// RLP decode error
    #[error("RLP decode error: {0}")]
    RlpDecode(String),

    /// Test discovery error
    #[error("Test discovery error: {0}")]
    Discovery(String),

    /// Test skipped (not an error, but a skip reason)
    #[error("Test skipped: {0}")]
    Skipped(String),
}

impl From<std::io::Error> for EfTestError {
    fn from(err: std::io::Error) -> Self {
        Self::Execution(err.to_string())
    }
}

impl From<serde_json::Error> for EfTestError {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidTestData(err.to_string())
    }
}

impl From<alloy_rlp::Error> for EfTestError {
    fn from(err: alloy_rlp::Error) -> Self {
        Self::RlpDecode(err.to_string())
    }
}

/// Result type alias for EF test operations
pub type EfTestResult<T> = Result<T, EfTestError>;

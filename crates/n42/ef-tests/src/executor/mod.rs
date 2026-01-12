//! Test executors for running EF tests
//!
//! This module provides executors for different types of Ethereum Foundation tests:
//! - State tests: Execute a single transaction and verify the resulting state
//! - Blockchain tests: Execute a sequence of blocks and verify the chain state
//! - Transaction tests: Validate transaction decoding and intrinsic gas

mod blockchain_executor;
mod state_executor;
mod transaction_executor;

pub use blockchain_executor::BlockchainTestExecutor;
pub use state_executor::StateTestExecutor;
pub use transaction_executor::TransactionTestExecutor;

use crate::error::EfTestResult;
use crate::result::TestResult;

/// Trait for test executors
pub trait TestExecutor {
    /// The test type this executor handles
    type Test;

    /// Execute a single test and return the result
    fn execute(&self, test: &Self::Test, test_name: &str, fork: &str) -> EfTestResult<TestResult>;
}

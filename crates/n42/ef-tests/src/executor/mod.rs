//! Test executors for running EF tests
//!
//! This module provides executors for different types of Ethereum Foundation tests:
//! - State tests: Execute a single transaction and verify the resulting state
//! - Blockchain tests: Execute a sequence of blocks and verify the chain state

mod state_executor;

pub use state_executor::StateTestExecutor;

use crate::error::EfTestResult;
use crate::result::TestResult;

/// Trait for test executors
pub trait TestExecutor {
    /// The test type this executor handles
    type Test;

    /// Execute a single test and return the result
    fn execute(&self, test: &Self::Test, test_name: &str, fork: &str) -> EfTestResult<TestResult>;
}

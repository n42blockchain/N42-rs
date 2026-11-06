//! Test executors for running EF tests
//!
//! This module provides executors for different types of Ethereum Foundation tests:
//! - State tests: Execute a single transaction and verify the resulting state
//! - Blockchain tests: Execute a sequence of blocks and verify the chain state
//! - Transaction tests: Validate transaction decoding and intrinsic gas

mod blockchain_executor;
mod state_db;
mod state_executor;
mod transaction_executor;

pub use blockchain_executor::BlockchainTestExecutor;
pub use state_executor::StateTestExecutor;
pub use transaction_executor::TransactionTestExecutor;

use crate::error::EfTestResult;
use crate::fork::ForkSpec;
use crate::result::TestResult;

/// Trait for test executors
pub trait TestExecutor {
    /// The test type this executor handles
    type Test;

    /// Execute a single test and return the result
    fn execute(&self, test: &Self::Test, test_name: &str, fork: &str) -> EfTestResult<TestResult>;
}

/// Maps a fixture fork to the evm2 specification it executes under.
pub(crate) const fn spec_id_for_fork(fork: ForkSpec) -> evm2::SpecId {
    use evm2::SpecId;
    match fork {
        ForkSpec::Frontier => SpecId::FRONTIER,
        ForkSpec::Homestead | ForkSpec::DaoFork => SpecId::HOMESTEAD,
        ForkSpec::TangerineWhistle => SpecId::TANGERINE,
        ForkSpec::SpuriousDragon => SpecId::SPURIOUS_DRAGON,
        ForkSpec::Byzantium => SpecId::BYZANTIUM,
        ForkSpec::Constantinople | ForkSpec::Petersburg => SpecId::PETERSBURG,
        ForkSpec::Istanbul | ForkSpec::MuirGlacier => SpecId::ISTANBUL,
        ForkSpec::Berlin => SpecId::BERLIN,
        ForkSpec::London | ForkSpec::ArrowGlacier | ForkSpec::GrayGlacier => SpecId::LONDON,
        ForkSpec::Paris => SpecId::MERGE,
        ForkSpec::Shanghai => SpecId::SHANGHAI,
        ForkSpec::Cancun => SpecId::CANCUN,
        ForkSpec::Prague | ForkSpec::Osaka => SpecId::PRAGUE,
    }
}

//! N42 Ethereum Foundation Test Suite
//!
//! This crate provides a comprehensive framework for running Ethereum Foundation (EF) tests
//! against the N42 execution client. It includes:
//!
//! - Data models for parsing EF test fixtures (state tests, blockchain tests)
//! - Test executors for running tests against the EVM
//! - Test suite management and discovery
//! - Result reporting and validation
//!
//! # Usage
//!
//! ```rust,ignore
//! use n42_ef_tests::suite::{StateTestSuite, Suite};
//!
//! let suite = StateTestSuite::new("/path/to/fixtures/state_tests");
//! let report = suite.run_all().await?;
//! println!("Passed: {}, Failed: {}", report.passed, report.failed);
//! ```

#![warn(missing_docs)]
#![warn(unused_crate_dependencies)]

pub mod error;
pub mod executor;
pub mod fork;
pub mod models;
pub mod result;
pub mod suite;
pub mod utils;

// Re-export commonly used types
pub use error::EfTestError;
pub use fork::ForkSpec;
pub use models::{Account, BlockchainTest, StateTest};
pub use result::{TestReport, TestResult, TestStatus};
pub use suite::{BlockchainTestSuite, StateTestSuite, Suite, TestDiscovery};

//! Test suite management and discovery
//!
//! This module provides the infrastructure for organizing and running EF tests:
//! - Test discovery: Find and load test fixtures from the filesystem
//! - Test suites: Group related tests together
//! - Parallel execution support

mod discovery;
mod suite;

pub use discovery::TestDiscovery;
pub use suite::{BlockchainTestSuite, StateTestSuite, Suite};

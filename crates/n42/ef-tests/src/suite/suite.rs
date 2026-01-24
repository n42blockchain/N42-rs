//! Test suite implementations

use crate::error::{EfTestError, EfTestResult};
use crate::executor::{BlockchainTestExecutor, StateTestExecutor};
use crate::fork::{is_fork_supported, ForkSpec};
use crate::models::{BlockchainTest, StateTest};
use crate::result::{TestReport, TestReportBuilder, TestResult};
use crate::suite::TestDiscovery;
use crate::utils::TestFilter;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Trait for test suites
pub trait Suite {
    /// Run all tests in the suite
    fn run_all(&self) -> EfTestResult<TestReport>;

    /// Run tests matching a filter
    fn run_filtered(&self, filter: &TestFilter) -> EfTestResult<TestReport>;

    /// Get the number of tests in the suite
    fn test_count(&self) -> usize;

    /// Get the suite name
    fn name(&self) -> &str;
}

/// State test suite
#[derive(Debug)]
pub struct StateTestSuite {
    /// Suite name
    name: String,
    /// Test discovery
    discovery: TestDiscovery,
    /// Forks to test
    forks: Vec<String>,
    /// Whether to run tests in parallel
    parallel: bool,
    /// Chain ID to use
    chain_id: u64,
}

impl StateTestSuite {
    /// Create a new state test suite
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            name: "State Tests".to_string(),
            discovery: TestDiscovery::new(base_path),
            forks: Vec::new(),
            parallel: true,
            chain_id: 1,
        }
    }

    /// Set the suite name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Add specific forks to test
    pub fn with_forks(mut self, forks: Vec<String>) -> Self {
        self.forks = forks;
        self
    }

    /// Set whether to run tests in parallel
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Set the chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Run a single test file
    pub fn run_test_file(
        &self,
        file_path: &Path,
        filter: Option<&TestFilter>,
    ) -> EfTestResult<Vec<TestResult>> {
        let tests = self.discovery.load_state_test_file(file_path)?;
        let mut results = Vec::new();

        for (test_name, test) in &tests {
            // Check filter
            if let Some(f) = filter {
                if !f.matches(test_name) {
                    continue;
                }
            }

            // Run test for each fork
            let test_forks: Vec<_> = if self.forks.is_empty() {
                test.forks().into_iter().map(String::from).collect()
            } else {
                self.forks.clone()
            };

            for fork in test_forks {
                // Check if fork is supported
                if !is_fork_supported(&fork) {
                    results.push(TestResult::skipped(
                        test_name.clone(),
                        fork.clone(),
                        format!("Unsupported fork: {}", fork),
                    ));
                    continue;
                }

                // Check fork filter
                if let Some(f) = filter {
                    if !f.matches_fork(&fork) {
                        continue;
                    }
                }

                // Get the post-state results for this fork
                if let Some(post_results) = test.post_for_fork(&fork) {
                    // Run each variant
                    for (variant_idx, _) in post_results.iter().enumerate() {
                        let result = self.run_test_variant(
                            test,
                            test_name,
                            &fork,
                            variant_idx,
                        );
                        results.push(result);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Run a single test variant
    fn run_test_variant(
        &self,
        test: &StateTest,
        test_name: &str,
        fork: &str,
        variant_index: usize,
    ) -> TestResult {
        let fork_spec = match ForkSpec::from_name(fork) {
            Ok(f) => f,
            Err(e) => {
                return TestResult::skipped(test_name.to_string(), fork.to_string(), e.to_string());
            }
        };

        let executor = StateTestExecutor::new(&fork_spec, self.chain_id);

        match executor.execute(test, test_name, fork, variant_index) {
            Ok(result) => result,
            Err(e) => TestResult::failed(
                test_name.to_string(),
                fork.to_string(),
                std::time::Duration::ZERO,
                e.to_string(),
            )
            .with_variant(variant_index),
        }
    }

    /// Run all tests in a directory
    fn run_directory(&self, filter: Option<&TestFilter>) -> EfTestResult<TestReport> {
        let start = Instant::now();
        let mut builder = TestReportBuilder::new(&self.name);

        let files = self.discovery.discover_files()?;
        info!("Running {} test files", files.len());

        if self.parallel {
            // Run tests in parallel
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|file| {
                    match self.run_test_file(file, filter) {
                        Ok(results) => Some(results),
                        Err(e) => {
                            warn!("Error running test file {}: {}", file.display(), e);
                            None
                        }
                    }
                })
                .flatten()
                .collect();

            for result in results {
                builder.add_result(result);
            }
        } else {
            // Run tests sequentially
            for file in &files {
                match self.run_test_file(file, filter) {
                    Ok(results) => {
                        for result in results {
                            builder.add_result(result);
                        }
                    }
                    Err(e) => {
                        warn!("Error running test file {}: {}", file.display(), e);
                    }
                }
            }
        }

        let report = builder.build();
        info!(
            "Completed {} tests in {:?}",
            report.summary.total(),
            start.elapsed()
        );

        Ok(report)
    }
}

impl Suite for StateTestSuite {
    fn run_all(&self) -> EfTestResult<TestReport> {
        self.run_directory(None)
    }

    fn run_filtered(&self, filter: &TestFilter) -> EfTestResult<TestReport> {
        self.run_directory(Some(filter))
    }

    fn test_count(&self) -> usize {
        // Estimate based on discovered files
        self.discovery.discover_files().map(|f| f.len()).unwrap_or(0)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Blockchain test suite
#[derive(Debug)]
pub struct BlockchainTestSuite {
    /// Suite name
    name: String,
    /// Test discovery
    discovery: TestDiscovery,
    /// Forks to test
    forks: Vec<String>,
    /// Whether to run tests in parallel
    parallel: bool,
    /// Chain ID to use
    chain_id: u64,
}

impl BlockchainTestSuite {
    /// Create a new blockchain test suite
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            name: "Blockchain Tests".to_string(),
            discovery: TestDiscovery::new(base_path),
            forks: Vec::new(),
            parallel: true,
            chain_id: 1,
        }
    }

    /// Set the suite name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Add specific forks to test
    pub fn with_forks(mut self, forks: Vec<String>) -> Self {
        self.forks = forks;
        self
    }

    /// Set whether to run tests in parallel
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Set the chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Run a single test file
    pub fn run_test_file(
        &self,
        file_path: &Path,
        filter: Option<&TestFilter>,
    ) -> EfTestResult<Vec<TestResult>> {
        let tests = self.discovery.load_blockchain_test_file(file_path)?;
        let mut results = Vec::new();

        eprintln!("DEBUG: Loaded {} tests from {}", tests.len(), file_path.display());

        for (test_name, test) in &tests {
            // Check filter
            if let Some(f) = filter {
                if !f.matches(test_name) {
                    continue;
                }
            }

            let fork = test.fork();

            // Check if fork is supported
            if !is_fork_supported(fork) {
                results.push(TestResult::skipped(
                    test_name.clone(),
                    fork.to_string(),
                    format!("Unsupported fork: {}", fork),
                ));
                continue;
            }

            // Check fork filter
            if let Some(f) = filter {
                if !f.matches_fork(fork) {
                    continue;
                }
            }

            // Run the blockchain test
            let result = self.run_blockchain_test(test, test_name);
            results.push(result);
        }

        Ok(results)
    }

    /// Run a single blockchain test
    fn run_blockchain_test(&self, test: &BlockchainTest, test_name: &str) -> TestResult {
        let fork_spec = match ForkSpec::from_name(test.fork()) {
            Ok(f) => f,
            Err(e) => {
                return TestResult::skipped(
                    test_name.to_string(),
                    test.fork().to_string(),
                    e.to_string(),
                );
            }
        };

        let executor = BlockchainTestExecutor::new(&fork_spec, self.chain_id);

        match executor.execute(test, test_name) {
            Ok(result) => result,
            Err(e) => TestResult::failed(
                test_name.to_string(),
                test.fork().to_string(),
                std::time::Duration::ZERO,
                e.to_string(),
            ),
        }
    }

    /// Run all tests in a directory
    fn run_directory(&self, filter: Option<&TestFilter>) -> EfTestResult<TestReport> {
        let start = Instant::now();
        let mut builder = TestReportBuilder::new(&self.name);

        let files = self.discovery.discover_files()?;
        eprintln!("DEBUG: Discovered {} blockchain test files", files.len());
        eprintln!("DEBUG: Parallel mode: {}", self.parallel);
        info!("Running {} blockchain test files", files.len());

        if self.parallel {
            eprintln!("DEBUG: Using parallel execution");
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|file| {
                    eprintln!("DEBUG: [parallel] Processing file: {}", file.display());
                    match self.run_test_file(file, filter) {
                        Ok(results) => {
                            eprintln!("DEBUG: [parallel] Got {} results from file", results.len());
                            Some(results)
                        }
                        Err(e) => {
                            eprintln!("DEBUG: [parallel] Error running test file {}: {}", file.display(), e);
                            warn!("Error running test file {}: {}", file.display(), e);
                            None
                        }
                    }
                })
                .flatten()
                .collect();

            eprintln!("DEBUG: Collected {} total results from parallel execution", results.len());
            for result in results {
                builder.add_result(result);
            }
        } else {
            eprintln!("DEBUG: Using sequential execution");
            eprintln!("DEBUG: files.len() = {}", files.len());
            for (i, file) in files.iter().enumerate() {
                eprintln!("DEBUG: [{}] Processing file: {}", i, file.display());
                match self.run_test_file(file, filter) {
                    Ok(results) => {
                        eprintln!("DEBUG: [{}] Got {} results from file", i, results.len());
                        for result in results {
                            builder.add_result(result);
                        }
                    }
                    Err(e) => {
                        eprintln!("DEBUG: [{}] Error: {}", i, e);
                        warn!("Error running test file {}: {}", file.display(), e);
                    }
                }
            }
        }

        let report = builder.build();
        info!(
            "Completed {} blockchain tests in {:?}",
            report.summary.total(),
            start.elapsed()
        );

        Ok(report)
    }
}

impl Suite for BlockchainTestSuite {
    fn run_all(&self) -> EfTestResult<TestReport> {
        self.run_directory(None)
    }

    fn run_filtered(&self, filter: &TestFilter) -> EfTestResult<TestReport> {
        self.run_directory(Some(filter))
    }

    fn test_count(&self) -> usize {
        self.discovery.discover_files().map(|f| f.len()).unwrap_or(0)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Transaction test suite
#[derive(Debug)]
pub struct TransactionTestSuite {
    /// Suite name
    name: String,
    /// Test discovery
    discovery: TestDiscovery,
    /// Forks to test
    forks: Vec<String>,
    /// Whether to run tests in parallel
    parallel: bool,
}

impl TransactionTestSuite {
    /// Create a new transaction test suite
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            name: "Transaction Tests".to_string(),
            discovery: TestDiscovery::new(base_path),
            forks: Vec::new(),
            parallel: true,
        }
    }

    /// Set the suite name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Add specific forks to test
    pub fn with_forks(mut self, forks: Vec<String>) -> Self {
        self.forks = forks;
        self
    }

    /// Set whether to run tests in parallel
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Run a single test file
    pub fn run_test_file(
        &self,
        file_path: &Path,
        filter: Option<&TestFilter>,
    ) -> EfTestResult<Vec<TestResult>> {
        let tests = self.load_transaction_test_file(file_path)?;
        let mut results = Vec::new();

        for (test_name, test) in &tests {
            // Check filter
            if let Some(f) = filter {
                if !f.matches(test_name) {
                    continue;
                }
            }

            // Run test for each fork it covers
            for fork in test.forks() {
                if !is_fork_supported(fork) {
                    results.push(TestResult::skipped(
                        test_name.clone(),
                        fork.to_string(),
                        format!("Unsupported fork: {}", fork),
                    ));
                    continue;
                }

                // Check fork filter
                if let Some(f) = filter {
                    if !f.matches_fork(fork) {
                        continue;
                    }
                }

                // Check suite fork filter
                if !self.forks.is_empty() && !self.forks.iter().any(|f| f.eq_ignore_ascii_case(fork)) {
                    continue;
                }

                let result = self.run_transaction_test(test, test_name, fork);
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Run a single transaction test
    fn run_transaction_test(&self, test: &crate::models::TransactionTest, test_name: &str, fork: &str) -> TestResult {
        use crate::executor::TransactionTestExecutor;

        let fork_spec = match ForkSpec::from_name(fork) {
            Ok(f) => f,
            Err(e) => {
                return TestResult::skipped(
                    test_name.to_string(),
                    fork.to_string(),
                    e.to_string(),
                );
            }
        };

        let executor = TransactionTestExecutor::new(&fork_spec);

        match executor.execute(test, test_name, fork) {
            Ok(result) => result,
            Err(e) => TestResult::failed(
                test_name.to_string(),
                fork.to_string(),
                std::time::Duration::ZERO,
                e.to_string(),
            ),
        }
    }

    /// Load a transaction test file
    fn load_transaction_test_file(&self, path: &Path) -> EfTestResult<std::collections::HashMap<String, crate::models::TransactionTest>> {
        let content = std::fs::read_to_string(path).map_err(|e| EfTestError::FixtureRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        serde_json::from_str(&content).map_err(|e| EfTestError::JsonParse {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Run all tests in a directory
    fn run_directory(&self, filter: Option<&TestFilter>) -> EfTestResult<TestReport> {
        let start = Instant::now();
        let mut builder = TestReportBuilder::new(&self.name);

        let files = self.discovery.discover_files()?;
        info!("Running {} transaction test files", files.len());

        if self.parallel {
            let results: Vec<_> = files
                .par_iter()
                .filter_map(|file| match self.run_test_file(file, filter) {
                    Ok(results) => Some(results),
                    Err(e) => {
                        warn!("Error running test file {}: {}", file.display(), e);
                        None
                    }
                })
                .flatten()
                .collect();

            for result in results {
                builder.add_result(result);
            }
        } else {
            for file in &files {
                match self.run_test_file(file, filter) {
                    Ok(results) => {
                        for result in results {
                            builder.add_result(result);
                        }
                    }
                    Err(e) => {
                        warn!("Error running test file {}: {}", file.display(), e);
                    }
                }
            }
        }

        let report = builder.build();
        info!(
            "Completed {} transaction tests in {:?}",
            report.summary.total(),
            start.elapsed()
        );

        Ok(report)
    }
}

impl Suite for TransactionTestSuite {
    fn run_all(&self) -> EfTestResult<TestReport> {
        self.run_directory(None)
    }

    fn run_filtered(&self, filter: &TestFilter) -> EfTestResult<TestReport> {
        self.run_directory(Some(filter))
    }

    fn test_count(&self) -> usize {
        self.discovery.discover_files().map(|f| f.len()).unwrap_or(0)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_state_suite_creation() {
        let suite = StateTestSuite::new("/tmp/tests")
            .with_name("My Tests")
            .with_parallel(false)
            .with_chain_id(5);

        assert_eq!(suite.name(), "My Tests");
        assert!(!suite.parallel);
        assert_eq!(suite.chain_id, 5);
    }

    #[test]
    fn test_blockchain_suite_creation() {
        let suite = BlockchainTestSuite::new("/tmp/tests")
            .with_name("Blockchain")
            .with_forks(vec!["Berlin".to_string()]);

        assert_eq!(suite.name(), "Blockchain");
        assert_eq!(suite.forks, vec!["Berlin"]);
    }
}

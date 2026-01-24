//! Test result types and reporting
//!
//! This module provides types for representing test results and generating reports.

mod report;

pub use report::{TestReport, TestReportBuilder};

use crate::error::EfTestError;
use alloy_primitives::B256;
use serde::{Serialize, Deserialize};
use std::time::Duration;

/// Status of a test execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestStatus {
    /// Test passed successfully
    Passed,
    /// Test failed
    Failed,
    /// Test was skipped
    Skipped,
}

impl TestStatus {
    /// Check if the test passed
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Check if the test failed
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Check if the test was skipped
    pub fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped)
    }
}

impl std::fmt::Display for TestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passed => write!(f, "PASSED"),
            Self::Failed => write!(f, "FAILED"),
            Self::Skipped => write!(f, "SKIPPED"),
        }
    }
}

/// Result of a single test case execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test name/identifier
    pub name: String,
    /// Fork specification used
    pub fork: String,
    /// Test status
    pub status: TestStatus,
    /// Execution duration in milliseconds
    #[serde(with = "duration_ms")]
    pub duration: Duration,
    /// Error message if failed
    pub error: Option<String>,
    /// Expected state root
    pub expected_state_root: Option<B256>,
    /// Actual computed state root
    pub actual_state_root: Option<B256>,
    /// Expected logs hash
    pub expected_logs_hash: Option<B256>,
    /// Actual computed logs hash
    pub actual_logs_hash: Option<B256>,
    /// Test variant index (for multi-variant tests)
    pub variant_index: Option<usize>,
}

impl TestResult {
    /// Create a passed test result
    pub fn passed(name: String, fork: String, duration: Duration) -> Self {
        Self {
            name,
            fork,
            status: TestStatus::Passed,
            duration,
            error: None,
            expected_state_root: None,
            actual_state_root: None,
            expected_logs_hash: None,
            actual_logs_hash: None,
            variant_index: None,
        }
    }

    /// Create a failed test result
    pub fn failed(name: String, fork: String, duration: Duration, error: String) -> Self {
        Self {
            name,
            fork,
            status: TestStatus::Failed,
            duration,
            error: Some(error),
            expected_state_root: None,
            actual_state_root: None,
            expected_logs_hash: None,
            actual_logs_hash: None,
            variant_index: None,
        }
    }

    /// Create a skipped test result
    pub fn skipped(name: String, fork: String, reason: String) -> Self {
        Self {
            name,
            fork,
            status: TestStatus::Skipped,
            duration: Duration::ZERO,
            error: Some(reason),
            expected_state_root: None,
            actual_state_root: None,
            expected_logs_hash: None,
            actual_logs_hash: None,
            variant_index: None,
        }
    }

    /// Create a result from an error
    pub fn from_error(name: String, fork: String, duration: Duration, err: EfTestError) -> Self {
        match err {
            EfTestError::Skipped(reason) => Self::skipped(name, fork, reason),
            err => Self::failed(name, fork, duration, err.to_string()),
        }
    }

    /// Set the expected and actual state roots
    pub fn with_state_roots(mut self, expected: B256, actual: B256) -> Self {
        self.expected_state_root = Some(expected);
        self.actual_state_root = Some(actual);
        self
    }

    /// Set the expected and actual logs hashes
    pub fn with_logs_hashes(mut self, expected: B256, actual: B256) -> Self {
        self.expected_logs_hash = Some(expected);
        self.actual_logs_hash = Some(actual);
        self
    }

    /// Set the variant index
    pub fn with_variant(mut self, index: usize) -> Self {
        self.variant_index = Some(index);
        self
    }

    /// Check if state roots match
    pub fn state_roots_match(&self) -> bool {
        match (self.expected_state_root, self.actual_state_root) {
            (Some(expected), Some(actual)) => expected == actual,
            _ => true, // No roots to compare
        }
    }

    /// Check if logs hashes match
    pub fn logs_hashes_match(&self) -> bool {
        match (self.expected_logs_hash, self.actual_logs_hash) {
            (Some(expected), Some(actual)) => expected == actual,
            _ => true, // No hashes to compare
        }
    }

    /// Get a display-friendly name including variant
    pub fn display_name(&self) -> String {
        match self.variant_index {
            Some(idx) => format!("{}[{}] ({})", self.name, idx, self.fork),
            None => format!("{} ({})", self.name, self.fork),
        }
    }
}

impl std::fmt::Display for TestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} ({:?})", self.status, self.display_name(), self.duration)?;
        if let Some(ref err) = self.error {
            write!(f, " - {}", err)?;
        }
        Ok(())
    }
}

/// Summary statistics for a test run
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestSummary {
    /// Number of passed tests
    pub passed: usize,
    /// Number of failed tests
    pub failed: usize,
    /// Number of skipped tests
    pub skipped: usize,
    /// Total execution time in milliseconds
    #[serde(with = "duration_ms")]
    pub total_duration: Duration,
}

/// Serde helper module for serializing Duration as milliseconds
mod duration_ms {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ms = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(ms))
    }
}

impl TestSummary {
    /// Create a new empty summary
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of tests
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.skipped
    }

    /// Pass rate as a percentage
    pub fn pass_rate(&self) -> f64 {
        let total = self.passed + self.failed;
        if total == 0 {
            100.0
        } else {
            (self.passed as f64 / total as f64) * 100.0
        }
    }

    /// Add a result to the summary
    pub fn add_result(&mut self, result: &TestResult) {
        match result.status {
            TestStatus::Passed => self.passed += 1,
            TestStatus::Failed => self.failed += 1,
            TestStatus::Skipped => self.skipped += 1,
        }
        self.total_duration += result.duration;
    }

    /// Merge another summary into this one
    pub fn merge(&mut self, other: &TestSummary) {
        self.passed += other.passed;
        self.failed += other.failed;
        self.skipped += other.skipped;
        self.total_duration += other.total_duration;
    }
}

impl std::fmt::Display for TestSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Passed: {}, Failed: {}, Skipped: {}, Pass Rate: {:.1}%, Duration: {:?}",
            self.passed,
            self.failed,
            self.skipped,
            self.pass_rate(),
            self.total_duration
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_status() {
        let passed = TestResult::passed("test".to_string(), "Berlin".to_string(), Duration::from_millis(100));
        assert!(passed.status.is_passed());

        let failed = TestResult::failed(
            "test".to_string(),
            "Berlin".to_string(),
            Duration::from_millis(100),
            "error".to_string(),
        );
        assert!(failed.status.is_failed());

        let skipped = TestResult::skipped("test".to_string(), "Berlin".to_string(), "reason".to_string());
        assert!(skipped.status.is_skipped());
    }

    #[test]
    fn test_summary() {
        let mut summary = TestSummary::new();

        summary.add_result(&TestResult::passed("t1".to_string(), "Berlin".to_string(), Duration::from_millis(10)));
        summary.add_result(&TestResult::passed("t2".to_string(), "Berlin".to_string(), Duration::from_millis(10)));
        summary.add_result(&TestResult::failed(
            "t3".to_string(),
            "Berlin".to_string(),
            Duration::from_millis(10),
            "error".to_string(),
        ));

        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.total(), 3);
        assert!((summary.pass_rate() - 66.66).abs() < 1.0);
    }
}

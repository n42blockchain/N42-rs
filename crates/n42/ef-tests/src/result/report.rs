//! Test report generation

use super::{TestResult, TestStatus, TestSummary};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// A comprehensive test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    /// Report name/title
    pub name: String,
    /// All test results
    pub results: Vec<TestResult>,
    /// Summary statistics
    pub summary: TestSummary,
    /// Results grouped by fork
    pub by_fork: HashMap<String, Vec<TestResult>>,
    /// Results grouped by status
    pub by_status: HashMap<TestStatus, Vec<TestResult>>,
    /// Start time of the test run (not serializable)
    #[serde(skip)]
    pub started_at: Option<Instant>,
    /// End time of the test run (not serializable)
    #[serde(skip)]
    pub ended_at: Option<Instant>,
    /// Timestamp when the report was generated (ISO 8601 format)
    #[serde(default)]
    pub generated_at: Option<String>,
}

impl TestReport {
    /// Create a new empty report
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            results: Vec::new(),
            summary: TestSummary::new(),
            by_fork: HashMap::new(),
            by_status: HashMap::new(),
            started_at: None,
            ended_at: None,
            generated_at: None,
        }
    }

    /// Add a test result to the report
    pub fn add_result(&mut self, result: TestResult) {
        self.summary.add_result(&result);

        // Group by fork
        self.by_fork
            .entry(result.fork.clone())
            .or_default()
            .push(result.clone());

        // Group by status
        self.by_status
            .entry(result.status)
            .or_default()
            .push(result.clone());

        self.results.push(result);
    }

    /// Get all failed tests
    pub fn failures(&self) -> &[TestResult] {
        self.by_status
            .get(&TestStatus::Failed)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all passed tests
    pub fn passes(&self) -> &[TestResult] {
        self.by_status
            .get(&TestStatus::Passed)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all skipped tests
    pub fn skips(&self) -> &[TestResult] {
        self.by_status
            .get(&TestStatus::Skipped)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get results for a specific fork
    pub fn for_fork(&self, fork: &str) -> &[TestResult] {
        self.by_fork.get(fork).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.summary.failed == 0
    }

    /// Get the total duration
    pub fn total_duration(&self) -> Duration {
        match (self.started_at, self.ended_at) {
            (Some(start), Some(end)) => end.duration_since(start),
            _ => self.summary.total_duration,
        }
    }

    /// Generate a summary report as a string
    pub fn summary_report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("=== {} ===\n", self.name));
        report.push_str(&format!("{}\n\n", self.summary));

        // Summary by fork
        if !self.by_fork.is_empty() {
            report.push_str("Results by fork:\n");
            let mut forks: Vec<_> = self.by_fork.keys().collect();
            forks.sort();
            for fork in forks {
                let results = &self.by_fork[fork];
                let passed = results.iter().filter(|r| r.status.is_passed()).count();
                let failed = results.iter().filter(|r| r.status.is_failed()).count();
                let skipped = results.iter().filter(|r| r.status.is_skipped()).count();
                report.push_str(&format!(
                    "  {}: {} passed, {} failed, {} skipped\n",
                    fork, passed, failed, skipped
                ));
            }
            report.push('\n');
        }

        // List failures
        if !self.failures().is_empty() {
            report.push_str("Failures:\n");
            for (i, failure) in self.failures().iter().take(20).enumerate() {
                report.push_str(&format!(
                    "  {}. {} - {}\n",
                    i + 1,
                    failure.display_name(),
                    failure.error.as_deref().unwrap_or("Unknown error")
                ));
            }
            if self.failures().len() > 20 {
                report.push_str(&format!("  ... and {} more\n", self.failures().len() - 20));
            }
        }

        report
    }

    /// Generate a detailed report as a string
    pub fn detailed_report(&self) -> String {
        let mut report = self.summary_report();

        report.push_str("\nAll Results:\n");
        for result in &self.results {
            report.push_str(&format!("  {}\n", result));
        }

        report
    }

    /// Merge another report into this one
    pub fn merge(&mut self, other: TestReport) {
        for result in other.results {
            self.add_result(result);
        }
    }

    /// Save the report as a JSON file
    pub fn save_json(&mut self, path: impl AsRef<Path>) -> std::io::Result<()> {
        use std::io::Write;

        // Set the generated timestamp
        self.generated_at = Some(chrono::Utc::now().to_rfc3339());

        // Create parent directories if they don't exist
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut file = std::fs::File::create(path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    /// Load a report from a JSON file
    pub fn load_json(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl std::fmt::Display for TestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary_report())
    }
}

/// Builder for creating test reports
#[derive(Debug)]
pub struct TestReportBuilder {
    name: String,
    results: Vec<TestResult>,
    started_at: Option<Instant>,
}

impl TestReportBuilder {
    /// Create a new builder
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            results: Vec::new(),
            started_at: None,
        }
    }

    /// Start timing the test run
    pub fn start(mut self) -> Self {
        self.started_at = Some(Instant::now());
        self
    }

    /// Add a test result
    pub fn add_result(&mut self, result: TestResult) {
        self.results.push(result);
    }

    /// Add multiple test results
    pub fn add_results(&mut self, results: impl IntoIterator<Item = TestResult>) {
        self.results.extend(results);
    }

    /// Build the final report
    pub fn build(self) -> TestReport {
        let mut report = TestReport::new(self.name);
        report.started_at = self.started_at;
        report.ended_at = Some(Instant::now());

        for result in self.results {
            report.add_result(result);
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_builder() {
        let mut builder = TestReportBuilder::new("Test Suite").start();

        builder.add_result(TestResult::passed(
            "test1".to_string(),
            "Berlin".to_string(),
            Duration::from_millis(10),
        ));
        builder.add_result(TestResult::failed(
            "test2".to_string(),
            "London".to_string(),
            Duration::from_millis(20),
            "error".to_string(),
        ));

        let report = builder.build();

        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.results.len(), 2);
    }

    #[test]
    fn test_report_by_fork() {
        let mut report = TestReport::new("Test");

        report.add_result(TestResult::passed(
            "test1".to_string(),
            "Berlin".to_string(),
            Duration::from_millis(10),
        ));
        report.add_result(TestResult::passed(
            "test2".to_string(),
            "Berlin".to_string(),
            Duration::from_millis(10),
        ));
        report.add_result(TestResult::passed(
            "test3".to_string(),
            "London".to_string(),
            Duration::from_millis(10),
        ));

        assert_eq!(report.for_fork("Berlin").len(), 2);
        assert_eq!(report.for_fork("London").len(), 1);
        assert_eq!(report.for_fork("Cancun").len(), 0);
    }
}

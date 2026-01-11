//! Test discovery for finding EF test fixtures

use crate::error::{EfTestError, EfTestResult};
use crate::models::{BlockchainTest, StateTest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

/// Test discovery utility for finding and loading test fixtures
#[derive(Debug, Clone)]
pub struct TestDiscovery {
    /// Base path for test fixtures
    base_path: PathBuf,
    /// File patterns to include
    include_patterns: Vec<String>,
    /// File patterns to exclude
    exclude_patterns: Vec<String>,
}

impl TestDiscovery {
    /// Create a new test discovery instance
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
            include_patterns: vec!["*.json".to_string()],
            exclude_patterns: Vec::new(),
        }
    }

    /// Add an include pattern
    pub fn include(mut self, pattern: impl Into<String>) -> Self {
        self.include_patterns.push(pattern.into());
        self
    }

    /// Add an exclude pattern
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.exclude_patterns.push(pattern.into());
        self
    }

    /// Get the base path
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Discover all test fixture files
    pub fn discover_files(&self) -> EfTestResult<Vec<PathBuf>> {
        let mut files = Vec::new();

        if !self.base_path.exists() {
            return Err(EfTestError::Discovery(format!(
                "Base path does not exist: {}",
                self.base_path.display()
            )));
        }

        for entry in WalkDir::new(&self.base_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Check file extension
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Check include patterns
            let included = self.include_patterns.is_empty()
                || self
                    .include_patterns
                    .iter()
                    .any(|p| matches_pattern(file_name, p));

            if !included {
                continue;
            }

            // Check exclude patterns
            let excluded = self
                .exclude_patterns
                .iter()
                .any(|p| matches_pattern(file_name, p));

            if excluded {
                continue;
            }

            files.push(path.to_path_buf());
        }

        info!("Discovered {} test files in {}", files.len(), self.base_path.display());
        Ok(files)
    }

    /// Discover test files in a specific subdirectory
    pub fn discover_in_subdir(&self, subdir: &str) -> EfTestResult<Vec<PathBuf>> {
        let path = self.base_path.join(subdir);
        if !path.exists() {
            return Err(EfTestError::Discovery(format!(
                "Subdirectory does not exist: {}",
                path.display()
            )));
        }

        let discovery = Self::new(path)
            .include("*.json");
        discovery.discover_files()
    }

    /// Load a single state test file
    pub fn load_state_test_file(&self, path: &Path) -> EfTestResult<HashMap<String, StateTest>> {
        let content = std::fs::read_to_string(path).map_err(|e| EfTestError::FixtureRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        serde_json::from_str(&content).map_err(|e| EfTestError::JsonParse {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Load a single blockchain test file
    pub fn load_blockchain_test_file(
        &self,
        path: &Path,
    ) -> EfTestResult<HashMap<String, BlockchainTest>> {
        let content = std::fs::read_to_string(path).map_err(|e| EfTestError::FixtureRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        serde_json::from_str(&content).map_err(|e| EfTestError::JsonParse {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Load all state tests from discovered files
    pub fn load_all_state_tests(&self) -> EfTestResult<Vec<(PathBuf, HashMap<String, StateTest>)>> {
        let files = self.discover_files()?;
        let mut all_tests = Vec::new();

        for file in files {
            match self.load_state_test_file(&file) {
                Ok(tests) => {
                    debug!("Loaded {} tests from {}", tests.len(), file.display());
                    all_tests.push((file, tests));
                }
                Err(e) => {
                    warn!("Failed to load test file {}: {}", file.display(), e);
                }
            }
        }

        Ok(all_tests)
    }

    /// Load all blockchain tests from discovered files
    pub fn load_all_blockchain_tests(
        &self,
    ) -> EfTestResult<Vec<(PathBuf, HashMap<String, BlockchainTest>)>> {
        let files = self.discover_files()?;
        let mut all_tests = Vec::new();

        for file in files {
            match self.load_blockchain_test_file(&file) {
                Ok(tests) => {
                    debug!("Loaded {} tests from {}", tests.len(), file.display());
                    all_tests.push((file, tests));
                }
                Err(e) => {
                    warn!("Failed to load test file {}: {}", file.display(), e);
                }
            }
        }

        Ok(all_tests)
    }

    /// Get a list of available forks from state test directory names
    pub fn available_forks(&self) -> EfTestResult<Vec<String>> {
        let mut forks = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.base_path) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        // Skip hidden directories
                        if !name.starts_with('.') {
                            forks.push(name.to_string());
                        }
                    }
                }
            }
        }

        forks.sort();
        Ok(forks)
    }
}

/// Simple pattern matching (supports * as wildcard)
fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with('*') && pattern.ends_with('*') {
        let middle = &pattern[1..pattern.len() - 1];
        return name.contains(middle);
    }

    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        return name.ends_with(suffix);
    }

    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return name.starts_with(prefix);
    }

    name == pattern
}

/// Test case metadata extracted from a test file
#[derive(Debug, Clone)]
pub struct TestCaseInfo {
    /// Path to the test file
    pub file_path: PathBuf,
    /// Test name within the file
    pub test_name: String,
    /// Fork name
    pub fork: String,
    /// Number of variants
    pub variant_count: usize,
}

impl TestCaseInfo {
    /// Create a unique identifier for this test case
    pub fn id(&self) -> String {
        format!(
            "{}::{}::{}",
            self.file_path.display(),
            self.test_name,
            self.fork
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("test.json", "*.json"));
        assert!(matches_pattern("test.json", "*"));
        assert!(!matches_pattern("test.json", "*.txt"));
        assert!(matches_pattern("prefix_test", "prefix*"));
        assert!(matches_pattern("test_suffix", "*suffix"));
        assert!(matches_pattern("contains_word_here", "*word*"));
    }

    #[test]
    fn test_discovery_new() {
        let discovery = TestDiscovery::new("/tmp/tests");
        assert_eq!(discovery.base_path(), Path::new("/tmp/tests"));
    }
}

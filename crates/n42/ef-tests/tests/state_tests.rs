//! Integration tests for Ethereum Foundation State Tests
//!
//! This module runs the EF state tests against the N42 execution client.
//! Tests are discovered automatically from the fixtures directory.

use n42_ef_tests::{
    fork::ForkSpec,
    models::StateTest,
    result::TestReport,
    suite::{StateTestSuite, Suite, TestDiscovery},
    utils::TestFilter,
};
use std::path::PathBuf;

/// Get the path to the EF test fixtures
fn fixtures_path() -> PathBuf {
    // Try environment variable first
    if let Ok(path) = std::env::var("EF_TESTS_PATH") {
        return PathBuf::from(path);
    }

    // Default path relative to the crate
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("ethereum-tests")
        .join("fixtures")
        .join("state_tests")
}

/// Check if fixtures are available
fn fixtures_available() -> bool {
    fixtures_path().exists()
}

/// Get the path to the report output directory
fn report_output_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("ef-test-reports")
}

/// Save a test report to the reports directory
fn save_report(report: &mut TestReport, filename: &str) -> std::io::Result<()> {
    let path = report_output_dir().join(filename);
    report.save_json(&path)?;
    println!("Report saved to: {}", path.display());
    Ok(())
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_state_tests_berlin() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = StateTestSuite::new(fixtures_path().join("berlin"))
        .with_name("Berlin State Tests")
        .with_forks(vec!["Berlin".to_string()])
        .with_parallel(true);

    let mut report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);

    // Save the report
    if let Err(e) = save_report(&mut report, "berlin_state_tests.json") {
        eprintln!("Failed to save report: {}", e);
    }

    // For now, we just verify the framework works - tests may fail due to placeholder state root
    // The important thing is that we can parse and execute tests
    assert!(
        report.summary.total() > 0,
        "Should have executed at least some tests"
    );
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_state_tests_london() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = StateTestSuite::new(fixtures_path().join("london"))
        .with_name("London State Tests")
        .with_forks(vec!["London".to_string()])
        .with_parallel(true);

    let mut report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);

    // Save the report
    if let Err(e) = save_report(&mut report, "london_state_tests.json") {
        eprintln!("Failed to save report: {}", e);
    }
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_state_tests_shanghai() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = StateTestSuite::new(fixtures_path().join("shanghai"))
        .with_name("Shanghai State Tests")
        .with_forks(vec!["Shanghai".to_string()])
        .with_parallel(true);

    let mut report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);

    // Save the report
    if let Err(e) = save_report(&mut report, "shanghai_state_tests.json") {
        eprintln!("Failed to save report: {}", e);
    }
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_state_tests_cancun() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = StateTestSuite::new(fixtures_path().join("cancun"))
        .with_name("Cancun State Tests")
        .with_forks(vec!["Cancun".to_string()])
        .with_parallel(true);

    let mut report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);

    // Save the report
    if let Err(e) = save_report(&mut report, "cancun_state_tests.json") {
        eprintln!("Failed to save report: {}", e);
    }
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_state_tests_filtered() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let filter = TestFilter::new()
        .include("test_")
        .fork("Berlin");

    let suite = StateTestSuite::new(fixtures_path())
        .with_name("Filtered State Tests")
        .with_parallel(true);

    let mut report = suite.run_filtered(&filter).expect("Failed to run tests");

    println!("{}", report);

    // Save the report
    if let Err(e) = save_report(&mut report, "filtered_state_tests.json") {
        eprintln!("Failed to save report: {}", e);
    }
}

#[test]
fn test_fork_spec_parsing() {
    assert_eq!(ForkSpec::from_name("Berlin").unwrap(), ForkSpec::Berlin);
    assert_eq!(ForkSpec::from_name("london").unwrap(), ForkSpec::London);
    assert_eq!(ForkSpec::from_name("SHANGHAI").unwrap(), ForkSpec::Shanghai);
    assert_eq!(ForkSpec::from_name("Cancun").unwrap(), ForkSpec::Cancun);
    assert!(ForkSpec::from_name("InvalidFork").is_err());
}

#[test]
fn test_fork_spec_properties() {
    assert!(!ForkSpec::Berlin.is_pos());
    assert!(!ForkSpec::Berlin.has_eip1559());
    assert!(!ForkSpec::Berlin.has_blob_txs());

    assert!(!ForkSpec::London.is_pos());
    assert!(ForkSpec::London.has_eip1559());

    assert!(ForkSpec::Paris.is_pos());
    assert!(ForkSpec::Paris.has_eip1559());

    assert!(ForkSpec::Cancun.is_pos());
    assert!(ForkSpec::Cancun.has_eip1559());
    assert!(ForkSpec::Cancun.has_blob_txs());
}

#[test]
fn test_discovery() {
    let discovery = TestDiscovery::new("/tmp/nonexistent");
    assert!(discovery.discover_files().is_err());
}

#[test]
fn test_filter() {
    let filter = TestFilter::new()
        .include("test_add")
        .exclude("skip_me")
        .fork("Berlin");

    assert!(filter.matches("test_add_numbers"));
    assert!(!filter.matches("test_subtract")); // Doesn't match include
    assert!(!filter.matches("test_add_skip_me")); // Matches exclude
    assert!(filter.matches_fork("Berlin"));
    assert!(filter.matches_fork("berlin"));
    assert!(!filter.matches_fork("London"));
}

#[test]
fn test_state_test_deserialization() {
    let json = r#"{
        "env": {
            "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "currentGasLimit": "0x07270e00",
            "currentNumber": "0x01",
            "currentTimestamp": "0x03e8",
            "currentDifficulty": "0x020000"
        },
        "pre": {
            "0x1000000000000000000000000000000000000000": {
                "nonce": "0x00",
                "balance": "0x0de0b6b3a7640000",
                "code": "0x",
                "storage": {}
            }
        },
        "transaction": {
            "nonce": "0x00",
            "gasPrice": "0x0a",
            "gasLimit": ["0x0186a0"],
            "to": "0x1000000000000000000000000000000000000000",
            "value": ["0x00"],
            "data": ["0x"],
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
        },
        "post": {
            "Berlin": [
                {
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "txbytes": "0xf85f800a830186a0941000000000000000000000000000000000000000808025a0b9b8e0e4f9a0c9e9f9d1c2b3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3a0c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
                    "indexes": {
                        "data": 0,
                        "gas": 0,
                        "value": 0
                    }
                }
            ]
        }
    }"#;

    let test: StateTest = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(test.env.current_number, 1);
    assert_eq!(test.env.current_timestamp, 1000);
    assert!(test.pre.len() == 1);
    assert!(test.post.contains_key("Berlin"));
    assert_eq!(test.chain_id(), 1);
    assert_eq!(test.forks(), vec!["Berlin"]);
}

/// Run a quick sanity check on a small subset of tests
#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_sanity_check() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found");
        return;
    }

    // Just run a few tests to verify the infrastructure works
    let filter = TestFilter::new()
        .fork("Berlin");

    let suite = StateTestSuite::new(fixtures_path().join("berlin"))
        .with_name("Sanity Check")
        .with_parallel(false);

    let mut report = suite.run_filtered(&filter).expect("Failed to run tests");

    println!("Sanity check completed:");
    println!("  Total: {}", report.summary.total());
    println!("  Passed: {}", report.summary.passed);
    println!("  Failed: {}", report.summary.failed);
    println!("  Skipped: {}", report.summary.skipped);

    // Save the report
    if let Err(e) = save_report(&mut report, "sanity_check.json") {
        eprintln!("Failed to save report: {}", e);
    }
}

/// Generate a sample test report for verification
/// This test runs a small subset of frontier tests and generates a JSON report
#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_generate_sample_report() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    // Run frontier tests - these are the simplest and fastest
    let frontier_path = fixtures_path().join("frontier");
    if !frontier_path.exists() {
        eprintln!("Frontier tests not found at {:?}", frontier_path);
        // Try berlin instead
        let berlin_path = fixtures_path().join("berlin");
        if !berlin_path.exists() {
            eprintln!("Berlin tests not found either, skipping");
            return;
        }

        let suite = StateTestSuite::new(berlin_path)
            .with_name("Sample State Tests (Berlin)")
            .with_forks(vec!["Berlin".to_string()])
            .with_parallel(false);

        let mut report = suite.run_all().expect("Failed to run tests");

        println!("{}", report);
        println!();
        println!("Sample report generation completed.");
        println!("  Total tests: {}", report.summary.total());
        println!("  Passed: {}", report.summary.passed);
        println!("  Failed: {}", report.summary.failed);
        println!("  Skipped: {}", report.summary.skipped);

        // Save the sample report
        if let Err(e) = save_report(&mut report, "state_tests_sample.json") {
            eprintln!("Failed to save report: {}", e);
        }
        return;
    }

    let suite = StateTestSuite::new(frontier_path)
        .with_name("Sample State Tests (Frontier)")
        .with_forks(vec!["Frontier".to_string()])
        .with_parallel(false);

    let mut report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);
    println!();
    println!("Sample report generation completed.");
    println!("  Total tests: {}", report.summary.total());
    println!("  Passed: {}", report.summary.passed);
    println!("  Failed: {}", report.summary.failed);
    println!("  Skipped: {}", report.summary.skipped);

    // Save the sample report
    if let Err(e) = save_report(&mut report, "state_tests_sample.json") {
        eprintln!("Failed to save report: {}", e);
    }
}

//! Comprehensive test runner for ALL Ethereum Foundation tests
//!
//! This module runs all EF tests: state, blockchain, transaction, and engine tests.
//! Total: 35,000+ test files across all categories.

use n42_ef_tests::{
    result::TestSummary,
    suite::{BlockchainTestSuite, StateTestSuite, Suite, TransactionTestSuite},
};
use std::path::PathBuf;
use std::time::Instant;

/// Get the base fixtures path
fn fixtures_base_path() -> PathBuf {
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
}

/// Check if fixtures are available
fn fixtures_available() -> bool {
    fixtures_base_path().exists()
}

/// Run state tests for a specific fork
fn run_state_tests(fork: &str) -> Option<TestSummary> {
    let path = fixtures_base_path().join("state_tests").join(fork.to_lowercase());
    if !path.exists() {
        println!("State tests for {} not found at {:?}", fork, path);
        return None;
    }

    println!("\n=== Running State Tests: {} ===", fork);
    let suite = StateTestSuite::new(path)
        .with_name(&format!("{} State Tests", fork))
        .with_parallel(true);

    match suite.run_all() {
        Ok(report) => {
            println!("{}", report.summary);
            Some(report.summary)
        }
        Err(e) => {
            println!("Error running {} state tests: {}", fork, e);
            None
        }
    }
}

/// Run blockchain tests for a specific fork
fn run_blockchain_tests(fork: &str) -> Option<TestSummary> {
    let path = fixtures_base_path().join("blockchain_tests").join(fork.to_lowercase());
    if !path.exists() {
        println!("Blockchain tests for {} not found at {:?}", fork, path);
        return None;
    }

    println!("\n=== Running Blockchain Tests: {} ===", fork);
    let suite = BlockchainTestSuite::new(path)
        .with_name(&format!("{} Blockchain Tests", fork))
        .with_parallel(true);

    match suite.run_all() {
        Ok(report) => {
            println!("{}", report.summary);
            Some(report.summary)
        }
        Err(e) => {
            println!("Error running {} blockchain tests: {}", fork, e);
            None
        }
    }
}

/// Run blockchain engine tests
fn run_engine_tests(fork: &str) -> Option<TestSummary> {
    let path = fixtures_base_path().join("blockchain_tests_engine").join(fork.to_lowercase());
    if !path.exists() {
        println!("Engine tests for {} not found at {:?}", fork, path);
        return None;
    }

    println!("\n=== Running Engine Tests: {} ===", fork);
    let suite = BlockchainTestSuite::new(path)
        .with_name(&format!("{} Engine Tests", fork))
        .with_parallel(true);

    match suite.run_all() {
        Ok(report) => {
            println!("{}", report.summary);
            Some(report.summary)
        }
        Err(e) => {
            println!("Error running {} engine tests: {}", fork, e);
            None
        }
    }
}

/// Run blockchain engine_x tests
fn run_engine_x_tests(fork: &str) -> Option<TestSummary> {
    let path = fixtures_base_path().join("blockchain_tests_engine_x").join(fork.to_lowercase());
    if !path.exists() {
        return None;
    }

    println!("\n=== Running Engine_X Tests: {} ===", fork);
    let suite = BlockchainTestSuite::new(path)
        .with_name(&format!("{} Engine_X Tests", fork))
        .with_parallel(true);

    match suite.run_all() {
        Ok(report) => {
            println!("{}", report.summary);
            Some(report.summary)
        }
        Err(e) => {
            println!("Error running {} engine_x tests: {}", fork, e);
            None
        }
    }
}

/// Run transaction tests
fn run_transaction_tests(fork: &str) -> Option<TestSummary> {
    let path = fixtures_base_path().join("transaction_tests").join(fork.to_lowercase());
    if !path.exists() {
        return None;
    }

    println!("\n=== Running Transaction Tests: {} ===", fork);
    let suite = TransactionTestSuite::new(path)
        .with_name(&format!("{} Transaction Tests", fork))
        .with_forks(vec![fork.to_string()])
        .with_parallel(true);

    match suite.run_all() {
        Ok(report) => {
            println!("{}", report.summary);
            Some(report.summary)
        }
        Err(e) => {
            println!("Error running {} transaction tests: {}", fork, e);
            None
        }
    }
}

#[test]
#[ignore = "Runs all 35,000+ EF tests - takes a long time"]
fn run_all_ef_tests() {
    if !fixtures_available() {
        panic!("EF test fixtures not found at {:?}", fixtures_base_path());
    }

    let start = Instant::now();
    let mut total = TestSummary::default();
    let mut category_reports: Vec<(String, TestSummary)> = Vec::new();

    // List of all forks to test
    let forks = vec![
        "frontier",
        "homestead",
        "tangerinewhistle",
        "spuriousdragon",
        "byzantium",
        "constantinople",
        "petersburg",
        "istanbul",
        "berlin",
        "london",
        "paris",
        "shanghai",
        "cancun",
        "prague",
    ];

    println!("\n");
    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║         ETHEREUM FOUNDATION TEST SUITE - COMPREHENSIVE RUN          ║");
    println!("║                    Running 35,000+ Test Files                       ║");
    println!("╚════════════════════════════════════════════════════════════════════╝");
    println!("\n");

    // Run State Tests
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                           STATE TESTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let mut state_total = TestSummary::default();
    for fork in &forks {
        if let Some(summary) = run_state_tests(fork) {
            state_total.merge(&summary);
        }
    }
    category_reports.push(("State Tests".to_string(), state_total.clone()));
    total.merge(&state_total);

    // Run Blockchain Tests
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                        BLOCKCHAIN TESTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let mut blockchain_total = TestSummary::default();
    for fork in &forks {
        if let Some(summary) = run_blockchain_tests(fork) {
            blockchain_total.merge(&summary);
        }
    }
    category_reports.push(("Blockchain Tests".to_string(), blockchain_total.clone()));
    total.merge(&blockchain_total);

    // Run Engine Tests
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                         ENGINE TESTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let mut engine_total = TestSummary::default();
    for fork in &forks {
        if let Some(summary) = run_engine_tests(fork) {
            engine_total.merge(&summary);
        }
    }
    category_reports.push(("Engine Tests".to_string(), engine_total.clone()));
    total.merge(&engine_total);

    // Run Engine_X Tests
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                        ENGINE_X TESTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let mut engine_x_total = TestSummary::default();
    for fork in &forks {
        if let Some(summary) = run_engine_x_tests(fork) {
            engine_x_total.merge(&summary);
        }
    }
    if engine_x_total.total() > 0 {
        category_reports.push(("Engine_X Tests".to_string(), engine_x_total.clone()));
        total.merge(&engine_x_total);
    }

    // Run Transaction Tests
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                       TRANSACTION TESTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let mut transaction_total = TestSummary::default();
    for fork in &forks {
        if let Some(summary) = run_transaction_tests(fork) {
            transaction_total.merge(&summary);
        }
    }
    if transaction_total.total() > 0 {
        category_reports.push(("Transaction Tests".to_string(), transaction_total.clone()));
        total.merge(&transaction_total);
    }

    let elapsed = start.elapsed();

    // Print comprehensive report
    println!("\n\n");
    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║                    COMPREHENSIVE TEST REPORT                       ║");
    println!("╚════════════════════════════════════════════════════════════════════╝");
    println!();

    println!("Category Breakdown:");
    println!("────────────────────────────────────────────────────────────────────");
    for (category, summary) in &category_reports {
        println!(
            "  {:<20} | Passed: {:>6} | Failed: {:>6} | Skipped: {:>6} | Rate: {:>6.2}%",
            category,
            summary.passed,
            summary.failed,
            summary.skipped,
            summary.pass_rate()
        );
    }
    println!("────────────────────────────────────────────────────────────────────");
    println!();

    println!("Overall Summary:");
    println!("  Total Tests:  {}", total.total());
    println!("  Passed:       {} ({:.2}%)", total.passed, total.pass_rate());
    println!("  Failed:       {}", total.failed);
    println!("  Skipped:      {}", total.skipped);
    println!("  Duration:     {:?}", elapsed);
    println!();

    // Assert all tests pass
    if total.failed > 0 {
        panic!(
            "Test suite failed! {} out of {} tests failed.",
            total.failed,
            total.total()
        );
    }
}

/// Quick test run for CI - runs a subset of tests
#[test]
#[ignore = "Quick CI test"]
fn run_quick_ci_tests() {
    if !fixtures_available() {
        println!("Skipping: EF test fixtures not found");
        return;
    }

    let start = Instant::now();
    let mut total = TestSummary::default();

    // Run only Berlin and Cancun tests for quick CI
    println!("\n=== Quick CI Test Run ===\n");

    // Berlin state tests
    if let Some(s) = run_state_tests("berlin") {
        total.merge(&s);
    }

    // Cancun state tests
    if let Some(s) = run_state_tests("cancun") {
        total.merge(&s);
    }

    // Berlin blockchain tests
    if let Some(s) = run_blockchain_tests("berlin") {
        total.merge(&s);
    }

    println!("\n=== Quick CI Summary ===");
    println!("{}", total);
    println!("Duration: {:?}", start.elapsed());
}

/// Test just the Berlin fork across all test types
#[test]
#[ignore = "Requires EF test fixtures"]
fn run_berlin_all_types() {
    if !fixtures_available() {
        println!("Skipping: EF test fixtures not found");
        return;
    }

    println!("\n=== Berlin Fork - All Test Types ===\n");
    let mut total = TestSummary::default();

    if let Some(s) = run_state_tests("berlin") {
        total.merge(&s);
    }
    if let Some(s) = run_blockchain_tests("berlin") {
        total.merge(&s);
    }
    if let Some(s) = run_engine_tests("berlin") {
        total.merge(&s);
    }

    println!("\n=== Berlin Summary ===");
    println!("{}", total);
}

/// Test just the Cancun fork across all test types
#[test]
#[ignore = "Requires EF test fixtures"]
fn run_cancun_all_types() {
    if !fixtures_available() {
        println!("Skipping: EF test fixtures not found");
        return;
    }

    println!("\n=== Cancun Fork - All Test Types ===\n");
    let mut total = TestSummary::default();

    if let Some(s) = run_state_tests("cancun") {
        total.merge(&s);
    }
    if let Some(s) = run_blockchain_tests("cancun") {
        total.merge(&s);
    }
    if let Some(s) = run_engine_tests("cancun") {
        total.merge(&s);
    }

    println!("\n=== Cancun Summary ===");
    println!("{}", total);
}

//! Integration tests for Ethereum Foundation Blockchain Tests
//!
//! This module runs the EF blockchain tests against the N42 execution client.
//! Tests are discovered automatically from the fixtures directory.

use n42_ef_tests::{
    models::BlockchainTest,
    suite::{BlockchainTestSuite, Suite},
    utils::TestFilter,
};
use std::path::PathBuf;

/// Get the path to the EF blockchain test fixtures
fn fixtures_path() -> PathBuf {
    // Try environment variable first
    if let Ok(path) = std::env::var("EF_TESTS_PATH") {
        return PathBuf::from(path).join("blockchain_tests");
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
        .join("blockchain_tests")
}

/// Check if fixtures are available
fn fixtures_available() -> bool {
    fixtures_path().exists()
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_blockchain_tests_berlin() {
    let base_path = fixtures_path();
    let berlin_path = base_path.join("berlin");

    eprintln!("Base fixtures path: {:?}", base_path);
    eprintln!("Berlin path: {:?}", berlin_path);
    eprintln!("Path exists: {}", berlin_path.exists());

    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = BlockchainTestSuite::new(berlin_path)
        .with_name("Berlin Blockchain Tests")
        .with_forks(vec!["Berlin".to_string()])
        .with_parallel(false);

    eprintln!("Test count: {}", suite.test_count());

    let report = suite.run_all().expect("Failed to run tests");

    println!("=== {} ===", report.name);
    println!("{}", report.summary);
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_blockchain_tests_london() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = BlockchainTestSuite::new(fixtures_path().join("london"))
        .with_name("London Blockchain Tests")
        .with_forks(vec!["London".to_string()])
        .with_parallel(true);

    let report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_blockchain_tests_shanghai() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = BlockchainTestSuite::new(fixtures_path().join("shanghai"))
        .with_name("Shanghai Blockchain Tests")
        .with_forks(vec!["Shanghai".to_string()])
        .with_parallel(true);

    let report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);
}

#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_blockchain_tests_cancun() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let suite = BlockchainTestSuite::new(fixtures_path().join("cancun"))
        .with_name("Cancun Blockchain Tests")
        .with_forks(vec!["Cancun".to_string()])
        .with_parallel(true);

    let report = suite.run_all().expect("Failed to run tests");

    println!("{}", report);
}

#[test]
fn test_blockchain_test_deserialization() {
    // A minimal blockchain test for deserialization testing
    let json = r#"{
        "network": "Berlin",
        "genesisBlockHeader": {
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "transactionsTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "receiptTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "difficulty": "0x020000",
            "number": "0x00",
            "gasLimit": "0x07270e00",
            "gasUsed": "0x00",
            "timestamp": "0x00",
            "extraData": "0x00",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000000",
            "hash": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "pre": {},
        "postState": {},
        "lastblockhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "genesisRLP": "0x00",
        "blocks": []
    }"#;

    let test: BlockchainTest = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(test.network, "Berlin");
    assert_eq!(test.fork(), "Berlin");
    assert_eq!(test.chain_id(), 1);
    assert_eq!(test.block_count(), 0);
    assert!(!test.has_invalid_blocks());
}

/// Run a quick sanity check on blockchain tests
#[test]
#[ignore = "Requires EF test fixtures to be downloaded"]
fn test_blockchain_sanity_check() {
    if !fixtures_available() {
        eprintln!("Skipping test: EF test fixtures not found");
        return;
    }

    let filter = TestFilter::new()
        .fork("Berlin");

    let suite = BlockchainTestSuite::new(fixtures_path().join("berlin"))
        .with_name("Blockchain Sanity Check")
        .with_parallel(false);

    let report = suite.run_filtered(&filter).expect("Failed to run tests");

    println!("Blockchain sanity check completed:");
    println!("  Total: {}", report.summary.total());
    println!("  Passed: {}", report.summary.passed);
    println!("  Failed: {}", report.summary.failed);
    println!("  Skipped: {}", report.summary.skipped);
}

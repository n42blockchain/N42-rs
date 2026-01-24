//! Transaction test runner

use n42_ef_tests::suite::{Suite, TransactionTestSuite};
use std::path::PathBuf;

fn fixtures_path() -> PathBuf {
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
        .join("transaction_tests")
}

fn fixtures_available() -> bool {
    fixtures_path().exists()
}

#[test]
#[ignore = "Requires EF test fixtures"]
fn run_transaction_tests_prague() {
    if !fixtures_available() {
        eprintln!("Skipping: EF test fixtures not found at {:?}", fixtures_path());
        return;
    }

    let path = fixtures_path().join("prague");
    if !path.exists() {
        eprintln!("Prague transaction tests not found at {:?}", path);
        return;
    }

    let suite = TransactionTestSuite::new(path)
        .with_name("Prague Transaction Tests")
        .with_forks(vec!["Prague".to_string()])
        .with_parallel(true);

    let mut report = suite.run_all().expect("Failed to run tests");

    println!("{}", report.summary_report());

    // Save detailed report
    let report_path = PathBuf::from("target/ef-test-reports/prague_transaction_tests.json");
    if let Err(e) = report.save_json(&report_path) {
        eprintln!("Warning: Failed to save report: {}", e);
    } else {
        println!("\nDetailed report saved to: {:?}", report_path);
    }
}

#[test]
fn test_transaction_test_model() {
    let json = r#"{
        "result": {
            "Prague": {
                "intrinsicGas": "0x00",
                "exception": "TransactionException.TYPE_4_INVALID_AUTHORIZATION_FORMAT"
            }
        },
        "txbytes": "0x04f8c301808007830186a09400000000000000000000000000000000000000008080c0"
    }"#;

    let test: n42_ef_tests::models::TransactionTest = serde_json::from_str(json).unwrap();
    assert!(test.expects_exception("Prague"));
    assert_eq!(test.forks().len(), 1);
}

//! Single blockchain test for debugging

use n42_ef_tests::{
    executor::BlockchainTestExecutor,
    fork::ForkSpec,
    models::BlockchainTest,
};
use std::collections::HashMap;
use std::path::PathBuf;

/// Get the path to a single test file
fn test_file_path() -> PathBuf {
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
        .join("berlin")
        .join("eip2929_gas_cost_increases")
        .join("test_call_insufficient_balance.json")
}

#[test]
#[ignore = "Requires EF test fixtures"]
fn run_single_blockchain_test() {
    let path = test_file_path();
    eprintln!("Running test from: {:?}", path);

    if !path.exists() {
        eprintln!("Test file not found: {:?}", path);
        return;
    }

    // Read and parse the file
    let content = std::fs::read_to_string(&path).expect("Failed to read file");
    let tests: HashMap<String, BlockchainTest> =
        serde_json::from_str(&content).expect("Failed to parse JSON");

    eprintln!("Found {} tests in file", tests.len());

    for (test_name, test) in &tests {
        eprintln!("Running test: {}", test_name);
        eprintln!("  Fork: {}", test.fork());
        eprintln!("  Pre-state accounts: {}", test.pre.as_ref().map_or(0, |p| p.len()));
        eprintln!("  Blocks: {}", test.blocks.len());

        let fork_spec = ForkSpec::from_name(test.fork()).expect("Invalid fork");
        let executor = BlockchainTestExecutor::new(&fork_spec, test.chain_id());

        let result = executor.execute(test, test_name);
        match result {
            Ok(r) => {
                eprintln!("  Result: {:?}", r.status);
                if let Some(err) = &r.error {
                    eprintln!("  Error: {}", err);
                }
            }
            Err(e) => {
                eprintln!("  Error: {}", e);
            }
        }
    }
}

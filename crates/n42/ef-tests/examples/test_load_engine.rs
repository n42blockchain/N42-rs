use std::collections::HashMap;
use n42_ef_tests::models::BlockchainTest;

fn main() {
    let path = "/Users/jieliu/Documents/n42/N42-rs/ethereum-tests/fixtures/blockchain_tests_engine/berlin/eip2929_gas_cost_increases/test_call_insufficient_balance.json";
    
    let content = std::fs::read_to_string(path).expect("Failed to read file");
    
    match serde_json::from_str::<HashMap<String, BlockchainTest>>(&content) {
        Ok(tests) => {
            println!("✓ Successfully loaded {} tests", tests.len());
            for (name, test) in tests.iter().take(2) {
                println!("  Test: {}", name);
                println!("    Network: {}", test.network);
                println!("    Has blocks: {}", !test.blocks.is_empty());
                println!("    Has engine payloads: {}", test.engine_new_payloads.is_some());
                if let Some(payloads) = &test.engine_new_payloads {
                    println!("    Payload count: {}", payloads.len());
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to parse: {}", e);
            std::process::exit(1);
        }
    }
}

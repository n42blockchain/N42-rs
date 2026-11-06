//! State test executor
//!
//! This module implements the executor for Ethereum Foundation state tests.
//! A state test executes a single transaction against a pre-state and verifies
//! the resulting state root and logs hash.
//!
//! The transaction is the variant's signed `txbytes`, executed by the EVM that reth's
//! `EthEvmConfig` builds for a header made from the test environment, over an evm2
//! [`InMemoryDB`] holding the pre-state. No block-level system calls run, as the fixtures expect.

use super::state_db::{build_pre_state_db, state_root_of_db};
use crate::error::{EfTestError, EfTestResult};
use crate::fork::ForkSpec;
use crate::models::{Environment, PostStateResult, StateTest};
use crate::result::TestResult;

use alloy_consensus::{transaction::Recovered, Header};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, Address, Log, B256};
use evm2::{evm::InMemoryDB, SpecId};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::TransactionSigned;
use reth_evm::{ConfigureEvm, Evm};
use reth_evm_ethereum::EthEvmConfig;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

/// Executor for Ethereum Foundation state tests
#[derive(Debug, Clone)]
pub struct StateTestExecutor {
    /// Chain specification
    chain_spec: Arc<ChainSpec>,
    /// EVM configuration
    evm_config: EthEvmConfig,
    /// Fork specification
    fork: ForkSpec,
}

impl StateTestExecutor {
    /// Create a new state test executor for the given fork
    pub fn new(fork: &ForkSpec, chain_id: u64) -> Self {
        Self::with_chain_spec(fork.to_chain_spec(chain_id), *fork)
    }

    /// Create an executor with a specific chain spec
    pub fn with_chain_spec(chain_spec: Arc<ChainSpec>, fork: ForkSpec) -> Self {
        let evm_config = EthEvmConfig::ethereum(chain_spec.clone());
        Self { chain_spec, evm_config, fork }
    }

    /// Returns the chain specification the executor runs on.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        &self.chain_spec
    }

    /// Execute a state test for a specific fork and variant
    pub fn execute(
        &self,
        test: &StateTest,
        test_name: &str,
        fork: &str,
        variant_index: usize,
    ) -> EfTestResult<TestResult> {
        let start = Instant::now();

        // Get the expected result for this fork and variant
        let post_results = test
            .post_for_fork(fork)
            .ok_or_else(|| EfTestError::UnsupportedFork(fork.to_string()))?;

        let expected = post_results.get(variant_index).ok_or_else(|| {
            EfTestError::InvalidTestData(format!(
                "Variant index {} out of range (max {})",
                variant_index,
                post_results.len()
            ))
        })?;

        if let Some(ref exception) = expected.expect_exception {
            debug!("Test expects exception: {}", exception);
        }

        let result = self.execute_transaction(test, expected);
        let duration = start.elapsed();

        let test_result = if result.state_root == expected.hash && result.logs_hash == expected.logs
        {
            TestResult::passed(test_name.to_string(), fork.to_string(), duration)
        } else {
            let error = if result.state_root == expected.hash {
                format!("Logs hash mismatch: expected {}, got {}", expected.logs, result.logs_hash)
            } else {
                format!(
                    "State root mismatch: expected {}, got {}",
                    expected.hash, result.state_root
                )
            };
            TestResult::failed(test_name.to_string(), fork.to_string(), duration, error)
        };

        Ok(test_result
            .with_state_roots(expected.hash, result.state_root)
            .with_logs_hashes(expected.logs, result.logs_hash)
            .with_variant(variant_index))
    }

    /// Executes the variant's transaction and returns the post-state root and logs hash.
    ///
    /// A transaction that does not decode or that the EVM rejects (intrinsic gas, nonce,
    /// balance, blob count, ...) leaves the pre-state unchanged and produces no logs.
    fn execute_transaction(&self, test: &StateTest, expected: &PostStateResult) -> ExecutionResult {
        let mut db = build_pre_state_db(&test.pre);
        let include_empty = self.get_spec_id() < SpecId::SPURIOUS_DRAGON;

        let logs = match self.transact(
            &mut db,
            &test.env,
            &expected.txbytes,
            test.transaction.sender,
        ) {
            Ok(logs) => logs,
            Err(reason) => {
                debug!("Transaction rejected: {}", reason);
                // The database was not written: its root is the pre-state root.
                Vec::new()
            }
        };

        ExecutionResult {
            state_root: state_root_of_db(&db, include_empty),
            logs_hash: logs_hash(&logs),
        }
    }

    /// Runs the transaction and commits its state into `db`, returning its logs.
    fn transact(
        &self,
        db: &mut InMemoryDB,
        env: &Environment,
        txbytes: &[u8],
        sender: Address,
    ) -> Result<Vec<Log>, String> {
        let tx = TransactionSigned::decode_2718(&mut &*txbytes)
            .map_err(|e| format!("txbytes do not decode: {e}"))?;
        let tx = self.evm_config.tx_env(Recovered::new_unchecked(tx, sender));

        let evm_env = self
            .evm_config
            .evm_env(&environment_header(env))
            .map_err(|e| format!("evm env: {e}"))?;

        let mut evm = self.evm_config.evm_with_env(&mut *db, evm_env);
        let result = Evm::transact_commit(&mut evm, &tx).map_err(|e| e.to_string())?;
        let cache = Evm::take_state_cache(&mut evm);
        drop(evm);
        db.cache.merge(cache);
        Ok(result.logs)
    }

    /// Get the spec ID for the current fork
    pub const fn get_spec_id(&self) -> SpecId {
        super::spec_id_for_fork(self.fork)
    }
}

/// Builds the block header whose EVM environment the state test runs in.
fn environment_header(env: &Environment) -> Header {
    Header {
        beneficiary: env.current_coinbase,
        gas_limit: env.current_gas_limit,
        number: env.current_number,
        timestamp: env.current_timestamp,
        difficulty: env.difficulty(),
        mix_hash: env.prev_randao(),
        base_fee_per_gas: env.current_base_fee.map(|_| env.base_fee()),
        excess_blob_gas: env.current_excess_blob_gas.map(|v| v.try_into().unwrap_or(u64::MAX)),
        blob_gas_used: env.current_blob_gas_used.map(|v| v.try_into().unwrap_or(u64::MAX)),
        parent_beacon_block_root: env.parent_beacon_block_root,
        ..Default::default()
    }
}

/// Keccak256 of the RLP-encoded log list.
fn logs_hash(logs: &[Log]) -> B256 {
    let mut encoded = Vec::new();
    alloy_rlp::encode_list(logs, &mut encoded);
    keccak256(&encoded)
}

/// Result of transaction execution
#[derive(Debug, Clone)]
struct ExecutionResult {
    /// Computed state root
    state_root: B256,
    /// Computed logs hash
    logs_hash: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::state_db::state_root_of_accounts;
    use crate::models::Account;
    use alloy_primitives::{hex, U256};
    use hashbrown::HashMap;

    #[test]
    fn test_executor_creation() {
        let executor = StateTestExecutor::new(&ForkSpec::Berlin, 1);
        assert_eq!(executor.chain_spec().chain.id(), 1);
    }

    #[test]
    fn test_spec_id_mapping() {
        let executor = StateTestExecutor::new(&ForkSpec::Berlin, 1);
        assert_eq!(executor.get_spec_id(), SpecId::BERLIN);

        let executor = StateTestExecutor::new(&ForkSpec::London, 1);
        assert_eq!(executor.get_spec_id(), SpecId::LONDON);

        let executor = StateTestExecutor::new(&ForkSpec::Cancun, 1);
        assert_eq!(executor.get_spec_id(), SpecId::CANCUN);
    }

    #[test]
    fn test_empty_logs_hash() {
        assert_eq!(logs_hash(&[]), keccak256([0xc0]));
    }

    #[test]
    fn test_environment_header() {
        let env = Environment {
            current_coinbase: Address::with_last_byte(7),
            current_gas_limit: 30_000_000,
            current_number: 1,
            current_timestamp: 1000,
            current_difficulty: None,
            current_random: Some(B256::with_last_byte(1)),
            current_base_fee: Some(U256::from(7)),
            current_excess_blob_gas: Some(U256::ZERO),
            current_blob_gas_used: None,
            parent_beacon_block_root: None,
        };
        let header = environment_header(&env);
        assert_eq!(header.base_fee_per_gas, Some(7));
        assert_eq!(header.excess_blob_gas, Some(0));
        assert_eq!(header.mix_hash, B256::with_last_byte(1));
    }

    #[test]
    fn test_transfer_commits_state() {
        // A signed legacy transfer (chain id 1, nonce 0, gas price 10, gas 100000, value 0).
        let txbytes = hex!("f860800a830186a0945e4bad14480e006938dd30373936e0d7f92ad063808026a071a29ce7d01640cfc246b13e39600c95bb935ad4363439e8a3effe2d74ce93a7a06d692e4f80a487bcc7eb7d30cef75e475160c14b9e80037e023532d091770a73");
        let sender = Address::with_last_byte(0xaa);
        let mut pre = HashMap::new();
        pre.insert(sender, Account::with_balance(U256::from(10_000_000u64)));

        let env = Environment {
            current_coinbase: Address::with_last_byte(7),
            current_gas_limit: 30_000_000,
            current_number: 1,
            current_timestamp: 1000,
            current_difficulty: Some(U256::from(0x20000)),
            current_random: None,
            current_base_fee: None,
            current_excess_blob_gas: None,
            current_blob_gas_used: None,
            parent_beacon_block_root: None,
        };

        let executor = StateTestExecutor::new(&ForkSpec::Berlin, 1);
        let mut db = build_pre_state_db(&pre);
        let logs = executor.transact(&mut db, &env, &txbytes, sender).unwrap();
        assert!(logs.is_empty());

        let info = db.account_info(&sender).unwrap();
        assert_eq!(info.nonce, 1);
        // 21000 gas at price 10.
        assert_eq!(info.balance, U256::from(10_000_000u64 - 210_000));
        let coinbase = db.account_info(&env.current_coinbase).unwrap();
        assert_eq!(coinbase.balance, U256::from(210_000u64));
        assert_ne!(state_root_of_db(&db, false), state_root_of_accounts(&pre, false));
    }
}

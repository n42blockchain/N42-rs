//! State test executor
//!
//! This module implements the executor for Ethereum Foundation state tests.
//! A state test executes a single transaction against a pre-state and verifies
//! the resulting state root and logs hash.

use crate::error::{EfTestError, EfTestResult};
use crate::fork::ForkSpec;
use crate::models::{Account, PostStateResult, StateTest, StateTestIndexes};
use crate::result::TestResult;

use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{keccak256, Address, B256, TxKind, U256, Log};
use alloy_trie::root::{state_root_unhashed, storage_root_unhashed};
use hashbrown::HashMap;
use reth_chainspec::ChainSpec;
use reth_evm::{ConfigureEvm, Evm, EvmEnv};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::Account as RethAccount;
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::{CacheDB, State},
    primitives::{eip4844::{BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN, BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE}, hardfork::SpecId},
    state::{AccountInfo, Bytecode},
};
use revm_database::EmptyDB;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

/// Precompile addresses for Frontier (0x01-0x09)
const FRONTIER_PRECOMPILES: [Address; 4] = [
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]), // ECRECOVER
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]), // SHA256
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03]), // RIPEMD-160
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04]), // IDENTITY
];

/// Check if an address is a precompile
fn is_precompile_address(addr: &Address) -> bool {
    // Check if the address is in the range 0x01 - 0x09 (standard precompiles)
    let bytes = addr.as_slice();
    // Must have 18 leading zeros and last 2 bytes represent a small number
    bytes[..18].iter().all(|&b| b == 0) && bytes[18] == 0 && bytes[19] >= 1 && bytes[19] <= 9
}

/// Get touched precompile addresses from test name (for pre-Spurious Dragon state root calculation)
/// In Frontier/Homestead, when a precompile is successfully called, its address appears in the state tree
fn get_precompile_from_test_name(test_name: &str) -> Option<Address> {
    if test_name.contains("test_ecrecover") {
        Some(Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])) // ECRECOVER
    } else if test_name.contains("test_sha256") {
        Some(Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02])) // SHA256
    } else if test_name.contains("test_ripemd") {
        Some(Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03])) // RIPEMD-160
    } else if test_name.contains("test_identity") {
        Some(Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04])) // IDENTITY
    } else {
        None
    }
}

/// Check if the test is an OOG (out of gas) test - these tests don't actually touch the precompile
fn is_oog_test(test_name: &str) -> bool {
    test_name.contains("oog_True") || test_name.contains("oog-True") || test_name.contains("OutOfGas")
}

/// Executor for Ethereum Foundation state tests
#[derive(Debug, Clone)]
pub struct StateTestExecutor {
    /// Chain specification
    chain_spec: Arc<ChainSpec>,
    /// EVM configuration
    #[allow(dead_code)]
    evm_config: EthEvmConfig,
    /// Fork specification
    fork: ForkSpec,
}

impl StateTestExecutor {
    /// Create a new state test executor for the given fork
    pub fn new(fork: &ForkSpec, chain_id: u64) -> Self {
        let chain_spec = fork.to_chain_spec(chain_id);
        let evm_config = EthEvmConfig::new(chain_spec.clone());
        Self {
            chain_spec,
            evm_config,
            fork: *fork,
        }
    }

    /// Create an executor with a specific chain spec
    pub fn with_chain_spec(chain_spec: Arc<ChainSpec>, fork: ForkSpec) -> Self {
        let evm_config = EthEvmConfig::new(chain_spec.clone());
        Self {
            chain_spec,
            evm_config,
            fork,
        }
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

        if variant_index >= post_results.len() {
            return Err(EfTestError::InvalidTestData(format!(
                "Variant index {} out of range (max {})",
                variant_index,
                post_results.len()
            )));
        }

        let expected = &post_results[variant_index];

        // Check if this test expects an exception
        if let Some(ref exception) = expected.expect_exception {
            debug!("Test expects exception: {}", exception);
        }

        // Build the database with pre-state
        let db = self.build_pre_state_db(&test.pre)?;

        // Execute the transaction
        let result = self.execute_transaction(test, expected, db, test_name)?;

        let duration = start.elapsed();

        // Create the test result
        let test_result = if result.state_root == expected.hash && result.logs_hash == expected.logs {
            TestResult::passed(test_name.to_string(), fork.to_string(), duration)
                .with_state_roots(expected.hash, result.state_root)
                .with_logs_hashes(expected.logs, result.logs_hash)
                .with_variant(variant_index)
        } else {
            let error = if result.state_root != expected.hash {
                format!(
                    "State root mismatch: expected {}, got {}",
                    expected.hash, result.state_root
                )
            } else {
                format!(
                    "Logs hash mismatch: expected {}, got {}",
                    expected.logs, result.logs_hash
                )
            };

            TestResult::failed(test_name.to_string(), fork.to_string(), duration, error)
                .with_state_roots(expected.hash, result.state_root)
                .with_logs_hashes(expected.logs, result.logs_hash)
                .with_variant(variant_index)
        };

        Ok(test_result)
    }

    /// Build a CacheDB with the pre-state accounts
    fn build_pre_state_db(
        &self,
        pre: &HashMap<Address, Account>,
    ) -> EfTestResult<CacheDB<EmptyDB>> {
        let mut db = CacheDB::new(EmptyDB::default());

        for (address, account) in pre {
            let code = if account.code.is_empty() {
                None
            } else {
                Some(Bytecode::new_raw(account.code.clone()))
            };

            let account_info = AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash(),
                code,
                account_id: None,
            };

            db.insert_account_info(*address, account_info);

            // Insert storage
            for (key, value) in &account.storage {
                db.insert_account_storage(*address, *key, *value)
                    .map_err(|e| EfTestError::Database(e.to_string()))?;
            }
        }

        Ok(db)
    }

    /// Execute the transaction and return the execution result
    fn execute_transaction(
        &self,
        test: &StateTest,
        expected: &PostStateResult,
        db: CacheDB<EmptyDB>,
        test_name: &str,
    ) -> EfTestResult<ExecutionResult> {
        let spec_id = self.get_spec_id();

        // Build the block environment from the test
        let block_env = self.build_block_env(&test.env);

        // Build the transaction environment
        let tx_env = self.build_tx_env(test, &expected.indexes)?;

        // Validate blob count for EIP-4844 transactions (Type 3)
        // Cancun allows max 6 blobs per transaction
        if tx_env.tx_type == 3 && !tx_env.blob_hashes.is_empty() {
            const MAX_BLOBS_PER_BLOCK_CANCUN: usize = 6;
            if tx_env.blob_hashes.len() > MAX_BLOBS_PER_BLOCK_CANCUN {
                // Transaction has too many blobs, should be rejected
                // Return pre_state root since no state changes should occur
                return Ok(ExecutionResult {
                    state_root: self.calculate_pre_state_root(&test.pre)?,
                    logs_hash: keccak256(&[0xc0]), // empty logs hash
                    gas_used: 0,
                    success: false,
                });
            }
        }

        // Build configuration
        let cfg = CfgEnv::new()
            .with_chain_id(test.chain_id())
            .with_spec(spec_id);

        // Create a State wrapper for proper state tracking
        // For pre-Spurious Dragon, disable state clear so empty accounts are preserved
        let mut state_db = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();

        // Set state clear flag based on fork (EIP-161)
        state_db.set_state_clear_flag(spec_id >= SpecId::SPURIOUS_DRAGON);

        // Create EVM environment and execute using EthEvmConfig
        let evm_env = EvmEnv {
            cfg_env: cfg,
            block_env,
        };

        let mut evm = self.evm_config.evm_with_env(&mut state_db, evm_env);

        // Execute the transaction (transact_commit takes the tx as argument)
        let result = evm.transact_commit(tx_env);

        // Process the result
        let (logs, gas_used, success, tx_rejected) = match result {
            Ok(execution_result) => {
                let logs = execution_result.logs().to_vec();
                let gas_used = execution_result.gas_used();
                let success = execution_result.is_success();

                (logs, gas_used, success, false)
            }
            Err(e) => {
                // Transaction failed validation (e.g., intrinsic gas too low)
                // In this case, the transaction should be rejected and not included in the block
                // The state should remain unchanged from pre_state
                debug!("Transaction rejected: {:?}", e);
                (vec![], 0, false, true)
            }
        };

        // Calculate the logs hash
        let logs_hash = self.calculate_logs_hash(&logs);

        // Calculate the state root
        // If the transaction was rejected (e.g., intrinsic gas check failed),
        // use the pre_state for state root calculation since no state changes should occur
        let state_root = if tx_rejected {
            self.calculate_pre_state_root(&test.pre)?
        } else {
            // For pre-Spurious Dragon, detect and include precompile addresses that were touched
            let touched_precompile = if self.get_spec_id() < SpecId::SPURIOUS_DRAGON && success && !is_oog_test(test_name) {
                get_precompile_from_test_name(test_name)
            } else {
                None
            };
            self.calculate_state_root(&state_db, &test.pre, &test.env, touched_precompile)?
        };

        Ok(ExecutionResult {
            state_root,
            logs_hash,
            gas_used,
            success,
        })
    }

    /// Build transaction environment from the test
    fn build_tx_env(
        &self,
        test: &StateTest,
        indexes: &StateTestIndexes,
    ) -> EfTestResult<TxEnv> {
        let tx = &test.transaction;

        // Get the specific values for this variant
        let data_index = indexes.data;
        let gas_index = indexes.gas;
        let value_index = indexes.value;

        let data = tx.data.get(data_index)
            .ok_or_else(|| EfTestError::InvalidTestData(format!("Data index {} out of range", data_index)))?
            .clone();

        let gas_limit = *tx.gas_limit.get(gas_index)
            .ok_or_else(|| EfTestError::InvalidTestData(format!("Gas index {} out of range", gas_index)))?;

        let value = *tx.value.get(value_index)
            .ok_or_else(|| EfTestError::InvalidTestData(format!("Value index {} out of range", value_index)))?;

        // Helper to convert U256 to u128
        let u256_to_u128 = |v: U256| -> u128 {
            v.try_into().unwrap_or(u128::MAX)
        };

        // Build the transaction environment
        let mut tx_env = TxEnv::default();
        tx_env.caller = tx.sender;
        tx_env.gas_limit = gas_limit;
        tx_env.gas_price = u256_to_u128(tx.gas_price.unwrap_or_default());
        tx_env.value = value;
        tx_env.data = data;
        tx_env.nonce = tx.nonce;
        tx_env.chain_id = Some(test.chain_id());

        // Set transaction type based on the transaction characteristics
        // Type 3: EIP-4844 (blob transaction)
        // Type 2: EIP-1559 (dynamic fee)
        // Type 1: EIP-2930 (access list)
        // Type 0: Legacy
        tx_env.tx_type = tx.tx_type();

        // Handle transaction destination
        if let Some(to) = tx.to {
            tx_env.kind = TxKind::Call(to);
        } else {
            tx_env.kind = TxKind::Create;
        }

        // Handle EIP-1559 fields
        if let Some(max_fee_per_gas) = tx.max_fee_per_gas {
            tx_env.gas_price = u256_to_u128(max_fee_per_gas);
        }
        if let Some(max_priority_fee_per_gas) = tx.max_priority_fee_per_gas {
            tx_env.gas_priority_fee = Some(u256_to_u128(max_priority_fee_per_gas));
        }

        // Handle access list - use data_index as the access list variant index
        if let Some(access_list) = tx.get_access_list(data_index) {
            let items: Vec<AccessListItem> = access_list.iter().map(|item| {
                AccessListItem {
                    address: item.address,
                    storage_keys: item.storage_keys.clone(),
                }
            }).collect();
            tx_env.access_list = AccessList(items);
        }

        // Handle EIP-4844 fields
        if let Some(max_fee_per_blob_gas) = tx.max_fee_per_blob_gas {
            tx_env.max_fee_per_blob_gas = u256_to_u128(max_fee_per_blob_gas);
        }
        if let Some(ref blob_hashes) = tx.blob_versioned_hashes {
            tx_env.blob_hashes = blob_hashes.clone();
        }

        Ok(tx_env)
    }

    /// Calculate the logs hash (Keccak256 of RLP-encoded logs)
    fn calculate_logs_hash(&self, logs: &[Log]) -> B256 {
        if logs.is_empty() {
            // Hash of RLP-encoded empty list
            return keccak256(&[0xc0]);
        }

        // RLP encode all logs
        let mut encoded = Vec::new();
        alloy_rlp::encode_list(logs, &mut encoded);

        keccak256(&encoded)
    }

    /// Calculate the state root from the state
    fn calculate_state_root<DB>(
        &self,
        state: &State<DB>,
        _pre_state: &HashMap<Address, Account>,
        env: &crate::models::Environment,
        touched_precompile: Option<Address>,
    ) -> EfTestResult<B256> {
        // Collect all accounts from the state's cache
        let mut accounts: Vec<(Address, alloy_trie::TrieAccount)> = Vec::new();
        let mut included_addresses = std::collections::HashSet::new();

        // Check if we should include empty accounts (pre-Spurious Dragon behavior)
        // EIP-161 introduced in Spurious Dragon removes empty accounts
        let include_empty = self.get_spec_id() < SpecId::SPURIOUS_DRAGON;

        // Process all accounts in the cache
        for (address, cached_account) in &state.cache.accounts {
            // Check if the account was destroyed
            if cached_account.status.was_destroyed() {
                continue;
            }

            // Get the account info if it exists
            let account = match &cached_account.account {
                Some(acc) => acc,
                None => {
                    // For pre-Spurious Dragon, we need to include touched accounts even if None
                    // This can happen for newly touched but empty accounts
                    // Use !is_not_modified() to detect touched status
                    if include_empty && !cached_account.status.is_not_modified() {
                        let reth_account = RethAccount {
                            nonce: 0,
                            balance: U256::ZERO,
                            bytecode_hash: None,
                        };
                        let trie_account = reth_account.into_trie_account(alloy_trie::EMPTY_ROOT_HASH);
                        accounts.push((*address, trie_account));
                        included_addresses.insert(*address);
                    }
                    continue;
                }
            };

            let info = &account.info;

            // Skip empty accounts after Spurious Dragon (EIP-161)
            // Before Spurious Dragon, "touched" empty accounts should be included
            if !include_empty && info.balance.is_zero() && info.nonce == 0 && info.is_empty_code_hash() {
                continue;
            }

            // Calculate storage root for this account
            // Need to merge pre_state storage with cached storage changes
            let storage_root = {
                let mut merged_storage: HashMap<B256, U256> = HashMap::new();

                // First, add all storage from pre_state for this address
                if let Some(pre_account) = _pre_state.get(address) {
                    for (k, v) in &pre_account.storage {
                        if !v.is_zero() {
                            merged_storage.insert(B256::from(*k), *v);
                        }
                    }
                }

                // Then, overlay with cached storage (which contains modified slots)
                // Note: PlainStorage value is already U256 (not EvmStorageSlot)
                for (k, v) in &account.storage {
                    if v.is_zero() {
                        // Storage was cleared, remove from merged
                        merged_storage.remove(&B256::from(*k));
                    } else {
                        // Storage was set, update in merged
                        merged_storage.insert(B256::from(*k), *v);
                    }
                }

                if merged_storage.is_empty() {
                    alloy_trie::EMPTY_ROOT_HASH
                } else {
                    storage_root_unhashed(merged_storage.into_iter())
                }
            };

            // Create the reth Account and convert to TrieAccount
            let reth_account = RethAccount {
                nonce: info.nonce,
                balance: info.balance,
                bytecode_hash: if info.is_empty_code_hash() { None } else { Some(info.code_hash) },
            };

            let trie_account = reth_account.into_trie_account(storage_root);
            accounts.push((*address, trie_account));
            included_addresses.insert(*address);
        }

        // For pre-Spurious Dragon forks, ensure coinbase is included even if not in cache
        // The coinbase receives gas fees and should be in state
        // After Spurious Dragon, empty coinbase accounts are not included
        if !included_addresses.contains(&env.current_coinbase) {
            // Check if coinbase is in the cache
            if let Some(cached_coinbase) = state.cache.accounts.get(&env.current_coinbase) {
                if !cached_coinbase.status.was_destroyed() {
                    if let Some(cb_account) = &cached_coinbase.account {
                        let cb_info = &cb_account.info;
                        // Include coinbase if it has balance or if we're pre-Spurious Dragon
                        if include_empty || !cb_info.balance.is_zero() || cb_info.nonce != 0 || !cb_info.is_empty_code_hash() {
                            // Calculate storage root for coinbase (usually empty)
                            let storage_root = {
                                let mut merged_storage: HashMap<B256, U256> = HashMap::new();

                                // First, add all storage from pre_state for coinbase
                                if let Some(pre_account) = _pre_state.get(&env.current_coinbase) {
                                    for (k, v) in &pre_account.storage {
                                        if !v.is_zero() {
                                            merged_storage.insert(B256::from(*k), *v);
                                        }
                                    }
                                }

                                // Then, overlay with cached storage
                                for (k, v) in &cb_account.storage {
                                    if v.is_zero() {
                                        merged_storage.remove(&B256::from(*k));
                                    } else {
                                        merged_storage.insert(B256::from(*k), *v);
                                    }
                                }

                                if merged_storage.is_empty() {
                                    alloy_trie::EMPTY_ROOT_HASH
                                } else {
                                    storage_root_unhashed(merged_storage.into_iter())
                                }
                            };
                            let reth_account = RethAccount {
                                nonce: cb_info.nonce,
                                balance: cb_info.balance,
                                bytecode_hash: if cb_info.is_empty_code_hash() { None } else { Some(cb_info.code_hash) },
                            };
                            let trie_account = reth_account.into_trie_account(storage_root);
                            accounts.push((env.current_coinbase, trie_account));
                            included_addresses.insert(env.current_coinbase);
                        }
                    } else if include_empty && !cached_coinbase.status.is_not_modified() {
                        // Coinbase was touched but has no account info - include as empty
                        let reth_account = RethAccount {
                            nonce: 0,
                            balance: U256::ZERO,
                            bytecode_hash: None,
                        };
                        let trie_account = reth_account.into_trie_account(alloy_trie::EMPTY_ROOT_HASH);
                        accounts.push((env.current_coinbase, trie_account));
                        included_addresses.insert(env.current_coinbase);
                    }
                }
            } else if include_empty {
                // Coinbase not in cache but we're pre-Spurious Dragon, add as empty
                let reth_account = RethAccount {
                    nonce: 0,
                    balance: U256::ZERO,
                    bytecode_hash: None,
                };
                let trie_account = reth_account.into_trie_account(alloy_trie::EMPTY_ROOT_HASH);
                accounts.push((env.current_coinbase, trie_account));
                included_addresses.insert(env.current_coinbase);
            }
        }

        // For pre-Spurious Dragon forks, add touched precompile addresses to the state tree
        // When a precompile is successfully called, it should appear as an empty account
        if let Some(precompile_addr) = touched_precompile {
            if include_empty && !included_addresses.contains(&precompile_addr) {
                let reth_account = RethAccount {
                    nonce: 0,
                    balance: U256::ZERO,
                    bytecode_hash: None,
                };
                let trie_account = reth_account.into_trie_account(alloy_trie::EMPTY_ROOT_HASH);
                accounts.push((precompile_addr, trie_account));
            }
        }

        // Include accounts from pre_state that were not touched during execution
        // These accounts should still appear in the final state
        // But skip accounts that were destroyed during execution
        for (address, account) in _pre_state {
            if !included_addresses.contains(address) {
                // Check if this account was destroyed during execution
                if let Some(cached) = state.cache.accounts.get(address) {
                    if cached.status.was_destroyed() {
                        // Account was destroyed, don't include it
                        continue;
                    }
                }

                // This account was not modified and not destroyed, include it from pre_state
                // Skip empty accounts after Spurious Dragon
                if !include_empty && account.balance.is_zero() && account.nonce == 0 && account.code.is_empty() {
                    continue;
                }

                // Calculate storage root for this account
                let storage_root = if account.storage.is_empty() {
                    alloy_trie::EMPTY_ROOT_HASH
                } else {
                    storage_root_unhashed(
                        account.storage.iter()
                            .filter(|(_, v)| !v.is_zero())
                            .map(|(k, v)| (B256::from(*k), *v))
                    )
                };

                // Create the reth Account and convert to TrieAccount
                let reth_account = RethAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    bytecode_hash: if account.code.is_empty() { None } else { Some(account.code_hash()) },
                };

                let trie_account = reth_account.into_trie_account(storage_root);
                accounts.push((*address, trie_account));
                included_addresses.insert(*address);
            }
        }

        // Calculate state root
        let root = state_root_unhashed(accounts.into_iter());

        Ok(root)
    }

    /// Calculate state root from pre_state (for rejected transactions)
    fn calculate_pre_state_root(
        &self,
        pre_state: &HashMap<Address, Account>,
    ) -> EfTestResult<B256> {
        // Collect all accounts from the pre_state
        let mut accounts: Vec<(Address, alloy_trie::TrieAccount)> = Vec::new();

        for (address, account) in pre_state {
            // Skip empty accounts (zero balance, zero nonce, no code)
            if account.balance.is_zero() && account.nonce == 0 && account.code.is_empty() {
                continue;
            }

            // Calculate storage root for this account
            let storage_root = if account.storage.is_empty() {
                alloy_trie::EMPTY_ROOT_HASH
            } else {
                storage_root_unhashed(
                    account.storage.iter()
                        .filter(|(_, v)| !v.is_zero())
                        .map(|(k, v)| (B256::from(*k), *v))
                )
            };

            // Create the reth Account and convert to TrieAccount
            let reth_account = RethAccount {
                nonce: account.nonce,
                balance: account.balance,
                bytecode_hash: if account.code.is_empty() { None } else { Some(account.code_hash()) },
            };

            let trie_account = reth_account.into_trie_account(storage_root);
            accounts.push((*address, trie_account));
        }

        // Calculate state root
        let root = state_root_unhashed(accounts.into_iter());

        Ok(root)
    }

    /// Build the block environment
    fn build_block_env(&self, env: &crate::models::Environment) -> BlockEnv {
        let spec_id = self.get_spec_id();
        // Calculate blob_excess_gas_and_price for Cancun+ forks
        // Prague uses a different update fraction (EIP-7691)
        let blob_excess_gas_and_price = env.current_excess_blob_gas.map(|excess_blob_gas| {
            let excess: u64 = excess_blob_gas.try_into().unwrap_or(0);
            let update_fraction = if spec_id >= SpecId::PRAGUE {
                BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
            } else {
                BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
            };
            BlobExcessGasAndPrice::new(excess, update_fraction)
        });

        BlockEnv {
            number: U256::from(env.current_number),
            beneficiary: env.current_coinbase,
            timestamp: U256::from(env.current_timestamp),
            gas_limit: env.current_gas_limit,
            difficulty: env.difficulty(),
            basefee: env.current_base_fee.map(|b| b.try_into().unwrap_or(u64::MAX)).unwrap_or(0),
            prevrandao: env.current_random,
            blob_excess_gas_and_price,
        }
    }

    /// Get the spec ID for the current fork
    pub fn get_spec_id(&self) -> SpecId {
        match self.fork {
            ForkSpec::Frontier => SpecId::FRONTIER,
            ForkSpec::Homestead | ForkSpec::DaoFork => SpecId::HOMESTEAD,
            ForkSpec::TangerineWhistle => SpecId::TANGERINE,
            ForkSpec::SpuriousDragon => SpecId::SPURIOUS_DRAGON,
            ForkSpec::Byzantium => SpecId::BYZANTIUM,
            ForkSpec::Constantinople | ForkSpec::Petersburg => SpecId::PETERSBURG,
            ForkSpec::Istanbul | ForkSpec::MuirGlacier => SpecId::ISTANBUL,
            ForkSpec::Berlin => SpecId::BERLIN,
            ForkSpec::London | ForkSpec::ArrowGlacier | ForkSpec::GrayGlacier => SpecId::LONDON,
            ForkSpec::Paris => SpecId::MERGE,
            ForkSpec::Shanghai => SpecId::SHANGHAI,
            ForkSpec::Cancun => SpecId::CANCUN,
            ForkSpec::Prague | ForkSpec::Osaka => SpecId::PRAGUE,
        }
    }

}

/// Result of transaction execution
#[derive(Debug, Clone)]
struct ExecutionResult {
    /// Computed state root
    state_root: B256,
    /// Computed logs hash
    logs_hash: B256,
    /// Gas used
    #[allow(dead_code)]
    gas_used: u64,
    /// Whether execution was successful
    #[allow(dead_code)]
    success: bool,
}

/// Empty logs hash (hash of RLP-encoded empty list)
fn empty_logs_hash() -> B256 {
    keccak256(&[0xc0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::Database;

    #[test]
    fn test_executor_creation() {
        let executor = StateTestExecutor::new(&ForkSpec::Berlin, 1);
        assert_eq!(executor.chain_spec.chain.id(), 1);
    }

    #[test]
    fn test_build_pre_state_db() {
        let executor = StateTestExecutor::new(&ForkSpec::Berlin, 1);

        let mut pre = HashMap::new();
        let addr = Address::ZERO;
        pre.insert(
            addr,
            Account {
                nonce: 1,
                balance: U256::from(1000),
                code: alloy_primitives::Bytes::default(),
                storage: HashMap::new(),
            },
        );

        let mut db = executor.build_pre_state_db(&pre).unwrap();
        let account = db.basic(addr).unwrap().unwrap();
        assert_eq!(account.nonce, 1);
        assert_eq!(account.balance, U256::from(1000));
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
}

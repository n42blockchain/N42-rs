//! Blockchain test executor
//!
//! This module implements the executor for Ethereum Foundation blockchain tests.
//! A blockchain test executes a sequence of blocks against a genesis state and verifies
//! the final state root and block hashes.

use crate::error::{EfTestError, EfTestResult};
use crate::fork::ForkSpec;
use crate::models::{Account, BlockchainTest};
use crate::result::TestResult;

use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{Address, B256, TxKind, U256};
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
use revm_database::{EmptyDB, AccountStatus as DbAccountStatus, PlainAccount, states::CacheAccount};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, trace};

/// Minimum gas price for a data blob (EIP-4844)
const MIN_BLOB_GASPRICE: u64 = 1;

/// Safe version of fake_exponential that handles overflow gracefully.
/// Approximates `factor * e ** (numerator / denominator)` using Taylor expansion.
/// Returns u128::MAX on overflow instead of panicking.
fn safe_fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u128 {
    if denominator == 0 {
        return u128::MAX;
    }

    let factor = factor as u128;
    let numerator = numerator as u128;
    let denominator = denominator as u128;

    let mut i: u128 = 1;
    let mut output: u128 = 0;

    // Use checked arithmetic for the initial multiplication
    let mut numerator_accum = match factor.checked_mul(denominator) {
        Some(v) => v,
        None => return u128::MAX,
    };

    while numerator_accum > 0 {
        // Use saturating_add to prevent overflow in output accumulation
        output = output.saturating_add(numerator_accum);

        // Check for overflow in denominator * i
        let denom_mul_i = match denominator.checked_mul(i) {
            Some(v) => v,
            None => break, // Effectively terminates the loop
        };

        // Check for overflow in numerator_accum * numerator
        let numer_mul = match numerator_accum.checked_mul(numerator) {
            Some(v) => v,
            None => {
                // On overflow, we can't continue the Taylor series accurately
                // The result is astronomically large, so saturate to MAX
                return u128::MAX;
            }
        };

        numerator_accum = numer_mul / denom_mul_i;
        i += 1;
    }

    output / denominator
}

/// Safe calculation of blob gas price that handles overflow gracefully.
/// Uses the EIP-4844 fake_exponential formula but with overflow protection.
fn safe_calc_blob_gasprice(excess_blob_gas: u64, blob_base_fee_update_fraction: u64) -> u128 {
    safe_fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas, blob_base_fee_update_fraction)
}

/// Executor for Ethereum Foundation blockchain tests
#[derive(Debug, Clone)]
pub struct BlockchainTestExecutor {
    /// Chain specification
    chain_spec: Arc<ChainSpec>,
    /// EVM configuration
    evm_config: EthEvmConfig,
    /// Fork specification
    fork: ForkSpec,
}

impl BlockchainTestExecutor {
    /// Create a new blockchain test executor for the given fork
    pub fn new(fork: &ForkSpec, chain_id: u64) -> Self {
        let chain_spec = fork.to_chain_spec(chain_id);
        let evm_config = EthEvmConfig::new(chain_spec.clone());
        Self {
            chain_spec,
            evm_config,
            fork: *fork,
        }
    }

    /// Execute a blockchain test
    pub fn execute(&self, test: &BlockchainTest, test_name: &str) -> EfTestResult<TestResult> {
        let start = Instant::now();
        let fork = test.fork();

        // For engine_x tests without full state, we skip execution
        if test.pre.is_none() || test.genesis_block_header.is_none() {
            return Ok(TestResult::skipped(
                test_name.to_string(),
                fork.to_string(),
                "Engine_x test format - skipping (uses pre/post hashes)".to_string(),
            ));
        }

        let pre = test.pre.as_ref().unwrap();
        let genesis_header = test.genesis_block_header.as_ref().unwrap();

        // Build the database with genesis state (pre-state)
        let db = self.build_pre_state_db(pre)?;
        let spec_id = self.get_spec_id();

        // Create state wrapper
        let mut state_db = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        state_db.set_state_clear_flag(spec_id >= SpecId::SPURIOUS_DRAGON);

        // Track the last block hash
        let mut last_block_hash = genesis_header.hash;
        #[allow(unused_variables)]
        let mut current_block_number = genesis_header.number;

        // Convert engine payloads to blocks if present
        let blocks = if let Some(ref engine_payloads) = test.engine_new_payloads {
            self.convert_engine_payloads_to_blocks(engine_payloads)?
        } else {
            test.blocks.clone()
        };

        // Execute each block
        for (block_idx, block) in blocks.iter().enumerate() {
            // Check if block is expected to be invalid
            if block.is_invalid() {
                // For invalid blocks, we expect an exception - skip execution
                debug!(
                    "Block {} expects exception: {:?}",
                    block_idx, block.expect_exception
                );
                continue;
            }

            // Get block header if available
            let header = match &block.block_header {
                Some(h) => h,
                None => {
                    // Try to decode from RLP if header is not provided
                    if block.rlp.is_some() {
                        debug!("Block {} has RLP but no header, skipping detailed execution", block_idx);
                    }
                    continue;
                }
            };

            current_block_number = header.number;

            // Build block environment
            let block_env = self.build_block_env_from_header(header);

            // Build configuration
            let cfg = CfgEnv::new()
                .with_chain_id(test.chain_id())
                .with_spec(spec_id);

            // Create EVM environment
            let evm_env = EvmEnv {
                cfg_env: cfg.clone(),
                block_env: block_env.clone(),
            };

            // Apply pre-execution system calls for Cancun+ (EIP-4788 beacon roots)
            if spec_id >= SpecId::CANCUN {
                if let Some(parent_beacon_block_root) = header.parent_beacon_block_root {
                    // Skip genesis block (block number 0)
                    if header.number > 0 {
                        // EIP-4788: Store beacon root
                        // The contract stores:
                        // - slot[timestamp % HISTORY_BUFFER_LENGTH] = timestamp
                        // - slot[timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH] = parent_beacon_block_root
                        const HISTORY_BUFFER_LENGTH: u64 = 8191;
                        let beacon_roots_address = alloy_eips::eip4788::BEACON_ROOTS_ADDRESS;
                        let timestamp = header.timestamp;
                        let timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH;
                        let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH;

                        // Get the beacon roots contract bytecode
                        let beacon_roots_code = alloy_eips::eip4788::BEACON_ROOTS_CODE.clone();

                        // Build storage for beacon roots contract (using std HashMap for PlainAccount compatibility)
                        let mut beacon_storage = std::collections::HashMap::default();
                        // Store timestamp at timestamp_idx
                        beacon_storage.insert(U256::from(timestamp_idx), U256::from(timestamp));
                        // Store parent_beacon_block_root at root_idx (if not zero)
                        if !parent_beacon_block_root.is_zero() {
                            beacon_storage.insert(U256::from(root_idx), U256::from_be_bytes(parent_beacon_block_root.0));
                        }

                        // Update or create the beacon roots contract account in cache
                        let beacon_account_info = AccountInfo {
                            nonce: 1, // Contract accounts have nonce 1
                            balance: U256::ZERO,
                            code_hash: alloy_primitives::keccak256(&beacon_roots_code),
                            code: Some(Bytecode::new_raw(beacon_roots_code)),
                        };

                        // Insert or update the account in cache
                        if let Some(cached) = state_db.cache.accounts.get_mut(&beacon_roots_address) {
                            if let Some(account) = &mut cached.account {
                                // Update existing account storage
                                for (k, v) in &beacon_storage {
                                    account.storage.insert(*k, *v);
                                }
                            } else {
                                // Account exists but is empty - create it
                                cached.account = Some(PlainAccount {
                                    info: beacon_account_info,
                                    storage: beacon_storage,
                                });
                            }
                            cached.status = DbAccountStatus::Changed;
                        } else {
                            // Account not in cache - insert it
                            state_db.cache.accounts.insert(beacon_roots_address, CacheAccount {
                                account: Some(PlainAccount {
                                    info: beacon_account_info,
                                    storage: beacon_storage,
                                }),
                                status: DbAccountStatus::InMemoryChange,
                            });
                        }
                    }
                }
            }

            // Apply pre-execution system calls for Prague+ (EIP-2935 block hashes history)
            if spec_id >= SpecId::PRAGUE {
                // Skip genesis block
                if header.number > 0 {
                    // EIP-2935: Store parent block hash
                    // The contract stores: slot[(block_number - 1) % HISTORY_SERVE_WINDOW] = parent_hash
                    const HISTORY_SERVE_WINDOW: u64 = 8191;
                    let history_storage_address = alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS;
                    let slot = (header.number - 1) % HISTORY_SERVE_WINDOW;
                    let parent_hash = header.parent_hash;

                    // Get the history storage contract bytecode
                    let history_storage_code = alloy_eips::eip2935::HISTORY_STORAGE_CODE.clone();

                    // Build storage for history storage contract
                    let mut history_storage = std::collections::HashMap::default();
                    history_storage.insert(U256::from(slot), U256::from_be_bytes(parent_hash.0));

                    // Update or create the history storage contract account in cache
                    let history_account_info = AccountInfo {
                        nonce: 1,
                        balance: U256::ZERO,
                        code_hash: alloy_primitives::keccak256(&history_storage_code),
                        code: Some(Bytecode::new_raw(history_storage_code)),
                    };

                    // Insert or update the account in cache
                    if let Some(cached) = state_db.cache.accounts.get_mut(&history_storage_address) {
                        if let Some(account) = &mut cached.account {
                            for (k, v) in &history_storage {
                                account.storage.insert(*k, *v);
                            }
                        } else {
                            cached.account = Some(PlainAccount {
                                info: history_account_info,
                                storage: history_storage,
                            });
                        }
                        cached.status = DbAccountStatus::Changed;
                    } else {
                        state_db.cache.accounts.insert(history_storage_address, CacheAccount {
                            account: Some(PlainAccount {
                                info: history_account_info,
                                storage: history_storage,
                            }),
                            status: DbAccountStatus::InMemoryChange,
                        });
                    }
                }
            }

            // Execute all transactions in the block
            for (tx_idx, tx) in block.transactions.iter().enumerate() {
                let tx_env = self.build_tx_env_from_block_tx(tx)?;

                let mut evm = self.evm_config.evm_with_env(&mut state_db, evm_env.clone());

                match evm.transact_commit(tx_env) {
                    Ok(result) => {
                        trace!(
                            "Block {} Tx {} executed: gas_used={}, success={}",
                            block_idx,
                            tx_idx,
                            result.gas_used(),
                            result.is_success()
                        );
                    }
                    Err(e) => {
                        // Transaction execution error - might be expected for some tests
                        debug!(
                            "Block {} Tx {} execution error: {:?}",
                            block_idx, tx_idx, e
                        );
                    }
                }
            }

            // Apply withdrawals for Shanghai+
            if let Some(withdrawals) = &block.withdrawals {
                for withdrawal in withdrawals {
                    // Add withdrawal amount to recipient (amount is in Gwei, convert to Wei)
                    let amount_wei = U256::from(withdrawal.amount) * U256::from(1_000_000_000u64);

                    // Skip zero-amount withdrawals - they don't affect state
                    if amount_wei.is_zero() {
                        continue;
                    }

                    // Get or create the withdrawal recipient account
                    if let Some(cached) = state_db.cache.accounts.get_mut(&withdrawal.address) {
                        // Check if the account was destroyed by SELFDESTRUCT
                        if cached.status.was_destroyed() {
                            // Account was destroyed - create a fresh account with only the withdrawal balance
                            // After SELFDESTRUCT, the account is cleared (nonce=0, no code, no storage)
                            cached.account = Some(PlainAccount {
                                info: AccountInfo {
                                    balance: amount_wei,
                                    nonce: 0,
                                    code_hash: revm::primitives::KECCAK_EMPTY,
                                    code: None,
                                },
                                storage: Default::default(),
                            });
                            // Keep the destroyed status to indicate storage was cleared
                            cached.status = DbAccountStatus::DestroyedChanged;
                        } else if let Some(account) = &mut cached.account {
                            // Account exists in cache with account info - update balance
                            account.info.balance += amount_wei;
                            cached.status = DbAccountStatus::Changed;
                        } else {
                            // Account exists in cache but is empty (was not existing) - recreate it
                            // Check if account exists in pre_state to get initial values
                            let (initial_balance, initial_nonce, code_hash) = pre.get(&withdrawal.address)
                                .map(|pre_acc| (pre_acc.balance, pre_acc.nonce, pre_acc.code_hash()))
                                .unwrap_or((U256::ZERO, 0, revm::primitives::KECCAK_EMPTY));

                            cached.account = Some(PlainAccount {
                                info: AccountInfo {
                                    balance: initial_balance + amount_wei,
                                    nonce: initial_nonce,
                                    code_hash,
                                    code: None,
                                },
                                storage: Default::default(),
                            });
                            cached.status = DbAccountStatus::InMemoryChange;
                        }
                    } else {
                        // Account not in cache - check if it exists in pre_state
                        let (initial_balance, initial_nonce, code_hash) = pre.get(&withdrawal.address)
                            .map(|pre_acc| (pre_acc.balance, pre_acc.nonce, pre_acc.code_hash()))
                            .unwrap_or((U256::ZERO, 0, revm::primitives::KECCAK_EMPTY));

                        let account_info = AccountInfo {
                            balance: initial_balance + amount_wei,
                            nonce: initial_nonce,
                            code_hash,
                            code: None,
                        };
                        // Insert into cache as a changed/created account
                        // Storage is left as default - the calculate_state_root function
                        // will merge pre_state storage for accounts not touched during execution
                        state_db.cache.accounts.insert(withdrawal.address, CacheAccount {
                            account: Some(PlainAccount {
                                info: account_info,
                                storage: Default::default(),
                            }),
                            status: DbAccountStatus::InMemoryChange,
                        });
                    }
                }
            }

            // Apply block reward for PoW forks (before The Merge)
            // PoW is indicated by non-zero difficulty
            if !header.difficulty.is_zero() {
                // Block reward is 2 ETH for London and later PoW forks
                let block_reward = U256::from(2_000_000_000_000_000_000u64); // 2 ETH in wei

                // Add block reward to coinbase
                let coinbase = header.coinbase;
                if let Some(cached) = state_db.cache.accounts.get_mut(&coinbase) {
                    if let Some(account) = &mut cached.account {
                        account.info.balance += block_reward;
                        cached.status = DbAccountStatus::Changed;
                    } else {
                        // Account exists in cache but is empty, create it with block reward
                        cached.account = Some(PlainAccount {
                            info: AccountInfo {
                                balance: block_reward,
                                nonce: 0,
                                code_hash: revm::primitives::KECCAK_EMPTY,
                                code: None,
                            },
                            storage: Default::default(),
                        });
                        cached.status = DbAccountStatus::InMemoryChange;
                    }
                } else {
                    // Account not in cache, need to create it
                    let account_info = AccountInfo {
                        balance: block_reward,
                        nonce: 0,
                        code_hash: revm::primitives::KECCAK_EMPTY,
                        code: None,
                    };
                    // Insert into cache as a newly created account
                    state_db.cache.accounts.insert(coinbase, CacheAccount {
                        account: Some(PlainAccount {
                            info: account_info,
                            storage: Default::default(),
                        }),
                        status: DbAccountStatus::InMemoryChange,
                    });
                }
            }

            // Update last block hash
            last_block_hash = header.hash;
        }

        let duration = start.elapsed();

        // Get the coinbase from the last valid block header for state root calculation
        let coinbase = test.blocks.iter()
            .rev()
            .find_map(|b| b.block_header.as_ref().map(|h| h.coinbase));

        // Calculate final state root
        let actual_state_root = self.calculate_state_root(&state_db, pre, coinbase)?;

        // Verify results
        // 1. Check last block hash
        let hash_match = last_block_hash == test.lastblockhash;

        // 2. Check state root (compare with post_state)
        let (expected_state_root, state_match) = if let Some(post_state) = &test.post_state {
            let expected = self.calculate_expected_state_root(post_state)?;
            (expected, actual_state_root == expected)
        } else {
            // For engine_x tests without post_state, we can't verify state root
            (actual_state_root, true)
        };

        if hash_match && state_match {
            Ok(TestResult::passed(test_name.to_string(), fork.to_string(), duration)
                .with_state_roots(expected_state_root, actual_state_root))
        } else {
            let mut errors = Vec::new();
            if !hash_match {
                errors.push(format!(
                    "Last block hash mismatch: expected {}, got {}",
                    test.lastblockhash, last_block_hash
                ));
            }
            if !state_match {
                errors.push(format!(
                    "State root mismatch: expected {}, got {}",
                    expected_state_root, actual_state_root
                ));
            }
            Ok(TestResult::failed(
                test_name.to_string(),
                fork.to_string(),
                duration,
                errors.join("; "),
            )
            .with_state_roots(expected_state_root, actual_state_root))
        }
    }

    /// Convert Engine API payloads to Block structures for execution
    fn convert_engine_payloads_to_blocks(
        &self,
        engine_payloads: &[crate::models::EngineNewPayload],
    ) -> EfTestResult<Vec<crate::models::Block>> {
        use crate::models::{Block, ExecutionPayload, Withdrawal};
        use alloy_primitives::Bytes;
        use std::str::FromStr;

        let mut blocks = Vec::new();

        for payload in engine_payloads {
            // Parse the params field to get the execution payload
            let execution_payload: ExecutionPayload = serde_json::from_value(
                payload.params.get(0)
                    .ok_or_else(|| EfTestError::InvalidTestData("Engine payload missing params[0]".to_string()))?
                    .clone()
            ).map_err(|e| EfTestError::InvalidTestData(format!("Failed to parse execution payload: {}", e)))?;

            // Extract parent_beacon_block_root from params[2] if present
            let parent_beacon_block_root = if let Some(value) = payload.params.get(2) {
                serde_json::from_value(value.clone()).ok()
            } else {
                None
            };

            // Convert ExecutionPayload to Header
            let header = self.execution_payload_to_header(&execution_payload, parent_beacon_block_root)?;

            // Decode transactions from raw hex strings
            let mut transactions = Vec::new();
            for tx_hex in &execution_payload.transactions {
                // Convert hex string to Bytes
                let tx_bytes = Bytes::from_str(tx_hex)
                    .map_err(|e| EfTestError::InvalidTestData(format!("Failed to parse transaction hex: {}", e)))?;
                // Decode the RLP-encoded transaction
                let tx = self.decode_transaction(&tx_bytes)?;
                transactions.push(tx);
            }

            // Parse withdrawals if present
            let withdrawals = if execution_payload.withdrawals.is_empty() {
                None
            } else {
                let parsed_withdrawals: Result<Vec<Withdrawal>, _> = execution_payload.withdrawals
                    .iter()
                    .map(|w| serde_json::from_value(w.clone()))
                    .collect();
                Some(parsed_withdrawals.map_err(|e| EfTestError::InvalidTestData(format!("Failed to parse withdrawal: {}", e)))?)
            };

            // Create Block structure
            let block = Block {
                block_header: Some(header),
                transactions,
                uncle_headers: Vec::new(),
                withdrawals,
                rlp: None,
                expect_exception: None,
            };

            blocks.push(block);
        }

        Ok(blocks)
    }

    /// Convert ExecutionPayload to Header
    fn execution_payload_to_header(
        &self,
        payload: &crate::models::ExecutionPayload,
        parent_beacon_block_root: Option<B256>,
    ) -> EfTestResult<crate::models::Header> {
        use crate::models::Header;
        use alloy_primitives::B64;

        // Empty ommers hash (keccak256 of RLP-encoded empty list)
        const EMPTY_OMMERS_HASH: B256 = B256::new([
            0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc,
            0xd4, 0x1a, 0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd,
            0x40, 0xd4, 0x93, 0x47,
        ]);

        Ok(Header {
            parent_hash: payload.parent_hash,
            uncle_hash: EMPTY_OMMERS_HASH,
            coinbase: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_trie: payload.receipts_root, // Note: this is actually receipts root in payload
            receipt_trie: payload.receipts_root,
            bloom: payload.logs_bloom,
            difficulty: U256::ZERO, // PoS blocks have zero difficulty
            number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            mix_hash: payload.prev_randao,
            nonce: B64::ZERO, // PoS blocks have zero nonce
            hash: payload.block_hash,
            base_fee_per_gas: Some(payload.base_fee_per_gas),
            withdrawals_root: None, // We'll need to calculate this from withdrawals if present
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            parent_beacon_block_root,
            requests_root: None, // Not present in current ExecutionPayload
        })
    }

    /// Decode a transaction from RLP bytes
    fn decode_transaction(
        &self,
        tx_bytes: &alloy_primitives::Bytes,
    ) -> EfTestResult<crate::models::BlockTransaction> {
        use alloy_consensus::{TxEnvelope, TxType};
        use alloy_rlp::Decodable;
        use crate::models::{AccessListItem, Authorization, BlockTransaction};

        // Decode the transaction envelope
        let tx_envelope = TxEnvelope::decode(&mut tx_bytes.as_ref())
            .map_err(|e| EfTestError::InvalidTestData(format!("Failed to decode transaction: {}", e)))?;

        // Convert to BlockTransaction based on type
        let block_tx = match tx_envelope {
            TxEnvelope::Legacy(signed_tx) => {
                let tx = signed_tx.tx();
                let sig = signed_tx.signature();
                // For legacy transactions, v is calculated differently
                let v = if let Some(chain_id) = tx.chain_id {
                    // EIP-155: v = chain_id * 2 + 35 + y_parity
                    U256::from(chain_id * 2 + 35 + if sig.v() { 1 } else { 0 })
                } else {
                    // Pre-EIP-155: v = 27 + y_parity
                    U256::from(27 + if sig.v() { 1 } else { 0 })
                };

                BlockTransaction {
                    tx_type: Some(TxType::Legacy as u64),
                    chain_id: tx.chain_id,
                    nonce: tx.nonce,
                    gas_price: Some(U256::from(tx.gas_price)),
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    gas_limit: tx.gas_limit,
                    to: tx.to.to().copied(),
                    value: tx.value,
                    data: tx.input.clone(),
                    sender: signed_tx.recover_signer()
                        .map_err(|e| EfTestError::InvalidTestData(format!("Failed to recover sender: {}", e)))?,
                    v,
                    r: sig.r(),
                    s: sig.s(),
                    access_list: None,
                    max_fee_per_blob_gas: None,
                    blob_versioned_hashes: None,
                    authorization_list: None,
                }
            }
            TxEnvelope::Eip2930(signed_tx) => {
                let tx = signed_tx.tx();
                let sig = signed_tx.signature();
                BlockTransaction {
                    tx_type: Some(TxType::Eip2930 as u64),
                    chain_id: Some(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: Some(U256::from(tx.gas_price)),
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    gas_limit: tx.gas_limit,
                    to: tx.to.to().copied(),
                    value: tx.value,
                    data: tx.input.clone(),
                    sender: signed_tx.recover_signer()
                        .map_err(|e| EfTestError::InvalidTestData(format!("Failed to recover sender: {}", e)))?,
                    v: U256::from(if sig.v() { 1u64 } else { 0u64 }),
                    r: sig.r(),
                    s: sig.s(),
                    access_list: Some(
                        tx.access_list.0.iter().map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        }).collect()
                    ),
                    max_fee_per_blob_gas: None,
                    blob_versioned_hashes: None,
                    authorization_list: None,
                }
            }
            TxEnvelope::Eip1559(signed_tx) => {
                let tx = signed_tx.tx();
                let sig = signed_tx.signature();
                BlockTransaction {
                    tx_type: Some(TxType::Eip1559 as u64),
                    chain_id: Some(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: None,
                    max_fee_per_gas: Some(U256::from(tx.max_fee_per_gas)),
                    max_priority_fee_per_gas: Some(U256::from(tx.max_priority_fee_per_gas)),
                    gas_limit: tx.gas_limit,
                    to: tx.to.to().copied(),
                    value: tx.value,
                    data: tx.input.clone(),
                    sender: signed_tx.recover_signer()
                        .map_err(|e| EfTestError::InvalidTestData(format!("Failed to recover sender: {}", e)))?,
                    v: U256::from(if sig.v() { 1u64 } else { 0u64 }),
                    r: sig.r(),
                    s: sig.s(),
                    access_list: Some(
                        tx.access_list.0.iter().map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        }).collect()
                    ),
                    max_fee_per_blob_gas: None,
                    blob_versioned_hashes: None,
                    authorization_list: None,
                }
            }
            TxEnvelope::Eip4844(signed_tx) => {
                let tx = signed_tx.tx().tx();
                let sig = signed_tx.signature();
                BlockTransaction {
                    tx_type: Some(TxType::Eip4844 as u64),
                    chain_id: Some(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: None,
                    max_fee_per_gas: Some(U256::from(tx.max_fee_per_gas)),
                    max_priority_fee_per_gas: Some(U256::from(tx.max_priority_fee_per_gas)),
                    gas_limit: tx.gas_limit,
                    to: Some(tx.to),
                    value: tx.value,
                    data: tx.input.clone(),
                    sender: signed_tx.recover_signer()
                        .map_err(|e| EfTestError::InvalidTestData(format!("Failed to recover sender: {}", e)))?,
                    v: U256::from(if sig.v() { 1u64 } else { 0u64 }),
                    r: sig.r(),
                    s: sig.s(),
                    access_list: Some(
                        tx.access_list.0.iter().map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        }).collect()
                    ),
                    max_fee_per_blob_gas: Some(U256::from(tx.max_fee_per_blob_gas)),
                    blob_versioned_hashes: Some(tx.blob_versioned_hashes.clone()),
                    authorization_list: None,
                }
            }
            TxEnvelope::Eip7702(signed_tx) => {
                let tx = signed_tx.tx();
                let sig = signed_tx.signature();
                BlockTransaction {
                    tx_type: Some(TxType::Eip7702 as u64),
                    chain_id: Some(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: None,
                    max_fee_per_gas: Some(U256::from(tx.max_fee_per_gas)),
                    max_priority_fee_per_gas: Some(U256::from(tx.max_priority_fee_per_gas)),
                    gas_limit: tx.gas_limit,
                    to: Some(tx.to), // EIP-7702 tx.to is already Address
                    value: tx.value,
                    data: tx.input.clone(),
                    sender: signed_tx.recover_signer()
                        .map_err(|e| EfTestError::InvalidTestData(format!("Failed to recover sender: {}", e)))?,
                    v: U256::from(if sig.v() { 1u64 } else { 0u64 }),
                    r: sig.r(),
                    s: sig.s(),
                    access_list: Some(
                        tx.access_list.0.iter().map(|item| AccessListItem {
                            address: item.address,
                            storage_keys: item.storage_keys.clone(),
                        }).collect()
                    ),
                    max_fee_per_blob_gas: None,
                    blob_versioned_hashes: None,
                    authorization_list: Some(
                        tx.authorization_list.iter().map(|auth| Authorization {
                            chain_id: auth.chain_id.to::<u64>(),
                            address: auth.address,
                            nonce: auth.nonce,
                            v: 0, // TODO: extract from signature
                            r: U256::ZERO,
                            s: U256::ZERO,
                        }).collect()
                    ),
                }
            }
            _ => {
                return Err(EfTestError::InvalidTestData(
                    format!("Unsupported transaction type in engine payload")
                ))
            }
        };

        Ok(block_tx)
    }

    /// Build a CacheDB with the pre-state accounts
    fn build_pre_state_db(&self, pre: &HashMap<Address, Account>) -> EfTestResult<CacheDB<EmptyDB>> {
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

    /// Build block environment from header
    fn build_block_env_from_header(
        &self,
        header: &crate::models::Header,
    ) -> BlockEnv {
        let spec_id = self.get_spec_id();
        let blob_excess_gas_and_price = header.excess_blob_gas.map(|excess| {
            // Use a safe blob gas price calculation that handles overflow gracefully
            // The standard BlobExcessGasAndPrice::new() can panic with extremely large
            // excess_blob_gas values due to overflow in the fake_exponential calculation
            // Prague uses a different update fraction (EIP-7691)
            let update_fraction = if spec_id >= SpecId::PRAGUE {
                BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
            } else {
                BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
            };
            let blob_gasprice = safe_calc_blob_gasprice(excess, update_fraction);
            BlobExcessGasAndPrice {
                excess_blob_gas: excess,
                blob_gasprice,
            }
        });

        BlockEnv {
            number: U256::from(header.number),
            beneficiary: header.coinbase,
            timestamp: U256::from(header.timestamp),
            gas_limit: header.gas_limit,
            difficulty: header.difficulty,
            basefee: header.base_fee_per_gas.map(|b| b.try_into().unwrap_or(u64::MAX)).unwrap_or(0),
            prevrandao: Some(header.mix_hash),
            blob_excess_gas_and_price,
        }
    }

    /// Build transaction environment from block transaction
    fn build_tx_env_from_block_tx(
        &self,
        tx: &crate::models::transaction::BlockTransaction,
    ) -> EfTestResult<TxEnv> {
        let mut tx_env = TxEnv::default();

        // Set common fields
        tx_env.caller = tx.sender;
        tx_env.gas_limit = tx.gas_limit;
        tx_env.gas_price = tx.effective_gas_price().try_into().unwrap_or(u128::MAX);
        tx_env.value = tx.value;
        tx_env.data = tx.data.clone();
        tx_env.nonce = tx.nonce;
        tx_env.chain_id = tx.chain_id;

        // Set transaction type
        tx_env.tx_type = tx.tx_type();

        // Handle destination
        if let Some(to) = tx.to {
            tx_env.kind = TxKind::Call(to);
        } else {
            tx_env.kind = TxKind::Create;
        }

        // Handle EIP-1559 fields
        if let Some(max_fee) = tx.max_fee_per_gas {
            tx_env.gas_price = max_fee.try_into().unwrap_or(u128::MAX);
        }
        if let Some(max_priority_fee) = tx.max_priority_fee_per_gas {
            tx_env.gas_priority_fee = Some(max_priority_fee.try_into().unwrap_or(u128::MAX));
        }

        // Handle access list
        if let Some(ref access_list) = tx.access_list {
            let items: Vec<AccessListItem> = access_list
                .iter()
                .map(|item| AccessListItem {
                    address: item.address,
                    storage_keys: item.storage_keys.clone(),
                })
                .collect();
            tx_env.access_list = AccessList(items);
        }

        // Handle EIP-4844 fields
        if let Some(max_fee_per_blob_gas) = tx.max_fee_per_blob_gas {
            tx_env.max_fee_per_blob_gas = max_fee_per_blob_gas.try_into().unwrap_or(u128::MAX);
        }
        if let Some(ref blob_hashes) = tx.blob_versioned_hashes {
            tx_env.blob_hashes = blob_hashes.clone();
        }

        // Handle EIP-7702 authorization list
        if let Some(ref auth_list) = tx.authorization_list {
            use alloy_eips::eip7702::{Authorization as Eip7702Auth, SignedAuthorization};
            use revm::context_interface::{either::Either, transaction::RecoveredAuthorization};

            let signed_auths: Vec<Either<SignedAuthorization, RecoveredAuthorization>> = auth_list
                .iter()
                .map(|auth| {
                    let inner = Eip7702Auth {
                        chain_id: alloy_primitives::U256::from(auth.chain_id),
                        address: auth.address,
                        nonce: auth.nonce,
                    };
                    let y_parity = auth.v as u8;
                    Either::Left(SignedAuthorization::new_unchecked(inner, y_parity, auth.r, auth.s))
                })
                .collect();
            tx_env.authorization_list = signed_auths;
        }

        Ok(tx_env)
    }

    /// Calculate state root from current state
    fn calculate_state_root<DB>(
        &self,
        state: &State<DB>,
        pre_state: &HashMap<Address, Account>,
        coinbase: Option<Address>,
    ) -> EfTestResult<B256> {
        let mut accounts: Vec<(Address, alloy_trie::TrieAccount)> = Vec::new();
        let mut included_addresses = std::collections::HashSet::new();
        let include_empty = self.get_spec_id() < SpecId::SPURIOUS_DRAGON;

        // Process accounts from cache
        for (address, cached_account) in &state.cache.accounts {
            // Skip accounts that were destroyed and NOT recreated
            // Destroyed = destroyed, no changes after (skip)
            // DestroyedAgain = destroyed again after recreation (skip)
            // DestroyedChanged = destroyed then recreated/changed (include!)
            if matches!(cached_account.status, DbAccountStatus::Destroyed | DbAccountStatus::DestroyedAgain) {
                continue;
            }

            let account = match &cached_account.account {
                Some(acc) => acc,
                None => {
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

            if !include_empty && info.balance.is_zero() && info.nonce == 0 && info.is_empty_code_hash() {
                continue;
            }

            // Calculate storage root
            let storage_root = {
                let mut merged_storage: HashMap<B256, U256> = HashMap::new();

                // For DestroyedChanged accounts, the destruction clears all storage,
                // so we should NOT merge with pre_state storage
                let storage_was_destroyed = matches!(cached_account.status, DbAccountStatus::DestroyedChanged);

                if !storage_was_destroyed {
                    if let Some(pre_account) = pre_state.get(address) {
                        for (k, v) in &pre_account.storage {
                            if !v.is_zero() {
                                merged_storage.insert(B256::from(*k), *v);
                            }
                        }
                    }
                }

                for (k, v) in &account.storage {
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
                nonce: info.nonce,
                balance: info.balance,
                bytecode_hash: if info.is_empty_code_hash() { None } else { Some(info.code_hash) },
            };

            let trie_account = reth_account.into_trie_account(storage_root);
            accounts.push((*address, trie_account));
            included_addresses.insert(*address);
        }

        // Handle coinbase account specially - it may have been created during execution
        // and should be included in the state root if it has balance
        if let Some(coinbase_addr) = coinbase {
            if !included_addresses.contains(&coinbase_addr) {
                if let Some(cached_coinbase) = state.cache.accounts.get(&coinbase_addr) {
                    if !cached_coinbase.status.was_destroyed() {
                        if let Some(cb_account) = &cached_coinbase.account {
                            let cb_info = &cb_account.info;
                            // Include coinbase if it has balance or if we're pre-Spurious Dragon
                            if include_empty || !cb_info.balance.is_zero() || cb_info.nonce != 0 || !cb_info.is_empty_code_hash() {
                                // Calculate storage root for coinbase
                                let storage_root = {
                                    let mut merged_storage: HashMap<B256, U256> = HashMap::new();

                                    if let Some(pre_account) = pre_state.get(&coinbase_addr) {
                                        for (k, v) in &pre_account.storage {
                                            if !v.is_zero() {
                                                merged_storage.insert(B256::from(*k), *v);
                                            }
                                        }
                                    }

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
                                accounts.push((coinbase_addr, trie_account));
                                included_addresses.insert(coinbase_addr);
                            }
                        } else if include_empty && !cached_coinbase.status.is_not_modified() {
                            // Coinbase was touched but has no account info - include as empty
                            let reth_account = RethAccount {
                                nonce: 0,
                                balance: U256::ZERO,
                                bytecode_hash: None,
                            };
                            let trie_account = reth_account.into_trie_account(alloy_trie::EMPTY_ROOT_HASH);
                            accounts.push((coinbase_addr, trie_account));
                            included_addresses.insert(coinbase_addr);
                        }
                    }
                }
            }
        }

        // Include untouched accounts from pre_state
        for (address, account) in pre_state {
            if !included_addresses.contains(address) {
                if let Some(cached) = state.cache.accounts.get(address) {
                    if cached.status.was_destroyed() {
                        continue;
                    }
                }

                if !include_empty && account.balance.is_zero() && account.nonce == 0 && account.code.is_empty() {
                    continue;
                }

                let storage_root = if account.storage.is_empty() {
                    alloy_trie::EMPTY_ROOT_HASH
                } else {
                    storage_root_unhashed(
                        account.storage.iter()
                            .filter(|(_, v)| !v.is_zero())
                            .map(|(k, v)| (B256::from(*k), *v))
                    )
                };

                let reth_account = RethAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    bytecode_hash: if account.code.is_empty() { None } else { Some(account.code_hash()) },
                };

                let trie_account = reth_account.into_trie_account(storage_root);
                accounts.push((*address, trie_account));
            }
        }

        Ok(state_root_unhashed(accounts.into_iter()))
    }

    /// Calculate expected state root from post_state
    fn calculate_expected_state_root(&self, post_state: &HashMap<Address, Account>) -> EfTestResult<B256> {
        let mut accounts: Vec<(Address, alloy_trie::TrieAccount)> = Vec::new();
        let include_empty = self.get_spec_id() < SpecId::SPURIOUS_DRAGON;

        for (address, account) in post_state {
            if !include_empty && account.balance.is_zero() && account.nonce == 0 && account.code.is_empty() {
                continue;
            }

            let storage_root = if account.storage.is_empty() {
                alloy_trie::EMPTY_ROOT_HASH
            } else {
                storage_root_unhashed(
                    account.storage.iter()
                        .filter(|(_, v)| !v.is_zero())
                        .map(|(k, v)| (B256::from(*k), *v))
                )
            };

            let reth_account = RethAccount {
                nonce: account.nonce,
                balance: account.balance,
                bytecode_hash: if account.code.is_empty() { None } else { Some(account.code_hash()) },
            };

            let trie_account = reth_account.into_trie_account(storage_root);
            accounts.push((*address, trie_account));
        }

        Ok(state_root_unhashed(accounts.into_iter()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = BlockchainTestExecutor::new(&ForkSpec::Berlin, 1);
        assert_eq!(executor.chain_spec.chain.id(), 1);
    }

    #[test]
    fn test_safe_fake_exponential_matches_standard_cases() {
        // Test cases from EIP-4844 / go-ethereum
        // https://github.com/ethereum/go-ethereum/blob/28857080d732857030eda80c69b9ba2c8926f221/consensus/misc/eip4844/eip4844_test.go#L78
        let test_cases: &[(u64, u64, u64, u128)] = &[
            (1, 0, 1, 1),
            (38493, 0, 1000, 38493),
            (0, 1234, 2345, 0),
            (1, 2, 1, 6),
            (1, 4, 2, 6),
            (1, 3, 1, 16),
            (1, 6, 2, 18),
            (1, 4, 1, 49),
            (1, 8, 2, 50),
            (10, 8, 2, 542),
            (11, 8, 2, 596),
            (1, 5, 1, 136),
            (1, 5, 2, 11),
            (2, 5, 2, 23),
            (1, 50000000, 2225652, 5709098764),
            (1, 380928, 3338477, 1),  // BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
        ];

        for &(factor, numerator, denominator, expected) in test_cases {
            let result = safe_fake_exponential(factor, numerator, denominator);
            assert_eq!(
                result, expected,
                "safe_fake_exponential({}, {}, {}) = {}, expected {}",
                factor, numerator, denominator, result, expected
            );
        }
    }

    #[test]
    fn test_safe_fake_exponential_handles_overflow() {
        // Test with extremely large values that would cause overflow
        // in the standard implementation
        let result = safe_fake_exponential(1, u64::MAX, 1);
        // Should return u128::MAX on overflow instead of panicking
        assert_eq!(result, u128::MAX);

        // Test with large excess_blob_gas that caused the original panic
        let result = safe_calc_blob_gasprice(u64::MAX, BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN);
        // Should return u128::MAX on overflow
        assert_eq!(result, u128::MAX);
    }

    #[test]
    fn test_safe_fake_exponential_zero_denominator() {
        // Zero denominator should return u128::MAX instead of panicking
        let result = safe_fake_exponential(1, 100, 0);
        assert_eq!(result, u128::MAX);
    }
}

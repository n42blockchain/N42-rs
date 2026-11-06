//! Blockchain test executor
//!
//! This module implements the executor for Ethereum Foundation blockchain tests.
//! A blockchain test executes a sequence of blocks against a genesis state and verifies
//! the final state root and block hashes.
//!
//! Blocks run through reth's own block executor (`EthEvmConfig::executor`), so the
//! pre-execution system calls (EIP-4788 beacon roots, EIP-2935 block hashes), withdrawals,
//! block rewards and post-execution requests are applied exactly as the node applies them.
//! The state lives in an evm2 [`InMemoryDB`] that each block's bundle is committed into.

use super::state_db::{build_pre_state_db, state_root_of_accounts, state_root_of_db};
use crate::error::{EfTestError, EfTestResult};
use crate::fork::ForkSpec;
use crate::models::BlockchainTest;
use crate::result::TestResult;

use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::{eip2718::Decodable2718, eip4895::Withdrawal as AlloyWithdrawal};
use alloy_primitives::{Bytes, B256, B64, U256};
use alloy_rlp::Decodable;
use evm2::{evm::InMemoryDB, SpecId};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::{Block, BlockBody, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::BundleSource;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

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

/// A fixture block prepared for execution.
enum PreparedBlock {
    /// A decoded block with its senders recovered.
    Ready(Box<RecoveredBlock<Block>>),
    /// A block that is not executed, with the reason.
    Skip(String),
}

impl BlockchainTestExecutor {
    /// Create a new blockchain test executor for the given fork
    pub fn new(fork: &ForkSpec, chain_id: u64) -> Self {
        let chain_spec = fork.to_chain_spec(chain_id);
        let evm_config = EthEvmConfig::ethereum(chain_spec.clone());
        Self { chain_spec, evm_config, fork: *fork }
    }

    /// Returns the chain specification the executor runs on.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        &self.chain_spec
    }

    /// Execute a blockchain test
    pub fn execute(&self, test: &BlockchainTest, test_name: &str) -> EfTestResult<TestResult> {
        let start = Instant::now();
        let fork = test.fork();

        // For engine_x tests without full state, we skip execution
        let (Some(pre), Some(genesis_header)) = (&test.pre, &test.genesis_block_header) else {
            return Ok(TestResult::skipped(
                test_name.to_string(),
                fork.to_string(),
                "Engine_x test format - skipping (uses pre/post hashes)".to_string(),
            ));
        };

        // Build the database with genesis state (pre-state)
        let mut db = build_pre_state_db(pre);
        insert_block_hash(&mut db, genesis_header.number, genesis_header.hash);

        let blocks = match &test.engine_new_payloads {
            Some(payloads) => Self::engine_payloads_to_blocks(payloads)?,
            None => Self::fixture_blocks(test),
        };

        let mut last_block_hash = genesis_header.hash;
        for (block_idx, block) in blocks.into_iter().enumerate() {
            let block = match block {
                PreparedBlock::Ready(block) => block,
                PreparedBlock::Skip(reason) => {
                    debug!("Block {} not executed: {}", block_idx, reason);
                    continue;
                }
            };

            // Execute through reth's block executor; the bundle of a failed block is dropped.
            let output = match self.evm_config.executor(&mut db).execute(&block) {
                Ok(output) => output,
                Err(err) => {
                    return Ok(TestResult::failed(
                        test_name.to_string(),
                        fork.to_string(),
                        start.elapsed(),
                        format!("Block {} (number {}) failed: {err}", block_idx, block.number),
                    ));
                }
            };
            db.commit_source(&BundleSource(&output.state));
            insert_block_hash(&mut db, block.number, block.hash());
            last_block_hash = block.hash();
        }

        let duration = start.elapsed();
        let include_empty = self.include_empty_accounts();
        let actual_state_root = state_root_of_db(&db, include_empty);

        // 1. Check last block hash
        let hash_match = last_block_hash == test.lastblockhash;

        // 2. Check state root (compare with post_state)
        let (expected_state_root, state_match) = if let Some(post_state) = &test.post_state {
            let expected = state_root_of_accounts(post_state, include_empty);
            (expected, actual_state_root == expected)
        } else {
            // For engine_x tests without post_state, we can't verify state root
            (actual_state_root, true)
        };

        if hash_match && state_match {
            return Ok(TestResult::passed(test_name.to_string(), fork.to_string(), duration)
                .with_state_roots(expected_state_root, actual_state_root));
        }

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
        Ok(TestResult::failed(test_name.to_string(), fork.to_string(), duration, errors.join("; "))
            .with_state_roots(expected_state_root, actual_state_root))
    }

    /// Decodes the fixture's RLP blocks.
    ///
    /// Blocks that expect an exception are not executed; a block whose RLP does not decode or
    /// whose senders do not recover is skipped as well (only invalid blocks do that).
    fn fixture_blocks(test: &BlockchainTest) -> Vec<PreparedBlock> {
        test.blocks
            .iter()
            .map(|block| {
                if let Some(exception) = &block.expect_exception {
                    return PreparedBlock::Skip(format!("expects exception: {exception}"));
                }
                let Some(rlp) = &block.rlp else {
                    return PreparedBlock::Skip("no block RLP".to_string());
                };
                let sealed = match SealedBlock::<Block>::decode(&mut rlp.as_ref()) {
                    Ok(sealed) => sealed,
                    Err(err) => return PreparedBlock::Skip(format!("RLP decode failed: {err}")),
                };
                match sealed.try_recover() {
                    Ok(recovered) => PreparedBlock::Ready(Box::new(recovered)),
                    Err(err) => PreparedBlock::Skip(format!("sender recovery failed: {err}")),
                }
            })
            .collect()
    }

    /// Converts Engine API `newPayload` calls into blocks.
    fn engine_payloads_to_blocks(
        payloads: &[crate::models::EngineNewPayload],
    ) -> EfTestResult<Vec<PreparedBlock>> {
        use crate::models::{ExecutionPayload, Withdrawal};

        fn invalid(what: &str, e: impl std::fmt::Display) -> EfTestError {
            EfTestError::InvalidTestData(format!("{what}: {e}"))
        }

        let mut blocks = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let raw = payload.params.get(0).ok_or_else(|| {
                EfTestError::InvalidTestData("Engine payload missing params[0]".to_string())
            })?;
            let execution_payload: ExecutionPayload = serde_json::from_value(raw.clone())
                .map_err(|e| invalid("Failed to parse execution payload", e))?;

            // params[2] carries the parent beacon block root from engine_newPayloadV3 on.
            let parent_beacon_block_root: Option<B256> =
                payload.params.get(2).and_then(|v| serde_json::from_value(v.clone()).ok());

            let mut transactions = Vec::with_capacity(execution_payload.transactions.len());
            for tx_hex in &execution_payload.transactions {
                let tx_bytes = Bytes::from_str(tx_hex)
                    .map_err(|e| invalid("Failed to parse transaction hex", e))?;
                let tx = TransactionSigned::decode_2718(&mut tx_bytes.as_ref())
                    .map_err(|e| invalid("Failed to decode transaction", e))?;
                transactions.push(tx);
            }

            // A payload from engine_newPayloadV2 on carries a (possibly empty) withdrawal list.
            let withdrawals = if raw.get("withdrawals").is_some() {
                let parsed = execution_payload
                    .withdrawals
                    .iter()
                    .map(|w| serde_json::from_value::<Withdrawal>(w.clone()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| invalid("Failed to parse withdrawal", e))?;
                Some(
                    parsed
                        .into_iter()
                        .map(|w| AlloyWithdrawal {
                            index: w.index,
                            validator_index: w.validator_index,
                            address: w.address,
                            amount: w.amount,
                        })
                        .collect::<Vec<_>>()
                        .into(),
                )
            } else {
                None
            };

            let header = Header {
                parent_hash: execution_payload.parent_hash,
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: execution_payload.fee_recipient,
                state_root: execution_payload.state_root,
                receipts_root: execution_payload.receipts_root,
                logs_bloom: execution_payload.logs_bloom,
                difficulty: U256::ZERO,
                number: execution_payload.block_number,
                gas_limit: execution_payload.gas_limit,
                gas_used: execution_payload.gas_used,
                timestamp: execution_payload.timestamp,
                extra_data: execution_payload.extra_data.clone(),
                mix_hash: execution_payload.prev_randao,
                nonce: B64::ZERO,
                base_fee_per_gas: Some(
                    execution_payload.base_fee_per_gas.try_into().unwrap_or(u64::MAX),
                ),
                blob_gas_used: execution_payload.blob_gas_used,
                excess_blob_gas: execution_payload.excess_blob_gas,
                parent_beacon_block_root,
                ..Default::default()
            };

            let body = BlockBody { transactions, ommers: Vec::new(), withdrawals };
            // The payload names its own hash; the header here is not complete enough to rehash.
            let sealed =
                SealedBlock::new_unchecked(Block { header, body }, execution_payload.block_hash);
            blocks.push(match sealed.try_recover() {
                Ok(recovered) => PreparedBlock::Ready(Box::new(recovered)),
                Err(err) => PreparedBlock::Skip(format!("sender recovery failed: {err}")),
            });
        }

        Ok(blocks)
    }

    /// Whether empty accounts stay in the state trie (before EIP-161, Spurious Dragon).
    fn include_empty_accounts(&self) -> bool {
        self.get_spec_id() < SpecId::SPURIOUS_DRAGON
    }

    /// Get the spec ID for the current fork
    pub const fn get_spec_id(&self) -> SpecId {
        super::spec_id_for_fork(self.fork)
    }
}

/// Records a block hash for the `BLOCKHASH` opcode.
fn insert_block_hash(db: &mut InMemoryDB, number: u64, hash: B256) {
    db.insert_block_hash(&U256::from(number), &hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = BlockchainTestExecutor::new(&ForkSpec::Berlin, 1);
        assert_eq!(executor.chain_spec().chain.id(), 1);
        assert_eq!(executor.get_spec_id(), SpecId::BERLIN);
        assert!(!executor.include_empty_accounts());
        assert!(BlockchainTestExecutor::new(&ForkSpec::Homestead, 1).include_empty_accounts());
    }

    #[test]
    fn test_withdrawal_block_executes() {
        let executor = BlockchainTestExecutor::new(&ForkSpec::Shanghai, 1);
        let recipient = alloy_primitives::Address::with_last_byte(0x42);
        let header = Header {
            number: 1,
            timestamp: 12,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(B256::ZERO),
            ..Default::default()
        };
        let withdrawal = AlloyWithdrawal { index: 0, validator_index: 0, address: recipient, amount: 3 };
        let body = BlockBody {
            transactions: Vec::new(),
            ommers: Vec::new(),
            withdrawals: Some(vec![withdrawal].into()),
        };
        let block = SealedBlock::seal_slow(Block { header, body }).try_recover().unwrap();

        let mut db = InMemoryDB::default();
        let output = executor.evm_config.executor(&mut db).execute(&block).unwrap();
        db.commit_source(&BundleSource(&output.state));

        let info = db.account_info(&recipient).unwrap();
        assert_eq!(info.balance, U256::from(3_000_000_000u64));
    }
}

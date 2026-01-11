//! Blockchain test model for EF tests

use super::{
    deserialize_b256, deserialize_b256_opt, deserialize_bytes, deserialize_u256,
    deserialize_u256_opt, deserialize_u64, deserialize_u64_opt, Account, Header,
};
use crate::models::transaction::BlockTransaction;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// A complete blockchain test fixture file contains multiple test cases
pub type BlockchainTestFile = HashMap<String, BlockchainTest>;

/// A single blockchain test case
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockchainTest {
    /// Network/fork name
    pub network: String,

    /// Genesis block header
    pub genesis_block_header: GenesisBlockHeader,

    /// Pre-state accounts
    #[serde(deserialize_with = "deserialize_accounts")]
    pub pre: HashMap<Address, Account>,

    /// Expected post-state accounts
    #[serde(deserialize_with = "deserialize_accounts")]
    pub post_state: HashMap<Address, Account>,

    /// Expected last block hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub lastblockhash: B256,

    /// Chain configuration
    #[serde(default)]
    pub config: Option<BlockchainTestConfig>,

    /// Genesis RLP
    #[serde(deserialize_with = "deserialize_bytes")]
    pub genesis_rlp: Bytes,

    /// Blocks to execute
    pub blocks: Vec<Block>,

    /// Seal engine type
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_engine: Option<String>,

    /// Test info/metadata
    #[serde(rename = "_info", default)]
    pub info: Option<BlockchainTestInfo>,
}

/// Genesis block header
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisBlockHeader {
    /// Parent block hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub parent_hash: B256,

    /// Ommers/uncles hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub uncle_hash: B256,

    /// Beneficiary/coinbase address
    #[serde(deserialize_with = "deserialize_address")]
    pub coinbase: Address,

    /// State root
    #[serde(deserialize_with = "deserialize_b256")]
    pub state_root: B256,

    /// Transactions trie root
    #[serde(deserialize_with = "deserialize_b256")]
    pub transactions_trie: B256,

    /// Receipts trie root
    #[serde(deserialize_with = "deserialize_b256")]
    pub receipt_trie: B256,

    /// Logs bloom filter
    #[serde(deserialize_with = "deserialize_bloom")]
    pub bloom: Bloom,

    /// Block difficulty
    #[serde(deserialize_with = "deserialize_u256")]
    pub difficulty: U256,

    /// Block number
    #[serde(deserialize_with = "deserialize_u64")]
    pub number: u64,

    /// Gas limit
    #[serde(deserialize_with = "deserialize_u64")]
    pub gas_limit: u64,

    /// Gas used
    #[serde(deserialize_with = "deserialize_u64")]
    pub gas_used: u64,

    /// Block timestamp
    #[serde(deserialize_with = "deserialize_u64")]
    pub timestamp: u64,

    /// Extra data
    #[serde(deserialize_with = "deserialize_bytes")]
    pub extra_data: Bytes,

    /// Mix hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub mix_hash: B256,

    /// Nonce
    #[serde(deserialize_with = "deserialize_b64")]
    pub nonce: B64,

    /// Block hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub hash: B256,

    /// Base fee per gas (EIP-1559)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub base_fee_per_gas: Option<U256>,

    /// Withdrawals root (Shanghai)
    #[serde(
        default,
        deserialize_with = "deserialize_b256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub withdrawals_root: Option<B256>,

    /// Blob gas used (Cancun)
    #[serde(
        default,
        deserialize_with = "deserialize_u64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub blob_gas_used: Option<u64>,

    /// Excess blob gas (Cancun)
    #[serde(
        default,
        deserialize_with = "deserialize_u64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub excess_blob_gas: Option<u64>,

    /// Parent beacon block root (Cancun)
    #[serde(
        default,
        deserialize_with = "deserialize_b256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_beacon_block_root: Option<B256>,
}

/// A block in a blockchain test
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    /// Block header
    pub block_header: Option<Header>,

    /// Transactions in the block
    #[serde(default)]
    pub transactions: Vec<BlockTransaction>,

    /// Uncle headers
    #[serde(default)]
    pub uncle_headers: Vec<Header>,

    /// Withdrawals (Shanghai+)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Vec<Withdrawal>>,

    /// Block RLP
    #[serde(default, deserialize_with = "deserialize_bytes_opt")]
    pub rlp: Option<Bytes>,

    /// Expected exception (for invalid blocks)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_exception: Option<String>,
}

/// Withdrawal (Shanghai+)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    /// Withdrawal index
    #[serde(deserialize_with = "deserialize_u64")]
    pub index: u64,

    /// Validator index
    #[serde(deserialize_with = "deserialize_u64")]
    pub validator_index: u64,

    /// Withdrawal address
    #[serde(deserialize_with = "deserialize_address")]
    pub address: Address,

    /// Withdrawal amount (in Gwei)
    #[serde(deserialize_with = "deserialize_u64")]
    pub amount: u64,
}

/// Blockchain test configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockchainTestConfig {
    /// Network name
    #[serde(default)]
    pub network: Option<String>,

    /// Chain ID
    #[serde(
        default,
        deserialize_with = "deserialize_u64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub chainid: Option<u64>,
}

/// Blockchain test metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockchainTestInfo {
    /// Test hash
    #[serde(default)]
    pub hash: Option<String>,

    /// Comment/description
    #[serde(default)]
    pub comment: Option<String>,

    /// Filling tool version
    #[serde(rename = "filling-transition-tool", default)]
    pub filling_tool: Option<String>,

    /// Test description
    #[serde(default)]
    pub description: Option<String>,

    /// Source URL
    #[serde(default)]
    pub url: Option<String>,

    /// Fixture format
    #[serde(rename = "fixture-format", default)]
    pub fixture_format: Option<String>,
}

/// Deserialize an address from hex string
fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Address::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize bloom filter from hex string
fn deserialize_bloom<'de, D>(deserializer: D) -> Result<Bloom, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Bloom::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize B64 from hex string
fn deserialize_b64<'de, D>(deserializer: D) -> Result<B64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    B64::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize accounts map
fn deserialize_accounts<'de, D>(deserializer: D) -> Result<HashMap<Address, Account>, D::Error>
where
    D: Deserializer<'de>,
{
    let map: HashMap<String, Account> = Deserialize::deserialize(deserializer)?;
    map.into_iter()
        .map(|(k, v)| {
            let addr = Address::from_str(&k).map_err(serde::de::Error::custom)?;
            Ok((addr, v))
        })
        .collect()
}

/// Deserialize optional bytes
fn deserialize_bytes_opt<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) => Bytes::from_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

impl BlockchainTest {
    /// Get the chain ID for this test
    pub fn chain_id(&self) -> u64 {
        self.config
            .as_ref()
            .and_then(|c| c.chainid)
            .unwrap_or(1)
    }

    /// Get the fork name
    pub fn fork(&self) -> &str {
        &self.network
    }

    /// Get the number of blocks
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Check if any block is expected to be invalid
    pub fn has_invalid_blocks(&self) -> bool {
        self.blocks.iter().any(|b| b.expect_exception.is_some())
    }
}

impl Block {
    /// Check if this block is expected to be invalid
    pub fn is_invalid(&self) -> bool {
        self.expect_exception.is_some()
    }

    /// Check if this block has withdrawals
    pub fn has_withdrawals(&self) -> bool {
        self.withdrawals.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_genesis_header() {
        let json = r#"{
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "stateRoot": "0x823373b8ca7365c1632ce3b96302d1b84f693b1c11e5c3bb45a105b3a7ddf0f6",
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
            "hash": "0x0ed8738c93005f9a22e18a49ebf36a5f4fd2d4e51446d23ab0f6b6326baacda5"
        }"#;

        let header: GenesisBlockHeader = serde_json::from_str(json).unwrap();
        assert_eq!(header.number, 0);
        assert_eq!(header.gas_limit, 0x07270e00);
    }

    #[test]
    fn test_deserialize_withdrawal() {
        let json = r#"{
            "index": "0x00",
            "validatorIndex": "0x01",
            "address": "0x1234567890123456789012345678901234567890",
            "amount": "0x64"
        }"#;

        let withdrawal: Withdrawal = serde_json::from_str(json).unwrap();
        assert_eq!(withdrawal.index, 0);
        assert_eq!(withdrawal.validator_index, 1);
        assert_eq!(withdrawal.amount, 100);
    }
}

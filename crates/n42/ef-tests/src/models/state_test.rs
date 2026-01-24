//! State test model for EF tests

use super::{
    deserialize_b256, deserialize_bytes, deserialize_u256, deserialize_u256_opt, deserialize_u64,
    Account, Transaction,
};
use alloy_primitives::{Address, Bytes, B256, U256};
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// A complete state test fixture file contains multiple test cases
pub type StateTestFile = HashMap<String, StateTest>;

/// A single state test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTest {
    /// Test environment (block context)
    pub env: Environment,

    /// Pre-state accounts
    #[serde(deserialize_with = "deserialize_accounts")]
    pub pre: HashMap<Address, Account>,

    /// Transaction to execute
    pub transaction: Transaction,

    /// Expected post-state per fork
    pub post: HashMap<String, Vec<PostStateResult>>,

    /// Chain configuration
    #[serde(default)]
    pub config: Option<TestConfig>,

    /// Test info/metadata
    #[serde(rename = "_info", default)]
    pub info: Option<TestInfo>,
}

/// Test environment/block context
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    /// Block coinbase/beneficiary
    #[serde(deserialize_with = "deserialize_address")]
    pub current_coinbase: Address,

    /// Block gas limit
    #[serde(deserialize_with = "deserialize_u64")]
    pub current_gas_limit: u64,

    /// Block number
    #[serde(deserialize_with = "deserialize_u64")]
    pub current_number: u64,

    /// Block timestamp
    #[serde(deserialize_with = "deserialize_u64")]
    pub current_timestamp: u64,

    /// Block difficulty (PoW) or prev_randao (PoS)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_difficulty: Option<U256>,

    /// Block random/prev_randao (PoS)
    #[serde(
        default,
        deserialize_with = "deserialize_b256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_random: Option<B256>,

    /// Base fee per gas (EIP-1559)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_base_fee: Option<U256>,

    /// Excess blob gas (EIP-4844)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_excess_blob_gas: Option<U256>,

    /// Blob gas used (EIP-4844)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_blob_gas_used: Option<U256>,

    /// Parent beacon block root (EIP-4788)
    #[serde(
        default,
        deserialize_with = "deserialize_b256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_beacon_block_root: Option<B256>,
}

/// Expected result for a specific fork
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostStateResult {
    /// Expected state root hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub hash: B256,

    /// Expected logs hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub logs: B256,

    /// Serialized transaction bytes
    #[serde(deserialize_with = "deserialize_bytes")]
    pub txbytes: Bytes,

    /// Indexes into transaction arrays (data, gas, value)
    pub indexes: StateTestIndexes,

    /// Expected account states (optional, for detailed validation)
    #[serde(default, deserialize_with = "deserialize_accounts_opt")]
    pub state: Option<HashMap<Address, Account>>,

    /// Exception expected (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_exception: Option<String>,
}

/// Indexes for multi-variant transaction testing
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StateTestIndexes {
    /// Index into transaction.data array
    pub data: usize,

    /// Index into transaction.gas_limit array
    pub gas: usize,

    /// Index into transaction.value array
    pub value: usize,
}

/// Test configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestConfig {
    /// Chain ID
    #[serde(
        default,
        deserialize_with = "deserialize_u64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub chainid: Option<u64>,
}

/// Test metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestInfo {
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

/// Deserialize B256 with optional handling
fn deserialize_b256_opt<'de, D>(deserializer: D) -> Result<Option<B256>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) => B256::from_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Deserialize u64 with optional handling
fn deserialize_u64_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            u64::from_str_radix(s, 16)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        None => Ok(None),
    }
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

/// Deserialize optional accounts map
fn deserialize_accounts_opt<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<Address, Account>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<HashMap<String, Account>> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(map) => {
            let result: Result<HashMap<Address, Account>, _> = map
                .into_iter()
                .map(|(k, v)| {
                    let addr = Address::from_str(&k).map_err(serde::de::Error::custom)?;
                    Ok((addr, v))
                })
                .collect();
            result.map(Some)
        }
        None => Ok(None),
    }
}

impl StateTest {
    /// Get the chain ID for this test
    pub fn chain_id(&self) -> u64 {
        self.config
            .as_ref()
            .and_then(|c| c.chainid)
            .unwrap_or(1)
    }

    /// Get all forks that this test supports
    pub fn forks(&self) -> Vec<&str> {
        self.post.keys().map(|s| s.as_str()).collect()
    }

    /// Get post-state results for a specific fork
    pub fn post_for_fork(&self, fork: &str) -> Option<&Vec<PostStateResult>> {
        self.post.get(fork)
    }

    /// Get the number of test variants for a specific fork
    pub fn variant_count(&self, fork: &str) -> usize {
        self.post_for_fork(fork).map(|v| v.len()).unwrap_or(0)
    }
}

impl Environment {
    /// Get difficulty as U256
    pub fn difficulty(&self) -> U256 {
        self.current_difficulty.unwrap_or_default()
    }

    /// Get base fee as u64
    pub fn base_fee(&self) -> u64 {
        self.current_base_fee
            .map(|b| b.try_into().unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    /// Get prev_randao/random value
    pub fn prev_randao(&self) -> B256 {
        self.current_random.unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_environment() {
        let json = r#"{
            "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "currentGasLimit": "0x07270e00",
            "currentNumber": "0x01",
            "currentTimestamp": "0x03e8",
            "currentDifficulty": "0x020000"
        }"#;

        let env: Environment = serde_json::from_str(json).unwrap();
        assert_eq!(env.current_number, 1);
        assert_eq!(env.current_timestamp, 1000);
    }

    #[test]
    fn test_deserialize_post_state_result() {
        let json = r#"{
            "hash": "0x586a7a7dc500b9ca0ee53ee4d2f36a3e8c34d07483be0c2854cc768774c74491",
            "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "txbytes": "0xf860800a830186a0945e4bad14480e006938dd30373936e0d7f92ad063808026a071a29ce7d01640cfc246b13e39600c95bb935ad4363439e8a3effe2d74ce93a7a06d692e4f80a487bcc7eb7d30cef75e475160c14b9e80037e023532d091770a73",
            "indexes": {
                "data": 0,
                "gas": 0,
                "value": 0
            }
        }"#;

        let result: PostStateResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.indexes.data, 0);
        assert_eq!(result.indexes.gas, 0);
        assert_eq!(result.indexes.value, 0);
    }
}

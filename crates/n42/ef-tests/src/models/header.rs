//! Block header model for EF tests

use super::{deserialize_b256, deserialize_b256_opt, deserialize_bytes, deserialize_u256, deserialize_u256_opt, deserialize_u64, deserialize_u64_opt};
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// Block header as it appears in blockchain tests
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
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

    /// Mix hash (PoW) / prev_randao (PoS)
    #[serde(deserialize_with = "deserialize_b256")]
    pub mix_hash: B256,

    /// Nonce (PoW)
    #[serde(deserialize_with = "deserialize_b64")]
    pub nonce: B64,

    /// Block hash
    #[serde(deserialize_with = "deserialize_b256")]
    pub hash: B256,

    /// Base fee per gas (EIP-1559)
    #[serde(default, deserialize_with = "deserialize_u256_opt", skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,

    /// Withdrawals root (Shanghai)
    #[serde(default, deserialize_with = "deserialize_b256_opt", skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<B256>,

    /// Blob gas used (EIP-4844)
    #[serde(default, deserialize_with = "deserialize_u64_opt", skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<u64>,

    /// Excess blob gas (EIP-4844)
    #[serde(default, deserialize_with = "deserialize_u64_opt", skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<u64>,

    /// Parent beacon block root (EIP-4788)
    #[serde(default, deserialize_with = "deserialize_b256_opt", skip_serializing_if = "Option::is_none")]
    pub parent_beacon_block_root: Option<B256>,

    /// Requests root (EIP-7685)
    #[serde(default, deserialize_with = "deserialize_b256_opt", skip_serializing_if = "Option::is_none")]
    pub requests_root: Option<B256>,
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

impl Header {
    /// Get the base fee per gas, returning 0 if not present
    pub fn base_fee(&self) -> u64 {
        self.base_fee_per_gas
            .map(|b| b.try_into().unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    /// Check if this is a post-merge (PoS) block
    pub fn is_pos(&self) -> bool {
        // Post-merge blocks have difficulty = 0
        self.difficulty.is_zero()
    }

    /// Check if this block has EIP-1559 (London+)
    pub fn has_eip1559(&self) -> bool {
        self.base_fee_per_gas.is_some()
    }

    /// Check if this block has withdrawals (Shanghai+)
    pub fn has_withdrawals(&self) -> bool {
        self.withdrawals_root.is_some()
    }

    /// Check if this block has blob transactions (Cancun+)
    pub fn has_blobs(&self) -> bool {
        self.blob_gas_used.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_header() {
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

        let header: Header = serde_json::from_str(json).unwrap();
        assert_eq!(header.number, 0);
        assert!(!header.is_pos());
        assert!(!header.has_eip1559());
    }
}

//! Account model for EF tests

use super::{deserialize_bytes, deserialize_u256, deserialize_u64};
use alloy_primitives::{Bytes, B256, U256};
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// Represents an Ethereum account in EF test fixtures
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    /// Account nonce
    #[serde(deserialize_with = "deserialize_u64")]
    pub nonce: u64,

    /// Account balance
    #[serde(deserialize_with = "deserialize_u256")]
    pub balance: U256,

    /// Account bytecode
    #[serde(deserialize_with = "deserialize_bytes")]
    pub code: Bytes,

    /// Account storage
    #[serde(deserialize_with = "deserialize_storage")]
    pub storage: HashMap<U256, U256>,
}

impl Account {
    /// Create a new empty account
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an account with only a balance
    pub fn with_balance(balance: U256) -> Self {
        Self {
            balance,
            ..Default::default()
        }
    }

    /// Check if the account is empty (no code, zero balance, zero nonce)
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance.is_zero() && self.code.is_empty()
    }

    /// Get the code hash for this account
    pub fn code_hash(&self) -> B256 {
        if self.code.is_empty() {
            alloy_primitives::keccak256([])
        } else {
            alloy_primitives::keccak256(&self.code)
        }
    }
}

/// Deserialize storage from a map of hex strings
fn deserialize_storage<'de, D>(deserializer: D) -> Result<HashMap<U256, U256>, D::Error>
where
    D: Deserializer<'de>,
{
    let map: HashMap<String, String> = Deserialize::deserialize(deserializer)?;
    map.into_iter()
        .map(|(k, v)| {
            let key = U256::from_str(&k).map_err(serde::de::Error::custom)?;
            let value = U256::from_str(&v).map_err(serde::de::Error::custom)?;
            Ok((key, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_account() {
        let json = r#"{
            "nonce": "0x01",
            "balance": "0x3635c9adc5dea00000",
            "code": "0x600160005260206000f3",
            "storage": {
                "0x01": "0x02"
            }
        }"#;

        let account: Account = serde_json::from_str(json).unwrap();
        assert_eq!(account.nonce, 1);
        assert!(!account.balance.is_zero());
        assert!(!account.code.is_empty());
        assert_eq!(account.storage.len(), 1);
    }

    #[test]
    fn test_empty_account() {
        let json = r#"{
            "nonce": "0x00",
            "balance": "0x00",
            "code": "0x",
            "storage": {}
        }"#;

        let account: Account = serde_json::from_str(json).unwrap();
        assert!(account.is_empty());
    }
}

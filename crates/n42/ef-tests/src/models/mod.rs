//! Data models for parsing EF test fixtures
//!
//! This module contains all the data structures needed to parse and represent
//! Ethereum Foundation test fixtures, including state tests and blockchain tests.

mod account;
mod blockchain_test;
mod header;
mod state_test;
pub mod transaction;
mod transaction_test;

pub use account::Account;
pub use blockchain_test::{Block, BlockchainTest, EngineNewPayload, ExecutionPayload, GenesisBlockHeader, Withdrawal};
pub use header::Header;
pub use state_test::{Environment, PostStateResult, StateTest, StateTestIndexes};
pub use transaction::{AccessListItem, Authorization, BlockTransaction, Transaction};
pub use transaction_test::{TransactionTest, TransactionTestResult};

use alloy_primitives::{Bytes, B256, U256};
use serde::{Deserialize, Deserializer};
use std::str::FromStr;

/// Deserialize a hex string into U256
pub fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    U256::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize a hex string into U256, with optional default
pub fn deserialize_u256_opt<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) => U256::from_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Deserialize a hex string into u64
pub fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

/// Deserialize a hex string into u64, with optional default
pub fn deserialize_u64_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
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

/// Deserialize a hex string into B256
pub fn deserialize_b256<'de, D>(deserializer: D) -> Result<B256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    B256::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize a hex string into B256, with optional default
pub fn deserialize_b256_opt<'de, D>(deserializer: D) -> Result<Option<B256>, D::Error>
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

/// Deserialize a hex string into Bytes
pub fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Bytes::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize a hex string into Bytes, with optional default
pub fn deserialize_bytes_opt<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
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

/// Deserialize a vector of hex strings into Vec<Bytes>
pub fn deserialize_bytes_vec<'de, D>(deserializer: D) -> Result<Vec<Bytes>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<String> = Deserialize::deserialize(deserializer)?;
    vec.into_iter()
        .map(|s| Bytes::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Deserialize a vector of hex strings into Vec<U256>
pub fn deserialize_u256_vec<'de, D>(deserializer: D) -> Result<Vec<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<String> = Deserialize::deserialize(deserializer)?;
    vec.into_iter()
        .map(|s| U256::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Deserialize a vector of hex strings into Vec<u64>
pub fn deserialize_u64_vec<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<String> = Deserialize::deserialize(deserializer)?;
    vec.into_iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
        })
        .collect()
}

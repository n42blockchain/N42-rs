//! Transaction model for EF tests

use super::{
    deserialize_b256, deserialize_b256_opt, deserialize_bytes, deserialize_bytes_opt,
    deserialize_bytes_vec, deserialize_u256, deserialize_u256_opt, deserialize_u256_vec,
    deserialize_u64, deserialize_u64_opt, deserialize_u64_vec,
};
use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// Transaction in state test format (with arrays for multi-variant testing)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// Transaction nonce
    #[serde(deserialize_with = "deserialize_u64")]
    pub nonce: u64,

    /// Gas price (for legacy transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub gas_price: Option<U256>,

    /// Max fee per gas (for EIP-1559 transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_per_gas: Option<U256>,

    /// Max priority fee per gas (for EIP-1559 transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_priority_fee_per_gas: Option<U256>,

    /// Gas limit array (for multi-variant testing)
    #[serde(deserialize_with = "deserialize_u64_vec")]
    pub gas_limit: Vec<u64>,

    /// Recipient address (None for contract creation)
    #[serde(default, deserialize_with = "deserialize_address_opt")]
    pub to: Option<Address>,

    /// Transfer value array (for multi-variant testing)
    #[serde(deserialize_with = "deserialize_u256_vec")]
    pub value: Vec<U256>,

    /// Input data array (for multi-variant testing)
    #[serde(deserialize_with = "deserialize_bytes_vec")]
    pub data: Vec<Bytes>,

    /// Sender address
    #[serde(deserialize_with = "deserialize_address")]
    pub sender: Address,

    /// Secret key for signing
    #[serde(deserialize_with = "deserialize_b256")]
    pub secret_key: B256,

    /// Access lists array (for multi-variant testing)
    /// In state tests, this is an array where each element corresponds to a test variant
    #[serde(default, rename = "accessLists", skip_serializing_if = "Option::is_none")]
    pub access_lists: Option<Vec<Vec<AccessListItem>>>,

    /// Legacy access list field (single value, for backward compatibility)
    #[serde(default, rename = "accessList", skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<AccessListItem>>,

    /// Max fee per blob gas (for EIP-4844 transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_per_blob_gas: Option<U256>,

    /// Blob versioned hashes (for EIP-4844 transactions)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_versioned_hashes: Option<Vec<B256>>,
}

/// Transaction in blockchain test format (single values, already signed)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockTransaction {
    /// Transaction type
    #[serde(
        default,
        rename = "type",
        deserialize_with = "deserialize_u64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub tx_type: Option<u64>,

    /// Chain ID
    #[serde(
        default,
        deserialize_with = "deserialize_u64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub chain_id: Option<u64>,

    /// Transaction nonce
    #[serde(deserialize_with = "deserialize_u64")]
    pub nonce: u64,

    /// Gas price (for legacy transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub gas_price: Option<U256>,

    /// Max fee per gas (for EIP-1559 transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_per_gas: Option<U256>,

    /// Max priority fee per gas (for EIP-1559 transactions)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_priority_fee_per_gas: Option<U256>,

    /// Gas limit
    #[serde(deserialize_with = "deserialize_u64")]
    pub gas_limit: u64,

    /// Recipient address (None for contract creation)
    #[serde(default, deserialize_with = "deserialize_address_opt")]
    pub to: Option<Address>,

    /// Transfer value
    #[serde(deserialize_with = "deserialize_u256")]
    pub value: U256,

    /// Input data
    #[serde(deserialize_with = "deserialize_bytes")]
    pub data: Bytes,

    /// Sender address
    #[serde(deserialize_with = "deserialize_address")]
    pub sender: Address,

    /// Signature v value
    #[serde(deserialize_with = "deserialize_u256")]
    pub v: U256,

    /// Signature r value
    #[serde(deserialize_with = "deserialize_u256")]
    pub r: U256,

    /// Signature s value
    #[serde(deserialize_with = "deserialize_u256")]
    pub s: U256,

    /// Access list
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<AccessListItem>>,

    /// Max fee per blob gas (for EIP-4844)
    #[serde(
        default,
        deserialize_with = "deserialize_u256_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_per_blob_gas: Option<U256>,

    /// Blob versioned hashes (for EIP-4844)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_versioned_hashes: Option<Vec<B256>>,
}

/// Access list item for EIP-2930 transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    /// Account address
    #[serde(deserialize_with = "deserialize_address")]
    pub address: Address,

    /// Storage keys
    pub storage_keys: Vec<B256>,
}

/// Deserialize an address from hex string
fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Address::from_str(&s).map_err(serde::de::Error::custom)
}

/// Deserialize an optional address from hex string
fn deserialize_address_opt<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) if s.is_empty() || s == "0x" => Ok(None),
        Some(s) => Address::from_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

impl Transaction {
    /// Get the transaction type based on fields present
    pub fn tx_type(&self) -> u8 {
        if self.blob_versioned_hashes.is_some() {
            3 // EIP-4844
        } else if self.max_fee_per_gas.is_some() {
            2 // EIP-1559
        } else if self.access_list.is_some() || self.access_lists.is_some() {
            1 // EIP-2930
        } else {
            0 // Legacy
        }
    }

    /// Get the access list for a specific variant index
    /// Returns the access list from `accessLists[index]` if available,
    /// otherwise falls back to `accessList` for backward compatibility
    pub fn get_access_list(&self, index: usize) -> Option<&Vec<AccessListItem>> {
        // First try accessLists array (new format)
        if let Some(ref lists) = self.access_lists {
            if index < lists.len() {
                return Some(&lists[index]);
            }
        }
        // Fall back to single accessList (legacy format)
        self.access_list.as_ref()
    }
}

impl BlockTransaction {
    /// Get the transaction type
    pub fn tx_type(&self) -> u8 {
        self.tx_type.unwrap_or(0) as u8
    }

    /// Check if this is a contract creation transaction
    pub fn is_create(&self) -> bool {
        self.to.is_none()
    }

    /// Get the sender address (already included in the JSON)
    pub fn sender(&self) -> crate::error::EfTestResult<Address> {
        Ok(self.sender)
    }

    /// Get the gas price (uses gas_price or max_fee_per_gas for EIP-1559)
    pub fn effective_gas_price(&self) -> U256 {
        self.gas_price
            .or(self.max_fee_per_gas)
            .unwrap_or(U256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_state_transaction() {
        let json = r#"{
            "nonce": "0x00",
            "gasPrice": "0x0a",
            "gasLimit": ["0x0186a0"],
            "to": "0x5e4bad14480e006938dd30373936e0d7f92ad063",
            "value": ["0x00"],
            "data": ["0x"],
            "sender": "0x21e1c3a34d72ca08cb22941cf167d23460b18ad7",
            "secretKey": "0x950cb9a39c0bd00ce126e8c95e4bad14480e006938dd30373936e0d7f92ad063"
        }"#;

        let tx: Transaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.gas_limit.len(), 1);
        assert_eq!(tx.value.len(), 1);
        assert_eq!(tx.data.len(), 1);
        assert!(tx.to.is_some());
    }

    #[test]
    fn test_deserialize_block_transaction() {
        let json = r#"{
            "type": "0x00",
            "chainId": "0x01",
            "nonce": "0x00",
            "gasPrice": "0x0a",
            "gasLimit": "0x0186a0",
            "to": "0x8bdd606002ba768021b49908ffa662c6776575c4",
            "value": "0x00",
            "data": "0x610010600081600b8239f334600014600c5734600055005b6000ff",
            "v": "0x25",
            "r": "0x0d9617a9d2af57ba938b90b031cc1e65af27f590979b6c2815b352c558f62206",
            "s": "0x3dec2263fb70cfb67d95d32a35e26617814c6afcd71a12818524d42e43cd51f6",
            "sender": "0xf8e777dd5900e7f541d204e0cc6e0e1c08c1b9a4"
        }"#;

        let tx: BlockTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.tx_type(), 0);
        assert_eq!(tx.nonce, 0);
        assert!(tx.to.is_some());
    }

    #[test]
    fn test_deserialize_access_lists() {
        let json = r#"{
            "nonce": "0x00",
            "gasPrice": "0x0a",
            "gasLimit": ["0x5208"],
            "to": "0xc3ea744aa6b9f501386aa167ad42f49e3787066f",
            "value": ["0x01"],
            "data": ["0x"],
            "accessLists": [
                [
                    {
                        "address": "0x0000000000000000000000000000000000000000",
                        "storageKeys": []
                    },
                    {
                        "address": "0x0000000000000000000000000000000000000001",
                        "storageKeys": [
                            "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "0x0000000000000000000000000000000000000000000000000000000000000001"
                        ]
                    }
                ]
            ],
            "sender": "0x9015bca99e8d49107c33b2cac14013a8dfd2c1b0",
            "secretKey": "0xa4e7ea6dc542e6de38bf1229c3ea744aa6b9f501386aa167ad42f49e3787066f"
        }"#;

        let tx: Transaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.tx_type(), 1); // EIP-2930

        // Check accessLists was parsed correctly
        let access_list = tx.get_access_list(0);
        assert!(access_list.is_some());
        let al = access_list.unwrap();
        assert_eq!(al.len(), 2);
        assert_eq!(al[0].storage_keys.len(), 0);
        assert_eq!(al[1].storage_keys.len(), 2);
    }

    #[test]
    fn test_deserialize_empty_access_lists() {
        let json = r#"{
            "nonce": "0x00",
            "gasPrice": "0x0a",
            "gasLimit": ["0x5208"],
            "to": "0xc3ea744aa6b9f501386aa167ad42f49e3787066f",
            "value": ["0x01"],
            "data": ["0x"],
            "accessLists": [
                []
            ],
            "sender": "0x9015bca99e8d49107c33b2cac14013a8dfd2c1b0",
            "secretKey": "0xa4e7ea6dc542e6de38bf1229c3ea744aa6b9f501386aa167ad42f49e3787066f"
        }"#;

        let tx: Transaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.tx_type(), 1); // EIP-2930 because accessLists is present

        // Check empty accessLists was parsed correctly
        let access_list = tx.get_access_list(0);
        assert!(access_list.is_some());
        let al = access_list.unwrap();
        assert_eq!(al.len(), 0);
    }
}

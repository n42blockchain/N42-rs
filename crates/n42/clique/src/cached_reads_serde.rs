// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serde for [`CachedReads`], which `reth_evm::cached` (reth v2.9.0) no longer derives.
//!
//! The vendored `reth-revm` used to carry `Serialize`/`Deserialize` on `CachedReads` and
//! `CachedAccount`; reth v2.9.0 deleted that crate and its successor has no serde. This module
//! mirrors the same shape (`accounts`, `contracts`, `block_hashes`; an account is `info` plus
//! `storage`) and is used through `#[serde(with = "...")]`, so `UnverifiedBlock` keeps the
//! upstream type.

use alloy_primitives::{
    map::{AddressMap, B256Map, HashMap, U256Map},
    B256, U256,
};
use evm2::{bytecode::Bytecode, evm::AccountInfo};
use reth_evm::cached::{CachedAccount, CachedReads};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize)]
struct CachedReadsRef<'a> {
    accounts: AddressMap<CachedAccountRef<'a>>,
    contracts: &'a B256Map<Bytecode>,
    block_hashes: &'a HashMap<u64, B256>,
}

#[derive(Serialize)]
struct CachedAccountRef<'a> {
    info: &'a Option<AccountInfo>,
    storage: &'a U256Map<U256>,
}

#[derive(Deserialize)]
struct CachedReadsOwned {
    accounts: AddressMap<CachedAccountOwned>,
    contracts: B256Map<Bytecode>,
    block_hashes: HashMap<u64, B256>,
}

#[derive(Deserialize)]
struct CachedAccountOwned {
    info: Option<AccountInfo>,
    storage: U256Map<U256>,
}

/// Serializes a [`CachedReads`] in the shape the vendored `reth-revm` derived.
pub fn serialize<S: Serializer>(reads: &CachedReads, serializer: S) -> Result<S::Ok, S::Error> {
    CachedReadsRef {
        accounts: reads
            .accounts
            .iter()
            .map(|(address, account)| {
                (*address, CachedAccountRef { info: &account.info, storage: &account.storage })
            })
            .collect(),
        contracts: &reads.contracts,
        block_hashes: &reads.block_hashes,
    }
    .serialize(serializer)
}

/// Deserializes a [`CachedReads`] written by [`serialize`].
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<CachedReads, D::Error> {
    let owned = CachedReadsOwned::deserialize(deserializer)?;
    Ok(CachedReads {
        accounts: owned
            .accounts
            .into_iter()
            .map(|(address, account)| {
                (address, CachedAccount { info: account.info, storage: account.storage })
            })
            .collect(),
        contracts: owned.contracts,
        block_hashes: owned.block_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    #[derive(Serialize, Deserialize)]
    struct Wrap(#[serde(with = "super")] CachedReads);

    #[test]
    fn round_trips_accounts_contracts_and_block_hashes() {
        let mut reads = CachedReads::default();
        let mut storage = U256Map::default();
        storage.insert(U256::from(1), U256::from(2));
        reads.insert_account(
            Address::with_last_byte(7),
            AccountInfo { nonce: 3, balance: U256::from(9), ..Default::default() },
            storage,
        );
        reads.contracts.insert(B256::with_last_byte(1), Bytecode::default());
        reads.block_hashes.insert(5, B256::with_last_byte(5));

        let json = serde_json::to_string(&Wrap(reads.clone())).unwrap();
        let back: Wrap = serde_json::from_str(&json).unwrap();
        let account = &back.0.accounts[&Address::with_last_byte(7)];
        assert_eq!(account.info.as_ref().map(|i| i.nonce), Some(3));
        assert_eq!(account.storage.get(&U256::from(1)), Some(&U256::from(2)));
        assert_eq!(back.0.contracts.len(), 1);
        assert_eq!(back.0.block_hashes.get(&5), Some(&B256::with_last_byte(5)));
    }
}

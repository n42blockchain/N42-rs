// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A genesis allocation as block zero's change set.
//!
//! gov5 reads the plain state the alloc just produced and hands it to the same
//! root computer a block goes through (`internal/genesis_qmdb.go`), so genesis
//! is nothing more special than the first batch of leaves. The root of that
//! batch is what a QMDB chain's genesis header carries.

use std::collections::BTreeMap;

use alloy_genesis::GenesisAccount;
use alloy_primitives::{keccak256, Address, B256, U256};

use crate::{AccountState, BlockChanges};

/// Keccak-256 of empty code, which is what an account without code carries.
const KECCAK_EMPTY: B256 = alloy_primitives::KECCAK256_EMPTY;

/// A genesis allocation entry that is empty under EIP-161 yet carries storage
/// (sync standard Q-S1): nonce 0, zero balance, no code, at least one storage
/// entry. gov5 drops such an account with its storage while
/// [`changes_from_alloc`] would still write the storage leaves, so the two
/// clients would compute different genesis roots. Every client refuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "genesis alloc {0} has storage but nonce 0, zero balance and empty code: the account is \
     empty under EIP-161 and its storage would be dropped; set a nonce, balance or code"
)]
pub struct StorageOnlyAllocEntry(pub Address);

/// Refuses a genesis allocation holding a [`StorageOnlyAllocEntry`].
///
/// The predicate is gov5's `validateGenesisAlloc` (`internal/genesis_block.go`):
/// a storage map with any entry counts, zero-valued entries included, and the
/// check applies to every chain whatever its state scheme. The first offending
/// address in address order is reported.
pub fn validate_alloc(alloc: &BTreeMap<Address, GenesisAccount>) -> Result<(), StorageOnlyAllocEntry> {
    match alloc.iter().find(|(_, account)| is_storage_only(account)) {
        Some((address, _)) => Err(StorageOnlyAllocEntry(*address)),
        None => Ok(()),
    }
}

fn is_storage_only(account: &GenesisAccount) -> bool {
    account.nonce.unwrap_or_default() == 0
        && account.balance.is_zero()
        && account.code.as_ref().is_none_or(|code| code.is_empty())
        && account.storage.as_ref().is_some_and(|storage| !storage.is_empty())
}

/// The leaves a genesis allocation writes.
pub fn changes_from_alloc(alloc: &BTreeMap<Address, GenesisAccount>) -> BlockChanges {
    let mut changes = BlockChanges::new();
    for (address, account) in alloc {
        let code_hash = account
            .code
            .as_ref()
            .filter(|code| !code.is_empty())
            .map_or(KECCAK_EMPTY, keccak256);
        changes.set_account(
            *address,
            AccountState {
                nonce: account.nonce.unwrap_or_default(),
                balance: account.balance,
                code_hash,
            },
        );
        if let Some(storage) = &account.storage {
            for (slot, value) in storage {
                changes.set_storage(*address, *slot, U256::from_be_bytes(value.0));
            }
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alloc_of(json: &str) -> BTreeMap<Address, GenesisAccount> {
        serde_json::from_str(json).expect("an alloc")
    }

    const ADDR: &str = "0xaa00000000000000000000000000000000000000";
    const STORAGE: &str = r#""storage": { "0x01": "0x02" }"#;

    fn entry(fields: &str) -> BTreeMap<Address, GenesisAccount> {
        alloc_of(&format!(r#"{{ "{ADDR}": {{ {fields} }} }}"#))
    }

    /// gov5 `TestValidateGenesisAllocStorageOnly`, case by case.
    #[test]
    fn storage_only_entries_are_refused_and_their_neighbours_accepted() {
        let address: Address = ADDR.parse().unwrap();
        for refused in [
            format!(r#""balance": "0x0", {STORAGE}"#),
            format!(r#""balance": "0x0", "nonce": "0x0", "code": "0x", {STORAGE}"#),
            // A zero-valued slot still counts, as `len(Storage)` does in gov5.
            r#""balance": "0x0", "storage": { "0x01": "0x00" }"#.to_owned(),
        ] {
            let err = validate_alloc(&entry(&refused)).expect_err(&refused);
            assert_eq!(err, StorageOnlyAllocEntry(address));
            assert!(err.to_string().contains(&address.to_string()), "names the address: {err}");
        }
        for accepted in [
            format!(r#""balance": "0x0", "nonce": "0x1", {STORAGE}"#),
            format!(r#""balance": "0x1", {STORAGE}"#),
            format!(r#""balance": "0x0", "code": "0x60", {STORAGE}"#),
            r#""balance": "0x0""#.to_owned(),
            r#""balance": "0x0", "storage": {}"#.to_owned(),
        ] {
            assert_eq!(validate_alloc(&entry(&accepted)), Ok(()), "{accepted}");
        }
    }
}

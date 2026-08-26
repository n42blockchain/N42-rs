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

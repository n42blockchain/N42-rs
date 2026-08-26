// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! From what the execution client produced to what the commitment consumes.
//!
//! The one question this module answers is *which leaves a block writes*, and
//! it has to answer it the way gov5 does, because a QMDB root is a function of
//! every write that happened — a leaf written with its existing value still
//! consumes a slot and still moves the root. So this is not "the state diff";
//! it is gov5's dirty set, reconstructed from revm's bundle.
//!
//! gov5 (`IntraBlockState.computeRootViaComputer`) passes every account in
//! `stateObjectsDirty` — the journal's touched set — to the root computer,
//! copying the whole account whether or not a field changed, and for each of
//! those the slots in `dirtyStorage`, which Erigon only populates for a store
//! whose value differs from the previous one. revm's bundle is the same shape
//! from the other side: [`BundleState::state`] holds exactly the accounts a
//! transaction touched, and a bundle account's storage holds the slots whose
//! present value differs from the original. The mapping is therefore direct,
//! and deliberately does not filter "unchanged" accounts out.
//!
//! What cannot be reconstructed from a bundle is the full pre-block slot set
//! of a self-destructed contract, which gov5 wipes leaf by leaf. Post-EIP-6780
//! a contract can only self-destruct in the transaction that created it, so it
//! has no pre-block slots and the two agree; a chain that re-enables the old
//! semantics would need a storage enumerator here.

use alloy_primitives::B256;
use n42_qmdb_state::{AccountState, BlockChanges};
use revm_database::BundleState;

/// The leaves a block writes, from the bundle its execution left behind.
pub fn changes_from_bundle(bundle: &BundleState) -> BlockChanges {
    let mut changes = BlockChanges::new();
    for (address, account) in &bundle.state {
        match &account.info {
            Some(info) => {
                changes.set_account(
                    *address,
                    AccountState {
                        nonce: info.nonce,
                        balance: info.balance,
                        code_hash: info.code_hash,
                    },
                );
            }
            // Destroyed, or touched while not existing. gov5 deletes in both
            // cases, and deleting an absent leaf is a no-op in both trees.
            None => {
                changes.delete_account(*address);
            }
        }
        for (slot, value) in &account.storage {
            changes.set_storage(
                *address,
                B256::from(slot.to_be_bytes::<32>()),
                value.present_value,
            );
        }
    }
    changes
}

pub use n42_qmdb_state::changes_from_alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_genesis::GenesisAccount;
    use alloy_primitives::{keccak256, Address, U256};
    use std::collections::BTreeMap;

    const KECCAK_EMPTY: B256 = alloy_primitives::KECCAK256_EMPTY;
    use revm_database::states::bundle_state::BundleBuilder;
    use revm_state::AccountInfo;

    const ALICE: Address = Address::with_last_byte(1);
    const BOB: Address = Address::with_last_byte(2);

    fn info(nonce: u64, balance: u64) -> AccountInfo {
        AccountInfo {
            nonce,
            balance: U256::from(balance),
            code_hash: KECCAK_EMPTY,
            code: None,
            ..Default::default()
        }
    }

    /// gov5 writes every touched account, changed or not, and the root moves
    /// either way. Filtering unchanged ones out here would agree with gov5 on
    /// state and disagree with it on the root.
    #[test]
    fn a_touched_but_unchanged_account_is_still_written() {
        let bundle = BundleBuilder::new(0..=0)
            .state_present_account_info(ALICE, info(1, 100))
            .state_original_account_info(ALICE, info(1, 100))
            .build();
        let changes = changes_from_bundle(&bundle);
        assert_eq!(
            changes.accounts.get(&ALICE).copied().flatten(),
            Some(AccountState {
                nonce: 1,
                balance: U256::from(100u64),
                code_hash: KECCAK_EMPTY
            }),
        );
    }

    #[test]
    fn a_destroyed_account_deletes_its_leaf_and_zeroes_its_slots() {
        let bundle = BundleBuilder::new(0..=0)
            .state_original_account_info(BOB, info(3, 7))
            .state_storage(BOB, std::iter::once((U256::from(1u64), (U256::from(9u64), U256::ZERO))).collect())
            .build();
        // No present info: the account is gone.
        let changes = changes_from_bundle(&bundle);
        assert_eq!(changes.accounts.get(&BOB), Some(&None));
        let slots = changes.storage.get(&BOB).expect("its slots are named");
        assert_eq!(slots.get(&B256::with_last_byte(1)), Some(&U256::ZERO));
        // And the operation for that slot is a deletion, not a zero leaf.
        let deletions = changes.operations().iter().filter(|op| op.value.is_none()).count();
        assert_eq!(deletions, 2, "account leaf and slot leaf both deleted");
    }

    #[test]
    fn storage_keys_are_big_endian_slot_numbers() {
        let bundle = BundleBuilder::new(0..=0)
            .state_present_account_info(ALICE, info(1, 1))
            .state_storage(
                ALICE,
                std::iter::once((U256::from(0x1234u64), (U256::ZERO, U256::from(42u64)))).collect(),
            )
            .build();
        let changes = changes_from_bundle(&bundle);
        let mut expected = [0u8; 32];
        expected[30] = 0x12;
        expected[31] = 0x34;
        assert_eq!(
            changes.storage[&ALICE].get(&B256::from(expected)),
            Some(&U256::from(42u64))
        );
    }

    #[test]
    fn a_genesis_alloc_is_block_zero() {
        let mut alloc = BTreeMap::new();
        alloc.insert(
            ALICE,
            GenesisAccount {
                balance: U256::from(1_000u64),
                nonce: Some(5),
                code: Some(alloy_primitives::Bytes::from_static(&[0x60, 0x00])),
                storage: Some([(B256::with_last_byte(1), B256::with_last_byte(9))].into()),
                private_key: None,
            },
        );
        alloc.insert(
            BOB,
            GenesisAccount {
                balance: U256::from(7u64),
                ..Default::default()
            },
        );
        let changes = changes_from_alloc(&alloc);

        let alice = changes.accounts[&ALICE].unwrap();
        assert_eq!(alice.nonce, 5);
        assert_eq!(alice.code_hash, keccak256([0x60, 0x00]));
        assert_eq!(
            changes.storage[&ALICE][&B256::with_last_byte(1)],
            U256::from(9u64)
        );

        let bob = changes.accounts[&BOB].unwrap();
        assert_eq!(bob.nonce, 0);
        assert_eq!(bob.code_hash, KECCAK_EMPTY, "no code means the empty-code hash");
        assert!(!changes.storage.contains_key(&BOB));
    }
}

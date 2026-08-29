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

use alloy_primitives::{address, Address, B256, U256};
use n42_qmdb_state::{AccountState, BlockChanges};
use revm_database::BundleState;

/// The leaves a block writes, from the bundle its execution left behind.
pub fn changes_from_bundle(bundle: &BundleState) -> BlockChanges {
    let mut changes = BlockChanges::new();
    for (address, account) in &bundle.state {
        match &account.info {
            Some(info) => {
                tracing::debug!(
                    target: "n42.qmdb.changes",
                    %address, nonce = info.nonce, balance = %info.balance, code_hash = %info.code_hash,
                    "leaf: account",
                );
                // A bundle account is a state object gov5 would hold, and every
                // state object it holds is `Initialised`: live even when empty.
                changes.set_account_initialised(
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
                tracing::debug!(target: "n42.qmdb.changes", %address, "leaf: account deleted");
                changes.delete_account(*address);
            }
        }
        for (slot, value) in &account.storage {
            tracing::debug!(
                target: "n42.qmdb.changes",
                %address, slot = %B256::from(slot.to_be_bytes::<32>()), value = %value.present_value,
                "leaf: slot",
            );
            changes.set_storage(
                *address,
                B256::from(slot.to_be_bytes::<32>()),
                value.present_value,
            );
        }
    }
    changes
}

/// A storage slot a block changed and then restored to its value at the
/// block's start: `(address, slot, that value)`.
///
/// revm drops such a slot from its bundle (`TransitionAccount::update`: "if
/// new value is same as original value, remove storage entry"), so nothing
/// downstream of execution can see it was written. gov5 writes it — its
/// `BufferedPlainStateWriter` refuses to short-circuit on `original ==
/// value` — and a write to QMDB is an append: a new slot for the key, the
/// old one deactivated, and a different root, for the same value. Chain 94
/// showed the case at block 13,561,251: an ERC-20 balance moved and moved
/// back within the block, gov5's root counted the rewrite, revm's bundle
/// had no trace of it. The executor records these as it goes
/// (`n42_engine_types::evm`), keyed by what both it and the root job know.
pub type RestoredSlot = (Address, U256, U256);

/// The key a block's restored slots are filed under: keccak of the parent
/// hash and the committed transactions' hashes, in order — what the
/// executor knows before the header exists, and what the root job knows
/// from the block.
pub fn restored_slots_key(parent_hash: B256, tx_hashes: impl IntoIterator<Item = B256>) -> B256 {
    let mut preimage = Vec::with_capacity(32 * 64);
    preimage.extend_from_slice(parent_hash.as_slice());
    for hash in tx_hashes {
        preimage.extend_from_slice(hash.as_slice());
    }
    alloy_primitives::keccak256(&preimage)
}

/// Restored slots of recently executed blocks, by key. Bounded: a block is
/// executed and its root computed within moments, but a build that is never
/// used, or a validation that fails before the root, would otherwise leak.
struct RestoredSlotsRegistry {
    slots: std::collections::HashMap<B256, std::sync::Arc<Vec<RestoredSlot>>>,
    order: std::collections::VecDeque<B256>,
}

const RESTORED_SLOTS_KEPT: usize = 512;

static RESTORED_SLOTS: std::sync::Mutex<Option<RestoredSlotsRegistry>> = std::sync::Mutex::new(None);

/// Files a block's restored slots under `key`; an empty list is filed too,
/// so a look-up can tell "none" from "not executed here".
pub fn record_restored_slots(key: B256, slots: Vec<RestoredSlot>) {
    let mut guard = RESTORED_SLOTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let registry = guard.get_or_insert_with(|| RestoredSlotsRegistry {
        slots: std::collections::HashMap::new(),
        order: std::collections::VecDeque::new(),
    });
    if registry.slots.insert(key, std::sync::Arc::new(slots)).is_none() {
        registry.order.push_back(key);
    }
    while registry.order.len() > RESTORED_SLOTS_KEPT {
        if let Some(old) = registry.order.pop_front() {
            registry.slots.remove(&old);
        }
    }
}

/// The restored slots filed under `key`, if the block was executed here.
pub fn restored_slots(key: B256) -> Option<std::sync::Arc<Vec<RestoredSlot>>> {
    let guard = RESTORED_SLOTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_ref()?.slots.get(&key).cloned()
}

/// Adds the rewrites gov5 makes for slots the block changed and restored:
/// a leaf with the value it already had, which QMDB records as a fresh
/// slot. Only for accounts the block leaves alive, and only for slots the
/// bundle does not already write; a zero value is a deletion of a leaf that
/// is not there, which neither side records.
pub fn with_restored_slots(changes: &mut BlockChanges, bundle: &BundleState, restored: &[RestoredSlot]) {
    for (address, slot, original) in restored {
        let Some(account) = bundle.state.get(address) else {
            continue;
        };
        if account.info.is_none() || account.storage.contains_key(slot) || original.is_zero() {
            continue;
        }
        let key = B256::from(slot.to_be_bytes::<32>());
        tracing::debug!(
            target: "n42.qmdb.changes",
            %address, slot = %key, value = %original,
            "leaf: slot rewritten (changed and restored within the block, as gov5 writes it)",
        );
        changes.set_storage(*address, key, *original);
    }
}

/// The leaves a block writes, from its execution, under the rules of the fork
/// it executed in.
///
/// `prague_active` adds the one leaf revm's bundle cannot show: see
/// [`with_prague_system_caller`]. `restored` adds the others: see
/// [`with_restored_slots`].
pub fn changes_from_execution(
    bundle: &BundleState,
    prague_active: bool,
    restored: &[RestoredSlot],
) -> BlockChanges {
    let mut changes = changes_from_bundle(bundle);
    with_restored_slots(&mut changes, bundle, restored);
    if prague_active {
        with_prague_system_caller(&mut changes);
    }
    changes
}

/// `SYSTEM_ADDRESS` (EIP-4788): the caller of every system call.
pub const PRAGUE_SYSTEM_CALLER: Address = address!("fffffffffffffffffffffffffffffffffffffffe");

/// The caller of Prague's end-of-block system calls, as gov5 writes it.
///
/// EIP-7002 and EIP-7251 are executed by calling the request contracts from
/// `SYSTEM_ADDRESS`. Erigon's `SysCallContract` (gov5 `ProcessPragueSystemCalls`)
/// loads that caller as a state object, which puts it in the journal's dirty
/// set, and gov5's root computer writes every dirty account — so every Prague
/// block on a gov5 chain writes `0xffff…fffe` as a live, empty account: nonce
/// 0, balance 0, no code — a one-byte leaf, `[0x00]`, since gov5's
/// `isAccountEmpty` spares an initialised account and `MarshalV2` encodes an
/// empty field bitmap. reth's `SystemCaller` deliberately removes the
/// system address from the state after each call, so it never reaches the
/// bundle. Measured on the devnet: this leaf was the entire difference
/// between the two clients' roots for block 1.
///
/// EIP-4788 and EIP-2935 do not contribute it: gov5 writes those slots
/// directly (`SetState`, `StoreParentBlockHash`) rather than through a call.
pub fn with_prague_system_caller(changes: &mut BlockChanges) {
    changes.set_account_initialised(
        PRAGUE_SYSTEM_CALLER,
        AccountState {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: alloy_primitives::KECCAK256_EMPTY,
        },
    );
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

    #[test]
    fn a_prague_block_writes_the_system_caller_as_an_empty_live_account() {
        let bundle = BundleState::default();
        let without = changes_from_execution(&bundle, false, &[]);
        assert_eq!(without.len(), 0);
        let with = changes_from_execution(&bundle, true, &[]);
        assert_eq!(with.len(), 1);
        // Live and empty, not deleted: gov5's root computer sees a state
        // object, and an object is a leaf.
        assert_eq!(
            with.account(&PRAGUE_SYSTEM_CALLER),
            Some(Some(&AccountState {
                nonce: 0,
                balance: U256::ZERO,
                code_hash: alloy_primitives::KECCAK256_EMPTY,
            }))
        );
        // And it is a leaf, not a deletion: gov5's `[0x00]`.
        let ops = with.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].value.as_deref(), Some(&[0u8][..]));
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
    fn a_slot_changed_and_restored_is_rewritten_as_gov5_writes_it() {
        // ALICE's slot 1 holds 9 in the bundle (revm kept it: it changed);
        // slot 2 was moved and moved back, so the bundle has no trace of it.
        let bundle = BundleBuilder::new(0..=0)
            .state_present_account_info(ALICE, info(1, 100))
            .state_storage(ALICE, std::iter::once((U256::from(1u64), (U256::ZERO, U256::from(9u64)))).collect())
            .build();
        let restored = vec![
            (ALICE, U256::from(2u64), U256::from(7u64)),
            // Already in the bundle: not doubled.
            (ALICE, U256::from(1u64), U256::from(1u64)),
            // Restored to zero: a deletion of nothing, not written.
            (ALICE, U256::from(3u64), U256::ZERO),
            // An account the block does not hold: ignored.
            (BOB, U256::from(2u64), U256::from(7u64)),
        ];
        let plain = changes_from_execution(&bundle, false, &[]);
        let with = changes_from_execution(&bundle, false, &restored);
        assert_eq!(plain.storage[&ALICE].len(), 1);
        assert_eq!(with.storage[&ALICE].len(), 2);
        assert_eq!(with.storage[&ALICE][&B256::with_last_byte(2)], U256::from(7u64));
        assert_eq!(with.storage[&ALICE][&B256::with_last_byte(1)], U256::from(9u64));
        assert!(!with.storage.contains_key(&BOB));
        // The rewrite is a real operation: the roots differ.
        let mut a = n42_twig_core::qmdb_compat::QmdbCompatTree::new();
        let mut b = a.clone();
        a.apply_sorted_ops(plain.operations()).unwrap();
        b.apply_sorted_ops(with.operations()).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn the_registry_files_by_parent_and_transactions_and_forgets_old_blocks() {
        let key = restored_slots_key(B256::repeat_byte(1), [B256::repeat_byte(2), B256::repeat_byte(3)]);
        assert_ne!(key, restored_slots_key(B256::repeat_byte(1), [B256::repeat_byte(3), B256::repeat_byte(2)]));
        assert!(restored_slots(key).is_none());
        record_restored_slots(key, vec![(ALICE, U256::from(1u64), U256::from(2u64))]);
        assert_eq!(restored_slots(key).unwrap().len(), 1);
        record_restored_slots(key, Vec::new());
        assert!(restored_slots(key).unwrap().is_empty());
        for i in 0..RESTORED_SLOTS_KEPT as u64 + 8 {
            record_restored_slots(restored_slots_key(B256::from(U256::from(i)), []), Vec::new());
        }
        assert!(restored_slots(key).is_none(), "evicted after the bound");
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

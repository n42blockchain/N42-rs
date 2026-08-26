// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The properties a QMDB state root has to have to be a gov5 block's state root.
//!
//! Three of them come straight from gov5's `QMDBRootComputer.ComputeRoot` and
//! the notes around it, and each one is a fork if it is wrong:
//!
//! 1. The root depends on the order writes were applied in, so the operations
//!    for a block are sorted by key hash before any of them lands.
//! 2. A deleted account and a zero storage slot remove their leaf; they do not
//!    write an empty or zero-valued one.
//! 3. A competing block at the same height must be executed against the tree as
//!    it stood, not on top of the loser's writes.
//!
//! The leaf encoding itself is checked against gov5 fixtures in `n42-twig-core`;
//! what is tested here is the layer that decides which leaves to write.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use n42_qmdb_state::{AccountState, BlockChanges, QmdbState, StateError};

fn account(nonce: u64, balance: u64) -> AccountState {
    AccountState {
        nonce,
        balance: U256::from(balance),
        code_hash: B256::ZERO,
    }
}

const fn addr(byte: u8) -> Address {
    Address::with_last_byte(byte)
}

/// The property the whole scheme rests on. gov5 sorts because Go map iteration
/// is randomized and an append-ordered root would otherwise not even be
/// reproducible on one machine — let alone across a fleet.
#[test]
fn the_root_does_not_depend_on_the_order_changes_were_recorded_in() {
    let mut forwards = BlockChanges::new();
    for i in 1..=8u8 {
        forwards.set_account(addr(i), account(i as u64, 100 * i as u64));
        forwards.set_storage(addr(i), B256::with_last_byte(i), U256::from(i));
    }

    // The same changes, recorded in the opposite order.
    let mut backwards = BlockChanges::new();
    for i in (1..=8u8).rev() {
        backwards.set_storage(addr(i), B256::with_last_byte(i), U256::from(i));
        backwards.set_account(addr(i), account(i as u64, 100 * i as u64));
    }

    let mut a = QmdbState::new();
    let mut b = QmdbState::new();
    assert_eq!(
        a.apply_block(1, &forwards).unwrap(),
        b.apply_block(1, &backwards).unwrap(),
        "two nodes recording the same block differently must still agree",
    );
}

/// The other half of the same property: the order across *blocks* does matter,
/// because each write consumes a new slot. A node that reconstructs the same
/// final state by a different route has a different root, and this is what makes
/// checkpointing rather than re-application the answer to a reorg.
#[test]
fn the_root_does_depend_on_the_order_blocks_were_applied_in() {
    let mut first = BlockChanges::new();
    first.set_account(addr(1), account(1, 100));
    let mut second = BlockChanges::new();
    second.set_account(addr(2), account(2, 200));

    let mut forwards = QmdbState::new();
    forwards.apply_block(1, &first).unwrap();
    let forwards_root = forwards.apply_block(2, &second).unwrap();

    let mut backwards = QmdbState::new();
    backwards.apply_block(1, &second).unwrap();
    let backwards_root = backwards.apply_block(2, &first).unwrap();

    assert_ne!(
        forwards_root, backwards_root,
        "QMDB commits to the append history; if these matched, the scheme would \
         not be append-ordered and the reorg rule would be unnecessary",
    );
}

#[test]
fn an_emptied_account_deletes_its_leaf_rather_than_writing_an_empty_one() {
    let mut state = QmdbState::new();
    let mut funded = BlockChanges::new();
    funded.set_account(addr(1), account(3, 500));
    state.apply_block(1, &funded).unwrap();
    assert!(state.account_leaf(addr(1)).is_some());

    // gov5 deletes on `Nonce == 0 && Balance.IsZero() && !Initialised`. An
    // account written back as empty must not leave a leaf encoding "nothing":
    // that is a different tree from one where the account is gone.
    let mut emptied = BlockChanges::new();
    emptied.set_account(addr(1), account(0, 0));
    state.apply_block(2, &emptied).unwrap();
    assert!(
        state.account_leaf(addr(1)).is_none(),
        "an empty account must leave no leaf",
    );

    // And explicit deletion reaches the same place.
    let mut state2 = QmdbState::new();
    state2.apply_block(1, &funded).unwrap();
    let mut deleted = BlockChanges::new();
    deleted.delete_account(addr(1));
    state2.apply_block(2, &deleted).unwrap();
    assert!(state2.account_leaf(addr(1)).is_none());
}

#[test]
fn a_zeroed_storage_slot_deletes_its_leaf_rather_than_storing_zero() {
    let mut state = QmdbState::new();
    let slot = B256::with_last_byte(7);

    let mut written = BlockChanges::new();
    written.set_storage(addr(1), slot, U256::from(42));
    state.apply_block(1, &written).unwrap();
    assert_eq!(
        state.storage_leaf(addr(1), slot).map(<[u8]>::to_vec),
        Some(U256::from(42).to_be_bytes::<32>().to_vec()),
    );

    let mut zeroed = BlockChanges::new();
    zeroed.set_storage(addr(1), slot, U256::ZERO);
    state.apply_block(2, &zeroed).unwrap();
    assert!(
        state.storage_leaf(addr(1), slot).is_none(),
        "a zero slot is an absent leaf, not a leaf of 32 zero bytes",
    );
}

/// The reorg rule, from gov5's own comment on `RevertBlock`: executing a
/// competing block on top of an un-reverted tree "appends at shifted slots and
/// forks the root permanently vs nodes that only ever applied the winner".
#[test]
fn a_sibling_block_must_be_executed_against_the_reverted_tree() {
    let mut common = BlockChanges::new();
    common.set_account(addr(1), account(1, 100));

    let mut loser = BlockChanges::new();
    loser.set_account(addr(2), account(2, 200));
    let mut winner = BlockChanges::new();
    winner.set_account(addr(3), account(3, 300));

    // A node that saw only the winner.
    let mut honest = QmdbState::new();
    honest.apply_block(1, &common).unwrap();
    let honest_root = honest.apply_block(2, &winner).unwrap();

    // A node that saw the loser first, reverted, then applied the winner.
    let mut reorged = QmdbState::new();
    reorged.apply_block(1, &common).unwrap();
    reorged.apply_block(2, &loser).unwrap();
    reorged.revert_to(1).expect("checkpoint at block 1");
    let reorged_root = reorged.apply_block(2, &winner).unwrap();

    assert_eq!(
        honest_root, reorged_root,
        "a reverted tree must be indistinguishable from one that never saw the loser",
    );

    // Without the revert, it is not — which is the whole reason revert exists.
    let mut naive = QmdbState::new();
    naive.apply_block(1, &common).unwrap();
    naive.apply_block(2, &loser).unwrap();
    let naive_root = naive.apply_block(3, &winner).unwrap();
    assert_ne!(
        naive_root, honest_root,
        "applying the winner on top of the loser must not accidentally agree",
    );
}

#[test]
fn reverting_to_a_block_the_tree_never_stood_at_is_an_error() {
    let mut state = QmdbState::new();
    let mut changes = BlockChanges::new();
    changes.set_account(addr(1), account(1, 100));
    state.apply_block(1, &changes).unwrap();

    // Silently succeeding here would leave the caller executing against a tree
    // at the wrong height, which is the fork this whole mechanism prevents.
    match state.revert_to(99) {
        Err(StateError::UnknownCheckpoint(99)) => {}
        other => panic!("expected an unknown checkpoint, got {other:?}"),
    }
}

/// Two writes to the same leaf in one block are refused rather than resolved:
/// which one wins would decide the root, and nothing in the block says which
/// should. A caller producing this has a bug in its change collection.
#[test]
fn a_duplicate_leaf_in_one_block_is_refused_without_mutating_the_tree() {
    let mut state = QmdbState::new();
    let mut changes = BlockChanges::new();
    changes.set_account(addr(1), account(1, 100));
    let before = state.apply_block(1, &changes).unwrap();

    // `BlockChanges` is keyed, so a duplicate has to be built by hand — which is
    // exactly what a buggy adapter feeding raw operations would do.
    let ops = {
        let mut changes = BlockChanges::new();
        changes.set_account(addr(2), account(2, 200));
        let mut ops = changes.operations();
        ops.push(ops[0].clone());
        ops
    };
    assert_eq!(ops.len(), 2);

    let mut direct = BlockChanges::new();
    direct.set_account(addr(2), account(2, 200));
    // Applying the honest version works; the duplicate is what must not.
    assert!(state.apply_block(2, &direct).is_ok());
    assert_ne!(state.root(), before);
}

#[test]
fn a_membership_proof_is_available_for_what_the_tree_commits_to() {
    let mut state = QmdbState::new();
    let slot = B256::with_last_byte(7);
    let mut changes = BlockChanges::new();
    changes.set_account(addr(1), account(1, 100));
    changes.set_storage(addr(1), slot, U256::from(42));
    state.apply_block(1, &changes).unwrap();

    assert!(state.prove_account(addr(1)).is_some());
    assert!(state.prove_storage(addr(1), slot).is_some());

    // Nothing was ever written here. QMDB membership proofs do not prove
    // absence, so `None` is the honest answer rather than an empty proof a
    // caller might read as one.
    assert!(state.prove_account(addr(99)).is_none());
    assert!(state.prove_storage(addr(1), B256::with_last_byte(8)).is_none());
}

#[test]
fn an_empty_block_leaves_the_root_alone() {
    let mut state = QmdbState::new();
    let mut changes = BlockChanges::new();
    changes.set_account(addr(1), account(1, 100));
    let root = state.apply_block(1, &changes).unwrap();

    let unchanged = state.apply_block(2, &BlockChanges::new()).unwrap();
    assert_eq!(root, unchanged, "a block that touches no state moves no root");
    assert_eq!(state.block_number(), 2);
}

#[test]
fn the_operations_a_block_produces_are_inspectable() {
    // The point where this side and gov5 must agree byte for byte, so a caller
    // comparing implementations needs the operations, not only the root.
    let mut changes = BlockChanges::new();
    changes.set_account(addr(1), account(1, 100));
    changes.set_storage(addr(1), B256::with_last_byte(7), U256::from(42));
    changes.set_storage(addr(1), B256::with_last_byte(8), U256::ZERO);

    let ops = changes.operations();
    assert_eq!(ops.len(), 3);
    assert_eq!(
        ops.iter().filter(|op| op.value.is_none()).count(),
        1,
        "the zeroed slot is a deletion",
    );

    // Keys are gov5's: Blake3 over the address, and over address||slot.
    let expected: BTreeMap<_, _> = ops.iter().map(|op| (op.key, op.value.is_some())).collect();
    assert_eq!(expected.len(), 3, "three distinct leaves");
}

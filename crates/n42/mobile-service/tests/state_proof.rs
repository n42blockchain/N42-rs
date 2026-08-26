// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A phone checking state against a root it established for itself.
//!
//! This is the chain of trust closing: the `Decide` the node serves carries
//! signatures the phone verifies, those signatures commit to a state root, and
//! the proof is checked against that same root. If the proof verified against
//! anything the server merely asserted, none of it would be worth doing.
//!
//! On a QMDB chain the header's state root *is* the twig-forest root, which is
//! why one tree answers both questions.

use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, U256};
use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
use n42_mobile_service::{dispatch, MobileService, StateProofReport};
use n42_qmdb_state::{AccountState, BlockChanges, QmdbState};
use n42_twig_core::qmdb_compat::{gov5_account_key, gov5_storage_key, QmdbProof};
use serde_json::json;

const ALICE: Address = Address::with_last_byte(1);
const SLOT: B256 = B256::with_last_byte(7);

const fn identity() -> H2V4ChainIdentity {
    H2V4ChainIdentity {
        chain_id: 96,
        genesis_hash: B256::repeat_byte(0x42),
    }
}

/// A node with one block of state applied and a mobile endpoint over it.
fn node() -> (MobileService, B256) {
    let mut state = QmdbState::new();
    let mut changes = BlockChanges::new();
    changes.set_account(
        ALICE,
        AccountState {
            nonce: 3,
            balance: U256::from(1_000u64),
            code_hash: B256::ZERO,
        },
    );
    changes.set_storage(ALICE, SLOT, U256::from(42u64));
    let root = state.apply_block(1, &changes).expect("apply");

    let service =
        MobileService::new(identity(), 1).with_state(Arc::new(Mutex::new(state)));
    (service, root)
}

#[test]
fn a_phone_verifies_an_account_proof_against_the_state_root() {
    let (service, root) = node();

    let report = service.prove(ALICE, None).expect("a proof");
    assert_eq!(report.root, root, "the proof names the root it was cut from");

    let proof = QmdbProof::decode(&report.proof).expect("gov5 v2 proof layout");
    assert!(
        proof.verify_for_key(&root.0, &gov5_account_key(&ALICE.0 .0)),
        "the proof must verify against the state root, which is the header's",
    );
}

#[test]
fn a_phone_verifies_a_storage_proof_the_same_way() {
    let (service, root) = node();

    let report = service.prove(ALICE, Some(SLOT)).expect("a proof");
    let proof = QmdbProof::decode(&report.proof).expect("decode");
    assert!(proof.verify_for_key(&root.0, &gov5_storage_key(&ALICE.0 .0, &SLOT.0)));
    assert_eq!(
        report.value,
        U256::from(42u64).to_be_bytes::<32>().to_vec(),
        "the leaf holds the slot value in gov5's encoding",
    );
}

/// The check that makes a proof worth anything: one cut from a different tree
/// must not verify against this root. Without this, a server could serve any
/// proof at all.
#[test]
fn a_proof_from_another_tree_does_not_verify_against_this_root() {
    let (service, root) = node();

    let mut other = QmdbState::new();
    let mut changes = BlockChanges::new();
    changes.set_account(
        ALICE,
        AccountState {
            nonce: 99,
            balance: U256::from(999_999u64),
            code_hash: B256::ZERO,
        },
    );
    let other_root = other.apply_block(1, &changes).expect("apply");
    assert_ne!(other_root, root);

    let forged = other.prove_account(ALICE).expect("a proof of the lie");
    assert!(
        !forged.verify_for_key(&root.0, &gov5_account_key(&ALICE.0 .0)),
        "a proof of a different state must not check out against this root",
    );
    // And the honest one still does.
    let honest = service.prove(ALICE, None).expect("a proof");
    let honest = QmdbProof::decode(&honest.proof).unwrap();
    assert!(honest.verify_for_key(&root.0, &gov5_account_key(&ALICE.0 .0)));
}

#[test]
fn the_proof_travels_over_the_rpc_surface() {
    let (mut service, root) = node();

    let value = dispatch(
        &mut service,
        "mobile_getProof",
        &json!([ALICE.to_string()]),
    )
    .expect("a result");
    let report: StateProofReport = serde_json::from_value(value).expect("a proof report");
    assert_eq!(report.root, root);

    let with_slot = dispatch(
        &mut service,
        "mobile_getProof",
        &json!([ALICE.to_string(), SLOT.to_string()]),
    )
    .expect("a result");
    let storage: StateProofReport = serde_json::from_value(with_slot).expect("a proof report");
    assert_ne!(storage.key, report.key, "account and slot are different leaves");

    let proof = QmdbProof::decode(&storage.proof).expect("decode");
    assert!(proof.verify_for_key(&root.0, &gov5_storage_key(&ALICE.0 .0, &SLOT.0)));
}

#[test]
fn a_key_with_no_leaf_yields_null_rather_than_an_empty_proof() {
    // QMDB membership proofs do not prove absence. Returning something here
    // would let a caller read "no proof" as "proved not to exist".
    let (mut service, _) = node();
    let unknown = Address::with_last_byte(200);

    assert!(service.prove(unknown, None).is_none());
    assert_eq!(
        dispatch(&mut service, "mobile_getProof", &json!([unknown.to_string()])).unwrap(),
        serde_json::Value::Null,
    );
}

#[test]
fn a_node_without_a_state_tree_says_so_rather_than_inventing_a_proof() {
    let mut service = MobileService::new(identity(), 1);
    assert!(!service.serves_state_proofs());
    assert_eq!(
        dispatch(&mut service, "mobile_getProof", &json!([ALICE.to_string()])).unwrap(),
        serde_json::Value::Null,
    );
}

/// The finality and the proof have to come from the same node's view, or a phone
/// would verify a proof against a root from one block and finality from another.
#[test]
fn finality_and_proofs_are_served_from_the_same_node() {
    let (mut service, root) = node();
    service
        .record_commit(1, B256::repeat_byte(0x11), 1, QuorumCertificate::genesis(), None)
        .expect("record");

    assert!(service.finality().is_some());
    let report = service.prove(ALICE, None).expect("a proof");
    assert_eq!(report.root, root);
}

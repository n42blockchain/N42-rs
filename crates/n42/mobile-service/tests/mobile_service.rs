// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node side of mobile verification, exercised the way phones use it.
//!
//! The properties worth pinning are the ones that involve untrusted input:
//! what happens to a forged receipt, an unregistered verifier, a block the node
//! never committed, and a phone that retries. Getting any of those wrong hands
//! a stranger the ability to void a block's attestation for everyone.

use alloy_primitives::B256;
use n42_h2_primitives::bls::BlsSecretKey;
use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
use n42_mobile_service::{MobileService, SubmitError};
use n42_mobile_verify::{sign_receipt, VerificationReceipt};

const fn identity() -> H2V4ChainIdentity {
    H2V4ChainIdentity {
        chain_id: 96,
        genesis_hash: B256::repeat_byte(0x42),
    }
}

fn phone() -> (BlsSecretKey, [u8; 48]) {
    let key = BlsSecretKey::random().expect("bls keygen");
    let pubkey = key.public_key().to_bytes();
    (key, pubkey)
}

fn receipt(key: &BlsSecretKey, block_hash: B256, root: B256) -> VerificationReceipt {
    sign_receipt(block_hash, 1, root, 0, key)
}

/// A service with one committed block, ready for receipts.
fn service_with_block(threshold: u32, block_hash: B256, root: Option<B256>) -> MobileService {
    let mut service = MobileService::new(identity(), threshold);
    service
        .record_commit(1, block_hash, 1, QuorumCertificate::genesis(), root)
        .expect("recording a commit");
    service
}

/// The proof a phone gets must be the bytes a fleet member would verify, not a
/// summary it has to take on trust. If this were a server-side struct, a
/// compromised node could report any head it liked.
#[test]
fn finality_is_served_as_a_verifiable_decide_envelope() {
    let block_hash = B256::repeat_byte(0x11);
    let service = service_with_block(1, block_hash, None);

    let finality = service.finality().expect("a commit was recorded");
    assert_eq!(finality.view, 1);
    assert_eq!(finality.block_hash, block_hash);

    // It decodes as the v4 envelope a fleet member receives, naming this chain.
    let envelope =
        n42_h2_wire::h2_v4::decode_envelope(&finality.decide_envelope, identity()).unwrap();
    assert!(matches!(
        envelope.message,
        n42_h2_wire::H2Message::Decide(_)
    ));

    // And it is refused for any other chain, so a phone cannot be replayed a
    // proof from a different network.
    let other = H2V4ChainIdentity {
        chain_id: identity().chain_id + 1,
        genesis_hash: identity().genesis_hash,
    };
    assert!(n42_h2_wire::h2_v4::decode_envelope(&finality.decide_envelope, other).is_err());
}

#[test]
fn a_finality_report_survives_json_in_a_form_a_person_can_read() {
    let service = service_with_block(1, B256::repeat_byte(0x11), None);
    let finality = service.finality().unwrap();

    let json = serde_json::to_value(finality).unwrap();
    // Hex, not a decimal byte array: this is pasted between clients and read by
    // operators.
    let envelope = json["decide_envelope"].as_str().expect("hex string");
    assert!(envelope.starts_with("0x"));

    let round_tripped: n42_mobile_service::FinalityReport =
        serde_json::from_value(json).unwrap();
    assert_eq!(&round_tripped, finality);
}

/// The check the whole service turns on. BLS aggregation is all-or-nothing, so
/// a forged signature reaching the aggregate does not cost one vote — it voids
/// the block's attestation for every honest phone that took part.
#[test]
fn a_forged_signature_is_refused_before_it_can_poison_the_aggregate() {
    let block_hash = B256::repeat_byte(0x11);
    let root = B256::repeat_byte(0x22);
    let mut service = service_with_block(1, block_hash, Some(root));

    let (honest_key, honest_pubkey) = phone();
    let (attacker_key, _) = phone();
    service.register_verifier(honest_pubkey);

    // Signed by the attacker, but claiming the honest phone's identity.
    let mut forged = receipt(&attacker_key, block_hash, root);
    forged.verifier_pubkey = honest_pubkey;

    match service.submit_receipt(&forged) {
        Err(SubmitError::InvalidSignature) => {}
        other => panic!("expected the forgery to be refused, got {other:?}"),
    }
    assert!(
        service.attestation(&block_hash).is_none(),
        "a refused receipt must leave no trace in the aggregate",
    );

    // The honest phone's own receipt still works afterwards.
    let good = receipt(&honest_key, block_hash, root);
    let outcome = service.submit_receipt(&good).unwrap();
    assert!(outcome.accepted);
    assert!(outcome.attested);
}

#[test]
fn an_unregistered_verifier_is_refused() {
    let block_hash = B256::repeat_byte(0x11);
    let mut service = service_with_block(1, block_hash, None);
    let (key, _) = phone();

    // A perfectly valid signature from a phone nobody registered. Its index is
    // what an attestation bitfield refers to, so there is nowhere to put it.
    match service.submit_receipt(&receipt(&key, block_hash, B256::repeat_byte(0x22))) {
        Err(SubmitError::UnknownVerifier) => {}
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn a_receipt_for_a_block_this_node_never_committed_is_refused() {
    let mut service = service_with_block(1, B256::repeat_byte(0x11), None);
    let (key, pubkey) = phone();
    service.register_verifier(pubkey);

    let stranger = B256::repeat_byte(0x99);
    // Unbounded acceptance here is how a stranger fills the node's memory.
    match service.submit_receipt(&receipt(&key, stranger, B256::repeat_byte(0x22))) {
        Err(SubmitError::UnknownBlock(hash)) => assert_eq!(hash, stranger),
        other => panic!("expected refusal, got {other:?}"),
    }
    assert_eq!(service.tracked_blocks(), 1);
}

/// A phone on a flaky link retries. That is not an attack and must not read as
/// a failure — but it must not be counted twice either.
#[test]
fn a_retried_receipt_is_not_an_error_and_is_not_counted_twice() {
    let block_hash = B256::repeat_byte(0x11);
    let root = B256::repeat_byte(0x22);
    let mut service = service_with_block(3, block_hash, Some(root));

    let (key, pubkey) = phone();
    service.register_verifier(pubkey);
    let receipt = receipt(&key, block_hash, root);

    let first = service.submit_receipt(&receipt).unwrap();
    assert!(first.accepted);
    assert_eq!(first.valid_receipts, 1);

    let again = service.submit_receipt(&receipt).unwrap();
    assert!(!again.accepted, "a retry is a duplicate, not a new receipt");
    assert_eq!(again.valid_receipts, 1, "and must not be counted twice");
}

/// The aggregate is derived on demand, so a phone that reports late still
/// strengthens it. Freezing it at the threshold would throw those away.
#[test]
fn late_receipts_still_strengthen_an_already_attested_block() {
    let block_hash = B256::repeat_byte(0x11);
    let root = B256::repeat_byte(0x22);
    let mut service = service_with_block(1, block_hash, Some(root));

    let (first_key, first_pubkey) = phone();
    let (second_key, second_pubkey) = phone();
    service.register_verifier(first_pubkey);
    service.register_verifier(second_pubkey);

    let outcome = service
        .submit_receipt(&receipt(&first_key, block_hash, root))
        .unwrap();
    assert!(outcome.attested, "threshold of 1 is met by one receipt");
    let early = service.attestation(&block_hash).expect("an aggregate exists");
    assert_eq!(early.participant_count, 1);

    service
        .submit_receipt(&receipt(&second_key, block_hash, root))
        .unwrap();
    let late = service.attestation(&block_hash).expect("still there");
    assert_eq!(late.participant_count, 2);

    // And the stronger aggregate verifies against the registry, which is the
    // only thing a third party needs.
    late.verify(service.registry()).expect("aggregate verifies");
}

#[test]
fn an_attestation_verifies_for_a_multi_phone_block() {
    let block_hash = B256::repeat_byte(0x11);
    let root = B256::repeat_byte(0x22);
    let mut service = service_with_block(3, block_hash, Some(root));

    for _ in 0..4 {
        let (key, pubkey) = phone();
        service.register_verifier(pubkey);
        service
            .submit_receipt(&receipt(&key, block_hash, root))
            .unwrap();
    }

    let attestation = service.attestation(&block_hash).expect("an aggregate");
    assert_eq!(attestation.participant_count, 4);
    attestation
        .verify(service.registry())
        .expect("four phones aggregate to a valid attestation");
}

#[test]
fn a_block_with_no_receipts_has_no_attestation() {
    // An empty aggregate is not a weak attestation — it is no attestation, and
    // returning something for it would let a caller mistake silence for assent.
    let block_hash = B256::repeat_byte(0x11);
    let service = service_with_block(1, block_hash, None);
    assert!(service.attestation(&block_hash).is_none());
}

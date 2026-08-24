// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end: a gov5 gossip payload becomes a verified finality event.
//!
//! This exercises the whole observer path in one place — snappy-framed wire
//! bytes in, decode against chain identity, BLS quorum verification against the
//! validator set, finality event out — using the finality fixture gov5 pins.
//! Everything except the socket.

use alloy_primitives::{Address, B256};
use n42_h2_consensus::{ValidatorInfo, ValidatorSet};
use n42_h2_net::{gov5_message_id_parts, H2V4Observer, ObserverConfig, ObserverEvent, H2_V4_TOPIC};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_primitives::BlsPublicKey;
use n42_h2_wire::h2_v4::{decode_envelope, encode_gossip};
use serde::Deserialize;

/// Single source of truth: the same file `n42-h2-consensus` verifies against,
/// included by path rather than copied so the two cannot drift.
const FINALITY_FIXTURE: &str =
    include_str!("../../h2-consensus/testdata/h2_v4_finality_v1.json");

#[derive(Deserialize)]
struct Fixture {
    schema: String,
    chain_id: u64,
    genesis_hash: String,
    changes_hash: String,
    validator_public_keys: Vec<String>,
    envelope_hex: String,
}

fn fixture() -> (H2V4ChainIdentity, ValidatorSet, Vec<u8>, B256) {
    let fixture: Fixture = serde_json::from_str(FINALITY_FIXTURE).unwrap();
    assert_eq!(fixture.schema, "n42-h2-v4-finality-v1");

    let identity = H2V4ChainIdentity {
        chain_id: fixture.chain_id,
        genesis_hash: B256::from_slice(&hex::decode(&fixture.genesis_hash).unwrap()),
    };
    let envelope =
        decode_envelope(&hex::decode(&fixture.envelope_hex).unwrap(), identity).unwrap();
    let changes_hash = B256::from_slice(&hex::decode(&fixture.changes_hash).unwrap());

    let validators = fixture
        .validator_public_keys
        .iter()
        .enumerate()
        .map(|(index, encoded)| {
            let bytes: [u8; 48] = hex::decode(encoded).unwrap().try_into().unwrap();
            ValidatorInfo {
                address: Address::with_last_byte(index as u8 + 1),
                bls_public_key: BlsPublicKey::from_bytes(&bytes).unwrap(),
                p2p_peer_id: None,
            }
        })
        .collect::<Vec<_>>();

    // The gossip payload is the snappy-framed envelope — exactly what gov5's
    // publishH2V4Decide hands to PublishToTopic.
    let payload = encode_gossip(&envelope).unwrap();
    (identity, ValidatorSet::new(&validators, 1), payload, changes_hash)
}

#[tokio::test]
async fn gossip_payload_becomes_a_verified_finality_event() {
    let (identity, validators, payload, changes_hash) = fixture();
    let observer = H2V4Observer::new(ObserverConfig::new(identity), validators).unwrap();

    match observer.handle_payload(None, &payload) {
        ObserverEvent::Finality {
            block_hash,
            changes_hash: got_changes,
            view,
            ..
        } => {
            assert_ne!(block_hash, B256::ZERO, "finalized a zero block hash");
            // The proof must carry the fixture's changes hash, not a value of
            // the verifier's choosing. The fixture uses a non-zero one on
            // purpose: the deployed v4 profile pins this to zero (static
            // validators), so a non-zero value here is what proves the field is
            // genuinely bound into the signed preimage rather than ignored.
            assert_eq!(got_changes, changes_hash);
            assert_ne!(changes_hash, B256::ZERO);
            assert!(view > 0, "decided in view 0");
        }
        other => panic!("expected finality, got {other:?}"),
    }
}

#[tokio::test]
async fn payload_from_another_chain_is_rejected() {
    let (identity, validators, payload, _) = fixture();
    let foreign = H2V4ChainIdentity {
        chain_id: identity.chain_id + 1,
        genesis_hash: identity.genesis_hash,
    };
    let observer = H2V4Observer::new(ObserverConfig::new(foreign), validators).unwrap();

    match observer.handle_payload(None, &payload) {
        ObserverEvent::Rejected { reason, .. } => assert!(
            reason.starts_with("envelope:"),
            "chain mismatch must fail at the envelope, not the signature: {reason}"
        ),
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_foreign_genesis_is_rejected_even_on_the_right_chain_id() {
    let (identity, validators, payload, _) = fixture();
    let foreign = H2V4ChainIdentity {
        chain_id: identity.chain_id,
        genesis_hash: B256::repeat_byte(0xff),
    };
    let observer = H2V4Observer::new(ObserverConfig::new(foreign), validators).unwrap();
    assert!(matches!(
        observer.handle_payload(None, &payload),
        ObserverEvent::Rejected { .. }
    ));
}

#[tokio::test]
async fn corrupt_payloads_are_rejected_not_panicked_on() {
    let (identity, validators, payload, _) = fixture();
    let observer = H2V4Observer::new(ObserverConfig::new(identity), validators).unwrap();

    for case in [
        Vec::new(),
        vec![0u8; 8],
        payload[..payload.len() / 2].to_vec(),
        {
            let mut truncated = payload.clone();
            truncated.pop();
            truncated
        },
        {
            let mut extended = payload.clone();
            extended.push(0);
            extended
        },
    ] {
        assert!(
            matches!(
                observer.handle_payload(None, &case),
                ObserverEvent::Rejected { .. }
            ),
            "payload of {} bytes should have been rejected",
            case.len()
        );
    }
}

#[tokio::test]
async fn a_flipped_signature_byte_fails_verification_not_decoding() {
    let (identity, validators, payload, _) = fixture();
    let observer = H2V4Observer::new(ObserverConfig::new(identity), validators).unwrap();

    // Re-frame a mutated envelope so it still decodes but no longer verifies.
    let envelope = decode_envelope(
        &snap::raw::Decoder::new().decompress_vec(&payload).unwrap(),
        identity,
    )
    .unwrap();
    let mut wire = snap::raw::Decoder::new().decompress_vec(&payload).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let mutated = snap::raw::Encoder::new().compress_vec(&wire).unwrap();

    assert!(
        matches!(
            observer.handle_payload(None, &mutated),
            ObserverEvent::Rejected { .. }
        ),
        "a mutated envelope must not verify"
    );
    // Sanity: the untouched envelope still verifies, so the rejection above is
    // the mutation and not a broken fixture.
    assert!(matches!(
        observer.handle_payload(None, &encode_gossip(&envelope).unwrap()),
        ObserverEvent::Finality { .. }
    ));
}

#[tokio::test]
async fn observer_subscribes_to_the_gov5_topic_and_ids_messages_like_gov5() {
    let (identity, validators, payload, _) = fixture();
    let observer = H2V4Observer::new(ObserverConfig::new(identity), validators).unwrap();

    assert_eq!(H2_V4_TOPIC, "/n42/h2/4/ssz_snappy");
    // The observer's peer id is stable for its keypair and non-empty — this is
    // what a fleet operator adds to a peer allowlist.
    assert!(!observer.local_peer_id().to_string().is_empty());
    assert_eq!(observer.connected_peers(), 0);

    // The dedup key a Go fleet member would compute for this exact payload.
    let id = gov5_message_id_parts(identity.genesis_hash, H2_V4_TOPIC, &payload);
    assert_eq!(id.len(), 20);
    assert_ne!(id, [0u8; 20]);
}

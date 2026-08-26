// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The send half of the transport, against a real mesh.
//!
//! `gossip_loopback.rs` proves the observer accepts a gov5-shaped publisher.
//! This proves the reverse direction — that what `H2V4Transport::publish` puts
//! on the wire is accepted as a valid finality proof by a peer that did not
//! send it. That is the property a participating node needs and an observer
//! never exercises: without it a Rust validator can vote into the void and look
//! healthy doing it.
//!
//! The envelope is gov5's own cross-client fixture, so a pass here means the
//! bytes this node emits are the bytes a Go fleet member verifies.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use libp2p::Multiaddr;
use n42_h2_consensus::{ValidatorInfo, ValidatorSet};
use n42_h2_net::{
    H2V4Observer, H2V4Transport, ObserverConfig, ObserverEvent, PublishError, TransportConfig,
    TransportEvent,
};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_primitives::BlsPublicKey;
use n42_h2_wire::h2_v4::{decode_envelope, H2V4Envelope};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    chain_id: u64,
    genesis_hash: String,
    validator_public_keys: Vec<String>,
    envelope_hex: String,
}

fn fixture() -> (H2V4ChainIdentity, ValidatorSet, H2V4Envelope) {
    let f: Fixture = serde_json::from_str(include_str!(
        "../../h2-consensus/testdata/h2_v4_finality_v1.json"
    ))
    .unwrap();
    let identity = H2V4ChainIdentity {
        chain_id: f.chain_id,
        genesis_hash: B256::from_slice(&hex::decode(&f.genesis_hash).unwrap()),
    };
    let envelope = decode_envelope(&hex::decode(&f.envelope_hex).unwrap(), identity).unwrap();
    let validators = f
        .validator_public_keys
        .iter()
        .enumerate()
        .map(|(i, k)| ValidatorInfo {
            address: Address::with_last_byte(i as u8 + 1),
            bls_public_key: BlsPublicKey::from_bytes(
                &<[u8; 48]>::try_from(hex::decode(k).unwrap()).unwrap(),
            )
            .unwrap(),
            p2p_peer_id: None,
        })
        .collect::<Vec<_>>();
    (identity, ValidatorSet::new(&validators, 1), envelope)
}

#[tokio::test]
async fn published_envelope_verifies_as_finality_at_a_peer() {
    let (identity, validators, envelope) = fixture();
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    // The observer listens; the publishing transport dials it.
    let mut observer = H2V4Observer::new(
        ObserverConfig::new(identity).with_listen_addr(loopback),
        validators,
    )
    .unwrap();
    let observer_peer = *observer.local_peer_id();

    let listen_addr = loop {
        match observer.next_event().await {
            Some(ObserverEvent::Listening(addr)) => break addr,
            Some(_) => continue,
            None => panic!("observer swarm ended before listening"),
        }
    };

    let mut publisher = H2V4Transport::new(
        TransportConfig::new(identity)
            .with_peer(listen_addr.with(libp2p::multiaddr::Protocol::P2p(observer_peer))),
    )
    .unwrap();

    // gossipsub refuses to publish until a mesh peer exists, and meshing takes
    // a few heartbeats after the connection comes up, so retry rather than
    // sending once and hoping.
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut publish_tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                event = observer.next_event() => {
                    if let Some(ObserverEvent::Finality { from, view, block_hash, .. }) = event {
                        return (from, view, block_hash);
                    }
                }
                _ = publisher.next_event() => {}
                _ = publish_tick.tick() => {
                    if let Err(err) = publisher.publish(&envelope) {
                        // Duplicate means an earlier attempt already went out —
                        // gossipsub dedupes by message id, and the observer has
                        // it either way.
                        let expected = err.is_transient()
                            || matches!(
                                err,
                                PublishError::Gossipsub(
                                    libp2p::gossipsub::PublishError::Duplicate
                                )
                            );
                        assert!(expected, "publish failed for a non-transient reason: {err}");
                    }
                }
            }
        }
    })
    .await;

    let (from, view, block_hash) = outcome.expect("no finality observed within 30s");
    assert!(view > 0);
    assert_ne!(block_hash, B256::ZERO);
    // Anonymous publishing must not carry a source peer id: gov5 runs
    // StrictNoSign + NoAuthor and would reject an authored message.
    assert!(from.is_none(), "published message carried authorship");
}

#[tokio::test]
async fn publishing_to_the_wrong_chain_is_refused_before_it_reaches_the_wire() {
    let (identity, _, envelope) = fixture();
    let other_chain = H2V4ChainIdentity {
        chain_id: identity.chain_id + 1,
        genesis_hash: identity.genesis_hash,
    };

    let mut transport = H2V4Transport::new(TransportConfig::new(other_chain)).unwrap();

    // The envelope is well-formed and would encode fine; it is refused because
    // it names a chain this transport is not on. Letting it through would emit
    // a message that every recipient silently drops.
    match transport.publish(&envelope) {
        Err(PublishError::IdentityMismatch) => {}
        other => panic!("expected IdentityMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn publishing_with_no_peers_is_reported_as_transient() {
    let (identity, _, envelope) = fixture();
    let mut transport = H2V4Transport::new(TransportConfig::new(identity)).unwrap();

    // A validator that starts before its fleet does hits this on every send.
    // It has to be distinguishable from a permanent failure, or the node either
    // gives up on a recoverable condition or retries one forever.
    match transport.publish(&envelope) {
        Err(err) => assert!(err.is_transient(), "expected a transient error, got {err}"),
        Ok(_) => panic!("publish succeeded with no mesh peers"),
    }
    assert_eq!(transport.mesh_size(), 0);
}

#[tokio::test]
async fn transport_hands_up_non_decide_envelopes_without_judging_them() {
    let (identity, _, envelope) = fixture();
    let transport = H2V4Transport::new(TransportConfig::new(identity)).unwrap();

    let payload = n42_h2_wire::h2_v4::encode_gossip(&envelope).unwrap();
    match transport.decode_payload(None, &payload) {
        TransportEvent::Envelope { envelope: decoded, .. } => {
            assert_eq!(*decoded, envelope);
        }
        other => panic!("expected an envelope, got {other:?}"),
    }

    // Chain binding is the one judgement this layer does make.
    let wrong_chain = H2V4Transport::new(TransportConfig::new(H2V4ChainIdentity {
        chain_id: identity.chain_id + 1,
        genesis_hash: identity.genesis_hash,
    }))
    .unwrap();
    match wrong_chain.decode_payload(None, &payload) {
        TransportEvent::Rejected { .. } => {}
        other => panic!("expected rejection on chain mismatch, got {other:?}"),
    }
}

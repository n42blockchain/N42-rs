// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two nodes, a real socket, one finality proof.
//!
//! `observer_finality.rs` covers decode-and-verify with the payload handed
//! straight to the observer. This test puts the payload through an actual
//! gossipsub mesh built with gov5's router parameters, so it also exercises the
//! parts that only fail on the wire: anonymous message validation (gov5 runs
//! StrictNoSign + NoAuthor, and a signed message would be rejected), the
//! transmit-size cap, and topic hashing.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use futures::StreamExt;
use libp2p::gossipsub::{self, MessageAuthenticity};
use libp2p::{Multiaddr, SwarmBuilder};
use n42_h2_consensus::{ValidatorInfo, ValidatorSet};
use n42_h2_net::config::gov5_gossipsub_config;
use n42_h2_net::topic::h2_v4_topic;
use n42_h2_net::{H2V4Observer, ObserverConfig, ObserverEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_primitives::BlsPublicKey;
use n42_h2_wire::h2_v4::{decode_envelope, encode_gossip};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    chain_id: u64,
    genesis_hash: String,
    validator_public_keys: Vec<String>,
    envelope_hex: String,
}

fn fixture() -> (H2V4ChainIdentity, ValidatorSet, Vec<u8>) {
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
    (
        identity,
        ValidatorSet::new(&validators, 1),
        encode_gossip(&envelope).unwrap(),
    )
}

/// A minimal publisher standing in for a gov5 fleet member.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct PublisherBehaviour {
    gossipsub: gossipsub::Behaviour,
}

#[tokio::test]
async fn observer_verifies_finality_received_over_a_real_gossip_mesh() {
    let (identity, validators, payload) = fixture();

    // The observer listens; the publisher dials it.
    let mut observer = H2V4Observer::new(
        ObserverConfig::new(identity).with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        validators,
    )
    .unwrap();

    let observer_addr: Multiaddr = loop {
        match observer.next_event().await {
            Some(ObserverEvent::Listening(addr)) => break addr,
            Some(_) => continue,
            None => panic!("observer stopped before it listened"),
        }
    };

    let topic = h2_v4_topic();
    let mut publisher = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_key| PublisherBehaviour {
            // Anonymous, exactly as gov5 publishes.
            gossipsub: gossipsub::Behaviour::new(
                MessageAuthenticity::Anonymous,
                gov5_gossipsub_config(identity.genesis_hash).unwrap(),
            )
            .expect("gossipsub behaviour"),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    publisher.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    publisher
        .dial(observer_addr.clone())
        .expect("dial the observer");

    // Drive both sides until the observer reports finality. The publisher
    // retries because gossipsub refuses to publish until a mesh peer exists,
    // and mesh formation is heartbeat-driven.
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut publish_tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                event = observer.next_event() => {
                    match event {
                        Some(ObserverEvent::Finality { view, block_hash, from, .. }) => {
                            return (view, block_hash, from.is_some());
                        }
                        Some(ObserverEvent::Rejected { reason, .. }) => {
                            panic!("observer rejected a genuine proof: {reason}");
                        }
                        Some(_) => {}
                        None => panic!("observer stream ended"),
                    }
                }
                _ = publisher.select_next_some() => {}
                _ = publish_tick.tick() => {
                    // Ignores InsufficientPeers until the mesh forms.
                    let _ = publisher
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), payload.clone());
                }
            }
        }
    })
    .await;

    let (view, block_hash, had_source) = result.expect("no finality within 30s");
    assert!(view > 0);
    assert_ne!(block_hash, B256::ZERO);
    // gov5 publishes with NoAuthor, so gossipsub carries no source peer id.
    // Provenance comes from the BLS quorum in the envelope, not the transport.
    assert!(!had_source, "anonymous publishing must not carry a source");
}

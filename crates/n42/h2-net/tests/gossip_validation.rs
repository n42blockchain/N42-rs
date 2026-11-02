// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit 2026-10 round 3 (R3-N4): GossipSub forwarded every message before
//! this node had looked at it, so a peer's undecodable payload went on to
//! the whole mesh. Messages are now validated first and only what decodes is
//! forwarded. Three members in a line, A - B - C: A publishes garbage beside
//! a genuine proof, and C hears the proof through B and never the garbage.

use std::time::Duration;

use alloy_primitives::B256;
use futures::StreamExt;
use libp2p::gossipsub::{self, MessageAuthenticity};
use libp2p::{Multiaddr, SwarmBuilder};
use n42_h2_net::config::gov5_gossipsub_config;
use n42_h2_net::topic::h2_v4_topic;
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_wire::h2_v4::{decode_envelope, encode_gossip};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    chain_id: u64,
    genesis_hash: String,
    envelope_hex: String,
}

fn fixture() -> (H2V4ChainIdentity, Vec<u8>) {
    let f: Fixture =
        serde_json::from_str(include_str!("../../h2-consensus/testdata/h2_v4_finality_v1.json")).unwrap();
    let identity = H2V4ChainIdentity {
        chain_id: f.chain_id,
        genesis_hash: B256::from_slice(&hex::decode(&f.genesis_hash).unwrap()),
    };
    let envelope = decode_envelope(&hex::decode(&f.envelope_hex).unwrap(), identity).unwrap();
    (identity, encode_gossip(&envelope).unwrap())
}

/// A bare publisher, as a misbehaving member would be.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct PublisherBehaviour {
    gossipsub: gossipsub::Behaviour,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payload_that_does_not_decode_is_not_forwarded() {
    let (identity, payload) = fixture();
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut b = H2V4Transport::new(TransportConfig::new(identity).with_listen_addr(loopback)).unwrap();
    let b_addr = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(TransportEvent::Listening(addr)) = b.next_event().await {
                return addr.with(libp2p::multiaddr::Protocol::P2p(*b.local_peer_id()));
            }
        }
    })
    .await
    .expect("B listens");
    let mut c = H2V4Transport::new(TransportConfig::new(identity).with_peer(b_addr.clone())).unwrap();

    let topic = h2_v4_topic();
    let mut a = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .unwrap()
        .with_behaviour(|_key| PublisherBehaviour {
            gossipsub: gossipsub::Behaviour::new(
                MessageAuthenticity::Anonymous,
                gov5_gossipsub_config(identity.genesis_hash).unwrap(),
            )
            .expect("gossipsub behaviour"),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    a.dial(b_addr).expect("A dials B");

    let (mut b_rejected, mut c_rejected, mut c_heard_proof) = (0u32, 0u32, false);
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    let mut garbage = 0u32;
    let mut after_proof = 0u32;
    let outcome = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            tokio::select! {
                event = b.next_event() => {
                    if let Some(TransportEvent::Rejected { .. }) = event {
                        b_rejected += 1;
                    }
                }
                event = c.next_event() => match event {
                    Some(TransportEvent::Rejected { reason, .. }) => {
                        c_rejected += 1;
                        panic!("C was forwarded a payload B could not decode: {reason}");
                    }
                    Some(TransportEvent::Envelope { .. }) => c_heard_proof = true,
                    _ => {}
                },
                _ = a.select_next_some() => {}
                _ = tick.tick() => {
                    garbage += 1;
                    let _ = a.behaviour_mut().gossipsub.publish(topic.clone(), format!("garbage-{garbage}").into_bytes());
                    let _ = a.behaviour_mut().gossipsub.publish(topic.clone(), payload.clone());
                    if c_heard_proof && b_rejected > 0 {
                        after_proof += 1;
                        // A few more rounds of garbage after the path is
                        // proven to carry what does decode.
                        if after_proof > 5 {
                            return;
                        }
                    }
                }
            }
        }
    })
    .await;
    outcome.expect("C heard the proof through B within 45 s");
    assert!(b_rejected > 0, "B saw the garbage");
    assert_eq!(c_rejected, 0);
}

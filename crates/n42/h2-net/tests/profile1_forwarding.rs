// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! AM36 on the wire: three members in a line, A - B - C, on a profile-1
//! chain. A publishes on the HotStuff topic, each tick, junk bytes, a vote
//! with an out-of-range view, a vote for a view below B's latest commit QC,
//! and a current vote. B rejects the first two and ignores the stale one,
//! yet still hands the stale vote to its engine (AM34 item 6); C hears only
//! the current votes.

use std::time::Duration;

use alloy_primitives::B256;
use futures::StreamExt;
use libp2p::gossipsub::{self, MessageAuthenticity};
use libp2p::{Multiaddr, SwarmBuilder};
use n42_h2_net::config::gov5_gossipsub_config;
use n42_h2_net::topic::fork_scoped_topic;
use n42_h2_net::{H2V4Transport, HeaderProfile, Profile1Gossip, TransportConfig, TransportEvent};
use n42_h2_primitives::bls::BlsSecretKey;
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_wire::h2_wire::{encode_gov5_gossip_message, H2Message, H2Vote};

const IDENTITY: H2V4ChainIdentity = H2V4ChainIdentity { chain_id: 4242, genesis_hash: B256::repeat_byte(0x5a) };
const VALIDATORS: usize = 4;
const COMMIT_VIEW: u64 = 10;
const STALE_VIEW: u64 = 5;
const CURRENT_VIEW: u64 = 20;

#[derive(libp2p::swarm::NetworkBehaviour)]
struct PublisherBehaviour {
    gossipsub: gossipsub::Behaviour,
}

fn vote(view: u64, nonce: u32) -> Vec<u8> {
    let key = BlsSecretKey::from_bytes(&[9; 32]).unwrap();
    let message = H2Message::Vote(H2Vote {
        view,
        block_hash: B256::left_padding_from(&nonce.to_be_bytes()),
        voter: 1,
        signature: key.sign(&nonce.to_be_bytes()),
        high_tc: None,
    });
    encode_gov5_gossip_message(&message).unwrap()
}

fn view_of(event: &TransportEvent) -> Option<u64> {
    match event {
        TransportEvent::Native { message, .. } => match message.as_ref() {
            H2Message::Vote(v) => Some(v.view),
            _ => None,
        },
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn junk_is_not_relayed_and_a_stale_vote_reaches_the_engine_only() {
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let profile1 = || Profile1Gossip::new(VALIDATORS, HeaderProfile::Gov5H2);
    let mut b =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_profile1(profile1())).unwrap();
    b.commit_view_hint().expect("a profile-1 transport has a hint").raise(COMMIT_VIEW);
    let b_addr = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(TransportEvent::Listening(addr)) = b.next_event().await {
                return addr.with(libp2p::multiaddr::Protocol::P2p(*b.local_peer_id()));
            }
        }
    })
    .await
    .expect("B listens");
    // C knows no commit yet: anything stale that reached it would be accepted.
    let mut c =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_peer(b_addr.clone()).with_profile1(profile1())).unwrap();

    let topic = fork_scoped_topic(IDENTITY.genesis_hash, "hotstuff_consensus");
    let mut a = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .unwrap()
        .with_behaviour(|_key| PublisherBehaviour {
            gossipsub: gossipsub::Behaviour::new(
                MessageAuthenticity::Anonymous,
                gov5_gossipsub_config(IDENTITY.genesis_hash).unwrap(),
            )
            .expect("gossipsub behaviour"),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    a.dial(b_addr).expect("A dials B");

    let (mut b_rejected, mut b_stale, mut c_current) = (0u32, 0u32, 0u32);
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    let mut nonce = 0u32;
    let mut after = 0u32;
    let outcome = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            tokio::select! {
                event = b.next_event() => match event {
                    Some(TransportEvent::Rejected { .. }) => b_rejected += 1,
                    Some(event) if view_of(&event) == Some(STALE_VIEW) => b_stale += 1,
                    _ => {}
                },
                event = c.next_event() => match event {
                    Some(TransportEvent::Rejected { reason, .. }) => {
                        panic!("C was forwarded a message B rejected: {reason}");
                    }
                    Some(event) => match view_of(&event) {
                        Some(CURRENT_VIEW) => c_current += 1,
                        Some(view) => panic!("C was forwarded a vote for view {view}"),
                        None => {}
                    },
                    None => {}
                },
                _ = a.select_next_some() => {}
                _ = tick.tick() => {
                    nonce += 1;
                    let gossip = &mut a.behaviour_mut().gossipsub;
                    let _ = gossip.publish(topic.clone(), format!("junk-{nonce}").into_bytes());
                    let _ = gossip.publish(topic.clone(), vote(u64::MAX, nonce));
                    let _ = gossip.publish(topic.clone(), vote(STALE_VIEW, nonce));
                    let _ = gossip.publish(topic.clone(), vote(CURRENT_VIEW, nonce));
                    if c_current > 0 && b_stale > 0 && b_rejected > 0 {
                        after += 1;
                        // A few more rounds once the path is proven to carry
                        // what B accepts.
                        if after > 5 {
                            return;
                        }
                    }
                }
            }
        }
    })
    .await;
    outcome.expect("C heard a current vote through B within 45 s");
    assert!(b_rejected >= 2, "B rejected the junk and the 2^64-1 vote");
    assert!(b_stale > 0, "B's engine got the stale vote");
}

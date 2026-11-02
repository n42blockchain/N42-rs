// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's two mobile-verification topics: joined only on request, raw bytes
//! relayed both ways, and the topic strings gov5 builds.

use std::time::Duration;

use alloy_primitives::B256;
use n42_h2_net::{H2V4Transport, MobileTopic, TransportConfig, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

const ID: H2V4ChainIdentity = H2V4ChainIdentity { chain_id: 98, genesis_hash: B256::repeat_byte(0x98) };

async fn listening(transport: &mut H2V4Transport) -> libp2p::Multiaddr {
    loop {
        match transport.next_event().await {
            Some(TransportEvent::Listening(addr)) => {
                return addr.with(libp2p::multiaddr::Protocol::P2p(*transport.local_peer_id()))
            }
            Some(_) => {}
            None => panic!("transport ended before listening"),
        }
    }
}

#[test]
fn topic_strings_match_gov5() {
    // gov5: fmt.Sprintf(p2p.MobilePacketTopicFormat, ToBytes4(genesis)) +
    // the encoder's "/ssz_snappy" suffix (internal/node/node.go).
    let packet = n42_h2_net::topic::fork_scoped_topic(ID.genesis_hash, n42_h2_net::MOBILEVERIFY_PACKET_KIND);
    let registration =
        n42_h2_net::topic::fork_scoped_topic(ID.genesis_hash, n42_h2_net::MOBILEVERIFY_REGISTRATION_KIND);
    assert_eq!(packet.to_string(), "/n42/98989898/mobileverify_packet/ssz_snappy");
    assert_eq!(registration.to_string(), "/n42/98989898/mobileverify_registration/ssz_snappy");
}

#[test]
fn a_transport_off_the_topics_refuses_to_publish_on_them() {
    let mut transport = H2V4Transport::new(TransportConfig::new(ID)).expect("transport");
    assert!(transport.publish_mobile(MobileTopic::Packet, vec![1]).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packets_and_registrations_travel_raw_both_ways() {
    let loopback: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().expect("addr");
    let mut a = H2V4Transport::new(TransportConfig::new(ID).with_listen_addr(loopback).with_mobileverify(true))
        .expect("a");
    let addr = tokio::time::timeout(Duration::from_secs(20), listening(&mut a)).await.expect("listen");
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    // The off-loop pump on one side, so both publish paths are covered.
    let mut b =
        H2V4Transport::with_keypair_off_loop(TransportConfig::new(ID).with_peer(addr).with_mobileverify(true), keypair)
            .expect("b");

    let got = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        let (mut packet_at_a, mut registration_at_b) = (None, None);
        let mut n = 0u32;
        loop {
            tokio::select! {
                event = a.next_event() => {
                    if let Some(TransportEvent::MobilePacket { data, .. }) = event {
                        packet_at_a = Some(data);
                    }
                }
                event = b.next_event() => {
                    if let Some(TransportEvent::MobileRegistration { data, .. }) = event {
                        registration_at_b = Some(data);
                    }
                }
                _ = tick.tick() => {
                    n += 1;
                    let _ = b.publish_mobile(MobileTopic::Packet, format!("N2packet-{n}").into_bytes());
                    let _ = a.publish_mobile(MobileTopic::Registration, format!("reg-{n}").into_bytes());
                }
            }
            if let (Some(p), Some(r)) = (&packet_at_a, &registration_at_b) {
                return (p.clone(), r.clone());
            }
        }
    })
    .await
    .expect("both topics carried a message");
    assert!(got.0.starts_with(b"N2packet-"), "the packet arrives as published, uncompressed");
    assert!(got.1.starts_with(b"reg-"), "the registration arrives as published");
}

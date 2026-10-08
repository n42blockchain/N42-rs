// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The swarm on its own task (`N42_GOSSIP_OFF_LOOP=1`): an off-loop member
//! and an inline one on a real socket, both directions, order kept.

use std::time::Duration;

use alloy_primitives::B256;
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

const ID: H2V4ChainIdentity = H2V4ChainIdentity {
    chain_id: 97,
    genesis_hash: B256::repeat_byte(0x97),
};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_off_loop_member_publishes_and_receives_in_order() {
    let loopback: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().expect("addr");
    let mut inline = H2V4Transport::new(TransportConfig::new(ID).with_listen_addr(loopback)).expect("inline");
    assert!(!inline.is_off_loop());
    let addr = tokio::time::timeout(Duration::from_secs(20), listening(&mut inline)).await.expect("listen");

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let mut off = H2V4Transport::with_keypair_off_loop(TransportConfig::new(ID).with_peer(addr), keypair)
        .expect("off loop");
    assert!(off.is_off_loop());

    // The mesh forms on GossipSub's heartbeat: probe until the inline side
    // hears one, driving both.
    let formed = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        let mut n = 0u32;
        loop {
            tokio::select! {
                event = inline.next_event() => {
                    if let Some(TransportEvent::Transactions { data, .. }) = event {
                        if data.starts_with(b"probe") {
                            return;
                        }
                    }
                }
                _ = off.next_event() => {}
                _ = tick.tick() => {
                    n += 1;
                    let _ = off.publish_transactions(format!("probe-{n}").into_bytes());
                }
            }
        }
    })
    .await;
    assert!(formed.is_ok(), "the mesh did not form");
    assert_eq!(off.connected_peers(), 1);
    assert_eq!(off.connected_peer_ids(), vec![*inline.local_peer_id()]);

    // Outbound, in order.
    const COUNT: usize = 50;
    for i in 0..COUNT {
        off.publish_transactions(format!("seq-{i:03}").into_bytes()).expect("queued");
    }
    let received = tokio::time::timeout(Duration::from_secs(30), async {
        let mut got = Vec::new();
        while got.len() < COUNT {
            tokio::select! {
                event = inline.next_event() => {
                    if let Some(TransportEvent::Transactions { data, .. }) = event {
                        if data.starts_with(b"seq-") {
                            got.push(String::from_utf8(data).expect("utf8"));
                        }
                    }
                }
                _ = off.next_event() => {}
            }
        }
        got
    })
    .await
    .expect("every message arrives");
    let expected: Vec<String> = (0..COUNT).map(|i| format!("seq-{i:03}")).collect();
    assert_eq!(received, expected, "the order is kept");

    // Inbound, in order, through the bounded channel.
    for i in 0..COUNT {
        inline.publish_transactions(format!("back-{i:03}").into_bytes()).expect("published");
    }
    let back = tokio::time::timeout(Duration::from_secs(30), async {
        let mut got = Vec::new();
        while got.len() < COUNT {
            tokio::select! {
                event = off.next_event() => {
                    if let Some(TransportEvent::Transactions { data, .. }) = event {
                        if data.starts_with(b"back-") {
                            got.push(String::from_utf8(data).expect("utf8"));
                        }
                    }
                }
                _ = inline.next_event() => {}
            }
        }
        got
    })
    .await
    .expect("every message comes back");
    let expected: Vec<String> = (0..COUNT).map(|i| format!("back-{i:03}")).collect();
    assert_eq!(back, expected);

    let (queue_max, poll_us) = off.take_loop_stats();
    assert!(queue_max >= 1, "something was queued");
    assert!(poll_us > 0, "the task polled the swarm");
    assert_eq!(inline.take_loop_stats(), (0, 0), "inline: the caller times its own polls");
}

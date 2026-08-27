// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's fetch-on-miss over a real connection: one transport asks another
//! for a block by hash and gets the body, or gov5's "not found".

use std::time::Duration;

use alloy_primitives::B256;
use libp2p::Multiaddr;
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

const IDENTITY: H2V4ChainIdentity = H2V4ChainIdentity {
    chain_id: 1143,
    genesis_hash: B256::repeat_byte(0x42),
};

async fn listening(transport: &mut H2V4Transport) -> Multiaddr {
    loop {
        match transport.next_event().await {
            Some(TransportEvent::Listening(addr)) => {
                return addr.with(libp2p::multiaddr::Protocol::P2p(*transport.local_peer_id()));
            }
            Some(_) => {}
            None => panic!("transport ended before listening"),
        }
    }
}

#[tokio::test]
async fn a_peer_gets_the_body_it_asks_for_or_gov5s_not_found() {
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone())).unwrap();
    let server_addr = listening(&mut server).await;
    let mut client =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_peer(server_addr)).unwrap();
    let server_id = *server.local_peer_id();

    let known = B256::repeat_byte(0xAA);
    let unknown = B256::repeat_byte(0xBB);
    let body = vec![0xc4, 0xc0, 0xc0, 0xc0, 0xc0];

    // The server answers whatever it is asked; the client asks once connected.
    let body_for_server = body.clone();
    let server_task = tokio::spawn(async move {
        loop {
            match server.next_event().await {
                Some(TransportEvent::BlockRequest { hash, channel, .. }) => {
                    let reply = (hash == known).then(|| body_for_server.clone());
                    server.respond_block(channel, reply);
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let mut asked = false;
    let mut replies = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::PeerConnected(peer)) if peer == server_id && !asked => {
                    asked = true;
                    client.request_block(server_id, known);
                    client.request_block(server_id, unknown);
                }
                Some(TransportEvent::BlockFetched { hash, reply, .. }) => {
                    replies.push((hash, reply));
                    if replies.len() == 2 {
                        return;
                    }
                }
                Some(TransportEvent::BlockFetchFailed { reason, .. }) => panic!("request failed: {reason}"),
                Some(_) => {}
                None => panic!("client transport ended"),
            }
        }
    })
    .await;
    server_task.abort();
    outcome.expect("both replies within the budget");

    let served = replies.iter().find(|(h, _)| *h == known).map(|(_, r)| r.clone()).unwrap();
    let chunk = served.expect("the known block is served");
    assert_eq!(chunk.rlp, body);
    assert_eq!(chunk.fork_digest, IDENTITY.genesis_hash[..4]);
    let missing = replies.iter().find(|(h, _)| *h == unknown).map(|(_, r)| r.clone()).unwrap();
    assert!(missing.unwrap_err().contains("block not found"));
}

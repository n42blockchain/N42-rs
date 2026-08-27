// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's fetch-on-miss over a real connection: one transport asks another
//! for a block by hash and gets the body, or gov5's "not found".

use std::time::Duration;

use alloy_primitives::B256;
use libp2p::Multiaddr;
use n42_h2_net::{H2V4Transport, RangeRequest, TransportConfig, TransportEvent};
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

#[tokio::test]
async fn a_range_is_served_in_order_and_ends_where_the_server_runs_out() {
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone())).unwrap();
    let server_addr = listening(&mut server).await;
    let mut client =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_peer(server_addr)).unwrap();
    let server_id = *server.local_peer_id();

    // The server holds blocks 1..=3; a request for 2..=5 gets 2 and 3.
    let server_task = tokio::spawn(async move {
        loop {
            match server.next_event().await {
                Some(TransportEvent::RangeRequest { request, channel, .. }) => {
                    let have = (request.start..request.start + request.count)
                        .take_while(|n| (1..=3).contains(n))
                        .map(|n| vec![0xc1, n as u8])
                        .collect();
                    server.respond_range(channel, have);
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let request = RangeRequest { start: 2, count: 4, step: 1 };
    let mut asked = false;
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::PeerConnected(peer)) if peer == server_id && !asked => {
                    asked = true;
                    client.request_range(server_id, request);
                }
                Some(TransportEvent::RangeFetched { reply, request: got, .. }) => return (got, reply),
                Some(_) => {}
                None => panic!("client transport ended"),
            }
        }
    })
    .await
    .expect("a reply within the budget");
    server_task.abort();

    let (got, reply) = outcome;
    assert_eq!(got, request);
    let chunks = reply.expect("served");
    assert_eq!(chunks.iter().map(|c| c.rlp.clone()).collect::<Vec<_>>(), vec![vec![0xc1, 2], vec![0xc1, 3]]);
    assert!(chunks.iter().all(|c| c.fork_digest == IDENTITY.genesis_hash[..4]));
}

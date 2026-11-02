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
    round_trip_body(vec![0xc4, 0xc0, 0xc0, 0xc0, 0xc0]).await;
}

#[tokio::test]
async fn an_incompressible_body_crosses_many_adaptive_receive_windows() {
    // Public deterministic test bytes, intentionally not Snappy-compressible.
    let mut state = 0x9e3779b97f4a7c15u64;
    let body = (0..2 * 1024 * 1024).map(|_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
    }).collect();
    round_trip_body(body).await;
}

async fn round_trip_body(body: Vec<u8>) {
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone())).unwrap();
    let server_addr = listening(&mut server).await;
    let mut client =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_peer(server_addr)).unwrap();
    let server_id = *server.local_peer_id();

    let known = B256::repeat_byte(0xAA);
    let unknown = B256::repeat_byte(0xBB);

    // The server answers whatever it is asked; the client asks once connected.
    let body_for_server = body.clone();
    let server_task = tokio::spawn(async move {
        loop {
            match server.next_event().await {
                Some(TransportEvent::BlockRequest { hash, channel, .. }) => {
                    let reply = (hash == known)
                        .then(|| alloy_primitives::Bytes::from(body_for_server.clone()));
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

/// A client on `client_identity` asks a server on [`IDENTITY`] holding
/// blocks 1..=3 for 2..=5, once their status exchange is done.
async fn fetch_range(
    client_identity: H2V4ChainIdentity,
) -> (RangeRequest, Result<Vec<n42_h2_net::BlockChunk>, String>) {
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone())).unwrap();
    let server_addr = listening(&mut server).await;
    let mut client = H2V4Transport::new(
        TransportConfig::new(client_identity).with_listen_addr(loopback).with_peer(server_addr),
    )
    .unwrap();
    let server_id = *server.local_peer_id();

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

    // As a node does: a range is asked for from a peer whose status it has.
    let request = RangeRequest { start: 2, count: 4, step: 1 };
    let mut asked = false;
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::StatusExchanged { peer, .. }) if peer == server_id && !asked => {
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
    outcome
}

#[tokio::test]
async fn a_range_is_served_in_order_and_ends_where_the_server_runs_out() {
    let (got, reply) = fetch_range(IDENTITY).await;
    assert_eq!(got, RangeRequest { start: 2, count: 4, step: 1 });
    let chunks = reply.expect("served");
    assert_eq!(chunks.iter().map(|c| c.rlp.clone()).collect::<Vec<_>>(), vec![vec![0xc1, 2], vec![0xc1, 3]]);
    assert!(chunks.iter().all(|c| c.fork_digest == IDENTITY.genesis_hash[..4]));
}

/// Audit 2026-10 B-3: ranges are served only to a peer that completed the
/// status handshake for this chain. One on another chain never does, so it
/// is refused rather than served a chain it cannot use.
#[tokio::test]
async fn a_range_is_not_served_to_a_peer_without_a_matching_status() {
    let other_chain = H2V4ChainIdentity { chain_id: 1143, genesis_hash: B256::repeat_byte(0x43) };
    let (_, reply) = fetch_range(other_chain).await;
    let refused = reply.expect_err("refused");
    assert!(refused.contains("status"), "{refused}");
}

/// Audit 2026-10 B-4: what a server holds for a range reply (its serve slot,
/// its byte budget) is held until libp2p has sent the reply, not only until
/// the reply is handed to the swarm -- a slow reader otherwise keeps the
/// bytes queued without anything counting them.
#[tokio::test]
async fn a_range_replys_guard_is_held_until_the_reply_is_sent() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Flag(Arc<AtomicBool>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone())).unwrap();
    let server_addr = listening(&mut server).await;
    let mut client =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_peer(server_addr)).unwrap();
    let server_id = *server.local_peer_id();

    let released = Arc::new(AtomicBool::new(false));
    let held_after_respond = Arc::new(AtomicBool::new(false));
    let (server_released, server_held) = (released.clone(), held_after_respond.clone());
    let server_task = tokio::spawn(async move {
        loop {
            match server.next_event().await {
                Some(TransportEvent::RangeRequest { channel, .. }) => {
                    let guard = n42_h2_net::ServeGuard::new(Flag(server_released.clone()));
                    server.respond_range_holding(channel, vec![vec![0xc1, 1]], guard);
                    // Nothing has been sent yet: the swarm has not been polled.
                    server_held.store(!server_released.load(Ordering::SeqCst), Ordering::SeqCst);
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let mut asked = false;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::StatusExchanged { peer, .. }) if peer == server_id && !asked => {
                    asked = true;
                    client.request_range(server_id, RangeRequest { start: 1, count: 1, step: 1 });
                }
                Some(TransportEvent::RangeFetched { reply, .. }) => {
                    reply.expect("served");
                    return;
                }
                Some(_) => {}
                None => panic!("client transport ended"),
            }
        }
    })
    .await
    .expect("a reply within the budget");
    assert!(held_after_respond.load(Ordering::SeqCst), "the guard is held while the reply waits to be sent");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !released.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the guard is released once the reply is sent");
    server_task.abort();
}

/// Audit 2026-10 R2-I6: a block-by-hash reply and a named-transactions
/// reply hold their guard (the server's byte budget) until libp2p has sent
/// them, as a range reply does (B-4). A whole body is tens of megabytes: a
/// slow reader asking for it again and again otherwise queued copies
/// nothing counted.
#[tokio::test]
async fn block_and_fill_replies_hold_their_guard_until_sent() {
    for fill in [false, true] {
        guard_held_until_sent(fill).await;
    }
}

async fn guard_held_until_sent(fill: bool) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Flag(Arc<AtomicBool>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone())).unwrap();
    let server_addr = listening(&mut server).await;
    let mut client =
        H2V4Transport::new(TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_peer(server_addr)).unwrap();
    let server_id = *server.local_peer_id();

    let released = Arc::new(AtomicBool::new(false));
    let held_after_respond = Arc::new(AtomicBool::new(false));
    let (server_released, server_held) = (released.clone(), held_after_respond.clone());
    let server_task = tokio::spawn(async move {
        loop {
            match server.next_event().await {
                Some(TransportEvent::BlockRequest { channel, .. }) => {
                    let guard = n42_h2_net::ServeGuard::new(Flag(server_released.clone()));
                    server.respond_block_holding(channel, Some(vec![0xc1, 1].into()), guard);
                    server_held.store(!server_released.load(Ordering::SeqCst), Ordering::SeqCst);
                }
                Some(TransportEvent::BlockTxnsRequested { channel, .. }) => {
                    let guard = n42_h2_net::ServeGuard::new(Flag(server_released.clone()));
                    server.respond_block_txns_holding(channel, Ok(vec![vec![0x01].into()]), guard);
                    server_held.store(!server_released.load(Ordering::SeqCst), Ordering::SeqCst);
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let mut asked = false;
    let hash = B256::repeat_byte(0x16);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::StatusExchanged { peer, .. }) if peer == server_id && !asked => {
                    asked = true;
                    if fill {
                        client.request_block_txns(server_id, n42_h2_net::BlockTxnsRequest { hash, indices: vec![0] });
                    } else {
                        client.request_block(server_id, hash);
                    }
                }
                Some(TransportEvent::BlockFetched { .. } | TransportEvent::BlockTxnsFetched { .. }) => return,
                Some(_) => {}
                None => panic!("client transport ended"),
            }
        }
    })
    .await
    .expect("a reply within the budget");
    assert!(held_after_respond.load(Ordering::SeqCst), "fill {fill}: the guard is held while the reply waits to be sent");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !released.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the guard is released once the reply is sent");
    server_task.abort();
}

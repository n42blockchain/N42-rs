// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sync v1.1 over a real connection: a pull prefers `bodies_by_range/2`
//! when the peer lists it in identify, and stays on `/1` when it does not
//! (gov5's main line, n42-26); `commit_qc/1` likewise.

use std::time::Duration;

use alloy_primitives::{Bytes, B256};
use libp2p::Multiaddr;
use n42_h2_consensus::N42Header;
use n42_h2_net::sync_v11::bodies::{item_links, RangeItem, RangeV2Builder};
use n42_h2_net::sync_v11::commit_qc::{CommitQcRequest, CommitQcResponse};
use n42_h2_net::{H2V4Transport, PeerId, RangeRequest, TransportConfig, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

const IDENTITY: H2V4ChainIdentity = H2V4ChainIdentity { chain_id: 1143, genesis_hash: B256::repeat_byte(0x42) };

/// Blocks 0..=n, each `[header, [], [], []]`, parent-linked.
fn chain(n: u64) -> Vec<Bytes> {
    let mut parent = B256::ZERO;
    (0..=n)
        .map(|number| {
            let header = N42Header::from(alloy_consensus::Header { number, parent_hash: parent, ..Default::default() });
            parent = header.hash_slow();
            let mut payload = alloy_rlp::encode(&header);
            payload.extend_from_slice(&[0xc0, 0xc0, 0xc0]);
            let mut block = Vec::new();
            alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut block);
            block.extend_from_slice(&payload);
            block.into()
        })
        .collect()
}

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

/// What the server saw.
#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    v1: usize,
    v2: usize,
    commit_qc: usize,
}

/// A server holding blocks 0..=`head` (committed), answering every
/// protocol it serves; what it was asked comes back on the channel.
fn spawn_server(mut server: H2V4Transport, head: u64) -> (tokio::task::JoinHandle<()>, tokio::sync::watch::Receiver<Seen>) {
    let (tx, rx) = tokio::sync::watch::channel(Seen::default());
    let blocks = chain(head);
    let handle = tokio::spawn(async move {
        let mut seen = Seen::default();
        loop {
            match server.next_event().await {
                Some(TransportEvent::RangeRequest { request, channel, .. }) => {
                    seen.v1 += 1;
                    let have = (request.start..request.start + request.count)
                        .filter_map(|n| blocks.get(n as usize).map(|b| b.to_vec()))
                        .collect();
                    server.respond_range(channel, have);
                }
                Some(TransportEvent::RangeV2Request { request, channel, .. }) => {
                    seen.v2 += 1;
                    let mut builder = RangeV2Builder::new(request, head);
                    while let Some(n) = builder.wanted() {
                        let item = blocks.get(n as usize).map(|payload| {
                            let links = item_links(payload, false).unwrap();
                            RangeItem { payload: payload.clone(), hash: links.hash, parent: links.parent }
                        });
                        if !builder.offer(item) {
                            break;
                        }
                    }
                    server.respond_range_v2(channel, builder.into_reply(), None);
                }
                Some(TransportEvent::CommitQcRequest { channel, .. }) => {
                    seen.commit_qc += 1;
                    let payload = CommitQcResponse { qc: vec![7; 10], headers: Vec::new() }.encode().unwrap();
                    server.respond_commit_qc(channel, Ok(payload));
                }
                Some(_) => {}
                None => return,
            }
            let _ = tx.send(seen);
        }
    });
    (handle, rx)
}

/// A client connected to a fresh server (serving v1.1 or not), driven until
/// the status exchange and a moment after it, so identify has landed.
async fn connected(serve_v11: bool, client_v11: bool, head: u64) -> (H2V4Transport, PeerId, tokio::task::JoinHandle<()>, tokio::sync::watch::Receiver<Seen>) {
    let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let mut server = H2V4Transport::new(
        TransportConfig::new(IDENTITY).with_listen_addr(loopback.clone()).with_sync_v11_serve(serve_v11),
    )
    .unwrap();
    let server_addr = listening(&mut server).await;
    let server_id = *server.local_peer_id();
    let (handle, seen) = spawn_server(server, head);
    let mut client = H2V4Transport::new(
        TransportConfig::new(IDENTITY).with_listen_addr(loopback).with_peer(server_addr).with_sync_v11_client(client_v11),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(TransportEvent::StatusExchanged { peer, .. }) = client.next_event().await
                && peer == server_id
            {
                return;
            }
        }
    })
    .await
    .expect("status exchanged");
    // Identify travels beside the status exchange; give it a moment.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            client.next_event().await;
        }
    })
    .await;
    (client, server_id, handle, seen)
}

async fn fetch(client: &mut H2V4Transport, peer: PeerId, request: RangeRequest) -> Result<Vec<n42_h2_net::BlockChunk>, String> {
    client.request_range(peer, request);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::RangeFetched { request: got, reply, .. }) if got == request => return reply,
                Some(_) => {}
                None => panic!("client ended"),
            }
        }
    })
    .await
    .expect("a reply")
}

async fn commit_qc(client: &mut H2V4Transport, peer: PeerId) -> Result<Vec<u8>, String> {
    let request = CommitQcRequest { number: 3, hash: B256::ZERO };
    client.request_commit_qc(peer, request);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.next_event().await {
                Some(TransportEvent::CommitQcFetched { request: got, reply, .. }) if got == request => return reply,
                Some(_) => {}
                None => panic!("client ended"),
            }
        }
    })
    .await
    .expect("a commit QC answer")
}

#[tokio::test]
async fn a_pull_from_a_v11_peer_goes_over_bodies_by_range_2_and_commit_qc_1() {
    let (mut client, server, handle, seen) = connected(true, true, 10).await;
    let blocks = chain(10);
    // Up to the committed head and past it: CANONICAL_END after block 10.
    let reply = fetch(&mut client, server, RangeRequest { start: 3, count: 20, step: 1 }).await.expect("served");
    assert_eq!(reply.iter().map(|c| c.rlp.clone()).collect::<Vec<_>>(), blocks[3..=10].to_vec());
    assert!(reply.iter().all(|c| c.fork_digest == IDENTITY.genesis_hash[..4]));
    // Past the head: zero blocks with END CANONICAL_END, an empty reply.
    assert_eq!(fetch(&mut client, server, RangeRequest { start: 11, count: 4, step: 1 }).await, Ok(Vec::new()));
    let payload = commit_qc(&mut client, server).await.expect("a commit QC");
    assert_eq!(CommitQcResponse::decode(&payload).unwrap().qc, vec![7; 10]);
    let seen = *seen.borrow();
    assert_eq!((seen.v1, seen.v2, seen.commit_qc), (0, 2, 1), "{seen:?}");
    handle.abort();
}

#[tokio::test]
async fn a_pull_from_a_v1_only_peer_stays_on_bodies_by_range_1() {
    let (mut client, server, handle, seen) = connected(false, true, 10).await;
    let reply = fetch(&mut client, server, RangeRequest { start: 2, count: 3, step: 1 }).await.expect("served");
    assert_eq!(reply.len(), 3);
    let refused = commit_qc(&mut client, server).await.expect_err("not spoken");
    assert!(refused.contains("does not speak"), "{refused}");
    let seen = *seen.borrow();
    assert_eq!((seen.v1, seen.v2, seen.commit_qc), (1, 0, 0), "{seen:?}");
    handle.abort();
}

#[tokio::test]
async fn n42_sync_v11_off_keeps_the_client_on_v1() {
    let (mut client, server, handle, seen) = connected(true, false, 10).await;
    let reply = fetch(&mut client, server, RangeRequest { start: 2, count: 3, step: 1 }).await.expect("served");
    assert_eq!(reply.len(), 3);
    assert!(commit_qc(&mut client, server).await.is_err());
    let seen = *seen.borrow();
    assert_eq!((seen.v1, seen.v2, seen.commit_qc), (1, 0, 0), "{seen:?}");
    handle.abort();
}

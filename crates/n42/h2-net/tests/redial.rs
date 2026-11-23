// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A configured fleet member is dialled again until it is connected.
//!
//! The transport used to dial its `--peer` list once, at start: a member that
//! was not up yet, or a connection that closed later, stayed gone until this
//! node was restarted. Found on a live gov5 fleet (2026-11-23), where a node
//! that lost its connections sat with none and imported nothing.

use std::time::Duration;

use alloy_primitives::B256;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

const IDENTITY: H2V4ChainIdentity = H2V4ChainIdentity { chain_id: 1, genesis_hash: B256::repeat_byte(7) };

/// A loopback port nothing listens on yet.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn until_connected(transport: &mut H2V4Transport, peer: PeerId) {
    loop {
        if let Some(TransportEvent::PeerConnected(connected)) = transport.next_event().await
            && connected == peer
        {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_starts_later_is_dialled_again() {
    let member_key = Keypair::generate_secp256k1();
    let member_id = member_key.public().to_peer_id();
    let listen: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", free_port()).parse().unwrap();
    let member_addr: Multiaddr = format!("{listen}/p2p/{member_id}").parse().unwrap();

    // The member is not up: the dial made at start fails.
    let mut node = H2V4Transport::new(
        TransportConfig::new(IDENTITY).with_peer(member_addr).with_redial_interval(Duration::from_millis(200)),
    )
    .unwrap();
    let early = tokio::time::timeout(Duration::from_secs(1), until_connected(&mut node, member_id)).await;
    assert!(early.is_err(), "nothing listens yet");

    // The member comes up and dials nobody; only a redial can connect the two.
    let mut member =
        H2V4Transport::with_keypair(TransportConfig::new(IDENTITY).with_listen_addr(listen), member_key).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = until_connected(&mut node, member_id) => {}
            () = async { loop { member.next_event().await; } } => {}
        }
    })
    .await
    .expect("the configured member is dialled again once it is up");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_drops_the_connection_is_dialled_again() {
    let member_key = Keypair::generate_secp256k1();
    let member_id = member_key.public().to_peer_id();
    let listen: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", free_port()).parse().unwrap();
    let member_addr: Multiaddr = format!("{listen}/p2p/{member_id}").parse().unwrap();

    let mut member = H2V4Transport::with_keypair(
        TransportConfig::new(IDENTITY).with_listen_addr(listen.clone()),
        member_key.clone(),
    )
    .unwrap();
    let mut node = H2V4Transport::new(
        TransportConfig::new(IDENTITY).with_peer(member_addr).with_redial_interval(Duration::from_millis(200)),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = until_connected(&mut node, member_id) => {}
            () = async { loop { member.next_event().await; } } => {}
        }
    })
    .await
    .expect("first connection");

    // The member goes away and comes back on the same address.
    drop(member);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut member =
        H2V4Transport::with_keypair(TransportConfig::new(IDENTITY).with_listen_addr(listen), member_key).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = until_connected(&mut node, member_id) => {}
            () = async { loop { member.next_event().await; } } => {}
        }
    })
    .await
    .expect("the member is dialled again after the connection closed");
}

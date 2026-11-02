// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One peer cannot take every inbound slot.
//!
//! Audit 2026-10 round 3 (R3-N1): the transport capped inbound connections in
//! total (128) but not per peer, so a single identity dialling again and
//! again held every slot and the fleet's own members could no longer connect.

use std::time::Duration;

use alloy_primitives::B256;
use futures::StreamExt;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{dummy, SwarmEvent};
use libp2p::SwarmBuilder;
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent, MAX_CONNECTIONS_PER_PEER};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

#[tokio::test(flavor = "multi_thread")]
async fn one_peer_holds_at_most_its_share_of_connections() {
    let identity = H2V4ChainIdentity { chain_id: 1, genesis_hash: B256::repeat_byte(7) };
    let mut transport = H2V4Transport::new(
        TransportConfig::new(identity).with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
    )
    .unwrap();
    let target = *transport.local_peer_id();
    let listen = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(TransportEvent::Listening(addr)) = transport.next_event().await {
                break addr;
            }
        }
    })
    .await
    .expect("listening");

    let mut dialer = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(Default::default(), libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .unwrap()
        .with_behaviour(|_| dummy::Behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let dials = MAX_CONNECTIONS_PER_PEER as usize + 4;
    for _ in 0..dials {
        dialer
            .dial(
                DialOpts::peer_id(target)
                    .condition(PeerCondition::Always)
                    .addresses(vec![listen.clone()])
                    .build(),
            )
            .unwrap();
    }

    // Count what stays up once every dial has settled.
    let mut open = 0usize;
    let mut settled = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = dialer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { .. } => { open += 1; settled += 1; }
                    SwarmEvent::ConnectionClosed { .. } => open = open.saturating_sub(1),
                    SwarmEvent::OutgoingConnectionError { .. } => settled += 1,
                    _ => {}
                },
                _ = transport.next_event() => {}
            }
            if settled >= dials {
                // Give refused connections a moment to close.
                let quiet = tokio::time::sleep(Duration::from_secs(1));
                tokio::pin!(quiet);
                loop {
                    tokio::select! {
                        event = dialer.select_next_some() => {
                            if let SwarmEvent::ConnectionClosed { .. } = event { open = open.saturating_sub(1) }
                        }
                        _ = transport.next_event() => {}
                        _ = &mut quiet => return,
                    }
                }
            }
        }
    })
    .await;
    assert!(open >= 1, "the peer is still served");
    assert!(
        open <= MAX_CONNECTIONS_PER_PEER as usize,
        "{open} connections from one peer, past {MAX_CONNECTIONS_PER_PEER}"
    );
}

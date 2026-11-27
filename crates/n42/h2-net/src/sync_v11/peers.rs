// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the transport keeps for the v1.1 sync protocols: which peers speak
//! them (§5.0 capability discovery through identify, a multistream refusal
//! marking a peer v1-only for an hour), the requests in flight, and the
//! reply channels a server answers on.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use libp2p::request_response::{InboundRequestId, OutboundRequestId, ResponseChannel};
use libp2p::{PeerId, StreamProtocol};

use super::bodies::{RangeV2Reply, RangeV2Request, BODIES_BY_RANGE_V2_PROTOCOL};
use super::commit_qc::{CommitQcReply, CommitQcRequest, COMMIT_QC_PROTOCOL};
use crate::rpc::RangeRequest;
use crate::transport::ServeGuard;

/// The environment variable that turns the v1.1 *client* off:
/// `N42_SYNC_V11=off` keeps every pull on `bodies_by_range/1` and never asks
/// `commit_qc/1`. The servers are registered either way (§5.0: old and new
/// ids side by side).
pub const SYNC_V11_ENV: &str = "N42_SYNC_V11";

/// Whether a value of [`SYNC_V11_ENV`] leaves the v1.1 client on (unset,
/// empty or anything but `off`/`0`/`false`).
pub fn client_enabled_from(value: Option<&str>) -> bool {
    !matches!(value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("off" | "0" | "false" | "no"))
}

/// [`client_enabled_from`] of the environment.
pub fn client_enabled() -> bool {
    client_enabled_from(std::env::var(SYNC_V11_ENV).ok().as_deref())
}

/// How long a peer that refused a v1.1 protocol is treated as v1-only.
pub const V1_ONLY_FOR: Duration = Duration::from_secs(3600);

/// Where the answer to a [`crate::TransportEvent::RangeV2Request`] goes.
#[derive(Debug)]
pub struct RangeV2Channel(pub(crate) ResponseChannel<RangeV2Reply>, pub(crate) InboundRequestId);

/// Where the answer to a [`crate::TransportEvent::CommitQcRequest`] goes.
#[derive(Debug)]
pub struct CommitQcChannel(pub(crate) ResponseChannel<CommitQcReply>);

/// A v1.1 command from the loop to the swarm (inline or off the loop).
#[derive(Debug)]
pub(crate) enum V11Command {
    /// Ask a peer for a commit QC.
    RequestCommitQc(PeerId, CommitQcRequest),
    /// Answer a `bodies_by_range/2` request, holding the guard until sent.
    RespondRangeV2(RangeV2Channel, RangeV2Reply, Option<ServeGuard>),
    /// Answer a `commit_qc/1` request.
    RespondCommitQc(CommitQcChannel, CommitQcReply),
}

/// The peers this node asks `commit_qc/1`, shared with the transport's
/// owner (the swarm may run on its own task).
pub(crate) type CommitQcPeers = Arc<RwLock<HashSet<PeerId>>>;

/// The transport's v1.1 bookkeeping.
#[derive(Debug)]
pub(crate) struct V11State {
    /// Whether this node asks peers over v1.1 at all ([`SYNC_V11_ENV`]).
    pub(crate) client: bool,
    /// The v1.1 protocols each identified peer lists.
    caps: HashMap<PeerId, (bool, bool)>,
    /// Peers that refused a protocol, until when.
    refused: HashMap<(PeerId, &'static str), Instant>,
    /// Range requests sent over `/2`: the `/1` request the caller made and
    /// the `/2` request that carries it.
    pub(crate) ranges: HashMap<OutboundRequestId, (RangeRequest, RangeV2Request)>,
    /// Commit-QC requests in flight.
    pub(crate) commit_qcs: HashMap<OutboundRequestId, CommitQcRequest>,
    /// What each `/2` reply holds until it is sent.
    pub(crate) range_guards: HashMap<InboundRequestId, ServeGuard>,
    /// [`Self::speaks`] `commit_qc/1`, as a set the owner can read.
    commit_qc_peers: CommitQcPeers,
}

impl Default for V11State {
    fn default() -> Self {
        Self::new(client_enabled())
    }
}

impl V11State {
    /// Bookkeeping with the client on or off.
    pub(crate) fn new(client: bool) -> Self {
        Self {
            client,
            caps: HashMap::new(),
            refused: HashMap::new(),
            ranges: HashMap::new(),
            commit_qcs: HashMap::new(),
            range_guards: HashMap::new(),
            commit_qc_peers: CommitQcPeers::default(),
        }
    }

    /// The peers this node asks `commit_qc/1`, kept current.
    pub(crate) fn commit_qc_peers(&self) -> CommitQcPeers {
        Arc::clone(&self.commit_qc_peers)
    }

    fn publish_commit_qc(&self, peer: PeerId) {
        let speaks = self.speaks(&peer, COMMIT_QC_PROTOCOL);
        if let Ok(mut peers) = self.commit_qc_peers.write() {
            if speaks {
                peers.insert(peer);
            } else {
                peers.remove(&peer);
            }
        }
    }

    /// Records what `peer` listed in identify.
    pub(crate) fn learn(&mut self, peer: PeerId, protocols: &[StreamProtocol]) {
        let lists = |id: &str| protocols.iter().any(|p| p.as_ref() == id);
        self.caps.insert(peer, (lists(BODIES_BY_RANGE_V2_PROTOCOL), lists(COMMIT_QC_PROTOCOL)));
        self.publish_commit_qc(peer);
    }

    /// Forgets a peer that went away.
    pub(crate) fn forget(&mut self, peer: &PeerId) {
        self.caps.remove(peer);
        self.publish_commit_qc(*peer);
    }

    /// Marks `peer` v1-only for `protocol` ([`V1_ONLY_FOR`]).
    pub(crate) fn mark_refused(&mut self, peer: PeerId, protocol: &'static str) {
        if self.refused.len() > 4096 {
            let now = Instant::now();
            self.refused.retain(|_, until| *until > now);
        }
        self.refused.insert((peer, protocol), Instant::now() + V1_ONLY_FOR);
        self.publish_commit_qc(peer);
    }

    /// Whether this node asks `peer` over `protocol`: the client is on, the
    /// peer listed it in identify, and has not refused it within the hour.
    pub(crate) fn speaks(&self, peer: &PeerId, protocol: &'static str) -> bool {
        if !self.client {
            return false;
        }
        if self.refused.get(&(*peer, protocol)).is_some_and(|until| *until > Instant::now()) {
            return false;
        }
        self.caps.get(peer).is_some_and(|(range_v2, commit_qc)| match protocol {
            BODIES_BY_RANGE_V2_PROTOCOL => *range_v2,
            COMMIT_QC_PROTOCOL => *commit_qc,
            _ => false,
        })
    }
}

/// The `/2` request that carries a `/1` range request, or `None` when it
/// cannot (a count outside 1..1024).
#[cfg(test)]
pub(crate) fn v2_for(request: &RangeRequest) -> Option<RangeV2Request> {
    v2_for_bounded(request, 0)
}

/// [`v2_for`] with the requester's decoded-byte budget (`0`: the server's
/// default, 64 MiB).
pub(crate) fn v2_for_bounded(request: &RangeRequest, max_bytes: u64) -> Option<RangeV2Request> {
    (1..=super::bodies::MAX_RANGE_V2_COUNT)
        .contains(&request.count)
        .then(|| RangeV2Request { max_bytes, ..RangeV2Request::bodies(request.start, request.count) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_is_on_unless_turned_off() {
        assert!(client_enabled_from(None));
        assert!(client_enabled_from(Some("")));
        assert!(client_enabled_from(Some("on")));
        assert!(!client_enabled_from(Some("off")));
        assert!(!client_enabled_from(Some(" 0 ")));
    }

    #[test]
    fn a_peer_speaks_what_it_listed_until_it_refuses() {
        let peer = PeerId::random();
        let mut state = V11State::new(true);
        assert!(!state.speaks(&peer, BODIES_BY_RANGE_V2_PROTOCOL), "unidentified: v1");
        state.learn(peer, &[StreamProtocol::new(BODIES_BY_RANGE_V2_PROTOCOL)]);
        assert!(state.speaks(&peer, BODIES_BY_RANGE_V2_PROTOCOL));
        assert!(!state.speaks(&peer, COMMIT_QC_PROTOCOL));
        state.mark_refused(peer, BODIES_BY_RANGE_V2_PROTOCOL);
        assert!(!state.speaks(&peer, BODIES_BY_RANGE_V2_PROTOCOL));
        let mut off = V11State::new(false);
        off.learn(peer, &[StreamProtocol::new(BODIES_BY_RANGE_V2_PROTOCOL)]);
        assert!(!off.speaks(&peer, BODIES_BY_RANGE_V2_PROTOCOL));
    }

    /// §5.0: a peer that lists `/2` but whose multistream refuses it is
    /// asked again over `/1` at once, and marked v1-only for the hour.
    #[tokio::test]
    async fn a_peer_that_refuses_v2_is_asked_again_over_v1_and_marked() {
        use crate::transport::{TransportConfig, TransportCore, TransportEvent};
        use libp2p::identity::Keypair;
        use libp2p::Multiaddr;

        let identity = n42_h2_primitives::consensus::H2V4ChainIdentity { chain_id: 1143, genesis_hash: alloy_primitives::B256::repeat_byte(0x42) };
        let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let mut server = TransportCore::with_keypair(
            TransportConfig::new(identity).with_listen_addr(loopback.clone()).with_sync_v11_serve(false),
            Keypair::generate_ed25519(),
        )
        .unwrap();
        let server_id = *server.local_peer_id();
        let addr = loop {
            if let Some(TransportEvent::Listening(addr)) = server.next_event().await {
                break addr.with(libp2p::multiaddr::Protocol::P2p(server_id));
            }
        };
        let server_task = tokio::spawn(async move {
            while let Some(event) = server.next_event().await {
                if let TransportEvent::RangeRequest { channel, .. } = event {
                    server.respond_range(channel, vec![vec![0xc1, 1]]);
                }
            }
        });
        let mut client = TransportCore::with_keypair(
            TransportConfig::new(identity).with_listen_addr(loopback).with_peer(addr).with_sync_v11_client(true),
            Keypair::generate_ed25519(),
        )
        .unwrap();
        let request = RangeRequest { start: 1, count: 1, step: 1 };
        let reply = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match client.next_event().await {
                    Some(TransportEvent::StatusExchanged { peer, .. }) if peer == server_id => {
                        // As if its identify had listed `/2`.
                        client.v11_mut().learn(server_id, &[StreamProtocol::new(BODIES_BY_RANGE_V2_PROTOCOL)]);
                        client.request_range(server_id, request);
                    }
                    Some(TransportEvent::RangeFetched { request: got, reply, .. }) if got == request => return reply,
                    Some(_) => {}
                    None => panic!("client ended"),
                }
            }
        })
        .await
        .expect("a reply");
        server_task.abort();
        assert_eq!(reply.expect("served over /1")[0].rlp.to_vec(), vec![0xc1, 1]);
        assert!(!client.v11_mut().speaks(&server_id, BODIES_BY_RANGE_V2_PROTOCOL), "marked v1-only");
    }

    #[test]
    fn a_v1_request_maps_to_v2_within_the_count() {
        let request = RangeRequest { start: 5, count: 1024, step: 1 };
        assert_eq!(v2_for(&request), Some(RangeV2Request::bodies(5, 1024)));
        assert_eq!(v2_for(&RangeRequest { count: 0, ..request }), None);
        assert_eq!(v2_for(&RangeRequest { count: 1025, ..request }), None);
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A read-only observer that follows a gov5 fleet's finality over gossip.
//!
//! This is the transport half of the observer path: subscribe to
//! `/n42/h2/4/ssz_snappy`, decode each chain-bound v4 envelope, and verify the
//! committed `Decide` against a validator set. It never votes, never proposes,
//! and never publishes — a node running this is invisible to consensus and
//! cannot affect liveness or safety of the fleet it watches.
//!
//! Transport matches gov5's host (`internal/p2p/options.go`): TCP with Noise
//! and Yamux. gov5 also listens on QUIC-v1; dialing it from here is possible
//! but not enabled by default, because a QUIC dial to a node that only
//! advertises TCP fails in a way that is easy to misread as a consensus problem.

use std::collections::HashSet;
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::request_response;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity::Keypair, Multiaddr, PeerId, Swarm, SwarmBuilder};
use n42_h2_consensus::{h2_finality::verify_h2_v4_decide, ValidatorSet};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_wire::h2_v4::decode_gossip;
use n42_h2_wire::H2Message;

use crate::config::gov5_gossipsub_config;
use crate::rpc::{status_behaviour, StatusBehaviour};
use crate::status::Status;
use crate::topic::h2_v4_topic;

/// Errors that stop an observer from starting.
#[derive(Debug, thiserror::Error)]
pub enum ObserverError {
    /// The gossipsub parameters were rejected by libp2p.
    #[error("gossipsub configuration rejected: {0}")]
    Config(&'static str),
    /// The gossipsub behaviour could not be constructed.
    #[error("gossipsub behaviour: {0}")]
    Behaviour(String),
    /// Building the libp2p transport failed.
    #[error("transport: {0}")]
    Transport(String),
    /// A listen address could not be bound.
    #[error("listen on {addr}: {source}")]
    Listen {
        /// The address that failed to bind.
        addr: Multiaddr,
        /// The underlying libp2p error.
        source: libp2p::TransportError<std::io::Error>,
    },
    /// Subscribing to the v4 topic failed.
    #[error("subscribe to {topic}: {source}")]
    Subscribe {
        /// The topic that could not be subscribed.
        topic: String,
        /// The underlying gossipsub error.
        source: gossipsub::SubscriptionError,
    },
}

/// How an observer is wired to a fleet.
#[derive(Debug, Clone)]
pub struct ObserverConfig {
    /// The chain this observer accepts envelopes for. Envelopes carrying any
    /// other chain id or genesis hash are rejected by the decoder, so this is
    /// the primary defence against cross-chain replay.
    pub identity: H2V4ChainIdentity,
    /// Addresses to listen on. An observer needs none to follow a fleet — it
    /// can dial out only — but listening lets fleet members dial back.
    pub listen_addrs: Vec<Multiaddr>,
    /// Fleet members to dial on startup, as full multiaddrs including `/p2p/<peer id>`.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Idle connection timeout. gov5 keeps fleet connections long-lived.
    pub idle_connection_timeout: Duration,
}

impl ObserverConfig {
    /// A config for `identity` with no listeners and no peers yet.
    pub fn new(identity: H2V4ChainIdentity) -> Self {
        Self {
            identity,
            listen_addrs: Vec::new(),
            bootstrap_peers: Vec::new(),
            idle_connection_timeout: Duration::from_secs(300),
        }
    }

    /// Adds a peer to dial on startup.
    pub fn with_peer(mut self, addr: Multiaddr) -> Self {
        self.bootstrap_peers.push(addr);
        self
    }

    /// Adds a listen address.
    pub fn with_listen_addr(mut self, addr: Multiaddr) -> Self {
        self.listen_addrs.push(addr);
        self
    }
}

/// What the observer saw.
#[derive(Debug)]
pub enum ObserverEvent {
    /// A committed `Decide` verified against the validator set. This is a
    /// finality proof: safe to use as a sync target.
    Finality {
        /// The peer that delivered it.
        from: Option<PeerId>,
        /// View the decision was reached in.
        view: u64,
        /// The finalized block.
        block_hash: alloy_primitives::B256,
        /// Validator-change hash. The deployed v4 profile pins this to zero
        /// (static validators) and rejects reconfiguration; it is carried here
        /// because it is bound into the signed preimage.
        changes_hash: alloy_primitives::B256,
    },
    /// An envelope decoded but failed verification. Worth surfacing rather than
    /// dropping: on a healthy fleet this should never fire, so it is a signal.
    Rejected {
        /// The peer that delivered it.
        from: Option<PeerId>,
        /// Why it was rejected.
        reason: String,
    },
    /// A well-formed envelope that was not a `Decide` (a vote, timeout, and so
    /// on). Only `Decide` carries finality, so these are counted, not verified.
    NonDecide {
        /// The peer that delivered it.
        from: Option<PeerId>,
    },
    /// The observer joined the v4 topic.
    Subscribed,
    /// A fleet member connected.
    PeerConnected(PeerId),
    /// A fleet member went away.
    PeerDisconnected(PeerId),
    /// A listen address became active.
    Listening(Multiaddr),
    /// A peer completed the gov5 status handshake with us. Until this happens
    /// the connection is on borrowed time.
    StatusExchanged {
        /// The peer.
        peer: PeerId,
        /// Their reported genesis hash.
        genesis_hash: alloy_primitives::B256,
        /// Their reported head height.
        height: u64,
        /// Whether their fork digest matches the chain this observer follows.
        /// A mismatch means gov5 will send goodbye — the chain is simply not
        /// the one configured here.
        fork_matches: bool,
    },
    /// An outbound dial failed. Surfaced rather than swallowed: when an
    /// observer sits there reporting nothing, the operator needs to know
    /// whether it is connected and idle or never connected at all.
    DialFailed {
        /// The peer that could not be reached, when the address named one.
        peer: Option<PeerId>,
        /// Why the dial failed.
        reason: String,
    },
}

#[derive(NetworkBehaviour)]
struct ObserverBehaviour {
    gossipsub: gossipsub::Behaviour,
    /// gov5 drops peers that cannot answer a status request, so this is not
    /// optional decoration — without it the connection dies within seconds.
    status: StatusBehaviour,
}

/// A read-only follower of a gov5 HotStuff-2 v4 fleet.
pub struct H2V4Observer {
    swarm: Swarm<ObserverBehaviour>,
    topic: IdentTopic,
    identity: H2V4ChainIdentity,
    validators: ValidatorSet,
    mesh_peers: HashSet<PeerId>,
    /// Events produced before the loop starts (dials that failed immediately).
    pending_events: Vec<ObserverEvent>,
    /// The head height this observer advertises in its own status messages.
    advertised_height: u64,
}

impl H2V4Observer {
    /// Builds an observer with a freshly generated identity.
    pub fn new(config: ObserverConfig, validators: ValidatorSet) -> Result<Self, ObserverError> {
        Self::with_keypair(config, validators, Keypair::generate_ed25519())
    }

    /// Builds an observer with a caller-supplied libp2p identity. Use this when
    /// the fleet gates inbound connections on a known peer id.
    pub fn with_keypair(
        config: ObserverConfig,
        validators: ValidatorSet,
        keypair: Keypair,
    ) -> Result<Self, ObserverError> {
        let gossipsub_config = gov5_gossipsub_config(config.identity.genesis_hash)
            .map_err(ObserverError::Config)?;

        // Anonymous authorship is required, not preferred: gov5 runs
        // StrictNoSign + NoAuthor, so a signed message from this node would be
        // rejected outright by every fleet member.
        let behaviour = ObserverBehaviour {
            gossipsub: gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, gossipsub_config)
                .map_err(|e| ObserverError::Behaviour(e.to_string()))?,
            status: status_behaviour(),
        };

        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                Default::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| ObserverError::Transport(e.to_string()))?
            .with_behaviour(|_| behaviour)
            .map_err(|e| ObserverError::Behaviour(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(config.idle_connection_timeout))
            .build();

        let topic = h2_v4_topic();
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|source| ObserverError::Subscribe {
                topic: topic.to_string(),
                source,
            })?;

        for addr in &config.listen_addrs {
            swarm
                .listen_on(addr.clone())
                .map_err(|source| ObserverError::Listen {
                    addr: addr.clone(),
                    source,
                })?;
        }
        let mut dial_errors = Vec::new();
        for addr in &config.bootstrap_peers {
            // A failed dial is not fatal — fleet members come and go, and
            // gossipsub uses whichever peers do connect — but it is reported,
            // because a silent dial failure looks exactly like an idle fleet.
            if let Err(error) = swarm.dial(addr.clone()) {
                dial_errors.push(ObserverEvent::DialFailed {
                    peer: None,
                    reason: format!("{addr}: {error}"),
                });
            }
        }

        Ok(Self {
            swarm,
            topic,
            identity: config.identity,
            validators,
            mesh_peers: HashSet::new(),
            pending_events: dial_errors,
            advertised_height: 0,
        })
    }

    /// This observer's peer id — hand it to the fleet if it gates inbound peers.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Peers currently connected.
    pub fn connected_peers(&self) -> usize {
        self.mesh_peers.len()
    }

    /// Dials an additional fleet member.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.swarm.dial(addr)
    }

    /// Replaces the validator set — call this at an epoch boundary. The first
    /// v4 profile mandates a static set, so on a v4 chain this should not be
    /// needed until the dynamic-changes revision is specified on both sides.
    pub fn set_validators(&mut self, validators: ValidatorSet) {
        self.validators = validators;
    }

    /// Drives the swarm until something worth reporting happens.
    ///
    /// Returns `None` only if the swarm stream ends, which it does not do in
    /// normal operation.
    pub async fn next_event(&mut self) -> Option<ObserverEvent> {
        if !self.pending_events.is_empty() {
            return Some(self.pending_events.remove(0));
        }
        loop {
            let event = self.swarm.select_next_some().await;
            match event {
                SwarmEvent::Behaviour(ObserverBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { message, .. },
                )) => {
                    if message.topic != self.topic.hash() {
                        continue;
                    }
                    return Some(self.handle_payload(message.source, &message.data));
                }
                SwarmEvent::Behaviour(ObserverBehaviourEvent::Gossipsub(
                    gossipsub::Event::Subscribed { topic, .. },
                )) if topic == self.topic.hash() => {
                    return Some(ObserverEvent::Subscribed);
                }
                SwarmEvent::Behaviour(ObserverBehaviourEvent::Status(
                    request_response::Event::Message { peer, message, .. },
                )) => {
                    if let Some(event) = self.handle_status_message(peer, message) {
                        return Some(event);
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    // Ask for their status as soon as we connect. gov5 also
                    // initiates, but asking makes the exchange symmetric and
                    // gives us their head without waiting to be asked.
                    let our_status = self.our_status();
                    self.swarm
                        .behaviour_mut()
                        .status
                        .send_request(&peer_id, our_status);
                    if self.mesh_peers.insert(peer_id) {
                        return Some(ObserverEvent::PeerConnected(peer_id));
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    num_established: 0,
                    ..
                } => {
                    if self.mesh_peers.remove(&peer_id) {
                        return Some(ObserverEvent::PeerDisconnected(peer_id));
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Some(ObserverEvent::Listening(address));
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    return Some(ObserverEvent::DialFailed {
                        peer: peer_id,
                        reason: error.to_string(),
                    });
                }
                _ => {}
            }
        }
    }

    /// The status this observer advertises.
    ///
    /// It reports the configured chain's genesis hash, which is what gov5's
    /// fork-digest check actually compares. Height is whatever the caller set
    /// via [`Self::set_advertised_height`] — an observer that has not synced
    /// anything honestly reports 0 rather than mirroring the peer's height back
    /// at them.
    fn our_status(&self) -> Status {
        Status::new(self.identity.genesis_hash, self.advertised_height)
    }

    /// Sets the head height advertised to peers.
    pub fn set_advertised_height(&mut self, height: u64) {
        self.advertised_height = height;
    }

    /// Answers an inbound status request and reports what a peer told us.
    fn handle_status_message(
        &mut self,
        peer: PeerId,
        message: request_response::Message<Status, Status>,
    ) -> Option<ObserverEvent> {
        let (their_status, channel) = match message {
            request_response::Message::Request {
                request, channel, ..
            } => (request, Some(channel)),
            request_response::Message::Response { response, .. } => (response, None),
        };

        // Answer before judging: gov5 responds to a mismatched peer with its own
        // status and only then disconnects, so the peer learns *why* it was
        // dropped instead of seeing a bare stream reset.
        if let Some(channel) = channel {
            let our_status = self.our_status();
            let _ = self
                .swarm
                .behaviour_mut()
                .status
                .send_response(channel, our_status);
        }

        let ours = self.our_status();
        Some(ObserverEvent::StatusExchanged {
            peer,
            genesis_hash: their_status.genesis_hash,
            height: their_status.height(),
            fork_matches: their_status.fork_digest() == ours.fork_digest(),
        })
    }

    /// Decodes and verifies one gossip payload.
    ///
    /// Split out from the event loop so it can be tested without a network:
    /// this is where the whole cross-client contract actually lands.
    pub fn handle_payload(&self, from: Option<PeerId>, data: &[u8]) -> ObserverEvent {
        let envelope = match decode_gossip(data, self.identity) {
            Ok(envelope) => envelope,
            Err(err) => {
                return ObserverEvent::Rejected {
                    from,
                    reason: format!("envelope: {err}"),
                }
            }
        };

        if !matches!(envelope.message, H2Message::Decide(_)) {
            return ObserverEvent::NonDecide { from };
        }

        match verify_h2_v4_decide(&envelope, &self.validators) {
            Ok(proof) => ObserverEvent::Finality {
                from,
                view: proof.view,
                block_hash: proof.block_hash,
                changes_hash: proof.changes_hash,
            },
            Err(err) => ObserverEvent::Rejected {
                from,
                reason: format!("finality: {err}"),
            },
        }
    }
}

impl std::fmt::Debug for H2V4Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2V4Observer")
            .field("local_peer_id", self.swarm.local_peer_id())
            .field("topic", &self.topic.to_string())
            .field("chain_id", &self.identity.chain_id)
            .field("validators", &self.validators.len())
            .field("connected_peers", &self.mesh_peers.len())
            .finish()
    }
}

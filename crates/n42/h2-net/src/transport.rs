// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The GossipSub transport a Rust node uses to speak HotStuff-2 v4 with a gov5
//! fleet, in both directions.
//!
//! This carries the mesh, the `/rpc/status/1/ssz_snappy` handshake, and the
//! envelope codec, and it hands decoded envelopes up rather than judging them:
//! whether an envelope is a valid `Decide`, a vote worth counting, or a message
//! from a validator at all is a consensus question, answered above this layer by
//! [`n42_h2_consensus`]. What this layer does guarantee is chain binding — the
//! decoder rejects any envelope carrying a different chain id or genesis hash,
//! so cross-chain replay never reaches the caller.
//!
//! Publishing is anonymous by protocol, not by omission: gov5 runs
//! `StrictNoSign` + `NoAuthor`, so a libp2p-signed message from this node would
//! be rejected outright by every fleet member. Authentication of consensus
//! messages is BLS over the envelope preimage, carried inside the message.
//!
//! Transport matches gov5's host (`internal/p2p/options.go`): TCP with Noise and
//! Yamux. gov5 also listens on QUIC-v1; dialing it from here is possible but not
//! enabled by default, because a QUIC dial to a node that only advertises TCP
//! fails in a way that is easy to misread as a consensus problem.

use std::collections::{HashMap, HashSet};

use alloy_primitives::B256;
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::request_response;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity::Keypair, Multiaddr, PeerId, Swarm, SwarmBuilder};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_h2_wire::h2_v4::{decode_gossip, encode_gossip, H2V4Envelope, H2V4Error};

use crate::config::gov5_gossipsub_config;
use crate::rpc::{
    block_by_hash_behaviour, bodies_by_range_behaviour, status_behaviour, BlockByHashBehaviour,
    BlockChunk, BlockReply, BodiesByRangeBehaviour, RangeReply, RangeRequest, StatusBehaviour,
};
use crate::status::Status;
use crate::block_gossip::gov5_block_topic;
use crate::topic::{fork_scoped_topic, h2_v4_topic};
use n42_h2_wire::h2_wire::{decode_gov5_gossip_message, encode_gov5_gossip_message};
use n42_h2_wire::H2Message;

/// Errors that stop a transport from starting.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
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

/// Why an outbound message did not reach the mesh.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The envelope names a different chain than this transport follows.
    /// Publishing it would put a message on the wire that every fleet member —
    /// and this node itself — rejects, so it is refused here instead.
    #[error("envelope chain identity does not match the transport's")]
    IdentityMismatch,
    /// The envelope could not be encoded.
    #[error("encode envelope: {0}")]
    Encode(#[from] H2V4Error),
    /// gossipsub refused the message. The common case on a healthy node is
    /// [`gossipsub::PublishError::NoPeersSubscribedToTopic`], which means the
    /// mesh has not formed yet — a retry once peers connect is the right
    /// response, not an error to the operator.
    #[error("publish to mesh: {0}")]
    Gossipsub(#[from] gossipsub::PublishError),
}

impl PublishError {
    /// Whether the message is already on the wire.
    ///
    /// gossipsub dedupes by message id, and gov5's id is a hash of the payload,
    /// so re-sending an identical message is refused as a duplicate. That is
    /// success from the sender's point of view — the fleet has the message —
    /// and consensus engines re-broadcast on purpose, so treating it as a
    /// failure buries the real ones in noise.
    pub const fn is_already_published(&self) -> bool {
        matches!(self, Self::Gossipsub(gossipsub::PublishError::Duplicate))
    }

    /// Whether retrying once the mesh has peers is likely to succeed.
    ///
    /// A node that comes up before the fleet does hits this on every send until
    /// its first mesh peer appears, so callers need to distinguish it from a
    /// message that will never be publishable.
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Gossipsub(
                gossipsub::PublishError::NoPeersSubscribedToTopic
                    | gossipsub::PublishError::AllQueuesFull(_)
            )
        )
    }
}

/// How a transport is wired to a fleet.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// The chain this transport accepts and emits envelopes for. Envelopes
    /// carrying any other chain id or genesis hash are rejected by the decoder,
    /// so this is the primary defence against cross-chain replay.
    pub identity: H2V4ChainIdentity,
    /// Addresses to listen on. A node can follow a fleet by dialing out only,
    /// but a validator should listen: fleet members dial back, and a validator
    /// that cannot be reached will miss votes addressed to it.
    pub listen_addrs: Vec<Multiaddr>,
    /// Fleet members to dial on startup, as full multiaddrs including `/p2p/<peer id>`.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Idle connection timeout. gov5 keeps fleet connections long-lived.
    pub idle_connection_timeout: Duration,
}

impl TransportConfig {
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

/// Where the answer to a [`TransportEvent::BlockRequest`] goes.
#[derive(Debug)]
pub struct BlockRequestChannel(request_response::ResponseChannel<BlockReply>);

/// Where the answer to a [`TransportEvent::RangeRequest`] goes.
#[derive(Debug)]
pub struct RangeRequestChannel(request_response::ResponseChannel<RangeReply>);

/// What the transport saw.
#[derive(Debug)]
pub enum TransportEvent {
    /// A chain-bound envelope that decoded cleanly. Not verified: the BLS
    /// signatures inside are checked by the consensus layer, which is also the
    /// only layer that knows the current validator set.
    Envelope {
        /// The peer that delivered it. gov5 publishes with `NoAuthor`, so this
        /// is `None` for fleet traffic; it is populated only if some peer
        /// publishes with authorship, which a v4 fleet does not.
        from: Option<PeerId>,
        /// The decoded envelope.
        envelope: Box<H2V4Envelope>,
    },
    /// A payload that did not decode as an envelope for this chain. Worth
    /// surfacing rather than dropping: on a healthy fleet this should never
    /// fire, so it is a signal.
    Rejected {
        /// The peer that delivered it.
        from: Option<PeerId>,
        /// Why it was rejected.
        reason: String,
    },
    /// A consensus message from the chain's native topic —
    /// `/n42/<fork digest>/hotstuff_consensus/ssz_snappy`, where a gov5 fleet
    /// runs its consensus. Native encoding, no chain-bound envelope: the
    /// topic is already chain-scoped by its fork digest. Signatures are
    /// verified by the consensus layer, as for [`Self::Envelope`].
    Native {
        /// The peer that delivered it, when authored.
        from: Option<PeerId>,
        /// The decoded message.
        message: Box<H2Message>,
    },
    /// A peer asked for a block by hash (gov5's fetch-on-miss). Answer with
    /// [`H2V4Transport::respond_block`]; every request must be answered, a
    /// dropped channel leaves the peer waiting out its timeout.
    BlockRequest {
        /// Who asked.
        peer: PeerId,
        /// The block they want.
        hash: B256,
        /// Where the answer goes.
        channel: BlockRequestChannel,
    },
    /// A block this node asked for came back — or the peer said no.
    BlockFetched {
        /// Who answered.
        peer: PeerId,
        /// The block asked for.
        hash: B256,
        /// The block, or the peer's error.
        reply: BlockReply,
    },
    /// A block request never got an answer.
    BlockFetchFailed {
        /// Who was asked.
        peer: PeerId,
        /// The block asked for.
        hash: B256,
        /// Why.
        reason: String,
    },
    /// A peer asked for a range of blocks by number (gov5's range sync,
    /// how a member that starts behind catches up). Answer with
    /// [`H2V4Transport::respond_range`].
    RangeRequest {
        /// Who asked.
        peer: PeerId,
        /// What they want.
        request: RangeRequest,
        /// Where the answer goes.
        channel: RangeRequestChannel,
    },
    /// A range this node asked for came back — or the peer said no.
    RangeFetched {
        /// Who answered.
        peer: PeerId,
        /// What was asked.
        request: RangeRequest,
        /// The blocks, in order, or the peer's error.
        reply: RangeReply,
    },
    /// A block body arrived on the chain's block topic, still compressed.
    /// Which header shapes to accept is the consumer's decision — see
    /// [`crate::block_gossip::HeaderProfile`] — so it is not decoded here.
    Block {
        /// The peer that delivered it, when authored.
        from: Option<PeerId>,
        /// The raw-snappy payload.
        data: Vec<u8>,
    },
    /// The transport joined the v4 topic.
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
        /// Whether their fork digest matches the chain this node follows.
        /// A mismatch means gov5 will send goodbye — the chain is simply not
        /// the one configured here.
        fork_matches: bool,
    },
    /// An outbound dial failed. Surfaced rather than swallowed: when a node
    /// sits there reporting nothing, the operator needs to know whether it is
    /// connected and idle or never connected at all.
    DialFailed {
        /// The peer that could not be reached, when the address named one.
        peer: Option<PeerId>,
        /// Why the dial failed.
        reason: String,
    },
}

/// What this node says it is, in the identify exchange. gov5 does not check
/// the string; it checks the protocol list that comes with it.
pub const IDENTIFY_PROTOCOL_VERSION: &str = "/n42/h2/1.0.0";

#[derive(NetworkBehaviour)]
pub(crate) struct H2Behaviour {
    gossipsub: gossipsub::Behaviour,
    /// gov5 drops peers that cannot answer a status request, so this is not
    /// optional decoration — without it the connection dies within seconds.
    status: StatusBehaviour,
    /// gov5's fetch-on-miss: how a member that missed a body, or holds a
    /// competing sibling, catches up. Served from the bodies the consensus
    /// layer keeps; a fleet member that does not answer leaves a Go peer
    /// behind for good.
    blocks: BlockByHashBehaviour,
    /// gov5's range sync, served from the execution layer's chain.
    ranges: BodiesByRangeBehaviour,
    /// Not decoration either. go-libp2p-pubsub learns which peers speak
    /// gossipsub from the identify exchange (`EvtPeerIdentificationCompleted`,
    /// `peer_notify.go`): a peer that connects after startup and never
    /// identifies is never given a gossipsub stream, never sent the Go
    /// node's subscriptions, and never counted as a topic peer — connected,
    /// status-exchanged, and invisible to consensus. Observed live: three Rust
    /// members connected to a gov5 node for a minute without a single
    /// gossipsub RPC in either direction.
    identify: libp2p::identify::Behaviour,
}

/// A bidirectional member of a gov5 HotStuff-2 v4 gossip mesh.
pub struct H2V4Transport {
    swarm: Swarm<H2Behaviour>,
    topic: IdentTopic,
    /// Where block bodies travel; bound to the chain by its fork digest.
    block_topic: IdentTopic,
    /// gov5's own consensus topic, likewise fork-scoped.
    native_topic: IdentTopic,
    identity: H2V4ChainIdentity,
    mesh_peers: HashSet<PeerId>,
    /// Events produced before the loop starts (dials that failed immediately).
    pending_events: Vec<TransportEvent>,
    /// Block requests this node sent, by request id, so the answer can be
    /// matched to the hash it was for.
    block_requests: HashMap<request_response::OutboundRequestId, B256>,
    /// Range requests this node sent, by request id.
    range_requests: HashMap<request_response::OutboundRequestId, RangeRequest>,
    /// The head height this node advertises in its own status messages.
    advertised_height: u64,
}

impl H2V4Transport {
    /// Builds a transport with a freshly generated identity.
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        Self::with_keypair(config, Keypair::generate_ed25519())
    }

    /// Builds a transport with a caller-supplied libp2p identity. Use this when
    /// the fleet gates inbound connections on a known peer id, which a
    /// validator's fleet generally does.
    pub fn with_keypair(
        config: TransportConfig,
        keypair: Keypair,
    ) -> Result<Self, TransportError> {
        let gossipsub_config =
            gov5_gossipsub_config(config.identity.genesis_hash).map_err(TransportError::Config)?;

        // Anonymous authorship is required, not preferred: gov5 runs
        // StrictNoSign + NoAuthor, so a signed message from this node would be
        // rejected outright by every fleet member.
        let behaviour = H2Behaviour {
            gossipsub: gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, gossipsub_config)
                .map_err(|e| TransportError::Behaviour(e.to_string()))?,
            status: status_behaviour(),
            blocks: block_by_hash_behaviour(),
            ranges: bodies_by_range_behaviour(),
            identify: libp2p::identify::Behaviour::new(
                libp2p::identify::Config::new(IDENTIFY_PROTOCOL_VERSION.into(), keypair.public())
                    .with_agent_version(format!("n42-rs/h2-net/{}", env!("CARGO_PKG_VERSION"))),
            ),
        };

        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                Default::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| TransportError::Transport(e.to_string()))?
            .with_behaviour(|_| behaviour)
            .map_err(|e| TransportError::Behaviour(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(config.idle_connection_timeout))
            .build();

        let topic = h2_v4_topic();
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|source| TransportError::Subscribe {
                topic: topic.to_string(),
                source,
            })?;
        // Bodies travel separately from proposals; a validator that joins only
        // the consensus topic hears every proposal and can vote on none.
        let block_topic = gov5_block_topic(config.identity.genesis_hash);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&block_topic)
            .map_err(|source| TransportError::Subscribe {
                topic: block_topic.to_string(),
                source,
            })?;
        // gov5's consensus runs on its fork-scoped native topic; the v4
        // topic carries only Decide proofs for observers. A fleet member
        // has to be on both to hear a Go leader's proposals.
        let native_topic = fork_scoped_topic(config.identity.genesis_hash, "hotstuff_consensus");
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&native_topic)
            .map_err(|source| TransportError::Subscribe {
                topic: native_topic.to_string(),
                source,
            })?;

        for addr in &config.listen_addrs {
            swarm
                .listen_on(addr.clone())
                .map_err(|source| TransportError::Listen {
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
                dial_errors.push(TransportEvent::DialFailed {
                    peer: None,
                    reason: format!("{addr}: {error}"),
                });
            }
        }

        Ok(Self {
            swarm,
            topic,
            block_topic,
            native_topic,
            identity: config.identity,
            mesh_peers: HashSet::new(),
            pending_events: dial_errors,
            block_requests: HashMap::new(),
            range_requests: HashMap::new(),
            advertised_height: 0,
        })
    }

    /// This node's peer id — hand it to the fleet if it gates inbound peers.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Peers currently connected.
    pub fn connected_peers(&self) -> usize {
        self.mesh_peers.len()
    }

    /// Peers that have this node in their gossip mesh for the v4 topic.
    ///
    /// This, not [`Self::connected_peers`], is what determines whether a publish
    /// can succeed: a connected peer that has not meshed will not relay.
    pub fn mesh_size(&self) -> usize {
        self.swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&self.topic.hash())
            .count()
    }

    /// The chain this transport is bound to.
    pub const fn identity(&self) -> H2V4ChainIdentity {
        self.identity
    }

    /// Dials an additional fleet member.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.swarm.dial(addr)
    }

    /// Sets the head height advertised to peers.
    pub fn set_advertised_height(&mut self, height: u64) {
        self.advertised_height = height;
    }

    /// Publishes a consensus envelope to the fleet.
    ///
    /// The envelope must name the chain this transport is bound to; a mismatch
    /// is refused rather than sent, because such a message would be dropped by
    /// every recipient and by this node's own decoder, making the resulting
    /// silence very hard to diagnose.
    pub fn publish(
        &mut self,
        envelope: &H2V4Envelope,
    ) -> Result<gossipsub::MessageId, PublishError> {
        if envelope.identity != self.identity {
            return Err(PublishError::IdentityMismatch);
        }
        let payload = encode_gossip(envelope)?;
        Ok(self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), payload)?)
    }

    /// Publishes a consensus message on the chain's native topic, in gov5's
    /// own encoding — what a Go fleet member listens for.
    pub fn publish_native(&mut self, message: &H2Message) -> Result<gossipsub::MessageId, PublishError> {
        let payload = encode_gov5_gossip_message(message)
            .map_err(|e| PublishError::Encode(n42_h2_wire::H2V4Error::Wire(e)))?;
        Ok(self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.native_topic.clone(), payload)?)
    }

    /// Peers in this node's mesh for the native consensus topic.
    pub fn native_mesh_size(&self) -> usize {
        self.swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&self.native_topic.hash())
            .count()
    }

    /// Peers currently connected, for asking them things.
    pub fn connected_peer_ids(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    /// Asks `peer` for a block by hash. The answer arrives as
    /// [`TransportEvent::BlockFetched`] or [`TransportEvent::BlockFetchFailed`].
    pub fn request_block(&mut self, peer: PeerId, hash: B256) {
        let id = self.swarm.behaviour_mut().blocks.send_request(&peer, hash);
        self.block_requests.insert(id, hash);
    }

    /// Asks `peer` for a range of blocks. The answer arrives as
    /// [`TransportEvent::RangeFetched`].
    pub fn request_range(&mut self, peer: PeerId, request: RangeRequest) {
        let id = self.swarm.behaviour_mut().ranges.send_request(&peer, request);
        self.range_requests.insert(id, request);
    }

    /// Answers a [`TransportEvent::RangeRequest`] with the blocks this node
    /// has, in order — as many as it could find from the start, which is
    /// how gov5 serves a range it only partly holds.
    pub fn respond_range(&mut self, channel: RangeRequestChannel, rlps: Vec<Vec<u8>>) {
        let fork_digest = self.our_status().fork_digest();
        let chunks = rlps
            .into_iter()
            .map(|rlp| BlockChunk { fork_digest, rlp })
            .collect();
        let _ = self.swarm.behaviour_mut().ranges.send_response(channel.0, Ok(chunks));
    }

    /// Answers a [`TransportEvent::BlockRequest`]: the block's gov5 RLP, or
    /// gov5's "not found" when this node does not have it.
    pub fn respond_block(&mut self, channel: BlockRequestChannel, rlp: Option<Vec<u8>>) {
        let reply = match rlp {
            Some(rlp) => Ok(BlockChunk {
                fork_digest: self.our_status().fork_digest(),
                rlp,
            }),
            None => Err("block not found".to_owned()),
        };
        // A closed channel means the peer went away; nothing to do about it.
        let _ = self.swarm.behaviour_mut().blocks.send_response(channel.0, reply);
    }

    /// Publishes an already-encoded block body on the chain's block topic.
    ///
    /// Takes the compressed bytes from [`crate::block_gossip::encode_block_gossip`]
    /// rather than a payload, so the profile decision stays with the caller.
    pub fn publish_block(&mut self, data: Vec<u8>) -> Result<gossipsub::MessageId, PublishError> {
        Ok(self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.block_topic.clone(), data)?)
    }

    /// Drives the swarm until something worth reporting happens.
    ///
    /// Returns `None` only if the swarm stream ends, which it does not do in
    /// normal operation.
    pub async fn next_event(&mut self) -> Option<TransportEvent> {
        if !self.pending_events.is_empty() {
            return Some(self.pending_events.remove(0));
        }
        loop {
            let event = self.swarm.select_next_some().await;
            match event {
                SwarmEvent::Behaviour(H2BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    if message.topic == self.block_topic.hash() {
                        return Some(TransportEvent::Block {
                            from: message.source,
                            data: message.data,
                        });
                    }
                    if message.topic == self.native_topic.hash() {
                        return Some(match decode_gov5_gossip_message(&message.data) {
                            Ok(decoded) => TransportEvent::Native {
                                from: message.source,
                                message: Box::new(decoded),
                            },
                            Err(err) => TransportEvent::Rejected {
                                from: message.source,
                                reason: format!("native message: {err}"),
                            },
                        });
                    }
                    if message.topic != self.topic.hash() {
                        continue;
                    }
                    return Some(self.decode_payload(message.source, &message.data));
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Gossipsub(
                    gossipsub::Event::Subscribed { peer_id, topic },
                )) => {
                    tracing::debug!(target: "n42.h2.net", %peer_id, %topic, "peer subscribed");
                    if topic == self.topic.hash() {
                        return Some(TransportEvent::Subscribed);
                    }
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Gossipsub(
                    gossipsub::Event::Unsubscribed { peer_id, topic },
                )) => {
                    tracing::debug!(target: "n42.h2.net", %peer_id, %topic, "peer unsubscribed");
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Gossipsub(
                    gossipsub::Event::GossipsubNotSupported { peer_id },
                )) => {
                    // A peer this node cannot gossip with is a peer that will
                    // never hear a proposal: worth more than a debug line.
                    tracing::warn!(target: "n42.h2.net", %peer_id, "peer does not support gossipsub");
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Identify(
                    libp2p::identify::Event::Received { peer_id, info, .. },
                )) => {
                    tracing::debug!(
                        target: "n42.h2.net",
                        %peer_id, agent = %info.agent_version, protocols = info.protocols.len(),
                        "peer identified",
                    );
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Identify(_)) => {}
                SwarmEvent::Behaviour(H2BehaviourEvent::Blocks(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        return Some(TransportEvent::BlockRequest {
                            peer,
                            hash: request,
                            channel: BlockRequestChannel(channel),
                        });
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        if let Some(hash) = self.block_requests.remove(&request_id) {
                            return Some(TransportEvent::BlockFetched {
                                peer,
                                hash,
                                reply: response,
                            });
                        }
                    }
                },
                SwarmEvent::Behaviour(H2BehaviourEvent::Blocks(
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    },
                )) => {
                    if let Some(hash) = self.block_requests.remove(&request_id) {
                        return Some(TransportEvent::BlockFetchFailed {
                            peer,
                            hash,
                            reason: error.to_string(),
                        });
                    }
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Blocks(_)) => {}
                SwarmEvent::Behaviour(H2BehaviourEvent::Ranges(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        return Some(TransportEvent::RangeRequest {
                            peer,
                            request,
                            channel: RangeRequestChannel(channel),
                        });
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        if let Some(request) = self.range_requests.remove(&request_id) {
                            return Some(TransportEvent::RangeFetched {
                                peer,
                                request,
                                reply: response,
                            });
                        }
                    }
                },
                SwarmEvent::Behaviour(H2BehaviourEvent::Ranges(
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    },
                )) => {
                    if let Some(request) = self.range_requests.remove(&request_id) {
                        return Some(TransportEvent::RangeFetched {
                            peer,
                            request,
                            reply: Err(error.to_string()),
                        });
                    }
                }
                SwarmEvent::Behaviour(H2BehaviourEvent::Ranges(_)) => {}
                SwarmEvent::Behaviour(H2BehaviourEvent::Status(
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
                        return Some(TransportEvent::PeerConnected(peer_id));
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    num_established: 0,
                    ..
                } => {
                    if self.mesh_peers.remove(&peer_id) {
                        return Some(TransportEvent::PeerDisconnected(peer_id));
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Some(TransportEvent::Listening(address));
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    return Some(TransportEvent::DialFailed {
                        peer: peer_id,
                        reason: error.to_string(),
                    });
                }
                _ => {}
            }
        }
    }

    /// The status this node advertises.
    ///
    /// It reports the configured chain's genesis hash, which is what gov5's
    /// fork-digest check actually compares. Height is whatever the caller set
    /// via [`Self::set_advertised_height`] — a node that has not synced
    /// anything honestly reports 0 rather than mirroring the peer's height back
    /// at them.
    fn our_status(&self) -> Status {
        Status::new(self.identity.genesis_hash, self.advertised_height)
    }

    /// Answers an inbound status request and reports what a peer told us.
    fn handle_status_message(
        &mut self,
        peer: PeerId,
        message: request_response::Message<Status, Status>,
    ) -> Option<TransportEvent> {
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
        Some(TransportEvent::StatusExchanged {
            peer,
            genesis_hash: their_status.genesis_hash,
            height: their_status.height(),
            fork_matches: their_status.fork_digest() == ours.fork_digest(),
        })
    }

    /// Decodes one gossip payload.
    ///
    /// Split out from the event loop so it can be tested without a network:
    /// this is where the chain-binding half of the cross-client contract lands.
    pub fn decode_payload(&self, from: Option<PeerId>, data: &[u8]) -> TransportEvent {
        match decode_gossip(data, self.identity) {
            Ok(envelope) => TransportEvent::Envelope {
                from,
                envelope: Box::new(envelope),
            },
            Err(err) => TransportEvent::Rejected {
                from,
                reason: format!("envelope: {err}"),
            },
        }
    }
}

impl std::fmt::Debug for H2V4Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2V4Transport")
            .field("local_peer_id", self.swarm.local_peer_id())
            .field("topic", &self.topic.to_string())
            .field("chain_id", &self.identity.chain_id)
            .field("connected_peers", &self.mesh_peers.len())
            .finish()
    }
}

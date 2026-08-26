// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A read-only observer that follows a gov5 fleet's finality over gossip.
//!
//! This is [`H2V4Transport`] with the send half left unused: it subscribes to
//! `/n42/h2/4/ssz_snappy`, decodes each chain-bound v4 envelope, and verifies
//! the committed `Decide` against a validator set. It never votes, never
//! proposes, and never publishes — a node running this is invisible to
//! consensus and cannot affect liveness or safety of the fleet it watches. That
//! is a property of this type, not of the transport: `H2V4Observer` simply
//! exposes no way to publish.
//!
//! It is the right thing to run when following a fleet is all that is wanted:
//! sync targets, monitoring, a mobile verifier's finality feed. A node that is
//! meant to participate wants [`H2V4Transport`] and the consensus engine above
//! it instead.

use libp2p::{identity::Keypair, Multiaddr, PeerId};
use n42_h2_consensus::{h2_finality::verify_h2_v4_decide, ValidatorSet};
use n42_h2_wire::H2Message;

use crate::transport::{H2V4Transport, TransportEvent};

/// Errors that stop an observer from starting.
pub type ObserverError = crate::transport::TransportError;

/// How an observer is wired to a fleet.
pub type ObserverConfig = crate::transport::TransportConfig;

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

/// A read-only follower of a gov5 HotStuff-2 v4 fleet.
#[derive(Debug)]
pub struct H2V4Observer {
    transport: H2V4Transport,
    validators: ValidatorSet,
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
        Ok(Self {
            transport: H2V4Transport::with_keypair(config, keypair)?,
            validators,
        })
    }

    /// This observer's peer id — hand it to the fleet if it gates inbound peers.
    pub fn local_peer_id(&self) -> &PeerId {
        self.transport.local_peer_id()
    }

    /// Peers currently connected.
    pub fn connected_peers(&self) -> usize {
        self.transport.connected_peers()
    }

    /// Dials an additional fleet member.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.transport.dial(addr)
    }

    /// Replaces the validator set — call this at an epoch boundary. The first
    /// v4 profile mandates a static set, so on a v4 chain this should not be
    /// needed until the dynamic-changes revision is specified on both sides.
    pub fn set_validators(&mut self, validators: ValidatorSet) {
        self.validators = validators;
    }

    /// Sets the head height advertised to peers.
    pub fn set_advertised_height(&mut self, height: u64) {
        self.transport.set_advertised_height(height);
    }

    /// Drives the swarm until something worth reporting happens.
    ///
    /// Returns `None` only if the swarm stream ends, which it does not do in
    /// normal operation.
    pub async fn next_event(&mut self) -> Option<ObserverEvent> {
        let event = self.transport.next_event().await?;
        Some(self.classify(event))
    }

    /// Decodes and verifies one gossip payload.
    ///
    /// Split out from the event loop so it can be tested without a network:
    /// this is where the whole cross-client contract actually lands.
    pub fn handle_payload(&self, from: Option<PeerId>, data: &[u8]) -> ObserverEvent {
        self.classify(self.transport.decode_payload(from, data))
    }

    /// Turns a transport event into what an observer cares about: finality, and
    /// everything else.
    fn classify(&self, event: TransportEvent) -> ObserverEvent {
        match event {
            TransportEvent::Envelope { from, envelope } => {
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
            TransportEvent::Rejected { from, reason } => ObserverEvent::Rejected { from, reason },
            // A block body is fleet traffic, not finality: an observer watches
            // for Decide and does not execute blocks.
            TransportEvent::Block { from, .. } => ObserverEvent::NonDecide { from },
            TransportEvent::Subscribed => ObserverEvent::Subscribed,
            TransportEvent::PeerConnected(peer) => ObserverEvent::PeerConnected(peer),
            TransportEvent::PeerDisconnected(peer) => ObserverEvent::PeerDisconnected(peer),
            TransportEvent::Listening(addr) => ObserverEvent::Listening(addr),
            TransportEvent::StatusExchanged {
                peer,
                genesis_hash,
                height,
                fork_matches,
            } => ObserverEvent::StatusExchanged {
                peer,
                genesis_hash,
                height,
                fork_matches,
            },
            TransportEvent::DialFailed { peer, reason } => {
                ObserverEvent::DialFailed { peer, reason }
            }
        }
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loop that makes a Rust node a participating member of a gov5 fleet.
//!
//! Three pieces already existed and did not touch each other: the gossip
//! transport ([`n42_h2_net::H2V4Transport`]), the HotStuff-2 engine
//! ([`n42_h2_consensus::ConsensusEngine`]), and the execution driver
//! ([`n42_h2_execution::ExecutionDriver`]). This is the seam between them —
//! inbound envelopes become consensus events, engine outputs become published
//! envelopes and execution calls, and what the execution layer says comes back
//! as more consensus events.
//!
//! **Draining is not optional.** The engine emits into a bounded channel and
//! gives up after a fixed retry budget when nobody drains it, so an output can
//! be dropped if this loop is busy. Every branch below therefore drains the
//! engine's outputs to empty before returning to the select, rather than
//! treating the channel as one more thing to poll.
//!
//! **A leader has to be asked to build.** The engine proposes only when it is
//! handed a `BlockReady`, which comes from the execution layer, which needs
//! payload attributes this layer has no business inventing. So block production
//! is opt-in: supply [`H2Service::with_payload_attributes`] and this node
//! proposes when it is leader; leave it out and it votes but never proposes,
//! which is what a non-producing fleet member should do.
//!
//! **Startup is not a timeout.** A node that comes up before its mesh does
//! would otherwise spend its first views broadcasting timeouts to nobody and
//! arrive at the fleet already several views behind. The first view's clock
//! therefore does not start until there is at least one mesh peer to talk to.
//!
//! **Timeouts drive liveness.** A view that produces nothing advances only
//! because the pacemaker fires, so the sleep is armed from the pacemaker's own
//! deadline on every iteration. Dropping that arm is what turns a node that
//! looks connected into one that silently stops voting.

use std::time::Duration;

use alloy_primitives::B256;
use n42_h2_consensus::wire_bridge::{self, BridgeError};
use n42_h2_consensus::{ConsensusEngine, ConsensusEvent, EngineOutput};
use n42_h2_execution::{DriverAction, ExecutionDriver, ExecutionLayer};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_h2_net::{H2V4Transport, TransportEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How far the view deadline is pushed out on each step taken before the mesh
/// exists. Small enough that a mesh forming mid-step costs almost nothing,
/// large enough that it does not have to fire on every event.
const MESH_WAIT_STEP: Duration = Duration::from_millis(200);

/// Why the service stopped.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The transport's swarm ended, which it does not do in normal operation.
    #[error("gossip transport ended")]
    TransportEnded,
    /// The engine's output channel closed while the engine was still alive.
    #[error("consensus engine output channel closed")]
    OutputChannelClosed,
    /// The consensus engine returned a fatal error.
    #[error("consensus engine: {0}")]
    Engine(#[from] n42_h2_consensus::ConsensusError),
}

/// What the service is doing, for a caller that wants to watch without owning
/// the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceEvent {
    /// A block was committed by consensus and finalised in the execution layer.
    Committed {
        /// The view it was committed in.
        view: u64,
        /// The block.
        block_hash: B256,
    },
    /// This node published a consensus message.
    Published {
        /// The view the message referred to.
        view: u64,
    },
    /// Consensus wants a block whose body this node has never seen. The caller
    /// is responsible for fetching it and calling
    /// [`H2Service::cache_payload`]; until then the node cannot vote on it.
    PayloadMissing {
        /// The block that could not be executed.
        block_hash: B256,
    },
    /// The view advanced.
    ViewChanged {
        /// The view now current.
        new_view: u64,
    },
    /// This node is behind the fleet by more than the buffering window and
    /// needs to sync before it can contribute again.
    SyncRequired {
        /// The view this node is on.
        local_view: u64,
        /// The view the fleet is on.
        target_view: u64,
    },
}

/// Ties the gossip transport, the consensus engine, and the execution layer
/// together.
pub struct H2Service<E> {
    transport: H2V4Transport,
    engine: ConsensusEngine,
    driver: ExecutionDriver<E>,
    outputs: mpsc::Receiver<EngineOutput>,
    identity: H2V4ChainIdentity,
    /// The size the signer bitmaps on the wire are read against. A message
    /// whose certificates were signed by a differently-sized set is rejected
    /// rather than guessed at — see [`wire_bridge`].
    validator_count: usize,
    /// Messages the engine produced that the mesh would not accept yet. gossipsub
    /// refuses to publish before a mesh forms, which is the normal state of a
    /// node that started before its fleet, so these are retried rather than lost.
    outbox: Vec<n42_h2_primitives::consensus::ConsensusMessage>,
    /// Builds the payload attributes for a block this node proposes. `None`
    /// means this node never proposes — see the module docs.
    payload_attributes: Option<Box<dyn Fn(u64, B256) -> PayloadAttributes + Send + Sync>>,
    /// The view this node last built a block for, so a leader does not rebuild
    /// on every event it handles while still in the same view.
    proposed_view: Option<u64>,
    /// Whether the gossip mesh has ever had a peer. Until it does, the view
    /// clock is held off — see the module docs.
    meshed: bool,
}

impl<E> std::fmt::Debug for H2Service<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Service")
            .field("transport", &self.transport)
            .field("validator_count", &self.validator_count)
            .field("view", &self.engine.current_view())
            .field("proposes", &self.payload_attributes.is_some())
            .field("queued_messages", &self.outbox.len())
            .finish_non_exhaustive()
    }
}

impl<E: ExecutionLayer> H2Service<E> {
    /// Assembles a service from its three parts.
    ///
    /// `outputs` must be the receiver whose sender was handed to `engine`;
    /// without it the loop sees nothing the engine produces.
    pub fn new(
        transport: H2V4Transport,
        engine: ConsensusEngine,
        driver: ExecutionDriver<E>,
        outputs: mpsc::Receiver<EngineOutput>,
        validator_count: usize,
    ) -> Self {
        let identity = transport.identity();
        Self {
            transport,
            engine,
            driver,
            outputs,
            identity,
            validator_count,
            outbox: Vec::new(),
            payload_attributes: None,
            proposed_view: None,
            meshed: false,
        }
    }

    /// Makes this node produce blocks when it is leader.
    ///
    /// The closure is called with the view and the current head, and returns the
    /// attributes to build under. Without it the node votes on other members'
    /// proposals but never makes one — a valid way to run, and the safe default,
    /// since a node that proposes garbage is worse than one that proposes
    /// nothing.
    pub fn with_payload_attributes(
        mut self,
        attributes: impl Fn(u64, B256) -> PayloadAttributes + Send + Sync + 'static,
    ) -> Self {
        self.payload_attributes = Some(Box::new(attributes));
        self
    }

    /// The transport, for dialing more peers or reading mesh state.
    pub const fn transport(&self) -> &H2V4Transport {
        &self.transport
    }

    /// The transport, mutably.
    pub const fn transport_mut(&mut self) -> &mut H2V4Transport {
        &mut self.transport
    }

    /// The consensus engine.
    pub const fn engine(&self) -> &ConsensusEngine {
        &self.engine
    }

    /// Hands the driver a block body it asked for via
    /// [`ServiceEvent::PayloadMissing`].
    pub fn cache_payload(
        &mut self,
        block_hash: B256,
        payload: alloy_rpc_types_engine::ExecutionData,
    ) {
        self.driver.cache_payload(block_hash, payload);
    }

    /// Runs one iteration: waits for the next thing to happen, handles it, and
    /// drains everything it caused.
    ///
    /// Returns the events worth reporting. Callers that just want the node to
    /// run can loop on this and ignore the result.
    pub async fn step(&mut self) -> Result<Vec<ServiceEvent>, ServiceError> {
        let mut events = Vec::new();
        self.hold_view_clock_until_meshed();

        // Arm from the pacemaker every iteration rather than holding one sleep
        // across views: a commit resets the deadline, and a sleep armed for the
        // old view would fire late or not at all.
        let timeout = self.engine.pacemaker().timeout_sleep();
        tokio::pin!(timeout);

        tokio::select! {
            event = self.transport.next_event() => {
                let Some(event) = event else {
                    return Err(ServiceError::TransportEnded);
                };
                self.handle_transport_event(event)?;
            }
            output = self.outputs.recv() => {
                let Some(output) = output else {
                    return Err(ServiceError::OutputChannelClosed);
                };
                self.handle_output(output, &mut events).await?;
            }
            () = &mut timeout => {
                // A view that produced nothing advances only because of this.
                debug!(target: "n42.h2.node", view = self.engine.current_view(), "view timed out");
                self.engine.on_timeout()?;
            }
        }

        self.drain_outputs(&mut events).await?;
        self.propose_if_leader().await;
        // Proposing emits, so drain again rather than leaving a proposal to sit
        // in the channel until the next event arrives.
        self.drain_outputs(&mut events).await?;
        self.flush_outbox(&mut events);
        Ok(events)
    }

    /// Runs until the transport or the engine stops.
    pub async fn run(&mut self) -> Result<(), ServiceError> {
        loop {
            for event in self.step().await? {
                match event {
                    ServiceEvent::Committed { view, block_hash } => {
                        info!(target: "n42.h2.node", view, ?block_hash, "committed");
                    }
                    ServiceEvent::SyncRequired {
                        local_view,
                        target_view,
                    } => {
                        warn!(target: "n42.h2.node", local_view, target_view, "behind the fleet");
                    }
                    ServiceEvent::PayloadMissing { block_hash } => {
                        warn!(target: "n42.h2.node", ?block_hash, "block body not available");
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_transport_event(&mut self, event: TransportEvent) -> Result<(), ServiceError> {
        match event {
            TransportEvent::Envelope { envelope, .. } => {
                match wire_bridge::to_engine(&envelope, self.validator_count) {
                    Ok(message) => {
                        // A message that fails the engine's own checks is a
                        // peer problem, not a local one: log it and keep the
                        // node running rather than taking the fleet's word for
                        // when this process should stop.
                        if let Err(err) = self.engine.process_event(ConsensusEvent::Message(message))
                        {
                            debug!(target: "n42.h2.node", %err, "engine rejected a message");
                        }
                    }
                    Err(BridgeError::InvalidBitmap { .. }) => {
                        // Almost always a fleet running a different validator
                        // set size, which is a configuration problem worth
                        // seeing rather than a malformed-packet statistic.
                        warn!(
                            target: "n42.h2.node",
                            expected = self.validator_count,
                            "rejected a message whose signer bitmap does not match our validator set size",
                        );
                    }
                    Err(err) => {
                        debug!(target: "n42.h2.node", %err, "undecodable consensus message");
                    }
                }
            }
            TransportEvent::StatusExchanged {
                peer,
                height,
                fork_matches,
                ..
            } => {
                if fork_matches {
                    debug!(target: "n42.h2.node", %peer, height, "peer on our chain");
                } else {
                    // gov5 sends goodbye on a fork mismatch, so this connection
                    // is about to die and the operator needs to know why.
                    warn!(target: "n42.h2.node", %peer, "peer is on a different chain; it will disconnect");
                }
            }
            TransportEvent::PeerConnected(peer) => {
                debug!(target: "n42.h2.node", %peer, "peer connected");
            }
            TransportEvent::Rejected { reason, .. } => {
                debug!(target: "n42.h2.node", reason, "dropped a gossip payload");
            }
            TransportEvent::DialFailed { reason, .. } => {
                warn!(target: "n42.h2.node", reason, "dial failed");
            }
            _ => {}
        }
        Ok(())
    }

    /// Drains the engine's output channel to empty.
    ///
    /// Not a `while let Some(..) = recv().await` loop: that would block waiting
    /// for the *next* output rather than stopping when the channel runs dry.
    async fn drain_outputs(&mut self, events: &mut Vec<ServiceEvent>) -> Result<(), ServiceError> {
        while let Ok(output) = self.outputs.try_recv() {
            self.handle_output(output, events).await?;
        }
        Ok(())
    }

    async fn handle_output(
        &mut self,
        output: EngineOutput,
        events: &mut Vec<ServiceEvent>,
    ) -> Result<(), ServiceError> {
        // The execution driver sees every output and decides for itself which
        // ones concern it, so this does not have to duplicate that judgement.
        let action = self.driver.handle_output(&output).await;
        self.apply_driver_action(action, events)?;

        match output {
            // v4 has no direct-to-validator transport: a vote to the leader goes
            // over the same topic as everything else, and the leader picks it
            // out. Treating these differently would mean inventing a channel
            // gov5 does not have.
            EngineOutput::BroadcastMessage(message)
            | EngineOutput::SendToValidator(_, message) => {
                self.publish(message, events);
            }
            EngineOutput::BlockCommitted {
                view, block_hash, ..
            } => {
                events.push(ServiceEvent::Committed { view, block_hash });
            }
            EngineOutput::ViewChanged { new_view } => {
                events.push(ServiceEvent::ViewChanged { new_view });
            }
            EngineOutput::SyncRequired {
                local_view,
                target_view,
            } => {
                events.push(ServiceEvent::SyncRequired {
                    local_view,
                    target_view,
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Keeps the first view from timing out before the node has anyone to talk
    /// to.
    ///
    /// A timeout vote is only useful if peers receive it. Broadcasting into an
    /// empty mesh burns views: by the time the node meshes it has already voted
    /// to abandon several, and every peer it meets is ahead of it. Once a mesh
    /// peer appears the clock starts for real, from that moment.
    fn hold_view_clock_until_meshed(&mut self) {
        if self.meshed {
            return;
        }
        let view = self.engine.current_view();
        if self.transport.mesh_size() > 0 {
            self.meshed = true;
            self.engine.pacemaker_mut().reset_for_view(view, 0);
            debug!(target: "n42.h2.node", view, "mesh formed; view clock started");
            return;
        }
        self.engine.pacemaker_mut().extend_deadline(MESH_WAIT_STEP);
    }

    /// Builds and announces a block when this node is the leader of a view it
    /// has not yet proposed for.
    async fn propose_if_leader(&mut self) {
        let Some(build_attributes) = self.payload_attributes.as_ref() else {
            return;
        };
        let view = self.engine.current_view();
        if self.proposed_view == Some(view) || !self.engine.is_current_leader() {
            return;
        }
        // Marked before the build, not after: a build that fails should not be
        // retried on every subsequent event in the same view, which would pin
        // the loop against a broken execution layer.
        self.proposed_view = Some(view);

        let attrs = build_attributes(view, self.driver.head());
        match self.driver.build_block(attrs).await {
            Ok(built) => {
                debug!(target: "n42.h2.node", view, block = ?built.hash, txs = built.tx_count, "built a block to propose");
                if let Err(err) = self
                    .engine
                    .process_event(ConsensusEvent::BlockReady(built.hash, None))
                {
                    warn!(target: "n42.h2.node", %err, view, "engine refused our own block");
                }
            }
            Err(err) => {
                // The view will time out and move on; that is the correct
                // outcome for a leader that cannot produce.
                warn!(target: "n42.h2.node", %err, view, "could not build a block to propose");
            }
        }
    }

    fn apply_driver_action(
        &mut self,
        action: DriverAction,
        events: &mut Vec<ServiceEvent>,
    ) -> Result<(), ServiceError> {
        match action {
            DriverAction::Consensus(event) => {
                if let Err(err) = self.engine.process_event(*event) {
                    debug!(target: "n42.h2.node", %err, "engine rejected an execution event");
                }
            }
            DriverAction::PayloadMissing { block_hash } => {
                events.push(ServiceEvent::PayloadMissing { block_hash });
            }
            DriverAction::Rejected { block_hash, reason } => {
                // Consensus must not vote for it, and the engine learns that by
                // never receiving a BlockImported for this hash.
                warn!(target: "n42.h2.node", ?block_hash, reason, "execution layer rejected a block");
            }
            DriverAction::Finalized { .. } | DriverAction::Ignored => {}
        }
        Ok(())
    }

    /// Publishes a message, queueing it if the mesh is not ready.
    fn publish(
        &mut self,
        message: n42_h2_primitives::consensus::ConsensusMessage,
        events: &mut Vec<ServiceEvent>,
    ) {
        let view = message.view();
        // The v4 profile is static-validator, so the changes hash is zero
        // throughout. `wire_bridge` refuses a Decide that disagrees with this
        // rather than letting a mismatch onto the wire.
        let envelope = match wire_bridge::to_wire(&message, self.identity, B256::ZERO) {
            Ok(envelope) => envelope,
            Err(err) => {
                // Refusing to send is the right outcome — the alternative is a
                // message peers read differently than we meant it — but it
                // means this node is not participating, so it is not a debug
                // line.
                warn!(target: "n42.h2.node", %err, view, "cannot encode our own consensus message");
                return;
            }
        };

        match self.transport.publish(&envelope) {
            // A duplicate is already on the wire — engines re-broadcast by
            // design, and gov5's message id is a hash of the payload.
            Ok(_) => events.push(ServiceEvent::Published { view }),
            Err(err) if err.is_already_published() => {
                events.push(ServiceEvent::Published { view });
            }
            Err(err) if err.is_transient() => {
                debug!(target: "n42.h2.node", view, "mesh not ready; queueing");
                self.outbox.push(message);
            }
            Err(err) => {
                warn!(target: "n42.h2.node", %err, view, "publish failed");
            }
        }
    }

    /// Retries queued messages once the mesh exists.
    ///
    /// Only worth attempting when there is somewhere to send: retrying into an
    /// empty mesh just re-queues everything and burns the loop.
    fn flush_outbox(&mut self, events: &mut Vec<ServiceEvent>) {
        if self.outbox.is_empty() || self.transport.mesh_size() == 0 {
            return;
        }
        for message in std::mem::take(&mut self.outbox) {
            self.publish(message, events);
        }
    }

    /// How long the current view has left before the pacemaker fires.
    pub fn time_to_timeout(&self) -> Duration {
        self.engine.pacemaker().remaining()
    }
}

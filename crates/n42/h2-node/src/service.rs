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
//! **A leader has to be asked to build, before it waits.** The engine proposes
//! only when handed a `BlockReady`, which comes from the execution layer, which
//! needs payload attributes this layer has no business inventing. So block
//! production is opt-in: supply [`H2Service::with_payload_attributes`] and this
//! node proposes when it is leader; leave it out and it votes but never
//! proposes, which is what a member joining an existing fleet should do.
//!
//! The attempt happens at the top of each step, before blocking on anything.
//! HotStuff-2 is responsive — a leader that has just formed a QC proposes for
//! the next view straight away — and a leader that has just committed has no
//! other event coming, so an attempt made after the wait waits for a timeout it
//! should never have needed.
//!
//! **Durability comes before finality.** Committing tells the execution layer a
//! block is finalized, and the Engine API does not allow that to be taken back.
//! A node that announces finality and then dies before its own consensus state
//! reaches disk restarts believing less than its execution layer does, and every
//! forkchoice it sends afterwards is rejected as a reorg past the finalized
//! block. So a commit checkpoint, when one is configured, is written *before*
//! the commit reaches the execution layer, and a checkpoint that fails stops the
//! commit rather than proceeding undurable.
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

use std::collections::HashSet;
use std::time::Duration;

use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256};
use n42_h2_consensus::wire_bridge::{self, BridgeError};
use n42_h2_consensus::{ConsensusEngine, ConsensusEvent, EngineOutput};
use n42_h2_execution::{DriverAction, ExecutionDriver, ExecutionLayer};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_h2_net::{
    compress_block_rlp, decode_block_rlp, decode_tx_batch, decompress_block_gossip,
    encode_block_rlp, encode_tx_batch,
    encode_block_rlp_parts, BlockChunk, H2V4Transport, HeaderProfile, PeerId, RangeRequest,
    TransportEvent, MAX_RANGE_BLOCKS,
};
use n42_h2_consensus::withdrawals_to_rewards;
use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
use n42_h2_wire::{H2Message, H2V4Envelope};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Decides what a leader proposes for a view, given the view number and the
/// current head. `None` declines the view — see
/// [`H2Service::with_payload_attributes`].
type PayloadAttributesBuilder =
    dyn Fn(ProposalContext) -> Option<PayloadAttributes> + Send + Sync;

/// How many views one step may propose for before going back to the network.
///
/// Bounded rather than "until the view stops moving": a fleet that commits
/// faster than the transport is polled would otherwise starve its own gossip,
/// and a node that stops reading the network stops being a fleet member.
const MAX_PROPOSALS_PER_STEP: usize = 4;

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
        /// The certificate that committed it.
        ///
        /// Carried, not dropped: it is what turns "this node says so" into a
        /// proof anyone can check, and the only thing that lets a consumer —
        /// a mobile-verification endpoint, an archive, a bridge — republish the
        /// commit as the `Decide` a fleet member would have verified. Boxed
        /// because it is far larger than the rest of the enum.
        commit_qc: Box<QuorumCertificate>,
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
    /// A block body arrived over the block topic and is now cached. If
    /// consensus was waiting on it, execution is retried in the same step.
    BodyReceived {
        /// The block the body belongs to.
        block_hash: B256,
    },
    /// A peer's status showed it ahead of this node's execution layer, and
    /// this node started pulling the gap by range.
    Syncing {
        /// This node's height when it started.
        from: u64,
        /// The peer's height.
        to: u64,
    },
    /// The pull finished — the execution layer is at the height the peer
    /// reported — or stopped short.
    Synced {
        /// The height reached.
        height: u64,
        /// Whether the target was reached.
        complete: bool,
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
    payload_attributes: Option<Box<PayloadAttributesBuilder>>,
    /// The view this node last built a block for, so a leader does not rebuild
    /// on every event it handles while still in the same view.
    proposed_view: Option<u64>,
    /// Whether the gossip mesh has ever had a peer. Until it does, the view
    /// clock is held off — see the module docs.
    meshed: bool,
    /// Persists consensus state before a commit is announced as final.
    checkpoint: Option<Box<CheckpointWriter>>,
    /// The builder declined to propose for the current view — the period had
    /// not elapsed — so the next step must not wait for the view to time out
    /// before asking again. See [`PROPOSE_RETRY`].
    proposal_deferred: bool,
    /// Which header shapes this node puts on, and accepts from, the block
    /// topic. See [`HeaderProfile`].
    header_profile: HeaderProfile,
    /// Whether consensus messages go out on gov5's native topic in gov5's
    /// own encoding, as a Go fleet member sends them, rather than on the
    /// chain-bound v4 topic. Inbound traffic is accepted from both either
    /// way; Decide proofs are always also published on v4 for observers.
    native_wire: bool,
    /// Blocks consensus asked to execute before their bodies arrived. A body
    /// for one of these re-runs the execution instead of waiting for the next
    /// proposal to mention the block again, which it may never do.
    awaiting_bodies: HashSet<B256>,
    /// Bodies that arrived for awaited blocks, to execute on the next drain.
    /// Kept separate because the transport handler cannot await.
    ready_bodies: Vec<B256>,
    /// Every body that arrived since the last drain, for reporting.
    received_bodies: Vec<B256>,
    /// Block bodies the mesh would not accept yet; retried like `outbox`.
    body_outbox: Vec<Vec<u8>>,
    /// Peers whose status arrived since the last drain, with the height
    /// they reported, to compare against the execution layer there.
    pending_status: Vec<(PeerId, u64)>,
    /// A catch-up in progress, if any.
    catch_up: Option<CatchUp>,
    /// Range replies to import on the next drain. Bounded without a cap of
    /// its own: a reply comes only for a request this node made, one catch-up
    /// runs at a time with one request in flight, and the transport holds a
    /// reply to [`n42_h2_net::MAX_RANGE_BYTES`] of decoded blocks.
    pending_imports: Vec<(PeerId, RangeRequest, Vec<BlockChunk>)>,
    /// Block requests the store could not answer, for the execution layer
    /// on the next drain.
    pending_block_requests: Vec<(String, B256, n42_h2_net::BlockRequestChannel)>,
    /// Range requests to answer from the execution layer on the next drain;
    /// kept here because the transport handler cannot await.
    pending_ranges: Vec<(String, n42_h2_net::RangeRequest, n42_h2_net::RangeRequestChannel)>,
    /// Every body this node built or received, as gov5 block RLP, to answer
    /// `block_by_hash` — gov5's fetch-on-miss, and this node's own. Bounded;
    /// insertion order in `body_store_order`.
    body_store: std::collections::HashMap<B256, Vec<u8>>,
    body_store_order: Vec<B256>,
    /// Timestamps of blocks this node has seen the body of, for
    /// [`ProposalContext::head_timestamp`]. Bounded; insertion order in
    /// `timestamp_order`.
    block_timestamps: std::collections::HashMap<B256, u64>,
    /// Transactions heard on the fleet's transaction topic, waiting to be
    /// handed to the execution layer's pool.
    inbound_transactions: Vec<Bytes>,
    /// Transactions this node's own pool admitted, from the source installed
    /// with [`Self::with_transaction_source`], waiting to go out.
    outbound_transactions: Option<mpsc::Receiver<Vec<Bytes>>>,
    /// Hashes of transactions heard from the fleet, so the pool's echo of
    /// them is not gossiped back. Bounded.
    gossiped_transactions: std::collections::VecDeque<B256>,
    /// The headers of the same blocks.
    block_headers: std::collections::HashMap<B256, Header>,
    /// Block numbers, same bookkeeping, for the height this node advertises
    /// in the status handshake once a block commits.
    block_numbers: std::collections::HashMap<B256, u64>,
    /// When each block was first seen here, for [`ProposalContext::head_seen`].
    block_seen: std::collections::HashMap<B256, std::time::Instant>,
    timestamp_order: Vec<B256>,
}

/// How long a leader whose builder declined waits before asking it again.
///
/// A declined proposal is a pacing decision — the chain's period has not
/// elapsed since the parent — and nothing else is due to happen in a view
/// where the leader has not proposed. Without this the next ask comes at the
/// view timeout, and every other view is lost to it. gov5 paces its own
/// re-asks at `minProposeDelayMs`, 200ms on the devnet.
const PROPOSE_RETRY: Duration = Duration::from_millis(200);

/// A pull of the blocks this node is missing, from one peer, by range.
///
/// Started when a peer's status shows it ahead of this node's execution
/// layer — a member restarting after an absence, or joining a chain that
/// has been running — and driven one range at a time: the reply is
/// imported through `newPayload` in order, each block becoming the
/// finalized head, and the next range asked for until the peer's height is
/// reached. Only the execution layer catches up here; the consensus engine
/// finds the current view from the messages it hears.
#[derive(Debug)]
struct CatchUp {
    peer: PeerId,
    next: u64,
    target: u64,
    started_at: u64,
    /// The target from the peer's status is reached; the pull now probes
    /// past it, a window at a time, for what the fleet produced meanwhile.
    /// The peer's first short reply is the end of its chain.
    probing: bool,
}

/// How many block requests may wait for the execution layer at once, and
/// how many range requests: past these a request is answered empty rather
/// than queued, so one peer cannot hold every other's answers behind a
/// thousand lookups.
const MAX_PENDING_SERVES: usize = 256;
const MAX_PENDING_RANGES: usize = 8;

/// How many block bodies to keep for peers that ask. gov5 asks for the
/// parent of a block it cannot place and for the block a proposal names —
/// recent blocks, both — but a member restarting after a long absence walks
/// back further, and a body is a few hundred bytes when empty.
const REMEMBERED_BODIES: usize = 4096;

/// How many block timestamps to remember. Far more than any head-selection
/// needs; the bound is against a peer flooding bodies, not a working set.
const REMEMBERED_TIMESTAMPS: usize = 256;

/// What a leader knows when deciding whether, and how, to propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalContext {
    /// The view being proposed for.
    pub view: u64,
    /// The block the proposal would build on.
    pub head: B256,
    /// The head's timestamp, when this node has seen the block — its own
    /// builds and every body received over the block topic. `None` after a
    /// restart, or for a head whose body never came this way. A builder paces
    /// against this: an Engine API timestamp is a whole second and must be
    /// strictly greater than the parent's, and only the parent's timestamp
    /// says what that means.
    pub head_timestamp: Option<u64>,
    /// The head's header, when this node holds it — its own builds, bodies
    /// received, or the execution layer's copy. What a builder derives the
    /// parent beacon root from on a chain with a committee pool.
    pub head_header: Option<Header>,
    /// When this node first had the head — built it, or received its body —
    /// by this node's own clock. What a builder paces against: the head's
    /// timestamp is another leader's claim about time (gov5 stamps
    /// `parent + period` however early it proposes), while this is when the
    /// block actually happened here.
    pub head_seen: Option<std::time::Instant>,
}

/// Persists the engine's state. Called before a commit reaches the execution
/// layer; an `Err` aborts the commit rather than finalising something this node
/// could not record.
type CheckpointWriter = dyn Fn(&ConsensusEngine) -> Result<(), String> + Send + Sync;

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
            checkpoint: None,
            proposal_deferred: false,
            header_profile: HeaderProfile::Ethereum,
            native_wire: false,
            awaiting_bodies: HashSet::new(),
            ready_bodies: Vec::new(),
            received_bodies: Vec::new(),
            body_outbox: Vec::new(),
            pending_status: Vec::new(),
            catch_up: None,
            pending_imports: Vec::new(),
            pending_block_requests: Vec::new(),
            pending_ranges: Vec::new(),
            body_store: std::collections::HashMap::new(),
            body_store_order: Vec::new(),
            block_timestamps: std::collections::HashMap::new(),
            inbound_transactions: Vec::new(),
            outbound_transactions: None,
            gossiped_transactions: std::collections::VecDeque::new(),
            block_headers: std::collections::HashMap::new(),
            block_numbers: std::collections::HashMap::new(),
            block_seen: std::collections::HashMap::new(),
            timestamp_order: Vec::new(),
        }
    }

    /// Runs this node under gov5's `HotStuff` header profile.
    ///
    /// Blocks it builds are finished before they are proposed — the view
    /// stamped into the extra data, the seal signed with `key`, the ommers
    /// hash and difficulty set to what gov5's producer writes — and blocks it
    /// receives are decoded under the same profile. What a Go fleet member
    /// does, so the two can share a chain.
    pub fn with_gov5_h2_profile(mut self, key: n42_h2_primitives::bls::BlsSecretKey) -> Self {
        self.header_profile = HeaderProfile::Gov5H2;
        self.native_wire = true;
        self.driver.set_payload_normalizer(move |payload, view| {
            n42_h2_consensus::normalize_to_gov5_h2(payload, view, Some(&key))
                .map_err(|e| e.to_string())
        });
        self
    }

    /// Sets the header shape used on the block topic.
    ///
    /// [`HeaderProfile::Ethereum`] is what this node's own builder produces
    /// and is the default; a fleet shared with gov5 nodes needs
    /// [`HeaderProfile::Gov5H2`] at both ends, which the builder does not emit
    /// yet.
    pub const fn with_header_profile(mut self, profile: HeaderProfile) -> Self {
        self.header_profile = profile;
        self
    }

    /// Persists consensus state at every commit.
    ///
    /// Called *before* the commit is handed to the execution layer, because
    /// finality announced over the Engine API cannot be withdrawn: a node that
    /// finalises a block and then restarts without a record of it points its
    /// forkchoice at an earlier block and is refused. If the writer returns an
    /// error the commit does not reach the execution layer at all — better a
    /// stalled node than one whose execution layer has finalised more than its
    /// consensus can prove.
    pub fn with_checkpoint(
        mut self,
        writer: impl Fn(&ConsensusEngine) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.checkpoint = Some(Box::new(writer));
        self
    }

    /// Makes this node produce blocks when it is leader.
    ///
    /// The closure is called with a [`ProposalContext`] — the view, the head,
    /// and the head's timestamp when known — and returns the attributes to
    /// build under. Without it the node votes on other members'
    /// proposals but never makes one — a valid way to run, and the safe default,
    /// since a node that proposes garbage is worse than one that proposes
    /// nothing.
    ///
    /// Returning `None` declines to propose for this view, and the node asks
    /// again on the next step. That is the answer to the constraint below: an
    /// Engine API timestamp is a whole second, and HotStuff-2 commits in tens of
    /// milliseconds, so a leader that always proposes runs the chain's clock
    /// into the future until the execution layer refuses the blocks.
    ///
    /// **The timestamp must be strictly greater than the parent block's, and
    /// must not be ahead of wall clock.** Returning `now()` unconditionally
    /// gives two consecutive blocks the same second: the execution layer accepts
    /// the forkchoiceUpdated, never finishes the build, and `getPayload` blocks
    /// until the view times out, with nothing in the logs but a slow call.
    /// Forcing the timestamp forward instead runs it past the local clock, and
    /// the execution layer rejects the block outright. Between those two, a
    /// leader proposes about once a second and declines in between.
    pub fn with_payload_attributes(
        mut self,
        attributes: impl Fn(ProposalContext) -> Option<PayloadAttributes> + Send + Sync + 'static,
    ) -> Self {
        self.payload_attributes = Some(Box::new(attributes));
        self
    }

    /// Gossips the transactions this node's execution layer admits to its
    /// pool, read from its public JSON-RPC at `rpc_url` — the Engine API's
    /// auth endpoint accepts transactions but does not list them. Polled
    /// with `eth_newPendingTransactionFilter`; a Go leader seals what it
    /// hears here, exactly as a Rust leader seals what it hears from the
    /// Go members.
    pub fn with_transaction_source(mut self, rpc_url: url::Url) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(crate::tx_source::poll_pending_transactions(rpc_url, tx));
        self.outbound_transactions = Some(rx);
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

        // Drain, then propose, then drain again — before waiting, not after.
        //
        // HotStuff-2 is responsive: a leader that has just formed a QC proposes
        // for the next view immediately. Deferring the attempt until after the
        // select makes it wait for some unrelated event first, and a leader that
        // has just committed has none coming, so it sits until the view times
        // out and the round is lost.
        //
        // The leading drain is what makes the view current: the commit that
        // ended the last round may still be sitting in the output channel, and
        // proposing before reading it proposes for the view just finished, which
        // the guard then skips.
        let mut still_advancing = false;
        for remaining in (0..MAX_PROPOSALS_PER_STEP).rev() {
            self.drain_outputs(&mut events).await?;
            let before = self.engine.current_view();
            self.propose_if_leader().await;
            self.drain_outputs(&mut events).await?;
            // A commit lands in the drain *after* the proposal that caused it,
            // so one step can span several views. Stopping at one proposal per
            // step means the next view's proposal waits for the select to
            // return, and a leader that just committed has nothing else coming —
            // so it waits for a timeout it never needed.
            if self.engine.current_view() == before {
                break;
            }
            still_advancing = remaining == 0;
        }

        if still_advancing {
            // The bound stopped a leader that was still making progress.
            // Blocking now would trade the rest of its views for a timeout, so
            // look at the network without waiting and come straight back —
            // skipping the look entirely would starve the transport of a node
            // that always has something to propose.
            tokio::select! {
                biased;
                event = self.transport.next_event() => {
                    let Some(event) = event else {
                        return Err(ServiceError::TransportEnded);
                    };
                    self.handle_transport_event(event)?;
                }
                () = std::future::ready(()) => {}
            }
            self.drain_outputs(&mut events).await?;
            self.forward_inbound_transactions().await;
            self.flush_outbox(&mut events);
            return Ok(events);
        }

        // Arm from the pacemaker every iteration rather than holding one sleep
        // across views: a commit resets the deadline, and a sleep armed for the
        // old view would fire late or not at all.
        let timeout = self.engine.pacemaker().timeout_sleep();
        tokio::pin!(timeout);
        let outbound = self.outbound_transactions.as_mut();

        tokio::select! {
            event = self.transport.next_event() => {
                let Some(event) = event else {
                    return Err(ServiceError::TransportEnded);
                };
                self.handle_transport_event(event)?;
            }
            batch = async {
                match outbound {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(batch) = batch {
                    self.publish_transactions(batch);
                }
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
            () = tokio::time::sleep(PROPOSE_RETRY), if self.proposal_deferred => {
                // Nothing happened; the builder is asked again at the top of
                // the next step.
            }
        }

        self.drain_outputs(&mut events).await?;
        self.forward_inbound_transactions().await;
        self.flush_outbox(&mut events);
        Ok(events)
    }

    /// Hands the transactions heard from the fleet to the execution layer's
    /// pool. A refusal is the pool's verdict on one transaction, logged and
    /// forgotten; the fleet's next batch is not held up by it.
    async fn forward_inbound_transactions(&mut self) {
        if self.inbound_transactions.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.inbound_transactions);
        let el = self.driver.execution_layer();
        let mut accepted = 0usize;
        for raw in batch {
            match el.send_raw_transaction(raw).await {
                Ok(_) => accepted += 1,
                Err(err) => debug!(target: "n42.h2.node", %err, "the pool declined a gossiped transaction"),
            }
        }
        if accepted > 0 {
            debug!(target: "n42.h2.node", accepted, "handed gossiped transactions to the pool");
        }
    }

    /// Gossips transactions this node's pool admitted, leaving out the ones
    /// that came from the fleet in the first place.
    fn publish_transactions(&mut self, batch: Vec<Bytes>) {
        let fresh: Vec<Bytes> = batch
            .into_iter()
            .filter(|raw| !self.gossiped_transactions.contains(&keccak256(raw)))
            .collect();
        if fresh.is_empty() {
            return;
        }
        for chunk in fresh.chunks(n42_h2_net::TX_BATCH_MAX_TXS) {
            let encoded = match encode_tx_batch(chunk).and_then(|payload| {
                compress_block_rlp(&payload).map_err(|_| n42_h2_net::TxGossipError::TooLarge(payload.len()))
            }) {
                Ok(encoded) => encoded,
                Err(err) => {
                    debug!(target: "n42.h2.node", %err, "could not encode a transaction batch");
                    continue;
                }
            };
            if let Err(err) = self.transport.publish_transactions(encoded) {
                debug!(target: "n42.h2.node", %err, "could not gossip transactions");
            } else {
                debug!(target: "n42.h2.node", count = chunk.len(), "gossiped transactions");
            }
        }
    }

    /// Runs until the transport or the engine stops.
    pub async fn run(&mut self) -> Result<(), ServiceError> {
        loop {
            for event in self.step().await? {
                match event {
                    ServiceEvent::Committed {
                        view, block_hash, ..
                    } => {
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
                    ServiceEvent::BodyReceived { block_hash } => {
                        debug!(target: "n42.h2.node", ?block_hash, "block body received");
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_transport_event(&mut self, event: TransportEvent) -> Result<(), ServiceError> {
        match event {
            TransportEvent::Envelope { envelope, .. } => self.accept_envelope(&envelope),
            TransportEvent::Native { message, .. } => {
                // The native topic is chain-scoped by its fork digest and
                // carries no envelope; give the message the envelope the
                // bridge expects, under this node's own identity. The
                // signatures inside are chain-bound regardless — a gov5
                // fleet with interopV4 signs the v4 domains on this topic.
                let envelope = H2V4Envelope {
                    identity: self.identity,
                    changes_hash: B256::ZERO,
                    message: *message,
                };
                self.accept_envelope(&envelope);
            }
            TransportEvent::Transactions { data, .. } => {
                match decompress_block_gossip(&data).and_then(|payload| {
                    decode_tx_batch(&payload).map_err(|e| n42_h2_net::BlockGossipError::InvalidRewards(e.to_string()))
                }) {
                    Ok(transactions) => {
                        for raw in transactions {
                            self.gossiped_transactions.push_back(keccak256(&raw));
                            while self.gossiped_transactions.len() > REMEMBERED_TIMESTAMPS * 16 {
                                self.gossiped_transactions.pop_front();
                            }
                            self.inbound_transactions.push(raw);
                        }
                    }
                    Err(err) => debug!(target: "n42.h2.node", %err, "dropped a transaction message"),
                }
            }
            TransportEvent::Block { data, .. } => {
                // Nothing here is trusted beyond its own consistency: the
                // header hashes to the block hash, the transactions hash to
                // the header's root. Whether the block is *valid* is the
                // execution layer's verdict, and whether it is *the* block is
                // consensus's — both check the same hash.
                let decoded = decompress_block_gossip(&data).and_then(|rlp| {
                    decode_block_rlp(&rlp, self.header_profile).map(|block| (block, rlp))
                });
                match decoded {
                    Ok((block, rlp)) => {
                        let block_hash = block.block_hash;
                        self.remember_body(block_hash, rlp);
                        self.remember_block(block_hash, &block.header);
                        self.driver.cache_payload(block_hash, block.execution_data());
                        if self.awaiting_bodies.remove(&block_hash) {
                            self.ready_bodies.push(block_hash);
                        }
                        self.received_bodies.push(block_hash);
                    }
                    Err(err) => {
                        // The bytes matter here: a body this node cannot read
                        // is a body it cannot vote on, and the usual cause is
                        // a wire-format difference with the producer.
                        let head = data.iter().take(256).map(|b| format!("{b:02x}")).collect::<String>();
                        debug!(target: "n42.h2.node", %err, len = data.len(), head, "dropped a block body");
                    }
                }
            }
            TransportEvent::BlockRequest { peer, hash, channel } => {
                // The store holds recent bodies byte for byte; anything older
                // is rebuilt from the execution layer on the next drain, the
                // way ranges are served.
                match self.body_store.get(&hash).cloned() {
                    Some(body) => {
                        debug!(target: "n42.h2.node", %peer, ?hash, "peer asked for a block; served from the store");
                        self.transport.respond_block(channel, Some(body));
                    }
                    None if self.pending_block_requests.len() >= MAX_PENDING_SERVES => {
                        // A queue this deep is a peer asking faster than the
                        // execution layer answers; better a prompt "not
                        // found" than a stall for everyone behind it.
                        debug!(target: "n42.h2.node", %peer, ?hash, "block request queue full; refused");
                        self.transport.respond_block(channel, None);
                    }
                    None => self.pending_block_requests.push((peer.to_string(), hash, channel)),
                }
            }
            TransportEvent::BlockFetched { peer, hash, reply } => match reply {
                Ok(chunk) => {
                    // The same path a gossiped body takes; the hash the peer
                    // sent it under is checked by the decode, not trusted.
                    match decode_block_rlp(&chunk.rlp, self.header_profile) {
                        Ok(block) if block.block_hash == hash => {
                            self.remember_block(hash, &block.header);
                            self.remember_body(hash, chunk.rlp);
                            self.driver.cache_payload(hash, block.execution_data());
                            if self.awaiting_bodies.remove(&hash) {
                                self.ready_bodies.push(hash);
                            }
                            self.received_bodies.push(hash);
                        }
                        Ok(block) => {
                            debug!(target: "n42.h2.node", %peer, ?hash, got = ?block.block_hash, "peer answered a block request with the wrong block");
                        }
                        Err(err) => {
                            debug!(target: "n42.h2.node", %peer, ?hash, %err, "peer answered a block request with a body this node cannot read");
                        }
                    }
                }
                Err(reason) => {
                    debug!(target: "n42.h2.node", %peer, ?hash, reason, "peer does not have a requested block");
                }
            },
            TransportEvent::BlockFetchFailed { peer, hash, reason } => {
                debug!(target: "n42.h2.node", %peer, ?hash, reason, "block request failed");
            }
            TransportEvent::RangeRequest { peer, request, channel } => {
                // Served from the execution layer's canonical chain, which
                // has every block, rather than from the body store, which
                // has the recent ones. As many as it has from the start, in
                // order; gov5 reads until the stream closes.
                if self.pending_ranges.len() >= MAX_PENDING_RANGES {
                    debug!(target: "n42.h2.node", %peer, ?request, "range request queue full; refused");
                    self.transport.respond_range(channel, Vec::new());
                } else {
                    self.pending_ranges.push((peer.to_string(), request, channel));
                }
            }
            TransportEvent::RangeFetched { peer, request, reply } => match reply {
                Ok(chunks) => self.pending_imports.push((peer, request, chunks)),
                Err(reason) => {
                    if self.catch_up.as_ref().is_some_and(|c| c.peer == peer) {
                        // Handed to the import loop as an empty reply: a
                        // refusal of a probe past the peer's head is the end
                        // of its chain, anything else stops the catch-up.
                        debug!(target: "n42.h2.node", %peer, ?request, reason, "range request refused");
                        self.pending_imports.push((peer, request, Vec::new()));
                    } else {
                        warn!(target: "n42.h2.node", %peer, ?request, reason, "range request refused");
                    }
                }
            },
            TransportEvent::StatusExchanged {
                peer,
                height,
                fork_matches,
                ..
            } => {
                if fork_matches {
                    debug!(target: "n42.h2.node", %peer, height, "peer on our chain");
                    self.pending_status.push((peer, height));
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

    /// Feeds a decoded consensus message to the engine.
    fn accept_envelope(&mut self, envelope: &H2V4Envelope) {
        match wire_bridge::to_engine(envelope, self.validator_count) {
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

    /// Drains the engine's output channel to empty.
    ///
    /// Not a `while let Some(..) = recv().await` loop: that would block waiting
    /// for the *next* output rather than stopping when the channel runs dry.
    async fn drain_outputs(&mut self, events: &mut Vec<ServiceEvent>) -> Result<(), ServiceError> {
        self.consider_catch_up(events).await;
        self.import_ranges(events).await;
        for (peer, hash, channel) in std::mem::take(&mut self.pending_block_requests) {
            let body = match self.driver.execution_layer().block_by_hash(hash).await {
                Ok(Some(block)) => Some(encode_block_rlp_parts(
                    &block.header,
                    &block.transactions,
                    &withdrawals_to_rewards(block.withdrawals.as_deref().unwrap_or(&[])),
                )),
                Ok(None) => None,
                Err(err) => {
                    debug!(target: "n42.h2.node", ?hash, %err, "execution layer could not serve a block");
                    None
                }
            };
            debug!(target: "n42.h2.node", peer, ?hash, found = body.is_some(), "peer asked for a block; execution layer consulted");
            self.transport.respond_block(channel, body);
        }
        for (peer, request, channel) in std::mem::take(&mut self.pending_ranges) {
            // Only the execution layer is held across the await: the
            // transport is not `Sync`, and a future holding all of `self`
            // could not be spawned.
            let rlps = serve_range(self.driver.execution_layer(), request).await;
            debug!(target: "n42.h2.node", peer, ?request, served = rlps.len(), "peer asked for a range");
            self.transport.respond_range(channel, rlps);
        }
        for block_hash in std::mem::take(&mut self.received_bodies) {
            events.push(ServiceEvent::BodyReceived { block_hash });
        }
        // A body that consensus already asked for re-runs the execution it
        // could not do at the time. Through the same path as the original
        // request, so the resulting BlockImported reaches the engine the same
        // way.
        for block_hash in std::mem::take(&mut self.ready_bodies) {
            self.handle_output(EngineOutput::ExecuteBlock(block_hash), events)
                .await?;
        }
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
        // Durability first, and only for the output that announces finality.
        // See the module docs: the Engine API has no way to un-finalise a block.
        if let (EngineOutput::BlockCommitted { view, block_hash, .. }, Some(write)) =
            (&output, self.checkpoint.as_ref())
            && let Err(error) = write(&self.engine)
        {
            warn!(
                target: "n42.h2.node",
                %error, view, ?block_hash,
                "could not persist consensus state; the commit is not being finalised",
            );
            return Ok(());
        }

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
                view,
                block_hash,
                commit_qc,
                ..
            } => {
                // The status handshake advertises the committed height; a
                // peer deciding whether this node is worth syncing from reads
                // it, and gov5 waits for a peer at or above its own height.
                if let Some(number) = self.block_numbers.get(&block_hash).copied() {
                    self.transport.set_advertised_height(number);
                }
                events.push(ServiceEvent::Committed {
                    view,
                    block_hash,
                    commit_qc: Box::new(commit_qc),
                });
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
        // A node that reaches quorum by itself has nobody to wait for. Holding
        // the clock for a mesh peer would stop a single-validator chain dead:
        // the one member waits forever for a fleet that is already complete.
        if self.engine.quorum_size() <= 1 {
            self.meshed = true;
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
            self.proposal_deferred = false;
            return;
        }
        // The parent is the block the highest QC certifies, not whatever the
        // execution layer imported last: a proposal has to extend its justify
        // QC's block (the fleet refuses one that does not), and a leader that
        // has yet to import that block — it joined after the block went round,
        // or the QC reached it before the body — would otherwise propose a
        // sibling from a stale head. Such a leader asks for the block and
        // proposes once it has it; the genesis QC certifies nothing and leaves
        // the head in charge.
        let certified = self.engine.locked_qc().block_hash;
        let head = if certified == B256::ZERO { self.driver.head() } else { certified };
        let head_header = match self.block_headers.get(&head) {
            Some(header) => Some(header.clone()),
            None => match self.driver.execution_layer().block_by_hash(head).await {
                Ok(Some(block)) => Some(block.header),
                Ok(None) => None,
                Err(err) => {
                    debug!(target: "n42.h2.node", ?head, %err, "execution layer could not serve the head's header");
                    None
                }
            },
        };
        if head != self.driver.head() && head_header.is_none() {
            warn!(target: "n42.h2.node", view, certified = ?head, imported = ?self.driver.head(), "the block our highest QC certifies is not imported; asking for it before proposing");
            if self.awaiting_bodies.insert(head) {
                for peer in self.transport.connected_peer_ids() {
                    self.transport.request_block(peer, head);
                }
            }
            self.proposal_deferred = true;
            return;
        }
        // Marked before the build, not after: a build that fails should not be
        // retried on every subsequent event in the same view, which would pin
        // the loop against a broken execution layer.
        let context = ProposalContext {
            view,
            head,
            head_timestamp: self.block_timestamps.get(&head).copied(),
            head_header,
            head_seen: self.block_seen.get(&head).copied(),
        };
        let Some(attrs) = build_attributes(context) else {
            // Declined for now — not marked as proposed, so the next step asks
            // again. This is how a leader paces itself against a clock coarser
            // than its commit latency.
            self.proposal_deferred = true;
            return;
        };
        self.proposal_deferred = false;
        self.proposed_view = Some(view);
        match self.driver.build_block_on(head, attrs, view).await {
            Ok(built) => {
                debug!(target: "n42.h2.node", view, block = ?built.hash, txs = built.tx_count, "built a block to propose");
                // The proposal names the hash; the body has to get there by
                // itself, and before the proposal if the followers are to vote
                // in the first round. Publishing it first is the best order
                // gossip can offer.
                match built.execution_data.clone().try_into_block::<alloy_consensus::TxEnvelope>() {
                    Ok(block) => self.remember_block(built.hash, &block.header),
                    Err(err) => debug!(target: "n42.h2.node", %err, "built payload has no header to remember"),
                }
                self.publish_body(&built.execution_data);
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
                // The engine's extends rule reads the parent of an imported
                // block; every block imported here came with its header.
                if let ConsensusEvent::BlockImported(block_hash) = event.as_ref() {
                    if let Some(header) = self.block_headers.get(block_hash) {
                        self.engine.remember_parent(*block_hash, header.parent_hash);
                    }
                }
                if let Err(err) = self.engine.process_event(*event) {
                    debug!(target: "n42.h2.node", %err, "engine rejected an execution event");
                }
            }
            DriverAction::PayloadMissing { block_hash } => {
                // The body may still be in flight on the block topic; ask
                // for it too, as gov5 does, from everyone connected. An
                // answer that arrives after the gossip copy is a duplicate
                // the cache absorbs.
                if self.awaiting_bodies.insert(block_hash) {
                    for peer in self.transport.connected_peer_ids() {
                        self.transport.request_block(peer, block_hash);
                    }
                }
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

        let result = if self.native_wire {
            // What a Go member does: consensus on the native topic, and the
            // Decide proof additionally on the chain-bound v4 topic, where
            // observers verify finality without joining consensus.
            if matches!(envelope.message, H2Message::Decide(_)) {
                let _ = self.transport.publish(&envelope);
            }
            self.transport.publish_native(&envelope.message)
        } else {
            self.transport.publish(&envelope)
        };
        match result {
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

    /// Starts a catch-up if a peer's status shows it ahead of the execution
    /// layer and none is running.
    async fn consider_catch_up(&mut self, events: &mut Vec<ServiceEvent>) {
        let statuses = std::mem::take(&mut self.pending_status);
        if statuses.is_empty() || self.catch_up.is_some() {
            return;
        }
        let Some((peer, height)) = statuses.into_iter().max_by_key(|(_, h)| *h) else {
            return;
        };
        let latest = match self.driver.execution_layer().latest_block_number().await {
            Ok(Some(latest)) => latest,
            // An execution layer that does not say cannot be caught up.
            Ok(None) => return,
            Err(err) => {
                debug!(target: "n42.h2.node", %err, "could not read the execution layer's height");
                return;
            }
        };
        // Statuses arrive on connect, and a block the fleet gossiped before
        // this node connected never comes by itself — however small the gap.
        if height <= latest {
            return;
        }
        info!(target: "n42.h2.node", %peer, from = latest, to = height, "behind a peer; pulling the gap by range");
        self.catch_up = Some(CatchUp {
            peer,
            next: latest + 1,
            target: height,
            started_at: latest,
            probing: false,
        });
        self.request_next_range();
        events.push(ServiceEvent::Syncing {
            from: latest,
            to: height,
        });
    }

    fn request_next_range(&mut self) {
        let Some(catch_up) = &self.catch_up else {
            return;
        };
        let count = (catch_up.target - catch_up.next + 1).min(MAX_RANGE_BLOCKS);
        self.transport.request_range(
            catch_up.peer,
            RangeRequest {
                start: catch_up.next,
                count,
                step: 1,
            },
        );
    }

    /// Imports the ranges that came back, in order, through the execution
    /// layer; asks for the next range while the target is not reached.
    async fn import_ranges(&mut self, events: &mut Vec<ServiceEvent>) {
        for (peer, request, chunks) in std::mem::take(&mut self.pending_imports) {
            let Some(catch_up) = self.catch_up.as_ref() else {
                continue;
            };
            if catch_up.peer != peer || request.start != catch_up.next {
                debug!(target: "n42.h2.node", %peer, ?request, "range reply not part of the catch-up; dropped");
                continue;
            }
            if chunks.is_empty() {
                if catch_up.probing {
                    self.finish_catch_up(events, true);
                } else {
                    warn!(target: "n42.h2.node", %peer, ?request, "peer served none of the range; catch-up stopped");
                    self.finish_catch_up(events, false);
                }
                continue;
            }
            for chunk in chunks {
                let block = match decode_block_rlp(&chunk.rlp, self.header_profile) {
                    Ok(block) => block,
                    Err(err) => {
                        warn!(target: "n42.h2.node", %peer, %err, "peer served a block this node cannot read; catch-up stopped");
                        self.finish_catch_up(events, false);
                        return;
                    }
                };
                let expected = self.catch_up.as_ref().map(|c| c.next).unwrap_or_default();
                if block.header.number != expected {
                    warn!(target: "n42.h2.node", %peer, got = block.header.number, expected, "peer served blocks out of order; catch-up stopped");
                    self.finish_catch_up(events, false);
                    return;
                }
                let hash = block.block_hash;
                match self.driver.import_pulled(block.execution_data()).await {
                    Ok(_) => {
                        self.remember_block(hash, &block.header);
                        self.remember_body(hash, chunk.rlp);
                        if let Some(c) = self.catch_up.as_mut() {
                            c.next += 1;
                        }
                    }
                    Err(err) => {
                        warn!(target: "n42.h2.node", %peer, number = block.header.number, %err, "could not import a pulled block; catch-up stopped");
                        self.finish_catch_up(events, false);
                        return;
                    }
                }
            }
            let Some(catch_up) = self.catch_up.as_mut() else {
                continue;
            };
            let window_filled = catch_up.next > catch_up.target;
            if window_filled {
                // The status's target is reached, or a probe window came back
                // full: the fleet kept producing while this pull ran, and a
                // gap of a whole window is not one gossip's future queue
                // closes. Probe on until the peer serves short.
                catch_up.probing = true;
                catch_up.target = catch_up.next + MAX_RANGE_BLOCKS - 1;
                self.request_next_range();
            } else if catch_up.probing {
                // Short of a probe window: that was the peer's head.
                self.finish_catch_up(events, true);
            } else {
                self.request_next_range();
            }
        }
    }

    fn finish_catch_up(&mut self, events: &mut Vec<ServiceEvent>, complete: bool) {
        let Some(catch_up) = self.catch_up.take() else {
            return;
        };
        let height = catch_up.next.saturating_sub(1);
        if height > catch_up.started_at {
            self.transport.set_advertised_height(height);
        }
        info!(target: "n42.h2.node", from = catch_up.started_at, height, target = catch_up.target, complete, "catch-up finished");
        events.push(ServiceEvent::Synced { height, complete });
    }

    fn remember_body(&mut self, block_hash: B256, rlp: Vec<u8>) {
        if self.body_store.insert(block_hash, rlp).is_none() {
            self.body_store_order.push(block_hash);
            while self.body_store_order.len() > REMEMBERED_BODIES {
                let oldest = self.body_store_order.remove(0);
                self.body_store.remove(&oldest);
            }
        }
    }

    fn remember_block(&mut self, block_hash: B256, header: &Header) {
        if self.block_timestamps.insert(block_hash, header.timestamp).is_none() {
            self.block_numbers.insert(block_hash, header.number);
            self.block_headers.insert(block_hash, header.clone());
            self.block_seen.insert(block_hash, std::time::Instant::now());
            self.timestamp_order.push(block_hash);
            while self.timestamp_order.len() > REMEMBERED_TIMESTAMPS {
                let oldest = self.timestamp_order.remove(0);
                self.block_timestamps.remove(&oldest);
                self.block_numbers.remove(&oldest);
                self.block_headers.remove(&oldest);
                self.block_seen.remove(&oldest);
            }
        }
    }

    /// Publishes a block body, queueing it if the mesh is not ready.
    fn publish_body(&mut self, execution: &alloy_rpc_types_engine::ExecutionData) {
        let block_hash = execution.block_hash();
        let data = match encode_block_rlp(execution, self.header_profile)
            .and_then(|rlp| compress_block_rlp(&rlp).map(|data| (rlp, data)))
        {
            Ok((rlp, data)) => {
                self.remember_body(block_hash, rlp);
                data
            }
            Err(err) => {
                // A block nobody else can receive is a block nobody else can
                // vote on: the view is going to time out, and this is why.
                warn!(target: "n42.h2.node", %err, ?block_hash, "cannot encode our own block for the fleet");
                return;
            }
        };
        self.send_body(data, block_hash);
    }

    fn send_body(&mut self, data: Vec<u8>, block_hash: B256) {
        match self.transport.publish_block(data.clone()) {
            Ok(_) => {}
            Err(err) if err.is_already_published() => {}
            Err(err) if err.is_transient() => {
                debug!(target: "n42.h2.node", ?block_hash, "mesh not ready; queueing block body");
                self.body_outbox.push(data);
            }
            Err(err) => {
                warn!(target: "n42.h2.node", %err, ?block_hash, "block body publish failed");
            }
        }
    }

    /// Retries queued messages once the mesh exists.
    ///
    /// Only worth attempting when there is somewhere to send: retrying into an
    /// empty mesh just re-queues everything and burns the loop.
    fn flush_outbox(&mut self, events: &mut Vec<ServiceEvent>) {
        if self.transport.mesh_size() == 0 {
            return;
        }
        for data in std::mem::take(&mut self.body_outbox) {
            self.send_body(data, B256::ZERO);
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

/// The blocks of a range, read from one view of the execution layer's chain.
///
/// A range is served over up to a thousand separate lookups, and the chain
/// can move between any two of them: a block-by-number read on each side of
/// a reorg hands the peer blocks from two chains that do not link, and its
/// import stops at the seam (Erigon shipped the same class of bug in its
/// range server, hash and body read from different snapshots). So the range
/// is read from one anchor and walked by hash: the highest block of the
/// range is resolved by number once, and every earlier block is fetched by
/// its child's `parent_hash`. What is served is one chain by construction —
/// the one that was canonical when the anchor was read — however the head
/// moves meanwhile. Each block is checked to hash to what its child named
/// and to carry the number expected of it, so an execution layer answering
/// with the wrong block cannot smuggle one in.
///
/// An execution layer that does not report its head or does not answer by
/// hash (both are the trait's defaults), that fails either lookup, or that
/// no longer holds a block of the range, is walked forward by number
/// instead, with the same parent link checked between neighbours; a seam
/// ends the reply there, so what is served still links, only shorter. gov5
/// reads a reply from `start` in order, so a reply is never served with a
/// hole.
///
/// The reply is also held to [`n42_h2_net::MAX_RANGE_BYTES`] of block RLP,
/// the budget a requester of this implementation reads a reply up to: past
/// it the requester would drop the rest unread, so it is not fetched or
/// sent. A reply cut there is a short reply like any other, and the
/// requester asks for the rest from where it ended.
async fn serve_range<E: ExecutionLayer>(el: &E, request: n42_h2_net::RangeRequest) -> Vec<Vec<u8>> {
    serve_range_within(el, request, n42_h2_net::MAX_RANGE_BYTES).await
}

/// [`serve_range`] with the byte budget as a parameter, for the tests.
async fn serve_range_within<E: ExecutionLayer>(
    el: &E,
    request: n42_h2_net::RangeRequest,
    max_bytes: u64,
) -> Vec<Vec<u8>> {
    let count = request.count.min(MAX_RANGE_BLOCKS);
    if count == 0 {
        return Vec::new();
    }
    let last = request.start.saturating_add(count - 1);
    let latest = match el.latest_block_number().await {
        Ok(latest) => latest,
        Err(err) => {
            debug!(target: "n42.h2.node", %err, "execution layer could not report its head; walking the range forward");
            None
        }
    };
    if let Some(head) = latest
        && let Some(chunks) = serve_range_anchored(el, request.start, last.min(head), max_bytes).await
    {
        return chunks;
    }
    serve_range_forward(el, request.start, last, max_bytes).await
}

/// gov5's block form of an execution layer block.
fn range_chunk(block: &n42_h2_execution::ChainBlock) -> Vec<u8> {
    encode_block_rlp_parts(
        &block.header,
        &block.transactions,
        &withdrawals_to_rewards(block.withdrawals.as_deref().unwrap_or(&[])),
    )
}

/// `start..=last` by walking parent hashes down from `last`, resolved by
/// number once. `None` when a block of the range could not be had — the
/// anchor by number, or an earlier block by hash — or was not the block its
/// child named, or when the range's blocks together outweigh `max_bytes`:
/// the caller falls back to the forward walk, which serves what it can from
/// `start`; nothing partial is served from here.
async fn serve_range_anchored<E: ExecutionLayer>(
    el: &E,
    start: u64,
    last: u64,
    max_bytes: u64,
) -> Option<Vec<Vec<u8>>> {
    if last < start {
        return Some(Vec::new());
    }
    let anchor = match el.block_by_number(last).await {
        Ok(Some(block)) if block.header.number == last => block,
        Ok(Some(block)) => {
            debug!(target: "n42.h2.node", asked = last, got = block.header.number, "execution layer answered a block request with the wrong number");
            return None;
        }
        Ok(None) => {
            debug!(target: "n42.h2.node", number = last, "execution layer does not serve the block its head names; walking forward");
            return None;
        }
        Err(err) => {
            debug!(target: "n42.h2.node", number = last, %err, "execution layer could not serve a block");
            return None;
        }
    };
    let mut chunks = Vec::with_capacity((last - start + 1) as usize);
    let mut parent_hash = anchor.header.parent_hash;
    let mut number = last;
    let mut total = 0u64;
    let chunk = range_chunk(&anchor);
    if !fits_budget(&mut total, chunk.len(), max_bytes, number) {
        return None;
    }
    chunks.push(chunk);
    while number > start {
        number -= 1;
        let block = match el.block_by_hash(parent_hash).await {
            Ok(Some(block)) => block,
            Ok(None) => {
                debug!(target: "n42.h2.node", number, hash = ?parent_hash, "execution layer does not serve a block of the range by hash; walking forward");
                return None;
            }
            Err(err) => {
                debug!(target: "n42.h2.node", number, %err, "execution layer could not serve a block");
                return None;
            }
        };
        if block.header.number != number || block.header.hash_slow() != parent_hash {
            debug!(target: "n42.h2.node", asked = ?parent_hash, number, got = block.header.number, "execution layer answered a block request with the wrong block");
            return None;
        }
        parent_hash = block.header.parent_hash;
        let chunk = range_chunk(&block);
        if !fits_budget(&mut total, chunk.len(), max_bytes, number) {
            return None;
        }
        chunks.push(chunk);
    }
    chunks.reverse();
    Some(chunks)
}

/// Adds a chunk's bytes to a reply's running total, and says whether the
/// reply is still within `max_bytes` with it.
fn fits_budget(total: &mut u64, len: usize, max_bytes: u64, number: u64) -> bool {
    *total = total.saturating_add(len as u64);
    if *total > max_bytes {
        debug!(target: "n42.h2.node", number, total = *total, max_bytes, "range reply outweighs the byte budget");
        return false;
    }
    true
}

/// `start..=last` by number, forward, ending at the first block that does
/// not link to the one before it, or that would take the reply past
/// `max_bytes`.
async fn serve_range_forward<E: ExecutionLayer>(el: &E, start: u64, last: u64, max_bytes: u64) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut previous: Option<B256> = None;
    let mut total = 0u64;
    for number in start..=last {
        let block = match el.block_by_number(number).await {
            Ok(Some(block)) => block,
            Ok(None) => break,
            Err(err) => {
                debug!(target: "n42.h2.node", number, %err, "execution layer could not serve a block");
                break;
            }
        };
        if block.header.number != number {
            debug!(target: "n42.h2.node", asked = number, got = block.header.number, "execution layer answered a block request with the wrong number");
            break;
        }
        if previous.is_some_and(|hash| block.header.parent_hash != hash) {
            debug!(target: "n42.h2.node", number, "chain moved under a range being served; ended at the seam");
            break;
        }
        let chunk = range_chunk(&block);
        if !fits_budget(&mut total, chunk.len(), max_bytes, number) {
            break;
        }
        previous = Some(block.header.hash_slow());
        chunks.push(chunk);
    }
    chunks
}

#[cfg(test)]
mod range_tests {
    use super::*;
    use n42_h2_execution::{ChainBlock, ElError};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn chain(genesis_parent: B256, len: u64, salt: u8) -> Vec<ChainBlock> {
        let mut blocks = Vec::new();
        let mut parent_hash = genesis_parent;
        for number in 0..len {
            let header = Header {
                number,
                parent_hash,
                timestamp: 1_000 + number * 4,
                extra_data: vec![salt].into(),
                ..Default::default()
            };
            parent_hash = header.hash_slow();
            blocks.push(ChainBlock { header, transactions: Vec::new(), withdrawals: None });
        }
        blocks
    }

    /// An execution layer whose canonical chain can be swapped for another
    /// after a number of lookups — a reorg happening while a range is served.
    struct Reorging {
        canonical: Mutex<Vec<ChainBlock>>,
        by_hash: HashMap<B256, ChainBlock>,
        fork: Mutex<Option<Vec<ChainBlock>>>,
        lookups_before_fork: usize,
        lookups: AtomicUsize,
        reports_head: bool,
        /// `latest_block_number` fails outright.
        head_error: bool,
        /// How far past its last block the reported head lies — a head the
        /// layer names but cannot serve.
        head_overstated_by: u64,
    }

    impl Reorging {
        fn new(canonical: Vec<ChainBlock>, fork: Option<Vec<ChainBlock>>, lookups_before_fork: usize) -> Self {
            let mut by_hash = HashMap::new();
            for block in canonical.iter().chain(fork.iter().flatten()) {
                by_hash.insert(block.header.hash_slow(), block.clone());
            }
            Self {
                canonical: Mutex::new(canonical),
                by_hash,
                fork: Mutex::new(fork),
                lookups_before_fork,
                lookups: AtomicUsize::new(0),
                reports_head: true,
                head_error: false,
                head_overstated_by: 0,
            }
        }

        fn tick(&self) {
            let n = self.lookups.fetch_add(1, Ordering::SeqCst) + 1;
            if n == self.lookups_before_fork
                && let Some(fork) = self.fork.lock().unwrap().take()
            {
                *self.canonical.lock().unwrap() = fork;
            }
        }
    }

    #[async_trait::async_trait]
    impl ExecutionLayer for Reorging {
        async fn latest_block_number(&self) -> Result<Option<u64>, ElError> {
            if self.head_error {
                return Err(ElError::new("eth_blockNumber: connection refused"));
            }
            Ok(self
                .reports_head
                .then(|| self.canonical.lock().unwrap().len() as u64 - 1 + self.head_overstated_by))
        }
        async fn block_by_hash(&self, hash: B256) -> Result<Option<ChainBlock>, ElError> {
            self.tick();
            Ok(self.by_hash.get(&hash).cloned())
        }
        async fn block_by_number(&self, number: u64) -> Result<Option<ChainBlock>, ElError> {
            self.tick();
            Ok(self.canonical.lock().unwrap().get(number as usize).cloned())
        }
        async fn new_payload(&self, _: alloy_rpc_types_engine::ExecutionData) -> Result<alloy_rpc_types_engine::PayloadStatus, ElError> {
            unreachable!()
        }
        async fn fork_choice_updated(&self, _: alloy_rpc_types_engine::ForkchoiceState) -> Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError> {
            unreachable!()
        }
        async fn fork_choice_updated_with_attrs(&self, _: alloy_rpc_types_engine::ForkchoiceState, _: PayloadAttributes) -> Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError> {
            unreachable!()
        }
        async fn resolve_payload(&self, _: alloy_rpc_types_engine::PayloadId, _: n42_h2_execution::ResolveKind) -> Option<Result<n42_h2_execution::BuiltBlock, ElError>> {
            unreachable!()
        }
    }

    fn numbers_and_links(rlps: &[Vec<u8>]) -> Vec<(u64, B256, B256)> {
        rlps.iter()
            .map(|rlp| {
                let block = decode_block_rlp(rlp, HeaderProfile::Ethereum).unwrap();
                (block.header.number, block.block_hash, block.header.parent_hash)
            })
            .collect()
    }

    fn assert_linked(served: &[(u64, B256, B256)], from: u64) {
        for (i, (number, _, parent)) in served.iter().enumerate() {
            assert_eq!(*number, from + i as u64, "served out of order");
            if i > 0 {
                assert_eq!(*parent, served[i - 1].1, "block {number} does not link to the one before");
            }
        }
    }

    #[tokio::test]
    async fn a_range_is_one_chain_even_when_the_head_reorgs_mid_way() {
        let main = chain(B256::ZERO, 20, 0xA);
        // A fork sharing blocks 0..=9 and diverging from 10.
        let mut fork = main[..10].to_vec();
        fork.extend(chain(main[9].header.hash_slow(), 10, 0xB).into_iter().map(|mut b| {
            b.header.number += 10;
            b
        }));
        // Re-link the fork's numbers: rebuild hashes after renumbering.
        let mut parent = main[9].header.hash_slow();
        for block in fork.iter_mut().skip(10) {
            block.header.parent_hash = parent;
            parent = block.header.hash_slow();
        }
        let request = RangeRequest { start: 5, count: 12, step: 1 };

        // Reorg after the fourth lookup, in the middle of the range.
        let el = Reorging::new(main.clone(), Some(fork.clone()), 4);
        let served = numbers_and_links(&serve_range(&el, request).await);
        assert_eq!(served.len(), 12);
        assert_linked(&served, 5);
        // And it is the chain that was canonical when the range was anchored.
        let expected: Vec<B256> = main[5..17].iter().map(|b| b.header.hash_slow()).collect();
        assert_eq!(served.iter().map(|(_, h, _)| *h).collect::<Vec<_>>(), expected);
    }

    #[tokio::test]
    async fn a_forward_walk_ends_at_the_seam_when_the_head_is_not_reported() {
        let main = chain(B256::ZERO, 20, 0xA);
        let mut fork = main[..10].to_vec();
        let mut parent = main[9].header.hash_slow();
        for number in 10..20 {
            let header = Header { number, parent_hash: parent, extra_data: vec![0xB].into(), ..Default::default() };
            parent = header.hash_slow();
            fork.push(ChainBlock { header, transactions: Vec::new(), withdrawals: None });
        }
        let mut el = Reorging::new(main.clone(), Some(fork), 4);
        el.reports_head = false;
        let request = RangeRequest { start: 8, count: 8, step: 1 };
        let served = numbers_and_links(&serve_range(&el, request).await);
        // Blocks 8, 9, 10 came from `main`; the fourth lookup swapped the
        // chain, and block 11 of the fork does not link to `main`'s 10.
        assert_eq!(served.len(), 3);
        assert_linked(&served, 8);
    }

    #[tokio::test]
    async fn a_range_is_bounded_by_the_head_and_the_block_cap() {
        let main = chain(B256::ZERO, 8, 0xA);
        let el = Reorging::new(main, None, usize::MAX);
        let served = numbers_and_links(&serve_range(&el, RangeRequest { start: 5, count: 100, step: 1 }).await);
        assert_eq!(served.len(), 3);
        assert_linked(&served, 5);
        assert!(serve_range(&el, RangeRequest { start: 8, count: 4, step: 1 }).await.is_empty());
        assert!(serve_range(&el, RangeRequest { start: 2, count: 0, step: 1 }).await.is_empty());

        let long = chain(B256::ZERO, MAX_RANGE_BLOCKS + 10, 0xA);
        let el = Reorging::new(long, None, usize::MAX);
        let served = serve_range(&el, RangeRequest { start: 0, count: MAX_RANGE_BLOCKS + 5, step: 1 }).await;
        assert_eq!(served.len() as u64, MAX_RANGE_BLOCKS);
    }

    #[tokio::test]
    async fn a_block_the_layer_does_not_serve_by_hash_falls_back_to_the_forward_walk() {
        let main = chain(B256::ZERO, 10, 0xA);
        let mut el = Reorging::new(main.clone(), None, usize::MAX);
        // Block 3 is gone from the by-hash index; by number it is there.
        let missing = main[3].header.hash_slow();
        el.by_hash.remove(&missing);
        let served = numbers_and_links(&serve_range(&el, RangeRequest { start: 2, count: 5, step: 1 }).await);
        assert_eq!(served.len(), 5);
        assert_linked(&served, 2);
        // An execution layer with no by-hash lookup at all (the trait's
        // default answers `None`) is served the same way.
        el.by_hash.clear();
        let served = numbers_and_links(&serve_range(&el, RangeRequest { start: 2, count: 5, step: 1 }).await);
        assert_eq!(served.len(), 5);
        assert_linked(&served, 2);
    }

    #[tokio::test]
    async fn a_wrong_block_from_the_layer_is_not_served() {
        let main = chain(B256::ZERO, 10, 0xA);
        let mut el = Reorging::new(main.clone(), None, usize::MAX);
        // The by-hash index answers block 4's hash with block 2.
        let four = main[4].header.hash_slow();
        el.by_hash.insert(four, main[2].clone());
        let served = numbers_and_links(&serve_range(&el, RangeRequest { start: 3, count: 4, step: 1 }).await);
        // The lie is not served: what comes back links and carries the
        // numbers asked for (the forward walk by number supplied it).
        assert_eq!(served.len(), 4);
        assert_linked(&served, 3);
        assert_eq!(served[1].1, four);
    }

    #[tokio::test]
    async fn a_head_the_layer_cannot_report_or_serve_is_walked_forward() {
        let main = chain(B256::ZERO, 10, 0xA);
        // `eth_blockNumber` fails: the range is still served, by number.
        let mut el = Reorging::new(main.clone(), None, usize::MAX);
        el.head_error = true;
        let served = numbers_and_links(&serve_range(&el, RangeRequest { start: 2, count: 5, step: 1 }).await);
        assert_eq!(served.len(), 5);
        assert_linked(&served, 2);
        // The layer names a head it does not serve (block 12 of a chain to
        // 9): the anchor is missing, and the range is served by number up
        // to what exists rather than answered empty.
        let mut el = Reorging::new(main, None, usize::MAX);
        el.head_overstated_by = 3;
        let served = numbers_and_links(&serve_range(&el, RangeRequest { start: 7, count: 6, step: 1 }).await);
        assert_eq!(served.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(), vec![7, 8, 9]);
        assert_linked(&served, 7);
    }

    #[tokio::test]
    async fn a_reply_is_cut_at_the_byte_budget_on_either_walk() {
        let mut main = chain(B256::ZERO, 6, 0xA);
        // Heavy blocks, re-linked after the change.
        let mut parent = B256::ZERO;
        for block in &mut main {
            block.header.parent_hash = parent;
            block.header.extra_data = vec![0xC; 1024].into();
            parent = block.header.hash_slow();
        }
        let sizes: Vec<u64> = main.iter().map(|b| range_chunk(b).len() as u64).collect();
        let request = RangeRequest { start: 1, count: 4, step: 1 };
        // Room for blocks 1 and 2 and half of 3.
        let budget = sizes[1] + sizes[2] + sizes[3] / 2;

        let el = Reorging::new(main.clone(), None, usize::MAX);
        let served = numbers_and_links(&serve_range_within(&el, request, budget).await);
        assert_eq!(served.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(), vec![1, 2]);
        assert_linked(&served, 1);
        // Exactly the budget fits the three.
        let served = serve_range_within(&el, request, sizes[1] + sizes[2] + sizes[3]).await;
        assert_eq!(served.len(), 3);

        let mut el = Reorging::new(main, None, usize::MAX);
        el.reports_head = false;
        let served = numbers_and_links(&serve_range_within(&el, request, budget).await);
        assert_eq!(served.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(), vec![1, 2]);
        assert_linked(&served, 1);
        // The production budget is the requester's.
        assert_eq!(n42_h2_net::MAX_RANGE_BYTES, 256 << 20);
    }
}

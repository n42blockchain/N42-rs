// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The swarm on its own task (`N42_GOSSIP_OFF_LOOP=1`).
//!
//! Inline, the validator's single consensus loop polls the libp2p swarm
//! itself: GossipSub's state machine, the decoding of every envelope and
//! native message (a vote's G2 signature decompression among them) and the
//! request-response bookkeeping all run on the thread that also verifies
//! votes and drives the engine. At 99 keys that is ~1,600 gossip deliveries a
//! block per node. Here a tokio task owns the swarm instead:
//!
//! * inbound: the task decodes and forwards [`TransportEvent`]s through a
//!   bounded channel ([`INBOUND_CAPACITY`]); when the loop falls behind, the
//!   task waits on the channel (back-pressure, no drops) and the swarm's own
//!   per-connection buffers absorb the rest. One task, one FIFO: events keep
//!   the order the swarm produced them in, so per-peer order is preserved;
//! * outbound publishes travel through a second bounded channel
//!   ([`PUBLISH_CAPACITY`]); a full one is a transient publish error, which
//!   the service already retries. A publish GossipSub refuses as transient
//!   (no peers on the topic yet, queues full) is retried by the task when the
//!   next swarm event arrives, up to [`RETRY_CAPACITY`];
//! * requests, responses, pushes and dials travel through an unbounded
//!   command channel: a dropped response would leave a peer waiting out its
//!   timeout, and the loop produces these at protocol rate.
//!
//! GossipSub is configured exactly as inline (`gov5_gossipsub_config`): only
//! which thread polls it changes.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use libp2p::gossipsub;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;

use crate::rpc::{BlockTxnsReply, BlockTxnsRequest, RangeRequest};
use crate::transport::{
    BlockRequestChannel, BlockTxnsChannel, PublishError, RangeRequestChannel, TransportCore,
    TransportEvent,
};

/// Events the task may have forwarded and the loop not yet taken.
pub const INBOUND_CAPACITY: usize = 4096;

/// Publishes the loop may have queued and the task not yet taken.
pub const PUBLISH_CAPACITY: usize = 1024;

/// Transiently refused publishes the task keeps for a retry.
pub const RETRY_CAPACITY: usize = 1024;

/// Which topic a queued publish goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PubTopic {
    /// The chain-bound v4 envelope topic.
    V4,
    /// gov5's native consensus topic.
    Native,
    /// The block-body topic.
    Block,
    /// The transaction topic.
    Tx,
}

/// What the loop asks the task to do, other than publish.
#[derive(Debug)]
pub(crate) enum Command {
    Dial(Multiaddr),
    SetHeight(u64),
    RequestBlock(PeerId, B256),
    RequestRange(PeerId, RangeRequest),
    RequestTxns(PeerId, BlockTxnsRequest),
    RespondTxns(BlockTxnsChannel, BlockTxnsReply),
    RespondRange(RangeRequestChannel, Vec<Vec<u8>>),
    RespondBlock(BlockRequestChannel, Option<alloy_primitives::Bytes>),
    PushBlock(PeerId, alloy_primitives::Bytes),
    /// A direct vote (or hello) for one peer; see [`crate::rpc::VOTE_PROTOCOL`].
    SendVote(PeerId, crate::rpc::VoteRequest),
}

/// What the loop reads of the task's state without asking it.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    connected: Mutex<Vec<PeerId>>,
    mesh: AtomicUsize,
    native_mesh: AtomicUsize,
    queue_max: AtomicUsize,
    poll_us: AtomicU64,
}

impl Shared {
    pub(crate) fn connected_count(&self) -> usize {
        self.connected.lock().map_or(0, |peers| peers.len())
    }

    pub(crate) fn connected_peer_ids(&self) -> Vec<PeerId> {
        self.connected.lock().map_or_else(|_| Vec::new(), |peers| peers.clone())
    }

    pub(crate) fn mesh_size(&self) -> usize {
        self.mesh.load(Ordering::Relaxed)
    }

    pub(crate) fn native_mesh_size(&self) -> usize {
        self.native_mesh.load(Ordering::Relaxed)
    }

    /// The deepest inbound queue and the swarm poll time since the last call.
    pub(crate) fn take_stats(&self) -> (usize, u64) {
        (
            self.queue_max.swap(0, Ordering::Relaxed),
            self.poll_us.swap(0, Ordering::Relaxed),
        )
    }
}

/// The loop's half: the channels to and from the task.
#[derive(Debug)]
pub(crate) struct OffLoop {
    commands: mpsc::UnboundedSender<Command>,
    publishes: mpsc::Sender<(PubTopic, Vec<u8>)>,
    inbound: mpsc::Receiver<TransportEvent>,
    shared: Arc<Shared>,
}

impl OffLoop {
    /// Moves `core` onto a task of the current tokio runtime.
    pub(crate) fn spawn(core: TransportCore) -> Self {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (publishes, publish_rx) = mpsc::channel(PUBLISH_CAPACITY);
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_CAPACITY);
        let shared = Arc::new(Shared::default());
        tokio::spawn(pump(core, command_rx, publish_rx, inbound_tx, Arc::clone(&shared)));
        Self {
            commands,
            publishes,
            inbound,
            shared,
        }
    }

    pub(crate) fn shared(&self) -> &Shared {
        &self.shared
    }

    /// Queues a command; a stopped task drops it (the loop learns that the
    /// transport ended from `next_event`).
    pub(crate) fn command(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    /// Queues a publish.
    pub(crate) fn publish(
        &self,
        topic: PubTopic,
        data: Vec<u8>,
    ) -> Result<gossipsub::MessageId, PublishError> {
        match self.publishes.try_send((topic, data)) {
            Ok(()) => Ok(gossipsub::MessageId::new(&[])),
            Err(_) => Err(PublishError::Gossipsub(gossipsub::PublishError::AllQueuesFull(
                PUBLISH_CAPACITY,
            ))),
        }
    }

    pub(crate) async fn next_event(&mut self) -> Option<TransportEvent> {
        self.inbound.recv().await
    }
}

/// A future with the time spent inside its `poll` calls.
struct Timed<F> {
    inner: Pin<Box<F>>,
    spent: Duration,
}

impl<F: Future> Future for Timed<F> {
    type Output = (F::Output, Duration);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let at = Instant::now();
        let polled = self.inner.as_mut().poll(cx);
        self.spent += at.elapsed();
        match polled {
            Poll::Ready(output) => Poll::Ready((output, self.spent)),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn pump(
    mut core: TransportCore,
    mut commands: mpsc::UnboundedReceiver<Command>,
    mut publishes: mpsc::Receiver<(PubTopic, Vec<u8>)>,
    inbound: mpsc::Sender<TransportEvent>,
    shared: Arc<Shared>,
) {
    let mut retry: VecDeque<(PubTopic, Vec<u8>)> = VecDeque::new();
    let mut connected: HashSet<PeerId> = HashSet::new();
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => match command {
                Some(command) => apply(&mut core, command),
                None => return,
            },
            publish = publishes.recv() => match publish {
                Some((topic, data)) => publish_or_keep(&mut core, topic, data, &mut retry),
                None => return,
            },
            (event, spent) = Timed { inner: Box::pin(core.next_event()), spent: Duration::ZERO } => {
                shared.poll_us.fetch_add(spent.as_micros() as u64, Ordering::Relaxed);
                let Some(event) = event else { return };
                match &event {
                    TransportEvent::PeerConnected(peer) => {
                        connected.insert(*peer);
                        publish_connected(&shared, &connected);
                    }
                    TransportEvent::PeerDisconnected(peer) => {
                        connected.remove(peer);
                        publish_connected(&shared, &connected);
                    }
                    _ => {}
                }
                shared.mesh.store(core.mesh_size(), Ordering::Relaxed);
                shared.native_mesh.store(core.native_mesh_size(), Ordering::Relaxed);
                // Back-pressure, not drops: a consensus message is never
                // discarded here.
                if inbound.send(event).await.is_err() {
                    return;
                }
                let depth = inbound.max_capacity() - inbound.capacity();
                shared.queue_max.fetch_max(depth, Ordering::Relaxed);
                for _ in 0..retry.len() {
                    if let Some((topic, data)) = retry.pop_front() {
                        publish_or_keep(&mut core, topic, data, &mut retry);
                    }
                }
            }
        }
    }
}

fn publish_connected(shared: &Shared, connected: &HashSet<PeerId>) {
    if let Ok(mut peers) = shared.connected.lock() {
        *peers = connected.iter().copied().collect();
    }
}

fn publish_or_keep(
    core: &mut TransportCore,
    topic: PubTopic,
    data: Vec<u8>,
    retry: &mut VecDeque<(PubTopic, Vec<u8>)>,
) {
    match core.publish_raw(topic, data.clone()) {
        Ok(_) => {}
        Err(err) if err.is_already_published() => {}
        Err(err) if err.is_transient() => {
            retry.push_back((topic, data));
            while retry.len() > RETRY_CAPACITY {
                retry.pop_front();
            }
        }
        Err(err) => {
            tracing::debug!(target: "n42.h2.net", ?topic, %err, "publish refused");
        }
    }
}

fn apply(core: &mut TransportCore, command: Command) {
    match command {
        Command::Dial(addr) => {
            if let Err(err) = core.dial(addr) {
                tracing::debug!(target: "n42.h2.net", %err, "dial refused");
            }
        }
        Command::SetHeight(height) => core.set_advertised_height(height),
        Command::RequestBlock(peer, hash) => core.request_block(peer, hash),
        Command::RequestRange(peer, request) => core.request_range(peer, request),
        Command::RequestTxns(peer, request) => core.request_block_txns(peer, request),
        Command::RespondTxns(channel, reply) => core.respond_block_txns(channel, reply),
        Command::RespondRange(channel, rlps) => core.respond_range(channel, rlps),
        Command::RespondBlock(channel, rlp) => core.respond_block(channel, rlp),
        Command::PushBlock(peer, rlp) => core.push_block(peer, rlp),
        Command::SendVote(peer, request) => core.send_vote(peer, request),
    }
}

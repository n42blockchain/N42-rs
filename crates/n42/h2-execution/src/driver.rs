// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Connects the HotStuff-2 state machine to an execution layer.
//!
//! The consensus engine speaks in two directions and this driver services both:
//!
//! | Consensus says | Driver does | Consensus hears back |
//! |---|---|---|
//! | (leader for this view) | FCU-with-attrs, then resolve the build | [`ConsensusEvent::BlockReady`] |
//! | [`EngineOutput::ExecuteBlock`] | `new_payload` for that hash | [`ConsensusEvent::BlockImported`] |
//! | [`EngineOutput::BlockCommitted`] | FCU with head = safe = finalized | — |
//!
//! The middle row is the one that matters for safety: N42 votes are
//! *import-gated*, so a follower only votes after its own execution layer has
//! accepted the block. That is what stops a validator from endorsing a block it
//! cannot execute.

use std::collections::HashMap;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    ExecutionData, ForkchoiceState, PayloadAttributes, PayloadStatusEnum,
};
use n42_h2_consensus::{ConsensusEvent, EngineOutput};
use tracing::{debug, info, warn};

use crate::{
    el::{BuiltBlock, ElError, ExecutionLayer, ForeignBody, ResolveKind},
    ExecutionPath,
};

/// What the driver produced for one consensus output.
///
/// Not `Clone`/`PartialEq`: [`ConsensusEvent`] is neither, and wrapping it in
/// something that is would mean cloning payloads on a path that never needs to.
/// Tests use the accessors below.
/// What a follower import running on a task reports to the loop, through
/// the channel [`ExecutionDriver::take_foreign_imports`] hands out.
#[derive(Debug)]
pub enum ImportReport {
    /// Under deferred execution: the execution layer checked the block
    /// (header fields against its result for the parent, transactions
    /// includable on the parent's state) and is executing it -- the vote
    /// may go out.
    Checked(B256),
    /// The import finished, with the verdict an awaited import would have
    /// returned.
    Done(B256, ImportVerdict),
}

/// How a spawned import ended.
#[derive(Debug)]
pub enum ImportVerdict {
    /// The execution layer holds the block.
    Imported,
    /// The execution layer has not executed it (SYNCING/ACCEPTED): not a
    /// verdict -- the block is asked for again, as on the awaited path.
    NotYet,
    /// The execution layer refused it, or the import could not run.
    Invalid(String),
}

impl ImportVerdict {
    fn of(outcome: Result<alloy_rpc_types_engine::PayloadStatus, ElError>) -> Self {
        match outcome {
            Ok(status) => match status.status {
                PayloadStatusEnum::Valid => Self::Imported,
                PayloadStatusEnum::Syncing | PayloadStatusEnum::Accepted => Self::NotYet,
                PayloadStatusEnum::Invalid { validation_error } => Self::Invalid(validation_error.to_string()),
            },
            Err(error) => Self::Invalid(error.to_string()),
        }
    }
}

/// Reports a spawned import that ended without a verdict (a panic, a
/// dropped runtime), so the driver never waits on it forever.
struct ReportGuard {
    block_hash: B256,
    report: Option<tokio::sync::mpsc::UnboundedSender<ImportReport>>,
}

impl ReportGuard {
    fn done(mut self, verdict: ImportVerdict) {
        if let Some(report) = self.report.take() {
            let _ = report.send(ImportReport::Done(self.block_hash, verdict));
        }
    }
}

impl Drop for ReportGuard {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            let _ = report.send(ImportReport::Done(
                self.block_hash,
                ImportVerdict::Invalid("the import task ended without a verdict".to_string()),
            ));
        }
    }
}

/// Imports in flight at once under deferred execution: the one executing
/// and the one being checked behind it. The rest queue -- the pipeline is
/// one block deep by design, and every block admitted is a payload, a
/// sender recovery and an executed state held at once.
const DEFERRED_IN_FLIGHT: usize = 2;

/// A commit whose forkchoice has not been sent yet
/// (`N42_COMMIT_FCU_ASYNC=1`). One forkchoice is in flight at a time and
/// this is what goes next, so the engine never sees two commits out of
/// order.
#[derive(Debug)]
struct PendingCommit {
    block_hash: B256,
    /// Where this block sits in the order the driver heard commits (see
    /// [`ExecutionDriver::commit_order_of`]). The slot keeps the highest,
    /// because a commit for a lower order is a commit for an ancestor.
    order: u64,
    /// When the commit was heard, for the `queued_ms` of the measurement
    /// line.
    heard_at: std::time::Instant,
    /// Commits folded into this one, oldest first. Each has a lower commit
    /// order than `block_hash` and is therefore an ancestor of it: HotStuff-2
    /// commits a chain, one block per decided view, so the block committed at
    /// an earlier view is an ancestor of the one committed later. A forkchoice
    /// to a descendant makes its ancestors canonical and finalised too, so
    /// these need no forkchoice of their own -- only their bookkeeping, which
    /// [`ExecutionDriver::finish_commit`] does when the answer arrives.
    skipped: Vec<B256>,
}

/// What a commit forkchoice sent from a task reports back to the loop,
/// through the channel [`ExecutionDriver::take_commit_reports`] hands out.
///
/// The loop feeds it to [`ExecutionDriver::finish_commit`], which applies
/// every state effect the awaited `commit` applied when it returned.
#[derive(Debug)]
pub struct CommitReport {
    block_hash: B256,
    /// The commit order this forkchoice was sent under (see
    /// [`ExecutionDriver::commit_order_of`]).
    order: u64,
    skipped: Vec<B256>,
    /// Whether this commit ran before the block's import landed, for the log
    /// line the awaited path writes.
    ahead_of_import: bool,
    answer: Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError>,
    /// Heard to sent.
    queued: std::time::Duration,
    /// Sent to answered.
    in_flight: std::time::Duration,
}

/// Reports a commit forkchoice whose task ended without an answer (a panic,
/// a dropped runtime), so the one-in-flight slot is never held for good.
struct CommitGuard {
    report: Option<tokio::sync::mpsc::UnboundedSender<CommitReport>>,
    block_hash: B256,
    order: u64,
    skipped: Vec<B256>,
    ahead_of_import: bool,
    queued: std::time::Duration,
    started: std::time::Instant,
}

impl CommitGuard {
    fn answer(mut self, answer: Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError>) {
        self.send(answer);
    }

    fn send(&mut self, answer: Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError>) {
        if let Some(report) = self.report.take() {
            let _ = report.send(CommitReport {
                block_hash: self.block_hash,
                order: self.order,
                skipped: std::mem::take(&mut self.skipped),
                ahead_of_import: self.ahead_of_import,
                answer,
                queued: self.queued,
                in_flight: self.started.elapsed(),
            });
        }
    }
}

impl Drop for CommitGuard {
    fn drop(&mut self) {
        self.send(Err(ElError::new("the commit forkchoice ended without an answer")));
    }
}

#[derive(Debug)]
pub enum DriverAction {
    /// Feed this back into [`n42_h2_consensus::ConsensusEngine::process_event`].
    ///
    /// Boxed because [`ConsensusEvent`] is ~800 bytes (its `Message` variant
    /// carries a whole consensus message) while every other action here is a
    /// hash or a string. Unboxed, every `DriverAction` would cost that much —
    /// and the driver only ever produces the tiny `BlockImported` variant.
    Consensus(Box<ConsensusEvent>),
    /// The execution layer accepted a commit; nothing to feed back.
    Finalized {
        /// The finalised block.
        block_hash: B256,
    },
    /// Consensus asked to execute a block whose payload the driver has not seen.
    ///
    /// Not an error: the proposal carries only a hash, and the block body
    /// arrives separately (direct push or fetch-on-miss). The caller should
    /// fetch it, call [`ExecutionDriver::cache_payload`], and retry.
    PayloadMissing {
        /// The block that could not be executed yet.
        block_hash: B256,
    },
    /// The execution layer rejected a block. Consensus must not vote for it.
    Rejected {
        /// The block that was rejected.
        block_hash: B256,
        /// Why.
        reason: String,
    },
    /// The output needed nothing from the execution layer.
    Ignored,
}

impl DriverAction {
    /// The block this action says was imported, if it is an import event.
    pub fn imported_block(&self) -> Option<B256> {
        match self {
            Self::Consensus(event) => match event.as_ref() {
                ConsensusEvent::BlockImported(hash) => Some(*hash),
                _ => None,
            },
            _ => None,
        }
    }

    /// The block this action finalised, if any.
    pub fn finalized_block(&self) -> Option<B256> {
        match self {
            Self::Finalized { block_hash } => Some(*block_hash),
            _ => None,
        }
    }

    /// The block whose payload is still missing, if any.
    pub fn missing_block(&self) -> Option<B256> {
        match self {
            Self::PayloadMissing { block_hash } => Some(*block_hash),
            _ => None,
        }
    }

    /// The rejection reason, if the execution layer refused the block.
    pub fn rejection(&self) -> Option<(B256, &str)> {
        match self {
            Self::Rejected { block_hash, reason } => Some((*block_hash, reason.as_str())),
            _ => None,
        }
    }
}

/// Rewrites a freshly built payload into the block this node will propose.
///
/// Called with the payload and the view it is proposed in. The execution
/// layer builds without knowing the view, and on a chain whose header
/// commits to it (gov5's HotStuff profile) the header has to be finished —
/// view stamped, seal signed, hash re-formed — before anyone else sees it.
/// The result is what gets cached, imported, and proposed.
pub type PayloadNormalizer = dyn Fn(&ExecutionData, Option<&alloy_consensus::Header>, u64)
        -> Result<(ExecutionData, Option<alloy_consensus::Header>), String>
    + Send
    + Sync;

/// Decodes a held [`ForeignBody`] into the payload the `NEW_PAYLOAD`
/// fallback sends. The wire form belongs to the node (`n42-h2-net`), not
/// here, so the node installs it.
type Decode = dyn Fn(&ForeignBody) -> Result<ExecutionData, String> + Send + Sync;

#[derive(Clone)]
pub struct BodyDecoder(std::sync::Arc<Decode>);

impl BodyDecoder {
    /// Wraps the node's decode.
    pub fn new(
        decode: impl Fn(&ForeignBody) -> Result<ExecutionData, String> + Send + Sync + 'static,
    ) -> Self {
        Self(std::sync::Arc::new(decode))
    }

    /// The payload a held body describes.
    pub fn decode(&self, body: &ForeignBody) -> Result<ExecutionData, String> {
        (self.0)(body)
    }
}

impl std::fmt::Debug for BodyDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BodyDecoder")
    }
}

struct Normalizer(Box<PayloadNormalizer>);

impl std::fmt::Debug for Normalizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PayloadNormalizer")
    }
}

/// A block being built before this node is leader.
///
/// Resolved the moment its first build is done rather than when the proposal
/// wants it, because a payload job that is still open holds a build lease in
/// reth's engine, and the engine (2.5.1, `wait_for_event`) stops taking any
/// message at all -- imports, forkchoice, everything -- from the moment a
/// persistence completes until every lease is released. A job left open for
/// the rest of the view therefore deadlocks with the very loop that would
/// close it, and the deadlock is only broken by the 8-second RPC timeout.
/// Measured as seven of those per round with a tenure of 16. Resolved at once,
/// the job lives for one build.
#[derive(Debug)]
struct AheadBuild {
    parent: B256,
    attrs: PayloadAttributes,
    task: tokio::task::JoinHandle<Result<BuiltBlock, ElError>>,
    /// Set by a build on the sealed block that the execution layer refused:
    /// this entry then counts as *no* build ahead, so the request that
    /// follows the own import replaces it with a forkchoice build instead of
    /// finding it "already prepared" (loop110 S1: a forkchoice sent before
    /// the import had landed was answered SYNCING and the leader built on
    /// its critical path 38 times).
    refused: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set when the build is given up. A build a forkchoice started holds a
    /// payload job in the execution layer until the job is resolved or its
    /// deadline passes (12 s at `--builder.deadline 3` once the chain's clock
    /// runs ahead of the wall clock), and reth takes no engine message while
    /// a persistence hand-off waits for every payload job to end: an aborted
    /// task left its job running, and a new leader's commit forkchoice and
    /// own block sat 10-11 s in front of the tree until a TC (loop161 W,
    /// node3 and node4). Such a task is told instead, and resolves its job
    /// before it ends. `None` for a build on the sealed block, which starts
    /// no job.
    give_up: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl AheadBuild {
    /// Drops this build: a task holding a payload job resolves the job and
    /// discards the block (see `give_up`); any other is aborted.
    fn discard(self) {
        match self.give_up {
            Some(flag) => flag.store(true, std::sync::atomic::Ordering::Release),
            None => self.task.abort(),
        }
    }

    /// Whether this build is for a later block than `attrs` asks for. The
    /// chain's attributes carry the block's number as `slot_number`, so two
    /// requests compare without either block being known here.
    fn is_newer_than(&self, attrs: &PayloadAttributes) -> bool {
        matches!((self.attrs.slot_number, attrs.slot_number), (Some(mine), Some(theirs)) if mine > theirs)
    }

    fn covers(&self, parent: B256, attrs: &PayloadAttributes) -> bool {
        self.parent == parent
            && self.attrs == *attrs
            && !self.refused.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Takes an own block off [`ExecutionDriver::is_importing_own_block`]'s set
/// when its import task ends, however it ends.
struct OwnImportDone {
    importing: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<B256>>>,
    hash: B256,
}

impl Drop for OwnImportDone {
    fn drop(&mut self) {
        self.importing.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.hash);
    }
}

/// Drives an [`ExecutionLayer`] on behalf of the consensus engine.
#[derive(Debug)]
pub struct ExecutionDriver<E> {
    /// Shared so a leader's import of its own block can be handed to a task
    /// instead of awaited. See [`Self::spawn_import_own_block`].
    el: std::sync::Arc<E>,
    /// Finishes a built payload before it is proposed. `None` proposes the
    /// payload exactly as built.
    normalizer: Option<Normalizer>,
    /// A build started before this node needed the block. See
    /// [`Self::prepare_build_on`].
    prepared: Option<AheadBuild>,
    /// Where [`Self::spawn_import_own_block`] reports a block the execution
    /// layer has taken, for the loop to build ahead on: a leader's own block
    /// raises no `BlockImported` -- that event belongs to the follower path
    /// -- and with a tenure the next build waits for exactly this.
    own_imports: tokio::sync::mpsc::UnboundedSender<B256>,
    /// The receiving end, until the loop takes it.
    own_imports_rx: Option<tokio::sync::mpsc::UnboundedReceiver<B256>>,
    /// This node's own blocks whose import task has not ended. See
    /// [`Self::is_importing_own_block`].
    own_importing: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<B256>>>,
    /// **Bench only** (`N42_VOTE_BEFORE_IMPORT=1`): a follower's import runs
    /// on a task instead of being awaited by the loop, so the loop can vote
    /// on the next proposal while the block executes -- what deferred
    /// execution would give the cycle. Imports still run one at a time, in
    /// order; the rest queue.
    spawn_imports: bool,
    /// The chain's `deferredExecutionTime`
    /// (docs/PHASE_D_DEFERRED_EXECUTION.md), if it has one: a block stamped
    /// at or past it is *checked* before it is executed, the check releases
    /// the vote ([`ImportReport::Checked`]), and the import runs on a task
    /// beside the loop and beside the next block's check -- the execution
    /// layer orders them by parent. Blocks before the fork take the path
    /// above.
    deferred_execution_time: Option<u64>,
    /// Where a spawned import reports.
    foreign_imports: tokio::sync::mpsc::UnboundedSender<ImportReport>,
    /// The receiving end, until the loop takes it.
    foreign_imports_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ImportReport>>,
    /// Blocks waiting for the import in flight to finish (spawned mode).
    import_queue: std::collections::VecDeque<B256>,
    /// Payloads seen but not yet executed, keyed by block hash. Populated from
    /// proposals, direct pushes, and our own builds.
    payloads: HashMap<B256, ExecutionData>,
    /// Foreign blocks held as the bytes they arrived in, for
    /// [`ExecutionLayer::new_payload_body_checked`] (`N42_BODY_ONCE=1`). A
    /// block here has no entry in `payloads`: the whole point is that the
    /// body is decoded once, on the execution layer's side. If that side
    /// refuses the request the body is decoded here instead -- on the
    /// import's task, off the consensus loop -- by `body_decoder`.
    bodies: HashMap<B256, ForeignBody>,
    /// Turns a held body into the payload the fallback sends. Installed by
    /// the node, which owns the wire format; without one a refused body
    /// cannot fall back and the block is asked for again.
    body_decoder: Option<BodyDecoder>,
    /// Current head, as consensus understands it.
    head: B256,
    /// Last block consensus committed.
    finalized: B256,
    /// The blocks `execute` is importing right now: one on the awaited and
    /// the queued paths, any number under deferred execution.
    executing: std::collections::HashSet<B256>,
    /// Commits that arrived while their import was in flight (a follower
    /// that voted before importing): the forkchoice waits for the import,
    /// since the engine would answer SYNCING for a block it has not seen.
    /// Only an import in flight defers a commit -- a block imported by
    /// another path (the leader's own block by header, a synced range)
    /// commits at once, as before.
    pending_commits: std::collections::HashSet<B256>,
    /// Blocks whose import landed here (any path), newest last, bounded:
    /// what a commit checks to know whether the engine had the block.
    imported: std::collections::VecDeque<B256>,
    /// Commits that ran before the block reached this node at all -- a
    /// follower hears the Decide before the body channel delivers (tens of
    /// milliseconds apart under load, and block after block: loop152-154).
    /// The forkchoice the engine answered then made nothing canonical; it
    /// runs again when the block's import lands.
    commits_ahead: std::collections::HashSet<B256>,
    /// Bounds `payloads` so a peer cannot make us buffer without limit.
    max_cached_payloads: usize,
    /// Insertion order, for evicting the oldest cached payload.
    payload_order: Vec<B256>,
    /// `N42_COMMIT_FCU_ASYNC`: send the commit's forkchoice from a task and
    /// apply its outcome when the report arrives, instead of awaiting it
    /// inside the consensus loop. Measured (loop189 X0a) as 37 ms of the
    /// 51 ms between the next view opening and the leader's proposal
    /// preamble -- time in which the loop processes no proposal, no vote and
    /// no body. Off, every commit takes the awaited path byte for byte.
    commit_async: bool,
    /// The commit whose forkchoice is on the wire, if any. One at a time, so
    /// the engine never sees two out of order.
    commit_in_flight: Option<B256>,
    /// The commit that goes next (see [`PendingCommit`]).
    commit_pending: Option<PendingCommit>,
    /// The order the driver first heard each block's commit in, so a commit
    /// re-asked for an ancestor (the pending-commit replay after an import
    /// lands) is never sent after a descendant's.
    commit_orders: HashMap<B256, u64>,
    /// Insertion order of `commit_orders`, for bounding it.
    commit_order_seen: std::collections::VecDeque<B256>,
    /// The next commit order to hand out.
    commit_seq: u64,
    /// The highest commit order whose forkchoice the engine has taken. A
    /// commit re-asked for a block at or below it is a commit for a block
    /// already canonical, and sending it would move the engine's head
    /// backwards.
    commit_landed: u64,
    /// Commit forkchoices answered so far, for rate-limiting the
    /// measurement line to every sixteenth.
    commits_answered: u64,
    /// Where a spawned commit forkchoice reports.
    commit_reports: tokio::sync::mpsc::UnboundedSender<CommitReport>,
    /// The receiving end, until the loop takes it.
    commit_reports_rx: Option<tokio::sync::mpsc::UnboundedReceiver<CommitReport>>,
}

/// `N42_BODY_ONCE`, read once: opt-in, and read on the validator's side,
/// because that is the side that stops decoding the body. Off, everything
/// takes the `NEW_PAYLOAD` path it always took.
pub fn body_once() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BODY_ONCE").is_ok_and(|v| v == "1"))
}

/// `N42_COMMIT_FCU_ASYNC`, read once: opt-in, and only the *default* for a
/// driver -- [`ExecutionDriver::set_commit_fcu_async`] is what a test uses,
/// so the two paths are exercised without the process environment deciding
/// for them.
pub fn commit_fcu_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_COMMIT_FCU_ASYNC").is_ok_and(|v| v == "1"))
}

/// Releases a deferred block's vote: the execution layer said the header
/// carries its result for the parent and the transactions are includable.
/// Anything but VALID is not a vote and is left to the import's verdict.
fn release_check(
    report: &tokio::sync::mpsc::UnboundedSender<ImportReport>,
    block_hash: B256,
    size: BlockSize,
    started: std::time::Instant,
    checked: Option<alloy_rpc_types_engine::PayloadStatus>,
) {
    let Some(status) = checked else { return };
    if !matches!(status.status, PayloadStatusEnum::Valid) {
        return;
    }
    if size.worth_logging() {
        info!(target: "n42.h2.el", block = ?block_hash, txs = size.txs, bytes = size.bytes, check_ms = started.elapsed().as_millis() as u64, "checked a block; executing");
    }
    let _ = report.send(ImportReport::Checked(block_hash));
}

/// How big the block being imported is, in whichever unit this node knows
/// it: a payload's transaction count, or a body's bytes -- a body is held
/// undecoded, which is the whole point, so its transactions have not been
/// counted.
#[derive(Debug, Clone, Copy, Default)]
struct BlockSize {
    txs: usize,
    bytes: usize,
}

impl BlockSize {
    /// Big enough for the per-block lines, which exist for the bench tier.
    const fn worth_logging(self) -> bool {
        self.txs >= 10_000 || self.bytes >= 1_000_000
    }
}

impl<E: ExecutionLayer> ExecutionDriver<E> {
    /// Default payload cache size — a few views' worth of blocks.
    pub const DEFAULT_MAX_CACHED_PAYLOADS: usize = 16;

    /// Builds a driver whose head and finalised block are `genesis`.
    pub fn new(el: E, genesis: B256) -> Self {
        let (own_imports_tx, own_imports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (foreign_tx, foreign_rx) = tokio::sync::mpsc::unbounded_channel();
        let (commit_tx, commit_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            el: std::sync::Arc::new(el),
            normalizer: None,
            prepared: None,
            own_imports: own_imports_tx,
            own_imports_rx: Some(own_imports_rx),
            own_importing: Default::default(),
            spawn_imports: false,
            deferred_execution_time: None,
            foreign_imports: foreign_tx,
            foreign_imports_rx: Some(foreign_rx),
            import_queue: std::collections::VecDeque::new(),
            payloads: HashMap::new(),
            bodies: HashMap::new(),
            body_decoder: None,
            head: genesis,
            finalized: genesis,
            executing: std::collections::HashSet::new(),
            pending_commits: std::collections::HashSet::new(),
            imported: std::collections::VecDeque::new(),
            commits_ahead: std::collections::HashSet::new(),
            max_cached_payloads: Self::DEFAULT_MAX_CACHED_PAYLOADS,
            payload_order: Vec::new(),
            commit_async: commit_fcu_async(),
            commit_in_flight: None,
            commit_pending: None,
            commit_orders: HashMap::new(),
            commit_order_seen: std::collections::VecDeque::new(),
            commit_seq: 0,
            commit_landed: 0,
            commits_answered: 0,
            commit_reports: commit_tx,
            commit_reports_rx: Some(commit_rx),
        }
    }

    /// Installs a [`PayloadNormalizer`] applied to every block this node builds.
    pub fn set_payload_normalizer(
        &mut self,
        normalizer: impl Fn(&ExecutionData, Option<&alloy_consensus::Header>, u64) -> Result<(ExecutionData, Option<alloy_consensus::Header>), String>
            + Send
            + Sync
            + 'static,
    ) {
        self.normalizer = Some(Normalizer(Box::new(normalizer)));
    }

    /// Overrides the payload cache bound.
    pub fn with_max_cached_payloads(mut self, max: usize) -> Self {
        self.max_cached_payloads = max.max(1);
        self
    }

    /// The execution layer this driver owns.
    pub fn execution_layer(&self) -> &E {
        &self.el
    }

    /// Current head.
    pub fn head(&self) -> B256 {
        self.head
    }

    /// Last committed block.
    pub fn finalized(&self) -> B256 {
        self.finalized
    }

    /// Records a block payload so a later `ExecuteBlock` for it can proceed.
    pub fn cache_payload(&mut self, block_hash: B256, payload: ExecutionData) {
        if self.payloads.insert(block_hash, payload).is_none() {
            self.payload_order.push(block_hash);
            while self.payload_order.len() > self.max_cached_payloads {
                let oldest = self.payload_order.remove(0);
                self.payloads.remove(&oldest);
                self.bodies.remove(&oldest);
            }
        }
    }

    /// Whether a payload is cached for `block_hash`.
    pub fn has_payload(&self, block_hash: &B256) -> bool {
        self.payloads.contains_key(block_hash)
    }

    /// Records a foreign block as the bytes it arrived in, so its import
    /// can hand the execution layer those bytes rather than a payload
    /// re-encoded from them. Bounded exactly as the payload cache is.
    pub fn cache_body(&mut self, body: ForeignBody) {
        let block_hash = body.block_hash;
        if self.bodies.insert(block_hash, body).is_none() {
            self.payload_order.push(block_hash);
            while self.payload_order.len() > self.max_cached_payloads {
                let oldest = self.payload_order.remove(0);
                self.payloads.remove(&oldest);
                self.bodies.remove(&oldest);
            }
        }
    }

    /// Installs the decoder the `NEW_PAYLOAD` fallback needs. See
    /// [`BodyDecoder`].
    pub fn set_body_decoder(&mut self, decoder: BodyDecoder) {
        self.body_decoder = Some(decoder);
    }

    /// The payload for a block on the paths that have no body request of
    /// their own (the awaited import, the queued one): the cached payload,
    /// or a held body decoded here. Decoding on the loop is the price of
    /// those paths; the deferred path, the one the fleet runs, decodes only
    /// on its own task and only when the execution layer refused the body.
    fn payload_for(&self, block_hash: B256) -> Result<ExecutionData, DriverAction> {
        if let Some(payload) = self.payloads.get(&block_hash) {
            return Ok(payload.clone());
        }
        match (self.bodies.get(&block_hash), &self.body_decoder) {
            (Some(body), Some(decode)) => decode.decode(body).map_err(|err| {
                warn!(target: "n42.h2.el", block = ?block_hash, %err, "a held body could not be decoded");
                DriverAction::Rejected { block_hash, reason: err }
            }),
            _ => Err(DriverAction::PayloadMissing { block_hash }),
        }
    }

    /// Whether a body is held for `block_hash`.
    pub fn has_body(&self, block_hash: &B256) -> bool {
        self.bodies.contains_key(block_hash)
    }

    /// The forkchoice this driver would send right now.
    fn forkchoice(&self, head: B256) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: head,
            safe_block_hash: self.finalized,
            finalized_block_hash: self.finalized,
        }
    }

    /// Starts a build now for a block this node expects to propose later.
    ///
    /// The execution layer needs time to fill a block -- measured at the 480M
    /// tier as 95 ms of a 195 ms leader path, which is the largest single
    /// piece of it -- and that time is only on the critical path because the
    /// build starts when the node becomes leader. It does not have to.
    ///
    /// The parent of the block a leader proposes is the block committed in the
    /// view before it, and a node knows that block when it *imports* it, which
    /// is before the fleet has finished voting on it. Starting the build there
    /// overlaps it with the rest of the consensus round, so by the time this
    /// node is leader the payload is waiting.
    ///
    /// Speculative and cheap to be wrong about: if that view ends in a timeout
    /// instead of a commit, the parent this was started on is not the parent
    /// the proposal needs, the prepared build is discarded on the mismatch, and
    /// the leader starts one the old way.
    pub async fn prepare_build_on(
        &mut self,
        parent: B256,
        attrs: PayloadAttributes,
    ) -> Result<(), ElError> {
        if self.prepared.as_ref().is_some_and(|ahead| ahead.covers(parent, &attrs)) {
            return Ok(());
        }
        if self.prepared.as_ref().is_some_and(|ahead| ahead.is_newer_than(&attrs)) {
            // A request for a parent older than the build already prepared:
            // the own import of block N completing after N+1 was sealed and
            // its build started (loop116 S2: a hand-off held 491 ms by a QMDB
            // checkpoint). Replacing the build would abort N+2's, and the
            // forkchoice to N that started the replacement made reth unwind
            // N+1 as a reorg -- 11 s on the engine, the validator's request
            // timing out, the chain forking on the rebuilt block.
            info!(target: "n42.h2.el", ?parent, "a build ahead is already prepared on a newer parent; the request is stale");
            return Ok(());
        }
        if let Some(stale) = self.prepared.take() {
            stale.discard();
        }
        // Off the caller's loop entirely: the forkchoice call that starts the
        // build is answered by the same engine the loop's other calls queue
        // behind, and a loop that awaits it here is the loop that cannot
        // resolve the build when the engine waits for that.
        let el = std::sync::Arc::clone(&self.el);
        let state = self.forkchoice(parent);
        let task_attrs = attrs.clone();
        info!(target: "n42.h2.el", ?parent, "starting a build ahead of leading");
        let give_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let given_up = std::sync::Arc::clone(&give_up);
        let task = tokio::spawn(async move {
            // Given up before it started: no forkchoice, so no job to end.
            if given_up.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ElError::new("the build ahead was given up before it started"));
            }
            let started = std::time::Instant::now();
            let updated = el
                .fork_choice_updated_with_attrs_for(ExecutionPath::LIVE_SEQUENTIAL, state, task_attrs)
                .await?;
            let id = updated.payload_id.ok_or_else(|| {
                ElError::new(format!(
                    "forkchoiceUpdated started no build ahead of leading (status {:?})",
                    updated.payload_status.status
                ))
            })?;
            let after_fcu = started.elapsed();
            let built = el
                .resolve_payload_for(ExecutionPath::LIVE_SEQUENTIAL, id, ResolveKind::WaitForPending)
                .await
                .ok_or_else(|| ElError::new(format!("no payload build for id {id}")))??;
            if given_up.load(std::sync::atomic::Ordering::Acquire) {
                info!(target: "n42.h2.el", ?parent, number = built.number, "a build ahead that was given up resolved its payload job");
                return Err(ElError::new("the build ahead was given up"));
            }
            info!(
                target: "n42.h2.el",
                ?parent,
                number = built.number,
                fcu_ms = after_fcu.as_millis() as u64,
                build_ms = (started.elapsed() - after_fcu).as_millis() as u64,
                "built a block ahead of leading"
            );
            Ok(built)
        });
        self.prepared = Some(AheadBuild { parent, attrs, task, refused: Default::default(), give_up: Some(give_up) });
        Ok(())
    }

    /// [`Self::prepare_build_on`] for a block this node built and has just
    /// sealed: the build starts on the builder's own post-state at once
    /// (`ExecutionLayer::build_on_own_block`), instead of after the engine
    /// has imported the block and answered a forkchoice on it -- own import
    /// 62 ms and forkchoice 72 ms on the leader's chain at the bench tier,
    /// with the leader then waiting for the build on nearly every block
    /// (loop108, `docs/FLEET7_PLAN_V2.md`). An execution layer that does not
    /// offer the direct build, or no longer holds the parent, falls back to
    /// the forkchoice path inside the same task, so the prepared build is
    /// there either way.
    /// `chain` says the height after the one being built is this node's as
    /// well (`N42_BUILD_CHAIN`): the execution layer may hand the block's
    /// header back the moment it seals it, and the build after it starts on
    /// that header instead of on the request the proposal makes ~110 ms
    /// later (loop190/191: 68-84 ms with the builder idle, then 33-42 ms of
    /// request overhead). `None` chains nothing.
    pub async fn prepare_build_on_sealed(
        &mut self,
        parent: B256,
        header: alloy_consensus::Header,
        attrs: PayloadAttributes,
        chain: Option<crate::el::ChainAhead>,
    ) -> Result<(), ElError> {
        if self.prepared.as_ref().is_some_and(|ahead| ahead.covers(parent, &attrs)) {
            return Ok(());
        }
        if self.prepared.as_ref().is_some_and(|ahead| ahead.is_newer_than(&attrs)) {
            info!(target: "n42.h2.el", ?parent, "a build ahead is already prepared on a newer parent; the request is stale");
            return Ok(());
        }
        if let Some(stale) = self.prepared.take() {
            stale.discard();
        }
        let el = std::sync::Arc::clone(&self.el);
        let task_attrs = attrs.clone();
        let refused = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mark_refused = std::sync::Arc::clone(&refused);
        info!(target: "n42.h2.el", ?parent, "starting a build ahead on the sealed block");
        let task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            match el.build_on_own_block_chaining(&header, task_attrs, chain).await {
                Some(Ok(built)) => {
                    // The same line the forkchoice path logs, so the leader
                    // analysis reads both; `fcu_ms` is zero here by design.
                    info!(
                        target: "n42.h2.el",
                        ?parent,
                        number = built.number,
                        fcu_ms = 0u64,
                        build_ms = started.elapsed().as_millis() as u64,
                        on_seal = true,
                        "built a block ahead of leading"
                    );
                    Ok(built)
                }
                // No forkchoice fallback here: the parent's import is still in
                // flight, and a forkchoice on a block the engine has not seen
                // is answered SYNCING. Marked refused instead, so the request
                // the own import makes afterwards builds ahead the ordinary
                // way, on a parent the engine then knows.
                Some(Err(err)) => {
                    mark_refused.store(true, std::sync::atomic::Ordering::Release);
                    warn!(target: "n42.h2.el", %err, ?parent, "the build on the sealed block failed; the own import will build ahead");
                    Err(err)
                }
                None => {
                    mark_refused.store(true, std::sync::atomic::Ordering::Release);
                    info!(target: "n42.h2.el", ?parent, "no build on the sealed block; the own import will build ahead");
                    Err(ElError::new("build on the sealed block refused"))
                }
            }
        });
        self.prepared = Some(AheadBuild { parent, attrs, task, refused, give_up: None });
        Ok(())
    }

    /// Leader path: builds a block on top of the current head.
    ///
    /// Returns the built block *and* caches its payload, so the subsequent
    /// `ExecuteBlock` for our own proposal is served locally rather than
    /// requiring a round trip.
    pub async fn build_block(
        &mut self,
        attrs: PayloadAttributes,
        view: u64,
    ) -> Result<BuiltBlock, ElError> {
        self.build_block_on(self.head, attrs, view).await
    }

    /// Builds on `parent` rather than on the head: what a leader does when the
    /// block its highest QC certifies is not the last block its execution
    /// layer imported. The forkchoice that starts the build makes `parent`
    /// the head (safe and finalized stay where they are), so the execution
    /// layer has to know the block already.
    /// Asks the execution layer for a block on `parent` now, and waits for it.
    async fn build_now(
        &self,
        parent: B256,
        attrs: PayloadAttributes,
        started: std::time::Instant,
    ) -> Result<(BuiltBlock, std::time::Duration), ElError> {
        let updated = self
            .el
            .fork_choice_updated_with_attrs_for(
                ExecutionPath::LIVE_SEQUENTIAL,
                self.forkchoice(parent),
                attrs,
            )
            .await?;
        let after_fcu = started.elapsed();
        let payload_id = updated.payload_id.ok_or_else(|| {
            ElError::new(format!(
                "forkchoiceUpdated returned no payload id (status {:?})",
                updated.payload_status.status
            ))
        })?;
        let built = self
            .el
            .resolve_payload_for(
                ExecutionPath::LIVE_SEQUENTIAL,
                payload_id,
                ResolveKind::WaitForPending,
            )
            .await
            .ok_or_else(|| ElError::new(format!("no payload build for id {payload_id}")))??;
        Ok((built, after_fcu))
    }

    pub async fn build_block_on(
        &mut self,
        parent: B256,
        attrs: PayloadAttributes,
        view: u64,
    ) -> Result<BuiltBlock, ElError> {
        // Timed in four parts because the leader's whole path is 396.5 ms
        // against 82.7 ms of block execution, and which part holds the rest
        // decides between two different fixes: building ahead of being leader
        // (so the wait leaves the critical path) or not building the block
        // twice (so the work is not done twice). Guessing between them is how
        // this file has been wrong before.
        let started = std::time::Instant::now();
        // A build prepared earlier counts only if it was started on this exact
        // parent with these exact attributes. Anything else and the block it
        // assembled is not the block this node is about to propose. One that
        // failed is reported and replaced, not propagated: the proposal is
        // worth more than the shortcut.
        let ahead = match self.prepared.take() {
            // A build on the sealed block the execution layer refused, and
            // that nothing replaced: the same as no build ahead.
            Some(prepared) if prepared.refused.load(std::sync::atomic::Ordering::Acquire) => {
                prepared.discard();
                None
            }
            Some(prepared) if prepared.parent == parent && prepared.attrs == attrs => {
                match prepared.task.await {
                    Ok(Ok(built)) => Some(built),
                    Ok(Err(err)) => {
                        warn!(target: "n42.h2.el", %err, ?parent, "the build prepared ahead failed; building now");
                        None
                    }
                    Err(err) => {
                        warn!(target: "n42.h2.el", %err, ?parent, "the build prepared ahead was lost; building now");
                        None
                    }
                }
            }
            Some(prepared) => {
                info!(
                    target: "n42.h2.el",
                    prepared_on = ?prepared.parent,
                    asked = ?parent,
                    same_parent = prepared.parent == parent,
                    same_attrs = prepared.attrs == attrs,
                    "a build prepared ahead does not match the proposal; discarded"
                );
                prepared.discard();
                None
            }
            None => None,
        };
        // With a build from ahead, fcu_ms below is the wait for one still in
        // flight and build_ms is nothing. Without, the status is reported
        // rather than a bare "no payload id": VALID-without-an-id and SYNCING
        // mean very different things to an operator.
        // A build prepared ahead is trusted only if the block it delivered
        // really extends the parent asked for: round 38 saw a build ahead
        // resolve in 2 ms with a block on the previous parent, which every
        // voter then refused as not extending the justify QC.
        let ahead = match ahead {
            Some(built) if built.execution_data.payload.parent_hash() == parent => Some(built),
            Some(built) => {
                warn!(
                    target: "n42.h2.el",
                    asked = ?parent,
                    delivered_on = ?built.execution_data.payload.parent_hash(),
                    block = ?built.hash,
                    "the build prepared ahead extends another parent; building now"
                );
                None
            }
            None => None,
        };
        let (mut built, after_fcu, after_resolve, ahead) = match ahead {
            Some(built) => (built, started.elapsed(), started.elapsed(), true),
            None => {
                let (built, after_fcu) = self.build_now(parent, attrs, started).await?;
                (built, after_fcu, started.elapsed(), false)
            }
        };
        if built.execution_data.payload.parent_hash() != parent {
            return Err(ElError::new(format!(
                "the execution layer built on {} when asked for {parent}",
                built.execution_data.payload.parent_hash()
            )));
        }

        // The block the execution layer built is not necessarily the block
        // this node proposes: a chain whose header carries the view needs it
        // stamped and sealed first, and that changes the hash. From here on
        // only the finished block exists — it is what gets imported, and the
        // hash consensus sees.
        if let Some(normalize) = &self.normalizer {
            // The header the execution layer handed over, when it did: the
            // seal then touches the header alone and never decodes the block.
            let (finished, header) = (normalize.0)(&built.execution_data, built.header.as_ref(), view)
                .map_err(|e| ElError::new(format!("finishing the built block: {e}")))?;
            built.hash = finished.block_hash();
            built.execution_data = finished;
            built.header = header;
        }

        let after_seal = started.elapsed();
        self.cache_payload(built.hash, built.execution_data.clone());

        info!(
            target: "n42.h2.el",
            view,
            ahead,
            fcu_ms = after_fcu.as_millis() as u64,
            build_ms = (after_resolve - after_fcu).as_millis() as u64,
            seal_ms = (after_seal - after_resolve).as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "leader build path"
        );
        Ok(built)
    }

    /// Inserts a block this node built into its own execution layer.
    ///
    /// Separate from building, and called *after* the proposal has gone out,
    /// because it is not on the fleet's critical path and used to be on it.
    /// `getPayload` builds a block without inserting it, and the leader never
    /// receives its own proposal back over gossip, so nothing else ever will:
    /// the block would be committed by consensus and then rejected by the
    /// leader's own execution layer, which answers the commit's
    /// forkchoiceUpdated with SYNCING and leaves the chain stuck at the parent.
    /// So it has to happen -- it just does not have to happen first.
    ///
    /// It costs a second full execution of the block. Sealing the view into
    /// the header changes the hash, so the execution layer cannot recognise
    /// the block as the one it assembled and runs every transaction again;
    /// reth short-circuits a block already in its tree, and a block from
    /// `getPayload` is not in it. Measured at the 480M tier as 80 ms of a
    /// 195 ms leader path, against 95 ms of waiting for the build and 17 ms of
    /// sealing. Ahead of the proposal it delayed every follower by that much;
    /// behind it, the followers have had the body for 80 ms already and are
    /// executing it in parallel with this.
    /// Starts the import of a block this node built, without waiting for it.
    ///
    /// The wait was the point of moving it behind the proposal and it is not
    /// enough on its own: at the 163,000-transaction tier the import is 710 ms,
    /// and awaiting it holds the consensus loop for that long -- during which
    /// the leader cannot read the votes for the block it has just proposed.
    ///
    /// Nothing needs to come back from it. The consensus engine asks for the
    /// block to be executed like any other, and that request finds it already
    /// in the execution layer's tree and returns at once; if this task has not
    /// finished by then, the request executes the block itself and the only
    /// cost is that the saving did not happen. gov5's sibling client calls
    /// those the two cases and falls back the same way.
    ///
    /// Two `newPayload` calls for one block cannot race: reth serialises engine
    /// requests through one channel, and the second finds the block in the tree.
    pub fn spawn_import_own_block(&self, built: &BuiltBlock) {
        let el = std::sync::Arc::clone(&self.el);
        let payload = built.execution_data.clone();
        let header = built.header.clone();
        let hash = built.hash;
        let imported = self.own_imports.clone();
        self.own_importing.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(hash);
        let done = OwnImportDone { importing: std::sync::Arc::clone(&self.own_importing), hash };
        tokio::spawn(async move {
            let _done = done;
            let started = std::time::Instant::now();
            match el.import_own_block(header.as_ref(), payload).await {
                Ok(status) => {
                    info!(
                        target: "n42.h2.el",
                        block = ?hash,
                        import_ms = started.elapsed().as_millis() as u64,
                        status = ?status.status,
                        "imported our own block"
                    );
                    if status.status.is_valid() {
                        let _ = imported.send(hash);
                    }
                }
                Err(err) => warn!(
                    target: "n42.h2.el",
                    block = ?hash, %err,
                    "our own execution layer would not take the block we built"
                ),
            }
        });
    }

    /// Imports a block this node built and waits for the verdict.
    /// Drops a build prepared ahead, if any. A leader whose proposal timed out
    /// prepared its next build on the block that was not voted for; the next
    /// proposal extends the last QC's block instead, and a build on the wrong
    /// parent is discarded on the mismatch anyway -- this only stops the
    /// execution layer finishing a build nobody will collect -- or, for a
    /// build a forkchoice started, has its payload job resolved at once
    /// rather than left to its deadline (see `AheadBuild::give_up`).
    pub fn discard_prepared(&mut self) {
        if let Some(prepared) = self.prepared.take() {
            prepared.discard();
        }
    }

    /// This node's own block has reached the execution layer.
    ///
    /// The own import runs on a task of its own
    /// ([`Self::spawn_import_own_block`]) and never came back through the
    /// driver, so the state a follower import moves did not move for it: the
    /// block was not recorded as imported, and a commit for it that was
    /// answered SYNCING -- because the forkchoice reached the engine while
    /// the import was still landing -- was kept in `pending_commits` and
    /// never run again. Nothing else ever runs it, and the driver's head
    /// then stays at the block *before* this node's own last one for the
    /// rest of the node's life. The node keeps receiving bodies and Decides
    /// and never imports another block, because every block after it looks
    /// like it runs ahead of the execution layer (defect 12, loop190 Y1a
    /// node5: head stuck at 381, block 383 and everything after it held).
    ///
    /// Returns the action the replayed commit produced, if there was one.
    pub async fn own_block_imported(&mut self, block_hash: B256) -> Option<DriverAction> {
        self.note_imported(block_hash);
        // Only a commit that is still waiting. In the ordinary order the
        // import lands first and the commit runs on its own a moment later,
        // so there is nothing here and no second forkchoice is sent.
        self.commits_ahead.remove(&block_hash);
        if !self.pending_commits.remove(&block_hash) {
            return None;
        }
        info!(
            target: "n42.h2.el",
            block = ?block_hash,
            "our own block landed; the commit that was answered SYNCING runs again"
        );
        Some(self.commit(block_hash).await)
    }

    /// Whether this node's own block `block_hash` is still on its way into the
    /// execution layer ([`Self::spawn_import_own_block`]). A leader whose next
    /// proposal builds on it is answered SYNCING until it lands, and asks again
    /// then instead of losing the view (loop162 C13: view 276 timed out after
    /// "could not build a block to propose" while the parent's own import was
    /// still landing). Kept apart from [`Self::is_importing`] on purpose: a
    /// commit for a block counted there waits for a follower import's report,
    /// which an own import never sends.
    pub fn is_importing_own_block(&self, block_hash: &B256) -> bool {
        self.own_importing.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains(block_hash)
    }

    /// The channel [`Self::spawn_import_own_block`] reports on, once.
    pub fn take_own_imports(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<B256>> {
        self.own_imports_rx.take()
    }

    /// The channel a spawned follower import reports on, once.
    pub fn take_foreign_imports(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<ImportReport>> {
        self.foreign_imports_rx.take()
    }

    /// The channel a spawned commit forkchoice reports on, once. A loop that
    /// does not take it must leave [`Self::set_commit_fcu_async`] off, or the
    /// commits' outcomes are never applied.
    pub fn take_commit_reports(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<CommitReport>> {
        self.commit_reports_rx.take()
    }

    /// Runs the commit's forkchoice on a task instead of awaiting it (see the
    /// `commit_async` field). The default is [`commit_fcu_async`]; this is how
    /// a test picks the path without the process environment.
    pub fn set_commit_fcu_async(&mut self, on: bool) {
        self.commit_async = on;
    }

    /// Whether a commit forkchoice is on the wire or waiting to go.
    pub fn is_committing(&self) -> bool {
        self.commit_in_flight.is_some() || self.commit_pending.is_some()
    }

    /// **Bench only**: run follower imports on a task (see the field).
    pub fn set_spawn_imports(&mut self, on: bool) {
        self.spawn_imports = on;
    }

    /// The chain's `deferredExecutionTime` (see the field); `None` keeps
    /// every block on the import-gated path.
    pub fn set_deferred_execution_time(&mut self, at: Option<u64>) {
        self.deferred_execution_time = at;
    }

    /// Whether `block_hash`'s import is in flight: a commit for it is not
    /// dropped as "not imported" but deferred to the import's success.
    pub fn is_importing(&self, block_hash: &B256) -> bool {
        self.executing.contains(block_hash) || self.import_queue.contains(block_hash)
    }

    /// A commit heard before this block's import started (the Decide came
    /// ahead of the execute request): nothing is sent now, since the engine
    /// does not have the block, and the import that brings it in runs the
    /// commit's forkchoice. Dropped instead, the block was imported but never
    /// canonical, the next block's direct import waited out its parent, and a
    /// node that fell behind stayed behind: by then most Decides came before
    /// the import started (loop160 C10 node5: 187 of 318; V10 node1: 96).
    pub fn commit_when_imported(&mut self, block_hash: B256) {
        self.remember_commit_ahead(block_hash);
    }

    /// Remembers a commit to repeat when `block_hash`'s import lands. Bounded:
    /// a block imported by a path the driver does not see (a synced range)
    /// stays in the set until it is bounded away, harmlessly.
    fn remember_commit_ahead(&mut self, block_hash: B256) {
        self.commits_ahead.insert(block_hash);
        if self.commits_ahead.len() > 64 {
            let stale: Vec<B256> = self.commits_ahead.iter().copied().take(self.commits_ahead.len() - 64).collect();
            for hash in stale {
                self.commits_ahead.remove(&hash);
            }
        }
    }

    /// The blocks whose imports are in flight.
    pub fn importing(&self) -> impl Iterator<Item = &B256> {
        self.executing.iter()
    }

    /// Whether a block stamped `timestamp` is under deferred execution.
    fn deferred_at(&self, timestamp: u64) -> bool {
        self.deferred_execution_time.is_some_and(|at| timestamp >= at)
    }

    /// Deferred execution: sends the block to the execution layer on a task
    /// at once -- no queue; the execution layer checks it against the
    /// parent's result as soon as the parent is in, and executes it after --
    /// and reports the check and then the import on the channel.
    fn spawn_execute_deferred(&mut self, block_hash: B256) -> DriverAction {
        if self.executing.contains(&block_hash) {
            return DriverAction::Ignored;
        }
        if self.executing.len() >= DEFERRED_IN_FLIGHT {
            if !self.import_queue.contains(&block_hash) {
                self.import_queue.push_back(block_hash);
            }
            return DriverAction::Ignored;
        }
        // The body when this node kept one (`N42_BODY_ONCE=1`), the payload
        // otherwise; a body's payload is only made if the execution layer
        // refuses the body.
        let body = self.bodies.get(&block_hash).cloned();
        let payload = self.payloads.get(&block_hash).cloned();
        if body.is_none() && payload.is_none() {
            return DriverAction::PayloadMissing { block_hash };
        }
        self.executing.insert(block_hash);
        let el = std::sync::Arc::clone(&self.el);
        let report = self.foreign_imports.clone();
        let guard = ReportGuard { block_hash, report: Some(report.clone()) };
        let size = BlockSize {
            txs: payload.as_ref().map_or(0, |p| p.payload.as_v1().transactions.len()),
            bytes: body.as_ref().map_or(0, |b| b.rlp.len()),
        };
        let decoder = self.body_decoder.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            // The body first. `None` is the execution layer saying "not this
            // way" before it answered anything, so nothing has been checked
            // and the payload below is the same block sent again; a failure
            // after the check comes back as `Some(Err(..))` and is not
            // retried.
            let mut answered = None;
            if let Some(body) = &body {
                let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
                let call = el.new_payload_body_checked(ExecutionPath::LIVE_SEQUENTIAL, body, checked_tx);
                tokio::pin!(call);
                answered = tokio::select! {
                    checked = checked_rx => {
                        release_check(&report, block_hash, size, started, checked.ok());
                        call.await
                    }
                    answer = &mut call => answer,
                };
                if answered.is_none() {
                    debug!(
                        target: "n42.h2.el",
                        block = ?block_hash,
                        "the execution layer would not take the body; sending the payload"
                    );
                }
            }
            let outcome = match answered {
                Some(outcome) => outcome,
                None => {
                    // The payload: the one this node already held, or the
                    // body decoded here -- on this task, not on the loop.
                    let payload = match payload {
                        Some(payload) => Ok(payload),
                        None => match (&body, &decoder) {
                            (Some(body), Some(decode)) => decode.decode(body).map_err(ElError::new),
                            (Some(_), None) => Err(ElError::new(
                                "the body cannot be sent as a payload: no decoder installed",
                            )),
                            (None, _) => Err(ElError::new("no payload and no body for this block")),
                        },
                    };
                    match payload {
                        Ok(payload) => {
                            let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
                            let import = el.new_payload_checked(ExecutionPath::LIVE_SEQUENTIAL, payload, checked_tx);
                            tokio::pin!(import);
                            // The check, when the execution layer offers one, arrives while
                            // the import is still running; a dropped sender means it does
                            // not, and the vote waits for the import as before.
                            tokio::select! {
                                checked = checked_rx => {
                                    release_check(&report, block_hash, size, started, checked.ok());
                                    import.await
                                }
                                outcome = &mut import => outcome,
                            }
                        }
                        Err(err) => {
                            warn!(target: "n42.h2.el", block = ?block_hash, %err, "a held body could not be sent");
                            Err(err)
                        }
                    }
                }
            };
            if size.worth_logging() {
                info!(target: "n42.h2.el", block = ?block_hash, txs = size.txs, bytes = size.bytes, import_ms = started.elapsed().as_millis() as u64, "imported a block");
            }
            guard.done(ImportVerdict::of(outcome));
        });
        DriverAction::Ignored
    }

    /// Starts `block_hash`'s import on a task, or queues it behind the one in
    /// flight. The verdict arrives on the channel and goes through
    /// [`Self::finish_execute`].
    fn spawn_execute(&mut self, block_hash: B256) -> DriverAction {
        if self.executing.contains(&block_hash) {
            // Asked again for the block in flight: its verdict is coming.
            return DriverAction::Ignored;
        }
        if !self.executing.is_empty() {
            if !self.import_queue.contains(&block_hash) {
                self.import_queue.push_back(block_hash);
            }
            return DriverAction::Ignored;
        }
        let payload = match self.payload_for(block_hash) {
            Ok(payload) => payload,
            Err(missing) => return missing,
        };
        self.executing.insert(block_hash);
        let el = std::sync::Arc::clone(&self.el);
        let guard = ReportGuard { block_hash, report: Some(self.foreign_imports.clone()) };
        let txs = payload.payload.as_v1().transactions.len();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let outcome = el.new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, payload).await;
            if txs >= 10_000 {
                info!(target: "n42.h2.el", block = ?block_hash, txs, import_ms = started.elapsed().as_millis() as u64, "imported a block");
            }
            guard.done(ImportVerdict::of(outcome));
        });
        DriverAction::Ignored
    }

    /// A spawned import's report. A check releases the vote and nothing
    /// else. A verdict: the head moves, a commit that waited runs its
    /// forkchoice, the next queued import starts, and the loop gets the same
    /// action an awaited import would have returned -- plus, when the next
    /// queued block's payload is gone from the cache, the `PayloadMissing`
    /// that makes the loop fetch it (dropping that would leave the block
    /// unimported for good).
    pub async fn finish_execute(&mut self, report: ImportReport) -> Vec<DriverAction> {
        let (block_hash, verdict) = match report {
            ImportReport::Checked(block_hash) => {
                return vec![DriverAction::Consensus(Box::new(ConsensusEvent::BlockChecked(block_hash)))];
            }
            ImportReport::Done(block_hash, verdict) => (block_hash, verdict),
        };
        self.executing.remove(&block_hash);
        let mut actions = Vec::with_capacity(2);
        actions.push(match verdict {
            ImportVerdict::Imported => {
                self.head = block_hash;
                self.note_imported(block_hash);
                if self.pending_commits.remove(&block_hash) || self.commits_ahead.remove(&block_hash) {
                    // The commit that waited for this import -- or one that
                    // ran before the body arrived, against an engine that
                    // did not have the block (loop152: the forkchoice was
                    // answered, the block was imported a moment later and
                    // never made canonical, the next block's direct import
                    // could not see its parent, the node fell behind). The
                    // forkchoice is idempotent; it runs again now.
                    let _ = self.commit(block_hash).await;
                }
                DriverAction::Consensus(Box::new(ConsensusEvent::BlockImported(block_hash)))
            }
            // Not executed: asked for again, as the awaited path does. A
            // commit that waited keeps waiting for the import that follows.
            ImportVerdict::NotYet => DriverAction::PayloadMissing { block_hash },
            ImportVerdict::Invalid(reason) => {
                // A commit for it can never run; a payload for it is dropped
                // so a fresh copy is executed again, not this outcome.
                if self.pending_commits.remove(&block_hash) {
                    warn!(target: "n42.h2.el", block = ?block_hash, %reason, "a commit waited for an import that failed; dropped");
                }
                self.forget_payload(block_hash);
                DriverAction::Rejected { block_hash, reason }
            }
        });
        // The next block queued behind the imports in flight, on whichever
        // path its timestamp puts it.
        if let Some(next) = self.import_queue.pop_front() {
            match self.execute(next).await {
                DriverAction::Ignored => {}
                other => actions.push(other),
            }
        }
        actions
    }

    /// Drops a cached payload (a rejected block's), so a block seen again
    /// is fetched and executed afresh.
    pub fn forget_payload(&mut self, block_hash: B256) {
        let had_body = self.bodies.remove(&block_hash).is_some();
        if self.payloads.remove(&block_hash).is_some() || had_body {
            self.payload_order.retain(|h| h != &block_hash);
        }
    }

    pub async fn import_own_block(&mut self, built: &BuiltBlock) -> Result<(), ElError> {
        let started = std::time::Instant::now();
        let status = self
            .el
            .new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, built.execution_data.clone())
            .await?;
        info!(
            target: "n42.h2.el",
            block = ?built.hash,
            import_ms = started.elapsed().as_millis() as u64,
            "imported our own block"
        );
        match status.status {
            PayloadStatusEnum::Valid => {
                self.head = built.hash;
                Ok(())
            }
            // A block this node's own execution layer will not accept has
            // already been proposed by the time we know. The view is lost
            // either way; what matters is that it is loud.
            PayloadStatusEnum::Invalid { validation_error } => Err(ElError::new(format!(
                "our own execution layer rejected the block we built: {validation_error}"
            ))),
            other => Err(ElError::new(format!(
                "our own execution layer did not accept the block we built: {other:?}"
            ))),
        }
    }

    /// Imports a block pulled from a peer to catch up and makes it the head.
    ///
    /// Head and safe, not finalized: the peer says this is the fleet's
    /// chain, and execution says the block is valid, but neither is a
    /// commit certificate. Finality follows the next Decide this node sees,
    /// which finalizes the block it names and, with it, everything pulled
    /// beneath; until then a peer that served a sibling chain costs a reorg
    /// rather than a node stuck behind a wrong finalized block. Returns the
    /// hash on success; any verdict but VALID is an error, because a
    /// catch-up that skips a block leaves every later one without a parent.
    pub async fn import_pulled(&mut self, payload: ExecutionData) -> Result<B256, ElError> {
        let block_hash = payload.block_hash();
        let status = self
            .el
            .new_payload_for(ExecutionPath::HISTORICAL_SEQUENTIAL, payload)
            .await?;
        match status.status {
            PayloadStatusEnum::Valid => {}
            PayloadStatusEnum::Invalid { validation_error } => {
                return Err(ElError::new(format!("execution layer rejected block {block_hash}: {validation_error}")));
            }
            other => {
                return Err(ElError::new(format!("execution layer did not accept block {block_hash}: {other:?}")));
            }
        }
        let state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: self.finalized,
        };
        let updated = self
            .el
            .fork_choice_updated_for(ExecutionPath::HISTORICAL_SEQUENTIAL, state)
            .await?;
        if let PayloadStatusEnum::Invalid { validation_error } = updated.payload_status.status {
            return Err(ElError::new(format!("forkchoice to {block_hash} refused: {validation_error}")));
        }
        self.head = block_hash;
        Ok(block_hash)
    }

    /// Handles one consensus output.
    pub async fn handle_output(&mut self, output: &EngineOutput) -> DriverAction {
        match output {
            EngineOutput::ExecuteBlock(block_hash) => self.execute(*block_hash).await,
            EngineOutput::BlockCommitted { block_hash, .. } => self.commit(*block_hash).await,
            _ => DriverAction::Ignored,
        }
    }

    /// Follower path: executes a proposed block and, on acceptance, produces the
    /// event that releases the import-gated vote.
    async fn execute(&mut self, block_hash: B256) -> DriverAction {
        let timestamp = self
            .payloads
            .get(&block_hash)
            .map(|p| p.payload.timestamp())
            .or_else(|| self.bodies.get(&block_hash).map(|body| body.timestamp));
        if let Some(timestamp) = timestamp
            && self.deferred_at(timestamp)
        {
            return self.spawn_execute_deferred(block_hash);
        }
        if self.spawn_imports {
            return self.spawn_execute(block_hash);
        }
        let payload = match self.payload_for(block_hash) {
            Ok(payload) => payload,
            Err(missing) => return missing,
        };
        let txs = payload.payload.as_v1().transactions.len();
        let started = std::time::Instant::now();
        self.executing.insert(block_hash);
        let outcome = self
            .el
            .new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, payload)
            .await;
        self.executing.remove(&block_hash);
        if txs >= 10_000 {
            info!(
                target: "n42.h2.el",
                block = ?block_hash,
                txs,
                import_ms = started.elapsed().as_millis() as u64,
                "imported a block"
            );
        }
        match outcome {
            Ok(status) => match status.status {
                PayloadStatusEnum::Valid => {
                    self.head = block_hash;
                    self.note_imported(block_hash);
                    if self.pending_commits.remove(&block_hash) || self.commits_ahead.remove(&block_hash) {
                        // The commit that waited for this import, or one that
                        // ran before the block arrived (see `finish_execute`);
                        // its own action is a log line the node does nothing
                        // with.
                        let _ = self.commit(block_hash).await;
                    }
                    DriverAction::Consensus(Box::new(ConsensusEvent::BlockImported(block_hash)))
                }
                // SYNCING/ACCEPTED are not a verdict: the EL has not executed the
                // block yet, so voting now would be voting blind. Treat it the
                // same as a missing payload — the caller retries.
                PayloadStatusEnum::Syncing | PayloadStatusEnum::Accepted => {
                    DriverAction::PayloadMissing { block_hash }
                }
                PayloadStatusEnum::Invalid { validation_error } => DriverAction::Rejected {
                    block_hash,
                    reason: validation_error.to_string(),
                },
            },
            Err(error) => DriverAction::Rejected {
                block_hash,
                reason: error.to_string(),
            },
        }
    }

    /// Commit path: makes a committed block the head and the finalised block.
    /// Records an import that landed, bounded to the last 256.
    fn note_imported(&mut self, block_hash: B256) {
        if self.imported.contains(&block_hash) {
            return;
        }
        self.imported.push_back(block_hash);
        while self.imported.len() > 256 {
            self.imported.pop_front();
        }
    }

    async fn commit(&mut self, block_hash: B256) -> DriverAction {
        if self.is_importing(&block_hash) {
            // Still importing, or queued behind the imports in flight: the
            // forkchoice follows the import's success.
            self.pending_commits.insert(block_hash);
            return DriverAction::Ignored;
        }
        self.finalized = block_hash;
        if !self.imported.contains(&block_hash) {
            // The block has not reached this node: whatever the engine says
            // to this forkchoice, it runs again when the import lands.
            self.remember_commit_ahead(block_hash);
        }
        if self.commit_async {
            // Off the loop from here: the forkchoice goes on a task and its
            // outcome is applied in `finish_commit`. Everything above happens
            // at send time either way, because none of it depends on the
            // answer.
            self.queue_commit(block_hash, Vec::new());
            return DriverAction::Ignored;
        }
        let state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: block_hash,
        };
        let started = std::time::Instant::now();
        let ahead = self.commits_ahead.contains(&block_hash);
        let answer = self
            .el
            .fork_choice_updated_for(ExecutionPath::LIVE_SEQUENTIAL, state)
            .await;
        say_slow_commit(block_hash, started.elapsed(), ahead, &answer);
        self.apply_commit(block_hash, Vec::new(), answer)
            .into_iter()
            .next()
            .unwrap_or(DriverAction::Ignored)
    }

    /// The commit order of `block_hash`: the position, in the order this
    /// driver first heard commits, that decides which of two commits waiting
    /// to be sent is the descendant. Stable per block, so the replay of a
    /// commit whose block was still importing keeps the order it was heard
    /// in rather than jumping ahead of a later one.
    fn commit_order_of(&mut self, block_hash: B256) -> u64 {
        if let Some(order) = self.commit_orders.get(&block_hash) {
            return *order;
        }
        self.commit_seq = self.commit_seq.saturating_add(1);
        let order = self.commit_seq;
        self.commit_orders.insert(block_hash, order);
        self.commit_order_seen.push_back(block_hash);
        while self.commit_order_seen.len() > 256 {
            if let Some(oldest) = self.commit_order_seen.pop_front() {
                self.commit_orders.remove(&oldest);
            }
        }
        order
    }

    /// Puts a commit in the pending slot and sends it if nothing is in
    /// flight. `skipped` are commits already folded into this one.
    ///
    /// Only one commit is ever pending: the one with the highest commit
    /// order, which is the descendant of every other (see
    /// [`PendingCommit::skipped`]). The rest are folded into it, so their
    /// bookkeeping still runs -- and so no forkchoice is ever sent to a block
    /// a later commit has already moved past, which reth reads as a reorg.
    fn queue_commit(&mut self, block_hash: B256, skipped: Vec<B256>) {
        let order = self.commit_order_of(block_hash);
        if order <= self.commit_landed && self.commit_pending.is_none() {
            // A commit re-asked for a block a later commit has already made
            // canonical: the pending-commit or commit-ahead replay, running
            // after the descendant's forkchoice landed. That forkchoice
            // finalised this block with it, and sending one to an ancestor
            // now would move the engine's head backwards -- which reth
            // unwinds as a reorg (the same hazard `prepare_build_on` guards
            // against for builds).
            debug!(target: "n42.h2.el", block = ?block_hash, order, landed = self.commit_landed, "a commit for a block a later one already finalised; nothing to send");
            return;
        }
        let heard_at = std::time::Instant::now();
        self.commit_pending = Some(match self.commit_pending.take() {
            None => PendingCommit { block_hash, order, heard_at, skipped },
            Some(mut pending) if pending.order >= order => {
                // The pending commit is for the descendant: this one rides
                // on its forkchoice.
                for hash in skipped.into_iter().chain(
                    (pending.block_hash != block_hash).then_some(block_hash),
                ) {
                    if !pending.skipped.contains(&hash) {
                        pending.skipped.push(hash);
                    }
                }
                pending
            }
            Some(pending) => {
                let mut folded = pending.skipped;
                folded.push(pending.block_hash);
                for hash in skipped {
                    if !folded.contains(&hash) {
                        folded.push(hash);
                    }
                }
                PendingCommit { block_hash, order, heard_at, skipped: folded }
            }
        });
        self.send_next_commit();
    }

    /// Sends the pending commit's forkchoice from a task, unless one is
    /// already in flight -- in which case its report sends this one.
    fn send_next_commit(&mut self) {
        if self.commit_in_flight.is_some() {
            return;
        }
        let Some(pending) = self.commit_pending.take() else {
            return;
        };
        self.commit_in_flight = Some(pending.block_hash);
        let block_hash = pending.block_hash;
        let state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: block_hash,
        };
        let el = std::sync::Arc::clone(&self.el);
        let guard = CommitGuard {
            report: Some(self.commit_reports.clone()),
            block_hash,
            order: pending.order,
            skipped: pending.skipped,
            ahead_of_import: self.commits_ahead.contains(&block_hash),
            queued: pending.heard_at.elapsed(),
            started: std::time::Instant::now(),
        };
        tokio::spawn(async move {
            let answer = el
                .fork_choice_updated_for(ExecutionPath::LIVE_SEQUENTIAL, state)
                .await;
            guard.answer(answer);
        });
    }

    /// A spawned commit forkchoice's report: the same state effects the
    /// awaited path applies when it returns, plus the ancestors this one
    /// finalised on its way.
    pub async fn finish_commit(&mut self, report: CommitReport) -> Vec<DriverAction> {
        let CommitReport { block_hash, order, skipped, ahead_of_import, answer, queued, in_flight } = report;
        // Exactly one report per forkchoice sent, guard included, so this is
        // always the one that was in flight.
        self.commit_in_flight = None;
        say_slow_commit(block_hash, queued + in_flight, ahead_of_import, &answer);
        // What the forkchoice now costs, where it now lies: off the loop, so
        // it no longer shows up as the loop's own time (loop189 X0a segment
        // D). Every sixteenth, because a full bench leg commits thousands of
        // blocks and one line each is not a better signal than one in
        // sixteen.
        self.commits_answered = self.commits_answered.wrapping_add(1);
        if self.commits_answered.is_multiple_of(16) {
            info!(
                target: "n42.h2.el",
                block = ?block_hash,
                elapsed_ms = (queued + in_flight).as_millis() as u64,
                in_flight_ms = in_flight.as_millis() as u64,
                queued_ms = queued.as_millis() as u64,
                "commit forkchoice answered"
            );
        }
        let landed = matches!(&answer, Ok(updated) if !matches!(updated.payload_status.status, PayloadStatusEnum::Invalid { .. } | PayloadStatusEnum::Syncing));
        let actions = if landed {
            self.commit_landed = self.commit_landed.max(order);
            self.apply_commit(block_hash, skipped, answer)
        } else {
            let actions = self.apply_commit(block_hash, Vec::new(), answer);
            // The forkchoice did not land, so the ancestors it would have
            // finalised did not either: the newest of them goes on its own,
            // carrying the rest.
            if let Some((newest, rest)) = skipped.split_last() {
                self.queue_commit(*newest, rest.to_vec());
            }
            actions
        };
        self.send_next_commit();
        actions
    }

    /// The outcome of one commit forkchoice, on either path. `skipped` are
    /// the ancestors a Valid answer finalises along with `block_hash`.
    fn apply_commit(
        &mut self,
        block_hash: B256,
        skipped: Vec<B256>,
        answer: Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError>,
    ) -> Vec<DriverAction> {
        match answer {
            Ok(updated) => match updated.payload_status.status {
                PayloadStatusEnum::Invalid { validation_error } => {
                    // A forkchoice the engine refused is not an execution
                    // verdict on the block (`Rejected` withdraws a block's
                    // import evidence): logged, and the next commit moves on.
                    warn!(target: "n42.h2.el", block = ?block_hash, %validation_error, "forkchoice to a committed block refused");
                    Vec::new()
                }
                PayloadStatusEnum::Syncing => {
                    // The engine does not have the block: the Decide came
                    // before the body (a follower hears consensus before the
                    // body channel delivers). Taking this as done left the
                    // block imported but never canonical, so the next block's
                    // direct import could not find its parent, fell to the
                    // ordinary path, and the node dropped 3 s behind for the
                    // rest of the leg (loop149 A1, node4). The commit waits
                    // for the import that follows.
                    info!(target: "n42.h2.el", block = ?block_hash, "forkchoice to a committed block the engine does not have yet; the commit waits for its import");
                    self.pending_commits.insert(block_hash);
                    Vec::new()
                }
                _ => {
                    let mut actions = Vec::with_capacity(skipped.len() + 1);
                    // The ancestors this forkchoice finalised on its way: no
                    // head of their own (the descendant is the head), but the
                    // same payload removal and the same `Finalized` the
                    // awaited path produced for each.
                    for ancestor in skipped {
                        self.forget_committed(ancestor);
                        actions.push(DriverAction::Finalized { block_hash: ancestor });
                    }
                    self.head = block_hash;
                    self.forget_committed(block_hash);
                    actions.push(DriverAction::Finalized { block_hash });
                    actions
                }
            },
            Err(error) => {
                warn!(target: "n42.h2.el", block = ?block_hash, %error, "forkchoice to a committed block failed");
                Vec::new()
            }
        }
    }

    /// Drops what a committed block no longer needs: it will never be
    /// re-executed.
    fn forget_committed(&mut self, block_hash: B256) {
        self.payloads.remove(&block_hash);
        self.bodies.remove(&block_hash);
        self.payload_order.retain(|h| h != &block_hash);
    }
}

/// A commit's forkchoice that is slow or not Valid is what leaves an
/// imported block short of canonical, and the next block's direct import then
/// waits out its parent (loop158 W: no forkchoice for block 188 reached the
/// engine for 6.5 s). Said when it happens, on both paths.
fn say_slow_commit(
    block_hash: B256,
    elapsed: std::time::Duration,
    ahead_of_import: bool,
    answer: &Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError>,
) {
    let elapsed_ms = elapsed.as_millis() as u64;
    let valid = matches!(answer, Ok(updated) if matches!(updated.payload_status.status, PayloadStatusEnum::Valid));
    if elapsed_ms >= 500 || !valid {
        let outcome = match answer {
            Ok(updated) => format!("{:?}", updated.payload_status.status),
            Err(error) => format!("error: {error}"),
        };
        info!(target: "n42.h2.el", block = ?block_hash, elapsed_ms, ahead_of_import, %outcome, "commit forkchoice");
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The execution-layer seam.
//!
//! A trait boundary over the Engine API that consensus drives, so the HotStuff-2
//! state machine never holds reth handles directly. Everything here is alloy or
//! std — no reth types cross this line — which is what lets the consensus side
//! stay independent of the reth version underneath.
//!
//! Ported from N42-26's `n42-consensus-service/src/el.rs`. The concrete adapter
//! that implements this against reth lives node-side; this crate holds the trait,
//! the node-neutral types, and the driver that connects them to consensus.

use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    ExecutionData, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId, PayloadStatus,
    PayloadStatusEnum,
};

use crate::ExecutionPath;

fn payload_outcome(status: &PayloadStatusEnum) -> &'static str {
    match status {
        PayloadStatusEnum::Valid => "valid",
        PayloadStatusEnum::Invalid { .. } => "invalid",
        PayloadStatusEnum::Syncing => "syncing",
        PayloadStatusEnum::Accepted => "accepted",
    }
}

fn record_call(
    path: ExecutionPath,
    phase: &'static str,
    started: std::time::Instant,
    outcome: &'static str,
) {
    metrics::histogram!(
        "n42_evm_path_duration_ms",
        "path" => path.label(),
        "phase" => phase,
    )
    .record(started.elapsed().as_secs_f64() * 1_000.0);
    metrics::counter!(
        "n42_evm_path_calls_total",
        "path" => path.label(),
        "phase" => phase,
        "outcome" => outcome,
    )
    .increment(1);
}

/// Error at the EL boundary.
///
/// Erases reth's concrete engine error enums — every call site here only logs
/// the message and branches on `Ok`/`Err`, so carrying the reth types across the
/// seam would buy nothing and would pin this crate to a reth version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ElError(pub String);

impl ElError {
    /// Builds an error from anything printable.
    pub fn new(message: impl std::fmt::Display) -> Self {
        Self(message.to_string())
    }
}

/// Node-neutral result of a completed payload build.
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    /// Block hash of the built block.
    pub hash: B256,
    /// Block number.
    pub number: u64,
    /// Block timestamp (seconds).
    pub timestamp: u64,
    /// Number of transactions in the block.
    pub tx_count: usize,
    /// Engine-API execution payload, for re-import via `new_payload` and for
    /// serialisation to followers.
    pub execution_data: ExecutionData,
    /// Transaction hashes of the EIP-4844 transactions in this block, used to
    /// gather and broadcast their sidecars.
    pub blob_tx_hashes: Vec<B256>,
    /// The header, when the normalizer built one.
    ///
    /// Carried rather than recovered: sealing constructs the header to hash it,
    /// and the caller needs the same header a moment later. Decoding the
    /// payload again to get it back is a clone and a full RLP walk of the whole
    /// block -- 648 ms at the 163,000-transaction tier, on a path where sealing
    /// itself is 150 ms.
    pub header: Option<alloy_consensus::Header>,
    /// Every transaction's hash, in block order, when the execution layer
    /// sent them (`N42_COMPACT_BODY`). Empty otherwise.
    ///
    /// Carried for the same reason the header is: the builder already has
    /// them -- they are cached on the transactions it built the block from
    /// -- and the compact body is exactly this list. Re-deriving them here
    /// would be a keccak over the block's 26 MB on the proposal path, which
    /// is most of what the compact body saves.
    pub tx_hashes: Vec<B256>,
    /// The block's frame layout when the execution layer built it from whole
    /// frames (`N42_FRAME_BLOCKS=1`): (frame id, how many of the frame's
    /// transactions the block holds) in block order. What the frame
    /// description names. Empty otherwise.
    pub frame_layout: Vec<(B256, u32)>,
}

/// What a caller passes with a build request when it will want the block
/// after this one too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainAhead {
    /// The view the block being built now will be proposed under. The
    /// execution layer hands it straight back with the sealed-early header,
    /// because it is the consensus side that needs it: the header's extra
    /// data is stamped with it, and the chained build's parent hash is that
    /// stamped header's hash.
    pub view: u64,
}

/// Turns a block's built header, the attributes it was built with and the
/// view it will be proposed under into the header this node will propose and
/// the attributes of the block after it.
///
/// The attributes are passed because sealing needs the block's withdrawals --
/// its rewards on this chain -- and they are not recoverable from the header,
/// which carries only their root.
///
/// Both halves must be the very functions the proposal uses, or a chained
/// build is a block the leader cannot propose: the parent hash would differ
/// from the one it seals, and every chained build would be discarded. The
/// node wires its own sealing and its own attributes builder in here for
/// exactly that reason. `None` declines -- no chain this time.
pub type ChainSealer = std::sync::Arc<
    dyn Fn(
            &alloy_consensus::Header,
            &PayloadAttributes,
            u64,
        ) -> Option<(alloy_consensus::Header, PayloadAttributes)>
        + Send
        + Sync,
>;

/// A block as the execution layer holds it: header, transactions and, on a
/// post-Shanghai chain, its withdrawals — which on a gov5 chain are its
/// rewards.
#[derive(Debug, Clone)]
pub struct ChainBlock {
    /// The header.
    pub header: alloy_consensus::Header,
    /// The transactions' EIP-2718 bytes, in order. Bytes rather than a typed
    /// envelope: a block may carry transaction types this crate does not
    /// model (N42's 0x50), and every consumer wants the bytes anyway.
    pub transactions: Vec<alloy_primitives::Bytes>,
    /// The withdrawals; `None` before Shanghai.
    pub withdrawals: Option<Vec<alloy_eips::eip4895::Withdrawal>>,
}

/// Another node's block as the bytes the gossip delivered it in.
///
/// The body is gov5's wire form, `[header, transactions, verifiers,
/// rewards]` (plus the EIP-7928 access list when the producer sent one) --
/// the same bytes a peer asking `block_by_hash` is served. Everything an
/// Engine API payload carries is derived from it, so nothing travels beside
/// it but the identity the consensus layer voted on: the block hash the
/// proposal named, and the header profile this chain reads headers under.
/// `number` and `timestamp` are the header's, kept here so the driver can
/// key and classify the block without decoding the body again.
#[derive(Debug, Clone)]
pub struct ForeignBody {
    /// The hash the proposal named; the decoded header must hash to it.
    pub block_hash: B256,
    /// The block number.
    pub number: u64,
    /// The block timestamp, which decides the deferred-execution path.
    pub timestamp: u64,
    /// The header profile the body was read under.
    pub profile: n42_h2_consensus::header_profile::N42HeaderProfile,
    /// The body, exactly as received.
    pub rlp: alloy_primitives::Bytes,
    /// Whether `rlp` is a *compact* body -- the block with its transactions
    /// named by hash instead of carried
    /// (`n42_h2_consensus::compact_body`). It goes to the execution layer
    /// on a request of its own and cannot be turned into a payload here, so
    /// a refusal means asking peers for the whole body rather than falling
    /// back to `NEW_PAYLOAD`.
    pub compact: bool,
}

/// What the execution layer did with a body handed to it.
///
/// A compact body has a third answer the full one does not: it named
/// transactions this node does not hold, and it will take the same body
/// again once they are supplied. That is BIP-152's `getblocktxn` and it is
/// what a miss costs instead of the whole 26 MB body -- on this fleet a
/// median of 448 transactions of 163,000 (loop195).
#[derive(Debug)]
pub enum BodyOutcome {
    /// The execution layer took the body; this is the import's answer.
    Answered(Result<PayloadStatus, ElError>),
    /// "Not this way", before anything was checked: no channel, an
    /// execution layer that does not serve the request, or one that refused
    /// this body. The caller sends the block by another road.
    NotThisWay,
    /// A compact body it could not assemble: these positions of the block,
    /// in block order, are transactions it does not hold.
    NeedTxns(Vec<u32>),
}

/// How to resolve a started build — the node-neutral stand-in for reth's
/// `PayloadKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveKind {
    /// Block until the pending build finishes packing.
    WaitForPending,
}

/// The execution layer, as consensus sees it.
#[async_trait::async_trait]
pub trait ExecutionLayer: Send + Sync + 'static {
    /// The execution layer's canonical head number, for telling how far
    /// behind a peer this node is. `None` when not offered.
    async fn latest_block_number(&self) -> Result<Option<u64>, ElError> {
        Ok(None)
    }

    /// A block by hash, canonical or not, as its header and transactions —
    /// for serving a peer's fetch-on-miss when the body is no longer in the
    /// consensus layer's own store. `None` when not held or not offered.
    async fn block_by_hash(&self, hash: B256) -> Result<Option<ChainBlock>, ElError> {
        let _ = hash;
        Ok(None)
    }

    /// A canonical block by number, as its header and transactions, for
    /// serving peers that sync by range. `None` when the execution layer
    /// does not have it — or, in the default, does not offer the lookup.
    async fn block_by_number(&self, number: u64) -> Result<Option<ChainBlock>, ElError> {
        let _ = number;
        Ok(None)
    }

    /// Hands a transaction to the execution layer's pool
    /// (`eth_sendRawTransaction`), returning its hash. The default declines:
    /// an execution layer that does not offer the method.
    async fn send_raw_transaction(&self, raw: alloy_primitives::Bytes) -> Result<B256, ElError> {
        let _ = raw;
        Err(ElError::new("the execution layer does not accept transactions here"))
    }

    /// Hands a batch of transactions to the pool, returning how many it took.
    ///
    /// One call for many transactions, because the caller is a consensus loop.
    /// Forwarding a gossiped batch one round trip at a time blocks that loop for
    /// as long as the batch takes — measured on the seven-node fleet as a
    /// median block cycle of 0.5 s with a p90 of 6 s and a p99 body arrival of
    /// 14 s, because the libp2p swarm is not polled while the loop is inside
    /// those awaits. The default implementation is the sequential one, so an
    /// execution layer that has nothing better keeps working; the JSON-RPC
    /// client overrides it with a single batched request.
    async fn send_raw_transactions(&self, raws: Vec<alloy_primitives::Bytes>) -> usize {
        let mut accepted = 0;
        for raw in raws {
            if self.send_raw_transaction(raw).await.is_ok() {
                accepted += 1;
            }
        }
        accepted
    }
    /// Engine-API `newPayload` — insert and validate a block.
    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError>;

    /// Imports a block this node built. An execution layer that keeps its
    /// builds can take the sealed header alone (`header`) and skip the
    /// payload's round trip -- encode 17 ms, 19 MB of wire, decode 10 ms on
    /// the leader's cycle at the 163,000-transaction tier -- falling back to
    /// the payload when it no longer has the build. The default sends the
    /// payload.
    async fn import_own_block(
        &self,
        header: Option<&alloy_consensus::Header>,
        payload: ExecutionData,
    ) -> Result<PayloadStatus, ElError> {
        let _ = header;
        self.new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, payload).await
    }
    /// Builds the next block on a block this node built and sealed a moment
    /// ago, from that build's own post-state, without waiting for the engine
    /// to import it: `header` is the sealed header, `attrs` the next block's
    /// attributes. `None` means the execution layer does not offer it, or no
    /// longer has the build, and the caller starts the build the ordinary
    /// way (forkchoice with attributes, then resolve); the default offers
    /// nothing.
    async fn build_on_own_block(
        &self,
        header: &alloy_consensus::Header,
        attrs: PayloadAttributes,
    ) -> Option<Result<BuiltBlock, ElError>> {
        let _ = (header, attrs);
        None
    }

    /// [`Self::build_on_own_block`] told that the height *after* the one
    /// being built is this node's as well, so the execution layer may be
    /// asked to hand back the block's header the moment it seals it and the
    /// next build may be started on it without waiting for the proposal --
    /// the build chain (`N42_BUILD_CHAIN`).
    ///
    /// `chain` is `None` whenever consensus has not said the next height is
    /// ours: the chain is never started on a guess. The default ignores it
    /// entirely, which is what an execution layer without the chain does.
    async fn build_on_own_block_chaining(
        &self,
        header: &alloy_consensus::Header,
        attrs: PayloadAttributes,
        chain: Option<ChainAhead>,
    ) -> Option<Result<BuiltBlock, ElError>> {
        let _ = chain;
        self.build_on_own_block(header, attrs).await
    }

    /// Installs what turns a block's *built* header into the header this node
    /// will propose, and into the next block's attributes. Only the consensus
    /// side can do that -- the view and the seal key live there -- so the
    /// build chain asks for it rather than guessing at a hash. Without a
    /// sealer nothing chains.
    fn set_chain_sealer(&self, sealer: ChainSealer) {
        let _ = sealer;
    }

    /// Classified Engine-API `newPayload` call.
    ///
    /// Raw methods remain the adapter/test-double seam. Production callers use
    /// the classified wrappers so historical catch-up is never aggregated with
    /// live execution and unsupported PEVM cannot silently fall back.
    async fn new_payload_for(
        &self,
        path: ExecutionPath,
        payload: ExecutionData,
    ) -> Result<PayloadStatus, ElError> {
        let started = std::time::Instant::now();
        if !path.uses_current_engine_api() {
            record_call(path, "new_payload", started, "unsupported");
            return Err(ElError::new(format!(
                "execution path {} is not implemented by the canonical Engine API adapter",
                path.label()
            )));
        }

        let result = self.new_payload(payload).await;
        let outcome = result
            .as_ref()
            .map_or("error", |status| payload_outcome(&status.status));
        record_call(path, "new_payload", started, outcome);
        result
    }

    /// [`Self::new_payload_for`] with the block's *check* reported ahead of
    /// its execution, under deferred execution
    /// (docs/PHASE_D_DEFERRED_EXECUTION.md): `checked` receives VALID once
    /// the execution layer has found the header's execution fields equal to
    /// its own result for the parent and the transactions includable on the
    /// parent's post-state -- what a follower's vote attests -- and the
    /// returned status is the import, as before. An execution layer without
    /// the early answer drops `checked` unused, and the caller votes on the
    /// import instead; this default is that.
    async fn new_payload_checked(
        &self,
        path: ExecutionPath,
        payload: ExecutionData,
        checked: tokio::sync::oneshot::Sender<PayloadStatus>,
    ) -> Result<PayloadStatus, ElError> {
        drop(checked);
        self.new_payload_for(path, payload).await
    }

    /// Hands the execution layer a foreign block as the bytes it arrived in
    /// ([`ForeignBody`]), to be decoded once there instead of decoded here,
    /// re-encoded as a payload and parsed again on the other side.
    ///
    /// Otherwise [`Self::new_payload_checked`]: `checked` releases the vote
    /// when the execution layer has checked the block, and the returned
    /// status is the import. See [`BodyOutcome`] for the three answers. The
    /// default offers nothing.
    async fn new_payload_body_checked(
        &self,
        path: ExecutionPath,
        body: &ForeignBody,
        checked: tokio::sync::oneshot::Sender<PayloadStatus>,
    ) -> BodyOutcome {
        let _ = (path, body, checked);
        BodyOutcome::NotThisWay
    }

    /// Engine-API `forkchoiceUpdated` without attributes — the finalise and
    /// import path.
    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError>;

    /// Classified canonical-head update paired with [`Self::new_payload_for`].
    async fn fork_choice_updated_for(
        &self,
        path: ExecutionPath,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let started = std::time::Instant::now();
        if !path.uses_current_engine_api() || !path.may_write_canonical_state() {
            record_call(path, "forkchoice_updated", started, "unsupported");
            return Err(ElError::new(format!(
                "execution path {} may not update canonical fork choice",
                path.label()
            )));
        }

        let result = self.fork_choice_updated(state).await;
        let outcome = result.as_ref().map_or("error", |updated| {
            payload_outcome(&updated.payload_status.status)
        });
        record_call(path, "forkchoice_updated", started, outcome);
        result
    }

    /// `forkchoiceUpdated` with attributes — starts a payload build. Kept
    /// separate from the attribute-less call so the finalise path can later move
    /// off the consensus hot path.
    async fn fork_choice_updated_with_attrs(
        &self,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError>;

    /// Classified FCU with payload attributes, used only to start a live build.
    async fn fork_choice_updated_with_attrs_for(
        &self,
        path: ExecutionPath,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let started = std::time::Instant::now();
        if !path.may_start_payload_build() {
            record_call(
                path,
                "forkchoice_updated_with_attrs",
                started,
                "unsupported",
            );
            return Err(ElError::new(format!(
                "execution path {} may not start a canonical payload build",
                path.label()
            )));
        }

        let result = self.fork_choice_updated_with_attrs(state, attrs).await;
        let outcome = result.as_ref().map_or("error", |updated| {
            payload_outcome(&updated.payload_status.status)
        });
        record_call(path, "forkchoice_updated_with_attrs", started, outcome);
        result
    }

    /// Resolves a started build. `None` means no such job.
    async fn resolve_payload(
        &self,
        id: PayloadId,
        kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>>;

    /// Classified resolution of a live payload build.
    async fn resolve_payload_for(
        &self,
        path: ExecutionPath,
        id: PayloadId,
        kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>> {
        let started = std::time::Instant::now();
        if !path.may_start_payload_build() {
            record_call(path, "resolve_payload", started, "unsupported");
            return Some(Err(ElError::new(format!(
                "execution path {} may not resolve a canonical payload build",
                path.label()
            ))));
        }

        let result = self.resolve_payload(id, kind).await;
        let outcome = match &result {
            Some(Ok(_)) => "ok",
            Some(Err(_)) => "error",
            None => "missing",
        };
        record_call(path, "resolve_payload", started, outcome);
        result
    }
}

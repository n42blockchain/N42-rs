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

use crate::el::{BuiltBlock, ElError, ExecutionLayer, ResolveKind};

/// What the driver produced for one consensus output.
///
/// Not `Clone`/`PartialEq`: [`ConsensusEvent`] is neither, and wrapping it in
/// something that is would mean cloning payloads on a path that never needs to.
/// Tests use the accessors below.
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

/// Drives an [`ExecutionLayer`] on behalf of the consensus engine.
#[derive(Debug)]
pub struct ExecutionDriver<E> {
    el: E,
    /// Payloads seen but not yet executed, keyed by block hash. Populated from
    /// proposals, direct pushes, and our own builds.
    payloads: HashMap<B256, ExecutionData>,
    /// Current head, as consensus understands it.
    head: B256,
    /// Last block consensus committed.
    finalized: B256,
    /// Bounds `payloads` so a peer cannot make us buffer without limit.
    max_cached_payloads: usize,
    /// Insertion order, for evicting the oldest cached payload.
    payload_order: Vec<B256>,
}

impl<E: ExecutionLayer> ExecutionDriver<E> {
    /// Default payload cache size — a few views' worth of blocks.
    pub const DEFAULT_MAX_CACHED_PAYLOADS: usize = 64;

    /// Builds a driver whose head and finalised block are `genesis`.
    pub fn new(el: E, genesis: B256) -> Self {
        Self {
            el,
            payloads: HashMap::new(),
            head: genesis,
            finalized: genesis,
            max_cached_payloads: Self::DEFAULT_MAX_CACHED_PAYLOADS,
            payload_order: Vec::new(),
        }
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
            }
        }
    }

    /// Whether a payload is cached for `block_hash`.
    pub fn has_payload(&self, block_hash: &B256) -> bool {
        self.payloads.contains_key(block_hash)
    }

    /// The forkchoice this driver would send right now.
    fn forkchoice(&self, head: B256) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: head,
            safe_block_hash: self.finalized,
            finalized_block_hash: self.finalized,
        }
    }

    /// Leader path: builds a block on top of the current head.
    ///
    /// Returns the built block *and* caches its payload, so the subsequent
    /// `ExecuteBlock` for our own proposal is served locally rather than
    /// requiring a round trip.
    pub async fn build_block(&mut self, attrs: PayloadAttributes) -> Result<BuiltBlock, ElError> {
        let updated = self
            .el
            .fork_choice_updated_with_attrs(self.forkchoice(self.head), attrs)
            .await?;

        // A build only starts if the EL accepted the forkchoice. Reporting the
        // status is more useful than a bare "no payload id": VALID-without-id
        // and SYNCING mean very different things to an operator.
        let payload_id = updated.payload_id.ok_or_else(|| {
            ElError::new(format!(
                "forkchoiceUpdated returned no payload id (status {:?})",
                updated.payload_status.status
            ))
        })?;

        let built = self
            .el
            .resolve_payload(payload_id, ResolveKind::WaitForPending)
            .await
            .ok_or_else(|| ElError::new(format!("no payload build for id {payload_id}")))??;

        self.cache_payload(built.hash, built.execution_data.clone());
        Ok(built)
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
        let Some(payload) = self.payloads.get(&block_hash).cloned() else {
            return DriverAction::PayloadMissing { block_hash };
        };

        match self.el.new_payload(payload).await {
            Ok(status) => match status.status {
                PayloadStatusEnum::Valid => {
                    self.head = block_hash;
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
    async fn commit(&mut self, block_hash: B256) -> DriverAction {
        self.finalized = block_hash;
        let state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: block_hash,
        };
        match self.el.fork_choice_updated(state).await {
            Ok(updated) => match updated.payload_status.status {
                PayloadStatusEnum::Invalid { validation_error } => DriverAction::Rejected {
                    block_hash,
                    reason: validation_error.to_string(),
                },
                _ => {
                    self.head = block_hash;
                    // Committed blocks never need re-execution.
                    self.payloads.remove(&block_hash);
                    self.payload_order.retain(|h| h != &block_hash);
                    DriverAction::Finalized { block_hash }
                }
            },
            Err(error) => DriverAction::Rejected {
                block_hash,
                reason: error.to_string(),
            },
        }
    }
}

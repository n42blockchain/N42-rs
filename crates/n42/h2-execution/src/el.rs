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
};

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
    /// A canonical block by number, as its header and transactions, for
    /// serving peers that sync by range. `None` when the execution layer
    /// does not have it — or, in the default, does not offer the lookup.
    async fn block_by_number(
        &self,
        number: u64,
    ) -> Result<Option<(alloy_consensus::Header, Vec<alloy_consensus::TxEnvelope>)>, ElError> {
        let _ = number;
        Ok(None)
    }

    /// Engine-API `newPayload` — insert and validate a block.
    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError>;

    /// Engine-API `forkchoiceUpdated` without attributes — the finalise and
    /// import path.
    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError>;

    /// `forkchoiceUpdated` with attributes — starts a payload build. Kept
    /// separate from the attribute-less call so the finalise path can later move
    /// off the consensus hot path.
    async fn fork_choice_updated_with_attrs(
        &self,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError>;

    /// Resolves a started build. `None` means no such job.
    async fn resolve_payload(
        &self,
        id: PayloadId,
        kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>>;
}

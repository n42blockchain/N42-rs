// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Blocks inserted as already executed stay out of reth's cross-block
//! execution cache.
//!
//! reth's `BasicEngineValidator::on_inserted_executed_block` does two things
//! with a block the node executed itself: it writes the block's whole
//! `BundleState` into the cross-block execution cache -- when, and only when,
//! the cache's block is the inserted block's parent -- and it builds the
//! `ExecutedBlock` the tree holds, with the trie data sorted on a blocking
//! worker. The first runs on the engine tree's thread and costs 14-46 ms for a
//! 163,000-transaction block (about 160,000 accounts); nothing on this node's
//! path reads what it writes: the follower executes on its published shards,
//! the leader's builder has its own state path, and the cache is read only by
//! reth's own payload execution (a fork at a handover, a few blocks a leg),
//! which finds it by the parent's hash and misses when the hash differs.
//!
//! Whether a node paid that cost was an accident of the start-up order: a
//! node that inserted the uncommitted view-1 block 1 had its cache left on
//! that block's hash, and every later insert skipped the update; the node
//! that started too late to see that block kept a cache that followed the
//! chain and paid the cost on every block (`docs/INDUSTRY_SURVEY_2026_10.md`,
//! 11.11). [`N42TreeValidator`] makes the skip deliberate on a QMDB chain and
//! keeps everything else the hook does.
//!
//! `N42_ENGINE_EXEC_CACHE=on` restores reth's behaviour for an A/B leg.
//! Non-QMDB chains are built in [`ExecCacheOnInsert::Update`] and behave
//! exactly as upstream.

use alloy_primitives::B256;
use reth_chain_state::ExecutedBlock;
use reth_engine_tree::tree::{
    payload_validator::TreeCtx, CacheWaitDurations, EngineApiTreeState, EngineValidator,
    ValidationOutcome, WaitForCaches,
};
use reth_network_p2p::full_block::SealedBlockWithAccessList;
use reth_payload_builder::PayloadBuilderResources;
use reth_payload_primitives::{
    BuiltPayloadExecutedBlock, InvalidPayloadAttributesError, NewPayloadError, PayloadTypes,
};
use reth_primitives_traits::{NodePrimitives, SealedBlock};
use reth_provider::ProviderResult;
use reth_tasks::Runtime;
use reth_trie::LazyTrieData;

/// The environment variable that restores reth's cache update on an executed
/// insert: `on` updates, anything else (or unset) skips.
pub const EXEC_CACHE_ENV: &str = "N42_ENGINE_EXEC_CACHE";

/// The blocking worker the trie sort runs on, the name reth's own hook uses.
const DEFERRED_TRIE_WORKER_NAME: &str = "deferred-trie";

/// What an executed insert does with reth's cross-block execution cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCacheOnInsert {
    /// reth's behaviour: the block's state goes into the cache when the
    /// cache's block is its parent.
    Update,
    /// The cache is left as it is.
    Skip,
}

impl ExecCacheOnInsert {
    /// The mode a QMDB chain runs in, from the value of [`EXEC_CACHE_ENV`].
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value {
            Some("on") => Self::Update,
            _ => Self::Skip,
        }
    }

    /// The mode a QMDB chain runs in, read from the process environment.
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var(EXEC_CACHE_ENV).ok().as_deref())
    }

    /// The word the start-up line prints.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Skip => "skip",
        }
    }
}

/// The engine tree's validator with the executed-insert hook replaced when
/// skipping; every other method is the inner validator's.
pub struct N42TreeValidator<V> {
    inner: V,
    mode: ExecCacheOnInsert,
    runtime: Runtime,
}

impl<V> std::fmt::Debug for N42TreeValidator<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("N42TreeValidator").field("mode", &self.mode).finish_non_exhaustive()
    }
}

impl<V> N42TreeValidator<V> {
    /// Wraps `inner`; `runtime` runs the trie sort of a skipped insert, as
    /// reth's validator runs its own on the node's task runtime.
    pub const fn new(inner: V, mode: ExecCacheOnInsert, runtime: Runtime) -> Self {
        Self { inner, mode, runtime }
    }

    /// What this validator does with the cache on an executed insert.
    pub const fn mode(&self) -> ExecCacheOnInsert {
        self.mode
    }

    /// The wrapped validator.
    pub const fn inner(&self) -> &V {
        &self.inner
    }
}

/// Everything reth's hook does for an executed insert except the cache
/// update: the deferred trie data (hashed state and trie updates sorted on a
/// blocking worker, waited for by whoever reads them first) and the
/// `ExecutedBlock` built from it. reth also records three histograms of the
/// sort in its private validation metrics; those are not recorded here.
pub fn executed_block_without_cache<N: NodePrimitives>(
    block: BuiltPayloadExecutedBlock<N>,
    runtime: &Runtime,
) -> ExecutedBlock<N> {
    let BuiltPayloadExecutedBlock { recovered_block, execution_output, hashed_state, trie_updates } =
        block;
    let (trie_data, producer) = LazyTrieData::pending(hashed_state, trie_updates);
    let _ = runtime.spawn_blocking_named(DEFERRED_TRIE_WORKER_NAME, move || {
        let _ = producer.compute_and_publish();
    });
    ExecutedBlock::with_deferred_trie_data(recovered_block, execution_output, trie_data)
}

impl<Types, N, V> EngineValidator<Types, N> for N42TreeValidator<V>
where
    Types: PayloadTypes,
    N: NodePrimitives,
    V: EngineValidator<Types, N>,
{
    fn validate_payload_attributes_against_header(
        &self,
        attr: &Types::PayloadAttributes,
        header: &N::BlockHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        self.inner.validate_payload_attributes_against_header(attr, header)
    }

    fn convert_payload_to_block(
        &self,
        payload: Types::ExecutionData,
    ) -> Result<SealedBlock<N::Block>, NewPayloadError> {
        self.inner.convert_payload_to_block(payload)
    }

    fn validate_payload(
        &mut self,
        payload: Types::ExecutionData,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N> {
        self.inner.validate_payload(payload, ctx)
    }

    fn validate_block(
        &mut self,
        block: SealedBlockWithAccessList<N::Block>,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N> {
        self.inner.validate_block(block, ctx)
    }

    fn on_inserted_executed_block(
        &self,
        block: BuiltPayloadExecutedBlock<N>,
    ) -> ProviderResult<ExecutedBlock<N>> {
        match self.mode {
            ExecCacheOnInsert::Update => self.inner.on_inserted_executed_block(block),
            ExecCacheOnInsert::Skip => Ok(executed_block_without_cache(block, &self.runtime)),
        }
    }

    fn on_canonical_head_changed(&self, hash: B256, state: &EngineApiTreeState<N>) {
        self.inner.on_canonical_head_changed(hash, state)
    }

    fn payload_builder_resources(
        &self,
        parent_hash: B256,
        parent_header: &N::BlockHeader,
        timestamp: u64,
        state: &mut EngineApiTreeState<N>,
    ) -> PayloadBuilderResources {
        self.inner.payload_builder_resources(parent_hash, parent_header, timestamp, state)
    }
}

impl<V: WaitForCaches> WaitForCaches for N42TreeValidator<V> {
    fn wait_for_caches(&self) -> CacheWaitDurations {
        self.inner.wait_for_caches()
    }
}

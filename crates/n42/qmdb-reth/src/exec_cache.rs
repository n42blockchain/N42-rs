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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, U256};
    use reth_engine_tree::tree::{ExecutionCache, PayloadExecutionCache, SavedCache};
    use reth_ethereum_engine_primitives::EthEngineTypes;
    use reth_ethereum_primitives::{Block, EthPrimitives};
    use reth_execution_types::BlockExecutionResult;
    use reth_primitives_traits::{Account, RecoveredBlock};
    use reth_provider::BlockExecutionOutput;
    use reth_trie::{updates::TrieUpdates, HashedPostState};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    /// Stands in for reth's validator: counts the executed inserts it is
    /// handed and answers with the block's trie data already sorted.
    #[derive(Default)]
    struct Recorder {
        inserted: Arc<AtomicUsize>,
    }

    impl EngineValidator<EthEngineTypes> for Recorder {
        fn validate_payload_attributes_against_header(
            &self,
            _attr: &<EthEngineTypes as PayloadTypes>::PayloadAttributes,
            _header: &alloy_consensus::Header,
        ) -> Result<(), InvalidPayloadAttributesError> {
            Ok(())
        }

        fn convert_payload_to_block(
            &self,
            _payload: <EthEngineTypes as PayloadTypes>::ExecutionData,
        ) -> Result<SealedBlock<Block>, NewPayloadError> {
            unreachable!("not reached by these tests")
        }

        fn validate_payload(
            &mut self,
            _payload: <EthEngineTypes as PayloadTypes>::ExecutionData,
            _ctx: TreeCtx<'_, EthPrimitives>,
        ) -> ValidationOutcome<EthPrimitives> {
            unreachable!("not reached by these tests")
        }

        fn validate_block(
            &mut self,
            _block: SealedBlockWithAccessList<Block>,
            _ctx: TreeCtx<'_, EthPrimitives>,
        ) -> ValidationOutcome<EthPrimitives> {
            unreachable!("not reached by these tests")
        }

        fn on_inserted_executed_block(
            &self,
            block: BuiltPayloadExecutedBlock<EthPrimitives>,
        ) -> ProviderResult<ExecutedBlock<EthPrimitives>> {
            self.inserted.fetch_add(1, Ordering::SeqCst);
            let BuiltPayloadExecutedBlock { recovered_block, execution_output, hashed_state, trie_updates } =
                block;
            let (data, producer) = LazyTrieData::pending(hashed_state, trie_updates);
            let _ = producer.compute_and_publish();
            Ok(ExecutedBlock::with_deferred_trie_data(recovered_block, execution_output, data))
        }

        fn payload_builder_resources(
            &self,
            _parent_hash: B256,
            _parent_header: &alloy_consensus::Header,
            _timestamp: u64,
            _state: &mut EngineApiTreeState<EthPrimitives>,
        ) -> PayloadBuilderResources {
            unreachable!("not reached by these tests")
        }
    }

    fn hashed_state() -> HashedPostState {
        let mut state = HashedPostState::default();
        state.accounts.insert(
            B256::with_last_byte(1),
            Some(Account { nonce: 3, balance: U256::from(7), bytecode_hash: None }),
        );
        state.accounts.insert(B256::with_last_byte(2), None);
        state
    }

    fn executed(number: u64) -> BuiltPayloadExecutedBlock<EthPrimitives> {
        let mut block = Block::default();
        block.header.number = number;
        let mut output = BlockExecutionOutput {
            result: BlockExecutionResult::default(),
            state: Default::default(),
        };
        output.result.gas_used = 21_000 * number;
        BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(RecoveredBlock::new_unhashed(block, vec![])),
            execution_output: Arc::new(output),
            hashed_state: Arc::new(hashed_state()),
            trie_updates: Arc::new(TrieUpdates::default()),
        }
    }

    fn wrapped(mode: ExecCacheOnInsert) -> (N42TreeValidator<Recorder>, Arc<AtomicUsize>) {
        let recorder = Recorder::default();
        let inserted = Arc::clone(&recorder.inserted);
        (N42TreeValidator::new(recorder, mode, Runtime::test()), inserted)
    }

    #[test]
    fn the_switch_reads_on_and_nothing_else() {
        assert_eq!(ExecCacheOnInsert::from_env_value(Some("on")), ExecCacheOnInsert::Update);
        for value in [None, Some(""), Some("off"), Some("1"), Some("ON")] {
            assert_eq!(ExecCacheOnInsert::from_env_value(value), ExecCacheOnInsert::Skip, "{value:?}");
        }
    }

    #[test]
    fn skipping_never_reaches_the_inner_hook() {
        let (validator, inserted) = wrapped(ExecCacheOnInsert::Skip);
        for number in 1..=3 {
            let _ = EngineValidator::<EthEngineTypes>::on_inserted_executed_block(&validator, executed(number))
                .expect("an executed insert");
        }
        assert_eq!(inserted.load(Ordering::SeqCst), 0, "the inner hook is the one that writes the cache");
    }

    #[test]
    fn updating_hands_every_insert_to_the_inner_hook() {
        let (validator, inserted) = wrapped(ExecCacheOnInsert::Update);
        for number in 1..=3 {
            let _ = EngineValidator::<EthEngineTypes>::on_inserted_executed_block(&validator, executed(number))
                .expect("an executed insert");
        }
        assert_eq!(inserted.load(Ordering::SeqCst), 3);
    }

    /// The block, its execution output and its sorted trie data are the same
    /// whichever way the insert went.
    #[test]
    fn both_modes_give_the_tree_the_same_executed_block() {
        let expected_hashed = hashed_state().clone_into_sorted();
        for mode in [ExecCacheOnInsert::Skip, ExecCacheOnInsert::Update] {
            let (validator, _) = wrapped(mode);
            let input = executed(5);
            let output_in = Arc::clone(&input.execution_output);
            let hash = input.recovered_block.hash();
            let block = EngineValidator::<EthEngineTypes>::on_inserted_executed_block(&validator, input)
                .expect("an executed insert");
            assert_eq!(block.recovered_block().hash(), hash, "{mode:?}");
            assert_eq!(block.recovered_block().number, 5, "{mode:?}");
            assert_eq!(block.execution_outcome(), &*output_in, "{mode:?}");
            assert_eq!(block.execution_outcome().result.gas_used, 105_000, "{mode:?}");
            // Waits for the worker's sort when it has not published yet.
            assert_eq!(*block.hashed_state(), expected_hashed, "{mode:?}");
            assert_eq!(*block.trie_updates(), TrieUpdates::default().into_sorted(), "{mode:?}");
            assert!(block.bal().is_none(), "{mode:?}");
        }
    }

    /// What a reth-side execution (a fork's payload, a range sync) finds in a
    /// cache that skipped inserts left at an old block: it asks for the
    /// cache by its parent's hash. A different parent gets the cache back
    /// empty -- every read goes to the state provider -- and the old block's
    /// own children get exactly that block's state, which a skipped insert
    /// never changed.
    #[test]
    fn a_stale_cache_misses_or_holds_its_own_block_state() {
        let stale = B256::repeat_byte(0xaa);
        let tip = B256::repeat_byte(0xbb);
        let who = address!("0000000000000000000000000000000000000042");
        let at_stale = Account { nonce: 1, balance: U256::from(10), bytecode_hash: None };
        let fill = |cache: &PayloadExecutionCache| {
            let saved = SavedCache::new(stale, ExecutionCache::new(1_000_000));
            saved.cache().insert_account(who, Some(at_stale));
            cache.update_with_guard(|slot| *slot = Some(saved));
        };
        let read = |saved: &SavedCache| {
            let mut miss = false;
            let account = saved
                .cache()
                .get_or_try_insert_account_with(who, || {
                    miss = true;
                    Ok::<_, ()>(None)
                })
                .expect("a cache read");
            (miss, account)
        };

        // A block on another parent: the cache comes back empty.
        let cache = PayloadExecutionCache::default();
        fill(&cache);
        let checked_out = cache.get_cache_for(tip).expect("an available cache");
        assert_eq!(checked_out.executed_block_hash(), tip);
        let (miss, _) = read(&checked_out);
        assert!(miss, "a cache left at another block must not answer for this one");

        // A block on the stale block itself: that block's state.
        let cache = PayloadExecutionCache::default();
        fill(&cache);
        let checked_out = cache.get_cache_for(stale).expect("an available cache");
        assert_eq!(checked_out.executed_block_hash(), stale);
        let (miss, account) = read(&checked_out);
        assert!(!miss, "the stale block's own state is what it holds");
        let text = format!("{account:?}");
        assert!(text.starts_with("Cached(Some(") && text.contains("nonce: 1"), "{text}");
    }
}

//! N42: a process-wide latch that is set before reth's engine tree can first
//! record a block in its invalid-header cache, and never cleared.
//!
//! The cache (`EngineApiTreeState::invalid_headers`, reth v2.11.0
//! `crates/engine/tree/src/tree/mod.rs:116`) is private and starts empty. It
//! is written in exactly three places (`invalid_headers.rs` has no other
//! writer, and no other module touches the field):
//!
//! - `on_insert_block_error` (mod.rs:3355), for a validation error of a
//!   payload or block the tree tried to insert. Its errors come from the
//!   tree's validator (`validate_payload` / `validate_block`, called through
//!   `insert_block_or_payload`'s `execute`, mod.rs:3236, for a payload
//!   (mod.rs:852), a buffered block (mod.rs:2731) or a downloaded one
//!   (mod.rs:3111)) or from the tree's consensus (`validate_block`,
//!   mod.rs:2684-2690, through `buffer_block`, mod.rs:2749, while a backfill
//!   is pending or running, mod.rs:882). Provider and internal errors are
//!   fatal there and insert nothing (`ensure_validation_error`).
//! - `on_backfill_sync_finished` (mod.rs:1855), for a backfill that unwound
//!   over a bad block. A backfill finishes only after the orchestrator was
//!   asked to start one (`BackfillSync::on_action(Start)`).
//! - `on_invalid_new_payload` (mod.rs:2594), for a block linking to an entry
//!   already in the cache (both callers, mod.rs:2581 and mod.rs:2660, first
//!   find that entry): never the first write.
//!
//! The latch also covers the tree leaving its idle backfill state. While
//! not idle, `on_new_payload` (mod.rs:791) buffers every payload and answers
//! SYNCING (`try_buffer_payload`), where a held block would otherwise have
//! been VALID. The tree starts idle (mod.rs:401) and leaves it only to:
//!
//! - `Active` (mod.rs:1588), on the orchestrator's `BackfillSyncStarted`,
//!   which follows `BackfillSync::on_action(Start)`;
//! - `Pending` (mod.rs:2200) or `PendingRevalidation` (mod.rs:2182), both
//!   only in `emit_event` for a `BackfillAction`. Those come from a backfill
//!   that just finished (mod.rs:1951, after a start) or from
//!   `on_disconnected_downloaded_block` (mod.rs:2995), for a block the
//!   downloader delivered (`on_downloaded`, mod.rs:689, fed only by
//!   `FromEngine::DownloadedBlocks`). The downloader is built with the
//!   tree's consensus (`launch.rs:152`), and every block it delivers has
//!   passed `validate_body_against_header` on it first
//!   (`net/p2p/src/full_block.rs:243`, `:258`, `:776`).
//!
//! The launcher wraps the three objects those roots go through:
//! [`LatchingValidator`] around the tree's validator, [`LatchingConsensus`]
//! around the tree's consensus, and [`LatchingBackfill`] around the
//! backfill. The validator and consensus set the latch before a failure
//! returns; the consensus also on any downloaded body or header range,
//! whatever the outcome; the backfill before a start is acted on. So the
//! latch is set before the first cache write and before the tree first
//! leaves idle, on the engine thread or (downloader, orchestrator) strictly
//! before the message that leads there reaches it. It may also be set where
//! neither follows (a transient consensus error, a download that ends in an
//! ordinary insert, a backfill that unwinds nothing): it only ever errs
//! toward set.

use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderConsensusError, HeaderValidator,
    ReceiptRootBloom, TransactionRoot,
};
use reth_engine_tree::{
    backfill::{BackfillAction, BackfillEvent, BackfillSync},
    tree::{
        error::InsertPayloadError, payload_validator::TreeCtx, CacheWaitDurations,
        EngineApiTreeState, EngineValidator, ValidationOutcome, WaitForCaches,
    },
};
use reth_evm::cached::CachedReads;
use reth_execution_types::BlockExecutionResult;
use reth_network_p2p::full_block::SealedBlockWithAccessList;
use reth_payload_builder::PayloadBuilderResources;
use reth_payload_primitives::{
    BuiltPayloadExecutedBlock, InvalidPayloadAttributesError, NewPayloadError, PayloadTypes,
};
use reth_primitives_traits::{Block, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    task::{Context, Poll},
    time::Duration,
};
use alloy_consensus::Header;
use alloy_primitives::{Address, BlockHash, B256, U256};
use reth_chain_state::ExecutedBlock;
use reth_provider::ProviderResult;
use tracing::warn;

/// A one-way flag with the reason it was first set.
#[derive(Debug, Default)]
pub struct Latch {
    set: AtomicBool,
    reason: OnceLock<String>,
}

impl Latch {
    /// A clear latch.
    pub const fn new() -> Self {
        Self { set: AtomicBool::new(false), reason: OnceLock::new() }
    }

    /// Sets the latch; `reason` is built and logged only the first time.
    pub fn set(&self, reason: impl FnOnce() -> String) {
        if !self.set.swap(true, Ordering::SeqCst) {
            let reason = reason();
            warn!(target: "reth::cli", %reason, "invalid-header latch set: own-block newPayloads are always sent from now on");
            let _ = self.reason.set(reason);
        }
    }

    /// Whether the latch was set.
    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::SeqCst)
    }

    /// The reason it was first set (`None` while clear, or for a moment
    /// after the first set).
    pub fn reason(&self) -> Option<&str> {
        self.reason.get().map(String::as_str)
    }
}

static GLOBAL: Latch = Latch::new();

/// The process's latch, the one the launcher's wrappers set.
pub fn global() -> &'static Latch {
    &GLOBAL
}

/// Whether the process's latch was set: once `true`, always `true`.
pub fn is_latched() -> bool {
    GLOBAL.is_set()
}

/// The tree's validator, setting the latch on a payload or block it rejects
/// as invalid.
#[derive(Debug)]
pub struct LatchingValidator<V> {
    inner: V,
    latch: &'static Latch,
}

impl<V> LatchingValidator<V> {
    /// Wraps `inner`, setting `latch`.
    pub const fn new(inner: V, latch: &'static Latch) -> Self {
        Self { inner, latch }
    }

    fn note<N: NodePrimitives>(&self, what: &str, outcome: &ValidationOutcome<N>) {
        if let Err(InsertPayloadError::Block(error)) = outcome &&
            error.kind().is_validation_error()
        {
            self.latch.set(|| format!("the engine's validator rejected a {what}: {}", error.kind()));
        }
    }
}

impl<Types, N, V> EngineValidator<Types, N> for LatchingValidator<V>
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
        let outcome = self.inner.validate_payload(payload, ctx);
        self.note("payload", &outcome);
        outcome
    }

    fn validate_block(
        &mut self,
        block: SealedBlockWithAccessList<N::Block>,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N> {
        let outcome = self.inner.validate_block(block, ctx);
        self.note("block", &outcome);
        outcome
    }

    fn on_inserted_executed_block(
        &self,
        block: BuiltPayloadExecutedBlock<N>,
    ) -> ProviderResult<ExecutedBlock<N>> {
        self.inner.on_inserted_executed_block(block)
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

impl<V: WaitForCaches> WaitForCaches for LatchingValidator<V> {
    fn wait_for_caches(&self) -> CacheWaitDurations {
        self.inner.wait_for_caches()
    }
}

/// The tree's consensus, setting the latch on any validation it fails.
/// Every method is forwarded, the N42 ones included.
#[derive(Debug)]
pub struct LatchingConsensus<C> {
    inner: C,
    latch: &'static Latch,
}

impl<C> LatchingConsensus<C> {
    /// Wraps `inner`, setting `latch`.
    pub const fn new(inner: C, latch: &'static Latch) -> Self {
        Self { inner, latch }
    }

    fn note<T, E: core::fmt::Display>(&self, what: &str, result: Result<T, E>) -> Result<T, E> {
        if let Err(error) = &result {
            self.latch.set(|| format!("the engine's consensus failed {what}: {error}"));
        }
        result
    }
}

impl<H, C> HeaderValidator<H> for LatchingConsensus<C>
where
    C: HeaderValidator<H>,
{
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        self.note("validate_header", self.inner.validate_header(header))
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        self.note(
            "validate_header_against_parent",
            self.inner.validate_header_against_parent(header, parent),
        )
    }

    fn validate_header_range(
        &self,
        headers: &[SealedHeader<H>],
    ) -> Result<(), HeaderConsensusError<H>>
    where
        H: Clone,
    {
        // Only the block downloader checks ranges: a range download, whatever
        // the outcome, may be what takes the tree out of idle.
        self.latch.set(|| "the engine's block downloader checked a header range".to_owned());
        self.inner.validate_header_range(headers)
    }
}

impl<B, C> Consensus<B> for LatchingConsensus<C>
where
    B: Block,
    C: Consensus<B>,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        // Only the block downloader checks bodies alone, once for every block
        // it delivers: a downloaded block, valid or not, may be what takes
        // the tree out of idle (module docs).
        self.latch.set(|| "the engine's block downloader checked a downloaded body".to_owned());
        self.inner.validate_body_against_header(body, header)
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        self.note("validate_block_pre_execution", self.inner.validate_block_pre_execution(block))
    }

    fn is_transient_error(&self, error: &ConsensusError) -> bool {
        self.inner.is_transient_error(error)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<B>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        self.note(
            "validate_block_pre_execution",
            self.inner.validate_block_pre_execution_with_tx_root(block, transaction_root),
        )
    }

    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {
        self.inner.prepare(parent_header)
    }

    fn seal(&self, header: &mut Header) -> Result<(), ConsensusError> {
        self.inner.seal(header)
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        self.inner.set_eth_signer_by_key(eth_signer_key)
    }

    fn get_eth_signer_address(&self) -> Result<Option<Address>, ConsensusError> {
        self.inner.get_eth_signer_address()
    }

    fn snapshot(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Header>>,
    ) -> Result<n42_primitives::Snapshot, ConsensusError> {
        self.inner.snapshot(number, hash, parents)
    }

    fn propose(&self, address: Address, auth: bool) -> Result<(), ConsensusError> {
        self.inner.propose(address, auth)
    }

    fn discard(&self, address: Address) -> Result<(), ConsensusError> {
        self.inner.discard(address)
    }

    fn proposals(&self) -> Result<HashMap<Address, bool>, ConsensusError> {
        self.inner.proposals()
    }

    fn total_difficulty(&self, hash: B256) -> U256 {
        self.inner.total_difficulty(hash)
    }

    fn wiggle(&self, parent_number: u64, parent_hash: BlockHash, difficulty: U256) -> Duration {
        self.inner.wiggle(parent_number, parent_hash, difficulty)
    }

    fn set_cached_reads(
        &self,
        block_hash: BlockHash,
        cached_reads: CachedReads,
    ) -> Result<(), ConsensusError> {
        self.inner.set_cached_reads(block_hash, cached_reads)
    }

    fn get_cached_reads(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<CachedReads>, ConsensusError> {
        self.inner.get_cached_reads(block_hash)
    }
}

impl<N, C> FullConsensus<N> for LatchingConsensus<C>
where
    N: NodePrimitives,
    C: FullConsensus<N>,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        self.note(
            "validate_block_post_execution",
            self.inner.validate_block_post_execution(
                block,
                result,
                receipt_root_bloom,
                block_access_list_hash,
            ),
        )
    }
}

/// The engine's backfill, setting the latch when it is asked to start one:
/// before the start is acted on, so before any run can finish.
#[derive(Debug)]
pub struct LatchingBackfill<B> {
    inner: B,
    latch: &'static Latch,
}

impl<B> LatchingBackfill<B> {
    /// Wraps `inner`, setting `latch`.
    pub const fn new(inner: B, latch: &'static Latch) -> Self {
        Self { inner, latch }
    }
}

impl<B: BackfillSync> BackfillSync for LatchingBackfill<B> {
    fn on_action(&mut self, action: BackfillAction) {
        if let BackfillAction::Start(target) = &action {
            self.latch.set(|| format!("a backfill was started (target {target})"));
        }
        self.inner.on_action(action)
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<BackfillEvent> {
        self.inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_consensus::noop::NoopConsensus;
    use reth_engine_tree::backfill::BackfillEvent;
    use reth_ethereum_primitives::{Block as EthBlock, EthPrimitives};

    fn leaked() -> &'static Latch {
        Box::leak(Box::new(Latch::new()))
    }

    #[test]
    fn the_latch_is_one_way_and_keeps_the_first_reason() {
        let latch = leaked();
        assert!(!latch.is_set() && latch.reason().is_none());
        latch.set(|| "first".to_owned());
        latch.set(|| unreachable!("built only once"));
        assert!(latch.is_set());
        assert_eq!(latch.reason(), Some("first"));
    }

    /// A consensus that fails every check.
    #[derive(Debug)]
    struct Refusing;

    impl<H> HeaderValidator<H> for Refusing {
        fn validate_header(&self, _: &SealedHeader<H>) -> Result<(), ConsensusError> {
            Err(ConsensusError::msg("refused"))
        }
        fn validate_header_against_parent(
            &self,
            _: &SealedHeader<H>,
            _: &SealedHeader<H>,
        ) -> Result<(), ConsensusError> {
            Err(ConsensusError::msg("refused"))
        }
    }

    impl<B: Block> Consensus<B> for Refusing {
        fn validate_body_against_header(
            &self,
            _: &B::Body,
            _: &SealedHeader<B::Header>,
        ) -> Result<(), ConsensusError> {
            Err(ConsensusError::msg("refused"))
        }
        fn validate_block_pre_execution(&self, _: &SealedBlock<B>) -> Result<(), ConsensusError> {
            Err(ConsensusError::msg("refused"))
        }
    }

    #[test]
    fn the_consensus_latches_on_a_failure_or_a_download() {
        let block = SealedBlock::<EthBlock>::seal_slow(EthBlock::default());

        let passing_latch = leaked();
        let passing = LatchingConsensus::new(NoopConsensus::default(), passing_latch);
        assert!(HeaderValidator::validate_header(&passing, block.sealed_header()).is_ok());
        assert!(Consensus::<EthBlock>::validate_block_pre_execution(&passing, &block).is_ok());
        assert!(!passing_latch.is_set());

        // The tree's own two checks (mod.rs:2685, mod.rs:2690), each alone.
        let header_latch = leaked();
        let refusing = LatchingConsensus::new(Refusing, header_latch);
        assert!(HeaderValidator::validate_header(&refusing, block.sealed_header()).is_err());
        assert!(header_latch.is_set());
        assert!(header_latch.reason().is_some_and(|why| why.contains("validate_header")));

        let body_latch = leaked();
        let refusing = LatchingConsensus::new(Refusing, body_latch);
        assert!(Consensus::<EthBlock>::validate_block_pre_execution(&refusing, &block).is_err());
        assert!(body_latch.is_set());

        // The downloader's body check latches even when the body passes: a
        // delivered block is how the tree first leaves idle.
        let download_latch = leaked();
        let downloading = LatchingConsensus::new(NoopConsensus::default(), download_latch);
        assert!(Consensus::<EthBlock>::validate_body_against_header(
            &downloading,
            block.body(),
            block.sealed_header()
        )
        .is_ok());
        assert!(download_latch.reason().is_some_and(|why| why.contains("downloaded body")));
        let range_latch = leaked();
        let downloading = LatchingConsensus::new(NoopConsensus::default(), range_latch);
        assert!(HeaderValidator::<alloy_consensus::Header>::validate_header_range(&downloading, &[]).is_ok());
        assert!(range_latch.is_set());

        // Whatever is forwarded unchanged stays unchanged.
        let forwarded = LatchingConsensus::new(NoopConsensus::default(), leaked());
        let error = ConsensusError::msg("x");
        assert_eq!(
            Consensus::<EthBlock>::is_transient_error(&forwarded, &error),
            Consensus::<EthBlock>::is_transient_error(&NoopConsensus::default(), &error)
        );
        let _: &dyn FullConsensus<EthPrimitives> = &forwarded;
    }

    /// A backfill that records the actions it got.
    #[derive(Debug, Default)]
    struct Recording(Vec<BackfillAction>);

    impl BackfillSync for Recording {
        fn on_action(&mut self, action: BackfillAction) {
            self.0.push(action);
        }
        fn poll(&mut self, _: &mut Context<'_>) -> Poll<BackfillEvent> {
            Poll::Pending
        }
    }

    #[test]
    fn the_backfill_latches_on_a_start_before_passing_it_on() {
        let latch = leaked();
        let mut backfill = LatchingBackfill::new(Recording::default(), latch);
        backfill.on_action(BackfillAction::UpdateFinalized(B256::ZERO));
        assert!(!latch.is_set(), "only a start latches");
        backfill.on_action(BackfillAction::Start(B256::ZERO.into()));
        assert!(latch.is_set());
        assert_eq!(backfill.inner.0.len(), 2, "every action passed on");
    }
}

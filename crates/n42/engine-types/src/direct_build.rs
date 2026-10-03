// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Building the next block on a block this node built a moment ago -- before
//! the engine has imported it, and without a forkchoice to name it.
//!
//! On the leader's chain the build ahead used to start only after two round
//! trips through the engine: the own block's header import (62 ms at the
//! 163,000-transaction tier) and the forkchoiceUpdated that creates the
//! payload job (72 ms), then reth's payload service around the builder
//! (~35 ms) -- some 170 ms of a 570 ms cycle that builds nothing
//! (`docs/FLEET7_PLAN_V2.md`, phase A). The builder had the parent's
//! post-state in hand the whole time: it executed the block. This module
//! lets the raw payload channel call the builder directly with that state.
//!
//! The parent is a build the node keeps (`built_executions`), addressed by
//! the sealed header consensus gave it; its bundle is laid over the chain's
//! state at the grandparent with reth's own in-memory overlay, so the
//! builder reads the parent's nonces and balances without the parent being
//! in the engine's tree. The engine's import and forkchoice still happen --
//! beside the build instead of ahead of it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, StorageValue, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_tx_types::N42Primitives;
use crate::memory_overlay::{MemoryOverlayStateProvider, MemoryOverlayStateProviderRef};
use reth_chain_state::ExecutedBlock;
use reth_primitives_traits::{Account, Bytecode, RecoveredBlock, SealedBlock, SealedHeader};
use reth_storage_api::{
    errors::ProviderResult, AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider,
    StateProofProvider, StateProvider, StateProviderBox, StateProviderFactory, StateRootProvider,
    StorageRootProvider,
};
use reth_trie::{
    updates::TrieUpdates, AccountProof, ComputedTrieData, ExecutionWitnessMode, HashedPostState, HashedStorage,
    LazyTrieData, MultiProof, MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};
use revm::database::BundleState;

use crate::{built_executions::BuiltExecution, engine_types::N42BuiltPayload};

/// Opens the state a build reads from, when it is not the state the client
/// would find by the parent's hash.
pub type ParentStateOpener = Arc<dyn Fn() -> ProviderResult<StateProviderBox> + Send + Sync>;

/// What a build on an own block needs.
#[derive(Debug)]
pub struct BuildOnOwnRequest {
    /// The parent, under the hash consensus sealed it with.
    pub parent: SealedHeader,
    /// The parent's execution, as the builder kept it (its block is under
    /// the builder's own hash) -- or, on a build started at the parent's
    /// seal (`N42_BUILD_ON_OUTPUT`), only the name it will be kept under.
    pub parent_execution: ParentExecution,
    /// The attributes of the block to build.
    pub attributes: PayloadAttributes,
    /// Signalled (or dropped) once the parent's transactions have left the
    /// queue's taken list: the build waits for it before its first pull, so
    /// the queue's hand-off runs beside the build's setup instead of ahead
    /// of it, and the order the queue depends on -- the parent's
    /// transactions held before the next build pulls -- is kept. `None`
    /// pulls at once, as every build did before.
    pub before_pull: Option<std::sync::mpsc::Receiver<()>>,
}

/// The parent's execution as a build on it receives it.
#[derive(Debug, Clone)]
pub enum ParentExecution {
    /// Found at `StateReady` or later: its post-state is in hand.
    Ready(BuiltExecution),
    /// Found at its seal: the post-state is still being filed behind it, and
    /// the build's state opener waits for it under this, the builder's hash
    /// ([`opener_on_sealed_parent`]).
    Sealed {
        /// The hash the builder gave the parent.
        built_hash: B256,
    },
    /// A parent this node did not build: a peer's block this node executed as
    /// a follower and published the output of (`N42_TENURE_FIRST_ON_OUTPUT`,
    /// the first build of a tenure). `executed` is that output and, when the
    /// engine is behind, the published outputs of its ancestors, **newest
    /// first**, each laid under its sealed header ([`executed_from_output`]);
    /// `anchor` is the parent of the oldest, whose state the reads none of
    /// them answers fall through to.
    Published {
        /// The parent's sealed hash: a peer's block has no builder hash, and
        /// its execution fields are filed under the hash consensus sealed.
        parent_hash: B256,
        /// The published outputs, newest first.
        executed: Vec<ExecutedParent>,
        /// The nearest ancestor below them.
        anchor: B256,
    },
}

impl ParentExecution {
    /// The hash the builder gave the parent.
    pub fn built_hash(&self) -> B256 {
        match self {
            Self::Ready(execution) => execution.block.hash(),
            Self::Sealed { built_hash } => *built_hash,
            Self::Published { parent_hash, .. } => *parent_hash,
        }
    }
}

/// A builder the raw payload channel can call directly.
pub trait DirectBuilder: Send + Sync {
    /// Builds a block on `request.parent`, reading the parent's post-state
    /// from `request.parent_execution`.
    fn build_on_own(&self, request: BuildOnOwnRequest) -> Result<N42BuiltPayload, String>;
}

fn registry() -> &'static OnceLock<Arc<dyn DirectBuilder>> {
    static REGISTRY: OnceLock<Arc<dyn DirectBuilder>> = OnceLock::new();
    &REGISTRY
}

/// Registers the node's builder; the first registration wins.
pub fn register(builder: Arc<dyn DirectBuilder>) {
    let _ = registry().set(builder);
}

/// The registered builder, once the payload service has started one.
pub fn get() -> Option<Arc<dyn DirectBuilder>> {
    registry().get().cloned()
}

/// The parent as an executed block under its sealed header, so the overlay
/// answers `BLOCKHASH` with the hash the chain knows rather than the
/// builder's. One copy of the body (163,000 transactions, ~10 ms) per build.
pub fn executed_under_seal(parent: &SealedHeader, execution: &BuiltExecution) -> ExecutedBlock<N42Primitives> {
    let sealed = SealedBlock::from_sealed_parts(parent.clone(), execution.block.body().clone());
    let recovered = RecoveredBlock::new_sealed(sealed, execution.block.senders().to_vec());
    let hashed = execution.hashed_state.clone();
    let updates = execution.trie_updates.clone();
    ExecutedBlock {
        recovered_block: Arc::new(recovered),
        execution_output: execution.execution_output.clone(),
        // Only reth's trie methods read this, and nothing on a QMDB chain's
        // build path calls them; computed if anything ever does.
        trie_data: LazyTrieData::deferred(move || {
            ComputedTrieData::new(Arc::new((*hashed).clone().into_sorted()), Arc::new((*updates).clone().into_sorted()))
        }),
        bal: None,
    }
}

/// The parent as an executed block, as a follower's import holds it while it
/// executes the next block on it.
pub type ExecutedParent = ExecutedBlock<N42Primitives>;

/// The follower-side twin of [`executed_under_seal`]: the parent as an
/// executed block built from the execution output a follower's import
/// produced for it, under the header consensus sealed.
///
/// A follower's import publishes that output when the parent's execution ends
/// (`bin/n42/src/follower_import.rs`), so the next block can be executed on it
/// instead of waiting for the parent to reach the engine's tree -- the leader
/// has built on its own block this way since phase A.
///
/// The body is left empty, and that is not a shortcut with a hazard behind
/// it: the overlay reads accounts, storage and bytecode from
/// `execution_output` and touches the block only for `BLOCKHASH`, which is
/// the sealed header's hash and number
/// (reth v2.5.1 `crates/chain-state/src/memory_overlay.rs:73-82`, `:114-124`,
/// `:237-262`). It saves the copy of 163,000 transactions
/// [`executed_under_seal`] pays (~10 ms a block).
///
/// The trie data is empty for the same reason: nothing on the read path
/// consults it, and the caller must keep reth's Merkle-Patricia passes off
/// (`N42_HASHED_TABLES=off`), since a follower's published output carries no
/// hashed post-state to put here.
pub fn executed_from_output(
    parent: &SealedHeader,
    output: Arc<reth_execution_types::BlockExecutionOutput<n42_tx_types::Receipt>>,
) -> ExecutedParent {
    let sealed = SealedBlock::from_sealed_parts(parent.clone(), n42_tx_types::BlockBody::default());
    ExecutedBlock {
        recovered_block: Arc::new(RecoveredBlock::new_sealed(sealed, Vec::new())),
        execution_output: output,
        trie_data: LazyTrieData::ready(ComputedTrieData::new(
            Arc::new(reth_trie::HashedPostState::default().into_sorted()),
            Arc::new(reth_trie::updates::TrieUpdates::default().into_sorted()),
        )),
        bal: None,
    }
}

/// The parent's post-state: `executed` laid over `historical`, the chain's
/// state at the oldest of those blocks' parent. The caller-owned twin of
/// [`opener_on_built_parent`], for a follower's import, which holds its
/// provider by reference and opens one view per execution batch.
///
/// `executed` is **newest first** -- the parent, then its parent, ... -- which
/// is the order reth's overlay documents for `in_memory` and the order its
/// reads take: `basic_account`, `storage` and `bytecode_by_hash` return the
/// first answer they find, so the newest block that touched an account is that
/// account's state and the rest of the stack is never consulted for it
/// (reth v2.5.1 `crates/chain-state/src/memory_overlay.rs:114-124`, `:237-251`,
/// `:253-262`). Several published outputs therefore compose as providers, with
/// no merged bundle in between: a follower whose parent is not yet in the
/// engine, and whose grandparent is not either, lays both over the state at
/// the nearest ancestor that is.
pub fn overlay_on_executed(historical: StateProviderBox, executed: Vec<ExecutedParent>) -> StateProviderBox {
    if read_depth::enabled() {
        read_depth::note_overlay_depth(executed.len());
        return Box::new(read_depth::CountingStateProvider { historical, executed });
    }
    Box::new(MemoryOverlayStateProvider::<N42Primitives>::new(historical, executed))
}

/// `N42_READ_DEPTH_COUNTS=1`: a per-depth count of the `basic_account` reads
/// [`overlay_on_executed`]'s provider answers, settling plan v6's ceiling-4
/// lead (`docs/FLEET7_PLAN_V4.md` 6.4) -- whether the leader's 65 ms execution
/// and the follower's 65-70 ms of groups are spent walking this overlay's own
/// stack of executed blocks (the leader's parent chain, one deep; the
/// follower's published-output ancestry,
/// `bin/n42/src/follower_import.rs::PARENT_OUTPUTS_KEPT` deep) rather than
/// reaching `historical`, the caller-supplied provider this overlay falls
/// through to.
///
/// `historical` is itself whatever `StateProviderFactory::state_by_block_hash`
/// returned -- on this chain, reth's engine in-memory state over the QMDB read
/// view when the view lags the chain (`reader_lag`, plan v6 6.4), which may be
/// another overlay of its own. That code is vendored reth
/// (`crates/storage/provider`, `reth-chain-state`), out of scope for this
/// counter: every read that does not land in `executed` is bucketed
/// `historical` without being decomposed further.
///
/// Off by default (an atomic load per call to check, nothing else); each
/// `basic_account` read costs one more atomic add when on.
pub mod read_depth {
    use super::*;

    /// Depth buckets: 0, 1, 2, 3, 4-7, 8-15, 16+, historical.
    pub const BUCKETS: usize = 8;
    const HISTORICAL: usize = BUCKETS - 1;

    fn bucket_of(depth: usize) -> usize {
        match depth {
            0..=3 => depth,
            4..=7 => 4,
            8..=15 => 5,
            _ => 6,
        }
    }

    static COUNTS: [AtomicU64; BUCKETS] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];
    static OVERLAY_DEPTH: AtomicU64 = AtomicU64::new(0);

    /// Whether `N42_READ_DEPTH_COUNTS=1` is set. Read once; the env var is
    /// not re-checked after the first call.
    pub fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var("N42_READ_DEPTH_COUNTS").is_ok_and(|v| v == "1"))
    }

    fn record(depth: usize) {
        COUNTS[bucket_of(depth)].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a read no executed block answered. `HISTORICAL` is a bucket
    /// index, not a depth: passing it through `bucket_of` would land it in
    /// the 4-7 bucket.
    fn record_historical() {
        COUNTS[HISTORICAL].fetch_add(1, Ordering::Relaxed);
    }

    /// Records the depth of `executed` an [`overlay_on_executed`] call was
    /// built with -- the number of executed blocks the overlay's own stack
    /// holds, before any read falls through to `historical` -- or `0` for a
    /// caller reading the engine's state directly, with no overlay at all.
    /// A no-op unless [`enabled`].
    pub fn note_overlay_depth(depth: usize) {
        if enabled() {
            OVERLAY_DEPTH.store(depth as u64, Ordering::Relaxed);
        }
    }

    /// The eight bucket counts and the last-seen overlay depth, summed since
    /// the previous snapshot: `(reads_d0, reads_d1, reads_d2, reads_d3,
    /// reads_d4_7, reads_d8_15, reads_d16p, reads_hist, overlay_depth)`. Reads
    /// and resets the counts; leaves `overlay_depth` (a gauge, not a counter)
    /// as it was.
    pub fn snapshot() -> [u64; BUCKETS] {
        let mut out = [0u64; BUCKETS];
        for (slot, counter) in out.iter_mut().zip(&COUNTS) {
            *slot = counter.swap(0, Ordering::Relaxed);
        }
        out
    }

    /// The overlay depth the most recent [`overlay_on_executed`] call was
    /// built with.
    pub fn overlay_depth() -> u64 {
        OVERLAY_DEPTH.load(Ordering::Relaxed)
    }

    /// The counting `StateProvider` [`overlay_on_executed`] returns under the
    /// flag: `basic_account` walks `executed` itself (the same newest-first
    /// order `MemoryOverlayStateProviderRef::basic_account` uses) to learn
    /// which depth answered, then falls through to `historical` unchanged.
    /// Every other method delegates to a fresh `MemoryOverlayStateProviderRef`
    /// built from the same two fields -- exactly what
    /// `MemoryOverlayStateProvider::as_ref` does -- so behaviour off the
    /// account-read path is unchanged.
    #[expect(missing_debug_implementations)]
    pub struct CountingStateProvider {
        pub(super) historical: StateProviderBox,
        pub(super) executed: Vec<ExecutedParent>,
    }

    impl CountingStateProvider {
        /// The overlay every method but `basic_account` delegates to, freshly
        /// built each call (as [`MemoryOverlayStateProvider::as_ref`] does)
        /// since `historical`'s borrow cannot be cached alongside it.
        fn as_ref(&self) -> MemoryOverlayStateProviderRef<'_, N42Primitives> {
            MemoryOverlayStateProviderRef::new(Box::new(self.historical.as_ref()), self.executed.clone())
        }
    }

    impl AccountReader for CountingStateProvider {
        fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
            for (depth, block) in self.executed.iter().enumerate() {
                if let Some(account) = block.execution_output.account(address) {
                    record(depth);
                    return Ok(account);
                }
            }
            record_historical();
            self.historical.basic_account(address)
        }
    }

    reth_storage_api::macros::delegate_impls_to_as_ref!(
        for CountingStateProvider =>
        BlockHashReader {
            fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>>;
            fn canonical_hashes_range(&self, start: BlockNumber, end: BlockNumber) -> ProviderResult<Vec<B256>>;
        }
        StateProvider {
            fn storage(&self, account: Address, storage_key: StorageKey) -> ProviderResult<Option<StorageValue>>;
        }
        BytecodeReader {
            fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>>;
        }
        StateRootProvider {
            fn state_root(&self, state: HashedPostState) -> ProviderResult<B256>;
            fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256>;
            fn state_root_with_updates(&self, state: HashedPostState) -> ProviderResult<(B256, TrieUpdates)>;
            fn state_root_from_nodes_with_updates(&self, input: TrieInput) -> ProviderResult<(B256, TrieUpdates)>;
        }
        StorageRootProvider {
            fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256>;
            fn storage_proof(&self, address: Address, slot: B256, storage: HashedStorage) -> ProviderResult<StorageProof>;
            fn storage_multiproof(&self, address: Address, slots: &[B256], storage: HashedStorage) -> ProviderResult<StorageMultiProof>;
        }
        StateProofProvider {
            fn proof(&self, input: TrieInput, address: Address, slots: &[B256]) -> ProviderResult<AccountProof>;
            fn multiproof(&self, input: TrieInput, targets: MultiProofTargets) -> ProviderResult<MultiProof>;
            fn multiproof_v2(&self, input: TrieInput, targets: reth_trie::MultiProofTargetsV2) -> ProviderResult<reth_trie::DecodedMultiProofV2>;
            fn witness(&self, input: TrieInput, target: HashedPostState, mode: ExecutionWitnessMode) -> ProviderResult<Vec<Bytes>>;
        }
        HashedPostStateProvider {
            fn hashed_post_state(&self, bundle_state: &BundleState) -> ProviderResult<HashedPostState>;
        }
    );
}

/// How long [`opener_on_built_parent`] waits for the grandparent to reach the
/// engine before giving up on the build.
///
/// The build chain (`N42_BUILD_CHAIN`) starts a build at its parent's early
/// seal, which on a leader with a tenure is *before* the engine has finished
/// importing the grandparent -- the block this node proposed one view ago.
/// Measured on loop193 W1b: 56 of 347 refused chained builds were exactly
/// this, and the block they named was added to the canonical chain a median
/// of 18 ms later (p90 68, max 209). Refusing costs the whole build and the
/// ~275 ms of lead it was for; waiting costs the wait. Bounded, because a
/// grandparent that is not coming must end as a refusal and not as a builder
/// thread that never returns.
const GRANDPARENT_WAIT: std::time::Duration = std::time::Duration::from_millis(150);

/// How often the wait looks again.
const GRANDPARENT_POLL: std::time::Duration = std::time::Duration::from_millis(2);

/// Where a build's open of its parent's state waited (`state_wait_on` on the
/// seal-first phases line): the parent's output (`StateReady` / the shards,
/// [`opener_on_sealed_parent`]), the state under it (the grandparent in the
/// engine, [`state_at_soon`]), and, when the grandparent was missing while the
/// parent finished, the parent's QMDB root and its `Complete`
/// ([`grandparent_state`]). Kept per thread: the build's open runs on the
/// builder's thread, which takes it before and after the open.
pub mod open_wait {
    use std::cell::Cell;

    /// One open's waits, in milliseconds.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct OpenWait {
        /// The parent's output filed (`built_executions::wait_for_state`).
        pub output_ms: u64,
        /// The state under the parent's output (the grandparent), first look
        /// and the bounded wait for its import.
        pub grandparent_ms: u64,
        /// How many times that wait looked again (2 ms apart).
        pub grandparent_polls: u32,
        /// The grandparent still missing: the wait for the parent's QMDB root
        /// and the look after it.
        pub parent_root_ms: u64,
        /// Still missing: the wait for the parent's `Complete` and the look after it.
        pub parent_complete_ms: u64,
        /// Opens that read the grandparent from its kept layer (its shards
        /// under its residual, or its filed bundle) over the engine's state
        /// at the great-grandparent instead of the grandparent in the engine
        /// (`N42_GRANDPARENT_SHARDS`, [`super::leader_layers`]).
        pub grandparent_layer: u32,
        /// Opens whose grandparent layer was kept but whose great-grandparent
        /// was not yet in the engine (a stall): they fell back to the wait
        /// for the grandparent in the engine.
        pub great_grandparent_missing: u32,
    }

    impl OpenWait {
        /// The largest of the waits, by name; `none` when every one is under
        /// a millisecond.
        pub fn label(&self) -> &'static str {
            [
                (self.output_ms, "output"),
                (self.grandparent_ms, "grandparent"),
                (self.parent_root_ms, "parent_root"),
                (self.parent_complete_ms, "parent_complete"),
            ]
            .into_iter()
            .filter(|(ms, _)| *ms > 0)
            .max_by_key(|(ms, _)| *ms)
            .map_or("none", |(_, name)| name)
        }

        /// `output/grandparent/parent_root/parent_complete` in ms, then the
        /// grandparent's polls, the opens on the grandparent's kept layer and
        /// the great-grandparent's misses.
        pub fn split(&self) -> String {
            format!(
                "{}/{}/{}/{} polls={} gp_layer={} ggp_missing={}",
                self.output_ms,
                self.grandparent_ms,
                self.parent_root_ms,
                self.parent_complete_ms,
                self.grandparent_polls,
                self.grandparent_layer,
                self.great_grandparent_missing
            )
        }
    }

    thread_local! {
        static WAIT: Cell<OpenWait> = const {
            Cell::new(OpenWait {
                output_ms: 0,
                grandparent_ms: 0,
                grandparent_polls: 0,
                parent_root_ms: 0,
                parent_complete_ms: 0,
                grandparent_layer: 0,
                great_grandparent_missing: 0,
            })
        };
    }

    pub(crate) fn add(f: impl FnOnce(&mut OpenWait)) {
        WAIT.with(|cell| {
            let mut wait = cell.get();
            f(&mut wait);
            cell.set(wait);
        });
    }

    /// This thread's waits since the last take, reset.
    pub fn take() -> OpenWait {
        WAIT.with(Cell::take)
    }
}

/// The state at `block`, waiting up to [`GRANDPARENT_WAIT`] for an import
/// that is already in flight to land.
///
/// Only "this node does not hold that state" is waited on; every other error
/// is the provider saying something is wrong, and waiting would only make the
/// build slower before it failed anyway.
fn state_at_soon<C>(client: &C, block: B256) -> ProviderResult<StateProviderBox>
where
    C: StateProviderFactory,
{
    let deadline = std::time::Instant::now() + GRANDPARENT_WAIT;
    loop {
        let err = match client.state_by_block_hash(block) {
            Ok(state) => return Ok(state),
            Err(err) => err,
        };
        if !matches!(err, reth_storage_api::errors::ProviderError::StateForHashNotFound(_))
            || std::time::Instant::now() >= deadline
        {
            return Err(err);
        }
        open_wait::add(|wait| wait.grandparent_polls += 1);
        std::thread::sleep(GRANDPARENT_POLL);
    }
}

/// The state at `grandparent` for a build on the sealed own parent filed
/// under `built_hash`: [`state_at_soon`], and when the grandparent is still
/// not in the engine while the parent's finish behind its seal is running,
/// once more after the parent's QMDB root is published, and once more after
/// that finish.
///
/// The grandparent is this node's own block, handed to the engine after its
/// own finish, and that hand-off can be held behind the parent's finish: on
/// loop278 IDX/IDXb and every `N42_OUTPUT_SHARDS` leg of loop276-277 the
/// grandparent's hand-off (`own block handed to the engine as executed`,
/// 590-640 ms) ended with the parent's slow QMDB roots (575-650 ms, every
/// ~44 blocks), where the ordinary hand-off takes ~40 ms -- with the shards
/// the parent's roots start at its seal, before the grandparent's hand-off
/// is through. The 150 ms wait then refused the chained build ("no state
/// found for block" the grandparent: 1-3 a leg on the leader, 0 on every
/// flag-off leg) and the leader lost the view (5-6 s, then a TC).
///
/// What held the hand-off is the QMDB forest's lock: the grandparent's rename
/// to its sealed hash (`chain_alias::rename`) waits for the parent's root job
/// (`compute_operations`) to let it go. So the first wait is for the parent's
/// root, published the moment that job ends (`executed_fields`) -- which this
/// build waits for anyway, its header carries the parent's execution
/// (`PARENT_FIELDS_WAIT`). Only if the grandparent is still missing then does
/// it wait for the parent's `Complete`, which since the shards' merge runs
/// behind the root's publication (BREAKTHROUGH_DESIGN 10.16) comes ~55 ms
/// later.
fn grandparent_state<C>(client: &C, grandparent: B256, built_hash: B256) -> ProviderResult<StateProviderBox>
where
    C: StateProviderFactory,
{
    use crate::built_executions::Stage;
    let finishing = || crate::built_executions::stage_of(built_hash).is_some_and(|stage| stage < Stage::Complete);
    let missing = |result: &ProviderResult<StateProviderBox>| {
        matches!(result, Err(reth_storage_api::errors::ProviderError::StateForHashNotFound(_)))
    };
    let first_at = std::time::Instant::now();
    let first = state_at_soon(client, grandparent);
    open_wait::add(|wait| wait.grandparent_ms += first_at.elapsed().as_millis() as u64);
    if !missing(&first) || !finishing() {
        return first;
    }
    let at = std::time::Instant::now();
    let _ = crate::executed_fields::wait_for(&built_hash, crate::hotstuff_consensus::PARENT_FIELDS_WAIT);
    let after_root = state_at_soon(client, grandparent);
    let root_ms = at.elapsed().as_millis() as u64;
    open_wait::add(|wait| wait.parent_root_ms += root_ms);
    if !missing(&after_root) || !finishing() {
        tracing::info!(
            target: "payload_builder",
            %grandparent,
            waited_ms = root_ms,
            found = after_root.is_ok(),
            "the grandparent was not in the engine; waited for the parent's QMDB root"
        );
        return after_root;
    }
    let complete_at = std::time::Instant::now();
    let _ = crate::built_executions::wait_for(built_hash, Stage::Complete);
    tracing::info!(
        target: "payload_builder",
        %grandparent,
        root_ms,
        waited_ms = at.elapsed().as_millis() as u64,
        "the grandparent was not in the engine; waited for the parent's QMDB root and finish"
    );
    let after_complete = state_at_soon(client, grandparent);
    open_wait::add(|wait| wait.parent_complete_ms += complete_at.elapsed().as_millis() as u64);
    after_complete
}

/// An opener for the parent's post-state: the chain's state at the
/// grandparent with the parent's bundle laid over it.
pub fn opener_on_built_parent<C>(client: C, grandparent: B256, executed: ExecutedBlock<N42Primitives>) -> ParentStateOpener
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    Arc::new(move || {
        let historical = state_at_soon(&client, grandparent)?;
        Ok(overlay_on_executed(historical, vec![executed.clone()]))
    })
}

/// An opener for a parent this node executed as a follower
/// ([`ParentExecution::Published`]): the published outputs, newest first,
/// over the chain's state at `anchor` -- the follower's own overlay
/// ([`overlay_on_executed`]), so the build reads exactly the state the
/// follower's execution of the parent produced.
pub fn opener_on_published_parent<C>(client: C, anchor: B256, executed: Vec<ExecutedParent>) -> ParentStateOpener
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    Arc::new(move || {
        let historical = state_at_soon(&client, anchor)?;
        Ok(overlay_on_executed(historical, executed.clone()))
    })
}

/// An opener for the parent's post-state on a build started at the parent's
/// seal (`N42_BUILD_ON_OUTPUT`): the parent's published output laid over the
/// chain's state at the grandparent -- the overlay of
/// [`opener_on_built_parent`] and of the follower's import -- with the output
/// waited for here, when the build first opens its state, rather than before
/// the build is started. Between the seal and `StateReady` the parent's
/// finish appends its ~147,000 reverts (`state_ready_ms` 15-19 on a full
/// block, loop223); the next build's queue hand-off and setup now run in
/// that time instead of after it.
///
/// The parent is laid under its sealed header with an empty body
/// ([`executed_from_output`]): the overlay reads the output and the header
/// only, so the body copy [`executed_under_seal`] makes (163,000
/// transactions, ~10 ms) is saved. The first open files the parent; every
/// later open (one per execution batch) reuses it.
pub fn opener_on_sealed_parent<C>(client: C, parent: SealedHeader, built_hash: B256) -> ParentStateOpener
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    opener_on_sealed_parent_with(client, parent, built_hash, leader_layers::enabled())
}

/// `N42_GRANDPARENT_SHARDS` (on by default; `0` turns it off): the chained
/// build reads its grandparent -- this node's own block two seals back --
/// from the layer the previous chained build opened its parent on (its frozen
/// shards under its residual, or its filed bundle), over the engine's state at
/// the great-grandparent, instead of waiting for the grandparent to reach the
/// engine (BREAKTHROUGH_DESIGN 10.40: that hand-off comes after the
/// grandparent's `Complete` and through the engine's loop, and in 22% of the
/// builds of loop293 P100 it was not there yet at the parent's seal:
/// `state_wait` 16-35 ms on the grandparent). The follower keeps the same two
/// generations (`FOLLOWER_SHARDS` in `bin/n42/src/follower_import.rs`).
///
/// The store holds two blocks' layers: the one a build just opened its parent
/// on, and that parent's parent -- the layer its own child will read as the
/// grandparent. Keeping a new parent drops every other entry, so the
/// great-grandparent's shards are released at the child's first open.
pub mod leader_layers {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    /// A block's post-state as a chained build reads it: the block under its
    /// sealed header with the bundle (the residual over the shards, or the
    /// filed full bundle), and the shards when it was filed as a shard set.
    pub type Layer = (ExecutedParent, Option<Arc<crate::output_shards::FrozenShards>>);

    static KEPT: Mutex<VecDeque<Layer>> = Mutex::new(VecDeque::new());

    /// Whether chained builds read their grandparent from its kept layer.
    pub fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("N42_GRANDPARENT_SHARDS").map_or(true, |v| v.trim() != "0"))
    }

    /// Keeps `layer` (the parent a build just opened on) and its own parent's
    /// layer, and releases every other block's.
    pub fn keep(layer: &Layer) {
        let hash = layer.0.recovered_block.hash();
        let parent_hash = layer.0.recovered_block.header().parent_hash;
        let released: Vec<Layer> = {
            let mut kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
            let (stay, released): (VecDeque<Layer>, VecDeque<Layer>) =
                std::mem::take(&mut *kept).into_iter().partition(|(executed, _)| executed.recovered_block.hash() == parent_hash);
            *kept = stay;
            kept.push_back(layer.clone());
            released.into_iter().filter(|(executed, _)| executed.recovered_block.hash() != hash).collect()
        };
        // The released shard sets (the last reference, usually) are dropped
        // here, after the lock.
        drop(released);
    }

    /// The kept layer of the block sealed as `hash`.
    pub fn find(hash: B256) -> Option<Layer> {
        KEPT.lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(executed, _)| executed.recovered_block.hash() == hash)
            .cloned()
    }

    /// How many blocks' layers are kept (at most two once the chain runs).
    pub fn len() -> usize {
        KEPT.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// `layers` (newest first) over `historical`: a block held as shards is a
    /// [`crate::output_shards::ShardLayer`] with its residual overlaid on
    /// top, consecutive bundles one overlay -- the follower's
    /// `open_on_layers`.
    pub fn open_on(historical: StateProviderBox, layers: &[Layer]) -> StateProviderBox {
        let mut state = historical;
        let mut pending: Vec<ExecutedParent> = Vec::new();
        for (executed, shards) in layers.iter().rev() {
            match shards {
                None => pending.insert(0, executed.clone()),
                Some(shards) => {
                    if !pending.is_empty() {
                        state = overlay_on_executed(state, std::mem::take(&mut pending));
                    }
                    let layer: StateProviderBox =
                        Box::new(crate::output_shards::ShardLayer::new(state, Arc::clone(shards)));
                    state = overlay_on_executed(layer, vec![executed.clone()]);
                }
            }
        }
        if pending.is_empty() { state } else { overlay_on_executed(state, pending) }
    }
}

/// [`opener_on_sealed_parent`] with [`leader_layers::enabled`] given.
fn opener_on_sealed_parent_with<C>(
    client: C,
    parent: SealedHeader,
    built_hash: B256,
    grandparent_layers: bool,
) -> ParentStateOpener
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    // The parent as filed, and (`N42_OUTPUT_SHARDS`) the shard set its
    // residual is laid over, when the shards came before `StateReady`.
    type Filed = leader_layers::Layer;
    let filed: Arc<OnceLock<Filed>> = Arc::new(OnceLock::new());
    // The grandparent's kept layer, looked up once at the first open.
    let grandparent: Arc<OnceLock<Option<Filed>>> = Arc::new(OnceLock::new());
    Arc::new(move || {
        let (executed, shards) = match filed.get() {
            Some(filed) => filed.clone(),
            None => {
                let at = std::time::Instant::now();
                let state = crate::built_executions::wait_for_state(built_hash);
                open_wait::add(|wait| wait.output_ms += at.elapsed().as_millis() as u64);
                let state =
                    state.ok_or(reth_storage_api::errors::ProviderError::StateForHashNotFound(parent.hash()))?;
                let sharded = matches!(state, crate::built_executions::ParentState::Sharded(_));
                tracing::debug!(
                    target: "payload_builder",
                    number = parent.number,
                    wait_ms = at.elapsed().as_millis() as u64,
                    sharded,
                    "the sealed parent's output is filed; the build opens its state on it"
                );
                filed
                    .get_or_init(|| match state {
                        crate::built_executions::ParentState::Full(execution) => {
                            (executed_from_output(&parent, execution.execution_output), None)
                        }
                        crate::built_executions::ParentState::Sharded(sharded) => {
                            (executed_from_output(&parent, sharded.residual), Some(sharded.shards))
                        }
                    })
                    .clone()
            }
        };
        let parent_layer: Filed = (executed, shards);
        let grandparent_layer = grandparent
            .get_or_init(|| {
                if !grandparent_layers {
                    return None;
                }
                leader_layers::keep(&parent_layer);
                leader_layers::find(parent.parent_hash)
            })
            .clone();
        // The grandparent from its kept layer over the engine's state at the
        // great-grandparent (three seals back, long committed); the engine's
        // grandparent when no layer was kept or the great-grandparent is not
        // in the engine yet (a stall: today's wait, counted).
        if let Some(grandparent_layer) = grandparent_layer {
            let great_grandparent = grandparent_layer.0.recovered_block.header().parent_hash;
            match client.state_by_block_hash(great_grandparent) {
                Ok(historical) => {
                    open_wait::add(|wait| wait.grandparent_layer += 1);
                    return Ok(leader_layers::open_on(historical, &[parent_layer, grandparent_layer]));
                }
                Err(reth_storage_api::errors::ProviderError::StateForHashNotFound(_)) => {
                    open_wait::add(|wait| wait.great_grandparent_missing += 1);
                    tracing::debug!(
                        target: "payload_builder",
                        number = parent.number,
                        %great_grandparent,
                        "the great-grandparent is not in the engine; the build opens on the engine's grandparent"
                    );
                }
                Err(err) => return Err(err),
            }
        }
        let historical = grandparent_state(&client, parent.parent_hash, built_hash)?;
        Ok(leader_layers::open_on(historical, &[parent_layer]))
    })
}

#[cfg(test)]
mod tests {
    //! The hazard of building on a block the engine has not imported: a state
    //! read that misses the parent's bundle and answers from the grandparent
    //! (a nonce one block stale refuses every transaction of that sender in
    //! the block being built), or a `BLOCKHASH` that answers the builder's
    //! hash instead of the one consensus sealed. A round lost to either would
    //! be the first on-seal block refusing 163,000 transactions.
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{Address, U256};
    use n42_tx_types::{Block, BlockBody};
    use reth_execution_types::BlockExecutionOutput;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::{AccountReader, BlockHashReader, StateProvider as _};
    use reth_trie::{updates::TrieUpdates, HashedPostState};
    use revm::{database::BundleState, state::AccountInfo};

    /// Serialises the tests that file builds in the process-wide stores.
    fn store_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::built_executions::STORE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn execution_of(header: &Header, bundle: BundleState) -> BuiltExecution {
        let block = Block { header: header.clone(), body: BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: Some(Vec::new().into()) } };
        BuiltExecution {
            block: Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), Vec::new())),
            execution_output: Arc::new(BlockExecutionOutput { result: Default::default(), state: bundle }),
            hashed_state: Arc::new(HashedPostState::default()),
            trie_updates: Arc::new(TrieUpdates::default()),
        }
    }

    #[test]
    fn the_parent_state_is_its_bundle_over_the_grandparent_under_the_sealed_hash() {
        let _store = store_lock();
        let sender = Address::with_last_byte(1);
        let created = Address::with_last_byte(2);
        let untouched = Address::with_last_byte(3);
        let grandparent = B256::with_last_byte(9);

        // The chain's state at the grandparent: the sender at nonce 0, an
        // account the parent never touches, and no `created` yet.
        let client = MockEthProvider::default();
        client.add_account(sender, ExtendedAccount::new(0, U256::from(100)));
        client.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));

        // The parent as the builder executed it: the sender moved to nonce 5,
        // `created` came into being.
        let bundle = BundleState::builder(11..=11)
            .state_present_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(50), ..Default::default() })
            .state_present_account_info(created, AccountInfo { nonce: 0, balance: U256::from(7), ..Default::default() })
            .build();
        let header = Header { number: 11, parent_hash: grandparent, gas_used: 21_000, ..Default::default() };
        let execution = execution_of(&header, bundle);
        let built_hash = execution.block.hash();

        // Consensus seals the header (the view and the signature go into
        // `extra_data`), so the hash the chain knows is not the builder's.
        let sealed = SealedHeader::seal_slow(Header { extra_data: b"view 7".as_slice().into(), ..header.clone() });
        assert_ne!(sealed.hash(), built_hash);

        // The registry finds the build by what a seal cannot change.
        crate::built_executions::remember(built_hash, execution.clone());
        let (found, _) = crate::built_executions::find(grandparent, 11, header.state_root, header.receipts_root, 21_000, None)
            .expect("the build is found under the sealed header's parent, number, roots and gas");
        assert_eq!(found, built_hash);
        // The own-block import takes the build; the build on the sealed block
        // must still find it, whichever request the execution layer served first.
        let (taken, _) = crate::built_executions::take(grandparent, 11, header.state_root, header.receipts_root, 21_000, None).expect("taken");
        assert_eq!(taken, built_hash);
        assert!(crate::built_executions::find(grandparent, 11, header.state_root, header.receipts_root, 21_000, None).is_none());
        let (kept, _) = crate::built_executions::find_kept(grandparent, 11, header.state_root, header.receipts_root, 21_000, None)
            .expect("a taken build is still there for the build on the sealed block");
        assert_eq!(kept, built_hash);

        let executed = executed_under_seal(&sealed, &execution);
        assert_eq!(executed.recovered_block.hash(), sealed.hash(), "the overlay's block carries the sealed hash");
        assert_eq!(executed.recovered_block.header().number, 11);

        let state = opener_on_built_parent(client, grandparent, executed)().expect("the parent's state opens");
        let account = |a: &Address| state.basic_account(a).expect("read");
        assert_eq!(account(&sender).map(|a| a.nonce), Some(5), "the sender's nonce is the parent's, not the grandparent's");
        assert_eq!(account(&sender).map(|a| a.balance), Some(U256::from(50)));
        assert_eq!(account(&created).map(|a| a.balance), Some(U256::from(7)), "an account the parent created exists");
        assert_eq!(account(&untouched).map(|a| a.nonce), Some(4), "an untouched account reads through to the grandparent");
        assert_eq!(state.block_hash(11).expect("read"), Some(sealed.hash()), "BLOCKHASH of the parent is the sealed hash");
    }

    /// The same hazard on the follower's side: a block executed on its
    /// parent's published output must read the parent's post-state, not the
    /// grandparent's -- and must do so with the empty hashed post-state an
    /// import produces under `N42_HASHED_TABLES=off`, which is what makes the
    /// overlay usable there at all.
    #[test]
    fn a_read_on_the_parents_output_sees_its_post_state_with_an_empty_hashed_state() {
        let sender = Address::with_last_byte(1);
        let created = Address::with_last_byte(2);
        let untouched = Address::with_last_byte(3);
        let grandparent = B256::with_last_byte(9);

        // The chain's state at the grandparent, which is what the engine's
        // tree can answer while the parent is still being imported.
        let client = MockEthProvider::default();
        client.add_account(sender, ExtendedAccount::new(4, U256::from(100)));
        client.add_account(untouched, ExtendedAccount::new(1, U256::from(40)));

        // The parent as the follower's import executed it.
        let bundle = BundleState::builder(12..=12)
            .state_present_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(60), ..Default::default() })
            .state_present_account_info(created, AccountInfo { nonce: 0, balance: U256::from(7), ..Default::default() })
            .build();
        let parent = SealedHeader::seal_slow(Header {
            number: 12,
            parent_hash: grandparent,
            extra_data: b"view 9".as_slice().into(),
            ..Default::default()
        });
        let output = Arc::new(BlockExecutionOutput { result: Default::default(), state: bundle });

        let executed = executed_from_output(&parent, output);
        assert!(executed.trie_data.hashed_state().is_empty(), "an import under N42_HASHED_TABLES=off publishes no hashed state");
        assert_eq!(executed.recovered_block.hash(), parent.hash(), "the overlay's block carries the hash consensus sealed");

        let state = overlay_on_executed(client.state_by_block_hash(grandparent).expect("the grandparent's state"), vec![executed]);
        let account = |a: &Address| state.basic_account(a).expect("read");
        assert_eq!(account(&sender).map(|a| a.nonce), Some(5), "the nonce the parent advanced, not the grandparent's 4");
        assert_eq!(account(&sender).map(|a| a.balance), Some(U256::from(60)));
        assert_eq!(account(&created).map(|a| a.balance), Some(U256::from(7)), "an account the parent created exists");
        assert_eq!(account(&untouched).map(|a| a.nonce), Some(1), "an untouched account reads through to the grandparent");
        assert_eq!(state.block_hash(12).expect("read"), Some(parent.hash()), "BLOCKHASH of the parent is the sealed hash");
    }

    /// Two published outputs stacked -- a follower whose parent's engine
    /// insert has not run *and* whose grandparent's has not either, which is
    /// the state of a node one cycle behind under load.
    ///
    /// What the execution rests on is that reading through both is the state
    /// the engine would hold after importing both: the newest bundle that
    /// touched an account answers for it, the older one answers for what only
    /// it touched, and everything else falls through to the ancestor. This
    /// compares the two readers account by account and slot by slot, so a
    /// block executed on the stack executes on the same inputs -- and produces
    /// the same bytes -- as one executed on the engine's tree.
    ///
    /// Storage is compared through `unwrap_or_default`: a destroyed account's
    /// slot reads `Some(0)` from a bundle (`BundleAccount::storage_slot`, the
    /// status carries "storage known") and `None` from a state that no longer
    /// has the account, and both are the zero revm reads.
    #[test]
    fn two_stacked_outputs_read_as_the_state_after_both() {
        let both = Address::with_last_byte(1);
        let only_older = Address::with_last_byte(2);
        let only_newer = Address::with_last_byte(3);
        let made_then_destroyed = Address::with_last_byte(4);
        let untouched = Address::with_last_byte(5);
        let slot = |n: u64| B256::from(U256::from(n));
        let anchor_hash = B256::with_last_byte(0x0a);

        // The chain's state at the nearest ancestor the engine holds.
        let anchor = MockEthProvider::default();
        anchor.add_account(
            both,
            ExtendedAccount::new(1, U256::from(100)).extend_storage([(slot(1), U256::from(10)), (slot(3), U256::from(33))]),
        );
        anchor.add_account(only_older, ExtendedAccount::new(5, U256::from(50)));
        anchor.add_account(only_newer, ExtendedAccount::new(7, U256::from(70)));
        anchor.add_account(untouched, ExtendedAccount::new(9, U256::from(9)));

        // The older of the two imports: block 11 on the anchor.
        let older_bundle = BundleState::new(
            [
                (
                    both,
                    Some(AccountInfo { nonce: 1, balance: U256::from(100), ..Default::default() }),
                    Some(AccountInfo { nonce: 2, balance: U256::from(90), ..Default::default() }),
                    [(U256::from(1), (U256::from(10), U256::from(11)))].into_iter().collect(),
                ),
                (
                    only_older,
                    Some(AccountInfo { nonce: 5, balance: U256::from(50), ..Default::default() }),
                    Some(AccountInfo { nonce: 6, balance: U256::from(40), ..Default::default() }),
                    Default::default(),
                ),
                (
                    made_then_destroyed,
                    None,
                    Some(AccountInfo { nonce: 0, balance: U256::from(5), ..Default::default() }),
                    Default::default(),
                ),
            ],
            Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
            Vec::new(),
        );
        // The newer: block 12 on it.
        let newer_bundle = BundleState::new(
            [
                (
                    both,
                    Some(AccountInfo { nonce: 2, balance: U256::from(90), ..Default::default() }),
                    Some(AccountInfo { nonce: 3, balance: U256::from(80), ..Default::default() }),
                    [(U256::from(2), (U256::ZERO, U256::from(22)))].into_iter().collect(),
                ),
                (
                    only_newer,
                    Some(AccountInfo { nonce: 7, balance: U256::from(70), ..Default::default() }),
                    Some(AccountInfo { nonce: 8, balance: U256::from(60), ..Default::default() }),
                    Default::default(),
                ),
                (
                    made_then_destroyed,
                    Some(AccountInfo { nonce: 0, balance: U256::from(5), ..Default::default() }),
                    None,
                    Default::default(),
                ),
            ],
            Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
            Vec::new(),
        );

        let older = SealedHeader::seal_slow(Header {
            number: 11,
            parent_hash: anchor_hash,
            extra_data: b"view 11".as_slice().into(),
            ..Default::default()
        });
        let newer = SealedHeader::seal_slow(Header {
            number: 12,
            parent_hash: older.hash(),
            extra_data: b"view 12".as_slice().into(),
            ..Default::default()
        });
        let executed_older =
            executed_from_output(&older, Arc::new(BlockExecutionOutput { result: Default::default(), state: older_bundle }));
        let executed_newer =
            executed_from_output(&newer, Arc::new(BlockExecutionOutput { result: Default::default(), state: newer_bundle }));
        // Newest first, which is the order the overlay reads them in.
        let stacked = overlay_on_executed(
            anchor.state_by_block_hash(anchor_hash).expect("the ancestor's state"),
            vec![executed_newer, executed_older],
        );

        // The serial path: the same two blocks imported into the engine, so
        // the state a block after them would be executed on.
        let after_both = MockEthProvider::default();
        after_both.add_account(
            both,
            ExtendedAccount::new(3, U256::from(80)).extend_storage([
                (slot(1), U256::from(11)),
                (slot(2), U256::from(22)),
                (slot(3), U256::from(33)),
            ]),
        );
        after_both.add_account(only_older, ExtendedAccount::new(6, U256::from(40)));
        after_both.add_account(only_newer, ExtendedAccount::new(8, U256::from(60)));
        after_both.add_account(untouched, ExtendedAccount::new(9, U256::from(9)));
        let serial = after_both.state_by_block_hash(anchor_hash).expect("the state after both blocks");

        for address in [both, only_older, only_newer, made_then_destroyed, untouched] {
            assert_eq!(
                stacked.basic_account(&address).expect("read"),
                serial.basic_account(&address).expect("read"),
                "account {address} read through the stack is the account after both blocks"
            );
            for n in 1..=3 {
                assert_eq!(
                    stacked.storage(address, slot(n)).expect("read").unwrap_or_default(),
                    serial.storage(address, slot(n)).expect("read").unwrap_or_default(),
                    "slot {n} of {address} read through the stack is the slot after both blocks"
                );
            }
        }
        // And BLOCKHASH answers for both of them, not only the parent.
        assert_eq!(stacked.block_hash(12).expect("read"), Some(newer.hash()));
        assert_eq!(stacked.block_hash(11).expect("read"), Some(older.hash()));
    }

    /// What stacking a second published output costs a read, at the shape a
    /// fleet block has: two blocks of 150,000 changed accounts, and a reader
    /// that looks up 6,000 senders -- the number an includability check and a
    /// block's execution read.
    ///
    /// Three populations, because the stack is only paid for on a miss: a
    /// sender the newest block moved (answered by the first bundle), one only
    /// the older block moved (the second), and one neither moved (through to
    /// the ancestor's state). The merge that composing avoids is timed beside
    /// them: `BundleState::extend` of two 150,000-account bundles is the
    /// alternative this path did not take.
    ///
    /// `cargo test -p n42-engine-types --lib
    /// direct_build::tests::bench_stacked_overlay_reads -- --ignored --nocapture`
    #[test]
    #[ignore = "timing"]
    fn bench_stacked_overlay_reads() {
        use std::time::Instant;

        const CHANGED: u64 = 150_000;
        const READS: u64 = 6_000;
        let address = |group: u8, i: u64| {
            let mut bytes = [0u8; 20];
            bytes[0] = group;
            bytes[12..].copy_from_slice(&i.to_be_bytes());
            Address::from(bytes)
        };
        let info = |nonce: u64| AccountInfo { nonce, balance: U256::from(1_000u64), ..Default::default() };
        // Group 1 is the newest block's, group 2 the older block's, group 3
        // neither's -- and group 3 is what the ancestor's state answers.
        let bundle_of = |group: u8, nonce: u64| {
            BundleState::new(
                (0..CHANGED).map(|i| (address(group, i), None, Some(info(nonce)), Default::default())),
                Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
                Vec::new(),
            )
        };
        let newer_bundle = bundle_of(1, 7);
        let older_bundle = bundle_of(2, 9);

        let client = MockEthProvider::default();
        for i in 0..READS {
            client.add_account(address(3, i), ExtendedAccount::new(1, U256::from(5u64)));
        }
        let anchor = B256::with_last_byte(0x0a);
        let header = |number: u64, parent: B256| {
            SealedHeader::seal_slow(Header { number, parent_hash: parent, ..Default::default() })
        };
        let older = header(11, anchor);
        let newer = header(12, older.hash());
        let executed = |head: &SealedHeader, bundle: BundleState| {
            executed_from_output(head, Arc::new(BlockExecutionOutput { result: Default::default(), state: bundle }))
        };

        let one = overlay_on_executed(
            client.state_by_block_hash(anchor).expect("state"),
            vec![executed(&newer, newer_bundle.clone())],
        );
        let two = overlay_on_executed(
            client.state_by_block_hash(anchor).expect("state"),
            vec![executed(&newer, newer_bundle.clone()), executed(&older, older_bundle.clone())],
        );

        let read = |state: &StateProviderBox, group: u8| {
            let at = Instant::now();
            let mut found = 0u64;
            for i in 0..READS {
                if state.basic_account(&address(group, i)).expect("read").is_some() {
                    found += 1;
                }
            }
            (at.elapsed().as_micros() as f64 / READS as f64 * 1000.0, found)
        };
        for (name, state) in [("one output", &one), ("two outputs", &two)] {
            for group in 1..=3u8 {
                let (ns, found) = read(state, group);
                println!("{name}, group {group}: {ns:.0} ns a read, {found} of {READS} found");
            }
        }
        let merge_at = Instant::now();
        let mut merged = older_bundle.clone();
        merged.extend(newer_bundle.clone());
        println!(
            "merging the two bundles instead: {} ms for {} accounts",
            merge_at.elapsed().as_millis(),
            merged.state.len()
        );
    }

    /// The per-depth cost `read_depth` (plan v6 6.4) exists to explain: a
    /// single `basic_account` walking a stack of 1 executed block against one
    /// walking 20, on an otherwise idle box, every read missing every block
    /// so it pays the whole walk before falling through to `historical` --
    /// the worst case, and the one `reader_lag` puts most of a fleet block's
    /// reads through if the overlay's own depth is where the leader's 65 ms
    /// and the follower's 65-70 ms of groups (plan v6 6.4) are spent.
    ///
    /// `cargo test -p n42-engine-types --lib
    /// direct_build::tests::bench_read_depth_1_vs_20 -- --ignored --nocapture`
    #[test]
    #[ignore = "timing"]
    fn bench_read_depth_1_vs_20() {
        use std::time::Instant;

        const READS: u64 = 100_000;
        let address = |i: u64| {
            let mut bytes = [0u8; 20];
            bytes[12..].copy_from_slice(&i.to_be_bytes());
            Address::from(bytes)
        };
        let info = || AccountInfo { nonce: 1, balance: U256::from(1u64), ..Default::default() };

        // Each stacked block touches its own disjoint 10 accounts, well clear
        // of the `READS` addresses read below -- every read misses every
        // block in the stack and falls through to `historical`, the walk
        // this bench times.
        let stack_of = |depth: usize| -> Vec<ExecutedParent> {
            (0..depth)
                .map(|d| {
                    let header = SealedHeader::seal_slow(Header { number: (d + 1) as u64, ..Default::default() });
                    let bundle = BundleState::new(
                        (0..10u64).map(|i| (address(10_000_000 + d as u64 * 10 + i), None, Some(info()), Default::default())),
                        Vec::<Vec<(Address, Option<Option<AccountInfo>>, Vec<(U256, U256)>)>>::new(),
                        Vec::new(),
                    );
                    executed_from_output(&header, Arc::new(BlockExecutionOutput { result: Default::default(), state: bundle }))
                })
                .collect()
        };

        let client = MockEthProvider::default();
        for i in 0..READS {
            client.add_account(address(i), ExtendedAccount::new(1, U256::from(5u64)));
        }
        let anchor = B256::with_last_byte(0x99);

        let bench = |depth: usize| {
            let historical = client.state_by_block_hash(anchor).expect("state");
            let state =
                Box::new(MemoryOverlayStateProvider::<N42Primitives>::new(historical, stack_of(depth))) as StateProviderBox;
            let at = Instant::now();
            let mut found = 0u64;
            for i in 0..READS {
                if state.basic_account(&address(i)).expect("read").is_some() {
                    found += 1;
                }
            }
            let ns_per_read = at.elapsed().as_nanos() as f64 / READS as f64;
            println!("depth {depth}: {ns_per_read:.0} ns a read, {found} of {READS} found through `historical`");
        };
        bench(1);
        bench(20);
    }

    /// Attempt J (`N42_BUILD_ON_OUTPUT`): a build started at its parent's
    /// seal, before the parent's output is filed, must open exactly the state
    /// the ordinary path opens at `StateReady` -- and the state the engine
    /// holds once the parent is installed. A build reads nothing of its
    /// parent but that state and `BLOCKHASH`, so equal reads are an equal
    /// block and equal roots; this compares the three readers on every
    /// account the parent touched, one it did not, and the parent's hash.
    #[test]
    fn a_build_started_at_the_seal_opens_the_state_the_ordinary_path_opens() {
        let _store = store_lock();
        let sender = Address::with_last_byte(0x31);
        let created = Address::with_last_byte(0x32);
        let untouched = Address::with_last_byte(0x33);
        let grandparent = B256::with_last_byte(0x3a);
        let grandparent_state = || {
            let client = MockEthProvider::default();
            client.add_account(sender, ExtendedAccount::new(0, U256::from(100)));
            client.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));
            client
        };
        // The engine's state once the parent is installed.
        let installed = MockEthProvider::default();
        installed.add_account(sender, ExtendedAccount::new(5, U256::from(50)));
        installed.add_account(created, ExtendedAccount::new(0, U256::from(7)));
        installed.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));

        let bundle = BundleState::builder(41..=41)
            .state_present_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(50), ..Default::default() })
            .state_present_account_info(created, AccountInfo { nonce: 0, balance: U256::from(7), ..Default::default() })
            .build();
        let header = Header { number: 41, parent_hash: grandparent, gas_used: 41_000, ..Default::default() };
        let execution = execution_of(&header, bundle);
        let built_hash = execution.block.hash();
        let sealed = SealedHeader::seal_slow(Header { extra_data: b"view 41".as_slice().into(), ..header.clone() });

        // Sealed, its output not yet filed: found at once, without an execution.
        crate::built_executions::remember_pending(built_hash, execution.block.clone());
        let (found, _, filed) =
            crate::built_executions::find_kept_sealed(grandparent, 41, header.state_root, header.receipts_root, 41_000, None)
                .expect("a sealed build is found before its state is ready");
        assert_eq!(found, built_hash);
        assert!(filed.is_none(), "nothing is filed at the seal");

        // The finish files the output a moment later, while the opener waits.
        let finish = {
            let execution = execution.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                crate::built_executions::state_ready(built_hash, execution);
            })
        };
        let on_seal = opener_on_sealed_parent_with(grandparent_state(), sealed.clone(), built_hash, false)()
            .expect("the parent's state opens once its output is filed");
        finish.join().expect("the finish thread");
        let ordinary = opener_on_built_parent(grandparent_state(), grandparent, executed_under_seal(&sealed, &execution))()
            .expect("the ordinary opener");
        let installed = installed.state_by_block_hash(B256::ZERO).expect("the installed state");

        for address in [sender, created, untouched, Address::with_last_byte(0x34)] {
            let read = |state: &StateProviderBox| state.basic_account(&address).expect("read");
            assert_eq!(read(&on_seal), read(&ordinary), "{address}: the seal's opener reads as the ordinary one");
            assert_eq!(read(&on_seal), read(&installed), "{address}: and as the installed state");
        }
        assert_eq!(on_seal.block_hash(41).expect("read"), Some(sealed.hash()), "BLOCKHASH is the sealed hash");
        assert_eq!(on_seal.block_hash(41).expect("read"), ordinary.block_hash(41).expect("read"));
        // A second open (one per execution batch) reuses the filed parent.
        let again = opener_on_sealed_parent_with(grandparent_state(), sealed, built_hash, false)().expect("opens again");
        assert_eq!(again.basic_account(&sender).expect("read").map(|a| a.nonce), Some(5));
    }

    /// `N42_OUTPUT_SHARDS`: the parent's output as its shard set with the
    /// executor's own changes over it, filed before `StateReady`, opens the
    /// state the merged bundle does -- the executor's newer value first (a
    /// withdrawal to a sender), the shards next, the grandparent last.
    #[test]
    fn a_build_on_the_parents_shards_reads_its_post_state() {
        // The store of builds keeps three and is process-wide: without this
        // lock a parallel test's filing can evict this build before it opens.
        let _store = store_lock();
        let sender = Address::with_last_byte(0x41);
        let created = Address::with_last_byte(0x42);
        let untouched = Address::with_last_byte(0x43);
        let grandparent = B256::with_last_byte(0x4a);
        let grandparent_state = || {
            let client = MockEthProvider::default();
            client.add_account(sender, ExtendedAccount::new(0, U256::from(100)));
            client.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));
            client
        };
        let batch = BundleState::builder(42..=42)
            .state_original_account_info(sender, AccountInfo { nonce: 0, balance: U256::from(100), ..Default::default() })
            .state_present_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(50), ..Default::default() })
            .state_present_account_info(created, AccountInfo { nonce: 0, balance: U256::from(7), ..Default::default() })
            .build();
        let shards = crate::output_shards::OutputShards::new(Address::with_last_byte(0x01), 2, 16);
        shards.add(batch);
        let shards = std::sync::Arc::new(shards.freeze());
        let residual = BundleState::builder(42..=42)
            .state_original_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(50), ..Default::default() })
            .state_present_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(55), ..Default::default() })
            .build();
        let header = Header { number: 42, parent_hash: grandparent, gas_used: 42_000, ..Default::default() };
        let execution = execution_of(&header, residual);
        let built_hash = execution.block.hash();
        let sealed = SealedHeader::seal_slow(Header { extra_data: b"view 42".as_slice().into(), ..header.clone() });
        crate::built_executions::remember_pending(built_hash, execution.block.clone());
        crate::built_executions::shards_ready(
            built_hash,
            crate::built_executions::ShardedParent { residual: execution.execution_output.clone(), shards },
        );
        let on_shards = opener_on_sealed_parent_with(grandparent_state(), sealed.clone(), built_hash, false)()
            .expect("the parent's state opens on its shards");
        let read = |address: Address| {
            on_shards.basic_account(&address).expect("read").map(|a| (a.nonce, a.balance))
        };
        assert_eq!(read(sender), Some((5, U256::from(55))), "the executor's change over the shard's");
        assert_eq!(read(created), Some((0, U256::from(7))), "the shard's account");
        assert_eq!(read(untouched), Some((4, U256::from(40))), "the grandparent's");
        assert_eq!(read(Address::with_last_byte(0x44)), None);
        assert_eq!(on_shards.block_hash(42).expect("read"), Some(sealed.hash()), "BLOCKHASH is the sealed hash");
    }

    /// `N42_GRANDPARENT_SHARDS`, in index mode: a chain of three own blocks
    /// -- the great-grandparent in the engine, the grandparent and the parent
    /// each filed as index shards under a residual. The child's open through
    /// both kept layers over the engine's great-grandparent must read what the
    /// open through the parent's shards over the engine's *grandparent* reads:
    /// an account only the grandparent wrote (and its slot), one only the
    /// parent wrote, one both residuals touched, an untouched one and an
    /// absent one.
    #[test]
    fn the_grandparents_shards_read_as_the_engines_grandparent() {
        let _store = store_lock();
        let from_gp = Address::with_last_byte(0x51);
        let from_parent = Address::with_last_byte(0x52);
        let coinbase = Address::with_last_byte(0x53);
        let untouched = Address::with_last_byte(0x54);
        let slot = B256::with_last_byte(7);
        let great_grandparent = B256::with_last_byte(0x5a);
        let info = |nonce: u64, balance: u64| AccountInfo { nonce, balance: U256::from(balance), ..Default::default() };
        // The engine at the great-grandparent, and at the grandparent (the
        // same plus the grandparent's writes): `MockEthProvider` answers any
        // hash with its one state, so each stands for the engine at one block.
        let engine_at_ggp = || {
            let client = MockEthProvider::default();
            client.add_account(from_gp, ExtendedAccount::new(1, U256::from(10)).extend_storage([(slot, U256::from(3))]));
            client.add_account(from_parent, ExtendedAccount::new(3, U256::from(30)));
            client.add_account(coinbase, ExtendedAccount::new(0, U256::from(1)));
            client.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));
            client
        };
        let engine_at_gp = || {
            let client = engine_at_ggp();
            client.add_account(from_gp, ExtendedAccount::new(2, U256::from(20)).extend_storage([(slot, U256::from(9))]));
            client.add_account(coinbase, ExtendedAccount::new(0, U256::from(2)));
            client
        };
        let shards_of = |bundle: BundleState| {
            let shards = crate::output_shards::OutputShards::with_index_live(Address::with_last_byte(0x01), 4, 16, true, true);
            shards.add(bundle);
            Arc::new(shards.freeze())
        };
        // One own block: sealed, its shards and residual filed.
        let file = |number: u64, parent_hash: B256, batch: BundleState, residual: BundleState| {
            let header = Header { number, parent_hash, gas_used: number * 1_000, ..Default::default() };
            let execution = execution_of(&header, residual);
            let built_hash = execution.block.hash();
            let sealed = SealedHeader::seal_slow(Header { extra_data: format!("view {number}").into_bytes().into(), ..header });
            crate::built_executions::remember_pending(built_hash, execution.block.clone());
            crate::built_executions::shards_ready(
                built_hash,
                crate::built_executions::ShardedParent {
                    residual: execution.execution_output.clone(),
                    shards: shards_of(batch),
                },
            );
            (sealed, built_hash)
        };
        let (gp_sealed, gp_built) = file(
            51,
            great_grandparent,
            BundleState::builder(51..=51)
                .state_original_account_info(from_gp, info(1, 10))
                .state_present_account_info(from_gp, info(2, 20))
                .state_storage(from_gp, [(U256::from(7), (U256::from(3), U256::from(9)))].into_iter().collect())
                .build(),
            BundleState::builder(51..=51)
                .state_original_account_info(coinbase, info(0, 1))
                .state_present_account_info(coinbase, info(0, 2))
                .build(),
        );
        // The parent's build opened on the grandparent: that keeps its layer.
        // (Each open follows its filing at once: the store of builds keeps
        // three, and the crate's other tests file theirs in parallel.)
        opener_on_sealed_parent_with(engine_at_ggp(), gp_sealed.clone(), gp_built, true)()
            .expect("the grandparent's child opens");
        assert!(leader_layers::find(gp_sealed.hash()).is_some(), "the grandparent's layer is kept");
        let (p_sealed, p_built) = file(
            52,
            gp_sealed.hash(),
            BundleState::builder(52..=52)
                .state_original_account_info(from_parent, info(3, 30))
                .state_present_account_info(from_parent, info(4, 31))
                .build(),
            BundleState::builder(52..=52)
                .state_original_account_info(coinbase, info(0, 2))
                .state_present_account_info(coinbase, info(0, 3))
                .build(),
        );
        let _ = open_wait::take();
        // The child: both layers over the engine's great-grandparent.
        let layered = opener_on_sealed_parent_with(engine_at_ggp(), p_sealed.clone(), p_built, true)()
            .expect("the child opens on the two layers");
        let wait = open_wait::take();
        assert_eq!((wait.grandparent_layer, wait.great_grandparent_missing), (1, 0), "{}", wait.split());
        assert_eq!(wait.grandparent_ms, 0, "the engine's grandparent was not waited for");
        assert!(leader_layers::len() <= 2, "two blocks' layers at most");
        // Today's path: the parent's shards over the engine's grandparent.
        let direct = opener_on_sealed_parent_with(engine_at_gp(), p_sealed.clone(), p_built, false)()
            .expect("the child opens on the engine's grandparent");

        let read = |state: &StateProviderBox, address: Address| {
            state.basic_account(&address).expect("read").map(|a| (a.nonce, a.balance))
        };
        for address in [from_gp, from_parent, coinbase, untouched, Address::with_last_byte(0x55)] {
            assert_eq!(read(&layered, address), read(&direct, address), "{address}: the layers read as the engine's grandparent");
        }
        assert_eq!(read(&layered, from_gp), Some((2, U256::from(20))), "the grandparent's write");
        assert_eq!(read(&layered, from_parent), Some((4, U256::from(31))), "the parent's write");
        assert_eq!(read(&layered, coinbase), Some((0, U256::from(3))), "the parent's residual over the grandparent's");
        assert_eq!(read(&layered, untouched), Some((4, U256::from(40))), "the great-grandparent's");
        let storage = |state: &StateProviderBox| state.storage(from_gp, slot).expect("read");
        assert_eq!(storage(&layered), storage(&direct));
        assert_eq!(storage(&layered), Some(U256::from(9)), "the grandparent's slot");
        assert_eq!(layered.block_hash(52).expect("read"), Some(p_sealed.hash()), "BLOCKHASH of the parent");
        assert_eq!(layered.block_hash(52).expect("read"), direct.block_hash(52).expect("read"));
        assert_eq!(layered.block_hash(51).expect("read"), Some(gp_sealed.hash()), "BLOCKHASH of the grandparent");
    }

    #[test]
    fn the_largest_open_wait_names_the_open_and_a_take_resets_it() {
        use super::open_wait::{self, OpenWait};
        assert_eq!(OpenWait::default().label(), "none");
        open_wait::add(|wait| wait.output_ms += 3);
        open_wait::add(|wait| {
            wait.grandparent_ms += 150;
            wait.grandparent_polls += 60;
        });
        open_wait::add(|wait| wait.parent_root_ms += 40);
        let wait = open_wait::take();
        assert_eq!(wait.label(), "grandparent");
        assert_eq!(wait.split(), "3/150/40/0 polls=60 gp_layer=0 ggp_missing=0");
        assert_eq!(open_wait::take(), OpenWait::default());
    }

    // ---- helpers over a provider whose answers can be scripted ----

    use reth_storage_api::errors::ProviderError;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    /// A provider that answers every state request from one mock state, except
    /// that `state_by_block_hash` can be told to miss: a number of times, for
    /// named hashes until `released`, or with a fatal error.
    struct Scripted {
        inner: MockEthProvider,
        /// Misses served first, whatever the hash.
        flaky_first: AtomicUsize,
        /// Hashes that miss until `released` is set.
        missing: HashSet<B256>,
        /// Hashes that fail with an error that is not a miss.
        fatal: HashSet<B256>,
        released: Arc<AtomicBool>,
        calls: AtomicUsize,
    }

    impl Scripted {
        fn new(inner: MockEthProvider) -> Self {
            Self {
                inner,
                flaky_first: AtomicUsize::new(0),
                missing: HashSet::new(),
                fatal: HashSet::new(),
                released: Arc::new(AtomicBool::new(false)),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl BlockHashReader for Scripted {
        fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
            Ok(None)
        }
        fn canonical_hashes_range(&self, _start: u64, _end: u64) -> ProviderResult<Vec<B256>> {
            Ok(Vec::new())
        }
    }

    impl reth_storage_api::BlockNumReader for Scripted {
        fn chain_info(&self) -> ProviderResult<reth_chainspec::ChainInfo> {
            Ok(Default::default())
        }
        fn best_block_number(&self) -> ProviderResult<u64> {
            Ok(0)
        }
        fn last_block_number(&self) -> ProviderResult<u64> {
            Ok(0)
        }
        fn block_number(&self, _hash: B256) -> ProviderResult<Option<u64>> {
            Ok(None)
        }
    }

    impl reth_storage_api::BlockIdReader for Scripted {
        fn pending_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> {
            Ok(None)
        }
        fn safe_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> {
            Ok(None)
        }
        fn finalized_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> {
            Ok(None)
        }
    }

    impl StateProviderFactory for Scripted {
        type Primitives = <MockEthProvider as StateProviderFactory>::Primitives;

        fn latest(&self) -> ProviderResult<StateProviderBox> {
            self.inner.latest()
        }
        fn state_with_block_appended(
            &self,
            parent_hash: B256,
            block: ExecutedBlock<Self::Primitives>,
        ) -> ProviderResult<StateProviderBox> {
            self.inner.state_with_block_appended(parent_hash, block)
        }
        fn state_by_block_number_or_tag(&self, n: alloy_eips::BlockNumberOrTag) -> ProviderResult<StateProviderBox> {
            self.inner.state_by_block_number_or_tag(n)
        }
        fn history_by_block_number(&self, block: u64) -> ProviderResult<StateProviderBox> {
            self.inner.history_by_block_number(block)
        }
        fn history_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> {
            self.inner.history_by_block_hash(block)
        }
        fn state_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fatal.contains(&block) {
                return Err(ProviderError::UnsupportedProvider);
            }
            let flaky = self.flaky_first.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            if flaky.is_ok() || (self.missing.contains(&block) && !self.released.load(Ordering::SeqCst)) {
                return Err(ProviderError::StateForHashNotFound(block));
            }
            self.inner.state_by_block_hash(block)
        }
        fn pending(&self) -> ProviderResult<StateProviderBox> {
            self.inner.pending()
        }
        fn pending_state_by_hash(&self, h: B256) -> ProviderResult<Option<StateProviderBox>> {
            self.inner.pending_state_by_hash(h)
        }
        fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
            self.inner.maybe_pending()
        }
    }

    fn info(nonce: u64, balance: u64) -> AccountInfo {
        AccountInfo { nonce, balance: U256::from(balance), ..Default::default() }
    }

    fn nonce_of(state: &StateProviderBox, address: Address) -> Option<u64> {
        state.basic_account(&address).expect("read").map(|a| a.nonce)
    }

    fn is_miss<T>(result: &ProviderResult<T>) -> bool {
        matches!(result, Err(ProviderError::StateForHashNotFound(_)))
    }

    #[test]
    fn a_state_that_is_not_there_yet_is_polled_for_and_counted() {
        let _ = open_wait::take();
        let mut client = Scripted::new(MockEthProvider::default());
        client.flaky_first = AtomicUsize::new(2);
        assert!(state_at_soon(&client, B256::with_last_byte(1)).is_ok());
        assert_eq!(client.calls.load(Ordering::SeqCst), 3, "two misses, then the state");
        assert_eq!(open_wait::take().grandparent_polls, 2);

        // Found at once: no polling.
        let client = Scripted::new(MockEthProvider::default());
        assert!(state_at_soon(&client, B256::with_last_byte(1)).is_ok());
        assert_eq!(open_wait::take().grandparent_polls, 0);
    }

    #[test]
    fn an_error_that_is_not_a_miss_is_not_waited_on() {
        let _ = open_wait::take();
        let hash = B256::with_last_byte(2);
        let mut client = Scripted::new(MockEthProvider::default());
        client.fatal.insert(hash);
        let at = std::time::Instant::now();
        assert!(matches!(state_at_soon(&client, hash), Err(ProviderError::UnsupportedProvider)));
        assert!(at.elapsed() < GRANDPARENT_WAIT, "returned without waiting");
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        assert_eq!(open_wait::take().grandparent_polls, 0);
    }

    #[test]
    fn a_state_that_never_arrives_is_refused_after_the_bounded_wait() {
        let _ = open_wait::take();
        let hash = B256::with_last_byte(3);
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(hash);
        let at = std::time::Instant::now();
        let result = state_at_soon(&client, hash);
        assert!(matches!(result, Err(ProviderError::StateForHashNotFound(h)) if h == hash));
        assert!(at.elapsed() >= GRANDPARENT_WAIT, "waited the whole bound: {:?}", at.elapsed());
        assert!(open_wait::take().grandparent_polls > 5, "and looked again meanwhile");
    }

    #[test]
    fn the_built_parent_opener_waits_for_the_grandparent_and_lays_the_parent_over_it() {
        let _guard = store_lock();
        let sender = Address::with_last_byte(0x61);
        let other = Address::with_last_byte(0x62);
        let grandparent = B256::with_last_byte(0x6a);
        let mock = MockEthProvider::default();
        mock.add_account(sender, ExtendedAccount::new(1, U256::from(10)));
        mock.add_account(other, ExtendedAccount::new(9, U256::from(10)));
        let mut client = Scripted::new(mock);
        client.flaky_first = AtomicUsize::new(1);
        let bundle = BundleState::builder(61..=61).state_present_account_info(sender, info(2, 5)).build();
        let header = Header { number: 61, parent_hash: grandparent, ..Default::default() };
        let execution = execution_of(&header, bundle);
        let sealed = SealedHeader::seal_slow(Header { extra_data: b"view 61".as_slice().into(), ..header });
        let opener = opener_on_built_parent(client, grandparent, executed_under_seal(&sealed, &execution));
        let state = opener().expect("opens after one miss");
        assert_eq!(nonce_of(&state, sender), Some(2), "the parent's value");
        assert_eq!(nonce_of(&state, other), Some(9), "the grandparent's value");
        // Every call of the opener is a fresh view.
        assert_eq!(nonce_of(&opener().expect("again"), sender), Some(2));
    }

    #[test]
    fn the_published_parent_opener_reads_newest_first_over_the_anchor() {
        let acct = Address::with_last_byte(0x71);
        let only_old = Address::with_last_byte(0x72);
        let anchor = B256::with_last_byte(0x7a);
        let mock = MockEthProvider::default();
        mock.add_account(acct, ExtendedAccount::new(0, U256::from(1)));
        mock.add_account(Address::with_last_byte(0x73), ExtendedAccount::new(3, U256::from(1)));
        let output = |block: u64, entries: &[(Address, u64)]| {
            let mut builder = BundleState::builder(block..=block);
            for (address, nonce) in entries {
                builder = builder.state_present_account_info(*address, info(*nonce, 1));
            }
            Arc::new(BlockExecutionOutput { result: Default::default(), state: builder.build() })
        };
        let seal = |number: u64| {
            SealedHeader::seal_slow(Header { number, parent_hash: B256::with_last_byte(number as u8), ..Default::default() })
        };
        let newest = executed_from_output(&seal(72), output(72, &[(acct, 7)]));
        let older = executed_from_output(&seal(71), output(71, &[(acct, 5), (only_old, 4)]));
        let opener = opener_on_published_parent(Scripted::new(mock), anchor, vec![newest, older]);
        let state = opener().expect("opens");
        assert_eq!(nonce_of(&state, acct), Some(7), "the newest block that touched it answers");
        assert_eq!(nonce_of(&state, only_old), Some(4), "an older block's own account");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0x73)), Some(3), "the anchor's");
        assert_eq!(state.block_hash(72).expect("read"), Some(seal(72).hash()));
        assert_eq!(state.block_hash(71).expect("read"), Some(seal(71).hash()));
    }

    #[test]
    fn executed_from_output_keeps_the_sealed_header_and_shares_the_output() {
        let parent = SealedHeader::seal_slow(Header { number: 8, extra_data: b"view 8".as_slice().into(), ..Default::default() });
        let output = Arc::new(BlockExecutionOutput { result: Default::default(), state: BundleState::default() });
        let executed = executed_from_output(&parent, output.clone());
        assert_eq!(executed.recovered_block.hash(), parent.hash());
        assert_eq!(executed.recovered_block.header().number, 8);
        assert!(executed.recovered_block.body().transactions.is_empty(), "the body is left empty by design");
        assert!(executed.recovered_block.senders().is_empty());
        assert!(Arc::ptr_eq(&executed.execution_output, &output));
    }

    #[test]
    fn executed_under_seal_carries_the_body_and_the_senders() {
        let sender = Address::with_last_byte(0x81);
        let header = Header { number: 9, ..Default::default() };
        let mut execution = execution_of(&header, BundleState::default());
        let tx = n42_tx_types::N42TxEnvelope::Eth(reth_ethereum_primitives::TransactionSigned::new_unhashed(
            reth_ethereum_primitives::Transaction::Legacy(alloy_consensus::TxLegacy { nonce: 3, ..Default::default() }),
            alloy_primitives::Signature::test_signature(),
        ));
        let block = Block {
            header: header.clone(),
            body: BlockBody { transactions: vec![tx], ommers: Vec::new(), withdrawals: Some(Vec::new().into()) },
        };
        execution.block = Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), vec![sender]));
        let sealed = SealedHeader::seal_slow(Header { extra_data: b"view 9".as_slice().into(), ..header });
        let executed = executed_under_seal(&sealed, &execution);
        assert_eq!(executed.recovered_block.hash(), sealed.hash());
        assert_eq!(executed.recovered_block.body().transactions.len(), 1);
        assert_eq!(executed.recovered_block.senders(), &[sender]);
        assert!(Arc::ptr_eq(&executed.execution_output, &execution.execution_output));
    }

    #[test]
    fn a_parents_builder_hash_is_named_by_each_kind_of_execution() {
        let header = Header { number: 10, ..Default::default() };
        let execution = execution_of(&header, BundleState::default());
        let built = execution.block.hash();
        assert_eq!(ParentExecution::Ready(execution).built_hash(), built);
        assert_eq!(ParentExecution::Sealed { built_hash: B256::with_last_byte(5) }.built_hash(), B256::with_last_byte(5));
        let published = ParentExecution::Published {
            parent_hash: B256::with_last_byte(6),
            executed: Vec::new(),
            anchor: B256::with_last_byte(7),
        };
        assert_eq!(published.built_hash(), B256::with_last_byte(6));
    }

    #[test]
    fn the_first_registered_builder_wins() {
        struct Stub(&'static str);
        impl DirectBuilder for Stub {
            fn build_on_own(&self, _request: BuildOnOwnRequest) -> Result<N42BuiltPayload, String> {
                Err(self.0.to_owned())
            }
        }
        let first: Arc<dyn DirectBuilder> = Arc::new(Stub("first"));
        register(first);
        let registered = get().expect("a builder is registered");
        register(Arc::new(Stub("second")));
        let still = get().expect("still registered");
        assert!(Arc::ptr_eq(&registered, &still), "a second registration does not replace the first");
    }

    #[test]
    fn a_missing_parent_output_refuses_the_open_at_once() {
        let _guard = store_lock();
        let parent = SealedHeader::seal_slow(Header { number: 91, extra_data: b"view 91".as_slice().into(), ..Default::default() });
        let opener = opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), parent.clone(), B256::with_last_byte(0x9f), false);
        let at = std::time::Instant::now();
        match opener() {
            Err(ProviderError::StateForHashNotFound(hash)) => assert_eq!(hash, parent.hash()),
            Err(other) => panic!("a miss naming the parent was expected, got {other:?}"),
            Ok(_) => panic!("an unfiled output cannot open"),
        }
        assert!(at.elapsed() < std::time::Duration::from_secs(1), "an unfiled build is not waited for");
    }

    /// Files a build as `StateReady` (its bundle is its state) and returns it with its seal.
    fn file_ready(number: u64, parent_hash: B256, bundle: BundleState) -> (SealedHeader, B256) {
        let header = Header { number, parent_hash, gas_used: number * 1_000, ..Default::default() };
        let execution = execution_of(&header, bundle);
        let built_hash = execution.block.hash();
        let sealed = SealedHeader::seal_slow(Header { extra_data: format!("view {number}").into_bytes().into(), ..header });
        crate::built_executions::remember_pending(built_hash, execution.block.clone());
        crate::built_executions::state_ready(built_hash, execution);
        (sealed, built_hash)
    }

    #[test]
    fn a_grandparent_found_at_once_needs_no_wait_on_the_parent() {
        let _guard = store_lock();
        let _ = open_wait::take();
        let grandparent = B256::with_last_byte(0xa1);
        let (sealed, built) = file_ready(101, grandparent, BundleState::default());
        // Pending: even a parent that is finishing is not waited for when the state is there.
        let state = grandparent_state(&Scripted::new(MockEthProvider::default()), grandparent, built);
        assert!(state.is_ok());
        assert_eq!(open_wait::take().parent_root_ms, 0);
        let _ = sealed;
    }

    #[test]
    fn a_grandparent_missing_for_a_parent_that_is_done_is_a_plain_miss() {
        let _guard = store_lock();
        let _ = open_wait::take();
        let grandparent = B256::with_last_byte(0xa2);
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(grandparent);
        // Not filed at all: `finishing` is false, so no extra waiting follows the bounded wait.
        let at = std::time::Instant::now();
        let result = grandparent_state(&client, grandparent, B256::with_last_byte(0xaf));
        assert!(is_miss(&result));
        assert!(at.elapsed() < GRANDPARENT_WAIT * 2, "one bounded wait only: {:?}", at.elapsed());
        let wait = open_wait::take();
        assert_eq!(wait.parent_root_ms, 0);
        assert_eq!(wait.parent_complete_ms, 0);
    }

    #[test]
    fn a_grandparent_that_lands_after_the_parents_root_is_found_on_the_second_look() {
        let _guard = store_lock();
        let _ = open_wait::take();
        let grandparent = B256::with_last_byte(0xa3);
        let header = Header { number: 103, parent_hash: grandparent, ..Default::default() };
        let execution = execution_of(&header, BundleState::default());
        let built = execution.block.hash();
        // Sealed, finishing; its QMDB root is already published, so the root wait returns at once.
        crate::built_executions::remember_pending(built, execution.block.clone());
        crate::executed_fields::remember(
            built,
            crate::executed_fields::ExecutedFields {
                state_root: B256::with_last_byte(1),
                receipts_root: B256::with_last_byte(2),
                logs_bloom: Default::default(),
                gas_used: 0,
            },
        );
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(grandparent);
        let released = client.released.clone();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(GRANDPARENT_WAIT + std::time::Duration::from_millis(50));
            released.store(true, Ordering::SeqCst);
        });
        let result = grandparent_state(&client, grandparent, built);
        releaser.join().expect("releaser");
        assert!(result.is_ok(), "the second look, after the root wait, finds it");
        assert_eq!(crate::built_executions::stage_of(built), Some(crate::built_executions::Stage::Sealed));
        assert!(open_wait::take().grandparent_polls > 0);
    }

    #[test]
    fn a_grandparent_that_lands_with_the_parents_finish_is_found_on_the_last_look() {
        let _guard = store_lock();
        let _ = open_wait::take();
        let grandparent = B256::with_last_byte(0xa4);
        let header = Header { number: 104, parent_hash: grandparent, ..Default::default() };
        let execution = execution_of(&header, BundleState::default());
        let built = execution.block.hash();
        crate::built_executions::remember_pending(built, execution.block.clone());
        crate::executed_fields::remember(
            built,
            crate::executed_fields::ExecutedFields {
                state_root: B256::with_last_byte(3),
                receipts_root: B256::with_last_byte(4),
                logs_bloom: Default::default(),
                gas_used: 0,
            },
        );
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(grandparent);
        let released = client.released.clone();
        // The engine gets the grandparent, then the parent's finish completes.
        let finisher = std::thread::spawn(move || {
            std::thread::sleep(GRANDPARENT_WAIT * 2 + std::time::Duration::from_millis(100));
            released.store(true, Ordering::SeqCst);
            crate::built_executions::complete(built, execution);
        });
        let result = grandparent_state(&client, grandparent, built);
        finisher.join().expect("finisher");
        assert!(result.is_ok(), "found after the parent's finish");
        assert_eq!(crate::built_executions::stage_of(built), Some(crate::built_executions::Stage::Complete));
    }

    // ---- leader_layers ----

    fn layer_of(number: u64, parent_hash: B256, bundle: BundleState) -> (leader_layers::Layer, SealedHeader) {
        let sealed = SealedHeader::seal_slow(Header { number, parent_hash, extra_data: format!("layer {number}").into_bytes().into(), ..Default::default() });
        let output = Arc::new(BlockExecutionOutput { result: Default::default(), state: bundle });
        ((executed_from_output(&sealed, output), None), sealed)
    }

    #[test]
    fn keeping_a_layer_releases_everything_but_its_parent() {
        let _guard = store_lock();
        let (a, a_seal) = layer_of(201, B256::with_last_byte(0xb0), BundleState::default());
        let (b, b_seal) = layer_of(202, a_seal.hash(), BundleState::default());
        let (c, c_seal) = layer_of(203, b_seal.hash(), BundleState::default());
        leader_layers::keep(&a);
        leader_layers::keep(&b);
        assert!(leader_layers::find(a_seal.hash()).is_some() && leader_layers::find(b_seal.hash()).is_some());
        leader_layers::keep(&c);
        assert!(leader_layers::find(a_seal.hash()).is_none(), "the great-grandparent is released");
        assert!(leader_layers::find(b_seal.hash()).is_some(), "the parent stays: it is the child's grandparent");
        assert!(leader_layers::find(c_seal.hash()).is_some());
        assert_eq!(leader_layers::len(), 2);
        // Keeping the same block again does not duplicate it.
        leader_layers::keep(&c);
        assert_eq!(leader_layers::len(), 2);
        // An unrelated block (a reorg) keeps nothing of the old chain.
        let (d, d_seal) = layer_of(300, B256::with_last_byte(0xb1), BundleState::default());
        leader_layers::keep(&d);
        assert_eq!(leader_layers::len(), 1);
        assert!(leader_layers::find(d_seal.hash()).is_some());
        assert!(leader_layers::find(c_seal.hash()).is_none());
    }

    #[test]
    fn layers_over_a_state_read_newest_first_and_an_empty_stack_is_the_state_itself() {
        let a = Address::with_last_byte(0xc1);
        let b = Address::with_last_byte(0xc2);
        let mock = MockEthProvider::default();
        mock.add_account(a, ExtendedAccount::new(1, U256::from(1)));
        mock.add_account(b, ExtendedAccount::new(1, U256::from(1)));
        let historical = || mock.state_by_block_hash(B256::ZERO).expect("state");
        let (parent, _) = layer_of(211, B256::with_last_byte(1), BundleState::builder(211..=211).state_present_account_info(a, info(3, 1)).build());
        let (grandparent, _) = layer_of(
            210,
            B256::with_last_byte(2),
            BundleState::builder(210..=210).state_present_account_info(a, info(2, 1)).state_present_account_info(b, info(5, 1)).build(),
        );
        let bare = leader_layers::open_on(historical(), &[]);
        assert_eq!((nonce_of(&bare, a), nonce_of(&bare, b)), (Some(1), Some(1)));
        // Newest first, as the caller passes them: the parent's write wins over the grandparent's.
        let stacked = leader_layers::open_on(historical(), &[parent, grandparent]);
        assert_eq!(nonce_of(&stacked, a), Some(3));
        assert_eq!(nonce_of(&stacked, b), Some(5));
    }

    /// Files and opens a grandparent and its child's parent, so the layers are kept.
    fn chain_of_two(great_grandparent: B256) -> ((SealedHeader, B256), (SealedHeader, B256)) {
        let gp = file_ready(401, great_grandparent, BundleState::builder(401..=401).state_present_account_info(Address::with_last_byte(0xd1), info(2, 1)).build());
        let parent = file_ready(402, gp.0.hash(), BundleState::builder(402..=402).state_present_account_info(Address::with_last_byte(0xd2), info(4, 1)).build());
        (gp, parent)
    }

    #[test]
    fn a_great_grandparent_not_in_the_engine_falls_back_to_the_engines_grandparent() {
        let _guard = store_lock();
        let _ = open_wait::take();
        let ggp = B256::with_last_byte(0xe0);
        let (gp, parent) = chain_of_two(ggp);
        let mock = || {
            let mock = MockEthProvider::default();
            mock.add_account(Address::with_last_byte(0xd1), ExtendedAccount::new(1, U256::from(1)));
            mock
        };
        // The grandparent's own child opens first, which keeps the grandparent's layer.
        opener_on_sealed_parent_with(Scripted::new(mock()), gp.0.clone(), gp.1, true)().expect("the first open");
        assert!(leader_layers::find(gp.0.hash()).is_some());
        let _ = open_wait::take();

        let mut client = Scripted::new(mock());
        client.missing.insert(ggp);
        let state = opener_on_sealed_parent_with(client, parent.0.clone(), parent.1, true)().expect("falls back");
        let wait = open_wait::take();
        assert_eq!((wait.grandparent_layer, wait.great_grandparent_missing), (0, 1), "{}", wait.split());
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd2)), Some(4), "the parent's write");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd1)), Some(1), "the engine's grandparent answers for the rest");
    }

    #[test]
    fn any_other_error_on_the_great_grandparent_refuses_the_open() {
        let _guard = store_lock();
        let ggp = B256::with_last_byte(0xe1);
        let (gp, parent) = chain_of_two(ggp);
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), gp.0.clone(), gp.1, true)().expect("the first open");
        let mut client = Scripted::new(MockEthProvider::default());
        client.fatal.insert(ggp);
        let result = opener_on_sealed_parent_with(client, parent.0.clone(), parent.1, true)();
        assert!(matches!(result, Err(ProviderError::UnsupportedProvider)));
    }

    #[test]
    fn a_full_bundle_parent_opens_with_the_grandparent_layer_when_kept() {
        let _guard = store_lock();
        let _ = open_wait::take();
        let ggp = B256::with_last_byte(0xe2);
        let (gp, parent) = chain_of_two(ggp);
        let mock = || {
            let mock = MockEthProvider::default();
            mock.add_account(Address::with_last_byte(0xd3), ExtendedAccount::new(7, U256::from(1)));
            mock
        };
        opener_on_sealed_parent_with(Scripted::new(mock()), gp.0.clone(), gp.1, true)().expect("the first open");
        let _ = open_wait::take();
        let state = opener_on_sealed_parent_with(Scripted::new(mock()), parent.0.clone(), parent.1, true)().expect("opens on both layers");
        assert_eq!(open_wait::take().grandparent_layer, 1);
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd1)), Some(2), "the grandparent's layer");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd2)), Some(4), "the parent's layer");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd3)), Some(7), "the engine's state under both");
    }

    // ---- the read-depth counter ----

    #[test]
    fn a_read_no_block_answers_is_counted_as_historical() {
        let _guard = store_lock();
        let _ = read_depth::snapshot();
        let mock = MockEthProvider::default();
        let address = Address::with_last_byte(0xee);
        mock.add_account(address, ExtendedAccount::new(42, U256::from(1)));
        let provider = read_depth::CountingStateProvider {
            historical: mock.state_by_block_hash(B256::ZERO).expect("state"),
            executed: Vec::new(),
        };
        assert_eq!(provider.basic_account(&address).expect("read").map(|a| a.nonce), Some(42));
        assert_eq!(read_depth::snapshot(), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn the_counting_provider_buckets_each_read_by_the_depth_that_answered() {
        let _guard = store_lock();
        let _ = read_depth::snapshot();
        let touched: Vec<(usize, Address)> =
            [0usize, 1, 3, 4, 8, 16].iter().map(|d| (*d, Address::with_last_byte(0x80 + *d as u8))).collect();
        let executed: Vec<ExecutedParent> = (0..17usize)
            .map(|depth| {
                let mut builder = BundleState::builder(depth as u64..=depth as u64);
                for (d, address) in &touched {
                    if *d == depth {
                        builder = builder.state_present_account_info(*address, info(depth as u64 + 1, 1));
                    }
                }
                let sealed = SealedHeader::seal_slow(Header { number: 500 - depth as u64, ..Default::default() });
                executed_from_output(&sealed, Arc::new(BlockExecutionOutput { result: Default::default(), state: builder.build() }))
            })
            .collect();
        let mock = MockEthProvider::default();
        let historical_only = Address::with_last_byte(0xee);
        mock.add_account(historical_only, ExtendedAccount::new(42, U256::from(1)));
        let provider = read_depth::CountingStateProvider {
            historical: mock.state_by_block_hash(B256::ZERO).expect("state"),
            executed,
        };
        for (depth, address) in &touched {
            let account = provider.basic_account(address).expect("read").expect("present");
            assert_eq!(account.nonce, *depth as u64 + 1, "depth {depth}");
        }
        // Depths 0, 1, 2, 3 | 4-7 | 8-15 | 16+.
        assert_eq!(read_depth::snapshot(), [1, 1, 0, 1, 1, 1, 1, 0]);
        assert_eq!(read_depth::snapshot(), [0; read_depth::BUCKETS], "a snapshot resets");
        // The value still comes from the historical state when no block answers.
        assert_eq!(provider.basic_account(&historical_only).expect("read").map(|a| a.nonce), Some(42));
        let _ = read_depth::snapshot();
        // The other reads delegate to the overlay: BLOCKHASH answers from the stack.
        assert!(provider.block_hash(500).expect("read").is_some());
        assert_eq!(provider.storage(historical_only, B256::ZERO).expect("read"), None);
    }
}

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

/// How long a build's open waits for an ancestor to reach the engine before
/// giving up on it.
///
/// The build chain (`N42_BUILD_CHAIN`) starts a build at its parent's early
/// seal, which on a leader with a tenure is *before* the engine has finished
/// importing the blocks this node proposed just before. Measured on loop193
/// W1b: 56 of 347 refused chained builds were exactly this, and the block they
/// named was added to the canonical chain a median of 18 ms later (p90 68, max
/// 209). Refusing costs the whole build and the ~275 ms of lead it was for;
/// waiting costs the wait. Bounded, because an ancestor that is not coming
/// must end as a refusal and not as a builder thread that never returns.
const GRANDPARENT_WAIT: std::time::Duration = std::time::Duration::from_millis(150);

/// How often the wait looks again when nothing wakes it
/// ([`engine_landed::wire`] not called: tests, a binary that does not follow
/// the canonical chain).
const GRANDPARENT_POLL: std::time::Duration = std::time::Duration::from_millis(2);

/// The longest a woken wait sleeps without a wake-up before it looks again
/// anyway: a safety net for a block that became readable without a canonical
/// notification, not the mechanism.
const LANDED_SAFETY_SLICE: std::time::Duration = std::time::Duration::from_millis(20);

/// Where a build's open of its parent's state waited (`state_wait_on` on the
/// seal-first phases line): the parent's output (`StateReady` / the shards,
/// [`opener_on_sealed_parent`]), the state under the kept layers (the anchor
/// in the engine, [`state_at_soon`]), and, when the anchor was missing while
/// the parent finished, the parent's QMDB root and its `Complete`
/// ([`grandparent_state`]); and, named since loop333 (the "open" waits of
/// `docs/SHARED_EXECUTION_SCOPE.md` 8.1), the open's own two costs: the
/// release of the layers no longer kept (`leader_layers::keep` drops them on
/// the build's thread) and the first look up of the anchor's state (the
/// provider's open: in-memory lookup, database read transaction, the
/// anchor's header). Kept per thread: the build's open runs on the builder's
/// thread, which takes it before and after the open.
pub mod open_wait {
    use std::cell::Cell;

    /// One open's waits.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct OpenWait {
        /// The parent's output filed (`built_executions::wait_for_state`), ms.
        pub output_ms: u64,
        /// The anchor under the kept layers (the grandparent when only the
        /// parent is laid over the engine) not in the engine at the first
        /// look: the bounded wait for its import, ms.
        pub grandparent_ms: u64,
        /// How many times that wait looked again (woken by a canonical
        /// notification, or every 2 ms when nothing wakes it).
        pub grandparent_polls: u32,
        /// The anchor still missing: the wait for the parent's QMDB root and
        /// the look after it, ms.
        pub parent_root_ms: u64,
        /// Still missing: the wait for the parent's `Complete` and the look
        /// after it, ms.
        pub parent_complete_ms: u64,
        /// Opens that read the grandparent (and older blocks) from kept layers
        /// over the engine's state at a deeper anchor
        /// (`N42_GRANDPARENT_SHARDS`, `N42_LEADER_LAYERS`,
        /// [`super::leader_layers`]).
        pub grandparent_layer: u32,
        /// Opens whose deepest anchor was not in the engine at the first look
        /// (they waited for it, [`OpenWait::grandparent_ms`]).
        pub great_grandparent_missing: u32,
        /// How many own blocks the open laid over the engine's state (the
        /// parent counts: 1 is the parent alone).
        pub layers: u32,
        /// Whether the open had to wait for its anchor to reach the engine.
        pub fallback: bool,
        /// That wait, microseconds (all of it: the woken wait, the root and
        /// `Complete` waits).
        pub engine_wait_us: u64,
        /// `leader_layers::keep`: keeping the parent's layer and dropping the
        /// layers released by it, microseconds.
        pub keep_us: u64,
        /// The first look up of the anchor's state, microseconds.
        pub provider_us: u64,
        /// Accounts the kept layers hold after the open's keep (shard sets
        /// and filed bundles, [`super::leader_layers::held`]): the memory the
        /// layer count costs.
        pub kept_accounts: u64,
    }

    impl OpenWait {
        /// The largest of the waits, by name; `none` when every one is under
        /// a millisecond.
        pub fn label(&self) -> &'static str {
            self.named_us()
                .into_iter()
                .filter(|(us, _)| *us >= 1000)
                .max_by_key(|(us, _)| *us)
                .map_or("none", |(_, name)| name)
        }

        /// The named waits in microseconds, by name.
        pub fn named_us(&self) -> [(u64, &'static str); 6] {
            [
                (self.output_ms * 1000, "output"),
                (self.grandparent_ms * 1000, "grandparent"),
                (self.parent_root_ms * 1000, "parent_root"),
                (self.parent_complete_ms * 1000, "parent_complete"),
                (self.keep_us, "layer_release"),
                (self.provider_us, "provider_open"),
            ]
        }

        /// `output/grandparent/parent_root/parent_complete` in ms, then the
        /// grandparent's polls, the opens on kept layers, the anchor misses,
        /// the layers laid, whether the open waited for the engine, that
        /// wait, the layer release and the anchor's first look (us).
        pub fn split(&self) -> String {
            format!(
                "{}/{}/{}/{} polls={} gp_layer={} ggp_missing={} open_layers={} open_fallback={} open_engine_us={} open_keep_us={} open_provider_us={} open_kept_accounts={}",
                self.output_ms,
                self.grandparent_ms,
                self.parent_root_ms,
                self.parent_complete_ms,
                self.grandparent_polls,
                self.grandparent_layer,
                self.great_grandparent_missing,
                self.layers,
                self.fallback,
                self.engine_wait_us,
                self.keep_us,
                self.provider_us,
                self.kept_accounts,
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
                layers: 0,
                fallback: false,
                engine_wait_us: 0,
                keep_us: 0,
                provider_us: 0,
                kept_accounts: 0,
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

/// A wake-up for every change of the engine's canonical chain, so a build
/// waiting for an ancestor to become readable sleeps until it may have, not
/// on a 2 ms poll.
///
/// The node calls [`notify`] from a canonical-state subscriber
/// (`bin/n42/src/main.rs`): reth publishes the notification after the
/// in-memory canonical state holds the new blocks, which is where
/// `state_by_block_hash` finds them. A waiter reads the generation *before*
/// it looks, so a landing between its look and its sleep is never missed.
pub mod engine_landed {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Condvar, Mutex,
    };
    use std::time::{Duration, Instant};

    static GENERATION: (Mutex<u64>, Condvar) = (Mutex::new(0), Condvar::new());
    static WIRED: AtomicBool = AtomicBool::new(false);

    /// Marks the wake-ups as delivered: waits then sleep up to
    /// [`super::LANDED_SAFETY_SLICE`] between looks instead of polling.
    pub fn wire() {
        WIRED.store(true, Ordering::Relaxed);
    }

    /// Whether [`wire`] was called.
    pub fn wired() -> bool {
        WIRED.load(Ordering::Relaxed)
    }

    /// The engine's canonical chain changed: wakes every waiter.
    pub fn notify() {
        let (count, landed) = &GENERATION;
        let mut count = count.lock().unwrap_or_else(|p| p.into_inner());
        *count = count.wrapping_add(1);
        landed.notify_all();
    }

    /// The current generation, read before a look.
    pub fn generation() -> u64 {
        *GENERATION.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The longest sleep between two looks.
    pub(crate) fn slice() -> Duration {
        if wired() {
            super::LANDED_SAFETY_SLICE
        } else {
            super::GRANDPARENT_POLL
        }
    }

    /// Sleeps until the generation moves past `seen`, `slice` has passed or
    /// `until`, whichever comes first; `true` when woken by a change.
    pub(crate) fn wait_past(seen: u64, until: Instant, slice: Duration) -> bool {
        let limit = until.min(Instant::now() + slice);
        let (count, landed) = &GENERATION;
        let mut guard = count.lock().unwrap_or_else(|p| p.into_inner());
        while *guard == seen {
            let now = Instant::now();
            if now >= limit {
                return false;
            }
            guard = landed.wait_timeout(guard, limit - now).unwrap_or_else(|p| p.into_inner()).0;
        }
        true
    }
}

/// The state at `block`, waiting up to [`GRANDPARENT_WAIT`] for an import
/// that is already in flight to land.
///
/// Only "this node does not hold that state" is waited on; every other error
/// is the provider saying something is wrong, and waiting would only make the
/// build slower before it failed anyway. The wait is woken by the engine's
/// canonical notifications ([`engine_landed`]).
fn state_at_soon<C>(client: &C, block: B256) -> ProviderResult<StateProviderBox>
where
    C: StateProviderFactory,
{
    state_when_landed(client, block, std::time::Instant::now() + GRANDPARENT_WAIT, engine_landed::slice())
}

/// [`state_at_soon`] with the deadline and the sleep between looks given.
fn state_when_landed<C>(
    client: &C,
    block: B256,
    deadline: std::time::Instant,
    slice: std::time::Duration,
) -> ProviderResult<StateProviderBox>
where
    C: StateProviderFactory,
{
    loop {
        let seen = engine_landed::generation();
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
        engine_landed::wait_past(seen, deadline, slice);
    }
}

/// The state at `anchor` -- the block under the layers a build on the sealed
/// own parent filed under `built_hash` lays over the engine -- looked up once
/// (timed: `provider_us`), then waited for ([`state_at_soon`]), and when the
/// anchor is still not in the engine while the parent's finish behind its
/// seal is running, once more after the parent's QMDB root is published, and
/// once more after that finish.
///
/// The anchor is an ancestor of this node's own blocks, handed to the engine
/// after its own finish, and that hand-off can be held behind the parent's
/// finish: on loop278 IDX/IDXb and every `N42_OUTPUT_SHARDS` leg of
/// loop276-277 the grandparent's hand-off (`own block handed to the engine as
/// executed`, 590-640 ms) ended with the parent's slow QMDB roots (575-650
/// ms, every ~44 blocks), where the ordinary hand-off takes ~40 ms -- with
/// the shards the parent's roots start at its seal, before the grandparent's
/// hand-off is through. The 150 ms wait then refused the chained build ("no
/// state found for block" the grandparent: 1-3 a leg on the leader, 0 on
/// every flag-off leg) and the leader lost the view (5-6 s, then a TC).
///
/// What held the hand-off is the QMDB forest's lock: the grandparent's rename
/// to its sealed hash (`chain_alias::rename`) waits for the parent's root job
/// (`compute_operations`) to let it go. So the first wait is for the parent's
/// root, published the moment that job ends (`executed_fields`) -- which this
/// build waits for anyway, its header carries the parent's execution
/// (`PARENT_FIELDS_WAIT`). Only if the anchor is still missing then does it
/// wait for the parent's `Complete`, which since the shards' merge runs
/// behind the root's publication (BREAKTHROUGH_DESIGN 10.16) comes ~55 ms
/// later.
///
/// The anchor is the *deepest* block the open can stand on: before loop333
/// the open that missed its great-grandparent waited for the grandparent,
/// which the engine lands one import (60-90 ms at E=1) after it
/// (`docs/SHARED_EXECUTION_SCOPE.md` 8.2).
fn grandparent_state<C>(client: &C, anchor: B256, built_hash: B256) -> ProviderResult<StateProviderBox>
where
    C: StateProviderFactory,
{
    use crate::built_executions::Stage;
    let finishing = || crate::built_executions::stage_of(built_hash).is_some_and(|stage| stage < Stage::Complete);
    let missing = |result: &ProviderResult<StateProviderBox>| {
        matches!(result, Err(reth_storage_api::errors::ProviderError::StateForHashNotFound(_)))
    };
    let looked_at = std::time::Instant::now();
    let first = client.state_by_block_hash(anchor);
    open_wait::add(|wait| wait.provider_us += looked_at.elapsed().as_micros() as u64);
    if !missing(&first) {
        return first;
    }
    let waited_at = std::time::Instant::now();
    let note_wait = |wait: &mut open_wait::OpenWait| {
        wait.fallback = true;
        wait.great_grandparent_missing += 1;
    };
    open_wait::add(note_wait);
    let soon = state_at_soon(client, anchor);
    open_wait::add(|wait| wait.grandparent_ms += waited_at.elapsed().as_millis() as u64);
    let done = |result: ProviderResult<StateProviderBox>| {
        open_wait::add(|wait| wait.engine_wait_us += waited_at.elapsed().as_micros() as u64);
        result
    };
    if !missing(&soon) || !finishing() {
        return done(soon);
    }
    let at = std::time::Instant::now();
    let _ = crate::executed_fields::wait_for(&built_hash, crate::hotstuff_consensus::PARENT_FIELDS_WAIT);
    let after_root = state_at_soon(client, anchor);
    let root_ms = at.elapsed().as_millis() as u64;
    open_wait::add(|wait| wait.parent_root_ms += root_ms);
    if !missing(&after_root) || !finishing() {
        tracing::info!(
            target: "payload_builder",
            %anchor,
            waited_ms = root_ms,
            found = after_root.is_ok(),
            "the anchor was not in the engine; waited for the parent's QMDB root"
        );
        return done(after_root);
    }
    let complete_at = std::time::Instant::now();
    let _ = crate::built_executions::wait_for(built_hash, Stage::Complete);
    tracing::info!(
        target: "payload_builder",
        %anchor,
        root_ms,
        waited_ms = at.elapsed().as_millis() as u64,
        "the anchor was not in the engine; waited for the parent's QMDB root and finish"
    );
    let after_complete = state_at_soon(client, anchor);
    open_wait::add(|wait| wait.parent_complete_ms += complete_at.elapsed().as_millis() as u64);
    done(after_complete)
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
    opener_on_sealed_parent_with(client, parent, built_hash, leader_layers::depth())
}

/// The own blocks a chained build lays over the engine's state.
///
/// `N42_GRANDPARENT_SHARDS` (on by default; `0` turns it off): the chained
/// build reads its grandparent -- this node's own block two seals back --
/// from the layer the previous chained build opened its parent on (its frozen
/// shards under its residual, or its filed bundle), over the engine's state at
/// the great-grandparent, instead of waiting for the grandparent to reach the
/// engine (BREAKTHROUGH_DESIGN 10.40). The follower keeps the same two
/// generations (`FOLLOWER_SHARDS` in `bin/n42/src/follower_import.rs`).
///
/// `N42_LEADER_LAYERS` (2..=4, default 2): how many own blocks a build lays
/// over the engine -- its parent and that many minus one ancestors -- so the
/// engine has to hold only the block below the deepest (N-3 at 2, N-4 at 3,
/// N-5 at 4). At E=1 the engine is two to three blocks behind a build's start
/// and three on 5-15% of starts (`docs/SHARED_EXECUTION_SCOPE.md` 8.2); one
/// more layer covers that.
///
/// What a layer holds: the block under its sealed header with an empty body,
/// its residual (the executor's own changes: fees, withdrawals, system calls)
/// and its frozen shard set (every account the block's batches wrote, with
/// the reverts; ~40 MB at 163,000 transfers, about 50 MB at 200,000 and 65 MB
/// at 250,000 by the accounts a block touches), or, filed after `StateReady`,
/// its whole bundle. All behind `Arc`s the build store and in-flight builds
/// share; a kept layer costs memory only while nothing else holds it, which
/// for the deepest one is about one block's shard set.
///
/// What bounds the count: memory (one shard set a layer), every read that no
/// layer answers walks every layer before the engine (one more index and map
/// lookup a layer), and depth past the engine's lag buys nothing. Nothing else
/// in the crate is keyed on two: the follower keeps its own generations.
///
/// What releases a layer: [`keep`] of a newer parent (every layer that is not
/// one of that parent's `depth - 1` nearest kept ancestors -- the oldest when
/// the chain moves on, every layer of a branch the chain abandoned, all of
/// them on a block that does not descend from them), and [`on_canonical`]
/// (every layer `depth` or more blocks under the engine's canonical tip --
/// the release after a handover, when this layer builds no more, and of an
/// abandoned build's branch). Persistence releases nothing by itself: a
/// persisted block was canonical first. A release is never a correctness
/// event: a build that does not find a layer lays fewer and waits for a
/// shallower anchor.
pub mod leader_layers {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    /// A block's post-state as a chained build reads it: the block under its
    /// sealed header with the bundle (the residual over the shards, or the
    /// filed full bundle), and the shards when it was filed as a shard set.
    pub type Layer = (ExecutedParent, Option<Arc<crate::output_shards::FrozenShards>>);

    static KEPT: Mutex<VecDeque<Layer>> = Mutex::new(VecDeque::new());

    /// The smallest and largest `N42_LEADER_LAYERS`. Up to 8 since
    /// `docs/SHARED_EXECUTION_SCOPE.md` 18.7 item 2: at E=1 the anchor (the
    /// block under the deepest layer) has to be canonical in the engine, and
    /// the canonical commit lands ~4 cycles after a seal (238 ms at 200k), so
    /// a ~42 ms cycle needs six layers to stand on a block the engine already
    /// holds. Nothing else bounds the count: the layers are kept here, not in
    /// the build store (`built_executions`' `KEEP` holds builds until their
    /// hand-off, and a layer is kept from its child's first open on), and the
    /// follower's `PARENT_OUTPUTS_KEPT` is the follower's own stack. What a
    /// layer costs is one shard set (~50 MB at 200k, ~100 MB at 400k) and one
    /// index probe on every read no newer layer answers; the open's line
    /// carries what the kept layers hold (`open_kept_accounts`). The engine's
    /// in-memory tree must still hold the anchor (`--engine.memory-block-buffer-target`
    /// at least the layers less the engine's lag; the fleet's 6 does at 6).
    pub const DEPTHS: std::ops::RangeInclusive<usize> = 2..=8;

    /// `N42_LEADER_LAYERS` as given: the default 2 when unset, `None` when
    /// it is not a number in [`DEPTHS`].
    pub fn parse_depth(value: Option<&str>) -> Option<usize> {
        match value.map(str::trim) {
            None | Some("") => Some(2),
            Some(v) => v.parse::<usize>().ok().filter(|d| DEPTHS.contains(d)),
        }
    }

    /// How many own blocks a chained build lays over the engine: 1 (the
    /// parent alone) with `N42_GRANDPARENT_SHARDS=0`, else
    /// `N42_LEADER_LAYERS` (2 when unset; an invalid value is refused with a
    /// warning and 2 is used).
    pub fn depth() -> usize {
        static DEPTH: OnceLock<usize> = OnceLock::new();
        *DEPTH.get_or_init(|| {
            if !enabled() {
                return 1;
            }
            let value = std::env::var("N42_LEADER_LAYERS").ok();
            parse_depth(value.as_deref()).unwrap_or_else(|| {
                tracing::warn!(target: "payload_builder", ?value, "N42_LEADER_LAYERS must be 2 to 8; using 2");
                2
            })
        })
    }

    /// Whether chained builds read their grandparent from its kept layer.
    pub fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("N42_GRANDPARENT_SHARDS").map_or(true, |v| v.trim() != "0"))
    }

    fn hash_of(layer: &Layer) -> B256 {
        layer.0.recovered_block.hash()
    }

    fn parent_of(layer: &Layer) -> B256 {
        layer.0.recovered_block.header().parent_hash
    }

    fn number_of(layer: &Layer) -> u64 {
        layer.0.recovered_block.header().number
    }

    /// Keeps `layer` (the parent a build just opened on) and its `depth - 1`
    /// nearest kept ancestors, and releases every other block's layer. The
    /// released layers are dropped here, after the lock; returns how many.
    pub fn keep(layer: &Layer, depth: usize) -> usize {
        let hash = hash_of(layer);
        let released: Vec<Layer> = {
            let mut kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
            let mut all: Vec<Layer> = std::mem::take(&mut *kept).into_iter().collect();
            let mut stay: VecDeque<Layer> = VecDeque::new();
            let mut want = parent_of(layer);
            while stay.len() + 1 < depth {
                let Some(at) = all.iter().position(|l| hash_of(l) == want) else { break };
                let ancestor = all.swap_remove(at);
                want = parent_of(&ancestor);
                stay.push_front(ancestor);
            }
            stay.push_back(layer.clone());
            *kept = stay;
            // The same block kept again replaces its old clone: not a release.
            all.into_iter().filter(|l| hash_of(l) != hash).collect()
        };
        let count = released.len();
        // The released shard sets (the last reference, usually) are dropped
        // here, after the lock.
        drop(released);
        count
    }

    /// The engine's canonical tip moved to `tip_number`: releases every layer
    /// `depth` or more blocks under it, which no build on the canonical chain
    /// or ahead of it lays any more (a build on a parent at or above the tip
    /// lays blocks down to `tip - depth + 1`). Returns how many.
    pub fn on_canonical(tip_number: u64, depth: usize) -> usize {
        let released: Vec<Layer> = {
            let mut kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
            let (stay, released): (VecDeque<Layer>, VecDeque<Layer>) =
                std::mem::take(&mut *kept).into_iter().partition(|l| number_of(l) + depth as u64 > tip_number);
            *kept = stay;
            released.into_iter().collect()
        };
        let count = released.len();
        drop(released);
        count
    }

    /// The kept layer of the block sealed as `hash`.
    pub fn find(hash: B256) -> Option<Layer> {
        KEPT.lock().unwrap_or_else(|p| p.into_inner()).iter().find(|l| hash_of(l) == hash).cloned()
    }

    /// The kept layers of `hash` and its ancestors, newest first, at most
    /// `count`, stopping at the first block not kept.
    pub fn ancestors(hash: B256, count: usize) -> Vec<Layer> {
        let kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::new();
        let mut want = hash;
        while out.len() < count {
            let Some(layer) = kept.iter().find(|l| hash_of(l) == want) else { break };
            want = parent_of(layer);
            out.push(layer.clone());
        }
        out
    }

    /// What the kept layers hold: (layers, accounts in their shard sets and
    /// filed bundles). The memory the layer count costs, in the unit the
    /// shard sets are sized by (~260 B an account with its revert at 200k).
    pub fn held() -> (usize, usize) {
        let kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
        let accounts = kept
            .iter()
            .map(|(executed, shards)| {
                shards.as_ref().map_or(0, |shards| shards.accounts()) + executed.execution_output.state.state.len()
            })
            .sum();
        (kept.len(), accounts)
    }

    /// How many blocks' layers are kept (at most `depth` once the chain runs).
    pub fn len() -> usize {
        KEPT.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Releases every kept layer (tests).
    #[cfg(test)]
    pub(crate) fn clear() {
        let released = std::mem::take(&mut *KEPT.lock().unwrap_or_else(|p| p.into_inner()));
        drop(released);
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

/// [`opener_on_sealed_parent`] with the number of own blocks to lay given
/// (`depth`: 1 is the parent alone over the engine's grandparent, the path
/// before `N42_GRANDPARENT_SHARDS`; see [`leader_layers::depth`]).
fn opener_on_sealed_parent_with<C>(
    client: C,
    parent: SealedHeader,
    built_hash: B256,
    depth: usize,
) -> ParentStateOpener
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    // The parent as filed, and (`N42_OUTPUT_SHARDS`) the shard set its
    // residual is laid over, when the shards came before `StateReady`.
    type Filed = leader_layers::Layer;
    let filed: Arc<OnceLock<Filed>> = Arc::new(OnceLock::new());
    // The kept ancestors' layers (newest first), looked up once at the first
    // open, so every batch of the build reads the same stack.
    let ancestors: Arc<OnceLock<Vec<Filed>>> = Arc::new(OnceLock::new());
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
        let ancestors = ancestors
            .get_or_init(|| {
                if depth < 2 {
                    return Vec::new();
                }
                let kept_at = std::time::Instant::now();
                leader_layers::keep(&parent_layer, depth);
                let (_, held) = leader_layers::held();
                open_wait::add(|wait| {
                    wait.keep_us += kept_at.elapsed().as_micros() as u64;
                    wait.kept_accounts = held as u64;
                });
                leader_layers::ancestors(parent.parent_hash, depth - 1)
            })
            .clone();
        // The kept ancestors over the engine's state under the deepest of
        // them; the engine's grandparent when none is kept. A missing anchor
        // is waited for (woken by the engine's canonical notifications) --
        // the deepest one, which lands first.
        let anchor = ancestors.last().map_or(parent.parent_hash, |deepest| deepest.0.recovered_block.header().parent_hash);
        let historical = grandparent_state(&client, anchor, built_hash)?;
        if !ancestors.is_empty() {
            open_wait::add(|wait| wait.grandparent_layer += 1);
        }
        let mut layers = Vec::with_capacity(ancestors.len() + 1);
        layers.push(parent_layer);
        layers.extend(ancestors);
        open_wait::add(|wait| wait.layers = layers.len() as u32);
        Ok(leader_layers::open_on(historical, &layers))
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
        let on_seal = opener_on_sealed_parent_with(grandparent_state(), sealed.clone(), built_hash, 1)()
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
        let again = opener_on_sealed_parent_with(grandparent_state(), sealed, built_hash, 1)().expect("opens again");
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
        let on_shards = opener_on_sealed_parent_with(grandparent_state(), sealed.clone(), built_hash, 1)()
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
        opener_on_sealed_parent_with(engine_at_ggp(), gp_sealed.clone(), gp_built, 2)()
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
        let layered = opener_on_sealed_parent_with(engine_at_ggp(), p_sealed.clone(), p_built, 2)()
            .expect("the child opens on the two layers");
        let wait = open_wait::take();
        assert_eq!((wait.grandparent_layer, wait.great_grandparent_missing), (1, 0), "{}", wait.split());
        assert_eq!(wait.grandparent_ms, 0, "the engine's grandparent was not waited for");
        assert!(leader_layers::len() <= 2, "two blocks' layers at most");
        // Today's path: the parent's shards over the engine's grandparent.
        let direct = opener_on_sealed_parent_with(engine_at_gp(), p_sealed.clone(), p_built, 1)()
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
        assert_eq!(
            wait.split(),
            "3/150/40/0 polls=60 gp_layer=0 ggp_missing=0 open_layers=0 open_fallback=false open_engine_us=0 open_keep_us=0 open_provider_us=0 open_kept_accounts=0"
        );
        assert_eq!(open_wait::take(), OpenWait::default());
        // The open's own costs are named, in microseconds.
        open_wait::add(|wait| wait.keep_us += 61_000);
        open_wait::add(|wait| wait.provider_us += 900);
        assert_eq!(open_wait::take().label(), "layer_release");
        open_wait::add(|wait| wait.provider_us += 70_000);
        assert_eq!(open_wait::take().label(), "provider_open");
        open_wait::add(|wait| wait.provider_us += 999);
        assert_eq!(open_wait::take().label(), "none", "under a millisecond is no wait");
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
        let opener = opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), parent.clone(), B256::with_last_byte(0x9f), 1);
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
        leader_layers::keep(&a, 2);
        leader_layers::keep(&b, 2);
        assert!(leader_layers::find(a_seal.hash()).is_some() && leader_layers::find(b_seal.hash()).is_some());
        leader_layers::keep(&c, 2);
        assert!(leader_layers::find(a_seal.hash()).is_none(), "the great-grandparent is released");
        assert!(leader_layers::find(b_seal.hash()).is_some(), "the parent stays: it is the child's grandparent");
        assert!(leader_layers::find(c_seal.hash()).is_some());
        assert_eq!(leader_layers::len(), 2);
        // Keeping the same block again does not duplicate it.
        leader_layers::keep(&c, 2);
        assert_eq!(leader_layers::len(), 2);
        // An unrelated block (a reorg) keeps nothing of the old chain.
        let (d, d_seal) = layer_of(300, B256::with_last_byte(0xb1), BundleState::default());
        leader_layers::keep(&d, 2);
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

    /// The fallback (loop333, `docs/SHARED_EXECUTION_SCOPE.md` 8.2): a
    /// great-grandparent not yet in the engine is waited for, and the open
    /// then stands on it with both layers -- it no longer waits for the
    /// grandparent, which the engine lands one import later.
    #[test]
    fn a_great_grandparent_not_in_the_engine_is_waited_for_with_both_layers_kept() {
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
        opener_on_sealed_parent_with(Scripted::new(mock()), gp.0.clone(), gp.1, 2)().expect("the first open");
        assert!(leader_layers::find(gp.0.hash()).is_some());
        let _ = open_wait::take();

        let mut client = Scripted::new(mock());
        client.missing.insert(ggp);
        // The grandparent itself is never asked for: were it, it would miss for good.
        client.missing.insert(gp.0.hash());
        let released = client.released.clone();
        let lander = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            released.store(true, Ordering::SeqCst);
            engine_landed::notify();
        });
        let at = std::time::Instant::now();
        let state = opener_on_sealed_parent_with(client, parent.0.clone(), parent.1, 2)().expect("waits, then opens");
        lander.join().expect("lander");
        let wait = open_wait::take();
        assert!(at.elapsed() < GRANDPARENT_WAIT, "found once it landed: {:?}", at.elapsed());
        assert_eq!((wait.grandparent_layer, wait.great_grandparent_missing, wait.layers), (1, 1, 2), "{}", wait.split());
        assert!(wait.fallback && wait.engine_wait_us >= 25_000, "{}", wait.split());
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd2)), Some(4), "the parent's write");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd1)), Some(2), "the grandparent's layer, not the engine");
    }

    #[test]
    fn any_other_error_on_the_great_grandparent_refuses_the_open() {
        let _guard = store_lock();
        let ggp = B256::with_last_byte(0xe1);
        let (gp, parent) = chain_of_two(ggp);
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), gp.0.clone(), gp.1, 2)().expect("the first open");
        let mut client = Scripted::new(MockEthProvider::default());
        client.fatal.insert(ggp);
        let result = opener_on_sealed_parent_with(client, parent.0.clone(), parent.1, 2)();
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
        opener_on_sealed_parent_with(Scripted::new(mock()), gp.0.clone(), gp.1, 2)().expect("the first open");
        let _ = open_wait::take();
        let state = opener_on_sealed_parent_with(Scripted::new(mock()), parent.0.clone(), parent.1, 2)().expect("opens on both layers");
        assert_eq!(open_wait::take().grandparent_layer, 1);
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd1)), Some(2), "the grandparent's layer");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd2)), Some(4), "the parent's layer");
        assert_eq!(nonce_of(&state, Address::with_last_byte(0xd3)), Some(7), "the engine's state under both");
    }

    // ---- N42_LEADER_LAYERS ----

    /// Files a build as its shard set and residual (before `StateReady`, as
    /// `N42_OUTPUT_SHARDS` does) and returns it with its seal.
    fn file_sharded(number: u64, parent_hash: B256, batch: BundleState, residual: BundleState) -> (SealedHeader, B256) {
        let header = Header { number, parent_hash, gas_used: number * 1_000, ..Default::default() };
        let execution = execution_of(&header, residual);
        let built_hash = execution.block.hash();
        let sealed = SealedHeader::seal_slow(Header { extra_data: format!("view {number}").into_bytes().into(), ..header });
        let shards = crate::output_shards::OutputShards::with_index_live(Address::with_last_byte(0x01), 4, 16, true, true);
        shards.add(batch);
        crate::built_executions::remember_pending(built_hash, execution.block.clone());
        crate::built_executions::shards_ready(
            built_hash,
            crate::built_executions::ShardedParent { residual: execution.execution_output.clone(), shards: Arc::new(shards.freeze()) },
        );
        (sealed, built_hash)
    }

    #[test]
    fn the_layer_count_parses_two_to_eight_and_defaults_to_two() {
        assert_eq!(leader_layers::parse_depth(None), Some(2));
        assert_eq!(leader_layers::parse_depth(Some("")), Some(2));
        assert_eq!(leader_layers::parse_depth(Some("2")), Some(2));
        assert_eq!(leader_layers::parse_depth(Some(" 3 ")), Some(3));
        assert_eq!(leader_layers::parse_depth(Some("4")), Some(4));
        assert_eq!(leader_layers::parse_depth(Some("6")), Some(6));
        assert_eq!(leader_layers::parse_depth(Some("8")), Some(8));
        for bad in ["1", "9", "0", "three", "-3"] {
            assert_eq!(leader_layers::parse_depth(Some(bad)), None, "{bad}");
        }
    }

    /// Three kept layers -- a full bundle, a shard set, a full bundle -- over
    /// the engine at the block under them read exactly as the engine's state
    /// once it has landed all three: every account each block wrote, one two
    /// of them wrote, one created, a slot, an untouched and an absent account,
    /// and `BLOCKHASH` of each.
    #[test]
    fn three_kept_layers_read_as_the_engine_after_it_landed_them() {
        let _guard = store_lock();
        leader_layers::clear();
        let x = Address::with_last_byte(0x71);
        let y = Address::with_last_byte(0x72);
        let z = Address::with_last_byte(0x73);
        let coinbase = Address::with_last_byte(0x74);
        let untouched = Address::with_last_byte(0x75);
        let created = Address::with_last_byte(0x76);
        let absent = Address::with_last_byte(0x77);
        let slot = B256::with_last_byte(7);
        let anchor = B256::with_last_byte(0x70);
        // The engine at the anchor (N-4), and after it landed N-3..N-1.
        let at_anchor = || {
            let m = MockEthProvider::default();
            m.add_account(x, ExtendedAccount::new(1, U256::from(10)));
            m.add_account(y, ExtendedAccount::new(5, U256::from(50)).extend_storage([(slot, U256::from(3))]));
            m.add_account(z, ExtendedAccount::new(7, U256::from(70)));
            m.add_account(coinbase, ExtendedAccount::new(0, U256::from(1)));
            m.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));
            m
        };
        let landed = MockEthProvider::default();
        landed.add_account(x, ExtendedAccount::new(3, U256::from(12)));
        landed.add_account(y, ExtendedAccount::new(6, U256::from(51)).extend_storage([(slot, U256::from(9))]));
        landed.add_account(z, ExtendedAccount::new(8, U256::from(71)));
        landed.add_account(coinbase, ExtendedAccount::new(0, U256::from(4)));
        landed.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));
        landed.add_account(created, ExtendedAccount::new(0, U256::from(7)));

        // N-3: x and z, the coinbase (a full bundle).
        let n3 = file_ready(
            171,
            anchor,
            BundleState::builder(171..=171)
                .state_present_account_info(x, info(2, 11))
                .state_present_account_info(z, info(8, 71))
                .state_present_account_info(coinbase, info(0, 2))
                .build(),
        );
        opener_on_sealed_parent_with(Scripted::new(at_anchor()), n3.0.clone(), n3.1, 3)().expect("N-2's build opens");
        // N-2: y and its slot, a created account; the coinbase in its residual (a shard set).
        let n2 = file_sharded(
            172,
            n3.0.hash(),
            BundleState::builder(172..=172)
                .state_original_account_info(y, info(5, 50))
                .state_present_account_info(y, info(6, 51))
                .state_storage(y, [(U256::from(7), (U256::from(3), U256::from(9)))].into_iter().collect())
                .state_original_account_info(created, info(0, 0))
                .state_present_account_info(created, info(0, 7))
                .build(),
            BundleState::builder(172..=172).state_present_account_info(coinbase, info(0, 3)).build(),
        );
        opener_on_sealed_parent_with(Scripted::new(at_anchor()), n2.0.clone(), n2.1, 3)().expect("N-1's build opens");
        // N-1: x again, the coinbase (a full bundle).
        let n1 = file_ready(
            173,
            n2.0.hash(),
            BundleState::builder(173..=173)
                .state_present_account_info(x, info(3, 12))
                .state_present_account_info(coinbase, info(0, 4))
                .build(),
        );
        let _ = open_wait::take();
        // N's build: N-4 is in the engine; nothing newer has to be.
        let mut client = Scripted::new(at_anchor());
        client.missing.extend([n3.0.hash(), n2.0.hash(), n1.0.hash()]);
        let layered = opener_on_sealed_parent_with(client, n1.0.clone(), n1.1, 3)().expect("N's build opens on three layers");
        let wait = open_wait::take();
        assert_eq!((wait.layers, wait.grandparent_layer, wait.fallback), (3, 1, false), "{}", wait.split());
        assert_eq!(leader_layers::len(), 3);
        let installed = landed.state_by_block_hash(B256::ZERO).expect("the landed state");

        let read = |state: &StateProviderBox, a: Address| state.basic_account(&a).expect("read").map(|a| (a.nonce, a.balance));
        for a in [x, y, z, coinbase, untouched, created, absent] {
            assert_eq!(read(&layered, a), read(&installed, a), "{a}: the layers read as the landed engine");
        }
        assert_eq!(layered.storage(y, slot).expect("read"), installed.storage(y, slot).expect("read"));
        assert_eq!(layered.storage(y, slot).expect("read"), Some(U256::from(9)));
        for (number, sealed) in [(171, &n3.0), (172, &n2.0), (173, &n1.0)] {
            assert_eq!(layered.block_hash(number).expect("read"), Some(sealed.hash()), "BLOCKHASH({number}) is the sealed hash");
        }
        // And as two layers over the engine at N-3 (today's default) does.
        let at_n3 = || {
            let m = at_anchor();
            m.add_account(x, ExtendedAccount::new(2, U256::from(11)));
            m.add_account(z, ExtendedAccount::new(8, U256::from(71)));
            m.add_account(coinbase, ExtendedAccount::new(0, U256::from(2)));
            m
        };
        let two = opener_on_sealed_parent_with(Scripted::new(at_n3()), n1.0.clone(), n1.1, 2)().expect("two layers");
        for a in [x, y, z, coinbase, untouched, created, absent] {
            assert_eq!(read(&two, a), read(&installed, a), "{a}: two layers over N-3 read the same");
        }
        leader_layers::clear();
    }

    /// Six kept layers (`docs/SHARED_EXECUTION_SCOPE.md` 18.7 item 2) --
    /// full bundles and shard sets alternating -- over the engine at N-7 read
    /// exactly as the engine's state once it has landed all six: every
    /// account each block wrote, one every block wrote, a slot written twice,
    /// one created, an untouched and an absent account, the coinbase from a
    /// residual or a bundle, and `BLOCKHASH` of each. The same reads at three
    /// and four layers over the engine at the matching deeper height are
    /// equal too, and the build store's `KEEP` (3) does not bound the count:
    /// the six blocks outlive their builds there as layers.
    #[test]
    fn six_kept_layers_read_as_the_engine_after_it_landed_them() {
        let _guard = store_lock();
        leader_layers::clear();
        const DEPTH: usize = 6;
        let own = |k: usize| Address::with_last_byte(0x90 + k as u8);
        let shared = Address::with_last_byte(0xa0);
        let slotted = Address::with_last_byte(0xa1);
        let created = Address::with_last_byte(0xa2);
        let coinbase = Address::with_last_byte(0xa3);
        let untouched = Address::with_last_byte(0xa4);
        let absent = Address::with_last_byte(0xa5);
        let slot = B256::with_last_byte(9);
        let anchor = B256::with_last_byte(0x8f);
        // The engine's state after `landed` of the six blocks.
        let engine_after = |landed: usize| {
            let m = MockEthProvider::default();
            for k in 0..DEPTH {
                let (nonce, balance) = if k < landed { (k as u64 + 2, 100 + k as u64) } else { (1, 10) };
                m.add_account(own(k), ExtendedAccount::new(nonce, U256::from(balance)));
            }
            let s = landed.checked_sub(1).map_or((0, 1), |k| (k as u64 + 1, 1000 + k as u64));
            m.add_account(shared, ExtendedAccount::new(s.0, U256::from(s.1)));
            let slot_value = [4usize, 1].into_iter().find(|k| *k < landed).map_or(0, |k| 10 * k as u64);
            m.add_account(slotted, ExtendedAccount::new(3, U256::from(30)).extend_storage([(slot, U256::from(slot_value))]));
            if landed > 2 {
                m.add_account(created, ExtendedAccount::new(0, U256::from(7)));
            }
            m.add_account(coinbase, ExtendedAccount::new(0, U256::from(landed as u64 + 1)));
            m.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));
            m
        };
        // Block k's writes; the coinbase is in the residual of a shard set
        // (odd k) and in the bundle of a full block (even k).
        let block = |k: usize, parent: B256| {
            let number = 191 + k as u64;
            let mut batch = BundleState::builder(number..=number)
                .state_original_account_info(own(k), info(1, 10))
                .state_present_account_info(own(k), info(k as u64 + 2, 100 + k as u64))
                .state_present_account_info(shared, info(k as u64 + 1, 1000 + k as u64));
            if k == 1 || k == 4 {
                let before = if k == 4 { 10 } else { 0 };
                batch = batch
                    .state_present_account_info(slotted, info(3, 30))
                    .state_storage(slotted, [(U256::from(9), (U256::from(before), U256::from(10 * k as u64)))].into_iter().collect());
            }
            if k == 2 {
                batch = batch
                    .state_original_account_info(created, info(0, 0))
                    .state_present_account_info(created, info(0, 7));
            }
            let coinbase_now = info(0, k as u64 + 2);
            if k % 2 == 1 {
                let residual = BundleState::builder(number..=number).state_present_account_info(coinbase, coinbase_now).build();
                file_sharded(number, parent, batch.build(), residual)
            } else {
                file_ready(number, parent, batch.state_present_account_info(coinbase, coinbase_now).build())
            }
        };
        let mut sealed = Vec::new();
        let mut parent = anchor;
        for k in 0..DEPTH {
            let filed = block(k, parent);
            parent = filed.0.hash();
            if k + 1 < DEPTH {
                // Block k's child opens on it: keeps its layer and its kept
                // ancestors, standing on the anchor.
                opener_on_sealed_parent_with(Scripted::new(engine_after(0)), filed.0.clone(), filed.1, DEPTH)()
                    .expect("the child's build opens");
            }
            sealed.push(filed);
        }
        let _ = open_wait::take();
        let last = &sealed[DEPTH - 1];
        // N's build: N-7 is in the engine; none of the six has to be.
        let mut client = Scripted::new(engine_after(0));
        client.missing.extend(sealed.iter().map(|(header, _)| header.hash()));
        let layered = opener_on_sealed_parent_with(client, last.0.clone(), last.1, DEPTH)().expect("N's build opens on six layers");
        let wait = open_wait::take();
        assert_eq!((wait.layers, wait.grandparent_layer, wait.fallback), (DEPTH as u32, 1, false), "{}", wait.split());
        assert_eq!(leader_layers::len(), DEPTH);
        assert!(wait.kept_accounts >= 6 * 3, "the kept layers' accounts are counted: {}", wait.split());
        assert_eq!(leader_layers::held(), (DEPTH, wait.kept_accounts as usize));

        let installed = engine_after(DEPTH).state_by_block_hash(B256::ZERO).expect("the landed state");
        let read = |state: &StateProviderBox, a: Address| state.basic_account(&a).expect("read").map(|a| (a.nonce, a.balance));
        let everyone: Vec<Address> =
            (0..DEPTH).map(own).chain([shared, slotted, created, coinbase, untouched, absent]).collect();
        for a in &everyone {
            assert_eq!(read(&layered, *a), read(&installed, *a), "{a}: six layers read as the landed engine");
        }
        assert_eq!(layered.storage(slotted, slot).expect("read"), Some(U256::from(40)), "the newer of two slot writes");
        assert_eq!(layered.storage(slotted, slot).expect("read"), installed.storage(slotted, slot).expect("read"));
        assert_eq!(read(&layered, coinbase), Some((0, U256::from(DEPTH as u64 + 1))), "the newest block's coinbase, from a residual");
        for (k, (header, _)) in sealed.iter().enumerate() {
            let number = 191 + k as u64;
            assert_eq!(layered.block_hash(number).expect("read"), Some(header.hash()), "BLOCKHASH({number}) is the sealed hash");
        }
        // Fewer layers over a deeper engine read the same (deepest first:
        // each open releases the layers past its own count).
        for depth in [4, 3] {
            let landed = DEPTH - depth;
            let _ = open_wait::take();
            let fewer = opener_on_sealed_parent_with(Scripted::new(engine_after(landed)), last.0.clone(), last.1, depth)()
                .expect("fewer layers");
            assert_eq!(open_wait::take().layers, depth as u32);
            for a in &everyone {
                assert_eq!(read(&fewer, *a), read(&installed, *a), "{a}: {depth} layers over N-{} read the same", depth + 1);
            }
            assert_eq!(fewer.storage(slotted, slot).expect("read"), Some(U256::from(40)));
        }
        leader_layers::clear();
    }

    /// The default (2) keeps two layers and stands on N-3, as before: N-4
    /// missing in the engine costs it nothing.
    #[test]
    fn at_two_layers_the_open_stands_on_the_great_grandparent_as_before() {
        let _guard = store_lock();
        leader_layers::clear();
        let anchor = B256::with_last_byte(0x80);
        let a = file_ready(181, anchor, BundleState::default());
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), a.0.clone(), a.1, 2)().expect("open");
        let b = file_ready(182, a.0.hash(), BundleState::default());
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), b.0.clone(), b.1, 2)().expect("open");
        let c = file_ready(183, b.0.hash(), BundleState::default());
        let _ = open_wait::take();
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(anchor);
        let at = std::time::Instant::now();
        opener_on_sealed_parent_with(client, c.0.clone(), c.1, 2)().expect("opens on N-3");
        let wait = open_wait::take();
        assert!(at.elapsed() < GRANDPARENT_WAIT);
        assert_eq!((wait.layers, wait.fallback), (2, false), "{}", wait.split());
        assert_eq!(leader_layers::len(), 2, "two blocks' layers");
        assert!(leader_layers::find(a.0.hash()).is_none(), "N-3 released");
        leader_layers::clear();
    }

    /// Every release event: the chain moving on (the count), an abandoned
    /// build's branch (a sibling kept), the engine's tip moving past (after a
    /// handover, when nothing more is kept here), and a block that does not
    /// descend from the kept ones.
    #[test]
    fn layers_are_released_at_each_release_event() {
        let _guard = store_lock();
        leader_layers::clear();
        let root = B256::with_last_byte(0x90);
        let (a, a_seal) = layer_of(191, root, BundleState::default());
        let (b, b_seal) = layer_of(192, a_seal.hash(), BundleState::default());
        let (c, c_seal) = layer_of(193, b_seal.hash(), BundleState::default());
        let (d, d_seal) = layer_of(194, c_seal.hash(), BundleState::default());
        // The count: at three, the fourth keep releases the oldest.
        assert_eq!(leader_layers::keep(&a, 3), 0);
        assert_eq!(leader_layers::keep(&b, 3), 0);
        assert_eq!(leader_layers::keep(&c, 3), 0);
        assert_eq!(leader_layers::keep(&d, 3), 1);
        assert!(leader_layers::find(a_seal.hash()).is_none());
        assert_eq!(leader_layers::ancestors(d_seal.hash(), 3).len(), 3);
        // An abandoned build: d never committed, the next build is on its sibling d'.
        let d2_seal = SealedHeader::seal_slow(Header {
            number: 194,
            parent_hash: c_seal.hash(),
            extra_data: b"layer 194b".as_slice().into(),
            ..Default::default()
        });
        let d2: leader_layers::Layer = (
            executed_from_output(&d2_seal, Arc::new(BlockExecutionOutput { result: Default::default(), state: BundleState::default() })),
            None,
        );
        assert_ne!(d2_seal.hash(), d_seal.hash());
        assert_eq!(leader_layers::keep(&d2, 3), 1, "the abandoned d is released");
        assert!(leader_layers::find(d_seal.hash()).is_none());
        assert!(leader_layers::find(b_seal.hash()).is_some() && leader_layers::find(c_seal.hash()).is_some());
        // The engine's tip: layers depth or more under it go; the rest stay.
        assert_eq!(leader_layers::on_canonical(194, 3), 0, "the tip at the newest keeps all");
        assert_eq!(leader_layers::on_canonical(195, 3), 1, "192 is three under 195");
        assert!(leader_layers::find(b_seal.hash()).is_none());
        // A handover to a layer elsewhere: no more keeps here, the tip moves on.
        assert_eq!(leader_layers::on_canonical(197, 3), 2);
        assert_eq!(leader_layers::len(), 0, "nothing is held after the handover");
        // A block that does not descend from the kept ones keeps only itself.
        leader_layers::keep(&b, 3);
        leader_layers::keep(&c, 3);
        let (e, e_seal) = layer_of(400, B256::with_last_byte(0x92), BundleState::default());
        assert_eq!(leader_layers::keep(&e, 3), 2);
        assert_eq!(leader_layers::len(), 1);
        assert!(leader_layers::find(e_seal.hash()).is_some());
        leader_layers::clear();
    }

    /// An abandoned build's layer is never read by the build on its sibling.
    #[test]
    fn a_build_on_a_sibling_reads_none_of_the_abandoned_build() {
        let _guard = store_lock();
        leader_layers::clear();
        let anchor = B256::with_last_byte(0xa0);
        let only_abandoned = Address::with_last_byte(0xa9);
        let gp = file_ready(201, anchor, BundleState::default());
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), gp.0.clone(), gp.1, 3)().expect("open");
        let abandoned = file_ready(202, gp.0.hash(), BundleState::builder(202..=202).state_present_account_info(only_abandoned, info(9, 9)).build());
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), abandoned.0.clone(), abandoned.1, 3)().expect("open");
        assert!(leader_layers::find(abandoned.0.hash()).is_some());
        let mut sibling_header = Header { number: 202, parent_hash: gp.0.hash(), gas_used: 1, ..Default::default() };
        sibling_header.extra_data = b"view 202b".as_slice().into();
        let execution = execution_of(&sibling_header, BundleState::default());
        let sibling_built = execution.block.hash();
        let sibling = SealedHeader::seal_slow(Header { extra_data: b"sealed 202b".as_slice().into(), ..sibling_header });
        crate::built_executions::remember_pending(sibling_built, execution.block.clone());
        crate::built_executions::state_ready(sibling_built, execution);
        let _ = open_wait::take();
        let state = opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), sibling.clone(), sibling_built, 3)().expect("opens");
        assert_eq!(open_wait::take().layers, 2, "the sibling and the shared grandparent");
        assert!(leader_layers::find(abandoned.0.hash()).is_none(), "the abandoned build is released");
        assert_eq!(nonce_of(&state, only_abandoned), None, "and nothing of it is read");
        leader_layers::clear();
    }

    /// A tenure handover at three layers. To a key on this execution layer:
    /// its builds' parents are this layer's sealed builds, so the chain of
    /// layers continues unchanged (the leader's key is invisible here). To a
    /// key elsewhere: nothing more is kept, and the engine's tip moving on
    /// releases what was.
    #[test]
    fn a_handover_with_three_layers_kept() {
        let _guard = store_lock();
        leader_layers::clear();
        let anchor = B256::with_last_byte(0xb0);
        let mut chain = Vec::new();
        let mut parent_hash = anchor;
        for number in 211..=215u64 {
            let filed = file_ready(number, parent_hash, BundleState::builder(number..=number).state_present_account_info(Address::with_last_byte(number as u8), info(number, 1)).build());
            parent_hash = filed.0.hash();
            let _ = open_wait::take();
            opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), filed.0.clone(), filed.1, 3)().expect("open");
            chain.push((number, filed, open_wait::take().layers));
        }
        // Blocks 211-213 led by key 0, 214-215 by key 1 on the same layer: the layers grow to three and stay.
        assert_eq!(chain.iter().map(|(_, _, layers)| *layers).collect::<Vec<_>>(), vec![1, 2, 3, 3, 3]);
        assert_eq!(leader_layers::len(), 3);
        // Then a key on another layer leads: its blocks come by import, the tip moves past ours.
        assert_eq!(leader_layers::on_canonical(216, 3), 1, "213 goes");
        assert_eq!(leader_layers::on_canonical(218, 3), 2, "214 and 215 go");
        assert_eq!(leader_layers::len(), 0);
        // Leading again later, on a block of the other layer: a build opens with its parent alone.
        let foreign = file_ready(219, B256::with_last_byte(0xb9), BundleState::default());
        let _ = open_wait::take();
        opener_on_sealed_parent_with(Scripted::new(MockEthProvider::default()), foreign.0.clone(), foreign.1, 3)().expect("open");
        assert_eq!(open_wait::take().layers, 1);
        leader_layers::clear();
    }

    /// The wait for an ancestor is woken by the engine's notification, not
    /// found by a poll: with a one-second slice it returns right after the
    /// landing, having slept once.
    #[test]
    fn the_wait_for_an_ancestor_is_woken_when_it_lands() {
        // Serialised with the other tests that notify.
        let _guard = store_lock();
        let _ = open_wait::take();
        let hash = B256::with_last_byte(0xc7);
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(hash);
        let released = client.released.clone();
        let lander = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(40));
            released.store(true, Ordering::SeqCst);
            engine_landed::notify();
        });
        let at = std::time::Instant::now();
        let state = state_when_landed(&client, hash, at + std::time::Duration::from_secs(5), std::time::Duration::from_secs(1));
        let elapsed = at.elapsed();
        lander.join().expect("lander");
        assert!(state.is_ok());
        assert!(elapsed >= std::time::Duration::from_millis(35) && elapsed < std::time::Duration::from_millis(500), "{elapsed:?}");
        assert_eq!(client.calls.load(Ordering::SeqCst), 2, "one look before, one after the wake-up");
        assert_eq!(open_wait::take().grandparent_polls, 1);
        // And the bound still holds when nothing lands.
        let mut client = Scripted::new(MockEthProvider::default());
        client.missing.insert(hash);
        let at = std::time::Instant::now();
        let result = state_when_landed(&client, hash, at + std::time::Duration::from_millis(60), std::time::Duration::from_secs(1));
        assert!(is_miss(&result));
        assert!(at.elapsed() >= std::time::Duration::from_millis(60) && at.elapsed() < std::time::Duration::from_millis(500));
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

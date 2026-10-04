// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `N42_FIELDS_AT_SEAL`: when the leader's own execution fields of a block
//! sealed early become available to the child's seal.
//!
//! Under deferred execution block N+1's header carries N's state root,
//! receipts root, logs bloom and gas used, and the chained build of N+1
//! (started at N's seal) waits for them in `executed_fields::wait_for`. The
//! only writer on the leader is N's own finish behind its seal, right after
//! N's QMDB root job. That job runs on N-1's tree under N-1's *sealed* hash,
//! and N-1's tree is filed under the hash its builder gave it; the finish
//! used to rename it only after waiting for N-1's `Complete` stage -- N-1's
//! shard merge and hashed post-state, ~185 ms after N-1's seal, i.e. ~70-80
//! ms after N's seal (INDUSTRY_SURVEY_2026_10 11.8).
//!
//! Nothing the rename reads comes from N-1's `Complete`: the record it moves
//! is filed (`QmdbNodeState::insert`) before N-1's fields are remembered, and
//! N's own seal waited for those fields. So with the switch on the parent's
//! tree is renamed the moment its record is there, and N's root job starts
//! as soon as N's own output (the shard view) exists. The values are the same
//! values: the same record, the same operations, the same receipts.
//!
//! `N42_FIELDS_AT_SEAL=verify` takes the early path and, behind `Complete`,
//! derives the fields' inputs again the late way (the operations from the
//! merged bundle, the parent's root after the parent's `Complete`, the
//! receipts root and gas from the merged output) and counts mismatches.

use alloy_primitives::{Bloom, B256};
use std::sync::atomic::{AtomicU64, Ordering};

/// What `N42_FIELDS_AT_SEAL` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Unset or `0`: the parent's tree is renamed after the parent's
    /// `Complete`, as before.
    Off,
    /// `1`: renamed as soon as the parent's record is filed.
    Early,
    /// `verify`: [`Mode::Early`], and the late derivation compared behind
    /// `Complete`.
    Verify,
}

impl Mode {
    /// The mode a value of the variable names; anything unknown is off.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("1") => Self::Early,
            Some("verify") => Self::Verify,
            _ => Self::Off,
        }
    }

    /// Whether the parent's tree is renamed without waiting for its `Complete`.
    pub const fn early(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Whether the late derivation is computed and compared.
    pub const fn verify(self) -> bool {
        matches!(self, Self::Verify)
    }

    /// The label on the phases line.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Early => "early",
            Self::Verify => "verify",
        }
    }
}

/// The process's mode, read once.
pub fn mode() -> Mode {
    static MODE: std::sync::OnceLock<Mode> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| Mode::parse(std::env::var("N42_FIELDS_AT_SEAL").ok().as_deref()))
}

/// How the parent's tree reached its sealed hash before this block's root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParentFiled {
    /// Microseconds spent waiting for the parent's `Complete`.
    pub waited_us: u64,
    /// Whether this call renamed the record.
    pub renamed: bool,
    /// Whether the rename was made on the filed record without the wait.
    pub early: bool,
    /// Whether the wait for the parent's `Complete` ran.
    pub waited: bool,
}

/// Files the parent's QMDB tree under `parent_sealed`, where this block's
/// root job looks for it.
///
/// Nothing to do when the tree is there already (the own import or an
/// earlier build renamed it), or when the parent has no builder hash of its
/// own (a peer's block executed as a follower: filed under its sealed hash by
/// that import). Otherwise, with `early`, a record already filed under
/// `parent_built` is renamed at once; in every other case `wait_complete`
/// runs first (the parent's `Complete`, as before) and the rename follows if
/// it is still needed. The rename itself is the same call either way
/// (`chain_alias::rename`, which an own import's later rename of the same
/// record tolerates).
pub fn file_parent_under_seal(
    qmdb: &n42_qmdb_reth::QmdbNodeState,
    parent_sealed: B256,
    parent_built: Option<B256>,
    early: bool,
    wait_complete: impl FnOnce(),
) -> Result<ParentFiled, n42_qmdb_reth::NodeStateError> {
    let mut filed = ParentFiled::default();
    if qmdb.root_of(&parent_sealed).is_some() {
        return Ok(filed);
    }
    let Some(built) = parent_built.filter(|built| *built != parent_sealed) else {
        return Ok(filed);
    };
    if early && qmdb.root_of(&built).is_some() {
        crate::chain_alias::rename(qmdb, built, parent_sealed)?;
        filed.renamed = true;
        filed.early = true;
        return Ok(filed);
    }
    let at = std::time::Instant::now();
    wait_complete();
    filed.waited = true;
    filed.waited_us = at.elapsed().as_micros() as u64;
    if qmdb.root_of(&parent_sealed).is_none() {
        crate::chain_alias::rename(qmdb, built, parent_sealed)?;
        filed.renamed = true;
    }
    Ok(filed)
}

/// What the early path published a block's fields from.
#[derive(Debug, Clone)]
pub struct EarlyInputs<O> {
    /// The fields as published.
    pub fields: crate::executed_fields::ExecutedFields,
    /// The QMDB operations the root job applied.
    pub ops: O,
    /// The parent's root as the root job found it under the sealed hash.
    pub parent_root: Option<B256>,
}

/// The same inputs derived the late way, behind `Complete`.
#[derive(Debug, Clone)]
pub struct LateInputs<O> {
    /// The operations from the block's merged bundle.
    pub ops: O,
    /// The parent's root under its sealed hash after the parent's `Complete`.
    pub parent_root: Option<B256>,
    /// The receipts root and logs bloom of the merged output's receipts.
    pub receipts: (B256, Bloom),
    /// The merged output's gas used.
    pub gas_used: u64,
}

/// One input the two paths disagree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// The QMDB operations differ, so the state root would.
    StateOps,
    /// The parent's tree under its sealed hash has a different root.
    ParentRoot,
    /// The receipts root.
    ReceiptsRoot,
    /// The logs bloom.
    LogsBloom,
    /// The gas used.
    GasUsed,
}

/// The outcome of one comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every input equal: the late path would publish the same bytes.
    Equal,
    /// The parent's root could not be read on one side (its record already
    /// persisted away); everything else equal.
    Unchecked,
    /// The inputs that differ.
    Differ(Vec<Mismatch>),
}

/// Compares what the early path published from with the late derivation.
/// The QMDB root is a deterministic function of the parent's tree and the
/// operations, so equal operations on the same parent root mean an equal
/// state root without computing it twice on the live forest.
pub fn compare<O: PartialEq>(early: &EarlyInputs<O>, late: &LateInputs<O>) -> Verdict {
    let mut differ = Vec::new();
    if early.ops != late.ops {
        differ.push(Mismatch::StateOps);
    }
    let parent_known = early.parent_root.is_some() && late.parent_root.is_some();
    if parent_known && early.parent_root != late.parent_root {
        differ.push(Mismatch::ParentRoot);
    }
    if early.fields.receipts_root != late.receipts.0 {
        differ.push(Mismatch::ReceiptsRoot);
    }
    if early.fields.logs_bloom != late.receipts.1 {
        differ.push(Mismatch::LogsBloom);
    }
    if early.fields.gas_used != late.gas_used {
        differ.push(Mismatch::GasUsed);
    }
    if !differ.is_empty() {
        Verdict::Differ(differ)
    } else if parent_known {
        Verdict::Equal
    } else {
        Verdict::Unchecked
    }
}

static CHECKED: AtomicU64 = AtomicU64::new(0);
static UNCHECKED: AtomicU64 = AtomicU64::new(0);
static MISMATCHED: AtomicU64 = AtomicU64::new(0);

/// Counts a verdict for the phases line.
pub fn note(verdict: &Verdict) {
    match verdict {
        Verdict::Equal => CHECKED.fetch_add(1, Ordering::Relaxed),
        Verdict::Unchecked => UNCHECKED.fetch_add(1, Ordering::Relaxed),
        Verdict::Differ(_) => MISMATCHED.fetch_add(1, Ordering::Relaxed),
    };
}

/// The process's counts so far: blocks equal, blocks whose parent root could
/// not be read on one side, blocks that differ.
pub fn counts() -> (u64, u64, u64) {
    (CHECKED.load(Ordering::Relaxed), UNCHECKED.load(Ordering::Relaxed), MISMATCHED.load(Ordering::Relaxed))
}

/// Microseconds from `from` to `to`, 0 when either is missing or `to` came first.
pub fn us_between(from: Option<std::time::Instant>, to: Option<std::time::Instant>) -> u64 {
    match (from, to) {
        (Some(from), Some(to)) => to.saturating_duration_since(from).as_micros() as u64,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_reads_off_early_and_verify() {
        assert_eq!(Mode::parse(None), Mode::Off);
        assert_eq!(Mode::parse(Some("0")), Mode::Off);
        assert_eq!(Mode::parse(Some("yes")), Mode::Off);
        assert_eq!(Mode::parse(Some("1")), Mode::Early);
        assert_eq!(Mode::parse(Some("verify")), Mode::Verify);
        assert!(!Mode::Off.early() && !Mode::Off.verify());
        assert!(Mode::Early.early() && !Mode::Early.verify());
        assert!(Mode::Verify.early() && Mode::Verify.verify());
    }

    use crate::executed_fields::ExecutedFields;
    use crate::output_shards::{FrozenShards, OutputShards};
    use alloy_primitives::{Address, U256};
    use n42_qmdb_reth::QmdbNodeState;
    use revm::{database::BundleState, state::AccountInfo};
    use std::sync::Arc;

    fn addr(i: u8) -> Address {
        Address::with_last_byte(i)
    }

    fn info(nonce: u64, balance: u64) -> AccountInfo {
        AccountInfo { nonce, balance: U256::from(balance), ..Default::default() }
    }

    /// A QMDB chain whose headers carry their parent's execution from genesis.
    fn chain() -> Arc<reth_chainspec::ChainSpec> {
        let mut genesis: alloy_genesis::Genesis = serde_json::from_str(
            r#"{
                "config": { "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0, "pragueTime": 0, "stateScheme": "qmdb" },
                "alloc": { "0x0000000000000000000000000000000000000002": { "balance": "0x64" } },
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
                "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000",
                "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#,
        )
        .expect("genesis json");
        genesis
            .config
            .extra_fields
            .insert(reth_chainspec::qmdb::DEFERRED_EXECUTION_TIME_KEY.to_owned(), serde_json::json!(0));
        Arc::new(n42_qmdb_reth::with_declared_state_scheme(genesis.into()).expect("a qmdb chain"))
    }

    /// A forest at genesis in a scratch directory of its own.
    fn forest(name: &str) -> (QmdbNodeState, B256) {
        let chain = chain();
        let dir = std::env::temp_dir().join(format!("n42-fields-at-seal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = QmdbNodeState::new(chain.clone(), dir);
        state.initialize((0, chain.genesis_hash())).expect("genesis seeded");
        (state, chain.genesis_hash())
    }

    /// Block N-1's output: two accounts moved.
    fn parent_bundle() -> BundleState {
        BundleState::builder(1..=1)
            .state_original_account_info(addr(2), info(0, 100))
            .state_present_account_info(addr(2), info(1, 60))
            .state_present_account_info(addr(3), info(0, 40))
            .build()
    }

    /// Block N's output as the leader holds it at the seal: the batches'
    /// shards, and the executor's residual (a withdrawal to a shard account,
    /// and a new account).
    fn child_output() -> (FrozenShards, BundleState) {
        let shards = OutputShards::with_index_live(addr(1), 8, 4, false, false);
        let mut batch = BundleState::builder(2..=2);
        for (a, (n0, b0), (n1, b1)) in [(3u8, (0u64, 40u64), (1u64, 30u64)), (4, (0, 0), (0, 10)), (2, (1, 60), (2, 50))] {
            batch = batch.state_original_account_info(addr(a), info(n0, b0)).state_present_account_info(addr(a), info(n1, b1));
        }
        shards.add(batch.build());
        let residual = BundleState::builder(2..=2)
            .state_original_account_info(addr(3), info(1, 30))
            .state_present_account_info(addr(3), info(1, 35))
            .state_present_account_info(addr(9), info(0, 5))
            .build();
        (shards.freeze(), residual)
    }

    fn receipts() -> Vec<n42_tx_types::Receipt> {
        (1..=3u64)
            .map(|i| {
                let mut receipt = n42_tx_types::Receipt::default();
                receipt.success = true;
                receipt.cumulative_gas_used = 21_000 * i;
                receipt
            })
            .collect()
    }

    /// Files block N-1 under the hash its builder gave it, as its finish does.
    fn file_parent(state: &QmdbNodeState, genesis: B256, built: B256) {
        let ops = n42_qmdb_reth::sorted_operations_from_execution(&parent_bundle(), true);
        let prepared = state.compute_operations(genesis, ops).expect("parent root");
        state.insert(built, 1, prepared).expect("parent filed");
    }

    /// Block N's finish from the parent's rename to its fields: the shard
    /// view's operations for the root, the receipts root beside it, then the
    /// tree filed before the fields are remembered.
    fn finish_child(
        state: &QmdbNodeState,
        parent_sealed: B256,
        parent_built: B256,
        child_built: B256,
        early: bool,
        wait: impl FnOnce(),
    ) -> (ParentFiled, EarlyInputs<n42_twig_core::qmdb_ops::QmdbOps>) {
        let filed = file_parent_under_seal(state, parent_sealed, Some(parent_built), early, wait).expect("parent filed");
        let parent_root = state.root_of(&parent_sealed);
        let (shards, residual) = child_output();
        let overlaps = shards.overlaps(&residual);
        let view = shards.view(&residual, &overlaps);
        let ops = n42_qmdb_reth::sorted_operations_from_accounts(&view, true);
        let prepared = state.compute_operations(parent_sealed, ops.clone()).expect("child root");
        let (receipts_root, logs_bloom) = crate::hotstuff_consensus::gov5_receipt_root_bloom(&receipts());
        let fields = ExecutedFields { state_root: prepared.root, receipts_root, logs_bloom, gas_used: 63_000 };
        state.insert(child_built, 2, prepared).expect("child filed");
        crate::executed_fields::remember(child_built, fields);
        (filed, EarlyInputs { fields, ops, parent_root })
    }

    /// The late derivation behind `Complete`: the merged bundle's operations.
    fn late_inputs(state: &QmdbNodeState, parent_sealed: B256) -> LateInputs<n42_twig_core::qmdb_ops::QmdbOps> {
        let (shards, residual) = child_output();
        let merged = shards.merged(&residual);
        LateInputs {
            ops: n42_qmdb_reth::sorted_operations_from_execution(&merged, true),
            parent_root: state.root_of(&parent_sealed),
            receipts: crate::hotstuff_consensus::gov5_receipt_root_bloom(&receipts()),
            gas_used: 63_000,
        }
    }

    #[test]
    fn early_and_late_publish_the_same_fields_on_a_built_block() {
        let parent_built = B256::repeat_byte(0xe1);
        let parent_sealed = B256::repeat_byte(0xe2);
        let child_built = B256::repeat_byte(0xe3);

        // Early: the parent's record is filed, so it is renamed without the wait.
        let (early_forest, genesis) = forest("equal-early");
        file_parent(&early_forest, genesis, parent_built);
        let waited = std::cell::Cell::new(false);
        let (filed, early) = finish_child(&early_forest, parent_sealed, parent_built, child_built, true, || waited.set(true));
        assert!(filed.early && filed.renamed && !filed.waited && !waited.get());

        // Late, on a forest of its own: the wait, then the rename.
        let (late_forest, genesis) = forest("equal-late");
        file_parent(&late_forest, genesis, parent_built);
        let (filed, late) = finish_child(&late_forest, parent_sealed, parent_built, B256::repeat_byte(0xe4), false, || {});
        assert!(!filed.early && filed.renamed && filed.waited);

        assert_eq!(early.fields, late.fields, "the same bytes either way");
        assert_eq!(early_forest.root_of(&child_built), Some(early.fields.state_root));
        assert_eq!(crate::executed_fields::get(&child_built), Some(early.fields));
        // And `verify`'s late derivation agrees with what was published.
        assert_eq!(compare(&early, &late_inputs(&early_forest, parent_sealed)), Verdict::Equal);
    }

    #[test]
    fn verify_names_each_input_that_differs() {
        let parent_built = B256::repeat_byte(0xd1);
        let parent_sealed = B256::repeat_byte(0xd2);
        let (state, genesis) = forest("verify-differs");
        file_parent(&state, genesis, parent_built);
        let (_, early) = finish_child(&state, parent_sealed, parent_built, B256::repeat_byte(0xd3), true, || {});
        let mut late = late_inputs(&state, parent_sealed);
        late.gas_used += 1;
        late.receipts.0 = B256::repeat_byte(0x99);
        late.ops = n42_qmdb_reth::sorted_operations_from_execution(&parent_bundle(), true);
        assert_eq!(
            compare(&early, &late),
            Verdict::Differ(vec![Mismatch::StateOps, Mismatch::ReceiptsRoot, Mismatch::GasUsed])
        );
        let mut late = late_inputs(&state, parent_sealed);
        late.parent_root = Some(B256::repeat_byte(0x98));
        assert_eq!(compare(&early, &late), Verdict::Differ(vec![Mismatch::ParentRoot]));
        // A parent persisted away on one side is not a mismatch, only unchecked.
        late.parent_root = None;
        assert_eq!(compare(&early, &late), Verdict::Unchecked);
    }

    #[test]
    fn switched_off_the_rename_still_waits_for_the_parents_complete() {
        let parent_built = B256::repeat_byte(0xc1);
        let parent_sealed = B256::repeat_byte(0xc2);
        let (state, genesis) = forest("off-waits");
        file_parent(&state, genesis, parent_built);
        // The record is there, but off means the old order: wait, then rename.
        let waited = std::cell::Cell::new(false);
        let filed = file_parent_under_seal(&state, parent_sealed, Some(parent_built), Mode::Off.early(), || {
            assert!(state.root_of(&parent_built).is_some(), "nothing renamed before the wait");
            waited.set(true);
        })
        .expect("filed");
        assert!(waited.get() && filed.waited && filed.renamed && !filed.early);
        assert!(state.root_of(&parent_built).is_none() && state.root_of(&parent_sealed).is_some());
    }

    #[test]
    fn switched_on_a_parent_not_yet_filed_falls_back_to_the_wait() {
        let parent_built = B256::repeat_byte(0xb1);
        let parent_sealed = B256::repeat_byte(0xb2);
        let (state, genesis) = forest("on-unfiled");
        // The parent's finish files its tree during the wait.
        let filed = file_parent_under_seal(&state, parent_sealed, Some(parent_built), true, || {
            file_parent(&state, genesis, parent_built);
        })
        .expect("filed");
        assert!(filed.waited && filed.renamed && !filed.early);
        assert!(state.root_of(&parent_sealed).is_some());
        // The own import's later rename of the same record is a no-op, not an error.
        crate::chain_alias::rename(&state, parent_built, parent_sealed).expect("idempotent");
    }

    #[test]
    fn a_block_sealed_but_never_committed_is_never_read_by_the_winning_chain() {
        let parent_built = B256::repeat_byte(0xa1);
        let parent_sealed = B256::repeat_byte(0xa2);
        let (state, genesis) = forest("lost-sibling");
        file_parent(&state, genesis, parent_built);
        // The leader seals block N (builder hash 0xa3) and publishes its fields
        // early; consensus never commits it.
        let (_, lost) = finish_child(&state, parent_sealed, parent_built, B256::repeat_byte(0xa3), true, || {});
        // The block that wins at height N on the same parent (another view, a
        // different body): its own operations, its own tree and fields.
        let won_built = B256::repeat_byte(0xa4);
        let won_ops = n42_qmdb_reth::sorted_operations_from_execution(
            &BundleState::builder(2..=2)
                .state_original_account_info(addr(2), info(1, 60))
                .state_present_account_info(addr(2), info(2, 55))
                .build(),
            true,
        );
        let prepared = state.compute_operations(parent_sealed, won_ops.clone()).expect("winner root");
        let won_root = prepared.root;
        state.insert(won_built, 2, prepared).expect("winner filed");
        let won = ExecutedFields { state_root: won_root, ..lost.fields };
        crate::executed_fields::remember(won_built, won);
        assert_ne!(won.state_root, lost.fields.state_root);

        // The same root a forest that never saw the lost block computes.
        let (clean, genesis) = forest("lost-sibling-clean");
        file_parent(&clean, genesis, parent_built);
        clean.rename(parent_built, parent_sealed).expect("renamed");
        assert_eq!(clean.compute_operations(parent_sealed, won_ops).expect("clean root").root, won_root);

        // The child of the winner reads the winner's fields: under its sealed
        // hash, falling back to its builder hash. Nothing keyed by the lost
        // block's hash is on that path.
        let mut header = alloy_consensus::Header { number: 2, timestamp: 2, ..Default::default() };
        header.parent_hash = parent_sealed;
        let won_sealed = reth_primitives_traits::SealedHeader::seal_slow(header);
        let found = crate::hotstuff_consensus::parent_executed_fields_or_built(
            chain().genesis(),
            &won_sealed,
            Some(won_built),
            std::time::Duration::from_millis(50),
        );
        assert_eq!(found, Some(won));
        assert_eq!(crate::executed_fields::get(&won_sealed.hash()), Some(won));
    }

    #[test]
    fn the_stamps_are_relative_and_never_negative() {
        let a = std::time::Instant::now();
        let b = a + std::time::Duration::from_micros(250);
        assert_eq!(us_between(Some(a), Some(b)), 250);
        assert_eq!(us_between(Some(b), Some(a)), 0);
        assert_eq!(us_between(None, Some(b)), 0);
    }
}

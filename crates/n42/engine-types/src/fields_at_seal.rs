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

    #[test]
    fn the_stamps_are_relative_and_never_negative() {
        let a = std::time::Instant::now();
        let b = a + std::time::Duration::from_micros(250);
        assert_eq!(us_between(Some(a), Some(b)), 250);
        assert_eq!(us_between(Some(b), Some(a)), 0);
        assert_eq!(us_between(None, Some(b)), 0);
    }
}

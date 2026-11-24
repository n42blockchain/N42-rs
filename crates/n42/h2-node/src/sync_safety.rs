// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The range catch-up's safety rule (sync standard §3.3): a conflict or an
//! anchor equivocation halts the sync importer.
//!
//! - **Conflict**: an authenticated chain that does not join this node's
//!   committed chain -- a verified anchor (or a block authenticated below
//!   one) at a height this node committed, with another hash. A safety
//!   violation: the importer stops, alerts, and neither executes nor
//!   reorgs. Consensus keeps running on its own chain.
//! - **Equivocation**: two verified anchors from peers for different blocks
//!   at one height (or two commit QCs for different blocks at one view).
//!   The same halt, and both certificates are kept as evidence (mixed
//!   production standard E15). The relaying peer is not blamed: a verified
//!   QC is the signers' act, not the relay's.
//!
//! [`SyncSafety`] records what is certified by height and by view, for this
//! node's own commits and for anchors whose height is authenticated (a block
//! whose header this node holds hashes to it), and says when a new one
//! contradicts a recorded one.

use alloy_primitives::B256;
use n42_h2_primitives::consensus::QuorumCertificate;
use std::collections::{BTreeMap, VecDeque};

/// Gauge, label `reason` (`conflict` | `equivocation`): 1 once the sync
/// importer halted on a safety violation.
pub const METRIC_SYNC_HALTED: &str = "n42_h2_sync_halted";

/// Counter: anchor equivocations seen (two verified commit QCs for
/// different blocks at one height or view), evidence kept.
pub const METRIC_SYNC_EQUIVOCATIONS_TOTAL: &str = "n42_h2_sync_anchor_equivocations_total";

/// Records kept per index (height, view); the lowest go first.
const MAX_RECORDS: usize = 4096;

/// Equivocation evidence kept; the oldest goes first.
const MAX_EVIDENCE: usize = 64;

/// Where a certified record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// This node's own commit (live, or restored at start).
    Committed,
    /// A verified anchor a peer's data carried, or a pulled block
    /// authenticated below one.
    Anchor,
}

/// One certified block: its hash, its height when authenticated, and the
/// certificate behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certified {
    /// The certified block.
    pub hash: B256,
    /// Its height, when a header that hashes to it was held.
    pub number: Option<u64>,
    /// The commit QC that certifies it: one naming it, or (a block
    /// authenticated by descent) one naming a descendant.
    pub qc: QuorumCertificate,
    /// Whose certification it is.
    pub origin: Origin,
}

/// What halted the sync importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltKind {
    /// An authenticated chain that does not join the committed head.
    Conflict,
    /// Two verified anchors for different blocks at one height or view.
    Equivocation,
}

impl HaltKind {
    /// The metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Equivocation => "equivocation",
        }
    }
}

/// A safety violation the sync importer halted on, with both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHalt {
    /// Conflict or equivocation.
    pub kind: HaltKind,
    /// What was recorded first (for a conflict, this node's side).
    pub first: Certified,
    /// What contradicted it.
    pub second: Certified,
}

/// Certified blocks by height and by view, and the first violation seen.
#[derive(Debug, Default)]
pub(crate) struct SyncSafety {
    by_height: BTreeMap<u64, Certified>,
    by_view: BTreeMap<u64, Certified>,
    halt: Option<SyncHalt>,
    evidence: VecDeque<SyncHalt>,
}

impl SyncSafety {
    /// The violation the importer halted on, if any.
    pub(crate) const fn halt(&self) -> Option<&SyncHalt> {
        self.halt.as_ref()
    }

    /// Every equivocation seen, oldest first (bounded).
    pub(crate) const fn evidence(&self) -> &VecDeque<SyncHalt> {
        &self.evidence
    }

    /// The highest block this node committed, by its records.
    pub(crate) fn committed_head(&self) -> Option<(u64, B256)> {
        self.by_height.iter().rev().find(|(_, c)| c.origin == Origin::Committed).map(|(n, c)| (*n, c.hash))
    }

    /// The block this node committed at `number`, when recorded.
    #[cfg(test)]
    pub(crate) fn committed_at(&self, number: u64) -> Option<B256> {
        self.by_height.get(&number).filter(|c| c.origin == Origin::Committed).map(|c| c.hash)
    }

    /// This node committed `qc.block_hash` (at `number`, when known). A
    /// verified anchor recorded before for another block at that height or
    /// view is a conflict.
    pub(crate) fn note_committed(&mut self, number: Option<u64>, qc: &QuorumCertificate) -> Result<(), SyncHalt> {
        if qc.view == 0 {
            return Ok(());
        }
        self.record(Certified { hash: qc.block_hash, number, qc: qc.clone(), origin: Origin::Committed })
    }

    /// A verified anchor (or a block authenticated below one): `hash` at
    /// `number` when its height is authenticated, certified by `qc`.
    pub(crate) fn note_anchor(&mut self, number: Option<u64>, hash: B256, qc: &QuorumCertificate) -> Result<(), SyncHalt> {
        if qc.view == 0 {
            return Ok(());
        }
        self.record(Certified { hash, number, qc: qc.clone(), origin: Origin::Anchor })
    }

    /// Records `new`, or returns the violation it makes. A violation is
    /// kept: the first as the halt, equivocations as evidence.
    fn record(&mut self, new: Certified) -> Result<(), SyncHalt> {
        let by_height = new.number.and_then(|n| self.by_height.get(&n)).filter(|old| old.hash != new.hash);
        // A view's commit QC names one block: only a QC naming `new` itself
        // is compared by view.
        let by_view = (new.qc.block_hash == new.hash)
            .then(|| self.by_view.get(&new.qc.view))
            .flatten()
            .filter(|old| old.hash != new.hash && old.qc.block_hash == old.hash);
        if let Some(old) = by_height.or(by_view).cloned() {
            let kind = if old.origin == Origin::Committed || new.origin == Origin::Committed {
                HaltKind::Conflict
            } else {
                HaltKind::Equivocation
            };
            // For a conflict, this node's side first.
            let (first, second) = if new.origin == Origin::Committed && old.origin != Origin::Committed {
                (new, old)
            } else {
                (old, new)
            };
            let halt = SyncHalt { kind, first, second };
            if kind == HaltKind::Equivocation {
                if self.evidence.len() >= MAX_EVIDENCE {
                    self.evidence.pop_front();
                }
                self.evidence.push_back(halt.clone());
            }
            if self.halt.is_none() {
                self.halt = Some(halt.clone());
            }
            return Err(halt);
        }
        if let Some(number) = new.number {
            // This node's commit takes the place of an anchor's record.
            let keep_old = self.by_height.get(&number).is_some_and(|old| old.origin == Origin::Committed);
            if !keep_old {
                self.by_height.insert(number, new.clone());
            }
            while self.by_height.len() > MAX_RECORDS {
                self.by_height.pop_first();
            }
        }
        if new.qc.block_hash == new.hash {
            self.by_view.entry(new.qc.view).or_insert(new);
            while self.by_view.len() > MAX_RECORDS {
                self.by_view.pop_first();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qc(view: u64, hash: B256) -> QuorumCertificate {
        let mut qc = QuorumCertificate::genesis();
        qc.view = view;
        qc.block_hash = hash;
        qc
    }

    #[test]
    fn an_anchor_at_a_committed_height_with_another_hash_is_a_conflict() {
        let mut s = SyncSafety::default();
        let (ours, theirs) = (B256::repeat_byte(1), B256::repeat_byte(2));
        s.note_committed(Some(10), &qc(12, ours)).expect("first");
        assert_eq!(s.committed_head(), Some((10, ours)));
        s.note_anchor(Some(10), ours, &qc(12, ours)).expect("the same block agrees");
        let halt = s.note_anchor(Some(10), theirs, &qc(15, theirs)).expect_err("a conflict");
        assert_eq!(halt.kind, HaltKind::Conflict);
        assert_eq!((halt.first.hash, halt.first.qc.view), (ours, 12));
        assert_eq!((halt.second.hash, halt.second.qc.view), (theirs, 15));
        assert_eq!(s.halt(), Some(&halt));
        assert!(s.evidence().is_empty(), "a conflict is not an equivocation");
        assert_eq!(s.committed_at(10), Some(ours), "the record stays this node's");
    }

    #[test]
    fn two_anchors_for_different_blocks_at_one_height_or_view_are_an_equivocation() {
        let mut s = SyncSafety::default();
        let (a, b, c) = (B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3));
        s.note_anchor(Some(5), a, &qc(7, a)).expect("first");
        let halt = s.note_anchor(Some(5), b, &qc(9, b)).expect_err("same height");
        assert_eq!(halt.kind, HaltKind::Equivocation);
        assert_eq!((halt.first.qc.view, halt.second.qc.view), (7, 9));
        // By view, the height unknown.
        let again = s.note_anchor(None, c, &qc(7, c)).expect_err("same view");
        assert_eq!(again.kind, HaltKind::Equivocation);
        assert_eq!(s.evidence().len(), 2, "both kept as evidence");
        assert_eq!(s.halt().map(|h| h.second.hash), Some(b), "the first violation is the halt");
    }

    #[test]
    fn a_block_authenticated_by_descent_is_compared_by_height_only() {
        let mut s = SyncSafety::default();
        let (a, b, top) = (B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(9));
        s.note_committed(Some(3), &qc(4, a)).expect("ours");
        // Certified by a QC naming a descendant: not a record of view 6.
        s.note_anchor(Some(4), b, &qc(6, top)).expect("above the commit");
        s.note_anchor(None, top, &qc(6, top)).expect("view 6 names `top` only");
        assert!(s.note_anchor(Some(3), b, &qc(6, top)).is_err(), "another block at the committed height");
    }

    #[test]
    fn a_commit_after_a_contradicting_anchor_is_a_conflict_too() {
        let mut s = SyncSafety::default();
        let (a, b) = (B256::repeat_byte(1), B256::repeat_byte(2));
        s.note_anchor(Some(8), a, &qc(10, a)).expect("anchor");
        let halt = s.note_committed(Some(8), &qc(11, b)).expect_err("conflict");
        assert_eq!(halt.kind, HaltKind::Conflict);
        assert_eq!(halt.first.origin, Origin::Committed, "this node's side first");
        assert!(s.note_committed(None, &QuorumCertificate::genesis()).is_ok(), "genesis is no record");
    }
}

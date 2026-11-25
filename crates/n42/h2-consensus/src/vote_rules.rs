// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vote and execution-write rules of the mixed production standard's
//! profile 1 (`docs/MIXED_PRODUCTION_STANDARD.md` A13, E6-E9, E14, E16, AM19,
//! AM21, AM23), as one switch.
//!
//! [`VoteRules::default`] is today's behaviour byte for byte: every road
//! below stays as it was. [`VoteRules::PROFILE1`] closes them:
//!
//! | Rule | Today | Profile 1 |
//! |---|---|---|
//! | Round 1 | import- or check-gated on the H2-v4 profile; on the header alone under `twoPhaseVoteGate`; optimistic on the native profile or with `N42_VOTE_BEFORE_IMPORT` | only after the block passed the execution layer's check (static header rules, the deferred-execution proposal check, the parent imported) or its import, and extends its justify QC's block |
//! | CommitVote | on the PrepareQC; under `twoPhaseVoteGate` after the block's check or import | only after this node's own import (execution) of the block |
//! | Progress votes | sent under the stragglers' grace, accepted into the voters ledger | never sent, ignored when received |
//! | Vote transport | `N42_VOTE_TRANSPORT=direct` may skip the consensus topic | every vote is published on the consensus topic |
//! | `N42_VOTE_BEFORE_SLOT` | the vote may go out with the block's execution held | off |
//! | Settlement tags | `split` or `legacy` | `split` only; `finalized` needs a reported persisted height |
//! | Genesis justify | passes the extends rule whatever the parent | the block's parent has to be the genesis block |
//! | `mobileRegistryRoot` without a mobileverify service | the build carries none (and fails on a MobileAnchor chain) | the parent's root is repeated (AM21/AM23) |
//!
//! The rules are local switches set once before a node runs; what maps a
//! genesis's `n42Profile` onto them is the chain-configuration layer's.

/// See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VoteRules {
    /// The chain runs the mixed production standard's profile 1.
    pub profile1: bool,
}

impl VoteRules {
    /// Today's behaviour.
    pub const TODAY: Self = Self { profile1: false };

    /// Profile 1's rules.
    pub const PROFILE1: Self = Self { profile1: true };

    /// Round 1 waits for the execution layer's check or the import, whatever
    /// the signing profile or the bench flags say; no header-only vote.
    pub const fn round1_needs_check(self) -> bool {
        self.profile1
    }

    /// The CommitVote waits for this node's own import of the block; a check
    /// does not release it.
    pub const fn commit_vote_needs_own_import(self) -> bool {
        self.profile1
    }

    /// Progress votes may be sent and are read into the voters ledger.
    pub const fn progress_votes_allowed(self) -> bool {
        !self.profile1
    }

    /// A vote may travel by the direct vote protocol alone, or by it at all
    /// (`/n42/vote/1` is not a standard protocol).
    pub const fn direct_votes_allowed(self) -> bool {
        !self.profile1
    }

    /// A vote may go out while the block's execution is held behind the
    /// import slots (`N42_VOTE_BEFORE_SLOT`).
    pub const fn vote_before_slot_allowed(self) -> bool {
        !self.profile1
    }

    /// The `legacy` settlement tags (head = safe = finalized) may be chosen.
    pub const fn legacy_settlement_allowed(self) -> bool {
        !self.profile1
    }

    /// `finalized` moves only on a persisted height the execution layer
    /// reports; one that reports none holds it rather than following `safe`.
    pub const fn finalized_needs_reported_persistence(self) -> bool {
        self.profile1
    }

    /// A Round 1 vote on a proposal justified by the genesis QC needs the
    /// block's parent to be the genesis block (E6: a proposal extends the
    /// block its justify certifies; gov5 refuses "block justified by the
    /// genesis QC does not extend genesis" on profile 1). Off, a genesis
    /// justify passes the extends rule whatever the parent.
    pub const fn genesis_justify_extends_genesis(self) -> bool {
        self.profile1
    }

    /// A leader without a mobileverify service repeats its parent's
    /// `mobileRegistryRoot` instead of building without one.
    pub const fn repeat_parent_registry_root(self) -> bool {
        self.profile1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_today_and_profile1_closes_every_road() {
        assert_eq!(VoteRules::default(), VoteRules::TODAY);
        let today = VoteRules::TODAY;
        assert!(!today.round1_needs_check());
        assert!(!today.commit_vote_needs_own_import());
        assert!(today.progress_votes_allowed());
        assert!(today.direct_votes_allowed());
        assert!(today.vote_before_slot_allowed());
        assert!(today.legacy_settlement_allowed());
        assert!(!today.finalized_needs_reported_persistence());
        assert!(!today.repeat_parent_registry_root());
        assert!(!today.genesis_justify_extends_genesis());
        let p1 = VoteRules::PROFILE1;
        assert!(p1.round1_needs_check());
        assert!(p1.commit_vote_needs_own_import());
        assert!(!p1.progress_votes_allowed());
        assert!(!p1.direct_votes_allowed());
        assert!(!p1.vote_before_slot_allowed());
        assert!(!p1.legacy_settlement_allowed());
        assert!(p1.finalized_needs_reported_persistence());
        assert!(p1.repeat_parent_registry_root());
        assert!(p1.genesis_justify_extends_genesis());
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TEST ONLY: a validator that deliberately equivocates, so a mixed round can
//! check that every client proves the fault (E15, AM28;
//! `docs/P1_EQUIVOCATION_INJECTOR.md`).
//!
//! Off unless BOTH the environment variable [`ENV`] and the CLI flag
//! `--test-equivocate` are given, and refused on any chain whose id is not in
//! [`TEST_CHAIN_IDS`]. When on, every message of the chosen kind this node
//! sends in a chosen view goes out as signed, followed by its twin: the same
//! message for another block (`n42_h2_consensus::twin_block_hash`), signed
//! with this validator's real key.
//!
//! `N42_TEST_EQUIVOCATE=<kind>:<when>`:
//! - `<kind>`: `vote` (two Round-1 votes), `commit_vote` (two commit votes)
//!   or `proposal` (two proposals, as leader);
//! - `<when>`: a view number (`vote:12`), or `every-<n>` for every view
//!   divisible by `n` (`proposal:every-1` is every view this node leads).

use n42_h2_consensus::EquivocationKind;
use n42_h2_primitives::consensus::ConsensusMessage;

/// The environment variable that names what to equivocate.
pub const ENV: &str = "N42_TEST_EQUIVOCATE";

/// Counter of twins sent, labelled by `kind` (zero on every real node).
pub const METRIC_INJECTED_TOTAL: &str = "n42_test_equivocations_injected_total";

/// The CLI flag that has to accompany [`ENV`].
pub const FLAG: &str = "--test-equivocate";

/// The chain ids the injector may run on: the dev chain (1143), the profile-1
/// chain the mixed rounds run (1144; no public network uses it), and the
/// usual local test ids. Production and public test chains (gov5's 94 and 95,
/// N42 1142, Ethereum's) are refused.
pub const TEST_CHAIN_IDS: &[u64] = &[1143, 1144, 1337, 31337];

/// Which views to equivocate in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// This one view.
    View(u64),
    /// Every view divisible by this (non-zero) number.
    Every(u64),
}

/// The injector's configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestEquivocation {
    /// What to sign twice.
    pub kind: EquivocationKind,
    /// When.
    pub trigger: Trigger,
}

impl TestEquivocation {
    /// Parses `<kind>:<view>` or `<kind>:every-<n>`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (kind, when) = spec.split_once(':').ok_or_else(|| format!("{ENV}={spec}: expected <kind>:<view> or <kind>:every-<n>"))?;
        let kind = match kind.trim() {
            "vote" => EquivocationKind::Vote,
            "commit_vote" | "commit-vote" | "commitVote" => EquivocationKind::CommitVote,
            "proposal" => EquivocationKind::Proposal,
            other => return Err(format!("{ENV}: unknown kind {other:?} (vote, commit_vote, proposal)")),
        };
        let when = when.trim();
        let trigger = match when.strip_prefix("every-") {
            Some(n) => match n.parse::<u64>() {
                Ok(n) if n > 0 => Trigger::Every(n),
                _ => return Err(format!("{ENV}: every-<n> needs a positive n, got {when:?}")),
            },
            None => Trigger::View(when.parse().map_err(|_| format!("{ENV}: {when:?} is not a view number or every-<n>"))?),
        };
        Ok(Self { kind, trigger })
    }

    /// The injector this process runs, if any: `env` is [`ENV`]'s value,
    /// `flag` whether [`FLAG`] was given. Either alone is refused rather than
    /// ignored, so a half-configured member does not quietly run honest.
    pub fn configure(env: Option<&str>, flag: bool, chain_id: u64) -> Result<Option<Self>, String> {
        let env = env.map(str::trim).filter(|value| !value.is_empty());
        match (env, flag) {
            (None, false) => Ok(None),
            (None, true) => Err(format!("{FLAG} given without {ENV}=<kind>:<view|every-n>")),
            (Some(_), false) => Err(format!("{ENV} is set but {FLAG} was not given; both are required")),
            (Some(spec), true) => {
                if !TEST_CHAIN_IDS.contains(&chain_id) {
                    return Err(format!(
                        "refusing to equivocate on chain {chain_id}: the injector runs only on {TEST_CHAIN_IDS:?}"
                    ));
                }
                Self::parse(spec).map(Some)
            }
        }
    }

    /// Whether `view` is one to equivocate in.
    pub const fn applies_to_view(&self, view: u64) -> bool {
        match self.trigger {
            Trigger::View(target) => view == target,
            Trigger::Every(n) => view.is_multiple_of(n),
        }
    }

    /// Whether `message` (one this node is sending) gets a twin.
    pub fn applies(&self, message: &ConsensusMessage) -> bool {
        let kind = match message {
            ConsensusMessage::Vote(_) => EquivocationKind::Vote,
            ConsensusMessage::CommitVote(_) => EquivocationKind::CommitVote,
            ConsensusMessage::Proposal(_) => EquivocationKind::Proposal,
            _ => return false,
        };
        kind == self.kind && self.applies_to_view(message.view())
    }

    /// One line for the startup banner and the log.
    pub fn describe(&self) -> String {
        let when = match self.trigger {
            Trigger::View(view) => format!("view {view}"),
            Trigger::Every(n) => format!("every view divisible by {n}"),
        };
        format!("{} in {when}", self.kind.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_kind_and_trigger() {
        assert_eq!(
            TestEquivocation::parse("vote:12").unwrap(),
            TestEquivocation { kind: EquivocationKind::Vote, trigger: Trigger::View(12) }
        );
        assert_eq!(
            TestEquivocation::parse("commit_vote:every-3").unwrap(),
            TestEquivocation { kind: EquivocationKind::CommitVote, trigger: Trigger::Every(3) }
        );
        assert_eq!(TestEquivocation::parse("proposal:every-1").unwrap().kind, EquivocationKind::Proposal);
        for bad in ["vote", "timeout:3", "vote:every-0", "vote:x", "vote:every-"] {
            assert!(TestEquivocation::parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn needs_both_switches_and_a_test_chain() {
        assert_eq!(TestEquivocation::configure(None, false, 94), Ok(None));
        assert_eq!(TestEquivocation::configure(Some(""), false, 1143), Ok(None));
        assert!(TestEquivocation::configure(None, true, 1143).is_err());
        assert!(TestEquivocation::configure(Some("vote:3"), false, 1143).is_err());
        for chain in [1, 94, 95, 1142] {
            assert!(TestEquivocation::configure(Some("vote:3"), true, chain).is_err(), "chain {chain} must be refused");
        }
        for chain in TEST_CHAIN_IDS {
            assert!(TestEquivocation::configure(Some("vote:3"), true, *chain).unwrap().is_some());
        }
    }

    #[test]
    fn triggers_select_views() {
        let every = TestEquivocation::parse("vote:every-4").unwrap();
        assert!(every.applies_to_view(8) && !every.applies_to_view(9));
        let one = TestEquivocation::parse("vote:9").unwrap();
        assert!(one.applies_to_view(9) && !one.applies_to_view(8));
    }
}

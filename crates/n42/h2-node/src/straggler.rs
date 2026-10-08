// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which voters a leader waits for before its next proposal.
//!
//! The stragglers' grace (`F7_STRAGGLER_GRACE_MS`, [`crate::H2Service::with_straggler_grace`])
//! was added for the round-43 tenure-handover stall: with one execution
//! layer per key, the keys outside the quorum imported more slowly than the
//! leader proposed, fell a block further behind each view, and when the
//! tenure passed to one of them it could not propose until it had caught up
//! (10-40 s stalls). The grace's rule, [`StragglerRule::All`], waits until
//! every validator's Round 1 vote of the previous view has arrived (or the
//! grace runs out): the slowest of N on every block.
//!
//! [`StragglerRule::Quorum`] (`N42_STRAGGLER_RULE=quorum`) waits for what the
//! stall needed and nothing else:
//!
//! 1. the **next tenure's leader**, while the handover is at most
//!    [`LAG_VIEWS`] views away and it has not been seen at the previous view:
//!    whoever leads next has imported the parent of its first block when the
//!    tenure passes;
//! 2. **voters more than [`LAG_VIEWS`] blocks behind**: their last vote is
//!    older than `view - LAG_VIEWS`. A voter one block late never holds
//!    anything; a voter that falls further is waited for once, and if the
//!    wait runs out it is given up on until it is seen within the bound
//!    again (a dead key costs one wait, not one per block).
//!
//! Each wait is capped at `min(grace, 2 x the measured cycle)` from the
//! moment the previous view was decided. Local policy, as the grace is: the
//! wire and the protocol are unchanged.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

/// How many blocks behind a voter may fall before the leader waits for it,
/// and how close the tenure handover must be before the next leader is
/// waited for.
pub const LAG_VIEWS: u64 = 2;

/// Commit intervals kept for the cycle estimate.
const CYCLE_SAMPLES: usize = 16;

/// An interval longer than this is a stall, not a cycle.
const CYCLE_SAMPLE_MAX: Duration = Duration::from_secs(10);

/// Which voters the leader waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StragglerRule {
    /// Every validator (today's grace).
    #[default]
    All,
    /// The next leader near a handover and the voters more than
    /// [`LAG_VIEWS`] behind.
    Quorum,
}

impl StragglerRule {
    /// `N42_STRAGGLER_RULE=quorum` selects [`Self::Quorum`]; anything else,
    /// or nothing, is [`Self::All`].
    pub fn from_env() -> Self {
        match std::env::var("N42_STRAGGLER_RULE").as_deref() {
            Ok("quorum") => Self::Quorum,
            _ => Self::All,
        }
    }
}

/// What the quorum rule reads of the leader's ledger.
pub struct Ledger<'a> {
    /// The view about to be proposed.
    pub view: u64,
    /// The validator set's size.
    pub validator_count: u32,
    /// This node's index.
    pub me: u32,
    /// The next tenure's leader, when the handover is at most [`LAG_VIEWS`]
    /// views away and it is not this node.
    pub next_leader: Option<u32>,
    /// The last view at which a voter's Round 1 vote (real or progress) was
    /// verified, within the ledger's window.
    pub last_seen: &'a dyn Fn(u32) -> Option<u64>,
}

impl std::fmt::Debug for Ledger<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("view", &self.view)
            .field("validator_count", &self.validator_count)
            .field("me", &self.me)
            .field("next_leader", &self.next_leader)
            .finish_non_exhaustive()
    }
}

impl Ledger<'_> {
    /// Seen within [`LAG_VIEWS`] of the view being proposed.
    fn caught_up(&self, voter: u32) -> bool {
        (self.last_seen)(voter).is_some_and(|seen| seen + LAG_VIEWS >= self.view)
    }

    /// Whether the next leader has been seen at the previous view.
    fn next_leader_ready(&self, next: u32) -> bool {
        (self.last_seen)(next).is_some_and(|seen| seen + 1 >= self.view)
    }
}

/// What to do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Propose.
    Proceed,
    /// Defer: these voters are waited for.
    Wait(Vec<u32>),
}

/// The quorum rule's state: who has been given up on, and the cycle.
#[derive(Debug, Default)]
pub struct QuorumRule {
    given_up: HashSet<u32>,
    cycles: VecDeque<Duration>,
    last_decided: Option<Instant>,
}

impl QuorumRule {
    /// Records a decision instant; consecutive ones give the cycle.
    pub fn note_decided(&mut self, decided_at: Instant) {
        if let Some(last) = self.last_decided
            && decided_at > last
        {
            let interval = decided_at - last;
            if interval <= CYCLE_SAMPLE_MAX {
                self.cycles.push_back(interval);
                if self.cycles.len() > CYCLE_SAMPLES {
                    self.cycles.pop_front();
                }
            }
        }
        if self.last_decided.is_none_or(|last| decided_at > last) {
            self.last_decided = Some(decided_at);
        }
    }

    /// The median of the recent commit intervals, if any were measured.
    pub fn cycle(&self) -> Option<Duration> {
        let mut sorted: Vec<Duration> = self.cycles.iter().copied().collect();
        sorted.sort_unstable();
        sorted.get(sorted.len() / 2).copied()
    }

    /// `min(grace, 2 x cycle)`; the grace alone while no cycle is known.
    pub fn cap(&self, grace: Duration) -> Duration {
        self.cycle().map_or(grace, |cycle| grace.min(cycle.saturating_mul(2)))
    }

    /// The voters the rule would wait for now (the next leader first).
    pub fn waited_for(&self, ledger: &Ledger<'_>) -> Vec<u32> {
        let mut waited = Vec::new();
        if let Some(next) = ledger.next_leader
            && next != ledger.me
            && !ledger.next_leader_ready(next)
        {
            waited.push(next);
        }
        for voter in 0..ledger.validator_count {
            if voter == ledger.me
                || Some(voter) == ledger.next_leader
                || self.given_up.contains(&voter)
                || ledger.caught_up(voter)
            {
                continue;
            }
            waited.push(voter);
        }
        waited
    }

    /// The voters given up on (not waited for until they are seen again).
    pub fn given_up(&self) -> impl Iterator<Item = u32> + '_ {
        self.given_up.iter().copied()
    }

    /// Decides whether the proposal of `ledger.view` waits, `decided_at`
    /// being when the previous view was decided. When the cap runs out the
    /// laggers still waited for are given up on; the next leader never is
    /// (it is waited for again at the next view, capped again).
    pub fn decide(
        &mut self,
        ledger: &Ledger<'_>,
        decided_at: Instant,
        grace: Duration,
        now: Instant,
    ) -> Verdict {
        self.note_decided(decided_at);
        self.given_up.retain(|voter| !ledger.caught_up(*voter));
        let waited = self.waited_for(ledger);
        if waited.is_empty() {
            return Verdict::Proceed;
        }
        if now.saturating_duration_since(decided_at) < self.cap(grace) {
            return Verdict::Wait(waited);
        }
        for voter in waited {
            if Some(voter) != ledger.next_leader {
                self.given_up.insert(voter);
            }
        }
        Verdict::Proceed
    }
}

/// The next tenure's leader when its first view is at most [`LAG_VIEWS`]
/// after `view` and it is not `me`; `leader_of` maps a view to its leader.
pub fn next_tenure_leader(view: u64, tenure: u64, me: u32, leader_of: impl Fn(u64) -> u32) -> Option<u32> {
    let tenure = tenure.max(1);
    let next_start = (view / tenure).saturating_add(1).saturating_mul(tenure);
    if next_start > view.saturating_add(LAG_VIEWS) {
        return None;
    }
    let next = leader_of(next_start);
    (next != me).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ledger<'a>(view: u64, next_leader: Option<u32>, last_seen: &'a dyn Fn(u32) -> Option<u64>) -> Ledger<'a> {
        Ledger {
            view,
            validator_count: 7,
            me: 0,
            next_leader,
            last_seen,
        }
    }

    fn seen(map: HashMap<u32, u64>) -> impl Fn(u32) -> Option<u64> {
        move |voter| map.get(&voter).copied()
    }

    /// Seven validators, one of them (6) one block late on every block: the
    /// leader does not wait for it.
    #[test]
    fn one_slow_voter_among_seven_is_not_waited_for() {
        let view = 100;
        let last = seen((1..7).map(|v| (v, if v == 6 { view - 2 } else { view - 1 })).collect());
        let current = ledger(view, None, &last);
        let mut rule = QuorumRule::default();
        let decided = Instant::now();
        assert_eq!(rule.decide(&current, decided, Duration::from_millis(600), decided), Verdict::Proceed);
    }

    /// The handover: the incoming leader (3) has not voted at the previous
    /// view; the outgoing leader waits for it, up to the cap, and never
    /// gives up on it.
    #[test]
    fn the_outgoing_leader_waits_for_an_incoming_leader_that_is_behind() {
        let view = 1023; // tenure 1024: the handover is at 1024
        let next = next_tenure_leader(view, 1024, 0, |v| ((v / 1024) % 7) as u32);
        assert_eq!(next, Some(1));
        let last = seen((1..7).map(|v| (v, if v == 1 { view - 2 } else { view - 1 })).collect());
        let behind = ledger(view, next, &last);
        let mut rule = QuorumRule::default();
        let decided = Instant::now();
        let grace = Duration::from_millis(600);
        assert_eq!(rule.decide(&behind, decided, grace, decided), Verdict::Wait(vec![1]));
        // Past the cap it proposes, without giving up on the next leader.
        let late = decided + grace;
        assert_eq!(rule.decide(&behind, decided, grace, late), Verdict::Proceed);
        assert_eq!(rule.given_up().count(), 0);
        // Once the incoming leader's vote of the previous view is in, no wait.
        let caught = seen((1..7).map(|v| (v, view - 1)).collect());
        let ready = ledger(view, next, &caught);
        assert_eq!(rule.decide(&ready, decided, grace, decided), Verdict::Proceed);
    }

    /// Far from the handover the next leader is not named at all.
    #[test]
    fn the_next_leader_is_only_waited_for_near_the_handover() {
        let leader_of = |v: u64| ((v / 1024) % 7) as u32;
        assert_eq!(next_tenure_leader(1000, 1024, 0, leader_of), None);
        assert_eq!(next_tenure_leader(1022, 1024, 0, leader_of), Some(1));
        // Round robin: the next view's leader, always.
        assert_eq!(next_tenure_leader(8, 1, 0, |v| (v % 7) as u32), Some(2));
        assert_eq!(next_tenure_leader(6, 1, 0, |v| (v % 7) as u32), None, "the next leader is this node");
    }

    /// A voter three blocks behind is waited for once; when the cap runs out
    /// it is given up on, and waited for again only after it returns.
    #[test]
    fn a_lagging_voter_costs_one_wait_then_is_given_up_until_it_returns() {
        let view = 50;
        let mut map: HashMap<u32, u64> = (1..7).map(|v| (v, view - 1)).collect();
        map.insert(4, view - 3);
        let last = seen(map.clone());
        let mut rule = QuorumRule::default();
        let decided = Instant::now();
        let grace = Duration::from_millis(600);
        assert_eq!(rule.decide(&ledger(view, None, &last), decided, grace, decided), Verdict::Wait(vec![4]));
        assert_eq!(rule.decide(&ledger(view, None, &last), decided, grace, decided + grace), Verdict::Proceed);
        // Next view, still behind: not waited for.
        let next_decided = decided + Duration::from_millis(100);
        assert_eq!(rule.decide(&ledger(view + 1, None, &last), next_decided, grace, next_decided), Verdict::Proceed);
        // It returns, then falls behind again: waited for again.
        map.insert(4, view);
        let back = seen(map.clone());
        assert_eq!(rule.decide(&ledger(view + 1, None, &back), next_decided, grace, next_decided), Verdict::Proceed);
        assert_eq!(rule.given_up().count(), 0);
        // Two views on, everyone else has kept up; 4 is three behind again.
        for voter in 1..7 {
            map.insert(voter, view + 1);
        }
        map.insert(4, view - 2);
        let behind = seen(map);
        let later = next_decided + Duration::from_millis(100);
        assert_eq!(rule.decide(&ledger(view + 2, None, &behind), later, grace, later), Verdict::Wait(vec![4]));
    }

    /// The cap is the grace until a cycle is known, then twice the median
    /// cycle if that is shorter.
    #[test]
    fn the_cap_is_the_grace_or_twice_the_cycle() {
        let mut rule = QuorumRule::default();
        let grace = Duration::from_millis(600);
        assert_eq!(rule.cap(grace), grace);
        let start = Instant::now();
        for i in 0..5 {
            rule.note_decided(start + Duration::from_millis(60 * i));
        }
        assert_eq!(rule.cycle(), Some(Duration::from_millis(60)));
        assert_eq!(rule.cap(grace), Duration::from_millis(120));
        assert_eq!(rule.cap(Duration::from_millis(100)), Duration::from_millis(100));
    }

    #[test]
    fn the_rule_is_all_unless_the_switch_says_quorum() {
        assert_eq!(StragglerRule::default(), StragglerRule::All);
    }
}

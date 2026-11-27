// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rotate-on-timeout (N42-SYNC-SPEC section 10; gov5
//! `rotate_on_timeout_test.go`, branch `feat/hotstuff-rotate-on-timeout`).
//!
//! The engine-level cases mirror gov5's test names. The network cases run
//! seven engines on a virtual clock: messages are delivered instantly, a
//! proposal costs [`BLOCK_MS`] of virtual time, and a view whose leader is
//! silent ends when the live nodes' pacemaker deadlines fire, with the
//! engine's own backoff (`Pacemaker::timeout_duration` of its consecutive
//! timeouts), so the stall lengths are the protocol's.

use super::*;
use crate::protocol::quorum::timeout_signing_message;
use crate::ValidatorInfo;
use alloy_primitives::Address;
use n42_h2_primitives::consensus::{NewView, Proposal, TimeoutCertificate, TimeoutMessage};
use std::collections::{BTreeMap, VecDeque};

const BASE_MS: u64 = 1_000;
const MAX_MS: u64 = 10_000;
const BLOCK_MS: u64 = 50;

fn key(seed: u8) -> n42_h2_primitives::BlsSecretKey {
    n42_h2_primitives::BlsSecretKey::key_gen(&[seed; 32]).expect("a valid deterministic key")
}

fn validators(n: usize) -> (Vec<n42_h2_primitives::BlsSecretKey>, ValidatorSet) {
    let sks: Vec<_> = (0..n).map(|i| key(0x60 + i as u8)).collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo {
            address: Address::with_last_byte(i as u8),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let vs = ValidatorSet::new(&infos, ((n as u32).saturating_sub(1)) / 3);
    (sks, vs)
}

fn engine(
    index: usize,
    sks: &[n42_h2_primitives::BlsSecretKey],
    vs: &ValidatorSet,
    tenure: u64,
    rotate_from: Option<u64>,
) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
    engine_with(index, sks, vs, tenure, rotate_from, 0, BASE_MS, MAX_MS)
}

#[allow(clippy::too_many_arguments)]
fn engine_with(
    index: usize,
    sks: &[n42_h2_primitives::BlsSecretKey],
    vs: &ValidatorSet,
    tenure: u64,
    rotate_from: Option<u64>,
    epoch_length: u64,
    base_ms: u64,
    max_ms: u64,
) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
    let (tx, rx) = mpsc::channel(4096);
    let mut engine = ConsensusEngine::new(index as u32, sks[index].clone(), vs.clone(), base_ms, max_ms, tx);
    engine.set_leader_tenure(tenure);
    engine.set_rotate_on_timeout(rotate_from, epoch_length);
    (engine, rx)
}

fn tc_for(view: u64, sks: &[n42_h2_primitives::BlsSecretKey], vs: &ValidatorSet, signers: &[u32]) -> TimeoutCertificate {
    let mut collector = TimeoutCollector::new(view, vs.len());
    for &i in signers {
        collector
            .add_timeout(i, sks[i as usize].sign(&timeout_signing_message(view)), QuorumCertificate::genesis())
            .expect("distinct senders");
    }
    collector.build_tc(vs).expect("a quorum")
}

fn new_view(view: u64, leader: u32, tc: &TimeoutCertificate, sks: &[n42_h2_primitives::BlsSecretKey]) -> ConsensusEvent {
    let profile = ConsensusSigningProfile::Native;
    ConsensusEvent::Message(ConsensusMessage::NewView(NewView {
        view,
        timeout_cert: tc.clone(),
        leader,
        signature: profile.sign(&sks[leader as usize], &profile.new_view_message(view)),
    }))
}

/// gov5 `TestViewAfterTCActivationView` (spec S8 at the engine): off by
/// default, classic below the activation view, rotated at and above it.
#[test]
fn view_after_tc_activation_view() {
    let (sks, vs) = validators(7);
    let (mut e, _rx) = engine(0, &sks, &vs, 8, None);
    assert_eq!(e.view_after_tc(8), 9, "default off");
    e.set_rotate_on_timeout(Some(20), 0);
    assert_eq!(e.view_after_tc(8), 9, "below the activation view");
    assert_eq!(e.view_after_tc(19), 20, "just below the activation view");
    assert_eq!(e.view_after_tc(20), 24, "at the activation view");
    assert_eq!(e.view_after_tc(25), 32, "above the activation view");
    // Spec S8: A = 100, TC(99) -> 100 (L5) classic; TC(100) -> 104 (L6).
    e.set_rotate_on_timeout(Some(100), 0);
    assert_eq!((e.view_after_tc(99), e.leader_index_for_view(100)), (100, 5));
    assert_eq!((e.view_after_tc(100), e.leader_index_for_view(104)), (104, 6));
    // The epoch clamp comes from the configured genesis epoch length.
    e.set_rotate_on_timeout(Some(0), 10);
    assert_eq!(e.view_after_tc(8), 11);
    // Off keeps the engine's old saturating successor at the top of the range.
    e.set_rotate_on_timeout(None, 0);
    assert_eq!(e.view_after_tc(u64::MAX), u64::MAX);
    // Tenure 1: the rule changes nothing.
    e.set_leader_tenure(1);
    e.set_rotate_on_timeout(Some(0), 0);
    for x in 0..40 {
        assert_eq!(e.view_after_tc(x), x + 1);
    }
}

/// gov5 `TestRotateOnTimeoutRejectsWrongLeader`: after a TC for view 8 a
/// follower accepts the rotated leader's NewView for view 16, refuses the
/// classic successor's for view 9, and then refuses a proposal for view 16
/// from anyone but validator 2.
#[test]
fn rotate_on_timeout_rejects_wrong_leader() {
    let (sks, vs) = validators(7);
    let (mut follower, _rx) = engine(6, &sks, &vs, 8, Some(0));
    follower.advance_to_view(8).expect("view 8");
    let tc = tc_for(8, &sks, &vs, &[0, 2, 3, 4, 5]);

    let classic = follower.process_event(new_view(9, 1, &tc, &sks));
    assert!(matches!(classic, Err(ConsensusError::InvalidTC { view: 8, .. })), "{classic:?}");
    assert_eq!(follower.current_view(), 8);
    follower.process_event(new_view(16, 2, &tc, &sks)).expect("the rotated NewView");
    assert_eq!(follower.current_view(), 16);

    let proposal = |proposer: u32| {
        let block_hash = B256::new([0x16, proposer as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ConsensusEvent::Message(ConsensusMessage::Proposal(Proposal {
            view: 16,
            block_hash,
            justify_qc: QuorumCertificate::genesis(),
            proposer,
            signature: sks[proposer as usize]
                .sign(&ConsensusSigningProfile::Native.proposal_message(16, block_hash, &None)),
            prepare_qc: None,
            validator_changes: None,
            tx_root_hash: None,
        }))
    };
    for proposer in [1u32, 3] {
        let result = follower.process_event(proposal(proposer));
        assert!(matches!(result, Err(ConsensusError::InvalidProposer { view: 16, expected: 2, .. })), "{result:?}");
    }
    follower.process_event(proposal(2)).expect("the rotated leader's proposal");

    // With the rule off the same TC only admits the classic successor.
    let (mut classic_node, _rx) = engine(6, &sks, &vs, 8, None);
    classic_node.advance_to_view(8).expect("view 8");
    assert!(classic_node.process_event(new_view(16, 2, &tc, &sks)).is_err());
    classic_node.process_event(new_view(9, 1, &tc, &sks)).expect("the classic NewView");
    assert_eq!(classic_node.current_view(), 9);
}

/// gov5 `TestRotateOnTimeoutPiggybackedTCJumpsToWindow` and spec S11: a node
/// that adopts a piggybacked TC for view 8 lands on view 16, also when it had
/// already left view 8 through a QC.
#[test]
fn rotate_on_timeout_piggybacked_tc_jumps_to_window() {
    let (sks, vs) = validators(7);
    let tc = tc_for(8, &sks, &vs, &[0, 2, 3, 4, 5]);
    let (mut lagging, _rx) = engine(0, &sks, &vs, 8, Some(0));
    assert!(lagging.adopt_embedded_tc(&tc).expect("adopted"));
    assert_eq!(lagging.current_view(), 16);

    let (mut at_nine, _rx) = engine(0, &sks, &vs, 8, Some(0));
    at_nine.advance_to_view(9).expect("view 9");
    assert!(at_nine.adopt_embedded_tc(&tc).expect("adopted"));
    assert_eq!(at_nine.current_view(), 16, "S11: the TC for 8 still moves a node at 9");

    let (mut off, _rx) = engine(0, &sks, &vs, 8, None);
    off.advance_to_view(9).expect("view 9");
    assert!(!off.adopt_embedded_tc(&tc).expect("not adopted"), "classic: TC(8) leads only to 9");
}

/// AM33: a piggybacked TC moves the node but keeps its consecutive-timeout
/// count (gov5 dropped the reset it took on a SyncInfo TC), and the timer
/// of the view it enters is `timeout(c)` under the set's backoff group.
#[test]
fn am33_an_adopted_tc_keeps_the_timeout_count() {
    let (sks, vs) = validators(7);
    let tc = tc_for(8, &sks, &vs, &[0, 2, 3, 4, 5]);
    let (mut e, _rx) = engine(6, &sks, &vs, 8, Some(0));
    e.advance_to_view(8).expect("view 8");
    e.on_timeout().expect("own timeout");
    e.on_timeout().expect("a repeat is not a new timeout");
    assert_eq!(e.consecutive_timeouts(), 1);
    assert!(e.adopt_embedded_tc(&tc).expect("adopted"));
    assert_eq!(e.current_view(), 16);
    assert_eq!(e.consecutive_timeouts(), 1, "a TC never resets c");
    assert_eq!(e.pacemaker().backoff_group(), 3, "n = 7: g = 3");
    assert_eq!(e.pacemaker().timeout_duration(e.consecutive_timeouts()), std::time::Duration::from_millis(BASE_MS));
    assert_eq!(e.pacemaker().timeout_duration(3), std::time::Duration::from_millis(2 * BASE_MS));
}

/// Forming a TC locally from timeouts: the node enters the rotated view, and
/// only that view's leader signs the NewView (spec 10.2 items 1 and 2).
#[test]
fn a_locally_formed_tc_enters_the_rotated_view() {
    let (sks, vs) = validators(7);
    for (me, sends_new_view) in [(2usize, true), (6, false)] {
        let (mut e, mut rx) = engine(me, &sks, &vs, 8, Some(0));
        e.advance_to_view(8).expect("view 8");
        for sender in [0u32, 3, 4, 5, 6].into_iter().filter(|s| *s != me as u32) {
            let _ = e.process_event(ConsensusEvent::Message(ConsensusMessage::Timeout(TimeoutMessage {
                view: 8,
                high_qc: QuorumCertificate::genesis(),
                sender,
                signature: sks[sender as usize].sign(&timeout_signing_message(8)),
            })));
        }
        e.on_timeout().expect("own timeout");
        assert_eq!(e.current_view(), 16, "node {me}");
        let nv: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|o| match o {
                EngineOutput::BroadcastMessage(ConsensusMessage::NewView(nv)) => Some(nv),
                _ => None,
            })
            .collect();
        assert_eq!(nv.len(), usize::from(sends_new_view), "node {me}");
        if let Some(nv) = nv.first() {
            assert_eq!((nv.view, nv.leader, nv.timeout_cert.view), (16, 2, 8));
        }
    }
}

// ---------------------------------------------------------------------------
// Seven engines on a virtual clock.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Commit {
    view: u64,
    leader: u32,
    at: u64,
}

struct Sim {
    sks: Vec<n42_h2_primitives::BlsSecretKey>,
    vs: ValidatorSet,
    tenure: u64,
    rotate: Option<u64>,
    engines: Vec<ConsensusEngine>,
    rxs: Vec<mpsc::Receiver<EngineOutput>>,
    alive: Vec<bool>,
    now: u64,
    deadline: Vec<u64>,
    seen_view: Vec<u64>,
    proposed: HashSet<u64>,
    commits: BTreeMap<u64, Commit>,
    parents: HashMap<B256, B256>,
    queue: VecDeque<(usize, ConsensusEvent)>,
    /// Leaders that stay in the network (vote, time out) but propose
    /// nothing from the given view on.
    silent_from: HashMap<usize, u64>,
    /// When each node entered each view.
    entered: HashMap<(usize, u64), u64>,
    /// The timer each node started on entering each view.
    timers: HashMap<(usize, u64), u64>,
}

impl Sim {
    fn new(n: usize, tenure: u64, rotate: Option<u64>) -> Self {
        Self::with_timeouts(n, tenure, rotate, 0, BASE_MS, MAX_MS)
    }

    fn with_timeouts(n: usize, tenure: u64, rotate: Option<u64>, epoch_length: u64, base_ms: u64, max_ms: u64) -> Self {
        let (sks, vs) = validators(n);
        let mut sim = Self {
            sks,
            vs,
            tenure,
            rotate,
            engines: Vec::new(),
            rxs: Vec::new(),
            alive: vec![true; n],
            now: 0,
            deadline: vec![base_ms; n],
            seen_view: vec![0; n],
            proposed: HashSet::new(),
            commits: BTreeMap::new(),
            parents: HashMap::new(),
            queue: VecDeque::new(),
            silent_from: HashMap::new(),
            entered: HashMap::new(),
            timers: HashMap::new(),
        };
        for i in 0..n {
            let (e, rx) = engine_with(i, &sim.sks, &sim.vs, tenure, rotate, epoch_length, base_ms, max_ms);
            sim.engines.push(e);
            sim.rxs.push(rx);
        }
        sim
    }

    fn leader(&self, view: u64) -> u32 {
        LeaderSelector::leader_for_view_with_tenure(view, self.tenure, &self.vs)
    }

    fn deliver(&mut self, to: usize, message: ConsensusMessage) {
        if self.alive[to] {
            self.queue.push_back((to, ConsensusEvent::Message(message)));
        }
    }

    /// Routes every pending output; dead nodes neither send nor receive.
    fn collect(&mut self) {
        for from in 0..self.engines.len() {
            while let Ok(output) = self.rxs[from].try_recv() {
                if !self.alive[from] {
                    continue;
                }
                match output {
                    EngineOutput::BroadcastMessage(message) => {
                        if let ConsensusMessage::Proposal(p) = &message {
                            self.parents.insert(p.block_hash, p.justify_qc.block_hash);
                        }
                        for to in (0..self.engines.len()).filter(|to| *to != from) {
                            self.deliver(to, message.clone());
                        }
                    }
                    EngineOutput::SendToValidator(to, message) => self.deliver(to as usize, message),
                    EngineOutput::ExecuteBlock(hash) => {
                        let parent = self.parents.get(&hash).copied().unwrap_or_default();
                        self.engines[from].remember_parent(hash, parent);
                        self.queue.push_back((from, ConsensusEvent::BlockImported(hash)));
                    }
                    EngineOutput::BlockCommitted { view, .. } => {
                        let leader = self.leader(view);
                        let at = self.now;
                        self.commits.entry(view).or_insert(Commit { view, leader, at });
                    }
                    _ => {}
                }
            }
        }
    }

    /// Delivers everything until the network is quiet; then a live leader
    /// that has not proposed in its view proposes.
    fn settle(&mut self, done: &impl Fn(&Self) -> bool) {
        let mut events = 0usize;
        loop {
            self.collect();
            if let Some((to, event)) = self.queue.pop_front() {
                events += 1;
                if events > 200_000 {
                    let views: Vec<u64> = self.engines.iter().map(|e| e.current_view()).collect();
                    panic!("no quiescence at {} ms: views {views:?}, last event to {to}: {event:?}", self.now);
                }
                let _ = self.engines[to].process_event(event);
                continue;
            }
            self.refresh_deadlines();
            if done(self) {
                return;
            }
            let mut proposed = false;
            for i in 0..self.engines.len() {
                let view = self.engines[i].current_view();
                let silent = self.silent_from.get(&i).is_some_and(|from| view >= *from);
                if self.alive[i] && !silent && self.engines[i].is_current_leader() && !self.proposed.contains(&view) {
                    self.proposed.insert(view);
                    self.now += BLOCK_MS;
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&view.to_be_bytes());
                    hash[31] = 0xB1;
                    let _ = self.engines[i].process_event(ConsensusEvent::BlockReady(B256::new(hash), None));
                    proposed = true;
                }
            }
            if !proposed {
                return;
            }
        }
    }

    fn refresh_deadlines(&mut self) {
        for i in 0..self.engines.len() {
            let view = self.engines[i].current_view();
            if view != self.seen_view[i] {
                self.seen_view[i] = view;
                self.entered.entry((i, view)).or_insert(self.now);
                let timer = self.timeout_ms(i);
                self.timers.entry((i, view)).or_insert(timer);
                self.deadline[i] = self.now + timer;
            }
        }
    }

    fn timeout_ms(&self, i: usize) -> u64 {
        let e = &self.engines[i];
        e.pacemaker.timeout_duration(e.consecutive_timeouts()).as_millis() as u64
    }

    /// One step: settle, then fire the earliest live pacemaker deadline.
    fn step(&mut self, done: &impl Fn(&Self) -> bool) {
        self.settle(done);
        if done(self) {
            return;
        }
        let Some(next) = (0..self.engines.len()).filter(|i| self.alive[*i]).map(|i| self.deadline[i]).min() else {
            return;
        };
        self.now = self.now.max(next);
        for i in 0..self.engines.len() {
            if self.alive[i] && self.deadline[i] <= self.now {
                let _ = self.engines[i].on_timeout();
                self.deadline[i] = self.now + self.timeout_ms(i);
            }
        }
    }

    fn run_until(&mut self, limit_ms: u64, done: impl Fn(&Self) -> bool) -> bool {
        while self.now < limit_ms {
            if done(self) {
                return true;
            }
            self.step(&done);
        }
        done(self)
    }

    fn max_commit_view(&self) -> u64 {
        self.commits.keys().next_back().copied().unwrap_or(0)
    }

    fn commits_after(&self, view: u64) -> Vec<Commit> {
        self.commits.range(view + 1..).map(|(_, c)| *c).collect()
    }

    fn last_commit_before(&self, view: u64) -> Commit {
        *self.commits.range(..view).next_back().map(|(_, c)| c).expect("a commit before")
    }

    /// Restarts node `i` from what the store persists (view, locked QC, last
    /// committed QC, timeouts, vote watermarks) -- nothing about the rule.
    fn restart(&mut self, i: usize) {
        let old = &self.engines[i];
        let (tx, rx) = mpsc::channel(4096);
        let mut fresh = ConsensusEngine::with_recovered_state(
            i as u32,
            self.sks[i].clone(),
            EpochManager::new(self.vs.clone()),
            BASE_MS,
            MAX_MS,
            tx,
            old.current_view(),
            old.locked_qc().clone(),
            old.last_committed_qc().clone(),
            old.consecutive_timeouts(),
            old.last_voted_view(),
        );
        fresh.set_leader_tenure(self.tenure);
        fresh.set_rotate_on_timeout(self.rotate, 0);
        self.engines[i] = fresh;
        self.rxs[i] = rx;
        self.seen_view[i] = 0;
    }
}

/// gov5 `TestRotateOnTimeoutDeadTenureLeader`: 7 validators, tenure 8, the
/// owner of the next tenure (validator 1, views 8-15) is silent. With the
/// rule validator 2 commits view 16 within two base timeouts of the last
/// good block and the chain is steady after it; without it every view of the
/// dead tenure times out with AM33's grouped backoff.
#[test]
fn rotate_on_timeout_dead_tenure_leader() {
    for rotate in [Some(0), None] {
        let mut sim = Sim::new(7, 8, rotate);
        sim.alive[1] = false;
        assert!(
            sim.run_until(600_000, |s| s.max_commit_view() >= 40),
            "rotate={rotate:?}: max commit view {}",
            sim.max_commit_view()
        );
        let last = sim.last_commit_before(8);
        assert_eq!(last.view, 7, "rotate={rotate:?}: the healthy tenure committed through view 7");
        let after = sim.commits_after(7);
        let first = after[0];
        let gap = first.at - last.at;
        assert!(sim.commits.values().all(|c| c.leader != 1), "rotate={rotate:?}: the silent validator led nothing");
        if rotate.is_some() {
            assert_eq!((first.view, first.leader), (16, 2), "first commit after the stall");
            assert!(gap <= 2 * BASE_MS, "stall {gap} ms exceeds two base timeouts");
            for pair in after.windows(2).filter(|w| w[1].view <= 40) {
                assert_eq!(pair[1].view, pair[0].view + 1, "steady after the rotation: {pair:?}");
                assert!(pair[1].at - pair[0].at <= 2 * BLOCK_MS, "steady after the rotation: {pair:?}");
            }
        } else {
            assert_eq!(first.view, 16, "off: the dead tenure is waited out view by view");
            // 8 timeouts under AM33 (n = 7: g = 3, one doubling per three
            // TCs): 1+1+1+2+2+2+4+4 = 17 s at base 1 s / max 10 s. Before
            // AM33 each TC doubled: 1+2+4+8+10*4 = 55 s.
            assert!(
                (17 * BASE_MS..17 * BASE_MS + 2 * BLOCK_MS).contains(&gap),
                "off: stall {gap} ms, expected AM33's per-view backoff stall of 17 s"
            );
        }
    }
}

/// gov5 `TestRotateOnTimeoutTwoConsecutiveDeadLeaders` (spec S2): validators
/// 1 and 2 are silent; the rule skips both windows for two base timeouts
/// (AM33, n = 7: the second TC is not doubled; before AM33 it was, 3 s).
#[test]
fn rotate_on_timeout_two_consecutive_dead_leaders() {
    let mut sim = Sim::new(7, 8, Some(0));
    sim.alive[1] = false;
    sim.alive[2] = false;
    assert!(sim.run_until(300_000, |s| s.max_commit_view() >= 30), "max {}", sim.max_commit_view());
    let last = sim.last_commit_before(8);
    let first = sim.commits_after(7)[0];
    assert_eq!((first.view, first.leader), (24, 3));
    assert!(first.at - last.at <= 2 * BASE_MS + 2 * BLOCK_MS, "stall {} ms", first.at - last.at);
}

/// gov5 `TestRotateOnTimeoutDeadLeaderComesBack`: validator 1 misses its
/// first tenure, returns, catches up and leads its next window (views 64-71)
/// in full.
#[test]
fn rotate_on_timeout_dead_leader_comes_back() {
    let mut sim = Sim::new(7, 8, Some(0));
    sim.alive[1] = false;
    assert!(sim.run_until(300_000, |s| s.max_commit_view() >= 20), "max {}", sim.max_commit_view());
    sim.alive[1] = true;
    sim.seen_view[1] = 0;
    assert!(sim.run_until(900_000, |s| s.max_commit_view() >= 75), "max {}", sim.max_commit_view());
    let led: Vec<u64> = sim.commits.values().filter(|c| c.leader == 1).map(|c| c.view).collect();
    assert_eq!(led, (64..=71).collect::<Vec<_>>(), "the returned validator leads its next window");
}

/// gov5 `TestRotateOnTimeoutRestartMidRotation` (spec S10): a follower
/// restarted from its persisted state after the rotation recomputes the same
/// leader and keeps voting; with one more node silent it is needed for
/// every quorum (5 of 7), so progress proves it accepts the rotated leaders.
#[test]
fn rotate_on_timeout_restart_mid_rotation() {
    let mut sim = Sim::new(7, 8, Some(0));
    sim.alive[1] = false;
    assert!(sim.run_until(300_000, |s| s.max_commit_view() >= 18), "max {}", sim.max_commit_view());
    const NODE: usize = 4;
    sim.restart(NODE);
    assert_eq!(sim.engines[NODE].current_leader_index(), sim.engines[0].current_leader_index());
    sim.alive[5] = false;
    assert!(sim.run_until(900_000, |s| s.max_commit_view() >= 30), "stalled after restart: max {}", sim.max_commit_view());
}

/// gov5 `TestRotateOnTimeoutTenureOneUnchanged` (spec S9): with tenure 1 the
/// switch changes nothing; commits and their times match the switch-off run.
#[test]
fn rotate_on_timeout_tenure_one_unchanged() {
    let runs: Vec<Vec<Commit>> = [None, Some(0)]
        .into_iter()
        .map(|rotate| {
            let mut sim = Sim::new(7, 1, rotate);
            sim.alive[3] = false;
            assert!(sim.run_until(600_000, |s| s.max_commit_view() >= 30), "rotate={rotate:?}");
            sim.commits.values().copied().collect()
        })
        .collect();
    assert_eq!(runs[0], runs[1]);
}

/// AM33 (`testdata/profile1/gov5/AM33/timeout_backoff.json`) on engines: the
/// vector's runs at n = 4 and 7 replayed on the virtual-clock network, the
/// listed leaders silent (they vote and time out but propose nothing). Each
/// view is entered at the step's view with its timer at the step's
/// timeout, and the time from entering the first silent view to entering
/// the live one is the run's `gapMs`. The engine's own pacemaker supplies
/// every timer, so this checks where `c` grows and where it does not reset
/// (a TC). The n = 100 runs are checked at the pacemaker
/// (`tests/profile1_am33.rs`).
#[test]
fn am33_runs_on_engines() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/AM33/timeout_backoff.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).expect("AM33")).expect("json");
    let num = |x: &serde_json::Value| x.as_u64().expect("number");
    let mut ran = 0;
    for run in v["runs"].as_array().expect("runs") {
        let n = num(&run["n"]) as usize;
        if n > 7 {
            continue;
        }
        let id = run["id"].as_str().expect("id");
        let mut sim = Sim::with_timeouts(
            n,
            num(&run["tenure"]),
            Some(0),
            num(&run["epochLength"]),
            num(&run["baseTimeoutMs"]),
            num(&run["maxTimeoutMs"]),
        );
        let start = num(&run["startView"]);
        for dead in run["deadLeaders"].as_array().expect("dead") {
            sim.silent_from.insert(num(dead) as usize, start);
        }
        let steps = run["steps"].as_array().expect("steps");
        let last = steps.last().expect("a QC step");
        assert_eq!(last["event"], "QC", "{id}");
        let live_view = num(&last["view"]);
        // A node that is no listed leader observes.
        let observer = (0..n).find(|i| !sim.silent_from.contains_key(i)).expect("an observer");
        assert!(
            sim.run_until(10_000_000, |s| s.commits.contains_key(&live_view)),
            "{id}: no commit at view {live_view}; views {:?}",
            sim.engines.iter().map(|e| e.current_view()).collect::<Vec<_>>()
        );
        let entered = |view: u64| *sim.entered.get(&(observer, view)).unwrap_or_else(|| panic!("{id}: view {view} not entered"));
        for (i, step) in steps.iter().enumerate() {
            let view = num(&step["view"]);
            assert_eq!(u64::from(sim.leader(view)), num(&step["leader"]), "{id} step {i}: leader");
            assert_eq!(sim.timers.get(&(observer, view)).copied(), Some(num(&step["timeoutMs"])), "{id} step {i}: timer on entry");
            if step["event"] == "TC" {
                let next = num(&step["nextView"]);
                assert_eq!(entered(next) - entered(view), num(&step["timeoutMs"]), "{id} step {i}: view {view}'s timer");
            }
        }
        assert_eq!(entered(live_view) - entered(start), num(&run["gapMs"]), "{id}: gap");
        ran += 1;
    }
    assert_eq!(ran, 17, "the n = 4 and 7 runs");
}

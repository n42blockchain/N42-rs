// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The engine at 100 and 200 validators (AM17 / AM22 of
//! `docs/MIXED_PRODUCTION_STANDARD.md`): the seven-engine virtual-clock
//! network of `state_machine_rotate_tests.rs`, grown to n engines with
//! Profile 1's values (8 s slot, base timeout 24 s, max 96 s, tenure 1).
//!
//! Messages are delivered instantly and in order; a proposal costs one slot
//! of virtual time; a view whose leader is silent ends when the live nodes'
//! pacemaker deadlines fire. Every signature is real, so the wall time is the
//! BLS work of the whole fleet on one thread. Each case prints its wall
//! time, the messages delivered per view by kind, and the largest per-node
//! buffers seen. Ignored by default (minutes in release):
//!
//! ```text
//! cargo test --release -p n42-h2-consensus --lib scale_tests -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Results: `docs/SCALE_100_VALIDATORS.md`.

use super::*;
use crate::ValidatorInfo;
use alloy_primitives::Address;
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

const SLOT_MS: u64 = 8_000;
const BASE_MS: u64 = 24_000;
const MAX_MS: u64 = 96_000;

fn validators(n: usize) -> (Vec<n42_h2_primitives::BlsSecretKey>, ValidatorSet) {
    let sks: Vec<_> = (0..n)
        .map(|i| {
            let mut ikm = [0x61u8; 32];
            ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
            n42_h2_primitives::BlsSecretKey::key_gen(&ikm).expect("a valid deterministic key")
        })
        .collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo {
            address: Address::left_padding_from(&(i as u64).to_be_bytes()),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let vs = ValidatorSet::new(&infos, ((n as u32).saturating_sub(1)) / 3);
    (sks, vs)
}

/// Largest per-node bookkeeping seen during a run.
#[derive(Debug, Default, Clone, Copy)]
struct Peaks {
    future_msgs: usize,
    future_timeout_collectors: usize,
    future_timeout_views: usize,
    voters_seen_views: usize,
    parked_vote_views: usize,
    imported_blocks: usize,
    queued_votes: usize,
}

struct Sim {
    vs: ValidatorSet,
    engines: Vec<ConsensusEngine>,
    rxs: Vec<mpsc::Receiver<EngineOutput>>,
    alive: Vec<bool>,
    aggregate: bool,
    now: u64,
    deadline: Vec<u64>,
    seen_view: Vec<u64>,
    proposed: HashSet<u64>,
    /// view -> (block hash, virtual time of the first commit seen).
    commits: BTreeMap<u64, (B256, u64)>,
    /// Commits that named a different block for an already committed view.
    conflicts: usize,
    parents: HashMap<B256, B256>,
    queue: VecDeque<(usize, ConsensusEvent)>,
    delivered: BTreeMap<&'static str, u64>,
    events: u64,
    errors: u64,
    peaks: Peaks,
}

fn kind(message: &ConsensusMessage) -> &'static str {
    match message {
        ConsensusMessage::Proposal(_) => "Proposal",
        ConsensusMessage::Vote(_) => "Vote",
        ConsensusMessage::CommitVote(_) => "CommitVote",
        ConsensusMessage::PrepareQC(_) => "PrepareQC",
        ConsensusMessage::Timeout(_) => "Timeout",
        ConsensusMessage::NewView(_) => "NewView",
        ConsensusMessage::Decide(_) => "Decide",
    }
}

impl Sim {
    fn new(n: usize, aggregate: bool) -> Self {
        let (sks, vs) = validators(n);
        let mut engines = Vec::with_capacity(n);
        let mut rxs = Vec::with_capacity(n);
        for (i, sk) in sks.iter().enumerate() {
            let (tx, rx) = mpsc::channel(65_536);
            let mut e = ConsensusEngine::new(i as u32, sk.clone(), vs.clone(), BASE_MS, MAX_MS, tx);
            e.set_leader_tenure(1);
            e.set_rotate_on_timeout(Some(0), 0);
            e.set_vote_aggregate(aggregate);
            engines.push(e);
            rxs.push(rx);
        }
        Self {
            vs,
            engines,
            rxs,
            alive: vec![true; n],
            aggregate,
            now: 0,
            deadline: vec![BASE_MS; n],
            seen_view: vec![0; n],
            proposed: HashSet::new(),
            commits: BTreeMap::new(),
            conflicts: 0,
            parents: HashMap::new(),
            queue: VecDeque::new(),
            delivered: BTreeMap::new(),
            events: 0,
            errors: 0,
            peaks: Peaks::default(),
        }
    }

    fn deliver(&mut self, to: usize, message: ConsensusMessage) {
        if self.alive[to] {
            *self.delivered.entry(kind(&message)).or_default() += 1;
            self.queue.push_back((to, ConsensusEvent::Message(message)));
        }
    }

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
                    EngineOutput::BlockCommitted { view, block_hash, .. } => {
                        let at = self.now;
                        match self.commits.get(&view) {
                            Some((hash, _)) if *hash != block_hash => self.conflicts += 1,
                            Some(_) => {}
                            None => {
                                self.commits.insert(view, (block_hash, at));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn sample(&mut self) {
        let p = &mut self.peaks;
        for e in &self.engines {
            p.future_msgs = p.future_msgs.max(e.future_msg_buffer.len());
            p.future_timeout_collectors = p.future_timeout_collectors.max(e.future_timeout_collectors.len());
            p.future_timeout_views = p.future_timeout_views.max(e.future_timeout_views.len());
            p.voters_seen_views = p.voters_seen_views.max(e.voters_seen.len());
            p.parked_vote_views = p.parked_vote_views.max(e.parked_votes.len());
            p.imported_blocks = p.imported_blocks.max(e.imported_blocks.len());
            p.queued_votes = p.queued_votes.max(e.vote_queue.len());
        }
    }

    /// Delivers until quiet (flushing the vote batches when on), then a live
    /// leader that has not proposed in its view proposes.
    fn settle(&mut self, done: &impl Fn(&Self) -> bool) {
        loop {
            self.collect();
            if let Some((to, event)) = self.queue.pop_front() {
                self.events += 1;
                assert!(self.events < 50_000_000, "no quiescence at {} ms", self.now);
                let event = match event {
                    ConsensusEvent::Message(m) if self.aggregate => match self.engines[to].queue_vote(m) {
                        Some(m) => ConsensusEvent::Message(m),
                        None => continue,
                    },
                    other => other,
                };
                if self.engines[to].process_event(event).is_err() {
                    self.errors += 1;
                }
                continue;
            }
            if self.aggregate {
                let mut flushed = false;
                for i in 0..self.engines.len() {
                    if self.alive[i] && self.engines[i].queued_votes() > 0 {
                        flushed = true;
                        if self.engines[i].flush_votes().is_err() {
                            self.errors += 1;
                        }
                    }
                }
                if flushed {
                    self.collect();
                    if !self.queue.is_empty() {
                        continue;
                    }
                }
            }
            self.sample();
            self.refresh_deadlines();
            if done(self) {
                return;
            }
            let mut proposed = false;
            for i in 0..self.engines.len() {
                let view = self.engines[i].current_view();
                if self.alive[i] && self.engines[i].is_current_leader() && !self.proposed.contains(&view) {
                    self.proposed.insert(view);
                    self.now += SLOT_MS;
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&view.to_be_bytes());
                    hash[31] = 0xB1;
                    if self.engines[i].process_event(ConsensusEvent::BlockReady(B256::new(hash), None)).is_err() {
                        self.errors += 1;
                    }
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
                self.deadline[i] = self.now + self.timeout_ms(i);
            }
        }
    }

    fn timeout_ms(&self, i: usize) -> u64 {
        let e = &self.engines[i];
        e.pacemaker.timeout_duration(e.consecutive_timeouts()).as_millis() as u64
    }

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
                if self.engines[i].on_timeout().is_err() {
                    self.errors += 1;
                }
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

    fn max_view(&self) -> u64 {
        (0..self.engines.len()).filter(|i| self.alive[*i]).map(|i| self.engines[i].current_view()).max().unwrap_or(0)
    }

    fn report(&self, name: &str, wall: std::time::Duration) {
        let views = self.max_view().max(1);
        let total: u64 = self.delivered.values().sum();
        println!(
            "[{name}] n={} aggregate={} wall {:.1} s, virtual {:.0} s, views {views}, commits {} (max view {}), \
             conflicts {}, engine errors {}, events {}",
            self.engines.len(),
            self.aggregate,
            wall.as_secs_f64(),
            self.now as f64 / 1000.0,
            self.commits.len(),
            self.max_commit_view(),
            self.conflicts,
            self.errors,
            self.events,
        );
        let per_view: Vec<String> =
            self.delivered.iter().map(|(k, v)| format!("{k} {:.0}", *v as f64 / views as f64)).collect();
        println!(
            "[{name}] deliveries per view: {:.0} total ({}); wall per view {:.0} ms",
            total as f64 / views as f64,
            per_view.join(", "),
            wall.as_secs_f64() * 1000.0 / views as f64,
        );
        println!("[{name}] per-node peaks: {:?}", self.peaks);
    }
}

fn steady(n: usize, views: u64, aggregate: bool) {
    let mut sim = Sim::new(n, aggregate);
    let start = Instant::now();
    assert!(sim.run_until(views * SLOT_MS * 4, |s| s.max_commit_view() >= views), "max commit {}", sim.max_commit_view());
    sim.report(&format!("steady {views}"), start.elapsed());
    let expected: Vec<u64> = (1..=views).collect();
    let got: Vec<u64> = sim.commits.keys().copied().filter(|v| *v <= views).collect();
    assert_eq!(got, expected, "every view commits");
    assert_eq!(sim.conflicts, 0);
    for pair in sim.commits.values().collect::<Vec<_>>().windows(2) {
        assert_eq!(pair[1].1 - pair[0].1, SLOT_MS, "one block a slot");
    }
}

fn leader_down(n: usize) {
    const DEAD: usize = 10;
    let mut sim = Sim::new(n, false);
    sim.alive[DEAD] = false;
    let start = Instant::now();
    assert!(sim.run_until(3_600_000, |s| s.max_commit_view() >= 20), "max commit {}", sim.max_commit_view());
    sim.report("leader down", start.elapsed());
    assert_eq!(sim.conflicts, 0);
    assert!(!sim.commits.contains_key(&(DEAD as u64)), "the dead leader's view commits nothing");
    let before = sim.commits.get(&(DEAD as u64 - 1)).expect("view before the dead leader").1;
    let after = sim.commits.get(&(DEAD as u64 + 1)).expect("the view after recovers").1;
    println!("[leader down] stall {} ms (base timeout {BASE_MS} ms)", after - before);
    assert!(after - before <= BASE_MS + 2 * SLOT_MS, "one base timeout");
}

/// Every third member from index 2: 33 of 100 (f), spread over the
/// round-robin so live and silent leaders interleave.
fn silent_set(n: usize, count: usize) -> Vec<usize> {
    (0..n).filter(|i| i % 3 == 2).take(count).collect()
}

#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_100_steady_state_50_views() {
    steady(100, 50, false);
}

#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_100_steady_state_50_views_batched_votes() {
    steady(100, 50, true);
}

#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_100_one_leader_down() {
    leader_down(100);
}

/// f = 33 silent: the remaining 67 are exactly a quorum, so every view with
/// a live leader commits and every view with a silent one times out.
#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_100_f_silent_still_commits() {
    let n = 100;
    let mut sim = Sim::new(n, false);
    let silent = silent_set(n, 33);
    assert_eq!(silent.len(), 33);
    for &i in &silent {
        sim.alive[i] = false;
    }
    let start = Instant::now();
    let target = 30;
    assert!(sim.run_until(24 * 3_600_000, |s| s.max_view() > target), "max view {}", sim.max_view());
    sim.report("f=33 silent", start.elapsed());
    assert_eq!(sim.conflicts, 0);
    let live_leader_views: Vec<u64> =
        (1..=target).filter(|v| sim.alive[(*v as usize) % n]).collect();
    let committed: Vec<u64> = sim.commits.keys().copied().filter(|v| *v <= target).collect();
    assert_eq!(committed, live_leader_views, "every view with a live leader commits");
}

/// f + 1 = 34 silent: 66 live members are one short of a quorum. Nothing
/// commits, nothing panics, and the per-node buffers stay bounded while the
/// live members keep timing out at the maximum backoff.
#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_100_f_plus_one_silent_never_commits() {
    let n = 100;
    let mut sim = Sim::new(n, false);
    let mut silent = silent_set(n, 33);
    silent.push(0);
    for &i in &silent {
        sim.alive[i] = false;
    }
    let start = Instant::now();
    // One virtual hour: with the backoff capped at 96 s, ~40 timeout rounds.
    sim.run_until(3_600_000, |_| false);
    sim.report("f+1=34 silent", start.elapsed());
    assert!(sim.commits.is_empty(), "no quorum, no commit: {:?}", sim.commits.keys().collect::<Vec<_>>());
    let p = sim.peaks;
    assert!(p.future_msgs <= 256, "{p:?}");
    assert!(p.future_timeout_collectors <= FUTURE_VIEW_WINDOW as usize, "{p:?}");
    assert!(p.future_timeout_views <= n, "{p:?}");
}

#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_200_steady_state_20_views() {
    steady(200, 20, false);
}

#[test]
#[ignore = "scale measurement; release, --nocapture"]
fn scale_200_one_leader_down() {
    leader_down(200);
}


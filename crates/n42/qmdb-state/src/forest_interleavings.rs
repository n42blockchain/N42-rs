// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every interleaving of the empty-block tenure handover over the forest's
//! own API (the same-parent rebuild root mismatch, plan rows G8 / M1 / S1).
//!
//! The shape both occurrences died in (blocks 8191 and 7167): one execution
//! layer, three executions of one block number on one parent P -- the
//! outgoing leader's chain build (E1), the incoming leader's given-up FCU
//! payload job whose root job still files (E2), the incoming leader's own
//! build (E3) -- the hand-off renaming E3's built hash to the sealed hash S,
//! the chain building a child C on S ahead of canonical (its parent rename
//! first, as `file_parent_under_seal_with_barrier` does), and the forkchoice
//! to S. Each actor is a sequence of the forest calls it makes, one call per
//! hold of the node's forest lock; this test runs *every* order of those
//! calls the lock allows, replaying each schedule from a fresh forest
//! (stateless model checking with backtracking).
//!
//! The lock rules modelled are `QmdbNodeState`'s: a computation either
//! holds the lock throughout (`compute_operations`) or leases the tree
//! (`N42_QMDB_COMPUTE_OFFLOCK`: lease and compute, then return in a second
//! hold, optionally with leaf hashes computed ahead,
//! `N42_QMDB_PARALLEL_APPLY` / `N42_ROOT_OPS_BEFORE_GATE`); while the tree is
//! out only the tree-free labels run (`rename`, `on_canonical_defer`, which
//! is `set_canonical_in_place` and waits for the tree when the head is off
//! the tip's path), every other taker waits for the tree. A queued rename
//! (`N42_QMDB_RENAME_DEFER`) runs at the start of the next hold, which is an
//! order this enumeration already contains.
//!
//! What is checked after every step: the tree's root is the root filed for
//! the block the forest says it stands at (or the pending block's root), and
//! every filed record and every computed root is the reference root of the
//! block it names -- a root computed over a sibling's state fails here, at
//! the step that computed it. At the end of each schedule the forest is
//! moved to every block it holds (through the parent's parent and a sibling
//! of P, so every record is reverted and replayed) and must land on each
//! filed root, and a fresh child of S must land on C's reference root.
use super::*;
use crate::AccountState;
use alloy_primitives::U256;
use n42_twig_core::qmdb_compat::LeafHashes;

const GENESIS: B256 = B256::repeat_byte(0xA0);
const GRANDPARENT: B256 = B256::repeat_byte(0x01);
const PARENT: B256 = B256::repeat_byte(0x02);
/// A sibling of the parent, filed unapplied: the final sweep's move to it
/// reverts the parent and replays it back.
const UNCLE: B256 = B256::repeat_byte(0x12);
const SEALED: B256 = B256::repeat_byte(0x5E);
const TWIG_SLOTS: u64 = n42_twig_core::TWIG_SIZE as u64;

/// How a root is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `compute_operations` under the lock.
    Locked,
    /// Lease the tree and compute on it, return it in a second hold.
    Leased,
    /// [`Self::Leased`] with the operations' leaf hashes computed ahead.
    LeasedLeaves,
}

/// One forest call, made in one hold of the node's lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// `compute_operations` for a build, under the lock.
    Compute(usize),
    /// `lease_tree` and the computation on the lease.
    Lease(usize),
    /// `return_tree`: the build's root filed as pending work.
    Return(usize),
    /// `insert` of a build's prepared block under its hash.
    Insert(usize),
    /// `rename`; a failure is what the node logs and goes on from.
    Rename(B256, B256),
    /// The forkchoice: `set_canonical_in_place` with the tree out,
    /// `set_canonical_releasing` with it here.
    Canon(B256),
}

impl Step {
    /// Whether the step needs the tree (waits while it is leased).
    const fn needs_tree(self) -> bool {
        matches!(self, Self::Compute(_) | Self::Lease(_) | Self::Insert(_))
    }
}

/// One execution of a block.
#[derive(Debug)]
struct Build {
    name: &'static str,
    parent: B256,
    hash: B256,
    number: u64,
    ops: QmdbOps,
    /// Its root on the true state of its parent.
    reference: B256,
}

/// The actors and what orders the lock allows them.
#[derive(Debug)]
struct Scenario {
    builds: Vec<Build>,
    actors: Vec<(&'static str, Vec<Step>)>,
    /// `(actor, step)` may run only once `(actor, step)` has run.
    after: Vec<((usize, usize), (usize, usize))>,
    /// Every hash a record may be filed under, with the reference root of
    /// the block it names.
    roots: HashMap<B256, B256>,
    entry_file: Option<std::path::PathBuf>,
    /// See [`start`].
    pad_to: Option<u64>,
}

/// Leaf operations of an empty block's shape: a write every execution of
/// the height makes alike (the history contract's slot), a write keyed by
/// what differs between them (the beacon-roots slot of the timestamp), the
/// withdrawal recipient's balance, a deletion and a fresh account.
fn empty_block(tag: u64, beneficiary: u8) -> QmdbOps {
    let mut c = BlockChanges::new();
    c.set_account(
        Address::with_last_byte(0xC1),
        AccountState { nonce: 1, balance: U256::from(77u64), code_hash: B256::ZERO },
    );
    c.set_account(
        Address::from_word(B256::from(U256::from(900_000u64 + tag))),
        AccountState { nonce: 1, balance: U256::from(tag), code_hash: B256::ZERO },
    );
    c.set_account(
        Address::with_last_byte(beneficiary),
        AccountState { nonce: 0, balance: U256::from(1_000u64 + u64::from(beneficiary)), code_hash: B256::ZERO },
    );
    c.set_storage(Address::with_last_byte(0xC2), B256::with_last_byte(1), U256::from(tag + 5));
    // The slot the grandparent wrote, cleared.
    c.set_storage(Address::with_last_byte(0xC2), B256::with_last_byte(9), U256::ZERO);
    let mut ops = c.ops();
    ops.sort();
    ops
}

fn base_block(tag: u64) -> BlockChanges {
    let mut c = BlockChanges::new();
    for i in 0..24u64 {
        c.set_account(
            Address::from_word(B256::from(U256::from(10_000 * tag + i))),
            AccountState { nonce: tag, balance: U256::from(i), code_hash: B256::ZERO },
        );
    }
    c.set_storage(Address::with_last_byte(0xC2), B256::with_last_byte(9), U256::from(tag));
    c
}

/// Genesis, the grandparent, the parent (canonical, the tree at it), and
/// the parent's sibling filed unapplied. With `pad_to`, genesis fills the
/// first twig (no undo holds it, so every head move trims its leaves) and
/// the parent writes enough fresh accounts that the tree's cursor stands at
/// that slot after it, so the height's executions append across a twig
/// boundary.
fn start(entry_file: Option<&std::path::Path>, pad_to: Option<u64>) -> QmdbForest {
    let mut alloc = base_block(1);
    if pad_to.is_some() {
        for i in 0..TWIG_SLOTS + 16 {
            alloc.set_account(
                Address::from_word(B256::from(U256::from(7_000_000u64 + i))),
                AccountState { nonce: 1, balance: U256::from(i), code_hash: B256::ZERO },
            );
        }
    }
    let mut forest = QmdbForest::genesis(GENESIS, &alloc).unwrap();
    if let Some(path) = entry_file {
        let _ = std::fs::remove_file(path);
        forest = forest.with_entry_file(path).unwrap();
    }
    forest.apply(GENESIS, GRANDPARENT, 1, &base_block(2)).unwrap();
    forest.set_canonical(GRANDPARENT).unwrap();
    forest.apply(GRANDPARENT, UNCLE, 2, &base_block(4)).unwrap();
    let mut parent = base_block(3);
    if let Some(target) = pad_to {
        // Every fresh account appends one slot.
        let unpadded = forest.compute(GRANDPARENT, &parent).unwrap();
        drop(unpadded);
        let at = forest.next_slot();
        assert!(target >= at, "pad target {target} below the unpadded cursor {at}");
        for i in 0..target - at {
            parent.set_account(
                Address::from_word(B256::from(U256::from(5_000_000u64 + i))),
                AccountState { nonce: 1, balance: U256::from(i), code_hash: B256::ZERO },
            );
        }
    }
    forest.apply(GRANDPARENT, PARENT, 2, &parent).unwrap();
    forest.set_canonical(PARENT).unwrap();
    if let Some(target) = pad_to {
        assert_eq!(forest.next_slot(), target);
        assert!(forest.trimmed_twigs().0 >= 1, "the first twig is trimmed");
    }
    forest
}

/// The reference roots: each build computed alone on a fresh forest.
fn reference_root(pad_to: Option<u64>, parent_chain: &[&QmdbOps], ops: &QmdbOps) -> B256 {
    let mut forest = start(None, pad_to);
    let mut parent = PARENT;
    for (i, step) in parent_chain.iter().enumerate() {
        let prepared = forest.compute_operations(parent, (*step).clone()).unwrap();
        let hash = B256::with_last_byte(0xE0 + i as u8);
        forest.insert(hash, 3 + i as u64, prepared).unwrap();
        parent = hash;
    }
    forest.compute_operations(parent, ops.clone()).unwrap().root
}

/// Which executions of the height share what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Siblings {
    /// E2 and E3 differ (another timestamp): three roots.
    Distinct,
    /// E2 and E3 are the same block content under two built hashes: one
    /// root, the equal-root adoption.
    SameContent,
    /// E2 and E3 are the same block under one built hash: the second
    /// insert is the early return.
    SameHash,
}

fn scenario(mode: Mode, siblings: Siblings, entry_file: Option<std::path::PathBuf>, pad_to: Option<u64>) -> Scenario {
    let e1 = empty_block(1, 0xB6);
    let e2 = empty_block(if siblings == Siblings::Distinct { 2 } else { 3 }, 0xB0);
    let e3 = empty_block(3, 0xB0);
    let child = empty_block(4, 0xB0);
    let b1 = B256::repeat_byte(0xB1);
    let b2 = B256::repeat_byte(0xB2);
    let b3 = if siblings == Siblings::SameHash { b2 } else { B256::repeat_byte(0xB3) };
    let bc = B256::repeat_byte(0xBC);
    let r1 = reference_root(pad_to, &[], &e1);
    let r2 = reference_root(pad_to, &[], &e2);
    let r3 = reference_root(pad_to, &[], &e3);
    let rc = reference_root(pad_to, &[&e3], &child);
    let builds = vec![
        Build { name: "E1", parent: PARENT, hash: b1, number: 3, ops: e1, reference: r1 },
        Build { name: "E2", parent: PARENT, hash: b2, number: 3, ops: e2, reference: r2 },
        Build { name: "E3", parent: PARENT, hash: b3, number: 3, ops: e3, reference: r3 },
        Build { name: "C", parent: SEALED, hash: bc, number: 4, ops: child, reference: rc },
    ];
    let compute = |b: usize| -> Vec<Step> {
        match mode {
            Mode::Locked => vec![Step::Compute(b), Step::Insert(b)],
            Mode::Leased | Mode::LeasedLeaves => vec![Step::Lease(b), Step::Return(b), Step::Insert(b)],
        }
    };
    let insert_at = compute(0).len() - 1;
    let mut child_steps = vec![Step::Rename(b3, SEALED)];
    child_steps.extend(compute(3));
    let actors = vec![
        ("E1", compute(0)),
        ("E2", compute(1)),
        ("E3", compute(2)),
        ("handoff", vec![Step::Rename(b3, SEALED)]),
        ("child", child_steps),
        ("forkchoice", vec![Step::Canon(SEALED)]),
    ];
    let after = vec![
        // The chain's parent rename waits for the parent's build to be
        // complete (its root filed).
        ((4, 0), (2, insert_at)),
        // The forkchoice to S follows the hand-off and the import.
        ((5, 0), (3, 0)),
        ((5, 0), (2, insert_at)),
    ];
    let mut roots = HashMap::new();
    roots.insert(b1, r1);
    roots.insert(b2, r2);
    roots.insert(b3, r3);
    roots.insert(SEALED, r3);
    roots.insert(bc, rc);
    Scenario { builds, actors, after, roots, entry_file, pad_to }
}

/// One schedule's run.
struct Run<'a> {
    scenario: &'a Scenario,
    mode: Mode,
    forest: QmdbForest,
    prepared: Vec<Option<PreparedBlock>>,
    lease: Option<(usize, TreeLease, Result<LeasedRoot, StateError>)>,
    pc: Vec<usize>,
    aborted: Vec<bool>,
    trace: Vec<String>,
}

impl<'a> Run<'a> {
    fn new(scenario: &'a Scenario, mode: Mode) -> Self {
        let forest = start(scenario.entry_file.as_deref(), scenario.pad_to);
        Self {
            scenario,
            mode,
            forest,
            prepared: (0..scenario.builds.len()).map(|_| None).collect(),
            lease: None,
            pc: vec![0; scenario.actors.len()],
            aborted: vec![false; scenario.actors.len()],
            trace: Vec::new(),
        }
    }

    fn done(&self, (actor, step): (usize, usize)) -> bool {
        self.pc[actor] > step
    }

    /// The actors whose next step the lock lets run now.
    fn enabled(&self) -> Vec<usize> {
        (0..self.scenario.actors.len())
            .filter(|&actor| {
                let steps = &self.scenario.actors[actor].1;
                if self.aborted[actor] || self.pc[actor] >= steps.len() {
                    return false;
                }
                let at = (actor, self.pc[actor]);
                if self.scenario.after.iter().any(|(this, before)| *this == at && !self.done(*before)) {
                    return false;
                }
                let step = steps[self.pc[actor]];
                let leased = self.lease.is_some();
                match step {
                    Step::Return(b) => self.lease.as_ref().is_some_and(|(owner, _, _)| *owner == b),
                    // `on_canonical_defer` runs with the tree out only when the
                    // head is on the tip's path; otherwise it waits.
                    Step::Canon(head) => !leased || self.forest.ancestry(self.forest.tip).contains(&head),
                    step => !(leased && step.needs_tree()),
                }
            })
            .collect()
    }

    fn fail(&self, what: String) -> String {
        format!("{what}\n  mode {:?}\n  schedule:\n    {}", self.mode, self.trace.join("\n    "))
    }

    fn check_root(&self, build: usize, root: B256, how: &str) -> Result<(), String> {
        let b = &self.scenario.builds[build];
        if root != b.reference {
            return Err(self.fail(format!(
                "{} {how} root {root}, but its parent's true state gives {}",
                b.name, b.reference
            )));
        }
        Ok(())
    }

    fn step(&mut self, actor: usize) -> Result<(), String> {
        let step = self.scenario.actors[actor].1[self.pc[actor]];
        self.pc[actor] += 1;
        let builds = &self.scenario.builds;
        let outcome: String = match step {
            Step::Compute(b) => match self.forest.compute_operations(builds[b].parent, builds[b].ops.clone()) {
                Ok(prepared) => {
                    self.check_root(b, prepared.root, "computed")?;
                    self.prepared[b] = Some(prepared);
                    "ok".into()
                }
                Err(err) => {
                    self.aborted[actor] = true;
                    format!("refused: {err}")
                }
            },
            Step::Lease(b) => match self.forest.lease_tree(builds[b].parent) {
                Ok(mut lease) => {
                    let ops = builds[b].ops.clone();
                    let leaves = (self.mode == Mode::LeasedLeaves).then(|| LeafHashes::of(&ops));
                    let computed = lease.compute_with_leaves(ops, leaves.as_ref());
                    self.lease = Some((b, lease, computed));
                    "leased".into()
                }
                Err(err) => {
                    self.aborted[actor] = true;
                    format!("refused: {err}")
                }
            },
            Step::Return(b) => {
                let (owner, lease, computed) = self.lease.take().expect("enabled only with its lease out");
                assert_eq!(owner, b);
                match self.forest.return_tree(lease, computed) {
                    Ok((prepared, renamed)) => {
                        self.check_root(b, prepared.root, "computed")?;
                        self.prepared[b] = Some(prepared);
                        format!("ok renamed={renamed}")
                    }
                    Err(err) => return Err(self.fail(format!("{} return_tree failed: {err}", builds[b].name))),
                }
            }
            Step::Insert(b) => {
                let Some(prepared) = self.prepared[b].take() else {
                    return Err(self.fail(format!("{} has nothing to insert", builds[b].name)));
                };
                self.forest
                    .insert(builds[b].hash, builds[b].number, prepared)
                    .map_err(|err| self.fail(format!("{} insert failed: {err}", builds[b].name)))?;
                "ok".into()
            }
            Step::Rename(from, to) => match self.forest.rename(from, to) {
                Ok(()) => "ok".into(),
                Err(err) => format!("refused: {err}"),
            },
            Step::Canon(head) => {
                let result = if self.lease.is_some() {
                    self.forest.set_canonical_in_place(head).map(|released| assert!(released.is_some()))
                } else {
                    self.forest.set_canonical_releasing(head).map(drop)
                };
                match result {
                    Ok(()) => "ok".into(),
                    Err(err @ StateError::Replay { .. }) => return Err(self.fail(format!("forkchoice to S: {err}"))),
                    Err(err) => {
                        self.aborted[actor] = true;
                        format!("refused: {err}")
                    }
                }
            }
        };
        self.trace.push(format!(
            "{:<10} {:<24} -> {outcome}; tip {} pending {:?}",
            self.scenario.actors[actor].0,
            format!("{step:?}").replace("0x", ""),
            short(self.forest.tip),
            self.forest.pending.as_ref().map(|(parent, _)| short(*parent)),
        ));
        self.check_invariants()
    }

    /// The tree is the state of the block the forest says it stands at, and
    /// every record is its block's reference root.
    fn check_invariants(&self) -> Result<(), String> {
        if let Some(reason) = self.forest.poisoned() {
            return Err(self.fail(format!("forest poisoned: {reason}")));
        }
        for (hash, record) in &self.forest.records {
            if let Some(reference) = self.scenario.roots.get(hash)
                && record.root != *reference
            {
                return Err(self.fail(format!("record {} filed with root {}, its block's root is {reference}", short(*hash), record.root)));
            }
        }
        if self.lease.is_some() {
            return Ok(());
        }
        let got = B256::from(self.forest.tree.root());
        let expected = match &self.forest.pending {
            Some((parent, _)) => {
                if *parent != self.forest.tip {
                    return Err(self.fail(format!("pending work on {} with the tip at {}", short(*parent), short(self.forest.tip))));
                }
                self.forest.pending_root
            }
            None => match self.forest.records.get(&self.forest.tip) {
                Some(record) => record.root,
                None => return Err(self.fail(format!("the tip {} is not filed", short(self.forest.tip)))),
            },
        };
        if got != expected {
            return Err(self.fail(format!("mislabelled tree: at {} the tree root is {got}, expected {expected}", short(self.forest.tip))));
        }
        Ok(())
    }

    /// Every record replays onto its filed root, and the next build on S
    /// lands on C's reference.
    fn finish(&mut self) -> Result<(), String> {
        if let Some((owner, _, _)) = &self.lease {
            return Err(self.fail(format!("schedule ended with {}'s lease out", self.scenario.builds[*owner].name)));
        }
        let mut hashes: Vec<B256> = self.forest.records.keys().copied().collect();
        hashes.sort();
        hashes.push(UNCLE);
        hashes.push(SEALED);
        for hash in hashes {
            if !self.forest.records.contains_key(&hash) {
                continue;
            }
            self.forest.move_to(hash).map_err(|err| self.fail(format!("final move to {}: {err}", short(hash))))?;
            if let Some((expected, got)) = self.forest.tree_mismatch(hash) {
                return Err(self.fail(format!("final move to {}: tree root {got}, filed {expected}", short(hash))));
            }
        }
        if self.forest.records.contains_key(&SEALED) {
            let child = &self.scenario.builds[3];
            let root = self
                .forest
                .compute_operations(SEALED, child.ops.clone())
                .map_err(|err| self.fail(format!("a fresh child of S: {err}")))?
                .root;
            if root != child.reference {
                return Err(self.fail(format!("a fresh child of S lands on {root}, reference {}", child.reference)));
            }
        }
        Ok(())
    }
}

fn short(hash: B256) -> String {
    let byte = hash.0[0];
    if hash == B256::repeat_byte(byte) { format!("{byte:02x}") } else { format!("{hash}") }
}

impl Run<'_> {
    /// Everything the rest of a schedule depends on: where each actor is and
    /// what it holds, and the forest's bookkeeping with the tree's root,
    /// cursor and trimmed twigs (the invariants checked at every step tie
    /// the tree's content to these labels). Two histories that reach the
    /// same signature have the same futures, so the second is not extended.
    fn signature(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("{:?}{:?}", self.pc, self.aborted);
        for prepared in &self.prepared {
            let _ = write!(out, "|{:?}", prepared.as_ref().map(|p| (p.root, p.parent)));
        }
        if let Some((owner, lease, computed)) = &self.lease {
            let _ = write!(out, "|lease {owner} {} {:?}", lease.parent, computed.as_ref().map(LeasedRoot::root).map_err(ToString::to_string));
        } else {
            let tree = &self.forest.tree;
            let _ = write!(out, "|tree {} {} {}", B256::from(tree.root()), tree.next_slot(), tree.trimmed_twigs());
        }
        let forest = &self.forest;
        let _ = write!(
            out,
            "|tip {} pending {:?} head {:?} poisoned {:?}",
            forest.tip,
            forest.pending.as_ref().map(|(parent, _)| (*parent, forest.pending_root)),
            forest.head,
            forest.poisoned,
        );
        let mut records: Vec<_> = forest.records.iter().collect();
        records.sort_by_key(|(hash, _)| **hash);
        for (hash, record) in records {
            let _ = write!(out, "|{hash} {} {} {} {}", record.parent, record.number, record.root, record.undo.is_some());
        }
        out
    }
}

/// What [`explore`] covered: the distinct states visited, and how many
/// schedules (orders of every actor's calls the lock allows) pass through
/// them -- each one checked, since a schedule's every state and its end
/// state were.
#[derive(Debug, Default, Clone, Copy)]
struct Coverage {
    states: u64,
    ends: u64,
    schedules: u128,
}

/// Explores every schedule of `scenario` depth first, replaying each
/// prefix on a fresh forest; returns the coverage or the first failure.
fn explore(scenario: &Scenario, mode: Mode) -> Result<Coverage, String> {
    fn visit(
        scenario: &Scenario,
        mode: Mode,
        prefix: &mut Vec<usize>,
        memo: &mut HashMap<String, u128>,
        coverage: &mut Coverage,
    ) -> Result<u128, String> {
        let mut run = Run::new(scenario, mode);
        run.check_invariants()?;
        for &actor in prefix.iter() {
            run.step(actor)?;
        }
        let signature = run.signature();
        if let Some(paths) = memo.get(&signature) {
            return Ok(*paths);
        }
        coverage.states += 1;
        let enabled = run.enabled();
        let paths = if enabled.is_empty() {
            run.finish()?;
            coverage.ends += 1;
            1
        } else {
            drop(run);
            let mut paths = 0u128;
            for actor in enabled {
                prefix.push(actor);
                paths += visit(scenario, mode, prefix, memo, coverage)?;
                prefix.pop();
            }
            paths
        };
        memo.insert(signature, paths);
        Ok(paths)
    }
    let mut coverage = Coverage::default();
    coverage.schedules = visit(scenario, mode, &mut Vec::new(), &mut HashMap::new(), &mut coverage)?;
    Ok(coverage)
}

fn explore_all(entry_file: bool, pads: &[Option<u64>], modes: &[Mode]) {
    let path = entry_file.then(|| std::env::temp_dir().join(format!("n42-forest-interleavings-{}.entries", std::process::id())));
    let mut total = 0;
    // Two slots short of the second twig's end: each execution of the
    // height (five leaf operations, four appends) crosses into the third.
    for &pad_to in pads {
        for &mode in modes {
            for siblings in [Siblings::Distinct, Siblings::SameContent, Siblings::SameHash] {
                let scenario = scenario(mode, siblings, path.clone(), pad_to);
                let coverage = explore(&scenario, mode)
                    .unwrap_or_else(|failure| panic!("{siblings:?}, cursor {pad_to:?}: {failure}"));
                eprintln!(
                    "handover interleavings: mode {mode:?}, siblings {siblings:?}, entry file {entry_file}, \
                     cursor {pad_to:?}: {} states, {} end states, {} schedules",
                    coverage.states, coverage.ends, coverage.schedules,
                );
                total += coverage.schedules;
            }
        }
    }
    if let Some(path) = path {
        let _ = std::fs::remove_file(path);
    }
    assert!(total > 0);
}

/// Two slots short of the second twig's end: each execution of the height
/// (five leaf operations, four appends) crosses into the third twig.
const ACROSS_A_TWIG: Option<u64> = Some(2 * TWIG_SLOTS - 2);

const ALL_MODES: [Mode; 3] = [Mode::Locked, Mode::Leased, Mode::LeasedLeaves];

/// The fleet's mode (a leased tree, `N42_QMDB_COMPUTE_OFFLOCK`) and every
/// sibling shape on a heap tree: 216,234 schedules, a few minutes in a
/// debug build.
#[test]
fn every_order_of_the_empty_block_handover_replays_to_the_filed_roots() {
    explore_all(false, &[None], &[Mode::Leased]);
}

/// The whole matrix: heap and entry file, with the height's appends inside
/// a twig and across a twig boundary over a trimmed twig (~12 minutes in a
/// release build: `cargo test --release -p n42-qmdb-state --lib
/// interleavings -- --ignored`).
#[test]
#[ignore = "the full matrix; ~12 minutes in a release build"]
fn every_order_of_the_empty_block_handover_replays_to_the_filed_roots_full_matrix() {
    explore_all(false, &[None, ACROSS_A_TWIG], &ALL_MODES);
    explore_all(true, &[None, ACROSS_A_TWIG], &ALL_MODES);
}

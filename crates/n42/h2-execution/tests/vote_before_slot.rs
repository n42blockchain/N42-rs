// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The deferred import slot (`N42_DEFERRED_IN_FLIGHT`) and the vote ahead of
//! it (`N42_VOTE_BEFORE_SLOT`), against the in-memory Engine API with each
//! body import held open after its check until the test lets it land
//! ([`MockBehaviour::body_gate`]) -- an engine that has not landed the block
//! yet, which is what keeps a slot taken.
//!
//! Every wait is bounded. No test pauses the clock.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use n42_h2_consensus::{ConsensusEvent, EngineOutput};
use n42_h2_execution::{
    BuiltBlock, DriverAction, ElCall, ExecutionDriver, ForeignBody, ImportReport, MockBehaviour, MockExecutionLayer,
};
use tokio::sync::{mpsc::UnboundedReceiver, Semaphore};

const GENESIS: B256 = B256::ZERO;

fn execute(hash: B256) -> EngineOutput {
    EngineOutput::ExecuteBlock(hash)
}

fn committed(hash: B256) -> EngineOutput {
    EngineOutput::BlockCommitted {
        view: 1,
        block_hash: hash,
        commit_qc: n42_h2_primitives::QuorumCertificate::genesis(),
        validator_changes: None,
    }
}

fn body_for(hash: B256, number: u64) -> ForeignBody {
    ForeignBody {
        block_hash: hash,
        number,
        timestamp: 1_700_000_000 + number,
        profile: n42_h2_consensus::N42HeaderProfile::Ethereum,
        rlp: alloy_primitives::Bytes::from_static(&[0xc0]),
        compact: false,
    }
}

/// A chain `1..=n` on genesis.
fn chain(n: u64) -> Vec<BuiltBlock> {
    let mut parent = GENESIS;
    (1..=n)
        .map(|number| {
            let block = MockExecutionLayer::built_block_on(number, parent);
            parent = block.hash;
            block
        })
        .collect()
}

/// The execution layer takes bodies and holds each import open after its
/// check until the gate gives it a permit.
fn gated() -> (MockExecutionLayer, Arc<Semaphore>) {
    let gate = Arc::new(Semaphore::new(0));
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        take_bodies: true,
        body_gate: Some(Arc::clone(&gate)),
        ..Default::default()
    });
    (el, gate)
}

/// A deferred driver with the switch as asked; the cap is the default.
fn driver(el: &MockExecutionLayer, vote_before_slot: bool) -> (ExecutionDriver<MockExecutionLayer>, UnboundedReceiver<ImportReport>) {
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_deferred_execution_time(Some(0));
    driver.set_vote_before_slot(vote_before_slot);
    let rx = driver.take_foreign_imports().expect("channel");
    (driver, rx)
}

/// Hands a block over: its payload (which names its parent) and its body.
async fn arrive(driver: &mut ExecutionDriver<MockExecutionLayer>, block: &BuiltBlock) -> DriverAction {
    driver.cache_payload(block.hash, block.execution_data.clone());
    driver.cache_body(body_for(block.hash, block.number));
    driver.handle_output(&execute(block.hash)).await
}

async fn next_report(rx: &mut UnboundedReceiver<ImportReport>) -> ImportReport {
    tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("a report in time").expect("channel open")
}

/// Whether a report arrives within a short while.
async fn quiet(rx: &mut UnboundedReceiver<ImportReport>) -> bool {
    tokio::time::timeout(Duration::from_millis(150), rx.recv()).await.is_err()
}

fn checked_hash(report: &ImportReport) -> Option<B256> {
    match report {
        ImportReport::Checked(hash) => Some(*hash),
        ImportReport::Done(..) => None,
    }
}

fn votes(actions: &[DriverAction]) -> Vec<B256> {
    actions
        .iter()
        .filter_map(|action| match action {
            DriverAction::Consensus(event) => match event.as_ref() {
                ConsensusEvent::BlockChecked(hash) => Some(*hash),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn count(el: &MockExecutionLayer, call: &ElCall) -> usize {
    el.calls().iter().filter(|c| *c == call).count()
}

/// Waits until `call` has been made: a release reaches the execution layer
/// on the import's own task.
async fn made(el: &MockExecutionLayer, call: ElCall) {
    let waited = tokio::time::timeout(Duration::from_secs(10), async {
        while count(el, &call) == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "timed out waiting for {call:?}");
}

/// `got` holds the blocks of `want` and nothing else, in any order: two
/// imports in flight land in whichever order the mock lets them (a real
/// execution layer lands them in parent order, which the mock does not
/// model).
fn same(got: &[B256], want: &[&BuiltBlock]) {
    let mut got = got.to_vec();
    let mut want: Vec<B256> = want.iter().map(|b| b.hash).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want);
}

/// What the test saw while it let imports land.
#[derive(Default)]
struct Seen {
    imported: Vec<B256>,
    voted: Vec<B256>,
}

/// Feeds reports to the driver until `done` verdicts have been read, letting
/// one import land per verdict wanted.
async fn land(
    driver: &mut ExecutionDriver<MockExecutionLayer>,
    rx: &mut UnboundedReceiver<ImportReport>,
    gate: &Semaphore,
    done: usize,
    seen: &mut Seen,
) {
    let mut verdicts = 0;
    gate.add_permits(1);
    while verdicts < done {
        let report = next_report(rx).await;
        let is_done = matches!(report, ImportReport::Done(..));
        let actions = driver.finish_execute(report).await;
        seen.voted.extend(votes(&actions));
        seen.imported.extend(actions.iter().filter_map(DriverAction::imported_block));
        if is_done {
            verdicts += 1;
            if verdicts < done {
                gate.add_permits(1);
            }
        }
    }
}

/// Reads the reports that are already due (checks), feeding them back.
async fn take_checks(
    driver: &mut ExecutionDriver<MockExecutionLayer>,
    rx: &mut UnboundedReceiver<ImportReport>,
    want: usize,
    seen: &mut Seen,
) {
    for _ in 0..want {
        let report = next_report(rx).await;
        assert!(checked_hash(&report).is_some(), "a check, not a verdict: {report:?}");
        seen.voted.extend(votes(&driver.finish_execute(report).await));
    }
}

#[test]
fn the_in_flight_knob_accepts_one_to_three() {
    assert_eq!(n42_h2_execution::DEFERRED_IN_FLIGHT, 2);
    assert_eq!(n42_h2_execution::parse_in_flight("1"), Ok(1));
    assert_eq!(n42_h2_execution::parse_in_flight(" 3 "), Ok(3));
    assert!(n42_h2_execution::parse_in_flight("0").is_err());
    assert!(n42_h2_execution::parse_in_flight("4").is_err());
    assert!(n42_h2_execution::parse_in_flight("two").is_err());
    let (el, _gate) = gated();
    let (mut driver, _rx) = driver(&el, false);
    assert!(driver.set_deferred_in_flight(4).is_err());
    assert!(driver.set_deferred_in_flight(3).is_ok());
}

/// Both switches unset: the third block waits for a slot with its whole
/// road, and starts only when the first lands -- as before the knobs.
#[tokio::test]
async fn by_default_a_third_block_waits_for_a_slot_vote_and_all() {
    let blocks = chain(3);
    let (el, gate) = gated();
    let (mut driver, mut rx) = driver(&el, false);
    let mut seen = Seen::default();
    for block in &blocks {
        assert!(matches!(arrive(&mut driver, block).await, DriverAction::Ignored));
    }
    take_checks(&mut driver, &mut rx, 2, &mut seen).await;
    assert!(quiet(&mut rx).await, "nothing more until a slot frees");
    assert_eq!(count(&el, &ElCall::NewPayloadBody(blocks[2].hash)), 0, "the third was not handed over");
    assert_eq!(driver.voted_ahead(), 0);
    assert!(driver.is_importing(&blocks[2].hash), "queued");

    land(&mut driver, &mut rx, &gate, 3, &mut seen).await;
    same(&seen.voted[..2], &[&blocks[0], &blocks[1]]);
    assert_eq!(seen.voted[2], blocks[2].hash, "the third voted only after a slot freed");
    same(&seen.imported, &blocks.iter().collect::<Vec<_>>());
    for block in &blocks {
        assert_eq!(count(&el, &ElCall::NewPayloadBody(block.hash)), 1, "each handed over once");
    }
    assert!(!el.calls().iter().any(|c| matches!(c, ElCall::BodyReleased(_) | ElCall::BodyDropped(_))));
    assert_eq!(driver.importing().count(), 0);
}

/// The switch on: the third block arrives with two imports in flight and is
/// voted for before either of them lands; its execution waits for the slot
/// the first one frees.
#[tokio::test]
async fn a_block_arriving_with_two_in_flight_votes_before_either_lands() {
    let blocks = chain(3);
    let (el, gate) = gated();
    let (mut driver, mut rx) = driver(&el, true);
    let mut seen = Seen::default();
    for block in &blocks {
        assert!(matches!(arrive(&mut driver, block).await, DriverAction::Ignored));
    }
    take_checks(&mut driver, &mut rx, 3, &mut seen).await;
    assert!(seen.voted.contains(&blocks[2].hash), "the third voted with nothing landed");
    assert!(seen.imported.is_empty(), "neither import has landed");
    assert_eq!(driver.voted_ahead(), 1);
    assert!(driver.is_voted_ahead(&blocks[2].hash));
    assert_eq!(count(&el, &ElCall::BodyReleased(blocks[2].hash)), 0, "its execution waits");

    land(&mut driver, &mut rx, &gate, 3, &mut seen).await;
    same(&seen.imported, &blocks.iter().collect::<Vec<_>>());
    assert_eq!(count(&el, &ElCall::BodyReleased(blocks[2].hash)), 1);
    assert_eq!(driver.voted_ahead(), 0);
    assert_eq!(driver.importing().count(), 0);
}

/// A block whose parent is itself waiting (voted ahead, not executing) has no
/// parent fields to be checked against: it waits for a slot as without the
/// switch, and votes once its parent has one.
#[tokio::test]
async fn a_block_missing_its_parents_execution_waits() {
    let blocks = chain(4);
    let (el, gate) = gated();
    let (mut driver, mut rx) = driver(&el, true);
    let mut seen = Seen::default();
    for block in &blocks {
        arrive(&mut driver, block).await;
    }
    take_checks(&mut driver, &mut rx, 3, &mut seen).await;
    assert!(quiet(&mut rx).await, "the fourth does not check");
    assert_eq!(count(&el, &ElCall::NewPayloadBody(blocks[3].hash)), 0, "nor is it handed over");
    assert!(!driver.is_voted_ahead(&blocks[3].hash));
    assert!(driver.is_importing(&blocks[3].hash), "queued");

    // The first lands: the third takes its slot, and the fourth, whose parent
    // is now executing, votes ahead.
    land(&mut driver, &mut rx, &gate, 1, &mut seen).await;
    made(&el, ElCall::BodyReleased(blocks[2].hash)).await;
    assert!(driver.is_voted_ahead(&blocks[3].hash));
    take_checks(&mut driver, &mut rx, 1, &mut seen).await;
    assert_eq!(seen.voted.last(), Some(&blocks[3].hash));
    assert_eq!(seen.imported.len(), 1, "with only one landed");

    land(&mut driver, &mut rx, &gate, 3, &mut seen).await;
    same(&seen.imported, &blocks.iter().collect::<Vec<_>>());
}

/// Past the follower-lag cap -- slots plus blocks voted ahead -- a block
/// waits with its vote, which is the backpressure.
#[tokio::test]
async fn past_the_lag_cap_the_vote_is_withheld() {
    let blocks = chain(3);
    let (el, gate) = gated();
    let (mut driver, mut rx) = driver(&el, true);
    driver.set_deferred_in_flight(3).expect("three slots");
    let mut seen = Seen::default();
    for block in &blocks {
        arrive(&mut driver, block).await;
    }
    // Two siblings at height four, each on a parent that executes.
    let first = MockExecutionLayer::built_block_on(4, blocks[2].hash);
    let mut second = first.clone();
    second.hash = B256::repeat_byte(0x4b);
    second.execution_data = MockExecutionLayer::payload_for(second.hash, 4);
    arrive(&mut driver, &first).await;
    arrive(&mut driver, &second).await;
    take_checks(&mut driver, &mut rx, 4, &mut seen).await;
    assert!(quiet(&mut rx).await, "the second sibling does not check");
    assert!(driver.is_voted_ahead(&first.hash));
    assert_eq!(driver.voted_ahead(), 1, "3 slots + 1 held = the cap of 4");
    assert_eq!(count(&el, &ElCall::NewPayloadBody(second.hash)), 0);
    assert!(driver.is_importing(&second.hash), "it waits for its slot");

    land(&mut driver, &mut rx, &gate, 5, &mut seen).await;
    let mut all: Vec<&BuiltBlock> = blocks.iter().collect();
    all.extend([&first, &second]);
    same(&seen.imported, &all);
    assert_eq!(count(&el, &ElCall::NewPayloadBody(second.hash)), 1, "imported in its turn, once");
}

/// A run of blocks arriving faster than they land: every block's execution
/// starts in arrival order and each is handed over, released and imported
/// exactly once.
#[tokio::test]
async fn imports_run_in_order_and_each_exactly_once() {
    let blocks = chain(7);
    let (el, gate) = gated();
    let (mut driver, mut rx) = driver(&el, true);
    let mut seen = Seen::default();
    for block in &blocks {
        arrive(&mut driver, block).await;
        // One landing every other arrival: the follower falls behind.
        if block.number % 2 == 0 {
            land(&mut driver, &mut rx, &gate, 1, &mut seen).await;
        }
    }
    let left = blocks.len() - seen.imported.len();
    land(&mut driver, &mut rx, &gate, left, &mut seen).await;
    same(&seen.imported, &blocks.iter().collect::<Vec<_>>());
    // Where each execution started: its hand-over when it had a slot, its
    // release when it voted ahead.
    let calls = el.calls();
    let started: Vec<B256> = blocks
        .iter()
        .map(|block| {
            let handed = calls.iter().position(|c| *c == ElCall::NewPayloadBody(block.hash)).expect("handed over");
            let released = calls.iter().position(|c| *c == ElCall::BodyReleased(block.hash));
            (released.unwrap_or(handed), block.hash)
        })
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_values()
        .collect();
    assert_eq!(started, blocks.iter().map(|b| b.hash).collect::<Vec<_>>(), "executions start in order");
    for block in &blocks {
        assert_eq!(count(&el, &ElCall::NewPayloadBody(block.hash)), 1);
        assert!(count(&el, &ElCall::BodyReleased(block.hash)) <= 1);
    }
    assert!(seen.voted.len() >= blocks.len(), "every block voted");
    assert!(calls.iter().any(|c| matches!(c, ElCall::BodyReleased(_))), "some voted ahead");
    assert_eq!(driver.importing().count(), 0);
    assert_eq!(driver.voted_ahead(), 0);
}

/// A block voted ahead whose height is then committed to a sibling is
/// dropped: its execution is never released, it leaves the queue and the
/// cache, its import's answer is swallowed, and a late child of it is refused
/// at once.
#[tokio::test]
async fn a_voted_block_that_lost_its_height_is_dropped_cleanly() {
    let blocks = chain(2);
    let (el, gate) = gated();
    let (mut driver, mut rx) = driver(&el, true);
    let mut seen = Seen::default();
    for block in &blocks {
        arrive(&mut driver, block).await;
    }
    let loser = MockExecutionLayer::built_block_on(3, blocks[1].hash);
    let mut winner = loser.clone();
    winner.hash = B256::repeat_byte(0x3b);
    winner.execution_data = MockExecutionLayer::payload_for(winner.hash, 3);
    arrive(&mut driver, &loser).await;
    arrive(&mut driver, &winner).await;
    take_checks(&mut driver, &mut rx, 4, &mut seen).await;
    assert_eq!(driver.voted_ahead(), 2, "both siblings voted ahead");

    // The view change: the sibling is committed at height three.
    driver.handle_output(&committed(winner.hash)).await;
    assert!(!driver.is_voted_ahead(&loser.hash));
    assert!(!driver.is_importing(&loser.hash), "out of the queue");
    assert!(!driver.has_body(&loser.hash) && !driver.has_payload(&loser.hash), "out of the cache");
    assert!(driver.is_voted_ahead(&winner.hash), "the winner keeps its turn");
    // Its task ends with the drop; the answer changes nothing.
    let report = next_report(&mut rx).await;
    assert!(matches!(report, ImportReport::Done(hash, _) if hash == loser.hash));
    assert!(driver.finish_execute(report).await.is_empty(), "swallowed");
    assert_eq!(count(&el, &ElCall::BodyDropped(loser.hash)), 1);
    assert_eq!(count(&el, &ElCall::BodyReleased(loser.hash)), 0, "never executed");

    // A child of the loser can never be canonical.
    let orphan = MockExecutionLayer::built_block_on(4, loser.hash);
    let action = arrive(&mut driver, &orphan).await;
    assert_eq!(action.rejection().map(|(hash, _)| hash), Some(orphan.hash));
    assert!(!driver.is_importing(&orphan.hash));

    land(&mut driver, &mut rx, &gate, 3, &mut seen).await;
    same(&seen.imported, &[&blocks[0], &blocks[1], &winner]);
    assert_eq!(driver.finalized(), winner.hash, "the commit that waited ran on the import");
    assert_eq!(driver.importing().count(), 0);
}

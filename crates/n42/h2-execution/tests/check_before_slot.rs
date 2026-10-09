// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The check ahead of the import slot (`N42_CHECK_BEFORE_SLOT`), against the
//! in-memory Engine API with each body import held open after its check until
//! the test lets it land ([`MockBehaviour::body_gate`]): a block queued behind
//! busy slots is voted for on a check-only answer that vouches for exactly
//! it, its import keeps its place and its request, and its import's own check
//! releases nothing more.
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

/// The body a proposal carries for `block`: its header first, so the header
/// hashes to the block's hash, as a real body's does.
fn body_of(block: &BuiltBlock) -> ForeignBody {
    let raw = block.execution_data.clone().into_block_raw().expect("the mock's payload is a block");
    let rlp = n42_h2_consensus::encode_block_rlp_raw(&raw.header, &[], &[], None);
    ForeignBody {
        block_hash: block.hash,
        number: block.number,
        timestamp: block.timestamp,
        profile: n42_h2_consensus::N42HeaderProfile::Ethereum,
        rlp: rlp.into(),
        compact: false,
    }
}

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

/// Takes bodies, holds each import open after its check until the gate gives
/// a permit, and answers check-only requests as asked.
fn gated(check_only: Option<Option<B256>>) -> (MockExecutionLayer, Arc<Semaphore>) {
    let gate = Arc::new(Semaphore::new(0));
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        take_bodies: true,
        body_gate: Some(Arc::clone(&gate)),
        check_only,
        ..Default::default()
    });
    (el, gate)
}

fn driver(el: &MockExecutionLayer, on: bool) -> (ExecutionDriver<MockExecutionLayer>, UnboundedReceiver<ImportReport>) {
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_deferred_execution_time(Some(0));
    driver.set_check_before_slot(on);
    let rx = driver.take_foreign_imports().expect("channel");
    (driver, rx)
}

async fn arrive(driver: &mut ExecutionDriver<MockExecutionLayer>, block: &BuiltBlock, body: ForeignBody) {
    driver.cache_payload(block.hash, block.execution_data.clone());
    driver.cache_body(body);
    let action = driver.handle_output(&EngineOutput::ExecuteBlock(block.hash)).await;
    assert!(matches!(action, DriverAction::Ignored), "{action:?}");
}

async fn next_report(rx: &mut UnboundedReceiver<ImportReport>) -> ImportReport {
    tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("a report in time").expect("channel open")
}

async fn quiet(rx: &mut UnboundedReceiver<ImportReport>) -> bool {
    tokio::time::timeout(Duration::from_millis(150), rx.recv()).await.is_err()
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

fn body_calls(el: &MockExecutionLayer) -> Vec<B256> {
    el.calls()
        .into_iter()
        .filter_map(|call| match call {
            ElCall::NewPayloadBody(hash) => Some(hash),
            _ => None,
        })
        .collect()
}

fn check_calls(el: &MockExecutionLayer) -> Vec<B256> {
    el.calls()
        .into_iter()
        .filter_map(|call| match call {
            ElCall::CheckOnly(hash) => Some(hash),
            _ => None,
        })
        .collect()
}

/// Reads `want` check reports of the blocks in the slots, feeding them back.
async fn take_votes(
    driver: &mut ExecutionDriver<MockExecutionLayer>,
    rx: &mut UnboundedReceiver<ImportReport>,
    want: usize,
) -> Vec<B256> {
    let mut voted = Vec::new();
    for _ in 0..want {
        let report = next_report(rx).await;
        assert!(matches!(report, ImportReport::Checked(_)), "a check, not a verdict: {report:?}");
        voted.extend(votes(&driver.finish_execute(report).await));
    }
    voted
}

/// Lets every import land, feeding every report back; returns the votes and
/// the imports seen.
async fn land_all(
    driver: &mut ExecutionDriver<MockExecutionLayer>,
    rx: &mut UnboundedReceiver<ImportReport>,
    gate: &Semaphore,
    verdicts: usize,
) -> (Vec<B256>, Vec<B256>) {
    let (mut voted, mut imported) = (Vec::new(), Vec::new());
    gate.add_permits(verdicts);
    let mut seen = 0;
    while seen < verdicts {
        let report = next_report(rx).await;
        seen += usize::from(matches!(report, ImportReport::Done(..)));
        let actions = driver.finish_execute(report).await;
        voted.extend(votes(&actions));
        imported.extend(actions.iter().filter_map(DriverAction::imported_block));
    }
    (voted, imported)
}

/// The third block arrives with both slots taken: its check-only answer
/// vouches for it and its vote goes out before any slot frees; its import
/// then runs in its turn, in order, and its own check releases no second
/// vote. Every block is voted for exactly once.
#[tokio::test]
async fn a_block_behind_busy_slots_is_voted_for_on_its_check_only_answer() {
    let blocks = chain(3);
    let (el, gate) = gated(Some(None));
    let (mut driver, mut rx) = driver(&el, true);
    for block in &blocks[..2] {
        arrive(&mut driver, block, body_of(block)).await;
    }
    let mut voted = take_votes(&mut driver, &mut rx, 2).await;
    arrive(&mut driver, &blocks[2], body_of(&blocks[2])).await;
    // The check ahead: a Checked report with both imports still held open.
    voted.extend(take_votes(&mut driver, &mut rx, 1).await);
    // The first two votes come from two concurrent imports and may arrive in either order.
    assert_eq!(voted.len(), 3, "exactly three votes: {voted:?}");
    let mut first_two = voted[..2].to_vec();
    first_two.sort();
    let mut expected = vec![blocks[0].hash, blocks[1].hash];
    expected.sort();
    assert_eq!(first_two, expected);
    assert_eq!(voted[2], blocks[2].hash);
    assert_eq!(check_calls(&el), vec![blocks[2].hash], "one check-only request, for the queued block only");
    assert_eq!(body_calls(&el), vec![blocks[0].hash, blocks[1].hash], "the queued block is not imported yet");
    assert_eq!(driver.check_ahead_counts(), (1, 1, 0));
    let (more_votes, imported) = land_all(&mut driver, &mut rx, &gate, 3).await;
    assert!(more_votes.is_empty(), "the import's own check releases nothing more: {more_votes:?}");
    let mut imported = imported;
    imported.sort();
    let mut want: Vec<B256> = blocks.iter().map(|b| b.hash).collect();
    want.sort();
    assert_eq!(imported, want);
    assert_eq!(body_calls(&el), blocks.iter().map(|b| b.hash).collect::<Vec<_>>(), "imports in arrival order");
}

/// A check-only answer for another build (CHECKED naming a different block)
/// releases no vote: the block's vote waits for its import's own check.
#[tokio::test]
async fn a_check_only_answer_for_another_build_releases_no_vote() {
    let blocks = chain(3);
    let (el, gate) = gated(Some(Some(B256::repeat_byte(0x5A))));
    let (mut driver, mut rx) = driver(&el, true);
    for block in &blocks[..2] {
        arrive(&mut driver, block, body_of(block)).await;
    }
    take_votes(&mut driver, &mut rx, 2).await;
    arrive(&mut driver, &blocks[2], body_of(&blocks[2])).await;
    assert!(quiet(&mut rx).await, "no vote before a slot frees");
    assert_eq!(check_calls(&el), vec![blocks[2].hash]);
    assert_eq!(driver.check_ahead_counts(), (1, 0, 1));
    let (voted, _) = land_all(&mut driver, &mut rx, &gate, 3).await;
    assert_eq!(voted, vec![blocks[2].hash], "voted once, on its import's check");
}

/// Off, or against an execution layer that does not answer check-only
/// requests, or with a body whose header is not the block's: no request is
/// sent and the road is today's.
#[tokio::test]
async fn without_the_switch_or_the_layer_or_the_header_nothing_is_asked() {
    let blocks = chain(3);
    for case in 0..3 {
        let (el, gate) = gated(if case == 1 { None } else { Some(None) });
        let (mut driver, mut rx) = driver(&el, case != 0);
        for block in &blocks[..2] {
            arrive(&mut driver, block, body_of(block)).await;
        }
        take_votes(&mut driver, &mut rx, 2).await;
        let mut third = body_of(&blocks[2]);
        if case == 2 {
            // The header of block 1 under block 3's hash.
            third.rlp = body_of(&blocks[0]).rlp;
        }
        arrive(&mut driver, &blocks[2], third).await;
        assert!(quiet(&mut rx).await, "case {case}: no vote before a slot frees");
        assert!(check_calls(&el).is_empty(), "case {case}: no check-only request");
        // The mock imports a body by its hash whatever its bytes say.
        let (voted, _) = land_all(&mut driver, &mut rx, &gate, 3).await;
        assert_eq!(voted, vec![blocks[2].hash], "case {case}: voted on its import's check");
    }
}

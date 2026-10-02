// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The driver's less-travelled paths against the in-memory Engine API:
//! imports run on a task and their verdicts, deferred execution with bodies,
//! builds prepared ahead (reuse, mismatch, staleness, refusal), own-block
//! imports, and commit forkchoices that are refused, answered SYNCING or
//! folded behind one another.
//!
//! Every wait is bounded. No test pauses the clock.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionPayload, PayloadAttributes, PayloadStatusEnum};
use n42_h2_consensus::EngineOutput;
use n42_h2_execution::{
    BodyDecoder, DriverAction, ElCall, ExecutionDriver, ExecutionLayer, ForeignBody, ImportReport, ImportVerdict,
    MockBehaviour, MockExecutionLayer,
};
use tokio::sync::mpsc::UnboundedReceiver;

const GENESIS: B256 = B256::ZERO;

fn attrs_at(timestamp: u64, slot: Option<u64>) -> PayloadAttributes {
    PayloadAttributes {
        slot_number: slot,
        target_gas_limit: None,
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: None,
        parent_beacon_block_root: None,
    }
}

fn attrs() -> PayloadAttributes {
    attrs_at(1_700_000_001, None)
}

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

fn body_for(hash: B256, number: u64, compact: bool) -> ForeignBody {
    ForeignBody {
        block_hash: hash,
        number,
        timestamp: 1_700_000_000 + number,
        profile: n42_h2_consensus::N42HeaderProfile::Ethereum,
        rlp: alloy_primitives::Bytes::from_static(&[0xc0]),
        compact,
    }
}

fn count(el: &MockExecutionLayer, pick: impl Fn(&ElCall) -> bool) -> usize {
    el.calls().iter().filter(|c| pick(c)).count()
}

async fn next_report(rx: &mut UnboundedReceiver<ImportReport>) -> ImportReport {
    tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("a report in time").expect("channel open")
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        while !ok() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(result.is_ok(), "timed out waiting for {what}");
}

/// A driver whose follower imports run on tasks, and the channel they report on.
fn spawning(el: &MockExecutionLayer) -> (ExecutionDriver<MockExecutionLayer>, UnboundedReceiver<ImportReport>) {
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_spawn_imports(true);
    let rx = driver.take_foreign_imports().expect("the channel is handed out once");
    (driver, rx)
}

/// A driver under deferred execution from timestamp zero.
fn deferred(el: &MockExecutionLayer) -> (ExecutionDriver<MockExecutionLayer>, UnboundedReceiver<ImportReport>) {
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_deferred_execution_time(Some(0));
    let rx = driver.take_foreign_imports().expect("channel");
    (driver, rx)
}

fn invalid(reason: &str) -> PayloadStatusEnum {
    PayloadStatusEnum::Invalid { validation_error: reason.to_owned() }
}

// ---------------------------------------------------------------------------
// Follower imports on a task
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_spawned_imports_verdict_becomes_the_action_an_awaited_import_would_return() {
    let built = MockExecutionLayer::built_block(1);
    for (behaviour, name) in [
        (MockBehaviour::default(), "valid"),
        (MockBehaviour { new_payload_status: PayloadStatusEnum::Syncing, ..Default::default() }, "syncing"),
        (MockBehaviour { new_payload_status: PayloadStatusEnum::Accepted, ..Default::default() }, "accepted"),
        (MockBehaviour { new_payload_status: invalid("bad state root"), ..Default::default() }, "invalid"),
        (MockBehaviour { new_payload_error: Some("db closed".into()), ..Default::default() }, "error"),
    ] {
        let el = MockExecutionLayer::with_behaviour(behaviour);
        let (mut driver, mut rx) = spawning(&el);
        driver.cache_payload(built.hash, built.execution_data.clone());
        let started = driver.handle_output(&execute(built.hash)).await;
        assert!(matches!(started, DriverAction::Ignored), "{name}: the verdict comes later");
        assert!(driver.is_importing(&built.hash), "{name}: in flight");
        let ImportReport::Done(hash, verdict) = next_report(&mut rx).await else { panic!("{name}: expected a verdict") };
        assert_eq!(hash, built.hash);
        let actions = driver.finish_execute(ImportReport::Done(hash, verdict)).await;
        assert_eq!(actions.len(), 1, "{name}: {actions:?}");
        assert!(!driver.is_importing(&built.hash), "{name}: no longer in flight");
        match name {
            "valid" => {
                assert_eq!(actions[0].imported_block(), Some(built.hash));
                assert_eq!(driver.head(), built.hash);
            }
            "syncing" | "accepted" => {
                assert_eq!(actions[0].missing_block(), Some(built.hash), "not a verdict: asked for again");
                assert_eq!(driver.head(), GENESIS);
            }
            "invalid" => {
                assert_eq!(actions[0].rejection(), Some((built.hash, "bad state root")));
                assert!(!driver.has_payload(&built.hash), "a rejected payload is dropped so a fresh copy runs again");
            }
            _ => assert_eq!(actions[0].rejection(), Some((built.hash, "db closed"))),
        }
    }
}

#[tokio::test]
async fn a_commit_that_waited_for_an_import_runs_when_it_succeeds_and_is_dropped_when_it_fails() {
    let built = MockExecutionLayer::built_block(1);

    // Success: the commit heard mid-import is sent once the block is in.
    let el = MockExecutionLayer::new();
    let (mut driver, mut rx) = spawning(&el);
    driver.cache_payload(built.hash, built.execution_data.clone());
    driver.handle_output(&execute(built.hash)).await;
    let waiting = driver.handle_output(&committed(built.hash)).await;
    assert!(matches!(waiting, DriverAction::Ignored));
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdated(_))), 0, "no forkchoice to a block still importing");
    let report = next_report(&mut rx).await;
    let actions = driver.finish_execute(report).await;
    assert_eq!(actions[0].imported_block(), Some(built.hash));
    assert_eq!(driver.finalized(), built.hash);
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdated(s) if s.head_block_hash == built.hash)), 1);

    // Failure: the commit can never run, and a later success does not resurrect it.
    let el = MockExecutionLayer::with_behaviour(MockBehaviour { new_payload_status: invalid("bad"), ..Default::default() });
    let (mut driver, mut rx) = spawning(&el);
    driver.cache_payload(built.hash, built.execution_data.clone());
    driver.handle_output(&execute(built.hash)).await;
    driver.handle_output(&committed(built.hash)).await;
    let report = next_report(&mut rx).await;
    let actions = driver.finish_execute(report).await;
    assert!(actions[0].rejection().is_some());
    el.set_behaviour(MockBehaviour::default());
    driver.cache_payload(built.hash, built.execution_data.clone());
    driver.handle_output(&execute(built.hash)).await;
    let report = next_report(&mut rx).await;
    driver.finish_execute(report).await;
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdated(_))), 0, "the dropped commit stayed dropped");
}

#[tokio::test]
async fn imports_queue_behind_the_one_in_flight_and_a_queued_block_with_no_payload_is_asked_for() {
    let first = MockExecutionLayer::built_block_on(1, GENESIS);
    let second = MockExecutionLayer::built_block_on(2, first.hash);
    let missing = B256::repeat_byte(0x77);
    let el = MockExecutionLayer::new();
    let (mut driver, mut rx) = spawning(&el);
    driver.cache_payload(first.hash, first.execution_data.clone());
    driver.cache_payload(second.hash, second.execution_data.clone());

    driver.handle_output(&execute(first.hash)).await;
    assert!(matches!(driver.handle_output(&execute(first.hash)).await, DriverAction::Ignored), "asked again: its verdict is coming");
    assert!(matches!(driver.handle_output(&execute(second.hash)).await, DriverAction::Ignored));
    assert!(matches!(driver.handle_output(&execute(second.hash)).await, DriverAction::Ignored), "queued once");
    assert!(driver.is_importing(&second.hash), "queued counts as importing for a commit");
    assert!(driver.handle_output(&execute(missing)).await.missing_block().is_none(), "queued behind the first, not judged yet");

    let report = next_report(&mut rx).await;
    let actions = driver.finish_execute(report).await;
    assert_eq!(actions[0].imported_block(), Some(first.hash));
    assert_eq!(actions.len(), 1, "the next queued block started on its own");
    let report = next_report(&mut rx).await;
    let actions = driver.finish_execute(report).await;
    assert_eq!(actions[0].imported_block(), Some(second.hash));
    assert_eq!(actions.len(), 2, "the queued block without a payload is reported missing");
    assert_eq!(actions[1].missing_block(), Some(missing));
}

#[tokio::test]
async fn an_import_task_that_dies_reports_an_invalid_verdict_instead_of_hanging() {
    // An execution layer that panics inside newPayload: the task ends with no
    // verdict, and the guard says so.
    struct Panics(MockExecutionLayer);
    #[async_trait::async_trait]
    impl ExecutionLayer for Panics {
        async fn new_payload(
            &self,
            _payload: alloy_rpc_types_engine::ExecutionData,
        ) -> Result<alloy_rpc_types_engine::PayloadStatus, n42_h2_execution::ElError> {
            panic!("the engine fell over");
        }
        async fn fork_choice_updated(
            &self,
            state: alloy_rpc_types_engine::ForkchoiceState,
        ) -> Result<alloy_rpc_types_engine::ForkchoiceUpdated, n42_h2_execution::ElError> {
            self.0.fork_choice_updated(state).await
        }
        async fn fork_choice_updated_with_attrs(
            &self,
            state: alloy_rpc_types_engine::ForkchoiceState,
            attrs: PayloadAttributes,
        ) -> Result<alloy_rpc_types_engine::ForkchoiceUpdated, n42_h2_execution::ElError> {
            self.0.fork_choice_updated_with_attrs(state, attrs).await
        }
        async fn resolve_payload(
            &self,
            id: alloy_rpc_types_engine::PayloadId,
            kind: n42_h2_execution::ResolveKind,
        ) -> Option<Result<n42_h2_execution::BuiltBlock, n42_h2_execution::ElError>> {
            self.0.resolve_payload(id, kind).await
        }
    }
    let built = MockExecutionLayer::built_block(1);
    let mut driver = ExecutionDriver::new(Panics(MockExecutionLayer::new()), GENESIS);
    driver.set_spawn_imports(true);
    let mut rx = driver.take_foreign_imports().expect("channel");
    driver.cache_payload(built.hash, built.execution_data.clone());
    driver.handle_output(&execute(built.hash)).await;
    let ImportReport::Done(hash, ImportVerdict::Invalid(reason)) = next_report(&mut rx).await else {
        panic!("expected an invalid verdict from the guard");
    };
    assert_eq!(hash, built.hash);
    assert_eq!(reason, "the import task ended without a verdict");
    let actions = driver.finish_execute(ImportReport::Done(hash, ImportVerdict::Invalid(reason))).await;
    assert!(actions[0].rejection().is_some());
    assert!(!driver.is_importing(&built.hash), "the slot is not held for good");
}

#[tokio::test]
async fn a_held_body_that_cannot_be_decoded_is_a_rejection_and_a_compact_one_is_missing() {
    let hash = B256::repeat_byte(0x21);
    let mut driver = ExecutionDriver::new(MockExecutionLayer::new(), GENESIS);
    driver.set_body_decoder(BodyDecoder::new(|_: &ForeignBody| Err("garbled body".to_owned())));
    driver.cache_body(body_for(hash, 1, false));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.rejection(), Some((hash, "garbled body")));

    let compact = B256::repeat_byte(0x22);
    driver.cache_body(body_for(compact, 2, true));
    let action = driver.handle_output(&execute(compact)).await;
    assert_eq!(action.missing_block(), Some(compact), "a compact body has no payload to make");
    assert!(format!("{:?}", BodyDecoder::new(|_: &ForeignBody| Err(String::new()))).contains("BodyDecoder"));
}

// ---------------------------------------------------------------------------
// Deferred execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn under_deferred_execution_a_body_is_checked_then_imported_and_the_vote_is_released_on_the_check() {
    let built = MockExecutionLayer::built_block(1);
    let el = MockExecutionLayer::with_behaviour(MockBehaviour { take_bodies: true, ..Default::default() });
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(built.hash, 1, false));
    assert!(matches!(driver.handle_output(&execute(built.hash)).await, DriverAction::Ignored));
    assert!(matches!(driver.handle_output(&execute(built.hash)).await, DriverAction::Ignored), "already executing");

    let checked = next_report(&mut rx).await;
    assert!(matches!(checked, ImportReport::Checked(h) if h == built.hash));
    let actions = driver.finish_execute(checked).await;
    assert!(
        matches!(actions.as_slice(), [DriverAction::Consensus(event)] if matches!(event.as_ref(), n42_h2_consensus::ConsensusEvent::BlockChecked(h) if *h == built.hash)),
        "{actions:?}"
    );
    assert!(driver.is_importing(&built.hash), "still executing after the check");
    let done = next_report(&mut rx).await;
    assert!(matches!(done, ImportReport::Done(h, ImportVerdict::Imported) if h == built.hash));
    let actions = driver.finish_execute(done).await;
    assert_eq!(actions[0].imported_block(), Some(built.hash));
    assert_eq!(driver.head(), built.hash);
    assert!(el.calls().contains(&ElCall::NewPayloadBody(built.hash)));
    assert_eq!(count(&el, |c| matches!(c, ElCall::NewPayload(_))), 0, "never sent as a payload too");
}

#[tokio::test]
async fn a_compact_body_the_execution_layer_cannot_assemble_names_the_transactions_it_lacks() {
    let hash = B256::repeat_byte(0x31);
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        take_bodies: true,
        body_needs_txns: Some(vec![4, 9]),
        ..Default::default()
    });
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(hash, 1, true));
    driver.handle_output(&execute(hash)).await;
    let report = next_report(&mut rx).await;
    assert!(matches!(&report, ImportReport::Done(_, ImportVerdict::NeedTxns(i)) if i == &vec![4, 9]), "{report:?}");
    let actions = driver.finish_execute(report).await;
    assert!(matches!(&actions[0], DriverAction::TransactionsMissing { block_hash, indices } if *block_hash == hash && indices == &vec![4, 9]));
    assert!(!driver.is_importing(&hash), "the slot is free for the retry");
}

#[tokio::test]
async fn a_body_the_layer_refuses_falls_back_to_the_payload_or_to_the_whole_body() {
    let built = MockExecutionLayer::built_block(1);
    // Refused (the default mock does not take bodies) with a payload held: the payload is sent.
    let el = MockExecutionLayer::new();
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(built.hash, 1, false));
    driver.cache_payload(built.hash, built.execution_data.clone());
    driver.handle_output(&execute(built.hash)).await;
    let report = next_report(&mut rx).await;
    assert!(matches!(report, ImportReport::Done(_, ImportVerdict::Imported)), "{report:?}");
    assert!(el.calls().contains(&ElCall::NewPayload(built.hash)));

    // Refused, no payload, a decoder installed: the body is decoded on the task.
    let el = MockExecutionLayer::new();
    let (mut driver, mut rx) = deferred(&el);
    driver.set_body_decoder(BodyDecoder::new(move |_: &ForeignBody| Ok(built.execution_data.clone())));
    let built2 = MockExecutionLayer::built_block(1);
    driver.cache_body(body_for(built2.hash, 1, false));
    driver.handle_output(&execute(built2.hash)).await;
    let report = next_report(&mut rx).await;
    assert!(matches!(report, ImportReport::Done(_, ImportVerdict::Imported)), "{report:?}");
    assert_eq!(count(&el, |c| matches!(c, ElCall::NewPayload(_))), 1);

    // Refused, no payload, no decoder.
    let el = MockExecutionLayer::new();
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(built2.hash, 1, false));
    driver.handle_output(&execute(built2.hash)).await;
    let ImportReport::Done(_, ImportVerdict::Invalid(reason)) = next_report(&mut rx).await else { panic!("expected invalid") };
    assert!(reason.contains("no decoder installed"), "{reason}");

    // Refused, no payload, the decoder fails.
    let (mut driver, mut rx) = deferred(&el);
    driver.set_body_decoder(BodyDecoder::new(|_: &ForeignBody| Err("garbled".to_owned())));
    driver.cache_body(body_for(built2.hash, 1, false));
    driver.handle_output(&execute(built2.hash)).await;
    let ImportReport::Done(_, ImportVerdict::Invalid(reason)) = next_report(&mut rx).await else { panic!("expected invalid") };
    assert_eq!(reason, "garbled");

    // A compact body refused with no payload: not yet, the whole body is wanted.
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(built2.hash, 1, true));
    driver.handle_output(&execute(built2.hash)).await;
    let report = next_report(&mut rx).await;
    assert!(matches!(report, ImportReport::Done(_, ImportVerdict::NotYet)), "{report:?}");
    let actions = driver.finish_execute(report).await;
    assert_eq!(actions[0].missing_block(), Some(built2.hash));
}

#[tokio::test]
async fn a_body_the_layer_takes_and_then_fails_is_rejected_without_a_second_attempt() {
    let built = MockExecutionLayer::built_block(1);
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        take_bodies: true,
        new_payload_error: Some("state db corrupt".into()),
        ..Default::default()
    });
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(built.hash, 1, false));
    driver.cache_payload(built.hash, built.execution_data.clone());
    driver.handle_output(&execute(built.hash)).await;
    let ImportReport::Done(_, ImportVerdict::Invalid(reason)) = next_report(&mut rx).await else { panic!("expected invalid") };
    assert_eq!(reason, "state db corrupt");
    assert_eq!(count(&el, |c| matches!(c, ElCall::NewPayload(_))), 0, "a failure after the body was taken is not retried as a payload");

    // INVALID after a VALID check: the check released the vote, the verdict withdraws it.
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        take_bodies: true,
        new_payload_status: invalid("bad receipts"),
        ..Default::default()
    });
    let (mut driver, mut rx) = deferred(&el);
    driver.cache_body(body_for(built.hash, 1, false));
    driver.handle_output(&execute(built.hash)).await;
    assert!(matches!(next_report(&mut rx).await, ImportReport::Checked(_)));
    let report = next_report(&mut rx).await;
    let actions = driver.finish_execute(report).await;
    assert_eq!(actions[0].rejection(), Some((built.hash, "bad receipts")));
}

#[tokio::test]
async fn deferred_execution_runs_two_blocks_at_once_and_queues_the_rest() {
    let b1 = MockExecutionLayer::built_block_on(1, GENESIS);
    let b2 = MockExecutionLayer::built_block_on(2, b1.hash);
    let b3 = MockExecutionLayer::built_block_on(3, b2.hash);
    let el = MockExecutionLayer::new();
    let (mut driver, mut rx) = deferred(&el);
    for b in [&b1, &b2, &b3] {
        driver.cache_payload(b.hash, b.execution_data.clone());
        driver.handle_output(&execute(b.hash)).await;
    }
    assert!(driver.is_importing(&b3.hash), "the third waits");
    assert_eq!(driver.importing().count(), 2, "the pipeline is two deep");
    assert!(matches!(driver.handle_output(&execute(b3.hash)).await, DriverAction::Ignored), "queued once");

    let mut imported = Vec::new();
    for _ in 0..3 {
        let report = next_report(&mut rx).await;
        for action in driver.finish_execute(report).await {
            imported.extend(action.imported_block());
        }
    }
    imported.sort();
    let mut expected = vec![b1.hash, b2.hash, b3.hash];
    expected.sort();
    assert_eq!(imported, expected, "all three were imported");
    assert_eq!(driver.importing().count(), 0);
}

#[tokio::test]
async fn deferred_execution_with_nothing_cached_asks_for_the_body() {
    let (mut driver, _rx) = deferred(&MockExecutionLayer::new());
    let hash = B256::repeat_byte(0x41);
    assert_eq!(driver.handle_output(&execute(hash)).await.missing_block(), Some(hash));
    assert!(!driver.is_importing(&hash), "nothing was started");
}

// ---------------------------------------------------------------------------
// Builds prepared ahead
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_build_without_one_prepared_says_so_and_a_matching_prepared_one_is_taken() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.build_block_on(GENESIS, attrs(), 1).await.expect("built");
    assert_eq!(driver.last_build_path(), (false, Some("no build was prepared ahead")));

    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.prepare_build_on(GENESIS, attrs()).await.expect("started");
    // The same request again is already covered: no second forkchoice.
    driver.prepare_build_on(GENESIS, attrs()).await.expect("covered");
    let built = driver.build_block_on(GENESIS, attrs(), 1).await.expect("built from the prepared one");
    assert_eq!(driver.last_build_path(), (true, None));
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_))), 1, "one build served both requests");
    assert_eq!(count(&el, |c| matches!(c, ElCall::ResolvePayload(_))), 1);
    assert_eq!(built.number, 1);
    assert!(driver.has_payload(&built.hash), "its payload is cached for the engine's execute request");
}

#[tokio::test]
async fn a_prepared_build_for_other_attributes_is_discarded_and_the_block_built_now() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.prepare_build_on(GENESIS, attrs_at(1_700_000_001, None)).await.expect("started");
    driver.build_block_on(GENESIS, attrs_at(1_700_000_099, None), 1).await.expect("built now");
    assert_eq!(driver.last_build_path(), (false, Some("a build prepared ahead did not match the proposal")));
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    // The discarded build was given up before it started, so it sent no
    // forkchoice of its own: the one build is the one made now.
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_))), 1);
    assert_eq!(count(&el, |c| matches!(c, ElCall::ResolvePayload(_))), 1);
}

#[tokio::test]
async fn a_request_for_an_older_block_does_not_replace_a_newer_prepared_build() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let newer = attrs_at(1_700_000_005, Some(5));
    let older = attrs_at(1_700_000_003, Some(3));
    driver.prepare_build_on(GENESIS, newer.clone()).await.expect("started");
    driver.prepare_build_on(B256::repeat_byte(1), older).await.expect("stale request ignored");
    let built = driver.build_block_on(GENESIS, newer, 1).await.expect("the newer build survived");
    assert_eq!(driver.last_build_path(), (true, None));
    assert_eq!(built.number, 1);
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_))), 1, "the stale request started nothing");
}

#[tokio::test]
async fn a_prepared_build_that_failed_is_reported_and_replaced_by_a_build_now() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour { start_builds: false, ..Default::default() });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.prepare_build_on(GENESIS, attrs()).await.expect("the request itself starts");
    let err = driver.build_block_on(GENESIS, attrs(), 1).await.expect_err("nothing can be built");
    assert!(err.to_string().contains("no payload id"), "{err}");
    let (ahead, why) = driver.last_build_path();
    assert!(!ahead);
    assert!(why.is_some_and(|w| w.starts_with("the build prepared ahead failed")), "{why:?}");
}

#[tokio::test]
async fn a_build_on_the_sealed_block_the_layer_refuses_falls_back_to_the_ordinary_build() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let header = alloy_consensus::Header::default();
    driver.prepare_build_on_sealed(GENESIS, header.clone(), attrs(), None).await.expect("requested");
    // The mock offers no direct build: the task marks the request refused.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let built = driver.build_block_on(GENESIS, attrs(), 1).await.expect("built the ordinary way");
    assert_eq!(
        driver.last_build_path(),
        (false, Some("the execution layer refused the build on the sealed parent"))
    );
    assert_eq!(built.number, 1);
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_))), 1, "one ordinary build");
}

#[tokio::test]
async fn the_first_build_of_a_tenure_keeps_a_build_already_prepared_on_the_parent() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let header = alloy_consensus::Header::default();
    assert_eq!(
        driver.prepare_first_build_on_output(GENESIS, header.clone(), attrs(), None).await.expect("ok"),
        "requested"
    );
    assert_eq!(
        driver.prepare_first_build_on_output(GENESIS, header.clone(), attrs(), None).await.expect("ok"),
        "a build on the sealed parent is already prepared",
        "asked again before the task ran: kept"
    );

    // A forkchoice build that has finished is kept too.
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.prepare_build_on(GENESIS, attrs()).await.expect("started");
    eventually("the forkchoice build", || count(&el, |c| matches!(c, ElCall::ResolvePayload(_))) == 1).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        driver.prepare_first_build_on_output(GENESIS, header, attrs(), None).await.expect("ok"),
        "a forkchoice build ahead on this parent has already finished"
    );
}

#[tokio::test]
async fn a_discarded_prepared_build_is_gone_and_its_job_is_resolved() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.prepare_build_on(GENESIS, attrs()).await.expect("started");
    driver.discard_prepared();
    driver.discard_prepared();
    driver.build_block_on(GENESIS, attrs(), 1).await.expect("built now");
    assert_eq!(driver.last_build_path(), (false, Some("no build was prepared ahead")));
}

#[tokio::test]
async fn a_normalizer_finishes_the_built_block_for_its_view_and_a_failure_is_an_error() {
    let seen_view = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let finished_hash = B256::repeat_byte(0xee);
    let view_sink = Arc::clone(&seen_view);
    driver.set_payload_normalizer(move |payload, _header, view| {
        view_sink.store(view, std::sync::atomic::Ordering::SeqCst);
        let mut finished = payload.clone();
        if let ExecutionPayload::V1(v1) = &mut finished.payload {
            v1.block_hash = finished_hash;
        }
        Ok((finished, None))
    });
    let built = driver.build_block_on(GENESIS, attrs(), 42).await.expect("built");
    assert_eq!(built.hash, finished_hash, "from here on only the finished block exists");
    assert_eq!(built.execution_data.block_hash(), finished_hash);
    assert_eq!(seen_view.load(std::sync::atomic::Ordering::SeqCst), 42);
    assert!(driver.has_payload(&finished_hash));
    assert!(driver.take_encoded_body(finished_hash).is_none(), "no body was encoded ahead");

    let mut driver = ExecutionDriver::new(MockExecutionLayer::new(), GENESIS);
    driver.set_payload_normalizer(|_, _, _| Err("no seal key".to_owned()));
    let err = driver.build_block_on(GENESIS, attrs(), 1).await.expect_err("sealing failed");
    assert_eq!(err.to_string(), "finishing the built block: no seal key");
}

// ---------------------------------------------------------------------------
// Own blocks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_own_import_is_tracked_while_it_runs_and_reported_when_the_block_is_valid() {
    let built = MockExecutionLayer::built_block(1);
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let mut own = driver.take_own_imports().expect("channel");
    assert!(driver.take_own_imports().is_none(), "handed out once");
    driver.spawn_import_own_block(&built);
    assert!(driver.is_importing_own_block(&built.hash), "marked before the task has run");
    assert_eq!(tokio::time::timeout(Duration::from_secs(10), own.recv()).await.expect("in time"), Some(built.hash));
    eventually("the marker to clear", || !driver.is_importing_own_block(&built.hash)).await;
    assert!(el.calls().contains(&ElCall::NewPayload(built.hash)));

    // An invalid block, or a failing layer, is not reported as imported.
    for behaviour in [
        MockBehaviour { new_payload_status: invalid("bad"), ..Default::default() },
        MockBehaviour { new_payload_error: Some("down".into()), ..Default::default() },
    ] {
        let el = MockExecutionLayer::with_behaviour(behaviour);
        let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
        let mut own = driver.take_own_imports().expect("channel");
        driver.spawn_import_own_block(&built);
        eventually("the import to end", || !driver.is_importing_own_block(&built.hash)).await;
        assert!(own.try_recv().is_err(), "nothing was reported");
    }
}

#[tokio::test]
async fn the_commit_that_was_answered_syncing_runs_again_when_the_own_block_lands() {
    let built = MockExecutionLayer::built_block(1);
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    // Nothing waiting: nothing to replay.
    assert!(driver.own_block_imported(B256::repeat_byte(5)).await.is_none());

    // The commit reaches an engine that does not have the block yet.
    assert!(matches!(driver.handle_output(&committed(built.hash)).await, DriverAction::Ignored));
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdated(_))), 1);
    el.set_behaviour(MockBehaviour::default());
    let replay = driver.own_block_imported(built.hash).await.expect("the commit runs again");
    assert_eq!(replay.finalized_block(), Some(built.hash));
    assert_eq!(driver.head(), built.hash);
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdated(_))), 2);
    assert!(driver.own_block_imported(built.hash).await.is_none(), "once");
}

// ---------------------------------------------------------------------------
// Commits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_commit_forkchoice_finalises_nothing() {
    let built = MockExecutionLayer::built_block(1);
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_status: invalid("unknown ancestor"),
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let action = driver.handle_output(&committed(built.hash)).await;
    assert!(matches!(action, DriverAction::Ignored), "not an execution verdict on the block: {action:?}");
    assert_eq!(driver.head(), GENESIS, "the head did not move");
}

#[tokio::test]
async fn an_async_commit_answered_syncing_waits_for_the_import_and_runs_again() {
    let built = MockExecutionLayer::built_block(1);
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("channel");
    driver.handle_output(&committed(built.hash)).await;
    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await.expect("in time").expect("open");
    let actions = driver.finish_commit(report).await;
    assert!(actions.is_empty(), "SYNCING finalises nothing: {actions:?}");
    assert!(!driver.is_committing());
    assert_eq!(driver.head(), GENESIS);

    // The block is imported afterwards: the commit that waited is sent again.
    el.set_behaviour(MockBehaviour::default());
    driver.cache_payload(built.hash, built.execution_data.clone());
    let action = driver.handle_output(&execute(built.hash)).await;
    assert_eq!(action.imported_block(), Some(built.hash));
    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await.expect("in time").expect("open");
    let actions = driver.finish_commit(report).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].finalized_block(), Some(built.hash));
    assert_eq!(count(&el, |c| matches!(c, ElCall::ForkchoiceUpdated(_))), 2);
}

#[tokio::test]
async fn when_the_folded_forkchoice_is_refused_the_newest_ancestor_is_sent_on_its_own() {
    let a = MockExecutionLayer::built_block_on(1, GENESIS);
    let b = MockExecutionLayer::built_block_on(2, a.hash);
    let c = MockExecutionLayer::built_block_on(3, b.hash);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let el = MockExecutionLayer::with_behaviour(MockBehaviour { forkchoice_gate: Some(gate.clone()), ..Default::default() });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("channel");
    for block in [&a, &b, &c] {
        driver.cache_payload(block.hash, block.execution_data.clone());
        assert!(driver.handle_output(&execute(block.hash)).await.imported_block().is_some());
    }
    // A is on the wire (held at the gate); B and C queue behind it, B folded into C.
    driver.handle_output(&committed(a.hash)).await;
    driver.handle_output(&committed(b.hash)).await;
    driver.handle_output(&committed(c.hash)).await;
    assert!(driver.is_committing());

    let forkchoice_order = |el: &MockExecutionLayer| -> Vec<B256> {
        el.calls()
            .iter()
            .filter_map(|call| if let ElCall::ForkchoiceUpdated(s) = call { Some(s.head_block_hash) } else { None })
            .collect()
    };
    // A answers VALID.
    gate.add_permits(1);
    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await.expect("in time").expect("open");
    let actions = driver.finish_commit(report).await;
    assert_eq!(actions.iter().filter_map(DriverAction::finalized_block).collect::<Vec<_>>(), vec![a.hash]);
    // C goes next, carrying B, and is refused.
    el.set_behaviour(MockBehaviour {
        forkchoice_gate: Some(gate.clone()),
        forkchoice_status: invalid("refused"),
        ..Default::default()
    });
    gate.add_permits(1);
    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await.expect("in time").expect("open");
    let actions = driver.finish_commit(report).await;
    assert!(actions.is_empty(), "a refused forkchoice finalises nothing: {actions:?}");
    // B, folded into it, now goes on its own.
    gate.add_permits(1);
    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv()).await.expect("in time").expect("open");
    driver.finish_commit(report).await;
    assert_eq!(forkchoice_order(&el), vec![a.hash, c.hash, b.hash]);
    assert!(!driver.is_committing());
}

#[test]
fn action_accessors_answer_only_for_their_own_variant() {
    let hash = B256::repeat_byte(1);
    let rejected = DriverAction::Rejected { block_hash: hash, reason: "no".into() };
    assert_eq!(rejected.rejection(), Some((hash, "no")));
    assert_eq!((rejected.imported_block(), rejected.finalized_block(), rejected.missing_block()), (None, None, None));
    let finalized = DriverAction::Finalized { block_hash: hash };
    assert_eq!(finalized.finalized_block(), Some(hash));
    assert_eq!((finalized.rejection(), finalized.missing_block()), (None, None));
    let ignored = DriverAction::Ignored;
    assert_eq!((ignored.imported_block(), ignored.finalized_block(), ignored.missing_block(), ignored.rejection()), (None, None, None, None));
    let checked = DriverAction::Consensus(Box::new(n42_h2_consensus::ConsensusEvent::BlockChecked(hash)));
    assert_eq!(checked.imported_block(), None, "a check is not an import");
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The consensus/execution loop, end to end against an in-memory Engine API.
//!
//! These drive the real [`ExecutionDriver`] and assert on the Engine API calls it
//! makes, in order. What is being pinned is the *protocol* between consensus and
//! execution — most importantly that a follower's vote is released only after its
//! own execution layer accepted the block, and never when it did not.

use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{PayloadAttributes, PayloadStatusEnum};
use n42_h2_consensus::EngineOutput;
use n42_h2_execution::{
    ElCall, ExecutionDriver, MockBehaviour, MockExecutionLayer,
};

const GENESIS: B256 = B256::ZERO;

fn attrs() -> PayloadAttributes {
    PayloadAttributes {
        timestamp: 1_700_000_001,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: None,
        parent_beacon_block_root: None,
    }
}

fn execute(hash: B256) -> EngineOutput {
    EngineOutput::ExecuteBlock(hash)
}

fn committed(hash: B256) -> EngineOutput {
    EngineOutput::BlockCommitted {
        view: 1,
        block_hash: hash,
        // The driver never inspects the QC; the genesis sentinel keeps the
        // fixture honest without fabricating signatures.
        commit_qc: n42_h2_primitives::QuorumCertificate::genesis(),
        validator_changes: None,
    }
}

#[tokio::test]
async fn leader_builds_a_block_and_can_serve_its_own_execute_request() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);

    let built = driver.build_block(attrs()).await.unwrap();
    assert_eq!(built.number, 1);

    // The build must have gone through FCU-with-attrs then resolve — an FCU
    // without attributes would never start a build.
    assert!(matches!(
        el.calls().as_slice(),
        [ElCall::ForkchoiceUpdatedWithAttrs(_), ElCall::ResolvePayload(_)]
    ));

    // Our own proposal must not require a network round trip to execute.
    assert!(driver.has_payload(&built.hash));
    let action = driver.handle_output(&execute(built.hash)).await;
    assert_eq!(action.imported_block(), Some(built.hash));
}

#[tokio::test]
async fn follower_votes_only_after_its_own_execution_layer_accepts() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0xab);

    // A proposal arrives before the body: consensus must not get an import event.
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.missing_block(), Some(hash));
    assert!(action.imported_block().is_none());
    assert!(el.calls().is_empty(), "must not call the EL without a payload");

    // Body arrives; now the block executes and the vote is released.
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    assert_eq!(el.calls(), vec![ElCall::NewPayload(hash)]);
    assert_eq!(driver.head(), hash);
}

#[tokio::test]
async fn an_invalid_block_never_releases_a_vote() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        new_payload_status: PayloadStatusEnum::Invalid {
            validation_error: "state root mismatch".into(),
        },
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0xcd);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    let action = driver.handle_output(&execute(hash)).await;
    assert!(action.imported_block().is_none(), "voted on an invalid block");
    let (rejected, reason) = action.rejection().expect("expected a rejection");
    assert_eq!(rejected, hash);
    assert!(reason.contains("state root mismatch"), "{reason}");
    // Head must not move to a block the EL rejected.
    assert_eq!(driver.head(), GENESIS);
}

#[tokio::test]
async fn a_syncing_execution_layer_defers_rather_than_voting_blind() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        new_payload_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el, GENESIS);
    let hash = B256::repeat_byte(0xef);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    // SYNCING is not a verdict: the EL has not executed the block, so voting
    // would be voting blind. The driver must ask the caller to retry.
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.missing_block(), Some(hash));
    assert!(action.imported_block().is_none());
    assert_eq!(driver.head(), GENESIS);
}

#[tokio::test]
async fn an_execution_layer_error_is_a_rejection_not_an_import() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        new_payload_error: Some("engine unavailable".into()),
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el, GENESIS);
    let hash = B256::repeat_byte(0x11);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    let action = driver.handle_output(&execute(hash)).await;
    assert!(action.imported_block().is_none());
    assert!(action.rejection().unwrap().1.contains("engine unavailable"));
}

#[tokio::test]
async fn commit_finalizes_head_safe_and_finalized_together() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0x22);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    driver.handle_output(&execute(hash)).await;

    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), Some(hash));
    assert_eq!(driver.finalized(), hash);
    assert_eq!(driver.head(), hash);

    let fcu = el
        .calls()
        .into_iter()
        .find_map(|c| match c {
            ElCall::ForkchoiceUpdated(state) => Some(state),
            _ => None,
        })
        .expect("commit must send a forkchoice update");
    // HotStuff-2 finality is immediate: a committed block is head, safe, and
    // finalized in one step — there is no separate justification round to wait for.
    assert_eq!(fcu.head_block_hash, hash);
    assert_eq!(fcu.safe_block_hash, hash);
    assert_eq!(fcu.finalized_block_hash, hash);

    // A committed block's payload is dropped: it will never be re-executed.
    assert!(!driver.has_payload(&hash));
}

#[tokio::test]
async fn a_build_that_never_starts_reports_the_status_not_a_bare_failure() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        start_builds: false,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el, GENESIS);

    let err = driver.build_block(attrs()).await.unwrap_err();
    assert!(err.to_string().contains("no payload id"), "{err}");
    // An operator needs to know whether the EL said VALID or SYNCING here.
    assert!(err.to_string().contains("Valid"), "{err}");
}

#[tokio::test]
async fn outputs_that_do_not_concern_execution_are_ignored() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);

    let action = driver
        .handle_output(&EngineOutput::ViewChanged { new_view: 7 })
        .await;
    assert!(matches!(action, n42_h2_execution::DriverAction::Ignored));
    assert!(el.calls().is_empty(), "a view change must not touch the EL");
}

#[tokio::test]
async fn the_payload_cache_is_bounded() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el, GENESIS).with_max_cached_payloads(2);

    let a = B256::from(U256::from(1));
    let b = B256::from(U256::from(2));
    let c = B256::from(U256::from(3));
    for (i, h) in [a, b, c].into_iter().enumerate() {
        driver.cache_payload(h, MockExecutionLayer::payload_for(h, i as u64));
    }

    // A peer that pushes bodies we never asked for must not grow this forever.
    assert!(!driver.has_payload(&a), "oldest payload should have been evicted");
    assert!(driver.has_payload(&b));
    assert!(driver.has_payload(&c));
}

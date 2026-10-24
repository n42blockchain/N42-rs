// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ordering and failure rules of `N42_ANSWER_AT_INSERT` against a
//! scripted engine channel.

use super::*;
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV1, ForkchoiceState, PayloadStatusEnum,
};
use alloy_primitives::U256;
use n42_engine_types::N42EngineTypes;
use reth_engine_primitives::{BeaconEngineMessage, OnForkChoiceUpdated};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

fn engine() -> (ConsensusEngineHandle<N42EngineTypes>, mpsc::UnboundedReceiver<BeaconEngineMessage<N42EngineTypes>>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (ConsensusEngineHandle::new(tx), rx)
}

fn data(number: u64) -> ExecutionData {
    let v1 = ExecutionPayloadV1 {
        parent_hash: B256::repeat_byte(1),
        fee_recipient: Default::default(),
        state_root: B256::repeat_byte(2),
        receipts_root: B256::repeat_byte(3),
        logs_bloom: Default::default(),
        prev_randao: B256::ZERO,
        block_number: number,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1_000 + number,
        extra_data: Default::default(),
        base_fee_per_gas: U256::from(7),
        block_hash: B256::repeat_byte(number as u8),
        transactions: Vec::new(),
        difficulty: U256::ZERO,
        nonce: Default::default(),
    };
    ExecutionData::new(ExecutionPayload::V1(v1), ExecutionPayloadSidecar::none())
}

fn status(status: PayloadStatusEnum) -> PayloadStatus {
    PayloadStatus::from_status(status)
}

/// A reply the test answers by hand.
fn held_reply() -> (Reply, oneshot::Sender<PayloadStatus>) {
    let (tx, rx) = oneshot::channel::<PayloadStatus>();
    let reply: Reply = Box::pin(async move { rx.await.map_err(|_| BeaconOnNewPayloadError::EngineUnavailable) });
    (reply, tx)
}

#[test]
fn the_switch_is_on_only_for_one() {
    assert!(enabled_from(Some("1")));
    for raw in [None, Some("0"), Some(""), Some("true"), Some("yes")] {
        assert!(!enabled_from(raw), "{raw:?}");
    }
}

/// The message is on the engine's channel when `dispatch` returns, before
/// anything awaits the reply. This pins the upstream `new_payload` shape the
/// ordering relies on: a version that sent on a later poll would let the
/// validator's forkchoice overtake the pass.
#[tokio::test]
async fn a_dispatched_new_payload_is_on_the_channel_before_any_await() {
    let (handle, mut rx) = engine();
    let reply = dispatch(&handle, data(5));
    let Ok(BeaconEngineMessage::NewPayload { payload, tx, .. }) = rx.try_recv() else {
        panic!("the newPayload is not on the channel after dispatch");
    };
    assert_eq!(payload.payload.block_number(), 5);
    let _ = tx.send(Ok(status(PayloadStatusEnum::Valid)));
    let answered = reply.await.expect("reply");
    assert!(answered.status.is_valid());
}

/// The validator's forkchoice, sent after the answer while the deferred pass
/// is still pending, reaches the engine behind the pass and is answered after
/// it, and the block is found.
#[tokio::test]
async fn a_forkchoice_after_the_answer_is_served_behind_the_pending_new_payload() {
    let (handle, mut rx) = engine();
    let deferred = Arc::new(Deferred::default());
    // The answer: the pass is dispatched and tracked, nothing awaited.
    let reply = dispatch(&handle, data(6));
    let previous = deferred.track(6, B256::repeat_byte(6), reply);
    deferred.settle(previous).await.expect("nothing failed");
    // The validator's commit, after the answer.
    let fcu_handle = handle.clone();
    let fcu = tokio::spawn(async move {
        let state = ForkchoiceState { head_block_hash: B256::repeat_byte(6), ..Default::default() };
        fcu_handle.fork_choice_updated(state, None).await
    });
    // The scripted tree, one message at a time in arrival order: the block
    // is filed by the time the forkchoice is served.
    let mut order = Vec::new();
    let mut filed = false;
    for _ in 0..2 {
        match rx.recv().await.expect("message") {
            BeaconEngineMessage::NewPayload { tx, .. } => {
                order.push("newPayload");
                tokio::time::sleep(Duration::from_millis(20)).await;
                filed = true;
                let _ = tx.send(Ok(status(PayloadStatusEnum::Valid)));
            }
            BeaconEngineMessage::ForkchoiceUpdated { tx, .. } => {
                order.push("forkchoice");
                let answer = if filed { PayloadStatusEnum::Valid } else { PayloadStatusEnum::Syncing };
                let _ = tx.send(Ok(OnForkChoiceUpdated::valid(status(answer))));
            }
            _ => panic!("unexpected message"),
        }
    }
    assert_eq!(order, ["newPayload", "forkchoice"]);
    let updated = fcu.await.expect("task").expect("forkchoice");
    assert!(updated.payload_status.is_valid(), "{updated:?}");
}

/// A deferred pass that comes back INVALID fails the next answer, and every
/// one after it.
#[tokio::test]
async fn an_invalid_deferred_new_payload_fails_the_next_answers() {
    let deferred = Arc::new(Deferred::default());
    let (reply, answer) = held_reply();
    let first = deferred.track(7, B256::repeat_byte(7), reply);
    deferred.settle(first).await.expect("the first answer has nothing before it");
    let _ = answer.send(status(PayloadStatusEnum::Invalid { validation_error: "bad".to_owned() }));
    let (reply, answer) = held_reply();
    let second = deferred.track(8, B256::repeat_byte(8), reply);
    let err = deferred.settle(second).await.expect_err("the next answer fails");
    assert!(err.contains("own block 7") && err.contains("Invalid"), "{err}");
    let _ = answer.send(status(PayloadStatusEnum::Valid));
    let (reply, _answer) = held_reply();
    let third = deferred.track(9, B256::repeat_byte(9), reply);
    assert!(deferred.settle(third).await.is_err(), "latched until restart");
}

/// SYNCING (the insert was dropped and the pass did not find the block) and
/// an unavailable engine fail it the same way.
#[tokio::test]
async fn a_syncing_or_lost_deferred_new_payload_fails_the_next_answer() {
    for syncing in [true, false] {
        let deferred = Arc::new(Deferred::default());
        let (reply, answer) = held_reply();
        let first = deferred.track(10, B256::repeat_byte(10), reply);
        deferred.settle(first).await.expect("nothing before");
        if syncing {
            let _ = answer.send(status(PayloadStatusEnum::Syncing));
        } else {
            drop(answer);
        }
        let (reply, _answer) = held_reply();
        let second = deferred.track(11, B256::repeat_byte(11), reply);
        assert!(deferred.settle(second).await.is_err(), "syncing {syncing}");
    }
}

/// An answer waits for the previous own block's pass, and goes once it is
/// VALID.
#[tokio::test]
async fn an_answer_waits_for_the_previous_pass() {
    let deferred = Arc::new(Deferred::default());
    let (reply, answer) = held_reply();
    let first = deferred.track(12, B256::repeat_byte(12), reply);
    deferred.settle(first).await.expect("nothing before");
    let (reply, _answer) = held_reply();
    let second = deferred.track(13, B256::repeat_byte(13), reply);
    let waiting = Arc::clone(&deferred);
    let mut settle = tokio::spawn(async move { waiting.settle(second).await });
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut settle).await.is_err(), "answered before the previous pass");
    let _ = answer.send(status(PayloadStatusEnum::Valid));
    settle.await.expect("task").expect("the previous pass was VALID");
}

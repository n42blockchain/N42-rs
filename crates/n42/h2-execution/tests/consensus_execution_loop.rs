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
    ElCall, ExecutionDriver, ExecutionLayer, ExecutionPath, MockBehaviour, MockExecutionLayer,
};

const GENESIS: B256 = B256::ZERO;

fn attrs() -> PayloadAttributes {
    PayloadAttributes {
        // upstream additions; N42 drives neither
        slot_number: None,
        target_gas_limit: None,
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

    let built = driver.build_block(attrs(), 1).await.unwrap();
    assert_eq!(built.number, 1);

    // Building is FCU-with-attrs to start it (an FCU without attributes never
    // would) and resolve to collect it. Importing is a separate call, made
    // after the proposal is on the wire, because it costs a second full
    // execution of the block and the fleet should not be waiting through it.
    assert!(matches!(
        el.calls().as_slice(),
        [ElCall::ForkchoiceUpdatedWithAttrs(_), ElCall::ResolvePayload(_)]
    ));

    // But it must still happen, and this is the assertion that says so.
    // `getPayload` builds a block without inserting it, and the leader never
    // receives its own proposal back over gossip, so nothing else ever imports
    // it. Without this the block is committed by consensus and then rejected by
    // the leader's own execution layer, which answers the commit's
    // forkchoiceUpdated with SYNCING and leaves the chain stuck at the parent —
    // which is exactly what a live node did.
    driver.import_own_block(&built).await.unwrap();
    assert!(matches!(
        el.calls().as_slice(),
        [
            ElCall::ForkchoiceUpdatedWithAttrs(_),
            ElCall::ResolvePayload(_),
            ElCall::NewPayload(_)
        ]
    ));

    // Our own proposal must not require a network round trip to execute.
    assert!(driver.has_payload(&built.hash));
    let action = driver.handle_output(&execute(built.hash)).await;
    assert_eq!(action.imported_block(), Some(built.hash));
}

/// A leader's own block counts as importing until its import task ends, so a
/// proposal that builds on it asks again instead of losing the view (loop162
/// C13), and it never counts as a follower import, whose commits wait for a
/// report an own import does not send.
#[tokio::test]
async fn an_own_block_counts_as_importing_until_its_import_ends() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let built = driver.build_block(attrs(), 1).await.unwrap();
    assert!(!driver.is_importing_own_block(&built.hash));

    driver.spawn_import_own_block(&built);
    assert!(driver.is_importing_own_block(&built.hash), "counted from the moment the import is started");
    assert!(!driver.is_importing(&built.hash), "not a follower import");

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(!driver.is_importing_own_block(&built.hash), "off the set once the import has ended");
    assert!(el.calls().iter().any(|c| matches!(c, ElCall::NewPayload(_))));
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
async fn unsupported_or_non_live_paths_fail_before_the_engine_adapter() {
    let el = MockExecutionLayer::new();
    let hash = B256::repeat_byte(0x12);

    let pevm = el
        .new_payload_for(
            ExecutionPath::LIVE_PEVM,
            MockExecutionLayer::payload_for(hash, 1),
        )
        .await
        .unwrap_err();
    assert!(pevm.to_string().contains("live_pevm"), "{pevm}");

    let historical_build = el
        .fork_choice_updated_with_attrs_for(
            ExecutionPath::HISTORICAL_SEQUENTIAL,
            alloy_rpc_types_engine::ForkchoiceState {
                head_block_hash: GENESIS,
                safe_block_hash: GENESIS,
                finalized_block_hash: GENESIS,
            },
            attrs(),
        )
        .await
        .unwrap_err();
    assert!(
        historical_build
            .to_string()
            .contains("historical_sequential"),
        "{historical_build}"
    );
    assert!(el.calls().is_empty(), "rejected paths reached the raw adapter");
}

#[tokio::test]
async fn commit_finalizes_head_safe_and_finalized_together() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    // The awaited commit path is what this test is about; the process
    // environment does not get to decide it (`N42_COMMIT_FCU_ASYNC`).
    driver.set_commit_fcu_async(false);
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

    let err = driver.build_block(attrs(), 1).await.unwrap_err();
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

/// A follower can hear the Decide before the body channel delivers the
/// block. The commit then runs a forkchoice for a block the engine does
/// not have, which the engine answers SYNCING. That is not "done": the
/// commit waits for the import and runs once it lands (loop149: taken as
/// done, the block was imported but never canonical, the next block's
/// direct import could not see its parent, and the node fell 3 s a block
/// behind for the rest of the leg).
#[tokio::test]
async fn a_commit_the_engine_does_not_have_yet_waits_for_the_import() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    // The awaited commit path is what this test is about; the process
    // environment does not get to decide it (`N42_COMMIT_FCU_ASYNC`).
    driver.set_commit_fcu_async(false);
    let hash = B256::repeat_byte(0x33);

    // The Decide first: the forkchoice is refused with SYNCING, nothing is final.
    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), None);
    assert_eq!(driver.head(), GENESIS);

    // The body arrives and the block imports: the engine now has it, and the
    // commit that waited runs.
    el.set_behaviour(MockBehaviour::default());
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    assert_eq!(driver.head(), hash);
    let forkchoices = el
        .calls()
        .into_iter()
        .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
        .count();
    assert_eq!(forkchoices, 2, "the refused forkchoice and the one after the import");
}

/// The same order with an engine that answers the early forkchoice as if it
/// had the block (loop152: no SYNCING, and the block still never became
/// canonical): the import that follows a commit of the same block runs the
/// forkchoice again.
#[tokio::test]
async fn a_commit_that_ran_before_the_import_is_repeated_when_the_import_lands() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    // The awaited commit path is what this test is about; the process
    // environment does not get to decide it (`N42_COMMIT_FCU_ASYNC`).
    driver.set_commit_fcu_async(false);
    let hash = B256::repeat_byte(0x44);
    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), Some(hash));
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    let forkchoices = el
        .calls()
        .into_iter()
        .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
        .count();
    assert_eq!(forkchoices, 2, "the early forkchoice and the one after the import");
}

/// Block after block with the Decide ahead of the body (loop154: the
/// follower's forkchoice for the next block ran before this one's import
/// landed, so no forkchoice ever ran after an import): every commit that
/// ran before its block arrived is repeated when that block's import lands.
#[tokio::test]
async fn commits_ahead_of_their_imports_are_each_repeated_when_the_import_lands() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    // The awaited commit path is what this test is about; the process
    // environment does not get to decide it (`N42_COMMIT_FCU_ASYNC`).
    driver.set_commit_fcu_async(false);
    let a = B256::repeat_byte(0x55);
    let b = B256::repeat_byte(0x56);
    driver.handle_output(&committed(a)).await;
    driver.handle_output(&committed(b)).await;
    driver.cache_payload(a, MockExecutionLayer::payload_for(a, 1));
    driver.cache_payload(b, MockExecutionLayer::payload_for(b, 2));
    assert_eq!(driver.handle_output(&execute(a)).await.imported_block(), Some(a));
    assert_eq!(driver.handle_output(&execute(b)).await.imported_block(), Some(b));
    let forkchoices_to = |hash: B256| {
        el.calls()
            .into_iter()
            .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
            .count()
    };
    assert_eq!(forkchoices_to(a), 2, "A: the early forkchoice and the one after its import");
    assert_eq!(forkchoices_to(b), 2, "B: the same, although A's import landed after B's commit");
}

/// A commit heard before the block's import started sends nothing, and the
/// import that follows runs its forkchoice (loop160 C10 node5: the service
/// dropped such a commit, the block never became canonical, and the next
/// block's direct import waited out its parent).
#[tokio::test]
async fn a_commit_heard_before_the_import_started_runs_when_the_import_lands() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    // The awaited commit path is what this test is about; the process
    // environment does not get to decide it (`N42_COMMIT_FCU_ASYNC`).
    driver.set_commit_fcu_async(false);
    let hash = B256::repeat_byte(0x57);
    let forkchoices_to = |hash: B256| {
        el.calls()
            .into_iter()
            .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
            .count()
    };
    driver.commit_when_imported(hash);
    assert_eq!(forkchoices_to(hash), 0, "no forkchoice for a block the engine does not have");
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    assert_eq!(driver.handle_output(&execute(hash)).await.imported_block(), Some(hash));
    assert_eq!(forkchoices_to(hash), 1, "the forkchoice after the import");
}

/// A build ahead given up after its forkchoice started a payload job still
/// resolves the job: an aborted task left the job to its deadline, and reth
/// took no engine message until it ended (loop161 W: a new leader's commit
/// forkchoice and own block sat 10-11 s, then a TC).
#[tokio::test]
async fn a_build_ahead_given_up_still_resolves_its_payload_job() {
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        resolve_gate: Some(std::sync::Arc::clone(&gate)),
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let count = |call: fn(&ElCall) -> bool| el.calls().iter().filter(|c| call(c)).count();

    // The build ahead sends its forkchoice and waits at its resolve.
    driver.prepare_build_on(B256::repeat_byte(0x61), attrs()).await.expect("build ahead started");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(count(|c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_))), 1);
    assert_eq!(count(|c| matches!(c, ElCall::ResolvePayload(_))), 0);

    // The proposal asks for another parent: the build ahead is given up, and
    // the build on the asked parent resolves through the same gate.
    gate.add_permits(2);
    driver.build_block_on(GENESIS, attrs(), 1).await.expect("built on the asked parent");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(count(|c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_))), 2);
    assert_eq!(count(|c| matches!(c, ElCall::ResolvePayload(_))), 2, "the given-up build's job was resolved too");
}

/// A body the driver holds and a decoder for it, as the node installs.
fn body_for(hash: B256, number: u64) -> n42_h2_execution::ForeignBody {
    n42_h2_execution::ForeignBody {
        block_hash: hash,
        number,
        timestamp: 1_700_000_000 + number,
        profile: n42_h2_consensus::N42HeaderProfile::Ethereum,
        // The decoder below never looks at these: what is being pinned here
        // is which request the driver makes, not the wire format, which has
        // its own tests in `n42-h2-consensus` and `n42-engine-types`.
        rlp: alloy_primitives::Bytes::from_static(&[0xc0]),
    }
}

fn with_decoder(driver: &mut ExecutionDriver<MockExecutionLayer>) {
    driver.set_body_decoder(n42_h2_execution::BodyDecoder::new(|body: &n42_h2_execution::ForeignBody| {
        Ok(MockExecutionLayer::payload_for(body.block_hash, body.number))
    }));
}

/// The point of the whole path: an execution layer that takes the body is
/// never sent the same block a second time as a payload.
#[tokio::test]
async fn a_body_the_execution_layer_takes_is_never_re_encoded_as_a_payload() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour { take_bodies: true, ..Default::default() });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    with_decoder(&mut driver);
    driver.set_deferred_execution_time(Some(0));
    let mut reports = driver.take_foreign_imports().expect("the report channel");
    let hash = B256::repeat_byte(0xab);

    driver.cache_body(body_for(hash, 1));
    driver.handle_output(&execute(hash)).await;

    // The check releases the vote, then the import's verdict lands.
    let checked = reports.recv().await.expect("a check");
    let actions = driver.finish_execute(checked).await;
    assert!(actions.iter().any(|a| matches!(
        a,
        n42_h2_execution::DriverAction::Consensus(event)
            if matches!(event.as_ref(), n42_h2_consensus::ConsensusEvent::BlockChecked(h) if *h == hash)
    )));
    let done = reports.recv().await.expect("a verdict");
    let actions = driver.finish_execute(done).await;
    assert_eq!(actions[0].imported_block(), Some(hash));
    assert_eq!(el.calls(), vec![ElCall::NewPayloadBody(hash)]);
    assert_eq!(driver.head(), hash);
}

/// An execution layer that does not serve the request -- an older binary --
/// refuses before it has answered anything, and the block goes as a payload.
#[tokio::test]
async fn a_refused_body_falls_back_to_the_payload() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    with_decoder(&mut driver);
    driver.set_deferred_execution_time(Some(0));
    let mut reports = driver.take_foreign_imports().expect("the report channel");
    let hash = B256::repeat_byte(0xcd);

    driver.cache_body(body_for(hash, 1));
    driver.handle_output(&execute(hash)).await;

    let done = reports.recv().await.expect("a verdict");
    let actions = driver.finish_execute(done).await;
    assert_eq!(actions[0].imported_block(), Some(hash));
    assert_eq!(el.calls(), vec![ElCall::NewPayload(hash)], "the payload, once, after the refusal");
}

/// The paths without a body request of their own -- the awaited import --
/// decode a held body rather than asking for the block again.
#[tokio::test]
async fn an_awaited_import_decodes_a_held_body() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0xef);

    // No decoder yet: nothing can be made of the body.
    driver.cache_body(body_for(hash, 1));
    assert_eq!(driver.handle_output(&execute(hash)).await.missing_block(), Some(hash));

    with_decoder(&mut driver);
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    assert_eq!(el.calls(), vec![ElCall::NewPayload(hash)]);
}

/// Holds every commit forkchoice until the test lets it through, so what the
/// loop does *while* one is open can be asserted on.
fn gated_forkchoices() -> (MockExecutionLayer, std::sync::Arc<tokio::sync::Semaphore>) {
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_gate: Some(std::sync::Arc::clone(&gate)),
        ..Default::default()
    });
    (el, gate)
}

/// Lets the runtime run the tasks that are ready, without a clock.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

fn forkchoices_to(el: &MockExecutionLayer, hash: B256) -> usize {
    el.calls()
        .into_iter()
        .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
        .count()
}

fn forkchoice_order(el: &MockExecutionLayer) -> Vec<B256> {
    el.calls()
        .into_iter()
        .filter_map(|call| match call {
            ElCall::ForkchoiceUpdated(state) => Some(state.head_block_hash),
            _ => None,
        })
        .collect()
}

/// The point of the flag (loop189 X0a segment D): the commit returns to the
/// consensus loop before its forkchoice has reached the engine, and the same
/// state the awaited call left behind is left behind when the report lands.
#[tokio::test]
async fn an_async_commit_returns_before_its_forkchoice_and_finalises_on_the_report() {
    let (el, gate) = gated_forkchoices();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("the commit report channel");
    let hash = B256::repeat_byte(0x71);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    let action = driver.handle_output(&committed(hash)).await;
    settle().await;
    assert_eq!(action.finalized_block(), None, "the loop is not told anything yet");
    assert_eq!(forkchoices_to(&el, hash), 0, "the forkchoice has not reached the engine");
    assert_eq!(driver.head(), GENESIS, "the head follows the answer, not the request");
    // Everything that does not depend on the answer happened at send time,
    // exactly as on the awaited path.
    assert_eq!(driver.finalized(), hash);
    assert!(driver.is_committing());

    gate.add_permits(1);
    let report = reports.recv().await.expect("a commit report");
    let actions = driver.finish_commit(report).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].finalized_block(), Some(hash));
    // The same driver state the awaited path leaves.
    assert_eq!(driver.head(), hash);
    assert_eq!(driver.finalized(), hash);
    assert!(!driver.has_payload(&hash), "a committed block's payload is dropped");
    assert!(!driver.is_committing());
    assert_eq!(forkchoices_to(&el, hash), 1);
}

/// One forkchoice in flight at a time, in commit order: three commits, each
/// answered before the next goes out.
#[tokio::test]
async fn async_commits_reach_the_engine_one_at_a_time_in_order() {
    let (el, gate) = gated_forkchoices();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("the commit report channel");
    let blocks = [B256::repeat_byte(0x81), B256::repeat_byte(0x82), B256::repeat_byte(0x83)];

    for hash in blocks {
        driver.handle_output(&committed(hash)).await;
        gate.add_permits(1);
        let report = reports.recv().await.expect("a commit report");
        let actions = driver.finish_commit(report).await;
        assert_eq!(actions[0].finalized_block(), Some(hash));
    }
    assert_eq!(forkchoice_order(&el), blocks.to_vec(), "in commit order, none lost");
    assert_eq!(driver.head(), blocks[2]);
}

/// Commits that pile up behind one in flight are folded into the newest,
/// because a forkchoice to a descendant finalises its ancestors -- but their
/// bookkeeping still happens, block by block, when the answer arrives.
#[tokio::test]
async fn commits_behind_one_in_flight_are_folded_into_the_newest_and_still_finalised() {
    let (el, gate) = gated_forkchoices();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("the commit report channel");
    let [a, b, c] = [B256::repeat_byte(0x91), B256::repeat_byte(0x92), B256::repeat_byte(0x93)];
    for (number, hash) in [a, b, c].into_iter().enumerate() {
        driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, number as u64 + 1));
    }

    // A goes out and is held; B and C queue behind it.
    driver.handle_output(&committed(a)).await;
    driver.handle_output(&committed(b)).await;
    driver.handle_output(&committed(c)).await;
    settle().await;
    assert!(el.calls().is_empty(), "nothing reached the engine while the gate is shut");

    gate.add_permits(1);
    let report = reports.recv().await.expect("A's report");
    let actions = driver.finish_commit(report).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].finalized_block(), Some(a));

    // C, not B: B is A's descendant and C's ancestor, and C's forkchoice
    // finalises it.
    gate.add_permits(1);
    let report = reports.recv().await.expect("C's report");
    let actions = driver.finish_commit(report).await;
    let finalised: Vec<B256> = actions.iter().filter_map(|action| action.finalized_block()).collect();
    assert_eq!(finalised, vec![b, c], "the skipped ancestor is finalised too, before its descendant");
    assert_eq!(driver.head(), c);
    assert!(!driver.has_payload(&b), "the skipped ancestor's payload is dropped too");
    assert!(!driver.has_payload(&c));
    assert_eq!(
        forkchoice_order(&el),
        vec![a, c],
        "two forkchoices, in order, never one to a block already passed"
    );
}

/// SYNCING on the async path is what it is on the awaited one: not done. The
/// commit waits for the block's import and runs again when it lands.
#[tokio::test]
async fn an_async_commit_the_engine_does_not_have_waits_for_the_import() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("the commit report channel");
    let hash = B256::repeat_byte(0xa1);

    driver.handle_output(&committed(hash)).await;
    let report = reports.recv().await.expect("the refused commit's report");
    let actions = driver.finish_commit(report).await;
    assert!(actions.is_empty(), "nothing is final");
    assert_eq!(driver.head(), GENESIS);

    // The body arrives and the block imports: the commit that waited runs.
    el.set_behaviour(MockBehaviour::default());
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    assert_eq!(driver.handle_output(&execute(hash)).await.imported_block(), Some(hash));
    let report = reports.recv().await.expect("the repeated commit's report");
    let actions = driver.finish_commit(report).await;
    assert_eq!(actions[0].finalized_block(), Some(hash));
    assert_eq!(driver.head(), hash);
    assert_eq!(forkchoices_to(&el, hash), 2, "the refused forkchoice and the one after the import");
}

/// A commit re-asked for a block a later commit has already made canonical
/// (the commit-ahead replay when the block's import finally lands) sends no
/// forkchoice: it would move the engine's head back to an ancestor, which
/// reth unwinds as a reorg.
#[tokio::test]
async fn a_commit_replayed_after_a_later_one_landed_sends_no_forkchoice() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("the commit report channel");
    let a = B256::repeat_byte(0xc1);
    let b = B256::repeat_byte(0xc2);

    // A is committed before this node has it, then B on top of it.
    for hash in [a, b] {
        driver.handle_output(&committed(hash)).await;
        let report = reports.recv().await.expect("a commit report");
        driver.finish_commit(report).await;
    }
    assert_eq!(driver.head(), b);

    // A's body finally arrives: the import lands and replays A's commit.
    driver.cache_payload(a, MockExecutionLayer::payload_for(a, 1));
    assert_eq!(driver.handle_output(&execute(a)).await.imported_block(), Some(a));
    settle().await;
    assert_eq!(forkchoices_to(&el, a), 1, "only the first one; B's forkchoice finalised A too");
    assert_eq!(forkchoice_order(&el).last().copied(), Some(b), "the engine's head was never moved back");
    assert!(!driver.is_committing());
}

/// The flag off is the default, and the default is the awaited path: the
/// commit's forkchoice has reached the engine before `handle_output` returns,
/// and nothing is ever written to the report channel.
#[tokio::test]
async fn the_default_keeps_the_commit_on_the_loop() {
    if n42_h2_execution::commit_fcu_async() {
        // The process asked for the other path; that one has its own tests.
        return;
    }
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let mut reports = driver.take_commit_reports().expect("the commit report channel");
    let hash = B256::repeat_byte(0xb1);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    driver.handle_output(&execute(hash)).await;

    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), Some(hash));
    assert_eq!(driver.head(), hash);
    assert_eq!(forkchoices_to(&el, hash), 1);
    assert!(!driver.is_committing());
    assert!(reports.try_recv().is_err(), "the awaited path reports nothing");
}

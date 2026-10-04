// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The service loop's decisions: what a commit, an execution verdict or a
//! driver action does to the node, when a leader proposes and when it defers,
//! and what one `step` does with the events it is handed.
//!
//! Same rig as the parent module: one real service, the mock execution layer,
//! every wait bounded.

use super::*;
use alloy_rpc_types_engine::PayloadStatusEnum;
use n42_h2_primitives::consensus::ConsensusMessage as Msg;
use std::sync::atomic::{AtomicUsize, Ordering};

fn committed(view: u64, block_hash: B256) -> EngineOutput {
    EngineOutput::BlockCommitted { view, block_hash, commit_qc: QuorumCertificate::genesis(), validator_changes: None }
}

fn attributes_for(context: &ProposalContext) -> PayloadAttributes {
    PayloadAttributes {
        timestamp: 1_700_000_000 + context.view,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        target_gas_limit: None,
        slot_number: None,
    }
}

// ---------------------------------------------------------------------------
// Engine outputs: commits, executions, durability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_commit_whose_checkpoint_cannot_be_written_is_not_finalised() {
    let rig = node(1, 0, None).await;
    let writes = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&writes);
    let mut svc = rig.svc.with_checkpoint(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Err("disk full".to_owned())
    });
    let hash = B256::repeat_byte(0x51);
    svc.remember_imported(hash);
    let mut events = Vec::new();
    within(svc.handle_output(committed(3, hash), &mut events)).await.expect("a refused commit is not fatal");
    assert_eq!(writes.load(Ordering::SeqCst), 1, "the checkpoint was attempted");
    assert!(events.is_empty(), "no Committed event for an undurable commit");
    assert!(rig.el.calls().is_empty(), "finality is never announced to the execution layer");
    assert_eq!(svc.driver.finalized(), ID.genesis_hash, "nothing was finalised");
    assert!(svc.loop_spend.since.is_none());
}

#[tokio::test]
async fn a_durable_commit_of_an_imported_block_finalises_it_and_is_announced() {
    let rig = node(1, 0, None).await;
    let writes = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&writes);
    let mut svc = rig.svc.with_checkpoint(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let built = MockExecutionLayer::built_block(1);
    svc.driver.cache_payload(built.hash, built.execution_data.clone());
    let mut events = Vec::new();
    within(svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("executed");
    assert_eq!(svc.driver.head(), built.hash, "the import landed");
    svc.remember_imported(built.hash);

    within(svc.handle_output(committed(1, built.hash), &mut events)).await.expect("committed");
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(svc.driver.finalized(), built.hash);
    let calls = rig.el.calls();
    assert!(
        matches!(calls.last(), Some(ElCall::ForkchoiceUpdated(state)) if state.finalized_block_hash == built.hash),
        "the forkchoice finalises the block: {calls:?}"
    );
    let committed_event = events.iter().find_map(|e| match e {
        ServiceEvent::Committed { view, block_hash, .. } => Some((*view, *block_hash)),
        _ => None,
    });
    assert_eq!(committed_event, Some((1, built.hash)));
    assert_eq!(svc.loop_spend.since.map(|(view, _)| view), Some(1), "the leader-loop window opens at the commit");
}

#[tokio::test]
async fn a_commit_for_a_block_not_imported_here_waits_for_its_import() {
    let mut rig = node(1, 0, None).await;
    let built = MockExecutionLayer::built_block(1);
    let mut events = Vec::new();
    within(rig.svc.handle_output(committed(1, built.hash), &mut events)).await.expect("ok");
    assert!(events.is_empty(), "no Committed event until the block is here");
    assert!(rig.el.calls().is_empty(), "no forkchoice to a head the execution layer lacks");
    assert_eq!(rig.svc.driver.finalized(), ID.genesis_hash);

    // The body arrives and the engine asks for it to be executed: the import
    // lands and the commit that waited runs behind it.
    rig.svc.driver.cache_payload(built.hash, built.execution_data.clone());
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("executed");
    let calls = rig.el.calls();
    assert!(matches!(calls.first(), Some(ElCall::NewPayload(h)) if *h == built.hash), "{calls:?}");
    assert!(
        calls.iter().any(|c| matches!(c, ElCall::ForkchoiceUpdated(s) if s.head_block_hash == built.hash)),
        "the waiting commit followed the import: {calls:?}"
    );
    assert_eq!(rig.svc.driver.finalized(), built.hash);
}

#[tokio::test]
async fn an_execution_that_is_not_a_verdict_asks_for_the_body_and_an_invalid_one_withdraws_the_vote() {
    let mut rig = node(1, 0, None).await;
    let built = MockExecutionLayer::built_block(1);
    let mut events = Vec::new();

    // Unknown body, grace running: it is waited for, not asked for.
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("ok");
    assert!(rig.svc.body_wait.contains_key(&built.hash));
    assert!(events.is_empty());
    assert!(rig.svc.awaiting_bodies.is_empty());

    // The grace runs out with no body: peers are asked and the caller told.
    rig.svc.body_wait.insert(built.hash, std::time::Instant::now().checked_sub(Duration::from_secs(5)).expect("clock"));
    rig.svc.request_overdue_bodies(&mut events);
    assert_eq!(events, vec![ServiceEvent::PayloadMissing { block_hash: built.hash }]);
    assert!(rig.svc.awaiting_bodies.contains(&built.hash));
    assert!(rig.svc.body_wait.is_empty());

    // A body that arrived in the meantime cancels the request.
    let other = B256::repeat_byte(0x62);
    rig.svc.body_wait.insert(other, std::time::Instant::now().checked_sub(Duration::from_secs(5)).expect("clock"));
    rig.svc.remember_body(other, alloy_primitives::Bytes::from_static(b"here"));
    let before = events.len();
    rig.svc.request_overdue_bodies(&mut events);
    assert_eq!(events.len(), before, "nothing asked for a body already held");
    assert!(rig.svc.body_wait.is_empty());

    // SYNCING is not a verdict either.
    rig.svc.driver.cache_payload(built.hash, built.execution_data.clone());
    rig.el.set_behaviour(MockBehaviour { new_payload_status: PayloadStatusEnum::Syncing, ..Default::default() });
    rig.svc.body_grace = Duration::ZERO;
    rig.svc.awaiting_bodies.clear();
    rig.svc.body_requested_at.clear();
    events.clear();
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("ok");
    assert!(!rig.svc.imported.contains(&built.hash), "never counted as imported");
    assert!(rig.svc.awaiting_bodies.contains(&built.hash), "with no grace the ask is immediate");
    assert_eq!(events, vec![ServiceEvent::PayloadMissing { block_hash: built.hash }]);
    // Asked again at once: rate limited, no second event.
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("ok");
    assert_eq!(events.len(), 1, "the interval holds");

    // INVALID: the engine is told and votes for nothing.
    rig.el.set_behaviour(MockBehaviour {
        new_payload_status: PayloadStatusEnum::Invalid { validation_error: "bad state root".to_owned() },
        ..Default::default()
    });
    events.clear();
    within(rig.svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("ok");
    assert!(events.is_empty());
    assert!(!rig.svc.imported.contains(&built.hash));
    assert!(rig.svc.outputs.try_recv().is_err(), "the engine produced no vote for a rejected block");
}

#[tokio::test]
async fn a_compact_body_that_did_not_assemble_is_asked_for_whole_at_once() {
    let mut rig = node(1, 0, None).await;
    rig.svc.body_grace = Duration::from_secs(10);
    let (hash, _, rlp) = block(4, B256::repeat_byte(2));
    let compact = n42_h2_consensus::encode_compact_body(&rlp, &[], HeaderProfile::Ethereum).expect("compact");
    rig.svc.accept_compact_body(alloy_primitives::Bytes::from(compact), None).expect("compact");
    let mut events = Vec::new();
    rig.svc.apply_driver_action(DriverAction::PayloadMissing { block_hash: hash }, &mut events).expect("ok");
    assert!(!rig.svc.compact_bodies.contains_key(&hash), "a compact body that cannot assemble is forgotten");
    assert!(rig.svc.body_wait.is_empty(), "the grace is for bodies still in flight, not this one");
    assert!(rig.svc.awaiting_bodies.contains(&hash));
    assert_eq!(events, vec![ServiceEvent::PayloadMissing { block_hash: hash }]);
    assert!(!rig.svc.driver.has_payload(&hash));
}

#[tokio::test]
async fn driver_actions_update_the_bookkeeping_the_next_proposal_depends_on() {
    let mut rig = node(1, 0, None).await;
    let (hash, header, _) = block(9, B256::repeat_byte(8));
    rig.svc.remember_block(hash, &header);
    rig.svc.fill_rounds.insert(hash, FillRounds { rounds: 2, wanted_first: 5, wanted_last: 1, ..Default::default() });
    let mut events = Vec::new();

    // A check (deferred execution) converges the fill but imports nothing.
    rig.svc
        .apply_driver_action(DriverAction::Consensus(Box::new(ConsensusEvent::BlockChecked(hash))), &mut events)
        .expect("ok");
    assert!(!rig.svc.fill_rounds.contains_key(&hash), "the block assembled: the fill is over");
    assert!(!rig.svc.imported.contains(&hash));
    assert!(rig.svc.prepare_on.is_none());

    rig.svc
        .apply_driver_action(DriverAction::Consensus(Box::new(ConsensusEvent::BlockImported(hash))), &mut events)
        .expect("ok");
    assert!(rig.svc.imported.contains(&hash));
    assert_eq!(rig.svc.imported_height, Some(9));
    assert_eq!(rig.svc.prepare_on, Some(hash), "the next build ahead starts from this block");

    // Rejected, finalized and ignored actions produce no events of their own.
    rig.svc.apply_driver_action(DriverAction::Rejected { block_hash: hash, reason: "bad".into() }, &mut events).expect("ok");
    rig.svc.apply_driver_action(DriverAction::Finalized { block_hash: hash }, &mut events).expect("ok");
    rig.svc.apply_driver_action(DriverAction::Ignored, &mut events).expect("ok");
    assert!(events.is_empty());
}

#[tokio::test]
async fn a_fill_with_no_one_to_ask_gives_up_on_the_compact_body_and_the_rounds_are_bounded() {
    let mut rig = node(1, 0, None).await;
    let hash = B256::repeat_byte(0x44);
    let mut events = Vec::new();
    // Round one with an empty mesh: no peer, so the whole body is asked for.
    rig.svc
        .apply_driver_action(DriverAction::TransactionsMissing { block_hash: hash, indices: vec![3, 4] }, &mut events)
        .expect("ok");
    assert!(rig.svc.awaiting_bodies.contains(&hash), "no peer to ask: the whole body road");
    assert!(!rig.svc.fill_rounds.contains_key(&hash));
    assert!(rig.svc.fill_asked.is_empty());

    // A block already past the round bound goes straight to the whole body,
    // clearing every trace of the fill.
    let hash = B256::repeat_byte(0x45);
    rig.svc.fill_rounds.insert(hash, FillRounds { rounds: fill_rounds_max(), wanted_first: 9, wanted_last: 9, ..Default::default() });
    rig.svc.fill_asked.insert(hash, std::time::Instant::now());
    rig.svc
        .apply_driver_action(DriverAction::TransactionsMissing { block_hash: hash, indices: vec![1] }, &mut events)
        .expect("ok");
    assert!(!rig.svc.fill_rounds.contains_key(&hash));
    assert!(!rig.svc.fill_asked.contains_key(&hash));
    assert!(rig.svc.awaiting_bodies.contains(&hash));
    assert!(events.is_empty(), "the fill path reports nothing to the caller");

    // A position already supplied being asked for again is the defect-18
    // alternation: also straight to the whole body.
    let hash = B256::repeat_byte(0x46);
    let mut rounds = FillRounds { rounds: 1, ..Default::default() };
    rounds.supplied.insert(7);
    rig.svc.fill_rounds.insert(hash, rounds);
    rig.svc
        .apply_driver_action(DriverAction::TransactionsMissing { block_hash: hash, indices: vec![7, 8] }, &mut events)
        .expect("ok");
    assert!(!rig.svc.fill_rounds.contains_key(&hash));
    assert!(rig.svc.awaiting_bodies.contains(&hash));
}

#[tokio::test]
async fn a_timeout_the_engine_broadcasts_is_queued_while_the_mesh_is_not_ready() {
    // Four validators, and this node is not the view's leader.
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    if rig.svc.engine().is_current_leader() {
        rig = node_in(&keys, &set, 2, None).await;
    }
    assert!(!rig.svc.engine().is_current_leader());
    rig.svc.engine.on_timeout().expect("a timeout vote");
    let mut events = Vec::new();
    within(rig.svc.drain_outputs(&mut events)).await.expect("drain");
    assert!(
        rig.svc.outbox.iter().any(|m| matches!(m, Msg::Timeout(_))),
        "the timeout vote waits for a mesh: {:?}",
        rig.svc.outbox.len()
    );
    assert!(!events.iter().any(|e| matches!(e, ServiceEvent::Published { .. })), "nothing was published");

    // No mesh: flushing leaves it queued.
    let queued = rig.svc.outbox.len();
    rig.svc.flush_outbox(&mut events);
    assert_eq!(rig.svc.outbox.len(), queued);
}

// ---------------------------------------------------------------------------
// The leader's proposal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_node_without_a_payload_builder_never_proposes() {
    let mut rig = node(1, 0, None).await;
    let mut events = Vec::new();
    within(rig.svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(rig.svc.proposed_view, None);
    assert!(rig.el.calls().is_empty());
    assert!(!rig.svc.proposal_deferred);
}

#[tokio::test]
async fn a_declining_builder_defers_the_view_without_building() {
    let rig = node(1, 0, None).await;
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&asked);
    let mut svc = rig.svc.with_payload_attributes(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        None
    });
    let view = svc.engine().current_view();
    let mut events = Vec::new();
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    assert!(svc.proposal_deferred, "the next step asks again");
    assert_eq!(svc.defer_reason, Some("the attribute builder declined"));
    assert_eq!(svc.declined_view, Some(view));
    assert_eq!(svc.proposed_view, None, "a decline is not a proposal");
    assert!(rig.el.calls().is_empty(), "the execution layer was never asked to build");

    // Asked again, and again declined: the count shows each ask.
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_leader_builds_publishes_and_marks_the_view_proposed() {
    let rig = node(1, 0, None).await;
    let contexts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&contexts);
    let mut svc = rig.svc.with_payload_attributes(move |context| {
        let attrs = attributes_for(&context);
        log.lock().expect("log").push(context);
        Some(attrs)
    });
    let view = svc.engine().current_view();
    let mut events = Vec::new();
    within(svc.propose_if_leader(&mut events)).await.expect("ok");

    assert_eq!(svc.proposed_view, Some(view));
    assert!(!svc.proposal_deferred);
    assert_eq!(svc.defer_reason, None);
    {
        let contexts = contexts.lock().expect("log");
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].view, view);
        assert!(!contexts[0].preparing, "a proposal, not a build ahead");
        assert_eq!(contexts[0].head, ID.genesis_hash, "built on the genesis head");
    }
    let calls = rig.el.calls();
    assert!(calls.iter().any(|c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(s) if s.head_block_hash == ID.genesis_hash)), "{calls:?}");
    assert!(calls.iter().any(|c| matches!(c, ElCall::ResolvePayload(_))), "{calls:?}");
    // The proposal is the engine's, queued because the mesh is empty.
    assert!(svc.outbox.iter().any(|m| matches!(m, Msg::Proposal(p) if p.view == view)), "queued: {}", svc.outbox.len());
    // The built block is remembered as imported-by-us and its header kept.
    let (hash, header) = svc.block_headers.iter().next().map(|(h, hd)| (*h, hd.clone())).expect("a header was remembered");
    assert!(svc.imported.contains(&hash));
    assert_eq!(header.number, 1);

    // The same view is not built twice. (A single validator's own proposal
    // may already have moved the engine on, so the guard is set on the
    // current view directly.)
    svc.proposed_view = Some(svc.engine().current_view());
    let builds = |calls: Vec<ElCall>| {
        calls.iter().filter(|c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(_) | ElCall::ResolvePayload(_))).count()
    };
    let before = builds(rig.el.calls());
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(builds(rig.el.calls()), before, "no second build for a proposed view");
}

#[tokio::test]
async fn a_failed_build_is_not_retried_inside_the_same_view() {
    let rig = node(1, 0, None).await;
    rig.el.set_behaviour(MockBehaviour { start_builds: false, ..Default::default() });
    let mut svc = rig.svc.with_payload_attributes(|context| Some(attributes_for(&context)));
    let view = svc.engine().current_view();
    let mut events = Vec::new();
    within(svc.propose_if_leader(&mut events)).await.expect("a failed build is not fatal");
    assert_eq!(svc.proposed_view, Some(view), "marked before the build so a broken layer is not pinned");
    assert!(svc.outbox.is_empty(), "nothing to propose");
    let attempts = rig.el.calls().len();
    assert!(attempts >= 1);
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(rig.el.calls().len(), attempts, "not tried again");
}

#[tokio::test]
async fn a_non_leader_clears_any_deferral_and_builds_nothing() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    if rig.svc.engine().is_current_leader() {
        rig = node_in(&keys, &set, 2, None).await;
    }
    let mut svc = rig.svc.with_payload_attributes(|context| Some(attributes_for(&context)));
    svc.proposal_deferred = true;
    svc.defer_reason = Some("stale");
    let mut events = Vec::new();
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert!(!svc.proposal_deferred);
    assert_eq!(svc.defer_reason, None);
    assert_eq!(svc.proposed_view, None);
    assert!(rig.el.calls().is_empty());
}

// ---------------------------------------------------------------------------
// One step of the loop
// ---------------------------------------------------------------------------

/// Steps until `done` holds or the budget runs out; returns every event.
async fn step_until(
    svc: &mut H2Service<MockExecutionLayer>,
    mut done: impl FnMut(&H2Service<MockExecutionLayer>, &[ServiceEvent]) -> bool,
) -> Vec<ServiceEvent> {
    let mut all = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let events = svc.step().await.expect("a step");
            all.extend(events);
            if done(svc, &all) {
                return;
            }
        }
    })
    .await;
    assert!(result.is_ok(), "the condition was not reached in time; events: {all:?}");
    all
}

#[tokio::test]
async fn a_single_validator_leads_commits_and_announces_each_block() {
    let rig = node(1, 0, None).await;
    let mut svc = rig.svc.with_payload_attributes(|context| Some(attributes_for(&context)));
    let events = step_until(&mut svc, |_, events| {
        events.iter().filter(|e| matches!(e, ServiceEvent::Committed { .. })).count() >= 2
    })
    .await;
    let views: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            ServiceEvent::Committed { view, .. } => Some(*view),
            _ => None,
        })
        .collect();
    assert!(views[0] >= 1 && views[1] > views[0], "commits arrive in increasing views: {views:?}");
    assert!(svc.driver.finalized() != ID.genesis_hash, "the execution layer was told");
    assert!(events.iter().any(|e| matches!(e, ServiceEvent::ViewChanged { .. })));
    // The leader's own blocks are remembered as imported.
    assert!(!svc.imported.is_empty());
    assert_ne!(svc.driver.head(), ID.genesis_hash);
}

#[tokio::test]
async fn a_followers_view_clock_runs_out_and_it_votes_to_leave_the_view() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 0, None).await;
    if rig.svc.engine().is_current_leader() {
        rig = node_in(&keys, &set, 2, None).await;
    }
    let mut svc = rig.svc;
    // The clock is held while there is no mesh; this test is about it running.
    svc.meshed = true;
    let started = std::time::Instant::now();
    step_until(&mut svc, |svc, _| svc.outbox.iter().any(|m| matches!(m, Msg::Timeout(_)))).await;
    assert!(started.elapsed() >= Duration::from_millis(900), "not before the pacemaker's 1 s: {:?}", started.elapsed());
}

#[tokio::test]
async fn the_view_clock_is_held_while_no_peer_has_connected() {
    let (keys, set) = keys(4);
    let mut rig = node_in(&keys, &set, 1, None).await;
    assert!(!rig.svc.meshed);
    let before = rig.svc.time_to_timeout();
    rig.svc.hold_view_clock_until_meshed();
    assert!(!rig.svc.meshed, "still alone");
    assert!(rig.svc.time_to_timeout() > before, "the deadline moved out by a mesh-wait step");

    // A single-validator chain has nobody to wait for.
    let mut solo = node(1, 0, None).await;
    solo.svc.hold_view_clock_until_meshed();
    assert!(solo.svc.meshed);
}

#[tokio::test]
async fn a_body_from_the_direct_channel_is_taken_by_the_step_and_reported() {
    let rig = node(1, 0, None).await;
    let mut svc = rig.svc;
    let (hash, _, rlp) = block(1, ID.genesis_hash);
    let (tx, rx) = mpsc::channel(4);
    svc.body_rx = Some(rx);
    tx.send(rlp.into()).await.expect("channel open");
    let events = step_until(&mut svc, |_, events| events.iter().any(|e| matches!(e, ServiceEvent::BodyReceived { .. }))).await;
    assert!(events.contains(&ServiceEvent::BodyReceived { block_hash: hash }));
    assert!(rig.el.calls().iter().any(|c| matches!(c, ElCall::NewPayload(h) if *h == hash)), "and executed: {:?}", rig.el.calls());
}

#[tokio::test]
async fn an_import_the_driver_ran_beside_the_loop_reaches_the_engine_through_the_step() {
    let rig = node(1, 0, None).await;
    let mut svc = rig.svc;
    svc.driver.set_spawn_imports(true);
    let built = MockExecutionLayer::built_block(1);
    svc.driver.cache_payload(built.hash, built.execution_data.clone());
    let mut events = Vec::new();
    within(svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("started");
    assert!(!svc.imported.contains(&built.hash), "the verdict has not been applied yet");
    assert!(svc.driver.is_importing(&built.hash));
    step_until(&mut svc, |svc, _| svc.imported.contains(&built.hash)).await;
    assert!(!svc.driver.is_importing(&built.hash));
    assert_eq!(svc.driver.head(), built.hash);
}

#[tokio::test]
async fn a_commit_forkchoice_run_beside_the_loop_is_applied_by_the_step() {
    let rig = node(1, 0, None).await;
    let mut svc = rig.svc;
    svc.driver.set_commit_fcu_async(true);
    let built = MockExecutionLayer::built_block(1);
    svc.driver.cache_payload(built.hash, built.execution_data.clone());
    let mut events = Vec::new();
    within(svc.handle_output(EngineOutput::ExecuteBlock(built.hash), &mut events)).await.expect("executed");
    within(svc.handle_output(committed(1, built.hash), &mut events)).await.expect("committed");
    assert!(events.iter().any(|e| matches!(e, ServiceEvent::Committed { .. })), "announced at once");
    step_until(&mut svc, |svc, _| !svc.driver.is_committing() && svc.driver.finalized() == built.hash).await;
    assert_eq!(svc.driver.head(), built.hash, "the forkchoice's answer made it the head");
    assert!(rig.el.calls().iter().any(|c| matches!(c, ElCall::ForkchoiceUpdated(s) if s.head_block_hash == built.hash)));
}

#[tokio::test]
async fn a_declined_proposal_goes_out_at_the_pacing_tick() {
    let rig = node(1, 0, None).await;
    let pacing = Duration::from_millis(300);
    let mut svc = rig
        .svc
        .with_block_pacing(pacing)
        .with_payload_attributes(move |context| {
            // The head's age against the pacing, as a chain's builder does.
            context.head_seen.is_some_and(|seen| seen.elapsed() >= pacing).then(|| attributes_for(&context))
        });
    // A re-ask interval far longer than the pacing: only the tick can wake it.
    svc.propose_retry = Duration::from_secs(5);
    let started = std::time::Instant::now();
    svc.block_seen.insert(ID.genesis_hash, started);
    let view = svc.engine().current_view();
    step_until(&mut svc, |svc, _| svc.proposed_view == Some(view)).await;
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(290), "not before the pacing: {waited:?}");
    assert!(waited < Duration::from_secs(4), "woken by the tick, not the re-ask or the timeout: {waited:?}");
    assert_eq!(svc.declined_view, Some(view), "the decline is on record");
}


// ---------------------------------------------------------------------------
// The build throttle
// ---------------------------------------------------------------------------

/// A throttle on SOFT 40 / HARD 80 whose count is whatever `count` holds
/// (`u64::MAX`: unknown).
fn throttle_reading(count: &Arc<std::sync::atomic::AtomicU64>, max_hold: Duration) -> crate::build_throttle::BuildThrottle {
    let count = Arc::clone(count);
    crate::build_throttle::BuildThrottle::new(
        crate::build_throttle::ThrottleConfig { soft: 40, hard: 80, max_hold },
        Arc::new(move || {
            let n = count.load(Ordering::SeqCst);
            (n != u64::MAX).then_some(n)
        }),
    )
}

/// The execution layer's calls a proposal made, in order.
async fn proposal_calls(throttle: Option<crate::build_throttle::BuildThrottle>) -> (Vec<ElCall>, bool) {
    let rig = node(1, 0, None).await;
    let mut svc = rig.svc.with_payload_attributes(|context| Some(attributes_for(&context)));
    if let Some(throttle) = throttle {
        svc = svc.with_build_throttle(throttle);
    }
    let view = svc.engine().current_view();
    let mut events = Vec::new();
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    (rig.el.calls(), svc.proposed_view == Some(view) && !svc.proposal_deferred)
}

#[tokio::test]
async fn a_throttle_below_soft_or_without_a_count_proposes_exactly_as_none() {
    let (none, proposed) = proposal_calls(None).await;
    assert!(proposed);
    assert!(!none.is_empty());
    for reading in [u64::MAX, 0, 39] {
        let count = Arc::new(std::sync::atomic::AtomicU64::new(reading));
        let (calls, proposed) = proposal_calls(Some(throttle_reading(&count, Duration::from_secs(2)))).await;
        assert!(proposed, "count {reading}: proposed at once");
        assert_eq!(calls, none, "count {reading}: the same calls as no throttle");
    }
}

#[tokio::test]
async fn a_throttled_leader_defers_without_building_and_proposes_once_the_count_drops() {
    let rig = node(1, 0, None).await;
    let count = Arc::new(std::sync::atomic::AtomicU64::new(80));
    let mut svc = rig
        .svc
        .with_payload_attributes(|context| Some(attributes_for(&context)))
        .with_build_throttle(throttle_reading(&count, Duration::from_secs(2)));
    let view = svc.engine().current_view();
    let mut events = Vec::new();
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert!(svc.proposal_deferred, "held, not refused: the next step asks again");
    assert_eq!(svc.defer_reason, Some(crate::build_throttle::THROTTLE_REASON));
    assert_eq!(svc.proposed_view, None, "a hold is not a proposal");
    assert!(rig.el.calls().is_empty(), "nothing was built while held");
    assert!(svc.deferred_pacing_tick().is_some(), "the loop wakes at the hold's end");

    count.store(10, Ordering::SeqCst);
    within(svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(svc.proposed_view, Some(view));
    assert!(!svc.proposal_deferred);
    let throttle = svc.build_throttle.as_ref().expect("installed");
    assert_eq!(throttle.hard_holds(), 1);
    assert_eq!(throttle.last_applied().in_mem, Some(10));
}


#[tokio::test]
async fn a_hold_that_never_clears_proposes_at_the_max_hold_woken_by_its_end() {
    let rig = node(1, 0, None).await;
    let count = Arc::new(std::sync::atomic::AtomicU64::new(500));
    let max_hold = Duration::from_millis(150);
    let mut svc = rig
        .svc
        .with_payload_attributes(|context| Some(attributes_for(&context)))
        .with_build_throttle(throttle_reading(&count, max_hold));
    // A re-ask far longer than the hold: only the hold's end can wake it.
    svc.propose_retry = Duration::from_secs(5);
    let started = std::time::Instant::now();
    let view = svc.engine().current_view();
    step_until(&mut svc, |svc, _| svc.proposed_view == Some(view)).await;
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(140), "held: {waited:?}");
    assert!(waited < Duration::from_secs(4), "woken by the hold's end, not the re-ask or the view timeout: {waited:?}");
    let throttle = svc.build_throttle.as_ref().expect("installed");
    assert_eq!(throttle.hard_holds(), 1);
    assert_eq!(throttle.last_applied().in_mem, Some(500));
}


// ---------------------------------------------------------------------------
// Building ahead of leading
// ---------------------------------------------------------------------------

/// The build ahead's forkchoice is sent from a task: waits for it, bounded.
async fn wait_for_build_on(el: &MockExecutionLayer, parent: B256) {
    let seen = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if el.calls().iter().any(|c| matches!(c, ElCall::ForkchoiceUpdatedWithAttrs(s) if s.head_block_hash == parent)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(seen.is_ok(), "no build was started on {parent}: {:?}", el.calls());
}

type Contexts = Arc<std::sync::Mutex<Vec<ProposalContext>>>;

fn recording_builder(rig: Rig, answer: bool) -> (H2Service<MockExecutionLayer>, MockExecutionLayer, Contexts) {
    let contexts: Contexts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&contexts);
    let svc = rig.svc.with_payload_attributes(move |context| {
        let attrs = attributes_for(&context);
        log.lock().expect("log").push(context);
        answer.then_some(attrs)
    });
    (svc, rig.el, contexts)
}

#[tokio::test]
async fn a_build_ahead_asks_the_builder_to_prepare_and_starts_the_execution_layer_on_the_parent() {
    let rig = node(1, 0, None).await;
    let (mut svc, el, contexts) = recording_builder(rig, true);
    let (parent, header, _) = block(4, B256::repeat_byte(3));
    svc.remember_block(parent, &header);
    within(svc.prepare_next_build(parent, false)).await;

    {
        let contexts = contexts.lock().expect("log");
        assert_eq!(contexts.len(), 1);
        assert!(contexts[0].preparing, "the builder is told this is a build, not a proposal");
        assert_eq!(contexts[0].head, parent);
        assert_eq!(contexts[0].view, svc.engine().current_view() + 1);
        assert_eq!(contexts[0].head_header.as_ref(), Some(&header));
        assert_eq!(contexts[0].head_timestamp, Some(header.timestamp));
        assert!(contexts[0].head_seen.is_some());
    }
    // The forkchoice that starts the build runs on a task.
    wait_for_build_on(&el, parent).await;
}

#[tokio::test]
async fn a_build_ahead_is_skipped_without_a_builder_a_header_an_answer_or_the_next_view() {
    // No builder.
    let mut rig = node(1, 0, None).await;
    let (parent, header, _) = block(4, B256::repeat_byte(3));
    rig.svc.remember_block(parent, &header);
    within(rig.svc.prepare_next_build(parent, false)).await;
    assert!(rig.el.calls().is_empty());

    // The parent's header is not remembered.
    let rig = node(1, 0, None).await;
    let (mut svc, el, contexts) = recording_builder(rig, true);
    within(svc.prepare_next_build(parent, false)).await;
    assert!(contexts.lock().expect("log").is_empty(), "the builder is not even asked");
    assert!(el.calls().is_empty());

    // The builder declines.
    let rig = node(1, 0, None).await;
    let (mut svc, el, contexts) = recording_builder(rig, false);
    svc.remember_block(parent, &header);
    within(svc.prepare_next_build(parent, false)).await;
    assert_eq!(contexts.lock().expect("log").len(), 1, "asked once");
    assert!(el.calls().is_empty(), "a decline starts nothing");

    // The next view is somebody else's.
    let (keys, set) = keys(4);
    let mut other = node_in(&keys, &set, 0, None).await;
    let next = other.svc.engine().current_view() + 1;
    if other.svc.engine().is_leader_for_view(next) {
        other = node_in(&keys, &set, 2, None).await;
    }
    assert!(!other.svc.engine().is_leader_for_view(next));
    let (mut svc, el, contexts) = recording_builder(other, true);
    svc.remember_block(parent, &header);
    within(svc.prepare_next_build(parent, false)).await;
    assert!(contexts.lock().expect("log").is_empty(), "a node not leading next builds nothing ahead");
    assert!(el.calls().is_empty());
}

#[tokio::test]
async fn the_import_flush_builds_ahead_only_when_enabled_and_always_consumes_the_parent() {
    let rig = node(1, 0, None).await;
    let (mut svc, el, _) = recording_builder(rig, true);
    let (parent, header, _) = block(4, B256::repeat_byte(3));
    svc.remember_block(parent, &header);

    svc.prepare_on = Some(parent);
    within(svc.flush_prepare()).await;
    assert_eq!(svc.prepare_on, None, "taken whether or not it is used");
    assert!(el.calls().is_empty(), "build-ahead is off by default");

    svc.prepare_ahead = true;
    svc.prepare_on = Some(parent);
    within(svc.flush_prepare()).await;
    wait_for_build_on(&el, parent).await;

    // Nothing pending: nothing to do.
    let before = el.calls().len();
    within(svc.flush_prepare()).await;
    assert_eq!(el.calls().len(), before);
}

#[tokio::test]
async fn the_chain_sealer_is_installed_once_and_only_where_the_sealing_rule_is_known() {
    // No key and no builder: no chain.
    let mut rig = node(1, 0, None).await;
    assert!(!rig.svc.install_chain_sealer());
    assert!(!rig.svc.chain_sealer_installed);

    // A key and a builder but not gov5's profile: still no chain.
    let key = BlsSecretKey::random().expect("key");
    let mut svc = rig.svc.with_payload_attributes(|context| Some(attributes_for(&context)));
    svc.chain_seal_key = Some(key.clone());
    assert!(!svc.install_chain_sealer(), "an unknown sealing rule is never guessed");

    // Under gov5's profile it installs, and a second call is a no-op that agrees.
    rig = node(1, 0, None).await;
    let mut svc = rig.svc.with_gov5_h2_profile(key).with_payload_attributes(|context| Some(attributes_for(&context)));
    assert!(svc.install_chain_sealer());
    assert!(svc.chain_sealer_installed);
    assert!(svc.install_chain_sealer());
}

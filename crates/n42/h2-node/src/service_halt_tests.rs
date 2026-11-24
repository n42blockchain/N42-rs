// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The safety halt ([`crate::safety_halt`]): what is proof of a conflicting
//! commit and what is not, what a halted node stops doing, the evidence
//! that outlives a restart and the operator's resume -- on one service fed
//! certificates by hand, then on four real services over loopback where
//! one is shown a conflicting verified commit.

use super::net_tests::{chain, header_qc, prepare_qc, qc_signed_over};
use super::*;
use n42_h2_primitives::consensus::{ConsensusMessage, Decide};

/// A commit QC of `rig`'s set: `signers` sign `(view, signed)` in the
/// commit domain; the certificate names `named`.
fn commit_qc(rig: &Rig, signers: &[usize], view: u64, named: B256, signed: B256) -> QuorumCertificate {
    let wire = header_qc(&rig.svc, &rig.keys, signers, view, named, signed);
    to_engine_qc(&wire)
}

/// gov5's QC bytes as the engine's certificate.
fn to_engine_qc(wire: &[u8]) -> QuorumCertificate {
    let decoded = n42_h2_wire::h2_wire::decode_h2_qc(wire).expect("a QC");
    wire_bridge::qc_to_engine(&decoded, 4, "test").expect("an engine QC")
}

/// Hands `qc` to the engine as a Decide, as the transport would, and runs
/// the outputs through the service.
async fn decide(rig: &mut Rig, qc: QuorumCertificate) -> Vec<ServiceEvent> {
    let message = ConsensusMessage::Decide(Decide {
        view: qc.view,
        block_hash: qc.block_hash,
        commit_qc: qc,
        validator_changes_hash: B256::ZERO,
    });
    let _ = rig.svc.engine.process_event(ConsensusEvent::Message(message));
    let mut events = Vec::new();
    within(rig.svc.drain_outputs(&mut events)).await.expect("drained");
    events
}

/// One member of four whose committed chain is blocks 1..=3 (block 3
/// committed at view 3), the headers held. Returns the rig and the chain.
async fn committed_rig() -> (Rig, Vec<(B256, Header, alloy_primitives::Bytes)>) {
    let mut rig = node(4, 0, None).await;
    let blocks = chain(3);
    for (hash, header, _) in &blocks {
        rig.svc.remember_block(*hash, header);
    }
    let mut events = Vec::new();
    let mut ours = QuorumCertificate::genesis();
    ours.view = 3;
    ours.block_hash = blocks[2].0;
    rig.svc.sync_note_commit(Some(3), &ours, &mut events);
    (rig, blocks)
}

/// Another block at height 3 (its parent is not block 2).
fn sibling_of_three() -> (B256, Header, alloy_primitives::Bytes) {
    block(3, B256::repeat_byte(0x99))
}

fn forkchoices(rig: &Rig) -> usize {
    rig.el.calls().iter().filter(|c| matches!(c, n42_h2_execution::ElCall::ForkchoiceUpdated(_))).count()
}

fn assert_running(rig: &Rig, case: &str) {
    assert!(rig.svc.safety_halt().is_none(), "{case}: halted");
    assert_eq!(rig.svc.voting_halted(), None, "{case}: voting halted");
    assert!(!rig.svc.driver.is_halted(), "{case}: driver halted");
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("n42-halt-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[tokio::test]
async fn a_verified_commit_of_another_block_at_a_committed_height_halts_the_node_before_its_forkchoice() {
    let (mut rig, blocks) = committed_rig().await;
    let dir = scratch("live");
    let path = crate::safety_halt::evidence_path(&dir);
    rig.svc = rig.svc.with_safety_halt_file(path.clone());
    let (theirs, header, _) = sibling_of_three();
    rig.svc.remember_block(theirs, &header);
    let before = forkchoices(&rig);

    let qc = commit_qc(&rig, &[0, 1, 2], 5, theirs, theirs);
    let events = decide(&mut rig, qc).await;

    let halt = rig.svc.safety_halt().expect("halted");
    assert_eq!(halt.reason(), "conflict");
    let evidence = halt.evidence().expect("evidence");
    assert_eq!((evidence.first.hash, evidence.first.number, evidence.first.qc.view), (blocks[2].0, Some(3), 3));
    assert_eq!((evidence.second.hash, evidence.second.number, evidence.second.qc.view), (theirs, Some(3), 5));
    assert_eq!((evidence.height, evidence.source.as_str()), (Some(3), "live-commit"));
    assert!(evidence.first.header.is_some() && evidence.second.header.is_some(), "both headers kept");
    assert_eq!(rig.svc.voting_halted(), Some("commit_conflict"));
    assert!(rig.svc.driver.is_halted());
    assert_eq!(forkchoices(&rig), before, "no forkchoice to the conflicting block");
    assert!(!events.iter().any(|e| matches!(e, ServiceEvent::Committed { .. })), "not announced as committed");
    assert_eq!(crate::safety_halt::load(&path).as_ref().and_then(|h| h.evidence()), Some(evidence), "persisted");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_commit_that_extends_the_committed_chain_or_cannot_be_placed_does_not_halt() {
    let (mut rig, blocks) = committed_rig().await;
    // The next block: extends the head.
    let (next, header, _) = block(4, blocks[2].0);
    rig.svc.remember_block(next, &header);
    let qc = commit_qc(&rig, &[0, 1, 2], 5, next, next);
    decide(&mut rig, qc).await;
    assert_running(&rig, "extension");
    // A verified commit far above, whose ancestry is not held here: undecided.
    let (far, _, _) = block(40, B256::repeat_byte(0x77));
    let qc = commit_qc(&rig, &[1, 2, 3], 9, far, far);
    decide(&mut rig, qc).await;
    assert_running(&rig, "unknown height");
}

#[tokio::test]
async fn unverifiable_certificates_never_halt() {
    let (theirs, header, _) = sibling_of_three();
    let other = node(4, 0, None).await;
    for case in ["forged", "prepare domain", "foreign set", "too few signers"] {
        let (mut rig, _) = committed_rig().await;
        rig.svc.remember_block(theirs, &header);
        let qc = match case {
            // Signed over another block, naming this one.
            "forged" => commit_qc(&rig, &[0, 1, 2], 5, theirs, B256::repeat_byte(0x55)),
            "prepare domain" => {
                to_engine_qc(&prepare_qc(&rig.svc, &rig.keys, &[0, 1, 2], 5, theirs))
            }
            // Keys of a set this node does not know.
            "foreign set" => {
                let message = rig.svc.engine.signing_profile().commit_message(5, theirs, B256::ZERO);
                to_engine_qc(&qc_signed_over(&rig.svc, &other.keys, &[0, 1, 2], 5, theirs, &message))
            }
            _ => commit_qc(&rig, &[0, 1], 5, theirs, theirs),
        };
        decide(&mut rig, qc).await;
        assert_running(&rig, case);
    }
}

#[tokio::test]
async fn a_conflicting_commit_decided_before_its_header_halts_when_the_header_arrives() {
    let (mut rig, _) = committed_rig().await;
    let (theirs, header, _) = sibling_of_three();
    let qc = commit_qc(&rig, &[0, 1, 2], 5, theirs, theirs);
    decide(&mut rig, qc).await;
    assert_running(&rig, "height unknown");
    rig.svc.remember_block(theirs, &header);
    assert_eq!(rig.svc.safety_halt().map(|h| h.reason()), Some("conflict"), "checked on the header");
    assert!(rig.svc.ready_bodies.is_empty() && rig.svc.driver.is_halted(), "nothing of it is imported");
}

#[tokio::test]
async fn a_halted_node_emits_no_late_vote_or_message_and_proposes_nothing() {
    let (mut rig, _) = committed_rig().await;
    let (theirs, header, _) = sibling_of_three();
    rig.svc.remember_block(theirs, &header);
    let qc = commit_qc(&rig, &[0, 1, 2], 5, theirs, theirs);
    let message = ConsensusMessage::Decide(Decide { view: 5, block_hash: theirs, commit_qc: qc.clone(), validator_changes_hash: B256::ZERO });
    // Running, a message without a mesh is queued to go out.
    let mut events = Vec::new();
    within(rig.svc.handle_output(EngineOutput::BroadcastMessage(message.clone()), &mut events)).await.expect("handled");
    assert_eq!(rig.svc.outbox.len(), 1, "queued while running");

    decide(&mut rig, qc).await;
    assert!(rig.svc.safety_halt().is_some());
    assert!(rig.svc.outbox.is_empty(), "what was queued is dropped");
    // What the engine emitted before the halt and is drained after it.
    let mut events = Vec::new();
    for output in [
        EngineOutput::BroadcastMessage(message.clone()),
        EngineOutput::SendToValidator(1, message.clone()),
        EngineOutput::ExecuteBlock(theirs),
    ] {
        within(rig.svc.handle_output(output, &mut events)).await.expect("handled");
    }
    rig.svc.flush_outbox(&mut events);
    assert!(events.is_empty() && rig.svc.outbox.is_empty(), "nothing goes out: {events:?}");
    assert!(rig.svc.vote_refusal(&theirs).is_some(), "every vote road refuses");
    // A leader with a builder proposes nothing.
    rig.svc = rig.svc.with_payload_attributes(|_| None);
    let calls = rig.el.calls().len();
    within(rig.svc.propose_if_leader(&mut events)).await.expect("ok");
    assert_eq!(rig.el.calls().len(), calls, "no build asked for");
}

#[tokio::test]
async fn the_halt_survives_a_restart_and_only_moving_the_evidence_away_resumes() {
    let dir = scratch("restart");
    let path = crate::safety_halt::evidence_path(&dir);
    {
        let (mut rig, _) = committed_rig().await;
        rig.svc = rig.svc.with_safety_halt_file(path.clone());
        let (theirs, header, _) = sibling_of_three();
        rig.svc.remember_block(theirs, &header);
        let qc = commit_qc(&rig, &[0, 1, 2], 5, theirs, theirs);
        decide(&mut rig, qc).await;
        assert!(rig.svc.safety_halt().is_some());
    }
    let restarted = node(4, 0, None).await;
    let svc = restarted.svc.with_safety_halt_file(path.clone());
    assert_eq!(svc.safety_halt().map(|h| h.reason()), Some("conflict"), "starts halted");
    assert_eq!(svc.voting_halted(), Some("commit_conflict"));
    assert!(svc.driver.is_halted());

    // An evidence file that cannot be read halts all the same.
    std::fs::write(&path, b"truncated").expect("written");
    let svc = node(4, 0, None).await.svc.with_safety_halt_file(path.clone());
    assert_eq!(svc.safety_halt().map(|h| h.reason()), Some("unreadable"));

    // The operator's resume: the file moved out of the datadir.
    std::fs::rename(&path, dir.join("safety-halt.kept.json")).expect("moved");
    let svc = node(4, 0, None).await.svc.with_safety_halt_file(path.clone());
    assert!(svc.safety_halt().is_none() && svc.voting_halted().is_none(), "resumed");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Four services over loopback
// ---------------------------------------------------------------------------

fn fleet_attributes(context: ProposalContext) -> Option<PayloadAttributes> {
    Some(PayloadAttributes {
        timestamp: 1_700_000_000 + context.view,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: alloy_primitives::Address::ZERO,
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        target_gas_limit: None,
        slot_number: None,
        mobile_registry_root: None,
    })
}

/// What the victim's task reports.
#[derive(Debug)]
enum Seen {
    Event(usize, ServiceEvent),
    Halted,
}

/// Shows `svc` a commit of another block at its committed head's height,
/// signed by three of the four keys, the way a Decide would arrive: true
/// once it is handed over.
fn inject_conflict(svc: &mut H2Service<MockExecutionLayer>, keys: &[n42_h2_primitives::bls::BlsSecretKey]) -> bool {
    let Some((number, head)) = svc.sync_safety.committed_head() else { return false };
    let Some(mut header) = svc.block_headers.get(&head).cloned() else { return false };
    header.timestamp += 1;
    let theirs = header.hash_slow();
    debug_assert_eq!(header.number, number);
    svc.remember_block(theirs, &header);
    let view = svc.engine.current_view();
    let message = svc.engine.signing_profile().commit_message(view, theirs, B256::ZERO);
    let qc = to_engine_qc(&qc_signed_over(svc, keys, &[0, 1, 2], view, theirs, &message));
    let decide = ConsensusMessage::Decide(Decide { view, block_hash: theirs, commit_qc: qc, validator_changes_hash: B256::ZERO });
    let _ = svc.engine.process_event(ConsensusEvent::Message(decide));
    true
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_member_shown_a_conflicting_commit_halts_and_the_other_three_keep_committing() {
    let (keys, set) = keys(4);
    let dir = scratch("fleet");
    let path = crate::safety_halt::evidence_path(&dir);
    let (tx, mut rx) = mpsc::unbounded_channel::<Seen>();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let inject = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut first = None;
    let mut handles = Vec::new();
    let mut victim_handle = None;
    for index in 0..4 {
        let rig = node_in(&keys, &set, index, first.clone()).await;
        if first.is_none() {
            first = Some(rig.addr.clone());
        }
        let mut svc = rig.svc.with_payload_attributes(fleet_attributes);
        let (tx, stop) = (tx.clone(), stop.clone());
        if index == 3 {
            svc = svc.with_safety_halt_file(path.clone());
            let (inject, keys) = (inject.clone(), keys.clone());
            victim_handle = Some(tokio::spawn(async move {
                let mut reported = false;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let Ok(events) = svc.step().await else { break };
                    for event in events {
                        let _ = tx.send(Seen::Event(3, event));
                    }
                    if inject.load(std::sync::atomic::Ordering::Relaxed) && inject_conflict(&mut svc, &keys) {
                        inject.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    if !reported && svc.safety_halt().is_some() {
                        reported = true;
                        let _ = tx.send(Seen::Halted);
                    }
                }
                svc
            }));
        } else {
            handles.push(tokio::spawn(async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let Ok(events) = svc.step().await else { break };
                    for event in events {
                        let _ = tx.send(Seen::Event(index, event));
                    }
                }
            }));
        }
    }
    drop(tx);

    // The fleet commits with the victim in it; then the victim is shown
    // the conflicting commit and halts; then the three commit on.
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        let (mut victim_commits, mut halted, mut after) = (0, false, 0);
        let mut victim_spoke_after = Vec::new();
        while let Some(seen) = rx.recv().await {
            match seen {
                Seen::Event(3, ServiceEvent::Committed { .. }) if !halted => {
                    victim_commits += 1;
                    if victim_commits == 2 {
                        inject.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Seen::Halted => halted = true,
                Seen::Event(3, event @ (ServiceEvent::Published { .. } | ServiceEvent::Committed { .. })) if halted => {
                    victim_spoke_after.push(format!("{event:?}"));
                }
                Seen::Event(i, ServiceEvent::Committed { .. }) if i < 3 && halted => {
                    after += 1;
                    if after >= 9 {
                        return victim_spoke_after;
                    }
                }
                _ => {}
            }
        }
        panic!("the event channel closed");
    })
    .await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for handle in handles {
        handle.abort();
    }
    let victim = tokio::time::timeout(Duration::from_secs(30), victim_handle.expect("victim")).await;
    let spoke = outcome.expect("the three commit three blocks each after the fourth halted");
    assert!(spoke.is_empty(), "the halted member still sent or committed: {spoke:?}");
    let victim = victim.expect("the victim stops").expect("the victim's task");
    assert_eq!(victim.voting_halted(), Some("commit_conflict"));
    assert!(crate::safety_halt::load(&path).is_some_and(|h| h.evidence().is_some()), "evidence persisted");
    drop(victim);

    // Rebuilt from its datadir: halted. The file moved away: running.
    let rebuilt = node_in(&keys, &set, 3, None).await.svc.with_safety_halt_file(path.clone());
    assert_eq!(rebuilt.voting_halted(), Some("commit_conflict"), "the halt survives the rebuild");
    drop(rebuilt);
    std::fs::rename(&path, dir.join("kept.json")).expect("moved");
    let resumed = node_in(&keys, &set, 3, None).await.svc.with_safety_halt_file(path.clone());
    assert!(resumed.safety_halt().is_none() && resumed.voting_halted().is_none(), "resumed by the operator");
    let _ = std::fs::remove_dir_all(&dir);
}

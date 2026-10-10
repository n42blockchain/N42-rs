// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Engine behaviour the main suite leaves unpinned: who signed what
//! (single and batch authentication), the view-jump on a quorum certificate
//! carried by a far-future message, certificate trust and bitmap checks,
//! leader tenure, the voter window, recovery caps, output back-pressure and
//! the per-view timing summary.

use super::*;
use crate::ValidatorInfo;
use alloy_primitives::Address;
use n42_h2_primitives::consensus::{CommitVote, NewView, PrepareQC, TimeoutCertificate, TimeoutMessage, Vote};
use std::time::Duration;

fn key(seed: u8) -> n42_h2_primitives::BlsSecretKey {
    n42_h2_primitives::BlsSecretKey::key_gen(&[seed; 32]).expect("a valid deterministic key")
}

fn make(n: usize, my_index: u32) -> (ConsensusEngine, Vec<n42_h2_primitives::BlsSecretKey>, ValidatorSet, mpsc::Receiver<EngineOutput>) {
    make_with_capacity(n, my_index, 1024)
}

fn make_with_capacity(
    n: usize,
    my_index: u32,
    capacity: usize,
) -> (ConsensusEngine, Vec<n42_h2_primitives::BlsSecretKey>, ValidatorSet, mpsc::Receiver<EngineOutput>) {
    let sks: Vec<_> = (0..n).map(|i| key(0x10 + i as u8)).collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo { address: Address::with_last_byte(i as u8), bls_public_key: sk.public_key(), p2p_peer_id: None })
        .collect();
    let vs = ValidatorSet::new(&infos, ((n as u32).saturating_sub(1)) / 3);
    let (tx, rx) = mpsc::channel(capacity);
    let engine = ConsensusEngine::new(my_index, sks[my_index as usize].clone(), vs.clone(), 60_000, 120_000, tx);
    (engine, sks, vs, rx)
}

fn prepare_qc(
    view: ViewNumber,
    block_hash: B256,
    sks: &[n42_h2_primitives::BlsSecretKey],
    vs: &ValidatorSet,
    signers: &[u32],
) -> QuorumCertificate {
    use crate::protocol::quorum::{signing_message, VoteCollector};
    let mut collector = VoteCollector::new(view, block_hash, vs.len());
    for &i in signers {
        collector.add_vote(i, sks[i as usize].sign(&signing_message(view, &block_hash))).expect("a vote");
    }
    collector.build_qc(vs).expect("a quorum")
}

fn drain(rx: &mut mpsc::Receiver<EngineOutput>) -> Vec<EngineOutput> {
    let mut out = Vec::new();
    while let Ok(o) = rx.try_recv() {
        out.push(o);
    }
    out
}

// ---------------------------------------------------------------------------
// Timing summary
// ---------------------------------------------------------------------------

#[test]
fn a_leaders_view_summary_names_each_round_and_dashes_the_missing_ones() {
    let base = Instant::now();
    let at = |ms| Some(base + Duration::from_millis(ms));
    let mut timing = ViewTiming::new();
    timing.view_start = base;
    timing.proposal_sent = at(10);
    timing.prepare_qc_formed = at(30);
    timing.commit_qc_formed = at(70);
    timing.prepare_vote_count = 3;
    timing.commit_vote_count = 4;
    assert_eq!(timing.summary(), "leader proposal=@10ms R1_collect=20ms R2_collect=40ms total=70ms votes=3+4 verify_us=0 verify_n=0 verify_batches=0 verify_fallbacks=0 inbound_queue_max=0 gossip_poll_us=0");

    let mut partial = ViewTiming::new();
    partial.view_start = base;
    partial.proposal_sent = at(10);
    assert_eq!(partial.summary(), "leader proposal=@10ms R1_collect=- R2_collect=- total=- votes=0+0 verify_us=0 verify_n=0 verify_batches=0 verify_fallbacks=0 inbound_queue_max=0 gossip_poll_us=0");
}

#[test]
fn a_followers_view_summary_gives_the_vote_delay_and_the_commit_stamps() {
    let base = Instant::now();
    let at = |ms| Some(base + Duration::from_millis(ms));
    let mut timing = ViewTiming::new();
    timing.view_start = base;
    timing.proposal_received = at(5);
    timing.vote_sent = at(9);
    timing.commit_vote_sent = at(40);
    timing.commit_qc_formed = at(45);
    assert_eq!(timing.summary(), "follower proposal=@5ms vote_delay=4ms commit_vote=@40ms total=@45ms inbound_queue_max=0 gossip_poll_us=0");

    let mut empty = ViewTiming::new();
    empty.view_start = base;
    assert_eq!(empty.summary(), "follower proposal=@- vote_delay=- commit_vote=@- total=@- inbound_queue_max=0 gossip_poll_us=0");
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[test]
fn a_message_is_attributed_to_its_signer_only_when_the_signature_verifies() {
    let (engine, sks, _vs, _rx) = make(4, 0);
    let profile = engine.signing_profile;
    let hash = B256::repeat_byte(0x33);
    let genesis = QuorumCertificate::genesis();

    // Proposal.
    let sign_proposal = |signer: &n42_h2_primitives::BlsSecretKey, proposer| {
        let message = profile.proposal_message(1, hash, &None);
        ConsensusMessage::Proposal(n42_h2_primitives::consensus::Proposal {
            view: 1,
            block_hash: hash,
            justify_qc: genesis.clone(),
            proposer,
            signature: profile.sign(signer, &message),
            prepare_qc: None,
            tx_root_hash: None,
            validator_changes: None,
        })
    };
    assert_eq!(engine.authenticated_signer(&sign_proposal(&sks[1], 1)), Some(1));
    assert_eq!(engine.authenticated_signer(&sign_proposal(&sks[2], 1)), None, "signed by another member");
    assert_eq!(engine.authenticated_signer(&sign_proposal(&sks[1], 9)), None, "a proposer outside the set");

    // Vote and commit vote.
    let vote = |signer: &n42_h2_primitives::BlsSecretKey, block| {
        ConsensusMessage::Vote(Vote { view: 1, block_hash: hash, voter: 2, signature: profile.sign(signer, &profile.vote_message(1, block)) })
    };
    assert_eq!(engine.authenticated_signer(&vote(&sks[2], hash)), Some(2));
    assert_eq!(engine.authenticated_signer(&vote(&sks[2], B256::repeat_byte(1))), None, "signed over another block");
    let commit = |signer: &n42_h2_primitives::BlsSecretKey| {
        ConsensusMessage::CommitVote(CommitVote {
            view: 1,
            block_hash: hash,
            voter: 3,
            signature: profile.sign(signer, &profile.commit_message(1, hash, B256::ZERO)),
        })
    };
    assert_eq!(engine.authenticated_signer(&commit(&sks[3])), Some(3));
    assert_eq!(engine.authenticated_signer(&commit(&sks[0])), None);

    // Timeout and NewView.
    let timeout = |signer: &n42_h2_primitives::BlsSecretKey| {
        ConsensusMessage::Timeout(TimeoutMessage {
            view: 1,
            high_qc: genesis.clone(),
            sender: 1,
            signature: profile.sign(signer, &profile.timeout_message(1)),
        })
    };
    assert_eq!(engine.authenticated_signer(&timeout(&sks[1])), Some(1));
    assert_eq!(engine.authenticated_signer(&timeout(&sks[3])), None);
    let new_view = |signer: &n42_h2_primitives::BlsSecretKey| {
        ConsensusMessage::NewView(NewView {
            view: 2,
            timeout_cert: TimeoutCertificate {
                view: 1,
                aggregate_signature: sks[0].sign(b"not a real aggregate"),
                signers: genesis.signers.clone(),
                high_qc: genesis.clone(),
            },
            leader: 2,
            signature: profile.sign(signer, &profile.new_view_message(2)),
        })
    };
    assert_eq!(engine.authenticated_signer(&new_view(&sks[2])), Some(2));
    assert_eq!(engine.authenticated_signer(&new_view(&sks[0])), None);

    // Certificates are not single-signer messages.
    let pqc = ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: hash, qc: genesis });
    assert_eq!(engine.authenticated_signer(&pqc), None);
}

#[test]
fn a_batch_of_votes_is_authenticated_per_message_with_the_proof_that_names_its_kind() {
    let (engine, sks, _vs, _rx) = make(4, 0);
    let profile = engine.signing_profile;
    let hash = B256::repeat_byte(0x44);
    let vote = |voter: u32, signer: &n42_h2_primitives::BlsSecretKey| {
        ConsensusMessage::Vote(Vote { view: 1, block_hash: hash, voter, signature: profile.sign(signer, &profile.vote_message(1, hash)) })
    };
    let commit = |voter: u32, signer: &n42_h2_primitives::BlsSecretKey| {
        ConsensusMessage::CommitVote(CommitVote {
            view: 1,
            block_hash: hash,
            voter,
            signature: profile.sign(signer, &profile.commit_message(1, hash, B256::ZERO)),
        })
    };
    let timeout = ConsensusMessage::Timeout(TimeoutMessage {
        view: 1,
        high_qc: QuorumCertificate::genesis(),
        sender: 1,
        signature: profile.sign(&sks[1], &profile.timeout_message(1)),
    });
    let batch = vec![
        vote(1, &sks[1]),   // valid
        vote(2, &sks[0]),   // right voter index, wrong key
        commit(3, &sks[3]), // valid
        vote(9, &sks[1]),   // a voter outside the set
        timeout,            // not a vote: never batch-authenticated
        commit(2, &sks[1]), // wrong key
    ];
    let results = engine.authenticate_vote_batch(batch);
    assert_eq!(results.len(), 6, "one answer per message, in order");
    assert!(matches!(&results[0], Some(m) if m.proof == AuthenticatedVoteProof::Vote { signer: 1 } && m.signer() == 1));
    assert!(results[1].is_none());
    assert!(matches!(
        &results[2],
        Some(m) if m.proof == AuthenticatedVoteProof::CommitVote { signer: 3, validator_changes_hash: B256::ZERO }
    ));
    assert!(results[3].is_none());
    assert!(results[4].is_none());
    assert!(results[5].is_none());

    assert!(engine.authenticate_vote_batch(Vec::new()).is_empty());
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

#[test]
fn a_certificate_the_node_already_holds_is_trusted_and_a_misshapen_one_is_refused() {
    let (mut engine, sks, vs, _rx) = make(4, 0);
    let hash = B256::repeat_byte(0x55);
    let genuine = prepare_qc(5, hash, &sks, &vs, &[0, 1, 2]);
    assert!(engine.verify_qc_any_domain_or_known(&genuine).is_ok());

    // A certificate with a signature that verifies nowhere is refused...
    let mut forged = genuine.clone();
    forged.aggregate_signature = sks[0].sign(b"forged");
    assert!(engine.verify_qc_any_domain_or_known(&forged).is_err());
    // ...unless it is exactly the lock the node restored from its own snapshot.
    engine.round_state.update_locked_qc(&forged);
    assert!(engine.verify_qc_any_domain_or_known(&forged).is_ok(), "trusted: it was verified before it was stored");

    // A bitmap the length of another set never reaches signature checks.
    let mut wrong_size = genuine;
    wrong_size.signers.push(false);
    let err = engine.verify_qc_any_domain_or_known(&wrong_size).expect_err("a bitmap of five for four validators");
    assert!(
        matches!(&err, ConsensusError::InvalidQC { view: 5, reason } if reason.contains("signer bitmap length 5")),
        "{err:?}"
    );
}

#[test]
fn a_prepare_certificate_for_a_far_future_view_moves_the_node_to_the_view_after_it() {
    let (mut engine, sks, vs, mut rx) = make(4, 0);
    let hash = B256::repeat_byte(0x66);
    let qc = prepare_qc(60, hash, &sks, &vs, &[0, 1, 2]);
    let message = ConsensusMessage::PrepareQC(PrepareQC { view: 60, block_hash: hash, qc: qc.clone() });
    engine.process_event(ConsensusEvent::Message(message)).expect("handled");

    assert_eq!(engine.current_view(), 61, "qc.view + 1, whatever view the message claimed");
    assert_eq!(engine.locked_qc(), &qc, "the certificate is the new lock");
    let outputs = drain(&mut rx);
    assert!(
        outputs.iter().any(|o| matches!(o, EngineOutput::SyncRequired { local_view: 1, target_view: 61 })),
        "{outputs:?}"
    );
    assert!(outputs.iter().any(|o| matches!(o, EngineOutput::ViewChanged { new_view: 61 })));
}

#[test]
fn a_certificate_inside_the_window_also_moves_the_node_and_one_that_is_forged_or_stale_does_not() {
    // Inside the buffering window: still a jump, to the view after the certificate.
    let (mut engine, sks, vs, _rx) = make(4, 0);
    let hash = B256::repeat_byte(0x67);
    let near = prepare_qc(5, hash, &sks, &vs, &[0, 1, 2]);
    engine
        .process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 5, block_hash: hash, qc: near })))
        .expect("handled");
    assert_eq!(engine.current_view(), 6);

    // A forged certificate: no movement, no outputs, and not an error.
    let (mut engine, sks, vs, mut rx) = make(4, 0);
    let mut forged = prepare_qc(60, hash, &sks, &vs, &[0, 1, 2]);
    forged.aggregate_signature = sks[0].sign(b"forged");
    engine
        .process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 60, block_hash: hash, qc: forged })))
        .expect("a bad message is not an engine error");
    assert_eq!(engine.current_view(), 1);
    assert!(drain(&mut rx).is_empty());

    // The genesis certificate proves nothing and never moves a node.
    engine
        .process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC {
            view: 70,
            block_hash: hash,
            qc: QuorumCertificate::genesis(),
        })))
        .expect("handled");
    assert_eq!(engine.current_view(), 1);

    // A valid certificate for a view the node is already past: no movement.
    let (mut engine, sks, vs, mut rx) = make(4, 0);
    let far = prepare_qc(100, hash, &sks, &vs, &[0, 1, 2]);
    engine
        .process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 100, block_hash: hash, qc: far })))
        .expect("handled");
    assert_eq!(engine.current_view(), 101);
    drain(&mut rx);
    let old = prepare_qc(50, hash, &sks, &vs, &[0, 1, 2]);
    engine
        .process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 200, block_hash: hash, qc: old })))
        .expect("handled");
    assert_eq!(engine.current_view(), 101, "a certificate older than the node's view does not pull it back or forward");
    assert!(drain(&mut rx).is_empty());
}

// ---------------------------------------------------------------------------
// Identity, tenure, windows
// ---------------------------------------------------------------------------

#[test]
fn a_node_finds_its_own_index_in_the_set_and_reports_when_it_is_not_in_it() {
    let (engine_at_1, sks, vs, _rx) = make(4, 1);
    let mut engine_at_1 = engine_at_1;
    assert_eq!(engine_at_1.sync_local_validator_index(), Some(1));
    assert_eq!(engine_at_1.my_index(), 1);

    // Constructed with the wrong index for its key: corrected from the set.
    let (tx, _rx2) = mpsc::channel(8);
    let mut misindexed = ConsensusEngine::new(0, sks[2].clone(), vs.clone(), 60_000, 120_000, tx);
    assert_eq!(misindexed.sync_local_validator_index(), Some(2));
    assert_eq!(misindexed.my_index(), 2);

    // A key outside the set is an observer: no index, and the old one is left alone.
    let (tx, _rx3) = mpsc::channel(8);
    let mut observer = ConsensusEngine::new(0, key(0xEE), vs, 60_000, 120_000, tx);
    assert_eq!(observer.sync_local_validator_index(), None);
    assert_eq!(observer.my_index(), 0);
    assert!(!observer.is_current_leader());
    assert!(!observer.is_local_validator_active_for_view(1));
}

#[test]
fn a_leader_keeps_its_turn_for_the_whole_tenure() {
    let (mut engine, _, _, _rx) = make(4, 1);
    assert_eq!(engine.leader_tenure(), 1);
    engine.set_leader_tenure(3);
    assert_eq!(engine.leader_tenure(), 3);
    let leaders: Vec<u32> = (3..=9).map(|view| engine.leader_index_for_view(view)).collect();
    assert_eq!(leaders, vec![1, 1, 1, 2, 2, 2, 3], "views 3-5 are one leader's, 6-8 the next's");
    assert!(engine.is_leader_for_view(4));
    assert!(!engine.is_leader_for_view(6));
    engine.set_leader_tenure(0);
    assert_eq!(engine.leader_tenure(), 1, "a zero tenure is one view");
    engine.set_vote_before_import(true);
}

#[test]
fn the_voter_window_remembers_the_latest_views_and_counts_distinct_voters() {
    let (mut engine, _, _, _rx) = make(4, 0);
    engine.note_voter(1, 0);
    engine.note_voter(1, 0);
    engine.note_voter(1, 2);
    assert_eq!(engine.voters_seen(1), 2, "a voter counts once per view");
    assert_eq!(engine.voters_seen(2), 0);
    for view in 2..=12 {
        engine.note_voter(view, 1);
    }
    assert_eq!(engine.voters_seen(12), 1);
    assert_eq!(engine.voters_seen(5), 1, "the eight latest views are kept");
    assert_eq!(engine.voters_seen(4), 0, "older ones are forgotten");
    assert_eq!(engine.voters_seen(1), 0);
}

#[test]
fn recovered_timeouts_are_capped_so_a_bad_snapshot_cannot_stall_the_node_for_ever() {
    let (fresh, sks, _vs, _rx) = make(4, 0);
    let (tx, _out) = mpsc::channel(8);
    let recovered = ConsensusEngine::with_recovered_state_and_vote_log(
        0,
        sks[0].clone(),
        fresh.epoch_manager,
        60_000,
        120_000,
        tx,
        9,
        QuorumCertificate::genesis(),
        QuorumCertificate::genesis(),
        1_000_000,
        0,
        0,
        Arc::new(NoopVoteLog),
    );
    assert_eq!(recovered.consecutive_timeouts(), 128);
    assert_eq!(recovered.current_view(), 9);
}

// ---------------------------------------------------------------------------
// Output back-pressure
// ---------------------------------------------------------------------------

#[test]
fn a_full_output_channel_is_retried_and_then_reported_not_silently_dropped() {
    let (engine, _, _, mut rx) = make_with_capacity(4, 0, 1);
    engine.emit(EngineOutput::ViewChanged { new_view: 2 }).expect("room for one");
    let started = Instant::now();
    let err = engine.emit(EngineOutput::ViewChanged { new_view: 3 }).expect_err("nobody is draining");
    assert!(matches!(err, ConsensusError::OutputChannelClosed), "{err:?}");
    assert!(started.elapsed() >= Duration::from_micros(1_000), "the retries waited: {:?}", started.elapsed());

    // A commit that cannot be delivered is the worst case and fails the same way.
    let err = engine
        .emit(EngineOutput::BlockCommitted {
            view: 1,
            block_hash: B256::ZERO,
            commit_qc: QuorumCertificate::genesis(),
            validator_changes: None,
        })
        .expect_err("still full");
    assert!(matches!(err, ConsensusError::OutputChannelClosed));

    // What was accepted is still there, in order, and draining makes room again.
    assert!(matches!(rx.try_recv(), Ok(EngineOutput::ViewChanged { new_view: 2 })));
    engine.emit(EngineOutput::ViewChanged { new_view: 4 }).expect("room again");
}

#[test]
fn a_closed_output_channel_is_fatal_for_every_kind_of_output() {
    let (engine, _, _, rx) = make(4, 0);
    drop(rx);
    for output in [
        EngineOutput::ExecuteBlock(B256::ZERO),
        EngineOutput::SyncRequired { local_view: 1, target_view: 2 },
        EngineOutput::EpochTransition { new_epoch: 1, validator_count: 4 },
        EngineOutput::EquivocationDetected { view: 1, validator: 2, hash1: B256::ZERO, hash2: B256::repeat_byte(1) },
        EngineOutput::SendToValidator(1, ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: B256::ZERO, qc: QuorumCertificate::genesis() })),
        EngineOutput::BroadcastMessage(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: B256::ZERO, qc: QuorumCertificate::genesis() })),
        EngineOutput::CommittedBlockValidatorChangesRecovered { view: 1, block_hash: B256::ZERO, validator_changes: Vec::new() },
    ] {
        let err = engine.emit(output).expect_err("nobody is listening");
        assert!(matches!(err, ConsensusError::OutputChannelClosed), "{err:?}");
    }
    let text = format!("{engine:?}");
    assert!(text.contains("ConsensusEngine") && text.contains("my_index: 0"), "{text}");
}

// ---------------------------------------------------------------------------
// Validator-set changes and read accessors
// ---------------------------------------------------------------------------

fn candidate(seed: u8, address: u8) -> ValidatorInfo {
    ValidatorInfo { address: Address::with_last_byte(address), bls_public_key: key(seed).public_key(), p2p_peer_id: None }
}

#[test]
fn validator_changes_are_refused_by_name_until_epochs_are_on_and_then_bounded_by_the_minimum_set() {
    let (mut engine, _sks, vs, _rx) = make(4, 0);

    // Epochs are off by default: the change cannot be staged at all.
    assert!(matches!(engine.propose_add_validator(candidate(0x90, 0x50)), Err(ConsensusError::EpochsDisabled)));
    assert!(matches!(engine.propose_remove_validator(Address::with_last_byte(1)), Err(ConsensusError::EpochsDisabled)));

    *engine.epoch_manager_mut() = EpochManager::with_epoch_length(vs, 10);
    engine.propose_add_validator(candidate(0x90, 0x50)).expect("a new address is queued");
    assert!(matches!(
        engine.propose_add_validator(candidate(0x91, 0x50)),
        Err(ConsensusError::ValidatorAlreadyExists { address }) if address == Address::with_last_byte(0x50)
    ), "already queued");
    assert!(matches!(
        engine.propose_add_validator(candidate(0x92, 1)),
        Err(ConsensusError::ValidatorAlreadyExists { .. })
    ), "already a member");

    assert!(matches!(
        engine.propose_remove_validator(Address::with_last_byte(0x77)),
        Err(ConsensusError::ValidatorNotFound { address }) if address == Address::with_last_byte(0x77)
    ));
    // Four members plus one queued: one may leave and four remain.
    engine.propose_remove_validator(Address::with_last_byte(1)).expect("the set stays at the minimum");
    assert!(matches!(
        engine.propose_remove_validator(Address::with_last_byte(1)),
        Err(ConsensusError::ValidatorAlreadyPendingRemoval { .. })
    ));
    assert!(matches!(
        engine.propose_remove_validator(Address::with_last_byte(2)),
        Err(ConsensusError::InsufficientValidators { have: 3, need: 4 })
    ), "a second departure would leave three");
}

#[test]
fn a_new_engine_reports_the_state_it_starts_in() {
    let (mut engine, _sks, _vs, _rx) = make(4, 2);
    assert!(matches!(engine.signing_profile(), ConsensusSigningProfile::Native));
    engine.enable_h2_v4_signing(H2V4ChainIdentity { chain_id: 96, genesis_hash: B256::repeat_byte(1) });
    assert!(matches!(engine.signing_profile(), ConsensusSigningProfile::H2V4(id) if id.chain_id == 96));

    assert_eq!((engine.validator_count(), engine.quorum_size()), (4, 3));
    assert_eq!(engine.current_view(), 1);
    assert_eq!(engine.current_leader_index(), 1, "view 1 belongs to validator 1");
    assert_eq!((engine.last_voted_view(), engine.last_commit_voted_view()), (0, 0));
    assert!(engine.last_committed_view_timing().is_none());
    assert_eq!(engine.consecutive_timeouts(), 0);
    let before = engine.pacemaker().remaining();
    engine.pacemaker_mut().extend_deadline(Duration::from_secs(10));
    assert!(engine.pacemaker().remaining() > before + Duration::from_secs(5), "the view clock moved out");
    assert!(engine.epoch_manager().current_validator_set().len() == 4);
}

// ---------------------------------------------------------------------------
// Lock durability across a crash
// ---------------------------------------------------------------------------

/// An in-memory vote log that keeps every record, to stand in for the disk.
#[derive(Debug, Default)]
struct RecordingLog {
    records: std::sync::Mutex<Vec<(&'static str, u64, QuorumCertificate)>>,
}

impl crate::vote_log::VoteLogWriter for RecordingLog {
    fn record_vote(&self, view: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        self.records.lock().expect("log").push(("r1", view, locked_qc.clone()));
        Ok(())
    }

    fn record_commit_vote(&self, view: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        self.records.lock().expect("log").push(("r2", view, locked_qc.clone()));
        Ok(())
    }
}

fn proposal_for(
    engine: &ConsensusEngine,
    sks: &[n42_h2_primitives::BlsSecretKey],
    view: ViewNumber,
    block_hash: B256,
    justify_qc: QuorumCertificate,
) -> ConsensusMessage {
    let proposer = engine.leader_index_for_view(view);
    let message = engine.signing_profile.proposal_message(view, block_hash, &None);
    ConsensusMessage::Proposal(n42_h2_primitives::consensus::Proposal {
        view,
        block_hash,
        justify_qc,
        proposer,
        signature: engine.signing_profile.sign(&sks[proposer as usize], &message),
        prepare_qc: None,
        tx_root_hash: None,
        validator_changes: None,
    })
}

#[test]
fn a_lock_raised_before_a_crash_still_refuses_an_older_justification_after_it() {
    let log = Arc::new(RecordingLog::default());
    let (tx, mut rx) = mpsc::channel(1024);
    let sks: Vec<_> = (0..4).map(|i| key(0x10 + i as u8)).collect();
    let (_, _, vs, _) = make(4, 2);
    let build = |view, locked: QuorumCertificate, voted, commit_voted, tx| {
        ConsensusEngine::with_recovered_state_and_vote_log(
            2,
            sks[2].clone(),
            EpochManager::new(vs.clone()),
            60_000,
            120_000,
            tx,
            view,
            locked,
            QuorumCertificate::genesis(),
            0,
            voted,
            commit_voted,
            log.clone(),
        )
    };

    // View 1: R1 vote on the proposal, then the PrepareQC raises the lock to 1
    // and the node commit-votes under it.
    let mut engine = build(1, QuorumCertificate::genesis(), 0, 0, tx);
    let hash = B256::repeat_byte(0x71);
    let proposal = proposal_for(&engine, &sks, 1, hash, QuorumCertificate::genesis());
    engine.process_event(ConsensusEvent::BlockImported(hash)).expect("import");
    engine.process_event(ConsensusEvent::Message(proposal)).expect("proposal");
    let qc = prepare_qc(1, hash, &sks, &vs, &[0, 1, 3]);
    engine
        .process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: hash, qc: qc.clone() })))
        .expect("prepare qc");
    assert_eq!(engine.locked_qc(), &qc, "the lock is raised to view 1");
    assert!(drain(&mut rx).iter().any(|o| matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::Vote(_)))));

    let (last_voted, last_commit_voted) = (engine.last_voted_view(), engine.last_commit_voted_view());
    assert_eq!((last_voted, last_commit_voted), (1, 1));
    let logged = log.records.lock().expect("log").clone();
    assert!(
        logged.iter().any(|(kind, view, lock)| *kind == "r2" && *view == 1 && lock == &qc),
        "the commit vote is logged together with the raised lock",
    );
    // Crash before the commit: the checkpoint still holds the genesis lock, so
    // recovery takes the higher of it and the log's.
    drop(engine);
    let recovered_lock = logged
        .iter()
        .map(|(_, _, lock)| lock.clone())
        .chain([QuorumCertificate::genesis()])
        .max_by_key(|lock| lock.view)
        .expect("a lock");
    assert_eq!(recovered_lock, qc);

    // View 2: a proposal justified by something older than the lock is refused.
    let (tx, mut rx) = mpsc::channel(1024);
    let mut engine = build(2, recovered_lock.clone(), last_voted, last_commit_voted, tx);
    let stale = proposal_for(&engine, &sks, 2, B256::repeat_byte(0x72), QuorumCertificate::genesis());
    let error = engine
        .process_event(ConsensusEvent::Message(stale))
        .expect_err("the restored lock must refuse it");
    assert!(matches!(error, ConsensusError::SafetyViolation { qc_view: 0, locked_view: 1 }), "{error:?}");

    // View 1 again: no second R1 vote, even for a proposal the lock allows.
    let (tx, mut rx1) = mpsc::channel(1024);
    let mut engine = build(1, recovered_lock.clone(), last_voted, last_commit_voted, tx);
    let again = B256::repeat_byte(0x73);
    let proposal = proposal_for(&engine, &sks, 1, again, recovered_lock);
    engine.process_event(ConsensusEvent::BlockImported(again)).expect("import");
    engine.process_event(ConsensusEvent::Message(proposal)).expect("handled");
    let outputs = drain(&mut rx1);
    assert!(
        !outputs.iter().any(|o| matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::Vote(_)))),
        "{outputs:?}",
    );
    assert!(drain(&mut rx).iter().all(|o| !matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::Vote(_)))));
}

// ---------------------------------------------------------------------------
// Fault injection at every boundary of "record vote -> persist -> sign -> send"
// ---------------------------------------------------------------------------

/// What the injected fault does to the Nth call of one kind of record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// No fault: the record is durable and the vote is signed and sent.
    None,
    /// The fsync fails and nothing reaches the disk.
    LostWrite,
    /// The record reaches the disk but the call reports failure, which is a
    /// crash between persist and sign as far as the engine can tell.
    DurableThenCrash,
}

/// A vote log that fails on the first record of one kind.
#[derive(Debug)]
struct FaultyLog {
    kind: &'static str,
    fault: Fault,
    calls: std::sync::Mutex<usize>,
    durable: std::sync::Mutex<Vec<(&'static str, u64, QuorumCertificate)>>,
}

impl FaultyLog {
    fn new(kind: &'static str, fault: Fault) -> Self {
        Self { kind, fault, calls: Default::default(), durable: Default::default() }
    }

    fn write(&self, kind: &'static str, view: u64, lock: &QuorumCertificate) -> ConsensusResult<()> {
        let fail = kind == self.kind && self.fault != Fault::None && {
            let mut calls = self.calls.lock().expect("calls");
            *calls += 1;
            *calls == 1
        };
        if !fail || self.fault == Fault::DurableThenCrash {
            self.durable.lock().expect("log").push((kind, view, lock.clone()));
        }
        if fail {
            return Err(ConsensusError::VoteLogFsync(format!("injected fault on {kind}")));
        }
        Ok(())
    }
}

impl crate::vote_log::VoteLogWriter for FaultyLog {
    fn record_vote(&self, view: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        self.write("r1", view, locked_qc)
    }

    fn record_commit_vote(&self, view: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        self.write("r2", view, locked_qc)
    }
}

fn sent_votes(outputs: &[EngineOutput]) -> (usize, usize) {
    let r1 = outputs.iter().filter(|o| matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::Vote(_)))).count();
    let r2 = outputs.iter().filter(|o| matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::CommitVote(_)))).count();
    (r1, r2)
}

/// Drives a follower through view 1 (proposal, then PrepareQC) against a log
/// that faults on the first record of `kind`, then rebuilds the engine from
/// what is durable and offers the same view again.
fn run_boundary(kind: &'static str, fault: Fault) {
    let log = Arc::new(FaultyLog::new(kind, fault));
    let sks: Vec<_> = (0..4).map(|i| key(0x10 + i as u8)).collect();
    let (_, _, vs, _) = make(4, 2);
    let build = |locked: QuorumCertificate, voted, commit_voted, log: Arc<dyn crate::vote_log::VoteLogWriter>| {
        let (tx, rx) = mpsc::channel(1024);
        let engine = ConsensusEngine::with_recovered_state_and_vote_log(
            2,
            sks[2].clone(),
            EpochManager::new(vs.clone()),
            60_000,
            120_000,
            tx,
            1,
            locked,
            QuorumCertificate::genesis(),
            0,
            voted,
            commit_voted,
            log,
        );
        (engine, rx)
    };
    let hash = B256::repeat_byte(0x81);
    let qc = prepare_qc(1, hash, &sks, &vs, &[0, 1, 3]);
    let prepare = || ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: hash, qc: qc.clone() });
    let injected = fault != Fault::None;
    let label = format!("{kind} {fault:?}");

    let (mut engine, mut rx) = build(QuorumCertificate::genesis(), 0, 0, log.clone());
    let proposal = proposal_for(&engine, &sks, 1, hash, QuorumCertificate::genesis());
    engine.process_event(ConsensusEvent::BlockImported(hash)).expect("import");
    let r1 = engine.process_event(ConsensusEvent::Message(proposal.clone()));
    let first = if kind == "r2" {
        r1.expect("R1 is not faulted in an R2 row");
        engine.process_event(ConsensusEvent::Message(prepare()))
    } else {
        r1
    };
    let outputs = drain(&mut rx);
    let (sent_r1, sent_r2) = sent_votes(&outputs);

    // (a)/(b) The faulted record aborts the vote: an error and nothing sent.
    if injected {
        assert!(matches!(first, Err(ConsensusError::VoteLogFsync(_))), "{label}: {first:?}");
        assert_eq!(if kind == "r1" { sent_r1 } else { sent_r2 }, 0, "{label}: no vote leaves after a failed persist");
    } else {
        first.expect("no fault");
        assert_eq!(if kind == "r1" { sent_r1 } else { sent_r2 }, 1, "{label}: the vote is sent");
    }

    // The watermark moves before the log call, so a failed persist still
    // consumes the view in memory: the engine refuses a retry in that view.
    let (marker, other) = if kind == "r1" { (engine.last_voted_view(), 0) } else { (engine.last_commit_voted_view(), engine.last_voted_view()) };
    assert_eq!(marker, 1, "{label}: the in-memory watermark is already advanced");
    assert_eq!(other, u64::from(kind == "r2"));
    let retry = if kind == "r1" { proposal.clone() } else { prepare() };
    let _ = engine.process_event(ConsensusEvent::Message(retry.clone()));
    let (retry_r1, retry_r2) = sent_votes(&drain(&mut rx));
    assert_eq!(if kind == "r1" { retry_r1 } else { retry_r2 }, 0, "{label}: a retry in the same view is refused");

    // Crash: rebuild from the durable records only (higher view and higher
    // lock win, as `ConsensusStore::load` does against a stale checkpoint).
    drop(engine);
    let durable = log.durable.lock().expect("log").clone();
    let watermark = |k: &str| durable.iter().filter(|(kind, ..)| *kind == k).map(|(_, v, _)| *v).max().unwrap_or(0);
    let lock = durable.iter().map(|(_, _, l)| l.clone()).chain([QuorumCertificate::genesis()]).max_by_key(|l| l.view).expect("lock");
    let (voted, commit_voted) = (watermark("r1"), watermark("r2"));
    let persisted = fault != Fault::LostWrite;
    assert_eq!(if kind == "r1" { voted } else { commit_voted }, u64::from(persisted), "{label}: durable watermark");
    if kind == "r2" {
        // The lock raised by the PrepareQC is durable exactly when the
        // commit-vote record is; a lost write leaves the old lock, which is
        // safe because no commit vote was signed under the new one.
        assert_eq!(lock, if persisted { qc.clone() } else { QuorumCertificate::genesis() }, "{label}: durable lock");
    }

    let (mut again, mut rx) = build(lock, voted, commit_voted, Arc::new(crate::vote_log::NoopVoteLog));
    again.process_event(ConsensusEvent::BlockImported(hash)).expect("import");
    if kind == "r2" {
        let _ = again.process_event(ConsensusEvent::Message(proposal));
        drain(&mut rx);
    }
    let _ = again.process_event(ConsensusEvent::Message(retry));
    let (again_r1, again_r2) = sent_votes(&drain(&mut rx));
    let again_sent = if kind == "r1" { again_r1 } else { again_r2 };
    // A lost write means nothing was signed, so the rebuilt node may vote; a
    // durable record (signed or not) means it must not vote in that view again.
    assert_eq!(again_sent, usize::from(!persisted), "{label}: rebuilt engine");
}

#[test]
fn every_persist_boundary_of_a_vote_is_safe_for_both_rounds() {
    for kind in ["r1", "r2"] {
        for fault in [Fault::LostWrite, Fault::DurableThenCrash, Fault::None] {
            run_boundary(kind, fault);
        }
    }
}

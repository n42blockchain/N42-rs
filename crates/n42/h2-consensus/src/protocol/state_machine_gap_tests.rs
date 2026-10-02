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
    assert_eq!(timing.summary(), "leader proposal=@10ms R1_collect=20ms R2_collect=40ms total=70ms votes=3+4");

    let mut partial = ViewTiming::new();
    partial.view_start = base;
    partial.proposal_sent = at(10);
    assert_eq!(partial.summary(), "leader proposal=@10ms R1_collect=- R2_collect=- total=- votes=0+0");
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
    assert_eq!(timing.summary(), "follower proposal=@5ms vote_delay=4ms commit_vote=@40ms total=@45ms");

    let mut empty = ViewTiming::new();
    empty.view_start = base;
    assert_eq!(empty.summary(), "follower proposal=@- vote_delay=- commit_vote=@- total=@-");
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

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A vote-log write that fails must not consume the view in memory: once the
//! disk recovers, the same proposal or PrepareQC is voted on.

use super::*;
use crate::ValidatorInfo;
use alloy_primitives::Address;
use n42_h2_primitives::consensus::PrepareQC;
use std::sync::atomic::{AtomicBool, Ordering};

/// Fails the first record of every kind, then succeeds.
#[derive(Debug, Default)]
struct FailOnce {
    r1_failed: AtomicBool,
    r2_failed: AtomicBool,
}

impl crate::vote_log::VoteLogWriter for FailOnce {
    fn record_vote(&self, _view: u64, _lock: &QuorumCertificate) -> ConsensusResult<()> {
        if self.r1_failed.swap(true, Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ConsensusError::VoteLogFsync("injected".into()))
        }
    }

    fn record_commit_vote(&self, _view: u64, _lock: &QuorumCertificate) -> ConsensusResult<()> {
        if self.r2_failed.swap(true, Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ConsensusError::VoteLogFsync("injected".into()))
        }
    }
}

fn votes(rx: &mut mpsc::Receiver<EngineOutput>) -> (usize, usize) {
    let (mut r1, mut r2) = (0, 0);
    while let Ok(o) = rx.try_recv() {
        match o {
            EngineOutput::SendToValidator(_, ConsensusMessage::Vote(_)) => r1 += 1,
            EngineOutput::SendToValidator(_, ConsensusMessage::CommitVote(_)) => r2 += 1,
            _ => {}
        }
    }
    (r1, r2)
}

#[test]
fn a_follower_votes_on_the_retry_after_a_failed_log_write_in_both_rounds() {
    use crate::protocol::quorum::{signing_message, VoteCollector};
    let sks: Vec<_> = (0..4u8)
        .map(|i| n42_h2_primitives::BlsSecretKey::key_gen(&[0x10 + i; 32]).expect("key"))
        .collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo { address: Address::with_last_byte(i as u8), bls_public_key: sk.public_key(), p2p_peer_id: None })
        .collect();
    let vs = ValidatorSet::new(&infos, 1);
    let (tx, mut rx) = mpsc::channel(1024);
    let mut engine = ConsensusEngine::with_recovered_state_and_vote_log(
        2,
        sks[2].clone(),
        EpochManager::new(vs.clone()),
        60_000,
        120_000,
        tx,
        1,
        QuorumCertificate::genesis(),
        QuorumCertificate::genesis(),
        0,
        0,
        0,
        Arc::new(FailOnce::default()),
    );
    let hash = B256::repeat_byte(0x82);
    let proposer = engine.leader_index_for_view(1);
    let sig_msg = engine.signing_profile.proposal_message(1, hash, &None);
    let proposal = ConsensusMessage::Proposal(n42_h2_primitives::consensus::Proposal {
        view: 1,
        block_hash: hash,
        justify_qc: QuorumCertificate::genesis(),
        proposer,
        signature: engine.signing_profile.sign(&sks[proposer as usize], &sig_msg),
        prepare_qc: None,
        tx_root_hash: None,
        validator_changes: None,
    });
    let mut collector = VoteCollector::new(1, hash, vs.len());
    for i in [0u32, 1, 3] {
        collector.add_vote(i, sks[i as usize].sign(&signing_message(1, &hash))).expect("vote");
    }
    let qc = collector.build_qc(&vs).expect("quorum");
    let prepare = ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: hash, qc });

    engine.process_event(ConsensusEvent::BlockImported(hash)).expect("import");
    // R1: the first write fails, nothing is sent, the watermark is restored.
    assert!(engine.process_event(ConsensusEvent::Message(proposal.clone())).is_err());
    assert_eq!(votes(&mut rx), (0, 0));
    assert_eq!(engine.last_voted_view(), 0);
    engine.process_event(ConsensusEvent::Message(proposal)).expect("retry");
    assert_eq!(votes(&mut rx), (1, 0), "R1 retry votes");
    assert_eq!(engine.last_voted_view(), 1);

    // R2: same, against the commit-vote watermark.
    assert!(engine.process_event(ConsensusEvent::Message(prepare.clone())).is_err());
    assert_eq!(votes(&mut rx), (0, 0));
    assert_eq!(engine.last_commit_voted_view(), 0);
    engine.process_event(ConsensusEvent::Message(prepare)).expect("retry");
    assert_eq!(votes(&mut rx), (0, 1), "R2 retry votes");
    assert_eq!(engine.last_commit_voted_view(), 1);
}

/// Fails every write while `fail` is set.
#[derive(Debug, Default)]
struct Switchable {
    fail: AtomicBool,
}

impl crate::vote_log::VoteLogWriter for Switchable {
    fn record_vote(&self, _view: u64, _lock: &QuorumCertificate) -> ConsensusResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            Err(ConsensusError::VoteLogFsync("injected".into()))
        } else {
            Ok(())
        }
    }

    fn record_commit_vote(&self, view: u64, lock: &QuorumCertificate) -> ConsensusResult<()> {
        self.record_vote(view, lock)
    }
}

fn follower_with(log: Arc<Switchable>) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
    let sks: Vec<_> = (0..4u8)
        .map(|i| n42_h2_primitives::BlsSecretKey::key_gen(&[0x30 + i; 32]).expect("key"))
        .collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo { address: Address::with_last_byte(i as u8), bls_public_key: sk.public_key(), p2p_peer_id: None })
        .collect();
    let (tx, rx) = mpsc::channel(1024);
    let engine = ConsensusEngine::with_recovered_state_and_vote_log(
        2,
        sks[2].clone(),
        EpochManager::new(ValidatorSet::new(&infos, 1)),
        60_000,
        120_000,
        tx,
        1,
        QuorumCertificate::genesis(),
        QuorumCertificate::genesis(),
        0,
        0,
        0,
        log,
    );
    (engine, rx)
}

#[test]
fn consecutive_vote_log_failures_are_fatal_on_the_third_and_a_success_resets_the_run() {
    let log = Arc::new(Switchable::default());
    let (mut engine, mut rx) = follower_with(Arc::clone(&log));
    let hash = B256::repeat_byte(0x91);
    assert_eq!(engine.vote_log_fatal_after, crate::DEFAULT_VOTE_LOG_FATAL_AFTER);

    // Two failures, then a success: the run resets and nothing is fatal.
    log.fail.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        let err = engine.send_vote(1, hash).expect_err("the write fails");
        assert!(matches!(err, ConsensusError::VoteLogFsync(_)), "{err:?}");
    }
    assert_eq!(engine.vote_log_failures_in_a_row(), 2);
    log.fail.store(false, Ordering::SeqCst);
    engine.send_vote(1, hash).expect("the disk recovered");
    assert_eq!(votes(&mut rx), (1, 0));
    assert_eq!(engine.vote_log_failures_in_a_row(), 0, "a success resets the run");
    assert_eq!(engine.voting_halted(), None);

    // Three in a row: the third is fatal and voting stops.
    log.fail.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert!(matches!(engine.send_vote(2, hash), Err(ConsensusError::VoteLogFsync(_))));
    }
    let err = engine.send_vote(2, hash).expect_err("third failure");
    assert_eq!(err.fatal_reason(), Some("vote_log"), "{err:?}");
    assert!(err.is_local());
    assert_eq!(engine.vote_log_failures_total(), 5);
    assert_eq!(engine.voting_halted(), Some("vote_log"));

    // Halted: even with the disk back, the node no longer votes.
    log.fail.store(false, Ordering::SeqCst);
    engine.send_vote(3, hash).expect("a halted node skips, it does not fail");
    assert_eq!(votes(&mut rx), (0, 0), "no vote after the fatal fault");
    assert!(!engine.is_current_leader() && !engine.is_leader_for_view(engine.current_view() + 1));
}

#[test]
fn a_vote_log_fatal_threshold_of_zero_is_never_fatal() {
    let log = Arc::new(Switchable::default());
    let (mut engine, mut rx) = follower_with(Arc::clone(&log));
    engine.set_vote_log_fatal_after(0);
    let hash = B256::repeat_byte(0x92);
    log.fail.store(true, Ordering::SeqCst);
    for _ in 0..10 {
        assert!(matches!(engine.send_vote(1, hash), Err(ConsensusError::VoteLogFsync(_))));
    }
    assert_eq!(engine.vote_log_failures_in_a_row(), 10);
    assert_eq!(engine.voting_halted(), None);
    log.fail.store(false, Ordering::SeqCst);
    engine.send_vote(1, hash).expect("still voting");
    assert_eq!(votes(&mut rx), (1, 0));
}

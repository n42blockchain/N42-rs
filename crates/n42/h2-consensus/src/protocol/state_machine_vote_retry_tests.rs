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

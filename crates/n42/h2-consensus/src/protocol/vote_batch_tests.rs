// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests of batched vote verification (`N42_VOTE_AGGREGATE_VERIFY`).

use alloy_primitives::{Address, B256};
use n42_h2_primitives::{
    BlsSecretKey,
    consensus::{CommitVote, ConsensusMessage, H2V4ChainIdentity, Vote},
};
use tokio::sync::mpsc;

use crate::protocol::quorum::{commit_signing_message, signing_message};
use crate::protocol::state_machine::{ConsensusEngine, ConsensusEvent, EngineOutput};
use crate::ValidatorInfo;
use crate::validator::ValidatorSet;

const N: usize = 21;
const LEADER: u32 = 1;
const VIEW: u64 = 1;

fn keys() -> Vec<BlsSecretKey> {
    (0..N)
        .map(|i| BlsSecretKey::key_gen(&[0x40 + i as u8; 32]).expect("test key"))
        .collect()
}

fn engine(sks: &[BlsSecretKey], me: u32, batched: bool) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo {
            address: Address::with_last_byte(i as u8),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let f = (N as u32 - 1) / 3;
    let set = ValidatorSet::new(&infos, f);
    let (tx, rx) = mpsc::channel(4096);
    let mut engine = ConsensusEngine::new(me, sks[me as usize].clone(), set, 60_000, 120_000, tx);
    engine.set_vote_aggregate(batched);
    (engine, rx)
}

fn vote(sks: &[BlsSecretKey], voter: u32, block_hash: B256) -> ConsensusMessage {
    ConsensusMessage::Vote(Vote {
        view: VIEW,
        block_hash,
        voter,
        signature: sks[voter as usize].sign(&signing_message(VIEW, &block_hash)),
    })
}

fn commit_vote(sks: &[BlsSecretKey], voter: u32, block_hash: B256) -> ConsensusMessage {
    ConsensusMessage::CommitVote(CommitVote {
        view: VIEW,
        block_hash,
        voter,
        signature: sks[voter as usize].sign(&commit_signing_message(VIEW, &block_hash, &B256::ZERO)),
    })
}

fn others() -> impl Iterator<Item = u32> {
    (0..N as u32).filter(|i| *i != LEADER)
}

fn feed(engine: &mut ConsensusEngine, message: ConsensusMessage) {
    if let Some(message) = engine.queue_vote(message) {
        let _ = engine.process_event(ConsensusEvent::Message(message));
    }
}

/// The gov5 wire bytes of every broadcast PrepareQC and Decide.
fn broadcast_bytes(rx: &mut mpsc::Receiver<EngineOutput>) -> Vec<Vec<u8>> {
    let identity = H2V4ChainIdentity {
        chain_id: 94,
        genesis_hash: B256::repeat_byte(0x94),
    };
    let mut out = Vec::new();
    while let Ok(output) = rx.try_recv() {
        if let EngineOutput::BroadcastMessage(message) = output
            && matches!(message, ConsensusMessage::PrepareQC(_) | ConsensusMessage::Decide(_))
        {
            let envelope = crate::wire_bridge::to_wire(&message, identity, B256::ZERO).expect("to wire");
            out.push(n42_h2_wire::h2_v4::encode_envelope(&envelope).expect("encode"));
        }
    }
    out
}

fn leader_ready(sks: &[BlsSecretKey], batched: bool, block_hash: B256) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
    let (mut engine, mut rx) = engine(sks, LEADER, batched);
    engine
        .process_event(ConsensusEvent::BlockReady(block_hash, None))
        .expect("block ready");
    while rx.try_recv().is_ok() {}
    (engine, rx)
}

/// Batched and one-by-one verification accept the same votes and put the
/// same PrepareQC and Decide on the wire, byte for byte.
#[test]
fn batched_equals_sequential_on_valid_votes_and_the_wire_bytes_match() {
    let sks = keys();
    let block_hash = B256::repeat_byte(0xA1);
    let (mut sequential, mut seq_rx) = leader_ready(&sks, false, block_hash);
    let (mut batched, mut batch_rx) = leader_ready(&sks, true, block_hash);

    for voter in others() {
        feed(&mut sequential, vote(&sks, voter, block_hash));
        feed(&mut batched, vote(&sks, voter, block_hash));
    }
    batched.flush_votes().expect("flush r1");
    for voter in others() {
        feed(&mut sequential, commit_vote(&sks, voter, block_hash));
        feed(&mut batched, commit_vote(&sks, voter, block_hash));
    }
    batched.flush_votes().expect("flush r2");

    assert_eq!(sequential.current_view(), 2);
    assert_eq!(batched.current_view(), 2);
    let seq_bytes = broadcast_bytes(&mut seq_rx);
    let batch_bytes = broadcast_bytes(&mut batch_rx);
    assert_eq!(seq_bytes.len(), 2, "a PrepareQC and a Decide");
    assert_eq!(seq_bytes, batch_bytes, "the wire bytes are untouched");

    let seq_timing = sequential.last_committed_view_timing().expect("timing").clone();
    let batch_timing = batched.last_committed_view_timing().expect("timing").clone();
    assert_eq!(seq_timing.verify_batches, 0);
    assert!(seq_timing.verify_n >= 2 * 14, "one by one: {}", seq_timing.verify_n);
    assert_eq!(batch_timing.verify_batches, 2, "one batch a round");
    assert_eq!(batch_timing.verify_fallbacks, 0);
    // The ledger agrees once the post-quorum votes are settled (here all
    // twenty were verified in the one batch that reached the quorum).
    batched.settle_voters_seen(VIEW, None);
    assert_eq!(batched.voters_seen(VIEW), sequential.voters_seen(VIEW));
}

/// One bad vote among twenty: the batch falls back, the bad one is
/// rejected, the nineteen others are accepted and the QC forms.
#[test]
fn one_bad_vote_in_twenty_is_rejected_and_nineteen_accepted() {
    let sks = keys();
    let block_hash = B256::repeat_byte(0xA2);
    let (mut leader, mut rx) = leader_ready(&sks, true, block_hash);
    for voter in others() {
        let message = if voter == 7 {
            ConsensusMessage::Vote(Vote {
                view: VIEW,
                block_hash,
                voter,
                signature: sks[7].sign(b"not the vote message"),
            })
        } else {
            vote(&sks, voter, block_hash)
        };
        feed(&mut leader, message);
    }
    assert_eq!(leader.queued_votes(), 20);
    leader.flush_votes().expect("flush");
    assert_eq!(leader.queued_votes(), 0);
    assert_eq!(leader.voters_seen(VIEW), 20, "the leader and nineteen voters");
    assert_eq!(leader.voter_last_seen(7), None, "the bad vote is not counted");
    assert_eq!(broadcast_bytes(&mut rx).len(), 1, "the PrepareQC formed");
    let timing = &leader.view_timing;
    assert_eq!(timing.verify_batches, 1);
    assert_eq!(timing.verify_fallbacks, 1);
    assert_eq!(timing.verify_n, 20);
}

/// Votes are held until the collector could reach its quorum with them,
/// then verified as one batch.
#[test]
fn votes_wait_until_the_quorum_is_reachable() {
    let sks = keys();
    let block_hash = B256::repeat_byte(0xA3);
    let (mut leader, mut rx) = leader_ready(&sks, true, block_hash);
    // Quorum is 15; the leader's own vote is one.
    let voters: Vec<u32> = others().collect();
    for voter in &voters[..10] {
        feed(&mut leader, vote(&sks, *voter, block_hash));
    }
    leader.flush_votes().expect("flush");
    assert_eq!(leader.view_timing.verify_n, 0, "11 of 15: nothing verified yet");
    assert_eq!(leader.queued_votes(), 10);
    for voter in &voters[10..14] {
        feed(&mut leader, vote(&sks, *voter, block_hash));
    }
    leader.flush_votes().expect("flush");
    assert_eq!(leader.view_timing.verify_batches, 1);
    assert_eq!(leader.view_timing.verify_n, 14);
    assert_eq!(broadcast_bytes(&mut rx).len(), 1, "the PrepareQC formed");
}

/// Votes after the PrepareQC cost nothing until the ledger asks, and then
/// only the ones it asks for are verified.
#[test]
fn post_quorum_votes_are_parked_and_settled_on_demand() {
    let sks = keys();
    let block_hash = B256::repeat_byte(0xA4);
    let (mut leader, _rx) = leader_ready(&sks, true, block_hash);
    let voters: Vec<u32> = others().collect();
    for voter in &voters[..14] {
        feed(&mut leader, vote(&sks, *voter, block_hash));
    }
    leader.flush_votes().expect("flush");
    let verified = leader.view_timing.verify_n;
    assert_eq!(leader.voters_seen(VIEW), 15);
    for voter in &voters[14..] {
        feed(&mut leader, vote(&sks, *voter, block_hash));
    }
    leader.flush_votes().expect("flush");
    assert_eq!(leader.view_timing.verify_n, verified, "post-quorum votes are not verified");
    assert_eq!(leader.voters_seen(VIEW), 15);
    let last = *voters.last().expect("voters");
    leader.settle_voters_seen(VIEW, Some(&[last]));
    assert_eq!(leader.voters_seen(VIEW), 16, "only the one asked for");
    assert_eq!(leader.voter_last_seen(last), Some(VIEW));
    leader.settle_voters_seen(VIEW, None);
    assert_eq!(leader.voters_seen(VIEW), N);
}

/// A progress vote for a view the leader has left is parked and settles
/// under the progress message.
#[test]
fn late_progress_votes_settle_under_their_own_message() {
    let sks = keys();
    let block_hash = B256::repeat_byte(0xA5);
    let (mut leader, _rx) = leader_ready(&sks, true, block_hash);
    leader.set_progress_votes(true);
    let voters: Vec<u32> = others().collect();
    for voter in &voters[..14] {
        feed(&mut leader, vote(&sks, *voter, block_hash));
    }
    leader.flush_votes().expect("flush");
    for voter in &voters[..14] {
        feed(&mut leader, commit_vote(&sks, *voter, block_hash));
    }
    leader.flush_votes().expect("flush");
    assert_eq!(leader.current_view(), 2);
    let late = voters[19];
    let progress = leader
        .signing_profile
        .progress_vote_message(VIEW, block_hash);
    let message = ConsensusMessage::Vote(Vote {
        view: VIEW,
        block_hash,
        voter: late,
        signature: sks[late as usize].sign(&progress),
    });
    assert!(leader.queue_vote(message).is_none(), "parked, not processed");
    assert_eq!(leader.voter_last_seen(late), None);
    leader.settle_voters_seen(VIEW, None);
    assert_eq!(leader.voter_last_seen(late), Some(VIEW));
}

/// A follower drops votes unverified; a vote for a voter already counted is
/// dropped before any check; both paths are off when the switch is.
#[test]
fn followers_duplicates_and_the_switch() {
    let sks = keys();
    let block_hash = B256::repeat_byte(0xA6);
    let (mut follower, _rx) = engine(&sks, 0, true);
    assert!(follower.queue_vote(vote(&sks, 2, block_hash)).is_none());
    assert_eq!(follower.queued_votes(), 0);

    let (mut leader, _rx) = leader_ready(&sks, true, block_hash);
    // The leader's own vote is in the collector: a vote "from" it is dropped.
    let forged = ConsensusMessage::Vote(Vote {
        view: VIEW,
        block_hash,
        voter: LEADER,
        signature: sks[3].sign(b"forged"),
    });
    assert!(leader.queue_vote(forged).is_none());
    assert_eq!(leader.queued_votes(), 0);

    let (mut off, _rx) = leader_ready(&sks, false, block_hash);
    assert!(off.queue_vote(vote(&sks, 2, block_hash)).is_some(), "off: handed back");
}

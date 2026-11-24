// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The engine's half of the profile-1 vote rules
//! (`docs/MIXED_PRODUCTION_STANDARD.md` A13, E6-E9, AM19, AM23;
//! [`crate::VoteRules`]): Round 1 only on the execution layer's check or the
//! import, never on a header alone or optimistically; the CommitVote only on
//! this node's own import; no progress votes either way; and the two safety
//! rules AM19 states, as the code implements them -- the lock and the
//! proposal after a timeout certificate.

use super::*;
use crate::protocol::quorum::VoteCollector;
use crate::{ValidatorInfo, VoteRules};
use alloy_primitives::Address;
use n42_h2_primitives::consensus::{PrepareQC, Proposal, TimeoutMessage, Vote};

type Keys = Vec<n42_h2_primitives::BlsSecretKey>;

fn key(seed: u8) -> n42_h2_primitives::BlsSecretKey {
    n42_h2_primitives::BlsSecretKey::key_gen(&[seed; 32]).expect("a valid deterministic key")
}

/// Four validators; this engine is `me`, signs under H2-v4 when `h2`, and
/// runs `rules`.
fn engine(me: u32, h2: bool, rules: VoteRules) -> (ConsensusEngine, Keys, ValidatorSet, mpsc::Receiver<EngineOutput>) {
    let sks: Keys = (0..4).map(|i| key(0x90 + i as u8)).collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo {
            address: Address::with_last_byte(i as u8),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let vs = ValidatorSet::new(&infos, 1);
    let (tx, rx) = mpsc::channel(1024);
    let mut engine = ConsensusEngine::new(me, sks[me as usize].clone(), vs.clone(), 60_000, 120_000, tx);
    if h2 {
        engine.enable_h2_v4_signing(H2V4ChainIdentity { chain_id: 1144, genesis_hash: B256::repeat_byte(0x44) });
    }
    engine.set_vote_rules(rules);
    (engine, sks, vs, rx)
}

/// A validator that does not lead `views` (leaders rotate with tenure 1).
fn follower_of(views: &[u64]) -> u32 {
    let (probe, ..) = engine(0, true, VoteRules::TODAY);
    let leaders: Vec<u32> = views.iter().map(|v| probe.leader_index_for_view(*v)).collect();
    (0..4).find(|i| !leaders.contains(i)).expect("a follower")
}

/// A prepare-domain QC for `(view, block)` signed by three validators.
fn prepare_qc(engine: &ConsensusEngine, sks: &Keys, vs: &ValidatorSet, view: u64, block: B256) -> QuorumCertificate {
    let message = engine.signing_profile.vote_message(view, block);
    let mut collector = VoteCollector::new(view, block, vs.len());
    for i in 0..3u32 {
        collector.add_vote(i, engine.signing_profile.sign(&sks[i as usize], &message)).expect("a vote");
    }
    collector.build_qc_with_profile_message(vs, &message, engine.signing_profile).expect("a QC")
}

fn proposal(engine: &ConsensusEngine, sks: &Keys, view: u64, block: B256, justify: QuorumCertificate) -> Proposal {
    let proposer = engine.leader_index_for_view(view);
    let message = engine.signing_profile.proposal_message(view, block, &None);
    Proposal {
        view,
        block_hash: block,
        justify_qc: justify,
        proposer,
        signature: engine.signing_profile.sign(&sks[proposer as usize], &message),
        prepare_qc: None,
        tx_root_hash: None,
        validator_changes: None,
    }
}

fn propose(engine: &mut ConsensusEngine, sks: &Keys, view: u64, block: B256, justify: QuorumCertificate) -> ConsensusResult<()> {
    let p = proposal(engine, sks, view, block, justify);
    engine.process_event(ConsensusEvent::Message(ConsensusMessage::Proposal(p)))
}

fn outputs(rx: &mut mpsc::Receiver<EngineOutput>) -> Vec<EngineOutput> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn votes_for(out: &[EngineOutput], block: B256) -> usize {
    out.iter()
        .filter(|o| matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::Vote(v)) if v.block_hash == block))
        .count()
}

fn commit_votes(out: &[EngineOutput]) -> usize {
    out.iter().filter(|o| matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::CommitVote(_)))).count()
}

/// AM19 / AM23: under gov5's two-phase gate today a known header releases
/// Round 1; under profile 1 it does not, nor does a rejection (the execution
/// layer refused the deferred check: wrong carried fields or a transaction
/// not includable). Only the check (or the import) does.
#[test]
fn profile1_round1_waits_for_the_check_never_the_header() {
    let block = B256::repeat_byte(0xA1);
    let parent = B256::repeat_byte(0x01);
    let me = follower_of(&[1]);

    // The header alone, then a rejection: no vote.
    let (mut e, sks, _, mut rx) = engine(me, true, VoteRules::PROFILE1);
    e.set_two_phase_vote_gate(true);
    propose(&mut e, &sks, 1, block, QuorumCertificate::genesis()).expect("the proposal");
    e.header_known(block, parent).expect("the header");
    assert_eq!(votes_for(&outputs(&mut rx), block), 0, "no Round 1 on the header alone");
    e.process_event(ConsensusEvent::BlockRejected(block)).expect("the rejection");
    assert_eq!(votes_for(&outputs(&mut rx), block), 0, "no Round 1 on a block whose check failed");
    assert_eq!(e.last_voted_view(), 0);

    // The check: the vote.
    let (mut e, sks, _, mut rx) = engine(me, true, VoteRules::PROFILE1);
    e.set_two_phase_vote_gate(true);
    propose(&mut e, &sks, 1, block, QuorumCertificate::genesis()).expect("the proposal");
    e.header_known(block, parent).expect("the header");
    e.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
    assert_eq!(votes_for(&outputs(&mut rx), block), 1, "Round 1 on the check");

    // Today's rules under the gate, for contrast: the header votes.
    let (mut e, sks, _, mut rx) = engine(me, true, VoteRules::TODAY);
    e.set_two_phase_vote_gate(true);
    propose(&mut e, &sks, 1, block, QuorumCertificate::genesis()).expect("the proposal");
    e.header_known(block, parent).expect("the header");
    assert_eq!(votes_for(&outputs(&mut rx), block), 1, "today: the header votes under the gate");
}

/// E8: the optimistic road (native signing) and `N42_VOTE_BEFORE_IMPORT`
/// are closed under profile 1.
#[test]
fn profile1_closes_the_optimistic_vote() {
    let block = B256::repeat_byte(0xA2);
    let me = follower_of(&[1]);
    for (h2, before_import) in [(false, false), (true, true)] {
        let (mut today, sks, _, mut rx) = engine(me, h2, VoteRules::TODAY);
        today.set_vote_before_import(before_import);
        propose(&mut today, &sks, 1, block, QuorumCertificate::genesis()).expect("the proposal");
        assert_eq!(votes_for(&outputs(&mut rx), block), 1, "today (h2 {h2}): voted at once");

        let (mut e, sks, _, mut rx) = engine(me, h2, VoteRules::PROFILE1);
        e.set_vote_before_import(before_import);
        propose(&mut e, &sks, 1, block, QuorumCertificate::genesis()).expect("the proposal");
        assert_eq!(votes_for(&outputs(&mut rx), block), 0, "profile 1 (h2 {h2}): no vote before the check");
        e.remember_parent(block, B256::repeat_byte(0x01));
        e.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
        assert_eq!(votes_for(&outputs(&mut rx), block), 1, "profile 1 (h2 {h2}): the check votes");
    }
}

/// A13 / AM19: the CommitVote attests this node's own execution of the
/// block. Under profile 1 a PrepareQC holds it, a check does not release it,
/// the import does -- with or without the two-phase gate. (Today under the
/// gate a check releases it: on a deferred chain that is a CommitVote before
/// the block executed here.)
#[test]
fn profile1_commit_vote_waits_for_the_own_import_not_the_check() {
    let block = B256::repeat_byte(0xA3);
    let me = follower_of(&[1]);
    for gate in [false, true] {
        let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::PROFILE1);
        e.set_two_phase_vote_gate(gate);
        let qc = prepare_qc(&e, &sks, &vs, 1, block);
        e.process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: block, qc })))
            .expect("the PrepareQC");
        assert_eq!(commit_votes(&outputs(&mut rx)), 0, "gate {gate}: held");
        e.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
        assert_eq!(commit_votes(&outputs(&mut rx)), 0, "gate {gate}: a check is not an execution");
        e.process_event(ConsensusEvent::BlockImported(block)).expect("the import");
        assert_eq!(commit_votes(&outputs(&mut rx)), 1, "gate {gate}: the import releases it");
    }
    // Imported before the PrepareQC: the commit vote goes at once.
    let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::PROFILE1);
    e.process_event(ConsensusEvent::BlockImported(block)).expect("the import");
    let qc = prepare_qc(&e, &sks, &vs, 1, block);
    e.process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: block, qc })))
        .expect("the PrepareQC");
    assert_eq!(commit_votes(&outputs(&mut rx)), 1);

    // Today, under the gate: the check releases it.
    let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::TODAY);
    e.set_two_phase_vote_gate(true);
    let qc = prepare_qc(&e, &sks, &vs, 1, block);
    e.process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: block, qc })))
        .expect("the PrepareQC");
    e.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
    assert_eq!(commit_votes(&outputs(&mut rx)), 1, "today: the check releases the commit vote");
}

/// E9: a block imported after its view passed sends a progress vote today
/// (under the stragglers' grace); under profile 1 none, whichever order the
/// switches are set in.
#[test]
fn profile1_emits_no_progress_vote() {
    let block = B256::repeat_byte(0xA4);
    let me = follower_of(&[1]);
    for (rules, rules_last) in [(VoteRules::TODAY, false), (VoteRules::PROFILE1, false), (VoteRules::PROFILE1, true)] {
        let (mut e, sks, _, mut rx) = engine(me, true, if rules_last { VoteRules::TODAY } else { rules });
        e.set_progress_votes(true);
        if rules_last {
            e.set_vote_rules(rules);
        }
        propose(&mut e, &sks, 1, block, QuorumCertificate::genesis()).expect("the proposal");
        e.advance_to_view(2).expect("the view passes unvoted");
        let _ = outputs(&mut rx);
        e.remember_parent(block, B256::repeat_byte(0x01));
        e.process_event(ConsensusEvent::BlockImported(block)).expect("the late import");
        let sent = outputs(&mut rx);
        let progress = sent.iter().any(|o| {
            matches!(o, EngineOutput::SendToValidator(_, ConsensusMessage::Vote(v)) if v.view == 1 && v.block_hash == block)
        });
        assert_eq!(progress, !rules.profile1, "{rules:?} (rules set last: {rules_last})");
    }
}

/// E9: a leader under profile 1 does not read a progress vote into its
/// voters ledger; a late real vote still counts.
#[test]
fn profile1_ignores_a_received_progress_vote() {
    let block = B256::repeat_byte(0xA5);
    for rules in [VoteRules::TODAY, VoteRules::PROFILE1] {
        let (probe, ..) = engine(0, true, rules);
        let leader = probe.leader_index_for_view(1);
        let (mut e, sks, _, mut rx) = engine(leader, true, rules);
        e.process_event(ConsensusEvent::BlockReady(block, None)).expect("the leader's block");
        assert_eq!(e.voters_seen(1), 1, "its own vote");
        e.advance_to_view(2).expect("the view passes");
        let _ = outputs(&mut rx);
        let others: Vec<u32> = (0..4).filter(|i| *i != leader).collect();
        let progress = e.signing_profile.progress_vote_message(1, block);
        let late = Vote { view: 1, block_hash: block, voter: others[0], signature: e.signing_profile.sign(&sks[others[0] as usize], &progress) };
        let _ = e.process_event(ConsensusEvent::Message(ConsensusMessage::Vote(late)));
        assert_eq!(e.voters_seen(1), if rules.profile1 { 1 } else { 2 }, "{rules:?}: the progress vote");
        let real = e.signing_profile.vote_message(1, block);
        let slow = Vote { view: 1, block_hash: block, voter: others[1], signature: e.signing_profile.sign(&sks[others[1] as usize], &real) };
        let _ = e.process_event(ConsensusEvent::Message(ConsensusMessage::Vote(slow)));
        assert_eq!(e.voters_seen(1), if rules.profile1 { 2 } else { 3 }, "{rules:?}: a slow real vote");
    }
}

/// AM19's lock rule as the code states it (`RoundState::is_safe_to_vote`,
/// `update_locked_qc`, `extends_justify`): a node locks on the highest QC it
/// has seen (here a PrepareQC of view 1); a proposal whose justification is
/// below the lock is refused; one whose justification is higher is taken, the
/// lock moves to it, and the vote (after the check) requires the block to be
/// a child of the justification's block.
#[test]
fn the_lock_refuses_a_lower_justification_and_follows_a_higher_one() {
    let me = follower_of(&[1, 3, 4]);
    let (a, b, c) = (B256::repeat_byte(0xB1), B256::repeat_byte(0xB3), B256::repeat_byte(0xB4));
    let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::PROFILE1);
    let qc1 = prepare_qc(&e, &sks, &vs, 1, a);
    e.process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: a, qc: qc1 })))
        .expect("the PrepareQC");
    assert_eq!(e.locked_qc().view, 1, "locked on the PrepareQC");

    e.advance_to_view(3).expect("view 3");
    let refused = propose(&mut e, &sks, 3, B256::repeat_byte(0xBB), QuorumCertificate::genesis());
    assert!(matches!(refused, Err(ConsensusError::SafetyViolation { qc_view: 0, locked_view: 1 })), "{refused:?}");
    assert_eq!(e.locked_qc().view, 1);

    e.advance_to_view(4).expect("view 4");
    let _ = outputs(&mut rx);
    let qc3 = prepare_qc(&e, &sks, &vs, 3, b);
    propose(&mut e, &sks, 4, c, qc3).expect("a higher justification is taken");
    assert_eq!((e.locked_qc().view, e.locked_qc().block_hash), (3, b), "the lock moved to it");
    // Checked, but not a child of the justification's block: no vote.
    e.remember_parent(c, B256::repeat_byte(0xEE));
    e.process_event(ConsensusEvent::BlockChecked(c)).expect("the check");
    assert_eq!(votes_for(&outputs(&mut rx), c), 0, "the extends rule");
    // A child of it: the vote.
    e.remember_parent(c, b);
    e.process_event(ConsensusEvent::BlockChecked(c)).expect("the check");
    assert_eq!(votes_for(&outputs(&mut rx), c), 1);
}

fn timeout(engine: &ConsensusEngine, sks: &Keys, view: u64, sender: u32, high_qc: QuorumCertificate) -> ConsensusEvent {
    let message = engine.signing_profile.timeout_message(view);
    ConsensusEvent::Message(ConsensusMessage::Timeout(TimeoutMessage {
        view,
        high_qc,
        sender,
        signature: engine.signing_profile.sign(&sks[sender as usize], &message),
    }))
}

fn proposed_justify(out: &[EngineOutput]) -> Option<(u64, B256)> {
    out.iter().find_map(|o| match o {
        EngineOutput::BroadcastMessage(ConsensusMessage::Proposal(p)) => Some((p.justify_qc.view, p.justify_qc.block_hash)),
        _ => None,
    })
}

/// AM19: a leader entering a view by a timeout certificate proposes on the
/// highest QC the certificate carries. The code (`advance_with_tc`:
/// `update_locked_qc(&tc.high_qc)`; `on_block_ready`: justify = the lock)
/// proposes on the higher of that QC and its own lock -- the same QC when
/// the leader holds nothing higher, its own lock when it does (second half).
#[test]
fn after_a_tc_the_leader_proposes_on_the_highest_qc() {
    let (probe, ..) = engine(0, true, VoteRules::TODAY);
    let me = probe.leader_index_for_view(probe.view_after_tc(1));
    let x = B256::repeat_byte(0xC1);
    let others: Vec<u32> = (0..4).filter(|i| *i != me).collect();

    // The TC carries the view-1 QC; the leader held only genesis.
    let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::PROFILE1);
    let qc1 = prepare_qc(&e, &sks, &vs, 1, x);
    let highs = [QuorumCertificate::genesis(), qc1.clone(), QuorumCertificate::genesis()];
    for (sender, high) in others.iter().zip(highs) {
        e.process_event(timeout(&e, &sks, 1, *sender, high)).expect("a timeout");
    }
    assert_eq!(e.current_view(), 2, "the TC moved the leader on");
    let _ = outputs(&mut rx);
    e.process_event(ConsensusEvent::BlockReady(B256::repeat_byte(0xC2), None)).expect("the block");
    assert_eq!(proposed_justify(&outputs(&mut rx)), Some((1, x)), "justified by the TC's highest QC");

    // The leader's own lock is above every QC in the TC: it proposes on its lock.
    let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::PROFILE1);
    let qc1 = prepare_qc(&e, &sks, &vs, 1, x);
    e.process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: x, qc: qc1 })))
        .expect("the PrepareQC");
    for sender in &others {
        e.process_event(timeout(&e, &sks, 1, *sender, QuorumCertificate::genesis())).expect("a timeout");
    }
    assert_eq!(e.current_view(), 2);
    let _ = outputs(&mut rx);
    e.process_event(ConsensusEvent::BlockReady(B256::repeat_byte(0xC3), None)).expect("the block");
    assert_eq!(proposed_justify(&outputs(&mut rx)), Some((1, x)), "its own, higher lock");
}

/// The first mixed profile-1 round (p1mixed-2): view 2's block 1 was refused
/// by everyone, a TC moved the fleet to view 3, and view 3's leader proposed
/// a block on that uncertified block 1 with the genesis QC as justify. Under
/// profile 1 a proposal justified by the genesis QC has to be a child of
/// genesis: the block on block 1 gets no vote, a child of genesis does.
#[test]
fn profile1_refuses_a_genesis_justified_block_that_does_not_extend_genesis() {
    let genesis = B256::repeat_byte(0x44);
    let uncertified = B256::repeat_byte(0xD1);
    let me = follower_of(&[3]);
    for (on_block_1, votes) in [(true, 0), (false, 1)] {
        let block = B256::repeat_byte(0xD3);
        let (mut e, sks, _, mut rx) = engine(me, true, VoteRules::PROFILE1);
        e.set_genesis_block(genesis);
        e.advance_to_view(3).expect("view 3");
        propose(&mut e, &sks, 3, block, QuorumCertificate::genesis()).expect("the proposal");
        e.remember_parent(block, if on_block_1 { uncertified } else { genesis });
        e.process_event(ConsensusEvent::BlockChecked(block)).expect("the check");
        e.process_event(ConsensusEvent::BlockImported(block)).expect("the import");
        assert_eq!(votes_for(&outputs(&mut rx), block), votes, "parent block 1: {on_block_1}");
    }

    // Today's rules keep passing a genesis justify (gov5 gates the rule on
    // profile 1 too).
    let block = B256::repeat_byte(0xD4);
    let (mut e, sks, _, mut rx) = engine(me, true, VoteRules::TODAY);
    e.set_genesis_block(genesis);
    e.advance_to_view(3).expect("view 3");
    propose(&mut e, &sks, 3, block, QuorumCertificate::genesis()).expect("the proposal");
    e.remember_parent(block, uncertified);
    e.process_event(ConsensusEvent::BlockImported(block)).expect("the import");
    assert_eq!(votes_for(&outputs(&mut rx), block), 1, "today: a genesis justify passes");
}

/// The leader's side of the same round: after a TC whose high QCs are all
/// genesis, the next proposal extends the genesis block -- whatever block 1
/// the node imported meanwhile -- and is justified by the genesis QC; once a
/// QC forms the parent is the block it certifies.
#[test]
fn after_a_genesis_tc_the_leader_builds_on_genesis() {
    let genesis = B256::repeat_byte(0x44);
    let (probe, ..) = engine(0, true, VoteRules::TODAY);
    let me = probe.leader_index_for_view(probe.view_after_tc(2));
    let others: Vec<u32> = (0..4).filter(|i| *i != me).collect();
    let (mut e, sks, vs, mut rx) = engine(me, true, VoteRules::PROFILE1);
    e.set_genesis_block(genesis);
    e.advance_to_view(2).expect("view 2");
    // Block 1 of view 2 imported here (the leader's own execution layer
    // holds it), never certified.
    let uncertified = B256::repeat_byte(0xD1);
    e.remember_parent(uncertified, genesis);
    e.process_event(ConsensusEvent::BlockImported(uncertified)).expect("the import");
    for sender in &others {
        e.process_event(timeout(&e, &sks, 2, *sender, QuorumCertificate::genesis())).expect("a timeout");
    }
    assert_eq!(e.current_view(), probe.view_after_tc(2), "the TC moved the leader on");
    assert_eq!(e.proposal_parent(), genesis, "the genesis QC certifies genesis, not block 1");
    let _ = outputs(&mut rx);
    e.process_event(ConsensusEvent::BlockReady(B256::repeat_byte(0xD3), None)).expect("the block");
    assert_eq!(proposed_justify(&outputs(&mut rx)), Some((0, B256::ZERO)), "justified by the genesis QC");

    // A certified block moves the parent to it.
    let x = B256::repeat_byte(0xD5);
    let (mut e, sks, vs, _rx) = engine(follower_of(&[1]), true, VoteRules::PROFILE1);
    e.set_genesis_block(genesis);
    let qc = prepare_qc(&e, &sks, &vs, 1, x);
    e.process_event(ConsensusEvent::Message(ConsensusMessage::PrepareQC(PrepareQC { view: 1, block_hash: x, qc })))
        .expect("the PrepareQC");
    assert_eq!(e.proposal_parent(), x, "the block the QC certifies");

    // Without a named genesis block the engine names none.
    let (e, ..) = engine(me, true, VoteRules::PROFILE1);
    assert_eq!(e.proposal_parent(), B256::ZERO);
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TEST ONLY: the second half of a deliberate equivocation
//! (`docs/P1_EQUIVOCATION_INJECTOR.md`).
//!
//! A mixed equivocation round needs a member that signs two conflicting
//! values in one view, with its real key, so that honest peers can prove the
//! fault (E15). The engine never does that on its own; the node's injector
//! (`n42_h2_node::test_equivocate`, off unless an environment variable and a
//! CLI flag are both given on a dev chain) takes a message this engine just
//! signed and asks for its twin here: the same message for another block,
//! signed again by this validator.
//!
//! The engine's own state is not touched: no vote log entry, no tracker, no
//! collector. The twin goes out and nothing in this node remembers it.

use alloy_primitives::{keccak256, B256};
use n42_h2_primitives::consensus::ConsensusMessage;

use super::state_machine::ConsensusEngine;

/// The domain the twin's block hash is derived under.
pub const TWIN_HASH_DOMAIN: &[u8] = b"n42-test-equivocate/1";

/// The block hash a twin names instead of `block_hash`:
/// `keccak256("n42-test-equivocate/1" || block_hash)`. Deterministic, so a
/// peer's log can be matched against the injector's, and never a real block.
pub fn twin_block_hash(block_hash: B256) -> B256 {
    let mut preimage = Vec::with_capacity(TWIN_HASH_DOMAIN.len() + 32);
    preimage.extend_from_slice(TWIN_HASH_DOMAIN);
    preimage.extend_from_slice(block_hash.as_slice());
    keccak256(preimage)
}

impl ConsensusEngine {
    /// TEST ONLY. `message`, which this validator signed, re-signed for
    /// [`twin_block_hash`] of its block: a Round-1 vote, a commit vote or a
    /// proposal. `None` for any other message and for one another validator
    /// signed (the engine signs only as itself).
    ///
    /// The commit vote's changes hash is zero: the twin names a block no
    /// peer holds, and a leader checks a commit vote for an unknown block
    /// against a zero changes hash. The proposal keeps its validator changes,
    /// which travel in the message.
    pub fn sign_equivocating_twin(&self, message: &ConsensusMessage) -> Option<ConsensusMessage> {
        let profile = self.signing_profile;
        match message {
            ConsensusMessage::Vote(vote) if vote.voter == self.my_index => {
                let mut twin = vote.clone();
                twin.block_hash = twin_block_hash(vote.block_hash);
                twin.signature = profile.sign(&self.secret_key, &profile.vote_message(twin.view, twin.block_hash));
                Some(ConsensusMessage::Vote(twin))
            }
            ConsensusMessage::CommitVote(vote) if vote.voter == self.my_index => {
                let mut twin = vote.clone();
                twin.block_hash = twin_block_hash(vote.block_hash);
                let signed = profile.commit_message(twin.view, twin.block_hash, B256::ZERO);
                twin.signature = profile.sign(&self.secret_key, &signed);
                Some(ConsensusMessage::CommitVote(twin))
            }
            ConsensusMessage::Proposal(proposal) if proposal.proposer == self.my_index => {
                let mut twin = proposal.clone();
                twin.block_hash = twin_block_hash(proposal.block_hash);
                let signed = profile.proposal_message(twin.view, twin.block_hash, &twin.validator_changes);
                twin.signature = profile.sign(&self.secret_key, &signed);
                Some(ConsensusMessage::Proposal(twin))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::state_machine::{ConsensusEvent, EngineOutput};
    use crate::{EquivocationKind, ValidatorInfo, ValidatorSet};
    use alloy_primitives::Address;
    use n42_h2_primitives::consensus::{CommitVote, H2V4ChainIdentity, Proposal, QuorumCertificate, Vote};
    use n42_h2_primitives::BlsSecretKey;
    use tokio::sync::mpsc;

    const N: usize = 4;

    fn keys() -> Vec<BlsSecretKey> {
        (0..N).map(|i| BlsSecretKey::key_gen(&[0x30 + i as u8; 32]).expect("key")).collect()
    }

    fn engine(index: u32, keys: &[BlsSecretKey]) -> (ConsensusEngine, mpsc::Receiver<EngineOutput>) {
        let infos: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| ValidatorInfo {
                address: Address::with_last_byte(i as u8),
                bls_public_key: sk.public_key(),
                p2p_peer_id: None,
            })
            .collect();
        let (tx, rx) = mpsc::channel(1024);
        let mut engine =
            ConsensusEngine::new(index, keys[index as usize].clone(), ValidatorSet::new(&infos, 1), 60_000, 120_000, tx);
        engine.enable_h2_v4_signing(H2V4ChainIdentity { chain_id: 1143, genesis_hash: B256::repeat_byte(0x42) });
        (engine, rx)
    }

    fn drain(rx: &mut mpsc::Receiver<EngineOutput>) -> Vec<EngineOutput> {
        let mut out = Vec::new();
        while let Ok(output) = rx.try_recv() {
            out.push(output);
        }
        out
    }

    /// The evidence a peer emits for `first` then its twin, verified.
    fn detected(outputs: &[EngineOutput], kind: EquivocationKind, profile: crate::protocol::quorum::ConsensusSigningProfile) -> (B256, B256) {
        outputs
            .iter()
            .find_map(|output| match output {
                EngineOutput::EquivocationDetected { hash1, hash2, evidence, .. } => {
                    assert_eq!(evidence.kind, kind);
                    assert!(evidence.verify(profile), "the pair must verify on its own");
                    Some((*hash1, *hash2))
                }
                _ => None,
            })
            .expect("equivocation detected")
    }

    #[test]
    fn twin_hash_is_deterministic_and_different() {
        let hash = B256::repeat_byte(7);
        assert_eq!(twin_block_hash(hash), twin_block_hash(hash));
        assert_ne!(twin_block_hash(hash), hash);
    }

    #[test]
    fn a_double_vote_and_a_double_commit_vote_are_proven_by_the_leader() {
        let keys = keys();
        // View 1's leader is validator 1; validator 2 equivocates.
        let (mut leader, mut rx) = engine(1, &keys);
        let (voter, _) = engine(2, &keys);
        let profile = leader.signing_profile();
        let hash = B256::repeat_byte(0xA1);

        let vote = Vote { view: 1, block_hash: hash, voter: 2, signature: profile.sign(&keys[2], &profile.vote_message(1, hash)) };
        let vote = ConsensusMessage::Vote(vote);
        let twin = voter.sign_equivocating_twin(&vote).expect("own vote");
        leader.process_event(ConsensusEvent::Message(vote)).expect("first vote");
        leader.process_event(ConsensusEvent::Message(twin)).expect("twin");
        assert_eq!(detected(&drain(&mut rx), EquivocationKind::Vote, profile), (hash, twin_block_hash(hash)));

        let signed = profile.commit_message(1, hash, B256::ZERO);
        let commit = ConsensusMessage::CommitVote(CommitVote { view: 1, block_hash: hash, voter: 2, signature: profile.sign(&keys[2], &signed) });
        let twin = voter.sign_equivocating_twin(&commit).expect("own commit vote");
        leader.process_event(ConsensusEvent::Message(commit)).expect("first commit vote");
        leader.process_event(ConsensusEvent::Message(twin)).expect("twin");
        assert_eq!(detected(&drain(&mut rx), EquivocationKind::CommitVote, profile), (hash, twin_block_hash(hash)));
    }

    #[test]
    fn a_double_commit_vote_after_the_view_closed_is_still_proven() {
        let keys = keys();
        let hash = B256::repeat_byte(0xC3);
        // Both orders across the boundary: the first counted in the view and
        // the twin late, and both late (outside the quorum).
        for first_in_view in [true, false] {
            let (mut leader, mut rx) = engine(1, &keys);
            let (voter, _) = engine(2, &keys);
            let profile = leader.signing_profile();
            let signed = profile.commit_message(1, hash, B256::ZERO);
            let commit = ConsensusMessage::CommitVote(CommitVote { view: 1, block_hash: hash, voter: 2, signature: profile.sign(&keys[2], &signed) });
            let twin = voter.sign_equivocating_twin(&commit).expect("own commit vote");
            if first_in_view {
                leader.process_event(ConsensusEvent::Message(commit.clone())).expect("in view");
            }
            leader.advance_to_view(2).expect("advance");
            drain(&mut rx);
            // A repeat of the first is not a conflict.
            let _ = leader.process_event(ConsensusEvent::Message(commit.clone()));
            let _ = leader.process_event(ConsensusEvent::Message(commit));
            assert!(!drain(&mut rx).iter().any(|o| matches!(o, EngineOutput::EquivocationDetected { .. })));
            let _ = leader.process_event(ConsensusEvent::Message(twin));
            assert_eq!(
                detected(&drain(&mut rx), EquivocationKind::CommitVote, profile),
                (hash, twin_block_hash(hash)),
                "first in view: {first_in_view}"
            );
        }
    }

    #[test]
    fn a_double_vote_after_the_view_closed_is_still_proven() {
        let keys = keys();
        let hash = B256::repeat_byte(0xD4);
        // First counted in the view and the twin late, or both late; on the
        // plain path and through the batch verifier's queue.
        for (first_in_view, batched) in [(true, false), (false, false), (true, true), (false, true)] {
            let (mut leader, mut rx) = engine(1, &keys);
            leader.set_vote_aggregate(batched);
            let (voter, _) = engine(2, &keys);
            let profile = leader.signing_profile();
            let vote = ConsensusMessage::Vote(Vote { view: 1, block_hash: hash, voter: 2, signature: profile.sign(&keys[2], &profile.vote_message(1, hash)) });
            let twin = voter.sign_equivocating_twin(&vote).expect("own vote");
            let deliver = |engine: &mut ConsensusEngine, message: ConsensusMessage| {
                let message = if batched { engine.queue_vote(message) } else { Some(message) };
                if let Some(message) = message {
                    let _ = engine.process_event(ConsensusEvent::Message(message));
                }
                let _ = engine.flush_votes();
            };
            if first_in_view {
                deliver(&mut leader, vote.clone());
            }
            leader.advance_to_view(2).expect("advance");
            drain(&mut rx);
            deliver(&mut leader, vote.clone());
            deliver(&mut leader, vote);
            assert!(!drain(&mut rx).iter().any(|o| matches!(o, EngineOutput::EquivocationDetected { .. })), "a repeat is no conflict");
            deliver(&mut leader, twin);
            assert_eq!(
                detected(&drain(&mut rx), EquivocationKind::Vote, profile),
                (hash, twin_block_hash(hash)),
                "first in view: {first_in_view}, batched: {batched}"
            );
        }
    }

    #[test]
    fn a_double_proposal_after_the_view_closed_is_still_proven() {
        let keys = keys();
        let hash = B256::repeat_byte(0xE5);
        for first_in_view in [true, false] {
            let (proposer, _) = engine(1, &keys);
            let (mut follower, mut rx) = engine(2, &keys);
            let profile = follower.signing_profile();
            let proposal = ConsensusMessage::Proposal(Proposal {
                view: 1,
                block_hash: hash,
                justify_qc: QuorumCertificate::genesis(),
                proposer: 1,
                signature: profile.sign(&keys[1], &profile.proposal_message(1, hash, &None)),
                prepare_qc: None,
                tx_root_hash: None,
                validator_changes: None,
            });
            let twin = proposer.sign_equivocating_twin(&proposal).expect("own proposal");
            if first_in_view {
                follower.process_event(ConsensusEvent::Message(proposal.clone())).expect("in view");
            }
            follower.advance_to_view(2).expect("advance");
            drain(&mut rx);
            let _ = follower.process_event(ConsensusEvent::Message(proposal.clone()));
            let _ = follower.process_event(ConsensusEvent::Message(proposal));
            assert!(!drain(&mut rx).iter().any(|o| matches!(o, EngineOutput::EquivocationDetected { .. })), "a repeat is no conflict");
            let _ = follower.process_event(ConsensusEvent::Message(twin));
            assert_eq!(
                detected(&drain(&mut rx), EquivocationKind::Proposal, profile),
                (hash, twin_block_hash(hash)),
                "first in view: {first_in_view}"
            );
        }
    }

    #[test]
    fn a_forged_late_first_gives_way_to_the_real_vote() {
        let keys = keys();
        let hash = B256::repeat_byte(0xF6);
        let (mut leader, mut rx) = engine(1, &keys);
        let profile = leader.signing_profile();
        leader.advance_to_view(2).expect("advance");
        // A forged commit vote for voter 2 arrives first, unverified.
        let forged = CommitVote { view: 1, block_hash: B256::repeat_byte(9), voter: 2, signature: profile.sign(&keys[3], &profile.commit_message(1, B256::repeat_byte(9), B256::ZERO)) };
        let _ = leader.process_event(ConsensusEvent::Message(ConsensusMessage::CommitVote(forged)));
        let real = CommitVote { view: 1, block_hash: hash, voter: 2, signature: profile.sign(&keys[2], &profile.commit_message(1, hash, B256::ZERO)) };
        let _ = leader.process_event(ConsensusEvent::Message(ConsensusMessage::CommitVote(real.clone())));
        assert!(!drain(&mut rx).iter().any(|o| matches!(o, EngineOutput::EquivocationDetected { .. })), "a forgery is no evidence");
        // The real one took the slot: its twin is proven.
        let (voter, _) = engine(2, &keys);
        let twin = voter.sign_equivocating_twin(&ConsensusMessage::CommitVote(real)).expect("own");
        let _ = leader.process_event(ConsensusEvent::Message(twin));
        assert_eq!(detected(&drain(&mut rx), EquivocationKind::CommitVote, profile), (hash, twin_block_hash(hash)));
    }

    #[test]
    fn a_double_proposal_is_proven_by_a_follower() {
        let keys = keys();
        let (proposer, _) = engine(1, &keys);
        let (mut follower, mut rx) = engine(2, &keys);
        let profile = follower.signing_profile();
        let hash = B256::repeat_byte(0xB2);
        let proposal = ConsensusMessage::Proposal(Proposal {
            view: 1,
            block_hash: hash,
            justify_qc: QuorumCertificate::genesis(),
            proposer: 1,
            signature: profile.sign(&keys[1], &profile.proposal_message(1, hash, &None)),
            prepare_qc: None,
            tx_root_hash: None,
            validator_changes: None,
        });
        let twin = proposer.sign_equivocating_twin(&proposal).expect("own proposal");
        follower.process_event(ConsensusEvent::Message(proposal)).expect("first proposal");
        follower.process_event(ConsensusEvent::Message(twin)).expect("twin");
        assert_eq!(detected(&drain(&mut rx), EquivocationKind::Proposal, profile), (hash, twin_block_hash(hash)));
    }

    #[test]
    fn the_engine_signs_no_twin_for_another_validator_or_another_kind() {
        let keys = keys();
        let (engine, _) = engine(2, &keys);
        let profile = engine.signing_profile();
        let hash = B256::repeat_byte(3);
        let foreign = ConsensusMessage::Vote(Vote { view: 1, block_hash: hash, voter: 3, signature: profile.sign(&keys[3], &profile.vote_message(1, hash)) });
        assert!(engine.sign_equivocating_twin(&foreign).is_none());
    }
}

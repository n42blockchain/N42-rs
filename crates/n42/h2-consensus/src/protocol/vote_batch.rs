// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batched vote verification for a leader (`N42_VOTE_AGGREGATE_VERIFY`).
//!
//! The default path verifies every Round 1 and Round 2 vote as it arrives,
//! one pairing check (~1.1 ms) each, including the votes that arrive after
//! the quorum and the late and progress votes the voters ledger reads. With
//! `vote_aggregate` on, the orchestrator hands votes to [`ConsensusEngine::queue_vote`]
//! and calls [`ConsensusEngine::flush_votes`] at the end of each transport
//! drain:
//!
//! * votes of the current view are grouped by the exact message they sign
//!   (view, block hash, and for Round 2 the validator-changes hash) and a
//!   group is verified in one randomised same-message batch once the
//!   collector *could* reach its quorum with it (or the group is not for the
//!   collector's block, so it can only be equivocation evidence, which is
//!   verified at once as today);
//! * a failed batch falls back to verifying each member on its own, so a bad
//!   vote is rejected and the good ones kept. Every vote is verified on its
//!   own at most once and takes part in at most one batch, so a peer that
//!   poisons every batch brings the leader back to today's cost plus one
//!   batch per group and drain, never more;
//! * Round 1 votes that arrive after the PrepareQC, or after their view, are
//!   parked unverified: the protocol does not need them and the voters
//!   ledger only needs some of them, at proposal time
//!   ([`ConsensusEngine::settle_voters_seen`]);
//! * Round 2 votes after the CommitQC are dropped on the view mismatch, as
//!   today, unverified.
//!
//! Neither the wire nor what a vote attests changes: an accepted vote is one
//! whose own signature verifies (the batch's random weights make a passing
//! batch imply that of every member), and it enters the collector through
//! the same `process_verified_vote` / `process_verified_commit_vote` path the
//! engine's other batch verifier uses.

use alloy_primitives::B256;
use n42_h2_primitives::{
    BlsPublicKey, BlsSignature,
    consensus::{CommitVote, ConsensusMessage, ViewNumber, Vote},
};
use std::collections::HashSet;
use std::time::Instant;

use super::state_machine::{ConsensusEngine, VOTERS_SEEN_WINDOW};
use crate::error::ConsensusResult;

/// A Round 1 vote kept for the voters ledger without being verified.
#[derive(Debug, Clone)]
pub(crate) struct ParkedVote {
    pub(crate) vote: Vote,
    /// Arrived in its own view (after the PrepareQC): it can only be a real
    /// vote. Otherwise it is a late vote or a progress vote and either
    /// message may be the one signed.
    pub(crate) in_view: bool,
}

/// How many votes the queue holds, per validator in the set, before it is
/// verified regardless of the quorum rule: forged votes cannot grow it
/// without bound.
const QUEUE_PER_VALIDATOR: usize = 4;

/// Parked votes per view, per validator in the set.
const PARKED_PER_VALIDATOR: usize = 2;

impl ConsensusEngine {
    /// Turns batched vote verification on or off (`N42_VOTE_AGGREGATE_VERIFY`).
    pub fn set_vote_aggregate(&mut self, on: bool) {
        self.vote_aggregate = on;
    }

    /// Whether batched vote verification is on.
    pub const fn vote_aggregate(&self) -> bool {
        self.vote_aggregate
    }

    /// Votes waiting for their batch.
    pub fn queued_votes(&self) -> usize {
        self.vote_queue.len()
    }

    /// Takes a `Vote` or `CommitVote` for batched verification and returns
    /// `None`, or hands the message back for the ordinary `process_event`
    /// path: anything else, any message while batching is off, and votes for
    /// a future view (those are buffered by the ordinary path).
    pub fn queue_vote(&mut self, message: ConsensusMessage) -> Option<ConsensusMessage> {
        if !self.vote_aggregate {
            return Some(message);
        }
        let view = self.round_state.current_view();
        match message {
            ConsensusMessage::Vote(vote) => {
                if vote.view > view {
                    return Some(ConsensusMessage::Vote(vote));
                }
                if vote.view < view {
                    self.park_vote(vote, false);
                    return None;
                }
                // Followers drop votes unverified, as `process_vote` does.
                if !self.is_current_leader() {
                    return None;
                }
                let for_collector = self
                    .vote_collector
                    .as_ref()
                    .filter(|c| c.block_hash() == vote.block_hash);
                if let Some(collector) = for_collector {
                    if self.prepare_qc.is_some() {
                        // After the quorum: only the ledger wants it.
                        self.park_vote(vote, true);
                        return None;
                    }
                    if collector.has_vote_from(vote.voter) {
                        // A duplicate (multi-path delivery) or a forgery for a
                        // voter already counted: nothing it could add.
                        return None;
                    }
                }
                self.push_queued(ConsensusMessage::Vote(vote));
                None
            }
            ConsensusMessage::CommitVote(cv) => {
                if cv.view != view {
                    return Some(ConsensusMessage::CommitVote(cv));
                }
                if !self.is_current_leader() {
                    return None;
                }
                if self
                    .commit_collector
                    .as_ref()
                    .is_some_and(|c| c.block_hash() == cv.block_hash && c.has_vote_from(cv.voter))
                {
                    return None;
                }
                self.push_queued(ConsensusMessage::CommitVote(cv));
                None
            }
            other => Some(other),
        }
    }

    fn push_queued(&mut self, message: ConsensusMessage) {
        self.vote_queue.push(message);
        let cap = QUEUE_PER_VALIDATOR
            .saturating_mul(self.validator_count() as usize)
            .max(64);
        if self.vote_queue.len() > cap {
            if let Err(err) = self.flush_votes_inner(true) {
                tracing::debug!(target: "n42::cl::voting", %err, "vote batch over its cap");
            }
        }
    }

    /// Verifies the queued votes that are due (see the module docs) and
    /// processes the good ones; called by the orchestrator at the end of
    /// each transport drain. Votes whose group cannot reach the quorum yet
    /// stay queued for the next drain.
    pub fn flush_votes(&mut self) -> ConsensusResult<()> {
        self.flush_votes_inner(false)
    }

    fn flush_votes_inner(&mut self, force: bool) -> ConsensusResult<()> {
        if self.vote_queue.is_empty() {
            return Ok(());
        }
        let queued = std::mem::take(&mut self.vote_queue);
        let view = self.round_state.current_view();
        let leader = self.is_current_leader();

        // Group by signed message, in arrival order, dropping exact repeats.
        let mut seen: HashSet<(bool, u32, [u8; 96])> = HashSet::new();
        let mut r1: Vec<(B256, Vec<Vote>)> = Vec::new();
        let mut r2: Vec<(B256, Vec<CommitVote>)> = Vec::new();
        for message in queued {
            match message {
                ConsensusMessage::Vote(vote) => {
                    if vote.view != view {
                        // The view moved while it waited: a real vote of a
                        // past view, for the ledger only.
                        if vote.view < view {
                            self.park_vote(vote, true);
                        }
                        continue;
                    }
                    if !leader || !seen.insert((false, vote.voter, vote.signature.to_bytes())) {
                        continue;
                    }
                    match r1.iter_mut().find(|(hash, _)| *hash == vote.block_hash) {
                        Some((_, group)) => group.push(vote),
                        None => r1.push((vote.block_hash, vec![vote])),
                    }
                }
                ConsensusMessage::CommitVote(cv) => {
                    // A Round 2 vote of a past view is dropped, as today.
                    if cv.view != view
                        || !leader
                        || !seen.insert((true, cv.voter, cv.signature.to_bytes()))
                    {
                        continue;
                    }
                    match r2.iter_mut().find(|(hash, _)| *hash == cv.block_hash) {
                        Some((_, group)) => group.push(cv),
                        None => r2.push((cv.block_hash, vec![cv])),
                    }
                }
                _ => {}
            }
        }

        let mut held: Vec<ConsensusMessage> = Vec::new();
        for (block_hash, votes) in r1 {
            if self.round_state.current_view() != view {
                for vote in votes {
                    self.park_vote(vote, true);
                }
                continue;
            }
            let quorum = self.validator_set_for_view(view).quorum_size();
            let collector = self
                .vote_collector
                .as_ref()
                .filter(|c| c.block_hash() == block_hash);
            if let Some(collector) = collector {
                if self.prepare_qc.is_some() {
                    for vote in votes {
                        self.park_vote(vote, true);
                    }
                    continue;
                }
                let have = collector.vote_count();
                let fresh: HashSet<u32> = votes
                    .iter()
                    .map(|v| v.voter)
                    .filter(|voter| !collector.has_vote_from(*voter))
                    .collect();
                if fresh.is_empty() {
                    continue;
                }
                if !force && have + fresh.len() < quorum {
                    held.extend(votes.into_iter().map(ConsensusMessage::Vote));
                    continue;
                }
            }
            let message = self.signing_profile.vote_message(view, block_hash);
            let signers: Vec<(u32, &BlsSignature)> =
                votes.iter().map(|v| (v.voter, &v.signature)).collect();
            let good = self.verify_group(view, &message, &signers);
            for (vote, ok) in votes.into_iter().zip(good) {
                if !ok {
                    tracing::debug!(target: "n42::cl::voting", view, voter = vote.voter,
                        "vote signature verification failed (batch)");
                    continue;
                }
                if let Err(err) = self.process_verified_vote(vote) {
                    tracing::debug!(target: "n42::cl::voting", view, %err, "batched vote refused");
                }
            }
        }

        for (block_hash, votes) in r2 {
            // A Round 1 batch may have formed the CommitQC (with the
            // leader's own Round 2 vote) and moved the view on.
            if self.round_state.current_view() != view || !self.is_current_leader() {
                continue;
            }
            let quorum = self.validator_set_for_view(view).quorum_size();
            let collector = self
                .commit_collector
                .as_ref()
                .filter(|c| c.block_hash() == block_hash);
            if let Some(collector) = collector {
                let have = collector.vote_count();
                let fresh: HashSet<u32> = votes
                    .iter()
                    .map(|v| v.voter)
                    .filter(|voter| !collector.has_vote_from(*voter))
                    .collect();
                if fresh.is_empty() {
                    continue;
                }
                if !force && have + fresh.len() < quorum {
                    held.extend(votes.into_iter().map(ConsensusMessage::CommitVote));
                    continue;
                }
            }
            let changes_hash = self.cached_changes_hash(&block_hash);
            let message = self
                .signing_profile
                .commit_message(view, block_hash, changes_hash);
            let signers: Vec<(u32, &BlsSignature)> =
                votes.iter().map(|v| (v.voter, &v.signature)).collect();
            let good = self.verify_group(view, &message, &signers);
            for (cv, ok) in votes.into_iter().zip(good) {
                if !ok {
                    tracing::debug!(target: "n42::cl::voting", view, voter = cv.voter,
                        "commit vote signature verification failed (batch)");
                    continue;
                }
                if let Err(err) = self.process_verified_commit_vote(cv) {
                    tracing::debug!(target: "n42::cl::voting", view, %err, "batched commit vote refused");
                }
            }
        }

        // Anything queued while the good votes were processed stays behind
        // what was held.
        held.append(&mut self.vote_queue);
        self.vote_queue = held;
        Ok(())
    }

    /// Verifies `signers` over `message` (keys of `view`'s set) in one batch
    /// with the bounded fallback, records the cost in the view's timing and
    /// returns which positions verified.
    fn verify_group(
        &mut self,
        view: ViewNumber,
        message: &[u8],
        signers: &[(u32, &BlsSignature)],
    ) -> Vec<bool> {
        let started = Instant::now();
        let set = self.validator_set_for_view(view);
        // Unknown voters never reach the batch.
        let known: Vec<(usize, &BlsPublicKey, &BlsSignature)> = signers
            .iter()
            .enumerate()
            .filter_map(|(i, (voter, sig))| set.get_public_key(*voter).ok().map(|pk| (i, pk, *sig)))
            .collect();
        let mut good = vec![false; signers.len()];
        if known.is_empty() {
            return good;
        }
        let sigs: Vec<&BlsSignature> = known.iter().map(|(_, _, sig)| *sig).collect();
        let pks: Vec<&BlsPublicKey> = known.iter().map(|(_, pk, _)| *pk).collect();
        let outcome = self.signing_profile.verify_same_message(message, &sigs, &pks);
        let bad: HashSet<usize> = outcome.bad.iter().copied().collect();
        for (k, (i, _, _)) in known.iter().enumerate() {
            good[*i] = !bad.contains(&k);
        }
        let count = known.len();
        self.view_timing
            .note_verify(started, count, true, outcome.fell_back);
        good
    }

    /// Keeps a Round 1 vote for the voters ledger, unverified, if this node
    /// led its view recently and the voter is not already in the ledger.
    fn park_vote(&mut self, vote: Vote, in_view: bool) {
        let current = self.round_state.current_view();
        if !(vote.view <= current
            && current - vote.view <= VOTERS_SEEN_WINDOW as u64
            && self.is_leader_for_view(vote.view))
        {
            return;
        }
        if self
            .voters_seen
            .get(&vote.view)
            .is_some_and(|seen| seen.contains(&vote.voter))
        {
            return;
        }
        let cap = PARKED_PER_VALIDATOR.saturating_mul(self.validator_count() as usize);
        let parked = self.parked_votes.entry(vote.view).or_default();
        if parked.len() >= cap
            || parked
                .iter()
                .any(|p| p.vote.voter == vote.voter && p.vote.signature == vote.signature)
        {
            return;
        }
        parked.push(ParkedVote { vote, in_view });
        let oldest = current.saturating_sub(VOTERS_SEEN_WINDOW as u64);
        self.parked_votes.retain(|v, _| *v >= oldest);
    }

    /// Verifies the parked votes of `view` -- of every voter, or of `only` --
    /// and notes the good ones in the voters ledger (`voters_seen`). The
    /// straggler rule calls this before it reads the ledger; with batching
    /// off nothing is ever parked and this does nothing.
    ///
    /// Cost: one batch per signed message (the vote's, then the progress
    /// vote's for the late ones that failed it) plus the bounded fallback.
    pub fn settle_voters_seen(&mut self, view: ViewNumber, only: Option<&[u32]>) {
        let Some(parked) = self.parked_votes.get_mut(&view) else {
            return;
        };
        let (take, keep): (Vec<ParkedVote>, Vec<ParkedVote>) = std::mem::take(parked)
            .into_iter()
            .partition(|p| only.is_none_or(|voters| voters.contains(&p.vote.voter)));
        *parked = keep;
        if parked.is_empty() {
            self.parked_votes.remove(&view);
        }
        let take: Vec<ParkedVote> = take
            .into_iter()
            .filter(|p| {
                !self
                    .voters_seen
                    .get(&view)
                    .is_some_and(|seen| seen.contains(&p.vote.voter))
            })
            .collect();
        if take.is_empty() {
            return;
        }
        // A late vote is more likely a progress vote when progress votes are
        // on (that is what a follower sends after its import), so that
        // message is tried first for those.
        let mut pending: Vec<&ParkedVote> = take.iter().collect();
        let mut messages: Vec<(Vec<u8>, bool)> = Vec::with_capacity(2);
        let block_hashes: HashSet<B256> = take.iter().map(|p| p.vote.block_hash).collect();
        for block_hash in block_hashes {
            messages.clear();
            let vote_message = self.signing_profile.vote_message(view, block_hash);
            let progress_message = self.signing_profile.progress_vote_message(view, block_hash);
            if self.progress_votes {
                messages.push((progress_message, false));
                messages.push((vote_message, true));
            } else {
                messages.push((vote_message, true));
                messages.push((progress_message, false));
            }
            let mut left: Vec<&ParkedVote> = pending
                .iter()
                .copied()
                .filter(|p| p.vote.block_hash == block_hash)
                .collect();
            for (message, is_vote_message) in &messages {
                // A vote that arrived in its view signed the vote message.
                let (try_now, rest): (Vec<&ParkedVote>, Vec<&ParkedVote>) = left
                    .into_iter()
                    .partition(|p| *is_vote_message || !p.in_view);
                if try_now.is_empty() {
                    left = rest;
                    continue;
                }
                let signers: Vec<(u32, &BlsSignature)> =
                    try_now.iter().map(|p| (p.vote.voter, &p.vote.signature)).collect();
                let good = self.verify_group(view, message, &signers);
                left = rest;
                for (p, ok) in try_now.into_iter().zip(good) {
                    if ok {
                        self.note_voter(view, p.vote.voter);
                    } else {
                        left.push(p);
                    }
                }
                if left.is_empty() {
                    break;
                }
            }
            pending.retain(|p| p.vote.block_hash != block_hash);
        }
    }

    /// The most recent view in the ledger's window at which `voter`'s Round
    /// 1 vote (real or progress) was verified; `None` if it is in none.
    pub fn voter_last_seen(&self, voter: u32) -> Option<ViewNumber> {
        self.voters_seen
            .iter()
            .filter(|(_, voters)| voters.contains(&voter))
            .map(|(view, _)| *view)
            .max()
    }

    /// The leader of `view` under the chain's tenure.
    pub fn leader_of_view(&self, view: ViewNumber) -> u32 {
        self.leader_index_for_view(view)
    }

}

#[cfg(test)]
#[path = "vote_batch_tests.rs"]
mod tests;

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Equivocation evidence (mixed-production standard E15): the two
//! conflicting signed messages one validator produced in one view.
//!
//! Each side carries the exact bytes the validator signed and the signature,
//! so the pair verifies on its own against the validator's BLS key, which is
//! carried too. Evidence only: nothing here slashes or gossips.

use alloy_primitives::{Bytes, B256};
use n42_h2_primitives::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::quorum::ConsensusSigningProfile;

/// The consensus value a validator signed twice in one view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivocationKind {
    /// Two Round-1 votes.
    Vote,
    /// Two Round-2 commit votes (`commit_vote` in AM28; records written as
    /// `commitVote` before AM28 was pinned still load).
    #[serde(alias = "commitVote")]
    CommitVote,
    /// Two proposals.
    Proposal,
}

impl EquivocationKind {
    /// A short label (metric label, log field).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Vote => "vote",
            Self::CommitVote => "commit_vote",
            Self::Proposal => "proposal",
        }
    }
}

/// One signed message of an equivocating pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedValue {
    /// The block the message names. Not part of the AM28 JSON shape: the
    /// record's `hash1` / `hash2` carry it.
    #[serde(skip)]
    pub block_hash: B256,
    /// The exact bytes the validator signed (the signing profile's message),
    /// named `signed` in the AM28 JSON shape.
    #[serde(rename = "signed")]
    pub message: Bytes,
    /// The validator's BLS signature over `message` (96 bytes).
    pub signature: Bytes,
}

impl SignedValue {
    /// One side of a pair from the signed bytes and the signature.
    pub fn new(block_hash: B256, message: Vec<u8>, signature: &BlsSignature) -> Self {
        Self { block_hash, message: message.into(), signature: Bytes::copy_from_slice(&signature.to_bytes()) }
    }

    /// Whether `signature` verifies over `message` under `key` in `profile`'s ciphersuite.
    pub fn verify(&self, profile: ConsensusSigningProfile, key: &BlsPublicKey) -> bool {
        let Ok(bytes) = <[u8; 96]>::try_from(self.signature.as_ref()) else { return false };
        let Ok(signature) = BlsSignature::from_bytes(&bytes) else { return false };
        profile.verify_single(key, &self.message, &signature)
    }
}

/// Two conflicting signed messages by one validator in one view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivocationEvidence {
    /// What was signed twice.
    pub kind: EquivocationKind,
    /// The view both messages are for.
    pub view: u64,
    /// The validator's index in the view's set.
    pub validator: u32,
    /// The validator's BLS public key (48 bytes), against which both sides verify.
    pub public_key: Bytes,
    /// The message seen first.
    pub first: SignedValue,
    /// The conflicting message.
    pub second: SignedValue,
}

impl EquivocationEvidence {
    /// Whether both sides verify against the carried key in `profile`'s
    /// ciphersuite and differ.
    pub fn verify(&self, profile: ConsensusSigningProfile) -> bool {
        let Ok(bytes) = <[u8; 48]>::try_from(self.public_key.as_ref()) else { return false };
        let Ok(key) = BlsPublicKey::from_bytes(&bytes) else { return false };
        self.first.message != self.second.message
            && self.first.verify(profile, &key)
            && self.second.verify(profile, &key)
    }
}

/// What the engine tracks per validator per view: the first signed value it
/// authenticated, keyed by a commitment the conflict is judged on.
pub(super) type EquivocationTracker = HashMap<u32, (B256, SignedValue)>;

/// Records `commitment` for `voter` and returns the earlier signed value when
/// it differs. `make` builds the signed value; it runs only on the first
/// message of a voter (to be kept) or on a conflict (to be reported), never
/// for a repeat.
pub(super) fn check_equivocation(
    tracker: &mut EquivocationTracker,
    voter: u32,
    commitment: B256,
    make: impl FnOnce() -> SignedValue,
) -> Option<(SignedValue, SignedValue)> {
    match tracker.get(&voter) {
        Some((previous, _)) if *previous == commitment => None,
        Some((_, first)) => Some((first.clone(), make())),
        None => {
            tracker.insert(voter, (commitment, make()));
            None
        }
    }
}

/// How many views back a late vote, commit vote or proposal is still checked
/// for a conflict.
pub(super) const LATE_WINDOW: u64 = 8;

/// What [`LateTracker::check`] found for a message of a closed view.
#[derive(Debug)]
pub(super) enum LateCheck {
    /// The voter's message of that view already seen, again.
    Repeat,
    /// The voter's first message of that view: kept.
    Kept,
    /// A different message from the same voter in that view: the first, and
    /// whether its signature was checked when it was kept.
    Conflict { first: SignedValue, verified: bool },
}

/// One kind's evidence across the view boundary. The engine leaves a view
/// as soon as it is decided, so a message outside the quorum (or the second
/// of a conflicting pair, after the first was counted) arrives in a closed
/// view, where it used to be dropped unseen. Kept here for [`LATE_WINDOW`]
/// views: the verified tracker of each closed view, and the late messages
/// as they came, verified or not (a signature not yet checked is checked
/// only when two of one validator conflict, so an honest late message costs
/// a map insert).
#[derive(Debug, Default)]
pub(super) struct LateTracker {
    closed: std::collections::VecDeque<(u64, EquivocationTracker)>,
    late: HashMap<(u64, u32), (B256, SignedValue, bool)>,
}

impl LateTracker {
    /// Keeps `tracker`, the verified messages of `view`, now closed.
    pub(super) fn close_view(&mut self, view: u64, tracker: EquivocationTracker) {
        if !tracker.is_empty() {
            self.closed.push_back((view, tracker));
        }
        while self.closed.front().is_some_and(|(closed, _)| closed + LATE_WINDOW < view) {
            self.closed.pop_front();
        }
        self.late.retain(|(late, _), _| late + LATE_WINDOW >= view);
    }

    /// Checks `voter`'s message `commitment` in closed `view` against what
    /// is kept, keeping it (built by `make`, `verified` or not) if it is the
    /// first.
    pub(super) fn check(
        &mut self,
        view: u64,
        voter: u32,
        commitment: B256,
        verified: bool,
        make: impl FnOnce() -> SignedValue,
    ) -> LateCheck {
        let closed = self.closed.iter().find(|(closed, _)| *closed == view).and_then(|(_, tracker)| tracker.get(&voter));
        if let Some((first, signed)) = closed {
            return if *first == commitment {
                LateCheck::Repeat
            } else {
                LateCheck::Conflict { first: signed.clone(), verified: true }
            };
        }
        match self.late.get(&(view, voter)) {
            Some((first, _, _)) if *first == commitment => LateCheck::Repeat,
            Some((_, signed, verified)) => LateCheck::Conflict { first: signed.clone(), verified: *verified },
            None => {
                self.late.insert((view, voter), (commitment, make(), verified));
                LateCheck::Kept
            }
        }
    }

    /// Replaces a kept first message whose signature did not verify.
    pub(super) fn replace(&mut self, view: u64, voter: u32, commitment: B256, signed: SignedValue, verified: bool) {
        self.late.insert((view, voter), (commitment, signed, verified));
    }
}

#[cfg(test)]
mod am28_kind_tests {
    use super::EquivocationKind;

    #[test]
    fn kinds_serialise_as_am28_names() {
        for (kind, name) in [
            (EquivocationKind::Vote, "vote"),
            (EquivocationKind::CommitVote, "commit_vote"),
            (EquivocationKind::Proposal, "proposal"),
        ] {
            assert_eq!(serde_json::to_value(kind).expect("serialise"), name);
            assert_eq!(serde_json::from_value::<EquivocationKind>(name.into()).expect("parse"), kind);
        }
        let old: EquivocationKind = serde_json::from_value("commitVote".into()).expect("pre-AM28 record");
        assert_eq!(old, EquivocationKind::CommitVote);
    }
}


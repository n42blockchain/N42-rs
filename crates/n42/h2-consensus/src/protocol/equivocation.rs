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
#[serde(rename_all = "camelCase")]
pub enum EquivocationKind {
    /// Two Round-1 votes.
    Vote,
    /// Two Round-2 commit votes.
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

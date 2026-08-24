//! Chain-bound signing domains shared by gov5 and n42-26 H2-v4 consensus.

use alloy_primitives::B256;

const PREFIX: &[u8; 7] = b"N42H2V4";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H2V4ChainIdentity {
    pub chain_id: u64,
    pub genesis_hash: B256,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Phase {
    Proposal = 1,
    Vote = 2,
    Commit = 3,
    Timeout = 4,
    NewView = 5,
}

fn base(identity: H2V4ChainIdentity, phase: Phase, view: u64) -> [u8; 56] {
    let mut out = [0u8; 56];
    out[..7].copy_from_slice(PREFIX);
    out[7] = phase as u8;
    out[8..16].copy_from_slice(&identity.chain_id.to_le_bytes());
    out[16..48].copy_from_slice(identity.genesis_hash.as_slice());
    out[48..56].copy_from_slice(&view.to_le_bytes());
    out
}

pub fn proposal_signing_message(
    identity: H2V4ChainIdentity,
    view: u64,
    block_hash: B256,
    changes_hash: B256,
) -> [u8; 120] {
    let mut out = [0u8; 120];
    out[..56].copy_from_slice(&base(identity, Phase::Proposal, view));
    out[56..88].copy_from_slice(block_hash.as_slice());
    out[88..].copy_from_slice(changes_hash.as_slice());
    out
}

pub fn vote_signing_message(identity: H2V4ChainIdentity, view: u64, block_hash: B256) -> [u8; 88] {
    let mut out = [0u8; 88];
    out[..56].copy_from_slice(&base(identity, Phase::Vote, view));
    out[56..].copy_from_slice(block_hash.as_slice());
    out
}

pub fn commit_signing_message(
    identity: H2V4ChainIdentity,
    view: u64,
    block_hash: B256,
    changes_hash: B256,
) -> [u8; 120] {
    let mut out = [0u8; 120];
    out[..56].copy_from_slice(&base(identity, Phase::Commit, view));
    out[56..88].copy_from_slice(block_hash.as_slice());
    out[88..].copy_from_slice(changes_hash.as_slice());
    out
}

pub fn timeout_signing_message(identity: H2V4ChainIdentity, view: u64) -> [u8; 56] {
    base(identity, Phase::Timeout, view)
}

pub fn new_view_signing_message(identity: H2V4ChainIdentity, view: u64) -> [u8; 56] {
    base(identity, Phase::NewView, view)
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's block body on the wire, decoded without touching the transactions.
//!
//! `[header, transactions, verifiers, rewards, bal?]` is what travels on
//! gov5's block topic and on this node's direct body channel; the transport
//! that carries it lives in `n42-h2-net`. The decode lives here because two
//! processes need it: the validator, which identifies the body by the header
//! it hashes to, and the execution layer, which turns the same bytes into the
//! block it imports (`request::FOREIGN_BODY`) — and the execution layer must
//! not link libp2p to read a block.
//!
//! Nothing here is trusted beyond its own consistency: the header hashes to
//! the block hash the proposal named, the rewards hash to the header's
//! withdrawals root, and the transactions are left as the bytes they arrived
//! as — their root against the header is the execution layer's check, on the
//! side that has to decode them anyway.

use alloy_consensus::Header;
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Header as RlpHeader, RlpDecodable, RlpEncodable};
use alloy_rpc_types_engine::ExecutionData;

use crate::header_profile::{
    execution_data_from_raw_parts, gov5_rewards_root, rewards_to_withdrawals,
    validate_gov5_h2_header, N42HeaderProfile, MAX_HEADER_EXTRA_LEN,
};

/// Why a block body could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockBodyError {
    /// The bytes are not the `[header, txs, verifiers, rewards]` list.
    #[error("invalid gov5 block RLP")]
    InvalidRlp,
    /// The header is not a shape the profile accepts.
    #[error("block header violates the {0:?} profile: {1}")]
    HeaderProfile(N42HeaderProfile, String),
    /// A reward cannot be a withdrawal, or the list does not decode.
    #[error("block rewards: {0}")]
    InvalidRewards(String),
    /// The rewards do not hash to the header's withdrawals root.
    #[error("block rewards root mismatch")]
    RewardsRootMismatch,
    /// The header does not hash to the block hash it was announced under.
    #[error("block body is not block {0}")]
    NotTheAnnouncedBlock(B256),
}

/// One reward on the wire: gov5's `Reward{Address, Amount}` under reflective
/// RLP, `[address, amount]`.
#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct RewardRlp {
    /// Who is credited.
    pub address: Address,
    /// How much, in wei.
    pub amount: U256,
}

/// A block body with its transactions left as the bytes they arrived as.
///
/// What a follower needs: the header to remember and vote on, the bytes to
/// hand to its execution layer. Decoding 163,000 transactions into envelopes
/// and encoding them back was ~200 ms on the follower's critical path, and
/// the transactions-root check that decoding enabled is one the execution
/// layer repeats before it accepts the block.
#[derive(Debug, Clone)]
pub struct RawBlockBody {
    /// Keccak of the header RLP, which is the hash the proposal named.
    pub block_hash: B256,
    /// The header, exactly as the producer sealed it.
    pub header: Header,
    /// Each transaction's EIP-2718 bytes, in block order.
    pub transactions: Vec<Bytes>,
    /// gov5's rewards, as sent.
    pub rewards: Vec<(Address, U256)>,
    /// The rewards as the withdrawals this node's execution layer credits.
    pub withdrawals: Vec<Withdrawal>,
    /// The EIP-7928 block access list, when the producer sent one.
    pub bal: Option<Bytes>,
}

impl RawBlockBody {
    /// The Engine API form of this block, straight from the bytes.
    pub fn execution_data(&self) -> ExecutionData {
        execution_data_from_raw_parts(
            self.block_hash,
            &self.header,
            self.transactions.clone(),
            self.withdrawals.clone(),
            self.bal.clone(),
        )
    }
}

/// Checks a header against a profile.
pub fn validate_body_header(
    header: &Header,
    profile: N42HeaderProfile,
) -> Result<(), BlockBodyError> {
    let violation =
        |reason: &str| Err(BlockBodyError::HeaderProfile(profile, reason.to_owned()));
    match profile {
        N42HeaderProfile::Ethereum => {
            if header.ommers_hash != alloy_consensus::EMPTY_OMMER_ROOT_HASH {
                return violation("ommers hash is not the empty-list hash");
            }
            if header.extra_data.len() > MAX_HEADER_EXTRA_LEN {
                return violation("extra data exceeds 4096 bytes");
            }
            Ok(())
        }
        N42HeaderProfile::Gov5H2 => validate_gov5_h2_header(header)
            .map(|_| ())
            .map_err(|e| BlockBodyError::HeaderProfile(profile, e.to_string())),
    }
}

/// The body's header alone: the first item of the list, its hash, and
/// nothing else read.
///
/// What a validator needs to identify a body it will not decode — the block
/// hash the proposal named, the number and timestamp consensus keys on. The
/// rest of the body is checked by whoever decodes it; a body whose header is
/// fine and whose transactions are not is refused by the execution layer,
/// which is where the transactions are read on this path.
pub fn decode_block_body_header(
    encoded: &[u8],
    profile: N42HeaderProfile,
) -> Result<(B256, Header), BlockBodyError> {
    let mut payload = encoded;
    let outer = RlpHeader::decode(&mut payload).map_err(|_| BlockBodyError::InvalidRlp)?;
    if !outer.list || outer.payload_length != payload.len() {
        return Err(BlockBodyError::InvalidRlp);
    }
    let header_rlp = take_rlp_item(&mut payload).ok_or(BlockBodyError::InvalidRlp)?;
    let mut header_cursor = header_rlp;
    let header = Header::decode(&mut header_cursor).map_err(|_| BlockBodyError::InvalidRlp)?;
    if !header_cursor.is_empty() {
        return Err(BlockBodyError::InvalidRlp);
    }
    validate_body_header(&header, profile)?;
    Ok((keccak256(header_rlp), header))
}

/// The whole body, with the transactions as bytes.
///
/// `shared` is the same buffer as `encoded` when the caller holds it as
/// shared bytes: the transactions (and the access list) are then slices of
/// it rather than copies. At 163,000 transactions the copies were 163,000
/// allocations and 19 MB per body on every follower — but a slice keeps the
/// whole buffer alive for as long as any transaction lives, so a caller that
/// hands the transactions on to something that outlives the body must pass
/// `None`.
pub fn decode_raw_block_body(
    encoded: &[u8],
    shared: Option<&Bytes>,
    profile: N42HeaderProfile,
) -> Result<RawBlockBody, BlockBodyError> {
    let mut payload = encoded;
    let outer = RlpHeader::decode(&mut payload).map_err(|_| BlockBodyError::InvalidRlp)?;
    if !outer.list || outer.payload_length != payload.len() {
        return Err(BlockBodyError::InvalidRlp);
    }
    let header_rlp = take_rlp_item(&mut payload).ok_or(BlockBodyError::InvalidRlp)?;
    let mut header_cursor = header_rlp;
    let header = Header::decode(&mut header_cursor).map_err(|_| BlockBodyError::InvalidRlp)?;
    if !header_cursor.is_empty() {
        return Err(BlockBodyError::InvalidRlp);
    }
    validate_body_header(&header, profile)?;

    let transactions_rlp = take_rlp_item(&mut payload).ok_or(BlockBodyError::InvalidRlp)?;
    let mut cursor = transactions_rlp;
    let list = RlpHeader::decode(&mut cursor).map_err(|_| BlockBodyError::InvalidRlp)?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(BlockBodyError::InvalidRlp);
    }
    let mut transactions = Vec::with_capacity(cursor.len() / 100);
    while !cursor.is_empty() {
        let bytes = take_rlp_bytes(&mut cursor).ok_or(BlockBodyError::InvalidRlp)?;
        if bytes.is_empty() {
            return Err(BlockBodyError::InvalidRlp);
        }
        transactions.push(match shared {
            Some(whole) => shared_slice(whole, bytes),
            None => Bytes::copy_from_slice(bytes),
        });
    }

    take_rlp_list_item(&mut payload).ok_or(BlockBodyError::InvalidRlp)?;
    let rewards_rlp = take_rlp_list_item(&mut payload).ok_or(BlockBodyError::InvalidRlp)?;
    let rewards = decode_rewards(rewards_rlp)?;
    let bal = if payload.is_empty() {
        None
    } else {
        take_rlp_bytes(&mut payload)
            .ok_or(BlockBodyError::InvalidRlp)
            .map(|bytes| {
                Some(match shared {
                    Some(whole) => shared_slice(whole, bytes),
                    None => Bytes::copy_from_slice(bytes),
                })
            })?
    };
    if !payload.is_empty() {
        return Err(BlockBodyError::InvalidRlp);
    }
    // The withdrawals root is gov5's rewards commitment; rewards that do not
    // hash to it are not the block's, and would only fail in execution. A
    // block without rewards may carry either spelling of "none": gov5's
    // keccak of nothing, or the empty trie root its resealed history and
    // genesis write.
    if profile == N42HeaderProfile::Gov5H2
        && let Some(root) = header.withdrawals_root
        && root != gov5_rewards_root(rewards.iter().copied())
        && !(rewards.is_empty() && root == alloy_consensus::EMPTY_ROOT_HASH)
    {
        return Err(BlockBodyError::RewardsRootMismatch);
    }
    let withdrawals = rewards_to_withdrawals(&rewards)
        .map_err(|error| BlockBodyError::InvalidRewards(error.to_string()))?;
    Ok(RawBlockBody {
        block_hash: keccak256(header_rlp),
        header,
        transactions,
        rewards,
        withdrawals,
        bal,
    })
}

/// A slice of `whole` for `part`, which must lie inside it.
pub fn shared_slice(whole: &Bytes, part: &[u8]) -> Bytes {
    let start = part.as_ptr() as usize - whole.as_ptr() as usize;
    whole.slice(start..start + part.len())
}

/// The rewards list: `[[address, amount], ...]`.
pub fn decode_rewards(encoded: &[u8]) -> Result<Vec<(Address, U256)>, BlockBodyError> {
    let mut cursor = encoded;
    let list = RlpHeader::decode(&mut cursor).map_err(|_| BlockBodyError::InvalidRlp)?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(BlockBodyError::InvalidRlp);
    }
    let mut rewards = Vec::new();
    while !cursor.is_empty() {
        let reward = RewardRlp::decode(&mut cursor)
            .map_err(|error| BlockBodyError::InvalidRewards(error.to_string()))?;
        rewards.push((reward.address, reward.amount));
    }
    Ok(rewards)
}

/// One RLP item — header and payload — as a slice, advancing the cursor.
pub fn take_rlp_item<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    let header_len = cursor.len() - probe.len();
    let total = header_len.checked_add(header.payload_length)?;
    if total > cursor.len() {
        return None;
    }
    let (item, rest) = cursor.split_at(total);
    *cursor = rest;
    Some(item)
}

/// [`take_rlp_item`], refusing anything that is not a list.
pub fn take_rlp_list_item<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    if !header.list {
        return None;
    }
    take_rlp_item(cursor)
}

/// A byte-string item's payload, advancing the cursor.
pub fn take_rlp_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    if header.list {
        return None;
    }
    let header_len = cursor.len() - probe.len();
    let total = header_len.checked_add(header.payload_length)?;
    if total > cursor.len() {
        return None;
    }
    let (item, rest) = cursor.split_at(total);
    *cursor = rest;
    Some(&item[header_len..])
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's block gossip: how a block body reaches the validators that vote on it.
//!
//! A HotStuff-2 proposal carries only a block hash. The body travels separately,
//! on gov5's block topic — `/n42/<fork digest>/block/ssz_snappy`, where the fork
//! digest is the first four bytes of the genesis hash — as raw-snappy RLP of
//! `[header, transactions, verifiers, rewards]` (`internal/p2p/broadcaster.go`
//! `BroadcastBlock`). A follower that has the body executes the proposal and
//! casts its deferred vote; one that does not has nothing to vote on, and a
//! fleet where nobody but the leader has bodies never reaches quorum.
//!
//! Ported from N42-26's `gov5_block.rs`, with one addition: a
//! [`HeaderProfile`]. gov5's live H2 headers have a shape of their own — a zero
//! ommers hash, an `N42H`-prefixed extra-data field carrying the view — that an
//! Engine API payload cannot express directly, so decoding one means
//! reconstructing it. This node's own blocks do not have that shape yet (its
//! builder still seals them the Ethereum way), so a Rust fleet gossips them
//! under [`HeaderProfile::Ethereum`], where the header is exactly what the
//! payload says. The wire format is gov5's either way; the profile decides only
//! which header shapes are accepted, and a mixed fleet needs the builder to
//! adopt gov5's.

use alloy_consensus::{proofs::calculate_transaction_root, Block, Header, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};
use alloy_rpc_types_engine::ExecutionData;
use libp2p::gossipsub::IdentTopic;

/// Fixed prefix gov5's H2 header-extra encoder writes.
pub const GOV5_HEADER_EXTRA_MAGIC: &[u8; 4] = b"N42H";
/// Magic plus the little-endian view number.
pub const MIN_GOV5_HEADER_EXTRA_BYTES: usize = 12;
/// Bound shared with gov5's high-TC envelope limit.
pub const MAX_GOV5_HEADER_EXTRA_BYTES: usize = 4096;

/// Which header shapes a block on the wire may have. The chain-wide
/// definition lives with the consensus crate; this is the same type.
pub use n42_h2_consensus::header_profile::N42HeaderProfile as HeaderProfile;

/// The block topic for a chain.
pub fn gov5_block_topic(genesis_hash: B256) -> IdentTopic {
    let fork_digest = hex::encode(&genesis_hash.as_slice()[..4]);
    IdentTopic::new(format!("/n42/{fork_digest}/block/ssz_snappy"))
}

/// A block as decoded from the wire.
#[derive(Clone, Debug)]
pub struct GossipBlock {
    /// Keccak of the header RLP, which is the hash the proposal named.
    pub block_hash: B256,
    /// The header, exactly as the producer sealed it.
    pub header: Header,
    /// The transactions, in order.
    pub transactions: Vec<TxEnvelope>,
}

/// Why a block could not be encoded or decoded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockGossipError {
    /// The bytes are not the `[header, txs, verifiers, rewards]` list.
    #[error("invalid gov5 block RLP")]
    InvalidRlp,
    /// The header is not a shape the profile accepts.
    #[error("block header violates the {0:?} profile: {1}")]
    HeaderProfile(HeaderProfile, String),
    /// The transactions do not hash to the header's transactions root.
    #[error("block transaction root mismatch")]
    TransactionRootMismatch,
    /// The payload could not be turned back into a block.
    #[error("execution payload cannot reconstruct a block: {0}")]
    PayloadReconstruction(String),
    /// The reconstructed header does not hash to the payload's block hash.
    #[error("execution payload block hash does not match its reconstructed header")]
    PayloadHashMismatch,
    /// The compressed payload could not be expanded.
    #[error("snappy: {0}")]
    Snappy(String),
}

/// The view a gov5 H2 header was proposed in.
pub fn gov5_header_view(header: &Header) -> Result<u64, BlockGossipError> {
    n42_h2_consensus::header_view(header)
        .map_err(|e| BlockGossipError::HeaderProfile(HeaderProfile::Gov5H2, e.to_string()))
}

/// Checks a header against a profile.
pub fn validate_header(header: &Header, profile: HeaderProfile) -> Result<(), BlockGossipError> {
    let violation = |reason: &str| {
        Err(BlockGossipError::HeaderProfile(profile, reason.to_owned()))
    };
    match profile {
        HeaderProfile::Ethereum => {
            if header.ommers_hash != alloy_consensus::EMPTY_OMMER_ROOT_HASH {
                return violation("ommers hash is not the empty-list hash");
            }
            if header.extra_data.len() > MAX_GOV5_HEADER_EXTRA_BYTES {
                return violation("extra data exceeds 4096 bytes");
            }
            Ok(())
        }
        HeaderProfile::Gov5H2 => n42_h2_consensus::validate_gov5_h2_header(header)
            .map(|_| ())
            .map_err(|e| BlockGossipError::HeaderProfile(profile, e.to_string())),
    }
}

/// Encodes a locally built payload as gov5's block gossip form, compressed the
/// way the topic expects.
///
/// The verifier and reward lists are empty: execution validity and H2-v4
/// consensus authentication travel separately.
pub fn encode_block_gossip(
    execution: &ExecutionData,
    profile: HeaderProfile,
) -> Result<Vec<u8>, BlockGossipError> {
    compress_block_rlp(&encode_block_rlp(execution, profile)?)
}

/// The topic's compression of an already-encoded block.
pub fn compress_block_rlp(rlp: &[u8]) -> Result<Vec<u8>, BlockGossipError> {
    snap::raw::Encoder::new()
        .compress_vec(rlp)
        .map_err(|error| BlockGossipError::Snappy(error.to_string()))
}

/// The block RLP inside a compressed topic payload, before any decoding —
/// what a node keeps to serve `block_by_hash` requests byte for byte.
pub fn decompress_block_gossip(data: &[u8]) -> Result<Vec<u8>, BlockGossipError> {
    let len = snap::raw::decompress_len(data)
        .map_err(|error| BlockGossipError::Snappy(error.to_string()))?;
    if len > crate::config::MAX_GOSSIP_SIZE {
        return Err(BlockGossipError::Snappy("expands past the gossip size limit".into()));
    }
    snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(|error| BlockGossipError::Snappy(error.to_string()))
}

/// Decodes a compressed block off the topic.
pub fn decode_block_gossip(
    data: &[u8],
    profile: HeaderProfile,
) -> Result<GossipBlock, BlockGossipError> {
    decode_block_rlp(&decompress_block_gossip(data)?, profile)
}

/// The uncompressed wire form: `[header, tx_bytes, verifiers, rewards]`.
pub fn encode_block_rlp(
    execution: &ExecutionData,
    profile: HeaderProfile,
) -> Result<Vec<u8>, BlockGossipError> {
    let block = reconstruct_block(execution, profile)?;
    if calculate_transaction_root(&block.body.transactions) != block.header.transactions_root {
        return Err(BlockGossipError::TransactionRootMismatch);
    }

    let mut header_rlp = Vec::new();
    block.header.encode(&mut header_rlp);
    let transaction_bytes = block
        .body
        .transactions
        .iter()
        .map(|transaction| Bytes::from(transaction.encoded_2718()))
        .collect::<Vec<_>>();
    let verifiers = Vec::<Bytes>::new();
    let rewards = Vec::<Bytes>::new();
    let payload_length =
        header_rlp.len() + transaction_bytes.length() + verifiers.length() + rewards.length();
    let mut encoded = Vec::new();
    RlpHeader {
        list: true,
        payload_length,
    }
    .encode(&mut encoded);
    encoded.extend_from_slice(&header_rlp);
    transaction_bytes.encode(&mut encoded);
    verifiers.encode(&mut encoded);
    rewards.encode(&mut encoded);
    Ok(encoded)
}

/// Decodes the uncompressed wire form.
///
/// The verifier and reward lists, and an optional trailing ZK proof, are
/// consumed structurally and never trusted: the header commits to the
/// transactions, and consensus separately authenticates the block hash.
pub fn decode_block_rlp(
    encoded: &[u8],
    profile: HeaderProfile,
) -> Result<GossipBlock, BlockGossipError> {
    let mut payload = encoded;
    let outer = RlpHeader::decode(&mut payload).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !outer.list || outer.payload_length != payload.len() {
        return Err(BlockGossipError::InvalidRlp);
    }

    let header_rlp = take_rlp_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let mut header_cursor = header_rlp;
    let header = Header::decode(&mut header_cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !header_cursor.is_empty() {
        return Err(BlockGossipError::InvalidRlp);
    }
    validate_header(&header, profile)?;

    let transactions_rlp = take_rlp_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let transactions = decode_transactions(transactions_rlp)?;

    take_rlp_list_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    take_rlp_list_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    if !payload.is_empty() {
        take_rlp_bytes(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    }
    if !payload.is_empty() {
        return Err(BlockGossipError::InvalidRlp);
    }

    if calculate_transaction_root(&transactions) != header.transactions_root {
        return Err(BlockGossipError::TransactionRootMismatch);
    }

    Ok(GossipBlock {
        block_hash: keccak256(header_rlp),
        header,
        transactions,
    })
}

impl GossipBlock {
    /// The execution payload a follower hands its execution layer.
    ///
    /// Everything the Engine API needs is in the header and transactions,
    /// with one exception: execution requests are carried by hash only, since
    /// gov5's block form does not list them. A block with the empty requests
    /// hash gets the empty list, which every version accepts; one with real
    /// requests is handed over by hash, which an execution layer accepts only
    /// where its API allows it.
    pub fn execution_data(&self) -> ExecutionData {
        let block = n42_h2_consensus::block_for_header(self.header.clone(), self.transactions.clone());
        n42_h2_consensus::execution_data_for_block(self.block_hash, &block)
    }
}

/// Rebuilds the block a payload describes, under a profile.
///
/// Engine payloads carry neither `ommers_hash` nor `difficulty`; the profile
/// says what they were. Both gov5 H2 difficulty variants are tried and the
/// payload's block hash selects the right one — no guessing is involved.
fn reconstruct_block(
    execution: &ExecutionData,
    profile: HeaderProfile,
) -> Result<Block<TxEnvelope>, BlockGossipError> {
    let expected_hash = execution.block_hash();
    let direct = execution
        .clone()
        .try_into_block::<TxEnvelope>()
        .map_err(|error| BlockGossipError::PayloadReconstruction(error.to_string()))?;
    match profile {
        HeaderProfile::Ethereum => {
            validate_header(&direct.header, profile)?;
            if direct.header.hash_slow() != expected_hash {
                return Err(BlockGossipError::PayloadHashMismatch);
            }
            Ok(direct)
        }
        HeaderProfile::Gov5H2 => n42_h2_consensus::reconstruct_gov5_h2_block::<TxEnvelope>(execution)
            .map_err(|e| BlockGossipError::HeaderProfile(profile, e.to_string())),
    }
}

fn decode_transactions(encoded: &[u8]) -> Result<Vec<TxEnvelope>, BlockGossipError> {
    let mut cursor = encoded;
    let list = RlpHeader::decode(&mut cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(BlockGossipError::InvalidRlp);
    }
    let mut transactions = Vec::new();
    while !cursor.is_empty() {
        let bytes = take_rlp_bytes(&mut cursor).ok_or(BlockGossipError::InvalidRlp)?;
        let mut tx_cursor = bytes;
        let transaction =
            TxEnvelope::decode_2718(&mut tx_cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
        if !tx_cursor.is_empty() {
            return Err(BlockGossipError::InvalidRlp);
        }
        transactions.push(transaction);
    }
    Ok(transactions)
}

/// One RLP item — header and payload — as a slice, advancing the cursor.
fn take_rlp_item<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
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

fn take_rlp_list_item<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    if !header.list {
        return None;
    }
    take_rlp_item(cursor)
}

/// A byte-string item's payload, advancing the cursor.
fn take_rlp_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::BlockBody;
    use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
    use alloy_primitives::{Address, U256};

    fn header(extra: Bytes) -> Header {
        Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
            beneficiary: Address::ZERO,
            state_root: B256::repeat_byte(2),
            transactions_root: calculate_transaction_root::<TxEnvelope>(&[]),
            receipts_root: alloy_consensus::EMPTY_ROOT_HASH,
            number: 7,
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            extra_data: extra,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        }
    }

    fn execution_data(header: Header) -> ExecutionData {
        let block = Block {
            header,
            body: BlockBody {
                transactions: Vec::<TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: Some(Default::default()),
            },
        };
        ExecutionData::from_block_unchecked(block.header.hash_slow(), &block)
    }

    #[test]
    fn a_block_survives_the_wire_and_reconstructs_the_same_payload() {
        let sealed = header(Bytes::from(vec![0u8; 97]));
        let execution = execution_data(sealed.clone());

        let wire = encode_block_gossip(&execution, HeaderProfile::Ethereum).unwrap();
        let decoded = decode_block_gossip(&wire, HeaderProfile::Ethereum).unwrap();
        assert_eq!(decoded.block_hash, execution.block_hash());
        assert_eq!(decoded.header, sealed);

        // And the follower's payload names the same block.
        let rebuilt = decoded.execution_data();
        assert_eq!(rebuilt.block_hash(), execution.block_hash());
        assert!(rebuilt.sidecar.requests().is_some(), "an empty requests hash becomes the empty list");
    }

    #[test]
    fn a_gov5_h2_header_is_reconstructed_by_its_hash() {
        let mut extra = Vec::new();
        extra.extend_from_slice(GOV5_HEADER_EXTRA_MAGIC);
        extra.extend_from_slice(&42u64.to_le_bytes());
        extra.resize(12 + 65, 0);
        let mut sealed = header(extra.into());
        sealed.ommers_hash = B256::ZERO;
        sealed.difficulty = U256::ZERO;
        let execution = execution_data(sealed.clone());

        // The payload cannot say "zero ommers"; the profile does, and the hash
        // confirms it.
        let wire = encode_block_gossip(&execution, HeaderProfile::Gov5H2).unwrap();
        let decoded = decode_block_gossip(&wire, HeaderProfile::Gov5H2).unwrap();
        assert_eq!(decoded.header, sealed);
        assert_eq!(gov5_header_view(&decoded.header).unwrap(), 42);

        // The Ethereum profile refuses it, and vice versa.
        assert!(encode_block_gossip(&execution, HeaderProfile::Ethereum).is_err());
        assert!(decode_block_gossip(&wire, HeaderProfile::Ethereum).is_err());
    }

    #[test]
    fn a_header_that_does_not_hash_to_the_payload_is_refused() {
        let execution = execution_data(header(Bytes::new()));
        let mut lying = execution.clone();
        lying.payload.as_v1_mut().block_hash = B256::repeat_byte(0xEE);
        assert_eq!(
            encode_block_gossip(&lying, HeaderProfile::Ethereum),
            Err(BlockGossipError::PayloadHashMismatch)
        );
    }

    #[test]
    fn garbage_is_rejected_not_panicked_on() {
        for bytes in [&[][..], &[0xC0][..], &[0xFF; 8][..]] {
            assert!(decode_block_rlp(bytes, HeaderProfile::Ethereum).is_err());
        }
        let compressed = snap::raw::Encoder::new().compress_vec(&[0xC1, 0x80]).unwrap();
        assert!(decode_block_gossip(&compressed, HeaderProfile::Ethereum).is_err());
    }

    /// `Block.Marshal()` of an empty Cancun+Prague block, printed by gov5's
    /// own code (`cmd/h2-profile-fixture`): the bytes `BroadcastBlock` puts on
    /// the block topic before snappy.
    #[test]
    fn a_block_gov5_produced_decodes_to_the_hash_gov5_computed() {
        let header_rlp =
            alloy_primitives::hex::decode(include_str!("../testdata/gov5_empty_block.header.hex").trim())
                .unwrap();
        let mut cursor = header_rlp.as_slice();
        let header = alloy_consensus::Header::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("gov5 header does not decode: {e}"));
        assert!(cursor.is_empty(), "gov5 header has {} trailing bytes", cursor.len());
        assert_eq!(
            header.hash_slow(),
            alloy_primitives::b256!("7f9765be6eb977fdd306510e60aeac2d4c6cb7925016d5c9b48dc0722544234a")
        );

        let rlp = alloy_primitives::hex::decode(include_str!("../testdata/gov5_empty_block.rlp.hex").trim())
            .unwrap();
        let block = decode_block_rlp(&rlp, HeaderProfile::Gov5H2)
            .unwrap_or_else(|e| panic!("gov5 block does not decode: {e:?}"));
        assert_eq!(block.block_hash, header.hash_slow());
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn the_topic_is_bound_to_the_chains_fork_digest() {
        let genesis = B256::repeat_byte(0xAB);
        assert_eq!(gov5_block_topic(genesis).to_string(), "/n42/abababab/block/ssz_snappy");
    }
}

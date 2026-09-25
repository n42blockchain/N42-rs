// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A block body that names its transactions instead of carrying them.
//!
//! On this fleet every node ingests every transaction (`F7_INGEST_ALL`): by
//! the time a leader proposes a block, every follower has already decoded
//! each of its 163,000 transactions, verified the signature, recorded the
//! sender and put it in its queue. The gossip body then moves 26 MB of
//! exactly that across the box and makes the follower derive it a second
//! time -- measured at loop194 as 43 ms of transfer, 82 ms of decode and 38
//! ms of sender look-ups out of a 240 ms binding term.
//!
//! The compact body is the same body with the transactions replaced by their
//! hashes in block order, 32 bytes each: ~5.2 MB instead of ~26. The
//! receiver assembles the block out of its own queue and checks the
//! transactions root of what it assembled against the header's, which is
//! what binds the assembled list to the block consensus voted on. A hash it
//! does not hold is a miss, and a miss falls back to the whole body.
//!
//! This travels on the Rust-only direct push channel and nowhere else.
//! gov5's block topic, `block_by_hash` and `bodies_by_range` carry
//! `[header, transactions, verifiers, rewards]` byte for byte, as they
//! always have -- they are a cross-client contract.
//!
//! A hash the receiver does not hold is a miss, and a miss is answered by
//! asking for those transactions alone -- BIP-152's `getblocktxn` shape. The
//! answer comes back as the frame's *fill*: the transactions for the
//! positions that were missing, appended to the same frame and handed back
//! to the side that assembles. Only that side ever sees a filled frame; what
//! travels between nodes never carries one.
//!
//! ```text
//! frame := "N42C" | u8 version
//!        | u32 len, header RLP
//!        | u32 count, count * 32 bytes of transaction hash, in block order
//!        | u32 len, the verifiers item as it stands in the gov5 body
//!        | u32 len, the rewards item as it stands in the gov5 body
//!        | u8 present, [u32 len, the EIP-7928 access list]
//!        | [u8 1, u32 count, count * (u32 index, u32 len, EIP-2718 bytes)]
//! ```
//!
//! The fill is the only optional section and it ends the frame, so a frame
//! without one is byte for byte what a frame was before it existed.
//!
//! Little-endian lengths, as on the raw engine channel; the RLP items are
//! carried whole so nothing about gov5's body has to be re-encoded here and
//! the receiver checks them exactly as it checks a full body's.

use alloy_consensus::Header;
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};

use crate::block_body::{
    decode_rewards, take_rlp_bytes, take_rlp_item, take_rlp_list_item, validate_body_header,
    BlockBodyError,
};
use crate::header_profile::{gov5_rewards_root, rewards_to_withdrawals, N42HeaderProfile};

/// The magic every compact frame starts with, so a body of one shape is
/// never read as the other however it reached this node.
const MAGIC: [u8; 4] = *b"N42C";

/// The frame version. A frame that does not carry this is refused rather
/// than guessed at: both ends of the direct channel are this binary, and a
/// peer that has not negotiated the capability is never sent one.
const VERSION: u8 = 1;

/// Introduces the fill section. A frame either ends after the access list or
/// carries exactly this and then the fill; anything else is refused, so the
/// optional section cannot be read out of trailing rubbish.
const FILL_PRESENT: u8 = 1;

/// Why a compact body could not be read. Kept as [`BlockBodyError`] so a
/// caller handles one failure, not two.
fn invalid() -> BlockBodyError {
    BlockBodyError::InvalidRlp
}

/// What a compact body says, with the transactions named rather than
/// carried.
#[derive(Debug, Clone)]
pub struct CompactBlockBody<'a> {
    /// Keccak of the header RLP, which is the hash the proposal named.
    pub block_hash: B256,
    /// The header, exactly as the producer sealed it.
    pub header: Header,
    /// The header's RLP as it arrived, for a caller that has to hand the
    /// same bytes on.
    pub header_rlp: &'a [u8],
    /// Each transaction's hash, in block order.
    pub hashes: Vec<B256>,
    /// gov5's rewards, as sent.
    pub rewards: Vec<(Address, U256)>,
    /// The rewards as the withdrawals this node's execution layer credits.
    pub withdrawals: Vec<Withdrawal>,
    /// The EIP-7928 block access list, when the producer sent one.
    pub bal: Option<&'a [u8]>,
    /// The verifiers item, carried so a full body can be put back together
    /// from this one byte for byte.
    pub verifiers_rlp: &'a [u8],
    /// The rewards item, carried for the same reason.
    pub rewards_rlp: &'a [u8],
    /// Transactions supplied for positions the receiver could not fill from
    /// its own queue, as EIP-2718 bytes: `(index, bytes)` in index order.
    /// Empty on every frame that crossed the wire.
    pub fill: Vec<(usize, &'a [u8])>,
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BlockBodyError> {
        if self.0.len() < n {
            return Err(invalid());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, BlockBodyError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, BlockBodyError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| invalid())?))
    }
    fn bytes(&mut self) -> Result<&'a [u8], BlockBodyError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// The compact form of a gov5 block body, given that body's bytes and its
/// transactions' hashes in block order.
///
/// The body is walked, not decoded: the transaction list is one RLP item and
/// is stepped over whole, so this costs the same at 163,000 transactions as
/// at none. The hashes come from the caller because the producer already has
/// them -- they are what its execution layer built the block from -- and
/// hashing 26 MB on the proposal path to rediscover them would give back
/// most of what the compact body saves.
pub fn encode_compact_body(
    gov5_body: &[u8],
    hashes: &[B256],
    profile: N42HeaderProfile,
) -> Result<Vec<u8>, BlockBodyError> {
    let mut payload = gov5_body;
    let outer = RlpHeader::decode(&mut payload).map_err(|_| invalid())?;
    if !outer.list || outer.payload_length != payload.len() {
        return Err(invalid());
    }
    let header_rlp = take_rlp_item(&mut payload).ok_or_else(invalid)?;
    let mut cursor = header_rlp;
    let header = Header::decode(&mut cursor).map_err(|_| invalid())?;
    if !cursor.is_empty() {
        return Err(invalid());
    }
    validate_body_header(&header, profile)?;
    // The transactions, stepped over whole and thrown away: their hashes are
    // what goes on the wire.
    take_rlp_list_item(&mut payload).ok_or_else(invalid)?;
    let verifiers_rlp = take_rlp_list_item(&mut payload).ok_or_else(invalid)?;
    let rewards_rlp = take_rlp_list_item(&mut payload).ok_or_else(invalid)?;
    let bal = if payload.is_empty() { None } else { Some(take_rlp_bytes(&mut payload).ok_or_else(invalid)?) };
    if !payload.is_empty() {
        return Err(invalid());
    }
    Ok(write_compact(header_rlp, hashes, verifiers_rlp, rewards_rlp, bal))
}

/// The bytes of a compact body, from parts already in hand.
pub fn write_compact(
    header_rlp: &[u8],
    hashes: &[B256],
    verifiers_rlp: &[u8],
    rewards_rlp: &[u8],
    bal: Option<&[u8]>,
) -> Vec<u8> {
    let mut w = Writer(Vec::with_capacity(
        64 + header_rlp.len() + hashes.len() * 32 + verifiers_rlp.len() + rewards_rlp.len(),
    ));
    w.0.extend_from_slice(&MAGIC);
    w.u8(VERSION);
    w.bytes(header_rlp);
    w.u32(hashes.len() as u32);
    for hash in hashes {
        w.0.extend_from_slice(hash.as_slice());
    }
    w.bytes(verifiers_rlp);
    w.bytes(rewards_rlp);
    match bal {
        Some(bal) => {
            w.u8(1);
            w.bytes(bal);
        }
        None => w.u8(0),
    }
    w.0
}

/// The same frame with `fill` appended: the transactions for the positions
/// the receiver could not fill from its own queue, in index order.
///
/// Appended rather than spliced in, because the frame the peer sent is the
/// one whose header and hashes were already checked, and this keeps those
/// bytes untouched.
pub fn with_fill(frame: &[u8], fill: &[(usize, alloy_primitives::Bytes)]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(frame.len() + 8 + fill.iter().map(|(_, tx)| tx.len() + 8).sum::<usize>());
    out.extend_from_slice(frame);
    if fill.is_empty() {
        return out;
    }
    let mut w = Writer(out);
    w.u8(FILL_PRESENT);
    w.u32(fill.len() as u32);
    for (index, tx) in fill {
        w.u32(*index as u32);
        w.bytes(tx);
    }
    w.0
}

/// The frame with `fill` merged into whatever fill it already carries: one
/// fill section, the union of both, in strictly increasing index order.
///
/// What the side that assembles keeps as a block's frame of record across
/// fill rounds (defect 18). [`with_fill`] appends a section to a frame that
/// must not have one yet; applying each round's answer to the frame as it
/// arrived from the peer -- not to the one the last round filled -- lost
/// every earlier round's fill, and loop249's followers asked for the same
/// two sets of positions in turn, 340-360 times, until the view timed out.
/// A position supplied twice keeps the first supply: both are checked
/// against the hash the frame names for that position, so they are the same
/// bytes or the assembly refuses the frame.
pub fn merge_fill(
    frame: &[u8],
    fill: &[(usize, alloy_primitives::Bytes)],
) -> Result<Vec<u8>, BlockBodyError> {
    let mut r = Reader(frame);
    if r.take(MAGIC.len())? != MAGIC || r.u8()? != VERSION {
        return Err(invalid());
    }
    r.bytes()?;
    let count = r.u32()? as usize;
    r.take(count.checked_mul(32).ok_or_else(invalid)?)?;
    r.bytes()?;
    r.bytes()?;
    if r.u8()? == 1 {
        r.bytes()?;
    }
    let base = frame.len() - r.0.len();
    let mut merged: std::collections::BTreeMap<usize, &[u8]> = std::collections::BTreeMap::new();
    if !r.0.is_empty() {
        if r.u8()? != FILL_PRESENT {
            return Err(invalid());
        }
        let n = r.u32()? as usize;
        for _ in 0..n {
            let index = r.u32()? as usize;
            if index >= count || merged.insert(index, r.bytes()?).is_some() {
                return Err(invalid());
            }
        }
        if !r.0.is_empty() {
            return Err(invalid());
        }
    }
    for (index, tx) in fill {
        if *index >= count {
            return Err(invalid());
        }
        merged.entry(*index).or_insert(&tx[..]);
    }
    let mut w = Writer(Vec::with_capacity(
        base + 8 + merged.values().map(|tx| tx.len() + 8).sum::<usize>(),
    ));
    w.0.extend_from_slice(&frame[..base]);
    if merged.is_empty() {
        return Ok(w.0);
    }
    w.u8(FILL_PRESENT);
    w.u32(merged.len() as u32);
    for (index, tx) in merged {
        w.u32(index as u32);
        w.bytes(tx);
    }
    Ok(w.0)
}

/// Whether these bytes claim to be a compact body. Cheap, and the only thing
/// that tells the two shapes apart on a channel that carries both.
pub fn is_compact_body(bytes: &[u8]) -> bool {
    bytes.len() > MAGIC.len() && bytes[..MAGIC.len()] == MAGIC
}

/// The compact body's header alone, the way [`crate::decode_block_body_header`]
/// reads a full one: what the validator needs to know which block this is,
/// with nothing else read.
pub fn decode_compact_body_header(
    encoded: &[u8],
    profile: N42HeaderProfile,
) -> Result<(B256, Header), BlockBodyError> {
    let mut r = Reader(encoded);
    if r.take(MAGIC.len())? != MAGIC || r.u8()? != VERSION {
        return Err(invalid());
    }
    let header_rlp = r.bytes()?;
    let mut cursor = header_rlp;
    let header = Header::decode(&mut cursor).map_err(|_| invalid())?;
    if !cursor.is_empty() {
        return Err(invalid());
    }
    validate_body_header(&header, profile)?;
    Ok((keccak256(header_rlp), header))
}

/// The whole compact body.
///
/// Every check a full body's decode makes that does not need the
/// transactions is made here, against the same values: the header profile,
/// and the rewards against the header's withdrawals root. What binds the
/// transactions -- the root over the list the receiver assembles -- is the
/// assembler's, because only it knows what the hashes stand for.
pub fn decode_compact_body(
    encoded: &[u8],
    profile: N42HeaderProfile,
) -> Result<CompactBlockBody<'_>, BlockBodyError> {
    let mut r = Reader(encoded);
    if r.take(MAGIC.len())? != MAGIC || r.u8()? != VERSION {
        return Err(invalid());
    }
    let header_rlp = r.bytes()?;
    let mut cursor = header_rlp;
    let header = Header::decode(&mut cursor).map_err(|_| invalid())?;
    if !cursor.is_empty() {
        return Err(invalid());
    }
    validate_body_header(&header, profile)?;
    let count = r.u32()? as usize;
    let raw = r.take(count.checked_mul(32).ok_or_else(invalid)?)?;
    // Exactly `count` whole hashes: the take above sized the slice, so the
    // remainder `as_chunks` hands back is empty.
    let hashes: Vec<B256> = raw.as_chunks::<32>().0.iter().copied().map(B256::from).collect();
    let verifiers_rlp = r.bytes()?;
    let rewards_rlp = r.bytes()?;
    let bal = if r.u8()? == 1 { Some(r.bytes()?) } else { None };
    // The fill, when the side that assembles appended one. Strict: the
    // marker must be exactly right and the section must end the frame.
    let mut fill = Vec::new();
    if !r.0.is_empty() {
        if r.u8()? != FILL_PRESENT {
            return Err(invalid());
        }
        let n = r.u32()? as usize;
        if n > count {
            return Err(invalid());
        }
        fill.reserve(n);
        let mut previous: Option<usize> = None;
        for _ in 0..n {
            let index = r.u32()? as usize;
            if index >= count || previous.is_some_and(|last| index <= last) {
                // Out of range, or not in strictly increasing index order:
                // a fill that names a position twice would let one
                // transaction stand for two.
                return Err(invalid());
            }
            previous = Some(index);
            fill.push((index, r.bytes()?));
        }
        if !r.0.is_empty() {
            return Err(invalid());
        }
    }
    let rewards = decode_rewards(rewards_rlp)?;
    // gov5's rewards commitment, exactly as the full body's decode checks
    // it: rewards that do not hash to the header's withdrawals root are not
    // this block's.
    if profile == N42HeaderProfile::Gov5H2
        && let Some(root) = header.withdrawals_root
        && root != gov5_rewards_root(rewards.iter().copied())
        && !(rewards.is_empty() && root == alloy_consensus::EMPTY_ROOT_HASH)
    {
        return Err(BlockBodyError::RewardsRootMismatch);
    }
    let withdrawals = rewards_to_withdrawals(&rewards)
        .map_err(|error| BlockBodyError::InvalidRewards(error.to_string()))?;
    Ok(CompactBlockBody {
        block_hash: keccak256(header_rlp),
        header,
        header_rlp,
        hashes,
        rewards,
        withdrawals,
        bal,
        verifiers_rlp,
        rewards_rlp,
        fill,
    })
}

/// Puts the gov5 body back together from a compact one and the transactions
/// it named, in their EIP-2718 form.
///
/// What a follower that only ever saw the compact body answers
/// `block_by_hash` and a range request with -- the same bytes the producer
/// put on the wire, since every part but the transactions travelled whole
/// and the transactions are re-encoded exactly as `encode_block_rlp_raw`
/// encodes them.
pub fn rebuild_gov5_body(compact: &CompactBlockBody<'_>, transactions: &[alloy_primitives::Bytes]) -> Vec<u8> {
    let items_length: usize = transactions.iter().map(Encodable::length).sum();
    let transactions_length = RlpHeader { list: true, payload_length: items_length }.length_with_payload();
    let bal_length = compact.bal.map_or(0, |bal| alloy_primitives::Bytes::copy_from_slice(bal).length());
    let payload_length = compact.header_rlp.len()
        + transactions_length
        + compact.verifiers_rlp.len()
        + compact.rewards_rlp.len()
        + bal_length;
    let mut out = Vec::with_capacity(payload_length + 16);
    RlpHeader { list: true, payload_length }.encode(&mut out);
    out.extend_from_slice(compact.header_rlp);
    RlpHeader { list: true, payload_length: items_length }.encode(&mut out);
    for raw in transactions {
        raw.encode(&mut out);
    }
    out.extend_from_slice(compact.verifiers_rlp);
    out.extend_from_slice(compact.rewards_rlp);
    if let Some(bal) = compact.bal {
        alloy_primitives::Bytes::copy_from_slice(bal).encode(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_body::encode_block_rlp_raw;
    use alloy_primitives::Bytes;

    fn header() -> Header {
        Header {
            number: 41,
            gas_used: 21_000,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            ..Default::default()
        }
    }

    fn transactions() -> Vec<Bytes> {
        vec![
            Bytes::from_static(&[0x02, 0x01, 0x02, 0x03]),
            Bytes::from_static(&[0xf8, 0x02, 0x11, 0x22]),
            Bytes::from_static(&[0x50, 0x09]),
        ]
    }

    #[test]
    fn a_compact_body_round_trips_and_names_the_same_block() {
        let txs = transactions();
        let hashes: Vec<B256> = txs.iter().map(keccak256).collect();
        let body = encode_block_rlp_raw(&header(), &txs, &[], None);
        let compact = encode_compact_body(&body, &hashes, N42HeaderProfile::Ethereum).expect("encodes");
        assert!(is_compact_body(&compact));
        assert!(!is_compact_body(&body));
        assert!(
            compact.len() < body.len() || txs.len() < 8,
            "a real block's compact body is the smaller one"
        );
        let decoded = decode_compact_body(&compact, N42HeaderProfile::Ethereum).expect("decodes");
        assert_eq!(decoded.hashes, hashes);
        assert_eq!(decoded.header, header());
        let (hash, header_only) =
            decode_compact_body_header(&compact, N42HeaderProfile::Ethereum).expect("decodes");
        assert_eq!(hash, decoded.block_hash);
        assert_eq!(header_only, decoded.header);
        assert_eq!(hash, header().hash_slow());
        // And the gov5 body it stands for is the one that was sent, byte for
        // byte, so a follower that only saw this can still serve its peers.
        assert_eq!(rebuild_gov5_body(&decoded, &txs), body);
    }

    #[test]
    fn a_truncated_padded_or_mistagged_compact_body_is_refused() {
        let txs = transactions();
        let hashes: Vec<B256> = txs.iter().map(keccak256).collect();
        let body = encode_block_rlp_raw(&header(), &txs, &[], None);
        let frame = encode_compact_body(&body, &hashes, N42HeaderProfile::Ethereum).expect("encodes");
        assert!(decode_compact_body(&frame[..frame.len() - 1], N42HeaderProfile::Ethereum).is_err());
        let mut padded = frame.clone();
        padded.push(0);
        assert!(decode_compact_body(&padded, N42HeaderProfile::Ethereum).is_err());
        let mut wrong_version = frame.clone();
        wrong_version[MAGIC.len()] = VERSION + 1;
        assert!(decode_compact_body(&wrong_version, N42HeaderProfile::Ethereum).is_err());
        assert!(decode_compact_body_header(&wrong_version, N42HeaderProfile::Ethereum).is_err());
        let mut wrong_magic = frame;
        wrong_magic[0] = b'X';
        assert!(decode_compact_body(&wrong_magic, N42HeaderProfile::Ethereum).is_err());
        assert!(!is_compact_body(&wrong_magic));
        // And a gov5 body is not a compact one however it is read.
        assert!(decode_compact_body(&body, N42HeaderProfile::Ethereum).is_err());
    }

    #[test]
    fn a_fill_round_trips_and_only_a_well_formed_one_is_read() {
        let txs = transactions();
        let hashes: Vec<B256> = txs.iter().map(keccak256).collect();
        let body = encode_block_rlp_raw(&header(), &txs, &[], None);
        let frame = encode_compact_body(&body, &hashes, N42HeaderProfile::Ethereum).expect("encodes");
        assert!(decode_compact_body(&frame, N42HeaderProfile::Ethereum).expect("decodes").fill.is_empty());

        // A frame with no fill is the frame itself, byte for byte.
        assert_eq!(with_fill(&frame, &[]), frame);

        let filled = with_fill(&frame, &[(0, txs[0].clone()), (2, txs[2].clone())]);
        let decoded = decode_compact_body(&filled, N42HeaderProfile::Ethereum).expect("decodes");
        assert_eq!(decoded.hashes, hashes, "the frame under the fill is unchanged");
        assert_eq!(decoded.fill.len(), 2);
        assert_eq!(decoded.fill[0], (0, &txs[0][..]));
        assert_eq!(decoded.fill[1], (2, &txs[2][..]));

        // Out of order, repeated, out of range, and truncated: all refused.
        assert!(decode_compact_body(
            &with_fill(&frame, &[(2, txs[2].clone()), (0, txs[0].clone())]),
            N42HeaderProfile::Ethereum
        )
        .is_err());
        assert!(decode_compact_body(
            &with_fill(&frame, &[(1, txs[1].clone()), (1, txs[1].clone())]),
            N42HeaderProfile::Ethereum
        )
        .is_err());
        assert!(decode_compact_body(
            &with_fill(&frame, &[(9, txs[0].clone())]),
            N42HeaderProfile::Ethereum
        )
        .is_err());
        assert!(decode_compact_body(&filled[..filled.len() - 1], N42HeaderProfile::Ethereum).is_err());
        let mut wrong_marker = filled.clone();
        wrong_marker[frame.len()] = FILL_PRESENT + 1;
        assert!(decode_compact_body(&wrong_marker, N42HeaderProfile::Ethereum).is_err());
    }

    /// Defect 18: fills across rounds converge. The queue here loses a
    /// transaction between rounds, so the second round asks for a position
    /// the first did not; with each answer merged into the frame of record,
    /// the next miss report is empty. Applied to the frame as it arrived
    /// (the old road), the second answer drops the first and the round
    /// after asks for round one's positions again -- the alternation
    /// loop249 saw.
    #[test]
    fn fills_merged_into_the_frame_of_record_converge() {
        let txs = transactions();
        let hashes: Vec<B256> = txs.iter().map(keccak256).collect();
        let body = encode_block_rlp_raw(&header(), &txs, &[], None);
        let frame = encode_compact_body(&body, &hashes, N42HeaderProfile::Ethereum).expect("encodes");
        // What the assembler asks for: every position neither its queue
        // holds nor the frame's fill covers.
        let misses = |frame: &[u8], queue: &[usize]| -> Vec<usize> {
            let decoded = decode_compact_body(frame, N42HeaderProfile::Ethereum).expect("decodes");
            let covered: Vec<usize> = decoded.fill.iter().map(|(i, _)| *i).collect();
            (0..decoded.hashes.len()).filter(|i| !queue.contains(i) && !covered.contains(i)).collect()
        };
        let supply = |indices: &[usize]| -> Vec<(usize, alloy_primitives::Bytes)> {
            indices.iter().map(|&i| (i, txs[i].clone())).collect()
        };
        assert!(txs.len() >= 3);
        let last = txs.len() - 1;
        let mut queue: Vec<usize> = (1..txs.len()).collect();
        let first = misses(&frame, &queue);
        assert_eq!(first, vec![0]);
        let mut record = merge_fill(&frame, &supply(&first)).expect("merges");
        assert!(misses(&record, &queue).is_empty(), "one fill, and nothing is missing");
        // The queue loses a transaction before the assembly runs again.
        queue.retain(|&i| i != last);
        let second = misses(&record, &queue);
        assert_eq!(second, vec![last], "only what the queue lost, not round one's positions");
        record = merge_fill(&record, &supply(&second)).expect("merges");
        assert!(misses(&record, &queue).is_empty(), "converged");
        let decoded = decode_compact_body(&record, N42HeaderProfile::Ethereum).expect("decodes");
        assert_eq!(decoded.fill, vec![(0, &txs[0][..]), (last, &txs[last][..])]);
        // The old road: the second answer applied to the frame as it arrived.
        let old = with_fill(&frame, &supply(&second));
        assert_eq!(misses(&old, &queue), first, "round one's positions asked again");
        // A merge of nothing new is the frame; a position out of range is refused.
        assert_eq!(merge_fill(&frame, &[]).expect("merges"), frame);
        assert_eq!(merge_fill(&record, &supply(&first)).expect("merges"), record);
        assert!(merge_fill(&frame, &[(txs.len(), txs[0].clone())]).is_err());
    }

    #[test]
    fn rewards_that_do_not_hash_to_the_header_are_refused() {
        let rewards = vec![(Address::repeat_byte(3), U256::from(1_000_000_000u64))];
        let mut header = header();
        header.withdrawals_root = Some(gov5_rewards_root(rewards.iter().copied()));
        header.extra_data = crate::header_profile::HeaderExtra::for_view(7).encode();
        header.ommers_hash = B256::ZERO;
        header.receipts_root = crate::header_profile::GOV5_NIL_HASH;
        let txs = transactions();
        let hashes: Vec<B256> = txs.iter().map(keccak256).collect();
        let body = encode_block_rlp_raw(&header, &txs, &rewards, None);
        let frame = encode_compact_body(&body, &hashes, N42HeaderProfile::Gov5H2).expect("encodes");
        assert!(decode_compact_body(&frame, N42HeaderProfile::Gov5H2).is_ok());

        let other = vec![(Address::repeat_byte(4), U256::from(1_000_000_000u64))];
        let wrong = encode_block_rlp_raw(&header, &txs, &other, None);
        let frame = encode_compact_body(&wrong, &hashes, N42HeaderProfile::Gov5H2).expect("encodes");
        assert_eq!(
            decode_compact_body(&frame, N42HeaderProfile::Gov5H2).unwrap_err(),
            BlockBodyError::RewardsRootMismatch
        );
    }
}

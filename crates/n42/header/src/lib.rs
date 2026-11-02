// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42's block header: Ethereum's fields 1-23 plus gov5's
//! `MobileRegistryRoot` at RLP element 24 (`docs/HEADER_FIELD_PARITY.md`).
//!
//! The RLP is gov5's (`common/block/header.go`, struct tags
//! `rlp:"optional,nil"`), byte for byte: every optional field up to the last
//! one that is set is written, an unset one before it as the empty string
//! `0x80`, and nothing after it. A header with no such gap and no root is
//! exactly alloy's encoding, so an Ethereum-shaped header keeps its hash.
//!
//! The empty string is also how RLP writes the integer zero, so on decode a
//! `0x80` in an integer position reads as `Some(0)` (alloy's reading) and in
//! a hash position as `None`. Both re-encode to the same `0x80`; the bytes,
//! and therefore the hash, round-trip.

extern crate alloc;

use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, BlockHash, BlockNumber, Bloom, Bytes, Sealable, B256, B64, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, EMPTY_STRING_CODE};
use serde::{Deserialize, Serialize};

#[cfg(feature = "chainspec")]
mod chainspec;
mod compact;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "chainspec")]
pub use chainspec::N42ChainSpec;
pub use compact::N42_HEADER_COMPACT_MARKER;

/// Optional elements: 16 `base_fee_per_gas` .. 24 `mobile_registry_root`.
const OPTIONAL_FIELDS: usize = 9;

/// N42's block header.
///
/// `inner` holds every Ethereum field, including EIP-7928's
/// `block_access_list_hash` (element 22) and EIP-7843's `slot_number`
/// (element 23); `mobile_registry_root` is element 24, present on the native
/// chain from gov5's Glamsterdam and MobileAnchor forks.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    Serialize,
    Deserialize,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::AsRef,
)]
pub struct N42Header {
    /// Ethereum's header, fields 1-23.
    #[deref]
    #[deref_mut]
    #[as_ref]
    #[serde(flatten)]
    pub inner: Header,
    /// gov5's committed mobile-registry root, RLP element 24.
    #[serde(rename = "mobileRegistryRoot", default, skip_serializing_if = "Option::is_none")]
    pub mobile_registry_root: Option<B256>,
}

impl From<Header> for N42Header {
    fn from(inner: Header) -> Self {
        Self { inner, mobile_registry_root: None }
    }
}

impl From<N42Header> for Header {
    fn from(header: N42Header) -> Self {
        header.inner
    }
}

impl N42Header {
    /// A header with `root` as its `mobile_registry_root`.
    pub const fn new(inner: Header, mobile_registry_root: Option<B256>) -> Self {
        Self { inner, mobile_registry_root }
    }

    /// Ethereum's part of the header, without the registry root.
    pub fn into_inner(self) -> Header {
        self.inner
    }
}

/// Re-seals an Ethereum header as an [`N42Header`] without a registry root.
/// Its hash is unchanged: a header without the root encodes as alloy's.
pub fn seal_from_alloy(sealed: reth_primitives_traits::SealedHeader<Header>) -> reth_primitives_traits::SealedHeader<N42Header> {
    let (header, hash) = sealed.split();
    reth_primitives_traits::SealedHeader::new(N42Header::from(header), hash)
}

/// The Ethereum view of a sealed [`N42Header`], for code that only reads
/// Ethereum's fields. The hash is the N42 header's (the registry root, when
/// set, is part of it).
pub fn seal_to_alloy(sealed: &reth_primitives_traits::SealedHeader<N42Header>) -> reth_primitives_traits::SealedHeader<Header> {
    reth_primitives_traits::SealedHeader::new(sealed.header().inner.clone(), sealed.hash())
}

impl AsRef<Self> for N42Header {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// One optional tail element, as RLP sees it.
#[derive(Clone, Copy)]
enum Tail {
    Int(Option<u64>),
    Hash(Option<B256>),
}

impl Tail {
    const fn is_some(self) -> bool {
        match self {
            Self::Int(v) => v.is_some(),
            Self::Hash(v) => v.is_some(),
        }
    }

    fn length(self) -> usize {
        match self {
            Self::Int(Some(v)) => U256::from(v).length(),
            Self::Hash(Some(v)) => v.length(),
            Self::Int(None) | Self::Hash(None) => 1,
        }
    }

    fn encode(self, out: &mut dyn BufMut) {
        match self {
            Self::Int(Some(v)) => U256::from(v).encode(out),
            Self::Hash(Some(v)) => v.encode(out),
            Self::Int(None) | Self::Hash(None) => out.put_u8(EMPTY_STRING_CODE),
        }
    }
}

impl N42Header {
    fn tail(&self) -> [Tail; OPTIONAL_FIELDS] {
        let h = &self.inner;
        [
            Tail::Int(h.base_fee_per_gas),
            Tail::Hash(h.withdrawals_root),
            Tail::Int(h.blob_gas_used),
            Tail::Int(h.excess_blob_gas),
            Tail::Hash(h.parent_beacon_block_root),
            Tail::Hash(h.requests_hash),
            Tail::Hash(h.block_access_list_hash),
            Tail::Int(h.slot_number),
            Tail::Hash(self.mobile_registry_root),
        ]
    }

    /// The optional elements that are written: up to the last one set.
    fn written_tail(&self) -> impl Iterator<Item = Tail> {
        let tail = self.tail();
        let n = tail.iter().rposition(|t| t.is_some()).map_or(0, |i| i + 1);
        tail.into_iter().take(n)
    }

    fn payload_length(&self) -> usize {
        let h = &self.inner;
        h.parent_hash.length() +
            h.ommers_hash.length() +
            h.beneficiary.length() +
            h.state_root.length() +
            h.transactions_root.length() +
            h.receipts_root.length() +
            h.logs_bloom.length() +
            h.difficulty.length() +
            U256::from(h.number).length() +
            U256::from(h.gas_limit).length() +
            U256::from(h.gas_used).length() +
            h.timestamp.length() +
            h.extra_data.length() +
            h.mix_hash.length() +
            h.nonce.length() +
            self.written_tail().map(Tail::length).sum::<usize>()
    }

    /// The header hash: keccak256 of its RLP.
    pub fn hash_slow(&self) -> B256 {
        let mut out = Vec::with_capacity(self.length());
        self.encode(&mut out);
        keccak256(&out)
    }
}

impl Encodable for N42Header {
    fn encode(&self, out: &mut dyn BufMut) {
        alloy_rlp::Header { list: true, payload_length: self.payload_length() }.encode(out);
        let h = &self.inner;
        h.parent_hash.encode(out);
        h.ommers_hash.encode(out);
        h.beneficiary.encode(out);
        h.state_root.encode(out);
        h.transactions_root.encode(out);
        h.receipts_root.encode(out);
        h.logs_bloom.encode(out);
        h.difficulty.encode(out);
        U256::from(h.number).encode(out);
        U256::from(h.gas_limit).encode(out);
        U256::from(h.gas_used).encode(out);
        h.timestamp.encode(out);
        h.extra_data.encode(out);
        h.mix_hash.encode(out);
        h.nonce.encode(out);
        for t in self.written_tail() {
            t.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload = self.payload_length();
        payload + alloy_rlp::length_of_length(payload)
    }
}

/// A hash element: `0x80` reads as absent.
fn decode_hash(buf: &mut &[u8]) -> alloy_rlp::Result<Option<B256>> {
    if buf.first() == Some(&EMPTY_STRING_CODE) {
        *buf = &buf[1..];
        return Ok(None);
    }
    B256::decode(buf).map(Some)
}

impl Decodable for N42Header {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_head = alloy_rlp::Header::decode(buf)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if buf.len() < rlp_head.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let (mut payload, rest) = buf.split_at(rlp_head.payload_length);
        let p = &mut payload;
        let mut h = Header {
            parent_hash: Decodable::decode(p)?,
            ommers_hash: Decodable::decode(p)?,
            beneficiary: Decodable::decode(p)?,
            state_root: Decodable::decode(p)?,
            transactions_root: Decodable::decode(p)?,
            receipts_root: Decodable::decode(p)?,
            logs_bloom: Decodable::decode(p)?,
            difficulty: Decodable::decode(p)?,
            number: u64::decode(p)?,
            gas_limit: u64::decode(p)?,
            gas_used: u64::decode(p)?,
            timestamp: Decodable::decode(p)?,
            extra_data: Decodable::decode(p)?,
            mix_hash: Decodable::decode(p)?,
            nonce: B64::decode(p)?,
            ..Default::default()
        };
        let mut root = None;
        // Elements 17, 20, 21, 22, 24 are hashes.
        let mut last_was_empty_hash = false;
        for i in 0..OPTIONAL_FIELDS {
            if p.is_empty() {
                break;
            }
            let empty = p.first() == Some(&EMPTY_STRING_CODE);
            match i {
                0 => h.base_fee_per_gas = Some(u64::decode(p)?),
                1 => h.withdrawals_root = decode_hash(p)?,
                2 => h.blob_gas_used = Some(u64::decode(p)?),
                3 => h.excess_blob_gas = Some(u64::decode(p)?),
                4 => h.parent_beacon_block_root = decode_hash(p)?,
                5 => h.requests_hash = decode_hash(p)?,
                6 => h.block_access_list_hash = decode_hash(p)?,
                7 => h.slot_number = Some(u64::decode(p)?),
                _ => root = decode_hash(p)?,
            }
            last_was_empty_hash = empty && matches!(i, 1 | 4 | 5 | 6 | 8);
        }
        if !p.is_empty() {
            // More than 24 elements: a field this type does not know.
            return Err(alloy_rlp::Error::Custom("header has elements after mobileRegistryRoot"));
        }
        if last_was_empty_hash {
            // An empty hash is a gap before a later field; as the last element
            // it would vanish on re-encoding and change the hash.
            return Err(alloy_rlp::Error::Custom("header ends with an empty hash element"));
        }
        *buf = rest;
        Ok(Self { inner: h, mobile_registry_root: root })
    }
}

impl Sealable for N42Header {
    fn hash_slow(&self) -> B256 {
        Self::hash_slow(self)
    }
}

impl alloy_consensus::BlockHeader for N42Header {
    fn parent_hash(&self) -> B256 {
        self.inner.parent_hash
    }
    fn ommers_hash(&self) -> B256 {
        self.inner.ommers_hash
    }
    fn beneficiary(&self) -> Address {
        self.inner.beneficiary
    }
    fn state_root(&self) -> B256 {
        self.inner.state_root
    }
    fn transactions_root(&self) -> B256 {
        self.inner.transactions_root
    }
    fn receipts_root(&self) -> B256 {
        self.inner.receipts_root
    }
    fn withdrawals_root(&self) -> Option<B256> {
        self.inner.withdrawals_root
    }
    fn logs_bloom(&self) -> Bloom {
        self.inner.logs_bloom
    }
    fn difficulty(&self) -> U256 {
        self.inner.difficulty
    }
    fn number(&self) -> BlockNumber {
        self.inner.number
    }
    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit
    }
    fn gas_used(&self) -> u64 {
        self.inner.gas_used
    }
    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }
    fn mix_hash(&self) -> Option<B256> {
        Some(self.inner.mix_hash)
    }
    fn nonce(&self) -> Option<B64> {
        Some(self.inner.nonce)
    }
    fn base_fee_per_gas(&self) -> Option<u64> {
        self.inner.base_fee_per_gas
    }
    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used
    }
    fn excess_blob_gas(&self) -> Option<u64> {
        self.inner.excess_blob_gas
    }
    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }
    fn requests_hash(&self) -> Option<B256> {
        self.inner.requests_hash
    }
    fn block_access_list_hash(&self) -> Option<B256> {
        self.inner.block_access_list_hash
    }
    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number
    }
    fn extra_data(&self) -> &Bytes {
        &self.inner.extra_data
    }
}

impl reth_primitives_traits::InMemorySize for N42Header {
    fn size(&self) -> usize {
        reth_primitives_traits::InMemorySize::size(&self.inner) + core::mem::size_of::<Option<B256>>()
    }
}

impl reth_primitives_traits::BlockHeader for N42Header {}

reth_codecs::impl_compression_for_compact!(N42Header);

impl reth_primitives_traits::header::HeaderMut for N42Header {
    fn set_parent_hash(&mut self, hash: BlockHash) {
        self.inner.parent_hash = hash;
    }
    fn set_block_number(&mut self, number: BlockNumber) {
        self.inner.number = number;
    }
    fn set_timestamp(&mut self, timestamp: u64) {
        self.inner.timestamp = timestamp;
    }
    fn set_state_root(&mut self, state_root: B256) {
        self.inner.state_root = state_root;
    }
    fn set_difficulty(&mut self, difficulty: U256) {
        self.inner.difficulty = difficulty;
    }
    fn set_mix_hash(&mut self, mix_hash: B256) {
        self.inner.mix_hash = mix_hash;
    }
    fn set_extra_data(&mut self, extra_data: Bytes) {
        self.inner.extra_data = extra_data;
    }
    fn set_parent_beacon_block_root(&mut self, parent_beacon_block_root: Option<B256>) {
        self.inner.parent_beacon_block_root = parent_beacon_block_root;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            number: 1001,
            gas_limit: 30_000_000,
            extra_data: Bytes::from_static(&[0xab; 40]),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(B256::repeat_byte(1)),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(2)),
            requests_hash: Some(B256::repeat_byte(3)),
            ..Default::default()
        }
    }

    fn roundtrip(h: &N42Header) -> N42Header {
        let enc = alloy_rlp::encode(h);
        assert_eq!(enc.len(), h.length());
        let back = N42Header::decode(&mut enc.as_slice()).expect("decodes");
        assert_eq!(alloy_rlp::encode(&back), enc, "re-encodes byte for byte");
        back
    }

    #[test]
    fn without_a_root_or_a_gap_it_is_alloys_encoding() {
        for inner in [
            sample(),
            Header { block_access_list_hash: Some(B256::repeat_byte(4)), slot_number: Some(1001), ..sample() },
            Header::default(),
        ] {
            let n42 = N42Header::from(inner.clone());
            assert_eq!(alloy_rlp::encode(&n42), alloy_rlp::encode(&inner));
            assert_eq!(n42.hash_slow(), inner.hash_slow());
            assert_eq!(roundtrip(&n42), n42);
        }
    }

    #[test]
    fn a_root_without_an_access_list_hash_writes_gov5s_gap() {
        let h = N42Header {
            inner: Header { slot_number: Some(1001), ..sample() },
            mobile_registry_root: Some(B256::repeat_byte(0x42)),
        };
        let back = roundtrip(&h);
        assert_eq!(back, h);
        assert_ne!(h.hash_slow(), N42Header::from(h.inner.clone()).hash_slow());
    }

    #[test]
    fn a_zero_integer_before_a_later_field_round_trips_its_bytes() {
        // `blob_gas_used: None` before a set field writes 0x80, which reads
        // back as Some(0): different value, same bytes, same hash.
        let h = N42Header {
            inner: Header { blob_gas_used: None, ..sample() },
            mobile_registry_root: None,
        };
        let back = roundtrip(&h);
        assert_eq!(back.blob_gas_used, Some(0));
        assert_eq!(back.hash_slow(), h.hash_slow());
    }

    #[test]
    fn a_25th_element_is_refused() {
        let h = N42Header {
            inner: Header { slot_number: Some(1), ..sample() },
            mobile_registry_root: Some(B256::ZERO),
        };
        let enc = alloy_rlp::encode(&h);
        // Re-wrap the payload with one extra element.
        let mut payload = enc[alloy_rlp::length_of_length(h.payload_length())..].to_vec();
        payload.push(0x01);
        let mut bad = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut bad);
        bad.extend_from_slice(&payload);
        assert!(N42Header::decode(&mut bad.as_slice()).is_err());
    }

    #[test]
    fn a_trailing_empty_hash_is_refused() {
        // 21 elements ending in an empty requests hash: not what any encoder
        // writes for a header, and it would re-encode one element shorter.
        let inner = Header { requests_hash: None, ..sample() };
        let mut payload = Vec::new();
        let n42 = N42Header::from(inner);
        let enc = alloy_rlp::encode(&n42);
        payload.extend_from_slice(&enc[alloy_rlp::length_of_length(n42.payload_length())..]);
        payload.push(EMPTY_STRING_CODE);
        let mut bad = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut bad);
        bad.extend_from_slice(&payload);
        assert!(N42Header::decode(&mut bad.as_slice()).is_err());
    }

    #[test]
    fn serde_names_the_root_like_gov5() {
        let h = N42Header { inner: sample(), mobile_registry_root: Some(B256::repeat_byte(0x42)) };
        let json = serde_json::to_value(&h).expect("serializes");
        assert!(json.get("mobileRegistryRoot").is_some());
        let back: N42Header = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, h);
        let plain = serde_json::to_value(N42Header::from(sample())).expect("serializes");
        assert!(plain.get("mobileRegistryRoot").is_none());
    }
}

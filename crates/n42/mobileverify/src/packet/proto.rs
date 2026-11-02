// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's protobuf messages (`proto/types_pb/types.proto` and the field set
//! of the generated `types.pb.go`, which adds `Header` fields 24 and 25),
//! declared with explicit tags so no protoc step is needed. Fields are listed
//! in tag order, which is the order Go's `proto.Marshal` writes them.
//!
//! Word mapping (`common/utils/util.go`): a hash is big-endian u64 chunks,
//! `hash[0:8]` → `hi.hi`, `[8:16]` → `hi.lo`, `[16:24]` → `lo.hi`,
//! `[24:32]` → `lo.lo`; a uint256 puts its most significant word in `hi.hi`;
//! an address is `hi.hi = [0:8]`, `hi.lo = [8:16]`, `lo = [16:20]` (u32).

#![allow(missing_docs)]

use alloy_primitives::{Address, B256, Bloom, U256};

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H128 {
    #[prost(uint64, tag = "1")]
    pub hi: u64,
    #[prost(uint64, tag = "2")]
    pub lo: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H160 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H128>,
    #[prost(uint32, tag = "2")]
    pub lo: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H256 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H128>,
    #[prost(message, optional, tag = "2")]
    pub lo: Option<H128>,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H384 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H256>,
    #[prost(message, optional, tag = "2")]
    pub lo: Option<H128>,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H768 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H384>,
    #[prost(message, optional, tag = "2")]
    pub lo: Option<H384>,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H512 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H256>,
    #[prost(message, optional, tag = "2")]
    pub lo: Option<H256>,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H1024 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H512>,
    #[prost(message, optional, tag = "2")]
    pub lo: Option<H512>,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct H2048 {
    #[prost(message, optional, tag = "1")]
    pub hi: Option<H1024>,
    #[prost(message, optional, tag = "2")]
    pub lo: Option<H1024>,
}

/// `types_pb.Header`.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct PbHeader {
    #[prost(message, optional, tag = "1")]
    pub parent_hash: Option<H256>,
    #[prost(message, optional, tag = "2")]
    pub coinbase: Option<H160>,
    #[prost(message, optional, tag = "3")]
    pub root: Option<H256>,
    #[prost(message, optional, tag = "4")]
    pub tx_hash: Option<H256>,
    #[prost(message, optional, tag = "5")]
    pub receipt_hash: Option<H256>,
    #[prost(message, optional, tag = "6")]
    pub difficulty: Option<H256>,
    #[prost(message, optional, tag = "7")]
    pub number: Option<H256>,
    #[prost(uint64, tag = "8")]
    pub gas_limit: u64,
    #[prost(uint64, tag = "9")]
    pub gas_used: u64,
    #[prost(uint64, tag = "10")]
    pub time: u64,
    #[prost(uint64, tag = "11")]
    pub nonce: u64,
    #[prost(message, optional, tag = "12")]
    pub base_fee: Option<H256>,
    #[prost(bytes = "vec", tag = "13")]
    pub extra: Vec<u8>,
    /// Deprecated, never written by gov5; tolerated on decode.
    #[prost(message, optional, tag = "14")]
    pub signature: Option<H768>,
    #[prost(message, optional, tag = "15")]
    pub bloom: Option<H2048>,
    #[prost(message, optional, tag = "16")]
    pub mix_digest: Option<H256>,
    #[prost(uint64, tag = "17")]
    pub blob_gas_used: u64,
    #[prost(uint64, tag = "18")]
    pub excess_blob_gas: u64,
    /// Never written by gov5's header; tolerated on decode.
    #[prost(message, optional, tag = "19")]
    pub lt_hash_root: Option<H256>,
    #[prost(message, optional, tag = "20")]
    pub uncle_hash: Option<H256>,
    #[prost(message, optional, tag = "21")]
    pub withdrawals_hash: Option<H256>,
    #[prost(message, optional, tag = "22")]
    pub parent_beacon_root: Option<H256>,
    #[prost(message, optional, tag = "23")]
    pub requests_hash: Option<H256>,
    #[prost(bool, tag = "24")]
    pub has_blob_gas_used: bool,
    #[prost(bool, tag = "25")]
    pub has_excess_blob_gas: bool,
}

/// `types_pb.AccessTuple`.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct PbAccessTuple {
    #[prost(message, optional, tag = "1")]
    pub address: Option<H160>,
    #[prost(message, repeated, tag = "2")]
    pub storage_keys: Vec<H256>,
}

/// `types_pb.Transaction`.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct PbTransaction {
    #[prost(uint64, tag = "1")]
    pub r#type: u64,
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    #[prost(message, optional, tag = "3")]
    pub gas_price: Option<H256>,
    #[prost(uint64, tag = "4")]
    pub gas: u64,
    #[prost(message, optional, tag = "5")]
    pub fee_per_gas: Option<H256>,
    #[prost(message, optional, tag = "6")]
    pub priority_fee_per_gas: Option<H256>,
    #[prost(message, optional, tag = "7")]
    pub value: Option<H256>,
    #[prost(bytes = "vec", tag = "8")]
    pub data: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub sign: Vec<u8>,
    #[prost(message, optional, tag = "10")]
    pub to: Option<H160>,
    #[prost(message, optional, tag = "11")]
    pub from: Option<H160>,
    #[prost(uint64, tag = "12")]
    pub chain_id: u64,
    #[prost(message, optional, tag = "13")]
    pub hash: Option<H256>,
    #[prost(message, optional, tag = "14")]
    pub r: Option<H256>,
    #[prost(message, optional, tag = "15")]
    pub s: Option<H256>,
    #[prost(message, optional, tag = "16")]
    pub v: Option<H256>,
    #[prost(uint32, tag = "17")]
    pub pq_sig_algo: u32,
    #[prost(uint32, tag = "18")]
    pub pq_pub_key_mode: u32,
    #[prost(bytes = "vec", tag = "19")]
    pub pq_pub_key_data: Vec<u8>,
    #[prost(bytes = "vec", tag = "20")]
    pub pq_signature: Vec<u8>,
    #[prost(message, optional, tag = "21")]
    pub blob_fee_cap: Option<H256>,
    #[prost(message, repeated, tag = "22")]
    pub blob_hashes: Vec<H256>,
    #[prost(message, repeated, tag = "23")]
    pub access_list: Vec<PbAccessTuple>,
}

fn be8(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[..8]);
    u64::from_be_bytes(w)
}

fn h128(hi: &[u8], lo: &[u8]) -> H128 {
    H128 { hi: be8(hi), lo: be8(lo) }
}

/// `ConvertHashToH256`.
pub fn hash_to_h256(h: &B256) -> H256 {
    H256 { hi: Some(h128(&h[0..8], &h[8..16])), lo: Some(h128(&h[16..24], &h[24..32])) }
}

/// `ConvertH256ToHash` (an absent part reads as zero).
pub fn h256_to_hash(h: Option<&H256>) -> B256 {
    let mut out = [0u8; 32];
    if let Some(h) = h {
        let hi = h.hi.unwrap_or_default();
        let lo = h.lo.unwrap_or_default();
        out[0..8].copy_from_slice(&hi.hi.to_be_bytes());
        out[8..16].copy_from_slice(&hi.lo.to_be_bytes());
        out[16..24].copy_from_slice(&lo.hi.to_be_bytes());
        out[24..32].copy_from_slice(&lo.lo.to_be_bytes());
    }
    B256::from(out)
}

/// `ConvertUint256IntToH256`.
pub const fn u256_to_h256(v: &U256) -> H256 {
    let w = v.as_limbs();
    H256 { hi: Some(H128 { hi: w[3], lo: w[2] }), lo: Some(H128 { hi: w[1], lo: w[0] }) }
}

/// `ConvertH256ToUint256Int` (absent → zero).
pub fn h256_to_u256(h: Option<&H256>) -> U256 {
    let Some(h) = h else { return U256::ZERO };
    let hi = h.hi.unwrap_or_default();
    let lo = h.lo.unwrap_or_default();
    U256::from_limbs([lo.lo, lo.hi, hi.lo, hi.hi])
}

/// `ConvertAddressToH160`.
pub fn address_to_h160(a: &Address) -> H160 {
    let b = a.as_slice();
    let mut lo = [0u8; 4];
    lo.copy_from_slice(&b[16..20]);
    H160 { hi: Some(h128(&b[0..8], &b[8..16])), lo: u32::from_be_bytes(lo) }
}

/// `ConvertH160toAddress` (absent → zero).
pub fn h160_to_address(h: Option<&H160>) -> Address {
    let mut out = [0u8; 20];
    if let Some(h) = h {
        let hi = h.hi.unwrap_or_default();
        out[0..8].copy_from_slice(&hi.hi.to_be_bytes());
        out[8..16].copy_from_slice(&hi.lo.to_be_bytes());
        out[16..20].copy_from_slice(&h.lo.to_be_bytes());
    }
    Address::from(out)
}

fn bytes_to_h512(b: &[u8]) -> H512 {
    H512 {
        hi: Some(H256 { hi: Some(h128(&b[0..8], &b[8..16])), lo: Some(h128(&b[16..24], &b[24..32])) }),
        lo: Some(H256 { hi: Some(h128(&b[32..40], &b[40..48])), lo: Some(h128(&b[48..56], &b[56..64])) }),
    }
}

fn h512_to_bytes(h: Option<&H512>, out: &mut [u8]) {
    let Some(h) = h else { return };
    out[0..32].copy_from_slice(h256_to_hash(h.hi.as_ref()).as_slice());
    out[32..64].copy_from_slice(h256_to_hash(h.lo.as_ref()).as_slice());
}

/// `ConvertBytesToH2048`.
pub fn bloom_to_h2048(b: &Bloom) -> H2048 {
    let b = b.as_slice();
    H2048 {
        hi: Some(H1024 { hi: Some(bytes_to_h512(&b[0..64])), lo: Some(bytes_to_h512(&b[64..128])) }),
        lo: Some(H1024 { hi: Some(bytes_to_h512(&b[128..192])), lo: Some(bytes_to_h512(&b[192..256])) }),
    }
}

/// `ConvertH2048ToBloom` (absent parts read as zero; gov5 panics on a
/// missing bloom, this does not).
pub fn h2048_to_bloom(h: Option<&H2048>) -> Bloom {
    let mut out = [0u8; 256];
    if let Some(h) = h {
        if let Some(hi) = &h.hi {
            h512_to_bytes(hi.hi.as_ref(), &mut out[0..64]);
            h512_to_bytes(hi.lo.as_ref(), &mut out[64..128]);
        }
        if let Some(lo) = &h.lo {
            h512_to_bytes(lo.hi.as_ref(), &mut out[128..192]);
            h512_to_bytes(lo.lo.as_ref(), &mut out[192..256]);
        }
    }
    Bloom::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn word_mapping() {
        let h = B256::from(core::array::from_fn::<u8, 32, _>(|i| i as u8));
        let p = hash_to_h256(&h);
        assert_eq!(p.hi.unwrap().hi, 0x0001_0203_0405_0607);
        assert_eq!(p.lo.unwrap().lo, 0x1819_1a1b_1c1d_1e1f);
        assert_eq!(h256_to_hash(Some(&p)), h);
        let v = U256::from(0x1234u64) << 200;
        assert_eq!(h256_to_u256(Some(&u256_to_h256(&v))), v);
        assert_eq!(u256_to_h256(&U256::from(5u64)).lo.unwrap().lo, 5);
        let a = Address::from(core::array::from_fn::<u8, 20, _>(|i| i as u8 + 1));
        assert_eq!(h160_to_address(Some(&address_to_h160(&a))), a);
        let mut bb = [0u8; 256];
        bb[0] = 1;
        bb[255] = 2;
        bb[100] = 3;
        let bloom = Bloom::from(bb);
        assert_eq!(h2048_to_bloom(Some(&bloom_to_h2048(&bloom))), bloom);
    }

    #[test]
    fn zero_hash_is_two_empty_submessages() {
        // Go writes non-nil empty H128s: `0a 00 12 00`.
        assert_eq!(hash_to_h256(&B256::ZERO).encode_to_vec(), vec![0x0a, 0x00, 0x12, 0x00]);
    }
}

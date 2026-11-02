// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's header `Marshal`/`Unmarshal` (`common/block/header.go:294-388`),
//! the encoding a `StreamPacket` carries (not RLP):
//!
//! `proto(types_pb.Header) ‖ "N42H" ‖ flags ‖ UncleHash32 ‖ [WithdrawalsHash32
//! 0x01] ‖ [ParentBeaconRoot32 0x02] ‖ [RequestsHash32 0x04] ‖ [BlobGasUsed LE8
//! 0x08] ‖ [ExcessBlobGas LE8 0x10] ‖ [BlockAccessListHash32 0x20] ‖
//! [MobileRegistryRoot32 0x40] ‖ [SlotNumber LE8 0x80] ‖ protoLen u32 LE`.
//!
//! Decoding follows Go's order: the trailer is parsed first, then the
//! protobuf fields overwrite it: `UncleHash` always comes from proto field 20
//! (or the empty-uncles hash when absent), `WithdrawalsHash`,
//! `ParentBeaconRoot` and `RequestsHash` from the proto when present there,
//! blob gas when `Has*` is set or the value is non-zero, and `BaseFee` only
//! from the proto.

use alloy_consensus::Header;
use alloy_primitives::{B64, B256, U256, b256};
use n42_header::N42Header;
use prost::Message;

use super::proto::{
    PbHeader, address_to_h160, bloom_to_h2048, h160_to_address, h256_to_hash, h256_to_u256, h2048_to_bloom,
    hash_to_h256, u256_to_h256,
};

/// The trailer magic.
pub const TRAILER_MAGIC: [u8; 4] = *b"N42H";

/// keccak256(rlp([])), gov5's default `UncleHash`.
pub const EMPTY_UNCLE_HASH: B256 = b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

/// A header that does not decode into an [`N42Header`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderCodecError {
    /// gov5's compact storage form (first byte 0xFF) is not a packet form.
    #[error("compact header encoding is not supported")]
    Compact,
    /// The protobuf part does not decode.
    #[error("header protobuf: {0}")]
    Proto(String),
    /// A uint256 field that the Rust header holds as u64 does not fit.
    #[error("header field {0} exceeds 64 bits")]
    Overflow(&'static str),
}

/// gov5 `Header.Marshal()` of an [`N42Header`].
pub fn marshal_header(header: &N42Header) -> Vec<u8> {
    let h = &header.inner;
    let pb = PbHeader {
        parent_hash: Some(hash_to_h256(&h.parent_hash)),
        coinbase: Some(address_to_h160(&h.beneficiary)),
        root: Some(hash_to_h256(&h.state_root)),
        tx_hash: Some(hash_to_h256(&h.transactions_root)),
        receipt_hash: Some(hash_to_h256(&h.receipts_root)),
        difficulty: Some(u256_to_h256(&h.difficulty)),
        number: Some(u256_to_h256(&U256::from(h.number))),
        gas_limit: h.gas_limit,
        gas_used: h.gas_used,
        time: h.timestamp,
        nonce: u64::from_be_bytes(h.nonce.0),
        base_fee: h.base_fee_per_gas.map(|v| u256_to_h256(&U256::from(v))),
        extra: h.extra_data.to_vec(),
        signature: None,
        bloom: Some(bloom_to_h2048(&h.logs_bloom)),
        mix_digest: Some(hash_to_h256(&h.mix_hash)),
        blob_gas_used: h.blob_gas_used.unwrap_or(0),
        excess_blob_gas: h.excess_blob_gas.unwrap_or(0),
        lt_hash_root: None,
        uncle_hash: Some(hash_to_h256(&h.ommers_hash)),
        withdrawals_hash: h.withdrawals_root.as_ref().map(hash_to_h256),
        parent_beacon_root: h.parent_beacon_block_root.as_ref().map(hash_to_h256),
        requests_hash: h.requests_hash.as_ref().map(hash_to_h256),
        has_blob_gas_used: h.blob_gas_used.is_some(),
        has_excess_blob_gas: h.excess_blob_gas.is_some(),
    };
    let mut out = pb.encode_to_vec();
    let proto_len = out.len() as u32;
    out.extend_from_slice(&TRAILER_MAGIC);
    let flags_at = out.len();
    out.push(0);
    out.extend_from_slice(h.ommers_hash.as_slice());
    let mut flags = 0u8;
    if let Some(v) = h.withdrawals_root {
        flags |= 0x01;
        out.extend_from_slice(v.as_slice());
    }
    if let Some(v) = h.parent_beacon_block_root {
        flags |= 0x02;
        out.extend_from_slice(v.as_slice());
    }
    if let Some(v) = h.requests_hash {
        flags |= 0x04;
        out.extend_from_slice(v.as_slice());
    }
    if let Some(v) = h.blob_gas_used {
        flags |= 0x08;
        out.extend_from_slice(&v.to_le_bytes());
    }
    if let Some(v) = h.excess_blob_gas {
        flags |= 0x10;
        out.extend_from_slice(&v.to_le_bytes());
    }
    if let Some(v) = h.block_access_list_hash {
        flags |= 0x20;
        out.extend_from_slice(v.as_slice());
    }
    if let Some(v) = header.mobile_registry_root {
        flags |= 0x40;
        out.extend_from_slice(v.as_slice());
    }
    if let Some(v) = h.slot_number {
        flags |= 0x80;
        out.extend_from_slice(&v.to_le_bytes());
    }
    out[flags_at] = flags;
    out.extend_from_slice(&proto_len.to_le_bytes());
    out
}

#[derive(Default)]
struct Trailer {
    withdrawals: Option<B256>,
    parent_beacon: Option<B256>,
    requests: Option<B256>,
    blob_gas_used: Option<u64>,
    excess_blob_gas: Option<u64>,
    bal: Option<B256>,
    registry_root: Option<B256>,
    slot: Option<u64>,
}

fn read_hash(t: &[u8], pos: &mut usize) -> Option<B256> {
    let v = t.get(*pos..*pos + 32).map(B256::from_slice)?;
    *pos += 32;
    Some(v)
}

fn read_le8(t: &[u8], pos: &mut usize) -> Option<u64> {
    let mut w = [0u8; 8];
    w.copy_from_slice(t.get(*pos..*pos + 8)?);
    *pos += 8;
    Some(u64::from_le_bytes(w))
}

/// gov5 `parseTrailer` over `magic ‖ flags ‖ uncle ‖ fields` (the protoLen
/// already cut off); fields that do not fit are skipped, as in Go.
fn parse_trailer(t: &[u8]) -> Trailer {
    let mut tr = Trailer::default();
    if t.len() < 37 {
        return tr;
    }
    let flags = t[4];
    let mut pos = 5 + 32;
    if flags & 0x01 != 0 {
        tr.withdrawals = read_hash(t, &mut pos);
    }
    if flags & 0x02 != 0 {
        tr.parent_beacon = read_hash(t, &mut pos);
    }
    if flags & 0x04 != 0 {
        tr.requests = read_hash(t, &mut pos);
    }
    if flags & 0x08 != 0 {
        tr.blob_gas_used = read_le8(t, &mut pos);
    }
    if flags & 0x10 != 0 {
        tr.excess_blob_gas = read_le8(t, &mut pos);
    }
    if flags & 0x20 != 0 {
        tr.bal = read_hash(t, &mut pos);
    }
    if flags & 0x40 != 0 {
        tr.registry_root = read_hash(t, &mut pos);
    }
    if flags & 0x80 != 0 {
        tr.slot = read_le8(t, &mut pos);
    }
    tr
}

/// gov5 `Header.Unmarshal` into an [`N42Header`].
pub fn unmarshal_header(data: &[u8]) -> Result<N42Header, HeaderCodecError> {
    if data.first() == Some(&0xFF) {
        return Err(HeaderCodecError::Compact);
    }
    let mut proto = data;
    let mut tr = Trailer::default();
    if data.len() > 41 {
        let n = data.len();
        let proto_len = u32::from_le_bytes([data[n - 4], data[n - 3], data[n - 2], data[n - 1]]) as usize;
        if proto_len < n && proto_len > 0 && proto_len + 4 <= n && data[proto_len..proto_len + 4] == TRAILER_MAGIC {
            proto = &data[..proto_len];
            tr = parse_trailer(&data[proto_len..n - 4]);
        }
    }
    let pb = PbHeader::decode(proto).map_err(|e| HeaderCodecError::Proto(e.to_string()))?;

    let number = h256_to_u256(pb.number.as_ref());
    let number = u64::try_from(number).map_err(|_| HeaderCodecError::Overflow("Number"))?;
    let base_fee = match pb.base_fee.as_ref() {
        Some(b) => Some(u64::try_from(h256_to_u256(Some(b))).map_err(|_| HeaderCodecError::Overflow("BaseFee"))?),
        None => None,
    };
    let blob_gas_used =
        if pb.has_blob_gas_used || pb.blob_gas_used != 0 { Some(pb.blob_gas_used) } else { tr.blob_gas_used };
    let excess_blob_gas =
        if pb.has_excess_blob_gas || pb.excess_blob_gas != 0 { Some(pb.excess_blob_gas) } else { tr.excess_blob_gas };
    let ommers_hash = pb.uncle_hash.as_ref().map_or(EMPTY_UNCLE_HASH, |h| h256_to_hash(Some(h)));
    let pick = |p: Option<&super::proto::H256>, t: Option<B256>| p.map(|h| h256_to_hash(Some(h))).or(t);

    let inner = Header {
        parent_hash: h256_to_hash(pb.parent_hash.as_ref()),
        ommers_hash,
        beneficiary: h160_to_address(pb.coinbase.as_ref()),
        state_root: h256_to_hash(pb.root.as_ref()),
        transactions_root: h256_to_hash(pb.tx_hash.as_ref()),
        receipts_root: h256_to_hash(pb.receipt_hash.as_ref()),
        logs_bloom: h2048_to_bloom(pb.bloom.as_ref()),
        difficulty: h256_to_u256(pb.difficulty.as_ref()),
        number,
        gas_limit: pb.gas_limit,
        gas_used: pb.gas_used,
        timestamp: pb.time,
        extra_data: pb.extra.into(),
        mix_hash: h256_to_hash(pb.mix_digest.as_ref()),
        nonce: B64::from(pb.nonce.to_be_bytes()),
        base_fee_per_gas: base_fee,
        withdrawals_root: pick(pb.withdrawals_hash.as_ref(), tr.withdrawals),
        blob_gas_used,
        excess_blob_gas,
        parent_beacon_block_root: pick(pb.parent_beacon_root.as_ref(), tr.parent_beacon),
        requests_hash: pick(pb.requests_hash.as_ref(), tr.requests),
        block_access_list_hash: tr.bal,
        slot_number: tr.slot,
    };
    Ok(N42Header::new(inner, tr.registry_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bloom, Bytes};

    fn full_header() -> N42Header {
        let mut bloom = [0u8; 256];
        bloom[3] = 0x80;
        let inner = Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash: EMPTY_UNCLE_HASH,
            beneficiary: Address::repeat_byte(2),
            state_root: B256::repeat_byte(3),
            transactions_root: B256::repeat_byte(4),
            receipts_root: B256::repeat_byte(5),
            logs_bloom: Bloom::from(bloom),
            difficulty: U256::ZERO,
            number: 1234,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: Bytes::from(vec![0xAB; 97]),
            mix_hash: B256::repeat_byte(6),
            nonce: B64::ZERO,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(B256::repeat_byte(8)),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(B256::repeat_byte(9)),
            block_access_list_hash: Some(B256::repeat_byte(10)),
            slot_number: Some(77),
        };
        N42Header::new(inner, Some(B256::repeat_byte(11)))
    }

    #[test]
    fn round_trip_every_flag() {
        let h = full_header();
        let enc = marshal_header(&h);
        let n = enc.len();
        let proto_len = u32::from_le_bytes(enc[n - 4..].try_into().unwrap()) as usize;
        assert_eq!(&enc[proto_len..proto_len + 4], b"N42H");
        assert_eq!(enc[proto_len + 4], 0xFF);
        assert_eq!(unmarshal_header(&enc).unwrap(), h);
    }

    #[test]
    fn round_trip_legacy() {
        let mut h = full_header();
        h.mobile_registry_root = None;
        let i = &mut h.inner;
        i.base_fee_per_gas = None;
        i.withdrawals_root = None;
        i.blob_gas_used = None;
        i.excess_blob_gas = None;
        i.parent_beacon_block_root = None;
        i.requests_hash = None;
        i.block_access_list_hash = None;
        i.slot_number = None;
        let enc = marshal_header(&h);
        let n = enc.len();
        let proto_len = u32::from_le_bytes(enc[n - 4..].try_into().unwrap()) as usize;
        assert_eq!(enc[proto_len + 4], 0);
        assert_eq!(n, proto_len + 4 + 1 + 32 + 4);
        assert_eq!(unmarshal_header(&enc).unwrap(), h);
    }

    #[test]
    fn proto_overrides_trailer_uncle() {
        let mut h = full_header();
        h.inner.ommers_hash = B256::repeat_byte(0x42);
        let mut enc = marshal_header(&h);
        let n = enc.len();
        let proto_len = u32::from_le_bytes(enc[n - 4..].try_into().unwrap()) as usize;
        // Corrupt the trailer's copy: the proto's wins.
        enc[proto_len + 5] ^= 0xFF;
        assert_eq!(unmarshal_header(&enc).unwrap().inner.ommers_hash, B256::repeat_byte(0x42));
        assert_eq!(unmarshal_header(&[0xFF, 1]).unwrap_err(), HeaderCodecError::Compact);
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The registry root on the Engine API (`docs/HEADER_FIELD_PARITY.md` 8.4).
//!
//! alloy's payload conversions are generic over the header but know only
//! Ethereum's fields; these wrap them so the root goes into a V4 payload's
//! `mobileRegistryRoot` and comes back out of it, and so does gov5's header
//! with a slot number but no access-list hash (an empty `blockAccessList`,
//! [`ExecutionPayloadV4::block_access_list_hash`]).

use crate::N42Header;
use alloy_consensus::{Block, BlockHeader as _, Transaction};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, B256};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV3, ExecutionPayloadV4,
};

/// The registry root a payload carries: only a V4 payload has one.
pub fn payload_mobile_registry_root(payload: &ExecutionPayload) -> Option<B256> {
    payload.as_v4().and_then(|v4| v4.mobile_registry_root)
}

/// `block` (as alloy's payload conversion rebuilt it) under the payload's
/// registry root.
pub fn block_with_payload_root<T>(block: Block<T>, payload: &ExecutionPayload) -> Block<T, N42Header> {
    block_with_root(block, payload_mobile_registry_root(payload))
}

/// `block` under `root`; its ommers (none, on any chain that has the root)
/// carry no root.
pub fn block_with_root<T>(block: Block<T>, root: Option<B256>) -> Block<T, N42Header> {
    let Block { header, body } = block;
    let alloy_consensus::BlockBody { transactions, ommers, withdrawals } = body;
    Block {
        header: N42Header::new(header, root),
        body: alloy_consensus::BlockBody {
            transactions,
            ommers: ommers.into_iter().map(N42Header::from).collect(),
            withdrawals,
        },
    }
}

/// A header's slot number, access-list hash and registry root in a payload
/// that alloy built from Ethereum's fields alone.
///
/// alloy writes a V4 payload only for a header with an access-list hash; a
/// gov5 header with a slot number (or a root) and no hash is promoted from V3
/// to V4 with an empty access list, and the root is set on every V4 payload.
/// A root on a header that has no V3 fields (no Cancun) cannot be carried and
/// is refused rather than dropped.
pub fn put_header_tail(payload: ExecutionPayload, header: &N42Header) -> Result<ExecutionPayload, RootNotCarried> {
    let needs_v4 = header.slot_number.is_some() || header.mobile_registry_root.is_some();
    let payload = match payload {
        ExecutionPayload::V4(mut v4) => {
            v4.mobile_registry_root = header.mobile_registry_root;
            ExecutionPayload::V4(v4)
        }
        ExecutionPayload::V3(v3) if needs_v4 => ExecutionPayload::V4(v4_from_v3(v3, header)),
        other if header.mobile_registry_root.is_some() => {
            let _ = other;
            return Err(RootNotCarried(header.number));
        }
        other => other,
    };
    Ok(payload)
}

fn v4_from_v3(v3: ExecutionPayloadV3, header: &N42Header) -> ExecutionPayloadV4 {
    ExecutionPayloadV4 {
        payload_inner: v3,
        block_access_list: header
            .block_access_list_hash
            .map_or_else(Bytes::new, |hash| Bytes::copy_from_slice(hash.as_slice())),
        slot_number: header.slot_number.unwrap_or_default(),
        mobile_registry_root: header.mobile_registry_root,
    }
}

/// A header's registry root on a payload that cannot carry it (before V3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("block {0}: a pre-Cancun payload cannot carry the mobile registry root")]
pub struct RootNotCarried(pub u64);

/// alloy's `ExecutionPayload::from_block_unchecked_with_extras` for an
/// [`N42Header`] block, carrying the header's tail
/// ([`put_header_tail`]).
pub fn payload_from_block<T>(
    block_hash: B256,
    block: &Block<T, N42Header>,
    bal: Option<Bytes>,
) -> Result<(ExecutionPayload, ExecutionPayloadSidecar), RootNotCarried>
where
    T: Encodable2718 + Transaction,
{
    let (payload, sidecar) = ExecutionPayload::from_block_unchecked_with_extras(block_hash, block, bal);
    Ok((put_header_tail(payload, &block.header)?, sidecar))
}

/// [`payload_from_block`] as [`ExecutionData`].
pub fn execution_data_from_block<T>(
    block_hash: B256,
    block: &Block<T, N42Header>,
    bal: Option<Bytes>,
) -> Result<ExecutionData, RootNotCarried>
where
    T: Encodable2718 + Transaction,
{
    payload_from_block(block_hash, block, bal).map(|(payload, sidecar)| ExecutionData::new(payload, sidecar))
}

/// Whether the header a payload rebuilds is shaped like `header`'s tail: the
/// timestamp's the caller's, this checks only that the conversion is exact.
pub fn tail_matches(payload: &ExecutionPayload, header: &N42Header) -> bool {
    payload_mobile_registry_root(payload) == header.mobile_registry_root
        && payload.slot_number() == header.slot_number()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, TxEnvelope};
    use alloy_primitives::U256;

    fn header(bal: Option<B256>, slot: Option<u64>, root: Option<B256>) -> N42Header {
        N42Header::new(
            Header {
                number: 1001,
                timestamp: 7,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(7),
                withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::repeat_byte(2)),
                requests_hash: Some(B256::repeat_byte(3)),
                block_access_list_hash: bal,
                slot_number: slot,
                difficulty: U256::ZERO,
                ..Default::default()
            },
            root,
        )
    }

    fn round_trip(mut h: N42Header) {
        // The payload carries the access list, not its hash: a header with a
        // hash is given a list that hashes to it.
        let bal = h.block_access_list_hash.map(|_| Bytes::from_static(&[0xc0]));
        h.block_access_list_hash = bal.as_ref().map(alloy_primitives::keccak256);
        let block: Block<TxEnvelope, N42Header> = Block {
            header: h.clone(),
            body: alloy_consensus::BlockBody { transactions: vec![], ommers: vec![], withdrawals: Some(Default::default()) },
        };
        let hash = h.hash_slow();
        let data = execution_data_from_block(hash, &block, bal).expect("carried");
        assert!(tail_matches(&data.payload, &h));
        // JSON both ways, as the Engine API carries it.
        let json = serde_json::to_string(&data.payload).expect("serializes");
        assert_eq!(json.contains("mobileRegistryRoot"), h.mobile_registry_root.is_some());
        let payload: ExecutionPayload = serde_json::from_str(&json).expect("deserializes");
        let back = payload.clone().try_into_block_with_sidecar::<TxEnvelope>(&data.sidecar).expect("rebuilds");
        let back = block_with_payload_root(back, &payload);
        assert_eq!(back.header.hash_slow(), hash, "{h:?}");
    }

    #[test]
    fn the_header_tail_survives_the_engine_api() {
        let root = Some(B256::repeat_byte(0x42));
        // Ethereum's Cancun/Prague shape, Amsterdam's, and gov5's two
        // Glamsterdam shapes (root without and with an access-list hash).
        round_trip(header(None, None, None));
        round_trip(header(Some(B256::repeat_byte(4)), Some(1001), None));
        round_trip(header(None, Some(1001), None));
        round_trip(header(None, Some(1001), root));
        round_trip(header(Some(B256::repeat_byte(4)), Some(1001), root));
    }

    #[test]
    fn a_root_on_a_v3_payload_is_refused_not_dropped() {
        let json = serde_json::to_value(
            &execution_data_from_block(
                B256::ZERO,
                &Block::<TxEnvelope, N42Header> {
                    header: header(None, None, None),
                    body: alloy_consensus::BlockBody { transactions: vec![], ommers: vec![], withdrawals: Some(Default::default()) },
                },
                None,
            )
            .expect("carried")
            .payload,
        )
        .expect("serializes");
        let mut json = json;
        json["mobileRegistryRoot"] = serde_json::json!(B256::repeat_byte(1));
        assert!(serde_json::from_value::<ExecutionPayload>(json).is_err());
    }
}

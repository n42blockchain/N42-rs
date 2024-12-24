use alloy_primitives::{Address, FixedBytes, B256};
use reth::rpc::types::engine::PayloadAttributes;
use n42_engine_types::N42PayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use std::str::FromStr;
/// Helper function to create a new n42 payload attributes
pub(crate) fn n42_payload_attributes(timestamp: u64) -> N42PayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    N42PayloadBuilderAttributes(EthPayloadBuilderAttributes::new(FixedBytes::from_str("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3").unwrap(), attributes))
}

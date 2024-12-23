use alloy_primitives::{Address, B256};
use reth::rpc::types::engine::PayloadAttributes;
use n42_engine_types::N42PayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;

/// Helper function to create a new n42 payload attributes
pub(crate) fn n42_payload_attributes(timestamp: u64) -> N42PayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };
    N42PayloadBuilderAttributes(EthPayloadBuilderAttributes::new(B256::ZERO, attributes))
}

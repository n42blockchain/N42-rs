use alloy_primitives::{Address, B256};
use reth::rpc::types::engine::PayloadAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;

#[cfg(test)]
pub(crate) fn n42_payload_attributes(timestamp: u64, parent_hash: B256, eth_signer_address: Address) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: eth_signer_address,
        withdrawals: None,

        // for chains that has cancun fork, parent_beacon_block_root must be set to Some, otherwise
        // tests will fail: "failed to resolve pending payload err=EIP-4788 parent beacon block
        // root missing for active Cancun block"
        parent_beacon_block_root: Some(B256::ZERO),
        //parent_beacon_block_root: None,
    };
    EthPayloadBuilderAttributes::new(parent_hash, attributes)
}

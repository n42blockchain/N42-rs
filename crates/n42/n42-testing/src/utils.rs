// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::{Address, B256};
use reth::rpc::types::engine::PayloadAttributes;

#[cfg(test)]
pub(crate) fn n42_payload_attributes(
    timestamp: u64,
    _parent_hash: B256,
    eth_signer_address: Address,
// upstream removed EthPayloadBuilderAttributes; the payload attributes are
// now used directly, and the parent hash travels separately.
) -> PayloadAttributes {
    PayloadAttributes {
        // upstream additions; N42 drives neither
        slot_number: None,
        target_gas_limit: None,
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: eth_signer_address,
        withdrawals: None,

        // for chains that has cancun fork, parent_beacon_block_root must be set to Some, otherwise
        // tests will fail: "failed to resolve pending payload err=EIP-4788 parent beacon block
        // root missing for active Cancun block"
        parent_beacon_block_root: Some(B256::ZERO),
        //parent_beacon_block_root: None,
    }
}

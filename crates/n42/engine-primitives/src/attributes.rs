// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The implementation of the [`PayloadAttributesBuilder`] for the N42 engine service

use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{Address, B256};
use reth_chainspec::EthereumHardforks;
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_payload_primitives::PayloadAttributesBuilder;
use std::sync::Arc;

/// The attributes builder for N42 Ethereum payload.
#[derive(Debug)]
#[non_exhaustive]
pub struct N42PayloadAttributesBuilder<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
    signer_address: Option<Address>,
}

impl<ChainSpec> N42PayloadAttributesBuilder<ChainSpec> {
    /// Creates a new instance of the builder.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            chain_spec,
            signer_address: None,
        }
    }

    /// Creates a new instance of the builder with an optional signer address
    pub const fn new_add_signer(
        chain_spec: Arc<ChainSpec>,
        signer_address: Option<Address>,
    ) -> Self {
        Self {
            chain_spec,
            signer_address,
        }
    }
}

impl<ChainSpec> PayloadAttributesBuilder<EthPayloadAttributes>
    for N42PayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build(&self, timestamp: u64) -> EthPayloadAttributes {
        EthPayloadAttributes {
            timestamp,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: self.signer_address.unwrap_or(Address::ZERO),
            withdrawals: self
                .chain_spec
                .is_shanghai_active_at_timestamp(timestamp)
                .then(Default::default),
            parent_beacon_block_root: self
                .chain_spec
                .is_cancun_active_at_timestamp(timestamp)
                .then(Default::default),
        }
    }
}

pub trait PayloadAttributesBuilderExt<Attributes>:
    PayloadAttributesBuilder<Attributes> + Send + Sync + 'static
{
    fn build_ext(
        &self,
        timestamp: u64,
        withdrawals: Option<Vec<Withdrawal>>,
        prev_randao: B256,
    ) -> Attributes;
}

impl<ChainSpec> PayloadAttributesBuilderExt<EthPayloadAttributes>
    for N42PayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build_ext(
        &self,
        timestamp: u64,
        withdrawals: Option<Vec<Withdrawal>>,
        prev_randao: B256,
    ) -> EthPayloadAttributes {
        let mut payload_attributes = self.build(timestamp);
        payload_attributes.withdrawals = withdrawals;
        payload_attributes.prev_randao = prev_randao;

        payload_attributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::ChainSpec;

    #[test]
    fn test_builder_new() {
        let chain_spec = Arc::new(ChainSpec::default());
        let builder = N42PayloadAttributesBuilder::new(chain_spec.clone());
        assert!(builder.signer_address.is_none());
    }

    #[test]
    fn test_builder_new_with_signer() {
        let chain_spec = Arc::new(ChainSpec::default());
        let signer = Address::from_slice(&[0x42; 20]);
        let builder = N42PayloadAttributesBuilder::new_add_signer(chain_spec.clone(), Some(signer));
        assert_eq!(builder.signer_address, Some(signer));
    }

    #[test]
    fn test_builder_new_with_no_signer() {
        let chain_spec = Arc::new(ChainSpec::default());
        let builder = N42PayloadAttributesBuilder::new_add_signer(chain_spec.clone(), None);
        assert!(builder.signer_address.is_none());
    }

    #[test]
    fn test_build_payload_attributes() {
        let chain_spec = Arc::new(ChainSpec::default());
        let signer = Address::from_slice(&[0x42; 20]);
        let builder = N42PayloadAttributesBuilder::new_add_signer(chain_spec, Some(signer));

        let timestamp = 1700000000u64;
        let attrs = builder.build(timestamp);

        assert_eq!(attrs.timestamp, timestamp);
        assert_eq!(attrs.prev_randao, B256::ZERO);
        assert_eq!(attrs.suggested_fee_recipient, signer);
    }

    #[test]
    fn test_build_payload_attributes_no_signer() {
        let chain_spec = Arc::new(ChainSpec::default());
        let builder = N42PayloadAttributesBuilder::new(chain_spec);

        let timestamp = 1700000000u64;
        let attrs = builder.build(timestamp);

        assert_eq!(attrs.timestamp, timestamp);
        assert_eq!(attrs.suggested_fee_recipient, Address::ZERO);
    }

    #[test]
    fn test_build_ext_with_withdrawals() {
        let chain_spec = Arc::new(ChainSpec::default());
        let signer = Address::from_slice(&[0x42; 20]);
        let builder = N42PayloadAttributesBuilder::new_add_signer(chain_spec, Some(signer));

        let timestamp = 1700000000u64;
        let prev_randao = B256::repeat_byte(0xAB);
        let withdrawals = Some(vec![Withdrawal {
            index: 0,
            validator_index: 1,
            address: Address::ZERO,
            amount: 1000,
        }]);

        let attrs = builder.build_ext(timestamp, withdrawals.clone(), prev_randao);

        assert_eq!(attrs.timestamp, timestamp);
        assert_eq!(attrs.prev_randao, prev_randao);
        assert_eq!(attrs.withdrawals, withdrawals);
    }

    #[test]
    fn test_build_ext_without_withdrawals() {
        let chain_spec = Arc::new(ChainSpec::default());
        let builder = N42PayloadAttributesBuilder::new(chain_spec);

        let timestamp = 1700000000u64;
        let prev_randao = B256::repeat_byte(0xCD);

        let attrs = builder.build_ext(timestamp, None, prev_randao);

        assert_eq!(attrs.timestamp, timestamp);
        assert_eq!(attrs.prev_randao, prev_randao);
        assert!(attrs.withdrawals.is_none());
    }
}

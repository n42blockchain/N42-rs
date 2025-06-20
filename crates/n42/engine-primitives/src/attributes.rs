//! The implementation of the [`PayloadAttributesBuilder`] for the N42 engine service

use alloy_primitives::{Address, B256};
use reth_chainspec::EthereumHardforks;
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_payload_primitives::PayloadAttributesBuilder;
use std::sync::Arc;
use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
};

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
        Self { chain_spec, signer_address: None }
    }

    /// Creates a new instance of the builder with an optional signer address
    pub const fn new_add_signer(chain_spec: Arc<ChainSpec>, signer_address: Option<Address>) -> Self {
        Self { chain_spec, signer_address }
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

pub trait PayloadAttributesBuilderExt<Attributes>: PayloadAttributesBuilder<Attributes> + Send + Sync + 'static {
    fn build_ext(&self, timestamp: u64, withdrawals: Option<Vec<Withdrawal>>) -> Attributes;
}

impl<ChainSpec> PayloadAttributesBuilderExt<EthPayloadAttributes>
    for N42PayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build_ext(&self, timestamp: u64, withdrawals: Option<Vec<Withdrawal>>) -> EthPayloadAttributes {
        let mut payload_attributes = self.build(timestamp);
        payload_attributes.withdrawals = withdrawals;

        payload_attributes
    }
}

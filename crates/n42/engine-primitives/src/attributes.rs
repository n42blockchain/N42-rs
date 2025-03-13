#![cfg_attr(not(test), warn(unused_crate_dependencies))]
use reth_payload_primitives::{PayloadAttributes, PayloadAttributesBuilder, PayloadBuilderAttributes};
use reth_chainspec::EthereumHardforks;

use std::{convert::Infallible};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use alloy_primitives::{Address, B256};
use alloy_rpc_types::{
    engine::{
        PayloadAttributes as EthPayloadAttributes, PayloadId,
    },
    Withdrawal,
};
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes;
use reth_primitives::Withdrawals;

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

    pub const fn new_add_signer(chain_spec: Arc<ChainSpec>, signer_address: Option<Address>) -> Self {
        Self { chain_spec, signer_address }
    }
}

impl<ChainSpec> PayloadAttributesBuilder<N42PayloadAttributes>
for N42PayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build(&self, timestamp: u64) -> N42PayloadAttributes {
        let inner = EthPayloadAttributes {
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
        };

        N42PayloadAttributes {
            inner, custom: 0,
        }
    }
}



/// A custom payload attributes type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct N42PayloadAttributes {
    /// An inner payload type
    #[serde(flatten)]
    pub inner: EthPayloadAttributes,
    /// A custom field
    pub custom: u64,
}

/// Custom error type used in payload attributes validation
#[derive(Debug, Error)]
pub enum CustomError {
    #[error("Custom field is not zero")]
    CustomFieldIsNotZero,
}

impl PayloadAttributes for N42PayloadAttributes {
    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }
}

/// New type around the payload builder attributes type
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct N42PayloadBuilderAttributes(pub EthPayloadBuilderAttributes);

impl PayloadBuilderAttributes for N42PayloadBuilderAttributes {
    type RpcPayloadAttributes = N42PayloadAttributes;
    type Error = Infallible;

    fn try_new(
        parent: B256,
        attributes: N42PayloadAttributes,
        _version: u8,
    ) -> Result<Self, Infallible> {
        Ok(Self(EthPayloadBuilderAttributes::new(parent, attributes.inner)))
    }

    fn payload_id(&self) -> PayloadId {
        self.0.id
    }

    fn parent(&self) -> B256 {
        self.0.parent
    }

    fn timestamp(&self) -> u64 {
        self.0.timestamp
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.0.parent_beacon_block_root
    }

    fn suggested_fee_recipient(&self) -> Address {
        self.0.suggested_fee_recipient
    }

    fn prev_randao(&self) -> B256 {
        self.0.prev_randao
    }

    fn withdrawals(&self) -> &Withdrawals {
        &self.0.withdrawals
    }
}

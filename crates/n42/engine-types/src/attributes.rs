#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::{convert::Infallible};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use alloy_primitives::{Address, B256};
use alloy_rpc_types::{
    engine::{
        PayloadAttributes as EthPayloadAttributes, PayloadId,
    },
    Withdrawal,
};
use reth_node_api::{
    PayloadAttributes, PayloadBuilderAttributes,
};
use reth_payload_builder::{
    EthPayloadBuilderAttributes,
};
use reth_primitives::Withdrawals;


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
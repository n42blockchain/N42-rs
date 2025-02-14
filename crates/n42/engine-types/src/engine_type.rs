#![cfg_attr(not(test), warn(unused_crate_dependencies))]
use serde::{Deserialize, Serialize};
use alloy_rpc_types::{
    engine::{
        ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
        ExecutionPayloadV1
    },
};
use reth_node_api::{
    EngineTypes,
};
use reth_payload_builder::{
    EthBuiltPayload
};
use reth_payload_primitives::PayloadTypes;
use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};

/// Custom engine types - uses a custom payload attributes RPC type, but uses the default
/// payload builder attributes type.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct N42EngineTypes;

impl PayloadTypes for N42EngineTypes {
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = N42PayloadAttributes;
    type PayloadBuilderAttributes = N42PayloadBuilderAttributes;
}

impl EngineTypes for N42EngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}
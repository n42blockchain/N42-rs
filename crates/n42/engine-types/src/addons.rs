#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use reth::{
    api::PayloadTypes,
    builder::{
        rpc::{RpcAddOns},
        FullNodeTypes
    },
    network::NetworkHandle,
    rpc::eth::EthApi,
};

use reth_node_api::{
    EngineTypes,
    FullNodeComponents, PayloadAttributes, PayloadBuilderAttributes,
};
use crate::engine_validator::N42EngineValidatorBuilder;

/// Custom addons configuring RPC types
pub type N42NodeAddOns<N> = RpcAddOns<
    N,
    EthApi<
        <N as FullNodeTypes>::Provider,
        <N as FullNodeComponents>::Pool,
        NetworkHandle,
        <N as FullNodeComponents>::Evm,
    >,
    N42EngineValidatorBuilder,
>;
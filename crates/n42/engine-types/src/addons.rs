//! This example shows how to implement a custom [EngineTypes].
//!
//! The [EngineTypes] trait can be implemented to configure the engine to work with custom types,
//! as long as those types implement certain traits.
//!
//! Custom payload attributes can be supported by implementing two main traits:
//!
//! [PayloadAttributes] can be implemented for payload attributes types that are used as
//! arguments to the `engine_forkchoiceUpdated` method. This type should be used to define and
//! _spawn_ payload jobs.
//!
//! [PayloadBuilderAttributes] can be implemented for payload attributes types that _describe_
//! running payload jobs.
//!
//! Once traits are implemented and custom types are defined, the [EngineTypes] trait can be
//! implemented:

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
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
use reth_network::NetworkHandle;
use reth_rpc::eth::EthApi;
use reth_node_builder::
    rpc::{
        RpcAddOns
    }
;
use reth_node_api::{FullNodeComponents,  FullNodeTypes};
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
//! The implementation of the [`PayloadAttributesBuilder`] for the
//! [`LocalEngineService`](super::service::N42EngineService).

use std::str::FromStr;
use alloy_primitives::{Address, B256};
use reth_chainspec::EthereumHardforks;
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_payload_primitives::PayloadAttributesBuilder;
use std::sync::Arc;
//
// /// The attributes builder for local Ethereum payload.
// #[derive(Debug)]
// #[non_exhaustive]
// pub struct N42PayloadAttributesBuilder<ChainSpec> {
//     chain_spec: Arc<ChainSpec>,
// }
//
// impl<ChainSpec> N42PayloadAttributesBuilder<ChainSpec> {
//     /// Creates a new instance of the builder.
//     pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
//         Self { chain_spec }
//     }
// }
//
// impl<ChainSpec> PayloadAttributesBuilder<EthPayloadAttributes>
//     for N42PayloadAttributesBuilder<ChainSpec>
// where
//     ChainSpec: Send + Sync + EthereumHardforks + 'static,
// {
//     fn build(&self, timestamp: u64) -> EthPayloadAttributes {
//         EthPayloadAttributes {
//             timestamp,
//             prev_randao: B256::random(),
//             suggested_fee_recipient: Address::ZERO,
//             withdrawals: self
//                 .chain_spec
//                 .is_shanghai_active_at_timestamp(timestamp)
//                 .then(Default::default),
//             parent_beacon_block_root: self
//                 .chain_spec
//                 .is_cancun_active_at_timestamp(timestamp)
//                 .then(B256::random),
//         }
//     }
// }


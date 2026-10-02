// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Engine API types over [`N42Primitives`]: the built payload and the
//! payload/engine type set. reth's `EthBuiltPayload` is generic over the
//! primitives but its Engine API conversions exist only for Ethereum's, and
//! `EthEngineTypes` requires Ethereum's block; this is the same type with
//! the conversions for ours.

use alloy_eips::eip7685::Requests;
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::{
    BlobsBundleV1, BlobsBundleV2, CancunPayloadFields, ExecutionData, ExecutionPayload,
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6, ExecutionPayloadFieldV2,
    ExecutionPayloadSidecar, ExecutionPayloadV1, ExecutionPayloadV3, ExecutionPayloadV4,
    PayloadAttributes as EthPayloadAttributes, PraguePayloadFields,
};
use n42_tx_types::{Block, N42Primitives};
use reth_engine_primitives::EngineTypes;
use reth_ethereum_engine_primitives::{BlobSidecars, BuiltPayloadConversionError};
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, RecoveredBlock, SealedBlock};
use std::sync::Arc;

/// A block this node built, with what the Engine API asks about it.
#[derive(Debug, Clone)]
pub struct N42BuiltPayload {
    block: Arc<RecoveredBlock<Block>>,
    fees: U256,
    sidecars: BlobSidecars,
    requests: Option<Requests>,
    block_access_list: Option<Bytes>,
}

impl N42BuiltPayload {
    /// A built payload with no blob sidecars.
    pub const fn new(
        block: Arc<RecoveredBlock<Block>>,
        fees: U256,
        requests: Option<Requests>,
        block_access_list: Option<Bytes>,
    ) -> Self {
        Self { block, fees, requests, sidecars: BlobSidecars::Empty, block_access_list }
    }

    /// The sealed block.
    pub fn block(&self) -> &SealedBlock<Block> {
        self.block.sealed_block()
    }

    /// The block with its senders.
    pub fn recovered_block(&self) -> &RecoveredBlock<Block> {
        &self.block
    }

    /// The block, shared.
    pub const fn block_arc(&self) -> &Arc<RecoveredBlock<Block>> {
        &self.block
    }

    /// Into the shared block.
    pub fn into_block_arc(self) -> Arc<RecoveredBlock<Block>> {
        self.block
    }

    /// The fees the block collected.
    pub const fn fees(&self) -> U256 {
        self.fees
    }

    /// The blob sidecars.
    pub const fn sidecars(&self) -> &BlobSidecars {
        &self.sidecars
    }

    /// With these sidecars.
    pub fn with_sidecars(mut self, sidecars: impl Into<BlobSidecars>) -> Self {
        self.sidecars = sidecars.into();
        self
    }

    /// `engine_getPayloadV3`.
    pub fn try_into_v3(self) -> Result<ExecutionPayloadEnvelopeV3, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, .. } = self;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV1::empty(),
            BlobSidecars::Eip4844(sidecars) => BlobsBundleV1::from(sidecars),
            BlobSidecars::Eip7594(_) => return Err(BuiltPayloadConversionError::UnexpectedEip7594Sidecars),
        };
        Ok(ExecutionPayloadEnvelopeV3 {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            should_override_builder: false,
            blobs_bundle,
        })
    }

    /// `engine_getPayloadV4`.
    pub fn try_into_v4(mut self) -> Result<ExecutionPayloadEnvelopeV4, BuiltPayloadConversionError> {
        let execution_requests = self.requests.take().unwrap_or_default();
        Ok(ExecutionPayloadEnvelopeV4 { execution_requests, envelope_inner: self.try_into_v3()? })
    }

    /// `engine_getPayloadV5`.
    pub fn try_into_v5(self) -> Result<ExecutionPayloadEnvelopeV5, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, requests, .. } = self;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars),
            BlobSidecars::Eip4844(_) => return Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars),
        };
        Ok(ExecutionPayloadEnvelopeV5 {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            should_override_builder: false,
            blobs_bundle,
            execution_requests: requests.unwrap_or_default(),
        })
    }

    /// `engine_getPayloadV6`.
    pub fn try_into_v6(self) -> Result<ExecutionPayloadEnvelopeV6, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, requests, block_access_list } = self;
        let block_access_list = block_access_list.ok_or(BuiltPayloadConversionError::MissingBlockAccessList)?;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars),
            BlobSidecars::Eip4844(_) => return Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars),
        };
        Ok(ExecutionPayloadEnvelopeV6 {
            execution_payload: ExecutionPayloadV4::from_block_unchecked_with_bal(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
                block_access_list,
            ),
            block_value: fees,
            should_override_builder: false,
            blobs_bundle,
            execution_requests: requests.unwrap_or_default(),
        })
    }

    /// The payload and sidecar `engine_newPayload` would carry.
    pub fn into_execution_data(self) -> ExecutionData {
        let Self { block, requests, block_access_list, .. } = self;
        let block_hash = block.hash();
        let block = Arc::unwrap_or_clone(block).into_block();
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked_with_extras(block_hash, &block, block_access_list);
        let sidecar = if let Some(requests) = requests {
            block.header.parent_beacon_block_root.map_or(sidecar, |parent_beacon_block_root| {
                ExecutionPayloadSidecar::v4(
                    CancunPayloadFields {
                        parent_beacon_block_root,
                        versioned_hashes: block.body.blob_versioned_hashes_iter().copied().collect(),
                    },
                    PraguePayloadFields::new(requests),
                )
            })
        } else {
            sidecar
        };
        ExecutionData::new(payload, sidecar)
    }
}

impl BuiltPayload for N42BuiltPayload {
    type Primitives = N42Primitives;

    fn block(&self) -> &SealedBlock<Block> {
        self.block.sealed_block()
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn block_access_list(&self) -> Option<&Bytes> {
        self.block_access_list.as_ref()
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

impl From<N42BuiltPayload> for ExecutionPayloadV1 {
    fn from(value: N42BuiltPayload) -> Self {
        Self::from_block_unchecked(value.block().hash(), &Arc::unwrap_or_clone(value.block).into_block())
    }
}

impl From<N42BuiltPayload> for ExecutionPayloadEnvelopeV2 {
    fn from(value: N42BuiltPayload) -> Self {
        let N42BuiltPayload { block, fees, .. } = value;
        Self {
            block_value: fees,
            execution_payload: ExecutionPayloadFieldV2::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
        }
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV3 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v3()
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV4 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v4()
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV5 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v5()
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV6 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v6()
    }
}

impl From<N42BuiltPayload> for ExecutionData {
    fn from(value: N42BuiltPayload) -> Self {
        value.into_execution_data()
    }
}

impl From<N42BuiltPayload> for reth_engine_primitives::BigBlockData<ExecutionData> {
    fn from(_value: N42BuiltPayload) -> Self {
        unreachable!("payload building is not supported for big blocks");
    }
}

/// The Engine API type set of the node: Ethereum's payload attributes and
/// execution data, [`N42BuiltPayload`] as the built payload.
#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct N42EngineTypes;

impl PayloadTypes for N42EngineTypes {
    type BuiltPayload = N42BuiltPayload;
    type PayloadAttributes = EthPayloadAttributes;
    type ExecutionData = ExecutionData;

    fn block_to_payload(
        block: SealedBlock<<<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block>,
        bal: Option<Bytes>,
    ) -> Self::ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked_with_extras(block.hash(), &block.into_block(), bal);
        ExecutionData { payload, sidecar }
    }
}

impl EngineTypes for N42EngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
    type ExecutionPayloadEnvelopeV6 = ExecutionPayloadEnvelopeV6;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, EMPTY_ROOT_HASH};
    use alloy_primitives::{Address, B256};
    use alloy_rpc_types_engine::ExecutionPayloadV1;
    use n42_tx_types::{BlockBody, N42TxEnvelope};

    fn envelope(nonce: u64) -> N42TxEnvelope {
        N42TxEnvelope::Eth(reth_ethereum_primitives::TransactionSigned::new_unhashed(
            reth_ethereum_primitives::Transaction::Legacy(alloy_consensus::TxLegacy { nonce, ..Default::default() }),
            alloy_primitives::Signature::test_signature(),
        ))
    }

    /// A Cancun-shaped block with `transactions` transfers.
    fn block(transactions: usize) -> Arc<RecoveredBlock<Block>> {
        let transactions: Vec<N42TxEnvelope> = (0..transactions as u64).map(envelope).collect();
        // The payload form carries no roots it can recompute: those must already be consistent.
        let header = Header {
            number: 12,
            gas_limit: 30_000_000,
            timestamp: 1_720_000_000,
            base_fee_per_gas: Some(7),
            ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
            transactions_root: alloy_consensus::proofs::calculate_transaction_root(&transactions),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(0xBB)),
            ..Default::default()
        };
        let body = BlockBody { transactions, ommers: Vec::new(), withdrawals: Some(Vec::new().into()) };
        let transactions = body.transactions.len();
        let senders = vec![Address::repeat_byte(1); transactions];
        Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(Block { header, body }), senders))
    }

    fn payload(transactions: usize) -> N42BuiltPayload {
        N42BuiltPayload::new(block(transactions), U256::from(99), None, None)
    }

    fn requests() -> Requests {
        let mut requests = Requests::default();
        requests.push_request_with_type(0x01, [7u8, 8, 9]);
        requests
    }

    #[test]
    fn accessors_expose_the_block_and_the_fees() {
        let built = payload(2);
        let hash = built.block_arc().hash();
        assert_eq!(built.block().hash(), hash);
        assert_eq!(built.recovered_block().senders().len(), 2);
        assert_eq!(built.fees(), U256::from(99));
        assert!(matches!(built.sidecars(), BlobSidecars::Empty));
        // The trait view agrees with the inherent one.
        assert_eq!(BuiltPayload::block(&built).hash(), hash);
        assert_eq!(BuiltPayload::fees(&built), U256::from(99));
        assert!(BuiltPayload::block_access_list(&built).is_none());
        assert!(BuiltPayload::requests(&built).is_none());
        assert_eq!(built.into_block_arc().hash(), hash);
    }

    #[test]
    fn requests_and_access_list_pass_through_the_trait() {
        let built = N42BuiltPayload::new(block(0), U256::ZERO, Some(requests()), Some(Bytes::from_static(b"bal")));
        assert_eq!(BuiltPayload::requests(&built), Some(requests()));
        assert_eq!(BuiltPayload::block_access_list(&built), Some(&Bytes::from_static(b"bal")));
    }

    #[test]
    fn v3_carries_the_sealed_hash_the_transactions_and_the_fees() {
        let built = payload(3);
        let hash = built.block().hash();
        let envelope: ExecutionPayloadEnvelopeV3 = built.try_into().expect("an empty sidecar set converts");
        assert_eq!(envelope.block_value, U256::from(99));
        assert!(!envelope.should_override_builder);
        assert!(envelope.blobs_bundle.blobs.is_empty());
        let v1 = &envelope.execution_payload.payload_inner.payload_inner;
        assert_eq!(v1.block_hash, hash);
        assert_eq!(v1.block_number, 12);
        assert_eq!(v1.transactions.len(), 3);
        assert_eq!(envelope.execution_payload.blob_gas_used, 0);
    }

    #[test]
    fn v3_refuses_peerdas_sidecars_and_v5_v6_refuse_4844_ones() {
        let peerdas = payload(0).with_sidecars(BlobSidecars::Eip7594(Vec::new()));
        assert!(matches!(peerdas.clone().try_into_v3(), Err(BuiltPayloadConversionError::UnexpectedEip7594Sidecars)));
        assert!(peerdas.clone().try_into_v5().is_ok());

        let legacy = payload(0).with_sidecars(BlobSidecars::Eip4844(Vec::new()));
        assert!(legacy.clone().try_into_v3().is_ok());
        assert!(matches!(legacy.clone().try_into_v5(), Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars)));
        let with_bal = N42BuiltPayload::new(block(0), U256::ZERO, None, Some(Bytes::from_static(b"bal")))
            .with_sidecars(BlobSidecars::Eip4844(Vec::new()));
        assert!(matches!(with_bal.try_into_v6(), Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars)));
    }

    #[test]
    fn v4_and_v5_carry_the_execution_requests() {
        let with = N42BuiltPayload::new(block(1), U256::from(5), Some(requests()), None);
        let v4 = with.clone().try_into_v4().unwrap();
        assert_eq!(v4.execution_requests, requests());
        assert_eq!(v4.envelope_inner.block_value, U256::from(5));
        let v5 = with.try_into_v5().unwrap();
        assert_eq!(v5.execution_requests, requests());
        assert_eq!(v5.execution_payload.payload_inner.payload_inner.transactions.len(), 1);

        // No requests reads as the empty list, not an error.
        assert_eq!(payload(0).try_into_v4().unwrap().execution_requests, Requests::default());
        assert_eq!(payload(0).try_into_v5().unwrap().execution_requests, Requests::default());
        // The TryFrom spellings are the same conversions.
        assert!(ExecutionPayloadEnvelopeV4::try_from(payload(0)).is_ok());
        assert!(ExecutionPayloadEnvelopeV5::try_from(payload(0)).is_ok());
    }

    #[test]
    fn v6_needs_a_block_access_list() {
        assert!(matches!(payload(0).try_into_v6(), Err(BuiltPayloadConversionError::MissingBlockAccessList)));
        assert!(matches!(
            ExecutionPayloadEnvelopeV6::try_from(payload(0)),
            Err(BuiltPayloadConversionError::MissingBlockAccessList)
        ));
        let bal = Bytes::from_static(b"\xc0");
        let built = N42BuiltPayload::new(block(2), U256::from(3), Some(requests()), Some(bal.clone()));
        let hash = built.block().hash();
        let v6 = ExecutionPayloadEnvelopeV6::try_from(built).unwrap();
        assert_eq!(v6.execution_payload.block_access_list, bal);
        assert_eq!(v6.execution_requests, requests());
        assert_eq!(v6.block_value, U256::from(3));
        assert_eq!(v6.execution_payload.payload_inner.payload_inner.payload_inner.block_hash, hash);
    }

    #[test]
    fn v1_and_v2_keep_the_hash_and_the_transactions() {
        let built = payload(2);
        let hash = built.block().hash();
        let v1: ExecutionPayloadV1 = built.clone().into();
        assert_eq!(v1.block_hash, hash);
        assert_eq!(v1.transactions.len(), 2);
        let v2: ExecutionPayloadEnvelopeV2 = built.into();
        assert_eq!(v2.block_value, U256::from(99));
        match v2.execution_payload {
            ExecutionPayloadFieldV2::V2(payload) => {
                assert_eq!(payload.payload_inner.block_hash, hash);
                assert!(payload.withdrawals.is_empty());
            }
            ExecutionPayloadFieldV2::V1(_) => panic!("a block with withdrawals is a V2 payload"),
        }
    }

    #[test]
    fn execution_data_adds_the_prague_sidecar_only_with_requests_and_a_beacon_root() {
        // Requests and a parent beacon root: the V4 sidecar carries both.
        let data: ExecutionData = N42BuiltPayload::new(block(1), U256::ZERO, Some(requests()), None).into();
        assert_eq!(data.sidecar.requests().cloned(), Some(requests()));
        assert_eq!(data.sidecar.parent_beacon_block_root(), Some(B256::repeat_byte(0xBB)));
        assert_eq!(data.payload.transactions().len(), 1);

        // Without requests the sidecar is whatever the payload shape implies, with no requests.
        let data = payload(1).into_execution_data();
        assert!(data.sidecar.requests().is_none());
        assert_eq!(data.payload.block_number(), 12);
    }

    #[test]
    fn block_to_payload_round_trips_the_block() {
        let recovered = block(2);
        let sealed = recovered.sealed_block().clone();
        let hash = sealed.hash();
        let data = <N42EngineTypes as PayloadTypes>::block_to_payload(sealed, None);
        assert_eq!(data.payload.block_hash(), hash);
        assert_eq!(data.payload.transactions().len(), 2);
        // The beacon root travels in the sidecar, so the whole of `ExecutionData` decodes back.
        let rebuilt: Block = data.try_into_block::<N42TxEnvelope>().expect("decodes back");
        assert_eq!(rebuilt.header.hash_slow(), hash, "the header survives the round trip");
        assert_eq!(rebuilt.body.transactions.len(), 2);
        assert_eq!(alloy_consensus::Transaction::nonce(&rebuilt.body.transactions[1]), 1);
    }

    #[test]
    #[should_panic(expected = "big blocks")]
    fn big_block_data_is_not_supported() {
        let _: reth_engine_primitives::BigBlockData<ExecutionData> = payload(0).into();
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validates execution payload wrt Ethereum Execution Engine API version.

use alloy_consensus::BlockHeader;
use alloy_rpc_types_engine::ExecutionData;
pub use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_node_api::PayloadTypes;
use reth_payload_primitives::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, InvalidPayloadAttributesError, NewPayloadError,
    PayloadOrAttributes,
};
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_chain_state::ExecutedBlock;
use std::sync::Arc;

/// Validator for the ethereum engine API.
#[derive(Debug, Clone)]
pub struct EthereumEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl<ChainSpec> EthereumEngineValidator<ChainSpec> {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
        }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl<ChainSpec, Types> PayloadValidator<Types> for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        self.inner.ensure_well_formed_payload(payload)
            .map_err(|e| NewPayloadError::Other(e.to_string().into()))
    }

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block = <Self as PayloadValidator<Types>>::convert_payload_to_block(self, payload)?;
        sealed_block
            .try_recover()
            .map_err(|e| NewPayloadError::Other(e.into()))
    }
}

impl<ChainSpec, Types> EngineApiValidator<Types> for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Types::ExecutionData, EthPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

/// Type alias for the validation outcome used by EngineValidator.
pub type EthValidationOutcome =
    reth_engine_tree::tree::payload_validator::ValidationOutcome<EthPrimitives>;

impl<ChainSpec, Types> reth_engine_tree::tree::EngineValidator<Types, EthPrimitives>
    for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_payload_attributes_against_header(
        &self,
        attr: &EthPayloadAttributes,
        header: &alloy_consensus::Header,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Validate that the payload attributes timestamp is greater than the header timestamp
        if attr.timestamp <= header.timestamp() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Block>, NewPayloadError> {
        // Delegate to PayloadValidator implementation
        <Self as PayloadValidator<Types>>::convert_payload_to_block(self, payload)
    }

    fn validate_payload(
        &mut self,
        payload: ExecutionData,
        _ctx: reth_engine_tree::tree::payload_validator::TreeCtx<'_, EthPrimitives>,
    ) -> EthValidationOutcome {
        // NOTE: This is a simplified implementation for N42.
        // Full block execution and state validation is not performed here.
        // The actual execution should be handled by the engine tree's internal
        // mechanisms or a separate execution layer.
        //
        // For now, we validate the payload structure and return an error
        // indicating that execution is required.
        match <Self as PayloadValidator<Types>>::convert_payload_to_block(self, payload) {
            Ok(_block) => {
                // We cannot return ExecutedBlock without actual execution.
                // Return an error indicating the payload needs execution.
                Err(reth_engine_tree::tree::error::InsertPayloadError::Payload(
                    NewPayloadError::Other(
                        "EthereumEngineValidator: block execution not implemented, use BasicEngineValidator".into()
                    )
                ))
            }
            Err(e) => Err(reth_engine_tree::tree::error::InsertPayloadError::Payload(
                e,
            )),
        }
    }

    fn validate_block(
        &mut self,
        _block: SealedBlock<Block>,
        _ctx: reth_engine_tree::tree::payload_validator::TreeCtx<'_, EthPrimitives>,
    ) -> EthValidationOutcome {
        // NOTE: This is a simplified implementation for N42.
        // Full block execution and state validation is not performed here.
        Err(reth_engine_tree::tree::error::InsertPayloadError::Payload(
            NewPayloadError::Other(
                "EthereumEngineValidator: block execution not implemented, use BasicEngineValidator".into()
            )
        ))
    }

    fn on_inserted_executed_block(&self, _block: ExecutedBlock<EthPrimitives>) {
        // No-op for this simplified implementation
        // In a full implementation, this would update caches or perform other bookkeeping
    }
}

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::{sync::Arc};
use reth_chainspec::{ChainSpec};
use reth_node_api::{
    payload::{EngineApiMessageVersion, EngineObjectValidationError, PayloadOrAttributes},
    validate_version_specific_fields, AddOnsContext, EngineTypes, EngineValidator,
    FullNodeComponents
};
use n42_engine_primitives::N42PayloadAttributes;
use reth_node_builder::NodeTypesWithEngine;
use reth_node_builder::rpc::EngineValidatorBuilder;
use crate::{N42EngineTypes};

/// Custom engine validator
#[derive(Debug, Clone)]
pub struct N42EngineValidator {
    chain_spec: Arc<ChainSpec>,
}

impl<T> EngineValidator<T> for N42EngineValidator
where
    T: EngineTypes<PayloadAttributes =N42PayloadAttributes>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, T::PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(&self.chain_spec, version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &T::PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(&self.chain_spec, version, attributes.into())?;

        // custom validation logic - ensure that the custom field is not zero
        // if attributes.custom == 0 {
        //     return Err(EngineObjectValidationError::invalid_params(
        //         CustomError::CustomFieldIsNotZero,
        //     ))
        // }

        Ok(())
    }
}

/// Custom engine validator builder
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct N42EngineValidatorBuilder;

impl<N> EngineValidatorBuilder<N> for N42EngineValidatorBuilder
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<Engine = N42EngineTypes, ChainSpec = ChainSpec>,
    >,
{
    type Validator = N42EngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        Ok(N42EngineValidator { chain_spec: ctx.config.chain.clone() })
    }
}
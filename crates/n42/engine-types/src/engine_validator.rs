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

use std::{sync::Arc};

use reth::{
    api::PayloadTypes,
    builder::{
        node::{NodeTypes, NodeTypesWithEngine},
        rpc::{EngineValidatorBuilder},
    },
};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_node_api::{
    payload::{EngineApiMessageVersion, EngineObjectValidationError, PayloadOrAttributes},
    validate_version_specific_fields, AddOnsContext, EngineTypes, EngineValidator,
    FullNodeComponents, PayloadAttributes, PayloadBuilderAttributes,
};
use crate::attributes::CustomError;
use crate::{N42EngineTypes, N42PayloadAttributes};

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
        if attributes.custom == 0 {
            return Err(EngineObjectValidationError::invalid_params(
                CustomError::CustomFieldIsNotZero,
            ))
        }

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
        Types: NodeTypesWithEngine<Engine =N42EngineTypes, ChainSpec = ChainSpec>,
    >,
{
    type Validator = N42EngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        Ok(N42EngineValidator { chain_spec: ctx.config.chain.clone() })
    }
}
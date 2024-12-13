#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use reth::{
    api::PayloadTypes,
    builder::{
        components::{PayloadServiceBuilder},
        node::{NodeTypes, NodeTypesWithEngine},
        BuilderContext, FullNodeTypes,
        PayloadBuilderConfig,
    },
    providers::{CanonStateSubscriptions, StateProviderFactory},
    transaction_pool::TransactionPool,
};
use reth::consensus::Consensus;
use reth_basic_payload_builder::{
    BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig, BuildArguments, BuildOutcome,
    PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainSpec, ChainSpecProvider};
use reth_node_api::{
    FullNodeComponents,
};
use reth_node_ethereum::{
    EthEvmConfig,
};
use reth_payload_builder::{
    EthBuiltPayload, PayloadBuilderError, PayloadBuilderHandle,
    PayloadBuilderService,
};
use crate::attributes::N42PayloadBuilderAttributes;
use crate::N42EngineTypes;

/// The type responsible for building custom payloads
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42PayloadBuilder;

impl<Pool, Client> PayloadBuilder<Pool, Client> for N42PayloadBuilder
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool,
{
    type Attributes = N42PayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let BuildArguments { client, pool, cached_reads, config, cancel, best_payload } = args;
        let PayloadConfig { parent_header, extra_data, attributes } = config;

        let chain_spec = client.chain_spec();

        // This reuses the default EthereumPayloadBuilder to build the payload
        // but any custom logic can be implemented here
        reth_ethereum_payload_builder::EthereumPayloadBuilder::new(EthEvmConfig::new(
            chain_spec.clone(),
        ))
            .try_build(BuildArguments {
                client,
                pool,
                cached_reads,
                config: PayloadConfig { parent_header, extra_data, attributes: attributes.0 },
                cancel,
                best_payload,
            })
    }

    fn build_empty_payload(
        &self,
        client: &Client,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let PayloadConfig { parent_header, extra_data, attributes } = config;
        let chain_spec = client.chain_spec();
        <reth_ethereum_payload_builder::EthereumPayloadBuilder as PayloadBuilder<Pool, Client>>::build_empty_payload(&reth_ethereum_payload_builder::EthereumPayloadBuilder::new(EthEvmConfig::new(chain_spec.clone())),client,
                                                                                                                     PayloadConfig { parent_header, extra_data, attributes: attributes.0})
    }
}



/// A custom payload service builder that supports the custom engine types
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42PayloadServiceBuilder;

impl<Node, Pool, Consensus> PayloadServiceBuilder<Node, Pool, Consensus> for N42PayloadServiceBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypesWithEngine<Engine =N42EngineTypes, ChainSpec = ChainSpec>,
    >,
    Pool: TransactionPool + Unpin + 'static,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        _: Consensus,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypesWithEngine>::Engine>> {
        let payload_builder = N42PayloadBuilder::default();
        let conf = ctx.payload_builder_config();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks())
            .extradata(conf.extradata_bytes());

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            pool,
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor().spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_builder)
    }
}
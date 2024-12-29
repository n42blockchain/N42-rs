use reth_ethereum_engine_primitives::ExecutionPayloadV1;
use n42_engine_primitives::N42PayloadBuilderAttributes;
use reth_payload_primitives::BuiltPayload;
use reth_consensus::Consensus;
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypesWithEngine,PayloadTypes};
use std::sync::Arc;
use zerocopy::AsBytes;
use reth_chainspec::ChainSpec;
use alloy_genesis::{ChainConfig, Genesis,CliqueConfig};
use reth_provider::{BlockReaderIdExt, BlockNumReader};
use crate::utils::n42_payload_attributes;
use alloy_primitives::{Bytes, Address};
use futures::StreamExt;
use reth:: args::{DevArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs};
//use reth_e2e_test_utils::setup;
use reth_node_builder::{
    NodeBuilder, NodeConfig, NodeHandle,FullNode,rpc::RethRpcAddOns,
};
use reth_tasks::TaskManager;
use reth_chainspec::N42;
use n42_engine_types::N42Node;

use reth::builder::Node;
use reth_payload_primitives::PayloadBuilder;
use std::time::{SystemTime, UNIX_EPOCH};
use reth_rpc_api::EngineApiClient;
use reth::rpc::types::engine::ForkchoiceState;
use n42_engine_types::N42EngineTypes;
use n42_clique::{NONCE_AUTH_VOTE, APos, DIFF_IN_TURN, EXTRA_VANITY, EXTRA_SEAL, SIGNATURE_LENGTH};

use crate::snapshot_test_utils::TesterAccountPool;

//
// Types representing tester votes and test structure
#[derive(Debug, Default)]
pub struct TesterVote {
    pub signer: String,
    pub voted: Option<String>,
    pub auth: Option<bool>,
    pub checkpoint: Option<Vec<String>>,
    pub newbatch: Option<bool>,
}

#[derive(Debug, Default)]
pub struct CliqueTest {
    pub epoch: u64,
    pub signers: Vec<String>,
    pub votes: Vec<TesterVote>,
    pub results: Vec<String>,
    pub failure: Option<String>,
}

fn get_addresses_from_extra_data(extra_data: Bytes) -> Vec<Address> {
    let signers_count = (extra_data.len() - EXTRA_VANITY - SIGNATURE_LENGTH) /  Address::len_bytes();

    let mut signers = Vec::with_capacity(signers_count);

    for i in 0..signers_count {
        let start = EXTRA_VANITY + i * Address::len_bytes();
        let end = start + Address::len_bytes();
        signers.push(Address::from_slice(&extra_data[start..end]));
    }

    return signers;
}

async fn new_block<Node: FullNodeComponents, AddOns: RethRpcAddOns<Node>>(node: &FullNode<Node, AddOns>, eth_signer_key: String) -> eyre::Result<()>
    where <<<Node as FullNodeTypes>::Types as NodeTypesWithEngine>::Engine as PayloadTypes>::PayloadBuilderAttributes: From<N42PayloadBuilderAttributes>,
    ExecutionPayloadV1: From<<<<Node as FullNodeTypes>::Types as NodeTypesWithEngine>::Engine as PayloadTypes>::BuiltPayload>

{

            let best_number = node.provider.chain_info().unwrap().best_number;
            println!("best_number={}", best_number);
            //let eth_signer_key = &eth_signer_keys[(best_number % 2) as usize];
            println!("eth_signer_key={:?}", eth_signer_key);
            let parent_hash = node.provider.latest_header().unwrap().unwrap().hash();
            println!("parent_hash={:?}", parent_hash);
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let attributes = n42_payload_attributes(timestamp, parent_hash);
            node.consensus.set_eth_signer_by_key(Some(eth_signer_key.clone()))?;
            let payload_id = node.payload_builder.send_new_payload(attributes.clone().into()).await.unwrap()?;
            println!("payload_id={}", payload_id);

            let payload_type = node.payload_builder.resolve(payload_id).await.unwrap().unwrap();
            println!("payload_type={:?}", payload_type);
            let extra_data = payload_type.block().header.extra_data.clone();
            println!("header={:?}", payload_type.block().header);
            println!("extra_data={:?}", extra_data);
            let signer_addresses = get_addresses_from_extra_data(extra_data);
            println!("signer_addresses={:?}", signer_addresses);

            let payload = payload_type.clone();

            let client = node.engine_http_client();
            let submission = EngineApiClient::<N42EngineTypes>::new_payload_v1(
                &client,
                payload.into(),
            )
            .await?;
            println!("submission={:?}", submission);

            let current_head = parent_hash;
            let new_head = payload_type.block().hash();
            EngineApiClient::<N42EngineTypes>::fork_choice_updated_v1(
                        &client,
                    ForkchoiceState {
                        head_block_hash: new_head,
                        safe_block_hash: current_head,
                        finalized_block_hash: current_head,
                    },
                    None,
                ).await?;
            println!("latest block_hash={:?}", node.provider.latest_header().unwrap().unwrap().hash());
            Ok(()) as eyre::Result<()>
}

impl CliqueTest {
    fn gen_chainspec(&self, accounts: &mut TesterAccountPool) -> ChainSpec {

        // Generate the initial set of signers
        let mut signers: Vec<Address> = self.signers.iter().map(|s| accounts.address(s)).collect();
        signers.sort();
        // println!("signers: {:?}", signers);

        let mut chainspec = (**N42).clone();
        let mut extra_data = vec![0u8; EXTRA_VANITY + self.signers.len() * Address::len_bytes() + EXTRA_SEAL];
        for (j, signer) in signers.iter().enumerate() {
            let start = EXTRA_VANITY + j * Address::len_bytes();
            let end = start + Address::len_bytes();
            extra_data[start..end].copy_from_slice(signer.as_bytes());
        }
        let extra_data_clone = extra_data.clone();
        chainspec.genesis.extra_data = extra_data.into();
        //chainspec.genesis.config.clique.epoch = Some(self.epoch);

        chainspec
    }

    async fn run(&self) -> eyre::Result<()> {
        reth_tracing::init_test_tracing();
        let tasks = TaskManager::current();
        let exec = tasks.executor();

        let network_config = NetworkArgs {
            discovery: DiscoveryArgs { disable_discovery: true, ..DiscoveryArgs::default() },
            ..NetworkArgs::default()
        };
        let mut accounts = TesterAccountPool::new();
        let chainspec= self.gen_chainspec(&mut accounts);
        //println!("chainspec={:?}", chainspec);

        let node_config = NodeConfig::new(Arc::new(chainspec))
            //.with_chain(custom_chain())
                .with_network(network_config.clone())
                .with_unused_ports()
                .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
            .with_dev(DevArgs { dev: true, ..Default::default() });

        let NodeHandle { node, .. } = NodeBuilder::new(node_config.clone())
            .testing_node(exec.clone())
            //.with_types_and_provider::<N42Node, BlockchainProvider2<_>>()
            .with_types::<N42Node>()
            .with_components(N42Node::default().components_builder())
            .with_add_ons(N42Node::default().add_ons())
            .launch()
            .await?;

        let payload_events = node.payload_builder.subscribe().await?;
        let mut payload_event_stream = payload_events.into_stream();

       let mut eth_signer_key = hex::encode(accounts.accounts.get(&"A".to_string()).unwrap().secret_bytes());
        println!("'A' eth_signer_key ={:?}", eth_signer_key);
        new_block(&node, eth_signer_key).await?;
       eth_signer_key = hex::encode(accounts.accounts.get(&"B".to_string()).unwrap().secret_bytes());
        println!("'B' eth_signer_key ={:?}", eth_signer_key);
        new_block(&node, eth_signer_key).await?;

        let first_event = payload_event_stream.next().await.unwrap()?;
        let second_event = payload_event_stream.next().await.unwrap()?;
        println!("first_event={:?}", first_event);
        println!("second_event={:?}", second_event);

        Ok(())
    }
}

#[tokio::test]
async fn payload_builder_and_consensus_ok() -> eyre::Result<()> {
    let test = CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(), "B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            }
            ],
            results: vec!["A".to_string(), "B".to_string()],
            failure: None,
        };
    test.run().await
}

#[tokio::test]
async fn payload_builder_and_consensus_2nd() -> eyre::Result<()> {
    println!("Running a 2nd test concurrently");
    //assert!(false);
    let test = CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(), "B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            }
            ],
            results: vec!["A".to_string(), "B".to_string()],
            failure: None,
        };
    test.run().await
}


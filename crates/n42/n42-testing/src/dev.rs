#![allow(non_snake_case)]
use reth_provider::HeaderProvider;
use reth_provider::BlockHashReader;
use reth_ethereum_engine_primitives::ExecutionPayloadV1;
use n42_engine_primitives::N42PayloadBuilderAttributes;
use reth_payload_primitives::BuiltPayload;
use reth_consensus::Consensus;
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypesWithEngine,PayloadTypes};
use std::sync::Arc;
use zerocopy::AsBytes;
use reth_chainspec::ChainSpec;
use reth_provider::{BlockReaderIdExt, BlockNumReader};
use crate::utils::n42_payload_attributes;
use alloy_primitives::{Bytes, Address, B256};
use alloy_genesis::CliqueConfig;
use futures::StreamExt;
use reth:: args::{DevArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs};
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
use n42_clique::{EXTRA_VANITY, EXTRA_SEAL};
use reth_primitives_traits::header::clique_utils::SIGNATURE_LENGTH;

use crate::snapshot_test_utils::TesterAccountPool;

//
// Types representing tester votes and test structure
#[derive(Debug, Default)]
pub struct TesterVote {
    pub signer: String,
    pub voted: Option<String>,
    pub auth: Option<bool>,
    //pub checkpoint: Option<Vec<String>>,
    //pub newbatch: Option<bool>,
}

#[derive(Debug, Default)]
pub struct CliqueTest {
    pub epoch: Option<u64>,
    pub signers: Vec<String>,
    pub votes: Vec<TesterVote>,
    pub results: Vec<String>,
    pub failure: Option<String>,
}

fn get_addresses_from_extra_data(extra_data: Bytes) -> Vec<Address> {
    let signers_count = (extra_data.len() - EXTRA_VANITY - SIGNATURE_LENGTH) / Address::len_bytes();

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
    println!("eth_signer_key={:?}", eth_signer_key);
    let parent_hash = node.provider.latest_header().unwrap().unwrap().hash();
    println!("parent_hash={:?}", parent_hash);
    println!("header={:?}", node.provider.latest_header().unwrap().unwrap().header());
    println!("header hash_slow={:?}", node.provider.latest_header().unwrap().unwrap().header().hash_slow());
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let attributes = n42_payload_attributes(timestamp, parent_hash);
    node.consensus.set_eth_signer_by_key(Some(eth_signer_key.clone()))?;
    let payload_id = node.payload_builder.send_new_payload(attributes.clone().into()).await.unwrap()?;
    println!("payload_id={}", payload_id);

    let payload_type = node.payload_builder.resolve(payload_id).await.unwrap()?;
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

        let signers: Vec<Address> = self.signers.iter().map(|s| accounts.address(s)).collect();
        // println!("signers: {:?}", signers);

        let mut chainspec = (**N42).clone();
        let mut extra_data = vec![0u8; EXTRA_VANITY + self.signers.len() * Address::len_bytes() + EXTRA_SEAL];
        for (j, signer) in signers.iter().enumerate() {
            let start = EXTRA_VANITY + j * Address::len_bytes();
            let end = start + Address::len_bytes();
            extra_data[start..end].copy_from_slice(signer.as_bytes());
        }
        chainspec.genesis.extra_data = extra_data.into();
        if let Some(epoch) = self.epoch {
            chainspec.genesis.config.clique = Some(CliqueConfig {
                epoch: Some(epoch),
                period: None,
            });
        }

        chainspec
    }

    async fn happy_path(&self) -> eyre::Result<()> {
        reth_tracing::init_test_tracing();
        let tasks = TaskManager::current();
        let exec = tasks.executor();

        let network_config = NetworkArgs {
            discovery: DiscoveryArgs { disable_discovery: true, ..DiscoveryArgs::default() },
            ..NetworkArgs::default()
        };
        let mut accounts = TesterAccountPool::new();
        let chainspec= self.gen_chainspec(&mut accounts);

        let node_config = NodeConfig::new(Arc::new(chainspec))
                .with_network(network_config.clone())
                .with_unused_ports()
                .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
            .with_dev(DevArgs { dev: false, consensus_signer_private_key: Some(B256::random()), ..Default::default() });

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

       for vote in &self.votes {
           let eth_signer_key = hex::encode(accounts.secret_key(&vote.signer).secret_bytes());
           println!("signer {} eth_signer_key ={:?}", vote.signer, eth_signer_key);
           if let Some(ref voted) = vote.voted {
               if let Some(auth) = vote.auth {
                   let voted_address = accounts.address(voted);
                   node.consensus.propose(voted_address, auth)?;
                   new_block(&node, eth_signer_key).await?;
                   node.consensus.discard(voted_address)?;
               }
           } else {
               new_block(&node, eth_signer_key).await?;
           }
       }
       let best_number = node.provider.chain_info().unwrap().best_number;
       let block_hash = node.provider.block_hash(best_number).unwrap().unwrap();
       println!("best_number={}, block_hash={}", best_number, block_hash);

       let snapshot = node.consensus.snapshot(best_number, block_hash, None).unwrap();
       println!("snapshot={:?}", snapshot);
       let expected_signers: Vec<Address> = self.results.iter().map(|a| accounts.address(a)).collect();
       assert_eq!(snapshot.signers, expected_signers);

       let first_event = payload_event_stream.next().await.unwrap()?;
       let second_event = payload_event_stream.next().await.unwrap()?;
       println!("first_event={:?}", first_event);
       println!("second_event={:?}", second_event);

       Ok(())
    }

    async fn run(&self) -> eyre::Result<()> {
        match self.happy_path().await {
            Ok(_) => (),
            Err(e) => {
                println!("error: {:?}", e);
                assert_eq!(e.to_string(), self.failure.clone().unwrap());
            },
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_single_signer__no_votes_cast() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_single_signer__voting_to_add_two_others__only_accept_first__second_needs_2_votes() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_two_signers__voting_to_add_three_others__only_accept_first_two__third_needs_3_votes_already() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("E".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("E".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_single_signer__dropping_itself__weird__but_one_less_cornercase_by_explicitly_allowing_this() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_two_signers__actually_needing_mutal_consent_to_drop_either_of_them__not_fulfilled() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_two_signers__actually_needing_mutal_consent_to_drop_either_of_them__fulfilled() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_three_signers__two_of_them_deciding_to_drop_the_third() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_four_signers__consensus_of_two_not_being_enough_to_drop_anyone() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_four_signers__consensus_of_three_already_being_enough_to_drop_someone() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_authorizations_are_counted_once_per_signer_per_target() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_authorizing_multiple_accounts_concurrently_is_permitted() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "D".to_string(),
            "C".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_deauthorizations_are_counted_once_per_signer_per_target() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_deauthorizing_multiple_accounts_concurrently_is_permitted() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_votes_from_deauthorized_signers_are_discarded_immediately__deauth_votes() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "C".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_votes_from_deauthorized_signers_are_discarded_immediately__auth_votes() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_cascading_changes_are_not_allowed__only_the_account_being_voted_on_may_change() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_changes_reaching_consensus_out_of_bounds__via_a_deauth__execute_on_touch() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_changes_reaching_consensus_out_of_bounds__via_a_deauth__may_go_out_of_consensus_on_first_touch() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_ensure_that_pending_votes_dont_survive_authorization_status_changes() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
            "E".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "E".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "E".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
            "E".to_string(),
            "F".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_epoch_transitions_reset_all_votes_to_allow_chain_checkpointing() -> eyre::Result<()> {
    let test = CliqueTest {
        epoch: Some(3),
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                // checkpoint is done on this block per epoch setting
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_an_unauthorized_signer_should_not_be_able_to_sign_blocks() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
        ],
        failure: Some("unauthorized signer".to_string()),
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_an_authorized_signer_that_signed_recently_should_not_be_able_to_sign_again() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
        ],
        failure: Some("recently signed".to_string()),
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_recent_signatures_should_not_reset_on_checkpoint_blocks_imported() -> eyre::Result<()> {
    let test = CliqueTest {
        epoch: Some(3),
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                // checkpoint is done on this block per epoch setting
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
        ],
        failure: Some("recently signed".to_string()),
        ..Default::default()
    };
    test.run().await
}

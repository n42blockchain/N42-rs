#![allow(non_snake_case)]
use alloy_rpc_types_engine::ExecutionPayloadV3;
use alloy_signer_local::PrivateKeySigner;
use reth_primitives_traits::{SealedHeader, NodePrimitives};
use reth_chainspec::make_genesis_header;
use alloy_primitives::{Sealable, FixedBytes};
use reth_node_builder::node::NodeTypes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_ethereum_forks::N42_HARDFORKS_FOR_CLIQUE_TEST;
use reth_ethereum_engine_primitives::ExecutionPayloadEnvelopeV3;
use reth_payload_primitives::{BuiltPayload, PayloadKind};
use reth_consensus::Consensus;
use reth_node_api::{FullNodeComponents, FullNodeTypes, PayloadTypes, EngineTypes};
use zerocopy::AsBytes;
use reth_chainspec::{ChainSpec, N42};
use reth_provider::{BlockHashReader, BlockReaderIdExt, BlockNumReader};

#[cfg(test)]
use crate::{utils::n42_payload_attributes, snapshot_test_utils::TesterAccountPool};

use alloy_primitives::{Bytes, Address, B256};
use alloy_genesis::CliqueConfig;
use futures::StreamExt;
use reth::{
    args::{DevArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs},
    builder::Node,
    rpc::types::engine::ForkchoiceState,
};
use reth_node_builder::{
    NodeBuilder, NodeConfig, NodeHandle, FullNode, rpc::RethRpcAddOns,
};
use reth_tasks::TaskManager;
use n42_engine_types::N42Node;

use std::{
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use reth_rpc_api::EngineApiClient;
use n42_clique::{EXTRA_VANITY, EXTRA_SEAL};
use reth_primitives_traits::{
    header::clique_utils::SIGNATURE_LENGTH,
    AlloyBlockHeader,
};

/// Types representing tester votes and test structure
#[cfg(test)]
#[derive(Debug, Default)]
pub struct TesterVote {
    pub signer: String,
    pub voted: Option<String>,
    pub auth: Option<bool>,
    //pub checkpoint: Option<Vec<String>>,
    //pub newbatch: Option<bool>,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct CliqueTest {
    pub epoch: Option<u64>,
    pub signers: Vec<String>,
    pub votes: Vec<TesterVote>,
    pub results: Vec<String>,
    pub failure: Option<String>,
}

#[cfg(test)]
fn get_addresses_from_extra_data(extra_data: Bytes) -> Vec<Address> {
    let signers_count = (extra_data.len() - EXTRA_VANITY - SIGNATURE_LENGTH) / Address::len_bytes();

    let mut signers = Vec::with_capacity(signers_count);

    for i in 0..signers_count {
        let start = EXTRA_VANITY + i * Address::len_bytes();
        let end = start + Address::len_bytes();
        signers.push(Address::from_slice(&extra_data[start..end]));
    }

    signers
}

#[cfg(test)]
async fn new_block<Node: FullNodeComponents, AddOns: RethRpcAddOns<Node>>(
    node: &FullNode<Node, AddOns>, eth_signer_key: String) -> eyre::Result<()>
    where <<<Node as FullNodeTypes>::Types as NodeTypes>::Payload as PayloadTypes>::PayloadBuilderAttributes: From<EthPayloadBuilderAttributes>,
    <<Node as FullNodeTypes>::Types as NodeTypes>::Primitives: NodePrimitives<Block = reth_ethereum_primitives::Block>,
    <<Node as FullNodeTypes>::Types as NodeTypes>::Payload: EngineTypes,
{
    let best_number = node.provider.chain_info().unwrap().best_number;
    println!("best_number={best_number}");
    println!("eth_signer_key={eth_signer_key}");
    let parent_hash = node.provider.latest_header().unwrap().unwrap().hash();
    println!("parent_hash={parent_hash:?}");
    println!("header={:?}", node.provider.latest_header().unwrap().unwrap().header());
    println!("header hash={:?}", node.provider.latest_header().unwrap().unwrap().header().hash_slow());
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let eth_signer = PrivateKeySigner::from_bytes(&FixedBytes::from_str(&eth_signer_key).unwrap()).unwrap();
    let eth_signer_address = eth_signer.address();
    let attributes = n42_payload_attributes(timestamp, parent_hash, eth_signer_address);
    node.consensus.set_eth_signer_by_key(Some(eth_signer_key.clone()))?;
    let payload_id = node.payload_builder_handle.send_new_payload(attributes.clone().into()).await.unwrap()?;
    println!("payload_id={payload_id}");

    let payload_type = node.payload_builder_handle.resolve_kind(payload_id, PayloadKind::default()).await.unwrap()?;
    println!("payload_type={payload_type:?}");
    let extra_data = payload_type.block().header().extra_data().clone();
    println!("header={:?}", payload_type.block().header());
    println!("extra_data={extra_data:?}");
    let signer_addresses = get_addresses_from_extra_data(extra_data);
    println!("signer_addresses={signer_addresses:?}");

    let payload = payload_type.clone();

    let client = node.engine_http_client();
    let execution_payload = ExecutionPayloadV3::from_block_slow(
        &payload.block().clone().into_block(),
    );
    let submission = EngineApiClient::new_payload_v3(
        &client,
        execution_payload,
        vec![],
        B256::ZERO,
    )
    .await?;
    println!("submission={submission:?}");

    let current_head = parent_hash;
    let new_head = payload_type.block().hash();
    EngineApiClient::fork_choice_updated_v1(
        &client,
        ForkchoiceState {
            head_block_hash: new_head,
            safe_block_hash: current_head,
            finalized_block_hash: current_head,
        },
        None,
        ).await?;
    println!("latest block_hash={:?}", node.provider.latest_header().unwrap().unwrap().hash());
    Ok(())
}

#[cfg(test)]
impl CliqueTest {
    fn gen_chainspec(&self, accounts: &mut TesterAccountPool) -> ChainSpec {
        let signers: Vec<Address> = self.signers.iter()
            .map(|s| accounts.address(s)).collect();

        let mut chainspec = (**N42).clone();
        let mut extra_data = vec![0u8; EXTRA_VANITY + self.signers.len() * Address::len_bytes() + EXTRA_SEAL];
        for (j, signer) in signers.iter().enumerate() {
            let start = EXTRA_VANITY + j * Address::len_bytes();
            let end = start + Address::len_bytes();
            extra_data[start..end].copy_from_slice(signer.as_bytes());
        }
        chainspec.genesis.extra_data = extra_data.into();
        let hardforks = N42_HARDFORKS_FOR_CLIQUE_TEST.clone();
        let genesis_header = SealedHeader::new_unhashed(
            make_genesis_header(&chainspec.genesis, &hardforks),
            //genesis_hash,
            );
        if let Some(epoch) = self.epoch {
            chainspec.genesis.config.clique = Some(
                CliqueConfig {
                epoch: Some(epoch),
                period: None,
            });
        }

        chainspec.hardforks = hardforks;
        chainspec.genesis_header = genesis_header;
        chainspec
    }

    async fn happy_path(&self) -> eyre::Result<()> {
        reth_tracing::init_test_tracing();
        let tasks = TaskManager::current();
        let exec = tasks.executor();

        let network_config = NetworkArgs {
            discovery: DiscoveryArgs { disable_discovery: true, ..DiscoveryArgs::default()
            },
            ..NetworkArgs::default()
        };
        let mut accounts = TesterAccountPool::new();
        let chainspec = self.gen_chainspec(&mut accounts);

        let node_config = NodeConfig::new(Arc::new(chainspec))
            .with_network(network_config.clone())
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
            .with_dev(DevArgs { dev: false, consensus_signer_private_key: Some(B256::random()), ..Default::default() });

        let NodeHandle { node, .. } = NodeBuilder::new(node_config.clone())
            .testing_node(exec.clone())
            .with_types::<N42Node>()
            .with_components(N42Node::default().components_builder())
            .with_add_ons(N42Node::default().add_ons())
            .launch()
            .await?;

       let payload_events = node.payload_builder_handle.subscribe().await?;
       let mut payload_event_stream = payload_events.into_stream();

       for vote in &self.votes {
           let eth_signer_key = hex::encode(accounts.secret_key(&vote.signer).secret_bytes());
           println!("signer={} eth_signer_key={eth_signer_key:?}", vote.signer);
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
       println!("best_number={best_number:?}, block_hash={block_hash:?}");

       let snapshot = node.consensus.snapshot(best_number, block_hash, None).unwrap();
       println!("snapshot={snapshot:?}");
       let expected_signers: Vec<Address> = self.results.iter()
           .map(|a| accounts.address(a)).collect();
       assert_eq!(snapshot.signers, expected_signers);

       let first_event = payload_event_stream.next().await.unwrap()?;
       let second_event = payload_event_stream.next().await.unwrap()?;
       println!("first_event={first_event:?}");
       println!("second_event={second_event:?}");

       Ok(())
    }

    async fn run(&self) -> eyre::Result<()> {
        match self.happy_path().await {
            Ok(_) => (),
            Err(e) => {
                println!("error: {e:?}");
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
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
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
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("E".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("E".to_string()),
                auth: Some(true),
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
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
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
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
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
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
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
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
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
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
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
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
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
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
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
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "E".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "E".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
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
        //failure: Some("unauthorized signer".to_string()),
        failure: Some("missing payload".to_string()),
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
        //failure: Some("recently signed".to_string()),
        failure: Some("missing payload".to_string()),
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
        //failure: Some("recently signed".to_string()),
        failure: Some("missing payload".to_string()),
        ..Default::default()
    };
    test.run().await
}

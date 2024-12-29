use reth_provider::{BlockReaderIdExt, BlockNumReader};
use n42_clique::{EXTRA_VANITY, SIGNATURE_LENGTH};
use crate::utils::n42_payload_attributes;
use alloy_primitives::{Bytes, Address};
use futures::StreamExt;
use reth:: args::{DevArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs};
//use reth_e2e_test_utils::setup;
use reth_node_builder::{
    NodeBuilder, NodeConfig, NodeHandle,
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

#[tokio::test]
async fn payload_builder_and_consensus_ok() -> eyre::Result<()> {
    run().await
}

#[tokio::test]
async fn payload_builder_and_consensus_2nd() -> eyre::Result<()> {
    println!("Running a 2nd test concurrently");
    //assert!(false);
    run().await
}

async fn run() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let exec = tasks.executor();

    let network_config = NetworkArgs {
        discovery: DiscoveryArgs { disable_discovery: true, ..DiscoveryArgs::default() },
        ..NetworkArgs::default()
    };
    let node_config = NodeConfig::new(N42.clone())
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

    let eth_signer_keys:Vec<String> = vec![
        "6f142508b4eea641e33cb2a0161221105086a84584c74245ca463a49effea30b",
        "4f5c2b3e8d45f72c87c8c7d1d5e6f5b8e7f9d4e6c1a2b3c4d5e6f7a8f9a0b1c2",
    ].iter().map(|v|v.to_string()).collect();
    let new_block_future = || async {
        let best_number = node.provider.chain_info().unwrap().best_number;
        println!("best_number={}", best_number);
        let eth_signer_key = &eth_signer_keys[(best_number % 2) as usize];
        println!("eth_signer_key={:?}", eth_signer_key);
        let parent_hash = node.provider.latest_header().unwrap().unwrap().hash();
        println!("parent_hash={:?}", parent_hash);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let attributes = n42_payload_attributes(timestamp, parent_hash);
        node.consensus.set_eth_signer_by_key(Some(eth_signer_key.clone()))?;
        let payload_id = node.payload_builder.send_new_payload(attributes.clone()).await.unwrap()?;
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
    };

    new_block_future().await?;

    new_block_future().await?;

    new_block_future().await?;

    new_block_future().await?;

    let first_event = payload_event_stream.next().await.unwrap()?;
    let second_event = payload_event_stream.next().await.unwrap()?;
    println!("first_event={:?}", first_event);
    println!("second_event={:?}", second_event);
    
    Ok(())
}

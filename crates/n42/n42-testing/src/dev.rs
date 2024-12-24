use n42_clique::{EXTRA_VANITY, SIGNATURE_LENGTH};
use crate::utils::n42_payload_attributes;
use alloy_primitives::{Bytes, Address};
use futures::StreamExt;
use reth::args::DevArgs;
//use reth_e2e_test_utils::setup;
use reth_node_builder::{
    NodeBuilder, NodeConfig, NodeHandle,
};
use reth_tasks::TaskManager;
use reth_chainspec::N42;
use n42_engine_types::N42Node;

use reth::builder::Node;
use reth_payload_primitives::PayloadBuilder;
use reth_provider::StateProviderFactory;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
async fn can_run_dev_node_new_engine() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let tasks = TaskManager::current();
    let exec = tasks.executor();

    let node_config = NodeConfig::new(N42.clone())
        //.with_chain(custom_chain())
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

    //let timestamp = 1710338135;
    //let timestamp = 0x6159af19;
    let timestamp = SystemTime::now().checked_add(Duration::new(1,0)).unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let attributes = n42_payload_attributes(timestamp);
    let payload_id = node.payload_builder.send_new_payload(attributes.clone()).await.unwrap()?;
    println!("payload_id={}", payload_id);
    let latest = node.provider.latest()?;
    println!("latest block_hash(1)={:?}", latest.block_hash(1));

    let payload_type = node.payload_builder.resolve(payload_id).await.unwrap().unwrap();
    println!("payload_type={:?}", payload_type);

    let first_event = payload_event_stream.next().await.unwrap()?;
    let second_event = payload_event_stream.next().await.unwrap()?;
    println!("first_event={:?}", first_event);
    println!("second_event={:?}", second_event);

    let extra_data = payload_type.block().header.extra_data.clone();
    println!("extra_data={:?}", extra_data);
    let signer_addresses = get_addresses_from_extra_data(extra_data);
    println!("signer_addresses={:?}", signer_addresses);
    Ok(())
}

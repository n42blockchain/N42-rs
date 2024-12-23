use std::sync::Arc;

use crate::utils::n42_payload_attributes;
use alloy_genesis::Genesis;
use alloy_primitives::{b256, hex};
use futures::StreamExt;
use reth::{args::DevArgs, rpc::api::eth::helpers::EthTransactions};
use reth_chainspec::ChainSpec;
//use reth_e2e_test_utils::setup;
use reth_node_api::FullNodeComponents;
use reth_node_builder::{
    rpc::RethRpcAddOns, EngineNodeLauncher, FullNode, NodeBuilder, NodeConfig, NodeHandle, DefaultNodeLauncher,
};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_provider::{providers::BlockchainProvider2, CanonStateSubscriptions};
use reth_tasks::TaskManager;
use reth_chainspec::N42;
use n42_engine_types::N42Node;
use reth_provider::test_utils::MockEthProvider;

use reth::{
    builder::{
        components::{ComponentsBuilder},
        node::{NodeTypes, NodeTypesWithEngine},
        FullNodeTypes, Node, NodeAdapter, NodeComponentsBuilder,
    },
};
use reth_payload_primitives::PayloadBuilder;

/*
#[tokio::test]
async fn can_run_dev_node() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let (mut nodes, _tasks, _) =
        setup::<EthereumNode>(1, custom_chain(), true, eth_payload_attributes).await?;

    assert_chain_advances(nodes.pop().unwrap().inner).await;
    Ok(())
}
*/

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
        /*
        .launch_with_fn(|builder| {
            let launcher = DefaultNodeLauncher::new(
                builder.task_executor().clone(),
                builder.config().datadir(),
            );
            builder.launch_with(launcher)
        })
        */
        .await?;

    let payload_events = node.payload_builder.subscribe().await?;
    let mut payload_event_stream = payload_events.into_stream();

    //let timestamp = 1710338135;
    //let timestamp = 0x6159af19;
    let timestamp = 0x6159af1f;
    let attributes = n42_payload_attributes(timestamp);
    let payload_id = node.payload_builder.send_new_payload(attributes.clone()).await.unwrap()?;
    println!("payload_id={}", payload_id);
    
    /*
    let first_event = payload_event_stream.next().await.unwrap()?;
    let second_event = payload_event_stream.next().await.unwrap()?;
    println!("first_event={:?}", first_event);
    println!("second_event={:?}", second_event);

  loop {
      let payload = node.payload_builder.best_payload(payload_id)
.await.unwrap().unwrap();
      if payload.block().body.transactions.is_empty() {
          tokio::time::sleep(std::time::Duration::from_millis(20))
.await;
          continue
      }
      break
  }
  */


    let payload_type = node.payload_builder.resolve(payload_id).await.unwrap().unwrap();
    println!("payload_type={:?}", payload_type);

    //assert_chain_advances(node).await;


    Ok(())
}

async fn assert_chain_advances<N, AddOns>(node: FullNode<N, AddOns>)
where
    N: FullNodeComponents<Provider: CanonStateSubscriptions>,
    AddOns: RethRpcAddOns<N, EthApi: EthTransactions>,
{
    let mut notifications = node.provider.canonical_state_stream();

    // submit tx through rpc
    let raw_tx = hex!("02f876820a28808477359400847735940082520894ab0840c0e43688012c1adb0f5e3fc665188f83d28a029d394a5d630544000080c080a0a044076b7e67b5deecc63f61a8d7913fab86ca365b344b5759d1fe3563b4c39ea019eab979dd000da04dfc72bb0377c092d30fd9e1cab5ae487de49586cc8b0090");

    let eth_api = node.rpc_registry.eth_api();

    let hash = eth_api.send_raw_transaction(raw_tx.into()).await.unwrap();

    let expected = b256!("b1c6512f4fc202c04355fbda66755e0e344b152e633010e8fd75ecec09b63398");

    assert_eq!(hash, expected);
    println!("submitted transaction: {hash}");

    let head = notifications.next().await.unwrap();

    let tx = head.tip().transactions().next().unwrap();
    assert_eq!(tx.hash(), hash);
    println!("mined transaction: {hash}");
}

fn custom_chain() -> Arc<ChainSpec> {
    let custom_genesis = r#"
{

    "nonce": "0x42",
    "timestamp": "0x0",
    "extraData": "0x5343",
    "gasLimit": "0x13880",
    "difficulty": "0x400000000",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
        "0x6Be02d1d3665660d22FF9624b7BE0551ee1Ac91b": {
            "balance": "0x4a47e3c12448f4ad000000"
        }
    },
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "config": {
        "ethash": {},
        "chainId": 2600,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "berlinBlock": 0,
        "londonBlock": 0,
        "terminalTotalDifficulty": 0,
        "terminalTotalDifficultyPassed": true,
        "shanghaiTime": 0
    }
}
"#;
    let genesis: Genesis = serde_json::from_str(custom_genesis).unwrap();
    Arc::new(genesis.into())
}


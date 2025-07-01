//! N42 Mobile Client
//!
//! This module provides a mobile client for connecting to N42 blockchain network
//! via WebSocket and processing unverified blocks.

use futures_util::{StreamExt, SinkExt};
// use revm_primitives::map::foldhash::fast::RandomState;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use serde_json::json;
use n42_engine_types::UnverifiedBlock;
use reth_provider::test_utils::MockEthProvider;
use reth_revm::{database::StateProviderDatabase,db::State};
use std::sync::Arc;
use reth_chainspec::{ChainSpecBuilder,N42_DEVNET,EthereumHardfork,ForkCondition,ChainSpec};
use alloy_primitives::address;
use reth_evm_ethereum::EthEvmConfig;
use reth_evm::ConfigureEvm;
use alloy_consensus::Header;
use revm_primitives::B256;
use reth_ethereum_primitives::{Block,Receipt};
use reth_evm::execute::Executor;
use reth_primitives_traits::{RecoveredBlock};
use alloy_consensus::EthereumTxEnvelope;
// use std::collections::HashMap;
use alloy_primitives::map::HashMap;
use alloy_primitives::Address;
use reth_provider::test_utils::ExtendedAccount;
use reth_primitives_traits::Account;
use alloy_primitives::U256;
use reth_primitives::Bytecode;
use foldhash::fast::RandomState;
use yansi::Paint;
fn evm_config(chain_spec: Arc<ChainSpec>) -> EthEvmConfig {
    EthEvmConfig::new(chain_spec)
}
fn inject_unverifiedblock_accounts(
    provider: &MockEthProvider,
    unverified_block: &UnverifiedBlock,
) {
    let mut extended_accounts: HashMap<Address, ExtendedAccount,RandomState> = 
        HashMap::with_hasher(RandomState::default());

    for (addr, cached) in &unverified_block.db.accounts {
        let account = Account {
            nonce: cached.info.as_ref().map_or(0, |info| info.nonce),
            balance: cached.info.as_ref().map_or(U256::ZERO, |info| info.balance),
            bytecode_hash: None,
        };

        let bytecode: Option<Bytecode> = cached
            .info
            .as_ref()
            .and_then(|info| info.code.clone())
            .map(Bytecode);

        // ✅ storage key 类型从 U256 -> B256
        let storage: HashMap<B256, U256> = cached
            .storage
            .iter()
            .map(|(k, v)| (B256::from(k.to_be_bytes()), *v))
            .collect();

        let extended = ExtendedAccount {
            account,
            bytecode,
            storage,
        };

        extended_accounts.insert(*addr, extended);
    }

    provider.extend_accounts(extended_accounts);
}

fn verify(mut unverifiedblock:UnverifiedBlock){
    // let nonce_of_tx = match &unverifiedblock.blockbody.transactions[0] {
    //     EthereumTxEnvelope::Eip4844(signed_tx) => signed_tx.tx().nonce,
    //     EthereumTxEnvelope::Eip1559(signed_tx)=>signed_tx.tx().nonce,
    //     EthereumTxEnvelope::Eip2930(signed_tx)=>signed_tx.tx().nonce,
    //     EthereumTxEnvelope::Eip7702(signed_tx)=>signed_tx.tx().nonce,
    //     EthereumTxEnvelope::Legacy(signed_tx)=>signed_tx.tx().nonce,
    //     _ => panic!("Not an EIP-4844 type transaction"),
    // };
    // println!("nonce_of_tx:{}",nonce_of_tx);
    // unverifiedblock.db.set_nonce(nonce_of_tx);
    // println!("nonce_of_state:{}",unverifiedblock.db.get_nonce());
    // let nonce1=unverifiedblock.db.get_nonce();
    // println!("nonce1:{}",nonce1);
    // if nonce1>0{
    //     unverifiedblock.db.set_nonce(nonce1-1);
    // }
    // let nonce2=unverifiedblock.db.get_nonce();
    // println!("nonce2:{}",nonce2);
    println!("➡️    cached_reads:{:?}",unverifiedblock.db);
    let provider_1=MockEthProvider::default();
    inject_unverifiedblock_accounts(&provider_1, &unverifiedblock);
    println!("➡️    accounts:{:?}",provider_1.accounts);
    // let state_provider=
    let state=StateProviderDatabase::new(provider_1);
    let cache_state = unverifiedblock.db.convert_cached_reads_to_cache_state();
    let db=
        State::builder().with_database(unverifiedblock.db.as_db_mut(state))
        .with_bundle_update().with_cached_prestate(cache_state).build();
    println!("➡️    cache_state:{:?}",db.cache);
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*N42_DEVNET)
            .shanghai_activated()
            .with_fork(
                EthereumHardfork::Cancun, 
                ForkCondition::Timestamp(1))
            .build(),
    );
    let addr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    let provider=evm_config(chain_spec);
    let mut executor = provider.batch_executor(db);
    let mut header=Header{gas_limit:50000,gas_used:50000,..Header::default()};
    header.parent_beacon_block_root=Some(B256::with_last_byte(0x69));
    let mut receipts:Vec<Receipt>=Vec::new();
    match executor.execute_one(&RecoveredBlock::new_unhashed(
        Block { header: header.clone(), body: unverifiedblock.blockbody },
        vec![addr,addr],
    )) {
        Ok(result) => {
            println!("success");
            receipts=result.receipts;
        }
        Err(e) => println!("Error during execution: {:?}", e),
        // println!("Error during execution: {:?}", e),
    }
    // let temp=executor.finalize();
    // let receipts=temp.receipts();
    // if !receipts.receipt_vec.is_empty() && !receipts.receipt_vec[0].is_empty() {
    //     let txreceipt = receipts.receipt_vec[0][0].as_ref().unwrap();
    //     println!("{:?}", txreceipt);
    // } else {
    //     println!("No receipts found");
    // }
    if receipts.is_empty() {
        println!("No receipts found");
    } else {
        println!("✅!!!!!!!!!!!!{:?}", receipts);
        println!("✅!!!!!!!!!!!!RRRRTTTT{:?}", Receipt::calculate_receipt_root_no_memo(&receipts));
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define Ethereum WebSocket RPC endpoint
    // You can use public services like Infura or Alchemy, or locally running Geth/Parity
    let url = "ws://127.0.0.1:8546"; // **Please replace with your Infura project ID**
    // Register an Infura account and create a new project to get your project ID.
    // If you don't have an Infura project ID, you can try using public testnet nodes, but they may be unstable.

    println!("Attempting to connect to WebSocket: {}", url);

    // 连接到 WebSocket
    let (ws_stream, _) = connect_async(url).await?;
    println!("Successfully connected to WebSocket!");

    let (mut write, mut read) = ws_stream.split();

    // 构建订阅 newHeads 的 JSON-RPC 请求
    let subscribe_message = json!({
        "jsonrpc": "2.0",
        "method": "minedblockExt_subscribeMinedblock",
        "params": [],
        "id": 1
    }).to_string();

    println!("Sending subscription message: {}", subscribe_message);

    // 发送订阅消息
    write.send(Message::Text(subscribe_message)).await?;
    println!("Subscription message sent, starting to listen for new block headers...");

    // 监听 WebSocket 消息
    while let Some(message) = read.next().await {
        match message {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_text()?;
                    // println!("Received message: {}", text); // Uncomment this line if you want to see all raw messages

                    // Parse JSON response
                    let json_response: serde_json::Value = serde_json::from_str(text)?;

                    // Check if this is a newHeads subscription notification
                    // println!("{:?}",json_response);
                    
                    // Organize json_response into UnverifiedBlock
                    if let Some(params) = json_response.get("params") {
                        if let Some(result) = params.get("result") {
                            // Try to parse UnverifiedBlock from JSON
                            match serde_json::from_value::<UnverifiedBlock>(result.clone()) {
                                Ok(unverified_block) => {
                                    if !unverified_block.blockbody.transactions.is_empty(){
                                        println!("There are transactions inside: {:?}",unverified_block.blockbody.transactions);
                                        verify(unverified_block);
                                    }else{
                                        println!("This block has no transactions");
                                    }
                                    // println!("Successfully parsed UnverifiedBlock: {:?}", unverified_block);
                                    // You can call the verify function here
                                    // verify(unverified_block);
                                },
                                Err(e) => {
                                    println!("Failed to parse UnverifiedBlock: {}", e);
                                    // If direct parsing fails, you can try manual construction
                                    // Here you can construct UnverifiedBlock based on the actual JSON structure
                                }
                            }
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("WebSocket error: {}", e);
                break; // Exit loop when encountering an error
            }
        }
    }

    Ok(())
}
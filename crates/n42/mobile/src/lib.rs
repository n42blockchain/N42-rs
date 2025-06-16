use jsonrpsee::ws_client::WsClientBuilder;
use n42_engine_types::{MinedblockExtApiClient,UnverifiedBlock};
use reth_provider::{test_utils::MockEthProvider, BlockExecutionResult};
use reth_revm::{
    context::result, database::StateProviderDatabase, db::State
};
use std::sync::Arc;
use reth_chainspec::{
    ChainSpecBuilder,N42,EthereumHardfork,ForkCondition,ChainSpec,
};
use alloy_primitives::address;
use reth_evm_ethereum::EthEvmConfig;
use reth_evm::{
    ConfigureEvm,
    execute::Executor,
};
use alloy_consensus::Header;
use revm_primitives::B256;
use reth_primitives_traits::{RecoveredBlock};
use reth_ethereum_primitives::{Block,Receipt};

fn evm_config(chain_spec: Arc<ChainSpec>) -> EthEvmConfig {
    EthEvmConfig::new(chain_spec)
}

fn verify(mut unverifiedblock:UnverifiedBlock){
    // let nonce1=unverifiedblock.db.get_nonce();
    // println!("nonce1:{}",nonce1);
    // if nonce1>0{
    //     unverifiedblock.db.set_nonce(nonce1-1);
    // }
    // let nonce2=unverifiedblock.db.get_nonce();
    // println!("nonce2:{}",nonce2);
    let provider_1=MockEthProvider::default();
    let state=StateProviderDatabase::new(provider_1);
    let mut db=State::builder().with_database(
        unverifiedblock.db.as_db_mut(state)).with_bundle_update().build();
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*N42)
            .shanghai_activated()
            .with_fork(
                EthereumHardfork::Cancun, 
                ForkCondition::Timestamp(1))
            .build(),
    );
    let addr = address!("73E766350Bd18867FE55ACb8b96Df7B11CdACF92");
    let provider=evm_config(chain_spec);
    let mut executor = provider.batch_executor(db);
    let mut header=Header{gas_limit:21000,gas_used:21000,..Header::default()};
    header.parent_beacon_block_root=Some(B256::with_last_byte(0x69));
    let mut receipts:Vec<Receipt>=Vec::new();
    match executor.execute_one(&RecoveredBlock::new_unhashed(
        Block { header: header.clone(), body: unverifiedblock.blockbody },
        vec![addr],
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
        let txreceipt = &receipts[0];
        println!("{:?}", txreceipt);
    }
}
fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let ws_url = "ws://127.0.0.1:8546".to_string();
        println!("linking to the server: {}", ws_url);

        let client = WsClientBuilder::default()
            .build(&ws_url)
            .await
            .expect("failed to connect to the server");
        println!("successfully connected to the server");

        let mut subscription = MinedblockExtApiClient::subscribe_minedblock(&client)
            .await
            .expect("failed to subscribe to block data");
        println!("successfully subscribed to block data");

        println!("listening to the block data...");
        loop {
            println!("waiting for new block...");
            match subscription.next().await {
                Some(Ok(block)) => {
                    println!("the new block: {:?}", block);
                    verify(block);
                }
                Some(Err(e)) => {
                    println!("failed to receive the new block data: {:?}", e);
                }
                None => {
                    println!("link been cut");
                    break;
                }
            }
        }
    });
}
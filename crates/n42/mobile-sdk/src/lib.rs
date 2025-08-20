use reth_primitives_traits::AlloyBlockHeader;
use blst::min_pk::SecretKey;
use reth_evm::execute::Executor;
use revm_primitives::B256;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_evm_ethereum::EthEvmConfig;
use reth_ethereum_primitives::{Block, Receipt};
use reth_provider::test_utils::MockEthProvider;
use reth_revm::{database::StateProviderDatabase,db::State};
use reth_chainspec::{ChainSpecBuilder,N42_DEVNET,EthereumHardfork,ForkCondition,ChainSpec};
use reth_evm::ConfigureEvm;
use std::sync::Arc;
use jsonrpsee::core::client::{SubscriptionClientT, ClientT};
use anyhow::Context;
use futures_util::StreamExt;
use jsonrpsee::core::client::Subscription;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;
use n42_clique::{BlockVerifyResult, UnverifiedBlock};
use n42_primitives::{AttestationData, BLS_DST};

const MAX_RETRIES: usize = 5;
const RETRY_INTERVAL_SECS: u64 = 5;

pub async fn run_client(ws_url: &str, sk: &SecretKey) -> anyhow::Result<()> {
    let mut retry_count = 0;

    loop {
        match try_run_client(ws_url, &sk).await {
            Ok(_) => {
                println!("WebSocket client exited normally.");
                break;
            }
            Err(e) => {
                eprintln!("Connection error: {:?}", e);
                retry_count += 1;
                if retry_count >= MAX_RETRIES {
                    eprintln!("Max retries reached, exiting.");
                    break;
                }
                println!("Retrying in {} seconds...", RETRY_INTERVAL_SECS);
                sleep(Duration::from_secs(RETRY_INTERVAL_SECS)).await;
            }
        }
    }

    Ok(())
}

async fn try_run_client(ws_url: &str, sk: &SecretKey) -> anyhow::Result<()> {
    let ws_client = WsClientBuilder::default()
        .build(ws_url)
        .await
        .context("Failed to build WebSocket client")?;

    println!("Connected to {}", ws_url);

    let pk = sk.sk_to_pk();
    let mut subscription: Subscription<UnverifiedBlock> = ws_client
        .subscribe("consensusBeaconExt_subscribeToVerificationRequest", rpc_params![hex::encode(pk.to_bytes())],
"")
        .await
        .context("Failed to subscribe")?;

    println!("Subscribed to 'subscribeToVerificationRequest'");

    while let Some(msg) = subscription.next().await {
        match msg {
            Ok(block) => {
                println!("Received block: {:?}", block);

                if let Ok(receipts_root) = verify(block.clone()) {
                    println!("receipts_root: {:?}", receipts_root);

                    let attestation_data = AttestationData {
                        slot: block.blockbody.header().number(),
                        committee_index: block.committee_index,
                        receipts_root,
                    };

                    let pk = sk.sk_to_pk();

                    let bytes: Vec<u8> = serde_json::to_vec(&attestation_data)?;
                    let bytes_slice: &[u8] = &bytes;

                    let msg = bytes_slice;
                    let sig = sk.sign(msg, BLS_DST, &[]);

                    let err = sig.verify(true, msg, BLS_DST, &[], &pk, true);
                    println!("sig verify result: {:?}", err);

                    let mut header = block.blockbody.header().clone();
                    header.receipts_root = receipts_root;
                    let body = block.blockbody.body().clone();
                    let sealed_block_recovered: SealedBlock<Block> = SealedBlock::from_parts_unhashed(header, body);

                    let recovered_block_hash = SealedBlock::hash(&sealed_block_recovered);
                    let params = rpc_params![hex::encode(pk.to_bytes()), hex::encode(sig.to_bytes()), attestation_data, hex::encode(recovered_block_hash.as_slice())];
                    let result = ws_client
                        .request("consensusBeaconExt_submitVerification", params)
                        .await?;
                    println!("request result: {:?}", result);

                } else {
                    println!("verify failed");
                    break;
                }

            }
            Err(e) => {
                eprintln!("Subscription error: {:?}", e);
                return Err(e.into());
            }
        }
    }

    println!("Subscription closed by server.");
    Ok(())
}

fn verify(mut unverifiedblock:UnverifiedBlock) -> anyhow::Result<B256> {
    println!("verify, {unverifiedblock:?}");
    let provider_1=MockEthProvider::default();
    let state=StateProviderDatabase::new(provider_1);
    let db=
        State::builder().with_database(unverifiedblock.db.as_db_mut(state)).build();
    let chain_spec = Arc::new(
        ChainSpecBuilder::from(&*N42_DEVNET)
            .shanghai_activated()
            .with_fork(
                EthereumHardfork::Cancun,
                ForkCondition::Timestamp(1))
            .build(),
    );
    let provider=evm_config(chain_spec);
    let mut executor = provider.batch_executor(db);
    let mut receipts:Vec<Receipt>=Vec::new();

    // for test
    let sealed_block_receipts_root = unverifiedblock.blockbody.header().receipts_root;

    let recovered = RecoveredBlock::try_recover_sealed(unverifiedblock.blockbody).unwrap();
    match executor.execute_one(&recovered) {
        Ok(result) => {
            println!("success, {result:?}");
            receipts=result.receipts;
        }
        Err(e) => println!("Error during execution: {:?}", e),
    }
    println!("{receipts:?}");
    let receipts_root = Receipt::calculate_receipt_root_no_memo(&receipts);
    println!("computed {receipts_root:?}");

    // for test
    if sealed_block_receipts_root != B256::ZERO {
        if receipts_root != sealed_block_receipts_root {
            return Err(anyhow::anyhow!("receipts_root={:?}, expected={:?}", receipts_root, sealed_block_receipts_root));
        }
    }

    Ok(receipts_root)
}

fn evm_config(chain_spec: Arc<ChainSpec>) -> EthEvmConfig {
    EthEvmConfig::new(chain_spec)
}

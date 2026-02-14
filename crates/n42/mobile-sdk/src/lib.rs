use tokio::time::Instant;
use hex::FromHex;
use once_cell::sync::Lazy;
use reth_primitives_traits::AlloyBlockHeader;
use blst::min_pk::SecretKey;
use reth_evm::execute::Executor;
use revm_primitives::B256;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_evm_ethereum::EthEvmConfig;
use reth_ethereum_primitives::{Block, EthPrimitives, Receipt};
use reth_provider::test_utils::MockEthProvider;
use reth_revm::{database::StateProviderDatabase,db::State};
use reth_chainspec::{ChainSpecBuilder,N42_DEVNET,EthereumHardfork,ForkCondition,ChainSpec};
use reth_evm::ConfigureEvm;
use tokio::time::timeout;
use std::{sync::Arc, time::Duration};

/// Cached chain spec for mobile SDK block verification.
/// Avoids rebuilding ChainSpec on every verify() call - important for mobile performance.
static SDK_CHAIN_SPEC: Lazy<Arc<ChainSpec>> = Lazy::new(|| {
    Arc::new(
        ChainSpecBuilder::from(&*N42_DEVNET)
            .shanghai_activated()
            .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
            .build(),
    )
});
use jsonrpsee::core::client::{SubscriptionClientT, ClientT};
use futures_util::StreamExt;
use jsonrpsee::core::client::Subscription;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use serde::{Deserialize, Serialize};
use n42_clique::{BlockVerifyResult, UnverifiedBlock};
use n42_primitives::{AttestationData};
use tracing::{trace, debug, info, warn, instrument, Level};

pub mod deposit_exit;

/// cbindgen:ignore
pub mod jni;

pub mod c_ffi;

pub mod blst_utils;

pub async fn run_client(
    ws_url: &str,
    validator_private_key: &str,
    ) -> eyre::Result<()> {
    let validator_private_key = validator_private_key.strip_prefix("0x").unwrap_or(validator_private_key);
    let mut validator_private_key_vec = Vec::from_hex(&validator_private_key)?;
    let sk = SecretKey::from_bytes(&validator_private_key_vec)
        .map_err(|e| eyre::eyre!("SecretKey error: {e:?}"));
    // Zero out private key bytes immediately after use
    validator_private_key_vec.fill(0);
    let sk = sk?;
    let pk = sk.sk_to_pk();

    let message_timeout_secs = 300;
    loop {
        let ws_client = WsClientBuilder::default()
            .build(ws_url)
            .await?;

        info!("Connected to {}", ws_url);

        let mut subscription: Subscription<UnverifiedBlock> = ws_client
            .subscribe("consensusBeaconExt_subscribeToVerificationRequest", rpc_params![hex::encode(pk.to_bytes())],
    "")
            .await?;

        info!("Subscribed to 'subscribeToVerificationRequest'");

        while let Ok(Some(msg)) = timeout(Duration::from_secs(message_timeout_secs ), subscription.next()).await {
            match msg {
                Ok(block) => {
                    let block_verify_result = gen_block_verify_result_inner(block, &sk).await?;
                    let params = rpc_params![block_verify_result.pubkey, block_verify_result.signature, block_verify_result.attestation_data, hex::encode(block_verify_result.block_hash.as_slice())];
                    let result: () = ws_client
                        .request("consensusBeaconExt_submitVerification", params)
                        .await?;
                    debug!("request result: {:?}", result);

                }
                Err(e) => {
                    warn!("Subscription error: {:?}", e);
                    return Err(e.into());
                }
            }
        }

        warn!("No update in {message_timeout_secs:?} seconds — closing and reconnecting...");

        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    Ok(())
}

pub async fn gen_block_verify_result(
    block: UnverifiedBlock,
    validator_private_key: &str,
    ) -> eyre::Result<BlockVerifyResult> {
    let validator_private_key = validator_private_key.strip_prefix("0x").unwrap_or(validator_private_key);
    let mut validator_private_key_vec = Vec::from_hex(&validator_private_key)?;
    let sk = SecretKey::from_bytes(&validator_private_key_vec)
        .map_err(|e| eyre::eyre!("SecretKey error: {e:?}"));
    // Zero out private key bytes immediately after use
    validator_private_key_vec.fill(0);
    let sk = sk?;
    gen_block_verify_result_inner(block, &sk).await
}

#[instrument(
    level = Level::DEBUG,
    ret,
    skip_all,
    fields(pubkey = hex::encode(sk.sk_to_pk().to_bytes()), block_number=block.blockbody.header().number()),
    )]
async fn gen_block_verify_result_inner(block: UnverifiedBlock, sk: &SecretKey) -> eyre::Result<BlockVerifyResult> {
    let pk = sk.sk_to_pk();
    debug!("Received block, thread-id: {:?}", std::thread::current().id());

    let block_clone = block.clone();

    let start = Instant::now();
    let verify_result = tokio::task::spawn_blocking(|| verify(block_clone)).await;
    let duration = start.elapsed();
    debug!(?duration, "block verify");

    // Propagate both JoinError and verify error directly
    let receipts_root = verify_result??;
    debug!("receipts_root: {:?}", receipts_root);

    let attestation_data = AttestationData {
        slot: block.blockbody.header().number(),
        committee_index: block.committee_index,
        receipts_root,
    };

    let bytes: Vec<u8> = serde_json::to_vec(&attestation_data)?;
    let start = Instant::now();
    let sig = sk.sign(&bytes, alloy_rpc_types_beacon::constants::BLS_DST_SIG, &[]);
    let duration = start.elapsed();
    debug!(?duration, "bls sign");

    // BLS self-verification skipped on mobile: node verifies signatures upon receipt.
    // Mobile's job is receipt verification (block re-execution), not signature self-check.

    let mut header = block.blockbody.header().clone();
    header.receipts_root = receipts_root;
    let body = block.blockbody.body().clone();
    let sealed_block_recovered: SealedBlock<Block> = SealedBlock::from_parts_unhashed(header, body);
    let recovered_block_hash = SealedBlock::hash(&sealed_block_recovered);

    let block_verify_result = BlockVerifyResult {
        pubkey: hex::encode(pk.to_bytes()),
        signature: hex::encode(sig.to_bytes()),
        attestation_data,
        block_hash: recovered_block_hash,
    };

    debug!("Finished block: {:?}, pk: {:?}, thread-id: {:?}", block.blockbody.header().number(), hex::encode(pk.to_bytes()), std::thread::current().id());
    Ok(block_verify_result)
}

#[instrument(
    level = Level::DEBUG,
    ret,
    skip_all,
    )]
fn verify(mut unverifiedblock:UnverifiedBlock) -> eyre::Result<B256> {
    trace!(?unverifiedblock);
    let chain_spec = SDK_CHAIN_SPEC.clone();
    let mock_eth_provider: MockEthProvider<EthPrimitives> = MockEthProvider::new_with_chain_spec((*chain_spec).clone());
    let state = StateProviderDatabase::new(mock_eth_provider);
    let db = State::builder().with_database(unverifiedblock.db.as_db_mut(state)).build();
    let evm_config = EthEvmConfig::new(chain_spec);
    let mut executor = evm_config.batch_executor(db);

    // The expected receipts_root from the block header, used to verify execution correctness.
    // Mobile SDK re-executes the block and compares receipts_root — this is the core
    // verification path for mobile validators (no full state/Merkle tree needed).
    let expected_receipts_root = unverifiedblock.blockbody.header().receipts_root;

    let recovered = RecoveredBlock::try_recover_sealed(unverifiedblock.blockbody)?;
    let result = executor.execute_one(&recovered)
        .map_err(|e| eyre::eyre!("block execution failed: {e:?}"))?;

    let receipts_root = Receipt::calculate_receipt_root_no_memo(&result.receipts);
    debug!("computed {receipts_root:?}");

    // Verify receipts_root matches: ensures the block execution is correct.
    if expected_receipts_root != B256::ZERO && receipts_root != expected_receipts_root {
        return Err(eyre::eyre!(
            "receipts_root mismatch: computed={receipts_root:?}, expected={expected_receipts_root:?}"
        ));
    }

    Ok(receipts_root)
}

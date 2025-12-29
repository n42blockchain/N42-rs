#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use consensus_client::migrate::N42Migrate;
use consensus_client::miner::N42Miner;
use n42::consensus_ext::{
    ConsensusBeaconExt, ConsensusBeaconExtApiServer, ConsensusExt, ConsensusExtApiServer,
};
use n42::{args::RessArgs, cli::Cli, ress::install_ress_subprotocol};
use n42_clique::UnverifiedBlock;
use n42_engine_primitives::N42PayloadAttributesBuilder;
use n42_engine_types::N42Node;
use n42_primitives::BLSPubkey;
use pubsub_mem::{publish, router_loop, Event, RouterMsg};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::{FullNodeComponents, NodeHandle};
use reth_node_core::primitives::AlloyBlockHeader;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info};

const DEFAULT_BLOCK_TIME_SECS: u64 = 8;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let (verification_tx, verification_rx) = mpsc::channel(100);
    let (broadcast_tx, _broadcast_rx) = broadcast::channel::<(UnverifiedBlock, Arc<Vec<BLSPubkey>>)>(100);
    let broadcast_tx_clone_for_miner = broadcast_tx.clone();

    // Create router channel for pubsub and start router loop
    let (router_tx, router_rx) = mpsc::channel::<RouterMsg<UnverifiedBlock>>(100);
    let router_tx_clone = router_tx.clone();
    let router_tx_for_bridge = router_tx.clone();

    // Start the pubsub router loop
    tokio::spawn(async move {
        debug!(target: "reth::cli", "Starting pubsub router loop");
        router_loop(router_rx).await;
    });

    // Bridge: forward messages from broadcast channel to pubsub router
    let mut broadcast_rx_for_bridge = broadcast_tx.subscribe();
    tokio::spawn(async move {
        debug!(target: "reth::cli", "Starting broadcast-to-pubsub bridge");
        while let Ok((unverified_block, target_pubkeys)) = broadcast_rx_for_bridge.recv().await {
            debug!(
                target: "reth::cli",
                block_number = unverified_block.blockbody.header().number(),
                num_validators = target_pubkeys.len(),
                "Broadcasting block to validators"
            );
            // Send to each validator's topic (pubkey hex)
            for pubkey in target_pubkeys.iter() {
                let topic = hex::encode(pubkey);
                let event = Event {
                    topic: topic.clone(),
                    payload: unverified_block.clone(),
                };
                publish(&router_tx_for_bridge, event).await;
                debug!(target: "reth::cli", ?topic, "Published block to validator topic");
            }
        }
        debug!(target: "reth::cli", "Broadcast-to-pubsub bridge ended");
    });

    // Shared consensus instance holder
    let consensus_holder: std::sync::Arc<
        std::sync::Mutex<
            Option<
                std::sync::Arc<
                    dyn reth_consensus::FullConsensus<
                            reth_ethereum_primitives::EthPrimitives,
                            Error = reth_consensus::ConsensusError,
                        > + Send
                        + Sync,
                >,
            >,
        >,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let consensus_holder_clone = consensus_holder.clone();

    if let Err(err) =
        Cli::<EthereumChainSpecParser, RessArgs>::parse().run(async move |builder, ress_args| {
            info!(target: "reth::cli", "Launching node");
            let NodeHandle {
                node,
                node_exit_future,
            } = builder
                .node(N42Node::default())
                .extend_rpc_modules(move |ctx| {
                    let consensus = ctx.node().consensus().clone();
                    let provider = ctx.provider().clone();

                    // Store consensus reference for later use
                    *consensus_holder_clone.lock().unwrap() =
                        Some(std::sync::Arc::new(consensus.clone()));

                    let beacon_ext = ConsensusBeaconExt {
                        consensus: consensus.clone(),
                        provider: provider.clone(),
                        verification_tx,
                        router_tx: router_tx_clone,
                    };
                    let ext = ConsensusExt {
                        consensus,
                        provider,
                    };

                    // now we merge our extension namespace into all configured transports
                    ctx.auth_module.merge_auth_methods(ext.into_rpc())?;
                    ctx.modules.merge_configured(beacon_ext.into_rpc())?;

                    info!(target: "reth::cli", "consensus rpc extension enabled");

                    Ok(())
                })
                .launch_with_debug_capabilities()
                .await?;

            // Get the stored consensus instance
            let consensus = consensus_holder
                .lock()
                .unwrap()
                .clone()
                .expect("consensus should be set");

            let node_config_dev = node.config.clone().dev();
            let consensus_signer_private_key = node_config_dev.dev.consensus_signer_private_key;
            let signer_address = if let Some(signer_private_key) = &consensus_signer_private_key {
                let eth_signer: PrivateKeySigner = signer_private_key.to_string().parse().unwrap();
                Some(eth_signer.address())
            } else {
                None
            };

            let mining_mode = if let Some(_) = consensus_signer_private_key {
                let block_time = node_config_dev
                    .dev
                    .block_time
                    .unwrap_or_else(|| Duration::from_secs(DEFAULT_BLOCK_TIME_SECS));
                consensus_client::miner::MiningMode::interval(block_time)
            } else {
                consensus_client::miner::MiningMode::NoMining
            };
            info!(target: "reth::cli", ?mining_mode);

            if node_config_dev.dev.migrate_old_chain_data_from_db.is_some()
                || node_config_dev
                    .dev
                    .migrate_old_chain_data_from_rpc
                    .is_some()
            {
                let migrate_from_db_path =
                    node_config_dev.dev.migrate_old_chain_data_from_db.clone();
                let migrate_from_db_rpc =
                    node_config_dev.dev.migrate_old_chain_data_from_rpc.clone();
                N42Migrate::spawn_new(
                    node.provider.clone(),
                    N42PayloadAttributesBuilder::new_add_signer(node.chain_spec(), signer_address),
                    node.add_ons_handle.beacon_engine_handle.clone(),
                    node.payload_builder_handle.clone(),
                    node.pool.clone(),
                    migrate_from_db_path,
                    migrate_from_db_rpc,
                );
            } else {
                N42Miner::spawn_new(
                    node.provider.clone(),
                    N42PayloadAttributesBuilder::new_add_signer(node.chain_spec(), signer_address),
                    node.add_ons_handle.beacon_engine_handle.clone(),
                    mining_mode,
                    node.payload_builder_handle.clone(),
                    node.network.clone(),
                    consensus,
                    broadcast_tx_clone_for_miner,
                    verification_rx,
                );
            }

            // Install ress subprotocol.
            if ress_args.enabled {
                install_ress_subprotocol(
                    ress_args,
                    node.provider,
                    node.evm_config,
                    node.network,
                    node.task_executor,
                    node.add_ons_handle.engine_events.new_listener(),
                )?;
            }

            node_exit_future.await
        })
    {
        error!(target: "reth::cli", "Error: {err:?}");
        std::process::exit(1);
    }
}

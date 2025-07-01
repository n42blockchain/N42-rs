#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use std::{time::Duration};
use alloy_signer_local::PrivateKeySigner;
use consensus_client::miner::N42Miner;
use n42_engine_primitives::N42PayloadAttributesBuilder;
use clap::Parser;
use n42::{args::RessArgs, cli::Cli, ress::install_ress_subprotocol};
use n42_engine_types::{N42Node};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::NodeHandle;
use reth_node_ethereum::EthereumNode;
use tracing::info;
use n42::consensus_ext::{ConsensusExtApiServer, ConsensusExt, ConsensusBeaconExtApiServer, ConsensusBeaconExt};

const DEFAULT_BLOCK_TIME_SECS: u64 = 8;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(err) =
        Cli::<EthereumChainSpecParser, RessArgs>::parse().run(async move |builder, ress_args| {
            info!(target: "reth::cli", "Launching node");
            let NodeHandle { node, node_exit_future } =
                builder.node(N42Node::default())
                        .extend_rpc_modules(|ctx| {

                            let consensus = ctx.consensus().clone();
                            let provider = ctx.provider().clone();

                            let beacon_ext = ConsensusBeaconExt { consensus: consensus.clone(), provider: provider.clone() };
                            let ext = ConsensusExt { consensus, provider };

                            // now we merge our extension namespace into all configured transports
                            ctx.auth_module.merge_auth_methods(ext.into_rpc())?;
                            ctx.modules.merge_configured(beacon_ext.into_rpc())?;

                            println!("consensus rpc extension enabled");

                            Ok(())
                        })
                .launch_with_debug_capabilities().await?;

            let consensus_signer_private_key = node.config.clone().dev().dev.consensus_signer_private_key;
            let signer_address = if let Some(signer_private_key) = &consensus_signer_private_key {
                let eth_signer: PrivateKeySigner = signer_private_key.to_string().parse().unwrap();
                Some(eth_signer.address())
            } else {
                None
            };

            let mining_mode = if let Some(_) = consensus_signer_private_key {
                let block_time = node.config.clone().dev().dev.block_time.unwrap_or_else(|| Duration::from_secs(DEFAULT_BLOCK_TIME_SECS));
                consensus_client::miner::MiningMode::interval(block_time)
            } else {
                consensus_client::miner::MiningMode::NoMining
            };
            info!(target: "reth::cli", ?mining_mode);

            N42Miner::spawn_new(
                node.provider.clone(),
                N42PayloadAttributesBuilder::new_add_signer(node.chain_spec(), signer_address),
                node.add_ons_handle.beacon_engine_handle.clone(),
                mining_mode,
                node.payload_builder_handle.clone(),
                node.network.clone(),
                node.consensus.clone(),
            );

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
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

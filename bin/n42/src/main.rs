#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use clap::Parser;
use n42::{args::RessArgs, cli::Cli, ress::install_ress_subprotocol};
use n42_engine_types::{MinedblockExt, MinedblockExtApiServer, N42Node};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::NodeHandle;
use reth_node_ethereum::EthereumNode;
use tracing::info;
use n42::consensus_ext::{ConsensusExtApiServer, ConsensusExt};

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

                            let ext = ConsensusExt { consensus, provider };

                            // now we merge our extension namespace into all configured transports
                            ctx.auth_module.merge_auth_methods(ext.into_rpc())?;

                            let minedblock_ext = MinedblockExt::instance();
                            if let Ok(minedblock) = minedblock_ext.try_lock() {
                                // 克隆单例实例，确保使用同一个实例
                                let rpc = minedblock.clone().into_rpc();
                                ctx.modules.merge_ws(rpc.clone())?;
                                ctx.modules.merge_http(rpc)?;
                            } else {
                                println!("minedblock rpc extension disabled");
                            }
                            // ctx.modules.merge_ws(minedblock_ext.clone().into_rpc())?;
                            // ctx.modules.merge_http(minedblock_ext.clone().into_rpc())?;

                            println!("consensus rpc extension enabled");

                            Ok(())
                        })
                .launch_with_debug_capabilities().await?;

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

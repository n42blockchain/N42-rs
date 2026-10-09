#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use consensus_client::migrate::N42Migrate;
use consensus_client::miner::N42Miner;
use n42::engine_ext::{N42EngineApiServer, N42EngineExt};
use n42::consensus_ext::{
    ConsensusBeaconExt, ConsensusBeaconExtApiServer, ConsensusExt, ConsensusExtApiServer,
};
use n42::cli::Cli;
use n42_clique::UnverifiedBlock;
use n42_engine_primitives::N42PayloadAttributesBuilder;
use n42_engine_types::N42Node;
use n42_primitives::BLSPubkey;
use pubsub_mem::{publish, router_loop, Event, RouterMsg};
use n42_qmdb_reth::{state_scheme, N42ChainSpecParser, QmdbNodeState, StateScheme};
use reth_provider::{BlockHashReader, BlockNumReader, CanonStateSubscriptions};
use reth_node_builder::{FullNodeComponents, NodeHandle};
use reth_node_core::primitives::AlloyBlockHeader;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

const DEFAULT_BLOCK_TIME_SECS: u64 = 8;

fn main() {
    // `N42_INGEST_VERIFY=shard` without a well-formed `N42_INGEST_SHARD=<i>/<n>`
    // would silently verify everything (or nothing); refuse to start instead.
    if let Err(err) = n42_tx_types::ingest_verify_mode() {
        eprintln!("error: {err}");
        std::process::exit(2);
    }
    // `N42_CORE_LAYOUT=isolate`: split the node's affinity mask into the
    // build, critical and background sets before any thread is spawned, and
    // move this thread (and any the allocator already has) to the background
    // set, so tokio, reth's rayon pools, persistence and the engine inherit
    // it. The critical pools pin their own threads. Logged once tracing is up.
    let _ = n42_core_layout::init();
    // `N42_THP_DISABLE=1`: no transparent huge pages for this process. With
    // the box's THP at `always`, a fleet allocating ~45 GB of anonymous
    // memory drove 5.8M direct-compaction stalls that tore the page cache
    // out from under the importers' reads (round 39: the "first leg"
    // collapses, 0.7-0.8 s cycles, millions of major faults at 70 GB free).
    #[cfg(target_os = "linux")]
    if std::env::var("N42_THP_DISABLE").is_ok_and(|v| v == "1") {
        // SAFETY: prctl with PR_SET_THP_DISABLE takes no pointers.
        let rc = unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1u64, 0u64, 0u64, 0u64) };
        if rc != 0 {
            eprintln!("could not disable transparent huge pages: {}", std::io::Error::last_os_error());
        }
    }
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let (verification_tx, verification_rx) = mpsc::channel(100);
    let (broadcast_tx, _broadcast_rx) = broadcast::channel::<(UnverifiedBlock, Arc<Vec<BLSPubkey>>)>(100);
    let broadcast_tx_clone_for_miner = broadcast_tx.clone();

    // Create router channel for pubsub
    let (router_tx, router_rx) = mpsc::channel::<RouterMsg<UnverifiedBlock>>(100);
    let router_tx_clone = router_tx.clone();
    let router_tx_for_bridge = router_tx.clone();
    let broadcast_rx_for_bridge = broadcast_tx.subscribe();

    // Shared consensus instance holder
    let consensus_holder: std::sync::Arc<
        std::sync::Mutex<
            Option<
                std::sync::Arc<
                    dyn reth_consensus::FullConsensus<n42_tx_types::N42Primitives>
                        + Send
                        + Sync,
                >,
            >,
        >,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let consensus_holder_clone = consensus_holder.clone();

    if let Err(err) =
        Cli::<N42ChainSpecParser>::parse().run(async move |builder, _extra_args| {
            info!(target: "reth::cli", "Launching node");

            // `deferredExecutionDepth` (docs/DEFERRED_DEPTH_2_DESIGN.md): a
            // malformed value or a depth this node does not run is refused here,
            // never read as depth 1 -- a depth-1 member of a depth-2 fleet
            // refuses every header.
            {
                let genesis = builder.config().chain.genesis();
                let depth = reth_chainspec::qmdb::check_deferred_execution_depth(genesis)
                    .map_err(|err| eyre::eyre!("genesis: {err}"))?;
                if let Some(at) = reth_chainspec::qmdb::deferred_execution_time(genesis) {
                    info!(target: "reth::cli", deferred_from = at, depth, "deferred execution: a header carries the result of its ancestor {depth} blocks back");
                }
            }

            // Start the pubsub router loop (must be inside async context)
            tokio::spawn(async move {
                debug!(target: "reth::cli", "Starting pubsub router loop");
                router_loop(router_rx).await;
            });

            // Bridge: forward messages from broadcast channel to pubsub router
            let mut broadcast_rx_for_bridge = broadcast_rx_for_bridge;
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

            // Which state commitment this chain uses is declared in its genesis,
            // the same way gov5 reads it. A QMDB chain gets one forest, shared by
            // the payload builder and the engine validator, and persisted under
            // the datadir so a restart continues the same append history.
            let chain = builder.config().chain.clone();
            let qmdb = match state_scheme(&chain.genesis) {
                StateScheme::Qmdb => {
                    let dir = builder.config().datadir().data_dir().join("qmdb");
                    info!(target: "reth::cli", dir = %dir.display(), "chain declares the QMDB state commitment");
                    Some(QmdbNodeState::new(chain, dir))
                }
                StateScheme::Mpt => None,
            };
            let qmdb_for_startup = qmdb.clone();

            let NodeHandle {
                node,
                node_exit_future,
            } = builder
                .node(N42Node::with_qmdb(qmdb))
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

                    // The raw getPayload, beside the Engine API on the auth
                    // transport. See `engine_ext`.
                    let raw_endpoint = std::env::var("N42_PAYLOAD_SERVE")
                        .ok()
                        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok());
                    // The canonical head minus the last persisted block:
                    // two reads of the in-memory state's trackers, no lock
                    // held across anything. Before the first persistence
                    // the in-memory chain itself is counted.
                    let in_memory = ctx.provider().canonical_in_memory_state();
                    let persisted_state = in_memory.clone();
                    let in_memory_blocks: n42::engine_ext::InMemoryBlocks = std::sync::Arc::new(move || {
                        match in_memory.get_persisted_num_hash() {
                            Some(persisted) => in_memory.get_canonical_block_number().saturating_sub(persisted.number),
                            None => in_memory.canonical_chain().count() as u64,
                        }
                    });
                    // The last persisted block: the tracker's, or before the
                    // first persistence of this run the database tip (the
                    // head less the blocks held in memory).
                    let persisted_block: n42::engine_ext::PersistedBlock = std::sync::Arc::new(move || {
                        match persisted_state.get_persisted_num_hash() {
                            Some(persisted) => persisted.number,
                            None => persisted_state
                                .get_canonical_block_number()
                                .saturating_sub(persisted_state.canonical_chain().count() as u64),
                        }
                    });
                    let engine_ext = N42EngineExt {
                        payloads: ctx.node().payload_builder_handle().clone(),
                        raw_endpoint,
                        in_memory_blocks: Some(in_memory_blocks),
                        persisted_block: Some(persisted_block),
                    };

                    // now we merge our extension namespace into all configured transports
                    ctx.auth_module.merge_auth_methods(ext.into_rpc())?;
                    ctx.auth_module.merge_auth_methods(engine_ext.into_rpc())?;
                    ctx.modules.merge_configured(beacon_ext.into_rpc())?;

                    info!(target: "reth::cli", "consensus rpc extension enabled");

                    Ok(())
                })
                .launch_with_debug_capabilities()
                .await?;

            // The layout (or its fallback), and `N42_BACKGROUND_NICE` on
            // reth's persistence thread (`save_blocks` runs there), which
            // exists from the launch on.
            n42_core_layout::log_once();
            let reniced = n42_core_layout::lower_threads_named(&["persistence"]);
            if let Some(priority) = n42_core_layout::background_priority() {
                info!(target: "n42::core_layout", %priority, reniced, "background priority on reth's persistence thread");
            }

            // `N42_FRAME_BLOCKS=1` (docs/BREAKTHROUGH_DESIGN.md step 1): whole
            // frames in the builder, frame-tree roots, frame descriptions on
            // the road. Refused outright on a chain whose genesis does not set
            // `frameBlocks`: the node would build blocks no other node accepts.
            if n42_engine_types::frame_blocks::init(reth_chainspec::qmdb::frame_blocks_enabled(node.chain_spec().genesis()))
                .map_err(|err| eyre::eyre!(err))?
            {
                info!(target: "reth::cli", "frame blocks on: the builder pulls whole frames and roots are frame trees");
            }

            // Get the stored consensus instance
            let consensus = consensus_holder
                .lock()
                .unwrap()
                .clone()
                .expect("consensus should be set");

            let node_config_dev = node.config.clone().dev();
            // The forest can only be restored once the database is open and the
            // head is known, which is now; and it has to be ready before anything
            // produces or validates a block, which is what follows.
            // `N42_HASHED_TABLES=off` needs a registered QMDB reader; a chain without QMDB has
            // none, so the setting is refused before anything is persisted without its state.
            if qmdb_for_startup.is_none() {
                n42_qmdb_reth::check_hashed_tables_setting().map_err(|err| eyre::eyre!(err))?;
            }
            // A state masking suffix leaves the hashed-state version behind the database tip,
            // and a view built at restart holds no journals to answer behind its head.
            if n42_qmdb_reth::n42_state::hashed_tables_off() && node.config.engine.num_state_masking_blocks > 0 {
                return Err(eyre::eyre!(
                    "N42_HASHED_TABLES=off needs --engine.num-state-masking-blocks 0 (got {}): the QMDB read view answers at the database tip",
                    node.config.engine.num_state_masking_blocks
                ));
            }
            if let Some(qmdb) = &qmdb_for_startup {
                let info = node.provider.chain_info()?;
                let head_hash = node
                    .provider
                    .block_hash(info.best_number)?
                    .ok_or_else(|| eyre::eyre!("no hash for head block {}", info.best_number))?;
                qmdb.initialize((info.best_number, head_hash))?;
                info!(target: "reth::cli", block = info.best_number, %head_hash, "QMDB state ready");
                // `N42_QMDB_READS=verify|on`: the read view answers or checks the
                // providers' latest-state reads (docs/QMDB_UPGRADE_PLAN.md, stage 6).
                if n42_qmdb_reth::register_state_reader(qmdb) {
                    info!(target: "reth::cli", "QMDB read view registered as the state reader");
                }
                n42_qmdb_reth::check_hashed_tables_setting().map_err(|err| eyre::eyre!(err))?;
                if n42_qmdb_reth::n42_state::hashed_tables_off() {
                    info!(target: "reth::cli", "hashed state tables are not written; QMDB answers the latest state");
                }
                // The head's execution result, for the first header after a
                // restart under deferred execution: before the fork the
                // header carries it; past the fork the forest holds the root
                // and the database the receipts.
                use reth_provider::{HeaderProvider, ReceiptProvider};
                if let Some(head) = node.provider.sealed_header(info.best_number)? {
                    let chain_spec = node.chain_spec();
                    let genesis = chain_spec.genesis();
                    if reth_chainspec::qmdb::deferred_execution_active_at(genesis, head.timestamp) {
                        let receipts = node.provider.receipts_by_block(head.hash().into())?.unwrap_or_default();
                        let (receipts_root, logs_bloom) = n42_engine_types::hotstuff_consensus::gov5_receipt_root_bloom(&receipts);
                        let gas_used = receipts.last().map_or(0, |r| r.cumulative_gas_used);
                        if let Some(state_root) = qmdb.root_of(&head.hash()) {
                            n42_engine_types::executed_fields::remember(
                                head.hash(),
                                n42_engine_types::executed_fields::ExecutedFields { state_root, receipts_root, logs_bloom, gas_used },
                            );
                        }
                    } else {
                        n42_engine_types::executed_fields::seed_from_header(head.hash(), head.header());
                    }
                }

                // Follow the canonical chain so the persisted head keeps up with
                // the database's. Lagging is tolerable — only the tip matters,
                // and every tree in between was filed at validation.
                let mut canonical = node.provider.subscribe_to_canonical_state();
                let follower = qmdb.clone();
                tokio::spawn(async move {
                    loop {
                        match canonical.recv().await {
                            Ok(notification) => {
                                let behind = canonical.len();
                                if behind > 8 {
                                    warn!(target: "reth::cli", behind, "canonical subscriber lag: qmdb head follower");
                                }
                                let tip = notification.tip().hash();
                                if let Err(error) = follower.on_canonical(tip) {
                                    error!(target: "reth::cli", %error, "QMDB head could not follow the canonical chain");
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(target: "reth::cli", skipped, "QMDB head follower fell behind canonical notifications");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }

            // A chained build that waits for an ancestor to reach the engine is
            // woken by the canonical chain's changes instead of polling, and the
            // own-block layers the engine's tip has passed are released
            // (`direct_build::engine_landed`, `leader_layers::on_canonical`).
            {
                let mut canonical = node.provider.subscribe_to_canonical_state();
                n42_engine_types::direct_build::engine_landed::wire();
                tokio::spawn(async move {
                    let depth = n42_engine_types::direct_build::leader_layers::depth();
                    loop {
                        match canonical.recv().await {
                            Ok(notification) => {
                                n42_engine_types::direct_build::engine_landed::notify();
                                n42_engine_types::direct_build::leader_layers::on_canonical(notification.tip().number, depth);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                n42_engine_types::direct_build::engine_landed::notify();
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }

            let consensus_signer_private_key = node_config_dev.dev.consensus_signer_private_key;
            let signer_address = if let Some(signer_private_key) = &consensus_signer_private_key {
                let eth_signer: PrivateKeySigner = signer_private_key.to_string().parse().unwrap();
                Some(eth_signer.address())
            } else {
                None
            };

            // The raw payload channel for the validator, loopback only. See
            // `payload_serve`.
            if let Ok(addr) = std::env::var("N42_PAYLOAD_SERVE") {
                // Several keys on this execution layer share each import
                // (`N42_IMPORT_ONCE`); a held execution cannot be shared.
                n42::import_once::check_startup().map_err(|err| eyre::eyre!(err))?;
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let payloads = node.payload_builder_handle.clone();
                        let engine = node.add_ons_handle.beacon_engine_handle.clone();
                        // Our own sealed blocks go in with the build's execution
                        // rather than being executed again; see payload_serve.
                        let reuse = (std::env::var("N42_NO_OWN_BLOCK_REUSE").is_err()).then(|| {
                            let chain_spec = node.chain_spec();
                            let profile = n42_engine_types::engine_validator::header_profile_for(&chain_spec);
                            n42::payload_serve::OwnBlockReuse {
                                validator: std::sync::Arc::new(
                                    n42_engine_types::engine_validator::N42EngineValidator::new(chain_spec, profile),
                                ),
                                qmdb: qmdb_for_startup.clone(),
                                inserts: reth_node_builder::executed_inserts::sender(),
                                canonical_head: Some(std::sync::Arc::new({
                                    let provider = node.provider.clone();
                                    move || reth_provider::BlockNumReader::chain_info(&provider).ok().map(|info| (info.best_hash, info.best_number))
                                })),
                                // Opt-in (N42_PRUNE_POOL_ON_IMPORT=1), measured and not
                                // adopted: removing a block's 163,000 transactions from
                                // reth's pool costs 260-293 ms under its write lock -- the
                                // same per-transaction removal the pool's own maintenance
                                // pays later -- so doing it on the import path moves the
                                // cost onto the critical path rather than removing it.
                                import_foreign: (std::env::var("N42_FOLLOWER_DIRECT_IMPORT").is_ok()).then(|| {
                                    let provider = node.provider.clone();
                                    let evm_config = node.evm_config.clone();
                                    let senders_cache = node.evm_config.sender_recovery_cache.clone();
                                    let carry: std::sync::Arc<n42::follower_import::CarriedReads> = Default::default();
                                    let qmdb = qmdb_for_startup.clone();
                                    let consensus = consensus.clone();
                                    let chain_spec = node.chain_spec();
                                    std::sync::Arc::new(move |sealed: n42::follower_import::ForeignBlock, senders, checked, road| {
                                        n42::follower_import::import_foreign_block(
                                            sealed, &provider, &evm_config, senders_cache.as_ref(), senders, &carry, qmdb.as_ref(), consensus.as_ref(), &chain_spec, checked, road,
                                        )
                                    }) as std::sync::Arc<n42::payload_serve::ForeignImport>
                                }),
                                exec_probe: (std::env::var("N42_FOLLOWER_EXEC_PROBE").is_ok()).then(|| {
                                    let provider = node.provider.clone();
                                    let evm_config = node.evm_config.clone();
                                    std::sync::Arc::new(move |block: reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>| {
                                        use reth_evm::execute::Executor as _;
                                        use reth_evm::ConfigureEvm as _;
                                        use reth_provider::StateProviderFactory as _;
                                        let state = provider.state_by_block_hash(block.parent_hash).map_err(|e| e.to_string())?;
                                        let db = reth_revm::database::StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state));
                                        let started = std::time::Instant::now();
                                        let mut executor = evm_config.executor(db);
                                        let out = executor.execute_one(&block).map_err(|e| e.to_string())?;
                                        Ok((started.elapsed().as_millis() as u64, out.gas_used, out.receipts.len()))
                                    }) as std::sync::Arc<dyn Fn(reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Result<(u64, u64, usize), String> + Send + Sync>
                                }),
                                prune_pool: (std::env::var("N42_PRUNE_POOL_ON_IMPORT").is_ok()).then(|| {
                                    let pool = node.pool.clone();
                                    std::sync::Arc::new(move |hashes: Vec<alloy_primitives::B256>| {
                                        let _ = reth_transaction_pool::TransactionPool::remove_transactions(&pool, hashes);
                                    }) as std::sync::Arc<dyn Fn(Vec<alloy_primitives::B256>) + Send + Sync>
                                }),
                            }
                        });
                        tokio::spawn(async move {
                            if let Err(err) = n42::payload_serve::serve(addr, payloads, engine, reuse).await {
                                error!(target: "reth::cli", %err, "raw payload channel stopped");
                            }
                        });
                    }
                    Err(err) => error!(target: "reth::cli", %err, %addr, "N42_PAYLOAD_SERVE is not an address"),
                }
            }

            // A watchdog for the direct import and the build: a block that
            // has been importing, or a payload that has been building, for six
            // seconds is a stuck node, and the stages of both are the first
            // thing to know. With `N42_WATCHDOG_STACKS=1` every thread's stack
            // follows (see `stacks`; symbols need `--profile profiling`).
            let dump_stacks = std::env::var("N42_WATCHDOG_STACKS").is_ok_and(|v| v == "1");
            if dump_stacks {
                n42::stacks::install();
            }
            std::thread::Builder::new().name("n42-watchdog".into()).spawn(move || {
                let mut last = ((0u64, 0u64, 0u64), std::time::Instant::now());
                let mut dumped_at = (0u64, 0u64, 0u64);
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let import = n42::follower_import::IMPORT_STAGE.load(std::sync::atomic::Ordering::Relaxed);
                    let build = n42_engine_types::BUILD_STAGE.load(std::sync::atomic::Ordering::Relaxed);
                    let handoff = n42::follower_import::HANDOFF_STAGE.load(std::sync::atomic::Ordering::Relaxed);
                    if (import, build, handoff) != last.0 {
                        last = ((import, build, handoff), std::time::Instant::now());
                        continue;
                    }
                    if (import == 0 && build == 0 && handoff == 0) || last.1.elapsed() < std::time::Duration::from_secs(6) {
                        continue;
                    }
                    tracing::warn!(
                        target: "n42.watchdog",
                        stuck_secs = last.1.elapsed().as_secs(),
                        import_block = import >> 8,
                        import_stage = n42::follower_import::IMPORT_STAGES[(import & 0xff) as usize % 8],
                        build_parent = build >> 8,
                        build_stage = n42_engine_types::BUILD_STAGES[(build & 0xff) as usize % 8],
                        handoff_block = handoff >> 8,
                        handoff_stage = n42::follower_import::HANDOFF_STAGES[(handoff & 0xff) as usize % 8],
                        "the import, the build or the own-block hand-off has not progressed",
                    );
                    // One dump per stall: the same stages stuck again six
                    // seconds later are the same stall.
                    if dump_stacks && dumped_at != (import, build, handoff) {
                        dumped_at = (import, build, handoff);
                        let answered = n42::stacks::dump_all(std::time::Duration::from_millis(300));
                        tracing::warn!(target: "n42.watchdog", answered, "thread stacks written to stderr");
                    }
                    last.1 = std::time::Instant::now();
                }
            }).ok();
            // The builder-side transaction queue, beside the pool. See
            // n42_tx_queue. Fed by the ingest, drained by the builder, pruned
            // here by every canonical block on every node.
            if std::env::var("N42_TX_QUEUE").is_ok() {
                let queue: n42_tx_queue::TxQueue<n42_engine_types::N42PooledTransaction> = n42_tx_queue::TxQueue::new();
                if std::env::var("N42_TX_QUEUE_DRAINER").is_ok() {
                    // The inbox drained off the builder's thread; see TxQueue::drain_now.
                    let drained = queue.clone();
                    tokio::spawn(async move {
                        let mut tick = tokio::time::interval(std::time::Duration::from_millis(5));
                        loop {
                            tick.tick().await;
                            let drained = drained.clone();
                            let _ = tokio::task::spawn_blocking(move || drained.drain_now()).await;
                        }
                    });
                }
                if n42_tx_queue::install(queue.clone()) {
                    info!(target: "reth::cli", "builder-side transaction queue installed");
                }
                // Fed by the pool's own arrivals, whichever door they came in
                // by, so what the builder sees is what the pool validated.
                let mut arrivals = reth_transaction_pool::TransactionPool::new_transactions_listener_for(
                    &node.pool,
                    reth_transaction_pool::TransactionListenerKind::All,
                );
                let feed = queue.clone();
                let pool_for_gaps = node.pool.clone();
                tokio::spawn(async move {
                    let mut batch = Vec::with_capacity(256);
                    let mut last_gap_warn: Option<std::time::Instant> = None;
                    loop {
                        // Holes the builder ran into: the pool's listener drops
                        // events on a full channel, so a nonce can be in the
                        // pool and not here. Look those up; one still on its
                        // way in is simply not found yet.
                        let mut unfilled: Vec<(alloy_primitives::Address, u64, u64)> = Vec::new();
                        let mut holes = 0usize;
                        for (sender, from, to) in feed.take_gaps() {
                            holes += 1;
                            let to = to.min(from.saturating_add(256));
                            let found: Vec<_> = (from..to)
                                .filter_map(|nonce| {
                                    reth_transaction_pool::TransactionPool::get_transaction_by_sender_and_nonce(
                                        &pool_for_gaps,
                                        sender,
                                        nonce,
                                    )
                                })
                                .collect();
                            if found.is_empty() {
                                if unfilled.len() < 4 {
                                    unfilled.push((sender, from, to));
                                }
                            } else {
                                feed.push_valid(found);
                            }
                        }
                        // A hole this feed cannot fill is a nonce that is in
                        // neither the queue nor the pool, and with the ingest
                        // going straight to the queue
                        // (`N42_TX_INGEST_DIRECT`) the pool never has it, so
                        // every one of them lands here. Said out loud, at
                        // most once a second, with the first few named: a
                        // build reports these by the hundred thousand on a
                        // node that has stalled (loop213 Pe: 269,522 in a
                        // leg) and nothing has ever named one.
                        if !unfilled.is_empty() {
                            let now = std::time::Instant::now();
                            if last_gap_warn.is_none_or(|last: std::time::Instant| now.duration_since(last).as_secs() >= 1) {
                                last_gap_warn = Some(now);
                                warn!(
                                    target: "n42.tx_queue",
                                    holes,
                                    first = ?unfilled,
                                    "holes a build ran into that the pool cannot fill: (sender, account nonce, lowest queued above it)"
                                );
                            }
                        }
                        let event = match tokio::time::timeout(std::time::Duration::from_millis(50), arrivals.recv()).await {
                            Ok(Some(event)) => event,
                            Ok(None) => break,
                            Err(_) => continue,
                        };
                        batch.push(event.transaction);
                        while let Ok(event) = arrivals.try_recv() {
                            batch.push(event.transaction);
                            if batch.len() >= 4096 {
                                break;
                            }
                        }
                        feed.push_valid(batch.drain(..));
                    }
                });
                let mut canonical = node.provider.subscribe_to_canonical_state();
                // `N42_QUEUE_PRUNE_THREAD=1`: the prune runs on a thread of its
                // own and this task only forwards (see `n42::queue_prune`).
                let pruner = n42::queue_prune::on_own_thread()
                    .then(|| n42::queue_prune::spawn_thread(queue.clone()))
                    .flatten();
                tokio::spawn(async move {
                    loop {
                        match canonical.recv().await {
                            Ok(notification) => {
                                let behind = canonical.len();
                                if behind > 8 {
                                    warn!(target: "reth::cli", behind, "canonical subscriber lag: queue pruner");
                                }
                                match pruner.as_ref() {
                                    Some(pruner) => {
                                        // Read by the builder: said here as
                                        // well, so the thread's queue does
                                        // not delay it.
                                        for block in notification.committed().blocks_iter() {
                                            n42_engine_types::canonical_head::saw(block.number());
                                        }
                                        if pruner.send((notification, std::time::Instant::now())).is_err() {
                                            error!(target: "n42.tx_queue", "the queue's pruning thread is gone; the queue is no longer pruned");
                                            break;
                                        }
                                    }
                                    None => n42::queue_prune::prune_notification(&queue, &notification, 1, std::time::Duration::ZERO),
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(target: "n42.tx_queue", skipped, "queue pruning fell behind canonical notifications");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }

            // A binary path into the pool, for load generators. Off unless
            // asked for, and meant for loopback: it admits nothing
            // `eth_sendRawTransaction` would not, but it is unauthenticated,
            // so binding it anywhere reachable would be a mistake.
            if let Ok(addr) = std::env::var("N42_TX_INGEST") {
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let pool = node.pool.clone();
                        // The sender-recovery cache, so a transaction admitted
                        // here is not recovered again when its block arrives.
                        let cache = node.evm_config().sender_recovery_cache.clone();
                        // The canonical head's number, for the ingest's gate to
                        // know how far the pool lags the chain.
                        let head = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                        {
                            use futures::StreamExt as _;
                            use reth_provider::CanonStateSubscriptions as _;
                            let head = head.clone();
                            let mut canonical = node.provider.canonical_state_stream();
                            tokio::spawn(async move {
                                while let Some(notification) = canonical.next().await {
                                    head.store(notification.tip().number, std::sync::atomic::Ordering::Relaxed);
                                }
                                // (a stream over the broadcast; its lag is not readable here)
                            });
                        }
                        // The chain id a frame attestation is signed over
                        // (`N42_FRAME_GATEWAYS`, step 2).
                        let chain_id = reth_chainspec::EthChainSpec::chain_id(&*node.chain_spec());
                        n42_tx_ingest::set_frame_hook(n42_engine_types::frame_scan::note_admitted_any);
                        // On its own runtime under `N42_INGEST_RUNTIME=1`
                        // (`n42_tx_ingest::runtime`), on this one otherwise.
                        n42_tx_ingest::spawn_serve(addr, pool, cache, head, chain_id, |err| {
                            error!(target: "reth::cli", %err, "transaction ingest stopped");
                        });
                    }
                    Err(err) => {
                        error!(target: "reth::cli", %err, %addr, "N42_TX_INGEST is not an address");
                    }
                }
            }

            // A chain whose genesis names a HotStuff-2 validator set is driven
            // over the Engine API by those validators (`h2_validator`); the
            // signer key still seals the blocks they ask for, but APoS block
            // production would race their forkchoice and lose.
            let hotstuff_chain =
                n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(node.chain_spec().genesis())
                    .is_ok();
            let mining_mode = if hotstuff_chain {
                info!(target: "reth::cli", "chain declares a HotStuff-2 validator set; APoS mining is off");
                consensus_client::miner::MiningMode::NoMining
            } else if let Some(_) = consensus_signer_private_key {
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
            } else if hotstuff_chain {
                // No miner at all, not merely a miner with mining off: the
                // miner also re-proposes when the chain looks stalled, which
                // on a HotStuff-2 chain is just the fleet pacing itself.
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
            // Disabled: ress protocol deps not yet available in v1.11.0
            // if ress_args.enabled {
            //     install_ress_subprotocol(
            //         ress_args,
            //         node.provider,
            //         node.evm_config,
            //         node.network,
            //         node.task_executor,
            //         node.add_ons_handle.engine_events.new_listener(),
            //     )?;
            // }

            node_exit_future.await
        })
    {
        error!(target: "reth::cli", "Error: {err:?}");
        std::process::exit(1);
    }
}

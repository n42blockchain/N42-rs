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

/// N42's own `node` flags, beside reth's.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
struct N42Args {
    /// Keep QMDB state history so `n42_getProof` proves past blocks: a
    /// block count (`N`, the last N persisted blocks), `all`, or `off`.
    /// Overrides `N42_QMDB_HISTORY`; an invalid value refuses to start.
    /// Needs a QMDB chain with the entry file (`docs/QMDB_HISTORY.md`).
    #[arg(long = "qmdb.history", value_name = "N|all|off", value_parser = parse_history_mode)]
    qmdb_history: Option<n42_qmdb_reth::history::HistoryMode>,
}

/// The CLI's chain spec parser with the node's chain spec type
/// ([`n42_header::N42ChainSpec`], whose genesis header is an `N42Header`).
#[derive(Debug, Clone, Copy, Default)]
struct N42HeaderChainSpecParser;

impl reth_cli::chainspec::ChainSpecParser for N42HeaderChainSpecParser {
    type ChainSpec = n42_header::N42ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = N42ChainSpecParser::SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        Ok(Arc::new(n42_header::N42ChainSpec::new(N42ChainSpecParser::parse(s)?)))
    }
}

/// `n42 init` on the node's own types ([`N42Node`]: `N42Header` storage), so
/// the genesis header written is the one the node serves and hashes.
fn profile1_init() -> eyre::Result<()> {
    let mut cli = Cli::<N42HeaderChainSpecParser, N42Args>::parse();
    let runner = reth_cli_runner::CliRunner::try_default_runtime()?;
    let _guards = cli.init_tracing(&runner, reth_tracing::Layers::new())?;
    let n42::cli::Commands::Init(command) = cli.command else {
        return Err(eyre::eyre!("profile1_init runs only the init command"));
    };
    let runtime = runner.runtime();
    runner.run_blocking_until_ctrl_c(command.execute::<N42Node>(runtime))
}

fn parse_history_mode(raw: &str) -> Result<n42_qmdb_reth::history::HistoryMode, String> {
    n42_qmdb_reth::history::HistoryMode::parse(raw)
}

#[allow(clippy::iter_with_drain)] // the batch buffer is reused, so it is drained rather than consumed
fn main() {
    // Profile 1 sizes the allocator, its thread pools and caches for
    // 8-second blocks (docs/P1_MEMORY.md). jemalloc reads its options before
    // `main`, so a member started without them restarts itself once with
    // them in MALLOC_CONF (same pid and arguments), before anything else
    // runs. A flag or variable the operator set wins; `N42_P1_MEMORY=0`
    // turns all of it off; a chain without `n42Profile` is untouched.
    let process_args = n42::profile1_memory::process_args();
    let p1_memory = n42_qmdb_reth::profile1_memory::MemoryDefaults::for_args(&process_args);
    if let Some(defaults) = &p1_memory
        && let Some(err) = n42_qmdb_reth::profile1_memory::reexec_with_malloc_conf(defaults)
    {
        eprintln!("n42: profile 1: could not restart with the allocator's options ({err}); keeping its defaults");
    }
    // `N42_PROFILE=x22`: the adopted knob set, for every knob the operator
    // left unset. First, before any knob is read (they are cached in
    // `OnceLock`s at first use) and before any thread exists.
    // SAFETY: no thread this program starts exists yet (the profile-1 check
    // above reads a file and the environment only), and nothing else reads
    // or writes the environment concurrently (the allocator read its
    // configuration before `main`; its background threads, on profile 1,
    // only return pages).
    unsafe { n42_env::profile::apply_or_exit("n42") };
    // Enable backtraces unless a RUST_BACKTRACE value has already been
    // explicitly provided. First, before this process spawns any thread or
    // moves the allocator's (`n42_core_layout::init` below).
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        // SAFETY: the first statement of `main`: no thread this program
        // starts exists yet, and nothing else in the process reads or writes
        // the environment concurrently (the allocator reads its
        // configuration once, at its own initialisation, before `main`).
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }
    // The command line, chain spec included (clap runs the chain parser
    // here), before any knob of the profile is read: the knobs a profile set
    // that need a genesis feature this chain lacks (`frameBlocks`) are
    // withdrawn again, so the profile never forces a chain feature. A
    // command without a chain withdraws them too. An operator's own
    // `N42_FRAME_BLOCKS=1` is left for `frame_blocks::init` to refuse.
    // Before it, profile 1's pool sizes and QMDB prefault knobs go into the
    // environment (rayon's pools follow RAYON_NUM_THREADS, and the chain
    // parser starts the global one); reth's pools and caches are set on the
    // parsed command.
    let mut p1_memory_set: Vec<String> = Vec::new();
    if let Some(defaults) = &p1_memory {
        // SAFETY: before any thread this program starts and before any of
        // the variables is read (the chain parser below is the first reader).
        p1_memory_set.extend(unsafe { n42_qmdb_reth::profile1_memory::set_env_defaults(defaults) });
        p1_memory_set.extend(std::env::var("MALLOC_CONF").ok().map(|conf| format!("MALLOC_CONF={conf}")));
    }
    let mut cli = Cli::<N42ChainSpecParser, N42Args>::parse();
    if let Some(defaults) = &p1_memory
        && let Some(node) = cli.as_node_command_mut()
    {
        p1_memory_set.extend(n42::profile1_memory::apply_to_node_command(
            defaults,
            &process_args,
            &mut node.engine,
            &mut node.db,
        ));
    }
    if let Some(cores) = p1_memory.as_ref().and_then(|defaults| defaults.cores) {
        // blst's verification pool (committee evidence in every header) is
        // one thread per CPU and has no setting: make it first, at this size.
        match n42_h2_primitives::bls::pool::size_verification_pool(cores) {
            Ok(threads) => p1_memory_set.push(format!("blst pool {threads}")),
            Err(err) => eprintln!("n42: profile 1: blst's pool keeps its size ({err})"),
        }
    }
    if !p1_memory_set.is_empty() {
        eprintln!("n42: profile 1 memory defaults: {} (N42_P1_MEMORY=0 turns them off)", p1_memory_set.join(", "));
    }
    let features = n42_env::profile::ChainFeatures {
        frame_blocks: cli
            .command
            .chain_spec()
            .is_some_and(|spec| reth_chainspec::qmdb::frame_blocks_enabled(&spec.genesis)),
    };
    // SAFETY: no thread of this program reads or writes the environment
    // concurrently. Parsing the command line is not thread-free on a QMDB
    // chain: the chain parser computes the genesis root, which can start
    // rayon's global pool (`N42_QMDB_PARALLEL_APPLY`), but those workers run
    // only the tree's hashing and are idle here; Rust's own environment
    // accesses are serialised by std's lock, and no C library code on them
    // calls `getenv` (audit 2026-10 E-9).
    unsafe { n42_env::profile::reconcile_and_report("n42", features) };
    // Profile 1 of the mixed production standard: the genesis is the only
    // source of consensus-visible values, so a variable or flag that could
    // change one refuses the start (every command with a chain: `node`,
    // `init`, ...); the block size bound is the genesis's `maxBlockBytes`.
    if let Some(spec) = cli.command.chain_spec() {
        if let Err(err) = n42_qmdb_reth::profile1::refuse_process_overrides(&spec.genesis) {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
        if let Some(bytes) = n42_qmdb_reth::profile1::max_block_bytes(&spec.genesis)
            && let Err(cap) = n42_engine_types::byte_budget::set_wire_cap(bytes)
        {
            eprintln!(
                "error: the block size cap was fixed at {cap} bytes before the genesis's maxBlockBytes {bytes} was read"
            );
            std::process::exit(2);
        }
    }
    // `init` on a profile-1 chain writes the genesis as the node stores it:
    // reth's `init` runs on Ethereum's node types, whose header has no
    // element 24, so the stored genesis would lack the zero
    // `mobileRegistryRoot` its hash covers (gov5 vector V1).
    if matches!(cli.command, n42::cli::Commands::Init(_))
        && cli.command.chain_spec().is_some_and(|spec| reth_chainspec::qmdb::is_profile1(&spec.genesis))
    {
        if let Err(err) = profile1_init() {
            eprintln!("Error: {err:?}");
            std::process::exit(1);
        }
        return;
    }
    // `N42_INGEST_VERIFY=shard` without a well-formed `N42_INGEST_SHARD=<i>/<n>`
    // would silently verify everything (or nothing); refuse to start instead.
    let ingest_mode = match n42_tx_types::ingest_verify_mode() {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };
    // `leader`, `shard` and frame gateways take a frame's word for a sender,
    // and the direct ingest skips the pool's checks: benchmark probes, refused
    // unless the operator acknowledges them with N42_BENCH_UNSAFE=1.
    let bench_unsafe = std::env::var("N42_BENCH_UNSAFE").ok();
    let gateways = std::env::var_os("N42_FRAME_GATEWAYS").is_some();
    let direct = n42_env::flag("N42_TX_INGEST_DIRECT", false);
    if let Some(refusal) = n42_tx_types::trusting_mode_refusal(ingest_mode, bench_unsafe.as_deref())
        .or_else(|| n42_tx_types::frame_gateways_refusal(gateways, bench_unsafe.as_deref()))
        .or_else(|| n42_tx_types::ingest_direct_refusal(direct, bench_unsafe.as_deref()))
    {
        eprintln!("error: {refusal}");
        std::process::exit(2);
    }
    let trusting_knobs = n42_tx_types::trusting_ingest_knobs(ingest_mode, direct, gateways);
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

    let (verification_tx, verification_rx) = mpsc::channel(100);
    let (broadcast_tx, _broadcast_rx) = broadcast::channel::<(UnverifiedBlock, Arc<Vec<BLSPubkey>>)>(100);
    let broadcast_tx_clone_for_miner = broadcast_tx.clone();

    // Create router channel for pubsub
    let (router_tx, router_rx) = mpsc::channel::<RouterMsg<UnverifiedBlock>>(100);
    let router_tx_clone = router_tx.clone();
    let router_tx_for_bridge = router_tx;
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
        cli.run(async move |builder, n42_args: N42Args| {
            info!(target: "reth::cli", "Launching node");
            for knob in &trusting_knobs {
                warn!(target: "reth::cli", knob = *knob, "trusting ingest mode accepted: this node admits transactions on a frame's word (benchmark only)");
            }
            // The own-build and follower stores are process-global queues
            // keyed by hash with fixed caps; a cap below the leader's layers
            // plus the build in flight and the one ahead means entries are
            // evicted while a later build may still look for them (the
            // fallback is a re-execution, not a fault, so this warns).
            //
            // On profile 1 the genesis fixes the leader schedule, and a build
            // chains on an own block only within one leader's tenure: the
            // layers that can be in flight are bounded by it (tenure 1: one),
            // not by the knob's default of 2.
            {
                let mut depth = n42_engine_types::direct_build::leader_layers::depth();
                if let Ok(Some(profile)) = n42_qmdb_reth::profile1::profile1(builder.config().chain.genesis()) {
                    depth = n42_engine_types::built_executions::scheduled_layer_depth(
                        depth,
                        profile.leader_tenure,
                        profile.validators.len(),
                    );
                }
                let mut caps = n42_engine_types::built_executions::store_caps();
                caps.extend(n42::follower_import::store_caps());
                for line in n42_engine_types::built_executions::undersized_stores(depth, &caps) {
                    warn!(target: "reth::cli", depth, "{line}");
                }
            }

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
                    let state = QmdbNodeState::new(chain, dir);
                    // `--qmdb.history` overrides `N42_QMDB_HISTORY` (an
                    // invalid value of either refuses to start).
                    if let Some(mode) = n42_args.qmdb_history {
                        info!(target: "reth::cli", %mode, "QMDB history set on the command line");
                        state.set_history_mode(mode);
                    }
                    Some(state)
                }
                StateScheme::Mpt => {
                    if n42_args.qmdb_history.is_some_and(|mode| mode.is_on()) {
                        return Err(eyre::eyre!("--qmdb.history needs a QMDB chain; this chain's genesis declares the MPT state commitment"));
                    }
                    None
                }
            };
            let qmdb_for_startup = qmdb.clone();
            let qmdb_before_launch = qmdb.clone();
            let qmdb_for_rpc = qmdb.clone();

            let NodeHandle {
                node,
                node_exit_future,
            } = builder
                // The node's header is `N42Header`; its chain spec wraps the
                // parsed one (same genesis hash) over that header.
                .map_chainspec(n42_header::N42ChainSpec::from)
                .node(N42Node::with_qmdb(qmdb))
                // Restore state and deferred results before engine/RPC launch.
                // A cold checkpoint can take seconds to read; an early payload
                // must not be permanently marked invalid while it is loading.
                .on_component_initialized(move |node| {
                    use reth_provider::ChainSpecProvider;
                    if let Some(qmdb) = &qmdb_before_launch {
                        let durable_provider = node.provider.clone();
                        qmdb.set_durable_head_reader(move || {
                            use reth_provider::DatabaseProviderFactory;
                            use reth_db_api::transaction::DbTx;
                            let database = durable_provider.database_provider_ro().ok()?;
                            database.tx_ref().get::<reth_db_api::tables::StageCheckpoints>("Finish".to_owned())
                                .ok()?.map(|checkpoint| checkpoint.block_number)
                        });
                        let info = node.provider.chain_info()?;
                        let head_hash = node
                            .provider
                            .block_hash(info.best_number)?
                            .ok_or_else(|| eyre::eyre!("no hash for head block {}", info.best_number))?;
                        use reth_provider::{HeaderProvider, ReceiptProvider};
                        let head = node.provider.sealed_header(info.best_number)?
                            .ok_or_else(|| eyre::eyre!("no header for head block {}", info.best_number))?;
                        if head.hash() != head_hash {
                            return Err(eyre::eyre!("canonical head changed during QMDB startup"));
                        }
                        let chain_spec = node.provider.chain_spec();
                        let genesis = chain_spec.genesis();
                        if info.best_number > 0 && reth_chainspec::qmdb::deferred_execution_depth_at(genesis, head.timestamp) == 2 {
                            // The first child carries result(head-1), then the next
                            // carries result(head). Restore the frontier before QMDB
                            // initialisation can resume a compaction or migrate files.
                            let parent = node.provider.sealed_header(info.best_number - 1)?
                                .ok_or_else(|| eyre::eyre!("no header for deferred recovery parent {}", info.best_number - 1))?;
                            if parent.hash() != head.parent_hash {
                                return Err(eyre::eyre!("deferred recovery parent is not canonical"));
                            }
                            let state_root = if parent.number == 0 {
                                parent.state_root
                            } else {
                                qmdb.persisted_state_root(parent.number, parent.hash())?
                            };
                            let receipts = match node.provider.receipts_by_block(parent.hash().into())? {
                                Some(receipts) => receipts,
                                None if parent.transactions_root == alloy_consensus::EMPTY_ROOT_HASH => Vec::new(),
                                None => return Err(eyre::eyre!("missing receipts for deferred recovery parent {}", parent.number)),
                            };
                            let (receipts_root, logs_bloom) = n42_engine_types::hotstuff_consensus::gov5_receipt_root_bloom(&receipts);
                            let gas_used = receipts.last().map_or(0, |receipt| receipt.cumulative_gas_used);
                            qmdb.remember_checkpoint_parent((head.number, head.hash()), parent.hash(), state_root)?;
                            n42_engine_types::executed_fields::remember(parent.hash(),
                                n42_engine_types::executed_fields::ExecutedFields { state_root, receipts_root, logs_bloom, gas_used, requests_hash: n42_engine_types::executed_fields::NO_REQUESTS_HASH });
                            info!(target: "reth::cli", block = parent.number, hash = %parent.hash(), "restored deferred execution parent result");
                        }
                        // Without deferred execution the head's header carries
                        // its own root: the restart's check when forest.roots
                        // lost the head's record (audit 2026-10 D-3).
                        if !reth_chainspec::qmdb::deferred_execution_active_at(genesis, head.timestamp) {
                            qmdb.expect_head_root((info.best_number, head_hash), head.state_root);
                        }
                        qmdb.initialize((info.best_number, head_hash))?;
                        info!(target: "reth::cli", block = info.best_number, %head_hash, "QMDB state ready");
                        // A lagging CL may re-submit persisted blocks below this EL's
                        // recovered frontier. Their deferred results are committed in
                        // canonical depth-D descendant headers, not in their own header.
                        // Resolve misses without replaying QMDB or evicting live results.
                        let historical_provider = node.provider.clone();
                        let historical_genesis = genesis.clone();
                        n42_engine_types::executed_fields::set_historical_reader(move |hash| {
                            use reth_provider::DatabaseProviderFactory;
                            let database = historical_provider.database_provider_ro().ok()?;
                            let ancestor = database.header(*hash).ok()??;
                            if ancestor.hash_slow() != *hash { return None; }
                            if database.block_hash(ancestor.number).ok()? != Some(*hash) { return None; }
                            let requests_deferred = n42_engine_types::hotstuff_consensus::requests_hash_deferred(&historical_genesis);
                            if !reth_chainspec::qmdb::deferred_execution_active_at(&historical_genesis, ancestor.timestamp) {
                                return Some(n42_engine_types::executed_fields::fields_from_child_header_deferring_requests(&ancestor, requests_deferred));
                            }
                            let depth = u8::try_from(reth_chainspec::qmdb::deferred_execution_depth_at(&historical_genesis, ancestor.timestamp)).ok()?;
                            if !(1..=2).contains(&depth) { return None; }
                            let mut descendants = Vec::with_capacity(usize::from(depth));
                            for step in 1..=depth {
                                descendants.push(database.header_by_number(ancestor.number.checked_add(u64::from(step))?).ok()??.into_inner());
                            }
                            let carrying = descendants.last()?;
                            if reth_chainspec::qmdb::deferred_execution_depth_at(&historical_genesis, carrying.timestamp) != u64::from(depth) { return None; }
                            n42_engine_types::executed_fields::fields_from_descendants_deferring_requests(&ancestor, &descendants, depth, requests_deferred)
                        });
                        // With HotStuff-2 finality the canonical head is the committed
                        // block, and a build on an ancestor of it is a stale request
                        // that would revert the state tree below the head.
                        if n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(node.provider.chain_spec().genesis()).is_ok() {
                            qmdb.set_refuse_stale_builds(true);
                            // The canonical head can run ahead of consensus onto a
                            // block that is never certified (a build ahead on the
                            // block this node just voted for makes it canonical); the
                            // next leader then builds on its high-QC block, an
                            // ancestor of that head (F5g5). The guard refuses only
                            // what lies below the committed block, which the
                            // validator's forkchoice gives as `safe` plus the
                            // deferred-execution depth (`safe` is the block whose
                            // execution a committed child carries, under the default
                            // `split` settlement tags; under `legacy` it is the
                            // committed block itself, and the floor is `safe`).
                            let provider = node.provider.clone();
                            let genesis = node.provider.chain_spec().genesis().clone();
                            // The validator's `N42_SETTLEMENT_TAGS` (h2-execution
                            // `settlement.rs`), read here too: under `legacy` the
                            // floor is `safe` itself.
                            let legacy_tags = std::env::var("N42_SETTLEMENT_TAGS").is_ok_and(|value| value.trim() == "legacy");
                            qmdb.set_committed_source(Some(std::sync::Arc::new(move || {
                                let safe = reth_provider::BlockIdReader::safe_block_num_hash(&provider).ok()??;
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |since| since.as_secs());
                                let depth = if reth_chainspec::qmdb::deferred_execution_active_at(&genesis, now) {
                                    reth_chainspec::qmdb::deferred_execution_depth_at(&genesis, now)
                                } else {
                                    0
                                };
                                // `safe` at the genesis floor: the committed block may be
                                // genesis itself (`n42_qmdb_reth::committed_floor`).
                                Some(n42_qmdb_reth::committed_floor_for(safe.number, depth, legacy_tags))
                            })));
                        }
                        // The QMDB state is registered as the state reader on every QMDB
                        // node: its persistence hook makes the delta log durable through a
                        // batch before the database commits it (`N42_QMDB_SETTLE_WAIT_MS`).
                        // `N42_QMDB_READS=verify|on`: the read view also answers or checks the
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
                        {
                            // A head initialised from a state snapshot has no body, receipts
                            // or parent state: its fields are those its child, the anchor
                            // `n42-init-snapshot init --anchor` kept, carries.
                            let snapshot_head = if reth_chainspec::qmdb::deferred_execution_active_at(genesis, head.timestamp) {
                                let qmdb_dir = qmdb.snapshot_path().parent().map(std::path::Path::to_path_buf).unwrap_or_default();
                                n42::snapshot_anchor::head_fields(
                                    &qmdb_dir,
                                    (head.number, head.hash()),
                                    n42_engine_types::hotstuff_consensus::requests_hash_deferred(genesis),
                                )?
                            } else {
                                None
                            };
                            if let Some(fields) = snapshot_head {
                                let root = qmdb.root_of(&head.hash())
                                    .ok_or_else(|| eyre::eyre!("missing QMDB root for snapshot head {}", head.number))?;
                                if root != fields.state_root {
                                    return Err(eyre::eyre!("snapshot head {}: the forest's root {root} is not the anchor's carried root {}", head.number, fields.state_root));
                                }
                                info!(target: "reth::cli", block = head.number, gas_used = fields.gas_used, "snapshot head: executed fields filed from the anchor");
                                n42_engine_types::executed_fields::remember(head.hash(), fields);
                            } else if reth_chainspec::qmdb::deferred_execution_active_at(genesis, head.timestamp) {
                                let receipts = match node.provider.receipts_by_block(head.hash().into())? {
                                    Some(receipts) => receipts,
                                    None if head.transactions_root == alloy_consensus::EMPTY_ROOT_HASH => Vec::new(),
                                    None => return Err(eyre::eyre!("missing receipts for deferred recovery head {}", head.number)),
                                };
                                let (receipts_root, logs_bloom) = n42_engine_types::hotstuff_consensus::gov5_receipt_root_bloom(&receipts);
                                // The receipts' cumulative gas is what the transactions paid; the
                                // block's gas used, the deferred field, can differ from it (on
                                // Amsterdam EIP-8037's state gas makes an account-creating
                                // transfer pay ~205k while the block counts less): the
                                // re-execution below gives the block's own value where it runs.
                                let receipts_gas_used = receipts.last().map_or(0, |r| r.cumulative_gas_used);
                                {
                                    let state_root = qmdb.root_of(&head.hash())
                                        .ok_or_else(|| eyre::eyre!("missing QMDB root for recovery head {}", head.number))?;
                                    // AM25: on a profile-1 chain the head's requests hash is a
                                    // deferred field its child carries. No table keeps requests,
                                    // so the head is executed once more on its parent's state.
                                    let (requests_hash, gas_used) = if head.number > 0
                                        && n42_engine_types::hotstuff_consensus::requests_hash_deferred(genesis)
                                    {
                                        match head_reexecution(&node.provider, node.evm_config(), head.hash()) {
                                            Ok((hash, gas_used)) => {
                                                if gas_used != receipts_gas_used {
                                                    info!(target: "reth::cli", block = head.number, gas_used, receipts_gas_used, "recovery head: the block's gas used is not its receipts' cumulative gas; filing the block's");
                                                }
                                                (hash, gas_used)
                                            }
                                            Err(err) => {
                                                error!(target: "reth::cli", %err, block = head.number, "could not re-execute the recovery head for its requests hash; filing the hash of no requests");
                                                (n42_engine_types::executed_fields::NO_REQUESTS_HASH, receipts_gas_used)
                                            }
                                        }
                                    } else {
                                        (n42_engine_types::executed_fields::NO_REQUESTS_HASH, receipts_gas_used)
                                    };
                                    n42_engine_types::executed_fields::remember(
                                        head.hash(),
                                        n42_engine_types::executed_fields::ExecutedFields { state_root, receipts_root, logs_bloom, gas_used, requests_hash },
                                    );
                                }
                            } else {
                                n42_engine_types::executed_fields::seed_from_header(head.hash(), head.header());
                            }
                        }

                        // Follow the canonical chain so the persisted head keeps up with
                        // the database's. Lagging is tolerable — only the tip matters,
                        // and every tree in between was filed at validation.
                        // `on_canonical` is synchronous QMDB work, so the loop runs on
                        // a thread of its own with a blocking receiver rather than on a
                        // tokio worker; one receiver, so the order is kept.
                        let mut canonical = node.provider.subscribe_to_canonical_state();
                        let follower = qmdb.clone();
                        let follow = move || loop {
                            match canonical.blocking_recv() {
                                Ok(notification) => {
                                    let behind = canonical.len();
                                    if behind > 8 {
                                        warn!(target: "reth::cli", behind, "canonical subscriber lag: qmdb head follower");
                                    }
                                    let tip = notification.tip().hash();
                                    if let Err(error) = follower.on_canonical(tip) {
                                        // A notification the log cannot follow leaves it unable to
                                        // track the chain: stop rather than run on a log that a
                                        // restart would refuse (`N42_QMDB_CANONICAL_FATAL=0` keeps
                                        // the old log-and-continue). I/O on the log is retried by
                                        // the next head and stays a log line.
                                        if n42_qmdb_reth::canonical_fatal() && follower.is_fatal_canonical_error(&error, tip) {
                                            error!(
                                                target: "reth::cli",
                                                %error, block_hash = %tip,
                                                "QMDB head cannot follow the canonical chain; exiting (N42_QMDB_CANONICAL_FATAL=0 continues)"
                                            );
                                            std::process::exit(1);
                                        }
                                        error!(target: "reth::cli", %error, "QMDB head could not follow the canonical chain");
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                    warn!(target: "reth::cli", skipped, "QMDB head follower fell behind canonical notifications");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        };
                        // A plain thread, not the runtime's blocking pool: a task
                        // there that never ends would hold up the runtime's shutdown.
                        std::thread::Builder::new()
                            .name("n42-qmdb-follow".into())
                            .spawn(follow)
                            .map_err(|err| eyre::eyre!("no thread for the QMDB head follower: {err}"))?;
                    }
                    Ok(())
                })
                .extend_rpc_modules(move |ctx| {
                    let consensus = ctx.node().consensus().clone();
                    let provider = ctx.provider().clone();

                    // Store consensus reference for later use
                    *consensus_holder_clone.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
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
                    // Canonical blocks by range, as RLP, for the validator's
                    // range serving (in-memory and persisted alike: the
                    // provider answers both). Stops at the first block not
                    // held and once the byte bound is reached.
                    let range_provider = ctx.provider().clone();
                    let blocks_by_range: n42::engine_ext::BlocksByRange =
                        std::sync::Arc::new(move |start, count, max_bytes| {
                            let mut out = Vec::new();
                            let mut bytes = 0usize;
                            for number in start..start.saturating_add(count) {
                                let Ok(Some(block)) = reth_provider::BlockReader::block_by_number(&range_provider, number) else {
                                    break;
                                };
                                let rlp = alloy_rlp::encode(&block);
                                bytes = bytes.saturating_add(rlp.len());
                                out.push(rlp.into());
                                if bytes >= max_bytes {
                                    break;
                                }
                            }
                            out
                        });
                    let engine_ext = N42EngineExt {
                        payloads: ctx.node().payload_builder_handle().clone(),
                        raw_endpoint,
                        in_memory_blocks: Some(in_memory_blocks),
                        persisted_block: Some(persisted_block),
                        blocks_by_range: Some(blocks_by_range),
                    };

                    // A QMDB chain proves state from the forest: `n42_getProof`
                    // (QMDB twig proofs at persisted blocks, from the history
                    // `N42_QMDB_HISTORY` keeps), and `eth_getProof` -- whose
                    // Merkle-Patricia proofs would not verify against a QMDB
                    // header -- refused with a pointer to it.
                    if let Some(qmdb) = qmdb_for_rpc {
                        use reth_provider::ChainSpecProvider;
                        let genesis = ctx.provider().chain_spec().genesis().clone();
                        let root_offset: n42::qmdb_proof_ext::RootOffset = std::sync::Arc::new(move |timestamp| {
                            if reth_chainspec::qmdb::deferred_execution_active_at(&genesis, timestamp) {
                                reth_chainspec::qmdb::deferred_execution_depth_at(&genesis, timestamp)
                            } else {
                                0
                            }
                        });
                        let finish_provider = ctx.provider().clone();
                        let persisted: n42::qmdb_proof_ext::PersistedHead = std::sync::Arc::new(move || {
                            use reth_db_api::transaction::DbTx;
                            use reth_provider::DatabaseProviderFactory;
                            let database = finish_provider.database_provider_ro().ok()?;
                            database
                                .tx_ref()
                                .get::<reth_db_api::tables::StageCheckpoints>("Finish".to_owned())
                                .ok()?
                                .map(|checkpoint| checkpoint.block_number)
                        });
                        let proofs = n42::qmdb_proof_ext::QmdbProofExt {
                            state: qmdb,
                            provider: ctx.provider().clone(),
                            root_offset,
                            persisted,
                        };
                        use n42::qmdb_proof_ext::QmdbProofApiServer;
                        ctx.modules.merge_configured(proofs.into_rpc())?;
                        ctx.modules.replace_configured(n42::qmdb_proof_ext::eth_get_proof_refusal())?;
                        ctx.auth_module.replace_auth_methods(n42::qmdb_proof_ext::eth_get_proof_refusal())?;
                        info!(target: "reth::cli", "QMDB proof namespace enabled (n42_getProof); eth_getProof refused");
                        // The execution witness is the same trie's nodes:
                        // refused too (`docs/RPC_SURFACE_NATIVE.md`).
                        if ctx.modules.module_config().contains_any(&reth_rpc_server_types::RethRpcModule::Debug) {
                            ctx.modules.replace_configured(n42::native_rpc::execution_witness_refusal())?;
                        }
                    }

                    // EIP-7910 `eth_config`: reth's handler on an Ethereum
                    // chain (upstream's node merges it, ours did not); gov5's
                    // refusal on a native one, whose fork schedule the EIP
                    // cannot express (`n42::native_rpc`).
                    {
                        use reth_provider::ChainSpecProvider;
                        use reth_rpc_server_types::RethRpcModule;
                        if reth_chainspec::qmdb::is_n42_native(ctx.provider().chain_spec().genesis()) {
                            ctx.modules.merge_if_module_configured(RethRpcModule::Eth, n42::native_rpc::eth_config_refusal())?;
                        } else {
                            use reth_rpc_eth_api::helpers::config::{EthConfigApiServer, EthConfigHandler};
                            let handler = EthConfigHandler::new(ctx.provider().clone(), ctx.node().evm_config().clone());
                            ctx.modules.merge_if_module_configured(RethRpcModule::Eth, handler.into_rpc())?;
                        }
                    }

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
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .ok_or_else(|| eyre::eyre!("the consensus instance was not set by the RPC hook"))?;

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
            // The node builder forces the suffix to 0 on a QMDB chain, so the configured value only
            // matters on a chain without QMDB.
            let qmdb_chain = reth_chainspec::qmdb::state_scheme(node.chain_spec().genesis())
                == reth_chainspec::qmdb::StateScheme::Qmdb;
            if n42_qmdb_reth::n42_state::hashed_tables_off()
                && !qmdb_chain
                && node.config.engine.num_state_masking_blocks > 0
            {
                return Err(eyre::eyre!(
                    "N42_HASHED_TABLES=off needs --engine.num-state-masking-blocks 0 (got {}): the QMDB read view answers at the database tip",
                    node.config.engine.num_state_masking_blocks
                ));
            }

            // The canonical notification channel's backlog: the notifications
            // tokio still holds because some receiver has not read them (each
            // keeps a whole block alive). Sampled every 5 s; logged when non-zero,
            // otherwise once a minute.
            {
                let in_memory = node.provider.canonical_in_memory_state();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                    let mut last_log: Option<std::time::Instant> = None;
                    loop {
                        tick.tick().await;
                        let slots = in_memory.canon_notification_backlog();
                        metrics::gauge!("n42_canon_notification_backlog").set(slots as f64);
                        let quiet_for = last_log.map(|at| at.elapsed());
                        if slots > 0 || quiet_for.is_none_or(|d| d >= std::time::Duration::from_secs(60)) {
                            last_log = Some(std::time::Instant::now());
                            info!(target: "n42.canon", slots, "canonical notification backlog");
                        }
                    }
                });
            }

            // QMDB health: `n42_qmdb_forest_poisoned` is 1 once the forest has
            // refused further applies (the node stalls rather than diverge), and
            // `n42_qmdb_unchecked_restart` is 1 when this run started on a tree
            // that was not checked against the root recorded for its head. Both
            // are sticky for the run; each is logged once, at error level, when
            // it first turns 1. A chain without QMDB exports neither.
            //
            // The entry store's growth (`docs/QMDB_COMPACTION_DESIGN.md` 3.7):
            // the entry file's bytes, its slots in all and still live, the
            // offsets' and the key index's heap, the file's sealed chunks, the
            // compacted twigs' bytes in `entries.relocated`, the bytes punched
            // (stage 3), and
            // `n42_qmdb_entry_bytes_per_live_slot` ((file + relocated - punched) / live),
            // logged once at warn level
            // when it passes `N42_QMDB_ENTRY_BYTES_PER_LIVE_ALARM` (default
            // 2000, 0 disables). A tick that finds the forest lock held skips
            // these gauges rather than wait.
            if let Some(qmdb) = qmdb_for_startup.clone() {
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                    let mut poisoned_seen = false;
                    let mut unchecked_seen = false;
                    let bytes_per_live_alarm: u64 = n42_env::parse("N42_QMDB_ENTRY_BYTES_PER_LIVE_ALARM", 2000);
                    let mut bytes_per_live_warned = false;
                    let mut ticks = 0u64;
                    loop {
                        tick.tick().await;
                        ticks += 1;
                        // `poisoned()` answers None while the forest lock is held,
                        // so a reason once seen is latched rather than re-read.
                        if !poisoned_seen
                            && let Some(reason) = qmdb.poisoned() {
                                poisoned_seen = true;
                                error!(target: "reth::cli", %reason, "QMDB forest is poisoned; state applies are refused");
                            }
                        if !unchecked_seen
                            && let Some(reason) = qmdb.unchecked_restart() {
                                unchecked_seen = true;
                                error!(target: "reth::cli", %reason, "QMDB restarted on a tree not checked against its recorded head root");
                            }
                        metrics::gauge!("n42_qmdb_forest_poisoned").set(if poisoned_seen { 1.0 } else { 0.0 });
                        metrics::gauge!("n42_qmdb_unchecked_restart").set(if unchecked_seen { 1.0 } else { 0.0 });
                        if let Some(stats) = qmdb.entry_stats() {
                            let per_live = stats.bytes_per_live_slot();
                            metrics::gauge!("n42_qmdb_entry_file_bytes").set(stats.file_bytes as f64);
                            metrics::gauge!("n42_qmdb_entry_total_slots").set(stats.total_slots as f64);
                            metrics::gauge!("n42_qmdb_entry_live_slots").set(stats.live_slots as f64);
                            metrics::gauge!("n42_qmdb_offsets_bytes").set(stats.offsets_bytes as f64);
                            metrics::gauge!("n42_qmdb_index_bytes").set(stats.index_bytes as f64);
                            metrics::gauge!("n42_qmdb_entry_chunks").set(stats.chunks as f64);
                            metrics::gauge!("n42_qmdb_entry_relocated_bytes").set(stats.relocated_bytes as f64);
                            metrics::gauge!("n42_qmdb_entry_punched_bytes").set(stats.punched_bytes as f64);
                            metrics::gauge!("n42_qmdb_entry_bytes_per_live_slot").set(per_live as f64);
                            // With the entry compaction running (`N42_QMDB_COMPACT=1`), the
                            // same numbers once a minute in the log, for a fleet leg to read.
                            let (rounds, twigs, written, punched) = qmdb.entry_compaction_totals();
                            if rounds > 0 && ticks.is_multiple_of(6) {
                                info!(
                                    target: "n42.qmdb",
                                    per_live,
                                    file_bytes = stats.file_bytes,
                                    relocated_bytes = stats.relocated_bytes,
                                    punched_bytes = stats.punched_bytes,
                                    live_slots = stats.live_slots,
                                    total_slots = stats.total_slots,
                                    offsets_bytes = stats.offsets_bytes,
                                    rounds, twigs, written, punched,
                                    "QMDB entry store",
                                );
                            }
                            if bytes_per_live_alarm > 0 && per_live > bytes_per_live_alarm && !bytes_per_live_warned {
                                bytes_per_live_warned = true;
                                warn!(
                                    target: "n42.qmdb",
                                    per_live,
                                    alarm = bytes_per_live_alarm,
                                    file_bytes = stats.file_bytes,
                                    relocated_bytes = stats.relocated_bytes,
                                    live_slots = stats.live_slots,
                                    total_slots = stats.total_slots,
                                    "the QMDB entry store holds more bytes per live slot than N42_QMDB_ENTRY_BYTES_PER_LIVE_ALARM; it grows with the append history (docs/QMDB_COMPACTION_DESIGN.md)",
                                );
                            }
                        }
                    }
                });
            }

            // The frame road's bounds (`docs/MATURITY_HARDENING_2026_10.md` 6.4):
            // `n42_road_taken_frames` is how many taken frames the road still
            // remembers (bounded by `N42_ROAD_TAKEN_BOUND=1`, else by
            // `N42_ROAD_TAKEN_MAX`), `n42_road_oversize_frames_total` the frames
            // refused for a gas above the block gas limit. Both read 0 while
            // the road is off.
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    let road = n42_tx_queue::road_stats().unwrap_or_default();
                    metrics::gauge!("n42_road_taken_frames").set(road.taken_frames as f64);
                    metrics::counter!("n42_road_oversize_frames_total").absolute(road.refused_oversize);
                }
            });

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
                                let behind = canonical.len();
                                if behind > 8 {
                                    warn!(target: "n42.canon", behind, "canonical subscriber lag: leader layers");
                                }
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
                let eth_signer: PrivateKeySigner = signer_private_key.clone()
                    .parse()
                    .map_err(|err| eyre::eyre!("invalid --dev.consensus-signer-private-key: {err}"))?;
                Some(eth_signer.address())
            } else {
                None
            };

            // The raw payload channel for the validator, loopback only (a
            // non-loopback address is refused unless
            // `N42_PAYLOAD_SERVE_ALLOW_REMOTE=1`). See `payload_serve`.
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
                        let reuse = (!n42_env::flag("N42_NO_OWN_BLOCK_REUSE", false)).then(|| {
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
                                import_foreign: n42_env::flag("N42_FOLLOWER_DIRECT_IMPORT", false).then(|| {
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
                                exec_probe: n42_env::flag("N42_FOLLOWER_EXEC_PROBE", false).then(|| {
                                    let provider = node.provider.clone();
                                    let evm_config = node.evm_config.clone();
                                    std::sync::Arc::new(move |block: reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>| {
                                        use reth_evm::execute::Executor as _;
                                        use reth_evm::ConfigureEvm as _;
                                        use reth_provider::StateProviderFactory as _;
                                        let state = provider.state_by_block_hash(block.parent_hash).map_err(|e| e.to_string())?;
                                        let db = reth_evm::database::StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state));
                                        let started = std::time::Instant::now();
                                        let mut executor = evm_config.executor(db);
                                        let out = executor.execute_one(&block).map_err(|e| e.to_string())?;
                                        Ok((started.elapsed().as_millis() as u64, out.gas_used, out.receipts.len()))
                                    }) as std::sync::Arc<dyn Fn(reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Result<(u64, u64, usize), String> + Send + Sync>
                                }),
                                prune_pool: n42_env::flag("N42_PRUNE_POOL_ON_IMPORT", false).then(|| {
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
            if n42_env::flag("N42_TX_QUEUE", false) {
                let queue: n42_tx_queue::TxQueue<n42_engine_types::N42PooledTransaction> = n42_tx_queue::TxQueue::new();
                if n42_env::flag("N42_TX_QUEUE_DRAINER", false) && queue.wants_drainer_thread() {
                    // N42_QUEUE_OFFLOCK: a thread of its own, woken early by a
                    // deep inbox; while it runs the block path's holds drain
                    // only a bounded slice. See TxQueue::run_drainer.
                    let drained = queue.clone();
                    if let Err(err) = std::thread::Builder::new()
                        .name("tx-queue-drainer".into())
                        .spawn(move || drained.run_drainer(std::time::Duration::from_millis(5)))
                    {
                        tracing::warn!(target: "reth::cli", %err, "could not start the queue's drainer thread");
                    }
                } else if n42_env::flag("N42_TX_QUEUE_DRAINER", false) {
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
                let mut pruner = n42::queue_prune::on_own_thread()
                    .then(|| n42::queue_prune::spawn_thread(queue.clone()))
                    .flatten();
                let prune_feed_lean = pruner.is_some() && n42::queue_prune::feed_lean();
                let backfill_provider = node.provider.clone();
                tokio::spawn(async move {
                    // Heights a lagged receiver skipped are read back and
                    // pruned ahead of the notification that shows them
                    // (R3-P4).
                    let mut watch = n42::queue_prune::GapWatch::default();
                    loop {
                        match canonical.recv().await {
                            Ok(notification) => {
                                let behind = canonical.len();
                                if behind > 8 {
                                    warn!(target: "reth::cli", behind, "canonical subscriber lag: queue pruner");
                                }
                                if let Some(gap) = watch.before(&notification) {
                                    let provider = backfill_provider.clone();
                                    let read = tokio::task::spawn_blocking(move || {
                                        n42::queue_prune::backfill(gap, |range| {
                                            reth_provider::BlockReader::recovered_block_range(&provider, range)
                                        })
                                    })
                                    .await
                                    .unwrap_or_default();
                                    if !read.is_empty() {
                                        n42::queue_prune::forward(&mut pruner, n42::queue_prune::PruneFeed::Lean(read), |feed| {
                                            n42::queue_prune::prune_feed_inline(&queue, &feed)
                                        });
                                    }
                                }
                                match pruner {
                                    Some(_) => {
                                        // Read by the builder: said here as
                                        // well, so the thread's queue does
                                        // not delay it.
                                        for block in notification.committed().blocks_iter() {
                                            n42_engine_types::canonical_head::saw(block.number());
                                        }
                                        // `N42_PRUNE_FEED_LEAN=1` (default off): an
                                        // ordinary commit goes as lean block
                                        // summaries and the notification -- the
                                        // last holder of the blocks' bodies once
                                        // the engine lets go -- is dropped here,
                                        // not when the pruner gets to it. Round
                                        // 10.226: it loses 2-3.6% (LA1/LA1b
                                        // 4.915 against 5.100/5.019 M tx/s), the
                                        // pair collection being on this thread.
                                        let feed = n42::queue_prune::PruneFeed::of(notification, prune_feed_lean);
                                        // A pruning thread that died (logged
                                        // once) leaves `pruner` empty: this item
                                        // and every later one are pruned here.
                                        n42::queue_prune::forward(&mut pruner, feed, |feed| {
                                            n42::queue_prune::prune_feed_inline(&queue, &feed)
                                        });
                                    }
                                    None if n42_tx_queue::prune_lean() => {
                                        // `N42_PRUNE_LEAN`: every notification
                                        // already waiting is folded into this
                                        // wake's one removal.
                                        let mut batch = vec![notification];
                                        loop {
                                            match canonical.try_recv() {
                                                Ok(next) => batch.push(next),
                                                // Ends the fold: the stretch is read
                                                // back at the next notification.
                                                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                                                    warn!(target: "n42.tx_queue", skipped, "queue pruning fell behind canonical notifications");
                                                    break;
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                        // `N42_PRUNE_MIN_FOLD`: hold the wake
                                        // until at least `min_fold` blocks are
                                        // in, or `max_wait` has passed since
                                        // the first (see `n42::queue_prune`).
                                        let (min_fold, max_wait) = n42::queue_prune::min_fold();
                                        let first_at = std::time::Instant::now();
                                        if min_fold > 1 {
                                            let deadline = first_at + max_wait;
                                            while batch.len() < min_fold {
                                                let now = std::time::Instant::now();
                                                if now >= deadline {
                                                    break;
                                                }
                                                match tokio::time::timeout(deadline - now, canonical.recv()).await {
                                                    Ok(Ok(next)) => batch.push(next),
                                                    Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped))) => {
                                                        warn!(target: "n42.tx_queue", skipped, "queue pruning fell behind canonical notifications");
                                                        break;
                                                    }
                                                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => break,
                                                }
                                            }
                                        }
                                        for later in &batch[1..] {
                                            let _ = watch.before(later);
                                        }
                                        let notifications: Vec<_> = batch.iter().collect();
                                        n42::queue_prune::prune_notifications_lean(&queue, &notifications, first_at.elapsed());
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
            // asked for, and unauthenticated: it binds loopback only unless
            // `N42_TX_INGEST_ALLOW_REMOTE=1`, and never off loopback under
            // the modes that trust a frame (direct, claimed senders, gateway
            // attestations), which admit what `eth_sendRawTransaction` would
            // not (`n42_tx_ingest::ingest_bind_refusal`). An empty value is
            // unset (`scripts/fleet7.sh` passes `N42_TX_INGEST=` to a node
            // that serves none).
            if let Some(addr) = n42_env::var("N42_TX_INGEST").filter(|addr| !addr.trim().is_empty()) {
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
                            let mut canonical = n42_engine_types::canon_lag::watched(
                                "head_tracker",
                                node.provider.subscribe_to_canonical_state(),
                            );
                            tokio::spawn(async move {
                                while let Some(notification) = canonical.next().await {
                                    head.store(notification.tip().number, std::sync::atomic::Ordering::Relaxed);
                                }
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
            } else if consensus_signer_private_key.is_some() {
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

#[cfg(test)]
mod tests {
    use super::N42Args;
    use clap::Parser;
    use n42_qmdb_reth::history::HistoryMode;

    #[derive(Debug, Parser)]
    struct Line {
        #[command(flatten)]
        n42: N42Args,
    }

    #[test]
    fn the_qmdb_history_flag_parses_a_count_all_or_off_and_refuses_anything_else() {
        let parse = |args: &[&str]| Line::try_parse_from(std::iter::once("n42").chain(args.iter().copied())).map(|l| l.n42.qmdb_history);
        assert_eq!(parse(&[]).unwrap(), None, "absent: N42_QMDB_HISTORY decides");
        assert_eq!(parse(&["--qmdb.history", "all"]).unwrap(), Some(HistoryMode::All));
        assert_eq!(parse(&["--qmdb.history", "50000"]).unwrap(), Some(HistoryMode::Keep(50_000)));
        assert_eq!(parse(&["--qmdb.history=off"]).unwrap(), Some(HistoryMode::Off));
        assert!(parse(&["--qmdb.history", "lots"]).is_err());
    }
}

/// The EIP-7685 requests hash of block `hash`'s execution, by executing it
/// once more on its parent's state: a profile-1 restart's head (AM25), whose
/// requests hash its child carries and no table keeps.
/// Re-executes a recovery head on its parent's state: its requests hash and
/// the block's gas used (the deferred field, not the receipts' cumulative gas).
fn head_reexecution<Provider, Evm>(provider: &Provider, evm_config: &Evm, hash: alloy_primitives::B256) -> eyre::Result<(alloy_primitives::B256, u64)>
where
    Provider: reth_provider::BlockReader<Block = n42_tx_types::Block> + reth_provider::StateProviderFactory,
    Evm: reth_evm::ConfigureEvm<Primitives = n42_tx_types::N42Primitives>,
{
    let block = provider
        .recovered_block(hash.into(), reth_provider::TransactionVariant::WithHash)?
        .ok_or_else(|| eyre::eyre!("no block {hash}"))?;
    let state = provider.state_by_block_hash(block.parent_hash)?;
    let db = reth_evm::database::StateProviderDatabase::new(reth_provider::StateProvider::into_evm_state_provider(&state));
    Ok(n42_engine_types::head_reexecution::reexecute_block(evm_config, db, &block)?)
}

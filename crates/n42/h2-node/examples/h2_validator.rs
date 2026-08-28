// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Run a participating HotStuff-2 v4 node against a real execution layer.
//!
//! This is the whole stack assembled: gossip transport, consensus engine, and an
//! Engine API client driving an execution client. Unlike `h2_observer`, it votes.
//!
//! ```text
//! cargo run -p n42-h2-node --example h2_validator -- \
//!     --chain crates/chainspec/res/genesis/n42_devnet.json \
//!     --index 0 \
//!     --bls-key 0x<64 hex chars> \
//!     --el http://127.0.0.1:8551 \
//!     --jwt /path/to/jwt.hex \
//!     --peer /ip4/127.0.0.1/tcp/32100/p2p/<peer id> \
//!     --listen /ip4/0.0.0.0/tcp/32200 \
//!     --propose
//! ```
//!
//! `--chain <genesis.json>` is the same file the execution layer and any gov5
//! node on the chain were initialised from. Chain id, genesis hash, validator
//! set (in QC bitmap order), view timeouts and block period all come from its
//! `hotstuff` block, so the three clients cannot disagree about the fleet.
//! `--chain-id`/`--genesis`/`--validators` remain for a chain that keeps its
//! validators elsewhere.
//!
//! `--el` is the *auth* port (reth's `--authrpc.port`, default 8551), not the
//! public JSON-RPC port. Pointing it at the public port makes every Engine API
//! call fail with "method not found", which reads like a version mismatch.
//!
//! `--propose` makes this node build blocks when it is leader. Without it the
//! node votes on other members' proposals but never makes one, which is the
//! right way to join a fleet that is already producing.
//!
//! `--datadir <path>` makes consensus state survive a restart: the vote log
//! (a safety requirement — a node that restarts without it re-votes in views it
//! already signed, which is equivocation) and a checkpoint so the node rejoins
//! near the head instead of proposing from genesis, which a live execution layer
//! answers with `-38006 Too deep reorg`. Without it the node runs stateless and
//! must not be restarted into a fleet it was already voting in.
//!
//! `--mobile <addr>` opens the `mobile_*` endpoint phones talk to: it serves
//! each commit as the `Decide` a fleet member would verify, and collects the
//! verification receipts phones send back. It has no TLS, auth, or rate limiting
//! — put it behind something that does before exposing it.
//!
//! The BLS key must be the one at `--index` in `validators.json`; the node
//! checks this at startup, because a mismatch turns it into a silent observer:
//! the engine finds no local key in the set, so it never votes, never proposes,
//! and never broadcasts a timeout, while looking connected and healthy.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::{JwtSecret, PayloadAttributes};
use n42_h2_consensus::{ConsensusEngine, EngineOutput, ValidatorInfo, ValidatorSet};
use n42_h2_el_rpc::{EngineApiClient, HttpTransport};
use n42_h2_execution::{ExecutionDriver, ExecutionLayer};
use n42_h2_net::{H2V4Transport, TransportConfig};
use n42_h2_node::{ConsensusStore, H2Service, ServiceEvent};
use n42_h2_primitives::bls::BlsSecretKey;
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use n42_mobile_service::MobileService;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut chain_path: Option<String> = None;
    let mut chain_id: Option<u64> = None;
    let mut genesis: Option<B256> = None;
    let mut validators_path: Option<String> = None;
    let mut index: Option<u32> = None;
    let mut bls_key: Option<String> = None;
    let mut el_url: Option<String> = None;
    let mut el_rpc: Option<String> = None;
    let mut jwt_path: Option<String> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut listen: Vec<String> = Vec::new();
    let mut fault_tolerance: Option<u32> = None;
    let mut propose = false;
    let mut mobile_addr: Option<String> = None;
    let mut datadir: Option<String> = None;
    let mut base_timeout_ms: Option<u64> = None;
    let mut max_timeout_ms: Option<u64> = None;
    let mut period_secs: u64 = 1;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chain" => chain_path = Some(args.next().ok_or("--chain needs a genesis path")?),
            "--chain-id" => chain_id = Some(args.next().ok_or("--chain-id needs a value")?.parse()?),
            "--genesis" => {
                let raw = args.next().ok_or("--genesis needs a value")?;
                genesis = Some(raw.trim_start_matches("0x").parse()?);
            }
            "--validators" => {
                validators_path = Some(args.next().ok_or("--validators needs a path")?)
            }
            "--index" => index = Some(args.next().ok_or("--index needs a value")?.parse()?),
            "--bls-key" => bls_key = Some(args.next().ok_or("--bls-key needs a value")?),
            "--el" => el_url = Some(args.next().ok_or("--el needs a URL")?),
            "--el-rpc" => el_rpc = Some(args.next().ok_or("--el-rpc needs a URL")?),
            "--jwt" => jwt_path = Some(args.next().ok_or("--jwt needs a path")?),
            "--peer" => peers.push(args.next().ok_or("--peer needs a multiaddr")?),
            "--listen" => listen.push(args.next().ok_or("--listen needs a multiaddr")?),
            "--fault-tolerance" => {
                fault_tolerance =
                    Some(args.next().ok_or("--fault-tolerance needs a value")?.parse()?)
            }
            "--timeout-ms" => {
                base_timeout_ms = Some(args.next().ok_or("--timeout-ms needs a value")?.parse()?)
            }
            "--datadir" => datadir = Some(args.next().ok_or("--datadir needs a path")?),
            "--mobile" => mobile_addr = Some(args.next().ok_or("--mobile needs an address")?),
            "--propose" => propose = true,
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}").into()),
        }
    }

    // Everything about the fleet from one file, when there is one.
    let mut hotstuff_config: Option<n42_qmdb_reth::HotStuffGenesisConfig> = None;
    let (identity, validators): (H2V4ChainIdentity, Vec<ValidatorInfo>) = match &chain_path {
        Some(path) => {
            use reth_cli::chainspec::ChainSpecParser as _;
            let spec = n42_qmdb_reth::N42ChainSpecParser::parse(path)?;
            let hotstuff = n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(&spec.genesis)?;
            base_timeout_ms.get_or_insert(hotstuff.base_timeout);
            max_timeout_ms.get_or_insert(hotstuff.max_timeout);
            period_secs = hotstuff.period.max(1);
            hotstuff_config = Some(hotstuff.clone());
            (
                H2V4ChainIdentity {
                    chain_id: chain_id.unwrap_or_else(|| spec.chain().id()),
                    genesis_hash: genesis.unwrap_or_else(|| spec.genesis_hash()),
                },
                hotstuff.validator_set()?,
            )
        }
        None => (
            H2V4ChainIdentity {
                chain_id: chain_id.ok_or("--chain-id is required without --chain")?,
                genesis_hash: genesis.ok_or("--genesis is required without --chain")?,
            },
            serde_json::from_str(&std::fs::read_to_string(
                validators_path.ok_or("--validators is required without --chain")?,
            )?)?,
        ),
    };
    let base_timeout_ms = base_timeout_ms.unwrap_or(4_000);
    let max_timeout_ms = max_timeout_ms.unwrap_or(base_timeout_ms * 4);
    if validators.is_empty() {
        return Err("validator list is empty".into());
    }
    let index = index.ok_or("--index is required")?;
    let entry = validators
        .get(index as usize)
        .ok_or_else(|| format!("--index {index} is past the end of a {}-validator set", validators.len()))?;

    let key_hex = bls_key.ok_or("--bls-key is required")?;
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| "--bls-key must be 32 bytes")?;
    let secret_key = BlsSecretKey::from_bytes(&key_bytes)?;

    // Checked here rather than left to fail silently: an engine that cannot find
    // its own key in the set runs as an observer, and nothing about a node in
    // that state looks wrong from the outside.
    // A genesis that names a hotstuff validator set is a gov5-profile chain:
    // blocks carry the view and a BLS seal in their extra data. The same key
    // that votes signs the seal.
    let gov5_profile = chain_path.is_some();
    let seal_key = secret_key.clone();
    if secret_key.public_key() != entry.bls_public_key {
        return Err(format!(
            "--bls-key does not match validator {index} in the set; this node would run as a \
             silent observer: connected, counted against quorum, never voting"
        )
        .into());
    }

    let f = fault_tolerance.unwrap_or_else(|| (validators.len() as u32).saturating_sub(1) / 3);
    let validator_set = ValidatorSet::try_new(&validators, f)?;
    let validator_count = validators.len();

    let mut config = TransportConfig::new(identity);
    config.idle_connection_timeout = Duration::from_secs(600);
    for addr in &peers {
        config = config.with_peer(addr.parse()?);
    }
    for addr in &listen {
        config = config.with_listen_addr(addr.parse()?);
    }
    if peers.is_empty() && listen.is_empty() {
        return Err("give at least one --peer to dial or one --listen address".into());
    }

    let el_url: url::Url = el_url.ok_or("--el is required")?.parse()?;
    let jwt = JwtSecret::from_file(Path::new(&jwt_path.ok_or("--jwt is required")?))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let transport = H2V4Transport::new(config)?;
        println!("node peer id : {}", transport.local_peer_id());
        println!("chain        : id {} genesis {}", identity.chain_id, identity.genesis_hash);
        println!("validator    : index {index} of {validator_count} (f = {f})");
        println!("execution    : {el_url}");
        println!("proposing    : {}", if propose { "yes" } else { "no (votes only)" });

        // Phones verify the Decide, not this node's word for it, so the endpoint
        // needs the chain identity the envelopes are bound to.
        let mobile = mobile_addr.as_ref().map(|addr| {
            let service = Arc::new(Mutex::new(MobileService::new(identity, 1)));
            let served = Arc::clone(&service);
            let bind_to = addr.clone();
            std::thread::spawn(move || {
                if let Err(error) = n42_mobile_service::serve(bind_to.as_str(), served) {
                    eprintln!("mobile endpoint stopped: {error}");
                }
            });
            println!("mobile       : {addr}");
            service
        });

        let (output_tx, output_rx) = tokio::sync::mpsc::channel::<EngineOutput>(256);
        let store = datadir
            .as_ref()
            .map(ConsensusStore::open)
            .transpose()?;
        // The execution layer's head has to be recovered alongside the view. A
        // node that resumes consensus at view N but points its driver at genesis
        // sends a forkchoiceUpdated for a block thousands behind, and a live
        // execution layer answers "-38006 Too deep reorg" for every proposal it
        // then tries to build. The last committed QC names the block that was
        // head when the checkpoint was written.
        let mut recovered_head = None;
        let mut engine = match &store {
            None => {
                println!("state        : in memory only (do not restart into a live fleet)");
                ConsensusEngine::new(
                    index,
                    secret_key,
                    validator_set,
                    base_timeout_ms,
                    max_timeout_ms,
                    output_tx,
                )
            }
            Some(store) => {
                // The vote log goes in whether or not there is anything to
                // recover: it has to be durable before the first signature, not
                // after the first restart.
                let vote_log: Arc<dyn n42_h2_consensus::VoteLogWriter> =
                    Arc::new(store.vote_log()?);
                let epochs = n42_h2_consensus::EpochManager::new(validator_set);
                match store.load()? {
                    None => {
                        println!("state        : {}, fresh", datadir.as_deref().unwrap_or("."));
                        ConsensusEngine::with_epoch_manager_and_vote_log(
                            index,
                            secret_key,
                            epochs,
                            base_timeout_ms,
                            max_timeout_ms,
                            output_tx,
                            vote_log,
                        )
                    }
                    Some(recovered) => {
                        println!(
                            "state        : resuming at view {} (last voted {})",
                            recovered.view, recovered.last_voted_view,
                        );
                        if recovered.last_committed_qc.view > 0 {
                            recovered_head = Some(recovered.last_committed_qc.block_hash);
                            println!(
                                "head         : {}",
                                recovered.last_committed_qc.block_hash,
                            );
                        }
                        ConsensusEngine::with_recovered_state_and_vote_log(
                            index,
                            secret_key,
                            epochs,
                            base_timeout_ms,
                            max_timeout_ms,
                            output_tx,
                            recovered.view,
                            recovered.locked_qc,
                            recovered.last_committed_qc,
                            recovered.consecutive_timeouts,
                            recovered.last_voted_view,
                            recovered.last_commit_voted_view,
                            vote_log,
                        )
                    }
                }
            }
        };
        // Without this the node signs under the native profile and every fleet
        // member rejects its votes.
        engine.enable_h2_v4_signing(identity);

        let el = EngineApiClient::new(HttpTransport::new(el_url, jwt, Duration::from_secs(8))?);
        // The driver starts where the execution layer actually is. The
        // checkpoint's last committed block may be one this node committed on
        // the fleet's certificates while behind, without ever importing it; a
        // driver anchored on a block the execution layer lacks would send
        // every forkchoice to an unknown head.
        let start_head = match recovered_head {
            Some(hash) if el.block_by_hash(hash).await?.is_some() => hash,
            Some(hash) => {
                let latest = el.latest_block_number().await?.unwrap_or(0);
                let head = el
                    .block_by_number(latest)
                    .await?
                    .map(|block| block.header.hash_slow())
                    .unwrap_or(identity.genesis_hash);
                println!("execution    : at {latest} ({head:#x}), not at the checkpoint's {hash:#x}; starting from the execution layer");
                head
            }
            None => identity.genesis_hash,
        };
        let driver = ExecutionDriver::new(el, start_head);

        let mut service = H2Service::new(transport, engine, driver, output_rx, validator_count);
        if let Some(store) = store {
            // Inside the service, not on the event it emits: the checkpoint has
            // to be durable before the commit reaches the execution layer, and
            // by the time an event is handed back here the forkchoice has
            // already gone out.
            service = service.with_checkpoint(move |engine| {
                store
                    .save(&n42_h2_node::persistence::checkpoint_from(engine))
                    .map_err(|error| error.to_string())
            });
        }
        if gov5_profile {
            service = service.with_gov5_h2_profile(seal_key);
        }
        if let Some(rpc) = &el_rpc {
            service = service.with_transaction_source(rpc.parse()?);
            println!("transaction source: {rpc}");
        }
        if propose {
            let fee_recipient = entry.address;
            // The chain's committee pool, if it has one: every header links
            // to the parent's committee evidence through its parent beacon
            // root, and gov5 refuses a block that does not.
            let committee = hotstuff_config
                .as_ref()
                .map(|config| config.committee_pool())
                .transpose()?
                .flatten()
                .map(std::sync::Arc::new);
            if let Some(pool) = &committee {
                println!(
                    "committee pool: {} keys, {} per block",
                    pool.config().pool_size,
                    pool.config().committee_size
                );
            }
            // The chain's per-block rewards, as the withdrawals the execution
            // layer credits; gov5 credits the same amounts in `Finalize`.
            let rewards = hotstuff_config
                .as_ref()
                .map(|config| config.block_rewards(fee_recipient))
                .unwrap_or_default();
            let withdrawals = n42_h2_consensus::rewards_to_withdrawals(&rewards)?;
            if !withdrawals.is_empty() {
                println!("block rewards: {} withdrawal(s) per block", withdrawals.len());
            }
            service = service.with_payload_attributes(move |context| {
                let parent_beacon_block_root = match (&committee, &context.head_header) {
                    (Some(pool), Some(parent)) => {
                        match pool.parent_beacon_root(parent.number, &parent.hash_slow(), &parent.receipts_root) {
                            Ok(root) => root,
                            Err(err) => {
                                eprintln!("committee evidence for the head failed: {err}");
                                return None;
                            }
                        }
                    }
                    // Without the parent's header there is no evidence to
                    // link to; wait until it is known.
                    (Some(_), None) => return None,
                    (None, _) => B256::ZERO,
                };
                block_attributes(
                    fee_recipient,
                    withdrawals.clone(),
                    parent_beacon_block_root,
                    period_secs,
                    context.head_timestamp,
                    context.head_seen,
                )
            });
        }

        println!("running…\n");
        loop {
            for event in service.step().await? {
                match event {
                    ServiceEvent::Committed {
                        view,
                        block_hash,
                        commit_qc,
                    } => {
                        println!("COMMIT view={view} block={block_hash}");
                        if let Some(mobile) = &mobile {
                            let mut guard = mobile
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            // Block number is not carried on the consensus event;
                            // the view is what a phone indexes finality by here.
                            if let Err(error) =
                                guard.record_commit(view, block_hash, view, *commit_qc, None)
                            {
                                eprintln!("could not publish the commit to phones: {error}");
                            }
                        }
                    }
                    ServiceEvent::ViewChanged { new_view } => {
                        println!("view   {new_view}");
                    }
                    ServiceEvent::SyncRequired { local_view, target_view } => {
                        eprintln!("BEHIND local={local_view} fleet={target_view}");
                    }
                    ServiceEvent::BodyReceived { block_hash } => {
                        println!("body         : {block_hash}");
                    }
                    ServiceEvent::PayloadMissing { block_hash } => {
                        eprintln!("NO BODY for {block_hash}; cannot vote on it");
                    }
                    ServiceEvent::Syncing { from, to } => {
                        println!("syncing      : {from} -> {to}");
                    }
                    ServiceEvent::Synced { height, complete } => {
                        println!("synced       : height {height}{}", if complete { "" } else { " (stopped short)" });
                    }
                    ServiceEvent::Published { .. } => {}
                }
            }
        }
    })
}

/// Attributes for a block this node proposes.
///
/// `prev_randao` is zero and the beacon root is zero because HotStuff-2 has no
/// beacon chain supplying them; what matters is that every member computes the
/// same values for the same block, and a constant satisfies that.
///
/// Returns `None` when it is too soon to propose again. An Engine API timestamp
/// is a whole second and each block's must exceed its parent's, while HotStuff-2
/// commits in tens of milliseconds — so a leader that proposes every view either
/// repeats a second (the execution layer never finishes the build and
/// `getPayload` blocks until the view times out) or runs the chain's clock into
/// the future (the execution layer rejects the block outright). Both were
/// observed on a live node. Declining in between paces the chain at roughly one
/// block per second, which is what the timestamp resolution allows.
fn block_attributes(
    fee_recipient: Address,
    withdrawals: Vec<alloy_eips::eip4895::Withdrawal>,
    parent_beacon_block_root: B256,
    period_secs: u64,
    head_timestamp: Option<u64>,
    head_seen: Option<std::time::Instant>,
) -> Option<PayloadAttributes> {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // Two clocks constrain a block's timestamp, and they are not the same
    // clock. The stamp is the wall clock — gov5 ignores any gossiped block
    // whose timestamp is ahead of its own clock, with no tolerance — and it
    // must exceed the parent's, which for a Go parent is `parent + period`
    // stamped however early the Go leader proposed (`hotstuff/adapter.go`
    // `Prepare`): after a Go block this node waits for the clock to pass the
    // parent's stamp. Pacing, meanwhile, is `period` after the parent was
    // *seen* here, by this node's clock, not after the parent's stamp: waiting
    // for the clock to reach `parent + period` after a Go block that is
    // already a period ahead lost every such view to the timeout (measured).
    // Without the parent (a restart, a head this node never saw the body of),
    // pace against this node's own last proposal.
    match (head_timestamp, head_seen) {
        (Some(parent), seen) => {
            if now <= parent {
                return None;
            }
            if seen.is_some_and(|seen| seen.elapsed().as_secs() < period_secs) {
                return None;
            }
        }
        (None, _) => {
            if now < LAST.load(Ordering::Relaxed).saturating_add(period_secs) {
                return None;
            }
        }
    }
    let timestamp = now;
    if LAST.fetch_max(timestamp, Ordering::Relaxed) >= timestamp {
        // Already proposed in this second.
        return None;
    }
    Some(PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: fee_recipient,
        withdrawals: Some(withdrawals),
        parent_beacon_block_root: Some(parent_beacon_block_root),
        target_gas_limit: None,
        slot_number: None,
    })
}

const USAGE: &str = "\
h2_validator — run a participating HotStuff-2 v4 node against an execution layer

  --chain <genesis.json>    the chain's genesis; supplies id, hash, validators, timeouts, period
  --el-rpc <url>            the execution layer's public JSON-RPC; its pool's transactions are gossiped to the fleet
  --chain-id <u64>          fleet chain id (without --chain)
  --genesis <0x…>           fleet genesis hash (without --chain)
  --validators <path>       JSON array of {address, bls_public_key} (without --chain)
  --index <u32>             this node's position in that array
  --bls-key <0x…>           this node's BLS secret key (32 bytes)
  --el <url>                Engine API auth endpoint (reth --authrpc.port, 8551)
  --jwt <path>              the execution layer's JWT secret file
  --peer <multiaddr>        fleet member to dial (repeatable)
  --listen <multiaddr>      address to listen on (repeatable)
  --propose                 build blocks when leader (default: vote only)
  --mobile <addr>           serve the mobile_* endpoint here (e.g. 127.0.0.1:9545)
  --datadir <path>          persist consensus state here (required to restart safely)
  --fault-tolerance <u32>   override f; defaults to (n-1)/3
  --timeout-ms <u64>        base view timeout (default: genesis hotstuff.baseTimeout, else 4000)
";

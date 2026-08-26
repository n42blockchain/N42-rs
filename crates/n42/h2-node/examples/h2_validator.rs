// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Run a participating HotStuff-2 v4 node against a real execution layer.
//!
//! This is the whole stack assembled: gossip transport, consensus engine, and an
//! Engine API client driving an execution client. Unlike `h2_observer`, it votes.
//!
//! ```text
//! cargo run -p n42-h2-node --example h2_validator -- \
//!     --chain-id 94 \
//!     --genesis 0x<genesis hash> \
//!     --validators validators.json \
//!     --index 0 \
//!     --bls-key 0x<64 hex chars> \
//!     --el http://127.0.0.1:8551 \
//!     --jwt /path/to/jwt.hex \
//!     --peer /ip4/127.0.0.1/tcp/32100/p2p/<peer id> \
//!     --listen /ip4/0.0.0.0/tcp/32200 \
//!     --propose
//! ```
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
use n42_h2_execution::ExecutionDriver;
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

    let mut chain_id: Option<u64> = None;
    let mut genesis: Option<B256> = None;
    let mut validators_path: Option<String> = None;
    let mut index: Option<u32> = None;
    let mut bls_key: Option<String> = None;
    let mut el_url: Option<String> = None;
    let mut jwt_path: Option<String> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut listen: Vec<String> = Vec::new();
    let mut fault_tolerance: Option<u32> = None;
    let mut propose = false;
    let mut mobile_addr: Option<String> = None;
    let mut datadir: Option<String> = None;
    let mut base_timeout_ms: u64 = 4_000;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
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
            "--jwt" => jwt_path = Some(args.next().ok_or("--jwt needs a path")?),
            "--peer" => peers.push(args.next().ok_or("--peer needs a multiaddr")?),
            "--listen" => listen.push(args.next().ok_or("--listen needs a multiaddr")?),
            "--fault-tolerance" => {
                fault_tolerance =
                    Some(args.next().ok_or("--fault-tolerance needs a value")?.parse()?)
            }
            "--timeout-ms" => {
                base_timeout_ms = args.next().ok_or("--timeout-ms needs a value")?.parse()?
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

    let identity = H2V4ChainIdentity {
        chain_id: chain_id.ok_or("--chain-id is required")?,
        genesis_hash: genesis.ok_or("--genesis is required")?,
    };
    let validators: Vec<ValidatorInfo> = serde_json::from_str(&std::fs::read_to_string(
        validators_path.ok_or("--validators is required")?,
    )?)?;
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
                    base_timeout_ms * 4,
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
                            base_timeout_ms * 4,
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
                            base_timeout_ms * 4,
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
        let driver = ExecutionDriver::new(el, recovered_head.unwrap_or(identity.genesis_hash));

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
        if propose {
            let fee_recipient = entry.address;
            service = service.with_payload_attributes(move |_view, _head| {
                block_attributes(fee_recipient)
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
                    ServiceEvent::PayloadMissing { block_hash } => {
                        eprintln!("NO BODY for {block_hash}; cannot vote on it");
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
fn block_attributes(fee_recipient: Address) -> Option<PayloadAttributes> {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // Claim this second, or decline if it is already taken.
    let timestamp = LAST
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            (now > last).then_some(now)
        })
        .ok()
        .map(|_| now)?;
    Some(PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: fee_recipient,
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        target_gas_limit: None,
        slot_number: None,
    })
}

const USAGE: &str = "\
h2_validator — run a participating HotStuff-2 v4 node against an execution layer

  --chain-id <u64>          fleet chain id (e.g. 94 for mainnet_qmdb_staggered)
  --genesis <0x…>           fleet genesis hash
  --validators <path>       JSON array of {address, bls_public_key}
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
  --timeout-ms <u64>        base view timeout (default 4000)
";

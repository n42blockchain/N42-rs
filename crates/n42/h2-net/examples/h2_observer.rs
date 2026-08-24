// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attach to a gov5 HotStuff-2 v4 fleet and print verified finality.
//!
//! ```text
//! cargo run -p n42-h2-net --example h2_observer -- \
//!     --chain-id 94 \
//!     --genesis 0x<genesis hash> \
//!     --validators validators.json \
//!     --peer /ip4/127.0.0.1/tcp/32100/p2p/<peer id> \
//!     --peer /ip4/127.0.0.1/tcp/32101/p2p/<peer id>
//! ```
//!
//! `validators.json` is the fleet's ordered validator list — the same order the
//! chainspec uses, because the commit bitmap indexes into it:
//!
//! ```json
//! [{"address":"0x…","bls_public_key":"0x<96 hex chars>"}, …]
//! ```
//!
//! This observer never publishes. It joins the mesh, verifies, and reports.

use std::time::Duration;

use alloy_primitives::B256;
use n42_h2_consensus::{ValidatorInfo, ValidatorSet};
use n42_h2_net::{H2V4Observer, ObserverConfig, ObserverEvent};
use n42_h2_primitives::consensus::H2V4ChainIdentity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // RUST_LOG=libp2p_gossipsub=debug,libp2p_swarm=debug is the setting that
    // actually explains a peer that connects and immediately drops.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut chain_id: Option<u64> = None;
    let mut genesis: Option<B256> = None;
    let mut validators_path: Option<String> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut listen: Vec<String> = Vec::new();
    let mut fault_tolerance: Option<u32> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chain-id" => chain_id = Some(args.next().ok_or("--chain-id needs a value")?.parse()?),
            "--genesis" => {
                let raw = args.next().ok_or("--genesis needs a value")?;
                genesis = Some(raw.trim_start_matches("0x").parse()?);
            }
            "--validators" => validators_path = Some(args.next().ok_or("--validators needs a path")?),
            "--peer" => peers.push(args.next().ok_or("--peer needs a multiaddr")?),
            "--listen" => listen.push(args.next().ok_or("--listen needs a multiaddr")?),
            "--fault-tolerance" => {
                fault_tolerance = Some(args.next().ok_or("--fault-tolerance needs a value")?.parse()?)
            }
            "--help" | "-h" => {
                eprintln!("{}", USAGE);
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}").into()),
        }
    }

    let identity = H2V4ChainIdentity {
        chain_id: chain_id.ok_or("--chain-id is required")?,
        genesis_hash: genesis.ok_or("--genesis is required")?,
    };
    let path = validators_path.ok_or("--validators is required")?;
    let validators: Vec<ValidatorInfo> = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    if validators.is_empty() {
        return Err("validator list is empty".into());
    }

    // Default to the largest f the set can carry: f = (n-1)/3.
    let f = fault_tolerance.unwrap_or_else(|| (validators.len() as u32).saturating_sub(1) / 3);
    let validator_set = ValidatorSet::try_new(&validators, f)?;

    let mut config = ObserverConfig::new(identity);
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

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let mut observer = H2V4Observer::new(config, validator_set)?;
        println!("observer peer id : {}", observer.local_peer_id());
        println!("chain            : id {} genesis {}", identity.chain_id, identity.genesis_hash);
        println!("validators       : {} (f = {f}, quorum {})", validators.len(), 2 * f as usize + 1);
        println!("topic            : {}", n42_h2_net::H2_V4_TOPIC);
        println!("waiting for finality…\n");

        while let Some(event) = observer.next_event().await {
            match event {
                ObserverEvent::Finality { view, block_hash, from, .. } => {
                    let source = from.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                    println!("FINAL view={view} block={block_hash} from={source}");
                }
                ObserverEvent::Rejected { from, reason } => {
                    let source = from.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                    eprintln!("REJECT from={source}: {reason}");
                }
                ObserverEvent::NonDecide { .. } => {}
                ObserverEvent::Subscribed => println!("subscribed to the v4 topic"),
                ObserverEvent::PeerConnected(peer) => println!("peer up   {peer}"),
                ObserverEvent::StatusExchanged { peer, genesis_hash, height, fork_matches } => {
                    let verdict = if fork_matches { "fork OK" } else { "FORK MISMATCH" };
                    println!("status    {peer} genesis={genesis_hash} height={height} [{verdict}]");
                }
                ObserverEvent::PeerDisconnected(peer) => println!("peer down {peer}"),
                ObserverEvent::Listening(addr) => println!("listening {addr}"),
                ObserverEvent::DialFailed { peer, reason } => {
                    let target = peer.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                    eprintln!("DIAL FAILED {target}: {reason}");
                }
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

const USAGE: &str = "\
h2_observer — follow a gov5 HotStuff-2 v4 fleet's finality (read-only)

  --chain-id <u64>          fleet chain id (e.g. 94 for mainnet_qmdb_staggered)
  --genesis <0x…>           fleet genesis hash
  --validators <path>       JSON array of {address, bls_public_key}
  --peer <multiaddr>        fleet member to dial (repeatable)
  --listen <multiaddr>      address to listen on (repeatable)
  --fault-tolerance <u32>   override f; defaults to (n-1)/3
";

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's chain description, as a genesis this node loads.
//!
//! gov5 keeps a chain in three places: a chainspec JSON that is the chain
//! config alone (`params/chainspecs/<chain>.json`), an allocation JSON with
//! decimal balances and base64 code (`internal/allocs/<chain>.json`), and a
//! Go function with the genesis block's own fields (`internal/genesis_block.go`
//! — timestamp, nonce, difficulty, gas limit). This tool folds the three into
//! one reth-style genesis JSON and then loads it the way the node does, so the
//! resulting genesis hash is checked on the spot — the hash is the chain's
//! identity on the wire (the fork digest is its first four bytes), and a
//! conversion that changes it would join nothing.
//!
//! Two fork spellings differ. gov5 activates Shanghai and Cancun by block
//! number; reth knows them only by timestamp, so `--fork-time shanghai=<ts>`
//! (the timestamp of that block, which makes the two schedules equivalent on
//! a chain whose timestamps only ever grow) becomes `shanghaiTime`. gov5's
//! `pectraTime` is reth's `pragueTime`. gov5's own forks (`eofTime`,
//! `ltHashTime`, `mobileAnchorTime`, `glamsterdamTime`, `beijingBlock`) have no
//! reth spelling and are carried through untouched, where they change nothing.

use clap::Parser;
use eyre::{bail, Context as _};
use reth_cli::chainspec::ChainSpecParser as _;
use serde_json::{json, Map, Value};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "n42-gov5-genesis", about = "Fold gov5's chainspec, alloc and genesis block into a reth genesis")]
struct Cli {
    /// gov5 `params/chainspecs/<chain>.json`.
    #[arg(long)]
    chainspec: PathBuf,
    /// gov5 `internal/allocs/<chain>.json`.
    #[arg(long)]
    alloc: PathBuf,
    /// The genesis block's timestamp (`internal/genesis_block.go`).
    #[arg(long)]
    timestamp: u64,
    /// The genesis block's difficulty; gov5's default is 131072, its newer
    /// HotStuff chains use 0.
    #[arg(long, default_value_t = 131_072)]
    difficulty: u64,
    /// The genesis block's gas limit; gov5's `params.GenesisGasLimit`.
    #[arg(long, default_value_t = 4_712_388)]
    gas_limit: u64,
    /// The genesis block's nonce.
    #[arg(long, default_value_t = 0)]
    nonce: u64,
    /// The genesis block's extra data, hex.
    #[arg(long, default_value = "0x")]
    extra_data: String,
    /// A block-number fork's activation timestamp, `shanghai=<ts>` or
    /// `cancun=<ts>`: the timestamp of the block gov5 names.
    #[arg(long = "fork-time", value_name = "FORK=TS")]
    fork_times: Vec<String>,
    /// Where the genesis JSON goes.
    #[arg(long)]
    out: PathBuf,
    /// The genesis hash gov5 computes (`params/config.go`); the conversion
    /// fails unless the loaded genesis hashes to it.
    #[arg(long)]
    expect_hash: Option<alloy_primitives::B256>,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let mut config: Map<String, Value> = serde_json::from_slice(&std::fs::read(&cli.chainspec)?)
        .wrap_err("chainspec is not a JSON object")?;
    let alloc: Map<String, Value> =
        serde_json::from_slice(&std::fs::read(&cli.alloc)?).wrap_err("alloc is not a JSON object")?;

    // Forks gov5 spells by block number that reth spells by timestamp.
    let mut fork_times = std::collections::BTreeMap::new();
    for entry in &cli.fork_times {
        let (fork, ts) = entry
            .split_once('=')
            .ok_or_else(|| eyre::eyre!("--fork-time wants FORK=TS, got {entry}"))?;
        fork_times.insert(fork.to_ascii_lowercase(), ts.parse::<u64>().wrap_err("fork timestamp")?);
    }
    for fork in ["shanghai", "cancun"] {
        let block_key = format!("{fork}Block");
        let time_key = format!("{fork}Time");
        let Some(block) = config.get(&block_key).and_then(Value::as_u64) else { continue };
        if config.get(&time_key).and_then(Value::as_u64).is_some() {
            continue;
        }
        if block == 0 {
            config.insert(time_key, json!(0));
        } else if let Some(ts) = fork_times.get(fork) {
            config.insert(time_key, json!(ts));
        } else {
            eprintln!(
                "warning: {block_key} = {block} has no timestamp; pass --fork-time {fork}=<timestamp of block {block}> or reth will not see the fork"
            );
        }
    }
    if let (Some(pectra), None) = (config.get("pectraTime").cloned(), config.get("pragueTime")) {
        config.insert("pragueTime".into(), pectra);
    }
    // A chain that never had proof of work: reth needs the merge to have
    // happened at genesis to run it as one.
    config.entry("terminalTotalDifficulty").or_insert(json!(0));
    config.entry("terminalTotalDifficultyPassed").or_insert(json!(true));
    config.entry("mergeNetsplitBlock").or_insert(json!(0));

    // The allocation: decimal balances and base64 code become hex.
    let mut converted = Map::new();
    for (address, account) in &alloc {
        let account = account.as_object().ok_or_else(|| eyre::eyre!("alloc entry {address} is not an object"))?;
        let mut out = Map::new();
        let balance = account.get("balance").and_then(Value::as_str).unwrap_or("0");
        let balance: alloy_primitives::U256 = balance.parse().wrap_err_with(|| format!("balance of {address}"))?;
        out.insert("balance".into(), json!(format!("{balance:#x}")));
        match account.get("nonce") {
            Some(Value::String(s)) => {
                out.insert("nonce".into(), json!(format!("{:#x}", s.parse::<u64>().wrap_err("nonce")?)));
            }
            Some(Value::Number(n)) => {
                out.insert("nonce".into(), json!(format!("{:#x}", n.as_u64().unwrap_or_default())));
            }
            _ => {}
        }
        if let Some(code) = account.get("code").and_then(Value::as_str) {
            let bytes = base64_decode(code).wrap_err_with(|| format!("code of {address}"))?;
            out.insert("code".into(), json!(format!("0x{}", alloy_primitives::hex::encode(bytes))));
        }
        if let Some(storage) = account.get("storage") {
            out.insert("storage".into(), storage.clone());
        }
        converted.insert(address.to_ascii_lowercase(), Value::Object(out));
    }

    let genesis = json!({
        "config": config,
        "nonce": format!("{:#x}", cli.nonce),
        "timestamp": format!("{:#x}", cli.timestamp),
        "extraData": cli.extra_data,
        "gasLimit": format!("{:#x}", cli.gas_limit),
        "difficulty": format!("{:#x}", cli.difficulty),
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": converted,
    });
    std::fs::write(&cli.out, serde_json::to_vec_pretty(&genesis)?)?;

    // Load it the way the node does, and say what chain it is.
    let spec = n42_qmdb_reth::N42ChainSpecParser::parse(&cli.out.to_string_lossy())?;
    let hash = spec.genesis_hash();
    println!("chain {} genesis {hash} state root {}", spec.chain().id(), spec.genesis_header().state_root);
    println!("fork digest {}", alloy_primitives::hex::encode(&hash.as_slice()[..4]));
    if let Some(expected) = cli.expect_hash
        && expected != hash
    {
        bail!("genesis hash {hash} is not gov5's {expected}: the conversion does not describe the same chain");
    }
    println!("written {}", cli.out.display());
    Ok(())
}

/// Standard base64 with padding, as Go's `encoding/json` writes `[]byte`.
fn base64_decode(text: &str) -> eyre::Result<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |c: u8| ALPHABET.iter().position(|a| *a == c).map(|v| v as u32);
    let bytes: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        let mut n = 0;
        for &c in chunk {
            if c == b'=' {
                break;
            }
            acc = (acc << 6) | value(c).ok_or_else(|| eyre::eyre!("invalid base64 byte {c:#x}"))?;
            n += 1;
        }
        match n {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
            2 => out.push((acc >> 4) as u8),
            _ => bail!("truncated base64"),
        }
    }
    Ok(out)
}

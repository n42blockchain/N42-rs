// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The MobileAnchor gate end to end: a real execution layer, four real
//! validators, the JSON Engine API between them.
//!
//! Every layer of the gate had unit tests, and the gate still failed on the
//! devnet four times over (2026-11-02): the builder rebuilt the sealed header
//! without the slot and the root, the pre-Amsterdam `getPayload` envelope had
//! no field for them, `newPayloadV5` refused a slot before reth's Amsterdam,
//! and the engine tree tried to decode the empty access list the tail travels
//! with. Each was found one devnet run at a time. This runs the same shape as
//! `scripts/devnet-fleet.sh` -- the `n42` binary on
//! `n42_devnet_mobileanchor.json` and four `h2_validator`s with
//! `--mobileverify.http` -- and asserts what the devnet is for: blocks commit,
//! and every header carries the slot and a `mobileRegistryRoot`.
//!
//! It needs the `n42` binary and the `h2_validator` example built in the same
//! target directory (`N42_BIN` overrides the first), so it is ignored by
//! default:
//!
//! ```text
//! cargo build -p n42 && cargo build -p n42-h2-node --example h2_validator
//! cargo test -p n42-h2-node --test mobile_anchor_gate -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Every port is an ephemeral one the kernel hands out (never the devnet
//! script's fixed 18545/18551/19000+/2101x/30313), and the fleet's processes
//! and directory (under the target directory, not the RAM-backed /tmp) go on
//! every exit path, a failed assertion included: they are owned by a value
//! whose `Drop` kills and reaps them. `N42_GATE_KEEP=1` keeps the directory
//! (logs) for a post-mortem.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use alloy_rlp::Decodable as _;
use n42_h2_consensus::N42Header;
use n42_h2_el_rpc::{HttpTransport, JsonRpcTransport};
use serde_json::{json, Value};

/// The workspace root, two levels above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `<target>/<profile>`: the test binary lives in its `deps/`.
fn profile_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("test binary path");
    exe.parent().and_then(Path::parent).expect("target profile directory").to_path_buf()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

/// A scratch directory under the target directory (not /tmp, which is RAM on
/// the bench host), removed on drop with every child still running killed.
struct Fleet {
    dir: PathBuf,
    children: Vec<(String, Child)>,
}

impl Fleet {
    fn new(name: &str) -> Self {
        let dir = profile_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self { dir, children: Vec::new() }
    }

    fn spawn(&mut self, label: &str, mut command: Command) {
        let log = std::fs::File::create(self.dir.join(format!("{label}.log"))).expect("log file");
        let child = command
            .stdout(log.try_clone().expect("log"))
            .stderr(log)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        self.children.push((label.to_owned(), child));
    }

    fn log(&self, label: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{label}.log"))).unwrap_or_default()
    }

    /// The last lines of every log, for a failure message.
    fn tails(&self) -> String {
        let mut out = String::new();
        for (label, _) in &self.children {
            let log = self.log(label);
            let lines: Vec<&str> = log.lines().collect();
            out.push_str(&format!("---- {label} ----\n"));
            for line in &lines[lines.len().saturating_sub(15)..] {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        if std::env::var_os("N42_GATE_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// The dev validators' BLS secrets, published in the repository (dev only).
fn validator_keys() -> Vec<String> {
    let path = repo().join("crates/chainspec/res/genesis/n42_devnet_validators.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("validators file")).expect("json");
    file["validators"]
        .as_array()
        .expect("validators")
        .iter()
        .map(|v| v["bls_secret_key"].as_str().expect("secret").to_owned())
        .collect()
}

/// Starts the execution layer and four validators on `genesis`; `mobileverify`
/// gives every validator the phone surface (and with it a registry root).
async fn start(name: &str, mobileverify: bool) -> (Fleet, HttpTransport) {
    let n42 = std::env::var_os("N42_BIN").map_or_else(|| profile_dir().join("n42"), PathBuf::from);
    let validator = profile_dir().join("examples/h2_validator");
    assert!(n42.exists(), "{} is missing: cargo build -p n42 (or set N42_BIN)", n42.display());
    assert!(validator.exists(), "{} is missing: cargo test builds it", validator.display());
    let genesis = repo().join("crates/chainspec/res/genesis/n42_devnet_mobileanchor.json");

    let mut fleet = Fleet::new(name);
    let jwt_hex = "4242424242424242424242424242424242424242424242424242424242424242";
    let jwt = fleet.dir.join("jwt.hex");
    std::fs::write(&jwt, jwt_hex).expect("jwt");
    let (auth, http, p2p) = (free_port(), free_port(), free_port());

    let mut el = Command::new(&n42);
    el.args(["node", "--chain"])
        .arg(&genesis)
        .arg("--datadir")
        .arg(fleet.dir.join("datadir"))
        .args(["--authrpc.port", &auth.to_string(), "--authrpc.jwtsecret"])
        .arg(&jwt)
        .args(["--http", "--http.port", &http.to_string(), "--http.api", "eth,net,web3,debug"])
        .args(["--port", &p2p.to_string(), "--disable-discovery", "--ipcdisable"])
        .env("RUST_LOG", "info");
    fleet.spawn("el", el);
    let deadline = Instant::now() + Duration::from_secs(120);
    while !fleet.log("el").contains("RPC auth server started") {
        assert!(Instant::now() < deadline, "the execution layer never started\n{}", fleet.tails());
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let mut peer: Option<String> = None;
    for (index, key) in validator_keys().iter().enumerate() {
        let listen = free_port();
        let mut command = Command::new(&validator);
        command
            .arg("--chain")
            .arg(&genesis)
            .args(["--index", &index.to_string(), "--bls-key", key])
            .args(["--el", &format!("http://127.0.0.1:{auth}"), "--el-rpc", &format!("http://127.0.0.1:{http}")])
            .arg("--jwt")
            .arg(&jwt)
            .args(["--listen", &format!("/ip4/127.0.0.1/tcp/{listen}"), "--propose", "--datadir"])
            .arg(fleet.dir.join(format!("consensus-{index}")))
            .env("RUST_LOG", "n42=debug");
        if mobileverify {
            command.args(["--mobileverify.http", &format!("127.0.0.1:{}", free_port())]);
        }
        if let Some(peer) = &peer {
            command.args(["--peer", peer]);
        }
        let label = format!("v{index}");
        fleet.spawn(&label, command);
        if index == 0 {
            let deadline = Instant::now() + Duration::from_secs(60);
            let id = loop {
                if let Some(line) = fleet.log(&label).lines().find(|line| line.contains("node peer id")) {
                    break line.split_whitespace().last().expect("peer id").to_owned();
                }
                assert!(Instant::now() < deadline, "validator 0 never printed its peer id\n{}", fleet.tails());
                tokio::time::sleep(Duration::from_millis(250)).await;
            };
            peer = Some(format!("/ip4/127.0.0.1/tcp/{listen}/p2p/{id}"));
        }
    }

    let jwt = alloy_rpc_types_engine::JwtSecret::from_hex(jwt_hex).expect("jwt");
    let rpc = HttpTransport::new(format!("http://127.0.0.1:{http}").parse().expect("url"), jwt, Duration::from_secs(5))
        .expect("transport");
    (fleet, rpc)
}

async fn block_number(rpc: &HttpTransport) -> u64 {
    match rpc.call("eth_blockNumber", vec![]).await {
        Ok(Value::String(hex)) => u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0),
        _ => 0,
    }
}

async fn header(rpc: &HttpTransport, number: u64) -> N42Header {
    let raw = rpc.call("debug_getRawHeader", vec![json!(format!("0x{number:x}"))]).await.expect("raw header");
    let bytes = alloy_primitives::hex::decode(raw.as_str().expect("hex")).expect("hex bytes");
    N42Header::decode(&mut bytes.as_slice()).expect("an N42 header")
}

/// Polls until the chain is at `target` or the budget runs out; returns the height.
async fn wait_for_height(rpc: &HttpTransport, target: u64, budget: Duration) -> u64 {
    let deadline = Instant::now() + budget;
    loop {
        let height = block_number(rpc).await;
        if height >= target || Instant::now() >= deadline {
            return height;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the n42 binary: cargo build -p n42, then --ignored"]
async fn a_gated_fleet_commits_and_every_header_names_a_registry_root() {
    let (fleet, rpc) = start("mobile-anchor-gate", true).await;
    let height = wait_for_height(&rpc, 4, Duration::from_secs(120)).await;
    assert!(height >= 4, "the gated fleet committed {height} block(s)\n{}", fleet.tails());

    for number in 1..=height {
        let header = header(&rpc, number).await;
        assert_eq!(header.inner.slot_number, Some(number), "block {number}: the slot is the block number");
        // Before the first epoch commit the registry is empty and its root
        // is zero; it is present either way.
        assert!(header.mobile_registry_root.is_some(), "block {number} carries no mobileRegistryRoot\n{}", fleet.tails());
        println!("block {number}: slot {:?} root {:?}", header.inner.slot_number, header.mobile_registry_root);
    }
    // A zero root is the empty registry's, not a default: until something
    // registers, that is the committed root every leader names.
    let root = header(&rpc, 1).await.mobile_registry_root;
    assert_eq!(root, Some(B256::ZERO), "block 1 is built before anything registers");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the n42 binary: cargo build -p n42, then --ignored"]
async fn a_gated_fleet_without_a_registry_builds_nothing() {
    // A leader that names no root cannot build on a chain whose schedule
    // carries one: the builder refuses ("named none") rather than seal a
    // header the fleet would reject.
    let (fleet, rpc) = start("mobile-anchor-ungated", false).await;
    let height = wait_for_height(&rpc, 1, Duration::from_secs(30)).await;
    assert_eq!(height, 0, "a fleet without a registry root committed block {height}");
    let refused = fleet.log("el").contains("named none")
        || (0..4).any(|index| fleet.log(&format!("v{index}")).contains("named none"));
    assert!(refused, "no \"named none\" refusal anywhere\n{}", fleet.tails());
}

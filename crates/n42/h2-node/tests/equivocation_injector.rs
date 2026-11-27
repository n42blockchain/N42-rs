// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The test-only equivocation injector (`n42_h2_node::test_equivocate`,
//! `docs/P1_EQUIVOCATION_INJECTOR.md`) against three honest members.
//!
//! Four `H2Service`s over a real gossip mesh on loopback, as in
//! `four_node_fleet.rs`; member 3 equivocates. For each kind the honest
//! members must prove the fault (a persisted, self-verifying signed pair
//! naming member 3), commit no two different blocks at one view, never
//! commit an injected twin, and keep committing after the injections.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_h2_consensus::protocol::quorum::ConsensusSigningProfile;
use n42_h2_consensus::{ConsensusEngine, EngineOutput, EquivocationEvidence, EquivocationKind, ValidatorInfo, ValidatorSet};
use n42_h2_execution::{ExecutionDriver, MockExecutionLayer};
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent};
use n42_h2_node::equivocations::EquivocationLog;
use n42_h2_node::test_equivocate::TestEquivocation;
use n42_h2_node::{H2Service, ProposalContext, ServiceEvent};
use n42_h2_primitives::bls::BlsSecretKey;
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use tokio::sync::mpsc;

const VALIDATORS: usize = 4;
const EQUIVOCATOR: usize = 3;
/// Commits every honest member must reach past the first injection.
const COMMITS_AFTER: u64 = 4;

const fn identity() -> H2V4ChainIdentity {
    // The dev chain: the injector refuses anything else.
    H2V4ChainIdentity { chain_id: 1143, genesis_hash: B256::repeat_byte(0x42) }
}

fn attributes(context: ProposalContext) -> Option<PayloadAttributes> {
    Some(PayloadAttributes {
        timestamp: 1_700_000_000 + context.view,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        target_gas_limit: None,
        slot_number: None,
        mobile_registry_root: None,
    })
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("equivocation-injector-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The fleet, every member proposing, `EQUIVOCATOR` running `injector`; each
/// member's evidence log in `dir/<index>`.
async fn build_fleet(injector: TestEquivocation, dir: &Path, aggregate: bool) -> Vec<H2Service<MockExecutionLayer>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let keys: Vec<BlsSecretKey> = (0..VALIDATORS).map(|_| BlsSecretKey::random().expect("bls keygen")).collect();
    let infos: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| ValidatorInfo { address: Address::with_last_byte(i as u8 + 1), bls_public_key: key.public_key(), p2p_peer_id: None })
        .collect();
    let set = ValidatorSet::new(&infos, 1);

    let mut nodes = Vec::new();
    let mut first_addr: Option<libp2p::Multiaddr> = None;
    for (index, key) in keys.into_iter().enumerate() {
        let mut config = TransportConfig::new(identity()).with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().unwrap());
        if let Some(addr) = &first_addr {
            config = config.with_peer(addr.clone());
        }
        let mut transport = H2V4Transport::new(config).expect("transport");
        let listen = loop {
            match transport.next_event().await {
                Some(TransportEvent::Listening(addr)) => break addr,
                Some(_) => {}
                None => panic!("transport ended before listening"),
            }
        };
        if first_addr.is_none() {
            first_addr = Some(listen.with(libp2p::multiaddr::Protocol::P2p(*transport.local_peer_id())));
        }
        let (output_tx, output_rx) = mpsc::channel::<EngineOutput>(256);
        let mut engine = ConsensusEngine::new(index as u32, key, set.clone(), 1_000, 4_000, output_tx);
        engine.enable_h2_v4_signing(identity());
        let driver = ExecutionDriver::new(MockExecutionLayer::new(), identity().genesis_hash);
        let node_dir = dir.join(index.to_string());
        std::fs::create_dir_all(&node_dir).expect("node dir");
        let mut service = H2Service::new(transport, engine, driver, output_rx, VALIDATORS)
            .with_payload_attributes(attributes)
            .with_equivocation_log(EquivocationLog::open(&node_dir).expect("evidence log"))
            // Batched vote verification (`N42_VOTE_AGGREGATE_VERIFY`, profile 1's default).
            .with_vote_aggregate(aggregate);
        if index == EQUIVOCATOR {
            service = service.with_test_equivocation(injector).expect("dev chain");
        }
        nodes.push(service);
    }
    nodes
}

#[derive(Default)]
struct Seen {
    /// Every member's commits, (view, block).
    commits: Vec<(usize, u64, B256)>,
    /// The twins the equivocator sent: view -> twin block.
    twins: HashMap<u64, B256>,
}

/// Runs the fleet until every honest member holds evidence against the
/// equivocator (when `honest_detectors` says so) and has committed
/// `COMMITS_AFTER` views past the first injection.
async fn run(
    nodes: Vec<H2Service<MockExecutionLayer>>,
    logs: &[EquivocationLog],
    detectors: &[usize],
    budget: Duration,
) -> (Seen, bool) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles: Vec<_> = nodes
        .into_iter()
        .enumerate()
        .map(|(index, mut service)| {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(events) = service.step().await {
                    for event in events {
                        if tx.send((index, event)).is_err() {
                            return;
                        }
                    }
                }
            })
        })
        .collect();
    drop(tx);

    let mut seen = Seen::default();
    let done = tokio::time::timeout(budget, async {
        while let Some((index, event)) = rx.recv().await {
            match event {
                ServiceEvent::Committed { view, block_hash, .. } => seen.commits.push((index, view, block_hash)),
                ServiceEvent::EquivocationInjected { view, second, .. } => {
                    assert_eq!(index, EQUIVOCATOR, "only the equivocator injects");
                    seen.twins.insert(view, second);
                }
                _ => {}
            }
            let Some(first) = seen.twins.keys().min().copied() else { continue };
            let detected = detectors.iter().all(|&i| logs[i].response().evidence.iter().any(|r| r.validator_index == EQUIVOCATOR as u32));
            let progressed = (0..VALIDATORS)
                .filter(|&i| i != EQUIVOCATOR)
                .all(|i| seen.commits.iter().filter(|(n, view, _)| *n == i && *view > first).count() as u64 >= COMMITS_AFTER);
            if detected && progressed {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    for handle in handles {
        handle.abort();
    }
    (seen, done)
}

/// Safety: one block per view across every member, and no twin committed.
fn assert_safe(seen: &Seen) {
    let mut by_view: HashMap<u64, B256> = HashMap::new();
    for (node, view, hash) in &seen.commits {
        if let Some(other) = by_view.insert(*view, *hash) {
            assert_eq!(other, *hash, "two different blocks committed at view {view} (node {node})");
        }
    }
    let twins: HashSet<B256> = seen.twins.values().copied().collect();
    assert!(seen.commits.iter().all(|(_, _, hash)| !twins.contains(hash)), "an injected twin was committed");
}

/// Every record against the equivocator is of `kind`, verifies on its own,
/// names a twin the equivocator sent, and survives a reopen of the file.
fn assert_evidence(dir: &Path, member: usize, kind: EquivocationKind, seen: &Seen) {
    let reopened = EquivocationLog::open(&dir.join(member.to_string())).expect("reopen");
    let records: Vec<_> =
        reopened.response().evidence.into_iter().filter(|r| r.validator_index == EQUIVOCATOR as u32).collect();
    assert!(!records.is_empty(), "member {member} persisted no evidence");
    for record in records {
        assert_eq!(record.kind, kind);
        assert_eq!(seen.twins.get(&record.view), Some(&record.hash2), "the second hash is the injected twin");
        let evidence = EquivocationEvidence {
            kind: record.kind,
            view: record.view,
            validator: record.validator_index,
            public_key: record.public_key,
            first: record.first,
            second: record.second,
        };
        assert!(evidence.verify(ConsensusSigningProfile::H2V4(identity())), "member {member}'s pair must verify");
    }
}

async fn equivocate(name: &str, spec: &str, kind: EquivocationKind, detectors: &[usize]) {
    for aggregate in [false, true] {
        equivocate_with(&format!("{name}-agg{}", u8::from(aggregate)), spec, kind, detectors, aggregate).await;
    }
}

async fn equivocate_with(name: &str, spec: &str, kind: EquivocationKind, detectors: &[usize], aggregate: bool) {
    let dir = scratch(name);
    let nodes = build_fleet(TestEquivocation::parse(spec).expect("spec"), &dir, aggregate).await;
    let logs: Vec<EquivocationLog> = nodes.iter().map(H2Service::equivocation_log).collect();
    let (seen, done) = run(nodes, &logs, detectors, Duration::from_secs(120)).await;
    assert!(!seen.twins.is_empty(), "the injector never fired");
    assert!(
        done,
        "fleet did not prove the fault and keep committing (aggregate {aggregate}): twins {:?}, evidence {:?}, commits {}",
        seen.twins,
        logs.iter().map(EquivocationLog::len).collect::<Vec<_>>(),
        seen.commits.len()
    );
    assert_safe(&seen);
    for &member in detectors {
        assert_evidence(&dir, member, kind, &seen);
    }
    assert!(logs[EQUIVOCATOR].response().evidence.iter().all(|r| r.validator_index != EQUIVOCATOR as u32));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_double_vote_is_proven_by_the_leaders_and_the_fleet_goes_on() {
    // Round-1 votes go to the view's leader: every honest member leads some
    // view member 3 votes in.
    equivocate("vote", "vote:every-1", EquivocationKind::Vote, &[0, 1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_double_commit_vote_is_proven_by_the_leaders_and_the_fleet_goes_on() {
    equivocate("commit-vote", "commit_vote:every-1", EquivocationKind::CommitVote, &[0, 1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_double_proposal_is_proven_by_every_follower_and_the_fleet_goes_on() {
    // A proposal is broadcast: every honest member is a follower of member 3.
    equivocate("proposal", "proposal:every-1", EquivocationKind::Proposal, &[0, 1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_injector_is_refused_off_the_test_chains() {
    let (output_tx, output_rx) = mpsc::channel::<EngineOutput>(8);
    let key = BlsSecretKey::random().expect("key");
    let info = ValidatorInfo { address: Address::with_last_byte(1), bls_public_key: key.public_key(), p2p_peer_id: None };
    let production = H2V4ChainIdentity { chain_id: 94, genesis_hash: B256::repeat_byte(0x42) };
    let mut engine = ConsensusEngine::new(0, key, ValidatorSet::new(&[info], 0), 1_000, 4_000, output_tx);
    engine.enable_h2_v4_signing(production);
    let transport = H2V4Transport::new(TransportConfig::new(production)).expect("transport");
    let driver = ExecutionDriver::new(MockExecutionLayer::new(), production.genesis_hash);
    let service = H2Service::new(transport, engine, driver, output_rx, 1);
    assert!(service.with_test_equivocation(TestEquivocation::parse("vote:1").expect("spec")).is_err());
}

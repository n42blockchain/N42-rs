// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Four Rust nodes, one real gossip mesh, one committed block.
//!
//! Every piece under this test already had its own coverage — the transport
//! publishes, the engine reaches quorum, the driver calls an execution layer,
//! the bridge round-trips gov5's bytes. None of that proves they work when
//! connected, which is the only property that matters for joining a fleet.
//!
//! So this runs the actual thing: four `H2Service`s over TCP, gov5's router
//! parameters, gov5's v4 envelope format, BLS signatures verified by the same
//! code path a Go node uses, and a mock execution layer standing in for reth.
//! A commit here means proposal, votes, quorum, commit votes, and decide all
//! crossed a socket in gov5's wire format and came back as agreement.
//!
//! It does not prove interoperability with gov5 itself — that needs a Go node,
//! and `docs/N42_26_PORT.md` records how far that got. It proves the Rust half
//! is a working fleet rather than a pile of working parts.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_h2_consensus::{ConsensusEngine, EngineOutput, ValidatorInfo, ValidatorSet};
use n42_h2_execution::{ExecutionDriver, MockExecutionLayer};
use n42_h2_net::{H2V4Transport, TransportConfig, TransportEvent};
use n42_h2_node::{H2Service, ProposalContext, ServiceEvent};
use n42_h2_primitives::bls::BlsSecretKey;
use n42_h2_primitives::consensus::H2V4ChainIdentity;
use tokio::sync::mpsc;

const VALIDATORS: usize = 4;
/// n - f with n = 4, f = 1 is a quorum of 3, so one node can be silent and the
/// fleet still commits. That is the configuration worth testing: a fleet that
/// only works when everyone answers is not fault tolerant.
const FAULT_TOLERANCE: u32 = 1;

const fn identity() -> H2V4ChainIdentity {
    H2V4ChainIdentity {
        chain_id: 96,
        genesis_hash: B256::repeat_byte(0x42),
    }
}

const fn attributes(context: ProposalContext) -> Option<PayloadAttributes> {
    Some(PayloadAttributes {
        // Deterministic rather than wall-clock: a test that depends on the
        // clock fails on a loaded machine for reasons unrelated to consensus.
        timestamp: 1_700_000_000 + context.view,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        target_gas_limit: None,
        slot_number: None,
    })
}

struct Node {
    service: H2Service<MockExecutionLayer>,
}

/// Builds `VALIDATORS` services sharing one validator set, all listening on
/// loopback, all signing under the v4 profile so their messages are the bytes
/// gov5 would verify.
///
/// `proposers` names the nodes given a payload builder. A node not in it votes
/// but never proposes, which is how a member joining someone else's fleet
/// usually starts.
async fn build_fleet(proposers: &[usize]) -> Vec<Node> {
    build_fleet_with(proposers, false).await
}

/// `gov5_profile` runs every node under gov5's `HotStuff` header profile:
/// built blocks are finished with the view and a BLS seal, and bodies are
/// decoded under that profile.
async fn build_fleet_with(proposers: &[usize], gov5_profile: bool) -> Vec<Node> {
    // Off unless RUST_LOG asks for it; a failing fleet test is otherwise silent
    // about which of the three layers stopped.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let identity = identity();
    let (keys, validator_set) = validator_keys();

    let mut nodes = Vec::with_capacity(VALIDATORS);
    let mut first_addr: Option<libp2p::Multiaddr> = None;
    for (index, key) in keys.into_iter().enumerate() {
        let (node, addr) = build_node(
            index,
            key,
            &validator_set,
            identity,
            first_addr.clone(),
            proposers.contains(&index),
            gov5_profile,
        )
        .await;
        if first_addr.is_none() {
            first_addr = Some(addr);
        }
        nodes.push(node);
    }
    nodes
}

/// One member: its transport listening on loopback (dialing `peer` if
/// given, star topology onto node 0), its engine, a mock execution layer.
/// Returns the node and the address others can dial it at.
async fn build_node(
    index: usize,
    key: BlsSecretKey,
    validator_set: &ValidatorSet,
    identity: H2V4ChainIdentity,
    peer: Option<libp2p::Multiaddr>,
    propose: bool,
    gov5_profile: bool,
) -> (Node, libp2p::Multiaddr) {
    let mut config = TransportConfig::new(identity)
        .with_listen_addr("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    if let Some(addr) = peer {
        config = config.with_peer(addr);
    }
    let mut transport = H2V4Transport::new(config).expect("transport");

    let listen_addr = loop {
        match transport.next_event().await {
            Some(TransportEvent::Listening(addr)) => break addr,
            Some(_) => {}
            None => panic!("transport ended before listening"),
        }
    };
    let addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(*transport.local_peer_id()));

    let (output_tx, output_rx) = mpsc::channel::<EngineOutput>(256);
    let seal_key = key.clone();
    let mut engine = ConsensusEngine::new(
        index as u32,
        key,
        validator_set.clone(),
        // Short enough that a stuck view recovers inside the test's budget,
        // long enough that a slow machine does not time out a healthy view.
        1_000,
        4_000,
        output_tx,
    );
    engine.enable_h2_v4_signing(identity);

    let driver = ExecutionDriver::new(MockExecutionLayer::new(), identity.genesis_hash);
    let mut service = H2Service::new(transport, engine, driver, output_rx, VALIDATORS);
    if gov5_profile {
        service = service.with_gov5_h2_profile(seal_key);
    }
    if propose {
        service = service.with_payload_attributes(attributes);
    }
    (Node { service }, addr)
}

/// The dev validator set: keys and the set built from them.
fn validator_keys() -> (Vec<BlsSecretKey>, ValidatorSet) {
    let keys: Vec<BlsSecretKey> = (0..VALIDATORS)
        .map(|_| BlsSecretKey::random().expect("bls keygen"))
        .collect();
    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| ValidatorInfo {
            address: Address::with_last_byte(i as u8 + 1),
            bls_public_key: key.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let set = ValidatorSet::new(&validators, FAULT_TOLERANCE);
    (keys, set)
}

/// Runs a node in its own task, forwarding its events. See [`run_until`]
/// for why a task each and not one `select_all`.
fn spawn_node(index: usize, mut node: Node, tx: mpsc::UnboundedSender<(usize, ServiceEvent)>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match node.service.step().await {
                Ok(events) => {
                    for event in events {
                        if tx.send((index, event)).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => return,
            }
        }
    })
}

/// Drives every node concurrently until `stop` accepts an event, or the
/// deadline passes. Returns the accepted event.
///
/// Each node gets its own task rather than being polled from one `select_all`.
/// That is not a style choice: `select_all` drops the futures that did not
/// finish, so every round would cancel the other three nodes mid-step and throw
/// away whatever they had just received. A fleet driven that way makes no
/// progress at all, which is exactly what it did.
async fn run_until(
    nodes: Vec<Node>,
    budget: Duration,
    mut stop: impl FnMut(usize, &ServiceEvent) -> bool,
) -> Option<(usize, ServiceEvent)> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles: Vec<_> = nodes
        .into_iter()
        .enumerate()
        .map(|(index, mut node)| {
            let tx = tx.clone();
            let trace = std::env::var_os("H2_TRACE").is_some();
            tokio::spawn(async move {
                let mut steps = 0u64;
                loop {
                    let result = node.service.step().await;
                    steps += 1;
                    if trace && steps.is_multiple_of(20) {
                        println!("node {index} after {steps} steps: {:?} mesh={}", node.service, node.service.transport().mesh_size());
                    }
                    match result {
                        Ok(events) => {
                            for event in events {
                                if tx.send((index, event)).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(err) => {
                            if trace {
                                println!("node {index} stopped: {err}");
                            }
                            return;
                        }
                    }
                }
            })
        })
        .collect();
    drop(tx);

    let trace = std::env::var_os("H2_TRACE").is_some();
    let found = tokio::time::timeout(budget, async {
        while let Some((index, event)) = rx.recv().await {
            if trace {
                println!("node {index}: {event:?}");
            }
            if stop(index, &event) {
                return Some((index, event));
            }
        }
        None
    })
    .await
    .ok()
    .flatten();

    for handle in handles {
        handle.abort();
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_node_recognises_itself_as_a_member_of_the_set() {
    // An engine that cannot find its own public key in the validator set runs
    // as an observer: it never proposes, never votes, and never broadcasts a
    // timeout, while looking perfectly healthy from the outside. That failure
    // is silent, so it is asserted before anything that depends on it.
    let nodes = build_fleet(&[0, 1, 2, 3]).await;
    let leaders = nodes
        .iter()
        .filter(|node| node.service.engine().is_current_leader())
        .count();
    for (index, node) in nodes.iter().enumerate() {
        assert_eq!(
            node.service.engine().my_index() as usize,
            index,
            "node {index} does not know its own index",
        );
    }
    assert_eq!(leaders, 1, "view 1 must have exactly one leader");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_rust_nodes_reach_agreement_over_a_real_gossip_mesh() {
    let nodes = build_fleet(&[0, 1, 2, 3]).await;

    let committed = run_until(nodes, Duration::from_secs(60), |_, event| {
        matches!(event, ServiceEvent::Committed { .. })
    })
    .await;

    let Some((index, ServiceEvent::Committed { view, block_hash, .. })) = committed else {
        panic!("no node committed a block within the budget");
    };
    assert!(view > 0, "commit must be in a real view");
    assert_ne!(block_hash, B256::ZERO, "commit must name a real block");
    assert!(index < VALIDATORS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn followers_commit_only_after_bodies_arrive_over_the_block_topic() {
    // The proposal names a hash; the body has to reach the followers some
    // other way, and gov5's way is the fork-scoped block topic. With one
    // proposer, nobody else ever builds the block, so a follower that commits
    // has necessarily received the body over gossip, executed it, and voted.
    //
    // This is what `four_rust_nodes_reach_agreement` cannot show: there every
    // node proposes, and the mock builds the same block for each of them.
    let nodes = build_fleet(&[0]).await;

    let mut bodies_at = std::collections::HashSet::new();
    let committed = run_until(nodes, Duration::from_secs(60), |index, event| {
        if matches!(event, ServiceEvent::BodyReceived { .. }) {
            bodies_at.insert(index);
        }
        index > 0 && matches!(event, ServiceEvent::Committed { .. })
    })
    .await;

    let Some((index, ServiceEvent::Committed { block_hash, .. })) = committed else {
        panic!("no follower committed a block within the budget");
    };
    assert!(
        bodies_at.contains(&index),
        "follower {index} committed {block_hash} without ever receiving a body",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fleet_commits_under_gov5s_header_profile() {
    // Same fleet, gov5's header profile: the leader finishes each block with
    // the view and its BLS seal before proposing, so the hash consensus
    // agrees on is not the hash the execution layer built. Followers decode
    // bodies under the same profile. A follower commit proves the finished
    // block travelled, reconstructed, and executed on the far side.
    let nodes = build_fleet_with(&[0], true).await;

    let mut bodies_at = std::collections::HashSet::new();
    let committed = run_until(nodes, Duration::from_secs(60), |index, event| {
        if matches!(event, ServiceEvent::BodyReceived { .. }) {
            bodies_at.insert(index);
        }
        index > 0 && matches!(event, ServiceEvent::Committed { .. })
    })
    .await;

    let Some((index, ServiceEvent::Committed { .. })) = committed else {
        panic!("no follower committed a gov5-profile block within the budget");
    };
    assert!(bodies_at.contains(&index), "follower {index} committed without a body");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_no_payload_builder_still_votes() {
    // A fleet member that does not produce blocks is a valid configuration, and
    // the one most likely to be deployed first when joining someone else's
    // fleet. It must still participate — a node that goes quiet because it has
    // no builder is worse than useless, because it counts against quorum.
    //
    // Only node 0 can propose; the other three can do nothing but vote.
    let nodes = build_fleet(&[0]).await;

    let spoke = run_until(nodes, Duration::from_secs(60), |index, event| {
        index > 0 && matches!(event, ServiceEvent::Published { .. })
    })
    .await;

    assert!(
        spoke.is_some(),
        "a non-proposing node never spoke; it would count against quorum"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_that_starts_behind_pulls_the_chain_from_its_peers() {
    // Three members run and commit; the fourth arrives with an empty
    // execution layer. Its peers' status shows them ahead, it pulls the gap
    // by range, imports each block through its execution layer, and ends
    // level with them. Views are the engine's problem and not asserted here.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let identity = identity();
    let (mut keys, validator_set) = validator_keys();
    let late_key = keys.pop().expect("four keys");

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handles = Vec::new();
    let mut first_addr = None;
    for (index, key) in keys.into_iter().enumerate() {
        let (node, addr) = build_node(index, key, &validator_set, identity, first_addr.clone(), true, false).await;
        if first_addr.is_none() {
            first_addr = Some(addr);
        }
        handles.push(spawn_node(index, node, tx.clone()));
    }

    // Let the three build a chain worth pulling.
    let mut commits = 0;
    let started = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some((index, event)) = rx.recv().await {
            if index == 0 && matches!(event, ServiceEvent::Committed { .. }) {
                commits += 1;
                if commits >= 5 {
                    return;
                }
            }
        }
    })
    .await;
    started.expect("the three-member fleet commits five blocks");

    let (late, _) = build_node(3, late_key, &validator_set, identity, first_addr, false, false).await;
    handles.push(spawn_node(3, late, tx.clone()));

    let synced = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some((index, event)) = rx.recv().await {
            if index == 3
                && let ServiceEvent::Synced { height, complete } = event
            {
                return (height, complete);
            }
        }
        panic!("event channel closed");
    })
    .await;
    for handle in handles {
        handle.abort();
    }
    let (height, complete) = synced.expect("the late member syncs within the budget");
    assert!(complete, "the pull stopped short at {height}");
    assert!(height >= 3, "synced only to {height}");
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42_IMPORT_ONCE` on the raw payload channel: several validator keys on one
//! execution layer, each on its own connection, with a scripted engine, a
//! scripted direct import and the real build registry behind them.

use super::*;
use alloy_consensus::Header;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV1, PayloadStatus, PayloadStatusEnum,
};
use n42_engine_types::N42EngineTypes;
use reth_engine_primitives::BeaconEngineMessage;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// The build registry is process-wide and keeps three builds: the tests that
/// file builds run one at a time.
static BUILDS: Mutex<()> = Mutex::new(());

/// What the execution layer behind the channel did.
#[derive(Default)]
struct Seen {
    /// `engine_newPayload` calls.
    new_payloads: AtomicUsize,
    /// Executed blocks handed to the engine (own hand-offs and direct imports).
    inserts: AtomicUsize,
    /// Direct imports run (executions).
    executions: AtomicUsize,
}

struct El {
    addr: std::net::SocketAddr,
    seen: Arc<Seen>,
    registry: Arc<crate::import_once::Registry>,
}

/// How the scripted parts behave.
#[derive(Clone, Copy)]
struct Script {
    /// The direct import is configured (a CHECKED frame, then the execution).
    direct_import: bool,
    /// How long an execution, a hand-off and an engine call each take: long
    /// enough that every key's request arrives while the first is working.
    work: std::time::Duration,
    /// The engine fails this many `newPayload` calls first.
    engine_failures: usize,
    /// The import-once registry is on.
    once: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self { direct_import: false, work: std::time::Duration::from_millis(150), engine_failures: 0, once: true }
    }
}

/// An empty block for the executed insert.
fn executed(header: &Header) -> Box<reth_payload_primitives::BuiltPayloadExecutedBlock<n42_tx_types::N42Primitives>> {
    let block = n42_tx_types::Block {
        header: header.clone(),
        body: n42_tx_types::BlockBody {
            transactions: Vec::new(),
            ommers: Vec::new(),
            withdrawals: header.withdrawals_root.map(|_| Vec::new().into()),
        },
    };
    Box::new(reth_payload_primitives::BuiltPayloadExecutedBlock {
        recovered_block: Arc::new(reth_primitives_traits::RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), Vec::new())),
        execution_output: Arc::new(reth_provider::BlockExecutionOutput { result: Default::default(), state: Default::default() }),
        hashed_state: Arc::new(reth_trie::HashedPostState::default()),
        trie_updates: Arc::new(reth_trie::updates::TrieUpdates::default()),
    })
}

/// An execution layer with one registry and a connection per key.
async fn execution_layer(script: Script) -> El {
    let seen = Arc::new(Seen::default());
    let (service_tx, mut service_rx) = mpsc::unbounded_channel::<reth_payload_builder::PayloadServiceCommand<N42EngineTypes>>();
    tokio::spawn(async move { while service_rx.recv().await.is_some() {} });
    let (engine_tx, mut engine_rx) = mpsc::unbounded_channel::<BeaconEngineMessage<N42EngineTypes>>();
    {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut failures = script.engine_failures;
            while let Some(message) = engine_rx.recv().await {
                if let BeaconEngineMessage::NewPayload { tx, .. } = message {
                    seen.new_payloads.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(script.work).await;
                    if failures > 0 {
                        failures -= 1;
                        // Dropped unanswered: the engine is unavailable.
                        drop(tx);
                    } else {
                        let _ = tx.send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Valid)));
                    }
                }
            }
        });
    }
    let (inserts_tx, mut inserts_rx) = mpsc::unbounded_channel::<reth_node_builder::executed_inserts::ExecutedInsert>();
    {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Some(insert) = inserts_rx.recv().await {
                seen.inserts.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(script.work).await;
                let _ = insert.done.send(true);
            }
        });
    }
    let chain_spec = reth_chainspec::MAINNET.clone();
    let profile = n42_engine_types::engine_validator::header_profile_for(&chain_spec);
    let import_foreign = script.direct_import.then(|| {
        let seen = Arc::clone(&seen);
        Arc::new(
            move |block: crate::follower_import::ForeignBlock,
                  _senders: Option<Vec<Address>>,
                  checked: Option<tokio::sync::oneshot::Sender<()>>,
                  _road: crate::follower_import::VoteRoad| {
                seen.executions.fetch_add(1, Ordering::SeqCst);
                let header = match block {
                    crate::follower_import::ForeignBlock::Sealed(sealed) => sealed.header().clone(),
                    _ => return Err("not a sealed block".to_owned()),
                };
                if let Some(checked) = checked {
                    let _ = checked.send(());
                }
                std::thread::sleep(script.work);
                Ok((executed(&header), [0u64; crate::follower_import::IMPORT_TIMES]))
            },
        ) as Arc<ForeignImport>
    });
    let reuse = OwnBlockReuse {
        validator: Arc::new(n42_engine_types::engine_validator::N42EngineValidator::new(chain_spec, profile)),
        qmdb: None,
        inserts: inserts_tx,
        prune_pool: None,
        exec_probe: None,
        import_foreign,
        canonical_head: None,
    };
    let registry = Arc::new(crate::import_once::Registry::new(crate::import_once::DEFAULT_CAP));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let payloads = PayloadBuilderHandle::new(service_tx);
    let engine = ConsensusEngineHandle::new(engine_tx);
    {
        let registry = script.once.then(|| Arc::clone(&registry));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (payloads, engine, reuse, registry) = (payloads.clone(), engine.clone(), reuse.clone(), registry.clone());
                tokio::spawn(async move {
                    let _ = serve_connection::<N42EngineTypes>(stream, payloads, engine, Some(reuse), registry).await;
                });
            }
        });
    }
    El { addr, seen, registry }
}

/// A block header the Ethereum profile converts back from its payload.
fn header(number: u64, tag: u8) -> Header {
    Header {
        number,
        parent_hash: B256::repeat_byte(tag),
        beneficiary: Address::repeat_byte(4),
        state_root: B256::repeat_byte(tag.wrapping_add(1)),
        receipts_root: B256::repeat_byte(tag.wrapping_add(2)),
        transactions_root: alloy_consensus::EMPTY_ROOT_HASH,
        ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
        gas_used: 0,
        timestamp: 1_000 + number,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(7),
        ..Default::default()
    }
}

/// The block's payload, under the hash the engine's conversion gives it.
fn payload(header: &Header) -> ExecutionData {
    let v1 = ExecutionPayloadV1 {
        parent_hash: header.parent_hash,
        fee_recipient: header.beneficiary,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom,
        prev_randao: header.mix_hash,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.clone(),
        base_fee_per_gas: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash: header.hash_slow(),
        transactions: Vec::new(),
        difficulty: header.difficulty,
        nonce: header.nonce,
    };
    ExecutionData::new(ExecutionPayload::V1(v1), ExecutionPayloadSidecar::none())
}

/// What a key's validator heard back.
#[derive(Debug, PartialEq, Eq)]
struct Heard {
    checked: bool,
    status: Result<PayloadStatusEnum, String>,
}

async fn connect(el: &El) -> tokio::net::TcpStream {
    let stream = tokio::net::TcpStream::connect(el.addr).await.expect("connect");
    stream.set_nodelay(true).expect("nodelay");
    stream
}

async fn send(client: &mut tokio::net::TcpStream, kind: u8, frame: &[u8]) {
    let mut request = vec![kind];
    request.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    request.extend_from_slice(frame);
    client.write_all(&request).await.expect("send");
}

/// Reads frames until the final answer, as the validator's client does.
async fn hear(client: &mut tokio::net::TcpStream) -> Heard {
    let mut checked = false;
    loop {
        let kind = client.read_u8().await.expect("kind");
        let len = client.read_u32_le().await.expect("len") as usize;
        let mut buf = vec![0u8; len];
        client.read_exact(&mut buf).await.expect("frame");
        match kind {
            raw_engine::reply::CHECKED => checked = true,
            raw_engine::reply::VALUE => {
                let status = raw_engine::decode_payload_status(&buf).expect("status");
                return Heard { checked, status: Ok(status.status) };
            }
            raw_engine::reply::ERROR => return Heard { checked, status: Err(String::from_utf8_lossy(&buf).into_owned()) },
            other => panic!("unexpected frame {other}"),
        }
    }
}

/// `k` keys, each on its own connection, send the same payload at once.
async fn keys_send_payload(el: &El, data: &ExecutionData, k: usize) -> Vec<Heard> {
    let frame = raw_engine::encode_execution_data(data);
    let mut tasks = Vec::new();
    for _ in 0..k {
        let mut client = connect(el).await;
        let frame = frame.clone();
        tasks.push(tokio::spawn(async move {
            send(&mut client, request::NEW_PAYLOAD, &frame).await;
            hear(&mut client).await
        }));
    }
    let mut heard = Vec::new();
    for task in tasks {
        heard.push(task.await.expect("key"));
    }
    heard
}

fn valid(checked: bool) -> Heard {
    Heard { checked, status: Ok(PayloadStatusEnum::Valid) }
}

/// Files `header` as one of this node's own builds.
fn file_build(header: &Header) -> B256 {
    let execution = executed(header);
    let built = n42_engine_types::built_executions::BuiltExecution {
        block: Arc::clone(&execution.recovered_block),
        execution_output: Arc::clone(&execution.execution_output),
        hashed_state: Arc::clone(&execution.hashed_state),
        trie_updates: Arc::clone(&execution.trie_updates),
    };
    let hash = built.block.hash();
    n42_engine_types::built_executions::remember(hash, built);
    hash
}

/// Seven keys bring one block at once: it is executed once, every key hears
/// CHECKED and then VALID, and the counters say one import for one block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seven_keys_import_a_block_once_and_all_hear_checked_then_valid() {
    let el = execution_layer(Script { direct_import: true, ..Default::default() }).await;
    let data = payload(&header(301, 0x31));
    let heard = keys_send_payload(&el, &data, 7).await;
    assert!(heard.iter().all(|h| *h == valid(true)), "{heard:?}");
    assert_eq!(el.seen.executions.load(Ordering::SeqCst), 1, "one execution");
    assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 1, "one executed insert");
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 1, "one engine pass");
}

/// A key whose request arrives after the import is answered from the
/// registry: VALID at once, nothing executed again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_after_the_import_is_answered_from_the_registry() {
    let el = execution_layer(Script { direct_import: true, ..Default::default() }).await;
    let data = payload(&header(302, 0x32));
    assert_eq!(keys_send_payload(&el, &data, 1).await, vec![valid(true)]);
    let at = std::time::Instant::now();
    assert_eq!(keys_send_payload(&el, &data, 3).await, vec![valid(false), valid(false), valid(false)]);
    assert!(at.elapsed() < std::time::Duration::from_millis(100), "answered without waiting: {:?}", at.elapsed());
    assert_eq!(el.seen.executions.load(Ordering::SeqCst), 1);
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 1);
}

/// The first request's work ends without a status (the engine failed it):
/// another key's request takes the import over, and the keys still waiting
/// hear its answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_work_is_taken_over_when_the_first_request_ends_without_a_status() {
    let el = execution_layer(Script { engine_failures: 1, ..Default::default() }).await;
    let data = payload(&header(303, 0x33));
    let heard = keys_send_payload(&el, &data, 4).await;
    let failed = heard.iter().filter(|h| h.status.is_err()).count();
    assert_eq!(failed, 1, "only the first request hears the engine's failure: {heard:?}");
    assert_eq!(heard.iter().filter(|h| **h == valid(false)).count(), 3);
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 2, "one failed pass, one taken over");
}

/// The leader key's own block: its `OWN_BLOCK` and six other keys' payloads
/// of it resolve to one hand-off of the build -- no execution, one insert,
/// one engine pass -- and every key hears VALID.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_leaders_own_build_is_shared_by_every_key() {
    let _builds = BUILDS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let el = execution_layer(Script { direct_import: true, ..Default::default() }).await;
    let block = header(304, 0x34);
    file_build(&block);
    let mut leader = connect(&el).await;
    send(&mut leader, request::OWN_BLOCK, &alloy_rlp::encode(&block)).await;
    let leader = tokio::spawn(async move { hear(&mut leader).await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let followers = keys_send_payload(&el, &payload(&block), 6).await;
    assert_eq!(leader.await.expect("leader"), valid(false));
    // The build was found before the hand-off: the followers vote on CHECKED.
    assert!(followers.iter().all(|h| *h == valid(true)), "{followers:?}");
    assert_eq!(el.seen.executions.load(Ordering::SeqCst), 0, "the own block is not executed");
    assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 1, "one hand-off of the build");
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 1);
}

/// A tenure handover between two keys on one execution layer. The outgoing
/// leader's last block reaches the execution layer first as the incoming
/// leader's follower request: it is imported from the build (not executed),
/// the outgoing leader's own `OWN_BLOCK` is answered from it, and the build
/// stays findable for the incoming leader's first build on it -- the chain
/// of builds goes on across the handover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handover_on_one_execution_layer_keeps_the_build_chain() {
    let _builds = BUILDS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let el = execution_layer(Script { direct_import: true, ..Default::default() }).await;
    let (from_build, again) = crate::import_once::own_counts();
    // The outgoing leader built N-1 and N, chained.
    let before = header(305, 0x35);
    file_build(&before);
    let last = Header { parent_hash: before.hash_slow(), ..header(306, 0x36) };
    file_build(&last);
    for block in [&before, &last] {
        // The incoming leader's follower request first, the outgoing
        // leader's own import second.
        let mut incoming = connect(&el).await;
        send(&mut incoming, request::NEW_PAYLOAD, &raw_engine::encode_execution_data(&payload(block))).await;
        let incoming = tokio::spawn(async move { hear(&mut incoming).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut outgoing = connect(&el).await;
        send(&mut outgoing, request::OWN_BLOCK, &alloy_rlp::encode(block)).await;
        assert_eq!(hear(&mut outgoing).await, valid(false));
        // The incoming key votes on CHECKED as soon as the build is found.
        assert_eq!(incoming.await.expect("incoming"), valid(true));
    }
    assert_eq!(el.seen.executions.load(Ordering::SeqCst), 0, "neither block executed");
    assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 2, "one hand-off each");
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 2);
    let (from_build_now, again_now) = crate::import_once::own_counts();
    assert_eq!(from_build_now - from_build, 2, "both own blocks served from their builds");
    assert_eq!(again_now, again, "no own block executed again");
    // The incoming leader's first build on the last block finds it (what
    // `BUILD_ON_OWN` on a sealed parent looks up), as the outgoing leader's
    // next build would have.
    let found = n42_engine_types::built_executions::find_kept_at(
        last.parent_hash,
        last.number,
        last.state_root,
        last.receipts_root,
        last.gas_used,
        Some(last.transactions_root),
        n42_engine_types::built_executions::Stage::StateReady,
    );
    assert_eq!(found.map(|(hash, _)| hash), Some(last.hash_slow()), "the build chain goes on across the handover");
}

/// A build refused at the handover (the execution layer no longer keeps it):
/// the outgoing leader's `OWN_BLOCK` is refused as before, and the refusal
/// is not kept for the block: the incoming leader's request for it (and the
/// outgoing leader's own fallback payload) does the import.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_own_block_leaves_the_import_to_the_next_request() {
    let el = execution_layer(Script::default()).await;
    let block = header(307, 0x37);
    let mut outgoing = connect(&el).await;
    send(&mut outgoing, request::OWN_BLOCK, &alloy_rlp::encode(&block)).await;
    let refused = hear(&mut outgoing).await;
    assert_eq!(refused.status, Err("unknown build".to_owned()));
    let heard = keys_send_payload(&el, &payload(&block), 2).await;
    assert_eq!(heard, vec![valid(false), valid(false)]);
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 1);
    assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 0, "no hand-off of a build that is not kept");
}

/// One key per execution layer: the answers are the bytes the channel gives
/// without the registry, and every request is its own block's only one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_key_hears_what_it_hears_without_the_registry() {
    let mut answers = Vec::new();
    for once in [false, true] {
        let el = execution_layer(Script { direct_import: true, once, work: std::time::Duration::from_millis(5), ..Default::default() }).await;
        let mut client = connect(&el).await;
        let mut bytes = Vec::new();
        for n in 0..3u8 {
            let data = payload(&header(310 + u64::from(n), 0x40 + n));
            send(&mut client, request::NEW_PAYLOAD, &raw_engine::encode_execution_data(&data)).await;
            let mut kind = [0u8; 1];
            loop {
                client.read_exact(&mut kind).await.expect("kind");
                let len = client.read_u32_le().await.expect("len");
                let mut frame = vec![0u8; len as usize];
                client.read_exact(&mut frame).await.expect("frame");
                bytes.push((kind[0], frame));
                if kind[0] != raw_engine::reply::CHECKED {
                    break;
                }
            }
        }
        assert_eq!(el.seen.executions.load(Ordering::SeqCst), 3);
        if once {
            assert_eq!(el.registry.len(), 3);
        }
        answers.push(bytes);
    }
    assert_eq!(answers[0], answers[1]);
}

/// The hash a later key's request is registered under is read straight out
/// of its frame, and is the payload's own.
#[test]
fn the_payload_hash_is_read_without_decoding_the_payload() {
    let mut block = header(320, 0x50);
    for extra in [Vec::new(), vec![0xAB; 97]] {
        block.extra_data = extra.into();
        let data = payload(&block);
        let frame = raw_engine::encode_execution_data(&data);
        assert_eq!(peek_payload_hash(&frame), Some(data.payload.block_hash()));
    }
    assert_eq!(peek_payload_hash(&[1, 2, 3]), None, "a short frame names no hash");
}

// ---- the layer's own blocks reaching it on a follower key's road first ----

/// How far the layer's build of the block has come when the requests arrive.
#[derive(Clone, Copy, Debug)]
enum Stage {
    /// Sealed and published, still finishing behind its seal.
    InFlight,
    /// Its post-state is filed, its receipts not yet.
    StateFiled,
    /// Finished.
    Done,
    /// Sealed, then its finish failed.
    Abandoned,
}

/// Which road the follower key brings the block on.
#[derive(Clone, Copy, Debug)]
enum Road {
    CompactBody,
    ForeignBody,
    Payload,
}

/// A block as the layer built it (Ethereum-shaped withdrawals root) and as
/// consensus sealed it (gov5's: the rewards commitment, zero ommers hash, the
/// view in the extra data) -- the seal the recognition used to miss.
fn own_block(number: u64, tag: u8) -> (Header, Header) {
    let built = Header {
        withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
        ..header(number, tag)
    };
    let sealed = n42_h2_consensus::gov5_h2_header_for_view(built.clone(), &[], number + 7, None).expect("sealed");
    assert_ne!(built.withdrawals_root, sealed.withdrawals_root, "the seal moves the withdrawals root");
    (built, sealed)
}

/// The build's execution, as the store files it.
fn build_of(built: &Header) -> n42_engine_types::built_executions::BuiltExecution {
    let execution = executed(built);
    n42_engine_types::built_executions::BuiltExecution {
        block: Arc::clone(&execution.recovered_block),
        execution_output: Arc::clone(&execution.execution_output),
        hashed_state: Arc::clone(&execution.hashed_state),
        trie_updates: Arc::clone(&execution.trie_updates),
    }
}

/// The follower key's request for the sealed block on `road`.
fn follower_request(road: Road, sealed: &Header) -> (u8, Vec<u8>) {
    let hash = sealed.hash_slow();
    let profile = n42_h2_consensus::N42HeaderProfile::Gov5H2;
    let body = n42_h2_consensus::encode_block_rlp_raw(sealed, &[], &[], None);
    match road {
        Road::CompactBody => {
            let compact = n42_h2_consensus::encode_compact_body(&body, &[], profile).expect("compact body");
            (request::COMPACT_BODY, raw_engine::encode_foreign_body(hash, profile, &compact))
        }
        Road::ForeignBody => (request::FOREIGN_BODY, raw_engine::encode_foreign_body(hash, profile, &body)),
        Road::Payload => {
            let data = n42_h2_consensus::execution_data_from_raw_parts(hash, sealed, Vec::new(), Vec::new(), None);
            (request::NEW_PAYLOAD, raw_engine::encode_execution_data(&data))
        }
    }
}

/// One race: the layer's build at `stage`, the follower key's request on
/// `road` and the leader key's `OWN_BLOCK`, in the order given. Returns what
/// the leader and the follower heard.
async fn own_block_race(el: &El, road: Road, follower_first: bool, stage: Stage, number: u64, tag: u8) -> (Heard, Heard) {
    let (built, sealed) = own_block(number, tag);
    let execution = build_of(&built);
    let built_hash = execution.block.hash();
    match stage {
        Stage::Done => n42_engine_types::built_executions::remember(built_hash, execution.clone()),
        Stage::InFlight | Stage::StateFiled | Stage::Abandoned => {
            n42_engine_types::built_executions::remember_pending(built_hash, Arc::clone(&execution.block));
            if matches!(stage, Stage::StateFiled) {
                n42_engine_types::built_executions::state_ready(built_hash, execution.clone());
            }
        }
    }
    let (kind, frame) = follower_request(road, &sealed);
    let mut follower = connect(el).await;
    let mut leader = connect(el).await;
    let leader_frame = alloy_rlp::encode(&sealed);
    if follower_first {
        send(&mut follower, kind, &frame).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        send(&mut leader, request::OWN_BLOCK, &leader_frame).await;
    } else {
        send(&mut leader, request::OWN_BLOCK, &leader_frame).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        send(&mut follower, kind, &frame).await;
    }
    let follower = tokio::spawn(async move { hear(&mut follower).await });
    let leader = tokio::spawn(async move { hear(&mut leader).await });
    // The build's finish (or its failure) lands while both are waiting.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    match stage {
        Stage::InFlight | Stage::StateFiled => n42_engine_types::built_executions::complete(built_hash, execution),
        Stage::Abandoned => n42_engine_types::built_executions::fail(built_hash),
        Stage::Done => {}
    }
    (leader.await.expect("leader"), follower.await.expect("follower"))
}

/// Every road, both orders, a build in flight, filed but unfinished, and done:
/// the block is imported from the build once, never executed again, and both
/// keys hear VALID; the follower key, whose road speaks it, hears CHECKED
/// first. Fails without the fix: the seal's withdrawals root kept the body
/// roads from recognising the build at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_own_block_on_a_follower_road_is_served_from_the_build_never_executed() {
    let _builds = BUILDS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut tag = 0x60u8;
    for road in [Road::CompactBody, Road::ForeignBody, Road::Payload] {
        for follower_first in [true, false] {
            for stage in [Stage::InFlight, Stage::StateFiled, Stage::Done] {
                let el = execution_layer(Script { direct_import: true, work: std::time::Duration::from_millis(30), ..Default::default() }).await;
                let (from_build, again) = crate::import_once::own_counts();
                tag = tag.wrapping_add(3);
                let case = format!("{road:?}, follower first {follower_first}, {stage:?}");
                let (leader, follower) = own_block_race(&el, road, follower_first, stage, 400 + u64::from(tag), tag).await;
                assert_eq!(leader.status, Ok(PayloadStatusEnum::Valid), "{case}: leader {leader:?}");
                assert_eq!(follower, valid(true), "{case}: follower");
                assert_eq!(el.seen.executions.load(Ordering::SeqCst), 0, "{case}: never executed again");
                assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 1, "{case}: one hand-off of the build");
                assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 1, "{case}: one engine pass");
                let (from_build_now, again_now) = crate::import_once::own_counts();
                assert_eq!(from_build_now - from_build, 1, "{case}: counted as served from the build");
                assert_eq!(again_now, again, "{case}: nothing executed again");
            }
        }
    }
}

/// A build abandoned behind its seal: the follower key's payload falls
/// through to the ordinary import and both keys hear its
/// status; nothing is counted as an own block executed again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_build_falls_through_to_an_ordinary_import() {
    let _builds = BUILDS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let el = execution_layer(Script { direct_import: true, work: std::time::Duration::from_millis(30), ..Default::default() }).await;
    let (_, again) = crate::import_once::own_counts();
    let (leader, follower) = own_block_race(&el, Road::Payload, true, Stage::Abandoned, 480, 0xA0).await;
    assert_eq!(follower.status, Ok(PayloadStatusEnum::Valid), "{follower:?}");
    assert_eq!(leader.status, Ok(PayloadStatusEnum::Valid), "{leader:?}");
    // The ordinary road: no hand-off of the abandoned build, the engine's own
    // pass once (the scripted chain's profile cannot convert a gov5 payload
    // for the direct import, so the engine's pass is the import here).
    assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 0, "the abandoned build is not handed off");
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 1, "imported once, the ordinary way");
    assert_eq!(crate::import_once::own_counts().1, again, "an abandoned build is no own block executed again");
}

/// Reads the single frame a check-only request is answered with.
async fn hear_one(client: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
    let kind = client.read_u8().await.expect("kind");
    let len = client.read_u32_le().await.expect("len") as usize;
    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await.expect("frame");
    (kind, buf)
}

/// `N42_CHECK_BEFORE_SLOT`: a check-only request for one of this layer's kept
/// builds (by the sealed header a follower key holds) is answered with one
/// CHECKED frame naming exactly that header's hash, and nothing is imported,
/// executed or claimed; a sibling's header (same parent and number, another
/// state root), an unknown block and bytes that are no header get one ERROR
/// frame. A block whose check another request's import already made is
/// vouched for from the registry. The connection serves every answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_check_only_request_vouches_for_a_kept_build_and_nothing_else() {
    let _builds = BUILDS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let el = execution_layer(Script { direct_import: true, work: std::time::Duration::from_millis(30), ..Default::default() }).await;
    let (built, sealed) = own_block(611, 0xB1);
    let execution = build_of(&built);
    n42_engine_types::built_executions::remember(execution.block.hash(), execution);
    let mut client = connect(&el).await;
    let (vouched_before, declined_before) = crate::import_once::check_only_counts();

    send(&mut client, request::CHECK_ONLY, &alloy_rlp::encode(&sealed)).await;
    let (kind, buf) = hear_one(&mut client).await;
    assert_eq!(kind, raw_engine::reply::CHECKED, "{}", String::from_utf8_lossy(&buf));
    let status = raw_engine::decode_payload_status(&buf).expect("status");
    assert!(n42_h2_execution::vouches_for(sealed.hash_slow(), &status), "{status:?}");

    let sibling = Header { state_root: B256::repeat_byte(0xEE), ..sealed.clone() };
    send(&mut client, request::CHECK_ONLY, &alloy_rlp::encode(&sibling)).await;
    assert_eq!(hear_one(&mut client).await.0, raw_engine::reply::ERROR, "a sibling of the build");
    send(&mut client, request::CHECK_ONLY, &alloy_rlp::encode(header(612, 0xB5))).await;
    assert_eq!(hear_one(&mut client).await.0, raw_engine::reply::ERROR, "an unknown block");
    send(&mut client, request::CHECK_ONLY, &[0xc0, 0x01]).await;
    assert_eq!(hear_one(&mut client).await.0, raw_engine::reply::ERROR, "no header");

    assert_eq!(el.seen.executions.load(Ordering::SeqCst), 0, "nothing executed");
    assert_eq!(el.seen.inserts.load(Ordering::SeqCst), 0, "nothing handed to the engine");
    assert_eq!(el.seen.new_payloads.load(Ordering::SeqCst), 0, "no engine pass");
    assert!(el.registry.is_empty(), "nothing registered");

    // A block another key's import checked: vouched for from the registry.
    let data = payload(&header(613, 0xB9));
    let heard = keys_send_payload(&el, &data, 1).await;
    assert_eq!(heard, vec![valid(true)]);
    let checked = header(613, 0xB9);
    send(&mut client, request::CHECK_ONLY, &alloy_rlp::encode(&checked)).await;
    let (kind, buf) = hear_one(&mut client).await;
    assert_eq!(kind, raw_engine::reply::CHECKED);
    assert!(n42_h2_execution::vouches_for(checked.hash_slow(), &raw_engine::decode_payload_status(&buf).expect("status")));
    let (vouched, declined) = crate::import_once::check_only_counts();
    assert!(vouched - vouched_before >= 2 && declined - declined_before >= 3);
}

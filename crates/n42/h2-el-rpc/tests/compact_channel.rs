// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The raw channel's opt-in paths: foreign bodies handed over as received, and
//! build answers that carry transaction hashes.
//!
//! Both are gated by process-wide switches that `n42_h2_execution` reads once
//! (`N42_BODY_ONCE`, `N42_COMPACT_BODY`), so they live in a test binary of
//! their own with the environment set before the first call.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

use alloy_consensus::{BlockBody, Header, TxEnvelope};
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{PayloadAttributes, PayloadId, PayloadStatus, PayloadStatusEnum};
use n42_h2_consensus::header_profile::N42HeaderProfile;
use n42_h2_el_rpc::{EngineApiClient, JsonRpcTransport, RpcError, TransportError};
use n42_h2_execution::raw_engine::{self, reply, request};
use n42_h2_execution::{BodyOutcome, ExecutionLayer, ExecutionPath, ForeignBody, ResolveKind};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static ENV: Once = Once::new();

/// Sets the switches once, before any code reads them.
fn env() {
    ENV.call_once(|| {
        // SAFETY: runs under a `Once` before any test touches the code that
        // reads the variables, and nothing else here reads the environment.
        unsafe {
            std::env::set_var("N42_BODY_ONCE", "1");
            std::env::set_var("N42_COMPACT_BODY", "1");
        }
    });
}

type Script = dyn Fn(u8, &[u8]) -> Option<Vec<u8>> + Send + Sync;

#[derive(Default)]
struct Observed {
    connections: AtomicUsize,
    requests: Mutex<Vec<(u8, Vec<u8>)>>,
}

async fn serve(script: Arc<Script>) -> (std::net::SocketAddr, Arc<Observed>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("addr");
    let observed = Arc::new(Observed::default());
    let seen = Arc::clone(&observed);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            seen.connections.fetch_add(1, Ordering::SeqCst);
            let script = Arc::clone(&script);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                loop {
                    let Ok(kind) = stream.read_u8().await else { return };
                    let frame = if kind == request::GET_PAYLOAD || kind == request::GET_PAYLOAD_HASHED {
                        let mut id = vec![0u8; 8];
                        if stream.read_exact(&mut id).await.is_err() {
                            return;
                        }
                        id
                    } else {
                        let Ok(len) = stream.read_u32_le().await else { return };
                        let mut frame = vec![0u8; len as usize];
                        if stream.read_exact(&mut frame).await.is_err() {
                            return;
                        }
                        frame
                    };
                    seen.requests.lock().unwrap().push((kind, frame.clone()));
                    let Some(out) = script(kind, &frame) else { return };
                    if stream.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, observed)
}

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn status(s: PayloadStatusEnum) -> Vec<u8> {
    raw_engine::encode_payload_status(&PayloadStatus { status: s, latest_valid_hash: None })
}

#[derive(Debug)]
struct Endpoint(std::net::SocketAddr);

#[async_trait::async_trait]
impl JsonRpcTransport for Endpoint {
    async fn call(&self, method: &str, _params: Vec<Value>) -> Result<Value, TransportError> {
        if method == "n42Engine_payloadEndpoint" {
            Ok(json!(self.0.to_string()))
        } else {
            Err(TransportError::Rpc(RpcError { code: -32601, message: "method not found".into() }))
        }
    }
}

fn body(compact: bool) -> ForeignBody {
    ForeignBody {
        block_hash: B256::repeat_byte(0xAB),
        number: 12,
        timestamp: 1_700_000_012,
        profile: N42HeaderProfile::Gov5H2,
        rlp: vec![0xc0, 1, 2, 3].into(),
        compact,
    }
}

// ---- foreign bodies --------------------------------------------------------

#[tokio::test]
async fn a_foreign_body_goes_over_as_received_and_its_check_is_released_first() {
    env();
    let (addr, observed) = serve(Arc::new(|kind, _| {
        assert_eq!(kind, request::FOREIGN_BODY);
        let mut out = frame(reply::CHECKED, &status(PayloadStatusEnum::Valid));
        out.extend(frame(reply::VALUE, &status(PayloadStatusEnum::Accepted)));
        Some(out)
    }))
    .await;
    let client = EngineApiClient::new(Endpoint(addr));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let outcome = client.new_payload_body_checked(ExecutionPath::LIVE_SEQUENTIAL, &body(false), tx).await;
    match outcome {
        BodyOutcome::Answered(Ok(s)) => assert!(matches!(s.status, PayloadStatusEnum::Accepted)),
        other => panic!("expected an answer, got {other:?}"),
    }
    assert!(matches!(rx.await.expect("check released").status, PayloadStatusEnum::Valid));

    let requests = observed.requests.lock().unwrap();
    let (hash, profile, rlp) = raw_engine::decode_foreign_body(&requests[0].1).expect("a valid frame");
    assert_eq!(hash, B256::repeat_byte(0xAB));
    assert_eq!(profile, N42HeaderProfile::Gov5H2);
    assert_eq!(rlp, &[0xc0, 1, 2, 3]);
}

#[tokio::test]
async fn a_compact_body_uses_its_own_request_kind() {
    env();
    let (addr, observed) = serve(Arc::new(|kind, _| {
        assert_eq!(kind, request::COMPACT_BODY);
        Some(frame(reply::VALUE, &status(PayloadStatusEnum::Valid)))
    }))
    .await;
    let client = EngineApiClient::new(Endpoint(addr));
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let outcome = client.new_payload_body_checked(ExecutionPath::LIVE_SEQUENTIAL, &body(true), tx).await;
    assert!(matches!(outcome, BodyOutcome::Answered(Ok(_))), "{outcome:?}");
    assert_eq!(observed.requests.lock().unwrap()[0].0, request::COMPACT_BODY);
}

#[tokio::test]
async fn a_body_the_layer_cannot_assemble_names_the_transactions_it_needs() {
    env();
    let (addr, _) = serve(Arc::new(|_, _| Some(frame(reply::NEED_TXNS, &raw_engine::encode_need_txns(&[3, 9, 40]))))).await;
    let client = EngineApiClient::new(Endpoint(addr));
    let (tx, _rx) = tokio::sync::oneshot::channel();
    match client.new_payload_body_checked(ExecutionPath::LIVE_SEQUENTIAL, &body(true), tx).await {
        BodyOutcome::NeedTxns(indices) => assert_eq!(indices, vec![3, 9, 40]),
        other => panic!("expected NeedTxns, got {other:?}"),
    }
}

#[tokio::test]
async fn a_body_refused_before_any_answer_is_not_this_way() {
    env();
    let (addr, _) = serve(Arc::new(|_, _| Some(frame(reply::ERROR, b"unknown parent")))).await;
    let client = EngineApiClient::new(Endpoint(addr));
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let outcome = client.new_payload_body_checked(ExecutionPath::LIVE_SEQUENTIAL, &body(false), tx).await;
    assert!(matches!(outcome, BodyOutcome::NotThisWay), "{outcome:?}");
}

#[tokio::test]
async fn a_failure_after_the_check_is_this_blocks_failure_and_is_not_resent() {
    env();
    // The check goes out, then a frame the client cannot read: the execution
    // layer has the block, so the caller must not send it a second time.
    let (addr, _) = serve(Arc::new(|_, _| {
        let mut out = frame(reply::CHECKED, &status(PayloadStatusEnum::Valid));
        out.extend(frame(99, b"?"));
        Some(out)
    }))
    .await;
    let client = EngineApiClient::new(Endpoint(addr));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let outcome = client.new_payload_body_checked(ExecutionPath::LIVE_SEQUENTIAL, &body(false), tx).await;
    assert!(matches!(outcome, BodyOutcome::Answered(Err(_))), "{outcome:?}");
    assert!(rx.await.is_ok(), "the check was still delivered");
}

#[tokio::test]
async fn a_path_that_is_not_the_canonical_engine_api_is_not_this_way() {
    env();
    let client = EngineApiClient::new(Endpoint("127.0.0.1:1".parse().unwrap()));
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let outcome = client.new_payload_body_checked(ExecutionPath::HISTORICAL_PEVM, &body(false), tx).await;
    assert!(matches!(outcome, BodyOutcome::NotThisWay));
}

// ---- hashed build answers --------------------------------------------------

fn header(number: u64) -> Header {
    Header {
        number,
        timestamp: 1_700_000_000,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(7),
        withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::ZERO),
        ..Default::default()
    }
}

fn block_rlp(header: Header) -> Vec<u8> {
    let block = alloy_consensus::Block::<TxEnvelope> {
        header,
        body: BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: Some(Withdrawals::new(Vec::new())) },
    };
    alloy_rlp::encode(&block)
}

/// The block plus the hash tail: `marker | u32 n | hashes [| u32 frames | frames * (id, count)]`.
fn hashed_answer(number: u64, tail: &[u8]) -> Vec<u8> {
    let mut out = frame(1, &block_rlp(header(number)));
    out.push(0); // no requests
    out.push(0); // no access list
    out.extend_from_slice(tail);
    out
}

fn hash_tail(marker: u8, hashes: &[B256], frames: &[(B256, u32)]) -> Vec<u8> {
    let mut out = vec![marker];
    out.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        out.extend_from_slice(h.as_slice());
    }
    if marker == 2 {
        out.extend_from_slice(&(frames.len() as u32).to_le_bytes());
        for (id, count) in frames {
            out.extend_from_slice(id.as_slice());
            out.extend_from_slice(&count.to_le_bytes());
        }
    }
    out
}

#[tokio::test]
async fn a_hashed_collection_carries_the_transaction_hashes_and_the_frame_layout() {
    env();
    let hashes = vec![B256::repeat_byte(1), B256::repeat_byte(2)];
    let frames = vec![(B256::repeat_byte(7), 2u32)];
    let tail = hash_tail(2, &hashes, &frames);
    let (addr, observed) = serve(Arc::new(move |kind, _| {
        assert_eq!(kind, request::GET_PAYLOAD_HASHED);
        Some(hashed_answer(6, &tail))
    }))
    .await;
    let client = EngineApiClient::new(Endpoint(addr));
    let built = client
        .resolve_payload(PayloadId::new([5; 8]), ResolveKind::WaitForPending)
        .await
        .expect("present")
        .expect("built");
    assert_eq!(built.tx_hashes, hashes);
    assert_eq!(built.frame_layout, frames);
    assert_eq!(observed.requests.lock().unwrap()[0].1, vec![5; 8]);
}

#[tokio::test]
async fn a_plain_hash_tail_has_no_frame_layout() {
    env();
    let hashes = vec![B256::repeat_byte(3)];
    let tail = hash_tail(1, &hashes, &[]);
    let (addr, _) = serve(Arc::new(move |_, _| Some(hashed_answer(6, &tail)))).await;
    let client = EngineApiClient::new(Endpoint(addr));
    let built = client
        .resolve_payload(PayloadId::new([5; 8]), ResolveKind::WaitForPending)
        .await
        .expect("present")
        .expect("built");
    assert_eq!(built.tx_hashes, hashes);
    assert!(built.frame_layout.is_empty());
}

#[tokio::test]
async fn an_unknown_tail_marker_means_no_hashes() {
    env();
    let (addr, _) = serve(Arc::new(|_, _| Some(hashed_answer(6, &[0])))).await;
    let client = EngineApiClient::new(Endpoint(addr));
    let built = client
        .resolve_payload(PayloadId::new([5; 8]), ResolveKind::WaitForPending)
        .await
        .expect("present")
        .expect("built");
    assert!(built.tx_hashes.is_empty());
    assert_eq!(built.number, 6);
}

#[tokio::test]
async fn a_build_on_the_sealed_block_asks_for_hashes_and_reads_them() {
    env();
    let hashes = vec![B256::repeat_byte(9)];
    let tail = hash_tail(1, &hashes, &[]);
    let (addr, _) = serve(Arc::new(move |kind, frame_bytes| {
        assert_eq!(kind, request::BUILD_ON_OWN);
        let (_, _, _, want_hashes) = raw_engine::decode_build_on_own(frame_bytes).expect("decodes");
        assert!(want_hashes, "the request asked for the hash tail");
        Some(hashed_answer(6, &tail))
    }))
    .await;
    let client = EngineApiClient::new(Endpoint(addr));
    let attrs = PayloadAttributes {
        timestamp: 2,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        slot_number: None,
        target_gas_limit: None,
    };
    let built = client.build_on_own_block(&header(5), attrs).await.expect("answered").expect("built");
    assert_eq!(built.tx_hashes, hashes);
}

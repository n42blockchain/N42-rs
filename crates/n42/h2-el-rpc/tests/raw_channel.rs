// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loopback raw payload channel, against a scripted TCP "execution layer".
//!
//! The client learns the channel's address from `n42Engine_payloadEndpoint`
//! and then speaks a small binary protocol (`n42_h2_execution::raw_engine`).
//! What matters is not the framing but the contract around it: what a request
//! looks like on the wire, which answers are taken, and which failures fall
//! back to the JSON Engine API instead of being surfaced -- a wrong fallback
//! either loses a block or imports it twice.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use alloy_consensus::{BlockBody, Header, TxEnvelope};
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState, PayloadAttributes,
    PayloadId, PayloadStatus, PayloadStatusEnum,
};
use n42_h2_el_rpc::{EngineApiClient, JsonRpcTransport, RpcError, TransportError};
use n42_h2_execution::raw_engine::{self, reply, request};
use n42_h2_execution::{ExecutionLayer, ExecutionPath, ResolveKind};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the scripted server does with a request: bytes to write back, or
/// `None` to close the connection without answering.
type Script = dyn Fn(u8, &[u8]) -> Option<Vec<u8>> + Send + Sync;

/// The scripted execution layer's observations.
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

/// `kind | u32 len | body`.
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn status(s: PayloadStatusEnum) -> Vec<u8> {
    raw_engine::encode_payload_status(&PayloadStatus { status: s, latest_valid_hash: Some(B256::repeat_byte(0x11)) })
}

type JsonAnswer = dyn Fn(&str, &[Value]) -> Result<Value, TransportError> + Send + Sync;

/// A JSON-RPC side that knows the endpoint method and whatever else the test
/// scripts, recording every method name it was asked.
#[derive(Clone)]
struct Json {
    calls: Arc<Mutex<Vec<String>>>,
    answer: Arc<JsonAnswer>,
}

impl Json {
    fn new(answer: impl Fn(&str, &[Value]) -> Result<Value, TransportError> + Send + Sync + 'static) -> Self {
        Self { calls: Arc::default(), answer: Arc::new(answer) }
    }

    /// Serves the endpoint address; everything else is "method not found".
    fn at(addr: std::net::SocketAddr) -> Self {
        Self::new(move |method, _| {
            if method == "n42Engine_payloadEndpoint" {
                Ok(json!(addr.to_string()))
            } else {
                Err(rpc(-32601))
            }
        })
    }

    fn methods(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn count(&self, method: &str) -> usize {
        self.methods().iter().filter(|m| *m == method).count()
    }
}

fn rpc(code: i64) -> TransportError {
    TransportError::Rpc(RpcError { code, message: "scripted".into() })
}

#[async_trait::async_trait]
impl JsonRpcTransport for Json {
    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, TransportError> {
        self.calls.lock().unwrap().push(method.to_string());
        (self.answer)(method, &params)
    }
}

fn v1(number: u64) -> ExecutionPayloadV1 {
    ExecutionPayloadV1 {
        parent_hash: B256::repeat_byte(1),
        fee_recipient: Default::default(),
        state_root: B256::repeat_byte(2),
        receipts_root: B256::repeat_byte(3),
        logs_bloom: Default::default(),
        prev_randao: B256::ZERO,
        block_number: number,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1_700_000_000,
        extra_data: Default::default(),
        base_fee_per_gas: alloy_primitives::U256::from(7u64),
        block_hash: B256::repeat_byte(9),
        transactions: Vec::new(),
        difficulty: Default::default(),
        nonce: Default::default(),
    }
}

fn cancun_data(number: u64) -> ExecutionData {
    ExecutionData::new(
        ExecutionPayload::V3(ExecutionPayloadV3 {
            payload_inner: ExecutionPayloadV2 { payload_inner: v1(number), withdrawals: Vec::new() },
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }),
        ExecutionPayloadSidecar::v3(CancunPayloadFields {
            parent_beacon_block_root: B256::repeat_byte(0xBB),
            versioned_hashes: Vec::new(),
        }),
    )
}

/// A Cancun-shaped header: the optional fields are positional in RLP.
fn cancun_header(number: u64, beacon_root: B256) -> Header {
    Header {
        number,
        timestamp: 1_700_000_000,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(7),
        withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(beacon_root),
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

/// A `GET_PAYLOAD` answer: `1 | u32 len | block | requests flag | bal flag`.
fn built_answer(header: Header) -> Vec<u8> {
    let mut out = frame(1, &block_rlp(header));
    out.push(0);
    out.push(0);
    out
}

fn valid(out: &PayloadStatus) -> bool {
    matches!(out.status, PayloadStatusEnum::Valid)
}

fn json_valid_status() -> Value {
    json!({"status": "VALID", "latestValidHash": null, "validationError": null})
}

// ---- newPayload ----------------------------------------------------------

#[tokio::test]
async fn new_payload_goes_over_the_channel_and_the_connection_is_reused() {
    let (addr, observed) = serve(Arc::new(|kind, _| {
        assert_eq!(kind, request::NEW_PAYLOAD);
        Some(frame(reply::VALUE, &status(PayloadStatusEnum::Valid)))
    }))
    .await;
    let json = Json::at(addr);
    let client = EngineApiClient::new(json.clone());

    let data = cancun_data(7);
    let first = client.new_payload(data.clone()).await.expect("answers");
    assert!(valid(&first));
    assert_eq!(first.latest_valid_hash, Some(B256::repeat_byte(0x11)));
    client.new_payload(cancun_data(8)).await.expect("answers");

    // The frame on the wire is the payload, decodable by the execution layer.
    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let sent = raw_engine::decode_execution_data(&requests[0].1).expect("a valid frame");
    assert_eq!(sent.block_hash(), data.block_hash());
    assert_eq!(sent.parent_hash(), data.parent_hash());
    // One connection, one endpoint lookup, and no JSON newPayload at all.
    assert_eq!(observed.connections.load(Ordering::SeqCst), 1);
    assert_eq!(json.count("n42Engine_payloadEndpoint"), 1);
    assert_eq!(json.count("engine_newPayloadV3"), 0);
}

#[tokio::test]
async fn an_invalid_status_comes_back_as_a_status_not_an_error() {
    let (addr, _) = serve(Arc::new(|_, _| {
        Some(frame(reply::VALUE, &status(PayloadStatusEnum::Invalid { validation_error: "bad root".into() })))
    }))
    .await;
    let client = EngineApiClient::new(Json::at(addr));
    let got = client.new_payload(cancun_data(7)).await.expect("a status");
    match got.status {
        PayloadStatusEnum::Invalid { validation_error } => assert_eq!(validation_error, "bad root"),
        other => panic!("expected invalid, got {other:?}"),
    }
}

#[tokio::test]
async fn a_channel_error_reply_falls_back_to_json_and_the_next_call_reconnects() {
    let (addr, observed) = serve(Arc::new(|_, _| Some(frame(reply::ERROR, b"no such parent")))).await;
    let json = {
        let base = Json::at(addr);
        Json::new(move |method, params| match method {
            "engine_newPayloadV3" => Ok(json_valid_status()),
            _ => (base.answer)(method, params),
        })
    };
    let client = EngineApiClient::new(json.clone());
    let got = client.new_payload(cancun_data(7)).await.expect("the JSON road answers");
    assert!(valid(&got));
    assert_eq!(json.count("engine_newPayloadV3"), 1);

    // The failed connection was dropped, not kept: the next call opens a new one.
    client.new_payload(cancun_data(8)).await.expect("answers");
    assert_eq!(observed.connections.load(Ordering::SeqCst), 2);
    assert_eq!(json.count("engine_newPayloadV3"), 2);
}

#[tokio::test]
async fn an_unknown_reply_kind_falls_back_to_json() {
    let (addr, _) = serve(Arc::new(|_, _| Some(vec![9u8]))).await;
    let base = Json::at(addr);
    let json = Json::new(move |m, p| match m {
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => (base.answer)(m, p),
    });
    let client = EngineApiClient::new(json.clone());
    assert!(valid(&client.new_payload(cancun_data(7)).await.unwrap()));
    assert_eq!(json.count("engine_newPayloadV3"), 1);
}

#[tokio::test]
async fn a_server_that_hangs_up_falls_back_to_json() {
    let (addr, _) = serve(Arc::new(|_, _| None)).await;
    let base = Json::at(addr);
    let json = Json::new(move |m, p| match m {
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => (base.answer)(m, p),
    });
    let client = EngineApiClient::new(json.clone());
    assert!(valid(&client.new_payload(cancun_data(7)).await.unwrap()));
}

// ---- endpoint discovery --------------------------------------------------

#[tokio::test]
async fn an_execution_layer_without_the_endpoint_method_is_asked_once_and_json_is_used() {
    let json = Json::new(|method, _| match method {
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => Err(rpc(-32601)),
    });
    let client = EngineApiClient::new(json.clone());
    client.new_payload(cancun_data(7)).await.expect("json answers");
    client.new_payload(cancun_data(8)).await.expect("json answers");
    // "Not found" is a stable answer and is remembered.
    assert_eq!(json.count("n42Engine_payloadEndpoint"), 1);
    assert_eq!(json.count("engine_newPayloadV3"), 2);
}

#[tokio::test]
async fn an_unparsable_endpoint_address_disables_the_channel() {
    let json = Json::new(|method, _| match method {
        "n42Engine_payloadEndpoint" => Ok(json!("not an address")),
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => Err(rpc(-32601)),
    });
    let client = EngineApiClient::new(json.clone());
    assert!(valid(&client.new_payload(cancun_data(7)).await.unwrap()));
    assert_eq!(json.count("engine_newPayloadV3"), 1);
}

#[tokio::test]
async fn a_non_string_endpoint_answer_disables_the_channel() {
    let json = Json::new(|method, _| match method {
        "n42Engine_payloadEndpoint" => Ok(json!(42)),
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => Err(rpc(-32601)),
    });
    let client = EngineApiClient::new(json.clone());
    assert!(valid(&client.new_payload(cancun_data(7)).await.unwrap()));
}

#[tokio::test]
async fn a_failed_endpoint_lookup_is_not_remembered() {
    // A transport hiccup says nothing about whether the channel exists, so the
    // next call asks again.
    let json = Json::new(|method, _| match method {
        "n42Engine_payloadEndpoint" => Err(TransportError::Transport("connection reset".into())),
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => Err(rpc(-32601)),
    });
    let client = EngineApiClient::new(json.clone());
    client.new_payload(cancun_data(7)).await.unwrap();
    client.new_payload(cancun_data(8)).await.unwrap();
    assert_eq!(json.count("n42Engine_payloadEndpoint"), 2);
}

// ---- own block by header --------------------------------------------------

#[tokio::test]
async fn an_own_block_is_imported_by_its_header() {
    let (addr, observed) = serve(Arc::new(|kind, _| {
        assert_eq!(kind, request::OWN_BLOCK);
        Some(frame(1, &status(PayloadStatusEnum::Valid)))
    }))
    .await;
    let json = Json::at(addr);
    let client = EngineApiClient::new(json.clone());
    let header = cancun_header(5, B256::repeat_byte(4));

    let got = client.import_own_block(Some(&header), cancun_data(5)).await.expect("answers");
    assert!(valid(&got));
    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1, alloy_rlp::encode(&header), "the frame is the sealed header's RLP");
    assert_eq!(json.count("engine_newPayloadV3"), 0, "the payload itself is not sent");
}

#[tokio::test]
async fn a_refused_own_block_by_header_sends_the_payload() {
    let (addr, observed) = serve(Arc::new(|kind, _| match kind {
        request::OWN_BLOCK => Some(frame(2, b"no build kept")),
        request::NEW_PAYLOAD => Some(frame(reply::VALUE, &status(PayloadStatusEnum::Valid))),
        other => panic!("unexpected request {other}"),
    }))
    .await;
    let client = EngineApiClient::new(Json::at(addr));
    let header = cancun_header(5, B256::repeat_byte(4));
    let got = client.import_own_block(Some(&header), cancun_data(5)).await.expect("answers");
    assert!(valid(&got));
    let kinds: Vec<u8> = observed.requests.lock().unwrap().iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec![request::OWN_BLOCK, request::NEW_PAYLOAD]);
}

#[tokio::test]
async fn without_a_header_the_own_block_is_sent_as_a_payload() {
    let (addr, observed) = serve(Arc::new(|kind, _| {
        assert_eq!(kind, request::NEW_PAYLOAD);
        Some(frame(reply::VALUE, &status(PayloadStatusEnum::Valid)))
    }))
    .await;
    let client = EngineApiClient::new(Json::at(addr));
    client.import_own_block(None, cancun_data(5)).await.expect("answers");
    assert_eq!(observed.requests.lock().unwrap().len(), 1);
}

// ---- checked newPayload ---------------------------------------------------

#[tokio::test]
async fn a_checked_import_releases_the_check_before_the_final_answer() {
    let (addr, _) = serve(Arc::new(|kind, _| {
        assert_eq!(kind, request::NEW_PAYLOAD);
        let mut out = frame(reply::CHECKED, &status(PayloadStatusEnum::Valid));
        out.extend(frame(reply::VALUE, &status(PayloadStatusEnum::Accepted)));
        Some(out)
    }))
    .await;
    let client = EngineApiClient::new(Json::at(addr));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let done = client
        .new_payload_checked(ExecutionPath::LIVE_SEQUENTIAL, cancun_data(7), tx)
        .await
        .expect("answers");
    // The final answer is the execution result; the check arrived on the side channel.
    assert!(matches!(done.status, PayloadStatusEnum::Accepted));
    let checked = rx.await.expect("the check was released");
    assert!(valid(&checked));
}

#[tokio::test]
async fn a_checked_import_error_falls_back_to_the_json_road() {
    let (addr, _) = serve(Arc::new(|_, _| Some(frame(reply::ERROR, b"boom")))).await;
    let base = Json::at(addr);
    let json = Json::new(move |m, p| match m {
        "engine_newPayloadV3" => Ok(json_valid_status()),
        _ => (base.answer)(m, p),
    });
    let client = EngineApiClient::new(json.clone());
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let got = client
        .new_payload_checked(ExecutionPath::LIVE_SEQUENTIAL, cancun_data(7), tx)
        .await
        .expect("json answers");
    assert!(valid(&got));
    assert_eq!(json.count("engine_newPayloadV3"), 1);
}

#[tokio::test]
async fn a_path_the_engine_api_does_not_serve_is_refused_before_any_io() {
    let json = Json::new(|_, _| panic!("no call is expected"));
    let client = EngineApiClient::new(json);
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let err = client
        .new_payload_checked(ExecutionPath::HISTORICAL_PEVM, cancun_data(7), tx)
        .await
        .expect_err("refused");
    assert!(err.to_string().contains("historical_pevm"), "{err}");
}

// ---- getPayload ------------------------------------------------------------

#[tokio::test]
async fn a_build_is_collected_over_the_channel_with_the_beacon_root_it_started_under() {
    let root = B256::repeat_byte(0x5A);
    let (addr, observed) = serve(Arc::new(move |kind, _| {
        assert_eq!(kind, request::GET_PAYLOAD);
        Some(built_answer(cancun_header(6, root)))
    }))
    .await;
    let base = Json::at(addr);
    let json = Json::new(move |m, p| match m {
        "engine_forkchoiceUpdatedV4" => Ok(json!({
            "payloadStatus": {"status": "VALID", "latestValidHash": null},
            "payloadId": "0x0102030405060708",
        })),
        _ => (base.answer)(m, p),
    });
    let client = EngineApiClient::new(json.clone());
    let attrs = PayloadAttributes {
        timestamp: 1_700_000_001,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(root),
        slot_number: None,
        target_gas_limit: None,
    };
    let state = ForkchoiceState {
        head_block_hash: B256::repeat_byte(1),
        safe_block_hash: B256::repeat_byte(1),
        finalized_block_hash: B256::repeat_byte(1),
    };
    let updated = client.fork_choice_updated_with_attrs(state, attrs).await.expect("started");
    let id = updated.payload_id.expect("a payload id");

    let built = client.resolve_payload(id, ResolveKind::WaitForPending).await.expect("present").expect("built");
    assert_eq!(built.number, 6);
    assert_eq!(built.tx_count, 0);
    assert_eq!(built.execution_data.sidecar.parent_beacon_block_root(), Some(root));
    assert!(built.header.is_some(), "the raw path carries the header");
    // The id went out as its eight bytes.
    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests[0].1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(json.count("engine_getPayloadV6"), 0);
}

#[tokio::test]
async fn an_absent_build_on_the_channel_is_none() {
    let (addr, _) = serve(Arc::new(|_, _| Some(vec![0u8]))).await;
    let client = EngineApiClient::new(Json::at(addr));
    assert!(client.resolve_payload(PayloadId::new([9; 8]), ResolveKind::WaitForPending).await.is_none());
}

#[tokio::test]
async fn a_refused_build_on_the_channel_carries_the_message() {
    let (addr, _) = serve(Arc::new(|_, _| Some(frame(2, b"payload too old")))).await;
    let client = EngineApiClient::new(Json::at(addr));
    let got = client.resolve_payload(PayloadId::new([9; 8]), ResolveKind::WaitForPending).await.expect("an answer");
    assert!(got.expect_err("an error").to_string().contains("payload too old"));
}

#[tokio::test]
async fn a_broken_channel_falls_through_to_the_raw_json_method() {
    let root = B256::repeat_byte(3);
    let (addr, _) = serve(Arc::new(|_, _| Some(vec![7u8]))).await;
    let rlp = block_rlp(cancun_header(6, root));
    let base = Json::at(addr);
    let json = Json::new(move |m, p| match m {
        "n42Engine_getPayloadRaw" => Ok(json!({"block": format!("0x{}", alloy_primitives::hex::encode(&rlp))})),
        _ => (base.answer)(m, p),
    });
    let client = EngineApiClient::new(json.clone());
    let built = client
        .resolve_payload(PayloadId::new([1; 8]), ResolveKind::WaitForPending)
        .await
        .expect("present")
        .expect("built");
    assert_eq!(built.number, 6);
    assert_eq!(json.count("n42Engine_getPayloadRaw"), 1);
}

// ---- build on own block ----------------------------------------------------

#[tokio::test]
async fn a_build_on_the_sealed_block_that_the_execution_layer_declines_is_none() {
    let (addr, _) = serve(Arc::new(|_, _| Some(vec![0u8]))).await;
    let client = EngineApiClient::new(Json::at(addr));
    let attrs = PayloadAttributes {
        timestamp: 2,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        slot_number: None,
        target_gas_limit: None,
    };
    let header = cancun_header(5, B256::ZERO);
    assert!(client.build_on_own_block(&header, attrs).await.is_none());
}

#[tokio::test]
async fn a_refused_or_broken_build_on_the_sealed_block_is_none_and_not_an_error() {
    let attrs = || PayloadAttributes {
        timestamp: 2,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::ZERO),
        slot_number: None,
        target_gas_limit: None,
    };
    let header = cancun_header(5, B256::ZERO);
    let (addr, _) = serve(Arc::new(|_, _| Some(frame(2, b"no direct builder")))).await;
    let client = EngineApiClient::new(Json::at(addr));
    assert!(client.build_on_own_block(&header, attrs()).await.is_none());

    // An unknown frame kind poisons the connection; it is dropped, not reused.
    let (addr, _) = serve(Arc::new(|_, _| Some(vec![9u8]))).await;
    let client = EngineApiClient::new(Json::at(addr));
    assert!(client.build_on_own_block(&header, attrs()).await.is_none());
}

#[tokio::test]
async fn a_build_on_the_sealed_block_returns_the_block_the_layer_built() {
    let (addr, observed) = serve(Arc::new(|kind, frame_bytes| {
        assert_eq!(kind, request::BUILD_ON_OWN);
        let (parent, attrs, hint, _) = raw_engine::decode_build_on_own(frame_bytes).expect("decodes");
        assert!(hint.is_none(), "no chain hint without a sealer");
        Some(built_answer(cancun_header(parent.number + 1, attrs.parent_beacon_block_root.unwrap())))
    }))
    .await;
    let client = EngineApiClient::new(Json::at(addr));
    let attrs = PayloadAttributes {
        timestamp: 2,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::repeat_byte(8)),
        slot_number: None,
        target_gas_limit: None,
    };
    let parent = cancun_header(5, B256::ZERO);
    let built = client.build_on_own_block(&parent, attrs).await.expect("answered").expect("built");
    assert_eq!(built.number, 6);
    assert_eq!(built.execution_data.sidecar.parent_beacon_block_root(), Some(B256::repeat_byte(8)));
    assert_eq!(observed.requests.lock().unwrap().len(), 1);
}

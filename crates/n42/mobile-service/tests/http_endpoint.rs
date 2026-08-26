// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HTTP front end over a real socket.
//!
//! `rpc.rs` covers the method surface without a transport. What is left to check
//! is the transport itself: that a phone speaking ordinary JSON-RPC over HTTP
//! gets a well-formed answer, that a bad request is answered rather than
//! dropping the connection, and that an oversized body is refused before the
//! node allocates for it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use alloy_primitives::B256;
use n42_h2_primitives::bls::BlsSecretKey;
use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
use n42_mobile_service::{http, MobileService};
use n42_mobile_verify::receipt::encode_receipt;
use n42_mobile_verify::sign_receipt;
use serde_json::{json, Value};

const BLOCK: B256 = B256::repeat_byte(0x11);
const ROOT: B256 = B256::repeat_byte(0x22);

/// Starts the endpoint on an ephemeral port and returns it with the service.
fn start() -> (u16, Arc<Mutex<MobileService>>) {
    let mut service = MobileService::new(
        H2V4ChainIdentity {
            chain_id: 96,
            genesis_hash: B256::repeat_byte(0x42),
        },
        1,
    );
    service
        .record_commit(1, BLOCK, 1, QuorumCertificate::genesis(), Some(ROOT))
        .expect("recording a commit");
    let service = Arc::new(Mutex::new(service));

    let listener = http::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let served = Arc::clone(&service);
    std::thread::spawn(move || {
        let _ = http::serve_on(&listener, &served);
    });
    (port, service)
}

/// Sends a raw request and returns the response body.
fn post(port: u16, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or(response)
}

fn call(port: u16, method: &str, params: Value) -> Value {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    serde_json::from_str(&post(port, &request.to_string())).expect("a JSON response")
}

/// The whole thing a phone does: learn the head, register, report, read back the
/// aggregate.
#[test]
fn a_phone_can_complete_the_round_trip_over_http() {
    let (port, service) = start();

    let finality = call(port, "mobile_finality", json!([]));
    assert_eq!(finality["result"]["block_hash"], json!(BLOCK.to_string()));
    let envelope = finality["result"]["decide_envelope"]
        .as_str()
        .expect("a hex envelope");
    // The proof the phone gets is a decodable v4 envelope, not a summary.
    let bytes = hex::decode(envelope.trim_start_matches("0x")).expect("hex");
    n42_h2_wire::h2_v4::decode_envelope(
        &bytes,
        H2V4ChainIdentity {
            chain_id: 96,
            genesis_hash: B256::repeat_byte(0x42),
        },
    )
    .expect("the served envelope verifies as v4");

    let key = BlsSecretKey::random().expect("keygen");
    let registered = call(
        port,
        "mobile_registerVerifier",
        json!([format!("0x{}", hex::encode(key.public_key().to_bytes()))]),
    );
    assert_eq!(registered["result"], json!(0));

    let receipt = sign_receipt(BLOCK, 1, ROOT, 0, &key);
    let submitted = call(
        port,
        "mobile_submitReceipt",
        json!([format!("0x{}", hex::encode(encode_receipt(&receipt)))]),
    );
    assert_eq!(submitted["result"]["accepted"], json!(true));
    assert_eq!(submitted["result"]["attested"], json!(true));

    let attestation = call(port, "mobile_attestation", json!([BLOCK.to_string()]));
    assert_eq!(attestation["result"]["participant_count"], json!(1));

    // The aggregate the endpoint served verifies against the registry the node
    // built — which is what makes it worth anything to a third party.
    let parsed: n42_mobile_verify::AggregatedAttestation =
        serde_json::from_value(attestation["result"].clone()).expect("an attestation");
    let guard = service.lock().expect("lock");
    parsed.verify(guard.registry()).expect("aggregate verifies");
}

#[test]
fn a_refusal_comes_back_as_a_json_rpc_error_with_its_code() {
    let (port, _service) = start();
    let key = BlsSecretKey::random().expect("keygen");
    let receipt = sign_receipt(BLOCK, 1, ROOT, 0, &key);

    // Never registered.
    let response = call(
        port,
        "mobile_submitReceipt",
        json!([format!("0x{}", hex::encode(encode_receipt(&receipt)))]),
    );
    assert_eq!(
        response["error"]["code"],
        json!(n42_mobile_service::rpc::codes::UNKNOWN_VERIFIER)
    );
    assert!(response.get("result").is_none());
}

#[test]
fn malformed_json_is_answered_rather_than_dropped() {
    // A phone that sends garbage should learn that it did, not see a reset
    // connection it will read as a network problem and retry forever.
    let (port, _service) = start();
    let response: Value = serde_json::from_str(&post(port, "{not json")).expect("a JSON response");
    assert_eq!(response["error"]["code"], json!(-32700));
}

#[test]
fn an_oversized_body_is_refused_before_it_is_read() {
    let (port, _service) = start();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // Claims a megabyte and sends nothing. If the limit were enforced after
    // reading, this would hold a buffer and a connection open on a promise.
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048576\r\n\r\n"
    )
    .expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 400"), "got: {response}");
}

#[test]
fn a_get_is_refused() {
    let (port, _service) = start();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write!(stream, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 400"), "got: {response}");
}

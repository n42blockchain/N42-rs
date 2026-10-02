// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `HttpTransport` against an in-process HTTP server on a loopback port.
//!
//! The server is a bare `tokio` listener: it reads one request (headers and a
//! `Content-Length` body), records it, and answers from a handler. The
//! assertions are about what went on the wire (method, JWT, body shape) and
//! how each kind of answer is mapped to a `TransportError`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_rpc_types_engine::JwtSecret;
use n42_h2_el_rpc::{HttpTransport, JsonRpcTransport, TransportError, UNKNOWN_PAYLOAD};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

const SECRET_HEX: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

/// One request as the server read it.
#[derive(Clone, Debug)]
struct Seen {
    /// The `Authorization` header value, original case.
    authorization: Option<String>,
    body: Value,
}

/// What the handler decides for one request: `None` closes the connection
/// without answering, `Some((status, body))` answers.
type Handler = dyn Fn(usize, &Seen) -> Option<(u16, String)> + Send + Sync;

async fn serve(handler: Arc<Handler>) -> (Url, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let url = Url::parse(&format!("http://{}/", listener.local_addr().expect("addr"))).expect("url");
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let handler = Arc::clone(&handler);
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let head_end = loop {
                    let mut chunk = [0u8; 4096];
                    let Ok(n) = stream.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let want: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                while buf.len() < head_end + want {
                    let mut chunk = [0u8; 4096];
                    let Ok(n) = stream.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body: Value = serde_json::from_slice(&buf[head_end..head_end + want]).unwrap_or(Value::Null);
                let seen = Seen { authorization: header("authorization"), body };
                let index = {
                    let mut log = log.lock().expect("not poisoned");
                    log.push(seen.clone());
                    log.len() - 1
                };
                let Some((status, answer)) = handler(index, &seen) else { return };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    (url, seen)
}

fn transport(url: Url, timeout: Duration) -> HttpTransport {
    HttpTransport::new(url, JwtSecret::from_hex(SECRET_HEX).expect("secret"), timeout).expect("builds")
}

fn ok_with(result: Value) -> Arc<Handler> {
    Arc::new(move |_, seen| {
        Some((200, json!({"jsonrpc": "2.0", "id": seen.body["id"], "result": result}).to_string()))
    })
}

fn dead_url() -> Url {
    // Bind and drop to get a port nothing listens on.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap()
}

#[tokio::test]
async fn a_call_sends_a_jsonrpc_body_and_returns_the_result() {
    let (url, seen) = serve(ok_with(json!("0x2a"))).await;
    let t = transport(url, Duration::from_secs(5));
    let got = t.call("eth_blockNumber", vec![json!("a"), json!(2)]).await.expect("answers");
    assert_eq!(got, json!("0x2a"));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body["jsonrpc"], "2.0");
    assert_eq!(seen[0].body["method"], "eth_blockNumber");
    assert_eq!(seen[0].body["params"], json!(["a", 2]));
}

#[tokio::test]
async fn the_bearer_token_validates_against_the_shared_secret() {
    let (url, seen) = serve(ok_with(json!(1))).await;
    let t = transport(url, Duration::from_secs(5));
    t.call("m", vec![]).await.expect("answers");
    let auth = seen.lock().unwrap()[0].authorization.clone().expect("an authorization header");
    let token = auth.strip_prefix("Bearer ").expect("a bearer scheme");
    JwtSecret::from_hex(SECRET_HEX).unwrap().validate(token).expect("the execution layer would accept it");
    // A different secret must not.
    let other = JwtSecret::from_hex("0x0202020202020202020202020202020202020202020202020202020202020202").unwrap();
    assert!(other.validate(token).is_err());
}

#[tokio::test]
async fn request_ids_increase_per_call() {
    let (url, seen) = serve(ok_with(json!(null))).await;
    let t = transport(url, Duration::from_secs(5));
    t.call("a", vec![]).await.unwrap();
    t.call("b", vec![]).await.unwrap();
    let seen = seen.lock().unwrap();
    let first = seen[0].body["id"].as_u64().unwrap();
    let second = seen[1].body["id"].as_u64().unwrap();
    assert!(second > first, "ids {first} then {second}");
}

#[tokio::test]
async fn an_rpc_error_keeps_its_code_and_message() {
    let handler: Arc<Handler> = Arc::new(|_, _| {
        Some((200, json!({"jsonrpc": "2.0", "id": 1, "error": {"code": UNKNOWN_PAYLOAD, "message": "Unknown payload"}}).to_string()))
    });
    let (url, _) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    match t.call("engine_getPayloadV3", vec![]).await {
        Err(TransportError::Rpc(e)) => {
            assert_eq!(e.code, UNKNOWN_PAYLOAD);
            assert_eq!(e.message, "Unknown payload");
        }
        other => panic!("expected an rpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_401_is_reported_as_a_jwt_problem() {
    let handler: Arc<Handler> = Arc::new(|_, _| Some((401, "unauthorized".into())));
    let (url, _) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    match t.call("engine_exchangeCapabilities", vec![]).await {
        Err(TransportError::Jwt(msg)) => assert!(msg.contains("jwt secret"), "{msg}"),
        other => panic!("expected a jwt error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_json_answer_is_a_transport_error_naming_the_status() {
    let handler: Arc<Handler> = Arc::new(|_, _| Some((502, "<html>bad gateway</html>".into())));
    let (url, _) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    match t.call("m", vec![]).await {
        Err(TransportError::Transport(msg)) => assert!(msg.contains("502"), "{msg}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_connection_dropped_before_any_response_is_retried_once() {
    // The first connection is closed unanswered (a stale keep-alive in real
    // life); the retry on a fresh connection gets the answer.
    let handler: Arc<Handler> = Arc::new(|index, seen| {
        if index == 0 {
            None
        } else {
            Some((200, json!({"jsonrpc": "2.0", "id": seen.body["id"], "result": "ok"}).to_string()))
        }
    });
    let (url, seen) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    assert_eq!(t.call("m", vec![]).await.expect("the retry answers"), json!("ok"));
    assert_eq!(seen.lock().unwrap().len(), 2, "one failed attempt and one retry");
}

#[tokio::test]
async fn a_second_failure_is_returned_not_retried_again() {
    let handler: Arc<Handler> = Arc::new(|_, _| None);
    let (url, seen) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    assert!(matches!(t.call("m", vec![]).await, Err(TransportError::Transport(_))));
    assert_eq!(seen.lock().unwrap().len(), 2, "exactly two attempts");
}

#[tokio::test]
async fn a_refused_connection_is_a_transport_error() {
    let t = transport(dead_url(), Duration::from_secs(5));
    assert!(matches!(t.call("m", vec![]).await, Err(TransportError::Transport(_))));
}

#[tokio::test]
async fn a_timeout_is_not_retried() {
    // A request that timed out may have been acted on, so it is sent once.
    let handler: Arc<Handler> = Arc::new(|_, _| {
        std::thread::sleep(Duration::from_millis(400));
        None
    });
    let (url, seen) = serve(handler).await;
    let t = transport(url, Duration::from_millis(100));
    assert!(matches!(t.call("m", vec![]).await, Err(TransportError::Transport(_))));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn call_many_sends_one_batch_and_counts_the_elements_without_an_error() {
    let handler: Arc<Handler> = Arc::new(|_, seen| {
        let n = seen.body.as_array().map_or(0, Vec::len);
        let answers: Vec<Value> = (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    json!({"jsonrpc": "2.0", "id": i, "result": "0x1"})
                } else {
                    json!({"jsonrpc": "2.0", "id": i, "error": {"code": -32000, "message": "nonce too low"}})
                }
            })
            .collect();
        Some((200, Value::Array(answers).to_string()))
    });
    let (url, seen) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    let accepted = t
        .call_many("eth_sendRawTransaction", vec![vec![json!("0xaa")], vec![json!("0xbb")], vec![json!("0xcc")]])
        .await;
    assert_eq!(accepted, 2);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "a single HTTP request carries the whole batch");
    let batch = seen[0].body.as_array().expect("a JSON array");
    assert_eq!(batch.len(), 3);
    assert!(batch.iter().all(|e| e["method"] == "eth_sendRawTransaction"));
    assert_eq!(batch[1]["params"], json!(["0xbb"]));
    let ids: std::collections::HashSet<_> = batch.iter().map(|e| e["id"].as_u64().unwrap()).collect();
    assert_eq!(ids.len(), 3, "each element has its own id");
}

#[tokio::test]
async fn call_many_with_nothing_to_send_makes_no_request() {
    let (url, seen) = serve(ok_with(json!(null))).await;
    let t = transport(url, Duration::from_secs(5));
    assert_eq!(t.call_many("m", vec![]).await, 0);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn call_many_counts_a_malformed_answer_as_none_accepted() {
    // An object where an array was expected (a proxy's error page, say).
    let handler: Arc<Handler> = Arc::new(|_, _| Some((200, json!({"error": "nope"}).to_string())));
    let (url, _) = serve(handler).await;
    let t = transport(url, Duration::from_secs(5));
    assert_eq!(t.call_many("m", vec![vec![json!(1)], vec![json!(2)]]).await, 0);
}

#[tokio::test]
async fn call_many_to_a_dead_endpoint_counts_zero() {
    let t = transport(dead_url(), Duration::from_secs(2));
    assert_eq!(t.call_many("m", vec![vec![json!(1)]]).await, 0);
}

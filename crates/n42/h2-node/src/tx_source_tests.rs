// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The transaction source and forwarders against a local JSON-RPC server and
//! a local ingest socket, both on `127.0.0.1:0`. Every wait is bounded.

use super::*;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// A minimal HTTP/1.1 JSON-RPC server: records each request body and answers
/// with whatever `respond` returns for it.
pub(crate) struct MockRpc {
    pub(crate) url: url::Url,
    pub(crate) requests: Arc<Mutex<Vec<Value>>>,
}

impl MockRpc {
    pub(crate) async fn start(respond: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url: url::Url = format!("http://{}/", listener.local_addr().expect("addr")).parse().expect("url");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let log = Arc::clone(&log);
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    loop {
                        // Read one request: the head, then Content-Length bytes.
                        let (head_end, length) = loop {
                            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
                                let length = head
                                    .lines()
                                    .find_map(|line| line.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                                    .unwrap_or(0);
                                break (end + 4, length);
                            }
                            let mut chunk = [0u8; 4096];
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                        };
                        while buffer.len() < head_end + length {
                            let mut chunk = [0u8; 4096];
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let body: Value = serde_json::from_slice(&buffer[head_end..head_end + length]).unwrap_or(Value::Null);
                        buffer.drain(..head_end + length);
                        let reply = respond(&body).to_string();
                        log.lock().expect("log").push(body);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                            reply.len()
                        );
                        if stream.write_all(head.as_bytes()).await.is_err() || stream.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { url, requests }
    }

    pub(crate) fn bodies(&self) -> Vec<Value> {
        self.requests.lock().expect("log").clone()
    }

    pub(crate) fn methods(&self) -> Vec<String> {
        self.bodies()
            .iter()
            .filter_map(|b| b.get("method").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        while !ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(result.is_ok(), "timed out waiting for {what}");
}

fn tx(i: u32) -> Bytes {
    Bytes::from(i.to_be_bytes().to_vec())
}

#[tokio::test]
async fn gossiped_transactions_are_posted_as_raw_transaction_batches() {
    let rpc = MockRpc::start(|_| json!([])).await;
    let (sink, source) = mpsc::channel(4);
    let task = tokio::spawn(forward_transactions(rpc.url.clone(), source));
    sink.send(vec![tx(1), tx(2)]).await.expect("open");
    eventually("the first post", || !rpc.bodies().is_empty()).await;
    let bodies = rpc.bodies();
    let batch = bodies[0].as_array().expect("a JSON-RPC batch");
    assert_eq!(batch.len(), 2);
    for (id, (call, raw)) in batch.iter().zip([tx(1), tx(2)]).enumerate() {
        assert_eq!(call["method"], "eth_sendRawTransaction");
        assert_eq!(call["id"], id);
        assert_eq!(call["params"][0], json!(raw));
    }

    // More than one chunk's worth is split, in order.
    let many: Vec<Bytes> = (0..FORWARD_CHUNK as u32 + 1).map(tx).collect();
    sink.send(many).await.expect("open");
    eventually("both chunks", || rpc.bodies().len() >= 3).await;
    let sizes: Vec<usize> = rpc.bodies()[1..3].iter().map(|b| b.as_array().expect("batch").len()).collect();
    assert_eq!(sizes, vec![FORWARD_CHUNK, 1]);

    drop(sink);
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("ends with its source").expect("no panic");
}

#[tokio::test]
async fn forwarding_to_an_unreachable_pool_drops_the_batch_and_keeps_running() {
    // A port nothing listens on.
    let url = {
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        format!("http://{}/", probe.local_addr().expect("addr")).parse::<url::Url>().expect("url")
    };
    let (sink, source) = mpsc::channel(4);
    let task = tokio::spawn(forward_transactions(url, source));
    sink.send(vec![tx(1)]).await.expect("the forwarder took it");
    sink.send(vec![tx(2)]).await.expect("and is still taking batches after a failure");
    drop(sink);
    tokio::time::timeout(Duration::from_secs(20), task).await.expect("ends with its source").expect("no panic");
}

#[tokio::test]
async fn the_pool_is_polled_through_a_filter_and_each_new_hash_is_fetched_raw() {
    let hashes = [B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3)];
    let calls = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&calls);
    let rpc = MockRpc::start(move |req| {
        let method = req["method"].as_str().unwrap_or_default();
        let result = match method {
            "eth_newPendingTransactionFilter" => json!("0x1"),
            "eth_getFilterChanges" => {
                let mut n = counter.lock().expect("count");
                *n += 1;
                // New hashes once, then nothing.
                if *n == 1 { json!(hashes) } else { json!([]) }
            }
            "eth_getRawTransactionByHash" => match req["params"][0].as_str() {
                Some(h) if h == format!("{:#x}", B256::repeat_byte(1)) => json!("0x01aa"),
                Some(h) if h == format!("{:#x}", B256::repeat_byte(2)) => json!("0x"),
                _ => json!("0x02bb"),
            },
            _ => Value::Null,
        };
        json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
    })
    .await;
    let (sink, mut batches) = mpsc::channel(4);
    let task = tokio::spawn(poll_pending_transactions(rpc.url.clone(), sink));
    let batch = tokio::time::timeout(Duration::from_secs(20), batches.recv()).await.expect("a batch in time").expect("open");
    assert_eq!(batch, vec![Bytes::from_static(&[0x01, 0xaa]), Bytes::from_static(&[0x02, 0xbb])], "the empty raw transaction is skipped");
    assert_eq!(rpc.methods().iter().filter(|m| *m == "eth_newPendingTransactionFilter").count(), 1, "one filter");
    assert_eq!(rpc.methods().iter().filter(|m| *m == "eth_getRawTransactionByHash").count(), 3);

    // The receiver going away ends the task.
    drop(batches);
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("ends once the sink is closed").expect("no panic");
}

#[tokio::test]
async fn a_filter_the_node_forgot_is_made_again() {
    let polls = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&polls);
    let rpc = MockRpc::start(move |req| {
        let result = match req["method"].as_str().unwrap_or_default() {
            "eth_newPendingTransactionFilter" => json!("0x7"),
            "eth_getFilterChanges" => {
                let mut n = counter.lock().expect("count");
                *n += 1;
                // The first poll finds the filter gone (null); later polls are empty.
                if *n == 1 { Value::Null } else { json!([]) }
            }
            _ => Value::Null,
        };
        json!({"jsonrpc": "2.0", "id": 1, "result": result})
    })
    .await;
    let (sink, batches) = mpsc::channel(1);
    let task = tokio::spawn(poll_pending_transactions(rpc.url.clone(), sink));
    eventually("a second filter", || {
        rpc.methods().iter().filter(|m| *m == "eth_newPendingTransactionFilter").count() >= 2
    })
    .await;
    drop(batches);
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("ends").expect("no panic");
}

#[tokio::test]
async fn an_unreachable_pool_is_polled_quietly_until_the_sink_closes() {
    let url = {
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        format!("http://{}/", probe.local_addr().expect("addr")).parse::<url::Url>().expect("url")
    };
    let (sink, batches) = mpsc::channel(1);
    let task = tokio::spawn(poll_pending_transactions(url, sink));
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!task.is_finished(), "a pool that is not up yet is waited for");
    drop(batches);
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("ends").expect("no panic");
}

/// A binary-ingest server: for every frame it records the transactions and
/// answers `(accepted, pending)`. `close_after_frame` drops the connection
/// after answering one frame.
pub(crate) async fn ingest_server(close_after_frame: bool) -> (String, mpsc::UnboundedReceiver<(usize, Vec<Vec<u8>>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let (frames, received) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut connection = 0usize;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            connection += 1;
            let frames = frames.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(count) = stream.read_u32_le().await else { return };
                    let mut txs = Vec::new();
                    for _ in 0..count {
                        let Ok(len) = stream.read_u32_le().await else { return };
                        let mut raw = vec![0u8; len as usize];
                        if stream.read_exact(&mut raw).await.is_err() {
                            return;
                        }
                        txs.push(raw);
                    }
                    let _ = frames.send((connection, txs));
                    if stream.write_all(&count.to_le_bytes()).await.is_err() || stream.write_all(&7u32.to_le_bytes()).await.is_err() {
                        return;
                    }
                    if close_after_frame {
                        return;
                    }
                }
            });
        }
    });
    (addr, received)
}

#[tokio::test]
async fn gossiped_transactions_reach_the_ingest_in_frames_across_its_connections() {
    let (addr, mut frames) = ingest_server(false).await;
    let (sink, source) = mpsc::channel(4);
    let task = tokio::spawn(forward_transactions_over_ingest(addr, source, 2));
    let batch: Vec<Bytes> = (0..INGEST_FRAME as u32 + 3).map(tx).collect();
    sink.send(batch.clone()).await.expect("open");
    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(tokio::time::timeout(Duration::from_secs(20), frames.recv()).await.expect("a frame").expect("open"));
    }
    seen.sort_by_key(|(_, txs)| std::cmp::Reverse(txs.len()));
    assert_eq!(seen[0].1.len(), INGEST_FRAME);
    assert_eq!(seen[1].1.len(), 3);
    assert_ne!(seen[0].0, seen[1].0, "round-robin: the two frames used two connections");
    let all: Vec<Vec<u8>> = seen.iter().flat_map(|(_, txs)| txs.clone()).collect();
    let mut expected: Vec<Vec<u8>> = batch.iter().map(|b| b.to_vec()).collect();
    let mut got = all;
    expected.sort();
    got.sort();
    assert_eq!(got, expected, "every transaction arrived exactly once");
    drop(sink);
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("ends with its source").expect("no panic");
}

#[tokio::test]
async fn a_dropped_ingest_connection_is_remade_on_a_later_frame() {
    let (addr, mut frames) = ingest_server(true).await;
    let (sink, source) = mpsc::channel(4);
    let task = tokio::spawn(forward_transactions_over_ingest(addr, source, 1));
    sink.send(vec![tx(1)]).await.expect("open");
    let (first, txs) = tokio::time::timeout(Duration::from_secs(20), frames.recv()).await.expect("a frame").expect("open");
    assert_eq!(txs, vec![tx(1).to_vec()]);
    // The server closed after answering; the next frame finds the stream dead
    // (and is dropped), the one after that connects afresh.
    let mut connection = first;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut next = 2;
    while connection == first && std::time::Instant::now() < deadline {
        sink.send(vec![tx(next)]).await.expect("open");
        next += 1;
        if let Ok(Some((c, _))) = tokio::time::timeout(Duration::from_millis(300), frames.recv()).await {
            connection = c;
        }
    }
    assert_ne!(connection, first, "a later frame arrived on a new connection");
    drop(sink);
    tokio::time::timeout(Duration::from_secs(10), task).await.expect("ends").expect("no panic");
}

#[tokio::test]
async fn an_unreachable_ingest_drops_frames_without_stopping() {
    let addr = {
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        probe.local_addr().expect("addr").to_string()
    };
    let (sink, source) = mpsc::channel(4);
    let task = tokio::spawn(forward_transactions_over_ingest(addr, source, 0));
    sink.send(vec![tx(1)]).await.expect("open");
    sink.send(vec![tx(2)]).await.expect("still open after a refused connection");
    drop(sink);
    tokio::time::timeout(Duration::from_secs(20), task).await.expect("ends").expect("no panic");
}

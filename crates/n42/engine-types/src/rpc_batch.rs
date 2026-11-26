// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON-RPC batches answered concurrently (`docs/EXPLORER_RPC_PERF.md`).
//!
//! jsonrpsee's server runs the calls of one batch one after the other, so a
//! client that batches -- a block explorer sends 10-500 calls a request at a
//! concurrency of 4-10 -- gets at most that concurrency from the node, no
//! matter how many cores it has: Blockscout's `debug_traceBlockByNumber`
//! fetcher (10 blocks a batch, 4 batches) traced 6 blocks/s on a node that
//! traces 44 a second once the same blocks arrive as 40 single requests.
//!
//! [`ConcurrentBatchLayer`] wraps reth's RPC service: with a limit above 1,
//! a batch's calls run as separate tasks, at most `limit` at a time, and the
//! answers are assembled in request order under the same response-size
//! bound and with the same error for an oversized batch as jsonrpsee's own
//! batch handler. Single calls and notifications pass through. The limit
//! comes from `N42_RPC_BATCH_CONCURRENCY` (default 1: jsonrpsee's
//! sequential batches, unchanged), the size bound from the node's
//! `--rpc.max-response-size`.

use futures_util::{stream, StreamExt};
use jsonrpsee::{
    core::{
        middleware::{Batch, BatchEntry, Notification, RpcServiceT},
        server::BatchResponseBuilder,
    },
    types::Request,
    MethodResponse,
};
use std::{borrow::Cow, future::Future, pin::Pin};
use tower::Layer;

/// The environment variable that sets the per-batch concurrency.
pub const BATCH_CONCURRENCY_ENV: &str = "N42_RPC_BATCH_CONCURRENCY";

/// reth's default `--rpc.max-response-size` (160 MiB), used until the node's
/// value is known.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 160 * 1024 * 1024;

/// The layer: how many calls of one batch run at a time, and the response
/// size bound a batch answer must stay under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcurrentBatchLayer {
    /// Calls of one batch in flight at most (1: sequential, as jsonrpsee).
    pub limit: usize,
    /// A batch answer larger than this is replaced by jsonrpsee's
    /// "batch response too large" error.
    pub max_response_bytes: usize,
}

impl Default for ConcurrentBatchLayer {
    fn default() -> Self {
        Self { limit: 1, max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES }
    }
}

impl ConcurrentBatchLayer {
    /// The limit from [`BATCH_CONCURRENCY_ENV`] (unset or unparsable: 1).
    pub fn from_env() -> Self {
        let limit = std::env::var(BATCH_CONCURRENCY_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(1usize);
        Self { limit: limit.max(1), ..Default::default() }
    }

    /// [`Self::from_env`] under the response size bound of this process's
    /// `--rpc.max-response-size` (megabytes, as reth reads it).
    pub fn from_process() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let layer = Self::from_env();
        match max_response_mb(&args) {
            Some(mb) => layer.with_max_response_bytes(mb.saturating_mul(1024 * 1024)),
            None => layer,
        }
    }

    /// The same limit under the node's response size bound.
    pub const fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

/// `--rpc.max-response-size` (or its aliases) from a command line, in MB.
pub fn max_response_mb(args: &[String]) -> Option<usize> {
    const NAMES: [&str; 3] = ["--rpc.max-response-size", "--rpc-max-response-size", "--rpc.returndata.limit"];
    let mut found = None;
    for (i, arg) in args.iter().enumerate() {
        for name in NAMES {
            if arg == name {
                found = args.get(i + 1).and_then(|v| v.parse().ok());
            } else if let Some(v) = arg.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')) {
                found = v.parse().ok();
            }
        }
    }
    found
}

impl<S> Layer<S> for ConcurrentBatchLayer {
    type Service = ConcurrentBatch<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConcurrentBatch { inner, limit: self.limit, max_response_bytes: self.max_response_bytes }
    }
}

/// The service [`ConcurrentBatchLayer`] builds.
#[derive(Clone, Debug)]
pub struct ConcurrentBatch<S> {
    inner: S,
    limit: usize,
    max_response_bytes: usize,
}

/// A request that owns its method name and parameters, so it can run on its
/// own task.
fn into_owned(request: Request<'_>) -> Request<'static> {
    Request {
        jsonrpc: request.jsonrpc,
        id: request.id.into_owned(),
        method: Cow::Owned(request.method.into_owned()),
        params: request.params.map(|p| Cow::Owned(p.into_owned())),
        extensions: request.extensions,
    }
}

/// One batch entry's answer: Some(response), or None for a notification
/// (which gets none). A call runs on its own task once polled.
fn answer<'a, S>(
    service: S,
    entry: Result<BatchEntry<'a>, jsonrpsee::core::middleware::BatchEntryErr<'a>>,
) -> Pin<Box<dyn Future<Output = Option<MethodResponse>> + Send + 'a>>
where
    S: RpcServiceT<MethodResponse = MethodResponse, BatchResponse = MethodResponse, NotificationResponse = MethodResponse>
        + Send
        + Sync
        + 'static,
{
    match entry {
        Ok(BatchEntry::Call(request)) => {
            let id = request.id.clone().into_owned();
            let request = into_owned(request);
            // Spawned when the stream polls it, so at most the limit run.
            Box::pin(async move {
                let task = tokio::spawn(async move { service.call(request).await });
                Some(task.await.unwrap_or_else(|_| {
                    MethodResponse::error(id, jsonrpsee::types::ErrorObject::from(jsonrpsee::types::ErrorCode::InternalError))
                }))
            })
        }
        Ok(BatchEntry::Notification(n)) => Box::pin(async move {
            service.notification(n).await;
            None
        }),
        Err(err) => {
            let (err, id) = err.into_parts();
            let response = MethodResponse::error(id, err);
            Box::pin(async move { Some(response) })
        }
    }
}

impl<S> RpcServiceT for ConcurrentBatch<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse, BatchResponse = MethodResponse, NotificationResponse = MethodResponse>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(&self, request: Request<'a>) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        self.inner.call(request)
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let service = self.clone();
        async move {
            if service.limit <= 1 {
                return service.inner.batch(batch).await;
            }
            let entries: Vec<_> = batch.into_iter().map(|entry| answer(service.inner.clone(), entry)).collect();
            let mut answers = stream::iter(entries).buffered(service.limit);
            let mut builder = BatchResponseBuilder::new_with_limit(service.max_response_bytes);
            let mut got_notification = false;
            while let Some(answer) = answers.next().await {
                match answer {
                    Some(response) => {
                        if let Err(too_large) = builder.append(response) {
                            return too_large;
                        }
                    }
                    None => got_notification = true,
                }
            }
            if builder.is_empty() && got_notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(builder.finish())
            }
        }
    }

    fn notification<'a>(&self, n: Notification<'a>) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.inner.notification(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{core::middleware::RpcServiceBuilder, server::Server, RpcModule};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    /// A server whose `sleep` method takes 50 ms and records the peak
    /// number of calls in flight.
    async fn server(layer: ConcurrentBatchLayer) -> (String, Arc<AtomicUsize>, jsonrpsee::server::ServerHandle) {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut module = RpcModule::new((in_flight, peak.clone()));
        module
            .register_async_method("sleep", |params, ctx, _| async move {
                let n: u64 = params.one()?;
                let now = ctx.0.fetch_add(1, Ordering::SeqCst) + 1;
                ctx.1.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                ctx.0.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(n * 2)
            })
            .unwrap();
        module
            .register_method("big", |_, _, _| Ok::<_, jsonrpsee::types::ErrorObjectOwned>("x".repeat(1000)))
            .unwrap();
        let server = Server::builder()
            .set_rpc_middleware(RpcServiceBuilder::new().layer(layer))
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (url, peak, server.start(module))
    }

    /// A raw HTTP/1.1 POST (the batch body as is), the answer's JSON.
    async fn post(url: &str, body: String) -> serde_json::Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = url.trim_start_matches("http://");
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST / HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let raw = String::from_utf8(raw).unwrap();
        let (_, body) = raw.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap()
    }

    fn batch(n: u64) -> String {
        let calls: Vec<String> =
            (0..n).map(|i| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"sleep","params":[{i}]}}"#)).collect();
        format!("[{}]", calls.join(","))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sequential_by_default_concurrent_with_a_limit_same_answers() {
        let (url, peak, _h) = server(ConcurrentBatchLayer::default()).await;
        let sequential = post(&url, batch(8)).await;
        assert_eq!(peak.load(Ordering::SeqCst), 1);

        let (url, peak, _h) = server(ConcurrentBatchLayer { limit: 4, ..Default::default() }).await;
        let concurrent = post(&url, batch(8)).await;
        assert_eq!(peak.load(Ordering::SeqCst), 4, "at most the limit in flight");
        assert_eq!(sequential, concurrent, "same answers in the same order");
        assert_eq!(concurrent[7]["id"], 7);
        assert_eq!(concurrent[7]["result"], 14);
    }

    #[test]
    fn the_response_bound_follows_the_command_line() {
        let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        assert_eq!(max_response_mb(&args(&["n42", "node"])), None);
        assert_eq!(max_response_mb(&args(&["n42", "node", "--rpc.max-response-size", "500"])), Some(500));
        assert_eq!(max_response_mb(&args(&["n42", "--rpc.returndata.limit=64"])), Some(64));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn errors_notifications_and_the_size_bound() {
        let (url, _, _h) = server(ConcurrentBatchLayer { limit: 8, max_response_bytes: 2500 }).await;
        let body = r#"[{"jsonrpc":"2.0","id":1,"method":"nope","params":[]},
                       {"jsonrpc":"2.0","method":"sleep","params":[1]},
                       {"jsonrpc":"2.0","id":2,"method":"sleep","params":[3]},
                       {"foo":1}]"#;
        let answer = post(&url, body.to_owned()).await;
        let answer = answer.as_array().unwrap();
        assert_eq!(answer.len(), 3, "the notification gets no answer: {answer:?}");
        assert_eq!(answer[0]["error"]["code"], -32601);
        assert_eq!(answer[1]["result"], 6);
        assert_eq!(answer[2]["error"]["code"], -32600);
        // Three 1,000-byte answers exceed 2,500 bytes.
        let big = r#"[{"jsonrpc":"2.0","id":1,"method":"big"},{"jsonrpc":"2.0","id":2,"method":"big"},
                      {"jsonrpc":"2.0","id":3,"method":"big"}]"#;
        let answer = post(&url, big.to_owned()).await;
        assert_eq!(answer["error"]["code"], -32011, "{answer}");
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The validator's operations surface (mixed-production standard J1/J2):
//! the seven common metrics every client exposes, a Prometheus endpoint for
//! them, and the `n42_equivocations` JSON-RPC method (E15).
//!
//! One small HTTP/1.1 server answers both: `GET /metrics` renders the
//! installed Prometheus recorder, `POST /` takes a JSON-RPC 2.0 request. The
//! only method is `n42_equivocations`; any other answers -32601.

use crate::equivocations::EquivocationLog;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

/// J2: the number of the block at the head of this node's chain.
pub const METRIC_HEAD_NUMBER: &str = "n42_head_number";
/// J2: the view of the last block this node saw committed.
pub const METRIC_COMMITTED_VIEW: &str = "n42_committed_view";
/// J2: the number of the last block this node saw committed.
pub const METRIC_COMMITTED_NUMBER: &str = "n42_committed_number";
/// J2: views this node's pacemaker timed out.
pub const METRIC_VIEW_TIMEOUTS_TOTAL: &str = "n42_view_timeouts_total";
/// J2: timeout certificates this node formed from a timeout quorum.
pub const METRIC_TC_FORMED_TOTAL: &str = "n42_tc_formed_total";
/// J2 / E15: equivocations this node recorded (the datadir's count at start).
pub const METRIC_EQUIVOCATIONS_TOTAL: &str = "n42_equivocations_total";
/// J2: blocks this node refused, by `reason` (gov5's labels, [`refusal_label`]).
pub const METRIC_BLOCKS_REFUSED_TOTAL: &str = "n42_blocks_refused_total";

/// The seven J2 names, for a test or a scrape check.
pub const J2_METRICS: [&str; 7] = [
    METRIC_HEAD_NUMBER,
    METRIC_COMMITTED_VIEW,
    METRIC_COMMITTED_NUMBER,
    METRIC_VIEW_TIMEOUTS_TOTAL,
    METRIC_TC_FORMED_TOTAL,
    METRIC_EQUIVOCATIONS_TOTAL,
    METRIC_BLOCKS_REFUSED_TOTAL,
];

/// The JSON-RPC method of E15.
pub const RPC_EQUIVOCATIONS: &str = "n42_equivocations";

/// The `reason` label of a refusal, read from the refusal's message (the
/// `Profile1Error` texts of `n42-h2-consensus`, which start with the rule id).
///
/// The labels are gov5's (`Profile1RefusalReason`,
/// `internal/consensus/hotstuff/vote_gate_profile1.go`): one per static header
/// rule, `header` for anything else, so both clients count a refusal under one
/// name and the label's values stay bounded whatever the message says.
pub fn refusal_label(reason: &str) -> &'static str {
    let (rule, text) = reason.split_once(": ").unwrap_or(("", reason));
    if text.ends_with(" is missing") {
        return match text {
            "withdrawalsRoot is missing" => "withdrawals_root",
            "requestsHash is missing" => "requests_hash",
            _ => "header",
        };
    }
    match rule {
        "B1" if text.contains("QC") => "header_qc",
        "B1" => "extra",
        "B2" if text.starts_with("seal") => "seal",
        "B2" => "proposer",
        "B3" if text.starts_with("difficulty") => "difficulty",
        "B3" if text.starts_with("nonce") => "nonce",
        "B3" if text.starts_with("mix hash") => "mix_hash",
        "B3" if text.starts_with("ommers hash") => "ommers_hash",
        "B3" if text.starts_with("coinbase") => "proposer",
        "B4" if text.contains("before the parent") => "time_before_parent",
        "B4" if text.contains("past now") => "time_future",
        "B8" => "requests_hash",
        "B9" => "blob_gas",
        "B12" => "element22",
        "A23" => "gas_limit",
        "B14" => "base_fee",
        _ => "header",
    }
}

/// Counts one refused block under its reason's label.
pub fn note_block_refused(reason: &str) {
    metrics::counter!(METRIC_BLOCKS_REFUSED_TOTAL, "reason" => refusal_label(reason)).increment(1);
}

/// Installs the process's Prometheus recorder and describes the J2 metrics.
/// `None` when a recorder is already installed.
pub fn install_prometheus() -> Option<PrometheusHandle> {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder().ok()?;
    metrics::describe_gauge!(METRIC_HEAD_NUMBER, "Number of the block at this node's head");
    metrics::describe_gauge!(METRIC_COMMITTED_VIEW, "View of the last committed block");
    metrics::describe_gauge!(METRIC_COMMITTED_NUMBER, "Number of the last committed block");
    metrics::describe_counter!(METRIC_VIEW_TIMEOUTS_TOTAL, "Views this node timed out");
    metrics::describe_counter!(METRIC_TC_FORMED_TOTAL, "Timeout certificates this node formed");
    metrics::describe_counter!(METRIC_EQUIVOCATIONS_TOTAL, "Equivocations recorded (E15)");
    metrics::describe_counter!(METRIC_BLOCKS_REFUSED_TOTAL, "Blocks refused, by reason");
    // Present from the first scrape, before anything happened.
    for name in [METRIC_VIEW_TIMEOUTS_TOTAL, METRIC_TC_FORMED_TOTAL, METRIC_EQUIVOCATIONS_TOTAL] {
        metrics::counter!(name).increment(0);
    }
    Some(handle)
}

/// What the server answers from.
#[derive(Clone, Debug)]
pub struct OpsState {
    /// The equivocation log `n42_equivocations` reads.
    pub equivocations: EquivocationLog,
    /// The Prometheus recorder `GET /metrics` renders; without it, 404.
    pub metrics: Option<PrometheusHandle>,
}

/// The largest request body read.
const MAX_BODY: usize = 64 * 1024;
/// A connection's whole life.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(30);

/// Answers one JSON-RPC 2.0 request (a single object; a batch is refused).
pub fn handle_rpc(state: &OpsState, body: &[u8]) -> Value {
    let request: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return rpc_error(Value::Null, -32700, "parse error"),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_error(id, -32600, "invalid request");
    };
    match method {
        RPC_EQUIVOCATIONS => json!({ "jsonrpc": "2.0", "id": id, "result": state.equivocations.response() }),
        _ => rpc_error(id, -32601, &format!("the method {method} does not exist/is not available")),
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn reply(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    if let Ok(value) = content_type.parse() {
        response.headers_mut().insert(hyper::header::CONTENT_TYPE, value);
    }
    response
}

async fn handle(state: OpsState, request: Request<Incoming>) -> Response<Full<Bytes>> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => match &state.metrics {
            Some(handle) => {
                handle.run_upkeep();
                reply(StatusCode::OK, "text/plain; version=0.0.4", handle.render())
            }
            None => reply(StatusCode::NOT_FOUND, "text/plain", "no metrics recorder\n"),
        },
        (&Method::POST, "/") => match Limited::new(request.into_body(), MAX_BODY).collect().await {
            Ok(body) => {
                let answer = handle_rpc(&state, &body.to_bytes());
                reply(StatusCode::OK, "application/json", answer.to_string())
            }
            Err(_) => reply(StatusCode::PAYLOAD_TOO_LARGE, "text/plain", "request too large\n"),
        },
        _ => reply(StatusCode::NOT_FOUND, "text/plain", "not found\n"),
    }
}

/// Binds `addr` and serves the surface until the process ends.
pub async fn serve(addr: SocketAddr, state: OpsState) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, state).await;
    Ok(())
}

/// Serves on a bound listener (tests bind port 0).
pub async fn serve_on(listener: TcpListener, state: OpsState) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                tracing::debug!(target: "n42.h2.node", %err, "ops: accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(state, request).await) }
            });
            let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
            let _ = tokio::time::timeout(CONNECTION_DEADLINE, connection).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_labels_are_gov5s() {
        use alloy_primitives::B256;
        use n42_h2_consensus::Profile1Error as E;
        let cases: [(E, &str); 12] = [
            (E::Extra("short".into()), "extra"),
            (E::Qc("bad".into()), "header_qc"),
            (E::Seal("bad".into()), "seal"),
            (E::NoProposer(3), "proposer"),
            (E::Nonce, "nonce"),
            (E::MixHash(B256::ZERO), "mix_hash"),
            (E::OmmersHash(B256::ZERO), "ommers_hash"),
            (E::TimestampBeforeParent { time: 1, parent: 2 }, "time_before_parent"),
            (E::TimestampInFuture { time: 9, now: 1 }, "time_future"),
            (E::Missing { item: "B6", field: "withdrawalsRoot" }, "withdrawals_root"),
            (E::Missing { item: "B8", field: "requestsHash" }, "requests_hash"),
            (E::AccessListHash(B256::ZERO), "element22"),
        ];
        for (error, label) in cases {
            assert_eq!(refusal_label(&error.to_string()), label, "{error}");
        }
        assert_eq!(refusal_label("B1: the embedded QC is not a commit-domain QC of its view's set: x"), "header_qc");
        assert_eq!(refusal_label("B2: seal: bad"), "seal");
        assert_eq!(refusal_label("safety halt: proof of a conflicting commit"), "header");
        assert_eq!(refusal_label("anything else: at all"), "header");
    }

    #[test]
    fn the_rpc_serves_n42_equivocations_and_refuses_the_rest() {
        let state = OpsState { equivocations: EquivocationLog::in_memory(), metrics: None };
        let answer = handle_rpc(&state, br#"{"jsonrpc":"2.0","id":7,"method":"n42_equivocations","params":[]}"#);
        assert_eq!(answer["id"], 7);
        assert_eq!(answer["result"]["total"], 0);
        assert!(answer["result"]["evidence"].as_array().is_some_and(Vec::is_empty));
        let answer = handle_rpc(&state, br#"{"jsonrpc":"2.0","id":1,"method":"eth_config"}"#);
        assert_eq!(answer["error"]["code"], -32601);
        assert_eq!(handle_rpc(&state, b"{").get("error").and_then(|e| e["code"].as_i64()), Some(-32700));
    }

    #[test]
    fn the_seven_j2_names_render_under_a_recorder() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::gauge!(METRIC_HEAD_NUMBER).set(12.0);
            metrics::gauge!(METRIC_COMMITTED_VIEW).set(30.0);
            metrics::gauge!(METRIC_COMMITTED_NUMBER).set(11.0);
            metrics::counter!(METRIC_VIEW_TIMEOUTS_TOTAL).increment(1);
            metrics::counter!(METRIC_TC_FORMED_TOTAL).increment(1);
            metrics::counter!(METRIC_EQUIVOCATIONS_TOTAL).increment(1);
            note_block_refused("B2: seal: bad");
        });
        let text = handle.render();
        for name in J2_METRICS {
            assert!(text.contains(name), "{name} missing from:\n{text}");
        }
        assert!(text.contains(r#"n42_blocks_refused_total{reason="seal"} 1"#), "{text}");
    }
}

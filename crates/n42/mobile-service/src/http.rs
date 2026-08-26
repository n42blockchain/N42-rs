// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal JSON-RPC-over-HTTP front end for [`crate::rpc::dispatch`].
//!
//! Enough HTTP to serve phones, and no more: one POST endpoint, a body, a JSON
//! response. It exists so the service can be run and talked to without pulling
//! a web framework into a crate whose job is verification, and because the
//! interesting logic is in `dispatch`, which is tested without a socket.
//!
//! Deliberately not here: TLS, authentication, and rate limiting. A node
//! exposing this to the internet should put it behind something that has them —
//! `submit_receipt` verifies a BLS signature per call, which is cheap to ask for
//! and not free to answer.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::rpc::{dispatch, RpcError};
use crate::service::MobileService;

/// Requests larger than this are refused unread.
///
/// A receipt is a couple of hundred bytes; anything at this size is a mistake or
/// an attempt to make the node allocate on demand.
const MAX_BODY: usize = 64 * 1024;

/// Serves `mobile_*` over HTTP until the process ends.
///
/// Single-threaded and blocking: one phone at a time, which is right for a
/// diagnostic or a small deployment and not for a public endpoint. The service
/// is behind a mutex so a node can keep recording commits into the same state
/// from its consensus loop.
pub fn serve(
    addr: impl ToSocketAddrs,
    service: Arc<Mutex<MobileService>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle(stream, &service) {
                    // One bad connection is not a reason to stop serving.
                    debug!(target: "n42.mobile.http", %error, "connection ended");
                }
            }
            Err(error) => warn!(target: "n42.mobile.http", %error, "accept failed"),
        }
    }
    Ok(())
}

/// The address a listener bound to, for a caller that asked for port 0.
pub fn bind(addr: impl ToSocketAddrs) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr)
}

/// Serves on an already-bound listener. Used by tests, which need the port.
pub fn serve_on(
    listener: &TcpListener,
    service: &Arc<Mutex<MobileService>>,
) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle(stream, service) {
                    debug!(target: "n42.mobile.http", %error, "connection ended");
                }
            }
            Err(error) => warn!(target: "n42.mobile.http", %error, "accept failed"),
        }
    }
    Ok(())
}

fn handle(stream: TcpStream, service: &Arc<Mutex<MobileService>>) -> std::io::Result<()> {
    let body = match read_request(&stream) {
        Ok(body) => body,
        Err(error) => {
            respond(&stream, 400, &json!({ "error": error }))?;
            return Ok(());
        }
    };

    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            // Parse errors carry the JSON-RPC code, so a client sees the same
            // shape whether the failure was in the envelope or the method.
            return respond(
                &stream,
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": error.to_string() },
                }),
            );
        }
    };

    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or_else(|| json!([]));

    let outcome = {
        let mut guard = service.lock().unwrap_or_else(|poisoned| {
            // A panic in one request must not take the endpoint down for
            // everyone: the state it guards is a cache of recent blocks.
            warn!(target: "n42.mobile.http", "service mutex was poisoned; continuing");
            poisoned.into_inner()
        });
        dispatch(&mut guard, method, &params)
    };

    let response = match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(RpcError { code, message }) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    };
    respond(&stream, 200, &response)
}

/// Reads one HTTP request and returns its body.
fn read_request(stream: &TcpStream) -> Result<Vec<u8>, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| e.to_string())?;
    if !request_line.starts_with("POST") {
        return Err("only POST is supported".into());
    }

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim())
        {
            content_length = value.parse().map_err(|_| "bad content-length".to_string())?;
        }
    }

    if content_length > MAX_BODY {
        return Err(format!("body of {content_length} bytes exceeds the {MAX_BODY} limit"));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(body)
}

fn respond(mut stream: &TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(body)?;
    write!(
        stream,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The transactions this node's own pool admits, read from its public
//! JSON-RPC so they can be gossiped to the fleet.
//!
//! The Engine API's auth endpoint takes transactions but cannot list them,
//! so this polls the public endpoint: `eth_newPendingTransactionFilter` once,
//! `eth_getFilterChanges` every half second, `eth_getRawTransactionByHash`
//! for each new hash. A filter the node forgot (a restart) is made again.

use alloy_primitives::{Bytes, B256};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;

const POLL: Duration = Duration::from_millis(500);

/// How many transactions go in one JSON-RPC batch.
///
/// A batch is one HTTP body and the execution layer caps how large that may
/// be (reth's `--rpc.max-request-size`, 15 MB by default). A hex-encoded
/// transfer is a few hundred bytes of JSON, so a thousand is comfortably
/// inside any such limit while still being a thousand round trips saved.
const FORWARD_CHUNK: usize = 1000;

/// Hands the fleet's gossiped transactions to this node's pool, off the
/// consensus loop.
///
/// Its own task for one reason, and it is the largest single result in this
/// fleet's history. Done inline, this is the only work in the service loop
/// whose size is set by the *fleet's* send rate rather than by the chain's:
/// the loop cannot poll its transport while it awaits, so a step that hands
/// over everything that arrived is a step during which the node is deaf to
/// proposals, votes and bodies. At 6,000 senders that was measured as one
/// member receiving nothing at all for 11.1 s, the view it should have led
/// expiring 31 ms before the body it was waiting for arrived, and every view
/// that member led costing the whole fleet a six-second timeout for the rest
/// of the round. Moving it here took the fleet from 13,714 TPS to 38,786 and
/// the block cycle from 1.667 s to 0.588 s.
///
/// Rationing it inline is not a substitute and was measured not to be: a
/// bounded batch every step is the same total work, spent in smaller pieces,
/// and it left the fleet at 12,190 TPS. The loop must not wait for the pool
/// at all.
pub async fn forward_transactions(rpc_url: url::Url, mut source: mpsc::Receiver<Vec<Bytes>>) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(err) => {
            debug!(target: "n42.h2.node", %err, "transaction forwarding: no HTTP client");
            return;
        }
    };
    while let Some(batch) = source.recv().await {
        for chunk in batch.chunks(FORWARD_CHUNK) {
            let body: Vec<Value> = chunk
                .iter()
                .enumerate()
                .map(|(id, raw)| {
                    json!({"jsonrpc": "2.0", "id": id, "method": "eth_sendRawTransaction", "params": [raw]})
                })
                .collect();
            // The reply is not read beyond its arrival. Every rejection here is
            // expected traffic -- a transaction the pool already holds, one
            // whose nonce has been mined, or a pool that is simply full -- and
            // there is nothing this node would do differently about any of
            // them.
            if let Err(err) = client.post(rpc_url.clone()).json(&body).send().await {
                debug!(target: "n42.h2.node", %err, count = chunk.len(), "could not hand transactions to the pool");
            }
        }
    }
}

/// Feeds every transaction the pool admits into `sink`, in batches, until
/// the receiver is dropped.
pub async fn poll_pending_transactions(rpc_url: url::Url, sink: mpsc::Sender<Vec<Bytes>>) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(err) => {
            debug!(target: "n42.h2.node", %err, "transaction source: no HTTP client");
            return;
        }
    };
    let call = |method: &'static str, params: Vec<Value>| {
        let client = client.clone();
        let url = rpc_url.clone();
        async move {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            let response: Value = client.post(url).json(&body).send().await.ok()?.json().await.ok()?;
            response.get("result").cloned()
        }
    };
    let mut filter: Option<Value> = None;
    loop {
        tokio::time::sleep(POLL).await;
        if sink.is_closed() {
            return;
        }
        if filter.is_none() {
            filter = call("eth_newPendingTransactionFilter", vec![]).await.filter(|id| !id.is_null());
            if filter.is_none() {
                continue;
            }
        }
        let Some(changes) = call("eth_getFilterChanges", vec![filter.clone().expect("set above")]).await
        else {
            // The node forgot the filter, or is gone; start over.
            filter = None;
            continue;
        };
        if changes.is_null() {
            filter = None;
            continue;
        }
        let hashes: Vec<B256> = serde_json::from_value(changes).unwrap_or_default();
        let mut batch = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some(raw) = call("eth_getRawTransactionByHash", vec![json!(hash)]).await
                && let Ok(raw) = serde_json::from_value::<Bytes>(raw)
                && !raw.is_empty()
            {
                batch.push(raw);
            }
        }
        if !batch.is_empty() && sink.send(batch).await.is_err() {
            return;
        }
    }
}

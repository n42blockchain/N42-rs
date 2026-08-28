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

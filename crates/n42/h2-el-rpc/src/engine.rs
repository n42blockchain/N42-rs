// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An [`ExecutionLayer`] backed by a standard Engine API endpoint.
//!
//! This is what connects HotStuff-2 to a real execution client. It speaks the
//! published Engine API rather than reth's internal handles, which means the
//! same adapter drives reth, this repo's own node, and gov5's `eth-el` mode —
//! and it does so without the consensus side taking a reth dependency, which is
//! the whole point of the seam in [`n42_h2_execution::el`].
//!
//! ## Choosing a method version
//!
//! The Engine API versions its methods by hard fork, and the mapping is not
//! one-to-one with the payload struct names, which is the main trap here:
//!
//! | payload | sidecar | method |
//! | --- | --- | --- |
//! | V1 | — | `engine_newPayloadV1` |
//! | V2 | — | `engine_newPayloadV2` (as `ExecutionPayloadInputV2`) |
//! | V3 | Cancun | `engine_newPayloadV3` |
//! | V3 | Prague (has requests) | `engine_newPayloadV4` |
//!
//! So a Prague block is a *V3* payload sent to `newPayloadV4`. Reading the
//! version off the payload struct alone sends Prague blocks to `newPayloadV3`,
//! which the execution layer rejects for a missing parameter — an error that
//! reads like a payload problem and is not one.
//!
//! Amsterdam (`ExecutionPayloadV4` / `newPayloadV5`) is deliberately refused
//! rather than guessed at. Its envelope and blobs bundle differ, and there is no
//! execution client to test the mapping against here; a wrong guess would fail
//! at the first Amsterdam block on a live chain instead of at startup.
//!
//! `forkchoiceUpdated` picks its version from the attributes, since each version
//! is defined by the fields it accepts: `parentBeaconBlockRoot` requires V3,
//! `withdrawals` requires V2.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_consensus::constants::EIP4844_TX_TYPE_ID;
use alloy_consensus::{TxEnvelope, Typed2718};
use alloy_eips::eip2718::Decodable2718;
use alloy_eips::eip7685::RequestsOrHash;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadEnvelopeV3,
    ExecutionPayloadEnvelopeV4, ExecutionPayloadInputV2, ExecutionPayloadSidecar,
    ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId, PayloadStatus,
    PraguePayloadFields,
};
use n42_h2_execution::{BuiltBlock, ElError, ExecutionLayer, ResolveKind};
use serde_json::{json, Value};
use tracing::debug;

use crate::transport::{JsonRpcTransport, TransportError, UNKNOWN_PAYLOAD};

/// How many in-flight builds to remember the beacon root for.
///
/// A node has one build in flight at a time in the normal case; the slack covers
/// builds that were superseded before anyone collected them. Old entries are
/// dropped rather than accumulating, since a build nobody collected is never
/// coming back.
const MAX_TRACKED_BUILDS: usize = 16;

/// An [`ExecutionLayer`] speaking the Engine API over `T`.
#[derive(Debug)]
pub struct EngineApiClient<T> {
    transport: T,
    /// Beacon roots for builds this client started, keyed by payload id, plus
    /// the order they were inserted in so the oldest can be evicted.
    ///
    /// The Engine API does not echo `parentBeaconBlockRoot` back from
    /// `getPayload`, but re-importing the built block through `newPayload`
    /// requires it, so a build's root has to survive from the request that
    /// started it to the response that collects it.
    builds: Mutex<(HashMap<PayloadId, B256>, Vec<PayloadId>)>,
}

impl<T: JsonRpcTransport> EngineApiClient<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            builds: Mutex::new((HashMap::new(), Vec::new())),
        }
    }

    /// Records the beacon root a build was started under.
    fn remember_build(&self, id: PayloadId, parent_beacon_block_root: B256) {
        let Ok(mut builds) = self.builds.lock() else {
            // A poisoned lock means another thread panicked mid-update. The map
            // is a cache, so losing it costs one failed collection, not
            // correctness — and taking the node down over it would be worse.
            return;
        };
        let (roots, order) = &mut *builds;
        if roots.insert(id, parent_beacon_block_root).is_none() {
            order.push(id);
        }
        while order.len() > MAX_TRACKED_BUILDS {
            let oldest = order.remove(0);
            roots.remove(&oldest);
        }
    }

    /// The beacon root a build was started under, if this client started it.
    fn recall_build(&self, id: PayloadId) -> Option<B256> {
        self.builds.lock().ok()?.0.get(&id).copied()
    }

    /// The transport, for callers that need to make a call this trait does not
    /// cover (`engine_exchangeCapabilities`, for instance).
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    async fn call<R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<R, TransportError> {
        let value = self.transport.call(method, params).await?;
        serde_json::from_value(value).map_err(|e| {
            TransportError::Transport(format!("{method} returned an unusable result: {e}"))
        })
    }
}

/// Builds the method name and parameters for a `newPayload` call.
///
/// Split out from the call so the mapping in the module docs is testable
/// without a transport — it is the part most likely to be wrong and least
/// likely to be noticed.
pub fn new_payload_call(data: &ExecutionData) -> Result<(&'static str, Vec<Value>), ElError> {
    let ExecutionData { payload, sidecar } = data;
    match payload {
        ExecutionPayload::V1(payload) => Ok(("engine_newPayloadV1", vec![json!(payload)])),
        ExecutionPayload::V2(payload) => {
            // V2 is not sent as `ExecutionPayloadV2`: the method takes a V1
            // payload with withdrawals flattened alongside it.
            let input = ExecutionPayloadInputV2 {
                execution_payload: payload.payload_inner.clone(),
                withdrawals: Some(payload.withdrawals.clone()),
            };
            Ok(("engine_newPayloadV2", vec![json!(input)]))
        }
        ExecutionPayload::V3(payload) => {
            // Cancun added both of these, and the method requires them, so an
            // absent one is a malformed payload rather than a default.
            let versioned_hashes = sidecar.versioned_hashes().cloned().ok_or_else(|| {
                ElError::new("a V3 payload needs versioned hashes; sidecar has none")
            })?;
            let parent_beacon_block_root = sidecar.parent_beacon_block_root().ok_or_else(|| {
                ElError::new("a V3 payload needs a parent beacon block root; sidecar has none")
            })?;
            let mut params = vec![
                json!(payload),
                json!(versioned_hashes),
                json!(parent_beacon_block_root),
            ];
            // Prague is a V3 payload with requests, sent to V4.
            Ok(match sidecar.requests() {
                Some(requests) => {
                    params.push(json!(requests));
                    ("engine_newPayloadV4", params)
                }
                None => ("engine_newPayloadV3", params),
            })
        }
        ExecutionPayload::V4(_) => Err(ElError::new(
            "Amsterdam payloads (engine_newPayloadV5) are not supported by this adapter",
        )),
    }
}

/// Picks the `forkchoiceUpdated` version for a set of attributes.
///
/// Each version is defined by the fields it accepts, so the attributes decide:
/// sending `parentBeaconBlockRoot` to V2 is rejected, and so is omitting it
/// from V3 on a Cancun chain.
pub const fn forkchoice_method(attrs: Option<&PayloadAttributes>) -> &'static str {
    match attrs {
        // Without attributes this is a plain head/finalise update. V3 accepts
        // that on every post-Cancun chain, which is every chain this runs on.
        None => "engine_forkchoiceUpdatedV3",
        Some(attrs) if attrs.parent_beacon_block_root.is_some() => "engine_forkchoiceUpdatedV3",
        Some(attrs) if attrs.withdrawals.is_some() => "engine_forkchoiceUpdatedV2",
        Some(_) => "engine_forkchoiceUpdatedV1",
    }
}

/// Picks the `getPayload` version matching the `forkchoiceUpdated` that started
/// the build.
///
/// Kept alongside [`forkchoice_method`] because the two must agree: a build
/// started by V3 must be collected by `getPayloadV3` or later, or the execution
/// layer returns a payload missing the Cancun fields.
const fn get_payload_method(started_with: &str) -> &'static str {
    match started_with.as_bytes() {
        b"engine_forkchoiceUpdatedV1" => "engine_getPayloadV1",
        b"engine_forkchoiceUpdatedV2" => "engine_getPayloadV2",
        _ => "engine_getPayloadV3",
    }
}

/// Turns a `getPayload` envelope into the node-neutral result.
///
/// `parent_beacon_block_root` is a parameter because the envelope does not carry
/// it: it was an input to the `forkchoiceUpdated` that started this build, and
/// the Engine API never echoes it back. It is nevertheless required to re-import
/// the block through `newPayload`, so the client remembers it per build — see
/// [`EngineApiClient::fork_choice_updated_with_attrs`].
///
/// Accepts both the V3 and V4 envelope shapes: V4 is V3 with execution requests
/// flattened on, so a Prague endpoint's answer parses as either, and trying V4
/// first is what keeps the requests instead of dropping them.
pub fn built_block_from_envelope(
    value: Value,
    parent_beacon_block_root: B256,
) -> Result<BuiltBlock, ElError> {
    let (envelope, requests) =
        match serde_json::from_value::<ExecutionPayloadEnvelopeV4>(value.clone()) {
            Ok(v4) => (v4.envelope_inner, Some(v4.execution_requests)),
            Err(_) => {
                let v3: ExecutionPayloadEnvelopeV3 = serde_json::from_value(value)
                    .map_err(|e| ElError::new(format!("unusable getPayload envelope: {e}")))?;
                (v3, None)
            }
        };

    let inner = &envelope.execution_payload.payload_inner.payload_inner;
    let hash = inner.block_hash;
    let number = inner.block_number;
    let timestamp = inner.timestamp;
    let tx_count = inner.transactions.len();
    let blob_tx_hashes = blob_transaction_hashes(&inner.transactions);

    // From the bundle's KZG commitments, not from the transactions: this is the
    // list `newPayload` checks the block against, and the execution layer that
    // built it is the authority on it.
    let versioned_hashes = envelope.blobs_bundle.versioned_hashes();
    let cancun = CancunPayloadFields {
        parent_beacon_block_root,
        versioned_hashes,
    };
    let sidecar = match requests {
        Some(requests) => ExecutionPayloadSidecar::v4(
            cancun,
            PraguePayloadFields {
                requests: RequestsOrHash::Requests(requests),
            },
        ),
        None => ExecutionPayloadSidecar::v3(cancun),
    };

    Ok(BuiltBlock {
        hash,
        number,
        timestamp,
        tx_count,
        execution_data: ExecutionData::new(
            ExecutionPayload::V3(envelope.execution_payload),
            sidecar,
        ),
        blob_tx_hashes,
    })
}

/// The hashes of the EIP-4844 transactions in a payload.
///
/// The consensus side broadcasts their sidecars separately, so blob
/// transactions that go unidentified produce a block its peers cannot validate.
///
/// A transaction that fails to decode is skipped rather than failing the block:
/// the execution layer built and accepted this payload, so a decode failure here
/// is this adapter's problem, and refusing the block over it would stall
/// consensus over a reporting detail.
fn blob_transaction_hashes(transactions: &[alloy_primitives::Bytes]) -> Vec<B256> {
    transactions
        .iter()
        .filter_map(|raw| {
            let mut slice = raw.as_ref();
            TxEnvelope::decode_2718(&mut slice).ok()
        })
        .filter(|tx| tx.ty() == EIP4844_TX_TYPE_ID)
        .map(|tx| *tx.tx_hash())
        .collect()
}

#[async_trait::async_trait]
impl<T: JsonRpcTransport> ExecutionLayer for EngineApiClient<T> {
    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError> {
        let (method, params) = new_payload_call(&payload)?;
        debug!(target: "n42.h2.el", method, "newPayload");
        self.call(method, params).await.map_err(ElError::new)
    }

    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let method = forkchoice_method(None);
        debug!(target: "n42.h2.el", method, "forkchoiceUpdated");
        self.call(method, vec![json!(state), Value::Null])
            .await
            .map_err(ElError::new)
    }

    async fn fork_choice_updated_with_attrs(
        &self,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let method = forkchoice_method(Some(&attrs));
        debug!(target: "n42.h2.el", method, "forkchoiceUpdated with attributes");
        let beacon_root = attrs.parent_beacon_block_root;
        let updated: ForkchoiceUpdated = self
            .call(method, vec![json!(state), json!(attrs)])
            .await
            .map_err(ElError::new)?;

        // Remember what this build was started under, so collecting it can
        // rebuild a sidecar the block can be re-imported with.
        if let (Some(id), Some(root)) = (updated.payload_id, beacon_root) {
            self.remember_build(id, root);
        }
        Ok(updated)
    }

    async fn resolve_payload(
        &self,
        id: PayloadId,
        _kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>> {
        // `ResolveKind::WaitForPending` has no Engine API equivalent: getPayload
        // returns the best payload available at the moment of the call and the
        // execution layer may stop building after serving it. The wait therefore
        // happens on the caller's side, in how long it lets the build run before
        // asking. Honouring the kind by polling here would be worse — each call
        // may terminate the build.
        let method = get_payload_method(forkchoice_method(None));
        // A build this client did not start has no remembered root. Zero is the
        // honest stand-in — it is what a pre-Cancun chain uses — and the block
        // will fail its own `newPayload` check rather than being imported under
        // a root nobody agreed to.
        let beacon_root = self.recall_build(id).unwrap_or_default();
        match self.transport.call(method, vec![json!(id)]).await {
            Ok(value) => Some(built_block_from_envelope(value, beacon_root)),
            // A build the execution layer does not know about is an absent
            // result, not a failure: the driver retries or moves on.
            Err(TransportError::Rpc(err)) if err.code == UNKNOWN_PAYLOAD => None,
            Err(err) => Some(Err(ElError::new(err))),
        }
    }
}

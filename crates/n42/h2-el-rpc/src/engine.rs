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
//! `withdrawals` requires V2. `getPayload` is asked newest-first, because each
//! of its versions answers for exactly one fork and refuses the rest.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_consensus::constants::EIP4844_TX_TYPE_ID;
use alloy_consensus::{TxEnvelope, Typed2718};
use alloy_eips::eip2718::Decodable2718;
use alloy_eips::eip7685::{Requests, RequestsOrHash};
use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadInputV2,
    ExecutionPayloadSidecar, ExecutionPayloadV3, ExecutionPayloadV4, ForkchoiceState,
    ForkchoiceUpdated,
    PayloadAttributes, PayloadId, PayloadStatus, PraguePayloadFields,
};
use n42_h2_execution::{ChainBlock, BuiltBlock, ElError, ExecutionLayer, ResolveKind};
use serde_json::{json, Value};
use tracing::debug;

use crate::transport::{
    JsonRpcTransport, TransportError, INVALID_PAYLOAD_ATTRIBUTES, UNKNOWN_PAYLOAD,
    UNSUPPORTED_FORK,
};

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
    /// Where in [`FCU_WITH_ATTRS_METHODS`] the last accepted build-starting
    /// call was, so the ladder is climbed once per chain rather than once per
    /// build: a pre-Amsterdam chain refuses V4 on every leader build, and a
    /// refused round trip on the leader's path is a refused round trip on the
    /// fleet's cycle.
    fcu_rung: std::sync::atomic::AtomicUsize,
}

impl<T: JsonRpcTransport> EngineApiClient<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            builds: Mutex::new((HashMap::new(), Vec::new())),
            fcu_rung: std::sync::atomic::AtomicUsize::new(0),
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
        // Amsterdam: the same three arguments as V4 plus the requests, with the
        // access list riding inside the payload itself. Sending this block to
        // `newPayloadV4` is refused outright -- reth's version gate rejects
        // `(V4, Payload)` once Amsterdam is active -- and sending it without
        // the access list would be worse than refused: the block would import
        // serially and nothing would say why.
        ExecutionPayload::V4(payload) => {
            let versioned_hashes = sidecar.versioned_hashes().cloned().unwrap_or_default();
            let parent_beacon_block_root = sidecar.parent_beacon_block_root().ok_or_else(|| {
                ElError::new("a V4 payload needs a parent beacon block root; sidecar has none")
            })?;
            let requests = sidecar.requests().cloned().unwrap_or_default();
            Ok((
                "engine_newPayloadV5",
                vec![
                    json!(payload),
                    json!(versioned_hashes),
                    json!(parent_beacon_block_root),
                    json!(requests),
                ],
            ))
        }
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
        // that on every post-Cancun chain, which is every chain this runs on,
        // and Amsterdam's version gate only rejects V3 when it carries
        // attributes.
        None => "engine_forkchoiceUpdatedV3",
        Some(attrs) if attrs.parent_beacon_block_root.is_some() => FCU_WITH_ATTRS_NEWEST,
        Some(attrs) if attrs.withdrawals.is_some() => "engine_forkchoiceUpdatedV2",
        Some(_) => "engine_forkchoiceUpdatedV1",
    }
}

/// The `forkchoiceUpdated` version used to *start a build*, newest first.
///
/// Amsterdam rejects `(V3, PayloadAttributes)` outright — reth's
/// `validate_version_specific_fields` returns `UNSUPPORTED_FORK` — so a chain
/// with `amsterdamTime` set needs V4 to begin a payload at all. A chain without
/// it rejects V4 the same way, so the caller falls back; see
/// [`FCU_WITH_ATTRS_METHODS`].
const FCU_WITH_ATTRS_NEWEST: &str = "engine_forkchoiceUpdatedV4";

/// Every `forkchoiceUpdated`-with-attributes version, newest first, for the
/// fallback the fork schedule would otherwise have to be carried to decide.
pub const FCU_WITH_ATTRS_METHODS: [&str; 2] =
    ["engine_forkchoiceUpdatedV4", "engine_forkchoiceUpdatedV3"];

/// The `getPayload` versions, newest first.
///
/// Each version is bound to a fork: V5 answers only for Osaka builds, V4 only
/// for Prague, V3 only for Cancun, and the execution layer refuses the others
/// with [`UNSUPPORTED_FORK`]. This client does not carry the fork schedule, so
/// it asks newest-first and takes the first version that answers. The wrong
/// choice is not merely refused, either: a Prague build collected through V3
/// arrives without its execution requests, the block re-imported from it lacks
/// the requests hash its header carries, and the leader's own execution layer
/// rejects the block it just built with "block hash mismatch".
const GET_PAYLOAD_METHODS: [&str; 4] =
    ["engine_getPayloadV6", "engine_getPayloadV5", "engine_getPayloadV4", "engine_getPayloadV3"];

/// What every `getPayload` version has in common.
///
/// V3, V4 and V5 differ in what else they carry — V4 adds execution requests,
/// V5 changes the blobs bundle — but the block, its KZG commitments and the
/// requests are all that re-importing it needs, and all three spell those the
/// same way. Reading them through one shape is what lets the version be chosen
/// at runtime.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetPayloadEnvelope {
    execution_payload: PayloadMaybeWithBal,
    #[serde(default)]
    blobs_bundle: BlobCommitments,
    #[serde(default)]
    execution_requests: Option<Vec<alloy_primitives::Bytes>>,
}

/// A `getPayload` payload, keeping the access list if the version carries one.
///
/// The list is *inside* `executionPayload`, not beside it: Amsterdam's envelope
/// types the field as `ExecutionPayloadV4`, which is a V3 payload plus the list.
/// Reading the field at the envelope's top level finds nothing and finds it
/// silently, because serde ignores what it does not recognise -- so the payload
/// comes back as V3, the block imports serially where it can import at all, and
/// the first sign of it is `Unsupported fork` three hops away in a follower.
///
/// Worth carrying for one reason: reth executes a block in parallel when it has
/// one and serially when it does not
/// (`payload_validator.rs::bal_path_eligible`).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayloadMaybeWithBal {
    #[serde(flatten)]
    payload: ExecutionPayloadV3,
    #[serde(default)]
    block_access_list: Option<alloy_primitives::Bytes>,
}

#[derive(Default, serde::Deserialize)]
struct BlobCommitments {
    #[serde(default)]
    commitments: Vec<alloy_primitives::FixedBytes<48>>,
}

/// Turns a `getPayload` envelope into the node-neutral result.
///
/// `parent_beacon_block_root` is a parameter because the envelope does not carry
/// it: it was an input to the `forkchoiceUpdated` that started this build, and
/// the Engine API never echoes it back. It is nevertheless required to re-import
/// the block through `newPayload`, so the client remembers it per build — see
/// [`EngineApiClient::fork_choice_updated_with_attrs`].
pub fn built_block_from_envelope(
    value: Value,
    parent_beacon_block_root: B256,
) -> Result<BuiltBlock, ElError> {
    let envelope: GetPayloadEnvelope = serde_json::from_value(value)
        .map_err(|e| ElError::new(format!("unusable getPayload envelope: {e}")))?;

    let inner = &envelope.execution_payload.payload.payload_inner.payload_inner;
    let hash = inner.block_hash;
    let number = inner.block_number;
    let timestamp = inner.timestamp;
    let tx_count = inner.transactions.len();
    let blob_tx_hashes = blob_transaction_hashes(&inner.transactions);

    // From the bundle's KZG commitments, not from the transactions: this is the
    // list `newPayload` checks the block against, and the execution layer that
    // built it is the authority on it.
    let versioned_hashes = envelope
        .blobs_bundle
        .commitments
        .iter()
        .map(|c| alloy_eips::eip4844::kzg_to_versioned_hash(c.as_slice()))
        .collect();
    let cancun = CancunPayloadFields {
        parent_beacon_block_root,
        versioned_hashes,
    };
    let sidecar = match envelope.execution_requests {
        Some(requests) => ExecutionPayloadSidecar::v4(
            cancun,
            PraguePayloadFields {
                requests: RequestsOrHash::Requests(Requests::new(requests)),
            },
        ),
        None => ExecutionPayloadSidecar::v3(cancun),
    };

    // V4 when the build came back with an access list, V3 otherwise. The
    // variant is what carries the list to `newPayload`, and `newPayload` is
    // where reth decides between rayon workers and a `while` loop.
    let payload = match envelope.execution_payload.block_access_list {
        Some(block_access_list) => ExecutionPayload::V4(ExecutionPayloadV4 {
            payload_inner: envelope.execution_payload.payload,
            block_access_list,
            // EIP-7843's slot number is a consensus-layer concept and this
            // chain has no slots: HotStuff commits a block per view, so the
            // block's own number is the only monotonic index every member
            // agrees on without being told. It is what this node will send
            // back with the block, so leader and followers derive it the same
            // way from the same block.
            slot_number: number,
        }),
        None => ExecutionPayload::V3(envelope.execution_payload.payload),
    };

    Ok(BuiltBlock {
        hash,
        number,
        timestamp,
        tx_count,
        execution_data: ExecutionData::new(payload, sidecar),
        blob_tx_hashes,
        header: None,
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
    async fn latest_block_number(&self) -> Result<Option<u64>, ElError> {
        let hex: String = self
            .call("eth_blockNumber", vec![])
            .await
            .map_err(|e| ElError::new(e.to_string()))?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map(Some)
            .map_err(|e| ElError::new(format!("eth_blockNumber returned {hex}: {e}")))
    }

    async fn block_by_hash(&self, hash: B256) -> Result<Option<ChainBlock>, ElError> {
        let block: Option<alloy_rpc_types_eth::Block> = self
            .call("eth_getBlockByHash", vec![json!(hash), json!(true)])
            .await
            .map_err(|e| ElError::new(e.to_string()))?;
        Ok(block.map(block_parts))
    }

    async fn block_by_number(&self, number: u64) -> Result<Option<ChainBlock>, ElError> {
        // The Engine API's auth endpoint also serves the handful of `eth_`
        // methods the spec requires of it, this one among them, so no second
        // endpoint is needed to serve peers the chain.
        let block: Option<alloy_rpc_types_eth::Block> = self
            .call("eth_getBlockByNumber", vec![json!(format!("0x{number:x}")), json!(true)])
            .await
            .map_err(|e| ElError::new(e.to_string()))?;
        Ok(block.map(block_parts))
    }

    async fn send_raw_transaction(&self, raw: alloy_primitives::Bytes) -> Result<B256, ElError> {
        // The Engine API's auth endpoint serves this too: the spec requires
        // it of every execution client, for exactly this use.
        self.call("eth_sendRawTransaction", vec![json!(raw)])
            .await
            .map_err(|e| ElError::new(e.to_string()))
    }

    async fn send_raw_transactions(&self, raws: Vec<alloy_primitives::Bytes>) -> usize {
        // Chunked, because a batch is one HTTP body and the execution layer
        // caps how large that may be (reth's `--rpc.max-request-size`, 15 MB by
        // default). A hex-encoded transfer is a few hundred bytes of JSON, so
        // a thousand of them is comfortably inside any such limit while still
        // being a thousand round trips saved.
        const CHUNK: usize = 1000;
        let mut accepted = 0;
        for chunk in raws.chunks(CHUNK) {
            accepted += self
                .transport
                .call_many(
                    "eth_sendRawTransaction",
                    chunk.iter().map(|raw| vec![json!(raw)]).collect(),
                )
                .await;
        }
        accepted
    }

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
        let beacon_root = attrs.parent_beacon_block_root;
        // Newest-first, like `getPayload`, and for the same reason: this client
        // does not carry the fork schedule, and each version is bound to a fork
        // in *both* directions. Amsterdam refuses V3-with-attributes and
        // requires EIP-7843's slot number; everything before Amsterdam refuses
        // V4 and refuses a slot number outright. Sending one shape to every
        // chain therefore breaks whichever chain it was not written for, which
        // is how a fix for an Amsterdam fleet stopped a Prague one.
        //
        // So the newest shape is tried and the older one answers for the older
        // chain. The fallback covers both refusals a wrong version produces:
        // `UNSUPPORTED_FORK` for the method and `INVALID_PAYLOAD_ATTRIBUTES`
        // for the field.
        // Only the post-Cancun shape has two candidate versions. Attributes
        // without a beacon root belong to an older fork and their version is
        // decided by the fields alone, with nothing to fall back to.
        let older = [forkchoice_method(Some(&attrs))];
        let ladder: &[&str] = if attrs.parent_beacon_block_root.is_some() {
            &FCU_WITH_ATTRS_METHODS
        } else {
            &older
        };
        let mut last: Option<ElError> = None;
        let mut updated: Option<ForkchoiceUpdated> = None;
        // Start from the rung that answered last time. The chain does not
        // change fork under a running client, so a version it refused once it
        // refuses every time, and paying that refusal per build was measured
        // as one more round trip on every leader path of a pre-Amsterdam fleet.
        let start = self.fcu_rung.load(std::sync::atomic::Ordering::Relaxed).min(ladder.len() - 1);
        for (rung, &method) in ladder.iter().enumerate().skip(start) {
            let mut attempt = attrs.clone();
            if method == "engine_forkchoiceUpdatedV3" {
                attempt.slot_number = None;
            }
            debug!(target: "n42.h2.el", method, "forkchoiceUpdated with attributes");
            match self.call(method, vec![json!(state), json!(attempt)]).await {
                Ok(value) => {
                    self.fcu_rung.store(rung, std::sync::atomic::Ordering::Relaxed);
                    updated = Some(value);
                    break;
                }
                Err(TransportError::Rpc(err))
                    if err.code == UNSUPPORTED_FORK || err.code == INVALID_PAYLOAD_ATTRIBUTES =>
                {
                    last = Some(ElError::new(err));
                }
                Err(err) => return Err(ElError::new(err)),
            }
        }
        let updated = updated.ok_or_else(|| {
            last.unwrap_or_else(|| ElError::new("no forkchoiceUpdated version accepted the attributes"))
        })?;

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
        //
        // A build this client did not start has no remembered root. Zero is the
        // honest stand-in — it is what a pre-Cancun chain uses — and the block
        // will fail its own `newPayload` check rather than being imported under
        // a root nobody agreed to.
        let beacon_root = self.recall_build(id).unwrap_or_default();
        for method in GET_PAYLOAD_METHODS {
            match self.transport.call(method, vec![json!(id)]).await {
                Ok(value) => {
                    debug!(target: "n42.h2.el", method, "getPayload");
                    return Some(built_block_from_envelope(value, beacon_root));
                }
                // Wrong version for this build's fork: ask the next one down.
                Err(TransportError::Rpc(err)) if err.code == UNSUPPORTED_FORK => {}
                // A build the execution layer does not know about is an absent
                // result, not a failure: the driver retries or moves on.
                Err(TransportError::Rpc(err)) if err.code == UNKNOWN_PAYLOAD => return None,
                Err(err) => return Some(Err(ElError::new(err))),
            }
        }
        Some(Err(ElError::new(
            "no getPayload version accepted this build; the execution layer is on a fork this \
             adapter does not know",
        )))
    }
}

/// The consensus header and transactions inside an `eth_getBlockByNumber`
/// answer, which is what gov5's block form is built from.
pub fn block_parts(block: alloy_rpc_types_eth::Block) -> ChainBlock {
    let header = block.header.inner;
    let transactions = block
        .transactions
        .into_transactions_vec()
        .into_iter()
        .map(|tx| tx.inner.into_inner())
        .collect();
    ChainBlock { header, transactions, withdrawals: block.withdrawals.map(|w| w.0) }
}

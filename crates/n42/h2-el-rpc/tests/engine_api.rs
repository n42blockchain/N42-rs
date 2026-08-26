// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Engine API adapter against a recorded transport.
//!
//! What is worth testing here is not that JSON-RPC works — it is the mapping:
//! which method a payload goes to, which parameters it carries, and which
//! errors mean "absent" rather than "broken". Those are wrong silently. A
//! Prague block sent to `newPayloadV3` is rejected for a missing parameter,
//! which reads like a payload problem; a build collected without its beacon
//! root produces a block that cannot be re-imported, which surfaces one hop
//! later at a peer.
//!
//! So the transport is a recorder: every call is captured and answered from a
//! script, and the assertions are about what was sent.

use std::sync::{Arc, Mutex};

use alloy_eips::eip7685::{Requests, RequestsOrHash};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ExecutionPayloadV4,
    ForkchoiceState, PayloadAttributes,
    PayloadId, PraguePayloadFields,
};
use n42_h2_el_rpc::{
    new_payload_call, EngineApiClient, JsonRpcTransport, RpcError, TransportError, UNKNOWN_PAYLOAD,
};
use n42_h2_execution::{ExecutionLayer, ResolveKind};
use serde_json::{json, Value};

/// Records what was sent and answers from a script.
#[derive(Debug, Default)]
struct Recorder {
    calls: Mutex<Vec<(String, Vec<Value>)>>,
    answers: Mutex<Vec<Result<Value, i64>>>,
}

impl Recorder {
    fn with_answers(answers: Vec<Result<Value, i64>>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            answers: Mutex::new(answers),
        })
    }

    fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, _)| m.clone())
            .collect()
    }

    fn params(&self, index: usize) -> Vec<Value> {
        self.calls.lock().unwrap()[index].1.clone()
    }
}

/// The orphan rule forbids implementing the trait on `Arc<Recorder>` directly,
/// and the tests need a handle to inspect after the client has taken ownership.
#[derive(Debug, Clone)]
struct SharedRecorder(Arc<Recorder>);

#[async_trait::async_trait]
impl JsonRpcTransport for SharedRecorder {
    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, TransportError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push((method.to_string(), params));
        let mut answers = self.0.answers.lock().unwrap();
        match answers.is_empty() {
            true => Ok(Value::Null),
            false => match answers.remove(0) {
                Ok(value) => Ok(value),
                Err(code) => Err(TransportError::Rpc(RpcError {
                    code,
                    message: "scripted".into(),
                })),
            },
        }
    }
}

fn payload_v1() -> ExecutionPayloadV1 {
    ExecutionPayloadV1 {
        parent_hash: B256::repeat_byte(1),
        fee_recipient: Address::ZERO,
        state_root: B256::repeat_byte(2),
        receipts_root: B256::repeat_byte(3),
        logs_bloom: Default::default(),
        prev_randao: B256::ZERO,
        block_number: 7,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1_700_000_000,
        extra_data: Bytes::new(),
        difficulty: U256::ZERO,
        nonce: Default::default(),
        base_fee_per_gas: U256::from(7u64),
        block_hash: B256::repeat_byte(9),
        transactions: Vec::new(),
    }
}

fn payload_v3() -> ExecutionPayloadV3 {
    ExecutionPayloadV3 {
        payload_inner: ExecutionPayloadV2 {
            payload_inner: payload_v1(),
            withdrawals: Vec::new(),
        },
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

fn cancun_data() -> ExecutionData {
    ExecutionData::new(
        ExecutionPayload::V3(payload_v3()),
        ExecutionPayloadSidecar::v3(CancunPayloadFields {
            parent_beacon_block_root: B256::repeat_byte(0xBB),
            versioned_hashes: Vec::new(),
        }),
    )
}

fn prague_data() -> ExecutionData {
    ExecutionData::new(
        ExecutionPayload::V3(payload_v3()),
        ExecutionPayloadSidecar::v4(
            CancunPayloadFields {
                parent_beacon_block_root: B256::repeat_byte(0xBB),
                versioned_hashes: Vec::new(),
            },
            PraguePayloadFields {
                requests: RequestsOrHash::Requests(Requests::new(vec![Bytes::from_static(&[1])])),
            },
        ),
    )
}

/// The trap this adapter exists to avoid: a Prague block is a *V3* payload, and
/// sending it to `newPayloadV3` because of that is how it breaks.
#[test]
fn a_prague_payload_goes_to_v4_even_though_it_is_a_v3_struct() {
    let (method, params) = new_payload_call(&prague_data()).unwrap();
    assert_eq!(method, "engine_newPayloadV4");
    assert_eq!(params.len(), 4, "V4 carries execution requests as a 4th param");

    let (method, params) = new_payload_call(&cancun_data()).unwrap();
    assert_eq!(method, "engine_newPayloadV3");
    assert_eq!(params.len(), 3);
}

#[test]
fn a_v2_payload_is_sent_in_the_flattened_shape_the_method_expects() {
    let data = ExecutionData::new(
        ExecutionPayload::V2(ExecutionPayloadV2 {
            payload_inner: payload_v1(),
            withdrawals: Vec::new(),
        }),
        ExecutionPayloadSidecar::none(),
    );
    let (method, params) = new_payload_call(&data).unwrap();
    assert_eq!(method, "engine_newPayloadV2");

    // `ExecutionPayloadInputV2` is a V1 payload with withdrawals flattened
    // alongside, not an `ExecutionPayloadV2` — the field must sit at the top
    // level, not nested under `executionPayload`.
    let sent = &params[0];
    assert!(sent.get("withdrawals").is_some());
    assert!(sent.get("blockHash").is_some());
    assert!(sent.get("executionPayload").is_none());
}

#[test]
fn a_v3_payload_without_cancun_fields_is_refused_rather_than_defaulted() {
    // Defaulting the beacon root to zero would produce a block that every peer
    // computes a different hash for.
    let data = ExecutionData::new(
        ExecutionPayload::V3(payload_v3()),
        ExecutionPayloadSidecar::none(),
    );
    assert!(new_payload_call(&data).is_err());
}

#[test]
fn amsterdam_is_refused_at_the_call_rather_than_mapped_by_guess() {
    // There is no execution client here to check the V5 mapping against, and a
    // wrong guess would first fail at the Amsterdam fork on a live chain.
    let data = ExecutionData::new(
        ExecutionPayload::V4(ExecutionPayloadV4 {
            payload_inner: payload_v3(),
            block_access_list: Bytes::new(),
            slot_number: 0,
        }),
        ExecutionPayloadSidecar::none(),
    );
    let err = new_payload_call(&data).unwrap_err();
    assert!(err.to_string().contains("Amsterdam"));
}

#[tokio::test]
async fn attributes_choose_the_forkchoice_version() {
    let recorder = Recorder::with_answers(vec![
        Ok(json!({"payloadStatus": {"status": "VALID"}, "payloadId": null})),
        Ok(json!({"payloadStatus": {"status": "VALID"}, "payloadId": null})),
        Ok(json!({"payloadStatus": {"status": "VALID"}, "payloadId": null})),
    ]);
    let client = EngineApiClient::new(SharedRecorder(recorder.clone()));
    let state = ForkchoiceState {
        head_block_hash: B256::repeat_byte(1),
        safe_block_hash: B256::repeat_byte(1),
        finalized_block_hash: B256::repeat_byte(1),
    };

    client.fork_choice_updated(state).await.unwrap();

    let mut attrs = PayloadAttributes {
        timestamp: 1,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(Vec::new()),
        parent_beacon_block_root: Some(B256::repeat_byte(0xBB)),
        target_gas_limit: None,
        slot_number: None,
    };
    client
        .fork_choice_updated_with_attrs(state, attrs.clone())
        .await
        .unwrap();

    // Withdrawals but no beacon root is Shanghai, and V3 rejects it for the
    // missing field.
    attrs.parent_beacon_block_root = None;
    client
        .fork_choice_updated_with_attrs(state, attrs)
        .await
        .unwrap();

    assert_eq!(
        recorder.methods(),
        vec![
            "engine_forkchoiceUpdatedV3",
            "engine_forkchoiceUpdatedV3",
            "engine_forkchoiceUpdatedV2",
        ]
    );
    // An attribute-less update must still send an explicit null second param;
    // omitting it makes the call arity wrong.
    assert_eq!(recorder.params(0)[1], Value::Null);
}

#[tokio::test]
async fn an_unknown_payload_is_absence_not_failure() {
    // A build the execution layer has forgotten — superseded, or the EL
    // restarted. The driver retries or moves on; treating it as an error would
    // make a routine race look like a broken execution layer.
    let recorder = Recorder::with_answers(vec![Err(UNKNOWN_PAYLOAD)]);
    let client = EngineApiClient::new(SharedRecorder(recorder));

    let result = client
        .resolve_payload(PayloadId::new([1; 8]), ResolveKind::WaitForPending)
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn any_other_rpc_error_is_a_failure_not_absence() {
    let recorder = Recorder::with_answers(vec![Err(-32000)]);
    let client = EngineApiClient::new(SharedRecorder(recorder));

    let result = client
        .resolve_payload(PayloadId::new([1; 8]), ResolveKind::WaitForPending)
        .await;
    assert!(matches!(result, Some(Err(_))));
}

/// The Engine API never echoes `parentBeaconBlockRoot` back from `getPayload`,
/// but the built block cannot be re-imported without it. A block collected
/// without its root is accepted locally and rejected by every peer, one hop
/// later — so the client has to carry it across the two calls.
#[tokio::test]
async fn a_collected_build_carries_the_beacon_root_it_was_started_with() {
    let beacon_root = B256::repeat_byte(0xBB);
    let payload_id = PayloadId::new([7; 8]);
    let recorder = Recorder::with_answers(vec![
        Ok(json!({
            "payloadStatus": {"status": "VALID"},
            "payloadId": payload_id,
        })),
        Ok(json!({
            "executionPayload": payload_v3(),
            "blockValue": "0x0",
            "blobsBundle": {"commitments": [], "proofs": [], "blobs": []},
            "shouldOverrideBuilder": false,
        })),
    ]);
    let client = EngineApiClient::new(SharedRecorder(recorder));
    let state = ForkchoiceState {
        head_block_hash: B256::repeat_byte(1),
        safe_block_hash: B256::repeat_byte(1),
        finalized_block_hash: B256::repeat_byte(1),
    };

    client
        .fork_choice_updated_with_attrs(
            state,
            PayloadAttributes {
                timestamp: 1,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: Some(Vec::new()),
                parent_beacon_block_root: Some(beacon_root),
                target_gas_limit: None,
                slot_number: None,
            },
        )
        .await
        .unwrap();

    let built = client
        .resolve_payload(payload_id, ResolveKind::WaitForPending)
        .await
        .expect("the build exists")
        .expect("and is usable");

    assert_eq!(
        built.execution_data.sidecar.parent_beacon_block_root(),
        Some(beacon_root),
        "the collected block lost the root it was built under",
    );
    assert_eq!(built.number, 7);
    assert_eq!(built.tx_count, 0);
}

/// A build this client never started has no remembered root, and inventing one
/// would be worse than admitting it: the block fails its own `newPayload` check
/// instead of being imported under a root nobody agreed to.
#[tokio::test]
async fn a_build_this_client_did_not_start_gets_the_zero_root() {
    let recorder = Recorder::with_answers(vec![Ok(json!({
        "executionPayload": payload_v3(),
        "blockValue": "0x0",
        "blobsBundle": {"commitments": [], "proofs": [], "blobs": []},
        "shouldOverrideBuilder": false,
    }))]);
    let client = EngineApiClient::new(SharedRecorder(recorder));

    let built = client
        .resolve_payload(PayloadId::new([9; 8]), ResolveKind::WaitForPending)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        built.execution_data.sidecar.parent_beacon_block_root(),
        Some(B256::ZERO)
    );
}

/// A Prague endpoint answers `getPayload` with the V4 envelope, which is V3
/// with requests flattened on. Parsing it as V3 succeeds and drops them.
#[tokio::test]
async fn a_v4_envelope_keeps_its_execution_requests() {
    let recorder = Recorder::with_answers(vec![Ok(json!({
        "executionPayload": payload_v3(),
        "blockValue": "0x0",
        "blobsBundle": {"commitments": [], "proofs": [], "blobs": []},
        "shouldOverrideBuilder": false,
        "executionRequests": ["0x01ff"],
    }))]);
    let client = EngineApiClient::new(SharedRecorder(recorder));

    let built = client
        .resolve_payload(PayloadId::new([1; 8]), ResolveKind::WaitForPending)
        .await
        .unwrap()
        .unwrap();

    assert!(
        built.execution_data.sidecar.requests().is_some(),
        "the V4 envelope's execution requests were dropped",
    );
}

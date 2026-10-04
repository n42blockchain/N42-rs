// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests of the raw payload channel that need no running node: the pure
//! helpers, and `serve_connection` over a loopback socket with a scripted
//! payload service and a scripted engine behind it.

use super::*;
use alloy_consensus::{Header, Signed, TxEip1559};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV1, PayloadStatus,
    PayloadStatusEnum,
};
use n42_engine_types::N42EngineTypes;
use reth_engine_primitives::BeaconEngineMessage;
use reth_ethereum_primitives::TransactionSigned;
use reth_payload_builder::{PayloadBuilderError, PayloadServiceCommand};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// `LISTED_TRANSACTIONS` is one process-wide store holding two entries; every
/// test that writes to it (directly or through `push_built_payload`) takes
/// this lock so another test's entry cannot evict the one being asserted on.
static LISTED_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_listed() -> std::sync::MutexGuard<'static, ()> {
    LISTED_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn transactions(n: u64, salt: u8) -> Vec<n42_tx_types::N42TxEnvelope> {
    (0..n)
        .map(|i| {
            let tx = TxEip1559 {
                chain_id: 1,
                nonce: i,
                gas_limit: 21_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 1,
                to: TxKind::Call(Address::repeat_byte(salt)),
                value: U256::from(i),
                ..Default::default()
            };
            let hash = B256::repeat_byte(salt.wrapping_add(i as u8));
            n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(Signed::new_unchecked(
                tx,
                Signature::test_signature(),
                hash,
            )))
        })
        .collect()
}

/// A built payload of `n` transactions at block `number`; `salt` keeps the
/// block hash distinct between tests that share the process-wide store.
fn built(number: u64, n: u64, salt: u8, requests: Option<Vec<Bytes>>, bal: Option<Bytes>) -> N42BuiltPayload {
    let block = n42_tx_types::Block {
        header: Header { number, extra_data: vec![salt].into(), ..Default::default() },
        body: n42_tx_types::BlockBody { transactions: transactions(n, salt), ommers: Vec::new(), withdrawals: None },
    };
    let recovered = reth_primitives_traits::RecoveredBlock::new_sealed(
        SealedBlock::seal_slow(block),
        vec![Address::repeat_byte(1); n as usize],
    );
    let requests = requests.map(|list| {
        let mut out = alloy_eips::eip7685::Requests::default();
        for (i, bytes) in list.into_iter().enumerate() {
            out.push_request_with_type(i as u8, bytes);
        }
        out
    });
    N42BuiltPayload::new(Arc::new(recovered), U256::ZERO, requests, bal)
}

#[test]
fn a_compact_refusal_prints_the_assemblers_error_or_the_message_said() {
    assert_eq!(CompactRefusal::Said("no transaction queue".to_owned()).to_string(), "no transaction queue");
    let err = CompactBodyError::Missing {
        indices: vec![3, 9],
        total: 20,
        sample: vec![B256::repeat_byte(1)],
        waited: std::time::Duration::from_millis(20),
    };
    let text = CompactRefusal::Refused(err).to_string();
    assert!(text.starts_with("compact body: 2 of 20 transactions not held here, at indices 3..9"), "{text}");
    assert!(text.ends_with("waited 20 ms"), "{text}");
}

#[test]
fn only_the_last_two_served_blocks_keep_their_listed_transactions() {
    let _guard = lock_listed();
    let (a, b, c) = (B256::repeat_byte(0xE1), B256::repeat_byte(0xE2), B256::repeat_byte(0xE3));
    remember_listed(a, vec![Bytes::from_static(b"a")]);
    remember_listed(b, vec![Bytes::from_static(b"b")]);
    assert_eq!(listed_for(a).unwrap().as_slice(), [Bytes::from_static(b"a")]);
    remember_listed(c, vec![Bytes::from_static(b"c")]);
    assert!(listed_for(a).is_none(), "the oldest entry is evicted");
    assert!(listed_for(b).is_some());
    assert!(listed_for(c).is_some());
    // Serving the same block again replaces its entry instead of taking a slot.
    remember_listed(c, vec![Bytes::from_static(b"c2")]);
    assert_eq!(listed_for(c).unwrap().as_slice(), [Bytes::from_static(b"c2")]);
    assert!(listed_for(b).is_some(), "a refresh must not evict the other entry");
    assert!(listed_for(B256::repeat_byte(0xEF)).is_none());
}

#[tokio::test]
async fn complete_listing_puts_the_copied_list_into_the_payload() {
    let mut data = payload_data(&Header { number: 5, ..Default::default() }, B256::ZERO);
    let list = vec![Bytes::from_static(b"tx1"), Bytes::from_static(b"tx2")];
    let mut raw = Vec::new();
    let mut listing = Some(tokio::spawn({
        let list = list.clone();
        async move { list }
    }));
    complete_listing(&mut data, &mut raw, &mut listing, 5, true).await;
    assert!(listing.is_none(), "the handle is consumed");
    assert_eq!(data.payload.as_v1().transactions, list);
    assert_eq!(raw, list, "kept for the prune when asked");

    // Not kept once the direct import has the hashes.
    let mut data = payload_data(&Header { number: 6, ..Default::default() }, B256::ZERO);
    let mut raw = Vec::new();
    let mut listing = Some(tokio::spawn({
        let list = list.clone();
        async move { list }
    }));
    complete_listing(&mut data, &mut raw, &mut listing, 6, false).await;
    assert_eq!(data.payload.as_v1().transactions, list);
    assert!(raw.is_empty());
}

#[tokio::test]
async fn complete_listing_leaves_the_payload_alone_without_a_copy_or_after_a_failed_one() {
    let mut data = payload_data(&Header::default(), B256::ZERO);
    let mut raw = vec![Bytes::from_static(b"kept")];
    let mut listing = None;
    complete_listing(&mut data, &mut raw, &mut listing, 1, true).await;
    assert!(data.payload.as_v1().transactions.is_empty());
    assert_eq!(raw.len(), 1);

    // A copy that panicked: the list stays empty (the engine refuses it later).
    let mut listing: Option<tokio::task::JoinHandle<Vec<Bytes>>> =
        Some(tokio::spawn(async { panic!("copy failed") }));
    complete_listing(&mut data, &mut raw, &mut listing, 1, true).await;
    assert!(listing.is_none());
    assert!(data.payload.as_v1().transactions.is_empty());
    assert_eq!(raw.len(), 1, "a failed copy does not touch the raw list");
}

/// An execution payload carrying `header`'s fields under `hash`.
fn payload_data(header: &Header, hash: B256) -> ExecutionData {
    let v1 = ExecutionPayloadV1 {
        parent_hash: header.parent_hash,
        fee_recipient: header.beneficiary,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom,
        prev_randao: header.mix_hash,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.clone(),
        base_fee_per_gas: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash: hash,
        transactions: Vec::new(),
        difficulty: header.difficulty,
        nonce: header.nonce,
    };
    ExecutionData::new(ExecutionPayload::V1(v1), ExecutionPayloadSidecar::none())
}

fn built_header() -> Header {
    Header {
        number: 90,
        parent_hash: B256::repeat_byte(9),
        beneficiary: Address::repeat_byte(4),
        timestamp: 1_000,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(7),
        ..Default::default()
    }
}

#[test]
fn the_sealed_header_takes_the_fields_the_seal_may_have_changed() {
    let built = built_header();
    // What consensus sealed: another beneficiary, a view in the extra data.
    let mut sealed = built.clone();
    sealed.beneficiary = Address::repeat_byte(5);
    sealed.extra_data = vec![0xAB, 0xCD].into();
    sealed.state_root = B256::repeat_byte(3);
    let hash = sealed.hash_slow();
    let found = sealed_header_from_fields(&payload_data(&sealed, hash), &built).expect("fields match");
    assert_eq!(found.hash(), hash);
    assert_eq!(found.beneficiary, Address::repeat_byte(5));
    assert_eq!(found.extra_data.as_ref(), [0xAB, 0xCD]);
    assert_eq!(found.state_root, B256::repeat_byte(3));
}

#[test]
fn the_sealed_header_is_found_under_gov5s_other_header_shapes() {
    // The build left difficulty 5 and a zero ommers hash in the header; the
    // sealed block the payload names carries the usual shape instead.
    let mut built = built_header();
    built.difficulty = U256::from(5);
    built.ommers_hash = B256::repeat_byte(0x11);
    let mut sealed = built_header();
    sealed.difficulty = U256::ZERO;
    sealed.ommers_hash = B256::ZERO;
    let hash = sealed.hash_slow();
    let found = sealed_header_from_fields(&payload_data(&sealed, hash), &built).expect("a candidate matches");
    assert_eq!(found.difficulty, U256::ZERO);
    assert_eq!(found.ommers_hash, B256::ZERO);
    assert_eq!(found.hash(), hash);
}

#[test]
fn the_sealed_header_is_refused_when_the_shapes_disagree() {
    let built = built_header();
    // A different number or parent is another block altogether.
    let mut other_number = built.clone();
    other_number.number += 1;
    assert!(sealed_header_from_fields(&payload_data(&other_number, other_number.hash_slow()), &built).is_none());
    let mut other_parent = built.clone();
    other_parent.parent_hash = B256::repeat_byte(1);
    assert!(sealed_header_from_fields(&payload_data(&other_parent, other_parent.hash_slow()), &built).is_none());
    // A hash no candidate header produces.
    assert!(sealed_header_from_fields(&payload_data(&built, B256::repeat_byte(0xFF)), &built).is_none());
    // A base fee that does not fit a u64 cannot be a header's.
    let mut data = payload_data(&built, built.hash_slow());
    if let ExecutionPayload::V1(v1) = &mut data.payload {
        v1.base_fee_per_gas = U256::MAX;
    }
    assert!(sealed_header_from_fields(&data, &built).is_none());
}

#[test]
fn building_on_the_sealed_block_requires_equal_roots_and_gas_limits() {
    use alloy_eips::eip4895::Withdrawal;
    let built = built_header();
    let mut ours = built.clone();
    ours.extra_data = vec![9].into();
    assert!(build_executes_as_sealed(&built, None, &ours, None));
    for mutate in [
        (|h: &mut Header| h.mix_hash = B256::repeat_byte(1)) as fn(&mut Header),
        |h| h.gas_limit += 1,
        |h| h.base_fee_per_gas = Some(8),
        |h| h.parent_beacon_block_root = Some(B256::repeat_byte(2)),
        |h| h.transactions_root = B256::repeat_byte(3),
    ] {
        let mut sibling = built.clone();
        mutate(&mut sibling);
        assert!(!build_executes_as_sealed(&built, None, &sibling, None));
    }
    // A built block with no rewards matches a payload that lists none.
    let w = [Withdrawal { index: 1, validator_index: 1, address: Address::ZERO, amount: 1 }];
    assert!(!build_executes_as_sealed(&built, None, &ours, Some(&w)));
    assert!(build_executes_as_sealed(&built, Some(&[]), &ours, None));
}

#[test]
fn a_served_block_is_written_with_its_requests_and_access_list() {
    let _guard = lock_listed();
    let payload = built(301, 3, 0x31, Some(vec![Bytes::from_static(&[1, 2]), Bytes::from_static(&[3])]), Some(Bytes::from_static(&[7, 8, 9])));
    let mut out = Vec::new();
    let (block_len, _) = push_built_payload(&mut out, &payload);
    let rlp = encode_block_parallel(payload.block());
    assert_eq!(block_len, rlp.len());
    assert_eq!(out[0], 1);
    assert_eq!(u32::from_le_bytes(out[1..5].try_into().unwrap()) as usize, rlp.len());
    assert_eq!(&out[5..5 + rlp.len()], rlp.as_slice());
    let mut tail = &out[5 + rlp.len()..];
    assert_eq!(tail[0], 1, "requests present");
    let count = u32::from_le_bytes(tail[1..5].try_into().unwrap());
    assert_eq!(count, 2);
    tail = &tail[5..];
    for expected in [vec![0u8, 1, 2], vec![1u8, 3]] {
        let len = u32::from_le_bytes(tail[..4].try_into().unwrap()) as usize;
        assert_eq!(&tail[4..4 + len], expected.as_slice());
        tail = &tail[4 + len..];
    }
    assert_eq!(tail[0], 1, "access list present");
    assert_eq!(u32::from_le_bytes(tail[1..5].try_into().unwrap()), 3);
    assert_eq!(&tail[5..], [7, 8, 9]);
    // The transactions were kept, in the form a payload lists them.
    assert_eq!(listed_for(payload.block().hash()).unwrap().len(), 3);
}

#[test]
fn a_served_block_without_requests_or_access_list_ends_in_two_zero_flags() {
    let _guard = lock_listed();
    let payload = built(302, 1, 0x32, None, None);
    let mut out = Vec::new();
    push_built_payload(&mut out, &payload);
    assert_eq!(&out[out.len() - 2..], [0, 0]);
}

#[test]
fn the_hash_tail_lists_every_transaction_hash_in_block_order() {
    use alloy_consensus::transaction::TxHashRef as _;
    let _guard = lock_listed();
    let payload = built(303, 4, 0x33, None, None);
    let mut plain = Vec::new();
    push_built_payload_hashed(&mut plain, &payload, false);
    let mut hashed = Vec::new();
    push_built_payload_hashed(&mut hashed, &payload, true);
    assert_eq!(&hashed[..plain.len()], plain.as_slice(), "the hashed form extends the plain one");
    let tail = &hashed[plain.len()..];
    assert_eq!(tail[0], 1, "marker 1: hashes only, no frame layout");
    assert_eq!(u32::from_le_bytes(tail[1..5].try_into().unwrap()), 4);
    let expected: Vec<u8> =
        payload.block().body().transactions.iter().flat_map(|tx| tx.tx_hash().as_slice().to_vec()).collect();
    assert_eq!(&tail[5..], expected.as_slice());
}

#[test]
fn an_assembled_block_becomes_a_road_block_with_its_senders_and_timings() {
    let sealed = SealedBlock::seal_slow(n42_tx_types::Block {
        header: Header { number: 44, ..Default::default() },
        body: n42_tx_types::BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: None },
    });
    let payload = payload_data(&sealed.header().clone(), sealed.hash());
    let assembled = n42_engine_types::engine_validator::AssembledBlock {
        block: sealed,
        payload,
        senders: vec![Address::repeat_byte(8)],
        assemble_us: 1,
        total_us: 2,
        root_us: 3,
        miss_wait_us: 4,
        fill_us: 5,
        filled: 6,
        misses: 7,
    };
    let road = RoadBlock::assembled(assembled);
    assert_eq!((road.number, road.txs), (44, 0));
    assert_eq!(road.senders, Some(vec![Address::repeat_byte(8)]));
    assert_eq!(
        (road.assemble_us, road.total_us, road.root_us, road.miss_wait_us, road.fill_us, road.filled, road.misses),
        (1, 2, 3, 4, 5, 6, 7)
    );
    assert!(matches!(road.block, crate::follower_import::ForeignBlock::Sealed(_)));
}

// --- the channel over a loopback socket --------------------------------------

/// What the scripted payload service answers a `Resolve` with.
#[derive(Clone)]
enum Script {
    Unknown,
    Fails,
    Serves(N42BuiltPayload),
}

/// A connected client, with a scripted payload service and engine behind the
/// server half. The engine answers `engine_status` (or drops the request).
async fn loopback(
    script: Script,
    engine_status: Option<PayloadStatusEnum>,
) -> tokio::net::TcpStream {
    let (service_tx, mut service_rx) = mpsc::unbounded_channel::<PayloadServiceCommand<N42EngineTypes>>();
    tokio::spawn(async move {
        while let Some(command) = service_rx.recv().await {
            if let PayloadServiceCommand::Resolve(_, _, reply) = command {
                let _ = match script.clone() {
                    Script::Unknown => reply.send(None),
                    Script::Fails => reply.send(Some(Box::pin(async { Err(PayloadBuilderError::MissingPayload) }))),
                    Script::Serves(payload) => reply.send(Some(Box::pin(async move { Ok(payload) }))),
                };
            }
        }
    });
    let (engine_tx, mut engine_rx) = mpsc::unbounded_channel::<BeaconEngineMessage<N42EngineTypes>>();
    tokio::spawn(async move {
        while let Some(message) = engine_rx.recv().await {
            // Without a status the sender is dropped: the engine is gone.
            if let BeaconEngineMessage::NewPayload { tx, .. } = message
                && let Some(status) = engine_status.clone()
            {
                let _ = tx.send(Ok(PayloadStatus::from_status(status)));
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let payloads = PayloadBuilderHandle::new(service_tx);
    let engine = ConsensusEngineHandle::new(engine_tx);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = serve_connection::<N42EngineTypes>(stream, payloads, engine, None, None).await;
    });
    tokio::net::TcpStream::connect(addr).await.unwrap()
}

/// Reads an error reply: status 2, `u32` length, message.
async fn read_error(client: &mut tokio::net::TcpStream) -> String {
    assert_eq!(client.read_u8().await.unwrap(), 2, "an error status");
    let len = client.read_u32_le().await.unwrap() as usize;
    let mut message = vec![0u8; len];
    client.read_exact(&mut message).await.unwrap();
    String::from_utf8(message).unwrap()
}

async fn send_frame(client: &mut tokio::net::TcpStream, kind: u8, frame: &[u8]) {
    let mut request = vec![kind];
    request.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    request.extend_from_slice(frame);
    client.write_all(&request).await.unwrap();
}

async fn send_get(client: &mut tokio::net::TcpStream, kind: u8, id: u64) {
    let mut request = vec![kind];
    request.extend_from_slice(&id.to_le_bytes());
    client.write_all(&request).await.unwrap();
}

#[tokio::test]
async fn an_unknown_build_is_answered_with_status_zero_and_the_connection_lives_on() {
    let mut client = loopback(Script::Unknown, None).await;
    send_get(&mut client, request::GET_PAYLOAD, 1).await;
    assert_eq!(client.read_u8().await.unwrap(), 0);
    send_get(&mut client, request::GET_PAYLOAD_HASHED, 2).await;
    assert_eq!(client.read_u8().await.unwrap(), 0, "the same connection serves the next request");
}

#[tokio::test]
async fn a_failed_build_is_reported_with_the_builders_message() {
    let mut client = loopback(Script::Fails, None).await;
    send_get(&mut client, request::GET_PAYLOAD, 1).await;
    let message = read_error(&mut client).await;
    assert_eq!(message, PayloadBuilderError::MissingPayload.to_string());
}

/// A plain test over a hand-built runtime: the serving task writes the
/// process-wide listed-transaction store, so the lock is held for the whole
/// exchange and must not sit in an async body.
#[test]
fn get_payload_serves_the_built_block_and_hashed_adds_the_hash_tail() {
    let _guard = lock_listed();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let payload = built(310, 2, 0x41, None, None);
        let mut client = loopback(Script::Serves(payload.clone()), None).await;
        let mut expected = Vec::new();
        push_built_payload(&mut expected, &payload);

        send_get(&mut client, request::GET_PAYLOAD, 7).await;
        let mut got = vec![0u8; expected.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);

        send_get(&mut client, request::GET_PAYLOAD_HASHED, 7).await;
        let mut got = vec![0u8; expected.len() + 1 + 4 + 2 * 32];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..expected.len()], expected.as_slice());
        assert_eq!(got[expected.len()], 1);
    });
}

#[tokio::test]
async fn an_unknown_request_kind_ends_the_connection() {
    let mut client = loopback(Script::Unknown, None).await;
    client.write_u8(0xEE).await.unwrap();
    // The server drops the stream on the protocol error: the next read ends.
    let mut rest = Vec::new();
    let _ = client.read_to_end(&mut rest).await;
    assert!(rest.is_empty(), "no reply to a request kind nobody serves");
}

#[tokio::test]
async fn oversized_header_frames_end_the_connection_without_a_reply() {
    for kind in [request::OWN_BLOCK, request::BUILD_ON_OWN] {
        let mut client = loopback(Script::Unknown, None).await;
        let mut request = vec![kind];
        request.extend_from_slice(&((1u32 << 20) + 1).to_le_bytes());
        client.write_all(&request).await.unwrap();
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest).await;
        assert!(rest.is_empty(), "kind {kind}: no reply to an oversized frame");
    }
}

#[tokio::test]
async fn header_requests_on_a_node_without_reuse_are_refused_with_a_message() {
    let mut client = loopback(Script::Unknown, None).await;
    send_frame(&mut client, request::OWN_BLOCK, &[0xc0]).await;
    assert_eq!(read_error(&mut client).await, "no own-block reuse on this node");
    send_frame(&mut client, request::BUILD_ON_OWN, &[0xc0]).await;
    assert_eq!(read_error(&mut client).await, "no own-block reuse on this node");
}

#[tokio::test(flavor = "multi_thread")]
async fn body_requests_without_the_direct_import_say_to_send_the_payload() {
    let mut client = loopback(Script::Unknown, None).await;
    let frame = raw_engine::encode_foreign_body(B256::repeat_byte(1), Default::default(), &[0xc0]);
    send_frame(&mut client, request::FOREIGN_BODY, &frame).await;
    assert_eq!(read_error(&mut client).await, "no direct import; send the payload");
    send_frame(&mut client, request::COMPACT_BODY, &frame).await;
    assert_eq!(read_error(&mut client).await, "no direct import; send the payload");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_frame_that_does_not_decode_is_refused_with_its_road_named() {
    let mut client = loopback(Script::Unknown, None).await;
    send_frame(&mut client, request::FOREIGN_BODY, &[1, 2, 3]).await;
    assert!(read_error(&mut client).await.starts_with("foreign body frame: "));
    send_frame(&mut client, request::COMPACT_BODY, &[1, 2, 3]).await;
    assert!(read_error(&mut client).await.starts_with("compact body frame: "));
}

#[tokio::test]
async fn a_new_payload_frame_that_does_not_decode_is_an_error_reply() {
    let mut client = loopback(Script::Unknown, None).await;
    send_frame(&mut client, request::NEW_PAYLOAD, &[0xFF; 5]).await;
    let message = read_error(&mut client).await;
    assert!(!message.is_empty());
    // The connection survives a refused frame.
    send_get(&mut client, request::GET_PAYLOAD, 1).await;
    assert_eq!(client.read_u8().await.unwrap(), 0);
}

#[tokio::test]
async fn new_payload_hands_the_decoded_payload_to_the_engine_and_returns_its_status() {
    let header = Header { number: 12, base_fee_per_gas: Some(7), ..Default::default() };
    let data = payload_data(&header, header.hash_slow());
    let frame = raw_engine::encode_execution_data(&data);
    let mut client = loopback(Script::Unknown, Some(PayloadStatusEnum::Syncing)).await;
    send_frame(&mut client, request::NEW_PAYLOAD, &frame).await;
    assert_eq!(client.read_u8().await.unwrap(), 1);
    let len = client.read_u32_le().await.unwrap() as usize;
    let mut encoded = vec![0u8; len];
    client.read_exact(&mut encoded).await.unwrap();
    let status = raw_engine::decode_payload_status(&encoded).unwrap();
    assert_eq!(status.status, PayloadStatusEnum::Syncing);
}

#[tokio::test]
async fn an_engine_that_drops_the_request_is_reported_as_unavailable() {
    let header = Header { number: 13, base_fee_per_gas: Some(7), ..Default::default() };
    let frame = raw_engine::encode_execution_data(&payload_data(&header, header.hash_slow()));
    let mut client = loopback(Script::Unknown, None).await;
    send_frame(&mut client, request::NEW_PAYLOAD, &frame).await;
    let message = read_error(&mut client).await;
    assert!(message.to_lowercase().contains("engine"), "{message}");
}

fn unset(name: &str) -> bool {
    std::env::var_os(name).is_none()
}

/// The experiment switches read once per process default to the shipped
/// behaviour; each is checked only when the environment leaves it alone.
#[test]
fn the_experiment_switches_default_to_the_shipped_behaviour() {
    for (name, read) in [
        ("N42_BUILD_START_ASYNC", build_start_async as fn() -> bool),
        ("N42_BUILD_ON_OUTPUT", build_on_output),
        ("N42_TENURE_FIRST_ON_OUTPUT", tenure_first_on_output),
        ("N42_BUILD_ON_SEAL", build_on_seal),
        ("N42_RAW_SHARED_DECODE", raw_shared_decode),
        ("N42_PAYLOAD_SERVE_FRESH_BUFFERS", fresh_buffers),
        ("N42_QUEUE_WORK_OFFLOAD", queue_work_offload),
        ("N42_DIRECT_FAST_ANSWER", direct_fast_answer),
    ] {
        if unset(name) {
            assert!(!read(), "{name} is off by default");
        }
    }
    if unset("N42_PRUNE_ASYNC") {
        assert!(prune_async(), "the prune runs beside the answer by default");
    }
    if unset("N42_COMPACT_BODY_FILL") {
        assert_eq!(fill_share(), 2, "up to half a block is fetched by index");
    }
    if unset("N42_COMPACT_BODY_WAIT") {
        assert_eq!(miss_wait(), std::time::Duration::from_millis(20));
    }
}

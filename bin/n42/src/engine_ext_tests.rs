// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `n42Engine` handlers against a scripted payload service.

use super::*;
use alloy_consensus::{Header, Signed, TxEip1559};
use alloy_primitives::{Address, Signature, TxKind, B256, U256};
use n42_engine_types::N42EngineTypes;
use reth_ethereum_primitives::TransactionSigned;
use reth_payload_builder::{PayloadBuilderError, PayloadServiceCommand};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
enum Script {
    Unknown,
    Fails,
    Serves(N42BuiltPayload),
}

fn payload(requests: Option<Vec<Bytes>>, bal: Option<Bytes>) -> N42BuiltPayload {
    let tx = TxEip1559 {
        chain_id: 1,
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        to: TxKind::Call(Address::repeat_byte(2)),
        value: U256::from(1),
        ..Default::default()
    };
    let envelope = n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(Signed::new_unchecked(
        tx,
        Signature::test_signature(),
        B256::repeat_byte(0x61),
    )));
    let block = n42_tx_types::Block {
        header: Header { number: 17, ..Default::default() },
        body: n42_tx_types::BlockBody { transactions: vec![envelope], ommers: Vec::new(), withdrawals: None },
    };
    let recovered = reth_primitives_traits::RecoveredBlock::new_sealed(
        reth_primitives_traits::SealedBlock::seal_slow(block),
        vec![Address::repeat_byte(1)],
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

/// An endpoint whose payload service answers every `Resolve` as scripted.
fn ext(script: Script, raw_endpoint: Option<std::net::SocketAddr>) -> N42EngineExt<N42EngineTypes> {
    let (tx, mut rx) = mpsc::unbounded_channel::<PayloadServiceCommand<N42EngineTypes>>();
    tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            if let PayloadServiceCommand::Resolve(_, kind, reply) = command {
                assert_eq!(kind, PayloadKind::WaitForPending, "a build in progress is finished, not skipped");
                let _ = match script.clone() {
                    Script::Unknown => reply.send(None),
                    Script::Fails => reply.send(Some(Box::pin(async { Err(PayloadBuilderError::MissingPayload) }))),
                    Script::Serves(payload) => reply.send(Some(Box::pin(async move { Ok(payload) }))),
                };
            }
        }
    });
    N42EngineExt { payloads: PayloadBuilderHandle::new(tx), raw_endpoint, in_memory_blocks: None }
}

#[tokio::test]
async fn an_unknown_build_is_null() {
    let ext = ext(Script::Unknown, None);
    assert!(ext.get_payload_raw(PayloadId::new([1; 8])).await.unwrap().is_none());
}

#[tokio::test]
async fn a_failed_build_is_an_internal_error_with_the_builders_message() {
    let ext = ext(Script::Fails, None);
    let err = ext.get_payload_raw(PayloadId::new([1; 8])).await.unwrap_err();
    assert_eq!(err.code(), INTERNAL_ERROR_CODE);
    assert_eq!(err.message(), PayloadBuilderError::MissingPayload.to_string());
}

#[tokio::test]
async fn a_built_block_is_answered_as_rlp_with_its_requests_and_access_list() {
    let built = payload(Some(vec![Bytes::from_static(&[9, 9])]), Some(Bytes::from_static(&[1, 2, 3])));
    let served = ext(Script::Serves(built.clone()), None);
    let raw = served.get_payload_raw(PayloadId::new([2; 8])).await.unwrap().expect("known build");
    assert_eq!(raw.block.as_ref(), alloy_rlp::encode(built.block()).as_slice());
    assert_eq!(raw.requests, Some(vec![Bytes::from_static(&[0, 9, 9])]));
    assert_eq!(raw.block_access_list, Some(Bytes::from_static(&[1, 2, 3])));

    let bare = ext(Script::Serves(payload(None, None)), None);
    let raw = bare.get_payload_raw(PayloadId::new([3; 8])).await.unwrap().expect("known build");
    assert_eq!(raw.requests, None, "no requests before Prague");
    assert_eq!(raw.block_access_list, None);
}

#[tokio::test]
async fn the_payload_endpoint_is_the_raw_channels_address_when_there_is_one() {
    let addr: std::net::SocketAddr = "127.0.0.1:9551".parse().unwrap();
    assert_eq!(ext(Script::Unknown, Some(addr)).payload_endpoint().await.unwrap(), Some("127.0.0.1:9551".to_owned()));
    assert_eq!(ext(Script::Unknown, None).payload_endpoint().await.unwrap(), None);
}

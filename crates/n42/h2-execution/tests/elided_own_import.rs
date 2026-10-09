// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The own import of a block taken without its transactions
//! (`N42_TAKE_COMPACT`): the sealed header first, and when the execution
//! layer cannot take it that way, the body fetched on demand and the payload
//! made whole from it -- never the elided payload itself, which lists no
//! transactions and would import as a different block.

use std::sync::Mutex;

use alloy_primitives::{Bytes, B256};
use alloy_rpc_types_engine::{
    ExecutionData, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId, PayloadStatus,
    PayloadStatusEnum,
};
use n42_h2_execution::driver::import_own;
use n42_h2_execution::{BuiltBlock, ChainBlock, ElError, ExecutionLayer, MockExecutionLayer, ResolveKind};

/// What the execution layer does with the header, and what it was sent.
#[derive(Default)]
struct Recording {
    /// Whether the header-only import is taken.
    by_header: bool,
    /// The body `own_block_body` answers with; `None` = no longer held.
    body: Option<ChainBlock>,
    headers: Mutex<Vec<B256>>,
    bodies_asked: Mutex<usize>,
    payloads: Mutex<Vec<ExecutionData>>,
}

fn valid() -> PayloadStatus {
    PayloadStatus { status: PayloadStatusEnum::Valid, latest_valid_hash: None }
}

#[async_trait::async_trait]
impl ExecutionLayer for Recording {
    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError> {
        self.payloads.lock().unwrap().push(payload);
        Ok(valid())
    }

    async fn own_block_body(&self, header: &alloy_consensus::Header) -> Result<Option<ChainBlock>, ElError> {
        *self.bodies_asked.lock().unwrap() += 1;
        Ok(self.body.clone().map(|body| ChainBlock { header: header.clone(), ..body }))
    }

    async fn import_own_block_by_header(&self, header: &alloy_consensus::Header) -> Option<PayloadStatus> {
        self.headers.lock().unwrap().push(header.hash_slow());
        self.by_header.then(valid)
    }

    async fn fork_choice_updated(&self, _state: ForkchoiceState) -> Result<ForkchoiceUpdated, ElError> {
        Err(ElError::new("not used"))
    }

    async fn fork_choice_updated_with_attrs(
        &self,
        _state: ForkchoiceState,
        _attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError> {
        Err(ElError::new("not used"))
    }

    async fn resolve_payload(&self, _id: PayloadId, _kind: ResolveKind) -> Option<Result<BuiltBlock, ElError>> {
        None
    }
}

/// A built block as an elided answer delivers it: its header, no
/// transactions in the payload, the count beside it.
fn elided(tx_count: usize) -> (BuiltBlock, alloy_consensus::Header) {
    let mut built = MockExecutionLayer::built_block(7);
    let header = built.execution_data.clone().into_block_raw().expect("block").header;
    built.header = Some(header.clone());
    built.tx_count = tx_count;
    built.elided = true;
    (built, header)
}

fn transactions(n: usize) -> Vec<Bytes> {
    (0..n).map(|i| Bytes::from(vec![0x02, i as u8])).collect()
}

#[tokio::test]
async fn an_elided_own_block_imports_by_its_header_without_fetching_the_body() {
    let (built, header) = elided(3);
    let el = Recording { by_header: true, ..Default::default() };
    let status = import_own(&el, built.header.as_ref(), built.execution_data.clone(), Some(built.tx_count))
        .await
        .expect("imports");
    assert!(status.status.is_valid());
    assert_eq!(*el.headers.lock().unwrap(), vec![header.hash_slow()]);
    assert_eq!(*el.bodies_asked.lock().unwrap(), 0, "the body is not fetched when the header suffices");
    assert!(el.payloads.lock().unwrap().is_empty(), "no payload sent");
}

#[tokio::test]
async fn a_refused_header_fetches_the_body_and_sends_the_whole_payload() {
    let (built, header) = elided(3);
    let el = Recording {
        by_header: false,
        body: Some(ChainBlock { header: header.clone(), transactions: transactions(3), withdrawals: None }),
        ..Default::default()
    };
    import_own(&el, built.header.as_ref(), built.execution_data.clone(), Some(built.tx_count))
        .await
        .expect("imports");
    assert_eq!(*el.bodies_asked.lock().unwrap(), 1, "fetched on demand, once");
    let payloads = el.payloads.lock().unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].payload.as_v1().transactions, transactions(3), "the whole block, not the elided payload");
    assert_eq!(payloads[0].block_hash(), built.hash);
}

#[tokio::test]
async fn an_elided_payload_is_never_sent_without_its_body() {
    // No longer held: an error, not an empty block.
    let (built, _) = elided(3);
    let el = Recording { by_header: false, body: None, ..Default::default() };
    assert!(import_own(&el, built.header.as_ref(), built.execution_data.clone(), Some(3)).await.is_err());
    assert!(el.payloads.lock().unwrap().is_empty());

    // A body of the wrong length is not this block either.
    let (built, header) = elided(3);
    let el = Recording {
        by_header: false,
        body: Some(ChainBlock { header, transactions: transactions(2), withdrawals: None }),
        ..Default::default()
    };
    assert!(import_own(&el, built.header.as_ref(), built.execution_data.clone(), Some(3)).await.is_err());
    assert!(el.payloads.lock().unwrap().is_empty());

    // And without the sealed header there is nothing to ask by.
    let (built, _) = elided(3);
    let el = Recording { by_header: true, ..Default::default() };
    assert!(import_own(&el, None, built.execution_data.clone(), Some(3)).await.is_err());
}

#[tokio::test]
async fn a_whole_own_block_is_imported_exactly_as_before() {
    // Switch off: no elision, the trait's own import (header, then payload)
    // and nothing fetched.
    let built = MockExecutionLayer::built_block(7);
    let el = Recording { by_header: true, ..Default::default() };
    import_own(&el, None, built.execution_data.clone(), None).await.expect("imports");
    assert!(el.headers.lock().unwrap().is_empty(), "the default import_own_block sends the payload");
    assert_eq!(*el.bodies_asked.lock().unwrap(), 0);
    assert_eq!(el.payloads.lock().unwrap().len(), 1);
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds on the sealed block, and the early seal: the leader's next block
//! assembled while its parent is still importing, sealed for the view it
//! expects to lead, and its body encoded before the proposal asks for it.
//!
//! The plain mock offers no direct build on a sealed block, so these use a
//! wrapper that does, in three flavours.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionData, ExecutionPayload, PayloadAttributes};
use n42_h2_execution::{BuiltBlock, ElError, ExecutionDriver, ExecutionLayer, MockExecutionLayer};

const GENESIS: B256 = B256::ZERO;

fn attrs() -> PayloadAttributes {
    PayloadAttributes {
        slot_number: None,
        target_gas_limit: None,
        timestamp: 1_700_000_001,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: None,
        parent_beacon_block_root: None,
    }
}

#[derive(Clone, Copy)]
enum Direct {
    /// Builds the block on the sealed header it was handed.
    OnTheHeader,
    /// Builds a block on some other parent.
    OnAnotherParent,
    /// Fails.
    Fails,
}

/// A mock that, unlike the plain one, offers the direct build on a sealed
/// block (`build_on_own_block`).
struct DirectEl {
    mock: MockExecutionLayer,
    mode: Direct,
}

#[async_trait::async_trait]
impl ExecutionLayer for DirectEl {
    async fn new_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<alloy_rpc_types_engine::PayloadStatus, ElError> {
        self.mock.new_payload(payload).await
    }
    async fn fork_choice_updated(
        &self,
        state: alloy_rpc_types_engine::ForkchoiceState,
    ) -> Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError> {
        self.mock.fork_choice_updated(state).await
    }
    async fn fork_choice_updated_with_attrs(
        &self,
        state: alloy_rpc_types_engine::ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<alloy_rpc_types_engine::ForkchoiceUpdated, ElError> {
        self.mock.fork_choice_updated_with_attrs(state, attrs).await
    }
    async fn resolve_payload(
        &self,
        id: alloy_rpc_types_engine::PayloadId,
        kind: n42_h2_execution::ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>> {
        self.mock.resolve_payload(id, kind).await
    }
    async fn build_on_own_block(
        &self,
        header: &alloy_consensus::Header,
        _attrs: PayloadAttributes,
    ) -> Option<Result<BuiltBlock, ElError>> {
        Some(match self.mode {
            Direct::OnTheHeader => Ok(MockExecutionLayer::built_block_on(header.number + 1, header.hash_slow())),
            Direct::OnAnotherParent => {
                Ok(MockExecutionLayer::built_block_on(header.number + 1, B256::repeat_byte(0xbb)))
            }
            Direct::Fails => Err(ElError::new("the sealed parent is gone")),
        })
    }
}

fn driver(mode: Direct) -> ExecutionDriver<DirectEl> {
    ExecutionDriver::new(DirectEl { mock: MockExecutionLayer::new(), mode }, GENESIS)
}

fn sealed_parent() -> (alloy_consensus::Header, B256) {
    let header = alloy_consensus::Header { number: 7, ..Default::default() };
    let hash = header.hash_slow();
    (header, hash)
}

fn stamp(payload: &ExecutionData, view: u64) -> ExecutionData {
    let mut finished = payload.clone();
    if let ExecutionPayload::V1(v1) = &mut finished.payload {
        v1.block_hash = B256::left_padding_from(&view.to_be_bytes());
    }
    finished
}

#[tokio::test]
async fn a_build_sealed_ahead_for_the_right_view_is_taken_as_it_is_with_its_body() {
    let (header, parent) = sealed_parent();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let mut driver = driver(Direct::OnTheHeader);
    driver.set_payload_normalizer(move |payload, _header, view| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok((stamp(payload, view), Some(alloy_consensus::Header { number: 8, ..Default::default() })))
    });
    driver.set_own_body_encoder(|execution, header| {
        assert_eq!(header.number, 8, "the encoder sees the finished header");
        Some(alloy_primitives::Bytes::from(execution.block_hash().0.to_vec()))
    });
    driver.prepare_build_on_sealed_for_view(parent, header, attrs(), None, Some(9)).await.expect("requested");
    let built = driver.build_block_on(parent, attrs(), 9).await.expect("built");

    let finished = B256::left_padding_from(&9u64.to_be_bytes());
    assert_eq!(built.hash, finished, "the sealed-ahead block replaced the raw one");
    assert_eq!(driver.last_build_path(), (true, None));
    assert!(driver.last_build_timing().presealed);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "sealed once, ahead, and not again at the proposal");
    assert_eq!(driver.take_encoded_body(finished), Some(alloy_primitives::Bytes::from(finished.0.to_vec())));
    assert!(driver.take_encoded_body(finished).is_none(), "taken once");
    assert!(driver.has_payload(&finished));
    assert_eq!(built.header.as_ref().map(|h| h.number), Some(8));
}

#[tokio::test]
async fn a_build_sealed_for_another_view_is_sealed_again_at_the_proposal() {
    let (header, parent) = sealed_parent();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let mut driver = driver(Direct::OnTheHeader);
    driver.set_payload_normalizer(move |payload, _header, view| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok((stamp(payload, view), Some(alloy_consensus::Header { number: 8, ..Default::default() })))
    });
    driver.set_own_body_encoder(|_, _| Some(alloy_primitives::Bytes::from_static(b"stale")));
    driver.prepare_build_on_sealed_for_view(parent, header, attrs(), None, Some(9)).await.expect("requested");
    let built = driver.build_block_on(parent, attrs(), 10).await.expect("built");
    assert_eq!(built.hash, B256::left_padding_from(&10u64.to_be_bytes()), "sealed for the view actually proposed");
    assert!(!driver.last_build_timing().presealed);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "once ahead for view 9, once at the proposal");
    assert!(driver.take_encoded_body(built.hash).is_none(), "the body encoded for view 9 is not this block's");
}

#[tokio::test]
async fn a_failed_early_seal_is_retried_at_the_proposal() {
    let (header, parent) = sealed_parent();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let mut driver = driver(Direct::OnTheHeader);
    driver.set_payload_normalizer(move |payload, _header, view| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err("key not loaded yet".to_owned());
        }
        Ok((stamp(payload, view), None))
    });
    driver.prepare_build_on_sealed_for_view(parent, header, attrs(), None, Some(4)).await.expect("requested");
    let built = driver.build_block_on(parent, attrs(), 4).await.expect("built");
    assert_eq!(built.hash, B256::left_padding_from(&4u64.to_be_bytes()));
    assert!(!driver.last_build_timing().presealed, "the early seal failed");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_failed_or_misplaced_build_on_the_sealed_block_falls_back_to_the_ordinary_build() {
    let (header, parent) = sealed_parent();

    // The execution layer fails the direct build.
    let mut driver = driver(Direct::Fails);
    driver.prepare_build_on_sealed(parent, header.clone(), attrs(), None).await.expect("requested");
    // Let the task fail and mark the request refused; a proposal that came
    // before that would instead collect the failure from the task itself.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let built = driver.build_block_on(parent, attrs(), 1).await.expect("built the ordinary way");
    assert_eq!(
        driver.last_build_path(),
        (false, Some("the execution layer refused the build on the sealed parent"))
    );
    assert_eq!(built.number, 1);

    // It builds, but on a parent other than the one asked for.
    let mut driver = self::driver(Direct::OnAnotherParent);
    driver.prepare_build_on_sealed(parent, header, attrs(), None).await.expect("requested");
    driver.build_block_on(parent, attrs(), 1).await.expect("rebuilt");
    assert_eq!(driver.last_build_path(), (false, Some("the build prepared ahead extends another parent")));
}

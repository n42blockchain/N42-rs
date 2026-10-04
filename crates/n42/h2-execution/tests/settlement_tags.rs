// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The forkchoice's safe and finalized hashes (`n42_h2_execution::settlement`,
//! `docs/PHASE_D_DEFERRED_EXECUTION.md` section 17): split (the default),
//! latest = committed, safe = certified, finalized = certified and persisted;
//! legacy, head = safe = finalized = the committed block.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadAttributes};
use n42_h2_consensus::EngineOutput;
use n42_h2_execution::{
    ElCall, ExecutionDriver, MockExecutionLayer, PersistedHeight, SettlementTags, Tag,
};

const GENESIS: B256 = B256::repeat_byte(0x01);

fn committed(hash: B256) -> EngineOutput {
    EngineOutput::BlockCommitted {
        view: 1,
        block_hash: hash,
        commit_qc: n42_h2_primitives::QuorumCertificate::genesis(),
        validator_changes: None,
    }
}

fn attrs(timestamp: u64) -> PayloadAttributes {
    PayloadAttributes {
        slot_number: None,
        target_gas_limit: None,
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: None,
        parent_beacon_block_root: None,
    }
}

/// A chain of `n` blocks on `parent`, numbered from `first`, with real
/// header hashes.
fn chain_on(parent: B256, first: u64, n: u64) -> Vec<(B256, alloy_rpc_types_engine::ExecutionData)> {
    let mut out = Vec::new();
    let mut parent = parent;
    for number in first..first + n {
        let block = MockExecutionLayer::built_block_on(number, parent);
        parent = block.hash;
        out.push((block.hash, block.execution_data));
    }
    out
}

/// The attribute-less forkchoices sent so far.
fn forkchoices(el: &MockExecutionLayer) -> Vec<ForkchoiceState> {
    el.calls()
        .into_iter()
        .filter_map(|call| match call {
            ElCall::ForkchoiceUpdated(state) => Some(state),
            _ => None,
        })
        .collect()
}

/// Every forkchoice sent, with attributes or without.
fn all_forkchoices(el: &MockExecutionLayer) -> Vec<ForkchoiceState> {
    el.calls()
        .into_iter()
        .filter_map(|call| match call {
            ElCall::ForkchoiceUpdated(state) | ElCall::ForkchoiceUpdatedWithAttrs(state) => Some(state),
            _ => None,
        })
        .collect()
}

/// A split driver under deferred execution from genesis, floored at genesis,
/// whose persisted block is read from `persisted`.
fn split_driver(el: &MockExecutionLayer, persisted: &Arc<AtomicU64>) -> ExecutionDriver<MockExecutionLayer> {
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(false);
    driver.set_settlement_tags(SettlementTags::Split);
    driver.set_deferred_execution_time(Some(0));
    let read = Arc::clone(persisted);
    driver.set_persisted_height(Arc::new(move || PersistedHeight::Known(read.load(Ordering::Relaxed))));
    driver.set_settlement_floor(GENESIS);
    driver
}

fn number_of(blocks: &[(B256, alloy_rpc_types_engine::ExecutionData)], hash: B256) -> u64 {
    if hash == GENESIS {
        return 0;
    }
    blocks.iter().position(|(h, _)| *h == hash).map_or(u64::MAX, |i| i as u64 + 1)
}

#[tokio::test]
async fn safe_is_one_behind_the_tip_and_finalized_follows_persistence_never_past_it() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(0));
    let mut driver = split_driver(&el, &persisted);
    let blocks = chain_on(GENESIS, 1, 24);
    let (mut last_safe, mut last_finalized) = (0u64, 0u64);
    for (i, (hash, payload)) in blocks.iter().enumerate() {
        let number = i as u64 + 1;
        // Persistence runs in batches, six to eight blocks behind the tip.
        if number.is_multiple_of(8) {
            persisted.store(number - 6, Ordering::Relaxed);
        }
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
        let sent = *forkchoices(&el).last().expect("a commit sends a forkchoice");
        assert_eq!(sent.head_block_hash, *hash, "latest is the committed block");
        // Certified is exactly one block behind the committed tip.
        let safe = number_of(&blocks, sent.safe_block_hash);
        assert_eq!(safe, number - 1, "block {number}: safe is the parent");
        let finalized = number_of(&blocks, sent.finalized_block_hash);
        assert!(finalized <= safe, "block {number}: finalized {finalized} past safe {safe}");
        assert!(finalized <= persisted.load(Ordering::Relaxed), "block {number}: finalized {finalized} past persisted");
        assert_eq!(finalized, safe.min(persisted.load(Ordering::Relaxed)));
        assert!(safe >= last_safe && finalized >= last_finalized, "block {number}: a tag moved backwards");
        (last_safe, last_finalized) = (safe, finalized);
    }
    assert_eq!(driver.safe_tag(), Some(Tag { number: 23, hash: blocks[22].0 }));
    assert_eq!(driver.finalized_tag(), Some(Tag { number: 18, hash: blocks[17].0 }));
}

#[tokio::test]
async fn before_deferred_execution_a_commit_certifies_its_own_block() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(100));
    let mut driver = split_driver(&el, &persisted);
    driver.set_deferred_execution_time(None);
    let blocks = chain_on(GENESIS, 1, 3);
    for (hash, payload) in &blocks {
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
    }
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    let tip = blocks[2].0;
    assert_eq!((sent.head_block_hash, sent.safe_block_hash, sent.finalized_block_hash), (tip, tip, tip));
}

#[tokio::test]
async fn a_view_change_that_drops_an_uncommitted_block_does_not_move_safe_backwards() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(100));
    let mut driver = split_driver(&el, &persisted);
    let blocks = chain_on(GENESIS, 1, 4);
    for (hash, payload) in &blocks[..3] {
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
    }
    assert_eq!(driver.safe_tag().map(|tag| tag.number), Some(2));
    // A block 4 proposed in a view that timed out: seen, never committed.
    let orphan = MockExecutionLayer::built_block_on(4, blocks[2].0);
    let orphan = {
        // A different block at the same height (another timestamp).
        let mut data = orphan.execution_data;
        if let alloy_rpc_types_engine::ExecutionPayload::V1(v1) = &mut data.payload {
            v1.timestamp += 1000;
        }
        (B256::repeat_byte(0x44), data)
    };
    driver.cache_payload(orphan.0, orphan.1);
    let safe_before = driver.safe_tag();
    // The next view commits its sibling.
    driver.cache_payload(blocks[3].0, blocks[3].1.clone());
    driver.handle_output(&committed(blocks[3].0)).await;
    assert_eq!(driver.safe_tag(), Some(Tag { number: 3, hash: blocks[2].0 }));
    assert!(driver.safe_tag().map(|tag| tag.number) >= safe_before.map(|tag| tag.number));
    // A commit re-asked for an ancestor (a replay) moves nothing back, and
    // the forkchoice it sends cannot carry tags above its head.
    driver.cache_payload(blocks[1].0, blocks[1].1.clone());
    driver.handle_output(&committed(blocks[1].0)).await;
    assert_eq!(driver.safe_tag(), Some(Tag { number: 3, hash: blocks[2].0 }));
    assert_eq!(driver.finalized_tag(), Some(Tag { number: 3, hash: blocks[2].0 }));
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    assert_eq!(sent.head_block_hash, blocks[1].0);
    assert_eq!((sent.safe_block_hash, sent.finalized_block_hash), (B256::ZERO, B256::ZERO), "zero is unchanged");
}

#[tokio::test]
async fn a_restarted_node_sends_no_tag_until_a_commit_proves_one() {
    let el = MockExecutionLayer::new();
    // The execution layer is at block 5, persisted through it.
    let earlier = chain_on(GENESIS, 1, 5);
    let start = earlier[4].0;
    let mut driver = ExecutionDriver::new(el.clone(), start);
    driver.set_commit_fcu_async(false);
    driver.set_settlement_tags(SettlementTags::Split);
    driver.set_deferred_execution_time(Some(0));
    driver.set_persisted_height(Arc::new(|| PersistedHeight::Known(5)));
    assert_eq!((driver.safe_tag(), driver.finalized_tag()), (None, None));
    // A Decide for a block this node has never seen: nothing proves a tag.
    let stranger = B256::repeat_byte(0x77);
    driver.handle_output(&committed(stranger)).await;
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    assert_eq!((sent.safe_block_hash, sent.finalized_block_hash), (B256::ZERO, B256::ZERO));
    // A build before any commit carries none either: the tags the execution
    // layer restored stay where they are, never back to genesis.
    let _ = driver.build_block_on(start, attrs(1_700_000_006), 1).await;
    let build = *all_forkchoices(&el).last().expect("a build forkchoice");
    assert_eq!((build.safe_block_hash, build.finalized_block_hash), (B256::ZERO, B256::ZERO));
    // The first commit on top of the restart point.
    let next = chain_on(start, 6, 1);
    driver.cache_payload(next[0].0, next[0].1.clone());
    driver.handle_output(&committed(next[0].0)).await;
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    assert_eq!((sent.head_block_hash, sent.safe_block_hash, sent.finalized_block_hash), (next[0].0, start, start));
}

#[tokio::test]
async fn an_unknown_persisted_height_holds_finalized() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(false);
    driver.set_settlement_tags(SettlementTags::Split);
    driver.set_deferred_execution_time(Some(0));
    driver.set_persisted_height(Arc::new(|| PersistedHeight::Unknown));
    driver.set_settlement_floor(GENESIS);
    let blocks = chain_on(GENESIS, 1, 4);
    for (hash, payload) in &blocks {
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
    }
    assert_eq!(driver.safe_tag().map(|tag| tag.number), Some(3));
    assert_eq!(driver.finalized_tag(), Some(Tag { number: 0, hash: GENESIS }), "genesis is the floor");
}

#[tokio::test]
async fn the_async_commit_path_carries_the_same_tags() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(1));
    let mut driver = split_driver(&el, &persisted);
    driver.set_commit_fcu_async(true);
    let mut reports = driver.take_commit_reports().expect("the report channel");
    let blocks = chain_on(GENESIS, 1, 3);
    for (hash, payload) in &blocks {
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
        let report = reports.recv().await.expect("a commit report");
        driver.finish_commit(report).await;
    }
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    assert_eq!((sent.head_block_hash, sent.safe_block_hash, sent.finalized_block_hash), (blocks[2].0, blocks[1].0, blocks[0].0));
}

#[tokio::test]
async fn legacy_sends_exactly_the_forkchoices_it_always_sent() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_commit_fcu_async(false);
    driver.set_settlement_tags(SettlementTags::Legacy);
    driver.set_deferred_execution_time(Some(0));
    // A persisted source and a floor change nothing in legacy.
    driver.set_persisted_height(Arc::new(|| PersistedHeight::Known(1)));
    driver.set_settlement_floor(GENESIS);
    let blocks = chain_on(GENESIS, 1, 3);
    for (hash, payload) in &blocks {
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
    }
    // A build on the last committed block, then a pulled block on top.
    let _ = driver.build_block_on(blocks[2].0, attrs(1_700_000_004), 1).await;
    let pulled = chain_on(blocks[2].0, 4, 1);
    driver.import_pulled(pulled[0].1.clone()).await.expect("pulled");
    let tip = blocks[2].0;
    let expected = vec![
        ForkchoiceState { head_block_hash: blocks[0].0, safe_block_hash: blocks[0].0, finalized_block_hash: blocks[0].0 },
        ForkchoiceState { head_block_hash: blocks[1].0, safe_block_hash: blocks[1].0, finalized_block_hash: blocks[1].0 },
        ForkchoiceState { head_block_hash: tip, safe_block_hash: tip, finalized_block_hash: tip },
        // The build: head = its parent, safe = finalized = the last commit.
        ForkchoiceState { head_block_hash: tip, safe_block_hash: tip, finalized_block_hash: tip },
        // The pulled block: head and safe, finalized = the last commit.
        ForkchoiceState { head_block_hash: pulled[0].0, safe_block_hash: pulled[0].0, finalized_block_hash: tip },
    ];
    assert_eq!(all_forkchoices(&el), expected);
}

#[tokio::test]
async fn a_pulled_block_moves_no_tag_under_split() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(100));
    let mut driver = split_driver(&el, &persisted);
    let blocks = chain_on(GENESIS, 1, 3);
    for (hash, payload) in &blocks {
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
    }
    let pulled = chain_on(blocks[2].0, 4, 2);
    for (_, payload) in &pulled {
        driver.import_pulled(payload.clone()).await.expect("pulled");
    }
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    assert_eq!((sent.head_block_hash, sent.safe_block_hash, sent.finalized_block_hash), (pulled[1].0, blocks[1].0, blocks[1].0));
    // The Decide for the pulled tip certifies its parent.
    driver.handle_output(&committed(pulled[1].0)).await;
    assert_eq!(driver.safe_tag(), Some(Tag { number: 4, hash: pulled[0].0 }));
}

/// A leader under the compact take answer (`N42_TAKE_COMPACT=1`): its builds
/// come back elided and are never cached as payloads.
fn elided_leader(el: &MockExecutionLayer, persisted: &Arc<AtomicU64>) -> ExecutionDriver<MockExecutionLayer> {
    el.set_behaviour(n42_h2_execution::MockBehaviour { elide_builds: true, ..Default::default() });
    split_driver(el, persisted)
}

#[tokio::test]
async fn a_leader_committing_its_own_elided_builds_moves_both_tags() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(2));
    let mut driver = elided_leader(&el, &persisted);
    let mut own = Vec::new();
    for view in 1..=4u64 {
        let built = driver.build_block_on(driver.head(), attrs(1_700_000_000 + view), view).await.expect("a build");
        assert!(built.elided, "the take answer was compact");
        driver.handle_output(&committed(built.hash)).await;
        assert_eq!(driver.head(), built.hash);
        own.push(built.hash);
    }
    // loop326 SPLIT node 0: safe and finalized stayed at genesis here.
    assert_eq!(driver.safe_tag(), Some(Tag { number: 3, hash: own[2] }));
    assert_eq!(driver.finalized_tag(), Some(Tag { number: 2, hash: own[1] }));
    let sent = *forkchoices(&el).last().expect("a forkchoice");
    assert_eq!((sent.head_block_hash, sent.safe_block_hash, sent.finalized_block_hash), (own[3], own[2], own[1]));
}

#[tokio::test]
async fn the_tags_follow_across_a_handover_from_leader_to_follower() {
    let el = MockExecutionLayer::new();
    let persisted = Arc::new(AtomicU64::new(1));
    let mut driver = elided_leader(&el, &persisted);
    let mut own = Vec::new();
    for view in 1..=3u64 {
        let built = driver.build_block_on(driver.head(), attrs(1_700_000_000 + view), view).await.expect("a build");
        driver.handle_output(&committed(built.hash)).await;
        own.push(built.hash);
    }
    assert_eq!(driver.safe_tag().map(|tag| tag.number), Some(2));
    // The tenure passes: the next blocks arrive from the new leader.
    let theirs = chain_on(own[2], 4, 3);
    let mut last = (2, 1);
    for (i, (hash, payload)) in theirs.iter().enumerate() {
        if i == 1 {
            // Persistence reaches into this node's own blocks.
            persisted.store(3, Ordering::Relaxed);
        }
        driver.cache_payload(*hash, payload.clone());
        driver.handle_output(&committed(*hash)).await;
        let safe = driver.safe_tag().expect("safe").number;
        let finalized = driver.finalized_tag().expect("finalized").number;
        assert_eq!(safe, 4 + i as u64 - 1, "safe is one behind the tip");
        assert!(finalized <= safe && finalized <= persisted.load(Ordering::Relaxed));
        assert!(safe >= last.0 && finalized >= last.1, "a tag moved backwards");
        last = (safe, finalized);
    }
    // Finalized walked from the follower's blocks into the leader's own.
    assert_eq!(driver.finalized_tag(), Some(Tag { number: 3, hash: own[2] }));
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The driver's half of the profile-1 vote gate
//! (`docs/MIXED_PRODUCTION_STANDARD.md` A13, E8, E14, AM19): a Round-1 vote
//! is released only by the execution layer's check (`ConsensusEvent::
//! BlockChecked`), a refused check releases none and the block is rejected,
//! `N42_VOTE_BEFORE_SLOT` cannot be turned on, and the settlement tags stay
//! `split`.
//!
//! Every wait is bounded. No test pauses the clock.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadStatusEnum;
use n42_h2_consensus::{ConsensusEvent, EngineOutput, VoteRules};
use n42_h2_execution::{
    BuiltBlock, DriverAction, ExecutionDriver, ForeignBody, ImportReport, MockBehaviour, MockExecutionLayer,
    SettlementTags,
};
use tokio::sync::{mpsc::UnboundedReceiver, Semaphore};

const GENESIS: B256 = B256::ZERO;

fn body_for(hash: B256, number: u64) -> ForeignBody {
    ForeignBody {
        block_hash: hash,
        number,
        timestamp: 1_700_000_000 + number,
        profile: n42_h2_consensus::N42HeaderProfile::Ethereum,
        rlp: alloy_primitives::Bytes::from_static(&[0xc0]),
        compact: false,
        source: None,
    }
}

fn chain(n: u64) -> Vec<BuiltBlock> {
    let mut parent = GENESIS;
    (1..=n)
        .map(|number| {
            let block = MockExecutionLayer::built_block_on(number, parent);
            parent = block.hash;
            block
        })
        .collect()
}

fn deferred_driver(el: &MockExecutionLayer) -> (ExecutionDriver<MockExecutionLayer>, UnboundedReceiver<ImportReport>) {
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    driver.set_deferred_execution_time(Some(0));
    let rx = driver.take_foreign_imports().expect("channel");
    (driver, rx)
}

async fn arrive(driver: &mut ExecutionDriver<MockExecutionLayer>, block: &BuiltBlock) -> DriverAction {
    driver.cache_payload(block.hash, block.execution_data.clone());
    driver.cache_body(body_for(block.hash, block.number));
    driver.handle_output(&EngineOutput::ExecuteBlock(block.hash)).await
}

async fn next_report(rx: &mut UnboundedReceiver<ImportReport>) -> ImportReport {
    tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("a report in time").expect("channel open")
}

async fn quiet(rx: &mut UnboundedReceiver<ImportReport>) -> bool {
    tokio::time::timeout(Duration::from_millis(150), rx.recv()).await.is_err()
}

fn checks(actions: &[DriverAction]) -> Vec<B256> {
    actions
        .iter()
        .filter_map(|action| match action {
            DriverAction::Consensus(event) => match event.as_ref() {
                ConsensusEvent::BlockChecked(hash) => Some(*hash),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// AM19: a proposal whose carried execution fields are not this node's result
/// for the parent, or whose transactions are not includable on the parent's
/// post-state, fails the execution layer's check (`bin/n42`
/// `follower_import`: `validate_against_parent`, `check_includable`). The
/// check then answers nothing, so no `BlockChecked` -- the only thing that
/// releases a Round-1 vote on a deferred chain -- reaches consensus; the
/// import's verdict rejects the block, which withdraws any evidence.
#[tokio::test]
async fn a_refused_check_releases_no_vote_and_rejects_the_block() {
    for reason in [
        "header against parent: deferred execution: the header's state root is not the parent's result",
        "transaction 3: nonce 7, the sender's next is 5",
    ] {
        let el = MockExecutionLayer::with_behaviour(MockBehaviour {
            take_bodies: true,
            check_refused: true,
            new_payload_status: PayloadStatusEnum::Invalid { validation_error: reason.to_string() },
            ..Default::default()
        });
        let (mut driver, mut rx) = deferred_driver(&el);
        driver.set_vote_rules(VoteRules::PROFILE1);
        let block = &chain(1)[0];
        assert!(matches!(arrive(&mut driver, block).await, DriverAction::Ignored));
        let report = next_report(&mut rx).await;
        assert!(matches!(report, ImportReport::Done(hash, _) if hash == block.hash), "{reason}: only a verdict: {report:?}");
        let actions = driver.finish_execute(report).await;
        assert!(checks(&actions).is_empty(), "{reason}: no vote released");
        assert!(
            actions.iter().any(|a| matches!(a, DriverAction::Rejected { block_hash, .. } if *block_hash == block.hash)),
            "{reason}: rejected: {actions:?}"
        );
        assert!(quiet(&mut rx).await, "{reason}: nothing more");
    }
}

/// A check that passes releases the vote, under profile 1 as today.
#[tokio::test]
async fn a_passed_check_releases_the_vote() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour { take_bodies: true, ..Default::default() });
    let (mut driver, mut rx) = deferred_driver(&el);
    driver.set_vote_rules(VoteRules::PROFILE1);
    let block = &chain(1)[0];
    arrive(&mut driver, block).await;
    let report = next_report(&mut rx).await;
    assert!(matches!(report, ImportReport::Checked(hash) if hash == block.hash), "the check first: {report:?}");
    assert_eq!(checks(&driver.finish_execute(report).await), vec![block.hash]);
}

/// E8 / J4: `N42_VOTE_BEFORE_SLOT` is not reachable under profile 1, set
/// before the rules or after them: a third block arriving with both slots
/// taken waits for a slot, vote and all.
#[tokio::test]
async fn profile1_never_votes_ahead_of_the_slot() {
    for rules_first in [false, true] {
        let blocks = chain(3);
        let gate = Arc::new(Semaphore::new(0));
        let el = MockExecutionLayer::with_behaviour(MockBehaviour {
            take_bodies: true,
            body_gate: Some(Arc::clone(&gate)),
            ..Default::default()
        });
        let (mut driver, mut rx) = deferred_driver(&el);
        if rules_first {
            driver.set_vote_rules(VoteRules::PROFILE1);
            driver.set_vote_before_slot(true);
        } else {
            driver.set_vote_before_slot(true);
            driver.set_vote_rules(VoteRules::PROFILE1);
        }
        for block in &blocks {
            assert!(matches!(arrive(&mut driver, block).await, DriverAction::Ignored));
        }
        let mut voted = Vec::new();
        for _ in 0..2 {
            let report = next_report(&mut rx).await;
            assert!(matches!(report, ImportReport::Checked(_)), "a check: {report:?}");
            voted.extend(checks(&driver.finish_execute(report).await));
        }
        assert!(quiet(&mut rx).await, "rules first {rules_first}: the third waits for a slot");
        assert!(!voted.contains(&blocks[2].hash));
        assert_eq!(driver.voted_ahead(), 0);
        gate.add_permits(3);
    }
}

/// E14: profile 1 keeps the `split` tags; `legacy` cannot be chosen, set
/// before the rules or after them. Today's rules still take it.
#[test]
fn profile1_keeps_the_split_settlement_tags() {
    let el = MockExecutionLayer::new();
    let mut today = ExecutionDriver::new(el.clone(), GENESIS);
    today.set_settlement_tags(SettlementTags::Legacy);
    assert_eq!(today.settlement_tags(), SettlementTags::Legacy);

    let mut before = ExecutionDriver::new(el.clone(), GENESIS);
    before.set_settlement_tags(SettlementTags::Legacy);
    before.set_vote_rules(VoteRules::PROFILE1);
    assert_eq!(before.settlement_tags(), SettlementTags::Split);

    let mut after = ExecutionDriver::new(el, GENESIS);
    after.set_vote_rules(VoteRules::PROFILE1);
    after.set_settlement_tags(SettlementTags::Legacy);
    assert_eq!(after.settlement_tags(), SettlementTags::Split);
}

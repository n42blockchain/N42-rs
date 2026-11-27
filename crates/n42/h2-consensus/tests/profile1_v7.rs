// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 vector V7 (leader schedule, `testdata/profile1/gov5/V7`,
//! a byte-exact copy) against this node's schedule code.
//!
//! - A15 leader tables and tenure windows (`LeaderSelector`).
//! - A18 epochs and boundaries (`EpochManager`).
//! - A22 / SYNC §10.2 `view_after_tc`, both the pure rule
//!   (`LeaderSelector::view_after_timeout`) and the engine's
//!   (`ConsensusEngine::view_after_tc`, configured as profile 1 is: rotate
//!   from view 0, the genesis epoch length).
//! - SYNC §10.4's sequences, AM32's rehearsal and the standard genesis's
//!   window-holds-a-boundary case, replayed step by step.
//!
//! One deliberate local difference: at `tc_view = u64::MAX` gov5's rule wraps
//! to 0 (the vector's `edge` row, matched by the pure rule); the engine
//! saturates there and stays at `u64::MAX`, because it never moves its view
//! backwards. The spec defines no view after the last one.

use alloy_primitives::{hex, Address};
use n42_h2_consensus::{ConsensusEngine, EpochManager, LeaderSelector, ValidatorInfo, ValidatorSet};
use n42_h2_primitives::BlsSecretKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

/// SHA-256 of `leader_schedule.json` as gov5 published it.
const SCHEDULE_SHA256: &str = "c835fa1672382b9e0438cd15e92e1020fda012dd14dad622c939a731c10697e5";

fn vector() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/V7/leader_schedule.json");
    let raw = std::fs::read(path).expect("V7");
    assert_eq!(hex::encode(Sha256::digest(&raw)), SCHEDULE_SHA256, "V7/leader_schedule.json is not gov5's byte-exact copy");
    serde_json::from_slice(&raw).expect("json")
}

fn number(value: &Value) -> u64 {
    value.as_u64().expect("a number")
}

fn key(i: usize) -> BlsSecretKey {
    BlsSecretKey::key_gen(&[i as u8 + 1; 32]).expect("a valid deterministic key")
}

fn set(n: usize) -> (Vec<BlsSecretKey>, ValidatorSet) {
    let sks: Vec<_> = (0..n).map(key).collect();
    let infos: Vec<_> = sks
        .iter()
        .enumerate()
        .map(|(i, sk)| ValidatorInfo {
            address: Address::with_last_byte(i as u8),
            bls_public_key: sk.public_key(),
            p2p_peer_id: None,
        })
        .collect();
    let vs = ValidatorSet::new(&infos, (n as u32).saturating_sub(1) / 3);
    assert_eq!(vs.len() as usize, n);
    (sks, vs)
}

/// An engine with profile 1's schedule: tenure `tenure`, rotate-on-timeout
/// from view 0, epoch length `epoch_length`.
fn engine(n: usize, tenure: u64, epoch_length: u64) -> (ConsensusEngine, mpsc::Receiver<n42_h2_consensus::EngineOutput>) {
    let (sks, vs) = set(n);
    let (tx, rx) = mpsc::channel(64);
    let mut engine = ConsensusEngine::new(0, sks[0].clone(), vs, 6_000, 30_000, tx);
    engine.set_leader_tenure(tenure);
    engine.set_rotate_on_timeout(Some(0), epoch_length);
    (engine, rx)
}

#[test]
fn profiles_are_profile_1s() {
    let v = vector();
    let profiles = v["profiles"].as_array().expect("profiles");
    assert_eq!(profiles.len(), 2);
    for p in profiles {
        assert_eq!(number(&p["validators"]), 4);
        assert!(p["rotateOnTimeoutActive"].as_bool().expect("bool"));
        assert_eq!(number(&p["rotateOnTimeoutFromView"]), 0);
    }
    assert_eq!((number(&profiles[0]["leaderTenure"]), number(&profiles[0]["epochLength"])), (8, 200));
    assert_eq!((number(&profiles[1]["leaderTenure"]), number(&profiles[1]["epochLength"])), (1, 10_800));
}

#[test]
fn leader_tables_match_gov5() {
    let v = vector();
    for table in v["leaderSchedule"].as_array().expect("leaderSchedule") {
        let (_, vs) = set(number(&table["n"]) as usize);
        let tenure = number(&table["tenure"]);
        for row in table["views"].as_array().expect("views") {
            let view = number(&row["view"]);
            assert_eq!(
                u64::from(LeaderSelector::leader_for_view_with_tenure(view, tenure, &vs)),
                number(&row["leader"]),
                "{}: view {view}",
                table["name"]
            );
        }
    }
}

#[test]
fn tenure_windows_match_gov5() {
    let v = vector();
    for row in v["tenureWindows"].as_array().expect("tenureWindows") {
        let (_, vs) = set(number(&row["n"]) as usize);
        let (tenure, view) = (number(&row["tenure"]), number(&row["view"]));
        let t = tenure.max(1);
        let window = view / t;
        assert_eq!(window, number(&row["window"]), "view {view}: window");
        assert_eq!(window * t, number(&row["firstView"]), "view {view}: first view");
        assert_eq!(window * t + t - 1, number(&row["lastView"]), "view {view}: last view");
        let leader = LeaderSelector::leader_for_view_with_tenure(view, tenure, &vs);
        assert_eq!(u64::from(leader), number(&row["leader"]), "view {view}: leader");
        // Every view of the window has that leader.
        for w in window * t..=window * t + t - 1 {
            assert_eq!(LeaderSelector::leader_for_view_with_tenure(w, tenure, &vs), leader, "view {w} in {view}'s window");
        }
    }
}

#[test]
fn epochs_match_gov5() {
    let v = vector();
    let (_, vs) = set(4);
    for row in v["epochs"].as_array().expect("epochs") {
        let (length, view) = (number(&row["epochLength"]), number(&row["view"]));
        let manager = EpochManager::with_epoch_length(vs.clone(), length);
        assert_eq!(manager.epoch_for_view(view), number(&row["epoch"]), "E = {length}, view {view}: epoch");
        assert_eq!(
            manager.is_epoch_boundary(view),
            row["isBoundary"].as_bool().expect("bool"),
            "E = {length}, view {view}: boundary"
        );
    }
}

#[test]
fn view_after_tc_matches_gov5() {
    let v = vector();
    let rows = v["viewAfterTC"].as_array().expect("viewAfterTC");
    assert_eq!(rows.len(), 52);
    for row in rows {
        let (x, tenure, length) = (number(&row["tcView"]), number(&row["tenure"]), number(&row["epochLength"]));
        let active = row["active"].as_bool().expect("bool");
        let result = number(&row["result"]);
        let what = format!("{} TC({x}) T = {tenure} E = {length} active = {active}", row["source"]);
        assert_eq!(LeaderSelector::view_after_timeout(x, tenure, length, active), result, "{what}");
        // Clamped = the result is the epoch boundary, not the window start.
        let window = (x / tenure.max(1)).checked_add(1).and_then(|w| w.checked_mul(tenure.max(1)));
        let boundary = (length > 0 && x >= 1)
            .then(|| ((x - 1) / length + 1).checked_mul(length).and_then(|b| b.checked_add(1)))
            .flatten();
        let clamped = active && tenure > 1 && boundary == Some(result) && window.is_some_and(|w| result < w);
        assert_eq!(clamped, row["clampedToEpochBoundary"].as_bool().expect("bool"), "{what}: clamp flag");

        // The engine, configured as the row's chain.
        let (mut e, _rx) = engine(4, tenure, length);
        e.set_rotate_on_timeout(active.then_some(0), length);
        let engine_result = e.view_after_tc(x);
        if x == u64::MAX {
            // gov5 wraps to 0; the engine never moves backwards (module doc).
            assert_eq!((result, engine_result), (0, u64::MAX), "{what}: the documented local difference");
        } else {
            assert_eq!(engine_result, result, "{what}: engine");
        }
    }
}

#[test]
fn sequences_match_gov5() {
    let v = vector();
    let sequences = v["sequences"].as_array().expect("sequences");
    assert_eq!(sequences.len(), 11);
    for seq in sequences {
        let id = seq["id"].as_str().expect("id");
        let (n, tenure, length) = (number(&seq["n"]) as usize, number(&seq["tenure"]), number(&seq["epochLength"]));
        let (_, vs) = set(n);
        let (e, _rx) = engine(n, tenure, length);
        let leader = |view: u64| u64::from(LeaderSelector::leader_for_view_with_tenure(view, tenure, &vs));
        let mut last_tc = None;
        let steps = seq["steps"].as_array().expect("steps");
        for (i, step) in steps.iter().enumerate() {
            let view = number(&step["view"]);
            let what = format!("{id} step {i} ({} at {view})", step["event"]);
            assert_eq!(leader(view), number(&step["leaderOfView"]), "{what}: leader of view");
            let next = match step["event"].as_str().expect("event") {
                "QC" => view + 1,
                "TC" => {
                    last_tc = Some(view);
                    let next = LeaderSelector::view_after_timeout(view, tenure, length, true);
                    assert_eq!(e.view_after_tc(view), next, "{what}: engine");
                    next
                }
                // A piggybacked TC (the latest TC of the sequence) moves a node
                // at `view` only if the view after it is higher.
                "adoptTC" | "ignoreTC" => {
                    let target = e.view_after_tc(last_tc.expect("a TC before"));
                    let adopt = target > view;
                    assert_eq!(adopt, step["event"] == "adoptTC", "{what}: adopt");
                    if adopt { target } else { view }
                }
                other => panic!("{what}: unknown event {other}"),
            };
            assert_eq!(next, number(&step["nextView"]), "{what}: next view");
            assert_eq!(leader(next), number(&step["nextLeader"]), "{what}: next leader");
            // A sequence is one node's path, except S11's race rows.
            if let Some(following) = steps.get(i + 1)
                && !matches!(following["event"].as_str(), Some("adoptTC" | "ignoreTC"))
                && !(id == "S11")
            {
                assert_eq!(number(&following["view"]), next, "{what}: the next step starts where this one ends");
            }
        }
    }
}

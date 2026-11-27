// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's AM33 vector (view-timeout backoff for consecutive absent leaders,
//! `testdata/profile1/gov5/AM33`, a byte-exact copy) against this node's
//! pacemaker: `timeout(c) = min(base * 2^floor(c / g), max)`,
//! `g = min(f + 1, 3)`, `f = floor((n - 1) / 3)`.
//!
//! - `groups`: `Pacemaker::backoff_group_size`.
//! - `timeouts`: the pacemaker at n = 4, 7, 100 and with no committee size
//!   (g = 1, the vector's `previousRuleMsByC`).
//! - `runs`: every run replayed with the pacemaker and the schedule (`c` on
//!   entering each view, +1 per TC, `view_after_tc` for the next view); the
//!   n = 4 and 7 runs are also replayed on engines in
//!   `state_machine_rotate_tests.rs` (`am33_runs_on_engines`).

use alloy_primitives::{hex, Address};
use n42_h2_consensus::{LeaderSelector, Pacemaker, ValidatorInfo, ValidatorSet};
use n42_h2_primitives::BlsSecretKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of `timeout_backoff.json` as gov5 published it.
const BACKOFF_SHA256: &str = "dd23ae8d4f3e3a7af25ed36ed3e7bf25da860d3a03dd63d266f4687348e9b222";

fn vector() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/AM33/timeout_backoff.json");
    let raw = std::fs::read(path).expect("AM33");
    assert_eq!(hex::encode(Sha256::digest(&raw)), BACKOFF_SHA256, "AM33 is not gov5's byte-exact copy");
    serde_json::from_slice(&raw).expect("json")
}

fn number(value: &Value) -> u64 {
    value.as_u64().expect("a number")
}

fn set(n: usize) -> ValidatorSet {
    let infos: Vec<_> = (0..n)
        .map(|i| ValidatorInfo {
            address: Address::with_last_byte(i as u8),
            bls_public_key: BlsSecretKey::key_gen(&[i as u8 + 1; 32]).expect("key").public_key(),
            p2p_peer_id: None,
        })
        .collect();
    ValidatorSet::new(&infos, (n as u32).saturating_sub(1) / 3)
}

fn ms(pacemaker: &Pacemaker, c: u32) -> u64 {
    pacemaker.timeout_duration(c).as_millis() as u64
}

#[test]
fn groups_match_gov5() {
    let v = vector();
    let rows = v["groups"].as_array().expect("groups");
    assert_eq!(rows.len(), 10);
    for row in rows {
        let n = number(&row["n"]) as usize;
        assert_eq!(((n - 1) / 3) as u64, number(&row["f"]), "n = {n}: f");
        assert_eq!(u64::from(Pacemaker::backoff_group_size(n)), number(&row["g"]), "n = {n}: g");
    }
}

#[test]
fn timeouts_match_gov5() {
    let v = vector();
    let rows = v["timeouts"].as_array().expect("timeouts");
    assert_eq!(rows.len(), 6);
    for row in rows {
        let (n, base, max) = (number(&row["n"]) as usize, number(&row["baseTimeoutMs"]), number(&row["maxTimeoutMs"]));
        let am33 = Pacemaker::with_committee_size(base, max, n);
        assert_eq!(u64::from(am33.backoff_group()), number(&row["g"]), "n = {n}: g");
        let previous = Pacemaker::new(base, max);
        for (c, (now, before)) in row["timeoutMsByC"]
            .as_array()
            .expect("by c")
            .iter()
            .zip(row["previousRuleMsByC"].as_array().expect("previous"))
            .enumerate()
        {
            assert_eq!(ms(&am33, c as u32), number(now), "n = {n}, {base}/{max}: c = {c}");
            assert_eq!(ms(&previous, c as u32), number(before), "n = {n}, {base}/{max}: c = {c}, previous rule");
        }
    }
}

#[test]
fn runs_match_gov5() {
    let v = vector();
    let runs = v["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 29);
    for run in runs {
        let id = run["id"].as_str().expect("id");
        let n = number(&run["n"]) as usize;
        let (tenure, length) = (number(&run["tenure"]), number(&run["epochLength"]));
        let (base, max) = (number(&run["baseTimeoutMs"]), number(&run["maxTimeoutMs"]));
        let vs = set(n);
        let dead: Vec<u64> = run["deadLeaders"].as_array().expect("dead").iter().map(number).collect();
        for (rule, pacemaker, gap) in [
            ("AM33", Pacemaker::with_committee_size(base, max, n), &run["gapMs"]),
            ("previous", Pacemaker::new(base, max), &run["previousRuleGapMs"]),
        ] {
            // From the first silent view: c starts at 0 (the views before
            // committed), grows by one per TC, and no TC resets it.
            let (mut view, mut c, mut total) = (number(&run["startView"]), 0u32, 0u64);
            for (i, step) in run["steps"].as_array().expect("steps").iter().enumerate() {
                let what = format!("{id} ({rule}) step {i}");
                assert_eq!(number(&step["view"]), view, "{what}: view");
                let leader = u64::from(LeaderSelector::leader_for_view_with_tenure(view, tenure, &vs));
                assert_eq!(leader, number(&step["leader"]), "{what}: leader");
                let timeout = ms(&pacemaker, c);
                if rule == "AM33" {
                    assert_eq!(u64::from(c), number(&step["c"]), "{what}: c on entry");
                    assert_eq!(timeout, number(&step["timeoutMs"]), "{what}: timer");
                }
                let silent = dead.contains(&leader);
                if silent {
                    assert_eq!(step["event"], "TC", "{what}: a silent leader's view ends in a TC");
                    total += timeout;
                    c += 1;
                    view = LeaderSelector::view_after_timeout(view, tenure, length, true);
                } else {
                    assert_eq!(step["event"], "QC", "{what}: a live leader's view ends in a QC");
                    view += 1;
                }
                assert_eq!(view, number(&step["nextView"]), "{what}: next view");
            }
            assert_eq!(total, number(gap), "{id} ({rule}): gap");
        }
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's profile-1 vector V2 (roots, `testdata/profile1/gov5/V2`, a
//! byte-exact copy) against this node's root and committee-link code.
//!
//! - B7 receiptsRoot: every receipt's encoding and the four roots
//!   (`gov5_receipts_root`), including a reverted CREATE and the Amsterdam
//!   EIP-7708 transfer log from `0xff..fe`.
//! - B6 withdrawalsRoot: every reward's encoding and the six roots
//!   (`gov5_rewards_root`), also through the Engine API withdrawals the
//!   node pays rewards as (`rewards_to_withdrawals` and back), which is the
//!   path block validation takes.
//! - B5 parentBeaconRoot: the committee, signing message, signer bitmap,
//!   aggregate signature, evidence bytes and root for V5's blocks 2..8 and
//!   the three ramp rows (`SimulatedCommitteePool`).

use alloy_primitives::{hex, keccak256, Address, Bytes, Log, B256, U256};
use n42_h2_consensus::{
    committee_pool::{active_pool, committee, signing_message},
    header_profile::{gov5_receipts_root, gov5_rewards_root, rewards_to_withdrawals, withdrawals_to_rewards, ReceiptView},
    CommitteePoolConfig, SimulatedCommitteePool,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of `roots.json` as gov5 published it (`V2/README.md`).
const ROOTS_SHA256: &str = "deff5a4736778ef0b70aedc30f747d7ccd89422479393d37cba04fc541cdef18";

fn vector() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1/gov5/V2/roots.json");
    let raw = std::fs::read(path).expect("V2");
    assert_eq!(hex::encode(Sha256::digest(&raw)), ROOTS_SHA256, "V2/roots.json is not gov5's byte-exact copy");
    serde_json::from_slice(&raw).expect("json")
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("hex")
}

fn b256(value: &Value) -> B256 {
    B256::from_slice(&bytes(value))
}

fn number(value: &Value) -> u64 {
    value.as_u64().expect("a number")
}

fn receipt_logs(receipt: &Value) -> Vec<Log> {
    receipt["logs"]
        .as_array()
        .expect("logs")
        .iter()
        .map(|log| {
            Log::new_unchecked(
                Address::from_slice(&bytes(&log["address"])),
                log["topics"].as_array().expect("topics").iter().map(b256).collect(),
                Bytes::from(bytes(&log["data"])),
            )
        })
        .collect()
}

#[test]
fn receipts_roots_match_gov5() {
    let v = vector();
    let receipts = v["receipts"].as_array().expect("receipts");
    let logs: Vec<Vec<Log>> = receipts.iter().map(receipt_logs).collect();
    let view = |i: usize| ReceiptView {
        success: number(&receipts[i]["status"]) == 1,
        cumulative_gas_used: number(&receipts[i]["cumulativeGasUsed"]),
        logs: &logs[i],
    };
    // Each receipt alone: the root is keccak of its encoding, so equal roots
    // are equal encodings.
    for (i, receipt) in receipts.iter().enumerate() {
        assert_eq!(gov5_receipts_root([view(i)]), keccak256(bytes(&receipt["encoding"])), "receipt {i}'s encoding");
    }
    // The revert and the EIP-7708 log are what the block is for.
    assert_eq!(number(&receipts[1]["status"]), 0);
    assert_eq!(logs[2][0].address, Address::from_slice(&[0xff; 19].iter().copied().chain([0xfe]).collect::<Vec<_>>()));
    let roots = v["receiptsRoots"].as_array().expect("receiptsRoots");
    assert_eq!(roots.len(), 4);
    for row in roots {
        let indexes: Vec<usize> =
            row["receiptIndexes"].as_array().expect("indexes").iter().map(|i| number(i) as usize).collect();
        assert_eq!(
            gov5_receipts_root(indexes.iter().map(|&i| view(i))),
            b256(&row["receiptsRoot"]),
            "{}",
            row["name"]
        );
    }
}

#[test]
fn withdrawals_roots_match_gov5() {
    let v = vector();
    let rows = v["withdrawalsRoots"].as_array().expect("withdrawalsRoots");
    assert_eq!(rows.len(), 6);
    for row in rows {
        let name = &row["name"];
        let rewards: Vec<(Address, U256)> = row["rewards"]
            .as_array()
            .expect("rewards")
            .iter()
            .map(|reward| {
                let pair = (
                    Address::from_slice(&bytes(&reward["address"])),
                    reward["amountWei"].as_str().expect("decimal").parse::<U256>().expect("wei"),
                );
                assert_eq!(gov5_rewards_root([pair]), keccak256(bytes(&reward["encoding"])), "{name}: encoding");
                pair
            })
            .collect();
        let expected = b256(&row["withdrawalsRoot"]);
        assert_eq!(gov5_rewards_root(rewards.clone()), expected, "{name}");
        // Through the withdrawals a block carries them as (block validation's path).
        let withdrawals = rewards_to_withdrawals(&rewards).expect("whole gwei");
        assert_eq!(withdrawals_to_rewards(&withdrawals), rewards, "{name}: round trip");
        assert_eq!(gov5_rewards_root(withdrawals_to_rewards(&withdrawals)), expected, "{name}: via withdrawals");
    }
}

#[test]
fn committee_evidence_matches_gov5() {
    let v = vector();
    let cfg = &v["committeePool"];
    let pool = SimulatedCommitteePool::new(CommitteePoolConfig {
        seed: b256(&cfg["seedHex"]),
        pool_size: number(&cfg["poolSize"]) as usize,
        committee_size: number(&cfg["committeeSize"]) as usize,
        ramp_blocks: number(&cfg["rampBlocks"]),
    })
    .expect("pool");
    let config = pool.config().clone();
    let rows = v["committeeEvidence"].as_array().expect("committeeEvidence");
    assert_eq!(rows.len(), 10);
    for row in rows {
        let parent = number(&row["parentNumber"]);
        let name = format!("{} (parent {parent})", row["name"].as_str().unwrap_or("?"));
        let hash = b256(&row["parentHash"]);
        let receipts_root = b256(&row["parentReceiptsRoot"]);
        let active = number(&row["activePoolSize"]) as usize;
        assert_eq!(active_pool(parent, config.pool_size, config.committee_size, config.ramp_blocks), active, "{name}: active pool");
        assert_eq!(pool.active_size(parent), active, "{name}: active pool");
        let members: Vec<usize> =
            row["committee"].as_array().expect("committee").iter().map(|i| number(i) as usize).collect();
        assert_eq!(committee(parent, &hash, active, config.committee_size), members, "{name}: committee");
        assert_eq!(pool.committee_at(parent, &hash), members, "{name}: committee");
        assert_eq!(signing_message(parent, &hash).as_slice(), bytes(&row["signingMessage"]), "{name}: signing message");

        let evidence = pool.build_evidence(parent, &hash, &receipts_root).expect("evidence");
        assert_eq!(evidence.signer_count as u64, number(&row["signerCount"]), "{name}: signer count");
        assert_eq!(evidence.signers_packed, bytes(&row["signersPacked"]), "{name}: signer bitmap");
        assert_eq!(evidence.aggregate_signature.as_slice(), bytes(&row["aggregateSignature"]), "{name}: aggregate signature");
        let marshalled = evidence.marshal();
        assert_eq!(marshalled.len(), 405, "{name}: evidence length");
        assert_eq!(marshalled, bytes(&row["evidence"]), "{name}: evidence bytes");
        let root = b256(&row["parentBeaconRoot"]);
        assert_eq!(evidence.beacon_root(), root, "{name}: parentBeaconRoot");
        assert_eq!(pool.parent_beacon_root(parent, &hash, &receipts_root).expect("root"), root, "{name}: parent_beacon_root");
    }
    // B5: block 1 (parent genesis) carries the zero root.
    assert_eq!(pool.parent_beacon_root(0, &B256::repeat_byte(1), &B256::ZERO).expect("root"), B256::ZERO);
}

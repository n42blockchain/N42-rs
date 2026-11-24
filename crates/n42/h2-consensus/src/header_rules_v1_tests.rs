// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's vector V1 (profile 1 header profile) against this crate's rules:
//! `testdata/profile1/header_profile_v1.json`, byte-exact from gov5.
//!
//! 1. The genesis and the two sealed headers decode, re-encode to the same
//!    RLP, hash to gov5's hash, and (blocks) have gov5's seal hash and a seal
//!    that verifies under the view's leader.
//! 2. Both blocks pass every rule; each of the 25 refused headers is refused
//!    for the rule gov5 names. Every mismatch, in either direction, fails
//!    the test with the header's name.

use super::*;
use crate::header_profile::{gov5_rewards_root, seal_hash};
use alloy_primitives::{hex, Address, B256, U256};
use alloy_rlp::Decodable;
use n42_h2_primitives::BlsPublicKey;
use serde_json::Value;
use std::collections::HashMap;

const V1: &str = include_str!("../testdata/profile1/header_profile_v1.json");
const GENESIS: &str = include_str!("../testdata/profile1/genesis_8s.json");

fn v1() -> Value {
    serde_json::from_str(V1).expect("V1 parses")
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("hex")
}

fn b256(value: &Value) -> B256 {
    value.as_str().expect("hash").parse().expect("hash")
}

fn decode(rlp: &[u8]) -> Result<N42Header, String> {
    let mut cursor = rlp;
    let header = N42Header::decode(&mut cursor).map_err(|err| err.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing bytes".into());
    }
    Ok(header)
}

fn validators(v1: &Value) -> Vec<ValidatorInfo> {
    v1["validators"]
        .as_array()
        .expect("validators")
        .iter()
        .map(|validator| {
            let key: [u8; 48] = bytes(&validator["blsPublicKey"]).try_into().expect("48 bytes");
            ValidatorInfo {
                address: validator["address"].as_str().unwrap().parse().unwrap(),
                bls_public_key: BlsPublicKey::from_bytes(&key).expect("key"),
                p2p_peer_id: None,
            }
        })
        .collect()
}

/// The rules `genesis_8s.json` declares, mapped by hand the way
/// `n42_qmdb_reth::Profile1Config::header_rules` maps them, plus the chain
/// identity.
fn rules(v1: &Value) -> HeaderRules {
    let genesis: Value = serde_json::from_str(GENESIS).expect("genesis parses");
    let hotstuff = &genesis["config"]["hotstuff"];
    let mut rules = HeaderRules::profile1(
        hotstuff["gasLimit"].as_u64().unwrap(),
        hotstuff["maxBlockBytes"].as_u64().unwrap(),
        Some(ProposerSchedule {
            validators: validators(v1),
            leader_tenure: hotstuff["leaderTenure"].as_u64().unwrap(),
        }),
    );
    rules.chain = Some(n42_h2_primitives::consensus::H2V4ChainIdentity {
        chain_id: v1["chainId"].as_u64().unwrap(),
        genesis_hash: b256(&v1["genesisHash"]),
    });
    rules
}

/// Import-time verdict of a header on top of `parent`, as a node with the
/// chain `known` (hash -> number, parent) would give it.
fn import_verdict(
    rules: &HeaderRules,
    header: &N42Header,
    parent: &N42Header,
    known: &HashMap<B256, (u64, B256)>,
) -> Result<(), Profile1Error> {
    rules.check_header(header)?;
    rules.check_against_parent(header, parent, parent.hash_slow())?;
    rules.check_qc_ancestry(header, |hash| known.get(hash).copied())
}

#[test]
fn v1_headers_reproduce_byte_for_byte() {
    let v1 = v1();
    let genesis = decode(&bytes(&v1["genesis"]["rlp"])).expect("genesis decodes");
    assert_eq!(alloy_rlp::encode(&genesis), bytes(&v1["genesis"]["rlp"]), "genesis RLP");
    assert_eq!(genesis.hash_slow(), b256(&v1["genesisHash"]), "genesis hash");
    assert_eq!(genesis.hash_slow(), b256(&v1["genesis"]["hash"]), "genesis hash field");
    validate_profile1_genesis_header(&genesis, &rules(&v1)).expect("gov5's genesis is a profile-1 genesis");

    let keys = validators(&v1);
    for block in v1["headers"].as_array().unwrap() {
        let name = block["name"].as_str().unwrap();
        let rlp = bytes(&block["rlp"]);
        let header = decode(&rlp).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(alloy_rlp::encode(&header), rlp, "{name}: RLP");
        assert_eq!(header.hash_slow(), b256(&block["hash"]), "{name}: hash");
        assert_eq!(seal_hash(&header), b256(&block["sealHash"]), "{name}: sealHash");
        let seal = bytes(&block["seal"]);
        assert_eq!(&header.extra_data[header.extra_data.len() - 96..], &seal[..], "{name}: seal bytes");
        let signer = &keys[block["signerIndex"].as_u64().unwrap() as usize];
        crate::verify_seal(&header, &signer.bls_public_key).unwrap_or_else(|err| panic!("{name}: seal: {err}"));
        assert_eq!(header.beneficiary, signer.address, "{name}: coinbase is the signer");
        if let Some(qc) = block.get("qc") {
            let extra = HeaderExtra::decode(&header.extra_data).unwrap();
            assert_eq!(extra.qc, bytes(&qc["ssz"]), "{name}: embedded QC bytes");
        }
    }
}

#[test]
fn v1_valid_headers_pass_and_every_refusal_is_refused_for_its_rule() {
    let v1 = v1();
    let rules = rules(&v1);
    let genesis = decode(&bytes(&v1["genesis"]["rlp"])).unwrap();
    let blocks: Vec<N42Header> =
        v1["headers"].as_array().unwrap().iter().map(|b| decode(&bytes(&b["rlp"])).unwrap()).collect();
    let (block1, block2) = (&blocks[0], &blocks[1]);
    let mut known: HashMap<B256, (u64, B256)> = HashMap::new();
    known.insert(genesis.hash_slow(), (0, B256::ZERO));
    known.insert(block1.hash_slow(), (1, genesis.hash_slow()));

    import_verdict(&rules, block1, &genesis, &known).expect("block 1");
    import_verdict(&rules, block2, block1, &known).expect("block 2");
    check_profile1_vote_time(block2.timestamp, block2.timestamp).expect("block 2 at vote time");

    let mut mismatches = Vec::new();
    for refusal in v1["refusals"].as_array().unwrap() {
        let name = refusal["name"].as_str().unwrap();
        let rule = refusal["rule"].as_str().unwrap();
        let check = refusal["check"].as_str().unwrap();
        let header = match decode(&bytes(&refusal["rlp"])) {
            Ok(header) => header,
            Err(err) => {
                // A header the decoder cannot read is refused, but not for
                // a named rule.
                mismatches.push(format!("{name} ({rule}): refused by the RLP decoder, not a rule: {err}"));
                continue;
            }
        };
        if header.hash_slow() != b256(&refusal["hash"]) {
            mismatches.push(format!("{name}: our hash {} is not gov5's", header.hash_slow()));
        }
        // "A stored sibling": the QC's block is known here, off the chain.
        let mut known = known.clone();
        if name == "QC names a non-ancestor" {
            let extra = HeaderExtra::decode(&header.extra_data).unwrap();
            let qc = n42_h2_wire::h2_wire::decode_h2_qc(&extra.qc).unwrap();
            known.insert(qc.block_hash, (1, genesis.hash_slow()));
        }
        let verdict = match check {
            "import" => import_verdict(&rules, &header, block1, &known).map_err(|err| err.to_string()),
            "vote" => match import_verdict(&rules, &header, block1, &known) {
                Err(err) => {
                    mismatches.push(format!("{name}: gov5 accepts it on import, we refuse: {err}"));
                    continue;
                }
                Ok(()) => check_profile1_vote_time(header.timestamp, refusal["nowUnix"].as_u64().unwrap_or(header.timestamp - 3))
                    .map_err(|err| err.to_string()),
            },
            "execution" => {
                // The header is valid; the body's rewards (the faucet only)
                // do not commit to its withdrawals root, while the order
                // n42-rs pays them in (coinbase, then faucet) does.
                if let Err(err) = import_verdict(&rules, &header, block1, &known) {
                    mismatches.push(format!("{name}: gov5 accepts the header, we refuse: {err}"));
                    continue;
                }
                let genesis_file: Value = serde_json::from_str(GENESIS).unwrap();
                let hotstuff = &genesis_file["config"]["hotstuff"];
                let reward: U256 = hotstuff["devBlockReward"].as_str().unwrap().parse().unwrap();
                let faucet: Address = hotstuff["devFaucetAddress"].as_str().unwrap().parse().unwrap();
                let ours = gov5_rewards_root([(header.beneficiary, reward), (faucet, reward)]);
                if Some(ours) != header.withdrawals_root {
                    mismatches.push(format!("{name}: our reward order (coinbase, faucet) gives {ours}, not the header's root"));
                }
                if gov5_rewards_root([(faucet, reward)]) == header.withdrawals_root.unwrap_or_default() {
                    Ok(())
                } else {
                    Err("B6: the body's rewards do not commit to withdrawalsRoot".to_owned())
                }
            }
            other => panic!("{name}: unknown check {other}"),
        };
        match verdict {
            Ok(()) => mismatches.push(format!("{name} ({rule}): gov5 refuses ({}), we accept", refusal["expectedError"])),
            Err(message) => {
                // gov5's E13 and B1/E13 refusals are ours under B1 (the QC
                // item of the header).
                let wanted: Vec<&str> = rule.split('/').map(|item| if item == "E13" { "B1" } else { item }).collect();
                if !wanted.iter().any(|item| message.starts_with(item)) {
                    mismatches.push(format!("{name}: gov5 refuses for {rule}, we for: {message}"));
                }
            }
        }
    }
    assert!(mismatches.is_empty(), "V1 mismatches:\n{}", mismatches.join("\n"));
}

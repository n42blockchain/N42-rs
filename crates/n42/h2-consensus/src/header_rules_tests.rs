// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Accept and reject cases for every profile-1 header rule, and the
//! self-check vector file `testdata/profile1_header_vectors.json`.

use super::*;
use crate::header_profile::{seal_header, HeaderExtra};
use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
use alloy_primitives::{b256, hex, Bytes};
use n42_h2_primitives::bls::BlsSecretKey;

const GAS_LIMIT: u64 = 480_000_000;
const PARENT_TIME: u64 = 1_800_000_000;

fn keys() -> Vec<BlsSecretKey> {
    (1u8..=4).map(|i| BlsSecretKey::key_gen(&[i; 32]).expect("key")).collect()
}

fn schedule() -> ProposerSchedule {
    ProposerSchedule {
        validators: keys()
            .iter()
            .enumerate()
            .map(|(i, key)| ValidatorInfo {
                address: Address::with_last_byte(0x10 + i as u8),
                bls_public_key: key.public_key(),
                p2p_peer_id: None,
            })
            .collect(),
        leader_tenure: 1,
    }
}

fn rules() -> HeaderRules {
    HeaderRules::profile1(GAS_LIMIT, PROFILE1_MAX_BLOCK_BYTES, Some(schedule()))
}

fn parent() -> N42Header {
    let mut header = N42Header::from(Header {
        number: 4,
        gas_limit: GAS_LIMIT,
        gas_used: 21_000,
        timestamp: PARENT_TIME,
        base_fee_per_gas: Some(1_000_000_000),
        ommers_hash: B256::ZERO,
        withdrawals_root: Some(crate::GOV5_NIL_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::repeat_byte(0x0b)),
        requests_hash: Some(PROFILE1_REQUESTS_HASH),
        extra_data: HeaderExtra::for_view(4).encode(),
        ..Default::default()
    });
    header.slot_number = Some(4);
    header.mobile_registry_root = Some(B256::ZERO);
    header
}

/// A conformant header at view 5 on `parent()`, unsealed.
fn unsealed(view: u64) -> N42Header {
    let parent = parent();
    let proposer = schedule().proposer(view).cloned().expect("proposer");
    let mut header = N42Header::from(Header {
        parent_hash: parent.hash_slow(),
        number: 5,
        beneficiary: proposer.address,
        gas_limit: GAS_LIMIT,
        gas_used: 21_000,
        timestamp: PARENT_TIME,
        base_fee_per_gas: Some(profile1_base_fee(&parent)),
        ommers_hash: B256::ZERO,
        withdrawals_root: Some(crate::GOV5_NIL_HASH),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::repeat_byte(0x0c)),
        requests_hash: Some(PROFILE1_REQUESTS_HASH),
        extra_data: HeaderExtra::for_view(view).encode(),
        ..Default::default()
    });
    header.slot_number = Some(5);
    header.mobile_registry_root = Some(B256::repeat_byte(0x24));
    header
}

fn seal(mut header: N42Header) -> N42Header {
    let view = HeaderExtra::decode(&header.extra_data).expect("extra").view;
    let index = (view % 4) as usize;
    seal_header(&mut header, &keys()[index]).expect("seal");
    header
}

fn valid() -> N42Header {
    seal(unsealed(5))
}

/// Applies `edit` to a valid unsealed header and seals it again, so the
/// failure is the edited field's and not the seal's.
fn edited(edit: impl FnOnce(&mut N42Header)) -> N42Header {
    let mut header = unsealed(5);
    edit(&mut header);
    seal(header)
}

fn check(header: &N42Header) -> Result<(), Profile1Error> {
    let rules = rules();
    rules.check_header(header)?;
    let parent = parent();
    rules.check_against_parent(header, &parent, parent.hash_slow())
}

#[test]
fn a_conformant_header_passes_every_rule() {
    check(&valid()).expect("valid");
}

#[test]
fn without_profile1_nothing_is_checked() {
    let off = HeaderRules::default();
    assert!(!off.is_profile1());
    let junk = N42Header::from(Header { number: 9, difficulty: U256::from(5), ..Default::default() });
    off.check_header(&junk).unwrap();
    off.check_against_parent(&junk, &parent(), B256::ZERO).unwrap();
    off.check_block_bytes(usize::MAX).unwrap();
    assert_eq!(off.max_block_bytes_or(7), 7);
    assert_eq!(rules().max_block_bytes_or(7), PROFILE1_MAX_BLOCK_BYTES);
}

#[test]
fn b1_extra_layout() {
    // Accept: a committed QC between view and seal.
    let qc = n42_h2_wire::h2_wire::encode_h2_qc(&n42_h2_wire::h2_wire::H2QuorumCertificate {
        view: 4,
        block_hash: B256::repeat_byte(1),
        aggregate_signature: vec![0x5a; 96],
        signers_bitmap: vec![4, 0, 0b0000_0111],
    })
    .unwrap();
    let with_qc = edited(|h| h.extra_data = HeaderExtra::with_committed_qc(5, qc.clone()).encode());
    check(&with_qc).expect("QC then seal");
    // Reject: the legacy layouts, no seal reserved.
    let mut bare = valid();
    bare.extra_data = Bytes::from([&crate::GOV5_HEADER_EXTRA_MAGIC[..], &5u64.to_le_bytes()[..]].concat());
    assert!(matches!(check(&bare), Err(Profile1Error::LegacyExtra(12))));
    let mut qc_alone = valid();
    qc_alone.extra_data = Bytes::from([&crate::GOV5_HEADER_EXTRA_MAGIC[..], &5u64.to_le_bytes()[..], &qc[..40]].concat());
    assert!(matches!(check(&qc_alone), Err(Profile1Error::LegacyExtra(_))));
    // Reject: past 4096 bytes, no magic, a QC that does not decode, a QC
    // past the header's view.
    let mut long = valid();
    long.extra_data = HeaderExtra::with_committed_qc(5, vec![0; 4096]).encode();
    assert!(matches!(check(&long), Err(Profile1Error::Extra(_))));
    let mut magicless = valid();
    let mut bytes = magicless.extra_data.to_vec();
    bytes[0] = b'X';
    magicless.extra_data = bytes.into();
    assert!(matches!(check(&magicless), Err(Profile1Error::Extra(_))));
    let garbage = edited(|h| h.extra_data = HeaderExtra::with_committed_qc(5, vec![1, 2, 3]).encode());
    assert!(matches!(check(&garbage), Err(Profile1Error::Qc(_))));
    let ahead_qc = n42_h2_wire::h2_wire::encode_h2_qc(&n42_h2_wire::h2_wire::H2QuorumCertificate {
        view: 6,
        block_hash: B256::repeat_byte(1),
        aggregate_signature: vec![0x5a; 96],
        signers_bitmap: vec![4, 0, 0b0000_0111],
    })
    .unwrap();
    let ahead = edited(|h| h.extra_data = HeaderExtra::with_committed_qc(5, ahead_qc).encode());
    assert!(matches!(check(&ahead), Err(Profile1Error::Qc(_))));
}

#[test]
fn b2_seal_by_the_proposer_of_the_view() {
    // Reject: unsealed (zero seal), sealed by another validator, and a field
    // changed after the seal.
    assert!(matches!(check(&unsealed(5)), Err(Profile1Error::Seal(_))));
    let mut wrong_key = unsealed(5);
    seal_header(&mut wrong_key, &keys()[0]).unwrap();
    assert!(matches!(check(&wrong_key), Err(Profile1Error::Seal(_))));
    let mut tampered = valid();
    tampered.gas_used += 1;
    assert!(matches!(check(&tampered), Err(Profile1Error::Seal(_))));
    // Accept: tenure 2 moves view 5 to validator 2.
    let mut tenure2 = rules();
    tenure2.proposers.as_mut().unwrap().leader_tenure = 2;
    let proposer = tenure2.proposers.as_ref().unwrap().proposer(5).cloned().unwrap();
    assert_eq!(proposer.address, Address::with_last_byte(0x12));
    let mut header = unsealed(5);
    header.beneficiary = proposer.address;
    seal_header(&mut header, &keys()[2]).unwrap();
    tenure2.check_header(&header).expect("tenure-2 proposer");
    assert!(matches!(tenure2.check_header(&valid()), Err(Profile1Error::Coinbase { .. })));
}

#[test]
fn b3_constant_fields_and_coinbase() {
    let cases: [(&str, fn(&mut N42Header)); 6] = [
        ("difficulty", |h| h.difficulty = U256::from(1)),
        ("nonce", |h| h.nonce = 1u64.into()),
        ("mix hash", |h| h.mix_hash = B256::repeat_byte(1)),
        ("empty-list ommers hash", |h| h.ommers_hash = EMPTY_OMMER_ROOT_HASH),
        ("other ommers hash", |h| h.ommers_hash = B256::repeat_byte(2)),
        ("coinbase", |h| h.beneficiary = Address::repeat_byte(0x77)),
    ];
    for (name, edit) in cases {
        let header = edited(edit);
        let err = check(&header).expect_err(name);
        assert!(err.to_string().starts_with("B3"), "{name}: {err}");
    }
}

#[test]
fn b4_timestamps_equal_allowed_before_parent_refused_future_only_at_vote() {
    // Accept: equal to the parent's (the fixture), and later.
    check(&valid()).expect("equal timestamps");
    check(&edited(|h| h.timestamp = PARENT_TIME + 1)).expect("later");
    // Reject: before the parent's.
    let early = edited(|h| h.timestamp = PARENT_TIME - 1);
    assert!(matches!(check(&early), Err(Profile1Error::TimestampBeforeParent { .. })));
    // The clock bound is the vote's: `now + 2` passes, `now + 3` does not;
    // import (`check`) never looks at a clock.
    check_profile1_vote_time(PARENT_TIME + 2, PARENT_TIME).expect("now + 2");
    assert!(matches!(
        check_profile1_vote_time(PARENT_TIME + 3, PARENT_TIME),
        Err(Profile1Error::TimestampInFuture { .. })
    ));
    check(&edited(|h| h.timestamp = PARENT_TIME + 1_000)).expect("import ignores the clock");
    // The producer stamps max(parent, now).
    assert_eq!(profile1_timestamp(PARENT_TIME, PARENT_TIME - 5), PARENT_TIME);
    assert_eq!(profile1_timestamp(PARENT_TIME, PARENT_TIME + 5), PARENT_TIME + 5);
}

#[test]
fn b5_b6_roots_present() {
    assert!(matches!(
        check(&edited(|h| h.parent_beacon_block_root = None)),
        Err(Profile1Error::Missing { item: "B5", .. })
    ));
    assert!(matches!(
        check(&edited(|h| h.withdrawals_root = None)),
        Err(Profile1Error::Missing { item: "B6", .. })
    ));
}

#[test]
fn a23_gas_limit_is_the_constant() {
    assert!(matches!(
        check(&edited(|h| h.gas_limit = GAS_LIMIT - 1)),
        Err(Profile1Error::GasLimit { .. })
    ));
    assert!(matches!(
        check(&edited(|h| h.gas_limit = GAS_LIMIT + 1)),
        Err(Profile1Error::GasLimit { .. })
    ));
}

#[test]
fn b8_requests_hash_has_one_spelling() {
    // Accept: the empty trie root (the fixture); AM3's constant.
    assert_eq!(
        PROFILE1_REQUESTS_HASH,
        b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
    );
    // Reject: EIP-7685's sha256(""), the empty-ommers hash, absent.
    assert!(matches!(
        check(&edited(|h| h.requests_hash = Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH))),
        Err(Profile1Error::RequestsHash(_))
    ));
    assert!(matches!(
        check(&edited(|h| h.requests_hash = Some(EMPTY_OMMER_ROOT_HASH))),
        Err(Profile1Error::RequestsHash(_))
    ));
    assert!(matches!(
        check(&edited(|h| h.requests_hash = None)),
        Err(Profile1Error::Missing { item: "B8", .. })
    ));
}

#[test]
fn b9_blob_gas_zero_and_present() {
    for (used, excess) in [(Some(1), Some(0)), (Some(0), Some(1)), (None, Some(0)), (Some(0), None)] {
        let header = edited(|h| {
            h.blob_gas_used = used;
            h.excess_blob_gas = excess;
        });
        assert!(check(&header).unwrap_err().to_string().starts_with("B9"), "{used:?} {excess:?}");
    }
}

#[test]
fn b10_b11_b12_header_tail() {
    assert!(matches!(check(&edited(|h| h.slot_number = None)), Err(Profile1Error::Missing { item: "B10", .. })));
    assert!(matches!(check(&edited(|h| h.slot_number = Some(4))), Err(Profile1Error::SlotNumber { .. })));
    assert!(matches!(
        check(&edited(|h| h.mobile_registry_root = None)),
        Err(Profile1Error::Missing { item: "B11", .. })
    ));
    assert!(matches!(
        check(&edited(|h| h.block_access_list_hash = Some(B256::repeat_byte(3)))),
        Err(Profile1Error::AccessListHash(_))
    ));
    // Accept: and element 22 is written as gov5's 0x80 gap.
    let encoded = alloy_rlp::encode(&valid());
    let tail = &encoded[encoded.len() - (1 + 1 + 1 + 32)..];
    assert_eq!(tail[0], 0x80, "element 22 is the empty string");
    assert_eq!(tail[1], 5, "element 23 is the slot number");
}

#[test]
fn b13_gas_used_bounded_by_the_parent_limit() {
    check(&edited(|h| h.gas_used = GAS_LIMIT)).expect("at the limit");
    assert!(matches!(check(&edited(|h| h.gas_used = GAS_LIMIT + 1)), Err(Profile1Error::GasUsed { .. })));
}

#[test]
fn b14_base_fee_from_the_parent() {
    let parent = parent();
    // Half-target usage moves the fee down by EIP-1559's rule.
    assert!(profile1_base_fee(&parent) < parent.base_fee_per_gas.unwrap());
    assert!(matches!(
        check(&edited(|h| h.base_fee_per_gas = Some(1_000_000_000))),
        Err(Profile1Error::BaseFee { .. })
    ));
    assert!(matches!(check(&edited(|h| h.base_fee_per_gas = None)), Err(Profile1Error::BaseFee { .. })));
}

#[test]
fn b15_block_bytes() {
    let rules = rules();
    rules.check_block_bytes(PROFILE1_MAX_BLOCK_BYTES as usize).expect("at the bound");
    assert!(matches!(
        rules.check_block_bytes(PROFILE1_MAX_BLOCK_BYTES as usize + 1),
        Err(Profile1Error::BlockTooLarge { .. })
    ));
}

#[test]
fn parent_link_is_checked() {
    let parent = parent();
    let header = valid();
    assert!(matches!(
        rules().check_against_parent(&header, &parent, B256::repeat_byte(9)),
        Err(Profile1Error::ParentLink { .. })
    ));
}

#[test]
fn a6_genesis_header() {
    let rules = rules();
    let mut genesis = N42Header::from(Header {
        gas_limit: GAS_LIMIT,
        ommers_hash: B256::ZERO,
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::ZERO),
        requests_hash: Some(PROFILE1_REQUESTS_HASH),
        ..Default::default()
    });
    validate_profile1_genesis_header(&genesis, &rules).expect("profile-1 genesis");
    // What reth's genesis builder stamps today: the empty-list ommers hash and
    // EIP-7685's requests hash. Both are refused.
    genesis.ommers_hash = EMPTY_OMMER_ROOT_HASH;
    assert!(validate_profile1_genesis_header(&genesis, &rules).is_err());
    genesis.ommers_hash = B256::ZERO;
    genesis.requests_hash = Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH);
    assert!(validate_profile1_genesis_header(&genesis, &rules).is_err());
}

// --- vectors -------------------------------------------------------------

/// One case of the self-check vector file.
fn vector_cases() -> Vec<(&'static str, &'static str, N42Header, Option<&'static str>)> {
    let qc = n42_h2_wire::h2_wire::encode_h2_qc(&n42_h2_wire::h2_wire::H2QuorumCertificate {
        view: 4,
        block_hash: B256::repeat_byte(1),
        aggregate_signature: vec![0x5a; 96],
        signers_bitmap: vec![4, 0, 0b0000_0111],
    })
    .unwrap();
    let mut legacy = valid();
    legacy.extra_data = Bytes::from([&crate::GOV5_HEADER_EXTRA_MAGIC[..], &5u64.to_le_bytes()[..]].concat());
    let mut wrong_seal = unsealed(5);
    seal_header(&mut wrong_seal, &keys()[0]).unwrap();
    vec![
        ("valid", "-", valid(), None),
        ("valid_with_qc", "B1", edited(|h| h.extra_data = HeaderExtra::with_committed_qc(5, qc.clone()).encode()), None),
        ("valid_equal_timestamp", "B4", valid(), None),
        ("legacy_extra_no_seal", "B1", legacy, Some("B1")),
        ("wrong_seal", "B2", wrong_seal, Some("B2")),
        ("difficulty_one", "B3", edited(|h| h.difficulty = U256::from(1)), Some("B3")),
        ("ommers_empty_list_hash", "B3", edited(|h| h.ommers_hash = EMPTY_OMMER_ROOT_HASH), Some("B3")),
        ("coinbase_not_proposer", "B3", edited(|h| h.beneficiary = Address::repeat_byte(0x77)), Some("B3")),
        ("timestamp_before_parent", "B4", edited(|h| h.timestamp = PARENT_TIME - 1), Some("B4")),
        ("gas_limit_not_constant", "A23", edited(|h| h.gas_limit = GAS_LIMIT - 1), Some("A23")),
        (
            "requests_hash_eip7685",
            "B8",
            edited(|h| h.requests_hash = Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH)),
            Some("B8"),
        ),
        ("blob_gas_used_nonzero", "B9", edited(|h| h.blob_gas_used = Some(131_072)), Some("B9")),
        ("slot_number_wrong", "B10", edited(|h| h.slot_number = Some(4)), Some("B10")),
        ("registry_root_missing", "B11", edited(|h| h.mobile_registry_root = None), Some("B11")),
        ("access_list_hash_present", "B12", edited(|h| h.block_access_list_hash = Some(B256::repeat_byte(3))), Some("B12")),
        ("gas_used_over_parent_limit", "B13", edited(|h| h.gas_used = GAS_LIMIT + 1), Some("B13")),
        ("base_fee_not_eip1559", "B14", edited(|h| h.base_fee_per_gas = Some(1_000_000_000)), Some("B14")),
    ]
}

fn render_vectors() -> String {
    let schedule = schedule();
    let parent = parent();
    let cases: Vec<serde_json::Value> = vector_cases()
        .into_iter()
        .map(|(name, item, header, expect)| {
            let verdict = check(&header);
            let got = verdict.as_ref().err().map(|err| err.to_string());
            match (expect, &got) {
                (None, None) => {}
                (Some(item), Some(message)) => {
                    assert!(message.starts_with(item), "{name}: expected {item}, got {message}")
                }
                _ => panic!("{name}: expected {expect:?}, got {got:?}"),
            }
            serde_json::json!({
                "name": name,
                "item": item,
                "header_rlp": format!("0x{}", hex::encode(alloy_rlp::encode(&header))),
                "header_hash": format!("{:?}", header.hash_slow()),
                "seal_hash": format!("{:?}", seal_hash(&header)),
                "valid": got.is_none(),
                "refused_by": expect,
            })
        })
        .collect();
    let document = serde_json::json!({
        "_comment": "SELF-CHECK placeholder generated by n42-rs (h2-consensus header_rules_tests); not gov5's authoritative V1. Regenerate with N42_WRITE_PROFILE1_VECTORS=1.",
        "standard": "docs/MIXED_PRODUCTION_STANDARD.md section 2 B1-B15, AM3, AM4, AM12, AM22",
        "rules": {
            "gasLimit": GAS_LIMIT,
            "maxBlockBytes": PROFILE1_MAX_BLOCK_BYTES,
            "leaderTenure": schedule.leader_tenure,
            "validators": schedule.validators.iter().map(|v| serde_json::json!({
                "address": format!("{:?}", v.address),
                "blsKey": format!("0x{}", hex::encode(v.bls_public_key.to_bytes())),
            })).collect::<Vec<_>>(),
            "blsSecretKeyIkm": "key_gen([i; 32]) for i in 1..=4",
        },
        "parent": {
            "header_rlp": format!("0x{}", hex::encode(alloy_rlp::encode(&parent))),
            "header_hash": format!("{:?}", parent.hash_slow()),
        },
        "cases": cases,
    });
    serde_json::to_string_pretty(&document).expect("json") + "\n"
}

/// The self-check vectors are what this code produces and decides. Written
/// with `N42_WRITE_PROFILE1_VECTORS=1`; otherwise the file must match.
#[test]
fn profile1_header_vectors_self_check() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/profile1_header_vectors.json");
    let rendered = render_vectors();
    if std::env::var_os("N42_WRITE_PROFILE1_VECTORS").is_some() {
        std::fs::write(&path, &rendered).expect("write vectors");
        return;
    }
    let on_disk = std::fs::read_to_string(&path).expect("vectors file; regenerate with N42_WRITE_PROFILE1_VECTORS=1");
    assert_eq!(on_disk, rendered, "profile-1 vectors changed; regenerate deliberately");
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Accept and reject cases for every profile-1 header rule, and the
//! self-check vector file `testdata/profile1_header_vectors.json`.

use super::*;
use crate::header_profile::{seal_header, HeaderExtra};
use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
use alloy_primitives::{b256, Bytes};
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

/// A grid whose genesis is 10 slots of 8 s before `PARENT_TIME`, so the
/// fixture's parent sits on slot 10.
const GRID: SlotGrid = SlotGrid { genesis_time: PARENT_TIME - 80, interval_ms: 8_000 };

fn check_on_grid(header: &N42Header) -> Result<(), Profile1Error> {
    check_on(GRID, header)
}

fn check_on(grid: SlotGrid, header: &N42Header) -> Result<(), Profile1Error> {
    let rules = rules().with_slot_grid(Some(grid));
    rules.check_header(header)?;
    let parent = parent();
    rules.check_against_parent(header, &parent, parent.hash_slow())
}

#[test]
fn am27_grid_from_interval_ms() {
    assert_eq!(SlotGrid::from_interval_ms(100, 8_000), Some(SlotGrid { genesis_time: 100, interval_ms: 8_000 }));
    assert_eq!(SlotGrid::from_interval_ms(100, 0), None);
    // AM27a: any positive interval has a grid.
    assert_eq!(SlotGrid::from_interval_ms(100, 500), Some(SlotGrid { genesis_time: 100, interval_ms: 500 }));
    assert_eq!(GRID.interval_secs(), Some(8));
    assert_eq!(SlotGrid::from_interval_ms(100, 1_500).and_then(|g| g.interval_secs()), None);
    assert_eq!(GRID.slot_of(PARENT_TIME), Some(10));
    assert_eq!(GRID.slot_of(PARENT_TIME + 3), None);
    assert_eq!(GRID.slot_of(GRID.genesis_time - 8), None);
    assert_eq!(GRID.slot_start(11), PARENT_TIME + 8);
}

#[test]
fn am27_slot_selection_normal_cadence() {
    let ms = |secs: u64| secs * 1000;
    // The parent of slot 10 arrives 300 ms into its slot: the next slot.
    assert_eq!(GRID.proposal_slot(PARENT_TIME, ms(PARENT_TIME) + 300), 11);
    assert_eq!(GRID.proposal_time(PARENT_TIME, ms(PARENT_TIME) + 300), PARENT_TIME + 8);
    // Asked before the parent's own slot started (a chained build sealed
    // ahead of its boundary): still the slot after the parent's.
    assert_eq!(GRID.proposal_time(PARENT_TIME, ms(PARENT_TIME) - 2_000), PARENT_TIME + 8);
    // Exactly on the next boundary: that boundary, not the one after.
    assert_eq!(GRID.proposal_time(PARENT_TIME, ms(PARENT_TIME + 8)), PARENT_TIME + 8);
    // A steady chain: each block's stamp is the next boundary, deltas of 8.
    let mut parent_time = PARENT_TIME;
    for _ in 0..5 {
        let next = GRID.proposal_time(parent_time, ms(parent_time) + 450);
        assert_eq!(next - parent_time, 8);
        parent_time = next;
    }
}

#[test]
fn am27_leader_entering_mid_slot_waits_for_the_next_boundary() {
    // A TC after a 24 s timeout: the new leader holds the slot-10 parent at
    // slot 13 + 5 s; slots 11-13 are past, so it proposes in slot 14.
    let now_ms = (PARENT_TIME + 3 * 8 + 5) * 1000 + 1;
    assert_eq!(GRID.proposal_slot(PARENT_TIME, now_ms), 14);
    assert_eq!(GRID.proposal_time(PARENT_TIME, now_ms), PARENT_TIME + 32);
    // One millisecond past a boundary is mid-slot: the next one.
    assert_eq!(GRID.proposal_time(PARENT_TIME, (PARENT_TIME + 8) * 1000 + 1), PARENT_TIME + 16);
}

#[test]
fn am27_parent_arriving_late() {
    // The slot-10 parent reached this leader 9.5 s after its slot began
    // (after slot 11 started): slot 12, the boundary still ahead.
    let now_ms = PARENT_TIME * 1000 + 9_500;
    assert_eq!(GRID.proposal_time(PARENT_TIME, now_ms), PARENT_TIME + 16);
    // The stamp passes B4 against the parent, with a delta of two slots.
    check_profile1_slot(&GRID, PARENT_TIME + 16, PARENT_TIME).expect("two slots later");
}

#[test]
fn am27_b4_on_the_grid() {
    // Accept: the next slot, and a later one (a timeout in between).
    check_on_grid(&edited(|h| h.timestamp = PARENT_TIME + 8)).expect("next slot");
    check_on_grid(&edited(|h| h.timestamp = PARENT_TIME + 24)).expect("three slots later");
    // Off the grid.
    for time in [PARENT_TIME + 9, PARENT_TIME + 1, PARENT_TIME + 15] {
        assert!(
            matches!(check_on_grid(&edited(|h| h.timestamp = time)), Err(Profile1Error::TimestampOffGrid { .. })),
            "{time}"
        );
    }
    // The parent's own slot (equal timestamps are no longer valid).
    assert!(matches!(check_on_grid(&valid()), Err(Profile1Error::TimestampSameSlot { .. })));
    // Before the parent.
    assert!(matches!(
        check_on_grid(&edited(|h| h.timestamp = PARENT_TIME - 8)),
        Err(Profile1Error::TimestampSameSlot { .. }) | Err(Profile1Error::TimestampBeforeParent { .. })
    ));
    // Future: import never reads a clock; only the vote does.
    let future = edited(|h| h.timestamp = PARENT_TIME + 8 * 100);
    check_on_grid(&future).expect("import ignores the clock");
    let now = PARENT_TIME + 8;
    check_profile1_vote_time(PARENT_TIME + 8, now).expect("in its slot");
    assert!(matches!(
        check_profile1_vote_time(future.timestamp, now),
        Err(Profile1Error::TimestampInFuture { .. })
    ));
    // The error names B4.
    let err = check_on_grid(&edited(|h| h.timestamp = PARENT_TIME + 9)).unwrap_err();
    assert!(err.to_string().starts_with("B4"), "{err}");
}

/// AM27a grids: 30 ms (the performance line), 1500 ms, and profile 1's
/// 8000 ms, each with the fixture's parent at the start of a slot.
const GRID_30: SlotGrid = SlotGrid { genesis_time: PARENT_TIME - 3, interval_ms: 30 };
const GRID_1500: SlotGrid = SlotGrid { genesis_time: PARENT_TIME - 3, interval_ms: 1_500 };

#[test]
fn am27a_8000_ms_is_am27() {
    // The whole-second path is AM27's arithmetic, value for value.
    assert_eq!(SlotGrid::from_interval_ms(PARENT_TIME - 80, 8_000), Some(GRID));
    for now_ms in [PARENT_TIME * 1000 - 2_000, PARENT_TIME * 1000 + 300, (PARENT_TIME + 8) * 1000, (PARENT_TIME + 8) * 1000 + 1]
    {
        let slot = GRID.proposal_slot(PARENT_TIME, now_ms);
        let am27 = core::cmp::max(10 + 1, (now_ms - GRID.genesis_time * 1000).div_ceil(8_000));
        assert_eq!(slot, am27, "{now_ms}");
        assert_eq!(GRID.proposal_time(PARENT_TIME, now_ms), GRID.genesis_time + 8 * am27);
        assert_eq!(GRID.slot_start_ms(slot), GRID.proposal_time(PARENT_TIME, now_ms) * 1000);
    }
    // An off-grid parent counts as the slot it falls in (floor), as in AM27.
    assert_eq!(GRID.parent_slot(PARENT_TIME + 7), 10);
    assert_eq!(GRID.parent_slot(GRID.genesis_time), 0);
}

#[test]
fn am27a_30_ms_proposal_selection() {
    let g = GRID_30;
    let parent_ms = PARENT_TIME * 1000; // slot 100 starts exactly here
    assert_eq!(g.slot_of(PARENT_TIME), Some(100));
    assert_eq!(g.parent_slot(PARENT_TIME), 100);
    // The parent of slot 100, known locally, arrives 10 ms into its slot:
    // the next slot, 30 ms on; the stamp stays in the same second.
    assert_eq!(g.proposal_slot_after(100, parent_ms + 10), 101);
    assert_eq!(g.slot_start_ms(101), parent_ms + 30);
    assert_eq!(g.slot_start(101), PARENT_TIME);
    // A chained build sealed before its parent's slot began still takes the
    // slot after the parent's (the local slot, not the timestamp's bound).
    assert_eq!(g.proposal_slot_after(120, parent_ms + 100), 121);
    // A late leader takes the first slot not in the past.
    assert_eq!(g.proposal_slot_after(100, parent_ms + 1_000), 134);
    assert_eq!(g.proposal_slot_after(100, parent_ms + 1_001), 134);
    assert_eq!(g.slot_start(134), PARENT_TIME + 1);
    // From the timestamp alone the parent's slot is a lower bound: the first
    // slot starting in its second.
    assert_eq!(g.parent_slot(PARENT_TIME + 1), 134);
    assert_eq!(g.proposal_slot(PARENT_TIME + 1, parent_ms + 500), 135);
    // A steady chain at 30 ms: 34 or 33 slots a second, stamps never fall.
    let (mut slot, mut stamp) = (100, PARENT_TIME);
    for step in 0..200u64 {
        let next = g.proposal_slot_after(slot, g.slot_start_ms(slot) + 7);
        assert_eq!(next, slot + 1, "{step}");
        assert!(g.slot_start(next) >= stamp);
        check_profile1_slot(&g, g.slot_start(next), stamp).expect("non-decreasing");
        (slot, stamp) = (next, g.slot_start(next));
    }
    assert_eq!(stamp, PARENT_TIME + 6);
}

#[test]
fn am27a_1500_ms_proposal_selection() {
    let g = GRID_1500;
    // G = PARENT_TIME - 3: slot 2 starts at PARENT_TIME, slot 3 at +1.5 s,
    // slot 4 at +3 s; second PARENT_TIME + 2 holds no slot start.
    assert_eq!(g.slot_of(PARENT_TIME), Some(2));
    assert_eq!(g.slot_of(PARENT_TIME + 1), None);
    assert_eq!(g.slot_start_ms(3), PARENT_TIME * 1000 + 1_500);
    assert_eq!(g.slot_start(3), PARENT_TIME + 1);
    assert_eq!(g.proposal_slot(PARENT_TIME, PARENT_TIME * 1000 + 300), 3);
    assert_eq!(g.proposal_time(PARENT_TIME, PARENT_TIME * 1000 + 300), PARENT_TIME + 1);
    // The stamp of slot 3 (second +1) read back is a lower bound of slot 3.
    assert_eq!(g.parent_slot(PARENT_TIME + 1), 3);
    assert_eq!(g.proposal_time(PARENT_TIME + 1, PARENT_TIME * 1000 + 1_600), PARENT_TIME + 3);
    // Mid-slot entry waits for the next boundary.
    assert_eq!(g.proposal_slot_after(2, PARENT_TIME * 1000 + 1_501), 4);
    // Deltas alternate 1 s and 2 s, the grid has no drift.
    let stamps: Vec<u64> = (2..8).map(|s| g.slot_start(s) - PARENT_TIME).collect();
    assert_eq!(stamps, [0, 1, 3, 4, 6, 7]);
}

#[test]
fn am27a_b4_on_sub_second_grids() {
    for grid in [GRID_30, GRID_1500] {
        // Equal seconds are allowed, and any later second: no grid check.
        check_on(grid, &valid()).expect("equal seconds");
        check_on(grid, &edited(|h| h.timestamp = PARENT_TIME + 1)).expect("next second");
        check_on(grid, &edited(|h| h.timestamp = PARENT_TIME + 2)).expect("no slot starts in it, still accepted");
        check_on(grid, &edited(|h| h.timestamp = PARENT_TIME + 997)).expect("a later second");
        assert!(matches!(
            check_on(grid, &edited(|h| h.timestamp = PARENT_TIME - 1)),
            Err(Profile1Error::TimestampBeforeParent { .. })
        ));
        assert!(matches!(
            check_profile1_slot(&grid, PARENT_TIME - 1, PARENT_TIME),
            Err(Profile1Error::TimestampBeforeParent { .. })
        ));
        // The clock bound is unchanged and vote-only.
        check_profile1_vote_time(PARENT_TIME + 2, PARENT_TIME).expect("within 2 s");
        assert!(matches!(
            check_profile1_vote_time(PARENT_TIME + 3, PARENT_TIME),
            Err(Profile1Error::TimestampInFuture { .. })
        ));
    }
    // 8000 ms keeps AM27's exact checks.
    assert!(matches!(check_on(GRID, &valid()), Err(Profile1Error::TimestampSameSlot { .. })));
    assert!(matches!(
        check_on(GRID, &edited(|h| h.timestamp = PARENT_TIME + 9)),
        Err(Profile1Error::TimestampOffGrid { .. })
    ));
    check_on(GRID, &edited(|h| h.timestamp = PARENT_TIME + 8)).expect("next slot");
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
    // EIP-7685's sha256("") (the fixture); AM24's constant.
    assert_eq!(
        PROFILE1_REQUESTS_HASH,
        b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    // Absent is refused at every height.
    assert!(matches!(
        check(&edited(|h| h.requests_hash = None)),
        Err(Profile1Error::Missing { item: "B8", .. })
    ));
}

/// AM25: `requestsHash` is a deferred field. Block 1 carries the genesis's,
/// the hash of no requests, so anything else is refused on the header alone;
/// past block 1 the header carries its parent's requests hash, which only the
/// parent's execution tells (checked against it by the execution layer's
/// `validate_header_against_parent`), so the header alone is checked for
/// presence.
#[test]
fn b8_am25_block_1_carries_the_hash_of_no_requests_later_headers_the_parents() {
    let at_1 = |hash| {
        let mut header = unsealed(5);
        header.number = 1;
        header.slot_number = Some(1);
        header.requests_hash = hash;
        seal(header)
    };
    let rules = rules();
    rules.check_header(&at_1(Some(PROFILE1_REQUESTS_HASH))).expect("block 1 with sha256(\"\")");
    for wrong in [alloy_consensus::EMPTY_ROOT_HASH, EMPTY_OMMER_ROOT_HASH, B256::repeat_byte(7)] {
        assert!(matches!(rules.check_header(&at_1(Some(wrong))), Err(Profile1Error::RequestsHash(_))));
    }
    assert!(matches!(rules.check_header(&at_1(None)), Err(Profile1Error::Missing { item: "B8", .. })));
    // Block 5 carrying block 4's requests hash: any value passes the header
    // alone, and the carried check holds it to the parent's execution's.
    for carried in [PROFILE1_REQUESTS_HASH, B256::repeat_byte(7), alloy_consensus::EMPTY_ROOT_HASH] {
        let header = edited(|h| h.requests_hash = Some(carried));
        check(&header).expect("a carried requests hash");
        rules.check_carried_requests_hash(&header, carried).expect("the parent's");
        let other = if carried == PROFILE1_REQUESTS_HASH { B256::repeat_byte(7) } else { PROFILE1_REQUESTS_HASH };
        assert!(matches!(
            rules.check_carried_requests_hash(&header, other),
            Err(Profile1Error::CarriedRequestsHash { .. })
        ));
    }
    assert!(HeaderRules::default().check_carried_requests_hash(&valid(), B256::repeat_byte(7)).is_ok(), "nothing off profile 1");
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
    // The empty-list ommers hash, which reth's genesis builder stamps today,
    // is refused; so is the empty trie root as the requests hash (AM3's value).
    genesis.ommers_hash = EMPTY_OMMER_ROOT_HASH;
    assert!(validate_profile1_genesis_header(&genesis, &rules).is_err());
    genesis.ommers_hash = B256::ZERO;
    genesis.requests_hash = Some(alloy_consensus::EMPTY_ROOT_HASH);
    assert!(validate_profile1_genesis_header(&genesis, &rules).is_err());
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What this node's header type makes of gov5's trailing header fields today
//! (`docs/HEADER_FIELD_PARITY.md`).
//!
//! The fixtures are raw RLP headers written by gov5's own codec
//! (`common/block/header_parity_fixtures_test.go`, with
//! `N42_HEADER_PARITY_FIXTURE_DIR`): the Cancun/Prague header gov5's HotStuff
//! chain seals, with
//!
//! - `slot23_root24`: EIP-7843's slot number at 23 and the root at 24, no
//!   access-list hash (gov5's empty string at 22) -- the native chain from
//!   Glamsterdam with `balTime` unset;
//! - `bal22_slot23_root24`: the same with an EIP-7928 access-list hash;
//! - `bal22_slot23`: no root -- an Ethereum Amsterdam header.
//!
//! Each assertion states current behaviour; the day this node carries the
//! root (`N42Header`, the plan in the document), the refusals flip.

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_rlp::Decodable;
use sha2::{Digest, Sha256};

const SLOT23_ROOT24: &[u8] = include_bytes!("../testdata/header_field_parity/gov5_header_slot23_root24.rlp");
const BAL22_SLOT23_ROOT24: &[u8] =
    include_bytes!("../testdata/header_field_parity/gov5_header_bal22_slot23_root24.rlp");
const BAL22_SLOT23: &[u8] = include_bytes!("../testdata/header_field_parity/gov5_header_bal22_slot23.rlp");
const HASHES: &str = include_str!("../testdata/header_field_parity/gov5_header_hashes.json");

/// The block number of every fixture, and the slot gov5 stamps.
const NUMBER: u64 = 1001;

fn gov5_hash(name: &str) -> B256 {
    let hashes: serde_json::Value = serde_json::from_str(HASHES).expect("hashes json");
    hashes[name].as_str().expect("fixture hash").parse().expect("hash hex")
}

fn decode(mut bytes: &[u8]) -> alloy_rlp::Result<Header> {
    Header::decode(&mut bytes)
}

#[test]
fn the_fixtures_are_the_bytes_gov5_wrote() {
    for (bytes, want) in [
        (SLOT23_ROOT24, "60751acf7c379cfe4fd1ae007376291651f0c83b67f9721b2c7c7691a650803c"),
        (BAL22_SLOT23_ROOT24, "1ddfb52d0e9e2ebf8eda99765c12ad9befeb4465c9ac6ffe698d61ed253879aa"),
        (BAL22_SLOT23, "9241512facd96fd95ccb8d572ba10d6e1dc0fb342d45bc910e3177a990178213"),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), want);
    }
}

/// The element counts the layouts are named after.
#[test]
fn the_fixtures_have_the_layouts_they_are_named_after() {
    fn elements(mut bytes: &[u8]) -> Vec<Vec<u8>> {
        let list = alloy_rlp::Header::decode(&mut bytes).expect("list header");
        assert!(list.list);
        let mut payload = &bytes[..list.payload_length];
        let mut out = Vec::new();
        while !payload.is_empty() {
            let start = payload;
            let item = alloy_rlp::Header::decode(&mut payload).expect("item header");
            payload = &payload[item.payload_length..];
            out.push(start[..start.len() - payload.len()].to_vec());
        }
        out
    }
    let slot_root = elements(SLOT23_ROOT24);
    assert_eq!(slot_root.len(), 24);
    assert_eq!(slot_root[21], [0x80], "no access-list hash: an empty string at 22");
    assert_eq!(slot_root[22], [0x82, 0x03, 0xe9], "slot 1001 at 23");
    assert_eq!(slot_root[23].len(), 33, "the root at 24");

    assert_eq!(elements(BAL22_SLOT23_ROOT24).len(), 24);
    assert_eq!(elements(BAL22_SLOT23).len(), 23);
}

/// alloy's header has no 24th field and no way to read an empty string as an
/// absent hash, so every gov5 header that carries the root is refused. Two
/// separate causes:
///
/// - an empty element 22 (gov5's nil `BlockAccessListHash` ahead of a later
///   field) is not a `B256`;
/// - a 24th element is beyond `slot_number`, the last field alloy knows.
#[test]
fn a_gov5_header_with_a_mobile_registry_root_is_refused_by_alloy_today() {
    assert!(
        matches!(decode(SLOT23_ROOT24), Err(alloy_rlp::Error::UnexpectedLength)),
        "slot at 23, root at 24: {:?}",
        decode(SLOT23_ROOT24)
    );
    assert!(
        matches!(decode(BAL22_SLOT23_ROOT24), Err(alloy_rlp::Error::ListLengthMismatch { .. })),
        "access-list hash, slot, root at 24: {:?}",
        decode(BAL22_SLOT23_ROOT24)
    );
}

/// Without the root, gov5's Amsterdam header is Ethereum's: alloy decodes it,
/// reads the slot at 23, and hashes it to gov5's hash.
#[test]
fn a_gov5_amsterdam_header_without_the_root_decodes_with_alloy_and_hashes_the_same() {
    let header = decode(BAL22_SLOT23).expect("an Ethereum Amsterdam header");
    assert_eq!(header.number, NUMBER);
    assert_eq!(header.slot_number, Some(NUMBER));
    assert!(header.block_access_list_hash.is_some());
    assert_eq!(header.hash_slow(), gov5_hash("gov5_header_bal22_slot23"));
    assert_eq!(alloy_rlp::encode(&header), BAL22_SLOT23);
}

/// Even a header alloy could hold field for field differs from gov5's once
/// the root is dropped: the root is bound into gov5's hash.
#[test]
fn dropping_the_root_changes_the_hash() {
    let header = decode(BAL22_SLOT23).expect("decodes");
    assert_ne!(header.hash_slow(), gov5_hash("gov5_header_bal22_slot23_root24"));
}

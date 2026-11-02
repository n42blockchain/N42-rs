// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `N42Header` against headers written by gov5's own codec
//! (`common/block/header_parity_fixtures_test.go`), byte for byte: each
//! decodes, re-encodes to the same bytes, and hashes to gov5's hash.

use alloy_primitives::B256;
use alloy_rlp::Decodable;
use n42_header::N42Header;
use sha2::{Digest, Sha256};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../h2-consensus/testdata/header_field_parity");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}.rlp")).expect("fixture")
}

fn gov5_hash(name: &str) -> B256 {
    let json = std::fs::read_to_string(format!("{DIR}/gov5_header_hashes.json")).expect("hashes");
    let hashes: serde_json::Value = serde_json::from_str(&json).expect("json");
    hashes[name].as_str().expect("hash").parse().expect("hex")
}

/// SHA-256 of the raw bytes, the same pins as h2-consensus's fixture test.
const FIXTURES: [(&str, &str); 3] = [
    ("gov5_header_slot23_root24", "60751acf7c379cfe4fd1ae007376291651f0c83b67f9721b2c7c7691a650803c"),
    ("gov5_header_bal22_slot23_root24", "1ddfb52d0e9e2ebf8eda99765c12ad9befeb4465c9ac6ffe698d61ed253879aa"),
    ("gov5_header_bal22_slot23", "9241512facd96fd95ccb8d572ba10d6e1dc0fb342d45bc910e3177a990178213"),
];

#[test]
fn every_gov5_fixture_decodes_reencodes_and_hashes_like_gov5() {
    for (name, sha) in FIXTURES {
        let bytes = fixture(name);
        assert_eq!(hex::encode(Sha256::digest(&bytes)), sha, "{name}: fixture bytes");
        let header = N42Header::decode(&mut bytes.as_slice()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(alloy_rlp::encode(&header), bytes, "{name}: re-encoding");
        assert_eq!(header.hash_slow(), gov5_hash(name), "{name}: hash");
        assert_eq!(header.number, 1001, "{name}");
        assert_eq!(header.slot_number, Some(1001), "{name}: slot = number");
    }
}

#[test]
fn the_root_is_element_24_and_absent_from_the_amsterdam_shape() {
    let root = Some(B256::repeat_byte(0x42));
    for name in ["gov5_header_slot23_root24", "gov5_header_bal22_slot23_root24"] {
        let h = N42Header::decode(&mut fixture(name).as_slice()).expect("decodes");
        assert_eq!(h.mobile_registry_root, root, "{name}");
    }
    let gap = N42Header::decode(&mut fixture("gov5_header_slot23_root24").as_slice()).expect("decodes");
    assert_eq!(gap.block_access_list_hash, None, "gov5's empty element 22");
    let amsterdam = N42Header::decode(&mut fixture("gov5_header_bal22_slot23").as_slice()).expect("decodes");
    assert_eq!(amsterdam.mobile_registry_root, None);
    // Without the root, N42Header and alloy agree on the hash.
    assert_eq!(amsterdam.hash_slow(), amsterdam.inner.hash_slow());
}

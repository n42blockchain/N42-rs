// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's sync v1.1 golden vectors (`testdata/sync-v11/`), loaded only after
//! the SHA-256 of the file's raw bytes matches the one its README lists.

use sha2::{Digest, Sha256};

use super::frame::{self, Chunk};

/// The directory of the vectors.
pub(crate) fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/sync-v11")
}

/// The SHA-256 the README lists for `name`.
fn listed_sha256(name: &str) -> String {
    let readme = std::fs::read_to_string(dir().join("README.md")).expect("README.md");
    readme
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            Some((words.next()?, words.next()?))
        })
        .find(|(_, file)| *file == name)
        .map(|(sha, _)| sha.to_owned())
        .unwrap_or_else(|| panic!("README lists no sha256 for {name}"))
}

/// The vector file `name`, checked against the README's SHA-256 of its raw
/// bytes, as JSON.
pub(crate) fn load(name: &str) -> serde_json::Value {
    let raw = std::fs::read(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    let got = hex::encode(Sha256::digest(&raw));
    assert_eq!(got, listed_sha256(name), "{name}: raw bytes differ from the README's sha256");
    serde_json::from_slice(&raw).expect("vector JSON")
}

/// A `0x…` hex field.
pub(crate) fn bytes(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string").trim_start_matches("0x")).expect("hex")
}

/// The chunks a case lists, as [`Chunk`]s.
pub(crate) fn listed_chunks(case: &serde_json::Value) -> Vec<Chunk> {
    case["response_chunks"]
        .as_array()
        .expect("response_chunks")
        .iter()
        .map(|c| {
            let code = u8::from_str_radix(c["code"].as_str().expect("code").trim_start_matches("0x"), 16).expect("code");
            let context = c.get("context_bytes").map(|v| <[u8; 4]>::try_from(bytes(v)).expect("4 context bytes"));
            Chunk { code, context, payload: bytes(&c["payload"]) }
        })
        .collect()
}

/// The framing of one vector file, both ways: every request wire is
/// `framed(request_payload)` and decodes to it; every response wire decodes
/// to exactly the chunks listed and re-encodes to the same bytes.
pub(crate) fn check_framing(name: &str, with_context: bool, max: u64) {
    let file = load(name);
    let cases = file["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let label = case["name"].as_str().unwrap_or("?");
        let payload = bytes(&case["request_payload"]);
        let wire = bytes(&case["request_wire"]);
        assert_eq!(frame::decode_request(&wire, frame::MAX_REQUEST_BYTES).unwrap(), payload, "{name}/{label}: request decode");
        assert_eq!(frame::framed(&payload), wire, "{name}/{label}: request encode");

        let response = bytes(&case["response_wire"]);
        let listed = listed_chunks(case);
        let decoded = frame::decode_chunks(&response, with_context, max).unwrap();
        assert_eq!(decoded, listed, "{name}/{label}: response decode");
        let mut encoded = Vec::new();
        for c in &listed {
            frame::append_chunk(&mut encoded, c.code, c.context.as_ref(), &c.payload);
        }
        assert_eq!(hex::encode(&encoded), hex::encode(&response), "{name}/{label}: response encode");
    }
}

#[test]
fn the_vectors_are_the_ones_gov5_published() {
    for name in ["bodies_by_range_2.json", "commit_qc_1.json"] {
        let file = load(name);
        assert_eq!(file["chain_id"], 1144, "{name}");
    }
}

#[test]
fn bodies_by_range_2_framing_matches_gov5_both_ways() {
    check_framing("bodies_by_range_2.json", true, 64 << 20);
}

#[test]
fn commit_qc_1_framing_matches_gov5_both_ways() {
    check_framing("commit_qc_1.json", false, 1 << 24);
}

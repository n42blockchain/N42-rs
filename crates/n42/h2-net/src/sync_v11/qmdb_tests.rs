// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's golden vectors (`testdata/sync-v11`, sha256-pinned against the
//! README): every request and every reply payload is decoded and re-encoded
//! byte for byte, and this crate's servers, run over the vectors' pivots,
//! answer every case with gov5's chunks.

use super::*;
use crate::sync_v11::code;
use serde_json::Value;
use sha2::Digest as _;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/sync-v11");

fn raw(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap()
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&raw(name)).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn h256(v: &Value) -> B256 {
    B256::from_slice(&hx(v))
}

fn case<'a>(file: &'a Value, name: &str) -> &'a Value {
    file["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()
}

fn chunks(c: &Value) -> Vec<ReplyChunk> {
    c["response_chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|ch| ReplyChunk { code: hx(&ch["code"])[0], payload: hx(&ch["payload"]) })
        .collect()
}

#[test]
fn the_vectors_are_the_readmes_bytes() {
    let readme = String::from_utf8(raw("README.md")).unwrap();
    for name in ["qmdb_status_1.json", "qmdb_manifest_1.json", "qmdb_twigs_1.json", "code_by_hash_1.json"] {
        let sum = hex::encode(sha2::Sha256::digest(raw(name)));
        assert!(readme.contains(&format!("{sum}  {name}")), "{name}: sha256 {sum} is not the README's");
    }
}

/// Twig `id` of a pivot, from a vector chunk carrying its records from the
/// first slot, its roots computed.
fn twig_from_chunk(payload: &[u8], next_slot: u64) -> ServedTwig {
    let c = TwigChunk::decode(payload).unwrap();
    let (start, end) = twig_slots(c.twig_id, next_slot, 0);
    let leaf_root = match c.records.as_slice() {
        [Record::Hollow { leaf_root }] => *leaf_root,
        records => {
            assert_eq!(records.len() as u64, end - start);
            let leaves: Vec<B256> = records
                .iter()
                .map(|r| match r {
                    Record::Dead { leaf_hash } => *leaf_hash,
                    r => leaf_hash(&r.key_hash().unwrap(), r.value().unwrap()),
                })
                .collect();
            fold_twig_leaves(&leaves)
        }
    };
    ServedTwig { id: c.twig_id, bits: c.bits, records: c.records, roots: TwigRoots { leaf_root, bits_root: bits_root(&c.bits) } }
}

/// The fixture chain's pivot 8 (one twig, 82 slots) and the synthetic
/// three-twig forest (hollow, full, partial), rebuilt from the vectors.
fn pivots() -> (Snapshot, Snapshot) {
    let man = load("qmdb_manifest_1.json");
    let tw = load("qmdb_twigs_1.json");
    let page = ManifestPage::decode(&chunks(case(&man, "chain_pivot"))[0].payload).unwrap();
    let chain_twig = twig_from_chunk(&chunks(case(&tw, "chain_twig"))[0].payload, page.next_slot);
    let chain =
        Snapshot::from_twigs(page.pivot_number, page.pivot_hash, page.root, page.next_slot, vec![chain_twig]).unwrap();
    let all = ManifestPage::decode(&chunks(case(&man, "synthetic_all"))[0].payload).unwrap();
    let hl = chunks(case(&tw, "hollow_and_live"));
    let past = chunks(case(&tw, "past_end"));
    let twigs = vec![
        twig_from_chunk(&hl[0].payload, all.next_slot),
        twig_from_chunk(&hl[1].payload, all.next_slot),
        twig_from_chunk(&past[0].payload, all.next_slot),
    ];
    assert_eq!(twigs.iter().map(|t| t.roots).collect::<Vec<_>>(), all.twigs);
    let synthetic = Snapshot::from_twigs(all.pivot_number, all.pivot_hash, all.root, all.next_slot, twigs).unwrap();
    (chain, synthetic)
}

fn server() -> StateServer {
    let (chain, synthetic) = pivots();
    let s = StateServer::default();
    s.publish(synthetic);
    s.publish(chain);
    s
}

#[test]
fn status_cases() {
    let file = load("qmdb_status_1.json");
    let s = server();
    for c in file["cases"].as_array().unwrap() {
        let req = hx(&c["request_payload"]);
        assert_eq!(vec![serve_status(Some(&s), 0, &req)], chunks(c), "{}", c["name"]);
    }
    let ok = &chunks(case(&file, "status"))[0].payload;
    let st = QmdbStatus::decode(ok).unwrap();
    assert_eq!((st.pivot_lo, st.pivot_hi, st.flags), (8, 8, 3));
    assert_eq!(st.encode(), *ok);
    assert!(QmdbStatus::decode(&ok[1..]).is_err());
}

#[test]
fn manifest_cases() {
    let file = load("qmdb_manifest_1.json");
    let s = server();
    for c in file["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let payload = hx(&c["request_payload"]);
        let req = ManifestRequest::decode(&payload).unwrap();
        let f = &c["request_fields"];
        assert_eq!(req.pivot_hash, h256(&f["pivot_hash"]), "{name}");
        assert_eq!((req.first_twig, u64::from(req.count)), (f["first_twig"].as_u64().unwrap(), f["count"].as_u64().unwrap()));
        assert_eq!(req.encode(), payload, "{name}");
        let want = chunks(c);
        let snap = s.lookup(&req.pivot_hash);
        assert_eq!(vec![serve_manifest(snap.as_deref(), &req)], want, "{name}");
        if want[0].code == CODE_SUCCESS {
            let page = ManifestPage::decode(&want[0].payload).unwrap();
            assert_eq!(page.encode(), want[0].payload, "{name}");
            verify_manifest_page(&page, &page.root).unwrap();
        }
    }
}

#[test]
fn twigs_cases() {
    let file = load("qmdb_twigs_1.json");
    let s = server();
    for c in file["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let payload = hx(&c["request_payload"]);
        let req = TwigsRequest::decode(&payload).unwrap();
        let f = &c["request_fields"];
        assert_eq!(
            (req.first_twig, u64::from(req.twig_count), req.from_slot, u64::from(req.flags), u64::from(req.max_bytes)),
            (
                f["first_twig"].as_u64().unwrap(),
                f["twig_count"].as_u64().unwrap(),
                f["from_slot"].as_u64().unwrap(),
                f["flags"].as_u64().unwrap(),
                f["max_bytes"].as_u64().unwrap()
            ),
            "{name}"
        );
        assert_eq!(req.encode(), payload, "{name}");
        let want = chunks(c);
        let snap = s.lookup(&req.pivot_hash);
        let mut got = Vec::new();
        serve_twigs(snap.as_deref(), &req, |ch| {
            got.push(ch);
            true
        });
        assert_eq!(got, want, "{name}");
        for ch in &want {
            match ch.code {
                CODE_SUCCESS => assert_eq!(TwigChunk::decode(&ch.payload).unwrap().encode().unwrap(), ch.payload, "{name}"),
                CODE_END => assert_eq!(TwigsEnd::decode(&ch.payload).unwrap().encode(), ch.payload, "{name}"),
                _ => {}
            }
        }
        match read_twigs(&want, &req) {
            Ok((tcs, end)) => {
                assert!(end.is_some(), "{name}");
                let snap = snap.unwrap();
                for tc in tcs.iter().filter(|_| req.from_slot == 0 && !req.bits_only()) {
                    verify_twig(tc, &snap.entries[tc.twig_id as usize], snap.next_slot).unwrap();
                }
            }
            Err(ReadError::Code { code, .. }) => assert_eq!(code, want[0].code),
            Err(e) => panic!("{name}: {e}"),
        }
    }
}

#[test]
fn code_cases() {
    let file = load("code_by_hash_1.json");
    for c in file["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let payload = hx(&c["request_payload"]);
        let want = chunks(c);
        match code::decode_code_request(&payload) {
            Ok(hashes) => {
                assert_eq!(code::encode_code_request(&hashes).unwrap(), payload, "{name}");
                let stored = want[0].payload.clone();
                let key = hashes[0];
                assert_eq!(alloy_primitives::keccak256(&stored), key);
                let mut got = Vec::new();
                code::serve_code(|h| (*h == key).then(|| stored.clone()), &hashes, |ch| {
                    got.push(ch);
                    true
                });
                assert_eq!(got, want, "{name}");
                let read = code::read_code(&want, hashes.len()).unwrap();
                code::verify_code(&hashes, &read).unwrap();
                assert_eq!(read, vec![Some(stored), None]);
            }
            Err(e) => {
                assert_eq!(want.len(), 1);
                assert_eq!((want[0].code, e.to_string()), (CODE_INVALID_REQUEST, want[0].message()), "{name}");
            }
        }
    }
}

#[test]
fn the_portable_file_and_its_twigs_round_trip() {
    let (chain, synthetic) = pivots();
    for snap in [chain, synthetic] {
        let twigs: Vec<ServedTwig> = (0..snap.twig_count()).map(|i| snap.twig(i).unwrap()).collect();
        let h = PortableHeader {
            chain_id: 1144,
            genesis_hash: B256::repeat_byte(7),
            block_number: snap.pivot,
            block_hash: snap.pivot_hash,
            root: snap.root,
            next_slot: snap.next_slot,
        };
        let bytes = assemble_portable(&h, &twigs).unwrap();
        let (h2, back) = twigs_from_portable(&bytes).unwrap();
        assert_eq!(h2, h);
        for (a, b) in twigs.iter().zip(&back) {
            assert_eq!((a.id, a.bits, a.roots), (b.id, b.bits, b.roots));
            let live_p_as_live: Vec<Record> = a
                .records
                .iter()
                .map(|r| match r {
                    Record::LiveP { value, .. } => Record::Live { key_hash: r.key_hash().unwrap(), value: value.clone() },
                    r => r.clone(),
                })
                .collect();
            assert_eq!(live_p_as_live, b.records);
        }
        let mut bad = bytes.clone();
        bad[200] ^= 1;
        assert!(twigs_from_portable(&bad).is_err());
    }
}

#[test]
fn damaged_twigs_and_pages_are_refused() {
    let (chain, synthetic) = pivots();
    let tw = chain.twig(0).unwrap();
    let good = TwigChunk { twig_id: 0, bits: tw.bits, records: tw.records.clone() };
    verify_twig(&good, &tw.roots, chain.next_slot).unwrap();

    // A changed value.
    let mut c = good.clone();
    let i = c.records.iter().position(|r| matches!(r, Record::LiveP { .. })).unwrap();
    if let Record::LiveP { value, .. } = &mut c.records[i] {
        value.push(0);
    }
    assert!(verify_twig(&c, &tw.roots, chain.next_slot).is_err());
    // A live slot tagged dead (same leaf, wrong tag).
    let mut c = good.clone();
    let r = &c.records[i];
    c.records[i] = Record::Dead { leaf_hash: leaf_hash(&r.key_hash().unwrap(), r.value().unwrap()) };
    assert!(verify_twig(&c, &tw.roots, chain.next_slot).is_err());
    // A flipped bit.
    let mut c = good.clone();
    c.bits[0] ^= 1;
    assert!(verify_twig(&c, &tw.roots, chain.next_slot).is_err());
    // A missing record.
    let mut c = good;
    c.records.pop();
    assert!(verify_twig(&c, &tw.roots, chain.next_slot).is_err());

    // Pages: a wrong anchored root, a damaged proof, a damaged twig entry.
    let req = ManifestRequest { pivot_hash: synthetic.pivot_hash, first_twig: 1, count: 1, reserved: 0 };
    let page = ManifestPage::decode(&serve_manifest(Some(&synthetic), &req).payload).unwrap();
    verify_manifest_page(&page, &synthetic.root).unwrap();
    assert!(verify_manifest_page(&page, &B256::repeat_byte(1)).is_err());
    let mut p = page.clone();
    p.proof[0].0[0] ^= 1;
    assert!(verify_manifest_page(&p, &synthetic.root).is_err());
    let mut p = page.clone();
    p.proof.push(B256::ZERO);
    assert!(verify_manifest_page(&p, &synthetic.root).is_err());
    let mut p = page;
    p.twigs[0].bits_root.0[3] ^= 1;
    assert!(verify_manifest_page(&p, &synthetic.root).is_err());
}

#[test]
fn a_source_that_drifted_is_served_as_a_server_error() {
    let (chain, _) = pivots();
    let mut tw = chain.twig(0).unwrap();
    tw.bits[0] ^= 1;
    let drifted = Snapshot::new(
        chain.pivot,
        chain.pivot_hash,
        chain.root,
        chain.next_slot,
        chain.entries.clone(),
        std::sync::Arc::new(MemTwigs(vec![tw])),
    )
    .unwrap();
    let req = TwigsRequest { pivot_hash: chain.pivot_hash, first_twig: 0, twig_count: 1, ..Default::default() };
    let mut got = Vec::new();
    serve_twigs(Some(&drifted), &req, |c| {
        got.push(c);
        true
    });
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].code, CODE_SERVER_ERROR);
}

#[test]
fn a_server_keeps_older_pivots_servable() {
    let (chain, synthetic) = pivots();
    let s = StateServer::new(2);
    s.publish(chain.clone());
    s.publish(synthetic.clone());
    assert!(s.lookup(&chain.pivot_hash).is_some());
    let mut third = chain.clone();
    third.pivot_hash = B256::repeat_byte(9);
    s.publish(third);
    assert!(s.lookup(&chain.pivot_hash).is_none());
    assert!(s.lookup(&synthetic.pivot_hash).is_some());
}

#[test]
fn range_proofs_verify_for_every_run() {
    for count in 1..=9u64 {
        let roots: Vec<B256> = (0..count).map(|i| B256::with_last_byte(i as u8 + 1)).collect();
        let root = upper_root(&roots);
        for first in 0..count {
            for n in 1..=count - first {
                let proof = range_proof(&roots, first, n).unwrap();
                verify_range(&root, count, first, &roots[first as usize..(first + n) as usize], &proof).unwrap();
            }
        }
    }
}

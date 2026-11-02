// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The crate against gov5's cross-client fixtures
//! (`testdata/gov5_cross_client_v1`, written by gov5's
//! `TestWriteCrossClientFixtures` at 39cff9ce). Every byte string and HTTP
//! body is compared exactly; the files themselves are pinned by SHA-256.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes as AlloyBytes, Log, LogData, U256, keccak256};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use n42_mobileverify::bls;
use n42_mobileverify::cohort::{CohortConfig, HeadSource};
use n42_mobileverify::collector::Collector;
use n42_mobileverify::mask::{decode_mask, encode_mask};
use n42_mobileverify::packet::cache::validate_packet_bytes;
use n42_mobileverify::packet::header::{marshal_header, unmarshal_header};
use n42_mobileverify::packet::proto::{h160_to_address, h256_to_u256};
use n42_mobileverify::packet::read_log::{ReadLogEntry, decode_read_log, encode_read_log};
use n42_mobileverify::packet::tx::{decode_transaction, encode_transaction};
use n42_mobileverify::pop::{pop_message, register_request_json};
use n42_mobileverify::pow::{leading_zero_bits, pow_message, solve_pow};
use n42_mobileverify::receipt::signing_message;
use n42_mobileverify::receipts_root::{encode_native_receipt, native_receipts_root};
use n42_mobileverify::{
    AlarmBuffer, CertStore, CohortCoordinator, DeviceKey, MobileAttestationCert, PacketCache, Receipt, Registry,
    Service, ServiceConfig, StreamPacket, accumulator, topics,
};
use parking_lot::RwLock;
use serde_json::Value;
use sha2::{Digest, Sha256};

const WINDOW_CLOSED_AT: u64 = 1_784_372_090_000;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/gov5_cross_client_v1")
}

fn load(name: &str) -> Value {
    let raw = std::fs::read(dir().join(name)).expect("fixture file");
    serde_json::from_slice(&raw).expect("fixture json")
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string field")
}

fn hx(v: &Value) -> Vec<u8> {
    let t = s(v);
    hex::decode(t.strip_prefix("0x").unwrap_or(t)).expect("hex field")
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().expect("fixed-length hex field")
}

fn b256(v: &Value) -> B256 {
    B256::from(arr::<32>(v))
}

fn u(v: &Value) -> u64 {
    v.as_u64().expect("number field")
}

fn quantity(v: &Value) -> U256 {
    let t = s(v);
    U256::from_str_radix(t.strip_prefix("0x").unwrap_or(t), 16).expect("hex quantity")
}

/// The four fixture devices, derived from `keys.json`'s IKMs.
fn devices() -> Vec<DeviceKey> {
    let keys = load("keys.json");
    keys["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .map(|d| DeviceKey::from_ikm(&arr::<32>(&d["ikm"])).expect("key"))
        .collect()
}

fn register_body(k: &DeviceKey) -> String {
    register_request_json(&k.pubkey(), &k.proof_of_possession(), None)
}

#[derive(Default)]
struct Chain {
    head: RwLock<Option<(u64, B256)>>,
    blocks: RwLock<HashMap<B256, u64>>,
}

impl HeadSource for Chain {
    fn head(&self) -> Option<(u64, B256)> {
        *self.head.read()
    }
    fn number_of(&self, hash: &B256) -> Option<u64> {
        self.blocks.read().get(hash).copied()
    }
}

struct Node {
    registry: Arc<Registry>,
    coordinator: Arc<CohortCoordinator>,
    chain: Arc<Chain>,
    svc: Service,
}

fn node(pow_bits: u32) -> Node {
    let registry = Arc::new(Registry::new());
    let packets = Arc::new(PacketCache::new(256));
    let certs = Arc::new(CertStore::new(512));
    let alarms = Arc::new(AlarmBuffer::default());
    let chain = Arc::new(Chain::default());
    let coordinator = Arc::new(
        CohortCoordinator::new(registry.clone(), chain.clone(), certs.clone(), CohortConfig::default())
            .with_clock(Arc::new(|| WINDOW_CLOSED_AT)),
    );
    coordinator.record_alarms_into(alarms.clone());
    let cfg = ServiceConfig { pow_bits, register_limit: 1000, ..ServiceConfig::default() };
    let svc = Service::new(registry.clone(), packets, coordinator.clone(), certs, alarms, chain.clone(), cfg);
    Node { registry, coordinator, chain, svc }
}

async fn call(svc: &Service, method: Method, path: &str, body: &str) -> (u16, Vec<(String, String)>, String) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("request");
    let peer: SocketAddr = "127.0.0.1:40000".parse().expect("addr");
    let resp = svc.handle(req, peer).await;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (status, headers, String::from_utf8(body.to_vec()).expect("utf8 body"))
}

fn assert_outcome(got: (u16, Vec<(String, String)>, String), want: &Value, case: &str) {
    assert_eq!(u64::from(got.0), u(&want["status"]), "status: {case}");
    assert_eq!(got.2, s(&want["body"]), "body: {case}");
}

/// Registers and commits the devices of registry.json's first `steps` steps
/// with the fixture's commit clocks.
fn commit_steps(reg: &Registry, keys: &[DeviceKey], steps: usize) {
    let fx = load("registry.json");
    for step in fx["steps"].as_array().expect("steps").iter().take(steps) {
        for d in step["registered_devices"].as_array().expect("devices") {
            let k = &keys[u(d) as usize];
            reg.register(&k.pubkey(), &k.proof_of_possession()).expect("register");
        }
        reg.commit_epoch_at(u(&step["commit_last_seen_ms"]));
    }
}

#[test]
fn sha256sums_match() {
    let sums = std::fs::read_to_string(dir().join("SHA256SUMS")).expect("SHA256SUMS");
    let mut n = 0;
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (want, name) = line.split_once("  ").expect("sha256sum line");
        let data = std::fs::read(dir().join(name.trim_start_matches('*'))).expect("listed file");
        assert_eq!(hex::encode(Sha256::digest(&data)), want, "{name}");
        n += 1;
    }
    assert_eq!(n, 13);
}

#[test]
fn keys_from_ikm() {
    let fx = load("keys.json");
    for d in fx["devices"].as_array().expect("devices") {
        let k = DeviceKey::from_ikm(&arr::<32>(&d["ikm"])).expect("key");
        assert_eq!(hex::encode(k.secret_scalar()), s(&d["secret_scalar"]));
        assert_eq!(hex::encode(k.pubkey()), s(&d["pubkey"]));
        assert_eq!(hex::encode(k.address()), s(&d["addr"]));
    }
}

#[tokio::test]
async fn pop_messages_and_rejections() {
    let fx = load("pop.json");
    let keys = devices();
    for (d, k) in fx["devices"].as_array().expect("devices").iter().zip(&keys) {
        assert_eq!(hex::encode(k.pubkey()), s(&d["pubkey"]));
        assert_eq!(hex::encode(pop_message(&k.pubkey())), s(&d["pop_message"]));
        assert_eq!(hex::encode(k.proof_of_possession()), s(&d["pop"]));
    }
    assert_eq!(register_body(&keys[0]), s(&fx["sdk_register_request_body"]));

    let n = node(0);
    for r in fx["rejections"].as_array().expect("rejections") {
        let case = s(&r["case"]);
        let (method, body) = if case.starts_with("GET") {
            (Method::GET, String::new())
        } else if let Some(b) = r.get("request_body") {
            (Method::POST, s(b).to_string())
        } else {
            (Method::POST, format!("{{\"pop\":\"{}\",\"pubkey\":\"{}\"}}", s(&r["pop"]), s(&r["pubkey"])))
        };
        let got = call(&n.svc, method, "/mobileverify/register", &body).await;
        assert_outcome(got, r, case);
    }
}

#[tokio::test]
async fn pow_vectors_and_server() {
    let fx = load("pow.json");
    let pk: [u8; 48] = arr(&fx["pubkey"]);
    for v in fx["vectors"].as_array().expect("vectors") {
        let bits = u(&v["bits"]) as u32;
        let m0 = pow_message(&pk, 0);
        assert_eq!(hex::encode(m0), s(&v["message_nonce0"]));
        assert_eq!(hex::encode(keccak256(m0)), s(&v["digest_nonce0"]));
        assert_eq!(u64::from(leading_zero_bits(keccak256(m0).as_slice())), u(&v["leading_zero_bits_nonce0"]));
        let nonce = solve_pow(&pk, bits, 1 << 24).expect("solvable");
        assert_eq!(nonce, u(&v["solved_nonce"]), "smallest nonce for {bits} bits");
        let m = pow_message(&pk, nonce);
        assert_eq!(hex::encode(m), s(&v["solved_message"]));
        assert_eq!(hex::encode(keccak256(m)), s(&v["solved_digest"]));
        assert_eq!(u64::from(leading_zero_bits(keccak256(m).as_slice())), u(&v["leading_zero_bits_solved"]));
    }

    let keys = devices();
    let k = keys.iter().find(|k| k.pubkey() == pk).expect("pow key is a fixture device");
    let trip = fx["sdk_round_trip"].as_array().expect("round trip");
    assert_eq!(register_request_json(&pk, &k.proof_of_possession(), None), s(&trip[0]));
    assert_eq!(register_request_json(&pk, &k.proof_of_possession(), Some(320)), s(&trip[1]));

    let srv = &fx["server_428"];
    let n = node(u(&srv["pow_bits"]) as u32);
    let got = call(&n.svc, Method::POST, "/mobileverify/register", s(&trip[0])).await;
    assert_outcome(got, &srv["missing_nonce"], "missing nonce");
    let bad = &srv["non_decimal_nonce"];
    let got = call(&n.svc, Method::POST, "/mobileverify/register", s(&bad["request_body"])).await;
    assert_outcome(got, bad, "non-decimal nonce");
    let got = call(&n.svc, Method::POST, "/mobileverify/register", s(&trip[1])).await;
    assert_eq!(got.0, 200, "solved retry: {}", got.2);
}

#[tokio::test]
async fn registry_epochs() {
    let fx = load("registry.json");
    let keys = devices();
    for kh in fx["key_hashes"].as_array().expect("key hashes") {
        let k = &keys[u(&kh["device"]) as usize];
        assert_eq!(hex::encode(accumulator::key_hash(&k.pubkey())), s(&kh["key_hash"]));
    }

    let n = node(0);
    let empty = &fx["empty"];
    assert_eq!(hex::encode(n.registry.root()), s(&empty["root"]));
    assert_eq!(hex::encode(n.registry.export_committed()), s(&empty["export_committed"]));
    assert_outcome(call(&n.svc, Method::GET, "/mobileverify/health", "").await, &empty["health"], "empty health");

    for step in fx["steps"].as_array().expect("steps") {
        let no = u(&step["step"]);
        for r in step["registrations"].as_array().expect("registrations") {
            let body = register_body(&keys[u(&r["device"]) as usize]);
            let got = call(&n.svc, Method::POST, "/mobileverify/register", &body).await;
            assert_outcome(got, &r["register"], &format!("step {no} register"));
            let got = call(&n.svc, Method::POST, "/mobileverify/register", &body).await;
            assert_outcome(got, &r["register_again_while_pending"], &format!("step {no} register again"));
        }
        let got = call(&n.svc, Method::GET, "/mobileverify/health", "").await;
        assert_outcome(got, &step["health_before_commit"], &format!("step {no} health before"));

        let (root, committed) = n.registry.commit_epoch_at(u(&step["commit_last_seen_ms"]));
        assert_eq!(committed as u64, u(&step["committed_now"]), "step {no} committed");
        assert_eq!(hex::encode(root), s(&step["root"]), "step {no} root");
        assert_eq!(hex::encode(n.registry.root()), s(&step["root"]));
        for i in step["indices"].as_array().expect("indices") {
            let k = &keys[u(&i["device"]) as usize];
            assert_eq!(n.registry.lookup(&k.pubkey()).map(u64::from), Some(u(&i["index"])), "step {no} index");
        }
        for l in step["leaves"].as_array().expect("leaves") {
            let k = &keys[u(&l["device"]) as usize];
            let kh = accumulator::key_hash(&k.pubkey());
            let idx = u(&l["index"]);
            let mut leaf = vec![0x4c];
            leaf.extend_from_slice(kh.as_slice());
            leaf.extend_from_slice(&idx.to_be_bytes());
            assert_eq!(hex::encode(&leaf), s(&l["leaf_bytes"]));
            assert_eq!(hex::encode(accumulator::leaf_hash(&kh, &idx.to_be_bytes())), s(&l["leaf_hash"]));
        }
        let export = n.registry.export_committed();
        assert_eq!(hex::encode(&export), s(&step["export_committed"]), "step {no} export");
        let copy = Registry::new();
        assert_eq!(copy.import_committed(&export).expect("import"), root, "step {no} import");

        for r in step["register_after_commit"].as_array().expect("after commit") {
            let body = register_body(&keys[u(&r["device"]) as usize]);
            let got = call(&n.svc, Method::POST, "/mobileverify/register", &body).await;
            assert_outcome(got, &r["register"], &format!("step {no} register after commit"));
        }
        let got = call(&n.svc, Method::GET, "/mobileverify/health", "").await;
        assert_outcome(got, &step["health_after_commit"], &format!("step {no} health after"));

        let snap = &step["snapshot_route"];
        assert_eq!(s(&snap["body_is"]), "export_committed");
        let req = Request::builder()
            .method(Method::GET)
            .uri("/mobileverify/snapshot")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let resp = n.svc.handle(req, "127.0.0.1:40000".parse().expect("addr")).await;
        assert_eq!(u64::from(resp.status().as_u16()), u(&snap["status"]));
        let root_header = resp.headers().get("x-mobileverify-root").and_then(|v| v.to_str().ok()).map(str::to_owned);
        assert_eq!(root_header.as_deref(), Some(s(&snap["x_mobileverify_root"])));
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(body.as_ref(), export.as_slice(), "step {no} snapshot body");
    }
}

#[test]
fn mask_vectors() {
    let fx = load("mask.json");
    for v in fx["valid"].as_array().expect("valid") {
        let indices: Vec<u32> = v["indices"].as_array().expect("indices").iter().map(|i| u(i) as u32).collect();
        assert_eq!(hex::encode(encode_mask(&indices).expect("encode")), s(&v["mask"]));
        assert_eq!(decode_mask(&hx(&v["mask"]), u(&v["bound"]) as usize).expect("decode"), indices);
    }
    for v in fx["invalid"].as_array().expect("invalid") {
        let err = decode_mask(&hx(&v["mask"]), u(&v["bound"]) as usize).expect_err(s(&v["class"]));
        assert_eq!(err.to_string(), s(&v["error"]), "{}", s(&v["class"]));
    }
    let err = encode_mask(&[2, 1]).expect_err("unsorted");
    assert_eq!(err.to_string(), s(&fx["encode_unsorted_error"]));
}

fn header_full() -> (B256, u64, B256) {
    let fx = load("cert.json");
    (b256(&fx["block_hash"]), u(&fx["block_number"]), b256(&fx["majority_root"]))
}

#[tokio::test]
async fn receipt_vectors_and_server() {
    let fx = load("receipt.json");
    assert_eq!(s(&fx["dst"]).as_bytes(), bls::DST);
    let keys = devices();
    for v in fx["vectors"].as_array().expect("vectors") {
        let (h, num, root) = (b256(&v["block_hash"]), u(&v["block_number"]), b256(&v["receipts_root"]));
        assert_eq!(hex::encode(signing_message(h, num, root)), s(&v["message"]), "{}", s(&v["name"]));
        for sig in v["signatures"].as_array().expect("signatures") {
            let k = &keys[u(&sig["device"]) as usize];
            assert_eq!(hex::encode(k.sign_receipt(h, num, root)), s(&sig["signature"]), "{}", s(&v["name"]));
        }
    }

    let (hash, number, root) = header_full();
    let sdk = Receipt {
        block_hash: hash,
        block_number: number,
        computed_receipts_root: root,
        verifier_pubkey: keys[0].pubkey(),
        signature: keys[0].sign_receipt(hash, number, root),
        timestamp_ms: 1_784_372_012_345,
    };
    assert_eq!(sdk.to_request_json(), s(&fx["sdk_request_body"]));
    assert_eq!(u(&fx["sdk_response_index"]), 0);

    let n = node(0);
    commit_steps(&n.registry, &keys, 2);
    n.chain.blocks.write().insert(hash, number);
    *n.chain.head.write() = Some((number, hash));
    for o in fx["server_outcomes"].as_array().expect("outcomes") {
        let case = s(&o["case"]);
        if case.contains("after the chain reached N+1") {
            n.coordinator.on_block_committed(number + 1);
        }
        let (method, body) = match o.get("request_body") {
            Some(b) => (Method::POST, s(b).to_string()),
            None => (Method::GET, String::new()),
        };
        let got = call(&n.svc, method, "/mobileverify/receipt", &body).await;
        assert_outcome(got, o, case);
    }
}

#[tokio::test]
async fn cert_aggregate_and_routes() {
    let fx = load("cert.json");
    let keys = devices();
    let (hash, number, majority) = header_full();
    let minority = b256(&fx["minority_root"]);
    let signers: Vec<u32> = fx["signer_indices"].as_array().expect("signers").iter().map(|i| u(i) as u32).collect();

    let reg = Arc::new(Registry::new());
    commit_steps(&reg, &keys, 3);
    assert_eq!(reg.index_bound() as u64, u(&fx["registry_index_bound"]));
    assert_eq!(hex::encode(signing_message(hash, number, majority)), s(&fx["message"]));

    let pks: Vec<_> = fx["signer_pubkeys"]
        .as_array()
        .expect("pubkeys")
        .iter()
        .map(|p| bls::decode_pubkey(&arr::<48>(&p["pubkey"])).expect("pubkey"))
        .collect();
    let agg_pk = bls::aggregate_pubkeys(&pks.iter().collect::<Vec<_>>()).expect("aggregate pubkey");
    assert_eq!(hex::encode(agg_pk.compress()), s(&fx["aggregate_pubkey"]));
    let sigs: Vec<_> = fx["signer_signatures"]
        .as_array()
        .expect("signatures")
        .iter()
        .map(|p| bls::decode_signature(&arr::<96>(&p["signature"])).expect("signature"))
        .collect();
    let agg = bls::aggregate_signatures(&sigs.iter().collect::<Vec<_>>()).expect("aggregate signature");
    assert_eq!(hex::encode(agg.compress()), s(&fx["aggregate_signature"]));
    assert_eq!(hex::encode(encode_mask(&signers).expect("mask")), s(&fx["signer_mask"]));
    let cert = MobileAttestationCert {
        block_hash: hash,
        block_number: number,
        receipts_root: majority,
        aggregate_sig: agg.compress(),
        signer_mask: hx(&fx["signer_mask"]),
        window_closed_at: WINDOW_CLOSED_AT,
    };
    assert_eq!(cert.verify(&reg).expect("cert verifies"), signers);

    // Devices 0, 1, 3 attest the majority root, device 2 the minority one.
    let receipt = |d: usize, root: B256| Receipt {
        block_hash: hash,
        block_number: number,
        computed_receipts_root: root,
        verifier_pubkey: keys[d].pubkey(),
        signature: keys[d].sign_receipt(hash, number, root),
        timestamp_ms: 0,
    };
    let receipts = [receipt(0, majority), receipt(1, majority), receipt(2, minority), receipt(3, majority)];

    // The window-manager variant stores every bucket, majority first.
    let col = Collector::new(reg.clone(), hash, number);
    for r in &receipts {
        col.add(r).expect("collector add");
    }
    let mut buckets = col.close(WINDOW_CLOSED_AT).expect("close");
    buckets.sort_by_key(|c| std::cmp::Reverse(c.signers(reg.index_bound())));
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0], cert);
    let mb = &fx["minority_bucket"];
    assert_eq!(hex::encode(buckets[1].aggregate_sig), s(&mb["aggregate_signature"]));
    assert_eq!(hex::encode(&buckets[1].signer_mask), s(&mb["signer_mask"]));
    let bound = reg.index_bound();
    let wm = format!("[{},{}]\n", buckets[0].to_json(bound), buckets[1].to_json(bound));
    assert_eq!(wm, s(&fx["window_manager_response"]["body"]));

    // The production coordinator, through the HTTP route.
    let n = node(0);
    commit_steps(&n.registry, &keys, 3);
    n.chain.blocks.write().insert(hash, number);
    *n.chain.head.write() = Some((number, hash));
    let path = format!("/mobileverify/cert/{}", hex::encode(hash));
    assert_outcome(call(&n.svc, Method::GET, &path, "").await, &fx["no_cert_response"], "no cert yet");
    for r in &receipts {
        let got = call(&n.svc, Method::POST, "/mobileverify/receipt", &r.to_request_json()).await;
        assert_eq!(got.0, 200, "receipt: {}", got.2);
    }
    for h in number + 1..=number + 5 {
        n.coordinator.on_block_committed(h);
    }
    let got = call(&n.svc, Method::GET, &path, "").await;
    assert_outcome(got, &fx["cohort_coordinator_response"], "coordinator cert");
}

#[test]
fn receipts_root_vectors() {
    let fx = load("receipts_root.json");
    let ok = encode_native_receipt(true, 21_000, &[]);
    let failed = encode_native_receipt(false, 21_000, &[]);
    let logs = [
        Log {
            address: Address::from_slice(&hex::decode("00000000000000000000000000000000000c0ffe").expect("hex")),
            data: LogData::new_unchecked(
                vec![
                    B256::from_slice(
                        &hex::decode("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").expect("hex"),
                    ),
                    B256::left_padding_from(&[0xbe, 0xef]),
                ],
                AlloyBytes::from(vec![0xab; 32]),
            ),
        },
        Log {
            address: Address::repeat_byte(0x11),
            data: LogData::new_unchecked(
                vec![B256::left_padding_from(&[1]), B256::left_padding_from(&[2])],
                AlloyBytes::new(),
            ),
        },
    ];
    let expected: HashMap<&str, Vec<Vec<u8>>> = [
        ("no receipts", vec![]),
        ("one successful receipt, cumulative gas 21000, no logs", vec![ok.clone()]),
        ("one failed receipt, cumulative gas 21000", vec![failed]),
        ("one receipt with two logs (2 topics each; data 32 bytes, then empty)", vec![encode_native_receipt(
            true, 52_345, &logs,
        )]),
        ("three receipts: success, failed (cumulative 42000), two logs (cumulative 94345)", vec![
            ok,
            encode_native_receipt(false, 42_000, &[]),
            encode_native_receipt(true, 94_345, &logs),
        ]),
    ]
    .into_iter()
    .collect();
    let cases = fx["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), expected.len());
    for c in cases {
        let name = s(&c["name"]);
        let enc = &expected[name];
        let want: Vec<String> = c["receipt_rlp"].as_array().expect("rlp").iter().map(|r| s(r).to_string()).collect();
        assert_eq!(enc.iter().map(hex::encode).collect::<Vec<_>>(), want, "{name}");
        assert_eq!(hex::encode(enc.concat()), s(&c["concatenation"]), "{name}");
        assert_eq!(hex::encode(native_receipts_root(enc)), s(&c["root"]), "{name}");
    }
}

#[test]
fn header_codec() {
    let fx = load("header.json");
    for h in fx["headers"].as_array().expect("headers") {
        let name = s(&h["name"]);
        let marshal = hx(&h["marshal"]);
        let proto_len = u(&h["proto_len"]) as usize;
        assert_eq!(hex::encode(&marshal[..proto_len]), s(&h["protobuf"]), "{name}");
        assert_eq!(hex::encode(&marshal[proto_len..]), s(&h["trailer"]), "{name}");
        assert_eq!(hex::encode([marshal[proto_len + 4]]), s(&h["trailer_flags"]), "{name}");
        let header = unmarshal_header(&marshal).expect("unmarshal");
        assert_eq!(hex::encode(marshal_header(&header)), s(&h["marshal"]), "{name} re-marshal");
        assert_eq!(hex::encode(alloy_rlp::encode(&header)), s(&h["rlp"]), "{name} rlp");
        assert_eq!(hex::encode(header.hash_slow()), s(&h["hash"]), "{name} hash");
    }

    // Spot-check the full header's decoded fields against its JSON.
    let j: Value = serde_json::from_str(s(&fx["full_header_json"])).expect("header json");
    let j = &j;
    let full = unmarshal_header(&hx(&fx["headers"][0]["marshal"])).expect("full");
    let i = &full.inner;
    assert_eq!(i.parent_hash, b256(&j["parentHash"]));
    assert_eq!(i.ommers_hash, b256(&j["sha3Uncles"]));
    assert_eq!(i.beneficiary.as_slice(), hx(&j["miner"]).as_slice());
    assert_eq!(i.receipts_root, b256(&j["receiptsRoot"]));
    assert_eq!(U256::from(i.number), quantity(&j["number"]));
    assert_eq!(i.gas_limit, u(&j["gasLimit"]));
    assert_eq!(i.gas_used, u(&j["gasUsed"]));
    assert_eq!(i.timestamp, u(&j["timestamp"]));
    assert_eq!(i.nonce.as_slice(), hx(&j["nonce"]).as_slice());
    assert_eq!(i.base_fee_per_gas.map(U256::from), Some(quantity(&j["baseFeePerGas"])));
    assert_eq!(i.blob_gas_used, Some(u(&j["blobGasUsed"])));
    assert_eq!(i.excess_blob_gas, Some(u(&j["excessBlobGas"])));
    assert_eq!(i.withdrawals_root, Some(b256(&j["withdrawalsRoot"])));
    assert_eq!(i.parent_beacon_block_root, Some(b256(&j["parentBeaconBlockRoot"])));
    assert_eq!(i.requests_hash, Some(b256(&j["requestsRoot"])));
    assert_eq!(full.mobile_registry_root, Some(b256(&j["mobileRegistryRoot"])));
    let minimal = unmarshal_header(&hx(&fx["headers"][1]["marshal"])).expect("minimal");
    assert_eq!(minimal.inner.number, 42);
    assert_eq!(minimal.inner.ommers_hash, B256::ZERO, "proto field 20 wins over the default uncle hash");
    assert_eq!(minimal.inner.base_fee_per_gas, None);
}

#[test]
fn transaction_protobuf() {
    let fx = load("transactions.json");
    let chain_id = u(&fx["chain_id"]);
    for t in fx["transactions"].as_array().expect("transactions") {
        let name = s(&t["name"]);
        let bytes = hx(&t["protobuf"]);
        let tx = decode_transaction(&bytes).expect("decode");
        assert_eq!(encode_transaction(&tx), bytes, "{name} re-encode");
        assert_eq!(tx.r#type, u(&t["type"]), "{name}");
        assert_eq!(tx.sender().map(hex::encode), Some(s(&t["from"]).to_string()), "{name}");
        assert_eq!(h256_to_u256(tx.r.as_ref()), quantity(&t["r"]), "{name} r");
        assert_eq!(h256_to_u256(tx.s.as_ref()), quantity(&t["s"]), "{name} s");
        assert_eq!(h256_to_u256(tx.v.as_ref()), quantity(&t["v"]), "{name} v");
        assert_eq!(tx.chain_id, if tx.r#type == 0 { 0 } else { chain_id }, "{name} chain id");

        let without = hx(&t["protobuf_without_from"]);
        let mut stripped = tx.clone();
        stripped.from = None;
        assert_eq!(encode_transaction(&stripped), without, "{name} without from");
        assert_eq!(decode_transaction(&without).expect("decode").sender(), None);

        let eth = hx(&t["ethereum_encoding"]);
        assert_eq!(hex::encode(keccak256(&eth)), s(&t["hash"]), "{name} hash");
        let env = alloy_consensus::TxEnvelope::decode_2718(&mut eth.as_slice()).expect("ethereum decode");
        use alloy_consensus::Transaction as _;
        assert_eq!(env.nonce(), tx.nonce, "{name} nonce");
        assert_eq!(env.gas_limit(), tx.gas, "{name} gas");
        assert_eq!(env.value(), h256_to_u256(tx.value.as_ref()), "{name} value");
        assert_eq!(env.to(), tx.to.as_ref().map(|h| h160_to_address(Some(h))), "{name} to");
        assert_eq!(env.input().as_ref(), tx.data.as_slice(), "{name} data");
        assert_eq!(env.chain_id(), Some(chain_id), "{name}");
    }
}

fn entry_of(d: &Value) -> ReadLogEntry {
    match s(&d["kind"]) {
        "account_not_found" => ReadLogEntry::AccountNotFound,
        "account" => ReadLogEntry::Account {
            nonce: s(&d["nonce"]).parse().expect("nonce"),
            balance: quantity(&d["balance"]),
            code_hash: b256(&d["code_hash"]),
        },
        "storage" => ReadLogEntry::Storage(quantity(&d["value"])),
        "block_hash" => ReadLogEntry::BlockHash(b256(&d["hash"])),
        k => panic!("unknown kind {k}"),
    }
}

#[test]
fn read_log_codec() {
    let fx = load("read_log.json");
    let entries: Vec<ReadLogEntry> =
        fx["entries"].as_array().expect("entries").iter().map(|e| entry_of(&e["decoded"])).collect();
    let encoded = hx(&fx["encoded"]);
    assert_eq!(decode_read_log(&encoded).expect("decode"), entries);
    assert_eq!(encode_read_log(&entries), encoded);
    for (e, want) in fx["entries"].as_array().expect("entries").iter().zip(&entries) {
        let one = encode_read_log(std::slice::from_ref(want));
        assert_eq!(hex::encode(&one[4..]), s(&e["entry_bytes"]), "{}", s(&e["desc"]));
    }
    for v in fx["invalid"].as_array().expect("invalid") {
        let err = decode_read_log(&hx(&v["bytes"])).expect_err(s(&v["bytes"]));
        assert_eq!(err.to_string(), s(&v["error"]));
    }
    for v in fx["non_canonical_inputs"].as_array().expect("non-canonical") {
        let got = decode_read_log(&hx(&v["bytes"]));
        assert_eq!(got.is_ok(), v["accepted"].as_bool().expect("accepted"), "{}", s(&v["bytes"]));
        if let Ok(entries) = got {
            assert_eq!(hex::encode(encode_read_log(&entries)), s(&v["reencoded"]), "{}", s(&v["bytes"]));
        }
    }
}

fn describe(e: &ReadLogEntry) -> String {
    match e {
        ReadLogEntry::AccountNotFound => "account_not_found".into(),
        ReadLogEntry::Account { nonce, balance, code_hash } => {
            format!("account nonce={nonce} balance={balance:#x} code_hash={}", hex::encode(code_hash))
        }
        ReadLogEntry::Storage(v) => format!("storage {v:#x}"),
        ReadLogEntry::BlockHash(h) => format!("block_hash {}", hex::encode(h)),
    }
}

#[test]
fn stream_packets() {
    let fx = load("stream_packet.json");
    for p in fx["packets"].as_array().expect("packets") {
        let name = s(&p["name"]);
        let d = &p["decoded"];
        let bytes = hx(&p["packet"]);
        let pkt = StreamPacket::decode(&bytes).expect("decode");
        assert_eq!(pkt.encode(), bytes, "{name} re-encode");
        assert_eq!(hex::encode([pkt.flags()]), s(&d["flags"]), "{name}");
        assert_eq!(pkt.block_hash, b256(&d["block_hash"]), "{name}");
        assert_eq!(hex::encode(&pkt.header), s(&d["header_bytes"]), "{name}");
        let header = unmarshal_header(&pkt.header).expect("header");
        assert_eq!(header.hash_slow(), pkt.block_hash, "{name} header hash");
        assert_eq!(header.inner.number, u(&d["block_number"]), "{name}");
        assert_eq!(validate_packet_bytes(&bytes).expect("valid"), (pkt.block_hash, u(&d["block_number"])));
        assert_eq!(pkt.transactions.len() as u64, u(&d["tx_count"]), "{name}");
        for (tx, want) in pkt.transactions.iter().zip(d["transactions"].as_array().expect("txs")) {
            assert_eq!(hex::encode(tx), s(want), "{name}");
            let t = decode_transaction(tx).expect("tx");
            assert!(t.sender().is_some(), "{name}: packet transactions carry from");
        }
        assert_eq!(hex::encode(&pkt.read_log), s(&d["read_log_bytes"]), "{name}");
        let entries = decode_read_log(&pkt.read_log).expect("read log");
        assert_eq!(entries.len() as u64, u(&d["read_log_entry_count"]), "{name}");
        let want: Vec<String> =
            d["read_log_entries"].as_array().expect("entries").iter().map(|e| s(e).to_string()).collect();
        assert_eq!(entries.iter().map(describe).collect::<Vec<_>>(), want, "{name}");
        assert_eq!(pkt.bytecodes.len() as u64, u(&d["bytecode_count"]), "{name}");
        for ((h, code), want) in pkt.bytecodes.iter().zip(d["bytecodes"].as_array().expect("codes")) {
            assert_eq!(*h, b256(&want["hash"]), "{name}");
            assert_eq!(hex::encode(code), s(&want["code"]), "{name}");
            assert_eq!(keccak256(code), *h, "{name}: code hash");
        }
        // The receipts root gov5's ExecuteAndVerifyV2 computed equals the header's.
        for r in p["execute_and_verify_v2"].as_array().expect("results") {
            assert!(r["verified"].as_bool().expect("verified"));
            assert_eq!(header.inner.receipts_root, b256(&r["computed_receipts_root"]), "{name}");
        }
    }
    // The transfer's one successful 21000-gas receipt gives that root.
    let transfer = &fx["packets"][1]["execute_and_verify_v2"][0];
    assert_eq!(native_receipts_root(&[encode_native_receipt(true, 21_000, &[])]), b256(&transfer["computed_receipts_root"]));
}

#[test]
fn gossip_topics() {
    let fx = load("topics.json");
    let genesis = b256(&fx["genesis_hash"]);
    assert_eq!(hex::encode(&genesis[..4]), s(&fx["genesis4"]));
    for (key, name) in [
        ("mobileverify_packet", topics::PACKET),
        ("mobileverify_registration", topics::REGISTRATION),
        ("mobileverify_cohort_index", topics::COHORT_INDEX),
        ("mobileverify_cohort_reveal", topics::COHORT_REVEAL),
        ("mobileverify_cohort_cert", topics::COHORT_CERT),
    ] {
        assert_eq!(topics::topic(&genesis, name), s(&fx[key]));
    }
    let keys = devices();
    let payload = topics::registration_payload(&keys[0].pubkey(), &keys[0].proof_of_possession());
    assert_eq!(hex::encode(payload), s(&fx["registration_payload_device0"]));
    let (pk, pop) = topics::parse_registration_payload(&payload).expect("parse");
    assert_eq!(pk, keys[0].pubkey());
    assert_eq!(pop, keys[0].proof_of_possession());
    assert!(topics::parse_registration_payload(&payload[1..]).is_none());
}

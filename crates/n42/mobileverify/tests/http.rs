// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HTTP surface over a real socket: status lines, header values and
//! body bytes per route, including the error strings the Go SDK matches on.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::Header;
use alloy_primitives::B256;
use bytes::Bytes;
use n42_header::N42Header;
use n42_mobileverify::cohort::{CohortConfig, HeadSource};
use n42_mobileverify::packet::header::{EMPTY_UNCLE_HASH, marshal_header};
use n42_mobileverify::pow::solve_pow;
use n42_mobileverify::{
    AlarmBuffer, CertStore, CohortCoordinator, DeviceKey, PacketCache, Receipt, Registry, Service, ServiceConfig,
    StreamPacket, serve,
};
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

struct Fixture {
    addr: SocketAddr,
    registry: Arc<Registry>,
    packets: Arc<PacketCache>,
    coordinator: Arc<CohortCoordinator>,
    alarms: Arc<AlarmBuffer>,
    chain: Arc<Chain>,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start(cfg: ServiceConfig) -> Fixture {
    let registry = Arc::new(Registry::new());
    let packets = Arc::new(PacketCache::new(256));
    let certs = Arc::new(CertStore::new(512));
    let alarms = Arc::new(AlarmBuffer::default());
    let chain = Arc::new(Chain::default());
    let coordinator =
        Arc::new(CohortCoordinator::new(registry.clone(), chain.clone(), certs.clone(), CohortConfig::default()));
    coordinator.record_alarms_into(alarms.clone());
    let svc = Arc::new(Service::new(
        registry.clone(),
        packets.clone(),
        coordinator.clone(),
        certs,
        alarms.clone(),
        chain.clone(),
        cfg,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(serve(listener, svc, async {
        let _ = rx.await;
    }));
    Fixture { addr, registry, packets, coordinator, alarms, chain, _stop: tx }
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Resp {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.get(&k.to_ascii_lowercase()).map(String::as_str)
    }
}

async fn request(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> Resp {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut raw)).await.unwrap().unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&raw[..split]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();
    Resp { status, headers, body: raw[split + 4..].to_vec() }
}

fn register_body(k: &DeviceKey, nonce: Option<u64>) -> String {
    let mut s = format!(
        "{{\"pubkey\":\"{}\",\"pop\":\"0x{}\"",
        hex::encode(k.pubkey()),
        hex::encode(k.proof_of_possession())
    );
    if let Some(n) = nonce {
        s.push_str(&format!(",\"pow_nonce\":\"{n}\""));
    }
    s.push('}');
    s
}

fn assert_json_error(r: &Resp, status: u16, msg: &str) {
    assert_eq!(r.status, status, "{}", r.text());
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.text(), format!("{{\"error\":\"{msg}\"}}\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_flow() {
    let f = start(ServiceConfig::default()).await;
    let k = DeviceKey::from_ikm(&[1; 32]).unwrap();

    let r = request(f.addr, "GET", "/mobileverify/register", b"").await;
    assert_json_error(&r, 405, "POST only");
    let r = request(f.addr, "POST", "/mobileverify/register", b"{").await;
    assert_json_error(&r, 400, "bad json");
    let r = request(f.addr, "POST", "/mobileverify/register", br#"{"pubkey":"ab","pop":"cd"}"#).await;
    assert_json_error(&r, 400, "pubkey must be 48 hex bytes, pop 96");
    let big = vec![b' '; 5000];
    let r = request(f.addr, "POST", "/mobileverify/register", &big).await;
    assert_json_error(&r, 400, "bad json");

    let other = DeviceKey::from_ikm(&[2; 32]).unwrap();
    let bad = format!(
        "{{\"pubkey\":\"{}\",\"pop\":\"{}\"}}",
        hex::encode(k.pubkey()),
        hex::encode(other.proof_of_possession())
    );
    let r = request(f.addr, "POST", "/mobileverify/register", bad.as_bytes()).await;
    assert_json_error(&r, 403, "mobileverify: invalid proof of possession");

    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, None).as_bytes()).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.text(), "{\"committed\":false,\"index\":0}\n");

    // The rate limit counts every POST from the IP: six so far, ten allowed.
    f.registry.commit_epoch();
    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, None).as_bytes()).await;
    assert_eq!(r.text(), "{\"committed\":true,\"index\":0}\n");
    for _ in 0..4 {
        let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, None).as_bytes()).await;
        assert_eq!(r.status, 200);
    }
    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, None).as_bytes()).await;
    assert_json_error(&r, 429, "registration rate limit");

    // Revoked keys must rotate.
    let f = start(ServiceConfig::default()).await;
    f.registry.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
    f.registry.commit_epoch();
    f.registry.revoke(&k.pubkey());
    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, None).as_bytes()).await;
    assert_json_error(&r, 403, "mobileverify: key was already registered; rotate to a fresh key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_pow() {
    let f = start(ServiceConfig { pow_bits: 8, ..ServiceConfig::default() }).await;
    let k = DeviceKey::from_ikm(&[3; 32]).unwrap();
    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, None).as_bytes()).await;
    assert_eq!(r.status, 428);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.text(), "{\"error\":\"mobileverify: registration proof-of-work required\",\"pow_bits\":8}\n");
    let nonce = solve_pow(&k.pubkey(), 8, 0).unwrap();
    let wrong = (0..).find(|n| !n42_mobileverify::pow::verify_pow(&k.pubkey(), *n, 8)).unwrap();
    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, Some(wrong)).as_bytes()).await;
    assert_eq!(r.status, 428);
    let r = request(f.addr, "POST", "/mobileverify/register", register_body(&k, Some(nonce)).as_bytes()).await;
    assert_eq!(r.text(), "{\"committed\":false,\"index\":0}\n");
}

fn sample_packet(number: u64) -> (StreamPacket, B256) {
    let h = N42Header::from(Header { number, ommers_hash: EMPTY_UNCLE_HASH, ..Default::default() });
    let hash = h.hash_slow();
    let pkt = StreamPacket {
        block_hash: hash,
        header: Bytes::from(marshal_header(&h)),
        read_log: Bytes::from_static(&[0, 0, 0, 0]),
        ..Default::default()
    };
    (pkt, hash)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_latest_and_ingest() {
    let f = start(ServiceConfig::default()).await;
    let r = request(f.addr, "GET", "/mobileverify/latest", b"").await;
    assert_json_error(&r, 503, "head not available");
    assert_eq!(r.header("cache-control"), None);

    let (pkt, hash) = sample_packet(88);
    *f.chain.head.write() = Some((88, hash));
    let r = request(f.addr, "GET", "/mobileverify/latest", b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.text(), format!("{{\"hash\":\"0x{}\",\"number\":88,\"packet\":false}}\n", hex::encode(hash)));
    let r = request(f.addr, "POST", "/mobileverify/latest", b"").await;
    assert_json_error(&r, 405, "GET only");

    let path = format!("/mobileverify/packet/{}", hex::encode(hash));
    let r = request(f.addr, "GET", &path, b"").await;
    assert_json_error(&r, 404, "packet not in window");
    let r = request(f.addr, "GET", "/mobileverify/packet/xyz", b"").await;
    assert_json_error(&r, 400, "bad block hash");
    let r = request(f.addr, "GET", "/mobileverify/packet/", b"").await;
    assert_json_error(&r, 400, "bad block hash");
    let r = request(f.addr, "POST", &path, b"").await;
    assert_json_error(&r, 405, "GET only");

    // Loopback ingest.
    let enc = pkt.encode();
    let r = request(f.addr, "PUT", "/mobileverify/packet", &enc).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.text(), format!("{{\"hash\":\"0x{}\",\"new\":true,\"number\":88}}\n", hex::encode(hash)));
    let mut forged = pkt.clone();
    forged.block_hash = B256::repeat_byte(1);
    let r = request(f.addr, "PUT", "/mobileverify/packet", &forged.encode()).await;
    assert_json_error(&r, 400, "mobileverify: packet block hash does not match its header");

    let r = request(f.addr, "GET", &format!("/mobileverify/packet/0x{}", hex::encode(hash)), b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.header("cache-control"), Some("public, max-age=31536000, immutable"));
    assert_eq!(r.body, enc);
    assert!(f.packets.has(&hash));
    let r = request(f.addr, "GET", "/mobileverify/latest", b"").await;
    assert!(r.text().ends_with("\"packet\":true}\n"));

    let r = request(f.addr, "GET", "/mobileverify/packet", b"").await;
    assert_eq!(r.status, 301);
    assert_eq!(r.header("location"), Some("/mobileverify/packet/"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_cert_health_alarms() {
    let f = start(ServiceConfig::default()).await;
    let keys: Vec<_> = (1..=3u8).map(|i| DeviceKey::from_ikm(&[i; 32]).unwrap()).collect();
    for k in &keys {
        f.registry.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
    }
    let pending = DeviceKey::from_ikm(&[9; 32]).unwrap();
    f.registry.commit_epoch();
    f.registry.register(&pending.pubkey(), &pending.proof_of_possession()).unwrap();
    let hash = B256::repeat_byte(0x42);
    f.chain.blocks.write().insert(hash, 500);
    let root = B256::repeat_byte(0xAA);
    let other = B256::repeat_byte(0xBB);
    let receipt = |k: &DeviceKey, n: u64, r: B256| {
        Receipt {
            block_hash: hash,
            block_number: n,
            computed_receipts_root: r,
            verifier_pubkey: k.pubkey(),
            signature: k.sign_receipt(hash, n, r),
            timestamp_ms: 1,
        }
        .to_request_json()
    };
    let post = |body: String| {
        let addr = f.addr;
        async move { request(addr, "POST", "/mobileverify/receipt", body.as_bytes()).await }
    };

    let r = request(f.addr, "GET", "/mobileverify/receipt", b"").await;
    assert_json_error(&r, 405, "POST only");
    assert_json_error(&post("{".into()).await, 400, "bad json");
    assert_json_error(&post("{\"blockHash\":\"00\"}".into()).await, 400, "bad hex field lengths");
    let mut unknown = receipt(&keys[0], 500, root);
    unknown = unknown.replace(&hex::encode(hash), &hex::encode(B256::repeat_byte(1)));
    assert_json_error(&post(unknown).await, 404, "mobileverify: unknown block");
    assert_json_error(
        &post(receipt(&keys[0], 501, root)).await,
        403,
        "mobileverify: receipt is for a different block: receipt number 501, block is 500",
    );
    assert_json_error(&post(receipt(&pending, 500, root)).await, 403, "mobileverify: verifier not registered");
    let mut forged = receipt(&keys[0], 500, root);
    forged = forged.replace(&hex::encode(root), &hex::encode(other));
    assert_json_error(&post(forged).await, 403, "mobileverify: invalid receipt signature");

    let idx0 = f.registry.lookup(&keys[0].pubkey()).unwrap();
    let r = post(receipt(&keys[0], 500, root)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), format!("{{\"index\":{idx0}}}\n"));
    post(receipt(&keys[1], 500, root)).await;
    post(receipt(&keys[2], 500, other)).await;

    let r = request(f.addr, "GET", "/mobileverify/health", b"").await;
    assert_eq!(
        r.text(),
        format!(
            "{{\"accumulator\":\"0x{}\",\"alarms\":0,\"certBlocks\":0,\"openWindows\":1,\"pending\":1,\"registry\":3}}\n",
            hex::encode(f.registry.root())
        )
    );
    let cert_path = format!("/mobileverify/cert/{}", hex::encode(hash));
    assert_json_error(&request(f.addr, "GET", &cert_path, b"").await, 404, "no certificates for block");

    f.coordinator.on_block_committed(501);
    assert_json_error(&post(receipt(&keys[0], 500, root)).await, 403, "mobileverify: collection window closed");
    f.coordinator.on_block_committed(505);

    let r = request(f.addr, "GET", &cert_path, b"").await;
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["signers"], 2);
    assert_eq!(arr[0]["receiptsRoot"], format!("0x{}", hex::encode(root)));
    assert!(r.text().starts_with(&format!("[{{\"blockHash\":\"0x{}\",\"blockNumber\":500,", hex::encode(hash))));
    assert!(r.text().ends_with("}]\n"));

    let r = request(f.addr, "GET", "/mobileverify/alarms", b"").await;
    assert_eq!(f.alarms.len(), 1);
    let at = f.alarms.recent(1)[0].at_ms;
    assert_eq!(
        r.text(),
        format!("[{{\"blockHash\":\"0x{}\",\"blockNumber\":500,\"cohorts\":2,\"atMs\":{at}}}]\n", hex::encode(hash))
    );
    let r = request(f.addr, "POST", "/mobileverify/alarms", b"").await;
    assert_json_error(&r, 405, "GET only");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_magnet_and_unknown() {
    let f = start(ServiceConfig::default()).await;
    let r = request(f.addr, "GET", "/mobileverify/alarms", b"").await;
    assert_eq!(r.text(), "[]\n");
    let k = DeviceKey::from_ikm(&[5; 32]).unwrap();
    f.registry.register(&k.pubkey(), &k.proof_of_possession()).unwrap();
    f.registry.commit_epoch();
    let r = request(f.addr, "GET", "/mobileverify/snapshot", b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-mobileverify-root"), Some(format!("0x{}", hex::encode(f.registry.root())).as_str()));
    assert_eq!(r.body, f.registry.export_committed());

    let r = request(f.addr, "GET", &format!("/mobileverify/magnet/{}", hex::encode([1u8; 32])), b"").await;
    assert_json_error(&r, 404, "packet not seeded");
    let r = request(f.addr, "GET", "/nope", b"").await;
    assert_eq!(r.status, 404);
    assert_eq!(r.text(), "404 page not found\n");
    assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
    let r = request(f.addr, "DELETE", "/mobileverify/health", b"").await;
    assert_eq!(r.status, 200);
}

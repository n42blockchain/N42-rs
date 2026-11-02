// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's phone-facing HTTP surface (`internal/mobileverify/httpserver.go`)
//! on hyper 1.x.
//!
//! | route | method | success | errors |
//! |---|---|---|---|
//! | `/mobileverify/register` | POST | `{"committed":b,"index":N}` | 405, 429, 400, 428, 403 |
//! | `/mobileverify/packet/<hash>` | GET | raw packet, immutable | 405, 400, 404 |
//! | `/mobileverify/packet` | PUT (loopback) | `{"hash","new","number"}` | 403, 413, 400 |
//! | `/mobileverify/receipt` | POST | `{"index":N}` | 405, 400, 404, 403 |
//! | `/mobileverify/cert/<hash>` | GET | `[cert]` | 405, 400, 404 |
//! | `/mobileverify/magnet/<hash>` | GET | — (no torrent seeding) | 405, 400, 404 |
//! | `/mobileverify/alarms` | GET | `[alarm]`, newest first, ≤ 100 | 405 |
//! | `/mobileverify/snapshot` | GET | committed-set snapshot | 405 |
//! | `/mobileverify/health` | any | counters | — |
//! | `/mobileverify/latest` | GET | `{"hash","number","packet"}` | 405, 503 |
//!
//! Every error body is `{"error":"<msg>"}\n` with `Content-Type:
//! application/json`; success JSON is Go's encoder output (sorted map keys,
//! trailing newline). The register rate limit (10 per minute per IP, one
//! fixed window for all IPs, counted before the body is read) and the body
//! limits (4 KiB register, 8 KiB receipt) are gov5's. Unknown paths get Go's
//! plain-text 404, and a subtree root without its slash Go's 301.
//!
//! Departures from gov5, all on overload or abuse:
//!
//! - **`503 {"error":"busy"}`** (new): registration (the proof-of-possession
//!   pairing) and receipt intake (the signature pairing) run on tokio's
//!   blocking pool behind a semaphore of [`ServiceConfig::blocking_limit`]
//!   permits, so a flood cannot occupy the runtime's workers. A request that
//!   waits longer than [`ServiceConfig::blocking_wait`] for a permit gets
//!   `503` with the usual JSON error body `{"error":"busy"}\n`; a client may
//!   retry it. gov5 runs this work in unbounded goroutines and never answers
//!   `busy`.
//! - At most [`ServiceConfig::max_connections`] connections are served at
//!   once; further ones wait in the listen backlog (Go's `LimitListener`
//!   shape; gov5 sets no cap). A failing `accept` backs off 5 ms doubling to
//!   1 s, as `net/http` does.
//!
//! Timeouts are Go's, kept apart per connection by an IO wrapper (hyper's
//! own `header_read_timeout` also bounds keep-alive idle time, which would
//! close a pooled connection the phone reuses for its receipt): 15 s idle
//! before a request's first byte, 5 s from it to the end of the headers,
//! 15 s for the body, and a 15 s write deadline from the end of the headers
//! to the end of the response (`WriteTimeout`).
//!
//! Not reproduced: the device attestor (never wired in production), Go's
//! path cleaning and percent-decoding.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Body;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, LOCATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, warn};

use crate::cert::CertStore;
use crate::cohort::{ALARMS_SERVED, AlarmBuffer, CohortCoordinator, HeadSource};
use crate::deadline_io::{DeadlineIo, Deadlines};
use crate::error::MobileVerifyError;
use crate::gojson::{self, Obj};
use crate::packet::{PacketCache, validate_packet_bytes};
use crate::pow::{MAX_POW_BITS, verify_pow};
use crate::receipt::{ReceiptRequestError, parse_receipt_request};
use crate::registry::Registry;

/// The register body limit.
pub const REGISTER_BODY_LIMIT: usize = 4 << 10;
/// The receipt body limit.
pub const RECEIPT_BODY_LIMIT: usize = 8 << 10;
/// The default limit on a loopback-ingested packet (the Go client's read cap).
pub const DEFAULT_INGEST_LIMIT: usize = 256 << 20;
/// `ReadHeaderTimeout`.
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// `ReadTimeout`, applied to reading the body.
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// `MaxHeaderBytes`.
pub const MAX_HEADER_BYTES: usize = 16 << 10;
/// Graceful-stop budget.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// The keep-alive idle timeout (gov5's effective `IdleTimeout`, its
/// `ReadTimeout`).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// `WriteTimeout`: from the end of a request's headers to the end of its
/// response.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// Default number of pairings run at once on the blocking pool.
pub const DEFAULT_BLOCKING_LIMIT: usize = 4;
/// Default wait for a blocking-pool permit before answering `busy`.
pub const DEFAULT_BLOCKING_WAIT: Duration = Duration::from_secs(2);
/// Default cap on connections served at once.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// First and last delay after a failed `accept` (`net/http`'s).
const ACCEPT_BACKOFF: (Duration, Duration) = (Duration::from_millis(5), Duration::from_secs(1));

const JSON: &str = "application/json";
const OCTETS: &str = "application/octet-stream";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const NO_STORE: &str = "no-store";

/// The HTTP response type.
pub type HttpResponse = Response<Full<Bytes>>;

/// Server settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Registration proof-of-work difficulty (0 disables), capped at 32.
    pub pow_bits: u32,
    /// Registrations per IP per window.
    pub register_limit: u32,
    /// The rate-limit window.
    pub register_window: Duration,
    /// The largest packet `PUT /mobileverify/packet` takes.
    pub ingest_limit: usize,
    /// Registrations and receipts verified at once on the blocking pool
    /// (at least 1).
    pub blocking_limit: usize,
    /// How long a request waits for a blocking-pool permit before `503 busy`.
    pub blocking_wait: Duration,
    /// Connections served at once (at least 1); more wait in the backlog.
    pub max_connections: usize,
    /// From a request's first byte to the end of its headers.
    pub read_header_timeout: Duration,
    /// Between requests on a keep-alive connection.
    pub idle_timeout: Duration,
    /// From the end of a request's headers to the end of its response.
    pub write_timeout: Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            pow_bits: 0,
            register_limit: 10,
            register_window: Duration::from_secs(60),
            ingest_limit: DEFAULT_INGEST_LIMIT,
            blocking_limit: DEFAULT_BLOCKING_LIMIT,
            blocking_wait: DEFAULT_BLOCKING_WAIT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_header_timeout: READ_HEADER_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
        }
    }
}

/// gov5's fixed-window per-IP counter: one window start for every IP, the
/// whole map cleared when it expires; denied attempts count too.
#[derive(Debug)]
struct RateLimiter {
    limit: u32,
    window: Duration,
    start: Instant,
    counts: HashMap<String, u32>,
}

impl RateLimiter {
    fn allow(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        if now.duration_since(self.start) > self.window {
            self.start = now;
            self.counts.clear();
        }
        let c = self.counts.entry(ip.to_string()).or_insert(0);
        *c = c.saturating_add(1);
        *c <= self.limit
    }
}

/// The surface's state: everything a handler reads.
pub struct Service {
    registry: Arc<Registry>,
    packets: Arc<PacketCache>,
    coordinator: Arc<CohortCoordinator>,
    certs: Arc<CertStore>,
    alarms: Arc<AlarmBuffer>,
    head: Arc<dyn HeadSource>,
    cfg: ServiceConfig,
    rate: Mutex<RateLimiter>,
    /// Permits for pairings on the blocking pool.
    blocking: Arc<Semaphore>,
}

/// No blocking-pool permit came free in time.
#[derive(Debug)]
struct Busy;

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

impl Service {
    /// Builds the service.
    pub fn new(
        registry: Arc<Registry>,
        packets: Arc<PacketCache>,
        coordinator: Arc<CohortCoordinator>,
        certs: Arc<CertStore>,
        alarms: Arc<AlarmBuffer>,
        head: Arc<dyn HeadSource>,
        mut cfg: ServiceConfig,
    ) -> Self {
        cfg.pow_bits = cfg.pow_bits.min(MAX_POW_BITS);
        cfg.blocking_limit = cfg.blocking_limit.clamp(1, Semaphore::MAX_PERMITS);
        cfg.max_connections = cfg.max_connections.clamp(1, Semaphore::MAX_PERMITS);
        let rate = RateLimiter {
            limit: cfg.register_limit,
            window: cfg.register_window,
            start: Instant::now(),
            counts: HashMap::new(),
        };
        let blocking = Arc::new(Semaphore::new(cfg.blocking_limit));
        Self { registry, packets, coordinator, certs, alarms, head, cfg, rate: Mutex::new(rate), blocking }
    }

    /// Runs CPU-bound `f` on the blocking pool once a permit is free, or
    /// gives up after [`ServiceConfig::blocking_wait`].
    async fn blocking<T, F>(&self, f: F) -> Result<T, Busy>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = match tokio::time::timeout(self.cfg.blocking_wait, self.blocking.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            _ => return Err(Busy),
        };
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        });
        match task.await {
            Ok(v) => Ok(v),
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(_) => Err(Busy),
        }
    }

    /// Answers one request from `peer`.
    pub async fn handle<B>(&self, req: Request<B>, peer: SocketAddr) -> HttpResponse
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let path = req.uri().path().to_string();
        match path.as_str() {
            "/mobileverify/register" => self.register(req, peer).await,
            "/mobileverify/receipt" => self.receipt(req).await,
            "/mobileverify/latest" => self.latest(req.method()),
            "/mobileverify/health" => self.health(),
            "/mobileverify/alarms" => self.alarms(req.method()),
            "/mobileverify/snapshot" => self.snapshot(req.method()),
            "/mobileverify/packet" if req.method() == Method::PUT => self.ingest(req, peer).await,
            "/mobileverify/packet" | "/mobileverify/cert" | "/mobileverify/magnet" => {
                redirect(&format!("{path}/"), req.uri().query())
            }
            p => {
                if let Some(rest) = p.strip_prefix("/mobileverify/packet/") {
                    self.packet(req.method(), rest)
                } else if let Some(rest) = p.strip_prefix("/mobileverify/cert/") {
                    self.cert(req.method(), rest)
                } else if let Some(rest) = p.strip_prefix("/mobileverify/magnet/") {
                    magnet(req.method(), rest)
                } else {
                    not_found()
                }
            }
        }
    }

    async fn register<B>(&self, req: Request<B>, peer: SocketAddr) -> HttpResponse
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if req.method() != Method::POST {
            return error(StatusCode::METHOD_NOT_ALLOWED, "POST only");
        }
        if !self.rate.lock().allow(&peer.ip().to_string()) {
            return error(StatusCode::TOO_MANY_REQUESTS, "registration rate limit");
        }
        let Some(body) = read_body(req.into_body(), REGISTER_BODY_LIMIT).await else {
            return error(StatusCode::BAD_REQUEST, "bad json");
        };
        let fields = (|| {
            let obj = gojson::decode_object(&body)?;
            let o = obj.as_ref();
            Ok::<_, gojson::BadJson>((
                gojson::get_string(o, "pubkey")?,
                gojson::get_string(o, "pop")?,
                gojson::get_string(o, "pow_nonce")?,
                gojson::get_string(o, "attestation")?,
            ))
        })();
        let Ok((pubkey, pop, pow_nonce, _attestation)) = fields else {
            return error(StatusCode::BAD_REQUEST, "bad json");
        };
        let (Some(pubkey), Some(pop)) = (gojson::hex_into::<48>(&pubkey), gojson::hex_into::<96>(&pop)) else {
            return error(StatusCode::BAD_REQUEST, "pubkey must be 48 hex bytes, pop 96");
        };
        if self.cfg.pow_bits > 0 {
            let solved = parse_go_uint(&pow_nonce).is_some_and(|n| verify_pow(&pubkey, n, self.cfg.pow_bits));
            if !solved {
                let body = gojson::line(
                    Obj::new().str("error", &MobileVerifyError::PowRequired.to_string()).num("pow_bits", u64::from(self.cfg.pow_bits)),
                );
                return respond(StatusCode::PRECONDITION_REQUIRED, JSON, body.into(), &[]);
            }
        }
        let registry = self.registry.clone();
        match self.blocking(move || registry.register(&pubkey, &pop)).await {
            Ok(Ok((index, committed))) => {
                ok_json(gojson::line(Obj::new().bool("committed", committed).num("index", u64::from(index))), &[])
            }
            Ok(Err(e)) => error(StatusCode::FORBIDDEN, &e.to_string()),
            Err(Busy) => busy(),
        }
    }

    async fn receipt<B>(&self, req: Request<B>) -> HttpResponse
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if req.method() != Method::POST {
            return error(StatusCode::METHOD_NOT_ALLOWED, "POST only");
        }
        let Some(body) = read_body(req.into_body(), RECEIPT_BODY_LIMIT).await else {
            return error(StatusCode::BAD_REQUEST, "bad json");
        };
        let receipt = match parse_receipt_request(&body) {
            Ok(r) => r,
            Err(e @ (ReceiptRequestError::BadJson | ReceiptRequestError::BadHex)) => {
                return error(StatusCode::BAD_REQUEST, &e.to_string());
            }
        };
        let coordinator = self.coordinator.clone();
        match self.blocking(move || coordinator.submit(&receipt)).await {
            Ok(Ok(index)) => ok_json(gojson::line(Obj::new().num("index", u64::from(index))), &[]),
            Ok(Err(e @ MobileVerifyError::UnknownBlock)) => error(StatusCode::NOT_FOUND, &e.to_string()),
            Ok(Err(e)) => error(StatusCode::FORBIDDEN, &e.to_string()),
            Err(Busy) => busy(),
        }
    }

    fn packet(&self, method: &Method, rest: &str) -> HttpResponse {
        if method != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
        }
        let Some(hash) = hash_from_path(rest) else {
            return error(StatusCode::BAD_REQUEST, "bad block hash");
        };
        match self.packets.get(&hash) {
            Some(data) => respond(StatusCode::OK, OCTETS, data, &[(CACHE_CONTROL, IMMUTABLE)]),
            None => error(StatusCode::NOT_FOUND, "packet not in window"),
        }
    }

    fn cert(&self, method: &Method, rest: &str) -> HttpResponse {
        if method != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
        }
        let Some(hash) = hash_from_path(rest) else {
            return error(StatusCode::BAD_REQUEST, "bad block hash");
        };
        let certs = self.certs.get(&hash);
        if certs.is_empty() {
            return error(StatusCode::NOT_FOUND, "no certificates for block");
        }
        let bound = self.registry.index_bound();
        ok_json(gojson::array_line(certs.iter().map(|c| c.to_json(bound))), &[])
    }

    fn alarms(&self, method: &Method) -> HttpResponse {
        if method != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
        }
        ok_json(gojson::array_line(self.alarms.recent(ALARMS_SERVED).iter().map(|a| a.to_json())), &[])
    }

    fn snapshot(&self, method: &Method) -> HttpResponse {
        if method != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
        }
        let blob = self.registry.export_committed();
        let root = gojson::hex0x(self.registry.root().as_slice());
        let mut resp = respond(StatusCode::OK, OCTETS, blob.into(), &[(CACHE_CONTROL, NO_STORE)]);
        if let Ok(v) = HeaderValue::from_str(&root) {
            resp.headers_mut().insert("X-Mobileverify-Root", v);
        }
        resp
    }

    fn health(&self) -> HttpResponse {
        let body = Obj::new()
            .str("accumulator", &gojson::hex0x(self.registry.root().as_slice()))
            .num("alarms", self.alarms.len() as u64)
            .num("certBlocks", self.certs.len() as u64)
            .num("openWindows", self.coordinator.open_windows() as u64)
            .num("pending", self.registry.pending_count() as u64)
            .num("registry", self.registry.count() as u64);
        ok_json(gojson::line(body), &[])
    }

    fn latest(&self, method: &Method) -> HttpResponse {
        if method != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
        }
        let Some((number, hash)) = self.head.head() else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "head not available");
        };
        let body = Obj::new()
            .str("hash", &gojson::hex0x(hash.as_slice()))
            .num("number", number)
            .bool("packet", self.packets.has(&hash));
        ok_json(gojson::line(body), &[(CACHE_CONTROL, NO_STORE)])
    }

    /// `PUT /mobileverify/packet` (new, loopback only): a packet built by the
    /// sidecar. It must decode and its header hash to its block hash.
    async fn ingest<B>(&self, req: Request<B>, peer: SocketAddr) -> HttpResponse
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if !peer.ip().to_canonical().is_loopback() {
            return error(StatusCode::FORBIDDEN, "loopback only");
        }
        let Some(body) = read_body(req.into_body(), self.cfg.ingest_limit).await else {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "packet body unreadable or too large");
        };
        match validate_packet_bytes(&body) {
            Ok((hash, number)) => {
                let new = self.packets.put(hash, number, body);
                debug!(target: "mobileverify", %hash, number, new, "ingested packet");
                ok_json(
                    gojson::line(Obj::new().str("hash", &gojson::hex0x(hash.as_slice())).bool("new", new).num("number", number)),
                    &[],
                )
            }
            Err(e) => error(StatusCode::BAD_REQUEST, &e.to_string()),
        }
    }
}

fn magnet(method: &Method, rest: &str) -> HttpResponse {
    if method != Method::GET {
        return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
    }
    if hash_from_path(rest).is_none() {
        return error(StatusCode::BAD_REQUEST, "bad block hash");
    }
    error(StatusCode::NOT_FOUND, "packet not seeded")
}

/// Go `strconv.ParseUint(s, 10, 64)`: ASCII digits only, no sign.
fn parse_go_uint(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// gov5 `hashFromPath` on the part after the prefix.
fn hash_from_path(rest: &str) -> Option<B256> {
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    gojson::hex_into::<32>(rest).map(B256::from)
}

async fn read_body<B>(body: B, limit: usize) -> Option<Bytes>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let collected = tokio::time::timeout(READ_TIMEOUT, Limited::new(body, limit).collect()).await.ok()?;
    collected.ok().map(|c| c.to_bytes())
}

fn respond(status: StatusCode, content_type: &str, body: Bytes, extra: &[(hyper::header::HeaderName, &str)]) -> HttpResponse {
    let mut resp = Response::new(Full::new(body));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(CONTENT_TYPE, v);
    }
    for (k, v) in extra {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(k.clone(), v);
        }
    }
    resp
}

fn ok_json(body: String, extra: &[(hyper::header::HeaderName, &str)]) -> HttpResponse {
    respond(StatusCode::OK, JSON, body.into(), extra)
}

/// gov5 `httpError`.
fn error(status: StatusCode, msg: &str) -> HttpResponse {
    respond(status, JSON, gojson::error_body(msg).into(), &[])
}

/// The overflow answer of the blocking pool (new; see the module docs).
fn busy() -> HttpResponse {
    error(StatusCode::SERVICE_UNAVAILABLE, "busy")
}

/// Go `http.NotFound`.
fn not_found() -> HttpResponse {
    respond(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        Bytes::from_static(b"404 page not found\n"),
        &[(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
    )
}

/// Go `ServeMux`'s redirect of a subtree root requested without its slash.
fn redirect(to: &str, query: Option<&str>) -> HttpResponse {
    let target = match query {
        Some(q) => format!("{to}?{q}"),
        None => to.to_string(),
    };
    let body = format!("<a href=\"{target}\">Moved Permanently</a>.\n\n");
    respond(StatusCode::MOVED_PERMANENTLY, "text/html; charset=utf-8", body.into(), &[(LOCATION, &target)])
}

/// The delay before the next `accept` after `prev` (zero: none yet).
fn next_backoff(prev: Duration) -> Duration {
    if prev.is_zero() { ACCEPT_BACKOFF.0 } else { (prev * 2).min(ACCEPT_BACKOFF.1) }
}

/// Waits out `backoff`, then a connection slot, then one connection.
async fn accept_one(
    listener: &TcpListener,
    slots: &Arc<Semaphore>,
    backoff: Duration,
) -> Option<(std::io::Result<(TcpStream, SocketAddr)>, OwnedSemaphorePermit)> {
    if !backoff.is_zero() {
        tokio::time::sleep(backoff).await;
    }
    let permit = slots.clone().acquire_owned().await.ok()?;
    Some((listener.accept().await, permit))
}

/// Serves `listener` until `shutdown` resolves, then gives open connections
/// [`SHUTDOWN_GRACE`] to finish. At most [`ServiceConfig::max_connections`]
/// are served at once.
pub async fn serve<F>(listener: TcpListener, service: Arc<Service>, shutdown: F)
where
    F: Future<Output = ()>,
{
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut conns = tokio::task::JoinSet::new();
    let slots = Arc::new(Semaphore::new(service.cfg.max_connections));
    let deadlines = Deadlines {
        idle: service.cfg.idle_timeout,
        header: service.cfg.read_header_timeout,
        write: service.cfg.write_timeout,
    };
    let mut backoff = Duration::ZERO;
    tokio::pin!(shutdown);
    loop {
        while conns.try_join_next().is_some() {}
        let (accepted, permit) = tokio::select! {
            () = &mut shutdown => break,
            next = accept_one(&listener, &slots, backoff) => match next {
                Some(x) => x,
                None => break,
            },
        };
        let (stream, peer) = match accepted {
            Ok(x) => {
                backoff = Duration::ZERO;
                x
            }
            Err(e) => {
                backoff = next_backoff(backoff);
                warn!(target: "mobileverify", err = %e, retry_in = ?backoff, "accept failed");
                continue;
            }
        };
        let svc = service.clone();
        let mut stop = stop_rx.clone();
        conns.spawn(async move {
            let _permit = permit;
            let handler = service_fn(move |req| {
                let svc = svc.clone();
                async move { Ok::<_, Infallible>(svc.handle(req, peer).await) }
            });
            let mut builder = http1::Builder::new();
            // The header deadline lives in DeadlineIo: hyper's would also
            // cut keep-alive idle time to it.
            builder.timer(TokioTimer::new()).header_read_timeout(None).max_buf_size(MAX_HEADER_BYTES);
            let conn = builder.serve_connection(TokioIo::new(DeadlineIo::new(stream, deadlines)), handler);
            tokio::pin!(conn);
            tokio::select! {
                res = conn.as_mut() => {
                    if let Err(e) = res {
                        debug!(target: "mobileverify", %peer, err = %e, "connection ended");
                    }
                }
                _ = stop.changed() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
            }
        });
    }
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, async { while conns.join_next().await.is_some() {} }).await;
    conns.abort_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_uint_and_hash_path() {
        assert_eq!(parse_go_uint("42"), Some(42));
        assert_eq!(parse_go_uint("+42"), None);
        assert_eq!(parse_go_uint(""), None);
        assert_eq!(parse_go_uint("18446744073709551616"), None);
        let h = "ab".repeat(32);
        assert_eq!(hash_from_path(&h), Some(B256::repeat_byte(0xab)));
        assert_eq!(hash_from_path(&format!("0x{h}")), Some(B256::repeat_byte(0xab)));
        assert_eq!(hash_from_path(&format!("{h}/x")), None);
        assert_eq!(hash_from_path(""), None);
        assert_eq!(hash_from_path("abcd"), None);
    }

    #[test]
    fn accept_backoff_doubles_to_one_second() {
        let mut d = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..10 {
            d = next_backoff(d);
            seen.push(d.as_millis());
        }
        assert_eq!(seen, vec![5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
    }

    struct NoChain;
    impl HeadSource for NoChain {
        fn head(&self) -> Option<(u64, B256)> {
            None
        }
        fn number_of(&self, _: &B256) -> Option<u64> {
            None
        }
    }

    fn service(cfg: ServiceConfig) -> Service {
        let registry = Arc::new(Registry::new());
        let certs = Arc::new(CertStore::new(16));
        let head: Arc<dyn HeadSource> = Arc::new(NoChain);
        let coordinator =
            Arc::new(CohortCoordinator::new(registry.clone(), head.clone(), certs.clone(), Default::default()));
        Service::new(registry, Arc::new(PacketCache::new(16)), coordinator, certs, Arc::default(), head, cfg)
    }

    async fn post(svc: &Service, path: &str, body: &str) -> (StatusCode, Bytes) {
        let req = Request::post(path).body(Full::new(Bytes::from(body.to_string()))).unwrap();
        let resp = svc.handle(req, "127.0.0.1:1".parse().unwrap()).await;
        (resp.status(), resp.into_body().collect().await.unwrap().to_bytes())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairings_overflow_to_busy() {
        let svc = service(ServiceConfig {
            blocking_limit: 2,
            blocking_wait: Duration::from_millis(50),
            ..ServiceConfig::default()
        });
        let k = crate::keys::DeviceKey::from_ikm(&[1; 32]).unwrap();
        let reg_body = format!(
            "{{\"pubkey\":\"{}\",\"pop\":\"{}\"}}",
            hex::encode(k.pubkey()),
            hex::encode(k.proof_of_possession())
        );
        let receipt = crate::receipt::Receipt {
            block_hash: B256::repeat_byte(1),
            block_number: 1,
            computed_receipts_root: B256::ZERO,
            verifier_pubkey: k.pubkey(),
            signature: k.sign_receipt(B256::repeat_byte(1), 1, B256::ZERO),
            timestamp_ms: 0,
        }
        .to_request_json();

        // Every permit taken: both pairing routes answer busy.
        let held = svc.blocking.clone().acquire_many_owned(2).await.unwrap();
        let busy_body = Bytes::from_static(b"{\"error\":\"busy\"}\n");
        assert_eq!(post(&svc, "/mobileverify/register", &reg_body).await, (StatusCode::SERVICE_UNAVAILABLE, busy_body.clone()));
        assert_eq!(post(&svc, "/mobileverify/receipt", &receipt).await, (StatusCode::SERVICE_UNAVAILABLE, busy_body));
        drop(held);

        // Freed: they run (on the blocking pool) and answer as before.
        let (status, body) = post(&svc, "/mobileverify/register", &reg_body).await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"{\"committed\":false,\"index\":0}\n"[..]));
        let (status, body) = post(&svc, "/mobileverify/receipt", &receipt).await;
        assert_eq!((status, &body[..]), (StatusCode::NOT_FOUND, &b"{\"error\":\"mobileverify: unknown block\"}\n"[..]));
        assert_eq!(svc.blocking.available_permits(), 2);
    }

    #[test]
    fn rate_limiter_fixed_window() {
        let mut r = RateLimiter { limit: 2, window: Duration::from_secs(60), start: Instant::now(), counts: HashMap::new() };
        assert!(r.allow("a"));
        assert!(r.allow("a"));
        assert!(!r.allow("a"));
        assert!(r.allow("b"));
        r.start = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
        assert!(r.allow("a"));
    }
}

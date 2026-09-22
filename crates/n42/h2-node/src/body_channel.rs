// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block bodies between members over plain TCP.
//!
//! The libp2p push hands a 19 MB body to each member over a Noise-encrypted
//! yamux stream, written and read from the swarm, which this fleet polls on
//! its consensus loop. Measured at the 163,000-transaction tier as 250-300 ms
//! from the leader finishing the body to a member holding it -- about
//! 50 MB/s across loopback, three orders of magnitude under the wire.
//!
//! This is the same bytes over a socket of their own: one persistent
//! connection per peer, a length-prefixed frame per body, written by a task
//! per peer and read by a task per connection, so neither end's consensus
//! loop touches the transfer. A body is self-authenticating -- the receiver
//! decodes it and files it under the hash of the header it decodes to, as it
//! does for a pushed or gossiped one -- so the channel carries nothing a
//! peer could not already send, and needs no handshake. It is for a static
//! fleet on one host or one LAN; a member it cannot reach still gets the
//! libp2p push.
//!
//! ```text
//! greeting := "N42P", u8 version, u32 features   (receiver -> sender, once)
//! frame    := u32 len (little-endian), len bytes of gov5 block RLP
//!           | u32 0xffffffff, u32 len, len bytes of compact body
//!           | u32 0xfffffffe, u32 len, len bytes of the sender's peer id
//! ```
//!
//! The sender names itself once per connection, before its first body. A
//! receiver that takes a *compact* body has to ask someone for the
//! transactions it does not hold, and the one member certain to have them is
//! the one that built the block -- which is the member that pushed it here.
//! Without this the receiver could only guess among its peers, and loop196
//! measured what guessing costs: 229-331 refusals a leg against 13-46 fills
//! that worked, each refusal then asking every peer for the whole 26 MB
//! body.
//!
//! The greeting is what makes the compact body (`N42_COMPACT_BODY`) safe in
//! a mixed fleet. It goes the other way down the same connection, which
//! carried nothing in that direction before: a sender that predates it
//! ignores the nine bytes, and a receiver that predates it sends none, so
//! the sender's read times out and it offers that peer the whole body as it
//! always did. Nothing is ever sent in a shape the other end did not say it
//! reads.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How many received buffers the listener keeps for reuse. A body is 13-15
/// MB at the bench tier; a fresh `Vec` per block meant the kernel zeroed and
/// mapped ~3,800 pages for every block on every follower, and those first
/// touches were most of the runtime threads' page faults in round gate5.
const POOLED_BUFFERS: usize = 8;

/// Buffers handed out by [`listen`] and returned when a [`BodyBuf`] drops.
#[derive(Debug, Default)]
pub struct BufPool {
    free: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl BufPool {
    fn take(&self) -> Vec<u8> {
        self.free.lock().unwrap_or_else(|p| p.into_inner()).pop().unwrap_or_default()
    }

    fn give(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut free = self.free.lock().unwrap_or_else(|p| p.into_inner());
        if free.len() < POOLED_BUFFERS {
            free.push(buf);
        }
    }
}

/// A block body's bytes. From the channel they sit in a pooled buffer that
/// goes back to the pool when this drops; from anywhere else they are a
/// plain `Vec`. Dereferences to the bytes.
#[derive(Debug)]
pub struct BodyBuf {
    buf: Vec<u8>,
    pool: Option<Arc<BufPool>>,
    /// A body that arrived as shared bytes (a pushed or fetched chunk) is
    /// kept as those bytes, not copied into `buf`.
    shared: Option<alloy_primitives::Bytes>,
    /// Whether these bytes are a compact body rather than a gov5 one. Only
    /// the channel ever sets it; everything else builds full bodies.
    compact: bool,
    /// The peer that pushed it, when it named itself. For a block's body
    /// that is the member that built it, which is the one member certain to
    /// hold every transaction of it.
    from: Option<Arc<str>>,
}

/// What the greeting starts with, so a stray connection is not read as one.
const GREETING_MAGIC: [u8; 4] = *b"N42P";

/// The greeting's version. A sender that does not know it reads no
/// features and offers whole bodies.
const GREETING_VERSION: u8 = 1;

/// Feature bit 0: this receiver reads compact bodies.
const FEATURE_COMPACT: u32 = 1;

/// The length field that says "a compact body follows" instead of a length.
/// Out of range for a real one -- [`MAX_BODY_BYTES`] is 256 MB -- and only
/// ever written to a peer whose greeting asked for it.
const COMPACT_MARKER: u32 = u32::MAX;

/// The length field that says "the sender's peer id follows". Written once
/// per connection, before the first body; a sender that predates it writes
/// none and its bodies simply arrive unattributed.
const HELLO_MARKER: u32 = u32::MAX - 1;

/// Longest peer id accepted, so a stray connection cannot make this node
/// allocate on a whim. A libp2p peer id is ~50 bytes as text.
const MAX_PEER_ID_BYTES: u32 = 256;

/// How long a sender waits for a receiver's greeting before deciding it has
/// none. Paid once per connection, and only against a peer that predates
/// the greeting; the channel is a LAN or one host.
const GREETING_WAIT: std::time::Duration = std::time::Duration::from_millis(200);

/// One body offered to the peers: the gov5 body every peer can read, and
/// the compact form for the peers that said they read it.
#[derive(Clone, Debug)]
pub struct OfferedBody {
    /// The gov5 body, `[header, transactions, verifiers, rewards]`.
    pub full: alloy_primitives::Bytes,
    /// The same block with its transactions named by hash, when this node
    /// built one.
    pub compact: Option<alloy_primitives::Bytes>,
}

impl BodyBuf {
    /// The bytes as an owned `Vec`, copied.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// The bytes as shared bytes: a refcount when they already are some
    /// (every body that arrived on this channel or over libp2p), a copy
    /// only for one that lives in a pooled buffer. Serving a peer used to
    /// copy 26 MB on the consensus loop for every request.
    pub fn to_shared(&self) -> alloy_primitives::Bytes {
        match &self.shared {
            Some(bytes) => bytes.clone(),
            None => alloy_primitives::Bytes::copy_from_slice(&self.buf),
        }
    }

    /// Whether these bytes are a compact body.
    pub const fn is_compact(&self) -> bool {
        self.compact
    }

    /// The peer that pushed it, as it named itself; `None` from any source
    /// but the channel, and from a sender that does not name itself.
    pub fn from(&self) -> Option<&str> {
        self.from.as_deref()
    }

    fn as_slice(&self) -> &[u8] {
        match &self.shared {
            Some(bytes) => bytes,
            None => &self.buf,
        }
    }
}

impl std::ops::Deref for BodyBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for BodyBuf {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, pool: None, shared: None, compact: false, from: None }
    }
}

impl From<alloy_primitives::Bytes> for BodyBuf {
    fn from(bytes: alloy_primitives::Bytes) -> Self {
        Self { buf: Vec::new(), pool: None, shared: Some(bytes), compact: false, from: None }
    }
}

impl Drop for BodyBuf {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.give(std::mem::take(&mut self.buf));
        }
    }
}

/// Largest body accepted, so a stray connection cannot make this node
/// allocate without bound.
const MAX_BODY_BYTES: u32 = 256 << 20;

/// Frames a peer may have queued before the leader stops offering it more.
const PER_PEER_QUEUE: usize = 4;

/// Listens on `addr` and hands every body received to `sink`.
///
/// Returns once bound; the accept loop runs on its own task. A body is
/// delivered as the bytes that arrived, for the same decode a pushed body
/// gets.
pub async fn listen(addr: SocketAddr, sink: mpsc::Sender<BodyBuf>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(target: "n42.h2.node", %addr, "body channel listening");
    let pool = Arc::new(BufPool::default());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    warn!(target: "n42.h2.node", %err, "body channel accept failed");
                    continue;
                }
            };
            let sink = sink.clone();
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                if let Err(err) = receive(stream, sink, pool).await {
                    debug!(target: "n42.h2.node", %peer, %err, "body channel connection ended");
                }
            });
        }
    });
    Ok(())
}

async fn receive(mut stream: TcpStream, sink: mpsc::Sender<BodyBuf>, pool: Arc<BufPool>) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    // What this node reads, said before anything is asked of it. A sender
    // that does not read it is unaffected: it never read this direction.
    let features = if n42_h2_execution::compact_body() { FEATURE_COMPACT } else { 0 };
    let mut greeting = Vec::with_capacity(9);
    greeting.extend_from_slice(&GREETING_MAGIC);
    greeting.push(GREETING_VERSION);
    greeting.extend_from_slice(&features.to_le_bytes());
    stream.write_all(&greeting).await?;
    stream.flush().await?;
    // Whoever is on the other end, once it has said so.
    let mut from: Option<Arc<str>> = None;
    loop {
        let len = match stream.read_u32_le().await {
            Ok(len) => len,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if len == HELLO_MARKER {
            let len = stream.read_u32_le().await?;
            if len == 0 || len > MAX_PEER_ID_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("peer id of {len} bytes"),
                ));
            }
            let mut id = vec![0u8; len as usize];
            stream.read_exact(&mut id).await?;
            match String::from_utf8(id) {
                Ok(id) => {
                    debug!(target: "n42.h2.node", %id, "a body-channel sender named itself");
                    from = Some(Arc::from(id.as_str()));
                }
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "peer id is not text",
                    ))
                }
            }
            continue;
        }
        let compact = len == COMPACT_MARKER;
        let len = if compact { stream.read_u32_le().await? } else { len };
        if len == 0 || len > MAX_BODY_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("body of {len} bytes")));
        }
        let mut body = pool.take();
        body.resize(len as usize, 0);
        stream.read_exact(&mut body).await?;
        let body = BodyBuf {
            buf: body,
            pool: Some(Arc::clone(&pool)),
            shared: None,
            compact,
            from: from.clone(),
        };
        if sink.send(body).await.is_err() {
            return Ok(());
        }
    }
}

/// The leader's side: one queue per peer, drained to that peer's socket by
/// its own task.
#[derive(Debug, Clone)]
pub struct BodyPushers {
    peers: Vec<(SocketAddr, mpsc::Sender<OfferedBody>)>,
    /// What this node calls itself on the channel, once it knows. Shared
    /// with every push task, which sends it on each connection it makes.
    me: Arc<std::sync::OnceLock<String>>,
}

impl BodyPushers {
    /// A pusher per address. Connections are made lazily and remade after
    /// any error, so a member that is down or not yet up costs nothing but
    /// the frames it missed.
    pub fn connect(addrs: Vec<SocketAddr>) -> Self {
        let me: Arc<std::sync::OnceLock<String>> = Arc::new(std::sync::OnceLock::new());
        let peers = addrs
            .into_iter()
            .map(|addr| {
                let (tx, rx) = mpsc::channel(PER_PEER_QUEUE);
                tokio::spawn(push_loop(addr, rx, Arc::clone(&me)));
                (addr, tx)
            })
            .collect();
        Self { peers, me }
    }

    /// Tells the push tasks what to call this node on the channel, so a
    /// receiver knows who pushed a body. Set once, before anything is
    /// pushed; a connection made before it stays unnamed.
    pub fn announce(&self, id: impl Into<String>) {
        let _ = self.me.set(id.into());
    }

    /// How many peers this pushes to.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether there are no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Offers `body` to every peer's queue without waiting. Returns how many
    /// queues took it; a full queue means that peer is behind and gets the
    /// libp2p push instead.
    ///
    /// Both shapes are offered and each peer's own task picks: only that
    /// task knows what its peer greeted with, and the pick therefore
    /// follows the connection rather than a guess made here. Offering both
    /// costs two refcounts, not two copies.
    pub fn push(&self, body: OfferedBody) -> usize {
        self.peers.iter().filter(|(_, tx)| tx.try_send(body.clone()).is_ok()).count()
    }
}

/// Reads a receiver's greeting, or decides it has none.
///
/// A peer that predates the greeting writes nothing in this direction, so
/// the wait is what tells the two apart. Anything unexpected is read as "no
/// features": the whole body always works.
async fn read_greeting(stream: &mut TcpStream) -> u32 {
    let mut greeting = [0u8; 9];
    match tokio::time::timeout(GREETING_WAIT, stream.read_exact(&mut greeting)).await {
        Ok(Ok(_)) if greeting[..4] == GREETING_MAGIC && greeting[4] == GREETING_VERSION => {
            u32::from_le_bytes([greeting[5], greeting[6], greeting[7], greeting[8]])
        }
        _ => 0,
    }
}

async fn push_loop(
    addr: SocketAddr,
    mut rx: mpsc::Receiver<OfferedBody>,
    me: Arc<std::sync::OnceLock<String>>,
) {
    let mut stream: Option<TcpStream> = None;
    let mut features = 0u32;
    while let Some(body) = rx.recv().await {
        if stream.is_none() {
            match tokio::time::timeout(std::time::Duration::from_secs(1), TcpStream::connect(addr)).await {
                Ok(Ok(connected)) => {
                    let _ = connected.set_nodelay(true);
                    let mut connected = connected;
                    // Only a sender that has a compact body to offer needs
                    // to know what the other end reads, so with the flag off
                    // this connection is made and used exactly as it always
                    // was -- no read, and no wait for a peer that greets
                    // with nothing.
                    features = if n42_h2_execution::compact_body() {
                        read_greeting(&mut connected).await
                    } else {
                        0
                    };
                    debug!(target: "n42.h2.node", %addr, features, "body channel connected");
                    // Name this node before the first body: the receiver
                    // needs to know who built the block it is about to get.
                    if let Some(me) = me.get() {
                        let hello = async {
                            connected.write_u32_le(HELLO_MARKER).await?;
                            connected.write_u32_le(me.len() as u32).await?;
                            connected.write_all(me.as_bytes()).await
                        }
                        .await;
                        if let Err(err) = hello {
                            debug!(target: "n42.h2.node", %addr, %err, "body channel: could not name this node");
                            continue;
                        }
                    }
                    stream = Some(connected);
                }
                Ok(Err(err)) => {
                    debug!(target: "n42.h2.node", %addr, %err, "body channel: cannot connect; body not sent this way");
                    continue;
                }
                Err(_) => {
                    debug!(target: "n42.h2.node", %addr, "body channel: connect timed out; body not sent this way");
                    continue;
                }
            }
        }
        let sock = stream.as_mut().expect("connected above");
        let started = std::time::Instant::now();
        // The compact body only to a peer that greeted for it; everyone
        // else gets the bytes they have always been sent.
        let compact = (features & FEATURE_COMPACT != 0).then_some(body.compact.as_ref()).flatten();
        let sent = compact.unwrap_or(&body.full);
        let result = async {
            if compact.is_some() {
                sock.write_u32_le(COMPACT_MARKER).await?;
            }
            sock.write_u32_le(sent.len() as u32).await?;
            sock.write_all(sent).await?;
            sock.flush().await
        }
        .await;
        match result {
            Ok(()) => {
                if sent.len() > 1_000_000 {
                    debug!(target: "n42.h2.node", %addr, bytes = sent.len(), compact = compact.is_some(), ms = started.elapsed().as_millis() as u64, "body sent over the channel");
                }
            }
            Err(err) => {
                debug!(target: "n42.h2.node", %addr, %err, "body channel write failed; reconnecting next time");
                stream = None;
            }
        }
    }
}

/// The body-channel address that goes with a libp2p `/ip4/<a>/tcp/<p>`
/// multiaddr: the same host, the port plus `offset`.
pub fn address_for(multiaddr: &str, offset: u16) -> Option<SocketAddr> {
    let mut parts = multiaddr.trim_start_matches('/').split('/');
    let (mut ip, mut port) = (None, None);
    while let Some(key) = parts.next() {
        let value = parts.next()?;
        match key {
            "ip4" | "ip6" => ip = value.parse::<std::net::IpAddr>().ok(),
            "tcp" => port = value.parse::<u16>().ok(),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?.checked_add(offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_channel_address_follows_the_libp2p_one() {
        assert_eq!(
            address_for("/ip4/127.0.0.1/tcp/19003/p2p/12D3KooWabc", 1000),
            Some("127.0.0.1:20003".parse().unwrap())
        );
        assert_eq!(address_for("/ip4/127.0.0.1/tcp/19003", 0), Some("127.0.0.1:19003".parse().unwrap()));
        assert_eq!(address_for("/dns4/x/tcp/1", 1), None);
    }

    /// A body offered to the pushers arrives at the listener, whole and once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_crosses_the_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, mut rx) = mpsc::channel(4);
        listen(addr, tx).await.unwrap();
        let pushers = BodyPushers::connect(vec![addr]);
        let body: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let offer = |bytes: Vec<u8>| OfferedBody { full: alloy_primitives::Bytes::from(bytes), compact: None };
        assert_eq!(pushers.push(offer(body.clone())), 1);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert_eq!(&got[..], &body[..]);
        assert!(!got.is_compact());
        assert_eq!(pushers.push(offer(vec![7u8; 10])), 1);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert_eq!(&got[..], &[7u8; 10][..]);
    }

    /// A sender that names itself is remembered, and every body from that
    /// connection carries it; one that does not leaves its bodies
    /// unattributed, which is what an older member does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_named_sender_is_carried_with_its_bodies() {
        for name in [Some("12D3KooWtheLeader"), None] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let (tx, mut rx) = mpsc::channel(4);
            listen(addr, tx).await.unwrap();
            let pushers = BodyPushers::connect(vec![addr]);
            if let Some(name) = name {
                pushers.announce(name);
            }
            assert_eq!(
                pushers.push(OfferedBody {
                    full: alloy_primitives::Bytes::from_static(&[1, 2, 3]),
                    compact: None,
                }),
                1
            );
            let got =
                tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
            assert_eq!(&got[..], &[1u8, 2, 3][..]);
            assert_eq!(got.from(), name);
        }
    }

    /// A peer that did not greet for compact bodies is sent the whole body,
    /// and one that did is sent the compact one -- the same offer, decided
    /// per connection. The receiver here greets with whatever this build's
    /// `N42_COMPACT_BODY` says, so the test asserts the pair rather than
    /// one branch: the bytes that arrive are the compact ones exactly when
    /// the arriving frame says it is compact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offer_arrives_in_the_shape_the_receiver_greeted_for() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, mut rx) = mpsc::channel(4);
        listen(addr, tx).await.unwrap();
        let pushers = BodyPushers::connect(vec![addr]);
        let full = vec![1u8; 4096];
        let compact = vec![2u8; 64];
        assert_eq!(
            pushers.push(OfferedBody {
                full: alloy_primitives::Bytes::from(full.clone()),
                compact: Some(alloy_primitives::Bytes::from(compact.clone())),
            }),
            1
        );
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        if got.is_compact() {
            assert_eq!(&got[..], &compact[..]);
        } else {
            assert_eq!(&got[..], &full[..]);
        }
    }
}

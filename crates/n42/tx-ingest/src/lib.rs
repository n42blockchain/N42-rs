// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A binary TCP path into the transaction pool, for throughput rounds.
//!
//! `eth_sendRawTransaction` is the only ingress an execution layer offers, and
//! for a load generator it costs three things that have nothing to do with the
//! transaction: hex encoding, which doubles the bytes; JSON parsing of both
//! request and reply; and, above all, a request/response round trip the sender
//! has to wait out before it can send again. Measured on the seven-node fleet,
//! a generator with 64 blocking threads spent 0.9 of a core and delivered
//! ~22,000 transactions a second — about 290 ms per 100-transaction batch, with
//! the threads idle for essentially all of it.
//!
//! This is the same thing without those three. Frames are length-prefixed raw
//! EIP-2718 bytes, and a sender may put as many on the wire as it likes without
//! waiting: acknowledgements come back on the same connection, in order, and a
//! generator that does not care about them can ignore them entirely.
//!
//! # Wire
//!
//! ```text
//! frame   := u32 count, then `count` x (u32 len, len bytes of EIP-2718)
//! reply   := u32 accepted, u32 pool_pending      -- one per frame, in order
//! ```
//!
//! Little-endian, because both ends of this are the same machine or the same
//! LAN and nothing here is a consensus artefact.
//!
//! # Backpressure, which is the point of the reply
//!
//! A generator that is refused does not stop, it retries — and every retry
//! re-signs the transaction, so a full pool turns the generator's whole budget
//! into work neither side keeps. Every round measured here logged
//! `txpool is full` and then reported the generator's ceiling as the chain's.
//!
//! So this waits rather than refusing. A frame is not admitted while the pool
//! is at its high water mark; the connection simply does not answer until there
//! is room, and a client with a bounded window stops sending on its own. The
//! reply carries the pool's pending count so a client that wants to pace itself
//! can, without a second round trip to ask.
//!
//! Taken from gov5's sibling client, which solved the same problem in the same
//! place. What is *not* taken from it, yet, is the other half of their design:
//! their client sends a pre-recovered sender with each transaction and the
//! server trusts it, skipping ECDSA entirely. That removes ~50 us a transaction
//! and it is the right trade when recovery is the ceiling — but on this fleet
//! the machine is 94% idle at 22,000 TPS, so recovery is not the ceiling, and
//! trusting a client-supplied sender would change what the benchmark verifies
//! without changing what it measures. It is a switch worth adding the day CPU
//! becomes the limit, and not before.
//!
//! # What it is not
//!
//! Not a peer protocol and not authenticated. It hands transactions to the pool
//! exactly as `eth_sendRawTransaction` does — the pool validates every one, and
//! recovering the sender is the bulk of that — so it can admit nothing the RPC
//! could not. It is off unless a `--tx-ingest` address is given, and it should
//! be bound to loopback.

use std::net::SocketAddr;

use alloy_primitives::Bytes;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Largest frame this will read, in transactions.
///
/// A frame is read into memory before any of it is validated, so this bounds
/// what one connection can make the node allocate. Ten thousand transfers is
/// about 1.1 MB and comfortably more than one block of any tier here.
const MAX_FRAME_TXS: u32 = 10_000;

/// Largest single transaction, in bytes.
const MAX_TX_BYTES: u32 = 1 << 20;

/// How long to wait between checks when the pool is at its high water mark.
const GATE_POLL: std::time::Duration = std::time::Duration::from_millis(2);

/// Pending transactions at which admission stops until the chain drains some.
///
/// From `N42_TX_INGEST_HIGH_WATER`, defaulting to a value that is only a
/// sensible default for a fleet whose pool holds far more: a gate above the
/// pool's own capacity never closes, and one far below it starves the builder.
/// Sized by the round, which knows its own pool depth.
fn high_water() -> usize {
    std::env::var("N42_TX_INGEST_HIGH_WATER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90_000)
}

/// Serves the ingest protocol on `addr` until the process ends.
///
/// One task per connection, and each connection is independent: a generator
/// gets its parallelism by opening several rather than by this doing anything
/// clever with one.
pub async fn serve<P>(addr: SocketAddr, pool: P) -> std::io::Result<()>
where
    P: TransactionPool + Clone + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    info!(target: "n42.tx_ingest", %addr, "binary transaction ingest listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(target: "n42.tx_ingest", %err, "accept failed");
                continue;
            }
        };
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, pool).await {
                debug!(target: "n42.tx_ingest", %peer, %err, "ingest connection ended");
            }
        });
    }
}

async fn serve_connection<P>(mut stream: TcpStream, pool: P) -> std::io::Result<()>
where
    P: TransactionPool,
{
    let gate = high_water();
    // Nagle would batch the acknowledgements into the next read's latency, and
    // the point of this path is that nothing waits for a round trip.
    stream.set_nodelay(true)?;
    loop {
        let count = match stream.read_u32_le().await {
            Ok(count) => count,
            // A generator that has finished simply closes.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if count == 0 || count > MAX_FRAME_TXS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame of {count} transactions"),
            ));
        }
        let mut raws = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let len = stream.read_u32_le().await?;
            if len == 0 || len > MAX_TX_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("transaction of {len} bytes"),
                ));
            }
            let mut buf = vec![0u8; len as usize];
            stream.read_exact(&mut buf).await?;
            raws.push(Bytes::from(buf));
        }
        // The gate. Not a refusal and not a drop: the frame is held until the
        // chain has taken a block out of the pool, and the client hears nothing
        // until then, which is the whole difference between backpressure and a
        // generator burning its budget on retries.
        while pool.pending_transactions().len() >= gate {
            tokio::time::sleep(GATE_POLL).await;
        }
        let accepted = admit(&pool, raws).await;
        let pending = u32::try_from(pool.pending_transactions().len()).unwrap_or(u32::MAX);
        stream.write_u32_le(accepted).await?;
        stream.write_u32_le(pending).await?;
    }
}

/// Hands a frame to the pool and counts what it took.
///
/// Decoding failures are counted as refusals rather than closing the
/// connection: one malformed transaction in a batch says nothing about the
/// next one, and a generator that sends one is not an attacker, it is a
/// generator with a bug.
async fn admit<P>(pool: &P, raws: Vec<Bytes>) -> u32
where
    P: TransactionPool,
{
    let mut decoded = Vec::with_capacity(raws.len());
    for raw in raws {
        // The same entry point `eth_sendRawTransaction` uses: decode the
        // EIP-2718 envelope and recover the sender. Recovery is most of the
        // cost and it is deliberately still here -- see the note at the top
        // about what this path does not shortcut.
        match <P::Transaction as PoolTransaction>::recover_raw_transaction(raw.as_ref()) {
            Ok(tx) => decoded.push(tx),
            Err(err) => debug!(target: "n42.tx_ingest", %err, "undecodable transaction"),
        }
    }
    if decoded.is_empty() {
        return 0;
    }
    // `External`, the same origin `eth_sendRawTransaction` uses for a
    // transaction that did not come from this node: it is validated, priced and
    // gossiped exactly as one that arrived over RPC.
    let results = pool.add_transactions(TransactionOrigin::External, decoded).await;
    let accepted = results.iter().filter(|outcome| outcome.is_ok()).count();
    u32::try_from(accepted).unwrap_or(u32::MAX)
}

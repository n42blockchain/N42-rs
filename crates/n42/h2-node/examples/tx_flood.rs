// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Load generator for the seven-node fleet: funds a derived sender set, then
//! floods it at the chain.
//!
//! ```text
//! tx_flood --rpc http://127.0.0.1:8700,http://127.0.0.1:8701 --chain-id 1143 \
//!          --senders 3000 --pertx 300 --offset 1 --conc 32 --rpcbatch 100
//! ```
//!
//! This is the Rust counterpart of gov5's `cmd/txflood`, and it derives its
//! senders the same way — `keccak256("n42-txflood-sender-v1" ‖ be64(offset+i+1))`
//! as the secret — so a round against either client draws on the identical set
//! of accounts. That matters for a comparison: the supply side is then provably
//! the same thing, not two harnesses that merely resemble each other.
//!
//! # Why one sender is not enough
//!
//! A key is a nonce sequence, so one key is one serial pipe: at 21,000-gas
//! transfers a single sender tops out around a hundred a second and the
//! measurement is of the harness. Thousands of senders in parallel is the only
//! way the chain becomes the limit — which is also how the chain's own limits
//! (pool depth, sender recovery, the gossip size cap) become visible at all.
//!
//! # `--offset` is not optional between rounds
//!
//! Derived accounts keep their nonces across runs. One transaction lost
//! anywhere in that history — rejected, or dropped from the pool before it was
//! mined — leaves a permanent hole: everything above it stays queued and can
//! never be promoted, because promotion needs the account's exact next nonce.
//! gov5 measured this as a pool holding 118,530 queued transactions with zero
//! pending and near-empty blocks, and it reads exactly like a node failure.
//! A fresh offset gives accounts whose nonces start at zero, which cannot have
//! a hole.
//!
//! # The gas price is a measurement decision
//!
//! The flood submits at a fixed price while the chain's base fee is chain state
//! that survives the round. A round started when the base fee sits above this
//! price does not merely run slow — it dies in its funding phase, and the
//! windows dutifully report an idle chain. Default 10 gwei against a 1 gwei
//! genesis floor leaves room for roughly twenty consecutive full blocks of
//! 12.5% climb; past that, let the chain idle or raise the price.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use n42_tx_types::{alt_sig::sender_of, TxAltSig, ALG_ED25519};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::{json, Value};

/// Where the flood's transfers go when `--recipients 1`.
///
/// Value lands somewhere that will never spend it again, so the senders'
/// balances are the only thing that moves.
const SINK: Address = Address::new([0x42; 20]);

/// Knuth's multiplicative constant, as N42-26's `n42-stress` uses it to spread
/// recipients. Kept identical so a block of this fleet's transfers touches the
/// same *number* of accounts, in the same scattered way, as a block of theirs.
const RECIPIENT_SPREAD: u32 = 2_654_435_761;

/// The recipient for one transfer.
///
/// One address for every transfer is the wrong shape and it took a comparison
/// to notice: a 163,000-transaction block that pays a single account writes one
/// account, where the same block with scattered recipients writes 163,000.
/// Five orders of magnitude of state, absent from every number this harness
/// produced before.
///
/// It also made one direction unmeasurable. Every transaction writing the same
/// account is a write-write conflict on every transaction, so a parallel
/// executor would serialise on it completely -- exactly the case N42-26's
/// roadmap excludes when it says the speedup shows only on contract-heavy
/// blocks.
fn recipient(spread: u32, index: u64) -> Address {
    if spread <= 1 {
        return SINK;
    }
    let slot = ((index as u32).wrapping_mul(RECIPIENT_SPREAD)) % spread;
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&slot.to_be_bytes());
    bytes[4] = 0x42;
    Address::new(bytes)
}
const TRANSFER_GAS: u64 = 21_000;
/// gov5 caps a batch here; beyond it the JSON body itself becomes the cost.
// Over the ingest a frame may carry up to 10,000 transactions and a bigger
// frame amortises the node's per-frame hand-off (~24 ms a frame at 100 on a
// connection's read loop); over JSON-RPC a batch this large may exceed the
// server's limit, so raise `--rpcbatch` past 200 only with `--ingest`.
const MAX_RPC_BATCH: usize = 2000;

struct Args {
    /// `secp256k1` (EIP-1559 transfers) or `ed25519` (0x50 transfers).
    alg: String,
    rpcs: Vec<String>,
    chain_id: u64,
    faucet: String,
    senders: usize,
    per_tx: u64,
    offset: u64,
    gas_price: u128,
    /// Gas limit on every transfer, funding included. 21,000 is a transfer
    /// everywhere before Amsterdam; on an Amsterdam chain EIP-8037 charges
    /// state creation up front, and a transfer that *creates* its recipient
    /// needs about 207,000 of limit or it runs out of gas -- mined, charged,
    /// and the value never moves. Measured here: a funding round that
    /// "mined through nonce 6000" and left every sender at 0 wei.
    gas: u64,
    conc: usize,
    rpc_batch: usize,
    /// Frames a worker may have unanswered at once over the ingest
    /// (`--window`, 32). The generator is a closed loop: its rate is the
    /// frames in flight over an answer's latency, so this is the knob that
    /// says whether a node's answers or its own signing bound it.
    window: usize,
    shard_senders: bool,
    /// `--legacy-recipients`: derive the ingest path's recipients from the
    /// sender's index within the worker's part, as every round through 42
    /// did (round 43 found it: the 64 workers' senders at one local index
    /// paid the same recipients at the same nonces, so a full block of
    /// 163,000 transfers touched ~13,000 accounts). Kept as a knob so that
    /// shape can be reproduced next to the real one.
    legacy_recipients: bool,
    skip_funding: bool,
    /// How many distinct recipients the transfers are spread over. 1 keeps the
    /// old single-sink shape.
    recipients: u32,
    /// Binary ingest addresses, one per node, in place of JSON-RPC for the
    /// flood. Funding stays on RPC: it is six thousand transactions once, and
    /// it needs to read nonces back.
    ingest: Vec<String>,
    /// Every worker sends every transaction to every ingest, so no pool
    /// depends on gossip to hold what another pool holds. gov5 measures this
    /// way (their flood submits to all seven RPCs), and a leader with a
    /// tenure needs it: a transaction its pool never received leaves that
    /// sender's later nonces unbuildable for the whole tenure, and the fleet's
    /// other pools fill with them until the ingest gate stops the generator.
    ingest_all: bool,
    /// Seconds a worker waits for one node's answer to a frame before it
    /// gives up on the connection and opens it again (`--ingest-timeout`,
    /// 10; 0 waits for ever, as this did before). The node holds a frame at
    /// its gate rather than refusing it, so a slow answer is expected and a
    /// missing one means the node stopped draining its queue.
    ingest_timeout: u64,
    /// `--claim-sender` (or `N42_FLOOD_CLAIM_SENDER=1`): each ingest frame
    /// carries the address that signed each transaction, so a node running
    /// `N42_INGEST_VERIFY=leader` can file it in a lane without recovering
    /// the sender. The node still verifies every signature — in its builder
    /// before it includes one, and on its vote road before it votes — so
    /// this changes where the work is done, never whether it is done.
    claim_sender: bool,
    /// `--rate` (tx/s across the whole process, every node and every worker
    /// combined; 0, the default, is unlimited). `scripts/fleet7-bench.sh`
    /// divides this among `F7_FLOOD_PROCS` processes before it gets here, so
    /// nothing in this file has to know about that split.
    rate: f64,
    /// `--pregen-out <dir>`: write a pre-generated set there and exit,
    /// sending nothing (see [`pregen`]).
    pregen_out: Option<std::path::PathBuf>,
    /// `--pregen-txs <n>`: how many transactions the set holds, across every
    /// worker (capped at `--senders` x `--pertx`).
    pregen_txs: u64,
    /// `--replay <dir>`: send a pre-generated set's frames instead of
    /// signing (see [`replay_over_ingest`]).
    replay: Option<std::path::PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse()?;
    let client = Arc::new(
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(args.conc.max(1))
            .build()?,
    );

    let ed25519 = match args.alg.as_str() {
        "secp256k1" => false,
        "ed25519" => true,
        other => return Err(format!("--alg {other}: secp256k1 or ed25519").into()),
    };
    let keys: Vec<Signer> = (0..args.senders).map(|i| derive(args.offset, i, ed25519)).collect();
    println!("algorithm    : {}", args.alg);
    println!(
        "senders      : {} derived at offset {} (first {})",
        keys.len(),
        args.offset,
        keys.first().map_or_else(|| "-".into(), |k| k.address().to_string())
    );
    println!(
        "rate         : {}",
        if args.rate > 0.0 { format!("rate={:.0}/s", args.rate) } else { "rate=0/s (unlimited)".to_string() }
    );
    let limiter = Arc::new(RateLimiter::new(args.rate));

    if let Some(dir) = args.pregen_out.clone() {
        return pregen(&args, &keys, &dir);
    }
    // One thread owns a disjoint set of senders (see the spawn below); a
    // pre-generated set was cut the same way, so it is opened and checked
    // against these arguments before anything is funded.
    let chunk = args.senders.div_ceil(args.conc.max(1));
    let workers = args.senders.div_ceil(chunk);
    let mut replay_files: Vec<Option<ReplayFile>> = match &args.replay {
        Some(dir) => {
            let set = open_replay_set(dir, &args, chunk)?;
            let (txs, frames) = set.iter().fold((0u64, 0u64), |(t, f), file| (t + file.header.txs, f + file.header.frames));
            println!("replay       : {} files from {}, {txs} transactions in {frames} frames", set.len(), dir.display());
            set.into_iter().map(Some).collect()
        }
        None => (0..workers).map(|_| None).collect(),
    };

    if !args.skip_funding {
        fund(&client, &args, &keys)?;
    }
    if args.replay.is_some() {
        check_fresh_senders(&client, &args, &keys, chunk)?;
    }

    let started = Instant::now();
    let sent = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    // A line every five seconds, because the round kills this process before
    // it could sum up, and a generator that cannot say its own rate leaves
    // "the chain was starved" and "the generator was slow" indistinguishable.
    // The three clocks say where a worker's time went: signing (CPU, this
    // process), sending (socket writes), waiting (the node's answer).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (sent, rejected, stop) = (Arc::clone(&sent), Arc::clone(&rejected), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut last = (Instant::now(), 0u64);
            let mut last_reply = ([0u64; 8], [0u64; 8]);
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
                let now = Instant::now();
                let total = sent.load(Ordering::Relaxed);
                let rate = (total - last.1) as f64 / now.duration_since(last.0).as_secs_f64();
                // Each node's answer latency (send to answer read) over the
                // interval, in ms: the number that says which node the
                // generator is waiting on, and whether the wait is the wire
                // or the node.
                let mut per_node = String::new();
                for node in 0..REPLY_NS.len() {
                    let (ns, n) = (REPLY_NS[node].load(Ordering::Relaxed), REPLY_N[node].load(Ordering::Relaxed));
                    let (dns, dn) = (ns - last_reply.0[node], n - last_reply.1[node]);
                    last_reply.0[node] = ns;
                    last_reply.1[node] = n;
                    if dn > 0 {
                        per_node.push_str(&format!("{:.1} ", dns as f64 / dn as f64 / 1e6));
                    }
                }
                eprintln!(
                    "flood +{:>4}s: sent {} ({:.0}/s), rejected {}, sign {}s, send {}s, wait {}s, deepest pool {}, reply ms/node [{}]",
                    started.elapsed().as_secs(),
                    total,
                    rate,
                    rejected.load(Ordering::Relaxed),
                    SIGN_NS.load(Ordering::Relaxed) / 1_000_000_000,
                    SEND_NS.load(Ordering::Relaxed) / 1_000_000_000,
                    WAIT_NS.load(Ordering::Relaxed) / 1_000_000_000,
                    DEEPEST.load(Ordering::Relaxed),
                    per_node.trim_end(),
                );
                last = (now, total);
            }
        });
    }
    // One thread owns a disjoint set of senders, so a sender's nonces are
    // produced in order by one place. Sharing a sender across threads is how a
    // flood generates its own nonce holes.
    std::thread::scope(|scope| {
        for (worker, part) in keys.chunks(chunk).enumerate() {
            let (client, sent, rejected, limiter, args) =
                (Arc::clone(&client), Arc::clone(&sent), Arc::clone(&rejected), Arc::clone(&limiter), &args);
            let replay_file = replay_files.get_mut(worker).and_then(Option::take);
            scope.spawn(move || {
                let mut batch: Vec<String> = Vec::with_capacity(args.rpc_batch);
                // Every sender this thread owns is in flight at once, a batch at
                // a time in rotation, rather than one sender being drained to
                // completion before the next one starts.
                //
                // Walking them sequentially puts exactly `--conc` nonce
                // sequences on the chain at any moment, and a single full block
                // of this tier can take more transactions than that offers. It
                // shows up as occupancy falling while the chain speeds up —
                // measured at 250 ms pacing as 68% occupancy with the chain
                // producing 51 blocks in a window — and it makes every sender
                // back off in lockstep when the pool fills, because they are all
                // at the same point in their own sequence.
                let mut nonce = vec![0u64; part.len()];
                let mut stalls = vec![0u32; part.len()];
                let mut live = part.len();
                // The binary path, when a round asked for one. A worker gets
                // one connection; its parallelism is the frames it keeps in
                // flight on that connection, not the number of connections.
                let mut ingest = if args.ingest.is_empty() {
                    None
                } else {
                    let addrs: Vec<&str> = if args.ingest_all {
                        args.ingest.iter().map(String::as_str).collect()
                    } else {
                        vec![args.ingest[worker % args.ingest.len()].as_str()]
                    };
                    // 0 keeps the old blocking read; anything else gives a
                    // worker a way out of a node that has stopped answering.
                    let read_timeout = match args.ingest_timeout {
                        0 => Duration::from_secs(u64::from(u32::MAX)),
                        secs => Duration::from_secs(secs),
                    };
                    match Ingest::connect(&addrs, read_timeout) {
                        Ok(conn) => Some(conn),
                        Err(err) => {
                            eprintln!("ingest {}: {err}", addrs.join(","));
                            return;
                        }
                    }
                };
                if let (Some(conn), Some(mut file)) = (ingest.as_mut(), replay_file) {
                    let end = replay_over_ingest(conn, &mut file.reader, part.len(), args, &sent, &rejected, &limiter);
                    if end.exhausted {
                        EXHAUSTED.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "replay       : worker {worker} sent all {} frames of {}; the set ran out",
                            end.frames,
                            file.path.display()
                        );
                    }
                    return;
                }
                if let Some(conn) = ingest.as_mut() {
                    flood_over_ingest(
                        conn, part, worker * chunk, &mut nonce, &mut stalls, args, &sent, &rejected, &limiter,
                    );
                    return;
                }
                while live > 0 {
                    live = 0;
                    for (index, key) in part.iter().enumerate() {
                        if nonce[index] >= args.per_tx {
                            continue;
                        }
                        live += 1;
                        // `--shard-senders` pins a sender to one node, so every
                        // proposer owns whole nonce sequences and the followers'
                        // pools stay cold: that measures the cold sender-recovery
                        // path. Spreading them warms every pool instead. Neither
                        // is wrong; a round has to say which it used.
                        let rpc = if args.shard_senders {
                            &args.rpcs[(worker * chunk + index) % args.rpcs.len()]
                        } else {
                            &args.rpcs[(worker + index) % args.rpcs.len()]
                        };
                        // Only advance a sender's nonce on acceptance. Under
                        // sustained oversupply the pool fills and starts
                        // refusing, and a flood that skipped the refused nonce
                        // would leave a hole: every later transaction from that
                        // sender stays queued forever, because promotion needs
                        // the account's exact next nonce. gov5 measured that as
                        // 118,530 queued with zero pending and near-empty
                        // blocks, which reads exactly like a node failure.
                        let from = nonce[index];
                        let upto = (from + args.rpc_batch as u64).min(args.per_tx);
                        batch.clear();
                        batch.extend(
                            (from..upto)
                                .map(|n| {
                                    let to = recipient(args.recipients, (worker * chunk + index) as u64 * args.per_tx + n);
                                    signed(key, n, args.chain_id, args.gas_price, args.gas, 1, to)
                                }),
                        );
                        // Wait for the bucket before the batch leaves, not
                        // after: a frame is sent only when it can take its
                        // full `rpcbatch` worth of tokens at once.
                        limiter.take(batch.len());
                        let accepted = submit(&client, rpc, &batch, &sent, &rejected);
                        nonce[index] += accepted as u64;
                        if accepted < batch.len() {
                            stalls[index] += 1;
                            // A sender that has been refused this long is not
                            // coming back within the round; give up on it rather
                            // than spending the rest of the round on it.
                            if stalls[index] > 600 {
                                nonce[index] = args.per_tx;
                            }
                        } else {
                            stalls[index] = 0;
                        }
                    }
                    // One sleep per pass, not one per refused sender: the pass
                    // has already given the chain every other sender's work.
                    if live > 0 && stalls.iter().any(|s| *s > 0) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            });
        }
    });
    stop.store(true, Ordering::Relaxed);

    let elapsed = started.elapsed().as_secs_f64();
    let (sent, rejected) = (sent.load(Ordering::Relaxed), rejected.load(Ordering::Relaxed));
    println!(
        "flood        : {sent} accepted, {rejected} rejected, {elapsed:.1}s, {:.0}/s submitted",
        (sent + rejected) as f64 / elapsed
    );
    // A flood that could not give the chain more than the chain took has
    // measured itself. Saying so is the difference between a result and a
    // number.
    println!("note         : the submission rate above is this harness's ceiling, not the chain's");
    if args.replay.is_some() {
        let ran_out = EXHAUSTED.load(Ordering::Relaxed);
        println!(
            "replay       : {ran_out} of {workers} workers ran out of pre-generated frames{}",
            if ran_out > 0 { " -- the set was smaller than the leg" } else { "" }
        );
    }
    Ok(())
}

/// A process-wide token bucket that caps how many transactions the whole
/// flood may *send* per second, across every worker thread and every node it
/// floods.
///
/// Refill is continuous (by elapsed wall time, not by tick), so the achieved
/// rate tracks the target smoothly rather than stair-stepping once a second.
/// Capacity is one second of tokens: enough that a frame is never split to
/// fit under the cap, small enough that a worker that stalled behind a slow
/// node cannot spend a burst of built-up tokens on a wall of frames once it
/// frees up. `rate <= 0` disables the bucket entirely — `take` returns at
/// once, exactly like the no-limiter behaviour this replaces.
struct RateLimiter {
    rate: f64,
    state: Mutex<RateLimiterState>,
}

struct RateLimiterState {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(rate: f64) -> Self {
        Self { rate, state: Mutex::new(RateLimiterState { tokens: rate.max(0.0), last: Instant::now() }) }
    }

    /// Blocks the calling thread until `n` tokens can be taken from the
    /// bucket, then takes them. A frame is sent only after this returns, so
    /// the total send rate across every caller never exceeds `rate`.
    fn take(&self, n: usize) {
        if self.rate <= 0.0 {
            return;
        }
        let capacity = self.rate;
        let n = (n as f64).min(capacity);
        loop {
            let wait = {
                let mut state = self.state.lock().expect("rate limiter lock");
                let now = Instant::now();
                let elapsed = now.duration_since(state.last).as_secs_f64();
                state.tokens = (state.tokens + elapsed * self.rate).min(capacity);
                state.last = now;
                if state.tokens >= n {
                    state.tokens -= n;
                    return;
                }
                Duration::from_secs_f64((n - state.tokens) / self.rate)
            };
            // Never sleep past a short slice: another thread may free up
            // tokens (or take them) in the meantime, and a long single sleep
            // would make this thread's own wait imprecise.
            std::thread::sleep(wait.clamp(Duration::from_millis(1), Duration::from_millis(50)));
        }
    }
}

/// A flood sender: a secp256k1 key for EIP-1559 transfers, or an Ed25519 key
/// for 0x50 transfers, whose account is `keccak256(0x01 || pubkey)[12..]`.
enum Signer {
    Secp(PrivateKeySigner),
    Ed { key: ed25519_dalek::SigningKey, pubkey: Bytes, address: Address },
}

impl Signer {
    fn address(&self) -> Address {
        match self {
            Self::Secp(key) => key.address(),
            Self::Ed { address, .. } => *address,
        }
    }
}

/// gov5 `deriveKey`: `keccak256("n42-txflood-sender-v1" ‖ be64(offset+i+1))`.
///
/// A hash that does not land on a valid secp256k1 scalar is hashed again rather
/// than skipped, so the set stays dense and the same index always names the
/// same account. Ed25519 senders use `"n42-txflood-ed25519-v1"` and every
/// 32-byte seed is a key.
fn derive(offset: u64, index: usize, ed25519: bool) -> Signer {
    let seed_of = |domain: &[u8]| {
        let mut input = Vec::with_capacity(domain.len() + 8);
        input.extend_from_slice(domain);
        input.extend_from_slice(&(offset + index as u64 + 1).to_be_bytes());
        keccak256(input)
    };
    if ed25519 {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed_of(b"n42-txflood-ed25519-v1").0);
        let pubkey = Bytes::copy_from_slice(key.verifying_key().as_bytes());
        let address = sender_of(ALG_ED25519, &pubkey);
        return Signer::Ed { key, pubkey, address };
    }
    let mut seed = seed_of(b"n42-txflood-sender-v1");
    loop {
        match PrivateKeySigner::from_bytes(&seed) {
            Ok(signer) => return Signer::Secp(signer),
            Err(_) => seed = keccak256(seed),
        }
    }
}

fn signed(key: &Signer, nonce: u64, chain_id: u64, gas_price: u128, gas: u64, value: u64, to: Address) -> String {
    alloy_primitives::hex::encode_prefixed(signed_raw(key, nonce, chain_id, gas_price, gas, value, to))
}

/// Time all workers spent signing, sending frames, and waiting for answers,
/// in nanoseconds; and the deepest pool any answer reported.
static SIGN_NS: AtomicU64 = AtomicU64::new(0);
static SEND_NS: AtomicU64 = AtomicU64::new(0);
static WAIT_NS: AtomicU64 = AtomicU64::new(0);
static DEEPEST: AtomicU64 = AtomicU64::new(0);

/// Floods one worker's senders over a binary ingest connection.
///
/// Round-robin across the senders, one frame in flight per sender, and a bound
/// on how many frames may be outstanding at once so a worker cannot outrun the
/// node's ability to answer. A sender whose frame is still unanswered is
/// skipped rather than waited on, which is what keeps every other sender
/// moving while one is being validated.
fn flood_over_ingest(
    conn: &mut Ingest,
    part: &[Signer],
    first_sender: usize,
    nonce: &mut [u64],
    stalls: &mut [u32],
    args: &Args,
    sent: &AtomicU64,
    rejected: &AtomicU64,
    limiter: &RateLimiter,
) {
    /// Frames a worker may have unanswered at once.
    ///
    /// Deep enough that the connection is never idle waiting for an answer,
    /// shallow enough that a worker cannot bury the node under work it has
    /// already refused: at 100 transactions a frame this is 3,200 in flight
    /// per worker.
    let window = args.window.max(1);

    let mut inflight = vec![false; part.len()];
    let mut done = vec![false; part.len()];
    // The deepest the pool was seen to be, so a round can tell a generator that
    // could not keep up from a chain that was full the whole time.
    let mut deepest = 0usize;
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(args.rpc_batch);
    // Connections this worker gave up on and opened again, and when it last
    // said so.
    let mut timeouts = 0u32;
    let mut last_warn = Instant::now();
    loop {
        let mut wrote = false;
        for (index, key) in part.iter().enumerate() {
            if done[index] || inflight[index] || conn.inflight.len() >= window {
                continue;
            }
            let from = nonce[index];
            if from >= args.per_tx {
                done[index] = true;
                continue;
            }
            let upto = (from + args.rpc_batch as u64).min(args.per_tx);
            batch.clear();
            let at = Instant::now();
            // Built by the same function a pre-generated set is, so a
            // replayed set is byte for byte this path's frames (recipients by
            // the sender's global index; see `sign_batch`).
            sign_batch(key, first_sender, index, from, upto, args, &mut batch);
            SIGN_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
            let at = Instant::now();
            // The sender this worker signed with, so a node in
            // `N42_INGEST_VERIFY=leader` need not recover it to file the
            // transaction in a lane. It is a claim, not a credential: every
            // node verifies the signature where it uses the sender.
            let claim = args.claim_sender.then(|| key.address());
            // Same bucket as the RPC path: a frame goes out only once it can
            // take its transaction count in tokens.
            limiter.take(batch.len());
            if conn.send(index, &batch, claim).is_err() {
                return;
            }
            SEND_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
            inflight[index] = true;
            wrote = true;
        }
        // Nothing left to write and nothing left to hear about.
        if !wrote && conn.inflight.is_empty() {
            if deepest > 0 {
                eprintln!("ingest       : deepest pool seen {deepest} pending");
            }
            return;
        }
        let at = Instant::now();
        let answer = conn.recv();
        WAIT_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
        match answer {
            Ok(Some((index, offered, accepted, pending))) => {
                deepest = deepest.max(pending);
                DEEPEST.fetch_max(pending as u64, Ordering::Relaxed);
                inflight[index] = false;
                sent.fetch_add(accepted as u64, Ordering::Relaxed);
                rejected.fetch_add((offered - accepted) as u64, Ordering::Relaxed);
                // Only accepted nonces advance, exactly as on the RPC path: a
                // skipped nonce leaves a hole and every later transaction from
                // that sender queues behind it forever.
                nonce[index] += accepted as u64;
                if accepted < offered {
                    stalls[index] += 1;
                    if stalls[index] > 600 {
                        done[index] = true;
                    }
                } else {
                    stalls[index] = 0;
                }
            }
            Ok(None) => {}
            // A node that has not answered within the timeout is not going
            // to: its gate is shut and only the chain reopens it. Say so
            // once, drop the frames in flight and carry on rather than
            // taking the whole round down with it (loop190Y1a).
            Err(err) if is_read_timeout(&err) => {
                timeouts += 1;
                if timeouts == 1 || last_warn.elapsed() >= Duration::from_secs(30) {
                    last_warn = Instant::now();
                    eprintln!("ingest       : no answer from {err}; reconnecting (timeout {timeouts})");
                }
                inflight.fill(false);
                if conn.reconnect().is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Whether a read failed because nothing arrived in time; `SO_RCVTIMEO`
/// reports that as `WouldBlock` on Unix and `TimedOut` elsewhere.
fn is_read_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// One connection to a node's binary transaction ingest.
///
/// Frames go out without waiting for the ones before them to be answered,
/// which is the whole reason this exists. Over JSON-RPC each batch was a
/// request the sender had to see answered before it could send again —
/// measured at about 290 ms per 100-transaction batch, with 64 threads idle
/// for essentially all of it and the generator using 0.9 of a core to deliver
/// ~22,000 transactions a second.
///
/// The window is per sender, not per transaction: a worker owns many senders
/// and puts one frame in flight for each, so a single sender's nonces are
/// still strictly serial — one frame, then its answer, then the next — while
/// the connection always has work on it.
struct Ingest {
    /// One node's ingest, or every node's at once (`--ingest-all`): a frame
    /// goes to each stream, and a reply is read from each in the same order.
    streams: Vec<std::net::TcpStream>,
    /// The addresses the streams were opened on, so a connection that has
    /// stopped answering can be opened again.
    addrs: Vec<String>,
    /// Senders with a frame in flight, in the order the frames were written.
    /// Replies come back in the same order, so this is what matches an answer
    /// to the sender it belongs to.
    inflight: std::collections::VecDeque<(usize, usize, Instant)>,
    /// How long a worker waits for one node's answer before it gives up on
    /// the connection (`--ingest-timeout`).
    ///
    /// The node's gate holds a frame rather than refusing it, so a slow
    /// answer is normal and a missing one is not: in leg loop190Y1a one
    /// node's gate shut for good and every worker blocked here, without a
    /// timeout, for the last 35 seconds of the round -- the round's own
    /// `reply ms/node` went empty and nothing said why. A harness that hangs
    /// silently costs the whole leg, so it gives up, says so once and opens
    /// the connection again.
    read_timeout: Duration,
}

/// One ingest frame's bytes: `u32` count, then each transaction as `u32`
/// length and its raw EIP-2718 bytes.
///
/// With `claim`, the count carries `0x8000_0000` and the twenty bytes of the
/// claimed sender sit between each length and its transaction. See the
/// server's wire section (`n42-tx-ingest`).
fn frame_bytes(batch: &[Vec<u8>], claim: Option<Address>) -> Vec<u8> {
    let per_claim = if claim.is_some() { 20 } else { 0 };
    let mut frame = Vec::with_capacity(4 + batch.iter().map(|t| 4 + per_claim + t.len()).sum::<usize>());
    let count = batch.len() as u32 | if claim.is_some() { 0x8000_0000 } else { 0 };
    frame.extend_from_slice(&count.to_le_bytes());
    for raw in batch {
        frame.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        if let Some(claim) = claim {
            frame.extend_from_slice(claim.as_slice());
        }
        frame.extend_from_slice(raw);
    }
    frame
}

/// Per stream (node), the answers' latency summed since the start and their
/// count: send to answer read, in nanoseconds. Eight slots for seven nodes.
static REPLY_NS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static REPLY_N: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

impl Ingest {
    fn connect(addrs: &[&str], read_timeout: Duration) -> std::io::Result<Self> {
        let owned: Vec<String> = addrs.iter().map(|a| (*a).to_owned()).collect();
        let streams = Self::open(&owned, read_timeout)?;
        Ok(Self { streams, addrs: owned, inflight: std::collections::VecDeque::new(), read_timeout })
    }

    fn open(addrs: &[String], read_timeout: Duration) -> std::io::Result<Vec<std::net::TcpStream>> {
        let mut streams = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let stream = std::net::TcpStream::connect(addr.as_str())?;
            // Without this the kernel holds a frame back waiting for company,
            // and the pipelining above turns back into a round trip per batch.
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(read_timeout))?;
            streams.push(stream);
        }
        Ok(streams)
    }

    /// Opens every connection again and forgets what was in flight on the
    /// old ones.
    ///
    /// A timeout can also leave a stream half-read (the answer is eight
    /// bytes and `read_exact` may have taken some of them), so the stream is
    /// replaced rather than reused. Nothing is lost by dropping the frames
    /// in flight: a sender's nonce only advances on an answer, so those
    /// transactions are simply sent again, and a node that did admit them
    /// the first time drops the duplicates by (sender, nonce).
    fn reconnect(&mut self) -> std::io::Result<()> {
        self.streams = Self::open(&self.addrs, self.read_timeout)?;
        self.inflight.clear();
        Ok(())
    }

    /// Writes one frame: `u32` count, then each transaction as `u32` length and
    /// its raw EIP-2718 bytes.
    ///
    /// With `claim`, the count carries `0x8000_0000` and each transaction is
    /// preceded by the twenty bytes of the sender that signed it — what a
    /// node running `N42_INGEST_VERIFY=leader` files the transaction under
    /// instead of recovering it. An older node reads the header as a count
    /// past its frame bound and closes the connection saying so.
    fn send(&mut self, sender: usize, batch: &[Vec<u8>], claim: Option<Address>) -> std::io::Result<()> {
        self.send_frame(sender, &frame_bytes(batch, claim), batch.len())
    }

    /// Writes one frame already encoded (by [`frame_bytes`], live or read
    /// back from a pre-generated set) that carries `count` transactions.
    fn send_frame(&mut self, sender: usize, frame: &[u8], count: usize) -> std::io::Result<()> {
        use std::io::Write;
        // One write for the whole frame: a frame split across writes is a
        // frame the server reads in two syscalls.
        for stream in &mut self.streams {
            stream.write_all(frame)?;
        }
        self.inflight.push_back((sender, count, Instant::now()));
        Ok(())
    }

    /// Reads the answer to the oldest frame still in flight.
    ///
    /// The answer arrives when the pool has room, not when the frame arrives:
    /// the server holds a frame at its high water mark rather than refusing it,
    /// so a full pool shows up here as a slow reply and not as a rejection to
    /// re-sign and resend. The pending count comes back with it, which is what
    /// makes the generator's own logs able to say whether it was the chain that
    /// was full or the generator that was slow.
    fn recv(&mut self) -> std::io::Result<Option<(usize, usize, usize, usize)>> {
        use std::io::Read;
        let Some((sender, offered, sent_at)) = self.inflight.pop_front() else {
            return Ok(None);
        };
        // Across the streams: the fewest accepted, so a nonce never advances
        // past what every pool holds, and the deepest pool, which is the one
        // gating the generator.
        let mut accepted = usize::MAX;
        let mut pending = 0usize;
        for (node, stream) in self.streams.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            // Which node did not answer is the whole point of the message:
            // the gate is per node and only one of them has to be stuck.
            if let Err(err) = stream.read_exact(&mut buf) {
                let kind = err.kind();
                let addr = self.addrs.get(node).map_or("?", String::as_str);
                return Err(std::io::Error::new(kind, format!("{addr}: {err}")));
            }
            accepted = accepted.min(u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes")) as usize);
            pending = pending.max(u32::from_le_bytes(buf[4..8].try_into().expect("4 bytes")) as usize);
            if node < REPLY_NS.len() {
                REPLY_NS[node].fetch_add(sent_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
                REPLY_N[node].fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(Some((sender, offered, accepted, pending)))
    }
}

/// The same transaction as [`signed`], as bytes rather than as a hex string.
fn signed_raw(key: &Signer, nonce: u64, chain_id: u64, gas_price: u128, gas: u64, value: u64, to: Address) -> Vec<u8> {
    match key {
        Signer::Secp(key) => {
            let tx = TxEip1559 {
                chain_id,
                nonce,
                gas_limit: gas,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price / 10,
                to: TxKind::Call(to),
                value: U256::from(value),
                ..Default::default()
            };
            let signature = sign_hash(key, &tx.signature_hash());
            let envelope: TxEnvelope = tx.into_signed(signature).into();
            envelope.encoded_2718()
        }
        Signer::Ed { key, pubkey, .. } => {
            let tx = TxAltSig {
                chain_id,
                nonce,
                max_priority_fee_per_gas: gas_price / 10,
                max_fee_per_gas: gas_price,
                gas_limit: gas,
                to,
                value: U256::from(value),
                input: Bytes::new(),
                access_list: Default::default(),
                alg_type: ALG_ED25519,
                pubkey: pubkey.clone(),
            };
            tx.sign_ed25519(key).encoded_2718()
        }
    }
}

/// Signs a hash with libsecp256k1 rather than the signer's k256.
///
/// The signer's own `sign_hash_sync` is pure-Rust k256 and costs ~80 us a
/// transaction on this generator's SMT-shared cores -- 22 of its 64 workers
/// were signing at 269k/s with the other 42 waiting on answers, which put
/// the flood's own ceiling near 300k/s, below what the chain now consumes.
/// libsecp256k1 signs in a fraction of that, and the node recovers with the
/// same library, so the two sides agree on low-s normalisation. The
/// secret is re-derived from the signer's bytes each call; that is a scalar
/// check, ~1 us, nothing beside the signature. `TX_FLOOD_K256_SIGN=1`
/// restores the k256 path for an A-B.
fn sign_hash(key: &PrivateKeySigner, hash: &B256) -> Signature {
    static K256: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *K256.get_or_init(|| std::env::var_os("TX_FLOOD_K256_SIGN").is_some()) {
        return key.sign_hash_sync(hash).expect("sign");
    }
    let secret = secp256k1::SecretKey::from_slice(key.to_bytes().as_slice()).expect("a derived key is a valid scalar");
    let message = secp256k1::Message::from_digest(hash.0);
    let (recovery_id, compact) =
        secp256k1::SECP256K1.sign_ecdsa_recoverable(&message, &secret).serialize_compact();
    Signature::new(
        U256::from_be_slice(&compact[..32]),
        U256::from_be_slice(&compact[32..]),
        i32::from(recovery_id) != 0,
    )
}

/// Submits a batch as one JSON-RPC array. Counts each element's outcome, since
/// a batch is not atomic: some elements are accepted while others are refused,
/// and reporting the call rather than the elements hides a pool that is full.
/// Submits a batch and returns how many of its leading elements were accepted.
///
/// The prefix is what matters, not the total: the elements are one sender's
/// consecutive nonces, so the first refusal invalidates everything behind it
/// whatever the node said about those.
fn submit(
    client: &reqwest::blocking::Client,
    rpc: &str,
    batch: &[String],
    sent: &AtomicU64,
    rejected: &AtomicU64,
) -> usize {
    let body: Vec<Value> = batch
        .iter()
        .enumerate()
        .map(|(id, raw)| {
            json!({"jsonrpc": "2.0", "id": id, "method": "eth_sendRawTransaction", "params": [raw]})
        })
        .collect();
    match client.post(rpc).json(&body).send().and_then(reqwest::blocking::Response::json::<Value>) {
        Ok(Value::Array(results)) => {
            let bad = results.iter().filter(|r| r.get("error").is_some()).count() as u64;
            // Say why, once. A round that reports "2000 rejected" and nothing
            // else is a round spent guessing: the reasons are all different
            // problems — a base fee above the price, a nonce hole, a full pool,
            // a chain that is not moving — and they are all one line away.
            if bad > 0 {
                static SAID: std::sync::Once = std::sync::Once::new();
                SAID.call_once(|| {
                    if let Some(error) = results.iter().find_map(|r| r.get("error")) {
                        eprintln!("first rejection: {error}");
                    }
                });
            }
            rejected.fetch_add(bad, Ordering::Relaxed);
            sent.fetch_add(results.len() as u64 - bad, Ordering::Relaxed);
            // A batch response may come back out of order, so the prefix is
            // measured by id rather than by position.
            let failed: std::collections::HashSet<u64> = results
                .iter()
                .filter(|r| r.get("error").is_some())
                .filter_map(|r| r.get("id").and_then(Value::as_u64))
                .collect();
            (0..batch.len()).take_while(|id| !failed.contains(&(*id as u64))).count()
        }
        Ok(other) => {
            // A single object rather than an array is an error for the whole
            // batch — a method the node does not have, or a body it refused.
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("batch refused: {other}"));
            rejected.fetch_add(batch.len() as u64, Ordering::Relaxed);
            0
        }
        Err(err) => {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("submit failed: {err}"));
            rejected.fetch_add(batch.len() as u64, Ordering::Relaxed);
            0
        }
    }
}

/// The same funding batch to every other node's RPC. Without transaction
/// gossip (`F7_NO_TX_GOSSIP=1`) a pool holds only what was sent to it, and a
/// leader tenure longer than the funding wait never mines funding sent to
/// the first node alone (loop118 T1: tenure 64, node1 then node2 led for
/// 29 s each and node0's turn came at view 448, after the 120 s). A node
/// that mines the batch prunes the copies the others hold when the block
/// lands; the counts stay the first node's.
fn fund_others(client: &reqwest::blocking::Client, args: &Args, batch: &[String]) {
    let (sent, rejected) = (AtomicU64::new(0), AtomicU64::new(0));
    for rpc in args.rpcs.iter().skip(1) {
        let _ = submit(client, rpc, batch, &sent, &rejected);
    }
}

/// One transfer per sender from the faucet, enough to cover every transaction
/// the flood will ask of it plus its own gas.
fn fund(
    client: &reqwest::blocking::Client,
    args: &Args,
    keys: &[Signer],
) -> Result<(), Box<dyn std::error::Error>> {
    let faucet: PrivateKeySigner = args.faucet.parse()?;
    let rpc = &args.rpcs[0];
    let call = |method: &str, params: Vec<Value>| -> Result<Value, Box<dyn std::error::Error>> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response: Value = client.post(rpc).json(&body).send()?.json()?;
        if let Some(error) = response.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    };

    // Per sender: everything the flood will spend, plus ten transfers of slack.
    let per_gas = args.gas_price * u128::from(args.gas);
    let fund_value = per_gas * u128::from(args.per_tx + 10);
    let total = (fund_value + per_gas) * args.senders as u128;

    // Check the faucet before submitting anything. A faucet that cannot cover
    // the round presents as mass rejection during the flood, not as an error,
    // and reads like a chain that fell over.
    let balance = call("eth_getBalance", vec![json!(faucet.address()), json!("latest")])?;
    let balance = U256::from_str_radix(balance.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    println!(
        "faucet       : {} holds {} wei, round needs {total}",
        faucet.address(),
        balance
    );
    if balance < U256::from(total) {
        return Err(format!(
            "faucet holds {balance} wei but this round needs {total}; lower --senders/--pertx or wait for rewards"
        )
        .into());
    }

    let nonce = call("eth_getTransactionCount", vec![json!(faucet.address()), json!("latest")])?;
    let mut nonce = u64::from_str_radix(nonce.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    let started = Instant::now();
    let (sent, rejected) = (AtomicU64::new(0), AtomicU64::new(0));
    let mut batch = Vec::with_capacity(args.rpc_batch);
    for key in keys {
        let tx = TxEip1559 {
            chain_id: args.chain_id,
            nonce,
            gas_limit: args.gas,
            max_fee_per_gas: args.gas_price,
            max_priority_fee_per_gas: args.gas_price / 10,
            to: TxKind::Call(key.address()),
            value: U256::from(fund_value),
            ..Default::default()
        };
        let signature = faucet.sign_hash_sync(&tx.signature_hash())?;
        let envelope: TxEnvelope = tx.into_signed(signature).into();
        batch.push(alloy_primitives::hex::encode_prefixed(envelope.encoded_2718()));
        nonce += 1;
        if batch.len() >= args.rpc_batch {
            // Funding is one nonce sequence from the faucet and it either goes
            // in or the round is over; the prefix count is for the flood.
            let _ = submit(client, rpc, &batch, &sent, &rejected);
            fund_others(client, args, &batch);
            batch.clear();
        }
    }
    if !batch.is_empty() {
        let _ = submit(client, rpc, &batch, &sent, &rejected);
        fund_others(client, args, &batch);
    }
    println!(
        "funding      : {} submitted, {} rejected, {:.1}s",
        sent.load(Ordering::Relaxed),
        rejected.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64()
    );

    // Wait for the last funding transaction to be mined. Flooding before the
    // senders hold anything spends the whole round on rejections.
    let target = nonce;
    for _ in 0..120 {
        let mined = call("eth_getTransactionCount", vec![json!(faucet.address()), json!("latest")])?;
        let mined = u64::from_str_radix(mined.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
        if mined >= target {
            println!("funding      : mined through nonce {mined}");
            // Mined is not funded. A transfer whose gas limit is below what
            // this chain charges to create the recipient is mined, charged
            // and failed, and the faucet's nonce advances exactly as if it had
            // worked -- so the balance is what has to be read.
            let first = keys.first().ok_or("no senders to fund")?;
            let held = call("eth_getBalance", vec![json!(first.address()), json!("latest")])?;
            let held = U256::from_str_radix(held.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
            if held.is_zero() {
                return Err(format!(
                    "funding mined but {} holds 0 wei: the transfers failed in execution -- on an Amsterdam chain raise --gas (EIP-8037 charges account creation up front)",
                    first.address()
                )
                .into());
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err("funding did not mine within 120s; check the base fee against --gasprice".into())
}

/// The flood's arguments before the command line is read.
fn default_args() -> Args {
    Args {
        alg: "secp256k1".into(),
        rpcs: vec!["http://127.0.0.1:8700".into()],
        chain_id: 1143,
        // hardhat account 0, which this chain's genesis funds; tests/e2e.sh uses it too.
        faucet: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        senders: 0,
        per_tx: 300,
        offset: 0,
        gas_price: 10_000_000_000,
        gas: TRANSFER_GAS,
        conc: 32,
        rpc_batch: 100,
        window: 32,
        shard_senders: false,
        legacy_recipients: false,
        skip_funding: false,
        ingest: Vec::new(),
        ingest_all: false,
        ingest_timeout: 10,
        recipients: 1,
        claim_sender: std::env::var("N42_FLOOD_CLAIM_SENDER").is_ok_and(|v| v != "0"),
        rate: 0.0,
        pregen_out: None,
        pregen_txs: 0,
        replay: None,
    }
}

fn parse() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = default_args();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--rpc" => args.rpcs = next()?.split(',').map(str::to_owned).collect(),
            "--alg" => args.alg = next()?,
            "--chain-id" => args.chain_id = next()?.parse()?,
            "--key" => args.faucet = next()?,
            "--senders" => args.senders = next()?.parse()?,
            "--pertx" => args.per_tx = next()?.parse()?,
            "--offset" => args.offset = next()?.parse()?,
            "--gasprice" => args.gas_price = next()?.parse()?,
            "--gas" => args.gas = next()?.parse()?,
            "--conc" => args.conc = next()?.parse()?,
            "--rpcbatch" => args.rpc_batch = next()?.parse::<usize>()?.clamp(1, MAX_RPC_BATCH),
            "--window" => args.window = next()?.parse::<usize>()?.clamp(1, 4096),
            "--ingest" => args.ingest = next()?.split(',').map(str::to_owned).collect(),
            "--ingest-all" => args.ingest_all = true,
            "--ingest-timeout" => args.ingest_timeout = next()?.parse()?,
            "--claim-sender" => args.claim_sender = true,
            "--recipients" => args.recipients = next()?.parse()?,
            "--shard-senders" => args.shard_senders = true,
            "--legacy-recipients" => args.legacy_recipients = true,
            "--skip-funding" => args.skip_funding = true,
            "--rate" => args.rate = next()?.parse()?,
            "--pregen-out" => args.pregen_out = Some(next()?.into()),
            "--pregen-txs" => args.pregen_txs = next()?.parse()?,
            "--replay" => args.replay = Some(next()?.into()),
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}").into()),
        }
    }
    if args.senders == 0 {
        return Err(format!("--senders is required\n\n{USAGE}").into());
    }
    if args.rpcs.is_empty() {
        return Err("--rpc needs at least one URL".into());
    }
    if args.pregen_out.is_some() && args.pregen_txs == 0 {
        return Err("--pregen-out needs --pregen-txs <n>".into());
    }
    if args.pregen_out.is_some() && args.replay.is_some() {
        return Err("--pregen-out and --replay are two different runs".into());
    }
    if args.replay.is_some() && args.ingest.is_empty() {
        return Err("--replay sends ingest frames; it needs --ingest".into());
    }
    Ok(args)
}

const USAGE: &str = "\
tx_flood — fund a derived sender set and flood the fleet with transfers

  --rpc <url[,url]>   nodes to submit to (default http://127.0.0.1:8700)
  --chain-id <u64>    the chain (default 1143)
  --key <hex>         faucet private key
  --senders <n>       how many accounts to derive and fund (required)
  --pertx <n>         transactions per sender (default 300)
  --offset <n>        shift the derived set; use a fresh one every round
  --gasprice <wei>    default 10 gwei; must stay above the chain's base fee
  --gas <limit>       gas limit per transfer (default 21000; ~210000 on Amsterdam,
                      where EIP-8037 makes creating the recipient cost more)
  --conc <n>          concurrent submitters (default 32)
  --rpcbatch <n>      transactions per JSON-RPC batch, 1-200 (default 100)
  --shard-senders     pin each sender to one node (cold-follower path)
  --legacy-recipients     ingest path: recipients by the worker-local sender index (the
                          pre-round-43 shape, ~13,000 accounts a full block), for comparison
  --alg <secp256k1|ed25519>  signature scheme of the senders (default secp256k1; ed25519 sends 0x50 transactions)
  --ingest-timeout <s>    seconds to wait for a node's answer to a frame before giving
                          up on the connection and opening it again (default 10, 0 never)
  --claim-sender          ingest frames carry the sender that signed each transaction, for a
                          node running N42_INGEST_VERIFY=leader (N42_FLOOD_CLAIM_SENDER=1)
  --skip-funding      the senders are already funded
  --rate <tx/s>       cap the whole process's send rate across every worker and every
                      node (default 0, unlimited); F7_FLOOD_PROCS splits this before
                      it reaches this flag, so one process's --rate is its own share
  --pregen-out <dir>  sign nothing live: write --pregen-txs transactions, framed exactly as
  --pregen-txs <n>    the ingest path sends them, one file per worker, and exit. The set is
                      bound to --alg --chain-id --senders --pertx --offset --gas --gasprice
                      --recipients --rpcbatch --conc --claim-sender (and --legacy-recipients),
                      and is valid only on a chain where those senders start at nonce 0
  --replay <dir>      send a pre-generated set (same arguments, --ingest required) instead of
                      signing; funding works as without it
";

/// Signs the transactions of one ingest frame: sender `index` of the worker
/// whose first sender is `first_sender`, nonces `from..upto`.
///
/// The live ingest path and the pre-generated set both build their frames
/// here, so a replayed set is byte for byte what the live flood would have
/// sent for the same arguments.
fn sign_batch(
    key: &Signer,
    first_sender: usize,
    index: usize,
    from: u64,
    upto: u64,
    args: &Args,
    batch: &mut Vec<Vec<u8>>,
) {
    // The recipient's index is the sender's *global* index: with the
    // worker's local one, the 64 workers' senders at one local index paid the
    // same recipients at the same nonces, and a "full" block of 163,000
    // transfers touched 13,000 recipients (found in round 43, after every
    // round through 42 had measured that shape).
    let base = if args.legacy_recipients { 0 } else { first_sender };
    batch.clear();
    batch.extend((from..upto).map(|n| {
        let to = recipient(args.recipients, (base + index) as u64 * args.per_tx + n);
        signed_raw(key, n, args.chain_id, args.gas_price, args.gas, 1, to)
    }));
}

/// The frame the live ingest path sends for sender `index` at nonce `from`
/// (the next `--rpcbatch` nonces, cut at `--pertx`), and how many
/// transactions it carries.
fn live_frame(key: &Signer, first_sender: usize, index: usize, from: u64, args: &Args) -> (Vec<u8>, usize) {
    let upto = (from + args.rpc_batch as u64).min(args.per_tx);
    let mut batch = Vec::with_capacity(args.rpc_batch);
    sign_batch(key, first_sender, index, from, upto, args, &mut batch);
    (frame_bytes(&batch, args.claim_sender.then(|| key.address())), batch.len())
}

/// How many transactions a frame built by [`frame_bytes`] carries.
fn frame_count(frame: &[u8]) -> usize {
    frame.get(..4).map_or(0, |b| (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff) as usize)
}

/// The same frame without its first `skip` transactions: what a sender sends
/// again after a node accepted only a prefix of it. `None` for a frame that
/// does not parse, which only a corrupt set could produce.
fn frame_suffix(frame: &[u8], skip: usize) -> Option<Vec<u8>> {
    let head = u32::from_le_bytes(frame.get(..4)?.try_into().ok()?);
    let (claim, count) = (head & 0x8000_0000, (head & 0x7fff_ffff) as usize);
    if skip >= count {
        return None;
    }
    let per_claim = if claim != 0 { 20 } else { 0 };
    let mut at = 4usize;
    for _ in 0..skip {
        let len = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?) as usize;
        at += 4 + per_claim + len;
    }
    let rest = frame.get(at..)?;
    let mut out = Vec::with_capacity(4 + rest.len());
    out.extend_from_slice(&((count - skip) as u32 | claim).to_le_bytes());
    out.extend_from_slice(rest);
    Some(out)
}

// ---------------------------------------------------------------------------
// Pre-generated sets (`--pregen-out`, `--replay`).
//
// The flood signs every transaction as it sends it, on the cores left beside
// the nodes, and tops out there (FLEET7_PLAN_V4 7.22-7.24). A pre-generated
// set moves the signing off the leg: the frames are built once, exactly as the
// live ingest path builds them, and a replay only reads and sends them.
//
// One file per worker thread, `o<offset>-w<worker, 4 digits>.flood`, all
// integers little-endian:
//
//   header, PREGEN_HEADER_LEN bytes: magic "N42FLOOD", u32 version, u8 alg
//     (0 secp256k1, 1 ed25519), u8 claim-sender, u8 legacy-recipients, u8 0,
//     u64 chain id, u64 senders, u64 offset, u64 per_tx, u32 rpcbatch,
//     u32 workers, u32 worker, u32 senders in this worker, u64 its first
//     sender, u64 gas, u128 gas price, u32 recipients, u32 0, u64 transactions,
//     u64 frames, 8 bytes 0;
//   then `frames` records: u32 sender (index within the worker), u32 length,
//     and the frame exactly as `frame_bytes` builds it.
//
// The frames are in pass order: pass k holds nonces k*rpcbatch.. of every one
// of the worker's senders, in sender order -- the live flood's round robin with
// every frame accepted whole. The worker split is the live one
// (`--senders` in chunks of ceil(senders / conc)), and the recipients are the
// live derivation, so a replayed set is indistinguishable from a live one to
// the nodes.
//
// A set is valid ONLY against a chain on which its senders are at nonce 0 --
// a fresh datadir, funded by this flood's own funding step (or already funded
// for `--skip-funding`). Every transaction carries its nonce, so a sender that
// has sent anything before makes the set's frames for it stale: the replay
// reads the first sender of every worker back over RPC before it sends and
// refuses a non-zero nonce. `--offset` is part of the set: a leg that replays
// it must pass the offset it was generated with.
// ---------------------------------------------------------------------------

const PREGEN_MAGIC: [u8; 8] = *b"N42FLOOD";
const PREGEN_VERSION: u32 = 1;
const PREGEN_HEADER_LEN: usize = 128;

/// Workers whose pre-generated set ran out before the leg ended.
static EXHAUSTED: AtomicU64 = AtomicU64::new(0);

/// A pre-generated file's header: the arguments it was built for, and what it
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PregenHeader {
    alg: u8,
    claim_sender: bool,
    legacy_recipients: bool,
    chain_id: u64,
    senders: u64,
    offset: u64,
    per_tx: u64,
    rpc_batch: u32,
    workers: u32,
    worker: u32,
    part_len: u32,
    first_sender: u64,
    gas: u64,
    gas_price: u128,
    recipients: u32,
    txs: u64,
    frames: u64,
}

impl PregenHeader {
    /// What a file for this worker has to say, given the flood's arguments;
    /// the totals are zero.
    fn for_args(args: &Args, workers: usize, worker: usize, first_sender: usize, part_len: usize) -> Self {
        Self {
            alg: u8::from(args.alg == "ed25519"),
            claim_sender: args.claim_sender,
            legacy_recipients: args.legacy_recipients,
            chain_id: args.chain_id,
            senders: args.senders as u64,
            offset: args.offset,
            per_tx: args.per_tx,
            rpc_batch: args.rpc_batch as u32,
            workers: workers as u32,
            worker: worker as u32,
            part_len: part_len as u32,
            first_sender: first_sender as u64,
            gas: args.gas,
            gas_price: args.gas_price,
            recipients: args.recipients,
            txs: 0,
            frames: 0,
        }
    }

    fn encode(&self) -> [u8; PREGEN_HEADER_LEN] {
        let mut out = [0u8; PREGEN_HEADER_LEN];
        out[0..8].copy_from_slice(&PREGEN_MAGIC);
        out[8..12].copy_from_slice(&PREGEN_VERSION.to_le_bytes());
        out[12] = self.alg;
        out[13] = u8::from(self.claim_sender);
        out[14] = u8::from(self.legacy_recipients);
        out[16..24].copy_from_slice(&self.chain_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.senders.to_le_bytes());
        out[32..40].copy_from_slice(&self.offset.to_le_bytes());
        out[40..48].copy_from_slice(&self.per_tx.to_le_bytes());
        out[48..52].copy_from_slice(&self.rpc_batch.to_le_bytes());
        out[52..56].copy_from_slice(&self.workers.to_le_bytes());
        out[56..60].copy_from_slice(&self.worker.to_le_bytes());
        out[60..64].copy_from_slice(&self.part_len.to_le_bytes());
        out[64..72].copy_from_slice(&self.first_sender.to_le_bytes());
        out[72..80].copy_from_slice(&self.gas.to_le_bytes());
        out[80..96].copy_from_slice(&self.gas_price.to_le_bytes());
        out[96..100].copy_from_slice(&self.recipients.to_le_bytes());
        out[104..112].copy_from_slice(&self.txs.to_le_bytes());
        out[112..120].copy_from_slice(&self.frames.to_le_bytes());
        out
    }

    fn decode(raw: &[u8; PREGEN_HEADER_LEN]) -> Result<Self, String> {
        if raw[0..8] != PREGEN_MAGIC {
            return Err("not a tx_flood pre-generated set (bad magic)".into());
        }
        let u32_at = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let u64_at = |at: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[at..at + 8]);
            u64::from_le_bytes(b)
        };
        let version = u32_at(8);
        if version != PREGEN_VERSION {
            return Err(format!("set version {version}, this flood reads {PREGEN_VERSION}"));
        }
        let mut price = [0u8; 16];
        price.copy_from_slice(&raw[80..96]);
        Ok(Self {
            alg: raw[12],
            claim_sender: raw[13] != 0,
            legacy_recipients: raw[14] != 0,
            chain_id: u64_at(16),
            senders: u64_at(24),
            offset: u64_at(32),
            per_tx: u64_at(40),
            rpc_batch: u32_at(48),
            workers: u32_at(52),
            worker: u32_at(56),
            part_len: u32_at(60),
            first_sender: u64_at(64),
            gas: u64_at(72),
            gas_price: u128::from_le_bytes(price),
            recipients: u32_at(96),
            txs: u64_at(104),
            frames: u64_at(112),
        })
    }

    /// Every field on which this file and the flood's arguments disagree
    /// (the totals are not arguments).
    fn mismatches(&self, want: &Self) -> Vec<String> {
        let mut out = Vec::new();
        let mut compare = |flag: &str, have: String, wants: String| {
            if have != wants {
                out.push(format!("{flag}: the set has {have}, this flood has {wants}"));
            }
        };
        compare("--alg (0 secp256k1, 1 ed25519)", self.alg.to_string(), want.alg.to_string());
        compare("--claim-sender", self.claim_sender.to_string(), want.claim_sender.to_string());
        compare("--legacy-recipients", self.legacy_recipients.to_string(), want.legacy_recipients.to_string());
        compare("--chain-id", self.chain_id.to_string(), want.chain_id.to_string());
        compare("--senders", self.senders.to_string(), want.senders.to_string());
        compare("--offset", self.offset.to_string(), want.offset.to_string());
        compare("--pertx", self.per_tx.to_string(), want.per_tx.to_string());
        compare("--rpcbatch", self.rpc_batch.to_string(), want.rpc_batch.to_string());
        compare("workers (--conc)", self.workers.to_string(), want.workers.to_string());
        compare("worker", self.worker.to_string(), want.worker.to_string());
        compare("senders of this worker (--conc)", self.part_len.to_string(), want.part_len.to_string());
        compare("first sender of this worker (--conc)", self.first_sender.to_string(), want.first_sender.to_string());
        compare("--gas", self.gas.to_string(), want.gas.to_string());
        compare("--gasprice", self.gas_price.to_string(), want.gas_price.to_string());
        compare("--recipients", self.recipients.to_string(), want.recipients.to_string());
        out
    }
}

/// Where worker `worker`'s file of the set for `offset` lives.
fn pregen_path(dir: &std::path::Path, offset: u64, worker: usize) -> std::path::PathBuf {
    dir.join(format!("o{offset}-w{worker:04}.flood"))
}

/// Reads a set's frame records in order.
struct FrameReader<R> {
    inner: R,
    /// Records the header promised and not yet read: the end of the file
    /// before this is a truncated set, not a finished one.
    frames_left: u64,
}

impl<R: std::io::Read> FrameReader<R> {
    /// The next record: the sender (within the worker), the frame, and the
    /// transactions it carries; `None` once the header's frames are read.
    fn next(&mut self) -> std::io::Result<Option<(usize, Vec<u8>, usize)>> {
        if self.frames_left == 0 {
            return Ok(None);
        }
        let truncated = |err: std::io::Error| {
            std::io::Error::new(err.kind(), format!("pre-generated set truncated or unreadable: {err}"))
        };
        let mut head = [0u8; 8];
        self.inner.read_exact(&mut head).map_err(truncated)?;
        let sender = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
        if len < 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "a frame record shorter than its count"));
        }
        let mut frame = vec![0u8; len];
        self.inner.read_exact(&mut frame).map_err(truncated)?;
        self.frames_left -= 1;
        let count = frame_count(&frame);
        Ok(Some((sender, frame, count)))
    }
}

/// One worker's file, opened and checked.
struct ReplayFile {
    path: std::path::PathBuf,
    header: PregenHeader,
    reader: FrameReader<std::io::BufReader<std::fs::File>>,
}

/// Opens every worker's file of the set in `dir` and checks each header
/// against the flood's arguments; any disagreement refuses the whole set.
fn open_replay_set(
    dir: &std::path::Path,
    args: &Args,
    chunk: usize,
) -> Result<Vec<ReplayFile>, Box<dyn std::error::Error>> {
    use std::io::Read;
    let workers = args.senders.div_ceil(chunk);
    let mut set = Vec::with_capacity(workers);
    for worker in 0..workers {
        let first_sender = worker * chunk;
        let part_len = chunk.min(args.senders - first_sender);
        let path = pregen_path(dir, args.offset, worker);
        let file = std::fs::File::open(&path).map_err(|err| {
            format!(
                "REFUSING --replay: {}: {err} (no set for --offset {} split over {workers} workers here)",
                path.display(),
                args.offset
            )
        })?;
        let mut inner = std::io::BufReader::with_capacity(8 << 20, file);
        let mut raw = [0u8; PREGEN_HEADER_LEN];
        inner.read_exact(&mut raw).map_err(|err| format!("REFUSING --replay: {}: {err}", path.display()))?;
        let header =
            PregenHeader::decode(&raw).map_err(|err| format!("REFUSING --replay: {}: {err}", path.display()))?;
        let bad = header.mismatches(&PregenHeader::for_args(args, workers, worker, first_sender, part_len));
        if !bad.is_empty() {
            return Err(format!(
                "REFUSING --replay: {} was generated for other arguments:\n  {}",
                path.display(),
                bad.join("\n  ")
            )
            .into());
        }
        let frames_left = header.frames;
        set.push(ReplayFile { path, header, reader: FrameReader { inner, frames_left } });
    }
    let extra = pregen_path(dir, args.offset, workers);
    if extra.exists() {
        return Err(
            format!("REFUSING --replay: {} exists, so the set has more workers than --conc gives", extra.display())
                .into(),
        );
    }
    Ok(set)
}

/// A replay set is valid only where its senders start at nonce 0: reads the
/// first sender of every worker back and refuses anything else. An RPC that
/// cannot answer is a warning, not a refusal.
fn check_fresh_senders(
    client: &reqwest::blocking::Client,
    args: &Args,
    keys: &[Signer],
    chunk: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc = &args.rpcs[0];
    for first in (0..keys.len()).step_by(chunk.max(1)) {
        let address = keys[first].address();
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount", "params": [address, "latest"]});
        let answer = client
            .post(rpc)
            .json(&body)
            .send()
            .and_then(reqwest::blocking::Response::json::<Value>)
            .map_err(|err| err.to_string())
            .and_then(|v| {
                v.get("result")
                    .and_then(Value::as_str)
                    .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok())
                    .ok_or_else(|| format!("no nonce in {v}"))
            });
        match answer {
            Ok(0) => {}
            Ok(nonce) => {
                return Err(format!(
                    "REFUSING --replay: sender {first} ({address}) is at nonce {nonce}, not 0 -- a pre-generated set \
                     replays only against a chain where its senders are fresh (fresh datadirs; a new --offset needs a new set)"
                )
                .into())
            }
            Err(err) => {
                eprintln!("WARN replay   : could not read sender {first}'s nonce ({err}); assuming a fresh chain");
                return Ok(());
            }
        }
    }
    println!("replay       : every worker's first sender is at nonce 0");
    Ok(())
}

/// Writes a pre-generated set: `--pregen-txs` transactions (at most
/// `--senders` x `--pertx`) split over the live flood's workers, each
/// worker's share in proportion to its senders.
fn pregen(args: &Args, keys: &[Signer], dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use rayon::prelude::*;
    std::fs::create_dir_all(dir)?;
    let chunk = args.senders.div_ceil(args.conc.max(1));
    let workers = args.senders.div_ceil(chunk);
    let capacity = args.senders as u64 * args.per_tx;
    let total = if args.pregen_txs > capacity {
        println!(
            "pregen       : --pregen-txs {} is more than --senders x --pertx = {capacity}; writing {capacity}",
            args.pregen_txs
        );
        capacity
    } else {
        args.pregen_txs
    };
    println!(
        "pregen       : {total} transactions, {workers} workers of up to {chunk} senders, {} a frame, into {}",
        args.rpc_batch,
        dir.display()
    );
    let started = Instant::now();
    let progress = (AtomicU64::new(0), AtomicU64::new(0));
    let done = std::sync::atomic::AtomicBool::new(false);
    let results: Vec<Result<(u64, u64, u64), String>> = std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut last = (Instant::now(), 0u64);
            while !done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                if last.0.elapsed() < Duration::from_secs(5) {
                    continue;
                }
                let txs = progress.0.load(Ordering::Relaxed);
                eprintln!(
                    "pregen +{:>4}s: {txs} of {total} ({:.0}/s), {:.1} GB",
                    started.elapsed().as_secs(),
                    (txs - last.1) as f64 / last.0.elapsed().as_secs_f64(),
                    progress.1.load(Ordering::Relaxed) as f64 / 1e9
                );
                last = (Instant::now(), txs);
            }
        });
        let results: Vec<Result<(u64, u64, u64), String>> = (0..workers)
            .into_par_iter()
            .map(|worker| {
                let first = worker * chunk;
                let part = &keys[first..(first + chunk).min(keys.len())];
                // Exact shares: the workers' quotas sum to `total`.
                let share = |upto: usize| (u128::from(total) * upto as u128 / keys.len() as u128) as u64;
                let quota = share(first + part.len()) - share(first);
                pregen_worker(dir, args, part, workers, worker, first, quota, &progress)
                    .map_err(|err| format!("worker {worker}: {err}"))
            })
            .collect();
        done.store(true, Ordering::Relaxed);
        results
    });
    let (mut txs, mut frames, mut bytes) = (0u64, 0u64, 0u64);
    for result in results {
        let (t, f, b) = result?;
        txs += t;
        frames += f;
        bytes += b;
    }
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "pregen       : {txs} transactions in {frames} frames, {workers} files, {:.2} GB ({:.1} bytes a transaction), {elapsed:.1}s, {:.0}/s",
        bytes as f64 / 1e9,
        bytes as f64 / txs.max(1) as f64,
        txs as f64 / elapsed
    );
    println!(
        "pregen       : replay with the same --alg --chain-id --senders --pertx --offset {} --gas --gasprice --recipients --rpcbatch --conc, on fresh datadirs",
        args.offset
    );
    Ok(())
}

/// One worker's file: its senders' frames in pass order until `quota`
/// transactions are written (whole frames, so the last may pass it), written
/// under a temporary name and renamed once complete, so a set cut short is
/// never replayed. Returns transactions, frames and bytes written.
#[allow(clippy::too_many_arguments)]
fn pregen_worker(
    dir: &std::path::Path,
    args: &Args,
    part: &[Signer],
    workers: usize,
    worker: usize,
    first_sender: usize,
    quota: u64,
    progress: &(AtomicU64, AtomicU64),
) -> std::io::Result<(u64, u64, u64)> {
    use rayon::prelude::*;
    use std::io::{Seek, Write};
    let path = pregen_path(dir, args.offset, worker);
    let partial = path.with_extension("flood.partial");
    let mut out = std::io::BufWriter::with_capacity(8 << 20, std::fs::File::create(&partial)?);
    let mut header = PregenHeader::for_args(args, workers, worker, first_sender, part.len());
    out.write_all(&header.encode())?;
    let mut bytes = PREGEN_HEADER_LEN as u64;

    // The live round robin with every frame accepted whole: pass k is nonces
    // k*rpcbatch.. of every sender, in sender order.
    let step = args.rpc_batch as u64;
    let mut plan: Vec<(usize, u64)> = Vec::new();
    let mut planned = 0u64;
    'passes: for from in (0..args.per_tx).step_by(args.rpc_batch.max(1)) {
        for index in 0..part.len() {
            if planned >= quota {
                break 'passes;
            }
            plan.push((index, from));
            planned += (from + step).min(args.per_tx) - from;
        }
    }
    // Signed in parallel a slab at a time and written in order, so the file
    // streams and the memory held is one slab of frames.
    for slab in plan.chunks(256) {
        let frames: Vec<(usize, Vec<u8>, usize)> = slab
            .par_iter()
            .map(|&(index, from)| {
                let (frame, count) = live_frame(&part[index], first_sender, index, from, args);
                (index, frame, count)
            })
            .collect();
        for (index, frame, count) in frames {
            out.write_all(&(index as u32).to_le_bytes())?;
            out.write_all(&(frame.len() as u32).to_le_bytes())?;
            out.write_all(&frame)?;
            header.txs += count as u64;
            header.frames += 1;
            bytes += 8 + frame.len() as u64;
            progress.0.fetch_add(count as u64, Ordering::Relaxed);
            progress.1.fetch_add(8 + frame.len() as u64, Ordering::Relaxed);
        }
    }
    let mut file = out.into_inner().map_err(std::io::IntoInnerError::into_error)?;
    file.seek(std::io::SeekFrom::Start(0))?;
    file.write_all(&header.encode())?;
    file.flush()?;
    drop(file);
    std::fs::rename(&partial, &path)?;
    Ok((header.txs, header.frames, bytes))
}

/// Where a replay sends its frames: the ingest connection, or a test's sink.
trait FrameSink {
    fn in_flight(&self) -> usize;
    fn send_frame(&mut self, sender: usize, frame: &[u8], count: usize) -> std::io::Result<()>;
    fn recv(&mut self) -> std::io::Result<Option<(usize, usize, usize, usize)>>;
    fn reconnect(&mut self) -> std::io::Result<()>;
}

impl FrameSink for Ingest {
    fn in_flight(&self) -> usize {
        self.inflight.len()
    }

    fn send_frame(&mut self, sender: usize, frame: &[u8], count: usize) -> std::io::Result<()> {
        Self::send_frame(self, sender, frame, count)
    }

    fn recv(&mut self) -> std::io::Result<Option<(usize, usize, usize, usize)>> {
        Self::recv(self)
    }

    fn reconnect(&mut self) -> std::io::Result<()> {
        Self::reconnect(self)
    }
}

/// How a worker's replay ended.
#[derive(Debug)]
struct ReplayEnd {
    /// Every frame of the file was sent and answered.
    exhausted: bool,
    /// Frames of the file sent (resends not counted).
    frames: u64,
}

/// Sends one worker's pre-generated frames, in the file's order, through the
/// same discipline as [`flood_over_ingest`]: at most `--window` frames
/// unanswered, one frame in flight per sender, the rate limiter before every
/// frame, and the counters and clocks the status line reads.
///
/// A sender's next frame waits for the answer to its last, so its nonces stay
/// serial exactly as on the live path. A frame a node accepted only part of is
/// sent again from the first refused transaction (cut from the frame, not
/// re-signed) before that sender's next frame; a sender refused 600 times in a
/// row is given up on, as the live path does, and its remaining frames are
/// skipped.
fn replay_over_ingest<S: FrameSink, R: std::io::Read>(
    conn: &mut S,
    reader: &mut FrameReader<R>,
    part_len: usize,
    args: &Args,
    sent: &AtomicU64,
    rejected: &AtomicU64,
    limiter: &RateLimiter,
) -> ReplayEnd {
    let window = args.window.max(1);
    // The frame each sender has in flight, kept to cut a resend from.
    let mut inflight: Vec<Option<Vec<u8>>> = vec![None; part_len];
    let mut stalls = vec![0u32; part_len];
    let mut dead = vec![false; part_len];
    let mut retry: std::collections::VecDeque<(usize, Vec<u8>, usize)> = std::collections::VecDeque::new();
    // The file's next frame, read but waiting on its sender's last answer.
    let mut held: Option<(usize, Vec<u8>, usize)> = None;
    let mut exhausted = false;
    let mut frames = 0u64;
    let mut deepest = 0usize;
    let mut timeouts = 0u32;
    let mut last_warn = Instant::now();
    loop {
        // What a node refused part of goes again first.
        let mut i = 0;
        while i < retry.len() && conn.in_flight() < window {
            if inflight[retry[i].0].is_some() {
                i += 1;
                continue;
            }
            let Some((sender, frame, count)) = retry.remove(i) else { break };
            limiter.take(count);
            let at = Instant::now();
            if conn.send_frame(sender, &frame, count).is_err() {
                return ReplayEnd { exhausted: false, frames };
            }
            SEND_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
            inflight[sender] = Some(frame);
        }
        // Then the file, in order.
        while !exhausted && conn.in_flight() < window {
            let next = match held.take() {
                Some(next) => Some(next),
                None => match reader.next() {
                    Ok(next) => next,
                    Err(err) => {
                        eprintln!("replay       : {err}");
                        return ReplayEnd { exhausted: false, frames };
                    }
                },
            };
            let Some((sender, frame, count)) = next else {
                exhausted = true;
                break;
            };
            if sender >= part_len {
                eprintln!("replay       : a frame names sender {sender} of a worker with {part_len}; corrupt set");
                return ReplayEnd { exhausted: false, frames };
            }
            if dead[sender] {
                continue;
            }
            if inflight[sender].is_some() || retry.iter().any(|r| r.0 == sender) {
                held = Some((sender, frame, count));
                break;
            }
            limiter.take(count);
            let at = Instant::now();
            if conn.send_frame(sender, &frame, count).is_err() {
                return ReplayEnd { exhausted: false, frames };
            }
            SEND_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
            inflight[sender] = Some(frame);
            frames += 1;
        }
        if conn.in_flight() == 0 {
            if exhausted && held.is_none() && retry.is_empty() {
                if deepest > 0 {
                    eprintln!("ingest       : deepest pool seen {deepest} pending");
                }
                return ReplayEnd { exhausted: true, frames };
            }
            continue;
        }
        let at = Instant::now();
        let answer = conn.recv();
        WAIT_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
        match answer {
            Ok(Some((sender, offered, accepted, pending))) => {
                deepest = deepest.max(pending);
                DEEPEST.fetch_max(pending as u64, Ordering::Relaxed);
                let frame = inflight.get_mut(sender).and_then(Option::take);
                sent.fetch_add(accepted as u64, Ordering::Relaxed);
                rejected.fetch_add((offered - accepted) as u64, Ordering::Relaxed);
                if accepted < offered {
                    stalls[sender] += 1;
                    if stalls[sender] > 600 {
                        dead[sender] = true;
                        retry.retain(|r| r.0 != sender);
                        if held.as_ref().is_some_and(|h| h.0 == sender) {
                            held = None;
                        }
                    } else if let Some(rest) = frame.and_then(|f| frame_suffix(&f, accepted)) {
                        retry.push_back((sender, rest, offered - accepted));
                    }
                } else {
                    stalls[sender] = 0;
                }
            }
            Ok(None) => {}
            // As on the live path: a node that has not answered within the
            // timeout is not going to. Every frame in flight goes again on a
            // new connection; a node that did admit one drops the duplicates
            // by (sender, nonce).
            Err(err) if is_read_timeout(&err) => {
                timeouts += 1;
                if timeouts == 1 || last_warn.elapsed() >= Duration::from_secs(30) {
                    last_warn = Instant::now();
                    eprintln!("ingest       : no answer from {err}; reconnecting (timeout {timeouts})");
                }
                for (sender, slot) in inflight.iter_mut().enumerate() {
                    if let Some(frame) = slot.take() {
                        let count = frame_count(&frame);
                        retry.push_back((sender, frame, count));
                    }
                }
                if conn.reconnect().is_err() {
                    return ReplayEnd { exhausted: false, frames };
                }
            }
            Err(_) => return ReplayEnd { exhausted: false, frames },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libsecp_signs_what_k256_signs() {
        for i in 0..8u64 {
            let key = PrivateKeySigner::from_bytes(&keccak256(i.to_be_bytes())).expect("key");
            let hash = keccak256((i * 7).to_be_bytes());
            let fast = sign_hash(&key, &hash);
            let slow = key.sign_hash_sync(&hash).expect("sign");
            assert_eq!(fast, slow, "sender {i}: libsecp256k1 and k256 disagree");
            assert_eq!(fast.recover_address_from_prehash(&hash).expect("recover"), key.address());
        }
    }

    /// The frame the ingest reads back: a plain one byte for byte as before,
    /// and a claiming one with the bit set and the sender ahead of each
    /// transaction's bytes.
    #[test]
    fn a_frame_carries_the_claim_where_the_server_reads_it() {
        let batch = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        assert_eq!(
            frame_bytes(&batch, None),
            [&2u32.to_le_bytes()[..], &3u32.to_le_bytes(), &[1, 2, 3], &2u32.to_le_bytes(), &[4, 5]].concat()
        );
        let claim = Address::repeat_byte(0xab);
        let claiming = frame_bytes(&batch, Some(claim));
        assert_eq!(
            claiming,
            [
                &(2u32 | 0x8000_0000).to_le_bytes()[..],
                &3u32.to_le_bytes(),
                claim.as_slice(),
                &[1, 2, 3],
                &2u32.to_le_bytes(),
                claim.as_slice(),
                &[4, 5],
            ]
            .concat()
        );
        assert_eq!(claiming.len(), frame_bytes(&batch, None).len() + 40);
    }

    /// Answers every frame at once, accepting all of it except where
    /// `short` says to accept only a prefix of the n-th frame sent.
    struct MemorySink {
        sent: Vec<(usize, Vec<u8>)>,
        queue: std::collections::VecDeque<(usize, usize)>,
        short: Option<(usize, usize)>,
    }

    impl FrameSink for MemorySink {
        fn in_flight(&self) -> usize {
            self.queue.len()
        }

        fn send_frame(&mut self, sender: usize, frame: &[u8], count: usize) -> std::io::Result<()> {
            self.sent.push((sender, frame.to_vec()));
            self.queue.push_back((sender, count));
            Ok(())
        }

        fn recv(&mut self) -> std::io::Result<Option<(usize, usize, usize, usize)>> {
            let answered = self.sent.len() - self.queue.len();
            Ok(self.queue.pop_front().map(|(sender, count)| {
                let accepted = match self.short {
                    Some((nth, prefix)) if nth == answered => prefix.min(count),
                    _ => count,
                };
                (sender, count, accepted, 0)
            }))
        }

        fn reconnect(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tx_flood_{tag}_{}_{nanos}", std::process::id()))
    }

    fn tiny_args(alg: &str, rpc_batch: usize, claim: bool) -> Args {
        let mut args = default_args();
        args.alg = alg.into();
        args.senders = 6;
        args.conc = 2;
        args.per_tx = 4;
        args.offset = 77;
        args.rpc_batch = rpc_batch;
        args.recipients = 1000;
        args.claim_sender = claim;
        args.chain_id = 1143;
        args
    }

    fn replay_all(args: &Args, dir: &std::path::Path, short: Option<(usize, usize)>) -> Vec<Vec<(usize, Vec<u8>)>> {
        let chunk = args.senders.div_ceil(args.conc);
        let set = open_replay_set(dir, args, chunk).expect("open the set");
        let (sent, rejected, limiter) = (AtomicU64::new(0), AtomicU64::new(0), RateLimiter::new(0.0));
        let mut out = Vec::new();
        for mut file in set {
            let mut sink = MemorySink { sent: Vec::new(), queue: Default::default(), short };
            let end = replay_over_ingest(
                &mut sink,
                &mut file.reader,
                file.header.part_len as usize,
                args,
                &sent,
                &rejected,
                &limiter,
            );
            assert!(end.exhausted, "a replay into a sink that accepts ends with the file");
            assert_eq!(end.frames, file.header.frames);
            out.push(sink.sent);
        }
        assert_eq!(sent.load(Ordering::Relaxed), (args.senders as u64) * args.per_tx);
        out
    }

    /// A pre-generated set replays byte for byte the frames the live ingest
    /// path builds for the same arguments, in its round-robin order, one
    /// file per worker; for both signature schemes, with and without the
    /// sender claim, and with frames that split a sender's nonces.
    #[test]
    fn a_replayed_set_is_the_live_flood_byte_for_byte() {
        for (alg, rpc_batch, claim) in [("ed25519", 5, false), ("secp256k1", 5, false), ("ed25519", 3, true), ("secp256k1", 3, false)] {
            let args = tiny_args(alg, rpc_batch, claim);
            let keys: Vec<Signer> = (0..args.senders).map(|i| derive(args.offset, i, alg == "ed25519")).collect();
            let dir = scratch_dir("pregen");
            let mut made = tiny_args(alg, rpc_batch, claim);
            made.pregen_txs = 24;
            pregen(&made, &keys, &dir).expect("generate");
            let replayed = replay_all(&args, &dir, None);
            let chunk = args.senders.div_ceil(args.conc);
            assert_eq!(replayed.len(), 2);
            for (worker, frames) in replayed.iter().enumerate() {
                let first = worker * chunk;
                let mut want = Vec::new();
                for from in (0..args.per_tx).step_by(rpc_batch) {
                    for index in 0..chunk {
                        want.push((index, live_frame(&keys[first + index], first, index, from, &args).0));
                    }
                }
                assert_eq!(frames, &want, "{alg} rpcbatch {rpc_batch}: worker {worker}'s frames");
            }
            let bytes: u64 = std::fs::read_dir(&dir).expect("dir").map(|e| e.expect("entry").metadata().expect("meta").len()).sum();
            eprintln!("{alg} rpcbatch {rpc_batch} claim {claim}: {bytes} bytes for 24 transactions");
            std::fs::remove_dir_all(&dir).expect("clean up");
        }
    }

    /// A frame accepted only in part goes again from the first refused
    /// transaction, before that sender's next frame; and a set made for other
    /// arguments is refused.
    #[test]
    fn a_partial_answer_resends_the_rest_and_a_foreign_set_is_refused() {
        let args = tiny_args("ed25519", 3, false);
        let keys: Vec<Signer> = (0..args.senders).map(|i| derive(args.offset, i, true)).collect();
        let dir = scratch_dir("partial");
        let mut made = tiny_args("ed25519", 3, false);
        made.pregen_txs = 24;
        pregen(&made, &keys, &dir).expect("generate");
        // The first frame (sender 0, nonces 0..3) accepted one transaction.
        let replayed = replay_all(&args, &dir, Some((0, 1)));
        let mut batch = Vec::new();
        sign_batch(&keys[0], 0, 0, 1, 3, &args, &mut batch);
        let rest = frame_bytes(&batch, None);
        let worker0 = &replayed[0];
        let resend = worker0.iter().position(|(s, f)| *s == 0 && *f == rest).expect("the rest was sent again");
        let next = worker0
            .iter()
            .position(|(s, f)| *s == 0 && *f == live_frame(&keys[0], 0, 0, 3, &args).0)
            .expect("sender 0's next frame");
        assert!(resend < next, "the rest goes before the sender's next frame");

        let mut other = tiny_args("ed25519", 3, false);
        other.chain_id = 1144;
        let err = open_replay_set(&dir, &other, 3).err().expect("refused").to_string();
        assert!(err.contains("--chain-id"), "{err}");
        other = tiny_args("ed25519", 3, false);
        other.conc = 3;
        assert!(open_replay_set(&dir, &other, 2).is_err(), "a set cut for two workers is not three");
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    /// A disabled bucket (`rate <= 0`) never blocks, whatever it is asked
    /// for.
    #[test]
    fn rate_limiter_disabled_never_blocks() {
        let limiter = RateLimiter::new(0.0);
        let start = Instant::now();
        limiter.take(1_000_000);
        assert!(start.elapsed() < Duration::from_millis(10));
    }

    /// A full bucket takes its first second's worth at once, then the
    /// bucket's own rate paces the rest: asking for another half-second's
    /// worth right after takes about half a second to refill.
    #[test]
    fn rate_limiter_bursts_to_capacity_then_paces_at_the_rate() {
        let limiter = RateLimiter::new(1000.0); // 1000 tok/s, capacity 1000
        let start = Instant::now();
        limiter.take(1000);
        assert!(start.elapsed() < Duration::from_millis(50), "the initial burst should not wait");
        limiter.take(500);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(400) && elapsed < Duration::from_millis(700),
            "expected ~500ms to refill 500 tokens at 1000/s, got {elapsed:?}"
        );
    }
}

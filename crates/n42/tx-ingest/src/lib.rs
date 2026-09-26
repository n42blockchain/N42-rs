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
//! frame   := u32 header, then `count` x entry
//! header  := count, or count | 0x8000_0000 for a frame that claims senders
//! entry   := u32 len, len bytes of EIP-2718
//!         := u32 len, 20 bytes of claimed sender, len bytes   (claiming frame)
//! reply   := u32 accepted, u32 pool_pending      -- one per frame, in order
//! ```
//!
//! Little-endian, because both ends of this are the same machine or the same
//! LAN and nothing here is a consensus artefact.
//!
//! The claim is additive and versioned by that one bit: `count` is bounded by
//! [`MAX_FRAME_TXS`], so the top bit was free, and a server that predates it
//! reads a claiming frame's header as a count far past the bound and closes
//! the connection with the reason named -- a loud failure rather than a
//! silently misread stream. A frame that does not claim is read exactly as
//! before.
//!
//! # The claim, and why it is not trust
//!
//! A generator knows the sender it signed with; recovering it again costs
//! ~11 us of this node's CPU. With `N42_INGEST_VERIFY=leader`
//! ([`n42_tx_types::senders_claimed_at_ingest`]) a claiming frame's sender is
//! taken as the *claim* the transaction is queued under -- the key of its
//! lane, nothing more -- and the signature is paid once later, in batch,
//! where it is needed: the builder verifies what it includes, the vote road
//! verifies what a block carries. Off (the default `all`), the claim is read
//! off the wire and discarded, and every transaction is verified here as it
//! always was.
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
//! Taken from N42-26's `crates/n42-node/src/ingest.rs`, which solved the same
//! problem in the same place — *not* from gov5, which is the Go client and has
//! no such path. What is *not* taken from it, yet, is the other half of their
//! design: their client sends a pre-recovered sender with each transaction and
//! the server trusts it, skipping ECDSA entirely. That removes ~50 us a transaction
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
//! could not. It is off unless `N42_TX_INGEST=<addr>` is set, and it should be
//! bound to loopback.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::{Address, Bytes, B256};
use n42_tx_queue::NewFrame;
use n42_tx_types::{ed25519_batch_size, AltSigSenderCache, AltSigTx, N42PooledTxEnvelope};
use reth_primitives_traits::Recovered;
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

/// The bit a frame's header sets to say that each of its entries carries the
/// sender the generator signed with, ahead of the transaction's bytes.
///
/// Free because [`MAX_FRAME_TXS`] bounds the count far below it; see the
/// wire section of the module docs.
const FRAME_CLAIMS_SENDERS: u32 = 0x8000_0000;

/// The bit has to be out of the count's range, or a claiming frame and a
/// large plain one would be the same header.
const _: () = assert!(MAX_FRAME_TXS < FRAME_CLAIMS_SENDERS);

/// Splits a frame's header into "does each entry carry a claimed sender" and
/// the transaction count.
const fn frame_header(header: u32) -> (bool, u32) {
    (header & FRAME_CLAIMS_SENDERS != 0, header & !FRAME_CLAIMS_SENDERS)
}

/// Frames one connection may have admitting in the background under
/// `N42_TX_INGEST_ASYNC`. At 100 transactions a frame and 64 connections
/// that is ~51,000 transactions buffered per node, about 300 ms of a full
/// block's demand: the length of the pool stall it is meant to cover.
const ASYNC_FRAMES_IN_FLIGHT: usize = 8;

/// `N42_TX_INGEST_ASYNC_FRAMES`: frames a connection may have recovering
/// or awaiting admission before its next answer waits; the default above.
fn async_frames_in_flight() -> usize {
    static FRAMES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *FRAMES.get_or_init(|| {
        std::env::var("N42_TX_INGEST_ASYNC_FRAMES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(ASYNC_FRAMES_IN_FLIGHT)
    })
}

/// How many frames may be in sender recovery at once, node-wide:
/// `N42_TX_INGEST_RECOVER_PARALLEL`, unlimited by default. Unlimited, 64
/// connections with 8 frames in flight each are 512 blocking threads of
/// secp256k1 on a node pinned to 16 cores, and the builder's thread -- and
/// the engine's import -- get a slice of a core while the generator is busy.
/// The nice value recovery threads run at: `N42_TX_INGEST_RECOVER_NICE`,
/// 0 by default. At 10 or more, the scheduler gives the builder's and the
/// engine's threads the core whenever they are runnable and recovery the
/// cycles nobody else wants -- a budget that follows the load instead of a
/// fixed one.
fn recovery_nice() -> i32 {
    static NICE: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *NICE.get_or_init(|| {
        std::env::var("N42_TX_INGEST_RECOVER_NICE")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .map(|n| n.clamp(0, 19))
            .unwrap_or(0)
    })
}

/// Lowers the calling thread's priority to [`recovery_nice`], once per
/// thread; blocking-pool threads are reused, so this is a few syscalls a
/// frame at most.
fn apply_recovery_nice() {
    thread_local! {
        static APPLIED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    let nice = recovery_nice();
    if nice == 0 || APPLIED.with(|a| a.replace(true)) {
        return;
    }
    // SAFETY: setpriority on the calling thread (PRIO_PROCESS with a thread
    // id) is a plain syscall with no memory effects; a failure leaves the
    // priority as it was.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS, tid, nice);
    }
}

/// `N42_TX_INGEST_RECOVER_PIN=1`: each recovery thread is pinned to one
/// physical core of the node's CPU set, round-robin, so two recoveries do
/// not share a core's execution units while the node's other threads float
/// over the set. Under load a recovery measured 48-63 us against 37 us on
/// an idle core (round 39): the SMT sibling was another recovery as often
/// as not. The node's set is what `taskset` left it; "physical" here means
/// the lower-numbered half of each sibling pair (cpu < 128 on this host's
/// 128-core parts), all of it when no such split is visible.
/// `=2` pins over every logical CPU of the set instead (one thread per SMT
/// thread, no migration); `=1` measured a loss -- 16 physical cores could not
/// carry 20 slots, 12.7 cores of recovery against 20 unpinned.
fn recovery_pin() -> u8 {
    static MODE: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| std::env::var("N42_TX_INGEST_RECOVER_PIN").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

fn physical_cores() -> &'static [usize] {
    static CORES: std::sync::OnceLock<Vec<usize>> = std::sync::OnceLock::new();
    CORES.get_or_init(|| {
        let all_logical = recovery_pin() == 2;
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        // SAFETY: sched_getaffinity fills a cpu_set_t of the given size.
        let ok = unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } == 0;
        let mut cpus: Vec<usize> = Vec::new();
        if ok {
            for cpu in 0..(8 * std::mem::size_of::<libc::cpu_set_t>()) {
                // SAFETY: cpu is within the set's bit range.
                if unsafe { libc::CPU_ISSET(cpu, &set) } {
                    cpus.push(cpu);
                }
            }
        }
        // The sibling split: keep a cpu whose sibling (cpu + half the
        // machine) is also in the set only once, as the lower number.
        let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) }.max(1) as usize;
        let half = ncpu / 2;
        if all_logical {
            return cpus;
        }
        let lower: Vec<usize> = cpus.iter().copied().filter(|&c| c < half || !cpus.contains(&(c - half))).collect();
        if lower.is_empty() { cpus } else { lower }
    })
}

/// Pins the calling thread to its core (see [`recovery_pin`]), once per
/// thread.
fn apply_recovery_affinity() {
    thread_local! {
        static PINNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if recovery_pin() == 0 || PINNED.with(|p| p.replace(true)) {
        return;
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let cores = physical_cores();
    if cores.is_empty() {
        return;
    }
    let core = cores[(NEXT.fetch_add(1, Ordering::Relaxed) as usize) % cores.len()];
    // SAFETY: a zeroed cpu_set_t with one bit set, applied to the calling
    // thread; a failure leaves the affinity as it was.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        let tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;
        libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// The recovery slot count when it is bounded, `None` when unlimited.
fn recovery_slot_count() -> Option<usize> {
    std::env::var("N42_TX_INGEST_RECOVER_PARALLEL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
}

fn recovery_slots() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| {
        let permits = recovery_slot_count().unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        std::sync::Arc::new(tokio::sync::Semaphore::new(permits))
    })
}

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
/// What the gate measures: the builder-side queue's depth when one is
/// installed (`N42_TX_QUEUE=1`), else the pool's pending count. The pool's
/// count includes a block's transactions until the pool's maintenance hears
/// of the block, which at this block size is long after the builder took
/// them; the queue's count is what the next build can still use.
/// `N42_TX_INGEST_DIRECT`, read once.
fn direct_to_queue() -> bool {
    static DIRECT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DIRECT.get_or_init(|| std::env::var("N42_TX_INGEST_DIRECT").is_ok())
}

/// What the gate sees at one instant: whether it is open, the depth it
/// measured and the limit that depth was tested against. The two numbers are
/// only for the warning below -- a gate that is shut for good has to be able
/// to say what it is shut on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GateView {
    open: bool,
    depth: u64,
    limit: u64,
}

/// Whether the gate lets a frame through: the queue's depth (the pool's
/// pending without a queue) against the high-water mark, plus one block's
/// allowance for each block the chain is ahead of the pool.
fn gate_view<P: TransactionPool + 'static>(
    pool: &P,
    head: &std::sync::Arc<AtomicU64>,
    gate: usize,
    allowance: u64,
) -> GateView
where
    P::Transaction: 'static,
{
    let lag = head
        .load(Ordering::Relaxed)
        .saturating_sub(pool.block_info().last_seen_block_number)
        .min(4);
    let depth = u64::try_from(queue_depth(pool)).unwrap_or(u64::MAX);
    let limit = gate as u64 + lag * allowance;
    GateView { open: depth < limit, depth, limit }
}

fn gate_open<P: TransactionPool + 'static>(
    pool: &P,
    head: &std::sync::Arc<AtomicU64>,
    gate: usize,
    allowance: u64,
) -> bool
where
    P::Transaction: 'static,
{
    gate_view(pool, head, gate, allowance).open
}

/// The node's gate: connections held at the high-water mark wait here, and
/// one watcher task ([`spawn_gate_watcher`]) wakes them when the depth is
/// back under it.
struct Gate {
    open: tokio::sync::Notify,
    waiting: AtomicU64,
}

static GATE: Gate = Gate { open: tokio::sync::Notify::const_new(), waiting: AtomicU64::new(0) };

/// How long a frame may sit at the gate before one WARN names the counters.
///
/// A healthy leg's worst frame waits ~200 ms here (loop190Y1a read
/// `gate_us_per_frame` between 583 and 192,683 us). Two seconds is an order
/// of magnitude past that and never fires on a chain that is moving.
const GATE_WARN_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a frame may sit at the gate before it is let through anyway:
/// `N42_TX_INGEST_GATE_MAX_WAIT_MS`, 15 seconds by default, 0 to wait for
/// ever (the behaviour before this).
///
/// The gate is backpressure, not a rule: waiting is how a generator is told
/// to slow down, and nothing about correctness depends on it. But the only
/// thing that reopens it is a canonical block pruning this node's queue, so
/// a node that stops following the chain holds its gate shut for good -- and
/// because every flood worker sends each frame to all seven nodes and reads
/// all seven answers, one such node stops the whole generator. The chain then
/// runs its queues dry and builds empty blocks, which prune nothing, so the
/// gate can never reopen: a closed loop. That is leg loop190Y1a
/// (2026-09-21), where node5's execution layer stopped at block 382 with
/// `queued=411428` against a gate of 407,500, all 64 flood workers blocked,
/// and the fleet produced 48 empty blocks to the end of the round.
///
/// Letting a stuck frame through costs the memory of one frame per connection
/// per deadline -- at 500 transactions a frame and 64 connections, ~32,000
/// transactions every 15 seconds on the node that is stuck, which is a
/// trickle and not a flood. Blocking for ever costs the round and hides the
/// node that failed.
fn gate_max_wait() -> Option<std::time::Duration> {
    static MAX: std::sync::OnceLock<Option<std::time::Duration>> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        let ms = std::env::var("N42_TX_INGEST_GATE_MAX_WAIT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15_000);
        (ms > 0).then(|| std::time::Duration::from_millis(ms))
    })
}

/// How a frame's wait at the gate ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateExit {
    /// The gate opened; the wait.
    Open(std::time::Duration),
    /// The gate was shut, but this node's vote road is assembling a proposed
    /// block and misses some of its transactions ([`open_gate_for_block`]);
    /// the wait.
    ForBlock(std::time::Duration),
    /// The deadline passed with the gate still shut; the wait.
    Forced(std::time::Duration),
}

/// Frames let through a shut gate by [`gate_max_wait`], since the process
/// started. Non-zero at the end of a round means a node stopped draining its
/// queue and the round is not comparable.
static GATE_FORCED: AtomicU64 = AtomicU64::new(0);

/// Defect 17 (loop245, three nodes): the gate against the block it waits for.
///
/// The gate reopens only when a canonical block prunes this node's queue. A
/// follower's vote road assembles the proposed block from that queue by
/// description, and the transactions it misses (`compact body: asking for
/// the transactions this node does not hold wanted=124`) are exactly the ones
/// in the frames held here: the flood sent them to every node, and this
/// node's copy is waiting at its own gate. The block cannot be voted until
/// they are admitted, the gate cannot reopen until a block is committed, and
/// the stall ends only at the view timeout -- with a quorum of three of
/// three, a TC every time (every one of five inspected).
///
/// So while the road reports misses, the gate lets frames through. The
/// window is [`GATE_FOR_BLOCK_WINDOW_MS`] from the road's last miss: the road
/// retries every 40-80 ms while it still misses, so the window is renewed
/// for as long as the block is incomplete and lapses on its own once the
/// block has been assembled. The trade-off: for that window the pool grows
/// past its high-water mark by whatever the generator offers (at ~900k/s,
/// ~450,000 transactions per window at most, in practice far fewer because
/// the block completes within a retry or two and its commit prunes a block's
/// worth). The backpressure the gate exists for is untouched whenever no
/// block is pending, which is the steady state: a pool that is full because
/// the chain is slow still holds the generator. The opening is opt-in
/// (`N42_TX_INGEST_GATE_FOR_BLOCK=1`, see [`gate_strict`]); without it the
/// old gate, which deadlocks as described, is what runs.
const GATE_FOR_BLOCK_WINDOW_MS: u64 = 500;

/// [`gate_clock_ms`] until which a block's misses keep the gate open; zero
/// when no block has asked.
static BLOCK_PENDING_UNTIL_MS: AtomicU64 = AtomicU64::new(0);

/// The transactions the road's last miss wanted, for the INFO line.
static BLOCK_PENDING_WANTED: AtomicU64 = AtomicU64::new(0);

/// Pending-block episodes: bumped when a miss arrives with no window open,
/// so the INFO line is written once per episode and not once per frame.
static BLOCK_PENDING_EPISODE: AtomicU64 = AtomicU64::new(0);

/// The last episode an INFO line was written for.
static BLOCK_PENDING_LOGGED: AtomicU64 = AtomicU64::new(0);

/// Frames let through a shut gate because a block was pending, since the
/// process started (`gate_opened_for_block` on the `ingest` line).
static GATE_OPENED_FOR_BLOCK: AtomicU64 = AtomicU64::new(0);

/// Whether the gate stays shut for a pending block. Off unless
/// `N42_TX_INGEST_GATE_FOR_BLOCK=1`: on loop246 (three nodes, the generator
/// at 880k/s against a chain consuming 860k/s) the road missed something on
/// most blocks, the window never lapsed, 16-26 thousand frames a leg went
/// past the limit and the pool grew without bound -- the fleet then died
/// faster than with the deadlock. The supply has to be rated at or under
/// the chain's consumption (plan v4 7.5); the opening is kept for a fleet
/// that is. `N42_TX_INGEST_GATE_STRICT=1` is the same as leaving the opt-in
/// unset and is read for the older runners.
fn gate_strict() -> bool {
    static STRICT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *STRICT.get_or_init(|| {
        let opt_in = std::env::var("N42_TX_INGEST_GATE_FOR_BLOCK").is_ok_and(|value| value == "1");
        let strict = std::env::var("N42_TX_INGEST_GATE_STRICT").is_ok_and(|value| value == "1");
        strict || !opt_in
    })
}

/// Whether a block is pending at `now_ms`, given the window's end.
const fn block_pending_at(now_ms: u64, until_ms: u64) -> bool {
    now_ms < until_ms
}

/// Called by the vote road when it is assembling a proposed block from the
/// queue and misses `wanted` of its transactions: opens the gate for
/// [`GATE_FOR_BLOCK_WINDOW_MS`] and wakes every held frame, so the missing
/// transactions reach the queue before the road's next attempt. A no-op
/// under `N42_TX_INGEST_GATE_STRICT=1`. See [`GATE_FOR_BLOCK_WINDOW_MS`].
pub fn open_gate_for_block(wanted: usize) {
    if gate_strict() {
        return;
    }
    let now = gate_clock_ms();
    let previous = BLOCK_PENDING_UNTIL_MS.swap(now + GATE_FOR_BLOCK_WINDOW_MS, Ordering::AcqRel);
    BLOCK_PENDING_WANTED.store(u64::try_from(wanted).unwrap_or(u64::MAX), Ordering::Relaxed);
    if !block_pending_at(now, previous) {
        BLOCK_PENDING_EPISODE.fetch_add(1, Ordering::AcqRel);
    }
    GATE.open.notify_waiters();
}

/// Whether the gate is open for a pending block now: `Some(wanted)` while
/// the road's last miss is inside its window.
fn block_pending_now() -> Option<u64> {
    if gate_strict() {
        return None;
    }
    block_pending_at(gate_clock_ms(), BLOCK_PENDING_UNTIL_MS.load(Ordering::Acquire))
        .then(|| BLOCK_PENDING_WANTED.load(Ordering::Relaxed))
}

/// Milliseconds since the process's first gate wait, for the warning's rate
/// limit: 64 connections reach the same deadline in the same millisecond and
/// only one of them needs to say so.
fn gate_clock_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

/// Whether this caller may log a gate warning now; at most one per second
/// node-wide.
/// Whether a dropped-transaction warning may be written now; at most one a
/// second across every door, because a systematic drop is a drop per
/// transaction at half a million a second. The counts on the `ingest` line
/// are the complete record; these lines are the first few, named.
fn drop_warn_allowed() -> bool {
    static NEXT_MS: AtomicU64 = AtomicU64::new(0);
    let now = gate_clock_ms();
    let next = NEXT_MS.load(Ordering::Acquire);
    now >= next
        && NEXT_MS.compare_exchange(next, now + 1_000, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

fn gate_warn_allowed() -> bool {
    static NEXT_MS: AtomicU64 = AtomicU64::new(0);
    let now = gate_clock_ms();
    let next = NEXT_MS.load(Ordering::Acquire);
    now >= next
        && NEXT_MS.compare_exchange(next, now + 1_000, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// Holds a frame until `view` says the gate is open, or until `max_wait`
/// has passed with it still shut.
///
/// Taking the gate's reading as a closure keeps the waiting testable without
/// a pool: the stall this guards against is a reading that never changes.
///
/// Every sleep is capped by whatever deadline comes next (the warning, then
/// the maximum wait), so the wait ends on time even if the watcher's
/// notification never arrives -- which is the other way this could hang, and
/// one a test cannot see.
///
/// `for_block` says whether a proposed block is waiting on this node's held
/// frames (`Some(wanted)`, see [`open_gate_for_block`]); a shut gate lets the
/// frame through while it does.
async fn wait_at_gate(
    view: impl Fn() -> GateView,
    for_block: impl Fn() -> Option<u64>,
    max_wait: Option<std::time::Duration>,
) -> GateExit {
    // The runtime's clock, not the system's: it is the one the sleeps below
    // are measured against, so the deadline and the sleeps cannot disagree --
    // and a test can drive both by pausing it.
    let started = tokio::time::Instant::now();
    let mut warned = false;
    loop {
        // Registered before the reading is taken: a waiter that checks first
        // and registers after can miss the notification that answers it.
        let notified = GATE.open.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let seen = view();
        if seen.open {
            return GateExit::Open(started.elapsed());
        }
        let waited = started.elapsed();
        if let Some(wanted) = for_block() {
            GATE_OPENED_FOR_BLOCK.fetch_add(1, Ordering::Relaxed);
            let episode = BLOCK_PENDING_EPISODE.load(Ordering::Acquire);
            if BLOCK_PENDING_LOGGED.swap(episode, Ordering::AcqRel) != episode {
                info!(
                    target: "n42.tx_ingest",
                    depth = seen.depth,
                    limit = seen.limit,
                    wanted,
                    waited_ms = waited.as_millis() as u64,
                    waiting = GATE.waiting.load(Ordering::Relaxed),
                    "the ingest gate opened for a proposed block this node misses transactions of"
                );
            }
            return GateExit::ForBlock(waited);
        }
        if !warned && waited >= GATE_WARN_AFTER {
            // Set whether or not the line is emitted: it is what takes the
            // warning off the sleep cap below, and a waiter that keeps the
            // deadline after the rate limit swallowed its line would spin on
            // a cap of zero.
            warned = true;
            if gate_warn_allowed() {
                warn!(
                    target: "n42.tx_ingest",
                    waited_ms = waited.as_millis() as u64,
                    depth = seen.depth,
                    limit = seen.limit,
                    waiting = GATE.waiting.load(Ordering::Relaxed),
                    "a frame has been held at the ingest gate; only a canonical block pruning this node's queue reopens it"
                );
            }
        }
        if let Some(max) = max_wait
            && waited >= max
        {
            let forced = GATE_FORCED.fetch_add(1, Ordering::Relaxed) + 1;
            if gate_warn_allowed() {
                warn!(
                    target: "n42.tx_ingest",
                    waited_ms = waited.as_millis() as u64,
                    depth = seen.depth,
                    limit = seen.limit,
                    forced,
                    "the ingest gate did not reopen within its maximum wait; letting the frame through so the generator is not blocked for ever"
                );
            }
            return GateExit::Forced(waited);
        }
        GATE.waiting.fetch_add(1, Ordering::Relaxed);
        match gate_sleep_cap(waited, warned, max_wait) {
            Some(cap) => {
                // A lapsed timeout is the deadline, not an error: the loop
                // re-reads the gate and decides.
                let _ = tokio::time::timeout(cap, notified).await;
            }
            None => notified.await,
        }
        GATE.waiting.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How long this waiter may sleep before it must look again: the time left
/// to the next deadline, or `None` when there is none and the watcher's
/// notification is the only thing to wait for.
fn gate_sleep_cap(
    waited: std::time::Duration,
    warned: bool,
    max_wait: Option<std::time::Duration>,
) -> Option<std::time::Duration> {
    let to_warn = (!warned).then(|| GATE_WARN_AFTER.saturating_sub(waited));
    let to_max = max_wait.map(|max| max.saturating_sub(waited));
    match (to_warn, to_max) {
        (Some(warn), Some(max)) => Some(warn.min(max)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// Polls the gate every `GATE_POLL` while anyone is waiting on it, and wakes
/// every waiter when it is open; idles at a slower rate otherwise.
fn spawn_gate_watcher<P>(pool: P, head: std::sync::Arc<AtomicU64>, gate: usize, allowance: u64)
where
    P: TransactionPool + 'static,
    P::Transaction: 'static,
{
    tokio::spawn(async move {
        loop {
            if GATE.waiting.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(GATE_POLL * 10).await;
                continue;
            }
            tokio::time::sleep(GATE_POLL).await;
            if gate_open(&pool, &head, gate, allowance) {
                GATE.open.notify_waiters();
            }
        }
    });
}

/// `N42_TX_INGEST_UNBUFFERED`, read once.
fn unbuffered_reads() -> bool {
    static UNBUFFERED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *UNBUFFERED.get_or_init(|| std::env::var("N42_TX_INGEST_UNBUFFERED").is_ok())
}

/// What the gate and the frame's answer report as the node's depth.
///
/// `gate_len`, not `len`: a lane parked behind a hole holds transactions no
/// build can take until the hole is filled, and counting them shuts the gate
/// on supply the node is starving for. loop209 Pa node3 spent fifteen
/// seconds in exactly that state -- depth 569,520 against a gate of 543,333,
/// all of it parked, `rate` down to 30,591/s, its own blocks empty so
/// nothing pruned it, and only the tenure change let it out.
fn queue_depth<P: TransactionPool + 'static>(pool: &P) -> usize
where
    P::Transaction: 'static,
{
    match n42_tx_queue::global::<P::Transaction>() {
        Some(queue) => queue.gate_len(),
        None => pool.pool_size().pending,
    }
}

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
/// Prints the ingest's rate and time split every five seconds, once.
fn spawn_stats_reporter() {
    tokio::spawn(async move {
        let slots = recovery_slot_count();
        let mut last = (std::time::Instant::now(), 0u64, 0u64, 0u64, 0u64, 0u64);
        let mut last_reply = (0u64, 0u64, 0u64, 0u64, 0u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let now = std::time::Instant::now();
            let (frames, txs, recover, pool, busy) = (
                STATS.frames.load(Ordering::Relaxed),
                STATS.txs.load(Ordering::Relaxed),
                STATS.recover_ns.load(Ordering::Relaxed),
                STATS.pool_ns.load(Ordering::Relaxed),
                STATS.busy_ns.load(Ordering::Relaxed),
            );
            let dframes = frames - last.1;
            if dframes > 0 {
                let dtxs = txs - last.2;
                let secs = now.duration_since(last.0).as_secs_f64();
                let dbusy = busy - last.5;
                let drecover = recover - last.3;
                // How much of the slots' capacity the recovery used: busy
                // time over slots x interval. Under 100% with the generator
                // waiting says the slots idle between frames (a pipeline
                // problem); at 100% they are the ceiling (a CPU problem).
                let slots_busy_pct = slots
                    .map(|slots| (dbusy as f64 / 1e9 / (slots as f64 * secs) * 100.0) as u64);
                let (reply, gate_ns, chan, acq, spawn) = (
                    STATS.reply_ns.load(Ordering::Relaxed),
                    STATS.gate_ns.load(Ordering::Relaxed),
                    STATS.chan_ns.load(Ordering::Relaxed),
                    STATS.acq_ns.load(Ordering::Relaxed),
                    STATS.spawn_ns.load(Ordering::Relaxed),
                );
                let (reply_us, gate_us, chan_us, acq_us, spawn_us) = (
                    (reply - last_reply.0) / dframes / 1_000,
                    (gate_ns - last_reply.1) / dframes / 1_000,
                    (chan - last_reply.2) / dframes / 1_000,
                    (acq - last_reply.3) / dframes / 1_000,
                    (spawn - last_reply.4) / dframes / 1_000,
                );
                last_reply = (reply, gate_ns, chan, acq, spawn);
                info!(
                    target: "n42.tx_ingest",
                    frames = dframes,
                    txs = dtxs,
                    rate = (dtxs as f64 / secs) as u64,
                    recover_ms_per_frame = drecover / dframes / 1_000_000,
                    pool_ms_per_frame = (pool - last.4) / dframes / 1_000_000,
                    recover_us_per_tx = drecover / dtxs.max(1) / 1_000,
                    busy_us_per_tx = dbusy / dtxs.max(1) / 1_000,
                    slot_wait_us_per_tx = drecover.saturating_sub(dbusy) / dtxs.max(1) / 1_000,
                    slots_busy_pct,
                    pool_us_per_tx = (pool - last.4) / dtxs.max(1) / 1_000,
                    reply_us_per_frame = reply_us,
                    gate_us_per_frame = gate_us,
                    chan_us_per_frame = chan_us,
                    acq_us_per_frame = acq_us,
                    spawn_us_per_frame = spawn_us,
                    altsig_txs = STATS.altsig_txs.load(Ordering::Relaxed),
                    altsig_batches = STATS.altsig_batches.load(Ordering::Relaxed),
                    // The supply's split: what this node paid a signature
                    // for here, and what it queued on the frame's word and
                    // will pay for at its builder or on its vote road.
                    verified_at_ingest = STATS.verified_at_ingest.load(Ordering::Relaxed),
                    claimed = STATS.claimed.load(Ordering::Relaxed),
                    shard_verified = STATS.shard_verified.load(Ordering::Relaxed),
                    shard_claimed = STATS.shard_claimed.load(Ordering::Relaxed),
                    // Any of these non-zero is a hole: the frame was
                    // acknowledged and the transaction never reached the
                    // queue.
                    dropped_decode = STATS.dropped_decode.load(Ordering::Relaxed),
                    dropped_signature = STATS.dropped_signature.load(Ordering::Relaxed),
                    dropped_altsig = STATS.dropped_altsig.load(Ordering::Relaxed),
                    dropped_altsig_disabled = STATS.dropped_altsig_disabled.load(Ordering::Relaxed),
                    // Cumulative: frames noted in the queue's frame index,
                    // and frames with a dropped transaction (never whole).
                    frames_admitted = STATS.frames_admitted.load(Ordering::Relaxed),
                    frames_unaligned = STATS.frames_unaligned.load(Ordering::Relaxed),
                    // Non-zero means the gate stopped reopening and frames
                    // were let through on the deadline; the round is not
                    // comparable and a node has stopped draining its queue.
                    gate_forced = GATE_FORCED.load(Ordering::Relaxed),
                    // Frames let through a shut gate because this node's
                    // vote road missed a proposed block's transactions
                    // (defect 17); cumulative.
                    gate_opened_for_block = GATE_OPENED_FOR_BLOCK.load(Ordering::Relaxed),
                    "ingest"
                );
            }
            last = (now, frames, txs, recover, pool, busy);
        }
    });
}

/// Transactions a block holds at the tier the gate is sized for, from
/// `N42_TX_INGEST_BLOCK_TXS`; the allowance the gate grants per block the
/// pool has yet to hear of. Zero (the default) is the old gate.
fn block_txs_allowance() -> u64 {
    std::env::var("N42_TX_INGEST_BLOCK_TXS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

pub async fn serve<P>(
    addr: SocketAddr,
    pool: P,
    cache: Option<reth_evm::SenderRecoveryCache>,
    head: std::sync::Arc<AtomicU64>,
) -> std::io::Result<()>
where
    P: TransactionPool + Clone + 'static,
    P::Transaction: PoolTransaction<Pooled = N42PooledTxEnvelope>,
{
    spawn_stats_reporter();
    spawn_gate_watcher(pool.clone(), std::sync::Arc::clone(&head), high_water(), block_txs_allowance());
    let listener = TcpListener::bind(addr).await?;
    info!(
        target: "n42.tx_ingest",
        %addr,
        buffered_reads = !unbuffered_reads(),
        direct_to_queue = direct_to_queue(),
        asynchronous = std::env::var("N42_TX_INGEST_ASYNC").is_ok(),
        senders_claimed = n42_tx_types::senders_claimed_at_ingest(),
        "binary transaction ingest listening"
    );
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(target: "n42.tx_ingest", %err, "accept failed");
                continue;
            }
        };
        let pool = pool.clone();
        let cache = cache.clone();
        let head = std::sync::Arc::clone(&head);
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, pool, cache, head).await {
                debug!(target: "n42.tx_ingest", %peer, %err, "ingest connection ended");
            }
        });
    }
}

async fn serve_connection<P>(
    mut stream: TcpStream,
    pool: P,
    cache: Option<reth_evm::SenderRecoveryCache>,
    head: std::sync::Arc<AtomicU64>,
) -> std::io::Result<()>
where
    P: TransactionPool + Clone + 'static,
    P::Transaction: PoolTransaction<Pooled = N42PooledTxEnvelope>,
    P::Transaction: 'static,
{
    let gate = high_water();
    let allowance = block_txs_allowance();
    // N42_TX_INGEST_ASYNC=1: answer a frame once it is past the gate and
    // admit it in the background, at most ASYNC_FRAMES_IN_FLIGHT frames at a
    // time per connection. The pool's write lock is taken for a block's
    // maintenance and the builder's snapshot, 200-300 ms at 163,000 a block,
    // and a generator whose every worker waits on this server's answer --
    // and, sending to all seven nodes, on the slowest of them -- stops for
    // that long at every block. Answered first, the frames in flight ride the
    // stall out. The answer's "accepted" is then the frame's size: what the
    // pool will not take (a gap, a fee, a full pool) is no longer reported,
    // which is right for a generator that only sends valid transactions and
    // wrong for anything else, so this is not the default.
    let asynchronous = std::env::var("N42_TX_INGEST_ASYNC").is_ok();
    // `N42_INGEST_VERIFY=leader`: a claiming frame's sender is kept as the
    // claim the transaction is queued under, and nothing here verifies it.
    // `N42_INGEST_VERIFY=shard` keeps the claims too: the frame's claim is
    // what the transactions outside this node's shard are admitted under.
    let claimed_senders = n42_tx_types::senders_claimed_at_ingest() || n42_tx_types::ingest_shard().is_some();
    // Recovery runs in parallel, ASYNC_FRAMES_IN_FLIGHT frames at a time, but
    // the pool takes a connection's frames in the order they arrived: one
    // admitter per connection drains them in sequence. Admitting each frame
    // as its recovery finished put a sender's frame k+1 into the pool before
    // its frame k; a builder reading the queue in nonce order then stopped
    // at the hole, and half of a full queue sat behind one (rounds queue3-4).
    let (admit_tx, mut admit_rx) =
        tokio::sync::mpsc::channel::<tokio::task::JoinHandle<(Vec<P::Transaction>, Option<NewFrame>)>>(ASYNC_FRAMES_IN_FLIGHT);
    if asynchronous {
        let pool = pool.clone();
        tokio::spawn(async move {
            while let Some(recovering) = admit_rx.recv().await {
                let started = std::time::Instant::now();
                match recovering.await {
                    Ok((decoded, frame)) => {
                        let _ = admit_decoded(&pool, decoded, frame, started).await;
                    }
                    Err(err) => warn!(target: "n42.tx_ingest", %err, "sender recovery task failed"),
                }
            }
        });
    }
    // Nagle would batch the acknowledgements into the next read's latency, and
    // the point of this path is that nothing waits for a round trip.
    stream.set_nodelay(true)?;
    // Reads go through a buffer: a frame is a 4-byte count and then, per
    // transaction, a 4-byte length and ~110 bytes, and tokio's TcpStream
    // makes a read(2) of each -- two syscalls a transaction, 400,000 a second
    // a node at the flood's rate. Writes stay direct; an answer is 8 bytes
    // and must not wait for company.
    // N42_TX_INGEST_UNBUFFERED=1 restores a read(2) per field, for the A-B-A
    // that separates the buffer from the box.
    let (read_half, mut write_half) = stream.into_split();
    let capacity = if unbuffered_reads() { 0 } else { 1 << 20 };
    let mut stream = tokio::io::BufReader::with_capacity(capacity, read_half);
    loop {
        let header = match stream.read_u32_le().await {
            Ok(header) => header,
            // A generator that has finished simply closes.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        // A claiming frame carries a sender ahead of each transaction. The
        // bytes are read either way -- the stream has to be walked past them
        // -- and kept only where this node is going to use them.
        let (claiming, count) = frame_header(header);
        if count == 0 || count > MAX_FRAME_TXS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame of {count} transactions"),
            ));
        }
        // The frame's transactions share one buffer: each is a slice of it
        // rather than its own allocation (500 a frame, ~350,000 a second a
        // node at the bench tier).
        let mut raws = Vec::with_capacity(count as usize);
        let keep_claims = claiming && claimed_senders;
        let mut claims: Vec<Address> = if keep_claims { Vec::with_capacity(count as usize) } else { Vec::new() };
        let mut frame_buf = bytes::BytesMut::with_capacity(count as usize * 160);
        for _ in 0..count {
            let len = stream.read_u32_le().await? as usize;
            if len == 0 || len > MAX_TX_BYTES as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("transaction of {len} bytes"),
                ));
            }
            if claiming {
                let mut claim = [0u8; 20];
                stream.read_exact(&mut claim).await?;
                if keep_claims {
                    claims.push(Address::from(claim));
                }
            }
            frame_buf.resize(len, 0);
            stream.read_exact(&mut frame_buf[..]).await?;
            raws.push(Bytes::from(frame_buf.split_to(len).freeze()));
        }
        // The gate. Not a refusal and not a drop: the frame is held until the
        // chain has taken a block out of the pool, and the client hears nothing
        // until then, which is the whole difference between backpressure and a
        // generator burning its budget on retries.
        //
        // Read off the pool's size counters, not `pending_transactions()`:
        // that one takes the pool's read lock and clones every pending
        // transaction's `Arc` into a fresh `Vec`, which at a 100,000-deep pool
        // polled every 2 ms by 32 connections is a few hundred million refcount
        // touches a second under the same lock the pool admits through.
        // The gate, on what a builder could use rather than on `pending` as
        // the pool counts it: a block's transactions stay pending until the
        // pool hears the block is canonical, and a follower that has just
        // imported one holds 163,000 of them through its maintenance. Every
        // full-block round reported the deepest pool at the gate while the
        // leader's ran short -- the generator, answered by all seven nodes,
        // throttled by a follower's stale count. So for each block the chain
        // is ahead of the pool, the gate allows one block's worth more.
        // Waiting is on a node-wide notification, not a poll per connection.
        // Sixty-four connections each sleeping 2 ms and re-reading the queue's
        // depth is 32,000 wake-ups and lock takes a second on the node's tokio
        // workers, and it happens only while the gate is shut -- i.e. exactly
        // when a backlog has formed, which is when the followers' import was
        // seen to double (80% of a follower's samples on the runtime's threads
        // in one kernel address). One watcher polls; the waiters sleep.
        // The wait has a deadline: see [`gate_max_wait`]. Nothing here
        // reopens the gate by itself, so a node that has stopped taking
        // blocks would otherwise hold every connection for the rest of the
        // round.
        let frame_read = std::time::Instant::now();
        let (GateExit::Open(at_gate) | GateExit::ForBlock(at_gate) | GateExit::Forced(at_gate)) =
            wait_at_gate(
                || gate_view(&pool, &head, gate, allowance),
                block_pending_now,
                gate_max_wait(),
            )
            .await;
        STATS.gate_ns.fetch_add(at_gate.as_nanos() as u64, Ordering::Relaxed);
        if asynchronous {
            let pending = u32::try_from(queue_depth(&pool)).unwrap_or(u32::MAX);
            let cache = cache.clone();
            let acquiring = std::time::Instant::now();
            // Decoded here, on the connection's task, before the slot is
            // taken: the slots are the ingest's bound (16 a node at 94-99%
            // busy, 48-50 us a transaction, round 39), and the RLP decode is
            // not secp256k1's work to wait for.
            let sent = raws.len();
            let (pooled, claims) = decode_frame::<P>(raws, claims);
            // What is acknowledged, and it is the decoded count and not the
            // offered one: the generator advances a sender's nonce by the
            // answer, so acknowledging a transaction this node then threw
            // away leaves that nonce in neither the queue nor a block, and
            // every later nonce of that sender queues behind the hole for
            // good. The recovery still runs after the answer -- that is what
            // the async path is -- so what it drops is counted in the
            // `ingest` line's `dropped_*` instead.
            let offered = u32::try_from(pooled.len()).unwrap_or(u32::MAX);
            let slot = std::sync::Arc::clone(recovery_slots())
                .acquire_owned()
                .await
                .expect("the recovery semaphore is never closed");
            let granted = std::time::Instant::now();
            STATS.acq_ns.fetch_add(granted.duration_since(acquiring).as_nanos() as u64, Ordering::Relaxed);
            let recovering = tokio::task::spawn_blocking(move || {
                let _slot = slot;
                apply_recovery_nice();
                apply_recovery_affinity();
                let busy = std::time::Instant::now();
                STATS.spawn_ns.fetch_add(busy.duration_since(granted).as_nanos() as u64, Ordering::Relaxed);
                let decoded = recover_frame::<P>(sent, pooled, claims, cache.as_ref());
                STATS.busy_ns.fetch_add(busy.elapsed().as_nanos() as u64, Ordering::Relaxed);
                decoded
            });
            // Full when ASYNC_FRAMES_IN_FLIGHT frames are still recovering or
            // waiting for the pool: the answer waits for a slot, as before.
            let chan = std::time::Instant::now();
            if admit_tx.send(recovering).await.is_err() {
                return Ok(());
            }
            STATS.chan_ns.fetch_add(chan.elapsed().as_nanos() as u64, Ordering::Relaxed);
            write_half.write_u32_le(offered).await?;
            write_half.write_u32_le(pending).await?;
            STATS.reply_ns.fetch_add(frame_read.elapsed().as_nanos() as u64, Ordering::Relaxed);
            continue;
        }
        let accepted = admit(&pool, raws, claims, cache.clone()).await;
        let pending = u32::try_from(queue_depth(&pool)).unwrap_or(u32::MAX);
        write_half.write_u32_le(accepted).await?;
        write_half.write_u32_le(pending).await?;
    }
}

/// Hands a frame to the pool and counts what it took.
///
/// Decoding failures are counted as refusals rather than closing the
/// connection: one malformed transaction in a batch says nothing about the
/// next one, and a generator that sends one is not an attacker, it is a
/// generator with a bug.
/// Where the ingest's time goes, summed over every connection, and printed
/// every five seconds by [`serve`]: a generator whose workers wait 76% of
/// their time for this server's answer needs the server to say which half
/// of the answer -- recovering the senders, or the pool taking them -- it
/// was waiting for.
struct IngestStats {
    frames: AtomicU64,
    txs: AtomicU64,
    /// Wall time from a frame's arrival at `admit` to its senders recovered:
    /// the wait for a recovery slot plus the recovery itself.
    recover_ns: AtomicU64,
    /// Time spent inside the recovery task alone, on a slot -- the CPU cost
    /// of decoding and secp256k1, without the queue for a slot in front of
    /// it. `recover_ns - busy_ns` is that queue.
    busy_ns: AtomicU64,
    pool_ns: AtomicU64,
    /// Per frame on the connection's read loop: from the frame fully read to
    /// its answer written (`reply_ns`), of which the gate (`gate_ns`) and the
    /// wait for room in the connection's admission channel (`chan_ns`). What
    /// the generator sees as an answer's latency, minus the wire.
    reply_ns: AtomicU64,
    /// 0x50 transactions verified here, and the batches they went through.
    altsig_txs: AtomicU64,
    altsig_batches: AtomicU64,
    /// Senders this ingest computed from the signature, and senders it took
    /// as the frame's claim without checking one
    /// (`N42_INGEST_VERIFY=leader`). Their sum is what reached the queue,
    /// and `claimed` is the work this node moved to its builder and its
    /// vote road.
    verified_at_ingest: AtomicU64,
    claimed: AtomicU64,
    /// `N42_INGEST_VERIFY=shard` only: transactions of a claiming frame this
    /// node routed to its own verification (their hash is in its shard), and
    /// those it queued on the claim with no verification anywhere. Both are
    /// also inside `verified_at_ingest` / `claimed`.
    shard_verified: AtomicU64,
    shard_claimed: AtomicU64,
    gate_ns: AtomicU64,
    chan_ns: AtomicU64,
    /// Waiting for a recovery slot (`acq_ns`), and from the slot granted to
    /// the recovery task actually running on a blocking thread (`spawn_ns`):
    /// the hand-off through the runtime, paid once per frame.
    acq_ns: AtomicU64,
    spawn_ns: AtomicU64,
    /// Transactions this ingest took off a frame and never queued, by door:
    /// undecodable, a signature that did not recover, a 0x50 signature that
    /// did not verify, and 0x50 on a chain that does not admit it.
    ///
    /// A frame is acknowledged by count, and the generator advances a
    /// sender's nonce by what was acknowledged, so every one of these is a
    /// permanent hole in that sender's lane on this node -- and every one of
    /// them used to be a `debug!` nobody runs at. On the async path the
    /// answer goes out before the recovery has run, so these can only be
    /// counted here; the decode is the one that now happens first, so the
    /// answer can tell the truth about it.
    dropped_decode: AtomicU64,
    dropped_signature: AtomicU64,
    dropped_altsig: AtomicU64,
    dropped_altsig_disabled: AtomicU64,
    /// Frames the ingest kept every transaction of, noted in the queue's
    /// frame index.
    frames_admitted: AtomicU64,
    /// Frames it dropped any transaction of: never referenceable whole.
    frames_unaligned: AtomicU64,
}

static STATS: IngestStats = IngestStats {
    frames: AtomicU64::new(0),
    txs: AtomicU64::new(0),
    recover_ns: AtomicU64::new(0),
    busy_ns: AtomicU64::new(0),
    pool_ns: AtomicU64::new(0),
    reply_ns: AtomicU64::new(0),
    gate_ns: AtomicU64::new(0),
    chan_ns: AtomicU64::new(0),
    dropped_decode: AtomicU64::new(0),
    dropped_signature: AtomicU64::new(0),
    dropped_altsig: AtomicU64::new(0),
    dropped_altsig_disabled: AtomicU64::new(0),
    frames_admitted: AtomicU64::new(0),
    frames_unaligned: AtomicU64::new(0),
    acq_ns: AtomicU64::new(0),
    spawn_ns: AtomicU64::new(0),
    altsig_batches: AtomicU64::new(0),
    altsig_txs: AtomicU64::new(0),
    verified_at_ingest: AtomicU64::new(0),
    claimed: AtomicU64::new(0),
    shard_verified: AtomicU64::new(0),
    shard_claimed: AtomicU64::new(0),
};


async fn admit<P>(
    pool: &P,
    raws: Vec<Bytes>,
    claims: Vec<Address>,
    cache: Option<reth_evm::SenderRecoveryCache>,
) -> u32
where
    P: TransactionPool + 'static,
    P::Transaction: PoolTransaction<Pooled = N42PooledTxEnvelope> + 'static,
{
    // Decoding and sender recovery are CPU work -- ~50 us of secp256k1 per
    // transaction, so a 10,000-transaction frame is half a second -- and they
    // used to run on the runtime's worker thread, where every other connection
    // on that thread, and the pool's own futures, waited behind them. Blocking
    // threads are for exactly this.
    let started = std::time::Instant::now();
    let sent = raws.len();
    let (pooled, claims) = decode_frame::<P>(raws, claims);
    let slot = std::sync::Arc::clone(recovery_slots())
        .acquire_owned()
        .await
        .expect("the recovery semaphore is never closed");
    let decoded = match tokio::task::spawn_blocking(move || {
        let _slot = slot;
        apply_recovery_nice();
        apply_recovery_affinity();
        let busy = std::time::Instant::now();
        let decoded = recover_frame::<P>(sent, pooled, claims, cache.as_ref());
        STATS.busy_ns.fetch_add(busy.elapsed().as_nanos() as u64, Ordering::Relaxed);
        decoded
    })
    .await
    {
        Ok(decoded) => decoded,
        Err(err) => {
            warn!(target: "n42.tx_ingest", %err, "sender recovery task failed");
            return 0;
        }
    };
    let (decoded, frame) = decoded;
    admit_decoded(pool, decoded, frame, started).await
}

/// Puts recovered transactions into the pool and counts them; `started` is
/// when their frame's recovery began.
async fn admit_decoded<P>(
    pool: &P,
    decoded: Vec<P::Transaction>,
    frame: Option<NewFrame>,
    started: std::time::Instant,
) -> u32
where
    P: TransactionPool + 'static,
    P::Transaction: 'static,
{
    if decoded.is_empty() {
        return 0;
    }
    // A frame admitted whole, for the queue's frame index: noted after its
    // transactions, whichever door they take into the queue. Nothing reads
    // the index unless the chain builds frame blocks.
    let note_frame = |queue: &n42_tx_queue::TxQueue<P::Transaction>, frame: Option<NewFrame>| {
        if let Some(frame) = frame {
            queue.note_frame(frame);
            STATS.frames_admitted.fetch_add(1, Ordering::Relaxed);
        }
    };
    let recovered_at = started.elapsed();
    let count = decoded.len() as u64;
    // N42_TX_INGEST_DIRECT=1: straight into the builder's queue, past the
    // pool. At a 0.3 s block the pool's maintenance -- a block's removals
    // under the write lock, 200-300 ms at 163,000 -- holds the lock most of
    // the time, `add_transactions` starves behind it, and the generator's
    // rate collapses in step with the chain's speed: the faster the chain,
    // the less it is fed. The queue is nonce-ordered per sender, deduplicated,
    // pruned by every canonical block on every node, and the pool then
    // carries only RPC traffic. What is skipped is the pool's validation --
    // balance and fee -- which the builder's execution catches by dropping;
    // right for a generator that funds every sender, and the reason this is
    // opt-in.
    if direct_to_queue() {
        if let Some(queue) = n42_tx_queue::global::<P::Transaction>() {
            queue.push(decoded);
            note_frame(&queue, frame);
            STATS.frames.fetch_add(1, Ordering::Relaxed);
            STATS.txs.fetch_add(count, Ordering::Relaxed);
            STATS.recover_ns.fetch_add(recovered_at.as_nanos() as u64, Ordering::Relaxed);
            STATS.pool_ns.fetch_add((started.elapsed() - recovered_at).as_nanos() as u64, Ordering::Relaxed);
            return u32::try_from(count).unwrap_or(u32::MAX);
        }
    }
    // `External`, the same origin `eth_sendRawTransaction` uses for a
    // transaction that did not come from this node: it is validated, priced and
    // gossiped exactly as one that arrived over RPC.
    let results = pool.add_transactions(TransactionOrigin::External, decoded).await;
    if let Some(queue) = n42_tx_queue::global::<P::Transaction>() {
        note_frame(&queue, frame);
    }
    STATS.frames.fetch_add(1, Ordering::Relaxed);
    STATS.txs.fetch_add(count, Ordering::Relaxed);
    STATS.recover_ns.fetch_add(recovered_at.as_nanos() as u64, Ordering::Relaxed);
    STATS.pool_ns.fetch_add((started.elapsed() - recovered_at).as_nanos() as u64, Ordering::Relaxed);
    // Accepted, for a sender that advances its nonce on the answer: the pool
    // took it, or already had it, or the chain already mined it. The last two
    // arrive when the same frame reaches every node (`tx_flood --ingest-all`)
    // and one of them is ahead -- reporting them as refusals made the
    // generator re-send the same nonce to every node forever, and every pool
    // that had it refuse it again, until the sender gave up as stalled. What
    // is *not* accepted is what a re-send would still not fix: a gap, a fee,
    // a full pool.
    let accepted = results
        .iter()
        .filter(|outcome| match outcome {
            Ok(_) => true,
            Err(err) => {
                matches!(err.kind, reth_transaction_pool::error::PoolErrorKind::AlreadyImported)
                    || matches!(&err.kind, reth_transaction_pool::error::PoolErrorKind::InvalidTransaction(invalid) if invalid.is_nonce_too_low())
            }
        })
        .count();
    u32::try_from(accepted).unwrap_or(u32::MAX)
}

/// Decodes a frame's transactions and recovers their senders, on the calling
/// thread.
/// The pooled transaction type of a pool.
type PooledOf<P> = <<P as TransactionPool>::Transaction as PoolTransaction>::Pooled;

/// Decodes a frame's raw transactions; an undecodable one is dropped with a
/// debug line rather than closing the connection. No signature work here.
///
/// `claims` is either empty -- the frame claimed nothing, or this node does
/// not take claims -- or one entry per raw transaction, and what comes back
/// beside the decoded transactions is the same list with the undecodable
/// ones removed, so the two stay aligned.
fn decode_frame<P>(raws: Vec<Bytes>, claims: Vec<Address>) -> (Vec<PooledOf<P>>, Vec<Address>)
where
    P: TransactionPool,
{
    let claimed = claims.len() == raws.len() && !claims.is_empty();
    let mut decoded = Vec::with_capacity(raws.len());
    let mut kept = if claimed { Vec::with_capacity(raws.len()) } else { Vec::new() };
    for (at, raw) in raws.into_iter().enumerate() {
        match <PooledOf<P> as alloy_eips::Decodable2718>::decode_2718_exact(raw.as_ref()) {
            Ok(pooled) => {
                decoded.push(pooled);
                if claimed {
                    kept.push(claims[at]);
                }
            }
            Err(err) => {
                let dropped = STATS.dropped_decode.fetch_add(1, Ordering::Relaxed) + 1;
                if drop_warn_allowed() {
                    warn!(target: "n42.tx_ingest", %err, dropped, "undecodable transaction: a hole in its sender's lane");
                }
            }
        }
    }
    (decoded, kept)
}

/// [`recover_decoded`], and the frame it was: `sent` is how many raw
/// transactions the frame carried, and a frame the ingest kept every one of
/// comes back described for the queue's frame index ([`frame_of`]).
fn recover_frame<P>(
    sent: usize,
    pooled: Vec<PooledOf<P>>,
    claims: Vec<Address>,
    cache: Option<&reth_evm::SenderRecoveryCache>,
) -> (Vec<P::Transaction>, Option<NewFrame>)
where
    P: TransactionPool,
    P::Transaction: PoolTransaction<Pooled = N42PooledTxEnvelope>,
{
    let hashes: Vec<B256> = pooled.iter().map(|tx| *tx.hash()).collect();
    let recovered = recover_decoded::<P>(pooled, claims, cache);
    let frame = frame_of(sent, hashes, &recovered);
    if frame.is_none() {
        STATS.frames_unaligned.fetch_add(1, Ordering::Relaxed);
    }
    (recovered, frame)
}

/// A frame's record for the queue's frame index, or `None` when the frame
/// is *unaligned*: the ingest dropped one of its `sent` transactions (an
/// undecodable one, a signature that did not verify, a type the chain does
/// not enable), so the frame can never be referenced whole.
///
/// `hashes` are the decoded transactions' hashes in frame order; the
/// recovery may return them in another order (a frame's 0x50 transactions
/// come back after its secp256k1 ones), so they are matched by hash. The
/// frame's id is its root over `hashes` ([`n42_tx_types::frame_root`]).
fn frame_of<T: PoolTransaction>(sent: usize, hashes: Vec<B256>, recovered: &[T]) -> Option<NewFrame> {
    if hashes.is_empty() || hashes.len() != sent || recovered.len() != hashes.len() {
        return None;
    }
    let in_order = recovered.iter().zip(&hashes).all(|(tx, hash)| tx.hash() == hash);
    let mut members = Vec::with_capacity(hashes.len());
    let mut gas = 0u64;
    if in_order {
        for tx in recovered {
            members.push((tx.sender(), tx.nonce()));
            gas = gas.saturating_add(tx.gas_limit());
        }
    } else {
        let by_hash: alloy_primitives::map::B256HashMap<&T> =
            recovered.iter().map(|tx| (*tx.hash(), tx)).collect();
        for hash in &hashes {
            let tx = by_hash.get(hash)?;
            members.push((tx.sender(), tx.nonce()));
            gas = gas.saturating_add(tx.gas_limit());
        }
    }
    let id = n42_tx_types::frame_root(&hashes);
    Some(NewFrame { id, hashes, members, gas })
}

/// Recovers the senders of decoded transactions, on a recovery slot.
///
/// Through the cache when there is one, so the sender this costs ~40 us to
/// compute is still there when the block carrying the transaction is
/// imported. Without it the work is simply done twice: reth's cache has
/// exactly two consumers -- devp2p transaction gossip and block import -- and
/// both recover-or-insert, so on a fleet that runs `--disable-tx-gossip` and
/// admits over this path, nothing else populates it before import.
///
/// 0x50 (Ed25519) transactions are verified together: `N42_ED25519_BATCH`
/// at a time through the cofactored batch equation (13 us a signature at 64
/// against 29-63 us of ecrecover on this host), a failed batch retried one
/// by one. Their senders go to the shared [`AltSigSenderCache`], which the
/// block import and the engine's payload conversion read.
/// `claims`, when it is not empty, is one sender per transaction and this
/// node is in `N42_INGEST_VERIFY=leader`: the transaction is queued under
/// the claim without a signature being checked here. Nothing downstream
/// takes a claim for an answer -- the builder verifies what it includes and
/// the vote road verifies what a block carries -- so the only thing a wrong
/// claim can do is put one transaction in the wrong lane, where no build can
/// use it.
fn recover_decoded<P>(
    pooled: Vec<PooledOf<P>>,
    claims: Vec<Address>,
    cache: Option<&reth_evm::SenderRecoveryCache>,
) -> Vec<P::Transaction>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction<Pooled = N42PooledTxEnvelope>,
{
    recover_decoded_in::<P>(pooled, claims, cache, n42_tx_types::ingest_shard())
}

/// Whether, under `N42_INGEST_VERIFY=shard` as shard `(index, count)`, the
/// transaction `hash` is this node's to verify at ingest.
fn in_my_shard(hash: &alloy_primitives::B256, (index, count): (u64, u64)) -> bool {
    n42_tx_types::shard_owner(hash, count) == index
}

/// [`recover_decoded`] with this node's shard given rather than read.
///
/// `shard` is `Some` only under `N42_INGEST_VERIFY=shard`, and matters only
/// for a claiming frame: a transaction in this node's shard goes through the
/// verification exactly as under `all`; any other is queued under its claim
/// and the claim is recorded as its sender (the 0x50 sender cache), so the
/// vote road and the payload conversion read it as an answer. **Nothing
/// verifies it anywhere afterwards** -- this is the unsafe benchmark probe of
/// `docs/VERIFY_ONCE_DESIGN.md` form C, correct only while no node and no
/// generator lies. With `shard` `None` this is `leader`/`all` unchanged.
fn recover_decoded_in<P>(
    pooled: Vec<PooledOf<P>>,
    claims: Vec<Address>,
    cache: Option<&reth_evm::SenderRecoveryCache>,
    shard: Option<(u64, u64)>,
) -> Vec<P::Transaction>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction<Pooled = N42PooledTxEnvelope>,
{
    let claimed = claims.len() == pooled.len() && !claims.is_empty();
    let shard = if claimed { shard } else { None };
    let mut shard_claimed_here = 0u64;
    let mut shard_verified_here = 0u64;
    let mut recovered = Vec::with_capacity(pooled.len());
    // The 0x50 transactions for the batch below, each with whether it is in
    // this node's shard: those never take a cache hit, because in shard mode
    // the cache also holds claims (unverified senders) and a claim must not
    // stand in for this node's own verification.
    let mut alt: Vec<(N42PooledTxEnvelope, bool)> = Vec::new();
    // Counted per frame rather than per transaction: these are two lines on
    // one cache line that a dozen recovery threads would otherwise write to
    // half a million times a second between them.
    let mut claimed_here = 0u64;
    let mut verified_here = 0u64;
    for (at, tx) in pooled.into_iter().enumerate() {
        // Shard mode: this node's shard falls through to the verification
        // below, as if the frame had claimed nothing.
        let verify_mine = shard.is_some_and(|shard| in_my_shard(tx.hash(), shard));
        if verify_mine {
            shard_verified_here += 1;
        }
        if claimed && !verify_mine {
            // The 0x50 gate stays where it is: a chain that does not admit
            // the type must not hold one, claim or no claim.
            if tx.is_alt_sig() && !n42_tx_types::alt_sig_enabled() {
                STATS.dropped_altsig_disabled.fetch_add(1, Ordering::Relaxed);
                if drop_warn_allowed() {
                    warn!(target: "n42.tx_ingest", dropped = 1, "a 0x50 transaction on a chain that does not enable them");
                }
                continue;
            }
            if shard.is_some() {
                // Recorded as the sender, unverified, so the road and the
                // payload conversion take it without a signature (probe only).
                if tx.is_alt_sig() {
                    AltSigSenderCache::global().insert(*tx.hash(), claims[at]);
                }
                shard_claimed_here += 1;
            }
            recovered.push(P::Transaction::from_pooled(Recovered::new_unchecked(tx, claims[at])));
            claimed_here += 1;
            continue;
        }
        if tx.is_alt_sig() {
            alt.push((tx, verify_mine));
            continue;
        }
        let result = match cache {
            Some(cache) => <P::Transaction as PoolTransaction>::try_recover_with_cache(tx, cache),
            None => <P::Transaction as PoolTransaction>::try_recover(tx),
        };
        match result {
            Ok(tx) => {
                recovered.push(tx);
                verified_here += 1;
            }
            Err(_) => {
                let dropped = STATS.dropped_signature.fetch_add(1, Ordering::Relaxed) + 1;
                if drop_warn_allowed() {
                    warn!(target: "n42.tx_ingest", dropped, "a signature did not recover: a hole in its sender's lane");
                }
            }
        }
    }
    if alt.is_empty() {
        count_senders(claimed_here, verified_here);
    count_shard(shard_claimed_here, shard_verified_here);
        return recovered;
    }
    if !n42_tx_types::alt_sig_enabled() {
        STATS.dropped_altsig_disabled.fetch_add(alt.len() as u64, Ordering::Relaxed);
        if drop_warn_allowed() {
            warn!(target: "n42.tx_ingest", dropped = alt.len(), "0x50 transactions on a chain that does not enable them");
        }
        count_senders(claimed_here, verified_here);
    count_shard(shard_claimed_here, shard_verified_here);
        return recovered;
    }
    let senders = AltSigSenderCache::global();
    let mut todo: Vec<N42PooledTxEnvelope> = Vec::with_capacity(alt.len());
    for (tx, mine) in alt {
        match (!mine).then(|| senders.get(tx.hash())).flatten() {
            Some(sender) => {
                // A hit is this node's own earlier verification of the same
                // signature, so it counts as verified here.
                recovered.push(P::Transaction::from_pooled(Recovered::new_unchecked(tx, sender)));
                verified_here += 1;
            }
            None => todo.push(tx),
        }
    }
    let batch = ed25519_batch_size();
    let mut verdicts = Vec::with_capacity(todo.len());
    for chunk in todo.chunks(batch) {
        let refs: Vec<&AltSigTx> = chunk
            .iter()
            .filter_map(|tx| match tx {
                N42PooledTxEnvelope::AltSig(tx) => Some(tx),
                N42PooledTxEnvelope::Eth(_) => None,
            })
            .collect();
        verdicts.extend(n42_tx_types::verify_batch(&refs));
        STATS.altsig_batches.fetch_add(1, Ordering::Relaxed);
    }
    STATS.altsig_txs.fetch_add(todo.len() as u64, Ordering::Relaxed);
    // One verdict per transaction, or the zip below would silently drop the
    // tail: `refs` filters, and a filter that ever removed anything would
    // make every later transaction of the batch a hole.
    if verdicts.len() != todo.len() {
        STATS.dropped_altsig.fetch_add((todo.len() - verdicts.len()) as u64, Ordering::Relaxed);
        warn!(
            target: "n42.tx_ingest",
            verdicts = verdicts.len(),
            txs = todo.len(),
            "the 0x50 batch returned fewer verdicts than it was given"
        );
    }
    for (tx, verdict) in todo.into_iter().zip(verdicts) {
        match verdict {
            Ok(sender) => {
                senders.insert(*tx.hash(), sender);
                recovered.push(P::Transaction::from_pooled(Recovered::new_unchecked(tx, sender)));
                verified_here += 1;
            }
            Err(err) => {
                let dropped = STATS.dropped_altsig.fetch_add(1, Ordering::Relaxed) + 1;
                if drop_warn_allowed() {
                    // No sender to name -- that is what failed -- so the
                    // hash and the nonce, which is what the generator's own
                    // log can be read against.
                    warn!(target: "n42.tx_ingest", %err, dropped, hash = ?tx.hash(), "a 0x50 signature did not verify: a hole in its sender's lane");
                }
            }
        }
    }
    count_senders(claimed_here, verified_here);
    count_shard(shard_claimed_here, shard_verified_here);
    recovered
}

/// Adds a frame's tally to the shard mode's counters: transactions queued
/// on the claim and never verified by this node, and transactions routed to
/// this node's own verification because their hash is in its shard.
fn count_shard(claimed: u64, verified: u64) {
    if claimed != 0 {
        STATS.shard_claimed.fetch_add(claimed, Ordering::Relaxed);
    }
    if verified != 0 {
        STATS.shard_verified.fetch_add(verified, Ordering::Relaxed);
    }
}

/// Adds a frame's tally to the ingest's sender counters: how many senders it
/// took as a claim, and how many it computed from the signature.
fn count_senders(claimed: u64, verified: u64) {
    if claimed != 0 {
        STATS.claimed.fetch_add(claimed, Ordering::Relaxed);
    }
    if verified != 0 {
        STATS.verified_at_ingest.fetch_add(verified, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod shard_tests {
    use super::*;
    use alloy_primitives::{Bytes, U256};
    use n42_engine_types::N42PooledTransaction;
    use n42_tx_types::{AltSigTx, TxAltSig, ALG_ED25519};
    use reth_transaction_pool::noop::NoopTransactionPool;

    fn signed(seed: u8, nonce: u64) -> AltSigTx {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        TxAltSig {
            chain_id: 94,
            nonce,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: Address::repeat_byte(0xaa),
            value: U256::from(1u64),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: ALG_ED25519,
            pubkey: Bytes::copy_from_slice(key.verifying_key().as_bytes()),
        }
        .sign_ed25519(&key)
    }

    /// A frame the ingest kept whole is described in frame order, whatever
    /// order the recovery returned it in; one it dropped from is unaligned.
    #[test]
    fn a_frame_is_described_in_frame_order_and_a_dropped_one_is_unaligned() {
        n42_tx_types::set_alt_sig_enabled(true);
        let txs: Vec<AltSigTx> = (0..6u64).map(|i| signed(1 + (i % 2) as u8, 50 + i / 2)).collect();
        let pooled: Vec<N42PooledTxEnvelope> = txs.into_iter().map(N42PooledTxEnvelope::AltSig).collect();
        let hashes: Vec<B256> = pooled.iter().map(|tx| *tx.hash()).collect();
        let (recovered, frame) =
            recover_frame::<NoopTransactionPool<N42PooledTransaction>>(6, pooled.clone(), Vec::new(), None);
        assert_eq!(recovered.len(), 6);
        let frame = frame.expect("every transaction kept");
        assert_eq!(frame.id, n42_tx_types::frame_root(&hashes));
        assert_eq!(frame.hashes, hashes);
        assert_eq!(frame.gas, 6 * 21_000);
        let nonces: Vec<u64> = frame.members.iter().map(|(_, nonce)| *nonce).collect();
        assert_eq!(nonces, vec![50, 50, 51, 51, 52, 52]);
        // Reversed recovery order: still described in frame order.
        let reversed: Vec<_> = recovered.iter().rev().cloned().collect();
        assert_eq!(frame_of(6, hashes.clone(), &reversed), Some(frame));
        // The frame carried seven and one was undecodable: unaligned.
        assert_eq!(frame_of(7, hashes.clone(), &recovered), None);
        // One did not verify: unaligned.
        assert_eq!(frame_of(6, hashes, &recovered[..5]), None);
    }

    /// A claiming frame in shard mode: exactly the transactions whose hash
    /// is in this node's shard are verified (and come out under their real
    /// sender, whatever the claim said); every other one is queued under its
    /// claim, unverified, and the claim is what the sender cache records.
    #[test]
    fn a_frame_in_shard_mode_verifies_exactly_its_shard() {
        n42_tx_types::set_alt_sig_enabled(true);
        let shard = (1u64, 3u64);
        let bogus = Address::repeat_byte(0xee);
        let txs: Vec<AltSigTx> = (0..48u64).map(|i| signed(1 + (i % 4) as u8, 1_000 + i)).collect();
        let real: Vec<Address> = txs
            .iter()
            .map(|tx| n42_tx_types::verify_batch(&[tx]).pop().expect("one verdict").expect("signed"))
            .collect();
        let mine: Vec<bool> = txs.iter().map(|tx| in_my_shard(tx.hash(), shard)).collect();
        // The recovery returns claimed transactions first and the verified
        // batch after them, so the output is matched by hash, not by index.
        let expected_by_hash: std::collections::HashMap<alloy_primitives::B256, (Address, bool)> = txs
            .iter()
            .enumerate()
            .map(|(at, tx)| (*tx.hash(), (if mine[at] { real[at] } else { bogus }, mine[at])))
            .collect();
        let owned = mine.iter().filter(|m| **m).count() as u64;
        assert!(owned > 0 && owned < 48, "a spread across shards: {owned}");
        let pooled: Vec<N42PooledTxEnvelope> = txs.into_iter().map(N42PooledTxEnvelope::AltSig).collect();
        let (verified_before, claimed_before) =
            (STATS.shard_verified.load(Ordering::Relaxed), STATS.shard_claimed.load(Ordering::Relaxed));
        let out = recover_decoded_in::<NoopTransactionPool<N42PooledTransaction>>(
            pooled,
            vec![bogus; 48],
            None,
            Some(shard),
        );
        assert_eq!(out.len(), 48);
        for tx in out.iter() {
            let (expected, in_shard) = expected_by_hash[tx.hash()];
            assert_eq!(tx.sender(), expected, "transaction {:?}, in shard: {in_shard}", tx.hash());
            assert_eq!(AltSigSenderCache::global().get(tx.hash()), Some(expected));
        }
        // Only this test runs the shard path, so the global counters move by
        // exactly this frame.
        assert_eq!(STATS.shard_verified.load(Ordering::Relaxed) - verified_before, owned);
        assert_eq!(STATS.shard_claimed.load(Ordering::Relaxed) - claimed_before, 48 - owned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Duration;

    /// A gate reading a test drives: `depth` against a fixed limit, exactly
    /// the shape [`gate_view`] returns from the queue.
    fn view_of(depth: Arc<AtomicUsize>, limit: u64) -> impl Fn() -> GateView {
        move || {
            let depth = depth.load(Ordering::Relaxed) as u64;
            GateView { open: depth < limit, depth, limit }
        }
    }

    /// loop190Y1a: node5's execution layer stopped at block 382 with
    /// `queued=411428` against a gate of 407,500, so nothing pruned its
    /// queue again and the depth never fell. The chain's other nodes then
    /// ran dry and built empty blocks, which prune nothing -- so no reading
    /// this gate ever takes can differ from the last one. Without a deadline
    /// the frame waits for the rest of the round, and with it every flood
    /// worker, which reads all seven nodes' answers to every frame.
    #[tokio::test(start_paused = true)]
    async fn a_gate_that_never_reopens_holds_a_frame_for_ever() {
        let depth = Arc::new(AtomicUsize::new(411_428));
        let held = tokio::time::timeout(
            Duration::from_secs(600),
            wait_at_gate(view_of(depth, 407_500), || None, None),
        )
        .await;
        assert!(held.is_err(), "the frame was let through, but nothing had reopened the gate");
    }

    /// The same stall with the deadline: the frame goes through, so the
    /// generator keeps running and the node that stopped is named in a WARN
    /// instead of silently taking the round with it.
    #[tokio::test(start_paused = true)]
    async fn a_gate_that_never_reopens_lets_a_frame_through_on_the_deadline() {
        let forced_before = GATE_FORCED.load(Ordering::Relaxed);
        let depth = Arc::new(AtomicUsize::new(411_428));
        let max = Duration::from_secs(15);
        match wait_at_gate(view_of(depth, 407_500), || None, Some(max)).await {
            GateExit::Forced(waited) => assert!(waited >= max, "{waited:?} is short of {max:?}"),
            GateExit::Open(waited) | GateExit::ForBlock(waited) => {
                panic!("the gate was shut the whole time, yet it opened after {waited:?}")
            }
        }
        assert!(
            GATE_FORCED.load(Ordering::Relaxed) > forced_before,
            "the forced frame was not counted for the round's stats line"
        );
    }

    /// A frame that claims nothing reads exactly as it always did, and one
    /// that claims is the same count with one bit set. The bit is above
    /// every count this server accepts, so the two can never be confused.
    #[test]
    fn a_frame_header_says_whether_it_claims() {
        assert_eq!(frame_header(500), (false, 500));
        assert_eq!(frame_header(500 | FRAME_CLAIMS_SENDERS), (true, 500));
        assert_eq!(frame_header(MAX_FRAME_TXS), (false, MAX_FRAME_TXS));
    }

    /// The healthy path is unchanged: an open gate holds nothing.
    #[tokio::test(start_paused = true)]
    async fn an_open_gate_does_not_hold_a_frame() {
        let depth = Arc::new(AtomicUsize::new(10));
        let exit = wait_at_gate(view_of(depth, 407_500), || None, Some(Duration::from_secs(15))).await;
        assert!(
            matches!(exit, GateExit::Open(waited) if waited < Duration::from_millis(1)),
            "{exit:?}"
        );
    }

    /// A gate the chain does reopen is waited on and then passed: the
    /// deadline must not turn ordinary backpressure into a forced admission.
    #[tokio::test(start_paused = true)]
    async fn a_gate_the_chain_reopens_is_passed_not_forced() {
        let depth = Arc::new(AtomicUsize::new(411_428));
        let draining = Arc::clone(&depth);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            draining.store(248_428, Ordering::Relaxed);
            GATE.open.notify_waiters();
        });
        match wait_at_gate(view_of(depth, 407_500), || None, Some(Duration::from_secs(15))).await {
            GateExit::Open(waited) => assert!(waited >= Duration::from_millis(400), "{waited:?}"),
            GateExit::Forced(waited) | GateExit::ForBlock(waited) => {
                panic!("a gate that reopened after 400 ms was forced at {waited:?}")
            }
        }
    }

    /// Defect 17: a shut gate that no canonical block will reopen, because
    /// the block it waits for misses the held frames' transactions. Once
    /// the road says so, the frame goes through -- well before the deadline.
    #[tokio::test(start_paused = true)]
    async fn a_shut_gate_opens_for_a_block_that_misses_its_frames() {
        let depth = Arc::new(AtomicUsize::new(872_000));
        let pending = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let road = Arc::clone(&pending);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            road.store(true, Ordering::Relaxed);
            GATE.open.notify_waiters();
        });
        let for_block = move || pending.load(Ordering::Relaxed).then_some(124);
        match wait_at_gate(view_of(depth, 833_333), for_block, Some(Duration::from_secs(2))).await {
            GateExit::ForBlock(waited) => {
                assert!(waited >= Duration::from_millis(60), "{waited:?}");
                assert!(waited < Duration::from_secs(2), "{waited:?}");
            }
            other => panic!("the gate should have opened for the pending block: {other:?}"),
        }
    }

    /// The window: open while the road's last miss is recent, shut after.
    #[test]
    fn a_block_is_pending_only_inside_its_window() {
        assert!(!block_pending_at(1_000, 0), "no miss yet");
        assert!(block_pending_at(1_000, 1_000 + GATE_FOR_BLOCK_WINDOW_MS));
        assert!(!block_pending_at(1_000 + GATE_FOR_BLOCK_WINDOW_MS, 1_000 + GATE_FOR_BLOCK_WINDOW_MS));
    }

    /// The deadline does not depend on the watcher's notification: every
    /// sleep is capped by whichever deadline comes next, so a waiter whose
    /// wake-up is lost still reaches the warning and the maximum wait.
    #[test]
    fn a_sleep_is_capped_by_the_next_deadline() {
        let max = Some(Duration::from_secs(15));
        assert_eq!(gate_sleep_cap(Duration::ZERO, false, max), Some(GATE_WARN_AFTER));
        assert_eq!(
            gate_sleep_cap(Duration::from_secs(3), true, max),
            Some(Duration::from_secs(12)),
            "past the warning, what is left of the maximum wait is the cap"
        );
        assert_eq!(
            gate_sleep_cap(Duration::from_secs(30), true, max),
            Some(Duration::ZERO),
            "past the deadline a waiter must not sleep at all"
        );
        assert_eq!(
            gate_sleep_cap(Duration::from_secs(30), true, None),
            None,
            "with no deadline there is nothing to wake for but the watcher"
        );
    }
}

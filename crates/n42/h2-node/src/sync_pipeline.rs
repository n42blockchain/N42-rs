// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The range catch-up's measurement and pipeline (sync standard S2/S5).
//!
//! [`CatchUpTimes`] records where a pull's time goes -- the round trip of
//! each range request, screening and anchoring of the pulled blocks, and the
//! execution layer's `newPayload` and forkchoice -- and is logged on one line
//! when the pull ends.
//!
//! With `N42_SYNC_PIPELINE=1` ([`pipeline_from_env`]) a pull runs as a
//! pipeline instead of one range at a time:
//!
//! - [`RangeScheduler`] keeps up to [`MAX_SLOTS`] ranges in flight across
//!   distinct peers (one slot per peer), ranks peers by an EWMA of the
//!   blocks/s they served, reassigns the range of a peer that misses its
//!   deadline, and holds replies in a bounded reorder buffer that hands them
//!   out strictly in height order -- to the same screening and anchoring
//!   (`N42_SYNC_ANCHOR`) the serial pull runs.
//! - [`PulledImporter`] runs the execution layer's `newPayload` of the blocks
//!   the screening released on a task of its own, fed through a bounded
//!   channel, and reports batches back to the consensus loop, which moves
//!   the head with one forkchoice per batch. Votes and timeouts never wait
//!   behind a pulled block's execution.
//!
//! Progress is the executed head only: a stall watchdog on the loop falls
//! back to the serial pull when the head has not moved for
//! [`stall_from_env`] while pulled blocks wait for execution.

use alloy_primitives::B256;
use alloy_rpc_types_engine::ExecutionData;
use n42_h2_execution::{ExecutionDriver, ExecutionLayer};
use n42_h2_net::{BlockChunk, PeerId, RangeRequest};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The environment variable that turns the pipeline on (`1`) or off (`0`).
pub const SYNC_PIPELINE_ENV: &str = "N42_SYNC_PIPELINE";

/// The pipeline's default when [`SYNC_PIPELINE_ENV`] is unset.
pub const SYNC_PIPELINE_DEFAULT: bool = true;

/// The environment variable for lazy screening of an anchored pull (`1` on,
/// `0` off): only a reply's last block, and every 32nd unanchored block,
/// has its header QC and seal verified; the blocks between are parent-linked
/// to it and execute only under a verified anchor at or above them, as
/// every pulled block does (`docs/P1_CATCHUP_PERF.md`, section 4).
pub const SYNC_LAZY_VERIFY_ENV: &str = "N42_SYNC_LAZY_VERIFY";

/// Lazy screening's default when [`SYNC_LAZY_VERIFY_ENV`] is unset.
pub const SYNC_LAZY_VERIFY_DEFAULT: bool = false;

/// Whether lazy screening is on ([`SYNC_LAZY_VERIFY_ENV`]); a value that is
/// not 0 or 1 keeps the default, with a warning.
pub fn lazy_verify_from_env() -> bool {
    let raw = std::env::var(SYNC_LAZY_VERIFY_ENV).ok();
    match raw.as_deref().map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") => SYNC_LAZY_VERIFY_DEFAULT,
        Some("1" | "on" | "true") => true,
        Some("0" | "off" | "false") => false,
        Some(_) => {
            tracing::warn!(target: "n42.h2.node", value = ?raw, "{SYNC_LAZY_VERIFY_ENV} is not 0 or 1; keeping the default");
            SYNC_LAZY_VERIFY_DEFAULT
        }
    }
}

/// The environment variable for the stall watchdog, in seconds.
pub const SYNC_STALL_ENV: &str = "N42_SYNC_STALL_SECS";

/// The stall watchdog's default.
pub const SYNC_STALL_DEFAULT: Duration = Duration::from_secs(30);

/// Ranges in flight at most, across distinct peers.
pub const MAX_SLOTS: usize = 4;

/// Blocks one pipeline range asks for.
pub const PIPELINE_RANGE_BLOCKS: u64 = 128;

/// No range is asked for that starts further than this past the next block
/// to deliver: the reorder buffer's bound in blocks.
pub const WINDOW_BLOCKS: u64 = 1024;

/// The reorder buffer's bound in bytes: no new range is asked for while the
/// buffered replies hold this much.
pub const MAX_READY_BYTES: usize = 256 << 20;

/// The EWMA weight of a new blocks/s sample (sync standard §6.4).
const EWMA_ALPHA: f64 = 0.3;

/// A range's deadline when its peer has no measured rate yet.
const UNKNOWN_DEADLINE: Duration = Duration::from_secs(10);

/// The shortest deadline a range gets.
const MIN_DEADLINE: Duration = Duration::from_secs(2);

/// A range's deadline is this many times its expected transfer time.
const DEADLINE_FACTOR: f64 = 4.0;

/// Pulled blocks queued for the importer at most.
pub const IMPORT_QUEUE: usize = 64;

/// The importer reports at least this often while it has work.
const REPORT_EVERY: Duration = Duration::from_millis(200);

/// Blocks one importer report covers at most.
const REPORT_BLOCKS: usize = 64;

/// Reads [`SYNC_PIPELINE_ENV`]: `1|on|true` and `0|off|false`; unset or empty
/// is [`SYNC_PIPELINE_DEFAULT`]. `None` for a value that names neither.
pub fn parse_pipeline(value: Option<&str>) -> Option<bool> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") => Some(SYNC_PIPELINE_DEFAULT),
        Some("1" | "on" | "true") => Some(true),
        Some("0" | "off" | "false") => Some(false),
        Some(_) => None,
    }
}

/// Whether the environment turns the pipeline on (see [`parse_pipeline`]);
/// a value that names neither is logged and the default kept.
pub fn pipeline_from_env() -> bool {
    let raw = std::env::var(SYNC_PIPELINE_ENV).ok();
    parse_pipeline(raw.as_deref()).unwrap_or_else(|| {
        tracing::warn!(target: "n42.h2.node", value = ?raw, "{SYNC_PIPELINE_ENV} is not 0 or 1; keeping the default");
        SYNC_PIPELINE_DEFAULT
    })
}

/// The stall watchdog's period from [`SYNC_STALL_ENV`] (whole seconds, at
/// least 1); else [`SYNC_STALL_DEFAULT`].
pub fn stall_from_env() -> Duration {
    std::env::var(SYNC_STALL_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs >= 1)
        .map_or(SYNC_STALL_DEFAULT, Duration::from_secs)
}

/// Where one catch-up's time went. Summed over the pull; logged when it ends
/// (`catch-up timing`).
#[derive(Debug, Clone)]
pub(crate) struct CatchUpTimes {
    /// When the pull started.
    pub(crate) started: Instant,
    /// Range requests sent.
    pub(crate) requests: u64,
    /// Range replies received (empty and refused ones included).
    pub(crate) replies: u64,
    /// Sum over replies of request sent to reply received.
    pub(crate) fetch: Duration,
    /// The slowest single request to reply.
    pub(crate) fetch_max: Duration,
    /// Decoding, screening, QC checks and anchor bookkeeping of pulled blocks.
    pub(crate) verify: Duration,
    /// `newPayload` of pulled blocks, summed (off the loop in the pipeline).
    pub(crate) new_payload: Duration,
    /// Forkchoice updates that made pulled blocks the head.
    pub(crate) forkchoice: Duration,
    /// Forkchoice updates sent.
    pub(crate) forkchoices: u64,
    /// Pulled blocks executed by this pull.
    pub(crate) executed: u64,
    /// Bytes of pulled blocks received.
    pub(crate) bytes: u64,
    /// Pulled blocks whose header QC and seal were verified (every one of
    /// them unless lazy screening is on).
    pub(crate) checked: u64,
}

impl CatchUpTimes {
    /// Times of a pull starting now.
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
            replies: 0,
            fetch: Duration::ZERO,
            fetch_max: Duration::ZERO,
            verify: Duration::ZERO,
            new_payload: Duration::ZERO,
            forkchoice: Duration::ZERO,
            forkchoices: 0,
            executed: 0,
            bytes: 0,
            checked: 0,
        }
    }

    /// One reply arrived `elapsed` after its request.
    pub(crate) fn note_reply(&mut self, elapsed: Duration) {
        self.replies += 1;
        self.fetch += elapsed;
        self.fetch_max = self.fetch_max.max(elapsed);
    }

    /// Executed pulled blocks per second of the pull's wall time.
    pub(crate) fn blocks_per_sec(&self) -> f64 {
        let secs = self.started.elapsed().as_secs_f64();
        if secs <= 0.0 { 0.0 } else { self.executed as f64 / secs }
    }

    /// Logs the pull's timing on one line.
    pub(crate) fn log(&self, mode: &'static str, complete: bool) {
        let ms = |d: Duration| d.as_millis() as u64;
        let wall = self.started.elapsed();
        tracing::info!(
            target: "n42.h2.node",
            mode,
            complete,
            executed = self.executed,
            wall_ms = ms(wall),
            blocks_per_s = format_args!("{:.1}", self.blocks_per_sec()),
            requests = self.requests,
            replies = self.replies,
            bytes = self.bytes,
            fetch_ms = ms(self.fetch),
            fetch_max_ms = ms(self.fetch_max),
            verify_ms = ms(self.verify),
            new_payload_ms = ms(self.new_payload),
            forkchoice_ms = ms(self.forkchoice),
            forkchoices = self.forkchoices,
            checked = self.checked,
            "catch-up timing"
        );
    }
}

/// What the scheduler knows of one peer.
#[derive(Debug, Default, Clone)]
struct PeerStat {
    /// EWMA of the blocks/s its replies came at; `None` before the first.
    bps: Option<f64>,
    /// EWMA of the bytes/s its replies came at; `None` before the first.
    byte_rate: Option<f64>,
    /// A request to it is outstanding (also one whose range was reassigned).
    busy: bool,
    /// It answered nothing from this height: no range at or above it is
    /// asked of it again in this pull.
    exhausted_from: Option<u64>,
    /// Missed deadlines in this pull; doubles its back-off.
    timeouts: u32,
    /// Not asked again before this (a soft fault: back-off, no score).
    backoff_until: Option<Instant>,
    /// It served a block that failed screening (a provable fault): not
    /// asked again in this pull.
    excluded: bool,
}

/// One range in flight.
#[derive(Debug, Clone)]
struct Slot {
    start: u64,
    count: u64,
    sent: Instant,
    deadline: Instant,
    /// The deadline passed and the range went back to be asked of another
    /// peer: the reply, when it comes, is dropped.
    reassigned: bool,
}

/// A reply waiting in the reorder buffer.
#[derive(Debug)]
struct Ready {
    peer: PeerId,
    chunks: Vec<BlockChunk>,
    bytes: usize,
}

/// What [`RangeScheduler::on_reply`] made of a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyOutcome {
    /// Buffered for delivery in height order (blocks it carried).
    Buffered(usize),
    /// The peer served nothing from the range's start: the range goes to
    /// another peer, this one is not asked past it again.
    Empty,
    /// Not a range in flight here, or one already reassigned: dropped.
    Stale,
}

/// The pipeline's range scheduler (sync standard S2, §6.4): ranges in
/// flight across peers, one slot per peer, EWMA ranking, reassignment on a
/// missed deadline, and a reorder buffer delivering replies in height order.
/// Pure bookkeeping: the caller sends the requests it returns and screens
/// what it delivers.
#[derive(Debug)]
pub(crate) struct RangeScheduler {
    /// The lowest height never asked for.
    next_assign: u64,
    /// Ranges to ask for again (a short reply's rest, a reassigned range,
    /// an empty one), by start.
    gaps: BTreeMap<u64, u64>,
    slots: HashMap<PeerId, Slot>,
    ready: BTreeMap<u64, Ready>,
    ready_bytes: usize,
    peers: HashMap<PeerId, PeerStat>,
    range_blocks: u64,
    max_slots: usize,
    /// EWMA of the bytes per block of the replies so far: with the peers'
    /// byte rates, what a range's deadline is sized by. Blocks of one chain
    /// differ by three orders of magnitude (an empty block is ~1 KB, a full
    /// 480M-gas one 2.7 MB), so a deadline sized by blocks/s alone, learnt
    /// on empty blocks, expired on every range of full ones
    /// (`docs/P1_CATCHUP_PERF.md`, step 2).
    block_bytes: Option<f64>,
}

impl RangeScheduler {
    /// A scheduler whose first range starts at `next`.
    pub(crate) fn new(next: u64) -> Self {
        Self::with_shape(next, PIPELINE_RANGE_BLOCKS, MAX_SLOTS)
    }

    /// [`Self::new`] with a range size and slot count of the caller's.
    pub(crate) fn with_shape(next: u64, range_blocks: u64, max_slots: usize) -> Self {
        Self {
            next_assign: next,
            gaps: BTreeMap::new(),
            slots: HashMap::new(),
            ready: BTreeMap::new(),
            ready_bytes: 0,
            peers: HashMap::new(),
            range_blocks: range_blocks.max(1),
            max_slots: max_slots.max(1),
            block_bytes: None,
        }
    }

    /// Ranges in flight whose replies are still wanted.
    pub(crate) fn active(&self) -> usize {
        self.slots.values().filter(|slot| !slot.reassigned).count()
    }

    /// Replies waiting in the reorder buffer.
    pub(crate) fn buffered(&self) -> usize {
        self.ready.len()
    }

    /// Whether `peer` may serve a range starting at `start`.
    fn serves(stat: Option<&PeerStat>, height: u64, start: u64) -> bool {
        height >= start
            && stat.is_none_or(|s| !s.excluded)
            && stat.and_then(|s| s.exhausted_from).is_none_or(|from| start < from)
    }

    /// Records `count` blocks from `start` to be asked for again.
    fn add_gap(&mut self, start: u64, count: u64) {
        if count == 0 {
            return;
        }
        let entry = self.gaps.entry(start).or_insert(count);
        *entry = (*entry).max(count);
    }

    /// `peer` served a block that failed screening (sync standard §3.5):
    /// it is asked for nothing more in this pull, its range in flight and
    /// its buffered replies go back to be asked of another peer, and so does
    /// `rest` (the failing block's range and what followed it in the reply).
    pub(crate) fn exclude(&mut self, peer: PeerId, rest: Option<(u64, u64)>) {
        self.peers.entry(peer).or_default().excluded = true;
        if let Some(slot) = self.slots.get_mut(&peer)
            && !slot.reassigned
        {
            slot.reassigned = true;
            let (start, count) = (slot.start, slot.count);
            self.add_gap(start, count);
        }
        let theirs: Vec<u64> = self.ready.iter().filter(|(_, r)| r.peer == peer).map(|(start, _)| *start).collect();
        for start in theirs {
            if let Some(ready) = self.ready.remove(&start) {
                self.ready_bytes = self.ready_bytes.saturating_sub(ready.bytes);
                self.add_gap(start, ready.chunks.len() as u64);
            }
        }
        if let Some((start, count)) = rest {
            self.add_gap(start, count);
        }
    }

    /// A reply handed out by [`Self::pop_ready`] and not screened, back into
    /// the reorder buffer -- or, from an excluded peer, back to be asked of
    /// another.
    pub(crate) fn put_back(&mut self, peer: PeerId, start: u64, chunks: Vec<BlockChunk>) {
        if self.peers.get(&peer).is_some_and(|s| s.excluded) {
            self.add_gap(start, chunks.len() as u64);
            return;
        }
        let bytes = chunks.iter().map(|c| c.rlp.len()).sum();
        self.ready_bytes += bytes;
        self.ready.insert(start, Ready { peer, chunks, bytes });
    }

    /// Whether `peer` is excluded from this pull.
    #[cfg(test)]
    pub(crate) fn is_excluded(&self, peer: &PeerId) -> bool {
        self.peers.get(peer).is_some_and(|s| s.excluded)
    }

    /// The lowest height still to be asked for.
    fn lowest_work(&self) -> u64 {
        self.gaps.keys().next().copied().unwrap_or(self.next_assign).min(self.next_assign)
    }

    /// The ranges to ask for now, each of a free peer: the lowest
    /// outstanding work first, to the measured-fastest (unmeasured first,
    /// so each peer gets measured) peer that can serve it. `peers` are the
    /// candidates with their known heights; `deliver_next` is the next block
    /// the caller will screen (the reorder window's base).
    pub(crate) fn assign(&mut self, deliver_next: u64, peers: &[(PeerId, u64)], now: Instant) -> Vec<(PeerId, RangeRequest)> {
        let mut out = Vec::new();
        while self.active() < self.max_slots && self.ready_bytes < MAX_READY_BYTES {
            let (start, count, from_gap) = match self.gaps.iter().next() {
                Some((start, count)) => (*start, *count, true),
                None => (self.next_assign, self.range_blocks, false),
            };
            if start > deliver_next.saturating_add(WINDOW_BLOCKS) {
                break;
            }
            let mut best: Option<(PeerId, u64, f64)> = None;
            for (peer, height) in peers {
                let stat = self.peers.get(peer);
                if stat.is_some_and(|s| s.busy || s.backoff_until.is_some_and(|until| now < until))
                    || !Self::serves(stat, *height, start)
                {
                    continue;
                }
                let rank = stat.and_then(|s| s.bps).unwrap_or(f64::INFINITY);
                if best.as_ref().is_none_or(|(_, _, r)| rank > *r) {
                    best = Some((*peer, *height, rank));
                }
            }
            let Some((peer, height, _)) = best else {
                break;
            };
            let count = count.min(height - start + 1);
            if from_gap {
                let left = self.gaps.remove(&start).unwrap_or(count);
                if left > count {
                    self.gaps.insert(start + count, left - count);
                }
            } else {
                self.next_assign = start + count;
            }
            let stat = self.peers.entry(peer).or_default();
            stat.busy = true;
            let expected = match (stat.byte_rate, self.block_bytes) {
                (Some(rate), Some(per_block)) => {
                    let bytes = (count as f64 * per_block).min(n42_h2_net::MAX_RANGE_REPLY_BYTES as f64);
                    Duration::from_secs_f64(bytes / rate.max(1.0) * DEADLINE_FACTOR).max(MIN_DEADLINE)
                }
                _ => stat.bps.map_or(UNKNOWN_DEADLINE, |bps| {
                    Duration::from_secs_f64(count as f64 / bps.max(1e-3) * DEADLINE_FACTOR).max(MIN_DEADLINE)
                }),
            };
            self.slots.insert(peer, Slot { start, count, sent: now, deadline: now + expected, reassigned: false });
            out.push((peer, RangeRequest { start, count, step: 1 }));
        }
        out
    }

    /// A reply (`chunks`, empty for a refusal) from `peer` to `request`.
    pub(crate) fn on_reply(&mut self, peer: PeerId, request: &RangeRequest, chunks: Vec<BlockChunk>, now: Instant) -> ReplyOutcome {
        let Some(slot) = self.slots.get(&peer).filter(|slot| slot.start == request.start).cloned() else {
            return ReplyOutcome::Stale;
        };
        self.slots.remove(&peer);
        let stat = self.peers.entry(peer).or_default();
        stat.busy = false;
        let served = chunks.len() as u64;
        if slot.reassigned {
            // Late, after its range was reassigned: the blocks are taken all
            // the same when nothing holds them yet (a late reply used to be
            // dropped, and the range asked again, on every range a deadline
            // learnt on smaller blocks had underestimated). What was not
            // reassigned yet is taken back from the gaps; a copy the other
            // peer serves later is a duplicate the delivery skips.
            if served == 0 || self.ready.contains_key(&slot.start) {
                return ReplyOutcome::Stale;
            }
            if let Some(left) = self.gaps.remove(&slot.start)
                && left > served
            {
                self.gaps.insert(slot.start + served, left - served);
            }
            stat.timeouts = 0;
            stat.backoff_until = None;
        }
        if served == 0 {
            stat.exhausted_from = Some(stat.exhausted_from.map_or(slot.start, |from| from.min(slot.start)));
            self.add_gap(slot.start, slot.count);
            return ReplyOutcome::Empty;
        }
        let secs = now.duration_since(slot.sent).as_secs_f64().max(1e-3);
        let sample = served as f64 / secs;
        stat.bps = Some(stat.bps.map_or(sample, |old| (1.0 - EWMA_ALPHA).mul_add(old, EWMA_ALPHA * sample)));
        let reply_bytes: usize = chunks.iter().map(|c| c.rlp.len()).sum();
        let byte_sample = reply_bytes as f64 / secs;
        stat.byte_rate =
            Some(stat.byte_rate.map_or(byte_sample, |old| (1.0 - EWMA_ALPHA).mul_add(old, EWMA_ALPHA * byte_sample)));
        stat.timeouts = 0;
        let per_block = reply_bytes as f64 / served as f64;
        self.block_bytes =
            Some(self.block_bytes.map_or(per_block, |old| (1.0 - EWMA_ALPHA).mul_add(old, EWMA_ALPHA * per_block)));
        let served = served.min(slot.count);
        if served < slot.count {
            // Short: a server caps a reply by bytes and blocks, so the rest
            // is asked again (of whichever peer is free) rather than taken
            // as this peer's head.
            self.add_gap(slot.start + served, slot.count - served);
        }
        let mut chunks = chunks;
        chunks.truncate(served as usize);
        if self.ready.contains_key(&slot.start) {
            // A late copy of this range from another peer got here first.
            return ReplyOutcome::Stale;
        }
        let bytes = chunks.iter().map(|c| c.rlp.len()).sum();
        self.ready_bytes += bytes;
        self.ready.insert(slot.start, Ready { peer, chunks, bytes });
        ReplyOutcome::Buffered(served as usize)
    }

    /// `peer` refused `request` as busy (over a server quota, sync standard
    /// §6.3): the range goes back to be asked of any free peer and the peer
    /// backs off as after a missed deadline -- not a sign of its head, no
    /// score.
    pub(crate) fn on_busy(&mut self, peer: PeerId, request: &RangeRequest, now: Instant) {
        let Some(slot) = self.slots.get(&peer).filter(|slot| slot.start == request.start).cloned() else {
            return;
        };
        self.slots.remove(&peer);
        let stat = self.peers.entry(peer).or_default();
        stat.busy = false;
        if slot.reassigned {
            return;
        }
        stat.timeouts += 1;
        stat.backoff_until = Some(now + Duration::from_secs(1u64 << stat.timeouts.min(6)));
        self.add_gap(slot.start, slot.count);
    }

    /// Ranges whose deadline passed go back to be asked of another peer;
    /// their peer backs off (doubling) and its rate is halved. Returns the
    /// peers that missed one.
    pub(crate) fn on_deadlines(&mut self, now: Instant) -> Vec<(PeerId, u64, u64)> {
        let mut missed = Vec::new();
        for (peer, slot) in &mut self.slots {
            if slot.reassigned || now < slot.deadline {
                continue;
            }
            slot.reassigned = true;
            let entry = self.gaps.entry(slot.start).or_insert(slot.count);
            *entry = (*entry).max(slot.count);
            let stat = self.peers.entry(*peer).or_default();
            stat.timeouts += 1;
            stat.bps = stat.bps.map(|bps| bps / 2.0);
            stat.backoff_until = Some(now + Duration::from_secs(1u64 << stat.timeouts.min(6)));
            missed.push((*peer, slot.start, slot.count));
        }
        missed
    }

    /// The buffered reply starting at `deliver_next`, if it has arrived:
    /// replies leave strictly in height order. A buffered reply wholly
    /// below it is dropped; one that overlaps it is cut to start there.
    pub(crate) fn pop_ready(&mut self, deliver_next: u64) -> Option<(PeerId, RangeRequest, Vec<BlockChunk>)> {
        loop {
            let (&start, _) = self.ready.iter().next()?;
            let ready = self.ready.remove(&start)?;
            self.ready_bytes = self.ready_bytes.saturating_sub(ready.bytes);
            let end = start + ready.chunks.len() as u64;
            if end <= deliver_next {
                continue;
            }
            if start > deliver_next {
                // Not yet: back where it was.
                self.ready_bytes += ready.bytes;
                self.ready.insert(start, ready);
                return None;
            }
            let mut chunks = ready.chunks;
            chunks.drain(..(deliver_next - start) as usize);
            let request = RangeRequest { start: deliver_next, count: chunks.len() as u64, step: 1 };
            return Some((ready.peer, request, chunks));
        }
    }

    /// Whether the reply that starts at (or overlaps) `deliver_next` has
    /// arrived.
    pub(crate) fn has_ready(&self, deliver_next: u64) -> bool {
        self.ready.keys().next().is_some_and(|start| *start <= deliver_next)
    }

    /// Whether nothing is left this pull can do: no range in flight, none
    /// buffered, and no candidate peer can serve the lowest height still to
    /// ask for (each is below it or answered nothing from it).
    pub(crate) fn exhausted(&self, peers: &[(PeerId, u64)]) -> bool {
        if self.active() > 0 || !self.ready.is_empty() {
            return false;
        }
        let start = self.lowest_work();
        !peers.iter().any(|(peer, height)| Self::serves(self.peers.get(peer), *height, start))
    }

    /// The height from which `peer` served nothing in this pull.
    pub(crate) fn exhausted_from(&self, peer: &PeerId) -> Option<u64> {
        self.peers.get(peer).and_then(|s| s.exhausted_from)
    }

    /// The EWMA blocks/s of `peer`, when measured.
    pub(crate) fn rate(&self, peer: &PeerId) -> Option<f64> {
        self.peers.get(peer).and_then(|s| s.bps)
    }
}

/// One pulled block for the importer.
#[derive(Debug)]
pub(crate) struct ImportJob {
    /// The importer generation the block was sent under.
    pub(crate) generation: u64,
    pub(crate) number: u64,
    pub(crate) hash: B256,
    pub(crate) payload: ExecutionData,
}

/// What the importer did with a run of jobs.
#[derive(Debug)]
pub(crate) struct ImportBatch {
    pub(crate) generation: u64,
    /// Executed (VALID), in order.
    pub(crate) done: Vec<(u64, B256)>,
    /// The block the execution layer refused, and why: nothing after it in
    /// the same generation is executed.
    pub(crate) failed: Option<(u64, B256, String)>,
    /// `newPayload` time of this batch.
    pub(crate) new_payload: Duration,
}

/// The pulled blocks' importer: one task, off the consensus loop, running
/// `newPayload` in the order the loop sent the blocks and reporting each run
/// back. It holds no driver state; the loop notes each block's settlement
/// bookkeeping before sending it and moves the head once per batch.
#[derive(Debug)]
pub(crate) struct PulledImporter {
    tx: tokio::sync::mpsc::Sender<ImportJob>,
    task: tokio::task::JoinHandle<()>,
}

impl PulledImporter {
    /// Spawns the importer on `el`; its reports arrive on the returned
    /// receiver.
    pub(crate) fn spawn<E: ExecutionLayer>(el: Arc<E>) -> (Self, tokio::sync::mpsc::UnboundedReceiver<ImportBatch>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ImportJob>(IMPORT_QUEUE);
        let (report_tx, report_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            // Jobs of a generation whose block failed are skipped: they
            // have no parent in the execution layer.
            let mut failed_generation: Option<u64> = None;
            while let Some(first) = rx.recv().await {
                let started = Instant::now();
                let mut batch = ImportBatch {
                    generation: first.generation,
                    done: Vec::new(),
                    failed: None,
                    new_payload: Duration::ZERO,
                };
                let mut job = Some(first);
                while let Some(next) = job.take() {
                    if next.generation != batch.generation {
                        // A new generation starts a new report.
                        if !batch.done.is_empty() || batch.failed.is_some() {
                            let _ = report_tx.send(std::mem::replace(
                                &mut batch,
                                ImportBatch { generation: next.generation, done: Vec::new(), failed: None, new_payload: Duration::ZERO },
                            ));
                        } else {
                            batch.generation = next.generation;
                        }
                    }
                    if failed_generation.is_some_and(|g| g >= next.generation) {
                        // Skipped.
                    } else {
                        let at = Instant::now();
                        let result = ExecutionDriver::<E>::pulled_new_payload(&*el, next.payload).await;
                        batch.new_payload += at.elapsed();
                        match result {
                            Ok(()) => batch.done.push((next.number, next.hash)),
                            Err(err) => {
                                failed_generation = Some(next.generation);
                                batch.failed = Some((next.number, next.hash, err.to_string()));
                                break;
                            }
                        }
                    }
                    if batch.done.len() >= REPORT_BLOCKS || started.elapsed() >= REPORT_EVERY {
                        break;
                    }
                    job = rx.try_recv().ok();
                }
                if (!batch.done.is_empty() || batch.failed.is_some()) && report_tx.send(batch).is_err() {
                    return;
                }
            }
        });
        (Self { tx, task }, report_rx)
    }

    /// Queues a block; gives it back when the queue is full.
    pub(crate) fn try_send(&self, job: ImportJob) -> Result<(), ImportJob> {
        self.tx.try_send(job).map_err(|err| match err {
            tokio::sync::mpsc::error::TrySendError::Full(job) | tokio::sync::mpsc::error::TrySendError::Closed(job) => job,
        })
    }

    /// Room left in the queue.
    pub(crate) fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

impl Drop for PulledImporter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(i: u8) -> PeerId {
        let key = libp2p::identity::Keypair::ed25519_from_bytes([i; 32]).expect("key");
        key.public().to_peer_id()
    }

    fn chunks(n: u64) -> Vec<BlockChunk> {
        (0..n).map(|_| BlockChunk { fork_digest: [0; 4], rlp: alloy_primitives::Bytes::from_static(&[1, 2, 3]) }).collect()
    }

    #[test]
    fn the_pipeline_switch_parses_and_defaults() {
        assert_eq!(parse_pipeline(None), Some(SYNC_PIPELINE_DEFAULT));
        assert_eq!(parse_pipeline(Some("")), Some(SYNC_PIPELINE_DEFAULT));
        assert_eq!(parse_pipeline(Some("1")), Some(true));
        assert_eq!(parse_pipeline(Some("off")), Some(false));
        assert_eq!(parse_pipeline(Some("maybe")), None);
    }

    #[test]
    fn ranges_go_one_per_peer_up_to_the_slot_cap_and_each_peers_height() {
        let (a, b, c) = (peer(1), peer(2), peer(3));
        let mut s = RangeScheduler::with_shape(1, 10, 2);
        let now = Instant::now();
        let asked = s.assign(1, &[(a, 100), (b, 15), (c, 100)], now);
        assert_eq!(asked.len(), 2, "two slots");
        let peers: Vec<_> = asked.iter().map(|(p, _)| *p).collect();
        assert_ne!(peers[0], peers[1], "one slot per peer");
        assert_eq!(asked[0].1.start, 1);
        assert_eq!(asked[1].1.start, 11);
        // No free slot: nothing more.
        assert!(s.assign(1, &[(a, 100), (b, 15), (c, 100)], now).is_empty());
    }

    #[test]
    fn replies_are_delivered_in_height_order_whatever_order_they_arrive_in() {
        let (a, b) = (peer(1), peer(2));
        let mut s = RangeScheduler::with_shape(1, 10, 2);
        let now = Instant::now();
        let asked = s.assign(1, &[(a, 100), (b, 100)], now);
        let (first, second) = (asked[0].clone(), asked[1].clone());
        // The second range answers first: held.
        assert_eq!(s.on_reply(second.0, &second.1, chunks(10), now), ReplyOutcome::Buffered(10));
        assert!(s.pop_ready(1).is_none(), "block 1 has not arrived");
        assert_eq!(s.on_reply(first.0, &first.1, chunks(10), now), ReplyOutcome::Buffered(10));
        let (_, r1, _) = s.pop_ready(1).expect("first range");
        assert_eq!((r1.start, r1.count), (1, 10));
        let (_, r2, _) = s.pop_ready(11).expect("second range");
        assert_eq!((r2.start, r2.count), (11, 10));
    }

    #[test]
    fn a_slow_peers_range_is_reassigned_and_its_late_reply_taken_once() {
        let (fast, slow) = (peer(1), peer(2));
        let mut s = RangeScheduler::with_shape(1, 10, 2);
        let t0 = Instant::now();
        let asked = s.assign(1, &[(slow, 100), (fast, 100)], t0);
        let slow_req = asked.iter().find(|(p, _)| *p == slow).expect("slow asked").1.clone();
        let fast_req = asked.iter().find(|(p, _)| *p == fast).expect("fast asked").1.clone();
        assert_eq!(s.on_reply(fast, &fast_req, chunks(10), t0 + Duration::from_millis(100)), ReplyOutcome::Buffered(10));
        let missed = s.on_deadlines(t0 + UNKNOWN_DEADLINE + Duration::from_millis(1));
        assert_eq!(missed, vec![(slow, slow_req.start, 10)]);
        // The fast peer takes the slow one's range; the slow one is busy and backing off.
        let again = s.assign(1, &[(slow, 100), (fast, 100)], t0 + UNKNOWN_DEADLINE);
        assert_eq!(again[0], (fast, RangeRequest { start: slow_req.start, count: 10, step: 1 }));
        // The slow peer's late reply arrives first: taken, nothing holds the
        // range yet; the fast peer's copy after it is a duplicate.
        assert_eq!(s.on_reply(slow, &slow_req, chunks(10), t0 + UNKNOWN_DEADLINE * 2), ReplyOutcome::Buffered(10));
        assert_eq!(s.on_reply(fast, &again[0].1, chunks(10), t0 + UNKNOWN_DEADLINE * 2), ReplyOutcome::Stale);
        let (_, first, _) = s.pop_ready(1).expect("the late range");
        assert_eq!((first.start, first.count), (slow_req.start, 10));
        assert_eq!(s.ready_bytes, 30, "the duplicate holds no bytes");
    }

    /// A late reply whose range was not asked again yet is taken, and the
    /// range is not asked again after it; a late empty one is stale.
    #[test]
    fn a_late_reply_before_the_range_is_asked_again_is_taken_and_ends_the_gap() {
        let (a, b) = (peer(1), peer(2));
        let mut s = RangeScheduler::with_shape(1, 10, 1);
        let t0 = Instant::now();
        let (who, req) = s.assign(1, &[(a, 100), (b, 100)], t0).remove(0);
        assert_eq!(s.on_deadlines(t0 + UNKNOWN_DEADLINE + Duration::from_millis(1)).len(), 1);
        // Late and short: the first 6 are taken, the other 4 stay a gap.
        assert_eq!(s.on_reply(who, &req, chunks(6), t0 + UNKNOWN_DEADLINE * 2), ReplyOutcome::Buffered(6));
        let next = s.assign(1, &[(a, 100), (b, 100)], t0 + UNKNOWN_DEADLINE * 2).remove(0).1;
        assert_eq!((next.start, next.count), (7, 4), "only the rest is asked again");
    }

    /// The deadline is sized by bytes once replies taught the scheduler a
    /// block size and the peer's byte rate: a peer that served 128 empty
    /// blocks in a millisecond is not given 2 s for 128 full ones when its
    /// byte rate says they take longer.
    #[test]
    fn the_deadline_follows_the_bytes_a_range_is_expected_to_carry() {
        let a = peer(1);
        let mut s = RangeScheduler::with_shape(1, 10, 1);
        let t0 = Instant::now();
        let r = s.assign(1, &[(a, 1000)], t0).remove(0).1;
        // 10 blocks of 1 MB in 1 s: 10 MB/s, 1 MB a block.
        let big: Vec<BlockChunk> = (0..10)
            .map(|_| BlockChunk { fork_digest: [0; 4], rlp: alloy_primitives::Bytes::from(vec![0u8; 1 << 20]) })
            .collect();
        assert_eq!(s.on_reply(a, &r, big, t0 + Duration::from_secs(1)), ReplyOutcome::Buffered(10));
        let _ = s.assign(11, &[(a, 1000)], t0 + Duration::from_secs(1));
        let slot = s.slots.get(&a).expect("in flight").clone();
        let deadline = slot.deadline.duration_since(slot.sent);
        assert!(deadline >= Duration::from_secs(3), "10 MB at 10 MB/s, times the factor: {deadline:?}");
    }

    #[test]
    fn a_short_reply_asks_for_its_rest_and_an_empty_one_ends_that_peer() {
        let a = peer(1);
        let mut s = RangeScheduler::with_shape(1, 10, 1);
        let now = Instant::now();
        let r = s.assign(1, &[(a, 100)], now).remove(0).1;
        assert_eq!(s.on_reply(a, &r, chunks(4), now), ReplyOutcome::Buffered(4));
        let rest = s.assign(1, &[(a, 100)], now).remove(0).1;
        assert_eq!((rest.start, rest.count), (5, 6));
        assert_eq!(s.on_reply(a, &rest, Vec::new(), now), ReplyOutcome::Empty);
        assert!(s.assign(1, &[(a, 100)], now).is_empty(), "not asked past where it served nothing");
        let _ = s.pop_ready(1);
        assert!(s.exhausted(&[(a, 100)]));
    }

    #[test]
    fn an_excluded_peer_is_asked_nothing_more_and_its_ranges_go_to_another() {
        let (forger, honest) = (peer(1), peer(2));
        let mut s = RangeScheduler::with_shape(1, 10, 2);
        let now = Instant::now();
        let asked = s.assign(1, &[(forger, 100), (honest, 100)], now);
        let forged = asked.iter().find(|(p, _)| *p == forger).expect("forger asked").1.clone();
        let fair = asked.iter().find(|(p, _)| *p == honest).expect("honest asked").1.clone();
        assert_eq!(s.on_reply(forger, &forged, chunks(10), now), ReplyOutcome::Buffered(10));
        assert_eq!(s.on_reply(honest, &fair, chunks(10), now), ReplyOutcome::Buffered(10));
        // The forger's first range is screened; its block 4 fails.
        let (_, r, mut got) = s.pop_ready(1).expect("first range");
        assert_eq!(r.start, 1);
        let rest = got.split_off(3);
        let (_, later_req, later) = s.pop_ready(11).expect("second range");
        s.exclude(forger, Some((4, rest.len() as u64)));
        s.put_back(honest, later_req.start, later);
        assert!(s.is_excluded(&forger));
        let again = s.assign(4, &[(forger, 100), (honest, 100)], now);
        assert_eq!(again, vec![(honest, RangeRequest { start: 4, count: 7, step: 1 })], "the rest, to the honest peer");
        assert!(s.has_ready(11) && !s.has_ready(4), "the honest reply waits in the buffer again");
        assert!(!s.exhausted(&[(forger, 100), (honest, 100)]));
    }

    #[test]
    fn a_busy_refusal_backs_the_peer_off_without_ending_it() {
        let (a, b) = (peer(1), peer(2));
        let mut s = RangeScheduler::with_shape(1, 10, 1);
        let now = Instant::now();
        let r = s.assign(1, &[(a, 100), (b, 100)], now).remove(0);
        s.on_busy(r.0, &r.1, now);
        assert_eq!(s.exhausted_from(&r.0), None, "not taken as the peer's head");
        let again = s.assign(1, &[(a, 100), (b, 100)], now).remove(0);
        assert_ne!(again.0, r.0, "the other peer takes the range while it backs off");
        assert_eq!(again.1.start, 1);
    }

    #[test]
    fn the_window_bounds_how_far_ahead_ranges_are_asked() {
        let peers: Vec<_> = (1..=4).map(|i| (peer(i), 1_000_000)).collect();
        let mut s = RangeScheduler::with_shape(1, WINDOW_BLOCKS, 4);
        let asked = s.assign(1, &peers, Instant::now());
        assert_eq!(asked.len(), 2, "a range starting past the window waits");
    }
}

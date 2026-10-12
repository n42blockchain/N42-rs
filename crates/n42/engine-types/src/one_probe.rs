// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0

//! One-probe state for the leader's build, stage 1 (`N42_ONE_PROBE=1`,
//! `docs/ONE_PROBE_STATE_DESIGN.md`).
//!
//! Today a recipient's read below a batch's own map walks the parent's
//! layers newest first, every link a dependent cache-missing probe. Here the
//! plan resolves, while the previous block still executes, where each of its
//! accounts' values will live before the block: the plan gives every distinct
//! address a dense block id and looks it up once in a rolling last-writer
//! table ([`Rolling`]: address -> the newest plan that touched it and its id
//! there), then records itself as that address's newest writer. The plan
//! carries the result ([`Resolved`]) with its prepared build.
//!
//! The build that took the plan keeps every account its batches commit in a
//! dense array of its own ids (one cache line an account, written through
//! from the batch's state), and a block sealed whole from its plan puts that
//! array into a ring of the last `N42_ONE_PROBE_DEPTH` outputs. The next
//! builds read an account the plan resolved to an earlier plan straight from
//! that plan's array -- one load at an address the plan names -- whenever the
//! reference is valid (the verified prefix, section 5.3 of the design), and
//! through today's chain otherwise.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
};

use alloy_primitives::{Address, B256, U256, map::AddressMap};
use revm::{Database, primitives::KECCAK_EMPTY, state::AccountInfo};

use crate::parallel_transfer::{WARM_SHARDS, warm_shard};

/// The stage (`N42_ONE_PROBE=1|2|3|4`), 0 (unset) is off. Stage 1 is
/// the plan-time resolve and the dense reads, 2 adds the plan's batches and
/// the dense batch state ([`Lanes`]), 3 adds the lane fold
/// ([`Lanes::fold_into`]), 4 hands a lane batch's lane over as its output
/// (`BatchState::take_output`, `OutputShards::add_lane`): no per-batch
/// `BundleAccount` map, the accounts made by the freeze. Read once.
pub fn stage() -> u8 {
    static N: OnceLock<u8> = OnceLock::new();
    *N.get_or_init(|| std::env::var("N42_ONE_PROBE").ok().and_then(|v| v.trim().parse::<u8>().ok()).unwrap_or(0).min(4))
}

/// The kept depth in plans and built outputs (`N42_ONE_PROBE_DEPTH`, 16 by
/// default, 1..=64). Read once.
pub fn depth() -> u64 {
    static N: OnceLock<u64> = OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("N42_ONE_PROBE_DEPTH").ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(16).clamp(1, 64)
    })
}

/// A source: where an account's value lives before the block -- plan
/// `seq`'s dense output at index `id`, packed `seq << 32 | id` -- or
/// [`CHAIN`], read through the build's provider stack.
pub type Src = u64;

/// The source "read the chain".
pub const CHAIN: Src = u64::MAX;

/// Packs plan `seq` and dense id `id` into a [`Src`].
#[inline]
pub const fn src(seq: u64, id: u32) -> Src {
    (seq << 32) | id as u64
}

/// The plan sequence number a [`Src`] names.
#[inline]
pub const fn src_seq(src: Src) -> u64 {
    src >> 32
}

/// The dense id a [`Src`] names.
#[inline]
pub const fn src_id(src: Src) -> u32 {
    src as u32
}

/// One transaction of the plan, in plan order: its two accounts, their dense
/// ids in this plan and their sources before the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanTx {
    /// The sender.
    pub sender: Address,
    /// The recipient.
    pub recipient: Address,
    /// The sender's dense id in this plan.
    pub s_bid: u32,
    /// The recipient's dense id in this plan.
    pub r_bid: u32,
    /// The sender's source.
    pub s_src: Src,
    /// The recipient's source.
    pub r_src: Src,
}

/// The rolling last-writer table: address -> the newest plan that touched it
/// and the account's id there ([`Src`]), in [`WARM_SHARDS`] shards by
/// [`warm_shard`]. Updated per plan, in plan order, under one lock.
#[derive(Debug)]
pub struct Rolling {
    shards: Vec<AddressMap<Src>>,
    /// The next plan's sequence number (from 1).
    next_seq: u64,
    /// The plan at which the last eviction sweep ran.
    swept_at: u64,
    /// Kept depth in plans: an entry older than this many plans resolves to
    /// [`CHAIN`] and is swept.
    depth: u64,
}

impl Rolling {
    /// An empty table keeping `depth` plans.
    pub fn new(depth: u64) -> Self {
        Self { shards: (0..WARM_SHARDS).map(|_| AddressMap::default()).collect(), next_seq: 1, swept_at: 0, depth: depth.max(1) }
    }

    /// Entries held (tests and diagnostics).
    pub fn len(&self) -> usize {
        self.shards.iter().map(AddressMap::len).sum()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The entry for `address`, as the next plan would resolve it.
    pub fn source(&self, address: &Address) -> Src {
        let seq = self.next_seq;
        self.shards[warm_shard(address)].get(address).copied().filter(|&s| self.live(s, seq)).unwrap_or(CHAIN)
    }

    /// Whether an entry is within the kept depth of plan `seq`.
    #[inline]
    const fn live(&self, entry: Src, seq: u64) -> bool {
        src_seq(entry) + self.depth > seq
    }
}

/// What the plan hook makes and the build takes: the plan's dense ids and
/// every transaction's sources.
#[derive(Debug)]
pub struct Resolved {
    /// This plan's sequence number.
    pub seq: u64,
    /// One record a transaction, in plan order.
    pub txs: Vec<PlanTx>,
    /// address -> dense id, by [`warm_shard`] (each shard's ids local, plus
    /// its offset).
    ids: Vec<(u32, AddressMap<u32>)>,
    /// Dense id -> whether transactions of more than one sender touch it:
    /// such an account may be written by several batches, so no single
    /// batch's value is the block's and it is never written through.
    shared: Vec<bool>,
    /// The plan's distinct accounts.
    pub accounts: usize,
    /// The resolve's wall time, microseconds.
    pub resolve_us: u64,
    /// The block's dense output in this plan's ids, written through by the
    /// build that takes the plan ([`DenseOut`]); made (and its pages
    /// touched) here, on the plan-body pool.
    pub(crate) out: Arc<DenseOut>,
    /// `N42_ONE_PROBE=2`: the plan's batches and their lanes, when the plan
    /// knew the partition and the dispatch's width ([`Lanes`]).
    pub lanes: Option<Lanes>,
}

impl Resolved {
    /// The dense id of `address` in this plan, if the plan touches it.
    pub fn id_of(&self, address: &Address) -> Option<u32> {
        let (offset, map) = self.ids.get(warm_shard(address))?;
        map.get(address).map(|local| offset + local)
    }

    /// Whether transactions of more than one sender touch dense id `bid`.
    #[inline]
    pub fn shared(&self, bid: u32) -> bool {
        self.shared.get(bid as usize).copied().unwrap_or(true)
    }

    /// Whether one batch's value of dense id `bid` is the block's: with the
    /// plan's lanes in use, when only one batch touches it; otherwise when
    /// only one sender's transactions do (a sender's are one group, a group
    /// is in one batch).
    #[inline]
    pub fn one_writer(&self, bid: u32) -> bool {
        match self.lanes.as_ref().filter(|lanes| lanes.used.load(Ordering::Relaxed)) {
            Some(lanes) => !lanes.cross.get(bid as usize).is_none_or(|cross| cross.load(Ordering::Relaxed)),
            None => !self.shared(bid),
        }
    }

    /// `N42_ONE_PROBE=4` when `on`: a batch run whole on its lane hands
    /// the lane over as its output when the build's sink takes one.
    pub fn with_lane_output(mut self, on: bool) -> Self {
        if let Some(lanes) = self.lanes.as_mut() {
            lanes.output = on;
        }
        self
    }

    /// `N42_ONE_PROBE=3` when `on`: the lane fold ([`Lanes::fold_into`]).
    pub fn with_fold(mut self, on: bool) -> Self {
        if let Some(lanes) = self.lanes.as_mut() {
            lanes.fold = on;
        }
        self
    }

    /// The plan's lanes computed for `groups` (the sender partition of these
    /// keys) packed by [`crate::parallel_transfer::batch_groups_one_wave`]
    /// at `width`, on the current rayon pool.
    pub fn with_lanes(mut self, groups: &[Vec<usize>], width: usize) -> Self {
        let at = std::time::Instant::now();
        self.lanes = Lanes::make(&self, groups, width);
        self.resolve_us += at.elapsed().as_micros() as u64;
        self
    }

    /// Transactions in the plan.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether the plan has none.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}

/// One shard's dedupe: its distinct addresses (local ids in first-touch
/// order), each one's first sender and whether another sender touched it,
/// and every occurrence's (index, local id).
#[derive(Default)]
struct ShardIds {
    map: AddressMap<u32>,
    addrs: Vec<Address>,
    owner: Vec<Address>,
    shared: Vec<bool>,
    occ: Vec<(u32, u32)>,
}

/// Resolves a plan's keys (each transaction's sender and recipient, in plan
/// order) against `table` and records the plan there as every one of its
/// addresses' newest writer, on the current rayon pool: the occurrences
/// bucketed by shard, each shard deduplicated into local ids, the shards'
/// offsets summed into dense ids, one probe and one insert a distinct
/// address, then one record a transaction. Every [`Rolling::depth`] plans
/// the table drops entries older than the depth (they resolve to [`CHAIN`]
/// whether swept or not).
pub fn resolve_with(table: &mut Rolling, keys: &[(Address, Address)]) -> Resolved {
    use rayon::prelude::*;
    let at = std::time::Instant::now();
    let seq = table.next_seq;
    table.next_seq += 1;
    // Occurrence `2i` is transaction i's sender, `2i + 1` its recipient.
    let buckets: Vec<Vec<Vec<u32>>> = keys
        .par_chunks(16_384)
        .enumerate()
        .map(|(c, chunk)| {
            let mut by_shard = vec![Vec::new(); WARM_SHARDS];
            for (k, (sender, recipient)) in chunk.iter().enumerate() {
                let i = (c * 16_384 + k) as u32;
                by_shard[warm_shard(sender)].push(2 * i);
                by_shard[warm_shard(recipient)].push(2 * i + 1);
            }
            by_shard
        })
        .collect();
    let address_of = |occ: u32| {
        let (sender, recipient) = &keys[(occ / 2) as usize];
        if occ % 2 == 0 { sender } else { recipient }
    };
    let mut shards: Vec<ShardIds> = (0..WARM_SHARDS)
        .into_par_iter()
        .map(|s| {
            let total = buckets.iter().map(|b| b[s].len()).sum::<usize>();
            let mut ids = ShardIds { occ: Vec::with_capacity(total), ..Default::default() };
            ids.map.reserve(total / 2 + 1);
            for bucket in &buckets {
                for &occ in &bucket[s] {
                    let address = address_of(occ);
                    let sender = &keys[(occ / 2) as usize].0;
                    let next = ids.addrs.len() as u32;
                    let local = *ids.map.entry(*address).or_insert(next);
                    if local == next {
                        ids.addrs.push(*address);
                        ids.owner.push(*sender);
                        ids.shared.push(false);
                    } else if ids.owner[local as usize] != *sender {
                        ids.shared[local as usize] = true;
                    }
                    ids.occ.push((occ, local));
                }
            }
            ids
        })
        .collect();
    drop(buckets);
    let mut offsets = Vec::with_capacity(WARM_SHARDS);
    let mut accounts = 0u32;
    for ids in &shards {
        offsets.push(accounts);
        accounts += ids.addrs.len() as u32;
    }
    // One probe and one insert a distinct address, each shard of the table
    // by its own thread; then every occurrence's dense id.
    let occ_bid: Vec<AtomicU32> = (0..2 * keys.len()).into_par_iter().with_min_len(8192).map(|_| AtomicU32::new(0)).collect();
    let sweep = seq >= table.swept_at + table.depth;
    let depth = table.depth;
    let srcs_by_shard: Vec<Vec<Src>> = table
        .shards
        .par_iter_mut()
        .zip(shards.par_iter_mut())
        .zip(offsets.par_iter())
        .map(|((rolling, ids), &offset)| {
            if sweep {
                rolling.retain(|_, entry| src_seq(*entry) + depth > seq);
            }
            let srcs = ids
                .addrs
                .iter()
                .enumerate()
                .map(|(local, address)| {
                    let bid = offset + local as u32;
                    let before = rolling.insert(*address, src(seq, bid));
                    before.filter(|&entry| src_seq(entry) + depth > seq).unwrap_or(CHAIN)
                })
                .collect();
            for &(occ, local) in &ids.occ {
                occ_bid[occ as usize].store(offset + local, Ordering::Relaxed);
            }
            ids.occ = Vec::new();
            ids.owner = Vec::new();
            ids.addrs = Vec::new();
            srcs
        })
        .collect();
    if sweep {
        table.swept_at = seq;
    }
    let srcs: Vec<Src> = srcs_by_shard.into_iter().flatten().collect();
    let txs: Vec<PlanTx> = keys
        .par_iter()
        .enumerate()
        .with_min_len(4096)
        .map(|(i, (sender, recipient))| {
            let s_bid = occ_bid[2 * i].load(Ordering::Relaxed);
            let r_bid = occ_bid[2 * i + 1].load(Ordering::Relaxed);
            PlanTx { sender: *sender, recipient: *recipient, s_bid, r_bid, s_src: srcs[s_bid as usize], r_src: srcs[r_bid as usize] }
        })
        .collect();
    let mut shared = Vec::with_capacity(accounts as usize);
    let mut ids = Vec::with_capacity(WARM_SHARDS);
    for (shard, offset) in shards.into_iter().zip(offsets) {
        shared.extend(shard.shared);
        ids.push((offset, shard.map));
    }
    let out = Arc::new(DenseOut::new(accounts as usize));
    Resolved { seq, txs, ids, shared, accounts: accounts as usize, resolve_us: at.elapsed().as_micros() as u64, out, lanes: None }
}

/// The process's rolling table, made at the first plan.
fn rolling() -> &'static Mutex<Rolling> {
    static TABLE: OnceLock<Mutex<Rolling>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(Rolling::new(depth())))
}

/// The plan hook (`N42_PLAN_AHEAD_BODY=1` with `N42_ONE_PROBE`): the plan's
/// keys resolved against the process's table on `pool` (the plan-body pool).
/// Plans are resolved one at a time, in the order they are made. `None` when
/// off or for an empty plan.
///
/// `N42_ONE_PROBE=2`: with `groups` (the plan's sender partition) and a
/// dispatch of a known width ([`crate::parallel_transfer::lane_width`]),
/// also the plan's batches and lanes ([`Lanes`]).
pub fn resolve(pool: &rayon::ThreadPool, keys: &[(Address, Address)], groups: Option<&[Vec<usize>]>) -> Option<Arc<Resolved>> {
    if stage() == 0 || keys.is_empty() || keys.len() > u32::MAX as usize / 2 {
        return None;
    }
    let mut table = rolling().lock().unwrap_or_else(PoisonError::into_inner);
    let table = &mut *table;
    let width = (stage() >= 2).then(|| crate::parallel_transfer::lane_width(crate::parallel_transfer::Dispatch::from_env())).flatten();
    Some(Arc::new(pool.install(|| {
        let resolved = resolve_with(table, keys);
        match (groups, width) {
            (Some(groups), Some(width)) => resolved.with_lanes(groups, width).with_fold(stage() >= 3).with_lane_output(stage() >= 4),
            _ => resolved,
        }
    })))
}

/// One batch's view of an account several batches touch (`N42_ONE_PROBE=3`):
/// as the batch read it and as the batch left it (`None`: no account).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldPart {
    /// The account's dense id.
    pub bid: u32,
    /// (balance, nonce) as read.
    pub original: Option<(U256, u64)>,
    /// (balance, nonce) as the batch left it.
    pub current: Option<(U256, u64)>,
}

/// The plan's batches and their lanes (`N42_ONE_PROBE=2`): the batches the
/// build makes of the same groups at the same width, each transaction's
/// batch and its two accounts' ids in its batch's lane, and each lane's
/// accounts in first-touch order. A lane is the batch's own dense state: its
/// accounts are found by the running transaction's ids, not by hashing.
#[derive(Debug)]
pub struct Lanes {
    /// The dispatch width the batches were made at.
    pub width: usize,
    /// Each batch's transactions.
    pub batch_txs: Vec<usize>,
    /// Transaction -> its batch.
    batch_of: Vec<u32>,
    /// Transaction -> (sender's lane id, recipient's lane id).
    lid: Vec<(u32, u32)>,
    /// Batch -> its lane's addresses, by lane id.
    lane_addrs: Vec<Vec<Address>>,
    /// Batch -> its lane's dense ids, by lane id.
    lane_bids: Vec<Vec<u32>>,
    /// `N42_ONE_PROBE=3`: each batch's values of the accounts several
    /// batches touch, folded into the block's dense output when the block is
    /// recorded ([`Lanes::fold_into`]).
    parts: Mutex<Vec<FoldPart>>,
    /// Dense id -> whether more than one batch touches it.
    cross: Vec<std::sync::atomic::AtomicBool>,
    /// Whether the build that took the plan runs its batches on these lanes.
    pub(crate) used: std::sync::atomic::AtomicBool,
    /// A batch whose transactions were not the plan's ran without its lane:
    /// the block's output is not put in the ring.
    pub(crate) broken: std::sync::atomic::AtomicBool,
    /// Reads answered from a lane's loaded entry, flushed per batch.
    pub(crate) hits: AtomicU64,
    /// Accounts loaded into lanes, flushed per batch.
    pub(crate) loaded: AtomicU64,
    /// `N42_ONE_PROBE=3`: accounts the lane fold wrote.
    pub(crate) folded: AtomicU64,
    /// `N42_ONE_PROBE=3`: the batches hand the accounts several batches
    /// touch to the lane fold.
    pub fold: bool,
    /// `N42_ONE_PROBE=4`: the batches hand their lanes over as their output
    /// (`BatchState::take_output`) to a sink that takes them.
    pub output: bool,
}

impl Lanes {
    fn make(resolved: &Resolved, groups: &[Vec<usize>], width: usize) -> Option<Self> {
        use rayon::prelude::*;
        let n = resolved.txs.len();
        if groups.iter().map(Vec::len).sum::<usize>() != n || width == 0 {
            return None;
        }
        let batches = crate::parallel_transfer::batch_groups_one_wave(groups, n, width);
        let accounts = resolved.accounts;
        let owner: Vec<AtomicU32> = (0..accounts).into_par_iter().with_min_len(8192).map(|_| AtomicU32::new(u32::MAX)).collect();
        let cross: Vec<std::sync::atomic::AtomicBool> =
            (0..accounts).into_par_iter().with_min_len(8192).map(|_| std::sync::atomic::AtomicBool::new(false)).collect();
        let tx_lane: Vec<std::sync::atomic::AtomicU64> =
            (0..n).into_par_iter().with_min_len(8192).map(|_| std::sync::atomic::AtomicU64::new(0)).collect();
        let lanes: Vec<(Vec<Address>, Vec<u32>, usize)> = batches
            .par_iter()
            .enumerate()
            .map_init(
                || vec![u32::MAX; accounts],
                |stamp, (b, members)| {
                    let mut addrs: Vec<Address> = Vec::new();
                    let mut bids: Vec<u32> = Vec::new();
                    let mut txs = 0usize;
                    let mut lid_of = |bid: u32, address: Address| -> u32 {
                        let slot = &mut stamp[bid as usize];
                        if *slot == u32::MAX {
                            *slot = addrs.len() as u32;
                            addrs.push(address);
                            bids.push(bid);
                        }
                        *slot
                    };
                    for group in members {
                        for &i in group.iter() {
                            let tx = &resolved.txs[i];
                            let s = lid_of(tx.s_bid, tx.sender);
                            let r = lid_of(tx.r_bid, tx.recipient);
                            tx_lane[i].store((b as u64) << 48 | (s as u64) << 24 | r as u64, Ordering::Relaxed);
                            txs += 1;
                        }
                    }
                    for &bid in &bids {
                        stamp[bid as usize] = u32::MAX;
                        let previous = owner[bid as usize]
                            .compare_exchange(u32::MAX, b as u32, Ordering::Relaxed, Ordering::Relaxed)
                            .unwrap_or_else(|owner| owner);
                        if previous != u32::MAX && previous != b as u32 {
                            cross[bid as usize].store(true, Ordering::Relaxed);
                        }
                    }
                    (addrs, bids, txs)
                },
            )
            .collect();
        // Lane ids are packed in 24 bits and batches in 16.
        if batches.len() > u16::MAX as usize || lanes.iter().any(|(addrs, _, _)| addrs.len() >= 1 << 24) {
            return None;
        }
        let (batch_of, lid): (Vec<u32>, Vec<(u32, u32)>) = tx_lane
            .par_iter()
            .with_min_len(8192)
            .map(|packed| {
                let packed = packed.load(Ordering::Relaxed);
                ((packed >> 48) as u32, (((packed >> 24) & 0xff_ffff) as u32, (packed & 0xff_ffff) as u32))
            })
            .unzip();
        let mut lane_addrs = Vec::with_capacity(lanes.len());
        let mut lane_bids = Vec::with_capacity(lanes.len());
        let mut batch_txs = Vec::with_capacity(lanes.len());
        for (addrs, bids, txs) in lanes {
            lane_addrs.push(addrs);
            lane_bids.push(bids);
            batch_txs.push(txs);
        }
        Some(Self {
            width,
            batch_txs,
            batch_of,
            lid,
            lane_addrs,
            lane_bids,
            parts: Mutex::new(Vec::new()),
            cross,
            used: Default::default(),
            broken: Default::default(),
            hits: Default::default(),
            loaded: Default::default(),
            folded: Default::default(),
            fold: false,
            output: false,
        })
    }

    /// Batches.
    pub fn batches(&self) -> usize {
        self.batch_txs.len()
    }

    /// The accounts of all lanes.
    pub fn accounts(&self) -> usize {
        self.lane_addrs.iter().map(Vec::len).sum()
    }

    /// Reads answered from lanes' loaded entries so far.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Accounts read into lanes so far (counted as each batch's bundle is
    /// taken).
    pub fn loaded(&self) -> u64 {
        self.loaded.load(Ordering::Relaxed)
    }

    /// Accounts the lane fold wrote into the block's output.
    pub fn folded(&self) -> u64 {
        self.folded.load(Ordering::Relaxed)
    }

    /// Whether the build runs its batches on the lanes.
    pub fn used(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    /// Whether a batch ran without its lane.
    pub fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    /// Transaction `i`'s batch.
    #[inline]
    pub fn batch_of(&self, i: usize) -> Option<u32> {
        self.batch_of.get(i).copied()
    }

    /// Transaction `i`'s (sender, recipient) lane ids.
    #[inline]
    pub fn lid(&self, i: usize) -> Option<(u32, u32)> {
        self.lid.get(i).copied()
    }

    /// Batch `b`'s lane addresses, by lane id.
    pub fn lane(&self, b: usize) -> Option<&[Address]> {
        self.lane_addrs.get(b).map(Vec::as_slice)
    }

    /// Batch `b`'s lane dense ids, by lane id.
    pub fn lane_bids(&self, b: usize) -> Option<&[u32]> {
        self.lane_bids.get(b).map(Vec::as_slice)
    }

    /// Whether more than one batch touches dense id `bid`.
    #[inline]
    pub fn cross(&self, bid: u32) -> bool {
        self.cross.get(bid as usize).is_none_or(|cross| cross.load(Ordering::Relaxed))
    }

    /// `N42_ONE_PROBE=3`: one batch's values of the accounts several batches
    /// touch, kept for [`Self::fold_into`] (one lock a batch).
    pub fn fold_part(&self, parts: Vec<FoldPart>) {
        self.parts.lock().unwrap_or_else(PoisonError::into_inner).extend(parts);
    }

    /// `N42_ONE_PROBE=3`: the lane fold. Every batch read an account several
    /// batches touch at the parent's value and changed it by its own
    /// transfers (a sender's are all in one batch; the others only credit
    /// it), and the block's merge sums those changes in any order
    /// (`OutputShards::freeze`): so the block's value is the parent's plus
    /// every batch's change. Written into `out` for each such account whose
    /// batches agree on the parent's value and that exists afterwards;
    /// returns how many. An account a batch touched only by a skipped
    /// transfer has no part: its change is zero.
    pub fn fold_into(&self, out: &DenseOut) -> usize {
        let mut parts = std::mem::take(&mut *self.parts.lock().unwrap_or_else(PoisonError::into_inner));
        parts.sort_unstable_by_key(|part| part.bid);
        let mut written = 0;
        for same in parts.chunk_by(|a, b| a.bid == b.bid) {
            let original = same[0].original;
            if same.iter().any(|part| part.original != original) {
                continue;
            }
            let (base_balance, base_nonce) = original.unwrap_or_default();
            let (mut balance, mut nonce, mut exists) = (base_balance, base_nonce, original.is_some());
            for part in same {
                let (b, n) = part.current.unwrap_or_default();
                balance = balance.wrapping_add(b).wrapping_sub(base_balance);
                nonce = nonce.wrapping_add(n).wrapping_sub(base_nonce);
                exists |= part.current.is_some();
            }
            if exists && let Some(slot) = out.get(same[0].bid) {
                slot.store(balance, nonce);
                written += 1;
            }
        }
        written
    }
}

/// [`Dense::tag`]: never written (the account is read through the chain).
const TAG_EMPTY: u64 = 0;
/// [`Dense::tag`]: a plain account (no code) with the balance and nonce held.
const TAG_PLAIN: u64 = 1;
/// [`Dense::tag`]: written with a value the array cannot hold (an account
/// with code, or none): read through the chain.
const TAG_POISON: u64 = 3;

/// One account of a block's dense output: one cache line. Written by the one
/// batch that owns the account (relaxed stores; the batches' join and the
/// ring's lock order them before any read), read by later builds.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct Dense {
    balance: [AtomicU64; 4],
    nonce: AtomicU64,
    tag: AtomicU64,
}

impl Dense {
    /// Holds a plain account's `balance` and `nonce`.
    #[inline]
    pub fn store(&self, balance: U256, nonce: u64) {
        let limbs = balance.as_limbs();
        for (slot, limb) in self.balance.iter().zip(limbs) {
            slot.store(*limb, Ordering::Relaxed);
        }
        self.nonce.store(nonce, Ordering::Relaxed);
        self.tag.store(TAG_PLAIN, Ordering::Relaxed);
    }

    /// Marks the account as one the array does not hold.
    #[inline]
    pub fn poison(&self) {
        self.tag.store(TAG_POISON, Ordering::Relaxed);
    }

    /// The plain account held, if one is.
    #[inline]
    pub fn load(&self) -> Option<(U256, u64)> {
        if self.tag.load(Ordering::Relaxed) != TAG_PLAIN {
            return None;
        }
        let limbs = [
            self.balance[0].load(Ordering::Relaxed),
            self.balance[1].load(Ordering::Relaxed),
            self.balance[2].load(Ordering::Relaxed),
            self.balance[3].load(Ordering::Relaxed),
        ];
        Some((U256::from_limbs(limbs), self.nonce.load(Ordering::Relaxed)))
    }

    /// Whether nothing was ever written.
    pub fn is_empty(&self) -> bool {
        self.tag.load(Ordering::Relaxed) == TAG_EMPTY
    }
}

/// A block's dense output: entry `id` is the account with dense id `id` in
/// the block's plan, as the block left it -- 64 bytes an account (9.4 MB for
/// 147,000 accounts). Only accounts one batch owns are written; the rest stay
/// empty and are read through the chain.
#[derive(Debug)]
pub struct DenseOut(Box<[Dense]>);

impl DenseOut {
    /// `accounts` empty entries, made and touched on the current rayon pool.
    pub fn new(accounts: usize) -> Self {
        use rayon::prelude::*;
        Self((0..accounts).into_par_iter().with_min_len(4096).map(|_| Dense::default()).collect::<Vec<_>>().into_boxed_slice())
    }

    /// Entry `id`.
    #[inline]
    pub fn get(&self, id: u32) -> Option<&Dense> {
        self.0.get(id as usize)
    }

    /// Entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether it has none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One block sealed whole from its plan: its dense output and what the
/// prefix check needs.
#[derive(Debug)]
pub struct BuiltOutput {
    /// The plan's sequence number.
    pub seq: u64,
    /// The state the build read (its parent's sealed hash).
    pub base: B256,
    /// The builder's hash of the build's parent, when this node built it.
    pub parent_built: Option<B256>,
    /// The hash the builder sealed the block under.
    pub built: B256,
    /// Accounts the block changed outside its transfers: its beneficiary and
    /// its withdrawal recipients (the system contracts are added by the
    /// reader).
    pub extra: Vec<Address>,
    /// The dense output.
    pub out: Arc<DenseOut>,
}

/// The ring of the last [`depth`] built outputs, newest first.
#[derive(Debug)]
pub struct Ring {
    outputs: VecDeque<Arc<BuiltOutput>>,
    depth: usize,
}

impl Ring {
    /// An empty ring of `depth` outputs.
    pub fn new(depth: usize) -> Self {
        Self { outputs: VecDeque::with_capacity(depth.max(1) + 1), depth: depth.max(1) }
    }

    /// Puts `output` in front; one with the same plan or the same built hash
    /// is replaced, and the oldest beyond the depth is dropped.
    pub fn push(&mut self, output: BuiltOutput) {
        self.outputs.retain(|o| o.seq != output.seq && o.built != output.built);
        self.outputs.push_front(Arc::new(output));
        self.outputs.truncate(self.depth);
    }

    /// [`note_built`] on this ring.
    pub fn record(&mut self, view: &BuildView, base: B256, parent_built: Option<B256>, built: B256, extra: Vec<Address>) -> bool {
        if view.mismatched() || view.resolved.lanes.as_ref().is_some_and(Lanes::broken) {
            return false;
        }
        // `N42_ONE_PROBE=3`: the accounts several batches touched, folded.
        if let Some(lanes) = view.resolved.lanes.as_ref().filter(|lanes| lanes.used()) {
            lanes.folded.store(lanes.fold_into(&view.resolved.out) as u64, Ordering::Relaxed);
        }
        self.push(BuiltOutput { seq: view.resolved.seq, base, parent_built, built, extra, out: Arc::clone(&view.resolved.out) });
        true
    }

    /// Outputs held.
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// The verified prefix of a build on the block the builder sealed as
    /// `parent_built`, whose parent is `grandparent`, resolved by plan
    /// `below`: the outputs of the parent, its parent, ... each sealed whole
    /// from its plan on the previous one's built hash, their plans older in
    /// turn, up to the first that is not held. Empty when the parent is not
    /// one of them.
    pub fn prefix(&self, grandparent: B256, parent_built: Option<B256>, below: u64) -> Vec<Arc<BuiltOutput>> {
        let mut prefix: Vec<Arc<BuiltOutput>> = Vec::new();
        let mut want = parent_built;
        let mut below = below;
        while let Some(hash) = want {
            let Some(output) = self.outputs.iter().find(|o| o.built == hash) else { break };
            if output.seq >= below || (prefix.is_empty() && output.base != grandparent) {
                break;
            }
            below = output.seq;
            want = output.parent_built;
            prefix.push(Arc::clone(output));
        }
        prefix
    }
}

/// The process's ring.
fn ring() -> &'static Mutex<Ring> {
    static RING: OnceLock<Mutex<Ring>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(Ring::new(depth() as usize)))
}

/// What a build reads its plan's references through: the plan's resolve, the
/// verified prefix's outputs, and the accounts forced to the chain.
#[derive(Debug)]
pub struct BuildView {
    resolved: Arc<Resolved>,
    prefix: Vec<Arc<BuiltOutput>>,
    /// The prefix's plan sequence numbers, newest first (the read's scan).
    seqs: Vec<u64>,
    /// Dense ids (a bit each) never served from an output: the prefix
    /// blocks' beneficiaries and withdrawal recipients, the system
    /// contracts, and this block's beneficiary.
    forced: Vec<u64>,
    /// This block's beneficiary: never written through.
    beneficiary: Address,
    hits: AtomicU64,
    fallbacks: AtomicU64,
    /// A transaction the batches ran was not the plan's at its index: the
    /// block's output is not put in the ring.
    mismatch: AtomicBool,
}

impl BuildView {
    /// The view of a build with beneficiary `beneficiary` that took
    /// `resolved`, over `prefix` ([`Ring::prefix`]).
    pub fn new(resolved: Arc<Resolved>, prefix: Vec<Arc<BuiltOutput>>, beneficiary: Address) -> Self {
        let mut forced = vec![0u64; resolved.accounts.div_ceil(64)];
        let residual = prefix
            .iter()
            .flat_map(|output| output.extra.iter())
            .chain(crate::warm_ahead::SYSTEM.iter())
            .chain(std::iter::once(&beneficiary));
        for address in residual {
            if let Some(bid) = resolved.id_of(address) {
                forced[bid as usize / 64] |= 1 << (bid % 64);
            }
        }
        let seqs = prefix.iter().map(|output| output.seq).collect();
        Self {
            resolved,
            prefix,
            seqs,
            forced,
            beneficiary,
            hits: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            mismatch: AtomicBool::new(false),
        }
    }

    /// The plan's resolve.
    pub fn resolved(&self) -> &Resolved {
        &self.resolved
    }

    /// The plan's resolve, shared (`N42_ONE_PROBE=2`: the lanes the batches
    /// run on).
    pub fn plan(&self) -> Arc<Resolved> {
        Arc::clone(&self.resolved)
    }

    /// Transactions in the plan.
    pub fn len(&self) -> usize {
        self.resolved.len()
    }

    /// Whether the plan has none.
    pub fn is_empty(&self) -> bool {
        self.resolved.is_empty()
    }

    /// The verified prefix's depth.
    pub fn prefix_depth(&self) -> usize {
        self.prefix.len()
    }

    /// Reads served from the outputs, by every [`OneProbeDb`] that dropped.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Reads of a transaction's account that went to the chain instead.
    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }

    /// Whether a transaction the batches ran was not the plan's.
    pub fn mismatched(&self) -> bool {
        self.mismatch.load(Ordering::Relaxed)
    }

    /// Whether dense id `bid` is forced to the chain.
    #[inline]
    fn forced(&self, bid: u32) -> bool {
        self.forced.get(bid as usize / 64).is_none_or(|word| word & (1 << (bid % 64)) != 0)
    }

    /// The value the reference `src` of dense id `bid` names, when it is
    /// valid: not the chain, not forced, a plan of the verified prefix, and
    /// an entry its block wrote with a plain account.
    #[inline]
    fn dense(&self, bid: u32, src: Src) -> Option<(U256, u64)> {
        if src == CHAIN || self.forced(bid) {
            return None;
        }
        let seq = src_seq(src);
        let at = self.seqs.iter().position(|&s| s == seq)?;
        self.prefix[at].out.get(src_id(src))?.load()
    }
}

/// An account as the chain's provider answers a plain one
/// (`AccountInfo::from(Account)`: no code loaded).
#[inline]
fn plain_info(balance: U256, nonce: u64) -> AccountInfo {
    AccountInfo::from(reth_primitives_traits::Account { balance, nonce, bytecode_hash: None })
}

/// A batch's view of the parent's state with its plan's references in
/// front: the running transaction's sender and recipient (named by
/// [`note_tx`](crate::parallel_transfer::AccountHint::note_tx)) are answered
/// from the output their reference names when it is valid, every other
/// read -- and those when it is not -- from `inner`. A valid reference names
/// the newest writer of the account below this block, so the answer is the
/// parent's either way and the block the same byte for byte. With no view it
/// is `inner` alone.
#[derive(Debug)]
pub struct OneProbeDb<'a, G> {
    view: Option<&'a BuildView>,
    inner: G,
    cur: Option<PlanTx>,
    hits: u64,
    fallbacks: u64,
}

impl<'a, G> OneProbeDb<'a, G> {
    /// `inner` behind `view`.
    pub const fn new(view: Option<&'a BuildView>, inner: G) -> Self {
        Self { view, inner, cur: None, hits: 0, fallbacks: 0 }
    }
}

impl<G> Drop for OneProbeDb<'_, G> {
    fn drop(&mut self) {
        if let Some(view) = self.view {
            if self.hits > 0 {
                view.hits.fetch_add(self.hits, Ordering::Relaxed);
            }
            if self.fallbacks > 0 {
                view.fallbacks.fetch_add(self.fallbacks, Ordering::Relaxed);
            }
        }
    }
}

impl<G: Database> Database for OneProbeDb<'_, G> {
    type Error = G::Error;

    #[inline]
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let (Some(view), Some(cur)) = (self.view, self.cur.as_ref()) {
            let named = if address == cur.sender {
                Some((cur.s_bid, cur.s_src))
            } else if address == cur.recipient {
                Some((cur.r_bid, cur.r_src))
            } else {
                None
            };
            if let Some((bid, src)) = named {
                match view.dense(bid, src) {
                    Some((balance, nonce)) => {
                        self.hits += 1;
                        return Ok(Some(plain_info(balance, nonce)));
                    }
                    None => self.fallbacks += 1,
                }
            }
        }
        self.inner.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<revm::state::Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: revm::primitives::StorageKey,
    ) -> Result<revm::primitives::StorageValue, Self::Error> {
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

impl<G: crate::parallel_transfer::AccountHint> crate::parallel_transfer::AccountHint for OneProbeDb<'_, G> {
    #[inline]
    fn hint_account(&self, address: &Address) -> bool {
        self.inner.hint_account(address)
    }

    #[inline]
    fn note_tx(&mut self, i: usize, key: &(Address, Address)) {
        let Some(view) = self.view else { return };
        self.cur = view.resolved.txs.get(i).copied().filter(|tx| tx.sender == key.0 && tx.recipient == key.1);
        if self.cur.is_none() {
            view.mismatch.store(true, Ordering::Relaxed);
        }
    }

    #[inline]
    fn written_accounts(&self) -> Option<[Address; 2]> {
        self.view?;
        self.cur.map(|tx| [tx.sender, tx.recipient])
    }

    /// Writes the batch's value of the running transaction's `address` into
    /// this block's output when one batch owns the account (transactions of
    /// one sender only touch it); an account with code or none is marked
    /// unheld. The beneficiary is never written.
    #[inline]
    fn write_through(&self, address: &Address, info: Option<&AccountInfo>) {
        let (Some(view), Some(cur)) = (self.view, self.cur.as_ref()) else { return };
        let bid = if *address == cur.sender {
            cur.s_bid
        } else if *address == cur.recipient {
            cur.r_bid
        } else {
            return;
        };
        if !view.resolved.one_writer(bid) || *address == view.beneficiary {
            return;
        }
        let Some(slot) = view.resolved.out.get(bid) else { return };
        match info {
            Some(info) if info.code_hash == KECCAK_EMPTY => slot.store(info.balance, info.nonce),
            _ => slot.poison(),
        }
    }
}

/// Build start: the view of a build with beneficiary `beneficiary` on the
/// block the builder sealed as `parent_built`, whose parent is
/// `grandparent`, that took `resolved`: the verified prefix out of the
/// process's ring.
pub fn view_for(resolved: Arc<Resolved>, grandparent: B256, parent_built: Option<B256>, beneficiary: Address) -> BuildView {
    let prefix = ring().lock().unwrap_or_else(PoisonError::into_inner).prefix(grandparent, parent_built, resolved.seq);
    BuildView::new(resolved, prefix, beneficiary)
}

/// A block sealed at its execution's end from exactly its plan's take with
/// nothing serial, built through `view` on `base` (the builder's hash of
/// that parent `parent_built`) and sealed as `built`, changing nothing
/// outside its transfers but `extra` (its beneficiary and withdrawal
/// recipients): its output goes into the ring. Returns whether it did (not
/// when a transaction ran that was not the plan's).
pub fn note_built(view: &BuildView, base: B256, parent_built: Option<B256>, built: B256, extra: Vec<Address>) -> bool {
    ring().lock().unwrap_or_else(PoisonError::into_inner).record(view, base, parent_built, built, extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(n: u64) -> Address {
        let mut bytes = [0u8; 20];
        bytes[12..].copy_from_slice(&n.to_be_bytes());
        Address::new(bytes)
    }

    /// Three plans through the table: ids, sources, the shared flag.
    #[test]
    fn resolve_names_the_newest_writer() {
        let mut table = Rolling::new(16);
        // Plan 1: s1 -> r1, s1 -> r2, s2 -> r2 (r2 shared by two senders).
        let p1 = resolve_with(&mut table, &[(a(1), a(11)), (a(1), a(12)), (a(2), a(12))]);
        assert_eq!(p1.seq, 1);
        assert_eq!(p1.accounts, 4);
        assert!(p1.txs.iter().all(|t| t.s_src == CHAIN && t.r_src == CHAIN), "nothing before the first plan");
        let r2 = p1.id_of(&a(12)).unwrap();
        assert!(p1.shared(r2));
        assert!(!p1.shared(p1.id_of(&a(11)).unwrap()));
        assert!(!p1.shared(p1.id_of(&a(1)).unwrap()), "a sender's own transfers");
        assert_eq!(p1.txs[1].r_bid, r2);
        assert_eq!(p1.txs[2].r_bid, r2);
        // Every id distinct and dense.
        let mut seen: Vec<u32> = [1, 2, 11, 12].iter().map(|&n| p1.id_of(&a(n)).unwrap()).collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3]);
        // Plan 2: r1 now sends to s1 (s1 a recipient of another sender: shared).
        let p2 = resolve_with(&mut table, &[(a(11), a(1)), (a(3), a(13))]);
        assert_eq!(p2.txs[0].s_src, src(1, p1.id_of(&a(11)).unwrap()));
        assert_eq!(p2.txs[0].r_src, src(1, p1.id_of(&a(1)).unwrap()));
        assert_eq!(p2.txs[1].s_src, CHAIN);
        // Plan 3: the newest writer of s1 is plan 2; of r2 still plan 1.
        let p3 = resolve_with(&mut table, &[(a(1), a(12))]);
        assert_eq!(p3.txs[0].s_src, src(2, p2.id_of(&a(1)).unwrap()));
        assert_eq!(p3.txs[0].r_src, src(1, r2));
        assert_eq!(p3.id_of(&a(13)), None);
    }

    /// An entry older than the kept depth resolves to the chain, and the
    /// sweep every `depth` plans drops it from the table.
    #[test]
    fn the_rolling_table_forgets_past_the_depth() {
        let mut table = Rolling::new(2);
        let p1 = resolve_with(&mut table, &[(a(1), a(11))]);
        let p2 = resolve_with(&mut table, &[(a(2), a(12))]);
        assert_eq!(table.source(&a(1)), CHAIN, "plan 1 is two plans back when plan 3 resolves");
        assert_eq!(table.source(&a(2)), src(2, p2.id_of(&a(2)).unwrap()));
        assert_eq!(table.len(), 4, "plan 2 swept nothing within the depth");
        let p3 = resolve_with(&mut table, &[(a(1), a(12))]);
        assert_eq!(p3.txs[0].s_src, CHAIN, "beyond the depth");
        assert_eq!(p3.txs[0].r_src, src(2, p2.id_of(&a(12)).unwrap()));
        let _ = p1;
        // The sweeps run at plans 2 and 4: plan 4's keeps plans 3 and 4.
        let _p4 = resolve_with(&mut table, &[(a(5), a(15))]);
        assert_eq!(table.len(), 4, "a(1) and a(12) from plan 3, a(5) and a(15) from plan 4");
        assert_eq!(table.source(&a(11)), CHAIN);
        assert_eq!(table.source(&a(2)), CHAIN);
    }

    /// A plan of many transactions spread over every shard resolves each
    /// occurrence to its own address's id.
    #[test]
    fn a_large_plan_resolves_every_occurrence() {
        let mut table = Rolling::new(16);
        let keys: Vec<(Address, Address)> = (0..40_000u64).map(|i| (a(i / 16), a(1_000_000 + (i * 7919) % 30_000))).collect();
        let p1 = resolve_with(&mut table, &keys);
        assert_eq!(p1.accounts, 2_500 + 30_000);
        for (i, t) in p1.txs.iter().enumerate() {
            assert_eq!((t.sender, t.recipient), keys[i]);
            assert_eq!(p1.id_of(&t.sender), Some(t.s_bid));
            assert_eq!(p1.id_of(&t.recipient), Some(t.r_bid));
        }
        let p2 = resolve_with(&mut table, &keys[..100]);
        for t in &p2.txs {
            assert_eq!(t.s_src, src(1, p1.id_of(&t.sender).unwrap()));
            assert_eq!(t.r_src, src(1, p1.id_of(&t.recipient).unwrap()));
        }
    }
    fn output(seq: u64, base: u8, parent_built: Option<u8>, built: u8) -> BuiltOutput {
        BuiltOutput {
            seq,
            base: B256::with_last_byte(base),
            parent_built: parent_built.map(B256::with_last_byte),
            built: B256::with_last_byte(built),
            extra: Vec::new(),
            out: Arc::new(DenseOut::new(1)),
        }
    }

    /// The verified prefix follows built hashes down from the build's
    /// parent while the plans get older, and is empty for a parent this node
    /// did not seal from a plan.
    #[test]
    fn the_prefix_follows_the_built_chain() {
        let mut ring = Ring::new(4);
        // Blocks 10 <- 11 <- 12 (built hashes), canonical bases 100, 101, 102.
        ring.push(output(1, 100, Some(9), 10));
        ring.push(output(2, 101, Some(10), 11));
        ring.push(output(3, 102, Some(11), 12));
        let seqs = |p: Vec<Arc<BuiltOutput>>| p.iter().map(|o| o.seq).collect::<Vec<_>>();
        assert_eq!(seqs(ring.prefix(B256::with_last_byte(102), Some(B256::with_last_byte(12)), 4)), vec![3, 2, 1]);
        assert!(ring.prefix(B256::with_last_byte(102), Some(B256::with_last_byte(99)), 4).is_empty(), "another parent");
        assert!(ring.prefix(B256::with_last_byte(102), None, 4).is_empty(), "a parent this node did not build");
        assert!(ring.prefix(B256::with_last_byte(7), Some(B256::with_last_byte(12)), 4).is_empty(), "another grandparent");
        assert!(ring.prefix(B256::with_last_byte(102), Some(B256::with_last_byte(12)), 3).is_empty(), "a plan not older");
        assert_eq!(seqs(ring.prefix(B256::with_last_byte(101), Some(B256::with_last_byte(11)), 4)), vec![2, 1]);
        // A gap: block 12 built on a block the ring does not hold.
        let mut gap = Ring::new(4);
        gap.push(output(1, 100, Some(9), 10));
        gap.push(output(3, 102, Some(55), 12));
        assert_eq!(seqs(gap.prefix(B256::with_last_byte(102), Some(B256::with_last_byte(12)), 4)), vec![3]);
        // The depth: the oldest output drops.
        ring.push(output(4, 103, Some(12), 13));
        ring.push(output(5, 104, Some(13), 14));
        assert_eq!(ring.len(), 4);
        assert_eq!(seqs(ring.prefix(B256::with_last_byte(104), Some(B256::with_last_byte(14)), 6)), vec![5, 4, 3, 2]);
    }

    /// A dense entry holds a plain account, or says it holds none.
    #[test]
    fn a_dense_entry_holds_one_account() {
        let out = DenseOut::new(3);
        let entry = out.get(1).unwrap();
        assert!(entry.is_empty() && entry.load().is_none());
        let balance = U256::from_limbs([1, 2, 3, u64::MAX]);
        entry.store(balance, 9);
        assert_eq!(entry.load(), Some((balance, 9)));
        entry.poison();
        assert_eq!(entry.load(), None);
        assert!(out.get(3).is_none());
        assert_eq!(std::mem::size_of::<Dense>(), 64);
    }
    /// The previous blocks' beneficiaries and withdrawal recipients, the
    /// system contracts and this block's beneficiary are read from the chain
    /// even when a valid reference names them; the others from the output.
    /// A transaction that is not the plan's keeps the block out of the ring.
    #[test]
    fn the_residual_accounts_read_the_chain() {
        use crate::parallel_transfer::AccountHint as _;
        use revm::database::{CacheDB, EmptyDB};
        let (s, r, w, sys, b) = (a(1), a(2), a(3), crate::warm_ahead::SYSTEM[1], a(5));
        let mut table = Rolling::new(16);
        let mut ring = Ring::new(16);
        let p1 = Arc::new(resolve_with(&mut table, &[(s, r), (s, w), (s, sys), (s, b)]));
        let p2 = Arc::new(resolve_with(&mut table, &[(s, r), (s, w), (s, sys), (s, b)]));
        // Block 1 wrote every account through (the system contract and `b`
        // as plain accounts too).
        let view1 = BuildView::new(Arc::clone(&p1), Vec::new(), a(99));
        {
            let mut db = OneProbeDb::new(Some(&view1), CacheDB::new(EmptyDB::default()));
            for (i, key) in [(s, r), (s, w), (s, sys), (s, b)].iter().enumerate() {
                db.note_tx(i, key);
                for address in db.written_accounts().unwrap() {
                    db.write_through(&address, Some(&plain_info(U256::from(1_000 + i as u64), 7)));
                }
            }
        }
        assert!(!view1.mismatched());
        // `w` a withdrawal recipient of block 1.
        assert!(ring.record(&view1, B256::with_last_byte(100), None, B256::with_last_byte(10), vec![a(99), w]));
        let prefix = ring.prefix(B256::with_last_byte(100), Some(B256::with_last_byte(10)), p2.seq);
        assert_eq!(prefix.len(), 1);
        // Block 2's beneficiary is `b`; the chain has different values.
        let view2 = BuildView::new(Arc::clone(&p2), prefix, b);
        let mut chain = CacheDB::new(EmptyDB::default());
        for address in [s, r, w, sys, b] {
            chain.insert_account_info(address, plain_info(U256::from(5), 1));
        }
        let mut db = OneProbeDb::new(Some(&view2), chain);
        let mut read = |i: usize, key: (Address, Address), address: Address| {
            db.note_tx(i, &key);
            db.basic(address).unwrap().unwrap().balance
        };
        assert_eq!(read(0, (s, r), s), U256::from(1_003), "the sender, last written by block 1's fourth transfer");
        assert_eq!(read(0, (s, r), r), U256::from(1_000), "a plain recipient");
        assert_eq!(read(1, (s, w), w), U256::from(5), "a withdrawal recipient of block 1");
        assert_eq!(read(2, (s, sys), sys), U256::from(5), "a system contract");
        assert_eq!(read(3, (s, b), b), U256::from(5), "this block's beneficiary");
        assert_eq!(read(3, (s, b), r), U256::from(5), "an account the running transaction does not name");
        drop(db);
        assert_eq!((view2.hits(), view2.fallbacks()), (2, 3));
        // A transaction that is not the plan's at its index.
        let mut db = OneProbeDb::new(Some(&view2), CacheDB::new(EmptyDB::default()));
        db.note_tx(0, &(r, s));
        assert!(db.written_accounts().is_none());
        drop(db);
        assert!(view2.mismatched());
        assert!(!ring.record(&view2, B256::with_last_byte(101), Some(B256::with_last_byte(10)), B256::with_last_byte(11), vec![]));
    }
    /// The plan's batches and lanes: a recipient two senders of one batch
    /// pay has one lane id there and one writer; the same recipient paid
    /// from two batches is touched by two, and a lane id names each
    /// transaction's accounts.
    #[test]
    fn a_lane_holds_a_recipient_two_of_its_senders_pay() {
        let keys = [(a(1), a(9)), (a(2), a(9)), (a(3), a(8))];
        let groups = vec![vec![0], vec![1], vec![2]];
        let mut table = Rolling::new(16);
        let two = resolve_with(&mut table, &keys).with_lanes(&groups, 2);
        let lanes = two.lanes.as_ref().expect("lanes");
        assert_eq!(lanes.batch_txs, vec![2, 1]);
        assert_eq!((lanes.batch_of(0), lanes.batch_of(1), lanes.batch_of(2)), (Some(0), Some(0), Some(1)));
        let r = two.id_of(&a(9)).unwrap();
        assert!(two.shared(r), "two senders");
        assert_eq!(lanes.lid(0).unwrap().1, lanes.lid(1).unwrap().1, "one lane id in the batch");
        assert_eq!(lanes.lane(0).unwrap(), &[a(1), a(9), a(2)]);
        assert_eq!(lanes.lane(1).unwrap(), &[a(3), a(8)]);
        assert!(!two.one_writer(r), "lanes not in use: the sender rule");
        lanes.used.store(true, Ordering::Relaxed);
        assert!(two.one_writer(r), "lanes in use: one batch writes it");
        let three = resolve_with(&mut table, &keys).with_lanes(&groups, 3);
        let lanes = three.lanes.as_ref().unwrap();
        lanes.used.store(true, Ordering::Relaxed);
        assert_eq!(lanes.batches(), 3);
        assert!(!three.one_writer(three.id_of(&a(9)).unwrap()), "two batches pay it");
        assert!(three.one_writer(three.id_of(&a(8)).unwrap()));
        assert!(resolve_with(&mut table, &keys).with_lanes(&[vec![0, 1]], 2).lanes.is_none(), "groups not covering the plan");
    }
}

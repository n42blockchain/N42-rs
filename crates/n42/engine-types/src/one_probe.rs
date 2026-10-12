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
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};

use alloy_primitives::{Address, B256, U256, map::AddressMap};

use crate::parallel_transfer::{WARM_SHARDS, warm_shard};

/// The stage (`N42_ONE_PROBE=1|2|3`), 0 (unset) is off. Stage 1 is the one
/// implemented; 2 and 3 run as 1 until theirs exist. Read once.
pub fn stage() -> u8 {
    static N: OnceLock<u8> = OnceLock::new();
    *N.get_or_init(|| {
        let stage = std::env::var("N42_ONE_PROBE").ok().and_then(|v| v.trim().parse::<u8>().ok()).unwrap_or(0).min(3);
        if stage > 1 {
            tracing::warn!(target: "payload_builder", stage, "N42_ONE_PROBE: only stage 1 exists; running stage 1");
        }
        stage
    })
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
    Resolved { seq, txs, ids, shared, accounts: accounts as usize, resolve_us: at.elapsed().as_micros() as u64, out }
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
pub fn resolve(pool: &rayon::ThreadPool, keys: &[(Address, Address)]) -> Option<Arc<Resolved>> {
    if stage() == 0 || keys.is_empty() || keys.len() > u32::MAX as usize / 2 {
        return None;
    }
    let mut table = rolling().lock().unwrap_or_else(PoisonError::into_inner);
    let table = &mut *table;
    Some(Arc::new(pool.install(|| resolve_with(table, keys))))
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
}

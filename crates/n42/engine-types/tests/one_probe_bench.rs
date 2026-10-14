// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one-probe state layout against today's hash layers
//! (`docs/ONE_PROBE_STATE_DESIGN.md`): one block of the flood's shape --
//! 12,500 senders x 16 transfers in sender runs, recipients drawn from a
//! 900,000-account set (`tx_flood::recipient`'s address shape) -- executed in
//! 128 batches of whole sender groups over a synthetic in-flight state of
//! `OP_LAYERS` earlier blocks (default 2) above a base map that stands in for
//! the QMDB view.
//!
//! * `today`: the build's shape as it is. Each batch keeps a hashbrown
//!   `AddressHashMap<BundleAccount>` (`BatchState`), reads an account it
//!   does not hold through the in-flight layers newest first, each in the
//!   output-index form (`FrozenShards::get` in index mode: a shard's
//!   address -> batch index, then the batch map it names), then the base;
//!   commits the three accounts of a transfer into its map; and hands its
//!   touched addresses over by shard. The output is then folded into the
//!   per-shard index with the conflicts summed, as `N42_OUTPUT_INDEX=1`.
//! * `proto`: the recommended layout, confined to this file. At plan time
//!   (timed separately: `plan`) every distinct address of the block gets a
//!   dense block id, and one probe of a rolling last-writer table (address ->
//!   the newest plan that touched it and its id there) resolves where its
//!   value lives: an earlier block's dense output array and the index in it,
//!   or the base. The plan also marks each transaction's first touch of an
//!   account in its batch and gives every account several batches write a
//!   lane each. The batches then do no hash probe: the account is
//!   `work[id]` (loaded on first touch from the resolved `(layer, index)`),
//!   or its lane; the block's output is the dense `work` array with the
//!   lanes folded into it.
//! * `deep`: `proto` with the rolling table covering every account (as it
//!   does on the fleet once the dense outputs are kept for ~32 blocks: a
//!   flood recipient is touched every ~6 blocks), so nothing falls back to
//!   the base map.
//!
//! The post-state of every path is compared with a serial application of
//! the block (balances, nonces, the beneficiary's fees).
//!
//! Ignored; run it pinned and in release:
//!
//! ```text
//! OP_THREADS=64 cargo test --release -p n42-engine-types \
//!   --test one_probe_bench -- --ignored --nocapture
//! ```
//!
//! * `stage1`: `today`'s batch map kept, its reads below the map taken from
//!   the plan's resolved `(layer, index)` instead of the layer walk;
//!   `stage1d` the same over the deep table (no base-map read left): what
//!   remains is the batch map's own cost.
//!
//! `OP_THREADS` (64) the pool, `OP_LAYERS` (2) in-flight blocks,
//! `OP_ROUNDS` (7) measured rounds, `OP_BATCHES` (128), `OP_MODE`
//! (`all`, or one of `today|stage1|stage1d|proto|deep` for a `perf stat` of one path).
#![allow(missing_docs, unreachable_pub, unused_crate_dependencies, unsafe_code)]

use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use alloy_primitives::{map::AddressHashMap, Address, U256};
use revm::database::BundleAccount;
use revm::database::AccountStatus;
use revm::state::AccountInfo;
use n42_engine_types::output_shards::OutputShards;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const SENDERS: usize = 12_500;
const PER_SENDER: usize = 16;
const RECIPIENTS: u64 = 900_000;
const INDEX_SHARDS: usize = 16;
const ROLL_SHARDS: usize = 64;
const PRICE: u64 = 1_000;
const GAS: u64 = 21_000;
const FEE: u64 = GAS * PRICE;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(default)
}

fn sender(i: usize) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x5e;
    bytes[1..9].copy_from_slice(&(i as u64).to_be_bytes());
    bytes[9..17].copy_from_slice(&(i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    Address::new(bytes)
}

/// `tx_flood::recipient`'s shape: the slot big-endian in the first four
/// bytes, then 0x42.
fn recipient(slot: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&(slot as u32).to_be_bytes());
    bytes[4] = 0x42;
    Address::new(bytes)
}

fn beneficiary() -> Address {
    Address::repeat_byte(0xbe)
}

/// `output_shards::address_mix`'s idea: every byte of the address in the
/// shard choice (the flood's recipients share their first bytes).
fn mix(address: &Address) -> u64 {
    let b = &address.0 .0;
    let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let mid = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let hi = u32::from_le_bytes(b[16..20].try_into().unwrap()) as u64;
    let h = lo.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ mid.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ hi.wrapping_mul(0x1656_67b1_9e37_79f9);
    h ^ (h >> 29)
}

fn shard_of(address: &Address, shards: usize) -> usize {
    (((mix(address) >> 48) as usize) * shards) >> 16
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[derive(Clone, Copy)]
struct Tx {
    from: Address,
    to: Address,
    value: u64,
    nonce: u64,
}

/// A block's transfers in sender runs: sender s's sixteen at consecutive
/// nonces from `nonce_base`.
fn block(rng: &mut Rng, nonce_base: u64) -> Vec<Tx> {
    let mut txs = Vec::with_capacity(SENDERS * PER_SENDER);
    for s in 0..SENDERS {
        let from = sender(s);
        for k in 0..PER_SENDER {
            let to = recipient(rng.next() % RECIPIENTS);
            txs.push(Tx { from, to, value: 1 + rng.next() % 1_000, nonce: nonce_base + k as u64 });
        }
    }
    txs
}

/// The batches: whole sender groups, about equal (`batch_groups_one_wave`'s
/// shape for equal groups), each a contiguous range of the sender-run order.
fn batches(txs: usize, count: usize) -> Vec<Range<usize>> {
    let groups = txs / PER_SENDER;
    (0..count)
        .map(|b| (b * groups / count) * PER_SENDER..((b + 1) * groups / count) * PER_SENDER)
        .filter(|r| !r.is_empty())
        .collect()
}

/// The serial truth: `(balance, nonce)` by address.
type Truth = AddressHashMap<(U256, u64)>;

fn apply_serial(truth: &mut Truth, txs: &[Tx]) -> AddressHashMap<(U256, u64)> {
    let mut written: AddressHashMap<(U256, u64)> = AddressHashMap::default();
    for tx in txs {
        let s = truth.get_mut(&tx.from).expect("sender");
        assert_eq!(s.1, tx.nonce);
        s.0 -= U256::from(tx.value + FEE);
        s.1 += 1;
        let sv = *s;
        written.insert(tx.from, sv);
        let r = truth.entry(tx.to).or_insert((U256::ZERO, 0));
        r.0 += U256::from(tx.value);
        let rv = *r;
        written.insert(tx.to, rv);
        let c = truth.get_mut(&beneficiary()).expect("beneficiary");
        c.0 += U256::from(FEE);
        let cv = *c;
        written.insert(beneficiary(), cv);
    }
    written
}

fn info(balance: U256, nonce: u64) -> AccountInfo {
    let mut info = AccountInfo::from_balance(balance);
    info.nonce = nonce;
    info
}

// ---------------------------------------------------------------- today ----

/// One in-flight block as the output index holds it: per shard an address
/// -> batch index, and the batches' maps.
struct IndexedLayer {
    index: Vec<AddressHashMap<u16>>,
    batches: Vec<AddressHashMap<BundleAccount>>,
}

impl IndexedLayer {
    #[inline]
    fn get(&self, address: &Address) -> Option<&BundleAccount> {
        let b = *self.index[shard_of(address, INDEX_SHARDS)].get(address)?;
        self.batches[b as usize].get(address)
    }
}

/// `today`'s parent read: the layers newest first, then the base.
#[inline]
fn chain_read(layers: &[IndexedLayer], base: &AddressHashMap<AccountInfo>, address: &Address) -> Option<AccountInfo> {
    for layer in layers {
        if let Some(account) = layer.get(address) {
            return account.info.clone();
        }
    }
    base.get(address).cloned()
}

fn loaded(info: Option<AccountInfo>) -> BundleAccount {
    let status = match &info {
        None => AccountStatus::LoadedNotExisting,
        Some(i) if i.is_empty() => AccountStatus::LoadedEmptyEIP161,
        Some(_) => AccountStatus::Loaded,
    };
    BundleAccount { original_info: info.clone(), info, storage: Default::default(), status }
}

#[inline]
fn change(entry: &mut BundleAccount, info: AccountInfo) {
    let had = entry.info.as_ref().is_some_and(AccountInfo::has_no_code_and_nonce);
    entry.status = entry.status.on_changed(had);
    entry.info = Some(info);
}

/// One result slot a transaction, as the build's `slots` (one line here).
#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
struct Slot {
    gas: u64,
    index: u32,
    ok: u32,
}

/// A slice written by disjoint indices from several threads.
#[derive(Clone, Copy)]
struct Shared<T>(*mut T);
unsafe impl<T> Send for Shared<T> {}
unsafe impl<T> Sync for Shared<T> {}
impl<T> Shared<T> {
    /// # Safety: no two threads touch the same `i` at once.
    #[inline]
    unsafe fn at(self, i: usize) -> &'static mut T {
        unsafe { &mut *self.0.add(i) }
    }
}

struct TodayBatch {
    map: AddressHashMap<BundleAccount>,
    by_shard: Vec<Vec<Address>>,
}

fn today_batch(
    txs: &[Tx],
    range: Range<usize>,
    parent: &(dyn Fn(usize, bool, &Address) -> Option<AccountInfo> + Sync),
    slots: Shared<Slot>,
) -> TodayBatch {
    let n = range.len();
    let mut map: AddressHashMap<BundleAccount> = AddressHashMap::with_capacity_and_hasher(n + n / 4 + 1, Default::default());
    let coinbase_addr = beneficiary();
    let mut skip_sender: Option<Address> = None;
    for i in range {
        let tx = &txs[i];
        if skip_sender == Some(tx.from) {
            continue;
        }
        let mut read = |a: Address, role: Option<bool>| -> Option<AccountInfo> {
            let entry = map.entry(a).or_insert_with(|| {
                loaded(match role {
                    Some(recipient) => parent(i, recipient, &a),
                    None => parent(usize::MAX, false, &a),
                })
            });
            entry.info.clone()
        };
        let Some(s) = read(tx.from, Some(false)) else { skip_sender = Some(tx.from); continue };
        let spend = U256::from(tx.value + FEE);
        if s.nonce != tx.nonce || s.balance < spend {
            skip_sender = Some(tx.from);
            continue;
        }
        let r = read(tx.to, Some(true)).unwrap_or_default();
        let c = read(coinbase_addr, None).expect("beneficiary");
        let mut s2 = s;
        s2.balance -= spend;
        s2.nonce += 1;
        let mut r2 = r;
        r2.balance += U256::from(tx.value);
        let mut c2 = c;
        c2.balance += U256::from(FEE);
        change(map.get_mut(&tx.from).unwrap(), s2);
        change(map.get_mut(&tx.to).unwrap(), r2);
        change(map.get_mut(&coinbase_addr).unwrap(), c2);
        unsafe { *slots.at(i) = Slot { gas: GAS, index: i as u32, ok: 1 } };
    }
    // The hand-over: the batch's addresses listed by shard (`OutputShards::add`).
    let mut by_shard: Vec<Vec<Address>> = (0..INDEX_SHARDS).map(|_| Vec::with_capacity(map.len() / INDEX_SHARDS + 16)).collect();
    for a in map.keys() {
        by_shard[shard_of(a, INDEX_SHARDS)].push(*a);
    }
    TodayBatch { map, by_shard }
}

/// The index fold: per shard, address -> batch, accounts several batches
/// wrote summed into the shard's conflicts map.
fn today_fold(batches: &[TodayBatch], pool: &rayon::ThreadPool) -> Vec<(AddressHashMap<u16>, AddressHashMap<BundleAccount>)> {
    let mut parts: Vec<(AddressHashMap<u16>, AddressHashMap<BundleAccount>)> =
        (0..INDEX_SHARDS).map(|_| Default::default()).collect();
    pool.scope(|scope| {
        for (s, part) in parts.iter_mut().enumerate() {
            scope.spawn(move |_| {
                let total: usize = batches.iter().map(|b| b.by_shard[s].len()).sum();
                part.0.reserve(total);
                for (b, batch) in batches.iter().enumerate() {
                    for a in &batch.by_shard[s] {
                        match part.0.get(a).copied() {
                            None => {
                                part.0.insert(*a, b as u16);
                            }
                            Some(first) => {
                                let account = &batch.map[a];
                                let delta = account.info.as_ref().unwrap().balance
                                    .wrapping_sub(account.original_info.as_ref().map_or(U256::ZERO, |i| i.balance));
                                let dn = account.info.as_ref().unwrap().nonce
                                    - account.original_info.as_ref().map_or(0, |i| i.nonce);
                                if first != u16::MAX {
                                    part.1.insert(*a, batches[first as usize].map[a].clone());
                                    part.0.insert(*a, u16::MAX);
                                }
                                let staged = part.1.get_mut(a).unwrap().info.as_mut().unwrap();
                                staged.balance = staged.balance.wrapping_add(delta);
                                staged.nonce += dn;
                            }
                        }
                    }
                }
            });
        }
    });
    parts
}

fn today_final(batches: &[TodayBatch], parts: &[(AddressHashMap<u16>, AddressHashMap<BundleAccount>)]) -> Vec<(Address, U256, u64)> {
    let mut out = Vec::new();
    for (index, conflicts) in parts {
        for (a, b) in index {
            let account = if *b == u16::MAX { &conflicts[a] } else { &batches[*b as usize].map[a] };
            let i = account.info.as_ref().unwrap();
            out.push((*a, i.balance, i.nonce));
        }
    }
    out.sort_unstable_by_key(|e| e.0);
    out
}

// ---------------------------------------------------------------- proto ----

/// One account in a dense array: a cache line.
#[repr(C, align(64))]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Dense {
    balance: U256,
    nonce: u64,
    /// 0: not loaded yet by this batch; 1: loaded, a plain account; 2:
    /// loaded, absent. Checked on the line the transfer uses anyway, so a
    /// transaction skipped by its sender's break leaves nothing unloaded.
    tag: u64,
}

/// Where a value lives, resolved at plan time: the source (0.. the in-flight
/// layers newest first, [`BASE_HASH`] the base map read by address,
/// [`BASE_DENSE`] the base as a dense array) and the index in it.
const BASE_HASH: u32 = 0xfe;
const BASE_DENSE: u32 = 0xff;

#[inline]
const fn pack(src: u32, index: u32) -> u64 {
    ((src as u64) << 32) | index as u64
}

/// A plan's transaction: both accounts' block ids, where each one's value
/// is (used on the batch's first touch), its lane when several batches
/// write it, and the first-touch flags.
#[derive(Clone, Copy, Default)]
struct PlanTx {
    s_bid: u32,
    r_bid: u32,
    s_src: u64,
    r_src: u64,
    s_lane: u32,
    r_lane: u32,
    first: u8,
}
const S_FIRST: u8 = 1;
const R_FIRST: u8 = 2;
const NO_LANE: u32 = u32::MAX;

struct Plan {
    txs: Vec<PlanTx>,
    /// Block id -> address (the output's keys).
    addrs: Vec<Address>,
    /// Block id -> where its pre-block value lives (the fold of lanes).
    srcs: Vec<u64>,
    lanes: usize,
    /// Per block id: (first lane, writers) for ids several batches write.
    lane_of: Vec<(u32, u32)>,
}

struct DenseLayer {
    out: Vec<Dense>,
}

struct ProtoState<'a> {
    layers: &'a [DenseLayer],
    base: &'a AddressHashMap<AccountInfo>,
    base_dense: &'a [Dense],
}

impl ProtoState<'_> {
    #[inline]
    fn load(&self, src: u64, address: &Address) -> Dense {
        let (layer, index) = ((src >> 32) as u32, src as u32);
        match layer {
            BASE_DENSE => self.base_dense[index as usize],
            BASE_HASH => match self.base.get(address) {
                Some(i) => Dense { balance: i.balance, nonce: i.nonce, tag: 1 },
                None => Dense { tag: 2, ..Dense::default() },
            },
            k => self.layers[k as usize].out[index as usize],
        }
    }
}

/// The plan-time resolve, on the pool: block ids by address (sharded, a
/// local map a shard), one probe of the rolling last-writer table an
/// address, the table updated to this plan, then the batches' first-touch
/// flags and lanes.
fn plan(txs: &[Tx], batches: &[Range<usize>], roll: &mut [AddressHashMap<u64>], new_layer: u32, pool: &rayon::ThreadPool) -> Plan {
    use rayon::prelude::*;
    let occ = txs.len() * 2;
    let address_of = |j: usize| if j & 1 == 0 { txs[j >> 1].from } else { txs[j >> 1].to };
    pool.install(|| {
        // 1. Occurrences bucketed by shard (counting sort over chunks).
        const CHUNK: usize = 1 << 14;
        let chunks = occ.div_ceil(CHUNK);
        let shard: Vec<u8> = (0..occ).into_par_iter().with_min_len(4096).map(|j| shard_of(&address_of(j), ROLL_SHARDS) as u8).collect();
        let counts: Vec<[u32; ROLL_SHARDS]> = (0..chunks)
            .into_par_iter()
            .map(|c| {
                let mut k = [0u32; ROLL_SHARDS];
                for j in c * CHUNK..((c + 1) * CHUNK).min(occ) {
                    k[shard[j] as usize] += 1;
                }
                k
            })
            .collect();
        let mut starts = vec![[0u32; ROLL_SHARDS]; chunks];
        let mut shard_start = [0usize; ROLL_SHARDS + 1];
        let mut at = 0u32;
        for s in 0..ROLL_SHARDS {
            shard_start[s] = at as usize;
            for c in 0..chunks {
                starts[c][s] = at;
                at += counts[c][s];
            }
        }
        shard_start[ROLL_SHARDS] = at as usize;
        let mut by_shard = vec![0u32; occ];
        let out = Shared(by_shard.as_mut_ptr());
        starts.par_iter().enumerate().for_each(|(c, start)| {
            let mut pos = *start;
            for j in c * CHUNK..((c + 1) * CHUNK).min(occ) {
                let s = shard[j] as usize;
                unsafe { *out.at(pos[s] as usize) = j as u32 };
                pos[s] += 1;
            }
        });
        // 2. Per shard: local ids, one probe of the rolling table a new
        //    address.
        let mut local = vec![0u32; occ];
        let local_out = Shared(local.as_mut_ptr());
        let per_shard: Vec<(Vec<Address>, Vec<u64>)> = (0..ROLL_SHARDS)
            .into_par_iter()
            .map(|s| {
                let list = &by_shard[shard_start[s]..shard_start[s + 1]];
                let mut ids: AddressHashMap<u32> = AddressHashMap::with_capacity_and_hasher(list.len(), Default::default());
                let (mut addrs, mut srcs) = (Vec::with_capacity(list.len()), Vec::with_capacity(list.len()));
                let table = &roll[s];
                for &j in list {
                    let a = address_of(j as usize);
                    let id = *ids.entry(a).or_insert_with(|| {
                        addrs.push(a);
                        srcs.push(table.get(&a).copied().unwrap_or(pack(BASE_HASH, 0)));
                        (addrs.len() - 1) as u32
                    });
                    unsafe { *local_out.at(j as usize) = id };
                }
                (addrs, srcs)
            })
            .collect();
        let mut offset = [0u32; ROLL_SHARDS];
        let mut total = 0u32;
        for s in 0..ROLL_SHARDS {
            offset[s] = total;
            total += per_shard[s].0.len() as u32;
        }
        // 3. The rolling table moved on to this plan; the block-wide arrays.
        roll.par_iter_mut().enumerate().for_each(|(s, table)| {
            for (k, a) in per_shard[s].0.iter().enumerate() {
                table.insert(*a, pack(new_layer, offset[s] + k as u32));
            }
        });
        let mut addrs = Vec::with_capacity(total as usize);
        let mut srcs = Vec::with_capacity(total as usize);
        for (a, s) in &per_shard {
            addrs.extend_from_slice(a);
            srcs.extend_from_slice(s);
        }
        let bid = |j: usize| offset[shard[j] as usize] + local[j];
        let mut ptxs: Vec<PlanTx> = (0..txs.len())
            .into_par_iter()
            .with_min_len(4096)
            .map(|i| {
                let (s, r) = (bid(2 * i), bid(2 * i + 1));
                PlanTx { s_bid: s, r_bid: r, s_src: srcs[s as usize], r_src: srcs[r as usize], s_lane: NO_LANE, r_lane: NO_LANE, first: 0 }
            })
            .collect();
        // 4. First touch in each batch; writers an id.
        let writers: Vec<AtomicU32> = (0..total).map(|_| AtomicU32::new(0)).collect();
        let ptx = Shared(ptxs.as_mut_ptr());
        batches.par_iter().enumerate().for_each_init(
            || vec![0u32; total as usize],
            |stamp, (b, range)| {
                let mark = b as u32 + 1;
                for i in range.clone() {
                    let p = unsafe { ptx.at(i) };
                    for (id, flag) in [(p.s_bid, S_FIRST), (p.r_bid, R_FIRST)] {
                        if stamp[id as usize] != mark {
                            stamp[id as usize] = mark;
                            p.first |= flag;
                            writers[id as usize].fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            },
        );
        // 5. Lanes for the ids several batches write.
        let mut lane_of = vec![(0u32, 0u32); total as usize];
        let mut lanes = 0u32;
        for (id, w) in writers.iter().enumerate() {
            let w = w.load(Ordering::Relaxed);
            if w > 1 {
                lane_of[id] = (lanes, w);
                lanes += w;
            }
        }
        let cursor: Vec<AtomicU32> = (0..total).map(|_| AtomicU32::new(0)).collect();
        batches.par_iter().for_each(|range| {
            for i in range.clone() {
                let p = unsafe { ptx.at(i) };
                if p.first & S_FIRST != 0 && lane_of[p.s_bid as usize].1 > 1 {
                    p.s_lane = lane_of[p.s_bid as usize].0 + cursor[p.s_bid as usize].fetch_add(1, Ordering::Relaxed);
                }
                if p.first & R_FIRST != 0 && lane_of[p.r_bid as usize].1 > 1 {
                    p.r_lane = lane_of[p.r_bid as usize].0 + cursor[p.r_bid as usize].fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        // A later touch in the same batch uses the lane of the first touch
        // (as sender or recipient). Rare: an account several batches write
        // and this one touches twice; found by a scan back in the batch.
        batches.par_iter().for_each(|range| {
            let lane_back = |i: usize, id: u32| -> u32 {
                let mut k = i;
                while k > range.start {
                    k -= 1;
                    let q = unsafe { ptx.at(k) };
                    if q.s_bid == id && q.first & S_FIRST != 0 {
                        return q.s_lane;
                    }
                    if q.r_bid == id && q.first & R_FIRST != 0 {
                        return q.r_lane;
                    }
                }
                NO_LANE
            };
            for i in range.clone() {
                let p = unsafe { ptx.at(i) };
                if p.first & S_FIRST == 0 && lane_of[p.s_bid as usize].1 > 1 {
                    p.s_lane = lane_back(i, p.s_bid);
                }
                if p.first & R_FIRST == 0 && lane_of[p.r_bid as usize].1 > 1 {
                    p.r_lane = lane_back(i, p.r_bid);
                }
            }
        });
        Plan { txs: ptxs, addrs, srcs, lanes: lanes as usize, lane_of }
    })
}

/// One batch of the prototype: no hash probe; `work[id]` or a lane.
#[inline(never)]
fn proto_batch(txs: &[Tx], plan: &[PlanTx], range: Range<usize>, state: &ProtoState<'_>, work: Shared<Dense>, lanes: Shared<Dense>, slots: Shared<Slot>) -> U256 {
    let mut fees = U256::ZERO;
    let mut skip: u32 = NO_LANE;
    for i in range {
        let (tx, p) = (&txs[i], &plan[i]);
        if skip == p.s_bid {
            continue;
        }
        let s = unsafe { if p.s_lane != NO_LANE { lanes.at(p.s_lane as usize) } else { work.at(p.s_bid as usize) } };
        if s.tag == 0 {
            *s = state.load(p.s_src, &tx.from);
        }
        let spend = U256::from(tx.value + FEE);
        if s.tag != 1 || s.nonce != tx.nonce || s.balance < spend {
            skip = p.s_bid;
            continue;
        }
        let r = unsafe { if p.r_lane != NO_LANE { lanes.at(p.r_lane as usize) } else { work.at(p.r_bid as usize) } };
        if r.tag == 0 {
            *r = state.load(p.r_src, &tx.to);
        }
        s.balance -= spend;
        s.nonce += 1;
        r.balance += U256::from(tx.value);
        r.tag = 1;
        fees += U256::from(FEE);
        unsafe { *slots.at(i) = Slot { gas: GAS, index: i as u32, ok: 1 } };
    }
    fees
}

/// The lanes folded into `work`: the pre-block value plus every lane's
/// change.
fn proto_fold(plan: &Plan, state: &ProtoState<'_>, work: &mut [Dense], lanes: &[Dense], pool: &rayon::ThreadPool) {
    use rayon::prelude::*;
    pool.install(|| {
        work.par_iter_mut().enumerate().with_min_len(4096).for_each(|(id, slot)| {
            let (first, writers) = plan.lane_of[id];
            if writers > 1 {
                let pre = state.load(plan.srcs[id], &plan.addrs[id]);
                let mut acc = pre;
                for lane in lanes[first as usize..(first + writers) as usize].iter().filter(|l| l.tag != 0) {
                    acc.balance = acc.balance.wrapping_add(lane.balance.wrapping_sub(pre.balance));
                    acc.nonce += lane.nonce - pre.nonce;
                    acc.tag = acc.tag.min(lane.tag);
                }
                *slot = acc;
            }
        });
    });
}

// ------------------------------------------------------------------ main ----

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() { 0.0 } else { v[v.len() / 2] }
}

#[test]
#[ignore = "a timing benchmark: run it pinned, release, on a quiet box"]
fn bench_one_probe_state() {
    let threads = env_usize("OP_THREADS", 64);
    let layers_n = env_usize("OP_LAYERS", 2);
    let rounds = env_usize("OP_ROUNDS", 7);
    let nbatches = env_usize("OP_BATCHES", 128);
    let mode = std::env::var("OP_MODE").unwrap_or_else(|_| "all".into());
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let setup_at = Instant::now();

    // The base (the QMDB view's stand-in): every sender and recipient.
    let mut base: AddressHashMap<AccountInfo> = AddressHashMap::default();
    let mut base_dense: Vec<Dense> = Vec::new();
    let mut gid: AddressHashMap<u32> = AddressHashMap::default();
    let rich = U256::from(10u64).pow(U256::from(24u64));
    let mut add_base = |a: Address, balance: U256| {
        base.insert(a, info(balance, 0));
        gid.insert(a, base_dense.len() as u32);
        base_dense.push(Dense { balance, nonce: 0, tag: 1 });
    };
    for s in 0..SENDERS {
        add_base(sender(s), rich);
    }
    for r in 0..RECIPIENTS {
        add_base(recipient(r), U256::from(1_000_000_000u64));
    }
    add_base(beneficiary(), U256::from(1u64));
    let mut truth: Truth = base.iter().map(|(a, i)| (*a, (i.balance, i.nonce))).collect();

    // The rolling last-writer tables: shallow (the in-flight layers only)
    // and deep (every account, as dense outputs kept ~32 blocks give it).
    let mut roll_shallow: Vec<AddressHashMap<u64>> = (0..ROLL_SHARDS).map(|_| AddressHashMap::default()).collect();
    let mut roll_deep: Vec<AddressHashMap<u64>> = (0..ROLL_SHARDS).map(|_| AddressHashMap::default()).collect();
    for (a, g) in &gid {
        roll_deep[shard_of(a, ROLL_SHARDS)].insert(*a, pack(BASE_DENSE, *g));
    }

    // The in-flight blocks, oldest first, applied serially; each kept in
    // both forms. Layer k (newest first) is plan `layers_n - 1 - k`.
    let mut rng = Rng(42);
    let mut indexed: Vec<IndexedLayer> = Vec::new();
    let mut dense: Vec<DenseLayer> = Vec::new();
    let batch_ranges = batches(SENDERS * PER_SENDER, nbatches);
    for l in 0..layers_n {
        let txs = block(&mut rng, (l * PER_SENDER) as u64);
        let pre = truth.clone();
        let written = apply_serial(&mut truth, &txs);
        // Index form: an account in the batch of its first writer.
        let mut index: Vec<AddressHashMap<u16>> = (0..INDEX_SHARDS).map(|_| AddressHashMap::default()).collect();
        let mut maps: Vec<AddressHashMap<BundleAccount>> = (0..batch_ranges.len()).map(|_| AddressHashMap::default()).collect();
        let mut ids: AddressHashMap<u32> = AddressHashMap::default();
        let mut out: Vec<Dense> = Vec::new();
        for (b, range) in batch_ranges.iter().enumerate() {
            for tx in &txs[range.clone()] {
                for a in [tx.from, tx.to, beneficiary()] {
                    if index[shard_of(&a, INDEX_SHARDS)].contains_key(&a) {
                        continue;
                    }
                    index[shard_of(&a, INDEX_SHARDS)].insert(a, b as u16);
                    let (pb, pn) = pre.get(&a).copied().unwrap_or_default();
                    let (b2, n2) = written[&a];
                    let mut account = loaded(Some(info(pb, pn)));
                    change(&mut account, info(b2, n2));
                    maps[b].insert(a, account);
                    // The dense form: the plan's ids in first-touch order;
                    // the beneficiary is the block's residual, not a plan
                    // account.
                    if a != beneficiary() {
                        ids.insert(a, out.len() as u32);
                        out.push(Dense { balance: b2, nonce: n2, tag: 1 });
                    }
                }
            }
        }
        // Named by plan sequence (oldest 0) here, newest-first below.
        for (a, id) in &ids {
            let sh = shard_of(a, ROLL_SHARDS);
            roll_shallow[sh].insert(*a, pack(l as u32, *id));
            roll_deep[sh].insert(*a, pack(l as u32, *id));
        }
        indexed.insert(0, IndexedLayer { index, batches: maps });
        dense.insert(0, DenseLayer { out });
    }
    // Plan sequence -> layer, newest first (0 = the parent).
    for table in roll_shallow.iter_mut().chain(roll_deep.iter_mut()) {
        for v in table.values_mut() {
            let src = (*v >> 32) as u32;
            if src < BASE_HASH {
                *v = pack(layers_n as u32 - 1 - src, *v as u32);
            }
        }
    }
    // The beneficiary is not a plan account: the build reads it from the
    // chain (the residual), so the rolling tables do not hold it.
    for table in roll_shallow.iter_mut().chain(roll_deep.iter_mut()) {
        table.remove(&beneficiary());
    }

    // The measured block and its serial truth.
    let txs = block(&mut rng, (layers_n * PER_SENDER) as u64);
    let coinbase_pre = truth[&beneficiary()].0;
    let mut truth_after = truth.clone();
    let written = apply_serial(&mut truth_after, &txs);
    let mut expected: Vec<(Address, U256, u64)> = written.iter().map(|(a, (b, n))| (*a, *b, *n)).collect();
    expected.sort_unstable_by_key(|e| e.0);
    let distinct = expected.len() - 1;
    let in_layers = txs.iter().filter(|tx| indexed.iter().any(|l| l.get(&tx.to).is_some())).count();
    println!(
        "setup {:.1} s: {} transfers, {} batches, {} distinct accounts, {} layers (recipients found in a layer: {:.1}%), {} threads",
        setup_at.elapsed().as_secs_f64(),
        txs.len(),
        batch_ranges.len(),
        distinct,
        layers_n,
        100.0 * in_layers as f64 / txs.len() as f64,
        threads
    );
    println!(
        "entry sizes: BundleAccount {} B (a batch map of ~{} transfers: {} buckets), Dense {} B",
        std::mem::size_of::<BundleAccount>(),
        batch_ranges[0].len(),
        AddressHashMap::<BundleAccount>::with_capacity_and_hasher(batch_ranges[0].len() * 5 / 4 + 1, Default::default()).capacity(),
        std::mem::size_of::<Dense>()
    );

    let mut slots: Vec<Slot> = vec![Slot::default(); txs.len()];
    let (mut t_exec, mut t_fold) = (Vec::new(), Vec::new());
    let (mut s_exec, mut s_fold) = (Vec::new(), Vec::new());
    let (mut sd_exec, mut sd_fold) = (Vec::new(), Vec::new());
    let (mut p_plan, mut p_exec, mut p_fold) = (Vec::new(), Vec::new(), Vec::new());
    let (mut d_plan, mut d_exec, mut d_fold) = (Vec::new(), Vec::new(), Vec::new());
    let want = |m: &str| mode == "all" || mode == m;

    for round in 0..rounds + 1 {
        let measured = round > 0;
        // today, and stage 1 (today's batch map over the resolved reads)
        for variant in 0..3 {
            let name = ["today", "stage1", "stage1d"][variant];
            if !want(name) {
                continue;
            }
            let stage1 = variant > 0;
            let resolved = stage1.then(|| {
                let mut roll = if variant == 2 { roll_deep.clone() } else { roll_shallow.clone() };
                let p = plan(&txs, &batch_ranges, &mut roll, 0x80, &pool);
                drop(roll);
                p
            });
            let state = ProtoState { layers: &dense, base: &base, base_dense: &base_dense };
            let chain = |_: usize, _: bool, a: &Address| chain_read(&indexed, &base, a);
            let by_ref = |i: usize, recipient: bool, a: &Address| -> Option<AccountInfo> {
                let Some(p) = resolved.as_ref().filter(|_| i != usize::MAX) else { return chain_read(&indexed, &base, a) };
                let t = &p.txs[i];
                let d = state.load(if recipient { t.r_src } else { t.s_src }, a);
                (d.tag == 1).then(|| info(d.balance, d.nonce))
            };
            let parent: &(dyn Fn(usize, bool, &Address) -> Option<AccountInfo> + Sync) = if stage1 { &by_ref } else { &chain };
            let sl = Shared(slots.as_mut_ptr());
            let at = Instant::now();
            let mut outs: Vec<Option<TodayBatch>> = (0..batch_ranges.len()).map(|_| None).collect();
            pool.scope(|scope| {
                for (slot, range) in outs.iter_mut().zip(&batch_ranges) {
                    let txs = &txs;
                    scope.spawn(move |_| *slot = Some(today_batch(txs, range.clone(), parent, sl)));
                }
            });
            let exec = at.elapsed().as_secs_f64() * 1e3;
            let outs: Vec<TodayBatch> = outs.into_iter().map(Option::unwrap).collect();
            let at = Instant::now();
            let parts = today_fold(&outs, &pool);
            let fold = at.elapsed().as_secs_f64() * 1e3;
            if measured {
                if variant == 2 {
                    sd_exec.push(exec);
                    sd_fold.push(fold);
                } else if stage1 {
                    s_exec.push(exec);
                    s_fold.push(fold);
                } else {
                    t_exec.push(exec);
                    t_fold.push(fold);
                }
            }
            if round <= 1 {
                assert_eq!(today_final(&outs, &parts), expected, "{name}'s post-state");
            }
            pool.install(|| drop((outs, parts, resolved)));
        }
        for deep in [false, true] {
            if !want(if deep { "deep" } else { "proto" }) {
                continue;
            }
            let mut roll = if deep { roll_deep.clone() } else { roll_shallow.clone() };
            // The new plan is "layer -1": its own index is never read here.
            let at = Instant::now();
            let p = plan(&txs, &batch_ranges, &mut roll, 0x80, &pool);
            let plan_ms = at.elapsed().as_secs_f64() * 1e3;
            drop(roll);
            let state = ProtoState { layers: &dense, base: &base, base_dense: &base_dense };
            // Made with the plan (as `PreparedExec`'s slots): allocated and
            // touched outside the timed execution.
            let mut work: Vec<Dense> = vec![Dense::default(); p.addrs.len()];
            let mut lanes: Vec<Dense> = vec![Dense::default(); p.lanes];
            let (wk, ln, sl) = (Shared(work.as_mut_ptr()), Shared(lanes.as_mut_ptr()), Shared(slots.as_mut_ptr()));
            let at = Instant::now();
            let mut fees: Vec<U256> = vec![U256::ZERO; batch_ranges.len()];
            pool.scope(|scope| {
                for (fee, range) in fees.iter_mut().zip(&batch_ranges) {
                    let (txs, ptxs, state) = (&txs, &p.txs, &state);
                    scope.spawn(move |_| *fee = proto_batch(txs, ptxs, range.clone(), state, wk, ln, sl));
                }
            });
            let exec = at.elapsed().as_secs_f64() * 1e3;
            let at = Instant::now();
            proto_fold(&p, &state, &mut work, &lanes, &pool);
            let fold = at.elapsed().as_secs_f64() * 1e3;
            if measured {
                if deep {
                    d_plan.push(plan_ms);
                    d_exec.push(exec);
                    d_fold.push(fold);
                } else {
                    p_plan.push(plan_ms);
                    p_exec.push(exec);
                    p_fold.push(fold);
                }
            }
            if round <= 1 {
                let mut got: Vec<(Address, U256, u64)> =
                    p.addrs.iter().zip(&work).filter(|(_, d)| d.tag != 0).map(|(a, d)| (*a, d.balance, d.nonce)).collect();
                let fee_total = fees.iter().fold(U256::ZERO, |a, f| a + *f);
                got.push((beneficiary(), coinbase_pre + fee_total, 0));
                got.sort_unstable_by_key(|e| e.0);
                assert_eq!(got, expected, "{}'s post-state", if deep { "deep" } else { "proto" });
                if round == 1 {
                    let conflicts = p.lane_of.iter().filter(|l| l.1 > 1).count();
                    println!(
                        "{}: {} block ids, {} written by several batches ({} lanes), plan {:.1} ms",
                        if deep { "deep" } else { "proto" },
                        p.addrs.len(),
                        conflicts,
                        p.lanes,
                        plan_ms
                    );
                }
            }
            pool.install(|| drop((p, work, lanes)));
        }
    }
    let line = |name: &str, plan: &[f64], exec: &[f64], fold: &[f64]| {
        if exec.is_empty() {
            return;
        }
        println!(
            "{name:>6}: exec p50 {:6.2} ms (min {:6.2}), output fold p50 {:5.2} ms, plan-time resolve p50 {:5.2} ms",
            median(exec.to_vec()),
            exec.iter().cloned().fold(f64::MAX, f64::min),
            median(fold.to_vec()),
            median(plan.to_vec()),
        );
    };
    line("today", &[], &t_exec, &t_fold);
    line("stage1", &[], &s_exec, &s_fold);
    line("stage1d", &[], &sd_exec, &sd_fold);
    line("proto", &p_plan, &p_exec, &p_fold);
    line("deep", &d_plan, &d_exec, &d_fold);
    println!("post-states equal to the serial application: yes (asserted)");
}

/// The node's own parent stand-in for [`bench_node_batch_state`]: one map
/// probe a read (the stage-1 resolved read's cost order, not the layer walk).
#[derive(Debug, Clone)]
struct MapDb(std::sync::Arc<AddressHashMap<AccountInfo>>);

impl revm::Database for MapDb {
    type Error = std::convert::Infallible;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.0.get(&address).cloned())
    }
    fn code_by_hash(&mut self, _code_hash: alloy_primitives::B256) -> Result<revm::state::Bytecode, Self::Error> {
        Ok(revm::state::Bytecode::default())
    }
    fn storage(&mut self, _address: Address, _index: revm::primitives::StorageKey) -> Result<U256, Self::Error> {
        Ok(U256::ZERO)
    }
    fn block_hash(&mut self, _number: u64) -> Result<alloy_primitives::B256, Self::Error> {
        Ok(alloy_primitives::B256::ZERO)
    }
}

impl n42_engine_types::parallel_transfer::AccountHint for MapDb {}

/// One batch of the node's `BatchState` -- on its map (stage 1) or on the
/// plan's lane (stage 2) -- driven as the batch loop drives it: the
/// transaction named, three reads, the commit; the bundle taken at the end.
fn node_batch(txs: &[Tx], members: &[&Vec<usize>], state: n42_engine_types::batch_state::BatchState<MapDb>) -> revm::database::BundleState {
    node_batch_run(txs, members, state).take_bundle()
}

/// [`node_batch`]'s loop, the state left open.
fn node_batch_run(
    txs: &[Tx],
    members: &[&Vec<usize>],
    mut state: n42_engine_types::batch_state::BatchState<MapDb>,
) -> n42_engine_types::batch_state::BatchState<MapDb> {
    use revm::Database as _;
    let coinbase = beneficiary();
    for group in members {
        for &i in group.iter() {
            let tx = &txs[i];
            state.note_tx(i, &(tx.from, tx.to));
            let s = state.basic(tx.from).unwrap().expect("sender");
            let spend = U256::from(tx.value + FEE);
            if s.nonce != tx.nonce || s.balance < spend {
                break;
            }
            let r = state.basic(tx.to).unwrap();
            let c = state.basic(coinbase).unwrap().expect("beneficiary");
            let plain = n42_engine_types::fast_transfer::PlainTransfer {
                caller: tx.from,
                sender_balance: s.balance - spend,
                sender: s,
                to: tx.to,
                recipient_balance: r.as_ref().map_or(U256::ZERO, |r| r.balance) + U256::from(tx.value),
                recipient: r,
                beneficiary: coinbase,
                coinbase_balance: c.balance + U256::from(FEE),
                coinbase: c,
            };
            state.commit_transfer(plain).expect("commit");
            state.after_commit();
        }
    }
    state
}

/// The node's batch state on the flood's block: the per-batch map (stage 1)
/// against the plan's lanes (stage 2, `BatchState::with_lane`), the same
/// batches of whole sender groups on `OP_THREADS` threads, each batch's
/// bundle checked equal; and the plan-time cost of the resolve and of the
/// lanes (`one_probe::resolve_with`, `Resolved::with_lanes`) on the same
/// pool.
#[test]
#[ignore = "a timing benchmark: run it pinned, release, on a quiet box"]
fn bench_node_batch_state() {
    use n42_engine_types::{batch_state::BatchState, one_probe, parallel_transfer};
    let threads = env_usize("OP_THREADS", 64);
    let rounds = env_usize("OP_ROUNDS", 7);
    let nbatches = env_usize("OP_BATCHES", 128);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let mut rng = Rng(42);
    let txs = block(&mut rng, 0);
    let mut parent = AddressHashMap::default();
    let rich = U256::from(10u64).pow(U256::from(24u64));
    // As the node's provider answers: no code loaded (`AccountInfo::from(Account)`).
    let plain = |balance: U256| AccountInfo { code: None, ..info(balance, 0) };
    for s in 0..SENDERS {
        parent.insert(sender(s), plain(rich));
    }
    for tx in &txs {
        parent.entry(tx.to).or_insert_with(|| plain(U256::from(1_000_000_000u64)));
    }
    parent.insert(beneficiary(), plain(U256::from(1u64)));
    let db = MapDb(std::sync::Arc::new(parent));
    let keys: Vec<(Address, Address)> = txs.iter().map(|tx| (tx.from, tx.to)).collect();
    let groups = parallel_transfer::partition_by_sender(&keys, beneficiary()).expect("groups");
    let batches = parallel_transfer::batch_groups_one_wave(&groups, keys.len(), nbatches);
    let (mut map_ms, mut lane_ms, mut direct_ms, mut resolve_ms, mut lanes_ms) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    // Stage 4: the batch loop handing lanes over, the shards' hand-over
    // (`add_lane`), the freeze, and the freeze's lane materialisation; stage
    // 3's hand-over and freeze of its bundles beside.
    let (mut out_ms, mut out_add_ms, mut out_freeze_ms, mut out_mat_ms, mut s3_add_ms, mut s3_freeze_ms) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    type Output = (revm::database::BundleState, Option<n42_engine_types::batch_state::LaneOutput>);
    // The persistent address table in the fleet's steady state: when a plan
    // resolves, the previous plan (its block being built) is pending and
    // every older one is recorded. The record (the merge into the table, on
    // the resolver thread behind the build) is timed apart.
    let table = one_probe::Rolling::new(16);
    let mut record_ms = Vec::new();
    let mut root_rows: Vec<[f64; 10]> = Vec::new();
    let mut leaves_n = 0usize;
    let mut previous: Option<(u64, std::sync::Arc<one_probe::PlanIds>)> = None;
    for round in 0..rounds + 1 {
        let at = Instant::now();
        let resolved = pool.install(|| one_probe::resolve_with(&table, &keys));
        let resolve = at.elapsed().as_secs_f64() * 1e3;
        let at = Instant::now();
        if let Some((seq, ids)) = previous.take() {
            pool.install(|| table.record(seq, &ids));
        }
        let record = at.elapsed().as_secs_f64() * 1e3;
        assert_eq!(table.pending(), 1);
        previous = Some((resolved.seq, resolved.ids()));
        let at = Instant::now();
        let plan = std::sync::Arc::new(pool.install(|| resolved.with_lanes(&groups, nbatches).with_fold(true).with_lane_output(true)));
        let lanes = at.elapsed().as_secs_f64() * 1e3;
        assert!(plan.lanes.as_ref().is_some_and(|l| l.batches() == batches.len()));
        // 0: the map (stage 1); 1: the lane (stage 2); 2: the lane with the
        // fold's parts (stage 3).
        let run = |mode: u8| -> (f64, Vec<revm::database::BundleState>) {
            let at = Instant::now();
            let bundles: Vec<revm::database::BundleState> = pool.install(|| {
                use rayon::prelude::*;
                batches
                    .par_iter()
                    .enumerate()
                    .map(|(b, members)| {
                        let txs_n = members.iter().map(|g| g.len()).sum::<usize>();
                        let state = if mode > 0 {
                            BatchState::with_lane(db.clone(), 4, std::sync::Arc::clone(&plan), b, mode == 2)
                        } else {
                            BatchState::with_capacity(db.clone(), txs_n + txs_n / 4 + 1)
                        };
                        node_batch(&txs, members, state)
                    })
                    .collect()
            });
            (at.elapsed().as_secs_f64() * 1e3, bundles)
        };
        let (map, map_bundles) = run(0);
        let (dense, lane_bundles) = run(1);
        let (direct, direct_bundles) = run(2);
        // Stage 4: the same batches closed with `take_output`.
        let at = Instant::now();
        let outputs: Vec<Output> = pool.install(|| {
            use rayon::prelude::*;
            batches
                .par_iter()
                .enumerate()
                .map(|(b, members)| {
                    let state = BatchState::with_lane(db.clone(), 4, std::sync::Arc::clone(&plan), b, true);
                    node_batch_run(&txs, members, state).take_output()
                })
                .collect()
        });
        let out_loop = at.elapsed().as_secs_f64() * 1e3;
        let hand_over = |lanes: bool, outputs: Vec<Output>, bundles: Vec<revm::database::BundleState>| {
            let shards = OutputShards::with_index_live(beneficiary(), keys.len(), 16, true, true);
            let at = Instant::now();
            pool.install(|| {
                use rayon::prelude::*;
                if lanes {
                    outputs.into_par_iter().for_each(|(bundle, lane)| match lane {
                        Some(lane) => shards.add_lane(bundle, lane),
                        None => shards.add(bundle),
                    });
                } else {
                    bundles.into_par_iter().for_each(|bundle| shards.add(bundle));
                }
            });
            let add = at.elapsed().as_secs_f64() * 1e3;
            let at = Instant::now();
            let frozen = shards.freeze_on(&pool);
            (add, at.elapsed().as_secs_f64() * 1e3, frozen)
        };
        let (s4_add, s4_freeze, s4_frozen) = hand_over(true, outputs, Vec::new());
        let (s3_add, s3_freeze, s3_frozen) = hand_over(false, Vec::new(), direct_bundles.clone());
        // The block's root path behind the seal: the view, the QMDB root's
        // operations and the hashed post-state (each timed alone, on the
        // pool). Stage 4 reads its lanes in place (`N42_LANE_ROOT`), then
        // the lane maps are made as the merge behind the publication makes
        // them; stage 4 as loop351 ran it is that materialisation plus the
        // view and the root over the maps; stage 3 has maps throughout.
        let empty = revm::database::BundleState::default();
        let root_of = |frozen: &n42_engine_types::output_shards::FrozenShards| {
            let at = Instant::now();
            let (maps, leaves) = pool.install(|| frozen.view_lanes(&empty, &[]));
            let view = at.elapsed().as_secs_f64() * 1e3;
            let at = Instant::now();
            let ops = pool.install(|| n42_qmdb_reth::sorted_operations_from_parts_timed(&maps, &leaves, true).0);
            let ops_ms = at.elapsed().as_secs_f64() * 1e3;
            let at = Instant::now();
            let hashed = pool.install(|| n42_engine_types::output_shards::hashed_post_state_of_parts(&maps, &leaves));
            let hashed_ms = at.elapsed().as_secs_f64() * 1e3;
            (view, ops_ms, hashed_ms, leaves.len(), ops.to_operations(), hashed.accounts.len())
        };
        let s4_lanes = root_of(&s4_frozen);
        let at = Instant::now();
        s4_frozen.materialise_lanes();
        let s4_made = at.elapsed().as_secs_f64() * 1e3;
        let s4_maps = root_of(&s4_frozen);
        let s3_root = root_of(&s3_frozen);
        assert_eq!(s4_maps.3, 0, "the maps are made");
        assert_eq!(s4_lanes.4, s3_root.4, "the root's operations over the lanes are stage 3's");
        assert_eq!(s4_maps.4, s3_root.4, "and over the made maps");
        assert_eq!(s4_lanes.5, s3_root.5, "hashed accounts");
        if round == 0 {
            assert!(s4_frozen.has_lanes());
            let residual = revm::database::BundleState::default();
            assert_eq!(s4_frozen.merged_state_first(&residual, None).0.state, s3_frozen.merged_state_first(&residual, None).0.state);
            assert_eq!(
                s4_frozen.late_reverts(Default::default(), Vec::new(), None),
                s3_frozen.late_reverts(Default::default(), Vec::new(), None),
                "stage 4's reverts are stage 3's"
            );
            for bundles in [&lane_bundles, &direct_bundles] {
                for (ours, theirs) in bundles.iter().zip(&map_bundles) {
                    assert_eq!(ours.state, theirs.state, "the lane's bundle is the map's");
                    assert_eq!((ours.state_size, ours.reverts_size), (theirs.state_size, theirs.reverts_size));
                    let ours: std::collections::BTreeMap<_, _> = ours.reverts.iter().flatten().cloned().collect();
                    let theirs: std::collections::BTreeMap<_, _> = theirs.reverts.iter().flatten().cloned().collect();
                    assert_eq!(ours, theirs, "reverts");
                }
            }
            continue;
        }
        map_ms.push(map);
        lane_ms.push(dense);
        direct_ms.push(direct);
        resolve_ms.push(resolve);
        record_ms.push(record);
        lanes_ms.push(lanes);
        out_ms.push(out_loop);
        out_add_ms.push(s4_add);
        out_freeze_ms.push(s4_freeze);
        out_mat_ms.push(s4_made);
        root_rows.push([s4_lanes.0, s4_lanes.1, s4_lanes.2, s4_made, s4_maps.0, s4_maps.1, s4_maps.2, s3_root.0, s3_root.1, s3_root.2]);
        leaves_n = s4_lanes.3;
        s3_add_ms.push(s3_add);
        s3_freeze_ms.push(s3_freeze);
    }
    println!(
        "node batch state, {} transfers, {} batches, {threads} threads, p50 of {rounds}: map (stage 1) {:.1} ms, lane (stage 2) {:.1} ms, lane with fold (stage 3) {:.1} ms; plan time: resolve {:.1} ms, lanes {:.1} ms; table record (behind) {:.1} ms, {} entries",
        keys.len(),
        batches.len(),
        median(map_ms),
        median(lane_ms),
        median(direct_ms),
        median(resolve_ms),
        median(lanes_ms),
        median(record_ms),
        table.len()
    );
    println!(
        "stage 4 (lane output): batch loop {:.1} ms; hand-over {:.1} ms, freeze {:.1} ms, lane maps made {:.1} ms (at the freeze with N42_LANE_ROOT=0, else behind); stage 3 beside: hand-over {:.1} ms, freeze {:.1} ms (16 shards, live index)",
        median(out_ms),
        median(out_add_ms),
        median(out_freeze_ms),
        median(out_mat_ms),
        median(s3_add_ms),
        median(s3_freeze_ms)
    );
    let col = |i: usize| median(root_rows.iter().map(|row| row[i]).collect());
    println!(
        "root path: stage 4 over lanes ({leaves_n} lane accounts): view {:.1} + ops {:.1} + hashed {:.1} = {:.1} ms, maps made behind {:.1} ms; stage 4 as loop351 (maps first): materialisation {:.1} + view {:.1} + ops {:.1} + hashed {:.1} = {:.1} ms; stage 3: view {:.1} + ops {:.1} + hashed {:.1} = {:.1} ms",
        col(0), col(1), col(2), col(0) + col(1) + col(2), col(3),
        col(3), col(4), col(5), col(6), col(3) + col(4) + col(5) + col(6),
        col(7), col(8), col(9), col(7) + col(8) + col(9)
    );
}

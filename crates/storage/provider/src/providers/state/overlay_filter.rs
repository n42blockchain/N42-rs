// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42: a per-block address filter for [`MemoryOverlayStateProvider`]'s reads.
//!
//! The layered overlay answers a read by probing the `BundleState` of every in-memory block
//! from the tip down before it falls to the database. At the fleet's shape (8-10 unpersisted
//! blocks of ~147k accounts) most reads hit none of them, so each read paid one hash-map probe
//! (a cache miss) per block. Each block now carries a split-block Bloom filter over the
//! addresses its bundle holds and the code hashes it deploys; a filter miss skips the block, a
//! hit probes it as before, so the answers are unchanged by construction.
//!
//! The filters live in a bounded side map keyed by the block's execution output (the `Arc`'s
//! address, confirmed by a `Weak` to it, so a dropped block's entry can never answer for
//! another), and are built once per output on a background thread the first time an overlay
//! is opened over it: the opener never waits for a build, and a block whose filter is not
//! ready yet is probed as before. `N42_OVERLAY_FILTER=0` turns the filters off.
//!
//! [`MemoryOverlayStateProvider`]: super::memory_overlay::MemoryOverlayStateProvider

use alloy_primitives::{Address, B256};
use reth_execution_types::BlockExecutionOutput;
use std::{
    any::Any,
    cell::Cell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, PoisonError, Weak,
    },
};

/// Bits per key: a split-block Bloom filter at 11 bits a key reads ~1% false positives.
const BITS_PER_KEY: usize = 11;

/// Entries the side map keeps at most (64 blocks of ~150k accounts: ~13 MB of filters).
const CACHE_CAP: usize = 64;

/// Whether the filters are on (`N42_OVERLAY_FILTER=0` turns them off; on by default).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !std::env::var("N42_OVERLAY_FILTER").is_ok_and(|v| v.trim() == "0"))
}

/// A key's 64-bit hash: the filter's block index and its eight bit positions come from it.
#[derive(Clone, Copy, Debug)]
pub struct FilterKey(u64);

#[inline(always)]
fn fold(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

const K0: u64 = 0xa076_1d64_78bd_642f;
const K1: u64 = 0xe703_7ed1_a0b4_28db;
const K2: u64 = 0x8ebc_6af0_9c88_c6e3;
const K3: u64 = 0x5899_65cc_7537_4cc3;

impl FilterKey {
    /// The key of an account address (accounts and their storage slots).
    #[inline(always)]
    pub fn address(address: &Address) -> Self {
        let b = address.as_slice();
        let mut lo = [0u8; 8];
        let mut mid = [0u8; 8];
        let mut hi = [0u8; 4];
        lo.copy_from_slice(&b[0..8]);
        mid.copy_from_slice(&b[8..16]);
        hi.copy_from_slice(&b[16..20]);
        let h = fold(u64::from_le_bytes(lo) ^ K0, u64::from_le_bytes(mid) ^ K1);
        Self(fold(h ^ u64::from(u32::from_le_bytes(hi)) ^ K2, K3))
    }

    /// The key of a code hash (bytecode reads).
    #[inline(always)]
    pub fn code_hash(hash: &B256) -> Self {
        let mut w = [0u64; 4];
        for (i, chunk) in hash.as_slice().chunks_exact(8).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            w[i] = u64::from_le_bytes(b);
        }
        let h = fold(w[0] ^ K1, w[1] ^ K2);
        Self(fold(h ^ w[2] ^ K0, w[3] ^ K3))
    }
}

/// A split-block Bloom filter: 512-bit blocks (one cache line), eight bits a key, one in each
/// 64-bit word of the key's block.
#[derive(Debug)]
pub struct SplitBloom {
    blocks: Box<[[u64; 8]]>,
}

impl SplitBloom {
    /// An empty filter sized for `keys` keys.
    pub fn with_capacity(keys: usize) -> Self {
        let n = (keys.saturating_mul(BITS_PER_KEY)).div_ceil(512).max(1);
        Self { blocks: vec![[0u64; 8]; n].into_boxed_slice() }
    }

    /// The filter's size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.blocks.len() * 64
    }

    #[inline(always)]
    fn locate(&self, key: FilterKey) -> (usize, [u64; 8]) {
        let index = ((u128::from(key.0) * self.blocks.len() as u128) >> 64) as usize;
        let bits = fold(key.0, K2);
        let mut mask = [0u64; 8];
        for (i, m) in mask.iter_mut().enumerate() {
            *m = 1u64 << ((bits >> (i * 8)) & 63);
        }
        (index, mask)
    }

    /// Adds `key`.
    pub fn insert(&mut self, key: FilterKey) {
        let (index, mask) = self.locate(key);
        if let Some(block) = self.blocks.get_mut(index) {
            for (word, m) in block.iter_mut().zip(mask) {
                *word |= m;
            }
        }
    }

    /// `false` only when `key` was never added.
    #[inline(always)]
    pub fn may_contain(&self, key: FilterKey) -> bool {
        let (index, mask) = self.locate(key);
        let Some(block) = self.blocks.get(index) else { return true };
        let mut missing = 0u64;
        for (word, m) in block.iter().zip(mask) {
            missing |= m & !word;
        }
        missing == 0
    }
}

/// One block's filters: the addresses its bundle holds (account and storage reads walk the
/// bundle by address) and the code hashes it deploys (bytecode reads).
#[derive(Debug)]
pub struct BlockFilter {
    accounts: SplitBloom,
    contracts: SplitBloom,
}

impl BlockFilter {
    /// Builds the filters of `output`'s bundle: one pass over its accounts and contracts.
    pub fn build<R>(output: &BlockExecutionOutput<R>) -> Self {
        let bundle = &output.state;
        let mut accounts = SplitBloom::with_capacity(bundle.state.len());
        for address in bundle.state.keys() {
            accounts.insert(FilterKey::address(address));
        }
        let mut contracts = SplitBloom::with_capacity(bundle.contracts.len());
        for hash in bundle.contracts.keys() {
            contracts.insert(FilterKey::code_hash(hash));
        }
        Self { accounts, contracts }
    }

    /// `false` only when the bundle holds no entry for the address keyed `key`.
    #[inline(always)]
    pub fn may_hold_account(&self, key: FilterKey) -> bool {
        self.accounts.may_contain(key)
    }

    /// `false` only when the bundle deploys no code under the hash keyed `key`.
    #[inline(always)]
    pub fn may_hold_code(&self, key: FilterKey) -> bool {
        self.contracts.may_contain(key)
    }

    /// The filters' size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.accounts.size_bytes() + self.contracts.size_bytes()
    }
}

/// A block's filter slot: empty until its build finishes.
pub type FilterCell = Arc<OnceLock<BlockFilter>>;

struct Entry {
    key: usize,
    owner: Weak<dyn Any + Send + Sync>,
    cell: FilterCell,
}

static CACHE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// The filter slot of `output`, starting its build on a background thread when it has none.
/// `None` when the filters are off (or the build could not be started).
pub fn filter_for<R>(output: &Arc<BlockExecutionOutput<R>>) -> Option<FilterCell>
where
    R: Send + Sync + 'static,
{
    if !enabled() {
        return None
    }
    let key = Arc::as_ptr(output) as *const () as usize;
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    cache.retain(|entry| entry.owner.strong_count() > 0);
    if let Some(entry) = cache.iter().find(|entry| {
        entry.key == key && entry.owner.as_ptr() as *const () as usize == key
    }) {
        return Some(entry.cell.clone())
    }
    if cache.len() >= CACHE_CAP {
        cache.remove(0);
    }
    let cell: FilterCell = Arc::new(OnceLock::new());
    let owner: Arc<dyn Any + Send + Sync> = output.clone();
    cache.push(Entry { key, owner: Arc::downgrade(&owner), cell: cell.clone() });
    drop(owner);
    drop(cache);

    let (build_output, build_cell) = (output.clone(), cell.clone());
    let spawned = std::thread::Builder::new().name("overlay-filter".into()).spawn(move || {
        build_cell.get_or_init(|| BlockFilter::build(&build_output));
    });
    if spawned.is_err() {
        // Probed as before; a later open retries.
        let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
        cache.retain(|entry| !Arc::ptr_eq(&entry.cell, &cell));
        return None
    }
    Some(cell)
}

/// [`filter_for`], with the filter built on the calling thread when it is not ready (tests and
/// benches, which need the filter in place before their reads).
pub fn filter_now<R>(output: &Arc<BlockExecutionOutput<R>>) -> Option<FilterCell>
where
    R: Send + Sync + 'static,
{
    let cell = filter_for(output)?;
    cell.get_or_init(|| BlockFilter::build(output));
    Some(cell)
}

/// Whether the block behind `cell` may hold the address keyed `key` (`true` when it has no
/// filter yet).
#[inline(always)]
pub fn may_hold_account(cell: Option<&FilterCell>, key: FilterKey) -> bool {
    cell.and_then(|cell| cell.get()).is_none_or(|filter| filter.may_hold_account(key))
}

/// Whether the block behind `cell` may deploy code keyed `key` (`true` when it has no filter
/// yet).
#[inline(always)]
pub fn may_hold_code(cell: Option<&FilterCell>, key: FilterKey) -> bool {
    cell.and_then(|cell| cell.get()).is_none_or(|filter| filter.may_hold_code(key))
}

// Counters: per-thread accumulators folded into the totals every `FLUSH_EVERY` reads, so a
// read pays two thread-local adds and no atomic.
static SKIPS: AtomicU64 = AtomicU64::new(0);
static PROBES: AtomicU64 = AtomicU64::new(0);
const FLUSH_EVERY: u32 = 4096;

std::thread_local! {
    static LOCAL: Cell<(u64, u64, u32)> = const { Cell::new((0, 0, 0)) };
}

/// Records one read's skipped blocks and probed blocks.
#[inline]
pub fn record(skips: u64, probes: u64) {
    let _ = LOCAL.try_with(|local| {
        let (s, p, n) = local.get();
        let (s, p, n) = (s + skips, p + probes, n + 1);
        if n >= FLUSH_EVERY {
            SKIPS.fetch_add(s, Ordering::Relaxed);
            PROBES.fetch_add(p, Ordering::Relaxed);
            local.set((0, 0, 0));
        } else {
            local.set((s, p, n));
        }
    });
}

/// `(overlay_filter_skips, overlay_probes)` since the last call, reset to zero: blocks a read
/// skipped on its filter and blocks whose bundle a read probed. Each thread folds its counts
/// in every 4096 reads, so up to that many reads a thread are not yet counted.
pub fn take_counters() -> (u64, u64) {
    (SKIPS.swap(0, Ordering::Relaxed), PROBES.swap(0, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_bloom_has_no_false_negatives_and_few_false_positives() {
        let n = 150_000u64;
        let addr = |i: u64| Address::from_word(B256::from(alloy_primitives::U256::from(i + 1)));
        let mut bloom = SplitBloom::with_capacity(n as usize);
        for i in 0..n {
            bloom.insert(FilterKey::address(&addr(i)));
        }
        for i in 0..n {
            assert!(bloom.may_contain(FilterKey::address(&addr(i))));
        }
        let fp = (n..2 * n).filter(|i| bloom.may_contain(FilterKey::address(&addr(*i)))).count();
        let rate = fp as f64 / n as f64;
        assert!(rate < 0.02, "false positive rate {rate}");
        assert!(bloom.size_bytes() < 220_000, "{}", bloom.size_bytes());
    }
}

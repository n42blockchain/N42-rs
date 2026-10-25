// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A compact key -> slot index for the QMDB tree (`docs/QMDB_UPGRADE_PLAN.md`, stage 1b).
//!
//! The `HashMap<[u8; 32], u64>` it replaces holds the key itself: 40 bytes an entry before the
//! table's slack, ~60 bytes a live key in practice, 3 GB at 50 million keys. The key is already in
//! the entry store, at the slot the index names, so this index keeps only a fingerprint of it:
//!
//! - 256 shards by a seeded mix of `key[0..8]`, so a block's appends insert per shard in
//!   parallel; the shard is seeded like the fingerprint, because keys are hashes a sender can
//!   grind, and shards chosen by `key[0]` let ~12.6M ground keys fill one shard and halt every
//!   node at the same block;
//! - in each shard an open-addressing table of `u64` buckets, `fingerprint:24 | slot + 1:40`
//!   (zero marks an empty bucket), linear probing, load at most 3/4 (10.7-21 bytes a key);
//! - the fingerprint is 24 bits of a seeded mix of `key[8..16]` (keys are hashes a sender can
//!   grind; the seed is per process and the index is never persisted), and a bucket's home is the
//!   fingerprint's top bits, so growing a table needs no key: every bucket carries its home;
//! - every fingerprint match is confirmed against the key the entry store holds at that slot
//!   (`key_at`), so a lookup is exact. A hit costs that one read, which a caller reading the value
//!   pays anyway; a miss confirms only on a full 24-bit fingerprint collision.
//!
//! Limits: a slot below 2^40 - 1 (1.1 trillion appends) and a shard below 2^24 buckets
//! (about 3.2 billion live keys in all); an insert past either returns an [`IndexError`],
//! which the tree's apply reports (and the forest above it treats as fatal).

use crate::Hash;

const SHARDS: usize = 256;
const FP_BITS: u32 = 24;
const SLOT_BITS: u32 = 40;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
/// The largest slot (or, in a [`SharedOffsetIndex`], byte offset) a bucket can name.
pub(crate) const MAX_SLOT: u64 = SLOT_MASK - 1;
/// [`MAX_SLOT`], public: the largest value a [`SharedOffsetIndex`] holds.
pub const MAX_INDEX_VALUE: u64 = MAX_SLOT;
const MIN_BITS: u32 = 4;
/// How many keys ahead a batch lookup prefetches its bucket.
const PREFETCH_AHEAD: usize = 8;
const MAX_BITS: u32 = FP_BITS;

/// A random seed per process, taken from std's randomly keyed hasher.
fn seed() -> u64 {
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(0x6e34_325f_6964_7832);
        hasher.finish()
    })
}

/// Why the index refused an insert.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    /// A shard would grow past its bucket limit.
    #[error("QMDB key index shard over 2^{max_bits} buckets ({len} keys)")]
    ShardFull {
        /// The shard's bucket limit, as a power of two.
        max_bits: u32,
        /// The keys it was asked to hold.
        len: usize,
    },
    /// A slot (or byte offset) does not fit the bucket's 40-bit field.
    #[error("QMDB slot {0} beyond the key index's 40 bits")]
    SlotTooLarge(u64),
    /// A batch too large to group by shard.
    #[error("QMDB key index batch of {0} keys is too large")]
    BatchTooLarge(usize),
}

/// A second per-process seed, for the shard choice: derived from [`seed`]
/// but not equal to it, so the shard and the fingerprint mixes differ.
fn shard_seed() -> u64 {
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| seed().rotate_left(29) ^ 0x9e37_79b9_7f4a_7c15)
}

/// The key's shard: the top byte of a seeded mix (murmur3's finalizer) of
/// `key[0..8]`. Without the seed a sender cannot aim keys at one shard.
#[inline]
fn shard_of(key: &Hash) -> usize {
    let mut x = u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]) ^ shard_seed();
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    (x >> 56) as usize
}

/// The positions `0..n` grouped by the shard of `key(i)`, each group in
/// position order, and where each shard's group starts (`starts[SHARDS]` is
/// `n`): a counting sort, so a batch inserts one shard's keys at a time.
fn group_by_shard<'k>(n: usize, key: impl Fn(usize) -> &'k Hash) -> Result<(Vec<u32>, Box<[usize; SHARDS + 1]>), IndexError> {
    if u32::try_from(n).is_err() {
        return Err(IndexError::BatchTooLarge(n));
    }
    let shards: Vec<u8> = (0..n).map(|i| shard_of(key(i)) as u8).collect();
    let mut starts = Box::new([0usize; SHARDS + 1]);
    for shard in &shards {
        starts[*shard as usize + 1] += 1;
    }
    for shard in 0..SHARDS {
        starts[shard + 1] += starts[shard];
    }
    let mut next = starts.clone();
    let mut order = vec![0u32; n];
    for (i, shard) in shards.iter().enumerate() {
        let at = &mut next[*shard as usize];
        order[*at] = i as u32;
        *at += 1;
    }
    Ok((order, starts))
}

/// The key's 24-bit fingerprint: splitmix64's finalizer over `key[8..16]` and the seed.
#[inline]
fn fingerprint(key: &Hash) -> u64 {
    let mut x = u64::from_le_bytes([key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]]) ^ seed();
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x >> (64 - FP_BITS)
}

#[derive(Clone, Default)]
struct Shard {
    /// `1 << bits` buckets, or none before the first insert.
    buckets: Vec<u64>,
    bits: u32,
    len: usize,
}

impl Shard {
    #[inline]
    fn home_of_fp(&self, fp: u64) -> usize {
        (fp >> (FP_BITS - self.bits)) as usize
    }

    #[inline]
    fn home_of_bucket(&self, bucket: u64) -> usize {
        self.home_of_fp(bucket >> SLOT_BITS)
    }

    #[inline]
    fn mask(&self) -> usize {
        self.buckets.len() - 1
    }

    fn get(&self, key: &Hash, key_at: &impl Fn(u64) -> Hash) -> Option<(usize, u64)> {
        if self.len == 0 {
            return None;
        }
        let fp = fingerprint(key);
        let mask = self.mask();
        let mut at = self.home_of_fp(fp);
        loop {
            let bucket = self.buckets[at];
            if bucket == 0 {
                return None;
            }
            if bucket >> SLOT_BITS == fp {
                let slot = (bucket & SLOT_MASK) - 1;
                if key_at(slot) == *key {
                    return Some((at, slot));
                }
            }
            at = (at + 1) & mask;
        }
    }

    /// Prefetches the bucket line `key` probes first (a no-op off x86_64 or on
    /// an empty table). A batch lookup issues it a few keys ahead
    /// ([`PREFETCH_AHEAD`]): the probes of a multi-million-key table are cache
    /// misses, and the prefetch overlaps them instead of taking them one by one.
    #[inline]
    fn prefetch(&self, key: &Hash) {
        if self.buckets.is_empty() {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
            let at = self.home_of_fp(fingerprint(key));
            // SAFETY: `at` is below `buckets.len()` (a home is `bits` bits wide
            // and the table holds `1 << bits` buckets); a prefetch reads nothing
            // and never faults.
            unsafe { _mm_prefetch(self.buckets.as_ptr().add(at) as *const i8, _MM_HINT_T0) };
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = key;
    }

    /// Room for `len` keys at a load of at most 3/4, within `1 << max_bits`
    /// buckets; past that an error, and the shard is left as it was.
    fn ensure_capacity(&mut self, len: usize, max_bits: u32) -> Result<(), IndexError> {
        let mut bits = self.bits.max(MIN_BITS);
        while (1usize << bits) * 3 < len * 4 {
            bits += 1;
            if bits > max_bits {
                return Err(IndexError::ShardFull { max_bits, len });
            }
        }
        if bits == self.bits && !self.buckets.is_empty() {
            return Ok(());
        }
        let old = std::mem::replace(&mut self.buckets, vec![0; 1 << bits]);
        self.bits = bits;
        let mask = self.mask();
        // Every bucket carries its home in its fingerprint: no key is read.
        for bucket in old.into_iter().filter(|bucket| *bucket != 0) {
            let mut at = self.home_of_bucket(bucket);
            while self.buckets[at] != 0 {
                at = (at + 1) & mask;
            }
            self.buckets[at] = bucket;
        }
        Ok(())
    }

    fn insert(&mut self, key: &Hash, slot: u64, key_at: &impl Fn(u64) -> Hash, max_bits: u32) -> Result<Option<u64>, IndexError> {
        if slot > MAX_SLOT {
            return Err(IndexError::SlotTooLarge(slot));
        }
        let fp = fingerprint(key);
        let bucket = (fp << SLOT_BITS) | (slot + 1);
        if let Some((at, old)) = self.get(key, key_at) {
            self.buckets[at] = bucket;
            return Ok(Some(old));
        }
        self.ensure_capacity(self.len + 1, max_bits)?;
        let mask = self.mask();
        let mut at = self.home_of_fp(fp);
        while self.buckets[at] != 0 {
            at = (at + 1) & mask;
        }
        self.buckets[at] = bucket;
        self.len += 1;
        Ok(None)
    }

    fn remove(&mut self, key: &Hash, key_at: &impl Fn(u64) -> Hash) -> Option<u64> {
        let (mut hole, slot) = self.get(key, key_at)?;
        self.buckets[hole] = 0;
        self.len -= 1;
        // Backward shift: pull later buckets of the run into the hole when the
        // hole lies on their probe path (cyclically within [home, position)).
        let mask = self.mask();
        let mut at = (hole + 1) & mask;
        loop {
            let bucket = self.buckets[at];
            if bucket == 0 {
                break;
            }
            let home = self.home_of_bucket(bucket);
            if (at.wrapping_sub(home) & mask) >= (at.wrapping_sub(hole) & mask) {
                self.buckets[hole] = bucket;
                self.buckets[at] = 0;
                hole = at;
            }
            at = (at + 1) & mask;
        }
        Some(slot)
    }
}

/// The key -> slot index: see the module documentation.
#[derive(Clone)]
pub(crate) struct TagIndex {
    shards: Vec<Shard>,
    /// Each shard's bucket limit, as a power of two ([`MAX_BITS`]; smaller
    /// in tests).
    max_bits: u32,
}

impl Default for TagIndex {
    fn default() -> Self {
        Self { shards: vec![Shard::default(); SHARDS], max_bits: MAX_BITS }
    }
}

impl TagIndex {
    /// An index whose shards hold at most `1 << max_bits` buckets.
    #[cfg(test)]
    pub(crate) fn with_max_bits(max_bits: u32) -> Self {
        Self { max_bits: max_bits.clamp(MIN_BITS, MAX_BITS), ..Self::default() }
    }

    /// The slot holding `key`; `key_at` reads the key the entry store holds at a slot.
    #[inline]
    pub(crate) fn get(&self, key: &Hash, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.shards[shard_of(key)].get(key, &key_at).map(|(_, slot)| slot)
    }

    /// `out[i]` = [`Self::get`] of `key(i)` for every `i < out.len()`, each
    /// bucket prefetched [`PREFETCH_AHEAD`] keys ahead. The answers are
    /// [`Self::get`]'s; only the order of the memory traffic changes.
    pub(crate) fn get_into<'k>(
        &self,
        out: &mut [Option<u64>],
        key: impl Fn(usize) -> &'k Hash,
        key_at: impl Fn(u64) -> Hash,
    ) {
        let n = out.len();
        for ahead in 0..PREFETCH_AHEAD.min(n) {
            let k = key(ahead);
            self.shards[shard_of(k)].prefetch(k);
        }
        for (i, slot) in out.iter_mut().enumerate() {
            if i + PREFETCH_AHEAD < n {
                let k = key(i + PREFETCH_AHEAD);
                self.shards[shard_of(k)].prefetch(k);
            }
            *slot = self.get(key(i), &key_at);
        }
    }

    /// Maps `key` to `slot`, returning the slot it replaced. `key_at` must
    /// already answer for every slot the index holds.
    #[inline]
    pub(crate) fn insert(&mut self, key: Hash, slot: u64, key_at: impl Fn(u64) -> Hash) -> Result<Option<u64>, IndexError> {
        self.shards[shard_of(&key)].insert(&key, slot, &key_at, self.max_bits)
    }

    #[inline]
    pub(crate) fn remove(&mut self, key: &Hash, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.shards[shard_of(key)].remove(key, &key_at)
    }

    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.len).sum()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| shard.len == 0)
    }

    /// Room for `additional` more keys, spread evenly over the shards.
    pub(crate) fn reserve(&mut self, additional: usize) {
        let per = additional / SHARDS + 1;
        let max_bits = self.max_bits;
        // On the worker pool: the keys spread evenly over the shards, so the
        // shards cross their load bound together and a growth rebuilds the
        // whole index in one block -- in sequence on the applying thread, and
        // with every fresh table's pages faulted there, it was the apply's
        // longest hold in the block it happened. Each shard's table depends
        // only on its own keys, so the result is the same either way.
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            // A hint: a shard it cannot grow is left as it is, and the
            // insert that needs the room reports it.
            self.shards.par_iter_mut().for_each(|shard| {
                let _ = shard.ensure_capacity(shard.len + per, max_bits);
            });
        }
        #[cfg(not(feature = "rayon"))]
        for shard in &mut self.shards {
            let _ = shard.ensure_capacity(shard.len + per, max_bits);
        }
    }

    /// Bytes the tables hold.
    pub(crate) fn memory_bytes(&self) -> usize {
        self.shards.iter().map(|shard| shard.buckets.capacity() * 8).sum::<usize>()
            + self.shards.capacity() * std::mem::size_of::<Shard>()
    }

    /// Inserts `(key, slot)` pairs with distinct keys, one shard at a time
    /// on the worker pool. An error (a shard full) leaves the pairs before it
    /// in that shard, and other shards', inserted.
    pub(crate) fn insert_sorted(&mut self, pairs: &[(Hash, u64)], key_at: impl Fn(u64) -> Hash + Sync) -> Result<(), IndexError> {
        let (order, starts) = group_by_shard(pairs.len(), |i| &pairs[i].0)?;
        let max_bits = self.max_bits;
        let work = |(index, shard): (usize, &mut Shard)| -> Result<(), IndexError> {
            let run = &order[starts[index]..starts[index + 1]];
            if run.is_empty() {
                return Ok(());
            }
            shard.ensure_capacity(shard.len + run.len(), max_bits)?;
            // The table does not grow inside the run (capacity reserved
            // above), so a bucket prefetched ahead is the one probed.
            for i in run.iter().take(PREFETCH_AHEAD) {
                shard.prefetch(&pairs[*i as usize].0);
            }
            for (at, i) in run.iter().enumerate() {
                if let Some(ahead) = run.get(at + PREFETCH_AHEAD) {
                    shard.prefetch(&pairs[*ahead as usize].0);
                }
                let (key, slot) = &pairs[*i as usize];
                shard.insert(key, *slot, &key_at, max_bits)?;
            }
            Ok(())
        };
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            self.shards.par_iter_mut().enumerate().try_for_each(work)
        }
        #[cfg(not(feature = "rayon"))]
        {
            self.shards.iter_mut().enumerate().try_for_each(work)
        }
    }
}

/// The fingerprint index with every shard behind its own lock: many readers
/// and one writer at a time, each holding one shard for one lookup or for one
/// shard's run of a sorted batch. Values are any `u64` up to
/// [`MAX_INDEX_VALUE`] -- a QMDB read view keeps entry-file byte offsets --
/// confirmed through `key_at` like [`TagIndex`]'s slots.
pub struct SharedOffsetIndex {
    shards: Vec<std::sync::RwLock<Shard>>,
}

impl std::fmt::Debug for SharedOffsetIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedOffsetIndex").field("len", &self.len()).finish()
    }
}

impl Default for SharedOffsetIndex {
    fn default() -> Self {
        Self { shards: (0..SHARDS).map(|_| std::sync::RwLock::new(Shard::default())).collect() }
    }
}

thread_local! {
    /// This thread's reads that found their shard write-locked (or a writer
    /// queued on it) and the nanoseconds they waited, cumulative.
    static READ_WAITS: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}

/// The calling thread's [`SharedOffsetIndex`] reads that had to wait for a
/// shard's lock -- a writer (`apply_sorted`, a QMDB read view's advance) held
/// or was queued on it -- and the nanoseconds they waited, cumulative since
/// the thread started. A read that takes its lock at once costs nothing more
/// than before: only a `try_read` that fails is timed. Callers difference two
/// readings to attribute waits to a span of work on one thread.
pub fn thread_read_waits() -> (u64, u64) {
    READ_WAITS.try_with(std::cell::Cell::get).unwrap_or((0, 0))
}

impl SharedOffsetIndex {
    fn read(&self, key: &Hash) -> std::sync::RwLockReadGuard<'_, Shard> {
        let lock = &self.shards[shard_of(key)];
        match lock.try_read() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                let at = std::time::Instant::now();
                let guard = lock.read().unwrap_or_else(std::sync::PoisonError::into_inner);
                let waited = at.elapsed().as_nanos() as u64;
                let _ = READ_WAITS.try_with(|waits| {
                    let (count, ns) = waits.get();
                    waits.set((count + 1, ns + waited));
                });
                guard
            }
        }
    }

    fn write(&self, shard: usize) -> std::sync::RwLockWriteGuard<'_, Shard> {
        self.shards[shard].write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The value held for `key`.
    pub fn get(&self, key: &Hash, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.read(key).get(key, &key_at).map(|(_, value)| value)
    }

    /// A hint that `key` will be looked up soon: prefetches the bucket line its
    /// probe reads first. Only if the shard's read lock is free right now -- a
    /// hint never waits, and is not counted in [`thread_read_waits`]. Returns
    /// whether it was issued.
    pub fn prefetch(&self, key: &Hash) -> bool {
        match self.shards[shard_of(key)].try_read() {
            Ok(shard) => {
                shard.prefetch(key);
                true
            }
            Err(_) => false,
        }
    }

    /// Maps `key` to `value`, returning the value it replaced.
    pub fn insert(&self, key: Hash, value: u64, key_at: impl Fn(u64) -> Hash) -> Result<Option<u64>, IndexError> {
        self.write(shard_of(&key)).insert(&key, value, &key_at, MAX_BITS)
    }

    /// Removes `key`, returning its value.
    pub fn remove(&self, key: &Hash, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.write(shard_of(key)).remove(key, &key_at)
    }

    /// How many keys are held.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.read().unwrap_or_else(std::sync::PoisonError::into_inner).len).sum()
    }

    /// Whether no key is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes the tables hold.
    pub fn memory_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.read().unwrap_or_else(std::sync::PoisonError::into_inner).buckets.capacity() * 8)
            .sum::<usize>()
            + self.shards.capacity() * std::mem::size_of::<std::sync::RwLock<Shard>>()
    }

    /// Applies `changes` with distinct keys -- `Some(value)` maps, `None`
    /// removes -- one shard's keys under one write lock, shards in parallel
    /// with the `rayon` feature. Returns what each key held before, in
    /// `changes`' order. An error (a shard full) leaves the changes before it
    /// in that shard, and other shards', applied.
    pub fn apply_sorted(&self, changes: &[(Hash, Option<u64>)], key_at: impl Fn(u64) -> Hash + Sync) -> Result<Vec<Option<u64>>, IndexError> {
        debug_assert!(changes.windows(2).all(|pair| pair[0].0 < pair[1].0), "changes sorted by key, keys distinct");
        let (order, starts) = group_by_shard(changes.len(), |i| &changes[i].0)?;
        let work = |shard: usize| -> Result<Vec<Option<u64>>, IndexError> {
            let run = &order[starts[shard]..starts[shard + 1]];
            if run.is_empty() {
                return Ok(Vec::new());
            }
            let mut guard = self.write(shard);
            let inserts = run.iter().filter(|i| changes[**i as usize].1.is_some()).count();
            let len = guard.len;
            guard.ensure_capacity(len + inserts, MAX_BITS)?;
            // No growth inside the run (capacity reserved above): a bucket
            // prefetched ahead is the one probed.
            for i in run.iter().take(PREFETCH_AHEAD) {
                guard.prefetch(&changes[*i as usize].0);
            }
            run.iter()
                .enumerate()
                .map(|(at, i)| {
                    if let Some(ahead) = run.get(at + PREFETCH_AHEAD) {
                        guard.prefetch(&changes[*ahead as usize].0);
                    }
                    let (key, value) = &changes[*i as usize];
                    match value {
                        Some(value) => guard.insert(key, *value, &key_at, MAX_BITS),
                        None => Ok(guard.remove(key, &key_at)),
                    }
                })
                .collect()
        };
        #[cfg(feature = "rayon")]
        let pieces: Vec<Vec<Option<u64>>> = {
            use rayon::prelude::*;
            (0..SHARDS).into_par_iter().map(work).collect::<Result<_, _>>()?
        };
        #[cfg(not(feature = "rayon"))]
        let pieces: Vec<Vec<Option<u64>>> = (0..SHARDS).map(work).collect::<Result<_, _>>()?;
        // Back into `changes`' order: `order` lists each shard's positions.
        let mut out = vec![None; changes.len()];
        for (at, previous) in order.iter().zip(pieces.into_iter().flatten()) {
            out[*at as usize] = previous;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A deterministic stream of 64-bit values (splitmix64).
    struct Stream(u64);
    impl Stream {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    fn key_of(n: u64, shard_byte: Option<u8>) -> Hash {
        let mut key = *blake3::hash(&n.to_le_bytes()).as_bytes();
        if let Some(byte) = shard_byte {
            key[0] = byte;
        }
        key
    }

    /// Random inserts, overwrites and removes against a `HashMap`, with a
    /// slot store standing in for the entry file (slots are append-only, as
    /// in the tree). `universe` keys sharing `key[0]` (or spread when `None`).
    fn differential(seed: u64, ops: usize, universe: u64, shard: Option<u8>) {
        let mut stream = Stream(seed);
        let mut store: Vec<Hash> = Vec::new();
        let mut index = TagIndex::default();
        let mut oracle: HashMap<Hash, u64> = HashMap::new();
        for _ in 0..ops {
            let key = key_of(stream.next() % universe, shard);
            match stream.next() % 4 {
                0 | 1 => {
                    let slot = store.len() as u64;
                    store.push(key);
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(index.insert(key, slot, key_at).unwrap(), oracle.insert(key, slot));
                }
                2 => {
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(index.remove(&key, key_at), oracle.remove(&key));
                }
                _ => {
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(index.get(&key, key_at), oracle.get(&key).copied());
                }
            }
            assert_eq!(index.len(), oracle.len());
        }
        let key_at = |slot: u64| store[slot as usize];
        for (key, slot) in &oracle {
            assert_eq!(index.get(key, key_at), Some(*slot));
        }
        for n in universe..universe + 1000 {
            assert_eq!(index.get(&key_of(n, shard), key_at), None);
        }
    }

    /// [`differential`] on one shard directly: a small table, so probes wrap
    /// around and removals shift runs back.
    fn shard_differential(seed: u64, ops: usize, universe: u64) {
        let mut stream = Stream(seed);
        let mut store: Vec<Hash> = Vec::new();
        let mut shard = Shard::default();
        let mut oracle: HashMap<Hash, u64> = HashMap::new();
        for _ in 0..ops {
            let key = key_of(stream.next() % universe, None);
            match stream.next() % 4 {
                0 | 1 => {
                    let slot = store.len() as u64;
                    store.push(key);
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(shard.insert(&key, slot, &key_at, MAX_BITS).unwrap(), oracle.insert(key, slot));
                }
                2 => {
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(shard.remove(&key, &key_at), oracle.remove(&key));
                }
                _ => {
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(shard.get(&key, &key_at).map(|(_, slot)| slot), oracle.get(&key).copied());
                }
            }
            assert_eq!(shard.len, oracle.len());
        }
    }

    #[test]
    fn matches_a_hash_map_in_one_small_shard_with_wraparound_and_backward_shifts() {
        for seed in 0..20 {
            shard_differential(seed, 20_000, 40);
            differential(seed, 2_000, 40, Some(7));
        }
    }

    /// Keys a sender ground to share `key[0]` spread over the shards: past the
    /// point where one shard would have been full they all insert.
    #[test]
    fn keys_sharing_their_first_byte_do_not_fill_one_shard() {
        // 16 buckets a shard: 12 keys at the 3/4 load.
        let mut index = TagIndex::with_max_bits(MIN_BITS);
        let store: Vec<Hash> = (0..400u64).map(|n| key_of(n, Some(0))).collect();
        let key_at = |slot: u64| store[slot as usize];
        for (slot, key) in store.iter().enumerate() {
            assert_eq!(index.insert(*key, slot as u64, key_at), Ok(None), "key {slot}");
        }
        assert_eq!(index.len(), store.len());
    }

    /// A shard past its limit is an error, not a panic, and the index keeps
    /// answering for what it holds.
    #[test]
    fn a_full_shard_is_an_error() {
        let mut index = TagIndex::with_max_bits(MIN_BITS);
        let store: Vec<Hash> = (0..(SHARDS as u64 * 16)).map(|n| key_of(n, Some(0))).collect();
        let key_at = |slot: u64| store[slot as usize];
        let refused = store
            .iter()
            .enumerate()
            .find_map(|(slot, key)| index.insert(*key, slot as u64, key_at).err().map(|err| (slot, err)));
        let (slot, err) = refused.expect("more keys than the shards hold");
        assert!(matches!(err, IndexError::ShardFull { max_bits: MIN_BITS, .. }), "{err}");
        for (held, key) in store.iter().enumerate().take(slot) {
            assert_eq!(index.get(key, key_at), Some(held as u64));
        }
        let mut pairs: Vec<(Hash, u64)> = store.iter().enumerate().map(|(slot, key)| (*key, slot as u64)).collect();
        pairs.sort_unstable();
        assert!(TagIndex::with_max_bits(MIN_BITS).insert_sorted(&pairs, key_at).is_err());
    }

    #[test]
    fn matches_a_hash_map_across_shards_and_growth() {
        differential(99, 400_000, 150_000, None);
    }

    #[test]
    fn sorted_inserts_match_single_inserts() {
        let mut store: Vec<Hash> = Vec::new();
        let mut pairs: Vec<(Hash, u64)> = Vec::new();
        for n in 0..50_000u64 {
            let key = key_of(n, None);
            pairs.push((key, store.len() as u64));
            store.push(key);
        }
        pairs.sort_unstable();
        let key_at = |slot: u64| store[slot as usize];
        let mut sorted = TagIndex::default();
        sorted.reserve(1000);
        sorted.insert_sorted(&pairs[..25_000], key_at).unwrap();
        sorted.insert_sorted(&pairs[25_000..], key_at).unwrap();
        let mut single = TagIndex::default();
        for (key, slot) in &pairs {
            assert_eq!(single.insert(*key, *slot, key_at), Ok(None));
        }
        assert_eq!(sorted.len(), 50_000);
        for (key, slot) in &pairs {
            assert_eq!(sorted.get(key, key_at), Some(*slot));
            assert_eq!(single.get(key, key_at), Some(*slot));
        }
        assert!(sorted.memory_bytes() < 50_000 * 22, "{} bytes", sorted.memory_bytes());
    }

    #[test]
    fn the_shared_index_applies_sorted_batches_like_single_operations() {
        let mut stream = Stream(7);
        let mut store: Vec<Hash> = Vec::new();
        let shared = SharedOffsetIndex::default();
        let mut oracle: HashMap<Hash, u64> = HashMap::new();
        for _ in 0..40 {
            let mut batch: HashMap<Hash, Option<u64>> = HashMap::new();
            for _ in 0..2_000 {
                let key = key_of(stream.next() % 30_000, None);
                let value = if stream.next().is_multiple_of(5) {
                    None
                } else {
                    store.push(key);
                    Some(store.len() as u64 - 1)
                };
                batch.insert(key, value);
            }
            let mut changes: Vec<(Hash, Option<u64>)> = batch.into_iter().collect();
            changes.sort_unstable_by_key(|(key, _)| *key);
            let key_at = |value: u64| store[value as usize];
            let previous = shared.apply_sorted(&changes, key_at).unwrap();
            for ((key, value), previous) in changes.iter().zip(previous) {
                let expected = match value {
                    Some(value) => oracle.insert(*key, *value),
                    None => oracle.remove(key),
                };
                assert_eq!(previous, expected);
            }
            assert_eq!(shared.len(), oracle.len());
        }
        let key_at = |value: u64| store[value as usize];
        for (key, value) in &oracle {
            assert_eq!(shared.get(key, key_at), Some(*value));
        }
    }

    #[test]
    fn a_read_behind_a_held_shard_is_counted_as_a_wait_and_answers_the_same() {
        let key = key_of(1, Some(9));
        let store = [key];
        let key_at = |value: u64| store[value as usize];
        let shared = SharedOffsetIndex::default();
        shared.insert(key, 0, key_at).unwrap();
        let (count_before, _) = thread_read_waits();
        assert_eq!(shared.get(&key, key_at), Some(0));
        assert_eq!(thread_read_waits().0, count_before, "an uncontended read is not a wait");
        let ready = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let held = shared.write(shard_of(&key));
            let reader = scope.spawn(|| {
                ready.wait();
                let found = shared.get(&key, key_at);
                (found, thread_read_waits())
            });
            ready.wait();
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
            let (found, (count, ns)) = reader.join().unwrap();
            assert_eq!(found, Some(0));
            assert_eq!(count, 1);
            assert!(ns > 0, "waited {ns} ns");
        });
    }

    #[test]
    fn readers_of_untouched_keys_see_them_while_a_writer_applies_batches() {
        let stable: Vec<Hash> = (0..5_000u64).map(|n| key_of(n, None)).collect();
        let churn: Vec<Hash> = (1_000_000..1_050_000u64).map(|n| key_of(n, None)).collect();
        let store: Vec<Hash> = stable.iter().chain(churn.iter()).copied().collect();
        let shared = SharedOffsetIndex::default();
        let key_at = |value: u64| store[value as usize];
        let mut initial: Vec<(Hash, Option<u64>)> = stable.iter().enumerate().map(|(i, key)| (*key, Some(i as u64))).collect();
        initial.sort_unstable_by_key(|(key, _)| *key);
        shared.apply_sorted(&initial, key_at).unwrap();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                for round in 0..20usize {
                    let mut changes: Vec<(Hash, Option<u64>)> = churn
                        .iter()
                        .enumerate()
                        .map(|(i, key)| (*key, round.is_multiple_of(2).then_some((stable.len() + i) as u64)))
                        .collect();
                    changes.sort_unstable_by_key(|(key, _)| *key);
                    shared.apply_sorted(&changes, key_at).unwrap();
                }
            });
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..20 {
                        for (i, key) in stable.iter().enumerate() {
                            assert_eq!(shared.get(key, key_at), Some(i as u64));
                        }
                    }
                });
            }
            writer.join().unwrap();
        });
    }

    /// A shared index over `live` keys (offsets are store positions) and a
    /// sorted batch of `batch` keys, half of them held, half misses.
    fn shared_fixture(live: u64, batch: u64) -> (Vec<Hash>, SharedOffsetIndex, Vec<(Hash, Option<u64>)>) {
        let store: Vec<Hash> = (0..live).map(|n| key_of(n, None)).collect();
        let index = SharedOffsetIndex::default();
        let mut pairs: Vec<(Hash, Option<u64>)> = store.iter().enumerate().map(|(i, k)| (*k, Some(i as u64))).collect();
        pairs.sort_unstable_by_key(|(k, _)| *k);
        index.apply_sorted(&pairs, |offset| store[offset as usize]).unwrap();
        let mut keys: Vec<(Hash, Option<u64>)> = (0..batch)
            .map(|n| if n % 2 == 0 { (key_of(n * 7 % live, None), None) } else { (key_of(live + n, None), None) })
            .collect();
        keys.sort_unstable_by_key(|(k, _)| *k);
        keys.dedup_by_key(|(k, _)| *k);
        (store, index, keys)
    }

    /// `apply_sorted` (prefetched runs) against one `insert`/`remove` a key:
    /// the same previous values and the same index afterwards.
    #[test]
    fn shared_apply_sorted_matches_single_ops() {
        let (mut store, batched, keys) = shared_fixture(60_000, 20_000);
        let (_, single, _) = shared_fixture(60_000, 20_000);
        // Held keys alternately removed and moved to a fresh offset; missing
        // keys inserted at a fresh offset.
        let changes: Vec<(Hash, Option<u64>)> = keys
            .iter()
            .enumerate()
            .map(|(i, (key, _))| {
                if i % 3 == 0 {
                    (*key, None)
                } else {
                    store.push(*key);
                    (*key, Some(store.len() as u64 - 1))
                }
            })
            .collect();
        let key_at = |offset: u64| store[offset as usize];
        let got = batched.apply_sorted(&changes, key_at).unwrap();
        let want: Vec<Option<u64>> = changes
            .iter()
            .map(|(key, value)| match value {
                Some(value) => single.insert(*key, *value, key_at).unwrap(),
                None => single.remove(key, key_at),
            })
            .collect();
        assert_eq!(got, want);
        assert_eq!(batched.len(), single.len());
        for (key, _) in &changes {
            assert_eq!(batched.get(key, key_at), single.get(key, key_at));
        }
    }

    #[test]
    fn tag_get_into_matches_get() {
        let store: Vec<Hash> = (0..50_000u64).map(|n| key_of(n, None)).collect();
        let mut index = TagIndex::default();
        let key_at = |slot: u64| store[slot as usize];
        for (slot, key) in store.iter().enumerate() {
            index.insert(*key, slot as u64, key_at).unwrap();
        }
        let probes: Vec<Hash> = (0..30_000u64).map(|n| key_of(n * 3, None)).collect();
        for len in [0usize, 1, 5, 8, 9, 1024, probes.len()] {
            let mut out = vec![Some(u64::MAX); len];
            index.get_into(&mut out, |i| &probes[i], key_at);
            for (i, got) in out.iter().enumerate() {
                assert_eq!(*got, index.get(&probes[i], key_at));
            }
        }
    }

    /// `cargo test -p n42-twig-core --release --features rayon --lib -- --ignored
    /// --nocapture batch_lookup_bench`: the read view's `apply_sorted` (its
    /// overwrite path, every key held) and the tree's held-slot pass, one
    /// lookup a key against `get_into`, over a 4M-key index and a 326k-key
    /// block (half misses for the held-slot pass).
    #[test]
    #[ignore = "timing; run by hand in release"]
    fn batch_lookup_bench() {
        let (store, index, keys) = shared_fixture(4_000_000, 326_000);
        let key_at = |offset: u64| store[offset as usize];
        let rounds = 20;
        let time = |f: &dyn Fn() -> usize| {
            let mut best = u128::MAX;
            let mut sink = 0;
            for _ in 0..rounds {
                let at = std::time::Instant::now();
                sink += f();
                best = best.min(at.elapsed().as_micros());
            }
            (best, sink)
        };
        // Every held key mapped again to the offset it holds: the overwrite
        // path (a probe, then a bucket write), the same index every round.
        let overwrites: Vec<(Hash, Option<u64>)> =
            keys.iter().filter_map(|(key, _)| index.get(key, key_at).map(|offset| (*key, Some(offset)))).collect();
        let (apply, a) = time(&|| index.apply_sorted(&overwrites, key_at).map_or(0, |out| out.len()));
        println!("shared apply_sorted: {apply} us ({} overwrites, sink {a})", overwrites.len());

        let mut tag = TagIndex::default();
        let mut pairs: Vec<(Hash, u64)> = store.iter().enumerate().map(|(i, k)| (*k, i as u64)).collect();
        pairs.sort_unstable_by_key(|(k, _)| *k);
        tag.insert_sorted(&pairs, key_at).unwrap();
        let probes: Vec<Hash> = keys.iter().map(|(k, _)| *k).collect();
        let (before, a) = time(&|| probes.iter().map(|k| tag.get(k, key_at)).filter(Option::is_some).count());
        let (after, b) = time(&|| {
            let mut out = vec![None; probes.len()];
            tag.get_into(&mut out, |i| &probes[i], key_at);
            out.iter().filter(|o| o.is_some()).count()
        });
        println!("tag held slots (one thread): get {before} us, get_into {after} us (sinks {a} {b})");
    }
}

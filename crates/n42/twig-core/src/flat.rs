//! Cache-friendly open-addressing index: 16-byte key prefix → slot.
//!
//! Replaces `std::collections::HashMap<u128, u64>` on the hot lookup path:
//! - **No SipHash**: the bucket is a single multiply-xor mix of the (already
//!   blake3-uniform) prefix with a per-process random seed. The secret seed
//!   keeps adversarially ground key prefixes from clustering probes (HashDoS),
//!   which is what lets us skip a cryptographic hasher safely.
//! - **Prefetchable**: flat arrays + linear probing expose the bucket address,
//!   so the apply loop can software-prefetch the bucket for op `i+K` while
//!   processing op `i`, hiding DRAM latency (the dominant update-path cost).
//!
//! The index is a pure lookup accelerator — it never feeds the merkle root
//! (leaves commit full keys), so the random seed cannot affect consensus.

const EMPTY: u64 = u64::MAX;
const TOMB: u64 = u64::MAX - 1;

pub(crate) struct FlatIndex {
    keys: Vec<u128>,
    slots: Vec<u64>, // EMPTY = vacant, TOMB = deleted, else the slot value
    mask: usize,
    live: usize,
    tombs: usize,
    seed: u64,
}

fn random_seed() -> u64 {
    // std-only entropy: RandomState's per-process random SipHash keys.
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

impl FlatIndex {
    pub(crate) fn new() -> Self {
        Self::with_capacity_pow2(64)
    }

    fn with_capacity_pow2(cap: usize) -> Self {
        debug_assert!(cap.is_power_of_two());
        Self {
            keys: vec![0u128; cap],
            slots: vec![EMPTY; cap],
            mask: cap - 1,
            live: 0,
            tombs: 0,
            seed: random_seed(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.live
    }

    #[inline]
    fn bucket(&self, prefix: u128) -> usize {
        let mut x = (prefix as u64) ^ ((prefix >> 64) as u64) ^ self.seed;
        x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^= x >> 32;
        (x as usize) & self.mask
    }

    /// Prefetch the bucket line(s) for `prefix` (no-op off x86_64). A cache line
    /// holds 4 prefix keys, which covers the typical 1–2 linear probes.
    #[inline]
    pub(crate) fn prefetch(&self, prefix: u128) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
            let b = self.bucket(prefix);
            _mm_prefetch(self.keys.as_ptr().add(b) as *const i8, _MM_HINT_T0);
            _mm_prefetch(self.slots.as_ptr().add(b) as *const i8, _MM_HINT_T0);
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = prefix;
    }

    pub(crate) fn get(&self, prefix: u128) -> Option<u64> {
        let mut b = self.bucket(prefix);
        loop {
            let s = self.slots[b];
            if s == EMPTY {
                return None;
            }
            if s != TOMB && self.keys[b] == prefix {
                return Some(s);
            }
            b = (b + 1) & self.mask;
        }
    }

    /// Insert or update `prefix → slot`.
    pub(crate) fn insert(&mut self, prefix: u128, slot: u64) {
        debug_assert!(slot < TOMB);
        if (self.live + self.tombs + 1) * 8 > (self.mask + 1) * 7 {
            self.grow();
        }
        let mut b = self.bucket(prefix);
        let mut insert_at = usize::MAX;
        loop {
            let s = self.slots[b];
            if s == EMPTY {
                // Not present: reuse the first tombstone seen, else this vacancy.
                let at = if insert_at != usize::MAX {
                    insert_at
                } else {
                    b
                };
                if self.slots[at] == TOMB {
                    self.tombs -= 1;
                }
                self.keys[at] = prefix;
                self.slots[at] = slot;
                self.live += 1;
                return;
            }
            if s == TOMB {
                if insert_at == usize::MAX {
                    insert_at = b;
                }
            } else if self.keys[b] == prefix {
                self.slots[b] = slot; // update in place
                return;
            }
            b = (b + 1) & self.mask;
        }
    }

    /// Remove `prefix`. Returns the slot it mapped to, if present.
    pub(crate) fn remove(&mut self, prefix: u128) -> Option<u64> {
        let mut b = self.bucket(prefix);
        loop {
            let s = self.slots[b];
            if s == EMPTY {
                return None;
            }
            if s != TOMB && self.keys[b] == prefix {
                self.slots[b] = TOMB;
                self.live -= 1;
                self.tombs += 1;
                return Some(s);
            }
            b = (b + 1) & self.mask;
        }
    }

    /// Ensure capacity for `n` live entries without growing mid-batch.
    pub(crate) fn reserve(&mut self, additional: usize) {
        let need = (self.live + additional) * 8 / 7 + 1;
        if need > self.mask + 1 {
            self.rehash(need.next_power_of_two());
        }
    }

    fn grow(&mut self) {
        // Tombstone-heavy tables rehash in place size; genuinely full ones double.
        let cap = if self.live * 4 >= (self.mask + 1) {
            (self.mask + 1) * 2
        } else {
            self.mask + 1
        };
        self.rehash(cap);
    }

    fn rehash(&mut self, cap: usize) {
        let mut next = Self::with_capacity_pow2(cap);
        next.seed = self.seed; // keep bucket placement stable across rehashes
        for b in 0..=self.mask {
            let s = self.slots[b];
            if s != EMPTY && s != TOMB {
                next.insert(self.keys[b], s);
            }
        }
        *self = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::collections::HashMap;

    #[test]
    fn insert_get_update_remove() {
        let mut f = FlatIndex::new();
        assert_eq!(f.get(42), None);
        f.insert(42, 7);
        assert_eq!(f.get(42), Some(7));
        f.insert(42, 8); // update
        assert_eq!(f.get(42), Some(8));
        assert_eq!(f.len(), 1);
        assert_eq!(f.remove(42), Some(8));
        assert_eq!(f.get(42), None);
        assert_eq!(f.remove(42), None);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn tombstone_reuse_and_reinsert() {
        let mut f = FlatIndex::new();
        f.insert(1, 10);
        f.remove(1);
        f.insert(1, 11); // must find the tombstone path and not duplicate
        assert_eq!(f.get(1), Some(11));
        assert_eq!(f.len(), 1);
    }

    /// Differential fuzz vs std HashMap across inserts/updates/removes + growth.
    #[test]
    fn fuzz_against_std_hashmap() {
        let mut rng = rand::rng();
        let mut f = FlatIndex::new();
        let mut model: HashMap<u128, u64> = HashMap::new();
        for i in 0..200_000u64 {
            // Small key space forces heavy update/remove collisions.
            let key = (rng.random::<u32>() % 30_000) as u128;
            match rng.random::<u8>() % 4 {
                0 => {
                    let got = f.remove(key);
                    let want = model.remove(&key);
                    assert_eq!(got, want, "remove {key} at op {i}");
                }
                _ => {
                    f.insert(key, i);
                    model.insert(key, i);
                }
            }
            if i % 8192 == 0 {
                for (k, v) in model.iter().take(64) {
                    assert_eq!(f.get(*k), Some(*v));
                }
                assert_eq!(f.len(), model.len(), "len at op {i}");
            }
        }
        for (k, v) in &model {
            assert_eq!(f.get(*k), Some(*v));
        }
    }
}

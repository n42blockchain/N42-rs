//! Small bounded map with insertion-order eviction.
//!
//! Used by the consensus engine to cap the proposal-side caches
//! (`pending_tx_roots`, `pending_changes_hashes`) at a fixed size while
//! evicting in true FIFO order. The previous implementation used a bare
//! `HashMap` and called `keys().next()` to "find the oldest" entry, but
//! `HashMap`'s key iteration order is unspecified, so the eviction was
//! actually random — a still-relevant block could get dropped while a stale
//! one remained, silently making cache lookups fall back to the
//! `unwrap_or_default()` zero hash and weakening the audit Plan #2 binding.
//!
//! `BoundedFifoMap` keeps a `HashMap` for O(1) lookups and a parallel
//! `VecDeque<K>` recording the insertion order. On overflow it pops the
//! oldest key from the front of the deque and removes it from the map.
//! Re-inserting an existing key overwrites the value but does NOT promote
//! it to "newest" — that matches the prior pattern (which never tried to
//! refresh on update) and keeps the implementation a few lines.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Debug)]
pub(crate) struct BoundedFifoMap<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K, V> BoundedFifoMap<K, V>
where
    K: Eq + Hash + Clone,
{
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    // We deliberately keep the `contains_key` + `insert` shape: in the miss
    // case we must update `self.order` (eviction + push_back) before the
    // `insert`, and re-borrowing the map via `Entry` would conflict with
    // mutating `self.order`.
    #[allow(clippy::map_entry)]
    pub(crate) fn insert(&mut self, key: K, value: V) {
        if !self.map.contains_key(&key) {
            // edition-2021: N42-26 writes this as a let-chain.
            if self.map.len() >= self.capacity {
                if let Some(oldest) = self.order.pop_front() {
                    self.map.remove(&oldest);
                }
            }
            self.order.push_back(key.clone());
        }
        self.map.insert(key, value);
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.map.remove(key);
        // edition-2021: N42-26 writes this as a let-chain.
        if removed.is_some() {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
        removed
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_eviction_drops_oldest() {
        let mut m = BoundedFifoMap::<u32, u32>::new(3);
        m.insert(1, 10);
        m.insert(2, 20);
        m.insert(3, 30);
        assert_eq!(m.len(), 3);
        // Inserting 4 evicts 1 (oldest), not a random key.
        m.insert(4, 40);
        assert_eq!(m.len(), 3);
        assert!(m.get(&1).is_none());
        assert_eq!(m.get(&2), Some(&20));
        assert_eq!(m.get(&3), Some(&30));
        assert_eq!(m.get(&4), Some(&40));
    }

    #[test]
    fn reinsert_overwrites_without_reordering() {
        let mut m = BoundedFifoMap::<u32, u32>::new(2);
        m.insert(1, 10);
        m.insert(2, 20);
        // Re-insert key 1 with new value: should overwrite, not push to back.
        m.insert(1, 100);
        assert_eq!(m.len(), 2);
        // Now insert 3: still evicts 1 (because it's the oldest in insertion order).
        m.insert(3, 30);
        assert!(m.get(&1).is_none());
        assert_eq!(m.get(&2), Some(&20));
        assert_eq!(m.get(&3), Some(&30));
    }

    #[test]
    fn explicit_remove_clears_both_structures() {
        let mut m = BoundedFifoMap::<u32, u32>::new(3);
        m.insert(1, 10);
        m.insert(2, 20);
        m.insert(3, 30);
        assert_eq!(m.remove(&2), Some(20));
        assert_eq!(m.len(), 2);
        // After removing 2, inserting 4 must evict 1 (still the oldest), not 3.
        m.insert(4, 40);
        m.insert(5, 50);
        assert!(m.get(&1).is_none());
        assert_eq!(m.get(&3), Some(&30));
        assert_eq!(m.get(&4), Some(&40));
        assert_eq!(m.get(&5), Some(&50));
    }

    #[test]
    fn remove_missing_is_noop() {
        let mut m = BoundedFifoMap::<u32, u32>::new(2);
        m.insert(1, 10);
        assert_eq!(m.remove(&999), None);
        assert_eq!(m.len(), 1);
    }
}

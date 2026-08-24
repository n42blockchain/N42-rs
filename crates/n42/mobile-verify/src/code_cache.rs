use alloy_primitives::{B256, Bytes};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use tracing::warn;

/// LRU cache for contract bytecodes on mobile devices.
///
/// Reduces verification packet sizes — the IDC node tracks which codes each
/// phone has cached and excludes them from `VerificationPacket.uncached_bytecodes`.
/// Cache keys are `keccak256(bytecode)` (the code hash).
pub struct CodeCache {
    cache: LruCache<B256, Bytes>,
}

impl CodeCache {
    /// Creates a new code cache with the given capacity (clamped to 1 if 0).
    pub fn new(capacity: usize) -> Self {
        let capacity = if capacity == 0 {
            warn!("CodeCache capacity 0 is invalid, clamping to 1");
            1
        } else {
            capacity
        };
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
        }
    }

    /// Inserts a bytecode into the cache.
    pub fn insert(&mut self, code_hash: B256, bytecode: Bytes) {
        self.cache.put(code_hash, bytecode);
    }

    /// Retrieves a bytecode from the cache (marks as recently used).
    pub fn get(&mut self, code_hash: &B256) -> Option<&Bytes> {
        self.cache.get(code_hash)
    }

    /// Checks if a code hash is in the cache without updating LRU order.
    pub fn contains(&self, code_hash: &B256) -> bool {
        self.cache.contains(code_hash)
    }

    /// Returns all cached code hashes.
    ///
    /// Used by the IDC node to determine which bytecodes to exclude from packets.
    pub fn cached_hashes(&self) -> Vec<B256> {
        self.cache.iter().map(|(k, _)| *k).collect()
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Removes an entry from the cache (used by evict hints from `CacheSyncMessage`).
    pub fn remove(&mut self, code_hash: &B256) -> Option<Bytes> {
        self.cache.pop(code_hash)
    }

    /// Clears all cached entries.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

/// Tracks hot contract usage across all mobile verifiers.
///
/// The IDC node uses this to proactively push frequently-accessed bytecodes
/// to phones during cache sync, before they appear in a verification packet.
pub struct HotContractTracker {
    access_counts: HashMap<B256, u64>,
    blocks_tracked: u64,
}

impl HotContractTracker {
    /// Creates a new hot contract tracker.
    pub fn new() -> Self {
        Self {
            access_counts: HashMap::new(),
            blocks_tracked: 0,
        }
    }

    /// Records contract accesses for a block's execution.
    pub fn record_block_accesses(&mut self, code_hashes: &[B256]) {
        self.blocks_tracked += 1;
        for hash in code_hashes {
            *self.access_counts.entry(*hash).or_insert(0) += 1;
        }
    }

    /// Returns the top-N hottest contracts by access count.
    pub fn top_contracts(&self, n: usize) -> Vec<(B256, u64)> {
        let mut sorted: Vec<_> = self.access_counts.iter().map(|(k, v)| (*k, *v)).collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        sorted.truncate(n);
        sorted
    }

    /// Returns the total number of blocks tracked.
    pub fn blocks_tracked(&self) -> u64 {
        self.blocks_tracked
    }

    /// Decays all access counts by `factor` (0.0–1.0), removing entries that reach zero.
    ///
    /// Call periodically (e.g., every epoch) to prevent stale contracts from
    /// occupying top positions indefinitely.
    pub fn decay(&mut self, factor: f64) {
        let factor = factor.clamp(0.0, 1.0);
        self.access_counts.retain(|_, count| {
            *count = (*count as f64 * factor) as u64;
            *count > 0
        });
    }
}

impl Default for HotContractTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache synchronization message sent from IDC to mobile devices.
///
/// Periodically, the IDC pushes hot contract bytecodes to phones so they can
/// pre-populate their caches before verification packets arrive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSyncMessage {
    /// Bytecodes to add to the cache: (code_hash, bytecode).
    pub codes: Vec<(B256, Bytes)>,
    /// Code hashes that are no longer hot and can be evicted.
    pub evict_hints: Vec<B256>,
}

/// Encodes a `CacheSyncMessage` with a wire header.
///
/// Format: `wire_header(4B) + codes_count(u32LE) + [code_hash(32B) + code_len(u32LE) + bytecode]...`
///       `+ evict_count(u32LE) + [code_hash(32B)]...`
pub fn encode_cache_sync(msg: &CacheSyncMessage) -> Vec<u8> {
    use crate::wire;

    let codes_size: usize = msg.codes.iter().map(|(_, c)| 32 + 4 + c.len()).sum();
    let estimated = wire::HEADER_SIZE + 4 + codes_size + 4 + msg.evict_hints.len() * 32;
    let mut buf = Vec::with_capacity(estimated);

    wire::encode_header(&mut buf, wire::VERSION_1, 0x00);

    // Codes
    buf.extend_from_slice(&(msg.codes.len() as u32).to_le_bytes());
    for (hash, code) in &msg.codes {
        buf.extend_from_slice(hash.as_slice());
        buf.extend_from_slice(&(code.len() as u32).to_le_bytes());
        buf.extend_from_slice(code);
    }

    // Evict hints
    buf.extend_from_slice(&(msg.evict_hints.len() as u32).to_le_bytes());
    for hash in &msg.evict_hints {
        buf.extend_from_slice(hash.as_slice());
    }

    buf
}

/// Maximum allowed code count to prevent OOM from corrupted data.
const MAX_CACHE_SYNC_CODES: usize = 10_000;
/// Maximum allowed evict hint count to prevent OOM from corrupted data.
const MAX_CACHE_SYNC_EVICTS: usize = 10_000;

/// Decodes a `CacheSyncMessage` from versioned wire format.
pub fn decode_cache_sync(data: &[u8]) -> Result<CacheSyncMessage, crate::wire::WireError> {
    use crate::wire::{self, WireError};

    let (_header, payload) = wire::decode_header(data)?;
    let mut pos = 0;

    let read_u32 = |pos: &mut usize| -> Result<u32, WireError> {
        if *pos + 4 > payload.len() {
            return Err(WireError::UnexpectedEof(*pos));
        }
        let val = u32::from_le_bytes([
            payload[*pos],
            payload[*pos + 1],
            payload[*pos + 2],
            payload[*pos + 3],
        ]);
        *pos += 4;
        Ok(val)
    };

    let read_bytes = |pos: &mut usize, n: usize| -> Result<&[u8], WireError> {
        if *pos + n > payload.len() {
            return Err(WireError::LengthOverflow {
                offset: *pos,
                need: n,
                remaining: payload.len() - *pos,
            });
        }
        let slice = &payload[*pos..*pos + n];
        *pos += n;
        Ok(slice)
    };

    // Codes
    let code_count = read_u32(&mut pos)? as usize;
    if code_count > MAX_CACHE_SYNC_CODES {
        return Err(WireError::LengthOverflow {
            offset: pos - 4,
            need: code_count,
            remaining: MAX_CACHE_SYNC_CODES,
        });
    }
    let mut codes = Vec::with_capacity(code_count);
    for _ in 0..code_count {
        let hash = B256::from_slice(read_bytes(&mut pos, 32)?);
        let code_len = read_u32(&mut pos)? as usize;
        let bytecode = Bytes::copy_from_slice(read_bytes(&mut pos, code_len)?);
        codes.push((hash, bytecode));
    }

    // Evict hints
    let evict_count = read_u32(&mut pos)? as usize;
    if evict_count > MAX_CACHE_SYNC_EVICTS {
        return Err(WireError::LengthOverflow {
            offset: pos - 4,
            need: evict_count,
            remaining: MAX_CACHE_SYNC_EVICTS,
        });
    }
    let mut evict_hints = Vec::with_capacity(evict_count);
    for _ in 0..evict_count {
        let hash = B256::from_slice(read_bytes(&mut pos, 32)?);
        evict_hints.push(hash);
    }

    Ok(CacheSyncMessage { codes, evict_hints })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes};

    /// Helper: creates a B256 hash from a single byte (for readability).
    fn hash(b: u8) -> B256 {
        B256::from([b; 32])
    }

    /// Helper: creates Bytes from a short slice.
    fn bytecode(data: &[u8]) -> Bytes {
        Bytes::from(data.to_vec())
    }

    // ---- CodeCache tests ----

    #[test]
    fn test_code_cache_insert_and_get() {
        let mut cache = CodeCache::new(10);
        let h = hash(1);
        let code = bytecode(&[0xAA, 0xBB, 0xCC]);

        cache.insert(h, code.clone());

        let retrieved = cache.get(&h).expect("should find the inserted bytecode");
        assert_eq!(*retrieved, code);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_code_cache_lru_eviction() {
        let capacity = 3;
        let mut cache = CodeCache::new(capacity);

        // Insert exactly `capacity` items.
        for i in 0..capacity {
            cache.insert(hash(i as u8), bytecode(&[i as u8]));
        }
        assert_eq!(cache.len(), capacity);

        // Insert one more (capacity + 1). This should evict hash(0), the oldest.
        cache.insert(hash(100), bytecode(&[100]));
        assert_eq!(cache.len(), capacity);

        // hash(0) should have been evicted.
        assert!(!cache.contains(&hash(0)), "oldest entry should be evicted");

        // The others should still be present.
        assert!(cache.contains(&hash(1)));
        assert!(cache.contains(&hash(2)));
        assert!(cache.contains(&hash(100)));
    }

    #[test]
    fn test_code_cache_contains() {
        let mut cache = CodeCache::new(10);
        let h = hash(5);

        assert!(
            !cache.contains(&h),
            "empty cache should not contain any key"
        );

        cache.insert(h, bytecode(&[0x01]));
        assert!(cache.contains(&h), "cache should contain the inserted key");

        assert!(
            !cache.contains(&hash(99)),
            "cache should not contain a key that was never inserted"
        );
    }

    #[test]
    fn test_code_cache_cached_hashes() {
        let mut cache = CodeCache::new(10);

        assert!(
            cache.cached_hashes().is_empty(),
            "empty cache returns empty hashes"
        );

        let hashes_to_insert = vec![hash(10), hash(20), hash(30)];
        for h in &hashes_to_insert {
            cache.insert(*h, bytecode(&[0xFF]));
        }

        let mut cached = cache.cached_hashes();
        cached.sort();
        let mut expected = hashes_to_insert.clone();
        expected.sort();

        assert_eq!(
            cached, expected,
            "cached_hashes should return all inserted hashes"
        );
    }

    #[test]
    fn test_code_cache_remove() {
        let mut cache = CodeCache::new(10);
        let h = hash(42);
        let code = bytecode(&[0xDE, 0xAD]);

        // Remove from empty cache returns None.
        assert!(cache.remove(&h).is_none());

        cache.insert(h, code.clone());
        assert_eq!(cache.len(), 1);

        // Remove existing key returns the value.
        let removed = cache.remove(&h);
        assert_eq!(removed, Some(code));
        assert_eq!(cache.len(), 0);

        // Remove again returns None.
        assert!(cache.remove(&h).is_none());
    }

    #[test]
    fn test_code_cache_clear() {
        let mut cache = CodeCache::new(10);

        cache.insert(hash(1), bytecode(&[0x01]));
        cache.insert(hash(2), bytecode(&[0x02]));
        cache.insert(hash(3), bytecode(&[0x03]));
        assert_eq!(cache.len(), 3);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert!(!cache.contains(&hash(1)));
    }

    #[test]
    fn test_cache_sync_message_roundtrip() {
        let msg = CacheSyncMessage {
            codes: vec![
                (hash(1), bytecode(&[0x60, 0x00])),
                (hash(2), bytecode(&[0x60, 0x01, 0x60, 0x00, 0xf3])),
            ],
            evict_hints: vec![hash(10), hash(20)],
        };

        let encoded = bincode::serialize(&msg).expect("serialize should succeed");
        let decoded: CacheSyncMessage =
            bincode::deserialize(&encoded).expect("deserialize should succeed");

        assert_eq!(decoded.codes.len(), 2);
        assert_eq!(decoded.codes[0].0, hash(1));
        assert_eq!(
            decoded.codes[1].1,
            bytecode(&[0x60, 0x01, 0x60, 0x00, 0xf3])
        );
        assert_eq!(decoded.evict_hints, vec![hash(10), hash(20)]);
    }

    #[test]
    fn test_cache_sync_message_empty() {
        let msg = CacheSyncMessage {
            codes: vec![],
            evict_hints: vec![],
        };

        let encoded = bincode::serialize(&msg).expect("serialize should succeed");
        let decoded: CacheSyncMessage =
            bincode::deserialize(&encoded).expect("deserialize should succeed");

        assert!(decoded.codes.is_empty());
        assert!(decoded.evict_hints.is_empty());
    }

    // ---- HotContractTracker tests ----

    #[test]
    fn test_hot_contract_tracker_basic() {
        let mut tracker = HotContractTracker::new();

        // Record accesses over multiple blocks.
        tracker.record_block_accesses(&[hash(1), hash(2), hash(3)]);
        tracker.record_block_accesses(&[hash(1), hash(2)]);
        tracker.record_block_accesses(&[hash(1)]);

        assert_eq!(tracker.blocks_tracked(), 3);

        let top = tracker.top_contracts(5);

        // hash(1) was accessed 3 times, hash(2) twice, hash(3) once.
        assert_eq!(top.len(), 3);
        assert_eq!(top[0], (hash(1), 3));
        assert_eq!(top[1], (hash(2), 2));
        assert_eq!(top[2], (hash(3), 1));

        // top_contracts with n=1 should return only the hottest.
        let top1 = tracker.top_contracts(1);
        assert_eq!(top1.len(), 1);
        assert_eq!(top1[0], (hash(1), 3));
    }

    #[test]
    fn test_hot_contract_tracker_decay() {
        let mut tracker = HotContractTracker::new();

        // hash(1): 10 accesses, hash(2): 1 access.
        for _ in 0..10 {
            tracker.record_block_accesses(&[hash(1)]);
        }
        tracker.record_block_accesses(&[hash(2)]);

        // After decay(0.5), hash(1) should have 5, hash(2) should have 0 and be removed.
        tracker.decay(0.5);

        let top = tracker.top_contracts(10);

        // hash(2) had count 1, after * 0.5 → 0.5 truncated to 0 → removed.
        // hash(1) had count 10, after * 0.5 → 5.
        let hash1_entry = top.iter().find(|(h, _)| *h == hash(1));
        assert_eq!(
            hash1_entry,
            Some(&(hash(1), 5)),
            "hash(1) count should be halved to 5"
        );

        let hash2_entry = top.iter().find(|(h, _)| *h == hash(2));
        assert!(
            hash2_entry.is_none(),
            "hash(2) should be removed after decay (count went to 0)"
        );
    }

    #[test]
    fn test_code_cache_zero_capacity_clamp() {
        // capacity=0 should be clamped to 1 instead of panicking.
        let mut cache = CodeCache::new(0);
        assert_eq!(cache.len(), 0);
        cache.insert(hash(1), bytecode(&[0x01]));
        assert_eq!(cache.len(), 1);
        // Cache holds exactly 1 item; inserting another evicts the first.
        cache.insert(hash(2), bytecode(&[0x02]));
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&hash(2)));
        assert!(
            !cache.contains(&hash(1)),
            "clamped capacity=1, oldest should be evicted"
        );
    }

    #[test]
    fn test_hot_tracker_decay_zero_removes_all() {
        let mut tracker = HotContractTracker::new();
        tracker.record_block_accesses(&[hash(1), hash(2)]);
        tracker.record_block_accesses(&[hash(1)]);
        assert_eq!(tracker.top_contracts(10).len(), 2);

        // decay(0.0) should remove all entries (counts become 0).
        tracker.decay(0.0);
        assert!(
            tracker.top_contracts(10).is_empty(),
            "decay(0.0) should remove all entries"
        );
    }

    #[test]
    fn test_hot_tracker_decay_one_keeps_all() {
        let mut tracker = HotContractTracker::new();
        tracker.record_block_accesses(&[hash(1), hash(2)]);
        tracker.record_block_accesses(&[hash(1)]);

        // decay(1.0) should keep all counts unchanged.
        tracker.decay(1.0);
        let top = tracker.top_contracts(10);
        assert_eq!(top.len(), 2);
        let h1 = top.iter().find(|(h, _)| *h == hash(1));
        assert_eq!(
            h1,
            Some(&(hash(1), 2)),
            "decay(1.0) should not change counts"
        );
    }

    #[test]
    fn test_hot_tracker_empty_top() {
        let tracker = HotContractTracker::new();
        assert!(
            tracker.top_contracts(10).is_empty(),
            "empty tracker should return empty list"
        );
        assert_eq!(tracker.blocks_tracked(), 0);
    }

    // ---- Versioned encode/decode tests ----

    #[test]
    fn test_cache_sync_versioned_roundtrip() {
        let msg = CacheSyncMessage {
            codes: vec![
                (hash(1), bytecode(&[0x60, 0x00])),
                (hash(2), bytecode(&[0x60, 0x01, 0x60, 0x00, 0xf3])),
            ],
            evict_hints: vec![hash(10), hash(20)],
        };

        let encoded = encode_cache_sync(&msg);
        let decoded = decode_cache_sync(&encoded).expect("should decode");

        assert_eq!(decoded.codes.len(), 2);
        assert_eq!(decoded.codes[0].0, hash(1));
        assert_eq!(decoded.codes[0].1, bytecode(&[0x60, 0x00]));
        assert_eq!(decoded.codes[1].0, hash(2));
        assert_eq!(
            decoded.codes[1].1,
            bytecode(&[0x60, 0x01, 0x60, 0x00, 0xf3])
        );
        assert_eq!(decoded.evict_hints, vec![hash(10), hash(20)]);
    }

    #[test]
    fn test_cache_sync_versioned_empty() {
        let msg = CacheSyncMessage {
            codes: vec![],
            evict_hints: vec![],
        };
        let encoded = encode_cache_sync(&msg);
        let decoded = decode_cache_sync(&encoded).expect("should decode empty");
        assert!(decoded.codes.is_empty());
        assert!(decoded.evict_hints.is_empty());
    }

    #[test]
    fn test_cache_sync_versioned_header_check() {
        let msg = CacheSyncMessage {
            codes: vec![],
            evict_hints: vec![],
        };
        let encoded = encode_cache_sync(&msg);
        // First 2 bytes should be "N2"
        assert_eq!(encoded[0], 0x4E);
        assert_eq!(encoded[1], 0x32);
        assert_eq!(encoded[2], 0x01); // VERSION_1
    }
}

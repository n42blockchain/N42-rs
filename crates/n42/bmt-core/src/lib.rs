//! Pure-blake3 Sparse Binary Merkle Tree engine + proof verification.
//!
//! Zero reth/mdbx dependencies, so `n42-mobile` / FFI can verify SBMT proofs
//! without pulling the storage stack. Contains the tree engine ([`Sbmt`]), the
//! in-shard proof ([`BmtProof`]), the depth-4 shard-root merkle, and the
//! end-to-end [`ShardedBmtProof`] (the type a mobile client verifies against a
//! block's combined state root).
//!
//! See `crates/n42-jmt/src/sharded_bmt.rs` for the sharded *builder* side
//! (`ShardedSbmt`), which depends on this crate.

use std::cell::Cell;

/// 32-byte hash or key.
pub type Hash = [u8; 32];

/// Hash of an empty subtree (all zeroes).
pub const EMPTY_HASH: Hash = [0u8; 32];

/// Number of shards (depth-4 shard-root merkle ⇒ 16 leaves).
pub const SHARD_COUNT: usize = 16;

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

#[inline]
fn hash_leaf(key: &Hash, value_hash: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_PREFIX]);
    h.update(key);
    h.update(value_hash);
    *h.finalize().as_bytes()
}

#[inline]
fn hash_internal(left: &Hash, right: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[INTERNAL_PREFIX]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Hash a raw value blob into the 32-byte leaf value hash.
#[inline]
pub fn hash_value(value: &[u8]) -> Hash {
    *blake3::hash(value).as_bytes()
}

// ---------------------------------------------------------------------------
// Canonical key derivation + shard assignment.
//
// These MUST stay byte-identical to `n42-jmt`'s `keys::account_key` /
// `keys::storage_key` and its `>> 4` shard split — `n42-jmt` re-uses them so
// there is a single source of truth. A key-bound proof check (see
// [`ShardedBmtProof::verify_for_key`]) is only sound if the verifier derives
// the key exactly the way the builder did.
// ---------------------------------------------------------------------------

/// Domain separators preventing cross-type key collisions.
/// Domain separator for account keys (public so batched derivation in other
/// crates can build the exact same blake3 input — single source of truth).
pub const ACCOUNT_DOMAIN: &[u8] = b"n42:account:";
/// Domain separator for storage keys (see [`ACCOUNT_DOMAIN`]).
pub const STORAGE_DOMAIN: &[u8] = b"n42:storage:";

/// Canonical SBMT key for an account leaf: `blake3("n42:account:" || address_20)`.
#[inline]
pub fn account_key(address: &[u8; 20]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(ACCOUNT_DOMAIN);
    h.update(address);
    *h.finalize().as_bytes()
}

/// Canonical SBMT key for a storage-slot leaf:
/// `blake3("n42:storage:" || address_20 || slot_32_be)`.
#[inline]
pub fn storage_key(address: &[u8; 20], slot_be: &[u8; 32]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(STORAGE_DOMAIN);
    h.update(address);
    h.update(slot_be);
    *h.finalize().as_bytes()
}

/// Shard a key falls into: the top nibble of byte 0, giving `0..SHARD_COUNT`.
///
/// Coupled to `SHARD_COUNT == 16` (a 4-bit split). The `debug_assert`
/// documents that coupling; if `SHARD_COUNT` ever changes this must too.
#[inline]
pub fn shard_index_for_key(key: &Hash) -> usize {
    debug_assert_eq!(
        SHARD_COUNT, 16,
        "shard_index_for_key assumes a 4-bit (16-way) split"
    );
    (key[0] >> 4) as usize
}

/// Bit at `depth` of `key`, MSB-first. `false` = left (0), `true` = right (1).
#[inline]
fn bit(key: &Hash, depth: usize) -> bool {
    (key[depth / 8] >> (7 - (depth % 8))) & 1 == 1
}

/// Index into the [`Sbmt`] node arena; `NIL` marks an empty link.
type NodeIdx = u32;
const NIL: NodeIdx = u32::MAX;

/// Arena node. Children are `NodeIdx` into the flat `Sbmt::nodes` Vec rather than
/// `Box` pointers — this removes per-node heap allocation + allocator overhead and
/// keeps nodes contiguous for cache locality. The tree structure (and therefore
/// every root/proof hash) is identical to the previous boxed representation.
enum Node {
    Leaf {
        key: Hash,
        value_hash: Hash,
    },
    Internal {
        left: NodeIdx,
        right: NodeIdx,
        cache: Cell<Option<Hash>>,
    },
}

/// Live-tree node accounting, for benchmarking footprint against other
/// content-addressed binary merkle trees (e.g. gov5's Go BMT).
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeStats {
    pub internal_nodes: usize,
    pub leaf_nodes: usize,
    /// Sum of per-node serialized bytes under a content-addressed store keyed by
    /// a 32-byte hash: internal = 32 + 64 (key + `left||right`), leaf = 32 + 32
    /// (key + value_hash). Mirrors gov5's `32 + len(value)` accounting so
    /// `avg_node_size` is comparable. This counts the *live* tree only — unlike
    /// an archival copy-on-write store, superseded node versions are not retained.
    pub serialized_bytes: u64,
}

impl NodeStats {
    pub fn total_nodes(&self) -> usize {
        self.internal_nodes + self.leaf_nodes
    }
}

/// A Sparse Binary Merkle Tree (blake3, 256-bit keys).
///
/// `base_depth` is the bit index the tree starts branching at: keys are assumed
/// to share their first `base_depth` bits (so those bits carry no information
/// inside this tree) and the structure skips them. The sharded layer sets
/// `base_depth = log2(SHARD_COUNT)` because every key in a shard shares the
/// top-nibble shard selector — this prunes the otherwise-forced single-child
/// chain for the shard prefix. The leaf still commits the FULL key
/// (`blake3(0x00 || key || value_hash)`), so the skip changes the commitment
/// (root) but not its soundness.
pub struct Sbmt {
    /// Flat node arena. Children reference slots by `NodeIdx`; `root == NIL` for
    /// an empty tree. Cache-friendly and free of per-node heap allocation.
    nodes: Vec<Node>,
    /// Recycled arena slots (freed by removes/collapses), reused before growing.
    free: Vec<NodeIdx>,
    root: NodeIdx,
    len: usize,
    base_depth: usize,
}

impl Default for Sbmt {
    fn default() -> Self {
        Self::new()
    }
}

impl Sbmt {
    /// Create an empty tree branching from bit 0.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: NIL,
            len: 0,
            base_depth: 0,
        }
    }

    /// Create an empty tree that skips the first `base_depth` (shared-prefix) bits.
    pub fn with_base_depth(base_depth: usize) -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: NIL,
            len: 0,
            base_depth,
        }
    }

    /// The bit index this tree starts branching at.
    pub fn base_depth(&self) -> usize {
        self.base_depth
    }

    /// Number of live leaves.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    // ── Arena helpers ──

    #[inline]
    fn alloc(&mut self, node: Node) -> NodeIdx {
        if let Some(i) = self.free.pop() {
            self.nodes[i as usize] = node;
            i
        } else {
            let i = self.nodes.len() as NodeIdx;
            self.nodes.push(node);
            i
        }
    }

    #[inline]
    fn free_slot(&mut self, idx: NodeIdx) {
        if idx != NIL {
            self.free.push(idx);
        }
    }

    fn node_hash(&self, idx: NodeIdx) -> Hash {
        if idx == NIL {
            return EMPTY_HASH;
        }
        match &self.nodes[idx as usize] {
            Node::Leaf { key, value_hash } => hash_leaf(key, value_hash),
            Node::Internal { left, right, cache } => {
                if let Some(h) = cache.get() {
                    return h;
                }
                let (l, r) = (*left, *right);
                let h = hash_internal(&self.node_hash(l), &self.node_hash(r));
                cache.set(Some(h));
                h
            }
        }
    }

    fn collect_stats(&self, idx: NodeIdx, s: &mut NodeStats) {
        if idx == NIL {
            return;
        }
        match &self.nodes[idx as usize] {
            Node::Leaf { .. } => {
                s.leaf_nodes += 1;
                s.serialized_bytes += 32 + 32;
            }
            Node::Internal { left, right, .. } => {
                s.internal_nodes += 1;
                s.serialized_bytes += 32 + 64;
                let (l, r) = (*left, *right);
                self.collect_stats(l, s);
                self.collect_stats(r, s);
            }
        }
    }

    /// Walk the live tree and tally internal/leaf node counts + serialized bytes.
    /// O(nodes); intended for diagnostics/benchmarks, not the hot path.
    pub fn node_stats(&self) -> NodeStats {
        let mut s = NodeStats::default();
        self.collect_stats(self.root, &mut s);
        s
    }

    /// Root hash (`EMPTY_HASH` for an empty tree).
    pub fn root_hash(&self) -> Hash {
        self.node_hash(self.root)
    }

    /// Insert or update a key with a pre-hashed value.
    pub fn insert_hashed(&mut self, key: Hash, value_hash: Hash) {
        let (new_root, added) = self.insert_at(self.root, key, value_hash, self.base_depth);
        self.root = new_root;
        if added {
            self.len += 1;
        }
    }

    fn insert_at(&mut self, slot: NodeIdx, key: Hash, vh: Hash, depth: usize) -> (NodeIdx, bool) {
        if slot == NIL {
            return (
                self.alloc(Node::Leaf {
                    key,
                    value_hash: vh,
                }),
                true,
            );
        }
        // Peek the node kind, copying out the fields we need, so the immutable
        // borrow is dropped before the `&mut self` recursion/alloc below.
        let (is_leaf, ek, ev, l, r) = match &self.nodes[slot as usize] {
            Node::Leaf { key, value_hash } => (true, *key, *value_hash, NIL, NIL),
            Node::Internal { left, right, .. } => (false, EMPTY_HASH, EMPTY_HASH, *left, *right),
        };
        if is_leaf {
            if ek == key {
                // Same key: update the value hash in place.
                self.nodes[slot as usize] = Node::Leaf {
                    key,
                    value_hash: vh,
                };
                (slot, false)
            } else {
                // Split: turn this slot into an internal node, then re-place the
                // existing leaf and insert the new key (recursive). Mirrors the
                // boxed `descend_insert` chain.
                self.nodes[slot as usize] = Node::Internal {
                    left: NIL,
                    right: NIL,
                    cache: Cell::new(None),
                };
                self.insert_at(slot, ek, ev, depth);
                self.insert_at(slot, key, vh, depth);
                (slot, true)
            }
        } else {
            // Internal: invalidate cache, recurse into the correct child, write
            // back the (possibly new) child index.
            if let Node::Internal { cache, .. } = &self.nodes[slot as usize] {
                cache.set(None);
            }
            if bit(&key, depth) {
                let (nr, added) = self.insert_at(r, key, vh, depth + 1);
                if let Node::Internal { right, .. } = &mut self.nodes[slot as usize] {
                    *right = nr;
                }
                (slot, added)
            } else {
                let (nl, added) = self.insert_at(l, key, vh, depth + 1);
                if let Node::Internal { left, .. } = &mut self.nodes[slot as usize] {
                    *left = nl;
                }
                (slot, added)
            }
        }
    }

    /// Insert or update a key with a raw value blob (hashed internally).
    pub fn insert(&mut self, key: Hash, value: &[u8]) {
        self.insert_hashed(key, hash_value(value));
    }

    /// Remove a key. Returns true if it existed.
    pub fn remove(&mut self, key: &Hash) -> bool {
        let (new_root, removed) = self.remove_at(self.root, key, self.base_depth);
        self.root = new_root;
        if removed {
            self.len -= 1;
        }
        removed
    }

    fn remove_at(&mut self, slot: NodeIdx, key: &Hash, depth: usize) -> (NodeIdx, bool) {
        if slot == NIL {
            return (NIL, false);
        }
        let (is_leaf, ek, l, r) = match &self.nodes[slot as usize] {
            Node::Leaf { key, .. } => (true, *key, NIL, NIL),
            Node::Internal { left, right, .. } => (false, EMPTY_HASH, *left, *right),
        };
        if is_leaf {
            if ek == *key {
                self.free_slot(slot);
                (NIL, true)
            } else {
                (slot, false)
            }
        } else {
            let removed = if bit(key, depth) {
                let (nr, rm) = self.remove_at(r, key, depth + 1);
                if let Node::Internal { right, cache, .. } = &mut self.nodes[slot as usize] {
                    *right = nr;
                    cache.set(None);
                }
                rm
            } else {
                let (nl, rm) = self.remove_at(l, key, depth + 1);
                if let Node::Internal { left, cache, .. } = &mut self.nodes[slot as usize] {
                    *left = nl;
                    cache.set(None);
                }
                rm
            };
            let (cl, cr) = match &self.nodes[slot as usize] {
                Node::Internal { left, right, .. } => (*left, *right),
                _ => (NIL, NIL),
            };
            (self.collapse(slot, cl, cr), removed)
        }
    }

    /// Collapse an internal `slot` after a child changed: a single leaf child
    /// replaces the internal; an all-empty internal becomes empty. A single
    /// *internal* child is kept wrapped (matches the boxed `collapse`).
    fn collapse(&mut self, slot: NodeIdx, left: NodeIdx, right: NodeIdx) -> NodeIdx {
        let l_leaf = left != NIL && matches!(self.nodes[left as usize], Node::Leaf { .. });
        let r_leaf = right != NIL && matches!(self.nodes[right as usize], Node::Leaf { .. });
        match (left, right) {
            (NIL, NIL) => {
                self.free_slot(slot);
                NIL
            }
            (l, NIL) if l_leaf => {
                self.free_slot(slot);
                l
            }
            (NIL, r) if r_leaf => {
                self.free_slot(slot);
                r
            }
            _ => slot,
        }
    }

    /// Apply a batch of `(key, Option<value>)` updates (`None` = delete).
    pub fn apply_batch(&mut self, updates: &[(Hash, Option<Vec<u8>>)]) {
        for (key, value) in updates {
            match value {
                Some(v) => self.insert(*key, v),
                None => {
                    self.remove(key);
                }
            }
        }
    }

    /// Look up a key's value hash.
    pub fn get(&self, key: &Hash) -> Option<Hash> {
        let mut idx = self.root;
        let mut depth = self.base_depth;
        loop {
            if idx == NIL {
                return None;
            }
            match &self.nodes[idx as usize] {
                Node::Leaf {
                    key: ek,
                    value_hash,
                } => return if ek == key { Some(*value_hash) } else { None },
                Node::Internal { left, right, .. } => {
                    idx = if bit(key, depth) { *right } else { *left };
                    depth += 1;
                }
            }
        }
    }

    /// Generate an inclusion/exclusion proof for `key`.
    pub fn prove(&self, key: Hash) -> BmtProof {
        let mut siblings = Vec::new();
        let mut idx = self.root;
        let mut depth = self.base_depth;
        loop {
            if idx == NIL {
                return BmtProof {
                    key,
                    value_hash: None,
                    siblings,
                    other_leaf: None,
                };
            }
            let (is_leaf, ek, ev, l, r) = match &self.nodes[idx as usize] {
                Node::Leaf { key, value_hash } => (true, *key, *value_hash, NIL, NIL),
                Node::Internal { left, right, .. } => {
                    (false, EMPTY_HASH, EMPTY_HASH, *left, *right)
                }
            };
            if is_leaf {
                return if ek == key {
                    BmtProof {
                        key,
                        value_hash: Some(ev),
                        siblings,
                        other_leaf: None,
                    }
                } else {
                    BmtProof {
                        key,
                        value_hash: None,
                        siblings,
                        other_leaf: Some((ek, ev)),
                    }
                };
            }
            if bit(&key, depth) {
                siblings.push(self.node_hash(l));
                idx = r;
            } else {
                siblings.push(self.node_hash(r));
                idx = l;
            }
            depth += 1;
        }
    }
}

/// An inclusion or exclusion proof for a single key within one shard's tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BmtProof {
    pub key: Hash,
    pub value_hash: Option<Hash>,
    /// Sibling hashes, top-down (root → leaf).
    pub siblings: Vec<Hash>,
    pub other_leaf: Option<(Hash, Hash)>,
}

impl BmtProof {
    /// Whether this is an inclusion proof.
    pub fn is_inclusion(&self) -> bool {
        self.value_hash.is_some()
    }

    /// Number of sibling hashes on the authentication path (= proof depth).
    pub fn path_len(&self) -> usize {
        self.siblings.len()
    }

    /// Estimated serialized size in bytes.
    pub fn encoded_len(&self) -> usize {
        32 + 1
            + if self.value_hash.is_some() { 32 } else { 0 }
            + 4
            + self.siblings.len() * 32
            + 1
            + if self.other_leaf.is_some() { 64 } else { 0 }
    }

    /// Verify the proof against a shard `root`, given the expected value hash.
    ///
    /// `base_depth` is the bit index the tree branches from (0 for a standalone
    /// [`Sbmt`]; `log2(SHARD_COUNT)` for an in-shard tree, where the shard
    /// selector prefix is skipped). The sibling at index `i` authenticates bit
    /// `base_depth + i`, and an exclusion proof's occupying leaf must share the
    /// full in-tree path prefix `[base_depth, base_depth + siblings.len())`.
    pub fn verify(
        &self,
        root: &Hash,
        expected_value_hash: Option<Hash>,
        base_depth: usize,
    ) -> bool {
        if self.value_hash != expected_value_hash {
            return false;
        }
        let mut cur = match (self.value_hash, self.other_leaf) {
            (Some(vh), None) => hash_leaf(&self.key, &vh),
            (None, None) => EMPTY_HASH,
            (None, Some((ok, ovh))) => {
                // The occupying leaf MUST be a different key. Otherwise a present
                // key K could be passed off as absent by reusing its own leaf
                // (key=K, value_hash=None, other_leaf=Some((K, V))): the fold would
                // reach the real root and a forged exclusion proof would verify.
                if ok == self.key {
                    return false;
                }
                if !shares_prefix_range(&self.key, &ok, base_depth, self.siblings.len()) {
                    return false;
                }
                hash_leaf(&ok, &ovh)
            }
            (Some(_), Some(_)) => return false,
        };
        for i in (0..self.siblings.len()).rev() {
            let sib = self.siblings[i];
            let depth = base_depth + i;
            cur = if bit(&self.key, depth) {
                hash_internal(&sib, &cur)
            } else {
                hash_internal(&cur, &sib)
            };
        }
        cur == *root
    }
}

/// Whether `a` and `b` agree on bits `[base, base + len)`.
#[inline]
fn shares_prefix_range(a: &Hash, b: &Hash, base: usize, len: usize) -> bool {
    (base..base + len).all(|d| bit(a, d) == bit(b, d))
}

// ---------------------------------------------------------------------------
// Shard-root commitment: depth-4 binary merkle over the 16 shard roots.
// ---------------------------------------------------------------------------

#[inline]
fn hash_pair(a: &Hash, b: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(a);
    h.update(b);
    *h.finalize().as_bytes()
}

/// Merkle root over the shard roots (16 → 8 → 4 → 2 → 1, depth 4).
pub fn shard_tree_root(leaves: &[Hash]) -> Hash {
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| hash_pair(&c[0], &c[1])).collect();
    }
    level[0]
}

/// Authentication path (siblings, bottom-up) from `index` to the shard-tree root.
pub fn shard_tree_path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    let mut path = Vec::new();
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        path.push(level[idx ^ 1]);
        level = level.chunks(2).map(|c| hash_pair(&c[0], &c[1])).collect();
        idx >>= 1;
    }
    path
}

/// Recompute the shard-tree root from a leaf shard root + its authentication path.
pub fn shard_tree_root_from_path(leaf: Hash, index: usize, path: &[Hash]) -> Hash {
    let mut cur = leaf;
    let mut idx = index;
    for sib in path {
        cur = if idx & 1 == 0 {
            hash_pair(&cur, sib)
        } else {
            hash_pair(sib, &cur)
        };
        idx >>= 1;
    }
    cur
}

/// Verification error for [`ShardedBmtProof`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BmtVerifyError {
    #[error("shard index {0} out of range (max 15)")]
    ShardIndexOutOfRange(u8),
    #[error("proof leaf key does not match the queried key")]
    KeyMismatch,
    #[error("shard index {got} does not match queried key's shard {expected}")]
    WrongShardForKey { expected: u8, got: u8 },
    #[error("combined root mismatch")]
    CombinedRootMismatch,
    #[error("malformed shard path length {len}, expected {expected}")]
    MalformedShardPath { len: usize, expected: usize },
    #[error("value does not match committed value hash")]
    ValueHashMismatch,
    #[error("in-shard proof verification failed")]
    InShardProofFailed,
}

/// A self-contained proof for a key in a sharded SBMT.
///
/// Carries the target shard root + its depth-4 shard-tree path, the in-shard
/// [`BmtProof`], and the raw value. Verifiable with only the block header's
/// combined state root — no tree access (this is what a mobile client runs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardedBmtProof {
    pub shard_index: u8,
    pub shard_root: Hash,
    pub shard_path: Vec<Hash>,
    pub inner: BmtProof,
    pub value: Option<Vec<u8>>,
}

impl ShardedBmtProof {
    /// Verify against a known combined root hash (`[u8; 32]`).
    pub fn verify(&self, combined_root: &Hash) -> Result<(), BmtVerifyError> {
        if self.shard_index as usize >= SHARD_COUNT {
            return Err(BmtVerifyError::ShardIndexOutOfRange(self.shard_index));
        }
        // The shard-tree is a fixed depth-log2(SHARD_COUNT) binary merkle, so the
        // authentication path must have exactly that many siblings. Reject any
        // other length explicitly (untrusted proof) rather than relying on the
        // root re-comparison below to catch a malformed fold.
        if self.shard_path.len() != SHARD_COUNT.trailing_zeros() as usize {
            return Err(BmtVerifyError::MalformedShardPath {
                len: self.shard_path.len(),
                expected: SHARD_COUNT.trailing_zeros() as usize,
            });
        }
        let computed =
            shard_tree_root_from_path(self.shard_root, self.shard_index as usize, &self.shard_path);
        if computed != *combined_root {
            return Err(BmtVerifyError::CombinedRootMismatch);
        }
        let expected_vh = self.value.as_ref().map(|v| hash_value(v));
        if self.inner.value_hash != expected_vh {
            return Err(BmtVerifyError::ValueHashMismatch);
        }
        // In-shard trees skip the shard-selector prefix (top `log2(SHARD_COUNT)`
        // bits), so the in-shard proof branches from that base depth.
        let base_depth = SHARD_COUNT.trailing_zeros() as usize;
        if !self.inner.verify(&self.shard_root, expected_vh, base_depth) {
            return Err(BmtVerifyError::InShardProofFailed);
        }
        Ok(())
    }

    /// Verify against a known combined root **and bind the proof to a queried
    /// key**.
    ///
    /// This is what an untrusted-server light client must use. [`verify`] only
    /// checks the proof is internally consistent with `combined_root`; it does
    /// NOT check that the proof concerns the key the client actually asked
    /// about. Without that binding a server can answer a query for key A with a
    /// valid proof for an unrelated key B, or forge a *non-membership* proof
    /// for A by presenting it against a shard where A is legitimately absent
    /// (A's real shard is fixed by `shard_index_for_key`). This method rejects
    /// both: the leaf key must equal `expected_key`, and `shard_index` must be
    /// `expected_key`'s shard.
    ///
    /// [`verify`]: Self::verify
    pub fn verify_for_key(
        &self,
        combined_root: &Hash,
        expected_key: &Hash,
    ) -> Result<(), BmtVerifyError> {
        if self.inner.key != *expected_key {
            return Err(BmtVerifyError::KeyMismatch);
        }
        let expected_shard = shard_index_for_key(expected_key);
        if self.shard_index as usize != expected_shard {
            return Err(BmtVerifyError::WrongShardForKey {
                expected: expected_shard as u8,
                got: self.shard_index,
            });
        }
        self.verify(combined_root)
    }

    /// Estimated serialized size in bytes.
    pub fn estimated_size(&self) -> usize {
        1 + 32
            + 4
            + self.shard_path.len() * 32
            + self.inner.encoded_len()
            + self.value.as_ref().map_or(0, |v| v.len())
    }

    /// Bytes of the in-shard merkle authentication path.
    pub fn path_bytes(&self) -> usize {
        self.inner.path_len() * 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte: u8) -> Hash {
        [byte; 32]
    }

    fn key_from(seed: u64) -> Hash {
        *blake3::hash(&seed.to_le_bytes()).as_bytes()
    }

    #[test]
    fn empty_and_single() {
        let mut t = Sbmt::new();
        assert!(t.is_empty());
        assert_eq!(t.root_hash(), EMPTY_HASH);
        t.insert(k(0xAB), b"hello");
        assert_eq!(t.get(&k(0xAB)), Some(hash_value(b"hello")));
    }

    #[test]
    fn order_independent_root() {
        let keys: Vec<Hash> = (0..64).map(key_from).collect();
        let mut a = Sbmt::new();
        for (i, key) in keys.iter().enumerate() {
            a.insert(*key, &i.to_le_bytes());
        }
        let mut b = Sbmt::new();
        for (i, key) in keys.iter().enumerate().rev() {
            b.insert(*key, &i.to_le_bytes());
        }
        assert_eq!(a.root_hash(), b.root_hash());
    }

    #[test]
    fn delete_matches_fresh_build() {
        let keys: Vec<Hash> = (0..50).map(key_from).collect();
        let victim = keys[17];
        let mut full = Sbmt::new();
        for (i, key) in keys.iter().enumerate() {
            full.insert(*key, &i.to_le_bytes());
        }
        full.remove(&victim);
        let mut without = Sbmt::new();
        for (i, key) in keys.iter().enumerate() {
            if *key != victim {
                without.insert(*key, &i.to_le_bytes());
            }
        }
        assert_eq!(full.root_hash(), without.root_hash());
    }

    #[test]
    fn bmt_proof_inclusion_exclusion() {
        let mut t = Sbmt::new();
        for i in 0..100u64 {
            t.insert(key_from(i), &i.to_le_bytes());
        }
        let root = t.root_hash();
        let key = key_from(42);
        let vh = hash_value(&42u64.to_le_bytes());
        assert!(t.prove(key).verify(&root, Some(vh), 0));
        assert!(t.prove(key_from(99999)).verify(&root, None, 0));
    }

    #[test]
    fn forged_exclusion_proof_rejected() {
        // K is present; reuse its own leaf to forge an absence proof.
        let mut t = Sbmt::new();
        for i in 0..50u64 {
            t.insert(key_from(i), &i.to_le_bytes());
        }
        let root = t.root_hash();
        let key = key_from(7);
        let vh = hash_value(&7u64.to_le_bytes());
        let incl = t.prove(key);
        assert!(
            incl.verify(&root, Some(vh), 0),
            "real inclusion must verify"
        );

        let forged = BmtProof {
            key,
            value_hash: None,
            siblings: incl.siblings.clone(),
            other_leaf: Some((key, vh)),
        };
        assert!(
            !forged.verify(&root, None, 0),
            "exclusion proof reusing the key's own leaf must be rejected"
        );
    }

    #[test]
    fn base_depth_prefix_skip_inclusion_and_exclusion() {
        // All keys share the top nibble (shard 0xA); a base_depth=4 tree skips it.
        let base = 4usize;
        let mut t = Sbmt::with_base_depth(base);
        let mk = |i: u64| {
            let mut k = key_from(i);
            k[0] = 0xA0 | (k[0] & 0x0F); // force top nibble = 0xA
            k
        };
        for i in 0..200u64 {
            t.insert(mk(i), &i.to_le_bytes());
        }
        let root = t.root_hash();

        // Inclusion verifies with the correct base_depth, and FAILS with a wrong one.
        let key = mk(123);
        let vh = hash_value(&123u64.to_le_bytes());
        let incl = t.prove(key);
        assert!(
            incl.verify(&root, Some(vh), base),
            "inclusion @base_depth must verify"
        );
        assert!(
            !incl.verify(&root, Some(vh), 0),
            "verifying with the wrong base_depth must fail"
        );

        // Exclusion of an absent (but same-shard-prefix) key verifies.
        let absent = mk(999999);
        let excl = t.prove(absent);
        assert!(excl.value_hash.is_none());
        assert!(
            excl.verify(&root, None, base),
            "exclusion @base_depth must verify"
        );
    }

    #[test]
    fn shard_tree_path_roundtrip() {
        let leaves: Vec<Hash> = (0..SHARD_COUNT as u64).map(key_from).collect();
        let root = shard_tree_root(&leaves);
        for i in 0..SHARD_COUNT {
            let path = shard_tree_path(&leaves, i);
            assert_eq!(path.len(), 4, "depth-4 tree");
            assert_eq!(shard_tree_root_from_path(leaves[i], i, &path), root);
        }
    }
}

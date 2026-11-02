// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's binary Merkle tree (`lib/bmt`, sequential `Put`/`Delete`), the
//! accumulator the mobile registry anchors on chain.
//!
//! - leaf: bytes `'L'(0x4C) ‖ keyHash32 ‖ value`, hash `blake3(0x00 ‖ bytes)`;
//! - internal: `blake3(left32 ‖ right32)`, an empty child is 32 zero bytes;
//! - the path is the key hash's bits, MSB first; a single leaf is its own
//!   root; a split of two leaves sharing a prefix makes a chain of internals
//!   with empty siblings (no path compression);
//! - delete collapses an internal whose children are one leaf and one empty;
//! - the empty tree's root is all zeros.
//!
//! This is not `n42-bmt-core`, whose leaf hashing differs. gov5's `PutBatch`
//! builds a different (compressed) shape and is not what the registry uses.
//!
//! The tree is held structurally (no content-addressed store), so updates
//! leave no garbage behind.

use alloy_primitives::B256;

/// Tag byte of a serialised leaf.
const LEAF_TAG: u8 = 0x4C;

/// One subtree.
#[derive(Debug, Clone, Default)]
enum Node {
    #[default]
    Empty,
    Leaf {
        key: B256,
        value: Vec<u8>,
        hash: B256,
    },
    Internal {
        left: Box<Self>,
        right: Box<Self>,
        hash: B256,
    },
}

impl Node {
    const fn hash(&self) -> B256 {
        match self {
            Self::Empty => B256::ZERO,
            Self::Leaf { hash, .. } | Self::Internal { hash, .. } => *hash,
        }
    }

    fn leaf(key: B256, value: Vec<u8>) -> Self {
        let hash = leaf_hash(&key, &value);
        Self::Leaf { key, value, hash }
    }

    fn internal(left: Self, right: Self) -> Self {
        let hash = node_hash(&left.hash(), &right.hash());
        Self::Internal { left: Box::new(left), right: Box::new(right), hash }
    }

    const fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf { .. })
    }

    const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// `HashLeaf(encodeLeafValue(key, value))`: `blake3(0x00 ‖ 'L' ‖ key ‖ value)`.
pub fn leaf_hash(key: &B256, value: &[u8]) -> B256 {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00, LEAF_TAG]);
    h.update(key.as_slice());
    h.update(value);
    B256::from(*h.finalize().as_bytes())
}

/// `HashNode(left, right)`: `blake3(left ‖ right)`.
pub fn node_hash(left: &B256, right: &B256) -> B256 {
    let mut h = blake3::Hasher::new();
    h.update(left.as_slice());
    h.update(right.as_slice());
    B256::from(*h.finalize().as_bytes())
}

/// `HashKey(key)`: `blake3(key)`, the path a key takes.
pub fn key_hash(key: &[u8]) -> B256 {
    B256::from(*blake3::hash(key).as_bytes())
}

/// Bit `i` of the path, MSB of byte 0 first.
fn bit(key: &B256, i: usize) -> u8 {
    if i >= 256 {
        return 0;
    }
    (key[i / 8] >> (7 - (i % 8))) & 1
}

/// The key is not in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("bmt: not found")]
pub struct NotFound;

/// gov5's BMT over 32-byte key hashes.
#[derive(Debug, Clone, Default)]
pub struct Accumulator {
    root: Node,
    len: usize,
}

impl Accumulator {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// The root hash; all zeros for an empty tree.
    pub const fn root(&self) -> B256 {
        self.root.hash()
    }

    /// Number of keys held.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree holds no key.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The value stored under `key`.
    pub fn get(&self, key: &B256) -> Option<&[u8]> {
        let mut node = &self.root;
        let mut depth = 0;
        loop {
            match node {
                Node::Empty => return None,
                Node::Leaf { key: k, value, .. } => return (k == key).then_some(value.as_slice()),
                Node::Internal { left, right, .. } => {
                    node = if bit(key, depth) == 0 { left } else { right };
                    depth += 1;
                }
            }
        }
    }

    /// Inserts or replaces `key` (gov5 `Tree.Put`).
    pub fn put(&mut self, key: B256, value: Vec<u8>) {
        let existed = self.get(&key).is_some();
        let root = std::mem::take(&mut self.root);
        self.root = insert(root, key, Node::leaf(key, value), 0);
        if !existed {
            self.len += 1;
        }
    }

    /// Removes `key` (gov5 `Tree.Delete`).
    pub fn delete(&mut self, key: &B256) -> Result<(), NotFound> {
        if self.get(key).is_none() {
            return Err(NotFound);
        }
        let root = std::mem::take(&mut self.root);
        self.root = remove(root, key, 0);
        self.len -= 1;
        Ok(())
    }
}

fn insert(node: Node, key: B256, leaf: Node, depth: usize) -> Node {
    match node {
        Node::Empty => leaf,
        Node::Leaf { key: existing, value, hash } => {
            if existing == key {
                return leaf;
            }
            split(Node::Leaf { key: existing, value, hash }, existing, leaf, key, depth)
        }
        Node::Internal { left, right, .. } => {
            if bit(&key, depth) == 0 {
                Node::internal(insert(*left, key, leaf, depth + 1), *right)
            } else {
                Node::internal(*left, insert(*right, key, leaf, depth + 1))
            }
        }
    }
}

/// gov5 `splitLeaves`: two leaves under one slot, descending until their
/// paths differ.
fn split(existing: Node, existing_key: B256, new: Node, new_key: B256, depth: usize) -> Node {
    if depth >= 256 {
        return new;
    }
    let e = bit(&existing_key, depth);
    let n = bit(&new_key, depth);
    if e != n {
        return if n == 0 { Node::internal(new, existing) } else { Node::internal(existing, new) };
    }
    let child = split(existing, existing_key, new, new_key, depth + 1);
    if e == 0 { Node::internal(child, Node::Empty) } else { Node::internal(Node::Empty, child) }
}

/// gov5 `remove`; the caller has checked that `key` is present.
fn remove(node: Node, key: &B256, depth: usize) -> Node {
    match node {
        Node::Empty | Node::Leaf { .. } => Node::Empty,
        Node::Internal { left, right, .. } => {
            let (l, r) = if bit(key, depth) == 0 {
                (remove(*left, key, depth + 1), *right)
            } else {
                (*left, remove(*right, key, depth + 1))
            };
            if l.is_empty() && r.is_empty() {
                return Node::Empty;
            }
            if l.is_empty() && r.is_leaf() {
                return r;
            }
            if r.is_empty() && l.is_leaf() {
                return l;
            }
            Node::internal(l, r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kh(i: u64) -> B256 {
        key_hash(&i.to_be_bytes())
    }

    #[test]
    fn empty_and_single() {
        let mut t = Accumulator::new();
        assert_eq!(t.root(), B256::ZERO);
        let k = kh(1);
        t.put(k, 7u64.to_be_bytes().to_vec());
        assert_eq!(t.root(), leaf_hash(&k, &7u64.to_be_bytes()));
        assert_eq!(t.get(&k), Some(&7u64.to_be_bytes()[..]));
        t.delete(&k).unwrap();
        assert_eq!(t.root(), B256::ZERO);
        assert_eq!(t.delete(&k), Err(NotFound));
    }

    #[test]
    fn split_chain_has_empty_siblings() {
        // Two keys that share the first bit 0 and differ at bit 1.
        let a = B256::repeat_byte(0x00);
        let mut b = B256::repeat_byte(0x00);
        b[0] = 0x40;
        let mut t = Accumulator::new();
        t.put(a, vec![1]);
        t.put(b, vec![2]);
        let la = leaf_hash(&a, &[1]);
        let lb = leaf_hash(&b, &[2]);
        let inner = node_hash(&la, &lb);
        assert_eq!(t.root(), node_hash(&inner, &B256::ZERO));
        // Delete collapses the chain back to the remaining leaf.
        t.delete(&a).unwrap();
        assert_eq!(t.root(), lb);
    }

    #[test]
    fn order_independent_and_delete_inverse() {
        let keys: Vec<B256> = (0..64).map(kh).collect();
        let mut fwd = Accumulator::new();
        for (i, k) in keys.iter().enumerate() {
            fwd.put(*k, (i as u64).to_be_bytes().to_vec());
        }
        let mut rev = Accumulator::new();
        for (i, k) in keys.iter().enumerate().rev() {
            rev.put(*k, (i as u64).to_be_bytes().to_vec());
        }
        assert_eq!(fwd.root(), rev.root());
        assert_eq!(fwd.len(), 64);

        let mut half = Accumulator::new();
        for (i, k) in keys.iter().enumerate().take(32) {
            half.put(*k, (i as u64).to_be_bytes().to_vec());
        }
        for k in &keys[32..] {
            fwd.delete(k).unwrap();
        }
        assert_eq!(fwd.root(), half.root());
    }

    #[test]
    fn replace_changes_root() {
        let mut t = Accumulator::new();
        t.put(kh(1), vec![1]);
        t.put(kh(2), vec![2]);
        let r = t.root();
        t.put(kh(2), vec![3]);
        assert_ne!(t.root(), r);
        assert_eq!(t.len(), 2);
    }
}

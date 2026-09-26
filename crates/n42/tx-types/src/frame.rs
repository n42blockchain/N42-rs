// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frames: the ingest's unit of transactions (500 at the bench tier), named
//! by a binary Merkle root over their transactions' hashes.
//!
//! `docs/BREAKTHROUGH_DESIGN.md` step 1. Every node receives the same frames
//! and computes each frame's root once, at admission; the root is the
//! frame's id. A frame-aligned block's transactions root is the same binary
//! Merkle construction over its frames' roots ([`frame_tree_root`]), so a
//! follower that holds the frames checks a 163,000-transaction body with a
//! ~326-leaf tree instead of a 163,000-leaf trie.
//!
//! The construction ([`binary_merkle_root`]):
//! - the empty list is `keccak256("")`;
//! - a single node is its own root;
//! - otherwise each level pairs neighbours as `keccak256(left || right)`,
//!   an odd last node paired with itself (`keccak256(last || last)`), until
//!   one node is left.

use alloy_primitives::{keccak256, B256};

/// The binary Merkle root over `leaves`, keccak256 throughout; see the
/// module documentation for the rule.
pub fn binary_merkle_root(leaves: &[B256]) -> B256 {
    match leaves {
        [] => keccak256([]),
        [only] => *only,
        _ => {
            let mut level: Vec<B256> = leaves.to_vec();
            let mut pair = [0u8; 64];
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len().div_ceil(2));
                for chunk in level.chunks(2) {
                    let left = chunk[0];
                    let right = chunk.get(1).copied().unwrap_or(left);
                    pair[..32].copy_from_slice(left.as_slice());
                    pair[32..].copy_from_slice(right.as_slice());
                    next.push(keccak256(pair));
                }
                level = next;
            }
            level[0]
        }
    }
}

/// A frame's root, and so its id: the binary Merkle root over its
/// transactions' hashes in frame order.
///
/// A block whose last frame is truncated to a prefix roots that frame over
/// the prefix's hashes alone -- `frame_root(&hashes[..prefix])` -- which is
/// not the frame's id; the id still names the whole frame.
pub fn frame_root(tx_hashes: &[B256]) -> B256 {
    binary_merkle_root(tx_hashes)
}

/// A frame-aligned block's transactions root: the binary Merkle root over
/// its frames' roots, in block order (the last one over the prefix it
/// carries, see [`frame_root`]).
pub fn frame_tree_root(frame_roots: &[B256]) -> B256 {
    binary_merkle_root(frame_roots)
}

/// The frame tree over a body laid out as frames: `layout` is each frame's
/// length in the body, in order. `None` when the layout does not cover the
/// body exactly or names an empty frame, i.e. the body is not frame-aligned
/// by that layout.
pub fn frame_tree_root_of(tx_hashes: &[B256], layout: &[usize]) -> Option<B256> {
    if layout.iter().any(|len| *len == 0) || layout.iter().sum::<usize>() != tx_hashes.len() {
        return None;
    }
    let mut at = 0usize;
    let mut roots = Vec::with_capacity(layout.len());
    for len in layout {
        roots.push(frame_root(&tx_hashes[at..at + len]));
        at += len;
    }
    Some(frame_tree_root(&roots))
}

/// `N42_FRAME_BLOCKS=1`, read once: this node builds, describes and checks
/// frame-aligned blocks (phase B of step 1). Meaningful only on a chain whose
/// genesis sets `frameBlocks`; the execution layer refuses to start with it
/// on any other.
pub fn frame_blocks_requested() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FRAME_BLOCKS").is_ok_and(|v| v == "1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> B256 {
        keccak256([i])
    }

    fn node(left: B256, right: B256) -> B256 {
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(left.as_slice());
        pair[32..].copy_from_slice(right.as_slice());
        keccak256(pair)
    }

    #[test]
    fn the_frame_root_follows_the_rule() {
        assert_eq!(frame_root(&[]), keccak256([]));
        assert_eq!(frame_root(&[leaf(0)]), leaf(0));
        assert_eq!(frame_root(&[leaf(0), leaf(1)]), node(leaf(0), leaf(1)));
        // Three leaves: the odd last one is hashed with itself.
        let three = node(node(leaf(0), leaf(1)), node(leaf(2), leaf(2)));
        assert_eq!(frame_root(&[leaf(0), leaf(1), leaf(2)]), three);
        // Five: the odd node is paired with itself at every level it is odd.
        let five = node(
            node(node(leaf(0), leaf(1)), node(leaf(2), leaf(3))),
            node(node(leaf(4), leaf(4)), node(leaf(4), leaf(4))),
        );
        assert_eq!(frame_root(&(0..5).map(leaf).collect::<Vec<_>>()), five);
    }

    /// Pinned bytes, so a change of construction cannot pass as a refactor:
    /// leaves are `keccak256([i])` for i in 0..3.
    #[test]
    fn the_frame_root_vector() {
        let root = frame_root(&[leaf(0), leaf(1), leaf(2)]);
        assert_eq!(
            root.to_string(),
            "0xda965b3735d18da2dc9567c85f04f64c4df7e15e2f9cc1796aba0a583bf8d9aa"
        );
    }

    #[test]
    fn a_layout_must_cover_the_body() {
        let hashes: Vec<B256> = (0..7).map(leaf).collect();
        let expected = frame_tree_root(&[
            frame_root(&hashes[..3]),
            frame_root(&hashes[3..6]),
            frame_root(&hashes[6..]),
        ]);
        assert_eq!(frame_tree_root_of(&hashes, &[3, 3, 1]), Some(expected));
        assert_eq!(frame_tree_root_of(&hashes, &[3, 3]), None);
        assert_eq!(frame_tree_root_of(&hashes, &[3, 0, 3, 1]), None);
    }
}

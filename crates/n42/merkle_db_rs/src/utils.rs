// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{Digest, Sha256};
use tree_hash::Hash256;

pub fn tree_height(n_leaves: usize) -> usize {
    if n_leaves <= 1 {
        return 0;
    }

    let mut height = 0;
    let mut size = 1;

    while size < n_leaves {
        size <<= 1; // multiply by 2
        height += 1;
    }

    height
}

/// Compute the Merkle root of an all-zero SSZ-style tree of `height`.
///
/// Height meaning:
/// - 0 → leaf: zero hash
/// - n → hash upward n times (H(node || node))
pub fn zero_tree_root(height: usize) -> Hash256 {
    let mut node = [0u8; 32];

    for _ in 0..height {
        let mut h = Sha256::new();
        h.update(node.as_ref()); // left
        h.update(node.as_ref()); // right
        node = h.finalize().into();
    }

    Hash256::from(node)
}

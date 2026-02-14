use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use tree_hash::Hash256;

pub fn tree_height(n_leaves: usize) -> usize {
    if n_leaves <= 1 {
        return 0;
    }

    let mut height = 0;
    let mut size = 1;

    while size < n_leaves {
        size <<= 1;    // multiply by 2
        height += 1;
    }

    height
}

/// Maximum precomputed zero tree height (sufficient for all practical tree sizes).
const MAX_CACHED_HEIGHT: usize = 64;

/// Precomputed zero tree roots for heights 0..=MAX_CACHED_HEIGHT.
static ZERO_TREE_ROOTS: LazyLock<Vec<Hash256>> = LazyLock::new(|| {
    let mut roots = Vec::with_capacity(MAX_CACHED_HEIGHT + 1);
    let mut node = [0u8; 32];
    roots.push(Hash256::from(node));

    for _ in 1..=MAX_CACHED_HEIGHT {
        let mut h = Sha256::new();
        h.update(node.as_ref());
        h.update(node.as_ref());
        node = h.finalize().into();
        roots.push(Hash256::from(node));
    }

    roots
});

/// Compute the Merkle root of an all-zero SSZ-style tree of `height`.
///
/// Height meaning:
/// - 0 → leaf: zero hash
/// - n → hash upward n times (H(node || node))
///
/// Results are cached for heights 0..=64. Heights beyond that are computed on the fly.
pub fn zero_tree_root(height: usize) -> Hash256 {
    if height <= MAX_CACHED_HEIGHT {
        return ZERO_TREE_ROOTS[height];
    }

    // Fallback for extremely large heights (should never happen in practice)
    let mut node = [0u8; 32];
    for _ in 0..height {
        let mut h = Sha256::new();
        h.update(node.as_ref());
        h.update(node.as_ref());
        node = h.finalize().into();
    }
    Hash256::from(node)
}

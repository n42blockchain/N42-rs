// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::{Display, Error as FmtError, Formatter};
use tree_hash::Hash256;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    VecLenTooLarge {
        vec_len: u64,
        limit: u64,
    },
    OutOfBoundsUpdate {
        index: u64,
        len: u64,
    },

    /// Found a `Tree::Zero` node with an unexpected height.
    /// This indicates an inconsistent or corrupt tree state.
    InconsistentTreeZeroHeightMismatch {
        expected: usize,
        found: usize,
        hash: Hash256,
    },

    /// Found a `Tree::Leaf` at a non-zero height during traversal.
    /// This indicates an inconsistent or corrupt tree state.
    InconsistentTreeLeafAtNonZeroHeight {
        height: usize,
        hash: Hash256,
    },

    /// Traversed to a hash that is not in the `kv` map and is not
    /// a known `zero_tree_root`. This indicates an inconsistent
    /// or corrupt tree state.
    InconsistentTreeMissingNode {
        height: usize,
        hash: Hash256,
    },

    /// Called `try_pop` on a non-empty `VecTree` but the popped
    /// leaf was a `Zero` (empty) slot.
    PoppedEmptySlot {
        index: u64,
    },

    /// Found a `Tree::Node` or `Tree::Zero(h>0)` at height 0 during traversal.
    /// At height 0, we should only find `Tree::Leaf` or `Tree::Zero(0)`.
    InconsistentTreeNonLeafAtZeroHeight {
        hash: Hash256,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

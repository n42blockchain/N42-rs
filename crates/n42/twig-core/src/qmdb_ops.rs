// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A block's QMDB leaf operations in one arena.
//!
//! [`QmdbOperation`] owns its value, so a block of 163,000 operations is
//! 163,000 allocations -- built on the root job, kept in the forest's record
//! of the block, and freed when the record leaves the window: 4.5 million
//! `free`s for a persistence batch of 28 blocks, beside the build's threads
//! allocating (BREAKTHROUGH_DESIGN 10.38-10.39). [`QmdbOps`] keeps the same
//! operations as two vectors -- every value in one byte buffer, and a key with
//! the value's span per operation -- so building a block's operations is a
//! handful of allocations and dropping them is two `free`s.

use crate::qmdb_compat::QmdbOperation;
use crate::Hash;

/// The span `len` of a deletion (`value: None`).
const DELETE: usize = usize::MAX;

#[derive(Debug, Clone, Copy)]
struct OpSpan {
    key: Hash,
    /// Where the value starts in [`QmdbOps::values`]; unused for a deletion.
    start: usize,
    /// The value's length, or [`DELETE`].
    len: usize,
}

/// A block's leaf operations: the keys with each value's span, and every
/// value in one buffer. The same operations as a `Vec<QmdbOperation>`
/// ([`Self::to_operations`], `From`), in two allocations.
#[derive(Clone, Default)]
pub struct QmdbOps {
    ops: Vec<OpSpan>,
    values: Vec<u8>,
    /// Known to be in key order: set by [`Self::sort`] and by a merge of two
    /// sorted sets, cleared by anything that adds operations. Lets
    /// [`Self::is_sorted`] answer without a pass over the keys (the root's
    /// path asked twice a block, ~190,000 32-byte compares each).
    sorted: bool,
}

impl QmdbOps {
    /// No operations.
    pub const fn new() -> Self {
        Self { ops: Vec::new(), values: Vec::new(), sorted: false }
    }

    /// Room for `ops` operations whose values total `value_bytes`.
    pub fn with_capacity(ops: usize, value_bytes: usize) -> Self {
        Self { ops: Vec::with_capacity(ops), values: Vec::with_capacity(value_bytes), sorted: false }
    }

    /// How many operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The bytes every value holds together.
    pub fn value_bytes(&self) -> usize {
        self.values.len()
    }

    /// Appends an operation: `Some` writes the value, `None` deletes the key.
    pub fn push(&mut self, key: Hash, value: Option<&[u8]>) {
        match value {
            Some(value) => self.push_with(key, |out| out.extend_from_slice(value)),
            None => {
                self.sorted = false;
                self.ops.push(OpSpan { key, start: self.values.len(), len: DELETE });
            }
        }
    }

    /// Appends a write whose value `write` appends to the buffer it is given
    /// (the arena itself: no allocation for the value).
    pub fn push_with(&mut self, key: Hash, write: impl FnOnce(&mut Vec<u8>)) {
        let start = self.values.len();
        write(&mut self.values);
        // A closure can only grow the buffer; saturating keeps a misbehaving
        // one from producing a span that is not in it.
        let len = self.values.len().saturating_sub(start);
        self.sorted = false;
        self.ops.push(OpSpan { key, start, len });
    }

    /// The `index`th operation's key.
    pub fn key(&self, index: usize) -> Option<&Hash> {
        self.ops.get(index).map(|op| &op.key)
    }

    /// The `index`th operation: its key and its value (`None` for a deletion).
    pub fn get(&self, index: usize) -> Option<(&Hash, Option<&[u8]>)> {
        self.ops.get(index).map(|op| (&op.key, self.value_of(op)))
    }

    fn value_of(&self, op: &OpSpan) -> Option<&[u8]> {
        if op.len == DELETE {
            None
        } else {
            self.values.get(op.start..op.start + op.len)
        }
    }

    /// Every operation in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Hash, Option<&[u8]>)> + '_ {
        self.ops.iter().map(|op| (&op.key, self.value_of(op)))
    }

    /// Whether the keys are in ascending order.
    pub fn is_sorted(&self) -> bool {
        self.sorted || self.ops.is_sorted_by_key(|op| op.key)
    }

    /// Sorts the operations by key. Only the spans move; the values stay
    /// where they were written.
    pub fn sort(&mut self) {
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            self.ops.par_sort_unstable_by_key(|op| op.key);
        }
        #[cfg(not(feature = "rayon"))]
        {
            self.ops.sort_unstable_by_key(|op| op.key);
        }
        self.sorted = true;
    }

    /// Joins pieces built apart (a worker pool's chunks) into one, in order.
    pub fn concat(pieces: Vec<Self>) -> Self {
        let ops = pieces.iter().map(Self::len).sum();
        let bytes = pieces.iter().map(Self::value_bytes).sum();
        let mut out = Self::with_capacity(ops, bytes);
        for piece in pieces {
            let base = out.values.len();
            out.values.extend_from_slice(&piece.values);
            out.ops.extend(piece.ops.iter().map(|op| OpSpan { start: op.start + base, ..*op }));
        }
        out
    }

    /// `self` and `other`, both sorted by key, merged into one sorted set,
    /// leaving out every operation of `self` whose key is in `dropped`
    /// (sorted). One pass over the spans; `self`'s values stay where they
    /// are and `other`'s are appended after them. With keys unique across
    /// the two (a block's operations name each key once), the result is the
    /// operations of both, less the dropped ones, in the order [`Self::sort`]
    /// gives them.
    pub fn merge_sorted(mut self, other: Self, dropped: &[Hash]) -> Self {
        let both_sorted = self.is_sorted() && other.is_sorted();
        let base = self.values.len();
        self.values.extend_from_slice(&other.values);
        let mut ops = Vec::with_capacity(self.ops.len() + other.ops.len());
        let mut theirs = other.ops.iter().map(|op| OpSpan { start: op.start + base, ..*op }).peekable();
        let mut dropped = dropped.iter().peekable();
        for op in &self.ops {
            while dropped.next_if(|key| **key < op.key).is_some() {}
            if dropped.peek().is_some_and(|key| **key == op.key) {
                continue;
            }
            while let Some(next) = theirs.next_if(|next| next.key < op.key) {
                ops.push(next);
            }
            ops.push(*op);
        }
        ops.extend(theirs);
        self.ops = ops;
        self.sorted = both_sorted;
        self
    }

    /// The operations as owned [`QmdbOperation`]s, a value allocation apiece.
    pub fn to_operations(&self) -> Vec<QmdbOperation> {
        self.iter().map(|(key, value)| QmdbOperation { key: *key, value: value.map(<[u8]>::to_vec) }).collect()
    }
}

impl From<&[QmdbOperation]> for QmdbOps {
    fn from(operations: &[QmdbOperation]) -> Self {
        let bytes = operations.iter().map(|op| op.value.as_ref().map_or(0, Vec::len)).sum();
        let mut out = Self::with_capacity(operations.len(), bytes);
        for op in operations {
            out.push(op.key, op.value.as_deref());
        }
        out
    }
}

impl From<Vec<QmdbOperation>> for QmdbOps {
    fn from(operations: Vec<QmdbOperation>) -> Self {
        Self::from(operations.as_slice())
    }
}

impl FromIterator<QmdbOperation> for QmdbOps {
    fn from_iter<I: IntoIterator<Item = QmdbOperation>>(iter: I) -> Self {
        let mut out = Self::new();
        for op in iter {
            out.push(op.key, op.value.as_deref());
        }
        out
    }
}

impl PartialEq for QmdbOps {
    /// The same operations in the same order, wherever their values sit.
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for QmdbOps {}

impl std::fmt::Debug for QmdbOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbOps").field("ops", &self.ops.len()).field("value_bytes", &self.values.len()).finish()
    }
}

/// The operations a block apply reads: by index, key and value. Implemented
/// by a slice of [`QmdbOperation`]s and by [`QmdbOps`], so the tree applies
/// either without converting.
pub(crate) trait LeafOps: Sync {
    fn op_count(&self) -> usize;
    fn op_key(&self, index: usize) -> &Hash;
    fn op_value(&self, index: usize) -> Option<&[u8]>;
}

impl LeafOps for [QmdbOperation] {
    fn op_count(&self) -> usize {
        self.len()
    }

    fn op_key(&self, index: usize) -> &Hash {
        &self[index].key
    }

    fn op_value(&self, index: usize) -> Option<&[u8]> {
        self[index].value.as_deref()
    }
}

impl LeafOps for QmdbOps {
    fn op_count(&self) -> usize {
        self.ops.len()
    }

    fn op_key(&self, index: usize) -> &Hash {
        &self.ops[index].key
    }

    fn op_value(&self, index: usize) -> Option<&[u8]> {
        self.value_of(&self.ops[index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Hash {
        let mut k = [0u8; 32];
        k[0] = n.wrapping_mul(37);
        k[31] = n;
        k
    }

    fn sample() -> Vec<QmdbOperation> {
        (0..40u8)
            .map(|n| QmdbOperation {
                key: key(n),
                value: (n % 5 != 0).then(|| vec![n; (n % 9) as usize]),
            })
            .collect()
    }

    #[test]
    fn round_trips_through_the_owned_form() {
        let ops = sample();
        let arena = QmdbOps::from(ops.as_slice());
        assert_eq!(arena.len(), ops.len());
        assert_eq!(arena.to_operations(), ops);
        assert_eq!(arena.iter().filter(|(_, v)| v.is_some_and(<[u8]>::is_empty)).count(), 4, "empty values stay values");
        assert_eq!(arena.get(5), Some((&key(5), None)));
        assert_eq!(arena.get(40), None);
    }

    /// A sorted set merged with another, some of its keys dropped, equals the
    /// two joined, filtered and sorted.
    #[test]
    fn merge_sorted_equals_join_filter_sort() {
        let all = sample();
        for split in [0usize, 1, 17, 39, 40] {
            for drop_every in [0usize, 1, 3, 7] {
                let (mine, theirs) = all.split_at(split);
                let mut left = QmdbOps::from(mine);
                left.sort();
                let mut right = QmdbOps::from(theirs);
                right.sort();
                let mut dropped: Vec<Hash> = mine
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| drop_every != 0 && i % drop_every == 0)
                    .map(|(_, op)| op.key)
                    .collect();
                // A key that is not there is no harm.
                dropped.push([0xEE; 32]);
                dropped.sort_unstable();
                let mut expected: Vec<QmdbOperation> =
                    all.iter().filter(|op| !dropped.contains(&op.key) || theirs.contains(op)).cloned().collect();
                expected.sort_unstable_by_key(|op| op.key);
                let merged = left.merge_sorted(right, &dropped);
                assert!(merged.is_sorted(), "split {split}, drop {drop_every}");
                assert_eq!(merged.to_operations(), expected, "split {split}, drop {drop_every}");
            }
        }
    }

    #[test]
    fn sorts_and_joins_like_the_owned_form() {
        let mut ops = sample();
        let (a, b) = ops.split_at(17);
        let mut arena = QmdbOps::concat(vec![QmdbOps::from(a), QmdbOps::from(b), QmdbOps::new()]);
        assert_eq!(arena, QmdbOps::from(ops.as_slice()));
        assert!(!arena.is_sorted());
        arena.sort();
        ops.sort_unstable_by_key(|op| op.key);
        assert!(arena.is_sorted());
        assert_eq!(arena.to_operations(), ops);
        assert_eq!(ops.into_iter().collect::<QmdbOps>(), arena);
    }
}

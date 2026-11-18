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
use std::sync::{Arc, OnceLock};

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
    /// Identity of this immutable version, allocated only when hashes are
    /// cached. Clones share it until either copy is changed.
    identity: OnceLock<Arc<()>>,
}

impl QmdbOps {
    /// No operations.
    pub const fn new() -> Self {
        Self { ops: Vec::new(), values: Vec::new(), sorted: false, identity: OnceLock::new() }
    }

    /// Room for `ops` operations whose values total `value_bytes`.
    pub fn with_capacity(ops: usize, value_bytes: usize) -> Self {
        Self { ops: Vec::with_capacity(ops), values: Vec::with_capacity(value_bytes), sorted: false, identity: OnceLock::new() }
    }

    /// The retained identity of this immutable version for leaf-hash caches.
    pub(crate) fn identity(&self) -> &Arc<()> {
        self.identity.get_or_init(|| Arc::new(()))
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
                self.identity.take();
                self.sorted = false;
                self.ops.push(OpSpan { key, start: self.values.len(), len: DELETE });
            }
        }
    }

    /// Appends a write whose value `write` appends to the buffer it is given
    /// (the arena itself: no allocation for the value).
    pub fn push_with(&mut self, key: Hash, write: impl FnOnce(&mut Vec<u8>)) {
        self.identity.take();
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
        self.identity.take();
        #[cfg(feature = "rayon")]
        {
            if self.ops.len() >= PARALLEL_MIN {
                bucket_sort(&mut self.ops);
            } else {
                self.ops.sort_unstable_by_key(|op| op.key);
            }
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
        #[cfg(feature = "rayon")]
        if ops >= PARALLEL_MIN && pieces.len() > 1 {
            return Self::concat_parallel(&pieces, ops, bytes);
        }
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
        self.identity.take();
        let both_sorted = self.is_sorted() && other.is_sorted();
        let base = self.values.len();
        self.values.extend_from_slice(&other.values);
        let theirs: Vec<OpSpan> = other.ops.iter().map(|op| OpSpan { start: op.start + base, ..*op }).collect();
        // In chunks on the pool when every input is in order (the chunks
        // are cut by key, which needs the order); the same spans in the same
        // order as the one pass (`parallel_merge_equals_the_serial_one`).
        #[cfg(feature = "rayon")]
        if self.ops.len() >= PARALLEL_MIN && both_sorted && dropped.is_sorted() {
            self.ops = merge_spans_parallel(&self.ops, &theirs, dropped);
            self.sorted = true;
            return self;
        }
        let mut ops = Vec::with_capacity(self.ops.len() + theirs.len());
        merge_spans(&self.ops, &theirs, dropped, &mut ops);
        self.ops = ops;
        self.sorted = both_sorted;
        self
    }

    /// [`Self::concat`] on the pool: every piece's values and spans copied
    /// to their places beside the others'. The same arena as the serial join.
    #[cfg(feature = "rayon")]
    fn concat_parallel(pieces: &[Self], ops: usize, bytes: usize) -> Self {
        use rayon::prelude::*;
        let mut out = Self::with_capacity(ops, bytes);
        {
            let mut spans = &mut out.ops.spare_capacity_mut()[..ops];
            let mut values = &mut out.values.spare_capacity_mut()[..bytes];
            let mut jobs = Vec::with_capacity(pieces.len());
            let mut base = 0usize;
            for piece in pieces {
                let (piece_spans, rest) = std::mem::take(&mut spans).split_at_mut(piece.ops.len());
                spans = rest;
                let (piece_values, rest) = std::mem::take(&mut values).split_at_mut(piece.values.len());
                values = rest;
                jobs.push((piece, piece_spans, piece_values, base));
                base += piece.values.len();
            }
            jobs.into_par_iter().for_each(|(piece, spans, values, base)| {
                values.write_copy_of_slice(&piece.values);
                for (slot, op) in spans.iter_mut().zip(&piece.ops) {
                    slot.write(OpSpan { start: op.start + base, ..*op });
                }
            });
        }
        // SAFETY: the pieces' spans and values were cut from the first `ops`
        // spans and `bytes` bytes of spare capacity, in order and without a
        // gap (their lengths sum to `ops` and `bytes`), and every element of
        // each was written above; a panic in a piece leaves the lengths at 0.
        unsafe {
            out.ops.set_len(ops);
            out.values.set_len(bytes);
        }
        out
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

/// Operations from which the sort, the join and the merge use the pool.
#[cfg(feature = "rayon")]
const PARALLEL_MIN: usize = 16_384;

/// Spans a task of the bucket sort's and the merge's passes takes.
#[cfg(feature = "rayon")]
const SPAN_CHUNK: usize = 8_192;

/// The one-pass merge of [`QmdbOps::merge_sorted`] over spans: `mine` less
/// the keys in `dropped`, with `theirs` merged in, appended to `out`. Every
/// input sorted by key.
fn merge_spans(mine: &[OpSpan], theirs: &[OpSpan], dropped: &[Hash], out: &mut Vec<OpSpan>) {
    let mut theirs = theirs.iter().copied().peekable();
    let mut dropped = dropped.iter().peekable();
    for op in mine {
        while dropped.next_if(|key| **key < op.key).is_some() {}
        if dropped.peek().is_some_and(|key| **key == op.key) {
            continue;
        }
        while let Some(next) = theirs.next_if(|next| next.key < op.key) {
            out.push(next);
        }
        out.push(*op);
    }
    out.extend(theirs);
}

/// [`merge_spans`] in chunks of `mine` on the pool. A chunk `mine[a..b]`
/// takes the dropped keys and `theirs` from `mine[a]`'s key (inclusive;
/// the first chunk from the start) to `mine[b]`'s (exclusive; the last chunk
/// to the end): exactly what the one pass consumes between reaching `mine[a]`
/// and reaching `mine[b]`, so the chunks' outputs joined are its output.
#[cfg(feature = "rayon")]
fn merge_spans_parallel(mine: &[OpSpan], theirs: &[OpSpan], dropped: &[Hash]) -> Vec<OpSpan> {
    use rayon::prelude::*;
    let chunks = mine.len().div_ceil(SPAN_CHUNK);
    let pieces: Vec<Vec<OpSpan>> = (0..chunks)
        .into_par_iter()
        .map(|chunk| {
            let (a, b) = (chunk * SPAN_CHUNK, ((chunk + 1) * SPAN_CHUNK).min(mine.len()));
            let theirs_from = if a == 0 { 0 } else { theirs.partition_point(|t| t.key < mine[a].key) };
            let theirs_to = if b == mine.len() { theirs.len() } else { theirs.partition_point(|t| t.key < mine[b].key) };
            let dropped_from = if a == 0 { 0 } else { dropped.partition_point(|k| *k < mine[a].key) };
            let dropped_to = if b == mine.len() { dropped.len() } else { dropped.partition_point(|k| *k < mine[b].key) };
            let mut out = Vec::with_capacity(b - a + theirs_to.saturating_sub(theirs_from));
            merge_spans(
                &mine[a..b],
                &theirs[theirs_from..theirs_to.max(theirs_from)],
                &dropped[dropped_from..dropped_to.max(dropped_from)],
                &mut out,
            );
            out
        })
        .collect();
    join_spans(&pieces)
}

/// The pieces' spans one after another, copied on the pool.
#[cfg(feature = "rayon")]
fn join_spans(pieces: &[Vec<OpSpan>]) -> Vec<OpSpan> {
    use rayon::prelude::*;
    let total = pieces.iter().map(Vec::len).sum();
    let mut out: Vec<OpSpan> = Vec::with_capacity(total);
    {
        let mut rest = &mut out.spare_capacity_mut()[..total];
        let mut jobs = Vec::with_capacity(pieces.len());
        for piece in pieces {
            let (head, tail) = std::mem::take(&mut rest).split_at_mut(piece.len());
            rest = tail;
            jobs.push((piece, head));
        }
        jobs.into_par_iter().for_each(|(piece, out)| {
            out.write_copy_of_slice(piece);
        });
    }
    // SAFETY: the jobs' slices cut the first `total` spare elements in order
    // without a gap, and each was written whole from its piece.
    unsafe { out.set_len(total) };
    out
}

/// Sorts spans by key on the pool: a scatter into 256 buckets by the key's
/// first byte (counted per chunk, so each chunk writes its own ranges), then
/// each bucket sorted on its own. Keys are hashes, so the buckets are even.
/// With distinct keys -- a block's, always -- the order is the only sorted
/// one, the order `sort_unstable_by_key` gives.
#[cfg(feature = "rayon")]
fn bucket_sort(ops: &mut Vec<OpSpan>) {
    use rayon::prelude::*;
    const BUCKETS: usize = 256;
    let n = ops.len();
    let counts: Vec<[usize; BUCKETS]> = ops
        .par_chunks(SPAN_CHUNK)
        .map(|chunk| {
            let mut counts = [0usize; BUCKETS];
            for op in chunk {
                counts[op.key[0] as usize] += 1;
            }
            counts
        })
        .collect();
    let mut bounds = [0usize; BUCKETS + 1];
    let mut starts = vec![[0usize; BUCKETS]; counts.len()];
    let mut at = 0usize;
    for bucket in 0..BUCKETS {
        bounds[bucket] = at;
        for (chunk, counts) in counts.iter().enumerate() {
            starts[chunk][bucket] = at;
            at += counts[bucket];
        }
    }
    bounds[BUCKETS] = n;
    let mut out: Vec<OpSpan> = Vec::with_capacity(n);
    let dst = SpanPtr(out.as_mut_ptr());
    ops.par_chunks(SPAN_CHUNK).zip(starts.into_par_iter()).for_each(|(chunk, mut next)| {
        for op in chunk {
            let at = &mut next[op.key[0] as usize];
            // SAFETY: `*at < n` (inside the capacity reserved above), and the
            // prefix sums give every (chunk, bucket) its own range, so no two
            // writes, in this task or another, meet.
            unsafe { dst.at(*at).write(*op) };
            *at += 1;
        }
    });
    // SAFETY: the scatter wrote every position below `n` exactly once: the
    // ranges partition `0..n` and each chunk wrote its counts' worth.
    unsafe { out.set_len(n) };
    let mut rest = out.as_mut_slice();
    let mut buckets = Vec::with_capacity(BUCKETS);
    for bucket in 0..BUCKETS {
        let (head, tail) = std::mem::take(&mut rest).split_at_mut(bounds[bucket + 1] - bounds[bucket]);
        buckets.push(head);
        rest = tail;
    }
    buckets.into_par_iter().for_each(|bucket| bucket.sort_unstable_by_key(|op| op.key));
    *ops = out;
}

/// A span array shared by the scatter's tasks, each writing its own range.
#[cfg(feature = "rayon")]
#[derive(Clone, Copy)]
struct SpanPtr(*mut OpSpan);

#[cfg(feature = "rayon")]
impl SpanPtr {
    /// The `i`th element's place. A method, so closures capture the wrapper
    /// (which is `Sync`) and not its raw field.
    const fn at(self, i: usize) -> *mut OpSpan {
        self.0.wrapping_add(i)
    }
}

// SAFETY: used only for writes to disjoint positions of one allocation that
// outlives the parallel pass (`bucket_sort`).
#[cfg(feature = "rayon")]
unsafe impl Send for SpanPtr {}
// SAFETY: as above.
#[cfg(feature = "rayon")]
unsafe impl Sync for SpanPtr {}

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

    /// A deterministic xorshift for the large random sets below.
    struct Rng(u64);

    impl Rng {
        fn step(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn key(&mut self) -> Hash {
            let mut key = [0u8; 32];
            for word in key.chunks_mut(8) {
                word.copy_from_slice(&self.step().to_le_bytes());
            }
            key
        }
    }

    /// `n` operations with random distinct keys, a deletion every seventh.
    fn random_ops(rng: &mut Rng, n: usize) -> QmdbOps {
        let mut ops = QmdbOps::with_capacity(n, n * 8);
        for i in 0..n {
            let key = rng.key();
            if i % 7 == 3 {
                ops.push(key, None);
            } else {
                let len = (rng.step() % 40) as usize;
                ops.push_with(key, |out| out.extend((0..len).map(|b| (b as u8) ^ key[1])));
            }
        }
        ops
    }

    /// The arena exactly: spans (key, start, length) and the value bytes.
    fn arena(ops: &QmdbOps) -> (Vec<(Hash, usize, usize)>, Vec<u8>) {
        (ops.ops.iter().map(|op| (op.key, op.start, op.len)).collect(), ops.values.clone())
    }

    /// The pool's join, sort and merge (`PARALLEL_MIN` and up) leave the
    /// arena the serial ones leave, span for span and byte for byte: random
    /// pieces, a sort, and merges with dropped keys that are and are not
    /// there, their keys among the dropped ones (a replaced account), before
    /// and after every key, and empty sides.
    #[test]
    fn the_pools_join_sort_and_merge_equal_the_serial_ones() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for (pieces, per) in [(1usize, 40_000usize), (7, 5_000), (40, 1_024), (3, 0)] {
            let parts: Vec<QmdbOps> = (0..pieces).map(|_| random_ops(&mut rng, per)).collect();
            // The serial join, by hand.
            let mut serial = QmdbOps::new();
            for piece in &parts {
                let base = serial.values.len();
                serial.values.extend_from_slice(&piece.values);
                serial.ops.extend(piece.ops.iter().map(|op| OpSpan { start: op.start + base, ..*op }));
            }
            let mut joined = QmdbOps::concat(parts);
            assert_eq!(arena(&joined), arena(&serial), "join of {pieces} x {per}");
            let mut expected = serial.clone();
            expected.ops.sort_unstable_by_key(|op| op.key);
            joined.sort();
            assert!(joined.is_sorted());
            assert_eq!(arena(&joined), arena(&expected), "sort of {pieces} x {per}");

            for (theirs_n, drop_every) in [(0usize, 0usize), (5, 1000), (3_000, 97), (20_000, 5)] {
                let mut theirs = random_ops(&mut rng, theirs_n);
                // Replaced keys: in `mine`, dropped, and again in `theirs`.
                let mut dropped: Vec<Hash> = Vec::new();
                for (i, op) in joined.ops.iter().enumerate() {
                    if drop_every != 0 && i % drop_every == 0 {
                        dropped.push(op.key);
                        if i % 2 == 0 {
                            theirs.push(op.key, Some(&[7, 7]));
                        }
                    }
                }
                // Keys that are not there, and the extremes.
                dropped.extend([[0u8; 32], [0xFF; 32], rng.key()]);
                theirs.push([0u8; 32], Some(&[1]));
                theirs.push([0xFF; 32], None);
                dropped.sort_unstable();
                theirs.sort();
                let base = joined.values.len();
                let theirs_spans: Vec<OpSpan> = theirs.ops.iter().map(|op| OpSpan { start: op.start + base, ..*op }).collect();
                let mut serial_spans = Vec::new();
                merge_spans(&joined.ops, &theirs_spans, &dropped, &mut serial_spans);
                let mut serial_values = joined.values.clone();
                serial_values.extend_from_slice(&theirs.values);
                let merged = joined.clone().merge_sorted(theirs, &dropped);
                assert!(merged.is_sorted());
                assert_eq!(
                    arena(&merged),
                    (serial_spans.iter().map(|op| (op.key, op.start, op.len)).collect(), serial_values),
                    "merge of {pieces} x {per} with {theirs_n}, dropping every {drop_every}"
                );
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

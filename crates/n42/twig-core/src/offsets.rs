// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where each slot's record starts, readable outside the tree's lock
//! (`docs/QMDB_COMPACTION_DESIGN.md` 3.3, stage 1).
//!
//! The tree is the only writer: it appends, truncates and retargets slots under its own lock
//! (`&mut Offsets`). An [`OffsetsReader`] resolves a slot to its offset from any thread with
//! acquire loads and no lock, so a read view can index keys by slot -- a slot's identity is fixed
//! once the view holds it, while its record may move to `entries.relocated`.
//!
//! The layout keeps that sound without a reader epoch on the structure itself:
//!
//! - a fixed directory of segment pointers, sized for every slot a 40-bit index can name, so
//!   it is never reallocated under a reader;
//! - segments of [`OFFSET_SEGMENT_SLOTS`] `AtomicU64`s, published before the length that
//!   covers them, and never freed before the structure is: a truncation only lowers the length
//!   and keeps the segments for the appends that follow;
//! - the length is stored with release after the offsets it covers, and loaded with acquire.
//!
//! What a reader must not do is resolve a slot at or above the length it could see, or one the
//! tree may truncate while it reads: the read view's guards (`TruncationGuard`, its floor)
//! already keep it below both.

use std::sync::{
    atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use crate::prefault::{OFFSET_SEGMENT_BITS, OFFSET_SEGMENT_SLOTS};

/// Slots the directory can name: as many as the key index's 40-bit field.
const MAX_SLOTS: usize = 1 << 40;
/// Directory entries, one per segment.
const DIRECTORY_LEN: usize = MAX_SLOTS >> OFFSET_SEGMENT_BITS;
const MASK: usize = OFFSET_SEGMENT_SLOTS - 1;

/// The shared part: the directory, the segments it points at, and the length.
struct Inner {
    /// Segment `i` covers slots `i << OFFSET_SEGMENT_BITS ..`; null until first used.
    directory: Box<[AtomicPtr<AtomicU64>]>,
    /// Segments allocated (a prefix of the directory).
    segments: AtomicUsize,
    /// Slots that hold an offset.
    len: AtomicUsize,
}

impl Inner {
    fn new() -> Self {
        // A zeroed allocation: a null pointer is all zero bits, and the pages
        // of a directory mostly never touched are never faulted in.
        let directory = Box::<[AtomicPtr<AtomicU64>]>::new_zeroed_slice(DIRECTORY_LEN);
        // SAFETY: `AtomicPtr` is valid at all zero bits (null).
        let directory = unsafe { directory.assume_init() };
        Self { directory, segments: AtomicUsize::new(0), len: AtomicUsize::new(0) }
    }

    /// The segment of `slot`, which must be below the allocated segments.
    #[inline]
    fn segment(&self, slot: usize) -> &[AtomicU64] {
        let ptr = self.directory[slot >> OFFSET_SEGMENT_BITS].load(Ordering::Acquire);
        debug_assert!(!ptr.is_null(), "slot {slot} has no segment");
        // SAFETY: a non-null entry points at a live segment of
        // `OFFSET_SEGMENT_SLOTS` atomics (`Offsets::grow`), freed only when
        // `Inner` is dropped, which the caller's borrow outlives.
        unsafe { std::slice::from_raw_parts(ptr, OFFSET_SEGMENT_SLOTS) }
    }

    #[inline]
    fn get(&self, slot: usize) -> Option<u64> {
        (slot < self.len.load(Ordering::Acquire)).then(|| self.segment(slot)[slot & MASK].load(Ordering::Acquire))
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let segments = *self.segments.get_mut();
        for entry in &mut self.directory[..segments] {
            let ptr = *entry.get_mut();
            if !ptr.is_null() {
                // SAFETY: made by `Box::into_raw` of a segment of
                // `OFFSET_SEGMENT_SLOTS` atomics in `Offsets::grow`, and
                // freed only here, once.
                drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, OFFSET_SEGMENT_SLOTS)) });
            }
        }
    }
}

/// A prefaulted `u64` segment as atomics.
fn atomic_segment(segment: Box<[u64]>) -> Box<[AtomicU64]> {
    const _: () = assert!(std::mem::size_of::<u64>() == std::mem::size_of::<AtomicU64>());
    const _: () = assert!(std::mem::align_of::<u64>() == std::mem::align_of::<AtomicU64>());
    // SAFETY: `AtomicU64` has the size and alignment of `u64` (asserted above)
    // and the same bit validity, and the box is uniquely owned.
    unsafe { Box::from_raw(Box::into_raw(segment) as *mut [AtomicU64]) }
}

/// The tree's offsets: one writer, through `&mut self`. See the module documentation.
pub(crate) struct Offsets {
    inner: Arc<Inner>,
}

impl Default for Offsets {
    fn default() -> Self {
        Self { inner: Arc::new(Inner::new()) }
    }
}

impl Clone for Offsets {
    /// A copy of its own: a cloned tree's offsets move apart from the original's.
    fn clone(&self) -> Self {
        let mut out = Self::default();
        let len = self.len();
        let mut slot = 0;
        while slot < len {
            let run = (OFFSET_SEGMENT_SLOTS - (slot & MASK)).min(len - slot);
            out.grow_to(slot + run);
            let from = &self.inner.segment(slot)[slot & MASK..][..run];
            let to = &out.inner.segment(slot)[slot & MASK..][..run];
            for (to, from) in to.iter().zip(from) {
                to.store(from.load(Ordering::Relaxed), Ordering::Relaxed);
            }
            slot += run;
        }
        out.inner.len.store(len, Ordering::Release);
        out
    }
}

impl std::fmt::Debug for Offsets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offsets").field("len", &self.len()).field("segments", &self.allocated_segments()).finish()
    }
}

impl Offsets {
    pub(crate) fn from_vec(offsets: Vec<u64>) -> Self {
        let mut out = Self::default();
        out.extend_from_slice(&offsets);
        out
    }

    pub(crate) fn len(&self) -> usize {
        // Only this writer stores the length.
        self.inner.len.load(Ordering::Relaxed)
    }

    /// Segments allocated, kept across truncations.
    pub(crate) fn allocated_segments(&self) -> usize {
        self.inner.segments.load(Ordering::Relaxed)
    }

    /// A reader of these offsets for other threads.
    pub(crate) fn reader(&self) -> OffsetsReader {
        OffsetsReader { inner: Arc::clone(&self.inner) }
    }

    pub(crate) fn get(&self, slot: usize) -> Option<u64> {
        self.inner.get(slot)
    }

    /// `slot`'s offset; panics past the length.
    #[track_caller]
    pub(crate) fn at(&self, slot: usize) -> u64 {
        assert!(slot < self.len(), "offset {slot} past {} slots", self.len());
        self.inner.segment(slot)[slot & MASK].load(Ordering::Relaxed)
    }

    /// Replaces `slot`'s offset (a compaction retargeting the slot). A
    /// reader that loaded the old offset keeps reading the old record, which
    /// stays where it was until it is punched.
    #[track_caller]
    pub(crate) fn set(&mut self, slot: usize, offset: u64) {
        assert!(slot < self.len(), "offset {slot} past {} slots", self.len());
        self.inner.segment(slot)[slot & MASK].store(offset, Ordering::Release);
    }

    /// Makes sure segments cover slots below `end`, publishing each before
    /// any length that reaches it.
    fn grow_to(&mut self, end: usize) {
        assert!(end <= MAX_SLOTS, "{end} slots past the directory's {MAX_SLOTS}");
        let mut segments = self.allocated_segments();
        while segments << OFFSET_SEGMENT_BITS < end {
            let segment = atomic_segment(crate::prefault::take_offset_segment());
            let ptr = Box::into_raw(segment) as *mut AtomicU64;
            self.inner.directory[segments].store(ptr, Ordering::Release);
            segments += 1;
            self.inner.segments.store(segments, Ordering::Release);
        }
    }

    pub(crate) fn push(&mut self, offset: u64) {
        let slot = self.len();
        self.grow_to(slot + 1);
        self.inner.segment(slot)[slot & MASK].store(offset, Ordering::Relaxed);
        self.inner.len.store(slot + 1, Ordering::Release);
    }

    /// Appends `offsets` in order: what one [`Self::push`] each leaves, with
    /// the length published once.
    pub(crate) fn extend_from_slice(&mut self, offsets: &[u64]) {
        let first = self.len();
        self.grow_to(first + offsets.len());
        let mut slot = first;
        let mut rest = offsets;
        while !rest.is_empty() {
            let at = slot & MASK;
            let run = (OFFSET_SEGMENT_SLOTS - at).min(rest.len());
            for (cell, offset) in self.inner.segment(slot)[at..at + run].iter().zip(&rest[..run]) {
                cell.store(*offset, Ordering::Relaxed);
            }
            slot += run;
            rest = &rest[run..];
        }
        self.inner.len.store(slot, Ordering::Release);
    }

    /// Drops every slot from `len` on. The segments stay allocated: a reader
    /// may still hold a pointer into them, and the next appends reuse them.
    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.inner.len.store(len, Ordering::Release);
        }
    }
}

/// Resolves slots to offsets from any thread, without a lock (module documentation).
#[derive(Clone)]
pub struct OffsetsReader {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for OffsetsReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffsetsReader").field("len", &self.len()).finish()
    }
}

impl OffsetsReader {
    /// `slot`'s offset as the tree last stored it; `None` at or past the
    /// length. Bit 63 set: the record is in `entries.relocated`.
    #[inline]
    pub fn get(&self, slot: u64) -> Option<u64> {
        usize::try_from(slot).ok().and_then(|slot| self.inner.get(slot))
    }

    /// Slots that hold an offset, as of now.
    pub fn len(&self) -> u64 {
        self.inner.len.load(Ordering::Acquire) as u64
    }

    /// Whether no slot holds an offset.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_extend_truncate_and_set_read_back_through_a_reader() {
        let mut offsets = Offsets::default();
        let reader = offsets.reader();
        assert!(reader.is_empty());
        assert_eq!(reader.get(0), None);
        // Across a segment boundary, both ways of appending.
        let first: Vec<u64> = (0..OFFSET_SEGMENT_SLOTS as u64 - 3).map(|n| n * 40).collect();
        offsets.extend_from_slice(&first);
        for n in 0..10u64 {
            offsets.push((first.len() as u64 + n) * 40);
        }
        let len = first.len() + 10;
        assert_eq!(offsets.len(), len);
        assert_eq!(reader.len(), len as u64);
        assert_eq!(offsets.allocated_segments(), 2);
        for slot in [0, 1, OFFSET_SEGMENT_SLOTS - 4, OFFSET_SEGMENT_SLOTS - 1, OFFSET_SEGMENT_SLOTS, len - 1] {
            assert_eq!(offsets.at(slot), slot as u64 * 40);
            assert_eq!(reader.get(slot as u64), Some(slot as u64 * 40));
        }
        assert_eq!(reader.get(len as u64), None);
        assert_eq!(reader.get(u64::MAX), None);

        offsets.set(5, 7 | (1 << 63));
        assert_eq!(reader.get(5), Some(7 | (1 << 63)));

        // A truncation below a segment boundary keeps the segment for the
        // appends that follow, and the reader sees the new length.
        offsets.truncate(OFFSET_SEGMENT_SLOTS - 2);
        assert_eq!(reader.len(), OFFSET_SEGMENT_SLOTS as u64 - 2);
        assert_eq!(reader.get(OFFSET_SEGMENT_SLOTS as u64), None);
        assert_eq!(offsets.allocated_segments(), 2);
        offsets.extend_from_slice(&[1, 2, 3]);
        assert_eq!(reader.get(OFFSET_SEGMENT_SLOTS as u64), Some(3));
        assert_eq!(offsets.allocated_segments(), 2);
    }

    #[test]
    fn a_clone_moves_apart_from_the_original() {
        let mut offsets = Offsets::from_vec((0..100).collect());
        let reader = offsets.reader();
        let mut copy = offsets.clone();
        assert_eq!(copy.len(), 100);
        assert_eq!(copy.at(99), 99);
        copy.set(3, 1000);
        copy.truncate(10);
        offsets.push(100);
        assert_eq!(reader.get(3), Some(3));
        assert_eq!(reader.len(), 101);
        assert_eq!(copy.reader().len(), 10);
        assert_eq!(copy.at(3), 1000);
    }

    /// A reader running beside the writer never sees an offset the writer
    /// did not store for that slot, nor a slot past what it published.
    #[test]
    fn a_reader_beside_the_writer_sees_only_published_offsets() {
        let mut offsets = Offsets::default();
        let reader = offsets.reader();
        let total = 3 * OFFSET_SEGMENT_SLOTS / 2;
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let (reader, done) = (reader.clone(), Arc::clone(&done));
            std::thread::spawn(move || {
                let mut checked = 0u64;
                while !done.load(Ordering::Acquire) {
                    let len = reader.len();
                    if len == 0 {
                        continue;
                    }
                    for slot in [0, len / 2, len - 1] {
                        assert_eq!(reader.get(slot), Some(slot * 8 + 1));
                        checked += 1;
                    }
                }
                checked
            })
        };
        let mut next = 0u64;
        while (next as usize) < total {
            if next.is_multiple_of(3) {
                let run: Vec<u64> = (next..next + 4097).map(|slot| slot * 8 + 1).collect();
                offsets.extend_from_slice(&run);
                next += run.len() as u64;
            } else {
                offsets.push(next * 8 + 1);
                next += 1;
            }
        }
        done.store(true, Ordering::Release);
        assert!(watcher.join().expect("the reader thread") > 0);
        assert_eq!(reader.len(), next);
    }
}

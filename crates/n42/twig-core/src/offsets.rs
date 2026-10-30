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

use std::{
    io,
    sync::{
        atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use crate::prefault::{OFFSET_SEGMENT_BITS, OFFSET_SEGMENT_SLOTS};

/// Slots the directory can name: as many as the key index's 40-bit field,
/// which refuses a slot past it anyway (`index::MAX_SLOT`). A `u64`, so the
/// crate still builds for 32-bit targets.
const MAX_SLOTS: u64 = 1 << 40;
/// Directory entries, one per segment (2^20, which fits any `usize`).
const DIRECTORY_LEN: usize = (MAX_SLOTS >> OFFSET_SEGMENT_BITS) as usize;
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

    /// `slot`'s cell without the length check: `None` only when no segment
    /// covers it. One load of the (rarely written) directory and one acquire
    /// load of the cell; the length, stored at every append, is not touched.
    #[inline]
    fn location(&self, slot: usize) -> Option<u64> {
        let ptr = self.directory.get(slot >> OFFSET_SEGMENT_BITS)?.load(Ordering::Acquire);
        if ptr.is_null() {
            return None;
        }
        // SAFETY: a non-null entry points at a live segment of
        // `OFFSET_SEGMENT_SLOTS` atomics, freed only with `Inner`, and the
        // index is masked below that length.
        Some(unsafe { &*ptr.add(slot & MASK) }.load(Ordering::Acquire))
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

/// A `u64` segment as atomics; it must hold exactly `OFFSET_SEGMENT_SLOTS`,
/// the length every pointer into it is rebuilt with.
fn atomic_segment(segment: Box<[u64]>) -> Box<[AtomicU64]> {
    assert_eq!(segment.len(), OFFSET_SEGMENT_SLOTS, "an offsets segment of the wrong length");
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
            // Fresh segments, not the prefault pool's: those are kept for the
            // apply path, and a clone is not on it.
            out.grow_to(slot + run, false).expect("a clone needs no more slots than its original holds");
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
    pub(crate) fn from_vec(offsets: Vec<u64>) -> io::Result<Self> {
        let mut out = Self::default();
        out.extend_from_slice(&offsets)?;
        Ok(out)
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
    /// any length that reaches it; `pooled` takes them from the prefault
    /// pool. Past [`MAX_SLOTS`] it refuses and changes nothing: the caller's
    /// append fails, and the forest stops on it as on any store error.
    fn grow_to(&mut self, end: usize, pooled: bool) -> io::Result<()> {
        if end as u64 > MAX_SLOTS {
            return Err(io::Error::other(format!("{end} QMDB slots past the offsets' {MAX_SLOTS}")));
        }
        let mut segments = self.allocated_segments();
        while segments << OFFSET_SEGMENT_BITS < end {
            let raw = if pooled {
                crate::prefault::take_offset_segment()
            } else {
                vec![0u64; OFFSET_SEGMENT_SLOTS].into_boxed_slice()
            };
            let segment = atomic_segment(raw);
            let ptr = Box::into_raw(segment) as *mut AtomicU64;
            self.inner.directory[segments].store(ptr, Ordering::Release);
            segments += 1;
            self.inner.segments.store(segments, Ordering::Release);
        }
        Ok(())
    }

    /// Makes room for slots below `end` without changing the length, so an
    /// append that touches other structures first can fail before it does.
    pub(crate) fn reserve(&mut self, end: usize) -> io::Result<()> {
        self.grow_to(end, true)
    }

    pub(crate) fn push(&mut self, offset: u64) -> io::Result<()> {
        let slot = self.len();
        self.grow_to(slot + 1, true)?;
        self.inner.segment(slot)[slot & MASK].store(offset, Ordering::Relaxed);
        self.inner.len.store(slot + 1, Ordering::Release);
        Ok(())
    }

    /// Appends `offsets` in order: what one [`Self::push`] each leaves, with
    /// the length published once.
    pub(crate) fn extend_from_slice(&mut self, offsets: &[u64]) -> io::Result<()> {
        let first = self.len();
        self.grow_to(first + offsets.len(), true)?;
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
        Ok(())
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

    /// `slot`'s offset for a slot the caller knows the tree holds (below a
    /// length it saw, and not truncated since): the read view's hot path,
    /// which keeps to slots its guards cover and so skips the length, a
    /// cache line the tree writes at every append. A retarget (compaction)
    /// is seen with acquire: the offset is the old record or the new one,
    /// both readable until the old range is punched (stage 3). For a slot
    /// the tree does not hold the value is stale or zero, never out of
    /// bounds; `None` only past every allocated segment.
    #[inline]
    pub fn location(&self, slot: u64) -> Option<u64> {
        usize::try_from(slot).ok().and_then(|slot| self.inner.location(slot))
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

/// Offsets of an entry file no tree owns: for tests and benches that write
/// an entry file by hand and read it through a read view, which resolves
/// slots through an [`OffsetsReader`]. The same structure as the tree's.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct StandaloneOffsets(Offsets);

impl StandaloneOffsets {
    /// Appends the next slot's offset.
    pub fn push(&mut self, offset: u64) -> io::Result<()> {
        self.0.push(offset)
    }

    /// Retargets `slot` (bit 63: `entries.relocated`); panics past the length.
    #[track_caller]
    pub fn set(&mut self, slot: u64, offset: u64) {
        self.0.set(usize::try_from(slot).expect("a slot that fits"), offset);
    }

    /// Slots held.
    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }

    /// Whether no slot is held.
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// A reader of these offsets.
    pub fn reader(&self) -> OffsetsReader {
        self.0.reader()
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
        offsets.extend_from_slice(&first).expect("room");
        for n in 0..10u64 {
            offsets.push((first.len() as u64 + n) * 40).expect("room");
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
        offsets.extend_from_slice(&[1, 2, 3]).expect("room");
        assert_eq!(reader.get(OFFSET_SEGMENT_SLOTS as u64), Some(3));
        assert_eq!(offsets.allocated_segments(), 2);
    }

    #[test]
    fn a_clone_moves_apart_from_the_original() {
        let mut offsets = Offsets::from_vec((0..100).collect()).expect("room");
        let reader = offsets.reader();
        let mut copy = offsets.clone();
        assert_eq!(copy.len(), 100);
        assert_eq!(copy.at(99), 99);
        copy.set(3, 1000);
        copy.truncate(10);
        offsets.push(100).expect("room");
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
                offsets.extend_from_slice(&run).expect("room");
                next += run.len() as u64;
            } else {
                offsets.push(next * 8 + 1).expect("room");
                next += 1;
            }
        }
        done.store(true, Ordering::Release);
        assert!(watcher.join().expect("the reader thread") > 0);
        assert_eq!(reader.len(), next);
    }

    /// `location` answers what `get` answers below the length, needs no
    /// length, and is `None` only past the allocated segments.
    #[test]
    fn location_matches_get_without_the_length() {
        let mut offsets = StandaloneOffsets::default();
        for n in 0..10u64 {
            offsets.push(n * 3).expect("room");
        }
        let reader = offsets.reader();
        for slot in 0..10 {
            assert_eq!(reader.location(slot), reader.get(slot));
        }
        assert_eq!(reader.get(10), None);
        assert_eq!(reader.location(10), Some(0), "an unwritten cell of an allocated segment");
        assert_eq!(reader.location(OFFSET_SEGMENT_SLOTS as u64), None, "no segment");
        assert_eq!(reader.location(u64::MAX), None);
    }

    /// Readers resolving slots while the writer retargets them see the old
    /// location or the new one, never anything else.
    #[test]
    fn a_retarget_is_seen_whole() {
        let mut offsets = Offsets::from_vec((0..4096u64).map(|slot| slot * 40).collect()).expect("room");
        let reader = offsets.reader();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchers: Vec<_> = (0..3)
            .map(|t| {
                let (reader, done) = (reader.clone(), Arc::clone(&done));
                std::thread::spawn(move || {
                    let mut seen = 0u64;
                    let mut slot = t * 101;
                    while !done.load(Ordering::Acquire) {
                        let location = reader.location(slot % 4096).expect("a segment");
                        let old = (slot % 4096) * 40;
                        assert!(location == old || location == (old + 7) | (1 << 63), "slot {slot}: {location:#x}");
                        seen += u64::from(location != old);
                        slot += 13;
                    }
                    seen
                })
            })
            .collect();
        for round in 0..64u64 {
            for slot in (0..4096u64).filter(|slot| slot % 64 == round) {
                offsets.set(slot as usize, (slot * 40 + 7) | (1 << 63));
            }
        }
        done.store(true, Ordering::Release);
        for watcher in watchers {
            watcher.join().expect("a reader");
        }
        for slot in 0..4096u64 {
            assert_eq!(reader.location(slot), Some((slot * 40 + 7) | (1 << 63)));
        }
    }

    #[test]
    fn growth_past_the_directory_is_refused_and_changes_nothing() {
        let mut offsets = Offsets::default();
        offsets.push(1).expect("room");
        assert!(offsets.reserve(MAX_SLOTS as usize + 1).is_err());
        assert_eq!(offsets.len(), 1);
        assert_eq!(offsets.allocated_segments(), 1);
        offsets.push(2).expect("room");
        assert_eq!(offsets.at(1), 2);
    }
}

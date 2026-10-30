// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reads the entry files by slot or byte offset, outside the tree and its lock.
//!
//! A QMDB read view (`docs/QMDB_UPGRADE_PLAN.md`, stage 6) answers state reads for the persisted
//! head while the tree it was taken from moves on under its own lock. It keys its index by slot
//! (`docs/QMDB_COMPACTION_DESIGN.md` 3.3): a slot's identity never changes, while its record may
//! move from `entries.log` to `entries.relocated` when its twig is compacted. [`SlotFileView`]
//! resolves a slot through the tree's shared offsets (`crate::offsets::OffsetsReader`, one
//! acquire load) and reads the record through [`EntryFileView`], a read-only mapping of one file.
//!
//! Records never change once appended, and a compaction leaves the old bytes where they were
//! (punching them is stage 3, after a reader epoch), so a reader that loaded either location reads
//! a valid record. An [`EntryFileView`] maps its file in segments of [`VIEW_MAP_BYTES`] (1 TiB) of
//! address space each, mapped the first time a read reaches them; pages of a shared file mapping
//! follow the file as it grows, so appends made after a mapping are readable without remapping.
//! Each segment's mapping runs [`SEGMENT_OVERLAP`] bytes into the next, so a record that starts in
//! a segment lies wholly in its mapping. The file can grow to [`VIEW_SEGMENTS`] segments (1 PiB);
//! before stage 1 the view mapped one segment and invalidated itself past it.
//!
//! The contract: a caller reads only records that are written (flushed to the file, not
//! necessarily synced) and not truncated since. Past the file's end a mapped page is a `SIGBUS`,
//! which is why a tree cutting its file tells a `TruncationGuard` first, and why
//! [`EntryFileView::key`] and [`EntryFileView::record`] are `unsafe`: the caller vouches for the
//! offset. [`EntryFileView::checked_record`] checks it against the file's length instead.

use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{offsets::OffsetsReader, Hash};

/// Address space one mapping segment covers: 1 TiB, the whole of what the view mapped before
/// it resolved slots.
pub const VIEW_MAP_BYTES: u64 = 1 << VIEW_SEGMENT_BITS;
const VIEW_SEGMENT_BITS: u32 = 40;
/// Segments a file can span: with [`VIEW_MAP_BYTES`] each, 1 PiB.
pub const VIEW_SEGMENTS: usize = 1024;

/// The longest value a record can hold (the portable snapshot's bound, far
/// above any account or slot encoding): a longer length field is a torn or
/// foreign record, refused rather than read past.
pub const MAX_RECORD_VALUE: usize = 16 << 20;

/// How far each segment's mapping runs into the next: the longest record
/// (a relocated one: tag, slot, key, length, value), rounded up to 64 KiB.
pub const SEGMENT_OVERLAP: u64 = ((MAX_RECORD_VALUE + RELOCATED_HEAD + KEY_LEN + LEN_LEN) as u64).next_multiple_of(64 << 10);

const KEY_LEN: usize = 32;
const LEN_LEN: usize = 4;
/// A relocated record's tag and slot, before its payload or hash
/// (`crate::entry_store`).
const RELOCATED_HEAD: usize = 1 + 8;
/// Bit 63 of a slot's offset: the record is in `entries.relocated`.
const RELOCATED_BIT: u64 = 1 << 63;
/// A relocated dead slot: its leaf hash only (`crate::entry_store`).
const TAG_DEAD: u8 = 0x02;

/// A read-only mapping of an entry file, addressed by record offset.
pub struct EntryFileView {
    /// The mapped file: each segment is mapped from it, and
    /// [`Self::checked_record`] checks lengths against it.
    file: File,
    /// Segment `i` maps `[i << bits, (i << bits) + (1 << bits) + SEGMENT_OVERLAP)`.
    segments: Box<[OnceLock<Option<memmap2::Mmap>>]>,
    bits: u32,
}

impl std::fmt::Debug for EntryFileView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mapped = self.segments.iter().filter(|segment| segment.get().is_some()).count();
        f.debug_struct("EntryFileView").field("segment_bits", &self.bits).field("mapped", &mapped).finish_non_exhaustive()
    }
}

impl EntryFileView {
    /// Maps the entry file at `path` (its first segment now, the others when
    /// a read reaches them).
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_segment_bits(path, VIEW_SEGMENT_BITS)
    }

    /// [`Self::open`] with segments of `2^bits` bytes (16 to 46): tests take
    /// a file past several segments without writing a terabyte.
    #[doc(hidden)]
    pub fn open_with_segment_bits(path: &Path, bits: u32) -> io::Result<Self> {
        if !(16..=46).contains(&bits) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("view segments of 2^{bits} bytes")));
        }
        let file = File::open(path)?;
        let view = Self { file, segments: (0..VIEW_SEGMENTS).map(|_| OnceLock::new()).collect(), bits };
        // The first segment now, so a file that cannot be mapped fails here.
        if view.segment(0).is_none() {
            return Err(io::Error::other(format!("{}: the entry file could not be mapped", path.display())));
        }
        Ok(view)
    }

    /// Segment `index`'s mapping, made on first use; `None` past the last
    /// segment or when the mapping failed (every read of it then declines).
    #[cold]
    fn map_segment(&self, index: usize) -> Option<&memmap2::Mmap> {
        self.segments
            .get(index)?
            .get_or_init(|| {
                let start = (index as u64) << self.bits;
                let len = usize::try_from((1u64 << self.bits) + SEGMENT_OVERLAP).ok()?;
                // SAFETY: a shared, read-only mapping. The tree only appends
                // to the file, and cuts it only after telling its
                // `TruncationGuard`; readers keep to written, uncut records
                // (the module's contract). `start` is a multiple of 64 KiB,
                // so of the page size.
                let map = unsafe { memmap2::MmapOptions::new().offset(start).len(len).map(&self.file) }.ok()?;
                #[cfg(unix)]
                let _ = map.advise(memmap2::Advice::Random);
                Some(map)
            })
            .as_ref()
    }

    #[inline]
    fn segment(&self, index: usize) -> Option<&memmap2::Mmap> {
        match self.segments.get(index)?.get() {
            Some(map) => map.as_ref(),
            None => self.map_segment(index),
        }
    }

    /// The `len` bytes at `offset`, if they lie in the mapping of the segment
    /// `offset` starts in (no byte is touched).
    #[inline]
    fn bytes(&self, offset: u64, len: usize) -> Option<&[u8]> {
        let index = usize::try_from(offset >> self.bits).ok()?;
        let at = (offset & ((1u64 << self.bits) - 1)) as usize;
        self.segment(index)?.get(at..at.checked_add(len)?)
    }

    /// The record's value length at `offset` (its header's length field).
    #[inline]
    fn value_len(&self, offset: u64) -> Option<usize> {
        let len = self.bytes(offset.checked_add(KEY_LEN as u64)?, LEN_LEN)?;
        Some(u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize)
    }

    /// The key of the record at `offset`.
    ///
    /// # Safety
    ///
    /// `offset` must be the start of a record that is written to the file
    /// (flushed, not necessarily synced) and not truncated since (the
    /// module's contract). Past the file's end the read is a `SIGBUS`, not a
    /// panic. Past the view's reach ([`VIEW_SEGMENTS`] segments) it panics.
    #[inline]
    pub unsafe fn key(&self, offset: u64) -> Hash {
        // SAFETY: the caller's contract, passed on.
        unsafe { self.try_key(offset) }.unwrap_or_else(|| panic!("entry-file offset {offset} past the read view's reach"))
    }

    /// [`Self::key`], `None` past the view's reach instead of a panic.
    ///
    /// # Safety
    ///
    /// As [`Self::key`].
    #[inline]
    pub unsafe fn try_key(&self, offset: u64) -> Option<Hash> {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(self.bytes(offset, KEY_LEN)?);
        Some(key)
    }

    /// The key and value of the record at `offset`. A length field over
    /// [`MAX_RECORD_VALUE`] (a torn or foreign record) panics rather than
    /// reading that far.
    ///
    /// # Safety
    ///
    /// As [`Self::key`]: `offset` must be the start of a written record not
    /// truncated since.
    #[inline]
    pub unsafe fn record(&self, offset: u64) -> (Hash, &[u8]) {
        let len = self.value_len(offset).unwrap_or_else(|| panic!("entry-file offset {offset} past the read view's reach"));
        assert!(len <= MAX_RECORD_VALUE, "entry-file record at {offset} claims a {len}-byte value");
        // SAFETY: the caller's contract, passed on.
        unsafe { self.try_record(offset) }.unwrap_or_else(|| panic!("entry-file offset {offset} past the read view's reach"))
    }

    /// [`Self::record`], declining (`None`) instead of panicking when the
    /// length field is over [`MAX_RECORD_VALUE`] or the record lies past the
    /// view's reach. Same cost as `record` (no `fstat`): for a reader that
    /// trusts its offset but must not take its thread down if that trust is
    /// wrong.
    ///
    /// # Safety
    ///
    /// As [`Self::record`].
    #[inline]
    pub unsafe fn try_record(&self, offset: u64) -> Option<(Hash, &[u8])> {
        let len = self.value_len(offset)?;
        if len > MAX_RECORD_VALUE {
            return None;
        }
        let bytes = self.bytes(offset, KEY_LEN + LEN_LEN + len)?;
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes[..KEY_LEN]);
        Some((key, &bytes[KEY_LEN + LEN_LEN..]))
    }

    /// [`Self::record`] checked against the file as it is now: `None` when
    /// the record's header or value would lie past the file's end or the
    /// view's reach, or its length field is over [`MAX_RECORD_VALUE`]. Costs
    /// an `fstat`; for callers that cannot vouch for `offset`. A truncation
    /// racing the read is still the caller's to exclude (`TruncationGuard`).
    pub fn checked_record(&self, offset: u64) -> io::Result<Option<(Hash, &[u8])>> {
        let file_len = self.file.metadata()?.len();
        let Some(header_end) = offset.checked_add((KEY_LEN + LEN_LEN) as u64) else {
            return Ok(None);
        };
        if header_end > file_len {
            return Ok(None);
        }
        let Some(len) = self.value_len(offset) else { return Ok(None) };
        if len > MAX_RECORD_VALUE || header_end + len as u64 > file_len {
            return Ok(None);
        }
        // SAFETY: the whole record lies inside the file's current length.
        Ok(unsafe { self.try_record(offset) })
    }

    /// Where the record at `offset` ends, if it lies wholly inside the view's
    /// reach; `None` past it, where the view cannot read it (an entry file
    /// past [`VIEW_SEGMENTS`] segments: the caller invalidates the view and
    /// reads go elsewhere). Only the record's header is read.
    pub fn record_end(&self, offset: u64) -> Option<u64> {
        let len = self.value_len(offset)?;
        let end = offset + (KEY_LEN + LEN_LEN + len) as u64;
        self.bytes(offset, KEY_LEN + LEN_LEN + len)?;
        Some(end)
    }

    /// The relocated record at `offset` in `entries.relocated`: its key and
    /// value, or `None` for a dead slot stored as its leaf hash, or a record
    /// that does not have the shape of one.
    ///
    /// # Safety
    ///
    /// As [`Self::key`], for a record of a relocated group.
    #[inline]
    unsafe fn relocated_payload(&self, offset: u64) -> Option<(Hash, &[u8])> {
        let head = self.bytes(offset, RELOCATED_HEAD)?;
        if head[0] == TAG_DEAD {
            return None;
        }
        debug_assert_eq!(head[0], 0x01, "a relocated record's tag at {offset}");
        // SAFETY: the payload follows the head, in the same record.
        unsafe { self.try_record(offset + RELOCATED_HEAD as u64) }
    }
}

/// The relocated file beside the entry file at `main` (`entries.relocated`
/// beside `entries.log`), where compacted twigs' records are.
pub fn relocated_path(main: &Path) -> PathBuf {
    crate::entry_store::relocated_path(main)
}

/// The tree's entry files read by slot: the shared offsets resolve a slot to
/// its record in `entries.log` or `entries.relocated` (bit 63), the latter
/// mapped the first time a slot points into it (a compaction syncs a group
/// before it retargets a slot at it, so the file then exists).
pub struct SlotFileView {
    offsets: OffsetsReader,
    main: EntryFileView,
    relocated_path: PathBuf,
    relocated: OnceLock<Option<EntryFileView>>,
    bits: u32,
}

impl std::fmt::Debug for SlotFileView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotFileView").field("main", &self.main).field("offsets", &self.offsets).finish_non_exhaustive()
    }
}

impl SlotFileView {
    /// Maps `entries.log` at `path` and resolves slots through `offsets`
    /// (the tree's own, `QmdbCompatTree::entry_offsets_reader`).
    pub fn open(path: &Path, offsets: OffsetsReader) -> io::Result<Self> {
        Self::open_with_segment_bits(path, offsets, VIEW_SEGMENT_BITS)
    }

    /// [`Self::open`] with mapping segments of `2^bits` bytes
    /// ([`EntryFileView::open_with_segment_bits`]).
    #[doc(hidden)]
    pub fn open_with_segment_bits(path: &Path, offsets: OffsetsReader, bits: u32) -> io::Result<Self> {
        let main = EntryFileView::open_with_segment_bits(path, bits)?;
        Ok(Self { offsets, main, relocated_path: relocated_path(path), relocated: OnceLock::new(), bits })
    }

    /// The offsets this view resolves through.
    pub const fn offsets(&self) -> &OffsetsReader {
        &self.offsets
    }

    #[cold]
    fn open_relocated(&self) -> Option<&EntryFileView> {
        self.relocated.get_or_init(|| EntryFileView::open_with_segment_bits(&self.relocated_path, self.bits).ok()).as_ref()
    }

    #[inline]
    fn relocated(&self) -> Option<&EntryFileView> {
        match self.relocated.get() {
            Some(view) => view.as_ref(),
            None => self.open_relocated(),
        }
    }

    /// `slot`'s key; `None` for a slot stored as its leaf hash (a dead slot
    /// of a compacted twig) or a location past the view's reach.
    ///
    /// # Safety
    ///
    /// `slot` must be one the tree holds, its record written and not
    /// truncated since (`EntryFileView`'s contract, by slot).
    #[inline]
    pub unsafe fn key(&self, slot: u64) -> Option<Hash> {
        let location = self.offsets.location(slot)?;
        if location & RELOCATED_BIT == 0 {
            // SAFETY: the caller's contract.
            return unsafe { self.main.try_key(location) };
        }
        // SAFETY: the caller's contract; a relocated location names a record
        // of a group synced before the slot was pointed at it.
        unsafe { self.relocated()?.relocated_payload(location & !RELOCATED_BIT) }.map(|(key, _)| key)
    }

    /// `slot`'s key and value; `None` as for [`Self::key`], or for a record
    /// that does not have the shape of one (a broken offset invariant
    /// declines the read rather than panicking on the reader's thread).
    ///
    /// # Safety
    ///
    /// As [`Self::key`].
    #[inline]
    pub unsafe fn record(&self, slot: u64) -> Option<(Hash, &[u8])> {
        let location = self.offsets.location(slot)?;
        if location & RELOCATED_BIT == 0 {
            // SAFETY: the caller's contract.
            return unsafe { self.main.try_record(location) };
        }
        // SAFETY: as in `key`.
        unsafe { self.relocated()?.relocated_payload(location & !RELOCATED_BIT) }
    }

    /// Whether `slot`'s record lies within the view's reach: a main-file
    /// record wholly inside the mapped segments, or a relocated one. Reads
    /// only the record's header.
    ///
    /// # Safety
    ///
    /// As [`Self::key`].
    pub unsafe fn reaches(&self, slot: u64) -> bool {
        match self.offsets.location(slot) {
            None => false,
            Some(location) if location & RELOCATED_BIT == 0 => self.main.record_end(location).is_some(),
            Some(_) => self.relocated().is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-entry-view-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("entries.log")
    }

    fn key(n: u64) -> Hash {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    fn block(range: std::ops::Range<u64>, tag: u8) -> Vec<QmdbOperation> {
        let mut ops: Vec<QmdbOperation> =
            range.map(|n| QmdbOperation { key: key(n), value: Some(vec![tag; (n % 90) as usize + 1]) }).collect();
        ops.sort_unstable_by_key(|op| op.key);
        ops
    }

    #[test]
    fn records_read_by_offset_match_the_tree_including_appends_after_the_mapping() {
        let path = scratch("appends");
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(block(0..3_000, 1)).unwrap();
        tree.set_entry_file(&path).unwrap();
        let view = EntryFileView::open(&path).unwrap();
        tree.apply_sorted_ops(block(2_000..9_000, 2)).unwrap();
        tree.flush_entries_for_sync().unwrap();
        for slot in 0..tree.next_slot() {
            let entry = tree.entry_at(slot).unwrap();
            // SAFETY: a flushed record of this tree, which never truncates here.
            let (k, value) = unsafe { view.record(tree.entry_offset(slot).unwrap()) };
            assert_eq!(k, entry.key, "slot {slot}");
            assert_eq!(value, entry.value.as_slice(), "slot {slot}");
        }
    }

    #[test]
    fn a_truncating_undo_tells_the_guard_the_new_length_first() {
        struct Record(std::sync::Mutex<Vec<(u64, u64)>>, std::path::PathBuf);
        impl crate::qmdb_compat::TruncationGuard for Record {
            fn before_truncate(&self, new_len: u64) {
                let file_len = std::fs::metadata(&self.1).unwrap().len();
                self.0.lock().unwrap().push((new_len, file_len));
            }
        }
        let path = scratch("guard");
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(block(0..1_000, 1)).unwrap();
        tree.set_entry_file(&path).unwrap();
        let calls = std::sync::Arc::new(Record(std::sync::Mutex::new(Vec::new()), path.clone()));
        tree.set_truncation_guard(Some(calls.clone()));
        let cut_at = tree.next_slot();
        let (_, undo) = tree.apply_sorted_ops_recorded(block(500..2_000, 2)).unwrap();
        tree.flush_entries_for_sync().unwrap();
        let cut_bytes = tree.entry_offset(cut_at).unwrap();
        tree.apply_undo(&undo).unwrap();
        let calls = calls.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, cut_at, "told the slots the file is cut to");
        assert!(calls[0].1 > cut_bytes, "before the cut");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), cut_bytes);
    }

    /// A record past the view's reach (every segment) is reported, not
    /// read: the bound is checked before any byte of it is touched.
    #[test]
    fn a_record_past_the_reach_has_no_end() {
        let path = scratch("bounds");
        let mut tree = QmdbCompatTree::new();
        tree.set_entry_file(&path).unwrap();
        tree.apply_sorted_ops(block(0..10, 1)).unwrap();
        tree.sync_entries().unwrap();
        let view = EntryFileView::open(&path).unwrap();
        // SAFETY: the file's first record, written and flushed above.
        let (_, value) = unsafe { view.record(0) };
        assert_eq!(view.record_end(0), Some((KEY_LEN + LEN_LEN + value.len()) as u64));
        assert_eq!(view.record_end((VIEW_SEGMENTS as u64) << VIEW_SEGMENT_BITS), None);
        assert_eq!(view.record_end(u64::MAX), None);
        assert!(EntryFileView::open_with_segment_bits(&path, 12).is_err(), "segments under 64 KiB are refused");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Records past several small segments read back, including ones that
    /// straddle a segment boundary (each segment's mapping overlaps the
    /// next), on a mapping made before the file grew past the first.
    #[test]
    fn records_across_segments_read_back() {
        let path = scratch("segments");
        let mut tree = QmdbCompatTree::new();
        tree.set_entry_file(&path).unwrap();
        let view = EntryFileView::open_with_segment_bits(&path, 16).unwrap();
        // ~60 bytes a record: ~4,000 records span four 64 KiB segments.
        tree.apply_sorted_ops(block(0..4_000, 3)).unwrap();
        tree.flush_entries_for_sync().unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > 3 << 16);
        let mut straddling = 0;
        for slot in 0..tree.next_slot() {
            let entry = tree.entry_at(slot).unwrap();
            let offset = tree.entry_offset(slot).unwrap();
            // SAFETY: a flushed record of this tree, which never truncates here.
            let (k, value) = unsafe { view.record(offset) };
            assert_eq!((k, value), (entry.key, entry.value.as_slice()), "slot {slot}");
            let end = view.record_end(offset).unwrap();
            straddling += usize::from(offset >> 16 != (end - 1) >> 16);
        }
        assert!(straddling > 0, "some record crosses a segment boundary");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The checked read answers a record inside the file and refuses one at
    /// or past its end, and a length field over the bound, without touching
    /// an unmapped page.
    #[test]
    fn the_checked_read_refuses_offsets_past_the_file() {
        let path = scratch("checked");
        let mut tree = QmdbCompatTree::new();
        tree.set_entry_file(&path).unwrap();
        tree.apply_sorted_ops(block(0..10, 1)).unwrap();
        tree.sync_entries().unwrap();
        let view = EntryFileView::open(&path).unwrap();
        let file_len = std::fs::metadata(&path).unwrap().len();
        let (key0, value0) = view.checked_record(0).unwrap().expect("the first record");
        assert_eq!(key0, tree.entry_at(0).unwrap().key);
        assert_eq!(value0, tree.entry_at(0).unwrap().value.as_slice());
        assert!(view.checked_record(file_len).unwrap().is_none());
        assert!(view.checked_record(file_len - 1).unwrap().is_none());
        assert!(view.checked_record(u64::MAX).unwrap().is_none());

        // A record whose length field claims more than the bound.
        let torn = scratch("checked-torn");
        let mut bytes = vec![0u8; KEY_LEN];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&torn, &bytes).unwrap();
        let view = EntryFileView::open(&torn).unwrap();
        assert!(view.checked_record(0).unwrap().is_none());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(torn.parent().unwrap());
    }

    /// Audit 2026-10 D-8: a read that trusts its offset (the read view's)
    /// declines a record whose length field is over the bound instead of
    /// panicking on the reader's thread.
    #[test]
    fn the_unchecked_read_declines_an_oversized_record() {
        let torn = scratch("try-torn");
        let mut bytes = vec![0u8; KEY_LEN];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&torn, &bytes).unwrap();
        let view = EntryFileView::open(&torn).unwrap();
        // SAFETY: offset 0 starts the one record written.
        assert!(unsafe { view.try_record(0) }.is_none());
        let _ = std::fs::remove_dir_all(torn.parent().unwrap());

        let path = scratch("try-good");
        let mut tree = QmdbCompatTree::new();
        tree.set_entry_file(&path).unwrap();
        tree.apply_sorted_ops(block(0..4, 1)).unwrap();
        tree.sync_entries().unwrap();
        let view = EntryFileView::open(&path).unwrap();
        // SAFETY: offset 0 starts the first record, synced above.
        let (key, value) = unsafe { view.try_record(0) }.expect("the first record");
        assert_eq!(key, tree.entry_at(0).unwrap().key);
        assert_eq!(value, tree.entry_at(0).unwrap().value.as_slice());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

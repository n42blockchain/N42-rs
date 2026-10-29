// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reads the entry file by byte offset, outside the tree and its lock.
//!
//! A QMDB read view (`docs/QMDB_UPGRADE_PLAN.md`, stage 6) answers state reads for the persisted
//! head while the tree it was taken from moves on under its own lock. Records in the entry file
//! (`[key 32][len u32 LE][value]`) never change once appended, so the view keeps byte offsets and
//! reads them through its own read-only mapping of the file. The mapping reserves
//! [`VIEW_MAP_BYTES`] of address space once: pages of a shared file mapping follow the file as it
//! grows, so appends made after the mapping are readable without remapping.
//!
//! The contract: a caller reads only offsets of records that are written (flushed to the file,
//! not necessarily synced) and not truncated since. Past the file's end a mapped page is a
//! `SIGBUS`, which is why a tree cutting its file tells a `TruncationGuard` first, and why
//! [`EntryFileView::key`] and [`EntryFileView::record`] are `unsafe`: the caller vouches for the
//! offset. [`EntryFileView::checked_record`] checks it against the file's length instead.

use std::{fs::File, io, path::Path};

use crate::Hash;

/// Address space the view reserves: 1 TiB, the most a 40-bit index value can name.
pub const VIEW_MAP_BYTES: u64 = 1 << 40;

/// The longest value a record can hold (the portable snapshot's bound, far
/// above any account or slot encoding): a longer length field is a torn or
/// foreign record, refused rather than read past.
pub const MAX_RECORD_VALUE: usize = 16 << 20;

const KEY_LEN: usize = 32;
const LEN_LEN: usize = 4;

/// A read-only mapping of an entry file, addressed by record offset.
pub struct EntryFileView {
    map: memmap2::Mmap,
    /// The mapped file, for [`Self::checked_record`]'s length check.
    file: File,
}

impl std::fmt::Debug for EntryFileView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryFileView").finish_non_exhaustive()
    }
}

impl EntryFileView {
    /// Maps the entry file at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: a shared, read-only mapping. The tree only appends to the
        // file, and cuts it only after telling its `TruncationGuard`; readers
        // keep to written, uncut records (the module's contract).
        let map = unsafe { memmap2::MmapOptions::new().len(VIEW_MAP_BYTES as usize).map(&file)? };
        #[cfg(unix)]
        map.advise(memmap2::Advice::Random)?;
        Ok(Self { map, file })
    }

    /// The key of the record at `offset`.
    ///
    /// # Safety
    ///
    /// `offset` must be the start of a record that is written to the file
    /// (flushed, not necessarily synced) and not truncated since (the
    /// module's contract). Past the file's end the read is a `SIGBUS`, not a
    /// panic. Past the mapping it panics.
    #[inline]
    pub unsafe fn key(&self, offset: u64) -> Hash {
        let at = offset as usize;
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&self.map[at..at + KEY_LEN]);
        key
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
        let at = offset as usize;
        // SAFETY: the caller's contract, passed on.
        let key = unsafe { self.key(offset) };
        let len_at = at + KEY_LEN;
        let len = u32::from_le_bytes([self.map[len_at], self.map[len_at + 1], self.map[len_at + 2], self.map[len_at + 3]]) as usize;
        assert!(len <= MAX_RECORD_VALUE, "entry-file record at {offset} claims a {len}-byte value");
        let value_at = len_at + LEN_LEN;
        (key, &self.map[value_at..value_at + len])
    }

    /// [`Self::record`], declining (`None`) instead of panicking when the
    /// length field is over [`MAX_RECORD_VALUE`] or the record runs past the
    /// mapping. Same cost as `record` (no `fstat`): for a reader that trusts
    /// its offset but must not take its thread down if that trust is wrong.
    ///
    /// # Safety
    ///
    /// As [`Self::record`].
    #[inline]
    pub unsafe fn try_record(&self, offset: u64) -> Option<(Hash, &[u8])> {
        let end = self.record_end(offset)?;
        let len = end - offset - (KEY_LEN + LEN_LEN) as u64;
        if len as usize > MAX_RECORD_VALUE {
            return None;
        }
        // SAFETY: the caller's contract, and the length was checked above.
        Some(unsafe { self.record(offset) })
    }

    /// [`Self::record`] checked against the file as it is now: `None` when
    /// the record's header or value would lie past the file's end or the
    /// mapping, or its length field is over [`MAX_RECORD_VALUE`]. Costs an
    /// `fstat`; for callers that cannot vouch for `offset`. A truncation
    /// racing the read is still the caller's to exclude (`TruncationGuard`).
    pub fn checked_record(&self, offset: u64) -> io::Result<Option<(Hash, &[u8])>> {
        let file_len = self.file.metadata()?.len().min(VIEW_MAP_BYTES);
        let Some(header_end) = offset.checked_add((KEY_LEN + LEN_LEN) as u64) else {
            return Ok(None);
        };
        if header_end > file_len {
            return Ok(None);
        }
        let len_at = offset as usize + KEY_LEN;
        let len = u32::from_le_bytes([self.map[len_at], self.map[len_at + 1], self.map[len_at + 2], self.map[len_at + 3]]);
        if len as usize > MAX_RECORD_VALUE || header_end + u64::from(len) > file_len {
            return Ok(None);
        }
        // SAFETY: the whole record lies inside the file's current length.
        Ok(Some(unsafe { self.record(offset) }))
    }

    /// Where the record at `offset` ends, if it lies wholly inside the
    /// mapping ([`VIEW_MAP_BYTES`]); `None` past it, where the view cannot
    /// read it (an entry file past 1 TiB: the caller invalidates the view
    /// and reads go elsewhere). Nothing past the mapping is touched.
    pub fn record_end(&self, offset: u64) -> Option<u64> {
        let header_end = offset.checked_add((KEY_LEN + LEN_LEN) as u64)?;
        if header_end > VIEW_MAP_BYTES {
            return None;
        }
        let len_at = offset as usize + KEY_LEN;
        let len = u32::from_le_bytes([self.map[len_at], self.map[len_at + 1], self.map[len_at + 2], self.map[len_at + 3]]);
        let end = header_end + u64::from(len);
        (end <= VIEW_MAP_BYTES).then_some(end)
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
        let expected = tree.entry_offset(cut_at).unwrap();
        tree.apply_undo(&undo).unwrap();
        let calls = calls.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, expected, "told the length the file is cut to");
        assert!(calls[0].1 > expected, "before the cut");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), expected);
    }

    /// A record past the 1 TiB mapping is reported, not read: the bound is
    /// checked before any byte of it is touched.
    #[test]
    fn a_record_past_the_mapping_has_no_end() {
        let path = scratch("bounds");
        let mut tree = QmdbCompatTree::new();
        tree.set_entry_file(&path).unwrap();
        tree.apply_sorted_ops(block(0..10, 1)).unwrap();
        tree.sync_entries().unwrap();
        let view = EntryFileView::open(&path).unwrap();
        // SAFETY: the file's first record, written and flushed above.
        let (_, value) = unsafe { view.record(0) };
        assert_eq!(view.record_end(0), Some((KEY_LEN + LEN_LEN + value.len()) as u64));
        assert_eq!(view.record_end(VIEW_MAP_BYTES), None);
        assert_eq!(view.record_end(VIEW_MAP_BYTES - (KEY_LEN + LEN_LEN) as u64 + 1), None);
        assert_eq!(view.record_end(u64::MAX), None);
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

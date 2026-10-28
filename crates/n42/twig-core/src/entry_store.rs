// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a QMDB tree keeps its entries: in the heap, or in an append-only
//! file with only an offset and an active bit per slot in memory.
//!
//! `docs/QMDB_ENTRY_LOG.md` is the design. The tree needs an entry's bytes
//! for the undo record of the slots a block retires, for the delta and the
//! checkpoint (sequential reads), for proofs, and for the mismatch check of a
//! revival; nothing on the hot path needs them in memory. In the heap an
//! entry is ~160 B (the struct and a heap `Vec<u8>` for the value); in the
//! file it is 8 B of offset and a bit, and the page cache -- evictable, which
//! the heap is not -- holds whatever is read often.
//!
//! # The relocated file
//!
//! `docs/QMDB_COMPACTION_DESIGN.md` (stage 2) adds a second append-only file
//! beside `entries.log`, `entries.relocated` (the main file's name with the
//! extension `relocated`), which receives compacted twigs: a twig's 2048
//! slots rewritten as one group, in slot order, keeping slot numbers -- so
//! no leaf, twig root, proof or root changes. A group is
//!
//! ```text
//! [0x01][slot u64][key 32][len u32][value]   a live slot, the main file's payload
//! [0x02][slot u64][leaf_hash 32]             a dead slot: its leaf hash only
//! [0x03][twig u64][crc32 u32]                the trailer
//! ```
//!
//! with every integer little endian and the CRC-32 (IEEE, `crc32fast`) taken
//! over every byte of the group before the CRC itself, the trailer's tag and
//! twig included. A slot's offset has bit 63 set when it points into the
//! relocated file. `entries.log` keeps every slot's original record (nothing
//! is punched in this stage), so the read view's byte offsets into it stay
//! valid and a lost group loses nothing.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Seek, Write},
    path::{Path, PathBuf},
};

use crate::{Hash, NULL_HASH, TWIG_SIZE, hash_leaf};

/// Fault injection for the entry file's appends (feature `failpoints`, for
/// tests of callers that must survive a failed write): an armed path's next
/// batch append copies its first `keep` records and then fails as a failed
/// seal does, leaving the store part way into the batch. A single append
/// (`QmdbCompatTree::set`) fails outright, whatever `keep` is.
#[cfg(feature = "failpoints")]
pub mod failpoints {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static ARMED: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

    /// Arms the entry file at `path`: its next batch append keeps `keep`
    /// records and fails.
    pub fn fail_next_append(path: &Path, keep: usize) {
        ARMED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((path.to_path_buf(), keep));
    }

    static ARMED_TRUNCATE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Arms the entry file at `path`: its next truncation (an undo that
    /// takes appended slots off) fails before it cuts anything.
    pub fn fail_next_truncate(path: &Path) {
        ARMED_TRUNCATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(path.to_path_buf());
    }

    /// Disarms the truncation failure armed for `path`; whether there was one.
    pub(crate) fn take_truncate(path: &Path) -> bool {
        let mut armed = ARMED_TRUNCATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(at) = armed.iter().position(|armed| armed == path) else {
            return false;
        };
        armed.swap_remove(at);
        true
    }

    /// Disarms and returns the failure armed for `path`, if any.
    pub(crate) fn take(path: &Path) -> Option<usize> {
        let mut armed = ARMED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let at = armed.iter().position(|(armed, _)| armed == path)?;
        Some(armed.swap_remove(at).1)
    }

    /// The error an armed append fails with.
    pub(crate) fn injected() -> std::io::Error {
        std::io::Error::other("injected entry-file seal failure (failpoints)")
    }
}

/// One entry, as the heap store keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The key; for a hash-only slot, its leaf hash.
    pub(crate) key: Hash,
    pub(crate) value: Vec<u8>,
    pub(crate) active: bool,
    /// A dead slot whose payload was dropped by a compaction: `key` holds
    /// its leaf hash and `value` is empty. Only a heap tree rebuilt from the
    /// snapshot of a compacted file tree has one.
    pub(crate) hash_only: bool,
}

/// What a slot holds, read out of either store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotContent {
    /// The entry's key and value bytes: every live slot, and every dead
    /// slot outside a compacted twig.
    Payload {
        /// The entry's key.
        key: Hash,
        /// Its value bytes.
        value: Vec<u8>,
    },
    /// A dead slot of a compacted twig: only its leaf hash is kept
    /// (`docs/QMDB_COMPACTION_DESIGN.md` 3.2).
    HashOnly {
        /// `hash_leaf(key, value)` of the entry the slot held.
        leaf_hash: Hash,
    },
}

/// A slot's content, read out of either store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotEntry {
    /// The payload, or only the leaf hash.
    pub content: SlotContent,
    /// Whether the slot is live (never for a hash-only slot).
    pub active: bool,
}

impl SlotEntry {
    /// The slot's leaf hash, computed from the payload or stored.
    pub fn leaf_hash(&self) -> Hash {
        match &self.content {
            SlotContent::Payload { key, value } => hash_leaf(key, value),
            SlotContent::HashOnly { leaf_hash } => *leaf_hash,
        }
    }
}

/// A slot's content borrowed from either store.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SlotRef<'a> {
    /// The key and the value.
    Payload(&'a Hash, &'a [u8]),
    /// A dead slot of a compacted twig: its leaf hash.
    HashOnly(&'a Hash),
}

impl SlotRef<'_> {
    /// The slot's leaf hash.
    pub(crate) fn leaf_hash(self) -> Hash {
        match self {
            Self::Payload(key, value) => hash_leaf(key, value),
            Self::HashOnly(hash) => *hash,
        }
    }
}

/// Bit 63 of an offset: the record is in `entries.relocated`.
const RELOCATED_BIT: u64 = 1 << 63;
/// The tags of a relocated group's records (module doc).
const TAG_LIVE: u8 = 0x01;
const TAG_DEAD: u8 = 0x02;
const TAG_END: u8 = 0x03;
/// A relocated record's tag and slot, before the payload or the hash.
const RELOCATED_HEAD: usize = 1 + 8;
/// A dead record: tag, slot, leaf hash.
const DEAD_RECORD: usize = RELOCATED_HEAD + 32;
/// A group's trailer: tag, twig, CRC.
const TRAILER: usize = 1 + 8 + 4;

/// The relocated file beside the main file at `main`: `entries.relocated`
/// for `entries.log`.
pub(crate) fn relocated_path(main: &Path) -> PathBuf {
    main.with_extension("relocated")
}

/// Why an operation on the relocated twigs was refused.
fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The record layout in the file: the key, the value's length, the value.
const KEY_LEN: usize = 32;
const LEN_LEN: usize = 4;
/// The file is mapped in chunks of about this many bytes, each sealed and
/// mapped once, with its page tables populated at that moment, so a read
/// never takes a page fault afterwards: 133,000 random reads a block on a
/// mapping that was just re-established cost 50-80 ms of minor faults
/// (loop123 E1, the follower's root phase 100-135 ms against ~56). Bytes
/// past the last sealed chunk are read from a tail buffer.
#[cfg(not(test))]
const CHUNK_BYTES: usize = 256 << 20;
/// Small in the unit tests, so a few blocks cross several seals.
#[cfg(test)]
const CHUNK_BYTES: usize = 1 << 20;

/// Chunks sealed since the process started, and the microseconds their
/// sealing took (the tail's write, the mapping), for a caller that wants
/// to say how much of a QMDB root a seal was ([`seal_stats`]). The tree
/// that seals is under its owner's lock, so a difference across one root
/// is that root's.
static SEALS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEAL_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many entry-file chunks have been sealed in this process, and the
/// microseconds the seals took in all.
pub fn seal_stats() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (SEALS.load(Relaxed), SEAL_US.load(Relaxed))
}

/// Where a tree's entries live, as [`EntryStoreStats`] reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryStoreMode {
    /// Every entry in the heap (`N42_QMDB_ENTRY_FILE` off).
    #[default]
    Heap,
    /// Entries in the append-only entry file.
    File,
}

/// The entry store's size, read from a few counters and the key index's length
/// (`docs/QMDB_COMPACTION_DESIGN.md` 3.7): what grows with the append
/// history (`total_slots`, `file_bytes`, `offsets_bytes`) against what grows
/// with the live state (`live_slots`, `index_bytes`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryStoreStats {
    /// Where the entries live.
    pub mode: EntryStoreMode,
    /// Slots ever appended and not cut by an undo.
    pub total_slots: u64,
    /// Slots still active: the key index's length, in both modes. The index
    /// names every active slot exactly once at rest -- an open builds it from
    /// the active bits and refuses a duplicate active key, and every apply,
    /// delete and undo retires or revives a slot together with its index
    /// entry under the same `&mut` -- so this is O(1), where a popcount of
    /// the file's active bits is linear in `total_slots` (128 MB at a billion
    /// slots, under the forest lock every sample). The tests check it
    /// against a count of the active slots.
    pub live_slots: u64,
    /// In the file, the bytes of the file that belong to slots (its length,
    /// less a torn tail); in the heap, the entry vector's own bytes, without
    /// the values' allocations.
    pub file_bytes: u64,
    /// The offsets' segments, 8 MiB each; 0 in the heap.
    pub offsets_bytes: u64,
    /// The key index's tables ([`crate::qmdb_compat::QmdbCompatTree::index_bytes`]).
    pub index_bytes: u64,
    /// Sealed mappings of the file; 0 in the heap.
    pub chunks: u64,
    /// Bytes of `entries.relocated` that belong to complete groups (the
    /// compacted twigs, `docs/QMDB_COMPACTION_DESIGN.md` 3.7); 0 in the heap.
    pub relocated_bytes: u64,
}

impl EntryStoreStats {
    /// Entry bytes per live slot, `(file_bytes + relocated_bytes) /
    /// max(live_slots, 1)`: the growth compaction would bound. Nothing is
    /// punched yet (stage 3), so a compaction raises it until then.
    pub fn bytes_per_live_slot(&self) -> u64 {
        (self.file_bytes + self.relocated_bytes) / self.live_slots.max(1)
    }
}

/// One sealed mapping of `[start, start + len)` of the file. A chunk sealed
/// at open is populated there; one sealed while the tree grows is populated
/// on a thread of its own ([`populate_off_lock`]), which holds the mapping
/// until it is done.
struct Chunk {
    start: u64,
    map: std::sync::Arc<memmap2::Mmap>,
}

/// Faults a freshly sealed chunk's page tables in (`MADV_POPULATE_READ`) on a
/// thread of its own, instead of with `MAP_POPULATE` in the `mmap` call.
///
/// The seal happens inside a block's apply -- the append that fills the
/// chunk -- under the lock the tree lives behind, so a populate there (65,536
/// pages, each read from the disk if the page cache has let it go since it
/// was written, as it does under the heaps' reclaim) held that block's QMDB
/// root, and every root behind it, for hundreds of milliseconds every ~13
/// blocks (defect 24, loop294). Reads of the chunk before the thread
/// is done take a fault of their own, as they would without the populate.
/// Without the thread (it cannot be spawned, or not on Linux) the chunk is
/// faulted in lazily.
fn populate_off_lock(map: &std::sync::Arc<memmap2::Mmap>) {
    #[cfg(target_os = "linux")]
    {
        let map = std::sync::Arc::clone(map);
        let _ = std::thread::Builder::new().name("n42-qmdb-populate".into()).spawn(move || {
            n42_core_layout::background_thread();
            // A failure (an old kernel, a file cut under the mapping) leaves
            // the pages to fault on first read.
            let _ = map.advise(memmap2::Advice::PopulateRead);
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = map;
}

/// Where each slot's record starts, in segments of
/// [`crate::prefault::OFFSET_SEGMENT_SLOTS`] slots instead of one `Vec`: a
/// `Vec` of a hundred million offsets grows by doubling, a copy of up to a
/// gigabyte into fresh pages inside one block's apply, under the tree's lock
/// (BREAKTHROUGH_DESIGN 10.42). A segment is 8 MiB, taken already faulted in
/// from the prefault thread.
#[derive(Clone, Default)]
struct Offsets {
    segments: Vec<Box<[u64]>>,
    len: usize,
}

impl Offsets {
    const BITS: u32 = crate::prefault::OFFSET_SEGMENT_BITS;
    const MASK: usize = crate::prefault::OFFSET_SEGMENT_SLOTS - 1;

    fn from_vec(offsets: Vec<u64>) -> Self {
        let mut out = Self::default();
        for offset in offsets {
            out.push(offset);
        }
        out
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn get(&self, slot: usize) -> Option<u64> {
        (slot < self.len).then(|| self.segments[slot >> Self::BITS][slot & Self::MASK])
    }

    /// Replaces `slot`'s offset (a compaction retargeting the slot).
    fn set(&mut self, slot: usize, offset: u64) {
        assert!(slot < self.len, "offset {slot} past {} slots", self.len);
        self.segments[slot >> Self::BITS][slot & Self::MASK] = offset;
    }

    fn push(&mut self, offset: u64) {
        let slot = self.len;
        if slot >> Self::BITS == self.segments.len() {
            self.segments.push(crate::prefault::take_offset_segment());
        }
        self.segments[slot >> Self::BITS][slot & Self::MASK] = offset;
        self.len += 1;
    }

    /// Appends `offsets` in order: what one [`Self::push`] each leaves, a
    /// segment's run at a time.
    #[cfg(feature = "rayon")]
    fn extend_from_slice(&mut self, mut offsets: &[u64]) {
        while !offsets.is_empty() {
            let slot = self.len;
            if slot >> Self::BITS == self.segments.len() {
                self.segments.push(crate::prefault::take_offset_segment());
            }
            let at = slot & Self::MASK;
            let run = (crate::prefault::OFFSET_SEGMENT_SLOTS - at).min(offsets.len());
            self.segments[slot >> Self::BITS][at..at + run].copy_from_slice(&offsets[..run]);
            self.len += run;
            offsets = &offsets[run..];
        }
    }

    fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        self.len = len;
        self.segments.truncate(len.div_ceil(crate::prefault::OFFSET_SEGMENT_SLOTS));
    }
}

impl std::ops::Index<usize> for Offsets {
    type Output = u64;

    fn index(&self, slot: usize) -> &u64 {
        assert!(slot < self.len, "offset {slot} past {} slots", self.len);
        &self.segments[slot >> Self::BITS][slot & Self::MASK]
    }
}

/// One append-only file of the entry store, mapped for reads: the sealed
/// chunks, the tail buffer the next flush writes, and the populate
/// bookkeeping. `entries.log` is one; `entries.relocated`, the compacted
/// twigs (`docs/QMDB_COMPACTION_DESIGN.md` 3.1), is the other.
struct LogFile {
    path: PathBuf,
    file: File,
    /// Sealed chunks in file order; `chunks[i].start` ascending.
    chunks: Vec<Chunk>,
    /// Bytes of the file the sealed chunks cover.
    sealed_len: u64,
    /// The file's content from `sealed_len` on. Its first `written` bytes
    /// are on disk; the rest are written in one call by `flush`, so an
    /// append is a memory copy and not a write syscall (147,000 of those a
    /// block were the file store's root phase, loop125).
    tail: Vec<u8>,
    /// How many bytes of `tail` the file already holds.
    written: usize,
    /// The tail buffer's address when `populated` was last set, and how
    /// many of its bytes are populated or asked to be
    /// ([`Self::populate_ahead`]).
    populated_base: usize,
    populated: usize,
    /// The append epoch the populate's progress is matched against
    /// (`prefault::note_append`): new with every buffer and every seal.
    populate_epoch: u64,
    /// The cursor when a window was last asked for.
    populate_asked_at: usize,
    /// Bytes of the file that belong to records.
    len_bytes: u64,
    /// Whether appends ask the populate thread to fault the tail in ahead
    /// of them: the main file's appends are a block's apply; the relocated
    /// file's are a compaction, off the hot path.
    populate: bool,
    /// A second handle made for a cloned tree ([`Self::duplicate`]): it
    /// refuses every append, truncation and write, so it can never cut or
    /// extend the file under the handle it was cloned from.
    read_only: bool,
}

impl LogFile {
    /// A file opened at `path` holding `len_bytes` of records, nothing
    /// sealed yet.
    const fn new(path: PathBuf, file: File, len_bytes: u64, populate: bool) -> Self {
        Self {
            path,
            file,
            chunks: Vec::new(),
            sealed_len: 0,
            tail: Vec::new(),
            written: 0,
            populated_base: 0,
            populated: 0,
            populate_epoch: 0,
            populate_asked_at: 0,
            len_bytes,
            populate,
            read_only: false,
        }
    }

    /// Creates (truncating) the file at `path`.
    fn create(path: &Path, populate: bool) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
        Ok(Self::new(path.to_path_buf(), file, 0, populate))
    }

    /// Maps `[0, len_bytes)` in chunks that end at one of `starts` (the
    /// record starts, ascending), so a record never straddles two chunks.
    fn seal_existing(&mut self, starts: &[u64]) -> io::Result<()> {
        let mut start = 0u64;
        let mut at = 0usize;
        while start < self.len_bytes {
            // The first record at or past `start + CHUNK_BYTES` ends the chunk.
            let limit = start + CHUNK_BYTES as u64;
            let mut end_at = at;
            while end_at < starts.len() && starts[end_at] < limit {
                end_at += 1;
            }
            let end = if end_at < starts.len() { starts[end_at] } else { self.len_bytes };
            // SAFETY: read-only mapping of bytes that are never rewritten in
            // place (see `seal_tail`).
            let map = unsafe {
                memmap2::MmapOptions::new().offset(start).len((end - start) as usize).populate().map(&self.file)?
            };
            self.chunks.push(Chunk { start, map: std::sync::Arc::new(map) });
            start = end;
            at = end_at;
        }
        self.sealed_len = self.len_bytes;
        Ok(())
    }

    /// The bytes from `start` to the end of the chunk, or of the tail, it
    /// lies in: a record that starts there ends within them.
    fn bytes_from(&self, start: u64) -> &[u8] {
        if start >= self.sealed_len {
            &self.tail[(start - self.sealed_len) as usize..]
        } else {
            let i = self.chunks.partition_point(|chunk| chunk.start <= start) - 1;
            let chunk = &self.chunks[i];
            &chunk.map[(start - chunk.start) as usize..]
        }
    }

    /// Appends `bytes` as one unit that no chunk boundary splits: the tail is
    /// sealed first if they would not fit in it. Returns where they start.
    /// No populate: this is the relocated file's append, off the hot path.
    fn append_unit(&mut self, bytes: &[u8]) -> io::Result<u64> {
        self.writable()?;
        if !self.tail.is_empty() && self.tail.len() + bytes.len() > CHUNK_BYTES {
            self.seal_tail()?;
        }
        let start = self.len_bytes;
        self.tail.extend_from_slice(bytes);
        self.len_bytes += bytes.len() as u64;
        Ok(start)
    }

    /// Asks the append populate thread to populate the tail buffer's pages
    /// ahead of the append cursor (`N42_QMDB_APPEND_AHEAD_MB`), so the
    /// appends a block's apply makes never fault.
    fn populate_ahead(&mut self) {
        let ahead = crate::prefault::append_ahead_bytes();
        if ahead == 0 || !self.populate {
            return;
        }
        let base = self.tail.as_ptr() as usize;
        if base != self.populated_base || self.populate_epoch == 0 {
            self.populated_base = base;
            self.populated = self.tail.len();
            self.populate_asked_at = self.tail.len();
            self.populate_epoch = crate::prefault::next_append_epoch();
        }
        // The window is re-walked from the cursor, not from the last edge,
        // every eighth of a window as well as when half of it is left: a
        // populate of pages still present is a page-table walk, and the
        // pages of a window populated seconds before the append reaches
        // them were taken back under the fleet's memory pressure (the host
        // swaps; loop302: ~1,070 faults in the appends of one root in five
        // while the populate had long covered them -- after the first chunk
        // it was never asked again, since the buffer is reused).
        let cursor = self.tail.len();
        let want = (cursor + ahead).min(self.tail.capacity());
        let rewalk = crate::prefault::append_rewalk() && cursor >= self.populate_asked_at + ahead / 8;
        if (self.populated < cursor + ahead / 2 || rewalk) && cursor < want {
            // From the populated edge on, never over the pages the append
            // is writing: populating from the cursor, or the buffer's start
            // again after a seal, made the append fault ~1,100 pages a
            // block for the four blocks after every seal in `root_faults`
            // (why is not established); the re-walk is left behind
            // `N42_QMDB_APPEND_REWALK=1`.
            let from = if rewalk { cursor } else { self.populated.max(cursor) };
            crate::prefault::populate_append(self.populate_epoch, base, from, want);
            self.populated = want;
            self.populate_asked_at = cursor;
        }
    }

    /// Writes the tail's unwritten bytes to the file, in one call.
    fn flush(&mut self) -> io::Result<()> {
        if self.written < self.tail.len() {
            // The handle it was cloned from writes these bytes.
            self.writable()?;
            self.file.seek(io::SeekFrom::Start(self.sealed_len + self.written as u64))?;
            self.file.write_all(&self.tail[self.written..])?;
            self.written = self.tail.len();
        }
        Ok(())
    }

    /// Maps the tail as a chunk (page tables populated) and empties it.
    fn seal_tail(&mut self) -> io::Result<()> {
        if self.tail.is_empty() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let sealed = self.seal_tail_timed();
        SEALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SEAL_US.fetch_add(started.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
        sealed
    }

    fn seal_tail_timed(&mut self) -> io::Result<()> {
        self.flush()?;
        // SAFETY: the mapping is read-only over bytes that `push` wrote
        // before this call and that nothing rewrites: the file is only ever
        // shortened, and a shortening below a chunk's start unmaps the chunk
        // first (`truncate`).
        let map = std::sync::Arc::new(unsafe {
            memmap2::MmapOptions::new().offset(self.sealed_len).len(self.tail.len()).map(&self.file)?
        });
        populate_off_lock(&map);
        self.chunks.push(Chunk { start: self.sealed_len, map });
        self.sealed_len = self.len_bytes;
        self.tail.clear();
        self.written = 0;
        self.tail.shrink_to(CHUNK_BYTES);
        // The next chunk starts at the buffer's start: its window is asked
        // for now, under a new epoch.
        if self.populate && crate::prefault::append_rewalk() {
            self.populated = 0;
            self.populate_asked_at = 0;
            self.populate_epoch = crate::prefault::next_append_epoch();
            self.populate_ahead();
        }
        Ok(())
    }

    /// Writes what the tail still holds and makes every record durable.
    fn sync(&mut self) -> io::Result<()> {
        self.flush()?;
        self.file.sync_data()
    }

    /// Shortens the file to `new_len_bytes`, unmapping the chunks the cut
    /// reaches into; the chunk it lands in becomes the tail again.
    fn cut(&mut self, new_len_bytes: u64) -> io::Result<()> {
        self.len_bytes = new_len_bytes;
        if new_len_bytes >= self.sealed_len {
            self.tail.truncate((new_len_bytes - self.sealed_len) as usize);
            self.written = self.written.min(self.tail.len());
        } else {
            // The cut lands inside a sealed chunk: that chunk and every later
            // one go, and the chunk's bytes below the cut become the tail
            // again, re-read from the file.
            let keep = self.chunks.partition_point(|chunk| chunk.start < new_len_bytes);
            let cut = &self.chunks[keep - 1];
            let within = (new_len_bytes - cut.start) as usize;
            let start = cut.start;
            // Into the tail's own buffer, whose pages are faulted in
            // already: a fresh one would be reserved, and faulted, by the
            // next append, inside a block's apply.
            self.tail.clear();
            self.tail.extend_from_slice(&cut.map[..within]);
            self.chunks.truncate(keep - 1);
            self.sealed_len = start;
            // The chunk's bytes are on disk already.
            self.written = self.tail.len();
        }
        self.file.set_len(new_len_bytes)
    }

    /// Refuses a write on a read-only handle ([`Self::duplicate`]).
    fn writable(&self) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{}: a cloned entry store is read-only", self.path.display()),
            ));
        }
        Ok(())
    }

    /// A second, read-only handle on the same file with the same chunks and
    /// tail (see [`FileEntries::duplicate`]).
    fn duplicate(&self) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).open(&self.path)?;
        let mut chunks = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            // SAFETY: as in `seal_tail`; the same sealed bytes.
            let map = unsafe {
                memmap2::MmapOptions::new().offset(chunk.start).len(chunk.map.len()).populate().map(&file)?
            };
            chunks.push(Chunk { start: chunk.start, map: std::sync::Arc::new(map) });
        }
        Ok(Self {
            path: self.path.clone(),
            file,
            chunks,
            sealed_len: self.sealed_len,
            tail: self.tail.clone(),
            written: self.written,
            populated_base: 0,
            populated: 0,
            populate_epoch: 0,
            populate_asked_at: 0,
            len_bytes: self.len_bytes,
            populate: self.populate,
            read_only: true,
        })
    }
}

/// A twig whose records were rewritten into `entries.relocated`.
#[derive(Clone, Debug)]
struct RelocatedTwig {
    /// Where `entries.log` holds the twig's slots, for [`FileEntries::offset`]:
    /// the read view resolves byte offsets into `entries.log`, which keeps
    /// every record in this stage. 16 KiB a compacted twig; stage 1 (a view
    /// that resolves slots) and stage 3 (punching) retire it.
    main: Box<[u64]>,
    /// The length of the twig's latest group in `entries.relocated`,
    /// trailer included.
    group_len: u64,
    /// The dead slots the latest group stored as hashes.
    dead: u32,
}

/// What [`FileEntries::append_group`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Relocation {
    /// The group's bytes, trailer included.
    pub(crate) written: u64,
    /// The bytes the twig's previous location held: its records in
    /// `entries.log`, or its previous group. Nothing is punched yet.
    pub(crate) reclaimable: u64,
}

/// A twig's records laid out as a relocated group
/// ([`FileEntries::build_group`]), not yet written.
#[derive(Debug)]
pub(crate) struct Group {
    twig: usize,
    bytes: Vec<u8>,
    /// Each slot's record start within `bytes`.
    starts: Box<[u32]>,
    /// The slots stored as hashes.
    dead: u32,
    /// Each slot's leaf hash, hashed from the group's own bytes.
    pub(crate) leaves: Box<[Hash]>,
}

/// The append-only entry file, mapped for reads.
pub(crate) struct FileEntries {
    /// `entries.log`: one record per slot, in slot order.
    main: LogFile,
    /// `entries.relocated`, once a twig has been compacted (or found on
    /// open): the compacted twigs' groups.
    relocated: Option<LogFile>,
    /// The twigs whose offsets point into `relocated`, by twig id.
    twigs: BTreeMap<usize, RelocatedTwig>,
    /// Where each slot's record starts; bit 63 set: in `relocated`.
    offsets: Offsets,
    /// One bit per slot.
    active: Vec<u64>,
}

impl std::fmt::Debug for FileEntries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileEntries")
            .field("path", &self.main.path)
            .field("slots", &self.offsets.len())
            .field("bytes", &self.main.len_bytes)
            .field("chunks", &self.main.chunks.len())
            .finish_non_exhaustive()
    }
}

impl FileEntries {
    /// Creates (truncating) the file at `path`. A relocated file left
    /// beside it is removed: its groups name slots of the file just emptied.
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        let main = LogFile::create(path, true)?;
        match std::fs::remove_file(relocated_path(path)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(Self { main, relocated: None, twigs: BTreeMap::new(), offsets: Offsets::default(), active: Vec::new() })
    }

    /// Opens the file at `path` as it was left, keeping at most `slots`
    /// records: the records are walked in order, a torn or surplus tail
    /// (records past `slots`, or a record cut short) is dropped and the
    /// file shortened to match, and `active` says which slots are live
    /// (missing bits read as dead). Returns the store and how many records
    /// it holds.
    pub(crate) fn open_existing(path: &Path, slots: u64, active: &[u64]) -> io::Result<(Self, u64)> {
        Self::open_existing_mode(path, slots, active, true)
    }

    /// Reads a historical prefix without shortening the live entry file.
    pub(crate) fn open_existing_readonly(path: &Path, slots: u64, active: &[u64]) -> io::Result<(Self, u64)> {
        Self::open_existing_mode(path, slots, active, false)
    }

    fn open_existing_mode(path: &Path, slots: u64, active: &[u64], truncate: bool) -> io::Result<(Self, u64)> {
        let mut file = OpenOptions::new().read(true).write(truncate).open(path)?;
        let len = file.metadata()?.len();
        // Walk the record headers: a scan of the whole file's bytes, in
        // 64 MB pieces so the tree's rebuild does not hold the file twice.
        use std::io::Read;
        let mut offsets: Vec<u64> = Vec::new();
        let mut at = 0u64;
        let mut header = [0u8; KEY_LEN + LEN_LEN];
        file.seek(io::SeekFrom::Start(0))?;
        let mut reader = std::io::BufReader::with_capacity(8 << 20, &mut file);
        while (offsets.len() as u64) < slots && at + (KEY_LEN + LEN_LEN) as u64 <= len {
            reader.read_exact(&mut header)?;
            let value_len = u32::from_le_bytes([header[32], header[33], header[34], header[35]]) as u64;
            let end = at + (KEY_LEN + LEN_LEN) as u64 + value_len;
            if end > len {
                break; // torn tail
            }
            offsets.push(at);
            // Skip the value.
            std::io::copy(&mut reader.by_ref().take(value_len), &mut std::io::sink())?;
            at = end;
        }
        drop(reader);
        let kept = offsets.len() as u64;
        let len_bytes = at;
        if truncate {
            file.set_len(len_bytes)?;
        }
        let mut main = LogFile::new(path.to_path_buf(), file, len_bytes, true);
        // Everything on disk is sealed into chunks; the tail starts empty.
        main.seal_existing(&offsets)?;
        let mut twigs = BTreeMap::new();
        let relocated = open_relocated(&relocated_path(path), &mut offsets, &mut twigs, truncate)?;
        let mut store = Self {
            main,
            relocated,
            twigs,
            offsets: Offsets::from_vec(offsets),
            active: vec![0u64; (kept as usize).div_ceil(64)],
        };
        for (word, bits) in store.active.iter_mut().zip(active) {
            *word = *bits;
        }
        // Bits past the kept slots are cleared.
        for slot in kept as usize..store.active.len() * 64 {
            store.set_active(slot, false);
        }
        Ok((store, kept))
    }

    /// The store's size ([`EntryStoreStats`]) with `live` active slots (the
    /// tree's index length); `index_bytes` is the tree's.
    fn stats(&self, live: usize) -> EntryStoreStats {
        EntryStoreStats {
            mode: EntryStoreMode::File,
            total_slots: self.offsets.len() as u64,
            live_slots: live as u64,
            file_bytes: self.main.len_bytes,
            offsets_bytes: (self.offsets.segments.len() * crate::prefault::OFFSET_SEGMENT_SLOTS * 8) as u64,
            index_bytes: 0,
            chunks: self.main.chunks.len() as u64,
            relocated_bytes: self.relocated_len(),
        }
    }

    /// Bytes of `entries.relocated` that belong to complete groups.
    pub(crate) fn relocated_len(&self) -> u64 {
        self.relocated.as_ref().map_or(0, |file| file.len_bytes)
    }

    /// The active bits, one per slot, 64 to a word.
    pub(crate) fn active_bits(&self) -> &[u64] {
        &self.active
    }

    /// The file this store appends to.
    pub(crate) fn path(&self) -> &Path {
        &self.main.path
    }

    /// `slot`'s content, wherever its record is. A record's end comes from
    /// its own length field, not from the next slot's offset, which may
    /// point into the other file.
    pub(crate) fn read(&self, slot: usize) -> SlotRef<'_> {
        let raw = self.offsets[slot];
        if raw & RELOCATED_BIT == 0 {
            return payload_at(self.main.bytes_from(raw));
        }
        let Some(file) = self.relocated.as_ref() else {
            unreachable!("slot {slot} names a relocated record without a relocated file");
        };
        let bytes = file.bytes_from(raw & !RELOCATED_BIT);
        match bytes[0] {
            TAG_DEAD => SlotRef::HashOnly(as_hash(&bytes[RELOCATED_HEAD..DEAD_RECORD])),
            tag => {
                debug_assert_eq!(tag, TAG_LIVE, "slot {slot}'s relocated record");
                payload_at(&bytes[RELOCATED_HEAD..])
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Where `slot`'s record starts in `entries.log`: the main file keeps
    /// every slot's record in this stage, a compacted one included, so the
    /// read view's byte offsets stay valid.
    pub(crate) fn offset(&self, slot: usize) -> Option<u64> {
        let raw = self.offsets.get(slot)?;
        if raw & RELOCATED_BIT == 0 {
            return Some(raw);
        }
        self.twigs.get(&(slot / TWIG_SIZE)).map(|twig| twig.main[slot % TWIG_SIZE])
    }

    /// `slot`'s key, `None` for a hash-only slot: the key index's
    /// confirmation read, so a record in the main file -- every slot but a
    /// compacted one -- is read without its length.
    fn key(&self, slot: usize) -> Option<&Hash> {
        let raw = self.offsets[slot];
        if raw & RELOCATED_BIT == 0 {
            return Some(as_hash(&self.main.bytes_from(raw)[..KEY_LEN]));
        }
        match self.read(slot) {
            SlotRef::Payload(key, _) => Some(key),
            SlotRef::HashOnly(_) => None,
        }
    }

    /// Tests: a slot's value, which must have its payload.
    #[cfg(test)]
    fn value(&self, slot: usize) -> &[u8] {
        match self.read(slot) {
            SlotRef::Payload(_, value) => value,
            SlotRef::HashOnly(_) => panic!("slot {slot} is hash-only"),
        }
    }

    /// Whether any slot keeps only its leaf hash.
    pub(crate) fn has_hash_only(&self) -> bool {
        self.twigs.values().any(|twig| twig.dead > 0)
    }

    /// The dead slots `twig`'s latest group stored as hashes, if it has one.
    pub(crate) fn relocated_dead(&self, twig: usize) -> Option<u32> {
        self.twigs.get(&twig).map(|twig| twig.dead)
    }

    /// The highest relocated twig's id.
    pub(crate) fn last_relocated_twig(&self) -> Option<usize> {
        self.twigs.keys().next_back().copied()
    }

    pub(crate) fn is_active(&self, slot: usize) -> bool {
        (self.active[slot / 64] >> (slot % 64)) & 1 == 1
    }

    pub(crate) fn set_active(&mut self, slot: usize, active: bool) {
        if active {
            self.active[slot / 64] |= 1 << (slot % 64);
        } else {
            self.active[slot / 64] &= !(1 << (slot % 64));
        }
    }

    /// Appends a live entry as the next slot: into the tail, which reaches
    /// the file at the next `flush` (a sync, a sealed chunk, a truncation).
    pub(crate) fn push(&mut self, key: &Hash, value: &[u8]) -> io::Result<()> {
        self.main.writable()?;
        let slot = self.offsets.len();
        let record_len = KEY_LEN + LEN_LEN + value.len();
        // Sealed before the record that would not fit rather than after the
        // one that overflowed: the tail never outgrows `CHUNK_BYTES`, so its
        // buffer, reserved once, is never reallocated. It used to grow past
        // the chunk by doubling -- a 256 MiB copy into 512 MiB of fresh pages
        // inside a block's apply, under the tree's lock, every chunk.
        let main = &mut self.main;
        if !main.tail.is_empty() && main.tail.len() + record_len > CHUNK_BYTES {
            main.seal_tail()?;
        }
        if main.tail.capacity() < CHUNK_BYTES {
            main.tail.reserve_exact(CHUNK_BYTES.max(record_len) - main.tail.len());
        }
        main.populate_ahead();
        crate::prefault::note_append(main.populate_epoch, main.tail.len() + record_len);
        main.tail.extend_from_slice(key);
        main.tail.extend_from_slice(&(value.len() as u32).to_le_bytes());
        main.tail.extend_from_slice(value);
        self.offsets.push(main.len_bytes);
        main.len_bytes += record_len as u64;
        if self.active.len() * 64 <= slot {
            self.active.push(0);
        }
        self.set_active(slot, true);
        Ok(())
    }

    /// [`Self::push`] for a block's records, one structure at a time -- the
    /// tail's bytes, then the offsets, then the active bits -- so the
    /// applying thread's page faults can be told apart per structure
    /// (`faults`). The file, the offsets and the bits end as the same
    /// sequence of `push` calls leaves them; a failed seal keeps the records
    /// copied before it, whole, as `push` would have.
    fn push_batch<'a>(
        &mut self,
        records: impl Iterator<Item = (&'a Hash, &'a [u8])> + Clone,
        faults: &mut AppendFaults,
    ) -> io::Result<()> {
        self.main.writable()?;
        let first_slot = self.offsets.len();
        let first_byte = self.main.len_bytes;
        let at = crate::prefault::thread_faults();
        let mut copied = 0usize;
        let mut sealed = Ok(());
        let main = &mut self.main;
        for (key, value) in records.clone() {
            let record_len = KEY_LEN + LEN_LEN + value.len();
            if !main.tail.is_empty()
                && main.tail.len() + record_len > CHUNK_BYTES
                && let Err(error) = main.seal_tail()
            {
                sealed = Err(error);
                break;
            }
            if main.tail.capacity() < CHUNK_BYTES {
                main.tail.reserve_exact(CHUNK_BYTES.max(record_len) - main.tail.len());
            }
            main.populate_ahead();
            crate::prefault::note_append(main.populate_epoch, main.tail.len() + record_len);
            main.tail.extend_from_slice(key);
            main.tail.extend_from_slice(&(value.len() as u32).to_le_bytes());
            main.tail.extend_from_slice(value);
            // A seal maps up to here, so the length moves with the bytes.
            main.len_bytes += record_len as u64;
            copied += 1;
        }
        let entries_done = crate::prefault::thread_faults();
        faults.entries += entries_done.saturating_sub(at);
        let mut offset = first_byte;
        for (_, value) in records.take(copied) {
            self.offsets.push(offset);
            offset += (KEY_LEN + LEN_LEN + value.len()) as u64;
        }
        let offsets_done = crate::prefault::thread_faults();
        faults.offsets += offsets_done.saturating_sub(entries_done);
        for slot in first_slot..first_slot + copied {
            if self.active.len() * 64 <= slot {
                self.active.push(0);
            }
            self.set_active(slot, true);
        }
        faults.bits += crate::prefault::thread_faults().saturating_sub(offsets_done);
        sealed
    }

    /// [`Self::push_batch`] with the record bytes copied on the worker pool
    /// (`N42_QMDB_PARALLEL_APPLY`): `count` records, the `k`-th of them
    /// `record(k)`. The records are split where `push` would seal the tail
    /// -- before the record that would not fit in it -- and each run between
    /// seals is laid out by its records' lengths and copied in pieces beside
    /// each other; the offsets and the active bits are then written a run at
    /// a time. The file, the tail, the offsets and the bits end as the same
    /// sequence of `push` calls leaves them, and a failed seal keeps the
    /// runs copied before it, whole.
    #[cfg(feature = "rayon")]
    fn push_batch_parallel<'a>(&mut self, count: usize, record: &(impl Fn(usize) -> (&'a Hash, &'a [u8]) + Sync)) -> io::Result<()> {
        use rayon::prelude::*;
        self.main.writable()?;
        let lens: Vec<usize> = (0..count).into_par_iter().with_min_len(4096).map(|k| KEY_LEN + LEN_LEN + record(k).1.len()).collect();
        let mut from = 0usize;
        while from < count {
            let main = &mut self.main;
            // The run that fits in the tail before `push` would seal it.
            let room = CHUNK_BYTES.saturating_sub(main.tail.len());
            let (mut to, mut bytes) = (from, 0usize);
            while to < count && (bytes + lens[to] <= room || (to == from && main.tail.is_empty())) {
                bytes += lens[to];
                to += 1;
            }
            if to == from {
                main.seal_tail()?;
                continue;
            }
            if main.tail.capacity() < CHUNK_BYTES {
                main.tail.reserve_exact(CHUNK_BYTES.max(main.tail.len() + bytes) - main.tail.len());
            }
            main.tail.reserve(bytes);
            main.populate_ahead();
            crate::prefault::note_append(main.populate_epoch, main.tail.len() + bytes);
            // Each record's start within the run, and the run cut into
            // pieces of whole records for the pool.
            let mut starts: Vec<u64> = Vec::with_capacity(to - from);
            let mut at = 0usize;
            for len in &lens[from..to] {
                starts.push(at as u64);
                at += len;
            }
            const PIECE: usize = 2048;
            let base = main.tail.len();
            {
                let mut spare = &mut main.tail.spare_capacity_mut()[..bytes];
                let mut pieces = Vec::with_capacity((to - from).div_ceil(PIECE));
                let mut first = from;
                while first < to {
                    let last = (first + PIECE).min(to);
                    let piece_bytes = lens[first..last].iter().sum::<usize>();
                    let (head, rest) = std::mem::take(&mut spare).split_at_mut(piece_bytes);
                    pieces.push((first, last, head));
                    spare = rest;
                    first = last;
                }
                pieces.into_par_iter().for_each(|(first, last, out)| {
                    let mut at = 0usize;
                    for k in first..last {
                        let (key, value) = record(k);
                        out[at..at + KEY_LEN].write_copy_of_slice(key);
                        at += KEY_LEN;
                        out[at..at + LEN_LEN].write_copy_of_slice(&(value.len() as u32).to_le_bytes());
                        at += LEN_LEN;
                        out[at..at + value.len()].write_copy_of_slice(value);
                        at += value.len();
                    }
                });
            }
            // SAFETY: `reserve` above made room for `bytes` past the length,
            // and the pieces cover `[base, base + bytes)` exactly -- each
            // piece is its records' summed lengths, cut in order -- and every
            // byte of a piece was written by the loop that owned it (a record
            // writes its key, its length and its value, `lens[k]` bytes in
            // all). A panic in a piece propagates out of `for_each` before
            // this line, leaving the length where it was.
            unsafe { main.tail.set_len(base + bytes) };
            let first_slot = self.offsets.len();
            let first_byte = main.len_bytes;
            for start in &mut starts {
                *start += first_byte;
            }
            main.len_bytes += bytes as u64;
            self.offsets.extend_from_slice(&starts);
            self.set_active_run(first_slot, first_slot + (to - from));
            from = to;
        }
        Ok(())
    }

    /// Marks slots `[from, to)` live, a word at a time, growing the bits as
    /// `push` does.
    #[cfg(feature = "rayon")]
    fn set_active_run(&mut self, from: usize, to: usize) {
        if self.active.len() * 64 < to {
            self.active.resize(to.div_ceil(64), 0);
        }
        let mut slot = from;
        while slot < to {
            let bit = slot % 64;
            let run = (64 - bit).min(to - slot);
            let mask = if run == 64 { u64::MAX } else { ((1u64 << run) - 1) << bit };
            self.active[slot / 64] |= mask;
            slot += run;
        }
    }

    /// Writes what the tail still holds and makes every record durable.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        self.main.sync()
    }

    /// Writes what the tail still holds and hands back a second handle on
    /// the file, so the caller can `sync_data` it without holding whatever
    /// lock guards this store: the fsync of a block's ~20 MB is tens of
    /// milliseconds, and under the forest lock it stalled the builder and
    /// the importer on every block (loop126).
    pub(crate) fn flush_for_sync(&mut self) -> io::Result<File> {
        self.main.flush()?;
        self.main.file.try_clone()
    }

    /// Drops every slot from `len` on, and shortens the file to match.
    /// Refused (`InvalidInput`) if a slot from `len` on is relocated:
    /// `entries.relocated` is never cut, so its group would rename the slots
    /// appended in their place on the next open. Compaction takes only twigs
    /// below the undo horizon, so an undo never gets here.
    pub(crate) fn truncate(&mut self, len: usize) -> io::Result<()> {
        if len >= self.offsets.len() {
            return Ok(());
        }
        self.main.writable()?;
        if let Some(twig) = self.last_relocated_twig().filter(|twig| (twig + 1) * TWIG_SIZE > len) {
            return Err(refused(format!(
                "{}: a truncation to slot {len} would cut into relocated twig {twig}",
                self.main.path.display()
            )));
        }
        let new_len_bytes = self.offsets[len];
        self.offsets.truncate(len);
        for slot in len..self.active.len() * 64 {
            self.set_active(slot, false);
        }
        self.active.truncate(len.div_ceil(64));
        self.main.cut(new_len_bytes)
    }

    /// Reserves room for `additional` more slots' bookkeeping.
    pub(crate) fn reserve(&mut self, additional: usize) {
        // The offsets grow a segment at a time (`Offsets`).
        self.active.reserve(additional.div_ceil(64));
    }

    /// A second, read-only handle on the same file with the same
    /// bookkeeping, for a tree that is cloned: it reads what the original
    /// had (its unwritten tail included, from memory) and refuses every
    /// append, truncation and write, since two handles writing one file
    /// would corrupt it and a clone cutting it would pull the original's
    /// sealed mappings out from under it (`SIGBUS`).
    pub(crate) fn duplicate(&self) -> io::Result<Self> {
        Ok(Self {
            main: self.main.duplicate()?,
            relocated: self.relocated.as_ref().map(LogFile::duplicate).transpose()?,
            twigs: self.twigs.clone(),
            offsets: self.offsets.clone(),
            active: self.active.clone(),
        })
    }

    /// Lays `twig`'s 2048 slots out as a relocated group (module doc): a
    /// live slot's payload as it is, a dead slot's leaf hash -- `leaf(slot)`
    /// if it names one, else the slot's own (stored, or hashed from its
    /// payload). The leaf hashes are hashed from the group's own bytes, for
    /// the caller to check against the twig before anything is written.
    pub(crate) fn build_group(&self, twig: usize, leaf: impl Fn(usize) -> Option<Hash>) -> io::Result<Group> {
        let base = twig * TWIG_SIZE;
        if base + TWIG_SIZE > self.len() {
            return Err(refused(format!("twig {twig} is not full ({} slots)", self.len())));
        }
        let mut bytes = Vec::new();
        let mut starts = Vec::with_capacity(TWIG_SIZE);
        let mut leaves = Vec::with_capacity(TWIG_SIZE);
        let mut dead = 0u32;
        for slot in base..base + TWIG_SIZE {
            let start = bytes.len();
            starts.push(u32::try_from(start).map_err(|_| refused(format!("twig {twig}'s group passes 4 GiB")))?);
            if self.is_active(slot) {
                let SlotRef::Payload(key, value) = self.read(slot) else {
                    return Err(refused(format!("live slot {slot} has no payload")));
                };
                let len = u32::try_from(value.len()).map_err(|_| refused(format!("slot {slot}'s value passes 4 GiB")))?;
                bytes.push(TAG_LIVE);
                bytes.extend_from_slice(&(slot as u64).to_le_bytes());
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(&len.to_le_bytes());
                bytes.extend_from_slice(value);
                let payload = &bytes[start + RELOCATED_HEAD..];
                leaves.push(hash_leaf(as_hash(&payload[..KEY_LEN]), &payload[KEY_LEN + LEN_LEN..]));
            } else {
                let hash = leaf(slot).unwrap_or_else(|| self.read(slot).leaf_hash());
                bytes.push(TAG_DEAD);
                bytes.extend_from_slice(&(slot as u64).to_le_bytes());
                bytes.extend_from_slice(&hash);
                leaves.push(*as_hash(&bytes[start + RELOCATED_HEAD..start + DEAD_RECORD]));
                dead += 1;
            }
        }
        bytes.push(TAG_END);
        bytes.extend_from_slice(&(twig as u64).to_le_bytes());
        let crc = crc32fast::hash(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        Ok(Group { twig, bytes, starts: starts.into_boxed_slice(), dead, leaves: leaves.into_boxed_slice() })
    }

    /// Appends `group` to `entries.relocated` (created on the first one),
    /// makes it durable, then points its twig's 2048 offsets at it. A
    /// failure before the retarget leaves every slot where it was; a group
    /// left complete in the file by one is applied by the next open, which
    /// is harmless, since it holds what the slots hold.
    pub(crate) fn append_group(&mut self, group: Group) -> io::Result<Relocation> {
        self.main.writable()?;
        let twig = group.twig;
        let base = twig * TWIG_SIZE;
        // What the twig's records take where they are now.
        let reclaimable = match self.twigs.get(&twig) {
            Some(relocated) => relocated.group_len,
            None => {
                let first = self.offsets[base];
                let last = self.offsets[base + TWIG_SIZE - 1];
                debug_assert_eq!((first | last) & RELOCATED_BIT, 0);
                let SlotRef::Payload(_, value) = payload_at(self.main.bytes_from(last)) else { unreachable!() };
                last + (KEY_LEN + LEN_LEN + value.len()) as u64 - first
            }
        };
        if self.relocated.is_none() {
            let path = relocated_path(&self.main.path);
            let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
            self.relocated = Some(LogFile::new(path, file, 0, false));
        }
        let Some(file) = self.relocated.as_mut() else { unreachable!("created above") };
        let start = file.append_unit(&group.bytes)?;
        // Durable before any slot points at it.
        file.sync()?;
        let main: Box<[u64]> = match self.twigs.remove(&twig) {
            Some(relocated) => relocated.main,
            None => (base..base + TWIG_SIZE).map(|slot| self.offsets[slot]).collect(),
        };
        for (local, at) in group.starts.iter().enumerate() {
            self.offsets.set(base + local, (start + u64::from(*at)) | RELOCATED_BIT);
        }
        let written = group.bytes.len() as u64;
        self.twigs.insert(twig, RelocatedTwig { main, group_len: written, dead: group.dead });
        Ok(Relocation { written, reclaimable })
    }

    /// Seals the tail now (tests: exercise the chunked reads without
    /// appending 256 MB).
    #[cfg(test)]
    fn seal_now(&mut self) -> io::Result<()> {
        self.main.seal_tail()
    }
}

/// A `[key 32][len u32][value]` record at the start of `bytes`.
fn payload_at(bytes: &[u8]) -> SlotRef<'_> {
    let len = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;
    SlotRef::Payload(as_hash(&bytes[..KEY_LEN]), &bytes[KEY_LEN + LEN_LEN..KEY_LEN + LEN_LEN + len])
}

fn as_hash(bytes: &[u8]) -> &Hash {
    bytes.try_into().expect("a 32-byte range")
}

/// Opens `entries.relocated` at `path`, if there is one, and retargets
/// `offsets` (the main file's, one per kept slot) to every complete group in
/// it, in file order, so the latest group of a twig wins; `twigs` records
/// each relocated twig with its `entries.log` offsets.
///
/// The walk stops at the first group that is torn, fails its CRC, is not
/// exactly one twig's 2048 slots in order, or names a twig not wholly within
/// the kept slots (an open that keeps a shorter prefix, or a main file cut
/// short); with `truncate` the file is cut there, as a torn tail of the main
/// file is. Losing a group loses nothing in this stage: `entries.log` still
/// holds every slot's record, and nothing is punched.
///
/// Groups past what the checkpoint recorded (`relocated_len`) are applied
/// like the rest when complete: a group only says where a slot's unchanged
/// content is, so applying one written after the checkpoint is idempotent.
fn open_relocated(
    path: &Path,
    offsets: &mut [u64],
    twigs: &mut BTreeMap<usize, RelocatedTwig>,
    truncate: bool,
) -> io::Result<Option<LogFile>> {
    use std::io::Read;
    let mut file = match OpenOptions::new().read(true).write(truncate).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let len = file.metadata()?.len();
    let mut good = 0u64;
    let mut group_starts = Vec::new();
    {
        file.seek(io::SeekFrom::Start(0))?;
        let mut reader = std::io::BufReader::with_capacity(8 << 20, &mut file);
        let mut starts = vec![0u64; TWIG_SIZE];
        let mut value = Vec::new();
        'groups: loop {
            let group_start = good;
            let mut at = good;
            let mut crc = crc32fast::Hasher::new();
            let mut dead_hash_count = 0u32;
            let mut twig = None;
            for local in 0..TWIG_SIZE {
                let mut head = [0u8; RELOCATED_HEAD];
                if at + RELOCATED_HEAD as u64 > len || reader.read_exact(&mut head).is_err() {
                    break 'groups;
                }
                let slot = u64::from_le_bytes(head[1..9].try_into().expect("8 bytes")) as usize;
                let expected = *twig.get_or_insert(slot / TWIG_SIZE) * TWIG_SIZE + local;
                if slot != expected {
                    break 'groups;
                }
                crc.update(&head);
                starts[local] = at;
                match head[0] {
                    TAG_LIVE => {
                        let mut header = [0u8; KEY_LEN + LEN_LEN];
                        if at + (RELOCATED_HEAD + KEY_LEN + LEN_LEN) as u64 > len || reader.read_exact(&mut header).is_err() {
                            break 'groups;
                        }
                        let value_len = u32::from_le_bytes([header[32], header[33], header[34], header[35]]) as u64;
                        let end = at + (RELOCATED_HEAD + KEY_LEN + LEN_LEN) as u64 + value_len;
                        if end > len {
                            break 'groups;
                        }
                        value.resize(value_len as usize, 0);
                        if reader.read_exact(&mut value).is_err() {
                            break 'groups;
                        }
                        crc.update(&header);
                        crc.update(&value);
                        at = end;
                    }
                    TAG_DEAD => {
                        let mut hash = [0u8; 32];
                        if at + DEAD_RECORD as u64 > len || reader.read_exact(&mut hash).is_err() {
                            break 'groups;
                        }
                        crc.update(&hash);
                        dead_hash_count += 1;
                        at += DEAD_RECORD as u64;
                    }
                    _ => break 'groups,
                }
            }
            let Some(twig) = twig else { break };
            let mut trailer = [0u8; TRAILER];
            if at + TRAILER as u64 > len || reader.read_exact(&mut trailer).is_err() {
                break;
            }
            crc.update(&trailer[..9]);
            if trailer[0] != TAG_END
                || u64::from_le_bytes(trailer[1..9].try_into().expect("8 bytes")) != twig as u64
                || u32::from_le_bytes(trailer[9..13].try_into().expect("4 bytes")) != crc.finalize()
            {
                break;
            }
            let base = twig * TWIG_SIZE;
            if base + TWIG_SIZE > offsets.len() {
                break;
            }
            at += TRAILER as u64;
            let main = &mut offsets[base..base + TWIG_SIZE];
            let entry = twigs.entry(twig).or_insert_with(|| RelocatedTwig {
                main: main.iter().copied().collect(),
                group_len: 0,
                dead: 0,
            });
            entry.group_len = at - group_start;
            entry.dead = dead_hash_count;
            for (offset, start) in main.iter_mut().zip(&starts) {
                *offset = start | RELOCATED_BIT;
            }
            group_starts.push(group_start);
            good = at;
        }
    }
    if truncate && good < len {
        file.set_len(good)?;
    }
    let mut log = LogFile::new(path.to_path_buf(), file, good, false);
    log.seal_existing(&group_starts)?;
    Ok(Some(log))
}

/// The applying thread's page faults in a batch append, per structure.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AppendFaults {
    /// The record bytes copied into the tail buffer.
    pub(crate) entries: u64,
    /// The offsets' segments.
    pub(crate) offsets: u64,
    /// The active bits.
    pub(crate) bits: u64,
}

/// The tree's entries, wherever they live.
#[derive(Debug)]
pub(crate) enum Entries {
    /// Every entry in the heap.
    Heap(Vec<Entry>),
    /// Entries in the append-only file; offsets and active bits in the heap.
    File(FileEntries),
}

impl Entries {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Heap(entries) => entries.len(),
            Self::File(file) => file.len(),
        }
    }

    /// `slot`'s content: its payload, or only its leaf hash.
    pub(crate) fn read(&self, slot: usize) -> SlotRef<'_> {
        match self {
            Self::Heap(entries) => {
                let entry = &entries[slot];
                if entry.hash_only { SlotRef::HashOnly(&entry.key) } else { SlotRef::Payload(&entry.key, &entry.value) }
            }
            Self::File(file) => file.read(slot),
        }
    }

    /// The key of a slot that has its payload: every slot the key index
    /// names (they are live), and every slot appended since the undo horizon.
    /// A hash-only slot has none; it reads as the null hash, which no key
    /// lookup matches, and a debug build stops there.
    pub(crate) fn key(&self, slot: usize) -> Hash {
        let key = match self {
            Self::Heap(entries) => (!entries[slot].hash_only).then_some(&entries[slot].key),
            Self::File(file) => file.key(slot),
        };
        match key {
            Some(key) => *key,
            None => {
                debug_assert!(false, "the key of hash-only slot {slot} was read");
                NULL_HASH
            }
        }
    }

    /// The value of a slot that has its payload ([`Self::key`]); a
    /// hash-only slot reads as empty, and a debug build stops there.
    pub(crate) fn value(&self, slot: usize) -> &[u8] {
        match self.read(slot) {
            SlotRef::Payload(_, value) => value,
            SlotRef::HashOnly(_) => {
                debug_assert!(false, "the value of hash-only slot {slot} was read");
                &[]
            }
        }
    }

    /// `slot`'s key and value, `None` for a hash-only slot.
    pub(crate) fn payload(&self, slot: usize) -> Option<(&Hash, &[u8])> {
        match self.read(slot) {
            SlotRef::Payload(key, value) => Some((key, value)),
            SlotRef::HashOnly(_) => None,
        }
    }

    /// `slot`'s leaf hash: stored for a hash-only slot, hashed from the
    /// payload for the rest.
    pub(crate) fn leaf_hash(&self, slot: usize) -> Hash {
        self.read(slot).leaf_hash()
    }

    /// Whether `slot` keeps only its leaf hash.
    pub(crate) fn is_hash_only(&self, slot: usize) -> bool {
        matches!(self.read(slot), SlotRef::HashOnly(_))
    }

    pub(crate) fn is_active(&self, slot: usize) -> bool {
        match self {
            Self::Heap(entries) => entries[slot].active,
            Self::File(file) => file.is_active(slot),
        }
    }

    pub(crate) fn set_active(&mut self, slot: usize, active: bool) {
        match self {
            Self::Heap(entries) => entries[slot].active = active,
            Self::File(file) => file.set_active(slot, active),
        }
    }

    pub(crate) fn entry(&self, slot: usize) -> SlotEntry {
        let content = match self.read(slot) {
            SlotRef::Payload(key, value) => SlotContent::Payload { key: *key, value: value.to_vec() },
            SlotRef::HashOnly(hash) => SlotContent::HashOnly { leaf_hash: *hash },
        };
        SlotEntry { content, active: self.is_active(slot) }
    }

    /// Appends a dead slot that keeps only its leaf hash (a heap tree
    /// rebuilt from a compacted tree's snapshot); refused in the file, where
    /// such a slot exists only in a relocated group.
    pub(crate) fn push_hash_only(&mut self, leaf_hash: Hash) -> io::Result<()> {
        match self {
            Self::Heap(entries) => {
                entries.push(Entry { key: leaf_hash, value: Vec::new(), active: false, hash_only: true });
                Ok(())
            }
            Self::File(_) => Err(refused("a hash-only slot cannot be appended to the entry file".to_owned())),
        }
    }

    /// Bytes of `entries.relocated` in complete groups; 0 in the heap.
    pub(crate) fn relocated_len(&self) -> u64 {
        match self {
            Self::Heap(_) => 0,
            Self::File(file) => file.relocated_len(),
        }
    }

    /// [`Self::push`] on borrowed bytes for every record of `records` in order, counting
    /// the applying thread's page faults per structure into `faults` (the
    /// heap's all go to `entries`).
    pub(crate) fn push_batch<'a>(
        &mut self,
        records: impl Iterator<Item = (&'a Hash, &'a [u8])> + Clone,
        faults: &mut AppendFaults,
    ) -> io::Result<()> {
        match self {
            Self::Heap(entries) => {
                let at = crate::prefault::thread_faults();
                entries.extend(records.map(|(key, value)| Entry { key: *key, value: value.to_vec(), active: true, hash_only: false }));
                faults.entries += crate::prefault::thread_faults().saturating_sub(at);
                Ok(())
            }
            Self::File(file) => {
                #[cfg(feature = "failpoints")]
                if let Some(keep) = failpoints::take(&file.main.path) {
                    file.push_batch(records.take(keep), faults)?;
                    return Err(failpoints::injected());
                }
                file.push_batch(records, faults)
            }
        }
    }

    /// [`Self::push_batch`] for `count` records, the `k`-th of them
    /// `record(k)`, written on the worker pool (`N42_QMDB_PARALLEL_APPLY`):
    /// the same entries in the same order.
    #[cfg(feature = "rayon")]
    pub(crate) fn push_batch_parallel<'a>(
        &mut self,
        count: usize,
        record: &(impl Fn(usize) -> (&'a Hash, &'a [u8]) + Sync),
    ) -> io::Result<()> {
        use rayon::prelude::*;
        match self {
            Self::Heap(entries) => {
                entries.par_extend((0..count).into_par_iter().with_min_len(1024).map(|k| {
                    let (key, value) = record(k);
                    Entry { key: *key, value: value.to_vec(), active: true, hash_only: false }
                }));
                Ok(())
            }
            Self::File(file) => {
                #[cfg(feature = "failpoints")]
                if let Some(keep) = failpoints::take(&file.main.path) {
                    file.push_batch_parallel(count.min(keep), record)?;
                    return Err(failpoints::injected());
                }
                file.push_batch_parallel(count, record)
            }
        }
    }

    /// Appends a live entry as the next slot.
    pub(crate) fn push(&mut self, key: Hash, value: Vec<u8>) -> io::Result<()> {
        match self {
            Self::Heap(entries) => {
                entries.push(Entry { key, value, active: true, hash_only: false });
                Ok(())
            }
            Self::File(file) => {
                #[cfg(feature = "failpoints")]
                if failpoints::take(&file.main.path).is_some() {
                    return Err(failpoints::injected());
                }
                file.push(&key, &value)
            }
        }
    }

    pub(crate) fn truncate(&mut self, len: usize) -> io::Result<()> {
        match self {
            Self::Heap(entries) => {
                entries.truncate(len);
                Ok(())
            }
            Self::File(file) => {
                #[cfg(feature = "failpoints")]
                if failpoints::take_truncate(&file.main.path) {
                    return Err(failpoints::injected());
                }
                file.truncate(len)
            }
        }
    }

    /// Where `slot`'s record starts in the entry file; `None` in the heap or
    /// past the last slot.
    pub(crate) fn file_offset(&self, slot: usize) -> Option<u64> {
        match self {
            Self::Heap(_) => None,
            Self::File(file) => file.offset(slot),
        }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        match self {
            Self::Heap(entries) => entries.reserve(additional),
            Self::File(file) => file.reserve(additional),
        }
    }

    /// Clears the active flag of every slot `held` names: one write a slot,
    /// in the heap as in the file, so the cost is the block's and not the
    /// state's (the heap used to scan a bitmap over every slot).
    pub(crate) fn retire(&mut self, held: &[Option<u64>]) {
        match self {
            Self::Heap(entries) => {
                for slot in held.iter().flatten() {
                    let entry = &mut entries[*slot as usize];
                    debug_assert!(entry.active, "the index named an inactive slot");
                    entry.active = false;
                }
            }
            Self::File(file) => {
                for slot in held.iter().flatten() {
                    debug_assert!(file.is_active(*slot as usize), "the index named an inactive slot");
                    file.set_active(*slot as usize, false);
                }
            }
        }
    }

    /// Makes the file's appends durable; nothing to do for the heap.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        match self {
            Self::Heap(_) => Ok(()),
            Self::File(file) => file.sync(),
        }
    }

    /// Writes the file's pending appends and returns a handle to fsync
    /// later, outside the tree's lock; `None` for the heap.
    pub(crate) fn flush_for_sync(&mut self) -> io::Result<Option<File>> {
        match self {
            Self::Heap(_) => Ok(None),
            Self::File(file) => file.flush_for_sync().map(Some),
        }
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Heap(entries) => Ok(Self::Heap(entries.clone())),
            Self::File(file) => file.duplicate().map(Self::File),
        }
    }

    /// The active bits, one per slot, 64 to a word (built from the entries
    /// in the heap).
    pub(crate) fn active_bits(&self) -> Vec<u64> {
        match self {
            Self::Heap(entries) => {
                let mut bits = vec![0u64; entries.len().div_ceil(64)];
                for (slot, entry) in entries.iter().enumerate() {
                    if entry.active {
                        bits[slot / 64] |= 1 << (slot % 64);
                    }
                }
                bits
            }
            Self::File(file) => file.active_bits().to_vec(),
        }
    }

    /// The store's size ([`EntryStoreStats`]); `live_slots` is `live`, the
    /// caller's count (a scan here would be linear in the slots), and
    /// `index_bytes` is left to the tree.
    pub(crate) fn stats(&self, live: usize) -> EntryStoreStats {
        match self {
            Self::Heap(entries) => EntryStoreStats {
                mode: EntryStoreMode::Heap,
                total_slots: entries.len() as u64,
                live_slots: live as u64,
                file_bytes: (entries.capacity() * std::mem::size_of::<Entry>()) as u64,
                ..EntryStoreStats::default()
            },
            Self::File(file) => file.stats(live),
        }
    }

    /// Where the entries are, for a caller deciding whether to move them.
    pub(crate) fn file_path(&self) -> Option<&Path> {
        match self {
            Self::Heap(_) => None,
            Self::File(file) => Some(file.path()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_readonly_historical_prefix_preserves_the_live_entry_file() {
        let path = scratch("readonly-prefix");
        let mut file = FileEntries::create(&path).unwrap();
        for n in 0..4u8 {
            file.push(&[n; 32], &[n; 8]).unwrap();
        }
        file.sync().unwrap();
        let before = std::fs::read(&path).unwrap();
        let (old, kept) = FileEntries::open_existing_readonly(&path, 2, &[3]).unwrap();
        assert_eq!(kept, 2);
        assert_eq!(old.key(1), Some(&[1; 32]));
        assert_eq!(old.value(1), &[1; 8]);
        drop(old);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let (_, kept) = FileEntries::open_existing(&path, 4, &[15]).unwrap();
        assert_eq!(kept, 4);
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("n42-entry-store-{name}-{}", std::process::id())).join("entries.log")
    }

    #[test]
    fn the_file_store_reads_back_what_it_appended_across_remaps_and_truncations() {
        let mut file = FileEntries::create(&scratch("roundtrip")).unwrap();
        let key = |i: usize| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            k
        };
        for i in 0..1000 {
            file.push(&key(i), &vec![(i % 256) as u8; 1 + i % 50]).unwrap();
        }
        assert_eq!(file.len(), 1000);
        assert_eq!(file.value(999), &vec![(999 % 256) as u8; 1 + 999 % 50][..]);
        assert_eq!(file.key(17), Some(&key(17)));
        assert!(file.is_active(17));
        file.set_active(17, false);
        assert!(!file.is_active(17));
        // Seal a chunk, then read through the chunk and the tail both.
        file.seal_now().unwrap();
        for i in 1000..1200 {
            file.push(&key(i), &[7u8; 3]).unwrap();
        }
        assert_eq!(file.value(500), &vec![(500 % 256) as u8; 1 + 500 % 50][..]);
        assert_eq!(file.value(1100), &[7u8; 3]);
        // Truncate into the sealed chunk, then append over it.
        file.truncate(800).unwrap();
        assert_eq!(file.len(), 800);
        file.push(&key(9000), &[9u8; 4]).unwrap();
        assert_eq!(file.len(), 801);
        assert_eq!(file.value(800), &[9u8; 4]);
        assert_eq!(file.value(799), &vec![(799 % 256) as u8; 1 + 799 % 50][..]);
        assert!(file.is_active(800));
        let mut copy = file.duplicate().unwrap();
        assert_eq!(copy.len(), 801);
        assert_eq!(copy.value(800), &[9u8; 4]);
        assert!(!copy.is_active(17));
        // The copy is read-only: it neither appends to nor cuts the file.
        let bytes = std::fs::metadata(&file.main.path).unwrap().len();
        assert_eq!(copy.push(&key(9001), &[1u8; 2]).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(copy.truncate(10).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(copy.len(), 801);
        file.sync().unwrap();
        assert!(std::fs::metadata(&file.main.path).unwrap().len() >= bytes);
        // The original is untouched by the copy and still appends.
        file.push(&key(9002), &[2u8; 2]).unwrap();
        assert_eq!(file.len(), 802);
    }

    /// The file store must be the heap store to every caller: same roots
    /// block after block, same snapshots, same undo behaviour, same proofs.
    #[test]
    fn a_file_backed_tree_matches_a_heap_tree_through_blocks_reverts_and_proofs() {
        use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};
        let key = |n: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&n.to_le_bytes());
            k
        };
        // A block: keys `base..base+n` set to a value tagged by the block,
        // sorted by key as the block path requires.
        let block = |base: u64, n: u64, tag: u8| -> Vec<QmdbOperation> {
            let mut ops: Vec<QmdbOperation> =
                (base..base + n).map(|i| QmdbOperation { key: key(i), value: Some(vec![tag; 40 + (i % 7) as usize]) }).collect();
            ops.sort_unstable_by_key(|op| op.key);
            ops
        };
        let mut heap = QmdbCompatTree::new();
        let mut file = QmdbCompatTree::new();
        // Seed both before the move, so the move copies a non-empty set.
        for tree in [&mut heap, &mut file] {
            tree.apply_sorted_ops(block(0, 5000, 1)).unwrap();
        }
        file.set_entry_file(&scratch("parity")).unwrap();
        assert!(file.entry_file().is_some());
        assert_eq!(heap.root(), file.root());

        let mut undos = Vec::new();
        for b in 0..12u64 {
            // Overlapping ranges: every block retires some slots and appends
            // across twig boundaries.
            let ops = block(b * 900, 3000, 10 + b as u8);
            let (root_h, undo_h) = heap.apply_sorted_ops_recorded(ops.clone()).unwrap();
            let (root_f, undo_f) = file.apply_sorted_ops_recorded(ops).unwrap();
            assert_eq!(root_h, root_f, "block {b}");
            // The file tree's record names the same slots but carries no
            // content (it reads a key at revival instead).
            assert!(undo_f.slots_only && !undo_h.slots_only);
            assert_eq!(undo_h.prev_next_slot, undo_f.prev_next_slot);
            assert_eq!(undo_h.appended_keys, undo_f.appended_keys);
            assert_eq!(
                undo_h.retired_slots().collect::<Vec<_>>(),
                undo_f.retired_slots().collect::<Vec<_>>(),
                "retired slots of block {b}"
            );
            assert_eq!(heap.snapshot(), file.snapshot(), "snapshot after block {b}");
            undos.push(undo_f);
        }
        assert_eq!(heap.get(&key(1234)), file.get(&key(1234)));
        assert_eq!(heap.prove(&key(1234)), file.prove(&key(1234)));
        // Revert the last three blocks on both, newest first -- the file
        // tree from its slot-only records, the heap tree from the same
        // records (a heap tree revives from a slot-only record by reading
        // the key too).
        for undo in undos.iter().rev().take(3) {
            heap.apply_undo(undo).unwrap();
            file.apply_undo(undo).unwrap();
            assert_eq!(heap.root(), file.root());
            assert_eq!(heap.next_slot(), file.next_slot());
        }
        // A slot-only record from another history is refused: its appended
        // keys are not what the slots hold.
        let mut foreign = undos[5].clone();
        foreign.prev_next_slot = file.next_slot() - foreign.appended_keys.len() as u64;
        assert!(file.apply_undo(&foreign).is_err());
        assert_eq!(heap.snapshot(), file.snapshot(), "after the reverts");
        // A different block on the reverted state, then the file's clone
        // reads the same state.
        let ops = block(777, 2500, 99);
        assert_eq!(heap.apply_sorted_ops(ops.clone()).unwrap(), file.apply_sorted_ops(ops).unwrap());
        let copy = file.clone();
        assert_eq!(copy.root(), file.root());
        assert_eq!(copy.snapshot(), file.snapshot());
        assert_eq!(copy.prove(&key(800)), heap.prove(&key(800)));
    }

    /// `entry_stats` matches a count by hand over the snapshot after
    /// appends, rewrites (retirements), deletions and an undo, in both modes.
    #[test]
    fn entry_stats_match_a_hand_count_in_both_modes() {
        use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};
        let key = |n: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&n.to_le_bytes());
            k
        };
        // Keys `base..base+n`: set, or deleted when `tag` is 0.
        let block = |base: u64, n: u64, tag: u8| -> Vec<QmdbOperation> {
            let mut ops: Vec<QmdbOperation> = (base..base + n)
                .map(|i| QmdbOperation { key: key(i), value: (tag != 0).then(|| vec![tag; 60 + (i % 13) as usize]) })
                .collect();
            ops.sort_unstable_by_key(|op| op.key);
            ops
        };
        let check = |tree: &QmdbCompatTree, mode: EntryStoreMode| {
            let stats = tree.entry_stats();
            let snap = tree.snapshot();
            let live = snap.entries.iter().filter(|e| e.active).count() as u64;
            assert_eq!(stats.mode, mode);
            assert_eq!(stats.total_slots, tree.next_slot());
            assert_eq!(stats.total_slots, snap.entries.len() as u64);
            assert_eq!(stats.live_slots, live);
            assert_eq!(stats.live_slots, tree.len() as u64);
            assert_eq!(stats.index_bytes, tree.index_bytes() as u64);
            assert!(stats.index_bytes > 0);
            assert_eq!(stats.bytes_per_live_slot(), stats.file_bytes / live.max(1));
            match mode {
                EntryStoreMode::File => {
                    let records: u64 = snap.entries.iter().map(|e| (KEY_LEN + LEN_LEN + e.value.len()) as u64).sum();
                    assert_eq!(stats.file_bytes, records);
                    let segments = stats.total_slots.div_ceil(crate::prefault::OFFSET_SEGMENT_SLOTS as u64);
                    assert_eq!(stats.offsets_bytes, segments * crate::prefault::OFFSET_SEGMENT_SLOTS as u64 * 8);
                    // A chunk is sealed at the last record that fits it.
                    assert!(stats.chunks * (CHUNK_BYTES as u64 / 2) <= records, "chunks of at least half a chunk's bytes");
                }
                EntryStoreMode::Heap => {
                    assert_eq!(stats.offsets_bytes, 0);
                    assert_eq!(stats.chunks, 0);
                    assert!(stats.file_bytes >= stats.total_slots * std::mem::size_of::<Entry>() as u64);
                }
            }
            stats
        };
        let mut heap = QmdbCompatTree::new();
        let mut file = QmdbCompatTree::new();
        file.set_entry_file(&scratch("stats")).unwrap();
        assert_eq!(check(&file, EntryStoreMode::File).total_slots, 0);
        let mut undo = None;
        for (b, (base, n, tag)) in [(0, 6000, 1), (2000, 6000, 2), (1000, 1500, 0), (5000, 9000, 3)].into_iter().enumerate() {
            for (tree, mode) in [(&mut heap, EntryStoreMode::Heap), (&mut file, EntryStoreMode::File)] {
                let (_, record) = tree.apply_sorted_ops_recorded(block(base, n, tag)).unwrap();
                check(tree, mode);
                if mode == EntryStoreMode::File && b == 3 {
                    undo = Some(record);
                }
            }
        }
        let (h, f) = (heap.entry_stats(), file.entry_stats());
        assert_eq!((h.total_slots, h.live_slots), (f.total_slots, f.live_slots));
        // 14,000 keys, 1,500 of them deleted; 21,000 records appended.
        assert_eq!(f.live_slots, 12_500);
        assert_eq!(f.total_slots, 21_000);
        assert!(f.chunks >= 1, "the records cross a test chunk");
        // An undo cuts the file and revives the retired slots.
        file.apply_undo(&undo.unwrap()).unwrap();
        let after = check(&file, EntryStoreMode::File);
        assert_eq!(after.total_slots, 12_000);
        assert_eq!(after.live_slots, 6_500);
        drop(file);
        if let Some(dir) = scratch("stats").parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Trimming a twig keeps the world root and every proof of a live key,
    /// never touches a twig within the window, and a tree keeps working
    /// (new blocks, snapshots) with trimmed twigs in it.
    #[test]
    fn trimmed_twigs_keep_the_root_and_the_proofs_of_live_keys() {
        use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};
        use crate::TWIG_SIZE;
        let key = |n: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&n.to_le_bytes());
            k
        };
        let block = |base: u64, n: u64, tag: u8| -> Vec<QmdbOperation> {
            let mut ops: Vec<QmdbOperation> =
                (base..base + n).map(|i| QmdbOperation { key: key(i), value: Some(vec![tag; 20]) }).collect();
            ops.sort_unstable_by_key(|op| op.key);
            ops
        };
        let mut tree = QmdbCompatTree::new();
        // Three twigs' worth of keys, then every one of them rewritten: the
        // first three twigs are all dead, the last ones live.
        let n = 3 * TWIG_SIZE as u64;
        tree.apply_sorted_ops(block(0, n, 1)).unwrap();
        let cursor_after_first = tree.next_slot();
        tree.apply_sorted_ops(block(0, n, 2)).unwrap();
        let root = tree.root();
        let proof = tree.prove(&key(5)).unwrap();
        assert_eq!(tree.trimmed_twigs(), 0);
        // Nothing before the first block's cursor was retired before it.
        assert_eq!(tree.trim_dead_twigs(cursor_after_first), 0, "the retirements are at the second block's cursor");
        // With the window past the second block, the three dead twigs go.
        let trimmed = tree.trim_dead_twigs(tree.next_slot() + 1);
        assert_eq!(trimmed, 3);
        assert_eq!(tree.trimmed_twigs(), 3);
        assert_eq!(tree.root(), root);
        assert_eq!(tree.prove(&key(5)), Some(proof));
        let snap = tree.snapshot();
        assert_eq!(snap.entries.len() as u64, 2 * n);
        // Life goes on: another block, and the root still matches a tree
        // that was never trimmed.
        let mut untrimmed = QmdbCompatTree::from_snapshot(&snap).unwrap();
        let ops = block(10, 100, 3);
        assert_eq!(tree.apply_sorted_ops(ops.clone()).unwrap(), untrimmed.apply_sorted_ops(ops).unwrap());
        // A file-backed tree trims the same way.
        let mut file = QmdbCompatTree::from_snapshot(&snap).unwrap();
        file.set_entry_file(&scratch("trim")).unwrap();
        assert_eq!(file.trim_dead_twigs(file.next_slot() + 1), 3);
        assert_eq!(file.root(), root);
    }
}

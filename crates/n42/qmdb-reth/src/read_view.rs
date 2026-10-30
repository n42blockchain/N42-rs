// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QMDB answering account and storage reads for the database's persisted block
//! (`docs/QMDB_UPGRADE_PLAN.md`, stage 6).
//!
//! reth reads state through an in-memory overlay of the blocks it has not persisted, over a base
//! provider at the block its read transaction sees as persisted (the `Finish` checkpoint, F). A
//! base answering at exactly F is correct for every reader, on whichever fork it executes. This
//! view answers at F without the forest's lock:
//!
//! - a key -> slot index at the view's head H (`docs/QMDB_COMPACTION_DESIGN.md` 3.3, stage 1):
//!   a slot resolves to its record through the tree's shared offsets with one acquire load, and
//!   the record is read through the view's own mappings of `entries.log` and `entries.relocated`
//!   ([`SlotFileView`]). A slot's identity never changes; a compaction may move its record to
//!   `entries.relocated`, and a reader sees the old location or the new one, both readable,
//!   since nothing is punched yet;
//! - for each of the last [`JOURNAL_DEPTH`] blocks up to H, the slot each of its keys held
//!   before it and the slots the view read before it, so a reader whose F is behind H undoes
//!   those blocks for its key, and the view itself can step back through them;
//! - a block being applied publishes its journal before the index changes, so no reader at or
//!   below H sees a half-applied block.
//!
//! Readers do not share a lock: what a read needs from the versions (validity, head, journals,
//! the pending block) is published as one immutable [`Frozen`] to [`READER_SLOTS`] cache-line
//! padded slots, and a reader takes only its own thread's slot's read lock, held through the
//! record read. A writer replaces every slot under its write lock, so it waits for each slot's
//! in-flight reads exactly as it waited for the one shared lock (a block's index is not touched
//! until every slot holds its journal; a truncation's step back holds every slot until it is done).
//!
//! It moves as the database persists (`QmdbNodeState::on_persisted`) and declines what it cannot
//! answer exactly (a reader ahead of it, or further behind than its journals). When the database
//! unwinds below H, or the tree is about to cut records the view reads (a revert below H, told
//! through [`TruncationGuard`] before the cut), the view steps back through its journals to the
//! newest block whose records survive -- the index is rewritten while every record it compares
//! is still in the file. It is invalidated for good only when the journals do not reach that
//! far, or when a persisted block is not the one it holds. Its files have no size limit short
//! of 1 PiB ([`n42_twig_core::entry_view::VIEW_SEGMENTS`] mapping segments of 1 TiB), and its
//! index names 2^40 slots, the tree's own limit; before stage 1 it indexed byte offsets and was
//! invalidated once the entry file passed 1 TiB.
//!
//! Stage 3 (punching a compacted twig's old bytes) needs two things from this view, neither of
//! which is behaviour yet:
//!
//! - a reader epoch: a reader loads a slot's location under its reader slot's read lock, so once
//!   a writer has held every slot's write lock after a retarget ([`QmdbReadView::advance`]'s publish
//!   does), no read in flight can still hold the old location. The old range joins a
//!   `punch_after` queue tagged with the retarget and is punched after the next such publish.
//!   TODO(stage 3): the queue and the epoch counter, published with each `Frozen`;
//! - a compaction horizon at or below [`QmdbReadView::journal_floor`]: the journals name slots that died
//!   in the blocks they cover, and a compaction stores dead slots as their leaf hash only, so a
//!   twig with such a slot must wait until the journals let go of the block. A read that meets a
//!   hash-only slot anyway is declined (it goes to the database), never answered wrong.

use std::{
    collections::VecDeque,
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, PoisonError, RwLock, RwLockWriteGuard,
    },
};

use alloy_primitives::{Address, B256, U256};
use n42_twig_core::{
    entry_view::SlotFileView,
    offsets::OffsetsReader,
    qmdb_compat::{gov5_account_key, gov5_storage_key, TruncationGuard},
    Hash, SharedOffsetIndex,
};
use rayon::prelude::*;
use reth_primitives_traits::Account;
use tracing::{info, warn};

/// How many blocks behind its head the view answers for.
///
/// This is a distance between a *reader* and the view's head, not between the
/// view's head and the canonical head: the head is the database's persisted
/// block, and a reader reads at the block its own transaction sees as
/// persisted, so the depth it needs is only how far persistence moved between
/// that transaction opening and its read -- one advance, or a persistence
/// batch. It is therefore independent of the forest's reader keep cap
/// (`QmdbForest::set_reader_keep_cap`), which bounds how far the *view* may
/// fall behind the chain, and does not follow it: a view 1024 blocks behind
/// the canonical head still answers its readers at depth 0.
pub const JOURNAL_DEPTH: usize = 64;

/// For one block, sorted by key: the slot of each key's live record before the block.
type Journal = Arc<JournalData>;

/// A block's journal: its entries, and with `N42_VIEW_JOURNAL_FILTER=1` an
/// address filter over their keys, so a read whose key the block did not
/// change skips the journal's binary search (~17 dependent probes of a
/// ~9 MB vector at a full block: 200-300 ns a journal on the E=1 bench,
/// `docs/SHARED_EXECUTION_SCOPE.md` 13). A filter has no false negatives:
/// every answer is the one the search gives.
#[derive(Debug)]
struct JournalData {
    entries: Vec<(Hash, Option<u64>)>,
    filter: Option<reth_provider::providers::overlay_filter::SplitBloom>,
}

impl JournalData {
    fn new(entries: Vec<(Hash, Option<u64>)>, with_filter: bool) -> Self {
        let filter = with_filter.then(|| {
            let mut filter = reth_provider::providers::overlay_filter::SplitBloom::with_capacity(entries.len());
            for (key, _) in &entries {
                filter.insert(journal_key(key));
            }
            filter
        });
        Self { entries, filter }
    }

    /// The slot `key` held before the block, if the block changed it.
    #[inline]
    fn before(&self, key: &Hash) -> Option<Option<u64>> {
        self.entries.binary_search_by(|(k, _)| k.cmp(key)).ok().map(|i| self.entries[i].1)
    }
}

impl std::ops::Deref for JournalData {
    type Target = [(Hash, Option<u64>)];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

/// A journal key's filter key.
#[inline(always)]
fn journal_key(key: &Hash) -> reth_provider::providers::overlay_filter::FilterKey {
    reth_provider::providers::overlay_filter::FilterKey::code_hash(&B256::from(*key))
}

/// Whether the view files a filter with each block's journal
/// (`N42_VIEW_JOURNAL_FILTER=1`, off by default).
pub fn journal_filter() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_VIEW_JOURNAL_FILTER").is_ok_and(|v| v.trim() == "1"))
}

/// Reads that walked journals: per-thread accumulators folded into the
/// totals every 4,096 such reads (see [`take_journal_counters`]).
static JOURNAL_READS: AtomicU64 = AtomicU64::new(0);
static JOURNAL_SEARCHES: AtomicU64 = AtomicU64::new(0);
static JOURNAL_SKIPS: AtomicU64 = AtomicU64::new(0);

std::thread_local! {
    static JOURNAL_LOCAL: std::cell::Cell<(u64, u64, u64)> = const { std::cell::Cell::new((0, 0, 0)) };
}

std::thread_local! {
    /// This thread's reads whose reader slot was write-locked (a publish in
    /// flight: an advance, a step back) and the nanoseconds they waited.
    static SLOT_WAITS: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}

/// The calling thread's waits on the read view's locks, cumulative since the
/// thread started (difference two readings to attribute them to a span of
/// work). Only a lock that could not be taken at once is timed, so a read that
/// waits for nothing costs what it did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewLockWaits {
    /// Reads whose reader slot was held by a writer publishing a new version.
    pub slot_waits: u64,
    /// Nanoseconds those reads waited for the slot.
    pub slot_wait_ns: u64,
    /// Reads whose offset-index shard was held by a writer (the index's
    /// `apply_sorted` at an advance, a step back's inserts).
    pub index_waits: u64,
    /// Nanoseconds those reads waited for the shard.
    pub index_wait_ns: u64,
}

impl ViewLockWaits {
    /// The calling thread's counts now.
    pub fn now() -> Self {
        let (slot_waits, slot_wait_ns) = SLOT_WAITS.try_with(std::cell::Cell::get).unwrap_or((0, 0));
        let (index_waits, index_wait_ns) = n42_twig_core::thread_read_waits();
        Self { slot_waits, slot_wait_ns, index_waits, index_wait_ns }
    }

    /// The waits between `earlier` and `self`.
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            slot_waits: self.slot_waits.saturating_sub(earlier.slot_waits),
            slot_wait_ns: self.slot_wait_ns.saturating_sub(earlier.slot_wait_ns),
            index_waits: self.index_waits.saturating_sub(earlier.index_waits),
            index_wait_ns: self.index_wait_ns.saturating_sub(earlier.index_wait_ns),
        }
    }
}

/// The reader slot's read lock, a failed `try_read` timed into [`SLOT_WAITS`].
fn read_slot(slot: &Slot) -> std::sync::RwLockReadGuard<'_, Arc<Frozen>> {
    match slot.0.try_read() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            let at = std::time::Instant::now();
            let guard = slot.0.read().unwrap_or_else(PoisonError::into_inner);
            let waited = at.elapsed().as_nanos() as u64;
            let _ = SLOT_WAITS.try_with(|waits| {
                let (count, ns) = waits.get();
                waits.set((count + 1, ns + waited));
            });
            guard
        }
    }
}

#[inline]
fn record_journal_walk(searches: u64, skips: u64) {
    let _ = JOURNAL_LOCAL.try_with(|local| {
        let (reads, s, k) = local.get();
        let (reads, s, k) = (reads + 1, s + searches, k + skips);
        if reads >= 4096 {
            JOURNAL_READS.fetch_add(reads, Ordering::Relaxed);
            JOURNAL_SEARCHES.fetch_add(s, Ordering::Relaxed);
            JOURNAL_SKIPS.fetch_add(k, Ordering::Relaxed);
            local.set((0, 0, 0));
        } else {
            local.set((reads, s, k));
        }
    });
}

/// `(reads that had journals to walk, journals they searched, journals their
/// filters skipped)` since the last call, reset to zero. Each thread folds its
/// counts in every 4,096 such reads.
pub fn take_journal_counters() -> (u64, u64, u64) {
    (
        JOURNAL_READS.swap(0, Ordering::Relaxed),
        JOURNAL_SEARCHES.swap(0, Ordering::Relaxed),
        JOURNAL_SKIPS.swap(0, Ordering::Relaxed),
    )
}

/// One block the view advanced by.
#[derive(Debug)]
struct Step {
    number: u64,
    hash: B256,
    journal: Journal,
    /// The slots the view read before this block (all below this count).
    floor_before: u64,
}

#[derive(Debug)]
struct Versions {
    valid: bool,
    /// The head's hash is `B256::ZERO` when the view stepped back past its oldest journal's
    /// block and no longer knows it.
    head: (u64, B256),
    /// The slots the view reads at its head (all below this count).
    head_floor: u64,
    /// Blocks `head - len + 1 ..= head`, oldest first.
    journals: VecDeque<Step>,
    /// The block whose index writes may be in flight (the head's child).
    pending: Option<Journal>,
    /// The version the database's readers stand at while a persistence batch
    /// is being applied ([`QmdbReadView::hold_journals_from`]): the steps
    /// above it are kept past [`JOURNAL_DEPTH`] until the next batch.
    held_from: Option<u64>,
}

impl Versions {
    /// What a read needs, as of now.
    fn frozen(&self) -> Arc<Frozen> {
        Arc::new(Frozen {
            valid: self.valid,
            head: self.head.0,
            journals: self.journals.iter().map(|step| step.journal.clone()).collect(),
            pending: self.pending.clone(),
        })
    }
}

/// The part of [`Versions`] a read uses, published to every reader slot. It
/// owns its journals (`Arc`s), and a reader holds its slot's read lock for the
/// whole read, so a writer can neither drop them nor move the index under it.
#[derive(Debug)]
struct Frozen {
    valid: bool,
    head: u64,
    /// The journals of blocks `head - len + 1 ..= head`, oldest first.
    journals: Vec<Journal>,
    pending: Option<Journal>,
}

/// Reader slots: threads are spread over them round robin, so a read writes
/// only its own slot's line (the one shared `versions` lock cost 1.8-2.1 us a
/// read at sixteen threads against 0.38 alone, `bench_concurrent_reads`).
const READER_SLOTS: usize = 128;

/// One reader slot, on its own cache lines.
#[derive(Debug)]
#[repr(align(128))]
struct Slot(RwLock<Arc<Frozen>>);

/// The calling thread's reader slot.
fn reader_slot() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static SLOT: usize = NEXT.fetch_add(1, Ordering::Relaxed) % READER_SLOTS;
    }
    SLOT.try_with(|slot| *slot).unwrap_or(0)
}

type SlotsWrite<'a> = Vec<RwLockWriteGuard<'a, Arc<Frozen>>>;

/// Where a persisted block stands against the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// At or below the head, and (where the view can tell) the block it holds.
    Held,
    /// The head's child: the view can advance to it.
    Next,
    /// A different block at a height the view holds.
    Mismatch,
    /// Beyond the head's child.
    Gap,
    /// The view is invalidated.
    Invalid,
}

/// What [`QmdbReadView::raise_floor`] hands to [`QmdbReadView::advance`]: the slot count the
/// block's records end at, and the tree's cuts counted when the floor went up -- a cut in
/// between may have taken the block's records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Raised {
    floor: u64,
    cuts: u64,
    /// A record the block names lies past the view's reach (an entry file
    /// past 1 PiB): the advance invalidates the view instead of reading it.
    past_view: bool,
}

/// The read view: see the module documentation.
pub struct QmdbReadView {
    file: SlotFileView,
    /// Key -> slot.
    index: SharedOffsetIndex,
    versions: RwLock<Versions>,
    /// [`Frozen`] copies of `versions`, one per reader slot (see the module documentation).
    /// Taken after `versions` by a writer; a reader takes one slot and nothing else.
    readers: Box<[Slot]>,
    /// Slots the view may read (all below this count): past its newest block's last record,
    /// including a block whose floor was raised and that has not advanced yet.
    floor: AtomicU64,
    /// Cuts below `floor` the tree announced.
    cuts: AtomicU64,
    /// Advances and steps back one at a time.
    advancing: Mutex<()>,
    /// Whether each new journal gets a filter ([`journal_filter`]).
    filter_journals: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for QmdbReadView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("QmdbReadView")
            .field("valid", &versions.valid)
            .field("head", &versions.head)
            .field("journals", &versions.journals.len())
            .finish_non_exhaustive()
    }
}

/// What a key lookup compares a slot's key with when the slot gives none (a
/// hash-only slot, or a location past the view's reach). Lookups that meet
/// one set their miss flag and are declined, so the value never answers.
const NO_KEY: Hash = [0xff; 32];

/// `slot`'s key, or [`NO_KEY`] with `missed` set when the slot gives none.
///
/// # Safety
///
/// As [`SlotFileView::key`].
#[inline]
unsafe fn key_or_miss(file: &SlotFileView, slot: u64, missed: &std::sync::atomic::AtomicBool) -> Hash {
    // SAFETY: the caller's contract.
    match unsafe { file.key(slot) } {
        Some(key) => key,
        None => {
            missed.store(true, Ordering::Relaxed);
            NO_KEY
        }
    }
}

/// gov5's `StateAccount.MarshalV2` leaf as reth's account: the presence bitmap
/// (nonce 1, balance 2, code 8), the LEB128 nonce, the length-prefixed
/// big-endian balance and the code hash.
fn decode_account(value: &[u8]) -> Option<Account> {
    let bitmap = *value.first()?;
    let mut at = 1;
    let mut nonce = 0u64;
    if bitmap & 1 != 0 {
        let mut shift = 0;
        loop {
            let byte = *value.get(at)?;
            at += 1;
            if shift == 63 && byte > 1 {
                return None;
            }
            nonce |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    let mut balance = U256::ZERO;
    if bitmap & 2 != 0 {
        let len = *value.get(at)? as usize;
        at += 1;
        balance = U256::try_from_be_slice(value.get(at..at + len)?)?;
        at += len;
    }
    let bytecode_hash = if bitmap & 8 != 0 { Some(B256::from_slice(value.get(at..at + 32)?)) } else { None };
    Some(Account { nonce, balance, bytecode_hash })
}

impl QmdbReadView {
    /// A view at `head` over the entry file at `entry_file`, resolving slots
    /// through `offsets` (the tree's, `QmdbForest::entry_offsets_reader`) and
    /// holding `live` (every live key and its slot at `head`, records flushed).
    pub fn build(entry_file: &Path, offsets: OffsetsReader, head: (u64, B256), live: Vec<(Hash, u64)>) -> std::io::Result<Arc<Self>> {
        Self::build_on(SlotFileView::open(entry_file, offsets)?, head, live)
    }

    /// [`Self::build`] with mapping segments of `2^bits` bytes: tests take the
    /// view past several segments (what used to be its 1 TiB limit) without
    /// writing a terabyte.
    #[doc(hidden)]
    pub fn build_with_segment_bits(
        entry_file: &Path,
        offsets: OffsetsReader,
        head: (u64, B256),
        live: Vec<(Hash, u64)>,
        bits: u32,
    ) -> std::io::Result<Arc<Self>> {
        Self::build_on(SlotFileView::open_with_segment_bits(entry_file, offsets, bits)?, head, live)
    }

    fn build_on(file: SlotFileView, head: (u64, B256), mut live: Vec<(Hash, u64)>) -> std::io::Result<Arc<Self>> {
        live.par_sort_unstable_by_key(|(key, _)| *key);
        let floor = match live.iter().map(|(_, slot)| *slot).max() {
            None => 0,
            // SAFETY: a live slot of the tree at `head`, flushed (the caller's contract).
            Some(slot) if unsafe { file.reaches(slot) } => slot + 1,
            Some(slot) => return Err(std::io::Error::other(format!("slot {slot}'s record lies past the read view's reach"))),
        };
        let changes: Vec<(Hash, Option<u64>)> = live.into_iter().map(|(key, slot)| (key, Some(slot))).collect();
        let index = SharedOffsetIndex::default();
        let missed = std::sync::atomic::AtomicBool::new(false);
        // SAFETY: every slot here is a live record of the tree at `head`,
        // flushed before the call (the caller's contract), and the tree tells
        // this view before it cuts the file; the index only reads the keys of
        // slots it was given.
        index
            .apply_sorted(&changes, |slot| unsafe { key_or_miss(&file, slot, &missed) })
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if missed.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("a live slot has no record the read view can read"));
        }
        let versions =
            Versions { valid: true, head, head_floor: floor, journals: VecDeque::new(), pending: None, held_from: None };
        let frozen = versions.frozen();
        Ok(Arc::new(Self {
            file,
            index,
            versions: RwLock::new(versions),
            readers: (0..READER_SLOTS).map(|_| Slot(RwLock::new(frozen.clone()))).collect(),
            floor: AtomicU64::new(floor),
            cuts: AtomicU64::new(0),
            advancing: Mutex::new(()),
            filter_journals: std::sync::atomic::AtomicBool::new(journal_filter()),
        }))
    }

    /// Tests and benches: whether the journals filed from now on carry a
    /// filter, whatever `N42_VIEW_JOURNAL_FILTER` says.
    #[doc(hidden)]
    pub fn set_journal_filter(&self, on: bool) {
        self.filter_journals.store(on, Ordering::Relaxed);
    }

    /// The block the view stands at.
    pub fn head(&self) -> (u64, B256) {
        self.versions.read().unwrap_or_else(PoisonError::into_inner).head
    }

    /// Whether the view still answers.
    pub fn is_valid(&self) -> bool {
        self.versions.read().unwrap_or_else(PoisonError::into_inner).valid
    }

    /// Keys indexed at the head.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether no key is indexed.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// The slot count the view's oldest journal starts at: every slot a
    /// journal names as a key's prior record lies above the slots the view
    /// read before that block, so a slot retired by a block the journals
    /// cover is at or above this. Stage 3's compaction horizon stays at or
    /// below it (module documentation); nothing calls it yet.
    pub fn journal_floor(&self) -> u64 {
        let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
        versions.journals.front().map_or(versions.head_floor, |step| step.floor_before)
    }

    /// Every reader slot's write lock, in order: a writer holding them has
    /// waited out every in-flight read. Taken after `versions`.
    fn lock_readers(&self) -> SlotsWrite<'_> {
        self.readers.iter().map(|slot| slot.0.write().unwrap_or_else(PoisonError::into_inner)).collect()
    }

    /// Publishes `versions` to the slots `readers` holds.
    fn publish_to(readers: &mut SlotsWrite<'_>, versions: &Versions) {
        let frozen = versions.frozen();
        for slot in readers.iter_mut() {
            **slot = frozen.clone();
        }
    }

    /// Publishes `versions` to every reader slot.
    fn publish(&self, versions: &Versions) {
        Self::publish_to(&mut self.lock_readers(), versions);
    }

    /// Reads `key` as of block `at`: `None` when the view cannot answer
    /// exactly, `Some(None)` for an absent key, else the decoded value. The
    /// thread's reader slot is held through the record read, so a truncation
    /// (and an index change) waits.
    fn read_at<T>(&self, key: &Hash, at: u64, decode: impl FnOnce(&[u8]) -> T) -> Option<Option<T>> {
        let frozen = read_slot(self.readers.get(reader_slot())?);
        if !frozen.valid || at > frozen.head {
            return None;
        }
        let behind = (frozen.head - at) as usize;
        if behind > frozen.journals.len() {
            return None;
        }
        let walk = behind + usize::from(frozen.pending.is_some());
        let undone = if walk == 0 {
            None
        } else {
            let filter_key = journal_key(key);
            let (mut searches, mut skips) = (0u64, 0u64);
            let found = frozen.journals.iter().skip(frozen.journals.len() - behind).chain(frozen.pending.iter()).find_map(|journal| {
                if journal.filter.as_ref().is_some_and(|filter| !filter.may_contain(filter_key)) {
                    skips += 1;
                    return None;
                }
                searches += 1;
                journal.before(key)
            });
            record_journal_walk(searches, skips);
            found
        };
        let slot = match undone {
            Some(slot) => slot,
            None => {
                let missed = std::sync::atomic::AtomicBool::new(false);
                // SAFETY: the index holds slots of records written at or below
                // the view's head, and the tree tells the view (`before_truncate`)
                // before it cuts any of them.
                let found = self.index.get(key, |slot| unsafe { key_or_miss(&self.file, slot, &missed) });
                if missed.load(Ordering::Relaxed) {
                    return None;
                }
                found
            }
        };
        // SAFETY: a slot from the index or a journal, as above. A record that
        // does not have the shape of one (a broken offset invariant) or has no
        // payload (a hash-only slot) is declined, not a panic on this RPC or
        // EVM thread (audit 2026-10 D-8).
        match slot {
            None => Some(None),
            Some(slot) => Some(Some(decode(unsafe { self.file.record(slot) }?.1))),
        }
    }

    /// An account as of block `at` (see [`Self::read_at`]). A record that does
    /// not decode is declined.
    pub fn account(&self, address: &Address, at: u64) -> Option<Option<Account>> {
        match self.read_at(&gov5_account_key(&address.0 .0), at, decode_account)? {
            None => Some(None),
            Some(Some(account)) => Some(Some(account)),
            Some(None) => None,
        }
    }

    /// A hint that the account at `address` will be read soon: its key
    /// derived as [`Self::account`] derives it and the index's bucket line
    /// for it prefetched (`SharedOffsetIndex::prefetch`, only when the
    /// shard's read lock is free). The record is not: its slot is in that
    /// bucket, which is the miss being hinted. No reader slot is
    /// taken and no counter moves. Returns whether the hint was issued.
    pub fn prefetch_account(&self, address: &Address) -> bool {
        self.index.prefetch(&gov5_account_key(&address.0 .0))
    }

    /// A storage slot as of block `at`; `Some(None)` for a zero (absent) slot.
    pub fn storage(&self, address: &Address, slot: &B256, at: u64) -> Option<Option<U256>> {
        match self.read_at(&gov5_storage_key(&address.0 .0, &slot.0), at, U256::try_from_be_slice)? {
            None => Some(None),
            Some(Some(value)) => Some(Some(value)),
            Some(None) => None,
        }
    }

    /// Where a persisted block stands against the view.
    pub fn position(&self, number: u64, hash: B256) -> Position {
        let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid {
            return Position::Invalid;
        }
        let head = versions.head;
        if number == head.0 + 1 {
            Position::Next
        } else if number > head.0 + 1 {
            Position::Gap
        } else if number == head.0 {
            if hash == head.1 || head.1 == B256::ZERO { Position::Held } else { Position::Mismatch }
        } else {
            match versions.journals.iter().find(|step| step.number == number) {
                Some(step) if step.hash != hash => Position::Mismatch,
                _ => Position::Held,
            }
        }
    }

    /// Raises the floor past the records `changes` names. Called under the
    /// forest's lock, before the lock that could let the tree cut them is
    /// released; the result goes to [`Self::advance`].
    pub fn raise_floor(&self, changes: &[(Hash, Option<u64>)]) -> Raised {
        self.raise_floor_to(changes.iter().filter_map(|(_, slot)| *slot).max())
    }

    /// [`Self::raise_floor`] from the highest slot the block's changes name
    /// (`None` for a block that appended nothing), for a caller that lists
    /// the changes only after the forest's lock is let go
    /// (`QmdbForest::block_changes_parts`). The same rule: under the lock,
    /// before anything that could cut the records, which are flushed.
    pub fn raise_floor_to(&self, max_slot: Option<u64>) -> Raised {
        // SAFETY: the block's highest slot, flushed and not cut (the caller
        // holds the forest's lock); only its record's header is read.
        let past_view = max_slot.is_some_and(|slot| !unsafe { self.file.reaches(slot) });
        let floor = max_slot.map_or(0, |slot| slot + 1);
        self.floor.fetch_max(floor, Ordering::SeqCst);
        Raised { floor, cuts: self.cuts.load(Ordering::SeqCst), past_view }
    }

    /// Moves the view to its head's child `number`, whose `changes` (sorted by
    /// key: the appended record's slot, or `None` for a deletion) are
    /// flushed to the file and covered by [`Self::raise_floor`], which gave `raised`.
    pub fn advance(&self, number: u64, hash: B256, changes: &[(Hash, Option<u64>)], raised: Raised) {
        let _one = self.advancing.lock().unwrap_or_else(PoisonError::into_inner);
        {
            let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
            if !versions.valid {
                return;
            }
            let why = if raised.past_view {
                Some("a block's records lie past the read view's reach")
            } else if number != versions.head.0 + 1 {
                Some("advanced to a block that is not the head's child")
            } else if self.cuts.load(Ordering::SeqCst) != raised.cuts {
                Some("the tree cut records between a block's floor and its advance")
            } else {
                None
            };
            if let Some(why) = why {
                drop(versions);
                self.invalidate(why);
                return;
            }
        }
        let missed = std::sync::atomic::AtomicBool::new(false);
        // SAFETY: the index holds slots of written records the tree has not
        // cut: a cut tells the view first and waits on `advancing`, held here.
        let key_at = |slot: u64| unsafe { key_or_miss(&self.file, slot, &missed) };
        let journal: Vec<(Hash, Option<u64>)> =
            changes.par_iter().with_min_len(1024).map(|(key, _)| (*key, self.index.get(key, key_at))).collect();
        if missed.load(Ordering::Relaxed) {
            self.invalidate("a slot the view holds has no record it can read");
            return;
        }
        let journal = Arc::new(JournalData::new(journal, self.filter_journals.load(Ordering::Relaxed)));
        {
            let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
            versions.pending = Some(journal.clone());
            // Every slot holds the journal before the index changes.
            self.publish(&versions);
        }
        let applied = self.index.apply_sorted(changes, key_at);
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        versions.pending = None;
        if applied.is_ok() && missed.load(Ordering::Relaxed) {
            Self::invalidate_locked(&mut versions, "a slot the view holds has no record it can read");
            self.publish(&versions);
            return;
        }
        if let Err(err) = applied {
            // Part of the block is in the index: the view cannot answer for
            // it, and reads go to the database from here on.
            warn!(target: "n42.qmdb", %err, number, "the QMDB read view's key index refused a block's changes");
            Self::invalidate_locked(&mut versions, "the key index refused a block's changes");
            self.publish(&versions);
            return;
        }
        let floor_before = versions.head_floor;
        versions.journals.push_back(Step { number, hash, journal, floor_before });
        versions.head = (number, hash);
        versions.head_floor = floor_before.max(raised.floor);
        while versions.journals.len() > JOURNAL_DEPTH
            && versions.journals.front().is_some_and(|step| versions.held_from.is_none_or(|held| step.number <= held))
        {
            versions.journals.pop_front();
        }
        self.publish(&versions);
    }

    /// A persistence batch starts: the database's readers stand at `number`
    /// (the view's head, which the previous batch's commit made the
    /// database's version) until this batch commits, and the view advances
    /// ahead of that commit. The steps above `number` are kept past
    /// [`JOURNAL_DEPTH`] until the next batch, so those readers are answered
    /// however many blocks the batch holds.
    ///
    /// Without it a batch of more than [`JOURNAL_DEPTH`] blocks -- the lag
    /// reaches ~100 late in a fleet leg -- popped the journals the database's
    /// version needed while its commit was still in flight, and every read in
    /// that window was declined: with `N42_HASHED_TABLES=off` an error
    /// ("the QMDB reader did not answer slot 0x546 of 0x0000F908...", the
    /// history contract's first read in a block's execution), and the block
    /// was rejected as invalid (loop279 IDX/IDXP100, block 1351).
    pub fn hold_journals_from(&self, number: u64) {
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        versions.held_from = Some(number);
    }

    /// Steps the view back to block `number` (the database unwound the state
    /// above it). Returns whether the view is valid at or below `number`
    /// afterwards; a view whose journals do not reach that far is invalidated.
    pub fn revert_to(&self, number: u64) -> bool {
        let _one = self.advancing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid {
            return false;
        }
        let mut readers = self.lock_readers();
        let held = self.step_back(&mut versions, number);
        if !held {
            Self::invalidate_locked(&mut versions, "the database unwound below the view's journals");
        }
        Self::publish_to(&mut readers, &versions);
        held
    }

    /// Undoes the journals above `number`, newest first, one key at a time
    /// (the caller may hold the forest's lock: no work goes to the worker pool,
    /// whose threads could take that lock while this one waits). Every slot
    /// the index compares is the view's own, below its floor, so still in the
    /// file. Callers hold `advancing`, the versions lock and every reader slot.
    fn step_back(&self, versions: &mut Versions, number: u64) -> bool {
        if number >= versions.head.0 {
            return true;
        }
        let depth = (versions.head.0 - number) as usize;
        if depth > versions.journals.len() {
            return false;
        }
        let missed = std::sync::atomic::AtomicBool::new(false);
        // SAFETY: the index and the journals hold slots of records written at
        // or below the head being stepped back from, not yet cut.
        let key_at = |slot: u64| unsafe { key_or_miss(&self.file, slot, &missed) };
        let from = versions.head.0;
        for _ in 0..depth {
            let step = versions.journals.pop_back().expect("depth checked against the journals");
            for (key, before) in step.journal.iter() {
                match before {
                    Some(slot) => {
                        // A refusal leaves the view part way back: the
                        // caller invalidates it.
                        if self.index.insert(*key, *slot, key_at).is_err() {
                            return false;
                        }
                    }
                    None => {
                        self.index.remove(key, key_at);
                    }
                }
                if missed.load(Ordering::Relaxed) {
                    return false;
                }
            }
            versions.head_floor = step.floor_before;
        }
        let hash = versions.journals.back().map_or(B256::ZERO, |step| step.hash);
        versions.head = (number, hash);
        self.floor.store(versions.head_floor, Ordering::SeqCst);
        info!(target: "n42.qmdb", from, to = number, journals = versions.journals.len(), "the QMDB read view stepped back");
        true
    }

    /// Stops the view answering, for good.
    pub fn invalidate(&self, why: &str) {
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        Self::invalidate_locked(&mut versions, why);
        self.publish(&versions);
    }

    fn invalidate_locked(versions: &mut Versions, why: &str) {
        if versions.valid {
            versions.valid = false;
            warn!(target: "n42.qmdb", why, head = versions.head.0, "the QMDB read view is invalidated; state reads go to the database");
        }
    }
}

impl TruncationGuard for QmdbReadView {
    /// The tree is about to cut every slot from `new_len` on. Records the
    /// view reads at its head are among them only when the tree reverts below
    /// the head: the view steps back to the newest block whose records all lie
    /// below `new_len`, before they go. A block whose floor was raised and has
    /// not advanced is caught by the cut count ([`Raised`]).
    fn before_truncate(&self, new_len: u64) {
        if new_len >= self.floor.load(Ordering::SeqCst) {
            return;
        }
        let _one = self.advancing.lock().unwrap_or_else(PoisonError::into_inner);
        self.cuts.fetch_add(1, Ordering::SeqCst);
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid || versions.head_floor <= new_len {
            return;
        }
        let mut readers = self.lock_readers();
        let target = versions.journals.iter().rev().find(|step| step.floor_before <= new_len).map(|step| step.number - 1);
        match target {
            Some(number) if self.step_back(&mut versions, number) => {}
            _ => Self::invalidate_locked(&mut versions, "the tree cuts entry-file records older than the view's journals"),
        }
        Self::publish_to(&mut readers, &versions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_twig_core::{
        offsets::StandaloneOffsets,
        qmdb_compat::{encode_gov5_account_value, GOV5_EMPTY_CODE_HASH},
    };
    use std::io::Write as _;

    /// An entry file written by hand (`[key 32][len u32 LE][value]` records),
    /// with the slot offsets a tree would hold for it.
    struct HandFile {
        out: std::io::BufWriter<std::fs::File>,
        offsets: StandaloneOffsets,
        at: u64,
    }

    impl HandFile {
        fn create(path: &Path) -> Self {
            let out = std::io::BufWriter::new(std::fs::File::create(path).expect("the entry file"));
            Self { out, offsets: StandaloneOffsets::default(), at: 0 }
        }

        /// Appends a record; returns its slot.
        fn put(&mut self, key: &Hash, value: &[u8]) -> u64 {
            self.out.write_all(key).expect("write");
            self.out.write_all(&(value.len() as u32).to_le_bytes()).expect("write");
            self.out.write_all(value).expect("write");
            self.offsets.push(self.at).expect("room");
            self.at += 36 + value.len() as u64;
            self.offsets.len() - 1
        }

        /// An account record for `address`; returns its key and slot.
        fn account(&mut self, address: &Address, nonce: u64, balance: u64) -> (Hash, u64) {
            let key = gov5_account_key(&address.0 .0);
            let value = encode_gov5_account_value(nonce, &U256::from(balance).to_be_bytes::<32>(), &GOV5_EMPTY_CODE_HASH);
            (key, self.put(&key, &value))
        }

        fn flush(&mut self) {
            self.out.flush().expect("flush");
        }

        fn reader(&self) -> OffsetsReader {
            self.offsets.reader()
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-view-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn accounts_decode_as_gov5_encodes_them() {
        let code = B256::repeat_byte(7);
        for (nonce, balance, code_hash, expected_code) in [
            (0u64, U256::ZERO, B256::ZERO, None),
            (1, U256::from(1), alloy_primitives::KECCAK256_EMPTY, None),
            (300, U256::from(10u64).pow(U256::from(24)), code, Some(code)),
            (u64::MAX, U256::MAX, code, Some(code)),
        ] {
            let value = encode_gov5_account_value(nonce, &balance.to_be_bytes::<32>(), &code_hash.0);
            assert_eq!(decode_account(&value), Some(Account { nonce, balance, bytecode_hash: expected_code }));
        }
        assert_eq!(decode_account(&[]), None);
        assert_eq!(decode_account(&[2, 5, 1]), None, "a truncated balance");
    }

    /// Stage 1: the view keeps serving past what used to be its limit (the
    /// one 1 TiB mapping, here segments of 64 KiB): blocks whose records lie
    /// several segments into the file advance it, and every read answers.
    #[test]
    fn the_view_serves_past_its_first_mapping_segment() {
        let dir = scratch("segments");
        let path = dir.join("entries.log");
        let mut hand = HandFile::create(&path);
        let address = |i: u64| Address::from_slice(&alloy_primitives::keccak256(i.to_be_bytes())[12..]);
        let live: Vec<(Hash, u64)> = (0..100).map(|i| hand.account(&address(i), 1, 1)).collect();
        hand.flush();
        let view = QmdbReadView::build_with_segment_bits(&path, hand.reader(), (1, B256::ZERO), live, 16).expect("the view");
        // ~41 bytes a record: 160 blocks of 100 accounts take the file past
        // nine 64 KiB segments.
        for b in 0..160u64 {
            let mut changes: Vec<(Hash, Option<u64>)> =
                (0..100).map(|i| hand.account(&address(i), b + 2, b + 2)).map(|(key, slot)| (key, Some(slot))).collect();
            hand.flush();
            changes.sort_unstable_by_key(|(key, _)| *key);
            let raised = view.raise_floor(&changes);
            view.advance(b + 2, B256::with_last_byte(b as u8 + 2), &changes, raised);
            assert!(view.is_valid(), "block {}", b + 2);
        }
        assert!(hand.at > 9 << 16, "{} bytes", hand.at);
        for i in 0..100 {
            assert_eq!(view.account(&address(i), 161).map(|a| a.map(|a| a.nonce)), Some(Some(161)));
            assert_eq!(view.account(&address(i), 120).map(|a| a.map(|a| a.nonce)), Some(Some(120)), "through the journals");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The journals hold slots: a block's journal names each key's slot
    /// before it, reads behind the head answer from those slots, and a step
    /// back puts them back in the index.
    #[test]
    fn journals_round_trip_in_slots() {
        let dir = scratch("journal-slots");
        let path = dir.join("entries.log");
        let mut hand = HandFile::create(&path);
        let address = |i: u64| Address::with_last_byte(i as u8 + 1);
        let live: Vec<(Hash, u64)> = (0..8).map(|i| hand.account(&address(i), 1, 1)).collect();
        let slots_at_one: std::collections::HashMap<Hash, u64> = live.iter().copied().collect();
        let mut blocks = Vec::new();
        for b in 0..3u64 {
            let mut changes: Vec<(Hash, Option<u64>)> =
                (0..8).filter(|i| i % 2 == b % 2).map(|i| hand.account(&address(i), b + 2, 0)).map(|(k, s)| (k, Some(s))).collect();
            changes.sort_unstable_by_key(|(key, _)| *key);
            blocks.push(changes);
        }
        hand.flush();
        let view = QmdbReadView::build(&path, hand.reader(), (1, B256::ZERO), live).expect("the view");
        for (b, changes) in blocks.iter().enumerate() {
            let raised = view.raise_floor(changes);
            view.advance(b as u64 + 2, B256::with_last_byte(b as u8 + 2), changes, raised);
        }
        {
            let versions = view.versions.read().expect("versions");
            let first = &versions.journals[0];
            assert_eq!(first.floor_before, 8, "the slots read before block 2");
            for (key, before) in first.journal.iter() {
                assert_eq!(*before, Some(slots_at_one[key]), "block 2's journal names the slot at block 1");
            }
            assert_eq!(versions.head_floor, 8 + 4 * 3);
        }
        assert_eq!(view.journal_floor(), 8);
        let nonce = |at: u64, i: u64| view.account(&address(i), at).map(|a| a.map(|a| a.nonce));
        assert_eq!((nonce(4, 0), nonce(4, 1)), (Some(Some(4)), Some(Some(3))));
        assert_eq!((nonce(1, 0), nonce(1, 1)), (Some(Some(1)), Some(Some(1))));
        assert_eq!((nonce(2, 0), nonce(2, 1)), (Some(Some(2)), Some(Some(1))));
        assert!(view.revert_to(2));
        assert_eq!(view.head().0, 2);
        assert_eq!((nonce(2, 0), nonce(2, 1)), (Some(Some(2)), Some(Some(1))), "the index holds block 2's slots again");
        assert_eq!(view.journal_floor(), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tree in file mode, its accounts `0..n` written at nonce 1 and the
    /// first `dead` of every 2048 rewritten at nonce 2 (so their first slots
    /// die), and a view over it.
    fn compactable(dir: &Path, twigs: u64, dead: u64) -> (n42_twig_core::qmdb_compat::QmdbCompatTree, Arc<QmdbReadView>, Vec<Address>) {
        use n42_twig_core::{qmdb_compat::{QmdbCompatTree, QmdbOperation}, TWIG_SIZE};
        let n = twigs * TWIG_SIZE as u64;
        let addresses: Vec<Address> = (0..n).map(|i| Address::from_slice(&alloy_primitives::keccak256(i.to_be_bytes())[12..])).collect();
        let op = |address: &Address, nonce: u64| QmdbOperation {
            key: gov5_account_key(&address.0 .0),
            value: Some(encode_gov5_account_value(nonce, &U256::from(nonce).to_be_bytes::<32>(), &GOV5_EMPTY_CODE_HASH)),
        };
        let sorted = |mut ops: Vec<QmdbOperation>| {
            ops.sort_unstable_by_key(|op| op.key);
            ops
        };
        let mut tree = QmdbCompatTree::new();
        tree.set_entry_file(&dir.join("entries.log")).expect("the entry file");
        // Slot order is key order within a block: write the accounts one
        // twig-sized block at a time so twig t holds accounts of block t.
        for t in 0..twigs {
            let block: Vec<QmdbOperation> = (t * TWIG_SIZE as u64..(t + 1) * TWIG_SIZE as u64).map(|i| op(&addresses[i as usize], 1)).collect();
            tree.apply_sorted_ops(sorted(block)).expect("a block");
        }
        let rewrite: Vec<QmdbOperation> =
            (0..n).filter(|i| i % TWIG_SIZE as u64 >= TWIG_SIZE as u64 - dead).map(|i| op(&addresses[i as usize], 2)).collect();
        tree.apply_sorted_ops(sorted(rewrite)).expect("the rewrite");
        tree.flush_entries_for_sync().expect("flush");
        let view = QmdbReadView::build(
            &dir.join("entries.log"),
            tree.entry_offsets_reader().expect("file mode"),
            (2, B256::with_last_byte(2)),
            tree.live_entry_slots().expect("file mode"),
        )
        .expect("the view");
        (tree, view, addresses)
    }

    /// Stage 1: a slot that a compaction relocated is read from
    /// `entries.relocated`. The old bytes in `entries.log` are zeroed after
    /// the compaction (what stage 3's punch leaves), and every read through
    /// the view still answers as before.
    #[test]
    fn a_relocated_slot_reads_the_relocated_record() {
        use n42_twig_core::TWIG_SIZE;
        let dir = scratch("relocated");
        let (mut tree, view, addresses) = compactable(&dir, 2, 1536);
        let reads = |view: &QmdbReadView| -> Vec<_> { addresses.iter().map(|a| view.account(a, 2).map(|a| a.map(|a| a.nonce))).collect() };
        let before = reads(&view);
        assert!(before.iter().all(|r| matches!(r, Some(Some(1 | 2)))), "every account answers");
        let main: Vec<u64> = (0..2 * TWIG_SIZE as u64).map(|slot| tree.entry_offset(slot).expect("a main-file slot")).collect();
        let end = tree.entry_offset(2 * TWIG_SIZE as u64).expect("the rewrite's first slot");
        let report = tree.compact_twigs(u64::MAX, 0.5, usize::MAX).expect("the compaction");
        assert_eq!(report.twigs, 2);
        assert_eq!(tree.entry_offset(0), None, "a relocated slot has no main-file offset");
        // Zero the two twigs' old records, as a punch would.
        {
            use std::os::unix::fs::FileExt as _;
            let file = std::fs::OpenOptions::new().write(true).open(dir.join("entries.log")).expect("the entry file");
            file.write_all_at(&vec![0u8; (end - main[0]) as usize], main[0]).expect("zero");
            file.sync_all().expect("sync");
        }
        assert_eq!(reads(&view), before, "the relocated records answer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Readers on other threads while compactions retarget slots under them
    /// read the old location or the new one, and every answer is the right
    /// one: never a torn or foreign record.
    #[test]
    fn reads_during_a_retarget_answer_old_or_new_never_garbage() {
        let dir = scratch("retarget");
        let (mut tree, view, addresses) = compactable(&dir, 4, 1536);
        let expected: Vec<_> = addresses.iter().map(|a| view.account(a, 2).map(|a| a.map(|a| a.nonce))).collect();
        assert!(expected.iter().all(|r| matches!(r, Some(Some(1 | 2)))));
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let readers: Vec<_> = (0..4)
                .map(|t| {
                    let (view, addresses, expected, done) = (&view, &addresses, &expected, &done);
                    scope.spawn(move || {
                        let mut reads = 0u64;
                        let mut i = t * 997;
                        while !done.load(Ordering::Acquire) || reads < 20_000 {
                            let k = i % addresses.len();
                            assert_eq!(view.account(&addresses[k], 2).map(|a| a.map(|a| a.nonce)), expected[k], "account {k}");
                            reads += 1;
                            i += 7;
                        }
                        reads
                    })
                })
                .collect();
            for _ in 0..4 {
                assert_eq!(tree.compact_twigs(u64::MAX, 0.5, 1).expect("a compaction").twigs, 1);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            done.store(true, Ordering::Release);
            for reader in readers {
                assert!(reader.join().expect("a reader") >= 20_000);
            }
        });
        assert_eq!(tree.compact_twigs(u64::MAX, 0.5, usize::MAX).expect("nothing left").twigs, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_overflowing_account_nonce_is_declined() {
        for last in [2, 0x7f, 0x80, 0xff] {
            let mut value = vec![1];
            value.extend_from_slice(&[0x80; 9]);
            value.push(last);
            assert_eq!(decode_account(&value), None, "overflow must not become a different nonce");
        }
    }

    /// Concurrent reads of the view (plan v6, the read view's contention):
    /// 160k distinct keys of a 2M-key view read at 1, 4 and 16 threads, at the
    /// head (no journal walked) and 16 blocks behind it (16 journals walked),
    /// each on a fresh mapping (`cold`: every page faulted in by the reads) and
    /// again on the same mapping (`warm`), beside the same reads with no
    /// versions lock (`raw`: index and record only). Pinned:
    /// `taskset -c 0-31 cargo test -p n42-qmdb-reth --release --lib bench_concurrent_reads -- --ignored --nocapture`.
    /// A read whose reader slot a publish holds waits, is counted as a slot
    /// wait (`ViewLockWaits`), and answers what an unheld read answers.
    #[test]
    fn a_read_behind_a_publish_is_counted_and_answers_the_same() {
        let dir = scratch("waits");
        let path = dir.join("entries.log");
        let address = Address::with_last_byte(0x24);
        let mut hand = HandFile::create(&path);
        let live = hand.account(&address, 5, 9);
        hand.flush();
        let view = QmdbReadView::build(&path, hand.reader(), (1, B256::ZERO), vec![live]).expect("the view");
        let unheld = view.account(&address, 1);
        assert_eq!(unheld.map(|a| a.map(|a| a.nonce)), Some(Some(5)));
        let ready = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let held = view.lock_readers();
            let reader = scope.spawn(|| {
                ready.wait();
                let before = ViewLockWaits::now();
                let found = view.account(&address, 1);
                (found, ViewLockWaits::now().since(before))
            });
            ready.wait();
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
            let (found, waits) = reader.join().expect("the reader");
            assert_eq!(found, unheld);
            assert_eq!(waits.slot_waits, 1);
            assert!(waits.slot_wait_ns > 0, "waited {} ns", waits.slot_wait_ns);
            assert_eq!(waits.index_waits, 0);
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A persistence batch longer than the journals: the database's readers
    /// stay at the batch's start until it commits, and are answered.
    #[test]
    fn a_batch_longer_than_the_journals_keeps_the_readers_at_its_start() {
        let dir = scratch("held");
        let path = dir.join("entries.log");
        let mut hand = HandFile::create(&path);
        let address = Address::with_last_byte(0x42);
        let live = vec![hand.account(&address, 1, 1)];
        let batch = JOURNAL_DEPTH as u64 + 20;
        let blocks: Vec<Vec<(Hash, Option<u64>)>> = (0..batch)
            .map(|b| hand.account(&address, b + 2, b + 2))
            .map(|(key, slot)| vec![(key, Some(slot))])
            .collect();
        hand.flush();
        let nonce_at = |view: &QmdbReadView, at: u64| view.account(&address, at).map(|a| a.map(|a| a.nonce));
        for held in [false, true] {
            let view = QmdbReadView::build(&path, hand.reader(), (1, B256::ZERO), live.clone()).expect("the view");
            if held {
                view.hold_journals_from(1);
            }
            for (b, changes) in blocks.iter().enumerate() {
                let raised = view.raise_floor(changes);
                view.advance(b as u64 + 2, B256::with_last_byte(b as u8 + 2), changes, raised);
            }
            assert_eq!(nonce_at(&view, batch + 1), Some(Some(batch + 1)), "the head answers");
            if held {
                assert_eq!(nonce_at(&view, 1), Some(Some(1)), "the batch's start answers until the next batch");
                // The next batch: the previous one committed, the journals trim.
                view.hold_journals_from(batch + 1);
                let (key, slot) = hand.account(&address, batch + 2, batch + 2);
                hand.flush();
                let changes = vec![(key, Some(slot))];
                let raised = view.raise_floor(&changes);
                view.advance(batch + 2, B256::with_last_byte(0xEE), &changes, raised);
                assert_eq!(nonce_at(&view, 1), None, "trimmed to the depth once the batch is behind");
                assert_eq!(nonce_at(&view, batch + 1), Some(Some(batch + 1)));
            } else {
                assert_eq!(nonce_at(&view, 1), None, "without the hold the start is past the journals");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `N42_VIEW_JOURNAL_FILTER`: a view whose journals carry filters gives
    /// every read the answer a view without them gives, at the head and at
    /// every depth its journals reach, for keys the blocks changed (some
    /// several times), keys they never changed and keys that do not exist;
    /// and the filters skip journals.
    /// `prefetch_account` is a hint: for a key the view holds and one it does
    /// not, at the head and behind it, every read answers as before and no
    /// counter of the calling thread moves (journal walks, slot and index
    /// waits).
    #[test]
    fn the_account_hint_changes_no_read_and_no_counter() {
        let dir = scratch("hint");
        let path = dir.join("entries.log");
        let mut hand = HandFile::create(&path);
        let address = |i: u64| Address::from_slice(&alloy_primitives::keccak256(i.to_be_bytes())[12..]);
        let keys = 1_000u64;
        let live: Vec<(Hash, u64)> = (0..keys).map(|i| hand.account(&address(i), 1, 1)).collect();
        let mut changes: Vec<(Hash, Option<u64>)> =
            (0..keys).step_by(3).map(|i| hand.account(&address(i), 2, 2)).map(|(key, slot)| (key, Some(slot))).collect();
        changes.sort_unstable_by_key(|(key, _)| *key);
        hand.flush();
        let view = QmdbReadView::build(&path, hand.reader(), (1, B256::ZERO), live).expect("the view");
        let raised = view.raise_floor(&changes);
        view.advance(2, B256::with_last_byte(2), &changes, raised);
        // Present keys and absent ones (`keys..keys + 200`), at the head (2)
        // and one block behind it (1).
        let reads = |view: &QmdbReadView| -> Vec<_> {
            (0..keys + 200).flat_map(|i| [view.account(&address(i), 2), view.account(&address(i), 1)]).collect()
        };
        let before = reads(&view);
        assert!(before.iter().all(Option::is_some), "the view answers");
        assert!(before.iter().any(|a| matches!(a, Some(None))), "absent keys are read too");
        let counters = || (JOURNAL_LOCAL.with(std::cell::Cell::get), ViewLockWaits::now());
        let (journal, waits) = counters();
        let mut issued = 0;
        for i in 0..keys + 200 {
            issued += usize::from(view.prefetch_account(&address(i)));
        }
        let (journal_after, waits_after) = counters();
        assert_eq!(issued as u64, keys + 200, "an uncontended index takes every hint");
        assert_eq!(journal, journal_after, "no journal walk counted");
        assert_eq!(
            (waits.slot_waits, waits.index_waits),
            (waits_after.slot_waits, waits_after.index_waits),
            "no lock wait counted"
        );
        assert_eq!(before, reads(&view), "every read answers as before");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_filters_change_no_answer() {
        let dir = scratch("filters");
        let path = dir.join("entries.log");
        let mut hand = HandFile::create(&path);
        let address = |i: u64| Address::from_slice(&alloy_primitives::keccak256(i.to_be_bytes())[12..]);
        let keys = 4_000u64;
        let live: Vec<(Hash, u64)> = (0..keys).map(|i| hand.account(&address(i), 1, 1)).collect();
        // Six blocks, each re-writing a tenth of the keys (overlapping) and
        // creating a few new ones.
        let blocks: Vec<Vec<(Hash, Option<u64>)>> = (0..6u64)
            .map(|b| {
                let mut changes: Vec<(Hash, Option<u64>)> = (0..keys)
                    .filter(|i| (i * 7 + b * 3) % 10 == 0)
                    .chain((0..20).map(|n| keys + b * 20 + n))
                    .map(|i| {
                        let (key, slot) = hand.account(&address(i), b + 2, b + 2);
                        (key, Some(slot))
                    })
                    .collect();
                changes.sort_unstable_by_key(|(key, _)| *key);
                changes
            })
            .collect();
        hand.flush();
        let views: Vec<Arc<QmdbReadView>> = [false, true]
            .into_iter()
            .map(|filtered| {
                let view = QmdbReadView::build(&path, hand.reader(), (1, B256::ZERO), live.clone()).expect("the view");
                view.set_journal_filter(filtered);
                for (b, changes) in blocks.iter().enumerate() {
                    let raised = view.raise_floor(changes);
                    view.advance(b as u64 + 2, B256::with_last_byte(b as u8 + 2), changes, raised);
                }
                view
            })
            .collect();
        for at in 1..=7u64 {
            for i in 0..keys + 200 {
                let (plain, filtered) = (views[0].account(&address(i), at), views[1].account(&address(i), at));
                assert_eq!(plain, filtered, "key {i} at {at}");
                assert!(plain.is_some(), "the view answers at {at}");
            }
        }
        // The filtered view alone, on a thread of its own: its counts fold in
        // whole every 4,096 reads.
        let _ = take_journal_counters();
        let filtered = Arc::clone(&views[1]);
        std::thread::spawn(move || {
            for i in 0..8192u64 {
                let _ = filtered.account(&address(i % keys), 1);
            }
        })
        .join()
        .expect("the reads");
        let (reads, searches, skips) = take_journal_counters();
        assert!(reads >= 8192, "every read had journals to walk ({reads})");
        assert!(skips > searches, "the filters skipped most journals ({skips} skipped, {searches} searched)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "timing"]
    fn bench_concurrent_reads() {
        use alloy_primitives::keccak256;
        // `N42_BENCH_VIEW_KEYS` / `_READS` / `_THREADS` scale it (an offsets
        // array past the last-level cache needs 50M keys or more).
        let env = |name: &str, default: u64| std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default);
        let keys = env("N42_BENCH_VIEW_KEYS", 2_000_000);
        let reads = env("N42_BENCH_VIEW_READS", 160_000) as usize;
        let thread_counts: Vec<usize> = std::env::var("N42_BENCH_VIEW_THREADS")
            .ok()
            .map(|v| v.split(',').filter_map(|t| t.trim().parse().ok()).collect())
            .unwrap_or_else(|| vec![1, 4, 16]);
        let behind = 16u64;
        let per_block = 10_000u64;
        let address_of = |i: u64| Address::from_slice(&keccak256(i.to_be_bytes())[12..]);
        let dir = std::env::temp_dir().join(format!("n42-bench-view-reads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("entries.log");
        let mut hand = HandFile::create(&path);
        let live: Vec<(Hash, u64)> = (0..keys).map(|i| hand.account(&address_of(i), 0, 1)).collect();
        hand.flush();
        // Blocks 2..=17 each rewrite `per_block` keys, so a reader at block 1 walks 16 journals.
        let mut blocks = Vec::new();
        for b in 0..behind {
            let mut changes: Vec<(Hash, Option<u64>)> = (0..per_block)
                .map(|j| hand.account(&address_of((b * 7_919 + j * 199) % keys), b + 1, b + 2))
                .map(|(key, slot)| (key, Some(slot)))
                .collect();
            changes.sort_unstable_by_key(|(key, _)| *key);
            changes.dedup_by_key(|(key, _)| *key);
            blocks.push(changes);
        }
        hand.flush();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut picks: Vec<u64> = Vec::with_capacity(reads * 2);
        let mut seen = std::collections::HashSet::new();
        while picks.len() < reads * 2 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            if seen.insert(seed % keys) {
                picks.push(seed % keys);
            }
        }
        let addresses: Vec<Address> = picks.iter().map(|i| address_of(*i)).collect();
        let (first, second) = addresses.split_at(reads);
        let build = || {
            let view = QmdbReadView::build(&path, hand.reader(), (1, B256::ZERO), live.clone()).expect("the view");
            for (b, changes) in blocks.iter().enumerate() {
                let raised = view.raise_floor(changes);
                view.advance(b as u64 + 2, B256::with_last_byte(b as u8 + 2), changes, raised);
            }
            view
        };
        let time = |threads: usize, f: &(dyn Fn(&Address) -> bool + Sync), addresses: &[Address]| {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("a pool");
            let start = std::time::Instant::now();
            let found = pool.install(|| addresses.par_iter().with_min_len(64).filter(|a| f(a)).count());
            assert_eq!(found, addresses.len(), "every key answers");
            start.elapsed().as_secs_f64() * 1e6 * threads as f64 / addresses.len() as f64
        };
        println!("us a read of pool time (wall x threads / reads), {reads} distinct keys of {keys}");
        println!("{:>7} {:>6} {:>9} {:>9} {:>9}", "threads", "at", "cold", "warm", "raw warm");
        for threads in thread_counts.iter().copied() {
            for at in [1 + behind, 1] {
                let view = build();
                let read = |a: &Address| matches!(view.account(a, at), Some(Some(_)));
                let raw = |a: &Address| {
                    let key = gov5_account_key(&a.0 .0);
                    // SAFETY: slots of the built view's own flushed records.
                    view.index
                        .get(&key, |slot| unsafe { view.file.key(slot) }.unwrap_or(NO_KEY))
                        .is_some_and(|slot| unsafe { view.file.record(slot) }.is_some_and(|(_, value)| decode_account(value).is_some()))
                };
                let cold = time(threads, &read, first);
                let warm = time(threads, &read, second);
                let raw_warm = time(threads, &raw, second);
                println!("{threads:>7} {:>6} {cold:>9.3} {warm:>9.3} {raw_warm:>9.3}", if at == 1 { "-16" } else { "head" });
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

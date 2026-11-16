// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QMDB state at past heights: retention behind `N42_QMDB_HISTORY`, and
//! membership proofs against the root a past header carries
//! (`docs/QMDB_HISTORY.md`).
//!
//! A QMDB root is a pure function of three things: the entry log (append-only;
//! a slot's leaf hash is frozen at its append), the append cursor, and the
//! active bit of every slot below it. So the state after a block is its cursor
//! plus its active bits, and what one block changes is its delta: the cursor
//! it moved to and the slots it retired -- exactly the file-mode
//! [`ForestDelta`] the node already writes to `forest.log`. History keeps
//! those deltas instead of folding them away:
//!
//! - `history/base.ckpt`: the [`ForestCheckpoint`] (cursor + active bits) of
//!   the earliest block history covers;
//! - `history/spans.log`: every persisted block's delta after it, framed as
//!   `forest.log` frames them (length, CRC-32, bincode payload);
//! - `history/twigs.idx`: the leaf root of every full twig, 32 bytes a twig,
//!   a cache of what the entry log hashes to (rebuilt when it disagrees).
//!
//! A proof at block `N` is the twig proof the head proof is
//! ([`QmdbProof`], gov5's v2 layout), cut from the tree as it stood after `N`:
//!
//! - the twig roots a block after `N` did not touch are the history head's;
//! - a touched twig is rebuilt at twig granularity: its bits at `N` are the
//!   head's with every later retirement undone and every slot at or past the
//!   cursor of `N` cleared; its leaf root is the frozen one for a twig full at
//!   `N`, or re-folded from the entry log for the youngest, partial twig;
//! - the upper tree is the head's with the touched leaves replaced and their
//!   ancestors rehashed, read in the shape (power-of-two capacity) of `N`.
//!
//! The root this yields is compared with the root the caller's header carries
//! before any proof leaves; every proof is verified against it as well. A
//! mismatch is an error, never a proof.
//!
//! Nothing here takes the forest's lock or moves the live tree, except a key
//! index probe ([`LiveTree::live_slot_of`]) whose answer is only a candidate:
//! a slot is used only when its record holds the key and its active bit at
//! `N` is set, and a QMDB tree has at most one live slot per key.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, RwLock},
};

use alloy_primitives::B256;
use n42_qmdb_state::{ForestCheckpoint, ForestDelta};
use n42_twig_core::{
    hash_leaf, hash_node,
    offsets::OffsetsReader,
    qmdb_compat::{twig_bits_hash, twig_leaf_tree, QmdbProof, TWIG_BITS_BYTES},
    Hash, NULL_HASH, TWIG_HEIGHT, TWIG_SIZE,
};
use tracing::{error, info, warn};

/// The environment variable that turns history on.
pub const HISTORY_ENV: &str = "N42_QMDB_HISTORY";
/// The directory under the QMDB directory.
pub const HISTORY_DIR: &str = "history";
const BASE_FILE: &str = "base.ckpt";
const LOG_FILE: &str = "spans.log";
const TWIGS_FILE: &str = "twigs.idx";
/// Framing of a record in `spans.log`: as `forest.log` (length, digest).
const RECORD_HEADER: usize = 12;
/// Key reads one key lookup may make before it gives up with an error.
const LOOKUP_BUDGET: u64 = 4_000_000;
/// A slot offset with this bit names `entries.relocated` (compaction).
const RELOCATED_BIT: u64 = 1 << 63;
/// The `len` field of a hash-only record in `entries.log`.
const HASH_ONLY_LEN: u32 = u32::MAX;

/// What `N42_QMDB_HISTORY` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    /// No history (the default): today's behaviour, nothing written.
    Off,
    /// Keep the last `n` persisted blocks provable.
    Keep(u64),
    /// Keep every block from where history started.
    All,
}

impl HistoryMode {
    /// Parses a value: unset, empty, `off` or `0` is [`Self::Off`]; `all` or
    /// `archive` is [`Self::All`]; a positive integer is [`Self::Keep`].
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "" | "off" | "0" => Ok(Self::Off),
            "all" | "archive" => Ok(Self::All),
            other => other
                .parse::<u64>()
                .map(Self::Keep)
                .map_err(|_| format!("{HISTORY_ENV}={other}: expected a block count, `all`, or `off`")),
        }
    }

    /// The mode the environment asks for.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(HISTORY_ENV) {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Ok(Self::Off),
        }
    }

    /// Whether anything is kept.
    pub const fn is_on(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Why a historical proof was not served.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum HistoryError {
    /// The node keeps no QMDB history.
    #[error("this node keeps no QMDB history (set N42_QMDB_HISTORY=<blocks>|all; file-mode entries required)")]
    Disabled,
    /// The block lies below the earliest one history covers.
    #[error("QMDB history for block {requested} is pruned or was never kept; the earliest provable block is {earliest}")]
    Pruned {
        /// The block asked for.
        requested: u64,
        /// The earliest block history can prove.
        earliest: u64,
    },
    /// The block lies above the newest one history covers.
    #[error("QMDB history reaches block {latest}; block {requested} is not recorded yet")]
    NotYet {
        /// The block asked for.
        requested: u64,
        /// The newest recorded block.
        latest: u64,
    },
    /// The block was persisted inside a multi-block delta, or is not the block
    /// history holds at that height.
    #[error("QMDB history holds no state for block {number} ({hash})")]
    NotRecorded {
        /// The block asked for.
        number: u64,
        /// Its hash.
        hash: B256,
    },
    /// A branch rewind of persisted state lies above the block.
    #[error("a rewind of persisted QMDB state at block {at} lies above block {requested}; heights below it are not provable")]
    Rewound {
        /// The block asked for.
        requested: u64,
        /// The rewinding record.
        at: u64,
    },
    /// The reconstructed root is not the one the header carries.
    #[error("the QMDB root rebuilt for block {number} is {computed} but its header carries {expected}")]
    RootMismatch {
        /// The block.
        number: u64,
        /// What history rebuilt.
        computed: B256,
        /// What the header carries.
        expected: B256,
    },
    /// A key's lookup would read more records than one request may.
    #[error("locating key {0} at the requested block exceeds the lookup budget")]
    LookupBudget(B256),
    /// The key changed above the history head; try again once it is persisted.
    #[error("key {0} changed after the newest recorded block; retry once it is persisted")]
    Retry(B256),
    /// A history or entry file could not be read, or held what it should not.
    #[error("QMDB history: {0}")]
    Io(String),
}

impl From<io::Error> for HistoryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// What a prover asks of the live tree: never a move, never the tree's
/// lock for longer than an index probe.
pub trait LiveTree {
    /// The slot of `key`'s live entry on the tree as it stands now.
    fn live_slot_of(&self, key: &Hash) -> Option<u64>;
    /// A lock-free reader of the entry log's record offsets.
    fn offsets_reader(&self) -> Option<OffsetsReader>;
}

/// One key's answer at a past block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAtHeight {
    /// The raw QMDB key.
    pub key: Hash,
    /// The membership proof, or `None` when the key had no live entry at the
    /// block (not provable: QMDB proofs prove membership only).
    pub proof: Option<QmdbProof>,
}

/// A historical proof bundle: the root of block `number` and one answer per
/// key, every proof verified against that root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalProof {
    /// The block.
    pub number: u64,
    /// Its hash.
    pub hash: B256,
    /// The QMDB root after it.
    pub root: B256,
    /// One answer per key asked, in order.
    pub keys: Vec<KeyAtHeight>,
}

/// What `spans.log` holds for one record, read without its slot lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordMeta {
    number: u64,
    hash: B256,
    base_next_slot: u64,
    next_slot: u64,
    offset: u64,
    len: u64,
    /// Its base is below the previous cursor or it revives a slot: a branch
    /// rewind, which the reverse walk cannot undo.
    rewind: bool,
    /// Its number does not follow the previous one: the heights in between
    /// were persisted inside it and are not provable.
    span: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseMeta {
    number: u64,
    hash: B256,
    next_slot: u64,
}

#[derive(Debug)]
struct Index {
    base: BaseMeta,
    records: Vec<RecordMeta>,
    log_len: u64,
    /// Bumped on every change that is not an append (truncation, prune,
    /// rebase): a prover's cache built on an older generation is rebuilt.
    generation: u64,
    /// Why recording stopped, if it did: history then ends at its last
    /// record until the next start rebases it.
    broken: Option<String>,
}

impl Index {
    fn head(&self) -> BaseMeta {
        self.records
            .last()
            .map_or(self.base, |r| BaseMeta { number: r.number, hash: r.hash, next_slot: r.next_slot })
    }
}

/// The node's QMDB history.
pub struct QmdbHistory {
    dir: PathBuf,
    entry_path: PathBuf,
    mode: HistoryMode,
    index: RwLock<Index>,
    /// Serialises file writes (record, truncate, prune, rebase).
    writer: Mutex<()>,
    prover: Mutex<Option<HeadState>>,
    /// The generation a root mismatch last rebuilt the twig cache for: one
    /// rebuild per generation, so a request that keeps disagreeing with its
    /// header cannot make every request rehash the state.
    rebuilt_for: Mutex<Option<u64>>,
}

impl std::fmt::Debug for QmdbHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbHistory").field("dir", &self.dir).field("mode", &self.mode).finish_non_exhaustive()
    }
}

fn io_at(path: &Path, error: impl std::fmt::Display) -> HistoryError {
    HistoryError::Io(format!("{}: {error}", path.display()))
}

fn frame(delta: &ForestDelta) -> Result<Vec<u8>, HistoryError> {
    let payload = bincode::serialize(delta).map_err(|e| HistoryError::Io(e.to_string()))?;
    let mut record = Vec::with_capacity(RECORD_HEADER + payload.len());
    record.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    record.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    record.extend_from_slice(&payload);
    Ok(record)
}

fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = File::create(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)?;
    sync_dir(path)
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn read_base(path: &Path) -> Result<Option<ForestCheckpoint>, HistoryError> {
    match std::fs::read(path) {
        Ok(bytes) => bincode::deserialize(&bytes).map(Some).map_err(|e| io_at(path, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_at(path, e)),
    }
}

fn write_base(path: &Path, ckpt: &ForestCheckpoint) -> Result<(), HistoryError> {
    let bytes = bincode::serialize(ckpt).map_err(|e| io_at(path, e))?;
    write_durably(path, &bytes).map_err(|e| io_at(path, e))
}

/// The records of `spans.log` after `base`, up to the first torn or
/// undecodable one, and the bytes they take. Records at or below the base's
/// block (a prune that renamed the base before the log) are skipped.
fn scan_log(path: &Path, base: &BaseMeta) -> Result<(Vec<RecordMeta>, u64), HistoryError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(io_at(path, e)),
    };
    let mut records: Vec<RecordMeta> = Vec::new();
    let mut at = 0usize;
    let mut kept_end = 0u64;
    while at + RECORD_HEADER <= bytes.len() {
        let len = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
        let Ok(len) = usize::try_from(len) else { break };
        let start = at + RECORD_HEADER;
        let Some(end) = start.checked_add(len) else { break };
        let Some(payload) = bytes.get(start..end) else { break };
        if bytes[at + 8..start] != crc32fast::hash(payload).to_le_bytes() {
            warn!(target: "n42.qmdb.history", offset = at, "the QMDB history log is torn here; ignoring the rest");
            break;
        }
        let Ok(delta) = bincode::deserialize::<ForestDelta>(payload) else { break };
        if delta.head_number <= base.number && records.is_empty() {
            at = end;
            continue;
        }
        let prev = records.last().map_or(*base, |r| BaseMeta { number: r.number, hash: r.hash, next_slot: r.next_slot });
        if delta.head_number <= prev.number || delta.base_next_slot > prev.next_slot {
            warn!(
                target: "n42.qmdb.history", offset = at, block = delta.head_number,
                "a QMDB history record does not follow the one before it; ignoring the rest",
            );
            break;
        }
        records.push(RecordMeta {
            number: delta.head_number,
            hash: delta.head_hash,
            base_next_slot: delta.base_next_slot,
            next_slot: delta.next_slot,
            offset: at as u64,
            len: (end - at) as u64,
            rewind: delta.base_next_slot < prev.next_slot || delta.changed.iter().any(|(_, active)| *active),
            span: delta.head_number != prev.number + 1,
        });
        kept_end = end as u64;
        at = end;
    }
    Ok((records, kept_end))
}

impl QmdbHistory {
    /// Opens (or starts) history for a node whose QMDB state stands at
    /// `head` with cursor `head_next_slot`, under `qmdb_dir`.
    ///
    /// History must reach the head exactly: records above it (the forest ran
    /// ahead of the database) are cut, and a history that ends below it or
    /// names another block there (history was off for a while, or a record
    /// was lost) cannot prove anything after its end -- it is discarded and
    /// started again at the head, with an error logged naming the earliest
    /// provable block. A node that never kept history starts at its head:
    /// heights below it are reported as pruned.
    pub fn open(
        qmdb_dir: &Path,
        mode: HistoryMode,
        head: (u64, B256),
        head_checkpoint: impl FnOnce() -> Result<ForestCheckpoint, String>,
    ) -> Result<Self, HistoryError> {
        let dir = qmdb_dir.join(HISTORY_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        let base_path = dir.join(BASE_FILE);
        let log_path = dir.join(LOG_FILE);
        let mut head_checkpoint = Some(head_checkpoint);
        let mut fresh = |why: &str| -> Result<Index, HistoryError> {
            let ckpt = (head_checkpoint.take().expect("history is started once"))().map_err(HistoryError::Io)?;
            if (ckpt.head_number, ckpt.head_hash) != head {
                return Err(HistoryError::Io(format!(
                    "the head checkpoint stands at block {} ({}), not at the head {} ({})",
                    ckpt.head_number, ckpt.head_hash, head.0, head.1
                )));
            }
            for stale in [&log_path, &dir.join(TWIGS_FILE)] {
                match std::fs::remove_file(stale) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(io_at(stale, e)),
                }
            }
            write_base(&base_path, &ckpt)?;
            info!(target: "n42.qmdb.history", block = head.0, hash = %head.1, slots = ckpt.next_slot, why, "QMDB history starts here; earlier blocks are not provable");
            Ok(Index {
                base: BaseMeta { number: ckpt.head_number, hash: ckpt.head_hash, next_slot: ckpt.next_slot },
                records: Vec::new(),
                log_len: 0,
                generation: 0,
                broken: None,
            })
        };
        let index = match read_base(&base_path)? {
            None => fresh("no history kept before")?,
            Some(base) if base.head_number > head.0 => {
                error!(target: "n42.qmdb.history", base = base.head_number, head = head.0, "QMDB history starts above the database head (the database was rolled back below it); history restarts at the head");
                fresh("history started above the database head")?
            }
            Some(base) => {
                let base = BaseMeta { number: base.head_number, hash: base.head_hash, next_slot: base.next_slot };
                let (mut records, mut log_len) = scan_log(&log_path, &base)?;
                if let Some(cut) = records.iter().position(|r| r.number > head.0) {
                    log_len = records[cut].offset;
                    records.truncate(cut);
                }
                let mut index = Index { base, records, log_len, generation: 0, broken: None };
                let end = index.head();
                if (end.number, end.hash) != head {
                    error!(
                        target: "n42.qmdb.history",
                        history_ends = end.number, history_hash = %end.hash, head = head.0, head_hash = %head.1,
                        "QMDB history does not reach the database head (it was off for a while, or lost a record); \
                         it restarts at the head and the blocks before it are no longer provable",
                    );
                    index = fresh("history did not reach the database head")?;
                } else {
                    truncate_file(&log_path, index.log_len)?;
                    info!(
                        target: "n42.qmdb.history",
                        earliest = index.base.number, latest = end.number, records = index.records.len(),
                        "opened the QMDB history",
                    );
                }
                index
            }
        };
        Ok(Self {
            entry_path: qmdb_dir.join("entries.log"),
            dir,
            mode,
            index: RwLock::new(index),
            writer: Mutex::new(()),
            prover: Mutex::new(None),
            rebuilt_for: Mutex::new(None),
        })
    }

    /// The mode history was opened with.
    pub const fn mode(&self) -> HistoryMode {
        self.mode
    }

    /// `(earliest, latest)` provable blocks.
    pub fn range(&self) -> (u64, u64) {
        let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
        (index.base.number, index.head().number)
    }

    /// Why recording stopped, if it did.
    pub fn broken(&self) -> Option<String> {
        self.index.read().unwrap_or_else(PoisonError::into_inner).broken.clone()
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join(LOG_FILE)
    }

    fn base_path(&self) -> PathBuf {
        self.dir.join(BASE_FILE)
    }

    fn twigs_path(&self) -> PathBuf {
        self.dir.join(TWIGS_FILE)
    }

    /// Records the deltas the node just appended to `forest.log`, in order.
    /// A failure stops recording (logged once, never returned: a block's
    /// persistence never waits on history); the next start rebases.
    pub fn record(&self, deltas: &[ForestDelta]) {
        if deltas.is_empty() {
            return;
        }
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if self.broken().is_some() {
            return;
        }
        if let Err(error) = self.record_locked(deltas) {
            error!(target: "n42.qmdb.history", %error, "QMDB history stopped recording; it ends at its last record until the next start");
            self.index.write().unwrap_or_else(PoisonError::into_inner).broken = Some(error.to_string());
        }
        self.maybe_prune();
    }

    fn record_locked(&self, deltas: &[ForestDelta]) -> Result<(), HistoryError> {
        let path = self.log_path();
        for delta in deltas {
            if !delta.appended.is_empty() {
                return Err(HistoryError::Io("a heap-mode delta reached file-mode history".into()));
            }
            // A record at or below the head is a re-persisted height: the
            // records from it on describe a branch no longer persisted.
            let cut = {
                let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
                index.records.iter().position(|r| r.number >= delta.head_number)
            };
            if let Some(cut) = cut {
                self.truncate_records(cut)?;
            }
            let (prev, log_len) = {
                let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
                if delta.head_number <= index.base.number {
                    return Err(HistoryError::Io(format!(
                        "block {} re-persisted at or below the history base {}",
                        delta.head_number, index.base.number
                    )));
                }
                (index.head(), index.log_len)
            };
            if delta.base_next_slot > prev.next_slot {
                return Err(HistoryError::Io(format!(
                    "the delta of block {} starts at slot {} past the history head's cursor {} (block {})",
                    delta.head_number, delta.base_next_slot, prev.next_slot, prev.number
                )));
            }
            let bytes = frame(delta)?;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .map_err(|e| io_at(&path, e))?;
            file.set_len(log_len).map_err(|e| io_at(&path, e))?;
            file.seek(SeekFrom::Start(log_len)).map_err(|e| io_at(&path, e))?;
            file.write_all(&bytes).map_err(|e| io_at(&path, e))?;
            file.sync_data().map_err(|e| io_at(&path, e))?;
            if log_len == 0 {
                sync_dir(&path).map_err(|e| io_at(&path, e))?;
            }
            let meta = RecordMeta {
                number: delta.head_number,
                hash: delta.head_hash,
                base_next_slot: delta.base_next_slot,
                next_slot: delta.next_slot,
                offset: log_len,
                len: bytes.len() as u64,
                rewind: delta.base_next_slot < prev.next_slot || delta.changed.iter().any(|(_, active)| *active),
                span: delta.head_number != prev.number + 1,
            };
            let mut index = self.index.write().unwrap_or_else(PoisonError::into_inner);
            index.records.push(meta);
            index.log_len = log_len + bytes.len() as u64;
            if meta.rewind {
                // The reverse walk cannot cross it; the prover's cache, built
                // forward, can, but its twig index may hold twigs it cut.
                index.generation += 1;
                warn!(target: "n42.qmdb.history", block = meta.number, "a rewind of persisted QMDB state: blocks below it are no longer provable");
            }
        }
        Ok(())
    }

    /// Drops the records from position `cut` on.
    fn truncate_records(&self, cut: usize) -> Result<(), HistoryError> {
        let path = self.log_path();
        let mut index = self.index.write().unwrap_or_else(PoisonError::into_inner);
        if cut >= index.records.len() {
            return Ok(());
        }
        let len = index.records[cut].offset;
        truncate_file(&path, len)?;
        index.records.truncate(cut);
        index.log_len = len;
        index.generation += 1;
        Ok(())
    }

    /// The node checkpointed its state at `ckpt` without a delta history saw
    /// (the defensive first-checkpoint path): unless history already stands
    /// there, it restarts at the checkpoint.
    pub fn note_checkpoint(&self, ckpt: &ForestCheckpoint) {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let head = self.index.read().unwrap_or_else(PoisonError::into_inner).head();
        if (head.number, head.hash, head.next_slot) == (ckpt.head_number, ckpt.head_hash, ckpt.next_slot) {
            return;
        }
        error!(target: "n42.qmdb.history", history_head = head.number, checkpoint = ckpt.head_number, "a QMDB checkpoint was written past QMDB history without a delta; history restarts at it");
        if let Err(error) = self.rebase_locked(ckpt) {
            error!(target: "n42.qmdb.history", %error, "QMDB history could not restart at the checkpoint; recording stops");
            self.index.write().unwrap_or_else(PoisonError::into_inner).broken = Some(error.to_string());
        }
    }

    fn rebase_locked(&self, ckpt: &ForestCheckpoint) -> Result<(), HistoryError> {
        write_base(&self.base_path(), ckpt)?;
        truncate_file(&self.log_path(), 0)?;
        let mut index = self.index.write().unwrap_or_else(PoisonError::into_inner);
        index.base = BaseMeta { number: ckpt.head_number, hash: ckpt.head_hash, next_slot: ckpt.next_slot };
        index.records.clear();
        index.log_len = 0;
        index.generation += 1;
        index.broken = None;
        Ok(())
    }

    /// The database unwound to `number`: records above it are cut. Below the
    /// base, history no longer describes the database; it stops recording
    /// and restarts at the next start.
    pub fn truncate_above(&self, number: u64) {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let (cut, below_base) = {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            (index.records.iter().position(|r| r.number > number), number < index.base.number)
        };
        if below_base {
            warn!(target: "n42.qmdb.history", block = number, "the database unwound below the QMDB history base; history restarts at the next start");
            self.index.write().unwrap_or_else(PoisonError::into_inner).broken =
                Some(format!("the database unwound to {number}, below the history base"));
            return;
        }
        if let Some(cut) = cut
            && let Err(error) = self.truncate_records(cut)
        {
            error!(target: "n42.qmdb.history", %error, "QMDB history could not be cut back to the unwound head; recording stops");
            self.index.write().unwrap_or_else(PoisonError::into_inner).broken = Some(error.to_string());
        }
    }

    /// In [`HistoryMode::Keep`], once a quarter more than the kept blocks
    /// (at least 16) has accumulated, folds the oldest records into the base.
    /// Runs under the writer lock: called from [`Self::record`].
    fn maybe_prune(&self) {
        let HistoryMode::Keep(keep) = self.mode else { return };
        let slack = (keep / 4).max(16);
        let (count, first_kept) = {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            let count = index.records.len() as u64;
            if count <= keep + slack {
                return;
            }
            (count, (count - keep) as usize)
        };
        let started = std::time::Instant::now();
        match self.prune_locked(first_kept) {
            Ok(()) => info!(
                target: "n42.qmdb.history",
                folded = first_kept, kept = count as usize - first_kept, ms = started.elapsed().as_millis() as u64,
                "folded the oldest QMDB history into its base",
            ),
            Err(error) => {
                error!(target: "n42.qmdb.history", %error, "QMDB history could not be pruned; recording stops");
                self.index.write().unwrap_or_else(PoisonError::into_inner).broken = Some(error.to_string());
            }
        }
    }

    /// The base moves to record `first_kept - 1`; the log keeps the records
    /// from `first_kept` on. The base is replaced first: a crash before the
    /// log's rewrite leaves records the base covers, which the next open skips.
    fn prune_locked(&self, first_kept: usize) -> Result<(), HistoryError> {
        let (metas, log_len) = {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            (index.records.clone(), index.log_len)
        };
        if first_kept == 0 || first_kept > metas.len() {
            return Ok(());
        }
        let base_path = self.base_path();
        let mut base = read_base(&base_path)?.ok_or_else(|| io_at(&base_path, "missing"))?;
        let log_path = self.log_path();
        let log = File::open(&log_path).map_err(|e| io_at(&log_path, e))?;
        for meta in &metas[..first_kept] {
            let delta = read_record(&log, meta)?;
            base.apply_delta(&delta).map_err(|e| HistoryError::Io(e.to_string()))?;
        }
        write_base(&base_path, &base)?;
        let tail_from = metas[first_kept].offset;
        let mut tail = vec![0u8; (log_len - tail_from) as usize];
        read_exact_at(&log, &mut tail, tail_from).map_err(|e| io_at(&log_path, e))?;
        drop(log);
        write_durably(&log_path, &tail).map_err(|e| io_at(&log_path, e))?;
        let mut index = self.index.write().unwrap_or_else(PoisonError::into_inner);
        index.base = BaseMeta { number: base.head_number, hash: base.head_hash, next_slot: base.next_slot };
        index.records.drain(..first_kept);
        for record in &mut index.records {
            record.offset -= tail_from;
        }
        if let Some(first) = index.records.first_mut() {
            first.rewind = first.base_next_slot < base.next_slot;
        }
        index.log_len = log_len - tail_from;
        index.generation += 1;
        Ok(())
    }

    /// Proves `keys` (raw QMDB keys) as the state stood after block `target`,
    /// whose header-carried root is `expected_root`. The root is rebuilt
    /// first and compared; every proof returned verifies against it.
    pub fn prove(
        &self,
        target: (u64, B256),
        expected_root: B256,
        keys: &[Hash],
        live: &dyn LiveTree,
    ) -> Result<HistoricalProof, HistoryError> {
        match self.prove_once(target, expected_root, keys, live) {
            Err(mismatch @ HistoryError::RootMismatch { .. }) => {
                // The cached twig leaf roots are the one input not re-derived
                // per request: rebuild them from the entry log and try once more.
                let generation = self.index.read().unwrap_or_else(PoisonError::into_inner).generation;
                if self.rebuilt_for.lock().unwrap_or_else(PoisonError::into_inner).replace(generation) == Some(generation) {
                    return Err(mismatch);
                }
                warn!(target: "n42.qmdb.history", block = target.0, "a rebuilt QMDB root disagreed with its header; rebuilding the twig cache and retrying");
                *self.prover.lock().unwrap_or_else(PoisonError::into_inner) = None;
                let _ = std::fs::remove_file(self.twigs_path());
                self.prove_once(target, expected_root, keys, live)
            }
            other => other,
        }
    }

    fn prove_once(
        &self,
        target: (u64, B256),
        expected_root: B256,
        keys: &[Hash],
        live: &dyn LiveTree,
    ) -> Result<HistoricalProof, HistoryError> {
        let (number, hash) = target;
        // Requests are served one at a time against the one cache; the
        // records above the target are copied out of the index under its lock
        // and read without it.
        let mut prover = self.prover.lock().unwrap_or_else(PoisonError::into_inner);
        let (base, position, next_n, later, generation, records_len) = {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            let head = index.head();
            if number < index.base.number {
                return Err(HistoryError::Pruned { requested: number, earliest: index.base.number });
            }
            if number > head.number {
                return Err(HistoryError::NotYet { requested: number, latest: head.number });
            }
            let position = if number == index.base.number {
                (index.base.hash == hash).then_some(None)
            } else {
                index.records.iter().position(|r| r.number == number && r.hash == hash).map(Some)
            };
            let Some(position) = position else {
                return Err(HistoryError::NotRecorded { number, hash });
            };
            let from = position.map_or(0, |p| p + 1);
            let later: Vec<RecordMeta> = index.records[from..].to_vec();
            if let Some(rewind) = later.iter().find(|r| r.rewind) {
                return Err(HistoryError::Rewound { requested: number, at: rewind.number });
            }
            let next_n = position.map_or(index.base.next_slot, |p| index.records[p].next_slot);
            (index.base, position, next_n, later, index.generation, index.records.len())
        };
        let log_path = self.log_path();
        let log = File::open(&log_path).ok();
        let read_later = |meta: &RecordMeta| -> Result<ForestDelta, HistoryError> {
            let log = log.as_ref().ok_or_else(|| io_at(&log_path, "missing"))?;
            read_record(log, meta)
        };
        let entries = EntryReader::open(&self.entry_path, live)?;
        let head = self.head_state(&mut prover, generation, records_len, &entries)?;
        let head_number = later.last().map_or(number, |r| r.number);
        if head.number != head_number {
            return Err(HistoryError::Io(format!(
                "the history cache stands at block {} but its records end at {head_number}",
                head.number
            )));
        }

        // Every slot below the cursor of N whose flag a later block changed,
        // with its flag at N: a later retirement undone.
        let mut flipped: BTreeMap<usize, Vec<(usize, bool)>> = BTreeMap::new();
        let mut retired_after: Vec<Vec<u64>> = Vec::with_capacity(later.len());
        for meta in &later {
            let delta = read_later(meta)?;
            let mut retired = Vec::new();
            for (slot, active) in &delta.changed {
                if *slot < next_n {
                    flipped.entry(*slot as usize / TWIG_SIZE).or_default().push((*slot as usize % TWIG_SIZE, !*active));
                    if !*active {
                        retired.push(*slot);
                    }
                }
            }
            retired_after.push(retired);
        }
        let count_n = (next_n as usize).div_ceil(TWIG_SIZE);
        let count_h = head.twig_roots.len();
        // Touched twigs: a flag flipped, or appended to after N (the partial
        // twig of N and every twig opened since).
        let mut touched: BTreeSet<usize> = flipped.keys().copied().collect();
        touched.extend((next_n as usize / TWIG_SIZE)..count_h.max(count_n));
        let mut bits_n: HashMap<usize, [u8; TWIG_BITS_BYTES]> = HashMap::new();
        let mut roots_n: HashMap<usize, Hash> = HashMap::new();
        for &twig in &touched {
            if twig >= count_n {
                continue;
            }
            let mut bits = head.twig_bits(twig);
            for &(local, active) in flipped.get(&twig).map(Vec::as_slice).unwrap_or(&[]) {
                set_bit(&mut bits, local, active);
            }
            let filled = (next_n as usize - twig * TWIG_SIZE).min(TWIG_SIZE);
            for local in filled..TWIG_SIZE {
                set_bit(&mut bits, local, false);
            }
            let leaf_root = if filled == TWIG_SIZE {
                head.leaf_roots.get(twig).copied().ok_or_else(|| HistoryError::Io(format!("no leaf root for full twig {twig}")))?
            } else {
                twig_leaf_tree(&entries.twig_leaves(twig, filled)?)[1]
            };
            roots_n.insert(twig, hash_node(&leaf_root, &twig_bits_hash(&bits)));
            bits_n.insert(twig, bits);
        }
        let upper = UpperAt::new(&head, count_n, &touched, &roots_n);
        let root = B256::from(upper.root());
        if root != expected_root {
            return Err(HistoryError::RootMismatch { number, computed: root, expected: expected_root });
        }
        let bit_n = |slot: u64| -> bool {
            if slot >= next_n {
                return false;
            }
            let twig = slot as usize / TWIG_SIZE;
            let local = slot as usize % TWIG_SIZE;
            match bits_n.get(&twig) {
                Some(bits) => bits[local / 8] & (1 << (local % 8)) != 0,
                None => head.active_bit(slot),
            }
        };
        let earlier: Vec<RecordMeta> = {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            if index.generation != generation {
                return Err(HistoryError::Io("history changed during the request; retry".into()));
            }
            index.records[..position.map_or(0, |p| p + 1)].to_vec()
        };
        let mut answers = Vec::with_capacity(keys.len());
        for key in keys {
            let mut budget = LOOKUP_BUDGET;
            let slot = locate(
                key,
                next_n,
                head.next_slot,
                &base,
                &earlier,
                &retired_after,
                &entries,
                live,
                &bit_n,
                &mut budget,
            )?;
            let proof = match slot {
                None => None,
                Some(slot) => {
                    let twig = slot as usize / TWIG_SIZE;
                    let filled = (next_n as usize - twig * TWIG_SIZE).min(TWIG_SIZE);
                    let leaves = entries.twig_leaves(twig, filled)?;
                    let nodes = twig_leaf_tree(&leaves);
                    let (record_key, value) = entries.record(slot)?;
                    if record_key != *key {
                        return Err(HistoryError::Io(format!("slot {slot} holds another key")));
                    }
                    let mut twig_path = [NULL_HASH; TWIG_HEIGHT];
                    let mut node = TWIG_SIZE + slot as usize % TWIG_SIZE;
                    for sibling in &mut twig_path {
                        *sibling = nodes[node ^ 1];
                        node >>= 1;
                    }
                    let active_bits = bits_n.get(&twig).copied().unwrap_or_else(|| head.twig_bits(twig));
                    let proof = QmdbProof { key: *key, value, slot, twig_path, active_bits, upper_path: upper.path(twig) };
                    if !proof.verify_for_key(&root.0, key) {
                        return Err(HistoryError::Io(format!("the proof cut for slot {slot} does not verify against the rebuilt root")));
                    }
                    Some(proof)
                }
            };
            answers.push(KeyAtHeight { key: *key, proof });
        }
        Ok(HistoricalProof { number, hash, root, keys: answers })
    }

    /// The prover's cache at the history head, caught up with the records.
    fn head_state<'a>(
        &self,
        slot: &'a mut Option<HeadState>,
        generation: u64,
        records_len: usize,
        entries: &EntryReader,
    ) -> Result<&'a HeadState, HistoryError> {
        if slot.as_ref().is_some_and(|state| state.generation != generation) {
            *slot = None;
        }
        if slot.is_none() {
            let base_path = self.base_path();
            let base = read_base(&base_path)?.ok_or_else(|| io_at(&base_path, "missing"))?;
            let leaf_roots = read_twig_index(&self.twigs_path());
            *slot = Some(HeadState::new(base, generation, leaf_roots));
        }
        let state = slot.as_mut().expect("just filled");
        let metas: Vec<RecordMeta> = {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            if index.generation != generation {
                return Err(HistoryError::Io("history changed during the request; retry".into()));
            }
            if state.applied > records_len || records_len > index.records.len() {
                return Err(HistoryError::Io("history changed during the request; retry".into()));
            }
            index.records[state.applied..records_len].to_vec()
        };
        if !metas.is_empty() {
            let log_path = self.log_path();
            let log = File::open(&log_path).map_err(|e| io_at(&log_path, e))?;
            for meta in &metas {
                let delta = read_record(&log, meta)?;
                state.apply(&delta)?;
            }
        }
        state.refresh(entries, &self.twigs_path())?;
        Ok(state)
    }
}

fn truncate_file(path: &Path, len: u64) -> Result<(), HistoryError> {
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => {
            if file.metadata().map_err(|e| io_at(path, e))?.len() != len {
                file.set_len(len).map_err(|e| io_at(path, e))?;
                file.sync_all().map_err(|e| io_at(path, e))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && len == 0 => Ok(()),
        Err(e) => Err(io_at(path, e)),
    }
}

fn read_record(log: &File, meta: &RecordMeta) -> Result<ForestDelta, HistoryError> {
    let mut bytes = vec![0u8; meta.len as usize];
    read_exact_at(log, &mut bytes, meta.offset)?;
    if bytes.len() < RECORD_HEADER {
        return Err(HistoryError::Io("a history record is shorter than its header".into()));
    }
    let payload = &bytes[RECORD_HEADER..];
    if bytes[8..RECORD_HEADER] != crc32fast::hash(payload).to_le_bytes() {
        return Err(HistoryError::Io(format!("the history record of block {} changed under the reader; retry", meta.number)));
    }
    let delta: ForestDelta = bincode::deserialize(payload).map_err(|e| HistoryError::Io(e.to_string()))?;
    if (delta.head_number, delta.head_hash) != (meta.number, meta.hash) {
        return Err(HistoryError::Io(format!("the history record of block {} names another block", meta.number)));
    }
    Ok(delta)
}

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            done += n;
        }
        Ok(())
    }
}

fn read_twig_index(path: &Path) -> Vec<Hash> {
    let Ok(bytes) = std::fs::read(path) else { return Vec::new() };
    bytes.chunks_exact(32).map(|chunk| chunk.try_into().expect("32 bytes")).collect()
}

fn set_bit(bits: &mut [u8; TWIG_BITS_BYTES], local: usize, on: bool) {
    if on {
        bits[local / 8] |= 1 << (local % 8);
    } else {
        bits[local / 8] &= !(1 << (local % 8));
    }
}

/// Reads records of `entries.log` by slot: positional reads at the offsets
/// the live tree publishes (never a mapping, so a cut file is an error, not
/// a fault).
struct EntryReader {
    file: File,
    path: PathBuf,
    offsets: OffsetsReader,
}

impl EntryReader {
    fn open(path: &Path, live: &dyn LiveTree) -> Result<Self, HistoryError> {
        let offsets = live.offsets_reader().ok_or_else(|| HistoryError::Io("the entry log's offsets are not available (heap mode, or the tree is busy); retry".into()))?;
        let file = File::open(path).map_err(|e| io_at(path, e))?;
        Ok(Self { file, path: path.to_path_buf(), offsets })
    }

    fn offset(&self, slot: u64) -> Result<u64, HistoryError> {
        let offset = self.offsets.get(slot).ok_or_else(|| HistoryError::Io(format!("slot {slot} is past the entry log")))?;
        if offset & RELOCATED_BIT != 0 {
            return Err(HistoryError::Io(format!("slot {slot} was relocated by compaction (N42_QMDB_COMPACT is incompatible with history)")));
        }
        Ok(offset)
    }

    /// The record of `slot`: its key and value (a hash-only record has none).
    fn record(&self, slot: u64) -> Result<(Hash, Vec<u8>), HistoryError> {
        let offset = self.offset(slot)?;
        let mut header = [0u8; 36];
        read_exact_at(&self.file, &mut header, offset).map_err(|e| io_at(&self.path, e))?;
        let key: Hash = header[..32].try_into().expect("32 bytes");
        let len = u32::from_le_bytes(header[32..].try_into().expect("4 bytes"));
        if len == HASH_ONLY_LEN {
            return Err(HistoryError::Io(format!("slot {slot} keeps only its leaf hash")));
        }
        let mut value = vec![0u8; len as usize];
        read_exact_at(&self.file, &mut value, offset + 36).map_err(|e| io_at(&self.path, e))?;
        Ok((key, value))
    }

    fn key(&self, slot: u64) -> Result<Hash, HistoryError> {
        let offset = self.offset(slot)?;
        let mut key = [0u8; 32];
        read_exact_at(&self.file, &mut key, offset).map_err(|e| io_at(&self.path, e))?;
        Ok(key)
    }

    /// The leaf hashes of the first `filled` slots of `twig`, read in one
    /// sequential pass from the twig's first record.
    fn twig_leaves(&self, twig: usize, filled: usize) -> Result<Vec<Hash>, HistoryError> {
        if filled == 0 {
            return Ok(Vec::new());
        }
        let first = (twig * TWIG_SIZE) as u64;
        let start = self.offset(first)?;
        let last = self.offset(first + filled as u64 - 1)?;
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start)).map_err(|e| io_at(&self.path, e))?;
        let mut reader = io::BufReader::with_capacity(1 << 20, file);
        let mut leaves = Vec::with_capacity(filled);
        let mut at = start;
        let mut header = [0u8; 36];
        let mut value = Vec::new();
        for local in 0..filled {
            reader.read_exact(&mut header).map_err(|e| io_at(&self.path, e))?;
            let key: Hash = header[..32].try_into().expect("32 bytes");
            let len = u32::from_le_bytes(header[32..].try_into().expect("4 bytes"));
            if local + 1 == filled && at != last {
                return Err(HistoryError::Io(format!("twig {twig}'s records are not contiguous in the entry log")));
            }
            if len == HASH_ONLY_LEN {
                leaves.push(key);
                at += 36;
                continue;
            }
            value.resize(len as usize, 0);
            reader.read_exact(&mut value).map_err(|e| io_at(&self.path, e))?;
            leaves.push(hash_leaf(&key, &value));
            at += 36 + u64::from(len);
        }
        Ok(leaves)
    }
}

/// The history head as the prover keeps it: the cursor and active bits, the
/// frozen leaf root of every full twig, every twig's root and the upper tree.
#[derive(Debug)]
struct HeadState {
    generation: u64,
    /// Records applied onto the base.
    applied: usize,
    number: u64,
    next_slot: u64,
    ckpt: ForestCheckpoint,
    leaf_roots: Vec<Hash>,
    /// Twigs whose root must be recomputed before the next read.
    dirty: BTreeSet<usize>,
    /// Leaf roots written to `twigs.idx`.
    persisted_leaf_roots: usize,
    twig_roots: Vec<Hash>,
    cap: usize,
    upper: Vec<Hash>,
    /// The upper tree must be rebuilt (its capacity changed, or first use).
    rebuild: bool,
}

impl HeadState {
    fn new(base: ForestCheckpoint, generation: u64, leaf_roots: Vec<Hash>) -> Self {
        let persisted_leaf_roots = leaf_roots.len();
        Self {
            generation,
            applied: 0,
            number: base.head_number,
            next_slot: base.next_slot,
            dirty: (0..(base.next_slot as usize).div_ceil(TWIG_SIZE)).collect(),
            ckpt: base,
            leaf_roots,
            persisted_leaf_roots,
            twig_roots: Vec::new(),
            cap: 0,
            upper: Vec::new(),
            rebuild: true,
        }
    }

    fn apply(&mut self, delta: &ForestDelta) -> Result<(), HistoryError> {
        let base = delta.base_next_slot;
        self.ckpt.apply_delta(delta).map_err(|e| HistoryError::Io(e.to_string()))?;
        for (slot, _) in &delta.changed {
            self.dirty.insert(*slot as usize / TWIG_SIZE);
        }
        let from = base as usize / TWIG_SIZE;
        if base < self.next_slot {
            // A rewind: the twigs at and past its base's twig were cut and
            // appended again, and the tree may have shrunk.
            self.leaf_roots.truncate(from);
            self.persisted_leaf_roots = self.persisted_leaf_roots.min(from);
            self.rebuild = true;
            self.dirty.extend(0..(self.next_slot as usize).div_ceil(TWIG_SIZE));
        }
        self.dirty.extend(from..(delta.next_slot as usize).div_ceil(TWIG_SIZE));
        self.next_slot = delta.next_slot;
        self.number = delta.head_number;
        self.applied += 1;
        Ok(())
    }

    /// Recomputes what the applied records made stale: leaf roots of twigs
    /// that filled, the dirty twigs' roots, the upper tree.
    fn refresh(&mut self, entries: &EntryReader, twigs_path: &Path) -> Result<(), HistoryError> {
        let count = (self.next_slot as usize).div_ceil(TWIG_SIZE);
        let full = self.next_slot as usize / TWIG_SIZE;
        if self.persisted_leaf_roots > self.leaf_roots.len() {
            self.persisted_leaf_roots = self.leaf_roots.len();
        }
        while self.leaf_roots.len() < full {
            let twig = self.leaf_roots.len();
            self.leaf_roots.push(twig_leaf_tree(&entries.twig_leaves(twig, TWIG_SIZE)?)[1]);
            self.dirty.insert(twig);
        }
        if self.persisted_leaf_roots < self.leaf_roots.len() {
            persist_twig_index(twigs_path, &self.leaf_roots, self.persisted_leaf_roots)?;
            self.persisted_leaf_roots = self.leaf_roots.len();
        }
        self.twig_roots.resize(count, NULL_HASH);
        let dirty = std::mem::take(&mut self.dirty);
        let mut changed = Vec::new();
        for twig in dirty.into_iter().filter(|twig| *twig < count) {
            let leaf_root = if twig < full {
                self.leaf_roots[twig]
            } else {
                let filled = self.next_slot as usize - twig * TWIG_SIZE;
                twig_leaf_tree(&entries.twig_leaves(twig, filled)?)[1]
            };
            self.twig_roots[twig] = hash_node(&leaf_root, &twig_bits_hash(&self.twig_bits(twig)));
            changed.push(twig);
        }
        let cap = count.next_power_of_two();
        if count == 0 {
            self.cap = 0;
            self.upper.clear();
            self.rebuild = true;
            return Ok(());
        }
        if self.rebuild || cap != self.cap {
            self.cap = cap;
            self.upper = vec![NULL_HASH; 2 * cap];
            self.upper[cap..cap + count].copy_from_slice(&self.twig_roots);
            for node in (1..cap).rev() {
                self.upper[node] = hash_node(&self.upper[2 * node], &self.upper[2 * node + 1]);
            }
            self.rebuild = false;
        } else {
            let mut level: Vec<usize> = changed.iter().map(|twig| cap + twig).collect();
            for &node in &level {
                self.upper[node] = self.twig_roots[node - cap];
            }
            while level.first().is_some_and(|node| *node > 1) {
                let mut parents: Vec<usize> = level.iter().map(|node| node / 2).collect();
                parents.dedup();
                for &parent in &parents {
                    self.upper[parent] = hash_node(&self.upper[2 * parent], &self.upper[2 * parent + 1]);
                }
                level = parents;
            }
        }
        Ok(())
    }

    fn twig_bits(&self, twig: usize) -> [u8; TWIG_BITS_BYTES] {
        let mut bits = [0u8; TWIG_BITS_BYTES];
        let words = TWIG_SIZE / 64;
        for (i, chunk) in bits.chunks_exact_mut(8).enumerate() {
            let word = self.ckpt.active.get(twig * words + i).copied().unwrap_or(0);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bits
    }

    fn active_bit(&self, slot: u64) -> bool {
        slot < self.next_slot
            && self.ckpt.active.get(slot as usize / 64).is_some_and(|word| word & (1 << (slot % 64)) != 0)
    }
}

fn persist_twig_index(path: &Path, leaf_roots: &[Hash], from: usize) -> Result<(), HistoryError> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| io_at(path, e))?;
    file.set_len(from as u64 * 32).map_err(|e| io_at(path, e))?;
    file.seek(SeekFrom::Start(from as u64 * 32)).map_err(|e| io_at(path, e))?;
    let mut bytes = Vec::with_capacity((leaf_roots.len() - from) * 32);
    for root in &leaf_roots[from..] {
        bytes.extend_from_slice(root);
    }
    file.write_all(&bytes).map_err(|e| io_at(path, e))?;
    Ok(())
}

/// The upper tree at block N, read off the head's: the head's capacity
/// `cap_h` holds N's tree (capacity `cap_n`, at most `cap_h`) as the subtree
/// rooted at heap index `cap_h / cap_n`, whose leaves are the head's leaves
/// `cap_h + t`. The touched twigs' roots at N replace those leaves (null
/// for a twig N did not have yet) and their ancestors up to that subtree's
/// root are rehashed; every other node is the head's.
struct UpperAt<'a> {
    head: &'a HeadState,
    root_index: usize,
    overrides: HashMap<usize, Hash>,
    empty: bool,
}

impl<'a> UpperAt<'a> {
    fn new(head: &'a HeadState, count_n: usize, touched: &BTreeSet<usize>, roots_n: &HashMap<usize, Hash>) -> Self {
        if count_n == 0 {
            return Self { head, root_index: 1, overrides: HashMap::new(), empty: true };
        }
        let cap_n = count_n.next_power_of_two();
        let cap_h = head.cap;
        let root_index = cap_h / cap_n;
        let mut overrides = HashMap::new();
        let mut level: Vec<usize> = Vec::new();
        for &twig in touched.iter().filter(|twig| **twig < cap_n) {
            let value = roots_n.get(&twig).copied().unwrap_or(NULL_HASH);
            overrides.insert(cap_h + twig, value);
            level.push(cap_h + twig);
        }
        let mut upper = Self { head, root_index, overrides, empty: false };
        while level.first().is_some_and(|node| *node > root_index) {
            let mut parents: Vec<usize> = level.iter().map(|node| node / 2).collect();
            parents.dedup();
            for &parent in &parents {
                let hash = hash_node(&upper.node(2 * parent), &upper.node(2 * parent + 1));
                upper.overrides.insert(parent, hash);
            }
            level = parents;
        }
        upper
    }

    fn node(&self, index: usize) -> Hash {
        self.overrides.get(&index).copied().unwrap_or_else(|| self.head.upper.get(index).copied().unwrap_or(NULL_HASH))
    }

    fn root(&self) -> Hash {
        if self.empty { NULL_HASH } else { self.node(self.root_index) }
    }

    /// The siblings from twig `twig`'s root up to N's root.
    fn path(&self, twig: usize) -> Vec<Hash> {
        let mut path = Vec::new();
        let mut node = self.head.cap + twig;
        while node > self.root_index {
            path.push(self.node(node ^ 1));
            node >>= 1;
        }
        path
    }
}

/// The slot that held `key`'s live entry after block N (cursor `next_n`), or
/// `None` when it had none. Every candidate is checked: its record holds the
/// key and its active bit at N is set.
#[allow(clippy::too_many_arguments)]
fn locate(
    key: &Hash,
    next_n: u64,
    history_next: u64,
    base: &BaseMeta,
    earlier: &[RecordMeta],
    retired_after: &[Vec<u64>],
    entries: &EntryReader,
    live: &dyn LiveTree,
    bit_n: &dyn Fn(u64) -> bool,
    budget: &mut u64,
) -> Result<Option<u64>, HistoryError> {
    let mut read_key = |slot: u64| -> Result<Hash, HistoryError> {
        if *budget == 0 {
            return Err(HistoryError::LookupBudget(B256::from(*key)));
        }
        *budget -= 1;
        entries.key(slot)
    };
    // 1. The live tree's slot: a key no block after N touched.
    let live_slot = live.live_slot_of(key);
    if let Some(slot) = live_slot
        && slot < next_n
        && bit_n(slot)
        && read_key(slot)? == *key
    {
        return Ok(Some(slot));
    }
    // 2. Its latest append at or before N: each block's appended run is in
    // key order (the block's operations are sorted), a multi-block span's
    // is not and is read whole.
    for meta in earlier.iter().rev() {
        let found = if meta.span || meta.rewind {
            let mut found = None;
            for slot in (meta.base_next_slot..meta.next_slot).rev() {
                if read_key(slot)? == *key {
                    found = Some(slot);
                    break;
                }
            }
            found
        } else {
            search_sorted(meta.base_next_slot, meta.next_slot, key, &mut read_key)?
        };
        if let Some(slot) = found {
            return Ok(bit_n(slot).then_some(slot));
        }
    }
    // 3. Not appended since the base. From genesis the base is the alloc,
    // appended in key order: the search is complete.
    if base.number == 0 {
        let found = search_sorted(0, base.next_slot, key, &mut read_key)?;
        return Ok(found.filter(|slot| bit_n(*slot)));
    }
    // Otherwise its slot predates the base: the first retirement of it after
    // N names that slot. None, and the live probe did not find it below N:
    // it had no entry at N -- unless the live tree holds it at a slot past
    // the history head, a change history has not recorded yet.
    for retired in retired_after {
        for &slot in retired {
            if read_key(slot)? == *key {
                return Ok(bit_n(slot).then_some(slot));
            }
        }
    }
    if live_slot.is_some_and(|slot| slot >= history_next) {
        return Err(HistoryError::Retry(B256::from(*key)));
    }
    Ok(None)
}

/// Binary search for `key` among slots `from..to` whose keys ascend.
fn search_sorted(
    from: u64,
    to: u64,
    key: &Hash,
    read_key: &mut dyn FnMut(u64) -> Result<Hash, HistoryError>,
) -> Result<Option<u64>, HistoryError> {
    let (mut lo, mut hi) = (from, to);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match read_key(mid)?.cmp(key) {
            std::cmp::Ordering::Equal => return Ok(Some(mid)),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    Ok(None)
}

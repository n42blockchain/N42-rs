// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QMDB state at past heights: retention behind `N42_QMDB_HISTORY` (or
//! `--qmdb.history`), and membership proofs against the root a past header
//! carries (`docs/QMDB_HISTORY.md`).
//!
//! A QMDB root is a pure function of three things: the entry log (append-only;
//! a slot's leaf hash is frozen at its append), the append cursor, and the
//! active bit of every slot below it. The state after a block is therefore its
//! cursor plus its active bits ([`ForestCheckpoint`]), and what one block
//! changes is its delta: the cursor it moved to and the slots whose flag it
//! changed -- exactly the file-mode [`ForestDelta`] the node writes to
//! `forest.log`. History keeps those deltas in segments, each headed by a
//! snapshot of the state it starts from:
//!
//! - `history/seg-<S>.ckpt`: the [`ForestCheckpoint`] after block `S` (the
//!   oldest one is the base; the others are written in the background);
//! - `history/seg-<S>.log`: the deltas of the blocks after `S`, framed as
//!   `forest.log` frames them (length, CRC-32, bincode payload);
//! - `history/seg-<S>.idx`: one fixed-width entry a record (block, hash,
//!   cursors, offset), so nothing about the records is held in memory;
//! - `history/seg-<S>.sum`: a sealed segment's summary;
//! - `history/twigs.idx`: the leaf root of every full twig, 32 bytes a twig,
//!   a cache of what the entry log hashes to.
//!
//! A segment is sealed (and the next begins) once its deltas outweigh a
//! snapshot (or after a fixed number of blocks), so the deltas between any
//! block and the snapshot before it are bounded by about one snapshot's size.
//!
//! A proof at block `N` is the twig proof the head proof is ([`QmdbProof`],
//! gov5's v2 layout), cut from the tree as it stood after `N`: the snapshot
//! at or before `N` is loaded (its twig roots computed from the frozen leaf
//! roots and its bits, its upper tree built), the deltas up to `N` are
//! replayed onto copies of the twigs they touch, those twigs' roots are
//! recomputed (the youngest, partial twig re-folded from the entry log), and
//! the upper tree is rehashed along their paths. The root this yields is
//! compared with the root the caller's header carries before any proof
//! leaves; every proof is verified against it as well. A mismatch is an
//! error, never a proof.
//!
//! Nothing here moves the live tree. A request takes the forest's lock once,
//! for an index probe of all its keys ([`LiveTree::probe`]); those slots are
//! only candidates, used when their record holds the key and their active
//! bit at `N` is set (a QMDB tree has at most one live slot per key).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs::File,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Condvar, Mutex, PoisonError, RwLock},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use n42_qmdb_state::{ForestCheckpoint, ForestDelta, LiveProbe};
use n42_twig_core::{
    hash_leaf, hash_node,
    offsets::OffsetsReader,
    qmdb_compat::{twig_bits_hash, twig_leaf_tree, QmdbProof, TWIG_BITS_BYTES},
    Hash, NULL_HASH, TWIG_HEIGHT, TWIG_SIZE,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

/// The environment variable that turns history on (`--qmdb.history` on the
/// command line overrides it).
pub const HISTORY_ENV: &str = "N42_QMDB_HISTORY";
/// The most blocks one history segment holds (a snapshot heads every one).
pub const SNAPSHOT_BLOCKS_ENV: &str = "N42_QMDB_HISTORY_SNAPSHOT_BLOCKS";
/// The delta bytes one request may replay, in MiB.
pub const BUDGET_ENV: &str = "N42_QMDB_HISTORY_BUDGET_MB";
/// The directory under the QMDB directory.
pub const HISTORY_DIR: &str = "history";
const TWIGS_FILE: &str = "twigs.idx";
/// Framing of a record (`forest.log`'s): length, digest.
const RECORD_HEADER: usize = 12;
/// One `seg-<S>.idx` entry.
const IDX_ENTRY: usize = 72;
const DEFAULT_SNAPSHOT_BLOCKS: u64 = 16_384;
/// A segment is never sealed for size below this many delta bytes.
const MIN_SEGMENT_BYTES: u64 = 32 << 20;
const DEFAULT_BUDGET_MB: u64 = 512;
/// Key reads one key lookup may make before it gives up with an error.
const LOOKUP_BUDGET: u64 = 4_000_000;
/// The most slots retired on the live tree past the history head a request
/// copies out under the forest's lock.
const LIVE_RETIRED_LIMIT: usize = 1 << 18;
/// Requests computed at once; the others wait.
const MAX_CONCURRENT_PROOFS: usize = 2;
/// Loaded snapshots kept.
const IMAGE_CACHE: usize = 2;
/// Proof-ready heights kept.
const HEIGHT_CACHE: usize = 16;
/// Twigs the background worker hashes before it looks at its queue again.
const WARM_CHUNK: usize = 512;
/// Uncached twigs one request hashes itself before it answers "warming".
const REQUEST_WARM_LIMIT: usize = 1024;
/// A slot offset with this bit names `entries.relocated` (compaction).
const RELOCATED_BIT: u64 = 1 << 63;
/// The `len` field of a hash-only record in `entries.log`.
const HASH_ONLY_LEN: u32 = u32::MAX;
const WORDS: usize = TWIG_SIZE / 64;
const SPAN: u8 = 1;
const REWIND: u8 = 2;

/// What `N42_QMDB_HISTORY` / `--qmdb.history` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    /// No history (the default): today's behaviour, nothing written.
    Off,
    /// Keep (at least) the last `n` persisted blocks provable.
    Keep(u64),
    /// Keep every block from where history started.
    All,
}

impl HistoryMode {
    /// Parses a value: empty, `off` or `0` is [`Self::Off`]; `all` or
    /// `archive` is [`Self::All`]; a positive integer is [`Self::Keep`].
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "" | "off" | "0" => Ok(Self::Off),
            "all" | "archive" => Ok(Self::All),
            other => other
                .parse::<u64>()
                .map(Self::Keep)
                .map_err(|_| format!("`{other}`: expected a block count, `all`, or `off`")),
        }
    }

    /// The mode the environment asks for; an unparsable value is an error
    /// (the node refuses to start on it).
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(HISTORY_ENV) {
            Ok(raw) => Self::parse(&raw).map_err(|e| format!("{HISTORY_ENV}={e}")),
            Err(std::env::VarError::NotPresent) => Ok(Self::Off),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{HISTORY_ENV} is not valid UTF-8")),
        }
    }

    /// Whether anything is kept.
    pub const fn is_on(self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl std::fmt::Display for HistoryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::All => f.write_str("all"),
            Self::Keep(n) => write!(f, "{n}"),
        }
    }
}

/// History's mode and tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryConfig {
    /// What is kept.
    pub mode: HistoryMode,
    /// The most blocks a segment holds before it is sealed.
    pub snapshot_blocks: u64,
    /// A segment is sealed for size only past this many delta bytes (and
    /// past one snapshot's size).
    pub min_segment_bytes: u64,
    /// The delta bytes one request may replay or scan.
    pub budget_bytes: u64,
}

impl HistoryConfig {
    /// `mode` with the tuning the environment sets (`N42_QMDB_HISTORY_*`),
    /// or the defaults: segments of at most 16384 blocks (in `Keep(n)` mode
    /// at most `max(n / 4, 16)`), a 512 MiB request budget.
    pub fn new(mode: HistoryMode) -> Self {
        let mode_blocks = match mode {
            HistoryMode::Keep(n) => (n / 4).clamp(16, DEFAULT_SNAPSHOT_BLOCKS),
            _ => DEFAULT_SNAPSHOT_BLOCKS,
        };
        let snapshot_blocks = n42_env::parse(SNAPSHOT_BLOCKS_ENV, mode_blocks).max(1);
        let budget_mb = n42_env::parse(BUDGET_ENV, DEFAULT_BUDGET_MB).max(1);
        Self { mode, snapshot_blocks, min_segment_bytes: MIN_SEGMENT_BYTES, budget_bytes: budget_mb << 20 }
    }

    /// The delta bytes past which a segment holding state of `next_slot`
    /// slots is sealed: one snapshot's size, at least the minimum, at most a
    /// quarter of the request budget.
    fn segment_bytes(&self, next_slot: u64) -> u64 {
        (next_slot / 8).max(self.min_segment_bytes).min((self.budget_bytes / 4).max(1))
    }
}

/// Why a historical proof was not served.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum HistoryError {
    /// The node keeps no QMDB history.
    #[error("this node keeps no QMDB history (start it with --qmdb.history <blocks|all> or N42_QMDB_HISTORY; file-mode entries required)")]
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
    /// A later rewind of persisted state re-appended slots the block's state
    /// used; its entries are no longer in the entry log.
    #[error("a rewind of persisted QMDB state at block {at} re-appended slots block {requested} used; it is not provable")]
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
    #[error("locating key {0} at the requested block exceeds the per-request lookup budget")]
    LookupBudget(B256),
    /// The request would replay or scan more delta bytes than one may.
    #[error("block {requested} needs {needed} bytes of QMDB history read, more than the per-request budget of {budget} (N42_QMDB_HISTORY_BUDGET_MB)")]
    Budget {
        /// The block asked for.
        requested: u64,
        /// The bytes it would read.
        needed: u64,
        /// The budget.
        budget: u64,
    },
    /// The leaf-root cache is still being built in the background (after
    /// history started, or after an unwind cut it); a request does not
    /// rehash the entry log itself past a small bound.
    #[error("the QMDB leaf-root cache covers {have} of the {need} twigs block {requested} needs; it is being built, retry shortly")]
    Warming {
        /// The block asked for.
        requested: u64,
        /// Twigs cached.
        have: usize,
        /// Twigs needed.
        need: usize,
    },
    /// The key's state at the block depends on blocks history has not
    /// recorded yet (or on a branch the live tree left); retry later.
    #[error("key {0} changed after the newest recorded block (or the live tree is on another branch); retry once it is persisted")]
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

/// What a prover asks of the live tree: one hold of its lock, never a move.
pub trait LiveTree {
    /// Each key's live slot, the entry log's offsets and, when asked, the
    /// slots retired since an ancestor (see
    /// [`n42_qmdb_state::QmdbForest::history_probe`]).
    fn probe(&self, keys: &[Hash], retired_since: Option<(B256, u64, usize)>) -> Option<LiveProbe>;
}

/// Where the background worker gets the entry log's offsets.
pub type OffsetsSource = Arc<dyn Fn() -> Option<OffsetsReader> + Send + Sync>;

/// One key's answer at a past block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAtHeight {
    /// The raw QMDB key.
    pub key: Hash,
    /// The membership proof, or `None` when the key had no live entry at the
    /// block -- shown from recorded data, never assumed (not provable: QMDB
    /// proofs prove membership only).
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

fn io_at(path: &Path, error: impl std::fmt::Display) -> HistoryError {
    HistoryError::Io(format!("{}: {error}", path.display()))
}

fn changed() -> HistoryError {
    HistoryError::Io("history changed during the request; retry".into())
}

// ---------------------------------------------------------------------------
// Records and their index

/// One record's index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Rec {
    number: u64,
    hash: B256,
    base_next_slot: u64,
    next_slot: u64,
    offset: u64,
    len: u32,
    flags: u8,
}

impl Rec {
    fn encode(&self) -> [u8; IDX_ENTRY] {
        let mut out = [0u8; IDX_ENTRY];
        out[..8].copy_from_slice(&self.number.to_le_bytes());
        out[8..40].copy_from_slice(self.hash.as_slice());
        out[40..48].copy_from_slice(&self.base_next_slot.to_le_bytes());
        out[48..56].copy_from_slice(&self.next_slot.to_le_bytes());
        out[56..64].copy_from_slice(&self.offset.to_le_bytes());
        out[64..68].copy_from_slice(&self.len.to_le_bytes());
        out[68] = self.flags;
        out
    }

    fn decode(bytes: &[u8]) -> Self {
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
        Self {
            number: u64_at(0),
            hash: B256::from_slice(&bytes[8..40]),
            base_next_slot: u64_at(40),
            next_slot: u64_at(48),
            offset: u64_at(56),
            len: u32::from_le_bytes(bytes[64..68].try_into().expect("four bytes")),
            flags: bytes[68],
        }
    }

    const fn end(&self) -> u64 {
        self.offset + self.len as u64
    }

    const fn plain(&self) -> bool {
        self.flags == 0
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(RECORD_HEADER + payload.len());
    record.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    record.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    record.extend_from_slice(payload);
    record
}

/// Reads one frame from a stream: `Ok(None)` at a clean end, a torn or
/// corrupt frame, or one longer than `limit`.
fn read_frame(reader: &mut impl Read, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; RECORD_HEADER];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u64::from_le_bytes(header[..8].try_into().expect("eight bytes"));
    if len > limit {
        return Ok(None);
    }
    let mut payload = vec![0u8; len as usize];
    match reader.read_exact(&mut payload) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    if header[8..] != crc32fast::hash(&payload).to_le_bytes() {
        return Ok(None);
    }
    Ok(Some(payload))
}

fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
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

fn remove_if_present(path: &Path) -> Result<(), HistoryError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_at(path, e)),
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

fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = file.seek_write(&buf[done..], offset + done as u64)?;
            done += n;
        }
        Ok(())
    }
}

fn decode_delta(payload: &[u8], rec: Option<&Rec>) -> Result<ForestDelta, HistoryError> {
    let delta: ForestDelta = bincode::deserialize(payload).map_err(|e| HistoryError::Io(e.to_string()))?;
    if delta.version != ForestDelta::VERSION {
        return Err(HistoryError::Io(format!("a history record has delta version {}", delta.version)));
    }
    if let Some(rec) = rec
        && (delta.head_number, delta.head_hash, delta.next_slot) != (rec.number, rec.hash, rec.next_slot)
    {
        return Err(HistoryError::Io(format!("the history record of block {} names another block", rec.number)));
    }
    Ok(delta)
}

fn read_ckpt(path: &Path) -> Result<Option<ForestCheckpoint>, HistoryError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_at(path, e)),
    };
    let payload = read_frame(&mut BufReader::new(file), u64::MAX)
        .map_err(|e| io_at(path, e))?
        .ok_or_else(|| io_at(path, "torn or corrupt snapshot"))?;
    bincode::deserialize(&payload).map(Some).map_err(|e| io_at(path, e))
}

fn write_ckpt(path: &Path, ckpt: &ForestCheckpoint) -> Result<(), HistoryError> {
    let payload = bincode::serialize(ckpt).map_err(|e| io_at(path, e))?;
    write_durably(path, &frame(&payload)).map_err(|e| io_at(path, e))
}

// ---------------------------------------------------------------------------
// Segments

/// A sealed segment's summary (`seg-<S>.sum`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Summary {
    count: u64,
    log_len: u64,
    last: Option<Rec>,
    rewinds: Vec<(u64, u64)>,
}

/// One segment as held in memory: its head snapshot's block and what its
/// files hold; never its records.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seg {
    start: u64,
    start_hash: B256,
    start_next_slot: u64,
    /// `seg-<start>.ckpt` is written.
    ckpt: bool,
    /// `seg-<start>.sum` is written; no record is appended any more.
    sealed: bool,
    count: u64,
    log_len: u64,
    last: Option<Rec>,
}

impl Seg {
    const fn empty(start: u64, start_hash: B256, start_next_slot: u64, ckpt: bool) -> Self {
        Self { start, start_hash, start_next_slot, ckpt, sealed: false, count: 0, log_len: 0, last: None }
    }

    fn head(&self) -> (u64, B256, u64) {
        self.last.map_or((self.start, self.start_hash, self.start_next_slot), |r| (r.number, r.hash, r.next_slot))
    }
}

fn seg_path(dir: &Path, start: u64, ext: &str) -> PathBuf {
    dir.join(format!("seg-{start:020}.{ext}"))
}

/// Reads entries `from..to` of a segment's index.
fn read_recs(dir: &Path, start: u64, from: u64, to: u64) -> Result<Vec<Rec>, HistoryError> {
    if from >= to {
        return Ok(Vec::new());
    }
    let path = seg_path(dir, start, "idx");
    let file = File::open(&path).map_err(|e| io_at(&path, e))?;
    let mut bytes = vec![0u8; ((to - from) as usize) * IDX_ENTRY];
    read_exact_at(&file, &mut bytes, from * IDX_ENTRY as u64).map_err(|e| io_at(&path, e))?;
    Ok(bytes.as_chunks::<IDX_ENTRY>().0.iter().map(|c| Rec::decode(c)).collect())
}

/// The position of block `number` in a segment's index (binary search: the
/// numbers ascend), with its entry.
fn find_rec(dir: &Path, seg: &Seg, number: u64) -> Result<Option<(u64, Rec)>, HistoryError> {
    let path = seg_path(dir, seg.start, "idx");
    let file = File::open(&path).map_err(|e| io_at(&path, e))?;
    let (mut lo, mut hi) = (0u64, seg.count);
    let mut entry = [0u8; IDX_ENTRY];
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        read_exact_at(&file, &mut entry, mid * IDX_ENTRY as u64).map_err(|e| io_at(&path, e))?;
        let rec = Rec::decode(&entry);
        match rec.number.cmp(&number) {
            std::cmp::Ordering::Equal => return Ok(Some((mid, rec))),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    Ok(None)
}

/// The first position in a segment whose block is at or above `number`.
fn first_at_or_above(dir: &Path, seg: &Seg, number: u64) -> Result<u64, HistoryError> {
    let path = seg_path(dir, seg.start, "idx");
    let file = File::open(&path).map_err(|e| io_at(&path, e))?;
    let (mut lo, mut hi) = (0u64, seg.count);
    let mut entry = [0u8; IDX_ENTRY];
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        read_exact_at(&file, &mut entry, mid * IDX_ENTRY as u64).map_err(|e| io_at(&path, e))?;
        if Rec::decode(&entry).number < number {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Streams the records of `segs` in order, with their deltas, until `f`
/// says stop or a record's block passes `until`.
fn walk_records(
    dir: &Path,
    segs: &[Seg],
    until: u64,
    mut f: impl FnMut(&Rec, ForestDelta) -> Result<bool, HistoryError>,
) -> Result<(), HistoryError> {
    for seg in segs {
        if seg.count == 0 {
            continue;
        }
        let idx_path = seg_path(dir, seg.start, "idx");
        let log_path = seg_path(dir, seg.start, "log");
        let mut idx = BufReader::with_capacity(1 << 16, File::open(&idx_path).map_err(|e| io_at(&idx_path, e))?);
        let mut log = BufReader::with_capacity(1 << 20, File::open(&log_path).map_err(|e| io_at(&log_path, e))?);
        let mut at = 0u64;
        let mut entry = [0u8; IDX_ENTRY];
        for _ in 0..seg.count {
            idx.read_exact(&mut entry).map_err(|e| io_at(&idx_path, e))?;
            let rec = Rec::decode(&entry);
            if rec.number > until {
                return Ok(());
            }
            if rec.offset != at {
                return Err(io_at(&log_path, format!("record of block {} is not where its index says", rec.number)));
            }
            let payload = read_frame(&mut log, u64::from(rec.len))
                .map_err(|e| io_at(&log_path, e))?
                .ok_or_else(|| io_at(&log_path, format!("record of block {} is torn", rec.number)))?;
            at = rec.end();
            if !f(&rec, decode_delta(&payload, Some(&rec))?)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Everything history holds about itself in memory: one entry per segment
/// and the (rare) rewinds, never its records.
#[derive(Debug, Default)]
struct Meta {
    segs: BTreeMap<u64, Seg>,
    /// Block -> the cursor its record rewound to.
    rewinds: BTreeMap<u64, u64>,
    /// Bumped on every change that is not an append (cut, rebase, a rewind):
    /// caches built on an older one are dropped.
    generation: u64,
    broken: Option<String>,
}

impl Meta {
    fn base(&self) -> &Seg {
        self.segs.values().next().expect("history has a base segment")
    }

    fn current(&self) -> &Seg {
        self.segs.values().next_back().expect("history has a base segment")
    }

    fn head(&self) -> (u64, B256, u64) {
        self.current().head()
    }
}

// ---------------------------------------------------------------------------
// The leaf-root cache

#[derive(Debug, Default)]
struct LeafState {
    generation: u64,
    roots: Vec<Hash>,
}

/// The frozen leaf roots of full twigs, `twigs.idx` on disk. Extended by one
/// extender at a time (computing off every lock), truncated by a cut or a
/// rewind under its write lock, which bumps its generation so an extension
/// computed across it is dropped.
#[derive(Debug)]
struct Leaves {
    path: PathBuf,
    state: RwLock<LeafState>,
    extend: Mutex<()>,
}

impl Leaves {
    fn open(path: PathBuf, max_twigs: usize) -> Self {
        let mut roots: Vec<Hash> = std::fs::read(&path)
            .map(|bytes| bytes.as_chunks::<32>().0.to_vec())
            .unwrap_or_default();
        if roots.len() > max_twigs {
            roots.truncate(max_twigs);
            let _ = truncate_file(&path, max_twigs as u64 * 32);
        }
        Self { path, state: RwLock::new(LeafState { generation: 0, roots }), extend: Mutex::new(()) }
    }

    fn generation(&self) -> u64 {
        self.state.read().unwrap_or_else(PoisonError::into_inner).generation
    }

    fn len(&self) -> usize {
        self.state.read().unwrap_or_else(PoisonError::into_inner).roots.len()
    }

    /// Drops the leaf roots of twigs `twigs..`, durably.
    fn truncate_to(&self, twigs: usize) -> Result<(), HistoryError> {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if state.roots.len() > twigs {
            truncate_file(&self.path, twigs as u64 * 32)?;
            state.roots.truncate(twigs);
        }
        state.generation += 1;
        Ok(())
    }

    /// A request's extension of the cache to `full` twigs: refused with
    /// [`HistoryError::Warming`] when more than a small bound is missing.
    fn ensure_for_request(&self, full: usize, entries: &EntryReader, requested: u64) -> Result<(), HistoryError> {
        let have = self.len();
        if full > have + REQUEST_WARM_LIMIT {
            return Err(HistoryError::Warming { requested, have, need: full });
        }
        self.ensure(full, entries, None).map(drop)
    }

    /// Extends the cache to cover `full` twigs, at most `chunk` twigs at a
    /// time per commit. Returns whether it covers them.
    fn ensure(&self, full: usize, entries: &EntryReader, chunk: Option<usize>) -> Result<bool, HistoryError> {
        let _extender = self.extend.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let (have, generation) = {
                let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
                (state.roots.len(), state.generation)
            };
            if have >= full {
                return Ok(true);
            }
            let to = full.min(have + chunk.unwrap_or(4096));
            let computed: Vec<Hash> = (have..to)
                .into_par_iter()
                .map(|twig| entries.twig_leaves(twig, TWIG_SIZE).map(|leaves| twig_leaf_tree(&leaves)[1]))
                .collect::<Result<_, _>>()?;
            let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
            if state.generation != generation || state.roots.len() != have {
                // Truncated meanwhile: what was computed may be stale.
                continue;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&self.path)
                .map_err(|e| io_at(&self.path, e))?;
            file.set_len(have as u64 * 32).map_err(|e| io_at(&self.path, e))?;
            write_all_at(&file, &computed.concat(), have as u64 * 32).map_err(|e| io_at(&self.path, e))?;
            state.roots.extend(computed);
            if chunk.is_some() && state.roots.len() < full {
                return Ok(false);
            }
        }
    }

    /// Recomputes every cached root from the entry log and cuts the cache at
    /// the first that disagrees. Returns how many it kept.
    fn verify(&self, entries: &EntryReader) -> Result<usize, HistoryError> {
        let _extender = self.extend.lock().unwrap_or_else(PoisonError::into_inner);
        let (roots, generation) = {
            let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
            (state.roots.clone(), state.generation)
        };
        let mut good = roots.len();
        for start in (0..roots.len()).step_by(4096) {
            let end = (start + 4096).min(roots.len());
            let bad = (start..end).into_par_iter().find_first(|&twig| {
                entries.twig_leaves(twig, TWIG_SIZE).map_or(true, |leaves| twig_leaf_tree(&leaves)[1] != roots[twig])
            });
            if let Some(bad) = bad {
                good = bad;
                break;
            }
        }
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        let same = state.generation == generation;
        drop(state);
        if same && good < roots.len() {
            self.truncate_to(good)?;
        }
        Ok(good)
    }
}

// ---------------------------------------------------------------------------
// The entry log

/// Reads records of `entries.log` by slot: positional reads at the offsets
/// the live tree publishes (never a mapping, so a cut file is an error, not
/// a fault). Shared across threads.
struct EntryReader {
    file: File,
    path: PathBuf,
    offsets: OffsetsReader,
}

impl EntryReader {
    fn open(path: &Path, offsets: OffsetsReader) -> Result<Self, HistoryError> {
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

    /// The record of `slot`: its key and value.
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

    /// The leaf hashes of the first `filled` slots of `twig`, read with one
    /// positional read of their contiguous records.
    fn twig_leaves(&self, twig: usize, filled: usize) -> Result<Vec<Hash>, HistoryError> {
        if filled == 0 {
            return Ok(Vec::new());
        }
        let first = (twig * TWIG_SIZE) as u64;
        let start = self.offset(first)?;
        let last = self.offset(first + filled as u64 - 1)?;
        let mut header = [0u8; 36];
        read_exact_at(&self.file, &mut header, last).map_err(|e| io_at(&self.path, e))?;
        let last_len = u32::from_le_bytes(header[32..].try_into().expect("4 bytes"));
        let end = last + 36 + if last_len == HASH_ONLY_LEN { 0 } else { u64::from(last_len) };
        if end < start {
            return Err(HistoryError::Io(format!("twig {twig}'s records are not in order in the entry log")));
        }
        let mut bytes = vec![0u8; (end - start) as usize];
        read_exact_at(&self.file, &mut bytes, start).map_err(|e| io_at(&self.path, e))?;
        let mut leaves = Vec::with_capacity(filled);
        let mut at = 0usize;
        for _ in 0..filled {
            let head = bytes.get(at..at + 36).ok_or_else(|| HistoryError::Io(format!("twig {twig}'s records are not contiguous")))?;
            let key: Hash = head[..32].try_into().expect("32 bytes");
            let len = u32::from_le_bytes(head[32..].try_into().expect("4 bytes"));
            at += 36;
            if len == HASH_ONLY_LEN {
                leaves.push(key);
                continue;
            }
            let value = bytes.get(at..at + len as usize).ok_or_else(|| HistoryError::Io(format!("twig {twig}'s records are not contiguous")))?;
            leaves.push(hash_leaf(&key, value));
            at += len as usize;
        }
        if at != bytes.len() {
            return Err(HistoryError::Io(format!("twig {twig}'s records are not contiguous in the entry log")));
        }
        Ok(leaves)
    }
}

// ---------------------------------------------------------------------------
// Proof-ready states

fn build_heap(roots: &[Hash]) -> (usize, Vec<Hash>) {
    if roots.is_empty() {
        return (0, Vec::new());
    }
    let cap = roots.len().next_power_of_two();
    let mut heap = vec![NULL_HASH; 2 * cap];
    heap[cap..cap + roots.len()].copy_from_slice(roots);
    for node in (1..cap).rev() {
        heap[node] = hash_node(&heap[2 * node], &heap[2 * node + 1]);
    }
    (cap, heap)
}

fn words_to_bits(words: &[u64; WORDS]) -> [u8; TWIG_BITS_BYTES] {
    let mut bits = [0u8; TWIG_BITS_BYTES];
    for (chunk, word) in bits.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bits
}

/// A snapshot loaded for proving: its bits, every twig's root, its upper tree.
#[derive(Debug)]
struct Image {
    start: u64,
    hash: B256,
    next_slot: u64,
    active: Vec<u64>,
    twig_roots: Vec<Hash>,
    cap: usize,
    upper: Vec<Hash>,
    generation: u64,
    leaf_generation: u64,
}

impl Image {
    fn build(ckpt: ForestCheckpoint, leaves: &Leaves, entries: &EntryReader, generation: u64, requested: u64) -> Result<Self, HistoryError> {
        let next = ckpt.next_slot as usize;
        let count = next.div_ceil(TWIG_SIZE);
        let full = next / TWIG_SIZE;
        leaves.ensure_for_request(full, entries, requested)?;
        let (full_roots, leaf_generation) = {
            let state = leaves.state.read().unwrap_or_else(PoisonError::into_inner);
            if state.roots.len() < full {
                return Err(changed());
            }
            (state.roots[..full].to_vec(), state.generation)
        };
        let active = &ckpt.active;
        let twig_roots: Vec<Hash> = (0..count)
            .into_par_iter()
            .map(|twig| {
                let leaf = if twig < full {
                    full_roots[twig]
                } else {
                    twig_leaf_tree(&entries.twig_leaves(twig, next - twig * TWIG_SIZE)?)[1]
                };
                Ok(hash_node(&leaf, &twig_bits_hash(&words_to_bits(&twig_words(active, twig)))))
            })
            .collect::<Result<_, HistoryError>>()?;
        let (cap, upper) = build_heap(&twig_roots);
        Ok(Self {
            start: ckpt.head_number,
            hash: ckpt.head_hash,
            next_slot: ckpt.next_slot,
            active: ckpt.active,
            twig_roots,
            cap,
            upper,
            generation,
            leaf_generation,
        })
    }
}

fn twig_words(active: &[u64], twig: usize) -> [u64; WORDS] {
    let mut words = [0u64; WORDS];
    for (i, word) in words.iter_mut().enumerate() {
        *word = active.get(twig * WORDS + i).copied().unwrap_or(0);
    }
    words
}

#[derive(Debug)]
enum Upper {
    Empty,
    /// The image's heap (same capacity) with these nodes replaced.
    Overlay(HashMap<usize, Hash>),
    Own { cap: usize, nodes: Vec<Hash> },
}

/// The state after block `number`, ready to cut proofs from.
#[derive(Debug)]
struct AtHeight {
    next_slot: u64,
    image: Arc<Image>,
    /// The twigs whose bits differ from the image's.
    bits: HashMap<usize, [u64; WORDS]>,
    upper: Upper,
    root: Hash,
    generation: u64,
    leaf_generation: u64,
}

impl AtHeight {
    fn words(&self, twig: usize) -> [u64; WORDS] {
        self.bits.get(&twig).copied().unwrap_or_else(|| twig_words(&self.image.active, twig))
    }

    fn bit(&self, slot: u64) -> bool {
        slot < self.next_slot && {
            let twig = slot as usize / TWIG_SIZE;
            let local = slot as usize % TWIG_SIZE;
            self.words(twig)[local / 64] & (1 << (local % 64)) != 0
        }
    }

    fn cap(&self) -> usize {
        match &self.upper {
            Upper::Empty => 0,
            Upper::Overlay(_) => self.image.cap,
            Upper::Own { cap, .. } => *cap,
        }
    }

    fn node(&self, index: usize) -> Hash {
        match &self.upper {
            Upper::Empty => NULL_HASH,
            Upper::Overlay(overrides) => {
                overrides.get(&index).copied().unwrap_or_else(|| self.image.upper.get(index).copied().unwrap_or(NULL_HASH))
            }
            Upper::Own { nodes, .. } => nodes.get(index).copied().unwrap_or(NULL_HASH),
        }
    }

    fn path(&self, twig: usize) -> Vec<Hash> {
        let mut path = Vec::new();
        let mut node = self.cap() + twig;
        while node > 1 {
            path.push(self.node(node ^ 1));
            node >>= 1;
        }
        path
    }

    /// Replays `deltas` (the records after the image's block, up to and
    /// including `number`'s) onto the image, touching copies of the twigs
    /// they change only.
    fn replay(
        image: Arc<Image>,
        requested: u64,
        deltas: impl FnOnce(&mut dyn FnMut(ForestDelta) -> Result<(), HistoryError>) -> Result<(), HistoryError>,
        leaves: &Leaves,
        entries: &EntryReader,
    ) -> Result<Self, HistoryError> {
        let mut bits: HashMap<usize, [u64; WORDS]> = HashMap::new();
        let mut dirty: BTreeSet<usize> = BTreeSet::new();
        let mut next = image.next_slot;
        {
            let active = &image.active;
            let mut set_range = |bits: &mut HashMap<usize, [u64; WORDS]>, from: u64, to: u64, on: bool| {
                let mut slot = from;
                while slot < to {
                    let twig = slot as usize / TWIG_SIZE;
                    let twig_end = ((twig + 1) * TWIG_SIZE) as u64;
                    let words = bits.entry(twig).or_insert_with(|| twig_words(active, twig));
                    for s in slot..to.min(twig_end) {
                        let local = s as usize % TWIG_SIZE;
                        if on {
                            words[local / 64] |= 1 << (local % 64);
                        } else {
                            words[local / 64] &= !(1 << (local % 64));
                        }
                    }
                    dirty.insert(twig);
                    slot = twig_end;
                }
            };
            let mut apply = |delta: ForestDelta| -> Result<(), HistoryError> {
                let base = delta.base_next_slot;
                if base > next || delta.next_slot < base || !delta.appended.is_empty() {
                    return Err(HistoryError::Io(format!("the history record of block {} does not follow the one before it", delta.head_number)));
                }
                if base < next {
                    set_range(&mut bits, base, next, false);
                }
                set_range(&mut bits, base, delta.next_slot, true);
                for &(slot, on) in &delta.changed {
                    if slot >= delta.next_slot {
                        return Err(HistoryError::Io(format!("the history record of block {} names slot {slot} past its cursor", delta.head_number)));
                    }
                    set_range(&mut bits, slot, slot + 1, on);
                }
                next = delta.next_slot;
                Ok(())
            };
            deltas(&mut apply)?;
        }
        let count = (next as usize).div_ceil(TWIG_SIZE);
        let full = next as usize / TWIG_SIZE;
        let image_count = image.twig_roots.len();
        let need = dirty.iter().copied().filter(|t| *t < full).max().map_or(0, |t| t + 1);
        leaves.ensure_for_request(need, entries, requested)?;
        let live: Vec<usize> = dirty.iter().copied().filter(|t| *t < count).collect();
        let (full_roots, leaf_generation) = {
            let state = leaves.state.read().unwrap_or_else(PoisonError::into_inner);
            if state.roots.len() < need {
                return Err(changed());
            }
            let roots: HashMap<usize, Hash> = live.iter().filter(|t| **t < full).map(|&t| (t, state.roots[t])).collect();
            (roots, state.generation)
        };
        let roots_n: HashMap<usize, Hash> = live
            .par_iter()
            .map(|&twig| {
                let leaf = if twig < full {
                    full_roots[&twig]
                } else {
                    twig_leaf_tree(&entries.twig_leaves(twig, next as usize - twig * TWIG_SIZE)?)[1]
                };
                let words = bits.get(&twig).copied().unwrap_or_else(|| twig_words(&image.active, twig));
                Ok((twig, hash_node(&leaf, &twig_bits_hash(&words_to_bits(&words)))))
            })
            .collect::<Result<_, HistoryError>>()?;
        bits.retain(|twig, _| *twig < count);
        let upper = if count == 0 {
            Upper::Empty
        } else if count.next_power_of_two() == image.cap {
            let cap = image.cap;
            let mut overrides: HashMap<usize, Hash> = HashMap::new();
            let mut level: Vec<usize> = Vec::new();
            for (&twig, root) in &roots_n {
                overrides.insert(cap + twig, *root);
                level.push(cap + twig);
            }
            for twig in count..image_count {
                overrides.insert(cap + twig, NULL_HASH);
                level.push(cap + twig);
            }
            level.sort_unstable();
            level.dedup();
            while level.first().is_some_and(|node| *node > 1) {
                let mut parents: Vec<usize> = level.iter().map(|node| node / 2).collect();
                parents.dedup();
                for &parent in &parents {
                    let child = |i: usize| overrides.get(&i).copied().unwrap_or_else(|| image.upper[i]);
                    let hash = hash_node(&child(2 * parent), &child(2 * parent + 1));
                    overrides.insert(parent, hash);
                }
                level = parents;
            }
            Upper::Overlay(overrides)
        } else {
            let roots: Vec<Hash> = (0..count)
                .map(|twig| {
                    roots_n.get(&twig).copied().unwrap_or_else(|| image.twig_roots.get(twig).copied().unwrap_or(NULL_HASH))
                })
                .collect();
            let (cap, nodes) = build_heap(&roots);
            Upper::Own { cap, nodes }
        };
        let generation = image.generation;
        let mut at = Self { next_slot: next, image, bits, upper, root: NULL_HASH, generation, leaf_generation };
        at.root = at.node(1);
        Ok(at)
    }
}

// ---------------------------------------------------------------------------
// Small shared helpers

struct Lru<K, V> {
    cap: usize,
    items: VecDeque<(K, V)>,
}

impl<K: PartialEq, V: Clone> Lru<K, V> {
    const fn new(cap: usize) -> Self {
        Self { cap, items: VecDeque::new() }
    }

    fn get(&mut self, key: &K) -> Option<V> {
        let at = self.items.iter().position(|(k, _)| k == key)?;
        let item = self.items.remove(at)?;
        let value = item.1.clone();
        self.items.push_front(item);
        Some(value)
    }

    fn put(&mut self, key: K, value: V) {
        self.items.retain(|(k, _)| *k != key);
        self.items.push_front((key, value));
        self.items.truncate(self.cap);
    }

    fn clear(&mut self) {
        self.items.clear();
    }
}

/// Bounds how many requests compute at once.
struct Permits {
    free: Mutex<usize>,
    freed: Condvar,
}

struct Permit<'a>(&'a Permits);

impl Permits {
    fn acquire(&self) -> Permit<'_> {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        while *free == 0 {
            free = self.freed.wait(free).unwrap_or_else(PoisonError::into_inner);
        }
        *free -= 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        self.0.freed.notify_one();
    }
}

// ---------------------------------------------------------------------------
// History

enum Msg {
    Work,
    VerifyLeaves,
    Sync(mpsc::Sender<()>),
    Stop,
}

struct Shared {
    dir: PathBuf,
    entry_path: PathBuf,
    config: HistoryConfig,
    meta: RwLock<Meta>,
    /// Serialises file changes: appends, cuts, seals, snapshots, prunes.
    writer: Mutex<()>,
    leaves: Leaves,
    images: Mutex<Lru<(u64, u64, u64), Arc<Image>>>,
    heights: Mutex<Lru<(u64, B256), Arc<AtHeight>>>,
    permits: Permits,
    /// The (generation, leaf generation) a root mismatch last scheduled a
    /// leaf-cache verification for.
    verified_for: Mutex<Option<(u64, u64)>>,
}

/// The node's QMDB history.
pub struct QmdbHistory {
    shared: Arc<Shared>,
    tx: Mutex<mpsc::Sender<Msg>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for QmdbHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbHistory").field("dir", &self.shared.dir).field("config", &self.shared.config).finish_non_exhaustive()
    }
}

impl Drop for QmdbHistory {
    fn drop(&mut self) {
        let _ = self.tx.lock().unwrap_or_else(PoisonError::into_inner).send(Msg::Stop);
        if let Some(worker) = self.worker.lock().unwrap_or_else(PoisonError::into_inner).take()
            && worker.thread().id() != std::thread::current().id()
        {
            let _ = worker.join();
        }
    }
}

/// The prefix of a [`ForestCheckpoint`], decoded without the rest.
#[derive(Deserialize)]
struct CkptPrefix {
    _version: u32,
    head_number: u64,
    head_hash: B256,
    next_slot: u64,
}

/// The prefix of a [`ForestDelta`], decoded without the rest.
#[derive(Deserialize)]
struct DeltaPrefix {
    version: u32,
    head_number: u64,
    head_hash: B256,
    _base_next_slot: u64,
    next_slot: u64,
}

impl QmdbHistory {
    /// Opens (or starts) history for a node whose database stands at `head`,
    /// under `qmdb_dir`.
    ///
    /// History must reach the head exactly. Records above it (the forest ran
    /// ahead of the database) are cut. A history that ends below it is first
    /// caught up from `forest.log` (it holds the same deltas: a crash between
    /// the two appends loses only history's); one that cannot be caught up,
    /// or names another block at its end, is discarded and started again at
    /// the head, with an error logged naming the earliest provable block. A
    /// node that never kept history starts at its head: heights below it are
    /// reported as pruned.
    pub fn open(
        qmdb_dir: &Path,
        config: HistoryConfig,
        head: (u64, B256),
        head_checkpoint: impl FnOnce() -> Result<ForestCheckpoint, String>,
        offsets_at_open: Option<OffsetsReader>,
        relocated_bytes: u64,
        offsets: OffsetsSource,
    ) -> Result<Self, HistoryError> {
        // Every slot's record must be in the entry log, at an offset the
        // live tree publishes: refused here rather than failing every
        // request later.
        if relocated_bytes > 0 {
            return Err(HistoryError::Io(format!(
                "compaction relocated {relocated_bytes} bytes of records out of the entry log; QMDB history \
                 cannot read them (keep history on a database N42_QMDB_COMPACT never compacted)"
            )));
        }
        let dir = qmdb_dir.join(HISTORY_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        // The first layout of this feature (one log, one base) is not read.
        for old in ["spans.log", "base.ckpt"] {
            remove_if_present(&dir.join(old))?;
        }
        let shared = Arc::new(Shared {
            entry_path: qmdb_dir.join("entries.log"),
            leaves: Leaves::open(dir.join(TWIGS_FILE), usize::MAX),
            dir,
            config,
            meta: RwLock::new(Meta::default()),
            writer: Mutex::new(()),
            images: Mutex::new(Lru::new(IMAGE_CACHE)),
            heights: Mutex::new(Lru::new(HEIGHT_CACHE)),
            permits: Permits { free: Mutex::new(MAX_CONCURRENT_PROOFS), freed: Condvar::new() },
            verified_for: Mutex::new(None),
        });
        let mut head_checkpoint = Some(head_checkpoint);
        let mut fresh = |shared: &Shared, why: &str| -> Result<(), HistoryError> {
            let ckpt = (head_checkpoint.take().ok_or_else(|| HistoryError::Io("history restarted twice".into()))?)()
                .map_err(HistoryError::Io)?;
            if (ckpt.head_number, ckpt.head_hash) != head {
                return Err(HistoryError::Io(format!(
                    "the head checkpoint stands at block {} ({}), not at the head {} ({})",
                    ckpt.head_number, ckpt.head_hash, head.0, head.1
                )));
            }
            shared.restart(&ckpt)?;
            info!(target: "n42.qmdb.history", block = head.0, hash = %head.1, slots = ckpt.next_slot, why, "QMDB history starts here; earlier blocks are not provable");
            Ok(())
        };
        let _writer = shared.writer.lock().unwrap_or_else(PoisonError::into_inner);
        match shared.load()? {
            None => fresh(&shared, "no history kept before")?,
            Some(base) if base > head.0 => {
                error!(target: "n42.qmdb.history", base, head = head.0, "QMDB history starts above the database head (the database was rolled back below it); history restarts at the head");
                fresh(&shared, "history started above the database head")?;
            }
            Some(_) => {
                shared.cut_from(head.0 + 1)?;
                let mut end = shared.meta().head();
                let mut backfilled = 0;
                if end.0 < head.0 {
                    backfilled = shared.backfill(qmdb_dir, head.0).unwrap_or_else(|error| {
                        warn!(target: "n42.qmdb.history", %error, "QMDB history could not be caught up from forest.log");
                        0
                    });
                    end = shared.meta().head();
                }
                if (end.0, end.1) == head {
                    let meta = shared.meta();
                    info!(
                        target: "n42.qmdb.history",
                        earliest = meta.base().start, latest = end.0, segments = meta.segs.len(), backfilled,
                        "opened the QMDB history",
                    );
                } else {
                    error!(
                        target: "n42.qmdb.history",
                        history_ends = end.0, history_hash = %end.1, head = head.0, head_hash = %head.1,
                        "QMDB history does not reach the database head and forest.log cannot fill the gap (it was off for a while, \
                         or lost records the log no longer holds); it restarts at the head and the blocks before it are no longer provable",
                    );
                    fresh(&shared, "history did not reach the database head")?;
                }
            }
        }
        // A cache past the head's cursor describes slots no longer appended.
        let head_next = shared.meta().head().2;
        match offsets_at_open {
            Some(reader) if reader.len() >= head_next => {}
            Some(reader) => {
                return Err(HistoryError::Io(format!(
                    "the entry log's offsets cover {} slots, fewer than the {head_next} the head uses",
                    reader.len()
                )));
            }
            None => return Err(HistoryError::Io("the live tree publishes no entry-log offsets (file mode is required)".into())),
        }
        shared.leaves.truncate_to(head_next as usize / TWIG_SIZE)?;
        drop(_writer);
        let (tx, rx) = mpsc::channel();
        let worker_shared = shared.clone();
        let worker = std::thread::Builder::new()
            .name("n42-qmdb-history".into())
            .spawn(move || worker_loop(&worker_shared, &rx, &offsets))
            .map_err(|e| HistoryError::Io(format!("cannot start the history worker: {e}")))?;
        let _ = tx.send(Msg::Work);
        Ok(Self { shared, tx: Mutex::new(tx), worker: Mutex::new(Some(worker)) })
    }

    /// History's mode.
    pub fn mode(&self) -> HistoryMode {
        self.shared.config.mode
    }

    /// History's configuration.
    pub fn config(&self) -> HistoryConfig {
        self.shared.config
    }

    /// `(earliest, latest)` recorded blocks.
    pub fn range(&self) -> (u64, u64) {
        let meta = self.shared.meta();
        (meta.base().start, meta.head().0)
    }

    /// Why recording stopped, if it did.
    pub fn broken(&self) -> Option<String> {
        self.shared.meta().broken.clone()
    }

    /// `(segments, of which with a snapshot written)`.
    pub fn segments(&self) -> (usize, usize) {
        let meta = self.shared.meta();
        (meta.segs.len(), meta.segs.values().filter(|s| s.ckpt).count())
    }

    /// Waits until the background worker has caught up with everything
    /// recorded so far (snapshots, pruning).
    pub fn sync(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.lock().unwrap_or_else(PoisonError::into_inner).send(Msg::Sync(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    fn notify(&self, msg: Msg) {
        let _ = self.tx.lock().unwrap_or_else(PoisonError::into_inner).send(msg);
    }

    /// Records the deltas the node just appended to `forest.log`, in order.
    /// A failure stops recording (logged once, never returned: a block's
    /// persistence never waits on history); the next start catches up from
    /// `forest.log`.
    pub fn record(&self, deltas: &[ForestDelta]) {
        if deltas.is_empty() {
            return;
        }
        let _writer = self.shared.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if self.broken().is_some() {
            return;
        }
        let mut sealed = false;
        for delta in deltas {
            match self.shared.record_one(delta) {
                Ok(s) => sealed |= s,
                Err(error) => {
                    error!(target: "n42.qmdb.history", %error, "QMDB history stopped recording; it ends at its last record until the next start");
                    self.shared.meta_mut().broken = Some(error.to_string());
                    break;
                }
            }
        }
        drop(_writer);
        if sealed {
            self.notify(Msg::Work);
        }
    }

    /// The node checkpointed its state at `ckpt` without a delta history saw
    /// (the defensive first-checkpoint path): unless history already stands
    /// there, it restarts at the checkpoint.
    pub fn note_checkpoint(&self, ckpt: &ForestCheckpoint) {
        let _writer = self.shared.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let head = self.shared.meta().head();
        if head == (ckpt.head_number, ckpt.head_hash, ckpt.next_slot) {
            return;
        }
        error!(target: "n42.qmdb.history", history_head = head.0, checkpoint = ckpt.head_number, "a QMDB checkpoint was written past QMDB history without a delta; history restarts at it");
        if let Err(error) = self.shared.restart(ckpt) {
            error!(target: "n42.qmdb.history", %error, "QMDB history could not restart at the checkpoint; recording stops");
            self.shared.meta_mut().broken = Some(error.to_string());
        }
    }

    /// The database unwound to `number`: records above it are cut. Below the
    /// base, history no longer describes the database; it stops recording
    /// and restarts at the next start.
    pub fn truncate_above(&self, number: u64) {
        let _writer = self.shared.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if number < self.shared.meta().base().start {
            warn!(target: "n42.qmdb.history", block = number, "the database unwound below the QMDB history base; history restarts at the next start");
            self.shared.meta_mut().broken = Some(format!("the database unwound to {number}, below the history base"));
            return;
        }
        if let Err(error) = self.shared.cut_from(number + 1) {
            error!(target: "n42.qmdb.history", %error, "QMDB history could not be cut back to the unwound head; recording stops");
            self.shared.meta_mut().broken = Some(error.to_string());
        }
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
        let _permit = self.shared.permits.acquire();
        let result = self.shared.prove(target, expected_root, keys, live);
        if let Err(HistoryError::RootMismatch { .. }) = &result {
            // Drop what the caches hold for it; a leaf root the entry log
            // disagrees with is found and cut in the background, once per
            // generation (never a full rehash on a request's path).
            self.shared.heights.lock().unwrap_or_else(PoisonError::into_inner).clear();
            self.shared.images.lock().unwrap_or_else(PoisonError::into_inner).clear();
            let generations = (self.shared.meta().generation, self.shared.leaves.generation());
            if self.shared.verified_for.lock().unwrap_or_else(PoisonError::into_inner).replace(generations) != Some(generations) {
                warn!(target: "n42.qmdb.history", block = target.0, "a rebuilt QMDB root disagreed with its header; verifying the leaf-root cache in the background");
                self.notify(Msg::VerifyLeaves);
            }
        }
        result
    }
}

impl Shared {
    fn meta(&self) -> std::sync::RwLockReadGuard<'_, Meta> {
        self.meta.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn meta_mut(&self) -> std::sync::RwLockWriteGuard<'_, Meta> {
        self.meta.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn bump(&self, meta: &mut Meta) {
        meta.generation += 1;
        self.heights.lock().unwrap_or_else(PoisonError::into_inner).clear();
        self.images.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }

    /// Reads the segments on disk into `meta`, checking each against the
    /// next; returns the base's block, `None` when there is no usable base.
    /// Under the writer lock.
    fn load(&self) -> Result<Option<u64>, HistoryError> {
        let mut starts: BTreeSet<u64> = BTreeSet::new();
        for entry in std::fs::read_dir(&self.dir).map_err(|e| io_at(&self.dir, e))? {
            let entry = entry.map_err(|e| io_at(&self.dir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                remove_if_present(&entry.path())?;
                continue;
            }
            if let Some(start) = name.strip_prefix("seg-").and_then(|rest| rest.split('.').next()).and_then(|n| n.parse().ok()) {
                starts.insert(start);
            }
        }
        let mut segs: BTreeMap<u64, Seg> = BTreeMap::new();
        let mut rewinds = BTreeMap::new();
        let mut dropped_from = None;
        for &start in &starts {
            let prev = segs.values().next_back().map(Seg::head);
            match self.load_seg(start, prev, &mut rewinds) {
                Ok(Some(seg)) => {
                    let sealed_short = segs.values().next_back().is_some_and(|p: &Seg| !p.sealed);
                    if sealed_short {
                        // A segment after an unsealed one: a seal that did
                        // not finish; nothing after it is trusted.
                        dropped_from = Some(start);
                        break;
                    }
                    segs.insert(start, seg);
                }
                Ok(None) | Err(_) => {
                    dropped_from = Some(start);
                    break;
                }
            }
        }
        if let Some(from) = dropped_from {
            warn!(target: "n42.qmdb.history", from, "a QMDB history segment does not follow the one before it; it and the ones after it are dropped");
            for &start in starts.range(from..) {
                for ext in ["ckpt", "log", "idx", "sum"] {
                    remove_if_present(&seg_path(&self.dir, start, ext))?;
                }
            }
            rewinds.retain(|number, _| *number <= from);
            // The segment before it may have been sealed for it: it is the
            // current one again.
            if let Some(last) = segs.values_mut().next_back()
                && last.sealed
            {
                remove_if_present(&seg_path(&self.dir, last.start, "sum"))?;
                last.sealed = false;
            }
        }
        // A stop between a seal and the next segment's creation: the next
        // one starts (empty) at the sealed one's last block.
        if let Some(last) = segs.values().next_back().filter(|s| s.sealed).and_then(|s| s.last) {
            for ext in ["log", "idx"] {
                let path = seg_path(&self.dir, last.number, ext);
                File::create(&path).map_err(|e| io_at(&path, e))?;
            }
            segs.insert(last.number, Seg::empty(last.number, last.hash, last.next_slot, false));
        }
        let base = segs.values().next().map(|s| (s.start, s.ckpt));
        let mut meta = self.meta_mut();
        meta.segs = segs;
        meta.rewinds = rewinds;
        match base {
            Some((start, true)) => Ok(Some(start)),
            _ => {
                meta.segs.clear();
                meta.rewinds.clear();
                Ok(None)
            }
        }
    }

    /// One segment from disk: its summary when sealed, else its index
    /// checked against (and completed from) its log.
    fn load_seg(&self, start: u64, prev: Option<(u64, B256, u64)>, rewinds: &mut BTreeMap<u64, u64>) -> Result<Option<Seg>, HistoryError> {
        let ckpt_path = seg_path(&self.dir, start, "ckpt");
        let (start_hash, start_next_slot, ckpt) = match prev {
            Some((number, hash, next)) => {
                if number != start {
                    return Ok(None);
                }
                (hash, next, ckpt_path.exists())
            }
            None => match read_ckpt(&ckpt_path)? {
                Some(c) if c.head_number == start => (c.head_hash, c.next_slot, true),
                _ => return Ok(None),
            },
        };
        let mut seg = Seg::empty(start, start_hash, start_next_slot, ckpt);
        let sum_path = seg_path(&self.dir, start, "sum");
        if let Ok(bytes) = std::fs::read(&sum_path)
            && let Ok(summary) = bincode::deserialize::<Summary>(&bytes)
        {
            let idx_len = std::fs::metadata(seg_path(&self.dir, start, "idx")).map(|m| m.len()).unwrap_or(0);
            let log_len = std::fs::metadata(seg_path(&self.dir, start, "log")).map(|m| m.len()).unwrap_or(0);
            if idx_len >= summary.count * IDX_ENTRY as u64 && log_len >= summary.log_len {
                seg.sealed = true;
                seg.count = summary.count;
                seg.log_len = summary.log_len;
                seg.last = summary.last;
                rewinds.extend(summary.rewinds);
                return Ok(Some(seg));
            }
        }
        remove_if_present(&sum_path)?;
        self.rebuild_index(&mut seg, rewinds)?;
        Ok(Some(seg))
    }

    /// Streams a segment's log, (re)writing its index for every record that
    /// follows the one before it, and cuts both files after the last one.
    fn rebuild_index(&self, seg: &mut Seg, rewinds: &mut BTreeMap<u64, u64>) -> Result<(), HistoryError> {
        let log_path = seg_path(&self.dir, seg.start, "log");
        let idx_path = seg_path(&self.dir, seg.start, "idx");
        let mut entries = Vec::new();
        let mut at = 0u64;
        let mut prev = (seg.start, seg.start_next_slot);
        if let Ok(file) = File::open(&log_path) {
            let mut log = BufReader::with_capacity(1 << 20, file);
            while let Some(payload) = read_frame(&mut log, u64::from(u32::MAX)).map_err(|e| io_at(&log_path, e))? {
                let Ok(delta) = decode_delta(&payload, None) else { break };
                if delta.head_number <= prev.0 || delta.base_next_slot > prev.1 {
                    break;
                }
                let len = (RECORD_HEADER + payload.len()) as u32;
                let mut flags = 0;
                if delta.head_number != prev.0 + 1 {
                    flags |= SPAN;
                }
                if delta.base_next_slot < prev.1 {
                    flags |= REWIND;
                    rewinds.insert(delta.head_number, delta.base_next_slot);
                }
                let rec = Rec {
                    number: delta.head_number,
                    hash: delta.head_hash,
                    base_next_slot: delta.base_next_slot,
                    next_slot: delta.next_slot,
                    offset: at,
                    len,
                    flags,
                };
                entries.extend_from_slice(&rec.encode());
                at += u64::from(len);
                prev = (rec.number, rec.next_slot);
                seg.last = Some(rec);
                seg.count += 1;
            }
        }
        seg.log_len = at;
        truncate_file(&log_path, at).or_else(|_| File::create(&log_path).map(drop).map_err(|e| io_at(&log_path, e)))?;
        write_durably(&idx_path, &entries).map_err(|e| io_at(&idx_path, e))?;
        Ok(())
    }

    /// Discards every segment and starts at `ckpt`. Under the writer lock.
    fn restart(&self, ckpt: &ForestCheckpoint) -> Result<(), HistoryError> {
        let starts: Vec<u64> = self.meta().segs.keys().copied().collect();
        let mut on_disk: BTreeSet<u64> = starts.into_iter().collect();
        for entry in std::fs::read_dir(&self.dir).map_err(|e| io_at(&self.dir, e))?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(start) = name.strip_prefix("seg-").and_then(|rest| rest.split('.').next()).and_then(|n| n.parse().ok()) {
                on_disk.insert(start);
            }
        }
        for start in on_disk {
            for ext in ["ckpt", "log", "idx", "sum"] {
                remove_if_present(&seg_path(&self.dir, start, ext))?;
            }
        }
        // Leaf roots below the checkpoint's cursor are still the entry log's
        // (it is the live tree's); the ones past it are not.
        self.leaves.truncate_to(ckpt.next_slot as usize / TWIG_SIZE)?;
        write_ckpt(&seg_path(&self.dir, ckpt.head_number, "ckpt"), ckpt)?;
        for ext in ["log", "idx"] {
            let path = seg_path(&self.dir, ckpt.head_number, ext);
            File::create(&path).map_err(|e| io_at(&path, e))?;
        }
        sync_dir(&seg_path(&self.dir, ckpt.head_number, "log")).map_err(|e| io_at(&self.dir, e))?;
        let mut meta = self.meta_mut();
        meta.segs.clear();
        meta.segs.insert(ckpt.head_number, Seg::empty(ckpt.head_number, ckpt.head_hash, ckpt.next_slot, true));
        meta.rewinds.clear();
        meta.broken = None;
        self.bump(&mut meta);
        Ok(())
    }

    /// Appends one delta; returns whether it sealed the segment. Under the
    /// writer lock.
    fn record_one(&self, delta: &ForestDelta) -> Result<bool, HistoryError> {
        if !delta.appended.is_empty() {
            return Err(HistoryError::Io("a heap-mode delta reached file-mode history".into()));
        }
        if delta.head_number <= self.meta().head().0 {
            // A re-persisted height: the records from it on describe a
            // branch no longer persisted.
            self.cut_from(delta.head_number)?;
        }
        let (head, current) = {
            let meta = self.meta();
            (meta.head(), meta.current().clone())
        };
        if delta.base_next_slot > head.2 {
            return Err(HistoryError::Io(format!(
                "the delta of block {} starts at slot {} past the history head's cursor {} (block {})",
                delta.head_number, delta.base_next_slot, head.2, head.0
            )));
        }
        let rewind = delta.base_next_slot < head.2;
        if rewind {
            // Slots from the rewind's base on are appended again: their
            // twigs' leaf roots are no longer the entry log's. Cut first, so
            // a crash leaves the cache short, never stale.
            self.leaves.truncate_to(delta.base_next_slot as usize / TWIG_SIZE)?;
        }
        let payload = bincode::serialize(delta).map_err(|e| HistoryError::Io(e.to_string()))?;
        let bytes = frame(&payload);
        let len = u32::try_from(bytes.len()).map_err(|_| HistoryError::Io(format!("the delta of block {} is over 4 GiB", delta.head_number)))?;
        let log_path = seg_path(&self.dir, current.start, "log");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&log_path)
            .map_err(|e| io_at(&log_path, e))?;
        log.set_len(current.log_len).map_err(|e| io_at(&log_path, e))?;
        write_all_at(&log, &bytes, current.log_len).map_err(|e| io_at(&log_path, e))?;
        log.sync_data().map_err(|e| io_at(&log_path, e))?;
        let rec = Rec {
            number: delta.head_number,
            hash: delta.head_hash,
            base_next_slot: delta.base_next_slot,
            next_slot: delta.next_slot,
            offset: current.log_len,
            len,
            flags: if delta.head_number == head.0 + 1 { 0 } else { SPAN } | if rewind { REWIND } else { 0 },
        };
        // The index need not be durable: a start rebuilds it from the log.
        let idx_path = seg_path(&self.dir, current.start, "idx");
        let idx = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&idx_path)
            .map_err(|e| io_at(&idx_path, e))?;
        write_all_at(&idx, &rec.encode(), current.count * IDX_ENTRY as u64).map_err(|e| io_at(&idx_path, e))?;
        let seal = {
            let mut meta = self.meta_mut();
            let seg = meta.segs.get_mut(&current.start).expect("the current segment");
            seg.count += 1;
            seg.log_len += u64::from(len);
            seg.last = Some(rec);
            let seal = seg.count >= self.config.snapshot_blocks || seg.log_len >= self.config.segment_bytes(rec.next_slot);
            if rewind {
                meta.rewinds.insert(rec.number, rec.base_next_slot);
                self.bump(&mut meta);
                warn!(target: "n42.qmdb.history", block = rec.number, cursor = rec.base_next_slot, "a rewind of persisted QMDB state: blocks whose state used slots past its cursor are no longer provable");
            }
            seal
        };
        if seal {
            self.seal(current.start)?;
        }
        Ok(seal)
    }

    /// Seals segment `start` (its summary written durably) and opens the
    /// next at its last block, whose snapshot the worker writes.
    fn seal(&self, start: u64) -> Result<(), HistoryError> {
        let (seg, rewinds) = {
            let meta = self.meta();
            let seg = meta.segs.get(&start).cloned().ok_or_else(|| HistoryError::Io(format!("no segment {start}")))?;
            let from = seg.start + 1;
            let rewinds: Vec<(u64, u64)> = match seg.last {
                Some(last) => meta.rewinds.range(from..=last.number).map(|(a, b)| (*a, *b)).collect(),
                None => Vec::new(),
            };
            (seg, rewinds)
        };
        let Some(last) = seg.last else { return Ok(()) };
        let idx_path = seg_path(&self.dir, start, "idx");
        File::open(&idx_path).and_then(|f| f.sync_all()).map_err(|e| io_at(&idx_path, e))?;
        let summary = Summary { count: seg.count, log_len: seg.log_len, last: seg.last, rewinds };
        let sum_path = seg_path(&self.dir, start, "sum");
        write_durably(&sum_path, &bincode::serialize(&summary).map_err(|e| io_at(&sum_path, e))?).map_err(|e| io_at(&sum_path, e))?;
        for ext in ["log", "idx"] {
            let path = seg_path(&self.dir, last.number, ext);
            File::create(&path).map_err(|e| io_at(&path, e))?;
        }
        sync_dir(&sum_path).map_err(|e| io_at(&sum_path, e))?;
        let mut meta = self.meta_mut();
        if let Some(seg) = meta.segs.get_mut(&start) {
            seg.sealed = true;
        }
        meta.segs.insert(last.number, Seg::empty(last.number, last.hash, last.next_slot, false));
        Ok(())
    }

    /// Drops the records of blocks `number` and above. Under the writer lock.
    fn cut_from(&self, number: u64) -> Result<(), HistoryError> {
        let (segs, base) = {
            let meta = self.meta();
            if meta.head().0 < number {
                return Ok(());
            }
            (meta.segs.values().cloned().collect::<Vec<_>>(), meta.base().start)
        };
        if number <= base {
            return Err(HistoryError::Io(format!("block {number} is at or below the history base {base}")));
        }
        // The last segment that keeps anything starts below `number`.
        let keep = segs.iter().rev().find(|s| s.start < number).cloned().expect("the base starts below");
        let pos = first_at_or_above(&self.dir, &keep, number)?;
        let kept = read_recs(&self.dir, keep.start, pos.saturating_sub(1), pos)?.pop();
        let new_next = kept.map_or(keep.start_next_slot, |r| r.next_slot);
        self.leaves.truncate_to(new_next as usize / TWIG_SIZE)?;
        for seg in segs.iter().filter(|s| s.start >= number) {
            for ext in ["ckpt", "log", "idx", "sum"] {
                remove_if_present(&seg_path(&self.dir, seg.start, ext))?;
            }
        }
        let log_len = kept.map_or(0, |r| r.end());
        truncate_file(&seg_path(&self.dir, keep.start, "log"), log_len)?;
        truncate_file(&seg_path(&self.dir, keep.start, "idx"), pos * IDX_ENTRY as u64)?;
        if keep.sealed {
            remove_if_present(&seg_path(&self.dir, keep.start, "sum"))?;
        }
        let mut meta = self.meta_mut();
        meta.segs.retain(|start, _| *start < number);
        if let Some(seg) = meta.segs.get_mut(&keep.start) {
            seg.count = pos;
            seg.log_len = log_len;
            seg.last = kept;
            seg.sealed = false;
        }
        meta.rewinds.retain(|block, _| *block < number);
        self.bump(&mut meta);
        Ok(())
    }

    /// Catches history up from the node's own delta log (`forest.log.sealed`
    /// then `forest.log`) to `head`: the deltas after history's last record.
    /// Under the writer lock.
    fn backfill(&self, qmdb_dir: &Path, head: u64) -> Result<usize, HistoryError> {
        let end = self.meta().head();
        // A log that starts after a checkpoint taken at history's end has
        // no record of it: it follows on from the start.
        let ckpt_path = qmdb_dir.join("forest.ckpt");
        let mut found = File::open(&ckpt_path).ok().and_then(|f| {
            let mut bytes = Vec::with_capacity(4096);
            f.take(4096).read_to_end(&mut bytes).ok()?;
            let prefix: CkptPrefix = bincode::deserialize(&bytes).ok()?;
            Some((prefix.head_number, prefix.head_hash, prefix.next_slot) == end)
        }) == Some(true);
        let mut appended = 0;
        for name in ["forest.log.sealed", "forest.log"] {
            let path = qmdb_dir.join(name);
            let Ok(file) = File::open(&path) else { continue };
            let mut log = BufReader::with_capacity(1 << 20, file);
            while let Some(payload) = read_frame(&mut log, u64::MAX).map_err(|e| io_at(&path, e))? {
                let Ok(prefix) = bincode::deserialize::<DeltaPrefix>(&payload) else { break };
                if prefix.version != ForestDelta::VERSION {
                    break;
                }
                if !found {
                    found = (prefix.head_number, prefix.head_hash, prefix.next_slot) == end;
                    continue;
                }
                if prefix.head_number > head {
                    return Ok(appended);
                }
                let delta = decode_delta(&payload, None)?;
                self.record_one(&delta)?;
                appended += 1;
            }
        }
        if appended > 0 {
            warn!(target: "n42.qmdb.history", from = end.0, records = appended, "caught QMDB history up from forest.log (a stop between the two appends)");
        }
        Ok(appended)
    }

    // -----------------------------------------------------------------------
    // Proving

    fn prove(&self, target: (u64, B256), expected_root: B256, keys: &[Hash], live: &dyn LiveTree) -> Result<HistoricalProof, HistoryError> {
        let (number, hash) = target;
        // Plan under the index's lock; read the files without it.
        let (seg_n, start, walk, base, head, generation, rewinds) = {
            let meta = self.meta();
            let base = meta.base().clone();
            let head = meta.head();
            if number < base.start {
                return Err(HistoryError::Pruned { requested: number, earliest: base.start });
            }
            if number > head.0 {
                return Err(HistoryError::NotYet { requested: number, latest: head.0 });
            }
            let seg_n = meta.segs.range(..=number).next_back().map(|(_, s)| s.clone()).expect("the base is at or below");
            let start = meta.segs.range(..=number).rev().map(|(_, s)| s).find(|s| s.ckpt).cloned().expect("the base has a snapshot");
            let walk: Vec<Seg> = meta.segs.range(start.start..=seg_n.start).map(|(_, s)| s.clone()).collect();
            let rewinds: Vec<(u64, u64)> = meta.rewinds.range(number + 1..).map(|(a, b)| (*a, *b)).collect();
            (seg_n, start, walk, base, head, meta.generation, rewinds)
        };
        let target_rec = if seg_n.start == number {
            if seg_n.start_hash != hash {
                return Err(HistoryError::NotRecorded { number, hash });
            }
            None
        } else {
            match find_rec(&self.dir, &seg_n, number)? {
                Some((_, rec)) if rec.hash == hash => Some(rec),
                _ => return Err(HistoryError::NotRecorded { number, hash }),
            }
        };
        let next_n = target_rec.map_or(seg_n.start_next_slot, |r| r.next_slot);
        if let Some((at, _)) = rewinds.iter().find(|(_, base)| *base < next_n) {
            return Err(HistoryError::Rewound { requested: number, at: *at });
        }
        let needed: u64 = walk
            .iter()
            .map(|s| if s.start == seg_n.start { target_rec.map_or(0, |r| r.end()) } else { s.log_len })
            .sum();
        if needed > self.config.budget_bytes {
            return Err(HistoryError::Budget { requested: number, needed, budget: self.config.budget_bytes });
        }
        // One hold of the forest's lock: every key's live slot, the offsets,
        // and (from a base past genesis) what the live tree retired since
        // the history head.
        let retired_since = (base.start > 0).then_some((head.1, base.start_next_slot, LIVE_RETIRED_LIMIT));
        let probe = live
            .probe(keys, retired_since)
            .ok_or_else(|| HistoryError::Io("the live tree is not available (poisoned, or heap mode); retry".into()))?;
        let entries = EntryReader::open(&self.entry_path, probe.offsets.clone())?;
        let at = self.at_height(number, hash, &start, &walk, generation, &entries)?;
        let root = B256::from(at.root);
        if root != expected_root {
            return Err(HistoryError::RootMismatch { number, computed: root, expected: expected_root });
        }
        let mut lookup = Lookup {
            shared: self,
            at: &at,
            base: &base,
            number,
            seg_n: &seg_n,
            target_pos: None,
            entries: &entries,
            probe: &probe,
            retired_after: None,
            genesis_limit: 0,
            reads: 0,
        };
        let mut answers = Vec::with_capacity(keys.len());
        for (i, key) in keys.iter().enumerate() {
            lookup.reads = 0;
            let slot = lookup.locate(key, probe.slots.get(i).copied().flatten())?;
            let proof = match slot {
                None => None,
                Some(slot) => Some(cut_proof(&at, &entries, key, slot, &root)?),
            };
            answers.push(KeyAtHeight { key: *key, proof });
        }
        if self.meta().generation != generation {
            // A cut or rewind meanwhile may have changed what the searches read.
            return Err(changed());
        }
        Ok(HistoricalProof { number, hash, root, keys: answers })
    }

    /// The proof-ready state after `number`: from the cache, or replayed
    /// from the snapshot `start` over the records of `walk`.
    fn at_height(&self, number: u64, hash: B256, start: &Seg, walk: &[Seg], generation: u64, entries: &EntryReader) -> Result<Arc<AtHeight>, HistoryError> {
        let leaf_generation = self.leaves.generation();
        if let Some(at) = self.heights.lock().unwrap_or_else(PoisonError::into_inner).get(&(number, hash))
            && at.generation == generation
            && at.leaf_generation == leaf_generation
        {
            return Ok(at);
        }
        let key = (start.start, generation, leaf_generation);
        let cached = self.images.lock().unwrap_or_else(PoisonError::into_inner).get(&key);
        let image = match cached {
            Some(image) => image,
            None => {
                let path = seg_path(&self.dir, start.start, "ckpt");
                let ckpt = read_ckpt(&path)?.ok_or_else(changed)?;
                if (ckpt.head_number, ckpt.head_hash) != (start.start, start.start_hash) {
                    return Err(changed());
                }
                let image = Arc::new(Image::build(ckpt, &self.leaves, entries, generation, number)?);
                self.images.lock().unwrap_or_else(PoisonError::into_inner).put((image.start, generation, image.leaf_generation), image.clone());
                image
            }
        };
        debug_assert_eq!((image.start, image.hash), (start.start, start.start_hash));
        let dir = self.dir.clone();
        let at = AtHeight::replay(
            image,
            number,
            |apply| {
                walk_records(&dir, walk, number, |rec, delta| {
                    apply(delta)?;
                    Ok(rec.number < number)
                })
            },
            &self.leaves,
            entries,
        )?;
        let at = Arc::new(at);
        // A cached height holds its snapshot image alive: keep only those
        // whose image is still among the cached ones, so memory stays at
        // most a few images.
        let images: Vec<Arc<Image>> =
            self.images.lock().unwrap_or_else(PoisonError::into_inner).items.iter().map(|(_, image)| image.clone()).collect();
        let mut heights = self.heights.lock().unwrap_or_else(PoisonError::into_inner);
        heights.put((number, hash), at.clone());
        heights.items.retain(|(_, cached)| images.iter().any(|image| Arc::ptr_eq(image, &cached.image)));
        Ok(at)
    }
}

/// Cuts and checks the proof of `key` at `slot`.
fn cut_proof(at: &AtHeight, entries: &EntryReader, key: &Hash, slot: u64, root: &B256) -> Result<QmdbProof, HistoryError> {
    let twig = slot as usize / TWIG_SIZE;
    let filled = (at.next_slot as usize - twig * TWIG_SIZE).min(TWIG_SIZE);
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
    let proof = QmdbProof { key: *key, value, slot, twig_path, active_bits: words_to_bits(&at.words(twig)), upper_path: at.path(twig) };
    if !proof.verify_for_key(&root.0, key) {
        return Err(HistoryError::Io(format!("the proof cut for slot {slot} does not verify against the rebuilt root")));
    }
    Ok(proof)
}

/// A request's key lookups at block `number`.
struct Lookup<'a> {
    shared: &'a Shared,
    at: &'a AtHeight,
    base: &'a Seg,
    number: u64,
    seg_n: &'a Seg,
    target_pos: Option<u64>,
    entries: &'a EntryReader,
    probe: &'a LiveProbe,
    /// Key -> the slot below the base's cursor a block after `number`
    /// retired first, recorded or live; built on first need.
    retired_after: Option<Result<HashMap<Hash, u64>, HistoryError>>,
    /// The lowest rewind base at or before N (the cursor at N if none).
    genesis_limit: u64,
    reads: u64,
}

impl Lookup<'_> {
    fn read_key(&mut self, key: &Hash, slot: u64) -> Result<Hash, HistoryError> {
        if self.reads >= LOOKUP_BUDGET {
            return Err(HistoryError::LookupBudget(B256::from(*key)));
        }
        self.reads += 1;
        self.entries.key(slot)
    }

    /// The slot that held `key`'s live entry after the block, or `None`
    /// when recorded data shows it had none.
    fn locate(&mut self, key: &Hash, live_slot: Option<u64>) -> Result<Option<u64>, HistoryError> {
        let next_n = self.at.next_slot;
        // 1. The live tree's slot: a key no block after N moved.
        if let Some(slot) = live_slot
            && slot < next_n
            && self.at.bit(slot)
            && self.read_key(key, slot)? == *key
        {
            return Ok(Some(slot));
        }
        // 2. Its latest append after the base and at or before N: a block's
        // appended run is in key order (its operations are sorted); a
        // multi-block or rewinding record's is not and is read whole.
        if let Some(slot) = self.search_appends(key)? {
            return Ok(self.at.bit(slot).then_some(slot));
        }
        // 3. Not appended since the base. From genesis the base is the
        // alloc, appended in key order: the search is complete.
        if self.base.start == 0 {
            let end = self.base.start_next_slot.min(self.genesis_limit);
            let found = search_sorted(0, end, key, &mut |slot| self.read_key(key, slot))?;
            return Ok(found.filter(|slot| self.at.bit(*slot)));
        }
        // 4. Its slot at N, if it had one, predates the base. It is live
        // now (step 1 found it) or a block after N retired it: recorded, or
        // on the live tree past the history head. Shown absent only when
        // both are known.
        let retired = match &self.retired_after {
            Some(retired) => retired.clone(),
            None => {
                let built = self.build_retired_after(key);
                self.retired_after = Some(built.clone());
                built
            }
        }?;
        match retired.get(key) {
            Some(&slot) if self.at.bit(slot) => Ok(Some(slot)),
            _ => Ok(None),
        }
    }

    fn search_appends(&mut self, key: &Hash) -> Result<Option<u64>, HistoryError> {
        let shared = self.shared;
        let segs: Vec<Seg> = shared.meta().segs.range(self.base.start..=self.seg_n.start).map(|(_, s)| s.clone()).collect();
        if self.target_pos.is_none() {
            self.target_pos = Some(first_at_or_above(&shared.dir, self.seg_n, self.number + 1)?);
        }
        // Slots a rewind at or before N re-appended no longer hold what the
        // records before it appended: each record is searched below the
        // lowest rewind base after it.
        let mut limit = self.at.next_slot;
        for seg in segs.iter().rev() {
            let mut to = if seg.start == self.seg_n.start { self.target_pos.unwrap_or(0) } else { seg.count };
            while to > 0 {
                let from = to.saturating_sub(4096);
                if self.reads + (to - from) > LOOKUP_BUDGET {
                    return Err(HistoryError::LookupBudget(B256::from(*key)));
                }
                self.reads += to - from;
                let recs = read_recs(&shared.dir, seg.start, from, to)?;
                for rec in recs.iter().rev() {
                    let end = rec.next_slot.min(limit);
                    if rec.flags & REWIND != 0 {
                        limit = limit.min(rec.base_next_slot);
                    }
                    let found = if rec.base_next_slot >= end {
                        None
                    } else if rec.plain() {
                        search_sorted(rec.base_next_slot, end, key, &mut |slot| self.read_key(key, slot))?
                    } else {
                        let mut found = None;
                        for slot in (rec.base_next_slot..end).rev() {
                            if self.read_key(key, slot)? == *key {
                                found = Some(slot);
                                break;
                            }
                        }
                        found
                    };
                    if found.is_some() {
                        return Ok(found);
                    }
                }
                to = from;
            }
        }
        self.genesis_limit = limit;
        Ok(None)
    }

    /// Key -> first slot below the base's cursor retired after block N:
    /// the recorded records after N, then the live tree past the history
    /// head. An error when either cannot be read within the budgets, or the
    /// live tree does not descend from the history head ([`HistoryError::Retry`]).
    fn build_retired_after(&mut self, key: &Hash) -> Result<HashMap<Hash, u64>, HistoryError> {
        let below = self.base.start_next_slot;
        let Some(live) = self.probe.retired_since.as_ref() else {
            return Err(HistoryError::Retry(B256::from(*key)));
        };
        let shared = self.shared;
        let (segs, generation) = {
            let meta = shared.meta();
            (meta.segs.range(self.seg_n.start..).map(|(_, s)| s.clone()).collect::<Vec<_>>(), meta.generation)
        };
        let needed: u64 = segs.iter().map(|s| s.log_len).sum();
        if needed > shared.config.budget_bytes {
            return Err(HistoryError::Budget { requested: self.number, needed, budget: shared.config.budget_bytes });
        }
        let mut slots: Vec<u64> = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let number = self.number;
        walk_records(&shared.dir, &segs, u64::MAX, |rec, delta| {
            if rec.number > number {
                for &(slot, on) in &delta.changed {
                    if !on && slot < below && seen.insert(slot) {
                        slots.push(slot);
                    }
                }
            }
            Ok(true)
        })?;
        // Records appended since the request planned are read too; the live
        // list covers everything after the head it planned against (the live
        // tree descends from it), so together they cover every block after N.
        if shared.meta().generation != generation {
            return Err(changed());
        }
        for &slot in live {
            if seen.insert(slot) {
                slots.push(slot);
            }
        }
        let mut map = HashMap::with_capacity(slots.len());
        for slot in slots {
            let k = self.read_key(key, slot)?;
            map.entry(k).or_insert(slot);
        }
        Ok(map)
    }
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

// ---------------------------------------------------------------------------
// The background worker: snapshots, pruning, the leaf-root cache

/// Where the worker stands while it writes snapshots: the state after one
/// block, carried from one segment to the next so every delta is applied
/// once.
struct Cursor {
    ckpt: ForestCheckpoint,
    generation: u64,
}

fn worker_loop(shared: &Shared, rx: &mpsc::Receiver<Msg>, offsets: &OffsetsSource) {
    let mut cursor: Option<Cursor> = None;
    let mut warm = true;
    let pause = Duration::ZERO;
    loop {
        // Idle, it still looks once a second: new full twigs to cache, a
        // window to prune after an unwind.
        let wait = if warm { pause } else { Duration::from_secs(1) };
        let msg = match rx.recv_timeout(wait) {
            Ok(msg) => Some(msg),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let mut reply = None;
        match msg {
            Some(Msg::Stop) => return,
            Some(Msg::Sync(tx)) => reply = Some(tx),
            Some(Msg::VerifyLeaves) => {
                if let Some(reader) = offsets()
                    && let Ok(entries) = EntryReader::open(&shared.entry_path, reader)
                {
                    let had = shared.leaves.len();
                    match shared.leaves.verify(&entries) {
                        Ok(kept) if kept < had => {
                            warn!(target: "n42.qmdb.history", kept, dropped = had - kept, "cut the QMDB leaf-root cache where it disagreed with the entry log");
                        }
                        Ok(_) => {}
                        Err(error) => warn!(target: "n42.qmdb.history", %error, "could not verify the QMDB leaf-root cache"),
                    }
                }
                continue;
            }
            Some(Msg::Work) | None => {}
        }
        let started = Instant::now();
        if let Err(error) = write_snapshots(shared, &mut cursor) {
            warn!(target: "n42.qmdb.history", %error, "a QMDB history snapshot was not written; retrying later");
            cursor = None;
        }
        if let Err(error) = prune(shared) {
            warn!(target: "n42.qmdb.history", %error, "QMDB history was not pruned; retrying later");
        }
        let spent = started.elapsed();
        if spent > Duration::from_secs(1) {
            info!(target: "n42.qmdb.history", ms = spent.as_millis() as u64, "QMDB history background work");
        }
        // Warm the leaf-root cache a chunk at a time, so a snapshot or a
        // stop is never kept waiting long. The live tree's lock is taken
        // (for the offsets) only when there is something to hash.
        let full = shared.meta().head().2 as usize / TWIG_SIZE;
        let needed = shared.leaves.len() < full;
        warm = match needed.then(|| offsets().map(|reader| EntryReader::open(&shared.entry_path, reader))).flatten() {
            Some(Ok(entries)) => {
                match shared.leaves.ensure(full, &entries, Some(WARM_CHUNK)) {
                    Ok(done) => !done,
                    Err(error) => {
                        warn!(target: "n42.qmdb.history", %error, "could not extend the QMDB leaf-root cache");
                        false
                    }
                }
            }
            _ => false,
        };
        if let Some(tx) = reply {
            let _ = tx.send(());
        }
    }
}

/// Writes the snapshot of every segment that has none, oldest first.
fn write_snapshots(shared: &Shared, cursor: &mut Option<Cursor>) -> Result<(), HistoryError> {
    loop {
        let (todo, from, walk, generation) = {
            let meta = shared.meta();
            let Some(todo) = meta.segs.values().find(|s| !s.ckpt).cloned() else { return Ok(()) };
            let from = meta
                .segs
                .range(..todo.start)
                .rev()
                .map(|(_, s)| s)
                .find(|s| s.ckpt)
                .cloned()
                .ok_or_else(|| HistoryError::Io("no snapshot before a segment".into()))?;
            let walk: Vec<Seg> = meta.segs.range(from.start..todo.start).map(|(_, s)| s.clone()).collect();
            (todo, from, walk, meta.generation)
        };
        // Resume from where the last snapshot left the cursor when it is on
        // the way; otherwise load the snapshot before.
        let usable = cursor
            .as_ref()
            .is_some_and(|c| c.generation == generation && c.ckpt.head_number >= from.start && c.ckpt.head_number <= todo.start);
        if !usable {
            let path = seg_path(&shared.dir, from.start, "ckpt");
            let ckpt = read_ckpt(&path)?.ok_or_else(changed)?;
            *cursor = Some(Cursor { ckpt, generation });
        }
        let state = cursor.as_mut().expect("set above");
        let at = state.ckpt.head_number;
        let segs: Vec<Seg> = walk.into_iter().filter(|s| s.last.is_some_and(|l| l.number > at)).collect();
        walk_records(&shared.dir, &segs, todo.start, |rec, delta| {
            if rec.number > at {
                state.ckpt.apply_delta(&delta).map_err(|e| HistoryError::Io(e.to_string()))?;
            }
            Ok(true)
        })?;
        if (state.ckpt.head_number, state.ckpt.head_hash, state.ckpt.next_slot) != (todo.start, todo.start_hash, todo.start_next_slot) {
            *cursor = None;
            return Err(changed());
        }
        let path = seg_path(&shared.dir, todo.start, "ckpt");
        write_ckpt(&path, &state.ckpt)?;
        let _writer = shared.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut meta = shared.meta_mut();
        let same = meta.generation == generation;
        match meta.segs.get_mut(&todo.start) {
            Some(seg) if same && (seg.start_hash, seg.start_next_slot) == (todo.start_hash, todo.start_next_slot) => {
                seg.ckpt = true;
            }
            _ => {
                drop(meta);
                remove_if_present(&path)?;
                *cursor = None;
            }
        }
    }
}

/// `Keep(n)`: drops the segments wholly older than the newest snapshot at
/// or below `head - n` (which becomes the base).
fn prune(shared: &Shared) -> Result<(), HistoryError> {
    let HistoryMode::Keep(keep) = shared.config.mode else { return Ok(()) };
    let _writer = shared.writer.lock().unwrap_or_else(PoisonError::into_inner);
    let (drop_starts, new_base) = {
        let meta = shared.meta();
        let cutoff = meta.head().0.saturating_sub(keep);
        let Some(new_base) = meta.segs.range(..=cutoff).rev().map(|(_, s)| s).find(|s| s.ckpt).map(|s| s.start) else {
            return Ok(());
        };
        (meta.segs.range(..new_base).map(|(start, _)| *start).collect::<Vec<_>>(), new_base)
    };
    if drop_starts.is_empty() {
        return Ok(());
    }
    {
        // Out of the index first: a request planned from now on does not
        // reach them; one already reading them sees an error and retries.
        let mut meta = shared.meta_mut();
        for start in &drop_starts {
            meta.segs.remove(start);
        }
        meta.rewinds = meta.rewinds.split_off(&(new_base + 1));
    }
    for start in drop_starts {
        for ext in ["ckpt", "log", "idx", "sum"] {
            remove_if_present(&seg_path(&shared.dir, start, ext))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-history-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_compacted_entry_log_refuses_history_at_start() {
        let dir = scratch("relocated");
        let opened = QmdbHistory::open(
            &dir,
            HistoryConfig::new(HistoryMode::All),
            (0, B256::ZERO),
            || Err("not reached".into()),
            None,
            64,
            Arc::new(|| None),
        );
        match opened {
            Err(HistoryError::Io(message)) => assert!(message.contains("relocated"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_entries_and_modes_round_trip() {
        let rec = Rec {
            number: 9,
            hash: B256::repeat_byte(3),
            base_next_slot: 5,
            next_slot: 70,
            offset: 1234,
            len: 99,
            flags: SPAN | REWIND,
        };
        assert_eq!(Rec::decode(&rec.encode()), rec);
        assert_eq!(HistoryMode::parse("all"), Ok(HistoryMode::All));
        assert_eq!(HistoryMode::parse(" 128 "), Ok(HistoryMode::Keep(128)));
        assert_eq!(HistoryMode::parse("off"), Ok(HistoryMode::Off));
        assert!(HistoryMode::parse("lots").is_err());
        let keep = HistoryConfig::new(HistoryMode::Keep(8));
        assert_eq!(keep.snapshot_blocks, 16, "a short window still gets segments of at least 16 blocks");
        assert_eq!(HistoryConfig::new(HistoryMode::Keep(1 << 20)).snapshot_blocks, DEFAULT_SNAPSHOT_BLOCKS);
        let all = HistoryConfig::new(HistoryMode::All);
        assert_eq!(all.segment_bytes(8 << 30), 128 << 20, "a segment is sealed past a quarter of the request budget");
        assert_eq!(all.segment_bytes(1 << 20), 32 << 20);
    }

    #[test]
    fn the_lru_keeps_the_most_recent() {
        let mut lru = Lru::new(2);
        lru.put(1, "a");
        lru.put(2, "b");
        assert_eq!(lru.get(&1), Some("a"));
        lru.put(3, "c");
        assert_eq!(lru.get(&2), None, "the least recently used went");
        assert_eq!(lru.get(&1), Some("a"));
        assert_eq!(lru.get(&3), Some("c"));
    }
}

// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consensus state that has to survive a restart.
//!
//! Two things are stored, for two different reasons.
//!
//! **The vote log is a safety requirement, and so is the lock in it.**
//! HotStuff-2 forbids voting twice in one view. In memory that is
//! `RoundState::last_voted_view`; across a crash it is this file. A node that
//! restarts without it re-votes in views it had already signed, which is
//! equivocation -- indistinguishable, to everyone else, from a validator
//! deliberately signing two conflicting values. So the log is written *before*
//! the signature, and [`n42_h2_consensus::VoteLogWriter`]'s contract is that an
//! fsync failure aborts the vote rather than proceeding unlogged.
//!
//! The locked QC is recorded in the same fsync. A vote is also a promise not to
//! support anything the current lock forbids; the lock normally reaches the
//! checkpoint only at commit, so a node that raised its lock, commit-voted and
//! crashed would restart with an older one and R1-vote for a proposal justified
//! below the lock. One such amnesiac plus f Byzantine validators is enough to
//! form a conflicting certificate.
//!
//! **The checkpoint is a liveness convenience.** It carries the view, the locked
//! and committed QCs, and the timeout count, so a restarted node rejoins near
//! the head instead of proposing from genesis -- which a live node answers with
//! `-38006 Too deep reorg` from its execution layer. Losing it costs a resync,
//! not safety.
//!
//! Recovery takes the *more conservative* of the two: the larger watermarks and
//! the higher lock. The vote log is written ahead of the checkpoint, so it can
//! legitimately be further along, and taking the checkpoint's older values would
//! re-open exactly the window the log exists to close. A vote log with no
//! checkpoint at all still binds the node.
//!
//! A vote log that fails its checksum stops the node. The alternative is
//! guessing at which views were already signed and which lock was held, and a
//! wrong guess here is the one fault this file exists to prevent.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use n42_h2_consensus::{ConsensusError, ConsensusResult, VoteLogWriter};
use n42_h2_primitives::consensus::QuorumCertificate;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// The pre-lock record: `[vote u64 LE][commit u64 LE][crc32 u32 LE]`. Still
/// read, so a log written by an older build does not stop the node.
const LEGACY_RECORD_LEN: usize = 8 + 8 + 4;

/// Current record: `[last_vote_view u64 LE][last_commit_vote_view u64 LE]
/// [qc_len u32 LE][qc bytes][crc32 u32 LE over everything before it]`.
///
/// Rewritten in place from offset 0 and expected to fit one sector, so a torn
/// write is not expected; the checksum is there to catch it if the storage
/// disagrees. Bytes past the record are ignored.
const SECTOR_BYTES: usize = 4096;

const VOTE_LOG_FILE: &str = "vote-log.bin";
const CHECKPOINT_FILE: &str = "consensus-checkpoint.json";

/// What a restarted node needs to rejoin near the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusCheckpoint {
    /// The view the node was in.
    pub view: u64,
    /// The QC it was locked on.
    pub locked_qc: QuorumCertificate,
    /// The QC of the last block it committed.
    pub last_committed_qc: QuorumCertificate,
    /// Consecutive timeouts, which set the pacemaker's backoff.
    pub consecutive_timeouts: u32,
    /// The highest view it cast an R1 vote in.
    pub last_voted_view: u64,
    /// The highest view it cast an R2 commit vote in.
    pub last_commit_voted_view: u64,
}

/// Why consensus state could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store's directory or files could not be used.
    #[error("consensus store at {path}: {source}")]
    Io {
        /// What was being opened or written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The vote log is corrupt. The node must not start: continuing means
    /// guessing which views were already signed, and a wrong guess is
    /// equivocation.
    #[error("vote log at {path} failed its checksum; refusing to guess which views were signed")]
    CorruptVoteLog {
        /// The file that failed.
        path: PathBuf,
    },
    /// The checkpoint could not be parsed. Unlike the vote log this is
    /// recoverable — the node resyncs — so it is reported and skipped.
    #[error("checkpoint at {path} is unreadable: {source}")]
    CorruptCheckpoint {
        /// The file that failed.
        path: PathBuf,
        /// The parse error.
        source: serde_json::Error,
    },
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Consensus state on disk.
#[derive(Debug)]
pub struct ConsensusStore {
    dir: PathBuf,
}

impl ConsensusStore {
    /// Opens (creating if needed) a store in `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(io(&dir))?;
        Ok(Self { dir })
    }

    /// The vote log, to hand to the consensus engine.
    ///
    /// Cheap to clone; the engine keeps one and calls it on the signing path.
    pub fn vote_log(&self) -> Result<FileVoteLog, StoreError> {
        FileVoteLog::open(self.dir.join(VOTE_LOG_FILE))
    }

    /// Reads the recovery state, if this node has run here before.
    ///
    /// Returns `None` for a fresh directory (no checkpoint and an empty vote
    /// log). The view and vote counters are
    /// reconciled with the vote log, taking whichever is further along — the log
    /// is written ahead of the checkpoint, so it can legitimately be newer, and
    /// taking the older value would re-open the double-vote window.
    pub fn load(&self) -> Result<Option<ConsensusCheckpoint>, StoreError> {
        let path = self.dir.join(CHECKPOINT_FILE);
        let logged = self.vote_log()?.read_record()?;
        let mut checkpoint: ConsensusCheckpoint = match std::fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|source| {
                StoreError::CorruptCheckpoint {
                    path: path.clone(),
                    source,
                }
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if logged == VoteRecord::EMPTY {
                    return Ok(None);
                }
                // The node signed something but never checkpointed. The log
                // still binds it: build a checkpoint from it, genesis for the
                // rest, and let the node resync.
                warn!(
                    target: "n42.h2.store",
                    logged_vote = logged.last_vote_view,
                    "vote log present without a checkpoint; recovering from the log alone",
                );
                ConsensusCheckpoint {
                    view: 0,
                    locked_qc: QuorumCertificate::genesis(),
                    last_committed_qc: QuorumCertificate::genesis(),
                    consecutive_timeouts: 0,
                    last_voted_view: 0,
                    last_commit_voted_view: 0,
                }
            }
            Err(error) => return Err(io(&path)(error)),
        };

        let (logged_vote, logged_commit) = (logged.last_vote_view, logged.last_commit_vote_view);
        if logged_vote > checkpoint.last_voted_view
            || logged_commit > checkpoint.last_commit_voted_view
        {
            // Normal: the crash landed between signing and checkpointing.
            debug!(
                target: "n42.h2.store",
                checkpoint_vote = checkpoint.last_voted_view,
                logged_vote,
                "vote log is ahead of the checkpoint; taking the log",
            );
        }
        checkpoint.last_voted_view = checkpoint.last_voted_view.max(logged_vote);
        checkpoint.last_commit_voted_view = checkpoint.last_commit_voted_view.max(logged_commit);
        // The lock is a safety requirement like the watermarks: a vote cast
        // under a higher lock than the checkpoint's must not be followed by a
        // proposal that lock forbids.
        if let Some(lock) = logged
            .locked_qc
            .filter(|lock| lock.view > checkpoint.locked_qc.view)
        {
            debug!(
                target: "n42.h2.store",
                checkpoint_lock = checkpoint.locked_qc.view,
                logged_lock = lock.view,
                "vote log holds a higher lock than the checkpoint; taking the log",
            );
            checkpoint.locked_qc = lock;
        }
        // A node must not resume in a view it has already voted in.
        checkpoint.view = checkpoint
            .view
            .max(checkpoint.last_voted_view)
            .max(checkpoint.last_commit_voted_view);
        Ok(Some(checkpoint))
    }

    /// Writes the recovery state.
    ///
    /// Written to a temporary file and renamed, so a crash mid-write leaves the
    /// previous checkpoint intact rather than a truncated one. Losing an update
    /// costs a resync; reading a half-written one would have the node resume on
    /// a QC that was never whole.
    pub fn save(&self, checkpoint: &ConsensusCheckpoint) -> Result<(), StoreError> {
        let path = self.dir.join(CHECKPOINT_FILE);
        let temp = path.with_extension("json.tmp");
        let encoded = serde_json::to_vec_pretty(checkpoint).map_err(|source| {
            StoreError::CorruptCheckpoint {
                path: path.clone(),
                source,
            }
        })?;
        {
            let mut file = File::create(&temp).map_err(io(&temp))?;
            file.write_all(&encoded).map_err(io(&temp))?;
            file.sync_all().map_err(io(&temp))?;
        }
        std::fs::rename(&temp, &path).map_err(io(&path))?;
        // The rename itself needs to reach the disk, or a crash can leave the
        // directory entry pointing at the old file.
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

/// What the vote log holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteRecord {
    /// The highest R1 vote view.
    pub last_vote_view: u64,
    /// The highest R2 commit vote view.
    pub last_commit_vote_view: u64,
    /// The highest locked QC the node voted under. `None` for a log written
    /// before the lock was recorded, or a fresh one.
    pub locked_qc: Option<QuorumCertificate>,
}

impl VoteRecord {
    const EMPTY: Self = Self {
        last_vote_view: 0,
        last_commit_vote_view: 0,
        locked_qc: None,
    };

    fn lock_view(&self) -> Option<u64> {
        self.locked_qc.as_ref().map(|qc| qc.view)
    }
}

/// A crash-safe [`VoteLogWriter`] backed by one small file.
#[derive(Debug)]
pub struct FileVoteLog {
    path: PathBuf,
    file: std::sync::Mutex<File>,
    /// The last record written, so a call that moves neither a watermark nor the
    /// lock costs no syscall -- a validator votes in the same view more than
    /// once per step in some paths, and fsync is not free.
    last: std::sync::Mutex<VoteRecord>,
    /// Set once the encoded record has been seen to exceed one sector.
    warned_size: std::sync::atomic::AtomicBool,
}

impl FileVoteLog {
    /// Opens or creates the log at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(io(&path))?;
        let log = Self {
            path,
            file: std::sync::Mutex::new(file),
            last: std::sync::Mutex::new(VoteRecord::EMPTY),
            warned_size: std::sync::atomic::AtomicBool::new(false),
        };
        let seen = log.read_record()?;
        *log.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = seen;
        Ok(log)
    }

    /// The highest R1 and R2 views recorded, or `(0, 0)` for a new log.
    pub fn read(&self) -> Result<(u64, u64), StoreError> {
        let record = self.read_record()?;
        Ok((record.last_vote_view, record.last_commit_vote_view))
    }

    /// The whole record: both watermarks and the locked QC.
    pub fn read_record(&self) -> Result<VoteRecord, StoreError> {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buf = Vec::new();
        file.seek(SeekFrom::Start(0)).map_err(io(&self.path))?;
        file.read_to_end(&mut buf).map_err(io(&self.path))?;
        self.decode(&buf)
    }

    fn corrupt(&self) -> StoreError {
        StoreError::CorruptVoteLog {
            path: self.path.clone(),
        }
    }

    /// Parses `[vote][commit][qc_len][qc][crc32]`; bytes past the record are
    /// ignored (the record is rewritten in place and may shrink).
    fn decode(&self, buf: &[u8]) -> Result<VoteRecord, StoreError> {
        // A brand-new (or zero-length) log is not corruption.
        if buf.is_empty() {
            return Ok(VoteRecord::EMPTY);
        }
        let u64_at = |at: usize| {
            buf.get(at..at + 8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
        };
        let u32_at = |at: usize| {
            buf.get(at..at + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
        };
        // The pre-lock format: exactly [vote][commit][crc32 over those 16].
        if buf.len() == LEGACY_RECORD_LEN {
            return match (u64_at(0), u64_at(8), u32_at(16)) {
                (Some(vote), Some(commit), Some(stored)) if stored == crc32(&buf[..16]) => {
                    Ok(VoteRecord {
                        last_vote_view: vote,
                        last_commit_vote_view: commit,
                        locked_qc: None,
                    })
                }
                _ => Err(self.corrupt()),
            };
        }
        let (Some(vote), Some(commit), Some(qc_len)) = (u64_at(0), u64_at(8), u32_at(16)) else {
            return Err(self.corrupt());
        };
        let qc_end = 20usize
            .checked_add(qc_len as usize)
            .ok_or_else(|| self.corrupt())?;
        let Some(stored) = u32_at(qc_end) else {
            return Err(self.corrupt());
        };
        if stored != crc32(&buf[..qc_end]) {
            return Err(self.corrupt());
        }
        let locked_qc: QuorumCertificate =
            bincode::deserialize(&buf[20..qc_end]).map_err(|_| self.corrupt())?;
        Ok(VoteRecord {
            last_vote_view: vote,
            last_commit_vote_view: commit,
            locked_qc: Some(locked_qc),
        })
    }

    /// Writes the record and waits for it to reach the disk.
    fn write(&self, record: &VoteRecord) -> ConsensusResult<()> {
        let genesis;
        let qc = match &record.locked_qc {
            Some(qc) => qc,
            None => {
                genesis = QuorumCertificate::genesis();
                &genesis
            }
        };
        let encoded = bincode::serialize(qc)
            .map_err(|e| ConsensusError::VoteLogFsync(format!("encoding the locked QC: {e}")))?;
        let mut buf = Vec::with_capacity(24 + encoded.len());
        buf.extend_from_slice(&record.last_vote_view.to_le_bytes());
        buf.extend_from_slice(&record.last_commit_vote_view.to_le_bytes());
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
        let crc = crc32(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());
        if buf.len() > SECTOR_BYTES
            && !self
                .warned_size
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            // The in-place rewrite relies on one sector being written atomically.
            warn!(
                target: "n42.h2.store",
                len = buf.len(),
                "vote log record exceeds one sector; torn writes become possible",
            );
        }

        let vote = record.last_vote_view;
        let commit = record.last_commit_vote_view;
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let at = std::time::Instant::now();
        let written = file
            .seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&buf))
            // sync_data rather than sync_all: file times are not needed, and
            // sync_data still flushes a size change when the record grows.
            // `N42_VOTE_LOG_NOSYNC=1` skips the sync: a bench knob that gives
            // up crash-safety of the vote log for a measurement of what the
            // sync costs on a disk seven execution layers are committing to.
            .and_then(|()| if vote_log_nosync() { Ok(()) } else { file.sync_data() })
            .map_err(n42_h2_consensus::vote_log::map_io_err);
        let took = at.elapsed();
        if took.as_millis() >= 3 {
            tracing::info!(target: "n42.h2.store", vote, commit, sync_ms = took.as_millis() as u64, "vote log sync was slow");
        }
        written
    }

    /// Raises a watermark or the lock, if the new value is higher.
    fn advance(&self, vote: u64, commit: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lock_rises = last.lock_view().is_none_or(|view| locked_qc.view > view);
        let next = VoteRecord {
            last_vote_view: last.last_vote_view.max(vote),
            last_commit_vote_view: last.last_commit_vote_view.max(commit),
            locked_qc: if lock_rises {
                Some(locked_qc.clone())
            } else {
                last.locked_qc.clone()
            },
        };
        if next.last_vote_view == last.last_vote_view
            && next.last_commit_vote_view == last.last_commit_vote_view
            && !lock_rises
        {
            // Already durable at this view or beyond. Rewriting the same value
            // would only cost an fsync on the signing path.
            return Ok(());
        }
        self.write(&next)?;
        *last = next;
        Ok(())
    }
}

impl VoteLogWriter for FileVoteLog {
    fn record_vote(&self, view: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        self.advance(view, 0, locked_qc).inspect_err(|error| {
            // The engine aborts the vote on this, which is correct and worth
            // seeing: a node that cannot log is a node that must not sign.
            warn!(target: "n42.h2.store", %error, view, "could not record an R1 vote; the vote is aborted");
        })
    }

    fn record_commit_vote(&self, view: u64, locked_qc: &QuorumCertificate) -> ConsensusResult<()> {
        self.advance(0, view, locked_qc).inspect_err(|error| {
            warn!(target: "n42.h2.store", %error, view, "could not record an R2 vote; the vote is aborted");
        })
    }
}

/// `N42_VOTE_LOG_NOSYNC`, read once.
fn vote_log_nosync() -> bool {
    static NOSYNC: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *NOSYNC.get_or_init(|| std::env::var("N42_VOTE_LOG_NOSYNC").is_ok_and(|v| v == "1"))
}

/// A CRC-32 (IEEE).
///
/// Not for tamper resistance -- anyone who can write this file can write a valid
/// checksum. It is here to tell a torn or partially-written record from a whole
/// one, because those look identical otherwise and one of them causes a double
/// vote or a lost lock.
fn crc32(bytes: &[u8]) -> u32 {
    const POLYNOMIAL: u32 = 0xEDB8_8320;
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLYNOMIAL & mask);
        }
    }
    !crc
}

/// Reads the state a running engine would need to be restored to.
pub fn checkpoint_from(engine: &n42_h2_consensus::ConsensusEngine) -> ConsensusCheckpoint {
    ConsensusCheckpoint {
        view: engine.current_view(),
        locked_qc: engine.locked_qc().clone(),
        last_committed_qc: engine.last_committed_qc().clone(),
        consecutive_timeouts: engine.consecutive_timeouts(),
        last_voted_view: engine.last_voted_view(),
        last_commit_voted_view: engine.last_commit_voted_view(),
    }
}

/// Maps a store error onto the consensus error type.
pub fn to_consensus_error(error: StoreError) -> ConsensusError {
    ConsensusError::VoteLogFsync(error.to_string())
}

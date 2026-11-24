// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The safety halt: proof of a conflicting commit stops this node for good
//! (sync standard 3.3 "Conflict" / "Equivocation", owner rule: fail closed).
//!
//! **What counts as proof.** Only certificates this node verified against a
//! validator set it knows, in the commit domain:
//! - a live commit (a Decide, or a commit QC this node formed) whose block
//!   does not extend this node's committed chain -- another block at a
//!   committed height or view, or a chain that does not run through the
//!   committed head ([`crate::sync_safety::SyncSafety::live_commit_conflict`]);
//! - what the sync importer's record finds
//!   ([`crate::sync_safety`]): a verified anchor that does not join the
//!   committed chain, or two verified anchors for different blocks at one
//!   height or one view.
//!
//! A certificate that does not verify, a prepare-domain one, one of a set
//! this node does not know, or one whose block's height or ancestry is not
//! held here is no proof and never halts: one peer cannot stop a node.
//! Uncommitted blocks never count (a same-parent rebuild, a reorg below the
//! lock): only commits are compared.
//!
//! **What stops** (gov5's `safety_halt.go`: no production, no outbound
//! consensus message): the engine casts no vote, commit vote or timeout and
//! proposes nothing (`ConsensusEngine::halt_voting`), so this node no longer
//! counts in any quorum; every consensus message already queued is dropped
//! on its way out; the execution driver sends no import and no forkchoice
//! (`ExecutionDriver::halt`), so nothing is executed or reorged; the sync
//! importer pulls nothing. It keeps answering status and serving ranges and
//! blocks by hash, up to what it committed, and inbound consensus messages
//! are still read, so peers and the operator can see it.
//!
//! **Evidence.** One `error!` line with both blocks, heights and QC views,
//! repeated every [`HALT_LOG_EVERY`]; the gauge [`METRIC_SAFETY_HALTED`]
//! (`reason` = `conflict` | `equivocation`) at 1; and both certificates,
//! with the headers held for them, written to
//! `<datadir>/`[`EVIDENCE_FILE`] before anything else happens. gov5 keeps
//! its halt in memory and relies on its chain refusing the same commit
//! again after a restart; here the file is the halt: a node that finds it
//! at start starts halted, and one whose file cannot be read starts halted
//! too.
//!
//! **Resume** is the operator's act alone, as in gov5 (decide which chain is
//! right, repair this node's data if it is the wrong one, restart): stop the
//! node, move the evidence file out of the datadir (keep it), restart.
//! Nothing in the node clears it.

use std::path::{Path, PathBuf};

use alloy_primitives::B256;
use n42_h2_consensus::N42Header;
use n42_h2_primitives::consensus::QuorumCertificate;
use serde::{Deserialize, Serialize};

use crate::sync_safety::{Certified, HaltKind, Origin, SyncHalt};

/// Gauge, label `reason` (`conflict` | `equivocation` | `unreadable`): 1
/// while this node is halted on proof of a conflicting commit.
pub const METRIC_SAFETY_HALTED: &str = "n42_h2_safety_halted";

/// The evidence file's name under the validator's datadir.
pub const EVIDENCE_FILE: &str = "safety-halt.json";

/// How often the halt's `error!` line is repeated.
pub const HALT_LOG_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// One side of the evidence: a block, its height when established, the
/// commit QC behind it and the header held for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSide {
    /// The block.
    pub hash: B256,
    /// Its height, when a header that hashes to it was held.
    pub number: Option<u64>,
    /// The commit QC certifying it (naming it, or a descendant).
    pub qc: QuorumCertificate,
    /// `committed` (this node's own commit) or `anchor` (a peer's data).
    pub origin: String,
    /// The block's header, when held.
    pub header: Option<N42Header>,
}

/// Both certificates of a safety violation, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyEvidence {
    /// `conflict` or `equivocation`.
    pub reason: String,
    /// The road the proof came by: `live-commit`, `sync`.
    pub source: String,
    /// The height the two chains differ at, when known.
    pub height: Option<u64>,
    /// What was certified first (for a conflict, this node's side).
    pub first: EvidenceSide,
    /// What contradicts it.
    pub second: EvidenceSide,
    /// When the halt was entered, Unix milliseconds.
    pub halted_at_ms: u64,
}

impl SafetyEvidence {
    /// The evidence of `halt`, found on `source`, with the headers
    /// `header_of` holds.
    pub fn new(
        halt: &SyncHalt,
        source: &str,
        height: Option<u64>,
        header_of: impl Fn(&B256) -> Option<N42Header>,
    ) -> Self {
        let side = |c: &Certified| EvidenceSide {
            hash: c.hash,
            number: c.number,
            qc: c.qc.clone(),
            origin: match c.origin {
                Origin::Committed => "committed",
                Origin::Anchor => "anchor",
            }
            .to_owned(),
            header: header_of(&c.hash),
        };
        let halted_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Self {
            reason: halt.kind.label().to_owned(),
            source: source.to_owned(),
            height: height.or(halt.first.number).or(halt.second.number),
            first: side(&halt.first),
            second: side(&halt.second),
            halted_at_ms,
        }
    }

    /// The halt kind's label, for the gauge (`conflict` for anything else).
    pub fn reason_label(&self) -> &'static str {
        if self.reason == HaltKind::Equivocation.label() {
            HaltKind::Equivocation.label()
        } else {
            HaltKind::Conflict.label()
        }
    }
}

/// Why this node is halted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyHalt {
    /// Proof of a conflicting commit, found now or read back from the
    /// evidence file at start.
    Proven(Box<SafetyEvidence>),
    /// An evidence file exists but cannot be read: halted all the same
    /// (fail closed).
    Unreadable {
        /// The file.
        path: PathBuf,
        /// What was wrong with it.
        error: String,
    },
}

impl SafetyHalt {
    /// The gauge label.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Proven(evidence) => evidence.reason_label(),
            Self::Unreadable { .. } => "unreadable",
        }
    }

    /// The evidence, when it could be read.
    pub fn evidence(&self) -> Option<&SafetyEvidence> {
        match self {
            Self::Proven(evidence) => Some(evidence),
            Self::Unreadable { .. } => None,
        }
    }
}

/// The evidence file under `datadir`.
pub fn evidence_path(datadir: &Path) -> PathBuf {
    datadir.join(EVIDENCE_FILE)
}

/// Reads the evidence file: `None` when there is none, a halt otherwise
/// (one that cannot be read is a halt too).
pub fn load(path: &Path) -> Option<SafetyHalt> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => return Some(SafetyHalt::Unreadable { path: path.to_owned(), error: err.to_string() }),
    };
    Some(match serde_json::from_slice::<SafetyEvidence>(&bytes) {
        Ok(evidence) => SafetyHalt::Proven(Box::new(evidence)),
        Err(err) => SafetyHalt::Unreadable { path: path.to_owned(), error: err.to_string() },
    })
}

/// Writes `evidence` to `path` durably: a temporary file beside it, synced,
/// renamed over, the directory synced.
pub fn persist(path: &Path, evidence: &SafetyEvidence) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(evidence).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent()
        && let Ok(dir) = std::fs::File::open(dir)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn halt() -> SyncHalt {
        let mut qc = QuorumCertificate::genesis();
        qc.view = 7;
        qc.block_hash = B256::repeat_byte(1);
        let mut other = qc.clone();
        other.view = 9;
        other.block_hash = B256::repeat_byte(2);
        SyncHalt {
            kind: HaltKind::Conflict,
            first: Certified { hash: qc.block_hash, number: Some(4), qc, origin: Origin::Committed },
            second: Certified { hash: other.block_hash, number: Some(4), qc: other, origin: Origin::Anchor },
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-safety-halt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn evidence_round_trips_through_its_file_and_no_file_is_no_halt() {
        let dir = scratch("roundtrip");
        let path = evidence_path(&dir);
        assert_eq!(load(&path), None);
        let mut header = N42Header::default();
        header.number = 4;
        let evidence = SafetyEvidence::new(&halt(), "live-commit", None, |h| (*h == B256::repeat_byte(1)).then(|| header.clone()));
        assert_eq!((evidence.height, evidence.first.origin.as_str(), evidence.second.origin.as_str()), (Some(4), "committed", "anchor"));
        assert_eq!(evidence.first.header.as_ref().map(|h| h.number), Some(4));
        assert!(evidence.second.header.is_none());
        persist(&path, &evidence).expect("written");
        let back = load(&path).expect("halted");
        assert_eq!(back.reason(), "conflict");
        assert_eq!(back.evidence(), Some(&evidence));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_evidence_file_is_a_halt_too() {
        let dir = scratch("unreadable");
        std::fs::create_dir_all(&dir).expect("dir");
        let path = evidence_path(&dir);
        std::fs::write(&path, b"{ not json").expect("written");
        let halt = load(&path).expect("fail closed");
        assert_eq!(halt.reason(), "unreadable");
        assert!(halt.evidence().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
